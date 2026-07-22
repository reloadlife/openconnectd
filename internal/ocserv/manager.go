package ocserv

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/reloadlife/openconnectd/internal/config"
	"github.com/reloadlife/openconnectd/internal/state"
	"github.com/reloadlife/openconnectd/pkg/api"
)

// Manager orchestrates the driver: it turns API calls into rendered config,
// PKI/password provisioning, persisted state, and a supervised ocserv process.
// It is the single object the HTTP handlers talk to.
type Manager struct {
	cfg   config.Config
	pki   *PKI
	sup   *Supervisor
	occtl *Occtl
	store *state.Store
	log   *slog.Logger
}

func NewManager(cfg config.Config, store *state.Store, log *slog.Logger) *Manager {
	return &Manager{
		cfg:   cfg,
		pki:   NewPKI(cfg.PKIDir),
		sup:   NewSupervisor(cfg.OcservBin),
		occtl: NewOcctl(cfg.OcctlBin),
		store: store,
		log:   log,
	}
}

// Reconcile (re)starts every enabled instance from persisted state. Called on
// boot so the fleet comes back after a daemon restart.
func (m *Manager) Reconcile(ctx context.Context) {
	for _, in := range m.store.ListInstances() {
		if !in.Enabled {
			continue
		}
		if err := m.startInstance(in); err != nil {
			m.log.Warn("reconcile start failed", "instance", in.Name, "err", err)
		}
	}
}

// --- instances ---

func (m *Manager) CreateInstance(ctx context.Context, req api.InstanceCreateRequest) (*api.Instance, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, fmt.Errorf("instance name required")
	}
	if _, exists := m.store.GetInstance(name); exists {
		return nil, fmt.Errorf("instance %q already exists", name)
	}

	in := api.Instance{
		Name:           name,
		Listen:         orString(req.Listen, ":443"),
		DTLS:           boolOr(req.DTLS, true),
		PoolCIDR:       req.PoolCIDR,
		PoolCIDRv6:     req.PoolCIDRv6,
		PublicEndpoint: req.PublicEndpoint,
		LocalBind:      req.LocalBind,
		AuthMode:       orAuth(req.AuthMode, api.AuthCert),
		DNS:            req.DNS,
		Routes:         req.Routes,
		Enabled:        boolOr(req.Enabled, true),
	}
	if req.Camouflage != nil {
		in.Camouflage = *req.Camouflage
	}
	if in.PoolCIDR == "" {
		return nil, fmt.Errorf("pool_cidr required")
	}

	// PKI: client CA for cert/both; server cert always (dev fallback).
	if in.AuthMode == api.AuthCert || in.AuthMode == api.AuthBoth || req.CreateCAIfEmpty {
		if _, err := m.pki.EnsureCA(name); err != nil {
			return nil, fmt.Errorf("ensure CA: %w", err)
		}
	}
	if err := m.pki.EnsureServerCert(name, hostsOf(in.PublicEndpoint)); err != nil {
		return nil, fmt.Errorf("ensure server cert: %w", err)
	}

	if err := m.renderAndWrite(in); err != nil {
		return nil, err
	}
	if err := m.store.PutInstance(in); err != nil {
		return nil, err
	}

	if in.Enabled {
		if err := m.startInstance(in); err != nil {
			// ocserv may be absent (dev/CI) — persist anyway, report Up=false.
			m.log.Warn("start instance", "instance", name, "err", err)
		}
	}
	return m.decorate(in), nil
}

func (m *Manager) ListInstances() []api.Instance {
	list := m.store.ListInstances()
	out := make([]api.Instance, len(list))
	for i, in := range list {
		out[i] = *m.decorate(in)
	}
	return out
}

func (m *Manager) GetInstance(name string) (*api.Instance, bool) {
	in, ok := m.store.GetInstance(name)
	if !ok {
		return nil, false
	}
	return m.decorate(in), true
}

func (m *Manager) DeleteInstance(name string) error {
	if _, ok := m.store.GetInstance(name); !ok {
		return fmt.Errorf("instance %q not found", name)
	}
	_ = m.sup.Stop(name)
	_ = os.Remove(m.configPath(name))
	return m.store.DeleteInstance(name)
}

// PatchInstance updates mutable fields, re-renders, and reloads ocserv.
func (m *Manager) PatchInstance(name string, body map[string]any) (*api.Instance, error) {
	in, ok := m.store.GetInstance(name)
	if !ok {
		return nil, fmt.Errorf("instance %q not found", name)
	}
	applyInstancePatch(&in, body)
	if err := m.renderAndWrite(in); err != nil {
		return nil, err
	}
	if err := m.store.PutInstance(in); err != nil {
		return nil, err
	}
	if in.Enabled {
		if err := m.startInstance(in); err == nil {
			_ = m.sup.Reload(name) // pick up config changes without a drop
		}
	} else {
		_ = m.sup.Stop(name)
	}
	return m.decorate(in), nil
}

// --- clients ---

func (m *Manager) CreateClient(ctx context.Context, instance string, req api.ClientCreateRequest) (*api.ClientPeer, error) {
	in, ok := m.store.GetInstance(instance)
	if !ok {
		return nil, fmt.Errorf("instance %q not found", instance)
	}
	cn := strings.TrimSpace(req.CommonName)
	if cn == "" {
		return nil, fmt.Errorf("common_name required")
	}
	if _, exists := m.store.GetClient(instance, cn); exists {
		return nil, fmt.Errorf("client %q already exists", cn)
	}
	mode := orAuth(req.AuthMode, in.AuthMode)

	c := api.ClientPeer{
		Name:         orString(req.Name, cn),
		CommonName:   cn,
		InstanceName: instance,
		AuthMode:     mode,
		StaticIP:     req.StaticIP,
		Enabled:      true,
	}

	if mode == api.AuthCert || mode == api.AuthBoth {
		issued, err := m.pki.IssueClient(instance, cn, 0)
		if err != nil {
			return nil, fmt.Errorf("issue client cert: %w", err)
		}
		c.CertSerial = issued.Serial
		exp := issued.NotAfter
		c.CertExpiry = &exp
	}
	if mode == api.AuthPassword || mode == api.AuthBoth {
		if req.Password == "" {
			return nil, fmt.Errorf("password required for %s auth", mode)
		}
		op := NewOcpasswd(m.cfg.OcpasswdBin, m.ocpasswdPath(instance))
		if err := op.SetPassword(ctx, cn, "", req.Password); err != nil {
			return nil, fmt.Errorf("set password: %w", err)
		}
	}

	// Pin (or clear) the address before persisting. PatchClient runs through
	// here too, so a changed StaticIP converges instead of being create-only.
	if err := m.writePerUserConfig(instance, cn, c.StaticIP); err != nil {
		return nil, fmt.Errorf("pin static ip: %w", err)
	}
	if err := m.store.PutClient(instance, c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (m *Manager) ListClients(instance string) ([]api.ClientPeer, error) {
	if _, ok := m.store.GetInstance(instance); !ok {
		return nil, fmt.Errorf("instance %q not found", instance)
	}
	return m.store.ListClients(instance), nil
}

func (m *Manager) DeleteClient(instance, cn string) error {
	c, ok := m.store.GetClient(instance, cn)
	if !ok {
		return fmt.Errorf("client %q not found", cn)
	}
	if c.CertSerial != "" {
		if err := m.pki.RevokeClient(instance, c.CertSerial); err != nil {
			return fmt.Errorf("revoke: %w", err)
		}
		_ = m.sup.Reload(instance) // ocserv re-reads the CRL
	}
	if c.AuthMode == api.AuthPassword || c.AuthMode == api.AuthBoth {
		_ = NewOcpasswd("", m.ocpasswdPath(instance)).DeleteUser(cn)
	}
	// Leaving the pin behind would hand a recycled address to whoever inherits
	// the common name.
	_ = m.removePerUserConfig(instance, cn)
	return m.store.DeleteClient(instance, cn)
}

func (m *Manager) PatchClient(ctx context.Context, instance, cn string, body map[string]any) (*api.ClientPeer, error) {
	c, ok := m.store.GetClient(instance, cn)
	if !ok {
		return nil, fmt.Errorf("client %q not found", cn)
	}
	if v, ok := body["static_ip"].(string); ok {
		c.StaticIP = v
	}
	if v, ok := body["suspended"].(bool); ok {
		c.Suspended = v
	}
	if v, ok := body["enabled"].(bool); ok {
		c.Enabled = v
	}
	if pw, ok := body["password"].(string); ok && pw != "" {
		if c.AuthMode == api.AuthPassword || c.AuthMode == api.AuthBoth {
			if err := NewOcpasswd("", m.ocpasswdPath(instance)).SetPassword(ctx, cn, "", pw); err != nil {
				return nil, fmt.Errorf("set password: %w", err)
			}
		}
	}
	// Pin (or clear) the address before persisting. PatchClient runs through
	// here too, so a changed StaticIP converges instead of being create-only.
	if err := m.writePerUserConfig(instance, cn, c.StaticIP); err != nil {
		return nil, fmt.Errorf("pin static ip: %w", err)
	}
	if err := m.store.PutClient(instance, c); err != nil {
		return nil, err
	}
	return &c, nil
}

// Sessions returns live connections from occtl. instance=="" fans out across
// every instance. An instance whose ocserv is down contributes no sessions
// rather than failing the whole call.
func (m *Manager) Sessions(ctx context.Context, instance string) ([]api.Session, error) {
	var names []string
	if instance != "" {
		if _, ok := m.store.GetInstance(instance); !ok {
			return nil, fmt.Errorf("instance %q not found", instance)
		}
		names = []string{instance}
	} else {
		for _, in := range m.store.ListInstances() {
			names = append(names, in.Name)
		}
	}
	out := []api.Session{}
	for _, name := range names {
		sessions, err := m.occtl.ShowUsers(ctx, m.occtlSocket(name))
		if err != nil {
			m.log.Debug("occtl show users", "instance", name, "err", err)
			continue
		}
		for i := range sessions {
			sessions[i].InstanceName = name
		}
		out = append(out, sessions...)
	}
	return out, nil
}

// Bans returns every scored or blocked IP across instances. Both occtl lists
// are merged: an IP that is banned is reported once, as banned, since its score
// appears in both.
//
// Unlike Sessions, a failing instance is reported rather than skipped. A ban
// list is a security signal, and an empty table that silently means "could not
// ask" would read as "nobody is being attacked".
func (m *Manager) Bans(ctx context.Context) ([]api.Ban, error) {
	var names []string
	for _, in := range m.store.ListInstances() {
		names = append(names, in.Name)
	}
	out := []api.Ban{}
	var failed []string
	for _, name := range names {
		sock := m.occtlSocket(name)
		seen := map[string]struct{}{}
		bans, err := m.occtl.ShowIPBans(ctx, sock)
		if err != nil {
			m.log.Debug("occtl show ip bans", "instance", name, "err", err)
			failed = append(failed, name)
			continue
		}
		for _, b := range bans {
			b.InstanceName = name
			seen[b.IP] = struct{}{}
			out = append(out, b)
		}
		points, err := m.occtl.ShowIPBanPoints(ctx, sock)
		if err != nil {
			// The ban list already succeeded, so the instance is up; a missing
			// points list is a version difference, not an outage.
			m.log.Debug("occtl show ip ban points", "instance", name, "err", err)
			continue
		}
		for _, b := range points {
			if _, dup := seen[b.IP]; dup {
				continue
			}
			b.InstanceName = name
			out = append(out, b)
		}
	}
	if len(failed) > 0 && len(failed) == len(names) {
		return out, fmt.Errorf("could not read ban list from any instance (%s)", strings.Join(failed, ", "))
	}
	return out, nil
}

// Unban clears an IP across every instance holding it. Callers name an address,
// not an instance: ocserv scores per instance, so the same client can be banned
// on more than one and unbanning only the first leaves it locked out.
func (m *Manager) Unban(ctx context.Context, ip string) error {
	if strings.TrimSpace(ip) == "" {
		return fmt.Errorf("ip required")
	}
	cleared := 0
	var lastErr error
	for _, in := range m.store.ListInstances() {
		if err := m.occtl.UnbanIP(ctx, m.occtlSocket(in.Name), ip); err != nil {
			lastErr = err
			continue
		}
		cleared++
	}
	if cleared == 0 {
		if lastErr != nil {
			return lastErr
		}
		return fmt.Errorf("%s is not banned", ip)
	}
	return nil
}

// Disconnect kicks a live session by common name on its instance.
func (m *Manager) Disconnect(ctx context.Context, instance, cn string) error {
	if _, ok := m.store.GetInstance(instance); !ok {
		return fmt.Errorf("instance %q not found", instance)
	}
	return m.occtl.Disconnect(ctx, m.occtlSocket(instance), cn)
}

// ClientConfig returns an importable profile for the user.
func (m *Manager) ClientConfig(instance, cn string) (string, error) {
	in, ok := m.store.GetInstance(instance)
	if !ok {
		return "", fmt.Errorf("instance %q not found", instance)
	}
	c, ok := m.store.GetClient(instance, cn)
	if !ok {
		return "", fmt.Errorf("client %q not found", cn)
	}
	endpoint := orString(in.PublicEndpoint, in.Listen)
	header := fmt.Sprintf("# openconnect --user=%s --servercert=pin-sha256 %s\n# OpenConnect/AnyConnect profile for %q on instance %q\n",
		cn, endpoint, cn, instance)
	if c.CertSerial != "" {
		bundle, err := m.pki.ClientBundle(instance, c.CertSerial)
		if err != nil {
			return "", err
		}
		return header + bundle, nil
	}
	// Password auth: no cert bundle, just the connection descriptor.
	return header + fmt.Sprintf("# auth: password (username %s)\n", cn), nil
}

// --- helpers ---

func (m *Manager) decorate(in api.Instance) *api.Instance {
	in.Up = m.sup.Running(in.Name)
	in.ClientCount = m.store.CountClients(in.Name)
	return &in
}

func (m *Manager) startInstance(in api.Instance) error {
	if err := m.renderAndWrite(in); err != nil {
		return err
	}
	return m.sup.Start(in.Name, m.configPath(in.Name))
}

func (m *Manager) renderAndWrite(in api.Instance) error {
	cfg, err := m.instanceConfig(in)
	if err != nil {
		return err
	}
	rendered, err := cfg.Render()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(m.cfg.ConfigDir, 0o755); err != nil {
		return err
	}
	// The rendered config names this directory. ocserv fails to start when
	// config-per-user points at a path that does not exist, so create it even
	// when no client has a pinned address yet.
	if err := os.MkdirAll(m.perUserDir(in.Name), 0o700); err != nil {
		return err
	}
	// Rebuild the pins from the client store. They are derived state: a client
	// provisioned before this existed already carries StaticIP on its record,
	// so drift detection has nothing to converge and would never write the
	// file. Rebuilding here is idempotent and self-heals a hand-edited or
	// half-migrated directory.
	m.syncPerUserConfigs(in.Name)
	return os.WriteFile(m.configPath(in.Name), []byte(rendered), 0o600)
}

func (m *Manager) instanceConfig(in api.Instance) (InstanceConfig, error) {
	port := parseListenPort(in.Listen)
	if port <= 0 {
		port = 443
	}
	udp := 0
	if in.DTLS {
		udp = port
	}
	cfg := InstanceConfig{
		Name:          in.Name,
		TCPPort:       port,
		UDPPort:       udp,
		LocalBind:     in.LocalBind,
		PoolCIDR:      in.PoolCIDR,
		PoolCIDRv6:    in.PoolCIDRv6,
		DNS:           in.DNS,
		Routes:        in.Routes,
		AuthMode:      in.AuthMode,
		Camouflage:    in.Camouflage,
		ServerCert:    m.pki.ServerCertPath(in.Name),
		ServerKey:     m.pki.ServerKeyPath(in.Name),
		OcctlSocket:   m.occtlSocket(in.Name),
		RunSocket:     m.runSocket(in.Name),
		Device:           tunName(in.Name),
		ConfigPerUserDir: m.perUserDir(in.Name),
		DefaultDomain:    hostOnly(in.PublicEndpoint),
	}
	if in.AuthMode == api.AuthCert || in.AuthMode == api.AuthBoth {
		cfg.CACert = m.pki.CACertPath(in.Name)
		cfg.CRLFile = m.pki.CRLPath(in.Name)
	}
	if in.AuthMode == api.AuthPassword || in.AuthMode == api.AuthBoth {
		cfg.OcpasswdFile = m.ocpasswdPath(in.Name)
	}
	return cfg, nil
}

func (m *Manager) configPath(name string) string  { return filepath.Join(m.cfg.ConfigDir, name+".conf") }
func (m *Manager) occtlSocket(name string) string { return filepath.Join(m.cfg.RunDir, name+".occtl") }
func (m *Manager) runSocket(name string) string   { return filepath.Join(m.cfg.RunDir, name+".sock") }
func (m *Manager) ocpasswdPath(name string) string {
	return filepath.Join(m.cfg.StateDir, name+".ocpasswd")
}

// perUserDir holds one ocserv config-per-user file per common name.
func (m *Manager) perUserDir(instance string) string {
	return filepath.Join(m.cfg.StateDir, instance+".per-user")
}

// perUserPath is the file ocserv reads for one client.
//
// ocserv looks the file up by the exact username it authenticated, so the name
// must be the common name verbatim — it cannot be hashed or escaped. The common
// name arrives from the API unvalidated, and this value is a path component
// written and removed as root, so anything that is not a bare filename is
// rejected rather than sanitised: silently rewriting it would produce a file
// ocserv never reads, which fails open as an unpinned address.
func (m *Manager) perUserPath(instance, cn string) (string, error) {
	if err := validPerUserName(cn); err != nil {
		return "", err
	}
	return filepath.Join(m.perUserDir(instance), cn), nil
}

// validPerUserName rejects any common name that is not a single safe path
// element.
func validPerUserName(cn string) error {
	if cn == "" {
		return fmt.Errorf("common name required")
	}
	if cn == "." || cn == ".." {
		return fmt.Errorf("invalid common name %q", cn)
	}
	if strings.ContainsAny(cn, `/\`) || strings.ContainsRune(cn, os.PathSeparator) {
		return fmt.Errorf("invalid common name %q: path separators not allowed", cn)
	}
	if cn != filepath.Base(cn) || cn != filepath.Clean(cn) {
		return fmt.Errorf("invalid common name %q", cn)
	}
	for _, r := range cn {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("invalid common name: control character")
		}
	}
	return nil
}

// writePerUserConfig pins a client's address. An empty staticIP removes the
// file so the client falls back to pool assignment rather than keeping a stale
// pin that no longer matches what the control plane believes.
func (m *Manager) writePerUserConfig(instance, cn, staticIP string) error {
	path, err := m.perUserPath(instance, cn)
	if err != nil {
		return err
	}
	if strings.TrimSpace(staticIP) == "" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	// The address is interpolated into an ocserv config file. A value carrying
	// a newline would inject directives ocserv then applies to the session, so
	// it must parse as a bare IPv4 literal and nothing else.
	ip := net.ParseIP(strings.TrimSpace(staticIP))
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("invalid static ip %q", staticIP)
	}
	if err := os.MkdirAll(m.perUserDir(instance), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(renderPerUserConfig(ip.To4().String())), 0o600)
}

// syncPerUserConfigs writes one pin per client that has an address. A client
// whose common name is not a safe filename is skipped and logged rather than
// failing the render: one bad legacy record must not stop the instance from
// starting, and an unpinned client is a degraded address, not an outage.
func (m *Manager) syncPerUserConfigs(instance string) {
	for _, c := range m.store.ListClients(instance) {
		if strings.TrimSpace(c.StaticIP) == "" {
			continue
		}
		if err := m.writePerUserConfig(instance, c.CommonName, c.StaticIP); err != nil {
			m.log.Warn("pin static ip", "instance", instance,
				"cn", c.CommonName, "err", err)
		}
	}
}

// removePerUserConfig drops a deleted client's pin.
func (m *Manager) removePerUserConfig(instance, cn string) error {
	path, err := m.perUserPath(instance, cn)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// OcctlSocket exposes the occtl socket path for the sessions layer (M2).
func (m *Manager) OcctlSocket(name string) string { return m.occtlSocket(name) }

func applyInstancePatch(in *api.Instance, body map[string]any) {
	if v, ok := body["local_bind"].(string); ok {
		in.LocalBind = v
	}
	if v, ok := body["public_endpoint"].(string); ok {
		in.PublicEndpoint = v
	}
	if v, ok := body["enabled"].(bool); ok {
		in.Enabled = v
	}
	if v, ok := body["dtls"].(bool); ok {
		in.DTLS = v
	}
	if v, ok := body["dns"].([]any); ok {
		in.DNS = toStrings(v)
	}
	if v, ok := body["routes"].([]any); ok {
		in.Routes = toStrings(v)
	}
	if cam, ok := body["camouflage"].(map[string]any); ok {
		if v, ok := cam["enabled"].(bool); ok {
			in.Camouflage.Enabled = v
		}
		if v, ok := cam["secret"].(string); ok {
			in.Camouflage.Secret = v
		}
		if v, ok := cam["realm"].(string); ok {
			in.Camouflage.Realm = v
		}
	}
}

func toStrings(in []any) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func parseListenPort(listen string) int {
	listen = strings.TrimSpace(listen)
	if listen == "" {
		return 0
	}
	if _, portStr, err := net.SplitHostPort(listen); err == nil {
		if p, err := strconv.Atoi(portStr); err == nil {
			return p
		}
	}
	if i := strings.LastIndex(listen, ":"); i >= 0 {
		if p, err := strconv.Atoi(listen[i+1:]); err == nil {
			return p
		}
	}
	if p, err := strconv.Atoi(listen); err == nil {
		return p
	}
	return 0
}

// tunName builds a Linux-safe tun device name (IFNAMSIZ is 16, so ≤15 chars).
func tunName(instance string) string {
	n := "oc-" + instance
	if len(n) > 15 {
		n = n[:15]
	}
	return n
}

func hostOnly(endpoint string) string {
	if endpoint == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(endpoint); err == nil {
		return h
	}
	return endpoint
}

func hostsOf(endpoint string) []string {
	h := hostOnly(endpoint)
	if h == "" {
		return nil
	}
	return []string{h}
}

func orString(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func orAuth(v, def api.AuthMode) api.AuthMode {
	if v == "" {
		return def
	}
	return v
}

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}
