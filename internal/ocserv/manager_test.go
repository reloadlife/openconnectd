package ocserv

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reloadlife/openconnectd/internal/config"
	"github.com/reloadlife/openconnectd/internal/state"
	"github.com/reloadlife/openconnectd/pkg/api"
)

func testManager(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Config{
		StateDir:  filepath.Join(dir, "state"),
		ConfigDir: filepath.Join(dir, "conf"),
		PKIDir:    filepath.Join(dir, "pki"),
		RunDir:    filepath.Join(dir, "run"),
		OcservBin: "/nonexistent/ocserv", // ocserv absent: CRUD still works, Up=false
	}
	store, err := state.Open(filepath.Join(cfg.StateDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return NewManager(cfg, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func mkInstance(t *testing.T, m *Manager, name string, cam *api.Camouflage) *api.Instance {
	t.Helper()
	in, err := m.CreateInstance(context.Background(), api.InstanceCreateRequest{
		Name:           name,
		PoolCIDR:       "10.20.0.0/24",
		PublicEndpoint: "vpn.example.com:443",
		DNS:            []string{"1.1.1.1"},
		Camouflage:     cam,
	})
	if err != nil {
		t.Fatalf("CreateInstance: %v", err)
	}
	return in
}

func TestInstanceLifecycle(t *testing.T) {
	m := testManager(t)
	in := mkInstance(t, m, "edge1", nil)
	if in.AuthMode != api.AuthCert {
		t.Errorf("default auth = %q, want cert", in.AuthMode)
	}
	if in.Up {
		t.Error("Up should be false with no ocserv")
	}

	// Config file rendered to disk.
	confData, err := os.ReadFile(m.configPath("edge1"))
	if err != nil {
		t.Fatalf("config file: %v", err)
	}
	conf := string(confData)
	for _, want := range []string{"tcp-port = 443", "udp-port = 443", "ipv4-network = 10.20.0.0", "ca-cert", "crl ="} {
		if !strings.Contains(conf, want) {
			t.Errorf("rendered config missing %q", want)
		}
	}

	// Duplicate rejected.
	if _, err := m.CreateInstance(context.Background(), api.InstanceCreateRequest{Name: "edge1", PoolCIDR: "10.0.0.0/24"}); err == nil {
		t.Error("expected duplicate instance error")
	}

	// List + get.
	if got := m.ListInstances(); len(got) != 1 {
		t.Errorf("ListInstances = %d, want 1", len(got))
	}
	if _, ok := m.GetInstance("edge1"); !ok {
		t.Error("GetInstance edge1 not found")
	}

	// Delete.
	if err := m.DeleteInstance("edge1"); err != nil {
		t.Fatalf("DeleteInstance: %v", err)
	}
	if _, ok := m.GetInstance("edge1"); ok {
		t.Error("instance still present after delete")
	}
}

func TestClientProvisioningCertAuth(t *testing.T) {
	m := testManager(t)
	mkInstance(t, m, "edge1", nil)

	c, err := m.CreateClient(context.Background(), "edge1", api.ClientCreateRequest{CommonName: "alice"})
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	if c.CertSerial == "" || c.CertExpiry == nil {
		t.Fatalf("cert not issued: %+v", c)
	}
	if c.AuthMode != api.AuthCert {
		t.Errorf("client auth = %q, want cert", c.AuthMode)
	}

	// client-config carries the importable bundle.
	prof, err := m.ClientConfig("edge1", "alice")
	if err != nil {
		t.Fatalf("ClientConfig: %v", err)
	}
	for _, want := range []string{"-----BEGIN CERTIFICATE-----", "-----BEGIN RSA PRIVATE KEY-----", "openconnect"} {
		if !strings.Contains(prof, want) {
			t.Errorf("client-config missing %q", want)
		}
	}

	if got := m.store.CountClients("edge1"); got != 1 {
		t.Errorf("client count = %d, want 1", got)
	}

	// Duplicate client rejected.
	if _, err := m.CreateClient(context.Background(), "edge1", api.ClientCreateRequest{CommonName: "alice"}); err == nil {
		t.Error("expected duplicate client error")
	}

	// Delete revokes the cert (appears in CRL).
	serial := c.CertSerial
	if err := m.DeleteClient("edge1", "alice"); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
	if !m.pki.IsRevoked("edge1", serial) {
		t.Error("deleted client's cert not revoked")
	}
	if _, ok := m.store.GetClient("edge1", "alice"); ok {
		t.Error("client still present after delete")
	}
}

func TestCamouflageRendersToConfig(t *testing.T) {
	m := testManager(t)
	mkInstance(t, m, "edge1", &api.Camouflage{Enabled: true, Secret: "hunter2", Realm: "CDN"})
	conf, _ := os.ReadFile(m.configPath("edge1"))
	for _, want := range []string{"camouflage = true", `camouflage_secret = "hunter2"`} {
		if !strings.Contains(string(conf), want) {
			t.Errorf("camouflage not rendered: missing %q", want)
		}
	}
}

func TestCreateClientUnknownInstance(t *testing.T) {
	m := testManager(t)
	if _, err := m.CreateClient(context.Background(), "ghost", api.ClientCreateRequest{CommonName: "x"}); err == nil {
		t.Error("expected error for unknown instance")
	}
}

func TestReconcileRestoresFromState(t *testing.T) {
	m := testManager(t)
	mkInstance(t, m, "edge1", nil)
	// New manager over the same dirs: state persists across restart.
	store, _ := state.Open(filepath.Join(m.cfg.StateDir, "state.json"))
	m2 := NewManager(m.cfg, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, ok := m2.GetInstance("edge1"); !ok {
		t.Error("instance not restored from persisted state")
	}
	m2.Reconcile(context.Background()) // must not panic without ocserv
}

// A client's StaticIP has to reach ocserv, not just the daemon's own state.
// It was previously stored on the record and never rendered anywhere, so
// ocserv assigned pool addresses in connect order and the control plane's
// AssignedIP was fiction — which silently broke per-device egress, the
// fail-closed egress guard, iran-direct, cross-node relay membership and plan
// speed limits, all of which match on that address as a source CIDR.
func TestClientStaticIPIsPinnedForOcserv(t *testing.T) {
	m := testManager(t)
	mkInstance(t, m, "oc-test", nil)
	ctx := context.Background()

	if _, err := m.CreateClient(ctx, "oc-test", api.ClientCreateRequest{
		CommonName: "phone-abc123",
		// Cert auth: exercises the same pin path without needing the ocpasswd
		// binary, which is not present on a dev machine.
		AuthMode: api.AuthCert,
		StaticIP: "10.20.0.7",
	}); err != nil {
		t.Fatalf("create client: %v", err)
	}

	path := filepath.Join(m.perUserDir("oc-test"), "phone-abc123")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("per-user config not written: %v", err)
	}
	if !strings.Contains(string(b), "explicit-ipv4 = 10.20.0.7") {
		t.Errorf("per-user config = %q, want the pinned address", b)
	}

	// The instance config must actually point ocserv at that directory.
	conf, err := os.ReadFile(m.configPath("oc-test"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(conf), "config-per-user = "+m.perUserDir("oc-test")) {
		t.Errorf("instance config does not declare config-per-user:\n%s", conf)
	}

	// A changed address must converge, not stay create-only.
	if _, err := m.PatchClient(ctx, "oc-test", "phone-abc123", map[string]any{
		"static_ip": "10.20.0.9",
	}); err != nil {
		t.Fatalf("patch: %v", err)
	}
	b, _ = os.ReadFile(path)
	if !strings.Contains(string(b), "explicit-ipv4 = 10.20.0.9") {
		t.Errorf("after patch = %q, want the new address", b)
	}

	// Deleting must drop the pin, or a recycled common name inherits it.
	if err := m.DeleteClient("oc-test", "phone-abc123"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("per-user config survived delete (err=%v)", err)
	}
}
