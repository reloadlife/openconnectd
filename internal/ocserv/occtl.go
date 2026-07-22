package ocserv

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/reloadlife/openconnectd/pkg/api"
)

// Occtl reads live state from a running ocserv via its occtl control socket and
// disconnects sessions. Each instance has its own socket (occtl-socket-file in
// the rendered config).
type Occtl struct {
	bin string // occtl binary; "" ⇒ resolved from PATH
}

func NewOcctl(bin string) *Occtl { return &Occtl{bin: bin} }

// flexUint parses a JSON value that may be a number or a numeric string.
// occtl's -j output gives RX/TX as raw byte counts, but versions differ on
// whether they are quoted, so accept both.
type flexUint uint64

func (f *flexUint) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	// Tolerate a trailing unit if a version ever emits one ("1234 bytes").
	if i := strings.IndexByte(s, ' '); i > 0 {
		s = s[:i]
	}
	n, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("occtl: bad numeric %q: %w", s, err)
	}
	*f = flexUint(n)
	return nil
}

type rawSession struct {
	ID           json.Number `json:"ID"`
	Username     string      `json:"Username"`
	Vhost        string      `json:"vhost"`
	Device       string      `json:"Device"`
	RemoteIP     string      `json:"Remote IP"`
	IPv4         string      `json:"IPv4"`
	RX           flexUint    `json:"RX"`
	TX           flexUint    `json:"TX"`
	RawConnected json.Number `json:"raw_connected_at"`
	UserAgent    string      `json:"User-Agent"`
	DTLSCipher   string      `json:"DTLS-CIPHER"`
	Session      string      `json:"Session"`
}

// ShowUsers runs `occtl -j -s <socket> show users` and returns the parsed
// sessions. A socket with no daemon (instance down) yields an error the caller
// can treat as "no sessions" rather than fatal.
func (o *Occtl) ShowUsers(ctx context.Context, socket string) ([]api.Session, error) {
	out, err := o.run(ctx, socket, "show", "users")
	if err != nil {
		return nil, err
	}
	out = strings.TrimSpace(out)
	if out == "" || out == "[]" {
		return nil, nil
	}
	var raw []rawSession
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("occtl: parse show users: %w", err)
	}
	return parseSessions(raw), nil
}

// Disconnect kicks a user's session(s) by username.
func (o *Occtl) Disconnect(ctx context.Context, socket, username string) error {
	if strings.TrimSpace(username) == "" {
		return fmt.Errorf("occtl: username required")
	}
	_, err := o.run(ctx, socket, "disconnect", "user", username)
	return err
}

func (o *Occtl) run(ctx context.Context, socket string, args ...string) (string, error) {
	bin := o.bin
	if bin == "" {
		p, err := exec.LookPath("occtl")
		if err != nil {
			return "", fmt.Errorf("occtl: tool not found (install ocserv): %w", err)
		}
		bin = p
	}
	full := []string{"-j"}
	if socket != "" {
		full = append(full, "-s", socket)
	}
	full = append(full, args...)
	out, err := exec.CommandContext(ctx, bin, full...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("occtl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// parseSessions converts occtl's raw JSON into api.Session. Exported logic path
// kept pure so it is unit-testable against fixtures without occtl present.
func parseSessions(raw []rawSession) []api.Session {
	out := make([]api.Session, 0, len(raw))
	for _, r := range raw {
		s := api.Session{
			CommonName: r.Username,
			VPNAddress: r.IPv4,
			Device:     r.Device,
			RemoteIP:   r.RemoteIP,
			RxBytes:    uint64(r.RX),
			TxBytes:    uint64(r.TX),
			UserAgent:  r.UserAgent,
			DTLS:       dtlsActive(r.DTLSCipher),
			SessionID:  r.Session,
		}
		if r.RawConnected != "" {
			if n, err := strconv.ParseInt(string(r.RawConnected), 10, 64); err == nil && n > 0 {
				s.ConnectedAt = time.Unix(n, 0).UTC()
			}
		}
		out = append(out, s)
	}
	return out
}

func dtlsActive(cipher string) bool {
	c := strings.ToLower(strings.TrimSpace(cipher))
	return c != "" && c != "(none)" && c != "none"
}

// rawBan is one row of `occtl -j show ip bans` / `show ip ban points`.
// Score is a JSON number in every version seen, but flexUint's tolerance costs
// nothing and the field has already changed shape once across releases.
type rawBan struct {
	IP    string   `json:"IP"`
	Since string   `json:"Since"`
	Score flexUint `json:"Score"`
}

// ShowIPBans returns the IPs ocserv is currently refusing.
func (o *Occtl) ShowIPBans(ctx context.Context, socket string) ([]api.Ban, error) {
	out, err := o.run(ctx, socket, "show", "ip", "bans")
	if err != nil {
		return nil, err
	}
	return parseBans([]byte(out), true)
}

// ShowIPBanPoints returns IPs accruing score that are not blocked yet — the
// early warning for a credential-stuffing run against one account.
func (o *Occtl) ShowIPBanPoints(ctx context.Context, socket string) ([]api.Ban, error) {
	out, err := o.run(ctx, socket, "show", "ip", "ban", "points")
	if err != nil {
		return nil, err
	}
	return parseBans([]byte(out), false)
}

// UnbanIP clears one address. occtl reports "could not unban" on an address it
// is not holding; that is surfaced rather than swallowed so the UI cannot show
// a successful unban that did nothing.
func (o *Occtl) UnbanIP(ctx context.Context, socket, ip string) error {
	if strings.TrimSpace(ip) == "" {
		return fmt.Errorf("occtl: ip required")
	}
	out, err := o.run(ctx, socket, "unban", "ip", ip)
	if err != nil {
		return err
	}
	if strings.Contains(strings.ToLower(out), "could not unban") {
		return fmt.Errorf("occtl: %s is not banned on this instance", ip)
	}
	return nil
}

// parseBans decodes an occtl ban list. banned marks which list it came from,
// since the two share a shape but not a meaning.
//
// occtl emits a trailing comma before the closing bracket ("},\n]"), which is
// not valid JSON and which encoding/json refuses outright. Stripping it is the
// whole reason this is a function rather than a plain Unmarshal.
func parseBans(out []byte, banned bool) ([]api.Ban, error) {
	s := strings.TrimSpace(string(out))
	if s == "" {
		return nil, nil
	}
	s = trailingCommaRE.ReplaceAllString(s, "$1")
	if s == "[]" {
		return nil, nil
	}
	var raw []rawBan
	if err := json.Unmarshal([]byte(s), &raw); err != nil {
		return nil, fmt.Errorf("occtl: parse ban list: %w", err)
	}
	bans := make([]api.Ban, 0, len(raw))
	for _, r := range raw {
		if strings.TrimSpace(r.IP) == "" {
			continue
		}
		bans = append(bans, api.Ban{
			IP:     r.IP,
			Score:  int(r.Score),
			Banned: banned,
			Since:  strings.TrimSpace(r.Since),
		})
	}
	return bans, nil
}

// trailingCommaRE matches a comma that is followed only by whitespace and a
// closing bracket or brace.
var trailingCommaRE = regexp.MustCompile(`,(\s*[\]}])`)
