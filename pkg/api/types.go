// Package api is the public contract for openconnectd: the wire types and a
// thin HTTP client. An orchestrator imports THIS package (never internal/...)
// to drive the daemon.
//
// openconnectd manages ocserv (OpenConnect/Cisco AnyConnect-compatible SSL VPN)
// on a node. The shapes below model instances (servers) and clients (users),
// with ocserv-specific bits (DTLS, camouflage, auth mode) as first-class fields.
package api

import "time"

// VersionInfo is returned by GET /v1/version.
type VersionInfo struct {
	Version    string `json:"version"`
	Commit     string `json:"commit,omitempty"`
	OcservPath string `json:"ocserv_path,omitempty"` // resolved ocserv binary
	OcservVer  string `json:"ocserv_version,omitempty"`
}

// AuthMode selects how a user proves identity to ocserv.
//
// ocserv can require cert, password, or "cert+password" (both). We default new
// instances to cert-primary with an optional password fallback per user; the
// per-user Client.AuthMode picks which credential that user actually uses.
type AuthMode string

const (
	AuthCert     AuthMode = "cert"     // X.509 client certificate (PKI)
	AuthPassword AuthMode = "password" // username/password via ocpasswd
	AuthBoth     AuthMode = "both"     // cert AND password required
)

// Camouflage is ocserv's anti-active-probing feature. When enabled, ocserv
// answers unauthenticated probes as an ordinary HTTPS site (a 404 or the decoy
// page) and only reveals the VPN to clients that present the secret path. This
// is what lets OpenConnect survive DPI that fingerprints VPNs by probing them.
type Camouflage struct {
	Enabled bool `json:"enabled"`
	// Secret is the URL path segment a real client must use, e.g. a client
	// connecting to https://host/?secret=<Secret>. Probes without it see a
	// normal web server. Empty when Enabled is false.
	Secret string `json:"secret,omitempty"`
	// Realm is the HTTP Basic realm/label shown to probes (cosmetic blending).
	Realm string `json:"realm,omitempty"`
	// DecoyHTML, if set, is served verbatim to unauthenticated probes instead
	// of a bare 404 — a more convincing "this is just a website" response.
	DecoyHTML string `json:"decoy_html,omitempty"`
}

// Instance is one ocserv server (an ingress endpoint).
type Instance struct {
	Name string `json:"name"`

	// Listen is the public bind, "0.0.0.0:443" or ":443". ocserv serves CSTP
	// over TCP here and (when DTLS is true) DTLS over UDP on the same port.
	Listen string `json:"listen,omitempty"`
	DTLS   bool   `json:"dtls"` // enable UDP/DTLS fast path alongside TCP

	// PoolCIDR is the client address pool, e.g. "10.10.10.0/24".
	PoolCIDR   string `json:"pool_cidr,omitempty"`
	PoolCIDRv6 string `json:"pool_cidr_v6,omitempty"`

	// PublicEndpoint is the hostname clients dial (also the cert SAN + the
	// camouflage decoy's apparent site), e.g. "vpn.example.com:443".
	PublicEndpoint string `json:"public_endpoint,omitempty"`
	// LocalBind pins ocserv to one host IP on multi-IP nodes.
	LocalBind string `json:"local_bind,omitempty"`

	AuthMode   AuthMode   `json:"auth_mode,omitempty"`
	Camouflage Camouflage `json:"camouflage"`

	// DNS and Routes are pushed to connected clients.
	DNS    []string `json:"dns,omitempty"`
	Routes []string `json:"routes,omitempty"` // empty ⇒ default route (full tunnel)

	Enabled bool `json:"enabled"`
	Up      bool `json:"up"` // process alive + listening (observed)

	ClientCount  int `json:"client_count,omitempty"`  // provisioned users
	SessionCount int `json:"session_count,omitempty"` // currently connected
}

// InstanceCreateRequest is POST /v1/instances.
type InstanceCreateRequest struct {
	Name           string      `json:"name"`
	Listen         string      `json:"listen"` // ":443" default if empty
	DTLS           *bool       `json:"dtls,omitempty"`
	PoolCIDR       string      `json:"pool_cidr,omitempty"`
	PoolCIDRv6     string      `json:"pool_cidr_v6,omitempty"`
	PublicEndpoint string      `json:"public_endpoint,omitempty"`
	LocalBind      string      `json:"local_bind,omitempty"`
	AuthMode       AuthMode    `json:"auth_mode,omitempty"` // default AuthCert
	Camouflage     *Camouflage `json:"camouflage,omitempty"`
	DNS            []string    `json:"dns,omitempty"`
	Routes         []string    `json:"routes,omitempty"`
	Enabled        *bool       `json:"enabled,omitempty"`
	// CreateCAIfEmpty mints a server CA named "default" when the node has none,
	// so the first instance works without a separate PKI bootstrap call.
	CreateCAIfEmpty bool `json:"create_ca_if_empty,omitempty"`
}

// ClientPeer is a provisioned user (identity), independent of whether they are
// currently connected. For a live connection see Session. Named ClientPeer
// (not Client) to avoid colliding with the HTTP Client.
type ClientPeer struct {
	Name         string   `json:"name"`        // display name
	CommonName   string   `json:"common_name"` // cert CN / ocserv username (stable id)
	InstanceName string   `json:"instance_name,omitempty"`
	AuthMode     AuthMode `json:"auth_mode,omitempty"`
	StaticIP     string   `json:"static_ip,omitempty"` // pin a pool address
	Enabled      bool     `json:"enabled"`
	Suspended    bool     `json:"suspended,omitempty"` // over quota / disabled, cert not revoked
	// CertSerial + CertExpiry populated for cert/both auth.
	CertSerial string     `json:"cert_serial,omitempty"`
	CertExpiry *time.Time `json:"cert_expiry,omitempty"`
}

// ClientCreateRequest is POST /v1/instances/{name}/clients.
type ClientCreateRequest struct {
	Name       string   `json:"name,omitempty"`
	CommonName string   `json:"common_name"` // required, stable id
	AuthMode   AuthMode `json:"auth_mode,omitempty"`
	StaticIP   string   `json:"static_ip,omitempty"`
	// Password sets the ocpasswd secret for password/both auth. Never returned
	// by the API on read. Ignored for cert-only clients.
	Password string `json:"password,omitempty"`
}

// Session is a live connection as reported by occtl. Read-only, sourced at
// query time from the control socket — this is the per-user monitoring signal.
type Session struct {
	CommonName   string    `json:"common_name"`
	InstanceName string    `json:"instance_name,omitempty"`
	VPNAddress   string    `json:"vpn_address,omitempty"` // assigned pool IP
	RemoteIP     string    `json:"remote_ip,omitempty"`   // client public IP
	RxBytes      uint64    `json:"rx_bytes"`              // server← client
	TxBytes      uint64    `json:"tx_bytes"`              // server→ client
	ConnectedAt  time.Time `json:"connected_at"`
	UserAgent    string    `json:"user_agent,omitempty"` // e.g. "AnyConnect ..."
	DTLS         bool      `json:"dtls"`                 // on the UDP fast path?
	SessionID    string    `json:"session_id,omitempty"`
}

// CA is a certificate authority managed by the daemon.
type CA struct {
	Name    string     `json:"name"`
	Subject string     `json:"subject,omitempty"`
	Expiry  *time.Time `json:"expiry,omitempty"`
}

// ErrorBody is the JSON error envelope.
type ErrorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}
