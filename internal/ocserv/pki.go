package ocserv

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PKI manages the per-instance client CA, per-user client certificates, the
// CRL, and a dev-fallback self-signed server certificate. Layout under root:
//
//	<root>/<instance>/ca.pem  ca.key
//	                  crl.pem  revoked.json
//	                  server.pem  server.key      (dev fallback only)
//	                  clients/<cn>.pem  <cn>.key
//
// Keys are RSA-2048 for broad AnyConnect/OpenConnect client compatibility.
type PKI struct {
	root string
}

func NewPKI(root string) *PKI { return &PKI{root: root} }

const (
	caTTL     = 10 * 365 * 24 * time.Hour
	serverTTL = 2 * 365 * 24 * time.Hour
	// DefaultClientTTL is used when IssueClient gets ttl<=0.
	DefaultClientTTL = 365 * 24 * time.Hour
)

func (p *PKI) dir(instance string) string     { return filepath.Join(p.root, instance) }
func (p *PKI) CACertPath(i string) string     { return filepath.Join(p.dir(i), "ca.pem") }
func (p *PKI) caKeyPath(i string) string      { return filepath.Join(p.dir(i), "ca.key") }
func (p *PKI) CRLPath(i string) string        { return filepath.Join(p.dir(i), "crl.pem") }
func (p *PKI) revokedPath(i string) string    { return filepath.Join(p.dir(i), "revoked.json") }
func (p *PKI) ServerCertPath(i string) string { return filepath.Join(p.dir(i), "server.pem") }
func (p *PKI) ServerKeyPath(i string) string  { return filepath.Join(p.dir(i), "server.key") }

// IssuedCert is the result of minting a client certificate.
type IssuedCert struct {
	// BundlePEM is client cert + client key + CA cert, concatenated — everything
	// a client needs to import.
	BundlePEM string
	CertPEM   string
	KeyPEM    string
	Serial    string // hex, matches the on-disk client file name
	NotAfter  time.Time
}

// EnsureCA loads the instance CA, creating it on first use. Returns the parsed
// CA certificate.
func (p *PKI) EnsureCA(instance string) (*x509.Certificate, error) {
	if err := os.MkdirAll(p.dir(instance), 0o700); err != nil {
		return nil, err
	}
	if cert, _, err := p.loadCA(instance); err == nil {
		return cert, nil
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               pkix.Name{CommonName: "openconnectd CA " + instance},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(caTTL),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	if err := writePEM(p.CACertPath(instance), "CERTIFICATE", der, 0o644); err != nil {
		return nil, err
	}
	if err := writePEM(p.caKeyPath(instance), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key), 0o600); err != nil {
		return nil, err
	}
	// Seed an empty CRL so ocserv always has a file to read.
	if err := p.writeCRL(instance, nil); err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// IssueClient mints a client certificate with CN=commonName, signed by the
// instance CA. ttl<=0 uses DefaultClientTTL.
func (p *PKI) IssueClient(instance, commonName string, ttl time.Duration) (*IssuedCert, error) {
	if strings.TrimSpace(commonName) == "" {
		return nil, fmt.Errorf("pki: common name required")
	}
	caCert, caKey, err := p.loadCA(instance)
	if err != nil {
		return nil, err
	}
	if ttl <= 0 {
		ttl = DefaultClientTTL
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial := newSerial()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	certPEM := pemString("CERTIFICATE", der)
	keyPEM := pemString("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key))
	caPEM, err := os.ReadFile(p.CACertPath(instance))
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(p.dir(instance), "clients"), 0o700); err != nil {
		return nil, err
	}
	hexSerial := serial.Text(16)
	base := filepath.Join(p.dir(instance), "clients", hexSerial)
	if err := os.WriteFile(base+".pem", []byte(certPEM), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(base+".key", []byte(keyPEM), 0o600); err != nil {
		return nil, err
	}
	return &IssuedCert{
		BundlePEM: certPEM + keyPEM + string(caPEM),
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		Serial:    hexSerial,
		NotAfter:  tmpl.NotAfter,
	}, nil
}

// ClientBundle reassembles a previously-issued client's cert + key + CA from
// disk (by hex serial). Used by the client-config endpoint so the importable
// profile can be re-fetched without re-issuing.
func (p *PKI) ClientBundle(instance, hexSerial string) (string, error) {
	base := filepath.Join(p.dir(instance), "clients", hexSerial)
	cert, err := os.ReadFile(base + ".pem")
	if err != nil {
		return "", fmt.Errorf("pki: client cert %s not found: %w", hexSerial, err)
	}
	key, err := os.ReadFile(base + ".key")
	if err != nil {
		return "", fmt.Errorf("pki: client key %s not found: %w", hexSerial, err)
	}
	ca, err := os.ReadFile(p.CACertPath(instance))
	if err != nil {
		return "", err
	}
	return string(cert) + string(key) + string(ca), nil
}

// RevokeClient adds a serial to the revocation set and regenerates the CRL.
// Idempotent: revoking an already-revoked serial is a no-op success.
func (p *PKI) RevokeClient(instance, hexSerial string) error {
	revoked, err := p.loadRevoked(instance)
	if err != nil {
		return err
	}
	if _, ok := revoked[hexSerial]; ok {
		return nil
	}
	revoked[hexSerial] = time.Now()
	if err := p.saveRevoked(instance, revoked); err != nil {
		return err
	}
	return p.regenCRL(instance, revoked)
}

// IsRevoked reports whether a serial is in the CRL set.
func (p *PKI) IsRevoked(instance, hexSerial string) bool {
	revoked, err := p.loadRevoked(instance)
	if err != nil {
		return false
	}
	_, ok := revoked[hexSerial]
	return ok
}

// EnsureServerCert writes a self-signed server cert if none exists. This is a
// DEV fallback — in production a real/LE fullchain is supplied and these paths
// point at it instead, so camouflage presents a trusted site.
func (p *PKI) EnsureServerCert(instance string, hosts []string) error {
	if fileExists(p.ServerCertPath(instance)) && fileExists(p.ServerKeyPath(instance)) {
		return nil
	}
	if err := os.MkdirAll(p.dir(instance), 0o700); err != nil {
		return err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	cn := instance
	if len(hosts) > 0 {
		cn = hosts[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(serverTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     hosts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	if err := writePEM(p.ServerCertPath(instance), "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	return writePEM(p.ServerKeyPath(instance), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key), 0o600)
}

// --- internals ---

func (p *PKI) loadCA(instance string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(p.CACertPath(instance))
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(p.caKeyPath(instance))
	if err != nil {
		return nil, nil, err
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, nil, fmt.Errorf("pki: corrupt CA files for %q", instance)
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, err := x509.ParsePKCS1PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func (p *PKI) regenCRL(instance string, revoked map[string]time.Time) error {
	return p.writeCRL(instance, revoked)
}

func (p *PKI) writeCRL(instance string, revoked map[string]time.Time) error {
	caCert, caKey, err := p.loadCA(instance)
	if err != nil {
		return err
	}
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for hexSerial, when := range revoked {
		n, ok := new(big.Int).SetString(hexSerial, 16)
		if !ok {
			continue
		}
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   n,
			RevocationTime: when,
		})
	}
	tmpl := &x509.RevocationList{
		Number:                    newSerial(),
		ThisUpdate:                time.Now().Add(-time.Hour),
		NextUpdate:                time.Now().Add(30 * 24 * time.Hour),
		RevokedCertificateEntries: entries,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, caCert, caKey)
	if err != nil {
		return err
	}
	return writePEM(p.CRLPath(instance), "X509 CRL", der, 0o644)
}

func (p *PKI) loadRevoked(instance string) (map[string]time.Time, error) {
	out := map[string]time.Time{}
	data, err := os.ReadFile(p.revokedPath(instance))
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (p *PKI) saveRevoked(instance string, revoked map[string]time.Time) error {
	data, err := json.MarshalIndent(revoked, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p.revokedPath(instance), data, 0o600)
}

func newSerial() *big.Int {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		// rand.Reader failing is fatal for crypto; fall back to time-ish value
		// that is still unique enough not to collide in practice.
		return big.NewInt(time.Now().UnixNano())
	}
	return n
}

func pemString(typ string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), mode)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
