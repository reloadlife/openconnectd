package ocserv

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"
)

func TestIssueClientChainsToCA(t *testing.T) {
	p := NewPKI(t.TempDir())
	caCert, err := p.EnsureCA("edge1")
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}

	issued, err := p.IssueClient("edge1", "alice", 0)
	if err != nil {
		t.Fatalf("IssueClient: %v", err)
	}
	if issued.Serial == "" || issued.NotAfter.Before(time.Now()) {
		t.Fatalf("bad issued cert: %+v", issued)
	}

	// The client cert must verify against the CA.
	block, _ := pem.Decode([]byte(issued.CertPEM))
	clientCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse client cert: %v", err)
	}
	if clientCert.Subject.CommonName != "alice" {
		t.Errorf("CN = %q, want alice", clientCert.Subject.CommonName)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := clientCert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("client cert does not chain to CA: %v", err)
	}

	// Bundle carries cert + key + ca.
	for _, want := range []string{"-----BEGIN CERTIFICATE-----", "-----BEGIN RSA PRIVATE KEY-----"} {
		if !strings.Contains(issued.BundlePEM, want) {
			t.Errorf("bundle missing %q", want)
		}
	}
}

func TestEnsureCAIsStable(t *testing.T) {
	p := NewPKI(t.TempDir())
	a, err := p.EnsureCA("edge1")
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.EnsureCA("edge1") // second call must not regenerate
	if err != nil {
		t.Fatal(err)
	}
	if a.SerialNumber.Cmp(b.SerialNumber) != 0 {
		t.Errorf("EnsureCA regenerated the CA: %v != %v", a.SerialNumber, b.SerialNumber)
	}
}

func TestRevokeAppearsInCRL(t *testing.T) {
	p := NewPKI(t.TempDir())
	if _, err := p.EnsureCA("edge1"); err != nil {
		t.Fatal(err)
	}
	issued, err := p.IssueClient("edge1", "bob", 0)
	if err != nil {
		t.Fatal(err)
	}

	if p.IsRevoked("edge1", issued.Serial) {
		t.Fatal("cert revoked before RevokeClient")
	}
	if err := p.RevokeClient("edge1", issued.Serial); err != nil {
		t.Fatalf("RevokeClient: %v", err)
	}
	if !p.IsRevoked("edge1", issued.Serial) {
		t.Error("serial not marked revoked")
	}

	// Parse the CRL and confirm the serial is listed.
	crlPEM, err := os.ReadFile(p.CRLPath("edge1"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(crlPEM)
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	found := false
	for _, e := range crl.RevokedCertificateEntries {
		if e.SerialNumber.Text(16) == issued.Serial {
			found = true
		}
	}
	if !found {
		t.Error("revoked serial not present in CRL")
	}

	// Revoking again is a no-op success (idempotent).
	if err := p.RevokeClient("edge1", issued.Serial); err != nil {
		t.Errorf("second RevokeClient errored: %v", err)
	}
}

func TestEnsureServerCertFallback(t *testing.T) {
	p := NewPKI(t.TempDir())
	if err := p.EnsureServerCert("edge1", []string{"vpn.example.com"}); err != nil {
		t.Fatalf("EnsureServerCert: %v", err)
	}
	if !fileExists(p.ServerCertPath("edge1")) || !fileExists(p.ServerKeyPath("edge1")) {
		t.Fatal("server cert/key not written")
	}
	// Idempotent: second call keeps the same cert.
	before, _ := os.ReadFile(p.ServerCertPath("edge1"))
	if err := p.EnsureServerCert("edge1", []string{"vpn.example.com"}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(p.ServerCertPath("edge1"))
	if string(before) != string(after) {
		t.Error("EnsureServerCert regenerated an existing cert")
	}
}
