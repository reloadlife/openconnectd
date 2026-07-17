package ocserv

import (
	"strings"
	"testing"

	"github.com/reloadlife/openconnectd/pkg/api"
)

func baseCfg() InstanceConfig {
	return InstanceConfig{
		Name:        "edge1",
		TCPPort:     443,
		UDPPort:     443,
		PoolCIDR:    "10.10.10.0/24",
		DNS:         []string{"1.1.1.1"},
		AuthMode:    api.AuthCert,
		ServerCert:  "/etc/oc/edge1/fullchain.pem",
		ServerKey:   "/etc/oc/edge1/privkey.pem",
		CACert:      "/etc/oc/edge1/ca.pem",
		OcctlSocket: "/run/oc/edge1.occtl",
		RunSocket:   "/run/oc/edge1.sock",
		Device:      "oc-edge1",
	}
}

func mustRender(t *testing.T, c InstanceConfig) string {
	t.Helper()
	out, err := c.Render()
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return out
}

func TestRenderCertAuthAndPool(t *testing.T) {
	out := mustRender(t, baseCfg())
	want := []string{
		`auth = "certificate"`,
		"ca-cert = /etc/oc/edge1/ca.pem",
		"cert-user-oid = 2.5.4.3",
		"tcp-port = 443",
		"udp-port = 443",
		"ipv4-network = 10.10.10.0",    // CIDR split → network
		"ipv4-netmask = 255.255.255.0", // …+ dotted mask, not /24
		"dns = 1.1.1.1",
		"cisco-client-compat = true",
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("config missing %q\n---\n%s", w, out)
		}
	}
}

func TestCamouflageRequiresSecret(t *testing.T) {
	c := baseCfg()
	c.Camouflage = api.Camouflage{Enabled: true} // no secret
	if _, err := c.Render(); err == nil {
		t.Fatal("expected error: camouflage enabled without secret")
	}

	c.Camouflage.Secret = "s3cr3t-path"
	c.Camouflage.Realm = "Cloud"
	out := mustRender(t, c)
	for _, w := range []string{"camouflage = true", `camouflage_secret = "s3cr3t-path"`, `camouflage_realm = "Cloud"`} {
		if !strings.Contains(out, w) {
			t.Errorf("camouflage config missing %q\n%s", w, out)
		}
	}
}

func TestDTLSOffOmitsUDPPort(t *testing.T) {
	c := baseCfg()
	c.UDPPort = 0
	out := mustRender(t, c)
	if strings.Contains(out, "udp-port") {
		t.Errorf("DTLS off but udp-port present:\n%s", out)
	}
}

func TestCertAuthNeedsCA(t *testing.T) {
	c := baseCfg()
	c.CACert = ""
	if _, err := c.Render(); err == nil {
		t.Fatal("expected error: cert auth without CA")
	}
}

func TestPasswordAuthNoCA(t *testing.T) {
	c := baseCfg()
	c.AuthMode = api.AuthPassword
	c.CACert = ""
	c.OcpasswdFile = "/etc/oc/edge1/ocpasswd"
	out := mustRender(t, c)
	if !strings.Contains(out, `auth = "plain[passwd=/etc/oc/edge1/ocpasswd]"`) {
		t.Errorf("password auth line wrong:\n%s", out)
	}
	if strings.Contains(out, "ca-cert") {
		t.Errorf("password-only should not set ca-cert:\n%s", out)
	}
}

func TestFullTunnelWhenNoRoutes(t *testing.T) {
	out := mustRender(t, baseCfg())
	if strings.Contains(out, "\nroute = ") {
		t.Errorf("no routes given ⇒ expected full tunnel, got explicit route:\n%s", out)
	}
}
