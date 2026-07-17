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
