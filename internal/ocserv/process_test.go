package ocserv

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeOcserv writes a script that ignores ocserv's args (-f -c <cfg>) and just
// sleeps, so the supervisor's start/running/stop lifecycle can be exercised
// without a real ocserv.
func fakeOcserv(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-ocserv")
	script := "#!/bin/sh\nexec sleep 30\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSupervisorLifecycle(t *testing.T) {
	s := NewSupervisor(fakeOcserv(t))
	if s.Running("edge1") {
		t.Fatal("running before start")
	}
	if err := s.Start("edge1", "/tmp/edge1.conf"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !s.Running("edge1") {
		t.Fatal("not running after start")
	}
	// Start again is idempotent.
	if err := s.Start("edge1", "/tmp/edge1.conf"); err != nil {
		t.Fatalf("second Start: %v", err)
	}

	if err := s.Stop("edge1"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	// Give Wait() a moment to reap.
	deadline := time.Now().Add(2 * time.Second)
	for s.Running("edge1") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if s.Running("edge1") {
		t.Fatal("still running after stop")
	}
}

func TestSupervisorStartMissingBinary(t *testing.T) {
	s := NewSupervisor("/nonexistent/ocserv")
	if err := s.Start("edge1", "/tmp/x.conf"); err == nil {
		t.Fatal("expected error starting a missing binary")
	}
	if s.Running("edge1") {
		t.Error("instance marked running despite failed start")
	}
}

func TestSupervisorReloadNotRunning(t *testing.T) {
	s := NewSupervisor(fakeOcserv(t))
	if err := s.Reload("ghost"); err == nil {
		t.Fatal("expected error reloading a non-running instance")
	}
	if err := s.Stop("ghost"); err != nil {
		t.Errorf("Stop on unknown instance should be no-op: %v", err)
	}
}
