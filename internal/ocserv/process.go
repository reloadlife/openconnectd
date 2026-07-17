package ocserv

import (
	"fmt"
	"os/exec"
	"sync"
	"syscall"
)

// Supervisor runs one ocserv process per instance directly (no systemd
// coupling): the daemon owns ocserv. Reload is SIGHUP — ocserv re-reads its
// config and CRL without dropping live sessions. When ocserv is not installed,
// Start returns an error the manager records as Up=false; it does not stop the
// rest of the daemon from working (state, PKI, config all still function).
//
// ponytail: no internal crash-restart loop yet. The control-plane reconcile
// loop re-applies desired state on a ticker and will restart a dead instance;
// add a supervised restart here if that proves too slow.
type Supervisor struct {
	bin string // ocserv binary; "" ⇒ resolved from PATH

	mu    sync.Mutex
	procs map[string]*exec.Cmd
}

func NewSupervisor(bin string) *Supervisor {
	return &Supervisor{bin: bin, procs: map[string]*exec.Cmd{}}
}

// Start launches `ocserv -f -c <configPath>` for instance. Idempotent: if the
// instance is already running, it is a no-op.
func (s *Supervisor) Start(instance, configPath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.procs[instance]; ok && alive(c) {
		return nil
	}
	bin := s.bin
	if bin == "" {
		p, err := exec.LookPath("ocserv")
		if err != nil {
			return fmt.Errorf("ocserv: binary not found (install ocserv): %w", err)
		}
		bin = p
	}
	// -f foreground (we supervise it), -c config.
	cmd := exec.Command(bin, "-f", "-c", configPath)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("ocserv start %q: %w", instance, err)
	}
	s.procs[instance] = cmd
	// Reap on exit so alive() reflects reality and we do not leak zombies.
	go func() { _ = cmd.Wait() }()
	return nil
}

// Reload sends SIGHUP so ocserv re-reads config + CRL without dropping sessions.
func (s *Supervisor) Reload(instance string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.procs[instance]
	if !ok || !alive(c) {
		return fmt.Errorf("ocserv reload %q: not running", instance)
	}
	return c.Process.Signal(syscall.SIGHUP)
}

// Stop sends SIGTERM and forgets the instance.
func (s *Supervisor) Stop(instance string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.procs[instance]
	if !ok {
		return nil
	}
	delete(s.procs, instance)
	if alive(c) {
		return c.Process.Signal(syscall.SIGTERM)
	}
	return nil
}

// Running reports whether the instance process is alive.
func (s *Supervisor) Running(instance string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.procs[instance]
	return ok && alive(c)
}

// alive is true while the process exists and has not exited.
func alive(c *exec.Cmd) bool {
	if c == nil || c.Process == nil {
		return false
	}
	if c.ProcessState != nil && c.ProcessState.Exited() {
		return false
	}
	// Signal 0 probes existence without delivering anything.
	return c.Process.Signal(syscall.Signal(0)) == nil
}
