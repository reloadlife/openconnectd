// Package state persists openconnectd's instances and provisioned clients to a
// single JSON file. It is the daemon's source of truth for desired config; the
// ocserv process is reconstructed from it on boot. Live session data is NOT
// stored here — that is read from occtl at query time.
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/reloadlife/openconnectd/pkg/api"
)

// Store is a mutex-guarded, file-backed record set. Every mutation writes the
// whole file — fine at this scale (tens of instances, thousands of clients),
// and it keeps the on-disk form trivially inspectable.
//
// ponytail: whole-file rewrite on each change. Swap for per-record files or a
// KV store only if write volume ever makes this hurt.
type Store struct {
	path string
	mu   sync.RWMutex
	data data
}

type data struct {
	Instances map[string]api.Instance              `json:"instances"`
	Clients   map[string]map[string]api.ClientPeer `json:"clients"` // [instance][cn]
}

// Open loads the store from path, creating an empty one if absent.
func Open(path string) (*Store, error) {
	s := &Store{
		path: path,
		data: data{
			Instances: map[string]api.Instance{},
			Clients:   map[string]map[string]api.ClientPeer{},
		},
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &s.data); err != nil {
			return nil, fmt.Errorf("state: parse %s: %w", path, err)
		}
	}
	if s.data.Instances == nil {
		s.data.Instances = map[string]api.Instance{}
	}
	if s.data.Clients == nil {
		s.data.Clients = map[string]map[string]api.ClientPeer{}
	}
	return s, nil
}

// --- instances ---

func (s *Store) PutInstance(in api.Instance) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Instances[in.Name] = in
	if s.data.Clients[in.Name] == nil {
		s.data.Clients[in.Name] = map[string]api.ClientPeer{}
	}
	return s.flushLocked()
}

func (s *Store) GetInstance(name string) (api.Instance, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	in, ok := s.data.Instances[name]
	return in, ok
}

func (s *Store) ListInstances() []api.Instance {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]api.Instance, 0, len(s.data.Instances))
	for _, in := range s.data.Instances {
		out = append(out, in)
	}
	return out
}

func (s *Store) DeleteInstance(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data.Instances, name)
	delete(s.data.Clients, name)
	return s.flushLocked()
}

// --- clients ---

func (s *Store) PutClient(instance string, c api.ClientPeer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data.Instances[instance]; !ok {
		return fmt.Errorf("state: unknown instance %q", instance)
	}
	if s.data.Clients[instance] == nil {
		s.data.Clients[instance] = map[string]api.ClientPeer{}
	}
	s.data.Clients[instance][c.CommonName] = c
	return s.flushLocked()
}

func (s *Store) GetClient(instance, cn string) (api.ClientPeer, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.data.Clients[instance][cn]
	return c, ok
}

func (s *Store) ListClients(instance string) []api.ClientPeer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := s.data.Clients[instance]
	out := make([]api.ClientPeer, 0, len(m))
	for _, c := range m {
		out = append(out, c)
	}
	return out
}

func (s *Store) DeleteClient(instance, cn string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m := s.data.Clients[instance]; m != nil {
		delete(m, cn)
	}
	return s.flushLocked()
}

// CountClients returns provisioned client count for an instance.
func (s *Store) CountClients(instance string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.data.Clients[instance])
}

// flushLocked writes the whole store atomically (temp file + rename). Caller
// holds the write lock.
func (s *Store) flushLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
