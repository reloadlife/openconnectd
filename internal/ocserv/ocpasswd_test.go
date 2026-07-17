package ocserv

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

func TestOcpasswdListAndDelete(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "ocpasswd")
	seed := "alice:vpn:hashA\nbob:vpn:hashB\n# a comment\ncarol:vpn:hashC\n"
	if err := os.WriteFile(file, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	o := NewOcpasswd("", file)

	users, err := o.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(users)
	if got, want := users, []string{"alice", "bob", "carol"}; !slices.Equal(got, want) {
		t.Fatalf("users = %v, want %v", got, want)
	}

	if err := o.DeleteUser("bob"); err != nil {
		t.Fatal(err)
	}
	users, _ = o.ListUsers()
	sort.Strings(users)
	if got := users; !slices.Equal(got, []string{"alice", "carol"}) {
		t.Errorf("after delete users = %v", got)
	}
	// The comment line must survive the rewrite.
	data, _ := os.ReadFile(file)
	if !strings.Contains(string(data), "# a comment") {
		t.Errorf("comment line lost on rewrite:\n%s", data)
	}
}

func TestOcpasswdListMissingFile(t *testing.T) {
	o := NewOcpasswd("", filepath.Join(t.TempDir(), "nope"))
	users, err := o.ListUsers()
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("expected no users, got %v", users)
	}
	if err := o.DeleteUser("ghost"); err != nil {
		t.Errorf("delete on missing file should be no-op: %v", err)
	}
}

func TestOcpasswdSetWithoutToolErrors(t *testing.T) {
	// No ocpasswd binary on the dev/CI box ⇒ a clear error, not a panic.
	o := NewOcpasswd("/nonexistent/ocpasswd", filepath.Join(t.TempDir(), "ocpasswd"))
	err := o.SetPassword(context.Background(), "alice", "vpn", "s3cret")
	if err == nil {
		t.Fatal("expected error when ocpasswd binary is missing")
	}
}
