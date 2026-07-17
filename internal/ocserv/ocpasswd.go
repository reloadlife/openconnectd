package ocserv

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Ocpasswd manages an ocserv "plain" auth password file. Setting a password
// shells out to the ocserv `ocpasswd` tool rather than hand-rolling
// sha512-crypt — reimplementing password hashing is exactly the kind of crypto
// you do not want to get subtly wrong. Reads and deletions are plain file ops.
//
// File format (per ocpasswd): "username:groupname:hash" per line.
type Ocpasswd struct {
	bin  string // ocpasswd binary; "" ⇒ resolved from PATH at call time
	file string
}

func NewOcpasswd(bin, file string) *Ocpasswd { return &Ocpasswd{bin: bin, file: file} }

// SetPassword creates or updates a user via the ocpasswd tool. group may be "".
// The password is piped on stdin twice (ocpasswd reads it, then a confirmation)
// which works when stdin is not a terminal.
func (o *Ocpasswd) SetPassword(ctx context.Context, user, group, password string) error {
	if strings.TrimSpace(user) == "" {
		return fmt.Errorf("ocpasswd: user required")
	}
	bin := o.bin
	if bin == "" {
		p, err := exec.LookPath("ocpasswd")
		if err != nil {
			return fmt.Errorf("ocpasswd: tool not found (install ocserv): %w", err)
		}
		bin = p
	}
	args := []string{"-c", o.file}
	if group != "" {
		args = append(args, "-g", group)
	}
	args = append(args, user)
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = strings.NewReader(password + "\n" + password + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ocpasswd set %q: %w: %s", user, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// DeleteUser removes a user by rewriting the file without their line. No-op if
// the file or user is absent.
func (o *Ocpasswd) DeleteUser(user string) error {
	users, lines, err := o.read()
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if _, ok := users[user]; !ok {
		return nil
	}
	kept := lines[:0]
	for _, ln := range lines {
		if lineUser(ln) == user {
			continue
		}
		kept = append(kept, ln)
	}
	return o.writeLines(kept)
}

// ListUsers returns the usernames in the file (empty when the file is absent).
func (o *Ocpasswd) ListUsers() ([]string, error) {
	users, _, err := o.read()
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]string, 0, len(users))
	for u := range users {
		out = append(out, u)
	}
	return out, nil
}

func (o *Ocpasswd) read() (map[string]struct{}, []string, error) {
	f, err := os.Open(o.file)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	users := map[string]struct{}{}
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ln := sc.Text()
		lines = append(lines, ln)
		if u := lineUser(ln); u != "" {
			users[u] = struct{}{}
		}
	}
	return users, lines, sc.Err()
}

func (o *Ocpasswd) writeLines(lines []string) error {
	var b strings.Builder
	for _, ln := range lines {
		b.WriteString(ln)
		b.WriteByte('\n')
	}
	return os.WriteFile(o.file, []byte(b.String()), 0o600)
}

func lineUser(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return ""
	}
	if i := strings.IndexByte(line, ':'); i > 0 {
		return line[:i]
	}
	return ""
}
