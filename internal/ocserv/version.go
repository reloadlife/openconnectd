package ocserv

import (
	"context"
	"os/exec"
	"regexp"
	"strings"
)

var verRe = regexp.MustCompile(`(?i)ocserv\s+v?([0-9][0-9.]*)`)

// Resolve finds the ocserv binary (using bin if set, else PATH) and reads its
// version. A missing ocserv is not fatal to the daemon — /v1/version still
// answers so a caller can detect that the node lacks ocserv.
func Resolve(ctx context.Context, bin string) (path, version string) {
	if bin == "" {
		bin = "ocserv"
	}
	p, err := exec.LookPath(bin)
	if err != nil {
		return "", ""
	}
	out, err := exec.CommandContext(ctx, p, "--version").CombinedOutput()
	if err != nil {
		return p, ""
	}
	if m := verRe.FindStringSubmatch(string(out)); m != nil {
		return p, m[1]
	}
	return p, strings.TrimSpace(firstLine(string(out)))
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
