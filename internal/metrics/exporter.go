// Package metrics exposes openconnectd state as Prometheus text. It pulls from a
// Source (the ocserv manager) at scrape time — no background collection, no
// client library, just the standard exposition format on a loopback port.
package metrics

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/reloadlife/openconnectd/pkg/api"
)

// Source is the slice of the manager the exporter needs. The manager satisfies
// it; keeping it an interface avoids a hard dependency and makes the renderer
// testable with a fake.
type Source interface {
	ListInstances() []api.Instance
	Sessions(ctx context.Context, instance string) ([]api.Session, error)
}

// Handler returns an http.Handler serving GET /metrics.
func Handler(src Source) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		Render(ctx, src, w)
	})
}

// Render writes the full exposition to w. Exported for testing.
func Render(ctx context.Context, src Source, w io.Writer) {
	var b strings.Builder

	help(&b, "openconnect_instance_up", "gauge", "1 if the ocserv instance process is up.")
	help(&b, "openconnect_instance_sessions", "gauge", "Currently connected sessions per instance.")
	help(&b, "openconnect_instance_clients", "gauge", "Provisioned clients per instance.")
	help(&b, "openconnect_user_rx_bytes_total", "counter", "Bytes received from the client (server← client).")
	help(&b, "openconnect_user_tx_bytes_total", "counter", "Bytes sent to the client (server→ client).")
	help(&b, "openconnect_session_dtls", "gauge", "1 if the session is on the DTLS (UDP) fast path.")

	instances := src.ListInstances()
	sort.Slice(instances, func(i, j int) bool { return instances[i].Name < instances[j].Name })

	sessions, _ := src.Sessions(ctx, "")
	byInstance := map[string]int{}
	for _, s := range sessions {
		byInstance[s.InstanceName]++
	}

	for _, in := range instances {
		lbl := labels("instance", in.Name)
		metric(&b, "openconnect_instance_up", lbl, bit(in.Up))
		metric(&b, "openconnect_instance_sessions", lbl, float64(byInstance[in.Name]))
		metric(&b, "openconnect_instance_clients", lbl, float64(in.ClientCount))
	}

	// Stable per-user series ordering keeps scrapes diff-friendly.
	sort.Slice(sessions, func(i, j int) bool {
		if sessions[i].InstanceName != sessions[j].InstanceName {
			return sessions[i].InstanceName < sessions[j].InstanceName
		}
		return sessions[i].CommonName < sessions[j].CommonName
	})
	for _, s := range sessions {
		lbl := labels("instance", s.InstanceName, "common_name", s.CommonName)
		metric(&b, "openconnect_user_rx_bytes_total", lbl, float64(s.RxBytes))
		metric(&b, "openconnect_user_tx_bytes_total", lbl, float64(s.TxBytes))
		metric(&b, "openconnect_session_dtls", lbl, bit(s.DTLS))
	}

	_, _ = io.WriteString(w, b.String())
}

func help(b *strings.Builder, name, typ, text string) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", name, text, name, typ)
}

func metric(b *strings.Builder, name, labels string, v float64) {
	fmt.Fprintf(b, "%s%s %g\n", name, labels, v)
}

// labels builds a {k="v",...} block with Prometheus value escaping.
func labels(kv ...string) string {
	if len(kv) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i+1 < len(kv); i += 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `%s="%s"`, kv[i], escapeLabel(kv[i+1]))
	}
	b.WriteByte('}')
	return b.String()
}

func escapeLabel(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(s)
}

func bit(v bool) float64 {
	if v {
		return 1
	}
	return 0
}
