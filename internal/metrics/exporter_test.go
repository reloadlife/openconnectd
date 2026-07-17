package metrics

import (
	"context"
	"strings"
	"testing"

	"github.com/reloadlife/openconnectd/pkg/api"
)

type fakeSource struct {
	instances []api.Instance
	sessions  []api.Session
}

func (f fakeSource) ListInstances() []api.Instance { return f.instances }
func (f fakeSource) Sessions(ctx context.Context, instance string) ([]api.Session, error) {
	return f.sessions, nil
}

func TestRenderExposition(t *testing.T) {
	src := fakeSource{
		instances: []api.Instance{
			{Name: "edge1", Up: true, ClientCount: 3},
			{Name: "edge2", Up: false, ClientCount: 0},
		},
		sessions: []api.Session{
			{InstanceName: "edge1", CommonName: "alice", RxBytes: 100, TxBytes: 200, DTLS: true},
			{InstanceName: "edge1", CommonName: "bob", RxBytes: 5, TxBytes: 6, DTLS: false},
		},
	}
	var b strings.Builder
	Render(context.Background(), src, &b)
	out := b.String()

	want := []string{
		`openconnect_instance_up{instance="edge1"} 1`,
		`openconnect_instance_up{instance="edge2"} 0`,
		`openconnect_instance_sessions{instance="edge1"} 2`,
		`openconnect_instance_clients{instance="edge1"} 3`,
		`openconnect_user_rx_bytes_total{instance="edge1",common_name="alice"} 100`,
		`openconnect_user_tx_bytes_total{instance="edge1",common_name="bob"} 6`,
		`openconnect_session_dtls{instance="edge1",common_name="alice"} 1`,
		`openconnect_session_dtls{instance="edge1",common_name="bob"} 0`,
		"# TYPE openconnect_user_rx_bytes_total counter",
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("exposition missing %q\n---\n%s", w, out)
		}
	}
}

func TestLabelEscaping(t *testing.T) {
	got := labels("instance", `a"b\c`)
	if got != `{instance="a\"b\\c"}` {
		t.Errorf("escaping wrong: %s", got)
	}
}
