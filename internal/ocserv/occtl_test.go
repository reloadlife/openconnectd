package ocserv

import (
	"encoding/json"
	"testing"
)

// A trimmed but representative `occtl -j show users` payload.
const sampleUsers = `[
  {
    "ID": 12,
    "Username": "alice",
    "vhost": "default",
    "Device": "oc-edge1",
    "Remote IP": "203.0.113.7",
    "IPv4": "10.20.0.5",
    "RX": 154892,
    "TX": "998877",
    "raw_connected_at": 1700000000,
    "User-Agent": "AnyConnect Darwin 4.10",
    "DTLS-CIPHER": "(DTLS1.2)-(ECDHE-RSA)-(AES-256-GCM)",
    "Session": "aBc123"
  },
  {
    "ID": 13,
    "Username": "bob",
    "IPv4": "10.20.0.6",
    "Remote IP": "198.51.100.9",
    "RX": 0,
    "TX": 0,
    "DTLS-CIPHER": "(none)"
  }
]`

func TestParseSessionsFromOcctlJSON(t *testing.T) {
	var raw []rawSession
	if err := json.Unmarshal([]byte(sampleUsers), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	sessions := parseSessions(raw)
	if len(sessions) != 2 {
		t.Fatalf("got %d sessions, want 2", len(sessions))
	}

	a := sessions[0]
	if a.CommonName != "alice" || a.VPNAddress != "10.20.0.5" || a.RemoteIP != "203.0.113.7" {
		t.Errorf("alice fields wrong: %+v", a)
	}
	if a.RxBytes != 154892 || a.TxBytes != 998877 { // TX came as a quoted string
		t.Errorf("alice rx/tx wrong: rx=%d tx=%d", a.RxBytes, a.TxBytes)
	}
	if !a.DTLS {
		t.Error("alice should be on DTLS")
	}
	if a.ConnectedAt.Unix() != 1700000000 {
		t.Errorf("alice connected_at = %v", a.ConnectedAt)
	}

	b := sessions[1]
	if b.DTLS {
		t.Error("bob DTLS-CIPHER=(none) should be DTLS=false")
	}
	if b.RxBytes != 0 || b.TxBytes != 0 {
		t.Errorf("bob rx/tx should be zero: %+v", b)
	}
}

func TestFlexUintForms(t *testing.T) {
	cases := map[string]uint64{
		`12345`:        12345,
		`"67890"`:      67890,
		`""`:           0,
		`null`:         0,
		`"1024 bytes"`: 1024,
	}
	for in, want := range cases {
		var f flexUint
		if err := f.UnmarshalJSON([]byte(in)); err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if uint64(f) != want {
			t.Errorf("%s → %d, want %d", in, uint64(f), want)
		}
	}
}
