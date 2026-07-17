# openconnectd — design

A daemon that manages **ocserv** (OpenConnect / Cisco AnyConnect-compatible SSL
VPN) on a host and exposes a loopback REST API. Any automation drives it through
a small typed client under `pkg/api`; a terminal UI ships in the same binary.

openconnectd owns everything ocserv needs — config, PKI, per-user provisioning,
process lifecycle, revocation, live session metrics — so nothing else has to
touch ocserv directly.

## Why OpenConnect

OpenConnect rides TLS on 443 and looks like ordinary HTTPS, so it survives DPI
that fingerprints OpenVPN/WireGuard by protocol shape. On top of that, ocserv
has native **camouflage**: unauthenticated probes get a normal-looking web
response (404 or a decoy page) and only clients that present a secret path reach
the VPN — defeating active-probing DPI too.

## Architecture

```
caller ──HTTP(loopback, bearer)──▶ openconnectd ──▶ ocserv
                                        │            (config + SIGHUP)
                                        ├─ occtl socket (live sessions, disconnect)
                                        ├─ PKI (CA + per-user certs, CRL)
                                        └─ /metrics (Prometheus)
```

The caller never touches ocserv; it speaks only to the daemon's REST API. The
daemon owns everything under its state/config/pki/run directories.

## Repo layout

```
cmd/openconnectd/       # flags, config load, HTTP server, TUI subcommand
pkg/api/                # PUBLIC contract: types.go + client.go
internal/
  httpapi/              # stdlib net/http routes, bearer auth, handlers
  ocserv/               # the driver
    config.go           # ocserv.conf renderer (camouflage, auth, pool)
    version.go          # resolve ocserv binary + version
    process.go          # start/stop/reload (SIGHUP), supervision
    occtl.go            # control-socket client: live sessions, disconnect
    pki.go              # CA + per-user cert issue/revoke (CRL)
    ocpasswd.go         # password-auth store
    manager.go          # ties the driver to persisted state
  state/                # instance + client records, persisted JSON
  metrics/              # occtl → Prometheus exporter
  tui/                  # terminal ops dashboard
  config/               # daemon settings
configs/openconnectd.yaml.example
deploy/systemd/openconnectd.service
```

## Contract (`pkg/api`)

- **Instance** — one ocserv server (an ingress). `Listen`, `DTLS` (UDP fast path
  on the same port), `PoolCIDR`(+v6), `PublicEndpoint`, `LocalBind`, `AuthMode`,
  `Camouflage`, `DNS`, `Routes`, `Enabled`/`Up`.
- **ClientPeer** — a provisioned user identity (cert CN / ocserv username),
  independent of connection state. Carries `AuthMode`, `StaticIP`, `Suspended`,
  `CertSerial`/`CertExpiry`.
- **Session** — a *live* connection from occtl: `VPNAddress`, `RemoteIP`,
  `RxBytes`/`TxBytes`, `ConnectedAt`, `UserAgent`, `DTLS`. Kept separate from
  ClientPeer on purpose — one is provisioned identity, the other is live state.
- **Camouflage** — `Enabled`, `Secret`, `Realm`, `DecoyHTML`.
- **AuthMode** — `cert` (default) | `password` | `both`.

Client methods: `Health`, `Version`, instance CRUD, client CRUD, `ClientConfig`,
`Sessions`, `Disconnect`. Full REST surface in [API.md](API.md).

## Authentication (cert-primary + password fallback)

- **cert** (default): a per-instance CA signs a per-user client cert; the cert
  CN is the stable user id (`cert-user-oid = 2.5.4.3`). Revocation via CRL.
- **password**: `ocpasswd` file; simplest provisioning.
- **both**: ocserv requires cert AND password.

`client-config` returns an importable profile: for cert users, the cert + key +
CA bundle; for password users, a server descriptor.

## ocserv.conf rendering

`InstanceConfig.Render()` is pure and unit-tested. It maps high-level fields to
ocserv directives: `auth`/`enable-auth`, `ca-cert`, `cert-user-oid`, `crl`,
`tcp-port`/`udp-port`, `listen-host`, `server-cert`/`server-key`,
`ipv4-network`+`ipv4-netmask` (CIDR split — ocserv wants a dotted mask), `dns`,
`route` (omitted ⇒ full tunnel), `camouflage`/`camouflage_secret`/
`camouflage_realm`, `max-clients`, `cisco-client-compat`, socket paths, device.

## Process management

`process.go` supervises one ocserv process per instance directly (no systemd
coupling): start (`ocserv -f -c <config>`), SIGHUP reload (ocserv re-reads
config + CRL without dropping sessions), stop. `Up` is observed from the process
state. A missing ocserv does not stop the rest of the daemon (state, PKI, config
all still function); it just reports `Up=false`.

## Live sessions & monitoring

`occtl.go` shells to `occtl -j -s <socket>` to read connected users and to
disconnect them. `Manager.Sessions` fans out across instance sockets and returns
the combined `[]Session`; `Disconnect` kicks by common name.

The `/metrics` exporter polls the same source and emits Prometheus text:
per-instance `openconnect_instance_up` / `openconnect_instance_sessions` and
per-user `openconnect_user_rx_bytes_total` / `openconnect_user_tx_bytes_total`
(+ `openconnect_session_dtls`). It binds a separate loopback port so Prometheus
scrapes it without touching the admin API.

## TUI

`openconnectd tui` is a terminal dashboard (bubbletea) that drives the running
daemon through `pkg/api`: instances with health, live sessions (user / remote IP
/ rx-tx / duration / DTLS), and one-key actions (kick a session, toggle an
instance). It is a thin API client, so it works against a local or remote daemon.

## State

`state/store.go` persists instances and provisioned clients to a single atomic
JSON file — the source of truth for desired config. Live session data is NOT
stored; it is read from occtl at query time. On boot the manager reconciles every
enabled instance from state, so a restart brings the fleet back.

## Testing

Pure logic (config render, CIDR split, PKI serial/CRL, occtl JSON parsing,
password-file ops) is covered by table tests that need neither root nor ocserv.
Anything requiring a live ocserv is exercised on a throwaway host.
