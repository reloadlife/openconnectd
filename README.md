# openconnectd

A daemon that manages **[ocserv](https://ocserv.gitlab.io/www/index.html)** —
the OpenConnect / Cisco AnyConnect-compatible SSL VPN server — behind a small,
loopback-only REST API. It owns everything ocserv needs on a host: config, PKI,
per-user provisioning, process lifecycle, revocation, live sessions, and
Prometheus metrics. A terminal UI ships in the same binary for hands-on ops.

Point any automation at the REST API (or import the Go client in
[`pkg/api`](pkg/api)) to run OpenConnect servers and users declaratively.

## Why OpenConnect

OpenConnect speaks TLS on port 443 and looks like ordinary HTTPS, so it survives
deep-packet-inspection that fingerprints and blocks OpenVPN or WireGuard by
protocol shape. On top of that, ocserv has native **camouflage**: an
unauthenticated probe gets a normal-looking web response (a 404 or a decoy page),
and only a client presenting the secret path ever reaches the VPN. That defeats
*active-probing* DPI as well, not just passive fingerprinting.

## Features

| Area | State |
|------|-------|
| `pkg/api` contract (types + HTTP client) | ✅ |
| `ocserv.conf` rendering (camouflage, auth modes, pool, routes) | ✅ |
| PKI — client CA, per-user certs, CRL revocation, server-cert fallback | ✅ |
| Password auth (`ocpasswd`) | ✅ |
| Process supervision — start / SIGHUP reload / stop, reconcile-on-boot | ✅ |
| State persistence (atomic JSON) | ✅ |
| Full instance / client REST API + `client-config` | ✅ |
| Live sessions + disconnect (`occtl`) | ✅ |
| Prometheus `/metrics` exporter | ✅ |
| TUI ops dashboard | ✅ |

See [docs/DESIGN.md](docs/DESIGN.md) for the architecture.

## Install

Requires Go 1.25+ and, on the host, `ocserv` + `occtl` (and `ocpasswd` for
password auth):

```sh
apt-get install -y ocserv          # Debian/Ubuntu
go build -o openconnectd ./cmd/openconnectd
```

## Run

```sh
openconnectd --version
openconnectd --config /etc/openconnectd/openconnectd.yaml   # API on 127.0.0.1:51990
openconnectd tui                                            # terminal dashboard
```

The daemon binds **loopback only** by design; it is never exposed publicly. See
[configs/openconnectd.yaml.example](configs/openconnectd.yaml.example) for all
settings, [deploy/systemd/openconnectd.service](deploy/systemd/openconnectd.service)
for the unit, and [docs/OPERATIONS.md](docs/OPERATIONS.md) for the runbook.

## API at a glance

Loopback REST, bearer-authed (except `/healthz`). Full reference with request/
response shapes in [docs/API.md](docs/API.md).

```
GET    /healthz
GET    /v1/version
GET    /v1/instances                                       list servers
POST   /v1/instances                                       create a server
GET    /v1/instances/{name}
PATCH  /v1/instances/{name}                                mutate + SIGHUP reload
DELETE /v1/instances/{name}
GET    /v1/instances/{name}/clients                        list users
POST   /v1/instances/{name}/clients                        provision a user
PATCH  /v1/instances/{name}/clients/{cn}                   static ip / suspend / password
DELETE /v1/instances/{name}/clients/{cn}                   revoke + remove
GET    /v1/instances/{name}/clients/{cn}/client-config     importable profile
GET    /v1/sessions[?instance=]                            live connections (occtl)
DELETE /v1/instances/{name}/sessions/{cn}                  kick a session
GET    /metrics                                            Prometheus exposition
```

### Quick tour

```sh
B=http://127.0.0.1:51990

# a camouflaged, cert-auth server on 443 with a /24 pool
curl -s -X POST $B/v1/instances -d '{
  "name": "edge1",
  "pool_cidr": "10.20.0.0/24",
  "public_endpoint": "vpn.example.com:443",
  "dns": ["1.1.1.1"],
  "camouflage": {"enabled": true, "secret": "a-long-random-path"}
}'

# provision a user (a client cert is minted)
curl -s -X POST $B/v1/instances/edge1/clients -d '{"common_name": "alice"}'

# fetch alice's importable cert bundle
curl -s $B/v1/instances/edge1/clients/alice/client-config

# who is connected right now?
curl -s $B/v1/sessions

# revoke + remove alice (cert lands in the CRL, ocserv reloads it)
curl -s -X DELETE $B/v1/instances/edge1/clients/alice
```

## Authentication

Instances default to **cert-primary** (`auth_mode: cert`); a user's credential
is chosen per-client:

- **cert** — a per-instance CA mints a per-user X.509 cert; the cert CN is the
  stable username. Revocation is via CRL. Best AnyConnect UX.
- **password** — `ocpasswd` file. Simplest to provision.
- **both** — ocserv requires cert *and* password.

## Monitoring

`GET /metrics` exposes Prometheus text — per-instance `up`/session counts and
per-user `rx`/`tx` counters sourced from `occtl`. Bind the exporter on a
separate loopback port (`metrics_listen`, default `127.0.0.1:9093`) and scrape it
from your Prometheus.

## TUI

`openconnectd tui` opens a terminal dashboard against the running daemon:
instances with health, live sessions (user / remote IP / rx-tx / duration /
DTLS), and one-key actions (kick a session, toggle an instance). Point it at a
remote daemon with `--url` / `--token`.

## Security model

- The API is loopback-only and bearer-token gated (constant-time compare).
- Client CA / server cert / CRL / password files live under the daemon's own
  `pki_dir` / `state_dir`, mode `0600`/`0700`.
- The self-signed server cert is a **dev fallback**; in production point
  `server-cert` at a real (e.g. Let's Encrypt) fullchain so camouflage presents
  a genuinely trusted site.

## Project layout

```
pkg/api/                 public contract: types.go + client.go
internal/ocserv/         the driver: config, pki, ocpasswd, process, occtl, manager
internal/state/          instance + client persistence (atomic JSON)
internal/httpapi/        REST server (stdlib net/http, bearer auth)
internal/metrics/        Prometheus exporter
internal/tui/            terminal ops dashboard
internal/config/         daemon settings, loopback defaults
cmd/openconnectd/        entrypoint (serve, tui)
docs/                    DESIGN.md, API.md, OPERATIONS.md
deploy/systemd/          service unit
```

## Development

```sh
go test ./...          # unit + end-to-end (no ocserv required)
go test -race ./...
go vet ./... && gofmt -l .
```

Tests run fully without ocserv installed — the contract, provisioning, config
rendering, and occtl parsing are exercised against fixtures and temp dirs.
