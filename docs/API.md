# openconnectd REST API

Loopback HTTP, JSON. Every route except `GET /healthz` requires
`Authorization: Bearer <token>` when a token is configured. Errors use a
uniform envelope:

```json
{ "error": { "code": "create_instance", "message": "pool_cidr required" } }
```

Status mapping: `404` not found, `409` already exists, `400` bad request /
missing field, `501` not implemented (sessions/disconnect until M2), `500`
otherwise.

The canonical Go client is [`pkg/api`](../pkg/api) — `api.NewClient(baseURL,
api.WithToken(tok))`.

---

## Meta

### `GET /healthz`
Liveness. `200 ok` (plain text). No auth.

### `GET /v1/version`
```json
{ "version": "0.2.0", "commit": "abc1234",
  "ocserv_path": "/usr/sbin/ocserv", "ocserv_version": "1.1.6" }
```
`ocserv_path`/`ocserv_version` are empty if ocserv is not installed — the
endpoint still answers, so a caller can detect a host missing ocserv.

---

## Instances (servers)

An **instance** is one ocserv server (an ingress endpoint).

### `GET /v1/instances`
Array of `Instance`. `up` reflects the live process; `client_count` is
provisioned users.

### `POST /v1/instances`
Body — `InstanceCreateRequest`:

| field | type | default | notes |
|-------|------|---------|-------|
| `name` | string | — | required, unique |
| `listen` | string | `":443"` | `"0.0.0.0:443"` or `":443"` |
| `dtls` | bool | `true` | UDP/DTLS fast path on the same port |
| `pool_cidr` | string | — | required, IPv4, e.g. `"10.20.0.0/24"` |
| `pool_cidr_v6` | string | — | optional |
| `public_endpoint` | string | — | host clients dial; also cert SAN + camouflage decoy site |
| `local_bind` | string | — | pin to one host IP on multi-IP nodes |
| `auth_mode` | `cert`\|`password`\|`both` | `cert` | |
| `camouflage` | object | off | `{enabled, secret, realm, decoy_html}` |
| `dns` | []string | — | pushed to clients |
| `routes` | []string | — | empty ⇒ full tunnel |
| `enabled` | bool | `true` | start on create |
| `create_ca_if_empty` | bool | `false` | mint the client CA even for password auth |

Returns `201` + `Instance`. `409` if the name exists.

### `GET /v1/instances/{name}` → `Instance` (`404` if absent)

### `PATCH /v1/instances/{name}`
JSON object of mutable fields: `local_bind`, `public_endpoint`, `enabled`,
`dtls`, `dns`, `routes`, `camouflage`. Re-renders config and **SIGHUP-reloads**
ocserv (no session drop). Returns the updated `Instance`.

### `DELETE /v1/instances/{name}`
Stops ocserv, removes the rendered config, drops state. `204`.

---

## Clients (users)

A **client** is a provisioned identity, independent of connection state.

### `GET /v1/instances/{name}/clients` → array of `ClientPeer`

### `POST /v1/instances/{name}/clients`
Body — `ClientCreateRequest`:

| field | type | notes |
|-------|------|-------|
| `common_name` | string | required, stable id (cert CN / username) |
| `name` | string | display name (defaults to CN) |
| `auth_mode` | `cert`\|`password`\|`both` | defaults to the instance's |
| `static_ip` | string | pin a pool address |
| `password` | string | required for `password`/`both`; never returned |

For cert/both, a client cert is minted and `cert_serial` + `cert_expiry` are
returned. `201` + `ClientPeer`. `409` if the CN exists, `404` if the instance
does not.

### `PATCH /v1/instances/{name}/clients/{cn}`
Mutable: `static_ip`, `suspended` (bool), `enabled` (bool), `password`.
Returns the updated `ClientPeer`.

### `DELETE /v1/instances/{name}/clients/{cn}`
Revokes the cert (adds it to the CRL, ocserv reloads), removes any password
entry, drops state. `204`.

### `GET /v1/instances/{name}/clients/{cn}/client-config`
`text/plain` — an importable profile. For cert users: a header with the connect
hint plus the client cert + key + CA (usable directly with
`openconnect --certificate=… --sslkey=…`). For password users: a connection
descriptor.

---

## Sessions (live) — M2

### `GET /v1/sessions[?instance=<name>]`
Array of `Session` (currently-connected users, from `occtl`): `common_name`,
`vpn_address`, `remote_ip`, `rx_bytes`, `tx_bytes`, `connected_at`,
`user_agent`, `dtls`. Returns `[]` until M2 lands.

### `DELETE /v1/instances/{name}/sessions/{cn}`
Kick a live session. `501` until M2.

---

## Types

See [`pkg/api/types.go`](../pkg/api/types.go) for the authoritative definitions
of `Instance`, `ClientPeer`, `Session`, `Camouflage`, `AuthMode`, and
`VersionInfo`.
