# Operating openconnectd on a host

This is the on-host runbook: what to install, how the daemon is wired, and the
security-relevant choices.

## Prerequisites

- Linux with `ocserv` and `occtl` installed (`ocpasswd` too, for password auth).
  Debian/Ubuntu: `apt-get install -y ocserv`.
- The kernel `tun` module and IP forwarding enabled for the VPN to route:
  `sysctl -w net.ipv4.ip_forward=1` (persist in `/etc/sysctl.d/`).
- Go 1.25+ to build, or ship the prebuilt binary.

## Install

```sh
go build -o /usr/local/bin/openconnectd ./cmd/openconnectd
install -d -m 700 /etc/openconnectd /var/lib/openconnectd /run/openconnectd
cp configs/openconnectd.yaml.example /etc/openconnectd/openconnectd.yaml
cp deploy/systemd/openconnectd.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now openconnectd
```

## Configuration

All settings and their loopback-only defaults are in
[`configs/openconnectd.yaml.example`](../configs/openconnectd.yaml.example). The
daemon owns four directories:

- `pki_dir` — client CA, issued certs, CRL, dev server cert.
- `config_dir` — one rendered `ocserv.conf` per instance.
- `state_dir` — `state.json` (instances + clients) and per-instance `ocpasswd`.
- `run_dir` — the ocserv control (`occtl`) and run sockets.

### Token

Leave `token: ""` to have the daemon generate one on first boot into
`token_file`. Your automation reads that file. The API is loopback-bound, but
the token is defence-in-depth for anything else on the host.

## The server certificate (important)

Each instance gets a **self-signed** server cert as a dev fallback so it boots
without external input. In production this is not what you want:

- **Camouflage only convinces if the TLS cert looks legitimate.** A self-signed
  cert on `vpn.example.com` is a tell. Point the instance's `server-cert` /
  `server-key` at a real certificate — Let's Encrypt for `public_endpoint` is
  ideal — so a probe sees a normal, trusted HTTPS site.
- Client-cert auth is unaffected: the client CA (which verifies *users*) is
  always the daemon's own and is separate from the server cert (which clients
  verify).

## Networking & firewall

- ocserv listens on the instance's `listen` (TCP 443, plus UDP 443 when
  `dtls`). Expose those to clients; keep the openconnectd API port
  (`51990`) firewalled to loopback.
- Behind Cloudflare/tunnels: OpenConnect needs raw TLS passthrough on 443, not
  an HTTP proxy that terminates TLS. If a proxy fronts it, use TCP/SNI
  passthrough (e.g. a `spectrum`/L4 route), not an HTTP origin rule.
- Each instance creates a `tun` device named `oc-<instance>` (truncated to the
  15-char interface limit). Deleting the instance stops ocserv and removes it.

## Lifecycle notes

- **Reload without dropping sessions:** `PATCH`ing an instance or revoking a
  client re-renders config / regenerates the CRL and sends ocserv `SIGHUP`;
  live tunnels stay up.
- **Restart recovery:** on boot the daemon reconciles every enabled instance
  from `state.json`, so a daemon or host restart brings the fleet back.
- **Revocation is a file:** ocserv reads `crl.pem`. Deleting a client adds its
  serial to the CRL and reloads; the cert stops working immediately.

## Health checks

```sh
curl -s http://127.0.0.1:51990/healthz            # ok
curl -s http://127.0.0.1:51990/v1/version         # confirms ocserv is present
systemctl status openconnectd
journalctl -u openconnectd -f
```
