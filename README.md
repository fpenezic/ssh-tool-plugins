# ssh-tool plugins

Optional VPN sidecars for [ssh-tool](https://github.com/fpenezic/ssh-tool).
Each plugin is a small standalone program the app starts per network
profile. It joins the network entirely in userspace (no TUN adapter, no
admin rights, no system routes) and hands the app a loopback SOCKS5 proxy
that SSH connections dial through.

They live outside the app because each one pulls in a large dependency
tree (and in two cases a GPL-family licence) that only users of that network
need. ssh-tool downloads them on demand from this repository's releases
(Settings -> Network profiles -> Plugins) and verifies the sha256 digest
before installing.

| Plugin | Directory | Networks | Engine | Licence |
| --- | --- | --- | --- | --- |
| `ssh-tool-netbird` | [`netbird/`](netbird) | NetBird (cloud or self-hosted) | [netbirdio/netbird](https://github.com/netbirdio/netbird) client | Apache-2.0 |
| `ssh-tool-tailscale` | [`tailscale/`](tailscale) | Tailscale, Headscale | [tailscale.com/tsnet](https://pkg.go.dev/tailscale.com/tsnet) | Apache-2.0 |
| `ssh-tool-openconnect` | [`openconnect/`](openconnect) | Cisco AnyConnect / ocserv, Fortinet, F5, GlobalProtect, Pulse / Ivanti, Juniper NC | [sagernet/sing-openconnect](https://github.com/sagernet/sing-openconnect) (vendored with a small patch, see [`openconnect/third_party`](openconnect/third_party)) | GPL-3.0-or-later |
| `ssh-tool-openvpn` | [`openvpn/`](openvpn) | OpenVPN 2.x servers (OpenVPN Community / Access Server, pfSense, OPNsense, ...) | own client, [`openvpn/internal/ovpn`](openvpn/internal/ovpn) | Apache-2.0 |
| `ssh-tool-checkpoint` | [`checkpoint/`](checkpoint) | Check Point remote access gateways (SSL Network Extender tunnel, what Endpoint Security VPN and snx connect to) | own Go client based on [snx-rs](https://github.com/ancwrd1/snx-rs), [`checkpoint/internal/snx`](checkpoint/internal/snx) | AGPL-3.0 |

Each directory is its own Go module with its own `LICENSE`. The
OpenConnect plugin is GPL because its engine is, and the Check Point
plugin AGPL because its client is based on snx-rs; each talks to the app
only over the process boundary described in [PROTOCOL.md](PROTOCOL.md),
so the app itself stays Apache-2.0.

## Releases

Every plugin is released on its own tag:

- `netbird-vN[.P]`, `tailscale-vN[.P]`, `openconnect-vN[.P]`, `openvpn-vN[.P]`,
  `checkpoint-vN[.P]`
- `N` is the helper protocol major the build speaks (see PROTOCOL.md);
  the app only installs releases whose `N` it understands.
- `.P` is a rebuild of the same protocol (dependency updates, fixes).
  Release tags are immutable: a fix is always a new `.P`, never a re-tag.

A tag push builds the plugin for linux-amd64, linux-arm64 and
windows-amd64 and publishes `ssh-tool-<plugin>-<os>-<arch>[.exe]` assets.
The build waits on a vulnerability gate (`scripts/vulncheck.py`, govulncheck):
a Go vulnerability the plugin's code reaches, the standard library
included, stops the release. One without a fix yet is listed with its
reason in `<plugin>/.vulncheck-allow`.
Releases are never marked "Latest".

Older app versions (before the move to this repository) fetch the
NetBird and Tailscale helpers from `helper-vN` releases in the app
repository; those stay published.

## Building locally

```bash
cd openvpn && CGO_ENABLED=0 go build -o ssh-tool-openvpn .
cd checkpoint && CGO_ENABLED=0 go build -o ssh-tool-checkpoint .
cd openconnect && CGO_ENABLED=0 go build -o ssh-tool-openconnect .
cd tailscale && CGO_ENABLED=0 go build -o ssh-tool-tailscale .
cd netbird && go build -o ssh-tool-netbird .   # CGO; Windows cross-build needs Zig, see the workflow
```

Put the binary next to the ssh-tool executable (or in its plugins
directory) and the app picks it up.

## The OpenVPN client

`openvpn/internal/ovpn` is an OpenVPN 2.x client written for this plugin
(no OpenVPN code; the protocol, not the implementation, is shared). What
it speaks:

- UDP and TCP, several `remote` lines tried in order
- TLS 1.2 / 1.3 control channel, `tls-auth` (any `auth` digest, both key
  directions) and `tls-crypt`; not yet `tls-crypt-v2`
- data channel AES-128/192/256-GCM, ChaCha20-Poly1305, AES-CBC + HMAC,
  negotiated (`data-ciphers` / NCP) or fixed; P_DATA_V2 with peer id
- key renegotiation started by either side, with the old key kept for the
  transition window
- `auth-user-pass`, `static-challenge`, dynamic challenges (CRV1),
  pending logins (AUTH_PENDING: a CR_TEXT question, a WEB_AUTH /
  OPEN_URL browser login, a phone approval), `auth-token` for
  renegotiations and reconnects
- `remote-cert-tls server`, `verify-x509-name`
- servers that compress (`comp-lzo`, `compress lzo` / `lz4` / `lz4-v2`,
  stub framing): what the server compresses is unpacked; the client
  never compresses what it sends (VORACLE)
- ping / ping-restart, reconnects, exit notification on UDP

Not supported: TAP, `fragment`, PKCS#11 / PKCS#12 / system certificate
stores (import the key as PEM).

It is tested against OpenVPN 2.6 in every combination above, including
renegotiation under packet loss.

## The Check Point client

`checkpoint/internal/snx` is a Go client for Check Point remote access
gateways based on [snx-rs](https://github.com/ancwrd1/snx-rs) by Dmitry
Pankratov (AGPL-3.0): written from a study of its source rather than
translated, with its protocol handling, several of its values and some
of its test fixtures carried over (credited in the code), which is why
this plugin is AGPL-3.0. It speaks the SSL Network Extender tunnel, the
one Endpoint Security VPN falls back to and the `snx` command line client
uses:

- the CCC login over HTTPS (`/clients/`): gateway discovery
  (ClientHello: tunnel port, login options), username and password, and
  any further factor the gateway asks for (a one-time code, a second
  password) relayed to the app as a `response` field
- the SLIM tunnel over TLS on the gateway's tunnel port: office-mode
  address, DNS servers and search domains from the hello, keepalives,
  reconnect with the same session (asking to keep the address), a new
  login when the gateway has ended the session
- the routed ranges from the hello or, when it has none, from the client
  settings: the app shows them in Details and its local proxy sends
  those networks into this VPN
- gateways with a certificate from their own internal CA: the app pins
  it on first use (the `cert_pin` error event), as for OpenConnect

Not supported yet: certificate logins (`vpn_Personal_Certificate`,
certificate + password), browser (SAML / identity provider) logins,
Mobile Access, and the IPsec transport.

It is tested against a production Check Point gateway (username +
password realm) and, in `internal/snx`, against a fake gateway that
plays the login and the tunnel.
