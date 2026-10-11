# ssh-tool plugins

Optional VPN sidecars for [ssh-tool](https://github.com/fpenezic/ssh-tool).
Each plugin is a small standalone program the app starts per network
profile. It joins the network entirely in userspace (no TUN adapter, no
admin rights, no system routes) and hands the app a loopback SOCKS5 proxy
that SSH connections dial through.

They live outside the app because each one pulls in a large dependency
tree (and in one case a GPL licence) that only users of that network
need. ssh-tool downloads them on demand from this repository's releases
(Settings -> Network profiles -> Plugins) and verifies the sha256 digest
before installing.

| Plugin | Directory | Networks | Engine | Licence |
| --- | --- | --- | --- | --- |
| `ssh-tool-netbird` | [`netbird/`](netbird) | NetBird (cloud or self-hosted) | [netbirdio/netbird](https://github.com/netbirdio/netbird) client | Apache-2.0 |
| `ssh-tool-tailscale` | [`tailscale/`](tailscale) | Tailscale, Headscale | [tailscale.com/tsnet](https://pkg.go.dev/tailscale.com/tsnet) | Apache-2.0 |
| `ssh-tool-openconnect` | [`openconnect/`](openconnect) | Cisco AnyConnect / ocserv, Fortinet, F5, GlobalProtect, Pulse / Ivanti, Juniper NC | [sagernet/sing-openconnect](https://github.com/sagernet/sing-openconnect) | GPL-3.0-or-later |

Each directory is its own Go module with its own `LICENSE`. The
OpenConnect plugin is GPL because its engine is; it talks to the app only
over the process boundary described in [PROTOCOL.md](PROTOCOL.md), so the
app itself stays Apache-2.0.

## Releases

Every plugin is released on its own tag:

- `netbird-vN[.P]`, `tailscale-vN[.P]`, `openconnect-vN[.P]`
- `N` is the helper protocol major the build speaks (see PROTOCOL.md);
  the app only installs releases whose `N` it understands.
- `.P` is a rebuild of the same protocol (dependency updates, fixes).
  Release tags are immutable: a fix is always a new `.P`, never a re-tag.

A tag push builds the plugin for linux-amd64, linux-arm64 and
windows-amd64 and publishes `ssh-tool-<plugin>-<os>-<arch>[.exe]` assets.
Releases are never marked "Latest".

Older app versions (before the move to this repository) fetch the
NetBird and Tailscale helpers from `helper-vN` releases in the app
repository; those stay published.

## Building locally

```bash
cd openconnect && CGO_ENABLED=0 go build -o ssh-tool-openconnect .
cd tailscale && CGO_ENABLED=0 go build -o ssh-tool-tailscale .
cd netbird && go build -o ssh-tool-netbird .   # CGO; Windows cross-build needs Zig, see the workflow
```

Put the binary next to the ssh-tool executable (or in its plugins
directory) and the app picks it up.
