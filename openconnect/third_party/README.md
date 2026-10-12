# Vendored dependencies

## sing-openconnect

`github.com/sagernet/sing-openconnect` v0.1.0 (GPL-3.0, see its LICENSE),
wired in through a `replace` directive in `../go.mod`. Unmodified except:

- `sshtool_session.go` (new): `Client.SessionCookie()`, the AnyConnect
  session cookie of the tunnel that is up.
- `anyconnect_auth.go`: `ConnectTunnel` records that cookie after a
  successful CSTP connect (one line, marked "ssh-tool patch").
- `dtls_mtu.go`: the MTU probe reads into a 64 KiB buffer instead of one
  sized to the probe; a bigger datagram arriving during the probe (data,
  a gateway probe) made the read fail with "buffer is too small" and the
  tunnel start without DTLS.

The plugin uses it for session reuse: the app keeps the cookie in memory
and passes it back (`SSHTOOL_OC_COOKIE`) on the next connect, and an idle
stop detaches without the CSTP disconnect that would end the session.

To update: copy the new upstream release over this directory and re-apply
the changes above (grep "ssh-tool patch").
