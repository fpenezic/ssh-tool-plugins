# Helper protocol (version 1)

How ssh-tool talks to a plugin process. Everything is line-delimited
JSON: events on the helper's stdout, commands on its stdin. stderr is
free-form log text the app copies into its own log.

## Start

The app runs the helper with plugin-specific flags (`--help` lists them)
and passes secrets through the environment, never argv (argv is visible
in the process list):

| Plugin | Variable | Meaning |
| --- | --- | --- |
| netbird | `SSHTOOL_NB_SETUP_KEY` | setup key, first registration only |
| tailscale | `SSHTOOL_TS_AUTHKEY` | auth key, first registration only |
| openconnect | `SSHTOOL_OC_CERT`, `SSHTOOL_OC_KEY` | client certificate chain and key, PEM |
| openconnect | `SSHTOOL_OC_KEY_PASSWORD` | password of an encrypted key (optional) |
| openconnect | `SSHTOOL_OC_SESSION` | `1` = report the session cookie (`session` event); AnyConnect only |
| openconnect | `SSHTOOL_OC_COOKIE` | session cookie from an earlier, detached run to resume with |
| openconnect | `SSHTOOL_OC_DEBUG` | `1` = the VPN engine's debug log on stderr |
| openvpn | `SSHTOOL_OVPN_CONFIG` | the .ovpn configuration, every file inline |
| checkpoint | `SSHTOOL_CP_DEBUG` | `1` = log the login and tunnel exchange on stderr |

`--version` prints the release tag the binary was built from and exits.
`--check` (openvpn) validates `SSHTOOL_OVPN_CONFIG` and prints one
`{"event":"check","remotes":[..],"auth_user_pass":..,"static_challenge":"..",
"client_cert":..,"tls_wrap":"..","warnings":[..]}` line, or an `error`.

## Events (stdout)

```json
{"event":"ready","socks":"127.0.0.1:PORT","protocol":1}
```
The network is up and the SOCKS5 proxy listens. `protocol` is this
document's version; the app refuses a helper outside the range it speaks.

```json
{"event":"status","peers":3,"transport":"dtls"}
```
Heartbeat, about every 15 s. Fields are optional per plugin.

```json
{"event":"info","info":{"addresses":["10.0.0.5/32"],"routes":[...],"dns":[...],"mtu":1340,"transport":"dtls"}}
```
Tunnel details for the app's Details view; sent at start and whenever
they change (openconnect, openvpn, checkpoint).

```json
{"event":"auth","id":"1","banner":"..","message":"..","error":"..",
 "fields":[{"key":"main:username:1","name":"username","label":"Username:","kind":"text","value":"","options":[]}]}
```
A login form to answer (openconnect, openvpn, checkpoint). The OpenVPN
and Check Point plugins ask with fields named `username`, `password` and
`response` (the answer to a static or dynamic challenge, or to a further
Check Point login factor; usually a one-time code). `kind` is `text`, `password` or
`select` (with `options`). `error` is set when the gateway rejected the
previous answer. The app answers with an `auth` command, or `cancel`.

```json
{"event":"session","cookie":".."}
```
The session cookie, sent once the tunnel is up and again if a later
login replaces it (openconnect, with `SSHTOOL_OC_SESSION=1`). A bearer
credential for the gateway session: the app keeps it in memory only and
passes it back in `SSHTOOL_OC_COOKIE`. A cookie the gateway no longer
knows makes the helper fall back to a normal login (`auth` events).

```json
{"event":"error","error":"..","cert_pin":"pin-sha256:..","cert_subject":"CN=..","cert_changed":false}
```
Fatal; the helper exits after it. The `cert_*` fields mean the gateway
certificate is not trusted: the app may ask the user and restart the
helper with that pin accepted. `"unreachable": true` (openconnect) means
the gateway did not answer at all (no TLS handshake within 10 seconds), so
the app may start the helper again with the profile's next gateway; any
other error, a rejected login above all, is not retried elsewhere.

```json
{"event":"open_url","url":"https://.."}
```
A login page for the user's browser (openvpn: the server holds the login
open until it is done there). Only http(s).

## Commands (stdin)

```json
{"cmd":"auth","id":"1","values":{"main:username:1":"alice"}}
{"cmd":"cancel"}
{"cmd":"detach"}
```

`detach` (openconnect) exits without ending the session at the gateway,
so it can be resumed with the cookie; closing stdin logs out. A helper
that does not know `detach` ignores it, and the app falls back to
closing stdin.

Closing stdin (EOF) shuts the helper down cleanly.

## Compatibility

Additions (new events, new optional fields, new commands) keep the
version at 1; a reader ignores what it does not know. A change that an
older app would misread bumps the version, and the release tag major with
it.
