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

`--version` prints the release tag the binary was built from and exits.

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
they change (openconnect).

```json
{"event":"auth","id":"1","banner":"..","message":"..","error":"..",
 "fields":[{"key":"main:username:1","name":"username","label":"Username:","kind":"text","value":"","options":[]}]}
```
A login form to answer (openconnect). `kind` is `text`, `password` or
`select` (with `options`). `error` is set when the gateway rejected the
previous answer. The app answers with an `auth` command, or `cancel`.

```json
{"event":"error","error":"..","cert_pin":"pin-sha256:..","cert_subject":"CN=..","cert_changed":false}
```
Fatal; the helper exits after it. The `cert_*` fields mean the gateway
certificate is not trusted: the app may ask the user and restart the
helper with that pin accepted.

## Commands (stdin)

```json
{"cmd":"auth","id":"1","values":{"main:username:1":"alice"}}
{"cmd":"cancel"}
```

Closing stdin (EOF) shuts the helper down cleanly.

## Compatibility

Additions (new events, new optional fields, new commands) keep the
version at 1; a reader ignores what it does not know. A change that an
older app would misread bumps the version, and the release tag major with
it.
