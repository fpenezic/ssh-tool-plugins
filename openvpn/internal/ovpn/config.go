// Package ovpn is a userspace OpenVPN 2.x client: the control channel
// (reliability layer, TLS, tls-auth / tls-crypt, key method 2, push,
// renegotiation) and the data channel (AES-GCM, ChaCha20-Poly1305,
// AES-CBC + HMAC), handing IP packets to the caller instead of a TUN
// device.
package ovpn

import (
	"bufio"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Remote is one "remote" line.
type Remote struct {
	Host  string
	Port  int
	Proto string // "udp" | "tcp"
}

// Config is the subset of an .ovpn client configuration this client
// understands. Files must be inline (<ca>, <cert>, ...).
type Config struct {
	Remotes []Remote

	CA, Cert, Key, ExtraCerts string // PEM

	// TLSAuth / TLSCrypt hold an "OpenVPN Static key V1" block; only
	// one of them is set. KeyDirection is tls-auth's direction: -1 =
	// bidirectional, 0 or 1.
	TLSAuth      string
	TLSCrypt     string
	KeyDirection int

	// Cipher is the fallback data cipher ("cipher"), DataCiphers the
	// negotiable list ("data-ciphers" / "ncp-ciphers"). Auth is the HMAC
	// digest for tls-auth and CBC data packets.
	Cipher      string
	DataCiphers []string
	Auth        string

	AuthUserPass bool
	// StaticChallenge is the "static-challenge" prompt (one-time code
	// typed with the password); StaticChallengeEcho shows it typed.
	StaticChallenge     string
	StaticChallengeEcho bool

	RemoteCertTLS  string // "server" | ""
	VerifyX509Name string
	VerifyX509Type string // subject | name | name-prefix

	// RenegSec > 0 makes the client renegotiate on its own; 0 / unset
	// leaves it to the server.
	RenegSec int

	// Compress is the compression framing: "" (none), "lzo" (comp-lzo,
	// compress lzo), "swap" (compress stub / lz4), "v2" (compress
	// stub-v2 / lz4-v2). The client never compresses what it sends (the
	// VORACLE attack); it decompresses what the server compressed.
	Compress string

	Ping, PingRestart int

	// Warnings lists directives that were ignored.
	Warnings []string
}

// ignored are directives that only steer the official client's own
// TUN / routing / process handling, or that are accepted as a no-op.
var ignored = map[string]bool{
	"client": true, "dev": true, "dev-type": true, "dev-node": true, "nobind": true,
	"persist-key": true, "persist-tun": true, "resolv-retry": true, "verb": true,
	"mute": true, "auth-nocache": true, "mute-replay-warnings": true,
	"redirect-gateway": true, "block-outside-dns": true, "script-security": true,
	"up": true, "down": true, "setenv": true, "pull": true, "tls-client": true,
	"remote-random": true, "explicit-exit-notify": true, "float": true,
	"sndbuf": true, "rcvbuf": true, "route-method": true, "route-delay": true,
	"register-dns": true, "auth-retry": true, "connect-retry": true,
	"connect-retry-max": true, "server-poll-timeout": true, "tun-mtu": true,
	"mssfix": true, "tls-version-min": true, "tls-version-max": true,
	"tls-cipher": true, "tls-ciphersuites": true, "tls-groups": true,
	"keysize": true, "topology": true, "route-nopull": true, "allow-pull-fqdn": true,
	"pull-filter": true, "ifconfig-nowarn": true, "setenv-safe": true,
	"push-peer-info": true, "hand-window": true, "tran-window": true,
	"key-method": true, "comp-noadapt": true, "machine-readable-output": true,
	"connect-timeout": true, "user": true, "group": true, "chroot": true,
	"daemon": true, "log": true, "log-append": true, "status": true, "writepid": true,
	"management": true, "management-query-passwords": true, "management-hold": true,
	"route": true, "route-ipv6": true, "dhcp-option": true, "ignore-unknown-option": true,
	"inactive": true, "ping-exit": true, "lport": true, "bind": true, "local": true,
}

// ParseConfig reads an .ovpn configuration.
func ParseConfig(text string) (*Config, error) {
	c := &Config{KeyDirection: -1, Auth: "SHA1"}
	defProto, defPort := "udp", 1194
	type pending struct{ host, port, proto string }
	var remotes []pending
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var block string
	var body strings.Builder
	for sc.Scan() {
		raw := strings.TrimRight(sc.Text(), "\r")
		line := strings.TrimSpace(raw)
		if block != "" {
			if line == "</"+block+">" {
				if err := c.setInline(block, body.String()); err != nil {
					return nil, err
				}
				block = ""
				body.Reset()
				continue
			}
			body.WriteString(raw)
			body.WriteByte('\n')
			continue
		}
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") && !strings.HasPrefix(line, "</") {
			block = line[1 : len(line)-1]
			continue
		}
		f := splitArgs(line)
		name := strings.TrimPrefix(f[0], "--")
		args := f[1:]
		arg := func(i int) string {
			if i < len(args) {
				return args[i]
			}
			return ""
		}
		switch name {
		case "remote":
			if len(args) == 0 {
				return nil, errors.New("remote: missing host")
			}
			remotes = append(remotes, pending{arg(0), arg(1), arg(2)})
		case "proto":
			defProto = arg(0)
		case "port", "rport":
			p, err := strconv.Atoi(arg(0))
			if err != nil {
				return nil, fmt.Errorf("%s: %q is not a port", name, arg(0))
			}
			defPort = p
		case "ca", "cert", "key", "tls-auth", "tls-crypt", "extra-certs":
			if arg(0) != "" && arg(0) != "[inline]" {
				return nil, fmt.Errorf("%s refers to a file (%s); the configuration must have it inline", name, arg(0))
			}
			if name == "tls-auth" && arg(1) != "" {
				d, err := strconv.Atoi(arg(1))
				if err != nil || d < 0 || d > 1 {
					return nil, fmt.Errorf("tls-auth: bad key direction %q", arg(1))
				}
				c.KeyDirection = d
			}
		case "key-direction":
			d, err := strconv.Atoi(arg(0))
			if err != nil || d < 0 || d > 1 {
				return nil, fmt.Errorf("key-direction: bad value %q", arg(0))
			}
			c.KeyDirection = d
		case "tls-crypt-v2":
			return nil, errors.New("tls-crypt-v2 is not supported yet")
		case "pkcs12":
			return nil, errors.New("pkcs12 is not supported: import the certificate and key as PEM")
		case "pkcs11-providers", "pkcs11-id", "cryptoapicert":
			return nil, fmt.Errorf("%s (smart card / system store) is not supported", name)
		case "cipher":
			c.Cipher = strings.ToUpper(arg(0))
		case "data-ciphers", "ncp-ciphers":
			for _, x := range strings.Split(arg(0), ":") {
				if x = strings.ToUpper(strings.TrimSpace(x)); x != "" {
					c.DataCiphers = append(c.DataCiphers, x)
				}
			}
		case "data-ciphers-fallback":
			c.Cipher = strings.ToUpper(arg(0))
		case "auth":
			c.Auth = strings.ToUpper(arg(0))
		case "auth-user-pass":
			if arg(0) != "" {
				c.Warnings = append(c.Warnings, "auth-user-pass file ignored, the app answers the login")
			}
			c.AuthUserPass = true
		case "static-challenge":
			c.StaticChallenge = arg(0)
			c.StaticChallengeEcho = arg(1) == "1"
		case "remote-cert-tls":
			c.RemoteCertTLS = arg(0)
		case "ns-cert-type":
			if arg(0) == "server" {
				c.RemoteCertTLS = "server"
			}
		case "verify-x509-name":
			c.VerifyX509Name, c.VerifyX509Type = arg(0), arg(1)
			if c.VerifyX509Type == "" {
				c.VerifyX509Type = "subject"
			}
		case "reneg-sec":
			n, _ := strconv.Atoi(arg(0))
			c.RenegSec = n
		case "comp-lzo":
			c.Compress = "lzo"
		case "compress":
			m, err := compressMode(arg(0))
			if err != nil {
				return nil, err
			}
			c.Compress = m
		case "allow-compression":
		case "ping":
			c.Ping, _ = strconv.Atoi(arg(0))
		case "ping-restart":
			c.PingRestart, _ = strconv.Atoi(arg(0))
		case "keepalive":
			c.Ping, _ = strconv.Atoi(arg(0))
			c.PingRestart, _ = strconv.Atoi(arg(1))
		case "fragment":
			return nil, errors.New("fragment is not supported")
		default:
			if !ignored[name] {
				c.Warnings = append(c.Warnings, "ignored: "+name)
			}
		}
		if name == "dev" && strings.HasPrefix(arg(0), "tap") {
			return nil, errors.New("TAP (layer 2) tunnels are not supported")
		}
	}
	if block != "" {
		return nil, fmt.Errorf("<%s> is not closed", block)
	}
	for _, r := range remotes {
		port := defPort
		if r.port != "" {
			p, err := strconv.Atoi(r.port)
			if err != nil {
				return nil, fmt.Errorf("remote %s: %q is not a port", r.host, r.port)
			}
			port = p
		}
		proto := r.proto
		if proto == "" {
			proto = defProto
		}
		np, err := normProto(proto)
		if err != nil {
			return nil, err
		}
		c.Remotes = append(c.Remotes, Remote{Host: r.host, Port: port, Proto: np})
	}
	if len(c.Remotes) == 0 {
		return nil, errors.New("no remote in the configuration")
	}
	if c.CA == "" {
		return nil, errors.New("no <ca> in the configuration")
	}
	if (c.Cert == "") != (c.Key == "") {
		return nil, errors.New("<cert> and <key> must come together")
	}
	if c.TLSAuth != "" && c.TLSCrypt != "" {
		return nil, errors.New("tls-auth and tls-crypt are mutually exclusive")
	}
	if c.RemoteCertTLS == "" && c.VerifyX509Name == "" {
		// As OpenVPN itself warns: any certificate from the same CA,
		// another client's included, would pass as the server.
		c.Warnings = append(c.Warnings, "no remote-cert-tls server / verify-x509-name: the server certificate is only checked against the CA")
	}
	if c.Cert == "" && !c.AuthUserPass {
		return nil, errors.New("neither a client certificate nor auth-user-pass: nothing to log in with")
	}
	return c, nil
}

func (c *Config) setInline(block, body string) error {
	switch block {
	case "ca":
		c.CA = body
	case "cert":
		c.Cert = body
	case "key":
		c.Key = body
	case "extra-certs":
		c.ExtraCerts = body
	case "tls-auth":
		c.TLSAuth = body
	case "tls-crypt":
		c.TLSCrypt = body
	case "tls-crypt-v2":
		return errors.New("tls-crypt-v2 is not supported yet")
	case "pkcs12":
		return errors.New("pkcs12 is not supported: import the certificate and key as PEM")
	case "connection":
		return errors.New("<connection> blocks are not supported; use remote lines")
	case "dh", "secret":
		return fmt.Errorf("<%s> is a server / static-key option, not a client one", block)
	default:
		c.Warnings = append(c.Warnings, "ignored: <"+block+">")
	}
	return nil
}

// compressMode maps a "compress" algorithm to its framing.
func compressMode(alg string) (string, error) {
	switch alg {
	case "lzo": // same framing as comp-lzo, no byte swap
		return "lzo", nil
	case "", "stub", "lz4":
		return "swap", nil
	case "stub-v2", "lz4-v2":
		return "v2", nil
	}
	return "", fmt.Errorf("compress %s is not supported", alg)
}

func normProto(p string) (string, error) {
	switch strings.ToLower(p) {
	case "udp", "udp4", "udp6":
		return "udp", nil
	case "tcp", "tcp-client", "tcp4", "tcp4-client", "tcp6", "tcp6-client":
		return "tcp", nil
	}
	return "", fmt.Errorf("proto %q is not supported", p)
}

// splitArgs splits a directive line, honouring double / single quotes.
func splitArgs(line string) []string {
	var out []string
	var cur strings.Builder
	quote := byte(0)
	inTok := false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case quote != 0:
			if ch == quote {
				quote = 0
			} else if ch == '\\' && quote == '"' && i+1 < len(line) {
				i++
				cur.WriteByte(line[i])
			} else {
				cur.WriteByte(ch)
			}
		case ch == '"' || ch == '\'':
			quote, inTok = ch, true
		case ch == ' ' || ch == '\t':
			if inTok {
				out = append(out, cur.String())
				cur.Reset()
				inTok = false
			}
		case ch == '#' || ch == ';':
			if !inTok {
				i = len(line)
				continue
			}
			cur.WriteByte(ch)
		default:
			cur.WriteByte(ch)
			inTok = true
		}
	}
	if inTok {
		out = append(out, cur.String())
	}
	return out
}
