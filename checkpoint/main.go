// ssh-tool-checkpoint: sidecar that connects to a Check Point remote
// access gateway (the SSL Network Extender tunnel, what Endpoint Security
// VPN / snx use) entirely in userspace and exposes it to ssh-tool through
// a loopback SOCKS5 proxy. No TUN device, no admin rights, and several
// gateways can be up at once, even with overlapping address ranges.
//
// The protocol is internal/snx (a Go client based on snx-rs, see its
// package comment: CCC login with username, password and any further
// challenge, the SLIM packet tunnel over TLS); packets go into a gVisor
// netstack (wireguard-go's tun/netstack), which the SOCKS server dials
// from. AGPL-3.0, see LICENSE.
//
// Protocol: see ../PROTOCOL.md. Line JSON on stdout:
//
//	{"event":"auth","id":"..","message":"..","fields":[...]}  login to answer
//	{"event":"info","info":{...}}                               tunnel settings
//	{"event":"ready","socks":"127.0.0.1:PORT","protocol":1}    proxy listening
//	{"event":"status","peers":N,"transport":"ssl"}             every 15s
//	{"event":"error","error":"..","cert_pin":".."}             fatal
//
// and on stdin {"cmd":"auth","id":"..","values":{..}} / {"cmd":"cancel"};
// stdin EOF disconnects, signs out at the gateway and exits.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/fpenezic/ssh-tool-plugins/checkpoint/internal/snx"
)

// version is stamped at build time via -X main.version=<release tag>.
var version = "dev"

const protocolVersion = 1

var outMu sync.Mutex

func emit(v any) {
	b, _ := json.Marshal(v)
	outMu.Lock()
	fmt.Println(string(b))
	outMu.Unlock()
}

func fatal(format string, args ...any) {
	emit(map[string]string{"event": "error", "error": fmt.Sprintf(format, args...)})
	os.Exit(1)
}

type authField struct {
	Key   string `json:"key"`
	Name  string `json:"name"`
	Label string `json:"label"`
	Kind  string `json:"kind"` // text | password
	Value string `json:"value,omitempty"`
}

type authEvent struct {
	Event   string      `json:"event"`
	ID      string      `json:"id"`
	Message string      `json:"message,omitempty"`
	Error   string      `json:"error,omitempty"`
	Fields  []authField `json:"fields"`
}

type command struct {
	Cmd    string            `json:"cmd"`
	ID     string            `json:"id"`
	Values map[string]string `json:"values"`
}

// tunnelInfo matches the openconnect plugin's, for the app's Details.
type tunnelInfo struct {
	Flavor        string   `json:"flavor"`
	Server        string   `json:"server"`
	Gateway       string   `json:"gateway,omitempty"`
	Transport     string   `json:"transport"`
	MTU           int      `json:"mtu"`
	LocalMTU      int      `json:"local_mtu"`
	Addresses     []string `json:"addresses"`
	Routes        []string `json:"routes"`
	DNS           []string `json:"dns"`
	SearchDomains []string `json:"search_domains,omitempty"`
	TunnelAllDNS  bool     `json:"tunnel_all_dns"`
	AuthExpires   int64    `json:"auth_expires,omitempty"` // unix seconds
	Reason        string   `json:"reason"`
}

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// prompts routes the app's auth answers to the waiting login.
var prompts = struct {
	sync.Mutex
	next    int
	waiting map[string]chan map[string]string
}{waiting: map[string]chan map[string]string{}}

func main() {
	server := flag.String("server", "", "gateway, host or host:port (required)")
	loginOption := flag.String("login-option", "", "login option id (default: the gateway's username + password option)")
	var pins listFlag
	flag.Var(&pins, "pin", "accepted server certificate pin (pin-sha256:BASE64), repeatable; disables system trust")
	mtu := flag.Int("mtu", 1400, "local stack MTU")
	showVersion := flag.Bool("version", false, "print helper version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	log.SetOutput(os.Stderr)
	srv := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(*server), "https://"), "/")
	if srv == "" {
		fatal("--server is required")
	}
	host, port := srv, "443"
	if h, p, err := net.SplitHostPort(srv); err == nil {
		host, port = h, p
	}
	srv = net.JoinHostPort(host, port)
	debug := os.Getenv("SSHTOOL_CP_DEBUG") == "1"
	logf := func(format string, a ...any) {
		if debug {
			log.Printf(format, a...)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go readCommands(cancel)

	if pin, subject, changed, err := probeTrust(srv, host, pins); err != nil {
		// Not trusted (by the system, or no longer matching the pin): hand
		// the app the certificate's pin so it can ask the user (trust on
		// first use, or accept a changed certificate) and start us again.
		// Check Point gateways mostly present a certificate from their own
		// internal CA, so this is the usual first run.
		ev := map[string]any{"event": "error", "error": err.Error()}
		if pin != "" {
			ev["cert_pin"], ev["cert_subject"], ev["cert_changed"] = pin, subject, changed
		}
		emit(ev)
		os.Exit(1)
	}
	tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if len(pins) > 0 {
		tlsCfg.InsecureSkipVerify = true // replaced by the pin check
		tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no server certificate")
			}
			got := spkiPin(cs.PeerCertificates[0])
			for _, p := range pins {
				if p == got {
					return nil
				}
			}
			return fmt.Errorf("server certificate %s does not match the trusted pin", got)
		}
	}

	gw := &snx.Gateway{Server: srv, TLS: tlsCfg, Logf: logf}
	info, err := gw.Hello(ctx)
	if err != nil {
		fatal("gateway: %v", err)
	}
	if !info.ClientEnabled {
		fatal("the gateway does not accept remote access clients")
	}
	if !contains(info.Protocols, "SSL") {
		fatal("the gateway does not offer the SSL tunnel (offers %s)", strings.Join(info.Protocols, ", "))
	}
	opt, err := chooseLoginOption(info, *loginOption)
	if err != nil {
		fatal("%v", err)
	}
	log.Printf("gateway %s: protocol %d, tunnel port %d, login %q", srv, info.ProtocolVersion, info.TunnelPort, opt.ID)

	l := &link{gw: gw, opt: opt, tunAddr: net.JoinHostPort(host, strconv.Itoa(info.TunnelPort)), tls: tlsCfg, logf: logf, fatal: make(chan error, 1)}
	if err := l.login(ctx, false); err != nil {
		if ctx.Err() != nil {
			fatal("login cancelled")
		}
		fatal("%v", err)
	}
	tun, err := l.dial(ctx, netip.Addr{})
	if err != nil {
		l.signout()
		fatal("tunnel: %v", err)
	}
	hello := tun.Hello
	addr := hello.Address
	if len(hello.Routes) == 0 {
		// Most gateways leave the ranges out of the hello; the client
		// settings carry them. The app routes its local proxy by them.
		if r, err := gw.Routes(ctx, l.sessionID); err == nil {
			hello.Routes = r
			l.routes = r
		} else {
			log.Printf("client settings: %v", err)
		}
	}

	localMTU := *mtu
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, hello.DNS, localMTU)
	if err != nil {
		l.signout()
		fatal("netstack: %v", err)
	}
	go pumpOut(ctx, tdev, l)
	go pumpIn(ctx, tdev, l)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		l.signout()
		fatal("socks listen: %v", err)
	}
	go serveSocks(ln, tnet)

	emit(map[string]any{"event": "info", "info": buildInfo(srv, hello, localMTU, l.expires, "initial")})
	emit(map[string]any{"event": "ready", "socks": ln.Addr().String(), "protocol": protocolVersion})

	go l.keepUp(ctx, addr, func(h snx.Hello) {
		if len(h.Routes) == 0 {
			h.Routes = l.routes
		}
		emit(map[string]any{"event": "info", "info": buildInfo(srv, h, localMTU, l.expires, "reconnect")})
	})

	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = ln.Close()
			l.shutdown()
			return
		case err := <-l.fatal:
			_ = ln.Close()
			l.shutdown()
			fatal("%v", err)
		case <-t.C:
			peers := 0
			if l.current() != nil {
				peers = 1
			}
			emit(map[string]any{"event": "status", "peers": peers, "transport": "ssl"})
		}
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// chooseLoginOption picks the asked-for option, else the username +
// password one. Certificate and identity-provider logins are not
// supported yet.
func chooseLoginOption(info *snx.Info, want string) (snx.LoginOption, error) {
	if len(info.LoginOptions) == 0 {
		// Older gateways list no options: plain username + password.
		if want == "" {
			want = "vpn_Username_Password"
		}
		return snx.LoginOption{ID: want, Factors: []string{"password"}}, nil
	}
	var ids []string
	for _, o := range info.LoginOptions {
		ids = append(ids, o.ID)
		if want != "" && o.ID == want {
			return checkFactors(o)
		}
	}
	if want != "" {
		return snx.LoginOption{}, fmt.Errorf("the gateway has no login option %q (it offers %s)", want, strings.Join(ids, ", "))
	}
	for _, o := range info.LoginOptions {
		if o.ID == "vpn_Username_Password" {
			return checkFactors(o)
		}
	}
	for _, o := range info.LoginOptions {
		if _, err := checkFactors(o); err == nil {
			return o, nil
		}
	}
	return snx.LoginOption{}, fmt.Errorf("no supported login option (the gateway offers %s)", strings.Join(ids, ", "))
}

func checkFactors(o snx.LoginOption) (snx.LoginOption, error) {
	for _, f := range o.Factors {
		switch f {
		case "certificate":
			return o, fmt.Errorf("login option %q needs a client certificate, which is not supported yet", o.ID)
		case "identity_provider":
			return o, fmt.Errorf("login option %q is a browser (SAML) login, which is not supported yet", o.ID)
		}
	}
	return o, nil
}

// link is the session: the login and whichever tunnel is current.
type link struct {
	gw      *snx.Gateway
	opt     snx.LoginOption
	tunAddr string
	tls     *tls.Config
	logf    func(string, ...any)
	fatal   chan error

	mu        sync.Mutex
	tun       *snx.Tunnel
	sessionID string
	key       string
	expires   int64
	routes    []netip.Prefix // from the client settings, when the hello has none
	changed   chan struct{}  // closed when tun is replaced
}

func (l *link) current() *snx.Tunnel {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.tun
}

// maxRefused is how many refused logins end the helper: the gateway may
// lock the account after a few, so a wrong stored password must not be
// retried without end.
const maxRefused = 3

// login runs the CCC login, asking the app for username and password and
// for every further challenge (a one-time code, a second password).
// reconnect marks a login the gateway forced on a running profile (the
// session expired): the app may answer it from storage again.
func (l *link) login(ctx context.Context, reconnect bool) error {
	deviceID := deviceID()
	var lastErr string
	if reconnect {
		lastErr = "reconnecting"
	}
	for refused := 0; ; {
		v, err := ask(ctx, authEvent{
			Message: "Please enter your username and password.", Error: lastErr,
			Fields: []authField{
				{Key: "username", Name: "username", Label: "Username:", Kind: "text"},
				{Key: "password", Name: "password", Label: "Password:", Kind: "password"},
			},
		})
		if err != nil {
			return err
		}
		res, err := l.gw.Login(ctx, l.opt.ID, v["username"], deviceID)
		password, usedPassword := v["password"], false
		for err == nil && !res.Done {
			answer := ""
			if !usedPassword && password != "" {
				answer, usedPassword = password, true // the first prompt is the password
			} else {
				label := strings.TrimSpace(res.Prompt)
				if label == "" {
					label = "Response:"
				}
				a, aerr := ask(ctx, authEvent{Message: label, Fields: []authField{
					{Key: "response", Name: "response", Label: label, Kind: "password"},
				}})
				if aerr != nil {
					return aerr
				}
				answer = a["response"]
			}
			res, err = l.gw.Challenge(ctx, res.SessionID, answer)
		}
		if err == nil {
			l.mu.Lock()
			l.sessionID, l.key = res.SessionID, res.ActiveKey
			if res.KeyTTL > 0 {
				l.expires = time.Now().Add(res.KeyTTL).Unix()
			}
			l.mu.Unlock()
			log.Printf("logged in, session valid for %s", res.KeyTTL)
			return nil
		}
		var ae *snx.AuthError
		if !errors.As(err, &ae) {
			return err
		}
		log.Printf("login refused: %v", err)
		if refused++; refused >= maxRefused {
			return fmt.Errorf("login refused %d times, last: %v", refused, err)
		}
		lastErr = ae.Error()
	}
}

func (l *link) dial(ctx context.Context, previous netip.Addr) (*snx.Tunnel, error) {
	l.mu.Lock()
	key := l.key
	l.mu.Unlock()
	t, err := snx.Dial(ctx, snx.DialOptions{Addr: l.tunAddr, TLS: l.tls, ActiveKey: key, Previous: previous, Logf: l.logf})
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.tun = t
	if l.changed != nil {
		close(l.changed)
	}
	l.changed = make(chan struct{})
	l.mu.Unlock()
	return t, nil
}

// keepUp reconnects a dropped tunnel with the same session, logging in
// again when the gateway has ended it. The office-mode address has to
// stay the same: the local stack was built on it.
func (l *link) keepUp(ctx context.Context, addr netip.Addr, onInfo func(snx.Hello)) {
	for {
		t := l.current()
		select {
		case <-ctx.Done():
			return
		case <-t.Done():
		}
		log.Printf("tunnel down: %v", t.Err())
		l.mu.Lock()
		l.tun = nil
		l.mu.Unlock()
		var de *snx.DisconnectedError
		relogin := errors.As(t.Err(), &de)
		backoff := time.Second
		for {
			if ctx.Err() != nil {
				return
			}
			if relogin {
				if err := l.login(ctx, true); err != nil {
					l.fatal <- err
					return
				}
			}
			nt, err := l.dial(ctx, addr)
			if err == nil {
				if nt.Hello.Address != addr {
					nt.Close()
					l.fatal <- fmt.Errorf("the gateway gave a new address (%s, was %s); reconnect the profile", nt.Hello.Address, addr)
					return
				}
				log.Printf("tunnel back up")
				onInfo(nt.Hello)
				break
			}
			log.Printf("reconnect: %v", err)
			relogin = errors.As(err, &de)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
		}
	}
}

func (l *link) signout() {
	l.mu.Lock()
	sid := l.sessionID
	l.mu.Unlock()
	if sid == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := l.gw.Signout(ctx, sid); err != nil {
		log.Printf("signout: %v", err)
	}
}

func (l *link) shutdown() {
	if t := l.current(); t != nil {
		_ = t.Close()
	}
	l.signout()
}

// deviceID is a stable per-machine id for the gateway's client log.
func deviceID() string {
	h, _ := os.Hostname()
	sum := sha256.Sum256([]byte("ssh-tool-checkpoint:" + h))
	b := sum[:16]
	return strings.ToUpper(fmt.Sprintf("{%x-%x-%x-%x-%x}", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]))
}

func buildInfo(server string, h snx.Hello, localMTU int, expires int64, reason string) tunnelInfo {
	in := tunnelInfo{
		Flavor: "checkpoint", Server: server, Transport: "ssl", LocalMTU: localMTU, MTU: localMTU,
		Addresses: []string{}, Routes: []string{}, DNS: []string{},
		SearchDomains: h.SearchDomains, AuthExpires: expires, Reason: reason,
	}
	bits := 32
	if h.Netmask.IsValid() {
		b := h.Netmask.As4()
		bits = 0
		for _, x := range b {
			for ; x&0x80 != 0; x <<= 1 {
				bits++
			}
		}
	}
	in.Addresses = append(in.Addresses, netip.PrefixFrom(h.Address, bits).String())
	for _, r := range h.Routes {
		in.Routes = append(in.Routes, r.String())
		if r.Bits() == 0 {
			in.TunnelAllDNS = true
		}
	}
	for _, d := range h.DNS {
		in.DNS = append(in.DNS, d.String())
	}
	return in
}

// ask sends an auth event and waits for the app's answer.
func ask(ctx context.Context, ev authEvent) (map[string]string, error) {
	prompts.Lock()
	prompts.next++
	id := strconv.Itoa(prompts.next)
	ch := make(chan map[string]string, 1)
	prompts.waiting[id] = ch
	prompts.Unlock()
	defer func() {
		prompts.Lock()
		delete(prompts.waiting, id)
		prompts.Unlock()
	}()
	ev.Event, ev.ID = "auth", id
	emit(ev)
	select {
	case v := <-ch:
		if v == nil {
			return nil, errors.New("login cancelled")
		}
		return v, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// readCommands applies the app's answers; stdin EOF is the shutdown signal.
func readCommands(cancel context.CancelFunc) {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var c command
		if json.Unmarshal(sc.Bytes(), &c) != nil {
			continue
		}
		prompts.Lock()
		ch := prompts.waiting[c.ID]
		prompts.Unlock()
		switch c.Cmd {
		case "auth":
			if ch != nil {
				ch <- c.Values
			}
		case "cancel":
			if ch != nil {
				ch <- nil
			}
			cancel()
		}
	}
	cancel()
}

func pumpOut(ctx context.Context, tdev interface {
	Read([][]byte, []int, int) (int, error)
}, l *link) {
	bufs := [][]byte{make([]byte, 65536)}
	sizes := make([]int, 1)
	for ctx.Err() == nil {
		n, err := tdev.Read(bufs, sizes, 0)
		if err != nil {
			return
		}
		t := l.current()
		if t == nil {
			continue // reconnecting: drop, TCP retransmits
		}
		for i := 0; i < n; i++ {
			_ = t.WritePacket(bufs[i][:sizes[i]])
		}
	}
}

func pumpIn(ctx context.Context, tdev interface {
	Write([][]byte, int) (int, error)
}, l *link) {
	for ctx.Err() == nil {
		l.mu.Lock()
		t, changed := l.tun, l.changed
		l.mu.Unlock()
		if t == nil {
			select {
			case <-ctx.Done():
				return
			case <-changed:
			}
			continue
		}
		p, err := t.ReadPacket(ctx)
		if err != nil {
			select { // wait for keepUp to swap the tunnel
			case <-ctx.Done():
				return
			case <-changed:
			}
			continue
		}
		if _, err := tdev.Write([][]byte{p}, 0); err != nil && ctx.Err() == nil {
			log.Printf("to stack: %v", err)
		}
	}
}

func spkiPin(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return "pin-sha256:" + base64.StdEncoding.EncodeToString(sum[:])
}

// probeTrust checks the gateway certificate against the pins if there are
// any, else against the system roots. On failure it returns the leaf's pin
// so the app can offer trust on first use; changed reports a certificate
// that no longer matches the pinned one.
func probeTrust(addr, host string, pins []string) (pin, subject string, changed bool, err error) {
	d := &net.Dialer{Timeout: 15 * time.Second}
	leafPin := func() (string, string, error) {
		raw, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{ServerName: host, InsecureSkipVerify: true})
		if err != nil {
			return "", "", err
		}
		defer raw.Close()
		leaf := raw.ConnectionState().PeerCertificates[0]
		return spkiPin(leaf), leaf.Subject.String(), nil
	}
	if len(pins) > 0 {
		got, subj, lerr := leafPin()
		if lerr != nil {
			return "", "", false, nil // a network problem: let the real connect report it
		}
		for _, p := range pins {
			if p == got {
				return "", "", false, nil
			}
		}
		return got, subj, true, fmt.Errorf("server certificate changed since it was trusted")
	}
	conn, derr := tls.DialWithDialer(d, "tcp", addr, &tls.Config{ServerName: host})
	if derr == nil {
		conn.Close()
		return "", "", false, nil
	}
	var verr *tls.CertificateVerificationError
	var herr x509.HostnameError
	var uerr x509.UnknownAuthorityError
	if !errors.As(derr, &verr) && !errors.As(derr, &herr) && !errors.As(derr, &uerr) {
		return "", "", false, nil // a network problem: let the real connect report it
	}
	got, subj, lerr := leafPin()
	if lerr != nil {
		return "", "", false, fmt.Errorf("server certificate is not trusted: %v", derr)
	}
	return got, subj, false, fmt.Errorf("server certificate is not trusted (%v)", derr)
}
