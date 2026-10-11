// ssh-tool-openconnect: sidecar that connects to an SSL VPN gateway
// (Cisco AnyConnect / ocserv, Fortinet, F5, GlobalProtect, Pulse, Juniper)
// entirely in userspace and exposes it to ssh-tool through a loopback
// SOCKS5 proxy. No TUN device, no admin rights, and several gateways can be
// up at once, even with overlapping address ranges.
//
// The VPN protocol is github.com/sagernet/sing-openconnect (a Go port of
// OpenConnect); packets go into a gVisor netstack (wireguard-go's
// tun/netstack), which the SOCKS server dials from.
//
// Protocol: see ../PROTOCOL.md. In short, line JSON on stdout:
//
//	{"event":"auth","id":"..","message":"..","fields":[...]}  login form to answer
//	{"event":"info","info":{...}}                               tunnel settings
//	{"event":"ready","socks":"127.0.0.1:PORT","protocol":1}    proxy listening
//	{"event":"status","peers":N,"transport":"dtls"}            every 15s
//	{"event":"error","error":"..","cert_pin":".."}             fatal
//
// and on stdin {"cmd":"auth","id":"..","values":{..}} / {"cmd":"cancel"};
// stdin EOF shuts the helper down. Every form goes to the app, which fills
// what it can (vault, TOTP) and prompts for the rest, so no secret has to be
// handed to this process up front.
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
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	oc "github.com/sagernet/sing-openconnect"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// version is stamped at build time via -X main.version=<release tag>.
var version = "dev"

// protocolVersion: same wire contract as the other ssh-tool helpers; the
// auth / info additions are optional for helpers that do not need them.
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

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// authField / authEvent mirror oc.AuthChallenge for the app.
type authField struct {
	Key     string       `json:"key"`
	Name    string       `json:"name"`
	Label   string       `json:"label"`
	Kind    string       `json:"kind"` // text | password | select
	Value   string       `json:"value,omitempty"`
	Options []authOption `json:"options,omitempty"`
}

type authOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

type authEvent struct {
	Event   string      `json:"event"`
	ID      string      `json:"id"`
	Message string      `json:"message,omitempty"`
	Banner  string      `json:"banner,omitempty"`
	Error   string      `json:"error,omitempty"`
	Fields  []authField `json:"fields"`
}

type command struct {
	Cmd    string            `json:"cmd"`
	ID     string            `json:"id"`
	Values map[string]string `json:"values"`
}

// tunnelInfo is the debug view of the session the app shows.
type tunnelInfo struct {
	Flavor         string   `json:"flavor"`
	Server         string   `json:"server"`
	Gateway        string   `json:"gateway"`
	Transport      string   `json:"transport"`
	MTU            uint32   `json:"mtu"`
	LocalMTU       int      `json:"local_mtu"`
	Addresses      []string `json:"addresses"`
	Routes         []string `json:"routes"`
	ExcludedRoutes []string `json:"excluded_routes,omitempty"`
	DNS            []string `json:"dns"`
	SearchDomains  []string `json:"search_domains,omitempty"`
	SplitDNS       []string `json:"split_dns,omitempty"`
	TunnelAllDNS   bool     `json:"tunnel_all_dns"`
	Banner         string   `json:"banner,omitempty"`
	IdleTimeout    int64    `json:"idle_timeout_s,omitempty"`
	AuthExpires    int64    `json:"auth_expires,omitempty"` // unix seconds
	Reason         string   `json:"reason"`
}

func main() {
	server := flag.String("server", "", "gateway URL, e.g. https://vpn.example.com/group (required)")
	flavor := flag.String("flavor", oc.FlavorAnyConnect, "anyconnect | fortinet | f5 | gp | pulse | nc")
	authGroup := flag.String("authgroup", "", "login group to select, when the gateway offers several")
	var pins listFlag
	flag.Var(&pins, "pin", "accepted server certificate pin (pin-sha256:BASE64), repeatable; disables system trust")
	mtu := flag.Uint("mtu", 0, "tunnel MTU to request; also caps the local stack (0 = gateway's)")
	baseMTU := flag.Uint("base-mtu", 0, "path MTU of the underlying network, for the gateway's calculation")
	noUDP := flag.Bool("no-udp", false, "do not use DTLS / ESP; tunnel over TLS only")
	showVersion := flag.Bool("version", false, "print helper version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}
	if *server == "" {
		fatal("--server is required")
	}
	if !strings.Contains(*server, "://") {
		*server = "https://" + *server
	}
	log.SetOutput(os.Stderr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	opts := oc.ClientOptions{
		Context:   ctx,
		Server:    *server,
		Flavor:    *flavor,
		AuthGroup: *authGroup,
		MTU:       uint32(*mtu),
		BaseMTU:   uint32(*baseMTU),
		NoUDP:     *noUDP,
	}
	if pin, subject, changed, err := probeTrust(*server, pins); err != nil {
		// Not trusted (by the system, or no longer matching the pin): hand the
		// app the certificate's pin so it can ask the user (trust on first
		// use, or accept a changed certificate) and start us again with it.
		ev := map[string]any{"event": "error", "error": err.Error()}
		if pin != "" {
			ev["cert_pin"], ev["cert_subject"], ev["cert_changed"] = pin, subject, changed
		}
		emit(ev)
		os.Exit(1)
	}
	if len(pins) > 0 {
		opts.TLSConfig.PeerFingerprints = pins
		opts.TLSConfig.SystemTrustDisabled = true
	}
	if c := os.Getenv("SSHTOOL_OC_CERT"); c != "" {
		opts.TLSConfig.Certificate = oc.Material{Content: []byte(c)}
		opts.TLSConfig.Key = oc.Material{Content: []byte(os.Getenv("SSHTOOL_OC_KEY"))}
		opts.TLSConfig.KeyPassword = os.Getenv("SSHTOOL_OC_KEY_PASSWORD")
	}

	var cur struct {
		sync.Mutex
		ready bool
		info  tunnelInfo
	}
	localMTU := 0
	opts.OnTunnelConfiguration = func(ev oc.TunnelConfigurationEvent) error {
		cur.Lock()
		defer cur.Unlock()
		old := cur.info.Addresses
		cur.info = buildInfo(*flavor, *server, ev, localMTU)
		if cur.ready {
			if strings.Join(old, ",") != strings.Join(cur.info.Addresses, ",") {
				log.Printf("tunnel address changed %v -> %v; open sessions will drop", old, cur.info.Addresses)
			}
			emit(map[string]any{"event": "info", "info": cur.info})
		}
		return nil
	}

	client, err := oc.NewClient(opts)
	if err != nil {
		fatal("%v", err)
	}
	defer client.Close()

	go watchAuth(ctx, client, cancel)
	go readCommands(client, cancel)

	if err := client.Start(); err != nil {
		fatal("%v", err)
	}
	readyCtx, readyCancel := context.WithTimeout(ctx, 5*time.Minute)
	err = client.WaitReady(readyCtx)
	readyCancel()
	if err != nil {
		if ctx.Err() != nil {
			fatal("login cancelled")
		}
		fatal("%v", err)
	}

	tc := client.TunnelConfiguration()
	var addrs []netip.Addr
	for _, p := range tc.Addresses {
		addrs = append(addrs, p.Addr())
	}
	if len(addrs) == 0 {
		fatal("gateway assigned no address")
	}
	localMTU = int(tc.MTU)
	if *mtu > 0 && (localMTU == 0 || int(*mtu) < localMTU) {
		// Gateways often ignore the requested MTU; capping our own stack still
		// keeps TCP segments small enough for a lossy path.
		localMTU = int(*mtu)
	}
	if localMTU == 0 {
		localMTU = 1300
	}
	tdev, tnet, err := netstack.CreateNetTUN(addrs, tc.DNS, localMTU)
	if err != nil {
		fatal("netstack: %v", err)
	}
	go pumpOut(ctx, tdev, client)
	go pumpIn(ctx, tdev, client)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fatal("socks listen: %v", err)
	}
	go serveSocks(ln, tnet)

	cur.Lock()
	cur.info = buildInfo(*flavor, *server, oc.TunnelConfigurationEvent{Reason: "initial", Configuration: tc}, localMTU)
	cur.info.Transport = client.ActiveTransport()
	cur.ready = true
	emit(map[string]any{"event": "info", "info": cur.info})
	cur.Unlock()
	emit(map[string]any{"event": "ready", "socks": ln.Addr().String(), "protocol": protocolVersion})

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-client.ActiveTransportUpdated():
				cur.Lock()
				cur.info.Transport = client.ActiveTransport()
				emit(map[string]any{"event": "info", "info": cur.info})
				cur.Unlock()
			}
		}
	}()

	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = ln.Close()
			return
		case <-t.C:
			peers := 0
			if client.Ready() {
				peers = 1
			}
			emit(map[string]any{"event": "status", "peers": peers, "transport": client.ActiveTransport()})
		}
	}
}

// probeTrust checks the gateway certificate: against pins when there are
// any, else against the system roots. On failure it returns the leaf's pin
// so the app can offer trust on first use; changed reports a certificate
// that no longer matches the pinned one.
func probeTrust(server string, pins []string) (pin, subject string, changed bool, err error) {
	u, perr := url.Parse(server)
	if perr != nil || u.Hostname() == "" {
		return "", "", false, fmt.Errorf("bad server URL %q", server)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(u.Hostname(), port)
	d := &net.Dialer{Timeout: 15 * time.Second}
	leafPin := func() (string, string, error) {
		raw, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{ServerName: u.Hostname(), InsecureSkipVerify: true})
		if err != nil {
			return "", "", err
		}
		defer raw.Close()
		leaf := raw.ConnectionState().PeerCertificates[0]
		sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		return "pin-sha256:" + base64.StdEncoding.EncodeToString(sum[:]), leaf.Subject.String(), nil
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
	conn, derr := tls.DialWithDialer(d, "tcp", addr, &tls.Config{ServerName: u.Hostname()})
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

// watchAuth forwards every login challenge to the app.
func watchAuth(ctx context.Context, client *oc.Client, cancel context.CancelFunc) {
	seen := map[string]bool{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-client.AuthChallengeUpdated():
		}
		ch := client.PendingAuthChallenge()
		if ch == nil || seen[ch.ID] {
			continue
		}
		seen[ch.ID] = true
		if ch.Browser != nil {
			emit(map[string]string{"event": "error", "error": "this gateway asks for a browser (SAML) login, which the plugin does not support yet"})
			cancel()
			return
		}
		ev := authEvent{Event: "auth", ID: ch.ID, Message: ch.Message, Banner: ch.Banner, Error: ch.Error, Fields: []authField{}}
		if ch.Form != nil {
			for _, f := range ch.Form.Fields {
				af := authField{Key: f.SubmissionKey, Name: f.Name, Label: f.Label, Kind: f.Kind, Value: f.Value}
				for _, o := range f.Options {
					af.Options = append(af.Options, authOption{Value: o.Value, Label: o.Label})
				}
				ev.Fields = append(ev.Fields, af)
			}
		}
		emit(ev)
	}
}

// readCommands applies the app's answers; stdin EOF is the shutdown signal.
func readCommands(client *oc.Client, cancel context.CancelFunc) {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var c command
		if json.Unmarshal(sc.Bytes(), &c) != nil {
			continue
		}
		switch c.Cmd {
		case "auth":
			resp := oc.AuthResponse{Form: &oc.AuthFormResponse{Values: c.Values}}
			if err := client.CompleteAuthChallenge(c.ID, resp); err != nil {
				log.Printf("auth answer %s: %v", c.ID, err)
			}
		case "cancel":
			_ = client.CancelAuthChallenge(c.ID)
			cancel()
		}
	}
	cancel()
}

func pumpOut(ctx context.Context, tdev interface {
	Read([][]byte, []int, int) (int, error)
}, client *oc.Client) {
	bufs := [][]byte{make([]byte, 65536)}
	sizes := make([]int, 1)
	for ctx.Err() == nil {
		n, err := tdev.Read(bufs, sizes, 0)
		if err != nil {
			return
		}
		for i := 0; i < n; i++ {
			if err := client.WriteDataPacket(bufs[i][:sizes[i]]); err != nil && ctx.Err() == nil {
				log.Printf("to vpn: %v", err)
			}
		}
	}
}

func pumpIn(ctx context.Context, tdev interface {
	Write([][]byte, int) (int, error)
}, client *oc.Client) {
	for {
		p, err := client.ReadDataPacket(ctx)
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("from vpn: %v", err)
			}
			return
		}
		if _, err := tdev.Write([][]byte{p}, 0); err != nil {
			log.Printf("to stack: %v", err)
		}
	}
}

func buildInfo(flavor, server string, ev oc.TunnelConfigurationEvent, localMTU int) tunnelInfo {
	tc := ev.Configuration
	in := tunnelInfo{
		Flavor: flavor, Server: server, MTU: tc.MTU, LocalMTU: localMTU,
		Banner: tc.Banner, TunnelAllDNS: tc.TunnelAllDNS, Reason: string(ev.Reason),
		SearchDomains: tc.SearchDomains, SplitDNS: tc.SplitDNS,
		Addresses: []string{}, Routes: []string{}, DNS: []string{},
	}
	if tc.RemoteAddress.IsValid() {
		in.Gateway = tc.RemoteAddress.String()
	}
	for _, a := range tc.Addresses {
		in.Addresses = append(in.Addresses, a.String())
	}
	for _, r := range tc.Routes {
		in.Routes = append(in.Routes, routeString(r))
	}
	for _, r := range tc.ExcludedRoutes {
		in.ExcludedRoutes = append(in.ExcludedRoutes, routeString(r))
	}
	for _, d := range tc.DNS {
		in.DNS = append(in.DNS, d.String())
	}
	if tc.IdleTimeout > 0 {
		in.IdleTimeout = int64(tc.IdleTimeout / time.Second)
	}
	if !tc.AuthenticationExpiration.IsZero() {
		in.AuthExpires = tc.AuthenticationExpiration.Unix()
	}
	return in
}

func routeString(r oc.TunnelRoute) string {
	if r.Gateway.IsValid() {
		return r.Prefix.String() + " via " + r.Gateway.String()
	}
	return r.Prefix.String()
}
