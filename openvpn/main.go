// ssh-tool-openvpn: sidecar that connects to an OpenVPN 2.x server
// entirely in userspace and exposes it to ssh-tool through a loopback
// SOCKS5 proxy. No TUN device, no admin rights, and several servers can be
// up at once, even with overlapping address ranges.
//
// The protocol is internal/ovpn (an OpenVPN client written for this
// plugin: tls-auth / tls-crypt, AES-GCM / ChaCha20-Poly1305 / AES-CBC,
// renegotiation, auth-user-pass with static and dynamic challenges);
// packets go into a gVisor netstack (wireguard-go's tun/netstack), which
// the SOCKS server dials from.
//
// Protocol: see ../PROTOCOL.md. The configuration (.ovpn text, files
// inline) comes in SSHTOOL_OVPN_CONFIG. Line JSON on stdout:
//
//	{"event":"auth","id":"..","message":"..","fields":[...]}  login to answer
//	{"event":"info","info":{...}}                               tunnel settings
//	{"event":"ready","socks":"127.0.0.1:PORT","protocol":1}    proxy listening
//	{"event":"status","peers":N,"transport":"udp"}             every 15s
//	{"event":"error","error":".."}                             fatal
//	{"event":"check",...}                                      --check summary
//	{"event":"open_url","url":".."}                            browser login (pending auth)
//
// and on stdin {"cmd":"auth","id":"..","values":{..}} / {"cmd":"cancel"};
// stdin EOF disconnects (telling a UDP server so) and exits.
package main

import (
	"bufio"
	"context"
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

	"github.com/fpenezic/ssh-tool-plugins/openvpn/internal/ovpn"
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
	Cipher        string   `json:"cipher,omitempty"`
	MTU           int      `json:"mtu"`
	LocalMTU      int      `json:"local_mtu"`
	Addresses     []string `json:"addresses"`
	Routes        []string `json:"routes"`
	DNS           []string `json:"dns"`
	SearchDomains []string `json:"search_domains,omitempty"`
	TunnelAllDNS  bool     `json:"tunnel_all_dns"`
	Reason        string   `json:"reason"`
}

// prompts routes the app's auth answers to the waiting login.
var prompts = struct {
	sync.Mutex
	next    int
	waiting map[string]chan map[string]string
}{waiting: map[string]chan map[string]string{}}

func main() {
	mtu := flag.Int("mtu", 0, "local stack MTU (0 = the pushed tun-mtu, at most 1400)")
	showVersion := flag.Bool("version", false, "print helper version and exit")
	check := flag.Bool("check", false, "validate SSHTOOL_OVPN_CONFIG, print a summary event and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	log.SetOutput(os.Stderr)
	text := os.Getenv("SSHTOOL_OVPN_CONFIG")
	if text == "" {
		fatal("no configuration (SSHTOOL_OVPN_CONFIG)")
	}
	cfg, err := ovpn.ParseConfig(text)
	if err != nil {
		fatal("configuration: %v", err)
	}
	if *check {
		var remotes []string
		for _, r := range cfg.Remotes {
			remotes = append(remotes, fmt.Sprintf("%s:%d/%s", r.Host, r.Port, r.Proto))
		}
		mode := ""
		switch {
		case cfg.TLSAuth != "":
			mode = "tls-auth"
		case cfg.TLSCrypt != "":
			mode = "tls-crypt"
		}
		emit(map[string]any{
			"event": "check", "remotes": remotes, "auth_user_pass": cfg.AuthUserPass,
			"static_challenge": cfg.StaticChallenge, "client_cert": cfg.Cert != "",
			"tls_wrap": mode, "warnings": cfg.Warnings,
		})
		return
	}
	for _, w := range cfg.Warnings {
		log.Printf("config %s", w)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go readCommands(cancel)

	changed := make(chan struct{}, 1)
	client, err := ovpn.Connect(ctx, ovpn.Options{
		Config:      cfg,
		Credentials: askCredentials,
		Logf:        log.Printf,
		OpenURL: func(u string) {
			emit(map[string]string{"event": "open_url", "url": u})
		},
		OnChange: func() {
			select {
			case changed <- struct{}{}:
			default:
			}
		},
	})
	if err != nil {
		if ctx.Err() != nil {
			fatal("login cancelled")
		}
		fatal("%v", err)
	}
	ti, _ := client.Info()
	var addrs []netip.Addr
	for _, p := range ti.Push.Addresses {
		addrs = append(addrs, p.Addr())
	}
	localMTU := 1400
	if ti.Push.TunMTU > 0 && ti.Push.TunMTU < localMTU {
		localMTU = ti.Push.TunMTU
	}
	if *mtu > 0 {
		localMTU = *mtu
	}
	tdev, tnet, err := netstack.CreateNetTUN(addrs, ti.Push.DNS, localMTU)
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

	first := addrString(ti)
	emit(map[string]any{"event": "info", "info": buildInfo(ti, localMTU, "initial")})
	emit(map[string]any{"event": "ready", "socks": ln.Addr().String(), "protocol": protocolVersion})

	select { // the first connect's own change notice
	case <-changed:
	default:
	}
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	wasUp := true
	for {
		select {
		case <-ctx.Done():
			_ = ln.Close()
			_ = client.Close()
			return
		case <-client.Done():
			fatal("%v", client.Err())
		case <-changed:
			ti, up := client.Info()
			if up {
				if a := addrString(ti); a != first {
					log.Printf("tunnel address changed %s -> %s; open sessions will drop", first, a)
				}
				emit(map[string]any{"event": "info", "info": buildInfo(ti, localMTU, "reconnect")})
			}
		case <-t.C:
			ti, up := client.Info()
			peers := 0
			if up {
				peers = 1
			}
			if up != wasUp {
				if up {
					log.Printf("tunnel back up")
				} else {
					log.Printf("tunnel down, reconnecting")
				}
				wasUp = up
			}
			emit(map[string]any{"event": "status", "peers": peers, "transport": ti.Proto})
		}
	}
}

func addrString(ti ovpn.TunnelInfo) string {
	var s []string
	for _, a := range ti.Push.Addresses {
		s = append(s, a.String())
	}
	return strings.Join(s, ",")
}

func buildInfo(ti ovpn.TunnelInfo, localMTU int, reason string) tunnelInfo {
	in := tunnelInfo{
		Flavor: "openvpn", Server: ti.Remote, Transport: ti.Proto, Cipher: ti.Cipher,
		MTU: ti.Push.TunMTU, LocalMTU: localMTU, Gateway: ti.Push.RouteGateway,
		Addresses: []string{}, Routes: []string{}, DNS: []string{},
		SearchDomains: ti.Push.Domains, TunnelAllDNS: ti.Push.RedirectAll, Reason: reason,
	}
	for _, a := range ti.Push.Addresses {
		in.Addresses = append(in.Addresses, a.String())
	}
	in.Routes = append(in.Routes, ti.Push.Routes...)
	if ti.Push.RedirectAll {
		in.Routes = append([]string{"0.0.0.0/0 (redirect-gateway)"}, in.Routes...)
	}
	for _, d := range ti.Push.DNS {
		in.DNS = append(in.DNS, d.String())
	}
	return in
}

// askCredentials turns a login request into an auth event and waits for
// the app's answer.
func askCredentials(ctx context.Context, req ovpn.CredRequest) (ovpn.Creds, error) {
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
	ev := authEvent{Event: "auth", ID: id, Error: req.Error}
	respKind := "password"
	switch {
	case req.CRText != nil:
		ev.Message = req.CRText.Text
		if req.CRText.Echo {
			respKind = "text"
		}
		ev.Fields = []authField{{Key: "response", Name: "response", Label: req.CRText.Text, Kind: respKind}}
	case req.CRV1 != nil:
		ev.Message = req.CRV1.Text
		if req.CRV1.Echo {
			respKind = "text"
		}
		ev.Fields = []authField{{Key: "response", Name: "response", Label: req.CRV1.Text, Kind: respKind}}
	default:
		ev.Message = "Please enter your username and password."
		ev.Fields = []authField{
			{Key: "username", Name: "username", Label: "Username:", Kind: "text"},
			{Key: "password", Name: "password", Label: "Password:", Kind: "password"},
		}
		if req.Challenge != "" {
			if req.Echo {
				respKind = "text"
			}
			ev.Fields = append(ev.Fields, authField{Key: "response", Name: "response", Label: req.Challenge, Kind: respKind})
		}
	}
	emit(ev)
	select {
	case v, ok := <-ch:
		if !ok || v == nil {
			return ovpn.Creds{}, errors.New("login cancelled")
		}
		return ovpn.Creds{Username: v["username"], Password: v["password"], Response: v["response"]}, nil
	case <-ctx.Done():
		return ovpn.Creds{}, ctx.Err()
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
}, client *ovpn.Client) {
	bufs := [][]byte{make([]byte, 65536)}
	sizes := make([]int, 1)
	for ctx.Err() == nil {
		n, err := tdev.Read(bufs, sizes, 0)
		if err != nil {
			return
		}
		for i := 0; i < n; i++ {
			_ = client.WritePacket(bufs[i][:sizes[i]])
		}
	}
}

func pumpIn(ctx context.Context, tdev interface {
	Write([][]byte, int) (int, error)
}, client *ovpn.Client) {
	for {
		p, err := client.ReadPacket(ctx)
		if err != nil {
			return
		}
		if _, err := tdev.Write([][]byte{p}, 0); err != nil && ctx.Err() == nil {
			log.Printf("to stack: %v", err)
		}
	}
}
