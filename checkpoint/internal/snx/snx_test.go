package snx

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The "testuser" vector is from snx-rs's obfuscation test
// (https://github.com/ancwrd1/snx-rs, AGPL-3.0).
func TestObfuscate(t *testing.T) {
	if got := Obfuscate("testuser"); got != "36203a333d372a59" {
		t.Fatalf("Obfuscate = %s", got)
	}
	for _, s := range []string{"", "a", "testuser", "a longer secret with spaces & symbols !@#", strings.Repeat("x", 200)} {
		back, err := Deobfuscate(Obfuscate(s))
		if err != nil || back != s {
			t.Fatalf("round trip %q -> %q (%v)", s, back, err)
		}
	}
}

// sampleHelloReply is based on snx-rs's tests/hello_reply.txt
// (https://github.com/ancwrd1/snx-rs, AGPL-3.0): its address, DNS servers,
// first range, timeouts and subnet, with example search domains, and a
// host and the default-route marker in place of its second range.
const sampleHelloReply = "(hello_reply\n" +
	"\t:version (1)\n" +
	"\t:protocol_version (1)\n" +
	"\t:OM (\n" +
	"\t\t:ipaddr (10.0.0.10)\n" +
	"\t\t:dns_servers (\n" +
	"\t\t\t: (10.0.0.1)\n" +
	"\t\t\t: (10.0.0.2))\n" +
	"\t\t:dns_suffix (\"corp.example.com,lab.example.com\"))\n" +
	"\t:range (\n" +
	"\t\t: (\n\t\t\t:from (10.0.0.0)\n\t\t\t:to (10.255.255.255))\n" +
	"\t\t: (:from (192.168.1.5) :to (192.168.1.5))\n" +
	"\t\t: (:from (0.0.0.1) :to (255.255.255.254)))\n" +
	"\t:timeouts (\n\t\t:authentication (259193)\n\t\t:keepalive (20))\n" +
	"\t:optional (:subnet (255.255.255.0)))\x00"

func TestParseHello(t *testing.T) {
	n, err := Parse(sampleHelloReply)
	if err != nil {
		t.Fatal(err)
	}
	if n.Name != "hello_reply" || n.Str("range", "1", "from") != "192.168.1.5" {
		t.Fatalf("parsed %s", n)
	}
	h, err := parseHello(n)
	if err != nil {
		t.Fatal(err)
	}
	if h.Address.String() != "10.0.0.10" || h.Netmask.String() != "255.255.255.0" {
		t.Fatalf("address %v / %v", h.Address, h.Netmask)
	}
	if len(h.DNS) != 2 || strings.Join(h.SearchDomains, " ") != "corp.example.com lab.example.com" {
		t.Fatalf("dns %v %v", h.DNS, h.SearchDomains)
	}
	if got := prefixes(h.Routes); got != "10.0.0.0/8 192.168.1.5/32" {
		t.Fatalf("routes %s", got)
	}
	if h.Keepalive != 20*time.Second || h.AuthTimeout != 259193*time.Second {
		t.Fatalf("timeouts %v %v", h.Keepalive, h.AuthTimeout)
	}
	// Encoding parses back to the same thing.
	again, err := Parse(n.String())
	if err != nil || again.String() != n.String() {
		t.Fatalf("re-encode: %v\n%s", err, again)
	}
}

func TestParseShapes(t *testing.T) {
	for in, want := range map[string]string{
		"()":                          "()",
		"(abc)":                       "(abc)",
		"(Windows 10 Pro)":            `("Windows 10 Pro")`,
		`("a \"b\" c")`:               `("a \"b\" c")`,
		"(x :a () :b (1))":            "(x\n\t:a ()\n\t:b (1))",
		"(: (1) : (2))":               "(\n\t: (1)\n\t: (2))",
		"(:k (: (192.0.2.9 :m (1))))": "(\n\t:k (\n\t\t: (192.0.2.9\n\t\t\t:m (1))))",
	} {
		n, err := Parse(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got := n.String(); got != want {
			t.Fatalf("%q encoded as %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"", "(", "(a :b (1)", "(a) x", "(:a b)"} {
		if _, err := Parse(bad); err == nil {
			t.Fatalf("%q parsed", bad)
		}
	}
}

func TestRangeToPrefixes(t *testing.T) {
	for _, c := range []struct{ from, to, want string }{
		{"10.0.0.0", "10.255.255.255", "10.0.0.0/8"},
		{"10.0.0.1", "10.0.0.1", "10.0.0.1/32"},
		{"10.0.0.1", "10.0.0.6", "10.0.0.1/32 10.0.0.2/31 10.0.0.4/31 10.0.0.6/32"},
		{"0.0.0.0", "255.255.255.255", "0.0.0.0/0"},
		{"192.168.0.0", "192.168.3.255", "192.168.0.0/22"},
	} {
		got := prefixes(RangeToPrefixes(netip.MustParseAddr(c.from), netip.MustParseAddr(c.to)))
		if got != c.want {
			t.Errorf("%s-%s = %s, want %s", c.from, c.to, got, c.want)
		}
	}
}

func prefixes(ps []netip.Prefix) string {
	var s []string
	for _, p := range ps {
		s = append(s, p.String())
	}
	return strings.Join(s, " ")
}

// fakeGateway answers CCC on /clients/ and runs a SLIM tunnel on the same
// TLS port, the way a gateway does, for the username + password flow.
type fakeGateway struct {
	t        *testing.T
	srv      *httptest.Server
	ln       net.Listener
	user     string
	password string
	key      string
}

func newFakeGateway(t *testing.T) *fakeGateway {
	g := &fakeGateway{t: t, user: "alice", password: "s3cret pass", key: "ACTIVEKEY123"}
	g.srv = httptest.NewTLSServer(http.HandlerFunc(g.ccc))
	// The tunnel listens on its own port in the test; the client is told
	// so through tcpt_port.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", g.srv.TLS)
	if err != nil {
		t.Fatal(err)
	}
	g.ln = ln
	go g.slim()
	t.Cleanup(func() { g.srv.Close(); ln.Close() })
	return g
}

func (g *fakeGateway) reply(w http.ResponseWriter, typ string, data *Node) {
	io.WriteString(w, Obj("CCCserverResponse",
		"ResponseHeader", Obj("", "id", V("1"), "type", V(typ), "session_id", V(""), "return_code", V("600")),
		"ResponseData", data).String())
}

func (g *fakeGateway) ccc(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	req, err := Parse(string(body))
	if err != nil {
		g.t.Errorf("gateway got unparsable request: %v", err)
		return
	}
	typ := req.Str("RequestHeader", "type")
	rd := req.Get("RequestData")
	switch typ {
	case "ClientHello":
		_, port, _ := net.SplitHostPort(g.ln.Addr().String())
		g.reply(w, typ, Obj("",
			"protocol_version", Obj("", "protocol_version", V("100")),
			"connectivity_info", Obj("",
				"client_enabled", V("true"),
				"supported_data_tunnel_protocols", Arr(V("IPSec"), V("SSL")),
				"server_ip", V("127.0.0.1"),
				"tcpt_port", V(port),
			),
			"login_options_data", Obj("",
				"login_options_list", Obj("",
					"0", Obj("", "id", V("vpn_Username_Password"), "display_name", V("Username Password"),
						"factors", Obj("", "0", Obj("", "factor_type", V("password")))),
				),
			),
		))
	case "UserPass":
		u, _ := Deobfuscate(rd.Str("username"))
		if u != g.user {
			g.reply(w, typ, Obj("", "authn_status", V("done"), "is_authenticated", V("false"),
				"error_message", V(Obfuscate("Access denied - wrong user name or password"))))
			return
		}
		g.reply(w, typ, Obj("", "authn_status", V("continue"), "session_id", V("AUTHSESS"),
			"prompt", V(Obfuscate("Password:"))))
	case "MultiChallange":
		p, _ := Deobfuscate(rd.Str("user_input"))
		if rd.Str("auth_session_id") != "AUTHSESS" || p != g.password {
			g.reply(w, typ, Obj("", "authn_status", V("done"), "is_authenticated", V("false"),
				"error_message", V(Obfuscate("Access denied - wrong user name or password"))))
			return
		}
		g.reply(w, typ, Obj("", "authn_status", V("done"), "is_authenticated", V("true"),
			"active_key", V(Obfuscate(g.key)), "session_id", V("SESS1"), "active_key_timeout", V("259200")))
	case "ClientSettings":
		if req.Str("RequestHeader", "session_id") != "SESS1" {
			g.t.Errorf("ClientSettings without the session")
		}
		g.reply(w, typ, Obj("",
			"gw_internal_ip", V("192.0.2.1"),
			"updated_policies", Obj("", "range", Obj("", "settings", Arr(
				Obj("", "from", V("172.16.0.0"), "to", V("172.16.255.255")),
				Obj("", "from", V("0.0.0.1"), "to", V("255.255.255.254")),
			))),
		))
	case "Signout":
		g.reply(w, typ, Obj(""))
	default:
		g.t.Errorf("unexpected request %s", typ)
	}
}

func (g *fakeGateway) slim() {
	for {
		c, err := g.ln.Accept()
		if err != nil {
			return
		}
		go g.slimConn(c)
	}
}

func (g *fakeGateway) slimConn(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	read := func() (uint32, []byte, error) {
		var h [8]byte
		if _, err := io.ReadFull(r, h[:]); err != nil {
			return 0, nil, err
		}
		b := make([]byte, binary.BigEndian.Uint32(h[:4]))
		_, err := io.ReadFull(r, b)
		return binary.BigEndian.Uint32(h[4:]), b, err
	}
	write := func(typ uint32, p []byte) {
		h := make([]byte, 8, 8+len(p))
		binary.BigEndian.PutUint32(h[:4], uint32(len(p)))
		binary.BigEndian.PutUint32(h[4:], typ)
		c.Write(append(h, p...))
	}
	typ, p, err := read()
	if err != nil || typ != pktControl {
		return
	}
	hello, err := Parse(string(p))
	if err != nil || hello.Name != "client_hello" {
		g.t.Errorf("bad client_hello: %v %q", err, p)
		return
	}
	if hello.Str("cookie") != g.key {
		write(pktControl, []byte(Obj("disconnect", "code", V("2"), "message", V("Invalid cookie")).String()+"\x00"))
		return
	}
	write(pktControl, []byte(sampleHelloReply))
	for {
		typ, p, err := read()
		if err != nil {
			return
		}
		if typ == pktData {
			write(pktData, append([]byte("echo:"), p...)) // loop it back
		} else if n, _ := Parse(string(p)); n != nil && n.Name == "disconnect" {
			return
		}
	}
}

func TestLoginAndTunnel(t *testing.T) {
	fg := newFakeGateway(t)
	addr := strings.TrimPrefix(fg.srv.URL, "https://")
	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	gw := &Gateway{Server: addr, TLS: tlsCfg}
	ctx := context.Background()

	info, err := gw.Hello(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.LoginOptions) != 1 || info.LoginOptions[0].ID != "vpn_Username_Password" || info.LoginOptions[0].Factors[0] != "password" {
		t.Fatalf("login options %+v", info.LoginOptions)
	}

	if _, err := gw.Login(ctx, "vpn_Username_Password", "mallory", "dev"); err == nil ||
		!strings.Contains(err.Error(), "Access denied") {
		t.Fatalf("wrong user: %v", err)
	}
	r, err := gw.Login(ctx, "vpn_Username_Password", "alice", "dev")
	if err != nil || r.Done || r.Prompt != "Password:" || r.SessionID != "AUTHSESS" {
		t.Fatalf("login step 1: %+v %v", r, err)
	}
	if _, err := gw.Challenge(ctx, r.SessionID, "nope"); err == nil {
		t.Fatal("wrong password accepted")
	}
	r, err = gw.Challenge(ctx, r.SessionID, "s3cret pass")
	if err != nil || !r.Done || r.ActiveKey != fg.key || r.SessionID != "SESS1" {
		t.Fatalf("login step 2: %+v %v", r, err)
	}

	host, _, _ := net.SplitHostPort(addr)
	tunAddr := net.JoinHostPort(host, strconv.Itoa(info.TunnelPort))
	if _, err := Dial(ctx, DialOptions{Addr: tunAddr, TLS: tlsCfg, ActiveKey: "stale"}); err == nil ||
		!strings.Contains(err.Error(), "Invalid cookie") {
		t.Fatalf("stale cookie: %v", err)
	}
	tun, err := Dial(ctx, DialOptions{Addr: tunAddr, TLS: tlsCfg, ActiveKey: r.ActiveKey})
	if err != nil {
		t.Fatal(err)
	}
	if tun.Hello.Address.String() != "10.0.0.10" {
		t.Fatalf("hello %+v", tun.Hello)
	}
	if err := tun.WritePacket([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	p, err := tun.ReadPacket(rctx)
	if err != nil || string(p) != "echo:ping" {
		t.Fatalf("read %q %v", p, err)
	}
	routes, err := gw.Routes(ctx, r.SessionID)
	if err != nil || prefixes(routes) != "172.16.0.0/16" {
		t.Fatalf("client settings routes %v %v", routes, err)
	}
	tun.Close()
	if err := gw.Signout(ctx, r.SessionID); err != nil {
		t.Fatal(err)
	}
}
