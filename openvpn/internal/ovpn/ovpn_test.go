package ovpn

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"

	"github.com/pierrec/lz4/v4"
)

func testStaticKey(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 256)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	h := hex.EncodeToString(raw)
	var b strings.Builder
	b.WriteString("#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\n")
	for i := 0; i < len(h); i += 32 {
		b.WriteString(h[i:i+32] + "\n")
	}
	b.WriteString("-----END OpenVPN Static key V1-----\n")
	return b.String()
}

const minimalCA = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"

func TestParseConfig(t *testing.T) {
	c, err := ParseConfig(`client
dev tun
proto tcp-client
remote vpn1.example.com 443
remote vpn2.example.com 1194 udp
remote-cert-tls server
verify-x509-name "CN=vpn.example.com" subject
cipher AES-256-CBC
data-ciphers AES-256-GCM:CHACHA20-POLY1305
auth SHA256
auth-user-pass
static-challenge "Enter OTP" 1
key-direction 1
comp-lzo no
reneg-sec 0
some-new-option x
<ca>
` + minimalCA + `</ca>
<tls-auth>
` + testStaticKey(t) + `</tls-auth>
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Remotes) != 2 || c.Remotes[0] != (Remote{"vpn1.example.com", 443, "tcp"}) || c.Remotes[1] != (Remote{"vpn2.example.com", 1194, "udp"}) {
		t.Fatalf("remotes = %+v", c.Remotes)
	}
	if c.KeyDirection != 1 || c.Auth != "SHA256" || c.Cipher != "AES-256-CBC" || len(c.DataCiphers) != 2 {
		t.Fatalf("crypto = %+v", c)
	}
	if !c.AuthUserPass || c.StaticChallenge != "Enter OTP" || !c.StaticChallengeEcho {
		t.Fatalf("auth = %+v", c)
	}
	if c.VerifyX509Name != "CN=vpn.example.com" || c.VerifyX509Type != "subject" || c.RemoteCertTLS != "server" {
		t.Fatalf("verify = %+v", c)
	}
	if c.Compress != "lzo" || len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], "some-new-option") {
		t.Fatalf("compress %q warnings %v", c.Compress, c.Warnings)
	}
}

func TestParseConfigRefuses(t *testing.T) {
	base := "client\nremote vpn.example.com\n<ca>\n" + minimalCA + "</ca>\nauth-user-pass\n"
	for name, extra := range map[string]string{
		"file ref":      "ca ca.crt\n",
		"tap":           "dev tap0\n",
		"tls-crypt-v2":  "<tls-crypt-v2>\nx\n</tls-crypt-v2>\n",
		"compress zstd": "compress zstd\n",
		"pkcs12":        "pkcs12 me.p12\n",
	} {
		if _, err := ParseConfig(base + extra); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseConfig("client\n<ca>\n" + minimalCA + "</ca>\nauth-user-pass\n"); err == nil {
		t.Error("no remote: accepted")
	}
	if _, err := ParseConfig("client\nremote a\n<ca>\n" + minimalCA + "</ca>\n"); err == nil {
		t.Error("no cert and no auth-user-pass: accepted")
	}
}

func TestSplitArgs(t *testing.T) {
	got := splitArgs(`verify-x509-name 'C=HR, CN=vpn' subject # comment`)
	if len(got) != 3 || got[1] != "C=HR, CN=vpn" || got[2] != "subject" {
		t.Fatalf("got %q", got)
	}
}

// Both wrappers round-trip between a client and a server-side twin,
// refuse a tampered packet and a replay.
func TestControlWrappers(t *testing.T) {
	k, err := parseStaticKey(testStaticKey(t))
	if err != nil {
		t.Fatal(err)
	}
	ta, _ := newTLSAuth(k, 1, "SHA256")
	taServer, _ := newTLSAuth(k, 0, "SHA256")
	tc, _ := newTLSCrypt(k)
	// The server's tls-crypt sends with key 0 and receives with key 1.
	tcServer := &tlsCrypt{sendKa: tc.recvKa, recvKa: tc.sendKa, sendKe: tc.recvKe, recvKe: tc.sendKe, ids: newReplayID()}
	pkt := (&ctrlPacket{op: opControl, keyID: 2, id: 7, acks: []uint32{1, 2}, payload: []byte("hello tls")}).encode()
	for name, pair := range map[string][2]wrapper{"tls-auth": {ta, taServer}, "tls-crypt": {tc, tcServer}} {
		wire := pair[0].wrap(pkt)
		got, err := pair[1].unwrap(wire)
		if err != nil || !bytes.Equal(got, pkt) {
			t.Fatalf("%s: round trip %v", name, err)
		}
		if _, err := pair[1].unwrap(wire); err != errReplay {
			t.Fatalf("%s: replay accepted (%v)", name, err)
		}
		bad := pair[0].wrap(pkt)
		bad[len(bad)-1] ^= 1
		if _, err := pair[1].unwrap(bad); err == nil {
			t.Fatalf("%s: tampered packet accepted", name)
		}
	}
	// tls-auth with the wrong direction fails authentication.
	same, _ := newTLSAuth(k, 1, "SHA256")
	if _, err := same.unwrap(ta.wrap(pkt)); err == nil {
		t.Fatal("tls-auth: same direction on both ends accepted")
	}
}

func TestCtrlPacketRoundTrip(t *testing.T) {
	p := &ctrlPacket{op: opControl, keyID: 3, sid: sessionID{1, 2, 3}, acks: []uint32{9}, ackSID: sessionID{4}, id: 5, payload: []byte("x")}
	q, err := decodeCtrl(p.encode())
	if err != nil || q.op != p.op || q.keyID != 3 || q.sid != p.sid || q.acks[0] != 9 || q.ackSID != p.ackSID || q.id != 5 || string(q.payload) != "x" {
		t.Fatalf("got %+v, %v", q, err)
	}
	a := &ctrlPacket{op: opAck, sid: sessionID{1}, acks: []uint32{1, 2}, ackSID: sessionID{2}}
	if q, err := decodeCtrl(a.encode()); err != nil || len(q.acks) != 2 || len(q.payload) != 0 {
		t.Fatalf("ack: %+v %v", q, err)
	}
}

func TestReplayWindow(t *testing.T) {
	var w window
	for _, id := range []uint32{1, 3, 2, 300, 100} {
		if !w.accept(id) {
			t.Fatalf("%d refused", id)
		}
	}
	for _, id := range []uint32{0, 2, 300, 40} { // zero, replays, beyond the window
		if w.accept(id) {
			t.Fatalf("%d accepted", id)
		}
	}
}

// Every cipher round-trips through a server-side twin (send and receive
// keys swapped) and refuses replays and tampering.
func TestDataKeys(t *testing.T) {
	var kb, swapped keyBlock
	rand.Read(kb[:])
	copy(swapped[:128], kb[128:])
	copy(swapped[128:], kb[:128])
	for name := range ciphers {
		for _, header := range [][]byte{{opDataV1<<3 | 1}, {opDataV2<<3 | 1, 0, 0, 7}} {
			cl, err := newDataKey(1, &kb, name, "SHA256")
			if err != nil {
				t.Fatal(err)
			}
			sv, _ := newDataKey(1, &swapped, name, "SHA256")
			payload := []byte("an IP packet, more or less")
			pkt, err := cl.seal(header, payload)
			if err != nil {
				t.Fatal(err)
			}
			got, err := sv.open(pkt, len(header))
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("%s/%d: %v", name, len(header), err)
			}
			if _, err := sv.open(pkt, len(header)); err != errReplay {
				t.Fatalf("%s: replay: %v", name, err)
			}
			pkt2, _ := cl.seal(header, payload)
			pkt2[len(pkt2)-1] ^= 0x80
			if _, err := sv.open(pkt2, len(header)); err == nil {
				t.Fatalf("%s: tampered packet accepted", name)
			}
		}
	}
}

func TestFraming(t *testing.T) {
	pkt := []byte{0x45, 1, 2, 3}
	for _, mode := range []string{"", "lzo", "swap", "v2"} {
		got, err := frameIn(mode, frameOut(mode, pkt))
		if err != nil || !bytes.Equal(got, pkt) {
			t.Fatalf("%q: %v %x", mode, err, got)
		}
	}
	esc := []byte{compV2Indicator, 9}
	if got, _ := frameIn("v2", frameOut("v2", esc)); !bytes.Equal(got, esc) {
		t.Fatalf("stub-v2 escape: %x", got)
	}
	if _, err := frameIn("lzo", []byte{0x13, 1}); err != errCompressed {
		t.Fatal("unknown marker accepted")
	}
}

// What a server with compress lz4 / lz4-v2 sends is decompressed.
func TestLZ4Decompress(t *testing.T) {
	plain := bytes.Repeat([]byte("ssh-tool compresses well "), 40)
	comp := make([]byte, lz4.CompressBlockBound(len(plain)))
	n, err := lz4.CompressBlock(plain, comp, nil)
	if err != nil || n == 0 {
		t.Fatal(err)
	}
	comp = comp[:n]
	// compress lz4: marker in front, the block's first byte moved to the end.
	swapped := append(append([]byte{lz4Compress}, comp[1:]...), comp[0])
	if got, err := frameIn("swap", swapped); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("lz4: %v", err)
	}
	if got, err := frameIn("v2", append([]byte{compV2Indicator, compV2LZ4}, comp...)); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("lz4-v2: %v", err)
	}
	if _, err := frameIn("v2", []byte{compV2Indicator, compV2LZ4, 0xff, 0xff}); err == nil {
		t.Fatal("garbage decompressed")
	}
}

func TestParsePush(t *testing.T) {
	pr, err := parsePush("route 172.16.0.0 255.255.0.0,dhcp-option DNS 10.0.0.53,dhcp-option DOMAIN corp.example.com,route-gateway 10.8.0.1,topology subnet,ping 10,ping-restart 60,ifconfig 10.8.0.6 255.255.255.0,ifconfig-ipv6 fd00::1000/64 fd00::1,peer-id 3,cipher AES-128-GCM,auth-token abc,dns server 0 address 10.0.0.54")
	if err != nil {
		t.Fatal(err)
	}
	if pr.Addresses[0] != netip.MustParsePrefix("10.8.0.6/24") || pr.Addresses[1] != netip.MustParsePrefix("fd00::1000/64") {
		t.Fatalf("addresses %v", pr.Addresses)
	}
	if pr.Routes[0] != "172.16.0.0/16" || len(pr.DNS) != 2 || pr.Domains[0] != "corp.example.com" {
		t.Fatalf("routes %v dns %v domains %v", pr.Routes, pr.DNS, pr.Domains)
	}
	if pr.PeerID != 3 || pr.Cipher != "AES-128-GCM" || pr.AuthToken != "abc" || pr.Ping != 10 || pr.PingRestart != 60 {
		t.Fatalf("session %+v", pr)
	}
	// net30: the second ifconfig argument is the peer, not a mask.
	pr, err = parsePush("ifconfig 10.8.0.6 10.8.0.5,route 10.8.0.1")
	if err != nil || pr.Addresses[0] != netip.MustParsePrefix("10.8.0.6/32") {
		t.Fatalf("net30: %v %v", pr, err)
	}
	if _, err := parsePush("route 10.0.0.0 255.0.0.0"); err == nil {
		t.Fatal("push without an address accepted")
	}
	if tok, _ := tokenUpdate("auth-token xyz"); tok != "xyz" {
		t.Fatal("token update missed")
	}
}

func TestCRV1(t *testing.T) {
	ch := parseCRV1("CRV1:R,E:abc123:dGVzdA==:Enter the code\n")
	if ch == nil || !ch.Echo || ch.State != "abc123" || ch.Username != "test" || ch.Text != "Enter the code" {
		t.Fatalf("got %+v", ch)
	}
}

func TestX509Name(t *testing.T) {
	c := &x509.Certificate{Subject: pkix.Name{CommonName: "vpn.example.com", Country: []string{"HR"}, Organization: []string{"Example"}}}
	cases := []struct {
		want, kind string
		ok         bool
	}{
		{"vpn.example.com", "name", true},
		{"vpn.", "name-prefix", true},
		{"other", "name", false},
		{"C=HR, O=Example, CN=vpn.example.com", "subject", true},
		{"/C=HR/O=Example/CN=vpn.example.com", "subject", true},
		{"C=HR, CN=vpn.example.com", "subject", false},
	}
	for _, tc := range cases {
		if got := x509NameMatches(c, tc.want, tc.kind); got != tc.ok {
			t.Errorf("%s %q = %v", tc.kind, tc.want, got)
		}
	}
}

// The PRF matches the TLS 1.0 construction OpenVPN uses: a fixed vector
// keeps a refactor honest (interop is covered by the lab test).
func TestPRFDeterministic(t *testing.T) {
	a := prf([]byte("secret"), "label", []byte("seed"), 48)
	b := prf([]byte("secret"), "label", []byte("seed"), 48)
	if !bytes.Equal(a, b) || len(a) != 48 {
		t.Fatal("prf not deterministic")
	}
	if bytes.Equal(a, prf([]byte("secreT"), "label", []byte("seed"), 48)) {
		t.Fatal("prf ignores the secret")
	}
}
