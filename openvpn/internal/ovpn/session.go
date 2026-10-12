package ovpn

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	handWindow     = 60 * time.Second
	transitionWait = 60 * time.Second // lame duck key lifetime
	pushRetry      = 5 * time.Second
	maxRetransmits = 8
	firstReply     = 15 * time.Second // the server's reset; else try the next remote
)

var (
	errRestart     = errors.New("server asked for a restart")
	errPingRestart = errors.New("no packets from the server, restarting")
)

// AuthFailedError is the server refusing the credentials.
type AuthFailedError struct {
	Reason string
	// CRV1 is set for a dynamic challenge (the server asks a question,
	// e.g. a one-time code, and expects a reconnect with the answer).
	CRV1 *CRV1Challenge
}

func (e *AuthFailedError) Error() string {
	if e.Reason == "" {
		return "authentication failed"
	}
	return "authentication failed: " + e.Reason
}

// CRV1Challenge is "AUTH_FAILED,CRV1:flags:state:user_b64:text".
type CRV1Challenge struct {
	Echo     bool
	State    string
	Username string
	Text     string
}

// CRTextChallenge is a question the server asks during a pending login
// (CR_TEXT), usually a one-time code.
type CRTextChallenge struct {
	Echo bool
	Text string
}

// HaltError is the server telling the client to stop for good.
type HaltError struct{ Reason string }

func (e *HaltError) Error() string { return "server halted the session: " + e.Reason }

type ksEvent struct {
	ks   *keyState
	kb   *keyBlock
	msg  string
	err  error
	done bool // key material ready
}

type tlsChunk struct {
	ks   *keyState
	data []byte
}

// session is one OpenVPN session: hard reset, TLS, push, data, and
// renegotiations, until it fails or the client closes.
type session struct {
	c     *Client
	conn  net.Conn
	tcp   bool
	wmu   sync.Mutex
	wrap  wrapper
	creds credentials

	local, remote sessionID
	haveRemote    bool

	keys      map[byte]*keyState
	newest    *keyState
	nextKeyID byte

	ctrlIn chan []byte
	tlsOut chan tlsChunk
	events chan ksEvent

	pushBuf  []string
	pushDone atomic.Bool
	push     *PushReply
	cipher   string
	digest   string
	compress string
	peerID   int

	// pendingUntil is set while the server holds the login open
	// (AUTH_PENDING: a web login, a push approval, a CR_TEXT question).
	pendingUntil time.Time

	lastSend, lastRecv atomic.Int64
	readErr            chan error
	ready              chan *PushReply // first push applied
}

type credentials struct {
	user, pass string
	send       bool
}

func (s *session) logf(format string, args ...any) { s.c.logf(format, args...) }

func newSession(c *Client, conn net.Conn, tcp bool, creds credentials) (*session, error) {
	w, err := newWrapper(c.cfg)
	if err != nil {
		return nil, err
	}
	s := &session{
		c: c, conn: conn, tcp: tcp, wrap: w, creds: creds,
		keys:   map[byte]*keyState{},
		ctrlIn: make(chan []byte, 256), tlsOut: make(chan tlsChunk, 256),
		events: make(chan ksEvent, 64), readErr: make(chan error, 1),
		ready:    make(chan *PushReply, 1),
		compress: c.cfg.Compress, peerID: -1, digest: c.cfg.Auth,
	}
	if _, err := rand.Read(s.local[:]); err != nil {
		return nil, err
	}
	now := time.Now().UnixNano()
	s.lastSend.Store(now)
	s.lastRecv.Store(now)
	return s, nil
}

// writeWire sends one packet, framed for TCP.
func (s *session) writeWire(b []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.tcp {
		fr := make([]byte, 2+len(b))
		binary.BigEndian.PutUint16(fr, uint16(len(b)))
		copy(fr[2:], b)
		_, err := s.conn.Write(fr)
		return err
	}
	_, err := s.conn.Write(b)
	return err
}

func (s *session) readLoop() {
	buf := make([]byte, 65536)
	var r *bufio.Reader
	if s.tcp {
		r = bufio.NewReaderSize(s.conn, 65536)
	}
	for {
		var p []byte
		if s.tcp {
			var l [2]byte
			if _, err := io.ReadFull(r, l[:]); err != nil {
				s.readErr <- err
				return
			}
			n := int(binary.BigEndian.Uint16(l[:]))
			if _, err := io.ReadFull(r, buf[:n]); err != nil {
				s.readErr <- err
				return
			}
			p = buf[:n]
		} else {
			n, err := s.conn.Read(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					continue
				}
				s.readErr <- err
				return
			}
			p = buf[:n]
		}
		if len(p) == 0 {
			continue
		}
		switch p[0] >> 3 {
		case opDataV1, opDataV2:
			s.c.deliverData(s, p)
		default:
			select {
			case s.ctrlIn <- append([]byte(nil), p...):
			default:
				s.logf("control queue full, dropping a packet")
			}
		}
	}
}

// run drives the session until it fails or ctx ends.
func (s *session) run(ctx context.Context) error {
	go s.readLoop()
	ks := newKeyState(0)
	s.keys[0] = ks
	s.newest = ks
	s.nextKeyID = 1
	ks.enqueue(opHardResetClient2, nil)
	s.forwardTLS(ks)
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	defer s.closeKeys()
	for {
		if err := s.flush(); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-s.readErr:
			return fmt.Errorf("transport: %w", err)
		case p := <-s.ctrlIn:
			if err := s.handleCtrl(p); err != nil {
				return err
			}
		case ch := <-s.tlsOut:
			if s.keys[ch.ks.id] == ch.ks {
				ch.ks.enqueue(opControl, ch.data)
			}
		case ev := <-s.events:
			if err := s.handleEvent(ev); err != nil {
				return err
			}
		case <-tick.C:
			if err := s.timers(); err != nil {
				return err
			}
		}
	}
}

func (s *session) closeKeys() {
	for _, k := range s.keys {
		k.pipe.Close()
	}
}

// forwardTLS moves a key state's TLS writes into the loop.
func (s *session) forwardTLS(ks *keyState) {
	go func() {
		for {
			select {
			case d := <-ks.pipe.out:
				s.tlsOut <- tlsChunk{ks, d}
			case <-ks.pipe.closed:
				return
			}
		}
	}()
}

func (s *session) handleCtrl(wire []byte) error {
	plain, err := s.wrap.unwrap(wire)
	if err != nil {
		if errors.Is(err, errReplay) {
			return nil
		}
		s.logf("dropping control packet: %v", err)
		return nil
	}
	p, err := decodeCtrl(plain)
	if err != nil {
		return nil
	}
	if s.haveRemote && p.sid != s.remote {
		return nil // another session's leftovers
	}
	s.lastRecv.Store(time.Now().UnixNano())
	ks := s.keys[p.keyID]
	switch p.op {
	case opHardResetServer2:
		if p.keyID != 0 || ks == nil {
			return nil
		}
		if !s.haveRemote {
			s.remote, s.haveRemote = p.sid, true
		}
	case opSoftReset:
		if !s.haveRemote {
			return nil
		}
		if ks == nil || ks.ready || ks.failed {
			// The server renegotiates: answer with our own soft reset
			// on the new key id and run a fresh TLS handshake there.
			if old := s.keys[p.keyID]; old != nil {
				s.retire(old, 0)
			}
			ks = newKeyState(p.keyID)
			s.keys[p.keyID] = ks
			s.newest = ks
			s.nextKeyID = nextKeyID(p.keyID)
			ks.enqueue(opSoftReset, nil)
			s.forwardTLS(ks)
			s.logf("renegotiating keys (server, key id %d)", p.keyID)
		}
	case opControl, opAck:
	default:
		return nil
	}
	if ks == nil {
		return nil
	}
	if len(p.acks) > 0 && p.ackSID == s.local {
		ks.ack(p.acks)
	}
	if p.op == opAck {
		s.maybeStartTLS(ks)
		return nil
	}
	deliver, _ := ks.receive(p.id, p.payload)
	for _, d := range deliver {
		select {
		case ks.pipe.in <- d:
		default:
			return errors.New("TLS input overflow")
		}
	}
	s.maybeStartTLS(ks)
	return nil
}

// maybeStartTLS starts the handshake once both resets crossed: ours is
// acknowledged and the server's arrived.
func (s *session) maybeStartTLS(ks *keyState) {
	if ks.tls != nil || !s.haveRemote || ks.recvNext == 0 {
		return
	}
	for _, m := range ks.inflight {
		if m.id == 0 {
			return
		}
	}
	for _, m := range ks.queue {
		if m.id == 0 {
			return
		}
	}
	tc, err := s.c.tlsConfig()
	if err != nil {
		s.events <- ksEvent{ks: ks, err: err}
		return
	}
	ks.tls = tls.Client(ks.pipe, tc)
	go s.runTLS(ks, ks.id == 0)
}

func (s *session) options() string {
	proto := "UDPv4"
	if s.tcp {
		proto = "TCPv4_CLIENT"
	}
	cipher := s.cipher
	if cipher == "" {
		cipher = s.c.cfg.Cipher
	}
	if cipher == "" {
		cipher = "AES-256-GCM"
	}
	return fmt.Sprintf("V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto %s,cipher %s,auth [null-digest],keysize 256,key-method 2,tls-client", proto, cipher)
}

func peerInfo(c *Config) string {
	plat := map[string]string{"windows": "win", "darwin": "mac"}[runtime.GOOS]
	if plat == "" {
		plat = runtime.GOOS
	}
	ciphers := c.DataCiphers
	if len(ciphers) == 0 {
		ciphers = supportedCiphers
	}
	var ok []string
	for _, x := range ciphers {
		if _, known := ciphersByName(x); known {
			ok = append(ok, x)
		}
	}
	// IV_PROTO: 2 = P_DATA_V2, 16 = AUTH_PENDING with keywords.
	// IV_SSO: the pending-login methods handled (handleInfo).
	return "IV_VER=2.6.0\nIV_PLAT=" + plat + "\nIV_PROTO=18\nIV_NCP=2\nIV_CIPHERS=" + strings.Join(ok, ":") +
		"\nIV_SSO=openurl,webauth,crtext\nIV_GUI_VER=ssh-tool\n"
}

func ciphersByName(n string) (cipherSpec, bool) {
	c, ok := ciphers[strings.ToUpper(n)]
	return c, ok
}

// runTLS is a key state's TLS side: handshake, key method 2, then the
// server's control messages (push reply, auth failure, restart...).
func (s *session) runTLS(ks *keyState, first bool) {
	fail := func(err error) { s.events <- ksEvent{ks: ks, err: err} }
	if err := ks.tls.Handshake(); err != nil {
		fail(fmt.Errorf("TLS handshake: %w", err))
		return
	}
	km, err := newKM2()
	if err != nil {
		fail(err)
		return
	}
	user, pass := s.creds.user, s.creds.pass
	if tok := s.c.authToken(); tok != "" && s.creds.send {
		pass = tok
		if u := s.c.authTokenUser(); u != "" {
			user = u
		}
	}
	if _, err := ks.tls.Write(km.message(s.options(), user, pass, peerInfo(s.c.cfg), s.creds.send)); err != nil {
		fail(err)
		return
	}
	r := bufio.NewReader(ks.tls)
	r1, r2, _, err := readServerKM2(r)
	if err != nil {
		fail(fmt.Errorf("key exchange: %w", err))
		return
	}
	s.events <- ksEvent{ks: ks, kb: keyExpansion(km, r1, r2, s.local, s.remote), done: true}
	if first {
		go func() {
			for !s.pushDone.Load() {
				if _, err := ks.tls.Write([]byte("PUSH_REQUEST\x00")); err != nil {
					return
				}
				for i := 0; i < int(pushRetry/(100*time.Millisecond)) && !s.pushDone.Load(); i++ {
					time.Sleep(100 * time.Millisecond)
				}
			}
		}()
	}
	for {
		m, err := readMessage(r)
		if err != nil {
			return // closed with the key state
		}
		s.events <- ksEvent{ks: ks, msg: m}
	}
}

func (s *session) handleEvent(ev ksEvent) error {
	ks := ev.ks
	if s.keys[ks.id] != ks {
		return nil
	}
	switch {
	case ev.err != nil:
		ks.failed = true
		if ks.id == 0 && s.push == nil {
			return ev.err
		}
		return fmt.Errorf("renegotiation (key id %d): %w", ks.id, ev.err)
	case ev.done:
		ks.kb = ev.kb
		ks.ready = true
		if s.push != nil {
			return s.activate(ks)
		}
	case ev.msg != "":
		return s.handleMessage(ks, ev.msg)
	}
	return nil
}

// activate builds a key state's data key and makes it the one data is
// sent with; the previous key keeps decrypting for the transition.
func (s *session) activate(ks *keyState) error {
	dk, err := newDataKey(ks.id, ks.kb, s.cipher, s.digest)
	if err != nil {
		return err
	}
	ks.data = dk
	for _, o := range s.keys {
		if o != ks && o.data != nil && o.retireAt.IsZero() {
			s.retire(o, transitionWait)
		}
	}
	s.c.setKey(s, dk)
	if ks.id != 0 {
		s.logf("renegotiation done, key id %d in use", ks.id)
	}
	return nil
}

func (s *session) retire(ks *keyState, after time.Duration) {
	ks.retireAt = time.Now().Add(after)
}

func (s *session) handleMessage(ks *keyState, m string) error {
	switch {
	case strings.HasPrefix(m, "PUSH_REPLY"):
		body := strings.TrimPrefix(strings.TrimPrefix(m, "PUSH_REPLY"), ",")
		if s.push != nil {
			// A later push renews the auth-token (sent after each
			// renegotiation with auth-gen-token); the rest stays.
			if tok, user := tokenUpdate(body); tok != "" {
				s.c.setAuthToken(tok, user)
			}
			return nil
		}
		s.pushBuf = append(s.pushBuf, body)
		if strings.Contains(body, "push-continuation 2") {
			return nil // more parts follow
		}
		pr, err := parsePush(strings.Join(s.pushBuf, ","))
		if err != nil {
			return err
		}
		s.pushDone.Store(true)
		return s.applyPush(ks, pr)
	case strings.HasPrefix(m, "AUTH_FAILED"):
		reason := strings.TrimPrefix(strings.TrimPrefix(m, "AUTH_FAILED"), ",")
		e := &AuthFailedError{Reason: reason}
		if strings.HasPrefix(reason, "CRV1:") {
			e.CRV1 = parseCRV1(reason)
		}
		return e
	case strings.HasPrefix(m, "RESTART"):
		return errRestart
	case strings.HasPrefix(m, "HALT"):
		return &HaltError{Reason: strings.TrimPrefix(strings.TrimPrefix(m, "HALT"), ",")}
	case strings.HasPrefix(m, "AUTH_PENDING"):
		// The server finishes the login out of band: a browser login
		// (OPEN_URL / WEB_AUTH), a question (CR_TEXT) or an approval
		// on a phone. It pushes once done; wait up to its timeout.
		wait := 120
		for _, kv := range strings.Split(strings.TrimPrefix(strings.TrimPrefix(m, "AUTH_PENDING"), ","), ",") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(kv), "timeout "); ok {
				if n, err := strconv.Atoi(v); err == nil && n > 0 {
					wait = n
				}
			}
		}
		s.pendingUntil = time.Now().Add(time.Duration(wait) * time.Second)
		s.logf("the server is waiting for the login to be completed (up to %ds)", wait)
	case strings.HasPrefix(m, "INFO_PRE,") || strings.HasPrefix(m, "INFO,"):
		return s.handleInfo(ks, m[strings.IndexByte(m, ',')+1:])
	default:
		s.logf("server message ignored: %.60s", m)
	}
	return nil
}

// handleInfo acts on the pending-login messages: open a browser for
// OPEN_URL / WEB_AUTH, ask a CR_TEXT question and send the answer back.
func (s *session) handleInfo(ks *keyState, body string) error {
	switch {
	case strings.HasPrefix(body, "OPEN_URL:"):
		s.c.openURL(strings.TrimPrefix(body, "OPEN_URL:"))
	case strings.HasPrefix(body, "WEB_AUTH:"):
		// WEB_AUTH:flags:url
		if parts := strings.SplitN(body, ":", 3); len(parts) == 3 {
			s.c.openURL(parts[2])
		}
	case strings.HasPrefix(body, "CR_TEXT:"):
		// CR_TEXT:flags:question; E = echo the answer, R = required
		parts := strings.SplitN(body, ":", 3)
		if len(parts) < 3 {
			return nil
		}
		ch := &CRTextChallenge{Echo: strings.Contains(parts[1], "E"), Text: strings.TrimSpace(parts[2])}
		tconn := ks.tls
		go func() {
			a, err := s.c.askCRText(ch)
			if err != nil {
				s.events <- ksEvent{ks: ks, err: err}
				return
			}
			msg := "CR_RESPONSE," + base64.StdEncoding.EncodeToString([]byte(a)) + "\x00"
			if _, err := tconn.Write([]byte(msg)); err != nil {
				s.events <- ksEvent{ks: ks, err: err}
			}
		}()
	default:
		s.logf("server: %.200s", body)
	}
	return nil
}

func (s *session) applyPush(ks *keyState, pr *PushReply) error {
	cipher := pr.Cipher
	if cipher == "" {
		cipher = s.c.cfg.Cipher
	}
	if cipher == "" {
		return errors.New("the server did not negotiate a data cipher and the configuration has none")
	}
	if _, ok := ciphersByName(cipher); !ok {
		return fmt.Errorf("data cipher %s is not supported", cipher)
	}
	s.cipher = strings.ToUpper(cipher)
	if pr.Auth != "" {
		s.digest = pr.Auth
	}
	if pr.Compress != "" {
		s.compress = pr.Compress
	}
	if pr.PeerID >= 0 {
		s.peerID = pr.PeerID
	}
	if pr.AuthToken != "" {
		s.c.setAuthToken(pr.AuthToken, pr.AuthTokenUser)
	}
	s.push = pr
	if err := s.activate(ks); err != nil {
		return err
	}
	select {
	case s.ready <- pr:
	default:
	}
	return nil
}

// flush sends what the windows allow: queued messages, retransmits and
// bare acknowledgements.
func (s *session) flush() error {
	now := time.Now()
	for _, ks := range s.keys {
		for len(ks.inflight) < sendWindow && len(ks.queue) > 0 {
			ks.inflight = append(ks.inflight, ks.queue[0])
			ks.queue = ks.queue[1:]
		}
		for _, m := range ks.inflight {
			if !m.sentAt.IsZero() && now.Sub(m.sentAt) < rto(m.tries) {
				continue
			}
			if m.tries >= maxRetransmits {
				return fmt.Errorf("control channel: no answer from the server (key id %d)", ks.id)
			}
			p := &ctrlPacket{op: m.op, keyID: ks.id, sid: s.local, id: m.id, payload: m.payload}
			if s.haveRemote {
				p.acks = ks.takeAcks()
				p.ackSID = s.remote
			}
			if err := s.send(p); err != nil {
				return err
			}
			m.sentAt = now
			m.tries++
		}
		for len(ks.acks) > 0 && s.haveRemote {
			p := &ctrlPacket{op: opAck, keyID: ks.id, sid: s.local, acks: ks.takeAcks(), ackSID: s.remote}
			if err := s.send(p); err != nil {
				return err
			}
		}
	}
	return nil
}

func rto(tries int) time.Duration {
	d := 2 * time.Second << max(tries-1, 0)
	return min(d, 16*time.Second)
}

func (s *session) send(p *ctrlPacket) error {
	s.lastSend.Store(time.Now().UnixNano())
	return s.writeWire(s.wrap.wrap(p.encode()))
}

func (s *session) timers() error {
	now := time.Now()
	if !s.haveRemote && now.Sub(s.keys[0].started) > firstReply {
		return errors.New("no answer from the server (wrong address or port, a firewall, or a tls-auth / tls-crypt key mismatch)")
	}
	for id, ks := range s.keys {
		if !ks.retireAt.IsZero() && now.After(ks.retireAt) {
			ks.pipe.Close()
			delete(s.keys, id)
			s.c.dropKey(s, ks.data)
			continue
		}
		if !ks.ready && now.Sub(ks.started) > handWindow {
			if s.push == nil {
				return errors.New("TLS key negotiation did not finish within 60 seconds (check tls-auth / tls-crypt key, certificates and the server log)")
			}
			return fmt.Errorf("renegotiation (key id %d) did not finish within 60 seconds", id)
		}
	}
	if s.push == nil {
		if !s.pendingUntil.IsZero() && now.After(s.pendingUntil) {
			return errors.New("the login was not completed in time (browser login, question or approval)")
		}
		return nil
	}
	ping, restart := s.c.cfg.Ping, s.c.cfg.PingRestart
	if s.push.Ping > 0 {
		ping = s.push.Ping
	}
	if s.push.PingRestart > 0 {
		restart = s.push.PingRestart
	}
	if ping > 0 && now.Sub(time.Unix(0, s.lastSend.Load())) >= time.Duration(ping)*time.Second {
		_ = s.c.writeData(s, pingMagic, true)
	}
	if restart > 0 && now.Sub(time.Unix(0, s.lastRecv.Load())) >= time.Duration(restart)*time.Second {
		return errPingRestart
	}
	if r := s.c.cfg.RenegSec; r > 0 && s.newest.ready && now.Sub(s.newest.started) >= time.Duration(r)*time.Second {
		s.renegotiate()
	}
	return nil
}

// renegotiate starts a client-side soft reset on the next key id.
func (s *session) renegotiate() {
	id := s.nextKeyID
	s.nextKeyID = nextKeyID(id)
	if old := s.keys[id]; old != nil {
		old.pipe.Close()
		s.c.dropKey(s, old.data)
	}
	ks := newKeyState(id)
	s.keys[id] = ks
	s.newest = ks
	ks.enqueue(opSoftReset, nil)
	s.forwardTLS(ks)
	s.logf("renegotiating keys (client, key id %d)", id)
}

func nextKeyID(id byte) byte {
	id = (id + 1) & 7
	if id == 0 {
		id = 1
	}
	return id
}

// exitNotify tells a UDP server the client is leaving, so it frees the
// session at once instead of waiting for its ping timeout.
func (s *session) exitNotify() {
	if s.tcp || s.push == nil {
		return
	}
	msg := append(append([]byte(nil), occMagic...), occExit)
	for i := 0; i < 2; i++ {
		_ = s.c.writeData(s, msg, true)
	}
}

func (c *Client) tlsConfig() (*tls.Config, error) {
	cfg := c.cfg
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(cfg.CA)) {
		return nil, errors.New("<ca> holds no certificate")
	}
	tc := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// OpenVPN does not tie the server certificate to a host name:
		// the chain is checked against <ca> below, plus remote-cert-tls
		// and verify-x509-name.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			return verifyServer(cfg, pool, raw)
		},
	}
	if cfg.Cert != "" {
		certPEM := cfg.Cert + "\n" + cfg.ExtraCerts
		pair, err := tls.X509KeyPair([]byte(certPEM), []byte(cfg.Key))
		if err != nil {
			if blk, _ := pem.Decode([]byte(cfg.Key)); blk != nil && (blk.Type == "ENCRYPTED PRIVATE KEY" || blk.Headers["Proc-Type"] != "") {
				return nil, errors.New("the client key is encrypted; store it decrypted")
			}
			return nil, fmt.Errorf("client certificate: %w", err)
		}
		tc.Certificates = []tls.Certificate{pair}
	}
	return tc, nil
}

func verifyServer(cfg *Config, pool *x509.CertPool, raw [][]byte) error {
	if len(raw) == 0 {
		return errors.New("server sent no certificate")
	}
	certs := make([]*x509.Certificate, len(raw))
	for i, r := range raw {
		c, err := x509.ParseCertificate(r)
		if err != nil {
			return err
		}
		certs[i] = c
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	leaf := certs[0]
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return fmt.Errorf("server certificate: %w", err)
	}
	if cfg.RemoteCertTLS == "server" {
		ok := false
		for _, u := range leaf.ExtKeyUsage {
			if u == x509.ExtKeyUsageServerAuth {
				ok = true
			}
		}
		if !ok {
			return errors.New("server certificate is not a TLS server certificate (remote-cert-tls server)")
		}
	}
	if cfg.VerifyX509Name != "" && !x509NameMatches(leaf, cfg.VerifyX509Name, cfg.VerifyX509Type) {
		return fmt.Errorf("server certificate name does not match verify-x509-name %q", cfg.VerifyX509Name)
	}
	return nil
}

func x509NameMatches(c *x509.Certificate, want, kind string) bool {
	switch kind {
	case "name":
		return c.Subject.CommonName == want
	case "name-prefix":
		return strings.HasPrefix(c.Subject.CommonName, want)
	}
	// subject: compare as a set of attribute=value pairs, whatever order
	// or separator the configuration writes them in.
	norm := func(s string) map[string]bool {
		m := map[string]bool{}
		for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '/' }) {
			if part = strings.TrimSpace(part); part != "" {
				m[strings.ToUpper(part[:strings.IndexByte(part+"=", '=')])+part[strings.IndexByte(part+"=", '='):]] = true
			}
		}
		return m
	}
	a, b := norm(c.Subject.String()), norm(want)
	if len(a) != len(b) {
		return false
	}
	for k := range b {
		if !a[k] {
			return false
		}
	}
	return true
}

func parseCRV1(reason string) *CRV1Challenge {
	// CRV1:flags:state_id:username_base64:text
	parts := strings.SplitN(strings.TrimPrefix(reason, "CRV1:"), ":", 4)
	if len(parts) < 4 {
		return nil
	}
	ch := &CRV1Challenge{Echo: strings.Contains(parts[0], "E"), State: parts[1], Text: strings.TrimSpace(parts[3])}
	if u, err := decodeB64(parts[2]); err == nil {
		ch.Username = u
	}
	return ch
}
