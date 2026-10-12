package ovpn

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CredRequest asks the caller for a login.
type CredRequest struct {
	// Error is the server's reason after a refused login ("" the first
	// time).
	Error string
	// Challenge is the static-challenge prompt ("" = none): the answer
	// goes in Creds.Response, alongside the password.
	Challenge string
	Echo      bool
	// CRV1 is a dynamic challenge: only Creds.Response is used.
	CRV1 *CRV1Challenge
	// CRText is a question during a pending login (CR_TEXT): only
	// Creds.Response is used.
	CRText *CRTextChallenge
}

// Creds is the answer to a CredRequest.
type Creds struct {
	Username, Password, Response string
}

// Options configures a client.
type Options struct {
	Config *Config
	// Credentials answers logins (auth-user-pass). Called before the first
	// connect and again when the server refuses, or after a reconnect
	// that cannot reuse the login (a one-time code without auth-token).
	Credentials func(ctx context.Context, req CredRequest) (Creds, error)
	// Dial opens the transport; nil = net.Dialer.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	Logf func(format string, args ...any)
	// OnChange is called when the tunnel goes up or down, or its pushed
	// settings change after a reconnect.
	OnChange func()
	// OpenURL shows the server's login page (a pending web / SSO login)
	// in the user's browser.
	OpenURL func(url string)
}

// TunnelInfo describes the session that is up.
type TunnelInfo struct {
	Remote string
	Proto  string
	Cipher string
	PeerID int
	Push   PushReply
}

// Client is a running OpenVPN connection. It reconnects on its own
// (ping-restart, server restart, network loss) until Close.
type Client struct {
	cfg  *Config
	opts Options

	mu       sync.RWMutex
	sess     *session
	sendKey  *dataKey
	recvKeys map[byte]*dataKey
	peerID   int
	compress string
	info     TunnelInfo
	up       bool

	tokMu         sync.Mutex
	token, tokenU string

	in           chan []byte
	decompressed atomic.Int64 // packets the server sent compressed
	ctx          context.Context
	cancel       context.CancelFunc
	done         chan struct{}
	err          error
}

func (c *Client) logf(format string, args ...any) {
	if c.opts.Logf != nil {
		c.opts.Logf(format, args...)
	}
}

// Connect logs in and brings the tunnel up; it returns once the server's
// push reply arrived, or with the first fatal error.
func Connect(ctx context.Context, opts Options) (*Client, error) {
	if opts.Config == nil {
		return nil, errors.New("no configuration")
	}
	cctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		cfg: opts.Config, opts: opts, recvKeys: map[byte]*dataKey{},
		in: make(chan []byte, 1024), ctx: cctx, cancel: cancel, done: make(chan struct{}),
	}
	creds, err := c.askCreds(ctx, CredRequest{})
	if err != nil {
		cancel()
		return nil, err
	}
	first := make(chan error, 1)
	go c.supervise(creds, first)
	select {
	case err := <-first:
		if err != nil {
			cancel()
			<-c.done
			return nil, err
		}
		return c, nil
	case <-ctx.Done():
		cancel()
		<-c.done
		return nil, ctx.Err()
	}
}

func (c *Client) askCreds(ctx context.Context, req CredRequest) (credentials, error) {
	if !c.cfg.AuthUserPass {
		return credentials{}, nil
	}
	if c.opts.Credentials == nil {
		return credentials{}, errors.New("the server needs a username and password")
	}
	if req.CRV1 == nil && req.CRText == nil {
		req.Challenge, req.Echo = c.cfg.StaticChallenge, c.cfg.StaticChallengeEcho
	}
	a, err := c.opts.Credentials(ctx, req)
	if err != nil {
		return credentials{}, err
	}
	cr := credentials{user: a.Username, pass: a.Password, send: true}
	switch {
	case req.CRV1 != nil:
		cr.user = req.CRV1.Username
		cr.pass = "CRV1::" + req.CRV1.State + "::" + a.Response
	case c.cfg.StaticChallenge != "":
		cr.pass = "SCRV1:" + base64.StdEncoding.EncodeToString([]byte(a.Password)) + ":" + base64.StdEncoding.EncodeToString([]byte(a.Response))
	}
	return cr, nil
}

// supervise runs sessions back to back: the first reports to first, the
// rest are reconnects.
func (c *Client) supervise(creds credentials, first chan<- error) {
	defer close(c.done)
	backoff := 2 * time.Second
	authFails := 0
	var reported atomic.Bool
	report := func(err error) {
		if reported.CompareAndSwap(false, true) {
			first <- err
		}
	}
	for c.ctx.Err() == nil {
		err := c.runOnce(creds, func() {
			report(nil)
			backoff = 2 * time.Second
			authFails = 0
		})
		if c.ctx.Err() != nil {
			break
		}
		c.setDown()
		var af *AuthFailedError
		var halt *HaltError
		switch {
		case errors.As(err, &halt):
			c.err = err
			report(err)
			return
		case errors.As(err, &af):
			c.setAuthToken("", "")
			authFails++
			if af.CRV1 == nil && authFails >= 3 {
				c.err = err
				report(err)
				return
			}
			if af.CRV1 != nil {
				c.logf("server asks a challenge: %s", af.CRV1.Text)
			} else {
				c.logf("%v", err)
			}
			reason := af.Reason
			switch {
			case af.CRV1 != nil:
				reason = "" // a question, not a refusal
			case reason == "":
				reason = "authentication failed"
			}
			nc, aerr := c.askCreds(c.ctx, CredRequest{Error: reason, CRV1: af.CRV1})
			if aerr != nil {
				c.err = err
				report(err)
				return
			}
			creds = nc
			continue
		}
		if !reported.Load() {
			// The first connect fails fast; the caller decides.
			c.err = err
			report(err)
			return
		}
		c.logf("connection lost: %v; reconnecting in %s", err, backoff)
		select {
		case <-c.ctx.Done():
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 60*time.Second)
		if c.cfg.StaticChallenge != "" && c.authToken() == "" {
			// A one-time code cannot be reused: ask again.
			nc, aerr := c.askCreds(c.ctx, CredRequest{Error: "reconnecting"})
			if aerr != nil {
				c.err = aerr
				return
			}
			creds = nc
		}
	}
	if c.err == nil {
		c.err = net.ErrClosed
	}
	report(c.err)
}

func (c *Client) openURL(u string) {
	if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
		c.logf("ignoring a login URL that is not http(s)")
		return
	}
	c.logf("the server asks for a login in the browser")
	if c.opts.OpenURL != nil {
		c.opts.OpenURL(u)
	}
}

// askCRText asks a pending-login question (CR_TEXT) and returns the answer.
func (c *Client) askCRText(ch *CRTextChallenge) (string, error) {
	if c.opts.Credentials == nil {
		return "", errors.New("the server asks a question at login and nothing can answer it")
	}
	a, err := c.opts.Credentials(c.ctx, CredRequest{CRText: ch})
	if err != nil {
		return "", err
	}
	return a.Response, nil
}

func (c *Client) runOnce(creds credentials, onUp func()) error {
	var lastErr error
	for _, r := range c.cfg.Remotes {
		err := c.runRemote(r, creds, onUp)
		if c.ctx.Err() != nil {
			return err
		}
		var af *AuthFailedError
		var halt *HaltError
		if errors.As(err, &af) || errors.As(err, &halt) {
			return err
		}
		lastErr = err
		if len(c.cfg.Remotes) > 1 {
			c.logf("%s %s:%d: %v", r.Proto, r.Host, r.Port, err)
		}
	}
	return lastErr
}

func (c *Client) runRemote(r Remote, creds credentials, onUp func()) error {
	dial := c.opts.Dial
	if dial == nil {
		d := &net.Dialer{Timeout: 15 * time.Second}
		dial = d.DialContext
	}
	addr := net.JoinHostPort(r.Host, strconv.Itoa(r.Port))
	dctx, cancel := context.WithTimeout(c.ctx, 20*time.Second)
	conn, err := dial(dctx, r.Proto, addr)
	cancel()
	if err != nil {
		return fmt.Errorf("connect %s %s: %w", r.Proto, addr, err)
	}
	defer conn.Close()
	s, err := newSession(c, conn, r.Proto == "tcp", creds)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.sess = s
	c.recvKeys = map[byte]*dataKey{}
	c.sendKey = nil
	c.mu.Unlock()
	sctx, scancel := context.WithCancel(c.ctx)
	defer scancel()
	go func() {
		select {
		case pr := <-s.ready:
			c.mu.Lock()
			c.info = TunnelInfo{Remote: addr, Proto: r.Proto, Cipher: s.cipher, PeerID: s.peerID, Push: *pr}
			c.up = true
			c.mu.Unlock()
			c.logf("connected to %s (%s), cipher %s", addr, r.Proto, s.cipher)
			onUp()
			if c.opts.OnChange != nil {
				c.opts.OnChange()
			}
		case <-sctx.Done():
		}
	}()
	err = s.run(sctx)
	if c.ctx.Err() != nil {
		s.exitNotify()
	}
	return err
}

func (c *Client) setDown() {
	c.mu.Lock()
	was := c.up
	c.up = false
	c.sendKey = nil
	c.mu.Unlock()
	if was && c.opts.OnChange != nil {
		c.opts.OnChange()
	}
}

func (c *Client) setKey(s *session, k *dataKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sess != s {
		return
	}
	c.sendKey = k
	c.recvKeys[k.id] = k
	c.peerID = s.peerID
	c.compress = s.compress
}

func (c *Client) dropKey(s *session, k *dataKey) {
	if k == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sess == s && c.recvKeys[k.id] == k {
		delete(c.recvKeys, k.id)
	}
}

func (c *Client) setAuthToken(tok, user string) {
	c.tokMu.Lock()
	c.token, c.tokenU = tok, user
	c.tokMu.Unlock()
}

func (c *Client) authToken() string {
	c.tokMu.Lock()
	defer c.tokMu.Unlock()
	return c.token
}

func (c *Client) authTokenUser() string {
	c.tokMu.Lock()
	defer c.tokMu.Unlock()
	return c.tokenU
}

// deliverData decrypts a data packet from the reader goroutine.
func (c *Client) deliverData(s *session, p []byte) {
	c.mu.RLock()
	if c.sess != s {
		c.mu.RUnlock()
		return
	}
	k := c.recvKeys[p[0]&7]
	mode := c.compress
	c.mu.RUnlock()
	if k == nil {
		return
	}
	hlen := 1
	if p[0]>>3 == opDataV2 {
		hlen = 4
	}
	pt, err := k.open(p, hlen)
	if err != nil {
		return
	}
	s.lastRecv.Store(time.Now().UnixNano())
	before := len(pt)
	pt, err = frameIn(mode, pt)
	if err != nil {
		c.logf("%v", err)
		return
	}
	if len(pt) > before {
		c.decompressed.Add(1)
	}
	if bytes.Equal(pt, pingMagic) {
		return
	}
	if len(pt) == len(occMagic)+1 && bytes.Equal(pt[:len(occMagic)], occMagic) {
		if pt[len(occMagic)] == occExit {
			c.logf("server is shutting down the session")
		}
		return
	}
	if len(pt) == 0 {
		return
	}
	select {
	case c.in <- pt:
	default: // reader too slow: drop, like a full TUN queue
	}
}

// writeData encrypts and sends one payload with the current key.
func (c *Client) writeData(s *session, payload []byte, internal bool) error {
	c.mu.RLock()
	k, peer, mode, cur := c.sendKey, c.peerID, c.compress, c.sess
	c.mu.RUnlock()
	if k == nil || cur != s {
		return errNotUp
	}
	var header []byte
	if peer >= 0 {
		header = []byte{opDataV2<<3 | k.id, byte(peer >> 16), byte(peer >> 8), byte(peer)}
	} else {
		header = []byte{opDataV1<<3 | k.id}
	}
	pkt, err := k.seal(header, frameOut(mode, payload))
	if err != nil {
		return err
	}
	s.lastSend.Store(time.Now().UnixNano())
	return s.writeWire(pkt)
}

var errNotUp = errors.New("tunnel is not up")

// WritePacket sends one IP packet into the tunnel; dropped while the
// tunnel reconnects.
func (c *Client) WritePacket(p []byte) error {
	c.mu.RLock()
	s := c.sess
	c.mu.RUnlock()
	if s == nil {
		return errNotUp
	}
	return c.writeData(s, p, false)
}

// ReadPacket returns the next IP packet from the tunnel.
func (c *Client) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case p := <-c.in:
		return p, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		return nil, c.err
	}
}

// Info is the current session's description; ok is false while down.
func (c *Client) Info() (TunnelInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.info, c.up
}

// Done is closed when the client stopped for good; Err says why.
func (c *Client) Done() <-chan struct{} { return c.done }
func (c *Client) Err() error            { return c.err }

// Close sends the exit notification (UDP) and stops.
func (c *Client) Close() error {
	c.cancel()
	<-c.done
	if n := c.decompressed.Load(); n > 0 {
		c.logf("%d packets arrived compressed", n)
	}
	return nil
}
