package snx

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The SLIM tunnel: one TLS connection to the gateway's tunnel port
// carrying framed packets,
//
//	uint32 length | uint32 type | payload
//
// type 1 = control (an s-expression, NUL terminated), type 2 = one IP
// packet. The client opens with client_hello (presenting the active key
// from the login), the gateway answers hello_reply with the office-mode
// address, DNS, the routed ranges and the timeouts. After that both sides
// send keepalives; either may send disconnect.

const (
	pktControl = 1
	pktData    = 2
	maxFrame   = 1 << 20
)

// Hello is the gateway's hello_reply.
type Hello struct {
	Address       netip.Addr
	Netmask       netip.Addr // invalid when not sent
	DNS           []netip.Addr
	SearchDomains []string
	// Routes are the ranges the gateway routes into the tunnel, as
	// prefixes. A range starting at 0.0.0.1 (the default-route marker)
	// is left out.
	Routes []netip.Prefix
	// AuthTimeout is how long the session lives; Keepalive the interval
	// the gateway expects keepalives at.
	AuthTimeout time.Duration
	Keepalive   time.Duration
}

// Tunnel is one connected SLIM tunnel.
type Tunnel struct {
	Hello Hello

	conn   net.Conn
	r      *bufio.Reader
	wmu    sync.Mutex
	logf   func(string, ...any)
	in     chan []byte
	done   chan struct{}
	once   sync.Once
	err    error
	missed atomic.Int32 // keepalives sent without anything heard back
	rx, tx atomic.Uint64
}

// DialOptions configure Dial.
type DialOptions struct {
	Addr      string // host:port of the tunnel
	TLS       *tls.Config
	ActiveKey string
	// Previous is the address to ask to keep (a reconnect), or invalid.
	Previous netip.Addr
	Logf     func(string, ...any)
}

// DisconnectedError is a disconnect sent by the gateway.
type DisconnectedError struct{ Code, Message string }

func (e *DisconnectedError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("gateway disconnected the tunnel: %s (code %s)", e.Message, e.Code)
	}
	return "gateway disconnected the tunnel (code " + e.Code + ")"
}

// Dial connects the tunnel and exchanges hellos.
func Dial(ctx context.Context, o DialOptions) (*Tunnel, error) {
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}, Config: o.TLS}
	c, err := d.DialContext(ctx, "tcp", o.Addr)
	if err != nil {
		return nil, err
	}
	if tc, ok := c.(*tls.Conn).NetConn().(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	t := &Tunnel{conn: c, r: bufio.NewReaderSize(c, 64<<10), logf: o.Logf,
		in: make(chan []byte, 256), done: make(chan struct{})}
	if t.logf == nil {
		t.logf = func(string, ...any) {}
	}

	ip, keep := "0.0.0.0", "false"
	if o.Previous.IsValid() {
		ip, keep = o.Previous.String(), "true"
	}
	hello := Obj("client_hello",
		"client_version", V("2"),
		"protocol_version", V("2"),
		"OM", Obj("", "ipaddr", V(ip), "keep_address", V(keep)),
		"optional", Obj("", "client_type", V("4")),
		"cookie", V(o.ActiveKey),
	)
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	if err := t.writeControl(hello); err != nil {
		c.Close()
		return nil, err
	}
	typ, payload, err := t.readFrame()
	if err != nil {
		c.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("tunnel hello: %w", err)
	}
	if typ != pktControl {
		c.Close()
		return nil, errors.New("tunnel hello: gateway sent data before hello_reply")
	}
	n, err := Parse(string(payload))
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("tunnel hello: %w", err)
	}
	if n.Name == "disconnect" {
		c.Close()
		return nil, disconnected(n)
	}
	if n.Name != "hello_reply" {
		c.Close()
		return nil, fmt.Errorf("tunnel hello: unexpected %q", n.Name)
	}
	if t.Hello, err = parseHello(n); err != nil {
		c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	go t.readLoop()
	go t.keepalive()
	return t, nil
}

func disconnected(n *Node) error {
	return &DisconnectedError{Code: n.Str("code"), Message: n.Str("message")}
}

func parseHello(n *Node) (Hello, error) {
	var h Hello
	var err error
	if h.Address, err = netip.ParseAddr(n.Str("OM", "ipaddr")); err != nil || !h.Address.Is4() {
		return h, fmt.Errorf("hello_reply: bad office mode address %q", n.Str("OM", "ipaddr"))
	}
	if m, err := netip.ParseAddr(n.Str("optional", "subnet")); err == nil && m.Is4() {
		h.Netmask = m
	}
	for _, d := range n.List("OM", "dns_servers") {
		if a, err := netip.ParseAddr(d.Value); err == nil {
			h.DNS = append(h.DNS, a)
		}
	}
	for _, s := range strings.FieldsFunc(n.Str("OM", "dns_suffix"), func(r rune) bool { return r == ',' || r == ';' }) {
		if s = strings.TrimSpace(s); s != "" {
			h.SearchDomains = append(h.SearchDomains, s)
		}
	}
	h.Routes = rangesToPrefixes(n.List("range"))
	h.AuthTimeout = time.Duration(n.Int("timeouts", "authentication")) * time.Second
	h.Keepalive = time.Duration(n.Int("timeouts", "keepalive")) * time.Second
	if h.Keepalive <= 0 {
		h.Keepalive = 20 * time.Second
	}
	return h, nil
}

// rangesToPrefixes turns (:from (a) :to (b)) items into prefixes. A range
// starting at 0.0.0.1 is the gateway's default-route marker and is left out.
func rangesToPrefixes(items []*Node) []netip.Prefix {
	var out []netip.Prefix
	for _, r := range items {
		from, err1 := netip.ParseAddr(r.Str("from"))
		to, err2 := netip.ParseAddr(r.Str("to"))
		if err1 != nil || err2 != nil || !from.Is4() || !to.Is4() || to.Less(from) {
			continue
		}
		if from == netip.AddrFrom4([4]byte{0, 0, 0, 1}) {
			continue
		}
		out = append(out, RangeToPrefixes(from, to)...)
	}
	return out
}

// RangeToPrefixes covers [from, to] (IPv4, inclusive) with the fewest
// CIDR prefixes.
func RangeToPrefixes(from, to netip.Addr) []netip.Prefix {
	u := func(a netip.Addr) uint64 { b := a.As4(); return uint64(binary.BigEndian.Uint32(b[:])) }
	lo, hi := u(from), u(to)
	var out []netip.Prefix
	for lo <= hi {
		// Largest block aligned at lo that stays within hi.
		bits := 32
		for bits > 0 {
			size := uint64(1) << (32 - bits + 1)
			if lo%size != 0 || lo+size-1 > hi {
				break
			}
			bits--
		}
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(lo))
		out = append(out, netip.PrefixFrom(netip.AddrFrom4(b), bits))
		lo += uint64(1) << (32 - bits)
	}
	return out
}

func (t *Tunnel) readFrame() (uint32, []byte, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(t.r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:4])
	typ := binary.BigEndian.Uint32(hdr[4:])
	if n > maxFrame {
		return 0, nil, fmt.Errorf("frame of %d bytes", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(t.r, buf); err != nil {
		return 0, nil, err
	}
	return typ, buf, nil
}

func (t *Tunnel) writeFrame(typ uint32, payload []byte) error {
	buf := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(payload)))
	binary.BigEndian.PutUint32(buf[4:8], typ)
	copy(buf[8:], payload)
	t.wmu.Lock()
	defer t.wmu.Unlock()
	_ = t.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	_, err := t.conn.Write(buf)
	return err
}

func (t *Tunnel) writeControl(n *Node) error {
	return t.writeFrame(pktControl, append([]byte(n.String()), 0))
}

func (t *Tunnel) readLoop() {
	for {
		typ, p, err := t.readFrame()
		if err != nil {
			t.fail(err)
			return
		}
		t.missed.Store(0)
		switch typ {
		case pktData:
			t.rx.Add(uint64(len(p)))
			select {
			case t.in <- p:
			case <-t.done:
				return
			}
		case pktControl:
			n, err := Parse(string(p))
			if err != nil {
				t.logf("control: %v", err)
				continue
			}
			switch n.Name {
			case "keepalive":
			case "disconnect":
				t.fail(disconnected(n))
				return
			default:
				t.logf("control: %s", n.Name)
			}
		default:
			t.fail(fmt.Errorf("unknown frame type %d", typ))
			return
		}
	}
}

// keepalive sends the gateway's keepalive every interval; three without
// any traffic back means the tunnel is dead.
func (t *Tunnel) keepalive() {
	tk := time.NewTicker(t.Hello.Keepalive)
	defer tk.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-tk.C:
		}
		if t.missed.Add(1) > 3 {
			t.fail(errors.New("no answer to keepalives"))
			return
		}
		if err := t.writeControl(Obj("keepalive", "id", V("0"))); err != nil {
			t.fail(err)
			return
		}
	}
}

func (t *Tunnel) fail(err error) {
	t.once.Do(func() {
		t.err = err
		close(t.done)
		_ = t.conn.Close()
	})
}

// ReadPacket returns the next IP packet from the gateway.
func (t *Tunnel) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case p := <-t.in:
		return p, nil
	case <-t.done:
		return nil, t.Err()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// WritePacket sends one IP packet to the gateway.
func (t *Tunnel) WritePacket(p []byte) error {
	select {
	case <-t.done:
		return t.Err()
	default:
	}
	if err := t.writeFrame(pktData, p); err != nil {
		t.fail(err)
		return err
	}
	t.tx.Add(uint64(len(p)))
	return nil
}

// Done is closed when the tunnel is gone; Err tells why.
func (t *Tunnel) Done() <-chan struct{} { return t.done }

// Err is why the tunnel ended.
func (t *Tunnel) Err() error {
	select {
	case <-t.done:
		return t.err
	default:
		return nil
	}
}

// Bytes is the IP payload received and sent so far.
func (t *Tunnel) Bytes() (rx, tx uint64) { return t.rx.Load(), t.tx.Load() }

// Close tells the gateway and drops the connection.
func (t *Tunnel) Close() error {
	select {
	case <-t.done:
	default:
		_ = t.writeControl(Obj("disconnect", "code", V("28"), "message", V("User has disconnected.")))
	}
	t.fail(errors.New("closed"))
	return nil
}
