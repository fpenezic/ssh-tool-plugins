package ovpn

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	maxCtrlPayload = 1100 // TLS bytes per P_CONTROL_V1, below a 1250 tls-mtu
	sendWindow     = 4    // unacknowledged control packets in flight
	recvWindow     = 8    // out-of-order control packets kept
	maxAcksPerPkt  = 4
)

// outMsg is one reliable control message.
type outMsg struct {
	op      byte
	id      uint32
	payload []byte
	sentAt  time.Time
	tries   int
}

// keyState is one OpenVPN key state (key id 0..7): its own reliability
// sequence, TLS session and, once negotiated, data channel key. The
// session loop owns everything here except what the TLS goroutine
// touches through the pipe.
type keyState struct {
	id      byte
	started time.Time

	// reliability (loop goroutine only)
	sendNext uint32
	queue    []*outMsg // waiting for the send window
	inflight []*outMsg
	recvNext uint32
	recvBuf  map[uint32][]byte
	acks     []uint32

	pipe *pipe
	tls  *tls.Conn

	// km2 results
	kb       *keyBlock
	data     *dataKey
	ready    bool // keys derived
	failed   bool
	retireAt time.Time // lame duck: drop after this
}

func newKeyState(id byte) *keyState {
	return &keyState{id: id, started: time.Now(), recvBuf: map[uint32][]byte{}, pipe: newPipe()}
}

// enqueue adds a reliable message (reset or TLS bytes).
func (k *keyState) enqueue(op byte, payload []byte) {
	if op != opControl {
		k.queue = append(k.queue, &outMsg{op: op, id: k.sendNext})
		k.sendNext++
		return
	}
	for len(payload) > 0 {
		n := min(len(payload), maxCtrlPayload)
		k.queue = append(k.queue, &outMsg{op: op, id: k.sendNext, payload: append([]byte(nil), payload[:n]...)})
		k.sendNext++
		payload = payload[n:]
	}
}

// receive records an incoming message; returns the in-order payloads now
// deliverable. Duplicates are acknowledged again, beyond-window ones
// dropped (the peer resends).
func (k *keyState) receive(id uint32, payload []byte) (deliver [][]byte, isNew bool) {
	if id < k.recvNext {
		k.acks = append(k.acks, id)
		return nil, false
	}
	if id >= k.recvNext+recvWindow {
		return nil, false
	}
	k.acks = append(k.acks, id)
	if _, dup := k.recvBuf[id]; dup {
		return nil, false
	}
	k.recvBuf[id] = append([]byte(nil), payload...)
	for {
		p, ok := k.recvBuf[k.recvNext]
		if !ok {
			break
		}
		delete(k.recvBuf, k.recvNext)
		k.recvNext++
		if len(p) > 0 {
			deliver = append(deliver, p)
		}
	}
	return deliver, true
}

func (k *keyState) ack(ids []uint32) {
	keep := k.inflight[:0]
	for _, m := range k.inflight {
		acked := false
		for _, a := range ids {
			if a == m.id {
				acked = true
				break
			}
		}
		if !acked {
			keep = append(keep, m)
		}
	}
	k.inflight = keep
}

func (k *keyState) takeAcks() []uint32 {
	n := min(len(k.acks), maxAcksPerPkt)
	out := append([]uint32(nil), k.acks[:n]...)
	k.acks = k.acks[n:]
	return out
}

// pipe connects crypto/tls to the reliability layer: TLS writes go out
// as control messages, delivered control payloads come in as TLS bytes.
type pipe struct {
	in     chan []byte
	out    chan []byte
	closed chan struct{}
	once   sync.Once
	buf    []byte
}

func newPipe() *pipe {
	return &pipe{in: make(chan []byte, 1024), out: make(chan []byte, 256), closed: make(chan struct{})}
}

func (p *pipe) Read(b []byte) (int, error) {
	if len(p.buf) == 0 {
		select {
		case d := <-p.in:
			p.buf = d
		case <-p.closed:
			return 0, io.EOF
		}
	}
	n := copy(b, p.buf)
	p.buf = p.buf[n:]
	return n, nil
}

func (p *pipe) Write(b []byte) (int, error) {
	select {
	case p.out <- append([]byte(nil), b...):
		return len(b), nil
	case <-p.closed:
		return 0, net.ErrClosed
	}
}

func (p *pipe) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

func (p *pipe) LocalAddr() net.Addr              { return pipeAddr{} }
func (p *pipe) RemoteAddr() net.Addr             { return pipeAddr{} }
func (p *pipe) SetDeadline(time.Time) error      { return nil }
func (p *pipe) SetReadDeadline(time.Time) error  { return nil }
func (p *pipe) SetWriteDeadline(time.Time) error { return nil }

type pipeAddr struct{}

func (pipeAddr) Network() string { return "ovpn" }
func (pipeAddr) String() string  { return "control-channel" }

// km2 is the key method 2 exchange.
type km2Client struct {
	preMaster [48]byte
	random1   [32]byte
	random2   [32]byte
}

func newKM2() (*km2Client, error) {
	k := &km2Client{}
	for _, b := range [][]byte{k.preMaster[:], k.random1[:], k.random2[:]} {
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
	}
	return k, nil
}

func writeString(b *bytes.Buffer, s string) {
	if s == "" {
		binary.Write(b, binary.BigEndian, uint16(0))
		return
	}
	binary.Write(b, binary.BigEndian, uint16(len(s)+1))
	b.WriteString(s)
	b.WriteByte(0)
}

// message is the client's key method 2 record: key material, options
// string, credentials and peer info.
func (k *km2Client) message(options, user, pass, peerInfo string, sendCreds bool) []byte {
	var b bytes.Buffer
	b.Write([]byte{0, 0, 0, 0, 2})
	b.Write(k.preMaster[:])
	b.Write(k.random1[:])
	b.Write(k.random2[:])
	writeString(&b, options)
	if sendCreds {
		writeString(&b, user)
		writeString(&b, pass)
	} else {
		writeString(&b, "")
		writeString(&b, "")
	}
	writeString(&b, peerInfo)
	return b.Bytes()
}

// readServerKM2 reads the server's record: key material and options.
func readServerKM2(r *bufio.Reader) (random1, random2 [32]byte, options string, err error) {
	var head [5]byte
	if _, err = io.ReadFull(r, head[:]); err != nil {
		return
	}
	if binary.BigEndian.Uint32(head[:4]) != 0 || head[4]&0x0f != 2 {
		err = errors.New("server does not speak key method 2")
		return
	}
	if _, err = io.ReadFull(r, random1[:]); err != nil {
		return
	}
	if _, err = io.ReadFull(r, random2[:]); err != nil {
		return
	}
	var l uint16
	if err = binary.Read(r, binary.BigEndian, &l); err != nil {
		return
	}
	if l > 4096 {
		err = fmt.Errorf("server options string too long (%d)", l)
		return
	}
	s := make([]byte, l)
	if _, err = io.ReadFull(r, s); err != nil {
		return
	}
	options = string(bytes.TrimRight(s, "\x00"))
	// Two empty credential strings and the (empty) peer info may follow;
	// they are zero bytes, which the message reader skips as empty.
	return
}

// keyExpansion derives the 256-byte data channel key block.
func keyExpansion(c *km2Client, sRandom1, sRandom2 [32]byte, clientSID, serverSID sessionID) *keyBlock {
	seed := append(append([]byte{}, c.random1[:]...), sRandom1[:]...)
	master := prf(c.preMaster[:], "OpenVPN master secret", seed, 48)
	seed = append(append([]byte{}, c.random2[:]...), sRandom2[:]...)
	seed = append(append(seed, clientSID[:]...), serverSID[:]...)
	var kb keyBlock
	copy(kb[:], prf(master, "OpenVPN key expansion", seed, 256))
	return &kb
}

// readMessage reads one NUL-terminated control message from TLS.
func readMessage(r *bufio.Reader) (string, error) {
	for {
		s, err := r.ReadString(0)
		if err != nil {
			return "", err
		}
		s = s[:len(s)-1]
		if s != "" {
			return s, nil
		}
	}
}
