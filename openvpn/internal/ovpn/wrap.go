package ovpn

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strings"
	"sync"
	"time"
)

// staticKey is an "OpenVPN Static key V1": two keys, each a 64-byte
// cipher part and a 64-byte HMAC part.
type staticKey [2]struct{ cipher, hmac [64]byte }

func parseStaticKey(block string) (*staticKey, error) {
	var hexs strings.Builder
	in := false
	for _, l := range strings.Split(block, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "-----BEGIN OpenVPN Static key V1"):
			in = true
		case strings.HasPrefix(l, "-----END OpenVPN Static key V1"):
			in = false
		case in && l != "" && l[0] != '#':
			hexs.WriteString(l)
		}
	}
	raw, err := hex.DecodeString(hexs.String())
	if err != nil || len(raw) != 256 {
		return nil, errors.New("not an OpenVPN static key (expected 2048 bits of hex)")
	}
	var k staticKey
	for i := 0; i < 2; i++ {
		copy(k[i].cipher[:], raw[i*128:])
		copy(k[i].hmac[:], raw[i*128+64:])
	}
	return &k, nil
}

// wrapper protects control packets on the wire. plain is opcode, session
// id and the rest (acks, message id, payload) as the reliability layer
// builds them.
type wrapper interface {
	wrap(plain []byte) []byte
	unwrap(wire []byte) ([]byte, error)
}

type noWrap struct{}

func (noWrap) wrap(p []byte) []byte            { return p }
func (noWrap) unwrap(p []byte) ([]byte, error) { return p, nil }

// replayID is the packet id + time pair tls-auth and tls-crypt carry: a
// sending counter and a receiving window, one each per TLS session (it
// spans renegotiations).
type replayID struct {
	mu       sync.Mutex
	sendID   uint32
	sendTime uint32

	recvTime uint32
	recvMax  uint32
	recvMask uint64 // bit i = recvMax-i seen
}

func newReplayID() *replayID {
	return &replayID{sendTime: uint32(time.Now().Unix())}
}

func (r *replayID) next() (uint32, uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sendID++
	return r.sendID, r.sendTime
}

// check accepts an id once, within a 64-packet window of the newest; a
// newer time restarts the sequence.
func (r *replayID) check(id, t uint32) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case t < r.recvTime:
		return false
	case t > r.recvTime:
		r.recvTime, r.recvMax, r.recvMask = t, id, 1
		return id != 0
	}
	if id == 0 {
		return false
	}
	if id > r.recvMax {
		shift := id - r.recvMax
		if shift >= 64 {
			r.recvMask = 1
		} else {
			r.recvMask = r.recvMask<<shift | 1
		}
		r.recvMax = id
		return true
	}
	back := r.recvMax - id
	if back >= 64 || r.recvMask&(1<<back) != 0 {
		return false
	}
	r.recvMask |= 1 << back
	return true
}

// tlsAuth is --tls-auth: an HMAC over every control packet, which drops
// anything not from a holder of the key before TLS sees it.
type tlsAuth struct {
	newHash      func() hash.Hash
	size         int
	sendK, recvK []byte
	ids          *replayID
}

func newTLSAuth(k *staticKey, direction int, digest string) (*tlsAuth, error) {
	newHash, size, err := digestFor(digest)
	if err != nil {
		return nil, err
	}
	send, recv := 0, 0
	switch direction {
	case 0:
		send, recv = 0, 1
	case 1:
		send, recv = 1, 0
	}
	return &tlsAuth{
		newHash: newHash, size: size,
		sendK: k[send].hmac[:size], recvK: k[recv].hmac[:size],
		ids: newReplayID(),
	}, nil
}

// wire: op sid HMAC pid time rest; the HMAC covers pid time op sid rest.
func (w *tlsAuth) wrap(p []byte) []byte {
	id, t := w.ids.next()
	var pt [8]byte
	binary.BigEndian.PutUint32(pt[:4], id)
	binary.BigEndian.PutUint32(pt[4:], t)
	m := hmac.New(w.newHash, w.sendK)
	m.Write(pt[:])
	m.Write(p)
	sum := m.Sum(nil)
	out := make([]byte, 0, len(p)+w.size+8)
	out = append(out, p[:9]...)
	out = append(out, sum...)
	out = append(out, pt[:]...)
	return append(out, p[9:]...)
}

func (w *tlsAuth) unwrap(p []byte) ([]byte, error) {
	if len(p) < 9+w.size+8 {
		return nil, errors.New("tls-auth: short packet")
	}
	sum := p[9 : 9+w.size]
	pt := p[9+w.size : 9+w.size+8]
	m := hmac.New(w.newHash, w.recvK)
	m.Write(pt)
	m.Write(p[:9])
	m.Write(p[9+w.size+8:])
	if !hmac.Equal(sum, m.Sum(nil)) {
		return nil, errors.New("tls-auth: HMAC mismatch (wrong key or key direction)")
	}
	if !w.ids.check(binary.BigEndian.Uint32(pt[:4]), binary.BigEndian.Uint32(pt[4:])) {
		return nil, errReplay
	}
	out := make([]byte, 0, len(p)-w.size-8)
	out = append(out, p[:9]...)
	return append(out, p[9+w.size+8:]...), nil
}

var errReplay = errors.New("replayed control packet")

// tlsCrypt is --tls-crypt: HMAC-SHA256 plus AES-256-CTR over the control
// channel, so even the TLS handshake is hidden. The client always uses
// the key pair the server does not send with (inverse direction).
type tlsCrypt struct {
	sendKa, recvKa []byte
	sendKe, recvKe cipher.Block
	ids            *replayID
}

func newTLSCrypt(k *staticKey) (*tlsCrypt, error) {
	se, err := aes.NewCipher(k[1].cipher[:32])
	if err != nil {
		return nil, err
	}
	re, err := aes.NewCipher(k[0].cipher[:32])
	if err != nil {
		return nil, err
	}
	return &tlsCrypt{
		sendKa: k[1].hmac[:32], recvKa: k[0].hmac[:32],
		sendKe: se, recvKe: re, ids: newReplayID(),
	}, nil
}

// wire: op sid pid time TAG ciphertext; TAG = HMAC(op sid pid time
// plaintext), and its first 16 bytes are the CTR IV.
func (w *tlsCrypt) wrap(p []byte) []byte {
	id, t := w.ids.next()
	head := make([]byte, 0, 17+32+len(p)-9)
	head = append(head, p[:9]...)
	head = binary.BigEndian.AppendUint32(head, id)
	head = binary.BigEndian.AppendUint32(head, t)
	m := hmac.New(sha256.New, w.sendKa)
	m.Write(head)
	m.Write(p[9:])
	tag := m.Sum(nil)
	ct := make([]byte, len(p)-9)
	cipher.NewCTR(w.sendKe, tag[:16]).XORKeyStream(ct, p[9:])
	out := append(head, tag...)
	return append(out, ct...)
}

func (w *tlsCrypt) unwrap(p []byte) ([]byte, error) {
	if len(p) < 17+32 {
		return nil, errors.New("tls-crypt: short packet")
	}
	head, tag, ct := p[:17], p[17:49], p[49:]
	pt := make([]byte, len(ct))
	cipher.NewCTR(w.recvKe, tag[:16]).XORKeyStream(pt, ct)
	m := hmac.New(sha256.New, w.recvKa)
	m.Write(head)
	m.Write(pt)
	if !hmac.Equal(tag, m.Sum(nil)) {
		return nil, errors.New("tls-crypt: authentication failed (wrong key)")
	}
	if !w.ids.check(binary.BigEndian.Uint32(head[9:13]), binary.BigEndian.Uint32(head[13:17])) {
		return nil, errReplay
	}
	out := make([]byte, 0, 9+len(pt))
	out = append(out, head[:9]...)
	return append(out, pt...), nil
}

func newWrapper(c *Config) (wrapper, error) {
	switch {
	case c.TLSAuth != "":
		k, err := parseStaticKey(c.TLSAuth)
		if err != nil {
			return nil, fmt.Errorf("tls-auth: %w", err)
		}
		return newTLSAuth(k, c.KeyDirection, c.Auth)
	case c.TLSCrypt != "":
		k, err := parseStaticKey(c.TLSCrypt)
		if err != nil {
			return nil, fmt.Errorf("tls-crypt: %w", err)
		}
		return newTLSCrypt(k)
	}
	return noWrap{}, nil
}
