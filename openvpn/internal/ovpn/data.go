package ovpn

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/anchore/go-lzo"
	"github.com/pierrec/lz4/v4"
	"golang.org/x/crypto/chacha20poly1305"
)

func digestFor(name string) (func() hash.Hash, int, error) {
	switch strings.ToUpper(name) {
	case "SHA1", "SHA-1", "":
		return sha1.New, 20, nil
	case "SHA256", "SHA-256":
		return sha256.New, 32, nil
	case "SHA384", "SHA-384":
		return sha512.New384, 48, nil
	case "SHA512", "SHA-512":
		return sha512.New, 64, nil
	case "MD5":
		return md5.New, 16, nil
	case "NONE":
		return nil, 0, errors.New("auth none is not supported")
	}
	return nil, 0, fmt.Errorf("auth %s is not supported", name)
}

// cipherSpec describes a data channel cipher.
type cipherSpec struct {
	name    string
	keyLen  int
	aead    bool
	newAEAD func(key []byte) (cipher.AEAD, error)
}

func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

var ciphers = map[string]cipherSpec{
	"AES-128-GCM":       {"AES-128-GCM", 16, true, gcm},
	"AES-192-GCM":       {"AES-192-GCM", 24, true, gcm},
	"AES-256-GCM":       {"AES-256-GCM", 32, true, gcm},
	"CHACHA20-POLY1305": {"CHACHA20-POLY1305", 32, true, chacha20poly1305.New},
	"AES-128-CBC":       {"AES-128-CBC", 16, false, nil},
	"AES-192-CBC":       {"AES-192-CBC", 24, false, nil},
	"AES-256-CBC":       {"AES-256-CBC", 32, false, nil},
}

// supportedCiphers is what the client offers (IV_CIPHERS), strongest
// first.
var supportedCiphers = []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305", "AES-256-CBC", "AES-192-CBC", "AES-128-CBC", "AES-192-GCM"}

// keyBlock is the 256-byte data channel key material: two keys, each a
// 64-byte cipher part and a 64-byte HMAC part.
type keyBlock [256]byte

func (k *keyBlock) cipherKey(i int) []byte { return k[i*128 : i*128+64] }
func (k *keyBlock) hmacKey(i int) []byte   { return k[i*128+64 : i*128+128] }

// dataKey is one key state's data channel crypto.
type dataKey struct {
	id      byte
	spec    cipherSpec
	sendID  atomic.Uint32
	sendAE  cipher.AEAD
	recvAE  cipher.AEAD
	sendIV  []byte // AEAD implicit IV (8 bytes)
	recvIV  []byte
	sendBlk cipher.Block // CBC
	recvBlk cipher.Block
	newHash func() hash.Hash
	hsize   int
	sendMac []byte
	recvMac []byte

	replayMu sync.Mutex
	replay   window
}

func newDataKey(id byte, kb *keyBlock, cipherName, digest string) (*dataKey, error) {
	spec, ok := ciphers[strings.ToUpper(cipherName)]
	if !ok {
		return nil, fmt.Errorf("data cipher %s is not supported", cipherName)
	}
	k := &dataKey{id: id, spec: spec}
	// The client sends with key 0 and receives with key 1 (OpenVPN's
	// KEY_DIRECTION_NORMAL on the client, INVERSE on the server).
	const send, recv = 0, 1
	if spec.aead {
		var err error
		if k.sendAE, err = spec.newAEAD(kb.cipherKey(send)[:spec.keyLen]); err != nil {
			return nil, err
		}
		if k.recvAE, err = spec.newAEAD(kb.cipherKey(recv)[:spec.keyLen]); err != nil {
			return nil, err
		}
		k.sendIV = append([]byte(nil), kb.hmacKey(send)[:8]...)
		k.recvIV = append([]byte(nil), kb.hmacKey(recv)[:8]...)
		return k, nil
	}
	var err error
	if k.sendBlk, err = aes.NewCipher(kb.cipherKey(send)[:spec.keyLen]); err != nil {
		return nil, err
	}
	if k.recvBlk, err = aes.NewCipher(kb.cipherKey(recv)[:spec.keyLen]); err != nil {
		return nil, err
	}
	if k.newHash, k.hsize, err = digestFor(digest); err != nil {
		return nil, err
	}
	k.sendMac = append([]byte(nil), kb.hmacKey(send)[:k.hsize]...)
	k.recvMac = append([]byte(nil), kb.hmacKey(recv)[:k.hsize]...)
	return k, nil
}

var errDataAuth = errors.New("data packet failed authentication")

// seal encrypts one payload; header is the opcode byte (plus peer id for
// P_DATA_V2), returned with the encrypted packet appended.
func (k *dataKey) seal(header, payload []byte) ([]byte, error) {
	id := k.sendID.Add(1)
	if id == 0xffffffff {
		return nil, errors.New("data packet id exhausted")
	}
	out := append([]byte(nil), header...)
	if k.spec.aead {
		var nonce [12]byte
		binary.BigEndian.PutUint32(nonce[:4], id)
		copy(nonce[4:], k.sendIV)
		out = binary.BigEndian.AppendUint32(out, id)
		// P_DATA_V2 authenticates opcode + peer id + packet id; P_DATA_V1
		// only the packet id (its opcode is added after encryption).
		ad := out
		if len(header) == 1 {
			ad = out[1:]
		}
		sealed := k.sendAE.Seal(nil, nonce[:], payload, ad)
		tagAt := len(sealed) - k.sendAE.Overhead()
		out = append(out, sealed[tagAt:]...) // tag first, as OpenVPN sends it
		return append(out, sealed[:tagAt]...), nil
	}
	// CBC: HMAC(IV || ciphertext) || IV || ciphertext(packet id || payload)
	pt := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(payload)+aes.BlockSize), id)
	pt = append(pt, payload...)
	pad := aes.BlockSize - len(pt)%aes.BlockSize
	pt = append(pt, bytes.Repeat([]byte{byte(pad)}, pad)...)
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	ct := make([]byte, len(pt))
	cipher.NewCBCEncrypter(k.sendBlk, iv).CryptBlocks(ct, pt)
	m := hmac.New(k.newHash, k.sendMac)
	m.Write(iv)
	m.Write(ct)
	out = append(out, m.Sum(nil)...)
	out = append(out, iv...)
	return append(out, ct...), nil
}

// open decrypts a data packet whose header (opcode [+ peer id]) is
// hlen bytes long.
func (k *dataKey) open(p []byte, hlen int) ([]byte, error) {
	if k.spec.aead {
		ov := k.recvAE.Overhead()
		if len(p) < hlen+4+ov {
			return nil, errDataAuth
		}
		id := binary.BigEndian.Uint32(p[hlen : hlen+4])
		var nonce [12]byte
		copy(nonce[:4], p[hlen:hlen+4])
		copy(nonce[4:], k.recvIV)
		tag := p[hlen+4 : hlen+4+ov]
		ct := p[hlen+4+ov:]
		buf := make([]byte, 0, len(ct)+ov)
		buf = append(append(buf, ct...), tag...)
		ad := p[:hlen+4]
		if hlen == 1 {
			ad = p[1:5]
		}
		pt, err := k.recvAE.Open(nil, nonce[:], buf, ad)
		if err != nil {
			return nil, errDataAuth
		}
		if !k.accept(id) {
			return nil, errReplay
		}
		return pt, nil
	}
	if len(p) < hlen+k.hsize+2*aes.BlockSize {
		return nil, errDataAuth
	}
	sum := p[hlen : hlen+k.hsize]
	rest := p[hlen+k.hsize:]
	m := hmac.New(k.newHash, k.recvMac)
	m.Write(rest)
	if !hmac.Equal(sum, m.Sum(nil)) {
		return nil, errDataAuth
	}
	iv, ct := rest[:aes.BlockSize], rest[aes.BlockSize:]
	if len(ct)%aes.BlockSize != 0 {
		return nil, errDataAuth
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(k.recvBlk, iv).CryptBlocks(pt, ct)
	pad := int(pt[len(pt)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(pt)-4 {
		return nil, errDataAuth
	}
	pt = pt[:len(pt)-pad]
	if !k.accept(binary.BigEndian.Uint32(pt[:4])) {
		return nil, errReplay
	}
	return pt[4:], nil
}

func (k *dataKey) accept(id uint32) bool {
	k.replayMu.Lock()
	defer k.replayMu.Unlock()
	return k.replay.accept(id)
}

// window is a 256-packet replay window: UDP reorders, a replay is still
// refused.
type window struct {
	max  uint32
	bits [4]uint64
}

func (w *window) accept(id uint32) bool {
	if id == 0 {
		return false
	}
	if id > w.max {
		shift := id - w.max
		if shift >= 256 {
			w.bits = [4]uint64{}
		} else {
			for ; shift > 0; shift-- {
				carry := uint64(0)
				for i := 0; i < 4; i++ {
					nc := w.bits[i] >> 63
					w.bits[i] = w.bits[i]<<1 | carry
					carry = nc
				}
			}
		}
		w.max = id
		w.bits[0] |= 1
		return true
	}
	back := w.max - id
	if back >= 256 {
		return false
	}
	word, bit := back/64, back%64
	if w.bits[word]&(1<<bit) != 0 {
		return false
	}
	w.bits[word] |= 1 << bit
	return true
}

// prf is the TLS 1.0 PRF OpenVPN's key method 2 derives keys with.
func prf(secret []byte, label string, seed []byte, n int) []byte {
	half := (len(secret) + 1) / 2
	s1, s2 := secret[:half], secret[len(secret)-half:]
	ls := append([]byte(label), seed...)
	a := pHash(md5.New, s1, ls, n)
	b := pHash(sha1.New, s2, ls, n)
	for i := range a {
		a[i] ^= b[i]
	}
	return a
}

func pHash(h func() hash.Hash, secret, seed []byte, n int) []byte {
	out := make([]byte, 0, n+64)
	m := hmac.New(h, secret)
	m.Write(seed)
	a := m.Sum(nil)
	for len(out) < n {
		m.Reset()
		m.Write(a)
		m.Write(seed)
		out = append(out, m.Sum(nil)...)
		m.Reset()
		m.Write(a)
		a = m.Sum(nil)
	}
	return out[:n]
}

// Compression framing. The client sends uncompressed packets with the
// "not compressed" marker the mode expects, and decompresses what the
// server compressed (LZO or LZ4).
const (
	noCompress         = 0xfa // comp-lzo: not compressed
	lzoCompress        = 0x66 // comp-lzo / compress lzo: LZO1X
	lz4Compress        = 0x69 // compress lz4
	noCompressByteSwap = 0xfb // compress stub / lzo / lz4: not compressed
	compV2Indicator    = 0x50 // compress stub-v2 / lz4-v2
	compV2LZ4          = 0x01
	maxDecompressed    = 65536
)

func frameOut(mode string, p []byte) []byte {
	switch mode {
	case "lzo":
		return append([]byte{noCompress}, p...)
	case "swap":
		// The marker takes the first byte's place, which moves to the end.
		if len(p) == 0 {
			return []byte{noCompressByteSwap}
		}
		out := make([]byte, 0, len(p)+1)
		out = append(out, noCompressByteSwap)
		out = append(out, p[1:]...)
		return append(out, p[0])
	case "v2":
		if len(p) > 0 && p[0] == compV2Indicator {
			return append([]byte{compV2Indicator, 0}, p...)
		}
	}
	return p
}

var errCompressed = errors.New("compressed packet could not be decompressed")

func frameIn(mode string, p []byte) ([]byte, error) {
	if len(p) == 0 {
		return p, nil
	}
	switch mode {
	case "lzo":
		switch p[0] {
		case noCompress:
			return p[1:], nil
		case lzoCompress:
			return unLZO(p[1:])
		}
		return nil, errCompressed
	case "swap":
		// Undo the swap: the marker's place gets the last byte back.
		marker := p[0]
		body := make([]byte, 0, len(p)-1)
		if len(p) > 1 {
			body = append(body, p[len(p)-1])
			body = append(body, p[1:len(p)-1]...)
		}
		switch marker {
		case noCompressByteSwap:
			return body, nil
		case lz4Compress:
			return unLZ4(body)
		case lzoCompress:
			return unLZO(body)
		}
		return nil, errCompressed
	case "v2":
		if p[0] == compV2Indicator && len(p) >= 2 {
			switch p[1] {
			case 0:
				return p[2:], nil
			case compV2LZ4:
				return unLZ4(p[2:])
			}
			return nil, errCompressed
		}
	}
	return p, nil
}

func unLZ4(src []byte) ([]byte, error) {
	dst := make([]byte, maxDecompressed)
	n, err := lz4.UncompressBlock(src, dst)
	if err != nil {
		return nil, errCompressed
	}
	return dst[:n], nil
}

func unLZO(src []byte) ([]byte, error) {
	dst := make([]byte, maxDecompressed)
	n, err := lzo.Decompress(src, dst)
	if err != nil {
		return nil, errCompressed
	}
	return dst[:n], nil
}

var (
	pingMagic = []byte{0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48}
	occMagic  = []byte{0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81, 0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c}
)

const occExit = 6
