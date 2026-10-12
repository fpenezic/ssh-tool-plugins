package ovpn

import (
	"encoding/binary"
	"errors"
)

// Opcodes (high 5 bits of the first byte; the low 3 are the key id).
const (
	opSoftReset        = 3
	opControl          = 4
	opAck              = 5
	opDataV1           = 6
	opHardResetClient2 = 7
	opHardResetServer2 = 8
	opDataV2           = 9
)

type sessionID [8]byte

// ctrlPacket is a control channel packet before wrapping.
type ctrlPacket struct {
	op, keyID byte
	sid       sessionID
	acks      []uint32
	ackSID    sessionID // the peer's session id, present with acks
	id        uint32    // message packet id (not on P_ACK_V1)
	payload   []byte
}

func (p *ctrlPacket) encode() []byte {
	b := make([]byte, 0, 9+1+len(p.acks)*4+8+4+len(p.payload))
	b = append(b, p.op<<3|p.keyID&7)
	b = append(b, p.sid[:]...)
	b = append(b, byte(len(p.acks)))
	for _, a := range p.acks {
		b = binary.BigEndian.AppendUint32(b, a)
	}
	if len(p.acks) > 0 {
		b = append(b, p.ackSID[:]...)
	}
	if p.op != opAck {
		b = binary.BigEndian.AppendUint32(b, p.id)
	}
	return append(b, p.payload...)
}

var errShort = errors.New("short control packet")

func decodeCtrl(b []byte) (*ctrlPacket, error) {
	if len(b) < 10 {
		return nil, errShort
	}
	p := &ctrlPacket{op: b[0] >> 3, keyID: b[0] & 7}
	copy(p.sid[:], b[1:9])
	n := int(b[9])
	b = b[10:]
	if len(b) < n*4 {
		return nil, errShort
	}
	for i := 0; i < n; i++ {
		p.acks = append(p.acks, binary.BigEndian.Uint32(b[i*4:]))
	}
	b = b[n*4:]
	if n > 0 {
		if len(b) < 8 {
			return nil, errShort
		}
		copy(p.ackSID[:], b[:8])
		b = b[8:]
	}
	if p.op != opAck {
		if len(b) < 4 {
			return nil, errShort
		}
		p.id = binary.BigEndian.Uint32(b[:4])
		b = b[4:]
	}
	p.payload = b
	return p, nil
}
