package snx

import (
	"encoding/hex"
	"fmt"
)

// Secrets in CCC messages (username, password, the session key, error
// texts) travel "obfuscated": each byte XORed with a fixed table, the
// result reversed and hex encoded. Not encryption - the HTTPS around it
// is what protects them.

var xorTable = []byte{
	45, 79, 68, 73, 70, 73, 69, 68, 38, 87, 48, 82, 79, 80, 69, 82, 84, 89, 51, 72, 69, 69, 84, 55, 73, 84, 72, 47, 43,
	52, 72, 69, 51, 72, 69, 69, 84, 41, 36, 51, 63, 44, 36, 33, 48, 63, 33, 53, 63, 48, 50, 47, 48, 37, 50, 52, 41, 37,
	51, 46, 53, 44, 44, 16, 38, 55, 63, 55, 48, 63, 47, 34, 42, 37, 35, 52, 51,
}

func xorByte(i int, c byte) byte {
	v := (c % 255) ^ xorTable[i%len(xorTable)]
	if v == 0 {
		return 255
	}
	return v
}

// Obfuscate encodes a secret for a CCC message.
func Obfuscate(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		out[len(s)-1-i] = xorByte(i, s[i])
	}
	return hex.EncodeToString(out)
}

// Deobfuscate reverses Obfuscate.
func Deobfuscate(h string) (string, error) {
	raw, err := hex.DecodeString(h)
	if err != nil {
		return "", fmt.Errorf("obfuscated value: %w", err)
	}
	n := len(raw)
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = xorByte(i, raw[n-1-i])
	}
	return string(out), nil
}
