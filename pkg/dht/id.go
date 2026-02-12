package dht

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

const IDLength = 32 // 256 bits

type ID [IDLength]byte

// NewID generates an ID from a string (e.g., node address or file key)
func NewID(data string) ID {
	return sha256.Sum256([]byte(data))
}

func NewIDFromBytes(b []byte) ID {
	var id ID
	copy(id[:], b)
	return id
}

func IDFromHex(s string) (ID, error) {
	var id ID
	b, err := hex.DecodeString(s)
	if err != nil {
		return id, err
	}
	if len(b) != IDLength {
		return id, fmt.Errorf("invalid ID length: expected %d, got %d", IDLength, len(b))
	}
	copy(id[:], b)
	return id, nil
}

func (id ID) String() string {
	return hex.EncodeToString(id[:])
}

// Distance calculates the XOR distance between two IDs
func Distance(a, b ID) *big.Int {
	res := make([]byte, IDLength)
	for i := 0; i < IDLength; i++ {
		res[i] = a[i] ^ b[i]
	}
	return new(big.Int).SetBytes(res)
}

// Less returns true if distance(a, target) < distance(b, target)
func Less(a, b, target ID) bool {
	distA := Distance(a, target)
	distB := Distance(b, target)
	return distA.Cmp(distB) == -1
}

// CommonPrefixLen returns the number of leading zero bits in (a XOR b)
func CommonPrefixLen(a, b ID) int {
	for i := 0; i < IDLength; i++ {
		xor := a[i] ^ b[i]
		if xor != 0 {
			// Find position of first set bit
			for j := 0; j < 8; j++ {
				if (xor>>uint(7-j))&1 != 0 {
					return i*8 + j
				}
			}
		}
	}
	return IDLength * 8
}
