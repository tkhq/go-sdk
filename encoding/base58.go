package encoding

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
)

// Bs58Encode encodes a byte slice to a base58 string.
func Bs58Encode(b []byte) string {
	return base58.Encode(b)
}

// Bs58Decode decodes a base58 string to a byte slice.
// Returns nil for invalid input.
func Bs58Decode(s string) []byte {
	return base58.Decode(s)
}

// Bs58DecodeUnsafe decodes a base58 string, returning (nil, false) on invalid input.
func Bs58DecodeUnsafe(s string) ([]byte, bool) {
	b := base58.Decode(s)
	if len(b) == 0 {
		return nil, false
	}

	return b, true
}

// Bs58CheckEncode appends a 4-byte double-SHA256 checksum to payload and base58 encodes the result.
func Bs58CheckEncode(payload []byte) string {
	cksum := Checksum(payload)
	full := make([]byte, len(payload)+4)
	copy(full, payload)
	copy(full[len(payload):], cksum[:])

	return base58.Encode(full)
}

// Bs58CheckDecode decodes a base58check string, verifies the checksum, and returns the payload.
func Bs58CheckDecode(s string) ([]byte, error) {
	decoded := base58.Decode(s)
	if err := ValidateChecksum(decoded); err != nil {
		return nil, fmt.Errorf("invalid bs58check string: %w", err)
	}

	return decoded[:len(decoded)-4], nil
}

// Bs58CheckDecodeUnsafe decodes a base58check string, returning nil on any error.
func Bs58CheckDecodeUnsafe(s string) []byte {
	b, err := Bs58CheckDecode(s)
	if err != nil {
		return nil
	}

	return b
}

// ValidateChecksum validates that a payload has a valid base58check checksum in its last four bytes.
func ValidateChecksum(payload []byte) error {
	if len(payload) < 5 {
		return fmt.Errorf("payload length is < 5 (length: %d)", len(payload))
	}

	expected := Checksum(payload[:len(payload)-4])

	checksum := payload[len(payload)-4:]
	for i := range checksum {
		if checksum[i] != expected[i] {
			return errors.New("checksum mismatch")
		}
	}

	return nil
}

// Checksum returns the first four bytes of a double-SHA256 digest.
func Checksum(payload []byte) (checksum [4]byte) {
	first := sha256.Sum256(payload)
	second := sha256.Sum256(first[:])
	copy(checksum[:], second[:4])

	return checksum
}
