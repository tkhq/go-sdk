package encoding

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

var hexRegex = regexp.MustCompile(`^[0-9A-Fa-f]+$`)

// BytesToHex converts a byte slice into a lowercase hex string.
func BytesToHex(input []byte) string {
	return hex.EncodeToString(input)
}

// HexToBytes creates a byte slice from a hex string. If length is provided, the result
// is left-padded with zeros to that length; it is an error if the hex value exceeds length.
func HexToBytes(hexString string, length ...int) ([]byte, error) {
	if len(hexString) == 0 || len(hexString)%2 != 0 || !hexRegex.MatchString(hexString) {
		return nil, fmt.Errorf("cannot create bytes from invalid hex string: %q", hexString)
	}

	b, err := hex.DecodeString(hexString)
	if err != nil {
		return nil, fmt.Errorf("cannot create bytes from invalid hex string: %q: %w", hexString, err)
	}

	if len(length) == 0 || length[0] == 0 {
		return b, nil
	}

	target := length[0]
	if len(b) > target {
		return nil, fmt.Errorf("hex value cannot fit in a buffer of %d byte(s)", target)
	}

	padded := make([]byte, target)
	copy(padded[target-len(b):], b)

	return padded, nil
}

// HexToASCII converts a hex string to its ASCII string representation.
func HexToASCII(hexString string) string {
	b, _ := hex.DecodeString(hexString)
	return string(b)
}

// NormalizePadding pads or trims a byte slice to exactly targetLength bytes.
// When trimming, leading bytes must be zero or an error is returned.
func NormalizePadding(b []byte, targetLength int) ([]byte, error) {
	paddingLength := targetLength - len(b)

	if paddingLength > 0 {
		padded := make([]byte, targetLength)
		copy(padded[paddingLength:], b)

		return padded, nil
	}

	if paddingLength < 0 {
		expectedZeroCount := -paddingLength
		zeroCount := 0

		for i := 0; i < expectedZeroCount && i < len(b); i++ {
			if b[i] == 0 {
				zeroCount++
			}
		}

		if zeroCount != expectedZeroCount {
			return nil, fmt.Errorf("invalid number of starting zeroes. Expected number of zeroes: %d. Found: %d", expectedZeroCount, zeroCount)
		}

		return b[expectedZeroCount : expectedZeroCount+targetLength], nil
	}

	return b, nil
}

// PointEncode compresses an uncompressed P-256 public key (65 bytes, 0x04 prefix) into
// its 33-byte compressed form (0x02 or 0x03 prefix).
func PointEncode(raw []byte) ([]byte, error) {
	if len(raw) != 65 || raw[0] != 0x04 {
		return nil, fmt.Errorf("invalid uncompressed P-256 key")
	}

	// NewPublicKey accepts the uncompressed SEC 1 encoding and verifies the point is on the curve.
	if _, err := ecdh.P256().NewPublicKey(raw); err != nil {
		return nil, fmt.Errorf("invalid uncompressed P-256 key")
	}

	x := new(big.Int).SetBytes(raw[1:33])
	y := new(big.Int).SetBytes(raw[33:65])

	return elliptic.MarshalCompressed(elliptic.P256(), x, y), nil
}

// StringToBase64URL encodes a plain string to a base64url string (no padding).
func StringToBase64URL(input string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(input))
}

// HexToBase64URL converts a hex string to a base64url string. If length is provided,
// the byte buffer is left-padded with zeros to that length.
func HexToBase64URL(input string, length ...int) (string, error) {
	if len(input)%2 != 0 {
		input = "0" + input
	}

	b, err := HexToBytes(input, length...)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Base64ToBase64URL converts a standard base64 string to base64url by replacing
// '+' with '-', '/' with '_', and stripping '=' padding.
func Base64ToBase64URL(input string) string {
	s := strings.ReplaceAll(input, "+", "-")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "=", "")

	return s
}

// Base64URLToBase64 converts a base64url string back to standard base64 by
// replacing '-' with '+', '_' with '/', and re-adding '=' padding.
func Base64URLToBase64(input string) string {
	s := strings.ReplaceAll(input, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	padLen := (4 - len(s)%4) % 4

	return s + strings.Repeat("=", padLen)
}

// Base64URLToString decodes a base64url string to a plain UTF-8 string.
func Base64URLToString(input string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(input)
	if err != nil {
		b, err = base64.URLEncoding.DecodeString(input)
		if err != nil {
			return "", err
		}
	}

	return string(b), nil
}
