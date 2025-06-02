// Package util provides convenience utilities for interacting with the API.
package util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"time"
)

// RequestTimestamp returns a timestamp formatted for inclusion in a request.
func RequestTimestamp() *string {
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)

	return &ts
}

// StringPointer returns a pointer to the given string.
func StringPointer(s string) *string {
	return &s
}

// HexToPublicKey converts a hex-encoded string to an ECDSA P-256 public key.
// This key is used in encryption and decryption of data transferred to and from Turnkey secure enclaves.
func HexToPublicKey(hexString string) (*ecdsa.PublicKey, error) {
	publicKeyBytes, err := hex.DecodeString(hexString)
	if err != nil {
		return nil, err
	}

	// second half is the public key bytes for the enclave quorum encryption key
	if len(publicKeyBytes) != 65 {
		return nil, fmt.Errorf("invalid public key length. Expected 65 bytes but got %d (hex string: \"%s\")", len(publicKeyBytes), publicKeyBytes)
	}

	// init curve instance
	curve := elliptic.P256()

	// curve's bitsize converted to length in bytes
	byteLen := (curve.Params().BitSize + 7) / 8

	// ensure the public key bytes have the correct length
	if len(publicKeyBytes) != 1+2*byteLen {
		return nil, fmt.Errorf("invalid encryption public key length")
	}

	// extract X and Y coordinates from the public key bytes
	// ignore first byte (prefix)
	x := new(big.Int).SetBytes(publicKeyBytes[1 : 1+byteLen])
	y := new(big.Int).SetBytes(publicKeyBytes[1+byteLen:])

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}
