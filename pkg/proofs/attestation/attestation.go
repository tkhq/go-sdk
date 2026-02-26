package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// ParseAndVerify parses a COSE Sign1 attestation document and verifies its signature.
// COSE Sign1 structure: [protected, unprotected, payload, signature]
//
//nolint:gocyclo
func ParseAndVerify(data []byte, validationTime time.Time) (map[string]interface{}, error) {
	// Decode COSE Sign1 array
	var coseSign1 []interface{}
	if err := cbor.Unmarshal(data, &coseSign1); err != nil {
		return nil, fmt.Errorf("failed to unmarshal COSE Sign1: %w", err)
	}

	protected, ok := coseSign1[0].([]byte)
	if !ok {
		return nil, errors.New("invalid COSE Sign1: protected headers is not a byte array")
	}
	payload, ok := coseSign1[2].([]byte)
	if !ok {
		return nil, errors.New("invalid COSE Sign1: payload is not a byte array")
	}
	signature, ok := coseSign1[3].([]byte)
	if !ok {
		return nil, errors.New("invalid COSE Sign1: signature is not a byte array")
	}

	// Decode payload to get attestation document
	var doc map[string]interface{}
	if err := cbor.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal document: %w", err)
	}

	// Convert cabundle to [][]byte
	cabundle, ok := doc["cabundle"].([]interface{})
	if !ok {
		return nil, errors.New("invalid attestation document: cabundle is not an array")
	}
	certs := make([][]byte, 0, len(cabundle))
	for _, cert := range cabundle {
		certBytes, ok := cert.([]byte)
		if !ok {
			return nil, errors.New("invalid attestation document: cabundle entry is not a byte array")
		}
		certs = append(certs, certBytes)
	}

	// Verify certificate chain to get the leaf certificate
	certificate, ok := doc["certificate"].([]byte)
	if !ok {
		return nil, errors.New("invalid attestation document: certificate is not a byte array")
	}
	cert, err := verifyCertificateChain(certificate, certs, validationTime)
	if err != nil {
		return nil, fmt.Errorf("certificate chain verification failed: %w", err)
	}

	// Extract ECDSA public key from certificate
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("certificate public key is not ECDSA")
	}

	if pubKey.Curve != elliptic.P384() {
		return nil, fmt.Errorf("expected P-384 curve, got %s", pubKey.Curve.Params().Name)
	}

	// Construct Sig_structure for COSE Sign1
	sigStructure := []interface{}{
		"Signature1",
		protected,
		[]byte{},
		payload,
	}

	// CBOR-encode Sig_structure (to-be-signed data)
	tbs, err := cbor.Marshal(sigStructure)
	if err != nil {
		return nil, fmt.Errorf("failed to encode Sig_structure: %w", err)
	}

	// Hash with SHA-384 (for ES384)
	digest := sha512.Sum384(tbs)

	// Parse signature (96 bytes for P-384: 48 bytes R + 48 bytes S)
	if len(signature) != 96 {
		return nil, fmt.Errorf("invalid signature length: expected 96 bytes, got %d", len(signature))
	}

	r := new(big.Int).SetBytes(signature[0:48])
	s := new(big.Int).SetBytes(signature[48:96])

	// Verify ECDSA signature
	if !ecdsa.Verify(pubKey, digest[:], r, s) {
		return nil, errors.New("COSE signature verification failed")
	}

	return doc, nil
}
