// Package proofs provides verification for Turnkey app proofs and boot proofs.
//
// App proofs and boot proofs establish a cryptographic chain of trust
// that proves Turnkey operations were executed within a genuine AWS Nitro Enclave.
//
// To learn more about verifying app proofs and boot proofs, see:
// https://whitepaper.turnkey.com/foundations/
package proofs

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/tkhq/go-sdk/pkg/api/models"
	"github.com/tkhq/go-sdk/pkg/proofs/attestation"
)

const (
	// expectedEphemeralPublicKeyLength is the expected length of the ephemeral public key in bytes.
	// This is 65 bytes for each of two concatenated P-256 uncompressed public keys (130 hex chars).
	expectedEphemeralPublicKeyLength = 130
)

// Verify an app proof and boot proof pair.
//
// This establishes a cryptographic chain of trust:
//  1. Verifies the app proof signature
//  2. Verifies the boot proof
//     a. Verifies the AWS Nitro attestation document signature and validity
//     b. Verifies the QOS manifest hash matches the attestation document user_data
//  3. Verifies the app proof / boot proof connection - that the app proof's ephemeral public key matches attestation document's public_key field
//
// To learn more about verifying app proofs and boot proofs, see:
// https://whitepaper.turnkey.com/foundations/
func Verify(appProof *models.AppProof, bootProof *models.BootProof) error {
	// 1. Verify App Proof signature
	if err := VerifyAppProofSignature(appProof); err != nil {
		return fmt.Errorf("app proof verification failed: %w", err)
	}

	// 2. Verify Boot Proof
	attestationDoc, err := verifyBootProof(bootProof)
	if err != nil {
		return fmt.Errorf("boot proof verification failed: %w", err)
	}

	// 3. Verify that all ephemeral public keys match: app proof, boot proof structure, actual attestation doc
	if err := verifyEphemeralKeysMatch(appProof, bootProof, attestationDoc); err != nil {
		return err
	}

	return nil
}

// VerifyAppProofSignature verifies the app proof's P-256 ECDSA signature
//
//nolint:gocyclo
func VerifyAppProofSignature(appProof *models.AppProof) error {
	if appProof.Scheme == nil {
		return errors.New("missing app proof scheme")
	}
	if appProof.PublicKey == nil {
		return errors.New("missing app proof public key")
	}
	if appProof.Signature == nil {
		return errors.New("missing app proof signature")
	}
	if appProof.ProofPayload == nil {
		return errors.New("missing app proof payload")
	}

	// Check signature scheme
	if *appProof.Scheme != models.SignatureSchemeEphemeralKeyP256 {
		return errors.New("invalid signature scheme: expected SIGNATURE_SCHEME_EPHEMERAL_KEY_P256")
	}

	// Decode public key from hex
	pubKeyBytes, err := hex.DecodeString(*appProof.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	// The public key should be 130 bytes (two concatenated 65-byte uncompressed P-256 keys)
	if len(pubKeyBytes) != expectedEphemeralPublicKeyLength {
		return fmt.Errorf("invalid public key length: got %d bytes, expected %d", len(pubKeyBytes), expectedEphemeralPublicKeyLength)
	}

	// Extract the signing key (second 65-byte key)
	signingPubKeyBytes := pubKeyBytes[expectedEphemeralPublicKeyLength/2:]
	signingPubKey, err := toEcdsaPublic(signingPubKeyBytes)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	// Decode signature from hex (64 bytes = raw R||S format)
	sigBytes, err := hex.DecodeString(*appProof.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	if len(sigBytes) != 64 {
		return fmt.Errorf("invalid signature length: expected 64 bytes, got %d", len(sigBytes))
	}

	// Convert raw R||S (64 bytes) to big.Int
	r := new(big.Int).SetBytes(sigBytes[0:32])
	s := new(big.Int).SetBytes(sigBytes[32:64])

	// Hash the proof payload with SHA-256
	payloadDigest := sha256.Sum256([]byte(*appProof.ProofPayload))
	if !ecdsa.Verify(signingPubKey, payloadDigest[:], r, s) {
		return errors.New("signature verification failed")
	}

	return nil
}

// verifyBootProof verifies the boot proof's AWS Nitro attestation document
// and returns the parsed attestation document
func verifyBootProof(bootProof *models.BootProof) (map[string]interface{}, error) {
	// Validate required fields
	if bootProof.AwsAttestationDocB64 == nil {
		return nil, errors.New("missing boot proof attestation document")
	}
	if bootProof.QosManifestB64 == nil {
		return nil, errors.New("missing boot proof QOS manifest")
	}

	// Attestation docs technically expire after 3 hours, so an app proof generated 3+ hours after an enclave
	// boots up will fail verification due to certificate expiration. This is okay because enclaves are immutable;
	// even if the cert is technically invalid, the code contained within it cannot change. To prevent the cert
	// expiration failure, we pass in the time from the boot proof as validation time.
	bootProofTime, err := GetBootProofTime(bootProof)
	if err != nil {
		return nil, err
	}

	// Decode attestation document from base64
	attestationBytes, err := base64.StdEncoding.DecodeString(*bootProof.AwsAttestationDocB64)
	if err != nil {
		return nil, fmt.Errorf("attestation document base64 decoding failed: %w", err)
	}

	// Verify the attestation document using our custom implementation
	attestationDoc, err := attestation.ParseAndVerify(attestationBytes, bootProofTime)
	if err != nil {
		return nil, fmt.Errorf("attestation document verification failed: %w", err)
	}

	// Decode QOS manifest from base64
	manifestBytes, err := base64.StdEncoding.DecodeString(*bootProof.QosManifestB64)
	if err != nil {
		return nil, fmt.Errorf("QOS manifest base64 decoding failed: %w", err)
	}

	// Compute SHA-256 hash of the manifest
	manifestDigest := sha256.Sum256(manifestBytes)

	// Verify manifest digest matches attestation user_data
	userData, ok := attestationDoc["user_data"].([]byte)
	if !ok || userData == nil {
		return nil, errors.New("attestation document missing user_data")
	}

	if !bytes.Equal(manifestDigest[:], userData) {
		return nil, fmt.Errorf("manifest digest does not match attestation user_data: attestation=%x, manifest=%x",
			userData, manifestDigest[:])
	}

	return attestationDoc, nil
}

// verifyEphemeralKeysMatch verifies that the ephemeral public keys match across
// the app proof, boot proof, and attestation document
func verifyEphemeralKeysMatch(appProof *models.AppProof, bootProof *models.BootProof, attestationDoc map[string]interface{}) error {
	// Validate required fields
	if bootProof.EphemeralPublicKeyHex == nil {
		return errors.New("missing boot proof ephemeral public key")
	}

	// Get ephemeral key from attestation document
	publicKey, ok := attestationDoc["public_key"].([]byte)
	if !ok || publicKey == nil {
		return errors.New("attestation document missing public_key")
	}
	attestationPubKey := hex.EncodeToString(publicKey)

	// All three keys must match
	appProofKey := *appProof.PublicKey
	bootProofKey := *bootProof.EphemeralPublicKeyHex

	if appProofKey != attestationPubKey || attestationPubKey != bootProofKey {
		return fmt.Errorf("ephemeral public keys do not match: app_proof=%s, boot_proof=%s, attestation=%s",
			appProofKey, bootProofKey, attestationPubKey)
	}

	return nil
}

// GetBootProofTime extracts the timestamp from a boot proof
func GetBootProofTime(bootProof *models.BootProof) (time.Time, error) {
	if bootProof.CreatedAt == nil {
		return time.Time{}, errors.New("missing boot proof timestamp")
	}
	if bootProof.CreatedAt.Seconds == nil || bootProof.CreatedAt.Nanos == nil {
		return time.Time{}, errors.New("missing boot proof timestamp")
	}

	seconds, err := strconv.ParseInt(*bootProof.CreatedAt.Seconds, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid boot proof timestamp: %w", err)
	}

	nanos, err := strconv.ParseInt(*bootProof.CreatedAt.Nanos, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid boot proof timestamp: %w", err)
	}

	return time.Unix(seconds, nanos), nil
}

// toEcdsaPublic converts a 65-byte uncompressed P-256 public key to an ECDSA public key
func toEcdsaPublic(b []byte) (*ecdsa.PublicKey, error) {
	if len(b) != 65 || b[0] != 0x04 {
		return nil, fmt.Errorf("want 65-byte uncompressed P-256 point (0x04||X||Y)")
	}

	if _, err := ecdh.P256().NewPublicKey(b); err != nil {
		return nil, fmt.Errorf("invalid P-256 public key bytes: %w", err)
	}

	x := new(big.Int).SetBytes(b[1:33])
	y := new(big.Int).SetBytes(b[33:65])

	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}
