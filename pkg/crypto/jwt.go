package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// VerifySessionJwtSignature verifies the signature of a Turnkey session JWT using the custom
// double SHA-256 scheme with the production notarizer public key.
//
// Session JWTs use a custom signing scheme:
//   - Double SHA-256 hash: hash = SHA256(SHA256(header.payload))
//   - ECDSA signature with P-256 curve
//   - IEEE P1363 signature format (raw R || S concatenation, 64 bytes)
//   - Uncompressed public key (65 bytes, starts with 0x04)
//
// This is different from standard ES256 JWTs which use single SHA-256 hashing.
//
// Parameters:
//   - jwtString: The session JWT to verify (format: header.payload.signature)
//   - dangerouslyOverrideNotarizerPublicKey: Optional hex-encoded public key for testing.
//     If not provided, uses ProductionNotarizerPublicKey.
//
// Returns an error if:
//   - JWT format is invalid
//   - Public key cannot be parsed
//   - Signature is invalid
//   - Signature format is incorrect
func VerifySessionJwtSignature(jwtString string, dangerouslyOverrideNotarizerPublicKey ...string) error {
	// Determine which public key to use
	notarizerPublicKeyHex := ProductionNotarizerPublicKey
	if len(dangerouslyOverrideNotarizerPublicKey) > 0 && dangerouslyOverrideNotarizerPublicKey[0] != "" {
		notarizerPublicKeyHex = dangerouslyOverrideNotarizerPublicKey[0]
	}

	// 1. Split JWT into header, payload, signature
	parts := strings.Split(jwtString, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// 2. Create signing input (header.payload)
	signingInput := parts[0] + "." + parts[1]

	// 3. Double SHA-256 hash (custom scheme for session JWTs)
	hash1 := sha256.Sum256([]byte(signingInput))
	msgDigest := sha256.Sum256(hash1[:])

	// 4. Parse the uncompressed notarizer public key
	pubKeyBytes, err := hex.DecodeString(notarizerPublicKeyHex)
	if err != nil {
		return fmt.Errorf("invalid notarizer public key encoding: %w", err)
	}

	if len(pubKeyBytes) != 65 || pubKeyBytes[0] != 0x04 {
		return fmt.Errorf("invalid uncompressed public key format: expected 65 bytes starting with 0x04, got %d bytes", len(pubKeyBytes))
	}

	x := new(big.Int).SetBytes(pubKeyBytes[1:33])
	y := new(big.Int).SetBytes(pubKeyBytes[33:65])

	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	// 5. Decode the signature from base64url
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// 6. Parse IEEE P1363 format signature (raw R || S, 64 bytes for P-256)
	if len(sigBytes) != 64 {
		return fmt.Errorf("invalid signature length: expected 64 bytes, got %d", len(sigBytes))
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:64])

	// 7. Verify the ECDSA signature
	if !ecdsa.Verify(pubKey, msgDigest[:], r, s) {
		return fmt.Errorf("session JWT signature verification failed")
	}

	return nil
}

// VerifyOtpVerificationToken verifies the signature of an OTP verification token JWT
// using the production OTP verification public key.
//
// OTP verification tokens use standard ES256 JWT signing:
//   - Single SHA-256 hash (standard ES256)
//   - ECDSA signature with P-256 curve
//   - Compressed public key (33 bytes, starts with 0x02 or 0x03)
//
// Parameters:
//   - tokenString: The OTP verification token JWT to verify
//   - dangerouslyOverrideOtpVerificationPublicKey: Optional hex-encoded public key for testing.
//     If not provided, uses ProductionOTPVerificationPublicKey.
//
// Returns an error if:
//   - JWT format is invalid
//   - Public key cannot be parsed
//   - Signature is invalid
//   - Required claims are missing (id, verification_type, contact)
//
//nolint:gocyclo // Complexity from thorough validation is intentional for security
func VerifyOtpVerificationToken(tokenString string, dangerouslyOverrideOtpVerificationPublicKey ...string) error {
	// Determine which public key to use
	otpVerificationPublicKeyHex := ProductionOTPVerificationPublicKey
	if len(dangerouslyOverrideOtpVerificationPublicKey) > 0 && dangerouslyOverrideOtpVerificationPublicKey[0] != "" {
		otpVerificationPublicKeyHex = dangerouslyOverrideOtpVerificationPublicKey[0]
	}

	// 1. Decode the compressed public key from hex
	pubKeyBytes, err := hex.DecodeString(otpVerificationPublicKeyHex)
	if err != nil {
		return fmt.Errorf("invalid public key encoding: %w", err)
	}

	// 2. Unmarshal the compressed P-256 point
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), pubKeyBytes)
	if x == nil || y == nil {
		return fmt.Errorf("invalid public key format")
	}

	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	// 3. Parse and verify the JWT with ES256
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		// Verify the signing method is ES256
		if t.Method != jwt.SigningMethodES256 {
			return nil, fmt.Errorf("unexpected signing method: %v (expected ES256)", t.Method.Alg())
		}
		return pubKey, nil
	})

	if err != nil {
		return fmt.Errorf("failed to parse and verify token: %w", err)
	}

	if !token.Valid {
		return fmt.Errorf("token is invalid")
	}

	// 4. Extract and validate claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid token claims")
	}

	// Verify required claims exist
	if _, ok := claims["id"].(string); !ok {
		return fmt.Errorf("token missing 'id' claim")
	}
	if _, ok := claims["verification_type"].(string); !ok {
		return fmt.Errorf("token missing 'verification_type' claim")
	}
	if _, ok := claims["contact"].(string); !ok {
		return fmt.Errorf("token missing 'contact' claim")
	}

	return nil
}
