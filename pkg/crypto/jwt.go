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
	notarizerPublicKeyHex := ProductionNotarizerPublicKey
	if len(dangerouslyOverrideNotarizerPublicKey) > 0 && dangerouslyOverrideNotarizerPublicKey[0] != "" {
		notarizerPublicKeyHex = dangerouslyOverrideNotarizerPublicKey[0]
	}

	parts := strings.Split(jwtString, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	signingInput := parts[0] + "." + parts[1]

	// Double SHA-256 hash (custom scheme for session JWTs)
	hash1 := sha256.Sum256([]byte(signingInput))
	msgDigest := sha256.Sum256(hash1[:])

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

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// IEEE P1363 format: raw R || S, 64 bytes for P-256
	if len(sigBytes) != 64 {
		return fmt.Errorf("invalid signature length: expected 64 bytes, got %d", len(sigBytes))
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:64])

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
//   - dangerouslyOverridePublicKey: Hex-encoded public key for testing. Pass empty string to use
//     ProductionOTPVerificationPublicKey.
//   - parserOpts: Optional jwt.ParserOption values passed to the JWT parser. Tests may pass
//     jwt.WithTimeFunc to bypass expiry on captured tokens.
//
// Returns an error if:
//   - JWT format is invalid
//   - Public key cannot be parsed
//   - Signature is invalid
//   - Required claims are missing (id, verification_type, contact)
func VerifyOtpVerificationToken(tokenString, dangerouslyOverridePublicKey string, parserOpts ...jwt.ParserOption) error {
	otpVerificationPublicKeyHex := ProductionOTPVerificationPublicKey
	if dangerouslyOverridePublicKey != "" {
		otpVerificationPublicKeyHex = dangerouslyOverridePublicKey
	}

	pubKeyBytes, err := hex.DecodeString(otpVerificationPublicKeyHex)
	if err != nil {
		return fmt.Errorf("invalid public key encoding: %w", err)
	}

	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), pubKeyBytes)
	if x == nil || y == nil {
		return fmt.Errorf("invalid public key format")
	}

	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	parser := jwt.NewParser(parserOpts...)
	token, err := parser.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
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

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid token claims")
	}

	return validateOtpVerificationTokenClaims(claims)
}

func validateOtpVerificationTokenClaims(claims jwt.MapClaims) error {
	for _, field := range []string{"id", "verification_type", "contact"} {
		if _, ok := claims[field].(string); !ok {
			return fmt.Errorf("token missing %q claim", field)
		}
	}
	return nil
}
