package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
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

// VerifyLegacyVerificationToken verifies the signature of an OTP verification token JWT
// using the production OTP verification public key.
func VerifyLegacyVerificationToken(tokenString, dangerouslyOverridePublicKey string, parserOpts ...jwt.ParserOption) error {
	otpVerificationPublicKeyHex := ProductionLegacyVerificationTokenPublicKey
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

// P256Sign signs msg with ECDSA P-256 using SHA-256 and ASN.1 encoding.
func P256Sign(privateKey *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	hash := sha256.Sum256(msg)
	return ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
}

// P256Verify verifies an ASN.1 ECDSA P-256 signature over msg using SHA-256.
func P256Verify(publicKey *ecdsa.PublicKey, msg []byte, signature []byte) bool {
	hash := sha256.Sum256(msg)
	return ecdsa.VerifyASN1(publicKey, hash[:], signature)
}

// ToECDSAPublic parses an uncompressed P-256 ECDSA public key.
func ToECDSAPublic(publicBytes []byte) (*ecdsa.PublicKey, error) {
	if len(publicBytes) != 65 || publicBytes[0] != 0x04 {
		return nil, errors.New("invalid P-256 public key: want 65-byte uncompressed point (0x04||X||Y)")
	}

	if _, err := ecdh.P256().NewPublicKey(publicBytes); err != nil {
		return nil, fmt.Errorf("invalid P-256 public key: %w", err)
	}

	curve := elliptic.P256()
	x := new(big.Int).SetBytes(publicBytes[1:33])
	y := new(big.Int).SetBytes(publicBytes[33:65])

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// AWS Nitro root CA certificate.
// Downloaded from: https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
// Documentation: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
const awsRootCertPEM = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----`

const (
	// SignatureSchemeEphemeralKeyP256 is the expected app proof signature scheme.
	SignatureSchemeEphemeralKeyP256 = "SIGNATURE_SCHEME_EPHEMERAL_KEY_P256"

	expectedEphemeralPublicKeyLength = 130
)

// Timestamp represents a protobuf-style timestamp returned by Turnkey APIs.
type Timestamp struct {
	Seconds string
	Nanos   string
}

// AppProof contains the app proof fields required for cryptographic verification.
type AppProof struct {
	ProofPayload string
	PublicKey    string
	Scheme       string
	Signature    string
}

// BootProof contains the boot proof fields required for cryptographic verification.
type BootProof struct {
	AWSAttestationDocB64   string
	CreatedAt              Timestamp
	DeploymentLabel        string
	EnclaveApp             string
	EphemeralPublicKeyHex  string
	Owner                  string
	QosManifestB64         string
	QosManifestEnvelopeB64 string
}

// VerifyProofs verifies an app proof and boot proof pair.
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
func VerifyProofs(appProof *AppProof, bootProof *BootProof) error {
	if appProof == nil {
		return errors.New("missing app proof")
	}

	if bootProof == nil {
		return errors.New("missing boot proof")
	}

	if err := VerifyAppProofSignature(appProof); err != nil {
		return fmt.Errorf("app proof verification failed: %w", err)
	}

	attestationDoc, err := verifyBootProof(bootProof)
	if err != nil {
		return fmt.Errorf("boot proof verification failed: %w", err)
	}

	if err := verifyEphemeralKeysMatch(appProof, bootProof, attestationDoc); err != nil {
		return err
	}

	return nil
}

// VerifyAppProofSignature verifies the app proof's P-256 ECDSA signature.
//
//nolint:gocyclo
func VerifyAppProofSignature(appProof *AppProof) error {
	if appProof == nil {
		return errors.New("missing app proof")
	}

	if appProof.Scheme == "" {
		return errors.New("missing app proof scheme")
	}

	if appProof.PublicKey == "" {
		return errors.New("missing app proof public key")
	}

	if appProof.Signature == "" {
		return errors.New("missing app proof signature")
	}

	if appProof.ProofPayload == "" {
		return errors.New("missing app proof payload")
	}

	if appProof.Scheme != SignatureSchemeEphemeralKeyP256 {
		return errors.New("invalid signature scheme: expected SIGNATURE_SCHEME_EPHEMERAL_KEY_P256")
	}

	pubKeyBytes, err := hex.DecodeString(appProof.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	if len(pubKeyBytes) != expectedEphemeralPublicKeyLength {
		return fmt.Errorf("invalid public key length: got %d bytes, expected %d", len(pubKeyBytes), expectedEphemeralPublicKeyLength)
	}

	signingPubKeyBytes := pubKeyBytes[expectedEphemeralPublicKeyLength/2:]

	signingPubKey, err := ToECDSAPublic(signingPubKeyBytes)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	sigBytes, err := hex.DecodeString(appProof.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	if len(sigBytes) != 64 {
		return fmt.Errorf("invalid signature length: expected 64 bytes, got %d", len(sigBytes))
	}

	r := new(big.Int).SetBytes(sigBytes[0:32])
	s := new(big.Int).SetBytes(sigBytes[32:64])

	payloadDigest := sha256.Sum256([]byte(appProof.ProofPayload))
	if !ecdsa.Verify(signingPubKey, payloadDigest[:], r, s) {
		return errors.New("signature verification failed")
	}

	return nil
}

func verifyBootProof(bootProof *BootProof) (map[string]interface{}, error) {
	if bootProof == nil {
		return nil, errors.New("missing boot proof")
	}

	if bootProof.AWSAttestationDocB64 == "" {
		return nil, errors.New("missing boot proof attestation document")
	}

	if bootProof.QosManifestB64 == "" {
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

	attestationBytes, err := base64.StdEncoding.DecodeString(bootProof.AWSAttestationDocB64)
	if err != nil {
		return nil, fmt.Errorf("attestation document base64 decoding failed: %w", err)
	}

	attestationDoc, err := parseAndVerifyAttestation(attestationBytes, bootProofTime)
	if err != nil {
		return nil, fmt.Errorf("attestation document verification failed: %w", err)
	}

	manifestBytes, err := base64.StdEncoding.DecodeString(bootProof.QosManifestB64)
	if err != nil {
		return nil, fmt.Errorf("QOS manifest base64 decoding failed: %w", err)
	}

	manifestDigest := sha256.Sum256(manifestBytes)

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

func verifyEphemeralKeysMatch(appProof *AppProof, bootProof *BootProof, attestationDoc map[string]interface{}) error {
	if bootProof.EphemeralPublicKeyHex == "" {
		return errors.New("missing boot proof ephemeral public key")
	}

	publicKey, ok := attestationDoc["public_key"].([]byte)
	if !ok || publicKey == nil {
		return errors.New("attestation document missing public_key")
	}

	attestationPubKey := hex.EncodeToString(publicKey)

	appProofKey := appProof.PublicKey
	bootProofKey := bootProof.EphemeralPublicKeyHex

	if appProofKey != attestationPubKey || attestationPubKey != bootProofKey {
		return fmt.Errorf("ephemeral public keys do not match: app_proof=%s, boot_proof=%s, attestation=%s",
			appProofKey, bootProofKey, attestationPubKey)
	}

	return nil
}

// GetBootProofTime extracts the timestamp from a boot proof.
func GetBootProofTime(bootProof *BootProof) (time.Time, error) {
	if bootProof == nil {
		return time.Time{}, errors.New("missing boot proof")
	}

	if bootProof.CreatedAt.Seconds == "" || bootProof.CreatedAt.Nanos == "" {
		return time.Time{}, errors.New("missing boot proof timestamp")
	}

	seconds, err := strconv.ParseInt(bootProof.CreatedAt.Seconds, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid boot proof timestamp: %w", err)
	}

	nanos, err := strconv.ParseInt(bootProof.CreatedAt.Nanos, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid boot proof timestamp: %w", err)
	}

	return time.Unix(seconds, nanos), nil
}

// parseAndVerifyAttestation parses a COSE Sign1 attestation document and verifies its signature.
//
//nolint:gocyclo
func parseAndVerifyAttestation(data []byte, validationTime time.Time) (map[string]interface{}, error) {
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

	var doc map[string]interface{}
	if err := cbor.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal document: %w", err)
	}

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

	certificate, ok := doc["certificate"].([]byte)
	if !ok {
		return nil, errors.New("invalid attestation document: certificate is not a byte array")
	}

	cert, err := verifyCertificateChain(certificate, certs, validationTime)
	if err != nil {
		return nil, fmt.Errorf("certificate chain verification failed: %w", err)
	}

	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("certificate public key is not ECDSA")
	}

	if pubKey.Curve != elliptic.P384() {
		return nil, fmt.Errorf("expected P-384 curve, got %s", pubKey.Curve.Params().Name)
	}

	sigStructure := []interface{}{
		"Signature1",
		protected,
		[]byte{},
		payload,
	}

	tbs, err := cbor.Marshal(sigStructure)
	if err != nil {
		return nil, fmt.Errorf("failed to encode Sig_structure: %w", err)
	}

	digest := sha512.Sum384(tbs)

	if len(signature) != 96 {
		return nil, fmt.Errorf("invalid signature length: expected 96 bytes, got %d", len(signature))
	}

	r := new(big.Int).SetBytes(signature[0:48])
	s := new(big.Int).SetBytes(signature[48:96])

	if !ecdsa.Verify(pubKey, digest[:], r, s) {
		return nil, errors.New("COSE signature verification failed")
	}

	return doc, nil
}

func verifyCertificateChain(certificate []byte, cabundle [][]byte, validationTime time.Time) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	if cert.PublicKeyAlgorithm != x509.ECDSA {
		return nil, errors.New("certificate must use ECDSA")
	}

	if cert.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		return nil, errors.New("certificate must use ECDSAWithSHA384")
	}

	intermediates := x509.NewCertPool()

	for i, certDER := range cabundle {
		intermediate, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, fmt.Errorf("failed to parse intermediate cert %d: %w", i, err)
		}

		intermediates.AddCert(intermediate)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(awsRootCertPEM)) {
		return nil, errors.New("failed to parse AWS root certificate")
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   validationTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	chains, err := cert.Verify(opts)
	if err != nil {
		return nil, fmt.Errorf("certificate chain verification failed: %w", err)
	}

	if len(chains) == 0 {
		return nil, errors.New("no valid certificate chains found")
	}

	return cert, nil
}
