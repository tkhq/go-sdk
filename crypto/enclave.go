package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/cloudflare/circl/kem"

	tkencoding "github.com/tkhq/go-sdk/encoding"
)

type Bytes = tkencoding.HexBytes

// ServerSendMsgV1 is the server send message format with enclave quorum key and signature.
type ServerSendMsgV1 struct {
	Version             string `json:"version"`
	Data                Bytes  `json:"data"`
	DataSignature       Bytes  `json:"dataSignature"`
	EnclaveQuorumPublic Bytes  `json:"enclaveQuorumPublic"`
}

// ServerSendData is the signed data payload inside a ServerSendMsgV1.
type ServerSendData struct {
	EncappedPublic Bytes  `json:"encappedPublic"`
	Ciphertext     Bytes  `json:"ciphertext"`
	OrganizationID string `json:"organizationId"`
}

// ServerTargetMsgV1 is the server target message format with enclave quorum key and signature.
type ServerTargetMsgV1 struct {
	Version             string `json:"version"`
	Data                Bytes  `json:"data"`
	DataSignature       Bytes  `json:"dataSignature"`
	EnclaveQuorumPublic Bytes  `json:"enclaveQuorumPublic"`
}

// ServerTargetData is the signed data payload inside a ServerTargetMsgV1.
type ServerTargetData struct {
	TargetPublic   Bytes  `json:"targetPublic"`
	OrganizationID string `json:"organizationId"`
	UserID         string `json:"userId"`
}

// ClientSendMsg is the client's encrypted message to the enclave.
type ClientSendMsg struct {
	EncappedPublic *Bytes `json:"encappedPublic,omitempty"`
	Ciphertext     *Bytes `json:"ciphertext,omitempty"`
}

// KeyFormat values supported by EncryptPrivateKeyToBundle.
const (
	KeyFormatHexadecimal = "HEXADECIMAL"
	KeyFormatSolana      = "SOLANA"
)

// DecryptExportBundle decrypts an export bundle (wallet or private key export flow).
// Verifies the enclave signature using the production signer key and validates organizationID.
// Pass dangerouslyOverrideSignerKey to use a custom enclave quorum public key (non-production only).
func DecryptExportBundle(bundleBytes []byte, organizationID string, kemPrivateKey kem.PrivateKey, dangerouslyOverrideSignerKey ...*ecdsa.PublicKey) ([]byte, error) {
	signerKey, err := resolveSignerKey(dangerouslyOverrideSignerKey...)
	if err != nil {
		return nil, err
	}

	var msg ServerSendMsgV1
	if err := json.Unmarshal(bundleBytes, &msg); err != nil {
		return nil, err
	}

	if err := verifyEnclaveSignature(msg.EnclaveQuorumPublic, msg.DataSignature, msg.Data, signerKey); err != nil {
		return nil, err
	}

	var signedData ServerSendData
	if err := json.Unmarshal(msg.Data, &signedData); err != nil {
		return nil, err
	}

	if signedData.OrganizationID != organizationID {
		return nil, fmt.Errorf("organization id does not match expected value. Expected: %s. Found: %s", organizationID, signedData.OrganizationID)
	}

	return HPKEDecrypt(signedData.EncappedPublic, kemPrivateKey, signedData.Ciphertext)
}

// DecryptCredentialBundle decrypts a base58check-encoded credential bundle from the server.
// Used in email authentication and email recovery flows.
func DecryptCredentialBundle(credentialBundle string, kemPrivateKey kem.PrivateKey) ([]byte, error) {
	payloadBytes := tkencoding.Bs58Decode(credentialBundle)

	if err := tkencoding.ValidateChecksum(payloadBytes); err != nil {
		return nil, err
	}

	payloadBytes = payloadBytes[:len(payloadBytes)-4]
	if len(payloadBytes) < 33 {
		return nil, errors.New("payload is less than 33 bytes, the length of the expected public key")
	}

	compressedKey := payloadBytes[0:33]
	ciphertext := payloadBytes[33:]

	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), compressedKey)
	if x == nil || y == nil {
		return nil, errors.New("invalid compressed P-256 public key")
	}

	encappedPublic := make([]byte, 65)
	encappedPublic[0] = 0x04
	x.FillBytes(encappedPublic[1:33])
	y.FillBytes(encappedPublic[33:65])

	return HPKEDecrypt(encappedPublic, kemPrivateKey, ciphertext)
}

// EncryptWalletToBundle encrypts a wallet mnemonic to the given import bundle.
// Verifies the enclave signature using the production signer key and validates organizationID and userID.
// Pass dangerouslyOverrideSignerKey to use a custom enclave quorum public key (non-production only).
func EncryptWalletToBundle(mnemonic, importBundle, organizationID, userID string, dangerouslyOverrideSignerKey ...*ecdsa.PublicKey) (string, error) {
	signerKey, err := resolveSignerKey(dangerouslyOverrideSignerKey...)
	if err != nil {
		return "", err
	}

	return encryptImportBundle([]byte(mnemonic), []byte(importBundle), organizationID, userID, signerKey)
}

// EncryptPrivateKeyToBundle encrypts a private key to the given import bundle.
// keyFormat is "HEXADECIMAL" or "SOLANA". Verifies the enclave signature and validates organizationID and userID.
// Pass dangerouslyOverrideSignerKey to use a custom enclave quorum public key (non-production only).
func EncryptPrivateKeyToBundle(privateKey, keyFormat, importBundle, organizationID, userID string, dangerouslyOverrideSignerKey ...*ecdsa.PublicKey) (string, error) {
	signerKey, err := resolveSignerKey(dangerouslyOverrideSignerKey...)
	if err != nil {
		return "", err
	}

	plaintext, err := decodeKey(privateKey, keyFormat)
	if err != nil {
		return "", err
	}

	return encryptImportBundle(plaintext, []byte(importBundle), organizationID, userID, signerKey)
}

// EncryptSecretToBundle verifies the target's signature, org, and empty user ID, then returns encrypted ClientSendMsg JSON and its hex target key.
// The ciphertext is bound to the secret's name and static properties (see ImportSecretsPurposeBinding). The
// ImportSecrets activity must send the same name and properties in the same order, with
// TRANSPORT_ENCRYPTION_SUITE_ENCLAVE_ENCRYPT_V2.
// dangerouslyOverrideSignerKey replaces the production quorum key (non-production only).
func EncryptSecretToBundle(plaintext []byte, targetBundle, organizationID string, name *string, staticProperties []StaticProperty, dangerouslyOverrideSignerKey ...*ecdsa.PublicKey) (string, string, error) {
	signerKey, err := resolveSignerKey(dangerouslyOverrideSignerKey...)
	if err != nil {
		return "", "", err
	}

	signedData, err := verifyImportTarget([]byte(targetBundle), organizationID, signerKey)
	if err != nil {
		return "", "", err
	}

	// Secret targets are signed with an empty user ID; a non-empty one marks a private key or wallet import target.
	if signedData.UserID != "" {
		return "", "", fmt.Errorf("secret import target user id must be empty. Found: %s", signedData.UserID)
	}

	payload, err := hpkeEncryptToTarget(signedData.TargetPublic, plaintext, ImportSecretsPurposeBinding(name, staticProperties))
	if err != nil {
		return "", "", err
	}

	return payload, hex.EncodeToString(signedData.TargetPublic), nil
}

// otpAttemptBundle is the confidential VerifyOtp input encrypted to the TLS Fetcher.
type otpAttemptBundle struct {
	OtpCode   string `json:"otp_code"`
	PublicKey string `json:"public_key"`
}

// String redacts the bundle, which carries the OTP code.
func (otpAttemptBundle) String() string {
	return "otpAttemptBundle(<redacted>)"
}

// LogValue redacts the bundle in structured logs.
func (b otpAttemptBundle) LogValue() slog.Value {
	return slog.StringValue(b.String())
}

// EncryptOtpCodeToBundle encrypts an OTP code and a client public key to the target bundle
// returned by InitOtp. Verifies the enclave signature using ProductionTLSFetcherSigningPublicKey.
// Pass dangerouslyOverrideSignerPublicKeyHex to use a custom signer key (non-production only).
func EncryptOtpCodeToBundle(otpCode, targetBundle, publicKey string, dangerouslyOverrideSignerPublicKeyHex ...string) (string, error) {
	var override *ecdsa.PublicKey

	if len(dangerouslyOverrideSignerPublicKeyHex) > 0 && dangerouslyOverrideSignerPublicKeyHex[0] != "" {
		overrideBytes, err := hex.DecodeString(dangerouslyOverrideSignerPublicKeyHex[0])
		if err != nil {
			return "", fmt.Errorf("failed to decode signer public key: %w", err)
		}

		override, err = ToECDSAPublic(overrideBytes)
		if err != nil {
			return "", fmt.Errorf("failed to parse signer public key: %w", err)
		}
	}

	signerKey, err := resolveTLSFetcherKey(override)
	if err != nil {
		return "", err
	}

	var msg ServerTargetMsgV1
	if err := json.Unmarshal([]byte(targetBundle), &msg); err != nil {
		return "", err
	}

	if err := verifyEnclaveSignature(msg.EnclaveQuorumPublic, msg.DataSignature, msg.Data, signerKey); err != nil {
		return "", err
	}

	var signedData ServerTargetData
	if err := json.Unmarshal(msg.Data, &signedData); err != nil {
		return "", err
	}

	plaintext, err := json.Marshal(otpAttemptBundle{OtpCode: otpCode, PublicKey: publicKey})
	if err != nil {
		return "", err
	}

	defer clear(plaintext)

	return hpkeEncryptToTarget(signedData.TargetPublic, plaintext, nil)
}

// OAuth2AuthenticationBundle is the confidential OAuth2AuthenticateV2 input encrypted to the TLS Fetcher.
// OrganizationID, OAuth2CredentialID, ClientID, and Provider must match the authenticating organization's credential.
type OAuth2AuthenticationBundle struct {
	OrganizationID     string `json:"organization_id"`
	OAuth2CredentialID string `json:"oauth2_credential_id"`
	ClientID           string `json:"client_id"`
	// Provider is the OAuth 2.0 provider enum name, such as OAUTH2_PROVIDER_DISCORD.
	Provider     string `json:"provider"`
	AuthCode     string `json:"auth_code"`
	CodeVerifier string `json:"code_verifier"`
	RedirectURI  string `json:"redirect_uri"`
	// Nonce is the lowercase hex SHA-256 digest bound into the issued OIDC token.
	Nonce string `json:"nonce"`
	// BearerTokenTargetPublicKey optionally receives the provider bearer token, encrypted to this uncompressed P-256 key.
	BearerTokenTargetPublicKey string `json:"bearer_token_target_public_key,omitempty"`
}

// String redacts the payload, which carries the authorization code and PKCE verifier.
func (OAuth2AuthenticationBundle) String() string {
	return "OAuth2AuthenticationBundle(<redacted>)"
}

// LogValue redacts the payload in structured logs.
func (b OAuth2AuthenticationBundle) LogValue() slog.Value {
	return slog.StringValue(b.String())
}

// EncryptOAuth2ToBundle verifies the TLS Fetcher target returned by InitOAuth2Authenticate, then returns the encrypted
// ClientSendMsg JSON and hex target public key for OAuth2AuthenticateV2's encryptedMessage and targetPublicKey.
// dangerouslyOverrideSignerKey replaces ProductionTLSFetcherSigningPublicKey (non-production only).
func EncryptOAuth2ToBundle(bundle OAuth2AuthenticationBundle, targetBundle string, dangerouslyOverrideSignerKey ...*ecdsa.PublicKey) (string, string, error) {
	signerKey, err := resolveTLSFetcherKey(dangerouslyOverrideSignerKey...)
	if err != nil {
		return "", "", err
	}

	plaintext, err := json.Marshal(bundle)
	if err != nil {
		return "", "", err
	}

	defer clear(plaintext)

	signedData, err := verifyImportTarget([]byte(targetBundle), bundle.OrganizationID, signerKey)
	if err != nil {
		return "", "", err
	}

	// TLS Fetcher OAuth2 targets are signed with an empty user ID.
	if signedData.UserID != "" {
		return "", "", fmt.Errorf("oauth2 target user id must be empty. Found: %s", signedData.UserID)
	}

	// OAuth2AuthenticateV2 decrypts without a purpose binding.
	payload, err := hpkeEncryptToTarget(signedData.TargetPublic, plaintext, nil)
	if err != nil {
		return "", "", err
	}

	return payload, hex.EncodeToString(signedData.TargetPublic), nil
}

// encryptImportBundle is the shared parse+verify+encrypt flow for wallet and private-key imports.
func encryptImportBundle(plaintext, bundleBytes []byte, organizationID, userID string, signerKey *ecdsa.PublicKey) (string, error) {
	signedData, err := verifyImportTarget(bundleBytes, organizationID, signerKey)
	if err != nil {
		return "", err
	}

	if signedData.UserID != userID {
		return "", fmt.Errorf("user id does not match expected value. Expected: %s. Found: %s", userID, signedData.UserID)
	}

	return hpkeEncryptToTarget(signedData.TargetPublic, plaintext, nil)
}

// verifyImportTarget parses a signed import target, verifies its enclave signature, and checks its organization ID.
func verifyImportTarget(bundleBytes []byte, organizationID string, signerKey *ecdsa.PublicKey) (ServerTargetData, error) {
	var msg ServerTargetMsgV1
	if err := json.Unmarshal(bundleBytes, &msg); err != nil {
		return ServerTargetData{}, err
	}

	if err := verifyEnclaveSignature(msg.EnclaveQuorumPublic, msg.DataSignature, msg.Data, signerKey); err != nil {
		return ServerTargetData{}, err
	}

	var signedData ServerTargetData
	if err := json.Unmarshal(msg.Data, &signedData); err != nil {
		return ServerTargetData{}, err
	}

	if signedData.OrganizationID != organizationID {
		return ServerTargetData{}, fmt.Errorf("organization id does not match expected value. Expected: %s. Found: %s", organizationID, signedData.OrganizationID)
	}

	return signedData, nil
}

func hpkeEncryptToTarget(targetPublicRaw []byte, plaintext, purposeBinding []byte) (string, error) {
	targetPublic, err := KemID.Scheme().UnmarshalBinaryPublicKey(targetPublicRaw)
	if err != nil {
		return "", err
	}

	ciphertext, encappedPublic, err := HPKEEncryptWithPurposeBinding(&targetPublic, plaintext, purposeBinding)
	if err != nil {
		return "", err
	}

	enc := Bytes(encappedPublic)
	ciph := Bytes(ciphertext)

	out, err := json.Marshal(&ClientSendMsg{EncappedPublic: &enc, Ciphertext: &ciph})
	if err != nil {
		return "", err
	}

	return string(out), nil
}

// verifyEnclaveSignature verifies that the enclave bundle was signed by the expected signer key.
func verifyEnclaveSignature(enclaveQuorumPublic, dataSignature, data []byte, expectedSignerKey *ecdsa.PublicKey) error {
	if enclaveQuorumPublic == nil {
		return errors.New("missing enclave quorum public key")
	}

	enclaveQuorumKey, err := ToECDSAPublic(enclaveQuorumPublic)
	if err != nil {
		return err
	}

	if !enclaveQuorumKey.Equal(expectedSignerKey) {
		return errors.New("enclave quorum public keys from client and message do not match")
	}

	if !P256Verify(enclaveQuorumKey, data, dataSignature) {
		return errors.New("invalid enclave auth key signature")
	}

	return nil
}

func resolveSignerKey(override ...*ecdsa.PublicKey) (*ecdsa.PublicKey, error) {
	return resolveKey(SignerProductionPublicKey, override...)
}

func resolveTLSFetcherKey(override ...*ecdsa.PublicKey) (*ecdsa.PublicKey, error) {
	return resolveKey(ProductionTLSFetcherSigningPublicKey, override...)
}

func resolveKey(productionKeyHex string, override ...*ecdsa.PublicKey) (*ecdsa.PublicKey, error) {
	if len(override) > 0 && override[0] != nil {
		return override[0], nil
	}

	keyBytes, err := hex.DecodeString(productionKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode production signer key: %w", err)
	}

	return ToECDSAPublic(keyBytes)
}

func decodeKey(privateKey, keyFormat string) ([]byte, error) {
	switch keyFormat {
	case KeyFormatSolana:
		decoded := tkencoding.Bs58Decode(privateKey)
		if len(decoded) != 64 {
			return nil, fmt.Errorf("invalid key length. Expected 64 bytes. Got %d", len(decoded))
		}

		return decoded[:32], nil
	case KeyFormatHexadecimal, "":
		return hex.DecodeString(strings.TrimPrefix(privateKey, "0x"))
	default:
		return nil, fmt.Errorf("invalid key format: %q", keyFormat)
	}
}
