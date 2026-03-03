// Package main demonstrates the OTP enclave authentication flow.
//
// Security model:
// The OTP code and client public key are HPKE-encrypted together to Turnkey's TLS Fetcher
// enclave before being sent to the server. This ensures that even a compromised auth proxy
// or backend cannot substitute its own public key — only a party who knows the OTP
// code can bind a public key to the resulting verification token.
//
// Flow:
//  1. Client generates a P256 keypair — the persistent session credential (stored in
//     IndexedDB or equivalent secure storage in a real client).
//  2. Backend calls INIT_OTP → receives otpID and an enclave-signed encryption target bundle.
//  3. User receives the OTP code out-of-band (email).
//  4. Client HPKE-encrypts {otp_code, client_public_key} to the enclave's bundle.
//     Only the resulting ciphertext is transmitted — neither value crosses the network in plaintext.
//  5. Backend calls VERIFY_OTP with the encrypted bundle → enclave issues a verificationToken
//     bound to the client public key.
//  6. Client signs a TokenUsage{LOGIN} message with its private key, proving ownership.
//  7. Backend calls OTP_LOGIN with the verificationToken, client public key, and ClientSignature
//     → receives a session JWT embedding the client public key.
//  8. Session JWT signature is verified against the production notarizer public key.
//
// Usage:
//
//	go run main.go -api-private-key "your_api_private_key" -parent-org-id "parent_org_id" -sub-org-id "sub_org_id" -email "user@example.com"
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	sdk "github.com/tkhq/go-sdk"
	"github.com/tkhq/go-sdk/pkg/api/client/sessions"
	"github.com/tkhq/go-sdk/pkg/api/client/user_verification"
	"github.com/tkhq/go-sdk/pkg/api/models"
	"github.com/tkhq/go-sdk/pkg/apikey"
	"github.com/tkhq/go-sdk/pkg/crypto"
	"github.com/tkhq/go-sdk/pkg/enclave_encrypt"
	"github.com/tkhq/go-sdk/pkg/util"
)

var (
	apiPrivateKey string
	parentOrgID   string
	subOrgID      string
	emailAddress  string
)

func init() {
	flag.StringVar(&apiPrivateKey, "api-private-key", "", "Turnkey API private key for authentication")
	flag.StringVar(&parentOrgID, "parent-org-id", "", "parent organization ID")
	flag.StringVar(&subOrgID, "sub-org-id", "", "sub-organization ID for login")
	flag.StringVar(&emailAddress, "email", "", "email address to receive OTP")
}

func main() {
	flag.Parse()

	if apiPrivateKey == "" || parentOrgID == "" || subOrgID == "" || emailAddress == "" {
		log.Println("Missing required flags: -api-private-key, -parent-org-id, -sub-org-id, and -email are required")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	client, err := initClient()
	if err != nil {
		return err
	}

	// Step 1: Send OTP — returns the otpID and the enclave-signed encryption target bundle.
	// The bundle contains the enclave's ephemeral HPKE public key for this session.
	otpID, encryptionTargetBundle, err := sendOTP(client)
	if err != nil {
		return fmt.Errorf("failed to send OTP: %w", err)
	}
	fmt.Println("OTP sent to your email.")

	// Step 2: Generate a P256 client keypair.
	// This is the single credential used for the entire flow:
	//   a) Its public key is HPKE-encrypted together with the OTP code and sent to VERIFY_OTP,
	//      so the enclave issues a verificationToken tied to this key.
	//   b) Its private key signs the TokenUsage{LOGIN} message in OTP_LOGIN, proving ownership.
	//   c) Its public key becomes the session credential embedded in the resulting JWT.
	// In a real client this key would be stored in IndexedDB (or equivalent secure storage).
	clientPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate client keypair: %w", err)
	}
	clientAPIKey, err := apikey.FromECDSAPrivateKey(clientPrivKey, apikey.SchemeP256)
	if err != nil {
		return fmt.Errorf("failed to derive API key from client keypair: %w", err)
	}
	clientPubHex := clientAPIKey.TkPublicKey

	// Step 3: Prompt the user for the OTP code received out-of-band.
	fmt.Print("Enter the OTP code: ")
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read OTP code: %w", err)
	}
	otpCode := strings.TrimSpace(input)

	// Step 4: Verify the OTP.
	// The OTP code and client public key are HPKE-encrypted before being sent — only the
	// resulting ciphertext (EncryptedOtpBundle) is transmitted; neither value crosses the
	// network in plaintext.
	verificationToken, err := verifyOTP(client, otpID, otpCode, encryptionTargetBundle, clientPubHex)
	if err != nil {
		return fmt.Errorf("OTP verification failed: %w", err)
	}
	fmt.Println("OTP verified successfully.")

	// Step 5: Log in using the verification token and a signed client payload.
	err = loginOTP(client, verificationToken, clientPrivKey, clientPubHex)
	if err != nil {
		return fmt.Errorf("OTP login failed: %w", err)
	}
	fmt.Println("OTP login successful.")

	return nil
}

func initClient() (*sdk.Client, error) {
	apiKey, err := apikey.FromTurnkeyPrivateKey(apiPrivateKey, apikey.SchemeP256)
	if err != nil {
		return nil, fmt.Errorf("failed to create API key: %w", err)
	}

	client, err := sdk.New(sdk.WithAPIKey(apiKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create SDK client: %w", err)
	}

	return client, nil
}

// sendOTP initiates an OTP flow for the configured email address.
// Returns:
//   - otpID: identifies this OTP session, passed to VERIFY_OTP.
//   - encryptionTargetBundle: an enclave-signed JSON bundle containing the enclave's
//     ephemeral HPKE public key, used to encrypt the OTP attempt client-side.
func sendOTP(client *sdk.Client) (otpID, encryptionTargetBundle string, err error) {
	otpType := "OTP_TYPE_EMAIL"

	params := user_verification.NewInitOtpParams().WithBody(&models.InitOtpRequest{
		TimestampMs:    util.RequestTimestamp(),
		OrganizationID: util.StringPointer(parentOrgID),
		Type:           util.StringPointer(models.InitOtpRequestTypeACTIVITYTYPEINITOTPV3),
		Parameters: &models.InitOtpIntentV3{
			AppName: util.StringPointer("Example App"),
			Contact: util.StringPointer(emailAddress),
			OtpType: &otpType,
		},
	})

	reply, err := client.V0().UserVerification.InitOtp(params, client.Authenticator)
	if err != nil {
		return "", "", fmt.Errorf("INIT_OTP request failed: %w", err)
	}

	result := reply.Payload.Activity.Result.InitOtpResultV2
	if result.OtpID == nil {
		return "", "", fmt.Errorf("otpID missing from INIT_OTP response")
	}
	if result.OtpEncryptionTargetBundle == nil {
		return "", "", fmt.Errorf("encryptionTargetBundle missing from INIT_OTP response")
	}

	return *result.OtpID, *result.OtpEncryptionTargetBundle, nil
}

// otpAttemptBundle is the plaintext HPKE-encrypted to the enclave during VERIFY_OTP.
// Binding otp_code and public_key together inside the ciphertext ensures a malicious
// proxy cannot swap the public key without knowing the OTP code.
type otpAttemptBundle struct {
	OtpCode   string `json:"otp_code"`
	PublicKey string `json:"public_key"`
}

// verifyOTP submits the OTP attempt to the enclave.
//
// encryptionTargetBundle is a signed JSON envelope returned by INIT_OTP. It contains
// an ephemeral HPKE public key (targetPublic) generated fresh by the TLS Fetcher enclave
// for this session, signed with the enclave's quorum key. The client verifies that
// signature (against the pinned ProductionTLSFetcherSigningPublicKey) before encrypting,
// ensuring the key came from the genuine enclave and not a compromised proxy.
//
// The OTP code and client public key are then HPKE-encrypted to targetPublic so that
// only the enclave can decrypt them — neither value is visible to the backend in transit.
// Returns the verificationToken issued by the enclave on success.
func verifyOTP(client *sdk.Client, otpID, otpCode, encryptionTargetBundle, clientPubHex string) (string, error) {
	signerKeyBytes, err := hex.DecodeString(crypto.ProductionTLSFetcherSigningPublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode TLS Fetcher signing key: %w", err)
	}
	signerKey, err := enclave_encrypt.ToEcdsaPublic(signerKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse TLS Fetcher signing key: %w", err)
	}

	encryptClient, err := enclave_encrypt.NewEnclaveEncryptClient(signerKey)
	if err != nil {
		return "", fmt.Errorf("failed to create enclave encrypt client: %w", err)
	}

	plaintext, err := json.Marshal(otpAttemptBundle{
		OtpCode:   otpCode,
		PublicKey: clientPubHex,
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal OTP attempt bundle: %w", err)
	}

	// Encrypt the attempt bundle to the enclave's TEK. The enclave decrypts this,
	// verifies the OTP code, and issues a verificationToken bound to clientPubHex.
	clientSendMsg, err := encryptClient.Encrypt(plaintext, []byte(encryptionTargetBundle), parentOrgID, "")
	if err != nil {
		return "", fmt.Errorf("failed to HPKE-encrypt OTP attempt: %w", err)
	}

	encryptedBundle, err := json.Marshal(clientSendMsg)
	if err != nil {
		return "", fmt.Errorf("failed to serialize encrypted bundle: %w", err)
	}

	params := user_verification.NewVerifyOtpParams().WithBody(&models.VerifyOtpRequest{
		TimestampMs:    util.RequestTimestamp(),
		OrganizationID: util.StringPointer(parentOrgID),
		Type:           util.StringPointer(models.VerifyOtpRequestTypeACTIVITYTYPEVERIFYOTPV2),
		Parameters: &models.VerifyOtpIntentV2{
			OtpID:              &otpID,
			EncryptedOtpBundle: util.StringPointer(string(encryptedBundle)),
		},
	})

	reply, err := client.V0().UserVerification.VerifyOtp(params, client.Authenticator)
	if err != nil {
		return "", fmt.Errorf("VERIFY_OTP request failed: %w", err)
	}

	token := reply.Payload.Activity.Result.VerifyOtpResult.VerificationToken
	if token == nil {
		return "", fmt.Errorf("verificationToken missing from VERIFY_OTP response")
	}

	return *token, nil
}

// ParseVerificationTokenID extracts the token ID from a Turnkey verification token (JWT).
// The token ID is needed to construct the TokenUsage payload signed in OTP_LOGIN.
func ParseVerificationTokenID(verificationToken string) (string, error) {
	parts := strings.Split(verificationToken, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid verification token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode token payload: %w", err)
	}

	var claims struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("failed to parse token claims: %w", err)
	}
	if claims.ID == "" {
		return "", fmt.Errorf("id claim missing from verification token")
	}

	return claims.ID, nil
}

// loginOTP completes authentication by:
//  1. Building a TokenUsage{LOGIN} payload that binds the client public key to the
//     verification token ID, then signing it with clientPrivKey.
//  2. Calling OTP_LOGIN with the verificationToken, client public key, and ClientSignature.
//
// The ClientSignature proves the caller holds the private key that was bound to the OTP
// attempt during VERIFY_OTP, preventing a compromised backend from hijacking the session.
// The client public key is embedded in the resulting session JWT.
func loginOTP(client *sdk.Client, verificationToken string, clientPrivKey *ecdsa.PrivateKey, clientPubHex string) error {
	tokenID, err := ParseVerificationTokenID(verificationToken)
	if err != nil {
		return fmt.Errorf("failed to parse verification token: %w", err)
	}

	// Sign TokenUsage{LOGIN} with the client key to prove ownership.
	// This prevents the backend from substituting a different public key.
	loginType := models.UsageTypeLogin
	tokenUsage := models.TokenUsage{
		TokenID: &tokenID,
		Type:    &loginType,
		Login:   &models.LoginUsage{PublicKey: &clientPubHex},
	}

	tokenUsageJSON, err := json.Marshal(tokenUsage)
	if err != nil {
		return fmt.Errorf("failed to marshal TokenUsage: %w", err)
	}

	hash := sha256.Sum256(tokenUsageJSON)
	r, s, err := ecdsa.Sign(rand.Reader, clientPrivKey, hash[:])
	if err != nil {
		return fmt.Errorf("failed to sign TokenUsage: %w", err)
	}

	// Encode as r||s, each zero-padded to 32 bytes.
	rb, sb := r.Bytes(), s.Bytes()
	rb32, sb32 := make([]byte, 32), make([]byte, 32)
	copy(rb32[32-len(rb):], rb)
	copy(sb32[32-len(sb):], sb)
	sigHex := hex.EncodeToString(append(rb32, sb32...))

	scheme := models.ClientSignatureSchemeAPIP256
	clientSig := &models.ClientSignature{
		Scheme:    &scheme,
		PublicKey: &clientPubHex,
		Message:   util.StringPointer(string(tokenUsageJSON)),
		Signature: &sigHex,
	}

	params := sessions.NewOtpLoginParams().WithBody(&models.OtpLoginRequest{
		TimestampMs:    util.RequestTimestamp(),
		OrganizationID: util.StringPointer(subOrgID),
		Type:           util.StringPointer(models.OtpLoginRequestTypeACTIVITYTYPEOTPLOGINV2),
		Parameters: &models.OtpLoginIntentV2{
			VerificationToken: &verificationToken,
			PublicKey:         &clientPubHex,
			ClientSignature:   clientSig,
		},
	})

	reply, err := client.V0().Sessions.OtpLogin(params, client.Authenticator)
	if err != nil {
		return fmt.Errorf("OTP_LOGIN request failed: %w", err)
	}

	sessionJWT := reply.Payload.Activity.Result.OtpLoginResult.Session
	if sessionJWT == nil {
		return fmt.Errorf("session JWT missing from OTP_LOGIN response")
	}

	fmt.Printf("Session JWT: %s\n", *sessionJWT)

	if err := crypto.VerifySessionJwtSignature(*sessionJWT); err != nil {
		return fmt.Errorf("failed to verify session JWT signature: %w", err)
	}
	fmt.Println("Session JWT signature verified.")

	return nil
}
