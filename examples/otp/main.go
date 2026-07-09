// Package main demonstrates the OTP enclave authentication flow.
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/tkhq/go-sdk/crypto"
	turnkey "github.com/tkhq/go-sdk/v2"
)

//nolint:cyclop,gocyclo
func main() {
	apiPrivateKey := os.Getenv("TURNKEY_API_PRIVATE_KEY")
	if apiPrivateKey == "" {
		log.Fatal("TURNKEY_API_PRIVATE_KEY is required")
	}
	parentOrgID := os.Getenv("TURNKEY_ORGANIZATION_ID")
	if parentOrgID == "" {
		log.Fatal("TURNKEY_ORGANIZATION_ID is required")
	}
	subOrgID := os.Getenv("TURNKEY_SUB_ORGANIZATION_ID")
	if subOrgID == "" {
		log.Fatal("TURNKEY_SUB_ORGANIZATION_ID is required")
	}
	emailAddress := os.Getenv("TURNKEY_EMAIL")
	if emailAddress == "" {
		log.Fatal("TURNKEY_EMAIL is required")
	}

	ctx := context.Background()

	stamper, err := turnkey.NewAPIKeyStamper(apiPrivateKey)
	if err != nil {
		log.Fatal("failed to create stamper:", err)
	}
	client, err := turnkey.NewClient(stamper, parentOrgID)
	if err != nil {
		log.Fatal("failed to create SDK client:", err)
	}

	otpResult, err := client.InitOTP(ctx, turnkey.InitOTPRequest{
		AppName: "Example App",
		Contact: emailAddress,
		OTPType: "OTP_TYPE_EMAIL",
	})
	if err != nil {
		log.Fatal("INIT_OTP failed:", err)
	}
	if otpResult.OTPID == "" {
		log.Fatal("otpID missing from INIT_OTP response")
	}
	if otpResult.OTPEncryptionTargetBundle == "" {
		log.Fatal("encryptionTargetBundle missing from INIT_OTP response")
	}
	fmt.Println("OTP sent to your email.")

	clientPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal("failed to generate client keypair:", err)
	}
	clientAPIKey, err := crypto.FromECDSAPrivateKey(clientPrivKey, crypto.SchemeP256)
	if err != nil {
		log.Fatal("failed to derive API key from client keypair:", err)
	}
	clientPubHex := clientAPIKey.TkPublicKey

	fmt.Print("Enter the OTP code: ")
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		log.Fatal("failed to read OTP code:", err)
	}
	otpCode := strings.TrimSpace(input)

	encryptedOTPBundle, err := crypto.EncryptOtpCodeToBundle(otpCode, otpResult.OTPEncryptionTargetBundle, clientPubHex)
	if err != nil {
		log.Fatal("failed to encrypt OTP bundle:", err)
	}
	verifyResult, err := client.VerifyOTP(ctx, turnkey.VerifyOTPRequest{
		OTPID:              otpResult.OTPID,
		EncryptedOTPBundle: encryptedOTPBundle,
	})
	if err != nil {
		log.Fatal("VERIFY_OTP failed:", err)
	}
	if verifyResult.VerificationToken == "" {
		log.Fatal("verificationToken missing from VERIFY_OTP response")
	}
	fmt.Println("OTP verified successfully.")

	verificationToken := verifyResult.VerificationToken

	parts := strings.Split(verificationToken, ".")
	if len(parts) != 3 {
		log.Fatal("invalid verification token format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		log.Fatal("failed to decode token payload:", err)
	}
	var claims struct {
		ID string `json:"id"`
	}
	if err = json.Unmarshal(payload, &claims); err != nil {
		log.Fatal("failed to parse token claims:", err)
	}
	if claims.ID == "" {
		log.Fatal("id claim missing from verification token")
	}

	tokenUsage := turnkey.TokenUsage{
		TokenID:   claims.ID,
		TypeValue: turnkey.UsageTypeLogin,
		Login: &turnkey.LoginUsage{
			PublicKey: clientPubHex,
		},
	}
	tokenUsageJSON, err := json.Marshal(tokenUsage)
	if err != nil {
		log.Fatal("failed to marshal TokenUsage:", err)
	}

	hash := sha256.Sum256(tokenUsageJSON)
	r, s, err := ecdsa.Sign(rand.Reader, clientPrivKey, hash[:])
	if err != nil {
		log.Fatal("failed to sign message:", err)
	}
	rBytes, sBytes := r.Bytes(), s.Bytes()
	rPadded, sPadded := make([]byte, 32), make([]byte, 32)
	copy(rPadded[32-len(rBytes):], rBytes)
	copy(sPadded[32-len(sBytes):], sBytes)
	sigHex := fmt.Sprintf("%x%x", rPadded, sPadded)

	loginResult, err := client.OTPLogin(ctx, turnkey.OTPLoginRequest{
		OrganizationID:    subOrgID,
		VerificationToken: verificationToken,
		PublicKey:         clientPubHex,
		ClientSignature: turnkey.ClientSignature{
			Scheme:    turnkey.ClientSignatureSchemeApip256,
			PublicKey: clientPubHex,
			Message:   string(tokenUsageJSON),
			Signature: sigHex,
		},
	})
	if err != nil {
		log.Fatal("OTP_LOGIN failed:", err)
	}
	if loginResult.Session == "" {
		log.Fatal("session JWT missing from OTP_LOGIN response")
	}
	fmt.Println("OTP login successful.")
	fmt.Printf("Session JWT: %s\n", loginResult.Session)

	if err = crypto.VerifySessionJwtSignature(loginResult.Session); err != nil {
		log.Fatal("failed to verify session JWT signature:", err)
	}
	fmt.Println("Session JWT signature verified.")
}
