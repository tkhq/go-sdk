// Package main demonstrates the strict OTP signup flow.
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

//nolint:gocyclo
func main() {
	apiPrivateKey := os.Getenv("TURNKEY_API_PRIVATE_KEY")
	if apiPrivateKey == "" {
		log.Fatal("TURNKEY_API_PRIVATE_KEY is required")
	}
	parentOrganizationID := os.Getenv("TURNKEY_ORGANIZATION_ID")
	if parentOrganizationID == "" {
		log.Fatal("TURNKEY_ORGANIZATION_ID is required")
	}
	emailAddress := os.Getenv("TURNKEY_EMAIL")
	if emailAddress == "" {
		log.Fatal("TURNKEY_EMAIL is required")
	}
	subOrganizationName := os.Getenv("TURNKEY_SUB_ORGANIZATION_NAME")
	if subOrganizationName == "" {
		log.Fatal("TURNKEY_SUB_ORGANIZATION_NAME is required")
	}

	ctx := context.Background()

	stamper, err := turnkey.NewAPIKeyStamper(apiPrivateKey)
	if err != nil {
		log.Fatal("failed to create stamper:", err)
	}
	client, err := turnkey.NewClient(stamper, parentOrganizationID)
	if err != nil {
		log.Fatal("failed to create SDK client:", err)
	}

	otpResult, err := client.InitOTP(ctx, turnkey.InitOTPRequest{
		AppName: "OTP Signup Example",
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

	clientPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal("failed to generate client keypair:", err)
	}
	clientAPIKey, err := crypto.FromECDSAPrivateKey(clientPrivateKey, crypto.SchemeP256)
	if err != nil {
		log.Fatal("failed to derive API key from client keypair:", err)
	}
	clientPublicKey := clientAPIKey.TkPublicKey

	fmt.Print("Enter the OTP code: ")
	otpCode, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		log.Fatal("failed to read OTP code:", err)
	}

	encryptedOTPBundle, err := crypto.EncryptOtpCodeToBundle(
		strings.TrimSpace(otpCode),
		otpResult.OTPEncryptionTargetBundle,
		clientPublicKey,
	)
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
	tokenID, err := verificationTokenID(verificationToken)
	if err != nil {
		log.Fatal("failed to read verification token ID:", err)
	}

	disableEmailAuth := false
	disableEmailRecovery := false
	disableOTPEmailAuth := false
	disableSMSAuth := false
	signupRequest := turnkey.CreateSubOrganizationRequest{
		OrganizationID:      parentOrganizationID,
		SubOrganizationName: subOrganizationName,
		RootQuorumThreshold: 1,
		RootUsers: []turnkey.RootUserParamsV5{
			{
				UserName:  "OTP Signup User",
				UserEmail: &emailAddress,
				APIKeys: []turnkey.APIKeyParamsV2{
					{
						APIKeyName: "OTP Signup API Key",
						CurveType:  turnkey.APIKeyCurveP256,
						PublicKey:  clientPublicKey,
					},
				},
				Authenticators: []turnkey.AuthenticatorParamsV2{},
				OAuthProviders: []turnkey.OAuthProviderParamsV2{},
			},
		},
		VerificationToken:    &verificationToken,
		DisableEmailAuth:     &disableEmailAuth,
		DisableEmailRecovery: &disableEmailRecovery,
		DisableOTPEmailAuth:  &disableOTPEmailAuth,
		DisableSmsAuth:       &disableSMSAuth,
	}

	tokenUsageJSON, signature, err := marshalAndSignTokenUsage(
		clientPrivateKey,
		tokenUsageForOTPSignup(tokenID, signupRequest),
	)
	if err != nil {
		log.Fatal("failed to sign TokenUsage:", err)
	}
	signupRequest.ClientSignature = &turnkey.ClientSignature{
		Scheme:    turnkey.ClientSignatureSchemeApip256,
		PublicKey: clientPublicKey,
		Message:   string(tokenUsageJSON),
		Signature: signature,
	}

	result, err := client.CreateSubOrganization(ctx, signupRequest)
	if err != nil {
		log.Fatal("CREATE_SUB_ORGANIZATION failed:", err)
	}
	if result.SubOrganizationID == "" {
		log.Fatal("subOrganizationID missing from CREATE_SUB_ORGANIZATION response")
	}
	fmt.Printf("Created sub-organization: %s\n", result.SubOrganizationID)
}

// tokenUsageForOTPSignup binds an OTP signup signature to the exact request fields.
func tokenUsageForOTPSignup(tokenID string, request turnkey.CreateSubOrganizationRequest) turnkey.TokenUsage {
	return turnkey.TokenUsage{
		TokenID:   tokenID,
		TypeValue: turnkey.UsageTypeSignup,
		SignupV3: &turnkey.SignupUsageV3{
			ParentOrganizationID: request.OrganizationID,
			SubOrganizationName:  request.SubOrganizationName,
			RootUsers:            request.RootUsers,
			RootQuorumThreshold:  request.RootQuorumThreshold,
			Wallet:               request.Wallet,
			DisableEmailAuth:     request.DisableEmailAuth,
			DisableEmailRecovery: request.DisableEmailRecovery,
			DisableOTPEmailAuth:  request.DisableOTPEmailAuth,
			DisableSmsAuth:       request.DisableSmsAuth,
		},
	}
}

func verificationTokenID(verificationToken string) (string, error) {
	parts := strings.Split(verificationToken, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid verification token format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode token payload: %w", err)
	}
	var claims struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("parse token claims: %w", err)
	}
	if claims.ID == "" {
		return "", fmt.Errorf("id claim missing from verification token")
	}

	return claims.ID, nil
}

// marshalAndSignTokenUsage signs the exact JSON message with a raw P-256 r||s signature.
func marshalAndSignTokenUsage(privateKey *ecdsa.PrivateKey, tokenUsage turnkey.TokenUsage) ([]byte, string, error) {
	tokenUsageJSON, err := json.Marshal(tokenUsage)
	if err != nil {
		return nil, "", err
	}

	hash := sha256.Sum256(tokenUsageJSON)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, "", err
	}
	rBytes, sBytes := r.Bytes(), s.Bytes()
	rPadded, sPadded := make([]byte, 32), make([]byte, 32)
	copy(rPadded[32-len(rBytes):], rBytes)
	copy(sPadded[32-len(sBytes):], sBytes)

	return tokenUsageJSON, fmt.Sprintf("%x%x", rPadded, sPadded), nil
}
