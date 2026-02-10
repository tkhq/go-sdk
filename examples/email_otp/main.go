// Package main demonstrates email OTP authentication flow
//
// Usage:
//
//	go run main.go -api-private-key "your_api_private_key" -parent-org-id "parent_org_id" -sub-org-id "sub_org_id" -email "user@example.com"
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/tkhq/go-sdk"
	"github.com/tkhq/go-sdk/pkg/api/client/sessions"
	"github.com/tkhq/go-sdk/pkg/api/client/user_verification"
	"github.com/tkhq/go-sdk/pkg/api/models"
	"github.com/tkhq/go-sdk/pkg/apikey"
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

	// Validate required flags
	if apiPrivateKey == "" || parentOrgID == "" || subOrgID == "" || emailAddress == "" {
		log.Fatal("Missing required flags: -api-private-key, -parent-org-id, -sub-org-id, and -email are required")
	}

	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	// Initialize the Turnkey API client
	client, err := initClient()
	if err != nil {
		return err
	}

	// Step 1: Send OTP
	otpID, err := sendOTP(client)
	if err != nil {
		return fmt.Errorf("failed to send OTP: %w", err)
	}
	fmt.Println("OTP sent to your email.")

	// Step 2: Prompt for OTP code
	fmt.Print("Enter the OTP code: ")
	reader := bufio.NewReader(os.Stdin)
	code, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read OTP code: %w", err)
	}
	code = strings.TrimSpace(code)

	// Step 3: Verify OTP
	token, err := verifyOTP(client, otpID, code)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}
	fmt.Println("OTP verified successfully.")

	// Step 4: Login using the verification token
	err = loginOTP(client, token)
	if err != nil {
		return fmt.Errorf("login with OTP failed: %w", err)
	}
	fmt.Println("OTP login successful")

	return nil
}

func initClient() (*sdk.Client, error) {
	apiKey, err := apikey.FromTurnkeyPrivateKey(apiPrivateKey, apikey.SchemeP256)
	if err != nil {
		return nil, fmt.Errorf("failed to create API key: %w", err)
	}

	client, err := sdk.New(sdk.WithAPIKey(apiKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create new SDK client: %w", err)
	}

	return client, nil
}

func sendOTP(client *sdk.Client) (string, error) {
	otpType := "OTP_TYPE_EMAIL"

	params := user_verification.NewInitOtpParams().WithBody(&models.InitOtpRequest{
		TimestampMs:    util.RequestTimestamp(),
		OrganizationID: util.StringPointer(parentOrgID),
		Type:           (*string)(models.ActivityTypeInitOtp.Pointer()),
		Parameters: &models.InitOtpIntentV2{
			AppName: util.StringPointer("Example App"),
			Contact: util.StringPointer(emailAddress),
			OtpType: &otpType,
		},
	})

	reply, err := client.V0().UserVerification.InitOtp(params, client.Authenticator)
	if err != nil {
		return "", fmt.Errorf("send OTP request failed: %w", err)
	}

	otpID := reply.Payload.Activity.Result.InitOtpResult.OtpID
	if otpID == nil {
		return "", fmt.Errorf("otpID is nil in response")
	}
	return *otpID, nil
}

func verifyOTP(client *sdk.Client, id, code string) (string, error) {
	params := user_verification.NewVerifyOtpParams().WithBody(&models.VerifyOtpRequest{
		TimestampMs:    util.RequestTimestamp(),
		OrganizationID: util.StringPointer(parentOrgID),
		Type:           (*string)(models.ActivityTypeVerifyOtp.Pointer()),
		Parameters: &models.VerifyOtpIntent{
			OtpCode: &code,
			OtpID:   &id,
		},
	})

	reply, err := client.V0().UserVerification.VerifyOtp(params, client.Authenticator)
	if err != nil {
		return "", fmt.Errorf("failed to verify OTP: %w", err)
	}

	token := reply.Payload.Activity.Result.VerifyOtpResult.VerificationToken
	if token == nil {
		return "", fmt.Errorf("verification token is nil")
	}

	fmt.Printf("Verification Token: %s\n", *token)
	return *token, nil
}

func loginOTP(client *sdk.Client, token string) error {

	// Mock a client-side P256 API key, in reality this would be passed from your frontend
	clientApiKey, err := apikey.New(parentOrgID)
	if err != nil {
		return fmt.Errorf("failed to generate user API key: %w", err)
	}

	params := sessions.NewOtpLoginParams().WithBody(&models.OtpLoginRequest{
		TimestampMs:    util.RequestTimestamp(),
		OrganizationID: util.StringPointer(subOrgID), // target sub-org id
		Type:           (*string)(models.ActivityTypeOtpLogin.Pointer()),
		Parameters: &models.OtpLoginIntent{
			VerificationToken: &token,
			PublicKey:         &clientApiKey.TkPublicKey,
		},
	})

	reply, err := client.V0().Sessions.OtpLogin(params, client.Authenticator)
	if err != nil {
		return fmt.Errorf("failed to verify OTP: %w", err)
	}

	sessionJwt := reply.Payload.Activity.Result.OtpLoginResult.Session
	if sessionJwt == nil {
		return fmt.Errorf("session jwt is nil")
	}

	fmt.Printf("Session jwt token: %s\n", *sessionJwt)
	return nil
}
