package main

import (
	"bufio"
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
	tkPrivateKey = "<private_key_here>"
	parentOrgID  = "<parent_org_id>"
	subOrgID     = "<sub_org_id>"
	emailAddress = "<email_address>"
	client       *sdk.Client
)

func main() {

	// Initialize the Turnkey API client
	initClient()

	// Step 1: Send OTP
	otpID, err := sendOTP()
	if err != nil {
		log.Fatalf("failed to send OTP: %v", err)
	}
	fmt.Println("OTP sent to your email.")

	// Step 2: Prompt for OTP code
	fmt.Print("Enter the OTP code: ")
	reader := bufio.NewReader(os.Stdin)
	code, _ := reader.ReadString('\n')
	code = strings.TrimSpace(code)

	// Step 3: Verify OTP
	token, err := verifyOTP(otpID, code)
	if err != nil {
		log.Fatalf("Verification failed: %v", err)
	}
	fmt.Println("OTP verified successfully.")

	// Step 4: Login using the verification token
	err = loginOTP(token)
	if err != nil {
		log.Fatalf("Login with OTP failed: %v", err)
	}
	fmt.Println("OTP login successfull")
}

func initClient() {
	apiKey, err := apikey.FromTurnkeyPrivateKey(tkPrivateKey, apikey.SchemeP256)
	if err != nil {
		log.Fatalf("failed to create API key: %v", err)
	}

	c, err := sdk.New(sdk.WithAPIKey(apiKey))
	if err != nil {
		log.Fatalf("failed to create new SDK client: %v", err)
	}

	client = c
}

func sendOTP() (string, error) {
	otpType := "OTP_TYPE_EMAIL"

	params := user_verification.NewInitOtpParams().WithBody(&models.InitOtpRequest{
		TimestampMs:    util.RequestTimestamp(),
		OrganizationID: util.StringPointer(parentOrgID),
		Type:           (*string)(models.ActivityTypeInitOtp.Pointer()),
		Parameters: &models.InitOtpIntent{
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

func verifyOTP(id, code string) (string, error) {
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

func loginOTP(token string) error {

	// Mock a client-side P256 API key, in reality this would be passed from your frontend
	clientApiKey, err := apikey.New(parentOrgID)
	if err != nil {
		log.Fatalf("failed to generate user API key: %s", err)
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
