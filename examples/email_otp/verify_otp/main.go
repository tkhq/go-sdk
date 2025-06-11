package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/tkhq/go-sdk"
	"github.com/tkhq/go-sdk/pkg/api/client/user_verification"
	"github.com/tkhq/go-sdk/pkg/api/models"
	"github.com/tkhq/go-sdk/pkg/apikey"
	"github.com/tkhq/go-sdk/pkg/util"
)

func main() {
	var otpID string
	var otpCode string

	flag.StringVar(&otpID, "id", "", "OTP ID")
	flag.StringVar(&otpCode, "code", "", "OTP code")
	flag.Parse()

	if otpID == "" || otpCode == "" {
		log.Fatalf("Usage: go run main.go --id <otp-id> --code <otp-code>")
	}

	err := verifyOTP(otpID, otpCode)
	if err != nil {
		log.Fatalf("Verification failed: %v", err)
	}

	fmt.Println("OTP verified successfully.")
}

func verifyOTP(id, code string) error {

	tkPrivateKey := "<private_key_here>"

	apiKey, err := apikey.FromTurnkeyPrivateKey(tkPrivateKey, apikey.SchemeP256)
	if err != nil {
		log.Fatal("failed to create API key: %w", err)
	}

	client, err := sdk.New(sdk.WithAPIKey(apiKey))
	if err != nil {
		log.Fatal("failed to create new SDK client:", err)
	}

	// Returns a `verificationToken`, which is required for creating sessions via the `otpLogin` action.
	params := user_verification.NewVerifyOtpParams().WithBody(&models.VerifyOtpRequest{
		TimestampMs:    util.RequestTimestamp(),
		OrganizationID: util.StringPointer("<parent_org_id>"),
		Type:           (*string)(models.ActivityTypeVerifyOtp.Pointer()),
		Parameters: &models.VerifyOtpIntent{
			OtpCode: &code,
			OtpID:   &id,
		},
	})

	reply, err := client.V0().UserVerification.VerifyOtp(params, client.Authenticator)
	if err != nil {
		return fmt.Errorf("failed to verify OTP: %w", err)
	}

	token := reply.Payload.Activity.Result.VerifyOtpResult.VerificationToken
	if token == nil {
		return fmt.Errorf("verification token is nil")
	}

	fmt.Printf("Verification Token: %s\n", *token)
	return nil
}
