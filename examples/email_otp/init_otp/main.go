package main

import (
	"fmt"
	"log"

	"github.com/tkhq/go-sdk"
	"github.com/tkhq/go-sdk/pkg/api/client/user_verification"
	"github.com/tkhq/go-sdk/pkg/api/models"
	"github.com/tkhq/go-sdk/pkg/apikey"
	"github.com/tkhq/go-sdk/pkg/util"
)

func main() {
	otpID, err := sendOTP()
	if err != nil {
		log.Fatalf("failed to send OTP: %v", err)
	}

	fmt.Printf("OTP ID: %s\n", otpID)
}

func sendOTP() (string, error) {
	fmt.Println("Sending OTP...")

	tkPrivateKey := "<private_key_here>"

	apiKey, err := apikey.FromTurnkeyPrivateKey(tkPrivateKey, apikey.SchemeP256)
	if err != nil {
		log.Fatal("failed to create API key: %w", err)
	}

	client, err := sdk.New(sdk.WithAPIKey(apiKey))
	if err != nil {
		log.Fatal("failed to create new SDK client:", err)
	}

	otpType := "OTP_TYPE_EMAIL"

	// No longer requires a suborganization ID
	// OTPs can now be sent directly under a parent organization's context to any email or phone number
	params := user_verification.NewInitOtpParams().WithBody(&models.InitOtpRequest{
		TimestampMs:    util.RequestTimestamp(),
		OrganizationID: util.StringPointer("<parent_org_id>"),
		Type:           (*string)(models.ActivityTypeInitOtp.Pointer()),
		Parameters: &models.InitOtpIntent{
			Contact: util.StringPointer("<email_address>"),
			OtpType: &otpType,
		},
	})

	reply, err := client.V0().UserVerification.InitOtp(params, client.Authenticator)
	if err != nil {
		log.Fatal("send OTP request failed:", err)
	}

	otpID := reply.Payload.Activity.Result.InitOtpResult.OtpID
	return *otpID, nil
}
