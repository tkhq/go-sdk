// Package main demonstrates an API client which signs a raw payload with a wallet account
package main

import (
	"fmt"
	"log"

	"github.com/tkhq/go-sdk"
	"github.com/tkhq/go-sdk/pkg/api/client/signing"
	"github.com/tkhq/go-sdk/pkg/api/models"
	"github.com/tkhq/go-sdk/pkg/util"
)

func main() {
	// NB: make sure to create and register an API key, first.
	client, err := sdk.New(sdk.WithAPIKeyName("default"))
	if err != nil {
		log.Fatal("failed to create new SDK client:", err)
	}

	// you could use https://build.tx.xyz/ to generate an Ethereum unsignedTransaction string
	unsignedTransaction := "<unisgned_transaction_here>"
	walletAccountAddress := "<account_address_here>"

	params := signing.NewSignRawPayloadParams().WithBody(&models.SignRawPayloadRequest{
		OrganizationID: client.DefaultOrganization(),
		TimestampMs:    util.RequestTimestamp(),
		Parameters: &models.SignRawPayloadIntentV2{
			Encoding:     models.PayloadEncodingHexadecimal.Pointer(),
			HashFunction: models.HashFunctionKeccak256.Pointer(),
			Payload:      &unsignedTransaction,
			SignWith:     &walletAccountAddress,
		},
		Type: (*string)(models.ActivityTypeSignRawPayloadV2.Pointer()),
	})

	signResp, err := client.V0().Signing.SignRawPayload(params, client.Authenticator)
	if err != nil {
		log.Fatal("failed to make Sign Raw Payload request:", err)
	}

	fmt.Printf("Signed raw payload:\nR: %v\nS: %v\nV: %v\n",
		*signResp.Payload.Activity.Result.SignRawPayloadResult.R,
		*signResp.Payload.Activity.Result.SignRawPayloadResult.S,
		*signResp.Payload.Activity.Result.SignRawPayloadResult.V,
	)
}
