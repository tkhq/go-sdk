// Package main demonstrates an API client which signs a raw payload with a private key ID or wallet account.
package main

import (
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/tkhq/go-sdk"
	"github.com/tkhq/go-sdk/pkg/api/client/signing"
	"github.com/tkhq/go-sdk/pkg/api/models"
)

func main() {
	// NB: make sure to create and register an API key, first.
	client, err := sdk.New("default")
	if err != nil {
		log.Fatal("failed to create new SDK client:", err)
	}

	timestamp := time.Now().UnixMilli()
	timestampString := strconv.FormatInt(timestamp, 10)

	var privateKeyID string
	var unsignedTransaction string // no 0x prefix necessary

	pkParams := signing.NewSignTransactionParams().WithBody(&models.SignTransactionRequest{
		OrganizationID: client.DefaultOrganization(),
		TimestampMs:    &timestampString,
		Parameters: &models.SignTransactionIntentV2{
			SignWith:            &privateKeyID,
			Type:                models.TransactionTypeEthereum.Pointer(),
			UnsignedTransaction: &unsignedTransaction,
		},
		Type: (*string)(models.ActivityTypeSignTransactionV2.Pointer()),
	})

	signResp, err := client.V0().Signing.SignTransaction(pkParams, client.Authenticator)
	if err != nil {
		log.Fatal("failed to make PrivateKeys SignTransaction request:", err)
	}

	fmt.Printf("Signed tx: %v\n", *signResp.Payload.Activity.Result.SignTransactionResult.SignedTransaction)
}
