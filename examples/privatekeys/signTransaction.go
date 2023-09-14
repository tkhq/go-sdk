// Package main demonstrates an API client which returns the UserID of its API key.
package main

import (
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/tkhq/go-sdk"
	"github.com/tkhq/go-sdk/pkg/api/client/private_keys"

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

	pkParams := private_keys.NewPublicAPIServiceSignTransactionParams().WithBody(&models.V1SignTransactionRequest{
		OrganizationID: client.DefaultOrganization(),
		TimestampMs:    &timestampString,
		Parameters: &models.V1SignTransactionIntent{
			PrivateKeyID:        &privateKeyID,
			Type:                models.Immutableactivityv1TransactionTypeTRANSACTIONTYPEETHEREUM.Pointer(),
			UnsignedTransaction: &unsignedTransaction,
		},
		Type: (*string)(models.V1ActivityTypeACTIVITYTYPESIGNTRANSACTION.Pointer()),
	})

	signResp, err := client.V0().PrivateKeys.PublicAPIServiceSignTransaction(pkParams, client.Authenticator)
	if err != nil {
		log.Fatal("failed to make PrivateKeys SignTransaction request:", err)
	}

	fmt.Printf("Signed tx: %v\n", *signResp.Payload.Activity.Result.SignTransactionResult.SignedTransaction)
}
