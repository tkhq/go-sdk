// Package main demonstrates an API client which creates new wallet accounts.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	turnkey "github.com/tkhq/go-sdk/v2"
)

func main() {
	apiPrivateKey := os.Getenv("TURNKEY_API_PRIVATE_KEY")
	if apiPrivateKey == "" {
		log.Fatal("TURNKEY_API_PRIVATE_KEY is required")
	}
	organizationID := os.Getenv("TURNKEY_ORGANIZATION_ID")
	if organizationID == "" {
		log.Fatal("TURNKEY_ORGANIZATION_ID is required")
	}

	stamper, err := turnkey.NewAPIKeyStamper(apiPrivateKey)
	if err != nil {
		log.Fatal("failed to create stamper:", err)
	}

	client, err := turnkey.NewClient(stamper, organizationID)
	if err != nil {
		log.Fatal("failed to create Turnkey client:", err)
	}

	walletid := os.Getenv("TURNKEY_WALLET_ID")
	if walletid == "" {
		log.Fatal("TURNKEY_WALLET_ID is required")
	}

	result, err := client.CreateWalletAccounts(context.Background(), turnkey.CreateWalletAccountsRequest{
		WalletID: walletid,
		Accounts: []turnkey.WalletAccountParams{
			{
				AddressFormat: turnkey.AddressFormatEthereum,
				Curve:         turnkey.CurveSecp256K1,
				Path:          "m/44'/60'/0'/0/0",
				PathFormat:    turnkey.PathFormatBip32,
			},
		},
	})
	if err != nil {
		var reqErr *turnkey.RequestError
		if errors.As(err, &reqErr) {
			log.Fatalf("failed to create wallet accounts (status=%d): %s", reqErr.StatusCode, reqErr.Body)
		}
		log.Fatal("failed to create wallet accounts:", err)
	}

	fmt.Printf("Wallet ID: %s\n", walletid)
	fmt.Printf("Addresses: %v\n", result.Addresses)
}
