// Package main demonstrates an API client which creates a new wallet with a wallet account.
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

	result, err := client.CreateWallet(context.Background(), turnkey.CreateWalletRequest{
		WalletName: "New Wallet",
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
			log.Fatalf("failed to create wallet (status=%d): %s", reqErr.StatusCode, reqErr.Body)
		}
		log.Fatal("failed to create wallet:", err)
	}

	fmt.Printf("Wallet ID: %s\n", result.WalletID)
	fmt.Printf("Addresses: %v\n", result.Addresses)
}
