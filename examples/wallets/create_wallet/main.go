// Package main demonstrates an API client which creates a new wallet with a wallet account.
package main

import (
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/tkhq/go-sdk"
	"github.com/tkhq/go-sdk/pkg/api/client/wallets"
	"github.com/tkhq/go-sdk/pkg/api/models"
)

func main() {
	// NB: make sure to create and register an API key, first.
	client, err := sdk.New(sdk.WithAPIKeyName("default"))
	if err != nil {
		log.Fatal("failed to create new SDK client:", err)
	}

	walletName := "New Wallet"
	path := "m/44'/60'/0'/0/0"

	timestamp := time.Now().UnixMilli()
	timestampString := strconv.FormatInt(timestamp, 10)

	params := wallets.NewCreateWalletParams().WithBody(&models.CreateWalletRequest{
		OrganizationID: client.DefaultOrganization(),
		Parameters: &models.CreateWalletIntent{
			WalletName: &walletName,
			Accounts: []*models.WalletAccountParams{
				{
					AddressFormat: models.AddressFormatEthereum.Pointer(),
					Curve:         models.CurveSecp256k1.Pointer(),
					Path:          &path,
					PathFormat:    models.PathFormatBip32.Pointer(),
				},
			},
		},
		TimestampMs: &timestampString,
		Type:        (*string)(models.ActivityTypeCreateWallet.Pointer()),
	})

	resp, err := client.V0().Wallets.CreateWallet(params, client.Authenticator)
	if err != nil {
		log.Fatal("failed to make Wallets CreateWallet request:", err)
	}

	fmt.Printf("New wallet: %v\n", resp.Payload.Activity.Result.CreateWalletResult.WalletID)
}
