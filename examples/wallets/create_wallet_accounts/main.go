// Package main demonstrates an API client which creates new wallet accounts.
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

	path := "m/44'/60'/0'/0/0"
	// replace the <Wallet ID> below
	walletid := "<Wallet ID>"

	timestamp := time.Now().UnixMilli()
	timestampString := strconv.FormatInt(timestamp, 10)

	params := wallets.NewCreateWalletAccountsParams().WithBody(&models.CreateWalletAccountsRequest{
		OrganizationID: client.DefaultOrganization(),
		Parameters: &models.CreateWalletAccountsIntent{
			WalletID: &walletid,
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
		Type:        (*string)(models.ActivityTypeCreateWalletAccounts.Pointer()),
	})

	resp, err := client.V0().Wallets.CreateWalletAccounts(params, client.Authenticator)
	if err != nil {
		log.Fatal("failed to make Wallets CreateWalletAccounts request:", err)
	}

	fmt.Printf("New wallet account: %v\n", resp.Payload.Activity.Result.CreateWalletAccountsResult.Addresses[0])
}
