// Package main demonstrates importing a wallet from a mnemonic phrase.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/tkhq/go-sdk/crypto"
	turnkey "github.com/tkhq/go-sdk/v2"
)

func main() {
	apiPrivateKey := mustEnv("TURNKEY_API_PRIVATE_KEY")
	organizationID := mustEnv("TURNKEY_ORGANIZATION_ID")
	mnemonic := mustEnv("TURNKEY_MNEMONIC")

	stamper, err := turnkey.NewAPIKeyStamper(apiPrivateKey)
	if err != nil {
		log.Fatal("failed to create stamper:", err)
	}

	client, err := turnkey.NewClient(stamper, organizationID)
	if err != nil {
		log.Fatal("failed to create Turnkey client:", err)
	}

	ctx := context.Background()

	whoami, err := client.GetWhoami(ctx, turnkey.GetWhoamiRequest{})
	if err != nil {
		log.Fatal("failed to get whoami:", err)
	}

	initResult, err := client.InitImportWallet(ctx, turnkey.InitImportWalletRequest{
		UserID: whoami.UserID,
	})
	if err != nil {
		fatalRequestError(err, "init import wallet")
	}

	encryptedBundle, err := crypto.EncryptWalletToBundle(mnemonic, initResult.ImportBundle, organizationID, whoami.UserID)
	if err != nil {
		log.Fatal("failed to encrypt mnemonic:", err)
	}

	walletName := fmt.Sprintf("Imported Wallet %d", time.Now().UnixMilli())

	importResult, err := client.ImportWallet(ctx, turnkey.ImportWalletRequest{
		UserID:          whoami.UserID,
		WalletName:      walletName,
		EncryptedBundle: encryptedBundle,
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
		fatalRequestError(err, "import wallet")
	}

	fmt.Printf("Wallet ID: %s\n", importResult.WalletID)
	fmt.Printf("Addresses: %v\n", importResult.Addresses)
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("%s is required", key)
	}
	return v
}

func fatalRequestError(err error, action string) {
	var reqErr *turnkey.RequestError
	if errors.As(err, &reqErr) {
		log.Fatalf("failed to %s (status=%d): %s", action, reqErr.StatusCode, reqErr.Body)
	}
	log.Fatalf("failed to %s: %v", action, err)
}
