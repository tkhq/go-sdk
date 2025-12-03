// Package main demonstrates a wallet import from menmonic
package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/tkhq/go-sdk"
	"github.com/tkhq/go-sdk/pkg/api/client/wallets"
	"github.com/tkhq/go-sdk/pkg/api/models"
	"github.com/tkhq/go-sdk/pkg/apikey"
	"github.com/tkhq/go-sdk/pkg/enclave_encrypt"
	"github.com/tkhq/go-sdk/pkg/encryptionkey"
	"github.com/tkhq/go-sdk/pkg/util"
)

func main() {
	// Insert the wallet mnemonic you want to import
	mnemonic := "<your_mnemonic_here>"

	// Organization ID, user ID and API private key
	organizationId := "<orgId>"
	userId := "<user_from_orgId>"
	apiPrivateKey := "<private_key_here>"

	// Generate a new key pair used to encrypt the export bundle
	encryptionKey, err := encryptionkey.New(userId, organizationId)
	if err != nil {
		log.Fatal("creating encryption key: %w", err)
	}

	// API key used by the client
	apiKey, err := apikey.FromTurnkeyPrivateKey(apiPrivateKey, apikey.SchemeP256)
	if err != nil {
		log.Fatal("creating API key: %w", err)
	}

	client, err := sdk.New(sdk.WithAPIKey(apiKey))
	if err != nil {
		log.Fatal("creating SDK client: %w", err)
	}

	signerKey, err := util.HexToPublicKey(encryptionkey.SignerProductionPublicKey)
	if err != nil {
		log.Fatal("failed to convert the public key")
	}

	// Get the private key
	tkPrivateKey := encryptionKey.GetPrivateKey()

	kemPrivateKey, err := encryptionkey.DecodeTurnkeyPrivateKey(tkPrivateKey)
	if err != nil {
		log.Fatal("failed to decode encryption private key")
	}

	// Set up enclave encrypt client
	encryptClient, err := enclave_encrypt.NewEnclaveEncryptClientFromTargetKey(signerKey, *kemPrivateKey)
	if err != nil {
		log.Fatal("failed to setup enclave encrypt client")
	}

	// Init import activity, this produces an import bundle, containing a public key and signature.
	// These artifacts will be used in the next step to ensure that key material is only accessible by Turnkey, and cannot be extracted by any man-in-the-middle (MITM)
	initImportParams := wallets.NewInitImportWalletParams().WithBody(&models.InitImportWalletRequest{
		OrganizationID: &organizationId,
		Parameters: &models.InitImportWalletIntent{
			UserID: &userId,
		},
		TimestampMs: util.RequestTimestamp(),
		Type:        (*string)(models.ActivityTypeInitImportWallet.Pointer()),
	})

	reply, err := client.V0().Wallets.InitImportWallet(initImportParams, client.Authenticator)
	if err != nil {
		log.Fatal("init import request failed: %w", err)
	}

	importBundle := *reply.Payload.Activity.Result.InitImportWalletResult.ImportBundle

	clientSendMsg, err := encryptClient.Encrypt([]byte(mnemonic), []byte(importBundle), organizationId, userId)
	if err != nil {
		log.Fatal("unable to encrypt wallet to target: %w", err)
	}

	encryptedBundle, err := json.Marshal(clientSendMsg)
	if err != nil {
		log.Fatal("failed to encrypt bundle: %w", err)
	}

	// For other HD wallet paths see https://docs.turnkey.com/concepts/wallets#hd-wallet-default-paths
	path := "m/44'/60'/1'/0/0"

	// Perform import activity
	importParams := wallets.NewImportWalletParams().WithBody(&models.ImportWalletRequest{
		OrganizationID: &organizationId,
		Parameters: &models.ImportWalletIntent{
			UserID: &userId,
			Accounts: []*models.WalletAccountParams{
				{
					AddressFormat: models.AddressFormatSolana.Pointer(),
					Curve:         models.CurveEd25519.Pointer(),
					Path:          util.StringPointer(path),
					PathFormat:    models.PathFormatBip32.Pointer(),
				},
			},
			EncryptedBundle: util.StringPointer(string(encryptedBundle)),
			WalletName:      util.StringPointer("New Test Wallet"),
		},
		TimestampMs: util.RequestTimestamp(),
		Type:        (*string)(models.ActivityTypeImportWallet.Pointer()),
	})

	importReply, err := client.V0().Wallets.ImportWallet(importParams, client.Authenticator)
	if err != nil {
		log.Fatal("import wallet request failed: %w", err)
	}

	fmt.Println("Imported walletId:", *importReply.Payload.Activity.Result.ImportWalletResult.WalletID)
}
