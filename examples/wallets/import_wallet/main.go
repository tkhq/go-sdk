// Package main demonstrates a wallet import from menmonic
//
// Usage:
//   go run main.go -mnemonic "your mnemonic phrase" -org-id "org_id" -user-id "user_id" -api-private-key "api_private_key"
package main

import (
	"encoding/json"
	"flag"
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

var (
	mnemonic      string
	organizationID string
	userID         string
	apiPrivateKey  string
)

func init() {
	flag.StringVar(&mnemonic, "mnemonic", "", "wallet mnemonic to import")
	flag.StringVar(&organizationID, "org-id", "", "organization ID for the wallet import")
	flag.StringVar(&userID, "user-id", "", "user ID within the organization")
	flag.StringVar(&apiPrivateKey, "api-private-key", "", "Turnkey API private key for authentication")
}

// setupEncryptionClient sets up the encryption key and enclave encrypt client
func setupEncryptionClient(userId, organizationId string) (*enclave_encrypt.EnclaveEncryptClient, error) {
	encryptionKey, err := encryptionkey.New(userId, organizationId)
	if err != nil {
		return nil, fmt.Errorf("creating encryption key: %w", err)
	}

	signerKey, err := util.HexToPublicKey(encryptionkey.SignerProductionPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert the public key: %w", err)
	}

	tkPrivateKey := encryptionKey.GetPrivateKey()
	kemPrivateKey, err := encryptionkey.DecodeTurnkeyPrivateKey(tkPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encryption private key: %w", err)
	}

	encryptClient, err := enclave_encrypt.NewEnclaveEncryptClientFromTargetKey(signerKey, *kemPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to setup enclave encrypt client: %w", err)
	}

	return encryptClient, nil
}

// initWalletImport initializes the wallet import and returns the import bundle
func initWalletImport(client *sdk.Client, organizationId, userId string) (string, error) {
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
		return "", fmt.Errorf("init import request failed: %w", err)
	}

	return *reply.Payload.Activity.Result.InitImportWalletResult.ImportBundle, nil
}

// encryptMnemonic encrypts the mnemonic and returns the encrypted bundle as a string
func encryptMnemonic(encryptClient *enclave_encrypt.EnclaveEncryptClient, mnemonic, importBundle, organizationId, userId string) (string, error) {
	clientSendMsg, err := encryptClient.Encrypt([]byte(mnemonic), []byte(importBundle), organizationId, userId)
	if err != nil {
		return "", fmt.Errorf("unable to encrypt wallet to target: %w", err)
	}

	encryptedBundle, err := json.Marshal(clientSendMsg)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt bundle: %w", err)
	}

	return string(encryptedBundle), nil
}

func main() {
	flag.Parse()

	// Validate required flags
	if mnemonic == "" || organizationID == "" || userID == "" || apiPrivateKey == "" {
		log.Fatal("Missing required flags: -mnemonic, -org-id, -user-id, and -api-private-key are required")
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

	encryptClient, err := setupEncryptionClient(userID, organizationID)
	if err != nil {
		log.Fatal(err)
	}

	// Init import activity, this produces an import bundle, containing a public key and signature.
	// These artifacts will be used in the next step to ensure that key material is only accessible by Turnkey, and cannot be extracted by any man-in-the-middle (MITM)
	importBundle, err := initWalletImport(client, organizationID, userID)
	if err != nil {
		log.Fatal(err)
	}

	encryptedBundle, err := encryptMnemonic(encryptClient, mnemonic, importBundle, organizationID, userID)
	if err != nil {
		log.Fatal(err)
	}

	// For other HD wallet paths see https://docs.turnkey.com/concepts/wallets#hd-wallet-default-paths
	path := "m/44'/60'/1'/0/0"

	// Generate a unique name with timestamp
	walletName := fmt.Sprintf("Test Wallet %s", util.RequestTimestamp())

	// Perform import activity
	importParams := wallets.NewImportWalletParams().WithBody(&models.ImportWalletRequest{
		OrganizationID: &organizationID,
		Parameters: &models.ImportWalletIntent{
			UserID: &userID,
			Accounts: []*models.WalletAccountParams{
				{
					AddressFormat: models.AddressFormatSolana.Pointer(),
					Curve:         models.CurveEd25519.Pointer(),
					Path:          util.StringPointer(path),
					PathFormat:    models.PathFormatBip32.Pointer(),
				},
			},
			EncryptedBundle: util.StringPointer(encryptedBundle),
			WalletName:      util.StringPointer(walletName),
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
