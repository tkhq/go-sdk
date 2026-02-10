// Package main demonstrates a Secp256k1 or Ed25519 private key import
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"

	"github.com/btcsuite/btcutil/base58"

	"github.com/tkhq/go-sdk"
	"github.com/tkhq/go-sdk/pkg/api/client/private_keys"
	"github.com/tkhq/go-sdk/pkg/api/models"
	"github.com/tkhq/go-sdk/pkg/apikey"
	"github.com/tkhq/go-sdk/pkg/enclave_encrypt"
	"github.com/tkhq/go-sdk/pkg/encryptionkey"
	"github.com/tkhq/go-sdk/pkg/util"
)

func main() {

	// Only set one of the hexEncodedPrivateKey or solanaEncodedPrivateKey; the other should stay empty
	hexEncodedPrivateKey := ""    // Ethereum
	solanaEncodedPrivateKey := "" // Solana base58-encoded private key

	var addressFormat models.AddressFormat
	var importedKey []byte
	var err error

	switch {
	case hexEncodedPrivateKey != "":
		addressFormat = models.AddressFormatEthereum

		importedKey, err = hex.DecodeString(hexEncodedPrivateKey)
		if err != nil {
			log.Fatalf("Failed to decode Ethereum private key: %v", err)
		}

	case solanaEncodedPrivateKey != "":
		addressFormat = models.AddressFormatSolana

		decoded := base58.Decode(solanaEncodedPrivateKey)
		if len(decoded) < 32 {
			log.Fatalf("Decoded Solana private key is too short")
		}
		importedKey = decoded[:32]

	default:
		log.Fatal("No private key provided")
	}

	privateKeyID, err := ImportPrivateKey(importedKey, addressFormat)
	if err != nil {
		log.Fatalf("Failed to import private key: %v", err)
	}

	fmt.Println("Private Key ID:", *privateKeyID)
}

// setupClient creates and returns an SDK client
func setupClient(apiPrivateKey string) (*sdk.Client, error) {
	apiKey, err := apikey.FromTurnkeyPrivateKey(apiPrivateKey, apikey.SchemeP256)
	if err != nil {
		return nil, fmt.Errorf("failed to create API key: %w", err)
	}

	client, err := sdk.New(sdk.WithAPIKey(apiKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create SDK client: %w", err)
	}

	return client, nil
}

// setupEncryptClient creates and returns an enclave encrypt client
func setupEncryptClient(userId, organizationId string) (*enclave_encrypt.EnclaveEncryptClient, error) {
	encryptionKey, err := encryptionkey.New(userId, organizationId)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption key: %w", err)
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

// getImportBundle initializes the import and returns the import bundle
func getImportBundle(client *sdk.Client, organizationId, userId string) (string, error) {
	initImportParams := private_keys.NewInitImportPrivateKeyParams().WithBody(&models.InitImportPrivateKeyRequest{
		OrganizationID: &organizationId,
		Parameters: &models.InitImportPrivateKeyIntent{
			UserID: &userId,
		},
		TimestampMs: util.RequestTimestamp(),
		Type:        (*string)(models.ActivityTypeInitImportPrivateKey.Pointer()),
	})

	reply, err := client.V0().PrivateKeys.InitImportPrivateKey(initImportParams, client.Authenticator)
	if err != nil {
		return "", fmt.Errorf("init import request failed: %w", err)
	}

	return *reply.Payload.Activity.Result.InitImportPrivateKeyResult.ImportBundle, nil
}

// encryptPrivateKey encrypts the private key and returns the encrypted bundle
func encryptPrivateKey(encryptClient *enclave_encrypt.EnclaveEncryptClient, importedKey []byte, importBundle, organizationId, userId string) (string, error) {
	clientSendMsg, err := encryptClient.Encrypt(importedKey, []byte(importBundle), organizationId, userId)
	if err != nil {
		return "", fmt.Errorf("unable to encrypt private key to target: %w", err)
	}

	encryptedBundle, err := json.Marshal(clientSendMsg)
	if err != nil {
		return "", fmt.Errorf("failed to convert clientSendMsg into encryptedBundle: %w", err)
	}

	return string(encryptedBundle), nil
}

// getCurveForAddressFormat returns the appropriate curve for the given address format
func getCurveForAddressFormat(addressFormat models.AddressFormat) *models.Curve {
	switch addressFormat {
	case models.AddressFormatEthereum:
		return models.CurveSecp256k1.Pointer()
	case models.AddressFormatSolana:
		return models.CurveEd25519.Pointer()
	default:
		return nil
	}
}

// ImportPrivateKey is a helper that executes a private key import for a hex-encoded Ethereum or Solana private key in a compatible address format.
// Returns the resulting private key ID
func ImportPrivateKey(importedKey []byte, addressFormat models.AddressFormat) (*string, error) {
	// Organization ID, user ID and API private key
	organizationId := "<orgId>"
	userId := "<user_from_orgId>"
	apiPrivateKey := "<private_key_here>"

	client, err := setupClient(apiPrivateKey)
	if err != nil {
		return nil, err
	}

	encryptClient, err := setupEncryptClient(userId, organizationId)
	if err != nil {
		return nil, err
	}

	importBundle, err := getImportBundle(client, organizationId, userId)
	if err != nil {
		return nil, err
	}

	encryptedBundle, err := encryptPrivateKey(encryptClient, importedKey, importBundle, organizationId, userId)
	if err != nil {
		return nil, err
	}

	curve := getCurveForAddressFormat(addressFormat)

	// Perform import
	importParams := private_keys.NewImportPrivateKeyParams().WithBody(&models.ImportPrivateKeyRequest{
		OrganizationID: &organizationId,
		Parameters: &models.ImportPrivateKeyIntent{
			UserID:          &userId,
			AddressFormats:  []models.AddressFormat{addressFormat},
			EncryptedBundle: util.StringPointer(encryptedBundle),
			Curve:           curve,
			PrivateKeyName:  util.StringPointer("New Test Private Key"),
		},
		TimestampMs: util.RequestTimestamp(),
		Type:        (*string)(models.ActivityTypeImportPrivateKey.Pointer()),
	})

	importReply, err := client.V0().PrivateKeys.ImportPrivateKey(importParams, client.Authenticator)
	if err != nil {
		return nil, fmt.Errorf("import private key request failed: %w", err)
	}

	return importReply.Payload.Activity.Result.ImportPrivateKeyResult.PrivateKeyID, nil
}
