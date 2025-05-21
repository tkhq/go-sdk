package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"strconv"
	"time"

	"github.com/tkhq/go-sdk/pkg/enclave_encrypt"
	"github.com/tkhq/go-sdk/pkg/encryptionkey"

	"github.com/tkhq/go-sdk"
	"github.com/tkhq/go-sdk/pkg/api/client/wallets"
	"github.com/tkhq/go-sdk/pkg/api/models"
	"github.com/tkhq/go-sdk/pkg/apikey"
)

func main() {

	organizationId := "<wallet_orgId>"
	userId := "<user_from_orgId>"

	// Generate a new key pair used to encrypt the export bundle
	encryptionKey, err := encryptionkey.New(userId, organizationId)
	if err != nil {
		log.Fatal("creating encryption key: %w", err)
	}

	targetPublicKey := encryptionKey.GetPublicKey()

	// API key used by the client
	apiKey, err := apikey.FromTurnkeyPrivateKey("<api_private_key_here>", apikey.SchemeP256)

	if err != nil {
		log.Fatal("creating API key: %w", err)
	}

	client, err := sdk.New(sdk.WithAPIKey(apiKey))
	if err != nil {
		log.Fatal("creating SDK client: %w", err)
	}

	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
	address := "<wallet_account_address_to_export>"

	params := wallets.NewExportWalletAccountParams().WithBody(&models.ExportWalletAccountRequest{
		Type:           (*string)(models.ActivityTypeExportWalletAccount.Pointer()),
		TimestampMs:    &timestamp,
		OrganizationID: &organizationId,
		Parameters: &models.ExportWalletAccountIntent{
			Address:         &address,
			TargetPublicKey: &targetPublicKey,
		},
	})

	result, err := client.V0().Wallets.ExportWalletAccount(params, client.Authenticator)
	if err != nil {
		log.Fatal("export wallet account: %w", err)
	}

	exportBundle := *result.Payload.Activity.Result.ExportWalletAccountResult.ExportBundle

	// Get the private key
	tkPrivateKey := encryptionKey.GetPrivateKey()
	kemPrivateKey, err := encryptionkey.DecodeTurnkeyPrivateKey(tkPrivateKey)
	if err != nil {
		log.Fatal("failed to decode encryption private key")
	}

	// Turnkey Signer enclave's quorum public key
	signerProductionPublicKey := "04cf288fe433cc4e1aa0ce1632feac4ea26bf2f5a09dcfe5a42c398e06898710330f0572882f4dbdf0f5304b8fc8703acd69adca9a4bbf7f5d00d20a5e364b2569"
	signerKey, err := hexToPublicKey(signerProductionPublicKey)
	if err != nil {
		log.Fatal("failed to convert the public key")
	}

	// set up enclave encrypt client
	encryptClient, err := enclave_encrypt.NewEnclaveEncryptClientFromTargetKey(signerKey, *kemPrivateKey)
	if err != nil {
		log.Fatal("failed to setup enclave encrypt client")
	}

	// decrypt exportBundle
	plaintextBytes, err := encryptClient.Decrypt([]byte(exportBundle), organizationId)
	if err != nil {
		log.Fatal("failed to decrypt")
	}

	fmt.Println("Decrypted private key (hex):", hex.EncodeToString(plaintextBytes))
}

// Convert a hex-encoded string to an ECDSA P-256 public key
func hexToPublicKey(hexString string) (*ecdsa.PublicKey, error) {
	publicKeyBytes, err := hex.DecodeString(hexString)
	if err != nil {
		return nil, err
	}

	// second half is the public key bytes for the enclave quorum encryption key
	if len(publicKeyBytes) != 65 {
		return nil, fmt.Errorf("invalid public key length. Expected 65 bytes but got %d (hex string: \"%s\")", len(publicKeyBytes), publicKeyBytes)
	}

	// init curve instance
	curve := elliptic.P256()

	// curve's bitsize converted to length in bytes
	byteLen := (curve.Params().BitSize + 7) / 8

	// ensure the public key bytes have the correct length
	if len(publicKeyBytes) != 1+2*byteLen {
		return nil, fmt.Errorf("invalid encryption public key length")
	}

	// extract X and Y coordinates from the public key bytes
	// ignore first byte (prefix)
	x := new(big.Int).SetBytes(publicKeyBytes[1 : 1+byteLen])
	y := new(big.Int).SetBytes(publicKeyBytes[1+byteLen:])

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}
