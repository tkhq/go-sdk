// Package main demonstrates a wallet import from menmonic
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"

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

	signerKey, err := hexToPublicKey(encryptionkey.SignerProductionPublicKey)

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

	// Perform import activity
	importParams := wallets.NewImportWalletParams().WithBody(&models.ImportWalletRequest{
		OrganizationID: &organizationId,
		Parameters: &models.ImportWalletIntent{
			UserID: &userId,
			Accounts: []*models.WalletAccountParams{
				{
					AddressFormat: models.AddressFormatSolana.Pointer(),
					Curve:         models.CurveEd25519.Pointer(),
					Path:          util.StringPointer("m/44'/60'/1'/0/0"),
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

// Convert a hex-encoded string to an ECDSA P-256 public key.
// This key is used in encryption and decryption of data transferred to
// and from Turnkey secure enclaves.
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
