// Package main demonstrates importing a raw private key (Secp256k1 or Ed25519).
//
// Set exactly one of TURNKEY_ETHEREUM_PRIVATE_KEY (hex-encoded) or
// TURNKEY_SOLANA_PRIVATE_KEY (base58-encoded). The key is encrypted client-side
// before being sent — Turnkey's enclave decrypts it and stores it. The plaintext
// private key is never transmitted.
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

	ethereumKey := os.Getenv("TURNKEY_ETHEREUM_PRIVATE_KEY")
	solanaKey := os.Getenv("TURNKEY_SOLANA_PRIVATE_KEY")

	// Select the key material and its matching curve / address / key format.
	var (
		privateKey    string
		keyFormat     string
		curve         turnkey.Curve
		addressFormat turnkey.AddressFormat
	)
	switch {
	case ethereumKey != "" && solanaKey != "":
		log.Fatal("set only one of TURNKEY_ETHEREUM_PRIVATE_KEY or TURNKEY_SOLANA_PRIVATE_KEY")
	case ethereumKey != "":
		privateKey = ethereumKey
		keyFormat = crypto.KeyFormatHexadecimal
		curve = turnkey.CurveSecp256K1
		addressFormat = turnkey.AddressFormatEthereum
	case solanaKey != "":
		privateKey = solanaKey
		keyFormat = crypto.KeyFormatSolana
		curve = turnkey.CurveEd25519
		addressFormat = turnkey.AddressFormatSolana
	default:
		log.Fatal("set one of TURNKEY_ETHEREUM_PRIVATE_KEY or TURNKEY_SOLANA_PRIVATE_KEY")
	}

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

	initResult, err := client.InitImportPrivateKey(ctx, turnkey.InitImportPrivateKeyRequest{
		UserID: whoami.UserID,
	})
	if err != nil {
		fatalRequestError(err, "init import private key")
	}

	encryptedBundle, err := crypto.EncryptPrivateKeyToBundle(privateKey, keyFormat, initResult.ImportBundle, organizationID, whoami.UserID)
	if err != nil {
		log.Fatal("failed to encrypt private key:", err)
	}

	privateKeyName := fmt.Sprintf("Imported Private Key %d", time.Now().UnixMilli())

	importResult, err := client.ImportPrivateKey(ctx, turnkey.ImportPrivateKeyRequest{
		UserID:          whoami.UserID,
		PrivateKeyName:  privateKeyName,
		EncryptedBundle: encryptedBundle,
		Curve:           curve,
		AddressFormats:  []turnkey.AddressFormat{addressFormat},
	})
	if err != nil {
		fatalRequestError(err, "import private key")
	}

	fmt.Printf("Private Key ID: %s\n", importResult.PrivateKeyID)
	for _, addr := range importResult.Addresses {
		if addr.Address == nil {
			continue
		}
		fmt.Printf("Address: %s\n", *addr.Address)
	}
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
