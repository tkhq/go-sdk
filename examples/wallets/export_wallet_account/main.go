// Package main demonstrates exporting a wallet account's private key via the Turnkey enclave export flow.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/tkhq/go-sdk/crypto"
	turnkey "github.com/tkhq/go-sdk/v2"
)

func main() {
	apiPrivateKey := mustEnv("TURNKEY_API_PRIVATE_KEY")
	organizationID := mustEnv("TURNKEY_ORGANIZATION_ID")
	address := mustEnv("TURNKEY_ADDRESS")

	stamper, err := turnkey.NewAPIKeyStamper(apiPrivateKey)
	if err != nil {
		log.Fatal("failed to create stamper:", err)
	}

	client, err := turnkey.NewClient(stamper, organizationID)
	if err != nil {
		log.Fatal("failed to create Turnkey client:", err)
	}

	ctx := context.Background()

	targetPublicKey, kemPrivateKey, err := crypto.GenerateEncryptionKeyPair()
	if err != nil {
		log.Fatal("failed to generate encryption key:", err)
	}

	result, err := client.ExportWalletAccount(ctx, turnkey.ExportWalletAccountRequest{
		Address:         address,
		TargetPublicKey: targetPublicKey,
	})
	if err != nil {
		fatalRequestError(err, "export wallet account")
	}

	privateKeyBytes, err := crypto.DecryptExportBundle([]byte(result.ExportBundle), organizationID, kemPrivateKey)
	if err != nil {
		log.Fatal("failed to decrypt export bundle:", err)
	}

	fmt.Printf("Address: %s\n", result.Address)
	fmt.Printf("Private key (hex): %s\n", hex.EncodeToString(privateKeyBytes))
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
