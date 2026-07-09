package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	turnkey "github.com/tkhq/go-sdk/v2"
)

func main() {
	apiPrivateKey := os.Getenv("TURNKEY_API_PRIVATE_KEY")
	if apiPrivateKey == "" {
		log.Fatal("TURNKEY_API_PRIVATE_KEY is required")
	}
	organizationID := os.Getenv("TURNKEY_ORGANIZATION_ID")
	if organizationID == "" {
		log.Fatal("TURNKEY_ORGANIZATION_ID is required")
	}
	signWith := os.Getenv("TURNKEY_SIGN_WITH") // wallet address or key ID
	if signWith == "" {
		log.Fatal("TURNKEY_SIGN_WITH is required")
	}
	// EIP-1559 unsigned transaction sending 0 ETH to the zero address on mainnet.
	unsignedTx := "02e8018084773594008506fc23ac0082520894e2e30c19e1a60db94926e9763074be21e7e4402a8080c0"

	stamper, err := turnkey.NewAPIKeyStamper(apiPrivateKey)
	if err != nil {
		log.Fatal("failed to create stamper:", err)
	}

	client, err := turnkey.NewClient(stamper, organizationID)
	if err != nil {
		log.Fatal("failed to create Turnkey client:", err)
	}

	result, err := client.SignTransaction(context.Background(), turnkey.SignTransactionRequest{
		SignWith:            signWith,
		TypeValue:           turnkey.TransactionTypeEthereum,
		UnsignedTransaction: unsignedTx,
	})
	if err != nil {
		var reqErr *turnkey.RequestError
		if errors.As(err, &reqErr) {
			log.Fatalf("failed to sign transaction (status=%d): %s", reqErr.StatusCode, reqErr.Body)
		}
		log.Fatal("failed to sign transaction:", err)
	}

	fmt.Printf("Signed transaction: %s\n", result.SignedTransaction)
}
