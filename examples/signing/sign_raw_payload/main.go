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

	// Example raw payload (hex for "hello world")
	rawPayload := "68656c6c6f20776f726c64"

	stamper, err := turnkey.NewAPIKeyStamper(apiPrivateKey)
	if err != nil {
		log.Fatal("failed to create stamper:", err)
	}

	client, err := turnkey.NewClient(stamper, organizationID)
	if err != nil {
		log.Fatal("failed to create Turnkey client:", err)
	}

	result, err := client.SignRawPayload(context.Background(), turnkey.SignRawPayloadRequest{
		Encoding:     turnkey.PayloadEncodingHexadecimal,
		HashFunction: turnkey.HashFunctionKeccak256,
		Payload:      rawPayload,
		SignWith:     signWith,
	})
	if err != nil {
		var reqErr *turnkey.RequestError
		if errors.As(err, &reqErr) {
			log.Fatalf("failed to sign transaction (status=%d): %s", reqErr.StatusCode, reqErr.Body)
		}
		log.Fatal("failed to sign transaction:", err)
	}

	fmt.Printf("Signature r=%s s=%s v=%s\n", result.R, result.S, result.V)
}
