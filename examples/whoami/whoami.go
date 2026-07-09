// Package main demonstrates an API client which returns the UserID of its API key.
package main

import (
	"context"
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

	stamper, err := turnkey.NewAPIKeyStamper(apiPrivateKey)
	if err != nil {
		log.Fatal("failed to create stamper:", err)
	}

	client, err := turnkey.NewClient(stamper, organizationID)
	if err != nil {
		log.Fatal("failed to create Turnkey client:", err)
	}

	resp, err := client.GetWhoami(context.Background(), turnkey.GetWhoamiRequest{})
	if err != nil {
		log.Fatal("failed to get whoami:", err)
	}

	fmt.Printf("UserID: %s\n", resp.UserID)
}
