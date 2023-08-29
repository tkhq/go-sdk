// Package main demonstrates an API client which returns the UserID of its API key.
package main

import (
	"fmt"
	"log"

	"github.com/tkhq/go-sdk"
	"github.com/tkhq/go-sdk/pkg/api/client/who_am_i"
	"github.com/tkhq/go-sdk/pkg/api/models"
)

func main() {
	// NB: make sure to create and register an API key, first.
	client, err := sdk.New("")
	if err != nil {
		log.Fatal("failed to create new SDK client:", err)
	}

	p := who_am_i.NewPublicAPIServiceGetWhoamiParams().WithBody(&models.V1GetWhoamiRequest{
		OrganizationID: client.DefaultOrganization(),
	})

	resp, err := client.V0().WhoAmi.PublicAPIServiceGetWhoami(p, client.Authenticator)
	if err != nil {
		log.Fatal("failed to make WhoAmI request:", err)
	}

	fmt.Println("UserID: ", *resp.Payload.UserID)
}
