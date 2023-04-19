package main

import (
	"fmt"
	"log"

	"github.com/tkhq/go-sdk"
	"github.com/tkhq/go-sdk/pkg/api/client/users"
	"github.com/tkhq/go-sdk/pkg/api/models"
)

func main() {
	// NB: make sure to create and register an API key, first.
	client, err := sdk.New("")
	if err != nil {
		log.Fatal("failed to create new SDK client:", err)
	}

	p := users.NewPublicAPIServiceGetWhoamiParams().WithBody(&models.V1GetWhoamiRequest{
		OrganizationID: client.DefaultOrganization(),
	})

	resp, err := client.V0().Users.PublicAPIServiceGetWhoami(p, client.Authenticator)
	if err != nil {
		log.Fatal("failed to make WhoAmI request:", err)
	}

	fmt.Println("UserID: ", *resp.Payload.UserID)
}
