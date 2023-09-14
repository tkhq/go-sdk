# Turnkey GO SDK
[![GoDocs](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white&style=flat-square)](https://pkg.go.dev/github.com/tkhq/go-sdk) 

The Turnkey Go SDK is an early tool for interacting with the Turnkey API.

There is much work to be done, but it is completly usable in its current form.  The main thing to keep in mind is that each requests needs to be manually provided the client.Authenticator.

Example:

```go
import (
	"fmt"
	"log"

	"github.com/tkhq/go-sdk"
	"github.com/tkhq/go-sdk/pkg/api/client/who_am_i"
	"github.com/tkhq/go-sdk/pkg/api/models"
)

func main() {
	// NB: make sure to create and register an API key, first.
	client, err := sdk.New("") // your local API key name
	if err != nil {
		log.Fatal("failed to create new SDK client:", err)
	}

	p := who_am_i.NewPublicAPIServiceGetWhoamiParams().WithBody(&models.V1GetWhoamiRequest{
		OrganizationID: client.DefaultOrganization(), // alternatively, specify your desired organization ID
	})

	resp, err := client.V0().WhoAmi.PublicAPIServiceGetWhoami(p, client.Authenticator)
	if err != nil {
		log.Fatal("failed to make WhoAmI request:", err)
	}

	fmt.Println("UserID: ", *resp.Payload.UserID)
}
```

## API key

In order to use the SDK, you will need an API key.
When creating API keys, the private part never leaves the local system, but the public part must be registered to your Turnkey account.

The easiest way to manage your API keys is with the [Turnkey CLI](https://github.com/tkhq/tkcli), but you can also create one using this SDK.  See [this example](./examples/apikey/).

## Updating the SDK with the latest Swagger definitions

1. Install [go-swagger](https://goswagger.io/install.html):
```
brew tap go-swagger/go-swagger
brew install go-swagger
```
2. Update the swagger file in `inputs/` with a new one
3. Run `make generate`
