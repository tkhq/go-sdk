# Turnkey GO SDK

The Turnkey Go SDK is an early tool for interacting with the Turnkey API.

There is much work to be done, but it is completly usable in its current form.  The main thing to keep in mind is that each requests needs to be manually provided the client.Authenticator.

Example:

```go
import (
	"fmt"

	"github.com/tkhq/go-sdk"
	"github.com/tkhq/go-sdk/pkg/apikey"
	"github.com/tkhq/go-sdk/pkg/store"
)

func ExampleClient() {
	client, err := sdk.New("")
	if err != nil {
		return
	}

	p := users.NewPublicAPIServiceGetWhoamiParams().WithBody(&models.V1GetWhoamiRequest{
		OrganizationID: client.DefaultOrganization(),
	})

	resp, err := client.V0().Users.PublicAPIServiceGetWhoami(p, client.Authenticator)
	if err != nil {
		return
	}

	fmt.Println(*resp.Payload.UserID)
}
```

## API key

In order to use the SDK, you will need an API key.
When creating API keys, the private part never leaves the local system, but the public part must be registered to your Turnkey account.

The easiest way to manage your API keys is with the [Turnkey CLI](https://github.com/tkhq/tkcli), but you can also create one using this SDK.  See [this example](./examples/apikey/).
