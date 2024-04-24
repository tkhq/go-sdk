// Package sdk provides a Go SDK with which to interact with the Turnkey API service.
package sdk

import (
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/pkg/errors"

	"github.com/tkhq/go-sdk/pkg/api/client"
	"github.com/tkhq/go-sdk/pkg/apikey"
	"github.com/tkhq/go-sdk/pkg/store/local"
)

// New returns a new API Client with the given API key name from the default keystore.
func New(keyname string) (*Client, error) {
	apiKey, err := local.New[apikey.Key, apikey.Metadata]().Load(keyname)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load API key")
	}

	return &Client{
		Client:        client.NewHTTPClient(nil),
		Authenticator: &Authenticator{Key: apiKey},
		APIKey:        apiKey,
	}, nil
}

// NewHTTPClient returns a new base HTTP API client.
// Most users will call New() instead.
func NewHTTPClient(formats strfmt.Registry) *client.TurnkeyAPI {
	return client.NewHTTPClient(formats)
}

// Client provides a handle by which to interact with the Turnkey API.
type Client struct {
	// Client is the base HTTP API Client.
	Client *client.TurnkeyAPI

	// Authenticator provides a client option authentication provider which should be attached to every API request as a clientOption.
	Authenticator *Authenticator

	// APIKey is the API key to be used for API request signing.
	APIKey *apikey.Key
}

// DefaultOrganization returns the first organization found in the APIKey's set of organizations.
func (c *Client) DefaultOrganization() *string {
	for _, o := range c.APIKey.Organizations {
		return &o
	}

	return nil
}

// V0 returns the raw initial Turnkey API client.
// WARNING: this is a temporary API which requires a bit more work to use than the one which will be eventually offered.
func (c *Client) V0() *client.TurnkeyAPI {
	return c.Client
}

// Authenticator provides a runtime.ClientAuthInfoWriter for use with the swagger API client.
type Authenticator struct {
	// Key optionally overrides the globally-parsed APIKeypair with a custom key.
	Key *apikey.Key
}

// AuthenticateRequest implements runtime.ClientAuthInfoWriter.
// It adds the X-Stamp header to the request based by generating the Stamp with the request body and API key.
func (auth *Authenticator) AuthenticateRequest(req runtime.ClientRequest, reg strfmt.Registry) (err error) { //nolint: revive
	stamp, err := apikey.Stamp(req.GetBody(), auth.Key)
	if err != nil {
		return errors.Wrap(err, "failed to generate API stamp")
	}

	return req.SetHeaderParam("X-Stamp", stamp)
}
