// Package sdk provides a Go SDK with which to interact with the Turnkey API service.
package sdk

import (
	"net/http"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/pkg/errors"

	"github.com/tkhq/go-sdk/pkg/api/client"
	"github.com/tkhq/go-sdk/pkg/apikey"
	"github.com/tkhq/go-sdk/pkg/store/local"
)

const DefaultClientVersion = "go-sdk"

type config struct {
	apiKey          *apikey.Key
	clientVersion   string
	registry        strfmt.Registry
	transportConfig *client.TransportConfig
}

// OptionFunc defines a function which sets configuration options for a Client.
type OptionFunc func(c *config) error

// WithClientVersion overrides the client version used for this API client.
func WithClientVersion(clientVersion string) OptionFunc {
	return func(c *config) error {
		c.clientVersion = clientVersion
		return nil
	}
}

// WithRegistry sets the registry formats used for this API client.
func WithRegistry(registry strfmt.Registry) OptionFunc {
	return func(c *config) error {
		c.registry = registry
		return nil
	}
}

// WithTransportConfig sets the TransportConfig used for this API client.
func WithTransportConfig(transportConfig client.TransportConfig) OptionFunc {
	return func(c *config) error {
		c.transportConfig = &transportConfig
		return nil
	}
}

// WithAPIKey sets the API key used for this API client.
// Users would normally use WithAPIKeyName. This offers a lower-level custom API
// key.
func WithAPIKey(apiKey *apikey.Key) OptionFunc {
	return func(c *config) error {
		c.apiKey = apiKey
		return nil
	}
}

// WithAPIKeyName sets the API key to the key loaded from the local keystore
// with the provided name.
func WithAPIKeyName(keyname string) OptionFunc {
	return func(c *config) error {
		apiKey, err := local.New[*apikey.Key]().Load(keyname)
		if err != nil {
			return errors.Wrap(err, "failed to load API key")
		}
		c.apiKey = apiKey
		return nil
	}
}

// New returns a new API Client with the given API key name from the default keystore.
func New(options ...OptionFunc) (*Client, error) {
	c := &config{
		clientVersion:   DefaultClientVersion,
		transportConfig: client.DefaultTransportConfig(),
	}

	for _, o := range options {
		o(c)
	}

	// Create transport and client
	transport := httptransport.New(
		c.transportConfig.Host,
		c.transportConfig.BasePath,
		c.transportConfig.Schemes,
	)

	// Add client version header
	transport.Transport = SetClientVersion(transport.Transport, c.clientVersion)

	return &Client{
		Client:        client.New(transport, c.registry),
		Authenticator: &Authenticator{Key: c.apiKey},
		APIKey:        c.apiKey,
	}, nil
}

func SetClientVersion(inner http.RoundTripper, clientVersion string) http.RoundTripper {
	return &addClientVersion{
		inner:   inner,
		Version: clientVersion,
	}
}

type addClientVersion struct {
	inner   http.RoundTripper
	Version string
}

func (acv *addClientVersion) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Set("X-Client-Version", acv.Version)
	return acv.inner.RoundTrip(r)
}

// NewHTTPClient returns a new base HTTP API client.
// Most users will call New() instead.
// Deprecated: Use New(WithRegistry(formats)) instead
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
