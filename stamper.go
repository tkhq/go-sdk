package turnkey

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	tkcrypto "github.com/tkhq/go-sdk/crypto"
)

// Stamp holds the HTTP header name and value used to authenticate a Turnkey request.
type Stamp struct {
	HeaderName  string
	HeaderValue string
}

// apiStamp is the JSON payload base64-encoded into the X-Stamp header value.
type apiStamp struct {
	PublicKey string `json:"publicKey"`
	Signature string `json:"signature"`
	Scheme    string `json:"scheme"`
}

// Stamper signs request bodies for Turnkey authentication.
type Stamper interface {
	Stamp(ctx context.Context, body []byte) (*Stamp, error)
}

// APIKeyStamper implements Stamper using a Turnkey API key.
type APIKeyStamper struct {
	key *tkcrypto.APIKey
}

// apiKeyStamperConfig holds the configurable settings for an APIKeyStamper.
type apiKeyStamperConfig struct {
	scheme tkcrypto.SignatureScheme
}

// APIKeyStamperOption configures an APIKeyStamper.
type APIKeyStamperOption func(*apiKeyStamperConfig)

// WithSignatureScheme sets the signature scheme used by the APIKeyStamper.
func WithSignatureScheme(scheme tkcrypto.SignatureScheme) APIKeyStamperOption {
	return func(c *apiKeyStamperConfig) {
		c.scheme = scheme
	}
}

// NewAPIKeyStamper creates an APIKeyStamper from a raw Turnkey private key string.
// The signature scheme defaults to P256, pass WithSignatureScheme to override.
func NewAPIKeyStamper(privateKey string, opts ...APIKeyStamperOption) (*APIKeyStamper, error) {
	cfg := apiKeyStamperConfig{scheme: tkcrypto.SchemeP256}
	for _, opt := range opts {
		opt(&cfg)
	}

	apiKey, err := tkcrypto.FromTurnkeyPrivateKey(privateKey, cfg.scheme)
	if err != nil {
		return nil, fmt.Errorf("invalid API key: %w", err)
	}

	return &APIKeyStamper{key: apiKey}, nil
}

// PublicKey returns the Turnkey API public key used by the stamper.
func (s *APIKeyStamper) PublicKey() string {
	return s.key.GetPublicKey()
}

// Stamp generates a Stamp for the given request body by signing it with the API key.
func (s *APIKeyStamper) Stamp(_ context.Context, body []byte) (*Stamp, error) {
	signature, err := s.key.Sign(body)
	if err != nil {
		return nil, err
	}

	apiStamp := apiStamp{
		PublicKey: s.key.GetPublicKey(),
		Signature: signature,
		Scheme:    string(s.key.GetScheme()),
	}

	jsonStamp, err := json.Marshal(apiStamp)
	if err != nil {
		return nil, err
	}

	return &Stamp{HeaderName: "X-Stamp", HeaderValue: base64.RawURLEncoding.EncodeToString(jsonStamp)}, nil
}
