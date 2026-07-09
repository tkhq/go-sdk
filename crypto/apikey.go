// Package crypto manages Turnkey cryptographic primitives and key material.
package crypto

import (
	"errors"
	"fmt"
	"strings"
)

// Curve is a wrapped abbreviated version of a signature curve.
type Curve string

type SignatureScheme string

const (
	CurveP256      = Curve("p256")
	CurveSecp256k1 = Curve("secp256k1")
	CurveEd25519   = Curve("ed25519")

	SchemeUnsupported = SignatureScheme("")
	SchemeP256        = SignatureScheme("SIGNATURE_SCHEME_TK_API_P256")
	SchemeSECP256K1   = SignatureScheme("SIGNATURE_SCHEME_TK_API_SECP256K1")
	SchemeED25519     = SignatureScheme("SIGNATURE_SCHEME_TK_API_ED25519")

	defaultSignatureScheme = SchemeP256
)

// ToScheme returns a Curve's associated SignatureScheme.
func (c Curve) ToScheme() SignatureScheme {
	symbolMap := map[Curve]SignatureScheme{
		CurveP256:      SchemeP256,
		CurveSecp256k1: SchemeSECP256K1,
		CurveEd25519:   SchemeED25519,
	}

	scheme, ok := symbolMap[c]
	if ok {
		return scheme
	}

	return SchemeUnsupported
}

// extractSignatureSchemeFromSuffixedPrivateKey infers the signature type from a suffix appended to the end
// of the private key data (e.g. "deadbeef0123:secp256k1").
func extractSignatureSchemeFromSuffixedPrivateKey(data string) (string, SignatureScheme, error) {
	pieces := strings.Split(data, ":")

	if len(pieces) == 1 {
		return pieces[0], SchemeP256, nil
	}

	scheme := Curve(pieces[1]).ToScheme()
	if scheme == SchemeUnsupported {
		return "", SchemeUnsupported, errors.New("improperly formatted raw key string or unsupported scheme")
	}

	return pieces[0], scheme, nil
}

type APIKeyOptionFunc func(k *APIKey)

func WithScheme(scheme SignatureScheme) APIKeyOptionFunc {
	return func(k *APIKey) {
		k.scheme = scheme
	}
}

// APIKeyMetadata stores non-secret metadata about the API key.
type APIKeyMetadata struct {
	Name          string   `json:"name"`
	Organizations []string `json:"organizations"`
	PublicKey     string   `json:"public_key"`
	Scheme        string   `json:"scheme"`
}

// APIKey defines a structure in which to hold both serialized and signer-friendly versions of an API key.
type APIKey struct {
	APIKeyMetadata

	TkPrivateKey string `json:"-"` // do not store the private key in the metadata file
	TkPublicKey  string `json:"public_key"`

	scheme        SignatureScheme
	underlyingKey underlyingKey
}

type underlyingKey interface {
	sign(message []byte) (string, error)
}

// NewAPIKey generates a new API key.
func NewAPIKey(opts ...APIKeyOptionFunc) (*APIKey, error) {
	apiKey := &APIKey{
		scheme: defaultSignatureScheme,
	}

	for _, opt := range opts {
		opt(apiKey)
	}

	var err error

	// generate key pair data
	switch apiKey.scheme {
	case SchemeP256:
		apiKey, err = newECDSAKey(apiKey.scheme)
		if err != nil {
			return nil, fmt.Errorf("failed to generate p256 key pair: %s", err)
		}
	case SchemeSECP256K1:
		apiKey, err = newECDSAKey(apiKey.scheme)
		if err != nil {
			return nil, fmt.Errorf("failed to generate secp256k1 key pair: %s", err)
		}
	case SchemeED25519:
		apiKey, err = newED25519Key()
		if err != nil {
			return nil, fmt.Errorf("failed to generate ed25519 key pair: %s", err)
		}
	default:
		return nil, fmt.Errorf("unsupported signature scheme: %s", apiKey.scheme)
	}

	// supply metadata
	apiKey.PublicKey = apiKey.TkPublicKey
	apiKey.Scheme = string(apiKey.scheme)

	return apiKey, nil
}

// FromTurnkeyPrivateKey takes a private key, derives a public key from it, and then returns the corresponding API key.
func FromTurnkeyPrivateKey(encodedPrivateKey string, scheme SignatureScheme) (*APIKey, error) {
	switch scheme {
	case SchemeP256:
		return fromECDSAKey(encodedPrivateKey, scheme)
	case SchemeSECP256K1:
		return fromECDSAKey(encodedPrivateKey, scheme)
	case SchemeED25519:
		return fromED25519Key(encodedPrivateKey)
	default:
		return nil, errors.New("unsupported signature scheme")
	}
}

// Sign signs the given message and returns the hex-encoded signature.
func (k *APIKey) Sign(message []byte) (string, error) {
	return k.underlyingKey.sign(message)
}

// GetScheme returns the signature scheme of the key.
func (k APIKey) GetScheme() SignatureScheme {
	return k.scheme
}

// GetPublicKey gets the key's public key.
func (k APIKey) GetPublicKey() string {
	return k.TkPublicKey
}

// GetPrivateKey gets the key's private key.
func (k APIKey) GetPrivateKey() string {
	return k.TkPrivateKey
}

// GetMetadata gets the key's metadata.
func (k APIKey) GetMetadata() APIKeyMetadata {
	return k.APIKeyMetadata
}

// GetCurve returns the curve used; defaults to p256 for backwards compatibility with keys
// created before there were multiple supported types.
func (k APIKey) GetCurve() string {
	switch k.scheme {
	case SchemeSECP256K1:
		return string(CurveSecp256k1)
	case SchemeED25519:
		return string(CurveEd25519)
	case SchemeP256:
		return string(CurveP256)
	default:
		return string(CurveP256)
	}
}
