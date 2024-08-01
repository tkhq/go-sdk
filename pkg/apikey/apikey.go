// Package apikey manages Turnkey API keys for organizations
package apikey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

// Metadata stores non-secret metadata about the API key.
type Metadata struct {
	Name          string   `json:"name"`
	Organizations []string `json:"organizations"`
	PublicKey     string   `json:"public_key"`
	Scheme        string   `json:"scheme"`
}

// Key defines a structure in which to hold both serialized and ecdsa-lib-friendly versions of a Turnkey API keypair.
type Key struct {
	Metadata

	TkPrivateKey string `json:"-"` // do not store the private key in the metadata file
	TkPublicKey  string `json:"public_key"`

	scheme signatureScheme

	// Underlying ECDSA keypair (if applicable)
	ecdsaPrivKey *ecdsa.PrivateKey
	ecdsaPubKey  *ecdsa.PublicKey

	// Underlying ED25519 keypair (if applicable)
	ed25519PrivKey *ed25519.PrivateKey
	ed25519PubKey  *ed25519.PublicKey
}

// APIStamp defines the stamp format used to authenticate payloads to the API.
type APIStamp struct {
	// API public key, hex-encoded
	PublicKey string `json:"publicKey"`

	// Signature is the P-256 signature bytes, hex-encoded
	Signature string `json:"signature"`

	// Signature scheme. Can be set to "SIGNATURE_SCHEME_TK_API_P256", "SIGNATURE_SCHEME_TK_API_SECP256K1",
	// or "SIGNATURE_SCHEME_TK_API_ED25519"
	Scheme signatureScheme `json:"scheme"`
}

// New generates a new Turnkey API key.
func New(organizationID string, scheme signatureScheme) (*Key, error) {
	if organizationID == "" {
		return nil, fmt.Errorf("please supply a valid Organization UUID")
	}

	if _, err := uuid.Parse(organizationID); err != nil {
		return nil, fmt.Errorf("failed to parse organization ID")
	}

	var apiKey *Key

	var err error

	// generate key pair data
	switch scheme {
	case SchemeP256:
		apiKey, err = newECDSAKey(scheme)
		if err != nil {
			return nil, fmt.Errorf("failed to generate p256 key pair: %s", err)
		}
	case SchemeSECP256K1:
		apiKey, err = newECDSAKey(scheme)
		if err != nil {
			return nil, fmt.Errorf("failed to generate secp256k1 key pair: %s", err)
		}
	case SchemeED25519:
		apiKey, err = newED25519Key()
		if err != nil {
			return nil, fmt.Errorf("failed to generate ed25519 key pair: %s", err)
		}
	default:
		return nil, fmt.Errorf("unsupported signature scheme: %s", scheme)
	}

	// supply metadata
	apiKey.Metadata.Organizations = append(apiKey.Metadata.Organizations, organizationID)
	apiKey.Metadata.PublicKey = apiKey.PublicKey
	apiKey.Metadata.Scheme = string(scheme)
	apiKey.scheme = scheme

	return apiKey, nil
}

// FromTurnkeyPrivateKey takes a Turnkey-encoded private key, derives a public key from it, and then returns the corresponding Turnkey API key.
func FromTurnkeyPrivateKey(encodedPrivateKey string, scheme signatureScheme) (*Key, error) {
	if scheme == SchemeED25519 {
		return fromTurnkeyED25519Key(encodedPrivateKey)
	}

	switch scheme {
	case SchemeP256:
		return fromTurnkeyECDSAKey(encodedPrivateKey, scheme)
	case SchemeSECP256K1:
		return fromTurnkeyECDSAKey(encodedPrivateKey, scheme)
	case SchemeED25519:
		return fromTurnkeyED25519Key(encodedPrivateKey)
	default:
	}

	return nil, errors.New("unsupported signature scheme")
}

// Stamp generates a signing stamp for the given message with the given API key.
// The resulting stamp should be added as the "X-Stamp" header of an API request.
func Stamp(message []byte, apiKey *Key) (out string, err error) {
	var signature string

	switch apiKey.scheme {
	case SchemeP256:
		signature, err = signECDSA(message, apiKey.ecdsaPrivKey)
		if err != nil {
			return "", err
		}
	case SchemeSECP256K1:
		signature, err = signECDSA(message, apiKey.ecdsaPrivKey)
		if err != nil {
			return "", err
		}
	case SchemeED25519:
		signature = signED25519(message, *apiKey.ed25519PrivKey)
	default:
		return "", fmt.Errorf("unsupported signature scheme: %s", apiKey.scheme)
	}

	stamp := APIStamp{
		PublicKey: apiKey.TkPublicKey,
		Signature: signature,
		Scheme:    apiKey.scheme,
	}

	jsonStamp, err := json.Marshal(stamp)
	if err != nil {
		return "", errors.Wrap(err, "failed to encode API stamp as JSON")
	}

	return base64.RawURLEncoding.EncodeToString(jsonStamp), nil
}

// GetPublicKey gets the key's public key.
func (k Key) GetPublicKey() string {
	return k.TkPublicKey
}

// GetPrivateKey gets the key's private key.
func (k Key) GetPrivateKey() string {
	return k.TkPrivateKey
}

// GetMetadata gets the key's metadata.
func (k Key) GetMetadata() Metadata {
	return k.Metadata
}

// GetCurve returns the curve used; defaults to p256 for backwards compatibility with keys
// created before there were multiple supported types.
func (k Key) GetCurve() string {
	switch k.scheme {
	case SchemeSECP256K1:
		return string(CurveSecp256k1)
	case SchemeED25519:
		return string(CurveEd25519)
	case SchemeP256:
		return string(CurveP256)
	default:
	}

	return string(CurveP256)
}

// LoadMetadata loads a JSON metadata file.
func (k Key) LoadMetadata(fn string) (*Metadata, error) {
	f, err := os.Open(fn)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open metadata file")
	}

	md := new(Metadata)

	if err := json.NewDecoder(f).Decode(md); err != nil {
		return nil, errors.Wrap(err, "failed to decode metadata file")
	}

	return md, nil
}

// MergeMetadata merges the given metadata with the api key.
func (k *Key) MergeMetadata(md Metadata) error {
	if k.TkPublicKey != md.PublicKey {
		return errors.Errorf("metadata public key %q does not match API key public key %q", md.PublicKey, k.TkPublicKey)
	}

	k.Metadata.Name = md.Name
	k.Metadata.Organizations = md.Organizations
	k.Metadata.PublicKey = md.PublicKey
	k.Metadata.Scheme = md.Scheme

	return nil
}
