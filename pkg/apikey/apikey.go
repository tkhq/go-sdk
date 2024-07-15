// Package apikey manages Turnkey API keys for organizations
package apikey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"

	dcrec "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
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

	// Underlying ECDSA keypair
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
}

// APIStamp defines the stamp format used to authenticate payloads to the API.
type APIStamp struct {
	// API public key, hex-encoded
	PublicKey string `json:"publicKey"`

	// Signature is the P-256 signature bytes, hex-encoded
	Signature string `json:"signature"`

	// Signature scheme. Must be set to "SIGNATURE_SCHEME_TK_API_P256"
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

	var curve elliptic.Curve

	switch scheme {
	case SchemeP256:
		curve = elliptic.P256()
	case SchemeSECP256K1:
		curve = secp256k1.S256()
	default:
		// should be unreachable since scheme type is non-exported with discreet options
		return nil, fmt.Errorf("invalid signature scheme type: %s", scheme)
	}

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	apiKey, err := FromECDSAPrivateKey(privateKey, scheme)
	if err != nil {
		return nil, err
	}

	fmt.Printf("tk pub %s, pub %s\n", apiKey.TkPublicKey, apiKey.PublicKey)

	apiKey.Metadata.Organizations = append(apiKey.Metadata.Organizations, organizationID)
	apiKey.Metadata.PublicKey = apiKey.PublicKey
	apiKey.Metadata.Scheme = string(scheme)
	apiKey.scheme = scheme

	return apiKey, nil
}

// EncodePrivateKey encodes an ECDSA private key into the Turnkey format.
// For now, "Turnkey format" = raw DER form.
func EncodePrivateKey(privateKey *ecdsa.PrivateKey) string {
	return fmt.Sprintf("%064x", privateKey.D)
}

// EncodePublicKey encodes an ECDSA public key into the Turnkey format.
// For now, "Turnkey format" = standard compressed form for ECDSA keys.
func EncodePublicKey(publicKey *ecdsa.PublicKey) string {
	// ANSI X9.62 point encoding
	var prefix string
	if publicKey.Y.Bit(0) == 0 {
		// Even Y
		prefix = "02"
	} else {
		// Odd Y
		prefix = "03"
	}

	// Encode the public key X coordinate as 64 hexadecimal characters, padded with zeroes as necessary
	return fmt.Sprintf("%s%064x", prefix, publicKey.X)
}

// FromECDSAPrivateKey takes an ECDSA keypair and forms a Turnkey API key from it.
// Assumes that privateKey.PublicKey has already been derived.
func FromECDSAPrivateKey(privateKey *ecdsa.PrivateKey, scheme signatureScheme) (*Key, error) {
	if privateKey == nil || privateKey.PublicKey.X == nil {
		return nil, errors.New("empty key")
	}

	publicKey := &privateKey.PublicKey

	return &Key{
		TkPrivateKey: EncodePrivateKey(privateKey),
		TkPublicKey:  EncodePublicKey(publicKey),
		publicKey:    publicKey,
		privateKey:   privateKey,
		scheme:       scheme,
	}, nil
}

// FromTurnkeyPrivateKey takes a Turnkey-encoded private key, derives a public key from it, and then returns the corresponding Turnkey API key.
func FromTurnkeyPrivateKey(encodedPrivateKey string, scheme signatureScheme) (*Key, error) {
	bytes, err := hex.DecodeString(encodedPrivateKey)
	if err != nil {
		return nil, err
	}

	dValue := new(big.Int).SetBytes(bytes)

	publicKey := new(ecdsa.PublicKey)
	privateKey := ecdsa.PrivateKey{
		PublicKey: *publicKey,
		D:         dValue,
	}

	var curve elliptic.Curve

	// Derive the public key
	switch scheme {
	case SchemeP256:
		curve = elliptic.P256()
	case SchemeSECP256K1:
		curve = secp256k1.S256()
	default:
		// should be unreachable since scheme type is non-exported with discreet options
		return nil, fmt.Errorf("invalid signature scheme type: %s", scheme)
	}

	privateKey.PublicKey.Curve = curve
	privateKey.PublicKey.X, privateKey.PublicKey.Y = privateKey.PublicKey.Curve.ScalarBaseMult(privateKey.D.Bytes())

	apiKey, err := FromECDSAPrivateKey(&privateKey, scheme)
	if err != nil {
		return nil, err
	}

	return apiKey, nil
}

// DecodeTurnkeyPublicKey takes a Turnkey-encoded public key and creates an ECDSA public key.
func DecodeTurnkeyPublicKey(encodedPublicKey string, scheme signatureScheme) (*ecdsa.PublicKey, error) {
	fmt.Printf("scheme in decode public key %s\n", scheme)

	bytes, err := hex.DecodeString(encodedPublicKey)
	if err != nil {
		return nil, err
	}

	if len(bytes) != 33 {
		return nil, fmt.Errorf("expected a 33-bytes-long public key (compressed). Got %d bytes", len(bytes))
	}

	var x, y *big.Int

	var curve elliptic.Curve

	// Derive the public key
	switch scheme {
	case SchemeP256:
		curve = elliptic.P256()
		x, y = elliptic.UnmarshalCompressed(curve, bytes)
	case SchemeSECP256K1:
		curve = secp256k1.S256()

		pubkey, err := dcrec.ParsePubKey(bytes)
		if err != nil {
			return nil, fmt.Errorf("cannot parse bytes into secp256k1 public key")
		}

		x = pubkey.X()
		y = pubkey.Y()
	default:
		// should be unreachable since scheme type is non-exported with discreet options
		return nil, fmt.Errorf("invalid signature scheme type: %s", scheme)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// Stamp generates a signing stamp for the given message with the given API key.
// The resulting stamp should be added as the "X-Stamp" header of an API request.
func Stamp(message []byte, apiKey *Key) (out string, err error) {
	hash := sha256.Sum256(message)

	sigBytes, err := ecdsa.SignASN1(rand.Reader, apiKey.privateKey, hash[:])
	if err != nil {
		return "", errors.Wrap(err, "failed to generate signature")
	}

	stamp := APIStamp{
		PublicKey: apiKey.TkPublicKey,
		Signature: hex.EncodeToString(sigBytes),
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

// GetCurve returns the curve used
func (k Key) GetCurve() string {
	switch k.scheme {
	case SchemeSECP256K1:
		return "secp256k1"
	default:
	}
	return "p256"
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
func (k Key) MergeMetadata(md Metadata) error {
	if k.TkPublicKey != md.PublicKey {
		return errors.Errorf("metadata public key %q does not match API key public key %q", md.PublicKey, k.TkPublicKey)
	}

	k.Metadata.Name = md.Name
	k.Metadata.Organizations = md.Organizations
	k.Metadata.PublicKey = md.PublicKey
	k.Metadata.Scheme = md.Scheme

	return nil
}

func ExtractCurveTypeFromSuffixedPrivateKey(data string) (string, signatureScheme, error) {
	symbolMap := map[string]signatureScheme{
		"p256":      SchemeP256,
		"secp256k1": SchemeSECP256K1,
	}

	pieces := strings.Split(data, ":")

	if len(pieces) == 1 {
		return pieces[0], SchemeP256, nil
	}

	if scheme, ok := symbolMap[pieces[1]]; ok {
		return pieces[0], scheme, nil
	}

	return "", signatureScheme(""), errors.New("improperly formatted raw key string")
}
