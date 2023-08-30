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

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

// Metadata stores non-secret metadata about the API key.
type Metadata struct {
	// ID is the unique identifier of the API key inside the Turnkey database.
	ID string `json:"id"`

	// Name is the arbitrary human-readable label of this key.
	Name string `json:"name"`

	// Organizations is the set unique identifiers of organizations to which this API key is bound and for which this API key can enact API calls.
	Organizations []string `json:"organizations"`

	// PublicKey is the text form of the PublicKey, for display purposes.
	PublicKey string `json:"public_key"`

	// User is the unique identifier of the user to which this API key is attached and on behalf of whom activities by this key will be taken.
	User string `json:"user"`
}

// Key defines a structure in which to hold both serialized and ecdsa-lib-friendly versions of a Turnkey API keypair.
type Key struct {
	Metadata

	TkPrivateKey string `json:"-"` // do not store the private key in the metadata file
	TkPublicKey  string `json:"public_key"`

	// Underlying ECDSA keypair
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
}

// MergeMetadata merges the given metadata with the api key.
func (k *Key) MergeMetadata(md *Metadata) error {
	if k.TkPublicKey != md.PublicKey {
		return errors.Errorf("metadata public key %q does not match API key public key %q", md.PublicKey, k.TkPublicKey)
	}

	k.Metadata.ID = md.ID
	k.Metadata.Name = md.Name
	k.Metadata.Organizations = md.Organizations
	k.Metadata.PublicKey = md.PublicKey
	k.Metadata.User = md.User

	return nil
}

// TurnkeyAPISignatureScheme is the signature scheme to use for the API request signature.
const TurnkeyAPISignatureScheme = "SIGNATURE_SCHEME_TK_API_P256"

// APIStamp defines the stamp format used to authenticate payloads to the API.
type APIStamp struct {
	// API public key, hex-encoded
	PublicKey string `json:"publicKey"`

	// Signature is the P-256 signature bytes, hex-encoded
	Signature string `json:"signature"`

	// Signature scheme. Must be set to "SIGNATURE_SCHEME_TK_API_P256"
	Scheme string `json:"scheme"`
}

// New generates a new Turnkey API key.
func New(organizationID string) (*Key, error) {
	if organizationID == "" {
		return nil, fmt.Errorf("please supply a valid Organization UUID")
	}

	if _, err := uuid.Parse(organizationID); err != nil {
		return nil, fmt.Errorf("failed to parse organization ID")
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	apiKey, err := FromECDSAPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	apiKey.Metadata.Organizations = append(apiKey.Metadata.Organizations, organizationID)
	apiKey.Metadata.PublicKey = apiKey.PublicKey

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
func FromECDSAPrivateKey(privateKey *ecdsa.PrivateKey) (*Key, error) {
	if privateKey == nil || privateKey.PublicKey.X == nil {
		return nil, errors.New("empty key")
	}

	publicKey := &privateKey.PublicKey

	return &Key{
		TkPrivateKey: EncodePrivateKey(privateKey),
		TkPublicKey:  EncodePublicKey(publicKey),
		publicKey:    publicKey,
		privateKey:   privateKey,
	}, nil
}

// FromTurnkeyPrivateKey takes a Turnkey-encoded private key, derives a public key from it, and then returns the corresponding Turnkey API key.
func FromTurnkeyPrivateKey(encodedPrivateKey string) (*Key, error) {
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

	// Derive the public key
	privateKey.PublicKey.Curve = elliptic.P256()
	privateKey.PublicKey.X, privateKey.PublicKey.Y = privateKey.PublicKey.Curve.ScalarBaseMult(privateKey.D.Bytes())

	apiKey, err := FromECDSAPrivateKey(&privateKey)
	if err != nil {
		return nil, err
	}

	return apiKey, nil
}

// DecodeTurnkeyPublicKey takes a Turnkey-encoded public key and creates an ECDSA public key.
func DecodeTurnkeyPublicKey(encodedPublicKey string) (*ecdsa.PublicKey, error) {
	bytes, err := hex.DecodeString(encodedPublicKey)
	if err != nil {
		return nil, err
	}

	if len(bytes) != 33 {
		return nil, fmt.Errorf("expected a 33-bytes-long public key (compressed). Got %d bytes", len(bytes))
	}

	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), bytes)

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
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
		Scheme:    TurnkeyAPISignatureScheme,
	}

	jsonStamp, err := json.Marshal(stamp)
	if err != nil {
		return "", errors.Wrap(err, "failed to encode API stamp as JSON")
	}

	return base64.RawURLEncoding.EncodeToString(jsonStamp), nil
}
