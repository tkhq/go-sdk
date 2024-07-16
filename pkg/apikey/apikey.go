// Package apikey manages Turnkey API keys for organizations
package apikey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
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

	var apiKey *Key

	if scheme == SchemeED25519 {
		var err error
		apiKey, err = NewED25519()
		if err != nil {
			return nil, fmt.Errorf("failed to generate ed25519 key pair: %s", err)
		}
	} else {

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

		apiKey, err = FromECDSAPrivateKey(privateKey, scheme)
		if err != nil {
			return nil, err
		}
	}

	apiKey.Metadata.Organizations = append(apiKey.Metadata.Organizations, organizationID)
	apiKey.Metadata.PublicKey = apiKey.PublicKey
	apiKey.Metadata.Scheme = string(scheme)
	apiKey.scheme = scheme

	return apiKey, nil
}

func NewED25519() (*Key, error) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	return FromED25519PrivateKey(privKey)
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
		ecdsaPubKey:  publicKey,
		ecdsaPrivKey: privateKey,
		scheme:       scheme,
	}, nil
}

// FromED25519PrivateKey takes an ED25519 keypair and forms a Turnkey API key from it.
func FromED25519PrivateKey(privateKey ed25519.PrivateKey) (*Key, error) {
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("malformed ed25519 key pair (type assertion failed)")
	}

	return &Key{
		TkPrivateKey:   hex.EncodeToString(privateKey),
		TkPublicKey:    hex.EncodeToString(publicKey),
		ed25519PubKey:  &publicKey,
		ed25519PrivKey: &privateKey,
		scheme:         SchemeED25519,
	}, nil
}

// FromTurnkeyPrivateKey takes a Turnkey-encoded private key, derives a public key from it, and then returns the corresponding Turnkey API key.
func FromTurnkeyPrivateKey(encodedPrivateKey string, scheme signatureScheme) (*Key, error) {
	if scheme == SchemeED25519 {
		return fromTurnkeyED25519Key(encodedPrivateKey)
	}

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

func fromTurnkeyED25519Key(encodedPrivateKey string) (*Key, error) {
	// Decode the hex string to bytes
	privateKeyBytes, err := hex.DecodeString(encodedPrivateKey)
	if err != nil {
		log.Fatalf("Failed to decode hex string: %v", err)
	}

	// Check if the length of the byte slice is correct
	if len(privateKeyBytes) != ed25519.PrivateKeySize {
		log.Fatalf("Invalid private key length: expected %d, got %d", ed25519.PrivateKeySize, len(privateKeyBytes))
	}

	// Convert the byte slice to ed25519.PrivateKey and encapsulate in TK struct
	return FromED25519PrivateKey(ed25519.PrivateKey(privateKeyBytes))
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

	var signature string

	switch apiKey.scheme {
	case SchemeP256:
		signature, err = signECDSA(hash[:], apiKey.ecdsaPrivKey)
		if err != nil {
			return "", err
		}
	case SchemeSECP256K1:
		signature, err = signECDSA(hash[:], apiKey.ecdsaPrivKey)
		if err != nil {
			return "", err
		}
	case SchemeED25519:
		signature = signED25519(hash[:], *apiKey.ed25519PrivKey)
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

func signECDSA(hash []byte, privKey *ecdsa.PrivateKey) (string, error) {
	sigBytes, err := ecdsa.SignASN1(rand.Reader, privKey, hash)
	if err != nil {
		return "", errors.Wrap(err, "failed to generate signature")
	}

	return hex.EncodeToString(sigBytes), nil
}

func signED25519(hash []byte, privKey ed25519.PrivateKey) string {
	return hex.EncodeToString(ed25519.Sign(privKey, hash))
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
	case SchemeED25519:
		return "ed25519"
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

func ExtractCurveTypeFromSuffixedPrivateKey(data string) (string, signatureScheme, error) {
	symbolMap := map[string]signatureScheme{
		"p256":      SchemeP256,
		"secp256k1": SchemeSECP256K1,
		"ed25519":   SchemeED25519,
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
