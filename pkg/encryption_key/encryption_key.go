package encryption_key

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/pkg/errors"
	"github.com/tkhq/go-sdk/pkg/common"
)

const KemId hpke.KEM = hpke.KEM_P256_HKDF_SHA256

// Metadata stores non-secret metadata about the API key.
type Metadata struct {
	Name         string `json:"name"`
	Organization string `json:"organization"`
	User         string `json:"user"`
	PublicKey    string `json:"public_key"`
}

// Key defines a structure in which to hold both serialized and ecdh-lib-friendly versions of a Turnkey API keypair.
type Key struct {
	Metadata

	TkPrivateKey string `json:"-"` // do not store the private key in the metadata file
	TkPublicKey  string `json:"public_key"`

	// Underlying KEM keypair
	privateKey *kem.PrivateKey
	publicKey  *kem.PublicKey
}

// MergeMetadata merges the given metadata with the api key.
func (k *Key) MergeMetadata(imd *common.IMetadata) error {
	md, ok := (*imd).(Metadata)
	if !ok {
		return errors.New("metadata type mismatch")
	}

	if k.TkPublicKey != md.PublicKey {
		return errors.Errorf("metadata public key %q does not match encryption key public key %q", md.PublicKey, k.TkPublicKey)
	}

	k.Metadata.Name = md.Name
	k.Metadata.Organization = md.Organization
	k.Metadata.PublicKey = md.PublicKey
	k.Metadata.User = md.User

	return nil
}

// New generates a new Turnkey encryption key.
func New(userID string, organizationID string) (*Key, error) {
	_, privateKey, err := KemId.Scheme().GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	encryptionKey, err := FromKemPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	encryptionKey.Metadata.Organization = organizationID
	encryptionKey.Metadata.User = userID
	encryptionKey.Metadata.PublicKey = encryptionKey.PublicKey

	return encryptionKey, nil
}

// EncodePrivateKey encodes an ECDSA private key into the Turnkey format.
// For now, "Turnkey format" = raw DER form.
func EncodePrivateKey(privateKey *kem.PrivateKey) string {
	return fmt.Sprintf("%064x", privateKey)
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

// FromKemPrivateKey takes a HPKE KEM keypair and forms a Turnkey encryption key from it.
// Assumes that privateKey.Public() has already been derived.
func FromKemPrivateKey(privateKey kem.PrivateKey) (*Key, error) {
	if privateKey == nil || privateKey.Public() == nil {
		return nil, errors.New("empty key")
	}

	publicKey := privateKey.Public()

	return &Key{
		// TkPrivateKey: EncodePrivateKey(privateKey),
		// TkPublicKey:  EncodePublicKey(publicKey),
		publicKey:  &publicKey,
		privateKey: &privateKey,
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

	// encryptionKey, err := FromKemPrivateKey(&privateKey)
	// if err != nil {
	return nil, err
	// }

	// return encryptionKey, nil
}

// DecodeTurnkeyPublicKey takes a Turnkey-encoded public key and creates an ECDSA public key.
// func DecodeTurnkeyPublicKey(encodedPublicKey string) (*kem.PublicKey, error) {
// 	bytes, err := hex.DecodeString(encodedPublicKey)
// 	if err != nil {
// 		return nil, err
// 	}

// 	if len(bytes) != 33 {
// 		return nil, fmt.Errorf("expected a 33-bytes-long public key (compressed). Got %d bytes", len(bytes))
// 	}

// 	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), bytes)

// 	return &kem.PublicKey{
// 		Curve: elliptic.P256(),
// 		X:     x,
// 		Y:     y,
// 	}, nil
// }

func (k Key) GetPublicKey() string {
	return k.TkPublicKey
}

func (k Key) GetPrivateKey() string {
	return k.TkPrivateKey
}

func (k Key) SerializeMetadata() ([]byte, error) {
	// Implement serialization logic here.
	// This is an example:
	return json.Marshal(k.Metadata)
}

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
