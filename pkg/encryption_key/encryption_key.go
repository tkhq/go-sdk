package encryption_key

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

const KemId hpke.KEM = hpke.KEM_P256_HKDF_SHA256

// Metadata stores non-secret metadata about the Encryption key.
type Metadata struct {
	Name         string `json:"name"`
	Organization string `json:"organization"`
	User         string `json:"user"`
	PublicKey    string `json:"public_key"`
}

// Key defines a structure in which to hold both serialized and ecdh-lib-friendly versions of a Turnkey Encryption keypair.
type Key struct {
	Metadata

	TkPrivateKey string `json:"-"` // do not store the private key in the metadata file
	TkPublicKey  string `json:"public_key"`

	// Underlying KEM keypair
	privateKey *kem.PrivateKey
	publicKey  *kem.PublicKey
}

// New generates a new Turnkey encryption key.
func New(userID string, organizationID string) (*Key, error) {
	if userID == "" {
		return nil, fmt.Errorf("please supply a valid User UUID")
	}

	if _, err := uuid.Parse(userID); err != nil {
		return nil, fmt.Errorf("failed to parse user ID")
	}

	if organizationID == "" {
		return nil, fmt.Errorf("please supply a valid Organization UUID")
	}

	if _, err := uuid.Parse(organizationID); err != nil {
		return nil, fmt.Errorf("failed to parse organization ID")
	}

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

// EncodePrivateKey encodes a KEM private key into the Turnkey format.
// For now, "Turnkey format" = raw DER form.
func EncodePrivateKey(privateKey *kem.PrivateKey) string {
	return fmt.Sprintf("%064x", privateKey)
}

// EncodePublicKey encodes a KEM public key into the Turnkey format.
// For now, "Turnkey format" = raw DER form.
func EncodePublicKey(publicKey *kem.PublicKey) string {
	return fmt.Sprintf("%064x", publicKey)
}

// FromKemPrivateKey takes a HPKE KEM keypair and forms a Turnkey encryption key from it.
// Assumes that privateKey.Public() has already been derived.
func FromKemPrivateKey(privateKey kem.PrivateKey) (*Key, error) {
	if privateKey == nil || privateKey.Public() == nil {
		return nil, errors.New("empty key")
	}

	publicKey := privateKey.Public()

	return &Key{
		TkPrivateKey: EncodePrivateKey(&privateKey),
		TkPublicKey:  EncodePublicKey(&publicKey),
		publicKey:    &publicKey,
		privateKey:   &privateKey,
	}, nil
}

// FromTurnkeyPrivateKey takes a Turnkey-encoded private key, derives a public key from it, and then returns the corresponding Turnkey API key.
func FromTurnkeyPrivateKey(encodedPrivateKey string) (*Key, error) {
	bytes, err := hex.DecodeString(encodedPrivateKey)
	if err != nil {
		return nil, err
	}

	privateKey, err := KemId.Scheme().UnmarshalBinaryPrivateKey(bytes)
	if err != nil {
		return nil, err
	}

	encryptionKey, err := FromKemPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	return encryptionKey, nil
}

// DecodeTurnkeyPublicKey takes a Turnkey-encoded public key and creates a KEM public key.
func DecodeTurnkeyPublicKey(encodedPublicKey string) (*kem.PublicKey, error) {
	bytes, err := hex.DecodeString(encodedPublicKey)
	if err != nil {
		return nil, err
	}

	publicKey, err := KemId.Scheme().UnmarshalBinaryPublicKey(bytes)
	if err != nil {
		return nil, err
	}

	return &publicKey, nil
}

func (k Key) GetPublicKey() string {
	return k.TkPublicKey
}

func (k Key) GetPrivateKey() string {
	return k.TkPrivateKey
}

func (k Key) SerializeMetadata() (string, error) {
	jsonBytes, err := json.Marshal(k.Metadata)
	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
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

// MergeMetadata merges the given metadata with the api key.
func (k Key) MergeMetadata(md Metadata) error {
	if k.TkPublicKey != md.PublicKey {
		return errors.Errorf("metadata public key %q does not match encryption key public key %q", md.PublicKey, k.TkPublicKey)
	}

	k.Metadata.Name = md.Name
	k.Metadata.Organization = md.Organization
	k.Metadata.PublicKey = md.PublicKey
	k.Metadata.User = md.User

	return nil
}
