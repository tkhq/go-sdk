// Package crypto manages Turnkey encryption keys and cryptographic primitives.
package crypto

import (
	"errors"

	"github.com/cloudflare/circl/kem"
)

// EncryptionKeyMetadata stores non-secret metadata about the encryption key.
type EncryptionKeyMetadata struct {
	Name         string `json:"name"`
	Organization string `json:"organization"`
	User         string `json:"user"`
	PublicKey    string `json:"public_key"`
}

// EncryptionKey defines a structure in which to hold both serialized and ECDH-friendly versions of a Turnkey encryption keypair.
type EncryptionKey struct {
	EncryptionKeyMetadata

	TkPrivateKey string `json:"-"` // do not store the private key in the metadata file
	TkPublicKey  string `json:"public_key"`

	// Underlying KEM keypair
	privateKey *kem.PrivateKey
	publicKey  *kem.PublicKey
}

// FromKemPrivateKey takes a HPKE KEM keypair and forms a Turnkey encryption key from it.
// Assumes that privateKey.Public() has already been derived.
func FromKemPrivateKey(privateKey kem.PrivateKey) (*EncryptionKey, error) {
	if privateKey == nil || privateKey.Public() == nil {
		return nil, errors.New("empty key")
	}

	publicKey := privateKey.Public()

	tkPrivateKey, err := EncodeKEMPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	tkPublicKey, err := EncodeKEMPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	return &EncryptionKey{
		TkPrivateKey: tkPrivateKey,
		TkPublicKey:  tkPublicKey,
		publicKey:    &publicKey,
		privateKey:   &privateKey,
	}, nil
}

// FromTurnkeyEncryptionPrivateKey takes a Turnkey-encoded private key, derives a public key from it, and returns the corresponding Turnkey encryption key.
func FromTurnkeyEncryptionPrivateKey(encodedPrivateKey string) (*EncryptionKey, error) {
	privateKey, err := DecodeKEMPrivateKey(encodedPrivateKey)
	if err != nil {
		return nil, err
	}

	encryptionKey, err := FromKemPrivateKey(*privateKey)
	if err != nil {
		return nil, err
	}

	return encryptionKey, nil
}

// GetCurve returns the curve used.
func (k EncryptionKey) GetCurve() string {
	return ""
}

// GetPublicKey gets the key's public key.
func (k EncryptionKey) GetPublicKey() string {
	return k.TkPublicKey
}

// GetPrivateKey gets the key's private key.
func (k EncryptionKey) GetPrivateKey() string {
	return k.TkPrivateKey
}

// GetMetadata gets the key's metadata.
func (k EncryptionKey) GetMetadata() EncryptionKeyMetadata {
	return k.EncryptionKeyMetadata
}
