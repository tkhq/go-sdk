package apikey

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/pkg/errors"
)

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

// newED25519Key generates a new random ed25519 key pair.
func newED25519Key() (*Key, error) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	return FromED25519PrivateKey(privKey)
}

// fromTurnkeyED25519Key extracts an ed25519 private key from a TK-encoded string and uses it to form
// a Turnkey API key.
func fromTurnkeyED25519Key(encodedPrivateKey string) (*Key, error) {
	// Decode the hex string to bytes
	privateKeyBytes, err := hex.DecodeString(encodedPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %v", err)
	}

	// Check if the length of the byte slice is correct
	if len(privateKeyBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key length: expected %d, got %d", ed25519.PrivateKeySize, len(privateKeyBytes))
	}

	// Convert the byte slice to ed25519.PrivateKey and encapsulate in TK struct
	return FromED25519PrivateKey(ed25519.PrivateKey(privateKeyBytes))
}

func signED25519(message []byte, privKey ed25519.PrivateKey) string {
	return hex.EncodeToString(ed25519.Sign(privKey, message))
}
