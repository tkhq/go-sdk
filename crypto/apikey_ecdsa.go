//nolint:staticcheck
//lint:file-ignore SA1019 secp256k1 needs an elliptic.Curve (only dcrec.S256 provides one)
package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	dcrec "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type ecdsaKey struct {
	privKey *ecdsa.PrivateKey
	pubKey  *ecdsa.PublicKey
}

func (k *ecdsaKey) sign(msg []byte) (string, error) {
	hash := sha256.Sum256(msg)

	sigBytes, err := ecdsa.SignASN1(rand.Reader, k.privKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to generate signature: %w", err)
	}

	return hex.EncodeToString(sigBytes), nil
}

// ECDSAPublicKeyBytes is the expected number of bytes for a public ECDSA key.
const ECDSAPublicKeyBytes = 33

// EncodePrivateECDSAKey encodes an ECDSA private key
func EncodePrivateECDSAKey(privateKey *ecdsa.PrivateKey) string {
	return fmt.Sprintf("%064x", privateKey.D)
}

// EncodePublicECDSAKey encodes an ECDSA public key.
func EncodePublicECDSAKey(publicKey *ecdsa.PublicKey) string {
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

// FromECDSAPrivateKey takes an ECDSA keypair and forms an API key from it.
// Assumes that privateKey.PublicKey has already been derived.
func FromECDSAPrivateKey(privateKey *ecdsa.PrivateKey, scheme SignatureScheme) (*APIKey, error) {
	if privateKey == nil || privateKey.X == nil {
		return nil, errors.New("empty key")
	}

	publicKey := &privateKey.PublicKey

	uk := ecdsaKey{
		pubKey:  publicKey,
		privKey: privateKey,
	}

	return &APIKey{
		TkPrivateKey:  EncodePrivateECDSAKey(privateKey),
		TkPublicKey:   EncodePublicECDSAKey(publicKey),
		underlyingKey: &uk,
		scheme:        scheme,
	}, nil
}

// DecodePublicECDSAKey takes a public key and creates an ECDSA public key.
func DecodePublicECDSAKey(encodedPublicKey string, scheme SignatureScheme) (*ecdsa.PublicKey, error) {
	bytes, err := hex.DecodeString(encodedPublicKey)
	if err != nil {
		return nil, err
	}

	if len(bytes) != ECDSAPublicKeyBytes {
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
		curve = dcrec.S256()

		pubkey, err := dcrec.ParsePubKey(bytes)
		if err != nil {
			return nil, errors.New("cannot parse bytes into secp256k1 public key")
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

// newECDSAKey creates a new ECDSA private key.
func newECDSAKey(scheme SignatureScheme) (*APIKey, error) {
	var curve elliptic.Curve

	switch scheme {
	case SchemeP256:
		curve = elliptic.P256()
	case SchemeSECP256K1:
		curve = dcrec.S256()
	default:
		// should be unreachable since scheme type is non-exported with discreet options
		return nil, fmt.Errorf("invalid signature scheme type: %s", scheme)
	}

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	return FromECDSAPrivateKey(privateKey, scheme)
}

// fromECDSAKey instantiates an ApiKey struct using a tk-encoded ECDSA key and scheme.
func fromECDSAKey(encodedPrivateKey string, scheme SignatureScheme) (*APIKey, error) {
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
		curve = dcrec.S256()
	default:
		// should be unreachable since scheme type is non-exported with discreet options
		return nil, fmt.Errorf("invalid signature scheme type: %s", scheme)
	}

	privateKey.Curve = curve
	privateKey.X, privateKey.Y = curve.ScalarBaseMult(privateKey.D.Bytes())

	apiKey, err := FromECDSAPrivateKey(&privateKey, scheme)
	if err != nil {
		return nil, err
	}

	return apiKey, nil
}
