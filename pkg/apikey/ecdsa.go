package apikey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"

	dcrec "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

type ecdsaKey struct {
	privKey *ecdsa.PrivateKey
	pubKey  *ecdsa.PublicKey
}

type ecdsaEIP191Key ecdsaKey

func (k *ecdsaKey) sign(msg []byte) (string, error) {
	hash := sha256.Sum256(msg)

	sigBytes, err := ecdsa.SignASN1(rand.Reader, k.privKey, hash[:])
	if err != nil {
		return "", errors.Wrap(err, "failed to generate signature")
	}

	return hex.EncodeToString(sigBytes), nil
}

func (k *ecdsaEIP191Key) sign(msg []byte) (string, error) {
	hash := crypto.Keccak256Hash(
		[]byte("\x19Ethereum Signed Message:\n"),
		[]byte(strconv.Itoa(len(msg))),
		msg,
	)

	sigBytes, err := crypto.Sign(hash[:], k.privKey)
	if err != nil {
		return "", errors.Wrap(err, "failed to generate signature")
	}

	return hex.EncodeToString(sigBytes), nil
}

// TurnkeyECDSAPublicKeyBytes is the expected number of bytes for a public ECDSA
// key.
const TurnkeyECDSAPublicKeyBytes = 33

// EncodePrivateECDSAKey encodes an ECDSA private key into the Turnkey format.
// For now, "Turnkey format" = raw DER form.
func EncodePrivateECDSAKey(privateKey *ecdsa.PrivateKey) string {
	return fmt.Sprintf("%064x", privateKey.D)
}

// EncodePublicECDSAKey encodes an ECDSA public key into the Turnkey format.
// For now, "Turnkey format" = standard compressed form for ECDSA keys.
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

// FromECDSAPrivateKey takes an ECDSA keypair and forms a Turnkey API key from it.
// Assumes that privateKey.PublicKey has already been derived.
func FromECDSAPrivateKey(privateKey *ecdsa.PrivateKey, scheme signatureScheme) (*Key, error) {
	if privateKey == nil || privateKey.PublicKey.X == nil {
		return nil, errors.New("empty key")
	}

	publicKey := &privateKey.PublicKey

	var uk underlyingKey
	switch scheme {
	case SchemeSECP256K1EIP191:
		uk = &ecdsaEIP191Key{
			pubKey:  publicKey,
			privKey: privateKey,
		}
	default:
		uk = &ecdsaKey{
			pubKey:  publicKey,
			privKey: privateKey,
		}
	}

	return &Key{
		TkPrivateKey:  EncodePrivateECDSAKey(privateKey),
		TkPublicKey:   EncodePublicECDSAKey(publicKey),
		underlyingKey: uk,
		scheme:        scheme,
	}, nil
}

// DecodeTurnkeyPublicECDSAKey takes a Turnkey-encoded public key and creates an ECDSA public key.
func DecodeTurnkeyPublicECDSAKey(encodedPublicKey string, scheme signatureScheme) (*ecdsa.PublicKey, error) {
	bytes, err := hex.DecodeString(encodedPublicKey)
	if err != nil {
		return nil, err
	}

	if len(bytes) != TurnkeyECDSAPublicKeyBytes {
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
func newECDSAKey(scheme signatureScheme) (*Key, error) {
	var curve elliptic.Curve

	switch scheme {
	case SchemeP256:
		curve = elliptic.P256()
	case SchemeSECP256K1, SchemeSECP256K1EIP191:
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

// fromTurnkeyECDSAKey instantiates an ApiKey struct using a tk-encoded ECDSA key and scheme.
func fromTurnkeyECDSAKey(encodedPrivateKey string, scheme signatureScheme) (*Key, error) {
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
	case SchemeSECP256K1, SchemeSECP256K1EIP191:
		curve = dcrec.S256()
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
