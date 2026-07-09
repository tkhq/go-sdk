package turnkey

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tkcrypto "github.com/tkhq/go-sdk/crypto"
)

func TestP256Stamper_RoundTrip(t *testing.T) {
	key, err := tkcrypto.NewAPIKey(tkcrypto.WithScheme(tkcrypto.SchemeP256))
	require.NoError(t, err)

	stamper, err := NewAPIKeyStamper(key.GetPrivateKey())
	require.NoError(t, err)

	body := []byte(`{"hello":"world"}`)
	stamp, err := stamper.Stamp(context.Background(), body)
	require.NoError(t, err)

	assert.Equal(t, "X-Stamp", stamp.HeaderName)

	jsonBytes, err := base64.RawURLEncoding.DecodeString(stamp.HeaderValue)
	require.NoError(t, err)

	var decoded apiStamp
	require.NoError(t, json.Unmarshal(jsonBytes, &decoded))

	assert.Equal(t, key.GetPublicKey(), decoded.PublicKey)
	assert.Equal(t, string(tkcrypto.SchemeP256), decoded.Scheme)
	assert.NotEmpty(t, decoded.Signature)

	pubKey, err := tkcrypto.DecodePublicECDSAKey(decoded.PublicKey, tkcrypto.SchemeP256)
	require.NoError(t, err)

	sigBytes, err := hex.DecodeString(decoded.Signature)
	require.NoError(t, err)

	hash := sha256.Sum256(body)
	assert.True(t, ecdsa.VerifyASN1(pubKey, hash[:], sigBytes), "signature did not verify against public key")
}

func TestSECP256K1Stamper_RoundTrip(t *testing.T) {
	key, err := tkcrypto.NewAPIKey(tkcrypto.WithScheme(tkcrypto.SchemeSECP256K1))
	require.NoError(t, err)

	stamper, err := NewAPIKeyStamper(key.GetPrivateKey(), WithSignatureScheme(tkcrypto.SchemeSECP256K1))
	require.NoError(t, err)

	body := []byte(`{"hello":"world"}`)
	stamp, err := stamper.Stamp(context.Background(), body)
	require.NoError(t, err)

	assert.Equal(t, "X-Stamp", stamp.HeaderName)

	jsonBytes, err := base64.RawURLEncoding.DecodeString(stamp.HeaderValue)
	require.NoError(t, err)

	var decoded apiStamp
	require.NoError(t, json.Unmarshal(jsonBytes, &decoded))

	assert.Equal(t, key.GetPublicKey(), decoded.PublicKey)
	assert.Equal(t, string(tkcrypto.SchemeSECP256K1), decoded.Scheme)
	assert.NotEmpty(t, decoded.Signature)

	pubKey, err := tkcrypto.DecodePublicECDSAKey(decoded.PublicKey, tkcrypto.SchemeSECP256K1)
	require.NoError(t, err)

	sigBytes, err := hex.DecodeString(decoded.Signature)
	require.NoError(t, err)

	hash := sha256.Sum256(body)
	assert.True(t, ecdsa.VerifyASN1(pubKey, hash[:], sigBytes), "signature did not verify against public key")
}

func TestED25519Stamper_RoundTrip(t *testing.T) {
	key, err := tkcrypto.NewAPIKey(tkcrypto.WithScheme(tkcrypto.SchemeED25519))
	require.NoError(t, err)

	stamper, err := NewAPIKeyStamper(key.GetPrivateKey(), WithSignatureScheme(tkcrypto.SchemeED25519))
	require.NoError(t, err)

	body := []byte(`{"hello":"world"}`)
	stamp, err := stamper.Stamp(context.Background(), body)
	require.NoError(t, err)

	assert.Equal(t, "X-Stamp", stamp.HeaderName)

	jsonBytes, err := base64.RawURLEncoding.DecodeString(stamp.HeaderValue)
	require.NoError(t, err)

	var decoded apiStamp
	require.NoError(t, json.Unmarshal(jsonBytes, &decoded))

	assert.Equal(t, key.GetPublicKey(), decoded.PublicKey)
	assert.Equal(t, string(tkcrypto.SchemeED25519), decoded.Scheme)
	assert.NotEmpty(t, decoded.Signature)

	pubKeyBytes, err := hex.DecodeString(decoded.PublicKey)
	require.NoError(t, err)
	require.Len(t, pubKeyBytes, ed25519.PublicKeySize)

	sigBytes, err := hex.DecodeString(decoded.Signature)
	require.NoError(t, err)

	assert.True(t, ed25519.Verify(ed25519.PublicKey(pubKeyBytes), body, sigBytes), "signature did not verify against public key")
}

func TestStamper_InvalidPrivateKey(t *testing.T) {
	_, err := NewAPIKeyStamper("invalidkey", WithSignatureScheme(tkcrypto.SchemeED25519))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid API key")
}

func TestDefaultScheme(t *testing.T) {
	key, err := tkcrypto.NewAPIKey()
	require.NoError(t, err)

	stamper, err := NewAPIKeyStamper(key.GetPrivateKey())
	require.NoError(t, err)

	body := []byte(`{"hello":"world"}`)
	stamp, err := stamper.Stamp(context.Background(), body)
	require.NoError(t, err)

	assert.Equal(t, "X-Stamp", stamp.HeaderName)

	jsonBytes, err := base64.RawURLEncoding.DecodeString(stamp.HeaderValue)
	require.NoError(t, err)

	var decoded apiStamp
	require.NoError(t, json.Unmarshal(jsonBytes, &decoded))

	assert.Equal(t, key.GetPublicKey(), decoded.PublicKey)
	assert.Equal(t, string(tkcrypto.SchemeP256), decoded.Scheme)
	assert.NotEmpty(t, decoded.Signature)
}

func TestAPIKeyStamper_PublicKey(t *testing.T) {
	key, err := tkcrypto.NewAPIKey()
	require.NoError(t, err)

	stamper, err := NewAPIKeyStamper(key.GetPrivateKey())
	require.NoError(t, err)

	assert.Equal(t, key.GetPublicKey(), stamper.PublicKey())
}
