package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	turnkey "github.com/tkhq/go-sdk/v2"
)

func TestMarshalAndSignTokenUsageUsesDeterministicRawP256Signature(t *testing.T) {
	const (
		finalOrganizationID = "org-final"
		clientPublicKey     = "client-public-key"
		tokenID             = "token-id"
	)

	privateKey := deterministicP256PrivateKey(t)
	usage := tokenUsageForOTPLogin(
		tokenID,
		turnkey.OTPLoginRequest{
			OrganizationID: finalOrganizationID,
			PublicKey:      clientPublicKey,
		},
	)
	entropy := bytes.Repeat([]byte{0x42}, 64)

	message, signature, err := marshalAndSignTokenUsage(
		bytes.NewReader(entropy),
		privateKey,
		usage,
	)
	require.NoError(t, err)
	secondMessage, secondSignature, err := marshalAndSignTokenUsage(
		bytes.NewReader(entropy),
		privateKey,
		usage,
	)
	require.NoError(t, err)
	assert.Equal(t, message, secondMessage)
	assert.Equal(t, signature, secondSignature)

	signatureBytes, err := hex.DecodeString(signature)
	require.NoError(t, err)
	require.Len(t, signatureBytes, 64)

	hash := sha256.Sum256(message)
	r := new(big.Int).SetBytes(signatureBytes[:32])
	s := new(big.Int).SetBytes(signatureBytes[32:])
	assert.True(
		t,
		ecdsa.Verify(&privateKey.PublicKey, hash[:], r, s),
		"raw P-256 signature did not verify",
	)
}

func deterministicP256PrivateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(
		elliptic.P256(),
		bytes.NewReader(bytes.Repeat([]byte{0x07}, 64)),
	)
	require.NoError(t, err)

	return privateKey
}
