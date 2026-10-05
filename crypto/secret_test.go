package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncryptSecretToBundle(t *testing.T) {
	const organizationID = "8a1e6f5c-0000-4000-8000-000000000001"

	quorumKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	targetPublicHex, _, err := GenerateEncryptionKeyPair()
	require.NoError(t, err)

	targetPublic, err := hex.DecodeString(targetPublicHex)
	require.NoError(t, err)

	data, err := json.Marshal(ServerTargetData{
		TargetPublic:   targetPublic,
		OrganizationID: organizationID,
	})
	require.NoError(t, err)

	signature, err := P256Sign(quorumKey, data)
	require.NoError(t, err)

	quorumPublicKey, err := quorumKey.PublicKey.ECDH()
	require.NoError(t, err)

	bundleBytes, err := json.Marshal(ServerTargetMsgV1{
		Version:             "v1.0.0",
		Data:                data,
		DataSignature:       signature,
		EnclaveQuorumPublic: quorumPublicKey.Bytes(),
	})
	require.NoError(t, err)

	bundle := string(bundleBytes)
	plaintext := []byte("super secret")

	t.Run("organizationMismatch", func(t *testing.T) {
		_, _, err := EncryptSecretToBundle(plaintext, bundle, "0e51e13c-0000-4000-8000-000000000002", &quorumKey.PublicKey)
		require.ErrorContains(t, err, "organization id does not match")
	})

	t.Run("wrongQuorumKey", func(t *testing.T) {
		otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		_, _, err = EncryptSecretToBundle(plaintext, bundle, organizationID, &otherKey.PublicKey)
		require.ErrorContains(t, err, "enclave quorum public keys from client and message do not match")
	})

	t.Run("tamperedSignature", func(t *testing.T) {
		var msg ServerTargetMsgV1
		require.NoError(t, json.Unmarshal([]byte(bundle), &msg))
		msg.Data[len(msg.Data)-1] ^= 0xff

		tampered, err := json.Marshal(msg)
		require.NoError(t, err)

		_, _, err = EncryptSecretToBundle(plaintext, string(tampered), organizationID, &quorumKey.PublicKey)
		require.ErrorContains(t, err, "invalid enclave auth key signature")
	})
}
