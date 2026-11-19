package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptSecretToBundle(t *testing.T) {
	const organizationID = "8a1e6f5c-0000-4000-8000-000000000001"

	quorumKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	targetPublicHex, targetPrivate, err := GenerateEncryptionKeyPair()
	require.NoError(t, err)

	targetPublic, err := hex.DecodeString(targetPublicHex)
	require.NoError(t, err)

	quorumPublicKey, err := quorumKey.PublicKey.ECDH()
	require.NoError(t, err)

	signTarget := func(t *testing.T, targetData ServerTargetData) string {
		t.Helper()

		data, err := json.Marshal(targetData)
		require.NoError(t, err)

		signature, err := P256Sign(quorumKey, data)
		require.NoError(t, err)

		bundleBytes, err := json.Marshal(ServerTargetMsgV1{
			Version:             "v1.0.0",
			Data:                data,
			DataSignature:       signature,
			EnclaveQuorumPublic: quorumPublicKey.Bytes(),
		})
		require.NoError(t, err)

		return string(bundleBytes)
	}

	bundle := signTarget(t, ServerTargetData{
		TargetPublic:   targetPublic,
		OrganizationID: organizationID,
	})
	plaintext := []byte("super secret")

	t.Run("organizationMismatch", func(t *testing.T) {
		_, _, err := EncryptSecretToBundle(plaintext, bundle, "0e51e13c-0000-4000-8000-000000000002", nil, nil, &quorumKey.PublicKey)
		require.ErrorContains(t, err, "organization id does not match")
	})

	t.Run("wrongQuorumKey", func(t *testing.T) {
		otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		_, _, err = EncryptSecretToBundle(plaintext, bundle, organizationID, nil, nil, &otherKey.PublicKey)
		require.ErrorContains(t, err, "enclave quorum public keys from client and message do not match")
	})

	t.Run("nonEmptyUserID", func(t *testing.T) {
		privateKeyTarget := signTarget(t, ServerTargetData{
			TargetPublic:   targetPublic,
			OrganizationID: organizationID,
			UserID:         "5f2c9b1d-0000-4000-8000-000000000003",
		})

		_, _, err := EncryptSecretToBundle(plaintext, privateKeyTarget, organizationID, nil, nil, &quorumKey.PublicKey)
		assert.ErrorContains(t, err, "secret import target user id must be empty")
	})

	t.Run("emptyUserID", func(t *testing.T) {
		payload, targetPublicKey, err := EncryptSecretToBundle(plaintext, bundle, organizationID, nil, nil, &quorumKey.PublicKey)
		require.NoError(t, err)
		assert.Equal(t, targetPublicHex, targetPublicKey)

		var clientMsg ClientSendMsg
		require.NoError(t, json.Unmarshal([]byte(payload), &clientMsg))
		require.NotNil(t, clientMsg.EncappedPublic)
		require.NotNil(t, clientMsg.Ciphertext)

		decrypted, err := HPKEDecryptWithPurposeBinding(*clientMsg.EncappedPublic, targetPrivate, *clientMsg.Ciphertext, ImportSecretsPurposeBinding(nil, nil))
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("tamperedSignature", func(t *testing.T) {
		var msg ServerTargetMsgV1
		require.NoError(t, json.Unmarshal([]byte(bundle), &msg))
		msg.Data[len(msg.Data)-1] ^= 0xff

		tampered, err := json.Marshal(msg)
		require.NoError(t, err)

		_, _, err = EncryptSecretToBundle(plaintext, string(tampered), organizationID, nil, nil, &quorumKey.PublicKey)
		require.ErrorContains(t, err, "invalid enclave auth key signature")
	})
}
