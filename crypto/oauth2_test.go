package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"

	"github.com/cloudflare/circl/kem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newSignedTestTarget returns a quorum key, a target bundle it signed for organizationID, and the target's key pair.
func newSignedTestTarget(t *testing.T, organizationID string) (*ecdsa.PrivateKey, string, string, kem.PrivateKey) {
	t.Helper()

	quorumKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	targetPublicHex, targetPrivate, err := GenerateEncryptionKeyPair()
	require.NoError(t, err)

	targetPublic, err := hex.DecodeString(targetPublicHex)
	require.NoError(t, err)

	data, err := json.Marshal(ServerTargetData{TargetPublic: targetPublic, OrganizationID: organizationID})
	require.NoError(t, err)

	signature, err := P256Sign(quorumKey, data)
	require.NoError(t, err)

	quorumPublicKey, err := quorumKey.PublicKey.ECDH()
	require.NoError(t, err)

	bundle, err := json.Marshal(ServerTargetMsgV1{
		Version:             "v1.0.0",
		Data:                data,
		DataSignature:       signature,
		EnclaveQuorumPublic: quorumPublicKey.Bytes(),
	})
	require.NoError(t, err)

	return quorumKey, string(bundle), targetPublicHex, targetPrivate
}

// decryptTestMessage opens ClientSendMsg JSON with the target's private key.
func decryptTestMessage(t *testing.T, message string, targetPrivate kem.PrivateKey) map[string]any {
	t.Helper()

	var sent ClientSendMsg
	require.NoError(t, json.Unmarshal([]byte(message), &sent))

	plaintext, err := HPKEDecrypt(*sent.EncappedPublic, targetPrivate, *sent.Ciphertext)
	require.NoError(t, err)

	var decrypted map[string]any
	require.NoError(t, json.Unmarshal(plaintext, &decrypted))

	return decrypted
}

func TestEncryptOAuth2ToBundle(t *testing.T) {
	const organizationID = "8a1e6f5c-0000-4000-8000-000000000001"

	quorumKey, bundle, targetPublicHex, targetPrivate := newSignedTestTarget(t, organizationID)
	payload := OAuth2AuthenticationBundle{
		OrganizationID:     organizationID,
		OAuth2CredentialID: "10000000-0000-4000-8000-000000000001",
		ClientID:           "client-app",
		Provider:           "OAUTH2_PROVIDER_DISCORD",
		AuthCode:           "AUTH_CODE_SECRET_SENTINEL",
		CodeVerifier:       "PKCE_VERIFIER_SECRET_SENTINEL",
		RedirectURI:        "https://client.example/callback",
		Nonce:              "a3f1",
	}

	t.Run("roundTrip", func(t *testing.T) {
		for _, bearerTokenTargetPublicKey := range []string{"", targetPublicHex} {
			payload := payload
			payload.BearerTokenTargetPublicKey = bearerTokenTargetPublicKey

			message, targetKey, err := EncryptOAuth2ToBundle(payload, bundle, &quorumKey.PublicKey)
			require.NoError(t, err)
			assert.Equal(t, targetPublicHex, targetKey)

			expected := map[string]any{
				"organization_id":      organizationID,
				"oauth2_credential_id": payload.OAuth2CredentialID,
				"client_id":            payload.ClientID,
				"provider":             payload.Provider,
				"auth_code":            payload.AuthCode,
				"code_verifier":        payload.CodeVerifier,
				"redirect_uri":         payload.RedirectURI,
				"nonce":                payload.Nonce,
			}
			if bearerTokenTargetPublicKey != "" {
				expected["bearer_token_target_public_key"] = bearerTokenTargetPublicKey
			}

			assert.Equal(t, expected, decryptTestMessage(t, message, targetPrivate))
		}
	})

	t.Run("productionKeyByDefault", func(t *testing.T) {
		_, _, err := EncryptOAuth2ToBundle(payload, bundle)
		assert.ErrorContains(t, err, "enclave quorum public keys from client and message do not match")
	})

	t.Run("organizationMismatch", func(t *testing.T) {
		payload := payload
		payload.OrganizationID = "0e51e13c-0000-4000-8000-000000000002"

		_, _, err := EncryptOAuth2ToBundle(payload, bundle, &quorumKey.PublicKey)
		assert.ErrorContains(t, err, "organization id does not match")
	})

	t.Run("tamperedSignature", func(t *testing.T) {
		var msg ServerTargetMsgV1
		require.NoError(t, json.Unmarshal([]byte(bundle), &msg))
		msg.Data[len(msg.Data)-1] ^= 0xff

		tampered, err := json.Marshal(msg)
		require.NoError(t, err)

		_, _, err = EncryptOAuth2ToBundle(payload, string(tampered), &quorumKey.PublicKey)
		assert.ErrorContains(t, err, "invalid enclave auth key signature")
	})

	t.Run("redactsPayload", func(t *testing.T) {
		var logs bytes.Buffer
		slog.New(slog.NewTextHandler(&logs, nil)).Info("oauth", slog.Any("payload", payload))

		for _, rendered := range []string{fmt.Sprint(payload), fmt.Sprintf("%+v", payload), logs.String()} {
			assert.Contains(t, rendered, "OAuth2AuthenticationBundle(<redacted>)")
			assert.NotContains(t, rendered, "SECRET_SENTINEL")
		}
	})
}
