package turnkey

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudflare/circl/kem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tkhq/go-sdk/crypto"
)

// secretsMockEnclave creates signed import and export bundles with a test quorum key.
type secretsMockEnclave struct {
	t         *testing.T
	quorumKey *ecdsa.PrivateKey
}

func newSecretsMockEnclave(t *testing.T) *secretsMockEnclave {
	t.Helper()

	quorumKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return &secretsMockEnclave{t: t, quorumKey: quorumKey}
}

func (e *secretsMockEnclave) signedBundle(payload any) string {
	data, err := json.Marshal(payload)
	require.NoError(e.t, err)

	signature, err := crypto.P256Sign(e.quorumKey, data)
	require.NoError(e.t, err)

	quorumPublicKey, err := e.quorumKey.PublicKey.ECDH()
	require.NoError(e.t, err)

	bundle, err := json.Marshal(crypto.ServerTargetMsgV1{
		Version:             "v1.0.0",
		Data:                data,
		DataSignature:       signature,
		EnclaveQuorumPublic: quorumPublicKey.Bytes(),
	})
	require.NoError(e.t, err)

	return string(bundle)
}

// targetBundle returns a signed ingress bundle and its private key.
func (e *secretsMockEnclave) targetBundle(organizationID string) (string, kem.PrivateKey) {
	targetPublicHex, kemPrivate, err := crypto.GenerateEncryptionKeyPair()
	require.NoError(e.t, err)

	targetPublic, err := hex.DecodeString(targetPublicHex)
	require.NoError(e.t, err)

	return e.signedBundle(crypto.ServerTargetData{
		TargetPublic:   targetPublic,
		OrganizationID: organizationID,
	}), kemPrivate
}

// exportBundle encrypts to the client's target key and signs the result.
func (e *secretsMockEnclave) exportBundle(plaintext []byte, targetPublicKeyHex, organizationID string) string {
	targetPublic, err := hex.DecodeString(targetPublicKeyHex)
	require.NoError(e.t, err)

	kemPublic, err := crypto.KemID.Scheme().UnmarshalBinaryPublicKey(targetPublic)
	require.NoError(e.t, err)

	ciphertext, encappedPublic, err := crypto.HPKEEncrypt(&kemPublic, plaintext)
	require.NoError(e.t, err)

	return e.signedBundle(crypto.ServerSendData{
		EncappedPublic: encappedPublic,
		Ciphertext:     ciphertext,
		OrganizationID: organizationID,
	})
}

func completedActivity(resultField string, result any) map[string]any {
	return map[string]any{
		"activity": map[string]any{
			"id":     "11111111-1111-4111-8111-111111111111",
			"status": string(ActivityStatusCompleted),
			"result": map[string]any{resultField: result},
		},
	}
}

func newSecretsTestClient(t *testing.T, baseURL, organizationID string) *Client {
	t.Helper()

	stamper, err := NewAPIKeyStamper(testPrivateKey(t))
	require.NoError(t, err)

	client, err := NewClient(stamper, organizationID, WithBaseURL(baseURL))
	require.NoError(t, err)

	return client
}

func TestSecretWrappersImportSecret(t *testing.T) {
	const organizationID = "8a1e6f5c-0000-4000-8000-000000000001"

	enclave := newSecretsMockEnclave(t)
	bundle, targetKey := enclave.targetBundle(organizationID)

	var importedParams []ImportSecretParams

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/public/v1/submit/init_import_secrets":
			require.NoError(t, json.NewEncoder(w).Encode(completedActivity("initImportSecretsResult", InitImportSecretsResult{
				EnclaveTargetMessages: []string{bundle},
			})))
		case "/public/v1/submit/import_secrets":
			var body struct {
				Parameters ImportSecretsIntent `json:"parameters"`
			}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			importedParams = body.Parameters.Secrets

			require.NoError(t, json.NewEncoder(w).Encode(completedActivity("importSecretsResult", ImportSecretsResult{
				SecretIds: []string{"22222222-2222-4222-8222-222222222222"},
			})))
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := newSecretsTestClient(t, server.URL, organizationID)

	name := "wrapped-secret"
	plaintext := []byte("wrapper plaintext")

	secretID, err := client.ImportSecret(context.Background(), organizationID, &name, plaintext,
		map[string]string{"kind": "test", "environment": "sandbox"}, &enclave.quorumKey.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, "22222222-2222-4222-8222-222222222222", secretID)

	// Decrypt the submitted payload to verify the imported plaintext.
	require.Len(t, importedParams, 1)
	require.Len(t, importedParams[0].StaticProperties, 2)
	assert.Equal(t, []string{"environment", "kind"}, []string{*importedParams[0].StaticProperties[0].Key, *importedParams[0].StaticProperties[1].Key})
	assert.Equal(t, []string{"sandbox", "test"}, []string{*importedParams[0].StaticProperties[0].Value, *importedParams[0].StaticProperties[1].Value})

	var msg crypto.ClientSendMsg
	require.NoError(t, json.Unmarshal([]byte(importedParams[0].SecretPayload), &msg))

	decrypted, err := crypto.HPKEDecrypt(*msg.EncappedPublic, targetKey, *msg.Ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestSecretWrappersExportSecret(t *testing.T) {
	const organizationID = "8a1e6f5c-0000-4000-8000-000000000001"

	const secretID = "33333333-3333-4333-8333-333333333333"

	enclave := newSecretsMockEnclave(t)
	plaintext := []byte("export plaintext")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/public/v1/submit/export_secrets", r.URL.Path)

		var body struct {
			Parameters ExportSecretsIntent `json:"parameters"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Len(t, body.Parameters.Secrets, 1)

		param := body.Parameters.Secrets[0]
		require.Equal(t, secretID, param.SecretID)

		require.NoError(t, json.NewEncoder(w).Encode(completedActivity("exportSecretsResult", ExportSecretsResult{
			SecretPayloads: []string{enclave.exportBundle(plaintext, param.TargetPublicKey, organizationID)},
		})))
	}))
	defer server.Close()

	client := newSecretsTestClient(t, server.URL, organizationID)

	exported, err := client.ExportSecret(context.Background(), organizationID, secretID, &enclave.quorumKey.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, plaintext, exported)
}
