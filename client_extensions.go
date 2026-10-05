package turnkey

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/tkhq/go-sdk/crypto"
)

// SendSignedRequest sends a POST request with a signed body and decodes the response into T.
// For activity requests, it polls until the activity reaches a terminal status before decoding.
func SendSignedRequest[T any](ctx context.Context, c *Client, sr *SignedRequest) (*T, error) {
	if sr.Stamp == nil {
		return nil, errors.New("SignedRequest requires a Stamp")
	}

	respBody, err := c.postWithRetry(ctx, sr.URL, "", []byte(sr.Body), sr.Stamp, nil)
	if err != nil {
		return nil, err
	}

	var data map[string]any
	if err := json.Unmarshal(respBody, &data); err != nil {
		return nil, err
	}

	if sr.Type == RequestTypeActivity {
		if err := c.resolveActivityInResponse(ctx, data); err != nil {
			return nil, err
		}
	}

	respBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	var result T
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// resolveActivityInResponse re-marshals the "activity" field of a signed-request
// response, polls to terminal status if needed, and replaces it in data.
func (c *Client) resolveActivityInResponse(ctx context.Context, data map[string]any) error {
	activityData, ok := data["activity"].(map[string]any)
	if !ok {
		return nil
	}

	activityBytes, err := json.Marshal(activityData)
	if err != nil {
		return err
	}

	var activity Activity
	if err := json.Unmarshal(activityBytes, &activity); err != nil {
		return err
	}

	if _, done, err := classifyActivity(&activity); err != nil {
		return err
	} else if done {
		return nil
	}

	final, err := c.waitActivity(ctx, activity.ID)
	if err != nil {
		return err
	}

	data["activity"] = final

	return nil
}

// ImportSecret verifies the enclave signature and org, encrypts one secret, and returns its ID.
// signerKey overrides the production quorum key (non-production only).
func (c *Client) ImportSecret(ctx context.Context, organizationID string, name *string, plaintext []byte, staticProperties map[string]string, signerKey ...*ecdsa.PublicKey) (string, error) {
	organizationID, err := c.organizationID(organizationID)
	if err != nil {
		return "", err
	}

	initRes, err := c.InitImportSecrets(ctx, InitImportSecretsRequest{
		OrganizationID:  organizationID,
		EncryptionSuite: TransportEncryptionSuiteEnclaveEncryptV1,
		NumSecrets:      1,
	})
	if err != nil {
		return "", fmt.Errorf("failed to init import secret: %w", err)
	}

	targetBundle, err := exactlyOne(initRes.EnclaveTargetMessages, "enclave target message")
	if err != nil {
		return "", err
	}

	payload, targetPublicKey, err := crypto.EncryptSecretToBundle(plaintext, targetBundle, organizationID, signerKey...)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt secret to target bundle: %w", err)
	}

	importRes, err := c.ImportSecrets(ctx, ImportSecretsRequest{
		OrganizationID: organizationID,
		Secrets: []ImportSecretParams{{
			Name:             name,
			SecretPayload:    payload,
			TargetPublicKey:  targetPublicKey,
			EncryptionSuite:  TransportEncryptionSuiteEnclaveEncryptV1,
			StaticProperties: keyValuesFromMap(staticProperties),
		}},
	})
	if err != nil {
		return "", fmt.Errorf("failed to import secret: %w", err)
	}

	return exactlyOne(importRes.SecretIds, "imported secret id")
}

// ExportSecret uses a fresh target key, verifies the enclave signature and org, and decrypts one secret.
// signerKey overrides the production quorum key (non-production only).
func (c *Client) ExportSecret(ctx context.Context, organizationID, secretID string, signerKey ...*ecdsa.PublicKey) ([]byte, error) {
	organizationID, err := c.organizationID(organizationID)
	if err != nil {
		return nil, err
	}

	targetPublicKey, kemPrivate, err := crypto.GenerateEncryptionKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate export target key: %w", err)
	}

	exportRes, err := c.ExportSecrets(ctx, ExportSecretsRequest{
		OrganizationID: organizationID,
		Secrets: []ExportSecretParams{{
			SecretID:        secretID,
			TargetPublicKey: targetPublicKey,
			EncryptionSuite: TransportEncryptionSuiteEnclaveEncryptV1,
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to export secret: %w", err)
	}

	payload, err := exactlyOne(exportRes.SecretPayloads, "exported secret payload")
	if err != nil {
		return nil, err
	}

	plaintext, err := crypto.DecryptExportBundle([]byte(payload), organizationID, kemPrivate, signerKey...)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret payload: %w", err)
	}

	return plaintext, nil
}

// exactlyOne returns the sole element of items, with a descriptive error otherwise.
func exactlyOne[T any](items []T, what string) (T, error) {
	if len(items) != 1 {
		var zero T
		return zero, fmt.Errorf("expected exactly one %s, got %d", what, len(items))
	}

	return items[0], nil
}

// keyValuesFromMap converts a map to KeyValue pairs sorted by key.
func keyValuesFromMap(m map[string]string) []KeyValue {
	out := make([]KeyValue, 0, len(m))
	for _, k := range slices.Sorted(maps.Keys(m)) {
		key, value := k, m[k]
		out = append(out, KeyValue{Key: &key, Value: &value})
	}

	return out
}
