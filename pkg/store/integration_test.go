package store_test

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tkhq/go-sdk/pkg/apikey"
	"github.com/tkhq/go-sdk/pkg/encryptionkey"
	"github.com/tkhq/go-sdk/pkg/store/local"
	"github.com/tkhq/go-sdk/pkg/store/ram"
)

func TestLocalStoreAPIKeyIntegration(t *testing.T) {
	// Create a temporary directory for the test
	tmpDir, err := os.MkdirTemp(os.TempDir(), "api-keys-test")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, os.RemoveAll(tmpDir))
	}()

	// Create a store and configure it to use the temp directory
	store := local.NewAPIKeyStore()
	require.NoError(t, store.SetAPIKeysDirectory(tmpDir))

	// Generate a test API key
	originalKey, err := apikey.New("2a7e29e2-9e92-48c2-98bf-c849c1159bc7", apikey.WithScheme(apikey.SchemeP256))
	require.NoError(t, err)
	originalKey.Name = "test-key"
	
	// Ensure the metadata is properly set
	originalKey.Metadata.PublicKey = originalKey.GetPublicKey()
	originalKey.Metadata.Scheme = string(apikey.SchemeP256)

	// Store the key
	require.NoError(t, store.Store("test-key", originalKey))

	// Load the key back
	loadedKey, err := store.Load("test-key")
	require.NoError(t, err)

	// Verify all fields match
	assert.Equal(t, originalKey.GetPublicKey(), loadedKey.GetPublicKey())
	assert.Equal(t, originalKey.GetPrivateKey(), loadedKey.GetPrivateKey())
	assert.Equal(t, originalKey.GetCurve(), loadedKey.GetCurve())
	assert.Equal(t, originalKey.Name, loadedKey.Name)
	assert.Equal(t, originalKey.Organizations, loadedKey.Organizations)

	// Verify files were created
	assert.FileExists(t, path.Join(tmpDir, "test-key.public"))
	assert.FileExists(t, path.Join(tmpDir, "test-key.private"))
	assert.FileExists(t, path.Join(tmpDir, "test-key.meta"))
}

func TestLocalStoreEncryptionKeyIntegration(t *testing.T) {
	// Create a temporary directory for the test
	tmpDir, err := os.MkdirTemp(os.TempDir(), "encryption-keys-test")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, os.RemoveAll(tmpDir))
	}()

	// Create a store and configure it to use the temp directory
	store := local.NewEncryptionKeyStore()
	require.NoError(t, store.SetEncryptionKeysDirectory(tmpDir))

	// Generate a test encryption key
	originalKey, err := encryptionkey.New("93e79c64-001d-4ee3-8235-590e17bb8068", "2a7e29e2-9e92-48c2-98bf-c849c1159bc7")
	require.NoError(t, err)
	originalKey.Name = "test-encryption-key"
	
	// Ensure the metadata is properly set
	originalKey.Metadata.PublicKey = originalKey.GetPublicKey()

	// Store the key
	require.NoError(t, store.Store("test-encryption-key", originalKey))

	// Load the key back
	loadedKey, err := store.Load("test-encryption-key")
	require.NoError(t, err)

	// Verify all fields match
	assert.Equal(t, originalKey.GetPublicKey(), loadedKey.GetPublicKey())
	assert.Equal(t, originalKey.GetPrivateKey(), loadedKey.GetPrivateKey())
	assert.Equal(t, originalKey.Name, loadedKey.Name)
	assert.Equal(t, originalKey.User, loadedKey.User)
	assert.Equal(t, originalKey.Organization, loadedKey.Organization)

	// Verify files were created
	assert.FileExists(t, path.Join(tmpDir, "test-encryption-key.public"))
	assert.FileExists(t, path.Join(tmpDir, "test-encryption-key.private"))
	assert.FileExists(t, path.Join(tmpDir, "test-encryption-key.meta"))
}

func TestRAMStoreAPIKeyIntegration(t *testing.T) {
	// Create a RAM store
	store := new(ram.Store[*apikey.Key, apikey.Metadata])

	// Generate a test API key
	originalKey, err := apikey.New("2a7e29e2-9e92-48c2-98bf-c849c1159bc7", apikey.WithScheme(apikey.SchemeSECP256K1))
	require.NoError(t, err)
	originalKey.Name = "test-ram-key"

	// Store the key
	require.NoError(t, store.Store("test-ram-key", originalKey))

	// Load the key back
	loadedKey, err := store.Load("test-ram-key")
	require.NoError(t, err)

	// Verify all fields match (should be same object since it's in RAM)
	assert.Equal(t, originalKey.GetPublicKey(), loadedKey.GetPublicKey())
	assert.Equal(t, originalKey.GetPrivateKey(), loadedKey.GetPrivateKey())
	assert.Equal(t, originalKey.GetCurve(), loadedKey.GetCurve())
	assert.Equal(t, originalKey.Name, loadedKey.Name)
	assert.Equal(t, originalKey.Organizations, loadedKey.Organizations)
}

func TestRAMStoreEncryptionKeyIntegration(t *testing.T) {
	// Create a RAM store
	store := new(ram.Store[*encryptionkey.Key, encryptionkey.Metadata])

	// Generate a test encryption key
	originalKey, err := encryptionkey.New("93e79c64-001d-4ee3-8235-590e17bb8068", "2a7e29e2-9e92-48c2-98bf-c849c1159bc7")
	require.NoError(t, err)
	originalKey.Name = "test-ram-encryption-key"

	// Store the key
	require.NoError(t, store.Store("test-ram-encryption-key", originalKey))

	// Load the key back
	loadedKey, err := store.Load("test-ram-encryption-key")
	require.NoError(t, err)

	// Verify all fields match (should be same object since it's in RAM)
	assert.Equal(t, originalKey.GetPublicKey(), loadedKey.GetPublicKey())
	assert.Equal(t, originalKey.GetPrivateKey(), loadedKey.GetPrivateKey())
	assert.Equal(t, originalKey.Name, loadedKey.Name)
	assert.Equal(t, originalKey.User, loadedKey.User)
	assert.Equal(t, originalKey.Organization, loadedKey.Organization)
}

func TestErrorHandling(t *testing.T) {
	// Test loading from non-existent RAM store
	ramStore := new(ram.Store[*apikey.Key, apikey.Metadata])
	_, err := ramStore.Load("non-existent")
	require.Error(t, err)

	// Test loading from non-existent local store
	localStore := local.NewAPIKeyStore()
	_, err = localStore.Load("non-existent")
	require.Error(t, err)
}