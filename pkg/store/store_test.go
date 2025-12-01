package store_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tkhq/go-sdk/pkg/apikey"
	"github.com/tkhq/go-sdk/pkg/encryptionkey"
	"github.com/tkhq/go-sdk/pkg/store"
)

func TestNewKeyFactoryAPIKey(t *testing.T) {
	// Create a test API key
	originalKey, err := apikey.New("2a7e29e2-9e92-48c2-98bf-c849c1159bc7", apikey.WithScheme(apikey.SchemeP256))
	require.NoError(t, err)

	// Get the private key data with curve suffix (as stored in files)
	privateKeyData := originalKey.GetPrivateKey() + ":" + originalKey.GetCurve()

	// Test the new KeyFactory approach
	kf := store.NewKeyFactory[*apikey.Key, apikey.Metadata](apikey.Factory{})
	recoveredKey, err := kf.FromTurnkeyPrivateKey(privateKeyData)
	require.NoError(t, err)

	// Verify the recovered key matches the original
	assert.Equal(t, originalKey.GetPublicKey(), recoveredKey.GetPublicKey())
	assert.Equal(t, originalKey.GetCurve(), recoveredKey.GetCurve())
}

func TestNewKeyFactoryEncryptionKey(t *testing.T) {
	// Create a test encryption key
	originalKey, err := encryptionkey.New("93e79c64-001d-4ee3-8235-590e17bb8068", "2a7e29e2-9e92-48c2-98bf-c849c1159bc7")
	require.NoError(t, err)

	// Get the private key data
	privateKeyData := originalKey.GetPrivateKey()

	// Test the new KeyFactory approach
	kf := store.NewKeyFactory[*encryptionkey.Key, encryptionkey.Metadata](encryptionkey.Factory{})
	recoveredKey, err := kf.FromTurnkeyPrivateKey(privateKeyData)
	require.NoError(t, err)

	// Verify the recovered key matches the original
	assert.Equal(t, originalKey.GetPublicKey(), recoveredKey.GetPublicKey())
}

func TestKeyFactoryInvalidData(t *testing.T) {
	// Test with invalid private key data
	kf := store.NewKeyFactory[*apikey.Key, apikey.Metadata](apikey.Factory{})
	_, err := kf.FromTurnkeyPrivateKey("invalid:data")
	require.Error(t, err)
	
	// Test with invalid scheme
	kf2 := store.NewKeyFactory[*apikey.Key, apikey.Metadata](apikey.Factory{})
	_, err = kf2.FromTurnkeyPrivateKey("deadbeef:invalid_scheme")
	require.Error(t, err)
}

func TestDeprecatedKeyFactory(t *testing.T) {
	// Test backward compatibility with deprecated factory
	
	// Create a test API key
	originalKey, err := apikey.New("2a7e29e2-9e92-48c2-98bf-c849c1159bc7", apikey.WithScheme(apikey.SchemeP256))
	require.NoError(t, err)

	// Get the private key data with curve suffix (as stored in files)
	privateKeyData := originalKey.GetPrivateKey() + ":" + originalKey.GetCurve()

	// Test the deprecated KeyFactory approach
	kf := store.DeprecatedKeyFactory[*apikey.Key, apikey.Metadata]{}
	recoveredKey, err := kf.FromTurnkeyPrivateKey(privateKeyData)
	require.NoError(t, err)

	// Verify the recovered key matches the original
	assert.Equal(t, originalKey.GetPublicKey(), recoveredKey.GetPublicKey())
	assert.Equal(t, originalKey.GetCurve(), recoveredKey.GetCurve())
}

func TestDeprecatedKeyFactoryEncryption(t *testing.T) {
	// Test backward compatibility with deprecated factory for encryption keys
	
	// Create a test encryption key
	originalKey, err := encryptionkey.New("93e79c64-001d-4ee3-8235-590e17bb8068", "2a7e29e2-9e92-48c2-98bf-c849c1159bc7")
	require.NoError(t, err)

	// Get the private key data
	privateKeyData := originalKey.GetPrivateKey()

	// Test the deprecated KeyFactory approach
	kf := store.DeprecatedKeyFactory[*encryptionkey.Key, encryptionkey.Metadata]{}
	recoveredKey, err := kf.FromTurnkeyPrivateKey(privateKeyData)
	require.NoError(t, err)

	// Verify the recovered key matches the original
	assert.Equal(t, originalKey.GetPublicKey(), recoveredKey.GetPublicKey())
}