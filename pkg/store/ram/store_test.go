package ram_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tkhq/go-sdk/pkg/apikey"
	"github.com/tkhq/go-sdk/pkg/encryptionkey"
	"github.com/tkhq/go-sdk/pkg/store/ram"
)

func TestApiKeyStore(t *testing.T) {
	s := new(ram.Store[apikey.Key, apikey.Metadata])

	key, err := apikey.New("2a7e29e2-9e92-48c2-98bf-c849c1159bc7")
	require.NoError(t, err)
	assert.NotNil(t, key)

	require.NoError(t, s.Store("test", key))

	retrievedKey, err := s.Load("test")
	require.NoError(t, err)
	assert.Equal(t, key.Name, retrievedKey.Name)
	assert.Equal(t, key.Organizations[0], retrievedKey.Organizations[0])
	assert.Equal(t, key.PublicKey, retrievedKey.PublicKey)
}

func TestEncryptionKeyStore(t *testing.T) {
	s := new(ram.Store[encryptionkey.Key, encryptionkey.Metadata])

	key, err := encryptionkey.New("93e79c64-001d-4ee3-8235-590e17bb8068", "2a7e29e2-9e92-48c2-98bf-c849c1159bc7")
	require.NoError(t, err)
	assert.NotNil(t, key)

	require.NoError(t, s.Store("test", key))

	retrievedKey, err := s.Load("test")
	require.NoError(t, err)
	assert.Equal(t, key.Name, retrievedKey.Name)
	assert.Equal(t, key.User, retrievedKey.User)
	assert.Equal(t, key.Organization, retrievedKey.Organization)
	assert.Equal(t, key.PublicKey, retrievedKey.PublicKey)
}
