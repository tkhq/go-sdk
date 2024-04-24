package ram_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tkhq/go-sdk/pkg/apikey"
	"github.com/tkhq/go-sdk/pkg/store/ram"
)

func TestStore(t *testing.T) {
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
