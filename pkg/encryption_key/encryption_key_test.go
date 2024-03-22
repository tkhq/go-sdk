package encryption_key_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tkhq/go-sdk/pkg/encryption_key"
)

func Test_EncodedKeySizeIsFixed(t *testing.T) {
	for i := 0; i < 1000; i++ {
		encryptionKey, err := encryption_key.New(uuid.NewString(), uuid.NewString())
		require.NoError(t, err)

		assert.Len(t, encryptionKey.TkPublicKey, 66, "attempt %d: expected 66 characters for public key %s", i, encryptionKey.TkPublicKey)
		assert.Len(t, encryptionKey.TkPrivateKey, 64, "attempt %d: expected 64 characters for private key %s", i, encryptionKey.TkPrivateKey)
	}
}
