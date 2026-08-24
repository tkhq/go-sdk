package crypto

import (
	"testing"

	"github.com/stretchr/testify/require"

	tkencoding "github.com/tkhq/go-sdk/encoding"
)

func TestDecryptCredentialBundleRejectsInvalidCompressedPublicKey(t *testing.T) {
	payload := make([]byte, 33)
	payload[0] = 0x04 // Compressed P-256 points must start with 0x02 or 0x03.
	credentialBundle := tkencoding.Bs58CheckEncode(payload)

	require.NotPanics(t, func() {
		_, err := DecryptCredentialBundle(credentialBundle, nil)
		require.ErrorContains(t, err, "invalid compressed P-256 public key")
	})
}
