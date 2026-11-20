package crypto

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptOtpCodeToBundle(t *testing.T) {
	quorumKey, bundle, _, targetPrivate := newSignedTestTarget(t, "8a1e6f5c-0000-4000-8000-000000000001")
	quorumPublicKey, err := quorumKey.PublicKey.ECDH()
	require.NoError(t, err)

	quorumKeyHex := hex.EncodeToString(quorumPublicKey.Bytes())

	t.Run("roundTrip", func(t *testing.T) {
		message, err := EncryptOtpCodeToBundle("123456", bundle, "02abcd", quorumKeyHex)
		require.NoError(t, err)
		assert.Equal(t, map[string]any{"otp_code": "123456", "public_key": "02abcd"}, decryptTestMessage(t, message, targetPrivate))
	})

	t.Run("productionKeyByDefault", func(t *testing.T) {
		_, err := EncryptOtpCodeToBundle("123456", bundle, "02abcd")
		assert.ErrorContains(t, err, "enclave quorum public keys from client and message do not match")
	})

	t.Run("invalidOverride", func(t *testing.T) {
		_, err := EncryptOtpCodeToBundle("123456", bundle, "02abcd", "not hex")
		assert.ErrorContains(t, err, "failed to decode signer public key")
	})

	t.Run("redactsBundle", func(t *testing.T) {
		attempt := otpAttemptBundle{OtpCode: "OTP_SECRET_SENTINEL", PublicKey: "02abcd"}

		var logs bytes.Buffer
		slog.New(slog.NewTextHandler(&logs, nil)).Info("otp", slog.Any("bundle", attempt))

		for _, rendered := range []string{fmt.Sprint(attempt), fmt.Sprintf("%+v", attempt), logs.String()} {
			assert.Contains(t, rendered, "otpAttemptBundle(<redacted>)")
			assert.NotContains(t, rendered, "OTP_SECRET_SENTINEL")
		}
	})
}
