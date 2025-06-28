package local_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tkhq/go-sdk/pkg/store/local"
)

// MacOSX has $HOME set by default.
func TestGetKeyDirPathMacOSX(t *testing.T) {
	t.Setenv("HOME", "/home/dir")

	// Need to unset this explicitly: the test runner has this set by default!
	originalValue := os.Getenv("XDG_CONFIG_HOME")

	require.NoError(t, os.Unsetenv("XDG_CONFIG_HOME"))

	defer func() {
		require.NoError(t, os.Setenv("XDG_CONFIG_HOME", originalValue))
	}()

	assert.Equal(t, "/home/dir/.config/turnkey/keys", local.DefaultAPIKeysDir())
	assert.Equal(t, "/home/dir/.config/turnkey/encryption-keys", local.DefaultEncryptionKeysDir())
}

// On UNIX, we expect XDG_CONFIG_HOME to be set.
// If it's not set, we're back to a MacOSX-like system.
func TestGetKeyDirPathUnix(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/special/dir")
	t.Setenv("HOME", "/home/dir")

	assert.Equal(t, "/special/dir/turnkey/keys", local.DefaultAPIKeysDir())
	assert.Equal(t, "/special/dir/turnkey/encryption-keys", local.DefaultEncryptionKeysDir())
}

// If calling with a path, we should get this back if the path exists.
// If not we should get an error.
func TestGetAPIKeyDirPathOverride(t *testing.T) {
	tmpDir, err := os.MkdirTemp(os.TempDir(), "keys")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, os.RemoveAll(tmpDir))
	}()

	s := local.NewAPIKeyStore()

	require.Error(t, s.SetAPIKeysDirectory("/does/not/exist"))

	require.NoError(t, s.SetAPIKeysDirectory(tmpDir))
}

// If calling with a path, we should get this back if the path exists.
// If not we should get an error.
func TestGetEncryptionKeyDirPathOverride(t *testing.T) {
	tmpDir, err := os.MkdirTemp(os.TempDir(), "encryption-keys")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, os.RemoveAll(tmpDir))
	}()

	s := local.NewEncryptionKeyStore()

	require.Error(t, s.SetEncryptionKeysDirectory("/does/not/exist"))

	require.NoError(t, s.SetEncryptionKeysDirectory(tmpDir))
}
