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
	require.NoError(t, os.Setenv("HOME", "/home/dir"))

	defer func() {
		require.NoError(t, os.Unsetenv("HOME"))
	}()

	// Need to unset this explicitly: the test runner has this set by default!
	originalValue := os.Getenv("XDG_CONFIG_HOME")

	require.NoError(t, os.Unsetenv("XDG_CONFIG_HOME"))

	defer func() {
		require.NoError(t, os.Setenv("XDG_CONFIG_HOME", originalValue))
	}()

	dir := local.DefaultKeysDir()
	assert.Equal(t, "/home/dir/.config/turnkey/keys", dir)
}

// On UNIX, we expect XDG_CONFIG_HOME to be set.
// If it's not set, we're back to a MacOSX-like system.
func TestGetKeyDirPathUnix(t *testing.T) {
	require.NoError(t, os.Setenv("XDG_CONFIG_HOME", "/special/dir"))

	defer func() {
		require.NoError(t, os.Unsetenv("XDG_CONFIG_HOME"))
	}()

	require.NoError(t, os.Setenv("HOME", "/home/dir"))

	defer func() {
		require.NoError(t, os.Unsetenv("HOME"))
	}()

	dir := local.DefaultKeysDir()
	assert.Equal(t, "/special/dir/turnkey/keys", dir)
}

// If calling with a path, we should get this back if the path exists.
// If not we should get an error.
func TestGetKeyDirPathOverride(t *testing.T) {
	tmpDir, err := os.MkdirTemp(os.TempDir(), "keys")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, os.RemoveAll(tmpDir))
	}()

	s := local.New()

	require.Error(t, s.SetKeysDirectory("/does/not/exist"))

	require.NoError(t, s.SetKeysDirectory(tmpDir))
}
