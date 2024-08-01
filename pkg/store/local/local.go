// Package local provides a keystore based on a local directory.
package local

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"runtime"
	"strings"

	"github.com/pkg/errors"

	"github.com/tkhq/go-sdk/pkg/common"
	"github.com/tkhq/go-sdk/pkg/store"
)

const (
	// DefaultKeyName is the name of the default API key.
	DefaultKeyName = "default"

	turnkeyDirectoryName        = "turnkey"
	apiKeysDirectoryName        = "keys"
	encryptionKeysDirectoryName = "encryption-keys"
	publicKeyExtension          = "public"
	privateKeyExtension         = "private"
	metadataExtension           = "meta"
)

// Store defines an api key Store using the local filesystem.
type Store[T common.IKey[M], M common.IMetadata] struct {
	// DefaultKeyName is the name of the key to use when none is specified.
	// Normally, this is simply "default".
	DefaultKeyName string

	// KeyDirectory is the directory in which all the keys and metadata are stored.
	// Normally, this will simply be the user/system default.
	KeyDirectory string
}

// New provides a new local API key store.
// keyDirectory is optional, and if it is the empty string, the system default will be used.
func New[T common.IKey[M], M common.IMetadata]() *Store[T, M] {
	return &Store[T, M]{
		DefaultKeyName: DefaultKeyName,
		KeyDirectory:   DefaultAPIKeysDir(),
	}
}

// PublicKeyFile returns the filename for the public key of the given name.
func (s *Store[T, M]) PublicKeyFile(name string) string {
	if name == "" {
		name = DefaultKeyName
	}

	return path.Join(s.KeyDirectory, fmt.Sprintf("%s.%s", name, publicKeyExtension))
}

// PrivateKeyFile returns the filename for the private key of the given name.
func (s *Store[T, M]) PrivateKeyFile(name string) string {
	if name == "" {
		name = DefaultKeyName
	}

	return path.Join(s.KeyDirectory, fmt.Sprintf("%s.%s", name, privateKeyExtension))
}

// MetadataFile returns the filename for the metadata of the given key name.
func (s *Store[T, M]) MetadataFile(name string) string {
	return path.Join(s.KeyDirectory, fmt.Sprintf("%s.%s", name, metadataExtension))
}

// DeprecatedDefaultAPIKeysDir checks the deprecated location of API keys on macOS;
// returns the full path if it exists on disk.
// `~/Library/Application Support/turnkey/keys/`.
func DeprecatedDefaultAPIKeysDir() string {
	if runtime.GOOS != "darwin" {
		return ""
	}

	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}

	keysDir := path.Join(cfgDir, turnkeyDirectoryName, apiKeysDirectoryName)

	exists, _ := checkFolderExists(keysDir) //nolint: errcheck

	if !exists {
		return ""
	}

	return keysDir
}

// DefaultAPIKeysDir returns the default directory for API key storage for the user's system.
func DefaultAPIKeysDir() string {
	return path.Join(getConfigDir(), turnkeyDirectoryName, apiKeysDirectoryName)
}

// DefaultEncryptionKeysDir returns the default directory for encryption key storage for the user's system.
func DefaultEncryptionKeysDir() string {
	return path.Join(getConfigDir(), turnkeyDirectoryName, encryptionKeysDirectoryName)
}

func getConfigDir() string {
	var cfgDir string

	shouldUseHomeDir := false

	// The default `UserConfigDir` in golang doesn't make sense on macOS
	// https://github.com/golang/go/issues/29960#issuecomment-505321146
	// Solution: always use `~/.config/turkey` on macOS when possible
	if runtime.GOOS == "darwin" {
		if os.Getenv("XDG_CONFIG_HOME") != "" {
			cfgDir = os.Getenv("XDG_CONFIG_HOME")
		} else {
			shouldUseHomeDir = true
		}
	} else {
		var err error

		cfgDir, err = os.UserConfigDir()

		if err != nil {
			shouldUseHomeDir = true
		}
	}

	if shouldUseHomeDir {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "."
		}

		return path.Join(homeDir, ".config")
	}

	return cfgDir
}

// SetAPIKeysDirectory sets the clifs root directory, ensuring its existence and writability.
func (s *Store[T, M]) SetAPIKeysDirectory(keysPath string) (err error) {
	if keysPath == "" || keysPath == DefaultAPIKeysDir() {
		keysPath = DefaultAPIKeysDir()

		// NB: we only attempt to create the default directory; never a user-supplied one.
		if err = os.MkdirAll(keysPath, os.ModePerm); err != nil {
			return errors.Wrapf(err, "failed to create API key store location %q", keysPath)
		}
	}

	stat, err := os.Stat(keysPath)
	if err != nil {
		return err
	}

	if !stat.IsDir() {
		return errors.Errorf("API keys directory %q is not a directory", keysPath)
	}

	s.KeyDirectory = keysPath

	return nil
}

// SetEncryptionKeysDirectory sets the clifs root directory, ensuring its existence and writability.
func (s *Store[T, M]) SetEncryptionKeysDirectory(keysPath string) (err error) {
	if keysPath == "" || keysPath == DefaultEncryptionKeysDir() {
		keysPath = DefaultEncryptionKeysDir()

		// NB: we only attempt to create the default directory; never a user-supplied one.
		if err = os.MkdirAll(keysPath, os.ModePerm); err != nil {
			return errors.Wrapf(err, "failed to create encryption key store location %q", keysPath)
		}
	}

	stat, err := os.Stat(keysPath)
	if err != nil {
		return err
	}

	if !stat.IsDir() {
		return errors.Errorf("Encryption keys directory %q is not a directory", keysPath)
	}

	s.KeyDirectory = keysPath

	return nil
}

// Store implements store.Store.
func (s *Store[T, M]) Store(name string, keypair common.IKey[M]) error {
	if name == "" {
		name = s.DefaultKeyName
	}

	pubExists, err := checkFileExists(s.PublicKeyFile(name))
	if err != nil {
		return errors.Wrap(err, "failed to check for existence of public key")
	}

	privExists, err := checkFileExists(s.PrivateKeyFile(name))
	if err != nil {
		return errors.Wrap(err, "failed to check for existence of private key")
	}

	if pubExists || privExists {
		return errors.Errorf("a keypair named %q already exists; exiting", name)
	}

	if err = createKeyFile(s.PublicKeyFile(name), keypair.GetPublicKey(), 0o0644); err != nil {
		return errors.Wrap(err, "failed to store public key to file")
	}

	privateKeyData := keypair.GetPrivateKey()
	if curve := keypair.GetCurve(); curve != "" {
		privateKeyData = fmt.Sprintf("%s:%s", privateKeyData, curve)
	}
	if err = createKeyFile(s.PrivateKeyFile(name), privateKeyData, 0o0600); err != nil {
		return errors.Wrap(err, "failed to store private key to file")
	}

	if err = s.createMetadataFile(s.MetadataFile(name), keypair.GetMetadata(), 0o0600); err != nil {
		return errors.Wrap(err, "failed to store key metadata")
	}

	return nil
}

// Load implements store.Store.
func (s *Store[T, M]) Load(name string) (T, error) {
	keyBytes, keyPath, err := s.loadKeyBytes(name)
	if err != nil {
		return *new(T), errors.Wrapf(err, "failed to load key bytes %q", name)
	}

	kf := store.KeyFactory[T, M]{}

	key, err := kf.FromTurnkeyPrivateKey(string(keyBytes))
	if err != nil {
		return *new(T), errors.Wrapf(err, "failed to recover key from private key file %q", keyPath)
	}

	if ok, _ := checkFileExists(s.MetadataFile(name)); ok { //nolint: errcheck
		metadata, err := key.LoadMetadata(s.MetadataFile(name))
		if err != nil {
			return *new(T), errors.Wrapf(err, "failed to load key metadata from metadata file %q", s.MetadataFile(name))
		}

		if err := key.MergeMetadata(*metadata); err != nil {
			return *new(T), errors.Wrap(err, "failed to merge key metadata with key")
		}
	}

	return key, nil
}

func (s *Store[T, M]) loadKeyBytes(name string) ([]byte, string, error) {
	if name == "" {
		name = s.DefaultKeyName
	}

	keyPath := s.PrivateKeyFile(name)

	// If we are given an explicit path, try to use it directly, rather than as the key name.
	if strings.Contains(name, "/") {
		keyPath = strings.TrimSuffix(name, "."+privateKeyExtension)

		exists, _ := checkFileExists(keyPath) //nolint: errcheck
		if !exists {
			keyPath = keyPath + "." + privateKeyExtension

			exists, _ = checkFileExists(keyPath) //nolint: errcheck
			if !exists {
				return nil, keyPath, errors.Errorf("failed to load key %q", name)
			}
		}
	}

	bytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, keyPath, errors.Wrapf(err, "failed to read from %q", keyPath)
	}

	return bytes, keyPath, err
}

func createKeyFile(path string, content string, mode fs.FileMode) error {
	return os.WriteFile(path, []byte(content), mode)
}

func (s *Store[T, M]) createMetadataFile(path string, metadata M, mode fs.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return errors.Wrap(err, "failed to create metadata file")
	}

	defer f.Close() //nolint: errcheck

	return json.NewEncoder(f).Encode(metadata)
}

func checkFolderExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}

	if err != nil {
		return false, err
	}

	return true, nil
}

// checkFileExists checks that the given file exists and has a non-zero size.
func checkFileExists(path string) (bool, error) {
	stat, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}

	if err != nil {
		return false, err
	}

	if stat.Size() < 1 {
		return false, fmt.Errorf("file %q is empty", path)
	}

	return true, nil
}
