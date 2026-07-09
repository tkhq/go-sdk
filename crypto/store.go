package crypto

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"reflect"
	"runtime"
	"strings"
)

// Key defines an interface for API keys and Encryption keys.
type Key[M Metadata] interface {
	GetPublicKey() string
	GetPrivateKey() string
	GetCurve() string
	GetMetadata() M
}

type metadataLoader[M Metadata] interface {
	loadMetadata(fn string) (*M, error)
}

// APIKey implements metadataLoader so the store can load sidecar metadata.
var _ metadataLoader[APIKeyMetadata] = APIKey{}

type metadataMerger[M Metadata] interface {
	mergeMetadata(m M) error
}

// Store provides an interface in which API or Encryption keys may be stored and retrieved.
type Store[T Key[M], M Metadata] interface {
	// Load pulls a key from the store.
	Load(name string) (T, error)

	// Store saves the key to the store.
	Store(name string, key T) error
}

// Metadata defines an interface for the metadata on keys.
type Metadata interface{}

// KeyFactory generic struct to select the correct FromTurnkeyPrivateKey function.
type KeyFactory[T Key[M], M Metadata] struct{}

// FromTurnkeyPrivateKey converts a Turnkey-encoded private key string to a key.
func (kf KeyFactory[T, M]) FromTurnkeyPrivateKey(data string) (T, error) {
	var instance T

	typeOfT := reflect.TypeOf(instance)
	if typeOfT.Kind() == reflect.Ptr {
		typeOfT = typeOfT.Elem()
	}

	if typeOfT == reflect.TypeOf(APIKey{}) {
		keyWithoutSuffix, scheme, err := extractSignatureSchemeFromSuffixedPrivateKey(data)
		if err != nil {
			return instance, err
		}

		key, err := FromTurnkeyPrivateKey(keyWithoutSuffix, scheme)
		if err != nil {
			return instance, err
		}

		result, ok := interface{}(key).(T)
		if !ok {
			return instance, fmt.Errorf("failed to convert crypto.APIKey to %v", reflect.TypeOf(instance))
		}

		return result, nil
	} else if typeOfT == reflect.TypeOf(EncryptionKey{}) {
		key, err := FromTurnkeyEncryptionPrivateKey(data)
		if err != nil {
			return instance, err
		}

		result, ok := interface{}(key).(T)
		if !ok {
			return instance, fmt.Errorf("failed to convert crypto.EncryptionKey to %v", reflect.TypeOf(instance))
		}

		return result, nil
	}

	return instance, fmt.Errorf("unsupported key type: %v", reflect.TypeOf(instance))
}

const (
	// DefaultKeyName is the name of the default API key.
	DefaultKeyName = "default"

	turnkeyDirectoryName        = "turnkey"
	apiKeysDirectoryName        = "keys"
	encryptionKeysDirectoryName = "encryption-keys"
	publicKeyExtension          = "public"
	privateKeyExtension         = "private"
	metadataExtension           = "meta"
	fileOwnerRWGroupRAllR       = 0o0644
	fileOwnerRW                 = 0o0600
)

// LocalStore defines an API key Store using the local filesystem.
type LocalStore[T Key[M], M Metadata] struct {
	// DefaultKeyName is the name of the key to use when none is specified.
	DefaultKeyName string

	// KeyDirectory is the directory in which all the keys and metadata are stored.
	KeyDirectory string
}

// NewLocal provides a new local API key store.
func NewLocal[T Key[M], M Metadata]() *LocalStore[T, M] {
	return &LocalStore[T, M]{
		DefaultKeyName: DefaultKeyName,
		KeyDirectory:   DefaultAPIKeysDir(),
	}
}

// PublicKeyFile returns the filename for the public key of the given name.
func (s *LocalStore[T, M]) PublicKeyFile(name string) string {
	if name == "" {
		name = DefaultKeyName
	}

	return path.Join(s.KeyDirectory, fmt.Sprintf("%s.%s", name, publicKeyExtension))
}

// PrivateKeyFile returns the filename for the private key of the given name.
func (s *LocalStore[T, M]) PrivateKeyFile(name string) string {
	if name == "" {
		name = DefaultKeyName
	}

	return path.Join(s.KeyDirectory, fmt.Sprintf("%s.%s", name, privateKeyExtension))
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
	// Solution: always use `~/.config/turnkey` on macOS when possible
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

// SetAPIKeysDirectory sets the store's key directory, ensuring its existence and writability.
func (s *LocalStore[T, M]) SetAPIKeysDirectory(keysPath string) (err error) {
	if keysPath == "" || keysPath == DefaultAPIKeysDir() {
		keysPath = DefaultAPIKeysDir()

		// NB: we only attempt to create the default directory; never a user-supplied one.
		if err = os.MkdirAll(keysPath, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create API key store location %q: %w", keysPath, err)
		}
	}

	stat, err := os.Stat(keysPath)
	if err != nil {
		return err
	}

	if !stat.IsDir() {
		return fmt.Errorf("API keys directory %q is not a directory", keysPath)
	}

	s.KeyDirectory = keysPath

	return nil
}

// SetEncryptionKeysDirectory sets the store's key directory, ensuring its existence and writability.
func (s *LocalStore[T, M]) SetEncryptionKeysDirectory(keysPath string) (err error) {
	if keysPath == "" || keysPath == DefaultEncryptionKeysDir() {
		keysPath = DefaultEncryptionKeysDir()

		// NB: we only attempt to create the default directory; never a user-supplied one.
		if err = os.MkdirAll(keysPath, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create encryption key store location %q: %w", keysPath, err)
		}
	}

	stat, err := os.Stat(keysPath)
	if err != nil {
		return err
	}

	if !stat.IsDir() {
		return fmt.Errorf("encryption keys directory %q is not a directory", keysPath)
	}

	s.KeyDirectory = keysPath

	return nil
}

// Store saves the key to the local filesystem.
func (s *LocalStore[T, M]) Store(name string, keypair T) error {
	if name == "" {
		name = s.DefaultKeyName
	}

	pubExists, err := checkFileExists(s.PublicKeyFile(name))
	if err != nil {
		return fmt.Errorf("failed to check for existence of public key: %w", err)
	}

	privExists, err := checkFileExists(s.PrivateKeyFile(name))
	if err != nil {
		return fmt.Errorf("failed to check for existence of private key: %w", err)
	}

	if pubExists || privExists {
		return fmt.Errorf("a keypair named %q already exists; exiting", name)
	}

	if err = createKeyFile(s.PublicKeyFile(name), keypair.GetPublicKey(), fileOwnerRWGroupRAllR); err != nil {
		return fmt.Errorf("failed to store public key to file: %w", err)
	}

	privateKeyData := keypair.GetPrivateKey()
	if curve := keypair.GetCurve(); curve != "" {
		privateKeyData = fmt.Sprintf("%s:%s", privateKeyData, curve)
	}

	if err = createKeyFile(s.PrivateKeyFile(name), privateKeyData, fileOwnerRW); err != nil {
		return fmt.Errorf("failed to store private key to file: %w", err)
	}

	if err = s.createMetadataFile(s.metadataFile(name), keypair.GetMetadata(), fileOwnerRW); err != nil {
		return fmt.Errorf("failed to store key metadata: %w", err)
	}

	return nil
}

// Load pulls a key from the local filesystem.
func (s *LocalStore[T, M]) Load(name string) (T, error) {
	keyBytes, keyPath, err := s.loadKeyBytes(name)
	if err != nil {
		return *new(T), fmt.Errorf("failed to load key bytes %q: %w", name, err)
	}

	kf := KeyFactory[T, M]{}

	key, err := kf.FromTurnkeyPrivateKey(string(keyBytes))
	if err != nil {
		return *new(T), fmt.Errorf("failed to recover key from private key file %q: %w", keyPath, err)
	}

	if ok, _ := checkFileExists(s.metadataFile(name)); ok {
		if ml, ok := any(key).(metadataLoader[M]); ok {
			metadata, err := ml.loadMetadata(s.metadataFile(name))
			if err != nil {
				return *new(T), fmt.Errorf("failed to load key metadata from metadata file %q: %w", s.metadataFile(name), err)
			}

			if mm, ok := any(key).(metadataMerger[M]); ok {
				if err := mm.mergeMetadata(*metadata); err != nil {
					return *new(T), fmt.Errorf("failed to merge key metadata with key: %w", err)
				}
			}
		}
	}

	return key, nil
}

func (k *APIKey) mergeMetadata(md APIKeyMetadata) error {
	if k.TkPublicKey != md.PublicKey {
		return fmt.Errorf("metadata public key %q does not match API key public key %q", md.PublicKey, k.TkPublicKey)
	}

	k.APIKeyMetadata = md

	return nil
}

func (k APIKey) loadMetadata(fn string) (*APIKeyMetadata, error) {
	f, err := os.Open(fn)
	if err != nil {
		return nil, fmt.Errorf("failed to open metadata file: %w", err)
	}

	md := new(APIKeyMetadata)
	if err := json.NewDecoder(f).Decode(md); err != nil {
		return nil, fmt.Errorf("failed to decode metadata file: %w", err)
	}

	return md, nil
}

// metadataFile returns the filename for the metadata of the given key name.
func (s *LocalStore[T, M]) metadataFile(name string) string {
	return path.Join(s.KeyDirectory, fmt.Sprintf("%s.%s", name, metadataExtension))
}

func (s *LocalStore[T, M]) loadKeyBytes(name string) ([]byte, string, error) {
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
				return nil, keyPath, fmt.Errorf("failed to load key %q", name)
			}
		}
	}

	bytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, keyPath, fmt.Errorf("failed to read from %q: %w", keyPath, err)
	}

	return bytes, keyPath, err
}

func createKeyFile(path string, content string, mode fs.FileMode) error {
	return os.WriteFile(path, []byte(content), mode)
}

func (s *LocalStore[T, M]) createMetadataFile(path string, metadata M, mode fs.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("failed to create metadata file: %w", err)
	}

	defer f.Close() //nolint: errcheck

	return json.NewEncoder(f).Encode(metadata)
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
