// Package store defines a key storage interface.
package store

import (
	"github.com/pkg/errors"

	"github.com/tkhq/go-sdk/pkg/apikey"
	"github.com/tkhq/go-sdk/pkg/common"
	"github.com/tkhq/go-sdk/pkg/encryptionkey"
)

// Store provides an interface in which API or Encryption keys may be stored and retrieved.
type Store[T common.IKey[M], M common.IMetadata] interface {
	// Load pulls a key from the store.
	Load(name string) (T, error)

	// Store saves the key to the store.
	Store(name string, key common.IKey[M]) error
}

// KeyFactory is a generic factory that wraps a concrete TurnkeyKeyFactory implementation.
// This eliminates the need for reflection by using the strategy pattern with generics.
type KeyFactory[T common.IKey[M], M common.IMetadata] struct {
	factory common.TurnkeyKeyFactory[T, M]
}

// NewKeyFactory creates a new KeyFactory with the provided concrete factory implementation.
func NewKeyFactory[T common.IKey[M], M common.IMetadata](factory common.TurnkeyKeyFactory[T, M]) KeyFactory[T, M] {
	return KeyFactory[T, M]{factory: factory}
}

// FromTurnkeyPrivateKey converts a Turnkey-encoded private key string to a key.
// This method delegates to the concrete factory implementation, eliminating reflection.
func (kf KeyFactory[T, M]) FromTurnkeyPrivateKey(data string) (T, error) {
	return kf.factory.FromTurnkeyPrivateKey(data)
}

// DeprecatedKeyFactory is the old reflection-based factory for backward compatibility.
// Deprecated: Use NewKeyFactory with concrete factory implementations instead.
type DeprecatedKeyFactory[T common.IKey[M], M common.IMetadata] struct{}

// FromTurnkeyPrivateKey converts a Turnkey-encoded private key string to a key using reflection.
// Deprecated: Use NewKeyFactory with concrete factory implementations instead.
func (kf DeprecatedKeyFactory[T, M]) FromTurnkeyPrivateKey(data string) (T, error) {
	// For backward compatibility, detect the type and delegate to the appropriate factory
	var instance T
	
	// Create the appropriate factory based on the concrete type
	if _, ok := any(instance).(*apikey.Key); ok {
		factory := NewKeyFactory[T, M](any(apikey.Factory{}).(common.TurnkeyKeyFactory[T, M]))
		return factory.FromTurnkeyPrivateKey(data)
	}
	
	if _, ok := any(instance).(*encryptionkey.Key); ok {
		factory := NewKeyFactory[T, M](any(encryptionkey.Factory{}).(common.TurnkeyKeyFactory[T, M]))
		return factory.FromTurnkeyPrivateKey(data)
	}
	
	var zero T
	return zero, errors.New("unsupported key type: use NewKeyFactory with appropriate concrete factory")
}
