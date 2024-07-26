// Package store defines a key storage interface.
package store

import (
	"reflect"

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

// KeyFactory generic struct to select the correct FromTurnkeyPrivateKey function.
type KeyFactory[T common.IKey[M], M common.IMetadata] struct{}

// FromTurnkeyPrivateKey converts a Turnkey-encoded private key string to a key.
func (kf KeyFactory[T, M]) FromTurnkeyPrivateKey(data string) (T, error) {
	var instance T

	// Determine type T and call the corresponding FromTurnkeyPrivateKey function
	typeOfT := reflect.TypeOf(instance)
	if typeOfT.Kind() == reflect.Ptr {
		typeOfT = typeOfT.Elem()
	}

	if typeOfT == reflect.TypeOf(apikey.Key{}) {
		key, err := apikey.FromTurnkeyPrivateKey(data)
		if err != nil {
			return instance, err
		}
		// Since T is an interface, we need to return the concrete type that implements T.
		// The conversion to T happens automatically if the concrete type satisfies T.
		return (interface{}(key).(T)), nil
	} else if typeOfT == reflect.TypeOf(encryptionkey.Key{}) {
		key, err := encryptionkey.FromTurnkeyPrivateKey(data)
		if err != nil {
			return instance, err
		}
		// Same automatic conversion to T applies here.
		return (interface{}(key).(T)), nil
	}

	return instance, errors.Errorf("unsupported key type: %v", reflect.TypeOf(instance))
}
