// Package store defines a key storage interface.
package store

import (
	"reflect"

	"github.com/pkg/errors"
	"github.com/tkhq/go-sdk/pkg/apikey"
	"github.com/tkhq/go-sdk/pkg/common"
	"github.com/tkhq/go-sdk/pkg/encryption_key"
)

// Store provides an interface in which API or Encryption keys may be stored and retrieved.
type Store[T common.IKey] interface {
	// Load pulls a key from the store.
	Load(name string) (T, error)

	// Store saves the key to the store.
	Store(name string, key common.IKey) error
}

// KeyFactory generic struct to select the correct FromTurnkeyPrivateKey function
type KeyFactory[T common.IKey] struct{}

func (kf KeyFactory[T]) FromTurnkeyPrivateKey(data string) (T, error) {
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
		return *(interface{}(key).(*T)), nil
	} else if typeOfT == reflect.TypeOf(encryption_key.Key{}) {
		key, err := encryption_key.FromTurnkeyPrivateKey(data)
		if err != nil {
			return instance, err
		}
		// Same automatic conversion to T applies here.
		return *(interface{}(key).(*T)), nil
	}

	return instance, errors.Errorf("unsupported key type: %v", reflect.TypeOf(instance))
}
