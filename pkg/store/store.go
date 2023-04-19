// Package to encapsulate CLI filesystem operations
package store

import (
	"github.com/tkhq/go-sdk/pkg/apikey"
	"github.com/tkhq/go-sdk/pkg/store/local"
)

// Store provides an interface in which API keys may be stored and retrieved.
type Store interface {
	// Load pulls an API key from the store.
	Load(name string) (*apikey.Key, error)

	// Store saves the API key to the store.
	Store(name string, key *apikey.Key) error
}

// Default is the default API key store.
var Default Store

func init() {
	Default = local.New()
}
