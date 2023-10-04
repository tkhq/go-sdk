// Package ram defines a RAM-based apikey store.
// It is recommended this only be used for testing, because NOTHING IS PERSISTED TO DISK!
package ram

import (
	"errors"
	"sync"

	"github.com/tkhq/go-sdk/pkg/apikey"
)

// Store implements a VOLATILE RAM-based keystore.
// This should only be used for testing.
type Store struct {
	s map[string]*apikey.Key

	mu sync.Mutex
}

// Load implements store.Store.
func (s *Store) Load(name string) (*apikey.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.s == nil {
		return nil, errors.New("key not found")
	}

	key, ok := s.s[name]
	if !ok {
		return nil, errors.New("key not found")
	}

	return key, nil
}

// Store implements store.Store.
func (s *Store) Store(name string, key *apikey.Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.s == nil {
		s.s = make(map[string]*apikey.Key)
	}

	s.s[name] = key

	return nil
}
