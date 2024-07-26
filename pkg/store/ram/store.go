// Package ram defines a RAM-based apikey store.
// It is recommended this only be used for testing, because NOTHING IS PERSISTED TO DISK!
package ram

import (
	"errors"
	"sync"

	"github.com/tkhq/go-sdk/pkg/common"
)

// Store implements a VOLATILE RAM-based keystore.
// This should only be used for testing.
type Store[T common.IKey[M], M common.IMetadata] struct {
	s map[string]T

	mu sync.Mutex
}

// Load implements store.Store.
func (s *Store[T, M]) Load(name string) (T, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.s == nil {
		return *new(T), errors.New("key not found")
	}

	key, ok := s.s[name]
	if !ok {
		return *new(T), errors.New("key not found")
	}

	return key, nil
}

// Store implements store.Store.
func (s *Store[T, M]) Store(name string, key T) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.s == nil {
		s.s = make(map[string]T)
	}

	s.s[name] = key

	return nil
}
