// Package common contains key and key metadata interfaces
package common

// IKey defines an interface for API keys and Encryption keys.
type IKey[M IMetadata] interface {
	GetPublicKey() string
	GetPrivateKey() string
	GetCurve() string
	GetMetadata() M
	LoadMetadata(s string) (*M, error)
	MergeMetadata(m M) error
}

// IMetadata defines an interface for the metadata on keys.
type IMetadata interface{}

// TurnkeyKeyFactory defines an interface for creating keys from Turnkey private key data.
// This interface eliminates the need for reflection-based type switching.
type TurnkeyKeyFactory[T IKey[M], M IMetadata] interface {
	FromTurnkeyPrivateKey(data string) (T, error)
}
