// Package common contains key and key metadata interfaces
package common

// IKey defines an interface for API keys and Encryption keys.
type IKey[M IMetadata] interface {
	GetPublicKey() string
	GetPrivateKey() string
	GetMetadata() M
	LoadMetadata(string) (*M, error)
	MergeMetadata(M) error
}

type IMetadata interface {
}
