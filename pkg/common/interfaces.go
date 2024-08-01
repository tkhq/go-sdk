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
