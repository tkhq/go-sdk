package common

// IKey defines an interface for API keys and Encryption keys.
type IKey[M IMetadata] interface {
	GetPublicKey() string
	GetPrivateKey() string
	SerializeMetadata() (string, error)
	LoadMetadata(string) (*M, error)
	MergeMetadata(M) error
}

type IMetadata interface {
}
