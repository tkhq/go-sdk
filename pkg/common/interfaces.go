package common

// IKey defines an interface for API keys and Encryption keys.
type IKey interface {
	GetPublicKey() string
	GetPrivateKey() string
	SerializeMetadata() ([]byte, error)
	LoadMetadata(string) (*IMetadata, error)
	MergeMetadata(md *IMetadata) error
}

type IMetadata interface {
}
