package crypto

import "github.com/cloudflare/circl/hpke"

// Production public keys used for signature verification
const (
	// ProductionNotarizerPublicKey used to verify session JWT signatures with the custom double SHA-256 scheme
	ProductionNotarizerPublicKey = "04d498aa87ac3bf982ac2b5dd9604d0074905cfbda5d62727c5a237b895e6749205e9f7cd566909c4387f6ca25c308445c60884b788560b785f4a96ac33702a469"

	// ProductionLegacyVerificationTokenPublicKey used to verify OTP verification tokens with standard ES256 JWT
	ProductionLegacyVerificationTokenPublicKey = "037e1d0aecd22e33bf831bcb905d31971013b83d2b3ebb718fba4e58fa5a93019d"

	// ProductionTLSFetcherSigningPublicKey is the production TLS Fetcher enclave quorum signing key.
	// It is used to verify the encryptionTargetBundle returned by INIT_OTP before HPKE-encrypting
	// the OTP attempt to the enclave
	ProductionTLSFetcherSigningPublicKey = "046b4f88421f76b6ba418afc2ea1d8ced671337d7db6b80478a60d8531bf8f17fa9a512f0fef96fc0c9b4cd9dff70b34992e520ce04c79d931f6ff6296b547d201"

	// SignerProductionPublicKey is the enclave quorum public key.
	SignerProductionPublicKey = "04cf288fe433cc4e1aa0ce1632feac4ea26bf2f5a09dcfe5a42c398e06898710330f0572882f4dbdf0f5304b8fc8703acd69adca9a4bbf7f5d00d20a5e364b2569"
)

const (
	// Consult the rust implementations README for how these should be configured.
	// See [here](../../../rust/enclave_encrypt/README.md#hpke-configuration)
	// KemID is the KEM used by Turnkey enclave HPKE messages.
	KemID hpke.KEM = hpke.KEM_P256_HKDF_SHA256
	// KdfID is the KDF used by Turnkey enclave HPKE messages.
	KdfID hpke.KDF = hpke.KDF_HKDF_SHA256
	// AeadID is the AEAD used by Turnkey enclave HPKE messages.
	AeadID hpke.AEAD = hpke.AEAD_AES256GCM
	// TurnkeyHPKEInfo is the HPKE info value used by Turnkey enclave messages.
	TurnkeyHPKEInfo = "turnkey_hpke"
)
