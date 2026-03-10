package crypto

// Production public keys used for signature verification
const (
	// ProductionNotarizerPublicKey used to verify session JWT signatures with the custom double SHA-256 scheme
	ProductionNotarizerPublicKey = "04d498aa87ac3bf982ac2b5dd9604d0074905cfbda5d62727c5a237b895e6749205e9f7cd566909c4387f6ca25c308445c60884b788560b785f4a96ac33702a469"

	// ProductionOTPVerificationPublicKey used to verify OTP verification tokens with standard ES256 JWT
	ProductionOTPVerificationPublicKey = "037e1d0aecd22e33bf831bcb905d31971013b83d2b3ebb718fba4e58fa5a93019d"

	// ProductionTLSFetcherSigningPublicKey is the production TLS Fetcher enclave quorum signing key.
	// It is used to verify the encryptionTargetBundle returned by INIT_OTP before HPKE-encrypting
	// the OTP attempt to the enclave
	ProductionTLSFetcherSigningPublicKey = "046b4f88421f76b6ba418afc2ea1d8ced671337d7db6b80478a60d8531bf8f17fa9a512f0fef96fc0c9b4cd9dff70b34992e520ce04c79d931f6ff6296b547d201"
)
