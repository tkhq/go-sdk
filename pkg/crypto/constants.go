package crypto

// Production public keys used for signature verification
const (
	// ProductionNotarizerPublicKey used to verify session JWT signatures with the custom double SHA-256 scheme
	ProductionNotarizerPublicKey = "04d498aa87ac3bf982ac2b5dd9604d0074905cfbda5d62727c5a237b895e6749205e9f7cd566909c4387f6ca25c308445c60884b788560b785f4a96ac33702a469"

	// ProductionOTPVerificationPublicKey used to verify OTP verification tokens with standard ES256 JWT
	ProductionOTPVerificationPublicKey = "037e1d0aecd22e33bf831bcb905d31971013b83d2b3ebb718fba4e58fa5a93019d"
)
