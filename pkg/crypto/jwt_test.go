package crypto

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestVerifySessionJwtSignature(t *testing.T) {
	tests := []struct {
		name    string
		jwt     string
		wantErr bool
	}{
		{
			name: "valid session JWT",
			//nolint:lll // JWT tokens are long by nature
			jwt: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJleHAiOjE3NDg4NzY4MzcsInB1YmxpY19rZXkiOiIwMzk5ZmUyYWNlNjIwOGFmMGFkZjg0OGY0NGJjNDgyMTBiNTk0YjdlNjllY2Q5MWVjOTY4ZmQ3NWIzYmI0NDgzMzYiLCJzZXNzaW9uX3R5cGUiOiJTRVNTSU9OX1RZUEVfUkVBRF9XUklURSIsInVzZXJfaWQiOiI2OTEyYjgxOS1mNGRmLTQwZjQtYTE5Mi0yMGVlNDMwOTA5NzQiLCJvcmdhbml6YXRpb25faWQiOiJjNzVlY2IwNy1jODRhLTRkZDUtOTMyYy01MzlkZmFmYzY4NjQifQ." +
				"y6LPW1jlTwc9jFcvCwKJoKfleL_vHnGUr5tRVdMFUCnHvDspSPZ3DWK85tf1znCCBFQ6MYaFOl-1FLb0KcFxqQ",
			wantErr: false,
		},
		{
			name:    "invalid format - too few parts",
			jwt:     "header.payload",
			wantErr: true,
		},
		{
			name:    "invalid format - too many parts",
			jwt:     "header.payload.signature.extra",
			wantErr: true,
		},
		{
			name:    "invalid base64 signature",
			jwt:     "header.payload.invalid!!!signature",
			wantErr: true,
		},
		{
			name:    "empty jwt",
			jwt:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifySessionJwtSignature(tt.jwt)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifySessionJwtSignature() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifySessionJwtSignature_WithCustomKey(t *testing.T) {
	invalidKey := "invalid_hex"

	err := VerifySessionJwtSignature("header.payload.signature", invalidKey)
	if err == nil {
		t.Error("Expected error when using invalid hex key, got nil")
	}
}

func TestVerifyOtpVerificationToken(t *testing.T) {
	tests := []struct {
		name    string
		jwt     string
		wantErr bool
	}{
		{
			name: "valid OTP verification token (real Turnkey-signed, expiry bypassed)",
			jwt: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJjb250YWN0IjoidXNlckBleGFtcGxlLmNvbSIsImV4cCI6MTc3MDc1MTgyMSwiaWQiOiI4ZmMxZDQ0NS05ZmI4LTQ3NWQtYWViNy04ZTlkOWY4ZjkwYTUiLCJ2ZXJpZmljYXRpb25fdHlwZSI6Ik9UUF9UWVBFX0VNQUlMIn0." +
				"YorjdeMCvQmjWe680OeWUDXB7LEBFudvGS8R8TP451DACO02MAyAlKOwXOulG9Z422qXMvVqn7mITT2f1hgWwQ",
			wantErr: false,
		},
		{
			name:    "invalid format - too few parts",
			jwt:     "header.payload",
			wantErr: true,
		},
		{
			name:    "empty jwt",
			jwt:     "",
			wantErr: true,
		},
	}

	// Freeze time to 1 second before the test token's expiry (exp: 1770751821).
	// This lets us verify the real Turnkey-signed token against ProductionOTPVerificationPublicKey
	// without needing a live token.
	frozenTime := jwt.WithTimeFunc(func() time.Time {
		return time.Unix(1770751820, 0)
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyOtpVerificationToken(tt.jwt, "", frozenTime)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyOtpVerificationToken() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyOtpVerificationToken_WithCustomKey(t *testing.T) {
	err := VerifyOtpVerificationToken("header.payload.signature", "invalid_hex")
	if err == nil {
		t.Error("Expected error when using invalid hex key, got nil")
	}
}
