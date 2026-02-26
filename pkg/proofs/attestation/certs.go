package attestation

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// verifyCertificateChain validates the certificate chain against the AWS root cert
func verifyCertificateChain(certificate []byte, cabundle [][]byte, validationTime time.Time) (*x509.Certificate, error) {
	// 1. Parse leaf certificate
	cert, err := x509.ParseCertificate(certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	if cert.PublicKeyAlgorithm != x509.ECDSA {
		return nil, errors.New("certificate must use ECDSA")
	}

	if cert.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		return nil, errors.New("certificate must use ECDSAWithSHA384")
	}

	// 2. Build intermediate certificate pool from CABundle
	intermediates := x509.NewCertPool()
	for i, certDER := range cabundle {
		intermediate, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, fmt.Errorf("failed to parse intermediate cert %d: %w", i, err)
		}
		intermediates.AddCert(intermediate)
	}

	// 3. Create root pool with hardcoded AWS root certificate
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(awsRootCertPEM)) {
		return nil, errors.New("failed to parse AWS root certificate")
	}

	// 4. Verify certificate chain
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   validationTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	chains, err := cert.Verify(opts)
	if err != nil {
		return nil, fmt.Errorf("certificate chain verification failed: %w", err)
	}

	if len(chains) == 0 {
		return nil, errors.New("no valid certificate chains found")
	}

	return cert, nil
}
