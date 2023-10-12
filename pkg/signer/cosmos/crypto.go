package cosmos

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"log"
	"math/big"
)

func verifyECDSASignature(msg []byte, sig []byte, pubKey []byte) bool {
	hashedMessage := sha256.Sum256(msg)

	publicKey, err := x509.ParsePKIXPublicKey(pubKey)
	if err != nil {
		return false
	}

	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return false
	}

	r, s, err := unmarshalECDSASignature(sig)
	if err != nil {
		log.Fatal(err)
	}

	return ecdsa.Verify(ecdsaPublicKey, hashedMessage[:], r, s)
}

func unmarshalECDSASignature(sig []byte) (*big.Int, *big.Int, error) {
	type ecdsaSignature struct {
		R, S *big.Int
	}

	var rs ecdsaSignature
	_, err := asn1.Unmarshal(sig, &rs)
	if err != nil {
		return nil, nil, err
	}
	return rs.R, rs.S, nil
}
