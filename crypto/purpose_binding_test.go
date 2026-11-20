package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Vectors from src/rust/secret/SPEC.md (ingress_aad_v2).
const (
	vectorReceiverPrivate = "1111111111111111111111111111111111111111111111111111111111111111"
	vectorEncappedPublic  = "04d65a93977caa3d1b081852ff57a79e465f1660577304baead505dd3a48589cf350185e895372df6221ea3a137557e473fddb6755f05bd507c3c533fce9c91285"
	vectorCiphertext      = "9afdba7451b5eacebb7e76a45b9860f968263279fb6b3ae3324a570ff48b0e8149dcc7af23a46ce01a319ca760a40f27da4cb738ccb0d5141ad3ce9738ce99d07e7bce10de3b58ee5454"
	vectorBinding         = "00000028454e435259505445445f494e47524553535f505552504f53455f494d504f52545f5345435245545300000009636f72702d616d657800000002000000046b696e640000000b6372656469742d63617264000000146475616c2d6167656e742d636f6e73656e7375730000000474727565"
	vectorPlaintext       = `{"number":"4111111111111111","expiry":"12/30","cvv":"123"}`
)

var vectorProperties = []StaticProperty{{Key: "kind", Value: "credit-card"}, {Key: "dual-agent-consensus", Value: "true"}}

func TestImportSecretsPurposeBindingVector(t *testing.T) {
	name := "corp-amex"
	assert.Equal(t, vectorBinding, hex.EncodeToString(ImportSecretsPurposeBinding(&name, vectorProperties)))

	receiverPrivate, err := DecodeKEMPrivateKey(vectorReceiverPrivate)
	if !assert.NoError(t, err) {
		return
	}

	encappedPublic, err := hex.DecodeString(vectorEncappedPublic)
	assert.NoError(t, err)

	ciphertext, err := hex.DecodeString(vectorCiphertext)
	assert.NoError(t, err)

	plaintext, err := HPKEDecryptWithPurposeBinding(encappedPublic, *receiverPrivate, ciphertext, ImportSecretsPurposeBinding(&name, vectorProperties))
	assert.NoError(t, err)
	assert.Equal(t, vectorPlaintext, string(plaintext))

	other := "corp-visa"

	otherPurpose := append(appendField(nil, "ENCRYPTED_INGRESS_PURPOSE_OAUTH2_AUTHENTICATE"), ImportSecretsPurposeBinding(&name, vectorProperties)[4+len(importSecretsPurpose):]...)
	for _, binding := range [][]byte{
		nil,
		otherPurpose,
		ImportSecretsPurposeBinding(&name, vectorProperties[:1]),
		ImportSecretsPurposeBinding(&other, vectorProperties),
		ImportSecretsPurposeBinding(nil, vectorProperties),
		ImportSecretsPurposeBinding(&name, []StaticProperty{vectorProperties[1], vectorProperties[0]}),
	} {
		_, err = HPKEDecryptWithPurposeBinding(encappedPublic, *receiverPrivate, ciphertext, binding)
		assert.EqualError(t, err, "cipher: message authentication failed")
	}
}
