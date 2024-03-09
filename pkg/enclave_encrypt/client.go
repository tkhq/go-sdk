package enclave_encrypt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"

	"github.com/btcsuite/btcutil/base58"
	"github.com/cloudflare/circl/kem"
)

// An instance of the client side for enclave encrypt protocol. This should only be used for either
// a SINGLE send or a single receive.
type EnclaveEncryptClient struct {
	enclaveAuthKey *ecdsa.PublicKey
	targetPrivate  kem.PrivateKey
}

// Create a client from the quorum public key.
func NewEnclaveEncryptClient(enclaveAuthKey *ecdsa.PublicKey) (*EnclaveEncryptClient, error) {
	_, targetPrivate, err := KemId.Scheme().GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	return &EnclaveEncryptClient{
		enclaveAuthKey,
		targetPrivate,
	}, nil
}

// Create a client from the quorum public key and target key pair.
func NewEnclaveEncryptClientFromTargetKey(enclaveAuthKey *ecdsa.PublicKey, targetPrivateKey *kem.PrivateKey) (*EnclaveEncryptClient, error) {
	return &EnclaveEncryptClient{
		enclaveAuthKey,
		*targetPrivateKey,
	}, nil
}

// Encrypt some plaintext to the given server target key.
func (c *EnclaveEncryptClient) Encrypt(plaintext Bytes, msg ServerTargetMsg) (*ClientSendMsg, error) {
	if !P256Verify(c.enclaveAuthKey, *msg.TargetPublic, *msg.TargetPublicSignature) {
		return nil, errors.New("invalid enclave auth key signature")
	}
	targetPublic, err := KemId.Scheme().UnmarshalBinaryPublicKey((*msg.TargetPublic)[:])
	if err != nil {
		return nil, err
	}

	ciphertext, encappedPublic, err := encrypt(
		&targetPublic,
		plaintext,
	)
	if err != nil {
		return nil, err
	}

	enc := Bytes(encappedPublic)
	ciph := Bytes(ciphertext)
	return &ClientSendMsg{
		EncappedPublic: &enc,
		Ciphertext:     &ciph,
	}, nil
}

// Decrypt a message from the server.
func (c *EnclaveEncryptClient) Decrypt(msg ServerSendMsg) (plaintext []byte, err error) {
	if !P256Verify(c.enclaveAuthKey, *msg.EncappedPublic, *msg.EncappedPublicSignature) {
		return nil, errors.New("invalid enclave auth key signature")
	}

	return decrypt(
		*msg.EncappedPublic,
		c.targetPrivate,
		*msg.Ciphertext,
	)
}

// Get this clients target public key.
func (c *EnclaveEncryptClient) TargetPublic() ([]byte, error) {
	return c.targetPrivate.Public().MarshalBinary()
}

// Decrypt a message from the server.
func (c *EnclaveEncryptClient) AuthDecrypt(payload string) (plaintext []byte, err error) {
	payloadBytes := base58.Decode(payload)
	err = ValidateChecksum(payloadBytes)
	if err != nil {
		return nil, err
	}
	// Trim the checksum
	payloadBytes = payloadBytes[:len(payloadBytes)-4]

	if len(payloadBytes) < 33 {
		return nil, errors.New("payload is less then 33 bytes, the length of the expected public key")
	}
	compressedKey := payloadBytes[0:33]
	ciphertext := payloadBytes[33:]

	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), compressedKey)

	// FIXME: `elliptic.Unmarshal` is deprecated, but scm does not know how to replace it.
	// nolint:staticcheck
	encappedPublic := elliptic.Marshal(elliptic.P256(), x, y)

	return decrypt(
		encappedPublic,
		c.targetPrivate,
		ciphertext,
	)
}

// Validates that a payload has a valid checksum in the last four bytes.
func ValidateChecksum(payload []byte) error {
	if len(payload) < 5 {
		return fmt.Errorf("payload length is < 5 (length: %d)", len(payload))
	}
	expected := checksum(payload[:len(payload)-4])
	if !reflect.DeepEqual(expected[:], payload[len(payload)-4:]) {
		return fmt.Errorf("checksum mismatch for payload %02x: %v (computed) != %v (last four bytes)", payload, expected, payload[len(payload)-4:])
	}
	return nil
}

// Takes a payload and return a checksum (4 bytes)
// The double-hash operation is dictated by the base58check standard
// See https://en.bitcoin.it/wiki/Base58Check_encoding#Creating_a_Base58Check_string
func checksum(payload []byte) (checkSum [4]byte) {
	h := sha256.Sum256(payload)
	h2 := sha256.Sum256(h[:])
	copy(checkSum[:], h2[:4])
	return checkSum
}
