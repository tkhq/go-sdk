package enclave_encrypt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/json"
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
func NewEnclaveEncryptClientFromTargetKey(enclaveAuthKey *ecdsa.PublicKey, targetPrivateKey kem.PrivateKey) (*EnclaveEncryptClient, error) {
	return &EnclaveEncryptClient{
		enclaveAuthKey,
		targetPrivateKey,
	}, nil
}

// Encrypt some plaintext to the given server, using `enclaveMsgBytes`.
// In the import flow for example, `bundleBytes` represents the bytes of the received bundle.
// Note: for v1 bundles this function extracts organizationId and userId fields from the signed data bytes, verifies their integrity,
// and verifies that they match with the (user-) provided `organizationId` and `userId` params.
// To decrypt v0 bundles, `organizationId` and `userId` are irrelevant and can be set to empty strings.
func (c *EnclaveEncryptClient) Encrypt(plaintext Bytes, bundleBytes Bytes, organizationId string, userId string) (*ClientSendMsg, error) {
	var targetPublic kem.PublicKey

	var enclaveMsg ServerMsg
	if err := json.Unmarshal(bundleBytes, &enclaveMsg); err != nil {
		return nil, err
	}

	switch {
	case *enclaveMsg.Version == DataVersion:
		var enclaveMsgV1 ServerTargetMsgV1
		if err := json.Unmarshal(bundleBytes, &enclaveMsgV1); err != nil {
			return nil, err
		}

		var enclaveSignedData ServerTargetData
		if err := json.Unmarshal(enclaveMsgV1.Data, &enclaveSignedData); err != nil {
			return nil, err
		}

		if enclaveMsgV1.EnclaveQuorumPublic == nil {
			return nil, errors.New("missing enclave quorum public key")
		}

		enclaveQuorumPublic, err := ToEcdsaPublic(enclaveMsgV1.EnclaveQuorumPublic)
		if err != nil {
			return nil, err
		}

		if !enclaveQuorumPublic.Equal(c.enclaveAuthKey) {
			return nil, errors.New("enclave quorum public keys from client and message do not match")
		}

		// Verify enclave signature
		if !P256Verify(enclaveQuorumPublic, enclaveMsgV1.Data, enclaveMsgV1.DataSignature) {
			return nil, errors.New("invalid enclave auth key signature")
		}

		// Validate that the expected fields are the same
		if enclaveSignedData.OrganizationId != organizationId {
			return nil, errors.New("organization id does not match expected value")
		}

		if enclaveSignedData.UserId != userId {
			return nil, errors.New("user id does not match expected value")
		}

		targetPublic, err = KemId.Scheme().UnmarshalBinaryPublicKey((enclaveSignedData.TargetPublic)[:])
		if err != nil {
			return nil, err
		}
	case enclaveMsg.Version == nil:
		var msgV0 ServerTargetMsgV0
		if err := json.Unmarshal(bundleBytes, &msgV0); err != nil {
			return nil, err
		}

		if !P256Verify(c.enclaveAuthKey, msgV0.TargetPublic, msgV0.TargetPublicSignature) {
			return nil, errors.New("invalid enclave auth key signature")
		}

		var err error

		targetPublic, err = KemId.Scheme().UnmarshalBinaryPublicKey((msgV0.TargetPublic)[:])
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("invalid data version: %v", enclaveMsg.Version)
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

// Decrypts a bundle. This is used in private key and wallet export flows.
// In the export flow for example, `bundleBytes` represents the bytes of the received bundle and contains the ciphertext of the exported wallet or private key.
// Note: for v1 bundles this function extracts the organizationId fields from the signed data bytes, verifies its integrity,
// and verifies that its match with the (user-) provided `organizationId`. For v0 bundles, `organizationId` is irrelevant.
func (c *EnclaveEncryptClient) Decrypt(bundleBytes Bytes, organizationId string) (plaintext []byte, err error) {
	var encappedPublic Bytes

	var ciphertext Bytes
	var enclaveMsg ServerMsg
	if err := json.Unmarshal(bundleBytes, &enclaveMsg); err != nil {
		return nil, err
	}

	switch {
	case *enclaveMsg.Version == DataVersion:
		var enclaveMsgV1 ServerSendMsgV1
		if err := json.Unmarshal(bundleBytes, &enclaveMsgV1); err != nil {
			return nil, err
		}

		var enclaveSignedData ServerSendData
		if err := json.Unmarshal(enclaveMsgV1.Data, &enclaveSignedData); err != nil {
			return nil, err
		}

		if enclaveMsgV1.EnclaveQuorumPublic == nil {
			return nil, errors.New("missing enclave quorum public key")
		}

		enclaveQuorumPublic, err := ToEcdsaPublic(enclaveMsgV1.EnclaveQuorumPublic)
		if err != nil {
			return nil, err
		}

		if !enclaveQuorumPublic.Equal(c.enclaveAuthKey) {
			return nil, errors.New("enclave quorum public keys from client and message do not match")
		}

		// Verify enclave signature
		if !P256Verify(enclaveQuorumPublic, enclaveMsgV1.Data, enclaveMsgV1.DataSignature) {
			return nil, errors.New("invalid enclave auth key signature")
		}

		// Validate that the expected fields are the same
		if enclaveSignedData.OrganizationId != organizationId {
			return nil, errors.New("organization id does not match expected value")
		}

		encappedPublic = enclaveSignedData.EncappedPublic
		ciphertext = enclaveSignedData.Ciphertext
	case enclaveMsg.Version == nil:
		var msgV0 ServerSendMsgV0
		if err := json.Unmarshal(bundleBytes, &msgV0); err != nil {
			return nil, err
		}

		if !P256Verify(c.enclaveAuthKey, *msgV0.EncappedPublic, *msgV0.EncappedPublicSignature) {
			return nil, errors.New("invalid enclave auth key signature")
		}

		encappedPublic = *msgV0.EncappedPublic
		ciphertext = *msgV0.Ciphertext
	default:
		return nil, fmt.Errorf("invalid data version: %v", enclaveMsg.Version)
	}

	return decrypt(
		encappedPublic,
		c.targetPrivate,
		ciphertext,
	)
}

// Get this clients target public key.
func (c *EnclaveEncryptClient) TargetPublic() ([]byte, error) {
	return c.targetPrivate.Public().MarshalBinary()
}

// Decrypt a base58-encoded payload from the server. This is used in email authentication and email recovery flows.
func (c *EnclaveEncryptClient) AuthDecrypt(payload string) (plaintext []byte, err error) {
	payloadBytes := base58.Decode(payload)

	if err = ValidateChecksum(payloadBytes); err != nil {
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
