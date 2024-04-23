package enclave_encrypt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"

	"github.com/btcsuite/btcutil/base58"
	"github.com/cloudflare/circl/kem"
)

type EnclaveEncryptServer struct {
	enclaveAuthKey *ecdsa.PrivateKey
	targetPrivate  kem.PrivateKey
	organizationId string
	userId         *string
}

type EnclaveEncryptServerRecv struct {
	targetPrivate kem.PrivateKey
}

// This should be the quorum signing secret derived from the quorum
// master seed.
func NewEnclaveEncryptServer(enclaveAuthKey *ecdsa.PrivateKey, organizationId string, userId *string) (EnclaveEncryptServer, error) {
	_, targetPrivate, err := KemId.Scheme().GenerateKeyPair()
	if err != nil {
		return EnclaveEncryptServer{}, err
	}

	return EnclaveEncryptServer{
		enclaveAuthKey,
		targetPrivate,
		organizationId,
		userId,
	}, nil
}

// Create a server from the enclave quorum public key and the target key.
func NewEnclaveEncryptServerFromTargetKey(enclaveAuthKey *ecdsa.PrivateKey, targetPrivateKey *kem.PrivateKey, organizationId string, userId *string) (EnclaveEncryptServer, error) {
	return EnclaveEncryptServer{
		enclaveAuthKey,
		*targetPrivateKey,
		organizationId,
		userId,
	}, nil
}

// Encrypt `plaintext` to the `clientTarget` key.
func (s *EnclaveEncryptServer) Encrypt(clientTarget []byte, plaintext []byte) (*ServerSendMsgV1, error) {
	clientTargetKem, err := KemId.Scheme().UnmarshalBinaryPublicKey(clientTarget[:])
	if err != nil {
		return nil, err
	}

	ciphertext, encappedPublic, err := encrypt(
		&clientTargetKem,
		plaintext,
	)
	if err != nil {
		return nil, err
	}

	data := ServerSendData{
		EncappedPublic: Bytes(encappedPublic),
		Ciphertext:     Bytes(ciphertext),
		OrganizationId: s.organizationId,
	}

	dataBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	dataSignature, err := P256Sign(s.enclaveAuthKey, dataBytes)
	if err != nil {
		return nil, err
	}

	dataSig := Bytes(dataSignature)

	enclaveQuorumPublic := s.enclaveAuthKey.PublicKey
	// FIXME: `elliptic.Marshal` is deprecated,
	// nolint:staticcheck
	enclaveQuorumPublicBytes := elliptic.Marshal(elliptic.P256(), enclaveQuorumPublic.X, enclaveQuorumPublic.Y)
	eqp := Bytes(enclaveQuorumPublicBytes)

	return &ServerSendMsgV1{
		Version:             DataVersion,
		Data:                data,
		DataSignature:       dataSig,
		EnclaveQuorumPublic: eqp,
	}, nil
}

// Return the servers encryption target key and a signature over it from
// the quorum key.
func (s *EnclaveEncryptServer) PublishTarget() (*ServerTargetMsgV1, error) {
	targetPublic, err := s.targetPrivate.Public().MarshalBinary()
	if err != nil {
		return nil, err
	}

	data := ServerTargetData{
		TargetPublic:   Bytes(targetPublic),
		OrganizationId: s.organizationId,
		UserId:         *s.userId,
	}

	dataBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	dataSignature, err := P256Sign(s.enclaveAuthKey, dataBytes)
	if err != nil {
		return nil, err
	}

	dataSig := Bytes(dataSignature)

	enclaveQuorumPublic := s.enclaveAuthKey.PublicKey
	// FIXME: `elliptic.Marshal` is deprecated,
	// nolint:staticcheck
	enclaveQuorumPublicBytes := elliptic.Marshal(elliptic.P256(), enclaveQuorumPublic.X, enclaveQuorumPublic.Y)
	eqp := Bytes(enclaveQuorumPublicBytes)

	return &ServerTargetMsgV1{
		Version:             DataVersion,
		Data:                data,
		DataSignature:       dataSig,
		EnclaveQuorumPublic: eqp,
	}, nil
}

// Get the server receiving type.
func (s *EnclaveEncryptServer) IntoEnclaveServerRecv() EnclaveEncryptServerRecv {
	return EnclaveEncryptServerRecv{
		targetPrivate: s.targetPrivate,
	}
}

// Relevant for usage with auth activities: Email Auth, Email Recovery.
func (s *EnclaveEncryptServer) AuthEncrypt(clientTarget []byte, plaintext []byte) (string, error) {
	clientTargetKem, err := KemId.Scheme().UnmarshalBinaryPublicKey(clientTarget[:])
	if err != nil {
		return "", err
	}

	ciphertext, encappedPublic, err := encrypt(
		&clientTargetKem,
		plaintext,
	)
	if err != nil {
		return "", err
	}

	// FIXME: `elliptic.Unmarshal` is deprecated, but scm does not know how to replace it.
	// nolint:staticcheck
	x, y := elliptic.Unmarshal(elliptic.P256(), encappedPublic)

	compressedEncappedPublic := elliptic.MarshalCompressed(elliptic.P256(), x, y)
	payload := append(compressedEncappedPublic, ciphertext...)

	checksum := checksum(payload)
	payload = append(payload, checksum[:]...)

	return base58.Encode(payload), nil
}

// Decrypt a message from a client that encrypted to this server instance
// target key.
// Relevant for usage with auth activities: Email Auth, Email Recovery.
func (s *EnclaveEncryptServerRecv) Decrypt(msg ClientSendMsg) ([]byte, error) {
	return decrypt(
		*msg.EncappedPublic,
		s.targetPrivate,
		*msg.Ciphertext,
	)
}
