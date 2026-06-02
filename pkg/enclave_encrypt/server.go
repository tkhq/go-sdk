package enclave_encrypt

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"encoding/json"

	"github.com/btcsuite/btcutil/base58"
	"github.com/cloudflare/circl/kem"
)

type EnclaveEncryptServer struct {
	enclaveAuthKey *ecdsa.PrivateKey
	targetPublic   kem.PublicKey
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
	targetPublic, targetPrivate, err := KemId.Scheme().GenerateKeyPair()
	if err != nil {
		return EnclaveEncryptServer{}, err
	}

	return EnclaveEncryptServer{
		enclaveAuthKey,
		targetPublic,
		targetPrivate,
		organizationId,
		userId,
	}, nil
}

// Create a server from the enclave quorum public key and the target key.
func NewEnclaveEncryptServerFromTargetKey(enclaveAuthKey *ecdsa.PrivateKey, targetPublicKey kem.PublicKey, organizationId string, userId *string) (EnclaveEncryptServer, error) {
	return EnclaveEncryptServer{
		enclaveAuthKey,
		targetPublicKey,
		nil,
		organizationId,
		userId,
	}, nil
}

// Get the server receiving type.
func (s *EnclaveEncryptServer) IntoEnclaveServerRecv() EnclaveEncryptServerRecv {
	return EnclaveEncryptServerRecv{
		targetPrivate: s.targetPrivate,
	}
}

// Create a server from the enclave quorum public key and the target key.
func NewEnclaveEncryptServerFromTargetKeyPair(enclaveAuthKey *ecdsa.PrivateKey, targetPrivateKey kem.PrivateKey, organizationId string, userId *string) (EnclaveEncryptServer, error) {
	return EnclaveEncryptServer{
		enclaveAuthKey,
		targetPrivateKey.Public(),
		targetPrivateKey,
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

	ecdhPub, err := s.enclaveAuthKey.PublicKey.ECDH()
	if err != nil {
		return nil, err
	}
	eqp := Bytes(ecdhPub.Bytes())

	return &ServerSendMsgV1{
		Version:             DataVersion,
		Data:                dataBytes,
		DataSignature:       dataSig,
		EnclaveQuorumPublic: eqp,
	}, nil
}

// Return the servers encryption target key and a signature over it from
// the quorum key.
func (s *EnclaveEncryptServer) PublishTarget() (*ServerTargetMsgV1, error) {
	targetPublic, err := s.targetPublic.MarshalBinary()
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

	ecdhPub, err := s.enclaveAuthKey.PublicKey.ECDH()
	if err != nil {
		return nil, err
	}
	eqp := Bytes(ecdhPub.Bytes())

	return &ServerTargetMsgV1{
		Version:             DataVersion,
		Data:                dataBytes,
		DataSignature:       dataSig,
		EnclaveQuorumPublic: eqp,
	}, nil
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

	ecdhPub, err := ecdh.P256().NewPublicKey(encappedPublic)
	if err != nil {
		return "", err
	}

	rawPub := ecdhPub.Bytes()
	x := rawPub[1:33]
	yLastByte := rawPub[64]
	prefix := byte(0x02) | (yLastByte & 1)
	compressedEncappedPublic := append([]byte{prefix}, x...)
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
