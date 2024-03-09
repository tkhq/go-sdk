package enclave_encrypt

import (
	"crypto/ecdsa"
	"crypto/elliptic"

	"github.com/btcsuite/btcutil/base58"
	"github.com/cloudflare/circl/kem"
)

type EnclaveEncryptServer struct {
	enclaveAuthKey *ecdsa.PrivateKey
	targetPrivate  kem.PrivateKey
}

type EnclaveEncryptServerRecv struct {
	targetPrivate kem.PrivateKey
}

// This should be the quorum signing secret derived from the quorum
// master seed.
func NewEnclaveEncryptServer(enclaveAuthKey *ecdsa.PrivateKey) (EnclaveEncryptServer, error) {
	_, targetPrivate, err := KemId.Scheme().GenerateKeyPair()
	if err != nil {
		return EnclaveEncryptServer{}, err
	}

	return EnclaveEncryptServer{
		enclaveAuthKey,
		targetPrivate,
	}, nil
}

// Create a server from the enclave quorum public key and the target key.
func NewEnclaveEncryptServerFromTargetKey(enclaveAuthKey *ecdsa.PrivateKey, targetPrivateKey *kem.PrivateKey) (EnclaveEncryptServer, error) {
	return EnclaveEncryptServer{
		enclaveAuthKey,
		*targetPrivateKey,
	}, nil
}

// Encrypt `plaintext` to the `clientTarget` key.
func (s *EnclaveEncryptServer) Encrypt(clientTarget []byte, plaintext []byte) (*ServerSendMsg, error) {
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

	encappedPublicSignature, err := P256Sign(s.enclaveAuthKey, encappedPublic)
	if err != nil {
		return nil, err
	}

	encSig := Bytes(encappedPublicSignature)
	enc := Bytes(encappedPublic)
	ciph := Bytes(ciphertext)
	return &ServerSendMsg{
		EncappedPublic:          &enc,
		EncappedPublicSignature: &encSig,
		Ciphertext:              &ciph,
	}, nil
}

// Return the servers encryption target key and a signature over it from
// the quorum key.
func (s *EnclaveEncryptServer) PublishTarget() (*ServerTargetMsg, error) {
	targetPublic, err := s.targetPrivate.Public().MarshalBinary()
	if err != nil {
		return nil, err
	}
	t := Bytes(targetPublic)

	targetPublicSignature, err := P256Sign(s.enclaveAuthKey, targetPublic)
	if err != nil {
		return nil, err
	}
	tSig := Bytes(targetPublicSignature)

	return &ServerTargetMsg{
		TargetPublic:          &t,
		TargetPublicSignature: &tSig,
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
