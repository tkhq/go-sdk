package enclave_encrypt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

const (
	// Consult the rust implementations README for how these should be configured.
	// See [here](../../../rust/enclave_encrypt/README.md#hpke-configuration)
	KemId           hpke.KEM  = hpke.KEM_P256_HKDF_SHA256
	KdfId           hpke.KDF  = hpke.KDF_HKDF_SHA256
	AeadId          hpke.AEAD = hpke.AEAD_AES256GCM
	TurnkeyHpkeInfo string    = "turnkey_hpke"
)

type Bytes []byte

func (bytes *Bytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(*bytes))
}

func (bytes *Bytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}

	*bytes = b

	return nil
}

// Message from the server with encapsulated key, quorum key signature over
// encapsulated key and ciphertext.
type ServerSendMsg struct {
	// Encapsulation key used to generate the ciphertext.
	EncappedPublic *Bytes `json:"encappedPublic,omitempty"`
	// Quorum key signature over the encapsulation key.
	EncappedPublicSignature *Bytes `json:"encappedPublicSignature,omitempty"`
	// Ciphertext from the server.
	Ciphertext *Bytes `json:"ciphertext,omitempty"`
}

// Message from the server with a encryption target key  and a quorum key
// signature over it.
type ServerTargetMsg struct {
	// Target public key for client to encrypt to.
	TargetPublic *Bytes `json:"targetPublic,omitempty"`
	// Signature over the servers public target key.
	TargetPublicSignature *Bytes `json:"targetPublicSignature,omitempty"`
}

// Message from the client with encapsulated key and ciphertext.
type ClientSendMsg struct {
	// We assume this public key can be trusted because the request went through
	// checks in the policy engine.
	EncappedPublic *Bytes `json:"encappedPublic,omitempty"`
	// The encrypted message.
	Ciphertext *Bytes `json:"ciphertext,omitempty"`
}

// Sign the given `msg`.
func P256Sign(privateKey *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	hash := sha256.Sum256(msg)
	sigBytes, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])

	return sigBytes, err
}

// Verify the given signature over `msg` with `publicKey`.
func P256Verify(publicKey *ecdsa.PublicKey, msg []byte, signature []byte) bool {
	hash := sha256.Sum256(msg)
	return ecdsa.VerifyASN1(publicKey, hash[:], signature)
}

func encrypt(
	receiverPublic *kem.PublicKey,
	plaintext []byte,
) (ciphertext Bytes, encappedPublic []byte, err error) {
	suite := hpke.NewSuite(KemId, KdfId, AeadId)

	sender, err := suite.NewSender(*receiverPublic, []byte(TurnkeyHpkeInfo))
	if err != nil {
		return nil, nil, err
	}

	encappedPublic, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	aad, err := additionalAssociatedData(*receiverPublic, encappedPublic)
	if err != nil {
		return nil, nil, err
	}
	ciphertext, err = sealer.Seal(plaintext, aad)
	if err != nil {
		return nil, nil, err
	}

	return ciphertext, encappedPublic, nil
}

func decrypt(
	encappedPublic Bytes,
	receiverPrivate kem.PrivateKey,
	ciphertext Bytes,
) (plaintext []byte, err error) {
	suite := hpke.NewSuite(KemId, KdfId, AeadId)

	receiver, err := suite.NewReceiver(receiverPrivate, []byte(TurnkeyHpkeInfo))
	if err != nil {
		return []byte{}, nil
	}

	opener, err := receiver.Setup(encappedPublic)
	if err != nil {
		return []byte{}, nil
	}

	aad, err := additionalAssociatedData(receiverPrivate.Public(), encappedPublic)
	if err != nil {
		return nil, err
	}
	plaintext, err = opener.Open(ciphertext, aad)

	return plaintext, err
}

func additionalAssociatedData(
	receiverPublic kem.PublicKey,
	senderPublic Bytes,
) ([]byte, error) {
	receiverPublicBytes, err := receiverPublic.MarshalBinary()
	if err != nil {
		return []byte{}, err
	}

	result := []byte{}
	result = append(result, senderPublic...)
	result = append(result, receiverPublicBytes...)

	return result, nil
}
