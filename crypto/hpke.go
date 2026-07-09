//nolint:staticcheck
//lint:file-ignore SA1019 HPKE public key conversion still needs elliptic encodings for compressed and uncompressed hex output
package crypto

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

// HPKEEncrypt encrypts plaintext to receiverPublic with Turnkey's enclave HPKE configuration.
func HPKEEncrypt(receiverPublic *kem.PublicKey, plaintext []byte) (ciphertext []byte, encappedPublic []byte, err error) {
	suite := hpke.NewSuite(KemID, KdfID, AeadID)

	sender, err := suite.NewSender(*receiverPublic, []byte(TurnkeyHPKEInfo))
	if err != nil {
		return nil, nil, err
	}

	encappedPublic, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	aad, err := AdditionalAssociatedData(*receiverPublic, encappedPublic)
	if err != nil {
		return nil, nil, err
	}

	ciphertext, err = sealer.Seal(plaintext, aad)
	if err != nil {
		return nil, nil, err
	}

	return ciphertext, encappedPublic, nil
}

// EncodeKEMPrivateKey encodes a KEM private key into Turnkey's hex format.
func EncodeKEMPrivateKey(privateKey kem.PrivateKey) (string, error) {
	privateKeyBytes, err := privateKey.MarshalBinary()
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(privateKeyBytes), nil
}

// EncodeKEMPublicKey encodes a KEM public key into Turnkey's hex format.
func EncodeKEMPublicKey(publicKey kem.PublicKey) (string, error) {
	publicKeyBytes, err := publicKey.MarshalBinary()
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(publicKeyBytes), nil
}

// DecodeKEMPrivateKey decodes a Turnkey hex-encoded KEM private key.
func DecodeKEMPrivateKey(encodedPrivateKey string) (*kem.PrivateKey, error) {
	bytes, err := hex.DecodeString(encodedPrivateKey)
	if err != nil {
		return nil, err
	}

	privateKey, err := KemID.Scheme().UnmarshalBinaryPrivateKey(bytes)
	if err != nil {
		return nil, err
	}

	return &privateKey, nil
}

// DecodeKEMPublicKey decodes a Turnkey hex-encoded KEM public key.
func DecodeKEMPublicKey(encodedPublicKey string) (*kem.PublicKey, error) {
	bytes, err := hex.DecodeString(encodedPublicKey)
	if err != nil {
		return nil, err
	}

	publicKey, err := KemID.Scheme().UnmarshalBinaryPublicKey(bytes)
	if err != nil {
		return nil, err
	}

	return &publicKey, nil
}

// HPKEDecrypt decrypts ciphertext with receiverPrivate and Turnkey's enclave HPKE configuration.
func HPKEDecrypt(encappedPublic []byte, receiverPrivate kem.PrivateKey, ciphertext []byte) ([]byte, error) {
	suite := hpke.NewSuite(KemID, KdfID, AeadID)

	receiver, err := suite.NewReceiver(receiverPrivate, []byte(TurnkeyHPKEInfo))
	if err != nil {
		return nil, fmt.Errorf("bad receiver private key: %s", err.Error())
	}

	opener, err := receiver.Setup(encappedPublic)
	if err != nil {
		return nil, fmt.Errorf("bad encapsulated public key: %s", err.Error())
	}

	aad, err := AdditionalAssociatedData(receiverPrivate.Public(), encappedPublic)
	if err != nil {
		return nil, err
	}

	return opener.Open(ciphertext, aad)
}

// AdditionalAssociatedData derives the AAD used by Turnkey enclave HPKE messages.
func AdditionalAssociatedData(receiverPublic kem.PublicKey, senderPublic []byte) ([]byte, error) {
	receiverPublicBytes, err := receiverPublic.MarshalBinary()
	if err != nil {
		return []byte{}, err
	}

	result := []byte{}
	result = append(result, senderPublic...)
	result = append(result, receiverPublicBytes...)

	return result, nil
}

// GenerateEncryptionKeyPair generates a new HPKE KEM keypair, returning the
// uncompressed public key plus the raw private key needed to decrypt enclave responses.
func GenerateEncryptionKeyPair() (uncompressedPublicKeyHex string, privateKey kem.PrivateKey, err error) {
	pub, priv, err := KemID.Scheme().GenerateKeyPair()
	if err != nil {
		return "", nil, err
	}

	publicKeyBytes, err := pub.MarshalBinary()
	if err != nil {
		return "", nil, err
	}

	x, y := elliptic.Unmarshal(elliptic.P256(), publicKeyBytes)
	if x == nil || y == nil {
		x, y = elliptic.UnmarshalCompressed(elliptic.P256(), publicKeyBytes)
	}

	if x == nil || y == nil {
		return "", nil, fmt.Errorf("invalid P-256 public key")
	}

	uncompressedPublicKeyHex = hex.EncodeToString(elliptic.Marshal(elliptic.P256(), x, y))

	return uncompressedPublicKeyHex, priv, nil
}
