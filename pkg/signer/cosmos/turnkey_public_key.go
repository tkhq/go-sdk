package cosmos

import (
	"bytes"
	"encoding/hex"

	"github.com/cosmos/cosmos-sdk/crypto/types"
)

func (t *TurnkeyPublicKey) Address() types.Address {
	compressedPublicKey := CompressPublicKey([]byte(t.GetPublicKey()))
	return AddressBytes(compressedPublicKey)
}

func (t *TurnkeyPublicKey) Bytes() []byte {
	if bytes, err := hex.DecodeString(t.GetPublicKey()); err != nil {
		return nil
	} else {
		return bytes
	}
}

func (t *TurnkeyPublicKey) VerifySignature(msg []byte, sig []byte) bool {
	return verifyECDSASignature(msg, sig, t.Bytes())
}

func (t *TurnkeyPublicKey) Equals(key types.PubKey) bool {
	return bytes.Equal(t.Address(), key.Address())
}

func (t *TurnkeyPublicKey) Type() string {
	return t.GetKeyType()
}
