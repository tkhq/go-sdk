package cosmos

import (
	"crypto/sha256"
	"math/big"

	"github.com/cosmos/btcutil/bech32"
	"golang.org/x/crypto/ripemd160"
)

func toBech32(addrPrefix string, addrBytes []byte) string {
	converted, err := bech32.ConvertBits(addrBytes, 8, 5, true)
	if err != nil {
		panic(err)
	}

	addr, err := bech32.Encode(addrPrefix, converted)
	if err != nil {
		panic(err)
	}

	return addr
}

func CompressPublicKey(uncompressedBytes []byte) []byte {
	x := new(big.Int).SetBytes(uncompressedBytes[1:33])
	y := new(big.Int).SetBytes(uncompressedBytes[33:65])

	compressed := make([]byte, 33)
	if y.Bit(0) == 0 {
		compressed[0] = 0x02
	} else {
		compressed[0] = 0x03
	}
	copy(compressed[1:], x.Bytes())

	return compressed
}

func AddressBytes(compressedPublicKey []byte) []byte {
	pubKeySha256Hash := sha256.Sum256(compressedPublicKey)

	ripemd160hash := ripemd160.New()
	ripemd160hash.Write(pubKeySha256Hash[:])

	return ripemd160hash.Sum(nil)
}

func PublicKeyToAddress(addressPrefix string, compressedPublicKey []byte) string {
	addressBytes := AddressBytes(compressedPublicKey)
	address := toBech32(addressPrefix, addressBytes)

	return address
}

func CosmosAddressFromPublicKey(publicKey []byte) string {
	return PublicKeyToAddress("cosmos", publicKey)
}
