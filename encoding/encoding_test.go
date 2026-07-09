package encoding

import (
	"crypto/ecdh"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- hex.go ---

func TestBytesToHex(t *testing.T) {
	input := []byte{82, 52, 208, 143, 250, 44, 129, 95, 48, 151, 184, 186, 132, 138, 40, 23, 46, 133, 190, 199, 136, 134, 232, 226, 1, 175, 204, 177, 102, 252, 84, 193}
	assert.Equal(t, "5234d08ffa2c815f3097b8ba848a28172e85bec78886e8e201afccb166fc54c1", BytesToHex(input))
}

func TestHexToBytes(t *testing.T) {
	hexStr := "5234d08dfa2c815f3097b8ba848a28172e85bec78886e8e201afccb166fc54c1"
	expected := []byte{82, 52, 208, 141, 250, 44, 129, 95, 48, 151, 184, 186, 132, 138, 40, 23, 46, 133, 190, 199, 136, 134, 232, 226, 1, 175, 204, 177, 102, 252, 84, 193}

	b, err := HexToBytes(hexStr)
	require.NoError(t, err)
	assert.Equal(t, expected, b)

	b, err = HexToBytes("627566666572")
	require.NoError(t, err)
	assert.Equal(t, []byte{98, 117, 102, 102, 101, 114}, b)

	// error: empty string
	_, err = HexToBytes("")
	assert.ErrorContains(t, err, "cannot create bytes from invalid hex string")

	// error: odd length
	_, err = HexToBytes("123")
	assert.ErrorContains(t, err, "cannot create bytes from invalid hex string")

	// error: invalid characters
	_, err = HexToBytes("oops")
	assert.ErrorContains(t, err, "cannot create bytes from invalid hex string")

	// with length: pads to target
	b, err = HexToBytes("01", 2)
	require.NoError(t, err)
	assert.Equal(t, []byte{0, 1}, b)

	// without length: no padding
	b, err = HexToBytes("01")
	require.NoError(t, err)
	assert.Equal(t, []byte{1}, b)

	// error: value too large for length
	_, err = HexToBytes("0100", 1)
	assert.ErrorContains(t, err, "hex value cannot fit in a buffer of 1 byte(s)")

	// short hex padded to 32 bytes
	shortHex := "5234d08dfa2c815f3097b8ba848a28172e85bec78886e8e201afccb166fc"
	expectedPadded := []byte{0, 0, 82, 52, 208, 141, 250, 44, 129, 95, 48, 151, 184, 186, 132, 138, 40, 23, 46, 133, 190, 199, 136, 134, 232, 226, 1, 175, 204, 177, 102, 252}
	b, err = HexToBytes(shortHex, 32)
	require.NoError(t, err)
	assert.Equal(t, expectedPadded, b)

	// error: hex longer than length
	longHex := "5234d08dfa2c815f3097b8ba848a28172e85bec78886e8e201afccb166fcfafbfcfd"
	_, err = HexToBytes(longHex, 32)
	assert.ErrorContains(t, err, "hex value cannot fit in a buffer of 32 byte(s)")
}

func TestHexToASCII(t *testing.T) {
	// "hello" in hex
	assert.Equal(t, "hello", HexToASCII("68656c6c6f"))
}

func TestNormalizePadding(t *testing.T) {
	// pad shorter slice
	b, err := NormalizePadding([]byte{1, 2, 3}, 5)
	require.NoError(t, err)
	assert.Equal(t, []byte{0, 0, 1, 2, 3}, b)

	// no-op when already correct length
	b, err = NormalizePadding([]byte{1, 2, 3}, 3)
	require.NoError(t, err)
	assert.Equal(t, []byte{1, 2, 3}, b)

	// trim leading zeros
	b, err = NormalizePadding([]byte{0, 0, 1, 2, 3}, 3)
	require.NoError(t, err)
	assert.Equal(t, []byte{1, 2, 3}, b)

	// error: leading bytes are not zero
	_, err = NormalizePadding([]byte{1, 2, 3}, 1)
	assert.ErrorContains(t, err, "invalid number of starting zeroes")
}

// --- base64.go ---

func TestStringToBase64URL(t *testing.T) {
	assert.Equal(t, "aGVsbG8", StringToBase64URL("hello"))

	assert.Equal(
		t,
		"NTIzNGQwOGRmYTJjODE1ZjMwOTdiOGJhODQ4YTI4MTcyZTg1YmVjNzg4ODZlOGUyMDFhZmNjYjE2NmZjNTRjMQ",
		StringToBase64URL("5234d08dfa2c815f3097b8ba848a28172e85bec78886e8e201afccb166fc54c1"),
	)

	assert.Equal(
		t,
		"eyJwdWJsaWNLZXkiOiIwMmY3MzlmOGM3N2IzMmY0ZDVmMTMyNjU4NjFmZWJkNzZlN2E5YzYxYTExNDBkMjk2YjhjMTYzMDI1MDg4NzAzMTYiLCJzaWduYXR1cmUiOiIzMDQ0MDIyMDJhOTJjMjRlNGI0ZGUzY2RiNWMwNWEyYjFmNDIyNjRiYTgxMzljZjY2YjJkMWVjZjBhMDk5ODdhYjlhMmZlY2IwMjIwM2JmZDkxZDhjNWU4N2Y3OGRhOGI1Y2Y1ZGRiMjdjOTZjYjAwYjg0ODc5N2QwZmM3M2JmMzcxODkyYzQyM2Y4MSIsInNjaGVtZSI6IlNJR05BVFVSRV9TQ0hFTUVfVEtfQVBJX1AyNTYifQ",
		StringToBase64URL(`{"publicKey":"02f739f8c77b32f4d5f13265861febd76e7a9c61a1140d296b8c16302508870316","signature":"304402202a92c24e4b4de3cdb5c05a2b1f42264ba8139cf66b2d1ecf0a09987ab9a2fecb02203bfd91d8c5e87f78da8b5cf5ddb27c96cb00b848797d0fc73bf371892c423f81","scheme":"SIGNATURE_SCHEME_TK_API_P256"}`),
	)
}

func TestBase64ToBase64URL(t *testing.T) {
	assert.Equal(t, "aGVsbG8gd29ybGQ", Base64ToBase64URL("aGVsbG8gd29ybGQ="))
	assert.Equal(t, "U29tZSBzYW1wbGUgdGV4dA", Base64ToBase64URL("U29tZSBzYW1wbGUgdGV4dA=="))
}

func TestBase64URLToBase64(t *testing.T) {
	assert.Equal(t, "aGVsbG8gd29ybGQ=", Base64URLToBase64("aGVsbG8gd29ybGQ"))
}

func TestBase64URLToString(t *testing.T) {
	s, err := Base64URLToString("aGVsbG8")
	require.NoError(t, err)
	assert.Equal(t, "hello", s)
}

func TestHexToBase64URL(t *testing.T) {
	s, err := HexToBase64URL("01")
	require.NoError(t, err)
	assert.Equal(t, "AQ", s)

	s, err = HexToBase64URL("01", 2)
	require.NoError(t, err)
	assert.Equal(t, "AAE", s)

	s, err = HexToBase64URL("ff")
	require.NoError(t, err)
	assert.Equal(t, "_w", s)

	s, err = HexToBase64URL("ff", 2)
	require.NoError(t, err)
	assert.Equal(t, "AP8", s)

	_, err = HexToBase64URL("0100", 1)
	assert.ErrorContains(t, err, "hex value cannot fit in a buffer of 1 byte(s)")
}

// --- encode.go ---

func TestPointEncode(t *testing.T) {
	pointWithPrefix := func(prefix byte) []byte {
		for i := byte(1); i < 255; i++ {
			scalar := make([]byte, 32)
			scalar[31] = i

			priv, err := ecdh.P256().NewPrivateKey(scalar)
			if err != nil {
				continue
			}

			// Bytes returns the uncompressed SEC 1 encoding (0x04 || X || Y).
			uncompressed := priv.PublicKey().Bytes()

			// The compressed-form prefix is 0x02 for an even Y coordinate, 0x03 for odd.
			gotPrefix := byte(0x02)
			if uncompressed[len(uncompressed)-1]&1 == 1 {
				gotPrefix = 0x03
			}

			if gotPrefix == prefix {
				return uncompressed
			}
		}

		return nil
	}

	raw := pointWithPrefix(0x02)
	require.NotNil(t, raw)
	compressed, err := PointEncode(raw)
	require.NoError(t, err)
	assert.Len(t, compressed, 33)
	assert.Equal(t, byte(0x02), compressed[0])

	raw = pointWithPrefix(0x03)
	require.NotNil(t, raw)
	compressed, err = PointEncode(raw)
	require.NoError(t, err)
	assert.Equal(t, byte(0x03), compressed[0])

	// error: wrong length
	_, err = PointEncode([]byte{0x04, 0x01})
	assert.ErrorContains(t, err, "invalid uncompressed P-256 key")

	// error: wrong prefix
	raw2 := make([]byte, 65)
	raw2[0] = 0x03
	_, err = PointEncode(raw2)
	assert.ErrorContains(t, err, "invalid uncompressed P-256 key")

	// error: point is not on the curve
	raw3 := make([]byte, 65)
	raw3[0] = 0x04
	raw3[32] = 0x01
	raw3[64] = 0x02
	_, err = PointEncode(raw3)
	assert.ErrorContains(t, err, "invalid uncompressed P-256 key")
}

// --- bs58.go ---

func TestBs58(t *testing.T) {
	original := []byte("hello world")
	encoded := Bs58Encode(original)
	assert.NotEmpty(t, encoded)

	decoded := Bs58Decode(encoded)
	assert.Equal(t, original, decoded)

	b, ok := Bs58DecodeUnsafe(encoded)
	assert.True(t, ok)
	assert.Equal(t, original, b)

	// invalid input
	b, ok = Bs58DecodeUnsafe("")
	assert.False(t, ok)
	assert.Nil(t, b)
}

// --- bs58check.go ---

func TestBs58Check(t *testing.T) {
	payload := []byte("hello world")
	encoded := Bs58CheckEncode(payload)
	assert.NotEmpty(t, encoded)

	decoded, err := Bs58CheckDecode(encoded)
	require.NoError(t, err)
	assert.Equal(t, payload, decoded)

	// unsafe variant
	decoded = Bs58CheckDecodeUnsafe(encoded)
	assert.Equal(t, payload, decoded)

	// tampered string returns error
	_, err = Bs58CheckDecode(encoded[:len(encoded)-1] + "X")
	assert.Error(t, err)

	// too short
	_, err = Bs58CheckDecode("abc")
	assert.Error(t, err)

	// unsafe on invalid returns nil
	assert.Nil(t, Bs58CheckDecodeUnsafe("notvalid!!!"))
}
