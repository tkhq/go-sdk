package apikey_test

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tkhq/go-sdk/pkg/apikey"
)

func Test_FromTkPrivateKey(t *testing.T) {
	// This private key is taken from an openSSL-generated PEM key:
	// 	$ openssl ec -in docs/fixtures/private_key.pem -noout -text
	// 	Private-Key: (256 bit)
	// 	priv:
	// 		48:7f:36:1d:df:d7:34:40:e7:07:f4:da:a6:77:5b:
	// 		37:68:59:e8:a3:c9:f2:9b:3b:b6:94:a1:29:27:c0:
	// 		21:3c
	// 	pub:
	// 		04:f7:39:f8:c7:7b:32:f4:d5:f1:32:65:86:1f:eb:
	// 		d7:6e:7a:9c:61:a1:14:0d:29:6b:8c:16:30:25:08:
	// 		87:03:16:c2:49:70:ad:78:11:cc:d9:da:7f:1b:88:
	// 		f2:02:be:ba:c7:70:66:3e:f5:8b:a6:83:46:18:6d:
	// 		d7:78:20:0d:d4
	// 	ASN1 OID: prime256v1
	// 	NIST CURVE: P-256
	privateKeyFromOpenSSL := "487f361ddfd73440e707f4daa6775b376859e8a3c9f29b3bb694a12927c0213c"
	apiKey, err := apikey.FromTurnkeyPrivateKey(privateKeyFromOpenSSL)
	require.NoError(t, err)

	// This value was computed based on an openssl-generated PEM file:
	//   $ openssl ec -in docs/fixtures/private_key.pem -pubout -conv_form compressed -outform der | tail -c 33 | xxd -p -c 33
	//   read EC key
	//   writing EC key
	//   02f739f8c77b32f4d5f13265861febd76e7a9c61a1140d296b8c16302508870316
	expectedPublicKey := "02f739f8c77b32f4d5f13265861febd76e7a9c61a1140d296b8c16302508870316"
	assert.Equal(t, expectedPublicKey, apiKey.TkPublicKey)
}

func Test_Sign(t *testing.T) {
	tkPrivateKey := "487f361ddfd73440e707f4daa6775b376859e8a3c9f29b3bb694a12927c0213c"

	apiKey, err := apikey.FromTurnkeyPrivateKey(tkPrivateKey)
	require.NoError(t, err)

	stampHeader, err := apikey.Stamp([]byte("hello"), apiKey)
	require.NoError(t, err)

	testStamp, err := base64.RawURLEncoding.DecodeString(stampHeader)
	require.NoError(t, err)

	var stamp *apikey.APIStamp

	require.NoError(t, json.Unmarshal(testStamp, &stamp))

	assert.Equal(t, "02f739f8c77b32f4d5f13265861febd76e7a9c61a1140d296b8c16302508870316", stamp.PublicKey)
	assert.Equal(t, "SIGNATURE_SCHEME_TK_API_P256", stamp.Scheme)

	sigBytes, err := hex.DecodeString(stamp.Signature)
	require.NoError(t, err)

	publicKey, err := apikey.DecodeTurnkeyPublicKey(stamp.PublicKey)
	require.NoError(t, err)

	// Verify the soundness of the hash:
	//   $ echo -n 'hello' | shasum -a256
	//   2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824  -
	msgHash := sha256.Sum256([]byte("hello"))
	assert.Equal(t, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", hex.EncodeToString(msgHash[:]))

	// Finally, check the signature itself
	verifiedSig := ecdsa.VerifyASN1(publicKey, msgHash[:], sigBytes)
	assert.True(t, verifiedSig)
}

func Test_EncodedKeySizeIsFixed(t *testing.T) {
	for i := 0; i < 1000; i++ {
		apiKey, err := apikey.New(uuid.NewString())
		require.NoError(t, err)

		assert.Len(t, apiKey.TkPublicKey, 66, "attempt %d: expected 66 characters for public key %s", i, apiKey.TkPublicKey)
		assert.Len(t, apiKey.TkPrivateKey, 64, "attempt %d: expected 64 characters for private key %s", i, apiKey.TkPrivateKey)
	}
}

func Test_MetadataMergeWorks(t *testing.T) {
	k, err := apikey.New(uuid.NewString())
	require.NoError(t, err)
	assert.Equal(t, "", k.GetMetadata().Name)

	err = k.MergeMetadata(apikey.Metadata{
		Name:      "Custom Name",
		PublicKey: k.TkPublicKey,
	})
	require.NoError(t, err)
	assert.Equal(t, "Custom Name", k.GetMetadata().Name)
}
