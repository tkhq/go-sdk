package apikey_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
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
	apiKey, err := apikey.FromTurnkeyPrivateKey(privateKeyFromOpenSSL, apikey.SchemeP256)
	require.NoError(t, err)

	// This value was computed based on an openssl-generated PEM file:
	//   $ openssl ec -in docs/fixtures/private_key.pem -pubout -conv_form compressed -outform der | tail -c 33 | xxd -p -c 33
	//   read EC key
	//   writing EC key
	//   02f739f8c77b32f4d5f13265861febd76e7a9c61a1140d296b8c16302508870316
	expectedPublicKey := "02f739f8c77b32f4d5f13265861febd76e7a9c61a1140d296b8c16302508870316"
	assert.Equal(t, expectedPublicKey, apiKey.TkPublicKey)
}

func Test_Sign_ECDSA(t *testing.T) {
	type testCase struct {
		name         string
		tkPrivateKey string
		tkPublicKey  string
		curve        apikey.Curve
	}

	testCases := []testCase{
		{
			name:         "p256",
			tkPrivateKey: "487f361ddfd73440e707f4daa6775b376859e8a3c9f29b3bb694a12927c0213c",
			tkPublicKey:  "02f739f8c77b32f4d5f13265861febd76e7a9c61a1140d296b8c16302508870316",
			curve:        apikey.CurveP256,
		},
		{
			name:         "secp256k1",
			tkPrivateKey: "1e0d32856eb059ee6c9d7871ac1c0755b7ecca4b6302263448da30d10c91c50d",
			tkPublicKey:  "032f1d146fc0de39f093bcb9f0b9ce667030c2b8a3ad0c3022cfae2c6a7a21d28a",
			curve:        apikey.CurveSecp256k1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(tt *testing.T) {
			apiKey, err := apikey.FromTurnkeyPrivateKey(tc.tkPrivateKey, tc.curve.ToScheme())
			require.NoError(tt, err)

			stampHeader, err := apikey.Stamp([]byte("hello"), apiKey)
			require.NoError(tt, err)

			testStamp, err := base64.RawURLEncoding.DecodeString(stampHeader)
			require.NoError(tt, err)

			var stamp *apikey.APIStamp

			require.NoError(tt, json.Unmarshal(testStamp, &stamp))

			assert.Equal(tt, tc.tkPublicKey, stamp.PublicKey)
			assert.Equal(tt, tc.curve.ToScheme(), stamp.Scheme)

			sigBytes, err := hex.DecodeString(stamp.Signature)
			require.NoError(tt, err)

			publicKey, err := apikey.DecodeTurnkeyPublicECDSAKey(stamp.PublicKey, tc.curve.ToScheme())
			require.NoError(tt, err)

			// Verify the soundness of the hash:
			//   $ echo -n 'hello' | shasum -a256
			//   2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824  -
			msgHash := sha256.Sum256([]byte("hello"))
			assert.Equal(tt, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", hex.EncodeToString(msgHash[:]))

			// Finally, check the signature itself
			verifiedSig := ecdsa.VerifyASN1(publicKey, msgHash[:], sigBytes)
			assert.True(tt, verifiedSig)
		})
	}
}

func Test_Sign_ED25519(t *testing.T) {
	tkPrivateKey := "3514c6f83c8fb2facfd1947d6332d8f38512dd945f3cb87b9b6ea3b877b564388ba00e7ee515fc82b53d525802d3769d66a0e1cc8b9927b6ca854d1a1e7d3211"
	tkPubKey := "8ba00e7ee515fc82b53d525802d3769d66a0e1cc8b9927b6ca854d1a1e7d3211"
	msg := "MESSAGE"

	apiKey, err := apikey.FromTurnkeyPrivateKey(tkPrivateKey, apikey.SchemeED25519)
	require.NoError(t, err)

	stampHeader, err := apikey.Stamp([]byte(msg), apiKey)
	require.NoError(t, err)

	testStamp, err := base64.RawURLEncoding.DecodeString(stampHeader)
	require.NoError(t, err)

	var stamp *apikey.APIStamp

	require.NoError(t, json.Unmarshal(testStamp, &stamp))

	assert.Equal(t, tkPubKey, stamp.PublicKey)
	assert.Equal(t, "SIGNATURE_SCHEME_TK_API_ED25519", string(stamp.Scheme))

	sigBytes, err := hex.DecodeString(stamp.Signature)
	require.NoError(t, err)

	pubKeyBytes, err := hex.DecodeString(tkPubKey)
	require.NoError(t, err)

	pubKey := ed25519.PublicKey(pubKeyBytes)

	// Finally, check the signature itself
	verifiedSig := ed25519.Verify(pubKey, []byte(msg), sigBytes)
	assert.True(t, verifiedSig)

	// Also check it manually against expected result
	expected := "fb8d09d2fa817ac0f99c99c3a65a2a8ea2a4c9b95008c22b4ba79a7d0227ed65f832234491a588f827fa33dbdda5bb47537be0166729d0f9f4d1f20d8e61b405"
	assert.Equal(t, expected, hex.EncodeToString(sigBytes))
}

func Test_EncodedKeySizeIsFixed(t *testing.T) {
	for i := 0; i < 1000; i++ {
		apiKey, err := apikey.New(uuid.NewString(), apikey.WithScheme(apikey.SchemeP256))
		require.NoError(t, err)

		assert.Len(t, apiKey.TkPublicKey, 66, "attempt %d: expected 66 characters for public key %s", i, apiKey.TkPublicKey)
		assert.Len(t, apiKey.TkPrivateKey, 64, "attempt %d: expected 64 characters for private key %s", i, apiKey.TkPrivateKey)
	}
}

func Test_MetadataMergeWorks(t *testing.T) {
	k, err := apikey.New(uuid.NewString(), apikey.WithScheme(apikey.SchemeP256))
	require.NoError(t, err)
	assert.Equal(t, "", k.GetMetadata().Name)

	err = k.MergeMetadata(apikey.Metadata{
		Name:      "Custom Name",
		PublicKey: k.TkPublicKey,
	})
	require.NoError(t, err)
	assert.Equal(t, "Custom Name", k.GetMetadata().Name)
}
