package crypto

import "encoding/binary"

const (
	importSecretsPurpose      = "ENCRYPTED_INGRESS_PURPOSE_IMPORT_SECRETS"
	oauth2AuthenticatePurpose = "ENCRYPTED_INGRESS_PURPOSE_OAUTH2_AUTHENTICATE"
)

// StaticProperty is one policy-visible key-value pair bound into an ImportSecrets ciphertext.
type StaticProperty struct {
	Key   string
	Value string
}

// ImportSecretsPurposeBinding encodes the AAD suffix that binds an ImportSecrets ciphertext to its name and
// static properties, in order. A nil name encodes as the empty string, which the enclave rejects as a name.
func ImportSecretsPurposeBinding(name *string, staticProperties []StaticProperty) []byte {
	binding := appendField(nil, importSecretsPurpose)

	if name != nil {
		binding = appendField(binding, *name)
	} else {
		binding = appendField(binding, "")
	}

	binding = binary.BigEndian.AppendUint32(binding, uint32(len(staticProperties)))
	for _, property := range staticProperties {
		binding = appendField(binding, property.Key)
		binding = appendField(binding, property.Value)
	}

	return binding
}

// OAuth2AuthenticatePurposeBinding encodes the AAD suffix that binds an OAuth2AuthenticateV2 ciphertext to its
// OAuth 2.0 credential ID, the canonical lowercase hyphenated UUID sent in the activity.
func OAuth2AuthenticatePurposeBinding(oauth2CredentialID string) []byte {
	return encodePurposeBinding(oauth2AuthenticatePurpose, []purposeBindingField{
		{key: "oauth2_credential_id", value: oauth2CredentialID},
	})
}

// purposeBindingField is one named request field bound into a ciphertext.
type purposeBindingField struct {
	key   string
	value string
}

// encodePurposeBinding encodes the length-prefixed purpose, the field count, and each length-prefixed key and value,
// matching turnkey_enclave_encrypt::purpose_binding::encode. ImportSecrets predates it and keeps its own encoding.
func encodePurposeBinding(purpose string, fields []purposeBindingField) []byte {
	binding := appendField(nil, purpose)

	binding = binary.BigEndian.AppendUint32(binding, uint32(len(fields)))
	for _, field := range fields {
		binding = appendField(binding, field.key)
		binding = appendField(binding, field.value)
	}

	return binding
}

func appendField(binding []byte, field string) []byte {
	binding = binary.BigEndian.AppendUint32(binding, uint32(len(field)))

	return append(binding, field...)
}
