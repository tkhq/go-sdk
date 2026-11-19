package crypto

import "encoding/binary"

const importSecretsPurpose = "ENCRYPTED_INGRESS_PURPOSE_IMPORT_SECRETS"

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

func appendField(binding []byte, field string) []byte {
	binding = binary.BigEndian.AppendUint32(binding, uint32(len(field)))

	return append(binding, field...)
}
