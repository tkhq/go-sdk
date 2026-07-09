// Package encoding provides encoding and decoding utilities ported from the Turnkey TypeScript SDK.
package encoding

import (
	"encoding/hex"
	"encoding/json"
)

// HexBytes marshals bytes as a hex-encoded JSON string.
type HexBytes []byte

func (bytes HexBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(bytes))
}

func (bytes *HexBytes) UnmarshalJSON(data []byte) error {
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
