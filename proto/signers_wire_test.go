package proto_test

import (
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	signersv1 "github.com/tkhq/go-sdk/proto/gen/external/signers/v1"
)

// TestExternalSignerProofPayloadWireContract pins the wire-level encoding of
// ExternalSignerProofPayloadV1. External signers (e.g. the HSM daemon) verify
// Ump signatures over these exact bytes, so the field numbers and wire types
// are a compatibility contract: renumbering a field in the schema would break
// every deployed verifier. If this test fails, that contract changed.
func TestExternalSignerProofPayloadWireContract(t *testing.T) {
	payload := &signersv1.ExternalSignerProofPayloadV1{
		Timestamp:            1761700000000,
		OrganizationDigest:   "digest",
		OrganizationId:       "org",
		ExternalSignerPubkey: "signer",
		TaskId:               "task",
	}

	encoded, err := proto.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	wantWireTypes := map[protowire.Number]protowire.Type{
		2: protowire.VarintType, // timestamp
		3: protowire.BytesType,  // organization_digest
		4: protowire.BytesType,  // organization_id
		5: protowire.BytesType,  // external_signer_pubkey
		6: protowire.BytesType,  // task_id
	}

	seen := parseWireTypes(t, encoded)
	for num, want := range wantWireTypes {
		got, ok := seen[num]
		if !ok {
			t.Fatalf("field %d missing from encoding", num)
		}

		if got != want {
			t.Fatalf("field %d: wire type %d, want %d", num, got, want)
		}
	}

	for num := range seen {
		if _, ok := wantWireTypes[num]; !ok {
			t.Fatalf("unexpected field number %d in encoding", num)
		}
	}

	// And the round trip: decoding the signed bytes must reproduce the payload.
	var decoded signersv1.ExternalSignerProofPayloadV1
	if err := proto.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !proto.Equal(payload, &decoded) {
		t.Fatalf("round trip mismatch: %v != %v", payload, &decoded)
	}
}

// parseWireTypes walks a protobuf encoding and returns the wire type observed
// for each field number.
func parseWireTypes(t *testing.T, encoded []byte) map[protowire.Number]protowire.Type {
	t.Helper()

	seen := map[protowire.Number]protowire.Type{}

	for len(encoded) > 0 {
		num, typ, n := protowire.ConsumeTag(encoded)
		if n < 0 {
			t.Fatalf("consuming tag: %v", protowire.ParseError(n))
		}

		encoded = encoded[n:]
		seen[num] = typ

		n = protowire.ConsumeFieldValue(num, typ, encoded)
		if n < 0 {
			t.Fatalf("consuming field %d: %v", num, protowire.ParseError(n))
		}

		encoded = encoded[n:]
	}

	return seen
}
