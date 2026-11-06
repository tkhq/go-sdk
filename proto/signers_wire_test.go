package proto_test

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	signersv1 "github.com/tkhq/go-sdk/proto/gen/external/signers/v1"
	activityv1 "github.com/tkhq/go-sdk/proto/gen/immutable/activity/v1"
)

// TestExternalSignerProofPayloadWireContract pins the wire-level encoding of
// ExternalSignerProofPayloadV1. External signers (e.g. the HSM daemon) verify
// Ump signatures over these exact bytes, so the field numbers, wire types, and
// name-to-number associations are a compatibility contract: renumbering a
// field in the schema — including swapping the tags of two fields with the
// same wire type — would break every deployed verifier. If this test fails,
// that contract changed.
func TestExternalSignerProofPayloadWireContract(t *testing.T) {
	intent := &activityv1.Intent{
		Inner: &activityv1.Intent_SignRawPayloadIntent{
			SignRawPayloadIntent: &activityv1.SignRawPayloadIntent{
				Payload: "intent-payload",
			},
		},
	}

	payload := &signersv1.ExternalSignerProofPayloadV1{
		Intent:               intent,
		Timestamp:            1761700000000,
		OrganizationDigest:   "digest",
		OrganizationId:       "org",
		ExternalSignerPubkey: "signer",
		TaskId:               "task",
	}

	// The descriptor is what drives encoding, so pin every field's
	// name-to-number association and kind. This is what catches a tag swap
	// between fields that share a wire type (e.g. organization_digest and
	// organization_id), which a wire-type-only check would miss.
	wantFields := []struct {
		name   protoreflect.Name
		number protoreflect.FieldNumber
		kind   protoreflect.Kind
	}{
		{"intent", 1, protoreflect.MessageKind},
		{"timestamp", 2, protoreflect.Uint64Kind},
		{"organization_digest", 3, protoreflect.StringKind},
		{"organization_id", 4, protoreflect.StringKind},
		{"external_signer_pubkey", 5, protoreflect.StringKind},
		{"task_id", 6, protoreflect.StringKind},
	}

	fields := payload.ProtoReflect().Descriptor().Fields()
	if fields.Len() != len(wantFields) {
		t.Fatalf("message has %d fields, want %d", fields.Len(), len(wantFields))
	}

	for _, want := range wantFields {
		fd := fields.ByName(want.name)
		if fd == nil {
			t.Fatalf("field %q missing from descriptor", want.name)
		}

		if fd.Number() != want.number {
			t.Fatalf("field %q: number %d, want %d", want.name, fd.Number(), want.number)
		}

		if fd.Kind() != want.kind {
			t.Fatalf("field %q: kind %v, want %v", want.name, fd.Kind(), want.kind)
		}
	}

	encoded, err := proto.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	seen := parseWireFields(t, encoded)

	// Each field carries a distinct value, so asserting the value observed at
	// each field number independently confirms, on the actual signed bytes,
	// which field landed where.
	wantBytes := map[protowire.Number]string{
		3: "digest",
		4: "org",
		5: "signer",
		6: "task",
	}

	for num, want := range wantBytes {
		field, ok := seen[num]
		if !ok {
			t.Fatalf("field %d missing from encoding", num)
		}

		if field.typ != protowire.BytesType {
			t.Fatalf("field %d: wire type %d, want %d (bytes)", num, field.typ, protowire.BytesType)
		}

		if string(field.raw) != want {
			t.Fatalf("field %d: value %q, want %q", num, field.raw, want)
		}
	}

	intentField, ok := seen[1]
	if !ok {
		t.Fatal("field 1 (intent) missing from encoding")
	}

	if intentField.typ != protowire.BytesType {
		t.Fatalf("field 1 (intent): wire type %d, want %d (bytes)", intentField.typ, protowire.BytesType)
	}

	wantIntent, err := proto.Marshal(intent)
	if err != nil {
		t.Fatalf("marshal intent: %v", err)
	}

	if !bytes.Equal(intentField.raw, wantIntent) {
		t.Fatalf("field 1 (intent): value %x, want %x", intentField.raw, wantIntent)
	}

	timestampField, ok := seen[2]
	if !ok {
		t.Fatal("field 2 (timestamp) missing from encoding")
	}

	if timestampField.typ != protowire.VarintType {
		t.Fatalf("field 2 (timestamp): wire type %d, want %d (varint)", timestampField.typ, protowire.VarintType)
	}

	if timestampField.varint != payload.Timestamp {
		t.Fatalf("field 2 (timestamp): value %d, want %d", timestampField.varint, payload.Timestamp)
	}

	for num := range seen {
		if num != 1 && num != 2 {
			if _, ok := wantBytes[num]; !ok {
				t.Fatalf("unexpected field number %d in encoding", num)
			}
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

// wireField is one field observed in a protobuf encoding: its wire type plus
// the payload bytes (BytesType) or varint value (VarintType).
type wireField struct {
	typ    protowire.Type
	raw    []byte
	varint uint64
}

// parseWireFields walks a protobuf encoding and returns the wire type and
// value observed for each field number.
func parseWireFields(t *testing.T, encoded []byte) map[protowire.Number]wireField {
	t.Helper()

	seen := map[protowire.Number]wireField{}

	for len(encoded) > 0 {
		num, typ, n := protowire.ConsumeTag(encoded)
		if n < 0 {
			t.Fatalf("consuming tag: %v", protowire.ParseError(n))
		}

		encoded = encoded[n:]
		field := wireField{typ: typ}

		switch typ {
		case protowire.BytesType:
			raw, n := protowire.ConsumeBytes(encoded)
			if n < 0 {
				t.Fatalf("consuming bytes field %d: %v", num, protowire.ParseError(n))
			}

			field.raw = raw
			encoded = encoded[n:]
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(encoded)
			if n < 0 {
				t.Fatalf("consuming varint field %d: %v", num, protowire.ParseError(n))
			}

			field.varint = v
			encoded = encoded[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, encoded)
			if n < 0 {
				t.Fatalf("consuming field %d: %v", num, protowire.ParseError(n))
			}

			encoded = encoded[n:]
		}

		seen[num] = field
	}

	return seen
}
