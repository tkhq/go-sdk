// Package proto carries generated Go types for the protobuf wire format of
// Turnkey messages that are signed and verified as raw bytes, such as the Ump
// enclave's ExternalSignerProof payload.
//
// The JSON-facing types in the root SDK module are generated from swagger and
// carry no wire-format information (field numbers, wire types), so they cannot
// decode signed protobuf bytes. Verifiers must decode the exact bytes that
// were signed — protobuf encoding is not canonical, so re-encoding a payload
// and comparing bytes is never correct. The packages under gen/ provide the
// types to do that with proto.Unmarshal.
//
// The schema/ directory is synced from the mono repo (make sync/go-sdk there)
// and gen/ is produced from it by `buf generate`; neither is edited by hand.
package proto
