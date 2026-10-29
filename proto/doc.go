// Package proto carries generated Go types for the protobuf types used in Turnkey messages.
// The JSON-facing types in the root SDK module are generated from swagger and
// carry no wire-format information (field numbers, wire types).
// //  The packages under gen/ provide the types to do that with proto.Unmarshal.
//
// The schema/ directory is synced from the mono repo (make sync/go-sdk there)
// and gen/ is produced from it by `make generate-proto` (see cmd/gen, which
// strips the documentation-only API annotations); neither is edited by hand.
package proto
