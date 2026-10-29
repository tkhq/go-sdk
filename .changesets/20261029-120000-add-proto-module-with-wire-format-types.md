---
module: "proto"
bump: "minor"
title: "Add proto module with generated wire-format types"
date: "2026-10-29"
---

Adds the github.com/tkhq/go-sdk/proto module: Go types generated from the Turnkey protobuf schemas (synced from mono via buf export) for messages that are signed and verified as raw protobuf bytes, such as the Ump enclave's ExternalSignerProofPayloadV1. External signers can now proto.Unmarshal the signed payload bytes instead of hand-parsing the wire format, since the swagger-generated JSON types carry no field-number information.
