---
module: "root"
bump: "patch"
title: "Return signed external key records with raw signing tasks"
date: "2026-11-10"
---

External signer task proofs include an optional key-record Signature. Its message is hex of the exact
record bytes; its signature is hex ASN.1 DER ECDSA-P256-SHA256, using TK_SIGNED_BLOB_P256.
Verify over ASCII `TURNKEY_EXTERNAL_SIGNER_KEY_RECORD_V1\n` followed by those decoded record bytes,
without re-encoding the record. The Signature public key identifies the daemon signer.
