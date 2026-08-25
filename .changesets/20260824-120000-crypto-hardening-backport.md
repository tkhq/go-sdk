---
module: "crypto"
bump: "patch"
title: "Reject malformed COSE and compressed P-256 input"
date: "2026-08-24"
---

`DecryptCredentialBundle` now returns an error instead of panicking on a malformed compressed P-256 public key, and attestation parsing rejects a COSE Sign1 structure that does not have exactly 4 elements. Also documents the verification checks `VerifyProofs` and `VerifyAppProofSignature` do not perform.
