---
module: "root"
bump: "patch"
title: "Return Ump-signed proofs from GetExternalSignerTasks"
date: "2026-10-14"
---

Reshapes the unreleased external signer types: `GetExternalSignerTasksResponse.Tasks` now
carries `ExternalSignerProof` values (the Ump-signed payload produced at ruling time, with
`ExternalSignerProofPayloadV1` and a shared `Signature`/`SignatureScheme` type) instead of the
coordinator-assembled `ExternalSignerTask`. The `ExternalSignerTask`, `ExternalCryptoV1Signature`,
and `ExternalCryptoV1SignatureScheme` types are removed.
