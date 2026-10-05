---
module: "root"
bump: "minor"
title: "Add GetExternalSignerTasks"
date: "2026-10-01"
---

Add the `GetExternalSignerTasks` query to the Go SDK client, along with the `GetExternalSignerTasksRequest`, `GetExternalSignerTasksResponse`, `ExternalSignerTask`, `ExternalCryptoV1Signature`, and `ExternalCryptoV1SignatureScheme` types. The query lets an external signer daemon poll the coordinator for a batch of pending signing tasks keyed by its public key.
