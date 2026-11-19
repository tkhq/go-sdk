---
module: "root"
bump: "patch"
title: "ImportSecret uses the name-bound EncryptSecretToBundle"
date: "2026-11-12"
---

`ImportSecret` now calls `crypto.EncryptSecretToBundle`, which binds the ciphertext to the secret name and static properties. No change to the `ImportSecret` signature.
