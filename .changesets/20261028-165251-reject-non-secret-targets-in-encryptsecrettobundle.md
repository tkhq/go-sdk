---
module: "crypto"
bump: "patch"
title: "Reject non-Secret targets in EncryptSecretToBundle"
date: "2026-10-28"
---

`EncryptSecretToBundle` now rejects a signed target whose `userId` is non-empty, so a substituted private key or wallet import target cannot receive a Secret.
