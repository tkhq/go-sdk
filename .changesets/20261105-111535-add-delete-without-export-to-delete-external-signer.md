---
module: "root"
bump: "patch"
title: "Add `deleteWithoutExport` to `DeleteExternalSignerIntentV1`"
date: "2026-11-05"
---

Add the optional `deleteWithoutExport` field to `DeleteExternalSignerIntentV1` and `DeleteExternalSignerV1Request`. When set, the external signer is deleted together with the wrapped keys it generated.
