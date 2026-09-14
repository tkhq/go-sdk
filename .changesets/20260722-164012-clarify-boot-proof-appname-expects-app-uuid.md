---
module: "root"
bump: "patch"
title: "Clarify boot proof appName expects app UUID"
date: "2026-07-22"
---

Clarify that `appName` on `get_latest_boot_proof` expects the enclave app's UUID, not its human-readable name (doc-only).
