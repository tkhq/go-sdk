---
module: "root"
bump: "patch"
title: "Document ListSecrets metadata as display-only"
date: "2026-11-12"
---

The ListSecrets docs now state that the returned metadata, including static properties, is for display only. For efficiency, the enclave does not authenticate it in this view, so do not use it for security-sensitive decisions.
