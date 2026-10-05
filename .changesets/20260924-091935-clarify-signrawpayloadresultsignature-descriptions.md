---
module: "root"
bump: "patch"
title: "clarify SignRawPayloadResult.signature descriptions"
date: "2026-09-24"
---

The r/s/v fields of `SignRawPayloadResult` were inaccurately described. They are now more explicit, especially with regards to `v` in EdDSA signatures.
