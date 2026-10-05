---
module: "root"
bump: "minor"
title: "Add TVC operator and quorum key methods"
date: "2026-09-18"
---

Add `GetTVCOperators` and `GetTVCQuorumKeys` queries and their request and response types. Expose encryption and signing public keys and the optional key source on `TVCOperator`, and add the `TVCQuorumKey` type.

Add `CreateTVCOperator` and `CreateTVCQuorumKey` methods, their stamping helpers, and their request and response types.
