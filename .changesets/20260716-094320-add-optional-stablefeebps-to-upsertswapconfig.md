---
module: "root"
bump: "patch"
title: "Add optional stableFeeBps to UpsertSwapConfig"
date: "2026-07-16"
---

UpsertSwapConfigIntent and UpsertSwapConfigResult now include optional stableFeeBps. When set, that rate is used for stablecoin pairs; otherwise feeBps applies.
