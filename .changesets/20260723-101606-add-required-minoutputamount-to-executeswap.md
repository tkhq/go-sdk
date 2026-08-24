---
module: "root"
bump: "minor"
title: "Add required minOutputAmount to ExecuteSwap"
date: "2026-07-23"
---

ExecuteSwapIntent now requires `minOutputAmount` (base units of the output asset). Execution fails if the provider quote's guaranteed minimum falls below that floor at execution time. Clients should typically haircut a prior quote's `minOutputAmount` when setting this value to tolerate normal quote drift.
