---
module: "root"
bump: "minor"
title: "Require bindable quotes for swap execution"
date: "2026-07-29"
---

`ExecuteSwap` now requires `ACTIVITY_TYPE_EXECUTE_SWAP_V2` with the exact quote ID, displayed economics, sponsor choice, and optional chain replay-protection value returned by `CreateSwapQuote`. The signing wallet is derived from the signed quote rather than repeated in the execute request. The unreleased V1 swap execution shape is no longer accepted by the API.

`CreateSwapQuote` accepts optional `slippageBps` and returns `quotes[]` with per-provider economics for UI (`slippageBps`, `clientFeeBps`, optional `estimatedTimeSeconds`) plus a `quoteId` that execute must bind to.
