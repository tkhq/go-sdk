---
module: "root"
bump: "minor"
title: "Add ExecuteSwapV4 and GetIndicativeSwapQuote"
date: "2026-10-29"
---

Adds `ExecuteSwapV4` and `StampExecuteSwapV4`, which execute a swap in one of two modes. With `BoundQuote`, the swap executes a quote from `CreateSwapQuote` at its exact terms. With `Market`, it executes at the provider's price when the activity is approved, within `SlippageBps` and an optional `MinOutputAmount` floor. Adds `GetIndicativeSwapQuote`, a query that previews the current price for a swap without creating an activity; its result is not binding and has no quote ID. Existing `ExecuteSwap`, `ExecuteSwapV2`, and `ExecuteSwapV3` are unchanged.
