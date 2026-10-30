---
module: "root"
bump: "minor"
title: "Add ExecuteSwapV4 activity types"
date: "2026-10-21"
---

Add `ActivityTypeExecuteSwapV4` and the `ExecuteSwapIntentV4`, `ExecuteSwapBoundQuote`, and `ExecuteSwapMarketTerms` types. An `ExecuteSwapIntentV4` sets exactly one of `BoundQuote`, which executes a `create_swap_quote` quote at its exact terms, or `Market`, which executes at the provider's price when the activity is approved. `ExecuteSwapResult` gains optional `OutputAmount`, `MinOutputAmount`, `FeeSponsorship`, and `FixedRate`. The activity type is internal until the execute endpoint switches to it.
