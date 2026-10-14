---
module: "root"
bump: "minor"
title: "CreateSwapQuote uses the V3 swap quote"
date: "2026-10-15"
---

`CreateSwapQuote` now sends `ACTIVITY_TYPE_CREATE_SWAP_QUOTE_V3`. Its parameters gain optional `feeSponsorship` and `fixedRate`, and each returned quote gains `feeSponsorship`, `fixedRate`, and `estimatedFixedRateAdjustmentUsd`. Every V2 field is unchanged, so existing calls behave the same. Code that names the V2 intent or result types directly should use the V3 types.
