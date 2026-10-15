---
module: "root"
bump: "patch"
title: "Swap quote V3 result fields are required"
date: "2026-10-15"
---

`CreateSwapQuoteResultV2.Quotes` is always serialized, and `SwapQuoteV2.FeeSponsorship` and `FixedRate` are now `bool` instead of `*bool`, matching what the API always returns.
