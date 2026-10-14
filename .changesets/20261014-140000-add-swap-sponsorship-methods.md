---
module: "root"
bump: "minor"
title: "Add swap fee sponsorship and fixed-rate methods"
date: "2026-10-14"
---

Adds `Client.CreateSwapQuoteV3`, which quotes a swap with optional fee sponsorship and fixed-rate conversion, and `Client.UpsertSwapFeeSponsorshipLimitConfig` and `Client.UpsertSwapFixedRateLimitConfig`, which set each feature's spending window, along with their `Stamp` variants and request and response types. Use `Client.ExecuteSwapV3` to execute a V3 quote and `Client.GetSwapSponsorshipUsage` to read window usage.
