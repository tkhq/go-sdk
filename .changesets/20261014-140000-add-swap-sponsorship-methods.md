---
module: "root"
bump: "minor"
title: "Add swap fee sponsorship and fixed-rate limit methods"
date: "2026-10-14"
---

Adds `Client.UpsertSwapFeeSponsorshipLimitConfig` and `Client.UpsertSwapFixedRateLimitConfig`, which set the fee sponsorship and fixed-rate spending windows, along with their `Stamp` variants and request and response types. Use `Client.GetSwapSponsorshipUsage` to read window usage.
