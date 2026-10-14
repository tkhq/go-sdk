---
module: "root"
bump: "patch"
title: "Swap feature error codes"
date: "2026-10-08"
---

Swap quotes that request a fixed rate or fee sponsorship the provider cannot honor now fail with the `SWAP_FIXED_RATE_UNAVAILABLE`, `SWAP_FIXED_RATE_PAIR_NOT_ELIGIBLE`, or `SWAP_FEE_SPONSORSHIP_UNAVAILABLE` Turnkey error code.
