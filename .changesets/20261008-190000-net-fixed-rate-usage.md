---
module: "root"
bump: "patch"
title: "Net fixed-rate earnings in swap sponsorship usage"
date: "2026-10-08"
---

`SwapSpendingWindow.UsageUsd` for fixed rate now nets fixed-rate earnings against fixed-rate costs in the window and never goes below zero, so earnings restore spending capacity up to the configured limit.
