---
module: "root"
bump: "minor"
title: "Expose transaction history execution status"
date: "2026-09-10"
---

Add `executionFailed` to Ethereum and Solana transaction history items so clients can distinguish successful transactions from transactions that failed during on-chain execution.
