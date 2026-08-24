---
module: "root"
bump: "minor"
title: "Align transaction history pagination with shared PageInfo contract"
date: "2026-07-30"
---

Update `ListEthTransactionHistory` and `ListSolTransactionHistory` SDK types to use shared `Pagination` request options and `PageInfo` response metadata instead of transaction-history-specific pagination cursor types.
