---
module: "root"
bump: "patch"
title: "route SolSendTransactionV2 to shared sol_send_transaction endpoint"
date: "2026-07-24"
---

`SolSendTransactionV2` now submits to `/public/v1/submit/sol_send_transaction` (same path as V1) with `ACTIVITY_TYPE_SOL_SEND_TRANSACTION_V2`, matching the EthSendTransaction versioning pattern. The separate `/sol_send_transaction_v2` endpoint is removed.
