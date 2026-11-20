---
module: "root"
bump: "minor"
title: "Expose the swap quote transaction calls"
date: "2026-11-04"
---

SwapQuoteV2, returned by ACTIVITY_TYPE_CREATE_SWAP_QUOTE_V3, now includes Transactions. Each call is executed in order, including approvals. On EVM, execution signs a batch or an EIP-7702 wrapper around these calls. On Solana, data is the instruction payload; execution adds the blockhash and address lookup tables, and when the swap is sponsored it also adds the fee payer and rent instructions.
