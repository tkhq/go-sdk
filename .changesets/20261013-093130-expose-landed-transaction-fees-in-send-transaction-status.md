---
module: "root"
bump: "minor"
title: "Expose landed transaction fees in send transaction status"
date: "2026-10-13"
---

Add optional eth.fee (gasUsed, effectiveGasPrice) and solana.fee (feeLamports, sponsoredRentLamports) to GetSendTransactionStatusResponse for landed transactions, including ones that reverted. Sponsored mainnet transactions also report totalCostUsd, and Solana adds feeCostUsd and rentCostUsd.