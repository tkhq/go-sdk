---
module: "root"
bump: "patch"
title: "Earn deposit/withdraw intents target a wrapper by address"
date: "2026-07-13"
---

EarnDepositIntent and EarnWithdrawIntent now carry `wrapperAddress` (the deployed Earn wrapper to act on) and no longer carry `vaultAddress`; the wrapper identifies its own vault.
