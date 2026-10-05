---
module: "root"
bump: "minor"
title: "Add EarnClaimRewards and GetEarnClaimRewardsStatus"
date: "2026-09-15"
---

Add the EarnClaimRewards activity, which claims every currently claimable Merkl reward attributed to a wallet on one chain in a single Distributor transaction, and GetEarnClaimRewardsStatus to poll the claim by its claim_request_id.
