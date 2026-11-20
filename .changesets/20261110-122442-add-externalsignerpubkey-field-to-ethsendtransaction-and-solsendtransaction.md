---
module: "root"
bump: "minor"
title: "Add externalSignerPubkey field to EthSendTransaction and SolSendTransaction"
date: "2026-11-10"
---

Adds the new externalSignerPubkey field for use with external signers (HSM) with EthSendTransaction and SolSendTransaction.
The new fields can currently only be used with unsponsored sends.
