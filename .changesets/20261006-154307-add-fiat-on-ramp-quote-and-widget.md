---
module: "root"
bump: "minor"
title: "Add fiat on-ramp quote and session"
date: "2026-10-06"
---

Add the `GetFiatOnRampQuote` query and the `CreateFiatOnRampSession` activity to the Go SDK client. The query returns Coinbase and MoonPay buy quotes for a fiat amount, asset, and network. The activity takes a saved quote id and wallet address and returns the provider session URL and on-ramp transaction id.
