---
module: "root"
bump: "patch"
title: "Document that secret export target keys must not be reused"
date: "2026-11-12"
---

ExportSecretParams.TargetPublicKey docs now state that each exported secret needs its own fresh ephemeral target key and that Turnkey does not enforce this.
