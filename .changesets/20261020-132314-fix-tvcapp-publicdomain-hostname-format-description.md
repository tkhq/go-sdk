---
module: "root"
bump: "patch"
title: "Fix TvcApp PublicDomain hostname format description"
date: "2026-10-20"
---

The `PublicDomain` field on `TvcApp` described its value as `app-<ID>.turnkey.cloud`. Apps on the TVC cluster get `app-<ID>.app.turnkey.cloud`; the old format only applied to the sunset TKMS cluster. The description now gives the current format and notes that the field may hold several comma-separated hostnames. Documentation only, no behavior change.
