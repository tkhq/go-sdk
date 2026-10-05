---
module: "root"
bump: "minor"
title: "Add linking info to auth proxy GetAccount"
date: "2026-09-24"
---

Add `IncludeRequiresSocialLinking` to `AuthProxyGetAccountRequest` and `RequiresSocialLinking` to `AuthProxyGetAccountResponse`. When a request opts in, the response reports whether the organization was matched by a sub-organization's verified email rather than by a registered OIDC identity, so callers can tell an ordinary login apart from one that first requires social linking.
