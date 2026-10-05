---
module: "root"
bump: "minor"
title: "Add GetActivePolicies"
date: "2026-08-24"
---

Add the `GetActivePolicies` query to the Go SDK client, along with the `GetActivePoliciesRequest`, `GetActivePoliciesResponse`, and `ActivePolicyStatus` types. For each policy in an organization, the query reports whether it is currently active based on the enclave's trusted timestamp and the policy's time window; policies without a time field are always active.
