---
module: "root"
bump: "patch"
title: "Add OUTCOME_TIME_INACTIVE to policy evaluation outcomes"
date: "2026-07-30"
---

With the addition of time based policies, we are introducing a new policy outcome called OUTCOME_TIME_INACTIVE to denote when a policy is not being applied because the current timestamp is outside the bounds denoted in the time field
