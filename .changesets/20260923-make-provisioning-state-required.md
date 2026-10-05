---
module: "root"
bump: "patch"
title: "Make TVC provisioning state required"
date: "2026-09-23"
---

Make `ProvisioningState` required on `DeploymentStatus` and `GetTVCDeploymentProvisioningDetailsResponse`. Both fields now use `ProvisioningState` instead of `*ProvisioningState` and are always included when marshaling JSON.

Callers must replace pointer assignments, dereferences, and nil checks with direct enum values and comparisons.
