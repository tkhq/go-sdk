---
module: "root"
bump: "minor"
title: "Rename velocity controls to usage controls"
date: "2026-10-23"
---

Renames the unreleased velocity controls activities and types to usage controls. The `ACTIVITY_TYPE_CREATE_VELOCITY_CONTROL` and `ACTIVITY_TYPE_DELETE_VELOCITY_CONTROLS` activity types become `ACTIVITY_TYPE_CREATE_USAGE_CONTROL` and `ACTIVITY_TYPE_DELETE_USAGE_CONTROLS` (the `ActivityTypeCreateVelocityControl` and `ActivityTypeDeleteVelocityControls` constants become `ActivityTypeCreateUsageControl` and `ActivityTypeDeleteUsageControls`). The `CreateVelocityControlIntent`, `CreateVelocityControlResult`, `DeleteVelocityControlsIntent` and `DeleteVelocityControlsResult` types, and every `VelocityControl*` type and enum value, are renamed to their `UsageControl*` equivalents. The `VelocityControlID` and `VelocityControlIds` fields become `UsageControlID` and `UsageControlIds`.
