---
module: "root"
bump: "minor"
title: "Rename DeleteVelocityControl to DeleteVelocityControls"
date: "2026-10-01"
---

Renames the `ACTIVITY_TYPE_DELETE_VELOCITY_CONTROL` activity type to `ACTIVITY_TYPE_DELETE_VELOCITY_CONTROLS` (the `ActivityTypeDeleteVelocityControl` constant becomes `ActivityTypeDeleteVelocityControls`), and the `DeleteVelocityControlIntent` and `DeleteVelocityControlResult` types to `DeleteVelocityControlsIntent` and `DeleteVelocityControlsResult`. The intent and result now take a `VelocityControlIds` list instead of a single `VelocityControlID`, matching the other bulk delete activities.
