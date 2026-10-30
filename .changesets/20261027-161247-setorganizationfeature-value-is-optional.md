---
module: "root"
bump: "patch"
title: "SetOrganizationFeature value is optional"
date: "2026-10-27"
---

`SetOrganizationFeatureIntent.Value` and `SetOrganizationFeatureRequest.Value` are now `*string` instead of `string`, and are omitted when nil. Features that take no value (e.g. `FEATURE_NAME_OTP_EMAIL_AUTH`) can now be set without sending `"value": ""`.
