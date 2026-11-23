---
module: "root"
bump: "patch"
title: "Keep development tools out of the SDK module graph"
date: "2026-11-23"
---

Move the pinned lint and format tools into a separate workspace module. SDK
consumers no longer inherit the tools' dependency graph. Repository development
commands continue to use the same tool versions.
