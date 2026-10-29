---
module: "root"
bump: "minor"
title: "Add TVC client-generated manifest support"
date: "2026-09-28"
---

Add the `GetTVCManifestGenerationInfo` client method, with its request and response types, and an optional `QosManifest` field on `CreateTVCDeploymentIntent`. Together these let TVC clients generate the QOS manifest for a deployment and submit it with the deployment request. Both are only available to organizations that have client-generated manifests enabled.
