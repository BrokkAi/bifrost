---
title: Versioned Docs
description: How docs builds are synchronized with Bifrost release tags.
---

Bifrost release tags use the `v<semver>` form, such as `v0.7.2`. The docs workflow builds from the checked-out tag and publishes that static site in two places:

- the GitHub Pages root, which represents the latest published docs;
- `versions/<tag>/`, which preserves the docs for that exact release tag.

Branch builds use the version from the root `Cargo.toml` package and are labeled as development docs.

The docs site receives these build-time values:

- `PUBLIC_BIFROST_VERSION`
- `PUBLIC_BIFROST_TAG`
- `PUBLIC_BIFROST_RELEASE_URL`

This keeps the displayed docs version tied to the same release tags used for Bifrost binaries, the VS Code extension, and the agent plugin artifacts.
