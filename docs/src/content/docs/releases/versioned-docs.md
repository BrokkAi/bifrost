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

## Manual Republish

Use the **Docs** workflow's manual dispatch when a previous release needs a docs-only correction or republish. Leave `tag` empty to republish the latest release tag, or pass a specific release tag, for example `v0.7.2`.

The workflow checks out that tag, builds the latest docs root, and also refreshes `versions/<tag>/` for the selected release. Existing versioned snapshots for other tags are preserved.
