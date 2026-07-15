# Bifrost Docs

This directory contains the public Bifrost documentation site. Keep client-facing documentation under
`src/content/docs/`.

## Internal Links

Write links to docs pages as site-root paths, for example `/install/` or
`/code-query-json/#limits-and-validation-errors`. The local Rehype plugin preserves those paths during local
development and prefixes the configured deployment base for production and versioned builds. Do not hard-code
`/bifrost` in content links.

`npm run build` checks every generated internal `href` and `src`, including fragments, against the built site. This
keeps root, GitHub Pages, and `versions/<tag>/` builds on the same authoring convention and fails CI when a link omits
the configured base or points at a missing output target.

## Release Documentation

Bifrost release tags use the `v<semver>` form, such as `v0.7.2`. The docs workflow uses GitHub Pages'
GitHub Actions deployment path and publishes the static site in two places:

- the GitHub Pages root, which represents the latest published docs;
- `versions/<tag>/`, which preserves the docs for that exact release tag.

Branch builds use the version from the root `Cargo.toml` package and are labeled as development docs.

The docs site receives these build-time values:

- `PUBLIC_BIFROST_VERSION`
- `PUBLIC_BIFROST_TAG`
- `PUBLIC_BIFROST_RELEASE_URL`

This keeps the displayed docs version tied to the same release tags used for Bifrost binaries, the VS Code
extension, and the agent plugin artifacts.

Use the **Docs** workflow's manual dispatch when a previous release needs a docs-only correction or republish.
Leave `tag` empty to republish the latest release tag, or pass a specific release tag, for example `v0.7.2`.

The workflow builds from the current docs source, labels the build with the selected tag, and includes
`versions/<tag>/` for that release in the Pages artifact.

Docs pull requests run the same build and dependency checks, but they do not deploy to GitHub Pages.
