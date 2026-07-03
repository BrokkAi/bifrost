# Add Astro Starlight documentation site and release-synced publishing

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md` from the repository root.

## Purpose / Big Picture

Bifrost needs a human-readable documentation site that can be rendered and published separately from internal agent notes and ExecPlans. After this work, the repository will contain an Astro Starlight site under `docs/`, a small branded landing page, starter user docs, and a GitHub Pages workflow that publishes docs from the same release tags used for Bifrost binaries. A user can see the result by running `npm run build` in `docs/` and by reading the workflow that deploys a tag such as `v0.7.2` to both the latest site root and `versions/v0.7.2/`.

## Progress

- [x] (2026-07-03) Created this ExecPlan before adding the Starlight project.
- [x] (2026-07-03) Added the Astro Starlight project under `docs/` with initial pages and Brokk-flavored CSS.
- [x] (2026-07-03) Added release metadata resolution for docs builds and a GitHub Pages workflow with release-tag snapshots.
- [x] (2026-07-03) Installed docs dependencies, generated `docs/package-lock.json`, and ran the docs build.

## Surprises & Discoveries

- Observation: The sandbox cannot write to this machine's existing npm cache under `~/.npm`.
  Evidence: `npm view astro version` failed with `EPERM` opening `/Users/dave/.npm/_cacache/tmp/...`; rerunning with escalated access succeeded.

- Observation: Astro tries to create a user-level telemetry preferences directory during build unless telemetry is disabled.
  Evidence: The first `npm run build` failed with `EPERM: operation not permitted, mkdir '/Users/dave/Library/Preferences/astro'`; package scripts and the workflow now set `ASTRO_TELEMETRY_DISABLED=1`.

- Observation: The existing release workflow already resolves tags through `scripts/resolve-release-tag.sh` and publishes binary, editor, and agent-plugin artifacts for `v*.*.*` tags.
  Evidence: `.github/workflows/release.yml` has tag and manual dispatch triggers, a `Resolve tag` step, and `softprops/action-gh-release` publication steps.

## Decision Log

- Decision: Put the public docs site under `docs/`, while keeping `.agents/docs/` and `.agents/plans/` for agent-only material.
  Rationale: `AGENTS.md` now reserves `docs/` for rendered human-readable documentation, so the Starlight project belongs there.
  Date/Author: 2026-07-03 / Codex.

- Decision: Publish release-tag docs snapshots under `versions/<tag>/` and publish a separate latest build at the site root.
  Rationale: Starlight does not need to own release history internally. The GitHub Pages workflow can sync the published docs to Bifrost release tags by building from the checked-out tag and preserving older version folders on the `gh-pages` branch. Version snapshots must be built with a versioned base path so links inside old docs stay under that version folder.
  Date/Author: 2026-07-03 / Codex.

## Outcomes & Retrospective

The first slice establishes the docs site skeleton, build scripts, and release-aware Pages workflow. The content is intentionally sparse: it creates a branded homepage plus starter install, MCP, LSP, and release-versioning pages so the next iteration can focus on full human-facing content instead of project plumbing.

## Context and Orientation

`docs/` is now the public documentation site. It is an independent Node package so the Rust crate and editor extension do not need to share JavaScript dependency state. `.agent/PLANS.md` remains the rules file for ExecPlans. `.agents/docs/` contains agent-only notes and runbooks. `.agents/plans/` contains historical and current ExecPlans.

The existing Bifrost release tag format is `v<semver>`, such as `v0.7.2`. The root Rust package version in `Cargo.toml` is the source of truth for non-release docs builds. The docs workflow should use a release tag when one is present and otherwise label the build as a development build for the current crate version.

## Plan of Work

Create `docs/package.json`, `docs/astro.config.mjs`, `docs/src/content.config.ts`, Starlight content pages under `docs/src/content/docs/`, and a custom stylesheet under `docs/src/styles/brokk.css`. Add `scripts/resolve-docs-version.mjs` to derive docs build metadata from either a release tag or `Cargo.toml`. Add `.github/workflows/docs.yml` to build and publish the static docs site through GitHub Pages by updating the `gh-pages` branch.

## Concrete Steps

From the repository root, install and build the docs:

    cd docs
    npm install
    npm run build

For release metadata checks:

    node scripts/resolve-docs-version.mjs
    RELEASE_TAG_INPUT=v0.7.2 node scripts/resolve-docs-version.mjs

## Validation and Acceptance

The docs setup is accepted when `npm run build` in `docs/` completes successfully, `docs/dist/` contains a static Starlight site, and `node scripts/resolve-docs-version.mjs` emits version metadata both for a branch build and a release-tag build. The workflow is accepted when `.github/workflows/docs.yml` builds from `docs/`, publishes latest content to the Pages root, and preserves release snapshots under `versions/<tag>/`.

## Idempotence and Recovery

The build is repeatable. `docs/dist/` is generated output and should not be committed. If dependency installation fails because of npm cache permissions, rerun the npm command with access to the user's normal npm cache rather than changing project files. If a release docs deployment fails, rerun the GitHub workflow for the same tag; the publish step replaces the matching `versions/<tag>/` folder before pushing.

## Artifacts and Notes

This plan intentionally avoids moving internal `.agents/` material into the public docs. Human-readable content can reference public APIs and workflows, but agent-only runbooks and historical implementation plans stay out of the rendered site.

## Interfaces and Dependencies

The docs package depends on `astro` and `@astrojs/starlight`. The workflow uses `actions/checkout`, `actions/setup-node`, and the repository `GITHUB_TOKEN` to publish the generated site to `gh-pages`.
