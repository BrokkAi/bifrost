# Publish the Bifrost CLI through npm

This ExecPlan is a living document. Keep the `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` sections current. Maintain this file as required by `.agents/PLANS.md`.

## Purpose / Big Picture

Users can install the released native Bifrost CLI with `npm install -g @brokkai/bifrost` or run it with `npx @brokkai/bifrost`. The npm packages reuse checksum-verified GitHub release archives. They do not rebuild or download the binary during installation. The first npm version is published by a maintainer. Later successful Bifrost release tags publish through npm trusted publishing.

## Progress

- [x] (2026-08-05 13:54Z) Compare the Anvil and Mjolnir npm package layouts and workflows.
- [x] (2026-08-05 14:05Z) Add the root launcher, seven platform package definitions, package builder, publisher, and tests.
- [x] (2026-08-05 14:05Z) Add the npm trusted-publishing workflow and public installation documentation.
- [x] (2026-08-05 14:05Z) Build and smoke-test the packages from the existing `v0.8.22` GitHub release.
- [x] (2026-08-05 14:07Z) Run final repository checks and prepare all scoped files for the checkpoint commit. The Bifrost policy MCP tools are not installed in this session.

## Surprises & Discoveries

- Observation: Bifrost already publishes `@brokk/bifrost-agent` as a Pi package artifact.
  Evidence: `plugins/bifrost-agent/package.json` names that package, while the new CLI package will use `@brokkai/bifrost`.
- Observation: Release `v0.8.22` has archives and SHA-256 sidecars for seven targets.
  Evidence: The release includes macOS universal, two Linux x64 variants, Linux ARM64, Android ARM64, and two Windows targets.
- Observation: Native release archives keep six notice files beside the binary.
  Evidence: Package validation found `LICENSE.md`, `GPL-3.0.md`, `SOURCE.md`, `README.md`, `THIRD_PARTY_LICENSES.html`, and `SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt`.
- Observation: The repository security audit rejects a `workflow_run` trigger.
  Evidence: Zizmor reported `dangerous-triggers` until the successful release summary dispatched `publish-npm.yml` through `workflow_dispatch`.

## Decision Log

- Decision: Follow the Mjolnir package structure and publication order.
  Rationale: It is the direct template requested by the user. It also publishes platform packages before the root wrapper.
  Date/Author: 2026-08-05 / Codex
- Decision: Add one package for each Bifrost release target.
  Rationale: Bifrost already publishes verified archives for all seven targets. The npm surface must not omit supported release files.
  Date/Author: 2026-08-05 / Codex
- Decision: Keep the CLI package separate from `@brokk/bifrost-agent`.
  Rationale: The existing package is a Pi extension. The new package installs the `bifrost` executable.
  Date/Author: 2026-08-05 / Codex
- Decision: Dispatch npm publication from the successful release summary.
  Rationale: This preserves tag-driven publication and passes the repository security policy.
  Date/Author: 2026-08-05 / Codex

## Outcomes & Retrospective

The package builder created eight `0.8.22` tarballs from the published release. The installed npm launcher ran the release binary and printed `bifrost 0.8.22`. The Node policy tests, documentation build, release metadata check, and GitHub Actions security audit pass. The scoped checkpoint commit records this implementation.

## Context and Orientation

`.github/workflows/release.yml` creates native archives named `bifrost-vX.Y.Z-<target>.tar.gz` or `.zip`. It also creates matching `.sha256` files. `Cargo.toml` contains the shared release version in `[workspace.package]`.

The new `npm/` directory will contain only package source and tests. It will create temporary package manifests from a release tag. The root package will contain a Node launcher. Each platform package will contain one native Bifrost release bundle. Exact optional dependencies will make npm install the package for the current operating system, CPU, and C library.

The new `.github/workflows/publish-npm.yml` workflow will run after the existing `Release` workflow succeeds. It will also support a manual validation run. The publish job will use the `npm-publish` GitHub environment and OIDC. OIDC is the short-lived identity token used by npm trusted publishing.

## Plan of Work

Add package definitions and packaging code under `npm/`. Use the Mjolnir launcher and package script as the model. Add Bifrost target names, release archive names, license paths, and Linux glibc or musl selection. Add unit tests for target selection, release tag parsing, generated manifests, launcher process handling, and package construction.

Add `.github/workflows/publish-npm.yml`. Check out the release tag. Download all Bifrost archives and sidecars. Run the npm tests. Build and smoke-test the tarballs. Upload them as workflow artifacts. Publish missing platform packages first. Wait for each version to become visible. Publish the root package last.

Update `README.md`, `docs/src/content/docs/install.md`, and `CONTRIBUTING.md`. Explain the npm install commands, the separate agent package, the one-time manual publication, and the trusted publisher settings.

## Concrete Steps

Run these commands from `/Users/ryansvihla/code/bifrost`:

    npm test --prefix npm
    gh release download v0.8.22 --repo BrokkAi/bifrost --dir <temporary-directory> --pattern 'bifrost-v0.8.22-*'
    npm run package-release --prefix npm -- --release-tag v0.8.22 --assets <temporary-directory>
    npm run test-release --prefix npm -- --dist dist --release-tag v0.8.22

Run the repository Node policy tests and the GitHub Actions security audit. Then run the Bifrost policy selection if its MCP tools are installed. Review all findings before the final commit.

## Validation and Acceptance

`npm test --prefix npm` must pass. Package construction must create eight tarballs for version `0.8.22`. The tarballs must contain only the root launcher or one released platform bundle. The local smoke test must run `bifrost --version` through the npm launcher and report `0.8.22`.

The workflow must pass the checked-in immutable-action policy and the security audit. A manual workflow run with publication disabled must stop after it uploads validated tarballs. A successful future `Release` workflow must publish missing platform packages before `@brokkai/bifrost`.

## Idempotence and Recovery

Package construction removes and recreates `npm/dist`. It does not change release assets. The publish script skips a package version that already exists. This permits a safe retry after partial publication. It never publishes the root wrapper until every platform package is visible.

## Artifacts and Notes

The initial npm version is `0.8.22`. A maintainer must publish it with interactive npm credentials before configuring trusted publishing. Each of the eight package names needs the same trusted publisher settings: repository `BrokkAi/bifrost`, workflow `publish-npm.yml`, and environment `npm-publish`.

## Interfaces and Dependencies

The npm package code uses only Node built-in modules and system `tar` or `unzip`. It has no runtime JavaScript dependency. The root package requires Node 18 or later. The native Bifrost binary keeps its existing command interface.

Revision note: Initial plan created from the current Anvil and Mjolnir npm implementations and Bifrost release `v0.8.22`.
