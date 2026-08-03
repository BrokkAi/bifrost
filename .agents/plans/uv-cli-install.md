# Ship the Bifrost CLI as a uv-installable tool

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Maintain this document in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

After this change, a user with uv can install the released Bifrost command-line program with `uv tool install brokk-bifrost` or run it without a persistent install with `uvx brokk-bifrost`. The installed `bifrost` command is the existing native Rust executable, not a Python reimplementation or downloader. The release workflow publishes platform wheels to PyPI, and the installation guide clearly separates this CLI distribution from the existing `brokk-bifrost-searchtools` Python library.

## Progress

- [x] (2026-08-03 16:25Z) Inspected the current Python package, wheel release workflow, installation documentation, uv tool behavior, and maturin binary-wheel support.
- [x] (2026-08-03 16:25Z) Confirmed that the current wheel is library-only and that the `brokk-bifrost` PyPI project name is unclaimed.
- [x] (2026-08-03 16:52Z) Built a separate binary wheel from the existing root Cargo package; its only script is `bifrost`, and a temporary uv tool install ran `bifrost --version` and `bifrost --help` successfully.
- [x] (2026-08-03 17:00Z) Added five-platform CLI wheel construction, artifact separation, version/count verification, canonical license staging, and publication download to the release workflow.
- [x] (2026-08-03 17:05Z) Documented persistent and one-shot uv use, upgrades, removal, platform coverage, and the separate Python API distribution.
- [x] (2026-08-03 17:10Z) Ran focused release and CI-impact tests, YAML parsing, Rust formatting, and diff checks. The repository-required `bifrost-policy-checking` skill and its MCP tools are not installed in this session, so that check could not run.

## Surprises & Discoveries

- Observation: `brokk-bifrost-searchtools` already supports uv as an ordinary Python dependency, but it cannot be installed as a uv tool because it has no executable entry point.
  Evidence: Root `pyproject.toml` declares only the `bifrost_searchtools._native` PyO3 module and `[tool.uv] package = false`; there is no `[project.scripts]` table.

- Observation: Maturin has a purpose-built binary binding that installs Rust executables as wheel scripts.
  Evidence: The official maturin bindings guide says `bindings = "bin"` packages binaries as scripts available on the virtual environment `PATH`; uv's tool guide says `uv tool install` installs all executables supplied by a package.

- Observation: PEP 639 license paths cannot escape the directory containing `pyproject.toml`, while Bifrost's canonical license and generated notice files live at the repository root.
  Evidence: Maturin rejected `../../LICENSE.md` with `The parent directory operator (..) ... is not allowed in glob`. `scripts/prepare-uv-cli-package.mjs` now stages the canonical files into an ignored package-local directory before the build, and the final wheel records each staged file under `.dist-info/licenses`.

- Observation: Truncating `bifrost --help` with `head` closes stdout early and makes the CLI panic on a broken pipe.
  Evidence: The installed wheel printed its help and then panicked at `std/src/io/stdio.rs` with `failed printing to stdout: Broken pipe`. Full, untruncated help exits successfully. This pre-existing CLI behavior is outside the uv packaging scope.

## Decision Log

- Decision: Publish the CLI as `brokk-bifrost`, separate from `brokk-bifrost-searchtools`.
  Rationale: The existing name describes and documents an importable Python API. Reusing it for a large executable would make library installs pay for a duplicate Rust artifact and blur two different interfaces. The CLI distribution can use the same name as the Cargo package and provide the `bifrost` command directly.
  Date/Author: 2026-08-03 / Codex

- Decision: Package the existing Rust binary with maturin's `bin` binding rather than add a Python launcher.
  Rationale: The native binary is already the canonical CLI. Binary wheels preserve its arguments, exit codes, MCP/LSP stdio behavior, and startup path without a second implementation layer.
  Date/Author: 2026-08-03 / Codex

- Decision: Publish CLI wheels only, without a CLI source distribution.
  Rationale: uv gets a fast native install on the explicitly built platforms. On other platforms the existing Cargo installation is the supported source build; silently compiling a large Rust project as a Python-package fallback would be slow and would obscure the Rust toolchain requirement.
  Date/Author: 2026-08-03 / Codex

## Outcomes & Retrospective

The implementation is complete in the checkout. A real `brokk_bifrost-0.8.19-py3-none-macosx_11_0_arm64.whl` contained one 86,948,560-byte native `bifrost` script, package metadata, canonical license files, and its generated CycloneDX SBOM. uv installed exactly one executable, and that executable printed `bifrost 0.8.19` and its normal help.

The release workflow now builds five searchtools wheels, five CLI wheels, and one searchtools source distribution; verifies their names, counts, and versions; and gives the existing trusted PyPI publisher all artifacts. The public installation page and root README document persistent and one-shot uv commands without confusing the CLI distribution with the Python API.

One external release-owner action remains before the first publication: configure a PyPI pending trusted publisher for the unclaimed `brokk-bifrost` project, using GitHub owner `BrokkAi`, repository `bifrost`, workflow `release.yml`, and environment `release`. This is registry configuration, not a repository change. After it exists, the next normal tagged release can create and publish the project through the existing OIDC job.

## Context and Orientation

The root `Cargo.toml` defines the Rust package `brokk-bifrost` and its `bifrost` binary in `src/bin/bifrost.rs`. The root `pyproject.toml` defines a different distribution, `brokk-bifrost-searchtools`, which maturin builds as the importable native module `bifrost_searchtools._native`. `.github/workflows/build-wheels.yml` builds that library distribution for Linux, macOS, and Windows, and `.github/workflows/release.yml` publishes the resulting wheels to PyPI. `docs/src/content/docs/install.md` is the public installation page.

A wheel is a Python package artifact. Maturin's `bin` binding places compiled Rust binary targets in the wheel's scripts area, which package installers expose as commands. uv calls such packages tools: `uv tool install` keeps one in a persistent isolated environment, while `uvx` creates or reuses a temporary isolated environment for one command invocation.

## Plan of Work

Add a CLI-specific Python package manifest under a repository-owned packaging directory. It names the distribution `brokk-bifrost`, takes its dynamic version from the root Cargo package, points maturin at the root `Cargo.toml`, selects binary bindings, and limits the packaged target to the user-facing `bifrost` executable if maturin otherwise includes development binaries.

First build a local wheel and inspect its contents. Install that exact wheel into a temporary uv tool directory and run `bifrost --version` and `bifrost --help`. This prototype decides whether a nested manifest can safely drive the root Cargo package and whether additional Cargo target metadata is needed.

Then extend `.github/workflows/build-wheels.yml` to build CLI wheels alongside the existing Python library wheels for the platforms supported by PyPI. Keep artifact names separate, verify both distributions carry the release version, and extend `.github/workflows/release.yml` so trusted publishing uploads both sets in the same release. Update `scripts/release-promotion-workflow.test.mjs` or add a focused packaging check so removal or renaming of the CLI artifacts fails before release.

Update `docs/src/content/docs/install.md` and the root `README.md` installation summary with persistent and one-shot uv commands, upgrade and uninstall commands, supported platform constraints, and the distinction between the CLI package and Python API package. Add a local validation script or test that builds or inspects the CLI package without writing a persistent target under `/tmp`.

## Concrete Steps

Work from the repository root.

Create the CLI packaging manifest, then build through the repository's isolated-target helper or the existing Cargo target when only inspecting the packaging prototype:

    uvx --from 'maturin>=1.7,<2.0' maturin build --manifest-path Cargo.toml --bindings bin --release --locked --out <temporary-dist>

Inspect the wheel and install it with uv using temporary tool and cache directories. The exact environment variables will be recorded after confirming uv's directory controls. Run:

    bifrost --version
    bifrost --help

The first command must print the Cargo workspace version, and the second must exit successfully with the existing CLI help.

After workflow and documentation edits, run the focused JavaScript release tests, formatting checks for changed text/configuration, and Rust formatting. Run broader Rust checks only if Rust source or Cargo target declarations change.

## Validation and Acceptance

Acceptance requires a locally built wheel named for the normalized `brokk-bifrost` distribution, containing only the intended `bifrost` executable plus wheel metadata. Installing that wheel with `uv tool install` must put `bifrost` in uv's tool binary directory, and invoking it must report the checkout's version and show the normal help output.

Release validation must prove that every supported target creates both the existing searchtools wheel and the CLI wheel, that artifact names cannot collide, that all artifacts carry the validated tag version, and that trusted publishing uploads both. Documentation must not imply that `uv add brokk-bifrost` provides the Python API; it must direct library users to `brokk-bifrost-searchtools`.

## Idempotence and Recovery

Local wheel output and uv tool directories must be created with `mktemp -d` and removed after validation. Cargo builds that require an isolated target must use `scripts/with-isolated-cargo-target.sh`, which cleans up on success, failure, or interruption. Re-running the workflow creates fresh artifacts and does not mutate a release. PyPI publication itself remains controlled by the existing explicit release workflow and is not performed during this task.

If the nested CLI manifest cannot drive the root Cargo package, do not add a Python wrapper. Instead, keep the user-visible design and move the CLI package metadata to a location maturin accepts, documenting the discovered constraint here before changing course.

## Artifacts and Notes

Current package boundary:

    brokk-bifrost-searchtools -> import bifrost_searchtools
    brokk-bifrost             -> run bifrost

The official maturin behavior relied on here is that `bin` bindings store Rust executables as wheel scripts. The official uv behavior relied on here is that `uv tool install PACKAGE` persistently installs every executable supplied by that package, while `uvx COMMAND` runs a provided command from an isolated tool environment.

## Interfaces and Dependencies

Use the existing release dependency on `maturin>=1.7,<2.0`; do not add a runtime Python dependency. The CLI wheel must compile the root Cargo package without `nlp` by default, matching normal `cargo install brokk-bifrost --locked`. The distribution metadata must use `requires-python` only to express uv/Python installer compatibility; the installed command remains a native Rust executable and must not import Python at runtime.

Revision note (2026-08-03): Created the initial plan after inspecting current packaging and release paths and confirming maturin and uv's supported binary-tool behavior.

Revision note (2026-08-03 17:10Z): Recorded the completed wheel prototype, release and documentation changes, license-staging discovery, validation evidence, and the one-time external PyPI publisher requirement.
