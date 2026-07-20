# Generate Rust third-party notices during packaging

This ExecPlan is a living document and must be maintained in accordance with `.agents/PLANS.md`. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must stay current while this work proceeds.

## Purpose / Big Picture

Bifrost currently commits a large `licenses/THIRD_PARTY_LICENSES.html` snapshot and asks CI to reproduce it byte for byte. `cargo-about` can render different license grouping or text from different source caches even when its version and `Cargo.lock` are pinned, so the snapshot check can block unrelated releases without identifying a license-policy violation. After this change, CI still rejects disallowed or unidentified licenses, while release workflows generate one Rust notice artifact from the locked dependency graph and put that exact artifact into every binary archive or Python distribution that incorporates compiled Rust dependencies.

## Progress

- [x] (2026-07-20 18:20Z) Identified every CI, release archive, Python package, crate, extension, and documentation reference to the tracked Rust notice.
- [x] (2026-07-20 18:29Z) Added one reusable generation script with nonempty, package-name, and current-version validation.
- [x] (2026-07-20 18:29Z) Changed ordinary CI from byte comparison to policy enforcement plus successful notice generation.
- [x] (2026-07-20 18:29Z) Added notice producer jobs and artifact downloads to binary and Python publishing workflows.
- [x] (2026-07-20 18:29Z) Removed the tracked HTML snapshot, ignored local generated output, and updated contributor and public documentation.
- [x] (2026-07-20 18:36Z) Parsed workflow YAML, validated shell syntax and generation, proved sdist inclusion, and passed all 43 Python tests with the tracked HTML absent.
- [x] (2026-07-20 18:40Z) Committed the implementation checkpoint, merged current upstream master, and passed final formatting, clippy, and `actionlint` checks before push.

## Surprises & Discoveries

- Observation: Pinning `cargo-about` to 0.9.1 did not make local and clean-CI HTML byte-identical.
  Evidence: the same locked `tree-sitter-scala` package was associated with different MIT text and ordering, while `cargo deny` continued to accept the dependency graph.

- Observation: the Rust notice is needed by binary archives and Python wheels, but the VS Code extension creates a separate notice from its npm lockfile.
  Evidence: `.github/workflows/release.yml` copies the Rust HTML beside binaries, `pyproject.toml` declares it as a wheel license file, and `scripts/prepare-vscode-license-artifacts.mjs` independently produces `editors/vscode/THIRD_PARTY_LICENSES.txt`.

- Observation: downloading every workflow artifact into the PyPI publish directory would also download the standalone notice artifact.
  Evidence: `pypa/gh-action-pypi-publish` receives the entire `dist/` directory, so the publish job now downloads only `wheels-*` and `sdist` artifacts.

## Decision Log

- Decision: Keep `cargo deny` as the license-policy gate and remove only the byte-for-byte `cargo-about` snapshot comparison.
  Rationale: policy acceptance is the correctness property; renderer byte stability is not.
  Date/Author: 2026-07-20 / Codex

- Decision: Generate one notice artifact per publishing workflow, then fan that artifact out to all packaging jobs in that workflow.
  Rationale: this avoids both a committed generated snapshot and per-platform renderer differences while preserving a notice in every artifact that incorporates Rust dependencies.
  Date/Author: 2026-07-20 / Codex

- Decision: Do not add the dependency notice to the crates.io source package.
  Rationale: the crate source does not incorporate its dependencies; Cargo resolves and licenses those dependencies separately. Official binaries and wheels do incorporate them and therefore keep the notice.
  Date/Author: 2026-07-20 / Codex

## Outcomes & Retrospective

The implementation removes the tracked 10,679-line renderer snapshot while preserving license-policy enforcement. A shared script generates a nonempty report identifying `brokk-bifrost 0.8.6`; a locally built sdist contained `licenses/THIRD_PARTY_LICENSES.html`; and all 43 Python integration tests passed while the tracked file was absent. After merging current upstream master, `cargo fmt`, strict all-feature clippy, YAML parsing, and `actionlint` passed. Binary and Python publishing now consume generated workflow artifacts rather than repository snapshots.

## Context and Orientation

`licenses/about.toml` defines accepted SPDX license identifiers and the union of release targets. `licenses/about.hbs` renders `cargo-about` data as HTML. `.github/workflows/ci.yml` currently installs `cargo-about` and `cargo-deny`, checks policy, regenerates HTML, and compares it with the tracked snapshot. `.github/workflows/release.yml` copies that snapshot into each binary archive. `.github/workflows/publish-wheels.yml` builds Python wheels and a source distribution; `pyproject.toml` names the notice as a license file. `licenses/SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt` is independently generated by a deterministic repository script and remains tracked.

A workflow artifact is a file uploaded by one GitHub Actions job and downloaded by dependent jobs in the same workflow run. It is the mechanism used here to ensure every packaging matrix member consumes identical notice bytes.

## Plan of Work

Add `scripts/generate-rust-third-party-notices.sh`. It accepts an output path, runs the pinned `cargo-about` interface against `Cargo.lock`, writes the HTML, and validates that the output is nonempty and contains the current package name and version. This gives CI and release workflows one command and one set of structural checks.

In `.github/workflows/ci.yml`, retain the pinned tools and `cargo deny`, generate the HTML under the runner temporary directory, and remove the `cmp` against a repository snapshot. Keep the deterministic supplemental-notice comparison.

In `.github/workflows/release.yml`, add a notice-generation job that uploads `THIRD_PARTY_LICENSES.html`. Make the binary build matrix depend on it and download the file into `licenses/` before staging archives. In `.github/workflows/publish-wheels.yml`, use the same pattern and make wheel and source-distribution jobs download the notice before invoking maturin. Leave `.github/workflows/publish-crate.yml` unchanged because source crates do not incorporate dependency code.

Delete `licenses/THIRD_PARTY_LICENSES.html`. Update `CONTRIBUTING.md`, `licenses/SOURCE.md`, and `docs/src/content/docs/third-party-notices.md` so they describe generated release artifacts rather than a committed report. Keep `pyproject.toml` naming the generated path so maturin includes it after the workflow downloads it.

## Concrete Steps

From the repository root, edit the script, workflows, packaging metadata documentation, and tracked notice described above. Validate shell syntax with `bash -n scripts/generate-rust-third-party-notices.sh`, parse workflow YAML using the repository's available Ruby or Python YAML parser, and run the generator to a temporary output rather than recreating the deleted tracked path.

Run `cargo fmt --all -- --check` and `cargo clippy --all-targets --all-features -- -D warnings`. Build a Python source distribution after placing a generated notice at the expected path, inspect the archive for the notice, and remove only that generated worktree file afterward. Run existing Node packaging checks affected by the workflow changes.

## Validation and Acceptance

Acceptance requires `git ls-files licenses/THIRD_PARTY_LICENSES.html` to print nothing. Running `scripts/generate-rust-third-party-notices.sh /tmp/THIRD_PARTY_LICENSES.html` must create a nonempty HTML file containing `brokk-bifrost` and the version from `Cargo.toml`. CI must continue to run `cargo deny` and must not contain a `cmp` for the Rust HTML. The release and wheel workflows must have notice jobs, downstream `needs` relationships, and downloads before packaging. A locally built sdist must contain the generated notice under its license files.

## Idempotence and Recovery

The generator overwrites its requested output and creates its parent directory, so rerunning it is safe. Workflow artifact names are scoped to one run. If packaging fails after notice generation, rerunning the workflow recreates the artifact from the same tagged `Cargo.lock`. Local validation must write to `/tmp` or remove only the known generated `licenses/THIRD_PARTY_LICENSES.html` file after packaging.

## Artifacts and Notes

The known failure mode was a byte mismatch in the rendered Scala MIT section rather than a `cargo deny` policy error. The implementation deliberately tests the report's existence and identity without asserting unstable rendering bytes.

## Interfaces and Dependencies

The new script has this interface:

    scripts/generate-rust-third-party-notices.sh OUTPUT_PATH

It requires `cargo-about` 0.9.1 to be on `PATH`, reads `Cargo.toml`, `Cargo.lock`, `licenses/about.toml`, and `licenses/about.hbs`, and writes only `OUTPUT_PATH`. GitHub jobs install the pinned CLI before invoking it. Release packaging jobs consume an Actions artifact named `rust-third-party-licenses` containing a single `THIRD_PARTY_LICENSES.html` file.

Revision note (2026-07-20): Initial plan created after tracing the existing CI and publishing workflows in response to the 0.8.6 release blockage.

Revision note (2026-07-20): Recorded the implemented workflow graph, local sdist proof, ignored generated path, and selective PyPI artifact download.

Revision note (2026-07-20): Recorded successful generation, sdist, and Python-suite validation before the upstream merge checkpoint.

Revision note (2026-07-20): Closed the plan after upstream integration and final workflow, formatting, and clippy validation.
