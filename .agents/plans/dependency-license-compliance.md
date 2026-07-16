# Ship complete dependency license notices

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan is maintained in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

Bifrost currently explains its own LGPL license well, but its downloadable binary archives, Python wheels, VS Code extension, and agent-plugin archive do not consistently carry the complete GNU license text, third-party dependency notices, or clear directions to matching source. After this change, every artifact produced by the repository's release workflows will contain the license material relevant to the code inside it, the public documentation will tell recipients where to find those notices and exact source, and CI will reject dependency-license drift that has not been reviewed.

A reviewer can see the result by generating the Rust and npm notice reports, packaging a release archive and VSIX locally, and listing each artifact. The archives must contain the combined GPLv3/LGPLv3 license, a corresponding-source notice, and the applicable third-party notices. The dependency-policy checks and docs build must also pass.

## Progress

- [x] (2026-07-16 13:52Z) Refreshed `origin/master`, confirmed the current worktree is detached at `v0.8.4`, and verified that the one newer remote commit does not change dependency or licensing files.
- [x] (2026-07-16 13:52Z) Audited the locked Rust, VS Code, and docs dependency metadata and the current release, wheel, VSIX, plugin, and docs workflows.
- [x] (2026-07-16 13:52Z) Verified the controlling LGPLv3, GPLv3, Apache-2.0, MPL-2.0, and voyage-4-nano license sources.
- [x] (2026-07-16 14:27Z) Added a deny-by-default Rust license policy, a generated Cargo crate report, and a generated supplemental report for standalone notices and vendored native sources that Cargo metadata does not describe.
- [x] (2026-07-16 14:27Z) Added reproducible npm notice generation for the 29 production dependencies bundled into the VS Code extension.
- [x] (2026-07-16 14:27Z) Made binary archives, wheels/source distributions, the VSIX, and the agent plugin carry their applicable license, source, and notice files.
- [x] (2026-07-16 14:27Z) Added and rendered the public Third-Party Notices page, linked it from the license guide, README, and sidebar, and documented optional NLP and build-tool boundaries.
- [x] (2026-07-16 14:27Z) Passed policy, freshness, formatting, workflow parsing, docs, VSIX, wheel, source-distribution, and staged-archive checks and recorded the evidence below.

## Surprises & Discoveries

- Observation: The existing `LICENSE.md` contains only the short LGPLv3 additional-permissions document, although that document incorporates GPLv3 and the public license page already instructs distributors to include both texts.
  Evidence: `LICENSE.md` ends after LGPLv3 section 6, while `docs/src/content/docs/license-use-cases.md` item 3 says distributions should carry copies of GPLv3 and LGPLv3.

- Observation: The tagged release archives copy only `LICENSE.md` and `README.md`; there is no third-party notice report or explicit corresponding-source direction inside the archive.
  Evidence: `.github/workflows/release.yml` stages exactly `LICENSE.md README.md` beside the binary.

- Observation: The default cross-target Rust graph is compatible with Bifrost's LGPL terms but is notice-heavy: about 380 normal/build packages use MIT, Apache, Unicode, BSD, ISC, Zlib, Boost, CC0, and similar terms. The optional `nlp` feature alone adds the MPL-2.0-only `option-ext` crate through `hf-hub -> dirs -> dirs-sys`.
  Evidence: `cargo tree --locked --offline --target all --edges normal,build` reports about 380 packages; adding `--all-features` reports about 454, and `cargo tree --features nlp -i option-ext` shows the stated path.

- Observation: The VSIX excludes `node_modules` but esbuild bundles its three production npm dependencies and transitives into `out/extension.js`; the locked production graph contains 29 packages under MIT, ISC, BSD-2-Clause, and BlueOak-1.0.0.
  Evidence: `editors/vscode/.vscodeignore` excludes `node_modules`, `editors/vscode/esbuild.mjs` bundles the extension, and the production entries in `editors/vscode/package-lock.json` produce the stated license counts.

- Observation: The documentation toolchain contains LGPL and MPL packages, but those native packages are build tools rather than files delivered in the GitHub Pages artifact. The public site still delivers generated client JavaScript from permissively licensed packages, so the docs should expose a scoped notice page rather than claim every package in `docs/package-lock.json` is shipped to browsers.
  Evidence: the LGPL packages are platform-specific `sharp-libvips` packages and MPL packages are `lightningcss` build binaries in the lockfile; `.github/workflows/docs.yml` uploads only `docs/dist`.

- Observation: `cargo-about` 0.9.1 no longer installs its command-line binary from `cargo install` with default features.
  Evidence: the pinned install completed with `bin "cargo-about" requires the features: cli`; the working install command must add `--features cli`.

- Observation: Cargo-level license reports do not expose notices embedded below a Rust wrapper crate's package license. In particular, `libgit2-sys` may compile bundled libgit2, whose `libgit2/COPYING` contains GPLv2 with a broad linking exception plus the notices for libgit2's bundled third-party code; `libz-sys`, bundled SQLite, and tree-sitter's Unicode data have the same metadata boundary.
  Evidence: `libgit2-sys` declares only `MIT OR Apache-2.0` for its Rust wrapper, while its build script falls back to `libgit2/` and the 1,410-line nested `COPYING` begins with libgit2's GPLv2 linking exception. The supplemental report reproduces the exact nested legal files from the versions resolved by `Cargo.lock`.

- Observation: `moka` carries a separate top-level `NOTICE` explaining that two files ported from Caffeine are Apache-2.0-only; `cargo-about` reports the selected crate license text but does not append this standalone notice.
  Evidence: a sweep of every resolved package's top-level `NOTICE*` files found `moka-0.12.15/NOTICE`. The supplemental report now preserves it, and its generator rejects any future unreviewed standalone notice file.

- Observation: A local macOS Maturin build selected Homebrew libgit2 and reported external dynamic dependencies on libgit2, llhttp, OpenSSL, and libssh2 rather than copying them into the test wheel.
  Evidence: Maturin emitted the external-shared-library list and recommended `--auditwheel=repair`; the local wheel contained no `.dylibs` directory. The published v0.8.4 arm64 macOS wheel was then checked directly: `otool -L` shows only macOS system libraries, so the Homebrew warning is local-build hygiene rather than a defect in that published wheel.

- Observation: The already-published v0.8.4 artifacts retain the gaps this plan fixes for future builds.
  Evidence: the downloaded x86_64 Linux release archive contains only the executable, `README.md`, and the old `LICENSE.md`; the published VSIX contains only `extension/LICENSE.md` among legal/source files; and the published PyPI wheel contains only `LICENSE.md` plus its generated SBOM. Repository workflow changes do not retroactively alter those downloads.

- Observation: `cargo-about` preserves CRLF bytes embedded in one upstream crate's license text, while Git's default text normalization rewrote those lines when the generated HTML was committed.
  Evidence: a clean regeneration differed only by 591 carriage returns inside the `proc-macro-error` Apache license block. Marking `THIRD_PARTY_LICENSES.html -text` in `.gitattributes` preserves the generator's exact bytes and makes the CI freshness comparison meaningful.

## Decision Log

- Decision: Treat the request as both an audit and a request to remediate confirmed documentation and artifact gaps.
  Rationale: The user explicitly asked whether the docs or notices need updating; the current release packaging demonstrably omits material the repository itself says should accompany distributions.
  Date/Author: 2026-07-16 / Codex

- Decision: Use `cargo-about` for exact Rust notice generation and `cargo-deny` for a deny-by-default Rust license policy instead of maintaining a handwritten crate inventory.
  Rationale: The Cargo graph has hundreds of target-conditional packages and changes with the lockfile. Established Cargo tooling evaluates SPDX alternatives and carries actual license text, reducing stale or incomplete hand-maintained notices.
  Date/Author: 2026-07-16 / Codex

- Decision: Generate a separate npm notice file for the VSIX production graph and do not represent all docs build dependencies as browser-shipped components.
  Rationale: The VSIX bundles npm code into one distributable JavaScript file, while GitHub Pages receives only the built docs output. Artifact-specific scopes are more accurate than one repository-wide dump.
  Date/Author: 2026-07-16 / Codex

- Decision: Ship `SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt` beside the Cargo-level report and make its generator reject newly introduced standalone notices or unaudited Cargo `links` packages.
  Rationale: `cargo-about` correctly reports crate metadata but cannot see Moka's separate notice or nested libgit2, zlib, SQLite, and Unicode terms. A deterministic companion report preserves those texts and exact source-package links without misclassifying the crates' own licenses. Failing on a new notice or native-linking package forces the same deeper audit on future dependency changes.
  Date/Author: 2026-07-16 / Codex

- Decision: Keep `option-ext` under a narrow MPL-2.0 exception and document its source-availability consequence for any future prebuilt `nlp` artifact.
  Rationale: MPL-2.0 is compatible with a larger LGPL work, but executable distribution requires informing recipients how to obtain the MPL-covered source. Current official binaries and wheels do not enable `nlp`, so this must not be misstated as an obligation of today's default artifact.
  Date/Author: 2026-07-16 / Codex

- Decision: Do not commit checkpoints while the worktree remains detached.
  Rationale: Repository instructions forbid switching or creating a branch without an explicit request, and a detached checkpoint would not land on the current branch. Changes and validation will remain in the shared worktree for the user to place on a branch.
  Date/Author: 2026-07-16 / Codex

## Outcomes & Retrospective

The audit found no dependency-license incompatibility in today's official default CLI or `python` wheel feature sets. The material gaps were distribution hygiene: the repository carried only the LGPL addendum rather than the combined GPL/LGPL text, release archives omitted dependency notices and exact-source directions, the VSIX bundled npm code without its notices, and crate-level reporting missed vendored native licenses.

Those gaps are now remediated in the worktree. The combined GNU text, exact tag-to-source mapping, generated crate report, and generated supplemental report are packaged with Rust binaries and Python distributions; the VSIX generates and ships its scoped npm report; the plugin carries Bifrost's license/source notice; and the docs explain each boundary. CI pins `cargo-about` and `cargo-deny`, rejects unreviewed Cargo licenses, standalone notices, and native-linking packages, and compares generated reports byte-for-byte.

Validation passed: `cargo deny --locked check licenses` reported `licenses ok`; both Rust notice generators reproduced the committed bytes; `cargo fmt --check`, Prettier, Node syntax checks, workflow YAML parsing, and `git diff --check` passed; VS Code ran 54 tests and the packaged VSIX contained all three expected documents; docs built 53 pages and checked 4,402 links; the rebuilt wheel and source distribution contained all four Rust compliance documents; and a staged binary archive contained the same four documents plus the README. The initial implementation remained uncommitted while the worktree was detached; the user's later PR request authorized creating `dave/dependency-license-notices` for publication.

Publication remains an operational follow-up: v0.8.4's existing GitHub and PyPI assets still contain the old payloads. They should be superseded by a release built from these changes (or replaced in place only after deliberate release-owner review), because committing the workflow and documentation fixes cannot update already-distributed archives.

## Context and Orientation

`Cargo.toml` and `Cargo.lock` define the Rust library, command-line binary, and native Python module dependency graph. The tagged binary workflow in `.github/workflows/release.yml` compiles the default feature set for Linux, Android, macOS, and Windows and archives the binary. `.github/workflows/publish-wheels.yml` builds the Python feature through Maturin; `pyproject.toml` controls which license files are placed in wheel metadata. The optional Rust `nlp` feature is not enabled by either of those workflows.

`editors/vscode/package.json`, its lockfile, `editors/vscode/esbuild.mjs`, and `.vscodeignore` define the VS Code artifact. Esbuild combines production dependencies into `out/extension.js`, and `vsce` packages that bundle without `node_modules`. The agent plugin is a separate tar archive assembled from `plugins/bifrost-agent` by the release workflow and has no external npm runtime dependencies.

`docs/src/content/docs/license-use-cases.md` is the current public orientation for Bifrost's LGPL terms. `docs/astro.config.mjs` supplies its sidebar. The new third-party page must distinguish licenses on Bifrost itself, dependencies actually incorporated into distributed artifacts, optional components downloaded or enabled by users, and build-only tooling.

A “third-party notice” is a file that preserves dependency copyright, attribution, and license text required when compiled or bundled copies are redistributed. A “corresponding-source direction” is a notice telling a binary recipient how to obtain the exact source revision and build scripts matching that binary. A “license policy check” evaluates each locked dependency's SPDX expression and fails when no reviewed license choice satisfies the configured allowlist.

## Plan of Work

First add `deny.toml`, `about.toml`, and a Handlebars template as appropriate for `cargo-about`. Configure the union of targets used by binary and wheel releases, exclude development-only dependencies, prefer permissive alternatives where a crate is dual-licensed, and allow Bifrost's LGPL license. Put the MPL-2.0 allowance only on `option-ext`, not in the global allowlist. Generate a source-controlled `THIRD_PARTY_LICENSES.html` for the default plus `python` feature union, because that matches today's compiled release artifacts. Generate a separate `SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt` from exact locked package sources for standalone notices and legal files nested below Cargo wrapper metadata. Add CI commands that check the all-feature license policy and regenerate both shipped reports to prove they are current.

Replace the incomplete standalone LGPL-only `LICENSE.md` with the official combined GPLv3 and LGPLv3 text while keeping the same path and project license identifier. Add a concise `SOURCE.md` explaining that version `X.Y.Z` corresponds to Git tag `vX.Y.Z`, where recipients can download the complete source and build scripts. Make Maturin include `LICENSE.md`, `SOURCE.md`, `THIRD_PARTY_LICENSES.html`, and `SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt` in wheel metadata. Make binary archives stage the same files.

Add a small Node script under `scripts/` that reads the production package graph from `editors/vscode/package-lock.json`, finds installed package license and notice files after `npm ci`, and emits a deterministic `editors/vscode/THIRD_PARTY_LICENSES.txt`. It must fail when a bundled package has neither a declared license nor readable license text. Generate the editor-local license copies during test and prepublish rather than committing them. Ensure the VSIX contains the combined GNU license, source notice, and npm notice report. Apply the same canonical license and source files to the dependency-free agent plugin archive.

Update `docs/src/content/docs/license-use-cases.md` to point to the artifact notices and explain the optional NLP boundary. Add `docs/src/content/docs/third-party-notices.md` and a sidebar entry. That page should summarize artifact scopes, source locations, and the Apache-2.0 license on the `voyageai/voyage-4-nano` model without turning the documentation into a substitute for the generated license report.

Finally, run the Rust license policy against all features and targets, regenerate both reports and prove a clean diff, build the docs, package the VSIX, inspect archive contents, and run relevant formatting/lint checks. Update this plan with exact command outputs and any limitations.

## Concrete Steps

Run all commands from `/Users/dave/.codex/worktrees/ddd3/bifrost` unless a command explicitly changes directory.

Install or invoke pinned `cargo-about` and `cargo-deny` versions, then generate and validate the Rust report:

    cargo deny --locked check licenses
    cargo about generate --features python --locked --fail about.hbs -o THIRD_PARTY_LICENSES.html
    node scripts/generate-supplemental-third-party-notices.mjs

After `npm ci` in `editors/vscode`, generate and verify the VSIX report:

    node scripts/prepare-vscode-license-artifacts.mjs
    npm test --prefix editors/vscode
    npx --prefix editors/vscode --no-install vsce package --out /tmp/bifrost-license-audit.vsix

Build and inspect documentation:

    npm ci --prefix docs
    npm run build --prefix docs

Inspect packaged content with `unzip -l` for the VSIX and wheel and `tar -tzf` for a Unix release archive. Each artifact must show the files described in `Validation and Acceptance`.

## Validation and Acceptance

The Rust policy passes for every normal and build dependency under all features, and fails if an unreviewed license is introduced. Regenerating `THIRD_PARTY_LICENSES.html` produces no Git diff. The report names each package/version and contains the exact chosen license text and source URL.

A staged binary archive contains `bifrost`, `README.md`, `LICENSE.md`, `SOURCE.md`, `THIRD_PARTY_LICENSES.html`, and `SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt`. `LICENSE.md` contains both the GPLv3 and LGPLv3 headings. `SOURCE.md` directs version `X.Y.Z` recipients to tag `vX.Y.Z`.

A built wheel contains the same four compliance documents under its `.dist-info/licenses` directory. The VSIX contains `LICENSE.md`, `SOURCE.md`, and `THIRD_PARTY_LICENSES.txt`, and its notice report covers the 29 locked production npm packages bundled by esbuild. The agent plugin archive contains `LICENSE.md` and `SOURCE.md`.

The public docs build and link checker pass, and the rendered navigation exposes “Third-Party Notices.” The page accurately says that official default binaries and Python wheels do not enable `nlp`; if an NLP-enabled binary is distributed, its notice/source bundle must additionally cover `option-ext` under MPL-2.0 and the separately downloaded Apache-2.0 voyage model.

`cargo fmt --check` remains clean. Workflow YAML parses, npm formatting/typecheck/lint/tests pass, and `git diff --check` reports no whitespace errors.

## Idempotence and Recovery

Notice generation must be deterministic: rerunning with the same lockfiles and tool versions rewrites identical bytes. `npm ci` may be safely rerun because `node_modules` is ignored. If a generator fails on missing metadata, do not insert a guessed license; inspect the dependency's published source and add a narrowly documented clarification. If generated files are interrupted, rerun the generator rather than editing its output by hand.

The worktree was detached at the start of this plan. The user subsequently requested a PR, explicitly authorizing branch creation, rebasing, committing, and pushing. All generated-file checks remain deterministic and recoverable from Git.

## Artifacts and Notes

Initial audit evidence:

    HEAD: 99eb52eb (v0.8.4), detached
    origin/master: 5d20c63e
    manifest/lockfile diffs: none
    default Rust normal/build graph across targets: about 380 packages
    all-feature Rust normal/build graph across targets: about 454 packages
    VSIX production npm graph: 29 packages
    current binary archive license payload: LICENSE.md, README.md

Authoritative findings used to shape the plan: LGPLv3 section 4 requires prominent notice plus copies of GPLv3 and LGPLv3 for a combined work; GPLv3 section 6 describes equivalent access to corresponding source for object-code downloads; Apache-2.0 section 4 requires the license and applicable NOTICE attributions on redistribution; MPL-2.0 section 3.2 requires executable recipients to be told how to obtain the MPL-covered source. The official `voyageai/voyage-4-nano` model repository declares Apache-2.0.

## Interfaces and Dependencies

Pin `cargo-about` at version 0.9.1 with its `cli` feature and `cargo-deny` at version 0.20.2 in CI or installation commands so generated output and policy behavior do not drift unexpectedly. `cargo-about` owns Rust license-text discovery and rendering. `cargo-deny` owns SPDX policy evaluation. The npm generator must use only Node's standard library so it does not add another production or notice-generation dependency.

The generated public interfaces are `THIRD_PARTY_LICENSES.html` for Rust crate metadata, `SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt` for standalone and vendored-source notices, and `editors/vscode/THIRD_PARTY_LICENSES.txt` for the VSIX. Human-facing explanations belong in the docs page; generated reports are not edited by hand.

Plan revision note (2026-07-16): Created the initial self-contained plan after auditing the current dependency graphs, official license terms, and all repository distribution workflows.

Plan revision note (2026-07-16): Recorded the `cargo-about` 0.9.1 `cli` feature requirement discovered during the first pinned installation attempt.

Plan revision note (2026-07-16): Added the supplemental audit layer after finding that Cargo wrapper metadata omits Moka's separate notice, libgit2's GPLv2 linking exception, and other nested native/data notices; recorded completed implementation and artifact-level validation.

Plan revision note (2026-07-16): Corrected the README duplicate reported during diff review, removed unrelated Markdown/YAML formatting churn, updated the VSIX generation steps to match the implementation, and recorded the user's authorization to publish a PR.

Plan revision note (2026-07-16): Rebased onto current `origin/master` and preserved cargo-about's mixed upstream line endings so the generated-report freshness gate is byte-stable.
