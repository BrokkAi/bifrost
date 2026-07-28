# Vet and pin a production Tree-sitter grammar for Kotlin

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept current as work proceeds.

This plan follows `.agents/PLANS.md` and implements GitHub issue `#1235`. It deliberately stops before Kotlin is registered as a Bifrost language or given analyzer semantics; those are follow-on issues beginning with `#1236`.

## Purpose / Big Picture

Bifrost needs a Kotlin concrete-syntax tree whose provenance, license, native build, error recovery, and incremental behavior are good enough to support every later Kotlin analyzer layer. After this work, the repository will contain one immutable grammar snapshot that builds without a runtime download, carries its upstream MIT license and exact revision, appears in generated third-party notices, and has focused tests proving clean Kotlin source, Kotlin script source, malformed-source recovery, and incremental reparsing through Bifrost's Tree-sitter 0.25 runtime.

The implementation must also record why the selected grammar beat the alternative. A future maintainer should be able to reproduce the comparison, identify the upstream commit, regenerate the checked-in parser, and update the snapshot without reverse-engineering this session.

## Progress

- [x] (2026-07-28 10:20Z) Read issue `#1235`, repository instructions, the ExecPlan contract, and the existing Scala vendoring/license precedent.
- [x] (2026-07-28 10:20Z) Resolve the current immutable candidate revisions: `fwcd/tree-sitter-kotlin@c8ac3d2627240160b999a2c100de3babbdb8f419` and `tree-sitter-grammars/tree-sitter-kotlin@3dea6dfa9c0129deb7c4315afbda806c85c41667`.
- [x] (2026-07-28 10:47Z) Build both candidates against `tree-sitter = 0.25.10` and collect comparable corpus, native-size, clean-parse, malformed-source, and incremental-edit evidence.
- [x] (2026-07-28 10:47Z) Select `fwcd/tree-sitter-kotlin@c8ac3d2627240160b999a2c100de3babbdb8f419` and record the decision, exact source inventory, MIT copyright, scanner contract, ABI facts, and rejected alternative.
- [x] (2026-07-28 10:47Z) Add the immutable grammar snapshot plus provenance and verified 0.24.7 regeneration instructions without registering Kotlin in the analyzer.
- [x] (2026-07-28 10:47Z) Add focused grammar smoke tests for `.kt`, `.kts`, malformed recovery, incremental edits, and private native symbols.
- [x] (2026-07-28 10:47Z) Integrate the vendored MIT license into Bifrost's supplemental notice generator and verify the publishable crate remains below its 10 MB gate.
- [x] (2026-07-28 10:56Z) Run formatting, focused tests, notice regeneration/check, package check, license policy, all-target/all-feature clippy, and practical local target checks; record MSVC/Android CI-only coverage explicitly.
- [x] (2026-07-28 11:15Z) Move unused upstream highlight/tag queries out of the vendored build surface into `resources/treesitter/kotlin/`, retain their upstream contents and attribution, and keep them excluded from the crate until a consumer is introduced.

## Surprises & Discoveries

- Observation: both candidates expose a modern `tree_sitter_language::LanguageFn`, and both generated parsers declare Tree-sitter language ABI version 14, which is loadable by Bifrost's 0.25 runtime.
  Evidence: both candidate `Cargo.toml` files depend on `tree-sitter-language = "0.1"`; both generated `src/parser.c` files define `LANGUAGE_VERSION 14`.

- Observation: the active `fwcd` source is materially ahead of its crates.io release. The source package declares version `0.4.0`, while its newest repository tag and published crate remain `0.3.8`; using a release number alone would discard the current Rust binding and recent grammar work.
  Evidence: GitHub tags resolve `0.3.8` to `e1a2d5ad1f61f5740677183cd4125bb071cd2f30`, while the compared head is `c8ac3d2627240160b999a2c100de3babbdb8f419`.

- Observation: native footprint is a real tradeoff. At the compared revisions, `fwcd` has a 33,716,905-byte generated parser and 34,940-byte stateful scanner; the community `-ng` candidate has a 22,443,237-byte parser and 15,179-byte stateless scanner.
  Evidence: `wc -c` over each immutable checkout's generated sources.

- Observation: upstream corpus depth strongly favors `fwcd`: it has 14 hand-authored corpus files plus pinned JetBrains PSI cross-validation tooling, whereas `-ng` has three corpus files and no equivalent reference-parser harness.
  Evidence: the immutable source trees and `fwcd`'s `tools/cross-validation/` documentation.

- Observation: both candidates parsed all 53 ordinary files from the two pinned Kotlin example repositories cleanly. On the 228 additional pinned JetBrains PSI sources, including intentional recovery cases, `fwcd` yielded 106 error-bearing roots and 9 files with missing nodes versus `-ng` at 115 and 20. `-ng` was faster: 23.719 ms versus 32.434 ms median aggregate parse time across 11 warm runs.
  Evidence: the disposable Tree-sitter 0.25.10 comparison probe and the retained evaluation report.

- Observation: direct vendoring initially appeared to exceed the 10 MB crate gate because the pre-Kotlin crate was already 9,331,190 bytes. Excluding documentation-site GIF demos from the Rust archive, while retaining them in the repository and docs site, produced a final verified crate of 9,603,624 bytes with every Kotlin build and legal file present and the unused reference queries excluded.
  Evidence: pre- and post-integration runs of `scripts/check-crate-package.sh`.

- Observation: this Mac's `cargo`/`rustc` come from rustup while the first `cargo clippy` dispatch found Homebrew's `clippy-driver`, producing Rust error E0514 despite identical version numbers. Invoking the rustup toolchain's exact `cargo-clippy` binary removed the mixed-compiler metadata and completed cleanly.
  Evidence: tool paths/version metadata and the successful isolated all-target/all-feature clippy run.

- Observation: the upstream highlight query is editor reference material derived from an Apache-licensed nvim-treesitter query; it is not one of Bifrost's `definitions.scm`, `imports.scm`, or `identifiers.scm` analyzer inputs.
  Evidence: the query's retained source header and the explicit embedded-query registry in `src/analyzer/store/epoch.rs`.

## Decision Log

- Decision: compare immutable source revisions rather than the newest crate releases.
  Rationale: the issue is about the production grammar, and `fwcd`'s published crate does not represent its current 0.25-compatible binding or recent grammar changes.
  Date/Author: 2026-07-28 / Codex

- Decision: prefer a vendored generated parser over a Cargo git dependency if `fwcd` wins the behavioral comparison.
  Rationale: vendoring removes runtime/build-time network access, gives release artifacts an auditable native-source snapshot, and follows the repository's successful Scala precedent. A git dependency would be immutable by revision but would complicate offline packaging and notice/source delivery.
  Date/Author: 2026-07-28 / Codex

- Decision: private-prefix Kotlin's native parser and scanner symbols if the snapshot is compiled by Bifrost's `build.rs`.
  Rationale: both candidates export the same generic `tree_sitter_kotlin` and scanner symbol names. Private symbols prevent a downstream Kotlin grammar crate or link order from silently substituting a different parser, matching the Scala correctness guard.
  Date/Author: 2026-07-28 / Codex

- Decision: select the `fwcd` revision despite the `-ng` candidate's smaller parser and roughly 27% faster spike result.
  Rationale: later indexing and semantic correctness depend more on clean, stable structure. `fwcd` has 257 hand-authored corpus cases, pinned JetBrains PSI cross-validation, fewer error-bearing fixture parses, and fewer missing-node parses. The source and package-size costs are measurable and fit the existing release gate after removing non-runtime documentation media from the crate archive.
  Date/Author: 2026-07-28 / Codex

- Decision: keep the vendored directory limited to grammar build, audit, and regeneration inputs; relocate the unchanged upstream highlight/tag queries to `resources/treesitter/kotlin/` without registering them as analyzer inputs.
  Rationale: Bifrost-owned Tree-sitter queries live under `resources/treesitter/<language>`. Keeping unrelated editor queries under `vendor/` obscures that ownership boundary, while deleting them would discard useful upstream reference material and attribution.
  Date/Author: 2026-07-28 / Codex

## Outcomes & Retrospective

The selected `fwcd` grammar and generated native sources are vendored unchanged, private-linked, licensed, documented, and reproducibly regenerable without entering Kotlin into analyzer discovery. The upstream query contents remain unchanged under `resources/treesitter/kotlin/`; only their paths in `tree-sitter.json` differ from upstream. Four focused grammar tests pass. Format and diff checks, deterministic notices, `cargo deny`, publishable-crate verification, and all-target/all-feature clippy pass. An independent intent/build/license review found no blocking issues. Native sources compile locally for macOS, Linux x64/arm64, and Windows GNU; the repository's CI runners remain the authoritative MSVC and Android gates once these uncommitted changes are published. Issue #1236 can now register this exact `LanguageFn` and add Kotlin to normal analyzer dispatch without reopening grammar selection.

## Context and Orientation

`Cargo.toml` pins Bifrost's shared runtime at `tree-sitter = "0.25.10"` and documents the policy that each grammar is independently pinned. `build.rs` currently compiles the checked-in Scala parser and scanner from `vendor/tree-sitter-scala/src`, prefixes every exported native symbol, and emits rerun directives. `vendor/tree-sitter-scala/BIFROST_PATCH.md` is the provenance model: it names the exact upstream commit, retained patches, Tree-sitter CLI version, regeneration command, and focused tests.

`scripts/generate-supplemental-third-party-notices.mjs` reads legal files from both resolved Cargo packages and native snapshots. Its vendored Scala section establishes how a Kotlin snapshot must be represented. `licenses/SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt` is generated output and `.github/workflows/ci.yml` fails when regeneration differs. `licenses/deny.toml` already allows MIT, so the Kotlin addition should require notice coverage rather than a policy exception.

The candidate source revisions being measured are:

* `https://github.com/fwcd/tree-sitter-kotlin/tree/c8ac3d2627240160b999a2c100de3babbdb8f419`, source package version `0.4.0`, MIT copyright 2019 fwcd, generated parser plus stateful C scanner, Rust `LanguageFn` binding.
* `https://github.com/tree-sitter-grammars/tree-sitter-kotlin/tree/3dea6dfa9c0129deb7c4315afbda806c85c41667`, source package version `1.1.0` / published crate `tree-sitter-kotlin-ng`, MIT copyright 2024 Amaan Qureshi, generated parser plus stateless C scanner, Rust `LanguageFn` binding.

The evaluation must not use node-name similarity as a substitute for syntax correctness. It should count Tree-sitter error and missing nodes, retain representative failure examples, and exercise incremental reparsing using a correctly edited old tree. Kotlin analyzer queries and CodeUnit lowering are intentionally outside this plan.

## Plan of Work

Milestone 1 is a disposable but reproducible comparison harness. Build a tiny Rust probe against `tree-sitter = 0.25.10`, alias both candidate crates from their exact source checkouts, and run the same Kotlin inputs through each language. The probe should report per-file bytes, parse duration, total named nodes, error nodes, missing nodes, and whether the root has errors. It should separately exercise a same-document edit by applying `InputEdit` to the old tree and report changed ranges and the reparsed tree's errors. Include ordinary `.kt`, Gradle-style `.kts`, intentionally malformed input, both upstream corpora, and pinned real-project samples. Record generated-source sizes and build artifacts separately because the richer grammar's footprint may be justified but should not be hidden.

Milestone 2 is the selection record. Add `.agents/docs/kotlin-tree-sitter-grammar-evaluation.md` with exact revisions, collection commands, corpus identities, measurements, known failure examples, ABI/scanner facts, licensing, packaging choice, and the reason the alternative was rejected. The report must distinguish observations measured by Bifrost from claims copied from upstream documentation.

Milestone 3 is the immutable grammar snapshot. Copy only files required for building, auditing, and regeneration into `vendor/tree-sitter-kotlin/`: the MIT `LICENSE`, `grammar.js`, generated `src/parser.c`, `src/scanner.c`, required `src/tree_sitter` headers, `src/grammar.json`, `src/node-types.json`, and `tree-sitter.json`. Retain unchanged upstream query reference material under `resources/treesitter/kotlin/`, separate from the vendored build surface and future Bifrost-owned analyzer queries. Add `BIFROST_PROVENANCE.md` naming the exact commit, unmodified or patched status, the pinned Tree-sitter CLI version taken from upstream generation metadata, regeneration commands, and the acceptance tests. Update `Cargo.toml`'s package include/exclude policy as needed.

Milestone 4 is the private native integration and smoke contract. Refactor `build.rs` only enough to compile the Kotlin parser/scanner alongside Scala with private-prefixed symbols and complete rerun tracking. Expose a narrow internal grammar-language function in a Kotlin module but do not add Kotlin to `Language`, extension discovery, registries, capabilities, or analyzer dispatch. Add behavior-focused tests that load the language through Tree-sitter 0.25 and prove clean `.kt`, clean `.kts`, intentional malformed recovery without losing a following declaration, and correct incremental reparsing after an edit. Add a coexistence test if a published dev dependency is practical; otherwise verify the symbol inventory directly and leave analyzer registration for `#1236`.

Milestone 5 is compliance and portability. Add the vendored license to the supplemental notice generator, regenerate the committed notice, and check package contents. Run the native build and tests locally on the host. Use available installed targets for `cargo check --target`; rely on the existing CI matrix for Windows and Linux architectures that require their native runners, and record that boundary rather than claiming cross-platform execution that did not occur.

## Concrete Steps

From the repository root, inspect and compare the exact sources in a disposable directory. The current spike uses temporary checkouts at the two revisions above. Build the Rust probe with the repository's installed toolchain and preserve its machine-readable result in the evaluation document, not as an opaque temporary artifact.

After selection, populate `vendor/tree-sitter-kotlin/` from the exact Git tree and verify the copied files against that checkout with checksums or `diff --no-index`. Do not regenerate the parser during the initial import; first preserve the immutable upstream generated output. If regeneration is needed, use the pinned CLI version and document any resulting delta as a Bifrost patch.

Use `apply_patch` for repository edits. Run focused validation through `scripts/with-isolated-cargo-target.sh` when a fresh target is useful; do not create persistent manually named Cargo target directories.

Expected focused commands after integration are conceptually:

    cargo fmt --check
    scripts/with-isolated-cargo-target.sh cargo test --test kotlin_grammar_smoke
    node scripts/generate-supplemental-third-party-notices.mjs /tmp/SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt
    cmp licenses/SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt /tmp/SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt
    scripts/check-crate-package.sh
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings

The exact test binary name may change to match the final module placement; update this plan when it does.

## Validation and Acceptance

Acceptance is observable at four levels.

First, the decision report names an exact repository commit, source/release version, SPDX `MIT`, copyright line, Rust binding form, ABI version, scanner state behavior, generated-source size, corpus evidence, and measured results for both candidates.

Second, a clean checkout can compile Bifrost with the selected generated parser and scanner without fetching grammar sources or running Node. Loading the internal Kotlin language through `tree-sitter 0.25.10` succeeds.

Third, focused tests demonstrate: a representative `.kt` file parses without error or missing nodes; a representative `.kts` script parses without error or missing nodes; malformed input produces recoverable error structure while a later declaration remains in the tree; and an `InputEdit` plus incremental reparse returns a clean tree with bounded changed ranges. These tests must inspect parser behavior, not merely compare a registry list.

Fourth, the Kotlin MIT license appears in generated supplemental notices, `cargo deny` remains green, the publishable crate contains every native file required by `build.rs`, and the practical local build checks pass. The existing CI target matrix is the final evidence for Windows/Linux/macOS portability after the change is pushed; local work must not falsely claim those runners were executed.

## Idempotence and Recovery

Candidate checkouts and comparison build artifacts live in a disposable temporary directory and can be recreated from the two recorded commits. Repository changes are additive. If a candidate import is wrong, remove only `vendor/tree-sitter-kotlin/` and its Kotlin-specific build/test/notice edits after reviewing `git diff`; never reset the worktree because unrelated user work may be present.

Parser regeneration is not part of normal builds. It is safe to repeat only with the documented Tree-sitter CLI version. Always compare regenerated native sources before replacing the upstream snapshot because generator-version changes can produce very large opaque diffs.

## Artifacts and Notes

The initial source inspection recorded:

    fwcd parser.c       33,716,905 bytes
    fwcd scanner.c          34,940 bytes
    kotlin-ng parser.c  22,443,237 bytes
    kotlin-ng scanner.c     15,179 bytes

Both licenses are standard MIT texts with distinct copyrights. Their SHA-256 values in the compared checkouts are `948495f61768f7de26bcc61113d8cd95f50bbc15adb678c28c941c6c8fcd5903` for `fwcd` and `0eea8dc45e89deeb03c7799bbbc7b4688f365fb274562f4540ecfebdea82e727` for `-ng`.

## Interfaces and Dependencies

The final native interface should mirror Scala without entering the public analyzer registry. `build.rs` will compile the selected C sources and rename at least these upstream exports to Bifrost-private equivalents:

    tree_sitter_kotlin
    tree_sitter_kotlin_external_scanner_create
    tree_sitter_kotlin_external_scanner_destroy
    tree_sitter_kotlin_external_scanner_scan
    tree_sitter_kotlin_external_scanner_serialize
    tree_sitter_kotlin_external_scanner_deserialize

Rust should convert the private `extern "C" fn() -> *const ()` into `tree_sitter_language::LanguageFn`, then into `tree_sitter::Language` at the internal call site. No second Tree-sitter runtime is permitted. The selected source remains an MIT native component incorporated into Bifrost's LGPL-covered distribution and therefore must retain its upstream license and source URL in supplemental notices.

Revision note (2026-07-28 10:20Z): Created the issue-specific ExecPlan after live issue review and immutable candidate inspection. It converts the approved GitHub outline into executable comparison, vendoring, smoke-test, and compliance milestones while preserving the #1236 registration boundary.

Revision note (2026-07-28 10:47Z): Recorded the completed two-candidate measurements, final `fwcd` selection, immutable source import, regeneration proof, parser smokes, notice integration, and verified crate size. The remaining work is repository-wide validation and review, not unresolved grammar selection.

Revision note (2026-07-28 10:56Z): Closed the local validation milestone with passing focused tests, format/diff checks, deterministic notices, license policy, package verification, clippy, and practical cross-compiles. Documented the local MSVC SDK limitation and retained real Windows/Android runners as CI-only evidence.

Revision note (2026-07-28 10:58Z): Recorded the independent final review result: no blocking scope, native-link, provenance, license, package, or smoke-test findings; real MSVC and Android runners remain the only residual validation boundary.
