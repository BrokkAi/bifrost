# Fix Scala annotated-constructor parsing for issue #1016

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this document in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost currently misparses some Scala classes whose primary constructor follows an annotation such as `@Inject()`. For TheHive's `JobCtrl`, the parser ends the class declaration immediately after the annotation. Bifrost consequently returns only two lines from `get_symbol_sources`, omits the constructor parameters and methods from the class range, and cannot resolve a reference whose context is copied from the missing body.

After this change, the same class is parsed as one complete declaration. `get_symbol_sources` returns the constructor and body, nested methods remain inside the class range, and `get_definitions_by_reference` can find `jobSrv.submit` from exact context inside `JobCtrl`. This behavior is demonstrated by analyzer, property-fuzzer, and SearchTools integration tests built from the issue's exact Scala source.

## Progress

- [x] (2026-07-22 11:05Z) Reproduced the existing property-fuzzer violation and confirmed the installed `tree-sitter-scala` is 0.25.1.
- [x] (2026-07-22 11:05Z) Located upstream's constructor-annotation grammar fix and selected the first immutable generated-parser commit containing it.
- [x] (2026-07-22 11:05Z) Chose vendoring over a git dependency so crates.io packages, wheels, and binaries all compile the same corrected parser.
- [x] (2026-07-22 11:13Z) Vendored the fixed generated parser, recorded its checksums, and compiled it through Bifrost's root crate.
- [x] (2026-07-22 11:13Z) Routed every Scala parser consumer through the internal language binding and explicitly invalidated persisted Scala analysis.
- [ ] Add exact analyzer, property-fuzzer, and SearchTools regressions.
- [ ] Update third-party notices and verify crate packaging (completed: notice generator and tracked notice; remaining: packaged-crate inspection and build).
- [ ] Run focused tests, all-feature lint/tests, corpus replays, and the final multi-angle review.

## Surprises & Discoveries

- Observation: The released `tree-sitter-scala` 0.25.1 parser truncates `class JobCtrl @Inject() (` because it can consume the following constructor parameter list as part of the annotation.
  Evidence: `cargo test --test mcp_property_fuzzer i1_fires_on_truncated_jobctrl_scala_fixture -- --nocapture` passes only because the test currently expects `declaration-truncated-at-parse-error`.

- Observation: Upstream fixed the ambiguity after its latest 0.26.0 crate release, so no published crate contains the correction.
  Evidence: grammar commit `6f9d7bc93ee153719d0d785e63e0fc77d333dad7` introduces a dedicated constructor-annotation rule; generated commit `a68000002745b94eec61cef741efe7cede4ff465` is the first immutable parser snapshot containing it.

- Observation: The Chisel confirmation has a different syntax shape, `class VCSSpec extends BackendSpec`, despite producing the same severe adjacent-ERROR signature.
  Evidence: `svsim/src/test/scala/BackendSpec.scala` at corpus commit `e639b4f69e90ecf3f14c25b898fda9d1eadf3cc1` has no constructor annotation. Its replay is evidence about the newer parser snapshot, not permission to add source-range recovery to this issue.

- Observation: The current analysis epoch hashes grammar ABI, node-kind names, and field names but not parser tables.
  Evidence: `src/analyzer/store/epoch.rs::hash_grammar` cannot guarantee that a grammar conflict-resolution change invalidates persisted rows. The Scala salt must therefore be bumped explicitly.

- Observation: The connected Bifrost code-intelligence plugin is rooted at its installed plugin cache rather than this worktree and returns false negatives for repository files.
  Evidence: plugin git operations reported `/Users/dave/.codex/plugins/cache/bifrost/brokk/0.8.7` as the project root. Repository exploration for this issue uses direct worktree reads until that separate tooling defect is addressed.

- Observation: The existing worktree `target` consumed 6.9 GiB and the first regression build failed while writing an incremental dependency graph, despite the volume reporting free space.
  Evidence: Cargo returned `No space left on device (os error 28)`; `cargo clean` removed 9,599 regenerable build files before validation resumed.

## Decision Log

- Decision: Fix the parser grammar rather than widening Bifrost declaration ranges or scanning source text.
  Rationale: A widened range would not restore members swallowed by an `ERROR` node and would make exact-range keyed analyzer facts inconsistent. The repository explicitly requires structured parser/resolver fixes.
  Date/Author: 2026-07-22 / Codex and user.

- Decision: Vendor generated runtime files from `a68000002745b94eec61cef741efe7cede4ff465`.
  Rationale: A git-only dependency is not publishable as-is to crates.io, while a version fallback would cause published artifacts to use the old broken grammar. Vendoring gives every release surface the same parser and pins an immutable source.
  Date/Author: 2026-07-22 / Codex and user.

- Decision: Vendor only `parser.c`, `scanner.c`, the three required tree-sitter headers, the upstream license, and a provenance document.
  Rationale: Bifrost only consumes the language function. Upstream node-type and highlighting assets are not used by this crate and would add unneeded generated material.
  Date/Author: 2026-07-22 / Codex.

- Decision: Append `tree-sitter-scala-a6800000-2026-07` to the Scala analysis-epoch salt.
  Rationale: Parser-table behavior may change without changing ABI, node kinds, or fields, so explicit invalidation is required.
  Date/Author: 2026-07-22 / Codex.

- Decision: Treat a residual Chisel `VCSSpec` truncation as separate follow-up evidence.
  Rationale: It does not use an annotated constructor. This issue must not grow a broad range-repair fallback to hide a distinct grammar failure.
  Date/Author: 2026-07-22 / Codex.

## Outcomes & Retrospective

Implementation has not started. At completion, record the observed TheHive behavior, whether the newer parser also clears Chisel's distinct error, package-validation results, review findings, and any remaining work.

## Context and Orientation

`tree-sitter` is the incremental parsing runtime. A language grammar supplies a generated C parser and an exported `tree_sitter_scala` function that returns the runtime's Scala language descriptor. Bifrost currently obtains that function from the published `tree-sitter-scala` Rust crate declared in `Cargo.toml`.

`src/analyzer/mod.rs` selects a tree-sitter language for each Bifrost `Language`. Scala-specific analyzers and usage resolvers also construct parsers directly. Every current Scala call site refers to `tree_sitter_scala::LANGUAGE`; all of them must instead use one private binding owned by `src/analyzer/scala/language.rs` so the vendored implementation cannot drift between consumers.

`src/analyzer/scala/declarations.rs` converts tree-sitter declarations into Bifrost `CodeUnit` ranges. It already contains structured recovery for malformed indentation trees. That recovery is intentionally unchanged: issue #1016 originates in the grammar's constructor-annotation ambiguity, before declaration extraction receives a correct class node.

`src/analyzer/store/epoch.rs` computes a per-language analysis epoch used to hide stale persisted rows and trigger reanalysis. A manual Scala salt change ensures caches produced by the old parser are not reused.

`tests/mcp_property_fuzzer.rs` contains the exact 109-line TheHive source and a test that currently expects the truncation invariant to fire. `tests/common/inline_project.rs` supplies `InlineTestProject`, which creates small temporary workspaces without handwritten path management. The shared issue fixture will remain a source file under `tests/fixtures/scala-issue-1016/JobCtrl.scala`; tests can load it with `include_str!` and install it through `InlineTestProject`.

`scripts/generate-supplemental-third-party-notices.mjs` supplements Cargo-generated license reports for bundled native source. Once Scala is no longer represented as a Cargo package, this script must read the vendored MIT license directly and render its immutable upstream source URL. CI compares its output byte-for-byte with `licenses/SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt`.

## Plan of Work

First, create `vendor/tree-sitter-scala/src/tree_sitter/` and copy the generated `parser.c`, `scanner.c`, `parser.h`, `alloc.h`, and `array.h` from upstream commit `a68000002745b94eec61cef741efe7cede4ff465`. Copy the upstream MIT `LICENSE`. Add `vendor/tree-sitter-scala/UPSTREAM.md` recording the generated commit, the grammar-fix commit `6f9d7bc93ee153719d0d785e63e0fc77d333dad7`, the exact source paths, and repeatable update steps. Do not edit generated C or headers locally.

Add a root `build.rs`. It must compile the two C files as C11 with `vendor/tree-sitter-scala/src` on the include path, use `-Wno-unused` where supported, add `-utf-8` under MSVC, and name the static library `tree-sitter-scala`. Emit `cargo:rerun-if-changed` for both C files and all three headers.

In `Cargo.toml`, remove `tree-sitter-scala`, add the existing compatible `tree-sitter-language` crate as a direct dependency, and add `cc` under `[build-dependencies]`. Regenerate `Cargo.lock`. Do not add a git dependency or a crates.io version fallback.

Create `src/analyzer/scala/language.rs`. Declare the generated C function in an `unsafe extern "C"` block and expose `pub(crate) const LANGUAGE: tree_sitter_language::LanguageFn` using `LanguageFn::from_raw`. Register the module in `src/analyzer/scala/mod.rs`. Replace every `tree_sitter_scala::LANGUAGE` use under `src/` with this constant, importing it through the Scala module rather than duplicating extern declarations.

Append `tree-sitter-scala-a6800000-2026-07` to the Scala salt in `src/analyzer/store/epoch.rs` and explain that it covers parser-table changes not represented by the structural grammar fingerprint.

Move the TheHive source from its inline constant into `tests/fixtures/scala-issue-1016/JobCtrl.scala`. Preserve the original AGPL header. Update the fuzzer regression to load that fixture and assert no issue-#1016 truncation violation. Add direct declaration assertions showing the class range contains its constructor and body, `JobCtrl.create` is a child declaration, and the following `PublicJob` remains independent.

Add SearchTools integration coverage using the exact fixture plus a minimal inline `JobSrv.scala`. Assert that `get_symbol_sources` returns `def create` and `jobSrv.submit` for `JobCtrl` but excludes `PublicJob`. Then call `get_definitions_by_reference` with exact body context and target `submit`; assert that it resolves the stub's `JobSrv.submit` declaration instead of returning `target_not_found`.

Add one compact Scala parser/analyzer regression covering the three upstream whitespace forms `@Inject()(...)`, `@ann() (...)`, and `@ann ()(...)`. The assertion must be behavioral: each class contains its constructor parameter and body declaration, not merely that a grammar registry contains a rule name.

Generalize the supplemental notice renderer so a section can have either Cargo package metadata or explicit vendored-source metadata. Read `vendor/tree-sitter-scala/LICENSE`, label it as tree-sitter-scala from the immutable generated commit, and describe it as compiled into every release target. Regenerate the tracked supplemental notice.

Run the focused tests and inspect failures before broad validation. Replay the TheHive fuzzer record with ephemeral cache. If the Chisel corpus checkout is available, replay `svsimTests.VCSSpec`; record whether it clears. A residual Chisel error does not authorize widening ranges or adding a mini-parser and does not block the annotated-constructor acceptance criteria.

Finally, validate formatting, lints, all-feature tests, license policy, generated notices, and crate packaging. Inspect the packaged file list to prove the vendored parser, headers, license, and provenance are included. Review the complete branch diff for security, duplication, intent, operational, and architectural concerns; fix all confirmed issues and update this living plan.

## Concrete Steps

Run all commands from `/Users/dave/.codex/worktrees/3cb7/bifrost`.

Acquire the immutable upstream source and verify its commit before copying files. A temporary clone or GitHub archive is acceptable; do not copy from a moving branch. Confirm that the vendored files match the selected commit with checksums or a clean diff against that checkout.

After dependency and build integration:

    cargo check --locked
    cargo test --test scala_analyzer_test

After regression tests:

    cargo test --test mcp_property_fuzzer i1_accepts_annotated_constructor_jobctrl_scala_fixture -- --nocapture
    cargo test --test searchtools_definition_selectors issue_1016 -- --nocapture

Use the actual final test names if Rust's test-module organization requires a different prefix, and update this section immediately.

Generate and compare notices:

    node scripts/generate-supplemental-third-party-notices.mjs /tmp/issue-1016-supplemental-notices.txt
    cmp licenses/SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt /tmp/issue-1016-supplemental-notices.txt
    cargo deny --config licenses/deny.toml --locked check licenses

Run release-quality Rust checks:

    cargo fmt --check
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    cargo test --features nlp,python

Validate the publishable package:

    cargo package --allow-dirty --list
    cargo package --allow-dirty

The package list must contain `build.rs`, every file under `vendor/tree-sitter-scala/`, and the two vendored legal/provenance files. `cargo package` must compile without attempting to resolve `tree-sitter-scala` from git or crates.io.

## Validation and Acceptance

The focused fuzzer regression fails before the parser replacement because it detects a declaration ending immediately before a sibling `ERROR` node. It passes afterward with no `declaration-truncated-at-parse-error` violation for `JobCtrl`.

The source integration test must observe one `JobCtrl` source whose text includes its constructor parameters, `def create`, and `jobSrv.submit`, while excluding the following top-level `PublicJob`. This proves the fix neither truncates nor overextends the class range.

The definition-by-reference integration test must resolve target `submit` from exact context copied from `JobCtrl.create` to the inline `JobSrv.submit` declaration. Any `invalid_location`, `target_not_found`, or context mismatch fails acceptance.

All existing Scala analyzer tests, the complete `nlp,python` suite, all-feature clippy with warnings denied, license checks, supplemental-notice comparison, and `cargo package` must pass. Cross-platform CI remains the final proof that the upstream-equivalent C build compiles on Linux, macOS, and Windows.

## Idempotence and Recovery

The vendored source is immutable and can be reacquired from its recorded commit. If a copy is interrupted, remove only the incomplete `vendor/tree-sitter-scala` subtree after reviewing `git status`, then copy the exact file set again. Never regenerate the parser with an unpinned CLI or from upstream `master`.

Cargo and test commands are repeatable. Use `scripts/with-isolated-cargo-target.sh` for isolated validation so temporary build output is removed automatically. Do not create manually named Bifrost target directories under `/tmp`.

If crate packaging omits a vendored file, adjust the package include rules only after inspecting `cargo package --list`; do not add a network dependency as a workaround. If the parser does not fix the exact TheHive fixture, stop and compare the vendored checksums and generated commit before changing analyzer code.

## Artifacts and Notes

Upstream grammar fix:

    https://github.com/tree-sitter/tree-sitter-scala/commit/6f9d7bc93ee153719d0d785e63e0fc77d333dad7

First generated parser commit containing that fix:

    https://github.com/tree-sitter/tree-sitter-scala/commit/a68000002745b94eec61cef741efe7cede4ff465

Issue and exact user-visible failure:

    https://github.com/BrokkAi/bifrost/issues/1016
    get_symbol_sources(JobCtrl) currently reports lines 25-26 only.
    get_definitions_by_reference(... target="submit") currently reports target_not_found.

## Interfaces and Dependencies

No public MCP, Python, or Rust API changes. The private internal interface added in `src/analyzer/scala/language.rs` is:

    pub(crate) const LANGUAGE: tree_sitter_language::LanguageFn

The root build script exports the same native symbol and static-library identity previously supplied transitively by the grammar crate:

    tree_sitter_scala() -> *const ()
    static library name: tree-sitter-scala

The direct dependency set changes from published `tree-sitter-scala` to `tree-sitter-language` plus build dependency `cc`. The shared `tree-sitter = "0.25.10"` runtime remains unchanged because it supports the generated parser's ABI.
