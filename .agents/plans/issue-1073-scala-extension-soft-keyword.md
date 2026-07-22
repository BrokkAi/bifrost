# Parse Scala `extension` as a context-sensitive identifier

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this document in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

After this change, valid Scala 2 code may use `extension` as an ordinary value or method name without corrupting the concrete syntax tree. Users asking the MCP symbols tools for the definition or usages of a member declared after such an expression will receive the physically nested member, rather than a false outer-trait declaration. The result is visible through a minimized test that parses without an `ERROR`, resolves `isWorksheet` to its enclosing implicit class, and finds the same exact call through `scan_usages_by_reference`.

## Progress

- [x] (2026-07-22 15:05Z) Read `.agents/PLANS.md`, inspected issue #1073, and reproduced the parser failure with the published `tree-sitter-scala` 0.25.1 crate used by Bifrost.
- [x] (2026-07-22 15:18Z) Audited official releases and commits, then tested v0.23.4, v0.24.0, v0.26.0, and upstream master `3991ad1a5603`; none parses `extension == "json"` as a valid identifier.
- [x] (2026-07-22 15:24Z) Prototyped the upstream-style grammar change on current master by making `extension` a soft identifier and declaring a GLR conflict with `extension_definition`; the minimized file parses without errors and all 169 upstream corpus parses still pass.
- [x] (2026-07-22 15:42Z) Vendored a narrow derivative of official v0.25.1 under `vendor/tree-sitter-scala`, retained its MIT license, added explicit patch provenance, and switched Cargo to the local path dependency without changing the public crate API.
- [x] (2026-07-22 15:49Z) Added `tests/scala_extension_soft_keyword_test.rs`; raw Scala 2 and Scala 3 parser controls plus the public forward/inverse symbol round trip all pass.
- [x] (2026-07-22 15:54Z) Repeated the focused feature-enabled target (6 passed), formatted the new test directly, and passed file-scoped `git diff --check`.
- [x] (2026-07-22 20:00Z) Root integrated all concurrent Scala changes. Repository-wide formatting and diff hygiene pass; the 51-test definition-precedence target, 147-test inverse graph target, 6-test parser/public target, post-merge all-feature Clippy, and complete out-of-sandbox `cargo test --features nlp,python` gate are green. The exact Metals witness resolves and round-trips as `ScalametaCommonEnrichments.XtensionAbsolutePath.isWorksheet`.

## Surprises & Discoveries

- Observation: Upgrading only to the latest official release cannot fix this bug.
  Evidence: v0.26.0 produces the same `ERROR` spanning the `extension` definition and use as the pinned 0.25.1 crate.

- Observation: Upstream master improves recovery but still does not accept the valid expression.
  Evidence: master `3991ad1a5603` leaves later methods inside the implicit class because of an unrelated braced-body recovery fix, yet retains an `ERROR` over `= extension == "json"` and parses `isJson` as a declaration without a body.

- Observation: The grammar already has the exact context-sensitive mechanism needed for another Scala 3 soft keyword.
  Evidence: current upstream makes `inline` both an `inline_modifier` and `_soft_identifier`, declares a GLR conflict between those readings, and uses dynamic precedence only when both parses complete. Adding `extension` to `_soft_identifier` plus the corresponding `extension_definition` conflict makes the minimized parse error-free while preserving every upstream extension-method corpus test.

## Decision Log

- Decision: Fix the grammar token ambiguity instead of widening analyzer ranges, walking source text, or recovering declarations from an `ERROR` node.
  Rationale: The source is valid Scala 2 and the wrong owner originates in the parser. A context-sensitive grammar fork preserves both Scala 2 identifier use and Scala 3 extension definitions with structured nodes.
  Date/Author: 2026-07-22 / Codex

- Decision: Require an error-free raw parse in addition to the MCP symbols round trip.
  Rationale: Upstream master happens to keep the later method nested despite the same token bug. Owner-only coverage would accept that incomplete recovery and allow future wrong-forward failures in the malformed method itself.
  Date/Author: 2026-07-22 / Codex

## Outcomes & Retrospective

Issue #1073 is implemented locally without analyzer recovery. Bifrost now builds against a source-controlled v0.25.1 grammar derivative that treats `extension` contextually, and the focused acceptance target proves an error-free Scala 2 parse, preserved Scala 3 extension syntax, correct nested forward identity, and an inverse hit for that exact identity. Six focused tests pass, the production witness is consistent, and repository-wide formatting, diff hygiene, post-merge all-feature Clippy, and the complete out-of-sandbox feature-enabled Cargo suite pass.

## Context and Orientation

Bifrost selects the Scala tree-sitter language in `src/analyzer/mod.rs` through the external `tree-sitter-scala` crate declared in `Cargo.toml`. A concrete syntax tree, or CST, is the parser's node tree retaining language syntax. The published grammar treats literal `extension` as the start of a Scala 3 `extension_definition` but does not also include it among `_soft_identifier` choices. A soft keyword is a word that acts as syntax only in a matching construct and remains a legal identifier elsewhere. Because the parser has no identifier branch at `extension == "json"`, it enters error recovery and changes the physical parent of later declarations.

The public MCP behavior can be tested without editing the concurrently owned Scala resolver files. `tests/common/inline_project.rs` builds small ad hoc workspaces. A new focused integration test can call `get_definitions_by_location` at the `isWorksheet` call and `scan_usages_by_reference` for the returned nested symbol. A second assertion can parse the same source directly with `tree_sitter_scala::LANGUAGE` and require `root_node().has_error()` to be false.

The official `tree-sitter-scala` repository has no published fix. Its grammar-level solution is two declarative changes: include `extension` in `_soft_identifier`, and declare the ambiguity between `extension_definition` and `_soft_identifier` so Tree-sitter's generalized LR parser retains both readings until following syntax selects one. The repository must consume generated parser tables carrying that change; builds must not download or generate grammars dynamically.

## Plan of Work

First package the smallest reproducible derivative of the official grammar. Keep upstream license and provenance, retain the declarative `grammar.js` change, and use generated C parser tables checked into the dependency just as the published crate does. Point `Cargo.toml` at that local patched crate and let `Cargo.lock` record the path dependency. Do not change Bifrost's analyzer APIs or any concurrent-work files.

Next add `tests/scala_extension_soft_keyword_test.rs`. The fixture will define a Scala 2 implicit class with a method named `extension`, use it as the left operand of `==`, and place `isWorksheet` afterward. One test will instantiate Tree-sitter directly and prove the whole source is error-free. Another will use `InlineTestProject` and the symbols service to prove location lookup returns `ScalametaCommonEnrichments.XtensionAbsolutePath.isWorksheet`, then query that exact symbol inversely and require the call-site snippet.

Finally run the new integration target, affected Scala analyzer tests, formatting, and Clippy. Inspect only this work's files and preserve concurrent changes. Update this plan with commands, observed counts, packaging rationale, and any compatibility findings.

## Concrete Steps

Work from `/mnt/optane/tmp/bifrost-burndown-3`.

To observe the pre-fix parser failure against the current dependency, run the minimized source through the published grammar and expect an `ERROR` covering the `extension` use. The research reproduction used:

    tree-sitter parse /tmp/Issue1073.scala

from the cached `tree-sitter-scala-0.25.1` crate and reported:

    (ERROR [2, 4] - [7, 4])

After packaging the patched grammar and adding tests, run:

    cargo test --features nlp,python --test scala_extension_soft_keyword_test
    cargo test --features nlp,python --test scala_analyzer_test
    cargo fmt --all -- --check
    cargo clippy --all-targets --all-features -- -D warnings

The new target must pass both tests. The analyzer target and Clippy must finish without failures or warnings.

## Validation and Acceptance

Acceptance requires the minimized Scala 2 source to parse with no `ERROR` or missing nodes. `extension` in `extension == "json"` must be an `identifier`, while a Scala 3 `extension (value: String) def ...` control must remain an `extension_definition`. The following `isWorksheet` declaration must retain the implicit class as its physical owner.

At the public API level, `get_definitions_by_location` at the unqualified `isWorksheet` call must resolve one function whose fully qualified name is `ScalametaCommonEnrichments.XtensionAbsolutePath.isWorksheet`. `scan_usages_by_reference` for that exact symbol must return the same source call. This proves forward and inverse identity rather than only parser shape.

Existing Scala analyzer behavior and the upstream extension-definition corpus must remain green. Formatting and all-feature Clippy are required before handoff.

## Idempotence and Recovery

Tests and parser inspection are read-only apart from normal managed Cargo output. The local grammar derivative is source-controlled, so builds require no network and can be retried safely. If parser generation changes more than the expected generated tables, regenerate with the version documented in the dependency provenance and compare the declarative grammar diff before accepting it. Do not discard the unrelated dirty files listed by `git status`; they belong to concurrent work.

## Artifacts and Notes

The minimized reproduction is `/tmp/Issue1073.scala`. The official upstream research clone is `/tmp/tree-sitter-scala-1073`. The successful prototype adds only this logical grammar behavior:

    conflicts: [
      [$.extension_definition, $._soft_identifier],
    ]

    _soft_identifier: choice(..., "extension")

The upstream parse suite passed 169 of 169 syntax cases after that change. Its highlight suite still labels a plain `val extension` token as a keyword because the upstream highlight query captures the literal globally; Bifrost does not consume that highlight query for symbol ownership, but dependency packaging should preserve the query and record this upstream limitation rather than disguise it as a parser failure.

## Interfaces and Dependencies

No public Rust or MCP schema changes are needed. The dependency must continue to expose `tree_sitter_scala::LANGUAGE` as a `tree_sitter_language::LanguageFn` compatible with Bifrost's `tree-sitter` runtime. The new test uses `tree_sitter::Parser`, `tree_sitter_scala::LANGUAGE`, `common::InlineTestProject`, and the existing symbols tool invocation helper.

Revision note: 2026-07-22 created the plan after reproducing #1073 across all relevant official releases and proving the two-rule grammar solution on current upstream master.

Revision note: 2026-07-22 recorded the vendored v0.25.1 derivative, provenance, public behavior tests, and focused acceptance; broad integrated formatting and Clippy remain root-owned because other agents are actively editing the affected Scala files.

Revision note: 2026-07-22 recorded the completed integrated review, production exact witness, focused suites, and Clippy gate; the full test rerun remains a post-merge publication gate because restricted process-I/O permissions rejected three unrelated benchmark harness tests.

Revision note: 2026-07-22 completed the post-merge publication gates outside the restricted sandbox; all feature-enabled Cargo tests pass, including the process-I/O harness tests.
