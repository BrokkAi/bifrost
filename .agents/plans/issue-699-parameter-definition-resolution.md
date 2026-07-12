# Resolve callable parameters as local definitions in every language

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document is maintained in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

Bifrost currently resolves editor definition and hover requests only when the target is an indexed `CodeUnit`. Function parameters are deliberately local and are not indexed, so a reference such as Rust's `cfg` in `cfg.font` returns no definition and therefore no hover even though the parser already knows the parameter declaration and its type. After this change, definition requests on explicit parameter declarations or references navigate to the exact parameter name, hover renders the complete parameter clause, and `get_definitions_by_location` returns the same local result. Resolution is performed from the current source tree at query time, so unsaved editor content works and no SQL schema is added.

## Progress

- [x] (2026-07-12 18:00Z) Assigned GitHub issue #699 to the authenticated user and created `/tmp/bifrost-issue-699` on `codex/issue-699-parameter-definitions` from the current `master` commit.
- [x] (2026-07-12 18:05Z) Inspected the shared definition resolver, LSP definition/hover handlers, search-tool response model, existing Java local-declaration seam, and all language parameter collectors.
- [x] (2026-07-12 19:05Z) Implemented and focused-tested the cross-language, structured lexical-binding resolver.
- [x] (2026-07-12 19:10Z) Carried lexical definitions through shared lookup without treating them as indexed `CodeUnit`s.
- [x] (2026-07-12 19:20Z) Rendered lexical definitions in LSP definition/hover and `get_definitions_by_location`.
- [x] (2026-07-12 19:40Z) Added all-language, shadowing, callable-form, declaration-site, hover, tool-contract, and overlay regressions; the focused suites pass.
- [x] (2026-07-12 21:30Z) Ran focused definition, hover, click-around, issue-reproduction, search-tool, and overlay suites; all pass.
- [x] (2026-07-12 22:10Z) Ran `cargo fmt`, warning-free all-target/all-feature clippy, the complete `nlp,python` Rust suite, and 38 Python tests; all pass.
- [x] (2026-07-12 22:20Z) Pushed the completed branch and opened pull request #702 linked to issue #699.
- [x] (2026-07-12 23:05Z) Merged the current `master` base after Linux CI exposed a persistence-fixture race, excluded the live `.brokk` cache from fixture commits, and reran the affected, definition, parameter, formatting, and clippy gates successfully.
- [x] (2026-07-12 23:35Z) Fixed the updated base branch's Windows-only dead-code benchmark failure by comparing selected definitions through workspace-relative `PathBuf`s instead of canonical-root-sensitive `ProjectFile` equality; the benchmark and Java, Python/JS/TS, and Rust dead-code suites pass.

## Surprises & Discoveries

- Observation: `DeclarationInfo` and `IAnalyzer::find_nearest_declaration` already model local declarations, but only Java implements useful lookup; most language wrappers delegate to a generic implementation that returns `None`.
  Evidence: `src/analyzer/tree_sitter_analyzer.rs` supplies a `None` default while `src/analyzer/java/declarations.rs` contains the only complete nearest-declaration walk.

- Observation: The shared definition outcome, common LSP symbol target, hover renderer, and search-tool candidate renderer all assume definitions are indexed `CodeUnit`s.
  Evidence: `DefinitionLookupOutcome.definitions` is a `Vec<CodeUnit>`, and both LSP handlers render only those candidates.

- Observation: The original `master` working tree contains unrelated edits, including an in-progress Rust field-hover regression.
  Evidence: work was isolated in a new worktree and the new parameter regressions will live in separate feature-owned files.

- Observation: C# primary constructor parameters are unnamed `parameter_list` children of `class_declaration`, not a `parameters` field.
  Evidence: the first special-form LSP run failed only C# primary constructors; adding a structured named-child lookup made the Java record, C# primary, and Scala class-parameter cases all pass.

- Observation: A PHP promoted parameter remains a lexical parameter only in its constructor body; another method must use the generated property through `$this->value`.
  Evidence: correcting the regression fixture from an invalid bare `$value` in a separate method to a constructor-body reference produced the expected promoted-parameter target.

- Observation: The complete callable-literal matrix passed for all eleven language grammars.
  Evidence: `cargo test --test lsp_parameter_definition` reports eight passing tests, including every ordinary parameter and every closure/lambda form.

- Observation: Running the complete definition suite exposed fifteen precedence regressions that focused parameter tests could not reveal: type-position identifiers, Rust field roles, initializer visibility, and Scala template members could be mistaken for lexical references or shadows.
  Evidence: after restricting lexical focus to value-capable roles and tightening declaration visibility/scope rules, `cargo test --test get_definition_test` reports 427 passing tests.

- Observation: The worktree's default target directory exhausted `/tmp` during the full all-feature build, and sharing the original checkout's target directory reused stale test artifacts.
  Evidence: the final gates use the isolated `CARGO_TARGET_DIR=/home/jonathan/Projects/bifrost/target/issue699`; the complete run exits successfully without touching the original dirty checkout.

- Observation: Both Linux CI targets failed in `csharp_package_existence_ignores_stale_complete_blobs` because its second broad fixture commit could sweep the live persisted-analyzer SQLite files under `.brokk` into the Git index. macOS, Windows, and local runs happened not to hit the race.
  Evidence: both failed logs reported libgit2 `failed to read file into stream` from `commit_all`; filtering `.brokk` in that helper makes all eight persistence tests pass on the merged base while the parameter and 427-case definition suites remain green.

- Observation: After the Linux fix, x86 Windows exposed a separate failure already present on the updated `master`: the benchmark could reject `A.method1` from explicitly selected `A.java` when persisted definitions and input files used different canonical spellings of the same Windows root.
  Evidence: both `master` run 29211992693 and PR run 29212727394 failed the identical `Candidate symbols analyzed: 1` assertion; the selection filter compared whole `ProjectFile` values even though its contract is workspace-relative file membership.

## Decision Log

- Decision: Resolve parameters from the current parsed source on every query instead of persisting them.
  Rationale: Parameters are file-local, lexical, cheap to derive, and must reflect unsaved overlays. Persistence would add invalidation and schema complexity without improving correctness.
  Date/Author: 2026-07-12 / Codex

- Decision: Discover other local bindings only to enforce shadowing; expose only explicit callable parameters as targets.
  Rationale: Returning an outer parameter when a nearer local owns the name is wrong, but expanding navigation to every local binding is outside issue #699.
  Date/Author: 2026-07-12 / Codex

- Decision: Represent a lexical definition separately from `CodeUnit` in the shared lookup outcome.
  Rationale: Inventing a synthetic globally named `CodeUnit` would leak local bindings into symbol indexes and downstream APIs that assume workspace declarations.
  Date/Author: 2026-07-12 / Codex

- Decision: Keep indexed candidates' existing JSON `fqn`, add a truthful `name`, and omit `fqn` for lexical candidates.
  Rationale: A parameter has no honest workspace FQN. The tool response should state that directly rather than fabricate an identifier.
  Date/Author: 2026-07-12 / Codex

- Decision: Exclude `.brokk` through the persistence test's Git-index callback rather than retrying CI or adding timing workarounds.
  Rationale: Analyzer cache files are not fixture source, and a live SQLite database must never be captured by the test repository's broad source commit.
  Date/Author: 2026-07-12 / Codex

- Decision: Compare dead-code selection scope by normalized relative `PathBuf`, not the full `ProjectFile` including its root.
  Rationale: all candidates belong to the same active workspace, while Windows may spell that workspace root through either an 8.3 temp path or its canonical long path. Relative file identity is both sufficient and portable.
  Date/Author: 2026-07-12 / Codex

## Outcomes & Retrospective

The implementation is complete and validated. Explicit parameters now resolve lexically from the current tree-sitter AST in all eleven languages without a persistence schema. Definition returns the exact binding leaf, declaration-site lookup resolves to itself, hover renders the full parameter syntax from the active overlay, and location-based search returns a truthful local candidate without a fabricated FQN. Structured local discovery prevents navigation through genuine shadows while existing indexed member/type resolution keeps precedence in non-value roles.

The new behavior passed the complete 427-case definition suite, the 176-case LSP server suite, click-around and Rust issue-reproduction suites, all eight new cross-language parameter fixtures, the complete all-feature Rust test run, warning-free clippy, formatting, and 38 Python tests. The main implementation lesson was that lexical lookup must be gated by the syntactic role of the focus as well as the enclosing scope: a same-spelled identifier in a field or type role is not a reference to a parameter.

## Context and Orientation

`src/analyzer/usages/get_definition/mod.rs` resolves a source location to a structured reference site, parses the source using the selected language grammar, and dispatches to language-specific indexed definition logic. Its `DefinitionLookupOutcome` is consumed by the search tools and several LSP handlers. `src/lsp/handlers/broad_symbol.rs` currently converts a resolved outcome into `CodeUnit` candidates used by definition and hover. `src/searchtools.rs` converts the same units into JSON candidates.

A lexical definition in this plan is an explicit parameter binding that is visible at the requested source position. It includes an exact name range for navigation and a larger declaration range for hover text. A local shadow is a distinct declaration in a nearer lexical scope; ordinary assignment to an existing parameter remains the same binding.

## Plan of Work

First, add a stack-safe lexical resolver under `src/analyzer/`. It will accept the already parsed tree, current source, focused identifier range, and language. A shared ancestor/scope walk will choose the nearest binding, while language-specific matchers interpret callable parameters, receivers, destructuring patterns, closures, constructors, and local declarations through tree-sitter node kinds and named fields. The resolver returns either an explicit parameter definition or proof that a nearer non-parameter local blocks it. Unknown syntax returns no opinion and leaves existing resolution unchanged.

Second, extend the shared definition outcome with an optional lexical definition. `resolve_one` will ask the lexical resolver before language-specific indexed resolution. An explicit parameter returns `resolved`; a proven nearer local returns the existing `local_binding` no-definition diagnostic; otherwise dispatch continues unchanged. Indexed-only consumers will continue reading `definitions`, while definition/hover and location lookup will also consume the lexical field.

Third, change the common LSP target to distinguish indexed and lexical targets. Definition will convert the lexical name byte range to a same-document LSP location. Hover will slice the full parameter declaration from current overlay content, fence it with the language tag, and highlight the selected reference. Requests on the declaration name follow the same path and resolve to themselves.

Fourth, extend search-tool candidate rendering. Indexed candidates retain their FQN and gain `name`; lexical candidates have no FQN and report their identifier, parameter kind, current path and lines, and full declaration text as the signature. `get_definitions_by_reference` remains indexed-only.

Finally, add end-to-end fixtures for all supported languages plus focused special forms and negative shadows. Preserve the dirty original worktree, update this plan with discoveries and evidence, make multiline checkpoint commits on the current feature branch, then push and open a PR linked to issue #699.

## Concrete Steps

Work from `/tmp/bifrost-issue-699`.

Run focused tests as they are added:

    cargo test --test lsp_parameter_definition
    BIFROST_SEMANTIC_INDEX=off cargo test --test get_definition_test parameter_definition

Run final gates:

    cargo fmt
    cargo clippy --all-targets --all-features -- -D warnings
    UV_CACHE_DIR=/tmp/bifrost-uv-cache BIFROST_SEMANTIC_INDEX=off cargo test --features nlp,python
    UV_CACHE_DIR=/tmp/bifrost-uv-cache scripts/test_python.sh

## Validation and Acceptance

For each of Java, Go, C++, JavaScript, TypeScript, Python, Rust, PHP, Scala, C#, and Ruby, an explicit parameter reference in a callable body must return exactly the parameter declaration name from `textDocument/definition`, and hover must include the full parameter clause. Definition and hover on the declaration name itself must behave the same way. Nested callable parameters must win over captured outer parameters, while a distinct nearer local declaration must block the outer target. Explicit receivers and destructured binding leaves must resolve where supported by the language grammar.

`get_definitions_by_location` must return `status: resolved`, a parameter-kind candidate with a truthful name and signature, and no `fqn` for lexical results. An open or changed overlay must drive ranges and hover text without rebuilding or persisting the analyzer.

Existing indexed definition, member hover, signature help, call hierarchy, rename, semantic token, and search-tool suites must remain green.

## Idempotence and Recovery

The resolver is read-only and query-local. Re-running tests or rebuilding the workspace creates only normal build artifacts. No database migration or destructive operation is involved. If a language grammar shape is unsupported, return no opinion rather than guessing from source text. The original dirty `master` worktree remains untouched; only files changed in `/tmp/bifrost-issue-699` are eligible for staging.

## Artifacts and Notes

Issue reproduction: Rust `fn mono_family(cfg: &config::Config)` currently returns null hover on the body reference `cfg` while `font` and `mono_family` member hovers resolve.

## Interfaces and Dependencies

Define a lexical result with identifier, `DeclarationKind`, exact name `Range`, and full declaration `Range`. Add an optional lexical field to `DefinitionLookupOutcome` while retaining `Vec<CodeUnit>` for indexed consumers. Extend `DefinitionCandidate` so `name` is always serialized and `fqn` is optional; indexed candidates populate both and lexical candidates omit `fqn`.

Use only existing tree-sitter grammars and analyzer helpers. Do not add dependencies, SQL tables, migrations, regex fallbacks, or hand-written source parsers.

Revision note (2026-07-12): Marked implementation and validation complete, recorded the precedence regressions found by the full suite and the isolated-target recovery, and replaced the provisional outcome with final evidence before delivery.

Revision note (2026-07-12, CI follow-up): Recorded the Linux persistence-fixture race found after PR creation, the structured exclusion of `.brokk` from fixture commits, and successful validation on the current merged base.

Revision note (2026-07-12, Windows CI follow-up): Recorded the inherited Windows benchmark failure, its canonical-root mismatch, and the workspace-relative selection fix used to unblock the full matrix.
