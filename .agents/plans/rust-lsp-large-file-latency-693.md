# Bound Rust LSP latency on large source files

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan is maintained in accordance with `.agents/PLANS.md` at the repository root.

## Purpose / Big Picture

Rust definition and hover requests should remain interactive after Bifrost finishes indexing a workspace containing a large source file. Issue #693 reports that the LGTM pull-request workspace at commit `1bb63fd9e46493df905fc2ad51cdac83ad7ab868` takes more than 30 seconds to answer requests in `crates/app/src/main.rs`, especially once the file includes the full roughly 5,874-line `impl ReviewApp`. After this work, the exact reported query and a representative repository-owned regression exercise will complete within a practical bound, with profiling evidence showing that the underlying superlinear work has been removed rather than hidden behind a timeout or text-search fallback.

## Progress

- [x] (2026-07-12 18:40Z) Read issue #693, the current LSP definition/hover entry points, and the repository planning and testing guidance.
- [x] (2026-07-12 19:10Z) Reproduced the latency against the exact LGTM revision and captured indexing and request profiles.
- [x] (2026-07-12 19:24Z) Identified repeated whole-file parsing during Rust export projection as the root cause.
- [x] (2026-07-12 19:47Z) Implemented one-parse export visibility collection, preserved cross-file public-module ancestry, and added synthetic plus exact-reproduction LSP coverage.
- [ ] Re-run the exact reproduction and focused tests, then run formatting, clippy, and the feature-complete test suite (completed: exact release-profile reproduction, synthetic scale test, all 108 Rust usage graph tests, targeted glob-import regression; remaining: full Rust LSP suite after the cross-file correction, clippy, full feature suite).
- [ ] Commit only the files changed for issue #693 on the current branch.

## Surprises & Discoveries

- Observation: Both definition and hover share `src/lsp/handlers/broad_symbol.rs::broad_symbol_target_at_position`, which ultimately calls the general definition resolver, but inspection alone does not distinguish parsing, declaration-site detection, lookup-index construction, or Rust receiver inference as the expensive phase.
  Evidence: `src/lsp/handlers/definition.rs` and `src/lsp/handlers/hover.rs` both call that helper; the issue specifically asks to separate indexing, source analysis, and request handling.

- Observation: Persisted workspace construction was not the stall. It took 6.4 ms on the exact checkout, while the first definition request took 10,601 ms in the release build.
  Evidence: `BIFROST_TIMING=1` reported `WorkspaceAnalyzer::build (6.4 ms)` and the LSP slow-request log reported 10,601 ms for request id 2.

- Observation: Of the 10,600 ms request, `RustAnalyzer::build_reference_context` consumed 10,510.6 ms. Its export projection called `is_export_public_declaration` for each declaration, and that helper read and parsed the declaration's entire source file on every call.
  Evidence: Nested timing scopes reported parsing the request tree at 21.6 ms, building the definition lookup index at 3.2 ms, and building the Rust reference context at 10,510.6 ms. Code inspection then showed the per-declaration parse loop in `src/analyzer/rust/graph_support.rs`.

- Observation: A first implementation that cached visibility only for declarations in the current file broke public module ancestry across files.
  Evidence: `rust_ufcs_trait_method_resolves_through_glob_imported_trait` returned no target because declarations in `service.rs` have a parent `pub mod service` CodeUnit sourced from `lib.rs`. Caching external-parent visibility separately restored the test while retaining the one-parse fast path for the large current file.

- Observation: The corrected implementation reduced the first exact definition request from 10,601 ms to 128.6 ms in release mode, an approximately 82-fold improvement; the export-index phase itself fell from roughly 10.5 seconds to 32.4 ms.
  Evidence: The ignored exact-reproduction driver in `tests/issue_693_profile.rs` returned the same `config.rs` field locations and hover content before and after the change.

## Decision Log

- Decision: Profile the exact external reproduction before editing the resolver.
  Rationale: The user explicitly requested profiling if the cause is not immediately obvious, and several plausible phases share the request path. A scale fix based only on code inspection would be guesswork.
  Date/Author: 2026-07-12 / Codex

- Decision: Keep semantic indexing disabled during the analyzer/LSP reproduction.
  Rationale: The reported feature is structured Rust definition/hover, while the optional embedding sidecar is unrelated and would add model startup and background work that obscures analyzer timing.
  Date/Author: 2026-07-12 / Codex

- Decision: Parse each file once when classifying its export-visible declarations, then reuse a `HashSet<CodeUnit>` for same-file ancestry and a small `HashMap<CodeUnit, bool>` for cross-file module parents.
  Rationale: The tree-sitter AST remains authoritative, the common large-file case becomes linear in source size plus declaration count, and Rust's cross-file `mod` ownership semantics remain intact.
  Date/Author: 2026-07-12 / Codex

- Decision: Keep an ignored exact-checkout profiling test and add a generated repository-owned scale regression using `InlineTestProject` and the real LSP server.
  Rationale: The ignored test preserves reproducible before/after evidence without vendoring external source, while the synthetic test continuously checks correct definition, correct hover, and a generous five-second catastrophic-regression bound on every machine.
  Date/Author: 2026-07-12 / Codex

## Outcomes & Retrospective

The root-cause implementation and focused verification are complete. The exact LGTM field query now resolves in 128.6 ms rather than 10.6 seconds in the same release-profile environment, and subsequent definition/hover requests take 66-68 ms. Full all-feature validation and the final commit remain.

## Context and Orientation

The executable `bifrost` implements a Language Server Protocol (LSP) server in `src/lsp/`. An LSP client sends a source URI plus line and character to `textDocument/definition` or `textDocument/hover`. The handlers in `src/lsp/handlers/definition.rs` and `src/lsp/handlers/hover.rs` use `src/lsp/handlers/broad_symbol.rs` to read the document, select the identifier under the cursor, and resolve it to indexed `CodeUnit` declarations. A `CodeUnit` is Bifrost's structured representation of a declaration such as a Rust struct, field, function, or method.

Reference resolution is implemented by `src/analyzer/usages/get_definition/mod.rs` and its language-specific `rust` submodule. It parses the current source with tree-sitter and combines syntax facts with indexed declarations; string scanning must not replace that structured path. The analyzer and workspace construction code already supports opt-in timing through the `BIFROST_TIMING` environment variable and `src/profiling.rs`. Additional temporary or permanent timing scopes may be added at meaningful phase boundaries while diagnosing this issue.

The external reproduction is the public `ellie/lgtm` repository at commit `1bb63fd9e46493df905fc2ad51cdac83ad7ab868`, with the cursor on `cfg.font.mono_family` in the `mono_family` expression of `crates/app/src/main.rs`. External source will be cloned under `/tmp`, never copied wholesale into this repository. A compact synthetic fixture based on the demonstrated expensive structure should become the committed regression unless a small licensed excerpt is both necessary and appropriate.

## Plan of Work

First build the current server in an optimized-enough configuration that does not confuse debug-build cost with the algorithmic boundary. Run it against the exact LGTM revision with `BIFROST_SEMANTIC_INDEX=off` and timing enabled. Measure workspace initialization separately from the first and subsequent definition and hover requests. If the existing timing scopes do not isolate the delay, add nested scopes around declaration-site selection, lookup-index access, parsing, and the Rust resolver's major phases, then repeat. Use a sampling profiler such as `perf` when available to identify hot functions inside a slow phase.

Next translate the profile into a root-cause change. Prefer bounded indexes, one-pass AST fact collection, or cached per-file structured state over repeated whole-file walks. Preserve exact Rust semantics and cross-platform path behavior. Do not introduce regular expressions, source splitting, manual delimiter parsing, or a timeout that merely suppresses work.

Add behavior-focused coverage through the existing real LSP harness in `tests/common/lsp_client.rs` or, if tighter measurement requires direct analyzer control, through `InlineTestProject` from `tests/common/inline_project.rs`. The regression must exercise enough repeated Rust structure to fail or demonstrate the superlinear behavior before the fix, assert correct definition and hover results, and include a generous latency or operation-bound guard that is stable in CI. Avoid checking internal registry membership or exact incidental ordering.

Finally repeat the external profile and record before/after times. Run the focused regression, existing Rust definition tests, `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, and `UV_CACHE_DIR=/tmp/bifrost-uv-cache BIFROST_SEMANTIC_INDEX=off cargo test --features nlp,python`. Fix any failure attributable to this change before committing.

## Concrete Steps

All repository commands run from `/home/jonathan/Projects/bifrost`.

Clone or update the reproduction in `/tmp`, then detach it at the reported revision:

    git clone https://github.com/ellie/lgtm.git /tmp/bifrost-issue-693-lgtm
    git -C /tmp/bifrost-issue-693-lgtm checkout 1bb63fd9e46493df905fc2ad51cdac83ad7ab868

Build and profile the LSP reproduction with semantic indexing disabled:

    BIFROST_ISSUE_693_ROOT=/tmp/bifrost-issue-693-lgtm \
      BIFROST_SEMANTIC_INDEX=off BIFROST_TIMING=1 \
      cargo test --release --test issue_693_profile -- --ignored --nocapture

Run the generated scale regression and Rust semantic suites:

    BIFROST_SEMANTIC_INDEX=off cargo test --test issue_693_profile
    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_rust_graph_test
    BIFROST_SEMANTIC_INDEX=off cargo test --test rust_analyzer_goto_definition

Run focused and complete validation after implementation:

    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings
    UV_CACHE_DIR=/tmp/bifrost-uv-cache BIFROST_SEMANTIC_INDEX=off cargo test --features nlp,python

## Validation and Acceptance

Acceptance requires all of the following observable results. On the exact LGTM revision, indexing completes, then definition and hover for the representative `cfg.font.mono_family` expression return without a 30-second stall. The returned semantic target remains correct rather than becoming `null` because expensive resolution was skipped. A repository-owned test exercises the scale-sensitive structure and returns the expected definition and hover. Profile evidence identifies the former hot phase and shows that its cost is bounded or materially reduced. Formatting, all-feature clippy, and the full `nlp,python` test suite pass.

The latency assertion in committed tests must tolerate noisy shared CI machines. The primary proof of speed is comparative before/after profiling on the same checkout and machine; the test guard exists to catch catastrophic regressions, not microbenchmark scheduler noise.

## Idempotence and Recovery

The external reproduction lives under `/tmp` and can be deleted or recloned without touching the working tree. Profiling scopes are inert unless `BIFROST_TIMING` is set. Tests create isolated temporary projects. Existing untracked files under `.agents/docs/` and `.brokk/` belong to the user and must remain untouched. If a full test run fails because the default uv cache is read-only, rerun with `UV_CACHE_DIR=/tmp/bifrost-uv-cache`; do not alter user cache permissions.

## Artifacts and Notes

Issue #693 reports a reduced file of roughly 3,163 lines completing after about 26 seconds, while inclusion of the full `impl ReviewApp` through roughly line 5,874 pushes the first definition request past 30 seconds. These are reporter observations, not yet locally verified measurements.

Local release-profile transcript on the full 7,672-line file at the exact revision:

    Before: definition cfg.font 10601 ms; build_reference_context 10510.6 ms
    After:  definition cfg.font   128.6 ms; export_index_of_declarations 32.4 ms
    After:  definition mono_family 68.3 ms; hover requests 65.8 ms and 66.5 ms

## Interfaces and Dependencies

No new external dependency is used. The existing `brokk_bifrost::profiling` module provides opt-in wall-clock scopes. Tree-sitter remains the source of syntax structure. `RustAnalyzer::export_visible_declarations` in `src/analyzer/rust/graph_support.rs` reads and parses one source file once and returns the export-visible CodeUnits; `RustAnalyzer::is_module_export_candidate` consumes that set plus a cache for parent modules sourced from other files.

Revision note (2026-07-12): Created the plan after issue intake and initial request-path orientation; implementation details intentionally remained conditional on profiling evidence.

Revision note (2026-07-12 19:47Z): Recorded the exact profile, the repeated-parse root cause, the cross-file module correction, the chosen one-parse design, focused test results, and before/after latency evidence.
