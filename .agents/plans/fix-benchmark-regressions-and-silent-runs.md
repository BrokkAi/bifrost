# Restore benchmark latency and support silent exploratory runs

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must remain current while implementation proceeds. This plan follows `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

The scheduled benchmark run `29489210696` found four repeatable latency regressions after recent Python, Go, and Rust correctness work. After this change, the affected tools should preserve the new correctness behavior without rebuilding target-independent state or repeatedly walking irrelevant syntax. Maintainers should also be able to dispatch exploratory benchmark runs without notifying Slack, while scheduled runs continue to notify by default.

The result is observable in two ways. Focused `bifrost_benchmark` runs for `click-py`, `gin-go`, and `serde-json-rs` should no longer exceed the checked-in 20 percent plus 50 millisecond regression threshold for the four affected scenarios. A manually dispatched GitHub Actions benchmark with the new Slack option disabled should upload and summarize its artifacts without executing the Slack action.

## Progress

- [x] (2026-07-16 10:42Z) Confirmed the branch `dave/triage-ci-regressions` is clean and based on current `origin/master` at `4051809a`.
- [x] (2026-07-16 10:42Z) Triaged run `29489210696` into Python targeted-scan, Python whole-graph, Go identifier-walk, and Rust forward-context hot paths.
- [x] (2026-07-16 10:59Z) Implemented generation-scoped Rust forward-reference-context reuse; cache identity, 111 Rust usage-graph tests, and 477 definition tests pass.
- [x] (2026-07-16 10:59Z) Replaced Go's per-identifier ancestor-to-root walk with a bounded keyed-element check; all 51 Go usage-graph tests pass. Residual index work remains subject to the focused profile.
- [x] (2026-07-16 10:59Z) Cached owned Python module-binding timelines and retained query-specific import classification; all 89 Python usage-graph tests pass, including rebinding and deferred-body behavior.
- [x] (2026-07-16 10:59Z) Added per-binding workspace-module facts and a graph-build-wide canonical namespace cache for Python inverted edges; all nine Python dead-code tests pass.
- [x] (2026-07-16 10:59Z) Added `post_to_slack` with schedule-preserving conditions shared by both Slack steps; workflow policy tests pass.
- [ ] Run focused profile benchmarks and the repository Rust quality gates.
- [ ] Review, commit each completed milestone, push the branch, run the silent benchmark path, and open a ready-for-review pull request.

## Surprises & Discoveries

- Observation: The benchmark job itself succeeded; only the strict comparison gate failed.
  Evidence: Run `29489210696` completed 76 scenarios with four actionable regressions and no environment-wide variance.

- Observation: This desktop worktree moved from detached `HEAD` during triage to an existing branch named `dave/triage-ci-regressions` without local changes.
  Evidence: `git status --short --branch` reported `## dave/triage-ci-regressions`, and both `HEAD` and `origin/master` resolved to `4051809aea27b59accb2180a29a6ef2b365f1613`.

- Observation: On this macOS host, feature-enabled integration-test linking attempts to build the crate's dynamic-library target and fails on unresolved PyO3 symbols, although the feature-enabled library test binary links and passes.
  Evidence: `cargo test --features nlp,python --lib reused_within` passed both cache tests; `cargo test --features nlp,python --test usages_go_graph_test ...` failed at the linker, while the same integration suite without optional features passed all 51 tests. Linux CI remains the authoritative full-feature gate.

## Decision Log

- Decision: Treat the four benchmark rows as three language milestones, with two distinct Python optimizations rather than one broad cache.
  Rationale: Python `scan_usages` uses the targeted forward extractor, while Python `dead_code_smells` builds an inverted whole-workspace graph. They share a regression commit but execute different code paths and need different reusable state.
  Date/Author: 2026-07-16 / Codex

- Decision: Make Slack suppression an explicit `workflow_dispatch` boolean whose default preserves current notifications.
  Rationale: Scheduled production monitoring must remain unchanged. Exploratory or PR validation runs should opt out without deleting secrets or changing the Slack action globally.
  Date/Author: 2026-07-16 / Codex

- Decision: Keep the current branch rather than create or switch branches.
  Rationale: Repository instructions prefer committing directly to the active branch, and the user explicitly requested a pull request from this session.
  Date/Author: 2026-07-16 / Codex

- Decision: Give the new Rust forward cache the same weighted `memo_budget / 8` capacity as the existing inverse context cache.
  Rationale: Forward contexts now include canonical re-export facts and can be materially larger than inverse contexts. A separate weighted cache prevents the two access patterns from evicting each other while remaining within the analyzer's existing bounded-cache design.
  Date/Author: 2026-07-16 / Codex

- Decision: Cache raw Python binding events, not target-classified results or syntax trees.
  Rationale: Source ordering and rebinding are generation-stable, while whether an import reaches a target depends on each query's seed set. Owned strings and byte positions safely reuse the expensive tree walk without leaking target state or retaining trees.
  Date/Author: 2026-07-16 / Codex

## Outcomes & Retrospective

Implementation is in progress. This section will record final benchmark medians, test results, the pull request URL, and any residual regression that needs follow-up.

## Context and Orientation

The benchmark workflow is `.github/workflows/benchmark.yml`. It builds the debug `bifrost` and `bifrost_benchmark` binaries, runs pinned repositories declared in `benchmark/targets.toml`, compares the resulting JSON report with `benchmark/baselines/ubuntu-latest.json`, uploads artifacts, posts a job summary, optionally sends a Slack webhook, and finally enforces the benchmark outcome. A manual dispatch can select one repository and enable per-iteration `BIFROST_TIMING` traces.

Python targeted usage scans live in `src/analyzer/usages/python_graph/extractor.rs`. The recent correctness work added a source-ordered module binding timeline so a reference observes the correct import or rebinding at its source position. The timeline is currently reconstructed by traversing every candidate file for every query, even though the syntax events are independent of the queried target. `src/analyzer/python/usage_index.rs` already stores generation-scoped import, export, module, and reverse-import state and is the appropriate owner for reusable timeline facts.

Python whole-workspace edges live in `src/analyzer/usages/python_graph/inverted.rs`. `dead_code_smells` invokes this builder from `src/code_quality/dead_code_smells.rs` with all Python declarations as graph nodes. Namespace attribute handling currently resolves whether the imported module belongs to the workspace and canonicalizes the same dotted reference repeatedly. The fix should retain tree-free analyzer state and bounded live syntax trees while caching only target-independent resolution results for the duration of one graph build.

Go targeted usage scans live in `src/analyzer/usages/go_graph/extractor.rs`. Every identifier currently calls `scan_composite_literal_field_label`, whose helper climbs ancestors until it finds a `keyed_element` or reaches the root. A keyed element is the tree-sitter node for syntax such as `Field: value` inside a composite literal. Only an identifier that is the key, or the single named child of the key expression, can qualify, so the search can be bounded to the identifier's immediate structural neighborhood. `src/analyzer/usages/go_graph/resolver.rs` also builds receiver, constructor, alias, and embedded-member metadata for each targeted query; profiling will decide whether this remains significant after the bounded walk.

Rust reference contexts live in `src/analyzer/rust/graph_support.rs` and are owned by `RustAnalyzer` in `src/analyzer/rust/mod.rs`. The ordinary inverse context is cached per file in a weighted `moka::sync::Cache`, but `forward_reference_context_of` rebuilds a more expensive export-aware context every time. Both contexts are immutable within an analyzer generation, and `update` or `update_all` already constructs fresh caches, so a second weighted cache can safely share an `Arc<RustReferenceContext>` for repeated forward queries.

## Plan of Work

First, add forward-reference-context storage to `RustAnalyzer`. Initialize it in every constructor and reset it in every analyzer update path, mirror the existing weighted cache lookup in `forward_reference_context_of`, and add behavior-focused tests that call a Rust definition query twice and prove the expensive context builds once or returns the same `Arc`. Run the focused Rust graph and definition tests, format, review, and commit this milestone.

Second, replace Go's unbounded ancestor loop with a constant-depth structural check. Preserve the behavior that rejects map keys, qualified key expressions, and nested elided literals while accepting direct struct-literal labels. Run the existing struct-literal and Go usage suites plus a focused `gin-go` profile. If the profile still attributes material time to `build_go_edge_index_from_parsed`, avoid constructing member-receiver metadata for a top-level target such as `gin.New`, without adding a text fallback or weakening receiver correctness. Review and commit this milestone.

Third, split the Python work by execution mode. Move target-independent module binding events into `PythonUsageIndex`, preserving source order and rebinding boundaries, and classify cached import events against each query's seed set without a separate full syntax walk. In the inverted builder, compute workspace-namespace status once per binding and share a query-local canonical dotted-name cache across file workers. Add focused tests for rebinding, named and namespace imports, re-exports, and repeat resolution. Run Python usage and dead-code suites plus a focused `click-py` profile, then review and commit this milestone.

Fourth, add a boolean manual-dispatch input such as `post_to_slack`, defaulting to `true`. Gate both Slack payload preparation and the Slack action so scheduled runs always post, while manual runs post only when the input is true. Extend the workflow policy tests to cover the default and suppression expressions. Review and commit this milestone.

Finally, run `cargo fmt`, focused tests, `cargo clippy --all-targets --all-features -- -D warnings`, and the full feature-enabled test gate when practical. Re-run focused benchmark comparisons for the three repositories, record exact medians and profile evidence here, inspect the complete diff, push the current branch, dispatch a benchmark with Slack disabled if GitHub permits it, and open a ready-for-review pull request against `master`.

## Concrete Steps

All commands run from `/Users/dave/.codex/worktrees/f5eb/bifrost`.

Inspect and format:

    git status --short --branch
    cargo fmt --all -- --check

Run focused tests as their exact names are finalized during implementation:

    cargo test --features nlp,python --test usages_rust_graph_test
    cargo test --features nlp,python --test get_definition_test
    cargo test --features nlp,python --test usages_go_graph_test
    cargo test --features nlp,python --test usages_python_graph_test
    cargo test --features nlp,python --test benchmark_workflow_policy

Run focused profiled benchmarks after the debug binaries are built and pinned repositories are available:

    cargo build --locked --bin bifrost --bin bifrost_benchmark
    BIFROST_BENCHMARK_BIFROST_BIN=./target/debug/bifrost ./target/debug/bifrost_benchmark run --manifest benchmark/targets.toml --repo serde-json-rs --output benchmark-output --profile
    BIFROST_BENCHMARK_BIFROST_BIN=./target/debug/bifrost ./target/debug/bifrost_benchmark run --manifest benchmark/targets.toml --repo gin-go --output benchmark-output --profile
    BIFROST_BENCHMARK_BIFROST_BIN=./target/debug/bifrost ./target/debug/bifrost_benchmark run --manifest benchmark/targets.toml --repo click-py --output benchmark-output --profile

Run the CI quality gates through the managed temporary target helper if an isolated rebuild is needed:

    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python

Publish only after validation:

    git add <explicit changed paths>
    git commit
    git push -u origin dave/triage-ci-regressions

The final GitHub dispatch should select the relevant repository or full manifest, keep strict comparison enabled, enable profiling when useful, and set the new Slack input to false.

## Validation and Acceptance

Rust acceptance requires repeated `serde-json-rs` `get_definition` iterations to reuse the forward context. A deterministic test must fail before the cache and pass after it. The focused benchmark should return below the comparator threshold relative to 406.2 milliseconds, or the profile must expose and justify any remaining hotspot before the milestone is considered complete.

Go acceptance requires existing struct-literal precision tests to remain green and the `gin-go` `scan_usages` median to return below the comparator threshold relative to 756.8 milliseconds. The implementation must not introduce string or regular-expression parsing of Go syntax.

Python acceptance requires the existing inverse-reference correctness tests from commit `6d6d76f3` to stay green. `click-py` `scan_usages` should return below the threshold relative to 2025.3 milliseconds, and `dead_code_smells` should return below the threshold relative to 2076.7 milliseconds. If only the dead-code scenario remains above threshold, profile evidence must identify whether the whole-graph design needs a separate follow-up rather than silently promoting the slower baseline.

Workflow acceptance requires repository tests to prove that scheduled runs still prepare and send Slack payloads, ordinary manual dispatches preserve the current default, and a manual dispatch with the new input false skips both Slack steps while still uploading artifacts, publishing the summary, and enforcing the benchmark result.

The pull request is ready only when the focused tests pass, formatting is clean, clippy is clean, benchmark evidence is attached to the ExecPlan and PR description, and no unrelated files are staged.

## Idempotence and Recovery

All cache changes are generation-scoped and can be rebuilt safely. Analyzer `update` and `update_all` paths must allocate fresh caches, so stale source facts cannot survive edits. Focused benchmark commands reuse pinned repositories under `benchmark/.cache/repos`; rerunning them is safe. The workflow input is additive and defaults to current behavior.

If a benchmark process is interrupted, rerun the same repository command; timestamped reports and profile directories do not overwrite earlier evidence. If an isolated Cargo command fails, the helper removes its target directory automatically. Git staging must always name explicit paths so unrelated worktree state is not swept into milestone commits.

## Artifacts and Notes

Initial run evidence from `29489210696`:

    click-py scan_usages:       2025.3 ms -> 3704.9 ms (+82.9%)
    click-py dead_code_smells:  2076.7 ms -> 20197.9 ms (+872.6%)
    gin-go scan_usages:          756.8 ms -> 1075.1 ms (+42.1%)
    serde-json-rs get_definition:406.2 ms -> 979.8 ms (+141.2%)

The prior scheduled run was faster than the blessed baseline on all four scenarios, so the current deltas are not explained by a generally slower runner.

## Interfaces and Dependencies

No new external Rust dependency is expected. Reuse the existing weighted `moka::sync::Cache`, `Arc`, `OnceLock`, project-relative `ProjectFile`, tree-sitter nodes, repository hash-map aliases, and benchmark workflow conventions.

`RustAnalyzer::forward_reference_context_of(&ProjectFile) -> Arc<RustReferenceContext>` keeps its signature but must become cached within an analyzer generation.

Python cached facts must remain internal to `PythonUsageIndex` and must not retain tree-sitter `Tree` or `Node` values. Store owned names, module specifiers, imported names, binding positions, and binding kinds only. Query-local inverted resolution caches may use thread-safe maps or precomputed immutable maps but must not outlive the graph build.

The workflow input should be a GitHub Actions boolean and should not change scheduled-run behavior. The Slack steps should use one shared condition so payload preparation and transmission cannot disagree.

Plan update note: Created on 2026-07-16 to capture the complete implementation, validation, publication, and silent-benchmark workflow requested in this session.
