# Restore weighted most_relevant_files seeds and add recency-aware git scoring

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](./PLANS.md).

## Purpose / Big Picture

After this change, `most_relevant_files` can accept explicit per-seed weights again, rejects duplicate resolved seeds instead of silently stacking them, and applies the same exponential half-life recency decay to git relevance that `most_important_project_files` also uses. A user should be able to call the tool with `seed_file_paths`, `seed_weights`, and optional `recency_half_life`, get a clear error when two inputs resolve to the same file, and see recent co-change partners outrank equally frequent but older ones on the public path. The proof is an expanded Rust test suite plus Python client tests.

## Progress

- [x] (2026-06-10T21:18:00Z) Re-read `AGENTS.md` and `.agent/PLANS.md`, then inspected `src/relevance.rs`, `src/searchtools.rs`, `src/tool_arguments.rs`, `src/mcp_extended.rs`, `src/searchtools_render.rs`, `bifrost_searchtools/client.py`, `bifrost_searchtools/models.py`, and `tests/most_relevant_files.rs`.
- [x] (2026-06-10T21:18:00Z) Confirmed the current gaps: `normalized_seed_weights` is misnamed and silently stacks duplicates, `most_relevant_files` resolves literals without duplicate detection, and `related_files_by_git` still uses uniform per-commit mass while `most_important_project_files` already uses `1/(index+1)`.
- [x] (2026-06-10T21:59:00Z) Added optional `seed_weights` to `MostRelevantFilesParams`, validated length/positivity/finiteness, changed `most_relevant_files` to return `Result<MostRelevantFilesResult, String>`, and threaded the new parameter through MCP schema, CLI handling, and the Python client/model.
- [x] (2026-06-10T21:59:00Z) Added duplicate resolved-seed detection after literal resolution, surfaced duplicates through `MostRelevantFilesResult`, and updated text rendering and Python deserialization to show duplicate failures without ranking.
- [x] (2026-06-10T21:59:00Z) Extracted shared commit-age weighting, renamed the raw seed-weight helper, added half-life-driven git scoring in `related_files_by_git`, and kept an explicit legacy uniform path available through `most_relevant_project_files_with_half_life(..., None)` for parity-sensitive tests.
- [x] (2026-06-10T22:05:00Z) Added Rust tests for weighted seed ranking, invalid weights, duplicate resolved seeds, public recency ranking, recency-vs-uniform internal sanity, legacy `None` pinning, and half-life-shape coverage; added Python client tests for `seed_weights`, `recency_half_life`, and duplicate-seed reporting.
- [x] (2026-06-10T22:05:00Z) Ran `cargo fmt --all`, `cargo test`, `cargo clippy --all-targets --all-features -- -D warnings`, and `uv run --python 3.12 --with maturin python -m unittest python_tests.test_searchtools_client`.
- [ ] Cut a multiline checkpoint commit after material progress, per `AGENTS.md`.

## Surprises & Discoveries

- Observation: the public `most_relevant_files` path already flows through code that multiplies `seed_weight * conditional * idf`; only the API surface for explicit weights was removed.
  Evidence: `src/relevance.rs::related_files_by_git` reads `seed_weights.get(&seed)` and multiplies it into each contribution.

- Observation: duplicate resolved seeds currently stack because the helper inserts into a hash map with `+= 1.0`, even if two different literals resolve to the same `ProjectFile`.
  Evidence: `src/relevance.rs::normalized_seed_weights` uses `*weights.entry(seed.clone()).or_insert(0.0) += 1.0`.

- Observation: the parity-sensitive git scorer is explicitly documented as shared with Brokk, so the recency change must be isolated behind an optional half-life to keep legacy parity fixtures stable until Brokk mirrors it.
  Evidence: the doc comment above `src/relevance.rs::related_files_by_git` says to keep behavior in sync with Brokk and rerun external parity fixtures when rules change.

## Decision Log

- Decision: restore seed weights as raw, unnormalized weights and rename the helper to match reality.
  Rationale: the user asked for the old Brokk-style API semantics, and the current helper never normalized anything.
  Date/Author: 2026-06-10 / Codex

- Decision: make duplicate resolved seeds a hard error in `MostRelevantFilesResult` instead of trying to auto-merge or preserve stacking.
  Rationale: explicit weights eliminate the only plausible reason to stack duplicates, and failing early matches the existing `not_found`/`ambiguous_paths` reporting style.
  Date/Author: 2026-06-10 / Codex

- Decision: gate git recency weighting inside `related_files_by_git` with `Option<f64>` half-life plumbing while leaving the public `most_relevant_files` path on the 250-commit default when the field is omitted.
  Rationale: this preserves legacy parity fixtures for the uniform `None` path while enabling the intended new behavior for the user-facing tool and targeted tests.
  Date/Author: 2026-06-10 / Codex

## Outcomes & Retrospective

Implementation outcome 2026-06-10T22:05:00Z: `most_relevant_files` once again accepts explicit raw seed weights, rejects duplicate resolved seeds before ranking, and uses half-life-aware git affinity on the public path while preserving a legacy uniform path for parity-sensitive checks. The Rust and Python layers now agree on the expanded request/result shape. The only follow-up outside this repo is the Brokk mirror: the git scorer should use `2^(-index/half_life)` with the default half-life of 250 commits, apply that weight to both joint mass and the seed denominator while keeping IDF unweighted, and use the same decay in `most_important_project_files` before external parity fixtures can move from the legacy path to the default path.

## Context and Orientation

`most_relevant_files` is a searchtools entry point in `src/searchtools.rs`. It accepts `MostRelevantFilesParams`, resolves `seed_file_paths` via `WorkspaceFileResolver::resolve_literal`, and returns `MostRelevantFilesResult` with `files`, `not_found`, and `ambiguous_paths`. Today it never validates or reports duplicate resolved seeds.

The actual relevance scoring is in `src/relevance.rs`. `most_relevant_project_files(...)` builds a seed-weight map from resolved seed files, then combines `related_files_by_git(...)` and `related_files_by_imports(...)`. Both `related_files_by_git(...)` and `most_important_project_files(...)` should now use the same half-life helper so the repo has one recency rule everywhere. That git scorer also carries a parity contract with Brokk in its doc comment, so any behavior change there must be easy to enumerate and to keep behind a legacy path.

The MCP-facing schema for `most_relevant_files` is declared in `src/mcp_extended.rs`. Tool argument normalization is in `src/tool_arguments.rs`, though this specific change only needs path normalization for `seed_file_paths`; weights are plain numbers. The structured tool dispatch passes through `src/searchtools_service.rs`.

The Python wrapper lives in `bifrost_searchtools/client.py`, with result models in `bifrost_searchtools/models.py`. The client signature now also needs `recency_half_life`, with omission preserving the server default and explicit `None` selecting the uniform legacy path for parity-sensitive experiments.

The Rust coverage for this feature lives in `tests/most_relevant_files.rs`, which already includes git-history and merge-without-duplicates tests built from inline fixtures and temporary git repos. Python coverage lives in `python_tests/test_searchtools_client.py`.

## Plan of Work

Start in `src/searchtools.rs` by extending `MostRelevantFilesParams` with `seed_weights: Option<Vec<f64>>` and `MostRelevantFilesResult` with a `duplicates` field that names duplicate resolved inputs. Add parameter validation near the start of `most_relevant_files`: when `seed_weights` is present, require equal length with `seed_file_paths`, require every weight to be finite and strictly positive, and return a `MostRelevantFilesResult` failure shape instead of ranking when validation fails. Resolve literals as today, but track the first input that resolves to each `ProjectFile`; if another input resolves to the same file, add a duplicate record and short-circuit the call before scoring.

Next update `src/relevance.rs`. Rename `normalized_seed_weights` to something like `seed_weight_map`, change its signature to accept both resolved seeds and optional raw weights, and keep the semantics raw rather than normalized. Extract a shared helper for commit-age weighting, `commit_age_weight(index, half_life) -> f64`, and use it in both `most_important_project_files` and `related_files_by_git`.

Then adjust `related_files_by_git(...)` to accept an internal `half_life: Option<f64>` parameter. For the legacy parity path, preserve the existing uniform weighting with `None`. For the new path, weight both the joint mass contribution and the seed denominator mass by the same per-commit age weight so `conditional = weighted_joint / weighted_seed_mass` remains a real conditional probability. Keep document frequency and IDF based on raw commit counts, and document that choice directly in the scorer because IDF is meant to measure global commonness across the commit corpus, not recency-biased affinity. Update `most_relevant_project_files(...)` to call the 250-commit default path, and keep an internal `None` caller for parity-sensitive tests.

After the scorer changes, update the MCP descriptor in `src/mcp_extended.rs` to advertise `seed_weights` plus `recency_half_life`, keep path normalization unchanged in `src/tool_arguments.rs`, and update any CLI or service callers that construct `MostRelevantFilesParams`. Extend `src/searchtools_render.rs` and `bifrost_searchtools/models.py` so duplicate errors render clearly and deserialize correctly.

Finish with tests. In `tests/most_relevant_files.rs`, add one test proving a heavily weighted seed changes the ranking, one proving duplicate resolved seeds fail with a `duplicates` payload, one proving recency makes a recent co-change target outrank an equally frequent old-only target, one proving `recency_half_life=None` pins the legacy uniform path, and one proving a huge half-life approximates uniform while a small half-life sharpens recency preference. Keep any existing parity-style tests on the legacy git path if they depend on recorded external fixtures, and add explicit recency-on coverage for the public path. In `python_tests/test_searchtools_client.py`, add at least one call that passes `seed_weights`, one that passes `recency_half_life`, and one that checks duplicate errors deserialize.

## Concrete Steps

From `/home/jonathan/Projects/bifrost`, implement and validate the change with:

    cargo fmt --all
    cargo clippy --all-targets --all-features -- -D warnings
    cargo test
    python -m unittest python_tests.test_searchtools_client

Expected signs of success:

    calling `most_relevant_files` with mismatched `seed_weights` length returns a structured error instead of ranking
    two literal seed inputs that resolve to the same file return a `duplicates` payload and no ranked files
    a recent co-change target outranks an equally frequent old-only target on the 250-commit default path
    `recency_half_life=None` still exercises the uniform git path and continues to pass parity-sensitive checks

This section will be updated with actual command evidence after implementation.

Actual results recorded 2026-06-10T22:05:00Z:

    cargo fmt --all
    <no output; completed successfully>

    cargo test
    test result: ok. library/unit/integration suites all passed

    cargo clippy --all-targets --all-features -- -D warnings
    Finished `dev` profile ... target(s) in 6.82s

    uv run --python 3.12 --with maturin python -m unittest python_tests.test_searchtools_client
    Ran 11 tests in 14.392s
    OK

## Validation and Acceptance

Acceptance is behavioral. The Rust tests must prove that explicit seed weights alter ranking, duplicate resolved seeds fail fast, the public git scorer prefers recent affinity when all else is equal, and `recency_half_life=None` preserves the uniform legacy path. The Python client tests must prove the new `seed_weights` and `recency_half_life` arguments are wired through and that the expanded result shape still deserializes and renders correctly. `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test`, and `python -m unittest python_tests.test_searchtools_client` must all complete successfully.

## Idempotence and Recovery

These are source-only edits. Reapplying the patch is safe as long as the new result fields remain additive and callers initialize them. If parity-backed tests start failing because they are exercising the new recency path, route those tests through the explicit legacy flag instead of weakening the public behavior. Do not revert unrelated working-tree changes.

## Artifacts and Notes

Key artifacts to preserve:

    the renamed raw-weight helper in `src/relevance.rs`
    the new half-life gate inside `related_files_by_git(...)`
    the new `MostRelevantFilesResult.duplicates` failure reporting
    test evidence showing weighted seeds and half-life-based recency both affect ranking as intended
    the Brokk-mirror checklist: `2^(-index/half_life)`, default half-life 250 commits, weight joint mass and seed denominator only, leave IDF unweighted, and use the same decay in `most_important_project_files`

## Interfaces and Dependencies

At the end of this work, these public interfaces must exist:

    pub struct MostRelevantFilesParams {
        pub seed_file_paths: Vec<String>,
        pub seed_weights: Option<Vec<f64>>,
        pub recency_half_life: Option<f64>,
        pub limit: usize,
    }

and:

    pub struct MostRelevantFilesResult {
        pub files: Vec<String>,
        pub not_found: Vec<String>,
        pub ambiguous_paths: Vec<AmbiguousPathInput>,
        pub duplicates: Vec<String>,
    }

The Python client must expose:

    def most_relevant_files(
        self,
        seed_files: list[str],
        *,
        limit: int = 20,
        seed_weights: list[float] | None = None,
        recency_half_life: float | None = None,
    ) -> MostRelevantFilesResult:

Revision note 2026-06-10T21:18:00Z: Created this ExecPlan before implementation because the change spans public tool params, parity-sensitive git scoring, duplicate validation semantics, the Python client, and multi-layer tests.
