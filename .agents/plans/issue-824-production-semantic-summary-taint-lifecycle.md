# Measure the production semantic-summary taint lifecycle

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept current while implementation proceeds. This plan follows `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

Issue #824 has a production route that activates dependency semantic-model packs, binds exact procedure summaries, compiles compatible taint policies into one set-oriented solve, retains the resulting findings and witnesses, and projects that one report through standalone CodeQuery/RQL and policy output. The repository currently tests those boundaries but does not measure their lifecycle as one reproducible workload. After this change, a developer can run one deterministic smoke locally or an explicitly enabled full campaign and obtain machine-readable p50/p95 phase timings, scaling evidence, cache behavior, retained-memory estimates, and peak RSS without adding unstable CI thresholds.

## Progress

- [x] (2026-08-03 12:05Z) Verified the clean feature worktree is exactly `origin/master` at `0ad7dc17d5cc8c95e6d7136f2baa5220ff756bff` after fetching the remote.
- [x] (2026-08-03 12:12Z) Read issue #824 and mapped the existing data-flow and summary benchmark protocols plus the production semantic-model and taint-policy route.
- [x] (2026-08-03 12:18Z) Confirmed the rmcp host is active and recorded a greater-than-five-second Bifrost navigation call for latency follow-up.
- [x] (2026-08-03 13:02Z) Added general production taint phase metrics without changing witness or adapter semantics.
- [x] (2026-08-03 13:38Z) Added the deterministic inline benchmark, scaling matrix, retained projection measurements, and aggregate tests in new files.
- [x] (2026-08-03 13:52Z) Added the fresh-process runner and fail-closed pinned realistic fixture contract.
- [x] (2026-08-03 14:48Z) Passed formatting, focused smoke, aggregation tests, strict focused Clippy for both the benchmark target and analysis library, and diff checks. The required policy pack completed with no diagnostics; its five prompts in the edited production file are pre-existing sorts in untouched code.
- [x] (2026-08-03 14:55Z) Checked in the machine-readable smoke aggregate and report without committing, pushing, or opening a pull request.
- [x] (2026-08-03 15:30Z) Completed hosted full-inline campaign run 30817764139 on commit `868f92fed`, verified all seven cases and 49 retained samples, and promoted its Linux release aggregate into the checked baseline report.

## Surprises & Discoveries

- Observation: `SemanticPackCatalog` already exposes load hit/miss counters, and `acquire_active_semantic_models` reports `Built` versus generation-scoped `Cached`; the benchmark does not need benchmark-only cache hooks.
  Evidence: `crates/bifrost-analysis/src/analyzer/semantic_model/catalog/mod.rs` defines `CatalogAccounting.lookup_hits` and `lookup_misses`, while `runtime.rs` defines `SemanticModelRuntimeLifecycle`.
- Observation: production already retains exact plan/report pairs and exposes plan bytes, report bytes, witness counts/steps/bytes, registration identity, and pure public projection. Only internal phase duration is unobservable from an integration benchmark.
  Evidence: `ProductionTaintAnalysisResult` in `crates/bifrost-analysis/src/analyzer/policy/taint_policy.rs`.
- Observation: the local pinned Spring PetClinic checkout is at `f182358d02e4a68e52bdbabf55ca7800288511e7` but contains an untracked `.DS_Store`; it is not eligible for the strict full campaign and will not be modified by this task.
- Observation: `origin/master` advanced from the verified task-start base `0ad7dc17d5cc8c95e6d7136f2baa5220ff756bff` to `487a4f96c807b5b1acd2832e617162aed690fbd8` during validation. Repository instructions prohibit an unsolicited rebase, so the completed and tested work remains on the exact task-start base.
- Observation: the roughly 50-second cold rmcp orientation batch is already owned by issue #1503, which documents the same concurrent cold-initialization shape and attribution limitation.
- Observation: the built-in code-smell pack reports existing repository findings and exits with `finding`; all five prompts in `taint_policy.rs` identify sort calls present in the base and outside this diff. Every selected policy completed with no diagnostics, and no changed benchmark or metrics file produced a finding.

## Decision Log

- Decision: Put timing data in a small general production metrics value attached to each retained production taint result.
  Rationale: compiler/binder, propagation, finding reconstruction, and policy projection cannot be separated reliably outside the adapter. Attaching immutable observations to the retained result keeps the metrics useful to diagnostics and future profiling without adding a benchmark-only execution path.
  Date/Author: 2026-08-03 / Codex
- Decision: Keep fixture generation, aggregation, and fresh-process orchestration in new benchmark files; make only the minimal module registration and instrumentation edits.
  Rationale: this lets the work proceed alongside Track A without editing `tests/suite_bench_policy/taint_policy_adapter.rs`, `witness_projection.rs`, or changing taint semantics.
  Date/Author: 2026-08-03 / Codex
- Decision: The checked-in baseline will be explicitly labeled a focused inline smoke, not a performance gate. The realistic fixture is a pinned contract that fails closed until both its clean repository and exact model artifact are supplied.
  Rationale: the user explicitly withheld authority for an expensive campaign without available pinned fixtures, and the current repository checkout is dirty.
  Date/Author: 2026-08-03 / Codex
- Decision: Do not make checkpoint commits even though ExecPlans normally use them.
  Rationale: the user explicitly said not to commit, push, or open a pull request.
  Date/Author: 2026-08-03 / Codex

## Outcomes & Retrospective

The implementation is complete as an additive production-route benchmark plus general observational instrumentation. The inline smoke proves cold `Built` and warm generation-scoped `Cached` model acquisition, zero warm catalog candidate/load SQL, exact summary binding, one compatible propagation solve, retained finding/witness reconstruction, and equivalent standalone JSON/RQL and policy projections. The checked aggregate contains three deterministic debug-profile retained rounds with p50/p95 phase timings, retained byte estimates, catalog counters, canonical checksums, and process peak RSS. Focused probes also exercised dependency depths four and eight and source/sink counts four and sixteen while retaining one solve.

The full release-profile matrix was not run locally. It is now an explicitly dispatched hosted campaign over the complete pinned inline matrix; its aggregate is uploaded as a workflow artifact. The Spring PetClinic/model contract remains intentionally `designed_not_available` and is not included in inline campaign claims until its repository, model artifacts, and policy are all pinned. No CI threshold was added; the checked report records the initial smoke variance and the next evidence step.

## Context and Orientation

`scripts/run-dataflow-lifecycle-benchmarks.sh` and `tests/suite_semantic/measure_dataflow_lifecycle.rs` define the existing fresh-process protocol: nine deterministic rounds, discard rounds zero and one, retain seven samples, preserve exact provenance, and emit one marker-prefixed JSON value. `scripts/run-summary-lifecycle-benchmarks.sh` and `tests/suite_semantic/measure_summary_lifecycle.rs` add build/hydrate pairing and aggregate invariants. `.agents/docs/dataflow-lifecycle-benchmark-2026-07-24.md` shows the reporting style and the distinction between process RSS and retained object estimates.

The new benchmark belongs in the consolidated `tests/suite_bench_policy` integration harness because it exercises policy loading and projection as well as semantic/data-flow behavior. A semantic-model catalog stores compiled packs and counts catalog loads. `acquire_active_semantic_models` resolves compatible shards and caches one immutable active set per analyzer generation. `TaintPolicyCompiler` uses public structured selectors, discovers value flow, selects the relevant summary dependency closure, and binds exact external targets. `TaintBatchPlanner` unions compatible policy observations. `solve_taint_batch_with_witnesses` performs propagation once per compatible batch. `collect_taint_findings_with_limits` reconstructs bounded findings and witnesses. `ProductionTaintAnalysisResult` retains the exact plan/report pair used by standalone taint projection and policy rendering.

## Plan of Work

Add `crates/bifrost-analysis/src/analyzer/policy/taint_metrics.rs` with an immutable, serializable `ProductionTaintPhaseMetrics` value expressed in nanoseconds and counts. Export it through `policy/mod.rs`. In `taint_policy.rs`, time compilation and exact summary binding per compiled policy, coordinator-wide batch planning, propagation, finding/witness reconstruction, initial standalone projection, and policy projection. Attach the metrics to each `ProductionTaintAnalysisResult` and expose a read-only accessor. Do not modify propagation inputs, budgets, ordering, evidence, witnesses, or projection results.

Add `tests/suite_bench_policy/measure_semantic_summary_taint_lifecycle.rs` and one module line in its existing `main.rs`. The benchmark will generate one deterministic Java project and semantic-model pack. Matrix cases vary total summary count, relevant dependency depth, and source/sink count. Every case uses semantic-model catalog registration, cold then warm acquisition, the public production policy coordinator, one compatible retained analysis, standalone retained projection, JSON CodeQuery, RQL execution, and policy JSON rendering. Samples record provenance, phase timings, catalog counter deltas, lifecycle states, one-solve work metrics, summary/source/sink counts, findings/witnesses, retained bytes, checksums, and peak RSS.

Aggregation accepts newline-delimited sample JSON, requires exact case and round membership for a full campaign, validates deterministic non-timing fields, and computes nearest-rank p50/p95 for each measured phase. Unit tests will build synthetic retained rounds to prove percentile selection and rejection of drift or missing rounds. Smoke mode is allowed to aggregate a smaller explicitly labeled sample set and cannot be confused with the full campaign format.

Add `scripts/run-semantic-summary-taint-lifecycle-benchmarks.sh`. Its default `smoke` mode runs one inline case and a small retained-round set. Its `full` mode runs nine fresh locked release processes for the declared inline scaling matrix and discards two warmups. Wire the full mode into the existing manually dispatchable benchmark workflow as an opt-in job that uploads its aggregate and raw run log. Keep the realistic Spring PetClinic fixture as a separate fail-closed design contract until the repository, model artifact, and policy pins are complete.

Generate `.agents/docs/semantic-summary-taint-lifecycle-benchmark-2026-08-03.json` from the focused smoke and write `.agents/docs/semantic-summary-taint-lifecycle-benchmark-2026-08-03.md` describing protocol, results, variance limitations, scaling design, and the pinned realistic fixture. State explicitly that no hard threshold is established and the full baseline remains pending.

## Concrete Steps

From `/Users/dave/.codex/worktrees/fc2d/bifrost`, edit only the new files plus the minimal policy module, production adapter instrumentation, and consolidated test-harness module line. Then run:

    cargo fmt --all
    cargo test --locked --test suite_bench_policy measure_semantic_summary_taint_lifecycle::
    scripts/run-semantic-summary-taint-lifecycle-benchmarks.sh smoke
    /Users/dave/.cargo/bin/cargo-clippy clippy -p brokk-bifrost --test suite_bench_policy -- -D warnings
    git diff --check
    git status --short

The full runner is not executed locally. After publishing the branch, dispatch the opt-in lifecycle job in `.github/workflows/benchmark.yml` and retain its hosted release-profile aggregate as the live baseline candidate.

## Validation and Acceptance

The focused test must prove cold acquisition is `Built`, warm acquisition is `Cached`, catalog load hit/miss counters do not change during warm policy execution, one retained production analysis exists, and every participating policy reports exactly one `taint.propagation_solves`. Its retained standalone JSON and RQL rows must be identical after serialization, and policy JSON must contain the same finding identity and witness evidence. Phase metrics must be present and internally consistent without requiring positive elapsed nanoseconds for sub-timer work.

Aggregation tests must prove p50/p95 values over seven deterministic retained rounds and reject changed checksums, incompatible sample provenance, duplicate/missing rounds, or more than one compatible solve. Formatting, focused tests, strict focused Clippy, the repository policy selection, and `git diff --check` must pass. The final diff must not touch `witness_projection.rs` or `tests/suite_bench_policy/taint_policy_adapter.rs`.

## Idempotence and Recovery

The runner creates one `mktemp` directory and removes it on success, failure, or interruption. It never modifies external fixture repositories. Aggregate documents are regenerated from the marker-prefixed JSON rather than hand-edited measurements. If a focused build is interrupted, rerun the same command; ordinary Cargo output stays under the worktree target directory and no manually named temporary target is created.

## Artifacts and Notes

The machine marker will be `BIFROST_SEMANTIC_SUMMARY_TAINT_LIFECYCLE_BENCHMARK=`. Sample and aggregate formats use distinct versioned format strings so a smoke artifact cannot be mistaken for the seven-round full campaign.

The Bifrost MCP batch used during orientation combined `find_filenames` for the five named protocol files, `get_summaries` for both large benchmark modules, and `search_symbols` for the production taint entry points. It completed in roughly 50 seconds, above the repository's five-second latency threshold. Open issue #1503 already owns this cold rmcp initialization behavior, including the fact that concurrent first calls cannot be attributed individually.

## Interfaces and Dependencies

`ProductionTaintPhaseMetrics` will expose read-only nanosecond counters for plan discovery and summary binding, batch planning, propagation, finding/witness reconstruction, initial standalone projection, and policy projection, plus compatible policy count and propagation solve count. `ProductionTaintAnalysisResult::phase_metrics()` will return this value by reference. The benchmark uses only public `brokk_bifrost::analyzer` APIs and `serde`/`serde_json` dependencies already available to the test target.

Revision note (2026-08-03): Created the initial self-contained plan after live issue, worktree, benchmark-protocol, semantic-model runtime, catalog accounting, and production taint-adapter inspection.

Revision note (2026-08-03): Closed the plan after implementation and focused validation, recorded the unavailable full-fixture gate, live remote movement, policy-pack review, and existing latency owner.

Revision note (2026-08-03): Added the authorized hosted full-inline campaign path to the existing benchmark workflow while keeping the unavailable realistic fixture out of baseline claims.

Revision note (2026-08-03): Promoted successful Actions run 30817764139 from an artifact candidate to the checked Linux release baseline; retained the earlier macOS debug smoke only as historical protocol evidence.
