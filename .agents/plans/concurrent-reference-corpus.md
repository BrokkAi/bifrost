# Run reference-differential repositories concurrently within a bounded resource budget

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this document in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

The reference-differential command can already select the largest N repositories for a language, but `run-corpus` audits those repositories one at a time. A single Java audit uses only a fraction of a 120-core machine on average because individual files and inverse targets vary greatly in cost. After this change, a user can run several independent repository audits concurrently with `--repo-jobs N`, while `--jobs M` limits both analyzer construction and differential work inside each repository. Progress identifies its repository, completed reports are appended safely as soon as each repository finishes, interrupted runs remain resumable, and two language audits sharing one physical clone never touch that clone's persisted SQLite cache concurrently.

The observable acceptance command is a fixture-backed `run-corpus` invocation with three repositories, `--repo-jobs 2`, and `--jobs 1`. Its stderr must show two repositories overlap, never more than two run together, every progress line identifies its repository, and a second identical invocation skips all three completed records without appending duplicates.

## Progress

- [x] (2026-07-16 23:08Z) Read `.agents/PLANS.md`, inspected the CLI selection/execution loop, progress callbacks, report append path, analyzer parallelism configuration, and existing CLI fixtures.
- [x] (2026-07-16 23:08Z) Chose a repository-group scheduler that serializes jobs sharing a canonical clone root while running distinct roots concurrently.
- [x] (2026-07-16 23:34Z) Implemented `--repo-jobs`, bounded repository groups, explicit analyzer parallelism, repository-qualified progress, and completion-time serialized report appends.
- [x] (2026-07-16 23:34Z) Added behavior-focused CLI coverage for bounded overlap, same-clone serialization, resource settings, report completeness, and resumption.
- [x] (2026-07-16 23:34Z) Ran formatting, 8 focused CLI tests, all-target/all-feature clippy, and the complete feature-enabled test suite successfully.
- [x] (2026-07-16 23:34Z) Ran the real Java top-ten dry-run with `--repo-jobs 5 --jobs 24`; it accepted the new resource settings and retained the established selection order without opening analyzers or caches.
- [ ] Update this plan with final integration evidence, commit only the changed files, merge current `origin/master`, and push directly to `master`.

## Surprises & Discoveries

- Observation: `--jobs` currently controls only the forward-file and inverse-target Rayon pool; workspace analyzer construction uses `AnalyzerConfig::default()` and therefore all available processors.
  Evidence: `src/bin/bifrost_reference_differential.rs::run_engine` constructs the workspace with the default config, while `src/reference_differential/mod.rs::run_reference_differential_with_progress` creates a separate pool from `ReferenceDifferentialConfig.parallelism`.

- Observation: repository selection already sorts each language by descending recorded LOC, which is the desirable longest-processing-time-first starting order for a bounded outer pool.
  Evidence: `select_corpus_repositories` sorts by reverse `code_loc` and then slug before taking the configured count.

- Observation: one physical clone can be selected for multiple corpus languages, so a naive parallel iterator can run two analyzers against the same `.brokk/bifrost_cache.db`.
  Evidence: selection is performed independently for each language and all language entries map a slug to the same `clones_root/<slug>` path.

- Observation: adding `repo=...` before the historical progress fields broke an existing assertion that intentionally treats the beginning of a progress line as stable.
  Evidence: the first focused CLI run failed `run_repo_writes_completed_jsonl_report_for_tiny_project`; retaining each old field prefix and adding `repo` after it restored compatibility, and all 8 focused tests then passed.

- Observation: the full suite cannot be judged inside the restricted Optane-worktree sandbox because process-tree tests receive `PermissionDenied` and the NLP sidecar cannot create its local `.venv`.
  Evidence: the restricted run reached 992 passing library tests but reported only those environment failures. Re-running the identical feature-enabled suite outside that filesystem restriction exited zero and removed its isolated Cargo target.

## Decision Log

- Decision: Add `--repo-jobs` only to `run-corpus`, defaulting to one for backward-compatible serial execution; retain `--jobs` as the per-repository worker count.
  Rationale: Existing `run-repo` scripts and report fingerprints already assign `--jobs` this meaning. The explicit product `repo-jobs * jobs` is easy to size for the host, such as five repositories times twenty-four workers on 120 processors.
  Date/Author: 2026-07-16 / Codex

- Decision: Apply `--jobs` to `AnalyzerConfig.parallelism` as well as the differential worker pool.
  Rationale: Otherwise five concurrent cold repositories each create a 120-thread analyzer pool before entering their nominal 24-worker audit, defeating the resource bound precisely during cache construction.
  Date/Author: 2026-07-16 / Codex

- Decision: Group pending jobs by canonical repository root and execute jobs within one group sequentially.
  Rationale: Different clones have independent persisted databases and are safe to run concurrently. Different language audits of the same clone do not, and must never overlap.
  Date/Author: 2026-07-16 / Codex

- Decision: Have worker threads return complete records over a channel and let the caller append each record upon receipt.
  Rationale: A single writer prevents interleaved JSON while completion-order writes preserve maximum crash resilience. Deterministic selection and report contents matter; JSONL line order does not participate in completion keys or semantic results.
  Date/Author: 2026-07-16 / Codex

## Outcomes & Retrospective

The bounded scheduler now executes distinct canonical clone roots concurrently and serializes all selected language jobs sharing a clone. `--jobs` bounds both analyzer construction and differential querying, so the intended Java campaign can use five independent repositories times twenty-four workers instead of creating five unbounded analyzer pools. Records still have one completion-time writer and resume by semantic completion key, regardless of their new completion-order JSONL layout.

The behavior-focused CLI suite reports 8 passed tests, including an observed maximum of exactly two active fixture repositories for `--repo-jobs 2`, one active repository for two language jobs sharing a clone, and a no-duplicate second invocation. Formatting, `cargo clippy --all-targets --all-features -- -D warnings`, and the complete `cargo test --features nlp,python` suite all pass. The production Java dry-run selected google-cloud-java, aws-sdk-java, IntelliJ, dragonwell8, Telegram, Hadoop, OpenSearch, StarRocks, Neo4j, and Trino in descending corpus LOC order.

The concurrency guarantee is intentionally local to one `run-corpus` process; two independently launched processes can still target the same persisted clone. That is unchanged from the old command and is outside this scheduler's scope.

## Context and Orientation

`src/bin/bifrost_reference_differential.rs` is the command-line driver. `parse_run_corpus_args` reads corpus-only flags, `select_corpus_repositories` deterministically chooses clone paths from corpus metadata, and `run_corpus_command` currently loops over that selection serially. `run_engine` constructs one `WorkspaceAnalyzer`, then calls `run_reference_differential_with_progress` from `src/reference_differential/mod.rs`. A persisted workspace stores analyzer state in the selected clone's `.brokk/bifrost_cache.db`.

`--jobs` is serialized into `ReferenceDifferentialConfig`, contributes to the run fingerprint, and controls the per-repository Rayon pool used for sampled forward files and inverse target groups. A repository worker means one outer operating-system thread responsible for one clone at a time. Repository grouping means collecting all selected language jobs with the same canonical clone path into one queue item so the worker performs them sequentially.

`tests/bifrost_reference_differential_cli.rs` launches the compiled binary against temporary Git repositories. It already proves deterministic corpus selection, exact repository filtering, JSONL output, progress, persisted versus ephemeral cache behavior, and resume skipping. Extend this end-to-end fixture rather than duplicating scheduler implementation details in unit tests.

## Plan of Work

In `src/bin/bifrost_reference_differential.rs`, add a positive `repo_parallelism` field to `RunCorpusArgs`, parse `--repo-jobs`, document it in corpus help, and leave its default at one. Refactor the body of `run_corpus_command` into a sequential preparation phase and a bounded execution phase. Preparation reads repository metadata, computes the semantic completion key, immediately records metadata errors, skips completed work, and groups pending jobs by canonical clone root while retaining each job's selection position.

Run the groups through scoped standard-library worker threads backed by a synchronized queue. Spawn no more than `min(repo_parallelism, group_count)` workers. A worker pops one clone group, runs every language job in that group sequentially, and sends each completed `RepositoryRecord` to the caller. The caller is the only JSONL writer and appends a record immediately when received, prints its summary, and accumulates strict-mode failure state. Worker start messages and engine progress must include a stable `language/repo_slug` label so interleaved stderr remains understandable.

Change `run_engine` to build `AnalyzerConfig` with `parallelism: Some(config.parallelism)` and otherwise retain defaults. Include the configured worker count in workspace-start progress. Preserve the existing `progress phase=...` prefix so current tooling and tests remain compatible, adding `repo=...` as another field rather than changing the phase field's position.

In `tests/bifrost_reference_differential_cli.rs`, expand the corpus fixture so valid clones can contain small language source projects. Add a complete `run-corpus` test with three distinct Rust repositories and two outer workers. It must assert three completed JSON records, report config parallelism equal to the requested inner jobs, repository-qualified progress, observable overlap of two repository starts, a maximum overlap of two, and successful skip-only resumption without extra JSON lines. Add a shared-clone multi-language fixture and assert its two jobs never overlap even with two outer workers. Keep tests based on the binary's user-visible behavior.

## Concrete Steps

Work in `/mnt/optane/tmp/bifrost-java-n10`.

After the implementation, run:

    cargo fmt --all -- --check
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test bifrost_reference_differential_cli
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    UV_CACHE_DIR=/tmp/bifrost-uv-cache scripts/with-isolated-cargo-target.sh cargo test --features nlp,python

The focused CLI test must report all tests passed. Clippy must produce no warnings. The complete suite must finish with no failed test binaries.

For a real selection-only smoke, run:

    scripts/with-isolated-cargo-target.sh cargo run --release \
      --bin bifrost_reference_differential -- run-corpus \
      --clones-root /home/jonathan/Projects/brokkbench/clones \
      --commits-root /home/jonathan/Projects/brokkbench/sft-tools-commits \
      --language java --repos-per-language 10 --repo-jobs 5 --jobs 24 --dry-run

The output must list the same ten Java repositories as before because outer parallelism is operational only and does not affect selection.

## Validation and Acceptance

Acceptance requires all existing CLI behavior to remain green and the new end-to-end tests to demonstrate bounded concurrent execution rather than merely inspecting configuration fields. With three distinct repositories and `--repo-jobs 2`, two `run` events must occur before the first matching `done`, the observed active count must never exceed two, and all three records must be valid completed JSON. With one clone selected for two languages, the second job for that clone must start only after the first finishes. Repeating a completed concurrent command must append no records and must report that each job was already completed.

The real Java dry run must accept `--repo-jobs 5`, retain the established top-ten ordering, and perform no analyzer or cache writes. Formatting, all-target/all-feature clippy, and the full `nlp,python` test suite are required before pushing because the scheduler changes a shared offline runner and analyzer construction configuration.

## Idempotence and Recovery

The scheduler reads existing completion keys before launching work. Repeating a command without `--force` skips completed records regardless of completion-order JSONL lines. If the process is interrupted, every record received before interruption has already been appended by the sole writer, and a retry runs only missing keys. A worker never processes two jobs simultaneously, and all jobs sharing a clone root reside in one group, so persisted cache access is serialized within the command. Existing output files and clone caches are never deleted.

If validation fails after a partial concurrent fixture run, rerun the fixture: each test owns a new temporary directory. Use the repository's isolated-target helper for Cargo validation so temporary build artifacts are removed automatically.

## Artifacts and Notes

The motivating clean Java N=1 run used `--jobs 120` but averaged 1,528% CPU and peaked at 10,649,208 KiB RSS. On the 120-processor, 98-GiB host, `--repo-jobs 5 --jobs 24` intentionally trades excess within-repository workers for independent repository work while leaving memory headroom.

## Interfaces and Dependencies

No new crate is required. Use `std::thread::scope` for bounded outer workers, `std::sync::mpsc` for completed records, and `std::sync::{Arc, Mutex}` plus `std::collections::VecDeque` for the clone-group queue. Continue using the existing `RepositoryRecord`, `CompletionKey`, `append_record`, `repository_record`, and `print_record_summary` types and functions.

`RunCorpusArgs` must expose an internal `repo_parallelism: usize`. The CLI interface is:

    --repo-jobs N    Maximum repositories audited concurrently (default: 1)

`--jobs N` remains the worker count within each repository and must also be passed to `AnalyzerConfig.parallelism` during workspace construction.

Revision note (2026-07-16): Created this ExecPlan after inspecting the serial corpus loop and both analyzer worker pools. It chooses clone-root grouping and a single completion-order writer to preserve cache safety and resumability while adding bounded repository concurrency.

Revision note (2026-07-16 23:34Z): Recorded the completed scheduler, behavior tests, validation results, compatibility adjustment, restricted-sandbox false failures, production top-ten dry-run, and the deliberately process-local scope of clone serialization.
