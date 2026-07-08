# Add pinned-repo analyzer benchmark harness and daily MCP smoke perf workflow

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

After this change, `bifrost` will have its own lightweight benchmark harness for real repositories instead of relying on Brokk's older baseline runner. A contributor will be able to run one command locally to clone or reuse a pinned corpus, warm the analyzer, execute a small set of analyzer-backed MCP tool calls, and write JSON results that are stable enough for scheduled regression checks. A human should be able to prove the feature works in three ways: validate that the checked-in manifest covers every language listed in `README.md`, run the harness locally against one or more pinned repos and inspect per-scenario timings plus pass/fail outcomes, and trigger a GitHub Actions workflow that uploads the same report and flags regressions against a blessed baseline.

## Progress

- [x] (2026-06-04T10:15Z) Read issue `#170`, `.agents/PLANS.md`, and the current worktree state. The worktree is detached at `HEAD`, so there is no branch-specific rebase target for this planning pass.
- [x] (2026-06-04T10:25Z) Confirmed the core local seams the harness should reuse: `src/analyzer/workspace.rs` provides `WorkspaceAnalyzer::build*`, `src/searchtools_service.rs` is the in-process tool dispatcher, `src/mcp_common.rs` owns the MCP stdio request/response loop, and `tests/bifrost_mcp_server.rs` already contains a minimal JSON-RPC helper for real `tools/call` traffic.
- [x] (2026-06-04T10:35Z) Confirmed there is no existing benchmark harness in this repository. Current workflows are `ci.yml`, `release.yml`, and `publish-crate.yml`; there is no scheduled perf workflow yet.
- [x] (2026-06-04T10:45Z) Compared the local code with sibling precedent. Brokk's `TreeSitterRepoRunner` is much larger and JVM-specific, while SlopCop's TOML benchmark manifest demonstrates the right style for a checked-in pinned corpus manifest.
- [x] (2026-06-04T11:05Z) Identified the main design risk: the requested MCP scenarios need deterministic inputs, but `search_symbols`, `get_symbol_locations`, `get_summaries`, and `most_relevant_files` all need per-repo arguments. The harness must store those arguments explicitly in the manifest instead of inventing them at runtime.
- [x] (2026-06-04T11:20Z) Drafted the first issue-scoped ExecPlan at `ISSUE_170_BENCHMARK_HARNESS_EXECPLAN.md`, including architecture, milestones, validation rules, and workflow strategy.
- [x] (2026-06-04T12:05Z) Implemented the Milestone 1 manifest layer in `src/benchmark/manifest.rs`, exported it from `src/lib.rs`, and added a checked-in corpus manifest plus operator notes under `benchmark/`.
- [x] (2026-06-04T12:12Z) Added `tests/benchmark_manifest.rs` to lock down probe-input validation, required-language coverage, required-scenario coverage, and successful loading of the checked-in manifest.
- [x] (2026-06-04T12:22Z) Verified the new manifest layer with `cargo test --test benchmark_manifest`, `cargo fmt --check`, and `cargo clippy --all-targets --all-features -- -D warnings`.
- [x] (2026-06-04T13:25Z) Started Milestone 2 by adding `src/bin/bifrost_benchmark.rs` with a real `validate` subcommand and adding `tests/bifrost_benchmark_cli.rs` so the checked-in manifest can be exercised through a user-facing entrypoint.
- [x] (2026-06-04T13:25Z) Extended the manifest schema and corpus to include `scan_usages` plus explicit `usage_symbols`, initially on the Java and Go corpus entries where symbol naming is likely to be stable.
- [x] (2026-06-04T15:05Z) Added the first runnable benchmark runtime slice: `src/benchmark/repo_cache.rs`, `src/benchmark/mcp_session.rs`, `src/benchmark/report.rs`, `src/benchmark/runner.rs`, and a `bifrost_benchmark run` path that executes `workspace_build` plus real MCP calls from the manifest.
- [x] (2026-06-04T15:05Z) Added `tests/bifrost_benchmark_run.rs`, which copies the existing Java fixture corpus into a temporary committed git repo and drives all six scenarios end-to-end through the actual CLI, including `scan_usages`.
- [x] (2026-06-04T15:08Z) Verified the runtime slice with `cargo test --test benchmark_manifest --test bifrost_benchmark_cli --test bifrost_benchmark_run`, `cargo fmt --check`, and `cargo clippy --all-targets --all-features -- -D warnings`.
- [x] (2026-06-04T15:47Z) Added `--max-files` subset mode to `bifrost_benchmark run`, which builds a deterministic trimmed workspace rooted under the repo cache, records the subset paths in the JSON report, and keeps manifest probe files pinned into the subset before filling the remaining file budget.
- [x] (2026-06-04T15:47Z) Added subset-mode coverage in `tests/bifrost_benchmark_run.rs` and verified a live quick run against the checked-in `gin-go` corpus entry with `./target/debug/bifrost_benchmark run --repo gin-go --max-files 100`, including a successful `scan_usages` call.
- [x] (2026-06-04T13:11Z) Moved benchmark runtime artifacts into ignored benchmark-local directories: `benchmark/.cache/repos` for cached clones and `benchmark/benchmark-output` for JSON reports. The checked-in manifest now points `repo_cache_dir` at `.cache/repos`, and `.gitignore` ignores both cache and output.
- [x] (2026-06-04T13:18Z) Hardened repo cache reuse in `src/benchmark/repo_cache.rs` so a run skips `git fetch` when the pinned commit is already present locally. Added `tests/benchmark_repo_cache.rs` to lock down this offline cached-run behavior.
- [x] (2026-06-04T13:30Z) Expanded the checked-in MCP probe set with runtime-validated `location_symbols` on every corpus repo and `usage_symbols` on Java, Go, JavaScript, TypeScript, Python, PHP, Scala, and C#. Direct MCP validation confirmed these symbols resolve and produce non-empty usage results on the pinned commits.
- [x] (2026-06-04T13:31Z) Verified the expanded probes through real subset harness runs on `fmt-cpp`, `express-js`, `click-py`, and `serde-json-rs`, and through direct per-scenario MCP validation on the remaining updated repos. This also exposed that some repos, notably `ky-ts` and `fastroute-php`, still need denser subset selection for `most_relevant_files` at `--max-files 100`.
- [x] (2026-06-04T13:17Z) Implemented per-scenario failure aggregation in the runner and CLI. Failed direct or MCP scenarios now produce structured `ScenarioReport` failures with `failure_message`, later scenarios continue to run, and `bifrost_benchmark run` exits nonzero only after writing the JSON report.
- [x] (2026-06-04T13:18Z) Added a regression test that forces `get_symbol_locations` to fail while `scan_usages` still succeeds later in the same repo run, and verified the new reporting path on real subset runs for `ky-ts` and `fastroute-php` where `most_relevant_files` still fails under `--max-files 100`.
- [x] (2026-06-04T13:24Z) Improved subset workspaces for `most_relevant_files` by preserving `.git` metadata inside the copied subset root. The subset-mode regression tests now include a successful `most_relevant_files` case, and real `--max-files 100` runs on `ky-ts` and `fastroute-php` now pass all configured scenarios.
- [x] (2026-06-04T14:20Z) Added baseline comparison support to `bifrost_benchmark`. The CLI now supports `compare --baseline ... --candidate ... [--output ...] [--strict]`, the report layer emits structured compare JSON, and tests now lock down unchanged scenarios, below-threshold slowdowns, above-threshold regressions, and pass/fail transitions.
- [x] (2026-06-04T14:28Z) Added `.github/workflows/benchmark.yml` as the dedicated daily/manual benchmark workflow on `ubuntu-latest`. It validates the manifest, runs the harness, uploads JSON artifacts, compares against `benchmark/baselines/ubuntu-latest.json` when that file exists, and supports a manual `strict_compare` gate without making the first scheduled runs depend on a yet-to-be-promoted baseline.
- [x] (2026-06-05T07:35Z) Promoted the first blessed Ubuntu baseline at `benchmark/baselines/ubuntu-latest.json` from the successful PR-path workflow artifact (`run-20260605T072813Z.json` on PR #172). The artifact contained all ten repos, zero failed scenarios, and a complete full-corpus MCP smoke report, so future scheduled and PR-triggered compare steps now have a real reference point.

## Surprises & Discoveries

- Observation: the MCP server path already has production-grade JSON-RPC handling, but the reusable helper lives only in tests.
  Evidence: `tests/bifrost_mcp_server.rs` contains `spawn_server`, `initialize_session`, `round_trip`, and JSON payload helpers, while `src/mcp_common.rs` owns the actual server loop.

- Observation: `SearchToolsService::new(...)` eagerly builds the workspace before it begins answering MCP requests.
  Evidence: `src/mcp_common.rs` creates `SearchToolsService` before entering the stdin loop, and `SearchToolsService::new_with_strategy(...)` builds a `FilesystemProject` plus `WorkspaceAnalyzer`.

- Observation: direct analyzer timing and MCP timing are not the same signal.
  Evidence: `WorkspaceAnalyzer::build` measures analyzer construction directly, while a real MCP session also includes subprocess startup, JSON serialization, request normalization, and tool dispatch overhead.

- Observation: `README.md` currently declares ten supported analyzer languages, so "better coverage" for this issue means explicit coverage accounting rather than adding one or two more repos.
  Evidence: the status section lists Java, JavaScript, TypeScript, Rust, Go, Python, C++, C#, PHP, and Scala.

- Observation: the existing profiling hook is diagnostic, not a benchmark result format.
  Evidence: `src/profiling.rs` writes nested timing lines to stderr behind `BIFROST_TIMING`; nothing there produces structured per-scenario result files or comparison logic.

- Observation: the checked-in corpus needs two separate coverage dimensions: languages and scenarios.
  Evidence: a corpus can cover all ten languages while still omitting `get_symbol_locations` or `most_relevant_files`, so Milestone 1 added top-level `required_scenarios` validation instead of treating repo language coverage as sufficient.

- Observation: exact pinned repo SHAs were cheap to capture live, while verifying probe-file existence was more important than proving every symbol upfront during Milestone 1.
  Evidence: `gh api` was used on 2026-06-04 to pin the first ten repo commits and confirm the summary/seed file paths, while symbol correctness is left for runtime smoke execution in later milestones.

- Observation: a manifest-only validation layer was not enough once `scan_usages` became a required scenario; a real CLI entrypoint was needed immediately to keep the operator path concrete.
  Evidence: Milestone 2 started by adding `bifrost_benchmark validate` and its integration test instead of waiting for the full runner, so the checked-in corpus is now executable via a stable command rather than only library tests.

- Observation: the local end-to-end runtime slice was easiest to stabilize against the existing Java fixture corpus rather than a hand-written mini-project.
  Evidence: `tests/bifrost_benchmark_run.rs` copies `tests/fixtures/testcode-java` into a temporary git repo and successfully exercises `workspace_build`, `search_symbols`, `get_symbol_locations`, `get_summaries`, `most_relevant_files`, and `scan_usages` through the real `bifrost_benchmark` CLI.

- Observation: quick subset runs need explicit probe-file pinning to stay meaningful.
  Evidence: the `--max-files` implementation now includes `summary_targets` and `seed_file_paths` before filling the remaining budget, and the live `gin-go` smoke run succeeded with `--max-files 100` once the subset workspace preserved those probe files.

- Observation: cached benchmark runs must not assume network access once the pinned commits have already been cloned.
  Evidence: the first expanded subset sweep failed immediately because `prepare_repo(...)` always attempted `git fetch`, even though `benchmark/.cache/repos/*` already contained the exact pinned commits. The repo cache now checks commit presence locally before fetching, and `tests/benchmark_repo_cache.rs` proves the offline reuse path.

- Observation: full-repo MCP validity and `--max-files 100` subset validity are different bars, especially for `most_relevant_files`.
  Evidence: direct MCP validation on the pinned repos confirmed the new location/usages probes for JavaScript, TypeScript, Python, PHP, Scala, and C#, while subset harness runs still showed `most_relevant_files` going empty on `ky-ts` and `fastroute-php` under a 100-file trimmed workspace.

- Observation: the harness needed failure aggregation before more subset tuning, because otherwise the first weak scenario hid the rest of the repo's usable signal.
  Evidence: before this milestone, `bifrost_benchmark run --repo ky-ts --max-files 100` and `--repo fastroute-php --max-files 100` aborted immediately on `most_relevant_files`. After the runner change, both runs now write full reports, record `most_relevant_files` as failed, and still execute the later `scan_usages` scenario successfully.

- Observation: the key missing signal in subset mode was git history, not only source-file choice.
  Evidence: `ky-ts` and `fastroute-php` each fit within the 100-file source budget already, yet `most_relevant_files` still returned nothing until the subset workspace included `.git` metadata. After preserving `.git`, the same 100-file subset runs returned meaningful related files and passed end-to-end.

- Observation: the workflow needs to remain useful before the first blessed Ubuntu baseline is checked in.
  Evidence: the compare logic is now implemented locally, but the repository still has no reviewed `benchmark/baselines/ubuntu-latest.json` artifact. The workflow therefore uploads the run artifact unconditionally, skips compare cleanly when that file is absent, and documents the promotion path in `benchmark/baselines/README.md`.

## Decision Log

- Decision: the benchmark corpus must be a checked-in TOML manifest under `benchmark/targets.toml`, and that manifest must declare explicit per-repo probe inputs for every enabled MCP scenario.
  Rationale: runtime auto-discovery would make the smoke test non-deterministic and would let analyzer behavior changes alter the benchmark inputs, which defeats regression tracking.
  Date/Author: 2026-06-04 / Codex

- Decision: the harness will measure direct analyzer warm-up separately from MCP tool calls.
  Rationale: the issue explicitly wants analyzer warm-up plus MCP smoke coverage, and those are different signals. A direct `WorkspaceAnalyzer::build*` timing isolates analyzer-core regressions, while the MCP calls catch protocol, dispatch, and rendered-result drift.
  Date/Author: 2026-06-04 / Codex

- Decision: MCP smoke scenarios must use the real `bifrost` stdio server, not only `SearchToolsService` in process.
  Rationale: the new requirement in this issue is MCP coverage. If the harness only calls library functions, it will miss regressions in `src/bin/bifrost.rs`, `src/mcp_common.rs`, path normalization, session initialization, and tool registry wiring.
  Date/Author: 2026-06-04 / Codex + user intent

- Decision: the manifest must carry explicit language coverage metadata and fail validation if the union of repo entries does not cover every language listed in `README.md`.
  Rationale: the primary product goal is language coverage. It should be impossible to add or remove corpus entries without seeing whether Java, JavaScript, TypeScript, Rust, Go, Python, C++, C#, PHP, and Scala are still represented.
  Date/Author: 2026-06-04 / Codex

- Decision: the harness will use a local repo cache under `target/benchmark-repos` and report output under `benchmark-output/` by default.
  Rationale: cached clones should stay outside version control, while reports should be easy to inspect locally and easy for GitHub Actions to upload as artifacts.
  Date/Author: 2026-06-04 / Codex

- Decision: regression gating will compare the median of measured iterations, with an initial threshold of `20%` and an absolute floor of `50 ms`, and any pass-to-fail scenario transition is always a regression.
  Rationale: scheduled GitHub runners are noisy. A relative threshold alone is too twitchy for very fast scenarios, while an absolute threshold alone misses large slowdowns on heavier repositories.
  Date/Author: 2026-06-04 / Codex

- Decision: the manifest schema will explicitly declare top-level `required_languages` and `required_scenarios` instead of hard-coding those checks in the future harness binary.
  Rationale: Milestone 1 needs validation that is visible in the checked-in corpus itself. Keeping those expectations in TOML makes corpus intent reviewable and lets tests validate drift without depending on one particular CLI implementation.
  Date/Author: 2026-06-04 / Codex

- Decision: the first pinned corpus uses one small public repository per supported language, with only Java and Go enabling `get_symbol_locations` initially.
  Rationale: Milestone 1 optimized for complete language coverage plus realistic checked-in probe inputs without over-committing to fragile symbol assumptions in every language before the runtime harness exists.
  Date/Author: 2026-06-04 / Codex

- Decision: `scan_usages` is part of the required minimum scenario set, but the first explicit `usage_symbols` are only attached to the Java and Go corpus entries.
  Rationale: the user explicitly called out usages as high-value and regression-prone, so the scenario should be mandatory overall. Starting with Java and Go keeps the first runtime slice anchored to symbols that are likely to remain stable while the harness is still being built.
  Date/Author: 2026-06-04 / Codex + user

- Decision: the first runnable `run` path will stop on scenario failure instead of trying to emit partial per-scenario failure reports.
  Rationale: getting the real repo-cache, MCP session, and scenario execution path working end-to-end was the higher-priority milestone. Richer failure aggregation is still desirable, but it can be layered on top of a working runner instead of complicating the first execution slice.
  Date/Author: 2026-06-04 / Codex

- Decision: quick local smoke runs will use a harness-local subset workspace instead of adding a new analyzer-wide file-cap configuration.
  Rationale: `scan_usages`, MCP startup, and direct `workspace_build` all need to observe the same reduced corpus, while the analyzers currently expose no shared "analyze at most N files" seam. A deterministic copied subset under the benchmark repo cache keeps the fast path isolated to the harness and avoids threading benchmark-only config through every language analyzer.
  Date/Author: 2026-06-04 / Codex + user

- Decision: the checked-in benchmark repo cache belongs under `benchmark/.cache/repos`, and cached runs should stay offline when the pinned commit is already available locally.
  Rationale: the user explicitly wanted repo pulls in a gitignored directory inside this checkout. Keeping clones and subset workspaces under `benchmark/.cache/` makes the runtime artifacts obvious and disposable, while skipping fetch when the commit already exists makes local smoke runs reliable without requiring repeated network access.
  Date/Author: 2026-06-04 / Codex + user

- Decision: expand MCP probe coverage incrementally using only symbols proven through the real stdio server, even if some repos temporarily gain `get_symbol_locations` before they gain `scan_usages`.
  Rationale: exact fully qualified symbol spelling varies materially by language and analyzer. Probes chosen only from grep are too fragile. The current milestone therefore promotes location coverage across all corpus repos, usage coverage across the repos with proven non-empty hits, and leaves subset-tuning for `most_relevant_files` as a follow-up seam instead of pretending every repo is equally subset-friendly.
  Date/Author: 2026-06-04 / Codex

- Decision: `bifrost_benchmark run` should return a nonzero exit code when any scenario fails, but only after writing the JSON report and printing the per-scenario summary.
  Rationale: CI and scheduled workflows need a failure signal, but operators also need the artifact and the surviving scenario timings from the same run. Recording structured failures first and exiting afterward preserves both.
  Date/Author: 2026-06-04 / Codex

- Decision: subset workspaces should preserve repository git metadata, because `most_relevant_files` depends on commit-churn relevance in addition to import relationships.
  Rationale: copying only the selected source files made the fast path unrepresentative for repos whose `most_relevant_files` results were primarily driven by recent related-file churn. Preserving `.git` inside the subset root restores that signal without abandoning the copied-workspace approach.
  Date/Author: 2026-06-04 / Codex

## Outcomes & Retrospective

Milestone 1 is implemented, and Milestone 2 now has a real execution path. The repository now has a manifest schema, a checked-in pinned corpus draft, a `bifrost_benchmark validate` command, a `bifrost_benchmark run` command, repo-cache preparation, a production MCP subprocess client, JSON report output, and a local end-to-end runtime test that covers all six scenarios on a committed Java repo. The remaining work is to enrich failure aggregation, add baseline comparison, broaden runtime coverage across more corpus entries, and wire the scheduled GitHub workflow.

The current corpus now exercises `get_symbol_locations` on every pinned repo and exercises `scan_usages` on most of them, using symbols validated against the real MCP server on the pinned commits. Per-scenario failure aggregation is in place, and the 100-file fast path is materially more representative now that subset workspaces preserve git metadata for `most_relevant_files`. The next milestone should shift to compare/baseline support and the scheduled workflow, with any remaining subset tuning treated as follow-up polish rather than a prerequisite.

## Context and Orientation

This repository already has the analyzer core, the MCP server, and representative integration tests, but it does not yet have a benchmark harness or a scheduled performance workflow. The important files and modules are:

`README.md` is the public source of truth for the supported language set and the currently documented binaries.

`src/analyzer/project.rs` defines `FilesystemProject`, which walks a real repository root, detects supported languages, respects `.gitignore`, and provides the `Project` abstraction used by every analyzer. The benchmark harness will use `FilesystemProject` for direct workspace construction.

`src/analyzer/workspace.rs` defines `WorkspaceAnalyzer::build`, `build_for_languages`, and storage-aware variants. This is the cold analyzer build path that should be measured directly as the warm-up scenario.

`src/searchtools.rs` defines the typed request and response structures for `search_symbols`, `get_symbol_locations`, `get_symbol_sources`, `get_summaries`, `list_symbols`, `most_relevant_files`, and `scan_usages`. The benchmark harness will not reimplement these tools; it will call them through the real MCP server.

`src/searchtools_service.rs` is the in-process tool dispatcher that maps tool names to the corresponding Rust functions. It is useful orientation because it shows the exact tool names and argument types, but the smoke harness should prefer the real stdio server path for MCP coverage.

`src/mcp_common.rs` owns the Model Context Protocol stdio loop. It implements `initialize`, `notifications/initialized`, `ping`, `tools/list`, and `tools/call`, and it normalizes path-bearing arguments before forwarding them to `SearchToolsService`.

`src/bin/bifrost.rs` is the current binary entrypoint. Its `--server searchtools` mode will be the subprocess the benchmark harness launches for MCP smoke scenarios.

`tests/bifrost_mcp_server.rs` already proves that the real server can be driven over newline-delimited JSON-RPC messages. The benchmark harness should lift that JSON-RPC helper logic into production code rather than inventing a second protocol helper from scratch.

`tests/most_relevant_files.rs` is relevant because it already demonstrates one form of pinned external-repo parity work and uses `FilesystemProject` and `WorkspaceAnalyzer` over real checked-out repository roots.

`.github/workflows/ci.yml` is the existing Rust and Python CI workflow. The new benchmark workflow should be a sibling workflow, not a large expansion of the normal CI matrix.

The sibling `brokk` repository contains `app/src/main/baseline-testing.md` and `scripts/run-treesitter-repos.sh`, which show prior art for a larger analyzer perf suite. That runner is useful as inspiration for artifact shape and operational flow, but this issue explicitly wants a much smaller and more deterministic v1. The sibling `slop-cop` repository contains `benchmark.example.toml`, which is useful precedent for a checked-in TOML manifest style.

In this plan, a "scenario" means one benchmarked unit of work such as direct workspace build, `search_symbols`, `get_symbol_locations`, `get_summaries`, or `most_relevant_files`. A "probe input" means the exact file path, symbol, or search pattern that makes a scenario deterministic for one pinned repo. A "blessed baseline" means a checked-in JSON result snapshot that the workflow compares against until a human intentionally updates it.

## Plan of Work

Milestone 1 is the corpus and manifest layer. Add a new `benchmark/` directory with `benchmark/targets.toml` as the checked-in manifest and `benchmark/README.md` as operator documentation. The manifest must define top-level run controls such as `warmup_iterations`, `measured_iterations`, `output_dir`, `repo_cache_dir`, and `required_languages`. Each `[[repos]]` entry must define `name`, `url`, `commit`, `languages`, and optional `extensions` so the harness can restrict analysis to a language subset when a repository contains more than one supported language. Each repo entry must also define the probe inputs required for any enabled scenarios: `search_patterns`, `location_symbols`, `summary_targets`, and `seed_file_paths`. The manifest loader must reject a repo that enables a scenario without the corresponding inputs. It must also reject the full manifest if the union of declared repo languages does not cover the ten supported languages from `README.md`.

The first implementation task inside this milestone is to decide the exact v1 corpus. Keep it intentionally small and CI-friendly. Prefer real repositories that are public, stable, and materially representative of their target language while still being small enough for a daily `ubuntu-latest` run. Do not copy Brokk's Chromium-sized baseline suite. The acceptance bar for corpus selection is not "famous repo"; it is "enough analyzable source to exercise the language-specific analyzer and enough deterministic probe points to make the MCP scenarios non-empty." When the corpus is chosen, pin exact commit SHAs in `benchmark/targets.toml` and record any special extension filters directly in that file.

Milestone 2 is the harness runtime. Add a new `src/benchmark/` module tree and a dedicated CLI binary in `src/bin/bifrost_benchmark.rs`. Keep the command-line parsing simple and repository-local, using the same explicit style as `src/bin/bifrost.rs` rather than introducing a large CLI dependency just for this harness. The binary should support at least `validate`, `run`, and `compare` subcommands. `validate` only parses the manifest, validates language coverage and required probe inputs, and prints a concise summary. `run` prepares the pinned repos, executes warm-up plus measured iterations, and writes one JSON report file. `compare` reads two report files and emits a machine-readable plus human-readable regression summary.

Inside `src/benchmark/`, split the work into narrow modules. `manifest.rs` should define the TOML-deserializable configuration and validation logic. `repo_cache.rs` should clone or refresh public repos into `target/benchmark-repos/<repo-name>` and check out the exact pinned commit into a detached state before each run. Use the system `git` executable through `std::process::Command` for clone, fetch, checkout, and reset operations; this keeps remote transport behavior predictable and avoids adding benchmark-specific libgit2 complexity to the runtime path. `runner.rs` should orchestrate per-repo execution, iteration loops, scenario timing, and report assembly. `mcp_session.rs` should own a minimal production JSON-RPC client for the real `bifrost --server searchtools` subprocess, based directly on the proven helpers in `tests/bifrost_mcp_server.rs`. `report.rs` should define the JSON output structs and the baseline-comparison logic.

Milestone 3 is scenario execution and validation. For each repo, the harness must first construct a `FilesystemProject` and call `WorkspaceAnalyzer::build` or `build_for_languages` directly, timing that work as the `workspace_build` scenario. If the repo entry declares `extensions` or `languages`, use `build_for_languages` so the warm-up timing matches the intended language slice. After the direct warm-up timing is captured, launch the real `bifrost` MCP server as a subprocess rooted at the checked-out repo. Initialize the session with the same `initialize` and `notifications/initialized` flow already covered by `tests/bifrost_mcp_server.rs`. Then call each configured MCP scenario over real `tools/call` requests. Record per-call elapsed milliseconds, success/failure, and a small structured assertion result that proves the response was not only well-formed JSON but also semantically non-empty. For `search_symbols`, require at least one returned file or symbol hit. For `get_symbol_locations`, require at least one location for a configured known symbol. For `get_summaries`, require that all configured targets are resolved. For `most_relevant_files`, require at least one returned related file that is not the seed itself. These assertions are the smoke-test half of the harness; they must fail fast if a regression turns a benchmark into a silent no-op.

Milestone 4 is reporting, comparison, and documentation. The JSON report should contain enough detail to compare two runs without rerunning anything: manifest path and digest, bifrost commit SHA, run timestamp, host metadata, repo metadata, scenario names, transport type (`direct` or `mcp`), raw warm-up durations, raw measured durations, computed median and mean, pass/fail, and any failure text captured from stderr or tool responses. The compare mode should treat any pass-to-fail transition as a hard regression. For timing-only comparisons, it should compare medians and mark a regression only when both the relative delta exceeds `20%` and the absolute delta exceeds `50 ms`. This dual threshold must be printed in the compare output so the workflow summary is easy to interpret.

Milestone 5 is workflow integration. Add `.github/workflows/benchmark.yml` as a separate workflow that runs only on `ubuntu-latest`, because the goal is stable longitudinal signal rather than full OS coverage. It should support `schedule` and `workflow_dispatch`. The job should install the Rust toolchain, restore the cargo cache, restore or populate `target/benchmark-repos` with `actions/cache`, build `bifrost` plus `bifrost_benchmark`, run `bifrost_benchmark validate`, then run `bifrost_benchmark run` against the checked-in manifest. The workflow should upload the generated JSON and any text summary as artifacts. It should then run `bifrost_benchmark compare` against a checked-in blessed baseline file under `benchmark/baselines/ubuntu-latest.json`. If the compare step finds regressions, the workflow must at least flag them in the job summary. It may also fail the job when `workflow_dispatch` requests strict mode, but the initial scheduled mode can be summary-first if needed to avoid noisy false reds while the first baseline is tuned.

Milestone 6 is tests. Add unit tests for manifest validation, especially missing required scenario inputs and incomplete language coverage. Add unit tests for report comparison so threshold behavior is locked down. Add integration tests that create tiny local git repositories in `tempfile::TempDir`, write language-specific files, initialize a commit, and then run the harness modules without network access. The benchmark runtime tests do not need to clone GitHub in CI; they only need to prove the manifest parser, repo cache path handling, direct warm-up timing, MCP subprocess session, and report serialization behave correctly against a local committed repository. Use local git repo paths or `file://` URLs in test manifests so the same code path exercises clone or checkout behavior without internet access.

## Concrete Steps

Work from the repository root `/Users/dave/.codex/worktrees/42b6/bifrost`.

Start by re-reading the current seams before editing:

    sed -n '1,220p' README.md
    sed -n '1,260p' src/analyzer/project.rs
    sed -n '1,260p' src/analyzer/workspace.rs
    sed -n '1,280p' src/searchtools_service.rs
    sed -n '1,320p' src/mcp_common.rs
    sed -n '1,220p' src/bin/bifrost.rs
    sed -n '1,240p' tests/bifrost_mcp_server.rs

Create the new benchmark files and modules:

    mkdir -p benchmark benchmark/baselines src/benchmark src/bin

Implement and validate the manifest layer first:

    cargo test benchmark_manifest

Once the loader exists, validate the checked-in corpus without running benchmarks:

    cargo run --bin bifrost_benchmark -- validate --manifest benchmark/targets.toml

Expected output should mention the repo count and the full language union. A concise example is:

    validated 10 repos
    covered languages: java, javascript, typescript, rust, go, python, cpp, csharp, php, scala

Run a narrow local benchmark on one repo while iterating on the harness:

    cargo run --bin bifrost_benchmark -- run --manifest benchmark/targets.toml --repo <repo-name> --output benchmark-output/local

Expected output should mention one direct warm-up scenario plus the configured MCP smoke scenarios and the JSON report path. A concise example is:

    repo gin-go
      workspace_build: ok median=412 ms
      search_symbols: ok median=37 ms
      get_symbol_locations: ok median=18 ms
      get_summaries: ok median=44 ms
      most_relevant_files: ok median=29 ms
    wrote benchmark-output/local/run-2026-06-04T11-30-00Z.json

For faster harness iteration, the same command can trim the checked-out workspace to a deterministic subset:

    cargo run --bin bifrost_benchmark -- run \
      --manifest benchmark/targets.toml \
      --repo gin-go \
      --max-files 100

Expected output should state that subset mode is active and print the subset workspace path alongside the scenario timings.

Compare a candidate report against the blessed baseline:

    cargo run --bin bifrost_benchmark -- compare \
      --baseline benchmark/baselines/ubuntu-latest.json \
      --candidate benchmark-output/local/run-2026-06-04T11-30-00Z.json

Expected output should explicitly label regressions, improvements, and unchanged scenarios. A concise example is:

    no regressions over threshold
    compared 50 scenarios
    threshold: 20% and 50 ms absolute floor

Before finishing implementation, run the standard repository checks:

    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings
    cargo test

After the workflow file exists, verify its YAML locally by inspection and then rely on GitHub Actions for live execution:

    sed -n '1,260p' .github/workflows/benchmark.yml

## Validation and Acceptance

The feature is complete only when all of the following are true.

First, `cargo run --bin bifrost_benchmark -- validate --manifest benchmark/targets.toml` succeeds and confirms that the manifest covers every language from `README.md`. If one language is missing, validation must fail with an explicit message naming that language.

Second, `cargo run --bin bifrost_benchmark -- run --manifest benchmark/targets.toml --repo <repo-name>` succeeds for at least one configured repo and writes a JSON report containing direct warm-up timings plus MCP scenario timings. The JSON must include pass/fail data and raw measured durations per scenario, not only a human-readable summary.

Third, the MCP smoke portion must use the real `bifrost` server. A broken `tools/list`, `initialize`, path normalization rule, or `tools/call` implementation must cause the harness to fail. Successful harness runs must therefore demonstrate that the benchmark is exercising `src/bin/bifrost.rs` and `src/mcp_common.rs`, not only library calls.

Fourth, `cargo run --bin bifrost_benchmark -- compare --baseline ... --candidate ...` must detect at least these cases correctly in tests: unchanged scenarios, slowed scenarios below threshold, slowed scenarios above threshold, and pass-to-fail regressions.

Fifth, `.github/workflows/benchmark.yml` must exist and be configured for both `schedule` and `workflow_dispatch`. The workflow must upload the generated report artifact and publish a summary that is sufficient to decide whether Brokk's older daily analyzer perf cron can be retired.

Sixth, the repository checks must stay green:

    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings
    cargo test

## Idempotence and Recovery

The benchmark harness must be safe to rerun repeatedly. The repo cache under `target/benchmark-repos` is intentionally reusable; rerunning `run` should fetch and reset each configured repo back to its pinned commit instead of accumulating drift. The report output directory should create timestamped files rather than overwriting the blessed baseline automatically.

If a clone or fetch fails because a remote repo is temporarily unavailable, the harness should fail that repo explicitly and continue only if a `--keep-going` mode is later added. The initial implementation may stop on first failure, but it must name the failing repo and git command clearly enough that the operator can retry.

If a benchmark scenario starts returning empty data after an analyzer change, that is a real smoke failure, not a case for silent fallback. The right recovery path is to inspect whether the analyzer regressed or whether the manifest probe input is no longer stable for that pinned commit, then update the code or manifest intentionally.

If the baseline becomes outdated after an intentional performance improvement or a deliberate scenario change, regenerate it with `run`, review the diff, and update `benchmark/baselines/ubuntu-latest.json` in the same change that justifies the new baseline. The workflow must never rewrite the blessed baseline on its own.

## Artifacts and Notes

The intended manifest shape is:

    warmup_iterations = 1
    measured_iterations = 3
    output_dir = "benchmark-output"
    repo_cache_dir = "target/benchmark-repos"
    required_languages = [
      "java", "javascript", "typescript", "rust", "go",
      "python", "cpp", "csharp", "php", "scala"
    ]

    [[repos]]
    name = "gin-go"
    url = "https://github.com/gin-gonic/gin"
    commit = "<exact sha>"
    languages = ["go"]
    extensions = ["go"]
    scenarios = ["workspace_build", "search_symbols", "get_symbol_locations", "get_summaries", "most_relevant_files"]
    search_patterns = ["Engine"]
    location_symbols = ["gin.New"]
    summary_targets = ["gin.go"]
    seed_file_paths = ["gin.go"]

This shape matters because it keeps the smoke inputs explicit and reviewable. A future contributor should be able to answer "what exactly are we timing for Scala?" by reading the manifest rather than reverse-engineering runtime heuristics.

The intended report shape is:

    {
      "bifrost_commit": "<current sha>",
      "manifest_path": "benchmark/targets.toml",
      "repos": [
        {
          "name": "gin-go",
          "commit": "<pinned sha>",
          "scenarios": [
            {
              "name": "workspace_build",
              "transport": "direct",
              "success": true,
              "warmup_durations_ms": [401.2],
              "measured_durations_ms": [412.9, 409.1, 414.0],
              "median_ms": 412.9
            }
          ]
        }
      ]
    }

This shape is intentionally small. It is enough to compare runs later without inheriting the much larger metrics surface from Brokk's JVM-focused baseline runner.

## Interfaces and Dependencies

In `src/benchmark/manifest.rs`, define serde-backed configuration structs for the top-level manifest and repo entries. Validation must exist as Rust methods, not only as ad hoc checks in the binary, so tests can exercise the rules directly.

In `src/benchmark/report.rs`, define stable serializable result structs for one full run, one repo, one scenario, and one compare result. The compare result must include per-scenario status plus an overall `has_regressions` boolean so the workflow can gate on it without scraping text.

In `src/benchmark/mcp_session.rs`, define a minimal helper around `std::process::Child` that can:

    start(root: &Path) -> Result<McpSession, String>
    initialize(&mut self) -> Result<(), String>
    call_tool(&mut self, name: &str, arguments: serde_json::Value) -> Result<serde_json::Value, String>

This helper should be a productionized extraction of the proven approach in `tests/bifrost_mcp_server.rs`.

In `src/benchmark/runner.rs`, define a runner entrypoint similar to:

    pub fn run_benchmark(config: &BenchmarkManifest, selection: RunSelection) -> Result<BenchmarkRunReport, String>

`RunSelection` should allow "all repos" or one named repo so local iteration does not require the full corpus every time.

In `src/bin/bifrost_benchmark.rs`, provide the thin CLI wrapper that parses arguments, calls `validate`, `run`, or `compare`, prints a concise human summary, and writes JSON files.

Revision note: initial ExecPlan draft created on 2026-06-04 after reading issue `#170`, local planning rules, current analyzer/MCP code, existing workflows, and sibling Brokk/SlopCop benchmark precedents. Updated later on 2026-06-04 after implementing Milestone 1, adding `scan_usages` to the required scenario set, and building the first runnable `bifrost_benchmark run` path so the progress log, discoveries, decisions, and retrospective reflect the checked-in runtime slice as well as the manifest layer.
