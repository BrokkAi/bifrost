# Clean and evaluate the CodeScaleBench grep-hard set

This ExecPlan is a living document. Maintain it according to `.agents/PLANS.md` in the Bifrost repository.

## Purpose / Big Picture

This work will produce a valid CodeScaleBench comparison for Bifrost symbol and semantic tools. The current 67-task `grep_hard` list has scoring and output-contract problems. The prior Bifrost arms are invalid because every Bifrost MCP server failed before it exposed tools. After this work, the dataset will score equivalent repository names and valid answer shapes consistently. A Bifrost-free Luna run will identify tasks that remain difficult with grep. The same shovel-ready tasks will then run with symbols and with symbols plus NLP. Each Bifrost arm must prove that Bifrost started and returned valid tool results.

If Luna does not use semantic search often enough, the final NLP arm will add a synthetic step zero. A small query model will produce only necessary initial queries. The harness will run those queries before Luna starts. Luna will not see the query-model turn, but it will receive the semantic results.

## Progress

- [x] (2026-08-05 20:10Z) Confirmed that `grep_hard/suite_final.jsonl` contains 67 unique tasks.
- [x] (2026-08-05 20:10Z) Confirmed that prior `SUCCESS` counts measured completion, not task solves.
- [x] (2026-08-05 20:10Z) Confirmed that all 40 prior Bifrost sessions disabled Bifrost because of a literal workspace placeholder.
- [x] (2026-08-05 21:33Z) Audited all 67 candidates against all 31 exact source revisions.
- [x] (2026-08-05 21:20Z) Added a 67-row canonical audit and scorer in Brokkbench commit `3d1402548b0`.
- [x] (2026-08-05 21:33Z) Added canonical scoring, output-contract repair, source validation, and 0.8 solve reporting.
- [x] (2026-08-05 21:45Z) Rescored reusable outputs and separated invalid output from localization scores.
- [x] (2026-08-05 22:31Z) Ran all 64 valid tasks without Bifrost at concurrency 10 and a 1,800-second task limit.
- [x] (2026-08-05 22:34Z) Selected 20 high-scoring baseline failures with ready sources and cache data.
- [x] (2026-08-05 22:43Z) Fixed Bifrost MCP workspace arguments and proved symbol calls in one end-to-end task.
- [x] (2026-08-06 00:31Z) Replaced the false 20-task cache set with 11 valid baseline failures and prewarmed all 11 against schema 15.
- [x] (2026-08-06 00:31Z) Fixed persistent prewarm, ordered active membership, one-pass active chunk loading, and canonical container workspace paths.
- [x] (2026-08-06 01:03Z) Stopped the first corrected symbol arm after a warm Kafka symbol call waited 71 seconds.
- [x] (2026-08-06 01:20Z) Grouped generator rules by language, moved trigger tests before enclosing-symbol lookup, and evaluated files in parallel.
- [x] (2026-08-06 01:22Z) Added shipped semantic-model activation to the CodeScale prewarm profiler.
- [x] (2026-08-06 01:47Z) Refreshed all 11 paired tasks with schema-3 readiness records for the current profiler.
- [x] (2026-08-06 01:55Z) Stopped the second symbol arm after one source call took 92 seconds and three exceeded two minutes.
- [x] (2026-08-06 02:05Z) Routed structured suffix lookup through the indexed terminal identifier before its table-scan fallback.
- [x] (2026-08-06 02:13Z) Built runtime r9 and started the corrected symbol arm.
- [x] (2026-08-06 02:16Z) Stopped runtime r9 after the paired-set audit found invalid baseline evidence.
- [x] (2026-08-06 02:25Z) Made answer-contract errors unscorable and selected 20 valid empirical Luna grep near-misses.
- [x] (2026-08-06 03:05Z) Removed OpenJDK from the paired set after its cold generated-file parse tail exceeded 35 minutes.
- [x] (2026-08-06 03:45Z) Filed Bifrost issue #1690 and bounded each complete-file tree-sitter parse to ten seconds.
- [ ] Prewarm the replacement 20-task set and restart the corrected symbol arm.
- [ ] (2026-08-05 23:25Z) Run the selected tasks with symbol tools. The first 20-task arm stopped after a linked-worktree fault and a false cache-readiness assumption.
- [ ] Run the same tasks with symbol and NLP tools.
- [ ] Add synthetic semantic step zero if natural semantic use is too low.
- [ ] Produce a paired report and complete the requirement audit.

## Surprises & Discoveries

- Observation: The prior report called 15 bare-arm tasks successful, but no task scored 1.0.
  Evidence: The bare score distribution has 11 zeros, three scores of at least 0.5, and a maximum of 0.8889.
- Observation: The prior Bifrost comparison did not expose Bifrost tools.
  Evidence: Every Bifrost-arm stderr contains `Unknown argument: {bifrost_workspace_args}` and then disables the MCP server.
- Observation: The test suite required the broken literal placeholder.
  Evidence: `cimeval/test_manifest.py` asserts that the generated setup contains `{bifrost_workspace_args}` instead of starting and calling Bifrost.
- Observation: The CodeScaleBench checkout has only the `public` branch, and `grep_hard/` is untracked.
  Evidence: `git branch -a` lists only `public` and `origin/public`; `git status` reports `?? grep_hard/`.
- Observation: The selection and live verifier use different oracle files.
  Evidence: The selection records cite `ground_truth.json`, while `eval.sh` scores `task_spec.json`; 48 of 67 canonical file counts differ.
- Observation: Two candidates are not localization tasks.
  Evidence: `django-rate-limit-design-001` requires code changes, and `elasticsearch-shard-alloc-design-001` requires a new design.
- Observation: Six architecture tasks require `answer.json` in their instructions but do not declare artifact verification.
  Evidence: Their task configuration omits `verification_modes = ["artifact"]`, so Brokkbench collects the wrong output path.
- Observation: One candidate requests a repository that its task does not provide.
  Evidence: `ccx-dep-trace-116` requires `kubernetes/apimachinery`, but its Dockerfile provides Kubernetes, client-go, api, and etcd only.
- Observation: The corrected old bare outputs do not show 15 solves.
  Evidence: One of 11 scorable outputs reaches the documented 0.8 threshold. Five outputs used the wrong contract, and three candidates are invalid.
- Observation: The complete source audit leaves 64 runnable localization candidates.
  Evidence: All canonical files exist at their exact revisions. The audit excludes two non-localization tasks and `ccx-dep-trace-116`, whose required repository is absent.
- Observation: The corrected baseline is hard for Luna with grep and workspace tools.
  Evidence: Luna passed 2 of 64 tasks. The 58 scorable outputs had a 0.4132 mean and a 0.4676 median composite score. Six tasks produced no valid `answer.json`.
- Observation: The symbol smoke test started Bifrost in seconds and improved the selected task.
  Evidence: `ccx-dep-trace-273` improved from 0.7727 to 0.8081. Luna completed one `get_summaries` call and one `search_symbols` call.
- Observation: The first selected set did not satisfy the cache-ready requirement.
  Evidence: OpenJDK had no readiness record. Its first analyzer call failed because libgit2 could not resolve a moved worktree back-pointer. After that fix, cold setup exceeded 120 seconds.
- Observation: The old readiness records name the unversioned schema-14 database, not the active schema-15 database.
  Evidence: Grafana took about 154 seconds to fill missing analyzer rows in schema 15. Its next analyzer build took 1.23 seconds.
- Observation: Semantic membership order caused most of the corrected prewarm delay.
  Evidence: Django exceeded five minutes before ordered lookup. It completed in 10.8 seconds after `(blob_oid, rel_path)` sorting. Semantic membership took 3.2 milliseconds.
- Observation: The semantic profiler did not prewarm the persistent analyzer cache.
  Evidence: Each short-lived container wrote about 1.4 GB to a temporary analyzer database and deleted it. The profiler now uses `build_persisted`.
- Observation: Active semantic setup repeated random reads from the 28 GB shared database.
  Evidence: The temporary membership table used path order, while the persistent chunk key uses `(blob_oid, rel_path)`. The active table now uses the same key and reads each active chunk once.
- Observation: Canonical task containers gave Bifrost a path alias that Git did not use.
  Evidence: Django had 2,887 Python files, but Bifrost reported zero analyzed files at `/opt/work/analysis`. The canonical self-bind reports 2,997 analyzed files and reaches semantic readiness in 11.5 seconds.
- Observation: Ordinary clones did not have a full source self-bind at their canonical path.
  Evidence: Kafka exposed only `.git` there. The harness now self-binds every full prepared source tree. All 11 selected tasks completed prewarm.
- Observation: Warm analyzer construction is no longer the symbol-arm startup problem.
  Evidence: A direct Kafka profile built the complete analyzer in 0.83 seconds. Built-in semantic-pack activation did not finish within 20 seconds.
- Observation: Generator-rule overlay creation traverses every structural file once for each rule and computes an enclosing code unit before it tests the rule trigger.
  Evidence: A 20-second CPU profile spent most samples in path hashing, live-source resolution, file-state hydration, and range lookup below `generated_overlay_facts`. The active built-in pack contained only six records.
- Observation: The existing CodeScale prewarm did not activate shipped semantic models.
  Evidence: It built the persisted analyzer and semantic vector index directly. The first symbol request had to create Scala structural snapshots for the shipped case-class model.
- Observation: Parallel, grouped activation meets the warm interactive limit after structural snapshots exist.
  Evidence: On Kafka with six Rayon threads, the analyzer took 0.75 seconds, semantic-pack activation took 2.15 seconds, and `search_symbols` took 0.44 seconds. Total first-call latency was 3.55 seconds.
- Observation: A near-canonical Go receiver selector entered a full-table substring scan.
  Evidence: `get_symbol_sources` took 92.0 seconds for one call. Timing showed `suffix_resolution.pattern_stage`, and a CPU profile stayed inside SQLite. The persisted row had short name `Replica.handleRaftReady` and indexed identifier `handleRaftReady`.
- Observation: The indexed terminal lookup removes the pathological fallback.
  Evidence: The exact three-symbol CockroachDB reproduction fell from more than 90 seconds to 4.55 seconds, including 0.96 seconds of process startup.
- Observation: The old corrected baseline still called contract-breaking answers scorable.
  Evidence: Only 37 of 64 outputs are valid grep failures. Two are solves, six are missing, and nineteen have answer-contract errors.
- Observation: The reported 15 of 20 result was a completion count, not a solve count.
  Evidence: The corrected Luna maximum baseline has only two solves across all 64 tasks. Every task called `grep_search`.
- Observation: The `grep_hard` source list came from manual task and oracle review.
  Evidence: Its `selection_basis` fields cite behavioral instructions and dispersed oracles. They do not cite a measured grep baseline.
- Observation: OpenJDK is not shovel-ready with the current analyzer cache.
  Evidence: Its prewarm wrote about 40 GB, then spent more than 35 minutes on one CPU core in tree-sitter. The largest Java files are generated-style tables and field fixtures. The run stopped before agent execution.
- Observation: LLVM has the same unbounded parse-tail class.
  Evidence: Its prewarm also entered a low-parallelism tree-sitter tail after ordinary files finished. The run stopped before agent execution.

## Decision Log

- Decision: Use composite verifier score to define task difficulty. Do not use harness completion status.
  Rationale: Completion only shows that the agent produced an artifact and the verifier ran.
  Date/Author: 2026-08-05 / Codex
- Decision: Separate format failures, repository-alias failures, and localization failures during the audit.
  Rationale: Only localization failures provide evidence that grep is insufficient.
  Date/Author: 2026-08-05 / Codex
- Decision: Keep the 67-task list intact until scoring cleanup and rescoring finish.
  Rationale: Removing tasks before correcting scorer defects would hide repairable benchmark errors.
  Date/Author: 2026-08-05 / Codex
- Decision: Require an end-to-end Bifrost tool call before any new Bifrost batch.
  Rationale: Configuration assertions did not detect the prior server-start failure.
  Date/Author: 2026-08-05 / Codex
- Decision: Use curated `ground_truth.json` as the canonical localization oracle.
  Rationale: The candidate audit used that source, and it follows the task instruction better than the stale task specification.
  Date/Author: 2026-08-05 / Codex
- Decision: Call a task solved only at canonical composite score 0.8 or more.
  Rationale: A single oracle hit is useful partial credit, not a complete solution.
  Date/Author: 2026-08-05 / Codex
- Decision: Preserve the original 67 rows in the audit, but run only the 64 validated candidates.
  Rationale: This keeps defects visible while preventing invalid tasks from consuming model tokens.
  Date/Author: 2026-08-05 / Codex
- Decision: Use the 20 highest-scoring valid baseline failures below 0.8 for paired tool tests.
  Rationale: These tasks are near enough to the solve limit to measure useful localization gains without selecting baseline passes.
  Date/Author: 2026-08-05 / Codex
- Decision: Replace the incorrect 20-task set with the 11 valid baseline failures that intersect the existing prewarm campaign.
  Rationale: Paired arms must not include cold analyzer or embedding work. The active schema-15 cache will receive a fresh readiness check before either arm runs.
  Date/Author: 2026-08-05 / Codex
- Decision: Use the prepared source's canonical absolute path inside canonical task containers.
  Rationale: Git and Bifrost must construct ProjectFile identities from the same root. An alias can make the persisted analyzer appear empty.
  Date/Author: 2026-08-06 / Codex
- Decision: Run sequential prewarm with all 60 workstation cores, then use six cores per task at concurrency 10.
  Rationale: Initial cache hydration is parallel and persistent. The paired evaluation must share the workstation without forcing each large repository onto one core.
  Date/Author: 2026-08-06 / Codex
- Decision: Group active generator rules by language and traverse each structural file once.
  Rationale: The current rule-first loop reloads a large workspace for each rule. Trigger checks can reject most nodes before the code computes an enclosing symbol.
  Date/Author: 2026-08-06 / Codex
- Decision: Evaluate independent structural files through the existing Rayon pool and preserve their sorted collection order.
  Rationale: Structural extraction and snapshot hydration are file-local. Each task gives Bifrost six cores, and indexed Rayon collection keeps deterministic output.
  Date/Author: 2026-08-06 / Codex
- Decision: Make the NLP prewarm profiler activate shipped semantic models before it starts vector indexing.
  Rationale: A readiness record must cover all persistent state required by the first symbol call, not only analyzer rows and vectors.
  Date/Author: 2026-08-06 / Codex
- Decision: Add terminal-identifier candidates to structured suffix resolution before substring search.
  Rationale: The terminal is already a parsed symbol segment and has a persistent index. The existing alias matcher remains the final authority, so the faster candidate source does not change accepted matches.
  Date/Author: 2026-08-06 / Codex
- Decision: Treat every answer-contract error as unscorable.
  Rationale: A partial score from a malformed answer cannot prove that grep did or did not solve the task.
  Date/Author: 2026-08-06 / Codex
- Decision: Define the evaluation set from measured Luna maximum grep failures.
  Rationale: Manual oracle dispersion does not prove grep difficulty. The replacement set contains the 20 highest valid scores below 0.8.
  Date/Author: 2026-08-06 / Codex
- Decision: Replace the OpenJDK near-miss with the next valid Kubernetes near-miss.
  Rationale: This campaign measures warm interactive tools. A repository with an unfinished 35-minute cold parse is not shovel-ready.
  Date/Author: 2026-08-06 / Codex
- Decision: Give each complete-file tree-sitter parse a ten-second budget and persist a minimal file-scope state after timeout.
  Rationale: One generated blob must not block workspace readiness. The stored blob marker prevents the same cold parse on later startup.
  Date/Author: 2026-08-06 / Codex

## Outcomes & Retrospective

The cleanup and new evaluation are in progress. The previous symbol and NLP results must not support product conclusions.

## Context and Orientation

The Bifrost worktree is `/mnt/optane/bifrost-nlp`. It stores this plan and provides the release Bifrost binary. The Brokkbench harness is `/home/jonathan/Projects/brokkbench`. Its `codescalebench_agent_engine.py` discovers tasks, runs task containers, and parses verifier results. Its `cimeval/remote/run_task.sh` writes the Mjolnir and Anvil configuration inside each task container. The CodeScaleBench checkout is `/home/jonathan/Projects/CodeScaleBench`. The 67-task selection is `grep_hard/suite_final.jsonl`. Task definitions live below `benchmarks/csb/`.

A completion outcome means the agent and verifier completed normally. It is not a solve. Composite score is the weighted task score from zero through one. A format failure means the agent found useful code but its artifact did not match the required shape. A repository-alias failure means the answer used an equivalent repository name that the scorer did not recognize. A localization failure means the scorer received a valid, normalized artifact that omitted required code.

The shovel-ready subset contains tasks whose images exist and whose exact source revisions and Bifrost vectors are already available. This restriction prevents image builds or new embeddings from changing the tool comparison.

The replacement paired manifest is `.agents/docs/codescale-grep-hard-luna-max-nearmiss20.tasks`. Each task has one valid Luna maximum baseline output, at least one `grep_search` call, and a canonical score below 0.8. Its scores range from 0.5522 through 0.7727. The set uses near-misses because they provide more sensitivity to localization-tool gains than arbitrary low-score failures. It excludes OpenJDK because that repository did not meet the warm-readiness requirement.

## Plan of Work

First, build a machine-readable audit for all 67 tasks. Read each task instruction, `task.toml`, answer parser, oracle, and verifier. Record the required output path, accepted schema, repository names, and score components. Detect inconsistent answer schemas and repository aliases. Reuse existing bare outputs where possible to determine whether each zero came from formatting, aliasing, missing output, or incorrect localization.

Next, correct the dataset and scorers. Use one canonical answer contract where task families permit it. Preserve task-specific semantic fields only when their oracle requires them. Canonicalize repository names through explicit task repository mappings. Do not accept arbitrary suffix matches. Add behavior tests with equivalent valid aliases and realistic invalid near-misses. Change reports to call normal execution `COMPLETED`, not `SUCCESS`.

Then, rescore existing outputs. This step measures how much the cleanup changes results without spending model tokens. Run a fresh Bifrost-free Luna maximum baseline across all 67 tasks. Use concurrency 10 because these task containers contain large repositories. Use a 1,800-second task limit. Define the hard set from corrected composite scores and diagnostic categories. A task is eligible only when its low score comes from localization, not output or scorer failure.

After baseline selection, fix `run_task.sh`. Generate the Bifrost MCP argument array from the named workspace specifications. Do not leave a placeholder for another component to expand. Add an end-to-end test that starts Bifrost, lists its tools, and calls one symbol tool against a small repository. Unit tests must not assert command text without executing the user-visible contract.

Before the paired arms, make complete-file parsing bounded. Use tree-sitter's progress callback for cancellation and a ten-second deadline. Persist a minimal file-scope state when a blob exceeds the deadline. Do not detect generated files by path or source-text patterns. See issue #1690.

Run one selected task with symbols. Inspect stderr, the first LLM tool schema, Bifrost startup timing, and at least one tool result. If Bifrost fails or exceeds 120 seconds, stop the batch. Profile and correct the exact path. Repeat the one-task gate until it passes. Then run the complete shovel-ready hard subset with symbols.

The corrected symbol smoke exposed a separate warm-path defect. In `crates/bifrost-analysis/src/analyzer/semantic_model/overlay.rs`, change `generated_overlay_facts` from a rule-first traversal to a provider-first traversal. Select all unique rules for the provider language. Load each file's structural facts once. Test rule triggers before computing the enclosing code unit. Compute that enclosing unit once for a node with one or more matching rules. Preserve rule conflict handling and emitted fact order. Reprofile Kafka with the same six-record built-in pack before the symbol arm restarts.

Run the same task set with symbols plus NLP. Count tasks and calls for `semantic_search`. Include semantic reranker requests in utility tokens, time, and cost. If natural semantic use is too sparse for comparison, add the existing CIM-style query generation and synthetic step zero only to this evaluation mode. Limit queries by necessity, not a fixed count. Deduplicate redundant queries and keep query-model turns out of Luna's history.

## Concrete Steps

In `/home/jonathan/Projects/CodeScaleBench`, inspect `grep_hard/suite_final.jsonl` and the selected task directories below `benchmarks/csb/`. Add the audit and scorer corrections in the smallest shared modules that own the behavior. Run focused task verifier tests and the repository health command.

In `/home/jonathan/Projects/brokkbench`, correct the CodeScale harness and reports. Run:

    PYTHONPATH=. uv run pytest -q tests/test_codescalebench_agent_engine.py cimeval/test_manifest.py
    RUFF_CACHE_DIR=/home/jonathan/.cache/uv/ruff-brokkbench uv run ruff check bpr_agent.py bpr_agent_engine.py codescalebench_agent_engine.py cimeval/remote/run_task.sh tests/test_codescalebench_agent_engine.py

Before a batch, run one task and inspect its archive. The first Bifrost arm is accepted only when stderr has no MCP-start error and the trace contains a completed Bifrost tool call.

Use campaign directories below `/mnt/containers/code_isnt_memory/`. Keep stopped and superseded runs for diagnosis. Never mix results from different runtime metadata.

## Validation and Acceptance

The dataset audit must contain 67 rows. The runnable manifest must contain 64 validated localization tasks. Every row must identify its answer contract, repository mapping, verifier, and current defect category. All corrected scorer tests must pass.

The fresh bare run must contain 64 result records. The hard-set manifest must exclude format failures and scorer failures. It must record the corrected score used for selection.

The symbol smoke test must prove Bifrost startup and one completed symbol call. The full symbol arm must have no MCP-start error. The NLP arm must use the identical task manifest and runtime, except for NLP enablement. Its report must include symbol calls, semantic calls, main and utility tokens, request time, cost, and paired composite scores.

Warm Kafka analyzer construction plus semantic-pack activation must complete in seconds. It must not repeat one complete structural-file pass per active generator rule. A normal `search_symbols` call must complete below the five-second product regression limit when the cache and operating-system page cache are warm.

If synthetic semantic injection is required, its trace must show the synthetic results before Luna's first turn. It must not include the query model's turn in Luna's conversation history.

## Idempotence and Recovery

Dataset audits and reports write to new versioned paths. Rerunning them must replace only derived outputs. Do not delete prior model runs. A stopped evaluation restarts in a new arm directory. Shared Bifrost cache access remains serialized for writers. Read-only task runs can share the database.

The CodeScaleBench checkout contains an untracked `grep_hard/` directory. Do not commit or push it until the audit proves the intended files and the correct repository branch is available.

## Artifacts and Notes

The invalid prior campaign is `/mnt/containers/code_isnt_memory/codescale-three-arm-luna-max-20-20260805`. Its data remains useful for bare-output rescoring and harness-failure diagnosis. Its Bifrost arms are not product evidence.

## Interfaces and Dependencies

The dataset audit will use the CodeScaleBench task loaders and verifier modules. It must not duplicate oracle scoring logic. The Brokkbench harness will keep `bare`, `symbols`, and `symbols-nlp` modes. It will add a real Bifrost startup gate and preserve separate main and utility LLM metrics.

Revision note: Created after the invalid Bifrost run. It expands the work to the complete 67-task cleanup and staged reevaluation.

Revision note: The complete audit found three invalid candidates. The execution count is now 64, while the audit still covers all 67 rows.

Revision note: The paired set now contains 11 cache-ready baseline failures. Canonical path and semantic startup faults were fixed before either paired arm.

Revision note: The corrected symbol arm exposed rule-first semantic-pack activation. The run stopped after four tasks so Bifrost can remove repeated workspace traversal before restart.

Revision note: The grouped and parallel traversal reduced warm Kafka first-call latency to 3.55 seconds. The prewarm profiler now creates the required structural snapshots before an evaluation.

Revision note: The second symbol arm stopped after issue #1688 exposed a full `code_units` substring scan for near-canonical Go receiver selectors. Indexed terminal lookup reduced the exact reproduction to 4.55 seconds including startup.

Revision note: Runtime r9 stopped before use after a new audit found that the 11-task paired set included malformed baseline answers. The replacement set uses only valid empirical Luna maximum grep failures.

Revision note: OpenJDK and LLVM exposed unbounded tree-sitter parse tails. Issue #1690 records the profiles. Bifrost now persists a minimal marker after a ten-second complete-file parse limit.
