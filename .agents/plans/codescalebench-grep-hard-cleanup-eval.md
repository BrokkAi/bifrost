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

## Outcomes & Retrospective

The cleanup and new evaluation are in progress. The previous symbol and NLP results must not support product conclusions.

## Context and Orientation

The Bifrost worktree is `/mnt/optane/bifrost-nlp`. It stores this plan and provides the release Bifrost binary. The Brokkbench harness is `/home/jonathan/Projects/brokkbench`. Its `codescalebench_agent_engine.py` discovers tasks, runs task containers, and parses verifier results. Its `cimeval/remote/run_task.sh` writes the Mjolnir and Anvil configuration inside each task container. The CodeScaleBench checkout is `/home/jonathan/Projects/CodeScaleBench`. The 67-task selection is `grep_hard/suite_final.jsonl`. Task definitions live below `benchmarks/csb/`.

A completion outcome means the agent and verifier completed normally. It is not a solve. Composite score is the weighted task score from zero through one. A format failure means the agent found useful code but its artifact did not match the required shape. A repository-alias failure means the answer used an equivalent repository name that the scorer did not recognize. A localization failure means the scorer received a valid, normalized artifact that omitted required code.

The shovel-ready subset contains tasks whose images exist and whose exact source revisions and Bifrost vectors are already available. This restriction prevents image builds or new embeddings from changing the tool comparison.

## Plan of Work

First, build a machine-readable audit for all 67 tasks. Read each task instruction, `task.toml`, answer parser, oracle, and verifier. Record the required output path, accepted schema, repository names, and score components. Detect inconsistent answer schemas and repository aliases. Reuse existing bare outputs where possible to determine whether each zero came from formatting, aliasing, missing output, or incorrect localization.

Next, correct the dataset and scorers. Use one canonical answer contract where task families permit it. Preserve task-specific semantic fields only when their oracle requires them. Canonicalize repository names through explicit task repository mappings. Do not accept arbitrary suffix matches. Add behavior tests with equivalent valid aliases and realistic invalid near-misses. Change reports to call normal execution `COMPLETED`, not `SUCCESS`.

Then, rescore existing outputs. This step measures how much the cleanup changes results without spending model tokens. Run a fresh Bifrost-free Luna maximum baseline across all 67 tasks. Use concurrency 10 because these task containers contain large repositories. Use a 1,800-second task limit. Define the hard set from corrected composite scores and diagnostic categories. A task is eligible only when its low score comes from localization, not output or scorer failure.

After baseline selection, fix `run_task.sh`. Generate the Bifrost MCP argument array from the named workspace specifications. Do not leave a placeholder for another component to expand. Add an end-to-end test that starts Bifrost, lists its tools, and calls one symbol tool against a small repository. Unit tests must not assert command text without executing the user-visible contract.

Run one selected task with symbols. Inspect stderr, the first LLM tool schema, Bifrost startup timing, and at least one tool result. If Bifrost fails or exceeds 120 seconds, stop the batch. Profile and correct the exact path. Repeat the one-task gate until it passes. Then run the complete shovel-ready hard subset with symbols.

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
