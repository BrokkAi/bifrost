# Run a three-arm CodeScaleBench localization comparison

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` current.

Maintain this document under `.agents/PLANS.md` from the Bifrost repository root.

## Purpose / Big Picture

This work compares three tool configurations on the same 20 CodeScaleBench tasks. The first configuration uses only Mjolnir and Anvil. The second adds Bifrost symbol tools. The third adds Bifrost semantic search with DW10 embeddings. The final report will show task results, tool calls, tokens, and LLM request time for each configuration.

The campaign must also find Bifrost performance failures. A Bifrost startup or query that exceeds 120 seconds is a failure. Stop that arm, profile the request, correct the root cause, and restart the affected work.

## Progress

- [x] (2026-08-05 18:06Z) Confirmed the 20-task panel, 120-second slow limit, and existing trace data.
- [x] (2026-08-05 18:23Z) Added explicit `bare`, `symbols`, and `symbols-nlp` CodeScaleBench modes.
- [x] (2026-08-05 18:23Z) Added tool-call and main or utility LLM timing metrics.
- [x] (2026-08-05 18:26Z) Passed 49 focused tests, Ruff, Bash syntax, and diff checks.
- [x] (2026-08-05 18:30Z) Committed the Brokkbench harness as `9e506113c85`.
- [x] (2026-08-05 18:44Z) Built runtime R2 with multi-workspace Mjolnir commit `1e976c0`.
- [x] (2026-08-05 19:00Z) Ran the bare arm at concurrency 10.
- [x] (2026-08-05 19:14Z) Ran the symbol arm at concurrency 10.
- [x] (2026-08-05 19:20Z) Stopped the first NLP arm after Camel preflight exceeded 120 seconds.
- [x] (2026-08-05 19:33Z) Profiled the exact path and added host analysis mounts with trusted-prewarm selection.
- [x] (2026-08-05 19:55Z) Restarted and completed the symbol and NLP arm at concurrency 10.
- [x] (2026-08-05 19:58Z) Generated the paired JSON and Markdown reports.

## Surprises & Discoveries

- Observation: The current CodeScaleBench `baseline` mode already starts Bifrost with symbol tools.
  Evidence: `cimeval/remote/run_task.sh` maps `baseline` to `--mcp symbol`.
- Observation: The semantic trace records utility request start and completion events.
  Evidence: `semantic_search_phase` rows contain `utility_request_start`, `utility_request_complete`, and timestamps.
- Observation: Bifrost now owns versioned database names, but the harness expected `bifrost_cache.db`.
  Evidence: The shared cache contains `bifrost_cache.v15.db`; the harness now selects the highest schema version.
- Observation: The first runtime used the old Mjolnir campaign worktree.
  Evidence: All first-wave tasks exited with `unexpected argument '--workspace'`; no LLM request started.
- Observation: The bare arm completed with no timeout or infrastructure failure.
  Evidence: It produced 20 results, with mean score 0.168235 and 44,048,572 combined tokens.
- Observation: Luna did not call a Bifrost tool in the symbol arm.
  Evidence: Its 3,025 tool calls used only Anvil file, grep, shell, edit, and write tools.
- Observation: The first NLP preflight repeated warm-cache setup inside the task overlay.
  Evidence: Camel took 156.6 seconds there, although it had no missing vectors.
- Observation: A direct host profile completed Camel in 64.8 seconds.
  Evidence: Workspace construction took 48.8 seconds. Active SQL and maps took 9.0 seconds.
- Observation: A read-only host bind reduced the in-container Bifrost profile to 100.8 seconds.
  Evidence: The profile found 24,559 indexed files, zero hashed files, and zero extraction work.

## Decision Log

- Decision: Add new CodeScaleBench modes without changing old CIM arm names.
  Rationale: CIM uses the shared runner, and its baseline must keep its present meaning.
  Date/Author: 2026-08-05 / Codex
- Decision: Count agent-visible tool calls from `tool_timing` events.
  Rationale: These events represent completed tool calls without duplicate stream updates.
  Date/Author: 2026-08-05 / Codex
- Decision: Report main and utility LLM metrics separately and together.
  Rationale: Semantic reranking is part of the requested NLP cost and time.
  Date/Author: 2026-08-05 / Codex
- Decision: Use one seed, Luna maximum reasoning, a 1,800-second task limit, and concurrency 10.
  Rationale: These settings continue the current CodeScaleBench campaign and keep the three arms paired.
  Date/Author: 2026-08-05 / Codex
- Decision: Discard the first bare run and build Mjolnir from `/mnt/optane/mjolnir-bifrost-multi-workspace`.
  Rationale: Commit `1e976c0` owns the named workspace option required by the harness.
  Date/Author: 2026-08-05 / Codex
- Decision: Keep the task image workspace unchanged and give Bifrost separate read-only host clone mounts.
  Rationale: The verifier keeps its normal image. Bifrost avoids slow overlay traversal and uses the prewarmed repository identity.
  Date/Author: 2026-08-05 / Codex
- Decision: Require an explicit trusted-prewarm option to skip semantic container preflight.
  Rationale: The campaign already warmed the exact commits. Repeating full setup adds cost without validation value.
  Date/Author: 2026-08-05 / Codex

## Outcomes & Retrospective

The bare arm had 15 successful completions, four test failures, and one agent failure. Its mean score was 0.168235.

The symbol arm had 14 successful completions, four test failures, and two agent failures. Its mean score was 0.150645. Luna made no Bifrost calls, so this arm measured tool availability without tool use.

The NLP arm had 16 successful completions, three test failures, and one agent failure. Its mean score was 0.158905.

The paired mean changes were -0.0176 for symbols against bare, -0.0093 for NLP against bare, and +0.0083 for NLP against symbols. No Bifrost arm called a Bifrost tool. The score changes therefore measure run variance and tool availability. They do not measure Bifrost localization value.

The final reports are `/mnt/containers/code_isnt_memory/codescale-three-arm-luna-max-20-20260805/report.json` and `report.md`.

## Context and Orientation

The Bifrost repository is `/mnt/optane/bifrost-nlp`. The evaluation harness is `/home/jonathan/Projects/brokkbench`. Its `codescalebench_agent_engine.py` prepares containers and writes result JSON. Its `bpr_agent.py` defines command-line modes. Its `cimeval/remote/run_task.sh` writes the Mjolnir configuration inside each task container.

An arm is one tool configuration. A tool call is one call that the agent can see. A semantic query run is one query inside a possibly multi-query `semantic_search` call. LLM request time is the sum of request durations. Concurrent utility requests therefore contribute their separate durations.

The selected model is `bedrock::openai.gpt-5.6-luna` with maximum reasoning. The semantic utility model is `deepseek::deepseek-v4-flash`. The semantic arm uses the `semantic-coedit-2-1` retrieval profile and the shared schema-v15 DW10 cache.

## Plan of Work

First, change the Brokkbench mode model. Add `bare`, `symbols`, and `symbols-nlp`. Keep old modes working. Make the runner omit the Bifrost MCP server in bare mode. Give symbol mode only symbol tools. Give NLP mode symbol tools plus `semantic_search`. Bind the shared cache for both Bifrost modes, but start the embedding service only for NLP.

Next, parse trace events into result metrics. Count `tool_timing` events by tool and success state. Pair main `llm_request` events with `llm_response` or `llm_error` events. Pair semantic utility start and completion events by call and query. Store counts, cumulative milliseconds, and distributions needed for the final report. Keep token usage by model, and add combined token totals that include the utility model.

Then, test the behavior. Tests must prove that bare mode has no Bifrost server, symbol mode cannot call semantic search, and NLP mode can call it. Trace fixtures must prove the tool and LLM metric calculations.

Finally, build one runtime bundle. Run all 20 tasks in each arm at concurrency 10 and in the required order. Use a new result directory for each arm. Monitor active traces. Stop an arm when a Bifrost startup or query reaches 120 seconds. Profile and correct the exact slow path. Restart affected arms with a new runtime identity and result directory.

## Concrete Steps

In `/home/jonathan/Projects/brokkbench`, edit the harness files with `apply_patch`. Then run:

    PYTHONPATH=. uv run pytest tests/test_codescalebench_agent_engine.py cimeval/test_manifest.py
    uv run ruff check --config pyproject.toml bpr_agent.py codescalebench_agent_engine.py tests/test_codescalebench_agent_engine.py

Commit only the changed harness files. Build the runtime with the existing CodeScaleBench runtime builder. Record repository commits in its manifest.

Run each arm with `--threads 10`, `--launch-threads 10`, `--runs 1`, `--codescale-agent-timeout 1800`, and the fixed 20 task identifiers. Use `bedrock::openai.gpt-5.6-luna+max`.

## Validation and Acceptance

The focused tests must pass. Ruff must report no errors.

Each completed task result must contain its outcome, reward, tool metrics, token metrics, and LLM request metrics. Bare results must contain no Bifrost tool calls. Symbol results must contain no semantic search calls. NLP results must include utility usage when semantic search runs.

The final paired report must contain 20 task rows and one aggregate row per arm. It must show all failure classes. It must show tool counts, tokens, main request time, utility request time, and total request time.

## Idempotence and Recovery

Never mix results from different runtime bundles. Keep stopped runs for diagnosis. Use a new result directory after each fix. Reuse completed earlier arms only when the fix cannot affect their tools or agent runtime.

The Brokkbench worktree contains unrelated user changes. Stage files by exact path. Do not use `git add -A`.

## Artifacts and Notes

Store large campaign artifacts under `/mnt/containers/code_isnt_memory/`. Store the paired final report beside the three result directories.

## Interfaces and Dependencies

`bpr_agent.py` must accept the three new mode names. `codescalebench_agent_engine.py` must map each mode to its required cache and embedding resources. Its result JSON must add stable `toolCalls`, `llmRequests`, and combined token fields. `cimeval/remote/run_task.sh` must accept the new remote arm names without changing existing names.

Revision note: Completed after all three arms and the paired report.
