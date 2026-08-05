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
- [ ] Make a checkpoint commit with only this campaign's files.
- [ ] Build one recorded runtime bundle for the campaign.
- [ ] Run the bare arm at concurrency 10.
- [ ] Run the symbol arm at concurrency 10.
- [ ] Run the symbol and NLP arm at concurrency 10.
- [ ] Compare the paired results and complete this plan.

## Surprises & Discoveries

- Observation: The current CodeScaleBench `baseline` mode already starts Bifrost with symbol tools.
  Evidence: `cimeval/remote/run_task.sh` maps `baseline` to `--mcp symbol`.
- Observation: The semantic trace records utility request start and completion events.
  Evidence: `semantic_search_phase` rows contain `utility_request_start`, `utility_request_complete`, and timestamps.
- Observation: Bifrost now owns versioned database names, but the harness expected `bifrost_cache.db`.
  Evidence: The shared cache contains `bifrost_cache.v15.db`; the harness now selects the highest schema version.

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

## Outcomes & Retrospective

No arm has run under the new configuration yet.

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

Revision note: Updated after harness implementation. It records the versioned cache discovery and focused validation result.
