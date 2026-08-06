# CodeScaleBench grep-hard checkpoint (2026-08-06)

## Objective

Evaluate the cleaned CodeScaleBench `grep_hard` localization set with three arms:

1. Bare mj/anvil, with no Bifrost.
2. Bifrost symbol tools, with no NLP.
3. Bifrost symbols plus semantic search.

The working plan is [codescalebench-grep-hard-cleanup-eval.md](../plans/codescalebench-grep-hard-cleanup-eval.md).

## Dataset and baseline

- The source suite had 67 rows.
- 64 rows passed validation and are the current evaluation population.
- Three invalid records were excluded.
- The current paired manifest has 14 shovel-ready tasks:
  `.agents/docs/codescale-grep-hard-luna-max-r3-shovel14.tasks`.
- The older seven-task manifest is an obsolete cache-ready subset.
- The corrected baseline rescore reported 39 scorable tasks, 25 invalid tasks, and 2 solves.

## External prewarm

- Host-only DW10 prewarm completed sequentially for all 14 paired tasks.
- No task container performed prewarm.
- Shared cache: `/mnt/T9/repo-clones/.codescale-cache-dw10/bifrost_cache.v15.db`.
- Runtime bundle: `/mnt/containers/code_isnt_memory/codescale-grep-hard-cleanup-20260805/runtime-r25/runtime.tgz`.
- The embedding sidecar uses the DW10 artifact and listens on `127.0.0.1:18765`.

## Bifrost changes

Commit `a9b33e65` (`Batch active symbol scans across languages`) contains:

- One SQL query for active symbol candidates across all requested languages.
- A regression test for mixed Java and Rust scans.
- A `get_summaries` description that warns against a repository root or broad source tree in large repositories.

Validation passed:

- `cargo fmt --all`
- `cargo check -p brokk-bifrost-analysis`
- The focused active-symbol regression test
- Release NLP build: `cargo build --release -p brokk-bifrost --features nlp`

## Performance findings

Firefox has about 401,804 tracked files and a 4.2 GB tree.

- Before the SQL change, a broad six-pattern `search_symbols` call took about 83-132 seconds.
- After the change, a single-task run took 102.6 seconds end to end.
- Bifrost profile time was about 54.6 seconds for resolution, 34.0 seconds for ranking, and 0.8 seconds for rendering.
- The first broad `get_summaries` request still took 126.98 seconds. The model first requested `/`; the new description discourages that request. This path needs a separate fix if it remains a gate.
- Candidate snapshot setup is separate from Bifrost. A Firefox `git add -A -- .` over the 4.2 GB tree took about 3-4 minutes.

## Current evaluation

The symbols arm was relaunched with runtime-r25, concurrency 10, and an 1800-second agent timeout. It uses the 14-task manifest above and the shared DW10 cache.

The first completed task was `ccx-incident-034`. It reached `TESTS_FAILED`, not a Bifrost startup failure. Its Bifrost calls were normal: summaries 1.3 seconds, symbol search 7-8 seconds, and symbol sources up to 2.7 seconds. Its recorded cost was about `$0.0213`.

At this checkpoint, only that task has a completed archive. The remaining symbols tasks are pending or running. The symbols-plus-NLP arm has not started.

## Next actions

1. Check the symbols driver and let the 14-task arm finish.
2. Record success, failure, tool-call, token, and timing data.
3. Launch the symbols-plus-NLP arm with the same manifest and concurrency.
4. Investigate or fix broad `get_summaries` latency before treating it as a Bifrost performance result.

