# Evaluate dw10 with a CIM-only synthetic semantic-search step

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`,
`Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.
This document is maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

The completed Granite/dw10 campaign in `.agents/plans/bifrost-localizer-cim-eval.md`
rarely exercised `semantic_search`, so its model comparison was dominated by ordinary coding-agent
variance. This extension gives every task only the semantic searches that an independent query
generator judges clearly necessary at startup. DeepSeek V4 Flash sees the task description and
produces a variable-length query list. Anvil executes those queries as a synthetic tool-call batch
before GPT-5.6 Luna's first inference; Luna sees the queries and results but never the DeepSeek
request, response, or reasoning.

The first reportable gate is deliberately small: 91 dw10 `semantic-coedit-2-1` cells for seed 0.
It is compared with seed 0 of the existing no-semantic Bedrock/Luna baseline. Only a statistically
significant positive paired result authorizes seeds 1 and 2. A significant three-seed result then
authorizes the remaining dw10 retrieval recipes.

## Progress

- [x] (2026-08-01) Inspected SuperCoder's conditional prompt/tool guidance, Anvil's P2T forced-step
  representation, cimeval's cell runner/reporting path, and localizer query generation.
- [x] (2026-08-01) Locked the design with the user: CIM-only behavior, non-prescriptive tool
  descriptions, DSV4 Flash task-only queries, no requested query count, k=20 per query, and a
  seed-0 gate against the existing baseline.
- [x] (2026-08-01) Implemented and focused-tested Anvil's CIM mode, synthetic initial tool step,
  trace boundaries, and non-prescriptive CIM-only description hierarchy.
- [x] (2026-08-01) Implemented and unit-tested frozen cimeval query generation, identity checks,
  per-cell configuration and trace validation, synthetic/agent telemetry, and reference-run
  statistics.
- [x] (2026-08-01) Generated and froze all 91 direct-provider DSV4 Flash query records: 104
  queries total, including 53 empty task lists; manifest SHA-256
  `48b30dbce1e6f285689ff27662fcc17791450a12ae5a363447d7e44cc755aefd`.
- [x] (2026-08-01) Fixed the cross-language summary projection panic, added the ownership
  regression, and rebuilt Bifrost at `c9dec2d6`.
- [x] (2026-08-01) Built immutable runtime v3 and passed the real nonempty-query Apache Dubbo
  smoke through synthetic retrieval, max-reasoning Bedrock Luna, artifact validation, and inline
  official scoring.
- [x] (2026-08-01) Verified all 91 pinned official images in the dedicated XFS Podman store and
  taught cimeval run/score/preflight to select that store without changing agenteval.
- [ ] Run, score, localize, and audit the 91-cell dw10 seed-0 gate at concurrency 30.
- [ ] Apply the statistical decision tree, update this retrospective, and commit the result.

## Surprises & Discoveries

- Observation: SuperCoder did not rely on a neutral tool schema. Its index-enabled system prompt
  says to prefer `codebase_search`, and the tool description says `USE THIS FIRST`; the released
  evaluation reports about 1.4 engine calls per cell. Anvil's prior description merely stated what
  semantic search does.
  Evidence: `/mnt/optane/bifrost-nlp-resources/SuperCoder/crates/agent/src/agent/prompt.rs` and
  `/mnt/optane/bifrost-nlp-resources/supercoder-eval/README.md`.
- Observation: Anvil's P2T mode already represents assistant tool-call batches and tool results,
  but enabling P2T also changes the tool catalog and turn accounting. CIM must reuse the message
  shape without enabling P2T.
  Evidence: `/mnt/optane/anvil-bifrost-nlp-ft/src/p2t.rs` and `src/tool_loop.rs`.
- Observation: brokkbench's unqualified DeepSeek aliases deliberately fail over to a corresponding
  OpenRouter model when the direct provider exhausts retries. Provider qualification still entered
  that failover tier, so it did not guarantee that DSV4 Flash generated the frozen queries.
  Evidence: `client.CachingClient.ask`; provider-qualified requests now retain their selected
  provider, with a regression test, while ordinary aliases preserve their existing failover.
- Observation: Anvil's full test suite has one unrelated dynamic Bedrock-model preset failure:
  `enrichment_attaches_family_specific_presets` now observes a `max` effort from discovery where
  the fixture expects the older list ending at `xhigh`. All 1,223 other tests pass, including the
  new CIM tests, and `cargo clippy --all-targets -- -D warnings` passes.
  Evidence: full gate on 2026-08-01; no CIM code participates in model-card enrichment.
- Observation: The first real Apache Dubbo smoke failed before Luna's first request because NLP
  extraction fanned a Rust file into a Java analyzer. `summary_file_projection` derived the
  foreign `rust` storage key and indexed the Java analyzer's generation map with it, panicking in
  four Rayon workers. Full file-state hydration already refused this legitimate multi-analyzer
  fan-out; summary projection lacked the same ownership boundary.
  Evidence: task-container Anvil stderr from the interrupted smoke, with four panics at
  `tree_sitter_analyzer.rs:6957`; the trace contains a synthetic-step start and no end.
- Observation: The analyzer library gate after the ownership fix passed 1,880 tests and the new
  regression, with one environment-only failure because this host image lacks `javac` and `jar`;
  six measurement tests were ignored.
  Evidence: `cargo test -p brokk-bifrost-analysis --lib` on 2026-08-01; the sole failure explicitly
  says `Java producer parity tests require javac and jar`.
- Observation: The corrected Apache Dubbo smoke executed all three generated searches at k=20 as
  one synthetic batch before Luna's first request, completed normally, and was scored inline. It
  did not resolve the task. Luna used 556 tool executions and the whole cell took 1,099 seconds,
  including 170 seconds of scoring, so campaign tails may be long even with the 30-job scheduler.
  Evidence: completed cell `apache__dubbo-8414--semantic-coedit-2-1--seed-0` in the seed-0 run;
  runtime v3 and query identities passed cimeval's completion validation.
- Observation: The frozen image set was already complete in
  `/mnt/containers/code_isnt_memory/podman-storage`; cimeval had silently used Podman's default
  per-user graph root instead. Accidental duplicate pulls reduced the home filesystem to 2.3 GB
  free before they were stopped. Removing only unreferenced duplicate task-image tags recovered
  it to 46 GB free; no broad prune or stopped-container deletion was performed.
  Evidence: an exact task-manifest/store comparison found zero missing images in the XFS store,
  which reports 91 images. The cimeval CLI regression suite passes 45 tests and Ruff passes after
  selecting `/mnt/containers/code_isnt_memory/storage.conf` at the orchestration boundary.
- Observation: Diagnostic run r1 exposed two unnecessary shared-cache write transactions under
  30-way startup. Matching analyzer epochs always reserved SQLite's writer slot, and a matching
  semantic fingerprint always opened a transaction and rewrote identical `cache_state` values.
  Five cells failed the analyzer-epoch check and one failed semantic invalidation while another
  process persisted analysis. The fail-fast queue preserved 26 completed cells and cancelled the
  rest after the original 30 workers drained.
  Evidence: r1's six incomplete traces report `database is locked`; focused persistent-store
  regressions hold an actual writer transaction and now pass matching analyzer and semantic reads
  in 0.02-0.03 seconds. Bifrost fixes are `8c91d985` and `68fb3764`.
- Observation: Clean run r2 eliminated those SQLite lock failures, but its first 30-way wave
  exposed two later startup races before Luna's first inference. Three synthetic searches reached
  Anvil's ordinary fixed 300-second MCP deadline while queued behind the single A4000, and two
  Bifrost processes saw a component row during an existence probe that another repository's
  post-build GC removed before composition read it.
  Evidence: r2 traces for `apache__dubbo-8414`, `apache__rocketmq-7563`, and
  `huggingface__transformers-25884` report the 300-second MCP timeout; two other incomplete traces
  report `component vector missing after embed`. The timeout is now 1,800 seconds only in CIM mode
  at Anvil `8c2e8e6`, and Bifrost `ca6a3f20` retains decoded cached components across composition;
  its regression forces GC after the read and passes.

## Decision Log

- Decision: gate all synthetic-step and tool-description changes behind `BRK_CIM_EVAL`; ordinary
  Anvil remains byte-for-byte behaviorally unchanged when the flag is absent.
  Rationale: this is benchmark instrumentation, not a new normal-agent policy.
  Date/Author: 2026-08-01 / Codex and user.
- Decision: DeepSeek receives only the task description and may return zero or more queries. The
  prompt supplies no desired count and says to emit only clearly necessary starting searches,
  because Luna may search again later. Every emitted query executes independently at final k=20.
  Rationale: fixed-count generation would flood Luna with redundant context and bias the test.
  Date/Author: 2026-08-01 / Codex and user.
- Decision: generate once per task and reuse the immutable query manifest across seeds and arms.
  Rationale: query-generator sampling must not become an arm or seed confounder.
  Date/Author: 2026-08-01 / Codex.
- Decision: use seed 0 as the first evaluation point. Compare its 91 binary outcomes with the
  existing baseline seed 0 using a two-sided exact discordant-pair test at p<0.05. Proceed only
  when dw10 has more exclusive solves. After seeds 1 and 2, use CIM's per-instance seed-mean paired
  Wilcoxon gate at p<0.05.
  Rationale: this spends only one seed before evidence clears the requested noise bar.
  Date/Author: 2026-08-01 / Codex and user.
- Decision: Bedrock Luna at maximum reasoning is mandatory for reportable cells.
  Rationale: changing provider would invalidate comparison with the existing baseline.
  Date/Author: 2026-08-01 / Codex.
- Decision: invoke query generation as `deepseek::deepseek-v4-flash`, not through the unqualified
  alias, and fail rather than substitute another provider.
  Rationale: the query model is part of the frozen experimental treatment.
  Date/Author: 2026-08-01 / Codex.
- Decision: cimeval alone selects the dedicated CIM XFS Podman graph root before run, score, and
  preflight operations; agenteval and other sandbox consumers retain their existing storage.
  Rationale: task images are campaign infrastructure and must not consume the space-constrained
  home filesystem, but this evaluation must not perturb agenteval's DeepSWE behavior.
  Date/Author: 2026-08-01 / Codex and user.
- Decision: retain r1 only as an infrastructure diagnostic and run the reportable seed-0 gate from
  scratch in r2 with one runtime identity.
  Rationale: resuming r1 with a corrected Bifrost binary would violate the predeclared
  single-runtime criterion even though the fixes affect only contention. Reusing the exact r1
  run-manifest bytes preserves the frozen query manifest's task identity.
  Date/Author: 2026-08-01 / Codex.
- Decision: retain r2 as a second infrastructure diagnostic and restart from scratch as r3 with
  Anvil's CIM-only 1,800-second MCP deadline and Bifrost's atomic read/retain composition design.
  Rationale: r2 contains one immutable runtime identity and valid completed cells, but resuming it
  with either fix would mix execution semantics. The longer deadline is confined to the requested
  benchmark mode; ordinary Anvil MCP calls remain capped at 300 seconds.
  Date/Author: 2026-08-01 / Codex.

## Outcomes & Retrospective

Implementation and seed-0 results are pending. At the stopping point, record query-count and
context distributions, synthetic versus agent-selected calls, official resolve/localization/cost
results, paired statistics, leak findings, exact commits, and whether the next gate opened.

## Context and Orientation

The primary planning checkout is `/mnt/optane/bifrost-nlp` on `bifrost-nlp-ft`. Bifrost's dw10
embedding support and shared per-repository caches are already complete; no retrieval change is
planned. Anvil development occurs in `/mnt/optane/anvil-bifrost-nlp-ft`. Its `src/tools/mod.rs`
assembles built-in and MCP tool descriptions, while `src/tool_loop.rs` executes a model response's
tool calls and records the exact replay messages later fed back to the model. `src/p2t.rs` contains
the existing serializable forced-step message types.

The evaluation harness is `/home/jonathan/Projects/brokkbench/cimeval`. `cell.py` creates one
official task container, installs the immutable runtime, and starts `remote/run_task.sh`.
`report.py` reads cell traces and official scores. The existing baseline and original dw10 results
are under `/mnt/optane/bifrost-nlp-resources/runs/granite-r2-cim-20260731-r8` and
`/mnt/optane/bifrost-nlp-resources/runs/dw10-cim-20260731-r2` respectively.

A synthetic step is a batch of assistant tool calls inserted by the harness, rather than emitted
by Luna. It follows the original user task in Luna's message sequence. The resulting tool messages
are normal `semantic_search` results, so CIM View B localization continues to treat their paths as
pointers until Luna explicitly reads, greps, or edits them.

## Plan of Work

In Anvil, add a small CIM configuration module modeled after P2T's environment loading. Require
`BRK_CIM_EVAL=1` and an absolute `BRK_CIM_CONFIG` JSON path with schema version 1, query-manifest
identity, k=20, and an ordered query array. Reject simultaneous CIM/P2T/training modes. When CIM is
enabled and semantic search is advertised, rewrite the relevant descriptions so semantic search is
preferred for behavior/concept discovery while symbol, summary, grep, and file tools retain clear
exact-hook roles. Do not use mandatory wording. With semantic search absent, leave the current
descriptions intact.

Before the first ordinary model request, convert the configured queries into one assistant
tool-call batch with stable call IDs, execute it through the existing semantic reranker, append
the assistant and tool-result messages to the live context and replay records, and continue with
Luna without decrementing its turn budget. Add explicit start/end trace records so reports can
separate synthetic from agent-selected calls. An empty query list is a successful no-op. Any
malformed config, missing semantic tool, or failed synthetic call is a setup failure.

In brokkbench, add `cimeval/querygen.py` and a `querygen` CLI command. Use the existing
`client.CachingClient` with provider-qualified model `deepseek::deepseek-v4-flash`, temperature
zero, and a strict object containing a
single string-array `queries` property. The prompt sees only `CimTask.problem_statement`; it says
that Luna can follow up, asks only for clearly necessary starting searches, rejects redundant
queries and queries already served by obvious task hooks, and explicitly permits an empty array.
Persist one immutable, resumable record per instance plus an aggregate manifest containing prompt,
model, response, and content hashes. Normalize whitespace and exact case-insensitive
duplicates only; never use gold data or hand selection.

Extend the cell configuration and remote runner to copy the selected task's CIM config into the
container and set the two CIM environment variables. Record the query identity and observed step
status in `result.json`; completed-cell reuse must reject identity drift. Extend reports to mark
rerank events inside the CIM step as synthetic, retain later calls as agent-selected, summarize
query counts and context bytes, and load an explicit immutable reference run for baseline rows.

After unit validation, generate all 91 query records at concurrency 30, inspect count/outlier
distributions without outcomes, and run one real smoke. Then run only dw10
`semantic-coedit-2-1`, seed 0, at concurrency 30 in official sandbox images. Score inline with
the existing selective pristine recovery, localize, and leak-audit. If the exact paired p-value is
below 0.05 and direction is positive, run seeds 1 and 2; otherwise stop as specified in the
Decision Log. Only a positive significant three-seed gate authorizes dw10 `all-signals` and
`semantic-only`.

## Concrete Steps

From `/mnt/optane/anvil-bifrost-nlp-ft`, run focused development gates:

    cargo fmt --check
    cargo test cim
    cargo test semantic_search_description
    cargo clippy --all-targets -- -D warnings

From `/home/jonathan/Projects/brokkbench`, run:

    uv run pytest -q cimeval
    uv run ruff check cimeval
    uv run python -m cimeval querygen --run-dir <new-run> --jobs 30

Build a new immutable runtime bundle using cimeval's existing `runtime` command, start the dw10
sidecar on the verified local A4000, and use the established `.bifrost/cache-dw10` caches. Run the
smoke and reportable queue with `--arms semantic-coedit-2-1 --seeds 0 --jobs 30`, maximum reasoning,
`--without-history`, inline scoring, and the frozen query manifest.

## Validation and Acceptance

With CIM variables absent, Anvil's tests must prove tool descriptions, messages, tool execution,
and turn limits are unchanged. With CIM enabled, tests must prove the description hierarchy,
stable k=20 call batch, exact message order, empty-list no-op, no turn consumption, persisted replay,
and fail-closed errors. P2T/training combinations must fail before any model call.

Querygen tests must prove task-only prompts, variable and empty lists, whitespace/case-insensitive
deduplication, immutable resume identity, schema/failure handling, and that raw DeepSeek content
never enters the generated Anvil configuration or Luna trace. Report tests must prove external
baseline validation and synthetic-versus-agent telemetry separation.

The smoke passes only if every generated query appears as a k=20 semantic call before the first
Luna inference, every result has normal retrieval/reranker telemetry and context, and no DeepSeek
message appears in Luna's request. The seed-0 gate is reportable only with 91 valid official scores,
91 localization artifacts, a reviewed 91-cell leak audit, one consistent query/runtime identity,
and no unaccounted synthetic-step failure.

## Idempotence and Recovery

Query generation and cell execution are resumable by immutable completion markers. A matching
record is reused; any identity mismatch fails rather than overwriting. If the query prompt changes,
create a new query-manifest version and run directory rather than modifying completed records. A
provider outage pauses the Bedrock queue; it does not authorize an OpenRouter substitution. Stop
the embedding sidecar and transient campaign services after each reporting gate.

## Artifacts and Notes

The new reportable run lives under `/mnt/optane/bifrost-nlp-resources/runs/` with a descriptive
`dw10-cim-synthetic` prefix. Large task images continue to use
`/mnt/containers/code_isnt_memory`. Record all exact run paths, bundle hashes, service names, and
commits here as they become known.

The seed-0 run is
`/mnt/optane/bifrost-nlp-resources/runs/dw10-cim-synthetic-20260801-r1`. Its frozen query manifest
is `querygen/manifest.json`; the count distribution is 0:53, 1:3, 2:12, 3:18, 4:3, 5:1, and 6:1.
The dw10 embedding sidecar is `cimeval-dw10-synthetic-r1-sidecar.service`, bound to the local A4000
on port 18765. Runtime v3 is `runtime/runtime-v3.tgz`, SHA-256
`85f9d5ed6ed7952b3c9552c48ef9d19c5e918fc0c42f2b4bf91ba1646bd94145`, and records Anvil
`e8fdbe3`, Bifrost `c9dec2d6`, brokkbench `75bd146`, and Mjolnir `26a3084`. Its Bifrost binary
SHA-256 is `425e963682acef41c5f4fc226958506a25e22b40e961cc67cfcd04f9dc1da915`.
The host orchestration fix selecting the CIM store is brokkbench `685a926dd7f`; it does not alter
the already-frozen remote runtime bytes, so runtime v3 remains the exact diagnostic-r1 bundle.

Diagnostic r1 stopped with 26 completed cells and six lock-failed cells. The clean reportable run
is `/mnt/optane/bifrost-nlp-resources/runs/dw10-cim-synthetic-20260801-r2`; it uses the same
byte-identical run manifest (SHA-256
`d8bf1a517bade527a03f861cab1e74751966f8fd1d345a2c09972d31363f5f40`) and frozen query manifest.
Runtime v5 is `r1/runtime/runtime-v5.tgz`, SHA-256
`d820fbaac2ac74c57d263c5fa336f5b2f8ac9b7ae6a9d4657da04182f55019ca`, with Bifrost
`68fb3764` and binary SHA-256
`85ec69a6a1cfe6d7c3359b1dd7b8c980493b1f0eadaa5fd3b791c9b3487bb5b5`. The reportable service is
`cimeval-dw10-synthetic-seed0-r2.service`, pinned at 30 workers.
R2 is retained as a diagnostic after the timeout/GC failures above; it is not a reportable mixed-
runtime run. The next clean reportable directory is `dw10-cim-synthetic-20260801-r3` and will reuse
the exact frozen run-manifest and query-manifest bytes with a newly recorded runtime.

## Interfaces and Dependencies

Anvil's private interface is two environment variables: `BRK_CIM_EVAL=1` and
`BRK_CIM_CONFIG=/absolute/path/config.json`. The version-1 JSON object contains
`schema_version: 1`, `query_manifest_sha256`, `k: 20`, and `queries: string[]`. It is an internal
benchmark contract and is not advertised as normal Anvil configuration.

The query generator uses only brokkbench's existing `CachingClient`; no new provider library is
introduced. The cell continues to use Bifrost's existing `semantic_search` schema and Anvil's
existing transparent reranker. Mjolnir remains the ACP driver and requires no change.

Revision note, 2026-08-01: Created this follow-up plan after the original campaign showed only
three comparable Granite and seven dw10 agent-selected semantic calls. The new design adds a
CIM-only synthetic query step and a seed-0 statistical spending gate.

Revision note, 2026-08-01: Recorded the completed Anvil/cimeval implementation and the decision to
pin query generation to DeepSeek's direct provider rather than permit brokkbench's normal
cross-provider failover.

Revision note, 2026-08-01: Recorded the frozen query corpus and the real-smoke analyzer panic. The
fix extends the existing foreign-file ownership rule to summary projections rather than weakening
generation-map invariants for files the adapter owns.

Revision note, 2026-08-01: Recorded the corrected runtime v3 and successful end-to-end smoke. The
smoke's unresolved official score is retained as a valid experimental observation, not retried or
hand-selected; the smoke criterion was infrastructure and treatment integrity.

Revision note, 2026-08-01: Recorded that the XFS image store was complete and checkpointed the
cimeval-only storage selection. The host orchestration change does not require rebuilding the
immutable task runtime because none of its bytes enter the container.

Revision note, 2026-08-01: Recorded r2's CIM deadline and cross-process semantic-GC failures, their
focused regression coverage, and the clean-r3 decision required to preserve one runtime identity.

Revision note, 2026-08-01: Recorded r1's shared-cache contention diagnosis, both read-only fast
paths, and the clean r2 restart required to retain one immutable runtime identity.
