# Serve Granite R2 and dw10 and run a gated CIM-style evaluation

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`,
`Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md`. It describes a gated
localizer evaluation: implement and evaluate the smaller Granite R2 fine-tune first, then run
the already-prewarmed dw10 fine-tune with only the best Granite retrieval recipe before the
combined report.

## Purpose / Big Picture

Bifrost currently serves a hardcoded Voyage embedding model and cannot correctly load the local
Granite R2 fine-tune. Anvil also treats semantic-search `k` as an input depth rather than a final
reranked-result ceiling. This work changes Bifrost, Anvil, and brokkbench so Granite R2 can be
indexed on the workstation's local NVIDIA RTX A4000 and evaluated with equal-size retrieval
candidate pools in official benchmark containers.

Before evaluating semantic search, establish a no-semantic-search baseline for GPT-5.6 Luna
running through Mjolnir and Anvil. Run seed 0 first and compare it with CIM's published
no-index results. If that result is not operationally and statistically plausible, stop the
campaign and repair the harness before spending two more seeds. While the baseline runs on CPU
and provider capacity, use one Bifrost indexing process at a time to saturate the A4000 and
precompute Granite indexes.

After a sane three-seed baseline, run Granite R2 over the three requested retrieval arms and
three seeds. Keep every evaluation and scoring phase pinned at 30 concurrent cells and observe
the 60-core host for contention with the user's other workload. While Granite's selective
pristine verifier recovery finishes, run dw10 over three seeds using only
`semantic-coedit-2-1`; do not repeat the all-signals or semantic-only arms for dw10. Report the
commits and behavior changed in Bifrost, Anvil, and brokkbench, all validation performed, the
baseline comparison, the Granite results, and the dw10 best-recipe results.

The observable outcomes are:

1. The 15 unique upstream CIM repositories are cloned in parallel under
   `/home/jonathan/Projects/brokkbench/clones/`, and the 91 task revisions are materialized as
   worktrees, before the main implementation/evaluation work.
2. A no-semantic-search seed-0 baseline completes at concurrency 30 and passes the explicit
   sanity gate before seeds 1 and 2 are scheduled.
3. Granite indexing runs concurrently with the baseline but at indexing concurrency one,
   pinned to the local RTX A4000, and produces one shared Bifrost DB per upstream repository.
4. Anvil documents and enforces a final `semantic_search.k` ceiling of 20 and may return fewer
   than `k` results by design.
5. At final `k=20`, Granite retrieval uses nominal raw budgets `40/40/40`, `120/0/0`, and
   `80/0/40` for vector/BM25/co-edit in the three arms, with at most 20 final Anvil results.
6. The completed campaign accounts for 273 baseline cells, 819 Granite cells, and 273 dw10
   `semantic-coedit-2-1` cells, subject to outcome-blind exclusions.

## Progress

- [x] (2026-07-31 09:21Z) Inspected Bifrost's semantic index, model sidecar, retrieval pipeline,
  MCP schema, and shared SQLite cache design.
- [x] (2026-07-31 09:21Z) Inspected Anvil's transparent semantic reranker and schema-description
  override.
- [x] (2026-07-31 09:21Z) Inspected the Granite R2 and dw10 artifacts and the released CIM
  manifest, scoring code, statistics, and published results.
- [x] (2026-07-31 09:38Z) Recorded the shared writable SQLite design for eval indexes.
- [x] (2026-07-31, initial campaign revision) Narrowed the initial delivery to Granite R2, added the
  no-semantic baseline gate, A4000 indexing, clone-first sequencing, 15 repository-shared
  indexes, and evaluation concurrency pinned at 30.
- [x] (2026-07-31, implementation) Verified or completed all 15 upstream clones in parallel
  under the established brokkbench clone root and materialized all 91 task revisions as clean,
  detached worktrees. The immutable reportable manifest is
  `/mnt/optane/bifrost-nlp-resources/runs/granite-r2-cim-20260731-r1/run-manifest.json`.
- [x] (2026-07-31, implementation) Implemented the first Bifrost Granite checkpoint: exact
  profile, dynamic dimensions/composition/fingerprints, TCP sidecar transport, three retrieval
  profiles, and semantic-off tool suppression. NLP unit tests and the A4000 real-model smoke
  pass; broader validation remains.
- [x] (2026-07-31, implementation) Implemented and committed Anvil's final-`k` contract in
  worktree commits `e002ba4` and `71c6346`, with focused tests and clippy passing. The latter
  also permits the container harness to set Anvil's bounded turn count through the environment.
- [x] (2026-07-31, implementation) Added and committed the isolated `cimeval` foundation and
  opt-in direct-Podman networking/mount support in brokkbench commit `e05760f759f`. It resolves
  the released sample, prepares all clones/worktrees, builds immutable runtime bundles, and
  launches a scrubbed task in its official image without changing agenteval defaults.
- [x] (2026-07-31, implementation) Finished reportable runtime validation: official task
  images run the bundled GNU Bifrost plus static Mjolnir/Anvil, Mjolnir commit `3e046fca`
  routes explicit provider-qualified Anvil model IDs, and one PolyBench plus one Pro task
  completed generation and independent fresh-container scoring.
- [x] (2026-07-31, implementation) Finished the core `cimeval` campaign commands in
  brokkbench commits `ce64f24fbb8` and `1f1d708aba1`: serial production prewarm, concurrent
  resumable waves, official fresh-container scoring, load sampling, and report aggregation.
- [x] (2026-07-31, r5) Ran provider preflight and the no-semantic seed-0 baseline at concurrency
  30. The first
  r1 wave was stopped and invalidated after leak audit found repository-history and web-search
  use. The r3 wave was subsequently invalidated after 71 cells: the container runner replaced
  each image's OCI `PATH`, so Go tasks could not use their bundled toolchain during either
  generation or scoring. Brokkbench commit `d508bd1c4a4` preserves image environments, its
  focused suite passes, and a real Flipt image exposes Go 1.24.3. The r4 smoke proved fresh
  scoring but exposed a remaining login shell in the provider-secret generation transport.
  Brokkbench commit `6f80c498bc5` fixes that final entry point; the clean r5 replacement is
  valid. Its queue and resume completed all 91 cells, all of which were scored with the
  pristine scorer for a uniform seed-0 method.
- [x] (2026-07-31, implementation) Changed later cimeval waves to score each result immediately
  in its generation sandbox, matching agenteval's faster lifecycle. The held-out patch and
  official test command run only after the agent patch and artifacts are captured. The prior
  separate pristine scorer remains available as `--scoring-mode pristine`; r5's already-closed
  generation sandboxes necessarily use it for their one-time score pass.
- [x] (2026-07-31, campaign) Finished and analyzed all three max-reasoning Luna baseline seeds
  at concurrency 30: 273/273 cells completed, localized, and scored, with 140 resolves (51.3%).
  Seeds 0, 1, and 2 resolved 49/91 (53.8%), 48/91 (52.7%), and 43/91 (47.3%); their Acc@5 values
  were 50.5%, 52.7%, and 50.5%. Mean turns were 39.6, 42.3, and 42.3. Mean cost/cell was $0.491,
  $0.508, and $0.469, for $133.52 total and $0.954 per solve. The regenerated leakage audit
  inspected all 273 cells and flagged zero. This passes the operational sanity gate and remains
  comparable in outcome, though not token budget, to CIM's published SC-OFF/OpenCode results.
- [x] (2026-07-31 10:01Z) Precomputed all Granite indexes on the A4000 at repository concurrency
  one. Bifrost commit `e36d4e6e` parallelizes each 64-file extraction group while preserving
  serial output order. The 15 repository `READY.json` records cover all 91 tasks. After resuming
  the partially warm Trino database, the remaining campaign completed in 366.4 seconds; the
  active CPU stages used roughly 30-45 cores instead of one.
- [x] (2026-07-31 13:32Z) Invalidated r6/r7 and started corrected r8 seed 0 with GPT-5.6 Luna
  at maximum reasoning effort, still capped at 30 concurrent cells and using inline scoring.
  r6 exposed that Mjolnir treated `+max` as part of the model ID; Mjolnir `f7ba210` now parses
  it and Anvil `3885f50` advertises and forwards Bedrock GPT `max`. The r7 one-cell smoke proved
  live `reasoning_effort=max` through 85 turns, then exposed that cimeval discarded 30-minute
  timeouts. Brokkbench `680d628e53d` now terminates the exact runner, preserves patch/logs,
  records `timed_out`, runs the inline scorer, and excludes scoring time from agent wall time.
  Fresh r8 service `cimeval-r8-baseline-max.service` has all 30 workers active; a live turn-0
  trace proves the corrected model and effort.
- [x] (2026-07-31 19:06Z) Added CIM-compatible localization extraction in brokkbench
  `8f861239a8c`. It reconstructs Anvil's structured assistant/tool history, computes diagnostic
  View A and canonical View B with semantic-result provenance, reads edits from the final patch,
  and reports accuracy/recall at 1, 3, 5, 10, and 20 plus edit precision/recall. The first 25
  completed r8 baseline cells localized with zero skips; their two views are identical and
  partial Acc@5 is 44%, close to CIM's published 44.3% no-index result.
- [x] (2026-07-31 20:03Z) Repaired the r8 inline-scoring queue failure in brokkbench
  `ba3c6d2f7b7`. SWE-bench Pro scoring had tried to check out hidden tests from a future commit
  that is absent from some official images; scoring now overlays the dataset's `test_patch`
  directly on the agent checkout. Unexpected scorer exceptions are published as explicit
  `scorer_failed` cell results with tracebacks instead of escaping a worker and canceling every
  queued future. All 24 cimeval tests and Ruff pass. The same immutable r8 run resumed with its
  38 completed cells intact and refilled to 30 live task containers.
- [x] (2026-07-31 21:02Z) Corrected inline verifier overlap without reverting to a second
  container for every cell. Forty-three of 91 max-baseline agents edited paths also touched by
  held-out test patches, so brokkbench `3d5ffbc134c`, `155f7ebb44d`, and `2faaaa359ec` retain the
  inline diagnostic and selectively publish a versioned pristine score. Git's patch parser
  identifies held-out paths; candidate edits to those paths are omitted while production edits
  are applied to the hidden-test checkout. All 43 conflicts have v2 scores, 30 of which resolve.
  A real RocketMQ smoke ran official tests for 237 seconds and changed an artificial conflict
  into a genuine resolve. Brokkbench `906c46377fb` also records shell network attempts as
  mitigated by the enforced `ANVIL_OFFLINE_SHELL` network namespace; the regenerated audit has
  91 cells and zero unmitigated findings. All 28 cimeval tests and Ruff pass.
- [x] (2026-07-31, campaign) Prewarmed dw10 serially on the A4000 for all 91 task revisions
  and all 15 shared repositories. The corrected run exited successfully with zero restarts;
  Trino's final three revisions produced one repository-ready manifest and a shared
  `cache-dw10` database. The first attempt was stopped
  after 42 task revisions because it incorrectly selected stock Voyage's `parent_alpha=0.5`.
  Bifrost `bac89d82` adds an explicit fingerprinted `dw10` profile with the checkpoint's
  `parent_alpha=0.65` and the shared Voyage prompt/pooling contract. The corrected fresh run is
  `/mnt/optane/bifrost-nlp-resources/runs/dw10-cim-20260731-r2`. Its sidecar was stopped after
  readiness so Granite could reuse the A4000 and port 18765. dw10 uses the separate
  per-repository `.bifrost/cache-dw10` namespace, so changing embedding fingerprints did not
  invalidate the completed `.bifrost/cache` Granite databases. At this checkpoint no dw10
  evaluation had run; it was subsequently authorized and completed below.
- [x] (2026-08-01, complete) Run the three Granite retrieval arms over seeds 0, 1, and 2 at
  concurrency 30. The reportable directory contains exactly the 273 baseline and 819 Granite
  cells.
- [x] (2026-07-31, campaign gate) Validated the immutable semantic runtime before the full
  queue. Two official Flipt sandbox cells ran concurrently against one shared repository DB;
  both completed and scored, both transient units exited successfully with zero restarts, and
  one resolved. The agents did not elect to call `semantic_search`, so a separate deterministic
  pair of concurrent Bifrost calls exercised two Flipt revisions against the same DB. Both
  returned Granite results with the `all-signals` profile and per-leg diagnostics, then
  `PRAGMA integrity_check` returned `ok`. This distinguishes raw Bifrost `k=20` (20 candidates
  per leg) from Anvil's tested final-`k` boundary, which forwards `2*k` to Bifrost before
  reranking.
- [x] (2026-07-31, first campaign launch) Started persistent unit
  `cimeval-r8-granite-grid.service` with one Cartesian queue containing all 819 Granite cells,
  fixed `--jobs 30`, max-reasoning Bedrock Luna, inline scoring, and resume enabled. It skipped
  the two completed smoke cells and filled all 30 worker slots. The first actual semantic trace
  proved Anvil's contract (`requested_final_k=20`, `forwarded_base_k=40`, requested legs
  40/40/40), but exposed a Bifrost startup race: its one-second readiness fallback fired before
  any active index existed and returned zero candidates. The unit was stopped immediately;
  zero additional cells had completed, and interrupted cells retained no frozen artifacts.
- [x] (2026-07-31, readiness repair) Bifrost `fcaf3a78` makes the first semantic query wait for
  the initial active index while preserving the one-second stale-index fallback during later
  rebuilds. Behavior-focused tests cover both cases; the focused five-test semantic suite,
  formatting, and Clippy pass. A cold one-shot Dubbo query with the rebuilt binary returned
  40/40/40 candidates with no fallback note. Immutable bundle
  `runtime-semantic-fcaf3a78.tgz` records the corrected Bifrost revision and unchanged Anvil,
  Mjolnir, and brokkbench revisions.
- [x] (2026-07-31, corrected campaign launch) Restarted the Cartesian queue as persistent unit
  `cimeval-r8-granite-grid-fcaf3a78.service` with the corrected immutable bundle. It again filled
  all 30 slots; scheduler and sidecar remained at zero restarts, initial load was 29 on 60 cores,
  and concurrency remained pinned at 30 as requested. The first real rerank then exposed a
  separate validity failure: retrieval produced 120 distinct candidates, but Anvil sent a
  symbol batch above Bifrost's 64-item schema limit and ignored Bifrost's compact degraded file
  outlines, leaving `context_bytes=0`. The unit was stopped before accepting this runtime.
- [x] (2026-07-31, reranker-context repair) Anvil `c4483eb` fetches candidate context in bounded
  RRF-order batches, retries individual requests only after a batch error, and accepts both full
  summaries and compact degraded file outlines. Its 13 focused tests, formatting, and Clippy
  pass. Brokkbench `6c62b71b247` records each cell's runtime path, SHA-256, and revision metadata,
  rejects resume under a different bundle, and reports runtime identities and zero-context
  candidate calls. All 31 cimeval tests and focused Ruff checks pass.
- [x] (2026-07-31, final campaign launch) Published and preflighted immutable bundle
  `runtime-semantic-context-c4483eb-6c62b71.tgz`, pinning Anvil `c4483eb`, Bifrost `378652eb`,
  Mjolnir `f7ba210`, and brokkbench `6c62b71`. The three semantic completions from superseded
  runtimes were moved, without deletion, to `invalidated/pre-final-runtime`; the reportable cell
  directory therefore returned to exactly 273 baseline completions. The 819-cell queue started
  at fixed concurrency 30 with max-reasoning Bedrock Luna and inline scoring, but its first
  completion failed during ACP setup after concurrent Bedrock catalog discovery timed out and
  Anvil advertised no model configuration control. The queue was stopped and that sole failed
  completion was recoverably moved to `invalidated/startup-discovery-timeout`.
- [x] (2026-07-31, startup-contract repair) Mjolnir `26a3084` launches every selected Anvil seat
  with its exact provider-qualified `--default-model` and per-seat `--reasoning-effort`, making
  requested runtime configuration independent of optional provider catalog discovery. All 38
  focused roster tests, formatting, and Clippy pass. Immutable bundle
  `runtime-semantic-mj26a3084.tgz` passed official-image preflight. Its one-cell Dubbo gate
  generated successfully through multiple provider turns and tool rounds; the live process
  table recorded Luna and `max` on both Mjolnir and Anvil. The smoke was stopped before freezing
  a result because it had not elected semantic search, and the final queue then started with all
  30 slots available. The first elected semantic trace remains a live context/budget gate.
- [x] (2026-07-31, final live retrieval gate) A live official Dubbo task under the final
  30-worker queue elected `semantic_search` in the semantic-only arm. It requested and realized
  exactly 120 vector, zero BM25, and zero co-edit candidates; deduplicated to 120; attached
  89,166 bytes of source context; selected 12 results beneath final `k=20`; and did not fall
  back. Retrieval took 84.9 ms, including 18.6 ms of Granite service time. This proves that the
  context repair is active in the immutable runtime rather than merely covered by unit tests.
- [x] (2026-08-01, 100-cell checkpoint) Audited the first 100 frozen Granite cells without
  inspecting partial outcome rates. All used maximum reasoning and runtime SHA-256
  `f626e492783d6a559b29abe123e19e8e65bdf094baa0f43a21241fd5e137ad75`; arms and seeds
  remained balanced. Frozen reportable traces now prove all three final-`k=20` contracts:
  all-signals requested and realized 40/40/40 vector/BM25/co-edit candidates, semantic-only
  120/0/0, and semantic-coedit 80/0/40. Every observed reranker call had nonempty context and
  no fallback. Incremental localization covered 390 cells with no skips, and the subsequent
  392-cell leak audit reported zero unmitigated findings. The dedicated XFS container store
  retained 1.2 TiB free.
- [x] (2026-08-01 04:15Z, 400-cell checkpoint) Rechecked the live queue after it crossed 400
  frozen Granite cells. Every inspected cell still records Bedrock GPT-5.6 Luna, maximum
  reasoning, and immutable runtime SHA-256
  `f626e492783d6a559b29abe123e19e8e65bdf094baa0f43a21241fd5e137ad75`. The nine arm/seed
  buckets remained balanced within three cells, the controller continued to refill all 30
  worker slots after container handoffs, and no controller or generation failure was recorded.
  The XFS container store retained 1.2 TiB free and `/mnt/optane` retained 261 GiB free.
- [x] (2026-08-01, scorer recovery) The checkpoint exposed load-induced official scorer
  failures rather than agent outcomes: 22 early semantic RocketMQ Maven scorers exhausted the
  separate 1,800-second verifier budget during the concurrent compiler wave, while matching
  baseline scorers normally finished in 4-11 minutes. Three baseline cells also retained an
  earlier `scorer_failed` result. Brokkbench `a8d05bfc441` now treats an inline
  `scorer_failed` result as inconclusive, preserves it, and routes resume or explicit `score`
  through the existing pristine fallback container. The focused 14-test scoring/report gate,
  all 32 cimeval tests, formatting, and Ruff pass. The running controller is not restarted;
  after all generation cells freeze, a controlled-concurrency explicit rescore will recover
  every failed verifier without changing agent patches or the immutable semantic runtime.
- [x] (2026-08-01, report denominator repair) A provisional comparison exposed that the report
  treated `scorer_failed` as an unresolved model outcome. Brokkbench `4c7e9d89800` now keeps
  those cells in completed-generation and trajectory/cost accounting but excludes them from
  scored/resolved denominators and paired resolve tests until a valid fallback score exists.
  Ruff and all 33 cimeval tests pass. The regenerated outcome-blind leak audit inspected 804
  frozen cells and reported zero unmitigated findings; all observed history/network attempts
  were neutralized by synthetic-root history or the offline shell namespace.
- [x] (2026-08-01, explicit history protocol) Brokkbench `a50ed197f07` adds a fail-closed
  sanitizer for subsequent campaigns that retains the original task-head commit and exactly its
  reachable ancestors while deleting every other ref, reflog, remote, and object. Official
  Transformers and Pro Flipt image smokes verified exact object closure in 5.8 and 12.1 seconds;
  Flipt lost 15,533 non-task-head objects and 236 extra refs. Brokkbench `401cb407962` makes this
  the safe default and adds `cimeval run --without-history` for the prior tree-identical
  synthetic-root protocol. Each result freezes its history mode and resume rejects a mismatch.
  All 39 cimeval tests and Ruff pass. The active controller loaded the prior implementation, so
  the current baseline and Granite cells remain uniformly no-history; this campaign will finish
  before any task-head-history comparison is started.
- [x] (2026-07-31, implementation) Brokkbench `64a2da6131f` extends the existing
  multi-arm scheduler with `--seeds`, so the full 91-task by three-arm by three-seed Granite
  matrix can enter one 819-cell queue. A single 30-worker pool now remains occupied through
  the campaign tail instead of draining once per seed; the legacy single-seed CLI and load-log
  names remain unchanged. All 29 cimeval tests and Ruff checks on the touched files pass.
- [x] (2026-07-31, campaign setup) Prepared the task-side tokenizer-only directory at
  `runtime/granite-tokenizer` in the r8 run. It contains only the 3.5 MiB `tokenizer.json`
  (SHA-256 `bb637767e8dfb8044597df6c58243bff2e592ae9e3b310c0bbdb8591f6ac543d`),
  rather than copying the 372 MiB host model/checkpoint tree into every one of 819 containers.
  Granite weights remain exclusively in the host A4000 sidecar.
- [x] (2026-07-31, implementation) Added reproducible final-analysis support in brokkbench
  `3ce7216dbc0`, `6a94ce2b4ef`, and `83a8979c9a5`: Luna cost/cell and cost/solve,
  mean-of-seed-means and across-seed standard deviation, CIM-style paired Wilcoxon tests,
  candidate/reranker/timing aggregation, and versioned immutable runtime bundles. Bifrost
  `71e8ac64` measures sidecar model-lock queue and service time and serializes retrieval budgets;
  Anvil `709f227` freezes those diagnostics in its reranker trace. All 31 cimeval tests, focused
  Bifrost/Anvil tests, formatting, Ruff, and the A4000 real-Granite smoke pass. The semantic
  runtime bundle records Bifrost `71e8ac64`, Anvil `709f227`, Mjolnir `f7ba210`, and brokkbench
  `83a8979c9a5`.
- [x] (2026-08-01, complete generation and analysis lattice) The frozen campaign contains
  exactly 1,092 cells: 91 tasks in every arm/seed bucket for the 273-cell baseline and 819-cell
  Granite grid. Every cell records Bedrock GPT-5.6 Luna at maximum reasoning. The 30-worker
  controller exited successfully with 998 completed agent runs, 94 normal 1,800-second agent
  timeouts, and zero controller failures. Final localization produced 1,092/1,092 artifacts
  with zero skips or errors. The final leak audit covered all 1,092 cells and flagged zero;
  1,753 Git-history attempts and 72 network attempts were all mitigated by synthetic-root
  history or Anvil's offline network namespace. Selective pristine recovery subsequently
  produced a valid official score for every cell.
- [x] (2026-08-01, final Granite report) Scored all 1,092 cells after selective pristine
  recovery, including successful versioned retries for all 29 first-pass verifier timeouts.
  The final report has no missing outcomes. Resolve rates are 52.0% baseline, 53.8% all
  signals, 54.6% semantic only, and 54.9% semantic plus co-edit; none of the paired resolve
  comparisons against baseline is statistically significant.
- [x] (2026-08-01, generation complete) Run dw10 `semantic-coedit-2-1` over seeds 0, 1, and 2
  at concurrency 30, using its
  separately fingerprinted cache and local A4000 sidecar.
  The full 273-cell Cartesian queue started on 2026-08-01 with Bedrock GPT-5.6 Luna at maximum
  reasoning, `--without-history`, inline scoring, the immutable dw10 runtime and tokenizer,
  port 18765, `cache-dw10`, and exactly 30 workers. A one-cell live attempt was deliberately
  discarded before this queue because the agent made 118 model requests without choosing the
  semantic tool; it had no completed result or score and therefore contributes no campaign
  data. The first reportable agent-selected DW10 retrieval call, Apollo seed 2, proves the live
  contract: it requested and realized exactly 80 vector, 0 BM25, and 40 co-edit candidates,
  deduplicated to 120, attached 60,968 context bytes, selected 12 results under final `k=20`,
  and did not fall back. DW10 embedding service time was 255 ms. The controller exited
  successfully with exactly 273 cells: 261 completed agents, 12 normal 1,800-second agent
  timeouts, and zero runner failures. Every result records Bedrock GPT-5.6 Luna, maximum
  reasoning, the `dw10` embedding profile, and no history. Seven cells selected semantic search.
  Localization completed 273/273 with no skips. The leak audit covered all 273 cells and flagged
  zero; all 440 Git-history attempts and 11 network attempts were mitigated by synthetic-root
  history and Anvil's offline network namespace. Of the 273 initial outcomes, 261 were valid;
  versioned third-pass pristine recovery produced valid official scores for all 12 Transformers
  verifier failures with zero retry failures. The final dw10 result is 146/273 (53.5%).
- [x] (2026-08-01, final validation and report) Regenerated both final reports, completed the
  paired analysis, updated this retrospective and repository inventory, and ran focused final
  gates. Bifrost passes formatting, 47 NLP tests, the actual MCP semantic/registry tests, and
  focused all-target NLP clippy; Anvil passes formatting and its 14 focused reranker/schema
  tests; Mjolnir passes formatting, eight focused routing/effort tests, and clippy; brokkbench
  passes all 39 cimeval tests and Ruff. The `bifrost-policy-checking` skill and policy tools are
  not installed in this session, so no policy success is claimed.
- [x] (2026-08-02 07:42Z) Finalized the compact multi-query follow-up design after auditing the
  DW10 trajectories and the live Anvil/Bifrost interfaces. Bifrost remains scalar. Anvil will
  run one complete raw-search plus DSV4Flash rerank pipeline independently for each of one to
  three queries, concurrently, and return separate query-local sections without global fusion,
  normalization, or cross-query deduplication. Rich excerpts remain private to each reranker;
  caller-visible results use Bifrost's structured declaration signatures and ranges.
- [x] (2026-08-02, implementation) Implemented and committed Anvil's queries-only schema,
  concurrent independent reranks, classifier-selected signature locator cards, and usage/trace
  aggregation in `243e5f2` and `c368264`. A live Apollo smoke exposed that valid candidate
  rankings could contain empty or inapplicable declaration choices; the second checkpoint keeps
  candidate validation fail-closed while making the presentation-only declaration choice
  best-effort. Formatting, 15 focused reranker tests, five CIM tests, and all-target Clippy pass.
- [x] (2026-08-02, implementation) Implemented and committed brokkbench's three-query generation
  ceiling in `f8cd8ba4f9c`. Query generation now asks for at most three nonredundant queries and
  preserves fewer when sufficient; the cell validator requires one query-local rerank trace per
  generated query. All focused cimeval tests and Ruff pass.
- [x] (2026-08-02, first live gate) Published immutable runtime `runtime-v10.tgz` with Anvil
  `c368264` and passed official Apollo image preflight. Its three-query synthetic step completed
  three concurrent scalar Bifrost searches and independent DSV4Flash reranks in 49.3 seconds,
  returned 20, 20, and 17 query-local results, and recorded no retrieval fallback or source-body
  leakage. The smoke was stopped before freezing a result because only 16 of 57 returned
  locators retained structured signatures.
- [x] (2026-08-02, signature coverage repair) Root-caused the missing cards to Bifrost's
  intentional aggregate-output degradation: a successful multi-target `get_summaries` call can
  become compact file outlines and omit declaration records. Anvil `0d83797` now issues one
  intrinsically bounded summary request per target while retaining concurrency within each
  eight-candidate batch, and traces both candidate and selected-result signature coverage.
  Formatting, 15 focused reranker tests, five CIM tests, and all-target Clippy pass.
- [x] (2026-08-02, compact DW10 checkpoint) Ran the 34 queried DW10 cells at fixed concurrency
  30 with Bedrock GPT-5.6 Luna at maximum reasoning, no history, the `dw10` A4000 sidecar, and
  per-query DSV4Flash reranking. The final r3 directory has 34/34 valid scores, zero timeouts,
  zero scorer failures, one synthetic step in every cell, 86 synthetic reranks, two later
  agent-initiated reranks, no retrieval fallback or final-`k` violation, and zero unmitigated
  leak-audit findings. It resolves 12/34, exactly matching the prior comparable 34-task cohort:
  one gain and one loss, exact paired p=1.0. On the 30 exact-query pairs it is 10/30 versus
  11/30; on the four query-capped pairs it is 2/4 versus 1/4. This does not clear the
  precommitted significant-improvement gate, so no additional seeds will run.
- [x] (2026-08-02, campaign validity repairs) Invalidated diagnostic r2 after RocketMQ 4122
  opened a second fresh primary Anvil session and executed synthetic step zero twice. Anvil
  `4043043` adds a fail-closed per-cell atomic claim so only the first fresh session performs
  the CIM step. The first r3 controller then rejected valid later agent semantic calls because
  its provenance check counted all reranks in the trajectory; brokkbench `3b7a7791928` scopes
  the invariant to the unique synthetic start/end interval. Resuming r3 preserved its 16
  already frozen valid results and reran only unfinished cells.

## Surprises & Discoveries

- Observation: `BIFROST_EMBED_MODEL_DIR` does not currently select the model loaded by
  `scripts/voyage_sidecar.py`; the Python side always loads `voyageai/voyage-4-nano` and emits
  512 values.
  Evidence: the model ID and output dimension are module constants in the current sidecar.

- Observation: a model directory alone is not an adequate index compatibility identity for
  the dw10 fine-tune because it keeps Voyage's architecture, dimension, prompts, and pooling
  while changing the parent/child blend from 0.5 to 0.65.
  Evidence: the artifact's `run_metadata.json` records `parent_alpha=0.65`; the initial
  stock-Voyage prewarm reached 42 task revisions before this mismatch was found. The corrected
  `dw10` profile changes Bifrost's semantic fingerprint, causing each stale cache to be
  invalidated and rebuilt rather than reused.

- Observation: Granite R2 uses a materially different representation contract from Voyage.
  Evidence: its artifact declares `ModernBertModel`, CLS pooling, width 384, maximum sequence
  length 8192, and parent composition
  `normalize(0.65 * child + 0.35 * parent)`.

- Observation: Granite's serving prefixes are not present in its exported
  `config_sentence_transformers.json`, whose prompt strings are empty.
  Evidence: `/home/jonathan/Projects/brokkbench/localizer/GRANITE_R2_V4_FINAL_RECIPE.md` and
  `localizer/localize_sft_core.py` define the required query and passage strings.

- Observation: Anvil currently forwards the model's `k` unchanged, caps its parsed pool at 30
  symbols and 20 files, permits an arbitrary-size reranker selection, and falls back to raw
  Bifrost lists.
  Evidence: `/home/jonathan/Projects/anvil/src/semantic_rerank.rs`.

- Observation: Bifrost's cache is intended to be shared by branches, worktrees, and processes
  when all processes open the same database, WAL, and SHM files.
  Evidence: `nlp/store.rs` collapses worktrees to the primary-repo cache, persisted vectors are
  content-addressed, active membership is connection-local, and `cache_db.rs` relies on
  SQLite's cross-process locking.

- Observation: rootless Podman task containers cannot use the WSL GPU directly, but they can
  reach a host loopback embedding service through `pasta` TCP forwarding.
  Evidence: direct `/dev/dxg` attempts failed during planning while `pasta:-T,<port>` reached a
  host test server.

- Observation: the released CIM no-index baselines are close to one another and stable across
  seeds. SC-OFF resolve is 43.9%, 41.5%, and 40.2%; OpenCode resolve is 44.4%, 45.7%, and
  45.7%. Their three-seed means are 41.9% and 45.3% respectively.
  Evidence: `supercoder-eval/paper/tables/tab-resolve-perseed.tex`.

- Observation: one inline scorer exception canceled all tasks still queued in the original r8
  `ThreadPoolExecutor`, leaving only the already-running tail to drain.
  Evidence: the controller fell from 31 threads to two while only 50 of 91 cell directories had
  started; its eventual traceback showed `git checkout <future-commit> -- <hidden-test>` failed
  with exit 128 in an official Ansible image. The service's automatic retry was stopped before
  it could repeat the expensive failure, and the corrected resume immediately created 30 live
  task containers.

- Observation: inline scoring is not accurate enough by itself for this workload because agents
  commonly edit the same public test files extended by the held-out patch.
  Evidence: 43/91 r8 cells had `test_patch_applied=false`; zero of r5's 91 pristine scores had
  that condition. Selective v2 pristine rescoring recovered 30 resolves and produced the final
  49/91 baseline, while preserving successful inline scores and both failed diagnostic passes.

- Observation: the WSL shim is available at `/usr/lib/wsl/lib/nvidia-smi`; the requested GPU is
  index 2, UUID `GPU-13db0817-4937-36dc-3061-d51b47799ce9`, model `NVIDIA RTX A4000`, with
  16,376 MiB reported memory.
  Evidence: the host query returned all four installed GPUs and this exact UUID/name pair.

- Observation: `/home/jonathan/Projects/brokkbench/clones` is an existing symlink to
  `/mnt/T9/repo-clones`, and 14 of the 15 required upstreams were already valid full clones.
  Evidence: resolved-path inspection and `git rev-parse` over the clone inventory. The missing
  Transformers clone was created there without replacing the symlink or existing repositories.

- Observation: the Granite TCP service matches SentenceTransformers at cosine 0.9999676 for a
  fixed prefixed query, returns a 384-dimensional unit vector, and passes Bifrost's opt-in
  end-to-end real-model semantic-search smoke.
  Evidence: the service/reference parity command and
  `BIFROST_NLP_MODEL_TESTS=1 cargo test --features nlp --test nlp_semantic_search_models --
  --ignored --nocapture`.

- Observation: a one-shot `semantic_search` process is not a valid prewarm primitive because
  the query's bounded readiness wait may expire and process exit then stops the background
  indexer.
  Evidence: the first Dubbo worktree returned the documented "index is still building" note
  and exited without an active index. The existing `semantic_index_profile` binary instead
  calls `SemanticIndexer::wait_ready` for up to 24 hours and reports final status, so the
  campaign will use that production pipeline sequentially with a repository-shared cache.

- Observation: valid retrieval counts do not prove that the reranker received source context.
  Evidence: the first readiness-fixed live trace realized 80 vector and 40 co-edit candidates
  and deduplicated them to 120, yet recorded `context_bytes=0`. The symbol request exceeded
  Bifrost's 64-symbol schema ceiling, while a large file-summary response degraded to
  `compact_symbols.files`, which the old Anvil parser did not consume.

- Observation: an explicit provider-qualified Mjolnir route was still vulnerable to Anvil's
  independent startup catalog discovery.
  Evidence: under the first final 30-way launch, Bedrock discovery timed out after 15 seconds in
  one Anvil process. Its session default was empty, so `session/new` omitted the model option and
  Mjolnir aborted with `ACP adapter did not advertise a model configuration control` before a
  generation request. Passing the already-selected model and effort on the Anvil command line
  removes catalog discovery from this correctness path.

- Observation: the first official-container baseline smoke failed before any provider request
  because Mjolnir rejected the explicit wire ID `bedrock::openai.gpt-5.6-luna` when Anvil's
  discovery snapshot did not list it.
  Evidence: `mj.stderr.log` says the model is not an eligible DeepSWE High/default model. A
  Mjolnir worktree at `/mnt/optane/mjolnir-bifrost-nlp-ft` now has a focused fix that passes an
  explicit provider-qualified selector to a ready Anvil server while preserving catalog-based
  auto-selection; its focused tests pass and full validation is in progress.

- Observation: `anvil.trace.jsonl` is legitimately absent when a run makes no semantic-search
  call, including the baseline arm.
  Evidence: the remote runner creates the trace only through Anvil semantic-search telemetry;
  the cell collector now treats that trace and candidate telemetry as optional while retaining
  Mjolnir and Anvil stderr/stream files as required core artifacts.

- Observation: Bedrock Luna completed both a SWE-bench Pro Ansible generation (42 tool calls,
  107.9 seconds) and a SWE-PolyBench Dubbo generation (36 tool calls, 434.3 seconds) without a
  provider or trace error. Independent fresh-container scoring resolved Ansible and correctly
  rejected Dubbo because its patch caused a Java interface compilation failure.
  Evidence: the two completed `baseline--seed-0` cells and their `score/result.json` records in
  `/mnt/optane/bifrost-nlp-resources/runs/granite-r2-cim-20260731-r1`.

- Observation: the official PolyBench evaluation applies both test and model patches first
  with `git apply --ignore-whitespace --reject`, then falls back to GNU `patch --batch
  --fuzz=5 -p1 -f`; importing its parser package normally also imports an unrelated Docker
  dependency.
  Evidence: the released PolyBench evaluation source and the Dubbo scoring smoke. The CIM
  scorer now mirrors the patch behavior and loads the official constants/parser modules
  without executing the package's unrelated initialization.

- Observation: staging all 91 official OCI images in rootless Podman's default graph root
  would consume the much smaller home filesystem.
  Evidence: 89 images were initially absent and `/home` had about 105 GB free. The campaign
  instead uses a generated `CONTAINERS_STORAGE_CONF` whose graph root is
  `/mnt/optane/bifrost-nlp-resources/podman-storage`; it is populated in parallel before the
  30-cell wave starts.

- Observation: repository embedding and task-image staging are independent storage pipelines.
  Granite's shared SQLite indexes live with the 15 primary clones under
  `/mnt/T9/repo-clones/<repo>/.bifrost/cache/`; the prepared task worktrees under
  `/home/jonathan/Projects/brokkbench/clones/` resolve each repository back to that primary
  cache. Podman stores immutable task-image layers in its configured graph root. Moving the
  graph root does not copy, invalidate, or rebuild an embedding index.

- Observation: `/mnt/containers` is a large XFS filesystem with project quotas and native
  overlay support, but its top level is root-owned. The existing `/mnt/containers/podman`
  namespace is user-owned; creating the specifically requested sibling
  `/mnt/containers/code_isnt_memory` requires one administrator-created directory before the
  controller can initialize its store.

- Observation: the initial r1 baseline wave was not sane: 6 of the first 17 completed traces
  attempted either repository-history inspection or web search, including RocketMQ 4122.
  Evidence: `/mnt/optane/bifrost-nlp-resources/runs/granite-r2-cim-20260731-r1/leak-audit.json`.
  The wave was stopped immediately and its cells are excluded from reportable results.

- Observation: cimeval's original max-reasoning launch was not actually using max. Mjolnir's
  known `MODEL+effort` suffixes ended at `xhigh`, so `+max` remained attached to the model wire
  ID and every r6 cell failed before its first LLM request. Anvil's Bedrock GPT metadata also
  omitted the provider's `max` preset. Mjolnir `f7ba210` and Anvil `3885f50` fix both sides; r7
  telemetry directly records Luna requests with `reasoning_effort: "max"`.

- Observation: Python's outer `subprocess.run(timeout=1800)` raised before cimeval captured any
  artifacts, and inline scoring made the recorded agent wall time include verifier time. This
  contradicted CIM's fixed 30-minute generation cap and `unsolved_timeout` accounting.
  Brokkbench `680d628e53d` makes the in-container runner PID explicit, captures timed-out cells
  as immutable unresolved attempts, and freezes agent wall time before inline scoring.

- Observation: container-wide network isolation is the wrong boundary because Anvil itself
  runs inside the official task container and needs network access to Bedrock. The task images
  do, however, provide `/usr/bin/unshare`, and a privileged official RocketMQ container
  successfully ran a repository-local command inside a fresh network namespace while DNS was
  unavailable.

- Observation: the first long Granite prewarm reached 9 repository READY records before a
  transient `cudaErrorUnknown` stopped the sidecar on Transformers. A direct A4000 tensor
  allocation succeeded immediately afterward; the sidecar was restarted on the same UUID and
  the serial prewarm resumed from the immutable READY records and shared SQLite caches.

- Observation: Bifrost already exposes semantic materialization counters through
  `SemanticIndexer::status`, but the profiling harness printed only the active-index chunk count
  (which remains zero until publication), and `cimeval` buffered that output until process exit.
  Bifrost commit `501f21e6` now adds the existing file numerator/denominator to the two-second
  profiler line; brokkbench commit `f91062e16bb` streams profiler output directly to the task
  logs. The resumed Trino revision exposed a live denominator of 1,291 missing files without a
  new progress protocol.

- Observation: semantic file extraction was a single producer loop and dominated Trino index
  construction: the first Trino revision spent about 2,692 of 2,710 seconds in extraction while
  GPU embedding took 172 seconds. Bifrost issue #1413 records the regression and WSL profiling
  limitations. Commit `e36d4e6e` extracts files in a Rayon indexed parallel iterator, merges in
  input order, and removes the nested per-file summary Rayon call. Its exact serial/parallel
  equivalence test, focused NLP tests, formatting, and NLP-library clippy pass. On the live
  resumed Trino index CPU utilization rose from about one core to 30-45 cores; the entire
  remaining 1,025-file delta and subsequent shared-cache checks completed in 366.4 seconds.

- Observation: 64 concurrent analyzer-store readers make process RSS look much worse than
  physical memory use because each connection maps the same SQLite pages. During Trino the
  process reported about 15.2 GB RSS, but `smaps_rollup` showed 9.8 GB shared-clean mappings,
  5.5 GB proportional usage, and 5.1 GB private memory. The private portion is consistent with
  the configured 64 MiB page cache per reader. This is future per-reader tuning work, not a
  blocker on the 98 GiB eval host.

- Observation: the synthetic-root checkout scrub failed deterministically for Vuls task
  `instance_future-architect__vuls-bff6...` because its source tree contains a Gitlink. Deleting
  `.git` and re-adding the working tree flattened that entry and changed the tree hash.
  Brokkbench commit `a8012514ec6` now creates the isolated root commit directly from the
  verified tree with `git commit-tree`, repoints `HEAD`, and prunes old history. A Gitlink
  regression test and the exact official task both pass setup.

- Observation: OpenLibrary's official images contain populated `vendor/infogami` and
  `vendor/js/wmd` submodules whose worktrees can be dirty relative to an older selected task
  base. The outer synthetic tree stayed exact, but the final clean-status invariant correctly
  failed on `M vendor/infogami`. Brokkbench commit `25057197bb3` resets and cleans every
  populated submodule to its recorded Gitlink, retains the dependency files, removes all
  nested Git metadata and module object stores, and makes the outer status ignore those
  metadata-free worktrees. A dirty real-submodule regression passes, and both formerly failing
  official OpenLibrary cells now pass the scrub and reach Luna.

- Observation: the run controller's exception handler attempted to cancel futures only after
  leaving the `ThreadPoolExecutor` context. Python's context manager waits for the queue before
  control reaches that handler, so the first scrub failure caused opaque queued work instead
  of prompt cancellation. Commit `58bb0a1b4e9` moves cancellation inside the context; the full
  15-test cimeval suite and Ruff pass. An obsolete one-worker reproduction was interrupted and
  its single explicitly identified orphaned Teleport sandbox was removed before resuming.

- Observation: after `/mnt/containers` ownership was corrected to `jonathan:jonathan`, the
  controller created `/mnt/containers/code_isnt_memory/podman-storage` and verified rootless
  native-overlay operation on XFS. Parallel image pulls initially showed zero committed images
  while their first multi-gigabyte layers unpacked, despite 4.24 GB already present; committed
  image IDs then began appearing normally.

- Observation: the initial r3 score of 15/71 resolved was invalid rather than a Luna capability
  result. Direct Podman execution used `bash -lc`, which reset the task image's OCI `PATH`, and
  the cimeval remote runner independently replaced `PATH` with a generic Unix path. Thirty-three
  scored cells logged a missing Go command, and generation had the same environment defect.
  Evidence: Flipt e2bd's score log says `go: command not found` despite its official image
  containing `/usr/local/go/bin/go`; an OCI-preserving smoke reports Go 1.24.3. Brokkbench
  commit `d508bd1c4a4` uses non-login direct shells and prepends the runtime paths instead.

- Observation: the r4 Flipt smoke's fresh official scorer successfully invoked Go and reported
  real candidate-patch compilation errors, but its generation trace showed the first unqualified
  `gofmt` still failed. Generation uniquely uses `DirectPodmanSandbox::run_with_secret_env`,
  whose shell remained `bash -lc` after the ordinary run/popen fix; the agent recovered only by
  exporting `/usr/local/go/bin` itself. Brokkbench commit `6f80c498bc5` makes that final transport
  non-login too and extends the exact-argv regression test.

- Observation: the corrected r5 baseline is operationally clean but fails the precommitted
  token-effort gate. It completes and scores all 91 cells, resolves 31 (34.1%), averages 47.5
  tool calls and 444.4 seconds, and has no provider terminal errors or unmitigated leak-audit
  findings. Mean uncached usage is 49.6k tokens (median 46.0k; 81/91 exceed 30k), compared with
  CIM SC-OFF's published roughly 11.1k input-plus-output mean on Claude Opus 4.7. Mjolnir's
  mean components are 42.0k input, 4.8k output, and 2.8k thought tokens, so this is not caused
  by accidentally counting the 862k mean cached reads as uncached usage.
  Evidence: r5 `report.json`, `leak-audit.json`, all terminal Mjolnir usage records, and the
  released CIM `results_public.csv`. Per the hard gate, no later seed has been scheduled.

- Observation: Anvil's trace contains the complete structured messages needed to reproduce
  CIM's dual-view localization rule without proxy logs or heuristic ACP-title parsing.
  Evidence: each latest `llm_request` carries assistant tool arguments, tool-call IDs, and tool
  results; `llm_response` supplies the terminal assistant step. On 25 completed no-semantic r8
  cells, the adapted extractor produced zero skips, identical View A/View B metrics, and 44%
  Acc@5 against CIM's published 44.3% no-index value.

- Observation: one benchmark cell can open more than one fresh primary Anvil session, so
  session-local state cannot enforce a once-per-cell synthetic prologue.
  Evidence: diagnostic r2's RocketMQ 4122 trace contained two complete synthetic start/end
  intervals 14 minutes apart. The runtime configuration file is cell-scoped, so an atomic
  sibling claim file provides the correct process-independent boundary.

- Observation: later Luna-initiated semantic searches are legitimate and must not be confused
  with the synthetic prologue when validating one-rerank-per-generated-query provenance.
  Evidence: the completed r3 cohort has 86 synthetic reranks inside the 34 step-zero intervals
  and two later agent-origin reranks. Scoping validation to the interval retains the strict
  synthetic invariant without forbidding normal follow-up use.

## Decision Log

- Decision: this delivery implements and evaluates Granite R2 only.
  Rationale: Granite is the smaller checkpoint and gives the fastest end-to-end validation of
  the model, retrieval, reranker, container, and scoring architecture. Dw10 is a later phase.
  Date/Author: 2026-07-31, user.

- Decision: use the local NVIDIA RTX A4000 for Granite inference and index construction.
  Rationale: it is locally available and a single Bifrost indexing job is sufficient to
  saturate it.
  Date/Author: 2026-07-31, user.

- Decision: run Granite index construction at concurrency one.
  Rationale: extra repository indexers would contend for the already saturated A4000 rather
  than improve throughput.
  Date/Author: 2026-07-31, user.

- Decision: parallelize extraction within that single repository indexer using Rayon's host
  thread pool, but preserve the input order during the serial merge and keep GPU/indexer
  concurrency at one.
  Rationale: the GPU is still saturated by one repository pipeline, while tree-sitter/summary
  materialization was independently single-core and dominated wall time. Indexed collection
  and deterministic global deduplication retain the persisted batching contract.
  Date/Author: 2026-07-31, user and Codex.

- Decision: use Bifrost's `semantic_index_profile` production-pipeline binary as the serial
  prewarm worker rather than teaching the controller to infer readiness from a one-shot query.
  Rationale: it already holds the process open, uses the same `SemanticIndexer`, waits for the
  ready/failed terminal phase, emits progress, and honors `BIFROST_CACHE_DIR` plus the remote
  Granite endpoint. This is the smallest reliable readiness contract.
  Date/Author: 2026-07-31, Codex.

- Decision: clone the 15 unique upstream benchmark repositories in parallel under
  `/home/jonathan/Projects/brokkbench/clones/` and materialize all 91 task revisions as
  worktrees as the first execution step.
  Rationale: baseline execution, scrub validation, and Granite prewarming should not wait on
  serial network preparation.
  Date/Author: 2026-07-31, user.

- Decision: use one no-semantic-search baseline arm with GPT-5.6 Luna on Mjolnir/Anvil.
  Rationale: it validates the agent, provider, official containers, scorers, and workload before
  semantic-search changes can influence outcomes.
  Date/Author: 2026-07-31, user.

- Decision: baseline seed 0 is a hard gate. Do not schedule seeds 1 and 2 unless it is sane.
  Rationale: three full replicates are wasteful if seed 0 exposes provider, scorer, leak, or
  harness defects.
  Date/Author: 2026-07-31, user.

- Decision: proceed after the corrected maximum-effort seed 0 despite retaining the token-band
  check as a failed comparability warning.
  Rationale: the final seed resolves 49/91 (53.8%), averages 39.6 turns, has baseline Acc@5
  50.5%, zero provider/scorer failures, and zero unmitigated leak findings. These outcome and
  behavior measures are sane against CIM. The 152.8k uncached-equivalent usage is a genuine
  Luna-max effort/cost difference from CIM's Claude Opus 4.7 cells, not evidence that the run is
  malfunctioning; reducing reasoning effort would contradict the user's explicit correction.
  Date/Author: 2026-07-31, Codex.

- Decision: keep model-provider networking in the task container, but run every Anvil shell
  child in a fresh Linux network namespace when `ANVIL_OFFLINE_SHELL` is set; reject any
  outside-sandbox shell override in that mode. Also remove web tools and replace task Git
  history with a single tree-identical root commit.
  Rationale: this preserves arbitrary local build/test commands and Bedrock access without
  relying on command-text filters, while physically removing all three observed leak paths.
  Date/Author: 2026-07-31, Codex.

- Decision: finish r8 under its uniformly loaded synthetic-root/no-history protocol, expose
  only task-head-reachable ancestry by default in subsequent campaigns, and retain an explicit
  `--without-history` mode for controlled comparisons.
  Rationale: no history is a defensible and internally consistent current control, while
  changing a live controller would mix agent capabilities. Future runs should retain legitimate
  pre-task `log` and `blame` information but must physically exclude post-head solution objects;
  an official Pro image contained 237 refs and 15,533 objects outside the task-head closure, so
  a plain checkout is not an adequate leak boundary.
  Date/Author: 2026-08-01, user and Codex.

- Decision: r1 is an invalid diagnostic run, r2 is an unused preflight attempt, and r3/r4 are
  invalid task-environment runs. The first reportable campaign identity is now
  `granite-r2-cim-20260731-r5`, with brokkbench environment fixes `d508bd1c4a4` and
  `6f80c498bc5`; it reuses the byte-identical r3 agent binary bundle but copies the corrected
  runner and uses the corrected direct-Podman transport for every fresh cell.
  Rationale: completed cells and runtime bundles are immutable; a new identity prevents fixed,
  contaminated, and toolchain-deficient artifacts from being silently mixed.
  Date/Author: 2026-07-31, Codex.

- Decision: use independent run replicates labeled seeds 0, 1, and 2; pass a provider sampling
  seed only if both Luna provider paths support the same parameter.
  Rationale: CIM's released use of “seed” denotes repeated pass@1 trials; its private generation
  harness does not document an exact provider seed knob.
  Date/Author: 2026-07-31, user and Codex.

- Decision: pin all remaining generation and scoring waves at concurrency 30; do not escalate
  later seeds even when the current wave has temporary headroom.
  Rationale: another workstation workload is expected to spin up and may create higher
  contention after the current measurements. Granite index construction remains separately
  serialized, and load sampling remains diagnostic rather than an escalation trigger.
  Date/Author: 2026-07-31, user.

- Decision: default cimeval to inline scoring in the live generation sandbox, while retaining
  the separate pristine-container scorer as an explicit mode and for older completed cells.
  Rationale: avoiding a second container provision per cell materially reduces campaign wall
  time and eliminates a separate scoring tail. The user accepts the corner-case accuracy risk
  from verifier setup observing agent-mutated container state or a hidden patch interacting
  differently with the live checkout. Total worker concurrency remains capped at 30.
  Date/Author: 2026-07-31, user and Codex.

- Decision: supersede the accepted inline corner-case loss with selective versioned pristine
  fallback whenever the held-out patch cannot apply to the live agent checkout.
  Rationale: overlap occurred in 43/91 cells, so it was not a corner case. Successful inline
  scores still avoid a second container. Conflicts preserve the inline diagnostic, then use
  Git-parsed held-out paths to omit agent edits to hidden-test files while applying production
  changes and running the official scorer in a fresh task image. Reports prefer only a completed
  v2 fallback, preserving immutable provenance and scorer fidelity.
  Date/Author: 2026-07-31, Codex.

- Decision: Anvil uses retrieval overfetch multiplier `m=2`; model-facing `k` has minimum 1,
  maximum 20, and default 20.
  Rationale: `k` is the final reranked-result ceiling. Bifrost needs a wider candidate pool for
  relevance filtering.
  Date/Author: 2026-07-31, user.

- Decision: a valid reranker result may contain fewer than `k`, including zero, and Anvil does
  not refill it.
  Rationale: relevance filtering should be allowed to reject irrelevant candidates.
  Date/Author: 2026-07-31, user.

- Decision: freeze runtime identity in every reportable semantic cell and treat a candidate
  rerank with zero attached context as a campaign validity failure, not merely a quality metric.
  Rationale: immutable bundle names alone do not prevent resume from accepting an older completed
  cell, and names-only reranking is materially different from the intended source-aware Anvil
  design even when retrieval counts and final `k` appear correct.
  Date/Author: 2026-07-31, Codex.

- Decision: every Granite retrieval arm presents a nominal `6k` pre-rerank pool.
  Rationale: this holds reranker opportunity approximately constant while ablating retrieval
  signals.
  Date/Author: 2026-07-31, user and Codex.

- Decision: share one live writable Bifrost DB per `(upstream repository, Granite model)` across
  that repository's task revisions, retrieval arms, and seeds.
  Rationale: this is Bifrost's intended content-addressed cross-worktree design. Every process
  bind-mounts the same DB/WAL/SHM directory and lets SQLite provide real locking; no per-cell
  copy or copy-on-write snapshot is needed. Connection-local active membership must ensure that
  content cached from another task revision is never surfaced unless it belongs to the current
  working tree.
  Date/Author: 2026-07-31, user.

- Decision: use one LLM provider for the baseline and Granite phases reported together.
  Rationale: provider behavior must not be confounded with semantic-search condition.
  Date/Author: 2026-07-31, user and Codex.

- Decision: use Bedrock Luna only if preflight passes; otherwise lock the entire delivery to
  OpenRouter Luna. Never mix providers in the reported cells.
  Rationale: Bedrock was recently flaky.
  Date/Author: 2026-07-31, user and Codex.

- Decision: store reportable campaign OCI layers under
  `/mnt/containers/code_isnt_memory/podman-storage` using XFS-native overlay rather than under
  the Optane resource root or rootless Podman's default home graph root. Preserve the old
  Optane store until the new image inventory and a task-container smoke test pass.
  Rationale: the 91-image official task set is large, `/mnt/containers` is the dedicated large
  XFS volume, and native overlay avoids the FUSE workaround required by the previous store.
  Every generation and scoring process receives the same generated storage configuration so
  image identity and reuse remain consistent.
  Date/Author: 2026-07-31, user and Codex.

- Decision: after the Granite campaign, evaluate dw10 only with `semantic-coedit-2-1` over all
  three seeds; do not run a second three-arm grid.
  Rationale: the user explicitly superseded the earlier Granite-only stopping point and chose
  the best recipe to limit additional campaign cost while still comparing fine-tunes under the
  same baseline, task set, final `k`, and no-history protocol.
  Date/Author: 2026-08-01, user.

- Decision: store dw10 and Granite embeddings in distinct per-repository cache namespaces.
  Rationale: a Bifrost database is safely shared across branches and worktrees, but its semantic
  tables intentionally support only one embedding fingerprint at a time. Reusing Granite's
  database for dw10 would wipe the completed Granite vectors during compatibility checking.
  Date/Author: 2026-07-31, Codex.

- Decision: represent dw10 as an explicit Bifrost/sidecar model profile rather than serving it
  through the stock Voyage profile.
  Rationale: the fine-tune deliberately uses `parent_alpha=0.65`, whereas stock Voyage uses
  0.5. The profile is part of the semantic-index fingerprint, so this makes incompatible
  vectors self-invalidating and keeps serving and indexing on the same contract.
  Date/Author: 2026-07-31, Codex.

- Decision: accept only a `queries` array of one through three strings in Anvil's public
  `semantic_search` contract; `k` remains a per-query final ceiling. Bifrost's raw tool remains
  scalar, and Anvil fans the array out into concurrent scalar calls.
  Rationale: batching is an agent-facing convenience and does not change retrieval semantics.
  Keeping batching above Bifrost avoids an unnecessary raw API change while allowing its
  embedding service to queue concurrent requests naturally.
  Date/Author: 2026-08-02, user and Codex.

- Decision: rerank every query independently with its own DSV4Flash utility call and preserve
  overlapping candidates in each query's ordered section. Do not construct a global candidate
  pool, globally rerank, normalize scores, or deduplicate across queries.
  Rationale: the query-specific relevance judgments are the intended treatment. Compact locator
  cards make repeated evidence inexpensive, so cross-query normalization is unnecessary and
  would change the previously established reranker behavior.
  Date/Author: 2026-08-02, user.

- Decision: retain rich source and file-summary excerpts only inside the disposable reranker
  prompt. Return structured locator cards containing exact Bifrost signatures and line ranges;
  for file candidates, ask that same query's reranker to choose at most five relevant
  declaration signatures.
  Rationale: the trajectory audit found that agents reread virtually every selected source
  before editing it. Signatures provide enough orientation to choose the next exact read while
  avoiding large, frequently duplicated bodies in Luna's persistent context.
  Date/Author: 2026-08-02, user and Codex.

- Decision: treat one 34-task DW10 seed as the compact-signature evaluation point and stop
  unless it is significantly better than the prior comparable seed.
  Rationale: the checkpoint is an explicit gate before spending two more seeds. Its 12/34
  result has zero paired mean difference and exact p=1.0, so it fails the gate.
  Date/Author: 2026-08-02, user and Codex.

## Outcomes & Retrospective

The campaign is complete. It contains 1,365 reportable cells: 273 no-semantic baseline cells,
819 Granite cells across three retrieval arms, and 273 dw10 cells for the selected vector plus
co-edit recipe. There are no exclusions or missing scores. Every cell used Bedrock GPT-5.6 Luna
at maximum reasoning in an official task image with synthetic-root/no-history Git exposure.

The later compact multi-query DW10 checkpoint is a separate 34-cell paired experiment, not an
extension of the 1,365-cell grid. It returned structured Bifrost signatures instead of source
bodies, accepted one to three queries in one Anvil call, and independently reranked each query.
It solved 12/34 (35.3%), exactly equal to the comparable prior cohort, with Apollo changing to
solved and Gson 2071 changing to unsolved. Exact paired analysis reports one gain, one loss,
and p=1.0. The 30 unchanged-query tasks declined from 11/30 to 10/30, while the four capped-query
tasks improved from 1/4 to 2/4. Mean caller-visible signature coverage was 98.0%; all 86
synthetic query reranks had context and none fell back. The result does not support spending
two more seeds, so the follow-up stops here as precommitted.

Against the same 34 tasks in the three-seed no-semantic baseline, the compact checkpoint's
12 solves match baseline seeds 1 and 2 and exceed seed 0's six; the baseline seed mean is 10.
This is ordinary run-to-run variation, not solve-rate evidence. Retrieval did improve measured
localization: compact View B Acc@5 is 27/34 (79.4%), versus 13/34, 16/34, and 16/34
(38.2%-47.1%) for the three no-semantic seeds. The remaining bottleneck is therefore turning a
good semantic shortlist into inspection and a correct patch, rather than simply finding a gold
file.

### Results

| Embedding / arm | Solved | Resolve | View B Acc@5 | Mean turns | Mean uncached tokens | Mean cost/cell | Total cost |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| no semantic baseline | 142/273 | 52.0% | 51.3% | 41.4 | 150,906 | $0.489 | $133.52 |
| Granite all signals | 147/273 | 53.8% | 53.5% | 44.9 | 253,603 | $0.799 | $218.26 |
| Granite semantic only | 149/273 | 54.6% | 49.5% | 44.5 | 233,317 | $0.749 | $204.58 |
| Granite vector + co-edit 2:1 | 150/273 | 54.9% | 52.0% | 43.8 | 232,229 | $0.744 | $203.21 |
| dw10 vector + co-edit 2:1 | 146/273 | 53.5% | 50.5% | 44.0 | 263,132 | $0.813 | $221.94 |

Granite vector plus co-edit has the best observed task result, 2.93 percentage points above the
baseline. Granite semantic only is +2.56 points and all signals is +1.83 points. Their paired
per-instance resolve p-values against baseline are 0.170, 0.228, and 0.376 respectively, so the
campaign does not establish that any Granite arm improves solve rate. The all-signals arm did
not outperform either reduced arm; its extra BM25 leg increased tokens and cost without a
measurable task benefit.

dw10 finishes at 53.5%, 1.47 points above baseline and 1.47 points below comparable Granite.
Against Granite it has 11 cell-level exclusive solves and 15 exclusive losses; the exact
discordant-pair p-value is 0.557. The plan's CIM-style per-instance seed-mean Wilcoxon comparison
also finds no difference (resolve p=0.206, View B Acc@5 p=0.328). Against baseline, dw10's
resolve p-value is 0.533. dw10 therefore shows no evidence of an advantage over Granite and is
also more expensive: $221.94 total and $1.520 per solve versus Granite vector plus co-edit's
$203.21 and $1.355 per solve.

Tool choice remained agent-controlled as in CIM. Only three Granite vector-plus-co-edit cells
and seven dw10 cells selected semantic search, so the task-level comparison primarily measures
the value of making each localizer available to the agent, not standalone retrieval quality.
Every observed call realized the requested candidate budgets, returned at most final `k=20`,
attached source context, and avoided fallback. dw10's seven calls all realized `80/0/40`; no
final-k violation occurred. Some dw10 calls experienced large initial readiness/embedding queue
waits under the shared 30-worker host, making the sparse latency samples unsuitable for a model
speed comparison.

The baseline is operationally sane beside CIM's published no-index references: its 52.0% solve
rate is above CIM SC-OFF's 40.2%-43.9% and OpenCode's 44.4%-45.7%, plausibly reflecting Luna at
maximum reasoning and a different agent. The report's old 5,000-30,000 mean-token predicate is
not appropriate for maximum-reasoning Luna (observed baseline mean 150,906); task count, solve
rate, turns, manual traces, and leak review pass. Seeds are independent pass@1 replicates, not a
provider sampling-seed control.

Generation produced 998 completed and 94 timed-out agents for the 1,092 baseline/Granite cells,
plus 261 completed and 12 timed-out dw10 agents. Timeouts remained reportable and were officially
scored. Localization covers all 1,365 cells. Leak audits flagged zero: all 2,193 history attempts
and 83 network attempts were neutralized by the declared no-history and offline-shell controls.

### Change inventory

#### Bifrost (`/mnt/optane/bifrost-nlp`)

- `23af0cfa` replaces the hardcoded Voyage contract with fingerprinted model profiles, dynamic
  dimensions, configurable pooling/prefixes, and Granite R2 serving.
- `501f21e6` exposes file-level materialization progress; `e36d4e6e` parallelizes extraction
  across host cores while preserving deterministic serial ordering.
- `bac89d82` adds the separately fingerprinted dw10 profile and its `parent_alpha=0.65` contract.
- `71e8ac64` records embedding queue/service and readiness timings; `fcaf3a78` waits for the
  initial semantic index without removing bounded stale-index behavior on later rebuilds.
- `8c82afe3` isolates the real MCP missing-model test from shared checkout caches; `dc674f22`
  keeps the affected NLP tests clean under the current all-target clippy gate.
- `ee4e9485`, `6e8a6ff8`, and `362dc8b8` specify and gate the compact multi-query follow-up and
  let independent writers to a shared semantic cache serialize through a 120-second SQLite
  busy timeout rather than failing immediately under evaluation load.

#### Anvil (`/mnt/optane/anvil-bifrost-nlp-ft`)

- `e002ba4` makes model-facing `k` the documented final result ceiling (default/max 20), tells
  the model that fewer results may be returned, forwards `m=2`, equalizes the three raw pools,
  and accepts valid empty/fewer reranker selections without refilling.
- `71c6346` provides bounded evaluation turns; `b385af1` runs offline shell commands inside an
  isolated network namespace; `3885f50` advertises and forwards Bedrock maximum reasoning.
- `709f227` freezes retrieval telemetry in reranker traces; `c4483eb` fetches the entire bounded
  candidate pool in RRF-order batches and accepts compact file outlines, ensuring the reranker
  receives source context.
- `243e5f2`, `c368264`, and `0d83797` add one-to-three-query calls with concurrent but independent
  per-query retrieval/reranking, best-effort structured signature cards, and signature-preserving
  summary requests. `4043043` makes CIM synthetic step zero once-per-cell across fresh sessions.

#### Mjolnir (`/mnt/optane/mjolnir-bifrost-nlp-ft`)

- `3e046fc` routes an explicit provider-qualified model through an available Anvil server even
  when a transient discovery snapshot omits it.
- `f7ba210` parses and preserves the `+max` per-seat reasoning override.
- `26a3084` seeds the selected Anvil process with its exact model and reasoning effort before
  optional catalog discovery, removing that network call from startup correctness.

#### brokkbench and sandbox infrastructure (`/home/jonathan/Projects/brokkbench`)

- The campaign harness spans `e05760f759f` through `fbfc8cd61e1`. It adds an independent
  `cimeval` workflow without changing agenteval defaults: official direct-Podman task images,
  fail-closed Git/network controls, resumable Cartesian scheduling, immutable runtime identity,
  model-specific shared caches, serial GPU prewarming, inline scoring, versioned pristine
  recovery, CIM-compatible localization, leak auditing, retrieval telemetry, and paired reports.
- Key checkpoints include `64a2da6131f` (one multi-seed worker pool), `02598f37ad9` (inline
  scoring), `8f861239a8c` (localization), `6a94ce2b4ef`/`3ce7216dbc0` (telemetry/statistics),
  `6c62b71b247`/`83a8979c9a5` (runtime identity), `a8d05bfc441`/`784e2e31aad` (selective versioned
  scorer recovery), `401cb407962` (explicit history modes), and `fbfc8cd61e1` (per-cell embedding
  profile identity).
- `f8cd8ba4f9c`, `637df9f40a4`, `d9a829a07d3`, `fab95d76890`, and `3b7a7791928` define the
  three-query compact checkpoint, report signature telemetry, compare the selected external
  arm, serialize same-repository shared-cache cells, and validate synthetic provenance only
  inside step zero.

No product repository has an uncommitted campaign diff. brokkbench contains unrelated user
changes and artifacts outside the owned `cimeval`/sandbox scope; those were preserved.

## Context and Orientation

The primary Bifrost checkout is `/mnt/optane/bifrost-nlp`, branch `bifrost-nlp-ft`. Commit
Bifrost work directly to that branch. Preserve the user's untracked `code_isnt_memory.md`.

The implementation ultimately changed four repositories:

1. `/mnt/optane/bifrost-nlp`: Granite model serving, dynamic embedding shape, retrieval
   profiles, shared-cache validation, and Bifrost tests.
2. `/home/jonathan/Projects/anvil`, developed through a clean worktree at
   `/mnt/optane/anvil-bifrost-nlp-ft`: model-facing schema, overfetch, bounded reranking,
   fallback, telemetry, and tests.
3. `/home/jonathan/Projects/mjolnir`, developed through
   `/mnt/optane/mjolnir-bifrost-nlp-ft`: explicit Anvil routing, maximum effort parsing, and
   deterministic startup configuration.
4. `/home/jonathan/Projects/brokkbench`: minimal sandbox port forwarding plus a new, separate
   `cimeval` harness, tests, and analysis/reporting code.

The Granite artifact is:

    /home/jonathan/Projects/brokkbench/localizer/artifacts/granite-r2-small-v4-final

Its serving contract is:

    architecture: ModernBertModel
    query prefix:
      "Given a GitHub issue, retrieve code that must be changed to fix it.\nQuery: "
    passage prefix: "Passage: Code chunk from repository.\n"
    pooling: CLS token, including the prompt
    served width: 384, then L2 normalize
    maximum sequence length: 8192
    parent composition: L2 normalize(0.65 * child + 0.35 * parent)

The exact sample is
`/mnt/optane/bifrost-nlp-resources/supercoder-eval/data/manifest_frame.csv`: 91 instances from
SWE-PolyBench and SWE-bench Pro across Go, Java, and Python. Use the official dataset metadata
to map every instance to its repository URL, base revision, problem statement, image tag,
scorer, and gold paths.

Create one full-history clone per unique upstream repository under:

    /home/jonathan/Projects/brokkbench/clones/<repo-key>

Do not use external Git alternates, hardlinks, or partial clones for the primary clones. Create
one worktree per manifest instance at its official base revision. These host worktrees are the
source for serialized Granite prewarming and deliberately share their primary repository's
Bifrost DB. They are not the official leak-isolated agent filesystem: each official cell still
gets a fresh brokkbench sandbox checkout that passes the fail-closed Git scrub before the agent
starts. The scrubbed sandbox must not expose future refs, reflogs, alternates, or forbidden
objects. Sharing a host primary clone and Bifrost DB therefore does not weaken the cell's Git
object isolation.

A cell is one `(instance, arm, seed)` run. The completed campaign contains:

    baseline: 91 instances * 1 no-semantic arm * 3 seeds = 273 cells
    Granite:  91 instances * 3 retrieval arms * 3 seeds = 819 cells
    dw10:     91 instances * 1 retrieval arm  * 3 seeds = 273 cells
    total:                                                   1,365 cells

The Granite retrieval arms use final model-facing `k`, Anvil multiplier `m=2`, and Bifrost base
depth `b=2k`:

    all-signals:          vector=b,  BM25=b, co-edit=b       (nominal 6k total)
    semantic-only:        vector=3b, BM25=0, co-edit=0       (nominal 6k total)
    semantic-coedit-2-1:  vector=2b, BM25=0, co-edit=b       (nominal 6k total)

The baseline has no semantic-search tool at all. Start Bifrost with semantic indexing disabled
so Anvil still receives the normal structural tools but does not advertise `semantic_search`.

## Plan of Work

### Milestone 1: materialize the sample before the main implementation

As the first execution work, implement only the minimal `cimeval prepare` manifest reader and
clone worker needed to resolve official dataset rows, create the 15 unique upstream clone
targets, and materialize the 91 task worktrees. Start all 15 clones in parallel, before the
remaining Bifrost/Anvil/harness implementation. Record URL, every required base commit, clone
start/end, Git version, and final object-set hash. Retry transient network failures without
deleting a valid completed clone.

Run scrub verification in each fresh official sandbox checkout before starting its cell. Strip
every remote, tag, replace, hidden, and future ref and every reflog; expire reflogs; run
`git gc --prune=now`; then compare the surviving objects against permitted base ancestry and
known forbidden gold/future objects. Mark the instance unusable and do not launch an agent if
this proof fails. Do not destructively scrub the shared host primary clones or their worktrees.

While clones run, continue implementing later milestones. Do not wait for all network work to
finish before editing code, but do not start baseline cells or Granite indexing for an
incomplete/unverified clone.

Acceptance: preparation accounts for 15 primary clones and all 91 task worktrees, and every
official cell sandbox is verified or failed closed with evidence. No primary clone or official
sandbox uses an external alternate object directory.

### Milestone 2: serve Granite R2 correctly in Bifrost

Introduce a model-profile abstraction next to `nlp/engine.rs` that carries exact prefixes,
pooling, dimension, maximum sequence length, parent alpha, representation version, and artifact
identity. Implement `granite-r2`; keep the existing Voyage behavior working where existing
tests require it, but do not implement or test dw10 in this delivery.

Add explicit configuration:

    BIFROST_EMBED_PROFILE=granite-r2
    BIFROST_EMBED_MODEL_DIR=<Granite artifact directory>
    BIFROST_EMBED_ENDPOINT=tcp://127.0.0.1:<port>
    BIFROST_EMBED_TOKENIZER_DIR=<tokenizer/config-only directory in a task container>

Refactor the Python sidecar into a profile-driven `scripts/embedding_sidecar.py`. Local
subprocess mode retains the existing framed stdin/stdout transport. TCP mode listens only on
host loopback and uses the same length-prefixed request and float-matrix response. The ready
frame reports profile, dimension, and authoritative fingerprint. The Rust side verifies all
three.

Load Granite through Transformers' native `ModernBertModel`, apply the external prefixes byte
exactly, perform CLS pooling, emit 384 float values, and L2-normalize. Make Rust vector
composition, quantization, store/index metadata, and query scoring dimension-dynamic. Change
parent composition to the selected profile's alpha, 0.65 for Granite.

The fingerprint must cover model configuration and weights, prefixes, pooling, dimension,
maximum sequence length, parent alpha, precision, representation/chunker/BM25 versions, and
backend. A mismatch must be detected before a shared DB is used. Do not publish or copy model
weights into task containers.

From the host context, identify the RTX A4000 by reported model name and UUID. Pin the Granite
service with `CUDA_VISIBLE_DEVICES=<A4000 UUID>`; do not assume device 0. Fail before indexing if
the selected device is not an A4000 or PyTorch reports a different device. Run exactly one
repository indexer at a time through this service.

Acceptance: a fixed query/passage fixture matches SentenceTransformers within a documented
precision tolerance, vectors have 384 finite unit-normalized values, and the parent-composed
vector matches `normalize(0.65 * child + 0.35 * parent)`.

### Milestone 3: implement the three query-time retrieval profiles

Add `BIFROST_SEMANTIC_SEARCH_PROFILE` with `all-signals`, `semantic-only`, and
`semantic-coedit-2-1`; default to `all-signals`. Parse it once during service construction.

Treat incoming raw Bifrost `k` as base depth `b`. Compute independent leg limits exactly as
shown in Context. In `all-signals`, seed co-edit from the weighted union of the top `b` vector
files and `b` BM25 files. In `semantic-only`, do not execute BM25 or co-edit. In
`semantic-coedit-2-1`, do not execute BM25 and seed co-edit from the top `2b` vector files.

Keep `vector_ranked`, `bm25_ranked`, `coedit_ranked`, and notes, with empty arrays for disabled
legs. Add retrieval-profile and requested/realized leg-count metadata for Anvil telemetry. Use
checked arithmetic and accept the needed per-leg maximum of 120.

Acceptance: behavior tests with fake embeddings/history demonstrate `40/40/40`, `120/0/0`,
and `80/0/40` at final Anvil `k=20`, plus corresponding budgets at `k=1` and an intermediate
value. Tests prove disabled code is not called and co-edit seeds come from the specified legs.

### Milestone 4: make Anvil k the final result ceiling

Fetch Anvil origin outside the restricted sandbox and create the clean worktree
`/mnt/optane/anvil-bifrost-nlp-ft`. Do not modify the dirty primary checkout.

Override the model-facing Bifrost schema so `semantic_search.k` has minimum 1, maximum 20, and
default 20. Both the property and overall tool descriptions say that `k` is the maximum number
of final relevance-reranked results and the reranker may return fewer by design.

Validate model input, retain `final_k`, and call Bifrost with `2 * final_k`. Remove fixed
30-symbol/20-file caps and deduplicate the full realized pool. Show every identity to the
disposable reranker while bounding source/summary context to 120,000 UTF-8 bytes globally and
8,000 bytes per candidate. Candidate metadata is never omitted.

A valid reranker selection of zero through `final_k` IDs is final and is not refilled. Drop
unknown/duplicate IDs and truncate overlong valid selections. On provider failure or malformed
structured output, use deterministic reciprocal-rank fusion over active legs and return at most
`final_k`; never expose raw three-list output. Include reranker tokens/cost in total usage.

Emit telemetry for final k, raw base depth, retrieval profile, requested and realized leg
counts, deduplicated count, context bytes, selected/final counts, fallback, and reranker usage.

Acceptance: schema, boundary, overfetch, 120-candidate prompt, fewer-than-k, empty, overlong,
malformed, provider-failure, and deterministic-fallback tests pass.

### Milestone 5: build the separate cimeval harness

Add `cimeval` beside `agenteval` in brokkbench. Reuse stable bundle and sandbox lifecycle code,
but do not change agenteval's task model or CLI. Add only the backward-compatible sandbox
capability needed to forward declared host loopback TCP ports into rootless Podman; the default
remains unchanged.

The cimeval CLI provides:

    prepare    resolve tasks, clones, dataset revisions, image tags, and image digests
    serve      start the Granite service pinned to the A4000
    prewarm    sequentially start Bifrost in each task worktree until its shared index is ready
    preflight  validate provider, binaries, containers, scorers, and traces
    run        execute/resume baseline or Granite cells with a fixed seed and concurrency
    score      run official scorers and CIM localization/leak extraction
    report     aggregate seed means, paired tests, load observations, and repo changes

Use `/mnt/optane/bifrost-nlp-resources/runs/<run-id>` for generated state. Build immutable
runtime bundles recording exact Bifrost, Anvil, Mjolnir, and brokkbench commits. Task containers
receive binaries and tokenizer/config metadata, not model weights.

Use official frozen task images and image-defined working directories. Generation and scoring
normally happen sequentially in the same fresh official task container: capture the agent patch
and artifacts, apply held-out tests, run the official scorer, then destroy the sandbox. Retain
an explicit pristine-container scoring mode for diagnostic replay and older completed cells.
Preserve manifests, scrub reports, Mjolnir streams, Anvil traces, patches, usage, candidate
telemetry, leak audits, official scores, load samples, and atomically written `COMPLETE` markers.

Acceptance: one PolyBench and one Pro no-semantic smoke produce replayable official scores, and
existing sandbox/agenteval targeted tests demonstrate no default behavior change.

### Milestone 6: prewarm Granite while baseline seed 0 runs

Lock the delivery to one provider before reportable cells. Try
`bedrock::openai.gpt-5.6-luna` with maximum main-agent reasoning. Run ten sequential
structured/tool calls and the two benchmark-family no-semantic smoke. If any call has an
unrecovered transport/stream/protocol error, select
`openrouter::openai/gpt-5.6-luna` instead and repeat preflight. Use the same provider for the
baseline, Granite agents, and Anvil reranker.

Start baseline seed 0 with 30 concurrent cells and semantic indexing disabled. At the same
time, start one long-lived Granite embedding service on the A4000 and a FIFO prewarm worker.
For each of the 91 task worktrees, launch Bifrost with Granite enabled and the upstream
repository's shared cache directory, wait until initial index status is ready and counts are
stable, record the DB/profile/tree identity, stop that Bifrost process cleanly, and continue to
the next worktree. Never run two initial Granite indexes concurrently. Traversing another
revision may reuse content-addressed vectors already present in that repository's DB while
updating only the launching connection's active membership.

The baseline and prewarm queues are independent: an instance may enter baseline as soon as its
host worktree and official sandbox inputs are ready, while the single GPU worker processes task
worktrees in deterministic manifest order. Baseline cells must not advertise semantic search
or connect to the Granite endpoint.

Store each of the 15 Granite DBs at its primary clone's real `.bifrost/cache` and mount that same
directory into every later arm/seed container for every task from that upstream repository.
Prewarm completes schema migration and fingerprint validation before creating a repository
`READY` manifest listing every prepared task revision. All later cell writers use the same DB,
WAL, and SHM host files. No migration, replacement, or invalidation is allowed while a cell has
the DB open.

Acceptance: baseline seed 0 and Granite prewarm make independent progress simultaneously; GPU
telemetry shows the A4000 is saturated by one indexer without a second indexer; all 15 completed
repository DBs have matching `READY` manifests accounting for their task revisions.

### Milestone 7: apply the baseline sanity gate and finish its replicates

Score and audit all seed-0 baseline cells before scheduling seed 1. The seed is sane only if all
of these hold:

1. At least 85 of 91 cells are legitimate after outcome-blind infrastructure/leak exclusions.
2. Unrecovered provider, sandbox, install, and scorer failures combined are at most five cells,
   with no failure concentrated in one benchmark family or language.
3. Resolve among legitimate cells is between 30% and 60%. This broad band contains CIM seed-0
   SC-OFF at 43.9% and OpenCode at 44.4% while allowing model/harness differences.
4. Mean turns are between 15 and 60 and mean total tokens are between 5,000 and 30,000. CIM's
   no-index references are approximately 35-36 turns and 10,700-14,100 tokens.
5. Leak audit finds no unexcluded gold/future access, and manual review of ten deterministic
   cells (five resolved, five unresolved when available) confirms valid task prompts, tool
   transcripts, patches, and scorer interpretation.

If any condition fails, stop new eval scheduling. Diagnose and fix root cause, rerun affected
smokes, and rerun baseline seed 0 from a new run identity. Do not waive a threshold based on
desired outcomes. If an apparently genuine Luna capability difference alone puts resolve
outside the band, document leak/scorer validation and ask the user before changing the gate.

If seed 0 passes, run seeds 1 and 2. Each is another clean independent replicate of the same 91
cells, and each runs at concurrency 30. Continue recording the following load signals to detect
interference from the user's other workstation workload, but do not use temporary headroom to
raise jobs:

    one-minute load average below 42 on the 60-core host
    mean CPU utilization below 70%
    memory utilization below 80% with no swap growth or OOM
    evaluated disk utilization below 70%
    provider throttle/retry rate below 2%
    no sustained scorer backlog longer than 60 seconds

Sample load at least every 30 seconds. If CPU, memory, or disk exceeds 90% for five minutes,
pause new launches and resume at 30, never below 30 unless continuing would
damage the host. Record every chosen concurrency and reason.

Acceptance: 273 expected baseline cells are complete or outcome-blind excluded, all use the same
provider, and per-seed/mean results are tabulated beside CIM SC-OFF and OpenCode references with
the model/harness difference clearly stated.

### Milestone 8: run the Granite retrieval grid

Do not begin until the baseline gate passed, all three baseline seeds finished, and every
eligible Granite DB has a matching ready manifest. Run all three retrieval arms within each
seed wave, balancing their order by deterministic instance hash so time/provider drift is not
aligned with an arm.

Run every Granite seed at concurrency 30 because semantic queries add A4000 service traffic and
shared-DB writers and the workstation is shared with another workload. Granite initial
indexing remains complete; query embeddings share
the one A4000 service, which must batch or queue requests rather than spawn per-cell models.

For every semantic-search call record final k, candidate budgets, realized and deduplicated
counts, reranker selection, final count, fallback, queue time, and embedding latency. Run a
two-container shared-DB smoke before the grid: both writers bind the same host DB/WAL/SHM,
change independent worktrees, query concurrently without cross-active results or unrecovered
SQLite locking errors, then pass `PRAGMA integrity_check` after close.

Acceptance: 819 expected Granite cells are complete or outcome-blind excluded, no response
exceeds requested k, the observed raw budgets agree with the selected profile subject to corpus
scarcity/deduplication, and all cells use the baseline's provider and Luna configuration.

### Milestone 9: score, report all three repos, and stop

Adapt CIM's released localization extractor. View A includes paths in agent-visible Anvil final
results, other tool targets, and edits; it excludes hidden raw Bifrost candidates. Canonical
View B removes paths introduced only by semantic-search results but retains later targeted use.
Report accuracy/recall at 1, 3, 5, and 10 plus exploratory 20, first-gold rank, and edit
precision/recall.

For the baseline and each Granite arm report official resolve, cost/cell, cost/solve, turns,
tokens, wall time, localization, edits, exclusions, and infrastructure/fallback rates. Report
mean of seed means and across-seed standard deviation. Run two-sided paired Wilcoxon tests on
per-instance seed means for:

    each Granite arm versus the no-semantic baseline
    all three pairwise comparisons among Granite arms

Use legitimate paired intersections and report paired n, nonzero n, paired difference, and raw
two-sided p-value. Treat multiple arm comparisons as exploratory.

Write `.agents/docs/granite-r2-cim-semantic-search-evaluation.md`. It must begin with a concise
inventory for each changed repository: starting/final commit, commits made, behavior changed,
files/modules affected, tests and lint run, and remaining work. Then give provider selection,
clone/scrub status, A4000/prewarm throughput, concurrency/load decisions, baseline sanity gate,
published CIM comparison, Granite results, candidate/reranker diagnostics, exclusions, and
reproduction commands.

Update this plan's living sections and commit the report. Stop after reporting. Do not load,
serve, implement, index, or evaluate dw10 until the user gives the next instruction.

### Milestone 10: compact query-local reranking and the queried DW10 checkpoint

Change Anvil's advertised `semantic_search` input from scalar `query` to `queries`, an array of
one through three whitespace-normalized strings that are unique ignoring case. The public `k`
field remains an integer from one through 20 and applies independently to each query. Anvil must
start up to three complete pipelines concurrently. Each pipeline forwards only its scalar query
and `2*k` to Bifrost, parses and enriches only that query's candidates, and sends those candidates
to its own DSV4Flash reranker. Collect results in input order and render one explicitly labeled
section per query. A candidate may appear in more than one section. There is no global pool,
rerank, normalization, or cross-query deduplication.

Extend Anvil's internal candidate representation with structured declaration locators obtained
from Bifrost `get_summaries`. Each locator has a stable prompt-local ID, exact signature text,
symbol, kind, path, and start/end line. Keep the existing bounded full source or rendered summary
as private reranker context. Ask the utility model to return ordered relevant candidate objects
and, when locators exist, one through five valid locator IDs for each selected candidate. Reject
malformed or unknown selections through the existing failure policy: CIM fails closed; ordinary
operation uses deterministic RRF and the first five Bifrost-ordered locators with a visible
fallback note. Caller-facing output contains only result kind/name, signals, location, and the
selected exact signatures/ranges. It must not contain source bodies or code fences.

Change CIM synthetic step zero to emit one forced tool call containing the full query array;
an empty query manifest still emits no call. Add a three-query validation ceiling to Anvil's CIM
configuration. In brokkbench, add `maxItems: 3`, update the prompt to say at most three while
preferring fewer, reject normalized results above three rather than truncating them, and bump the
prompt version so stale records cannot resume as the new treatment.

After focused validation, construct a new immutable run manifest containing the 34 prior r6
DW10 cells that both received generated queries and reached scoring. Reuse their exact saved
queries. For the four cells with more than three queries, retain the first three in recorded
order; the other 30 cells are an exact-query paired cohort. Run only this subset using the
existing DW10 cache and runtime, Bedrock GPT-5.6 Luna at maximum reasoning, DSV4Flash utility,
official sandbox images, no history, inline scoring, and concurrency 30. Compare paired solve
outcomes, turns, uncached tokens, cost, wall time, result bytes/lines, subsequent exact reads,
and edit breadth. Report the 30 exact-query cells separately from the four capped cells and stop
without launching another seed or the full task set.

Acceptance requires one public Anvil call per nonempty synthetic step, one independent rerank
event per query, stable input-order query sections, no cross-query deduplication, at most `k`
results and five signatures per result, no source-body/code-fence leakage, no CIM fallback or
hang, and valid scores for the checkpoint cells or explicit infrastructure failures.

## Concrete Steps

Network, Podman, host GPU, and localhost-binding operations must run outside the restricted
sandbox with appropriate approval. Do not place build systems, clones, databases, or generated
eval artifacts in `/tmp`.

The first implementation sequence is:

    cd /home/jonathan/Projects/brokkbench
    # implement the minimal cimeval prepare/clone surface and its focused tests
    uv run cimeval prepare \
      --manifest /mnt/optane/bifrost-nlp-resources/supercoder-eval/data/manifest_frame.csv \
      --clone-root /home/jonathan/Projects/brokkbench/clones \
      --jobs 15 \
      --run-dir /mnt/optane/bifrost-nlp-resources/runs/<run-id>

Immediately continue Bifrost, Anvil, and remaining cimeval implementation while clone workers
run.

Create the Anvil worktree:

    cd /home/jonathan/Projects/anvil
    git fetch origin
    git worktree add -b bifrost-nlp-ft-eval /mnt/optane/anvil-bifrost-nlp-ft origin/master

Resolve and verify the host GPU before model loading:

    nvidia-smi --query-gpu=index,uuid,name,memory.total --format=csv,noheader

Record the A4000 UUID in this plan and the run manifest. If `nvidia-smi` is not available in the
controller context, fix host GPU access before prewarming; do not silently run Granite on CPU or
another GPU.

Run focused Bifrost validation from `/mnt/optane/bifrost-nlp`:

    cargo fmt --check
    scripts/with-isolated-cargo-target.sh cargo test -p brokk-bifrost-analysis --features nlp nlp::
    scripts/with-isolated-cargo-target.sh cargo test -p brokk-bifrost-mcp --features nlp semantic
    scripts/with-isolated-cargo-target.sh cargo test -p brokk-bifrost-mcp --features nlp nlp_
    uv run --python 3.12 -- scripts/embedding_sidecar.py --selftest \
      --profile granite-r2 \
      --model-dir /home/jonathan/Projects/brokkbench/localizer/artifacts/granite-r2-small-v4-final

Before comprehensive NLP validation, check free disk and concurrent builds:

    df -h /mnt/optane /home/jonathan
    ps -eo pid,etimes,cmd
    scripts/cleanup-bifrost-tmp.sh

Then run:

    cargo fmt
    scripts/with-isolated-cargo-target.sh \
      uv run --python 3.12 -- cargo test --features nlp,python
    scripts/with-isolated-cargo-target.sh \
      cargo clippy --all-targets --all-features -- -D warnings

Run Anvil validation from its worktree, outside restrictions for full Wiremock tests:

    cargo fmt --check
    cargo test semantic_rerank
    cargo test semantic_search_description_is_overridden
    cargo test
    cargo clippy --all-targets -- -D warnings

Run focused brokkbench tests only:

    cd /home/jonathan/Projects/brokkbench
    PYTHONPATH=. uv run pytest cimeval
    PYTHONPATH=. uv run pytest <changed-sandbox-test-module>
    PYTHONPATH=. uv run pytest <relevant-agenteval-test-module>
    uv run ruff check --config pyproject.toml <changed-python-files>

The intended campaign commands are:

    uv run cimeval preflight --run-dir <run-dir> --provider auto --semantic off
    uv run cimeval serve --run-dir <run-dir> --profile granite-r2 --device <A4000-UUID>
    uv run cimeval prewarm --run-dir <run-dir> --profile granite-r2 --jobs 1

    uv run cimeval run --run-dir <run-dir> --arm baseline --seed 0 --jobs 30 --resume
    uv run cimeval score --run-dir <run-dir> --arm baseline --seed 0
    uv run cimeval report --run-dir <run-dir> --baseline-gate

Only after the gate passes:

    uv run cimeval run --run-dir <run-dir> --arm baseline --seed 1 --jobs 30 --resume
    uv run cimeval run --run-dir <run-dir> --arm baseline --seed 2 --jobs 30 --resume

After all Granite DBs are ready:

    uv run cimeval run --run-dir <run-dir> \
      --arms all-signals,semantic-only,semantic-coedit-2-1 \
      --seeds 0,1,2 --jobs 30 --resume
    uv run cimeval score --run-dir <run-dir>
    uv run cimeval report --run-dir <run-dir> --final

Stabilize either a console entry point or `python -m cimeval` during implementation and update
all commands together; do not leave competing forms.

At each checkpoint, update this plan, inspect owned diffs, stage only owned paths, and use a
multiline commit explaining why. Never use broad staging in any repository.

## Validation and Acceptance

Clone preparation passes when all 15 unique upstream repositories have complete primary clones,
all 91 task revisions have host worktrees, and every official cell sandbox is scrub-verified or
documented as a fail-closed exclusion, with no external alternates or surviving forbidden
objects in the sandbox.

Granite serving passes when the profile produces 384 finite unit vectors matching the reference,
uses the exact prefixes and CLS pooling, runs on the verified A4000, and changes the cache
fingerprint whenever any serving-contract component changes.

Shared-cache behavior passes when two containers for different task revisions of one upstream
repository concurrently bind the same DB directory, SQLite sees the same DB/WAL/SHM files, both
complete independent active-index queries without cross-revision results or unrecovered lock
errors, and final `PRAGMA integrity_check` is `ok`.

Anvil passes when its model-facing schema documents default/max 20 and fewer-than-k behavior;
it forwards twice final k, presents every deduplicated candidate to the bounded reranker, accepts
valid empty/fewer selections, never returns more than k, and has a deterministic at-most-k
fallback.

Baseline seed 0 passes only through the five-part sanity gate in Milestone 7. The other baseline
seeds and every Granite cell remain blocked until it passes.

Concurrency control passes when generation and primary inline scoring use 30 jobs, selective
pristine scorer recovery uses its bounded four-job pool, Granite and dw10 initial indexing
remain concurrency one, and saved load samples document any interference from the other
workstation workload.

The Granite evaluation passes when 819 expected cells are complete or outcome-blind excluded,
all use one provider and main-model configuration, official scorers run inline in the task
sandbox with selective versioned pristine recovery, leak audits are reviewed, result counts
respect k, and the report regenerates without rerunning an LLM.

Before completing Bifrost code changes, run the repository policy skill only if
`bifrost-policy-checking` and its policy tools are actually installed. If absent, record that
fact rather than claiming policy success.

The delivery is complete only when the four-repository change inventory and baseline, Granite,
and authorized dw10 best-recipe results are committed, every reportable cell has a valid score,
and all campaign services have stopped.

## Idempotence and Recovery

Clone preparation resumes completed verified clones and retries incomplete directories through
an atomic staging path. It never deletes a user-owned clone.

Prewarming builds a missing/mismatched Granite DB at the primary repository clone, traverses its
task worktrees sequentially, validates it, and publishes its repository ready manifest before
eval users begin. Once published, the DB is shared and writable. Never replace, rename, migrate,
or fingerprint-invalidate it while a cell has it open. On incompatibility, stop/drain all users,
quarantine the DB, and rebuild before resuming.

Each cell writes `COMPLETE` last. An interrupted cell can be retried from a fresh official task
container; content-addressed blobs it added to the shared cache may remain but are inactive
unless another working tree resolves the same content.

Provider attempts use separate run identities. If Bedrock is abandoned, do not merge its cells
with the OpenRouter reportable run.

Do not automatically remove clones, shared DBs, model services, worktrees, images, or run
artifacts. Report their paths and sizes; cleanup requires separate authorization.

Do not use `git reset`, `git clean`, `git checkout --`, broad staging, or destructive recursive
commands in the dirty brokkbench or Anvil primary checkouts. Do not redirect Cargo or uv caches
to `/tmp`; use Bifrost's isolated-target helper.

## Artifacts and Notes

Commit these small artifacts:

    /mnt/optane/bifrost-nlp/.agents/plans/bifrost-localizer-cim-eval.md
    /mnt/optane/bifrost-nlp/.agents/docs/granite-r2-cim-semantic-search-evaluation.md
    owned Bifrost source/tests
    owned Anvil worktree source/tests
    owned brokkbench cimeval/sandbox source/tests

Keep these large artifacts outside Git:

    /home/jonathan/Projects/brokkbench/clones/
    /mnt/optane/bifrost-nlp-resources/runs/<run-id>/

The final report and this section must record run ID, provider, A4000 UUID, runtime bundle
hashes, three final repository commits, clone status, shared DB locations/sizes, result DB/CSV,
and exact report command.

Never commit model weights, secrets, OCI layers, shared cache DBs, raw traces, or result
databases.

## Interfaces and Dependencies

Bifrost adds or stabilizes:

    BIFROST_EMBED_PROFILE=granite-r2
    BIFROST_EMBED_MODEL_DIR=<artifact path>
    BIFROST_EMBED_ENDPOINT=tcp://127.0.0.1:<port>
    BIFROST_EMBED_TOKENIZER_DIR=<tokenizer/config-only path>
    BIFROST_SEMANTIC_SEARCH_PROFILE=all-signals|semantic-only|semantic-coedit-2-1

Baseline uses the existing semantic-off configuration and must not advertise
`semantic_search`.

Anvil exposes:

    queries.type = array
    queries.minItems = 1
    queries.maxItems = 3
    queries.items.type = string
    k.type = integer
    k.minimum = 1
    k.maximum = 20
    k.default = 20
    k.description = "Maximum number of final relevance-reranked results. The reranker may return fewer than k by design when fewer candidates are relevant."

Brokkbench adds a separate cimeval CLI and one optional sandbox field for exact host-loopback
TCP forwarding. Its empty default preserves agenteval behavior.

Use Luna wire IDs already supported by Anvil:

    bedrock::openai.gpt-5.6-luna
    openrouter::openai/gpt-5.6-luna

Load provider credentials from `~/.secrets` without logging or copying them. Use official
SWE-PolyBench and SWE-bench Pro images/scorers and the checked
`supercoder-eval/scoring`/`analysis` definitions.

Revision note, 2026-07-31: Initial plan covered both dw10 and Granite R2 in one 1,638-cell
semantic grid.

Revision note, 2026-07-31: Clarified shared live SQLite caches rather than per-cell copies.

Revision note, 2026-07-31: Replaced the two-model campaign with a Granite-only first delivery.
Added clone-first preparation, A4000/concurrency-one prewarming in parallel with a gated
no-semantic Luna baseline, evaluation concurrency pinned at 30 on the shared 60-core host, a
1,092-cell maximum first delivery, 15 upstream clones with 91 task worktrees and repository-wide
shared Bifrost DBs, and an explicit stop/report point before dw10.

Revision note, 2026-07-31: Recorded the completed 91-worktree manifest, Bifrost/Anvil/brokkbench
checkpoints, official-image runtime proof, and the two issues found by the first real smoke.
Specified `semantic_index_profile` as the readiness-blocking serial prewarm primitive, the
Mjolnir provider-qualified Anvil routing fix, and optional semantic trace collection for a
baseline that may correctly make no semantic-search calls.

Revision note, 2026-08-02: Added the post-campaign compact multi-query milestone. It preserves
one independent reranker per query, keeps Bifrost scalar, replaces caller-visible excerpts with
classifier-selected Bifrost signature locators, caps generated queries at three, and defines a
34-cell queried-DW10 checkpoint before any broader rerun.
