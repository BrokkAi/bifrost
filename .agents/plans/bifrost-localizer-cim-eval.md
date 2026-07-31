# Serve Granite R2 and run a gated CIM-style evaluation

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`,
`Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md`. It describes the first
delivery of a larger localizer evaluation: implement and evaluate the smaller Granite R2
fine-tune, then stop and report. The dw10 evaluation remains deferred, but its repository
indexes are now being prepared in parallel at the user's direction.

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
the 60-core host for contention with the user's other workload. When Granite scoring and
analysis are complete, stop. Report the commits and behavior changed in Bifrost, Anvil, and
brokkbench, all validation performed, the baseline comparison, and the Granite results. Do not
begin dw10 evaluation in this delivery; the user separately authorized prewarming its indexes.

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
6. The completed first delivery accounts for 273 baseline cells and 819 Granite cells, subject
   to outcome-blind exclusions, and ends with a report rather than proceeding to dw10.

## Progress

- [x] (2026-07-31 09:21Z) Inspected Bifrost's semantic index, model sidecar, retrieval pipeline,
  MCP schema, and shared SQLite cache design.
- [x] (2026-07-31 09:21Z) Inspected Anvil's transparent semantic reranker and schema-description
  override.
- [x] (2026-07-31 09:21Z) Inspected the Granite R2 and dw10 artifacts and the released CIM
  manifest, scoring code, statistics, and published results.
- [x] (2026-07-31 09:38Z) Recorded the shared writable SQLite design for eval indexes.
- [x] (2026-07-31, current revision) Narrowed the first delivery to Granite R2, added the
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
- [ ] Pass the baseline sanity gate, then run baseline seeds 1 and 2 at concurrency 30. Seed 0
  resolves 31/91 (34.1%), has zero unmitigated leak findings, and passes the legitimate-count,
  resolve-band, and tool-call checks. New scheduling is stopped because mean uncached tokens
  are 49.6k against the precommitted 5k-30k band; this must be resolved before seeds 1 and 2.
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
- [ ] (2026-07-31 12:58Z) Prewarm dw10 serially on the A4000. The persistent sidecar and
  prewarm services are `cimeval-dw10-sidecar.service` and `cimeval-dw10-prewarm.service`.
  dw10 uses the separate per-repository `.bifrost/cache-dw10` namespace so changing embedding
  fingerprints cannot invalidate the completed `.bifrost/cache` Granite databases.
- [ ] Run the three Granite retrieval arms over seeds 0, 1, and 2 at concurrency 30.
- [ ] Score, leak-audit, analyze, and report the baseline and Granite results.
- [ ] Run final validation, update this plan's retrospective, commit the Granite report, and
  stop before running any dw10 evaluation arms.

## Surprises & Discoveries

- Observation: `BIFROST_EMBED_MODEL_DIR` does not currently select the model loaded by
  `scripts/voyage_sidecar.py`; the Python side always loads `voyageai/voyage-4-nano` and emits
  512 values.
  Evidence: the model ID and output dimension are module constants in the current sidecar.

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

- Decision: keep model-provider networking in the task container, but run every Anvil shell
  child in a fresh Linux network namespace when `ANVIL_OFFLINE_SHELL` is set; reject any
  outside-sandbox shell override in that mode. Also remove web tools and replace task Git
  history with a single tree-identical root commit.
  Rationale: this preserves arbitrary local build/test commands and Bedrock access without
  relying on command-text filters, while physically removing all three observed leak paths.
  Date/Author: 2026-07-31, Codex.

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

- Decision: Anvil uses retrieval overfetch multiplier `m=2`; model-facing `k` has minimum 1,
  maximum 20, and default 20.
  Rationale: `k` is the final reranked-result ceiling. Bifrost needs a wider candidate pool for
  relevance filtering.
  Date/Author: 2026-07-31, user.

- Decision: a valid reranker result may contain fewer than `k`, including zero, and Anvil does
  not refill it.
  Rationale: relevance filtering should be allowed to reject irrelevant candidates.
  Date/Author: 2026-07-31, user.

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

- Decision: stop after the Granite report and inventory changes across Bifrost, Anvil, and
  brokkbench.
  Rationale: the user wants to review the first model and implementation before authorizing the
  dw10 evaluation phase. On 2026-07-31 the user separately authorized dw10 prewarming, which
  does not authorize its evaluation arms.
  Date/Author: 2026-07-31, user.

- Decision: store dw10 and Granite embeddings in distinct per-repository cache namespaces.
  Rationale: a Bifrost database is safely shared across branches and worktrees, but its semantic
  tables intentionally support only one embedding fingerprint at a time. Reusing Granite's
  database for dw10 would wipe the completed Granite vectors during compatibility checking.
  Date/Author: 2026-07-31, Codex.

## Outcomes & Retrospective

No implementation or evaluation outcome exists yet. At completion, record the three repository
commit IDs, exact files/behavior changed, validation evidence, selected provider, concurrency
observations, baseline sanity comparison, Granite arm results, exclusions, and remaining work.
The final entry must distinguish the authorized dw10 prewarm from the still-deferred dw10
evaluation.

## Context and Orientation

The primary Bifrost checkout is `/mnt/optane/bifrost-nlp`, branch `bifrost-nlp-ft`. Commit
Bifrost work directly to that branch. Preserve the user's untracked `code_isnt_memory.md`.

The three repositories whose changes must be reported are:

1. `/mnt/optane/bifrost-nlp`: Granite model serving, dynamic embedding shape, retrieval
   profiles, shared-cache validation, and Bifrost tests.
2. `/home/jonathan/Projects/anvil`, developed through a clean worktree at
   `/mnt/optane/anvil-bifrost-nlp-ft`: model-facing schema, overfetch, bounded reranking,
   fallback, telemetry, and tests.
3. `/home/jonathan/Projects/brokkbench`: minimal sandbox port forwarding plus a new, separate
   `cimeval` harness, tests, and analysis/reporting code.

Mjolnir at `/home/jonathan/Projects/mjolnir` is the ACP client used to drive Anvil. No Mjolnir
source change is planned, so it is not one of the three changed repositories. If an integration
defect makes a Mjolnir change necessary, stop, create a worktree under `/mnt/optane`, record the
expanded scope here, and include it as a fourth repository in the report.

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

A cell is one `(instance, arm, seed)` run. The first delivery contains:

    baseline: 91 instances * 1 no-semantic arm * 3 seeds = 273 cells
    Granite:  91 instances * 3 retrieval arms * 3 seeds = 819 cells
    total:                                                   1,092 cells

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
`bedrock::openai.gpt-5.6-luna` with medium main-agent reasoning. Run ten sequential
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
    scripts/with-isolated-cargo-target.sh cargo test -p bifrost-analysis --features nlp nlp::
    scripts/with-isolated-cargo-target.sh cargo test -p bifrost-mcp --features nlp mcp_nlp
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
      --profile granite-r2 --seed 0 --jobs 30 --resume
    uv run cimeval run --run-dir <run-dir> \
      --arms all-signals,semantic-only,semantic-coedit-2-1 \
      --profile granite-r2 --seed 1 --jobs 30 --resume
    uv run cimeval run --run-dir <run-dir> \
      --arms all-signals,semantic-only,semantic-coedit-2-1 \
      --profile granite-r2 --seed 2 --jobs 30 --resume
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

Concurrency control passes when every generation and scoring phase uses 30 jobs, Granite
initial indexing remains concurrency one, and saved load samples document any interference
from the other workstation workload.

The Granite evaluation passes when 819 expected cells are complete or outcome-blind excluded,
all use one provider and main-model configuration, official scorers run after artifact capture
in the task sandbox, leak audits are reviewed, result counts respect k, and the report
regenerates without rerunning an LLM.

Before completing Bifrost code changes, run the repository policy skill only if
`bifrost-policy-checking` and its policy tools are actually installed. If absent, record that
fact rather than claiming policy success.

The delivery is complete only when the three-repository change inventory and baseline/Granite
report are committed and execution has stopped before dw10.

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
