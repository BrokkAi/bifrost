# Serve the dw10 and Granite R2 localizers and evaluate retrieval ablations

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`,
`Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md`. It covers coordinated
changes in the current Bifrost checkout, a clean Anvil worktree, and
`/home/jonathan/Projects/brokkbench`, followed by a complete Code Is Not Memory-style evaluation.

## Purpose / Big Picture

Bifrost currently serves the base Voyage model through a sidecar whose model identity, prefixes,
pooling, and 512-dimensional output are hardcoded. A local model-directory environment variable
changes some Rust-side metadata but does not cause the Python sidecar to load the requested
fine-tune. The result is that the two localizer checkpoints cannot be evaluated or selected
correctly.

After this work, Bifrost can serve the local dw10 and Granite R2 checkpoints with their exact
training-time representation contracts. In automatic mode it selects dw10 when CUDA or Metal is
available and Granite R2 on a CPU-only host. Anvil's `semantic_search` exposes a documented
`k <= 20` final-result ceiling, overfetches candidates by a factor of two, and may deliberately
return fewer than `k` results after relevance reranking.

A new `cimeval` harness runs the exact 91-instance sample from `code_isnt_memory.md` in official
SWE-PolyBench and SWE-bench Pro containers. It compares three equal-size candidate-pool designs
for both embedding models over three seeds, producing 1,638 scored cells, CIM-compatible
localization metrics, paired statistical tests, an exclusion ledger, and a reproducible report.
The existing `agenteval` DeepSWE/testsome workflow remains unchanged.

The observable success criteria are:

1. A Bifrost process reports and uses the correct model profile, output dimension, prefixes,
   pooling rule, parent composition, and cache fingerprint for each local checkpoint.
2. At model-facing `k=20`, Anvil sends base depth 40 to Bifrost and the three evaluation modes
   yield nominal raw budgets of `40/40/40`, `120/0/0`, and `80/0/40` for
   vector/BM25/co-edit respectively. Anvil always returns at most 20 final results.
3. The Anvil tool schema documents a default and maximum of 20 and explicitly says the reranker
   may return fewer than `k` by design.
4. One SWE-PolyBench task and one SWE-bench Pro task complete end to end in official task
   containers for both models and all three retrieval modes before the full campaign starts.
5. The full run contains a single-provider 91 by 3 by 3 by 2 grid, or a documented,
   outcome-blind exclusion for every missing cell, and its headline tables can be regenerated
   from preserved artifacts.

## Progress

- [x] (2026-07-31 09:21Z) Inspected the existing Bifrost semantic search, sidecar, cache, and MCP
  schema paths; inspected Anvil's transparent reranker and tool-description override.
- [x] (2026-07-31 09:21Z) Inspected both localizer artifacts and recorded their exact serving
  contracts.
- [x] (2026-07-31 09:21Z) Checked out and inspected SuperCoder, `supercoder-eval`,
  SWE-PolyBench, and SWE-bench Pro under `/mnt/optane/bifrost-nlp-resources`.
- [x] (2026-07-31 09:21Z) Verified that rootless Podman cannot use the WSL GPU directly but can
  reach a host loopback embedding service through `pasta` TCP forwarding.
- [x] (2026-07-31 09:21Z) Wrote this initial ExecPlan with the decisions reached with the user.
- [x] (2026-07-31 09:38Z) Clarified that eval cells share Bifrost's real writable SQLite
  database per instance/model; no per-cell copy or copy-on-write snapshot is used.
- [ ] Implement and validate model-profile-driven local and TCP embedding in Bifrost.
- [ ] Implement and validate the retrieval profiles and exact per-leg candidate budgets.
- [ ] Create the clean Anvil worktree and implement the final-`k` contract and bounded reranker.
- [ ] Add the backward-compatible sandbox TCP-forwarding option and the separate `cimeval`
  package in brokkbench.
- [ ] Build benchmark manifests, leak controls, index prewarming, official scoring adapters,
  localization scoring, and statistical reporting.
- [ ] Complete provider and benchmark pilots.
- [ ] Run, score, audit, and report the full 1,638-cell evaluation.
- [ ] Run final repository validation, update this plan's outcomes, and commit the final report.

## Surprises & Discoveries

- Observation: `BIFROST_EMBED_MODEL_DIR` does not presently select the model loaded by
  `scripts/voyage_sidecar.py`; that script always loads `voyageai/voyage-4-nano`.
  Evidence: the Python file defines a constant base model ID and fixed output dimension while the
  Rust model-directory resolution happens in `crates/bifrost-analysis/src/nlp/engine.rs`.

- Observation: the two fine-tunes do not share a representation shape.
  Evidence: dw10's artifact uses `Qwen3BidirectionalModel`, mean pooling, and
  `truncate_dim=512`; Granite R2 uses `ModernBertModel`, CLS pooling, and a 384-dimensional
  hidden state.

- Observation: both checkpoints require parent composition alpha 0.65, not Bifrost's current
  0.5.
  Evidence: each artifact's `run_metadata.json` records
  `normalize(0.65 * child + 0.35 * parent)` under representation `parent_avg_v1`.

- Observation: Granite's serving prefixes are external to its exported
  `config_sentence_transformers.json`, whose prompt strings are empty.
  Evidence: `localizer/GRANITE_R2_V4_FINAL_RECIPE.md` and
  `localizer/localize_sft_core.py` define the byte-exact Granite query and passage prefixes.

- Observation: Anvil currently forwards the model's `k` unchanged, caps the parsed pool at
  30 symbols and 20 files, permits an arbitrary-size reranker selection, and falls back to the
  raw three-list Bifrost payload.
  Evidence: `/home/jonathan/Projects/anvil/src/semantic_rerank.rs`.

- Observation: official benchmark containers cannot directly use the host WSL GPU through the
  current rootless Podman setup.
  Evidence: direct privileged and `/dev/dxg` attempts failed, while a loopback server became
  reachable using Podman's `pasta:-T,<port>` forwarding.

- Observation: `agenteval` is specialized for the DeepSWE/testsome task format even though its
  process bundling and sandbox lifecycle are reusable.
  Evidence: `/home/jonathan/Projects/brokkbench/agenteval` binds its task loading and scoring to
  the brokkbench corpus and testsome metadata.

- Observation: Bifrost's cache is intentionally safe to share across branches, worktrees, and
  processes when every process opens the same underlying SQLite database and its WAL/SHM files.
  Evidence: `crates/bifrost-analysis/src/nlp/store.rs` resolves worktrees to the primary-repo
  cache, keeps active chunk membership in a connection-local temporary table, and stores
  persisted vectors by content identity. `crates/bifrost-analysis/src/cache_db.rs` leaves
  cross-process serialization to SQLite and configures the shared database for WAL operation.

## Decision Log

- Decision: use retrieval overfetch multiplier `m=2`.
  Rationale: the model-facing `k` is a final Anvil ceiling, while Bifrost needs a wider candidate
  pool for the disposable reranker.
  Date/Author: 2026-07-31, user and Codex.

- Decision: expose Anvil `semantic_search.k` with minimum 1, maximum 20, and default 20.
  Rationale: this matches CIM's documented tool ceiling while making the ceiling visible in both
  schema and prose.
  Date/Author: 2026-07-31, user.

- Decision: a successful reranker may return fewer than `k`, including zero, and Anvil will not
  refill rejected candidates.
  Rationale: relevance filtering is the purpose of the reranker; filling to exactly `k` would
  undo its judgment.
  Date/Author: 2026-07-31, user.

- Decision: keep the nominal pre-rerank pool equal at `6k` for every evaluation arm.
  Rationale: this holds reranker opportunity and approximate reranker cost constant while
  ablating retrieval signals.
  Date/Author: 2026-07-31, user and Codex.

- Decision: use three fixed Bifrost retrieval profiles rather than allowing the benchmark agent
  to choose a profile.
  Rationale: the profile is the experimental condition. The model should see the same tool
  interface in every arm.
  Date/Author: 2026-07-31, Codex.

- Decision: automatic Bifrost model selection means dw10 on CUDA or Metal and Granite R2 on
  CPU-only hosts; explicit profile and directory settings take precedence.
  Rationale: dw10 is the higher-capacity accelerator model and Granite R2 is the practical CPU
  profile.
  Date/Author: 2026-07-31, user.

- Decision: run model inference on the host and forward only a loopback TCP port into official
  task containers.
  Rationale: this preserves official benchmark containers while working around the verified
  rootless Podman/WSL GPU boundary.
  Date/Author: 2026-07-31, Codex.

- Decision: add `cimeval` beside `agenteval` instead of generalizing `agenteval` in place.
  Rationale: the existing harness has a different task and scoring contract and must remain
  usable for DeepSWE/testsome.
  Date/Author: 2026-07-31, user and Codex.

- Decision: use one LLM provider for every cell in the reported grid.
  Rationale: provider behavior must not be confounded with model or retrieval condition.
  Date/Author: 2026-07-31, user and Codex.

- Decision: use Bedrock only if a provider preflight and representative container smoke pass;
  otherwise use OpenRouter for the full grid.
  Rationale: Bedrock was recently flaky. Mixing fallback cells into the same grid would damage
  comparability.
  Date/Author: 2026-07-31, user and Codex.

- Decision: do not commit, publish, or copy model weights into task containers.
  Rationale: the requested checkpoints are local artifacts and no model-publication authority
  was given.
  Date/Author: 2026-07-31, Codex.

- Decision: share one live read-write `bifrost_cache.db` per `(instance, embedding model)`
  across all retrieval arms and seeds for that instance/model.
  Rationale: this is Bifrost's intended branch/worktree cache model. All containers bind the
  same host directory, so SQLite sees one database plus one WAL/SHM pair and provides real
  cross-process locking. Per-cell copies or overlay copy-on-write layers add complexity without
  improving the intended content-addressed isolation.
  Date/Author: 2026-07-31, user and Codex.

## Outcomes & Retrospective

No implementation or evaluation outcome exists yet. At every milestone, record what became
observable, validation evidence, remaining gaps, and any deviation from this design. At
completion, compare the two embedding models and three retrieval arms on resolve rate,
localization, cost, turns, tokens, and candidate/reranker behavior, and identify which model and
retrieval profile should become the default.

## Context and Orientation

The primary checkout is `/mnt/optane/bifrost-nlp`, currently on branch `bifrost-nlp-ft` at
commit `7e4a940ae0cac7336c2706301b426cf024220ccf`. Commit Bifrost work directly to this branch.
The untracked root file `code_isnt_memory.md` belongs to the user and must remain unmodified and
unstaged.

Bifrost's embedding abstraction is the `Embedder` trait in
`crates/bifrost-analysis/src/nlp/engine.rs`. The current subprocess client is
`crates/bifrost-analysis/src/nlp/voyage_sidecar.rs`; it launches
`scripts/voyage_sidecar.py`. The indexer composes function and parent-summary vectors and stores
them in the semantic cache. `crates/bifrost-analysis/src/nlp/query.rs` performs one vector leg,
one grounded-string BM25 leg, and one git co-edit leg, returning three independent lists.
`crates/bifrost-mcp/src/mcp_nlp.rs` advertises that raw tool.

The requested local model artifacts are:

    /home/jonathan/Projects/brokkbench/localizer/artifacts/voyage-nano-gen-v4-n24-s30-dw10
    /home/jonathan/Projects/brokkbench/localizer/artifacts/granite-r2-small-v4-final

The dw10 contract is:

    architecture: Qwen3BidirectionalModel, loaded with trust_remote_code from the artifact
    query prefix: "Represent the query for retrieving supporting documents: "
    passage prefix: "Represent the document for retrieval: "
    pooling: attention-mask-aware token mean, including prompt tokens
    native pooled width: 2048
    served width: first 512 components, then L2 normalize
    maximum sequence length: 8192
    parent representation: L2 normalize(0.65 * child + 0.35 * parent)

The Granite R2 contract is:

    architecture: ModernBertModel
    query prefix:
      "Given a GitHub issue, retrieve code that must be changed to fix it.\nQuery: "
    passage prefix: "Passage: Code chunk from repository.\n"
    pooling: CLS token, including prompt
    served width: 384, then L2 normalize
    maximum sequence length: 8192
    parent representation: L2 normalize(0.65 * child + 0.35 * parent)

Anvil's primary checkout is `/home/jonathan/Projects/anvil`. It is on `master` at
`c2e027c833638d981569df82464cc94ef2e9cca7`, seven commits behind `origin/master`, and contains
an untracked `target-bookworm/`. Do not modify it. Fetch `origin` with the required network
escalation, then create `/mnt/optane/anvil-bifrost-nlp-ft` as a clean linked worktree based on
the fetched `origin/master`. Implement and commit Anvil work only there. Anvil's reranker is
`src/semantic_rerank.rs`; its MCP schema/description transformation is in `src/tools/mod.rs`.

Mjolnir is `/home/jonathan/Projects/mjolnir`, currently at
`b1d27555dc31bce5e952060ee0a4265db13f220e`. It is the headless ACP client that drives Anvil.
No source change is planned. If an integration defect requires a change, first create a clean
worktree under `/mnt/optane` and record the defect and decision here.

The harness repository is `/home/jonathan/Projects/brokkbench`, on `master` at
`9d1333141bafe742eb8d66051dfbf94b6907a830`. It has extensive user changes and generated data.
Do not clean, reset, or broadly scan it. Restrict work to `agenteval`, `sandbox`, the new
`cimeval`, and directly relevant tests. Stage only paths changed by this plan.

Read-only reference checkouts are:

    /mnt/optane/bifrost-nlp-resources/SuperCoder
    /mnt/optane/bifrost-nlp-resources/supercoder-eval
    /mnt/optane/bifrost-nlp-resources/SWE-PolyBench
    /mnt/optane/bifrost-nlp-resources/SWE-bench_Pro-os

The checked reference revisions at plan creation are:

    supercoder-eval: 89e4156ba11538a8be0e2343d215bdff778550ed
    SWE-PolyBench:   9c836c5d7f3cb991934132b77d29e6941d912a07
    SWE-bench Pro:   ca10a60a5fcae51e6948ffe1485d4153d421e6c5

The CIM manifest at `supercoder-eval/data/manifest_frame.csv` contains 91 instances across Go,
Java, and Python. A cell means one tuple of instance, seed, retrieval profile, and embedding
model. The full requested grid is:

    91 instances * 3 seeds * 3 retrieval profiles * 2 embedding models = 1,638 cells

The retrieval profiles use the following terminology:

`all-signals` means vector semantic search, grounded-string BM25, and git co-edit retrieval.
`semantic-only` means only the vector leg. `semantic-coedit-2-1` means vector and co-edit
candidate counts in a two-to-one ratio with no BM25. "Base depth" is the value Anvil sends to
Bifrost after multiplying the model's requested final ceiling by two.

For a model-facing final ceiling `k`, Anvil sends Bifrost base depth `b = 2k`. Bifrost allocates:

    all-signals:            vector=b,   BM25=b, co-edit=b
    semantic-only:          vector=3b,  BM25=0, co-edit=0
    semantic-coedit-2-1:    vector=2b,  BM25=0, co-edit=b

Thus every profile offers a nominal `3b = 6k` raw slots. Deduplication, a small corpus, or an
unavailable retrieval leg may reduce the realized pool; the harness records both requested and
realized counts.

## Plan of Work

### Milestone 1: make the embedding contract model-driven

Introduce a small Rust model-profile type next to the embedding engine. It must contain the
stable profile name, query and passage prefixes, pooling kind, served dimension, maximum
sequence length, parent alpha, and artifact directory name. The accepted
`BIFROST_EMBED_PROFILE` values are `auto`, `dw10`, and `granite-r2`. An explicit profile wins
over automatic selection. `auto` selects dw10 when the resolved local backend has CUDA or Metal
and Granite R2 otherwise.

Preserve `BIFROST_EMBED_MODEL_DIR` as the highest-priority explicit artifact directory.
Add `BIFROST_EMBED_MODEL_ROOT` for installations containing both canonical artifact directory
names. A missing selected artifact is an actionable startup error naming the selected profile
and accepted environment variables; never silently fall back to the base Voyage model.

Replace the Voyage-specific Python implementation with `scripts/embedding_sidecar.py` and
rename the Rust module accordingly. The Python process accepts `--profile`, `--model-dir`,
`--device`, and optional `--listen 127.0.0.1:PORT`. Local subprocess mode continues to use the
current little-endian framed protocol. TCP mode accepts persistent connections using the same
frames. Each connection first receives a JSON ready frame containing:

    {"ready": true, "profile": "...", "dim": N, "fingerprint": "..."}

Requests remain length-prefixed JSON with `kind` equal to `query` or `passage` and a `texts`
array. Matrix responses remain a length-prefixed `[rows, dimension, float32 data]` payload.
Reject unknown kinds, profile mismatches, dimensions inconsistent with the handshake, oversized
frames, and non-finite output.

Load dw10 through its artifact's `auto_map` with `trust_remote_code=True`. Keep the existing
fused SDPA path where its Qwen attention implementation requires it. Load Granite through
Transformers' native `ModernBertModel`. Apply profile-specific prefixes and pooling, truncate
dw10 after pooling, and L2-normalize both profiles. Add a self-test mode that compares fixed
texts against SentenceTransformers using the same artifact, prompts, pooling, truncation, and
normalization.

Make Rust sidecar dimensions dynamic. The local subprocess and TCP client both obtain the
dimension and fingerprint from the ready frame. Add
`BIFROST_EMBED_ENDPOINT=tcp://127.0.0.1:PORT`; when present, Bifrost connects rather than
spawning Python. Add `BIFROST_EMBED_TOKENIZER_DIR` for the tokenizer/config-only directory used
inside benchmark containers. Token counting remains in Rust so chunking does not pay an RPC
round trip.

Move parent alpha and representation identity into the selected profile. Update all fixed
512-dimensional assumptions in quantization, store/index metadata, vector composition, and
tests. The cache fingerprint must cover the SHA-256 content identity of model configuration and
weights, profile, exact prefixes including trailing spaces, pooling, truncation, served
dimension, maximum sequence length, parent alpha, numeric precision, and local-versus-remote
backend. The remote server reports the authoritative fingerprint; the client asserts it matches
the selected local tokenizer profile. Existing caches with the old fingerprint must rebuild.

Change semantic-search availability so a configured Granite CPU profile is advertised without
`--force-semantic-cpu`. Continue to omit the tool when semantic indexing is explicitly disabled,
the root is not a git repository, or the selected model cannot be resolved.

At the end of this milestone, both artifact self-tests pass, a small checked-out repository can
build and query one 512-dimensional dw10 index and one 384-dimensional Granite index, and
switching profiles invalidates the cache.

### Milestone 2: implement equal candidate pools in Bifrost

Add `BIFROST_SEMANTIC_SEARCH_PROFILE` with accepted values `all-signals`,
`semantic-only`, and `semantic-coedit-2-1`; default to `all-signals`. Parse it once during NLP
service construction rather than reading process environment inside each query.

Treat Bifrost's incoming `k` as the base depth described above. Refactor
`semantic_search` so vector, BM25, co-edit seed, and co-edit output depths are independent
integers computed from the profile:

    all-signals with base b:
      vector output b
      BM25 output b
      co-edit output b
      co-edit seeds are the weighted union of the top b vector files and top b BM25 files

    semantic-only with base b:
      vector output 3b
      BM25 is not computed
      co-edit is not computed

    semantic-coedit-2-1 with base b:
      vector output 2b
      BM25 is not computed
      co-edit output b
      co-edit seeds come from the top 2b vector files only

Keep the existing raw result shape with `vector_ranked`, `bm25_ranked`, `coedit_ranked`, and
`notes`; disabled legs are empty arrays. Add machine-readable `retrieval_profile` and
`candidate_budget` metadata so Anvil and the evaluation harness do not infer experimental
conditions from list lengths. The budget records each requested leg depth and each realized
length.

Use checked multiplication and an internal per-leg ceiling of 120 for the benchmark-facing
path, because model-facing `k=20`, multiplier two, and semantic-only multiplier three produce
120. Reject invalid or excessive base depth rather than silently changing the experiment.

Behavior tests must use `SearchToolsService::new_without_semantic_index` and fake embedders or
the existing NLP fakes; they must not download models or start indexer threads. Prove actual
leg behavior and co-edit seed provenance rather than asserting only an enum-to-number table.

At the end of this milestone, one instrumented query at model-facing `k=20` can demonstrate
raw budgets `40/40/40`, `120/0/0`, and `80/0/40`.

### Milestone 3: make Anvil's k a final relevance ceiling

Create the clean Anvil worktree before editing. Update its model-facing copy of Bifrost's tool
schema, not Bifrost's raw MCP schema, so `semantic_search.k` has `minimum: 1`, `maximum: 20`,
and `default: 20`. Its property description and the tool's overall description must state that
`k` is the maximum number of final relevance-reranked results and that the reranker may return
fewer by design.

When the model omits `k`, use 20. Validate explicit values before calling Bifrost. Copy the
arguments and replace `k` with `2 * final_k` for the raw Bifrost call. Preserve the original
final ceiling separately for result truncation and telemetry.

Remove `MAX_SYMBOL_CANDIDATES=30` and `MAX_FILE_CANDIDATES=20`. Parse and deduplicate the full
raw pool. Symbols appearing in vector and BM25 remain one candidate with both signal labels;
co-edit files remain file candidates. Retain per-leg rank and score for deterministic fallback
and telemetry.

Every realized candidate must be shown to the disposable reranker. Bound candidate context to a
global 120,000 UTF-8 byte budget and at most 8,000 bytes per candidate. Divide the available
context budget uniformly across candidates, preserving the beginning and end on UTF-8
boundaries. Candidate ID, name, kind, location, and signal labels are never omitted. This keeps
candidate opportunity equal without creating an unbounded prompt.

Tell the reranker that it may select zero through `final_k` IDs. Treat a valid empty list as a
successful zero-result response. Preserve selected order, discard unknown and duplicate IDs,
and truncate valid selections to `final_k` without refilling.

If the provider call fails or structured output is malformed, perform deterministic
rank-reciprocal fusion over all active raw legs, use stable name/path tie-breaking, and return
the first `final_k` candidates. Clearly annotate the output and trace as fallback. Do not pass
through Bifrost's raw payload. This preserves the public at-most-`k` contract on every
non-Bifrost-error path.

Emit structured trace fields for final `k`, Bifrost base depth, selected retrieval profile,
requested and realized per-leg counts, deduplicated count, candidate-context bytes, reranker
selected count, final count, fallback reason, and reranker token usage. Include disposable
reranker usage in the session's total tokens and cost.

Tests must exercise schema transformation, omitted and boundary `k`, rejection above 20,
overfetch forwarding, duplicate candidates, more than 50 candidates, uniform context
allocation, fewer-than-`k`, valid empty selection, overlong selection, malformed selection,
provider failure, stable fallback, and a raw Bifrost error.

At the end of this milestone, the model sees the documented ceiling and no Anvil response can
contain more than the requested number of final results.

### Milestone 4: add container transport without changing agenteval

In `/home/jonathan/Projects/brokkbench/sandbox`, add an optional
`host_loopback_tcp_ports: tuple[int, ...] = ()` to `SandboxSpec`. For direct rootless Podman
sandboxes, a non-empty tuple adds a `pasta` network configuration forwarding exactly those TCP
ports from the host loopback namespace. Validate port range, reject duplicates, and render
arguments without shell interpolation. An empty tuple must generate the byte-for-byte existing
Podman network behavior.

Add behavior tests using a local loopback echo server and a minimal direct Podman sandbox. Also
run the existing sandbox and agenteval targeted tests to demonstrate the default path is
unchanged.

Add `/home/jonathan/Projects/brokkbench/cimeval` as a separate PEP 723/uv-driven package. It may
import stable bundle and sandbox helpers from `agenteval`, but no CIM behavior may be added to
agenteval's public CLI or DeepSWE task model. Give cimeval these commands:

    prepare   resolve the 91 tasks, dataset revisions, image tags, and image digests
    serve     launch one embedding TCP service per assigned device for one model profile
    prewarm   build scrub-clean per-instance/model Bifrost caches
    preflight validate provider, bundle, two benchmark families, and all six conditions
    run       execute or resume selected cells
    score     run official scorers and CIM localization extraction
    report    create aggregate tables, paired tests, and exclusion summaries

Use a run directory under `/mnt/optane/bifrost-nlp-resources/runs/<run-id>`. All commands accept
that directory and are idempotent. A completed cell is reused only if its input manifest hash
matches exactly. Never write generated benchmark data or caches into `/tmp` or the brokkbench
working tree.

Build exact Bifrost, Anvil, and Mjolnir binaries and their required libraries into an immutable
runtime bundle. Record each source commit and bundle hash. The task container gets the runtime
bundle, tokenizer/config-only metadata, and a forwarded embedding port; it never gets model
weights.

At the end of this milestone, a generic official task image can connect to the host embedder and
run the bundled Bifrost/Anvil/Mjolnir stack, while an ordinary agenteval invocation produces its
unchanged command and sandbox configuration.

### Milestone 5: implement CIM task integrity, cache preparation, and scoring

Use `supercoder-eval/data/manifest_frame.csv` as the exact task selection. Fetch official
dataset rows and record immutable dataset revisions. For SWE-PolyBench, use the frozen v1.1 GHCR
image for each instance and read the working directory from image configuration. For SWE-bench
Pro, use the row's official `dockerhub_tag`; its repository root is `/app`. Resolve every image
to a digest before running cells.

Construct sanitized task statements by removing repository self-links while preserving all
other issue text. In each task image, check out the official base revision. Delete future,
remote, tag, replace, and hidden refs and all reflogs, expire reflogs, run
`git gc --prune=now`, and compare the surviving object set with the allowed base ancestry and
known forbidden gold/future objects. This is a fail-closed gate: if forbidden objects remain or
required base objects disappear, do not start the agent. Preserve the base commit's reachable
history because the co-edit arm requires historical commits.

Prewarm exactly one unified Bifrost cache per scrub-clean `(instance, embedding model)` pair,
for 182 potential databases. Store each cache in a stable host directory under the run
directory, with the repository tree identity, model fingerprint, tokenizer profile, Bifrost
commit, schema version, and initial database checksum in its preparation manifest. Finish
migrations, the initial full index build, and compatibility validation before publishing a
`READY` marker or starting any eval cell.

Every arm/seed container for that instance/model bind-mounts the same host cache directory
read-write at the workspace's `.bifrost/cache` path. Do not copy the database into containers,
put it behind an overlay layer, hard-link it to per-cell names, or separate its `-wal` and
`-shm` files. Every writer must reach the same host ext4 inode and the same adjacent WAL/SHM
files so SQLite's normal cross-process locks remain authoritative. The official task containers
share the host kernel, so ordinary SQLite file locking on that bind mount is the concurrency
mechanism; the harness must not add an application-level fiction that treats copies as one DB.

The database is deliberately writable and may accumulate content-addressed blobs from different
cell worktrees. That is the same behavior Bifrost supports for ordinary branches and worktrees.
Each Bifrost process builds its active chunk set in its own connection-local temporary table, so
only blobs resolved from that cell's working tree participate in semantic retrieval. Keep the
sharing boundary at one benchmark instance and embedding model: do not share across instances,
because their permitted git histories differ, and do not share across models, because the
database has one active embedding fingerprint.

All cells use the exact Bifrost binary that initialized the database. Before mounting it, the
harness verifies the `READY` manifest rather than re-hashing a database that legitimately
changes during the run. Bifrost still validates its embedding, chunker, BM25 tokenizer, and
schema identities on open. If any identity mismatches, abort that cell and drain all users of
the database before rebuilding it; never allow one process to wipe or migrate a shared database
while other cell processes have it open.

The cell runner uses the same sanitized problem statement, system instructions, main model,
reasoning effort, Mjolnir/Anvil configuration, timeout, and tool descriptions in every
condition. Disable Mjolnir discrete review and subagents. Do not impose a turn or dollar cap.
Apply a 30-minute wall-clock deadline. Seeds 0, 1, and 2 identify independent replicates and
deterministically control cell scheduling and artifact names; pass a provider seed only if both
Luna backends expose the same supported parameter.

Run generation inside a fresh official task image. At termination, capture the workspace patch
without test or gold data. Score the patch in a second fresh copy of the same pinned image using
the official benchmark scorer: SWE-PolyBench's model-patch evaluation path and SWE-bench Pro's
official evaluation script. Preserve raw scorer output.

Record one cell directory containing at least:

    input-manifest.json
    scrub-report.json
    mjolnir-stream.jsonl
    anvil-trace.jsonl
    stderr.log
    patch.diff
    diff-stat.json
    usage.json
    candidate-telemetry.jsonl
    leak-audit.json
    official-score.json
    cell-result.json
    COMPLETE

Write `COMPLETE` last through an atomic rename. Do not store secret values or full environment
dumps.

Adapt `supercoder-eval/scoring/localization.py` rather than inventing a new localization
definition. View A includes paths surfaced to the agent by Anvil's final result, plus paths
targeted through other tools and edits. It does not include Bifrost's hidden raw candidates.
Canonical View B removes paths introduced only by an agent-visible semantic-search result but
retains later targeted uses of those paths and all normal tool arguments. Emit accuracy and
recall at 1, 3, 5, and 10 for CIM comparability, plus exploratory 20, first-gold rank, edit
precision, and edit recall.

Run the released leak auditor over traces and shell/network activity. Maintain an outcome-blind
exclusion ledger with reason and evidence. A task-image or scrub failure applies to every model,
arm, and seed for that instance. Provider failures are retried on the locked provider before
classification; never label a model-quality failure as infrastructure failure after seeing the
official outcome.

At the end of this milestone, the two-instance pilot can be rescored entirely from preserved
patches and traces, and rerunning `score` produces identical cell results.

### Milestone 6: lock the provider and run the campaign

Use model `bedrock::openai.gpt-5.6-luna` with medium reasoning for the main agent. Anvil's
disposable reranker continues to use the active Luna model with low reasoning. Load only the
needed Bedrock credential variables from `~/.secrets`.

Before the reportable grid, run ten sequential Luna structured-output/tool calls and the full
two-instance, six-condition-per-instance container pilot. Bedrock passes only if every call
succeeds after the normal Anvil retries and both benchmark families produce valid patches,
traces, and official scores. Otherwise lock the run to
`openrouter::openai/gpt-5.6-luna`, load only its credentials, discard provider-dependent pilot
cells from the reportable grid, and rerun the pilot.

Write the selected provider into an immutable run manifest. Never mix providers in one
reportable grid. If Bedrock later has an unrecovered transport, streaming, or protocol failure,
retry the cell on Bedrock. If three cells encounter such unrecovered failures, stop scheduling
new Bedrock cells, preserve the attempt as a pilot/abandoned run, create a new OpenRouter run
directory, and rerun every condition there.

Schedule conditions in deterministic, balanced blocks by instance and seed so time-of-day and
provider drift are not aligned with one model or retrieval arm. Start with four concurrent
cells, one per available embedding-service device. Increase only after observing that GPU
queues, provider rate limits, disk I/O, and official scorers are not contending; record any
change in the run manifest. Network-only image metadata and pull preparation should use the
brokkbench convention of at least 50 concurrent operations.

Continue until all 1,638 expected cells are complete or represented in the exclusion ledger.
The runner must be safely resumable after interruption and must report expected, complete,
running, retryable, excluded, and missing counts.

### Milestone 7: analyze, report, and close the work

Create a result database and CSV modeled on `supercoder-eval` with added `embedding_model`,
`retrieval_profile`, provider, model fingerprint, requested/realized candidate counts,
reranker-selected count, fallback status, and cache identity. Unsuffixed localization columns
carry canonical View B, matching CIM.

For each embedding model and retrieval arm, report:

    official resolve rate
    cost per cell and cost per solve
    turns and wall time
    input, output, reasoning, and cached tokens
    View A and View B localization accuracy/recall
    first-gold rank
    edit precision and recall
    requested, realized, deduplicated, selected, and final candidate counts
    reranker fallback rate

Compute aggregates as the mean of the three seed means with across-seed standard deviation.
For each embedding model, run two-sided paired Wilcoxon signed-rank tests over per-instance
seed means for all three retrieval-arm pairs. Also run secondary paired dw10-versus-Granite
tests within each retrieval arm. Use only the paired legitimate-instance intersection and
report total paired `n`, nonzero-difference `n`, mean paired difference, statistic, and
two-sided p-value. Keep raw p-values for CIM comparability and label the multiple secondary
comparisons exploratory.

Write the human-facing result to
`.agents/docs/dw10-granite-cim-semantic-search-evaluation.md`. Include exact source revisions,
model artifact hashes, dataset revisions, image digests, provider decision, exclusions,
headline tables, paired tests, candidate diagnostics, known limitations, and commands that
regenerate the tables. Keep large traces, caches, images, database, and CSV under the run
directory rather than committing them.

Update this plan's progress, discoveries, decisions, and retrospective. Commit only the files
changed for this work in each repository. Bifrost commits land directly on `bifrost-nlp-ft`;
brokkbench commits land on its existing `master`; Anvil commits remain on the clean worktree's
dedicated branch until the user decides how to integrate them. Do not push, tag, publish
weights, or open a pull request without a separate request.

## Concrete Steps

All network access, GitHub access, localhost-binding Anvil tests, Podman operations, and writes
outside the configured writable roots must be run with the required escalation. Do not redirect
Cargo, uv, model, or benchmark build directories into `/tmp`.

First create the Anvil worktree:

    cd /home/jonathan/Projects/anvil
    git fetch origin
    git worktree add -b bifrost-nlp-ft-eval /mnt/optane/anvil-bifrost-nlp-ft origin/master

Record its resulting commit in this plan before editing.

Run focused Bifrost validation during milestones from `/mnt/optane/bifrost-nlp`:

    cargo fmt --check
    scripts/with-isolated-cargo-target.sh cargo test -p bifrost-analysis --features nlp nlp::
    scripts/with-isolated-cargo-target.sh cargo test -p bifrost-mcp --features nlp mcp_nlp
    uv run --python 3.12 -- scripts/embedding_sidecar.py --selftest \
      --profile dw10 \
      --model-dir /home/jonathan/Projects/brokkbench/localizer/artifacts/voyage-nano-gen-v4-n24-s30-dw10
    uv run --python 3.12 -- scripts/embedding_sidecar.py --selftest \
      --profile granite-r2 \
      --model-dir /home/jonathan/Projects/brokkbench/localizer/artifacts/granite-r2-small-v4-final

Before the comprehensive NLP build, inspect disk use and confirm no sibling all-feature build is
running:

    df -h /mnt/optane /home/jonathan
    ps -eo pid,etimes,cmd
    scripts/cleanup-bifrost-tmp.sh

Then run the repository-required gate:

    cargo fmt
    scripts/with-isolated-cargo-target.sh \
      uv run --python 3.12 -- cargo test --features nlp,python
    scripts/with-isolated-cargo-target.sh \
      cargo clippy --all-targets --all-features -- -D warnings

Run Anvil validation from `/mnt/optane/anvil-bifrost-nlp-ft`. Full tests require escalation
because Wiremock binds localhost:

    cargo fmt --check
    cargo test semantic_rerank
    cargo test semantic_search_description_is_overridden
    cargo test
    cargo clippy --all-targets -- -D warnings

Run targeted brokkbench tests from `/home/jonathan/Projects/brokkbench`:

    PYTHONPATH=. uv run pytest sandbox/<changed-test-module>.py
    PYTHONPATH=. uv run pytest agenteval/<relevant-existing-test-module>.py
    PYTHONPATH=. uv run pytest cimeval
    uv run ruff check --config pyproject.toml <changed-python-files>

The exact cimeval invocation must be documented by its CLI help and stabilized during
Milestone 4. Its intended sequence is:

    cd /home/jonathan/Projects/brokkbench
    uv run cimeval prepare --run-dir /mnt/optane/bifrost-nlp-resources/runs/<run-id>
    uv run cimeval serve --run-dir /mnt/optane/bifrost-nlp-resources/runs/<run-id> \
      --profile dw10
    uv run cimeval prewarm --run-dir /mnt/optane/bifrost-nlp-resources/runs/<run-id> \
      --models dw10,granite-r2
    uv run cimeval preflight --run-dir /mnt/optane/bifrost-nlp-resources/runs/<run-id> \
      --provider auto
    uv run cimeval run --run-dir /mnt/optane/bifrost-nlp-resources/runs/<run-id> \
      --models dw10,granite-r2 \
      --profiles all-signals,semantic-only,semantic-coedit-2-1 \
      --seeds 0,1,2 --timeout 30m --jobs 4 --resume
    uv run cimeval score --run-dir /mnt/optane/bifrost-nlp-resources/runs/<run-id>
    uv run cimeval report --run-dir /mnt/optane/bifrost-nlp-resources/runs/<run-id>

If implementation chooses `python -m cimeval` rather than installing a console entry point,
update every command here and in the report together. Do not leave two competing command forms.

At each material checkpoint, inspect all three working trees, stage only owned paths, and use a
multiline commit message explaining both the change and why it was needed:

    git status --short
    git diff --check
    git diff -- <owned paths>

## Validation and Acceptance

Model correctness is accepted when fixed query and passage fixtures produce finite,
unit-normalized Rust-side vectors matching the Python SentenceTransformers reference within a
documented tolerance for the same precision. The dw10 result must have 512 values and Granite
R2 384. Parent-composed vectors must match
`normalize(0.65 * child + 0.35 * parent)`. Swapping profile, prefix, pooling, dimension,
precision, artifact contents, or backend must change the fingerprint and prevent stale-cache
reuse.

Retrieval correctness is accepted through behavior-focused tests with enough fake symbols and
history to fill every leg. For final `k=20`, the Anvil trace must show:

    all-signals:
      Bifrost base depth 40
      requested vector/BM25/co-edit = 40/40/40

    semantic-only:
      Bifrost base depth 40
      requested vector/BM25/co-edit = 120/0/0

    semantic-coedit-2-1:
      Bifrost base depth 40
      requested vector/BM25/co-edit = 80/0/40

Repeat equivalent assertions at final `k=1` and at one intermediate value. Verify that BM25 code
is not called in profiles where it is disabled and that co-edit seed paths come from the
specified legs.

Anvil's public contract is accepted when its emitted JSON schema contains default 20, minimum
1, maximum 20, and explanatory prose about fewer-than-`k` results. A reranker selection of
seven candidates at `k=20` returns seven. A valid empty list returns zero. A selection of 25
returns 20. Provider failure returns at most 20 deterministic fused results and records
fallback. A Bifrost failure remains a tool error. A 120-candidate semantic-only pool includes
all 120 identities in the reranker prompt while respecting the global context budget.

Sandbox transport is accepted when a process inside a direct Podman sandbox reaches only the
declared host loopback test port, exchanges framed data, and an empty port tuple generates the
existing sandbox behavior. Existing agenteval targeted tests must pass without changed fixtures
or expectations except where a shared helper's new optional default is represented.

Shared-cache operation is accepted when two task containers concurrently bind the same prepared
cache directory, open Bifrost with the same model fingerprint, independently change their
working trees, rebuild their active indexes, and complete semantic searches without corruption,
unrecovered `SQLITE_BUSY`/`SQLITE_LOCKED`, or results from blobs absent from the querying
container's working tree. After both processes close, `PRAGMA integrity_check` must return
`ok`. The test must confirm that the database, WAL, and SHM paths resolve to the same host files,
not per-container copies.

The benchmark pilot is accepted when one PolyBench and one Pro instance each complete all six
model/profile combinations for seed 0, official scoring runs in fresh containers, every cell
has a valid manifest and trace, hidden raw candidates do not enter localization View A, View B
drops result-only paths, and rescoring is deterministic.

The full campaign is accepted when the run status accounts for exactly 1,638 expected cells,
uses one provider, contains no secret material, has no unreviewed leak finding, and every
non-legitimate cell appears in the exclusion ledger. The report must regenerate from the run
directory without calling an LLM or rerunning task containers.

Before completing code changes, attempt the repository-required Bifrost policy check only if
the `bifrost-policy-checking` skill and its `list_policies` and `run_policy` tools are actually
installed. Run `bifrost.code-smells` together with every executable repository policy root
explicitly named by the project. Treat `finding` as review work and `unreliable` as failure,
then rerun after fixes. If the skill or tools are absent, record that fact here and do not claim
policy success.

## Idempotence and Recovery

Model serving and prewarming commands may be rerun. They bind new managed processes and reuse a
shared database only when its `READY` manifest matches. A missing or mismatched database is
built in a temporary sibling and atomically published before any cell opens it. Once published,
the database remains a shared writable cache and must never be renamed, replaced, migrated, or
fingerprint-invalidated while a cell is using it. They must not mutate the localizer artifacts.

Each benchmark cell starts from a fresh official task image but bind-mounts the appropriate
shared instance/model cache directory. An interrupted cell lacks `COMPLETE` and is safe to
replace; its cached content may remain because it is content-addressed and inactive unless a
later working tree resolves the same blobs. A complete cell artifact directory is immutable; if
its input manifest changes, schedule a new cell/run identity rather than overwriting evidence.

Keep provider attempts in distinct run directories. An abandoned Bedrock run remains evidence
and is never merged into an OpenRouter grid.

Do not remove worktrees, caches, images, model services, or run directories automatically at
the end. Report their locations and sizes. Cleanup is a separate user-authorized action.

If an all-feature Bifrost build fails or is interrupted, rely on
`scripts/with-isolated-cargo-target.sh` cleanup. Never create a manually named Cargo target
under `/tmp`. Inspect stale targets with `scripts/cleanup-bifrost-tmp.sh` before applying any
cleanup.

The brokkbench and Anvil primary checkouts contain unrelated state. Never use `git reset`,
`git clean`, `git checkout --`, broad staging, or recursive deletion. If an owned file overlaps
an unexpected user edit, stop that edit, record the overlap here, and resolve it explicitly.

## Artifacts and Notes

The small committed artifacts are:

    /mnt/optane/bifrost-nlp/.agents/plans/bifrost-localizer-cim-eval.md
    /mnt/optane/bifrost-nlp/.agents/docs/dw10-granite-cim-semantic-search-evaluation.md
    Bifrost source and behavior tests
    Anvil worktree source and behavior tests
    brokkbench sandbox/cimeval source and behavior tests

The large uncommitted artifacts live under:

    /mnt/optane/bifrost-nlp-resources/runs/<run-id>

Record the final run ID, provider, run-manifest hash, result database path, report command, and
disk usage in this section.

Do not add model weights, credentials, OCI layers, semantic caches, raw agent traces, or result
databases to any Git commit.

## Interfaces and Dependencies

Bifrost adds these environment interfaces:

    BIFROST_EMBED_PROFILE=auto|dw10|granite-r2
    BIFROST_EMBED_MODEL_DIR=<one explicit artifact directory>
    BIFROST_EMBED_MODEL_ROOT=<root containing both canonical artifact directories>
    BIFROST_EMBED_ENDPOINT=tcp://127.0.0.1:<port>
    BIFROST_EMBED_TOKENIZER_DIR=<tokenizer/config-only directory for remote mode>
    BIFROST_SEMANTIC_SEARCH_PROFILE=all-signals|semantic-only|semantic-coedit-2-1

Existing explicit settings take precedence in this order:

    explicit profile and explicit model directory
    explicit profile and model root
    auto profile and model root

Remote endpoint selection changes only where inference runs. The selected profile and tokenizer
metadata still determine chunking and must agree with the endpoint handshake.

Anvil changes the model-facing `semantic_search` schema to:

    {
      "query": {
        "type": "string"
      },
      "k": {
        "type": "integer",
        "minimum": 1,
        "maximum": 20,
        "default": 20,
        "description": "Maximum number of final relevance-reranked results. The reranker may return fewer than k by design when fewer candidates are relevant."
      }
    }

The overall Anvil tool description must convey the same ceiling and fewer-results behavior.
Bifrost's raw MCP result remains structured for Anvil rather than being advertised as the
agent-visible final list.

Brokkbench adds one backward-compatible sandbox field:

    SandboxSpec.host_loopback_tcp_ports: tuple[int, ...] = ()

It also adds the `cimeval` command family described above. The harness depends on the existing
brokkbench sandbox/bundle code, official benchmark scorers, the checked `supercoder-eval`
localization/statistics definitions, and standard Python libraries already accepted by the
repository's PEP 723/uv workflow. Prefer existing dependencies; document and pin any new
dependency before use.

Revision note, 2026-07-31: Initial self-contained plan created after repository and artifact
inspection. It records the user's final decisions that Anvil uses multiplier two, documents a
maximum `k` of 20, and may return fewer than `k` by design.

Revision note, 2026-07-31: Replaced the underspecified immutable-cache restore language with
Bifrost's intended shared-database design. All arm/seed containers for one instance/model now
bind the same writable SQLite directory and rely on real SQLite WAL locking; initialization,
migration, invalidation, and rebuild are forbidden while concurrent cell users are active.
