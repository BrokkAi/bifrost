# Calibrate reference-kind weights for usage-graph relevance

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

The opt-in `usage_graph` mode of `most_relevant_files` currently treats every resolved source line equally, whether the line calls a function, names a type, accesses a member, or otherwise references a declaration. After this work, Bifrost will retain those broad reference kinds internally and use empirically selected default weights that retrieve useful companion files more consistently across several programming languages. The public MCP request will remain simple unless the measurements demonstrate a need for user tuning.

The result will be observable through a deterministic ignored benchmark over repositories in `/Users/dave/Workspace/test-repos`, focused behavior tests, and before/after ranking examples. The benchmark will report retrieval metrics against git co-change labels, which are independent of the usage graph being tuned, as well as category-specific graph coverage and timing.

## Progress

- [x] (2026-07-15T13:12:00Z) Created the calibration goal, inventoried available test repositories, and selected an evaluation design.
- [x] (2026-07-15T13:28:00Z) Retained call, member, type, and other reference counts through every inverted usage adapter without changing uniform aggregate weights.
- [ ] Add a deterministic ignored benchmark that builds each repository graph once and sweeps candidate profiles against held-out git co-change targets.
- [ ] Run the benchmark across representative Go, Python, JavaScript/TypeScript, Java, Rust, PHP, C#, C++, and Scala repositories where runtime permits.
- [ ] Inspect representative query results, choose conservative defaults, and add behavior regressions that demonstrate the intended ordering.
- [ ] Run formatting, focused tests, Clippy, and the full feature-enabled test suite; document and checkpoint every milestone.

## Surprises & Discoveries

- Observation: the graph already records type and member references for many languages, but `UsageEdgeWeights` collapses them into one integer before PageRank.
  Evidence: `src/analyzer/usages/inverted_edges.rs::PerFileEdges` keys only by caller and callee, and `src/relevance.rs::related_files_by_usage` converts that count directly to `f64`.

- Observation: scaling every edge by one configurable number cannot change PageRank because each node's outgoing transitions are normalized.
  Evidence: `src/relevance.rs::weighted_page_rank` divides each outgoing edge weight by the source node's total outgoing weight.

- Observation: `/Users/dave/Workspace/test-repos` contains manageable single-ecosystem corpora for Go (`godog`), Python (`cassandra-python-driver`), TypeScript (`ngx-admin`), PHP (`dbal`), Java (`Minestom`), C++ (`kokkos`), plus larger Rust, C#, and Scala corpora.
  Evidence: extension counts captured during the initial inventory; exact repository choices and sizes will be recorded under `Artifacts and Notes`.

- Observation: multiple resolved references from one caller to one callee on the same source line were historically one weighted site, so independently summing kind counts would change compatibility.
  Evidence: the new per-line kind map uses the strongest structured kind in the order call, member, type, other; `strongest_kind_wins_when_one_edge_repeats_on_a_line` proves one total site remains.

## Decision Log

- Decision: evaluate profiles primarily against recent git co-change relationships rather than treating existing usage edges as ground truth.
  Rationale: optimizing a graph against labels derived from the same graph would circularly reward whichever reference kind receives the largest configured weight. Co-change is imperfect but independent and directly related to the context-expansion use case.
  Date/Author: 2026-07-15 / Codex

- Decision: use four broad internal kinds: call, member, type, and other.
  Rationale: these categories are understandable across supported languages and avoid an unstable public taxonomy of reads, writes, inheritance, construction, annotations, and imports before evidence justifies it.
  Date/Author: 2026-07-15 / Codex

- Decision: do not add raw weight fields to the MCP schema during calibration.
  Rationale: tagging consistency and useful defaults are the hard problems. A benchmark-only internal control avoids making experimental knobs part of the client contract.
  Date/Author: 2026-07-15 / Codex

- Decision: use deterministic pseudo-random seed sampling and report aggregate NDCG@10, MRR@10, and Recall@10.
  Rationale: deterministic samples make runs comparable, while several retrieval metrics reduce the chance of choosing weights that optimize one arbitrary cutoff or one repository.
  Date/Author: 2026-07-15 / Codex

## Outcomes & Retrospective

Calibration is in progress. The initial design establishes an independent quantitative signal, retains qualitative inspection, and deliberately postpones public configurability.

Milestone 1 outcome 2026-07-15T13:28:00Z: `UsageReferenceCounts` now survives from every language scanner through `UsageEdgeWeights` and the dense workspace graph. The public site-bearing graph still emits its unchanged `(path, line)` payload, dead-code consumers sum the four counts, and relevance currently combines them with a uniform profile. Structured classifier and focused graph/relevance tests pass.

## Context and Orientation

`src/analyzer/usages/inverted_edges.rs` contains the language-independent edge collector. Each language-specific inverted scanner resolves a source AST node to a declaration and calls `EdgeCollector::record`. The collector currently stores distinct source lines under `(caller, callee)`, and `UsageEdgeWeights` reduces each pair to one count. `src/analyzer/usages/workspace_graph.rs` maps those declaration keys to dense workspace node IDs. `src/relevance.rs::related_files_by_usage` turns each integer edge count into a PageRank transition weight.

A reference kind describes why source code points at a declaration. A call invokes a callable. A member reference reads, writes, or otherwise names a field, property, method, or nested declaration through an owner or receiver. A type reference names a class, interface, trait, alias, or other type in an annotation, generic, inheritance clause, construction expression, or scoped type path. Other covers resolved bare references that do not fit those categories. A source site must contribute to one category only so total equal-weight behavior remains compatible.

For evaluation, a seed file is one source file given to `most_relevant_files`. A co-change target is another source file changed in the same recent git commit. NDCG@10 rewards relevant targets near the top while allowing multiple targets, MRR@10 measures the rank of the first relevant target, and Recall@10 measures how many known targets appear in the first ten results. Commits that are likely bulk formatting or vendoring changes must be excluded by bounding the number of touched source files.

## Plan of Work

First, extend the shared inverted-edge representation with an internal `UsageReferenceKind` and a compact count vector. Preserve the current site-bearing public `usage_graph` wire format by flattening kinds back into its existing site list. Change language scanners to tag references using structured AST context, not source-text parsing. Add per-language behavior tests for at least calls, types, and members, and prove a profile with all weights equal to one produces the same aggregate edge weights as before.

Second, separate compact graph construction from applying a `UsageReferenceWeights` profile so one expensive workspace scan can be reused for many candidate profiles. Add an ignored, environment-driven benchmark test under the relevance module. It will accept a list of repository paths, a deterministic seed, a sample limit, a bounded git-history window, and candidate profiles. It will build the analyzer and usage graph once per repository, derive co-change labels from git without modifying the repository, rank every sampled seed under every profile, and emit machine-readable per-repository and aggregate metrics plus phase timings.

Third, run a coarse sweep that includes uniform weighting and profiles that progressively favor calls and members over types and other references. Refine around profiles that improve macro-averaged metrics without materially harming any ecosystem. Inspect several deterministic queries per repository to reject profiles that retrieve superficially connected utility or model files at the expense of behaviorally relevant collaborators.

Finally, encode the most conservative defensible profile as the internal default. Keep the uniform profile available internally for regression comparison. Add small end-to-end tests where calls, types, and members compete, update this plan with the complete measurements, and run the required Rust gates. Do not expose raw MCP weights unless the evidence shows materially different repositories need materially different optima and no single conservative profile is acceptable.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/5e5c/bifrost` on the already checked-out issue branch.

After kind retention, run:

    cargo fmt --all -- --check
    BIFROST_SEMANTIC_INDEX=off cargo test inverted_edges --lib
    BIFROST_SEMANTIC_INDEX=off cargo test --test usage_graph_test --test usage_graph_identity_test

Run the ignored benchmark using the exact environment and test name added during the benchmark milestone. The command must use repository paths under `/Users/dave/Workspace/test-repos`, must not write into those repositories, and must print one JSON result line per repository plus one aggregate line.

Before completion, run:

    cargo fmt --all -- --check
    cargo clippy --all-targets --all-features -- -D warnings
    BIFROST_SEMANTIC_INDEX=off cargo test --features nlp,python

If an isolated Cargo target is required, use `scripts/with-isolated-cargo-target.sh`; do not create manually named target directories.

## Validation and Acceptance

With all reference-kind weights set to one, every existing usage edge weight and default `usage_graph` ranking test must remain unchanged. Category tests must prove that type, member, call, and other references are tagged once rather than duplicated. Public `usage_graph` JSON and Python models must remain unchanged.

The calibration benchmark must be deterministic for the same repository commits, sampling seed, and configuration. It must evaluate at least five ecosystems, include uniform weighting as the baseline, and report enough per-repository detail to detect a profile that wins only by dominating one large corpus. The selected default must improve or tie the macro-average retrieval metrics, avoid a material regression in any adequately sampled ecosystem, and pass qualitative inspection. Graph construction time and retained-memory growth must be recorded because richer counters must not conceal a material #754-style regression.

## Idempotence and Recovery

The benchmark reads repositories and git history without checkout, reset, or other mutation. Re-running it replaces no source artifacts and produces comparable stdout. If a large repository exceeds a practical runtime, reduce its deterministic sample count or replace it with the documented smaller corpus for the same ecosystem; do not silently omit the ecosystem. If kind tagging exposes a language resolver ambiguity, preserve it as `other` or unproven rather than guessing from source text.

## Artifacts and Notes

Initial corpus inventory includes `godog` (91 Go files), `cassandra-python-driver` (266 Python files), `ngx-admin` (242 TypeScript files), `dbal` (641 PHP files), `Minestom` (1,759 Java files), `kokkos` (about 1,200 C/C++ headers and sources), `ruff` (1,753 Rust files), `bitwarden-server` (4,204 C# files), and `spark` (5,547 Scala files). Large corpora may use fewer sampled seeds, but graph construction still covers their configured workspace.

The prior issue #781 implementation measured roughly 40.5 seconds to build Bifrost's compact usage graph, while PageRank and file aggregation together took about 26 milliseconds. The calibration harness must therefore build once and sweep profiles over the retained graph rather than rebuilding for every candidate.

Milestone 1 validation:

    BIFROST_SEMANTIC_INDEX=off cargo test inverted_edges::tests --lib
    test result: ok. 6 passed; 0 failed

    BIFROST_SEMANTIC_INDEX=off cargo test --test usage_graph_test --test usage_graph_identity_test --test most_relevant_files
    test result: ok. 16 + 9 + 27 passed; 0 failed

## Interfaces and Dependencies

Define an internal enum and compact counts in `src/analyzer/usages/inverted_edges.rs`, conceptually:

    pub(crate) enum UsageReferenceKind { Call, Member, Type, Other }

    pub(crate) struct UsageReferenceCounts { call: usize, member: usize, type_: usize, other: usize }

Define `UsageReferenceWeights` near the relevance graph consumer. It must validate finite non-negative weights and compute a combined transition weight from counts. Keep it internal while calibrating. No third-party dependency is required; deterministic sampling can use stable hashing or a small fixed pseudo-random generator implemented for the benchmark.

Revision note 2026-07-15T13:12:00Z: Created the calibration ExecPlan after inventorying available corpora and identifying git co-change retrieval as an independent evaluation signal.

Revision note 2026-07-15T13:28:00Z: Recorded the completed kind-retention milestone, the same-line compatibility rule, and focused validation evidence.
