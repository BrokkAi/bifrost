# Calibrate reference-kind weights for usage-graph relevance

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

The opt-in `usage_graph` mode of `most_relevant_files` currently treats every resolved source line equally, whether the line calls a function, names a type, accesses a member, or otherwise references a declaration. After this work, Bifrost will retain those broad reference kinds internally and use empirically selected default weights that retrieve useful companion files more consistently across several programming languages. The public MCP request will remain simple unless the measurements demonstrate a need for user tuning.

The result will be observable through a deterministic ignored benchmark over repositories in `/Users/dave/Workspace/test-repos`, focused behavior tests, and before/after ranking examples. The benchmark will report retrieval metrics against git co-change labels, which are independent of the usage graph being tuned, as well as category-specific graph coverage and timing.

## Progress

- [x] (2026-07-15T13:12:00Z) Created the calibration goal, inventoried available test repositories, and selected an evaluation design.
- [x] (2026-07-15T13:28:00Z) Retained call, member, type, and other reference counts through every inverted usage adapter without changing uniform aggregate weights.
- [x] (2026-07-15T14:08:00Z) Added a deterministic ignored benchmark that builds each repository graph once and sweeps candidate profiles against bounded recent git co-change targets.
- [x] (2026-07-15T14:08:00Z) Ran the benchmark across eight usable corpora covering Python, TypeScript, PHP, Java, Go, C++, mixed native/JVM code, and a small Rust workspace; recorded impractical full Rust and C# construction runs.
- [x] (2026-07-15T14:08:00Z) Inspected deterministic examples and selected the conservative calibrated profile: call 1.5, member 1.25, type 1.0, other 0.875.
- [x] (2026-07-15T15:02:00Z) Passed formatting, focused graph/relevance tests, all-target/all-feature Clippy, the complete `nlp,python` library and integration suite, and rustdoc; completed the final review and checkpoint.

## Surprises & Discoveries

- Observation: the graph already records type and member references for many languages, but `UsageEdgeWeights` collapses them into one integer before PageRank.
  Evidence: `src/analyzer/usages/inverted_edges.rs::PerFileEdges` keys only by caller and callee, and `src/relevance.rs::related_files_by_usage` converts that count directly to `f64`.

- Observation: scaling every edge by one configurable number cannot change PageRank because each node's outgoing transitions are normalized.
  Evidence: `src/relevance.rs::weighted_page_rank` divides each outgoing edge weight by the source node's total outgoing weight.

- Observation: `/Users/dave/Workspace/test-repos` contains manageable single-ecosystem corpora for Go (`godog`), Python (`cassandra-python-driver`), TypeScript (`ngx-admin`), PHP (`dbal`), Java (`Minestom`), C++ (`kokkos`), plus larger Rust, C#, and Scala corpora.
  Evidence: extension counts captured during the initial inventory; exact repository choices and sizes will be recorded under `Artifacts and Notes`.

- Observation: multiple resolved references from one caller to one callee on the same source line were historically one weighted site, so independently summing kind counts would change compatibility.
  Evidence: the new per-line kind map uses the strongest structured kind in the order call, member, type, other; `strongest_kind_wins_when_one_edge_repeats_on_a_line` proves one total site remains.

- Observation: several `test-repos` checkouts initially had only one commit, which produced valid graphs but no independent co-change labels.
  Evidence: `godog`, `ruff`, `kokkos`, `bitwarden-server`, and `spark` reported `git rev-list --count HEAD` as one. Their histories were deepened by 300 commits without changing the checked-out trees.

- Observation: aggressive call-first weighting overfits behavior-heavy corpora and degrades Go, where type relationships are especially informative.
  Evidence: on the 20-seed `godog` sample, uniform NDCG@10 was 0.28596, subtle weighting was 0.28668, and type-light weighting fell to 0.28075. On `kokkos`, the same values were 0.18745, 0.19240, and 0.20243, demonstrating why the selected cross-language default should be a small rather than maximal bias.

- Observation: full-scale Rust and C# graph construction is not practical for iterative weight calibration on this checkout.
  Evidence: `ruff` and `bitwarden-server` each exceeded nine minutes before reaching the profile sweep and were stopped. The small Rust `lgtm` corpus completed but only eight labeled seeds were available. This is a graph-construction performance concern, not PageRank cost.

- Observation: four `u16` counters retain the 8-byte compact edge payload used by the previous single `usize` weight on supported 64-bit targets.
  Evidence: `reference_counts_keep_the_legacy_edge_payload_size` pins `size_of::<UsageReferenceCounts>() == 8`; retained non-truncated callees are below the 1,000-site cap, so `u16` is exact for every edge PageRank consumes.

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

- Decision: select call 1.5, member 1.25, type 1.0, and other 0.875 as the production profile.
  Rationale: across eight corpora, this subtle profile improved macro NDCG@10 from 0.18686 to 0.18977, MRR@10 from 0.36166 to 0.36745, and Recall@10 from 0.13222 to 0.13847. It also slightly improved Go instead of accepting the regression caused by stronger profiles. The improvement is modest enough to reflect the noisy co-change proxy rather than claim false precision.
  Date/Author: 2026-07-15 / Codex

- Decision: keep the selected weights internal and expose no new MCP parameter.
  Rationale: one conservative profile generalized adequately, while raw numeric controls would enlarge every Rust, MCP, CLI, and Python interface without demonstrated user need. The ignored benchmark keeps alternatives reproducible for future recalibration.
  Date/Author: 2026-07-15 / Codex

## Outcomes & Retrospective

Calibration is complete. Bifrost now distinguishes four broad structured reference kinds internally, applies a conservative empirically selected profile in usage-graph relevance, and retains a deterministic benchmark for future recalibration without expanding the public request schema.

Milestone 1 outcome 2026-07-15T13:28:00Z: `UsageReferenceCounts` now survives from every language scanner through `UsageEdgeWeights` and the dense workspace graph. The public site-bearing graph still emits its unchanged `(path, line)` payload, dead-code consumers sum the four counts, and relevance currently combines them with a uniform profile. Structured classifier and focused graph/relevance tests pass.

Milestone 2 outcome 2026-07-15T14:08:00Z: the ignored benchmark evaluates deterministic random seed files against independent git co-change labels while reusing one expensive graph across all profiles. Eight completed corpora favor a subtle behavioral profile overall. The selected default improves all three macro metrics, preserves type references at full strength, avoids the measured Go regression, and adds no public configuration surface.

Final outcome 2026-07-15T15:02:00Z: the selected call 1.5, member 1.25, type 1.0, other 0.875 defaults passed the entire feature-enabled Rust suite. The benchmark remains explicitly opt-in and accepts an OS-native path list through `BIFROST_USAGE_WEIGHT_BENCH_REPOS`, so it has no user-specific paths and works on Windows as well as Unix-like hosts. The principal follow-up is graph-construction performance on large Rust and C# workspaces; profile application itself is cheap and does not justify a second cache.

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

Run the ignored benchmark using an OS-native path list (colon-separated on macOS/Linux, semicolon-separated on Windows). It reads git history but does not write into the repositories and prints one JSON result line per repository plus one aggregate line:

    BIFROST_USAGE_WEIGHT_BENCH_REPOS=/Users/dave/Workspace/test-repos/cassandra-python-driver:/Users/dave/Workspace/test-repos/ngx-admin:/Users/dave/Workspace/test-repos/dbal:/Users/dave/Workspace/test-repos/jgit:/Users/dave/Workspace/test-repos/godog:/Users/dave/Workspace/test-repos/kokkos:/Users/dave/Workspace/test-repos/lgtm:/Users/dave/Workspace/test-repos/tsngtest BIFROST_USAGE_WEIGHT_BENCH_SAMPLES=20 BIFROST_USAGE_WEIGHT_BENCH_COMMITS=300 BIFROST_USAGE_WEIGHT_BENCH_SEED=781 cargo test benchmark_usage_reference_weight_profiles --lib -- --ignored --nocapture

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

Final deterministic 20-seed macro results across `cassandra-python-driver`, `ngx-admin`, `dbal`, `jgit`, `godog`, `kokkos`, `lgtm`, and `tsngtest`:

    profile                 NDCG@10   MRR@10   Recall@10
    uniform                 0.18686   0.36166  0.13222
    subtle_behavioral       0.18977   0.36745  0.13847
    conservative_behavioral 0.19147   0.36920  0.13961
    type_light              0.19279   0.37461  0.14005

The stronger profiles have higher macro scores but reduce `godog` NDCG and recall. The selected subtle profile instead raises `godog` NDCG from 0.28596 to 0.28668 while also improving the behavior-heavy corpora. Representative output showed stable, plausible collaborators such as `cassandra/connection.py` for Python policy tests, JGit object-reader and object-ID files for abbreviation tests, and Kokkos execution-policy and view-construction headers for policy tests.

Graph timings from cold or partially warm debug-profile runs were approximately 15.6s for `cassandra-python-driver`, 0.7s for `ngx-admin`, 1.7s for `dbal`, 74.4s for `jgit`, 0.6s for `godog`, 171.0s for `kokkos`, 4.2s for `lgtm`, and 5.0s for `tsngtest`. Sweeping all profiles was much cheaper than construction. `ruff` and `bitwarden-server` exceeded the nine-minute calibration cutoff.

Milestone 1 validation:

    BIFROST_SEMANTIC_INDEX=off cargo test inverted_edges::tests --lib
    test result: ok. 6 passed; 0 failed

    BIFROST_SEMANTIC_INDEX=off cargo test --test usage_graph_test --test usage_graph_identity_test --test most_relevant_files
    test result: ok. 16 + 9 + 27 passed; 0 failed

Final validation:

    cargo fmt --all -- --check
    passed

    env PATH=/opt/homebrew/bin:/usr/bin:/bin scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    passed

    RUSTFLAGS='-Clink-arg=-undefined -Clink-arg=dynamic_lookup' BIFROST_SEMANTIC_INDEX=off cargo test --lib --tests --features nlp,python
    passed; library result 840 passed, 0 failed, 4 ignored, followed by all integration binaries with 0 failures

    env PATH=/opt/homebrew/bin:/usr/bin:/bin RUSTFLAGS='-Clink-arg=-undefined -Clink-arg=dynamic_lookup' BIFROST_SEMANTIC_INDEX=off scripts/with-isolated-cargo-target.sh cargo test --doc --features nlp,python
    passed; 0 doc tests, 0 failures

## Interfaces and Dependencies

Define an internal enum and compact counts in `src/analyzer/usages/inverted_edges.rs`, conceptually:

    pub(crate) enum UsageReferenceKind { Call, Member, Type, Other }

    pub(crate) struct UsageReferenceCounts { call: usize, member: usize, type_: usize, other: usize }

Define `UsageReferenceWeights` near the relevance graph consumer. It must validate finite non-negative weights and compute a combined transition weight from counts. Keep it internal while calibrating. No third-party dependency is required; deterministic sampling can use stable hashing or a small fixed pseudo-random generator implemented for the benchmark.

Revision note 2026-07-15T13:12:00Z: Created the calibration ExecPlan after inventorying available corpora and identifying git co-change retrieval as an independent evaluation signal.

Revision note 2026-07-15T13:28:00Z: Recorded the completed kind-retention milestone, the same-line compatibility rule, and focused validation evidence.

Revision note 2026-07-15T14:08:00Z: Recorded the reproducible benchmark, corpus limitations, profile sweep, selected calibrated defaults, compact counter representation, and decision not to add MCP configuration.

Revision note 2026-07-15T15:02:00Z: Recorded final validation, removed user-specific benchmark defaults in favor of an OS-native environment path list, and closed the calibration outcome.
