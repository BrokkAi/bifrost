# Granite R2 Semantic Search Evaluation

Status: semantic campaign in progress. This report records finalized methodology and baseline
results; Granite outcome tables remain intentionally absent until all reportable cells finish.

## Question

Does the Granite R2 localizer improve GPT-5.6 Luna's software-task performance when Bifrost
retrieval is exposed through Anvil, and how much do BM25 and co-edit signals contribute beyond
semantic similarity?

The three Granite arms use the same Anvil reranker and the same nominal `6k` raw opportunity at
model-facing final `k=20`:

| Arm | Vector | BM25 | Co-edit | Final ceiling |
| --- | ---: | ---: | ---: | ---: |
| all signals | 40 | 40 | 40 | 20 |
| semantic only | 120 | 0 | 0 | 20 |
| semantic + co-edit 2:1 | 80 | 0 | 40 | 20 |

Anvil may return fewer than `k` results by design. It does not refill candidates rejected by the
reranker.

## Experimental design

- Task set: the released 91-task Code Isn't Memory frame, joined to official SWE-PolyBench and
  SWE-bench Pro task metadata and images.
- Replicates: seeds 0, 1, and 2 denote independent pass@1 runs, matching CIM's usage rather than
  claiming a provider sampling-seed control.
- Agent: Mjolnir with Anvil, GPT-5.6 Luna through Bedrock, maximum reasoning effort, at most 100
  Anvil turns and 1,800 seconds of agent wall time.
- Execution: official task images through brokkbench direct-Podman sandboxes, with generation and
  inline scoring in the same container. Held-out patch conflicts use the versioned pristine
  fallback scorer.
- Concurrency: 30 cells throughout the baseline and Granite campaigns.
- Indexes: one live SQLite database per upstream repository and model, shared across task
  revisions, arms, and seeds. Granite inference and index construction run on the local A4000.
- Retrieval: Bifrost Granite R2 profile, CLS pooling, width 384, maximum sequence length 8192,
  and normalized `0.65 * child + 0.35 * parent` composition.
- Primary outcome: official resolve rate. Secondary outcomes include CIM-compatible View B
  localization, turns, tokens, cost, wall time, candidate realization, reranker selection,
  source-context bytes, fallback rate, and retrieval latency.
- Statistics: mean of the three seed means, across-seed standard deviation, and paired
  tie-corrected Wilcoxon signed-rank comparisons on per-instance seed means.

## No-semantic baseline sanity gate

The max-reasoning Luna baseline completed, localized, scored, and leak-audited all 273 cells.
It resolved 140/273 (51.3%) with zero leak flags.

| Seed | Resolved | Resolve rate | View B Acc@5 | Mean turns | Mean cost/cell |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 49/91 | 53.8% | 50.5% | 39.6 | $0.491 |
| 1 | 48/91 | 52.7% | 52.7% | 42.3 | $0.508 |
| 2 | 43/91 | 47.3% | 50.5% | 42.3 | $0.469 |

Total baseline cost was $133.52, or $0.954 per solve. The outcome is operationally sane beside
CIM's published no-index references: SC-OFF resolved 43.9%, 41.5%, and 40.2% across its three
seeds, while OpenCode resolved 44.4%, 45.7%, and 45.7%. The comparison is deliberately loose:
the agent, model, maximum reasoning behavior, and token usage differ from CIM.

## Runtime validity

The reportable semantic cells use one immutable runtime bundle. Each result records the bundle
SHA-256 plus exact Bifrost, Anvil, Mjolnir, and brokkbench revisions, and resume rejects a
completed cell produced by a different runtime.

Before the final queue, live task-container gates found and repaired three correctness issues:

1. Bifrost returned no candidates when the first query's one-second stale-index fallback fired
   before any active index existed. The first query now waits for initial readiness while later
   rebuilds retain bounded stale-index fallback.
2. Anvil could retrieve 120 candidates but attach zero source context because a symbol request
   exceeded Bifrost's schema limit and degraded file outlines were ignored. Context fetching is
   now batched in RRF order and accepts compact outlines.
3. Concurrent Bedrock catalog discovery could time out before Anvil advertised its model control.
   Mjolnir now launches Anvil with the already selected provider-qualified model and reasoning
   effort.

The first semantic call under the final 30-worker runtime was a semantic-only Dubbo task. It
requested and realized exactly 120 vector candidates, attached 89,166 bytes of source context,
selected 12 results under final `k=20`, did not fall back, and completed retrieval in 84.9 ms
(18.6 ms Granite service time).

## Granite results

To be populated after all 819 semantic cells complete, followed by localization and the final
leak audit. No partial outcome estimate is reported here because completion order is correlated
with task duration and therefore not outcome-blind.

## Change inventory

To be finalized with exact commits and validation evidence after the campaign. The implementation
spans Bifrost model/index/retrieval behavior, Anvil overfetch and reranking, Mjolnir provider and
effort routing, and brokkbench sandbox, scoring, provenance, audit, localization, scheduling, and
reporting infrastructure.
