---
title: Evidence and Evaluation Methodology
description: Understand what Bifrost currently demonstrates and how to evaluate it rigorously.
---

Bifrost's public documentation currently provides executable correctness examples, not a published aggregate accuracy or large-repository performance study. The distinction matters: an architecture designed to avoid permanently retaining every analysis graph is not evidence of a particular memory ceiling, and a passing language fixture is not a precision/recall measurement.

## What Is Publicly Reproducible Today

| Evidence | What it establishes | What it does not establish |
| --- | --- | --- |
| [Ten-minute evaluation](/evaluate-bifrost/) | One checked-in Python fixture produces the same structural result through CLI JSON, saved RQL, agent MCP, and VS Code LSP. | Corpus-wide accuracy, dynamic call completeness, or large-repository performance. |
| [Language query tutorials](/code-query-tutorials/) | Checked-in source, query, and expected output remain executable across all supported languages. | Representative prevalence or accuracy across real-world repositories. |
| [Receiver traversal cookbook](/code-query-tutorials/receiver-traversal/) | The shared outcome and provenance contract executes against exact cookbook output; adapter conformance regressions exercise proven forms and explicit uncertainty boundaries, while the cookbook also demonstrates reference-site and call-input composition. | Whole-program points-to completeness, general alias analysis, path feasibility, taint, or data-flow accuracy. |
| Data-flow solver, adapter, and production-taint conformance suites | Bounded language-neutral ICFG scenarios agree with independent reference implementations; every direct-ready language has one exact helper-flow case across the direct solver, JSON CodeQuery, and RQL; production taint fixtures exercise retained report/projection parity and semantic summaries. | Representative real-project precision/recall, complete language-feature coverage, or externally reviewed accuracy. |
| Semantic-summary taint lifecycle harness | The production route can report activation, acquisition, binding, batching, propagation, witness reconstruction, projection, retained bytes, and peak RSS for deterministic scaling cases. | Published repeatability thresholds, a realistic public corpus, or a comparative performance claim. |
| Analyzer and service test suites | Specific resolution, proof, diagnostics, truncation, and language-regression contracts are exercised in the repository. | An independently sampled benchmark or an externally reviewed accuracy result. |
| [Capability matrix](/capabilities/) | The implemented analysis surfaces and known hard boundaries are stated in one place. | A guarantee that every valid program within a language will resolve every edge. |

There is not yet a public, versioned table of cold and warm data-flow timings,
peak memory, pinned real-project flow expectations, or aggregate precision and
recall. Until one exists, treat unqualified performance adjectives and global
data-flow accuracy percentages as unsupported. The capability is documented as
experimental for this reason, not because the solver or policy evaluator is a
placeholder.

## Performance Evaluation Protocol

For a result that another person can compare, publish all of the following:

1. Bifrost version and full commit, build profile, feature set, operating system, CPU, memory, and accelerator.
2. Corpus repository URL, exact commit, included roots, generated/vendor exclusions, language/file counts, and total indexed bytes.
3. The exact command, MCP composition, environment variables, query files, and execution limits.
4. A cold-start definition that removes or relocates both the repository `.bifrost/cache/bifrost_cache.v<N>.db` stores and any deliberately tested process state. Do not call a new process “cold” while reusing a warm persistent cache.
5. A warm-run definition: how many warmups ran, whether the same process remained alive, and whether the workspace changed.
6. Wall time, CPU time, and peak resident memory for each phase you report: startup/index-ready, first query, and repeated query. Publish individual samples plus the aggregation method, not only the best run.

Launcher downloads and first-use semantic-model downloads are installation costs. Measure them separately from analyzer cold start unless download latency is the subject of the evaluation.

## Accuracy Evaluation Protocol

Define the unit of judgment before counting: a declaration, reference site,
call edge, structural match, receiver-analysis input/candidate set, file edge,
flow meeting, or ordered flow witness. Build a labeled corpus with positive and
negative cases, including ambiguity, unsupported syntax, generated code policy,
external dependencies, and language-specific dynamic behavior. For data flow,
record clean, reached, and inconclusive expectations separately; absence from a
partial result is never a true negative.

For each result, retain Bifrost's proof tier and diagnostics. Report at least:

- true positives, false positives, false negatives, precision, and recall for the chosen unit;
- proven and unproven results separately, plus the policy used to count unproven edges;
- queries with diagnostics, `truncated: true`, or `provenance_truncated: true` separately from complete executions;
- the exact set of unsupported or excluded cases rather than silently removing them from the denominator.

A structurally guaranteed match means the parsed normalized node satisfied the query. It does not by itself prove runtime reachability, callee identity, control flow, data flow, receiver values, or aliasing. Graph-backed steps add indexed declaration and edge evidence within the [documented capability boundary](/capabilities/). A `receiver_analysis` row adds bounded demand-driven receiver evidence for its exact input and outcome; it is not evidence of whole-program points-to or general alias completeness.

## Publishing A Result

Use [Reproduce an Analysis](/reproduce-analysis/) for the run manifest and artifact layout, and [Cite Bifrost](/cite-bifrost/) for software attribution. A useful report should let a reader rerun the exact revision and distinguish engine evidence from the evaluator's interpretation.
