---
title: Data Flow, Taint, and Typestate
description: Understand Bifrost's bounded interprocedural value-flow, taint, and typestate analyses.
---

Bifrost includes a bounded, context-respecting interprocedural data-flow engine.
It powers diagnostic-neutral value-flow queries, set-oriented taint policies,
and finite-state typestate protocols without turning each client into a separate
solver.

> **Experimental capability:** These analyses execute in the current engine and
> have deterministic cross-language conformance coverage. Bifrost has not yet
> published a representative real-project data-flow accuracy benchmark or
> aggregate production performance study. Treat the returned evidence and
> completeness metadata as authoritative for one run, not as a claim of
> compiler-complete whole-program coverage.

## Choose The Analysis Surface

| Goal | Surface | Execution boundary |
| --- | --- | --- |
| Inspect one procedure's control-flow structure | `cfg_*` CodeQuery/RQL steps | Materializes a source-backed procedure-local CFG and exposes one bounded edge hop per step. |
| Ask whether selected values reach selected observations | Registered `value_flow` / `value-flow` query | The embedding registers one immutable `ValueFlowPlan`; the query runs that plan once per procedure and projects diagnostic-neutral endpoints and witnesses. |
| Find attacker-controlled or sensitive data reaching configured sinks | A `.rqlp` policy with `:type taint` | The production policy evaluator resolves endpoint sets, compiles compatible plans, batches shared demand, solves each compatible batch once, and renders one retained report. |
| Project taint evidence through CodeQuery/RQL | Registered `taint` query | The embedding registers an immutable production taint result; the query projects it without compiling policies, rerunning propagation, or reclassifying findings. |
| Check a resource or API protocol | A `:type typestate` policy or registered `typestate` query | A finite-state protocol runs over the same bounded semantic graph and returns findings, completeness, and retained witnesses. |

The public CFG inspection steps remain procedure-local. Value-flow, taint, and
typestate use the interprocedural graph internally; `query_code` does not expose
an unbounded general-purpose ICFG traversal.

## Language Baseline

The production semantic adapters for Java, JavaScript, TypeScript, Go, Python,
Rust, PHP, Scala, C#, Ruby, Kotlin, C, and C++ have a shared source-backed
helper-flow conformance case. Each case runs through the direct solver, JSON
CodeQuery, and RQL, and checks both a reached sink and a clean or explicitly
incomplete sink.

That baseline establishes adapter wiring and public projection parity. It does
not say every language has equal precision for fields, receiver aliases,
exceptions, dynamic dispatch, generated code, or external libraries. Read each
result's certainty, ambiguity, completion, and diagnostics before treating a
missing flow as a clean negative.

## Set-Oriented Taint

A taint policy selects sets of sources and sinks. Compatible demand is compiled
into one batch rather than solved once for every source/sink permutation. One
retained `TaintFindingReport` supplies policy findings and any registered public
projection, so presentation does not rerun propagation or witness
reconstruction.

Endpoint selectors remain diagnostic-neutral. A source selector and sink
selector both matching is not a finding. A finding exists only when the solver
retains a compatible meeting between their typed bindings. Broad endpoint
categories can use generated fallback classification, while a narrower
`finding-combination` can refine the message, severity, classifications, or CVSS
for a specific meeting.

See [Static-Analysis Policies](/static-analysis-policies/#taint-broad-libraries-specific-findings)
for the checked authoring example and [CLI](/cli/#static-analysis-policies) for
report formats and exit statuses.

## Registered Value Flow And Taint

Raw CodeQuery/RQL does not invent a flow analysis from arbitrary structural
matches. A host first registers a bounded plan or retained result for the exact
workspace generation:

```lisp
(witness :max-steps 32 :max-bytes 16384
  (value-flow :plan-ref "request:user-input-to-store"
    (procedure-of (function :name "run"))))
```

`value-flow` runs the registered plan and returns `flow_endpoint` rows with
`reached`, `not_reached`, or `inconclusive` status. `witness` projects only the
source-backed paths retained by that solve. The registered `taint` step is
narrower still: it projects an existing production taint report and cannot load
a policy or invoke the solver.

See [Code Querying](/code-querying/), [JSON CodeQuery](/code-query-json/), and
[Rune Query Language](/rune-query-language/) for the exact contracts.

## Semantic Summaries

Workspace source bodies are analyzed directly. When an embedding explicitly
activates compatible [semantic-model packs](/semantic-model-packs/), exact
external procedure summaries can contribute parameter, receiver, normal-return,
exceptional-return, heap/location, and escape transfers. Source bodies take
precedence over external summaries, and missing, conflicting, incompatible, or
incomplete models remain visible instead of becoming proof that no flow exists.

The ordinary CLI does not ambiently discover or activate arbitrary external
model catalogs. An embedding that wants external summaries supplies the catalog
and exact activation request to the policy runtime.

## Result Honesty And Limits

Data-flow results keep these dimensions separate:

- may reachability from any must claim;
- exact evidence from ambiguous or best-effort evidence;
- complete execution from cancellation, unsupported semantics, or budget
  exhaustion;
- stable endpoint and source identities from run-local graph identities; and
- retained witnesses from omitted or truncated witness alternatives.

Bifrost does not currently claim SMT-backed path feasibility, complete
whole-program points-to results, general unbounded alias sets, compiler-complete
external-library modeling, or zero false positives and false negatives on a
representative public corpus.

The deterministic solver and cross-language suites exercise specific contracts.
The production lifecycle harness separately measures activation, acquisition,
binding, batching, propagation, reconstruction, projection, memory, reuse, and
invalidation. Until a pinned real-project benchmark is published, avoid global
accuracy percentages and unqualified performance adjectives. See [Evidence and
Evaluation Methodology](/evaluation-evidence/) for the publication standard.
