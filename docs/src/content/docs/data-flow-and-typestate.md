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

| Goal | Surface | Where it runs | Execution boundary |
| --- | --- | --- | --- |
| Inspect one procedure's control-flow structure | `cfg_*` CodeQuery/RQL steps | CLI, REPL, MCP, Rust | Materializes a source-backed procedure-local CFG and exposes one bounded edge hop per step. |
| Ask procedure-level control and safety questions | Procedure-level projection steps (see below) | CLI, REPL, MCP, Rust | Each step derives typed rows for one procedure from the same semantic IR. No registration is needed. |
| Ask whether selected origins reach selected observations | A `.rqlp` policy with `:type flow` | CLI (`bifrost --policy-file`), MCP `run_policy`, Rust | Evaluates bounded value-flow propagation through the policy runtime. Uncertain or unbindable typed ports stay incomplete instead of producing a clean verdict. |
| Find attacker-controlled or sensitive data reaching configured sinks | A `.rqlp` policy with `:type taint` | CLI, MCP `run_policy`, Rust | The policy evaluator resolves endpoint sets, compiles compatible plans, batches shared demand, solves each compatible batch once, and renders one retained report. |
| Check a resource or API protocol | A `.rqlp` policy with `:type typestate` | CLI, MCP `run_policy`, Rust | A finite-state protocol runs over the same bounded semantic graph and returns findings, completeness, and retained witnesses. |
| Run a value-flow plan inside a query | Registered `value_flow` / `value-flow` step | Rust only | The embedding registers one immutable `ValueFlowPlan`; the query runs that plan once per procedure and projects diagnostic-neutral endpoints and witnesses. |
| Project taint evidence through CodeQuery/RQL | Registered `taint` step | Rust only | The embedding registers an immutable production taint result; the query projects it without compiling policies, rerunning propagation, or reclassifying findings. |
| Run a typestate protocol inside a query | Registered `typestate` step | Rust only | The embedding registers a compiled protocol and binding plan for one procedure root. |

"Rust only" means that only an in-process Rust host can register the input the step needs. See [Registered Value Flow, Taint, And Typestate](#registered-value-flow-taint-and-typestate).

The public CFG inspection steps remain procedure-local. Value-flow, taint, and
typestate use the interprocedural graph internally; `query_code` does not expose
an unbounded general-purpose ICFG traversal.

### Procedure-Level Projections

These steps take a `procedure` row, usually from `procedure-of`, and need no registration. The RQL spelling is shown; the JSON `op` uses underscores instead of hyphens. [Code Query Vocabulary](/reference/code-query/) lists every step with its signature and options.

| Step | What it returns |
| --- | --- |
| `nilness-operations` | Source-backed pointer operations with their procedure-local nilness fact. Go only; other languages get an incomplete `unsupported_structural_feature` diagnostic. |
| `switch-coverage` | One coverage verdict per switch: exhaustive, non-exhaustive, or unknown. |
| `statement-reachability` | Java statements with their reachability from the procedure entry. A statement is unreachable only when every entry is outside complete bounded reachability. |
| `loop-relations` | For Java loops, whether the reachable body can reach its own repeat edge. |
| `control-relations` | Dominance, postdominance, control dependence, entry reachability, and loop membership between the procedure's program points. |
| `guards-of` | The normalized branch conditions recorded for the procedure, with their true and false successor edges. |
| `detached-task-transfers` | Values copied into calls that run on a different task, with their object identity when it is exact. |
| `assignment-relations` | Self-assignments, local self-initializers, failed swaps, and overwritten assignments that are never read. The bounded `self_initializer` relation supports direct C/C++ local declarations; conversions, macros, unevaluated contexts, and incomplete flow remain open or excluded. By default the step returns only self-assignments; use `:relation` to select the others. |
| `state-events-of` | Establishment, kill, and read events of bindings and their properties, anchored to program points. |
| `flow-relations-of` | Reaching-definition, dominance, and same-evaluation relations between state events. |
| `class-set` | For each member access reachable from the procedure, the classes its receiver may hold. Python, JavaScript, TypeScript, PHP, and Ruby only. |
| `absent-member` | Member accesses where a class certainly reaches the site and lacks the member. The Conditional filter also accepts only the documented receiver and write remainders. Python, JavaScript, TypeScript, PHP, and Ruby only. |

These steps report unsupported or incomplete coverage they detect as a row field or a diagnostic. An empty result is still not proof of absence. For example, `switch-coverage` returns a row for a Go `switch`, but in a check it returned no rows and no diagnostic for a Java `switch` statement.

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

The semantic IR capabilities of each language, such as asynchronous code,
generators, and resource management, are listed in
[language support](/reference/languages/). Class-set type flow, which the
`class-set` and `absent-member` steps use, runs only for Python, JavaScript,
TypeScript, PHP, and Ruby. For other languages these steps return no rows and a
`semantic_capability_unsupported` diagnostic.

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

See [Static-Analysis Policies](/static-analysis-policies/) for the checked
taint authoring example and [CLI](/cli/) for report formats and exit statuses.

## Registered Value Flow, Taint, And Typestate

Raw CodeQuery/RQL does not invent a flow analysis from arbitrary structural
matches. The `value-flow`, `taint`, and `typestate` steps each name an input
that a host registered for the exact workspace generation:

```lisp
(witness :max-steps 32 :max-bytes 16384
  (value-flow :plan-ref "request:user-input-to-store"
    (procedure-of (function :name "run"))))
```

`value-flow` runs the registered plan and returns `flow_endpoint` rows with
`reached`, `not_reached`, or `inconclusive` reachability. A separate public
`status` and optional `reason` preserve whether semantic construction, solver
propagation, or the enclosing query completed or stopped. `witness` projects only the
source-backed paths retained by that solve. The registered `taint` step is
narrower still: it projects an existing production taint report and cannot load
a policy or invoke the solver.

### Registration Is Rust-Only

Only an in-process Rust host can register these inputs. It calls these
`SearchToolsService` methods:

| Step | RQL reference option | Register | Unregister |
| --- | --- | --- | --- |
| `value-flow` | `:plan-ref` | `register_query_value_flow_plan` | `unregister_query_value_flow_plan` |
| `taint` | `:taint-ref` | `register_query_taint_results` | `unregister_query_taint_results` |
| `typestate` | `:protocol-ref` | `register_query_protocol` | `unregister_query_protocol` |

The methods take already-compiled Rust values: an `Arc<ValueFlowPlan>`, a list
of retained `ProductionTaintAnalysisResult` values, or a `CompiledProtocol`
with its `TypestateBindingPlan` and expected procedure root. No CLI option, REPL
command, MCP tool, or query field reaches them. A registration is bound to the
workspace generation that was current when it was made.

The CLI (`bifrost --query-file`, `bifrost --tool query_code`), the REPL, and the
MCP `query_code` tool never register anything. A query from those hosts that
uses one of these steps returns no rows, `truncated: true`, and one of these
diagnostics with `impact: incomplete`:

- `unresolved_value_flow_plan_reference`
- `unresolved_taint_result_reference`
- `unresolved_protocol_reference`

From the CLI or MCP, run a `.rqlp` policy with `:type flow`, `:type taint`, or
`:type typestate` instead. See [Static-Analysis Policies](/static-analysis-policies/).

A reference has the form `namespace:name`. Both parts are lowercase ASCII
letters and digits, plus `-`, `_`, and `.`; each part must start and end with a
letter or digit.

| Limit | Value |
| --- | --- |
| Whole reference | 192 bytes |
| Namespace | 63 bytes |
| Name | 128 bytes |
| Reference names per service, for each input type | 256 |
| Distinct registered values per service, for each input type; several references can name one value | 128 |
| Taint results in one taint registration | 256 |
| Retained value-flow plan bytes; retained value-flow artifact bytes | 64 MiB each |
| Retained taint plan bytes; taint report bytes; taint artifact bytes | 64 MiB each |
| Retained protocol bytes | 4 MiB |
| Retained typestate binding-plan bytes | 16 MiB |
| Retained typestate registration artifact bytes | 64 MiB |

See [Code Querying](/code-querying/), [JSON CodeQuery](/code-query-json/), and
[Rune Query Language](/rune-query-language/) for the query contracts, and
the [Rust API reference](/reference/rust-api/) for the methods.

## Semantic Summaries

Workspace source bodies are analyzed directly. When an embedding explicitly
activates compatible [semantic-model packs](/semantic-model-packs/), exact
external procedure summaries can contribute parameter, receiver, normal-return,
exceptional-return, heap/location, and escape transfers. Source bodies take
precedence over external summaries, and missing, conflicting, incompatible, or
incomplete models remain visible instead of becoming proof that no flow exists.

Hosts activate models as follows:

- `bifrost --policy-file` activates the reviewed models in
  `.bifrost/semantic-models/` and the installed catalog that
  `.bifrost/packs.json` configures. When `.bifrost/packs.json` is absent, it
  uses the ambient default catalog. Activated summaries take part in taint,
  flow, and typestate policy results.
- The MCP server, including `run_policy` and `query_code`, and one-shot
  `bifrost --tool` and `bifrost --query-file` runs activate the installed
  catalog when they bind the workspace. They activate the reviewed
  `.bifrost/semantic-models/` route only when `BIFROST_WORKSPACE_SEMANTIC_MODELS`
  is `on`.
- A Rust embedding can supply its own catalog and activation request.

See [Semantic Model Packs](/semantic-model-packs/),
[Static-Analysis Policies](/static-analysis-policies/), and
[Environment Variables](/reference/environment/).

## Result Honesty And Limits

Data-flow results keep these dimensions separate:

- may reachability from any must claim;
- exact evidence from ambiguous or best-effort evidence;
- a single flow status, with a reason, for completion, cancellation,
  unsupported semantics, or budget exhaustion;
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
