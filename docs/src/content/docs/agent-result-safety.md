---
title: Agent Result Safety
description: Decide when Bifrost results support matches, zero-result, or completeness claims.
---

Bifrost returns structured evidence, not permission to turn every response into “all callers” or “no matches.” An agent must inspect the execution envelope, diagnostics, truncation, proof tier, and provenance before choosing claim language.

## The Decision Rule

Never claim **all** or **none** unless every relevant check below passes:

| Check | Required condition | If it fails |
| --- | --- | --- |
| Tool execution | The transport/tool response is successful and the query validated | Report the error; do not treat it as an empty result. |
| Workspace | The active root and source revision are the intended ones | Correct the root/session or qualify the result with the actual workspace. |
| Capability diagnostics | No diagnostic says a requested language, kind, role, or file class was skipped | State which scope was not analyzed and avoid a zero/completeness claim. |
| Execution diagnostics | No diagnostic reports a scan, source-byte, fact-node, seed-row, or pipeline-work budget boundary | Narrow or split the query; the returned subset remains evidence, not completeness. |
| Result truncation | `truncated` is `false` | Say “at least these matches,” never “all.” |
| Proof tier | The claim distinguishes `proven` from `unproven` graph edges | Describe unproven rows as possible candidates or exclude them explicitly. |
| Provenance | Every result used for a path claim has `provenance_truncated != true` | Cite the retained paths only; do not claim every derivation is present. |
| Receiver outcome | Every `receiver_analysis` row used by the claim has the required `outcome`; unsupported/budget rows and candidate truncation are absent | Preserve unknown/unsupported/ambiguous states, narrow the query, or avoid the claim. |
| Analysis boundary | The claim does not require unsupported path-sensitive control flow, whole-program points-to, general alias sets, taint, or data flow | Restate the narrower structural/graph/receiver fact or use another analyzer. |

An empty `results` array is only a zero-result inside the query's actual workspace, language/path filters, supported capabilities, and execution budgets. It is never proof about files outside the index, unindexed external declarations, unsupported syntax roles, or possible runtime behavior that static resolution does not model.

## Safe Claim Vocabulary

| Evidence | Safe wording | Unsafe wording |
| --- | --- | --- |
| Some structural results, complete or truncated | “Bifrost found these parsed call shapes…” | “These are the runtime callees…” |
| `truncated: true` | “Bifrost returned at least these matches before its result boundary.” | “Bifrost found all matches.” |
| Clean, untruncated zero-result | “Bifrost found no matches for this supported query in the indexed scope.” | “This pattern does not exist anywhere.” |
| `proof: "proven"` reference/call edge | “The analyzer resolved this returned edge to the indexed declaration.” | “Every possible runtime edge is known.” |
| `proof: "unproven"` reference/call edge | “This is a structured possible target.” | “This call definitely targets…” |
| Importer-file result | “This file directly imports the target file.” | “This file calls or uses the target member.” |
| `provenance_truncated: true` | “The result has additional derivation paths that were not retained.” | “These are all paths to the result.” |
| `receiver_analysis` with `precise` | “The bounded JS/TS receiver provider returned this exact candidate set for the input.” | “Whole-program analysis proves this is the only runtime value.” |
| `receiver_analysis` with `ambiguous` | “The bounded analysis retained these possible candidates.” | “Each candidate is independently precise.” |
| `receiver_analysis` with `unknown`, `unsupported`, or `exceeded_budget` | “Bifrost could not establish candidates for this input for the reported reason/limit.” | “There are no targets.” |

Prefer “returned,” “indexed,” “resolved,” and “within this scope” when they describe the actual evidence. Reserve “all” for a bounded response that passed every decision-rule check, and even then name the boundary: for example, “all analyzer-resolved proven callers returned for this indexed workspace and query.”

## Read Diagnostics Before Results

Capability diagnostics are part of the answer. For example, querying the `kwargs` role across JavaScript can be valid globally but unsupported by that language adapter. Bifrost reports the unsupported role instead of pretending there were no keyword arguments. If other selected languages are supported, their results may still be useful, but the combined response cannot support “none across all selected languages.”

Broad queries can hit execution budgets even when the explicit result `limit` is high. A guidance diagnostic suggesting an exact name, `where`, or `languages` filter may be a performance hint; a diagnostic that reports a hard scan or pipeline boundary means the search was partial. Preserve the diagnostic in summaries and machine reports.

Receiver analysis makes this distinction row-local as well as response-wide. It always returns a row, even for `unknown` or `unsupported`. Candidate-cap truncation and `exceeded_budget` also set top-level `truncated` and emit a diagnostic; ordinary bounded `ambiguous` does not. Never reinterpret a missing `values` or `member_targets` field without first reading `outcome`.

## Separate Structural Matches From Identity

A structural match proves that parsed source has the requested normalized shape. A call whose callee text is `audit` is not automatically the declaration `package.Service.audit`. Use `enclosing_decl`, reference traversal, or call traversal when exact indexed identity is required.

Likewise, `imports_of` and `importers_of` prove direct project-file relationships. They produce candidate files for follow-up; they do not prove a concrete reference or callsite. Use `references_of`, `used_by`, `uses`, or a call-site step for that claim.

## Treat Proof As Per-Edge Evidence

Reference and call traversal can return `proven` and `unproven` edges. Proof belongs to that returned edge. A proven edge is strong positive evidence; it does not establish that the analyzer found every possible dynamic edge. An unproven edge is not noise to silently discard or certainty to silently promote—choose a policy and state it.

When the question asks for definite callers, filter to `proof: "proven"` and describe the result as analyzer-resolved. When the question asks for review candidates, include both tiers, group them by proof, and let a human or later analysis resolve uncertainty.

## Preserve Provenance And Locations

Derived results include one or more provenance paths from the structural seed through ordered steps. Declaration-returning reference and call traversals record the exact supporting site under `via`. Cite the terminal path/range and, when explaining why it was returned, the relevant seed and `via` site.

At most sixteen provenance paths are retained per terminal result. If `provenance_truncated` is true, the terminal result remains valid, but the response is not a complete explanation of every route that reached it.

For a reproducible citation or report, record:

- Bifrost version or commit and `CodeQuery` schema version;
- source repository revision and active workspace root;
- the complete saved query or its revision/hash;
- `result_type`, project-relative path, and exact returned range;
- proof and reference/call kind when present; and
- diagnostics, `truncated`, and `provenance_truncated` state.

## Agent Workflow

1. Confirm the active workspace and that the required tool is advertised.
2. Run the narrowest query that answers the question.
3. Read errors and diagnostics before interpreting `results`.
4. Check result-level and provenance truncation.
5. Separate structural shapes, exact identities, file relationships, and proof tiers.
6. State the analysis boundary in the answer and cite returned locations.
7. If a completeness check fails, narrow/split the query or report a qualified partial result.

For production policy consumption, continue with [Build a Static-Analysis Rule](/build-static-analysis-rule/). For the exact schema, budgets, and result fields, use [JSON CodeQuery](/code-query-json/).
