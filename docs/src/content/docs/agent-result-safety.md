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
| Policy completion | Every relevant policy ran, and the report has no load/evaluation diagnostic or retained-output omission that makes the batch non-clean | Preserve retained positive findings, but do not call zero findings clean or let a threshold exit override status 2. Only `complete` supports an absence claim; `not_run` makes no absence claim and is omitted from implicit catalog selections without changing their exit status. |
| Navigation completeness | The usage, graph, summary, or search tool reports no incomplete state (see [Navigation tools](#navigation-tools)) | Report the returned rows as a partial answer and name the reason. |
| Proof tier | The claim distinguishes `proven` from `unproven` graph edges | Describe unproven rows as possible candidates or exclude them explicitly. |
| Provenance | Every result used for a path claim has `provenance_truncated != true` | Cite the retained paths only; do not claim every derivation is present. |
| Receiver outcome | Every `receiver_analysis` row used by the claim has the required `outcome`; unsupported/budget rows and candidate truncation are absent | Preserve unknown/unsupported/ambiguous states, narrow the query, or avoid the claim. |
| Analysis boundary | The claim stays within supported structural/graph analysis or an explicitly configured value-flow, taint, or typestate analysis; it does not require path feasibility, complete whole-program points-to, general alias sets, or unmodeled flow semantics | Restate the narrower fact, inspect analysis completeness/uncertainty, or use another analyzer. |

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
| `receiver_analysis` with `precise` | “The bounded receiver analysis returned this exact candidate set for the input.” | “Whole-program analysis proves this is the only runtime value.” |
| `receiver_analysis` with `ambiguous` | “The bounded analysis retained these possible candidates.” | “Each candidate is independently precise.” |
| `receiver_analysis` with `unknown`, `unsupported`, or `exceeded_budget` | “Bifrost could not establish candidates for this input for the reported reason/limit.” | “There are no targets.” |
| Policy run | Use the wording for its `completion.type` in [Policy completion states](#policy-completion-states). | “The policy passed,” without reading the completion state. |
| Endpoint selector match | “This site matched the reusable source/sink endpoint definition.” | “This endpoint emitted a vulnerability.” |
| Source and sink endpoint co-presence | “Both endpoint candidates occur in the analyzed scope.” | “The source can reach the sink.” |
| Complete reached flow endpoint or taint meeting | “The configured analysis found this source-to-sink flow with the retained witness.” | “Every feasible runtime path carries this value.” |
| Inconclusive flow endpoint or taint run | “Bifrost retained this bounded evidence but could not complete the configured analysis.” | “No flow exists.” |

Prefer “returned,” “indexed,” “resolved,” and “within this scope” when they describe the actual evidence. Reserve “all” for a bounded response that passed every decision-rule check, and even then name the boundary: for example, “all analyzer-resolved proven callers returned for this indexed workspace and query.”

## Read Diagnostics Before Results

Capability diagnostics are part of the answer. For example, querying the `kwargs` role across JavaScript can be valid globally but unsupported by that language adapter. Bifrost reports the unsupported role instead of pretending there were no keyword arguments. If other selected languages are supported, their results may still be useful, but the combined response cannot support “none across all selected languages.”

Broad queries can hit execution budgets even when the explicit result `limit` is high. A guidance diagnostic suggesting an exact name, `where`, or `languages` filter may be a performance hint; a diagnostic that reports a hard scan or pipeline boundary means the search was partial. Preserve the diagnostic in summaries and machine reports.

Receiver analysis makes this distinction row-local as well as response-wide. It always returns a row, even for `unknown` or `unsupported`. Candidate-cap truncation and `exceeded_budget` also set top-level `truncated` and emit a diagnostic; ordinary bounded `ambiguous` does not. Never reinterpret a missing `values` or `member_targets` field without first reading `outcome`.

Policy evaluation applies the same rule at a durable reporting boundary. A
`complete` run with no findings is clean only inside its recorded policy,
selector, analyzer, dependency-manifest, and budget scope. An `inconclusive`
run (including cancellation or budget reasons), `unsupported` run, or `failed`
run is non-clean even if the findings array is empty. A `not_run` policy has no
findings and makes no absence claim; implicit pack, category, or default
selection does not affect the exit status, while an explicitly named policy ID
exits 2. Only `complete` supports an absence claim from analyzed code;
`proven_by_summary` supports one only under its stated dependency on authored
summaries. Human, canonical JSON, and SARIF preserve the same completion and
diagnostics; do not trust a transformed presentation that has removed them.

### Policy completion states

Each run in a policy report has a `completion` object. Its `type` is one of
seven values. Choose the claim from this table:

| `completion.type` | Findings are reliable | Zero findings is clean | Exit status the run allows | Safe claim | Unsafe claim |
| --- | --- | --- | --- | --- | --- |
| `complete` | Yes | Yes, within the recorded scope | 0 or 1 | “This policy retained no findings in its recorded analyzer and dependency scope.” With findings: “Bifrost proved these findings.” | “The issue cannot occur.” |
| `proven_subset` | Yes | No. The run searched only part of the program. `codes` lists the diagnostic codes that limited it. | 1 when a finding meets `fail_on`, otherwise 2 | “Bifrost proved these findings, but the run covered only part of the program, so there may be others.” | “There are no other findings.” |
| `proven_by_summary` | Yes | Only under authored summaries of external procedures. It is not proof from analyzed code. | 0 or 1 | “This policy retained no findings, if the authored summaries of the external procedures it used are correct.” | “Analysis of the code proves the issue is absent.” |
| `inconclusive` | No | No. `reasons` says why, for example `cancelled` or `deadline_exceeded`. | 2, unless the policy's `on-unknown` verdict is `warn-unreliable` or `fail-closed` | “The run did not finish its analysis because of the reported reason. The retained findings are leads, not a complete result.” | “The policy passed.” |
| `not_run` (implicit) | Yes | No. The policy did not run and makes no absence claim. | 0 or 1 based on policies that ran | “This selected policy did not run because the reported capability was unavailable.” | “The policy found no findings.” |
| `not_run` (explicit ID) | No | No. The policy did not run and makes no absence claim. | 2 | “Bifrost could not honor the requested policy ID because the reported capability was unavailable.” | “The policy passed.” |
| `unsupported` | No | No. `capability` names what is missing. | 2 | “Bifrost cannot evaluate this policy here because the named capability is missing.” | “The policy passed” or “nothing applies.” |
| `failed` | No | No. `reasons` says why. | 2 | “The policy run failed for the reported reason, so it gives no result.” | “The policy passed.” |

Only `complete` supports a zero-finding or "all findings" claim without
qualification. The batch exits with the highest status that any run requires.
An error diagnostic, truncated diagnostics, or an execution termination in the
report also gives the batch exit status 2. [Policy
Reference](/reference/policies/) gives the exact exit rules, the reason codes
for each state, and the matching SARIF notifications.

## Navigation tools

Usage, definition, graph, and summary tools carry their own completeness
fields. Read them before you claim "all callers" or "no callers".
[MCP Tools Reference](/reference/mcp-tools/) lists every field.

`scan_usages_by_location` and `scan_usages_by_reference` give each target a
`status`:

| `status` | Safe wording | Unsafe wording |
| --- | --- | --- |
| `found` | “Bifrost found these usage sites.” Add “at least” when `complete` is false. | “These are all the callers” when `complete` is false or `unproven_hits` is not zero. |
| `verified_absent` | “Bifrost found no usages of this declaration in the searched scope.” | “Nothing can call this at runtime.” |
| `no_external_usages` | “No usages outside the declaring type or module; `same_owner_sites` internal usages exist.” | “This is unused.” |
| `unverified_absent` | “Bifrost found no usages, but the scan could not prove absence: `absence_caveats` and `incomplete_reason` say why.” | “There are no usages.” |
| `ambiguous` | “The name matched several declarations.” Qualify it and scan again. When `too_many_candidates` is present, it gives the true count and no list. | Any claim about one of the candidates. |
| `too_many_callsites` | “The declaration has more than `limit` call sites; Bifrost did not list them.” | “It has `limit` callers.” |
| `not_found`, `failure` | “Bifrost could not scan this target.” | “There are no usages.” |

Only `verified_absent` supports “no usages”. A result with `complete: false`
names one `incomplete_reason`: `cancelled`, `time_budget`, `candidate_files`,
`source_bytes`, `source_unavailable`, `semantic_analysis`, `callsites`,
`response_budget`, `resolution_candidates`, or `unmatched_paths`.
`summary.partial` is true when any target is incomplete. `same_owner_sites`
counts self, this, and own-type static calls that are not in the external
count; set `include_same_owner` to list them. Hits in `unproven_files` are
possible usages, not proven ones.

Other tools:

| Tool | Fields to check | Meaning when set |
| --- | --- | --- |
| `search_symbols` | `truncated`, `too_many_matches`, `invalid_patterns` | `limit` cut the list; a pattern matched too many symbols to rank; a pattern could not be read and matched nothing. None of these supports “no such symbol”. |
| `get_symbol_sources` | `complete`, `incomplete`, `too_broad`, `ambiguous` | A lookup was cancelled; a glob matched too many files and was skipped; a name matched several symbols. |
| `get_summaries` | `degraded`, `listings[].truncated`, `too_broad` | Summaries were replaced by a compact symbol list to fit the response budget; a listing was cut and `total_entries` gives the true count; a glob was skipped. |
| `get_definitions_by_location`, `get_type_by_location`, `get_declarations_by_location` | `status`; for definitions also `complete` and `incomplete_reason` | Only `resolved` names a definite target. Any other status means no single answer. A definition result with `complete: false` is not definite even when `resolved`. |
| `usage_graph` | `complete`, `incomplete_reasons`, `truncated_symbols` | Part of the graph is missing; symbols with too many call sites have their inbound edges omitted. |
| `missing_tests` | `indeterminate_functions`, `analysis.incomplete_reasons` | Searches that did not finish. Only `missing_functions` supports “no test reaches this function”, as static evidence. |
| `blast_radius` | `analysis.graph_completion`, `analysis.paths_outside_file_graph`, `analysis.incomplete_reasons` | Zero reached tests is not proof that no test applies when the graph is incomplete or changed files fall outside it. |
| `most_relevant_files` | `complete` | A graph ranking was cut short and the result fell back to history and imports. |
| `search_file_contents`, `find_files_containing` | `truncated`, `invalid_patterns`, `unmatched_paths` | A match limit removed results; a pattern could not be read; a path selector matched nothing. |
| `get_file_contents` | `files[].truncated` | The file has more than 50 lines and only its first 25 and last 25 lines were returned. |

## Separate Structural Matches From Identity

A structural match proves that parsed source has the requested normalized shape. A call whose callee text is `audit` is not automatically the declaration `package.Service.audit`. Use `enclosing_decl`, reference traversal, or call traversal when exact indexed identity is required.

Likewise, `imports_of` and `importers_of` prove direct project-file relationships. They produce candidate files for follow-up; they do not prove a concrete reference or callsite. Use `references_of`, `used_by`, `uses`, or a call-site step for that claim.

Reusable policy endpoints are another deliberate separation. An `(endpoint
...)` document is a diagnostic-neutral selector, role, category, and typed
binding. Loading it as a dependency creates no policy run or finding, and
passing it as an executable policy root fails visibly. A source endpoint and a
sink endpoint both matching says only that both candidates are present. The
phrase “can reach” requires an actual compatible meeting from the production
taint evaluator; match co-presence is never a reachability fallback.

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
4. For policy reports, require `complete` for every relevant run, or state the narrower meaning of `proven_subset` or `proven_by_summary`, and check report/finding/witness/CVSS truncation; status 2 takes precedence over a finding threshold.
5. For usage and graph tools, check `status`, `complete`, and the truncation fields listed under [Navigation tools](#navigation-tools).
6. Check raw-query result-level and provenance truncation.
7. Separate structural shapes, endpoint candidates, exact identities, file relationships, proof tiers, and actual analysis findings.
8. State the analysis boundary in the answer and cite returned locations.
9. If a completeness check fails, narrow/split the query or policy, or report a qualified partial result.

For production policy consumption, continue with [Static-Analysis Policies](/static-analysis-policies/) and [Build a Static-Analysis Rule](/build-static-analysis-rule/). For the raw query schema, budgets, and result fields, use [JSON CodeQuery](/code-query-json/).
