---
title: Static-Analysis Policies
description: Author reusable RQLP rules and endpoints, run match policies, and interpret complete human, JSON, or SARIF reports.
---

Bifrost static-analysis policies are human-readable S-expressions stored in
`.rqlp` files. They add stable rule identity, reporting metadata, composition,
and completeness semantics around native [Rune Query Language
(RQL)](/rune-query-language/) selectors. JSON is available as a normalized or
reporting form, but it is not an alternate RQLP authoring syntax.

> **Current execution boundary:** Bifrost executes match- and
> typestate-analysis policies. Taint-analysis policies can be authored, parsed,
> validated, and composed, but their evaluator is not implemented yet. Running
> taint reports an `unsupported` completion and exits with status 2.

> **Important:** An RQL selector returns analysis candidates. An endpoint
> selector match is diagnostic-neutral. Neither an endpoint match nor the
> co-presence of a source and sink proves reachability, and neither creates a
> finding by itself.

## One Document Per File

Every `.rqlp` file contains exactly one top-level document:

| Document | Purpose | Executable root? |
| --- | --- | --- |
| `(policy ...)` | Defines one rule, its report metadata, and exactly one `match`, `taint`, or `typestate` analysis. | Yes. |
| `(endpoint ...)` | Names one reusable, diagnostic-neutral source or sink selector with categories and a typed value/API binding. | No. It is loaded only as a dependency. |

Passing an endpoint to `--policy-file` is an error; Bifrost does not turn it
into a match policy behind the author's back.

### Built-in code-smell pack

The installed binary embeds `bifrost.code-smells`, an initial catalog of twelve
structured match policies. It covers dynamic evaluation, unsafe Python object
deserialization, and review prompts for sorting, regular-expression compilation,
file reads, serialization, parsing, database calls, network calls, subprocesses,
sleep, and expensive operations beneath nested loops. Every rule is an ordinary
checked-in `.rqlp` source with a stable ID and semantic hash; the manifest also
records its category, claimed languages, required capabilities, severity
rationale, and remediation.

Pack version 1.1 adds Rust coverage to eight performance policies. The Rust
selectors recognize the standard slice `sort*` family, `Regex::new`,
`fs::read` / `fs::read_to_string`, `serde_json::{to_string, to_vec, from_str,
from_slice}`, `bincode::{serialize, deserialize}`, `toml::from_str`, direct
`reqwest::get` and `ureq::{get, post}` requests, and `thread::sleep`. These are
language- and API-specific normalized call shapes, not source-text matches. The
pack does not claim Rust database or
subprocess coverage yet: common APIs expose generic instance methods whose
resolved receiver type is not available to structural match policies, so a
name-only rule would be too broad. Dynamic evaluation and unsafe object
deserialization also remain scoped to languages with a defensible equivalent.

Use `bifrost --list-policies` or MCP `list_policies` to inspect the exact catalog
in the running build. Select it with `--policy-pack bifrost.code-smells`, a
`--policy-category`, or a stable `--policy-id`; MCP `run_policy` exposes the same
pack/category/ID selectors. These are deliberately review-oriented structural
matches. A call name or lexical location is evidence of the parsed shape, not
proof of runtime dispatch, loop invariance, or measured cost.

### A runnable match policy

This complete checked fixture selects direct Python call syntax whose callee is
named `eval`:

<!-- policy-doc-test:rqlp:tests/fixtures/policies/dynamic-eval.rqlp -->
```lisp
; Match policies are executable diagnostics. Omitting :schema-version selects
; the latest compatible policy schema, currently version 1.
(policy
  :id "bifrost.security.dynamic-eval"
  :name "No dynamic evaluation"
  :message "Dynamic evaluation is forbidden"
  :severity warning
  :description "Reject calls that execute source text as Python code."
  :tags ["security" "code-execution"]
  :analysis
    (analysis
      :type match
      :selector
        (rql
          (language python
            (call :callee (name "eval"))))))
```

`match` is currently the only analysis type that executes end to end. Its RQL
result is evidence for the surrounding policy, so the policy—not the selector—
owns the finding message, severity, identity, and completion state. A callee
name match is still a structural fact; it does not by itself prove runtime
dispatch.

The documentation test runs that exact policy against this source through the
current `bifrost` binary:

<!-- policy-doc-test:source:dynamic-eval -->
```python
def run(user_code):
    return eval(user_code)
```

With `--fail-on never`, the complete human report is:

<details>
<summary>Checked current output</summary>

<!-- policy-doc-test:human:dynamic-eval -->
```text
note: policy bifrost.security.dynamic-eval inferred policy schema 1 and RQL schema 8
[warning]  app.py:2:12
    Dynamic evaluation is forbidden

summary: 1 active finding; 0 suppressed findings; 1 complete policy run
```

</details>

The same run with the default `warning` threshold produces identical report
text and exits 1. Add `--verbose` to include the complete finding identity,
evidence, provenance, proof, classification, rule schema, and manifest record.

## Schema Versions And Selectors

Policy/endpoint schema versions and nested RQL schema versions resolve
independently:

| Source form | Omitted version | Explicit version |
| --- | --- | --- |
| `(policy ...)` or `(endpoint ...)` | Select the newest compiled-in version in the compatible policy lineage (currently 1). | An exact pin; unsupported versions fail instead of falling back. |
| `(rql QUERY)` | Select the compatible RQL head (currently 3). | Add `:schema-version N` for an exact RQL pin. |
| `(rql-file :path "queries/rule.rql")` | With no wrapper pin, an explicit pin in the referenced document wins; if both omit a version, resolve the compatible RQL head. | A wrapper pin is exact; an explicit referenced-document pin must agree. |

File-backed selectors have four version-resolution cases:

| `rql-file` wrapper | Referenced `.rql` document | Result |
| --- | --- | --- |
| Omitted | Native query with no version envelope | Resolve the latest compatible RQL version (currently 3); the version is inferred. |
| Exact pin `N` | Native query with no version envelope | Use exact `N`; the wrapper supplies the explicit pin. |
| Omitted | `(rql :schema-version N QUERY)` | Use exact `N`; the referenced document supplies the explicit pin. |
| Exact pin `N` | `(rql :schema-version N QUERY)` | Use exact `N`; the agreeing referenced-document pin is retained as the resolution origin. |

If the wrapper and referenced document pin different versions, loading fails
with `conflicting-rql-schema-version`; an exact unsupported version also fails
instead of falling back. A referenced `.rql` file accepts only a raw native
query or the exact `(rql :schema-version N QUERY)` envelope shown above.
Source-only editor validation cannot read the referenced file, so it reports
this resolution as deferred until workspace loading.

Omission is a safe compatibility fallback, not “accept any latest schema.” The
engine chooses only a registered compatible successor. Use explicit pins for a
reproducible release artifact, or run with
`--require-explicit-schema-versions` to reject every inferred policy, endpoint,
and RQL version in the dependency closure.

An inline `(rql ...)` selector is lowered directly from the nested S-expression.
An `(rql-file ...)` selector names one workspace-relative `.rql` file and is
resolved only by a workspace-backed loader. There is no ambient policy,
endpoint, query, catalog, environment, or network discovery.

## Reusable Endpoints

An endpoint has a stable ID, a human display phrase, one `source` or `sink`
role, exact opaque categories, one selector, and one binding. Bindings can name
the matched value, receiver, return value, or an argument by zero-based index or
formal name. Optional taint semantics declare source labels/evidence or sink
accepted labels; they still do not make the endpoint a diagnostic.

<!-- policy-doc-test:rqlp:tests/fixtures/policies/endpoints/http-request-parameter.rqlp -->
```lisp
; A reusable match-only source. Loading this file never creates a diagnostic.
(endpoint
  :id "bifrost.sources.http-request-parameter"
  :name "HTTP request parameter"
  :display-name "User-controlled I/O"
  :description "A value supplied by an external HTTP request."
  :role source
  :categories [input.user-controlled io.external]
  :selector
    (rql
      (language python
        (call :callee (name "request_parameter"))))
  :binding return-value
  :taint
    (source-semantics
      :labels [attacker-controlled]
      :evidence
        (evidence
          :trust-boundary external
          :system-entry vulnerable-system-network-stack))
  :supersedes [])
```

Aggregate policies opt into endpoints with either:

- `(match-directory ...)`, which names one capability-rooted directory, a
  `direct` or `recursive` scope, and an exact `(any [...])` or `(all [...])`
  category predicate; or
- `(match-endpoints :ids [...])`, which selects exact endpoint IDs already in
  the immutable endpoint index.

Directory traversal is explicit, bounded, symlink-free, `.rqlp`-only, and can
pin `:manifest-sha256`. The directory semantic-hash projection contains its
selection predicate plus only the selected endpoint identities and their full
semantic hashes. The report's richer manifest also retains the reference path,
directory, scope, role, categories, definition and selector schemas, and
analysis-projection hashes. Imported endpoints become dependencies of the
policy; they do not create extra policy runs.

Endpoint `:supersedes` edges express same-event dominance. They apply only when
semantic compilation later establishes that two endpoints describe the same
event, role, and binding. Bifrost never infers precedence from selector text,
directory order, source location, message wording, or “more specific-looking”
categories. A missing target, cycle, or ambiguous live winner is an error.

### Catalogs

Large machine-managed taint libraries can be registered before policy loading
through `TaintCatalogRegistry` as typed values, canonical JSON bytes, or an
explicit workspace-relative JSON path. A policy then names a catalog by
`(catalog :name "catalog.id" :version N)` and may add `:sha256`.
Registration is versioned, content-addressed, bounded, and transactional. It
does not scan directories or access the network. Catalog JSON is a machine
registration contract, not a second human `.rqlp` syntax; human reusable
source/sink leaves should normally use endpoint documents.

## Analysis Types

| Type | Public authoring model | Evaluation in this release |
| --- | --- | --- |
| `match` | One inline or file-backed RQL selector returning supported, location-bearing terminal results. | Executable. |
| `taint` | Set-oriented sources, sinks, sanitizers, transforms, external models, and optional finding combinations. | Parses, validates, and composes; evaluation reports `unsupported` until [#824](https://github.com/BrokkAi/bifrost/issues/824). |
| `typestate` | Tracked subjects, typed events, deterministic transitions, uncertainty rules, and terminal expectations. | Executes query-local semantic bindings and emits production findings with stable identity, primary/related locations, bounded witnesses, and completeness metadata. |

### Taint: broad libraries, specific findings

The taint policy below selects every compatible user-controlled source and
sensitive-data sink from one explicit directory. The generated fallback uses
the fixed `{source display-name} can reach {sink display-name}` relation. A
specific combination supplies more actionable wording:

<details>
<summary>Checked taint policy fixture</summary>

<!-- policy-doc-test:rqlp:tests/fixtures/policies/attacker-controlled-to-sensitive-sinks.rqlp -->
```lisp
; Broad compatible source/sink pairs use the generated relation. The specific
; PII combination supplies a more actionable message and explicitly wins.
(policy
  :schema-version 1
  :id "bifrost.security.attacker-controlled-to-sensitive-sinks"
  :name "Attacker-controlled data reaches a sensitive sink"
  :message (generated-message :relation can-reach)
  :severity warning
  :analysis
    (analysis
      :type taint
      :mode may
      :sources
        (endpoint-set
          :include-matches [
            (match-directory
              :path "tests/fixtures/policies/endpoints"
              :scope recursive
              :categories (all [input.user-controlled]))])
      :sinks
        (endpoint-set
          :include-matches [
            (match-directory
              :path "tests/fixtures/policies/endpoints"
              :scope recursive
              :categories (any [data.pii data.sensitive]))])
      :finding-combinations [
        (finding-combination
          :id "user-input-to-pii"
          :source (categories :all [input.user-controlled])
          :sink (categories :all [data.pii data.sensitive])
          :message "User-controlled I/O can reach sensitive user PII"
          :supersedes [])]))
```

</details>

A generated message is emitted only after the future taint analysis reports an
actual compatible source/sink meeting. Merely matching both endpoint selectors
does **not** license “can reach.” For one actual pair, an applicable explicit
combination replaces the generated default. If multiple explicit combinations
apply, `:supersedes` must leave one unique winner; it never creates a second
solver run or duplicate finding.

Categories, display phrases, and finding messages select and present this
composition. They do not become propagation keys or change the future solver's
set-oriented run identity.

### Typestate: endpoint reuse plus protocol rules

Typestate policies reuse endpoint selectors and bindings for tracked subjects
and phase-specific API observations, then add a protocol automaton:

<details>
<summary>Checked typestate policy fixture</summary>

<!-- policy-doc-test:rqlp:tests/fixtures/policies/resource-lifecycle.rqlp -->
```lisp
; Typestate reuses categorized endpoint selectors, then adds protocol state.
(policy
  :id "bifrost.correctness.resource-lifecycle"
  :name "Resource lifecycle"
  :message "Resource can leave its analysis root without being closed"
  :severity error
  :analysis
    (analysis
      :type typestate
      :mode may
      :call-modeling (call-modeling :unmodeled paranoid)
      :subjects
        (subject-set
          :include-matches [
            (match-directory
              :path "tests/fixtures/policies/endpoints"
              :scope recursive
              :categories (all [resource.acquire]))]
          :entries [])
      :uncertainty
        (uncertainty
          :escape inconclusive)
      :automaton
        (automaton
          :states [open closed violated]
          :initial open
          :accepting-states [closed]
          :error-states [violated]
          :events [
            (event
              :id close
              :matches
                (match-directory
                  :path "tests/fixtures/policies/endpoints"
                  :scope recursive
                  :role sink
                  :phase after-normal-return
                  :categories (all [resource.close]))
              :supersedes [])]
          :transitions [
            (transition :from open :on close :to closed)]
          :terminal-expectations [
            (terminal-expectation
              :id "normal-exit-closed"
              :on (normal-procedure-exit :scope analysis-root)
              :expected-states [closed]
              :supersedes [])
            (terminal-expectation
              :id "exceptional-exit-closed"
              :on (exceptional-procedure-exit :scope analysis-root)
              :expected-states [closed]
              :supersedes [])])))
```

</details>

Endpoint observations retain their matched-value, receiver, return, or argument
binding and their observation phase. Accepting states are not absorbing: later
events can transition away from them. Normal and exceptional **analysis-root**
exits can require that an accepting state was already reached; helper returns
remain interprocedural transfers, not implicit terminals. A terminal-expectation
violation is distinct from a transition into an error state.

`:call-modeling` is shared by taint and typestate policies. `paranoid` is the
default when the record is omitted and conservatively models transfers that are
justified by the structured call site. `optimistic` preserves existing facts
without introducing unseen-body transfers, while `require-model` abstains when
no applicable model exists. Every fallback retains incomplete call-boundary
evidence; none of these settings turns an unresolved call into proof of safety.

Endpoint categories and display/report text remain outside automaton and
interprocedural-summary keys; the protocol analysis consumes resolved endpoint
identity, binding, phase, and behavior.

## Checked Normalized Fragments

These compact JSON fragments are generated from the parsed typed authoring
model and checked against the complete fixture golds. They show normalized
authored JSON only: unresolved file, endpoint, directory, or catalog references
can remain, and this form is not a policy-hash input. The reported
`policy_hash` comes from the distinct loaded and composed canonical semantic
model after the loader has resolved the complete dependency closure. Rendered
report JSON is a third projection over policy runs and findings; it is neither
of those definition forms. JSON is not accepted as `.rqlp` source in any role.

Endpoint source semantics:

<!-- policy-doc-test:json:tests/fixtures/policies/endpoints/http-request-parameter.normalized.json#/taint -->
```json
{
  "evidence": {
    "system_entry": "vulnerable_system_network_stack",
    "trust_boundary": "external"
  },
  "labels": [
    "attacker-controlled"
  ],
  "type": "source"
}
```

The explicit taint presentation rule:

<!-- policy-doc-test:json:tests/fixtures/policies/attacker-controlled-to-sensitive-sinks.normalized.json#/analysis/finding_combinations/0 -->
```json
{
  "add_classifications": [],
  "id": "user-input-to-pii",
  "message": "User-controlled I/O can reach sensitive user PII",
  "sink": {
    "predicate": {
      "categories": [
        "data.pii",
        "data.sensitive"
      ],
      "type": "all"
    },
    "type": "categories"
  },
  "source": {
    "predicate": {
      "categories": [
        "input.user-controlled"
      ],
      "type": "all"
    },
    "type": "categories"
  },
  "supersedes": []
}
```

Typestate terminal obligations:

<!-- policy-doc-test:json:tests/fixtures/policies/resource-lifecycle.normalized.json#/analysis/automaton/terminal_expectations -->
```json
[
  {
    "expected_states": [
      "closed"
    ],
    "id": "exceptional-exit-closed",
    "supersedes": [],
    "trigger": {
      "event": {
        "scope": "analysis_root",
        "type": "exceptional_procedure_exit"
      },
      "type": "semantic_event"
    }
  },
  {
    "expected_states": [
      "closed"
    ],
    "id": "normal-exit-closed",
    "supersedes": [],
    "trigger": {
      "event": {
        "scope": "analysis_root",
        "type": "normal_procedure_exit"
      },
      "type": "semantic_event"
    }
  }
]
```

## Completeness, Findings, And Report Parity

A policy run is not just a list of findings:

- `complete` with zero findings is a clean result only for the analyzer,
  workspace, selector, and budgets used by that invocation. The policy report
  does not currently record the analyzer version, workspace root/revision, or
  configured budget maxima; preserve those separately as described in
  [Reproduce an Analysis](/reproduce-analysis/).
- `inconclusive` (including cancellation or budget reasons), `unsupported`, or
  `failed` is non-clean even when zero findings were retained. Existing positive
  findings remain useful bounded evidence, but the run cannot support a complete
  negative claim.
- Query diagnostics carry typed impact. Capability or work omissions propagate
  into policy completion instead of being flattened into an empty match set.

Every finding is built from one canonical typed model. Human, canonical JSON,
and SARIF 2.1.0 therefore retain the same rule and semantic hashes, finding ID,
location, severity, certainty, completion, endpoint/combination or terminal
identity, classifications, evidence, witnesses, and CVSS variants.

Strong finding IDs use semantic/source anchors and occurrence ordinals—not line
numbers or absolute native paths—so unrelated preceding-line changes do not
churn them unless they introduce an equal earlier anchor and therefore change
the ordinal. A weak ID is labeled inconclusive and is deliberately omitted
from SARIF `partialFingerprints`; it is not promoted into a fake stable
fingerprint.

## Review Findings With Exact Suppressions

Keep project-owned analysis inputs together and keep generated cache data
separate:

```text
.bifrost/
├── queries/                 # saved exploratory .rql
├── policies/                # recurring .rqlp roots
├── suppressions.json        # exact review decisions
└── cache/                   # generated; safe to ignore
```

The conventional suppression file is `.bifrost/suppressions.json`. Version 1
contains accepted review decisions for exact strong findings:

```json
{
  "schema_version": 1,
  "suppressions": [
    {
      "policy_id": "bifrost.security.dynamic-eval",
      "finding_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "identity_stability": "strong",
      "status": "accepted",
      "reason": "This evaluator runs only a checked-in migration script",
      "policy_hash_at_acceptance": "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
      "accepted_by": "security-review",
      "accepted_at": "2026-07-27",
      "expires_at": "2026-10-27"
    }
  ]
}
```

`policy_id` and `finding_id` are the complete join key. Bifrost applies a
record only to a current finding whose identity is strong and exactly equal.
It never falls back to paths, lines, globs, regular expressions, messages,
similar code, or weak identities. Unrelated line insertions and policy
presentation changes can preserve the ID. Editing the selected source bytes,
moving the file, changing its semantic owner, or changing the duplicate
occurrence ordinal produces a different ID and leaves the old decision for
review.

Use an explicit date for a reproducible accept-and-rerun cycle:

```bash
bifrost --root . \
  --policy-file .bifrost/policies/dynamic-eval.rqlp \
  --evaluation-date 2026-07-27 \
  --format json \
  --fail-on warning
```

Copy the reported strong finding ID, policy ID, and optional policy hash into
the suppression file, record a bounded reason and acceptance date, then run
the same command again. The second canonical report still contains the
finding and one suppression review, but an applied decision does not meet the
failure threshold. SARIF retains the result, its `bifrostFinding/v1`
fingerprint, and a standard external accepted suppression. Concise human
output hides the result from the active-finding list while counting it;
`--verbose` prints the reason and provenance.

The audit keeps independent states instead of collapsing review outcomes:

- A current exact strong match is `applied`. A changed `policy_hash` is also
  marked `drifted`, but hash drift alone does not reactivate the same finding.
- A record is `expired` only when the evaluation date is later than
  `expires_at`; it remains active on the expiration date itself.
- An unmatched record is `stale` only when the selected policy completed and
  proved that the finding is absent.
- An unselected, incomplete, failed, unsupported, or inconclusive policy
  cannot prove staleness. A current weak finding also cannot prove the strong
  match required for suppression.
- A retention-limit failure is explicit as `result_omitted` and makes the
  report unreliable rather than claiming a clean result.

A missing conventional or explicit suppression file means no suppressions.
Malformed, unsafe, oversized, escaping, duplicate, or conflicting input
produces a report diagnostic, applies none of that document, and exits with
status 2. Use `--suppressions-file PATH` for one workspace-relative override.
The CLI uses today's UTC date if `--evaluation-date` is omitted; library, LSP,
and MCP callers supply the date explicitly to the deterministic coordinator.

## Classification And CVSS v4.0

A policy can declare one broad fallback taxonomy classification plus typed
refinements. Refinements add evidence-backed classifications; they do not erase
the fallback. A winning taint finding combination can also add classifications.

CVSS is reduced from typed evidence. Policy input never supplies or overrides a
numeric score. A scored CVSS v4 Base assessment requires all eleven Base metrics
with coherent metric/value/scope evidence and no Base `X`. Missing or conflicting
evidence remains an explicit unscored variant with reasons. Threat,
Environmental, and analyst overlays stay separate from static policy assertions;
incompatible records are not averaged, spliced, or resolved by provider order.
Organizational risk is reported separately from CVSS.

## Run Policies From The CLI

Pass every runnable root explicitly. File-backed selectors and endpoint
dependencies are resolved from their authored query-file, exact-endpoint, and
directory references:

```bash
bifrost --root docs/fixtures/ten-minute-evaluation \
  --policy-file policies/review-audit-call.rqlp \
  --format human \
  --fail-on never
```

This is the published, executable [ten-minute policy
example](/evaluate-bifrost/#journey-2-run-a-match-policy). Replace the root and
policy path with your project when authoring a rule of your own.

Repeat `--policy-file` to produce one deterministic combined report. Choose
`human`, `json`, or `sarif`; use `--output report.sarif` for synchronized,
same-directory atomic replacement instead of stdout.

The one-shot CLI starts with empty catalog and endpoint registries. A policy
which names a machine catalog must be loaded through an embedding that
explicitly populated `TaintCatalogRegistry`. A policy which uses only
`(match-endpoints :ids [...])` likewise needs an embedding to pre-register those
endpoint IDs. In an ordinary CLI run, the same policy can instead discover its
closed endpoint set through `(match-directory ...)` and then select exact IDs
from that set. The CLI does not guess paths or scan ambient directories.

| Status | Meaning |
| --- | --- |
| `0` | Every requested policy completed and no active unsuppressed finding met `--fail-on`, or the threshold was `never`. |
| `1` | Every requested policy completed and at least one active unsuppressed finding met the threshold. |
| `2` | Policy or suppression loading, schema validation, composition, evaluation, completeness, serialization, or output was unreliable. This takes precedence over status 1. |

`--fail-on` accepts `never`, `finding`, `note`, `warning` (the default), or
`error`; `finding` includes unrated findings. It changes only the complete-run
finding threshold. It cannot turn an invalid, incomplete, cancelled, or
unsupported run into status 0. Today, running a taint policy emits a retained
report with an `unsupported` completion and exits 2 until #824 completes the
flow adapter. Typestate policies execute; cancellation, budgets, incomplete
selector discovery, semantic uncertainty, and witness truncation remain visible
in run/finding completeness instead of becoming clean zero-results.

See [CLI](/cli/#static-analysis-policies) for option interactions and
[Reproduce an Analysis](/reproduce-analysis/) for the artifacts to preserve.

## Author In VS Code

The Bifrost extension registers `.rqlp` as the distinct **Bifrost RQL Policy**
language. It provides source-only validation, schema-resolution hover,
optional-version completion, 100-column formatting, and a distinct **Run RQL
Policy** action while preserving comments and omitted version fields. Nested
RQL receives RQL highlighting only inside `(rql ...)`.

The policy action sends the current unsaved root to the workspace-backed
loader, which resolves saved query and endpoint dependencies and reads the
conventional suppression file. Active findings appear under **Bifrost Policy
Results**; applied findings move into its suppression audit with stale,
expired, drifted, and unproven review states. `.rqlp` remains separate from
the ordinary RQL query action and never publishes policy findings into
**Bifrost Query Results**. See [RQL in VS
Code](/rql-vscode/#rql-policy-documents).
