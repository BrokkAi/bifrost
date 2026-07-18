---
title: Static-Analysis Policies
description: Author reusable RQLP rules and endpoints, run match policies, and interpret complete human, JSON, or SARIF reports.
---

Bifrost static-analysis policies are human-readable S-expressions stored in
`.rqlp` files. They add stable rule identity, reporting metadata, composition,
and completeness semantics around native [Rune Query Language
(RQL)](/rune-query-language/) selectors. JSON is available as a normalized or
reporting form, but it is not an alternate RQLP authoring syntax.

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

## Schema Versions And Selectors

Policy/endpoint schema versions and nested RQL schema versions resolve
independently:

| Source form | Omitted version | Explicit version |
| --- | --- | --- |
| `(policy ...)` or `(endpoint ...)` | Select the newest compiled-in version in the compatible policy lineage (currently 1). | An exact pin; unsupported versions fail instead of falling back. |
| `(rql QUERY)` | Select the compatible RQL head (currently 2). | Add `:schema-version 2` for an exact RQL pin. |
| `(rql-file :path "queries/rule.rql")` | With no wrapper pin, an explicit pin in the referenced document wins; if both omit a version, resolve the compatible RQL head. | A wrapper pin is exact; an explicit referenced-document pin must agree. |

File-backed selectors have four version-resolution cases:

| `rql-file` wrapper | Referenced `.rql` document | Result |
| --- | --- | --- |
| Omitted | Native query with no version envelope | Resolve the latest compatible RQL version (currently 2); the version is inferred. |
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
| `typestate` | Tracked subjects, typed events, deterministic transitions, uncertainty rules, and terminal expectations. | Parses, validates, and composes; evaluation reports `unsupported` until [#824](https://github.com/BrokkAi/bifrost/issues/824). |

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
          :unknown-call inconclusive
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
bifrost --root /path/to/project \
  --policy-file policies/no-dynamic-eval.rqlp \
  --format human \
  --fail-on warning
```

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
| `0` | Every requested policy completed and no finding met `--fail-on`, or the threshold was `never`. |
| `1` | Every requested policy completed and at least one finding met the threshold. |
| `2` | Loading, schema validation, composition, evaluation, completeness, serialization, or output was unreliable. This takes precedence over status 1. |

`--fail-on` accepts `never`, `finding`, `note`, `warning` (the default), or
`error`; `finding` includes unrated findings. It changes only the complete-run
finding threshold. It cannot turn an invalid, incomplete, cancelled, or
unsupported run into status 0. Today, running a taint or typestate policy emits
a retained report with an `unsupported` completion and exits 2 until #824
provides the semantic compiler/adapter.

See [CLI](/cli/#static-analysis-policies) for option interactions and
[Reproduce an Analysis](/reproduce-analysis/) for the artifacts to preserve.

## Author In VS Code

The Bifrost extension registers `.rqlp` as the distinct **Bifrost RQL Policy**
language. It provides source-only validation, schema-resolution hover,
optional-version completion, and 100-column formatting while preserving
comments and omitted version fields. Nested RQL receives RQL highlighting only
inside `(rql ...)`.

Policy buffers are not executable RQL documents: `.rqlp` never enables the RQL
Play action and never publishes policy findings into the **Bifrost Query
Results** tree. Unsaved validation does not read an `rql-file`, endpoint
directory, or catalog; those dependencies are resolved when a workspace-backed
policy loader runs. See [RQL in VS Code](/rql-vscode/#rql-policy-documents).
