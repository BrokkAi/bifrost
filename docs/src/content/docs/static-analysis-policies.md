---
title: Static-Analysis Policies
description: Author reusable RQLP rules and endpoints, run structural and semantic policies, and interpret complete human, JSON, or SARIF reports.
---

Bifrost static-analysis policies are human-readable S-expressions stored in
`.rqlp` files. They add stable rule identity, reporting metadata, composition,
and completeness semantics around native [Rune Query Language
(RQL)](/rune-query-language/) selectors. JSON is available as a normalized or
reporting form, but it is not an alternate RQLP authoring syntax.

> **Current execution boundary:** Bifrost executes match-, taint-, typestate-,
> and assertion-analysis policies. Taint resolves typed source and sink
> bindings, compiles compatible demand, runs bounded set-oriented propagation,
> and renders retained findings. Unsupported or incomplete semantic boundaries
> remain non-clean completion states rather than empty successful results.

> **Important:** An RQL selector returns analysis candidates. An endpoint
> selector match is diagnostic-neutral. Neither an endpoint match nor the
> co-presence of a source and sink proves reachability, and neither creates a
> finding by itself.

## One Document Per File

Every `.rqlp` file contains exactly one top-level document:

| Document | Purpose | Executable root? |
| --- | --- | --- |
| `(policy ...)` | Defines one rule, its report metadata, and exactly one `match`, `taint`, `typestate`, or `assertion` analysis. | Yes. |
| `(endpoint ...)` | Names one reusable, diagnostic-neutral source or sink selector with categories and a typed value/API binding. | No. It is loaded only as a dependency. |

Passing an endpoint to `--policy-file` is an error; Bifrost does not turn it
into a match policy behind the author's back.

### Built-in code-smell pack

The installed binary embeds `bifrost.code-smells`, a catalog of thirteen
structured policies: twelve match policies and one assertion policy. It covers
dynamic evaluation, unsafe Python object deserialization, rayon parallelism
inside blocking Rust lazy initializers, loop-invariant sorting, and review
prompts for regular-expression compilation, file reads, serialization, parsing,
database calls, network calls, subprocesses, sleep, and expensive operations
beneath nested loops. Every rule is an ordinary checked-in `.rqlp` source with a
stable ID and semantic hash; the manifest also records its category, claimed
languages, required capabilities, severity rationale, and remediation.

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

Pack version 1.3 narrows `bifrost.performance.sleep-in-loop` to the `for_loop`
kind: a sleep that throttles every iterated item is worth review, while a
sleep inside a condition-controlled `while` loop is usually the deliberate
mechanism of a poll or bounded-backoff loop and no longer matches. Counting
loops that a language cannot lexically distinguish from iteration (Go's single
`for`, C-style `for`) stay outside the rule.

Pack version 1.5 adds `bifrost.correctness.rayon-in-blocking-lazy-init`, a
Rust-only review prompt for a blocking lazy-init call (`OnceLock::get_or_init`,
`OnceLock::get_or_try_init`, `Once::call_once`, `LazyLock::new`) whose
initializer closure lexically contains rayon parallelism (`par_iter`,
`into_par_iter`, `par_bridge`, `par_chunks`). When the first initialization
runs on a rayon worker, the initializer's parallel join steals sibling jobs; a
stolen job that re-enters the same cell parks on it forever and can wedge the
whole pool. The match is lexical containment, not proof of a deadlock: a rayon
call inside a nested closure defined within the initializer also matches even
when that closure only runs later, and bare `rayon::join`, `rayon::scope`, and
`ThreadPool::install` are excluded because their unqualified names are too
generic for a name-based rule.

Pack version 2.0 replaces the review prompt `bifrost.performance.sort-in-loop`
with `bifrost.performance.loop-invariant-sort`, and the removed ID is why the
major version moves. The old rule asked only "is a sort call written inside a
loop?", which on Bifrost's own repository produced 284 findings that triage
found to be false positives almost without exception: the sorted value was
built inside the loop, so the work was inherent to the iteration. The new rule
is an assertion policy over the question those prompts meant to ask -- whether
the sorted receiver's value is *established* inside the loop, by its binder or
by an assignment there. It claims Rust, Python, Java, TypeScript, and
JavaScript, each with positive and near-miss fixtures. The worked rule below is
its shipped source. The other in-loop prompts stay deliberately naive pending
the same treatment for their argument forms.

Pack version 2.1 moves the eight remaining in-loop review prompts -- regular
expression compilation, file reads, serialization, parsing, database calls,
network calls, subprocess launches, and expensive operations beneath nested
loops -- from `warning` to `note`. Their messages begin "Review whether ..."
because lexical containment cannot prove that the operation repeats per
iteration or that the loop is hot, and a prompt that declines to claim
run-time cost should not fail a build as though it had proved one. With the
default `--fail-on warning` threshold these prompts now surface without
gating; pass `--fail-on note` to restore the stricter gate. Policies that
substantiate their claim keep `warning`: `loop-invariant-sort` proves value
origin, and the correctness rules are not review prompts.

Pack version 2.2 gives `file-read-in-loop` and `parsing-in-loop` the
"same treatment" the 2.0 note promised: both become assertion policies whose
`assert-origin-shape` withdraws the prompt when the enclosing for-each loop's
iterated expression provably resolves to a collection literal with at most
eight elements. The bound came from triaging this repository's own accepted
suppressions, where release scripts loop over module-level lists of two to
seven known file names. The proof is deliberately narrow: it covers
declarator-established bindings -- JS/TS `const`/`let`/`var`, Rust `let`,
Java local declarators -- and every establishing initializer must qualify, so
a literal later reassigned from a call still reports. Loops whose iterated
value is out of evidence keep reporting: while and counting loops, call
results, parameters, Java fields, and Python names bound only by assignment,
which carry no lexical-binding rows in Python's scope-categorical model. A
Rust `[value; length]` repeat array never qualifies because its run-time size
is not its spelled element count.

Use `bifrost --list-policies` or MCP `list_policies` to inspect the exact catalog
in the running build. Select it with `--policy-pack bifrost.code-smells`, a
`--policy-category`, or a stable `--policy-id`; MCP `run_policy` exposes the same
pack/category/ID selectors. The match policies are deliberately
review-oriented: a call name or lexical location is evidence of the parsed
shape, not proof of runtime dispatch, loop invariance, or measured cost.
`bifrost.performance.loop-invariant-sort` is the exception that proves the rule
-- it reports only what its assert established -- and it states its own two
limits in its message and description.

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
note: policy bifrost.security.dynamic-eval inferred policy schema 1 and RQL schema 1
[warning]  app.py:2:12
    Dynamic evaluation is forbidden

summary: 1 active finding; 0 suppressed findings; dependency packs: mode default; complete; ecosystems python; 1 complete policy run
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
| `(rql QUERY)` | Select the compatible RQL head (currently 1). | Add `:schema-version N` for an exact RQL pin. |
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
| `taint` | Set-oriented sources, sinks, sanitizers, transforms, external models, and optional finding combinations. | Executes the production compiler, compatible batch planner, solver, retained report, and human/JSON/SARIF projection. |
| `typestate` | Tracked subjects, typed events, deterministic transitions, uncertainty rules, and terminal expectations. | Executes query-local semantic bindings and emits production findings with stable identity, primary/related locations, bounded witnesses, and completeness metadata. |
| `assertion` | Either a subject selector that captures identifier tokens plus one or more `assert`, `assert-resolution`, `assert-binding-scope`, `assert-value-origin`, `assert-boundary`, `assert-canonical`, `assert-route`, or `assert-round-trip` invariants about the [occurrence](/rune-query-language/) each captured token carries and about how it resolved; or a relational plan of `bind`, `join`, `group`, and `assert` records over typed rows. | Executes. Correlates captures to occurrence, candidate, and binding rows by AST identity and emits one multi-location finding per violated invariant or violated row group. |

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

A generated message is emitted only after the taint analysis reports an
actual compatible source/sink meeting. Merely matching both endpoint selectors
does **not** license “can reach.” For one actual pair, an applicable explicit
combination replaces the generated default. If multiple explicit combinations
apply, `:supersedes` must leave one unique winner; it never creates a second
solver run or duplicate finding.

Categories, display phrases, and finding messages select and present this
composition. They do not become propagation keys or change the solver's
set-oriented run identity.

### Assertion: what the parser must say about a token

An assertion policy is a conformance rule about the analyzer's own output. The
subject selector captures identifier tokens; each `assert` states the
occurrence role, class, and cardinality that token must carry. The correlation
is an equality on AST identity -- the captured node and the occurrence row name
the same arena node -- so an assertion can never be satisfied by a coincidence
of spelling or range.

<details>
<summary>Checked assertion policy fixture</summary>

<!-- policy-doc-test:rqlp:tests/fixtures/policies/role-fidelity.rqlp -->
```lisp
; Assertion policies are diagnostic-neutral conformance rules. The subject
; selector finds candidate tokens; each `assert` states what the parser must
; say about the token captured under `:at`, joined by AST identity rather than
; by spelling. Omitting :schema-version selects the latest compatible policy
; schema, currently version 1.
(policy
  :id "bifrost.conformance.logger-is-never-rebound"
  :name "Logger is never rebound"
  :message "The module logger must be read, never rebound by a local of the same name"
  :severity warning
  :description "A local named `logger` shadows the module logger and silently changes which sink receives the record."
  :tags ["correctness" "shadowing"]
  :analysis
    (analysis
      :type assertion
      :subject
        (rql
          (identifier :text/regex "^logger$" :capture "token"))
      :asserts [
        (assert
          :id no-rebinding
          :at "token"
          :role binder
          :expect none)]))
```

</details>

`:at` must name a capture on the **token** being asserted about, not on its
declaration. Capturing `(function :name "render")` addresses the function node,
while the occurrence lives on the identifier inside it, so the two would
correctly fail to join and the assert would report an absence.

`:expect` is one of `declaration`, `reference`, `binding`, or `none`, and
`:cardinality` is `(exactly N)`, `(at-least N)`, or `(at-most N)`, defaulting to
`(exactly 1)`. `:expect none` and `(exactly 0)` mean the same thing and must
agree; a role whose class can never satisfy the stated `:expect` is rejected
when the document loads rather than evaluated to a guaranteed verdict.
`:namespace` narrows to `type`, `value`, `module`, `macro`, or `label`, and
`:require-target` additionally demands that reference-class rows resolved.

#### Asserting how a name resolved

Four further assert records state *why* a name means what it means. They share
the subject selector, the AST-identity join, and the soundness rules above, and
each carries a required `:role` naming the reference-class occurrence role it is
about, so capability reporting narrows to exactly that role.

`(assert-resolution :id ID :at CAPTURE :role ROLE :expect-tier TIER)` requires
the candidate the resolver selected to sit at one precedence tier. The tiers are
ordered strongest first -- `lexical_binding`, `own_member`, `inherited_member`,
`explicit_import`, `package_or_module`, `wildcard_import`, `external_root`,
`name_only_fallback` -- and `:at-least true` accepts any tier at least as strong
as the named one. `:forbid-tier TIER` removes one tier from the accepted range,
and `:require-unique true` makes ambiguity a violation rather than a silent
pick. A combination no tier can satisfy is rejected when the document loads.

`(assert-binding-scope :id ID :at CAPTURE :role ROLE :declared inside|outside
:relative-to CAPTURE2)` requires the binding actually in effect at the captured
reference to be declared inside, or outside, a second captured node. This is the
loop-invariance predicate: capture a loop and the receiver of a call inside it,
then require the receiver's binding to be declared inside the loop. The half
that declares it outside -- and therefore sorts the same list on every iteration
-- is the finding. `:relative-to` may not name the same capture as `:at`, whose
containment is fixed.

`(assert-value-origin :id ID :at CAPTURE :role ROLE :established inside|outside
:relative-to CAPTURE2)` asks the same shape of question about the value rather
than the binder: it requires the value read at the captured reference to be
*established* inside, or outside, a second captured node. Two origins establish
a value and the requirement is over their union -- the declaring scope of the
binding in effect at the reference, and any assignment whose left operand
reaches that same binding. That second half is what separates a receiver
declared before a loop and overwritten on every pass, which is a fresh value
each iteration, from one that is genuinely re-used unchanged; in languages where
an assignment writes a binding instead of introducing one, `assert-binding-scope`
cannot see the difference. The join to an assignment is binding identity, never
the spelled name, so a write to a shadowing namesake exempts nothing.

`(assert-boundary :id ID :at CAPTURE :role ROLE :forbid-fallback-past
external_declared_unindexed|external_unknown)` forbids a `name_only_fallback`
selection once resolution reached or passed one authoritative boundary. It is a
prohibition, so a reference where nothing was selected satisfies it.

`(assert-canonical :id ID :at CAPTURE :role ROLE :equals CAPTURE :equals-role
ROLE [:distinct true])` requires the two captured tokens' resolved declarations
to share one canonical identity -- language, namespace, ordered kind-tagged
name segments, and generic arity, compared structurally and never by rendered
text. `:distinct true` inverts it: the selections must share none, which is how
a same-terminal decoy (two `Map`s under different owners) is separated from the
true target. `:equals` may not name the same capture as `:at`, whose comparison
is fixed.

`(assert-route :id ID :at CAPTURE :role ROLE :to CAPTURE :to-role ROLE [:via
HOP] [:forbid HOP])` requires an identity route from the captured site to what
the `:to` capture resolves to. The traversal follows the identity-preserving
hop kinds (alias, import, export, re_export) plus whatever `:via` names, and
`:via` additionally requires at least one hop of that kind on the matching
route -- `(assert-route ... :via re_export)` is how "this facade genuinely
forwards the origin" is spelled. A traversal that ends in a cycle or a
truncation is inconclusive, never evidence of absence.

`(assert-round-trip :id ID :at CAPTURE :role ROLE)` requires forward
resolution and inverse enumeration to close: every declaration the site's
route reaches must reach the site back through inverse edges over the involved
files. The mined regressions this family answers are the ones where the
forward and inverse sides of one indirection quietly disagreed.

Three absences make these asserts inconclusive rather than passing or failing:
a selected candidate whose recording seam could not name a tier (an absent tier
is not the weakest tier); an assert that needs the whole considered set on a
language whose resolver records selections but not rejections; and a reference
for which nothing was selected at all. A capture with no lexical binding in
effect is not one of them -- that is a complete answer, so a containment
requirement over an absent binding is simply skipped.

#### Relational assertions over typed rows

The asserts above each address one captured token. An assertion policy can
instead state an invariant over named relations of typed rows. It replaces
`:subject` and `:asserts` with a plan: `(bind ...)` names one relation, either
an RQL query or an expansion of an earlier binding; `(filter ...)` and
`(project ...)` refine a named relation; `(join ...)` relates two relations by
equal-typed registered fields; `(group ...)` groups the joined rows by
registered fields and computes named `(aggregate ...)` values; and `(assert
:group NAME :value NAME :cardinality ...)` bounds one aggregate in every group.
A group that violates its assertion becomes one finding anchored at the exact
source ranges of the rows that produced it. A binding the query engine had to
truncate makes the run inconclusive, never clean; the run's diagnostics then
name each assertion whose verdict that truncation blocked.

##### Row predicates

`:where` takes a bounded conjunction of typed row tests. Each test is one list,
and the operator decides its shape:

- `(BINDING.FIELD eq|ne|lt|le|gt|ge VALUE)` compares a field with a literal.
  `eq` and `ne` are defined for every field; the four ordered operators need an
  integer field, because no other registry scalar carries an order that
  survives a rename.
- `(BINDING.FIELD eq|ne|lt|le|gt|ge OTHER.FIELD)` compares two fields of the
  same row instead. A symbol carrying a `.` is always a field reference, so
  writing a bare registry value never becomes one by accident. Both fields must
  hold the same scalar type.
- `(BINDING.FIELD is-null)` and `(BINDING.FIELD is-not-null)` test presence.
  They are admitted only over fields the row registry marks optional; over a
  field the registry always populates they would be constants, so they are an
  authoring error rather than a question.
- `(BINDING.FIELD in (VALUE ...))` tests membership in a bounded literal set of
  one through 64 values.

Every comparison against an absent value is false, including `ne`. Three-valued
logic would make `(x ne "a")` true for rows that state nothing about `x` at
all, which is the opposite of what an invariant about `x` means. Say `is-null`
when you mean absent.

##### Filtering and projecting a relation

`(filter :over NAME :where (...))` narrows one named relation to the rows that
satisfy every listed predicate. The relation keeps its name and its columns, so
every later record reads the same `NAME.FIELD` columns whether or not a filter
stands between them and the binding. A filter reads only the relation it
narrows, so its predicates name that relation and nothing else.

`(project :name NEW :from NAME :columns (...))` publishes a new relation
holding chosen columns of an existing one. Each column entry is either
`NAME.FIELD`, which keeps the field name, or `(NAME.FIELD NEW-FIELD)`, which
renames it. The projected columns are addressable under the projection's own
name, and the relation it read is no longer addressable at all: a projection
takes the place of its input rather than sitting beside it.

##### Joins

`:kind` chooses how a join combines its two relations, and omitting it means
`inner`:

- `inner` keeps every matching pair and carries both relations' columns.
- `semi` keeps the left rows that have at least one partner and carries the
  left columns only, so it filters without multiplying rows.
- `anti` keeps the left rows that have no partner.

An anti-join is sound only over a right relation that was read exhaustively. If
the right relation was truncated or partly unreadable, its output rows exist
only because nothing was found to remove them, so they support no verdict and
the run reports an unmet obligation instead of a clean pass.

##### Aggregates

The aggregate operations are `count`, `count-distinct`, `min`, `max`, `any`,
`all`, and `ordered-equal`. `count` folds rows; `count-distinct` folds any
column; `min` and `max` fold an integer column; `any` and `all` fold a boolean
column to one or zero, so one cardinality assertion can state every fold. `any`
is one when some contributing row is true, `all` is one when every contributing
row is true, and a group with no contributing row folds `all` to one and `any`
to zero. `ordered-equal` compares two ordered sequences instead, each named by
its own integer position field and the value read at that position:

```lisp
(aggregate :name parity :op ordered-equal
  :left (arg.argument_index arg.name)
  :right (param.parameter_index param.label))
```

It yields one when the two sequences hold the same value at every position and
have the same length, and zero otherwise, so `:cardinality (exactly 1)` states
complete list parity. Position awareness is the point: a call that passes the
same named arguments in a different order is equal to the declaration as a set
and different as a list. A sequence is recovered from the group's rows rather
than from row order, so two states are undefined and never reported as parity:
a row that states no position, and two rows that claim one position and
disagree.

Whether a length difference is visible is a property of your join, not of the
predicate. Joining on the compared value keeps only positions that already
matched on both sides, and two such projections have equal length by
construction; joining on a correlation key instead -- one call site to one
callable -- puts both complete sequences in the group.

##### A plan that uses the whole surface

The rule below states that no member access rejects a candidate: the semi join
keeps only the sites the receiver analysis described, the fold's `:where`
compares two integer columns of the same row, and `max` reports how many
candidates the offending site actually weighed.

```lisp
(policy
  :id "example.relational.no-rejected-candidate"
  :name "Member accesses reject no candidate"
  :message "a member access must select every candidate it considered"
  :severity error
  :analysis (analysis
    :type assertion
    (bind :name site :query (rql (occurrences :role [member_position])))
    (bind :name outcome :from site :step receiver-outcome)
    (bind :name selection :from site :step member-selection)
    (join :left site :right outcome :kind semi :on ((ast_id site_ast_id)))
    (join :left site :right selection :on ((ast_id site_ast_id)))
    (group :name by-site :by (site.ast_id)
      (aggregate :name considered :op max :value selection.candidate_count
                 :where ((selection.selected_count lt selection.candidate_count))))
    (assert :group by-site :value considered :cardinality (exactly 0))))
```

`(assert-selected-in-winning-tier :id ID :site NAME :candidates NAME
[:cardinality ...])` is authoring sugar over the callable-applicability rows.
`:site` names a binding of `overload-selection` rows and `:candidates` a
binding of `callable-applicability` rows for the same sites. It lowers to one
inner join on `site_ast_id`, one group keyed on the site, one aggregate
counting the candidates that are both `selected` and `applicable`, and one
cardinality assertion -- exactly what you could write by hand, which is why it
reports through the same finding path. The winning tier is the set of
candidates the resolver's own applicability check accepted. The default
cardinality `(exactly 1)` is the uniquely resolved site; `(exactly 0)` states a
site where the resolver accepted nothing; `(at-least 2)` states a site that
bound more than one accepted candidate.

An undecided candidate is not an accepted one. A candidate whose verdict is
`unknown` -- the language does not report the callable axis, or it never
recorded that declaration's parameter list -- is not counted, so a site whose
candidates are all undecided counts zero accepted candidates and violates the
default cardinality. Bind the sites your invariant is about, and read the
`overload-selection` row's `resolution` and `supported` fields when you need to
tell an undecidable site from a resolved one. A site the resolver enumerated no
candidate for contributes no tuple to the join at all, so it forms no group and
is never asserted.

#### Completeness in a relational plan

A relational assertion counts rows, so the one completeness signal it can act
on is a bound row that says its own producer suppressed the row *set* it heads.
Today exactly one row says that: a `call_shape` row whose `coverage` is not
`exact`. A macro-derived or otherwise unreadable argument list emits no
argument-group and no argument row at all, precisely so it cannot look
byte-identical to a real zero-argument call, and binding such a row makes the
whole run inconclusive rather than clean.

That signal lives on the mandatory `call_shape` row, so a plan that asserts
anything about a call's arguments must bind that row. A plan that binds only
the projected argument rows sees a legitimately empty set for a macro-derived
site and reports it clean:

```lisp
(bind :name shape :query (rql (call-shape (occurrences :role [member_position]))))
(bind :name arg :query
  (rql (call-arguments (call-argument-groups
    (call-shape (occurrences :role [member_position]))))))
(join :left shape :right arg :on ((site_id site_id)))
```

Nothing weaker poisons the run. An `unknown_shape` overload summary, an
undecided candidate verdict, and a signature whose arity the language never
recorded all publish exact values in their own fields and emit every row they
head, so a whole file is never reported inconclusive because one site in it was
undecidable. Exclude those rows with `:where` when your invariant needs them
excluded.

#### A worked loop-invariance rule

The rule below is the reason `assert-value-origin` exists, and it is the one the
built-in `bifrost.code-smells` pack ships. A structural rule that only asks "is
this call written inside a loop" cannot tell a collection built inside the loop
and canonicalized once from a collection built before the loop and re-sorted on
every pass; the second is the waste worth reporting and the first is not. The
requirement is therefore that the sorted receiver's value be *established*
inside the loop -- declared there, or assigned there -- and the violation is the
half established by neither.

<details>
<summary>Checked loop-invariance rule (the shipped pack source)</summary>

<!-- policy-doc-test:rqlp:crates/bifrost-policy/policy-packs/bifrost.code-smells/policies/loop-invariant-sort.rqlp -->
```lisp
; Promoted from the #1474 Milestone 6 prototype (issue #1598). The naive
; sort-in-loop containment rule this replaces asked "is a sort call written
; inside a loop?" and measured a ~100% false-positive rate on this repository:
; in almost every finding the sorted value was created inside the loop, so the
; work was inherent to the iteration. This rule asks the intended question --
; loop *invariance* of the receiver. The requirement is that the sorted
; receiver's value be established inside the loop; the violation, and the
; finding, is the invariant half: the same value, created once outside,
; re-sorted on every pass.
;
; Two origins establish a value, and the requirement is over their union: the
; declaring scope of the binding in effect at the receiver, and any assignment
; whose left operand reaches that same binding. The second half is what keeps
; a receiver declared before the loop but overwritten on every pass out of the
; report; in Rust, Java, TypeScript and JavaScript such a write introduces no
; binder, so a declaration-only predicate would call it invariant. The join to
; an assignment is binding identity, never the spelled name.
;
; Boundaries, carried verbatim from the prototype because containment cannot
; decide them:
; - A receiver that is a field projection (`group.packages.sort()`) has no
;   receiver-position occurrence for the assert to address, so the rule
;   abstains under either polarity. It decides nothing there.
; - A call written inside a closure or other deferred body inside the loop is
;   reported because it is lexically inside the loop. Containment can say
;   where the call is written; it cannot say how many times the body runs. The
;   message says so rather than claiming per-iteration cost. A sort guarded by
;   a condition that leaves the loop is the same class of fact: the rule
;   reports where the call is written, not how often control reaches it.
(policy
  :schema-version 1
  :id "bifrost.performance.loop-invariant-sort"
  :name "Loop-invariant receiver sorted on every iteration"
  :message "this receiver's value is established outside the enclosing loop and never re-established inside it, so every iteration re-sorts the same value; if the call sits in a closure or other deferred body, it is reported because it is written inside the loop, not because it is proven to run once per iteration"
  :severity warning
  :description "The sorted receiver's value is established outside the enclosing loop -- its binding is declared outside and no assignment inside the loop reaches that binding -- so the loop re-sorts one unchanged-identity value on every pass. Sort once before the loop, or maintain order incrementally. Receivers that are field projections of another value are outside this rule's evidence and are not reported either way."
  :help-uri "https://bifrost.brokk.ai/static-analysis-policies/#built-in-code-smell-pack"
  :tags ["performance" "collections" "loop" "code-smell"]
  :analysis
    (analysis
      :type assertion
      :subject
        (rql
          :schema-version 1
          (union
            (language rust
              (inside (loop :capture "region")
                      (call :callee (name/regex "^(sort|sort_by|sort_by_key|sort_by_cached_key|sort_unstable|sort_unstable_by|sort_unstable_by_key)$")
                            :receiver (identifier :capture "target"))))
            (language python
              (inside (loop :capture "region")
                      (call :callee (name "sort") :receiver (identifier :capture "target"))))
            (language java
              (inside (loop :capture "region")
                      (call :callee (name "sort") :receiver (identifier :capture "target"))))
            (language typescript
              (inside (loop :capture "region")
                      (call :callee (name "sort") :receiver (identifier :capture "target"))))
            (language javascript
              (inside (loop :capture "region")
                      (call :callee (name "sort") :receiver (identifier :capture "target"))))))
      :asserts [
        (assert-value-origin :id established-inside :at "target" :role receiver_position
                             :established inside :relative-to "region")
      ]))
```

</details>

Two boundaries in that rule are worth copying into any rule built on this
predicate. A receiver that is a *field projection* of the loop variable
(`group.packages.sort()`) is not addressed at all: the capture is the projection
rather than an occurrence of a receiver role, so the assert abstains, under
either polarity. And a call inside a closure is reported because it is written
inside the loop, which is a lexical fact rather than a claim about how often the
body runs -- so the message says exactly that instead of asserting per-iteration
cost. The same limit applies to a sort a condition guards before leaving the
loop: containment says where the call is written, not how often control reaches
it.

Soundness is stricter here than for a match policy, because `none` and
`exactly` are claims about a *set*. If the subject query or the occurrence scan
is incomplete for any reason -- an adapter that marks the asserted role
unsupported, a truncated result, an exhausted budget -- the run reports
`inconclusive` with **no** findings and exits with status 2. A partial row set
can make a satisfied assertion look violated as easily as the reverse, so an
assertion over incomplete input is never a pass and never a clean.

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

## An Executable P0 Walkthrough

Everything below runs from a checked-in fixture directory,
`tests/fixtures/policy-substrate-p0/`. Two reference policies exercise the
whole substrate: exact semantic selection, policy-authored value flow,
declarative effects, bounded relational assertions, explicit behaviour when
analysis is incomplete, and one canonical report behind the human, JSON, SARIF,
CLI, and MCP surfaces.

Neither policy needs new analyzer code. Each is a `.rqlp` document; the second
also needs one reviewed semantic model, which is data as well.

### The fixture directory

```text
tests/fixtures/policy-substrate-p0/
  policies/
    acme-validated-value-reaches-store.rqlp         reference policy A (Java)
    acme-validated-value-reaches-store-python.rqlp  reference policy A (Python)
    acme-pure-has-no-network-io.rqlp                reference policy B
  semantic-models/
    acme-http-client.json                           the reviewed effect model
  flow/java/api/AcmeApi.java                        the exact APIs and the near miss
  flow/java/finding/App.java                        one proven violating path
  flow/java/clean/App.java                          validated directly and through a helper
  flow/java/unreliable/App.java                     an unresolvable wrapper
  flow/python/api.py                                the same APIs and near miss, `@final`
  flow/python/finding_app.py                        one proven violating path
  flow/python/clean_app.py                          validated directly, plus the near miss
  flow/python/inconclusive_app.py                   the two shapes Python cannot conclude
  effects/java/api/                                 the @Pure marker and the modeled API
  effects/java/finding/App.java                     a direct and a transitive effect
  effects/java/clean/App.java                       a proven-clean call graph
  effects/java/unreliable/App.java                  an unresolvable callee
  effects/java/deferred/App.java                    a declared deferred effect
```

The acceptance tests are `tests/suite_bench_policy/policy_substrate_p0.rs`
(library surfaces), `tests/suite_bench_policy/policy_substrate_p0_cli.rs`
(CLI), and `crates/bifrost-mcp/tests/bifrost_mcp_policy_substrate_p0.rs`
(MCP `run_policy`).

### Reference policy A: a validated value reaches an exact API

The invariant: every value `AcmeStore.put` stores must have been established by
`AcmeValidator.validate`.

<!-- policy-doc-test:rqlp:tests/fixtures/policy-substrate-p0/policies/acme-validated-value-reaches-store.rqlp -->
```lisp
; Reference policy A of the issue-2433 P0 epic, Java edition:
; "a validated value reaches an exact API".
;
; The invariant is a correctness rule, not a security rule. Every value
; AcmeStore.put stores must have been established by AcmeValidator.validate.
; The analysis carries no labels, categories, tags or impacts: a flow policy
; tracks one thing, whether the value an origin establishes reaches an
; observation without passing a kill.
;
; Exact selection
; ---------------
; Each endpoint selects call sites of one exact declaration rather than
; call text that merely ends in `put`:
;
;     (call-sites-to :proof proven
;       (enclosing-decl (inside-decl (class :name "AcmeStore") (method :name "put"))))
;
; `inside-decl` narrows the seed to the member of one named type, and
; `call-sites-to :proof proven` returns only call sites the definition
; resolver bound to that declaration. The fixture tree contains
; `AcmeCache.put(String)`, a same-named member of an unrelated class, and no
; finding attaches to it.
;
; Actual-to-formal binding
; ------------------------
; The observation binds `(argument :name "value")`, the formal `AcmeStore.put`
; declares, not `(argument :index 0)`, the ordinal the call happens to write it
; at. The port resolves the name through the caller/callee binding of the
; selected call, so it names the same operand whether the call is written
; positionally, as Java writes it here, or by keyword, as the Python edition of
; this policy writes it. `issue_2496_named_flow_port.rs` pins that the two
; spellings report the same sites on this tree.
;
; Selecting through `call-input` and binding `matched-value` is still not a
; substitute: when the actual is itself a call, `call-input` names that inner
; call exactly and the port then binds the inner call's operand.
;
; Unmodeled calls stay paranoid so a call whose body the analyzer cannot see
; still propagates. The abstention fixture runs the same rule with
; `:unmodeled require-model`.
(policy
  :schema-version 1
  :id "bifrost.p0.acme-validated-value-reaches-store"
  :name "Unvalidated value reaches AcmeStore.put"
  :message "a value AcmeValidator.validate never established reached AcmeStore.put"
  :severity warning
  :description "AcmeStore.put must only store values established by AcmeValidator.validate. A value that reaches put from AcmeSource.read without passing validate breaks that invariant."
  :help-uri "https://bifrost.brokk.ai/static-analysis-policies/"
  :tags ["flow" "provenance" "java"]
  :analysis
    (analysis
      :type flow
      :mode may
      :call-modeling (call-modeling :unmodeled paranoid)
      :origins
        (endpoint-set :entries [
          (origin :id acme-source-read
            :display-name "AcmeSource.read"
            :selector (rql :schema-version 1
              (language java
                (call-sites-to :proof proven
                  (enclosing-decl
                    (inside-decl (class :name "AcmeSource") (method :name "read"))))))
            :bind return-value)])
      :observations
        (endpoint-set :entries [
          (observation :id acme-store-put
            :display-name "AcmeStore.put"
            :selector (rql :schema-version 1
              (language java
                (call-sites-to :proof proven
                  (enclosing-decl
                    (inside-decl (class :name "AcmeStore") (method :name "put"))))))
            :observed-operand (argument :name "value"))])
      :kills
        (endpoint-set :entries [
          (kill :id acme-validate
            :selector (rql :schema-version 1
              (language java
                (call-sites-to :proof proven
                  (enclosing-decl
                    (inside-decl (class :name "AcmeValidator") (method :name "validate"))))))
            :input (argument :name "value")
            :output return-value)])))
```

Three things make this exact rather than name-shaped:

1. `(inside-decl (class :name "AcmeStore") (method :name "put"))` seeds on the
   member of one named type.
2. `(enclosing-decl ...)` lifts that match to the declaration.
3. `(call-sites-to :proof proven ...)` returns only call sites the definition
   resolver bound to that declaration.

The fixture tree contains `AcmeCache.put(String)`, a same-named member of an
unrelated class. Run the policy over `flow/java/finding/App.java`, which calls
both:

```sh
bifrost --policy-file policies/acme-validated-value-reaches-store.rqlp
```

One finding, on `store.put(value)`, exit status 1, completion `complete`. No
finding attaches to `cache.put(value)`.

Over `flow/java/clean/App.java` — one value validated directly, one validated
through a workspace helper, and an unvalidated value stored in the near-miss
class — the same command exits 0 with completion `complete`. That clean verdict
is the kill's doing: delete the `:kills` block and both validated flows are
reported.

Over `flow/java/unreliable/App.java`, where an unresolvable wrapper sits between
the origin and the observation, the run exits 2 under both
`:unmodeled paranoid` and `:unmodeled require-model`. An unresolved call is
never a clean verdict.

#### The same policy on Python

`acme-validated-value-reaches-store-python.rqlp` is the same document with
`(language python)` and the same `:proof proven` on every endpoint. It reaches
the same verdicts over `flow/python/`: exit 1 with one finding on
`store.put(value)` and none on the near-miss `cache.put(value)`, and exit 0 on
the validated tree.

Two facts have to hold for that, and both are visible in the source:

1. The receiver's type is evident at the call. An annotated parameter
   (`store: AcmeStore`), a local assigned exactly one visible constructor call
   (`store = AcmeStore()`), a direct `AcmeStore().put(...)` chain, and `self`
   all qualify. A bare untyped parameter does not, and a local that two
   assignments give two different classes does not; those return no proven row
   rather than a guess.
2. The target's dispatch is closed. Java gets this from `final`; Python gets it
   from PEP 591's `@final`, on the method or on its class. Without it the same
   tree still reports the same finding, but a clean verdict is refused: a
   subclass could override `put`, so the resolved member is not proven to be
   the complete target set.

Two Python shapes still exit 2, and `flow/python/inconclusive_app.py` carries
both: a keyword actual (`store.put(value=value)`), which has no formal to map
onto as a value-flow input, and a kill that runs inside a workspace helper
rather than on the observed value's own path.

### Binding the actual passed to a named formal

The analyzer publishes the actual-to-formal relation, and it is exact in both
syntaxes. This query returns the operand bound to formal `value` at every call
of the exact API:

```lisp
(call-input :parameter-name "value"
  (call-sites-to :proof proven
    (enclosing-decl
      (inside-decl (class :name "AcmeStore") (method :name "put")))))
```

Over the Java tree it returns one row, the operand of `store.put(value)`. Over
the Python tree it returns the operand of both `store.put(value)` and
`store.put(value=value)`, so a named call binds formal `value` the same way a
positional one does.

Reference policy A binds the same formal directly, as a value-flow port:

```lisp
:observed-operand (argument :name "value")
```

The port resolves the name against the selected call's own caller/callee
binding, so it names the operand of formal `value` in either syntax. It reads
two sources. The dispatch-aware binding relation is the authoritative one: it
maps a positional actual to the formal ordinal the resolved target declares.
That relation records only that an actual is a keyword argument, not which
keyword, so a keyword call falls back to the structural actual-to-formal
relation above, which reads the label from the call's own syntax; a binding
taken from it is complete only up to that relation. Both editions of reference
policy A use the port, and `issue_2496_named_flow_port.rs` pins that
`(argument :name "value")` and `(argument :index 0)` report the same sites, and
reach the same verdict, on every fixture tree. Every call in the Python
verdict trees is positional, so the named spelling takes the authoritative
route and keeps the complete clean verdict those trees earn; the keyword actual
in `flow/python/inconclusive_app.py` takes the structural one, and the run
reports that rather than concluding.

The ordinal a name resolves to is the callee's, not the call's. Python declares
its receiver, `self`, in the parameter list, and the lowering that mints formal
ordinals consumes it, so formal `value` of `AcmeStore.put(self, value)` is
ordinal 0 and not ordinal 1. The port reads each ordinal off the procedure's own
parameter value rather than off declaration order, which is what keeps
`(argument :name "value")` and `(argument :index 0)` the same claim in a
language that writes its receiver down. Naming the receiver itself is not a
binding at all: `(argument :name "self")` is the same diagnostic as any other
formal the target does not declare as a port.

The resolution is evidence-carrying, not name-shaped:

- A formal name the selected call's exactly resolved target does not declare is
  a diagnostic, not a silent non-match. The run reports `capability_incomplete`
  and exits 2.
- A callee the analyzer cannot resolve exactly degrades the endpoint's proof and
  completeness, exactly as any other unproven binding does, so a run over that
  code cannot be clean. Python's untyped receivers are this case.
- A call site where the name identifies no single actual -- neither a resolved
  formal ordinal nor a written keyword, an open argument group, or two dispatch
  targets that map the formal to different operands -- is a refused row: the run
  names the port and the site and reports `capability_incomplete`.
- Every resolved dispatch candidate has to agree. A call through an interface
  resolves to each implementation, and Java binds an implementation by signature
  rather than by parameter name, so one of them may declare the formal under
  another name. That call is refused too: what one candidate declares is that
  candidate's evidence, not the call's, and neither a confident sibling nor a
  keyword label written at the call site may answer for the set. A candidate
  whose parameter list cannot be read is the same refusal, because an unreadable
  declaration is a shortfall and not a statement that the formal is absent.

Selecting through `call-input` and binding `matched-value` is still not a
substitute: when the actual is itself a call, `call-input` names that inner call
exactly, and the port then binds the inner call's operand instead of the outer
one.

### Reference policy B: a forbidden transitive effect

The invariant: a procedure annotated `@Pure` must not reach the namespaced
effect `acme.network_io`, directly or through a workspace helper.

First the data. One reviewed semantic model declares the effect on one exact
API identity:

```json
{
  "schema_version": 1,
  "pack_id": "acme.http-effects",
  "version": "1.0.0",
  "producer": { "name": "acme-platform", "version": "1.0.0" },
  "language": "java",
  "ecosystem": "maven",
  "compatibility": {
    "bifrost": ">=0.8.0, <1.0.0",
    "toolchains": []
  },
  "provenance": {
    "source": "tests/fixtures/policy-substrate-p0",
    "revision": "reviewed"
  },
  "license": "Apache-2.0",
  "completeness": "complete",
  "safety": { "generated_code_only": false, "review_required": false },
  "shards": [
    {
      "id": "acme.http-effects.client",
      "activation": [{ "configurations": ["acme.http-effects"] }],
      "payload": {
        "kind": "procedure_summaries",
        "summaries": [
          {
            "id": "summary.acme-http-client.send",
            "target": {
              "path": "com/acme/AcmeHttpClient.java",
              "symbol": "com.acme.AcmeHttpClient.send(java.lang.String)",
              "has_receiver": true,
              "parameter_count": 1
            },
            "completeness": "complete",
            "transfers": [
              {
                "input": { "kind": "parameter", "ordinal": 0 },
                "exit_kind": "normal",
                "output": { "kind": "normal_return" }
              }
            ],
            "effects": [],
            "declared_effects": [
              { "id": "acme.network_io", "timing": "immediate", "certainty": "definite" }
            ]
          },
          {
            "id": "summary.acme-http-client.send-later",
            "target": {
              "path": "com/acme/AcmeHttpClient.java",
              "symbol": "com.acme.AcmeHttpClient.sendLater(java.lang.String)",
              "has_receiver": true,
              "parameter_count": 1
            },
            "completeness": "complete",
            "transfers": [
              {
                "input": { "kind": "parameter", "ordinal": 0 },
                "exit_kind": "normal",
                "output": { "kind": "normal_return" }
              }
            ],
            "effects": [],
            "declared_effects": [
              { "id": "acme.network_io", "timing": "deferred", "certainty": "definite" }
            ]
          }
        ]
      }
    }
  ]
}
```

Then the policy:

<!-- policy-doc-test:rqlp:tests/fixtures/policy-substrate-p0/policies/acme-pure-has-no-network-io.rqlp -->
```lisp
; Reference policy B of the issue-2433 P0 epic:
; "a forbidden transitive effect".
;
; A reviewed semantic model declares that the exact API
; `com.acme.AcmeHttpClient.send(java.lang.String)` performs the namespaced
; effect `acme.network_io`. This relational policy asserts that no procedure
; carrying the `@Pure` annotation reaches that effect, directly or through
; workspace helpers.
;
; The marker
; ----------
; `(method :decorators [(name "Pure")])` is the annotation match. The Java
; adapter normalizes `annotation` and `marker_annotation` nodes under a
; declaration's modifiers into the shared `decorators` role, so `@Pure` is
; matched the same way a Python decorator or a C# attribute would be. The
; match is on the annotation's written name, not on a resolved annotation
; type, so an unrelated `@Pure` from another package would also match.
;
; The join
; --------
; `procedure-effects` projects one row per (procedure, effect id), carrying
; `depth`, `classification` (direct or transitive), `certainty`, `timing`,
; `coverage`, and a bounded witness chain. The row is keyed on the
; `declaration` domain's own `procedure_id`, so the join to the marker
; relation is declaration-identity equality.
;
; The absence claim
; -----------------
; `(exactly 0)` is an absence claim, so it is conclusive only when the effect
; relation's coverage is exhaustive. A procedure with an unresolved callee
; leaves the effect set open; the run then publishes an unmet obligation and
; exits 2 rather than reporting a clean verdict.
(policy
  :schema-version 1
  :id "bifrost.p0.acme-pure-has-no-network-io"
  :name "Pure procedures perform no network I/O"
  :message "a procedure annotated @Pure reaches the acme.network_io effect"
  :severity error
  :description "A procedure annotated @Pure must not reach acme.network_io, directly or through a helper. The effect is declared on the exact API AcmeHttpClient.send by a reviewed workspace semantic model."
  :help-uri "https://bifrost.brokk.ai/static-analysis-policies/"
  :tags ["effects" "purity" "java"]
  :analysis (analysis
    :type assertion
    (bind :name pure
      :query (rql :schema-version 1
        (language java (enclosing-decl (method :decorators [(name "Pure")])))))
    (bind :name effect
      :query (rql :schema-version 1
        (language java
          (procedure-effects (enclosing-decl (method :decorators [(name "Pure")]))))))
    (join :left pure :right effect :on ((id procedure_id)))
    (group :name pure-procedure :by (pure.id)
      (aggregate :name network-effects :op count
        :where ((effect.effect_id eq "acme.network_io")
                (effect.derivation eq declared))))
    (assert :group pure-procedure :value network-effects :cardinality (exactly 0))))
```

`(method :decorators [(name "Pure")])` is the annotation match. The Java
adapter normalizes `annotation` and `marker_annotation` nodes under a
declaration's modifiers into the shared `decorators` role, so a Java
annotation, a Python decorator, and a C# attribute are all matched the same
way. The match is on the annotation's *written name*, not on a resolved
annotation type: an unrelated `@Pure` from another package would also match.

`procedure-effects` publishes one row per (procedure, effect id) with `depth`,
`classification`, `certainty`, `timing`, `coverage`, and a bounded witness
chain, keyed on the `declaration` domain's own `procedure_id`. The join is
therefore declaration-identity equality, and the witness's
`witness_effect_site_id` is an id equality against the direct `call_effect`
row, so "show me the exact call this transitive finding came from" is a join
rather than a text search.

Over `effects/java/finding/App.java` the policy reports two findings — the
direct call at depth 1 and the helper call at depth 2 — and exits 1. The same
helper without the marker is not reported, and neither is a marked procedure
whose whole reachable call graph is analyzed and clean.

Over `effects/java/clean/App.java` the run exits 0 with completion `complete`,
because the effect relation's coverage is `exhaustive` and the absence claim is
therefore provable.

Over `effects/java/unreliable/App.java` the run exits 2 and publishes the
blocked claim as data:

```json
{
  "assertion": "pure-procedure-network-effects",
  "kind": "absence_requires_exhaustive_coverage",
  "group": "pure-procedure",
  "group_key": "src/com/acme/App.java:method:com.acme.App.pureCallsAnUnresolvedTarget:273-385",
  "reasons": ["capability_incomplete"]
}
```

The human report counts the blocked verdicts in its scan view and names each
one in its audit view. SARIF publishes the census on the run-level
`BIFROST_POLICY_INCONCLUSIVE` notification and mints no result, because an
obligation is the absence of a claim and not a claim about a source location.

### Activating the model

A semantic model reaches the analyzer through one of two routes. Both routes
feed one activation, so a workspace can use either or both:

| Route | Location | Opt-in | Activated by |
| --- | --- | --- | --- |
| Reviewed workspace models | `.bifrost/semantic-models/*.json` and `*.yaml` | the directory exists | `bifrost --policy-file`, and the MCP host with `BIFROST_WORKSPACE_SEMANTIC_MODELS=on` |
| Installed catalog | the catalog `.bifrost/packs.json` names | the document configures ecosystems; an absent document uses the ambient default | `bifrost --policy-file`, the LSP host, and the MCP host |

Use the reviewed workspace route for a model you write and check in beside your
policies. Put the file in `.bifrost/semantic-models/`, commit it, and
`bifrost --policy-file` activates it. You need no packs document and no catalog
install. Reference policy B runs this way, and
`policy_substrate_p0_cli.rs` pins the outcome.

Use the installed catalog for a pack that ships with a dependency. The shared
packs document names the catalog and dependency ecosystems, while an absent
document uses an ephemeral catalog and the ecosystems serving languages in the
workspace. An empty `ecosystems` array explicitly disables that route.
Activation evidence comes from dependency discovery and remains subject to
compatibility and review gates.

Three rules keep the reviewed route honest.

- **A model that cannot be read fails the run.** If discovery cannot finish, or
  a file will not compile or register, the report carries a
  `workspace-model-load-failed` diagnostic and the run exits 2. A checked-in
  model is never skipped in silence, because a missing model changes verdicts.
- **The review gate is not bypassed.** A model with
  `safety.review_required: true` stays inert until an `enable` entry in
  `.bifrost/packs.json` names its pack id. While it is inert, the report
  carries a `workspace-model-inert` warning that names the pack id and the
  remedy. The warning does not by itself make the run unreliable: the
  evaluation that ran without the model reports its own incompleteness when it
  has any.
- **A diff run activates both sides.** The base revision activates the reviewed
  models its own tree checked in, so adding or removing a model shows up as
  changed findings rather than as noise.

Workspace sources outrank installed and shipped sources when both offer a
model for the same key. The activation provenance names the workspace source,
and the report's `packs` review lists every activation decision.

### Explaining a finding and a near miss

`explain_finding` says why a retained finding exists, by projecting the
evidence the run already kept; it executes nothing, so it cannot disagree with
the report it reads. `explain_candidate` says why one explicit candidate
position was not reported, by re-executing bounded prefixes of the selector
plan. `rank_near_misses` says which subjects came closest, by relaxing the
policy's own declared predicates over a bounded candidate set.

Over reference policy A's own flow run, `explain_finding` answers about the
`store.put` finding directly. The root sits on the observation the tracked
value reached; under it are the origin the value entered at, the retained
witness path as one `derivation` node per step in path order with each step's
exact site, and the finding's certainty, proof, witness retention,
completeness, and the run's completion. Each of those last five is `satisfied`
when the retained evidence licenses the claim and `unknown` when it does not —
never `failed`. A finding whose witness was truncated, or which retained no
witness at all, says so in that node rather than presenting a short path as a
whole one. Taint findings explain the same way in the security vocabulary,
naming each origin's label and source scenario.

Over the exact-selection view of reference policy A — the same selector as a
`match` policy — the `store.put` call explains as `satisfied`, and the
near-miss `cache.put` candidate explains as `failed`, which means the analyzer
finished, declared its result exhaustive, and the candidate was still not
there. That is different from `unknown`, which means the analyzer never
established the answer. A consumer may act on `failed`; a consumer must not
read `unknown` as evidence of absence.

`explain_finding` serves `match`, `assertion`, `flow`, and `taint` findings; a
relational assertion finding explains its assertion, group key, contributing
rows, and any coverage obligations. `explain_candidate` serves `match` and
`assertion` policies, and a relational candidate reports the first row binding
it is absent from. The families each entry point does not serve — `typestate`
for `why`, and `flow`, `taint`, and `typestate` for `why-not` — are refused
with an explicit adapter-unavailable answer that names the supported analysis
types. `why-not` over a flow or taint policy is not a projection of anything
the run retained: it needs candidate-specific solver queries, and it is
designed separately.

### Ranking the near misses

`explain_candidate` answers about a position you already suspect. When you are
refining a rule you usually want the opposite question: which subjects nearly
matched, and which predicate stopped each one. That is the bounded near-miss
ranking, published as its own versioned document,
`bifrost_policy_near_miss/v1`, rather than as a node kind inside
`bifrost_policy_explanation/v1` — an explanation is a tree about one subject,
and a ranking is an ordered list over many.

The distance is the policy's own declared predicates and nothing else. A
selector's seed carries a **scope** — its kind union, language filter, and path
globs — and a set of **predicates**: the root's name, text, arity, visibility,
parameter type, and role sub-patterns, plus the `inside`, `inside_decl`, and
`not_inside` containment. The ranking runs a ladder of selectors: the scope
alone, then the scope with one declared predicate restored, and so on up to the
selector you wrote. Every rung runs the whole pipeline, so its rows are
subjects in the policy's own final domain. A subject's distance is how many
conjuncts remain from the first rung that stopped returning it, and that rung's
predicate is named as its `failing_conjunct`. Nothing else contributes: no
embedding, no model score, no text similarity, no proximity.

Containment is restored last on purpose, and that ordering is what makes the
answer useful. Over the exact-selection view of reference policy A the ladder
is `scope`, `root.name`, `inside_decl`. The `store.put` call clears all three
and ranks first at distance 0. The near-miss `cache.put` call satisfies the
member name and fails only the class it is declared inside, so it ranks second
at distance 1 with `inside_decl` named. The unrelated `AcmeSource.read()` call
in the same file fails the member name too and ranks third at distance 2 with
`root.name` named.

Candidates are never scanned for by default. You either supply the list of
positions to measure, or you ask for a separately budgeted search whose scope
is the policy's own seed. A policy whose seed declares no kind union has no
bounded scope at all — relaxing its name would leave a wildcard over every node
in the workspace — so it is refused rather than searched. A supplied position
that the scope excludes reports `scope` as its failing conjunct instead of
being dropped without comment.

`failed` and `unknown` mean here exactly what they mean everywhere else in the
schema, and `unknown` is never distance. A subject is `failed` only when the
rung that dropped it completed and declared itself exhaustive; otherwise it is
`unknown` and carries the incomplete reasons. A ladder the execution budget cut
short leaves every subject still standing `unknown`, never `satisfied`.
Undecided subjects report the conjunct count they were observed to reach, the
same as decided ones, and the ranking breaks ties by decidedness, so
incompleteness never moves a subject further away than the evidence puts it.

A ranking serves `match` and `assertion` policies, the same two families
`why-not` serves and for the same reason: it relaxes a selector plan, and a
flow, taint, or typestate policy has none. Reference policy A is itself a flow
policy, which is why the ranking above is asked about its equivalent `match`
view. For a relational policy the candidates come from the first row binding's
source query and each further binding is one membership conjunct; a subject
that clears every binding is `unknown`, not `satisfied`, because the joins,
group keys, and aggregates still stand between a row and a violation and none
of them is replayed.

### Reaching the explanations without library code

The MCP tool `explain_policy` takes one policy selection plus exactly one of
`finding_id`, `candidate`, or `near_misses`, and returns the structured
document. The CLI accepts `--explain-finding <ID>`, `--explain-candidate
<PATH:BYTE_START[-BYTE_END]>`, or `--explain-near-misses <N>` beside
`--policy-file` and prints the same JSON. All three exit 0 whenever an answer
was produced, whatever its outcome and even when a ranking is empty, and 2 only
when none could be.

Both surfaces bound the ranking explicitly: how many subjects to retain, and
how many queries the ladder may run. What a bound removed is reported in the
document's truncation record in the same `*_truncated` plus
`omitted_*_lower_bound` form the explanation schema uses, so a caller can raise
the right one.

A `why` question through either surface evaluates the policy once to obtain the
run its finding came from. That evaluation does not activate semantic-model
packs, because activation belongs to the host that owns the analyzer's
lifecycle. A finding that exists only because an activated pack modeled a call
is therefore reported as "the run retains no finding with identity …" rather
than explained from a differently-modeled run.

### P0 capability boundaries

| Capability | Today | Boundary |
| --- | --- | --- |
| Exact call selection | `call-sites-to :proof proven` over an `inside-decl` seed | Java and Python both answer. Python proves the row whenever the receiver's type is evident at the call — annotated, constructed in the same procedure, or `self` — and returns nothing rather than a guess when it is not. A clean *flow* verdict additionally needs the target's dispatch closed, which on Python means `@final` |
| Actual-to-formal binding | `call-input :parameter-name` binds positional and named syntax exactly, and `(argument :name "...")` is a value-flow port for flow and taint endpoints, which both editions of reference policy A bind through | The port needs the callee's parameter list, so an unresolved callee degrades the endpoint rather than binding; a formal the resolved target does not declare is a diagnostic, and a declared receiver such as Python's `self` is not a formal; a keyword actual reaches the port only through the unproven structural relation, so a tree that writes one cannot be clean; and every resolved dispatch candidate must agree that the name reaches this operand, so a call through an interface whose implementations name the formal differently is refused |
| Declared effects | `declared_effects` on a procedure summary, propagated with depth, certainty, timing, and coverage | Path-conditional effects are a P0 non-goal; effect timing is the pack's declaration, not an inference about scheduling syntax |
| Annotation markers | The normalized `decorators` role | Matches the written annotation name, not a resolved annotation type |
| Negative claims | Absence requires exhaustive coverage; an unmet obligation is structured data on the run | An open effect set or an unresolved callee is exit 2, never exit 0 |
| Explanations | `explain_finding` over `match`, `assertion`, `flow`, and `taint` findings and `explain_candidate` over `match` and `assertion` policies, plus the MCP `explain_policy` tool and the CLI `--explain-finding`/`--explain-candidate` flags | A `why` answer projects retained evidence only, so it is exactly as complete as the report; typestate findings, and every `why-not` over a flow or taint policy, are refused rather than answered |
| Near-miss ranking | `rank_near_misses` over `match` and `assertion` policies, published as `bifrost_policy_near_miss/v1`, plus the MCP `explain_policy` `near_misses` form and the CLI `--explain-near-misses N` flag | Distance is the count of unsatisfied declared predicates and nothing else; candidates are the caller's list or the policy's own seed scope, never a repository scan, and a seed with no kind union is refused; a relational subject that clears every row binding is `unknown`, because the joins, group keys, and aggregates are not replayed |
| Model activation | Two routes, above; the CLI policy runner activates both | A `review_required` workspace model stays inert without an `enable` entry, reported as a warning |

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
├── queries/                    # saved exploratory .rql
├── policies/                   # recurring .rqlp roots
├── suppressions.json           # exact review decisions
├── suppressions.private.json   # decisions on files this repository does not publish
├── suppressions.local.json     # one developer's decisions; not committed
├── policy-scope.json           # directory-level review decisions
└── cache/                      # generated; safe to ignore
```

Bifrost reads all three suppression files, in that order, and merges them into
one record set. Each is optional: a repository that publishes everything needs
no private file, and the local file is absent on most machines. All three use
the identical schema below, so a record can be moved between them unchanged.

The split exists so every record can name the file its finding was reported
against. A repository that publishes a subset of its source publishes
`suppressions.json` with it, and a decision about an unpublished file would
otherwise have to omit that name -- leaving the record unreadable -- or
disclose it. `suppressions.private.json` holds those decisions instead. Add
`.bifrost/suppressions.local.json` to `.gitignore`; it is for decisions you are
still working out, and it is never published or shared.

Two files must not both claim the same finding. Bifrost rejects the run rather
than choosing a winner: a disagreement about one finding is a mistake in the
records, not an ordering question. Each source's state is reported separately,
so an absent local file is visibly absent rather than silently ignored.

`--suppressions-file PATH` replaces the whole convention with one named file,
including the private and local ones.

Version 1 contains accepted review decisions for exact strong findings:

```json
{
  "schema_version": 1,
  "suppressions": [
    {
      "policy_id": "bifrost.security.dynamic-eval",
      "finding_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "path": "src/migrate.py",
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

`path` is optional and is never part of the join key. It records the
workspace-relative file the decision was made against, which is what lets a
run tell a record whose identity changed under an edit from a record whose
file that run does not contain at all. Record it: without it a decision that
silently stopped matching is indistinguishable from one this run cannot see,
and the run cannot gate on either. It follows the same portable path rules as
a scope entry -- forward slashes, no absolute paths, no `.` or `..`
components.

Recording it also makes the record readable. A finding identity is a hash and
cannot be reversed, so a record carrying only an identity can be traced back to
its code only by re-running the policy and matching the hash -- and once the
identity has rotated, not at all. The path is what keeps a decision auditable
after the code around it moves.

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
- An unmatched record reports `finding_absent` only when the selected policy
  completed and proved that the finding is absent.
- An unselected, incomplete, failed, unsupported, or inconclusive policy
  cannot prove absence. A current weak finding also cannot prove the strong
  match required for suppression.
- A retention-limit failure is explicit as `result_omitted` and makes the
  report unreliable rather than claiming a clean result.

`finding_absent` alone does not say whether a decision went dead. A record
naming a file the run never analyzed reports `finding_absent` in every run
forever, and a document copied to a tree that does not contain every file it
names is full of those. The separate `orphan_state` answers the question the
gate needs:

- `orphaned`: the run analyzed the record's file and no finding carries its
  identity. The accepted decision no longer resolves to anything, either
  because an edit changed the identity or because the finding is genuinely
  gone. **This fails the run.** A finding that was reviewed and accepted must
  not quietly return to the gate as new code, and a decision that covers
  nothing must not sit in the document unnoticed. Repair it by re-keying the
  record to the current identity or by deleting it; the review lists the
  policy's unclaimed identities in that same file as `rekey_candidates`.
- `path_not_analyzed`: the run did not analyze the record's file, so it says
  nothing about the record and never fails the run.
- `path_unrecorded`: the record names no `path`, so the two cases above
  cannot be told apart. It never fails the run. Adding `path` to the record
  is what makes it decidable.
- `resolved`: the record matched, or the policy did not run exhaustively.

A missing conventional or explicit suppression file means no suppressions.
Malformed, unsafe, oversized, escaping, duplicate, or conflicting input
produces a report diagnostic, applies none of that document, and exits with
status 2. Use `--suppressions-file PATH` for one workspace-relative override.
The CLI uses today's UTC date if `--evaluation-date` is omitted; library, LSP,
and MCP callers supply the date explicitly to the deterministic coordinator.

## Scope Directories Out Of The Gate

An exact suppression accepts one finding of one rule version. Some
acceptances are instead standing statements about a directory: a checked-in
fixture corpus intentionally contains the code smells its tests assert, or a
test tree is not performance-sensitive, so performance review prompts there
are noise. Recording those per finding means every new fixture or test
re-dirties the gate. The conventional scope file `.bifrost/policy-scope.json`
records the directory-level decision once:

```json
{
  "schema_version": 1,
  "scopes": [
    {
      "path": "tests/fixtures",
      "reason": "Intentional smell corpus used as policy test fixtures."
    },
    {
      "path": "tests",
      "reason": "Test code is not performance-sensitive.",
      "policy_categories": ["performance"]
    }
  ]
}
```

Each entry names one workspace-relative directory with a mandatory reason.
`path` follows the portable path rules: forward slashes, no absolute paths,
no `.` or `..` components. Matching is a component-wise directory prefix on
the finding's primary location, so `tests` covers `tests/app.py` but never
`tests_extra/app.py`. Entries have no expiry: a directory scope describes
what the directory is, not one review cycle.

An entry without selectors applies to every policy. `policy_ids` and
`policy_categories` restrict it, as a union: the entry applies to a policy
whose stable id is listed or whose built-in category is listed. Categories
exist only for built-in pack policies, so an entry that should also cover a
repository `.rqlp` policy must list its id or omit selectors entirely. Two
entries may share a path when their selectors differ.

Scoping is applied after evaluation and after suppressions, and it never
hides anything. A scoped finding stays in the canonical report with an
attached `scope` decision (path and reason) and stops counting toward the
failure threshold, exactly like a suppressed finding; a finding that already
carries a suppression is not claimed by scope. The report's top-level `scope`
array audits every entry with its matched-finding count. An entry that
matched nothing is reported as unapplied so dead entries stay visible, and
concise human output hides scoped findings from the active list while
counting them in the summary.

This is deliberately not `.bifrostignore`. That file removes paths from
analysis entirely (navigation, search, usages); a scoped directory is still
fully analyzed and still visible in reports; only the policy failure status
changes.

A missing scope file means no scoping. A malformed one produces a
`scope-load-failed` report diagnostic, applies none of that document, and
exits with status 2, so a broken scope file can never silently accept
findings. Use `--scope-file PATH` on the CLI or `scope_file` on the MCP
`run_policy` tool for one workspace-relative override; both default to
`.bifrost/policy-scope.json`.

## Gate Only On What The Change Introduced

A full policy run fails a repository for every finding, including debt that
predates the change under review. `--diff-base REV` turns the same run into a
changed-code gate: the identical policies also evaluate the committed content
of `REV`, findings are joined across the two revisions by `(policy_id,
finding_id)`, and the failure threshold counts only the findings whose
identity is absent from the base.

```bash
bifrost --root . \
  --policy-pack bifrost.code-smells \
  --format sarif --output out.sarif \
  --diff-base origin/main
```

The join works because a strong finding identity hashes only content-derived
facts: the workspace-relative path, the semantic owner key, a digest of the
matched source bytes, and a small ordinal for identical slices under one
owner. It contains no absolute path, revision, timestamp, or run-local
handle, so the same finding in unchanged content produces the same identity
at both revisions. The base revision is exported into a private temporary
directory and analyzed there; the checkout is never touched.

Each retained finding gains a `diff` decision (`new` or `persisting`, plus a
`weak_identity` marker), and the report gains one top-level `diff` review
with the requested revision, the resolved commit, the three counts, and the
fixed identities the head no longer produces. Weak identities are
snapshot-local by construction, so a weak finding never joins and always
classifies as new. Suppressions and scope still apply first: a suppressed or
scoped new finding does not gate, exactly as in a full run. SARIF results
carry the standard `baselineState` field (`new` or `unchanged`; fixed base
findings are not emitted as results), and concise human output hides
persisting findings while the summary reports all three counts.

The reliability contract is asymmetric on purpose. An unresolvable base -- a
workspace outside a git repository, or a revision `git rev-parse` cannot
resolve -- fails the run with status 2: an unresolvable base is an unreliable
diff request, never a silent full run. A base that resolves but whose
evaluation cannot prove its own completeness instead degrades to full gating:
every head finding gates as if `--diff-base` had not been given, the review
records `degraded: true`, and a `diff-base-unreliable` report diagnostic
states why, so a broken base can never hide new findings and can never be
mistaken for a clean diff run.

Two identity limitations are accepted rather than solved. A pure file rename
re-keys every finding in the file (the path is part of the identity), so a
rename reports one `fixed` plus one `new` pair. Identical source slices under
one owner are distinguished by an ordinal, so inserting an exact duplicate
above an existing one can shift the ordinals and misclassify one pair.

The base evaluation is a full second in-memory analysis of the base tree; it
shares no analyzer cache in this version. For the GitHub Actions recipe that
passes the pull request's base SHA, see
[CI Gating with GitHub Actions](/ci-github-actions/).

## Accept Today's Findings, Gate Tomorrow's

A repository adopting Bifrost can carry hundreds to thousands of pre-existing
findings. The suppression store is deliberately the wrong tool for that scale:
it caps at 512 identity-exact records and demands a reviewed reason for each,
which is right for governed waivers and wrong for onboarding. `--diff-base`
removes the pressure from pull-request gates, but scheduled full runs and
release gates still need "accept everything that exists today, gate everything
new." That is the baseline document:

```bash
bifrost --root . --policy-pack bifrost.code-smells --accept-current
```

`--accept-current` runs the selected policies and writes
`.bifrost/baseline.json` (override with `--baseline-file`) from the completed
run: per policy, the sorted strong finding-id hashes plus the policy's
semantic hash at acceptance, under one batch-level reason and acceptance date.
Entries are identity-only — no per-record prose — so the document holds up to
100,000 entries in at most 16 MiB, two decimal orders beyond the suppression
cap. Acceptance is written only by a clean run: an unreliable run refuses to
define a baseline and exits 2 without writing, because an identity the run
could not prove cannot be accepted. Weak-identity findings are never written
(their identities are snapshot-local), and their excluded count is reported.
Regeneration is always an explicit re-run; the baseline never refreshes
itself.

On every later run the document joins by `(policy_id, finding_id)` after
suppressions and directory scope claim their findings; a finding already
suppressed or scoped is not claimed by the baseline, and its entry is audited
as `finding_claimed`. Claimed findings stay in the report with a `baseline`
decision and stop counting toward `--fail-on`, in full and in `--diff-base`
runs alike: gating counts findings that are new and unclaimed by suppression,
scope, and baseline. The report gains one top-level `baseline` review with the
document path, the batch metadata, exact per-state counts, and a bounded
needs-attention entry list (anything other than applied-with-matching-hash;
the counts stay exact when the list truncates). SARIF renders each baselined
finding as an external accepted suppression entry whose property bag carries
`bifrost.decision: "baseline"`, and concise human output hides baselined
findings while the summary reports the counts.

The audit rules mirror suppressions. A malformed or oversized document is a
diagnostic and exit 2; a baseline never turns an unreliable run clean. Editing
a policy marks its entries drifted without reactivating them — a drifted entry
still applies, and the drift count in the review is the signal to re-review.
An entry is stale only when an exhaustive completed run proves the finding
absent; an incomplete run reports `policy_incomplete` instead of guessing. The
`--diff-base` identity limitations apply unchanged: a rename or an edited
source slice re-keys the finding, so the old entry goes stale and the re-keyed
finding gates until it is re-accepted or fixed.

For the onboarding recipe that commits the baseline once and keeps
pull-request gates on `--diff-base`, see
[CI Gating with GitHub Actions](/ci-github-actions/).

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

The one-shot CLI starts with empty catalog and endpoint registries. A workspace
semantic-pack policy uses the shared `.bifrost/packs.json` contract: an absent
document selects compatible dependency packs for languages present in the
workspace, a configured document selects its named ecosystems, and an empty
`ecosystems` array explicitly disables that route. A configured catalog is
workspace-relative; without one, activation is ephemeral. Activation never
downloads packs or dependencies, and compatibility and `review_required` gates
remain authoritative. A policy which names a machine catalog must be loaded
through an embedding that explicitly populated `TaintCatalogRegistry`. A
policy which uses only
`(match-endpoints :ids [...])` likewise needs an embedding to pre-register those
endpoint IDs. In an ordinary CLI run, the same policy can instead discover its
closed endpoint set through `(match-directory ...)` and then select exact IDs
from that set. The CLI does not guess paths or scan ambient directories beyond
this explicit workspace document. Reports expose the dependency activation mode
and the individual decisions, including missing, incompatible, disabled, or
incomplete activation.

| Status | Meaning |
| --- | --- |
| `0` | Every requested policy completed and no active unsuppressed finding met `--fail-on`, or the threshold was `never`. |
| `1` | Every requested policy completed and at least one active unsuppressed finding met the threshold. |
| `2` | Policy, suppression, or scope loading, schema validation, composition, evaluation, completeness, serialization, or output was unreliable. This takes precedence over status 1. |

`--fail-on` accepts `never`, `finding`, `note`, `warning` (the default), or
`error`; `finding` includes unrated findings. It changes only the complete-run
finding threshold. It cannot turn an invalid, incomplete, cancelled, or
unsupported run into status 0. Taint and typestate policies execute through the
production semantic engine; cancellation, budgets, incomplete selector
discovery, semantic uncertainty, unmodeled call boundaries, and witness
truncation remain visible in run/finding completeness instead of becoming clean
zero-results. Source-backed taint works without external models. An embedding
must explicitly supply and activate a semantic-model catalog when external
procedure summaries are required outside the shared workspace activation
contract.

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
