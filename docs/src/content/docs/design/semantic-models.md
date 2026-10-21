---
title: Semantic Models and Summaries
description: How Bifrost adds dependency behavior while preserving exact identity, provenance, and completeness.
---

Bifrost inspects available source code directly. Real programs also depend on
standard libraries, frameworks, generated APIs, and binary artifacts whose
bodies may be unavailable. Semantic-model packs add structured declarations and
procedure behavior at that boundary.

[Bifrost-packs](https://github.com/BrokkAi/bifrost-packs) owns open semantic
packs and policy rules, their generation recipes, and their independent release
streams. The engine owns compilation, catalogs, activation, and interpretation.

Model evidence retains its origin. Source-derived proof comes from analysis of
the source itself.

## Model layers

| Layer | Purpose | Typical contents |
| --- | --- | --- |
| Artifact identity | Say exactly which dependency the model applies to | ecosystem coordinates, version/range, digests, language and compatibility profiles |
| Declaration model | Name external types, fields, callables, and signatures | structured owner/member identity, kind, receiver shape, formals, returns |
| Procedure summary | Describe behavior across a procedure boundary | receiver/parameter/return transfers, heap locations, exceptional returns, effects |
| Provenance and coverage | Explain who asserted the model and what it covers | pack, model and summary IDs, origin, completeness, unresolved or conflicting rows |
| Activation | Bind an exact model set to one workspace analysis | selected manifests, source kinds, configuration and active-set digest |

Artifact validity, applicability, declaration binding, and behavioral
completeness are recorded independently.

## Exact binding

A usable procedure summary must bind to a callable identity; display names are
presentation data. Depending on the language, that identity can include an
owner, namespace or module route, declaration kind, receiver presence, arity
and formal positions, signature information, and source or dependency artifact
identity.

Binding requires:

- a callable identity complete enough to distinguish the intended library
  method from a common name such as `exec`;
- owner and signature context sufficient to select one overload;
- call binding that maps argument zero to a formal parameter before applying
  the summary; and
- dependency-artifact identity within the model's stated validity contract.

If the required identity is absent, ambiguous, conflicting, or only partially
modeled, Bifrost preserves that boundary in the result.

Python runtime class bases and exact imported calls share bounded, structured
lexical import selection. A function-local import is eligible only when it is
one unconditional binding event preceding the reference in the same executing
function. Competing declarations, rebinding, parameters, class-namespace
shadowing and captured-cell uncertainty withhold proof. Dotted namespace
imports must match the consumed receiver segments exactly, including aliases.
Exhaustion or cancellation cannot fall through to a weaker import proof or
publish staged call evidence.

Selection proves an import binding. Workspace class admission separately
checks indexed source, facade bindings and declaration ownership; external
admission requires the exact applicable class identity. External intermediate
attribute owners require complete activated module evidence. A matching module
filename alone does not prove that a from-imported value is that module, so
unsupported value chains remain unknown. External ancestry additionally needs
applicable runtime-base claims and retains their provenance and incomplete
boundaries.

Runtime class-object proof also checks recognized AST mutation hazards for
module bindings. Immediate reads use structural execution order, including
loop back-edges; deferred reads remain conservative across the file. A hazard
in an earlier callable body can withhold proof without evidence that the
callable ran. The current guard does not prove invocation or the target
namespace of its exec call, even when an explicit namespace is supplied.
Source imports check each module and facade as a completed export. Actual
global binding events in a directive's own lexical scope remain file-wide
barriers, including pending declarations, imports and deletes; a read-only
global directive is not a mutation. Unknown or stopped admission cannot fall
through to source, external or builtin proof of the same uncertain binding.
These checks neither interpret arbitrary exec text nor infer replacement
values, and do not establish universal absence of side effects. Ordinary
declaration navigation retains its existing contract.

Runtime ancestry can follow class-object assignment aliases within one module.
An eligible alias has one unconditional binding: a plain, unannotated
assignment to a single identifier directly in module scope. The assignment
must finish before the alias read. Its right-hand side is resolved at the
assignment, so each referenced binding must already be available there. Both
reads independently retain the mutation and freshness checks above. Existing
source, imported-class, builtin and model admission rules still govern the
target.

Alias chains are followed iteratively within the same operation's budget and
cancellation state. Results retain the original base spelling, location and
order while reporting the underlying class identity. Competing bindings,
deletions, ambiguous wildcard imports, later target declarations, cycles and
unsupported assignment or value shapes withhold proof. Local and exported
assignment aliases remain unsupported. This runtime transport does not change
ordinary declaration navigation or establish general value-flow analysis.

Complete, pure-syntax inventories of binding-event names and dynamic-hazard
ranges can be reused by exact prepared-source identity within one query or
resolution operation. Syntax reuse does not replace the actual owner's source
and dependency reads, freshness checks or current stopping checks, even when
different owners have identical source bytes. The caller's budget and
cancellation state cover collection, reuse and each read or export check,
including operations without an outer query. Interrupted inventories are not
shared, and a completed inventory cannot override a current reader's stop. The
inventory retains no resolution or model answers and is discarded with its
query or operation; it is not a persistent cache.

## Source and model precedence

Workspace source bodies are analyzed directly. An external summary can stand
in for a missing body only after compatibility, declaration binding, and the
requested proof/completeness policy are checked.

Source and model evidence also make different claims:

- source-backed evidence can prove what the analyzed body contains;
- an authored external model remains an authored claim, even when the pack
  declares that claim complete; and
- a generated model remains tied to its producer and exact generation inputs.

Some reviewed external summaries may close a modeled call boundary under an
explicit policy. That closure applies only to the modeled call boundary.

## Summary identity and reuse

A reusable procedure summary is keyed by the semantic artifact, declaration
locator, schema and semantics versions, context and behavior keys, origin, and
the exact dependency closure it used. Recursive strongly connected components
are validated and published as a unit. A partial component remains visibly
incomplete in any cached form.

Domain-specific summaries extend that carrier identity with their own inputs:

- taint summaries add the taint universe, propagation semantics, event
  matching, and entry facts;
- typestate summaries add the compiled protocol, binding plan, and entry
  states; and
- type-flow and policy-level retained results add their exact request and
  projection identities.

Reuse requires semantic equivalence across every part of that identity.

## Catalog and activation lifecycle

Packs can come from installed, generated, pre-shipped, workspace-produced,
embedded, or explicitly ephemeral sources. Catalog ingestion validates the
pack before activation. The active set has its own digest, so changing one
selected pack changes the analysis identity.

Generated dependency packs use the
[separate semantic-model object catalog](/design/storage-and-cache/).
Its key includes exact inputs and producer identity. A producer change that can
alter generated bytes or meaning must rotate the production-cache version;
otherwise stale output could appear valid even though the generator changed.

Hosts supply or resolve an activation request for semantic packs. The ordinary
analysis path loads that exact set, and the host retains activation diagnostics.

## CSMI interoperability

Bifrost can import and export supported
[Code Semantic Model Interchange (CSMI)](http://csmi.brokk.ai/) profiles. CSMI
is the analyzer-neutral interchange specification targeted by the semantic-model
roadmap. Producer-specific generation and consumer-specific interpretation sit
around the neutral pack format. A schema-valid pack can still be semantically
invalid, inapplicable to the current artifact, or unsupported by a consumer
profile.

Import and export are library functions: `import_csmi_pack`,
`import_csmi_pack_for_language`, and `export_csmi_pack`. The only command-line
entry point is `bifrost-semantic-pack csmi-check`, which validates a document
or pack manifest against the bundled schemas and reports per-profile results.
The import and export adapters map these CSMI profiles onto native pack
fields:

| CSMI profile | Native pack field |
| --- | --- |
| `csmi.runtime-values` 0.1 | shard `runtime_values` |
| `csmi.runtime-values` 0.2 | shard `runtime_contracts` |
| `csmi.collection-flow` | shard `collection_flows` |
| `csmi.deferred-yield` | shard `deferred_yields` |
| `csmi.conditional-type-refinement` | shard `conditional_type_refinements` |
| `csmi.c-cpp-resolution`, `csmi.cpp` | pack `cpp_portability` |
| `csmi.python` | pack `python_correspondence` and `interchange` locators |
| `csmi.value-transfer` | summary `transfers[].value_transfer`, type `value_semantics`, member `implicit_operation` |
| `csmi.transfer-partitions` | summary `transfer_partitions` |

`csmi-check` also recognizes the schemas of the JavaScript/TypeScript, Node
compatibility, Rust, Java source identity, JVM binary identity, Java-JVM
mapping, and JVM compatibility profiles. Recognizing a profile's schema does
not mean that the native pack format has a field for it. The
[Semantic Pack Reference](/reference/semantic-packs/) lists the native fields.

Python predicate refinements use the same branch semantics whether they come
from resolved native `TypeIs`/`TypeGuard` annotations or the standard CSMI
conditional-type-refinement profile. `TypeIs` intersects on true and excludes
on false; `TypeGuard` replaces on true and leaves false unchanged. Application
requires an exact callee and argument binding with complete, agreeing evidence.
Structured generic targets survive transport; a target the class domain cannot
interpret remains explicitly uncertain.

The Python declaration adapter currently supports exact runtime artifact keys
with the standard Python identity profile. It retains artifact digests and
structured ownership descriptors through import and export. Distribution import
bindings, stub-to-runtime correspondence, and unsupported declaration shapes
return an unsupported result. Native declarations without portable identity
evidence cannot acquire that identity merely from their display names.

An interoperability test needs the exact artifact emitted by an independent
producer and the analysis difference with that pack disabled and enabled. A
hand-authored approximation cannot establish producer interoperability.

Runtime-values 0.2 adds portable contracts alongside the existing 0.1 exact
artifact profile. Contract content, source target, activation review, binding,
and executable observation retain distinct identities. A target range must be
fully covered by a supported contract; overlap alone stays indeterminate.
Imported policy and review records require independent consumer acceptance.
Neither a portable contract digest nor a declared target verifies runtime bytes.

The portable consumer currently transports and evaluates these claims. Joining
producer-owned observations to Bifrost's executable graph and discovering Node
targets automatically remain unsupported. Catalog activation cannot bypass
that boundary or create an exact runtime load.

The `keyed-read-value` query can select an exact `:property` or `:index`, all
static properties with `:key-kind static-property`, or static indices with
`:key-kind static-index` and optional inclusive `:index-min` / `:index-max`.
These selectors filter existing proven loads. Dynamic keys and missing runtime
or effect evidence remain incomplete.

## Current boundaries

Model coverage varies by pack. Coverage may close one procedure and leave the
surrounding library catalog partial. Dynamic dispatch, reflection, callbacks,
generated interfaces, native boundaries, and framework conventions remain
visible boundaries after an exact call-summary binding.

Automatic dependency discovery and activation is a
[continuing direction](/design/decisions-and-outlook/).
Its workflow keeps these steps independently diagnosable:

1. discover a dependency artifact;
2. acquire candidate packs;
3. validate and establish applicability;
4. activate an exact set;
5. bind declarations and procedure ports;
6. solve with the resulting evidence; and
7. report every boundary that remains.

Authoring and host integration details are in
[Semantic-Model Packs](/semantic-model-packs/). Every pack field, the shipped
packs, and the pack commands are listed in the
[Semantic Pack Reference](/reference/semantic-packs/). [Dataflow Engine](/design/dataflow-engine/)
and [Evidence and Result Contract](/design/evidence-and-results/) describe how model
evidence affects flow results.
