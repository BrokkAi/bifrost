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

A partial procedure summary may declare positive transfers without claiming to
enumerate all effects. Once exactly bound to a call, those transfers coexist
with the call's ordinary dispatch and unmodeled residual. Their proof comes
from their own evidence; partial coverage leaves unknown effects and prevents
clean absence through the call. A partial sanitizer affects only its declared
transfer edge.

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

A Python module field that a pack types with `value_type`, such as
`os.environ` declared as `os._Environ`, is the exact receiver class of a member
call made on it, so `os.environ.get(key)` can resolve to a declared `get`
member. The import binder selects the field by identity: a parameter, local or
rebound name that spells the module is not the module, and neither is a
workspace module of the same name. A workspace write to the field
(`os.environ = fake`), or a module object that escapes to an unseen writer,
withholds the declared class, and the call stays typed incomplete instead of
reading clean. Reading the field from the module's own namespace runs no
descriptor, so the declaration also retires that read's descriptor claim; the
member call still needs its own declared member and, under a policy that
requires models, a complete external model.

## Source and model precedence

Workspace source bodies are analyzed directly. An external summary can stand
in for a missing body only after compatibility, declaration binding, and the
requested proof/completeness policy are checked.

Source and model evidence also make different claims:

- source-backed evidence can prove what the analyzed body contains;
- an authored external model remains an authored claim, even when the pack
  declares that claim complete; and
- a generated model remains tied to its producer and exact generation inputs.

Schema 19 gives compiled packs an optional artifact-extraction claim: the
producer kind and an exact single-input SHA-256 or source-set digest. Bifrost's
artifact producers supply it to the compiler in memory; authored pack documents
cannot set it. The manifest and every shard repeat the same claim, and both
semantic digests include it. Catalog rows and hydrated provenance retain it.
Older and curated packs have no extraction authority. Producer names and
activation-source labels alone do not establish authority.

Activation decides which extraction claims keep their authority. An extraction
selected by coordinates alone, such as a JDK toolchain range or a package
version, defers to an active extraction of the exact artifact behind every
evidence row it matched. The exact artifact is what the workspace compiles
against, and two producers' facts for one owner need not agree structurally.
The deferred pack stays active and contributes as curated facts. An evidence row
with no exact extraction keeps the coordinate extraction's authority.

Rust implementation inventories make two independent claims within one artifact
source set: a type's direct implementations of source-set traits, and a trait's
generic implementation rules. Inventory-based absence requires both claims,
no applicable positive concrete implementation, and no potentially applicable
blanket rule under its bounds. An applicable explicit negative implementation
is direct evidence of absence. Unsupported predicates remain explicit unknown
applicability conditions in an exhaustive inventory. Compiler-derived auto
traits, including Send, Sync, Unpin and Sized, have no completeness claim. Consumers must preserve unknown results
when bounds or coverage cannot be proved.

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

Selecting the open packs can need a network request. An MCP server answers
`initialize` and `tools/list` without waiting for it: it acquires the packs in
the background. The session warm's installed stage never waits on that
acquisition. While it runs, the installed stage publishes an interim state that
names it, and a `query_code` answer carries the pending-acquisition diagnostic,
so the answer reads incomplete rather than pack-free. The expensive stage waits
for the acquisition, registers the selected packs and activates the whole set.
Policy catalog loading waits for the acquisition on first use. One-shot
commands acquire before they run.

Startup verifies the release envelope and the assets it consumes. It does not
hash unused distribution assets, so damage to one of those assets can remain
undetected until another operation reads it. Full-bundle verification remains
available separately. Stored shards are checked again when read; a writer's
publication marker alone does not certify their bytes for the current reader.

A release install can reuse a stored pack only when its source and manifest,
shard bytes, extraction accounting, selectors, routing, and published semantic
rows satisfy the current exact install check. The current shard validation
certificate and semantic-row publication marker are separate requirements.
Hydration still reads and hashes stored bytes. Distribution-only index changes,
such as an artifact URL or path, do not change install identity when the new
path selects the same verified content. An identical shard row is retained:
replacing it would cascade-delete its selector, routing, and semantic children.
A mismatched stored row is an integrity error, and missing derived rows are
reconciled in place. Bootstrap holds its owned leases until activation returns;
activation rechecks authority before publication, including after a concurrent
install or a failed intermediate write.

Release bootstrap covers the selected workspace's conservative demand: every
language of each kept ecosystem, explicit release-managed evidence pairs, and
exact eligible generated productions. Unknown or partial discovery uses the
whole release. Enabling conditions filter candidates and do not add coverage.
The published activation pins its coverage and the evidence used to compute it.
A request whose snapshot demands more than that coverage reports `WarmPending`
until a matching activation publishes; coverage does not certify that every
model has been acquired. A refresh starts outside `session.write` and coalesces
to one unfinished warm per session. Query or status settlement starts a
replacement for a superseded warm. Publication checks the semantic-pack state
and source snapshot pointers under `session.write`; input changes invalidate
those pointers, so an older warm cannot publish authority for a newer snapshot.

An unpinned Rust workspace explicitly requests approximate standard-library
facts. Shared activation chooses the newest available `bifrost.rust-stdlib`
pack by semantic pack version, retaining engine compatibility and review
controls. It records `approximate` in activation provenance and policy runs
publish an advisory naming the selected pack and version. This does not supply
an observed compiler version or artifact digest, or certify a complete exact
dependency boundary. A declared toolchain pin that
does not match a pack never falls back to approximate activation.

The selected stdlib also supplies one assumed Rust toolchain version for enabled
companion packs. This is the unique exact Rust version named by selectors on
its retained shards, not the stdlib pack's authoring version. Ordinary selector
matching checks companions against that version. Selected companions record the
approximation and assumed version in their activation evidence and dependency
advisory. If the stdlib is missing, its selectors name several Rust versions,
use a range, or name no Rust version, no shared assumption is available. Other
toolchain-keyed packs stay inactive with the reason; the stdlib's approximate
activation and advisory are retained. This assumption is request-scoped and
never becomes observed workspace evidence.

Source-set producers retain the exact extraction-input digest as production
identity. That digest does not automatically constrain runtime applicability:
Rust, Python and JDK source-set producers preserve the caller's activation
selectors. Individual dependency artifacts can still require exact digests.

A warm process keeps dependency-discovery evidence across a workspace update only when it can show that discovery would give the same answer. While it runs, discovery records every input it reads:
- project files, by content, explicit absence and candidate membership;
- external files, by a digest of the bytes it read, or their absence;
- environment values.

At an update, each ecosystem's evidence is carried onto the new snapshot only when every recorded input still verifies and the configuration is unchanged.

A change to the workspace's file set is allowed only when no added or removed path is a candidate for that ecosystem's discovery. One predicate per resolver decides that, and the discovery's own enumeration uses the same predicate.

An ecosystem that cannot be verified is rediscovered on its own, without touching the evidence or active models of the ecosystems that were carried. Discovery that reads process output or walks an external cache cannot be verified, nor can discovery that reported a diagnostic.

Incompleteness that the recorded inputs determine is carried with its truncated flag, so the warm answer equals the cold one. An approximate standard library chosen because no toolchain is pinned is one example: the recorded absent toolchain files pin it.

When a language's own reconcile has already run discovery for an update, activation consumes that captured result instead of running discovery again.

The provider identity includes one digest of the evidence that consumers read, the declared modules and the truncated flag of each language. So products built from different evidence never replay against each other.

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
