---
title: Name Resolution Engine
description: How Bifrost builds a binding graph once for each file's content and joins those graphs at query time to resolve names across a workspace.
---

Name resolution answers which declaration a reference names. Definition, type,
usage, call, rename, workspace-graph, and missing-test queries all depend on
that answer. Bifrost's engine follows the design of
[stack graphs](https://arxiv.org/abs/2211.01224) (Creager and van Antwerpen,
2023), which extends the scope graphs of Visser and colleagues: each file
becomes a small graph, and a query finds a binding by searching for a path
through the graphs of the files it needs.

Bifrost adds three things to that design. It stores the graphs as relational
rows that a query reads by key. It reads build configuration, such as Cargo
targets or Go packages, so that a route between files means what the compiler
would make it mean. And every answer states whether it is complete, so an empty
answer is a claim of absence only when the search finished.

> **Status:** This chapter describes the design that every analyzable language
> moves onto. Rust uses it in production. Go uses it for point navigation,
> calls, rename and target-directed references; its workspace graph rollout
> remains separate. Kotlin definition and type points also use it in
> production; Kotlin usage graphs retain their existing backend. Java and
> Scala have producers and trial resolvers; their production switch is in
> progress.
> The other languages still use the structured resolvers described in
> [Usage Analysis Engine](../usage-analysis/). See
> [Language status](#language-status).

## Design goals

- **Warm interactive work first.** The main workload is a long-lived process
  over an indexed repository that answers a stream of point requests (go to
  definition, find usages, rename) and occasional whole-workspace requests.
  A slower cold start is acceptable when it makes warm requests faster.
- **Per-file work happens once per file content.** Two worktrees, branches, or
  revisions that contain the same file bytes share that file's graph.
- **No global graph to patch.** An edit replaces one file's facts. Nothing
  else is rewritten, and no structure describing the whole workspace has to be
  kept consistent with the edit.
- **Bounded memory.** Workspace-scale state lives in SQLite. Rust holds only
  what one query needs, for that query's lifetime.
- **Explicit completeness.** An answer carries the reasons it may be
  incomplete. Incomplete is never reported as absent.
- **Shared algorithm, language-specific rules.** A language supplies facts
  read from its syntax tree and the rules for its build configuration. Shared
  code owns lowering, storage, selection, and the search.

## Build each file once, join files per query

The central property is the one the stack graphs paper calls
*file-incremental*: a file's graph depends only on that file's bytes and the
version of the language producer that read them. It does not depend on which
other files exist, where the file sits in the workspace, or which revision is
selected.

That property decides where work happens:

- Bifrost stores each file's graph once, keyed by its Git blob identity and the
  producer version, and reuses it in every revision and worktree that contains
  the same bytes.
- An edit creates a new blob. Bifrost reads and stores that one file. The
  graphs of all other files are unchanged.
- Joining files is a query-time operation. A query selects one workspace
  revision, mounts the graphs of the files in it, and searches across them.
  The cross-file answer is computed for that request and is not stored as a
  global graph that later edits would have to update.

The cost of this choice is that cross-file work is repeated per query. The
engine reduces that cost by reading only the parts of the graphs that the
search reaches, as described in [Answering a query](#answering-a-query).

## Pipeline

| Stage | Unit of work | When it runs | Output | Lifetime |
| --- | --- | --- | --- | --- |
| Produce facts | One file's content | When the blob is parsed | File-local facts | Durable, per blob |
| Lower and publish | One blob | Same transaction as the parse | Binding-graph and typed rows | Durable, per blob and producer version |
| Derive context | One build unit, such as a Cargo crate or a Go package | Workspace reconcile | Context rows | Durable, content-addressed |
| Select | One request | Request start | Mount table | One request |
| Search | One request | During the request | Answer with completion | One request |

### File-local facts

A language producer walks the Tree-sitter syntax tree it already traverses for
declaration extraction and records:

- lexical scopes and the declarations each scope introduces;
- references, each with its namespace (type, value, module, and so on) and the
  key it looks up;
- imports and qualified paths, as routes that leave the file;
- typed facts: declared types, literal types, how values move between
  expressions and bindings, member scopes, supertypes, and callable signatures;
  and
- coverage gaps for syntax the producer cannot represent exactly.

The facts stop before binding any reference to a declaration. That answer
depends on the selected workspace, while every fact here is a function of the
file's bytes alone.

### The binding graph

Shared lowering turns the lexical facts into a binding graph. Its node kinds
are the ones stack graphs use: scopes, *push symbol* and *pop symbol* nodes,
scoped variants of both that carry a scope stack, reference and definition
nodes, and the root. The root is one node shared by every file. It stands for
everything outside the file, and it is the only place where a path leaves one
file for another.

A reference pushes the name it looks up onto a symbol stack. A declaration pops
its name. A reference resolves to a definition when a path from the reference
reaches the definition and leaves the symbol stack empty. A qualified name such
as `a::b` is a sequence of lookups: `b` is looked up in the scope that `a`
resolves to.

Lowering records declaration order explicitly. Each lexical scope has a
timeline of checkpoints. A reference looks up its name at the checkpoint that is
active at its source position, and a binder becomes visible at its own
checkpoint. This represents shadowing and the languages that do not allow use
before declaration.

Lowering emits the graph as *partial paths*: path segments inside one file,
such as a reference's lookup in its scope, a scope's link to its parent, or a
declaration's pop of its name. A partial path describes its effect on the
symbol and scope stacks with patterns that can contain variables. The search
joins segments from the same file, or from different files, by unifying those
patterns. A segment that ends at the root continues outside the file. Each
partial path also carries its precedence (which candidate wins when several
are visible), a witness of the steps it took, and its own completion.

### Typed facts

Typed facts form a second, separate layer. Each expression, binding, parameter,
and call result has a slot. Rows record what the file knows about each slot:
declared types, literal types, and copy rules that say a value moves from one
slot to another, as in `let x = make()`. The rows describe structure only.
Lowering does not compute any slot's final type, because that depends on
declarations in other files.

Non-invoking member references use a shared binding-only projection. The producer
supplies a structured receiver and a callable or constructor namespace; shared
lookup applies visibility, inheritance, and hierarchy completion. One visible
member resolves, overloads remain ambiguous with all candidates, and a missing
member is a proved absence only when the receiver hierarchy is complete. There is
no call fact or invocation applicability filter. The projection output carries
binding completion, not a method return type or an inferred functional value
type. Expected-type narrowing is separate work (#5344). Java publishes this
projection for method references; Kotlin callable references and Scala method
values can supply the same receiver, terminal, and namespace facts.

Local reassignment uses an unordered value join. Language producers record a
write's positioned left-hand reference and its right-hand value from syntax;
shared lowering resolves the reference to its exact lexical binder. The
initializer and subsequent writes feed one `ValueJoin` output, followed by one
`Assignment` transfer to the binder's observed-value slot. Inferred local
types read the same join unless the language fixes an inferred local's type
to its initializer's type (`LanguageKnowledge::inferred_local_type_is_initializer_type`,
true for Kotlin). There, writes must conform to that type and only reach the
observed-value slot, so a write that reads the binding, such as `x = x + 1`,
cannot make the static type depend on itself. An explicitly declared static
type stays separate from observed values. The persisted `ObservedValue` declaration property links
the exact local definition to its `AssignmentValue` slot, including locals with
only an initializer. Readers can select that slot without replacing the
declaration's static `Value` property. Its completion is independent of whether
lexical binding found one definition.

Member-definition lookup on an explicitly typed local retains declared-type
precedence. The observed alternatives do not turn that lookup into runtime
dispatch. Inferred locals instead expose the initializer and write alternatives
through their shared inferred type, except in a language whose initializer
alone decides that type. Tests of an explicitly typed local therefore
check its static member target and its observed-value join independently.

This contract retains every alternative and every input's incompleteness. It
does not select the latest write or prove runtime reachability. Shadowed names
remain different binders, and named argument labels do not write to locals.
Unsupported writes remain explicit gaps rather than disappearing from the
known alternatives. Implicit and destructured initializers whose component value
is not modeled contribute an explicit unknown input. A genuinely uninitialized
local has no invented initializer input. These runtime gaps do not alter a
known static declaration type. See issue #5015 for the owner decision.

## Storage and identity

Lowering output is stored as ordinary SQLite rows. Two kinds of rows serve two
kinds of question:

- **Discovery rows** answer questions that cross files without knowing which
  file to open, such as which files contain a reference that looks up a given
  name.
- **Per-file rows** answer questions about one file the query already knows:
  its nodes, partial paths, typed slots, and gaps. They are keyed by blob and
  a key local to that blob.

A partial-path row stores, as indexed columns, the values the search seeks by:
the start node, the end node, and the first symbol of each end's stack. The
rest of the path is one JSONB array, because every reader takes a path whole.
Rows contain no workspace path, package identity, or revision. A blob's rows
are one complete publication that every worktree can share.

### Identity encoding

Identities are integers, not content digests.

- **Shared names.** A lookup recipe, such as "the value-namespace lookup of
  `len`", or an intrinsic type belongs to no file. The store interns it once
  as an integer, and rows refer to that integer.
- **Blob-local identities.** A node, path, or stack variable is stored as its
  blob and a local key.
- **Mounted identities.** In memory, a query uses a 64-bit value that holds a
  kind and a payload. A local identity's payload is the mount it belongs to and
  its local key. A shared identity's payload is the interned id. A value that
  one query or one selected context creates for itself has its own kind and is
  dropped with the query.

A mount is one blob placed at one workspace path for one query. The same bytes
at two paths are two mounts. This matters because a file's meaning can depend
on its location: in Rust, its module path comes from where it sits, and one
file can belong to two crates. The two mounts read the same stored rows and
receive different identities. These integers are internal to the engine.
Results that leave the process must not carry them.

### Write timing

Bifrost writes all of a blob's discovery rows and per-file rows when it parses
the blob, in the same transaction as the blob's other source facts and its
completion marker. The rule behind this is that a file is parsed once.
Everything the parse and the lowering produce is written then, so no later
query has to parse or lower the file again to obtain rows that the first pass
could have written. Indexing does more work up front, which is the trade-off
the design goals accept.

Readers mount only complete publications made under the active producer
version. A change to lowering semantics rotates the producer version, which
makes older publications unmountable until the files are reparsed.

Content that is not in the selected revision is published the same way. Live
working-tree content that has no stored publication yet, and the hypothetical
source that a rename checks before it edits, are published as ordinary blobs
and then mounted in place of their path for one request. Neither takes a
separate in-memory path.

## Workspace context

Stack graphs are purely syntactic. They need no build configuration, which
suits a code host that cannot run each project's build. Bifrost runs inside the
user's workspace, and in several languages the meaning of a route between
files depends on configuration:

- Rust: Cargo targets, each target's module tree, edition, enabled `cfg`
  options, and implicit prelude.
- Go: module and package membership, imports, and build constraints.
- JVM languages: source roots, packages, and dependencies.
- Other languages: project references, include paths, preprocessor
  configuration, or import roots.

For Go, the go command is the package authority. In module mode, vendoring
uses the main module root's `vendor` directory; nested `vendor` directories
are not providers. Bifrost reports the tool's discovery error for an unresolved
import, including the import path, rather than selecting a nearby source copy.
This retires the legacy nearest-vendor guarantee (#5697).

After a workspace update, native Go discovery includes unsaved Go source when
an edit changes build constraints, the package clause, cgo use, or imports.
Body-only edits reuse the existing package placement; body-only buffers are
overlaid only when some buffer changed membership. When discovery runs for a
disk-only reason, equal membership digests give the same `go list` answer from
disk, so body-only buffers need no replacement bytes. Source overlays require
Go 1.16 or newer when discovery needs their replacement bytes. Unsaved source
deletions and unsaved changes to `go.mod` or `go.work` are unsupported until
saved.

Go is the only native language whose prefixes can resolve into a remote source
environment: a package in the module cache or a vendor tree, prepared as an
overlay. Rust reads dependency packs and rustdoc JSON, and the JVM languages
read JARs, so neither needs one. Go therefore keeps a language hook for remote
prefixes: a nested evaluator resolves the prefix inside the remote
environment's prepared context. The shared demand scheduler evaluates prefixes
only in the caller's environment. Moving remote environments into it would
need a request-owned registry of environments and, for overlays prepared
during the request, a stable owner outside the request. That work waits until
a second language needs remote environments or the nested evaluator causes a
defect (#5658).

Source-owned root imports are published independently of lookup demands in
`resolution_root_imports`, `resolution_root_import_segments`, and
`resolution_root_import_demands`. Each route retains its native site and scope,
anchor, source position, named/glob kind, ordered path, and optional exact target
reference with its source spelling. An unused glob still has a route. A shared indexed reader selects a
scope's named and glob routes; language-specific context then chooses their
destinations. Rust import tokens carry an explicit site crosswalk rather than
borrowing a source import ordinal from a semantic key.

### Import halves and export halves

File-local facts describe each cross-file route in two halves that do not know
about each other. An *import half* runs from a reference out to an anchor, such
as `crate::`, a package name, or an imported module. An *export half* runs from
a root into one of the file's declarations. Context rows record, for one build
configuration, what each anchor names: which files a crate, module, or package
contains, and what it exports and imports. When a query selects a
revision, its selected context compiles *bridges* from those rows: extra
partial paths that connect import halves to export halves. A bridge belongs to
the request. It is never added to any file's stored graph.

### Shared import coordinates

The shared import layer reads one exact route coordinate: the catalog or staged
route kind and source site, whether it came from staging, and its identity
digest. The selector is a separate coordinate with its own authority: its kind,
source name, and local name do not derive from the route. A staged coordinate's
presence overrides the catalog route and digest even when its route kind or
digest is NULL. The route kind is a shape vocabulary shared by producers, not a
language-specific interpretation:

| Producer | Route kinds |
| --- | --- |
| Java | `single_type`, `type_on_demand`, `single_static`, `static_on_demand` |
| Kotlin and Scala | `named` and `star`; Scala selectors retain their source and local names |
| C# | `using N` writes `type_on_demand`; `using static T` writes `static_on_demand`; `using A = X` writes `named` with a named selector, as implemented in `crates/bifrost-csharp/src/resolution/imports.rs` |
| Go | Dot imports do not write a shared route kind; their private import facts feed the Go dot-import path. |
| Python | Does not use the shared import layers: its two-arm import-site crosswalk, its flow-sensitive reaching-import selection and its name-driven star imports fit none of them (see below). |

Python does not use the shared import layers. Its import-site crosswalk has two
private arms, from route reference to import site and from import demand to
semantic reference. Its reaching-import selection follows flow-sensitive
binding events and does not fit the shared scope and depth selection. Python
star imports are name-driven: for each requested spelling they check the
target's wildcard export-name surface and `wildcard_inventory_closed`, then
publish a synthetic route binding with an absence proof. They do not enumerate
export halves. Python already reads `resolution_import_selectors` directly.

### Three kinds of derived data

Everything the engine stores or computes is one of three kinds, and each kind
has one rebuild rule.

1. **File facts** depend on a file's bytes and the producer version, and on
   nothing else. They are the rows described above. When either input changes,
   the file's rows are replaced and no other row is touched.
2. **Unit summaries** describe one *unit of recursion*: a Cargo crate, a Go
   package, or a JVM source set. Inside the unit, resolution is recursive;
   outside it, resolution is a lookup against another unit's published
   surface. A summary is keyed by the unit's own inputs: its member files'
   contents, its configuration bytes, the producer version, and the version of
   the derivation rules. It records, as rows, the *output digest* of every
   unit it consumed, and it publishes an output digest of its own surface: what
   it exports and whether it is complete. The context rows of the previous
   section are this kind.
3. **Request answers**, such as a definition at a site, the usages of a
   symbol, a workspace graph, or a rename edit set, are never stored. Each
   request recomputes its answer over the two kinds above and keeps memos only
   for its own lifetime.

JVM selected operations reuse completed reads by their full inputs and selection
epochs within that request. These memos die with the operation and are never
persisted or shared with a later request.
The shared context-preparation lifecycle owns memo admission, lazy import
plans, compiled projections and registration charges. Languages supply exact
keys and typed derivations, including their metadata and inventory proofs.
Joinable membership remains in request TEMP rows, and named publication is a
SQL delta against staged membership. Compiling a projection does not authorize
its reuse as a published row until the context transaction commits; failed
registration charges do not advance the provider ledger. Provider cells are
registered once per request, with new named cells charged as deltas.

The rebuild rule for a summary gives the engine its incremental behavior. A
unit is derived again when its own inputs change or when a consumed unit's
output digest changes. If the new output digest equals the stored one, the
unit's dependents are left alone. This *early cutoff* is why an edit to a
function body stops at the unit that contains it.

Two rules follow. Point requests and graph requests share the relations they
are computed from, never cached answers, so no table is keyed by a request. And
a recursive relation, such as an import closure, is never maintained by
applying deltas when files change; the unit is recomputed, and early cutoff
limits how far the change spreads. A value that fits none of the three kinds
is a schema gap to report, not a cache to add.

Rust's crate rows reach early cutoff today by folding the consumed output
digests into their key. The shared summary relation, which stores them as rows
so that a unit's dependents can be found by query, is being adopted language by
language.

A Rust re-export can name a declaration reached through a direct dependency's
own exports. Its shared export row records that direct dependency's ordinal,
while Rust's target coordinates still identify the final declaration. The
dependency's published surface must therefore include public descendants of
modules it forwards, including their namespaces and effective visibility.
Forwarding a module is not just publishing the module's name: removing a
reachable item changes the facade's output. Changes outside that exposed
surface still allow early cutoff. Tuple-struct types and their value
constructors have separate visibility; a constructor is no more visible than
its least visible field.

The topology stores canonical public module memberships as relational rows.
These prove that a direct dependency exposes a target module even when a public
alias leaves the forwarded module's physical subtree. Membership follows only
unambiguous public edges. Uncertain candidate edges still affect the output
digest and open the inventory, but do not prove accessibility. Both results
come from the same finite module graph; aliases and cycles do not create new
canonical nodes. Shared Rust summaries reuse the topology's surface digest.
Those surface gaps belong to the topology, not to a member's binding summary: a
missing public module still has a known declaration and a known failed lookup,
so it opens the topology inventory and changes the digest without marking every
member of the crate incomplete.

### Rust import determinacy

Rust derives bindings by module, lexical scope, namespace and spelling, retaining
all distinct canonical declaration endpoints. Item and named-import precedence
is applied before glob propagation at each intermediate module. Accessibility
is checked on the carried binding. Equal-precedence endpoints remain ambiguous
and carry scoped `InconsistentPrecedence` evidence; SQLite row order never
selects a representative. Ambiguity follows accessible binding flows and named
path dependencies. A dependency needed only to prove completeness does not
carry ambiguity from names that the consumer cannot access.

Canonical endpoints do not replace dependency edges. A separate Rust binding
provenance relation retains each admitted source import, its first provider
binding and its canonical endpoint. Summary route provenance reads these edges,
so two facades of one declaration remain distinct dependencies. Point lookup
continues to read canonical endpoints directly. The output digest covers these
dependency-visible edges using logical source paths rather than blob ids, so
ordinary body edits can still stop at an unchanged output digest.

A conflicting glob group's visibility is exact when all members agree. A
consumer admitted by every member reads the group as ambiguous. If only some
members admit that consumer, the facts do not determine the group's effective
visibility: rustc's import resolution order selects the visibility of its
ambiguity binding. Bifrost preserves every canonical endpoint as scoped
`UnsupportedSemantic` evidence instead of modeling an order or selecting a
member. Exact exports exclude endpoints supported only by that uncertain
flow; an independent exact witness for the same endpoint remains available.
The final positive witness closure and uncertainty evidence are add-only, as
is the canonical binding relation. Point readers consume the same scoped exact
set; raw glob reachability cannot make an unsupported member exact. All-private
groups export nothing to an
inaccessible consumer, while all-public groups export their ambiguity.

Import lookup and glob propagation form one dependency graph. Lookup and glob
inputs are positive edges; named shadowing and external-prelude fallback add
negative edges. The shared SCC algorithm partitions this graph. A component
without an internal negative edge reaches its least fixed point after its
predecessor strata are complete. An empty such component proves absence,
including an unanchored cycle of named imports. An internal negative edge keeps
unsettled keys incomplete with `CyclicExpansion`. Open macro or external inputs
remain incomplete through the existing boundary evidence. Admitted endpoints
are never withdrawn.

A named import's source lookup excludes that import's own contribution when it
reads its bound spelling in its own scope. Other imports and globs still count.
These temporary lookup keys share the admission relation but are never
published as module exports. This allows a named import to obtain a binding
from its module's glob without making that weaker glob visible prematurely to
other readers. Named re-export chasing deduplicates the source identity and
current canonical target; it terminates on the finite relation rather than an
arbitrary hop limit. Visibility walks terminate at the path's segment count.

### Incremental context derivation

Summaries are derived for each unit during workspace reconcile, from the
unit's file facts and the exact bytes of its configuration inputs. Because the
key covers every input, an unchanged unit is reused across revisions instead of
being derived again.

After an edit, reconcile derives again only what the edit can affect:

1. the units that contain a changed file; and
2. the units that depend on a unit whose output digest changed. An edit to a
   function body changes no export, so it reaches no dependent unit.

Some changes can alter which files belong to which unit: a build manifest, a
lock or configuration file, or a new file that an existing module declaration
already names. These run the full pass, which derives every unit from scratch.
The full pass is also the reference that tests compare the incremental pass
against.

Rust's Cargo crates follow this design now. Context derivation for Go
packages and JVM source roots exists and is being completed. Each remaining
language needs its own.

## Answering a query

### Selection

A query starts on one read connection by selecting a workspace revision. The
engine builds a temporary mount table for that connection: one row per
selected file, linking its path to a complete publication. If a file has no
complete publication under the active producer version, the query reports that
the engine is unavailable for it, with the reason, instead of guessing.

The mount table and its selected context rows stay with the pooled connection
after the query ends. A later query that validates the same selection reuses
them, which makes the warm path a few statements instead of a rebuild. Rust
selections include indexed temporary rows for revision-valid unit summaries,
workspace dependency reachability and module placements. The connection
rebuilds these rows when the selection changes or its validity check fails. Ordinary
workspace readers check both revision snapshots and SQLite publication freshness:
summary publication can finish without changing the workspace revision. The
writer fallback explicitly invalidates its selection after publication because
SQLite's data version does not include that connection's own commits.

On the writer fallback, the query's connection is the store's only connection,
and the caller of a Rust reverse query reads the store between the query's
answers. The query therefore lends its connection to the caller and takes it
back for each answer; it publishes macro capsules on that same connection.
Ordinary reads share the query's revision rows. A read of other snapshots
replaces them, and the query restores them when it takes the connection back.
Any other change made while the connection was lent, such as another query
staging its own selection, makes the query stale. A request that waits for the
connection, to open a query or to take its connection back, stops waiting when
it is cancelled.

A query can narrow which mounts a name may bind into. A forward Rust lookup,
for example, binds only into the crates that the referencing crate can see. A
gap in an unrelated crate cannot hide a candidate, so it cannot make the answer
incomplete.

### Generated item surfaces

For unexpanded Rust attribute and derive macros, resolution assumes the macro
preserves the annotated item's name, binding, authored generics, defaults and
fields. Expansion may add members, impls and new names, but cannot shadow an
existing authored, imported, glob-imported or prelude binding. A type, value or
module name lookup that finds a binding therefore ignores generated-item-surface
reasons. A lookup that finds no binding retains those reasons: absence remains
open. This policy is a language capability, enabled for Rust; other languages
retain their existing lookup rules.

Member lookup uses the generated surface of the receiver type. On an annotated
receiver, a found authored field or inherent member (method, associated function
or const) is exact: duplicate inherent items are a compile error, and inherent
members outrank trait members. A trait-found member retains its existing
completeness: generated surfaces add no obligation to a found trait member.
Missing members and fields retain the generated surface reason. An unannotated
receiver uses its authored member surface, including trait-found members, even
when a field of an annotated type
supplied the receiver. These obligations do not imply missing authored reference
sites, so reverse inventory completeness does not become worse because of
additive generation.

Definitionless function-like macros invoked in item position follow the same
name-binding rule. Argument references recovered by guessing the macro's input
grammar stay unproven at their own sites. The expansion keeps the member
surfaces of every type owned by the invocation's lexical scope open, including
lookups that find an authored member. A type referenced by an argument but
defined elsewhere does not acquire an open member surface from that invocation.
This is the existing limit for unexpanded item macros. The reverse reference
inventory of the file holding the macro is incomplete only when an argument
group cannot be enumerated as references. Fully parsed arguments keep the
inventory complete while their guessed references remain unproven. Other
references an expansion might generate are the same accepted residual as
additive generation under #5205.

The documented `cfg_if!` arm structure is handled without general macro
expansion. The producer reads structural token trees and gives each ordinary
item its own arm predicate together with the negation of earlier predicates.
Cargo context selects those items at request time. Unknown conditions retain
uncertainty, while a proven earlier match excludes later unknown arms.
Unsupported macros inside an arm keep their own name and member frontiers;
only a predicate proven inactive in every selected membership discharges those
frontiers. Existing bindings follow the same additive rule as other item
macros.

Parse-time lowering evaluates the operands of built-in macro names: the
formatting and value macros listed in `crates/bifrost-rust/src/format_args.rs`,
and the `log::` level macros. A same-file `macro_rules!` scope or an explicit
`use` can shadow those names. Lowering uses only the file's content, so
shadowing from another file is an accepted limit. Source and sink binding
still require the resolver to prove the macro's identity. A survey of Vector,
Bifrost and 2,214 crates from the local Cargo registry found zero risky sites:
all 74 qualifying cross-file sites evaluate their operands.

### Forward search

Forward resolution starts from the partial paths that begin at the reference in
its own file. The engine repeatedly extends the current path: it looks for a
partial path whose start node equals the current end node and whose stack
patterns unify with the current stacks, and joins the two. Within a file, the
next segment comes from the same file. A path that reaches the root continues
through a bridge from the selected context into another file's export half. The search stops when a path reaches a definition with empty stacks.

The search is driven by demand. It reads only the rows its current frontier
needs, and it reads them in batches: one statement carries the keys of a whole
frontier rather than one key at a time. Routes that many references share,
such as the leading segments of `crate::a::b`, are evaluated once per query and
reused within it.

The result is the set of candidate definitions, ordered by precedence, with
the witness paths that support them and the answer's completion.

A root relation can request member selection from exact projected owner types.
While selecting members, the relation can wait on selected source roots and
qualified ancestor references in the same demand scheduler. These dependencies
use the existing hierarchy lookup and cycle detection. Scala imports use this
capability to include inherited members and members reached through stable
values. Missing ancestors retain their incomplete evidence alongside proven
members; dependency cycles return named incomplete answers. The capability also
accepts projection owners, without requiring a separate hierarchy walk. A stable
value contributes only its exact projected static type; an unresolved or
ambiguous projection cannot supply a guessed import owner. Other relations
close after their positioned reference inputs finish.

Package pairing uses a shared plan builder that reads the chosen sources in
order and keeps their member inventories and completeness evidence. Go uses a
shared source-major driver: source, then reference, then matching member. C#
will use that driver as its namespace support moves onto the shared engine.
The JVM keeps reference-major emission because its default-import gaps, lookup
filter and per-candidate access reads interleave with the join. Descriptor
order reaches answers, so both orders stay intact (#7314).

Lowering persists each route's precedence steps, including the JVM binding
origin rank. A supplier-dependent package bridge appends its own origin step
before the path reaches the engine. The engine compares the last origin step
when both paths carry one, then the shared choice points in path order. Equal
or unordered paths to distinct targets survive together as an ambiguous answer.
Scala ranks local, inherited and same-compilation-unit package declarations
first, then explicit imports, wildcard imports and package declarations from
other files. Java ranks local declarations, explicit imports, package
declarations and on-demand imports in that order. Kotlin ranks local
declarations, explicit imports, same-package declarations and star imports.
The shared precedence module supplies each language's ranks and lowering form.

### Typed member lookup

Stack graphs handle type-directed lookups, such as a method call on a value, by
pausing one lookup on the symbol stack while another name resolves. Bifrost's
graph has the same scoped symbols. Receiver types for member access, however,
come from the typed layer:

1. The query evaluates the receiver slot's *type frontier*: the set of types
   the receiver can have. It starts from declared and literal types and follows
   copy rules between slots until the set stops changing. Cycles in the copy
   rules are detected and classified, not cut off silently.
2. For each type in the frontier, the query looks up the member name in that
   type's member scope.
3. If the type does not declare the member, the lookup follows the type's
   hierarchy (supertypes, trait implementations, embedding) and records how
   many steps it took.

Name binding and type evaluation depend on each other. A qualifier must be
resolved before its type is known, and a type must be known before its members
are. Both run inside one query until they reach a fixed point. That state
belongs to the query and is discarded with it.

Some languages let members come from places the rows cannot list. In Rust, a
blanket trait implementation, a derive, a `Deref` target, or a trait from an
unindexed crate can each supply a method. When a lookup's member surface is
open in this way, the answer is an *open boundary*, not a proof that the member
does not exist.

Explicit receiver lookup searches ordered levels lazily. It first runs the
ordinary member search over the original receiver alternatives. An alternative
with no matching member may then ask its language for a derived receiver; the
first level with a member wins for that alternative. Rust supplies a user
`Deref` impl's associated `Target`, evaluated with the receiver's generic
arguments under the calling site's selected configuration. Standard trait
identity must be proved from selected routes, never its written name. An
unproved step retains its candidate with incomplete evidence. A cycle, a
non-singleton Target, or the eight-step limit stops that alternative with a
named incomplete reason. A known active cfg impl wins over unknown alternatives,
which only add incompleteness. Among the remaining alternatives, a common plain
Target may continue unproved. If any remaining Target is a generic application,
the step stops with an ambiguous-generic-Target reason, even when the written
arguments look equal: nominal identity alone cannot prove instantiation equality.
The levels and their visited sets live for one query.

A member's logical name is stored separately from the declaration returned to
the caller. Scala generated apply and extractor members can therefore match
their logical names while returning the case class's primary constructor. A
case class without an authored companion still publishes its companion and
relationship rows, including when nested inside another owner.

For a qualified call, a unique applicable direct member can close open hierarchy
reasons when every supplied argument has a known exact type match after generic
formal substitution. No ancestor can provide a more specific overload. This
proof covers every receiver or companion root offered by origin planning and
its established ancestors; it does not change that planning. Unknown arguments,
conversions, defaults, expanded varargs and multiple applicable candidates do
not establish the proof, and unrelated completion reasons stay attached. The
proof keeps only query-local roots and ancestors and walks them iteratively.

Java overload selection records a verdict for every member candidate it
classifies, including the ones it refuses. A candidate whose arity does not fit
fails potential applicability (JLS 15.12.2.1) before any invocation phase and
records no phase. A strict-invocation test (JLS 15.12.2.2) makes a candidate
applicable, or inapplicable at its first failing argument with the conversion
that argument would need. Among the applicable candidates of one phase, one
that another is strictly more specific than is `less_specific` (JLS 15.12.2.5):
it accepts the call but cannot win, so overload selection counts neither it nor
a refusal. This holds for primitive formals and for reference formals whose
subtype relation is proved; the row comes from the same dominance test that
drops the candidate from the selection.

The phases after the strict one are decided only where the code can decide
them. A candidate that needs boxing is `unknown` when no candidate is strictly
applicable, because the loose phase is then never evaluated, and the site stays
`unknown_shape`. When a strict candidate exists, the loose phase is never
reached, so a boxing-only sibling is refused at the strict phase with reason
`requires_boxing`; the legacy classifier reports it the same way. A candidate
that is applicable only through variable-arity expansion is `applicable` with
phase `variable_arity`. A variable-arity sibling of a fixed-arity applicable
candidate is dropped by phase selection without a row, and its site stays
`unknown_shape`.

A refused candidate's witness leaves the answer, so the check reads its route
before the witness is dropped, and the answer keeps its member owner. The
call's own applicability obligation stays open while the verdicts prove no
unique winner; it describes the selection, not a missing candidate.

Rust inherent implementations can share a nominal head while specializing its
written type arguments, as in typestate APIs. Candidate selection compares
those written patterns with the receiver's recovered arguments. It excludes an
implementation only when a known position proves a mismatch; unsupported or
unknown positions keep the candidate possible. Generic pattern variables must
agree across repeated occurrences. The predicate is tri-state: a mismatch at
any known position excludes, a fully known match admits, and all other cases
remain unknown. The producer stores these facts per source blob and selection
reads them at query time; it does not publish unit summary rows for impl
patterns.

Impl pattern arguments reuse ordinary written type-application argument rows on
the impl relation's subject slot. This preserves nested positions and written
pointer/reference deltas without a separate persisted argument family.

### Rust wrapper identity

Selected resolution decides whether a Rust type is a standard-library wrapper.
It has the crate topology, imports, globs and prelude needed to prove that
identity. The file-local producer cannot make that decision: an import such as
`use std::boxed::Box as Heap` gives the same wrapper a different written name.
It therefore preserves the written head and arguments of every generic declared
type and emits a conditional payload transfer, without filtering by spelling.
A local type named `Box`, `Option` or `Result` keeps its own identity.

The shared evaluator asks the Rust language hook to classify the selected head.
Standard wrapper identity does not require an installed semantic pack.
Workspace aliases use the shared alias walk; an external alias such as
`anyhow::Result` remains an unindexed external boundary until its target can be
proved. Pack-declared aliases are separate work (#7101): a pack may supply an
alias target, but that target must still pass the identity proof.

A wrapper proof discharges only the boundary reasons for the proved standard
item and its route. The payload keeps its own completion, together with any
remaining uncertainty about the head. Without a proof, the analyzer does not
guess the identity from the name. Incomplete candidates follow the general rule
below.

The semantic lowerer runs on one file before selected resolution, so it cannot
use the query-time identity predicate. It uses shared lexical selection through
`RustOwnershipIndex`, including `resolves_standard_path`. When that selection
cannot prove a standard head, lowering keeps the general `?` residual flow,
assigns no standard receiver model owner and makes no conditional `Option`
Copy claim. This preserves uncertainty when a cross-file glob or another
unresolved binding could change the type's identity.

### Reverse search

Finding the references to a declaration works in two steps:

1. Discovery rows list the files that contain a reference looking up the
   declaration's name in a compatible namespace. This is an index seek, not a
   scan of every file.
2. Each candidate file is confirmed by forward resolution in the context of
   each build unit that compiles it. A file that two Cargo targets compile is
   checked once for each target.

Only references whose forward resolution reaches the declaration are reported
as proven. A file's candidates share one confirmation request, because they
share that file's context and the cost of building it.

### Workspace graphs

Whole-workspace usage graphs use the same forward resolution, applied to files
in batches. A point request and a graph build therefore apply the same rules.
The
[Usage Analysis Engine](../usage-analysis/#workspace-graph-and-relevance-ranking)
chapter describes how edges become ranking graphs.

## Completeness and termination

Every answer carries a completion. It is *complete* only when no path that
could produce a different answer was left unexamined within the selection.
Otherwise it is *incomplete* and lists reasons, which include:

- an open boundary, where a route leaves the indexed workspace or reaches a
  member surface the rows cannot list;
- an unsupported construct that the producer recorded as a gap;
- a cyclic expansion that the engine cannot prove finite;
- inconsistent precedence, where the language itself refuses to choose between
  candidates (Rust's error E0034 is an example); and
- reasons that belong to the request, such as cancellation, an exhausted work
  budget, or a route out of a file that no build unit contains.

An incomplete lookup can still supply candidates. Their values continue through
type evaluation while the answer retains the unresolved reasons. One candidate
does not make an incomplete lookup complete; multiple candidates are retained
without preferring a standard-library type. Rust wrapper projection follows
this same rule.

Reasons that come from file content are stored with that file's rows. Reasons
that come from the request are never stored, because they say nothing about
the content.

Reachability in this graph model is undecidable in general: two unbounded
stacks can encode a Turing machine's tape. A worklist that stops expanding a
repeated path has therefore not proved that the search is complete. The engine
accepts a repeat only when it can show that continuing would add nothing new:
the repeated path has the same effect on both stacks as its earlier use, so
the observable state can only repeat. Any other repeat makes the answer
incomplete, and the pruned branch can never support a negative answer.

Work budgets bound how far a search may expand. Cancellation stops it at the
next check. Both produce an incomplete answer, never an empty complete one. The
[Evidence and Result Contract](../evidence-and-results/#positive-evidence-and-authoritative-absence)
states the general rule for absence claims.

## Revision safety

A query holds no lock and no long transaction. It records the inventory it
selected: the revision, producer versions, context publications, and the
content of any live files it mounted. When the search finishes, it checks that
inventory again. If any part changed while the query ran, the answer is
*stale*. The caller reports the engine as unavailable for that request rather
than returning an answer that mixes two states of the workspace. No other
resolver steps in.

The temporary tables that hold a query's working rows belong to its connection
and are cleared when the query ends. Selection-owned mount and context rows
can outlive the query under the reuse rule in [Selection](#selection).

## Memory and storage discipline

The stack graphs paper also persists each file's partial paths at index time,
as one stored list per file. At query time it loads the paths a search needs
and joins them in memory.

Bifrost stores the same per-file content as relational rows, indexed by the
values the search looks up. A query reads only the rows its frontier reaches.
The working state of a query (its mount table, selected context, and the
projections of each search stage) lives in temporary SQLite tables, and the
Rust process keeps only the values of the query in progress. No map, index, or
arena in Rust whose size grows with the workspace survives a query.

This is a deliberate trade-off. A keyed SQLite read costs far more than a
lookup in an in-memory hash table, so the engine batches reads across a whole
frontier and shares work between the references of one file. In return, memory
stays bounded on large workspaces, and the stored rows serve every process and
worktree that opens the cache.

## Comparison with stack graphs

| Topic | Stack graphs | Bifrost |
| --- | --- | --- |
| Unit of reuse | One file version | One blob and producer version |
| Stored form | A list of partial paths for each file | Rows indexed by search keys; shared names interned once per store |
| Build configuration | Not used; analysis is purely syntactic | Per-unit summaries derived from exact configuration bytes, with early cutoff at an unchanged output digest |
| Type-directed lookup | Scoped symbols and a stack of paused lookups | Scoped symbols, plus a typed layer that evaluates receiver type frontiers |
| Missing or ambiguous bindings | Allowed, for code navigation | Allowed, and each answer lists why it is incomplete |
| Query working state | In memory | Temporary SQLite tables and values that end with the query |

## Language status

Migration proceeds by consumer family. Each migrated consumer has one
resolution authority, without a hidden fallback to its previous resolver.
Go definition and type lookup, call targets and evidence, rename, selected
inverse references, target-directed usages, and rooted and whole-workspace
usage graphs use the native engine. Dead-code analysis retains the incumbent
strategy because its package-variable initializer callers are not counted by
the shared native dead-code consumer. The previous Go resolver can be removed
after those remaining consumers move. Kotlin definition and type points use native
resolution; its reference and workspace graph consumers retain the existing
Kotlin edge pass. The incumbent Kotlin point resolver is removed, while
graph-specific name and hierarchy support remains until those graph
consumers migrate. Calls, RQL and policy use the authority of the underlying
consumer.

| Language | Status | Context the language must supply |
| --- | --- | --- |
| Rust | Current | Cargo targets, module trees, editions, `cfg` options, preludes |
| Kotlin | Current for definition/type points; graph migration pending | Source roots, packages, dependencies; shared JVM ecosystem |
| Java, Scala | Direction | Source roots, packages, dependencies; shared JVM ecosystem |
| Go | Current for point, call, rename, target-directed references and workspace graphs | Modules, packages, imports, build constraints |
| JavaScript, TypeScript | Direction | Module resolution and project configuration |
| Python | Direction | Import roots and packages |
| C# | Direction | Projects and their references |
| PHP, Ruby | Direction | Namespaces, autoloading, and constant lookup, with dynamic boundaries |
| C, C++ | Direction | Build commands, include paths, preprocessor configuration |

Adding a language to the engine means writing its producer, which emits
file-local and typed facts from its syntax tree, and its context derivation.
The lowering, storage, selection, and search code is shared. The general
front-end contract is in
[Adding or extending a language front end](../identity-and-language-frontends/#adding-or-extending-a-language-front-end).

## Current decisions and trade-offs

| Decision | Benefit | Cost |
| --- | --- | --- |
| Build each file's graph once per content | An edit rereads one file; worktrees and revisions share graphs | Cross-file work repeats per query |
| Join files at query time | No global graph to keep consistent; any selected revision can be answered | Query latency depends on reading only what the search reaches |
| Store graphs as rows read by key | Bounded memory; reuse across processes and worktrees | A keyed read is slower than an in-memory probe, so reads must be batched |
| Read build configuration | Routes mean what the compiler would make them mean | Context derivation per language; membership changes rerun the full pass |
| Recompute a unit and cut off at an unchanged output digest | No delta maintenance of recursive relations; a body edit reaches no dependent | Any change inside a unit re-derives the unit's whole surface |
| Optimize warm requests over cold start | Fast repeated requests in a long-lived process | Indexing does more work up front |
| Report completion with every answer | Absence is claimed only when the search finished | More answers are reported as incomplete |
