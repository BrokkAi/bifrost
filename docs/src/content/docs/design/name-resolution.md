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
> moves onto. Rust uses it in production. Java, Kotlin, Scala, and Go have
> producers and test-only resolvers; their production switch is in progress.
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

The mount table stays with the pooled connection after the query ends. A later
query that selects the same revision reuses it, which makes the warm path a few
statements instead of a rebuild. The connection discards the table when anything
else has written to it.

A query can narrow which mounts a name may bind into. A forward Rust lookup,
for example, binds only into the crates that the referencing crate can see. A
gap in an unrelated crate cannot hide a candidate, so it cannot make the answer
incomplete.

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
and are cleared when the query ends. Only the mount table can outlive the query,
under the reuse rule in [Selection](#selection).

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

Each language moves onto this engine as a whole. Definition and type lookup,
forward and reverse usages, calls, rename, workspace graphs, missing-test and
dead-code analysis, relevance, RQL, and policy all switch to it together, and
the language's previous resolver is then removed. No language runs two
resolvers with a hidden fallback between them.

| Language | Status | Context the language must supply |
| --- | --- | --- |
| Rust | Current | Cargo targets, module trees, editions, `cfg` options, preludes |
| Java, Kotlin, Scala | Direction | Source roots, packages, dependencies; one shared JVM ecosystem |
| Go | Direction | Modules, packages, imports, build constraints |
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
