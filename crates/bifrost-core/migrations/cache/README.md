# Unified cache migrations

`0125-baseline.sql` is the complete cache schema and the permanent compatibility
floor. Stores below schema 125 are rebuildable derived state: startup does not
import them, and removes their database, SQLite sidecars, and analyzer-build
lock after it proves the store idle. A valid schema-125 store is upgraded.

To change the cache schema, add one numbered SQL file beginning with 0126 and
one corresponding entry to `POST_BASELINE_MIGRATIONS` in `src/cache_db.rs`.
Migration SQL must contain only schema and data changes, terminate statements
with semicolons, and omit transaction control and connection PRAGMAs. All
pending entries run in one transaction.

Regenerate and verify the baseline and forward chain with:

```console
python3 scripts/public/generate-cache-schema.py
python3 scripts/public/generate-cache-schema.py --check
```

Regeneration verifies the SQL artifacts; it does not update Rust's pinned
`CURRENT_SCHEMA_OBJECTS_SHA256`. Move that constant with the migration and
verify `cache_db::tests::current_schema_digest_matches_the_baseline_chain`
as well, so fresh-store and upgrade validation accept the generated schema.

Keep the generator's baseline and current version constants in sync with
`cache_db.rs`. Never edit a released migration and never add a down migration.
A comment-only edit to the baseline is the one exception (owner decision,
2026-09-29): SQLite keeps CREATE text verbatim, so such an edit moves
`CURRENT_SCHEMA_OBJECTS_SHA256` and nothing else; update the constant in the
same commit.

Migration `0126-policy-evaluation-per-policy.sql` replaces whole-policy-set
diff-base answers with independently qualified policy children. It discards
legacy aggregate evaluation rows because they cannot prove per-policy
completion or provenance, while preserving separately keyed policy units.

Migration `0142-policy-unit-content-identity.sql` records the content identity
of the workspace snapshot whose name-index answers each policy unit read, and of
the base each evaluation analyzed. A unit's name-index reads are verified only
against what moved since that snapshot, so older units, which cannot prove
their snapshot, are discarded with the evaluations that name them.

Migration `0147-resolved-file-import-edges.sql` adds the durable, indexed
workspace file-import graph and its provenance and route-dependency rows.
Migration `0148-incremental-file-import-edges.sql` adds source identities and
route dependencies used to carry unaffected edges across content generations.
Migration `0149-structured-import-candidate-dependencies.sql` adds indexed
consulted-file/name and missing-module dependencies for precise Rust
resolution invalidation.
Migration `0150-import-ordinal-edge-facts.sql` retains resolved edge facts per
import ordinal while keeping the indexed query-facing adjacency deduplicated.
The candidate dependency indexes now return exact importer/ordinal pairs, and
source rows record whether candidate dependencies are complete so mixed
language workspaces can retain conservative full-rebuild behavior.

Migration `0151-name-granular-import-dependencies.sql` stores normalized Rust
binding-surface rows, indexes candidate and route dependencies by consulted
file and name, and records glob dependencies separately. Body-only edits can
carry dependent import rows forward when the file's binding surface is stable.

Migration `0154-cpp-base-access.sql` persists C++ base access specifiers and
widens the C++ source-facts version checks to admit version 2 after the
upstream 0147-0153 import-graph migrations.

Migration `0155-rust-crate-member-paths.sql` separates a Rust crate member's
semantic identity from the source paths that realize it, preserving distinct
routes when identical source blobs are included from multiple paths.

Migration `0156-target-scoped-rust-gap-candidates.sql` stores Rust reverse-gap
candidate names with name-leading indexes so target completeness reads visit
only gaps and type-alias segments whose structured source can name the target.

Migration `0158-rust-module-self-imports.sql` preserves Rust module self-import
bindings in the derived export and module views.

Migration `0159-rust-generated-attribute-surfaces.sql` records whether a Rust
declaration has an unexpanded derive or attribute surface, allowing crate route
inventory to preserve the producer's structured boundary reason.

The Rust flag-day baseline also includes master's class-object and unmodeled
predicate reasons, guard-only class evidence, and C++ indirect field-binding
evidence. These are part of the single baseline, with no rehearsal migration
chain to retain.

Migration `0143-parse-completeness.sql` marks C and C++ blobs as partial when
the parser recovers an outer declaration from an incomplete parse.

Migration `0144-structural-recovered-regions.sql` stores byte ranges for
recovered declarations and structural regions in incomplete parses.

Migration `0145-native-declared-type-arguments.sql` stores positional type
arguments on declared type syntax so generic receivers can substitute callable
results through their selected owner.

Migration `0146-native-kotlin-jvm-facts.sql` stores shared Kotlin and Scala
source facts and JVM aliases used to project declarations to binary names.

Migration `0157-resolution-unit-summaries.sql` adds the language-neutral
per-unit resolution summary: a header, a revision-interval version table, and
member, dependency, read, export, import and gap child tables. Export rows carry
optional alias dependency and target identity fields for Go type aliases and
later language re-exports; the Go output digest folds their stable target data.

Migration `0160-kotlin-package-reference-choice.sql` stores Kotlin's selected
package-scope choice on package-reference rows.

Migration `0161-shared-package-reference-token.sql` permits one package lookup
token to identify multiple source-reference rows while keeping each reference
and namespace unique.

Migration `0162-generic-formal-positions.sql` stores generic declaration
formals as ordered owner/declaration rows and seals their count with each
resolution fragment. Go is the first producer to populate the language-neutral
family. It also adds shared Slice and Array type-component constructors, first
emitted by Go and available for later producers to adopt.

Migration `0163-kotlin-scala-named-argument-labels.sql` stores positioned
named-argument labels from the Kotlin and Scala producers, keyed to their call
and reference sites.

Migration `0164-php-include-path-kinds.sql` admits folded and dynamic PHP
include/require paths in canonical source import facts.

Migration `0165-semantic-ir-rows.sql` stores the lowered semantic IR of a blob
whose adapter lowers at parse time (Rust first) as rows keyed by blob: the
`semantic_ir_publications` head with its outcome and producer epoch, the
per-language `semantic_ir_producer_epochs`, the blob's interned texts,
declarations and locators, and one child table per IR element (procedures,
values, allocations, memory locations, captures, call sites and their
arguments and target groups, source mappings, statement entries, loop sites,
evidence, gaps, blocks, points, events and their five payload tables, control
edges, guard and switch facts and cases, lifecycle and pointer facts,
incomplete facts, and call receiver type facts). Deleting or republishing the
blob removes the rows through the head's foreign key.

Migration `0166-rust-reason-owner-source-site-index.sql` indexes Rust
declaration authority by its source site so selected gap reasons can resolve
their owning declaration without scanning all declarations in a blob.

Migration `0167-semantic-ir-partial-flows.sql` stores each procedure's partial
flows, computed from its semantic IR rows at parse time: the procedure's ports
(receiver, parameters, returns, capture slots, call receivers, arguments,
results and thrown values, and heap access paths rooted at an input port), the
port-to-port flows, and a per-procedure head with openness and the discharged
gaps. The rows cascade from the blob's publication like the 0164 rows.

Migration `0168-rust-derive-helper-attributes.sql` replaces the serde-only
declaration property with the JSON array of conditional derive-helper attribute
names.

Migration `0169-go-rename-import-declaration-range.sql` indexes the Go import
declaration byte range used to join selected import binders to source imports.

Migration `0170-go-package-unit-key.sql` stores each Go package row's unit key
and indexes it by context, so the reverse qualified-import read seeks the
package an import names instead of computing every package's key. It also
indexes package rows by context and for-test path, so the candidate target read
seeks the test variants of a target. It clears
derived Go contexts, which the producer republishes on demand, because an
added column cannot hold keys for rows that predate it. The column's zero-byte
default only satisfies NOT NULL on the emptied table: a CHECK rejects it, so a
writer that omits the key fails at insert time. The Go context derivation
version moves with it.

Migration `0171-semantic-ir-partial-flow-crossed-calls-and-relation-proof.sql`
records, on each partial flow, the call sites its paths crossed: one set per
distinct path class, as a positional JSONB array of arrays of call-site ids.
It also records, on each partial-flow head, whether every relation of the
procedure's value-flow snapshot is proven complete, the fact the composition
checks before any gap. The defaults only fill rows written under previous rows
versions, which no reader serves.

Migration `0172-root-import-activation-ordinal.sql` adds a nullable
`activation_ordinal` to `resolution_paths`. A positional root import (Scala)
stores the source position at which it takes effect, and the selected import
context consumes one blob's imports in that order. Other producers store NULL.

Migration `0173-rust-unit-summary-rows.sql` is create-only. It adds the Rust-owned
`rust_resolution_unit_summary_*` tables that hold placement, route, macro and typed
facts keyed to the shared per-unit summary rows. It also adds an index for
resolving effective bindings by summary, module, name, and namespace. It moves
no data and changes no shared table.

Migration `0174-jvm-external-owner-inventory.sql` adds durable external
declaration inventories for JVM resolution, recording member and supertype rows
plus completeness for each member namespace.

Migration `0175-contextual-callable-parameter-lists.sql` adds a normalized
contextual flag to callable parameter-list rows. Scala marks implicit and
using lists; the shared applicability mapper skips omitted contextual lists
while aligning explicit argument lists.

Migration `0177-resolution-member-owner-name.sql` stores the logical spelling of
each member-owner row so shared JVM member selection can match synthesized
members without relying on a source CodeUnit's display name.

Migration `0179-generic-formal-defaults.sql` adds owner/position/default-slot
rows and their publication count. Rust impl patterns reuse ordinary written
type-application argument rows, including pointer/reference deltas.

Migration `0182-summary-profile-validity.sql` keys shared unit-summary intervals
by context profile. Go reconciliation can now retain inventory and tool
summaries at the same workspace revision. It invalidates pre-upgrade Go
intervals for normal reconciliation to rebind, preserves other languages'
intervals, and extends Rust's foreign key with its singleton zero profile.

Migration `0183-go-struct-field-tags.sql` publishes byte-exact decoded Go struct
tags beside ordered field names, types and embeddedness. The Go extraction,
context and summary identities rebuild older field inventories. The nullable
column preserves publication format 1 and its matching blob requirement.

Migration `0184-rust-macro-input-cfg.sql` retains each macro input's effective
source cfg predicate, including ordered cfg_if arm guards. Selected contexts
discharge only proven-inactive frontiers; migrated inputs default to unknown
until the Rust source epoch forces a fresh publication.

Migration `0185-static-type-object-transfers.sql` preserves transfer rows and
both indexes while admitting value-transform code 8. StaticTypeObject converts
a runtime operand to the type object of its static type; Java qualified creation
uses that qualifier separately from its enclosing runtime instance.

Migration numbers are increasing, not necessarily contiguous. The generator
permits gaps in its numbered forward files, matching the runtime registry, so
an independently allocated later migration does not invent a placeholder for
another lane. Register each file in `POST_BASELINE_MIGRATIONS` as usual; the
cache schema parity tests compare that registry with the generated snapshot.

Migration `0187-rust-crate-public-module-reachability.sql` records the
canonical target modules exposed by a completed crate topology's fully public,
unambiguous module paths. The composite primary key deduplicates multiple
public aliases and supports exact membership proofs by topology, crate key,
and module path.

Migration `0188-declaration-access-boundaries.sql` stores explicit package and
lexical-template access regions as normalized source declaration rows. The native
bridge view exposes the canonical template owner, while publication manifests
and validation retain the boundary family alongside coarse visibility.

Migration `0193-class-set-owner-storage-identity.sql` separates the semantic
language of class-set rows from the physical dialect of their owner blob. It
preserves parent IDs, children, generation constraints and cascades while
binding the owner through `blobs.id`. Root-result attachment accounting retains
the exact storage key once, without changing semantic output digests.

Migration `0197-rust-expanding-attribute-contexts.sql` adds a positional JSONB
array of start bytes to each Rust source context, recording the attributes that
may expand to code. A NULL array belongs to a row published before this
producer and proves nothing; the Rust source epoch republishes it. An empty
array proves that the context has no expanding attribute.

Migration `0198-jvm-package-private-visibility.sql` rewrites legacy JVM
inventory visibility labels from `package` to the canonical
`package_private` label.

Migration `0210-cpp-namespace-aliases.sql` publishes C++ namespace aliases as
typed per-blob source facts: one row per definition (occurrence, name, target
presence and global marker, enclosing block, guards as a positional JSON
array) plus ordered target and enclosing-namespace path components. It extends
the C++ fact-cost view and the manifest's density checks to the new rows. The
C++ source epoch rotates with it, so blobs published before carry no alias
rows only until they are reparsed.

Migration `0211-procedure-dispatch-site-ordinal.sql` adds `site_ordinal` to the
three tables that persist procedure-dispatch read keys. It names one call among
the procedure's call rows at the same relative interval, which lowering can
produce several of (a Python `finally` body per exit path). Units, summaries
and surfaces that recorded the previous key are discarded and recomputed.
