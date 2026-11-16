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

After merging the latest `origin/master` into a branch that adds a migration,
including the last merge before marking it ready, run `node
scripts/public/check-migration-landing-order.mjs --base origin/master --head
HEAD`. A run after the pull request lands sees its migration in the base and
proves nothing. Before publishing a batch, merge agents must run the
check through `mm-db run` with mm-db's `base_sha` and the candidate head, and
keep the receipt. On exit 1, renumber the offending migration to the base's
highest version plus one, updating its file, `POST_BASELINE_MIGRATIONS`, and
other references such as `current-schema.sql` when applicable; record the
renumber in the batch notes. On exit 2, do not publish the batch. If an error
is found after landing, never renumber or delete the landed migration; add a
new higher migration that repeats the skipped migration's whole effect safely
on stores that already applied it: its DDL guarded by schema checks or `IF NOT
EXISTS`, and for data it changed, clearing the affected cache rows so they are
rebuilt, never re-applying a transformation. The `verify_upgraded_store`
function in `src/cache_db.rs` checks only that an upgraded store's schema
matches; confirm a data repair separately, for example with an upgrade test
that reads the affected rows.

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

In `source_structural_facts`, `roles[2]` stores the argument mode (#9773):
0=plain, 1=spread, 2=ref, 3=out, 4=in. The generated `current-schema.sql`
cannot carry hand-written comments, so the encoding is recorded here.

Migration `0279-semantic-ir-publication-row-digest.sql` adds a nullable digest
of the final sealed publication rows. Legacy heads remain NULL until republished;
the source content digest retains its existing meaning. It also rebuilds both
general read ledgers with a structured stored-IR publication question. Existing
read rows and IDs survive the rebuild. The restricted procedure-surface ledger
is unchanged.
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

Migration `0218-policy-unit-snapshots.sql` replaces that single identity with
`policy_unit_snapshots`, one row per snapshot a unit's name-index answers are
attested on. A check that verifies a unit adds its head (and its base, when no
probe names a moved name), so a chain of checks, each based on the previous
head, keeps verifying the unit instead of recomputing it.

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

Migration `0278-semantic-ir-call-control-coverage.sql` stores scoped call/control coverage separately from full-footprint admission.

Migration `0277-semantic-ir-footprint-coverage.sql` stores normalized callee footprint coverage witnesses. It is numbered above the already-landed 0275 so existing stores apply it during upgrade.

Migration `0275-resolution-site-prefix.sql` records a reference's proved root
prefix on its site row. A local semantic key names the prefix, -1 proves none,
and NULL means the producer has not published prefix evidence. Existing rows
remain NULL until the resolution bundle producer epoch rebuilds their interiors.

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

Migration `0213-drop-redundant-reverse-gap-site-index.sql` removes the redundant Rust
reverse-gap site index. The WITHOUT ROWID primary key already serves its
`(blob_id, site)` lookups with the same covering columns.

Migration `0215-sample-seal-validation.sql` samples per-blob publication
consistency checks through the writer's deterministic `bifrost_seal_validates`
SQL function. Tests and `test-support` builds validate every blob; production
validates blob IDs divisible by 64, or every blob when
`BIFROST_SEAL_VALIDATION=all` is set before the first decision. Immutability and
publication state-order guards remain unconditional. Every writable store
connection must register the function; a missing registration fails the seal.

Migration `0222-field-slot-exact-result-sources.sql` rebuilds the field-slot atom
table while preserving its rows, primary key, foreign key and checks. It admits
exact call and access result sources so complete factory-backed inventories
can be published and replayed instead of failing schema validation.

Migration `0231-policy-evaluation-replay-evidence.sql` records nullable
per-policy and aggregate effective grants and certified source censuses.
The aggregate also records whether its evidence was complete. Legacy rows
remain readable but have no replay evidence.

Migration `0256-directional-channel-components.sql` admits append-only channel
constructor codes 5-7 with one Element component while preserving legacy code 2
as direction-unknown historical evidence. It rebuilds only the component table,
copying existing rows and restoring its original keys, foreign keys and index.

Migration `0260-python-import-module-operands.sql` stores structured import
module operands so Python demand can resolve imports from their selected source
reference.

Migration `0261-python-module-registry-writes.sql` records source observations
of module-registry writes for demand-time authority checks.

Migration `0262-python-source-root-spellings.sql` records lookup spellings for
canonical Python providers without creating new module identities.

Migration `0264-candidate-fq-publication-witness.sql` adds a per-publication
witness and a database lineage nonce for bounded relational candidate memos.
The FQ segment seal prevents edits to completed publications. A future
`blob_meta` rebuild must preserve the witness and sequence.

Migration `0276-configuration-input-presence.sql` distinguishes absent configuration probes from present empty files; legacy empty rows remain unvalidated.

Migration `0283-csharp-compilation-open-reasons.sql` rebuilds populated C#
compilations to admit four registered open reasons while preserving their
columns, rows, constraints, and child foreign keys.

Migration `0285-structural-role-name-inventory.sql` stores role and keyword
columns for exact structural role-name inventory reads in both general ledgers.
Existing read rows and IDs survive the rebuild.

Migration `0286-g3-guarded-pattern-projections.sql` adds bounded, inert Rust
pattern candidate rows and ordered tuple/named field steps to semantic IR
publications. A candidate keeps its Values gap until selected declaration
authority admits it; the store records no admitted value effect.

Migration `0290-semantic-ir-static-type-classes.sql` adds static value classes and ordered declared result classes. Compatible: additive rows and columns, and versioned store filenames exclude mixed-version writers.

Migration `0291-rust-crate-path-probes.sql` adds `rust_crate_path_probes`, the
case-folded paths each Rust crate topology's derivation consulted: module-walk
candidates, naming probes and the target root. A created or deleted path
reaches exactly the crates that probe it. Compatible: it only adds a table that
older readers ignore.

Migration `0292-definition-index-inventory.sql` adds full-membership definition
name indexes and replaces the subsumed declaration and lookup partial indexes.
File projections own anchored names and nullable completeness evidence; legacy
and replacement file versions start unknown until publication supplies evidence.
A file version becomes known only in a transaction that proves its blob complete
and ready; NULL fences legacy rows. Compatible: the new columns are nullable,
NULL reads as unknown, and versioned store filenames exclude mixed-version
writers.

Migration 0292 indexes unknown definition-inventory state only for source file versions; configuration versions retain NULL because that state does not apply to them.

Migration `0299-rust-inventory-name-reads.sql` rebuilds both general read ledgers
to admit the three Rust inventory families as Rust-only Name questions. Compatible:
all existing rows, IDs, indexes and foreign keys are retained; no answer meanings
change, and versioned filenames exclude older writers.

Migration `0299-rust-inventory-name-reads.sql` also admits Rust bound-trait
impl inventory questions. These store the placed declaration as a blob OID,
workspace-relative path and a u32 declaration ID in both scalar interval
columns. The language must be Rust and unrelated question columns must be NULL.

Migration `0299` also admits `rust_traits_implemented_by_inventory` with the
bound inventory placed-declaration shape and `rust_alias_blob_inventory` with
the Rust name inventory shape, in both read ledgers.

Migration `0299` also admits `rust_macro_expansion_inventory` as a strict Rust
Name question in both ledgers. Each requested spelling records its own selected-live,
sorted distinct (blob OID, via) answer in a versioned domain. Publication readiness
is required; unknown placement is included and refusal is unavailable evidence.

Migration `0311-rust-unit-summary-context-lookups.sql` adds crate-name and
module/scope import-route indexes for the summary-backed context readers
(#11173). Compatible: indexes only, with no row or answer changes.
Migration `0314-candidate-macro-semantic-ir.sql` adds isolated candidate-macro
alternative IR and partial-flow rows. Their typed columns mirror the ordinary
semantic IR tables; candidate call IDs name the alternate call table. The
ordinary decoder does not enumerate these relations. Every alternative belongs
to the base semantic-IR publication through cascading foreign keys, including
procedure-owned rows whose parent in turn belongs to that publication. No
existing publication or base row is rewritten.

Migration `0338-cleanup-chains.sql` adds procedure-local immutable cleanup
nodes, ordered action and owner entries, and segment anchors, including candidate
macro mirrors. SQL row IDs are distinct from dense procedure-local arena IDs;
NULL chain references denote the empty sentinel. Node/ordinal uniqueness and
nonnegative ordinals are checked in SQL; publication and hydration validate
complete dense arenas, parent ordering and ancestor stops. Actions reuse the
existing typed-place, destructor-resolution, source/evidence and reason codecs.

The M1 cleanup relations include canonical projections and ordered projection
members in both ordinary and candidate-macro mirrors. Owners retain typed places
and optional complete invalidation targets. Anchors retain four direct-row
ordering offsets and an optional projection. Action incompleteness retains its
own evidence independently of action evidence.

Migration `0369-policy-evaluation-selection-reads.sql` adds
`policy_evaluation_reads`, the membership of the selection-authority reads an
aggregate policy evaluation consumed (#11482). Rows reference the same
`policy_read_keys` interning that policy units use, and cascade with their
evaluation. Compatible: one new table and index, with no existing row rewritten.
Rows written before it carry no reads and are retired by the policy substrate
epoch, which is part of every evaluation key.

Migration `0402-policy-unit-operands.sql` is compatible. It rebuilds
`policy_units` without changing existing unit IDs, keys, JSONB products or
referencing child rows. Only a seedless `operand` partition carries the new
question digest; the uniqueness key includes it and legacy partitions keep its
empty default. The existing Prefix product stores the typed operand output;
output-bound continuation Prefix keys retain final Rows products. Operand keys
require Prefix products, and Prefix products require Prefix or Operand keys.
Versioned store filenames exclude mixed-version writers. Existing policy key bytes
and root-cut bindings are unchanged. The same-root 08e4 master-warm/head-cold
control matches all three ordinary retained products and complete work objects
after preserving legacy inventory charges and ownership rules. No policy
substrate token is needed.

Migration `0404-evaluation-selection-tree-part.sql` records what an aggregate
policy evaluation's selection reads were taken over (#11607). It adds
`policy_evaluations.selection_export_tree` (the tree id of the revision export
the analyzer was built over, NULL for a live worktree),
`policy_evaluation_reads.basis_platform_override` (non-NULL when the read was
recorded with the tree part of a JVM dependency selection) and
`policy_evaluation_read_coordinates`, one row per declared coordinate with its
scope and declaring target, which cascades with its read. Compatible: two
nullable columns and one new table, with no existing row rewritten. Rows
written before it have no view, so they are treated as taken over a live
worktree, and no read carries a tree part.

Migration `0409-cleanup-owner-gap-subject.sql` extends ordinary and candidate gap
rows with subject tag 8 and nullable cleanup segment head/stop natural-key references.
Shared arena validation checks ancestry on hydration.

Migration `0410-candidate-macro-records.sql` (#11251) rebuilds
`candidate_macro_semantic_ir_candidates` as source-anchored candidate records:
`anchor_start`/`anchor_end` (a lookup index inside one blob's artifact; digests,
receipts and read keys never use offsets), `base_call` (the base call the
invocation replaces; an invocation nested in an opaque candidate's operands names
the nearest enclosing base candidate call), `realization` (`call`, `intrinsic` or
`lexical_no_items_introduced`) and `alternate_call`, which is set exactly for
`call` (CHECK). Rows only, no blob. Breaking: old rows hold only an alternate
call and cannot supply an anchor or base call, so the table is rebuilt empty. An
old reader would read intrinsic rows as calls, so compatibility rests on the IR
schema and rows versions that move with this migration: the producer epoch of an
older publication no longer matches, its head is not valid, and the blob is
republished.

Migration `0411-store-publication-lineage.sql` preserves installed allocator
identity while making the nonce nullable for reusable empty templates. Store
constructors mint once before returning publication authority. Versioned imports
from a still-live source mint a distinct destination namespace in their private
staging transaction.
The generator also writes `publication-lineage-nonce-guard.sql`, the identical
nonce guard restored before any imported destination is published.

Migration `0418-python-member-any-writes.sql` is COMPATIBLE: index-only, so older
readers are unaffected and SQLite maintains it for rows an older daemon writes.
It advances the current revision without changing the minimum compatible revision.
0418 is provisional until the final pre-Ready merge.

Migration 0419 replaces seven derived certificate version columns with raw
32-byte lever identities, withdrawing derived rows before changing their types.

Migration `0447-rust-macro-type-candidates.sql` is breaking: older readers do not
enforce selected macro identity and all-element agreement. It stores only
source-local candidate slots and path segments, separately from certified
structural type productions.

The 0447 candidate header also records lexical import interference as a checked
Boolean source fact. Named imports, unclosed globs and attributed imports block
standard-macro fallback certification at the invocation.
Migration `0420-rust-drop-inventory-read-keys.sql` adds typed Drop inventory
questions to both general read ledgers. The five scalar columns are present
only for rust_drop_inventory lookups. It also widens both semantic IR gap
CHECKs for ImplicitDropExecution. Existing rows and IDs survive the rebuilds.
The new discharge arm is reader-breaking: older row decoders reject it.
Version-suffixed store files and the transactional user_version check exclude
older readers without raising the oldest importable cache version.

Migration `0421-rust-async-body-execution.sql` widens the semantic IR
vocabularies for deferred-body construction and activation, memory
interference, and the DataDependency discharge code. It rebuilds the affected
IR tables while preserving every retained row and ID. The new tags are
reader-breaking: older row decoders reject them, and the version-suffixed
store files and user_version check fence those readers without raising the
oldest importable cache version.
