# Add a durable content-addressed semantic-pack catalog

This ExecPlan is a living document. The sections `Progress`, `Surprises &
Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to
date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost can already compile a semantic-model pack into a canonical manifest and
independently verified shards, but those artifacts disappear when the caller
drops the returned Rust value. After this work, callers can install the same
pack from multiple workspaces or sources and pay for each immutable payload only
once, discover candidate shards from indexed selectors without reading shard
payloads, activate only completely verified packs, inspect storage and usage
accounting, and safely collect unused packs without removing embedded, pinned,
active, or leased content.

The behavior is observable through a persistence integration test that opens
two workspaces against one shared catalog root, concurrently installs identical
compiled bytes, finds the same candidate by package selector, records distinct
workspace activation references, corrupts the stored object and observes a
quarantined miss, then runs garbage collection and proves that protected packs
survive while an unreachable pack is removed. An ignored measurement harness
will compare inline SQLite BLOBs with content-addressed files and record the
threshold and compression evidence used by production storage.

This issue stops at catalog selection and lifecycle. It does not build the
generation-scoped matcher, add synthetic declarations to analyzers, download a
registry, or query SQLite for each syntax node. Those runtime responsibilities
belong to issues #1147 and later children of #1144.

## Progress

- [x] (2026-07-31 06:30Z) Refreshed the branch, remote, issue #1146, its closed
  #1145 dependency, the #1144 epic, and the #817 lifecycle policy.
- [x] (2026-07-31 06:30Z) Diagnosed the compiler/catalog boundary, existing
  workspace cache migration and read-only machinery, current Git-reachability
  GC, semantic-pack producers, test harnesses, and recent history.
- [x] (2026-07-31 06:30Z) Drafted this implementation plan with the shared
  catalog, workspace-reference, atomic publication, quarantine, accounting,
  lease, GC, and measurement boundaries fixed.
- [x] (2026-07-31 07:06Z) Implemented and ran the release storage prototype,
  retained raw and DEFLATE evidence, and selected a zero-byte inline threshold
  because the 8 KiB candidate failed the preregistered cold-read gate.
- [ ] Implement the durable catalog schema, atomic content-addressed
  installation, selector lookup, verified loading, quarantine, and accounting.
- [ ] Implement session-only embedded/ephemeral entries, workspace active-set
  references, durable activation scopes, leases, and garbage collection.
- [ ] Complete migration, read-only, downgrade, corruption, concurrency,
  documentation, packaging, policy, and featureless Rust validation.

## Surprises & Discoveries

- Observation: The schema/compiler dependency already provides more of the
  trust boundary than the issue's original starting points imply.
  Evidence: `decode_manifest` verifies canonical bytes, schema version, limits,
  declaration inventories, and manifest digests, while
  `decode_shard_for_manifest` verifies the stored and uncompressed bytes and
  requires the duplicated shard envelope to match its manifest.

- Observation: Manifest routing keys are intentionally coarse and omit version,
  target, configuration, and artifact-digest constraints.
  Evidence: `semantic_model::artifact::routing_keys` emits exact package,
  module, toolchain, and trigger-kind strings only. The catalog must therefore
  persist normalized activation-selector columns during installation rather
  than claim that routing keys alone implement compatible selection.

- Observation: The unified analyzer database is workspace-local and cannot be
  the sole semantic-pack payload store.
  Evidence: `gitblob::cache_db_path` resolves beneath the primary repository's
  `.bifrost/cache`, while #1146 requires identical payloads to deduplicate
  across unrelated workspaces.

- Observation: Existing analyzer GC protects Git blob OIDs, not semantic-pack
  sources or readers.
  Evidence: `AnalyzerStore::gc_with` and `cache_gc::run_gc` determine liveness
  from repository refs and working-tree content; there is no representation for
  embedded content, pinning, active pack sets, or reader leases.

- Observation: Broad multi-target Bifrost navigation calls exceeded the
  interactive request budget during planning, while narrow calls completed in
  milliseconds.
  Evidence: one `get_summaries` call cancelled after 13.1 seconds and one
  `get_symbol_sources` call cancelled after 10.9 seconds; single-symbol source
  calls returned in roughly 7-11 milliseconds.

## Decision Log

- Decision: Use a separate shared catalog root containing `catalog.db` and an
  `objects/sha256/` tree, while adding only active-set identity and references
  to each workspace's existing unified cache.
  Rationale: A workspace database provides the right invalidation boundary but
  cannot deduplicate immutable payloads across workspaces. A global catalog
  alone cannot replace workspace-local activation identity. Keeping both roles
  explicit also prevents SQLite from becoming the runtime matcher.
  Date/Author: 2026-07-31 / Codex

- Decision: Require the analysis-library caller to pass the shared catalog root
  explicitly.
  Rationale: The library is embedded by several hosts and should not silently
  choose platform-specific user directories. A later host or distribution
  layer can resolve configuration and pass one stable root; tests can share a
  temporary root without mutating process environment variables.
  Date/Author: 2026-07-31 / Codex

- Decision: Key manifests by their manifest `content_sha256` and physical shard
  objects by `stored_sha256`, with a many-to-many manifest-to-object relation.
  Rationale: The manifest content digest binds its complete catalog view, while
  the stored digest names the exact raw or compressed bytes on disk. This
  permits identical physical bytes to deduplicate even when multiple sources or
  manifests reference them without conflating semantic and transport identity.
  Date/Author: 2026-07-31 / Codex

- Decision: Represent durable origins in a separate source table rather than a
  single origin column on a pack.
  Rationale: The same manifest may arrive as a generated, explicitly installed,
  or pre-shipped pack. Deduplication must retain every source and pin while
  storing the payload once; activation accounting must still report the source
  that won selection.
  Date/Author: 2026-07-31 / Codex

- Decision: Keep embedded release resources and ephemeral-workspace packs in
  the catalog instance's validated session view rather than copying them into
  the durable catalog.
  Rationale: Embedded bytes already live in the release, and ephemeral
  workspace output must disappear with the session. The selector and accounting
  APIs should merge session and durable candidates uniformly, while durable GC
  can never remove bytes it does not own.
  Date/Author: 2026-07-31 / Codex

- Decision: Publish external object files before committing catalog rows, using
  a unique staged file, file synchronization, no-clobber atomic persistence,
  and an immediate SQLite transaction for all metadata.
  Rationale: A crash may leave an unreferenced object file that reconciliation
  can delete, but it must never leave a committed pack or activation pointing
  at a missing partial file. Concurrent installers either publish the same
  verified bytes or reuse the winner's exact digest-named object.
  Date/Author: 2026-07-31 / Codex

- Decision: Persist complete normalized activation selectors and use SQL only
  for exact language, ecosystem, selector-kind, and selector-name narrowing.
  Apply SemVer, toolchain, target, configuration, artifact-digest, and Bifrost
  compatibility checks in Rust over those catalog rows.
  Rationale: SQLite has no trustworthy SemVer implementation, but loading shard
  payloads merely to discover compatibility would violate indexed selection.
  The normalized catalog rows provide bounded candidates without making SQL the
  semantic authority.
  Date/Author: 2026-07-31 / Codex

- Decision: Permanently quarantine invariant failures such as missing bytes,
  digest mismatch, unsupported schema, impossible sizes, or failed defensive
  decoding. Treat request-specific incompatibility as a reported, counted
  selection miss rather than permanently disabling the pack.
  Rationale: Corruption is independent of the caller and must disappear from
  future candidate results. Compatibility can legitimately change with a
  different Bifrost version, toolchain, target, or configuration; persisting it
  as global corruption would be incorrect.
  Date/Author: 2026-07-31 / Codex

- Decision: Use durable activation scopes and expiring reader leases as
  separate protections.
  Rationale: An activation records a workspace's selected model set across
  process restarts. A lease protects a concrete reader between selection and
  hydration, including while GC is running. GC may delete a pack only when it
  has no embedded ownership, durable source pin, activation, or unexpired lease.
  Date/Author: 2026-07-31 / Codex

- Decision: Make the inline payload threshold a catalog option and choose the
  production default only from the checked-in ignored benchmark.
  Rationale: The issue explicitly asks for measurement rather than an assumed
  all-BLOB or all-file layout. A configurable threshold lets the benchmark
  compare the same implementation at zero, candidate, and effectively
  unlimited thresholds before the result becomes a constant.
  Date/Author: 2026-07-31 / Codex

- Decision: Set the production inline shard threshold to zero bytes; keep every
  shard payload in the digest-addressed object tree.
  Rationale: The retained macOS/aarch64 release benchmark included one raw and
  five compiler-compressed sizes. Although inline storage passed install and
  total-byte gates, the 952-byte and 4,921-byte DEFLATE shards improved verified
  cold-read medians by only about 5.9% and 5.4%, below the required ten percent.
  Larger candidates inherit those failures, and file reads were already faster
  at 18,329 and 142,478 stored bytes. The compiler's existing DEFLATE decisions
  reduced stored bytes by about 78% to 85% and remain unchanged.
  Date/Author: 2026-07-31 / Codex

## Outcomes & Retrospective

Milestone one established the physical payload decision. The ignored release
benchmark passed at Bifrost `91357eec` and selected a zero-byte inline threshold,
so production shard bytes will live only in the content-addressed object tree.
The evidence is retained in
`.agents/docs/semantic-pack-catalog-storage-benchmark-2026-07-31.md`. The
durable catalog and lifecycle implementation remain.

## Context and Orientation

The public semantic-model code lives under
`crates/bifrost-analysis/src/analyzer/semantic_model/`.
`model.rs` defines authored packs and activation selectors. `compiler.rs`
validates and normalizes them. `artifact.rs` defines
`CompiledSemanticModelPack`, the canonical manifest, shard descriptors, digest
roles, resource limits, and defensive decoders. `producer.rs` can produce exact
Java and .NET API packs, but the module-level documentation correctly says that
compilation and production do not install or activate a pack.

A content-addressed store, abbreviated CAS, is a directory in which an object's
path is derived from a cryptographic digest of its exact bytes. In this plan,
large shard bytes live at
`objects/sha256/<first-two-hex>/<remaining-sixty-two-hex>`, keyed by the
descriptor's `stored_sha256`. Small shard bytes may instead live once in an
SQLite BLOB row when the measurement milestone proves that doing so is useful.
The catalog stores the manifest bytes because candidate selection needs its
small descriptor metadata, but it does not deserialize unrelated shard
payloads.

The existing unified workspace cache is opened by
`crates/bifrost-analysis/src/cache_db.rs`. Its schema is an immutable baseline
plus additive files under `crates/bifrost-analysis/migrations/cache/`; the next
migration is version 13. `AnalyzerStore` in
`crates/bifrost-analysis/src/analyzer/store/mod.rs` wraps one writer and a pool
of read-only WAL connections. Git workspaces use a persistent database;
non-Git workspaces use a delete-on-drop temporary database. New workspace
active-set rows must follow those existing persistent and ephemeral behaviors.

The shared catalog is not the existing unified cache. Add its independent,
rebuildable schema under
`crates/bifrost-analysis/migrations/semantic-pack-catalog/`. Its schema version
uses SQLite `PRAGMA user_version`; an older binary must reject a newer version
without changing the database. A missing or invalid version-one catalog may be
rebuilt only when opened read-write and only after preserving or reconciling
digest-named object files. Read-only open must never migrate, write sidecars,
touch last-use timestamps, create leases, quarantine rows, or run GC.

An activation scope is a stable caller-provided workspace identity associated
with an exact sorted set of manifest digests and activation sources. A reader
lease is a short-lived catalog row created before returning durable shard
locations; it has a unique ID, owner string, and expiration time. The caller
can renew it during long hydration and releases it explicitly or through
`Drop`. Expired leases do not protect content and are pruned by GC.

## Plan of Work

First add an ignored storage-measurement module at
`tests/suite_semantic/measure_semantic_pack_catalog.rs`, register it in
`tests/suite_semantic/main.rs`, and add it to
`.agents/docs/test-harness-consolidation-2026-07.md`. The harness will compile
deterministic declaration shards spanning representative stored sizes, then
measure install, cold load, warm load, catalog-file growth, total disk bytes,
and verified decode for inline thresholds of zero, 8 KiB, 32 KiB, 64 KiB,
256 KiB, and effectively unlimited. Run enough alternating rounds to avoid
always favoring the first layout. Record the exact Bifrost commit, OS, CPU,
SQLite version, fixture sizes, raw/compressed encoding, sample count, medians,
tail latency, database bytes, object bytes, and selected threshold in
`.agents/docs/semantic-pack-catalog-storage-benchmark-2026-07-31.md`. Promote
the largest inline threshold whose median verified load is at least ten percent
faster than the file layout, whose p95 install is no more than 125 percent of
the file layout, and whose total stored bytes are no more than 110 percent of
the smaller layout. If no size meets all three gates, use zero and keep every
shard in the CAS. The compiler's existing compression decision remains
authoritative; report raw versus DEFLATE results but do not recompress catalog
objects.

Create `crates/bifrost-analysis/src/analyzer/semantic_model/catalog/` with
`mod.rs`, `db.rs`, `storage.rs`, and `gc.rs`, then export its public types from
`semantic_model/mod.rs`. `db.rs` owns connection configuration, exact schema
version checks, read-write migration, read-only opening, transactions, selector
queries, and row mapping. `storage.rs` owns safe root validation, digest-derived
paths, symlink rejection, staged file publication, exact-byte verification,
inline-object handling, and orphan reconciliation. `gc.rs` owns lease pruning,
protected-pack selection, transactional metadata deletion, post-commit object
deletion, and accounting of reclaimed bytes. Keep short catalog orchestration
and public types in `mod.rs`; do not create additional files for one-use helper
types.

Add
`crates/bifrost-analysis/migrations/semantic-pack-catalog/0001-current-baseline.sql`.
Use strict tables for manifests, deduplicated objects, manifest-to-shard
membership, normalized selectors, selector targets, selector configurations,
durable sources, activation scopes, active entries, leases, and quarantine
events. Every enum-like column has a `CHECK` constraint. Manifest and object
digest columns require 64 lowercase hexadecimal characters. An object row has
exactly one of an inline BLOB or a relative CAS path. Foreign keys cascade from
manifests to selector and membership rows but do not delete a shared object
while another manifest references it. Add indexes beginning with language and
ecosystem plus package, module, or toolchain name, and indexes for active,
pinned, leased, quarantine, and last-use GC predicates. Do not store a mutable
runtime matcher, analyzer pointer, decoded declaration map, or per-node result.

Implement installation as a validate-then-publish operation. Decode the
manifest with the configured `DecodeLimits`, match every provided shard
descriptor exactly once, decode every shard through
`decode_shard_for_manifest`, and derive normalized selector rows from the
validated typed shard. Reject missing, duplicate, extra, corrupt, oversized, or
unknown-version inputs before touching durable state. Stage each above-threshold
object inside the catalog root, synchronize it, atomically publish it to the
digest path without overwriting a winner, and verify any existing winner before
reuse. In one immediate transaction, insert or reuse the object rows, manifest,
membership, selectors, and source. Activation is a separate transaction and
may reference only fully verified, non-quarantined manifests. Startup
reconciliation removes abandoned staging files and reports digest-named files
that no committed object row references; it never turns an orphan into an
installed pack.

Implement selector lookup with a typed `SemanticPackSelectorQuery`. SQL first
narrows by exact language, ecosystem, and one or more package/module/toolchain
names using the normalized indexes. Rust then evaluates Bifrost and toolchain
SemVer requirements, target and configuration membership, and optional artifact
digest without loading shard bytes. Return deterministic candidates ordered by
exact artifact match, source precedence supplied by the caller, manifest
digest, and shard ID; #1147 remains responsible for final model precedence and
matcher construction. Loading a candidate first acquires a lease in read-write
mode, reads the inline bytes or exact CAS file, verifies size and digest, and
calls the existing manifest-bound decoder. Only a successful load updates
last-use and hit accounting. Integrity failure records bounded quarantine
reason metadata, removes the pack from future verified lookup results, clears
its activations, records a miss, and returns a typed safe-miss result rather
than an empty valid pack.

Add
`crates/bifrost-analysis/migrations/cache/0013-semantic-model-active-set.sql`,
append it to the migration arrays and current-version constants in
`crates/bifrost-analysis/src/cache_db.rs`, and update the schema-construction
tests. The migration adds a singleton active-set row and normalized manifest
references carrying the manifest digest, source kind, source identity, and
workspace-produced flag. Add `AnalyzerStore` methods to load and atomically
replace this state. The active-set digest is a domain-separated SHA-256 over the
sorted complete reference records, not merely a concatenation of pack hashes.
Persistent workspaces retain it; `AnalyzerStore::open_in_memory` exercises the
same schema in its delete-on-drop temporary database.

Add session registration for embedded release packs and ephemeral-workspace
packs. Registration performs the same complete defensive validation as durable
installation but keeps the bytes and normalized selectors in immutable
in-memory entries owned by the catalog instance. Merge session and durable
selector results before deterministic ordering. Embedded entries are reported
as an activation source and are never counted as installed disk bytes.
Ephemeral workspace entries and their active-set rows disappear when their
catalog/store instances drop.

Implement durable activation scopes only after every referenced manifest is
verified. A replacement first acquires temporary leases for every member of the
new set, publishes the new global active references without removing the old
ones, commits the workspace-local active set as the authority, removes the old
global references, and finally releases the temporary leases. This order can
over-preserve packs after a crash but cannot leave a newly active pack
unprotected. Replacing either database's state is one immediate transaction and
updates accounting without duplicating payloads. If coordination fails, report
the mismatch and leave enough information for the next startup to reconcile the
workspace's authoritative desired references into the global scope. Do not
claim a cross-database atomic transaction. #1147 must perform reconciliation
before building a matcher.

Implement GC as a bounded explicit operation with configurable minimum age and
maximum deletions. In one immediate transaction, prune expired leases, select
manifests with no pinned source, activation, or unexpired lease, delete their
catalog metadata, and determine which object rows became unreferenced. Commit
before deleting object files so a crash can create only harmless orphans.
Immediately before each filesystem deletion, reacquire a read snapshot and
confirm that no concurrent reinstall has recreated an object reference. Delete
only validated paths derived from stored digests beneath the catalog root;
never follow symlinks or delete caller-supplied paths. A concurrent reader must
acquire its lease before GC's transaction or observe a safe miss afterward.
Reconciliation on the next open removes leftover unreferenced object files and
never removes staging or object directories broadly.

Expose a `CatalogAccounting` snapshot containing distinct durable installed
bytes, distinct active bytes, object and logical shard counts, verified hits,
misses by reason, quarantine count, reclaimed bytes, and activation counts by
source. Installed and active byte totals must deduplicate shared objects.
Process-local counters may remain in atomics so read-only mode can report them
without writing. Durable sizes, activations, sources, quarantine state,
last-successful-use, and GC results come from SQLite. Log or format full
accounting collections rather than counts alone.

Add behavior-focused integration tests in
`tests/suite_persistence/semantic_model_catalog.rs`, register the module in
`tests/suite_persistence/main.rs`, and update the consolidation manifest.
Coverage must include indexed lookup without shard reads, two-workspace
deduplication, same- and cross-process-style concurrent installation, a crash
window represented by an orphan staged/final object, activation rejection
before publication, missing/corrupt/oversized/unknown-schema quarantine,
request-specific incompatibility, distinct inline/file objects, accounting,
source attribution, active-set digest stability, read-only behavior, ephemeral
workspace/session behavior, migration from the preceding workspace schema,
catalog database too far ahead, pooled readers during writes, lease/activation
GC races, pinned and active preservation, expired lease collection, and
Windows-safe path reconstruction. Reuse the existing semantic-model fixtures
and inline test harness where workspace files are needed; do not add a new root
integration binary.

Update `docs/src/content/docs/semantic-model-packs.md` to replace the
compiler-only boundary with the implemented catalog boundary, explain the
shared-root API, content identities, selector discovery, safe misses,
accounting, session entries, active sets, and GC. Keep the page explicit that
no analyzer matcher is built yet. Update
`.agents/docs/semantic-artifact-lifecycle-matrix.md` with the catalog owner,
identity, representation, completeness rules, accounting, measurement result,
and promotion decision. Update this plan after each milestone, including the
selected inline threshold and exact validation evidence.

## Milestones

Milestone one proves the physical storage decision. At its end, the ignored
measurement harness can compare inline and file-backed storage using the same
compiled and verified shards, and the checked-in benchmark note selects a
threshold or selects zero according to explicit gates. Run the ignored release
measurement and the focused semantic-model tests. Commit the harness, evidence,
chosen catalog option default, and updated plan as one checkpoint before
building the full catalog around an unmeasured assumption.

Milestone two delivers durable installation and discovery. At its end, a caller
can open a shared root, install a complete compiled pack atomically, install it
again from another source without adding payload bytes, discover compatible
candidate shards through indexed selectors, load and verify one candidate, see
accounting, and observe corruption as a quarantined miss. Run catalog unit
tests, the persistence integration module, existing semantic-model pack tests,
formatting, and strict featureless Clippy. Review the checkpoint and commit only
the files changed for this milestone.

Milestone three delivers activation lifecycle and collection. At its end, two
workspace stores can retain different active-set references to the same shared
payload; embedded and ephemeral entries participate without durable copies;
leases protect readers; and GC preserves embedded, pinned, active, and leased
packs while reclaiming an old unreachable pack. Read-only and ephemeral modes,
unknown-schema refusal, concurrent readers/writers/installers, orphan
reconciliation, and migration tests all pass. Run the same focused gates,
review, and commit this independently verifiable checkpoint.

Milestone four completes the public contract and release evidence. At its end,
the public documentation and lifecycle matrix describe measured implemented
behavior, the package contains the required migration files, specialist review
findings have been fixed or recorded, and formatting, focused tests,
featureless analysis-library tests, strict featureless Clippy, docs checks,
package checks, and repository policies have completed reliably. This task does
not authorize a version bump, tag, push, pull request, or deployment.

## Concrete Steps

All commands run from
`/Users/dave/.codex/worktrees/d7b3/bifrost`. Do not create another branch; this
worktree is already on the issue branch. Use the repository's isolated-target
helper for Cargo commands and do not enable `nlp` for this storage-only task.

Run the existing focused baseline before implementation:

    scripts/with-isolated-cargo-target.sh cargo test \
      --test suite_semantic -- semantic_model_pack::

After adding the measurement harness, run its optimized ignored test:

    scripts/with-isolated-cargo-target.sh cargo test --release \
      --test suite_semantic -- \
      measure_semantic_pack_catalog::measure_inline_and_file_storage \
      --ignored --exact --nocapture

The output must contain one JSON record per threshold and encoding plus the
selected threshold and gate results. Copy the exact summarized evidence, not a
hand-chosen result, into
`.agents/docs/semantic-pack-catalog-storage-benchmark-2026-07-31.md`.

After each implementation milestone, run:

    cargo fmt --all -- --check
    git diff --check
    scripts/with-isolated-cargo-target.sh cargo test \
      -p brokk-bifrost-analysis semantic_model::catalog
    scripts/with-isolated-cargo-target.sh cargo test \
      --test suite_persistence -- semantic_model_catalog::
    scripts/with-isolated-cargo-target.sh cargo test \
      --test suite_semantic -- semantic_model_pack::
    scripts/with-isolated-cargo-target.sh cargo clippy \
      -p brokk-bifrost-analysis --all-targets --no-default-features \
      -- -D warnings

After documentation changes, run:

    npm --prefix docs run check
    npm --prefix docs run build

For the final storage-only gate, run:

    scripts/with-isolated-cargo-target.sh cargo test \
      -p brokk-bifrost-analysis --no-default-features
    scripts/check-workspace-packages.sh
    scripts/check-crate-package.sh

Before declaring the code-changing task complete, use the installed
`bifrost-policy-checking` skill and run `bifrost.code-smells` together with
every executable repository policy root named by the repository in one
`run_policy` request. A `finding` requires review or correction and an
`unreliable` result is a failed gate, not a clean result. Rerun the same
selection after changes. Record tool cancellation or fact-budget exhaustion
honestly without claiming success.

## Validation and Acceptance

The new persistence integration scenario must demonstrate the complete user
story: two workspace stores and one shared catalog root install identical pack
bytes from distinct sources; accounting reports one physical object set and two
sources; an exact selector lookup returns the candidate without incrementing a
test-only shard-read counter; both workspaces publish stable active-set
digests; one reader holds a lease while GC preserves the pack; after
deactivation and lease release GC removes the unpinned pack; embedded and
pinned controls remain; and corrupting another object's bytes makes selection
or load return a typed quarantined miss rather than a valid empty payload.

Every install must be all-or-nothing at the catalog level. A test that omits or
corrupts the final shard must leave no manifest, selector, source, activation,
or accounting row. Concurrent installers must converge on one manifest row,
one copy of each stored object, and all distinct source rows. An interrupted
file-first publication may leave an orphan but reopening/reconciliation must
remove it without publishing it.

Lookup tests must prove exact package, module, and toolchain indexes, then prove
version, Bifrost compatibility, target, configuration, and artifact-digest
filtering from normalized catalog metadata. No test may rely only on matching a
duplicated registry-shaped list; it must install and successfully select or
reject real compiled packs.

Migration tests must prove a version-12 workspace database upgrades additively
to version 13 and preserves existing rows. A newer workspace or catalog
`user_version` must be rejected without mutation. Read-only opening of a
current catalog must permit discovery and verified loading without creating a
WAL, updating last-use, writing quarantine, acquiring a durable lease, or
running GC. An ephemeral workspace must lose its active references and
session-produced pack after drop while leaving a previously installed durable
pack intact.

GC tests must prove all four protections independently: embedded content is not
durably owned, a pinned source keeps its pack, a durable activation keeps its
pack, and an unexpired lease keeps its pack. Expired leases are pruned. Object
bytes shared by a protected and an unreachable manifest remain until the last
reference disappears. GC paths must remain beneath the canonical catalog root
and reject symlinked catalog directories, databases, staging files, and object
files.

The measurement note must contain enough evidence to reproduce the selected
inline threshold and show whether the compiler's existing compression wins for
the tested payloads. Missing or invalid measurements mean the threshold remains
zero. Final documentation must state that the catalog performs generation-time
selection only and that #1147 still owns in-memory matching.

## Idempotence and Recovery

Compilation, selector derivation, and digest checks are deterministic. Installing
the same pack repeatedly is safe and adds at most a missing source or pin.
Migration and reconciliation are safe to retry. Staged files use unique names
inside a dedicated staging directory; recovery removes only files whose paths
and age satisfy the catalog's validated staging rules.

Never delete a caller-provided or recursively broad path. GC derives every
object path from a validated lowercase SHA-256 digest and confirms that the
canonical parent is the configured catalog root. Metadata commits before
object deletion, so a crash can leave an orphan but not a live row pointing at
newly deleted data. A failed install before the metadata transaction can be
retried; reconciliation handles its orphan. A failed workspace/global
activation coordination is reported and reconciled from the workspace's
desired active set on next open.

The ignored benchmark uses temporary catalog roots and can be repeated. The
isolated Cargo-target helper removes its own build directory on success,
failure, or interruption. Do not retain an isolated target unless the artifacts
are deliberately needed.

## Artifacts and Notes

The live issue is `https://github.com/BrokkAi/bifrost/issues/1146`. It depends
on closed issue #1145 and is a child of #1144. The branch began implementation
planning at `91357eec`, equal to the then-current `origin/master`.

The retained catalog benchmark note is
`.agents/docs/semantic-pack-catalog-storage-benchmark-2026-07-31.md`. The
release run selected a zero-byte threshold after the 8 KiB candidate failed the
verified cold-read gate. The command passed one ignored measurement test and
the isolated release target was removed.

Broad code-intelligence planning calls exposed a separate latency concern:
multi-target `get_summaries` and `get_symbol_sources` requests exceeded ten
seconds and cancelled, while narrow requests were fast. No clearly matching
open issue was found during the initial search. Do not widen #1146 to fix that
behavior.

## Interfaces and Dependencies

In `crates/bifrost-analysis/src/analyzer/semantic_model/catalog/mod.rs`, expose
names equivalent to the following. Exact ownership types may use `Box<str>` or
slices where that avoids cloning, but do not replace distinct operations with
mode flags:

    pub struct SemanticPackCatalog;

    pub struct CatalogOptions {
        pub inline_object_max_bytes: u64,
        pub decode_limits: DecodeLimits,
    }

    pub enum CatalogOpenMode {
        ReadWrite,
        ReadOnly,
    }

    pub enum DurablePackSourceKind {
        Installed,
        Generated,
        PreShipped,
        WorkspaceProduced,
    }

    pub enum SessionPackSourceKind {
        Embedded,
        EphemeralWorkspace,
    }

    pub struct SemanticPackSelectorQuery {
        pub language: String,
        pub ecosystem: String,
        pub package: Option<NameSelector>,
        pub module: Option<NameSelector>,
        pub toolchain: Option<NameSelector>,
        pub target: Option<String>,
        pub configuration: Option<String>,
        pub artifact_sha256: Option<String>,
        pub bifrost_version: semver::Version,
    }

    pub struct CatalogCandidate;
    pub struct CatalogLease;
    pub struct CatalogAccounting;
    pub struct SemanticPackActiveSet;
    pub struct SemanticPackActiveReference;

    impl SemanticPackCatalog {
        pub fn open(
            root: &Path,
            mode: CatalogOpenMode,
            options: CatalogOptions,
        ) -> Result<Self, CatalogError>;

        pub fn install(
            &self,
            pack: &CompiledSemanticModelPack,
            source: DurablePackSource,
        ) -> Result<InstallOutcome, CatalogError>;

        pub fn register_embedded(
            &self,
            pack: CompiledSemanticModelPack,
            source_id: String,
        ) -> Result<(), CatalogError>;

        pub fn register_ephemeral_workspace_pack(
            &self,
            pack: CompiledSemanticModelPack,
            source_id: String,
        ) -> Result<(), CatalogError>;

        pub fn candidates(
            &self,
            query: &SemanticPackSelectorQuery,
        ) -> Result<Vec<CatalogCandidate>, CatalogError>;

        pub fn load(
            &self,
            candidate: &CatalogCandidate,
            lease_owner: &str,
        ) -> Result<LoadedCatalogShard, CatalogMiss>;

        pub fn replace_activation_scope(
            &self,
            scope_id: &str,
            active_set: &SemanticPackActiveSet,
        ) -> Result<(), CatalogError>;

        pub fn accounting(&self) -> Result<CatalogAccounting, CatalogError>;

        pub fn collect_garbage(
            &self,
            policy: &CatalogGcPolicy,
        ) -> Result<CatalogGcOutcome, CatalogError>;
    }

Do not expose raw `rusqlite::Connection`, absolute object paths that callers can
mutate, or mutable decoded payload maps. `CatalogCandidate` carries stable
manifest and shard identities plus activation-source evidence. A loaded shard
owns or borrows a live lease for durable file-backed content and exposes only
the already validated `CompiledShard`.

In `AnalyzerStore`, add public methods equivalent to:

    pub fn semantic_pack_active_set(
        &self,
    ) -> Result<Option<SemanticPackActiveSet>>;

    pub fn replace_semantic_pack_active_set(
        &self,
        active_set: &SemanticPackActiveSet,
    ) -> Result<()>;

Use the existing `rusqlite`, `sha2`, `semver`, `tempfile`, `serde`, and
`serde_json` dependencies. Do not add a platform-directory dependency because
the catalog root is explicit. Do not add a new compression implementation;
store the exact bytes and encoding emitted by the semantic-pack compiler.

Plan revision note (2026-07-31 06:30Z): Created the initial self-contained plan
after live issue and dependency verification. It resolves the shared versus
workspace storage split, exact digest roles, multi-source deduplication,
file-first atomic publication, indexed selector boundary, session-only embedded
and ephemeral packs, quarantine semantics, activation/lease GC protection, and
measurement-first inline storage decision.

Plan revision note (2026-07-31 07:06Z): Completed milestone one's release
measurement, retained the raw-plus-DEFLATE evidence, selected a zero-byte inline
threshold according to the preregistered gates, and updated the remaining work
to use file-backed shard objects exclusively.
