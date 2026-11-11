//! Content-addressed Cargo crate reconciliation with query-local SQL scheduling.
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::HashSet;

use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

use std::sync::Mutex;

use brokk_bifrost_core::analyzer::rust_facts::decode_rust_cfg_condition;

use brokk_bifrost_rust::cargo_config::RustCargoConfigDocument;
use brokk_bifrost_rust::cargo_config::RustCargoConfiguration;
use brokk_bifrost_rust::cargo_config::is_cargo_configuration_path;

use brokk_bifrost_rust::selected_context::RustCallerTargetKind;
use brokk_bifrost_rust::selected_context::RustCargoDependencyKind;
use brokk_bifrost_rust::selected_context::RustCargoEdition;
use brokk_bifrost_rust::selected_context::RustCrateTarget;
use brokk_bifrost_rust::selected_context::RustSelectedActivation;
use brokk_bifrost_rust::selected_context::RustSelectedManifestMount;
use brokk_bifrost_rust::selected_context::rust_broad_target_discovery_complete;
use brokk_bifrost_rust::selected_context::rust_crate_targets;

use git2::Oid;

use rayon::prelude::*;

use rusqlite::Connection;
use rusqlite::OptionalExtension;
use rusqlite::functions::FunctionFlags;
use rusqlite::params;

use sha2::Digest;
use sha2::Sha256;

use super::unit_schedule;

use super::AnalyzerStore;
use super::Result;
use super::StoreError;
use super::WorkspaceSnapshotId;
use super::WorkspaceSnapshots;

use crate::analyzer::pool_memo::install_on_dedicated_build_pool;

pub(super) const REPLACED_BLOB_ID_SQL: &str = "SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2 AND generation = ?3 AND parse_variant = ?4 AND (EXISTS(SELECT 1 FROM rust_crate_container_sources WHERE blob_id = blobs.id) OR EXISTS(SELECT 1 FROM rust_crate_exports WHERE declaration_blob_id = blobs.id))";
pub(super) const REINSERT_BLOB_SQL: &str =
    "INSERT INTO blobs(id, blob_oid, lang, generation, parse_variant) VALUES(?1, ?2, ?3, ?4, ?5)";

pub(super) const INSERT_NAMING_SQL: &str =
    "INSERT INTO rust_crate_file_naming VALUES(?1,?2,jsonb(?3),jsonb(?4))";

pub(super) const INSERT_MODULE_SQL: &str =
    "INSERT INTO rust_crate_containers VALUES(?1, ?2, 'module', ?3)";

pub(super) const MODULE_WALK_SQL: &str = include_str!("rust_crate_module_walk.sql");

pub(super) const ITEM_MACRO_DECISIONS_SQL: &str =
    include_str!("rust_crate_item_macro_decisions.sql");

pub(super) use brokk_bifrost_core::cache_gc::DELETE_UNBOUND_TOPOLOGIES_SQL;

#[path = "rust_crate_derivation.rs"]
#[doc(hidden)]
pub mod derivation;

type CrateKey = [u8; 32];

/// The version of the crate-row derivation itself: the statements under
/// `store/rust_crate_*.sql`, the module route walk, the order
/// `derive_exports` runs them in, and the dependency waves, which decide which
/// dependencies each crate is derived with. It is hashed into every topology
/// digest, so a store built under an earlier rule set re-derives its crate rows
/// although its inputs are unchanged. Bump it whenever those rules change.
///
/// The digest also folds in the Rust analysis epoch, which versions the
/// per-blob payloads the derivation reads. Keeping the two apart is the point:
/// rotating the epoch for a consumer-side change would make every Rust blob
/// dirty and force a full reparse of a warm store.
#[doc(hidden)]
pub const RUST_CRATE_DERIVATION_VERSION: &str = "4460-2026-10-07-module-self-imports-target-has-atomic-cfg-attr-derived-surface-generated-attribute-boundary-fact-enum-variant-export-set-2026-10-08-cycle-only-forced-wave-2026-10-09-primitive-shadowing-5235-2026-10-14-item-macro-guess-scope-5375-2026-10-15-reverse-inventory-5375-2026-10-16-v2-composite-primitive-shadowing-5243-2026-10-15-reverse-inventory-5375-2026-10-16-v3-enumerated-inputs-5517-cfg-if-ordered-items-and-conditional-imports-5172-2026-10-17-conditional-macro-frontiers-constructor-visibility-5133-2026-10-15-forwarded-public-surface-5133-2026-10-17-rust-route-precedence-5780-v6-admitted-binding-provenance-5658-p2-own-binding-authority-native-namespaces-owner-gap-certificates-owner-wide-propagation-6046-own-member-source-paths-prelude-root-witnesses-6102-gap-subject-levels-6136-settled-terminal-lookups-6114-glob-own-root-lookup-6389-associated-macro-contexts-inherent-impl-subjects-6394-duplicate-module-macro-scope-v1-absent-feature-cfg-inactive-v1-workspace-exclude-curdir-patch-version-topology-v1-macro-replay-path-module-walk-6861-v1-6846-cargo-literal-exclude-selected-build-features-v1-unresolved-impl-resolved-half-declarations-7226-10042-missing-target-roots-9737-d18d-broad-placements-9737-unproven-path-candidates-10469-case-folded-path-candidates-10552-path-probes-10774-manifests-only-cargo-toml-10953-target-dependencies-and-lib-names-9737-crate-manifest-currency-10987-scoped-symlink-omissions-11060-unplaced-module-topology-11111-certified-absent-module-topology";
/// Set by `crate_topology_digests_follow_the_derivation_version` and
/// `warm_derivation_version_rotation_replaces_same_revision_versions` so that a
/// test can derive under a second version and compare. Nothing else writes it.
#[cfg(any(test, feature = "test-support"))]
static DERIVATION_VERSION_OVERRIDE: std::sync::Mutex<Option<&'static str>> =
    std::sync::Mutex::new(None);

/// The derivation version this process derives under.
#[doc(hidden)]
pub fn derivation_version() -> &'static str {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(version) = *DERIVATION_VERSION_OVERRIDE
        .lock()
        .expect("derivation version override lock")
    {
        return version;
    }
    RUST_CRATE_DERIVATION_VERSION
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn set_derivation_version(version: Option<&'static str>) {
    *DERIVATION_VERSION_OVERRIDE
        .lock()
        .expect("derivation version override lock") = version;
}

#[doc(hidden)]
pub struct Member {
    #[doc(hidden)]
    pub module_path: String,
    #[doc(hidden)]
    pub blob_id: i64,
    #[doc(hidden)]
    pub scope: i64,
    #[doc(hidden)]
    pub rel_path: String,
    #[doc(hidden)]
    pub placement: String,
    /// The module that declares this one; `None` only for the crate root.
    #[doc(hidden)]
    pub parent_path: Option<String>,
}
struct Gap {
    kind: &'static str,
    subject: String,
    detail: String,
}
// The configuration values are JSON arrays of scalar strings. Targets,
// dependency kinds, identity, availability and prior outputs are separate rows.
const STAGED_TARGET_SQL: &str = "SELECT crate_key,manifest_path,root_path,target_kind,crate_name,edition,cfg,features,inventory_complete,manifest_version,inventory_error FROM temp.rust_schedule_targets WHERE unit_id = ?1";
const STAGED_DEPENDENCIES_SQL: &str = "SELECT extern_name,kind,dependency_key FROM temp.rust_schedule_dependencies WHERE crate_key = ?1 ORDER BY ordinal";
const WAVE_UNIT_SQL: &str = "SELECT wave.unit_id, wave.forced
                                FROM temp.rust_schedule_wave_order AS ordered
                                JOIN temp.rust_schedule_wave AS wave USING(unit_id)
                                WHERE ordered.ordinal = ?1";
const LIVE_SURFACE_SQL: &str = "SELECT surface FROM temp.rust_schedule_live WHERE crate_key = ?1";

const RUST_SCHEDULE_SCHEMA_SQL: &str = "
CREATE TEMP TABLE IF NOT EXISTS rust_schedule_targets(
 unit_id INTEGER PRIMARY KEY, crate_key BLOB NOT NULL UNIQUE,
 manifest_path TEXT NOT NULL, root_path TEXT NOT NULL, target_kind TEXT NOT NULL,
 crate_name TEXT NOT NULL, edition TEXT NOT NULL,
 cfg TEXT NOT NULL CHECK(json_valid(cfg)), features TEXT NOT NULL CHECK(json_valid(features)),
 inventory_complete INTEGER NOT NULL, manifest_version INTEGER, inventory_error TEXT,
 reached INTEGER NOT NULL DEFAULT 0, pending INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE INDEX IF NOT EXISTS temp.rust_schedule_targets_pending ON rust_schedule_targets(pending, unit_id);
CREATE TEMP TABLE IF NOT EXISTS rust_schedule_dependencies(
 crate_key BLOB NOT NULL, ordinal INTEGER NOT NULL, extern_name TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('normal','dev','build')), dependency_key BLOB,
 PRIMARY KEY(crate_key, ordinal)
) WITHOUT ROWID, STRICT;
CREATE INDEX IF NOT EXISTS temp.rust_schedule_dependencies_dependency ON rust_schedule_dependencies(dependency_key);
CREATE TEMP TABLE IF NOT EXISTS rust_schedule_previous(crate_key BLOB PRIMARY KEY, topology_id INTEGER NOT NULL, surface BLOB NOT NULL) WITHOUT ROWID, STRICT;
CREATE TEMP TABLE IF NOT EXISTS rust_schedule_live(crate_key BLOB PRIMARY KEY, topology_id INTEGER NOT NULL, surface BLOB NOT NULL) WITHOUT ROWID, STRICT;
CREATE TEMP TABLE IF NOT EXISTS rust_schedule_reached(crate_key BLOB PRIMARY KEY) WITHOUT ROWID, STRICT;
CREATE TEMP TABLE IF NOT EXISTS rust_schedule_detached(topology_id INTEGER PRIMARY KEY) STRICT;
CREATE TEMP TABLE IF NOT EXISTS rust_schedule_blocked(crate_key BLOB PRIMARY KEY) WITHOUT ROWID, STRICT;
CREATE TEMP TABLE IF NOT EXISTS rust_schedule_wave(unit_id INTEGER PRIMARY KEY, forced INTEGER NOT NULL) STRICT;
CREATE TEMP TABLE IF NOT EXISTS rust_schedule_wave_order(ordinal INTEGER PRIMARY KEY, unit_id INTEGER NOT NULL) STRICT;
CREATE TEMP TABLE IF NOT EXISTS rust_schedule_outputs(crate_key BLOB PRIMARY KEY, topology_id INTEGER NOT NULL, surface BLOB NOT NULL) WITHOUT ROWID, STRICT;
CREATE TEMP TABLE IF NOT EXISTS rust_schedule_moved(crate_key BLOB PRIMARY KEY) WITHOUT ROWID, STRICT;
CREATE TEMP TABLE IF NOT EXISTS rust_schedule_next(ordinal INTEGER PRIMARY KEY, crate_key BLOB NOT NULL UNIQUE) STRICT;
CREATE TEMP TABLE IF NOT EXISTS rust_schedule_pending_order(ordinal INTEGER PRIMARY KEY, unit_id INTEGER NOT NULL UNIQUE) STRICT;
CREATE TEMP TABLE IF NOT EXISTS rust_schedule_retire(crate_key BLOB PRIMARY KEY, opened INTEGER NOT NULL) WITHOUT ROWID, STRICT;";

const RUST_READY_WAVE_SQL: &str = "INSERT INTO temp.rust_schedule_wave
 SELECT target.unit_id, 0 FROM temp.rust_schedule_targets AS target
 WHERE target.pending = 1
   AND NOT EXISTS (SELECT 1 FROM temp.rust_schedule_blocked AS blocked WHERE blocked.crate_key = target.crate_key)
   AND NOT EXISTS (SELECT 1 FROM temp.rust_schedule_dependencies AS edge
       WHERE edge.crate_key = target.crate_key AND edge.dependency_key IS NOT NULL
         AND NOT EXISTS (SELECT 1 FROM temp.rust_schedule_live AS live WHERE live.crate_key = edge.dependency_key))";

const RUST_FORCE_COMPONENT_SQL: &str = "SELECT component.component_id
 FROM temp.rust_schedule_targets AS target
 JOIN temp.unit_schedule_components AS component USING(unit_id)
 WHERE target.pending = 1 AND NOT EXISTS (
   SELECT 1 FROM temp.unit_schedule_components AS member
   JOIN temp.rust_schedule_targets AS peer USING(unit_id)
   WHERE member.component_id = component.component_id AND (
     EXISTS (SELECT 1 FROM temp.rust_schedule_blocked AS blocked WHERE blocked.crate_key = peer.crate_key)
     OR EXISTS (
       SELECT 1 FROM temp.rust_schedule_dependencies AS edge
       JOIN temp.rust_schedule_targets AS dependency ON dependency.crate_key = edge.dependency_key
       JOIN temp.unit_schedule_components AS dependency_component ON dependency_component.unit_id = dependency.unit_id
       WHERE edge.crate_key = peer.crate_key AND dependency.pending = 1
         AND dependency_component.component_id <> component.component_id
         AND NOT EXISTS (SELECT 1 FROM temp.rust_schedule_live AS live WHERE live.crate_key = edge.dependency_key))))
 ORDER BY (SELECT ordinal FROM temp.rust_schedule_pending_order WHERE unit_id = target.unit_id) LIMIT 1";

fn stage_crate(conn: &Connection, ordinal: i64, item: &PreparedCrate) -> Result<()> {
    let target = &item.target;
    conn.prepare_cached("INSERT INTO temp.rust_schedule_targets
        (unit_id,crate_key,manifest_path,root_path,target_kind,crate_name,edition,cfg,features,inventory_complete,manifest_version,inventory_error)
        VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)")?.execute( params![ordinal, item.key.as_slice(), stable_path(&target.manifest_path), stable_path(&target.root_path), target_kind(target.kind), target.name, edition(target.edition), serde_json::to_string(&target.cfg_atoms).expect("cfg string sets serialize"), serde_json::to_string(&target.features).expect("feature string sets serialize"), target.inventory_complete, item.manifest_version, item.inventory_error])?;
    for (ordinal, (name, kind, dependency)) in item.dependencies.iter().enumerate() {
        conn.prepare_cached("INSERT INTO temp.rust_schedule_dependencies VALUES(?1,?2,?3,?4,?5)")?
            .execute(params![
                item.key.as_slice(),
                ordinal as i64,
                name,
                kind,
                dependency.as_ref().map(|key| key.as_slice())
            ])?;
    }
    Ok(())
}

fn read_staged_crate(conn: &Connection, id: i64, forced: bool) -> Result<PreparedCrate> {
    let (
        key,
        manifest,
        root,
        kind,
        name,
        edition_value,
        cfg,
        features,
        complete,
        version,
        inventory_error,
    ) = conn
        .prepare_cached(STAGED_TARGET_SQL)?
        .query_row([id], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, bool>(8)?,
                row.get::<_, Option<i64>>(9)?,
                row.get::<_, Option<String>>(10)?,
            ))
        })?;
    let key = crate_key_from_row(key)?;
    let dependencies = conn
        .prepare_cached(STAGED_DEPENDENCIES_SQL)?
        .query_map([key.as_slice()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
            ))
        })?
        .map(|row| {
            let (name, kind, key) = row?;
            let kind = match kind.as_str() {
                "normal" => "normal",
                "dev" => "dev",
                "build" => "build",
                _ => unreachable!("staged dependency kind is checked"),
            };
            Ok((name, kind, key.map(crate_key_from_row).transpose()?))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(PreparedCrate {
        key,
        manifest_version: version,
        inventory_error: inventory_error.clone(),
        forced,
        dependencies,
        target: RustCrateTarget {
            manifest_path: PathBuf::from(manifest),
            root_path: PathBuf::from(root),
            kind: match kind.as_str() {
                "lib" => RustCallerTargetKind::Library,
                "bin" => RustCallerTargetKind::Binary,
                "test" => RustCallerTargetKind::Test,
                "example" => RustCallerTargetKind::Example,
                "bench" => RustCallerTargetKind::Bench,
                "build" => RustCallerTargetKind::Build,
                _ => unreachable!("only Cargo targets are staged"),
            },
            name,
            edition: match edition_value.as_str() {
                "2015" => RustCargoEdition::Rust2015,
                "2018" => RustCargoEdition::Rust2018,
                "2021" => RustCargoEdition::Rust2021,
                "2024" => RustCargoEdition::Rust2024,
                _ => unreachable!("only supported editions are staged"),
            },
            cfg_atoms: serde_json::from_str(&cfg).expect("staged cfg string arrays decode"),
            features: serde_json::from_str(&features).expect("staged feature string arrays decode"),
            dependencies: Vec::new(),
            inventory_complete: complete && !forced,
            inventory_error,
        },
    })
}

struct PreparedCrate {
    target: RustCrateTarget,
    key: CrateKey,
    manifest_version: Option<i64>,
    inventory_error: Option<String>,
    forced: bool,
    dependencies: Vec<(String, &'static str, Option<CrateKey>)>,
}
#[derive(Clone, Copy)]
struct DerivedCrate {
    key: CrateKey,
    topology_id: i64,
    surface: CrateKey,
}

/// Which crates one reconcile pass derives.
///
/// `Everything` is the from-scratch pass: it walks every Cargo target and
/// every detached file, and it is the oracle the scoped pass is checked
/// against. `Reached` carries the crates a set of changed paths named through
/// the crate rows, closed under "a dependent of a crate whose export surface
/// changed" and under "the other members of a dependency cycle", because a
/// cycle is derived as one wave whose members do not see each other. Every
/// other live crate keeps the topology the previous pass derived for it, read
/// back by key rather than recomputed.
///
/// This is which crates, not how to reconcile: both values run the same pass.
/// `from_revision` is the head revision the crate rows were current for
/// before the change; the pass advances the reconciliation marker only from
/// there. `created` lists the changed Rust paths that exist now but did not
/// at `from_revision`: a created file that no reached crate places gets its
/// detached topology from them.
///
/// A reached crate that no Cargo target places is a detached crate, and only
/// the detached pass derives those. The scoped pass carries every crate it did
/// not reach forward, so it re-derives a reached detached crate from the file
/// the change named instead of dropping the summary the crate already had.
#[doc(hidden)]
pub enum CrateReconcileScope {
    Everything,
    Reached {
        crates: HashSet<CrateKey>,
        from_revision: i64,
        created: Vec<String>,
    },
}

/// One row of `rust_crate_module_walk.sql`. `mount_blob` and `mount_start` are
/// the mounting file and the byte its `mod` declaration starts at, present only
/// for a module the walk reached through a module route; they carry the textual
/// `macro_rules!` scope from the mounting file into the mounted one.
struct WalkRow {
    module_path: String,
    blob: Option<i64>,
    scope: i64,
    path: Option<String>,
    placement: String,
    mount_blob: Option<i64>,
    mount_start: Option<i64>,
    activation: i64,
    parent_path: Option<String>,
    frontier: bool,
    depth_capped: bool,
    /// The files every placement the walk folded into this row names: `#[path]`
    /// and `include!` targets and the default candidates of `mod name;`.
    path_candidates: Vec<String>,
}

impl WalkRow {
    fn placement_gap(&self, counts: &HashMap<&str, usize>) -> Option<&'static str> {
        if self.activation == 0 {
            Some("inactive_placement")
        } else if self.activation < 0 {
            Some("unknown_activation")
        } else if self.blob.is_none() {
            Some("unplaced_module")
        } else if counts.get(self.module_path.as_str()).copied().unwrap_or(0) > 1 {
            Some("duplicate_placement")
        } else {
            None
        }
    }
}

// A file placed under different module paths supplies distinct modules. Only
// active non-include placements of the same module path conflict; includes
// contribute to their host module rather than declaring another placement.
fn active_placement_counts(rows: &[WalkRow]) -> HashMap<&str, usize> {
    let mut counts = HashMap::new();
    for row in rows {
        if row.placement != "include" && row.activation == 1 {
            *counts.entry(row.module_path.as_str()).or_insert(0) += 1;
        }
    }
    counts
}

/// One item-position macro decision used while walking a crate's module tree.
/// A passthrough replays its item arguments; a no-route decision proves the
/// invocation cannot create a module, either because the local matcher proves
/// it expands to no item or source macro scope proves its name unavailable.
#[derive(Debug, PartialEq, Eq)]
struct ItemMacroDecision {
    blob_id: i64,
    invocation_occurrence_id: i64,
    /// The activation the visible definition's rules add to each item they
    /// replay, encoded like an item's `cfg_condition`. The empty `any()` cfg
    /// expression is the closed route for a proven invisible invocation.
    decoration_cfg: String,
    no_route: bool,
}

impl AnalyzerStore {
    /// Reconcile every Rust crate in the workspace.
    ///
    /// The from-scratch pass, and the oracle for the scoped one: a first
    /// build, a manifest change, and any change whose paths the crate rows do
    /// not place all come here.
    #[doc(hidden)]
    pub fn reconcile_rust_crates(
        &self,
        snapshot: &WorkspaceSnapshotId,
    ) -> Result<super::unit_summaries::UnitSummaryReconciliation> {
        self.reconcile_rust_crates_in_scope(snapshot, CrateReconcileScope::Everything)
    }

    /// Reconcile every Rust crate unless the crate rows are already current.
    ///
    /// They are current when the last complete reconcile of this generation
    /// ran against this head revision under this derivation version. Every
    /// input of every topology digest is then unchanged: the analysis epoch
    /// is the generation's, the files and manifests are the revision's, and
    /// the rules are the derivation version's. A warm start that changed
    /// nothing therefore walks no crate. A missing marker, as after a first
    /// build, an epoch rotation or a failed pass, runs the full pass.
    #[doc(hidden)]
    pub fn reconcile_rust_crates_unless_current(
        &self,
        snapshot: &WorkspaceSnapshotId,
    ) -> Result<super::unit_summaries::UnitSummaryReconciliation> {
        assert_eq!(snapshot.lang, "rust");
        let current = self
            .read_conn()?
            .prepare_cached(SQL_RUST_CRATE_RECONCILIATION_CURRENT)?
            .query_row(
                params![
                    snapshot.workspace_id.as_str(),
                    snapshot.generation.0,
                    snapshot.revision,
                    derivation_version()
                ],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if current {
            crate::profiling::note_with(|| {
                format!(
                    "rust_crates.reconcile: skipped, rows current for generation {} revision {}",
                    snapshot.generation.0, snapshot.revision
                )
            });
            return self.reconcile_rust_unit_summaries(snapshot);
        }
        // The marker names the last complete pass under this derivation
        // version. The paths the revision log changed since then reach the
        // crates they place. No marker, or a marker not before the head (a
        // revision image built an older head), runs the full pass.
        let marker = self
            .read_conn()?
            .prepare_cached(SQL_RUST_CRATE_RECONCILIATION_PREVIOUS)?
            .query_row(
                params![
                    snapshot.workspace_id.as_str(),
                    snapshot.generation.0,
                    derivation_version()
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        let Some(previous_revision) = marker else {
            return self.reconcile_rust_crates(snapshot);
        };
        if previous_revision >= snapshot.revision {
            crate::profiling::note_with(|| {
                format!(
                    "rust_crates.reconcile: full pass, marker revision {previous_revision} is not before head {}",
                    snapshot.revision
                )
            });
            return self.reconcile_rust_crates(snapshot);
        }
        // A revision can differ from the marker's by its listing certificate
        // alone, as when a symlink appeared while the process was down. No file
        // version changed, so the range read below names no path, yet every
        // crate's broad completeness folds in the certificate.
        let previous = WorkspaceSnapshotId {
            workspace_id: snapshot.workspace_id.clone(),
            lang: "rust".into(),
            generation: snapshot.generation,
            revision: previous_revision,
        };
        // The reader is released before reconciliation: a single-connection
        // store has no second connection for the reconcile to read through.
        let certificate_differs = {
            let conn = self.read_conn()?;
            super::rust_listing_certificate_at(&conn, &previous)?
                != super::rust_listing_certificate_at(&conn, snapshot)?
        };
        if certificate_differs {
            crate::profiling::note_with(|| {
                format!(
                    "rust_crates.reconcile: full pass, listing certificate differs between marker revision {previous_revision} and head {}",
                    snapshot.revision
                )
            });
            return self.reconcile_rust_crates(snapshot);
        }
        // Revision rows of the current generation are never pruned: cache_gc
        // reclaims only whole stale generations. So the range read below
        // is complete, and no fallback is needed for an incomplete set.
        let changed_paths = self
            .read_conn()?
            .prepare_cached(SQL_WORKSPACE_FILE_CHANGES_BETWEEN)?
            .query_map(
                params![
                    snapshot.workspace_id.as_str(),
                    snapshot.generation.0,
                    previous_revision,
                    snapshot.revision
                ],
                |row| row.get::<_, String>(0),
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        self.reconcile_rust_crates_after_changes(&previous, snapshot, &changed_paths)
    }

    /// Keep shared crate summaries current even when topology rows already
    /// match this revision. A previous per-unit failure must be retried on a
    /// warm start. The Rust point and reverse readers answer from these
    /// summary rows, so a failed pass is an error for the caller: nothing
    /// falls back to older rows.
    #[doc(hidden)]
    pub fn reconcile_rust_unit_summaries(
        &self,
        snapshot: &WorkspaceSnapshotId,
    ) -> Result<super::unit_summaries::UnitSummaryReconciliation> {
        let report = self.reconcile_unit_summaries(
            snapshot,
            super::rust_unit_summaries::RustUnitSummaries,
            &crate::CancellationToken::default(),
        )?;
        crate::profiling::note_with(|| format!("rust_unit_summaries.reconcile: {report:?}"));
        #[cfg(any(test, feature = "test-support"))]
        {
            let conn = self
                .read_conn()
                .expect("open the Rust summary differential reader");
            super::rust_unit_summaries::assert_differential(&conn, snapshot);
        }
        Ok(report)
    }

    /// Check the complete topology/summary differential for current Rust heads.
    /// Integration tests use the same member, export and dependency assertions
    /// as the automatic unit-test check after reconciliation.
    #[cfg(feature = "test-support")]
    pub fn assert_rust_summary_differential_for_test(&self) {
        let conn = self
            .read_conn()
            .expect("open the Rust summary differential reader");
        let snapshots = conn
            .prepare_cached(
                "SELECT heads.workspace_id, heads.generation, heads.revision
                 FROM workspace_heads AS heads
                 LEFT JOIN analysis_epochs AS epochs ON epochs.lang = heads.lang
                 WHERE heads.lang = 'rust'
                   AND heads.generation = COALESCE(epochs.generation, 0)
                 ORDER BY heads.workspace_id",
            )
            .expect("prepare current Rust workspace heads")
            .query_map([], |row| {
                Ok(WorkspaceSnapshotId {
                    workspace_id: super::WorkspaceId(row.get(0)?),
                    lang: "rust".into(),
                    generation: super::GenerationId::from_persisted(row.get(1)?),
                    revision: row.get(2)?,
                })
            })
            .expect("read current Rust workspace heads")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect current Rust workspace heads");
        assert!(
            !snapshots.is_empty(),
            "the Rust differential requires a published workspace head"
        );
        for snapshot in snapshots {
            super::rust_unit_summaries::assert_differential(&conn, &snapshot);
        }
    }

    /// Reconcile the crates a set of changed paths reached.
    ///
    /// One changed file costs its own crates and, when its export surface
    /// moved, their dependents. Everything else keeps the topology the last
    /// pass derived. Cargo manifests, locks and configuration, and created or
    /// deleted package target roots, require the whole workspace. Other path
    /// creations and deletions reach placements and recorded case-folded probes;
    /// edits reach their recorded placements, including inactive ones.
    ///
    /// `previous` is the snapshot the crate rows were reconciled against
    /// before these changes.
    #[doc(hidden)]
    pub fn reconcile_rust_crates_after_changes(
        &self,
        previous: &WorkspaceSnapshotId,
        snapshot: &WorkspaceSnapshotId,
        changed_paths: &[String],
    ) -> Result<super::unit_summaries::UnitSummaryReconciliation> {
        assert_eq!(snapshot.lang, "rust");
        assert_eq!(previous.workspace_id, snapshot.workspace_id);
        if previous.generation != snapshot.generation {
            // The crate rows of a new generation have nothing to be scoped
            // against.
            return self.reconcile_rust_crates(snapshot);
        }
        let scope = self.rust_crate_reconcile_scope(snapshot, previous.revision, changed_paths)?;
        self.reconcile_rust_crates_in_scope(snapshot, scope)
    }

    /// Resolve changed paths to their placements and path-set dependencies.
    #[doc(hidden)]
    pub fn rust_crate_reconcile_scope(
        &self,
        snapshot: &WorkspaceSnapshotId,
        from_revision: i64,
        changed_paths: &[String],
    ) -> Result<CrateReconcileScope> {
        // The legacy `.cargo/config` has no extension.
        if changed_paths
            .iter()
            .any(|path| is_cargo_configuration_path(Path::new(path)))
        {
            return Ok(CrateReconcileScope::Everything);
        }
        // Extensions compare ignoring ASCII case, as the language of a selected
        // file does: a selected src/foo.RS is a Rust source.
        let has_extension = |path: &str, wanted: &str| {
            Path::new(path)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case(wanted))
        };
        let rust_paths = changed_paths
            .iter()
            .filter(|path| {
                has_extension(path, "rs")
                    || has_extension(path, "toml")
                    || has_extension(path, "lock")
            })
            .collect::<Vec<_>>();
        if rust_paths.is_empty() {
            return Ok(CrateReconcileScope::Reached {
                crates: HashSet::new(),
                from_revision,
                created: Vec::new(),
            });
        }
        if rust_paths
            .iter()
            .any(|path| has_extension(path, "toml") || has_extension(path, "lock"))
        {
            return Ok(CrateReconcileScope::Everything);
        }
        let snapshots = WorkspaceSnapshots::from_iter([("rust".to_string(), snapshot.clone())]);
        let conn = self.read_conn_for_workspace(&snapshots)?;
        // Existing paths are scoped by the published placements regardless of
        // certificate: changing the file cannot change whether the walk reaches
        // it. A new path can satisfy an old declaration with no placement row.
        let mut file_at = conn.prepare_cached(
            "SELECT 1 FROM workspace_file_versions
             WHERE workspace_id = ?1 AND lang = 'rust' AND generation = ?2
               AND rel_path = ?3 AND valid_from <= ?4
               AND (valid_until IS NULL OR valid_until > ?4) LIMIT 1",
        )?;
        let mut exists_at = |path: &str, revision: i64| -> Result<bool> {
            Ok(file_at
                .query_row(
                    params![
                        snapshot.workspace_id.as_str(),
                        snapshot.generation.0,
                        path,
                        revision
                    ],
                    |_| Ok(()),
                )
                .optional()?
                .is_some())
        };
        let mut path_events = Vec::new();
        let mut created = Vec::new();
        for path in &rust_paths {
            let existed = exists_at(path, from_revision)?;
            let exists = exists_at(path, snapshot.revision)?;
            if !existed && exists {
                created.push(path.to_string());
            }
            if !existed || !exists {
                path_events.push(path.as_str());
            }
        }
        if !path_events.is_empty() {
            let inputs = load_selected_cargo_inputs(&conn, snapshot)?;
            for manifest in &inputs.manifests {
                let Some(package) = &manifest.facts.package else {
                    continue;
                };
                let directory = manifest.relative_path.parent().unwrap_or(Path::new(""));
                let directory_key =
                    brokk_bifrost_rust::cargo_routes::rust_case_fold_key(&stable_path(directory));
                for path in &path_events {
                    let key = brokk_bifrost_rust::cargo_routes::rust_case_fold_key(path);
                    let relative = Path::new(&key).strip_prefix(Path::new(&directory_key)).ok();
                    let matches_root = |root: &Path| {
                        brokk_bifrost_rust::selected_context::normalize_selected_path(
                            directory, root,
                        )
                        .is_some_and(|root| {
                            brokk_bifrost_rust::cargo_routes::rust_case_fold_key(&stable_path(
                                &root,
                            )) == key
                        })
                    };
                    if relative.is_some_and(|relative| {
                        brokk_bifrost_rust::cargo_routes::auto_cargo_target_kind(
                            relative, true, true, true, true,
                        )
                        .is_some()
                    }) || matches_root(&package.library_path)
                        || package.build_script.as_deref().is_some_and(matches_root)
                        || package.explicit_targets.iter().any(|target| {
                            target.candidate_paths.iter().any(|root| matches_root(root))
                        })
                    {
                        return Ok(CrateReconcileScope::Everything);
                    }
                }
            }
        }
        let mut reached = HashSet::new();
        let mut probes = conn.prepare_cached(
            "SELECT versions.crate_key FROM rust_crate_path_probes AS probes
             JOIN rust_crate_versions AS versions USING(topology_id)
             WHERE probes.probe_key = ?3 AND versions.workspace_id = ?1
               AND versions.lang = 'rust' AND versions.generation = ?2
               AND versions.valid_until IS NULL",
        )?;
        for path in path_events {
            for key in probes.query_map(
                params![
                    snapshot.workspace_id.as_str(),
                    snapshot.generation.0,
                    brokk_bifrost_rust::cargo_routes::rust_case_fold_key(path)
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )? {
                reached.insert(crate_key_from_row(key?)?);
            }
        }
        let mut statement = conn.prepare_cached(SQL_RUST_CRATE_TOPOLOGIES_FOR_PATH)?;
        for path in rust_paths {
            for key in statement.query_map(
                params![
                    snapshot.workspace_id.as_str(),
                    snapshot.generation.0,
                    path.as_str()
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )? {
                reached.insert(crate_key_from_row(key?)?);
            }
        }
        Ok(CrateReconcileScope::Reached {
            crates: reached,
            from_revision,
            created,
        })
    }

    fn reconcile_rust_crates_in_scope(
        &self,
        snapshot: &WorkspaceSnapshotId,
        scope: CrateReconcileScope,
    ) -> Result<super::unit_summaries::UnitSummaryReconciliation> {
        let carried_context =
            brokk_bifrost_core::analyzer::carried_context::CarriedContext::current();
        assert_eq!(snapshot.lang, "rust");
        let started = std::time::Instant::now();
        let scope_kind = match &scope {
            CrateReconcileScope::Everything => "Everything".to_owned(),
            CrateReconcileScope::Reached { from_revision, .. } => {
                format!("Reached from revision {from_revision}")
            }
        };
        let snapshots = WorkspaceSnapshots::from_iter([("rust".to_string(), snapshot.clone())]);
        let prelude_timing = crate::profiling::scope("rust_crates.reconcile.inputs");
        let (crates, paths, epoch, inventory_errors, naming, configuration, broad_targets) = {
            let conn = self.read_conn_for_workspace(&snapshots)?;
            #[cfg(any(test, feature = "test-support"))]
            let _trace =
                StatementTrace::new(&conn, self.crate_statement_counter.lock().unwrap().clone());
            let SelectedCargoInputs {
                manifests,
                configuration_files,
                mut inventory_errors,
                manifest_versions,
            } = load_selected_cargo_inputs(&conn, snapshot)?;
            let paths = conn
                .prepare_cached(SQL_SELECTED_WORKSPACE_FILE_VERSIONS_3)?
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let naming =
                brokk_bifrost_rust::crate_naming::RustSelectedCargoNaming::from_selected_inputs(
                    paths.iter().map(|(path, _)| PathBuf::from(path)),
                    &manifests,
                )
                .map_err(StoreError::new)?;
            let configuration = RustCargoConfiguration::from_files(configuration_files);
            let epoch: String = conn
                .prepare_cached(SQL_ANALYSIS_EPOCHS_4)?
                .query_row([], |row| row.get(0))?;
            let manifest_map: std::collections::BTreeMap<_, _> = manifests
                .iter()
                .map(|manifest| (manifest.relative_path.clone(), manifest.clone()))
                .collect();
            let source_paths: BTreeSet<_> = paths
                .iter()
                .filter(|(path, _)| path.ends_with(".rs"))
                .map(|(path, _)| PathBuf::from(path))
                .collect();
            // These rows belong to this exact listing revision. A missing or
            // unreadable certificate remains workspace-wide incomplete below.
            let listing_failures = Self::rust_source_listing_failures_on(
                &conn,
                snapshot,
                super::RUST_SOURCE_LISTING_DERIVATION_VERSION,
            )?;
            let broad_targets: HashMap<_, _> = manifests
                .iter()
                .map(|manifest| {
                    (
                        manifest.relative_path.clone(),
                        rust_broad_target_discovery_complete(
                            manifest,
                            &manifest_map,
                            &source_paths,
                        ) && listing_failures.as_ref().is_none_or(|failures| {
                            failures.iter().all(|(prefix, reason)| {
                                reason != "omission: SymlinkToDirectory"
                                    || !brokk_bifrost_rust::selected_context::rust_directory_omission_affects_cargo(
                                        manifest, &manifest_map, Path::new(prefix),
                                    )
                            })
                        }),
                    )
                })
                .collect();
            let targets = rust_crate_targets(
                paths
                    .iter()
                    .map(|(path, oid)| Ok((PathBuf::from(path), Oid::from_str(oid)?)))
                    .collect::<Result<Vec<_>>>()?,
                manifests,
                &configuration,
            );
            let targets = match targets {
                Ok(targets) => targets,
                Err(error) => {
                    inventory_errors.push(error);
                    Vec::new()
                }
            };
            let libraries: HashMap<_, _> = targets
                .iter()
                .filter(|target| target.kind == RustCallerTargetKind::Library)
                .map(|target| (target.manifest_path.clone(), crate_key(target)))
                .collect();
            let crates = targets
                .into_iter()
                .map(|target| {
                    let key = crate_key(&target);
                    let dependencies = target
                        .dependencies
                        .iter()
                        .map(|dependency| {
                            (
                                dependency.extern_name.clone(),
                                dependency_kind(dependency.kind),
                                dependency
                                    .manifest_path
                                    .as_ref()
                                    .and_then(|manifest| libraries.get(manifest))
                                    .copied(),
                            )
                        })
                        .collect();
                    PreparedCrate {
                        key,
                        inventory_error: target.inventory_error.clone(),
                        forced: false,
                        manifest_version: manifest_versions.get(&target.manifest_path).copied(),
                        dependencies,
                        target,
                    }
                })
                .collect::<Vec<_>>();
            (
                crates,
                paths,
                epoch,
                inventory_errors,
                naming,
                configuration,
                broad_targets,
            )
        };
        // The case-fold keys of the selected Rust paths, for the module
        // candidates that match a selected file only by case. It lives for this
        // pass, beside the selected paths it is built from.
        let folded_paths: HashSet<String> = paths
            .iter()
            .map(|(path, _)| brokk_bifrost_rust::cargo_routes::rust_case_fold_key(path))
            .collect();
        drop(prelude_timing);
        let waves_timing = crate::profiling::scope("rust_crates.reconcile.waves");
        let schedule = Connection::open_in_memory()?;
        schedule.execute_batch(unit_schedule::SCHEMA_SQL)?;
        schedule.execute_batch(RUST_SCHEDULE_SCHEMA_SQL)?;
        // Targets are an input query result only until their normalized rows
        // have been staged. No target or topology arena survives into waves.
        for (ordinal, item) in crates.into_iter().enumerate() {
            stage_crate(&schedule, ordinal as i64, &item)?;
        }
        schedule.execute_batch("INSERT INTO temp.unit_schedule_units SELECT unit_id FROM temp.rust_schedule_targets;
            INSERT INTO temp.unit_schedule_edges
            SELECT DISTINCT owner.unit_id, dependency.unit_id, 1
            FROM temp.rust_schedule_dependencies AS edges
            JOIN temp.rust_schedule_targets AS owner ON owner.crate_key = edges.crate_key
            JOIN temp.rust_schedule_targets AS dependency ON dependency.crate_key = edges.dependency_key;")?;
        unit_schedule::build(&schedule)?;
        let (from_revision, created) = match scope {
            CrateReconcileScope::Everything => {
                schedule
                    .prepare_cached(
                        "UPDATE temp.rust_schedule_targets SET reached = 1, pending = 1",
                    )?
                    .execute([])?;
                (None, Vec::new())
            }
            CrateReconcileScope::Reached {
                crates,
                from_revision,
                created,
            } => {
                for key in crates {
                    schedule
                        .prepare_cached("INSERT INTO temp.rust_schedule_reached VALUES(?1)")?
                        .execute([key.as_slice()])?;
                }
                schedule.execute_batch("INSERT OR IGNORE INTO temp.rust_schedule_reached
                    SELECT peers.crate_key FROM temp.rust_schedule_reached AS seeds
                    JOIN temp.rust_schedule_targets AS target ON target.crate_key = seeds.crate_key
                    JOIN temp.unit_schedule_components AS component ON component.unit_id = target.unit_id
                    JOIN temp.unit_schedule_components AS member ON member.component_id = component.component_id
                    JOIN temp.rust_schedule_targets AS peers ON peers.unit_id = member.unit_id;
                    UPDATE temp.rust_schedule_targets SET reached = 1, pending = 1
                    WHERE crate_key IN (SELECT crate_key FROM temp.rust_schedule_reached);")?;
                {
                    let source = self.read_conn_for_workspace(&snapshots)?;
                    let mut query = source.prepare_cached(SQL_RUST_CRATE_LIVE_TOPOLOGIES)?;
                    let mut rows = query.query(params![
                        snapshot.workspace_id.as_str(),
                        snapshot.generation.0
                    ])?;
                    while let Some(row) = rows.next()? {
                        schedule
                            .prepare_cached(
                                "INSERT INTO temp.rust_schedule_previous VALUES(?1,?2,?3)",
                            )?
                            .execute(params![
                                row.get::<_, Vec<u8>>(0)?,
                                row.get::<_, i64>(1)?,
                                row.get::<_, Vec<u8>>(2)?
                            ])?;
                    }
                }
                schedule.execute_batch("INSERT INTO temp.rust_schedule_live
                    SELECT * FROM temp.rust_schedule_previous WHERE crate_key NOT IN (SELECT crate_key FROM temp.rust_schedule_reached);
                    INSERT INTO temp.rust_schedule_detached
                    SELECT previous.topology_id FROM temp.rust_schedule_previous AS previous
                    JOIN temp.rust_schedule_reached USING(crate_key)
                    WHERE NOT EXISTS (SELECT 1 FROM temp.rust_schedule_targets AS targets WHERE targets.crate_key = previous.crate_key);")?;
                (Some(from_revision), created)
            }
        };
        schedule.prepare_cached("INSERT INTO temp.rust_schedule_pending_order(unit_id) SELECT unit_id FROM temp.rust_schedule_targets WHERE pending = 1 ORDER BY unit_id")?.execute( [])?;
        let schedule = Mutex::new(schedule);
        let mut forced_cycles = Vec::new();
        let mut forced_unavailable = Vec::new();
        let mut derived_count = 0;
        loop {
            let wave_count = {
                let conn = schedule.lock().unwrap();
                if conn.prepare_cached("SELECT NOT EXISTS(SELECT 1 FROM temp.rust_schedule_targets WHERE pending = 1)")?.query_row(
                    [],
                    |row| row.get::<_, bool>(0),
                )? {
                    break;
                }
                conn.execute_batch(
                    "DELETE FROM temp.rust_schedule_blocked; DELETE FROM temp.rust_schedule_wave;",
                )?;
                if from_revision.is_some() {
                    let source_conn = self.read_conn_for_workspace(&snapshots)?;
                    let source = source_conn.unchecked_transaction()?;
                    source.execute_batch(CREATE_PENDING_CRATES_SQL)?;
                    source
                        .prepare_cached("DELETE FROM temp.rust_crate_pending_keys")?
                        .execute([])?;
                    {
                        let mut query = conn.prepare_cached(
                            "SELECT targets.crate_key, leader.crate_key
                        FROM temp.rust_schedule_targets AS targets
                        JOIN temp.unit_schedule_components AS component USING(unit_id)
                        JOIN temp.rust_schedule_targets AS leader ON leader.unit_id = (
                            SELECT min(member.unit_id) FROM temp.unit_schedule_components AS member
                            WHERE member.component_id = component.component_id)
                        WHERE targets.pending = 1",
                        )?;
                        let mut rows = query.query([])?;
                        while let Some(row) = rows.next()? {
                            source
                                .prepare_cached(INSERT_PENDING_CRATE_SQL)?
                                .execute(params![
                                    row.get::<_, Vec<u8>>(0)?,
                                    row.get::<_, Vec<u8>>(1)?
                                ])?;
                        }
                        let mut blocked =
                            source.prepare_cached(SQL_RUST_CRATE_PENDING_ANCESTORS)?;
                        let rows = blocked.query_map(
                            params![
                                snapshot.workspace_id.as_str(),
                                snapshot.generation.0,
                                snapshot.revision
                            ],
                            |row| row.get::<_, Vec<u8>>(0),
                        )?;
                        for key in rows {
                            conn.prepare_cached(
                                "INSERT INTO temp.rust_schedule_blocked VALUES(?1)",
                            )?
                            .execute([key?])?;
                        }
                    }
                    source.rollback()?;
                }
                let ready = conn.prepare_cached(RUST_READY_WAVE_SQL)?.execute([])?;
                if ready == 0 {
                    // Rust forces exactly one dependency-ready component once.
                    // Its members cannot consume each other's outputs.
                    let component: i64 = conn
                        .prepare_cached(RUST_FORCE_COMPONENT_SQL)?
                        .query_row([], |row| row.get(0))?;
                    conn.prepare_cached(
                        "INSERT INTO temp.rust_schedule_wave
                        SELECT targets.unit_id, 1 FROM temp.rust_schedule_targets AS targets
                        JOIN temp.unit_schedule_components AS component USING(unit_id)
                        WHERE targets.pending = 1 AND component.component_id = ?1",
                    )?
                    .execute([component])?;
                    let names = conn.prepare_cached("SELECT targets.crate_name || ':' || targets.target_kind
                        FROM temp.rust_schedule_wave AS wave JOIN temp.rust_schedule_targets AS targets USING(unit_id)
                        ORDER BY targets.unit_id")?.query_map([], |row| row.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
                    let cyclic: bool = conn.prepare_cached("SELECT cyclic FROM temp.unit_schedule_components WHERE component_id = ?1 LIMIT 1")?.query_row( [component], |row| row.get(0))?;
                    if cyclic {
                        forced_cycles.push(names);
                    } else {
                        forced_unavailable.extend(names);
                    }
                }
                conn.execute_batch("DELETE FROM temp.rust_schedule_wave_order;
                    DELETE FROM temp.rust_schedule_outputs;
                    INSERT INTO temp.rust_schedule_wave_order(unit_id)
                    SELECT wave.unit_id FROM temp.rust_schedule_wave AS wave
                    JOIN temp.rust_schedule_pending_order AS pending USING(unit_id) ORDER BY pending.ordinal;")?;
                conn.prepare_cached("SELECT count(*) FROM temp.rust_schedule_wave")?
                    .query_row([], |row| row.get::<_, usize>(0))?
            };
            // Each worker loads one target and streams settled rows into its
            // own TEMP schema. Results stay private until the whole wave ends.
            let failures = install_on_dedicated_build_pool(|| {
                (1..=wave_count)
                    .into_par_iter()
                    .filter_map(|ordinal| {
                        carried_context.run(|| {
                            let derive =
                                || -> Result<()> {
                                    let item = {
                                        let conn = schedule.lock().unwrap();
                                        let (id, forced) = conn
                                            .prepare_cached(WAVE_UNIT_SQL)?
                                            .query_row([ordinal as i64], |row| {
                                                Ok((row.get::<_, i64>(0)?, row.get::<_, bool>(1)?))
                                            })?;
                                        read_staged_crate(&conn, id, forced)?
                                    };
                                    let derived = self.derive_rust_crate(
                                        &item,
                                        &snapshots,
                                        &epoch,
                                        Some(&schedule),
                                        &naming,
                                        &folded_paths,
                                        broad_targets
                                            .get(&item.target.manifest_path)
                                            .copied()
                                            .unwrap_or(false),
                                    )?;
                                    schedule.lock().unwrap().prepare_cached(
                                    "INSERT INTO temp.rust_schedule_outputs VALUES(?1,?2,?3)"
                                )?.execute(
                                    params![
                                        derived.key.as_slice(),
                                        derived.topology_id,
                                        derived.surface.as_slice()
                                    ],
                                )?;
                                    Ok(())
                                };
                            derive().err()
                        })
                    })
                    .collect::<Vec<_>>()
            });
            derived_count += wave_count;
            let conn = schedule.lock().unwrap();
            conn.execute_batch("DELETE FROM temp.rust_schedule_moved;
                INSERT INTO temp.rust_schedule_moved
                SELECT outputs.crate_key FROM temp.rust_schedule_outputs AS outputs
                WHERE NOT EXISTS (SELECT 1 FROM temp.rust_schedule_previous AS previous
                    WHERE previous.crate_key = outputs.crate_key AND previous.surface = outputs.surface);
                INSERT OR REPLACE INTO temp.rust_schedule_live SELECT * FROM temp.rust_schedule_outputs;")?;
            if !failures.is_empty() {
                return Err(StoreError::new(format!(
                    "crate derivation wave failed: {failures:?}"
                )));
            }
            conn.execute_batch("UPDATE temp.rust_schedule_targets SET pending = 0 WHERE unit_id IN (SELECT unit_id FROM temp.rust_schedule_wave);")?;
            if from_revision.is_some() {
                // Only moved public surfaces reach consumers. Expand reached
                // consumers to their components before removing carried rows.
                {
                    let source = self.read_conn_for_workspace(&snapshots)?;
                    let mut moved =
                        conn.prepare_cached("SELECT crate_key FROM temp.rust_schedule_moved")?;
                    let mut keys = moved.query([])?;
                    while let Some(row) = keys.next()? {
                        let key: Vec<u8> = row.get(0)?;
                        let mut query = source.prepare_cached(SQL_RUST_CRATE_DEPENDENTS)?;
                        for key in query.query_map(
                            params![snapshot.workspace_id.as_str(), snapshot.generation.0, key],
                            |row| row.get::<_, Vec<u8>>(0),
                        )? {
                            conn.prepare_cached("INSERT OR IGNORE INTO temp.rust_schedule_next(crate_key) VALUES(?1)")?.execute(
                                [key?],
                            )?;
                        }
                        conn.execute_batch("INSERT OR IGNORE INTO temp.rust_schedule_next(crate_key)
                    SELECT peers.crate_key FROM temp.rust_schedule_next AS next
                    JOIN temp.rust_schedule_targets AS target USING(crate_key)
                    JOIN temp.unit_schedule_components AS component USING(unit_id)
                    JOIN temp.unit_schedule_components AS member ON member.component_id = component.component_id
                    JOIN temp.rust_schedule_targets AS peers ON peers.unit_id = member.unit_id
                    ORDER BY next.ordinal, peers.unit_id;
                    DELETE FROM temp.rust_schedule_next WHERE crate_key IN (SELECT crate_key FROM temp.rust_schedule_reached);
                    DELETE FROM temp.rust_schedule_live WHERE crate_key IN (SELECT crate_key FROM temp.rust_schedule_next);
                    UPDATE temp.rust_schedule_targets SET reached = 1, pending = 1
                    WHERE crate_key IN (SELECT crate_key FROM temp.rust_schedule_next);
                    INSERT INTO temp.rust_schedule_reached SELECT crate_key FROM temp.rust_schedule_next;
                    INSERT OR IGNORE INTO temp.rust_schedule_pending_order(unit_id)
                    SELECT targets.unit_id FROM temp.rust_schedule_next AS next
                    JOIN temp.rust_schedule_targets AS targets USING(crate_key) ORDER BY next.ordinal;
                    DELETE FROM temp.rust_schedule_next;")?;
                    }
                }
            }
        }
        drop(waves_timing);
        let detached_timing = crate::profiling::scope("rust_crates.reconcile.detached");
        // Seed previous placements of reached crates as well as new files: an
        // edit can leave a previously placed file detached without creating it.
        // Cargo placements also absorb carried detached roots. This cannot
        // cascade: retiring a detached topology adds no Cargo placements.
        let detached_paths = {
            let conn = schedule.lock().unwrap();
            conn.prepare_cached("CREATE TEMP TABLE IF NOT EXISTS rust_schedule_paths(path TEXT PRIMARY KEY) WITHOUT ROWID")?.execute( [])?;
            conn.prepare_cached("DELETE FROM temp.rust_schedule_paths")?
                .execute([])?;
            if from_revision.is_some() {
                let source = self.read_conn_for_workspace(&snapshots)?;
                // Created files may have no previous topology to seed them.
                for path in &created {
                    conn.prepare_cached(
                        "INSERT OR IGNORE INTO temp.rust_schedule_paths VALUES(?1)",
                    )?
                    .execute([path])?;
                }
                let mut query = conn.prepare_cached(
                    "SELECT previous.topology_id FROM temp.rust_schedule_previous AS previous
                     JOIN temp.rust_schedule_reached USING(crate_key)",
                )?;
                for id in query.query_map([], |row| row.get::<_, i64>(0))? {
                    for path in source
                        .prepare_cached(SQL_RUST_CRATE_MODULES_5)?
                        .query_map([id?], |row| row.get::<_, String>(0))?
                    {
                        conn.prepare_cached(
                            "INSERT OR IGNORE INTO temp.rust_schedule_paths VALUES(?1)",
                        )?
                        .execute([path?])?;
                    }
                }
            } else {
                for (path, _) in &paths {
                    conn.prepare_cached("INSERT INTO temp.rust_schedule_paths VALUES(?1)")?
                        .execute([path])?;
                }
            }
            let source = self.read_conn_for_workspace(&snapshots)?;
            conn.execute_batch(
                "CREATE TEMP TABLE rust_schedule_cargo_paths(path TEXT PRIMARY KEY) WITHOUT ROWID;",
            )?;
            let mut cargo = conn.prepare_cached(
                "SELECT topology_id FROM temp.rust_schedule_live
                 WHERE crate_key IN
                   (SELECT crate_key FROM temp.rust_schedule_targets WHERE reached = 1)",
            )?;
            for id in cargo.query_map([], |row| row.get::<_, i64>(0))? {
                for path in source
                    .prepare_cached(SQL_RUST_CRATE_MODULES_5)?
                    .query_map([id?], |row| row.get::<_, String>(0))?
                {
                    conn.prepare_cached(
                        "INSERT OR IGNORE INTO temp.rust_schedule_cargo_paths VALUES(?1)",
                    )?
                    .execute([path?])?;
                }
            }
            // Look up detached roots by the placed paths, so the cost follows
            // the reached crates rather than every live crate.
            let mut absorbed = Vec::new();
            let mut placed =
                conn.prepare_cached("SELECT path FROM temp.rust_schedule_cargo_paths")?;
            for path in placed.query_map([], |row| row.get::<_, String>(0))? {
                for id in source
                    .prepare_cached(
                        "SELECT topology.topology_id FROM rust_crate_container_sources AS sources
                         JOIN rust_crate_topologies AS topology USING(topology_id)
                         WHERE sources.rel_path = ?1 AND sources.container_path = 'crate'
                           AND topology.target_kind = 'detached'",
                    )?
                    .query_map([path?], |row| row.get::<_, i64>(0))?
                {
                    absorbed.push(id?);
                }
            }
            for id in absorbed {
                conn.prepare_cached("DELETE FROM temp.rust_schedule_live WHERE topology_id = ?1")?
                    .execute([id])?;
            }
            let mut query =
                conn.prepare_cached("SELECT topology_id FROM temp.rust_schedule_live")?;
            for id in query.query_map([], |row| row.get::<_, i64>(0))? {
                for path in source
                    .prepare_cached(SQL_RUST_CRATE_MODULES_5)?
                    .query_map([id?], |row| row.get::<_, String>(0))?
                {
                    conn.prepare_cached("DELETE FROM temp.rust_schedule_paths WHERE path = ?1")?
                        .execute([path?])?;
                }
            }
            conn.prepare_cached("SELECT path FROM temp.rust_schedule_paths ORDER BY path")?
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        for path in detached_paths {
            // A reached detached root may have been deleted; retiring its old
            // version is enough, and no new topology can be derived for it.
            if paths
                .binary_search_by(|(selected, _)| selected.cmp(&path))
                .is_err()
            {
                continue;
            }
            let root_path = PathBuf::from(&path);
            // No Cargo workspace owns the file, so the configuration of a
            // build started beside it applies.
            let cfg_atoms =
                configuration.cfg_atoms(root_path.parent().expect("a file has a directory"));
            let target = RustCrateTarget {
                manifest_path: root_path.clone(),
                root_path,
                kind: RustCallerTargetKind::Detached,
                name: path.clone(),
                edition: RustCargoEdition::Rust2021,
                cfg_atoms,
                features: BTreeSet::new(),
                dependencies: Vec::new(),
                inventory_complete: true,
                inventory_error: None,
            };
            let item = PreparedCrate {
                key: crate_key(&target),
                manifest_version: None,
                inventory_error: (!inventory_errors.is_empty())
                    .then(|| format!("{inventory_errors:?}")),
                dependencies: Vec::new(),
                forced: false,
                target,
            };
            // A detached unit has no manifest: its only target is the file itself,
            // so target discovery is complete by construction.
            let result = self.derive_rust_crate(
                &item,
                &snapshots,
                &epoch,
                None,
                &naming,
                &folded_paths,
                true,
            )?;
            derived_count += 1;
            schedule
                .lock()
                .unwrap()
                .prepare_cached("INSERT OR REPLACE INTO temp.rust_schedule_live VALUES(?1,?2,?3)")?
                .execute(params![
                    result.key.as_slice(),
                    result.topology_id,
                    result.surface.as_slice()
                ])?;
        }
        drop(detached_timing);
        let close_timing = crate::profiling::scope("rust_crates.reconcile.close_versions");
        let summary_snapshot = snapshot.clone();
        let snapshot = snapshot.clone();
        {
            let conn = schedule.lock().unwrap();
            let source = self.read_conn_for_workspace(&snapshots)?;
            let mut query = source.prepare_cached(SQL_RUST_CRATE_VERSIONS_6)?;
            for row in query.query_map(
                params![snapshot.workspace_id.as_str(), snapshot.generation.0],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
            )? {
                let (key, opened) = row?;
                if !conn
                    .prepare_cached(
                        "SELECT EXISTS(SELECT 1 FROM temp.rust_schedule_live WHERE crate_key = ?1)",
                    )?
                    .query_row([&key], |row| row.get::<_, bool>(0))?
                {
                    conn.prepare_cached("INSERT INTO temp.rust_schedule_retire VALUES(?1,?2)")?
                        .execute(params![key, opened])?;
                }
            }
        }
        let live_count: usize = schedule
            .lock()
            .unwrap()
            .prepare_cached("SELECT count(*) FROM temp.rust_schedule_live")?
            .query_row([], |row| row.get(0))?;
        #[cfg(any(test, feature = "test-support"))]
        let counter = self.crate_statement_counter.lock().unwrap().clone();
        self.execute_selection_publication(move |conn| -> Result<()> {
            let tx = conn.transaction()?;
            let _owner = super::sealed_families::Scope::new(
                &tx,
                super::sealed_families::Owner::CrateTopology,
            );
            #[cfg(any(test, feature = "test-support"))]
            let trace = StatementTrace::new(&tx, counter);
            let schedule = schedule.into_inner().unwrap();
            {
                let mut query = schedule
                    .prepare_cached("SELECT crate_key,opened FROM temp.rust_schedule_retire")?;
                for row in query.query_map([], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
                })? {
                    let (key, opened) = row?;
                    end_open_crate_version(&tx, &snapshot, &key, opened)?;
                }
            }
            let marker = params![
                snapshot.workspace_id.as_str(),
                snapshot.generation.0,
                snapshot.revision,
                derivation_version()
            ];
            match from_revision {
                None => tx
                    .prepare_cached(SQL_RUST_CRATE_RECONCILIATION_RECORD)?
                    .execute(marker)?,
                // A scoped pass is only as current as the rows it started
                // from, so it moves the marker only from the revision it
                // started at. After a failed or skipped pass the marker stays
                // behind the head, and the next start runs the full pass.
                Some(from_revision) => tx
                    .prepare_cached(SQL_RUST_CRATE_RECONCILIATION_ADVANCE)?
                    .execute(params![
                        snapshot.workspace_id.as_str(),
                        snapshot.generation.0,
                        snapshot.revision,
                        derivation_version(),
                        from_revision
                    ])?,
            };
            #[cfg(any(test, feature = "test-support"))]
            drop(trace);
            #[cfg(any(test, debug_assertions, feature = "test-support"))]
            drop(_owner);
            tx.commit()?;
            Ok(())
        })?;
        drop(close_timing);
        crate::profiling::note_with(|| {
            format!(
                "rust_crates.reconcile: {:.1} ms, scope {scope_kind}, {} crates, {} derived, \
                 forced_cycles={forced_cycles:?}, forced_unavailable={forced_unavailable:?}",
                started.elapsed().as_secs_f64() * 1000.0,
                live_count,
                derived_count
            )
        });
        self.reconcile_rust_unit_summaries(&summary_snapshot)
    }

    /// Run the module walk to a fixpoint over its item-position macro
    /// invocations.
    ///
    /// Each pass decides visible passthroughs, no-item invocations, and
    /// invocations whose same-named local macro is proven unavailable. The
    /// decisions change gated routes, which changes the mounted files and
    /// therefore the next pass's scope. Recompute until both the module
    /// placements and their macro decisions reach a fixed point.
    fn walk_crate_modules(
        &self,
        conn: &Connection,
        root_path: String,
        cfg: &str,
    ) -> Result<(Vec<WalkRow>, Vec<ItemMacroDecision>)> {
        let mut decisions: Vec<ItemMacroDecision> = Vec::new();
        loop {
            let admitted = serde_json::Value::Array(
                decisions
                    .iter()
                    .map(|decision| {
                        serde_json::json!([
                            decision.blob_id,
                            decision.invocation_occurrence_id,
                            decision.decoration_cfg,
                            decision.no_route
                        ])
                    })
                    .collect(),
            )
            .to_string();
            let rows =
                conn.prepare_cached(MODULE_WALK_SQL)?
                    .query_map(params![root_path, cfg, admitted], |row| {
                        Ok(WalkRow {
                            module_path: row.get(0)?,
                            blob: row.get(1)?,
                            scope: row.get(2)?,
                            path: row.get(3)?,
                            placement: row.get(4)?,
                            mount_blob: row.get(5)?,
                            mount_start: row.get(6)?,
                            activation: row.get(7)?,
                            parent_path: row.get(8)?,
                            frontier: row.get(9)?,
                            depth_capped: row.get(10)?,
                            path_candidates: serde_json::from_str(&row.get::<_, String>(11)?)
                                .map_err(|error| {
                                    rusqlite::Error::FromSqlConversionFailure(
                                        11,
                                        rusqlite::types::Type::Text,
                                        Box::new(error),
                                    )
                                })?,
                        })
                    })?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
            // Only an active placement carries macro scope: a module the walk
            // left inactive, duplicated or undecided is not a member, so its
            // file neither inherits the mounting file's `macro_rules!` nor
            // offers its own invocations for decision.
            let counts = active_placement_counts(&rows);
            let mounted = rows
                .iter()
                .filter(|row| row.frontier && row.placement_gap(&counts).is_none());
            let mounts = serde_json::Value::Array(
                mounted
                    .clone()
                    .filter_map(|row| {
                        (row.placement != "include").then_some(())?;
                        Some(serde_json::json!([
                            row.blob?,
                            row.mount_blob?,
                            row.mount_start?
                        ]))
                    })
                    .collect(),
            )
            .to_string();
            let members = serde_json::Value::Array(
                mounted
                    .filter_map(|row| row.blob.map(serde_json::Value::from))
                    .collect(),
            )
            .to_string();
            let decided = conn
                .prepare_cached(ITEM_MACRO_DECISIONS_SQL)?
                .query_map(params![mounts, members], |row| {
                    Ok(ItemMacroDecision {
                        blob_id: row.get(0)?,
                        invocation_occurrence_id: row.get(1)?,
                        decoration_cfg: row.get(2)?,
                        no_route: row.get(3)?,
                    })
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if decided == decisions {
                return Ok((rows, decided));
            }
            decisions = decided;
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn derive_rust_crate(
        &self,
        item: &PreparedCrate,
        snapshots: &WorkspaceSnapshots,
        epoch: &str,
        schedule: Option<&Mutex<Connection>>,
        naming: &brokk_bifrost_rust::crate_naming::RustSelectedCargoNaming,
        folded_paths: &HashSet<String>,
        broad_target_complete: bool,
    ) -> Result<DerivedCrate> {
        let _crate_timing = crate::profiling::scope_with(|| {
            format!(
                "rust_crates.crate name={} kind={} root={}",
                item.target.name,
                target_kind(item.target.kind),
                stable_path(&item.target.root_path)
            )
        });
        let mut conn = self.read_conn_for_workspace(snapshots)?;
        conn.use_derivation_mmap()?;
        conn.execute_batch("CREATE TEMP TABLE IF NOT EXISTS rust_schedule_live(crate_key BLOB PRIMARY KEY, topology_id INTEGER NOT NULL, surface BLOB NOT NULL) WITHOUT ROWID, STRICT;
            DELETE FROM temp.rust_schedule_live;")?;
        conn.cleanup_before_checkin("DELETE FROM temp.rust_schedule_live");
        if let Some(schedule) = schedule {
            let schedule = schedule.lock().unwrap();
            let mut query = schedule.prepare_cached(
                "SELECT crate_key, topology_id, surface FROM temp.rust_schedule_live",
            )?;
            let mut rows = query.query([])?;
            while let Some(row) = rows.next()? {
                conn.prepare_cached("INSERT INTO temp.rust_schedule_live VALUES(?1,?2,?3)")?
                    .execute(params![
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?
                    ])?;
            }
        }
        #[cfg(any(test, feature = "test-support"))]
        let trace =
            StatementTrace::new(&conn, self.crate_statement_counter.lock().unwrap().clone());
        debug_assert!(
            conn.prepare_cached(LIVE_SURFACE_SQL)?
                .query_row([item.key.as_slice()], |_| Ok(()))
                .optional()?
                .is_none(),
            "a crate is published only after its own derivation returns"
        );
        debug_assert_crate_functions(&conn);
        let mut atoms = item.target.cfg_atoms.clone();
        atoms.extend(
            item.target
                .features
                .iter()
                .map(|feature| format!("feature = {feature:?}")),
        );
        let cfg = serde_json::to_string(&atoms).expect("cfg strings serialize");
        let (rows, gate_decisions) = {
            let _timing = crate::profiling::scope_with(|| {
                format!(
                    "rust_crates.module_walk name={} kind={}",
                    item.target.name,
                    target_kind(item.target.kind)
                )
            });
            self.walk_crate_modules(&conn, stable_path(&item.target.root_path), &cfg)?
        };
        let mut path_probes = HashSet::new();
        path_probes.insert(brokk_bifrost_rust::cargo_routes::rust_case_fold_key(
            &stable_path(&item.target.root_path),
        ));
        for row in &rows {
            for path in row.path.iter().chain(row.path_candidates.iter()) {
                path_probes.insert(brokk_bifrost_rust::cargo_routes::rust_case_fold_key(path));
            }
        }
        let counts = active_placement_counts(&rows);
        let mut modules = Vec::new();
        let mut gaps = Vec::new();
        if let Some(error) = &item.inventory_error {
            gaps.push(Gap {
                kind: "unsupported_manifest",
                subject: stable_path(&item.target.root_path),
                detail: serde_json::json!({"reason": error}).to_string(),
            });
        }
        for row in rows.iter().filter(|row| row.frontier) {
            let WalkRow {
                module_path,
                blob,
                scope,
                path,
                placement,
                activation,
                parent_path,
                ..
            } = row;
            if let Some(kind) = row.placement_gap(&counts) {
                gaps.push(Gap {
                    kind,
                    subject: module_path.clone(),
                    detail: if kind == "unknown_activation" {
                        serde_json::json!({"subject_level": "binding", "path": path, "activation": activation})
                    } else {
                        serde_json::json!({"path": path, "activation": activation})
                    }.to_string(),
                });
            } else {
                assert_eq!(
                    parent_path.is_none(),
                    module_path == "crate",
                    "only the crate root has no declaring module: {module_path}"
                );
                modules.push(Member {
                    module_path: module_path.clone(),
                    blob_id: blob.expect("placed module has blob"),
                    scope: *scope,
                    rel_path: path.clone().expect("placed module has path"),
                    placement: placement.clone(),
                    parent_path: parent_path.clone(),
                });
            }
        }
        for (name, _, key) in &item.dependencies {
            if key.is_none() {
                gaps.push(Gap {
                    kind: "external_dependency",
                    subject: name.clone(),
                    detail: "{}".into(),
                });
            }
        }
        let mut digest = Sha256::new();
        hash_cell(&mut digest, epoch.as_bytes());
        hash_cell(&mut digest, derivation_version().as_bytes());
        hash_cell(&mut digest, &item.key);
        hash_cell(&mut digest, edition(item.target.edition).as_bytes());
        hash_cell(&mut digest, cfg.as_bytes());
        if let Some(error) = &item.inventory_error {
            hash_cell(&mut digest, error.as_bytes());
        }
        let listing_complete = match Self::rust_source_listing_failures_on(
            &conn,
            &snapshots["rust"],
            super::RUST_SOURCE_LISTING_DERIVATION_VERSION,
        )? {
            None => false,
            Some(failures) => failures.iter().all(|(prefix, reason)| {
                if reason != "omission: SymlinkToDirectory" {
                    return false;
                }
                let prefix = PathBuf::from(
                    brokk_bifrost_rust::cargo_routes::rust_omission_path_key(prefix),
                );
                // A missing descendant cannot bound its own routes. Likewise
                // an unknown activation or a capped walk may hide any path.
                let unbounded = rows
                    .iter()
                    .any(|row| row.depth_capped || row.activation < 0 || row.blob.is_none());
                !unbounded
                    && !path_probes.iter().any(|candidate| {
                        Path::new(&brokk_bifrost_rust::cargo_routes::rust_omission_path_key(
                            candidate,
                        ))
                        .starts_with(&prefix)
                    })
            }),
        };
        let mut published_facts = true;
        for row in &rows {
            if let Some(blob) = row.blob {
                let published = conn
                    .prepare_cached("SELECT publication_state = 'complete' FROM source_fact_manifests WHERE blob_id = ?1")?
                    .query_row(
                        [blob],
                        |entry| entry.get::<_, bool>(0),
                    )
                    .optional()?
                    .unwrap_or(false);
                published_facts &= published;
            } else if let Some(path) = &row.path {
                let listed: bool = conn.prepare_cached("SELECT EXISTS(SELECT 1 FROM selected_workspace_file_versions WHERE lang = 'rust' AND rel_path = ?1)")?.query_row(
                    [path],
                    |entry| entry.get(0),
                )?;
                published_facts &= !listed;
            } else {
                // A module or include! target the selection lacks proves
                // absence only when the listing certificate covers the names of
                // its candidates. A symlink or a file such as gen.inc may still
                // be Rust. The candidates of one row normally agree; requiring
                // all of them fails closed when they do not. An active row with
                // no candidates names a path the workspace cannot represent (an
                // escaping or absolute #[path] or include!), which the listing
                // cannot certify absent.
                published_facts &= (row.activation == 0 || !row.path_candidates.is_empty())
                    && row.path_candidates.iter().all(|candidate| {
                        brokk_bifrost_rust::cargo_routes::is_rust_listing_path(Path::new(candidate))
                    });
            }
            // A candidate the walk did not take that equals a selected file
            // ignoring case is unproven whatever its name: a case-insensitive
            // volume compiles that file, and the walk's exact join cannot tell
            // which volume the selection came from (see `rust_case_fold_key`,
            // which the per-unit path facts share). That holds beside a taken
            // candidate too: `mod foo;` with foo.rs and Foo/mod.rs selected
            // names two files there. A fold hit is rare, so only then is the
            // candidate checked for an exact selected file, which the walk
            // places itself.
            for candidate in &row.path_candidates {
                if row.path.as_deref() == Some(candidate.as_str())
                    || !folded_paths.contains(
                        &brokk_bifrost_rust::cargo_routes::rust_case_fold_key(candidate),
                    )
                {
                    continue;
                }
                let exact: bool = conn
                    .prepare_cached(
                        "SELECT EXISTS(SELECT 1 FROM selected_workspace_file_versions
                         WHERE lang = 'rust' AND rel_path = ?1)",
                    )?
                    .query_row([candidate], |entry| entry.get(0))?;
                published_facts &= exact;
            }
        }
        let broad_complete = broad_target_complete
            && listing_complete
            && published_facts
            && rows.iter().all(|row| !row.depth_capped)
            && !item.forced
            && item.inventory_error.is_none();
        hash_cell(&mut digest, &[u8::from(broad_complete)]);
        let mut broad_row_digests = Vec::with_capacity(rows.len());
        for row in &rows {
            let mut row_digest = Sha256::new();
            for value in [
                row.module_path.as_bytes(),
                row.path.as_deref().unwrap_or("").as_bytes(),
                row.placement.as_bytes(),
                row.parent_path.as_deref().unwrap_or("").as_bytes(),
            ] {
                hash_cell(&mut row_digest, value);
            }
            for value in [
                row.activation,
                row.scope,
                i64::from(row.depth_capped),
                row.mount_start.unwrap_or(-1),
                i64::from(row.frontier),
            ] {
                hash_cell(&mut row_digest, &value.to_le_bytes());
            }
            if let Some(mount_blob) = row.mount_blob {
                let oid: String = conn
                    .prepare_cached(SQL_BLOBS_8)?
                    .query_row([mount_blob], |entry| entry.get(0))?;
                hash_cell(&mut row_digest, oid.as_bytes());
            } else {
                hash_cell(&mut row_digest, b"no_mount");
            }
            if let Some(blob) = row.blob {
                let oid: String = conn
                    .prepare_cached(SQL_BLOBS_8)?
                    .query_row([blob], |entry| entry.get(0))?;
                hash_cell(&mut row_digest, oid.as_bytes());
            } else if let Some(path) = &row.path {
                // The selected file can exist before its source facts publish a
                // blob row. Its OID still belongs to the topology identity.
                let oid: String = conn
                    .prepare_cached(
                        "SELECT blob_oid FROM selected_workspace_file_versions
                     WHERE lang = 'rust' AND rel_path = ?1",
                    )?
                    .query_row([path], |entry| entry.get(0))?;
                hash_cell(&mut row_digest, oid.as_bytes());
            } else {
                hash_cell(&mut row_digest, b"unplaced");
            }
            broad_row_digests.push(row_digest.finalize().to_vec());
        }
        broad_row_digests.sort_unstable();
        for row_digest in broad_row_digests {
            hash_cell(&mut digest, &row_digest);
        }
        for member in &modules {
            hash_cell(&mut digest, member.module_path.as_bytes());
            let oid: String = conn
                .prepare_cached(SQL_BLOBS_8)?
                .query_row([member.blob_id], |row| row.get(0))?;
            hash_cell(&mut digest, oid.as_bytes());
            hash_cell(&mut digest, member.rel_path.as_bytes());
            hash_cell(&mut digest, member.placement.as_bytes());
        }
        for (name, kind, key) in &item.dependencies {
            hash_cell(&mut digest, name.as_bytes());
            hash_cell(&mut digest, kind.as_bytes());
            if let Some(key) = key {
                hash_cell(&mut digest, key);
                if let Some(surface) = conn
                    .prepare_cached(LIVE_SURFACE_SQL)?
                    .query_row([key.as_slice()], |row| row.get::<_, Vec<u8>>(0))
                    .optional()?
                {
                    hash_cell(&mut digest, &surface);
                } else {
                    hash_cell(&mut digest, b"unsupported_manifest");
                    gaps.push(Gap {
                        kind: "unsupported_manifest",
                        subject: name.clone(),
                        detail: serde_json::json!({"unavailable_dependency_crate_key": key})
                            .to_string(),
                    });
                }
            }
        }
        let mut naming_rows = Vec::new();
        let mut named_paths = HashSet::new();
        for member in &modules {
            if !named_paths.insert(&member.rel_path) {
                continue;
            }
            for path in naming.path_probes(Path::new(&member.rel_path)) {
                path_probes.insert(brokk_bifrost_rust::cargo_routes::rust_case_fold_key(
                    &stable_path(&path),
                ));
            }
            let components = |anchor| -> Result<String> {
                let fq = naming
                    .resolve_package_anchor(anchor, "", Path::new(&member.rel_path))
                    .ok_or_else(|| {
                        StoreError::corrupt("selected member has no naming authority")
                    })?;
                let interner = brokk_bifrost_core::analyzer::fq_name::segment_interner();
                Ok(serde_json::to_string(
                    &fq.segments()
                        .iter()
                        .map(|segment| interner.resolve(*segment).0)
                        .collect::<Vec<_>>(),
                )
                .expect("components serialize"))
            };
            let package =
                components(brokk_bifrost_core::analyzer::PackageAnchor::OwnModule { pop: 0 })?;
            let root = components(brokk_bifrost_core::analyzer::PackageAnchor::CrateRoot)?;
            hash_cell(&mut digest, package.as_bytes());
            hash_cell(&mut digest, root.as_bytes());
            naming_rows.push((member.rel_path.clone(), package, root));
        }
        let digest: CrateKey = digest.finalize().into();
        let root_blob = modules
            .iter()
            .find(|member| member.parent_path.is_none())
            .map(|member| member.blob_id);
        if root_blob.is_none() && !gaps.iter().any(|gap| gap.subject == "crate") {
            gaps.push(Gap {
                kind: "unplaced_module",
                subject: "crate".into(),
                detail: serde_json::json!({
                    "path": stable_path(&item.target.root_path),
                    "activation": 1
                })
                .to_string(),
            });
        }
        let attributes = match root_blob {
            Some(root_blob) => conn
                .prepare_cached(SQL_ROOT_INNER_ATTRIBUTES)?
                .query_map([root_blob], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?,
            None => Vec::new(),
        };
        let prelude = if root_blob.is_none() || attributes.iter().any(|name| name == "no_core") {
            "none"
        } else if attributes.iter().any(|name| name == "no_std") {
            "core"
        } else {
            "std"
        };
        let existing: Option<(i64, Vec<u8>)> = conn
            .prepare_cached(SQL_RUST_CRATE_TOPOLOGIES_9)?
            .query_row([digest.as_slice()], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()?;
        let derived = existing
            .is_none()
            .then(|| derivation::derive_exports(&conn, item, &modules, &gate_decisions, &cfg))
            .transpose()?;
        #[cfg(any(test, feature = "test-support"))]
        drop(trace);
        conn.prepare_cached("DELETE FROM temp.rust_schedule_live")?
            .execute([])?;
        drop(conn);
        let snapshot = snapshots["rust"].clone();
        let key = item.key;
        let manifest_version = item.manifest_version;
        let mut target = item.target.clone();
        target.inventory_complete &= gaps
            .iter()
            .all(|gap| matches!(gap.kind, "inactive_placement" | "external_dependency"));
        target.inventory_complete &= derived
            .as_ref()
            .is_none_or(derivation::ExportRows::inventory_complete);
        let dependencies = item.dependencies.clone();
        let epoch = epoch.to_string();
        #[cfg(any(test, feature = "test-support"))]
        let counter = self.crate_statement_counter.lock().unwrap().clone();
        self.execute_selection_publication(move |conn| -> Result<DerivedCrate> {
            let _timing = crate::profiling::scope_with(|| {
                format!(
                    "rust_crates.publication name={} kind={}",
                    target.name,
                    target_kind(target.kind)
                )
            });
            let tx = conn.transaction()?;
            let _owner = super::sealed_families::Scope::new(
                &tx,
                super::sealed_families::Owner::CrateTopology,
            );
            #[cfg(any(test, feature = "test-support"))]
            let trace = StatementTrace::new(&tx, counter);
            let (topology_id, surface) = if let Some((id, surface)) = existing {
                (id, surface.try_into().expect("schema checks digest length"))
            } else {
                tx.prepare_cached(SQL_RUST_CRATE_TOPOLOGIES_10)?
                    .execute(params![
                        digest.as_slice(),
                        key.as_slice(),
                        epoch,
                        target_kind(target.kind),
                        target.name,
                        edition(target.edition),
                        cfg,
                        target.inventory_complete,
                        prelude,
                        broad_complete
                    ])?;
                let id = tx.last_insert_rowid();
                let mut probes = path_probes.iter();
                loop {
                    let batch = probes
                        .by_ref()
                        .take(64)
                        .map(|key| (id, key))
                        .collect::<Vec<_>>();
                    if batch.is_empty() {
                        break;
                    }
                    assert!(super::row_batch::insert_typed_rows(
                        &tx,
                        "INSERT INTO rust_crate_path_probes(topology_id,probe_key) VALUES",
                        "(?, ?)",
                        &batch,
                        &crate::CancellationToken::default(),
                    )?);
                }
                for (path, package, root) in naming_rows {
                    tx.prepare_cached(INSERT_NAMING_SQL)?
                        .execute(params![id, path, package, root])?;
                }
                let counts = active_placement_counts(&rows);
                for row in &rows {
                    let duplicate_active = row.activation == 1
                        && row.path.is_some()
                        && row.placement_gap(&counts) == Some("duplicate_placement");
                    if (row.activation == 1 && !duplicate_active) || row.path.is_none() {
                        continue;
                    }
                    // Cargo rejects duplicate active module files. Keep each as a
                    // possible broad member without changing selected gaps.
                    tx.prepare_cached(INSERT_INACTIVE_PLACEMENT_SQL)?
                        .execute(params![
                            id,
                            row.module_path,
                            row.path,
                            row.placement,
                            row.mount_blob.unwrap_or(-1),
                            row.mount_start.unwrap_or(-1),
                            row.scope,
                            row.blob,
                            if duplicate_active { -1 } else { row.activation }
                        ])?;
                }
                for member in &modules {
                    if member.placement != "include" {
                        tx.prepare_cached(INSERT_MODULE_SQL)?.execute(params![
                            id,
                            member.module_path,
                            member.placement
                        ])?;
                    }
                }
                for member in modules {
                    tx.prepare_cached(derivation::SQL_RUST_CRATE_MEMBER_IDENTITY)?
                        .execute(params![id, member.module_path, member.blob_id])?;
                    tx.prepare_cached(SQL_RUST_CRATE_MODULES_11)?
                        .execute(params![
                            id,
                            member.module_path,
                            member.blob_id,
                            member.scope,
                            member.rel_path,
                            if member.placement == "include" {
                                "include"
                            } else {
                                "declared"
                            },
                            member.parent_path
                        ])?;
                }
                for (name, kind, dependency) in dependencies {
                    tx.prepare_cached(SQL_RUST_CRATE_DEPENDENCIES_12)?
                        .execute(params![
                            id,
                            name,
                            if dependency.is_some() {
                                "workspace"
                            } else {
                                "external"
                            },
                            dependency.map(|key| key.to_vec()),
                            kind
                        ])?;
                }
                for gap in gaps {
                    derivation::assert_gap_subject_level(gap.kind, &gap.detail);
                    tx.prepare_cached(SQL_RUST_CRATE_GAPS_13)?.execute(params![
                        id,
                        gap.kind,
                        gap.subject,
                        gap.detail
                    ])?;
                }
                let derived = derived.expect("missing topology was derived on its reader");
                let surface = derived.publish(&tx, id)?;
                tx.prepare_cached(SQL_RUST_CRATE_TOPOLOGIES_14)?
                    .execute(params![surface.as_slice(), id])?;
                (id, surface)
            };
            let open: Option<(i64, i64, Option<i64>)> = tx
                .prepare_cached(SQL_RUST_CRATE_VERSIONS_15)?
                .query_row(
                    params![
                        snapshot.workspace_id.as_str(),
                        snapshot.generation.0,
                        key.as_slice()
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            // A manifest-only edit can preserve topology; keep its manifest link
            // live for the route-question currentness check.
            if open.map(|(topology, _, manifest)| (topology, manifest))
                != Some((topology_id, manifest_version))
            {
                if let Some((_, opened, _)) = open {
                    end_open_crate_version(&tx, &snapshot, key.as_slice(), opened)?;
                }
                tx.prepare_cached(SQL_RUST_CRATE_VERSIONS_17)?
                    .execute(params![
                        snapshot.workspace_id.as_str(),
                        snapshot.generation.0,
                        key.as_slice(),
                        snapshot.revision,
                        manifest_version,
                        topology_id
                    ])?;
            }
            #[cfg(any(test, feature = "test-support"))]
            drop(trace);
            #[cfg(any(test, debug_assertions, feature = "test-support"))]
            drop(_owner);
            tx.commit()?;
            Ok(DerivedCrate {
                key,
                topology_id,
                surface,
            })
        })
    }
}

/// End a crate's open version row at the revision a reconcile publishes.
///
/// A validity interval is closed at the revision that superseded it, so a row
/// that opened at an earlier revision is closed at this one. A row that opened
/// at this revision was not superseded: an earlier pass at the same revision
/// wrote it, and this pass replaces it. That is what a derivation-version
/// rotation on a warm store does, because an upgrade changes no file and so
/// opens no revision. `[R, R)` is an empty interval the schema rejects, and the
/// primary key ends in `valid_from`, so that row is withdrawn instead. A row
/// that opened after this revision means the reconcile is publishing an older
/// snapshot than the rows already describe; that is an error, not a row to
/// write beside it.
fn end_open_crate_version(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
    key: &[u8],
    opened: i64,
) -> Result<()> {
    let statement = match opened.cmp(&snapshot.revision) {
        std::cmp::Ordering::Less => SQL_RUST_CRATE_VERSIONS_16,
        std::cmp::Ordering::Equal => SQL_RUST_CRATE_VERSIONS_WITHDRAW,
        std::cmp::Ordering::Greater => {
            return Err(StoreError::new(format!(
                "Rust crate reconcile at revision {} of workspace {} generation {} found crate {key:02x?} \
                 open since the later revision {opened}",
                snapshot.revision,
                snapshot.workspace_id.as_str(),
                snapshot.generation.0
            )));
        }
    };
    let changed = conn.prepare_cached(statement)?.execute(params![
        snapshot.revision,
        snapshot.workspace_id.as_str(),
        snapshot.generation.0,
        key
    ])?;
    assert_eq!(
        changed, 1,
        "crate {key:02x?} must have exactly one open version row"
    );
    Ok(())
}

/// A crate key as the schema guarantees it: exactly 32 bytes.
#[doc(hidden)]
pub fn crate_key_from_row(key: Vec<u8>) -> Result<CrateKey> {
    key.try_into()
        .map_err(|key: Vec<u8>| StoreError::corrupt(format!("crate key is {} bytes", key.len())))
}

fn hash_cell(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_le_bytes());
    digest.update(value);
}
fn crate_key(target: &RustCrateTarget) -> CrateKey {
    let mut digest = Sha256::new();
    for value in [
        stable_path(&target.manifest_path),
        target_kind(target.kind).to_string(),
        target.name.clone(),
    ] {
        hash_cell(&mut digest, value.as_bytes());
    }
    digest.finalize().into()
}
fn target_kind(kind: RustCallerTargetKind) -> &'static str {
    match kind {
        RustCallerTargetKind::Library => "lib",
        RustCallerTargetKind::Binary => "bin",
        RustCallerTargetKind::Test => "test",
        RustCallerTargetKind::Example => "example",
        RustCallerTargetKind::Bench => "bench",
        RustCallerTargetKind::Build => "build",
        RustCallerTargetKind::Detached => "detached",
    }
}
#[doc(hidden)]
pub fn edition(edition: RustCargoEdition) -> &'static str {
    match edition {
        RustCargoEdition::Rust2015 => "2015",
        RustCargoEdition::Rust2018 => "2018",
        RustCargoEdition::Rust2021 => "2021",
        RustCargoEdition::Rust2024 => "2024",
    }
}
fn dependency_kind(kind: RustCargoDependencyKind) -> &'static str {
    match kind {
        RustCargoDependencyKind::Normal => "normal",
        RustCargoDependencyKind::Development => "dev",
        RustCargoDependencyKind::Build => "build",
    }
}
fn stable_path(path: &Path) -> String {
    path.to_str()
        .expect("workspace path is UTF-8")
        .replace('\\', "/")
}
#[doc(hidden)]
pub fn register_point_export_functions(conn: &Connection) -> Result<()> {
    register_functions(conn)?;
    derivation::register_export_functions(conn)
}

/// Every connection the store hands out receives the crate SQL functions when
/// it is opened (`AnalyzerStore::from_parts` and `read_conn_with_acquisition`).
/// A derivation must not register them again: replacing an existing SQLite
/// function expires every prepared statement on the connection, so each crate
/// derivation used to recompile every cached statement on its reader.
fn debug_assert_crate_functions(conn: &Connection) {
    if cfg!(debug_assertions) {
        let registered = conn
            .prepare_cached("SELECT name, narg FROM pragma_function_list WHERE builtin = 0")
            .and_then(|mut statement| {
                statement
                    .query_map([], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .expect("list the connection's SQL functions");
        let missing: Vec<_> = [
            ("cr_parent", 1),
            ("cr_join", 2),
            ("cr_cfg", 2),
            ("cr_authority_cfg", 2),
            ("cr_authority_namespace", 1),
            ("cr_lookup_digest", 2),
            ("cr_visibility", 1),
            ("cr_visibility_segments", 1),
            ("cr_restriction", 3),
        ]
        .into_iter()
        .filter(|(name, narg)| {
            !registered
                .iter()
                .any(|(present, arity)| present == name && arity == narg)
        })
        .collect();
        assert!(
            missing.is_empty(),
            "crate derivation connection lacks SQL functions {missing:?}; registered: {registered:?}"
        );
    }
}

pub(super) fn register_functions(conn: &Connection) -> Result<()> {
    let flags = FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC;
    conn.create_scalar_function("cr_parent", 1, flags, |context| {
        let path: Option<String> = context.get(0)?;
        Ok(path.map(|path| stable_path(Path::new(&path).parent().unwrap_or(Path::new("")))))
    })?;
    conn.create_scalar_function("cr_join", 2, flags, |context| {
        let base: Option<String> = context.get(0)?;
        let path: Option<String> = context.get(1)?;
        // An escaping inline #[path] has no directory. Descendants retain
        // that missing placement instead of passing NULL to a String reader.
        let (Some(base), Some(path)) = (base, path) else {
            return Ok(None);
        };
        let mut result = PathBuf::from(base);
        for part in Path::new(&path).components() {
            match part {
                Component::CurDir => {}
                Component::Normal(part) => result.push(part),
                Component::ParentDir => {
                    if !result.pop() {
                        return Ok(None);
                    }
                }
                _ => return Ok(None),
            }
        }
        Ok(Some(stable_path(&result)))
    })?;
    // Native lookup recipes persist vocabulary ordinals. Convert once when
    // crossing into the crate binding relation's three namespace domains.
    conn.create_scalar_function("cr_authority_namespace", 1, flags, |context| {
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
        let namespace =
            super::resolution_prepare::resolution_rows::namespace_from_code(context.get(0)?);
        Ok(match namespace {
            ResolutionNamespace::Type | ResolutionNamespace::Macro => namespace.label(),
            _ => ResolutionNamespace::Value.label(),
        })
    })?;
    conn.create_scalar_function("cr_authority_cfg", 2, flags, |context| {
        let encoded: String = context.get(0)?;
        let atoms: String = context.get(1)?;
        let condition = super::resolution_prepare::rust_authority::decode_cfg(&encoded);
        let atoms = serde_json::from_str(&atoms)
            .map_err(|error| rusqlite::Error::UserFunctionError(Box::new(error)))?;
        Ok(
            match brokk_bifrost_rust::cfg::crate_activation(&atoms, &condition) {
                RustSelectedActivation::Active => 1,
                RustSelectedActivation::Inactive => 0,
                RustSelectedActivation::Unknown => -1,
            },
        )
    })?;
    conn.create_scalar_function("cr_cfg", 2, flags, |context| {
        let encoded: String = context.get(0)?;
        let atoms: String = context.get(1)?;
        let condition =
            decode_rust_cfg_condition(&encoded).expect("persisted cfg encoding is valid");
        let atoms = serde_json::from_str(&atoms)
            .map_err(|error| rusqlite::Error::UserFunctionError(Box::new(error)))?;
        Ok(
            match brokk_bifrost_rust::cfg::crate_activation(&atoms, &condition) {
                RustSelectedActivation::Active => 1,
                RustSelectedActivation::Inactive => 0,
                RustSelectedActivation::Unknown => -1,
            },
        )
    })?;
    Ok(())
}

#[cfg(any(test, feature = "test-support"))]
struct StatementTrace {
    _subscription: Option<brokk_bifrost_core::cache_db::sql_profile::TestStatementSubscription>,
}
#[cfg(any(test, feature = "test-support"))]
impl StatementTrace {
    fn new(
        conn: &Connection,
        counter: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
    ) -> Self {
        let subscription = counter.map(|counter| {
            brokk_bifrost_core::cache_db::sql_profile::subscribe_test_statements(
                conn,
                std::sync::Arc::new(move |_| {
                    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }),
            )
        });
        Self {
            _subscription: subscription,
        }
    }
}

/// Cargo manifests and configuration files of one snapshot, parsed from their
/// retained sources. A file that cannot be parsed is reported in
/// `inventory_errors` and left out of the other fields.
struct SelectedCargoInputs {
    manifests: Vec<RustSelectedManifestMount>,
    configuration_files: Vec<(PathBuf, RustCargoConfigDocument)>,
    inventory_errors: Vec<String>,
    manifest_versions: HashMap<PathBuf, i64>,
}

fn parse_selected_manifest(
    path: &str,
    oid: &str,
    source: Vec<u8>,
) -> Result<std::result::Result<RustSelectedManifestMount, String>> {
    Ok(RustSelectedManifestMount::from_retained_source(
        PathBuf::from(path),
        Oid::from_str(oid)?,
        source.into_boxed_slice(),
    ))
}

fn load_selected_cargo_inputs(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
) -> Result<SelectedCargoInputs> {
    let mut statement = conn.prepare_cached(SQL_WORKSPACE_FILE_VERSIONS_2)?;
    let rows = statement
        .query_map(
            params![
                snapshot.workspace_id.as_str(),
                snapshot.generation.0,
                snapshot.revision
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                ))
            },
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut inputs = SelectedCargoInputs {
        manifests: Vec::new(),
        configuration_files: Vec::new(),
        inventory_errors: Vec::new(),
        manifest_versions: HashMap::new(),
    };
    for (version, path, oid, source) in rows {
        // The Rust configuration inputs also hold Cargo.lock, rust-toolchain
        // files and Cargo's target-layout roots (`src/bin/<name>/main.rs`),
        // which other readers consume. Read as a manifest, a target root is a
        // TOML error that every detached crate inherits as an inventory gap.
        let configuration = is_cargo_configuration_path(Path::new(&path));
        if !configuration
            && Path::new(&path)
                .file_name()
                .is_none_or(|name| name != "Cargo.toml")
        {
            continue;
        }
        let Some(source) = source else {
            inputs
                .inventory_errors
                .push(format!("{path}: retained manifest source is missing"));
            continue;
        };
        if configuration {
            match RustCargoConfigDocument::from_source_bytes(&source) {
                Ok(document) => inputs
                    .configuration_files
                    .push((PathBuf::from(path), document)),
                Err(error) => inputs.inventory_errors.push(format!("{path}: {error}")),
            }
            continue;
        }
        let manifest = parse_selected_manifest(&path, &oid, source)?;
        let manifest = match manifest {
            Ok(manifest) => manifest,
            Err(error) => {
                inputs.inventory_errors.push(format!("{path}: {error}"));
                continue;
            }
        };
        inputs
            .manifest_versions
            .insert(PathBuf::from(path), version);
        inputs.manifests.push(manifest);
    }
    Ok(inputs)
}

impl AnalyzerStore {
    /// Read the selected Cargo configuration files at the requested paths, parsed
    /// as crate routing parses them. A path with no selected file is absent. A
    /// selected file whose source is missing or does not parse is a failure,
    /// because it cannot establish package identity.
    #[doc(hidden)]
    pub fn rust_selected_cargo_configuration_at_paths(
        conn: &Connection,
        snapshot: &WorkspaceSnapshotId,
        paths: &[String],
    ) -> Result<std::result::Result<RustCargoConfiguration, Vec<String>>> {
        let mut statement = conn.prepare_cached(SQL_SELECTED_CONFIGURATION_INPUTS_AT_PATHS)?;
        let rows = statement.query_map(
            params![
                snapshot.workspace_id.as_str(),
                snapshot.generation.0,
                snapshot.revision,
                serde_json::to_string(paths).expect("configuration paths serialize")
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                ))
            },
        )?;
        let mut files = Vec::new();
        let mut failures = Vec::new();
        for row in rows {
            let (path, oid, source) = row?;
            assert!(
                is_cargo_configuration_path(Path::new(&path)),
                "{path:?} is not a Cargo configuration file"
            );
            if oid.is_none() {
                continue;
            }
            let Some(source) = source else {
                failures.push(format!("{path}: retained configuration source is missing"));
                continue;
            };
            match RustCargoConfigDocument::from_source_bytes(&source) {
                Ok(document) => files.push((PathBuf::from(path), document)),
                Err(error) => failures.push(format!("{path}: {error}")),
            }
        }
        Ok(if failures.is_empty() {
            Ok(RustCargoConfiguration::from_files(files))
        } else {
            Err(failures)
        })
    }

    /// Load only the requested selected manifests, with identity evidence for
    /// both present and absent paths. Never consults the filesystem.
    ///
    /// The third element lists each requested manifest that is selected but
    /// unreadable, as the whole-index loader words its inventory errors. A
    /// path with no selected manifest is not a failure.
    #[doc(hidden)]
    pub fn rust_selected_manifest_mounts_at_paths(
        conn: &Connection,
        snapshot: &WorkspaceSnapshotId,
        paths: &[String],
    ) -> Result<(Vec<RustSelectedManifestMount>, [u8; 32], Vec<String>)> {
        let mut statement = conn.prepare_cached(SQL_SELECTED_CONFIGURATION_INPUTS_AT_PATHS)?;
        let rows = statement.query_map(
            params![
                snapshot.workspace_id.as_str(),
                snapshot.generation.0,
                snapshot.revision,
                serde_json::to_string(paths).expect("manifest paths serialize")
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                ))
            },
        )?;
        let mut hash = brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(
            b"rust-route-naming-inputs:v1",
        );
        let mut manifests = Vec::new();
        let mut failures = Vec::new();
        for row in rows {
            let (path, oid, source) = row?;
            hash.value(path.as_bytes());
            hash.value(oid.as_deref().unwrap_or("").as_bytes());
            let Some(oid) = oid else {
                continue;
            };
            let Some(source) = source else {
                failures.push(format!("{path}: retained manifest source is missing"));
                continue;
            };
            match parse_selected_manifest(&path, &oid, source)? {
                Ok(manifest) => manifests.push(manifest),
                Err(error) => failures.push(format!("{path}: {error}")),
            }
        }
        Ok((manifests, hash.finish(), failures))
    }
}

/// The selected Rust configuration input (a manifest or a Cargo configuration
/// file) at each requested path, with a NULL version for an absent path.
const SQL_SELECTED_CONFIGURATION_INPUTS_AT_PATHS: &str =
    "SELECT requested.value, versions.blob_oid, sources.source_bytes
     FROM json_each(?4) AS requested
     LEFT JOIN workspace_file_versions AS versions
       ON versions.rel_path = requested.value
      AND versions.workspace_id = ?1 AND versions.lang = 'rust'
      AND versions.generation = ?2 AND versions.input_kind = 'configuration'
      AND versions.valid_from <= ?3
      AND (versions.valid_until IS NULL OR ?3 < versions.valid_until)
     LEFT JOIN workspace_input_sources AS sources
       ON sources.content_oid = versions.blob_oid
     ORDER BY requested.value";
pub(super) const SQL_WORKSPACE_FILE_VERSIONS_2: &str = "SELECT versions.file_version_id, versions.rel_path, versions.blob_oid, sources.source_bytes
                 FROM workspace_file_versions AS versions
                 LEFT JOIN workspace_input_sources AS sources ON sources.content_oid = versions.blob_oid
                 WHERE versions.workspace_id = ?1 AND versions.lang = 'rust' AND versions.generation = ?2
                   AND versions.input_kind = 'configuration' AND versions.valid_from <= ?3
                   AND (versions.valid_until IS NULL OR ?3 < versions.valid_until)
                 ORDER BY versions.rel_path";
pub(super) const SQL_SELECTED_WORKSPACE_FILE_VERSIONS_3: &str =
    "SELECT files.rel_path, files.blob_oid FROM selected_workspace_file_versions AS files
                 WHERE files.lang = 'rust' ORDER BY files.rel_path";
pub(super) const SQL_RUST_CRATE_RECONCILIATION_CURRENT: &str =
    "SELECT 1 FROM rust_crate_reconciliations
     WHERE workspace_id = ?1 AND generation = ?2 AND revision = ?3 AND derivation_version = ?4";
/// The revision of the last complete reconcile of this generation under this
/// derivation version, at whatever revision that pass ran. The marker table
/// keeps one row per generation; the ORDER BY states the choice rather than
/// relying on that. A pass that fails writes no marker, so the row names the
/// last pass that completed.
pub(super) const SQL_RUST_CRATE_RECONCILIATION_PREVIOUS: &str =
    "SELECT revision FROM rust_crate_reconciliations
     WHERE workspace_id = ?1 AND generation = ?2 AND derivation_version = ?3
     ORDER BY revision DESC LIMIT 1";
/// The Rust paths the revision log changed in the range (from, to]: a file
/// version that opened or closed at one of those revisions. A path added,
/// changed or removed in the range appears here, whatever its input kind.
pub(super) const SQL_WORKSPACE_FILE_CHANGES_BETWEEN: &str = "SELECT DISTINCT versions.rel_path
     FROM workspace_file_versions AS versions
     WHERE versions.workspace_id = ?1 AND versions.lang = 'rust' AND versions.generation = ?2
       AND ((versions.valid_from > ?3 AND versions.valid_from <= ?4)
         OR (versions.valid_until > ?3 AND versions.valid_until <= ?4))";
pub(super) const SQL_RUST_CRATE_RECONCILIATION_RECORD: &str =
    "INSERT INTO rust_crate_reconciliations(workspace_id, generation, revision, derivation_version)
     VALUES(?1, ?2, ?3, ?4)
     ON CONFLICT(workspace_id, generation) DO UPDATE
     SET revision = excluded.revision, derivation_version = excluded.derivation_version";
pub(super) const SQL_RUST_CRATE_RECONCILIATION_ADVANCE: &str =
    "UPDATE rust_crate_reconciliations SET revision = ?3
     WHERE workspace_id = ?1 AND generation = ?2 AND derivation_version = ?4 AND revision = ?5";
pub(super) const SQL_ANALYSIS_EPOCHS_4: &str =
    "SELECT epoch FROM analysis_epochs WHERE lang = 'rust'";
pub(super) const SQL_RUST_CRATE_MODULES_5: &str =
    "SELECT rel_path FROM rust_crate_container_sources WHERE topology_id = ?1";
/// The live crate set this workspace generation already derived, with each
/// crate's topology and export surface.
///
/// A reconcile that derives only the crates a change reached still has to
/// publish the whole live set, both so the version-closing pass below does not
/// retire the crates it skipped and so a dependent's digest can fold its
/// dependency's surface. One query answers both.
pub(super) const SQL_RUST_CRATE_LIVE_TOPOLOGIES: &str =
    "SELECT versions.crate_key, versions.topology_id, topologies.export_surface_digest
     FROM rust_crate_versions AS versions
     JOIN rust_crate_topologies AS topologies USING(topology_id)
     WHERE versions.workspace_id = ?1 AND versions.lang = 'rust'
       AND versions.generation = ?2 AND versions.valid_until IS NULL
       AND topologies.export_surface_digest IS NOT NULL";

/// The live crates that place one changed path.
///
/// `rust_crate_container_sources` already records which topology mounts which
/// file, declared or included, so a changed file names its own crates without
/// walking any module tree. A path this returns nothing for is a path no crate
/// placed, which the caller treats as a reason to reconcile everything: a new
/// file can join a crate an unchanged `mod` declaration already names.
const INSERT_INACTIVE_PLACEMENT_SQL: &str = "INSERT INTO rust_crate_inactive_placements(
 topology_id,module_path,rel_path,placement,mount_blob_id,mount_start_byte,scope_ordinal,blob_id,activation)
 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)
 ON CONFLICT(topology_id,module_path,rel_path,placement,mount_blob_id,mount_start_byte,scope_ordinal)
 DO UPDATE SET activation = CASE WHEN activation = -1 OR excluded.activation = -1 THEN -1 ELSE 0 END";

pub(super) const SQL_RUST_CRATE_TOPOLOGIES_FOR_PATH: &str = "SELECT DISTINCT versions.crate_key
     FROM rust_crate_broad_placements AS sources
     JOIN rust_crate_versions AS versions USING(topology_id)
     WHERE sources.rel_path = ?3 AND versions.workspace_id = ?1
       AND versions.lang = 'rust' AND versions.generation = ?2
       AND versions.valid_until IS NULL";

/// The live crates that depend on one crate.
///
/// Only a crate whose dependency's export surface changed has to be derived
/// again; its own digest folds that surface. A body edit changes no surface
/// and reaches no dependent, which is the difference this query exists to
/// keep.
pub(super) const SQL_RUST_CRATE_DEPENDENTS: &str = "SELECT DISTINCT versions.crate_key
     FROM rust_crate_dependencies AS dependencies
     JOIN rust_crate_versions AS versions USING(topology_id)
     WHERE dependencies.dependency_crate_key = ?3 AND versions.workspace_id = ?1
       AND versions.lang = 'rust' AND versions.generation = ?2
       AND versions.valid_until IS NULL";

#[doc(hidden)]
pub const CREATE_PENDING_CRATES_SQL: &str =
    "CREATE TEMP TABLE IF NOT EXISTS rust_crate_pending_keys(
    crate_key BLOB NOT NULL PRIMARY KEY,
    component_key BLOB NOT NULL
) WITHOUT ROWID, STRICT";
#[doc(hidden)]
pub const INSERT_PENDING_CRATE_SQL: &str =
    "INSERT INTO temp.rust_crate_pending_keys(crate_key, component_key) VALUES(?1, ?2)";
#[doc(hidden)]
pub const SQL_RUST_CRATE_PENDING_ANCESTORS: &str = include_str!("rust_crate_pending_ancestors.sql");

pub(super) const SQL_RUST_CRATE_VERSIONS_6: &str = "SELECT crate_key, valid_from FROM rust_crate_versions WHERE workspace_id = ?1 AND lang = 'rust' AND generation = ?2 AND valid_until IS NULL";
#[doc(hidden)]
pub const SQL_BLOBS_8: &str = "SELECT blob_oid FROM blobs WHERE id = ?1";
pub(super) const SQL_RUST_CRATE_TOPOLOGIES_9: &str = "SELECT topology_id, export_surface_digest FROM rust_crate_topologies WHERE topology_digest = ?1 AND publication_state = 'complete'";
pub(super) const SQL_RUST_CRATE_TOPOLOGIES_10: &str = "INSERT INTO rust_crate_topologies(topology_digest, crate_key, producer_epoch, target_kind, crate_name, edition, prelude, cfg_atoms, inventory_complete, publication_state, broad_complete) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?9, jsonb(?7), ?8, 'building', ?10)";
/// The crate root file's top-level inner attribute names, for the crate's
/// prelude: `no_core` selects none, `no_std` selects core, and otherwise the
/// crate uses std's.
pub(super) const SQL_ROOT_INNER_ATTRIBUTES: &str =
    "SELECT name FROM source_rust_inner_attributes WHERE blob_id = ?1 ORDER BY ordinal";
pub(super) const SQL_RUST_CRATE_MODULES_11: &str =
    "INSERT INTO rust_crate_container_sources VALUES(?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7)";
#[doc(hidden)]
pub const SQL_RUST_CRATE_DEPENDENCIES_12: &str =
    "INSERT INTO rust_crate_dependencies VALUES(?1, ?2, ?3, ?4, ?5)";
pub(super) const SQL_RUST_CRATE_GAPS_13: &str =
    "INSERT OR IGNORE INTO rust_crate_gaps VALUES(?1, ?2, ?3, jsonb(?4))";
pub(super) const SQL_RUST_CRATE_TOPOLOGIES_14: &str = "UPDATE rust_crate_topologies SET export_surface_digest = ?1, publication_state = 'complete' WHERE topology_id = ?2";
pub(super) const SQL_RUST_CRATE_VERSIONS_15: &str = "SELECT topology_id, valid_from, manifest_file_version_id FROM rust_crate_versions WHERE workspace_id = ?1 AND lang = 'rust' AND generation = ?2 AND crate_key = ?3 AND valid_until IS NULL";
// The two ways `end_open_crate_version` ends an open row, bound alike: close it
// at a later revision, or withdraw the one this revision opened.
pub(super) const SQL_RUST_CRATE_VERSIONS_16: &str = "UPDATE rust_crate_versions SET valid_until = ?1 WHERE workspace_id = ?2 AND lang = 'rust' AND generation = ?3 AND crate_key = ?4 AND valid_until IS NULL";
pub(super) const SQL_RUST_CRATE_VERSIONS_WITHDRAW: &str = "DELETE FROM rust_crate_versions WHERE workspace_id = ?2 AND lang = 'rust' AND generation = ?3 AND crate_key = ?4 AND valid_from = ?1 AND valid_until IS NULL";
pub(super) const SQL_RUST_CRATE_VERSIONS_17: &str =
    "INSERT INTO rust_crate_versions VALUES(?1, 'rust', ?2, ?3, ?4, NULL, ?5, ?6)";
#[cfg(any(test, feature = "test-support"))]
pub(super) fn sql_pins() -> Vec<(&'static str, &'static str, usize)> {
    let mut pins = vec![
        ("rust_crate_insert_module", INSERT_MODULE_SQL, 3),
        ("rust_crate_insert_naming", INSERT_NAMING_SQL, 4),
        ("rust_crate_insert_pending_key", INSERT_PENDING_CRATE_SQL, 2),
        (
            "rust_crate_pending_ancestors",
            SQL_RUST_CRATE_PENDING_ANCESTORS,
            3,
        ),
        (
            "rust_crate_reconcile_sql_rust_crate_topologies_1",
            DELETE_UNBOUND_TOPOLOGIES_SQL,
            0,
        ),
        (
            "rust_crate_reconcile_sql_workspace_file_versions_2",
            SQL_WORKSPACE_FILE_VERSIONS_2,
            3,
        ),
        (
            "rust_crate_reconcile_sql_selected_workspace_file_versions_3",
            SQL_SELECTED_WORKSPACE_FILE_VERSIONS_3,
            0,
        ),
        (
            "rust_crate_reconcile_sql_reconciliation_previous",
            SQL_RUST_CRATE_RECONCILIATION_PREVIOUS,
            3,
        ),
        (
            "rust_crate_reconcile_sql_workspace_file_changes_between",
            SQL_WORKSPACE_FILE_CHANGES_BETWEEN,
            4,
        ),
        (
            "rust_crate_reconcile_sql_analysis_epochs_4",
            SQL_ANALYSIS_EPOCHS_4,
            0,
        ),
        (
            "rust_crate_reconcile_sql_rust_crate_containers_5",
            SQL_RUST_CRATE_MODULES_5,
            1,
        ),
        (
            "rust_crate_reconcile_sql_rust_crate_versions_6",
            SQL_RUST_CRATE_VERSIONS_6,
            2,
        ),
        ("rust_crate_replaced_blob_id", REPLACED_BLOB_ID_SQL, 4),
        ("rust_crate_reinsert_blob", REINSERT_BLOB_SQL, 5),
        ("rust_crate_reconcile_sql_blobs_8", SQL_BLOBS_8, 1),
        (
            "rust_crate_reconcile_sql_rust_crate_topologies_9",
            SQL_RUST_CRATE_TOPOLOGIES_9,
            1,
        ),
        (
            "rust_crate_reconcile_sql_rust_crate_topologies_10",
            SQL_RUST_CRATE_TOPOLOGIES_10,
            10,
        ),
        (
            "rust_crate_reconcile_sql_root_inner_attributes",
            SQL_ROOT_INNER_ATTRIBUTES,
            1,
        ),
        (
            "rust_crate_reconcile_sql_rust_crate_containers_11",
            SQL_RUST_CRATE_MODULES_11,
            7,
        ),
        (
            "rust_crate_reconcile_sql_rust_crate_dependencies_12",
            SQL_RUST_CRATE_DEPENDENCIES_12,
            5,
        ),
        (
            "rust_crate_reconcile_sql_rust_crate_gaps_13",
            SQL_RUST_CRATE_GAPS_13,
            4,
        ),
        (
            "rust_crate_reconcile_sql_rust_crate_topologies_14",
            SQL_RUST_CRATE_TOPOLOGIES_14,
            2,
        ),
        (
            "rust_crate_reconcile_sql_rust_crate_versions_15",
            SQL_RUST_CRATE_VERSIONS_15,
            3,
        ),
        (
            "rust_crate_reconcile_sql_rust_crate_versions_16",
            SQL_RUST_CRATE_VERSIONS_16,
            4,
        ),
        (
            "rust_crate_reconcile_sql_rust_crate_versions_withdraw",
            SQL_RUST_CRATE_VERSIONS_WITHDRAW,
            4,
        ),
        (
            "rust_crate_reconcile_sql_rust_crate_versions_17",
            SQL_RUST_CRATE_VERSIONS_17,
            6,
        ),
    ];
    pins.extend(derivation::sql_pins());
    pins.extend(unit_schedule::sql_pins());
    pins.extend([
        ("rust_crate_schedule_ready", RUST_READY_WAVE_SQL, 0),
        ("rust_crate_schedule_force", RUST_FORCE_COMPONENT_SQL, 0),
        ("rust_crate_schedule_staged_target", STAGED_TARGET_SQL, 1),
        (
            "rust_crate_schedule_staged_dependencies",
            STAGED_DEPENDENCIES_SQL,
            1,
        ),
        ("rust_crate_schedule_wave_unit", WAVE_UNIT_SQL, 1),
        ("rust_crate_schedule_live_surface", LIVE_SURFACE_SQL, 1),
    ]);
    pins.extend([
        (
            "rust_crate_export_source_edges",
            derivation::EXPORT_SOURCES_SQL,
            0,
        ),
        (
            "rust_crate_export_declarations",
            derivation::DECLARATIONS_SQL,
            0,
        ),
        (
            "rust_crate_import_routes",
            derivation::ROUTES_SQL.as_str(),
            0,
        ),
        ("rust_crate_export_fixpoint", derivation::FIXPOINT_SQL, 0),
    ]);
    pins
}
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn prepare_pin_context(conn: &Connection) -> Result<()> {
    register_point_export_functions(conn)?;
    conn.execute_batch(unit_schedule::SCHEMA_SQL)?;
    conn.execute_batch(RUST_SCHEDULE_SCHEMA_SQL)?;
    conn.execute_batch(CREATE_PENDING_CRATES_SQL)?;
    conn.execute_batch("CREATE TEMP TABLE IF NOT EXISTS rust_schedule_live(crate_key BLOB PRIMARY KEY, topology_id INTEGER NOT NULL, surface BLOB NOT NULL) WITHOUT ROWID, STRICT")?;
    derivation::prepare_tables(conn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#10774+#10830: a target-layout .rs root was parsed as a Cargo manifest")]
    fn cargo_inputs_mount_only_cargo_toml_as_a_manifest() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE workspace_file_versions(
            file_version_id INTEGER PRIMARY KEY, workspace_id, lang, generation,
            input_kind, valid_from, valid_until, rel_path, blob_oid);
            CREATE TABLE workspace_input_sources(content_oid, source_bytes);",
        )
        .unwrap();
        let snapshot = WorkspaceSnapshotId {
            workspace_id: super::super::WorkspaceId("test".into()),
            lang: "rust".into(),
            generation: super::super::GenerationId(1),
            revision: 1,
        };
        // Every kind of Rust configuration input a package records.
        for (path, source) in [
            ("Cargo.toml", "[package]\nname = 'app'\nversion = '0.1.0'\n"),
            (
                "Cargo.lock",
                "version = 3\n\n[[package]]\nname = 'app'\nversion = '0.1.0'\n",
            ),
            ("rust-toolchain.toml", "[toolchain]\nchannel = 'stable'\n"),
            ("src/bin/tool/main.rs", "mod app;\nfn main() {}\n"),
            (".cargo/config.toml", "[build]\n"),
        ] {
            let oid = Oid::hash_object(git2::ObjectType::Blob, source.as_bytes())
                .unwrap()
                .to_string();
            conn.execute(
                "INSERT INTO workspace_input_sources VALUES(?1, ?2)",
                params![oid, source.as_bytes()],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO workspace_file_versions(workspace_id, lang, generation, input_kind,
                 valid_from, valid_until, rel_path, blob_oid)
                 VALUES('test', 'rust', 1, 'configuration', 1, NULL, ?1, ?2)",
                params![path, oid],
            )
            .unwrap();
        }
        let inputs = load_selected_cargo_inputs(&conn, &snapshot).unwrap();
        assert_eq!(
            inputs
                .manifests
                .iter()
                .map(|manifest| manifest.relative_path.clone())
                .collect::<Vec<_>>(),
            [PathBuf::from("Cargo.toml")],
            "Cargo.lock, the toolchain file and a target-layout root are not manifests"
        );
        assert_eq!(
            inputs
                .configuration_files
                .iter()
                .map(|(path, _)| path.clone())
                .collect::<Vec<_>>(),
            [PathBuf::from(".cargo/config.toml")]
        );
        assert!(
            inputs.inventory_errors.is_empty(),
            "{:?}",
            inputs.inventory_errors
        );
    }

    #[test]
    fn rust_route_naming_reads_only_requested_manifests_and_tracks_absence() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE workspace_file_versions(
            workspace_id, lang, generation, input_kind, valid_from, valid_until,
            rel_path, blob_oid);
            CREATE TABLE workspace_input_sources(content_oid, source_bytes);",
        )
        .unwrap();
        let snapshot = WorkspaceSnapshotId {
            workspace_id: super::super::WorkspaceId("test".into()),
            lang: "rust".into(),
            generation: super::super::GenerationId(1),
            revision: 1,
        };
        let source = b"[package]\nname = 'app'\nversion = '0.1.0'\n";
        let oid = Oid::hash_object(git2::ObjectType::Blob, source)
            .unwrap()
            .to_string();
        conn.execute(
            "INSERT INTO workspace_input_sources VALUES(?1, ?2)",
            params![oid, source.as_slice()],
        )
        .unwrap();
        for path in ["Cargo.toml", "other/Cargo.toml", "third/Cargo.toml"] {
            conn.execute("INSERT INTO workspace_file_versions VALUES('test','rust',1,'configuration',1,NULL,?1,?2)", params![path, oid]).unwrap();
        }
        let paths = vec!["Cargo.toml".to_string(), "src/Cargo.toml".to_string()];
        let (mounts, before, failures) =
            AnalyzerStore::rust_selected_manifest_mounts_at_paths(&conn, &snapshot, &paths)
                .unwrap();
        assert!(failures.is_empty(), "an absent manifest is not a failure");
        assert_eq!(mounts.len(), 1, "unrelated manifests must never be parsed");
        assert_eq!(mounts[0].relative_path, PathBuf::from("Cargo.toml"));
        conn.execute("INSERT INTO workspace_file_versions VALUES('test','rust',1,'configuration',1,NULL,'src/Cargo.toml',?1)", params![oid]).unwrap();
        let (mounts, after, _) =
            AnalyzerStore::rust_selected_manifest_mounts_at_paths(&conn, &snapshot, &paths)
                .unwrap();
        assert_eq!(mounts.len(), 2);
        assert_ne!(
            before, after,
            "a formerly absent governing manifest changes identity"
        );
    }

    #[test]
    #[hardwon("#9737: a reader held across reconciliation deadlocked a single-connection store")]
    fn changed_listing_certificate_reconciles_on_a_single_connection_store() {
        let store = std::sync::Arc::new(AnalyzerStore::open_in_memory_single_connection().unwrap());
        let generation = store
            .ensure_language_epoch_value("rust", "single-connection")
            .unwrap();
        let version = super::super::RUST_SOURCE_LISTING_DERIVATION_VERSION;
        let first = store
            .sync_workspace_inputs_with_rust_listing(
                &super::super::WorkspaceId("a".repeat(64)),
                "rust",
                generation,
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                Some((version, Vec::new())),
            )
            .unwrap();
        store.reconcile_rust_crates_unless_current(&first).unwrap();
        // Only the certificate differs: no file version changed.
        let second = store
            .publish_rust_source_listing(
                &first,
                version,
                vec![("src/link.rs".into(), "symlink".into())],
            )
            .unwrap();
        assert!(
            store
                .rust_listing_certificates_differ(&first, &second)
                .unwrap()
        );
        let (done, finished) = std::sync::mpsc::channel();
        let worker = std::sync::Arc::clone(&store);
        std::thread::spawn(move || {
            done.send(
                worker
                    .reconcile_rust_crates_unless_current(&second)
                    .map(|_| ()),
            )
            .unwrap();
        });
        finished
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("reconciliation must not wait on a reader its own caller holds")
            .unwrap();
    }

    #[test]
    fn sql_cfg_preserves_incomplete_features() {
        use brokk_bifrost_core::analyzer::rust_facts::{
            RustCfgCondition, encode_rust_cfg_condition,
        };

        let conn = Connection::open_in_memory().unwrap();
        register_functions(&conn).unwrap();
        let condition =
            encode_rust_cfg_condition(&RustCfgCondition::Atom("feature = \"x\"".into()));
        let activation: (i32, i32) = conn
            .query_row(
                r#"SELECT cr_cfg(?1, '[]'),
                          cr_cfg(?1, '["bifrost_incomplete_features"]')"#,
                params![condition],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            activation,
            (0, -1),
            "complete: Inactive; incomplete: Unknown"
        );
    }

    #[test]
    #[hardwon("#6861: descendants of an escaping inline path must retain missing placement")]
    fn module_path_joins_propagate_missing_directory() {
        let conn = Connection::open_in_memory().unwrap();
        register_functions(&conn).unwrap();
        let joined: (Option<String>, Option<String>, Option<String>) = conn
            .query_row(
                "SELECT cr_join('src', 'alt'),
                    cr_join('src', '../../outside'),
                    cr_join(cr_join('src', '../../outside'), 'child.rs')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(joined, (Some("src/alt".to_owned()), None, None));
    }

    #[test]
    fn inactive_parent_walks_both_child_candidates_without_selecting_them() {
        use brokk_bifrost_core::analyzer::rust_facts::{
            RustCfgCondition, encode_rust_cfg_condition,
        };
        let conn = Connection::open_in_memory().unwrap();
        register_functions(&conn).unwrap();
        conn.execute_batch(
            "CREATE TABLE blobs(id,blob_oid,lang,generation,parse_variant BLOB NOT NULL DEFAULT x'');
             INSERT INTO blobs(id,blob_oid,lang,generation) VALUES
               (1,'root','rust',0),(2,'inner','rust',0),(3,'child-a','rust',0),(4,'child-b','rust',0);
             CREATE TABLE workspace_file_versions(file_version_id,rel_path,blob_oid,lang,generation);
             INSERT INTO workspace_file_versions VALUES
               (1,'src/lib.rs','root','rust',0),
               (2,'src/inner.rs','inner','rust',0),
               (3,'src/inner/child.rs','child-a','rust',0),
               (4,'src/inner/child/mod.rs','child-b','rust',0);
             CREATE VIEW selected_workspace_file_versions AS SELECT * FROM workspace_file_versions;
             CREATE TABLE source_declarations(blob_id,declaration_id,start_byte,end_byte);
             INSERT INTO source_declarations VALUES(1,0,0,10),(2,0,0,10);
             CREATE TABLE source_rust_module_declarations(
               blob_id,declaration_id,module_name,body_occurrence_id,path_attribute,
               body_start_byte,body_end_byte);
             INSERT INTO source_rust_module_declarations VALUES
               (1,0,'inner',NULL,NULL,NULL,NULL),(2,0,'child',NULL,NULL,NULL,NULL);
             CREATE TABLE source_rust_module_scopes(blob_id,ordinal,parent_ordinal,declaration_id);
             CREATE TABLE source_rust_declaration_properties(blob_id,declaration_id,cfg_condition);
             INSERT INTO source_rust_declaration_properties VALUES(2,0,'always');
             CREATE TABLE source_rust_module_routes(blob_id,ordinal,scope_ordinal,declaration_id);
             INSERT INTO source_rust_module_routes VALUES(1,0,0,0),(2,0,0,0);
             CREATE TABLE source_rust_module_route_gates(blob_id,route_ordinal,invocation_occurrence_id);
             CREATE TABLE source_rust_item_macro_expansions(
               blob_id,invocation_occurrence_id,invocation_start_byte,invocation_end_byte);
             CREATE TABLE rust_include_edges(blob_id,relative_path,include_start);",
        ).unwrap();
        let off = encode_rust_cfg_condition(&RustCfgCondition::Atom("feature = \"off\"".into()));
        conn.execute(
            "INSERT INTO source_rust_declaration_properties VALUES(1,0,?1)",
            [off],
        )
        .unwrap();
        let rows: Vec<(String, String, i64, bool)> = conn
            .prepare(MODULE_WALK_SQL)
            .unwrap()
            .query_map(params!["src/lib.rs", "[]", "[]"], |row| {
                Ok((row.get(0)?, row.get(3)?, row.get(7)?, row.get(9)?))
            })
            .unwrap()
            .map(|row| row.unwrap())
            .collect();
        assert!(rows.contains(&("crate::inner".into(), "src/inner.rs".into(), 0, true)));
        assert!(rows.contains(&(
            "crate::inner::child".into(),
            "src/inner/child.rs".into(),
            0,
            false
        )));
        assert!(rows.contains(&(
            "crate::inner::child".into(),
            "src/inner/child/mod.rs".into(),
            0,
            false
        )));
    }

    #[test]
    #[hardwon(
        "#9737: carrying each #[path] candidate in the walk's DISTINCT split one gap row per cfg branch"
    )]
    fn path_candidates_do_not_split_the_walks_rows() {
        use brokk_bifrost_core::analyzer::rust_facts::{
            RustCfgCondition, encode_rust_cfg_condition,
        };
        let conn = Connection::open_in_memory().unwrap();
        register_functions(&conn).unwrap();
        // lib.rs: #[cfg(a)] #[path = "a/m.rs"] mod m;
        //         #[cfg(not(a))] #[path = "b/m.rs"] mod m;
        //         mod n;
        // src/a/m.rs and src/b/m.rs are one blob (identical content) holding
        // `#[path = "gen.inc"] mod g;`. Both activations are unknown, and the
        // child has one mount (blob and start byte) under two candidates.
        conn.execute_batch(
            "CREATE TABLE blobs(id,blob_oid,lang,generation,parse_variant BLOB NOT NULL DEFAULT x'');
             INSERT INTO blobs(id,blob_oid,lang,generation) VALUES(1,'root','rust',0),(2,'m','rust',0);
             CREATE TABLE workspace_file_versions(file_version_id,rel_path,blob_oid,lang,generation);
             INSERT INTO workspace_file_versions VALUES
               (1,'src/lib.rs','root','rust',0),
               (2,'src/a/m.rs','m','rust',0),
               (3,'src/b/m.rs','m','rust',0);
             CREATE VIEW selected_workspace_file_versions AS SELECT * FROM workspace_file_versions;
             CREATE TABLE source_declarations(blob_id,declaration_id,start_byte,end_byte);
             INSERT INTO source_declarations VALUES(1,0,0,10),(1,1,20,30),(1,2,40,50),(2,0,0,10);
             CREATE TABLE source_rust_module_declarations(
               blob_id,declaration_id,module_name,body_occurrence_id,path_attribute,
               body_start_byte,body_end_byte);
             INSERT INTO source_rust_module_declarations VALUES
               (1,0,'m',NULL,'a/m.rs',NULL,NULL),
               (1,1,'m',NULL,'b/m.rs',NULL,NULL),
               (1,2,'n',NULL,NULL,NULL,NULL),
               (2,0,'g',NULL,'gen.inc',NULL,NULL);
             CREATE TABLE source_rust_module_scopes(blob_id,ordinal,parent_ordinal,declaration_id);
             CREATE TABLE source_rust_declaration_properties(blob_id,declaration_id,cfg_condition);
             CREATE TABLE source_rust_module_routes(blob_id,ordinal,scope_ordinal,declaration_id);
             INSERT INTO source_rust_module_routes VALUES(1,0,0,0),(1,1,0,1),(1,2,0,2),(2,0,0,0);
             CREATE TABLE source_rust_module_route_gates(blob_id,route_ordinal,invocation_occurrence_id);
             CREATE TABLE source_rust_item_macro_expansions(
               blob_id,invocation_occurrence_id,invocation_start_byte,invocation_end_byte);
             CREATE TABLE rust_include_edges(blob_id,relative_path,include_start);",
        )
        .unwrap();
        for (blob, declaration, condition) in [
            (1, 0, RustCfgCondition::Atom("a".into())),
            (1, 1, RustCfgCondition::NotAtom("a".into())),
            (1, 2, RustCfgCondition::Always),
            (2, 0, RustCfgCondition::Always),
        ] {
            conn.execute(
                "INSERT INTO source_rust_declaration_properties VALUES(?1,?2,?3)",
                params![blob, declaration, encode_rust_cfg_condition(&condition)],
            )
            .unwrap();
        }
        let rows: Vec<(String, Option<String>, i64, Vec<String>)> = conn
            .prepare(MODULE_WALK_SQL)
            .unwrap()
            .query_map(params!["src/lib.rs", "[]", "[]"], |row| {
                let candidates: String = row.get(11)?;
                let mut candidates: Vec<String> = serde_json::from_str(&candidates).unwrap();
                candidates.sort();
                Ok((row.get(0)?, row.get(3)?, row.get(7)?, candidates))
            })
            .unwrap()
            .map(|row| row.unwrap())
            .collect();
        // The row set is what the walk published before it carried candidates:
        // one root, one row per unselected-cfg file placement, and one gap row
        // for g (no path, no blob), not one per candidate.
        assert_eq!(
            rows,
            vec![
                ("crate".to_owned(), Some("src/lib.rs".to_owned()), 1, vec![]),
                (
                    "crate::m".to_owned(),
                    Some("src/a/m.rs".to_owned()),
                    -1,
                    vec!["src/a/m.rs".to_owned()]
                ),
                (
                    "crate::m".to_owned(),
                    Some("src/b/m.rs".to_owned()),
                    -1,
                    vec!["src/b/m.rs".to_owned()]
                ),
                (
                    "crate::m::g".to_owned(),
                    None,
                    -1,
                    vec!["src/a/gen.inc".to_owned(), "src/b/gen.inc".to_owned()]
                ),
                // `mod n;` names n.rs and n/mod.rs, and the walk carries both.
                (
                    "crate::n".to_owned(),
                    None,
                    1,
                    vec!["src/n.rs".to_owned(), "src/n/mod.rs".to_owned()]
                ),
            ]
        );
    }

    #[test]
    #[hardwon(
        "4fb16a86137c: duplicate module placements leaked macro_use scope into item decisions"
    )]
    fn duplicate_module_placements_do_not_supply_macro_scope() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = Connection::open_in_memory().unwrap();
        register_functions(&conn).unwrap();
        // Minimal query-input projection of this two-file crate:
        // lib.rs: #[path = "macros.rs"] mod duplicate;
        //         #[macro_use] #[path = "macros.rs"] mod duplicate;
        //         pass! { pub struct Leaked; }
        // macros.rs: macro_rules! pass { ($item:item) => { $item }; }
        // Keep the fixture at the store boundary: both production SQL queries
        // and the production fixed-point loop run against these source rows.
        conn.execute_batch(
            "CREATE TABLE blobs(id, blob_oid, lang, generation, parse_variant BLOB NOT NULL DEFAULT x'');
             INSERT INTO blobs(id, blob_oid, lang, generation) VALUES(1,'root','rust',0),(2,'macros','rust',0);
             CREATE TABLE workspace_file_versions(file_version_id, rel_path, blob_oid, lang, generation);
             INSERT INTO workspace_file_versions VALUES
               (1,'src/lib.rs','root','rust',0),(2,'src/macros.rs','macros','rust',0);
             CREATE VIEW selected_workspace_file_versions AS SELECT * FROM workspace_file_versions;
             CREATE TABLE source_declarations(blob_id, declaration_id, start_byte, end_byte);
             INSERT INTO source_declarations VALUES(1,0,0,10),(1,1,20,30);
             CREATE TABLE source_rust_module_declarations(
               blob_id, declaration_id, module_name, body_occurrence_id,
               path_attribute, body_start_byte, body_end_byte, macro_use);
             INSERT INTO source_rust_module_declarations VALUES
               (1,0,'duplicate',NULL,'macros.rs',NULL,NULL,0),
               (1,1,'duplicate',NULL,'macros.rs',NULL,NULL,1);
             CREATE TABLE source_rust_module_scopes(blob_id, ordinal, parent_ordinal, declaration_id);
             CREATE TABLE source_rust_declaration_properties(blob_id, declaration_id, cfg_condition, macro_exported);
             INSERT INTO source_rust_declaration_properties VALUES(1,0,'always',0),(1,1,'always',0);
             CREATE TABLE source_rust_module_routes(blob_id, ordinal, scope_ordinal, declaration_id);
             INSERT INTO source_rust_module_routes VALUES(1,0,0,0),(1,1,0,1);
             CREATE TABLE source_rust_module_route_gates(blob_id, route_ordinal, invocation_occurrence_id);
             CREATE TABLE rust_include_edges(blob_id, relative_path, include_start);
             CREATE TABLE source_rust_item_macro_expansions(
               blob_id, invocation_occurrence_id, invocation_start_byte, invocation_end_byte,
               source_position, expansion_kind);
             INSERT INTO source_rust_item_macro_expansions VALUES(1,7,40,70,0,0);
             CREATE TABLE source_rust_macro_invocations(blob_id, occurrence_id, macro_name);
             INSERT INTO source_rust_macro_invocations VALUES(1,7,'pass');
             CREATE TABLE rust_item_macros(
               blob_id, declaration_id, macro_name, passthrough, decoration_cfg,
               scope_start, scope_end, visible_after);
             INSERT INTO rust_item_macros VALUES(2,0,'pass',1,'always',0,100,60);
             CREATE TABLE source_rust_item_contexts(
               blob_id, context_kind, parent_occurrence_id, start_byte, end_byte);
             INSERT INTO source_rust_item_contexts VALUES(2,0,NULL,0,100);
             CREATE TABLE source_rust_macro_inputs(blob_id, invocation_occurrence_id, native_gap_site);
             INSERT INTO source_rust_macro_inputs VALUES(1,7,7);
             CREATE TABLE source_rust_import_targets(blob_id, bound_name, is_glob, is_macro_use);",
        )
        .unwrap();

        let (rows, decisions) = store
            .walk_crate_modules(&conn, "src/lib.rs".to_string(), "[]")
            .unwrap();
        let duplicate_mounts: Vec<_> = rows
            .iter()
            .filter(|row| row.module_path == "crate::duplicate" && row.activation == 1)
            .map(|row| (row.blob, row.mount_start))
            .collect();
        assert_eq!(
            duplicate_mounts,
            vec![(Some(2), Some(0)), (Some(2), Some(20))]
        );
        let admitted: Vec<_> = decisions
            .iter()
            .map(|decision| {
                (
                    decision.blob_id,
                    decision.invocation_occurrence_id,
                    decision.decoration_cfg.as_str(),
                    decision.no_route,
                )
            })
            .collect();
        assert_eq!(
            admitted,
            vec![],
            "rejected duplicate mounts cannot export pass!"
        );
    }
}
