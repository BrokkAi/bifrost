//! Content-addressed Cargo crate reconciliation. All Rust collections below
//! belong to this reconcile request; only SQLite rows survive its return.
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Component, Path, PathBuf};

use brokk_bifrost_core::analyzer::rust_facts::decode_rust_cfg_condition;
use brokk_bifrost_rust::selected_context::{
    RustCallerTargetKind, RustCargoDependencyKind, RustCargoEdition, RustCrateTarget,
    RustSelectedActivation, RustSelectedManifestMount, rust_crate_targets,
};
use git2::Oid;
use rayon::prelude::*;
use rusqlite::{Connection, OptionalExtension, functions::FunctionFlags, params};
use sha2::{Digest, Sha256};

use super::{AnalyzerStore, Result, StoreError, WorkspaceSnapshotId, WorkspaceSnapshots};
use crate::analyzer::pool_memo::install_on_dedicated_build_pool;

pub(super) const REPLACED_BLOB_ID_SQL: &str = "SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2 AND generation = ?3 AND (EXISTS(SELECT 1 FROM rust_crate_container_sources WHERE blob_id = blobs.id) OR EXISTS(SELECT 1 FROM rust_crate_exports WHERE declaration_blob_id = blobs.id))";
pub(super) const REINSERT_BLOB_SQL: &str =
    "INSERT INTO blobs(id, blob_oid, lang, generation) VALUES(?1, ?2, ?3, ?4)";

pub(super) const INSERT_NAMING_SQL: &str =
    "INSERT INTO rust_crate_file_naming VALUES(?1,?2,jsonb(?3),jsonb(?4))";

pub(super) const INSERT_MODULE_SQL: &str =
    "INSERT INTO rust_crate_containers VALUES(?1, ?2, 'module', ?3)";

pub(super) const MODULE_WALK_SQL: &str = include_str!("rust_crate_module_walk.sql");

pub(super) const ITEM_MACRO_DECISIONS_SQL: &str =
    include_str!("rust_crate_item_macro_decisions.sql");

pub(super) const DELETE_UNBOUND_TOPOLOGIES_SQL: &str = SQL_RUST_CRATE_TOPOLOGIES_1;

#[path = "rust_crate_derivation.rs"]
mod derivation;

type CrateKey = [u8; 32];

/// The version of the crate-row derivation itself: the statements under
/// `store/rust_crate_*.sql`, the module route walk, and the order
/// `derive_exports` runs them in. It is hashed into every topology digest, so a
/// store built under an earlier rule set re-derives its crate rows although its
/// inputs are unchanged. Bump it whenever those rules change.
///
/// The digest also folds in the Rust analysis epoch, which versions the
/// per-blob payloads the derivation reads. Keeping the two apart is the point:
/// rotating the epoch for a consumer-side change would make every Rust blob
/// dirty and force a full reparse of a warm store.
const RUST_CRATE_DERIVATION_VERSION: &str = "3746-2026-09-30-macro-scope-f";

/// Set by `crate_topology_digests_follow_the_derivation_version` and
/// `warm_derivation_version_rotation_replaces_same_revision_versions` so that a
/// test can derive under a second version and compare. Nothing else writes it.
#[cfg(any(test, feature = "test-support"))]
static DERIVATION_VERSION_OVERRIDE: std::sync::Mutex<Option<&'static str>> =
    std::sync::Mutex::new(None);

/// The derivation version this process derives under.
fn derivation_version() -> &'static str {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(version) = *DERIVATION_VERSION_OVERRIDE
        .lock()
        .expect("derivation version override lock")
    {
        return version;
    }
    RUST_CRATE_DERIVATION_VERSION
}

#[cfg(test)]
fn set_derivation_version(version: Option<&'static str>) {
    *DERIVATION_VERSION_OVERRIDE
        .lock()
        .expect("derivation version override lock") = version;
}

struct Member {
    module_path: String,
    blob_id: i64,
    scope: i64,
    rel_path: String,
    placement: String,
    /// The module that declares this one; `None` only for the crate root.
    parent_path: Option<String>,
}
struct Gap {
    kind: &'static str,
    subject: String,
    detail: String,
}
struct PreparedCrate {
    target: RustCrateTarget,
    key: CrateKey,
    manifest_version: Option<i64>,
    inventory_error: Option<String>,
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
/// changed". Every other live crate keeps the topology the previous pass
/// derived for it, read back by key rather than recomputed.
///
/// This is which crates, not how to reconcile: both values run the same pass.
/// `from_revision` is the head revision the crate rows were current for
/// before the change; the pass advances the reconciliation marker only from
/// there.
enum CrateReconcileScope {
    Everything,
    Reached {
        crates: HashSet<CrateKey>,
        from_revision: i64,
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
    pub(crate) fn reconcile_rust_crates(&self, snapshot: &WorkspaceSnapshotId) -> Result<()> {
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
    pub(crate) fn reconcile_rust_crates_unless_current(
        &self,
        snapshot: &WorkspaceSnapshotId,
    ) -> Result<()> {
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
            return Ok(());
        }
        self.reconcile_rust_crates(snapshot)
    }

    /// Reconcile the crates a set of changed paths reached.
    ///
    /// One changed file costs its own crates and, when its export surface
    /// moved, their dependents. Everything else keeps the topology the last
    /// pass derived. Three changes send the work back to the whole workspace,
    /// because each of them can change crate membership itself rather than a
    /// crate's contents: a Cargo manifest or lock file, a workspace manifest,
    /// and a changed path no crate places, which is what a newly added file
    /// looks like to a `mod` declaration that already named it.
    ///
    /// `previous` is the snapshot the crate rows were reconciled against
    /// before these changes.
    pub(crate) fn reconcile_rust_crates_after_changes(
        &self,
        previous: &WorkspaceSnapshotId,
        snapshot: &WorkspaceSnapshotId,
        changed_paths: &[String],
    ) -> Result<()> {
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

    /// Resolve changed paths to the crates that place them.
    fn rust_crate_reconcile_scope(
        &self,
        snapshot: &WorkspaceSnapshotId,
        from_revision: i64,
        changed_paths: &[String],
    ) -> Result<CrateReconcileScope> {
        let rust_paths = changed_paths
            .iter()
            .filter(|path| {
                let path = path.as_str();
                path.ends_with(".rs") || path.ends_with(".toml") || path.ends_with(".lock")
            })
            .collect::<Vec<_>>();
        if rust_paths.is_empty() {
            return Ok(CrateReconcileScope::Reached {
                crates: HashSet::new(),
                from_revision,
            });
        }
        if rust_paths.iter().any(|path| {
            let path = path.as_str();
            path.ends_with("Cargo.toml") || path.ends_with("Cargo.lock") || path.ends_with(".toml")
        }) {
            return Ok(CrateReconcileScope::Everything);
        }
        let snapshots = WorkspaceSnapshots::from_iter([("rust".to_string(), snapshot.clone())]);
        let conn = self.read_conn_for_workspace(&snapshots)?;
        let mut statement = conn.prepare(SQL_RUST_CRATE_TOPOLOGIES_FOR_PATH)?;
        let mut reached = HashSet::new();
        for path in rust_paths {
            let mut placed = false;
            for key in statement.query_map(
                params![
                    snapshot.workspace_id.as_str(),
                    snapshot.generation.0,
                    path.as_str()
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )? {
                placed = true;
                reached.insert(crate_key_from_row(key?)?);
            }
            if !placed {
                // A path no crate places can join one, so the membership
                // question is the whole workspace's again.
                return Ok(CrateReconcileScope::Everything);
            }
        }
        Ok(CrateReconcileScope::Reached {
            crates: reached,
            from_revision,
        })
    }

    /// The topology and export surface this generation already derived for
    /// every live crate.
    fn live_rust_crate_topologies(
        &self,
        snapshots: &WorkspaceSnapshots,
        snapshot: &WorkspaceSnapshotId,
    ) -> Result<HashMap<CrateKey, DerivedCrate>> {
        let conn = self.read_conn_for_workspace(snapshots)?;
        let mut live = HashMap::new();
        for row in conn.prepare(SQL_RUST_CRATE_LIVE_TOPOLOGIES)?.query_map(
            params![snapshot.workspace_id.as_str(), snapshot.generation.0],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )? {
            let (key, topology_id, surface) = row?;
            let key = crate_key_from_row(key)?;
            live.insert(
                key,
                DerivedCrate {
                    key,
                    topology_id,
                    surface: crate_key_from_row(surface)?,
                },
            );
        }
        Ok(live)
    }

    /// The live crates that name one crate as a dependency.
    fn live_rust_crate_dependents(
        &self,
        snapshots: &WorkspaceSnapshots,
        snapshot: &WorkspaceSnapshotId,
        dependency: CrateKey,
    ) -> Result<Vec<CrateKey>> {
        let conn = self.read_conn_for_workspace(snapshots)?;
        conn.prepare(SQL_RUST_CRATE_DEPENDENTS)?
            .query_map(
                params![
                    snapshot.workspace_id.as_str(),
                    snapshot.generation.0,
                    dependency.as_slice()
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )?
            .map(|key| crate_key_from_row(key?))
            .collect()
    }

    fn reconcile_rust_crates_in_scope(
        &self,
        snapshot: &WorkspaceSnapshotId,
        scope: CrateReconcileScope,
    ) -> Result<()> {
        assert_eq!(snapshot.lang, "rust");
        let started = std::time::Instant::now();
        let snapshots = WorkspaceSnapshots::from_iter([("rust".to_string(), snapshot.clone())]);
        let prelude_timing = crate::profiling::scope("rust_crates.reconcile.inputs");
        let (mut crates, paths, epoch, inventory_errors, naming) = {
            let conn = self.read_conn_for_workspace(&snapshots)?;
            #[cfg(test)]
            let _trace =
                StatementTrace::new(&conn, self.crate_statement_counter.lock().unwrap().clone());
            let mut statement = conn.prepare(SQL_WORKSPACE_FILE_VERSIONS_2)?;
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
            let mut manifests = Vec::new();
            let mut inventory_errors = Vec::new();
            let mut manifest_versions = HashMap::new();
            for (version, path, oid, source) in rows {
                let Some(source) = source else {
                    inventory_errors.push(format!("{path}: retained manifest source is missing"));
                    continue;
                };
                let manifest = RustSelectedManifestMount::from_retained_source(
                    PathBuf::from(&path),
                    Oid::from_str(&oid)?,
                    source.into_boxed_slice(),
                );
                let manifest = match manifest {
                    Ok(manifest) => manifest,
                    Err(error) => {
                        inventory_errors.push(format!("{path}: {error}"));
                        continue;
                    }
                };
                manifest_versions.insert(PathBuf::from(path), version);
                manifests.push(manifest);
            }
            let paths = conn
                .prepare(SQL_SELECTED_WORKSPACE_FILE_VERSIONS_3)?
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
            let targets = rust_crate_targets(
                paths
                    .iter()
                    .map(|(path, oid)| Ok((PathBuf::from(path), Oid::from_str(oid)?)))
                    .collect::<Result<Vec<_>>>()?,
                manifests,
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
                        inventory_error: None,
                        manifest_version: manifest_versions.get(&target.manifest_path).copied(),
                        dependencies,
                        target,
                    }
                })
                .collect::<Vec<_>>();
            let epoch: String = conn.query_row(SQL_ANALYSIS_EPOCHS_4, [], |row| row.get(0))?;
            (crates, paths, epoch, inventory_errors, naming)
        };
        drop(prelude_timing);
        let waves_timing = crate::profiling::scope("rust_crates.reconcile.waves");
        let mut complete = HashMap::<CrateKey, DerivedCrate>::new();
        // Crates this pass actually walked, as opposed to the live set it
        // publishes. The two differ exactly by what scoping saved.
        let mut derived_count = 0_usize;
        // A scoped pass publishes the whole live crate set: the crates it does
        // not derive keep the topology the last pass gave them, read back by
        // key. Seeding them here is what lets the version-closing pass below
        // stay exactly as the from-scratch pass leaves it, and what lets a
        // derived crate fold an undisturbed dependency's surface.
        let (previous, mut reached, mut unreached, from_revision) = match scope {
            CrateReconcileScope::Everything => (HashMap::new(), None, Vec::new(), None),
            CrateReconcileScope::Reached {
                crates: keys,
                from_revision,
            } => {
                let previous = self.live_rust_crate_topologies(&snapshots, snapshot)?;
                for (key, derived) in &previous {
                    if !keys.contains(key) {
                        complete.insert(*key, *derived);
                    }
                }
                let (wanted, rest): (Vec<_>, Vec<_>) = crates
                    .into_iter()
                    .partition(|item| keys.contains(&item.key));
                crates = wanted;
                (previous, Some(keys), rest, Some(from_revision))
            }
        };
        while !crates.is_empty() {
            let (mut wave, mut pending): (Vec<_>, Vec<_>) = crates.into_iter().partition(|item| {
                item.dependencies
                    .iter()
                    .all(|(_, _, key)| key.is_none_or(|key| complete.contains_key(&key)))
            });
            if wave.is_empty() {
                for item in &mut pending {
                    item.target.inventory_complete = false;
                }
                wave = std::mem::take(&mut pending);
            }
            let results = install_on_dedicated_build_pool(|| {
                wave.par_iter()
                    .map(|item| {
                        self.derive_rust_crate(item, &snapshots, &epoch, &complete, &naming)
                    })
                    .collect::<Vec<_>>()
            });
            let mut failures = Vec::new();
            let mut moved_surfaces = Vec::new();
            derived_count += wave.len();
            for result in results {
                match result {
                    Ok(derived) => {
                        // Only a crate whose export surface actually moved can
                        // change a dependent's digest. A body edit moves none,
                        // and reaches no dependent.
                        if previous
                            .get(&derived.key)
                            .is_none_or(|before| before.surface != derived.surface)
                        {
                            moved_surfaces.push(derived.key);
                        }
                        complete.insert(derived.key, derived);
                    }
                    Err(error) => failures.push(error),
                }
            }
            if !failures.is_empty() {
                return Err(StoreError::new(format!(
                    "crate derivation wave failed: {failures:?}"
                )));
            }
            crates = pending;
            if let Some(reached) = reached.as_mut() {
                for key in moved_surfaces {
                    for dependent in self.live_rust_crate_dependents(&snapshots, snapshot, key)? {
                        if !reached.insert(dependent) {
                            continue;
                        }
                        complete.remove(&dependent);
                        if let Some(position) =
                            unreached.iter().position(|item| item.key == dependent)
                        {
                            crates.push(unreached.swap_remove(position));
                        }
                    }
                }
            }
        }
        drop(waves_timing);
        let detached_timing = crate::profiling::scope("rust_crates.reconcile.detached");
        // A detached crate is one file no Cargo target placed. A scoped pass
        // only runs when the crate rows placed every changed path, so no file
        // can have joined or left the detached set and the seeded rows above
        // already carry it. The from-scratch pass recomputes it.
        let detached_paths = if reached.is_some() {
            Vec::new()
        } else {
            let conn = self.read_conn_for_workspace(&snapshots)?;
            #[cfg(test)]
            let _trace =
                StatementTrace::new(&conn, self.crate_statement_counter.lock().unwrap().clone());
            let mut reached = HashSet::new();
            for item in complete.values() {
                let mut statement = conn.prepare(SQL_RUST_CRATE_MODULES_5)?;
                for path in
                    statement.query_map([item.topology_id], |row| row.get::<_, String>(0))?
                {
                    reached.insert(path?);
                }
            }
            paths
                .into_iter()
                .filter(|(path, _)| !reached.contains(path))
                .collect::<Vec<_>>()
        };
        for (path, _) in detached_paths {
            let root_path = PathBuf::from(&path);
            let target = RustCrateTarget {
                manifest_path: root_path.clone(),
                root_path,
                kind: RustCallerTargetKind::Detached,
                name: path.clone(),
                edition: RustCargoEdition::Rust2021,
                cfg_atoms: brokk_bifrost_rust::cfg::default_cfg_atoms(),
                features: BTreeSet::new(),
                dependencies: Vec::new(),
                inventory_complete: true,
            };
            let item = PreparedCrate {
                key: crate_key(&target),
                manifest_version: None,
                inventory_error: (!inventory_errors.is_empty())
                    .then(|| format!("{inventory_errors:?}")),
                dependencies: Vec::new(),
                target,
            };
            let result = self.derive_rust_crate(&item, &snapshots, &epoch, &complete, &naming)?;
            derived_count += 1;
            complete.insert(result.key, result);
        }
        drop(detached_timing);
        let close_timing = crate::profiling::scope("rust_crates.reconcile.close_versions");
        let snapshot = snapshot.clone();
        let keys: HashSet<Vec<u8>> = complete.keys().map(|key| key.to_vec()).collect();
        #[cfg(test)]
        let counter = self.crate_statement_counter.lock().unwrap().clone();
        self.conn.execute(move |conn| -> Result<()> {
            let tx = conn.transaction()?;
            #[cfg(test)]
            let trace = StatementTrace::new(&tx, counter);
            let open = tx
                .prepare(SQL_RUST_CRATE_VERSIONS_6)?
                .query_map(
                    params![snapshot.workspace_id.as_str(), snapshot.generation.0],
                    |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
                )?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            for (key, opened) in open {
                if !keys.contains(&key) {
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
                None => tx.execute(SQL_RUST_CRATE_RECONCILIATION_RECORD, marker)?,
                // A scoped pass is only as current as the rows it started
                // from, so it moves the marker only from the revision it
                // started at. After a failed or skipped pass the marker stays
                // behind the head, and the next start runs the full pass.
                Some(from_revision) => tx.execute(
                    SQL_RUST_CRATE_RECONCILIATION_ADVANCE,
                    params![
                        snapshot.workspace_id.as_str(),
                        snapshot.generation.0,
                        snapshot.revision,
                        derivation_version(),
                        from_revision
                    ],
                )?,
            };
            #[cfg(test)]
            drop(trace);
            tx.commit()?;
            Ok(())
        })?;
        drop(close_timing);
        crate::profiling::note_with(|| {
            format!(
                "rust_crates.reconcile: {:.1} ms, {} crates, {} derived",
                started.elapsed().as_secs_f64() * 1000.0,
                complete.len(),
                derived_count
            )
        });
        Ok(())
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
            let rows = conn
                .prepare_cached(MODULE_WALK_SQL)?
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
                    })
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            // Only an active placement carries macro scope: a module the walk
            // left inactive, duplicated or undecided is not a member, so its
            // file neither inherits the mounting file's `macro_rules!` nor
            // offers its own invocations for decision.
            let mounted = rows.iter().filter(|row| row.activation == 1);
            let mounts = serde_json::Value::Array(
                mounted
                    .clone()
                    .filter_map(|row| {
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

    fn derive_rust_crate(
        &self,
        item: &PreparedCrate,
        snapshots: &WorkspaceSnapshots,
        epoch: &str,
        complete: &HashMap<CrateKey, DerivedCrate>,
        naming: &brokk_bifrost_rust::crate_naming::RustSelectedCargoNaming,
    ) -> Result<DerivedCrate> {
        let _crate_timing = crate::profiling::scope_with(|| {
            format!(
                "rust_crates.crate name={} kind={} root={}",
                item.target.name,
                target_kind(item.target.kind),
                stable_path(&item.target.root_path)
            )
        });
        let conn = self.read_conn_for_workspace(snapshots)?;
        #[cfg(test)]
        let trace =
            StatementTrace::new(&conn, self.crate_statement_counter.lock().unwrap().clone());
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
        // A duplicate placement is keyed on the module path, not on the file.
        // rustc compiles a file reached from two `mod` declarations once per
        // declaration, and the two results are distinct modules that hold
        // distinct items, so two placements of one file under two module paths
        // are two rows here. What the crate rows cannot hold is one module path
        // placed from two files, which is what `mod foo;` means when `foo.rs`
        // and `foo/mod.rs` both exist; that stays a gap. Only an active
        // placement can conflict, because an inactive or undecided one is not a
        // member and already carries its own gap kind.
        let mut counts = HashMap::new();
        for row in &rows {
            if row.placement != "include" && row.activation == 1 {
                *counts.entry(&row.module_path).or_insert(0) += 1;
            }
        }
        let mut modules = Vec::new();
        let mut gaps = Vec::new();
        if let Some(error) = &item.inventory_error {
            gaps.push(Gap {
                kind: "unsupported_manifest",
                subject: stable_path(&item.target.root_path),
                detail: serde_json::json!({"reason": error}).to_string(),
            });
        }
        for WalkRow {
            module_path,
            blob,
            scope,
            path,
            placement,
            activation,
            parent_path,
            ..
        } in &rows
        {
            let kind = if *activation == 0 {
                Some("inactive_placement")
            } else if *activation < 0 {
                Some("unknown_activation")
            } else if blob.is_none() {
                Some("unplaced_module")
            } else if counts.get(module_path).copied().unwrap_or(0) > 1 {
                Some("duplicate_placement")
            } else {
                None
            };
            if let Some(kind) = kind {
                gaps.push(Gap {
                    kind,
                    subject: module_path.clone(),
                    detail: serde_json::json!({"path": path, "activation": activation}).to_string(),
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
        for member in &modules {
            hash_cell(&mut digest, member.module_path.as_bytes());
            let oid: String = conn.query_row(SQL_BLOBS_8, [member.blob_id], |row| row.get(0))?;
            hash_cell(&mut digest, oid.as_bytes());
            hash_cell(&mut digest, member.rel_path.as_bytes());
            hash_cell(&mut digest, member.placement.as_bytes());
        }
        for (name, kind, key) in &item.dependencies {
            hash_cell(&mut digest, name.as_bytes());
            hash_cell(&mut digest, kind.as_bytes());
            if let Some(key) = key {
                hash_cell(&mut digest, key);
                if let Some(dependency) = complete.get(key) {
                    hash_cell(&mut digest, &dependency.surface);
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
            .expect("a crate has a root module")
            .blob_id;
        let attributes = conn
            .prepare_cached(SQL_ROOT_INNER_ATTRIBUTES)?
            .query_map([root_blob], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let prelude = if attributes.iter().any(|name| name == "no_core") {
            "none"
        } else if attributes.iter().any(|name| name == "no_std") {
            "core"
        } else {
            "std"
        };
        let existing: Option<(i64, Vec<u8>)> = conn
            .query_row(SQL_RUST_CRATE_TOPOLOGIES_9, [digest.as_slice()], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .optional()?;
        let derived = existing
            .is_none()
            .then(|| {
                derivation::derive_exports(&conn, item, &modules, &gate_decisions, &cfg, complete)
            })
            .transpose()?;
        #[cfg(test)]
        drop(trace);
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
        #[cfg(test)]
        let counter = self.crate_statement_counter.lock().unwrap().clone();
        self.conn.execute(move |conn| -> Result<DerivedCrate> {
            let _timing = crate::profiling::scope_with(|| {
                format!(
                    "rust_crates.publication name={} kind={}",
                    target.name,
                    target_kind(target.kind)
                )
            });
            let tx = conn.transaction()?;
            #[cfg(test)]
            let trace = StatementTrace::new(&tx, counter);
            let (topology_id, surface) = if let Some((id, surface)) = existing {
                (id, surface.try_into().expect("schema checks digest length"))
            } else {
                tx.execute(
                    SQL_RUST_CRATE_TOPOLOGIES_10,
                    params![
                        digest.as_slice(),
                        key.as_slice(),
                        epoch,
                        target_kind(target.kind),
                        target.name,
                        edition(target.edition),
                        cfg,
                        target.inventory_complete,
                        prelude
                    ],
                )?;
                let id = tx.last_insert_rowid();
                for (path, package, root) in naming_rows {
                    tx.execute(INSERT_NAMING_SQL, params![id, path, package, root])?;
                }
                for member in &modules {
                    if member.placement != "include" {
                        tx.execute(
                            INSERT_MODULE_SQL,
                            params![id, member.module_path, member.placement],
                        )?;
                    }
                }
                for member in modules {
                    tx.execute(
                        SQL_RUST_CRATE_MODULES_11,
                        params![
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
                        ],
                    )?;
                }
                for (name, kind, dependency) in dependencies {
                    tx.execute(
                        SQL_RUST_CRATE_DEPENDENCIES_12,
                        params![
                            id,
                            name,
                            if dependency.is_some() {
                                "workspace"
                            } else {
                                "external"
                            },
                            dependency.map(|key| key.to_vec()),
                            kind
                        ],
                    )?;
                }
                for gap in gaps {
                    tx.execute(
                        SQL_RUST_CRATE_GAPS_13,
                        params![id, gap.kind, gap.subject, gap.detail],
                    )?;
                }
                let derived = derived.expect("missing topology was derived on its reader");
                let surface = derived.publish(&tx, id)?;
                tx.execute(
                    SQL_RUST_CRATE_TOPOLOGIES_14,
                    params![surface.as_slice(), id],
                )?;
                (id, surface)
            };
            let open: Option<(i64, i64)> = tx
                .query_row(
                    SQL_RUST_CRATE_VERSIONS_15,
                    params![
                        snapshot.workspace_id.as_str(),
                        snapshot.generation.0,
                        key.as_slice()
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if open.map(|(open_topology, _)| open_topology) != Some(topology_id) {
                if let Some((_, opened)) = open {
                    end_open_crate_version(&tx, &snapshot, key.as_slice(), opened)?;
                }
                tx.execute(
                    SQL_RUST_CRATE_VERSIONS_17,
                    params![
                        snapshot.workspace_id.as_str(),
                        snapshot.generation.0,
                        key.as_slice(),
                        snapshot.revision,
                        manifest_version,
                        topology_id
                    ],
                )?;
            }
            #[cfg(test)]
            drop(trace);
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
    let changed = conn.execute(
        statement,
        params![
            snapshot.revision,
            snapshot.workspace_id.as_str(),
            snapshot.generation.0,
            key
        ],
    )?;
    assert_eq!(
        changed, 1,
        "crate {key:02x?} must have exactly one open version row"
    );
    Ok(())
}

/// A crate key as the schema guarantees it: exactly 32 bytes.
fn crate_key_from_row(key: Vec<u8>) -> Result<CrateKey> {
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
fn edition(edition: RustCargoEdition) -> &'static str {
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
pub(super) fn register_point_export_functions(conn: &Connection) -> Result<()> {
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
            .prepare("SELECT name, narg FROM pragma_function_list WHERE builtin = 0")
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
        let base: String = context.get(0)?;
        let path: String = context.get(1)?;
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

#[cfg(test)]
struct StatementTrace<'a> {
    conn: &'a Connection,
    counter: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
}
#[cfg(test)]
impl<'a> StatementTrace<'a> {
    fn new(
        conn: &'a Connection,
        counter: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
    ) -> Self {
        unsafe extern "C" fn count(
            event: std::ffi::c_uint,
            context: *mut std::ffi::c_void,
            _: *mut std::ffi::c_void,
            _: *mut std::ffi::c_void,
        ) -> std::ffi::c_int {
            if event == rusqlite::ffi::SQLITE_TRACE_STMT {
                // SAFETY: the guard retains this Arc until tracing is unregistered.
                let counter = unsafe { &*context.cast::<std::sync::atomic::AtomicUsize>() };
                counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            0
        }
        if let Some(counter) = &counter {
            // SAFETY: the callback retains no SQLite pointers; the guard owns
            // the counter and borrows the connection for the registration lifetime.
            let status = unsafe {
                rusqlite::ffi::sqlite3_trace_v2(
                    conn.handle(),
                    rusqlite::ffi::SQLITE_TRACE_STMT,
                    Some(count),
                    std::sync::Arc::as_ptr(counter).cast_mut().cast(),
                )
            };
            assert_eq!(status, rusqlite::ffi::SQLITE_OK);
        }
        Self { conn, counter }
    }
}
#[cfg(test)]
impl Drop for StatementTrace<'_> {
    fn drop(&mut self) {
        if self.counter.is_some() {
            // SAFETY: unregister before releasing the borrowed connection or Arc.
            let status = unsafe {
                rusqlite::ffi::sqlite3_trace_v2(self.conn.handle(), 0, None, std::ptr::null_mut())
            };
            assert_eq!(status, rusqlite::ffi::SQLITE_OK);
        }
    }
}

pub(super) const SQL_RUST_CRATE_TOPOLOGIES_1: &str =
    "DELETE FROM rust_crate_topologies WHERE NOT EXISTS (
         SELECT 1 FROM rust_crate_versions AS versions
         WHERE versions.topology_id = rust_crate_topologies.topology_id)";
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
pub(super) const SQL_RUST_CRATE_TOPOLOGIES_FOR_PATH: &str = "SELECT DISTINCT versions.crate_key
     FROM rust_crate_container_sources AS sources
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

pub(super) const SQL_RUST_CRATE_VERSIONS_6: &str = "SELECT crate_key, valid_from FROM rust_crate_versions WHERE workspace_id = ?1 AND lang = 'rust' AND generation = ?2 AND valid_until IS NULL";
pub(super) const SQL_BLOBS_8: &str = "SELECT blob_oid FROM blobs WHERE id = ?1";
pub(super) const SQL_RUST_CRATE_TOPOLOGIES_9: &str = "SELECT topology_id, export_surface_digest FROM rust_crate_topologies WHERE topology_digest = ?1 AND publication_state = 'complete'";
pub(super) const SQL_RUST_CRATE_TOPOLOGIES_10: &str = "INSERT INTO rust_crate_topologies(topology_digest, crate_key, producer_epoch, target_kind, crate_name, edition, prelude, cfg_atoms, inventory_complete, publication_state) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?9, jsonb(?7), ?8, 'building')";
/// The crate root file's top-level inner attribute names, for the crate's
/// prelude: `no_core` selects none, `no_std` selects core, and otherwise the
/// crate uses std's.
pub(super) const SQL_ROOT_INNER_ATTRIBUTES: &str =
    "SELECT name FROM source_rust_inner_attributes WHERE blob_id = ?1 ORDER BY ordinal";
pub(super) const SQL_RUST_CRATE_MODULES_11: &str =
    "INSERT INTO rust_crate_container_sources VALUES(?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7)";
pub(super) const SQL_RUST_CRATE_DEPENDENCIES_12: &str =
    "INSERT INTO rust_crate_dependencies VALUES(?1, ?2, ?3, ?4, ?5)";
pub(super) const SQL_RUST_CRATE_GAPS_13: &str =
    "INSERT OR IGNORE INTO rust_crate_gaps VALUES(?1, ?2, ?3, jsonb(?4))";
pub(super) const SQL_RUST_CRATE_TOPOLOGIES_14: &str = "UPDATE rust_crate_topologies SET export_surface_digest = ?1, publication_state = 'complete' WHERE topology_id = ?2";
pub(super) const SQL_RUST_CRATE_VERSIONS_15: &str = "SELECT topology_id, valid_from FROM rust_crate_versions WHERE workspace_id = ?1 AND lang = 'rust' AND generation = ?2 AND crate_key = ?3 AND valid_until IS NULL";
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
        (
            "rust_crate_reconcile_sql_rust_crate_topologies_1",
            SQL_RUST_CRATE_TOPOLOGIES_1,
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
        ("rust_crate_replaced_blob_id", REPLACED_BLOB_ID_SQL, 3),
        ("rust_crate_reinsert_blob", REINSERT_BLOB_SQL, 4),
        ("rust_crate_reconcile_sql_blobs_8", SQL_BLOBS_8, 1),
        (
            "rust_crate_reconcile_sql_rust_crate_topologies_9",
            SQL_RUST_CRATE_TOPOLOGIES_9,
            1,
        ),
        (
            "rust_crate_reconcile_sql_rust_crate_topologies_10",
            SQL_RUST_CRATE_TOPOLOGIES_10,
            9,
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
    pins.extend([
        (
            "rust_crate_export_declarations",
            derivation::DECLARATIONS_SQL,
            0,
        ),
        (
            "rust_crate_import_routes",
            derivation::ROUTES_SQL.as_str(),
            2,
        ),
        ("rust_crate_export_fixpoint", derivation::FIXPOINT_SQL, 1),
    ]);
    pins
}
#[cfg(any(test, feature = "test-support"))]
pub(super) fn prepare_pin_context(conn: &Connection) -> Result<()> {
    register_point_export_functions(conn)?;
    derivation::prepare_tables(conn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AnalyzerConfig;
    use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};

    fn fixture() -> BuiltInlineTestProject {
        InlineTestProject::new()
            .file("Cargo.toml", "[workspace]\nmembers = [\"app\", \"dep\", \"helper\"]\nresolver = \"2\"\n")
            .file("app/Cargo.toml", "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\ndep = { path = \"../dep\", features = [\"on\"] }\n[dev-dependencies]\nhelper = { path = \"../helper\" }\n")
            .file("dep/Cargo.toml", "[package]\nname = \"dep\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[features]\non = []\noff = []\n")
            .file("helper/Cargo.toml", "[package]\nname = \"helper\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
            .file("app/src/lib.rs", r#"
                pub mod a;
                #[path = "shared.rs"] mod shared;
                pub mod m { pub fn inside() {} }
                #[cfg(test)] mod tests { pub fn test_only() {} }
                pub use a::*;
                pub use a::original as b;
                pub use a::b as first;
                pub use first as second;
                pub use second as third;
                pub use dep::X;
                use crate::a::{b as c};
            "#)
            .file("app/src/main.rs", "#[path = \"shared.rs\"] mod shared; fn main() {}")
            .file("app/src/shared.rs", "pub fn shared() {}")
            .file("app/src/a.rs", "use super::*; pub fn b() { let body = 1; } pub fn original() {}")
            .file("app/tests/x.rs", "use helper::H; #[test] fn x() {}")
            .file("dep/src/lib.rs", "pub struct X(pub u8); #[cfg(feature = \"on\")] pub mod on; #[cfg(feature = \"off\")] pub mod off;")
            .file("dep/src/on.rs", "pub fn enabled() {}")
            .file("dep/src/off.rs", "pub fn disabled() {}")
            .file("helper/src/lib.rs", "pub struct H;")
            .file("detached.rs", "pub fn detached() {}")
            .build()
    }

    fn current_crate_digests(conn: &Connection) -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        conn.prepare("SELECT t.crate_key,t.topology_digest,t.export_surface_digest FROM rust_crate_versions v JOIN rust_crate_topologies t USING(topology_id) WHERE v.valid_until IS NULL ORDER BY t.crate_key").unwrap().query_map([], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
    }

    /// A scoped reconcile publishes what the from-scratch pass would.
    ///
    /// Gate 13: one changed file costs its own crates, not the workspace. The
    /// oracle is the from-scratch pass on the same cache right after the
    /// scoped one, which must find nothing left to change.
    ///
    /// Each edit goes through `update`, which is what production calls, so the
    /// store really holds the new blob; a reconcile run against an unchanged
    /// blob proves nothing. `app` depends on `dep`, so `app`'s digest folds
    /// `dep`'s export surface, and that surface is export names rather than
    /// signatures: only the third edit moves it and only that one may derive
    /// `app` again.
    #[test]
    fn a_scoped_reconcile_publishes_what_the_full_pass_would() {
        let fixture = fixture();
        let mut analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());

        let head = |store: &AnalyzerStore| {
            let row = store
                .read_conn()
                .unwrap()
                .query_row(
                    "SELECT workspace_id, generation, revision FROM workspace_heads WHERE lang='rust'",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .unwrap();
            WorkspaceSnapshotId {
                workspace_id: super::super::WorkspaceId(row.0),
                lang: "rust".into(),
                generation: super::super::GenerationId::from_persisted(row.1),
                revision: row.2,
            }
        };
        let app_digest = |store: &AnalyzerStore| -> Vec<u8> {
            store
                .read_conn()
                .unwrap()
                .query_row(
                    "SELECT t.topology_digest FROM rust_crate_versions v
                     JOIN rust_crate_topologies t USING(topology_id)
                     WHERE v.valid_until IS NULL AND t.crate_name='app' AND t.target_kind='lib'",
                    [],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .unwrap()
        };

        for (path, contents, reaches_dependents) in [
            // A body: no export name moves.
            (
                "dep/src/on.rs",
                "pub fn enabled() { let body = 1; let _ = body; }",
                false,
            ),
            // A signature: still no export name moves. The crate rows record
            // what a crate exports, not how it is called.
            ("dep/src/on.rs", "pub fn enabled(_added: u8) {}", false),
            // A new public item: the export surface moves, so `app` is derived
            // again even though no file of `app` changed.
            (
                "dep/src/on.rs",
                "pub fn enabled(_added: u8) {} pub fn appeared() {}",
                true,
            ),
        ] {
            let before = app_digest(analyzer.store().unwrap().as_ref());
            let file = fixture.file(path);
            file.write(contents).unwrap();
            analyzer = analyzer.update(&BTreeSet::from([file]));
            let store = analyzer.store().unwrap();
            assert_eq!(
                app_digest(store.as_ref()) != before,
                reaches_dependents,
                "{path}: a dependent is derived again exactly when its dependency's \
                 export surface moved"
            );
            let scoped = current_crate_digests(&store.read_conn().unwrap());
            store.reconcile_rust_crates(&head(store.as_ref())).unwrap();
            assert_eq!(
                current_crate_digests(&store.read_conn().unwrap()),
                scoped,
                "{path}: the from-scratch pass must find nothing the scoped pass missed"
            );
        }

        // A manifest can move crate membership, so it is never scoped, and
        // neither is a path no crate places, which is what a new file looks
        // like to a `mod` declaration that already named it.
        let store = analyzer.store().unwrap();
        let snapshot = head(store.as_ref());
        for path in ["dep/Cargo.toml", "dep/src/brand_new.rs"] {
            assert!(
                matches!(
                    store
                        .rust_crate_reconcile_scope(
                            &snapshot,
                            snapshot.revision,
                            &[path.to_owned()]
                        )
                        .unwrap(),
                    CrateReconcileScope::Everything
                ),
                "{path} must reconcile the whole workspace"
            );
        }
        assert!(
            matches!(
                store
                    .rust_crate_reconcile_scope(
                        &snapshot,
                        snapshot.revision,
                        &["dep/src/on.rs".to_owned()]
                    )
                    .unwrap(),
                CrateReconcileScope::Reached { crates, .. } if !crates.is_empty()
            ),
            "a placed source file reaches its own crates"
        );
    }

    /// A warm start skips the full reconcile exactly while the marker says the
    /// crate rows are current for the head revision and derivation version.
    ///
    /// The skip is observed by removing one open crate version behind the
    /// marker's back: a start that skips leaves it missing, and a start
    /// without the marker runs the full pass, which restores it. An
    /// incremental update advances the marker to the head it reconciled.
    #[test]
    fn a_warm_start_skips_the_full_reconcile_only_while_the_marker_is_current() {
        use crate::analyzer::WorkspaceAnalyzer;
        let project = fixture();
        let build = || {
            WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
                .expect("the workspace builds")
        };
        let read = |analyzer: &WorkspaceAnalyzer, sql: &str| -> Vec<(i64, String)> {
            analyzer
                .store()
                .unwrap()
                .read_conn()
                .unwrap()
                .prepare(sql)
                .unwrap()
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        let marker = |analyzer: &WorkspaceAnalyzer| {
            read(
                analyzer,
                "SELECT revision, derivation_version FROM rust_crate_reconciliations",
            )
        };
        let current = |analyzer: &WorkspaceAnalyzer| {
            read(
                analyzer,
                "SELECT revision, '' FROM workspace_heads WHERE lang = 'rust'",
            )
            .into_iter()
            .map(|(revision, _)| (revision, RUST_CRATE_DERIVATION_VERSION.to_owned()))
            .collect::<Vec<_>>()
        };
        let open_versions = |analyzer: &WorkspaceAnalyzer| {
            read(
                analyzer,
                "SELECT count(*), '' FROM rust_crate_versions WHERE valid_until IS NULL",
            )[0]
            .0
        };
        let tamper = |analyzer: &WorkspaceAnalyzer, sql: &'static str| {
            analyzer
                .store()
                .unwrap()
                .conn
                .execute(move |conn| conn.execute(sql, []))
                .unwrap()
        };

        let first = build();
        assert_eq!(
            marker(&first),
            current(&first),
            "a full pass records the marker"
        );
        let open = open_versions(&first);
        assert_eq!(
            tamper(
                &first,
                "DELETE FROM rust_crate_versions WHERE valid_until IS NULL AND crate_key =
                   (SELECT min(crate_key) FROM rust_crate_versions WHERE valid_until IS NULL)"
            ),
            1
        );
        drop(first);

        let skipped = build();
        assert_eq!(
            open_versions(&skipped),
            open - 1,
            "a start with a current marker walks no crate"
        );
        assert_eq!(
            tamper(&skipped, "DELETE FROM rust_crate_reconciliations"),
            1
        );
        drop(skipped);

        let recovered = build();
        assert_eq!(
            open_versions(&recovered),
            open,
            "a start without the marker runs the full pass"
        );
        let recovered_marker = marker(&recovered);
        assert_eq!(recovered_marker, current(&recovered));

        let file = project.file("dep/src/on.rs");
        file.write("pub fn enabled() { let body = 1; let _ = body; }")
            .unwrap();
        let updated = recovered.update(&BTreeSet::from([file]));
        let after_update = marker(&updated);
        assert_eq!(
            after_update,
            current(&updated),
            "the scoped pass advances the marker"
        );
        assert_ne!(
            after_update, recovered_marker,
            "the update opened a revision"
        );
    }

    #[test]
    fn crate_import_gaps_distinguish_external_boundaries_from_missing_local_routes() {
        let fixture = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname = \"boundaries\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nanyhow = \"1\"\n")
            .file("src/lib.rs", "use std::path::PathBuf; use anyhow::Result; use anyhow as error_lib; use crate::missing::Local; #[cfg(any())] use absent::Inactive;")
            .build();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let gaps = conn.prepare("SELECT gap_kind, subject FROM rust_crate_gaps WHERE subject IN ('crate::PathBuf','crate::Result','crate::Local','crate::Inactive','crate::error_lib') ORDER BY subject")
            .unwrap().query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
            .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert_eq!(
            gaps,
            vec![
                ("unresolved_import".into(), "crate::Local".into()),
                ("external_dependency".into(), "crate::PathBuf".into()),
                ("external_dependency".into(), "crate::Result".into()),
                ("external_dependency".into(), "crate::error_lib".into()),
            ]
        );
    }

    /// A `#[path]` module declared in an ordinary module file resolves against
    /// that file's own directory, the way Rust resolves it.
    ///
    /// The shared inline test harness is declared as
    /// `#[cfg(test)] #[path = "../../.../test-support/inline_project.rs"] mod
    /// inline_project;` in crate roots and in ordinary module files alike. Only
    /// the crate-root ones used to be placed: the walk carried a single base,
    /// the logical module directory, which for `coordinator.rs` is
    /// `src/coordinator/` rather than the `src/` the attribute is written
    /// against. The eight declarations in ordinary files therefore became
    /// `unplaced_module` gaps, and one such gap clears a target's
    /// `inventory_complete`.
    ///
    /// The ordinary `mod` declaration beside it is the control: it must keep
    /// resolving under the module directory, which is the base the two rules
    /// disagree about.
    #[test]
    fn a_path_attribute_in_a_module_file_resolves_against_that_file_directory() {
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname = \"harness_path\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("src/lib.rs", "pub mod coordinator;\n")
            .file(
                "src/coordinator.rs",
                "pub mod nested;\n\
                 #[cfg(test)]\n\
                 #[path = \"../test-support/harness.rs\"]\n\
                 mod harness;\n",
            )
            .file("src/coordinator/nested.rs", "pub fn nested() {}\n")
            .file("test-support/harness.rs", "pub struct Harness;\n")
            .build();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();

        let placed = conn.prepare("SELECT topologies.crate_name, containers.container_path, sources.rel_path, containers.placement FROM rust_crate_topologies AS topologies JOIN rust_crate_containers AS containers USING(topology_id) JOIN rust_crate_container_sources AS sources USING(topology_id, container_path) WHERE containers.container_path LIKE 'crate::coordinator%' ORDER BY 2")
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let gaps = conn
            .prepare("SELECT gap_kind, subject FROM rust_crate_gaps ORDER BY 1, 2")
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();

        assert!(
            placed.iter().any(|row| row
                == &(
                    "harness_path".to_string(),
                    "crate::coordinator::harness".to_string(),
                    "test-support/harness.rs".to_string(),
                    "path_attribute".to_string(),
                )),
            "placed={placed:?} gaps={gaps:?}"
        );
        assert!(
            placed.iter().any(|row| row
                == &(
                    "harness_path".to_string(),
                    "crate::coordinator::nested".to_string(),
                    "src/coordinator/nested.rs".to_string(),
                    "mod_declaration".to_string(),
                )),
            "placed={placed:?} gaps={gaps:?}"
        );
        assert!(
            !gaps.iter().any(|(kind, _)| kind == "unplaced_module"),
            "gaps={gaps:?}"
        );

        let incomplete = conn
            .prepare("SELECT crate_name, target_kind FROM rust_crate_topologies WHERE inventory_complete = 0 ORDER BY 1, 2")
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(incomplete, Vec::new(), "gaps={gaps:?}");
    }

    /// One file reached from two module files is two modules, not a gap.
    ///
    /// rustc compiles a file once per `mod` declaration that reaches it, and
    /// the results are distinct modules: `crate::coordinator::harness` and
    /// `crate::selector::harness` hold separate items with separate type
    /// identities. Owner decision of 2026-09-22: `duplicate_placement` is keyed
    /// on the module path, so two placements under two paths are two module
    /// rows. The container-source naming stays keyed on the file, because the
    /// package a file belongs to is a fact about the file.
    #[test]
    fn one_file_reached_from_two_module_files_is_two_modules() {
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname = \"shared_harness\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("src/lib.rs", "pub mod coordinator;\npub mod selector;\n")
            .file(
                "src/coordinator.rs",
                "#[cfg(test)]\n#[path = \"../test-support/harness.rs\"]\nmod harness;\n",
            )
            .file(
                "src/selector.rs",
                "#[cfg(test)]\n#[path = \"../test-support/harness.rs\"]\nmod harness;\n",
            )
            .file("test-support/harness.rs", "pub struct Harness;\n")
            .build();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let gaps = conn
            .prepare("SELECT gap_kind, subject FROM rust_crate_gaps ORDER BY 1, 2")
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(gaps, Vec::new(), "gaps={gaps:?}");

        let placements = conn
            .prepare(
                "SELECT source.container_path, source.rel_path, source.blob_id
                 FROM rust_crate_container_sources AS source
                 WHERE source.rel_path = 'test-support/harness.rs'
                 ORDER BY 1",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            placements
                .iter()
                .map(|(path, _, _)| path.as_str())
                .collect::<Vec<_>>(),
            vec!["crate::coordinator::harness", "crate::selector::harness"],
            "placements={placements:?}"
        );
        assert_eq!(
            placements[0].2, placements[1].2,
            "both placements carry the one file's blob: {placements:?}"
        );

        // The naming authority is a fact about the file, so it is written once
        // however many modules the crate compiles the file into.
        let named: usize = conn
            .query_row(
                "SELECT count(*) FROM rust_crate_file_naming WHERE rel_path = 'test-support/harness.rs'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(named, 1);

        let complete: i64 = conn
            .query_row(
                "SELECT inventory_complete FROM rust_crate_topologies",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(complete, 1);
    }

    /// Two files under one module path is the ambiguity the crate rows cannot
    /// hold, and it stays a `duplicate_placement` gap.
    ///
    /// `mod harness;` in a `mod.rs` looks for `harness.rs` and `harness/mod.rs`
    /// alike. rustc rejects a crate that offers both; the walk reaches the one
    /// module path twice, from two files, and neither placement becomes a
    /// member. This is the case the module-path key still refuses, and it is
    /// pinned beside the two-module case so the difference stays visible.
    #[test]
    fn one_module_path_placed_from_two_files_stays_a_duplicate_placement() {
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname = \"ambiguous_file\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("src/lib.rs", "pub mod harness;\n")
            .file("src/harness.rs", "pub struct FromFile;\n")
            .file("src/harness/mod.rs", "pub struct FromDirectory;\n")
            .build();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let gaps = conn
            .prepare("SELECT gap_kind, subject FROM rust_crate_gaps ORDER BY 1, 2")
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            gaps,
            vec![(
                "duplicate_placement".to_string(),
                "crate::harness".to_string()
            )]
        );
    }

    #[test]
    fn crate_enum_glob_import_has_a_persisted_demand_route() {
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname = \"enum_glob\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file(
                "src/lib.rs",
                "pub enum DatumType { A, B } pub fn select() -> DatumType { use DatumType::*; A }",
            )
            .build();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let gaps = conn.prepare("SELECT gap_kind, subject, json(detail) FROM rust_crate_gaps ORDER BY gap_kind, subject")
            .unwrap().query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)))
            .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        let globs: i64 = conn
            .query_row("SELECT count(*) FROM rust_crate_glob_imports", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            globs, 1,
            "the enum's glob import must have a row for endpoint closure; gaps={gaps:?}"
        );
    }

    #[test]
    fn crate_enum_named_variant_import_has_a_persisted_demand_route() {
        let fixture = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname = \"enum_named\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
            .file("src/lib.rs", "pub enum Shape { Circle(u32), Square { side: u32 }, Empty } use Shape::Circle; pub fn select() -> Shape { Circle(1) }")
            .build();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let variants = conn.prepare("SELECT namespace, name FROM rust_crate_exports WHERE module_path='crate::Shape' ORDER BY namespace, name")
            .unwrap().query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
            .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert_eq!(
            variants,
            vec![
                ("type".into(), "Circle".into()),
                ("type".into(), "Square".into()),
                ("value".into(), "Circle".into()),
                ("value".into(), "Empty".into()),
                ("value".into(), "Square".into()),
            ]
        );
        let imports = conn.prepare("SELECT namespace,target_module_path,target_name FROM rust_crate_imports WHERE bound_name='Circle' ORDER BY namespace")
            .unwrap().query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)))
            .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert_eq!(
            imports,
            vec![
                ("type".into(), "crate::Shape".into(), "Circle".into()),
                ("value".into(), "crate::Shape".into(), "Circle".into())
            ]
        );
        let containers: i64 = conn.query_row("SELECT count(*) FROM rust_crate_containers container JOIN rust_crate_container_sources source USING(topology_id,container_path) JOIN resolution_member_scope_properties scope ON scope.blob_id=source.blob_id AND scope.scope_head_node_key=source.enum_scope_node_key WHERE container.kind='enum' AND container.container_path='crate::Shape' AND source.scope_ordinal IS NULL", [], |row| row.get(0)).unwrap();
        assert_eq!(containers, 1);
    }

    #[test]
    fn crate_rows_reconcile_cargo_modules_and_body_update() {
        let fixture = fixture();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let before = {
            let conn = store.read_conn().unwrap();
            let modules = conn.prepare("SELECT topologies.crate_name, topologies.target_kind, modules.container_path, sources.rel_path, modules.placement FROM rust_crate_topologies AS topologies JOIN rust_crate_containers AS modules USING(topology_id) JOIN rust_crate_container_sources AS sources USING(topology_id, container_path) ORDER BY 1, 2, 3")
                .unwrap().query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?))).unwrap().collect::<std::result::Result<Vec<_>, _>>().unwrap();
            assert!(
                modules.contains(&(
                    "dep".into(),
                    "lib".into(),
                    "crate::on".into(),
                    "dep/src/on.rs".into(),
                    "mod_declaration".into()
                )),
                "{modules:?}"
            );
            assert!(
                !modules
                    .iter()
                    .any(|row| row.0 == "dep" && row.2 == "crate::off"),
                "{modules:?}"
            );
            assert_eq!(
                modules
                    .iter()
                    .filter(|row| row.3 == "app/src/shared.rs")
                    .count(),
                2,
                "{modules:?}"
            );
            assert!(
                modules
                    .iter()
                    .any(|row| row.2 == "crate::m" && row.4 == "inline"),
                "{modules:?}"
            );
            assert!(
                modules
                    .iter()
                    .any(|row| row.2 == "crate::tests" && row.4 == "inline"),
                "{modules:?}"
            );
            assert!(
                modules
                    .iter()
                    .any(|row| row.3 == "detached.rs" && row.1 == "detached"),
                "{modules:?}"
            );
            conn.query_row("SELECT count(*) FROM rust_crate_topologies", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap()
        };
        let file = fixture.file("app/src/a.rs");
        file.write("use super::*; pub fn b() { let body = 2; } pub fn original() {}")
            .unwrap();
        let updated = analyzer.update(&BTreeSet::from([file]));
        let conn = updated.store().unwrap().read_conn().unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM rust_crate_topologies", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            before + 1
        );
        let versions: (i64, i64, i64) = conn
            .query_row(
                "SELECT count(*), sum(valid_until IS NOT NULL),
                    sum(valid_until IS NULL AND valid_from =
                        (SELECT max(revision) FROM workspace_heads WHERE lang = 'rust'))
             FROM rust_crate_versions",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            versions,
            (before + 1, 1, 1),
            "a body edit closes one version and opens exactly one replacement"
        );
    }
    fn assert_fixture_rows(conn: &Connection) {
        fn strings(conn: &Connection, sql: &str) -> Vec<String> {
            conn.prepare(sql)
                .unwrap()
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        }
        let exports = strings(
            conn,
            "SELECT t.crate_name || ' ' || t.target_kind || ' ' || e.module_path || ' ' || e.namespace || ' ' || e.name || ' ' || e.origin || ' ' || e.visibility FROM rust_crate_exports e JOIN rust_crate_topologies t USING(topology_id) ORDER BY t.crate_name,t.target_kind,e.module_path,e.namespace,e.name",
        );
        assert_eq!(
            exports,
            [
                "app bin crate type shared declaration private",
                "app bin crate value main declaration private",
                "app bin crate::shared value shared declaration public",
                "app lib crate type X reexport public",
                "app lib crate type a declaration public",
                "app lib crate type m declaration public",
                "app lib crate type shared declaration private",
                "app lib crate type tests declaration private",
                "app lib crate value X reexport public",
                "app lib crate value b reexport public",
                "app lib crate value first reexport public",
                "app lib crate value original glob_reexport public",
                "app lib crate value second reexport public",
                "app lib crate value third reexport public",
                "app lib crate::a value b declaration public",
                "app lib crate::a value original declaration public",
                "app lib crate::m value inside declaration public",
                "app lib crate::shared value shared declaration public",
                "app lib crate::tests value test_only declaration public",
                "dep lib crate type X declaration public",
                "dep lib crate type on declaration public",
                "dep lib crate value X declaration public",
                "dep lib crate::on value enabled declaration public",
                "dep/src/off.rs detached crate value disabled declaration public",
                "detached.rs detached crate value detached declaration public",
                "helper lib crate type H declaration public",
                "helper lib crate value H declaration public",
                "x test crate value x declaration private"
            ]
        );
        assert_eq!(conn.query_row("SELECT count(*) FROM rust_crate_exports e WHERE NOT EXISTS (SELECT 1 FROM source_native_declaration_bridges b JOIN resolution_semantic_sites s ON s.blob_id=b.blob_id AND s.source_site=b.source_site WHERE b.blob_id=e.declaration_blob_id AND b.source_site=e.declaration_site AND s.semantic_role='definition')", [], |row| row.get::<_, i64>(0)).unwrap(), 0);
        let modules = strings(
            conn,
            "SELECT t.crate_name || '/' || t.target_kind || ' ' || m.container_path || ' ' || s.rel_path || ' ' || m.placement || ' ' || s.scope_ordinal FROM rust_crate_topologies t JOIN rust_crate_containers m USING(topology_id) JOIN rust_crate_container_sources s USING(topology_id, container_path) ORDER BY 1",
        );
        let mut expected = vec![
            "app/bin crate app/src/main.rs root 0",
            "app/bin crate::shared app/src/shared.rs path_attribute 0",
            "app/lib crate app/src/lib.rs root 0",
            "app/lib crate::a app/src/a.rs mod_declaration 0",
            "app/lib crate::m app/src/lib.rs inline 1",
            "app/lib crate::shared app/src/shared.rs path_attribute 0",
            "app/lib crate::tests app/src/lib.rs inline 2",
            "dep/lib crate dep/src/lib.rs root 0",
            "dep/lib crate::on dep/src/on.rs mod_declaration 0",
            "dep/src/off.rs/detached crate dep/src/off.rs root 0",
            "detached.rs/detached crate detached.rs root 0",
            "helper/lib crate helper/src/lib.rs root 0",
            "x/test crate app/tests/x.rs root 0",
        ];
        expected.sort_unstable();
        assert_eq!(modules, expected);
        assert_eq!(
            strings(
                conn,
                "SELECT t.crate_name || '/' || t.target_kind || ' ' || d.extern_name || ' ' || d.boundary || ' ' || d.dependency_kind || ' ' || target.crate_name FROM rust_crate_dependencies d JOIN rust_crate_topologies t USING(topology_id) JOIN rust_crate_topologies target ON target.crate_key=d.dependency_crate_key ORDER BY 1"
            ),
            [
                "app/bin app workspace normal app",
                "app/bin dep workspace normal dep",
                "app/bin helper workspace dev helper",
                "app/lib dep workspace normal dep",
                "app/lib helper workspace dev helper",
                "x/test app workspace normal app",
                "x/test dep workspace normal dep",
                "x/test helper workspace dev helper"
            ]
        );
        assert_eq!(
            strings(
                conn,
                "SELECT t.crate_name || '/' || t.target_kind || ' ' || i.module_path || ' ' || i.namespace || ' ' || i.bound_name || ' ' || i.import_ordinal || ' ' || i.binder_scope || ' ' || target.crate_name || ' ' || i.target_module_path || ' ' || i.target_name FROM rust_crate_imports i JOIN rust_crate_topologies t USING(topology_id) JOIN rust_crate_topologies target ON target.crate_key=i.target_crate_key ORDER BY 1"
            ),
            [
                "app/lib crate type X 5 0 dep crate X",
                "app/lib crate value X 5 0 dep crate X",
                "app/lib crate value b 1 0 app crate::a original",
                "app/lib crate value c 6 0 app crate::a b",
                "app/lib crate value first 2 0 app crate::a b",
                "app/lib crate value second 3 0 app crate first",
                "app/lib crate value third 4 0 app crate second",
                "x/test crate type H 0 0 helper crate H",
                "x/test crate value H 0 0 helper crate H"
            ]
        );
        assert_eq!(
            strings(
                conn,
                "SELECT t.crate_name || '/' || t.target_kind || ' ' || i.module_path || ' ' || i.import_ordinal || ' ' || i.binder_scope || ' ' || i.target_module_path FROM rust_crate_glob_imports i JOIN rust_crate_topologies t USING(topology_id) ORDER BY 1"
            ),
            ["app/lib crate 0 0 crate::a", "app/lib crate::a 0 0 crate"]
        );
        assert_eq!(
            strings(
                conn,
                "SELECT t.crate_name || '/' || t.target_kind || ' ' || r.module_path || ' ' || r.bound_name || ' ' || target.crate_name || ' ' || r.target_module_path || ' ' || r.target_name || ' ' || r.visibility FROM rust_crate_reexport_routes r JOIN rust_crate_topologies t USING(topology_id) JOIN rust_crate_topologies target ON target.crate_key=r.target_crate_key ORDER BY 1"
            ),
            [
                "app/lib crate X dep crate X public",
                "app/lib crate b app crate::a original public",
                "app/lib crate first app crate::a b public",
                "app/lib crate second app crate first public",
                "app/lib crate third app crate second public"
            ]
        );
        assert_eq!(
            strings(
                conn,
                "SELECT t.crate_name || ' ' || g.gap_kind || ' ' || g.subject FROM rust_crate_gaps g JOIN rust_crate_topologies t USING(topology_id) ORDER BY 1"
            ),
            ["dep inactive_placement crate::off"]
        );
        assert_eq!(
            strings(
                conn,
                "SELECT t.crate_name || '/' || t.target_kind || ' ' || coalesce(m.rel_path,'detached') FROM rust_crate_versions v JOIN rust_crate_topologies t USING(topology_id) LEFT JOIN workspace_file_versions m ON m.file_version_id=v.manifest_file_version_id WHERE v.valid_until IS NULL ORDER BY 1"
            ),
            [
                "app/bin app/Cargo.toml",
                "app/lib app/Cargo.toml",
                "dep/lib dep/Cargo.toml",
                "dep/src/off.rs/detached detached",
                "detached.rs/detached detached",
                "helper/lib helper/Cargo.toml",
                "x/test app/Cargo.toml"
            ]
        );
        let topologies = conn.prepare("SELECT crate_name, json(cfg_atoms), edition, inventory_complete, publication_state, length(topology_digest), length(export_surface_digest) FROM rust_crate_topologies").unwrap().query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, bool>(3)?, row.get::<_, String>(4)?, row.get::<_, i64>(5)?, row.get::<_, i64>(6)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert_eq!(topologies.len(), 7);
        for (name, cfg, edition, complete, state, topology_bytes, surface_bytes) in topologies {
            let mut expected_cfg = brokk_bifrost_rust::cfg::default_cfg_atoms();
            if name == "dep" {
                expected_cfg.insert("feature = \"on\"".into());
            }
            assert_eq!(
                serde_json::from_str::<BTreeSet<String>>(&cfg).unwrap(),
                expected_cfg
            );
            assert_eq!(
                (
                    edition.as_str(),
                    complete,
                    state.as_str(),
                    topology_bytes,
                    surface_bytes
                ),
                ("2021", true, "complete", 32, 32)
            );
        }
        assert_eq!(
            conn.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            0
        );
    }

    #[test]
    fn crate_rows_derive_exports_imports_and_public_invalidation() {
        let fixture = fixture();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let before = {
            let conn = store.read_conn().unwrap();
            let rows = conn.prepare("SELECT t.crate_name, t.target_kind, e.module_path, e.namespace, e.name, e.origin, e.visibility FROM rust_crate_exports e JOIN rust_crate_topologies t USING(topology_id) ORDER BY 1,2,3,4,5")
                .unwrap().query_map([], |row| (0..7).map(|n| row.get::<_, String>(n)).collect::<rusqlite::Result<Vec<_>>>()).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            eprintln!("EXPORT ROWS {rows:?}");
            for table in [
                "rust_crate_topologies",
                "rust_crate_versions",
                "rust_crate_containers",
                "rust_crate_container_sources",
                "rust_crate_dependencies",
                "rust_crate_exports",
                "rust_crate_reexport_routes",
                "rust_crate_glob_reexport_routes",
                "rust_crate_imports",
                "rust_crate_glob_imports",
                "rust_crate_gaps",
            ] {
                let count: i64 = conn
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })
                    .unwrap();
                eprintln!("{table}: {count}");
            }
            let gaps = conn.prepare("SELECT t.crate_name, g.gap_kind, g.subject, json(g.detail) FROM rust_crate_gaps g JOIN rust_crate_topologies t USING(topology_id) ORDER BY 1,2,3").unwrap().query_map([], |row| (0..4).map(|n| row.get::<_, String>(n)).collect::<rusqlite::Result<Vec<_>>>()).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            eprintln!("GAPS {gaps:?}");
            assert_fixture_rows(&conn);
            for namespace in ["type", "value"] {
                assert!(
                    rows.iter()
                        .any(|row| row[0] == "dep" && row[3] == namespace && row[4] == "X"),
                    "{rows:?}"
                );
            }
            for name in ["first", "second", "third"] {
                assert!(
                    rows.iter().any(|row| row[0] == "app"
                        && row[1] == "lib"
                        && row[2] == "crate"
                        && row[4] == name
                        && row[5] == "reexport"),
                    "{rows:?}"
                );
            }
            let b: (String, i64) = conn.query_row("SELECT e.origin, e.declaration_site FROM rust_crate_exports e JOIN rust_crate_topologies t USING(topology_id) WHERE t.crate_name='app' AND t.target_kind='lib' AND e.module_path='crate' AND e.name='b'", [], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
            let original: i64 = conn.query_row("SELECT e.declaration_site FROM rust_crate_exports e JOIN rust_crate_topologies t USING(topology_id) WHERE t.crate_name='app' AND t.target_kind='lib' AND e.module_path='crate::a' AND e.name='original'", [], |row| row.get(0)).unwrap();
            assert_eq!(b, ("reexport".into(), original));
            assert_eq!(conn.query_row("SELECT count(*) FROM rust_crate_imports WHERE bound_name='c' AND target_module_path='crate::a' AND target_name='b'", [], |row| row.get::<_, i64>(0)).unwrap(), 1);
            assert_eq!(conn.query_row("SELECT count(*) FROM rust_crate_glob_imports WHERE module_path='crate::a' AND target_module_path='crate'", [], |row| row.get::<_, i64>(0)).unwrap(), 1);
            assert_eq!(conn.query_row("SELECT count(*) FROM rust_crate_reexport_routes WHERE bound_name='X' AND target_module_path='crate' AND target_name='X'", [], |row| row.get::<_, i64>(0)).unwrap(), 1);
            conn.query_row("SELECT count(*) FROM rust_crate_topologies", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap()
        };
        let file = fixture.file("dep/src/lib.rs");
        file.write("pub struct Y(pub u8); #[cfg(feature = \"on\")] pub mod on; #[cfg(feature = \"off\")] pub mod off;").unwrap();
        let updated = analyzer.update(&BTreeSet::from([file]));
        let conn = updated.store().unwrap().read_conn().unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM rust_crate_topologies", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            before + 4
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM rust_crate_versions WHERE valid_until IS NOT NULL",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            4
        );
        let incremental = current_crate_digests(&conn);
        drop(conn);
        let cold = fixture.workspace_analyzer(AnalyzerConfig::default());
        assert_eq!(
            incremental,
            current_crate_digests(&cold.store().unwrap().read_conn().unwrap())
        );
    }

    #[test]
    fn crate_reconcile_statement_cost_scales_with_crates_and_modules() {
        fn measure(crates: usize) -> usize {
            let mut fixture = InlineTestProject::new();
            let members = (0..crates)
                .map(|index| format!("\"p{index}\""))
                .collect::<Vec<_>>()
                .join(",");
            fixture = fixture.file("Cargo.toml", format!("[workspace]\nmembers=[{members}]\n"));
            for index in 0..crates {
                fixture = fixture.file(
                    format!("p{index}/Cargo.toml"),
                    format!("[package]\nname=\"p{index}\"\nversion=\"0.1.0\"\nedition=\"2021\"\n"),
                );
                let root = (0..8)
                    .map(|module| format!("pub mod m{module};\n"))
                    .collect::<String>();
                fixture = fixture.file(format!("p{index}/src/lib.rs"), root);
                for module in 0..8 {
                    fixture = fixture.file(
                        format!("p{index}/src/m{module}.rs"),
                        format!("pub fn f{index}_{module}() {{}}"),
                    );
                }
            }
            let fixture = fixture.build();
            let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
            let store = analyzer.store().unwrap();
            let snapshot = store.conn.execute(|conn| -> Result<_> {
                let snapshot = conn.query_row("SELECT workspace_id, generation, revision FROM workspace_heads WHERE lang='rust'", [], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?)))?;
                conn.execute("DELETE FROM rust_crate_versions", [])?;
                conn.execute(DELETE_UNBOUND_TOPOLOGIES_SQL, [])?;
                Ok(snapshot)
            }).unwrap();
            let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            *store.crate_statement_counter.lock().unwrap() = Some(counter.clone());
            let snapshot = WorkspaceSnapshotId {
                workspace_id: super::super::WorkspaceId(snapshot.0),
                lang: "rust".into(),
                generation: super::super::GenerationId::from_persisted(snapshot.1),
                revision: snapshot.2,
            };
            store.reconcile_rust_crates(&snapshot).unwrap();
            *store.crate_statement_counter.lock().unwrap() = None;
            assert_eq!(
                std::sync::Arc::strong_count(&counter),
                1,
                "reader/writer trace did not release request state"
            );
            counter.load(std::sync::atomic::Ordering::Relaxed)
        }
        let small = measure(4);
        let large = measure(8);
        eprintln!("reconcile statements: 4 crates/36 modules={small}, 8 crates/72 modules={large}");
        assert!(
            small > 100,
            "trace must include actual derivation statements: {small}"
        );
        assert!(
            large > small && large < small * 3,
            "expected linear growth, measured {small} -> {large}"
        );
    }

    #[test]
    fn crate_declaration_derivation_work_scales_with_blob_rows_not_container_product() {
        fn measure(module_count: usize) -> (usize, i64) {
            let mut source = String::new();
            for module in 0..module_count {
                source.push_str(&format!("pub mod m{module} {{\n"));
                for declaration in 0..32 {
                    source.push_str(&format!("pub fn f{module}_{declaration}() {{}}\n"));
                }
                source.push_str("}\n");
            }
            let fixture = InlineTestProject::new()
                .file(
                    "Cargo.toml",
                    "[package]\nname=\"scale\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
                )
                .file("src/lib.rs", source)
                .build();
            let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
            let store = analyzer.store().unwrap();
            let conn = store.read_conn().unwrap();
            derivation::prepare_tables(&conn).unwrap();
            let (topology_id, cfg): (i64, String) = conn
                .query_row(
                    "SELECT topology_id, json(cfg_atoms) FROM rust_crate_topologies WHERE crate_name='scale' AND publication_state='complete' ORDER BY topology_id DESC LIMIT 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            let members = conn
                .prepare("SELECT sources.container_path, sources.blob_id, sources.scope_ordinal, sources.rel_path, containers.placement, sources.parent_container_path FROM rust_crate_container_sources AS sources JOIN rust_crate_containers AS containers USING(topology_id, container_path) WHERE sources.topology_id=?1 AND containers.kind='module'")
                .unwrap()
                .query_map([topology_id], |row| {
                    Ok(Member {
                        module_path: row.get(0)?,
                        blob_id: row.get(1)?,
                        scope: row.get(2)?,
                        rel_path: row.get(3)?,
                        placement: row.get(4)?,
                        parent_path: row.get(5)?,
                    })
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            for member in members {
                conn.execute(
                    derivation::SQL_CR_MEMBERS_1,
                    params![
                        member.module_path,
                        member.blob_id,
                        member.scope,
                        member.rel_path,
                        member.placement
                    ],
                )
                .unwrap();
            }
            conn.execute(derivation::SQL_CR_MEMBERS_2, []).unwrap();
            conn.execute(derivation::POPULATE_MEMBER_BLOBS_SQL, [])
                .unwrap();
            conn.execute(derivation::POPULATE_SCOPES_SQL, []).unwrap();
            let steps = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let observed = steps.clone();
            conn.progress_handler(
                1,
                Some(move || {
                    observed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    false
                }),
            )
            .unwrap();
            conn.execute(derivation::SOURCE_DECLARATIONS_SQL, [cfg])
                .unwrap();
            conn.progress_handler(0, None::<fn() -> bool>).unwrap();
            let rows = conn
                .query_row("SELECT count(*) FROM cr_source_declarations", [], |row| {
                    row.get(0)
                })
                .unwrap();
            (steps.load(std::sync::atomic::Ordering::Relaxed), rows)
        }

        let small = measure(8);
        let large = measure(16);
        eprintln!("declaration candidate work: 8 modules={small:?}, 16 modules={large:?}");
        assert_eq!(large.1, small.1 * 2, "{small:?} -> {large:?}");
        assert!(
            large.0 * (small.1 as usize) < small.0 * (large.1 as usize) * 6 / 5,
            "VM work per declaration candidate must stay within 20 percent: {small:?} -> {large:?}"
        );
    }

    #[test]
    fn crate_derivation_statements_have_indexed_plans_in_both_statistics_states() {
        use super::super::planner_statistics::pinned_plans::{explain_pin, pinned_queries};
        use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
        let fixture = fixture();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.conn.lock().unwrap();
        super::super::ensure_revisioned_workspace_views(&conn).unwrap();
        conn.execute("DELETE FROM selected_workspace_revisions", [])
            .unwrap();
        conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id, lang, generation, revision FROM workspace_heads WHERE lang='rust'", []).unwrap();
        prepare_pin_context(&conn).unwrap();
        let (id, key, cfg): (i64, Vec<u8>, String) = conn.query_row("SELECT topology_id, crate_key, json(cfg_atoms) FROM rust_crate_topologies WHERE crate_name='app' AND target_kind='lib'", [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).unwrap();
        let members = conn.prepare("SELECT container_path, blob_id, scope_ordinal, rel_path, placement, parent_container_path FROM rust_crate_containers JOIN rust_crate_container_sources USING(topology_id, container_path) WHERE topology_id=?1").unwrap().query_map([id], |row| Ok(Member { module_path:row.get(0)?, blob_id:row.get(1)?, scope:row.get(2)?, rel_path:row.get(3)?, placement:row.get(4)?, parent_path:row.get(5)? })).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        for member in members {
            conn.execute(
                derivation::SQL_CR_MEMBERS_1,
                params![
                    member.module_path,
                    member.blob_id,
                    member.scope,
                    member.rel_path,
                    member.placement
                ],
            )
            .unwrap();
        }
        conn.execute(derivation::SQL_CR_MEMBERS_2, []).unwrap();
        conn.execute(derivation::POPULATE_MEMBER_BLOBS_SQL, [])
            .unwrap();
        conn.execute(derivation::POPULATE_SCOPES_SQL, []).unwrap();
        conn.execute(derivation::INSERT_IDENTITY_SQL, [&key])
            .unwrap();
        conn.execute(
            "INSERT INTO cr_foreign SELECT crate_key, topology_id, crate_name FROM rust_crate_topologies WHERE topology_id <> ?1",
            [id],
        )
        .unwrap();
        conn.execute(derivation::FOREIGN_REEXPORT_STEPS_SQL, [])
            .unwrap();
        conn.execute(derivation::SOURCE_DECLARATIONS_SQL, [&cfg])
            .unwrap();
        conn.execute(derivation::RESTRICTION_INPUTS_SQL, [])
            .unwrap();
        conn.execute(derivation::RESTRICTIONS_SQL, []).unwrap();
        conn.execute(derivation::DECLARATIONS_SQL, []).unwrap();
        conn.execute(derivation::SQL_CR_EXPORTS_4, []).unwrap();
        conn.execute(derivation::ENUM_CONTAINERS_SQL, []).unwrap();
        conn.execute(derivation::ENUM_VARIANTS_SQL, []).unwrap();
        conn.execute("INSERT INTO cr_dependencies SELECT d.extern_name, d.dependency_crate_key, t.topology_id FROM rust_crate_dependencies d LEFT JOIN rust_crate_topologies t ON t.crate_key=d.dependency_crate_key WHERE d.topology_id=?1", [id]).unwrap();
        conn.execute(derivation::CONTAINERS_SQL, []).unwrap();
        conn.execute(derivation::CLOSE_REEXPORT_STEPS_SQL, [])
            .unwrap();
        conn.execute(derivation::FOREIGN_GLOB_STEPS_SQL, [])
            .unwrap();
        conn.execute(derivation::CLOSE_GLOB_STEPS_SQL, []).unwrap();
        conn.execute(derivation::SQL_CR_SOURCE_IMPORTS_5, [&cfg])
            .unwrap();
        conn.execute(derivation::ROUTES_SQL.as_str(), params![key, "2021"])
            .unwrap();
        conn.execute(derivation::LOCAL_REEXPORT_STEPS_SQL, [])
            .unwrap();
        conn.execute(derivation::CLEAR_REEXPORT_CLOSURE_SQL, [])
            .unwrap();
        conn.execute(derivation::CLOSE_REEXPORT_STEPS_SQL, [])
            .unwrap();
        conn.execute(derivation::LOCAL_GLOB_STEPS_SQL, []).unwrap();
        conn.execute(derivation::CLEAR_GLOB_CLOSURE_SQL, [])
            .unwrap();
        conn.execute(derivation::CLOSE_GLOB_STEPS_SQL, []).unwrap();
        conn.execute(derivation::DEPENDENCY_EXPORTS_SQL, [&key])
            .unwrap();
        let (workspace, generation, revision): (String, i64, i64) = conn
            .query_row(
                "SELECT workspace_id,generation,revision FROM workspace_heads WHERE lang='rust'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let (digest, surface, epoch): (Vec<u8>,Vec<u8>,String) = conn.query_row("SELECT topology_digest,export_surface_digest,producer_epoch FROM rust_crate_topologies WHERE topology_id=?1", [id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap();
        let root_blob: i64 = conn.query_row("SELECT blob_id FROM rust_crate_containers JOIN rust_crate_container_sources USING(topology_id, container_path) WHERE topology_id=?1 AND container_path='crate'", [id], |row| row.get(0)).unwrap();
        let root_oid: String = conn
            .query_row(SQL_BLOBS_8, [root_blob], |row| row.get(0))
            .unwrap();
        let manifest: i64 = conn
            .query_row(
                "SELECT manifest_file_version_id FROM rust_crate_versions WHERE topology_id=?1",
                [id],
                |row| row.get(0),
            )
            .unwrap();
        let (dependency, dependency_id): (Vec<u8>, i64) = conn
            .query_row(
                "SELECT crate_key,topology_id FROM rust_crate_topologies WHERE crate_name='dep'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let helper: Vec<u8> = conn
            .query_row(
                "SELECT crate_key FROM rust_crate_topologies WHERE crate_name='helper'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            for mut pin in pinned_queries()
                .into_iter()
                .filter(|pin| pin.name.starts_with("rust_crate_"))
            {
                use rusqlite::types::Value::{Blob, Integer, Null, Text};
                let text = |s: &str| Text(s.to_owned());
                if !pin.params.is_empty() {
                    pin.params = match pin.name.as_str() {
                        "rust_crate_replaced_blob_id" => {
                            vec![text(&root_oid), text("rust"), Integer(generation)]
                        }
                        "rust_crate_reinsert_blob" => vec![
                            Integer(root_blob),
                            text(&root_oid),
                            text("rust"),
                            Integer(generation),
                        ],
                        "rust_crate_module_walk" => {
                            vec![text("app/src/lib.rs"), text(&cfg), text("[]")]
                        }
                        "rust_crate_item_macro_decisions" => vec![text("[]"), text("[]")],
                        "rust_crate_source_declarations"
                        | "rust_crate_macro_items"
                        | "rust_crate_derivation_sql_cr_source_imports_5"
                        | "rust_crate_extern_crate_alias_dependencies" => vec![text(&cfg)],
                        "rust_crate_import_routes" => vec![Blob(key.clone()), text("2021")],
                        "rust_crate_export_fixpoint"
                        | "rust_crate_derivation_sql_cr_reexports_6"
                        | "rust_crate_dependency_exports"
                        | "rust_crate_insert_identity" => vec![Blob(key.clone())],
                        "rust_crate_insert_foreign" => {
                            vec![Blob(dependency.clone()), Integer(dependency_id)]
                        }
                        "rust_crate_reconcile_sql_workspace_file_versions_2" => {
                            vec![text(&workspace), Integer(generation), Integer(revision)]
                        }
                        "rust_crate_reconcile_sql_rust_crate_containers_5" => vec![Integer(id)],
                        "rust_crate_reconcile_sql_rust_crate_versions_6" => {
                            vec![text(&workspace), Integer(generation)]
                        }
                        "rust_crate_reconcile_sql_rust_crate_versions_16"
                        | "rust_crate_reconcile_sql_rust_crate_versions_withdraw" => vec![
                            Integer(revision),
                            text(&workspace),
                            Integer(generation),
                            Blob(key.clone()),
                        ],
                        "rust_crate_reconcile_sql_blobs_8" => vec![Integer(root_blob)],
                        "rust_crate_reconcile_sql_rust_crate_topologies_9" => {
                            vec![Blob(digest.clone())]
                        }
                        "rust_crate_reconcile_sql_rust_crate_topologies_10" => vec![
                            Blob(digest.clone()),
                            Blob(key.clone()),
                            text(&epoch),
                            text("lib"),
                            text("app"),
                            text("2021"),
                            text(&cfg),
                            Integer(1),
                            text("std"),
                        ],
                        "rust_crate_reconcile_sql_root_inner_attributes" => {
                            vec![Integer(root_blob)]
                        }
                        "rust_crate_insert_naming" => {
                            vec![Integer(id), text("app/src/lib.rs"), text("[]"), text("[]")]
                        }
                        "rust_crate_insert_enum_container" => vec![
                            Integer(id),
                            text("crate::Shape"),
                            text("enum"),
                            text("enum_declaration"),
                        ],
                        "rust_crate_insert_enum_source" => vec![
                            Integer(id),
                            text("crate::Shape"),
                            Integer(root_blob),
                            Null,
                            text("app/src/lib.rs"),
                            text("declared"),
                            Integer(0),
                            text("crate"),
                        ],
                        "rust_crate_insert_module" => {
                            vec![Integer(id), text("crate"), text("root")]
                        }
                        "rust_crate_reconcile_sql_rust_crate_containers_11" => vec![
                            Integer(id),
                            text("crate"),
                            Integer(root_blob),
                            Integer(0),
                            text("app/src/lib.rs"),
                            text("root"),
                            Null,
                        ],
                        "rust_crate_reconcile_sql_rust_crate_dependencies_12" => vec![
                            Integer(id),
                            text("dep"),
                            text("workspace"),
                            Blob(dependency.clone()),
                            text("normal"),
                        ],
                        "rust_crate_reconcile_sql_rust_crate_gaps_13"
                        | "rust_crate_derivation_sql_rust_crate_gaps_21" => vec![
                            Integer(dependency_id),
                            text("inactive_placement"),
                            text("crate::off"),
                            text("{\"activation\":0,\"path\":\"dep/src/off.rs\"}"),
                        ],
                        "rust_crate_reconcile_sql_rust_crate_topologies_14" => {
                            vec![Blob(surface.clone()), Integer(id)]
                        }
                        "rust_crate_reconcile_sql_rust_crate_versions_15" => {
                            vec![text(&workspace), Integer(generation), Blob(key.clone())]
                        }
                        "rust_crate_reconcile_sql_rust_crate_versions_17" => vec![
                            text(&workspace),
                            Integer(generation),
                            Blob(key.clone()),
                            Integer(revision),
                            Integer(manifest),
                            Integer(id),
                        ],
                        "rust_crate_derivation_sql_cr_members_1" => vec![
                            text("crate"),
                            Integer(root_blob),
                            Integer(0),
                            text("app/src/lib.rs"),
                            text("root"),
                        ],
                        "rust_crate_derivation_sql_cr_dependencies_3" => vec![
                            text("dep"),
                            Blob(dependency.clone()),
                            Integer(dependency_id),
                        ],
                        "rust_crate_derivation_sql_rust_crate_exports_17" => vec![
                            Integer(id),
                            text("crate"),
                            text("type"),
                            text("a"),
                            text("declaration"),
                            text("public"),
                            Null,
                            Integer(root_blob),
                            Integer(0),
                        ],
                        "rust_crate_derivation_sql_rust_crate_reexport_routes_18" => vec![
                            Integer(id),
                            text("crate"),
                            text("X"),
                            Blob(dependency.clone()),
                            text("crate"),
                            text("X"),
                            text("public"),
                            Null,
                        ],
                        "rust_crate_derivation_sql_rust_crate_imports_19" => vec![
                            Integer(id),
                            text("crate"),
                            text("value"),
                            text("c"),
                            Integer(root_blob),
                            Integer(6),
                            Integer(0),
                            Blob(key.clone()),
                            text("crate::a"),
                            text("b"),
                        ],
                        "rust_crate_derivation_sql_rust_crate_glob_imports_20" => vec![
                            Integer(id),
                            text("crate::a"),
                            Integer(root_blob),
                            Integer(0),
                            Integer(0),
                            Blob(key.clone()),
                            text("crate"),
                        ],
                        "rust_crate_root_routes" => vec![Blob(key.clone()), text("2021")],
                        // The `UnexpandedImplMacro` gap origin code the
                        // statement excludes undecided frontiers by.
                        "rust_crate_open_export_inventory" => vec![Integer(
                            crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code(
                                crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                                    brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnexpandedImplMacro,
                                ),
                            ),
                        )],
                        "rust_crate_trait_impl_subject_routes"
                        | "rust_crate_trait_impl_trait_routes" => {
                            vec![Blob(key.clone()), text("2018")]
                        }
                        "rust_crate_trait_impls_insert" => vec![
                            Integer(id),
                            Integer(root_blob),
                            Integer(0),
                            text("src/lib.rs"),
                            Integer(root_blob),
                            Integer(1),
                            text("src/lib.rs"),
                            Integer(root_blob),
                            Integer(2),
                            text("src/lib.rs"),
                            Integer(0),
                        ],
                        "rust_crate_decided_item_macros_insert" => {
                            vec![Integer(id), Integer(root_blob), Integer(0), text("always")]
                        }
                        "rust_crate_unresolved_trait_impls_insert" => vec![
                            Integer(id),
                            text("trait"),
                            text("Unbound"),
                            Integer(root_blob),
                            Integer(3),
                            text("src/lib.rs"),
                            Null,
                            text("unbound"),
                            text("crate::elsewhere"),
                        ],
                        "rust_crate_root_references_insert" => vec![
                            Integer(id),
                            text("crate"),
                            Integer(root_blob),
                            Integer(0),
                            Integer(0),
                            Blob(key.clone()),
                            text("crate"),
                            text("target"),
                        ],
                        "rust_crate_glob_reexport_derive" => vec![Blob(key.clone())],
                        "rust_crate_glob_reexport_insert" => vec![
                            Integer(id),
                            text("crate"),
                            Blob(dependency.clone()),
                            text("crate"),
                            text("public"),
                            Null,
                        ],
                        "rust_crate_glob_reexport_routes_target" => {
                            vec![Blob(dependency.clone()), text("crate")]
                        }
                        "rust_crate_imports_binder" => vec![
                            Integer(id),
                            text("crate"),
                            Integer(root_blob),
                            Integer(0),
                            text("c"),
                        ],
                        "rust_crate_imports_target" => {
                            vec![Blob(helper.clone()), text("crate"), text("H")]
                        }
                        "rust_crate_exports_declaration" => vec![Integer(root_blob), Integer(0)],
                        "rust_crate_reexport_routes_target" => {
                            vec![Blob(dependency.clone()), text("crate"), text("X")]
                        }
                        "rust_crate_exports_reachable" => {
                            vec![Integer(id), text("crate"), text("X")]
                        }
                        other => panic!("add populated production-shaped bindings for {other}"),
                    };
                }
                let plan = explain_pin(&conn, &pin);
                if pin.name == "rust_crate_source_declarations" {
                    for index in [
                        "SEARCH declaration USING PRIMARY KEY",
                        "SEARCH member USING COVERING INDEX cr_members_blob",
                        "SEARCH inner_module USING COVERING INDEX cr_scopes_range",
                    ] {
                        assert!(
                            plan.iter().any(|row| row.contains(index)),
                            "{state:?} {} must use {index}: {plan:?}",
                            pin.name
                        );
                    }
                    for forbidden in ["SCAN declaration", "AUTOMATIC", "CO-ROUTINE", "TEMP B-TREE"]
                    {
                        assert!(
                            !plan.iter().any(|row| row.contains(forbidden)),
                            "{state:?} {} must not use {forbidden}: {plan:?}",
                            pin.name
                        );
                    }
                }
                if pin.name == "rust_crate_derivation_sql_cr_imports_8" {
                    assert!(
                        plan.iter().any(|row| {
                            row.contains("SEARCH exports")
                                && row.contains(
                                    "crate_key=? AND module_path=? AND namespace=? AND name=?",
                                )
                        }),
                        "{state:?} {} must seek the complete export key in the route's crate: {plan:?}",
                        pin.name
                    );
                    assert!(
                        !plan.iter().any(|row| row.contains("SCAN exports")),
                        "{state:?} {} must not scan dependency exports: {plan:?}",
                        pin.name
                    );
                }
                // Ending an open version row runs once per crate a reconcile
                // re-derives, which is every crate in a derivation-version
                // rotation, so it seeks that crate's rows by key.
                if matches!(
                    pin.name.as_str(),
                    "rust_crate_reconcile_sql_rust_crate_versions_16"
                        | "rust_crate_reconcile_sql_rust_crate_versions_withdraw"
                ) {
                    assert!(
                        plan.iter().any(|row| {
                            row.contains("SEARCH rust_crate_versions USING PRIMARY KEY")
                        }),
                        "{state:?} {} must seek the crate's version rows by key: {plan:?}",
                        pin.name
                    );
                }
                if pin.name == "rust_crate_replaced_blob_id" {
                    for index in [
                        "rust_crate_containers_blob",
                        "rust_crate_exports_declaration",
                    ] {
                        assert!(
                            plan.iter().any(|row| row.contains(index)),
                            "{state:?}: {plan:?}"
                        );
                    }
                    assert!(
                        !plan.iter().any(|row| row.contains("AUTOMATIC")),
                        "{state:?}: {plan:?}"
                    );
                }
                // A root reference's module anchor is a key seek. Scanning the
                // anchors per reference cost 61 s of a 78 s derivation of the
                // analysis crate (#3749).
                if pin.name == "rust_crate_root_references_select" {
                    assert!(
                        plan.iter()
                            .any(|row| row.contains("SEARCH anchor USING PRIMARY KEY")),
                        "{state:?} {}: {plan:?}",
                        pin.name
                    );
                    assert!(
                        !plan
                            .iter()
                            .any(|row| row.contains("SCAN anchor") || row.contains("AUTOMATIC")),
                        "{state:?} {}: {plan:?}",
                        pin.name
                    );
                }
                // Every working statement of the trait-implementation
                // derivation seeks: the tier-1 family by its primary key, the
                // module route by its key, the export the half binds by the
                // complete export key, and the binding the gap statement tests
                // for by its key. The insert and the row select are the only
                // two that are not joins, as they are for every other family.
                if let Some(index) = match pin.name.as_str() {
                    "rust_crate_trait_impl_sources" | "rust_crate_trait_impl_rows" => {
                        Some("SEARCH subject USING PRIMARY KEY")
                    }
                    "rust_crate_trait_impl_subject_routes"
                    | "rust_crate_trait_impl_trait_routes" => {
                        Some("SEARCH resolution_trait_implementations USING PRIMARY KEY")
                    }
                    "rust_crate_trait_impl_subject_bindings"
                    | "rust_crate_trait_impl_trait_bindings"
                    | "rust_crate_trait_impl_subject_glob_bindings"
                    | "rust_crate_trait_impl_trait_glob_bindings" => {
                        Some("SEARCH exports USING PRIMARY KEY")
                    }
                    "rust_crate_trait_impl_subject_gaps" | "rust_crate_trait_impl_trait_gaps" => {
                        Some("SEARCH declaration USING PRIMARY KEY")
                    }
                    "rust_crate_trait_impl_declarations" => {
                        Some("SEARCH exports USING PRIMARY KEY")
                    }
                    _ => None,
                } {
                    assert!(
                        plan.iter().any(|row| row.contains(index)),
                        "{state:?} {} must use {index}: {plan:?}",
                        pin.name
                    );
                    assert!(
                        !plan.iter().any(|row| row.contains("AUTOMATIC")),
                        "{state:?} {}: {plan:?}",
                        pin.name
                    );
                }
                if matches!(
                    pin.name.as_str(),
                    "rust_crate_source_declarations"
                        | "rust_crate_export_declarations"
                        | "rust_crate_enum_containers"
                        | "rust_crate_enum_variants"
                        | "rust_crate_export_fixpoint"
                        | "rust_crate_import_routes"
                        | "rust_crate_derivation_sql_cr_imports_8"
                        | "rust_crate_macro_items"
                ) {
                    eprintln!("{state:?} {}: {plan:?}", pin.name);
                    assert!(
                        !plan.iter().any(|row| row.contains("AUTOMATIC")),
                        "{state:?} {}: {plan:?}",
                        pin.name
                    );
                    let index = match pin.name.as_str() {
                        "rust_crate_source_declarations" => "SEARCH declaration USING PRIMARY KEY",
                        "rust_crate_export_declarations" => "SEARCH bridges USING",
                        "rust_crate_enum_containers" => "SEARCH bridge USING",
                        "rust_crate_enum_variants" => {
                            "SEARCH candidate USING INDEX cr_source_declarations_declaration"
                        }
                        "rust_crate_export_fixpoint" => "SEARCH target USING PRIMARY KEY",
                        "rust_crate_import_routes" => "SEARCH segment USING",
                        "rust_crate_macro_items" => "SEARCH properties USING PRIMARY KEY",
                        _ => "SEARCH exports USING PRIMARY KEY",
                    };
                    assert!(
                        plan.iter().any(|row| row.contains(index)),
                        "{state:?} {}: {plan:?}",
                        pin.name
                    );
                }
            }
        }
    }

    #[test]
    fn crate_rows_release_foreign_keys_on_workspace_retirement_and_epoch_rotation() {
        let project = fixture();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let workspace = {
            let conn = store.read_conn().unwrap();
            let id: String = conn
                .query_row(
                    "SELECT workspace_id FROM workspace_heads WHERE lang='rust'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            super::super::WorkspaceId(id)
        };
        assert!(store.delete_workspace_projection(&workspace).unwrap() > 0);
        let conn = store.read_conn().unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM rust_crate_topologies", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            0
        );
        drop(conn);
        let project = fixture();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        store
            .ensure_language_epoch_value("rust", "crate-row-lifecycle-test")
            .unwrap();
        let conn = store.read_conn().unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM rust_crate_versions", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM rust_crate_topologies", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            0
        );
    }

    #[test]
    fn crate_glob_reexports_reach_dependency_names_through_selected_rows() {
        let project = InlineTestProject::new()
            .file("Cargo.toml", "[workspace]\nmembers=[\"app\",\"dep\"]\nresolver=\"2\"\n")
            .file("app/Cargo.toml", "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\ndep={path=\"../dep\"}\n")
            .file("dep/Cargo.toml", "[package]\nname=\"dep\"\nversion=\"0.1.0\"\nedition=\"2021\"\n")
            .file("app/src/lib.rs", "pub use dep::*; pub use dep::X as Y; pub use dep::X as Z;")
            .file("dep/src/lib.rs", "pub struct X; fn private() {}")
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'", []).unwrap();
        let id: i64 = conn
            .query_row(
                "SELECT topology_id FROM rust_crate_topologies WHERE crate_name='app'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(conn.query_row("SELECT count(*) FROM rust_crate_reexport_routes WHERE topology_id=?1 AND bound_name='Y' AND target_name='X'", [id], |row| row.get::<_, i64>(0)).unwrap(), 1);
        assert_eq!(conn.query_row("SELECT count(*) FROM rust_crate_glob_reexport_routes WHERE topology_id=?1 AND module_path='crate' AND target_module_path='crate'", [id], |row| row.get::<_, i64>(0)).unwrap(), 1);
        let names = conn.prepare("SELECT namespace || ':' || name FROM rust_crate_exports_reachable WHERE topology_id=?1 ORDER BY 1").unwrap().query_map([id], |row| row.get::<_, String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert_eq!(
            names,
            [
                "type:X", "type:Y", "type:Z", "value:X", "value:Y", "value:Z"
            ]
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            0
        );
    }

    // A glob binds names the walk must follow, and a glob's own path can be
    // one of those names, so routes and globs are one fixpoint. `Target` needs
    // the glob edges a first pass discovers; `Deeper` needs the edge that
    // `use leaf::*;` only becomes once `leaf` itself has a route, so it proves
    // the loop runs again rather than closing the edges it already had.
    #[test]
    fn crate_import_routes_follow_a_chain_of_glob_imports() {
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname=\"chained\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
            )
            .file("src/lib.rs", "mod consumer;\npub mod a;\npub use a::*;\n")
            .file("src/a.rs", "pub mod b;\npub use b::*;\n")
            .file(
                "src/a/b.rs",
                "pub mod leaf { pub struct Target; pub mod deep { pub struct Deeper; } }\n",
            )
            .file(
                "src/consumer.rs",
                "use crate::*;\nuse leaf::Target;\nuse leaf::*;\nuse deep::Deeper;\n\nfn consume(_: Target, _: Deeper) {}\n",
            )
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let id: i64 = conn
            .query_row(
                "SELECT topology_id FROM rust_crate_topologies WHERE crate_name='chained'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let routed = conn
            .prepare(
                "SELECT DISTINCT bound_name || ' -> ' || target_module_path || '::' || target_name
                 FROM rust_crate_imports
                 WHERE topology_id=?1 AND module_path='crate::consumer' ORDER BY 1",
            )
            .unwrap()
            .query_map([id], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            routed,
            [
                "Deeper -> crate::a::b::leaf::deep::Deeper",
                "Target -> crate::a::b::leaf::Target",
            ]
        );
    }

    #[test]
    fn crate_restricted_visibility_resolves_module_routes_and_gaps() {
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='visibility'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file(
                "src/lib.rs",
                r#"
mod outer {
    mod inner {
        pub(self) struct Here;
        pub(super) struct Parent;
        pub(in crate::outer) struct Absolute;
        pub(in super) struct Relative;
        pub(in self) struct Same;
        pub(in super::super) struct Root;
        pub(in crate::absent) struct Missing;
        pub(in super) use self::Here as Alias;
    }
}
"#,
            )
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.conn.lock().unwrap();
        let rows = conn.prepare("SELECT name, restricted_module_path FROM rust_crate_exports WHERE namespace='type' AND module_path='crate::outer::inner' ORDER BY name").unwrap()
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
            .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert_eq!(
            rows,
            [
                ("Absolute".into(), "crate::outer".into()),
                ("Alias".into(), "crate::outer".into()),
                ("Here".into(), "crate::outer::inner".into()),
                ("Parent".into(), "crate::outer".into()),
                ("Relative".into(), "crate::outer".into()),
                ("Root".into(), "crate".into()),
                ("Same".into(), "crate::outer::inner".into()),
            ]
        );
        let gaps: i64 = conn.query_row("SELECT count(*) FROM rust_crate_gaps WHERE gap_kind='unresolved_visibility' AND subject='crate::outer::inner'", [], |row| row.get(0)).unwrap();
        assert_eq!(gaps, 1);
    }

    #[test]
    fn crate_point_rows_distinguish_open_and_closed_export_inventories() {
        let mut evidence = Vec::new();
        // The fourth and fifth cases write the second case's invocation under
        // a `macro_rules!` the root makes visible in the mounted file. A proven
        // item passthrough with no arguments decides it and declares nothing,
        // so the module's inventory closes. A visible definition the matcher
        // did not prove to be a passthrough decides nothing, and this one does
        // declare an item of its own, so the inventory stays open exactly as it
        // does for the second case, whose macro is visible nowhere. Reading
        // "not proven a passthrough" as "adds no items" closed it on no proof
        // at all.
        //
        // The later cases give a proven passthrough an item. Declared in the
        // same file with rules that expand to their arguments only, the
        // producer declares the item, it is exported, and the inventory
        // closes. Every other decided invocation's items are the crate's to
        // declare (`rust_crate_macro_items`, which the point and graph routes
        // read): a macro declared in another file, and rules that add a `cfg`
        // to each item, whose activation the crate evaluates. Their inventory
        // closes once every item is accounted for. A unit struct is declared
        // in both namespaces. A decoration the profile turns off declares
        // nothing and still closes the inventory: the item is absent. An
        // invocation in an `impl` body expands to members, not module items,
        // so it declares no row and closes too. A rule that adds an attribute
        // other than a `cfg` leaves the invocation undecided and open.
        let passthrough = "macro_rules! generate { ($($item:item)*) => { $($item)* }; }\n";
        let decorating =
            "macro_rules! generate { ($($item:item)*) => { $(#[cfg(unix)] $item)* }; }\n";
        let opaque_decoration =
            "macro_rules! generate { ($($item:item)*) => { $(#[allow(dead_code)] $item)* }; }\n";
        let local_passthrough = format!("{passthrough}generate! {{ pub struct Extra; }}\n");
        let extra_in = |module: &str| {
            let module = module.to_owned();
            ["type", "value"]
                .map(|namespace| {
                    (
                        module.clone(),
                        namespace.to_owned(),
                        "Extra".to_owned(),
                        "public".to_owned(),
                        false,
                    )
                })
                .to_vec()
        };
        let extra = || extra_in("crate::provider");
        for (root_macro, provider, open, decided, exported, crate_declared) in [
            ("", "", false, false, false, Vec::new()),
            ("", "generate!();\n", true, false, false, Vec::new()),
            (
                "",
                "fn local() { generate!(); }\n",
                false,
                false,
                false,
                Vec::new(),
            ),
            (
                passthrough,
                "generate!();\n",
                false,
                false,
                false,
                Vec::new(),
            ),
            (
                "macro_rules! generate { () => { pub struct Extra; }; }\n",
                "generate!();\n",
                true,
                false,
                false,
                Vec::new(),
            ),
            (
                passthrough,
                "generate! { pub struct Extra; }\n",
                false,
                false,
                false,
                extra(),
            ),
            (
                decorating,
                "generate! { pub struct Extra; }\n",
                false,
                false,
                false,
                if cfg!(unix) { extra() } else { Vec::new() },
            ),
            (
                opaque_decoration,
                "generate! { pub struct Extra; }\n",
                true,
                false,
                false,
                Vec::new(),
            ),
            (
                passthrough,
                "pub struct Holder;\nimpl Holder { generate! { pub const Extra: u8 = 0; } }\n",
                false,
                false,
                false,
                Vec::new(),
            ),
            (
                "",
                local_passthrough.as_str(),
                false,
                false,
                true,
                Vec::new(),
            ),
            (
                passthrough,
                "pub mod inner { generate! { pub struct Extra; } }\n",
                false,
                false,
                false,
                extra_in("crate::provider::inner"),
            ),
        ] {
            let project = InlineTestProject::new()
                .file(
                    "Cargo.toml",
                    "[package]\nname='inventory'\nversion='0.1.0'\nedition='2021'\n",
                )
                .file(
                    "src/lib.rs",
                    format!("{root_macro}pub mod provider;\nuse crate::provider::Target;\n"),
                )
                .file("src/provider.rs", provider)
                .build();
            let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
            let store = analyzer.store().unwrap();
            let conn = store.read_conn().unwrap();
            conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'", []).unwrap();
            let topology: i64 = conn
                .query_row(
                    "SELECT topology_id FROM selected_rust_crates WHERE crate_name='inventory'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let gaps = conn.prepare("SELECT gap_kind,subject,json(detail) FROM rust_crate_gaps WHERE topology_id=?1 ORDER BY gap_kind,subject").unwrap().query_map([topology], |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            let names = conn.prepare("SELECT module_path,namespace,name FROM rust_crate_exports WHERE topology_id=?1 ORDER BY module_path,namespace,name").unwrap().query_map([topology], |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            let macro_count: i64 = conn.query_row("SELECT count(*) FROM rust_crate_container_sources AS source CROSS JOIN source_rust_macro_invocations AS invocation ON invocation.blob_id=source.blob_id WHERE source.topology_id=?1 AND source.container_path='crate::provider'", [topology], |row| row.get(0)).unwrap();
            eprintln!(
                "provider={provider:?}, macro_count={macro_count}, exports={names:?}, gaps={gaps:?}"
            );
            assert_eq!(macro_count, i64::from(provider.contains("generate!")));
            let inventory = gaps.iter().find(|(kind, subject, _)| {
                kind == "open_export_inventory" && subject == "crate::provider"
            });
            assert_eq!(
                inventory.is_some(),
                open,
                "item position controls export inventory: {gaps:?}"
            );
            if let Some((_, _, detail)) = inventory {
                let detail: serde_json::Value = serde_json::from_str(detail).unwrap();
                let evidence = &detail["evidence"][0];
                assert!(evidence["member_blob"].is_i64());
                assert!(evidence["invocation_occurrence"].is_u64());
                assert_eq!(evidence["replay_covered"], false);
                assert_eq!(evidence["reason"], "UnsupportedMacroGeneratedModule");
                assert_eq!(evidence["decided"], decided, "{gaps:?}");
            }
            // Only an item the file's producer declared is a persisted export.
            let persisted = names
                .iter()
                .any(|(module, _, name)| module == "crate::provider" && name == "Extra");
            assert_eq!(persisted, exported, "{names:?}");
            let declared = conn.prepare("SELECT module_path,namespace,name,visibility,module_item FROM rust_crate_macro_items WHERE topology_id=?1 ORDER BY module_path,namespace,name").unwrap().query_map([topology], |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?,row.get::<_,bool>(4)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            assert_eq!(declared, crate_declared, "{root_macro:?} {provider:?}");
            evidence.push((names, gaps));
        }
        assert_ne!(
            evidence[0], evidence[1],
            "the row consumer needs an open-export-inventory gap; absent Target is a proved negative only for the closed module"
        );
    }

    #[test]
    fn crate_file_naming_keeps_same_blob_placements_and_bench_identity() {
        let project = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname='identity'\nversion='0.1.0'\nedition='2024'\n[[bench]]\nname='custom_target'\npath='benches/routes.rs'\nharness=false\n")
            .file("src/lib.rs", "pub mod a; pub mod b;")
            .file("src/a.rs", "pub fn target() {}")
            .file("src/b.rs", "pub fn target() {}")
            .file("benches/routes.rs", "#[path=\"common/mod.rs\"] mod shared;")
            .file("benches/common/mod.rs", "pub fn target() {}")
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let mut names = conn.prepare("SELECT DISTINCT rel_path,json(package_components) FROM rust_crate_file_naming ORDER BY rel_path").unwrap();
        let actual = names
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            actual,
            [
                (
                    "benches/common/mod.rs".to_owned(),
                    r#"["identity","benches","common"]"#.to_owned()
                ),
                (
                    "benches/routes.rs".to_owned(),
                    r#"["identity","benches","routes"]"#.to_owned()
                ),
                ("src/a.rs".to_owned(), r#"["identity","a"]"#.to_owned()),
                ("src/b.rs".to_owned(), r#"["identity","b"]"#.to_owned()),
                ("src/lib.rs".to_owned(), r#"["identity"]"#.to_owned()),
            ]
        );
    }

    #[test]
    fn crate_inline_module_keys_use_declaration_names() {
        let project = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname='inline'\nversion='0.1.0'\nedition='2024'\n")
            .file("src/lib.rs", "pub mod provider { pub mod model { pub fn Target() {} } pub use model::Target; }\nuse crate::provider::Target as Alias;\n")
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let paths = conn
            .prepare("SELECT container_path FROM rust_crate_containers ORDER BY container_path")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            paths,
            ["crate", "crate::provider", "crate::provider::model"]
        );
        let count: i64 = conn.query_row("SELECT count(*) FROM rust_crate_exports WHERE module_path='crate::provider' AND name='Target' AND namespace='value'", [], |row|row.get(0)).unwrap();
        assert_eq!(
            count, 1,
            "the parent's reexport must reach the nested declaration"
        );
    }

    #[test]
    fn crate_point_binder_rows_follow_dependency_named_reexports() {
        for (facade_source, imported_name) in [
            ("pub use dep::Thing as Public;", "Public"),
            ("pub use dep::*;", "Thing"),
            ("pub use bridge::Public as Renamed;", "Renamed"),
            ("pub use bridge::*;", "Public"),
        ] {
            let project = InlineTestProject::new()
            .file("Cargo.toml", "[workspace]\nmembers=[\"app\",\"facade\",\"bridge\",\"dep\"]\nresolver=\"2\"\n")
            .file("app/Cargo.toml", "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\nfacade={path=\"../facade\"}\n")
            .file("facade/Cargo.toml", "[package]\nname=\"facade\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\ndep={path=\"../dep\"}\nbridge={path=\"../bridge\"}\n")
            .file("dep/Cargo.toml", "[package]\nname=\"dep\"\nversion=\"0.1.0\"\nedition=\"2021\"\n")
            .file("bridge/Cargo.toml", "[package]\nname=\"bridge\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\ndep={path=\"../dep\"}\n")
            .file("bridge/src/lib.rs", "pub use dep::Thing as Public;")
            .file("app/src/lib.rs", format!("use facade::{imported_name} as Local; pub fn make() -> Local {{ Local }}"))
            .file("facade/src/lib.rs", facade_source)
            .file("dep/src/lib.rs", "pub struct Thing;")
            .build();
            let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
            let store = analyzer.store().unwrap();
            let conn = store.read_conn().unwrap();
            conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'", []).unwrap();
            let facade: i64 = conn
                .query_row(
                    "SELECT topology_id FROM selected_rust_crates WHERE crate_name='facade'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let app: i64 = conn
                .query_row(
                    "SELECT topology_id FROM selected_rust_crates WHERE crate_name='app'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let source_imports = conn.prepare("SELECT imports.bound_name, imports.imported_name, imports.native_scope FROM selected_rust_crate_containers AS modules JOIN source_rust_import_targets AS imports ON imports.blob_id = modules.blob_id WHERE modules.topology_id = ?1").unwrap().query_map([app], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, u32>(2)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            assert_eq!(
                source_imports,
                [("Local".into(), imported_name.into(), 0)],
                "the producer has the structured source binder"
            );
            let exports = conn.prepare("SELECT namespace FROM rust_crate_exports_reachable WHERE topology_id=?1 AND module_path='crate' AND name=?2 ORDER BY namespace").unwrap().query_map(params![facade, imported_name], |row| row.get::<_, String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            assert_eq!(
                exports,
                ["type", "value"],
                "the dependency exposes both namespaces"
            );
            let bindings = conn.prepare("SELECT namespace, bound_name, target_module_path, target_name FROM rust_crate_imports WHERE topology_id=?1 ORDER BY namespace").unwrap().query_map([app], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            let gaps = conn.prepare("SELECT gap_kind, subject, json(detail) FROM rust_crate_gaps WHERE topology_id=?1 ORDER BY gap_kind, subject").unwrap().query_map([app], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            assert_eq!(
                bindings,
                [
                    (
                        "type".into(),
                        "Local".into(),
                        "crate".into(),
                        imported_name.into()
                    ),
                    (
                        "value".into(),
                        "Local".into(),
                        "crate".into(),
                        imported_name.into()
                    ),
                ],
                "a point route must find persisted binder authority; gaps={gaps:?}"
            );
            assert!(
                gaps.is_empty(),
                "a resolved reexport is not an import gap: {gaps:?}"
            );
        }
    }

    /// Every live crate row, with each store-local surrogate replaced by the
    /// content it stands for, so that two independently built stores compare
    /// equal exactly when they publish the same crates.
    ///
    /// A topology id becomes the digest of the topology an open version row
    /// binds, and a column whose foreign key names a blob becomes that blob's
    /// OID. A version row keeps its crate, topology and manifest, but not its
    /// workspace coordinates or revision, which count within one store. Tables
    /// and columns come from the schema, so a crate table added later is
    /// compared without editing this.
    fn live_crate_rows(conn: &Connection) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
        let rows = |sql: &str| -> Vec<Vec<rusqlite::types::Value>> {
            let mut statement = conn.prepare(sql).unwrap();
            let width = statement.column_count();
            statement
                .query_map([], |row| (0..width).map(|index| row.get(index)).collect())
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        let names = |sql: &str, table: &str| -> Vec<String> {
            conn.prepare(sql)
                .unwrap()
                .query_map([table], |row| row.get(0))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        let mut live = vec![(
            "rust_crate_versions".to_owned(),
            rows("SELECT versions.crate_key, topologies.topology_digest, manifest.rel_path, manifest.blob_oid
                  FROM rust_crate_versions AS versions
                  JOIN rust_crate_topologies AS topologies USING(topology_id)
                  LEFT JOIN workspace_file_versions AS manifest
                    ON manifest.file_version_id = versions.manifest_file_version_id
                  WHERE versions.valid_until IS NULL ORDER BY 1"),
        )];
        let tables = names(
            "SELECT name FROM sqlite_schema WHERE type = 'table' AND name GLOB 'rust_crate_*' AND name <> ?1
               AND name <> 'rust_crate_reconciliations' ORDER BY name",
            "rust_crate_versions",
        );
        for table in tables {
            let columns = names(
                "SELECT name FROM pragma_table_info(?1) ORDER BY cid",
                &table,
            );
            let blob_columns = names(
                "SELECT \"from\" FROM pragma_foreign_key_list(?1) WHERE \"table\" IN ('blobs', 'resolution_fragment_interiors')",
                &table,
            );
            assert!(
                columns.iter().any(|column| column == "topology_id"),
                "{table} is keyed by topology: {columns:?}"
            );
            let select = columns
                .iter()
                .map(|column| {
                    if column == "topology_id" {
                        "live.topology_digest".to_owned()
                    } else if blob_columns.contains(column) {
                        format!("(SELECT blob_oid FROM blobs WHERE id = row.{column})")
                    } else {
                        format!("row.{column}")
                    }
                })
                .collect::<Vec<_>>();
            let order = (1..=select.len())
                .map(|position| position.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let table_rows = rows(&format!(
                "SELECT {} FROM {table} AS row
                 JOIN (SELECT topology_id, topology_digest FROM rust_crate_versions
                       JOIN rust_crate_topologies USING(topology_id)
                       WHERE valid_until IS NULL) AS live USING(topology_id)
                 ORDER BY {order}",
                select.join(", ")
            ));
            live.push((table, table_rows));
        }
        live
    }

    /// A derivation-version rotation on a warm store, which is what a release
    /// upgrade does: no file changed, so the build opens no revision, and every
    /// crate's topology digest moves because it folds in the version.
    ///
    /// The publish path used to close the open version row at the revision it
    /// was about to reopen it at, and `rust_crate_versions` rejects an interval
    /// that ends where it starts. Pipeline two found it against a real tract
    /// cache, one second into the upgrade, as eight
    /// `CHECK constraint failed: valid_until IS NULL OR valid_until > valid_from`
    /// errors inside the derivation wave. No test had rotated the version
    /// without first deleting the version rows.
    ///
    /// The store is persisted and rebuilt the way the upgrade rebuilds it. An
    /// edit between the first two builds leaves one crate opened at the current
    /// revision and the rest at the first, so the rotation ends open rows both
    /// ways: it withdraws the rows this revision opened and closes the older
    /// ones. The oracle is a from-scratch build under the new version, whose
    /// live rows the rotated store must reproduce.
    #[test]
    fn warm_derivation_version_rotation_replaces_same_revision_versions() {
        use crate::analyzer::WorkspaceAnalyzer;
        type VersionRow = (Vec<u8>, i64, Option<i64>, Vec<u8>);
        let project = fixture();
        let build =
            || WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default());
        let head = |analyzer: &WorkspaceAnalyzer| -> i64 {
            analyzer
                .store()
                .unwrap()
                .read_conn()
                .unwrap()
                .query_row(
                    "SELECT revision FROM workspace_heads WHERE lang='rust'",
                    [],
                    |row| row.get(0),
                )
                .unwrap()
        };
        let versions = |analyzer: &WorkspaceAnalyzer| -> Vec<VersionRow> {
            analyzer
                .store()
                .unwrap()
                .read_conn()
                .unwrap()
                .prepare(
                    "SELECT versions.crate_key, versions.valid_from, versions.valid_until, topologies.topology_digest
                     FROM rust_crate_versions AS versions
                     JOIN rust_crate_topologies AS topologies USING(topology_id)
                     ORDER BY 1, 2",
                )
                .unwrap()
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };

        let first = build().expect("the first build succeeds");
        let first_revision = head(&first);
        drop(first);
        project
            .file("dep/src/on.rs")
            .write("pub fn enabled() { let body = 1; let _ = body; }")
            .unwrap();
        let warm = build().expect("the edited workspace rebuilds");
        let revision = head(&warm);
        assert!(revision > first_revision, "the edit opens a revision");
        let before = versions(&warm);
        drop(warm);
        let open_before = before
            .iter()
            .filter(|row| row.2.is_none())
            .collect::<Vec<_>>();
        assert!(
            open_before.iter().any(|row| row.1 == revision)
                && open_before.iter().any(|row| row.1 < revision),
            "the rotation must end rows opened at revision {revision} and before it: {before:?}"
        );

        // The rotation, and the oracle derived under the same version.
        set_derivation_version(Some("crate-derivation-version-warm-rotation"));
        let rotated = build();
        let scratch = WorkspaceAnalyzer::build_ephemeral_footgun(
            project.project_dyn(),
            AnalyzerConfig::default(),
        );
        set_derivation_version(None);
        let rotated = rotated.expect("a derivation-version rotation on a warm store rebuilds");
        let scratch = scratch.expect("a from-scratch build under the new version succeeds");
        assert_eq!(
            head(&rotated),
            revision,
            "the rotation changes no file, so it opens no revision"
        );

        // History: rows closed before stay as they were, a row opened before
        // this revision is closed at it, and a row this revision opened is
        // withdrawn rather than closed.
        let after = versions(&rotated);
        let mut closed = before
            .iter()
            .filter(|row| row.2.is_some())
            .cloned()
            .chain(
                open_before
                    .iter()
                    .filter(|row| row.1 < revision)
                    .map(|row| (row.0.clone(), row.1, Some(revision), row.3.clone())),
            )
            .collect::<Vec<_>>();
        closed.sort();
        assert_eq!(
            after
                .iter()
                .filter(|row| row.2.is_some())
                .cloned()
                .collect::<Vec<_>>(),
            closed,
            "the rotation closes only rows that opened before revision {revision}"
        );
        let open_after = after
            .iter()
            .filter(|row| row.2.is_none())
            .collect::<Vec<_>>();
        assert_eq!(
            open_after.iter().map(|row| &row.0).collect::<Vec<_>>(),
            open_before.iter().map(|row| &row.0).collect::<Vec<_>>(),
            "every crate is still published, once"
        );
        assert!(
            open_after
                .iter()
                .zip(&open_before)
                .all(|(after, before)| after.1 == revision && after.3 != before.3),
            "every crate is re-derived onto a new topology at revision {revision}: {after:?}"
        );

        let rotated_rows = live_crate_rows(&rotated.store().unwrap().read_conn().unwrap());
        let scratch_rows = live_crate_rows(&scratch.store().unwrap().read_conn().unwrap());
        assert_eq!(
            rotated_rows
                .iter()
                .map(|(table, _)| table)
                .collect::<Vec<_>>(),
            scratch_rows
                .iter()
                .map(|(table, _)| table)
                .collect::<Vec<_>>()
        );
        for ((table, rotated), (_, scratch)) in rotated_rows.iter().zip(&scratch_rows) {
            assert_eq!(
                rotated, scratch,
                "{table}: the rotated store must publish what a from-scratch build under the new version publishes"
            );
        }
        for derived in [
            "rust_crate_exports",
            "rust_crate_imports",
            "rust_crate_gaps",
        ] {
            assert!(
                rotated_rows
                    .iter()
                    .any(|(table, rows)| table == derived && !rows.is_empty()),
                "the comparison covers derived rows in {derived}"
            );
        }
    }

    #[test]
    fn crate_topology_digests_follow_the_derivation_version() {
        let project = fixture();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let snapshot = {
            let conn = store.read_conn().unwrap();
            let row: (String, i64, i64) = conn
                .query_row(
                    "SELECT workspace_id, generation, revision FROM workspace_heads WHERE lang='rust'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            WorkspaceSnapshotId {
                workspace_id: super::super::WorkspaceId(row.0),
                lang: "rust".into(),
                generation: super::super::GenerationId::from_persisted(row.1),
                revision: row.2,
            }
        };
        let topologies = |store: &AnalyzerStore| -> i64 {
            store
                .read_conn()
                .unwrap()
                .query_row("SELECT count(*) FROM rust_crate_topologies", [], |row| {
                    row.get(0)
                })
                .unwrap()
        };
        // Rebinding is what the reconcile does when it finds the digest it
        // computed already published. It used to clear the version rows first,
        // because a same-revision rebind could not close and reopen a row at
        // its own revision; that limitation was the defect, and
        // `warm_derivation_version_rotation_replaces_same_revision_versions`
        // is the test that holds it closed.
        let rebind = |store: &AnalyzerStore| {
            store.reconcile_rust_crates(&snapshot).unwrap();
        };

        let before = current_crate_digests(&store.read_conn().unwrap());
        let published = topologies(store);
        assert!(!before.is_empty() && published > 0);

        rebind(store);
        assert_eq!(
            (
                current_crate_digests(&store.read_conn().unwrap()),
                topologies(store)
            ),
            (before.clone(), published),
            "an unchanged derivation version reuses every published topology"
        );

        set_derivation_version(Some("crate-derivation-version-test"));
        rebind(store);
        set_derivation_version(None);

        let after = current_crate_digests(&store.read_conn().unwrap());
        assert_eq!(
            after.iter().map(|row| &row.0).collect::<Vec<_>>(),
            before.iter().map(|row| &row.0).collect::<Vec<_>>(),
            "the same crates are bound"
        );
        assert!(
            after
                .iter()
                .zip(&before)
                .all(|(after, before)| after.1 != before.1),
            "a second derivation version gives every crate a different topology digest"
        );
        assert_eq!(
            topologies(store),
            published * 2,
            "and the reconcile derived the replacements instead of reusing the published rows"
        );

        // The bump costs one derivation per crate, not one per run. Lane MB
        // attributed a 0.72 GiB tract peak-RSS rise to the single run that pays
        // it (`.agents/docs/stack-graph-memory-bracket-2026-09-16.md`), and that
        // attribution holds only while the run after it derives nothing.
        set_derivation_version(Some("crate-derivation-version-test"));
        rebind(store);
        set_derivation_version(None);
        assert_eq!(
            (
                current_crate_digests(&store.read_conn().unwrap()),
                topologies(store)
            ),
            (after, published * 2),
            "a second reconcile under the bumped version reuses what the first one published"
        );
    }

    /// A trait implementation is a tier-1 row per blob and a derived crate row
    /// per topology.
    ///
    /// The fixture separates the three declarations an impl joins: the type in
    /// one file, the trait in a second, the impl in a third, so every row here
    /// is a cross-blob answer no interior scan could give. It then covers each
    /// shape the header can take: a bare name reached through a `use`, a
    /// qualified path, a generic head, a cross-crate trait, a cross-crate
    /// subject, an inline module, and a trait that resolves nowhere.
    #[test]
    fn crate_trait_impl_rows_resolve_both_header_paths_through_module_routes() {
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[workspace]\nmembers=[\"app\",\"dep\"]\nresolver=\"2\"\n",
            )
            .file(
                "dep/Cargo.toml",
                "[package]\nname=\"dep\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
            )
            .file(
                "dep/src/lib.rs",
                "pub trait DepTrait { fn d(); } pub struct DepType;",
            )
            .file(
                "app/Cargo.toml",
                "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\ndep={path=\"../dep\"}\n",
            )
            .file("app/src/lib.rs", "pub mod ty; pub mod tr; pub mod im;")
            .file(
                "app/src/ty.rs",
                "pub struct Foo; pub struct Wrapper<T>(pub T); pub struct Local;",
            )
            .file(
                "app/src/tr.rs",
                "pub trait Trait { fn frobnicate(); } pub trait LocalTrait { fn l(); }",
            )
            .file(
                "app/src/im.rs",
                concat!(
                    "use crate::tr::Trait;\n",
                    "use crate::ty::Local;\n",
                    "impl Trait for crate::ty::Foo {}\n",
                    "impl crate::tr::Trait for crate::ty::Wrapper<u8> {}\n",
                    "impl Trait for &crate::ty::Foo {}\n",
                    "impl dep::DepTrait for Local {}\n",
                    "impl crate::tr::LocalTrait for dep::DepType {}\n",
                    "impl Absent for Local {}\n",
                    "pub mod deep { use crate::tr::Trait; impl Trait for crate::ty::Foo {} }\n",
                ),
            )
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let app: i64 = conn
            .query_row(
                "SELECT topology_id FROM rust_crate_topologies WHERE crate_name='app' AND target_kind='lib'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        // Both ends of a derived row are declarations, so the test names them the
        // way a reader does: through the export row that declares them. A row
        // that carried the (crate, module, name) triple its spelling resolved
        // through could not be compared this way, which is the point of the key.
        let declaration = |crate_name: &str, module: &str, name: &str| -> (i64, i64) {
            conn.query_row(
                "SELECT exports.declaration_blob_id, exports.declaration_site
                 FROM rust_crate_exports AS exports
                 JOIN rust_crate_topologies AS topology USING(topology_id)
                 WHERE topology.crate_name=?1 AND topology.target_kind='lib'
                   AND exports.module_path=?2 AND exports.namespace='type'
                   AND exports.name=?3 AND exports.origin='declaration'",
                params![crate_name, module, name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap_or_else(|error| {
                panic!("{crate_name} {module}::{name} has a declaration row: {error}")
            })
        };
        let rows = conn
            .prepare(
                "SELECT subject_declaration_blob_id, subject_declaration_site,
                        trait_declaration_blob_id, trait_declaration_site, impl_site
                 FROM rust_crate_trait_impls WHERE topology_id=?1 ORDER BY 1,2,3,4,5",
            )
            .unwrap()
            .query_map([app], |row| {
                Ok((
                    (row.get::<_, i64>(0)?, row.get::<_, i64>(1)?),
                    (row.get::<_, i64>(2)?, row.get::<_, i64>(3)?),
                    row.get::<_, i64>(4)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let gaps = conn
            .prepare(
                "SELECT subject, json(detail) FROM rust_crate_gaps
                 WHERE topology_id=?1 AND gap_kind='unresolved_trait_impl' ORDER BY 1",
            )
            .unwrap()
            .query_map([app], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let foo = declaration("app", "crate::ty", "Foo");
        let wrapper = declaration("app", "crate::ty", "Wrapper");
        let local = declaration("app", "crate::ty", "Local");
        let implemented = declaration("app", "crate::tr", "Trait");
        let local_trait = declaration("app", "crate::tr", "LocalTrait");
        let dep_type = declaration("dep", "crate", "DepType");
        let dep_trait = declaration("dep", "crate", "DepTrait");
        let mut expected = [
            (foo, implemented),
            (foo, implemented),
            (wrapper, implemented),
            (local, dep_trait),
            (dep_type, local_trait),
        ];
        expected.sort_unstable();
        assert_eq!(
            rows.iter().map(|row| (row.0, row.1)).collect::<Vec<_>>(),
            expected,
            "each half resolves to the declaration it names, by the route a name in the \
             impl's module already takes: a qualified path through the module walk, a bare \
             name through the module's import binding, an extern head into the dependency's \
             published exports"
        );
        assert_eq!(
            rows.iter().map(|row| row.2).collect::<BTreeSet<_>>().len(),
            5,
            "the five implementations sit at five impl sites, the two \
             `impl Trait for crate::ty::Foo` among them, one of which is in the inline \
             module `deep`: {rows:?}"
        );
        assert_eq!(
            gaps,
            [(
                "crate::im::Absent".into(),
                // The current source-fact producer assigns site 36 to this
                // unresolved impl header in the fixture.
                "{\"evidence\":[{\"side\":\"trait\",\"spelling\":\"Absent\",\"impl_site\":36,\
                 \"reason\":\"unbound\",\"target_module_path\":\"crate::im\"}]}"
                    .replace(" ", "")
            )],
            "a half that reaches no declaration names the half, the spelling, why it \
             reached none and the container its route reached, and its impl contributes \
             no row"
        );
    }
    /// `use super::*;` brings in what the parent module can name, and that
    /// includes the parent's own private `use` imports, named or glob: a
    /// private binding is in scope in the module that writes it and in every
    /// module below it. This is how a `#[cfg(test)] mod tests` names the trait
    /// its fixture implements, so an impl header written there resolves
    /// through the parent's imports, not only through the parent's own items.
    #[test]
    fn crate_trait_impl_rows_bind_parent_private_imports_through_use_super_glob() {
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
            )
            .file(
                "src/lib.rs",
                "pub mod tr; pub mod ty; mod named; mod globbed;",
            )
            .file("src/tr.rs", "pub trait Trait { fn f(); }")
            .file("src/ty.rs", "pub struct Foo;")
            .file(
                "src/named.rs",
                concat!(
                    "use crate::tr::Trait;\n",
                    "use crate::ty::Foo;\n",
                    "#[cfg(test)]\n",
                    "mod tests {\n",
                    "    use super::*;\n",
                    "    struct Fake;\n",
                    "    impl Trait for Fake { fn f() {} }\n",
                    "    impl Trait for Foo { fn f() {} }\n",
                    "    mod deeper { use super::*; impl Trait for Fake { fn f() {} } }\n",
                    "}\n",
                ),
            )
            .file(
                "src/globbed.rs",
                concat!(
                    "use crate::tr::*;\n",
                    "mod tests {\n",
                    "    use super::*;\n",
                    "    struct Fake;\n",
                    "    impl Trait for Fake { fn f() {} }\n",
                    "}\n",
                ),
            )
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let rows = conn
            .prepare(
                "SELECT subject.module_path || '::' || subject.name,
                        implemented.module_path || '::' || implemented.name
                 FROM rust_crate_trait_impls AS impls
                 JOIN rust_crate_topologies AS topology USING(topology_id)
                 JOIN rust_crate_exports AS subject
                   ON subject.topology_id=impls.topology_id
                  AND subject.declaration_blob_id=impls.subject_declaration_blob_id
                  AND subject.declaration_site=impls.subject_declaration_site
                  AND subject.origin='declaration' AND subject.namespace='type'
                 JOIN rust_crate_exports AS implemented
                   ON implemented.topology_id=impls.topology_id
                  AND implemented.declaration_blob_id=impls.trait_declaration_blob_id
                  AND implemented.declaration_site=impls.trait_declaration_site
                  AND implemented.origin='declaration' AND implemented.namespace='type'
                 WHERE topology.crate_name='app' AND topology.target_kind='lib'
                 ORDER BY 1, 2",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let gaps = conn
            .prepare(
                "SELECT subject FROM rust_crate_gaps
                 WHERE gap_kind='unresolved_trait_impl' ORDER BY 1",
            )
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            rows,
            [
                (
                    "crate::globbed::tests::Fake".into(),
                    "crate::tr::Trait".into()
                ),
                (
                    "crate::named::tests::Fake".into(),
                    "crate::tr::Trait".into()
                ),
                (
                    "crate::named::tests::Fake".into(),
                    "crate::tr::Trait".into()
                ),
                ("crate::ty::Foo".into(), "crate::tr::Trait".into()),
            ],
            "each impl binds both halves through the parent's private imports: a named \
             `use` one glob away, the same `use` two globs away in a nested module, and a \
             private glob one glob away; unresolved: {gaps:?}"
        );
        assert!(gaps.is_empty(), "no half is left unbound: {gaps:?}");
    }
    /// Two byte-identical files declare one `(blob, site)`, so the relation
    /// keys each end by the file that declares it. When the impl names its
    /// trait through a re-export, the file is found by following the
    /// re-export to the declaring module, in this crate and across a crate
    /// boundary, not by picking among every file that declares those bytes.
    #[test]
    fn crate_trait_impl_rows_place_each_end_in_its_declaring_file() {
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[workspace]\nmembers=[\"app\",\"dep\"]\nresolver=\"2\"\n",
            )
            .file(
                "dep/Cargo.toml",
                "[package]\nname=\"dep\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
            )
            .file(
                "dep/src/lib.rs",
                "pub mod a; pub mod b; pub mod prelude { pub use crate::b::Shared; }",
            )
            .file("dep/src/a.rs", "pub trait Shared {}")
            .file("dep/src/b.rs", "pub trait Shared {}")
            .file(
                "app/Cargo.toml",
                "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\ndep={path=\"../dep\"}\n",
            )
            .file(
                "app/src/lib.rs",
                "pub mod one; pub mod two; pub mod facade; pub mod worker;",
            )
            .file("app/src/one.rs", "pub trait Runnable {}")
            .file("app/src/two.rs", "pub trait Runnable {}")
            .file("app/src/facade.rs", "pub use crate::two::Runnable;")
            .file(
                "app/src/worker.rs",
                concat!(
                    "pub struct Worker;\n",
                    "impl crate::one::Runnable for Worker {}\n",
                    "impl crate::facade::Runnable for Worker {}\n",
                    "impl dep::prelude::Shared for Worker {}\n",
                ),
            )
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let rows = conn
            .prepare(
                "SELECT impls.subject_rel_path, impls.trait_rel_path, impls.impl_rel_path
                 FROM rust_crate_trait_impls AS impls
                 JOIN rust_crate_topologies AS topology USING(topology_id)
                 WHERE topology.crate_name='app' AND topology.target_kind='lib'
                 ORDER BY 1, 2, 3",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let worker = || "app/src/worker.rs".to_string();
        assert_eq!(
            rows,
            [
                (worker(), "app/src/one.rs".to_string(), worker()),
                (worker(), "app/src/two.rs".to_string(), worker()),
                (worker(), "dep/src/b.rs".to_string(), worker()),
            ],
            "a direct path places the trait in its own file, a re-export in this crate \
             places it in the file the re-export names, and a re-export in a dependency \
             places it in that dependency's declaring file"
        );
        let unbridged: i64 = conn
            .query_row(
                "SELECT count(*) FROM rust_crate_trait_impls WHERE impl_declaration_id IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let impl_items: Vec<i64> = conn
            .prepare(
                "SELECT DISTINCT impls.impl_declaration_id
                 FROM rust_crate_trait_impls AS impls
                 JOIN source_rust_impl_items AS item
                   ON item.blob_id=impls.impl_blob_id
                  AND item.declaration_id=impls.impl_declaration_id
                 ORDER BY 1",
            )
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            (unbridged, impl_items.len()),
            (0, 3),
            "every row names its impl item's source declaration, and the three impls \
             in worker.rs are three items: {impl_items:?}"
        );
    }

    #[test]
    fn crate_cross_crate_reexport_routes_become_exports_and_bindings() {
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[workspace]\nmembers=[\"app\",\"relay\",\"umbrella\",\"dep\"]\nresolver=\"2\"\n",
            )
            .file(
                "dep/Cargo.toml",
                "[package]\nname=\"dep\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
            )
            .file("dep/src/lib.rs", "pub mod inner { pub struct Name; }")
            .file(
                "umbrella/Cargo.toml",
                "[package]\nname=\"umbrella\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\ndep={path=\"../dep\"}\n",
            )
            .file("umbrella/src/lib.rs", "pub use dep::inner;")
            .file(
                "relay/Cargo.toml",
                "[package]\nname=\"relay\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\numbrella={path=\"../umbrella\"}\n",
            )
            .file("relay/src/lib.rs", "pub use umbrella::inner;")
            .file(
                "app/Cargo.toml",
                "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\ndep={path=\"../dep\"}\numbrella={path=\"../umbrella\"}\nrelay={path=\"../relay\"}\n",
            )
            .file(
                "app/src/lib.rs",
                "pub use dep::inner; pub mod facade; pub mod sub;",
            )
            .file(
                "app/src/facade.rs",
                "pub use dep::inner::Name; pub use dep::inner::Absent;",
            )
            .file(
                "app/src/sub.rs",
                "use crate::inner::Name; use crate::facade::Name as Viaf; use umbrella::inner::Name as Viau; use relay::inner::Name as Viar; pub fn make(_: Name, _: Viaf, _: Viau, _: Viar) {}",
            )
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let key = |name: &str| -> String {
            conn.query_row(
                "SELECT hex(crate_key) FROM rust_crate_topologies WHERE crate_name=?1 AND target_kind='lib'",
                [name],
                |row| row.get(0),
            )
            .unwrap()
        };
        let app: i64 = conn
            .query_row(
                "SELECT topology_id FROM rust_crate_topologies WHERE crate_name='app' AND target_kind='lib'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let exports = conn.prepare("SELECT module_path, namespace, name, origin FROM rust_crate_exports WHERE topology_id=?1 AND name IN ('inner','Name','Absent') ORDER BY 1,2,3").unwrap().query_map([app], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert_eq!(
            exports,
            [
                (
                    "crate".into(),
                    "type".into(),
                    "inner".into(),
                    "reexport".into()
                ),
                (
                    "crate::facade".into(),
                    "type".into(),
                    "Name".into(),
                    "reexport".into()
                ),
                (
                    "crate::facade".into(),
                    "value".into(),
                    "Name".into(),
                    "reexport".into()
                ),
            ],
            "a re-export of a dependency name is an export row of the re-exporting module"
        );
        let bindings = conn.prepare("SELECT bound_name, namespace, hex(target_crate_key), target_module_path, target_name FROM rust_crate_imports WHERE topology_id=?1 AND module_path='crate::sub' ORDER BY 1,2").unwrap().query_map([app], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        let dep = key("dep");
        let app_key = key("app");
        assert_eq!(
            bindings,
            [
                (
                    "Name".into(),
                    "type".into(),
                    dep.clone(),
                    "crate::inner".into(),
                    "Name".into()
                ),
                (
                    "Name".into(),
                    "value".into(),
                    dep.clone(),
                    "crate::inner".into(),
                    "Name".into()
                ),
                (
                    "Viaf".into(),
                    "type".into(),
                    app_key.clone(),
                    "crate::facade".into(),
                    "Name".into()
                ),
                (
                    "Viaf".into(),
                    "value".into(),
                    app_key,
                    "crate::facade".into(),
                    "Name".into()
                ),
                (
                    "Viar".into(),
                    "type".into(),
                    dep.clone(),
                    "crate::inner".into(),
                    "Name".into()
                ),
                (
                    "Viar".into(),
                    "value".into(),
                    dep.clone(),
                    "crate::inner".into(),
                    "Name".into()
                ),
                (
                    "Viau".into(),
                    "type".into(),
                    dep.clone(),
                    "crate::inner".into(),
                    "Name".into()
                ),
                (
                    "Viau".into(),
                    "value".into(),
                    dep,
                    "crate::inner".into(),
                    "Name".into()
                ),
            ],
            "a path through a re-exported dependency module binds the dependency's export, \
             however many crates re-exported it on the way"
        );
        let gaps = conn.prepare("SELECT gap_kind, subject, json(detail) FROM rust_crate_gaps WHERE topology_id=?1 ORDER BY 1,2").unwrap().query_map([app], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert_eq!(
            gaps,
            [(
                "unresolved_reexport".into(),
                "crate::facade::Absent".into(),
                "{\"evidence\":[{\"import_ordinal\":1,\"imported_name\":\"Absent\",\"target_crate\":\"dep\",\"target_module_path\":\"crate::inner\"}]}".into()
            )],
            "a name the dependency does not export stays a gap that names the dependency"
        );
    }

    #[test]
    fn crate_textual_macro_shadowing_requires_source_visibility_rows() {
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname=\"textual\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
            )
            .file(
                "src/lib.rs",
                r#"
macro_rules! choose { () => { 1u8 }; }
pub mod first;
macro_rules! choose { () => { 2u8 }; }
pub mod second;
"#,
            )
            .file("src/first.rs", "pub fn value() -> u8 { choose!() }")
            .file("src/second.rs", "pub fn value() -> u8 { choose!() }")
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let definitions = conn
            .prepare(
                "SELECT definitions.blob_id, bridges.source_site
                 FROM source_rust_macro_definitions AS definitions
                 JOIN source_native_declaration_bridges AS bridges
                   USING(blob_id, declaration_id)
                 ORDER BY definitions.ordinal",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            definitions.len(),
            2,
            "source macro definitions: {definitions:?}"
        );
        let exports = conn
            .prepare(
                "SELECT declaration_blob_id, declaration_site
                 FROM rust_crate_exports
                 WHERE module_path='crate' AND namespace='macro' AND name='choose'
                 ORDER BY declaration_site",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(exports.len(), 1, "namespace exports: {exports:?}");
        // File-backed children inherit the textual environment at their mod
        // declaration, not the final namespace export of the parent module.
        let selected = conn
            .prepare(
                "SELECT modules.module_name, modules.blob_id,
                   (SELECT bridges.source_site FROM rust_item_macros AS macros
                    JOIN source_native_declaration_bridges AS bridges
                      ON bridges.blob_id=macros.blob_id
                     AND bridges.declaration_id=macros.declaration_id
                    WHERE macros.blob_id=modules.blob_id
                      AND macros.macro_name='choose'
                      AND macros.visible_after <= occurrence.start_byte
                      AND macros.scope_start <= occurrence.start_byte
                      AND occurrence.start_byte < macros.scope_end
                    ORDER BY macros.scope_end-macros.scope_start,
                             macros.visible_after DESC LIMIT 1)
                 FROM source_rust_module_declarations AS modules
                 JOIN source_declarations AS declarations USING(blob_id, declaration_id)
                 JOIN source_occurrences AS occurrence
                   ON occurrence.blob_id=declarations.blob_id
                  AND occurrence.occurrence_id=declarations.occurrence_id
                 ORDER BY modules.module_name",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    (row.get::<_, i64>(1)?, row.get::<_, i64>(2)?),
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        eprintln!(
            "textual macro definitions={definitions:?}; namespace exports={exports:?}; inherited={selected:?}"
        );
        assert_eq!(
            selected,
            [
                ("first".to_owned(), definitions[0]),
                ("second".to_owned(), definitions[1])
            ]
        );
    }

    #[test]
    fn crate_include_splice_requires_multiple_blobs_at_one_module_path() {
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname=\"splice\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
            )
            .file("src/lib.rs", "include!(\"fragment.rs\");")
            .file("src/fragment.rs", "pub fn included() {}")
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let conn = analyzer.store().unwrap().read_conn().unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM rust_crate_gaps WHERE gap_kind='unplaced_module'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        let rows: i64 = conn.query_row("SELECT count(*) FROM rust_crate_container_sources s JOIN rust_crate_topologies t USING(topology_id) WHERE t.crate_name='splice' AND s.rel_path='src/fragment.rs' AND s.source_kind='include'", [], |row| row.get(0)).unwrap();
        assert_eq!(
            rows, 1,
            "the include splice must retain its own blob in the host namespace"
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM rust_crate_containers", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM rust_crate_container_sources",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            2
        );
        assert_eq!(conn.query_row("SELECT count(*) FROM rust_crate_exports WHERE module_path='crate' AND name='included'", [], |row| row.get::<_, i64>(0)).unwrap(), 1);
    }

    #[test]
    fn crate_local_imports_require_binder_scope_in_the_natural_key() {
        let project = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname=\"binders\"\nversion=\"0.1.0\"\nedition=\"2021\"\n")
            .file("src/lib.rs", "pub mod a { pub struct X; } fn f() { use crate::a::X; } fn g() { use crate::a::X; }")
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let conn = analyzer.store().unwrap().read_conn().unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM rust_crate_gaps WHERE gap_kind='unresolved_import'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        let rows: i64 = conn
            .query_row(
                "SELECT count(*) FROM rust_crate_imports WHERE namespace='type' AND bound_name='X'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rows, 2, "both disjoint lexical binders must survive");
    }

    #[test]
    fn crate_module_walk_uses_revision_path_indexes_in_both_statistics_states() {
        use super::super::planner_statistics::pinned_plans::{explain_pin, pinned};
        use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
        let fixture = fixture();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.conn.lock().unwrap();
        super::super::ensure_revisioned_workspace_views(&conn).unwrap();
        conn.execute("DELETE FROM selected_workspace_revisions", [])
            .unwrap();
        conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id, lang, generation, revision FROM workspace_heads WHERE lang = 'rust'", []).unwrap();
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            let plan = explain_pin(&conn, &pinned("rust_crate_module_walk"));
            assert!(
                plan.iter().any(
                    |row| row.contains("idx_workspace_file_versions_snapshot_kind")
                        && row.contains("rel_path=?")
                ),
                "{state:?}: {plan:?}"
            );
            assert!(
                plan.iter()
                    .any(|row| row.contains("source_rust_module_routes_fk_scope_ordinal")),
                "{state:?}: {plan:?}"
            );
            assert!(
                plan.iter()
                    .any(|row| row.contains("source_rust_module_scopes_fk_parent_ordinal")),
                "{state:?}: {plan:?}"
            );
            assert!(
                !plan.iter().any(|row| row.contains("SCAN files")
                    || row.contains("AUTOMATIC")
                    || row.contains("MATERIALIZE selected_workspace_file_versions")),
                "{state:?}: {plan:?}"
            );
        }
    }
}
