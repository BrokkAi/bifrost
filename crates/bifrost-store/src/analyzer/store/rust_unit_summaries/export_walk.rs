//! The summary-backed resolution of a foreign re-export (#11173 D5).
//!
//! A re-export in the unit being derived names a canonical target `(unit, module,
//! name)` that the crate topology produced. This walk turns that coordinate into
//! what the summary publishes: the target's identity, and the first direct
//! dependency, in dependency order, that publicly exposes the target. It does so
//! from other units' Rust child export rows only, so every unit it consults is
//! read through a [`WalkUnits`] that records it, whether the read finds the name
//! or not:
//!
//! - the endpoint: the target unit publishes a public row at the coordinate;
//! - a re-export hop: a direct dependency has a public alias row to the target;
//! - a module hop: a direct dependency reaches the target's module, or a module
//!   where the target unit re-exports the target, through public type rows that
//!   name a module. A declaration row names its own child module. An alias or
//!   glob row names the module at its canonical target. A name with more than one
//!   distinct target at one module is ambiguous and proves no hop.
//!
//! The walk is iterative, a visited set bounds cycles, and probes run in
//! dependency-ordinal order, so the units read do not depend on hash order.

use super::{
    ExportTargetCandidate, ExportTargetIdentity, ReadKind, Result, digest_from_row,
    identity_for_name,
};
use rusqlite::{Connection, params};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// How a walk reaches another unit's rows.
pub(super) trait WalkUnits {
    /// The live summary id of `unit_key`, or `None` when it is unavailable.
    fn fetch(&mut self, unit_key: [u8; 32]) -> Result<Option<i64>>;
    /// Record that the fetched unit was read for `kind`.
    fn note(&mut self, unit_key: [u8; 32], kind: ReadKind);
}

impl WalkUnits for super::ForeignReader<'_> {
    fn fetch(&mut self, unit_key: [u8; 32]) -> Result<Option<i64>> {
        super::ForeignReader::fetch(self, unit_key)
    }

    fn note(&mut self, unit_key: [u8; 32], kind: ReadKind) {
        super::ForeignReader::note(self, unit_key, kind);
    }
}

pub(crate) const ENDPOINT_ROW_SQL: &str = "SELECT 1 FROM main.rust_resolution_unit_summary_exports
    WHERE summary_id = ?1 AND module_path = ?2 AND namespace = ?3 AND name = ?4
      AND visibility = 'public'
    LIMIT 1";

/// The modules of one summary where a public alias row names the target.
pub(crate) const ALIAS_MODULES_SQL: &str = "SELECT exports.module_path
    FROM main.rust_resolution_unit_summary_exports AS exports
      INDEXED BY rust_resolution_unit_summary_exports_alias_target
    WHERE exports.target_unit_key = ?1 AND exports.target_module_path = ?2
      AND exports.target_name = ?3 AND exports.namespace = ?4
      AND exports.alias_identity_id = ?5 AND exports.summary_id = ?6
      AND exports.origin <> 'declaration' AND exports.visibility = 'public'
    ORDER BY exports.module_path";

pub(crate) const MODULE_ROWS_SQL: &str = "SELECT module_path, name, origin, target_unit_key,
        target_module_path, target_name
    FROM main.rust_resolution_unit_summary_exports
    WHERE summary_id = ?1 AND namespace = 'type' AND visibility = 'public'";

/// Named re-export routes: a crate-root or `self` alias need not have an export row.
pub(crate) const ROUTE_ROWS_SQL: &str = "SELECT module_path, bound_name, target_unit_key,
        target_module_path, target_name
    FROM main.rust_resolution_unit_summary_reexport_routes
    WHERE summary_id = ?1 AND visibility = 'public'";

pub(crate) const CONTAINERS_SQL: &str = "SELECT module_path
    FROM main.rust_resolution_unit_summary_container_attributes WHERE summary_id = ?1";

/// A unit, module path and name: where a row's name finally lands.
type Coordinate = ([u8; 32], String, String);

/// One unit's module structure, as its live summary publishes it.
struct UnitModules {
    /// Every module and enum scope the unit declares.
    containers: HashSet<String>,
    /// For each module path and name, the distinct coordinates its public type
    /// rows land on.
    types: HashMap<String, BTreeMap<String, BTreeSet<Coordinate>>>,
}

/// The caches of one derivation's walks. Units are numbered in `modules` and
/// named by index.
#[derive(Default)]
pub(super) struct ExportWalk {
    modules: Vec<UnitModules>,
    index: HashMap<[u8; 32], Option<usize>>,
    reach: HashMap<[u8; 32], HashSet<([u8; 32], String)>>,
}

impl ExportWalk {
    /// The unit's module structure, or `None` when the unit is unavailable. The
    /// read is recorded as `kind` whether or not it is available.
    fn unit_modules(
        &mut self,
        conn: &Connection,
        units: &mut impl WalkUnits,
        unit_key: [u8; 32],
        kind: ReadKind,
    ) -> Result<Option<usize>> {
        let loaded = match self.index.get(&unit_key) {
            Some(loaded) => {
                units.fetch(unit_key)?;
                *loaded
            }
            None => {
                let loaded = match units.fetch(unit_key)? {
                    None => None,
                    Some(summary_id) => {
                        let containers = conn
                            .prepare_cached(CONTAINERS_SQL)?
                            .query_map([summary_id], |row| row.get::<_, String>(0))?
                            .collect::<rusqlite::Result<HashSet<_>>>()?;
                        let mut types: HashMap<String, BTreeMap<String, BTreeSet<Coordinate>>> =
                            HashMap::new();
                        let mut statement = conn.prepare_cached(MODULE_ROWS_SQL)?;
                        let mut rows = statement.query([summary_id])?;
                        while let Some(row) = rows.next()? {
                            let module_path: String = row.get(0)?;
                            let name: String = row.get(1)?;
                            let origin: String = row.get(2)?;
                            let coordinate = if origin == "declaration" {
                                (unit_key, module_path.clone(), name.clone())
                            } else {
                                (
                                    digest_from_row(row.get::<_, Vec<u8>>(3)?)?,
                                    row.get(4)?,
                                    row.get(5)?,
                                )
                            };
                            types
                                .entry(module_path)
                                .or_default()
                                .entry(name)
                                .or_default()
                                .insert(coordinate);
                        }
                        // A route names a module with no export row of its own when
                        // it is a crate-root or `self` alias; an export row at the
                        // same name shadows the route.
                        let exported: HashSet<(String, String)> = types
                            .iter()
                            .flat_map(|(module_path, names)| {
                                names
                                    .keys()
                                    .map(move |name| (module_path.clone(), name.clone()))
                            })
                            .collect();
                        let mut statement = conn.prepare_cached(ROUTE_ROWS_SQL)?;
                        let mut rows = statement.query([summary_id])?;
                        while let Some(row) = rows.next()? {
                            let module_path: String = row.get(0)?;
                            let name: String = row.get(1)?;
                            // Only an export row shadows a route. Routes already
                            // read for this name do not: two routes with different
                            // targets stay two coordinates, which is ambiguous.
                            if exported.contains(&(module_path.clone(), name.clone())) {
                                continue;
                            }
                            types
                                .entry(module_path)
                                .or_default()
                                .entry(name)
                                .or_default()
                                .insert((
                                    digest_from_row(row.get::<_, Vec<u8>>(2)?)?,
                                    row.get(3)?,
                                    row.get(4)?,
                                ));
                        }
                        self.modules.push(UnitModules { containers, types });
                        Some(self.modules.len() - 1)
                    }
                };
                self.index.insert(unit_key, loaded);
                loaded
            }
        };
        units.note(unit_key, kind);
        Ok(loaded)
    }

    /// Every `(unit, module)` that `from` publicly reaches through module hops,
    /// `from`'s own root included. `own` is the unit being derived: it has not
    /// settled, so it is never read and its modules prove nothing.
    fn reachable(
        &mut self,
        conn: &Connection,
        units: &mut impl WalkUnits,
        own: [u8; 32],
        from: [u8; 32],
    ) -> Result<&HashSet<([u8; 32], String)>> {
        if !self.reach.contains_key(&from) {
            let root = (from, "crate".to_owned());
            let mut visited = HashSet::from([root.clone()]);
            let mut worklist = vec![root];
            while let Some((unit_key, module_path)) = worklist.pop() {
                if unit_key == own {
                    continue;
                }
                let Some(index) = self.unit_modules(conn, units, unit_key, ReadKind::ModuleHop)?
                else {
                    continue;
                };
                let hops: Vec<Coordinate> = self.modules[index]
                    .types
                    .get(&module_path)
                    .into_iter()
                    .flatten()
                    // More than one distinct target is ambiguous: no hop is proven.
                    .filter(|(_, coordinates)| coordinates.len() == 1)
                    .filter_map(|(_, coordinates)| coordinates.iter().next().cloned())
                    .collect();
                for (target_unit, target_module, target_name) in hops {
                    if target_unit == own {
                        continue;
                    }
                    // A `self` alias names its module itself.
                    let container = if target_name == "self" {
                        target_module
                    } else {
                        format!("{target_module}::{target_name}")
                    };
                    let Some(target_index) =
                        self.unit_modules(conn, units, target_unit, ReadKind::ModuleHop)?
                    else {
                        continue;
                    };
                    if !self.modules[target_index].containers.contains(&container) {
                        // The name lands on an item, not a module: nothing to follow.
                        units.note(target_unit, ReadKind::Absence);
                        continue;
                    }
                    let node = (target_unit, container);
                    if visited.insert(node.clone()) {
                        worklist.push(node);
                    }
                }
            }
            self.reach.insert(from, visited);
        }
        Ok(&self.reach[&from])
    }

    /// Resolve one non-declaration export of `unit_key` to its canonical target and
    /// the first direct dependency that publicly exposes it. `None` means the
    /// target is unproven: its unit is unavailable or lacks the name, or no direct
    /// dependency exposes it.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn export_target(
        &mut self,
        conn: &Connection,
        units: &mut impl WalkUnits,
        unit_key: [u8; 32],
        topology_id: i64,
        namespace: &str,
        target: ([u8; 32], String, String),
        dependency_ordinals: &HashMap<[u8; 32], usize>,
    ) -> Result<Option<ExportTargetCandidate>> {
        let (target_unit_key, target_module_path, target_name) = target;
        let same_unit = target_unit_key == unit_key;
        let target_summary = if same_unit {
            let published: bool = conn
                .prepare_cached(
                    "SELECT EXISTS(SELECT 1 FROM main.rust_crate_exports
                     WHERE topology_id = ?1 AND module_path = ?2 AND namespace = ?3 AND name = ?4)",
                )?
                .query_row(
                    params![topology_id, target_module_path, namespace, target_name],
                    |row| row.get(0),
                )?;
            if !published {
                return Ok(None);
            }
            None
        } else {
            // The target's rows are read from its live summary, which its output
            // digest covers. A name it lacks is recorded too: adding it must
            // derive this unit.
            let summary_id = units.fetch(target_unit_key)?;
            let published = match summary_id {
                Some(summary_id) => conn
                    .prepare_cached(ENDPOINT_ROW_SQL)?
                    .query_row(
                        params![summary_id, target_module_path, namespace, target_name],
                        |_| Ok(()),
                    )
                    .map(|()| true)
                    .or_else(|error| match error {
                        rusqlite::Error::QueryReturnedNoRows => Ok(false),
                        error => Err(error),
                    })?,
                None => false,
            };
            units.note(
                target_unit_key,
                if summary_id.is_some() && !published {
                    ReadKind::Absence
                } else {
                    ReadKind::Endpoint
                },
            );
            if !published {
                return Ok(None);
            }
            summary_id
        };
        let Some((identity_id, identity_digest)) =
            identity_for_name(conn, namespace, &target_name)?
        else {
            return Ok(None);
        };
        let identity = ExportTargetIdentity {
            identity_id,
            identity_digest,
        };
        if same_unit {
            return Ok(Some(ExportTargetCandidate {
                target_unit_key,
                target_module_path,
                target_name,
                identity,
                dependency_ordinal: None,
            }));
        }

        let mut exposing: Option<Vec<([u8; 32], String)>> = None;
        let mut first_hop = dependency_ordinals.get(&target_unit_key).copied();
        let mut ordered: Vec<(usize, [u8; 32])> = dependency_ordinals
            .iter()
            .map(|(key, ordinal)| (*ordinal, *key))
            .collect();
        ordered.sort_unstable();
        for (ordinal, dependency_key) in ordered {
            if first_hop.is_some_and(|previous| previous <= ordinal) {
                break;
            }
            // A direct dependency is recorded in the dependencies table. One that
            // has not settled has no current row to witness with.
            let dependency_summary = units.fetch(dependency_key)?;
            units.note(dependency_key, ReadKind::ReexportHop);
            let Some(dependency_summary) = dependency_summary else {
                continue;
            };
            let has_alias: bool = conn
                .prepare_cached(ALIAS_MODULES_SQL)?
                .query(params![
                    target_unit_key.as_slice(),
                    target_module_path,
                    target_name,
                    namespace,
                    identity_id,
                    dependency_summary
                ])?
                .next()?
                .is_some();
            let witnesses = has_alias || {
                // The modules where the target unit itself exposes the target:
                // its own module, and each module that re-exports it. Read only
                // when a dependency has to be walked to.
                if exposing.is_none() {
                    let mut modules = vec![(target_unit_key, target_module_path.clone())];
                    if let Some(summary_id) = target_summary {
                        let alias_modules = conn
                            .prepare_cached(ALIAS_MODULES_SQL)?
                            .query_map(
                                params![
                                    target_unit_key.as_slice(),
                                    target_module_path,
                                    target_name,
                                    namespace,
                                    identity_id,
                                    summary_id
                                ],
                                |row| row.get::<_, String>(0),
                            )?
                            .collect::<rusqlite::Result<Vec<_>>>()?;
                        modules.extend(
                            alias_modules
                                .into_iter()
                                .map(|module_path| (target_unit_key, module_path)),
                        );
                    }
                    exposing = Some(modules);
                }
                let exposing = exposing
                    .as_deref()
                    .expect("exposing modules were just read");
                let reachable = self.reachable(conn, units, unit_key, dependency_key)?;
                exposing.iter().any(|node| reachable.contains(node))
            };
            if witnesses {
                first_hop = Some(ordinal);
                break;
            }
        }
        let Some(first_hop) = first_hop else {
            // Do not let an unproven candidate disappear behind another
            // candidate and turn an incomplete export into a unique one.
            return Ok(None);
        };
        Ok(Some(ExportTargetCandidate {
            target_unit_key,
            target_module_path,
            target_name,
            identity,
            dependency_ordinal: Some(first_hop),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::store::AnalyzerStore;
    use brokk_bifrost_test_macros::hardwon;

    struct Units(HashMap<[u8; 32], i64>);

    impl WalkUnits for Units {
        fn fetch(&mut self, unit_key: [u8; 32]) -> Result<Option<i64>> {
            Ok(self.0.get(&unit_key).copied())
        }

        fn note(&mut self, _unit_key: [u8; 32], _kind: ReadKind) {}
    }

    #[test]
    fn a_name_two_globs_publish_proves_no_module_hop() {
        // `mid` globs two units that each publish a module `event`, and names
        // kernel_a's through `ok`. The ambiguous `event` proves neither module;
        // `ok` still proves kernel_a's, and kernel_b's stays unreached.
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().unwrap();
        let _fixture = crate::analyzer::store::sealed_families::Fixture::new(&conn);
        conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
        let (mid, a, b) = ([1_u8; 32], [2_u8; 32], [3_u8; 32]);
        for (summary, container) in [(2, "crate::event"), (3, "crate::event")] {
            conn.execute(
                "INSERT INTO rust_resolution_unit_summary_container_attributes(
                   summary_id, container_path, kind) VALUES(?1, ?2, 'module')",
                params![summary, container],
            )
            .unwrap();
        }
        for (name, origin, target) in [
            ("event", "glob_reexport", a),
            ("event", "glob_reexport", b),
            ("ok", "reexport", a),
        ] {
            conn.execute(
                "INSERT INTO rust_resolution_unit_summary_exports(
                   summary_id, module_path, namespace, name, identity_id, visibility, origin,
                   target_unit_key, alias_identity_id, target_module_path, target_name)
                 VALUES(1, 'crate', 'type', ?1, 1, 'public', ?2, ?3, 1, 'crate', 'event')",
                params![name, origin, target.as_slice()],
            )
            .unwrap();
        }
        let mut units = Units(HashMap::from([(mid, 1), (a, 2), (b, 3)]));
        let mut walk = ExportWalk::default();
        let reachable = walk.reachable(&conn, &mut units, [9; 32], mid).unwrap();
        assert!(
            reachable.contains(&(a, "crate::event".to_owned())),
            "{reachable:?}"
        );
        assert!(
            !reachable.contains(&(b, "crate::event".to_owned())),
            "{reachable:?}"
        );
    }

    #[test]
    #[hardwon(
        "b02bbdca17aa: a second re-export route to one name was skipped as shadowed, hiding the ambiguity"
    )]
    fn two_routes_to_one_name_prove_no_hop_but_an_export_row_shadows_a_route() {
        // Two routes bind `alias` to different modules, so `alias` is ambiguous
        // and proves neither. A route at `shadowed` is hidden by the export row of
        // that name, which alone decides it.
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().unwrap();
        let _fixture = crate::analyzer::store::sealed_families::Fixture::new(&conn);
        conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
        let (mid, a, b, c) = ([1_u8; 32], [2_u8; 32], [3_u8; 32], [4_u8; 32]);
        for (summary, container) in [(2, "crate::one"), (3, "crate::two"), (4, "crate::three")] {
            conn.execute(
                "INSERT INTO rust_resolution_unit_summary_container_attributes(
                   summary_id, container_path, kind) VALUES(?1, ?2, 'module')",
                params![summary, container],
            )
            .unwrap();
        }
        for (name, target, target_name) in [
            ("alias", a, "one"),
            ("alias", b, "two"),
            ("shadowed", c, "three"),
        ] {
            conn.execute(
                "INSERT INTO rust_resolution_unit_summary_reexport_routes(
                   summary_id, module_path, bound_name, target_unit_key,
                   target_module_path, target_name, visibility)
                 VALUES(1, 'crate', ?1, ?2, 'crate', ?3, 'public')",
                params![name, target.as_slice(), target_name],
            )
            .unwrap();
        }
        // The export row at `shadowed` publishes a module-less target in `a`.
        conn.execute(
            "INSERT INTO rust_resolution_unit_summary_exports(
               summary_id, module_path, namespace, name, identity_id, visibility, origin,
               target_unit_key, alias_identity_id, target_module_path, target_name)
             VALUES(1, 'crate', 'type', 'shadowed', 1, 'public', 'reexport', ?1, 1, 'crate', 'item')",
            [a.as_slice()],
        )
        .unwrap();
        let mut units = Units(HashMap::from([(mid, 1), (a, 2), (b, 3), (c, 4)]));
        let mut walk = ExportWalk::default();
        let reachable = walk.reachable(&conn, &mut units, [9; 32], mid).unwrap();
        for (unit, module) in [(a, "crate::one"), (b, "crate::two"), (c, "crate::three")] {
            assert!(
                !reachable.contains(&(unit, module.to_owned())),
                "{module} is not proven: {reachable:?}"
            );
        }
    }
}
