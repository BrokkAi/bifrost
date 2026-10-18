//! Query-local component schedules. The graph exists only while converting one
//! edge query to rows; reconciliation and derivation retain their state in SQL.
use std::collections::{HashMap, HashSet};

use rusqlite::{Connection, params};

use super::Result;
use crate::analyzer::semantic::CancellationToken;
use crate::analyzer::semantic::cfg_algorithms::{
    CfgAlgorithmBudget, CfgAlgorithmRequest, DenseUsizeGraph, strongly_connected_components,
};

pub(super) const SCHEMA_SQL: &str = "
CREATE TEMP TABLE IF NOT EXISTS unit_schedule_units(unit_id INTEGER PRIMARY KEY) STRICT;
CREATE TEMP TABLE IF NOT EXISTS unit_schedule_edges(
 unit_id INTEGER NOT NULL, dependency_id INTEGER NOT NULL,
 orders INTEGER NOT NULL CHECK(orders IN (0,1)),
 PRIMARY KEY(unit_id, dependency_id)
) WITHOUT ROWID, STRICT;
CREATE INDEX IF NOT EXISTS temp.unit_schedule_edges_dependency ON unit_schedule_edges(dependency_id);
CREATE TEMP TABLE IF NOT EXISTS unit_schedule_components(
 unit_id INTEGER PRIMARY KEY, component_id INTEGER NOT NULL, cyclic INTEGER NOT NULL CHECK(cyclic IN (0,1))
) STRICT;
CREATE INDEX IF NOT EXISTS temp.unit_schedule_components_component ON unit_schedule_components(component_id, unit_id);
CREATE TEMP TABLE IF NOT EXISTS unit_schedule_waves(
 component_id INTEGER PRIMARY KEY, wave INTEGER NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS temp.unit_schedule_waves_wave ON unit_schedule_waves(wave, component_id);
";

pub(super) const CLEAR_SQL: &str = "
DELETE FROM temp.unit_schedule_units;
DELETE FROM temp.unit_schedule_edges;
DELETE FROM temp.unit_schedule_components;
DELETE FROM temp.unit_schedule_waves;";

/// Includes isolated units and self edges. Consumed-only edges remain in the
/// input relation, but do not participate in ordering or component membership.
pub(super) const EDGES_SQL: &str = "SELECT units.unit_id, edges.dependency_id
 FROM temp.unit_schedule_units AS units
 LEFT JOIN temp.unit_schedule_edges AS edges ON edges.unit_id = units.unit_id AND edges.orders = 1
 ORDER BY units.unit_id";

/// Stable unit order within dependency-first component waves. Keeping the
/// unit-id tie break also preserves the previous acyclic Kahn order.
pub(super) const ORDER_SQL: &str = "SELECT component.unit_id
 FROM temp.unit_schedule_waves AS waves INDEXED BY unit_schedule_waves_wave
 CROSS JOIN temp.unit_schedule_components AS component INDEXED BY unit_schedule_components_component
 WHERE component.component_id = waves.component_id
 ORDER BY waves.wave, component.unit_id";

/// Read the entire graph once, compute SCCs and dependency-first parallel waves,
/// and release all graph allocations before any subsequent read of the store.
pub(super) fn build(conn: &Connection) -> Result<()> {
    let rows = conn
        .prepare(EDGES_SQL)?
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let (components, waves) = {
        let mut ids = Vec::new();
        for &(id, _) in &rows {
            if ids.last() != Some(&id) {
                ids.push(id);
            }
        }
        let index: HashMap<_, _> = ids.iter().enumerate().map(|(i, &id)| (id, i)).collect();
        let edges: HashSet<_> = rows
            .iter()
            .filter_map(|(from, to)| {
                to.map(|to| {
                    (
                        index[from],
                        *index.get(&to).expect("ordering edges name staged units"),
                    )
                })
            })
            .collect();
        let graph = DenseUsizeGraph::new(ids.len(), edges.iter().copied());
        let cancellation = CancellationToken::new();
        let mut budget = CfgAlgorithmBudget::default();
        let sccs = strongly_connected_components(
            &graph,
            &mut CfgAlgorithmRequest::new(&mut budget, &cancellation),
        )
        .expect("an unbounded uncancelled component pass completes")
        .components;
        let mut component_of = vec![0; ids.len()];
        for (component, members) in sccs.iter().enumerate() {
            for &member in members {
                component_of[member] = component;
            }
        }
        let mut dependencies = vec![HashSet::new(); sccs.len()];
        let mut consumers = vec![Vec::new(); sccs.len()];
        for &(from, to) in &edges {
            let (from, to) = (component_of[from], component_of[to]);
            if from != to && dependencies[from].insert(to) {
                consumers[to].push(from);
            }
        }
        let mut remaining: Vec<_> = dependencies.iter().map(HashSet::len).collect();
        let mut wave = vec![0_i64; sccs.len()];
        let mut ready: Vec<_> = remaining
            .iter()
            .enumerate()
            .filter_map(|(i, &n)| (n == 0).then_some(i))
            .collect();
        while let Some(dependency) = ready.pop() {
            for &consumer in &consumers[dependency] {
                wave[consumer] = wave[consumer].max(wave[dependency] + 1);
                remaining[consumer] -= 1;
                if remaining[consumer] == 0 {
                    ready.push(consumer);
                }
            }
        }
        assert!(
            remaining.iter().all(|&n| n == 0),
            "component condensation is acyclic"
        );
        let components = sccs
            .iter()
            .enumerate()
            .flat_map(|(component, members)| {
                let cyclic = members.len() > 1 || edges.contains(&(members[0], members[0]));
                let ids = &ids;
                members
                    .iter()
                    .map(move |&member| (ids[member], component as i64, cyclic))
            })
            .collect::<Vec<_>>();
        (components, wave)
    };
    drop(rows);
    let mut insert = conn.prepare("INSERT INTO temp.unit_schedule_components VALUES(?1,?2,?3)")?;
    for (unit, component, cyclic) in components {
        insert.execute(params![unit, component, cyclic])?;
    }
    let mut insert = conn.prepare("INSERT INTO temp.unit_schedule_waves VALUES(?1,?2)")?;
    for (component, wave) in waves.into_iter().enumerate() {
        insert.execute(params![component as i64, wave])?;
    }
    Ok(())
}

#[cfg(any(test, feature = "test-support"))]
pub(super) fn sql_pins() -> Vec<(&'static str, &'static str, usize)> {
    vec![
        ("unit_schedule_edges", EDGES_SQL, 0),
        ("unit_schedule_order", ORDER_SQL, 0),
    ]
}
