//! Test-only Rust summary reader SELECT pairs. Call before the corresponding INSERT,
//! on its connection with its TEMP inputs, using the driver's consumed frontier.
use rusqlite::{Connection, types::ValueRef};
use std::collections::BTreeMap;

pub const PUBLIC_SURFACE_BINDING_BLOCKED: &str =
    "needs the summary declaration-kind fact (#11173 M5 decision (i), migration 0425, separate PR)";

/// Every entry must come from the driver's selected/consumed summary at the
/// reader boundary. Never populate this with an unscoped current-version query.
#[derive(Debug)]
pub struct FrontierEntry {
    pub unit_key: [u8; 32],
    pub topology_id: i64,
    pub summary_id: i64,
}

/// SQLite storage classes are part of equality. Floating point values retain
/// their bits; NULL, integer zero, text and blobs remain different values.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Cell {
    Null,
    Integer(i64),
    Real(u64),
    Text(Vec<u8>),
    Blob(Vec<u8>),
}

impl std::fmt::Debug for Cell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Null => f.write_str("NULL"),
            Self::Integer(value) => f.debug_tuple("Integer").field(value).finish(),
            Self::Real(value) => f.debug_tuple("RealBits").field(value).finish(),
            Self::Text(value) => match std::str::from_utf8(value) {
                Ok(value) => f.debug_tuple("Text").field(&value).finish(),
                Err(_) => f.debug_tuple("TextBytes").field(value).finish(),
            },
            Self::Blob(value) => {
                f.write_str("Blob(")?;
                for byte in value {
                    write!(f, "{byte:02x}")?;
                }
                f.write_str(")")
            }
        }
    }
}

pub type Multiset = BTreeMap<Vec<Cell>, usize>;

pub fn values(conn: &Connection, sql: &str) -> rusqlite::Result<Multiset> {
    let mut statement = conn.prepare_cached(sql)?;
    assert!(statement.readonly(), "probe must execute a SELECT: {sql}");
    let columns = statement.column_count();
    let mut rows = statement.query([])?;
    let mut result = BTreeMap::new();
    while let Some(row) = rows.next()? {
        let row = (0..columns)
            .map(|i| {
                Ok(match row.get_ref(i)? {
                    ValueRef::Null => Cell::Null,
                    ValueRef::Integer(value) => Cell::Integer(value),
                    ValueRef::Real(value) => Cell::Real(value.to_bits()),
                    ValueRef::Text(value) => Cell::Text(value.to_vec()),
                    ValueRef::Blob(value) => Cell::Blob(value.to_vec()),
                })
            })
            .collect::<rusqlite::Result<Vec<_>>>()?;
        *result.entry(row).or_default() += 1;
    }
    Ok(result)
}

#[derive(Debug)]
pub struct Pair {
    pub name: &'static str,
    pub topology: String,
    pub summary: String,
}

// These are engine-owned SQL strings, not source code being parsed. Retaining
// their complete SELECT preserves UNION, window and anti-existence semantics.
fn select(sql: &str) -> &str {
    let start = sql.find("SELECT").expect("reader INSERT has a SELECT");
    let sql = sql[start..].trim().trim_end_matches(';').trim();
    sql.strip_suffix(" WHERE true ON CONFLICT DO NOTHING")
        .unwrap_or(sql)
}

/// Construct candidate forms without touching production statements. Frontier
/// tuples are scalar integer/blob values, so SQL quoting of source data is not
/// involved. All export and placement reads use the same explicit frontier.
pub fn pairs(frontier: &[FrontierEntry]) -> Vec<Pair> {
    let entries = frontier
        .iter()
        .map(|entry| {
            let key = entry
                .unit_key
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            format!("(x'{key}',{},{})", entry.topology_id, entry.summary_id)
        })
        .collect::<Vec<_>>();
    let frontier_sql = if entries.is_empty() {
        "SELECT NULL,NULL,NULL WHERE 0".to_owned()
    } else {
        format!("VALUES {}", entries.join(","))
    };
    let cte = format!(
        r#"WITH
probe_frontier(unit_key,topology_id,summary_id) AS ({frontier_sql}),
probe_containers AS (
 SELECT f.topology_id, CASE c.container_path WHEN '' THEN 'crate' ELSE c.container_path END container_path
 FROM probe_frontier f JOIN resolution_unit_summary_containers c ON c.summary_id=f.summary_id
),
probe_routes AS (
 SELECT f.topology_id,r.module_path,r.bound_name,r.target_unit_key target_crate_key,
 r.target_module_path,r.target_name,r.visibility,r.restricted_module_path
 FROM probe_frontier f JOIN rust_resolution_unit_summary_reexport_routes r ON r.summary_id=f.summary_id
),
probe_globs AS (
 SELECT f.topology_id,r.module_path,r.target_unit_key target_crate_key,
 r.target_module_path,r.visibility,r.restricted_module_path
 FROM probe_frontier f JOIN rust_resolution_unit_summary_glob_reexport_routes r ON r.summary_id=f.summary_id
),
probe_exports AS (
 SELECT f.topology_id,e.module_path,e.namespace,e.name,e.origin,e.visibility,
        e.restricted_module_path,m.blob_id AS declaration_blob_id,e.declaration_site,
        e.target_unit_key AS target_crate_key,e.target_module_path,e.target_name
 FROM probe_frontier f
 JOIN rust_resolution_unit_summary_exports e ON e.summary_id=f.summary_id
 LEFT JOIN resolution_unit_summary_members m
   ON m.summary_id=e.summary_id AND m.member_ordinal=e.declaration_member_ordinal
),
probe_sources AS (
 SELECT f.topology_id,
        CASE p.container_path WHEN '' THEN 'crate' ELSE p.container_path END AS container_path,
        m.blob_id,m.rel_path
 FROM probe_frontier f
 JOIN resolution_unit_summary_placements p ON p.summary_id=f.summary_id
 JOIN resolution_unit_summary_members m
   ON m.summary_id=p.summary_id AND m.member_ordinal=p.member_ordinal
)
"#
    );
    let statements = [
        ("FOREIGN_SQL", super::binding_relation::FOREIGN_SQL),
        (
            "FOREIGN_CONFLICT_SQL",
            super::binding_relation::FOREIGN_CONFLICT_SQL,
        ),
        (
            "CANONICAL_DEPENDENCY_DECLARATIONS_SQL",
            super::CANONICAL_DEPENDENCY_DECLARATIONS_SQL,
        ),
        ("IMPL_DECLARATIONS_SQL", super::IMPL_DECLARATIONS_SQL),
        (
            "PUBLIC_SURFACE_LOOKUP_SQL",
            super::PUBLIC_SURFACE_LOOKUP_SQL,
        ),
        (
            "PUBLIC_SURFACE_ALIASES_SQL",
            super::PUBLIC_SURFACE_ALIASES_SQL.as_str(),
        ),
        (
            "PUBLIC_SURFACE_LOOKUP_ALIASES_SQL",
            super::PUBLIC_SURFACE_LOOKUP_ALIASES_SQL.as_str(),
        ),
        ("MACRO_USE_IMPORTS_SQL", super::MACRO_USE_IMPORTS_SQL),
    ];
    let mut forms = statements
        .into_iter()
        .map(|(name, sql)| (name, select(sql).to_owned()))
        .collect::<Vec<_>>();
    let full = select(super::IMPL_DECLARATIONS_SQL);
    let begin = full.find("WITH RECURSIVE").unwrap();
    let end = full.rfind("SELECT blob_id, relation_key, module_path, side, declaration_blob_id, declaration_site,").unwrap();
    let ctes = &full[begin..end];
    forms.push(("IMPL_FOREIGN_PLACEMENTS_PRE_UNION_SQL", format!("{} SELECT * FROM placements WHERE declaring_unit_key<>(SELECT crate_key FROM cr_identity)", ctes.replace("AND declared.declaration_site=chase.declaration_site\n  UNION", "AND declared.declaration_site=chase.declaration_site\n  UNION ALL"))));
    forms.push(("IMPL_FOREIGN_PLACEMENT_COUNTS_SQL",format!("{ctes} SELECT * FROM reached WHERE declaring_unit_key<>(SELECT crate_key FROM cr_identity)")));
    forms.push(("IMPL_FOREIGN_DECLARATION_ANTI_EXISTENCE_SQL",format!("{ctes} SELECT chase.*, NOT EXISTS(SELECT 1 FROM cr_foreign AS dependency CROSS JOIN rust_crate_exports AS declared ON declared.topology_id=dependency.topology_id AND declared.module_path=chase.at_module AND declared.namespace='type' AND declared.name=chase.at_name WHERE dependency.crate_key=chase.crate_key AND declared.origin='declaration') FROM chase WHERE chase.crate_key<>(SELECT crate_key FROM cr_identity)")));
    forms.push(("IMPL_FOREIGN_PLACEMENT_INVENTORY_SQL", "SELECT DISTINCT dependency.crate_key AS unit_key,source.container_path,source.blob_id,source.rel_path FROM cr_foreign dependency JOIN rust_crate_container_sources source ON source.topology_id=dependency.topology_id".to_owned()));
    forms.extend([
        ("CONTAINERS_SQL",select(super::CONTAINERS_SQL).to_owned()),
        ("FOREIGN_REEXPORT_STEPS_SQL",select(super::FOREIGN_REEXPORT_STEPS_SQL).to_owned()),
        ("FOREIGN_ROOT_SQL",select(super::binding_relation::FOREIGN_ROOT_SQL).to_owned()),
        ("FOREIGN_GLOB_STEPS_SQL",select(super::FOREIGN_GLOB_STEPS_SQL).to_owned()),
        ("PUBLIC_SURFACE_GLOBS_SQL",select(super::PUBLIC_SURFACE_GLOBS_SQL).to_owned()),
        ("PUBLIC_SURFACE_ALIASES_ROUTES_SQL",select(&super::PUBLIC_SURFACE_ALIASES_SQL).to_owned()),
        ("PUBLIC_SURFACE_LOOKUP_ALIASES_ROUTES_SQL",select(&super::PUBLIC_SURFACE_LOOKUP_ALIASES_SQL).to_owned()),
        ("ALL_PLACEMENTS","SELECT f.crate_key,s.container_path,s.blob_id,s.rel_path FROM cr_foreign f JOIN rust_crate_container_sources s ON s.topology_id=f.topology_id".to_owned()),
    ]);
    forms
        .into_iter()
        .map(|(name, topology)| {
            // Keep alias export and route moves independently observable: two
            // wrong projections must not be able to cancel each other out.
            let candidate = match name {
                "CONTAINERS_SQL"
                | "FOREIGN_REEXPORT_STEPS_SQL"
                | "FOREIGN_ROOT_SQL"
                | "FOREIGN_GLOB_STEPS_SQL"
                | "PUBLIC_SURFACE_GLOBS_SQL"
                | "PUBLIC_SURFACE_ALIASES_ROUTES_SQL"
                | "PUBLIC_SURFACE_LOOKUP_ALIASES_ROUTES_SQL"
                | "ALL_PLACEMENTS" => topology
                    .replace("rust_crate_containers", "probe_containers")
                    .replace("rust_crate_reexport_routes", "probe_routes")
                    .replace("rust_crate_glob_reexport_routes", "probe_globs")
                    .replace("rust_crate_container_sources", "probe_sources"),
                _ => topology
                    .replace("rust_crate_exports", "probe_exports")
                    .replace("rust_crate_container_sources", "probe_sources"),
            };
            Pair {
                name,
                topology,
                summary: format!("{cte} SELECT * FROM ({candidate})"),
            }
        })
        .collect()
}

/// Unmatched rows retain their multiplicity and values for evidence-based
/// classification. Do not classify a difference solely from its reader name.
#[derive(Debug)]
pub struct Comparison {
    pub reader: &'static str,
    pub topology_rows: usize,
    pub summary_rows: usize,
    pub topology_only: Multiset,
    pub summary_only: Multiset,
    pub categories: BTreeMap<&'static str, usize>,
    pub unexplained_topology: Multiset,
    pub unexplained_summary: Multiset,
    pub consumer: Option<String>,
    pub frontier: Vec<([u8; 32], i64, i64)>,
    pub topology_destination: Option<Destination>,
    pub summary_destination: Option<Destination>,
    pub unexplained_destination: bool,
}

impl Pair {
    pub fn compare(&self, conn: &Connection) -> rusqlite::Result<Comparison> {
        let topology = values(conn, &self.topology)?;
        let summary = values(conn, &self.summary)?;
        let topology_rows = topology.values().sum();
        let summary_rows = summary.values().sum();
        let (topology_only, summary_only) = difference(topology, summary);
        Ok(Comparison {
            reader: self.name,
            topology_rows,
            summary_rows,
            unexplained_topology: topology_only.clone(),
            unexplained_summary: summary_only.clone(),
            topology_only,
            summary_only,
            categories: BTreeMap::new(),
            consumer: None,
            frontier: Vec::new(),
            topology_destination: None,
            summary_destination: None,
            unexplained_destination: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::store::AnalyzerStore;

    #[test]
    fn summary_reader_pairs_prepare_against_store_schema() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().unwrap();
        crate::analyzer::store::planner_statistics::pinned_plans::prepare_pin_context(&conn);
        for pair in pairs(&[]) {
            conn.prepare_cached(&pair.topology)
                .unwrap_or_else(|error| panic!("{} topology: {error}", pair.name));
            conn.prepare_cached(&pair.summary)
                .unwrap_or_else(|error| panic!("{} summary: {error}", pair.name));
        }
    }

    #[test]
    fn summary_reader_multisets_keep_storage_classes_and_repeated_rows() {
        let conn = Connection::open_in_memory().unwrap();
        let pair = Pair {
            name: "typed-multiplicity",
            topology: "SELECT NULL UNION ALL SELECT 0 UNION ALL SELECT 0 UNION ALL SELECT x'30' UNION ALL SELECT '0'".into(),
            summary: "SELECT NULL UNION ALL SELECT 0 UNION ALL SELECT x'30' UNION ALL SELECT '0'".into(),
        };
        let comparison = pair.compare(&conn).unwrap();
        assert_eq!(comparison.topology_rows, 5);
        assert_eq!(comparison.summary_rows, 4);
        assert_eq!(
            comparison.topology_only,
            BTreeMap::from([(vec![Cell::Integer(0)], 1)])
        );
        assert!(comparison.summary_only.is_empty());
    }
}

use rusqlite::{params_from_iter, types::Value};
use std::sync::{LazyLock, Mutex};

static CAPTURES: LazyLock<Mutex<BTreeMap<String, Vec<Boundary>>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

fn database_key(conn: &Connection) -> String {
    let path = conn.path().expect("capture requires a file-backed store");
    assert!(!path.is_empty(), "capture requires a file-backed store");
    path.to_owned()
}

#[derive(Clone)]
struct TableInput {
    name: String,
    columns: Vec<String>,
    rows: Vec<Vec<Value>>,
}
struct Boundary {
    reader: &'static str,
    consumer: String,
    inputs: Vec<TableInput>,
    topology: Multiset,
    foreign: Vec<([u8; 32], i64)>,
    extra: BTreeMap<&'static str, Multiset>,
}

/// Arm only this store. Worker connections open the same main database file,
/// including ephemeral stores, whose backing is a delete-on-drop temp file.
pub fn begin_capture(conn: &Connection) {
    let mut captures = CAPTURES.lock().unwrap();
    let key = database_key(conn);
    assert!(
        !captures.contains_key(&key),
        "overlapping equality captures"
    );
    captures.insert(key, Vec::new());
}

fn quote(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

pub(super) fn capture(conn: &Connection, statement: &str) -> rusqlite::Result<()> {
    let key = database_key(conn);
    if !CAPTURES.lock().unwrap().contains_key(&key) {
        return Ok(());
    }
    let Some(pair) = pairs(&[])
        .into_iter()
        .find(|pair| pair.topology == select(statement))
    else {
        return Ok(());
    };
    let names = conn.prepare_cached("SELECT name FROM temp.sqlite_schema WHERE type='table' AND substr(name,1,3)='cr_' ORDER BY name")?
        .query_map([], |row| row.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
    let mut inputs = Vec::new();
    for name in names {
        let columns = conn
            .prepare_cached(&format!("PRAGMA temp.table_info({})", quote(&name)))?
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let projection = columns
            .iter()
            .map(|name| quote(name))
            .collect::<Vec<_>>()
            .join(",");
        let rows = conn
            .prepare_cached(&format!("SELECT {projection} FROM temp.{}", quote(&name)))?
            .query_map([], |row| {
                (0..columns.len())
                    .map(|i| row.get(i))
                    .collect::<rusqlite::Result<Vec<Value>>>()
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        inputs.push(TableInput {
            name,
            columns,
            rows,
        });
    }
    let foreign = conn
        .prepare_cached("SELECT crate_key,topology_id FROM cr_foreign ORDER BY crate_key")?
        .query_map([], |row| {
            let key: Vec<u8> = row.get(0)?;
            Ok((key.try_into().expect("crate key is 32 bytes"), row.get(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let topology = values(conn, &pair.topology)?;
    let mut extra = BTreeMap::new();
    for auxiliary in pairs(&[]).into_iter().filter(|auxiliary| match pair.name {
        "IMPL_DECLARATIONS_SQL" => auxiliary.name.starts_with("IMPL_FOREIGN_"),
        "CONTAINERS_SQL" => auxiliary.name == "ALL_PLACEMENTS",
        "PUBLIC_SURFACE_ALIASES_SQL" => auxiliary.name == "PUBLIC_SURFACE_ALIASES_ROUTES_SQL",
        "PUBLIC_SURFACE_LOOKUP_ALIASES_SQL" => {
            auxiliary.name == "PUBLIC_SURFACE_LOOKUP_ALIASES_ROUTES_SQL"
        }
        _ => false,
    }) {
        extra.insert(auxiliary.name, values(conn, &auxiliary.topology)?);
    }
    let boundary = Boundary {
        reader: pair.name,
        consumer: conn
            .prepare_cached("SELECT hex(crate_key) FROM cr_identity")?
            .query_row([], |row| row.get(0))?,
        inputs,
        topology,
        foreign,
        extra,
    };
    if let Some(boundaries) = CAPTURES.lock().unwrap().get_mut(&key) {
        boundaries.push(boundary);
    }
    Ok(())
}

/// Replay captured TEMP inputs on the same fixture's store, with the real live
/// summary selector and the exact captured topology checked for every pairing.
/// The fixture must not edit or reconcile between capture and replay. Original
/// topology values are checked again, so a later publication cannot silently
/// replace a captured frontier. The savepoint restores all TEMP changes.
pub fn replay(conn: &Connection) -> crate::analyzer::store::Result<Vec<Comparison>> {
    use crate::analyzer::store::rust_unit_summaries::RustUnitSummaries;
    use crate::analyzer::store::unit_summaries::consume_unit;
    use crate::analyzer::store::{GenerationId, WorkspaceId, WorkspaceSnapshotId};
    let boundaries = CAPTURES
        .lock()
        .unwrap()
        .remove(&database_key(conn))
        .expect("store capture armed");
    assert!(!boundaries.is_empty(), "no reader boundaries captured");
    let snapshot = conn
        .prepare_cached(
            "SELECT workspace_id,generation,revision FROM workspace_heads WHERE lang='rust'",
        )?
        .query_row([], |row| {
            Ok(WorkspaceSnapshotId {
                workspace_id: WorkspaceId(row.get(0)?),
                lang: "rust".into(),
                generation: GenerationId(row.get(1)?),
                revision: row.get(2)?,
            })
        })?;
    let epoch: String = conn
        .prepare_cached("SELECT producer_epoch FROM resolution_producer_epochs WHERE lang='rust'")?
        .query_row([], |row| row.get(0))?;
    crate::analyzer::store::planner_statistics::pinned_plans::prepare_pin_context(conn);
    // Publication already ran the topology oracle. Replay must also accept
    // deliberately perturbed summary rows so the probe can reject them itself.
    conn.execute_batch("SAVEPOINT export_equality_replay")?;
    let result = (|| {
        let mut comparisons = Vec::new();
        for boundary in boundaries {
            conn.prepare_cached("DELETE FROM temp.unit_summary_order")?
                .execute([])?;
            for (ordinal, (unit_key, _)) in boundary.foreign.iter().enumerate() {
                conn.prepare_cached("INSERT INTO temp.unit_summary_order(ordinal,unit_id,unit_key) VALUES(?1,?1,?2)")?.execute(rusqlite::params![ordinal as i64,unit_key.as_slice()])?;
            }
            let mut frontier = Vec::new();
            for (unit_key, topology_id) in boundary.foreign {
                let selected =
                    consume_unit(conn, &snapshot, &RustUnitSummaries, &epoch, &unit_key)?;
                let Some((summary_id, _)) = selected else {
                    panic!(
                        "{}: captured dependency {unit_key:?}, topology {topology_id} has no live summary at {snapshot:?}",
                        boundary.reader
                    );
                };
                let matching: bool = conn.prepare_cached("SELECT EXISTS(SELECT 1 FROM rust_resolution_unit_summary_versions WHERE summary_id=?1 AND topology_id=?2 AND unit_key=?3)")?.query_row( rusqlite::params![summary_id,topology_id,unit_key.as_slice()], |row| row.get(0))?;
                assert!(
                    matching,
                    "{}: selected summary {summary_id} does not describe captured topology {topology_id} of {unit_key:?}",
                    boundary.reader
                );
                frontier.push(FrontierEntry {
                    unit_key,
                    topology_id,
                    summary_id,
                });
            }
            // Restore captured rows exactly. Replaying notification triggers here
            // would populate dirty queues before their captured rows are restored
            // (#12898). The outer savepoint also restores triggers on failure.
            let triggers = conn.prepare_cached("SELECT name,sql FROM temp.sqlite_schema WHERE type='trigger' AND substr(tbl_name,1,3)='cr_' ORDER BY name")?
                .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            for (name, _) in &triggers {
                conn.execute_batch(&format!("DROP TRIGGER temp.{}", quote(name)))?;
            }
            // Clear all inputs before restoring any, preserving cross-table
            // constraints and the schema supplied by the production preparer.
            for input in &boundary.inputs {
                conn.execute(&format!("DELETE FROM temp.{}", quote(&input.name)), [])?;
            }
            for input in boundary.inputs {
                let columns = input
                    .columns
                    .iter()
                    .map(|name| quote(name))
                    .collect::<Vec<_>>()
                    .join(",");
                let binds = vec!["?"; input.columns.len()].join(",");
                let mut insert = conn.prepare_cached(&format!(
                    "INSERT INTO temp.{} ({columns}) VALUES ({binds})",
                    quote(&input.name)
                ))?;
                for row in input.rows {
                    insert.execute(params_from_iter(row))?;
                }
            }
            for (_, sql) in triggers {
                // sqlite_schema omits TEMP from the recorded CREATE statement.
                conn.execute_batch(&sql.replacen("CREATE TRIGGER", "CREATE TEMP TRIGGER", 1))?;
            }
            let pair = pairs(&frontier)
                .into_iter()
                .find(|pair| pair.name == boundary.reader)
                .unwrap();
            assert_eq!(
                values(conn, &pair.topology)?,
                boundary.topology,
                "{}: reconstructed TEMP inputs changed the topology reader",
                pair.name
            );
            let mut comparison = pair.compare(conn)?;
            comparison.consumer = Some(boundary.consumer.clone());
            comparison.frontier = frontier
                .iter()
                .map(|entry| (entry.unit_key, entry.topology_id, entry.summary_id))
                .collect();
            explain(conn, &pair, &mut comparison)?;
            comparisons.push(comparison);
            for (name, original) in boundary.extra {
                let pair = pairs(&frontier)
                    .into_iter()
                    .find(|pair| pair.name == name)
                    .unwrap();
                assert_eq!(
                    values(conn, &pair.topology)?,
                    original,
                    "{name}: reconstructed impl subreader changed"
                );
                let mut comparison = pair.compare(conn)?;
                comparison.consumer = Some(boundary.consumer.clone());
                comparison.frontier = frontier
                    .iter()
                    .map(|entry| (entry.unit_key, entry.topology_id, entry.summary_id))
                    .collect();
                explain(conn, &pair, &mut comparison)?;
                comparisons.push(comparison);
            }
        }
        Ok(comparisons)
    })();
    conn.execute_batch("ROLLBACK TO export_equality_replay; RELEASE export_equality_replay")?;
    result
}

fn difference(mut left: Multiset, mut right: Multiset) -> (Multiset, Multiset) {
    for (row, count) in &mut left {
        if let Some(other) = right.get_mut(row) {
            let common = (*count).min(*other);
            *count -= common;
            *other -= common;
        }
    }
    left.retain(|_, count| *count != 0);
    right.retain(|_, count| *count != 0);
    (left, right)
}

// These explanatory projections do not change the candidate or its equality
// result. They show exactly which documented representation changes account
// for its unmatched rows, including anti-existence effects. Unknown changes to
// names, visibility, multiplicity or declaration coordinates remain failures.
fn explain(conn: &Connection, pair: &Pair, comparison: &mut Comparison) -> rusqlite::Result<()> {
    const FIELDS: [&str; 12] = [
        "topology_id",
        "module_path",
        "namespace",
        "name",
        "origin",
        "visibility",
        "restricted_module_path",
        "declaration_blob_id",
        "declaration_site",
        "target_crate_key",
        "target_module_path",
        "target_name",
    ];
    let expected = values(conn, &pair.topology)?;
    let mut previous = values(conn, &pair.summary)?;
    let mut projection = FIELDS
        .iter()
        .map(|field| format!("e.{field}"))
        .collect::<Vec<_>>();
    let matching = "t.topology_id=e.topology_id AND t.module_path=e.module_path AND t.namespace=e.namespace AND t.name=e.name AND t.origin=e.origin";
    let join = format!(
        "FROM probe_raw_exports e LEFT JOIN rust_crate_exports t ON {matching} AND ((t.target_crate_key IS e.target_crate_key AND t.target_module_path IS e.target_module_path AND t.target_name IS e.target_name) OR (NOT EXISTS(SELECT 1 FROM rust_crate_exports t WHERE {matching} AND t.target_crate_key IS e.target_crate_key AND t.target_module_path IS e.target_module_path AND t.target_name IS e.target_name) AND (SELECT count(*) FROM rust_crate_exports t WHERE {matching})=1))"
    );
    // Only attribute a declaration-coordinate change to representative choice
    // when the selected member is provably the lowest of multiple placements
    // carrying the topology declaration's semantic identity at the same site.
    let identity_match = "((old_catalog.shared_identity IS NOT NULL AND candidate_catalog.shared_identity=old_catalog.shared_identity) OR (old_catalog.shared_identity IS NULL AND candidate_catalog.shared_identity IS NULL AND candidate_catalog.identity_digest=old_catalog.identity_digest))";
    let candidates = format!(
        "FROM resolution_unit_summary_placements placement JOIN resolution_unit_summary_members member ON member.summary_id=placement.summary_id AND member.member_ordinal=placement.member_ordinal JOIN resolution_semantic_sites candidate_site ON candidate_site.blob_id=member.blob_id AND candidate_site.semantic_role='definition' AND candidate_site.source_site=e.declaration_site JOIN resolution_semantic_catalog candidate_catalog ON candidate_catalog.blob_id=candidate_site.blob_id AND candidate_catalog.local_key=candidate_site.semantic_key WHERE placement.summary_id=f.summary_id AND (CASE placement.container_path WHEN '' THEN 'crate' ELSE placement.container_path END)=e.module_path AND {identity_match}"
    );
    let duplicate_witness = format!(
        "EXISTS(SELECT 1 FROM probe_frontier f JOIN rust_resolution_unit_summary_exports selected ON selected.summary_id=f.summary_id AND selected.module_path=e.module_path AND selected.namespace=e.namespace AND selected.name=e.name AND selected.origin='declaration' JOIN resolution_semantic_sites old_site ON old_site.blob_id=t.declaration_blob_id AND old_site.source_site=t.declaration_site AND old_site.semantic_role='definition' JOIN resolution_semantic_catalog old_catalog ON old_catalog.blob_id=old_site.blob_id AND old_catalog.local_key=old_site.semantic_key WHERE f.topology_id=e.topology_id AND selected.declaration_site=e.declaration_site AND selected.declaration_member_ordinal=(SELECT min(placement.member_ordinal) {candidates}) AND (SELECT count(DISTINCT placement.member_ordinal) {candidates})>1)"
    );
    // Follow each endpoint independently. Only a shared final declaration
    // coordinate proves normalization; matching alias names alone proves nothing.
    let endpoint_witness = "EXISTS(WITH RECURSIVE old_endpoint(unit_key,module_path,namespace,name) AS (SELECT t.target_crate_key,t.target_module_path,t.namespace,t.target_name UNION SELECT x.target_crate_key,x.target_module_path,x.namespace,x.target_name FROM old_endpoint o JOIN probe_frontier f ON f.unit_key=o.unit_key JOIN rust_crate_exports x ON x.topology_id=f.topology_id AND x.module_path=o.module_path AND x.namespace=o.namespace AND x.name=o.name WHERE x.origin<>'declaration'), new_endpoint(unit_key,module_path,namespace,name) AS (SELECT e.target_crate_key,e.target_module_path,e.namespace,e.target_name UNION SELECT x.target_unit_key,x.target_module_path,x.namespace,x.target_name FROM new_endpoint n JOIN probe_frontier f ON f.unit_key=n.unit_key JOIN rust_resolution_unit_summary_exports x ON x.summary_id=f.summary_id AND x.module_path=n.module_path AND x.namespace=n.namespace AND x.name=n.name WHERE x.origin<>'declaration') SELECT 1 FROM old_endpoint o JOIN new_endpoint n USING(unit_key,module_path,namespace,name) JOIN probe_frontier f ON f.unit_key=o.unit_key JOIN rust_crate_exports d ON d.topology_id=f.topology_id AND d.module_path=o.module_path AND d.namespace=o.namespace AND d.name=o.name AND d.origin='declaration' JOIN rust_resolution_unit_summary_exports s ON s.summary_id=f.summary_id AND s.module_path=n.module_path AND s.namespace=n.namespace AND s.name=n.name AND s.origin='declaration')";
    let mut extra = String::new();
    let mut final_diagnostic = pair.summary.clone();
    for category in [
        "NULL declaration targets",
        "NULL alias coordinates",
        "alias endpoint normalization",
        "dropped unprovable aliases",
        "lowest member ordinal among duplicate placements",
    ] {
        match category {
            "NULL declaration targets" => {
                for index in 9..12 {
                    projection[index] = format!(
                        "CASE WHEN e.origin='declaration' AND e.target_crate_key IS NULL AND e.target_module_path IS NULL AND e.target_name IS NULL AND t.topology_id IS NOT NULL THEN t.{} ELSE {} END",
                        FIELDS[index], projection[index]
                    );
                }
            }
            "NULL alias coordinates" => {
                for index in 7..9 {
                    projection[index] = format!(
                        "CASE WHEN e.origin<>'declaration' AND e.declaration_blob_id IS NULL AND e.declaration_site IS NULL AND t.topology_id IS NOT NULL THEN t.{} ELSE {} END",
                        FIELDS[index], projection[index]
                    );
                }
            }
            "alias endpoint normalization" => {
                for index in 9..12 {
                    projection[index] = format!(
                        "CASE WHEN e.origin<>'declaration' AND t.topology_id IS NOT NULL AND {endpoint_witness} THEN t.{} ELSE {} END",
                        FIELDS[index], projection[index]
                    );
                }
            }
            "dropped unprovable aliases" => {
                extra = format!(
                    "UNION ALL SELECT {} FROM rust_crate_exports t JOIN probe_frontier f ON f.topology_id=t.topology_id WHERE t.origin<>'declaration' AND NOT EXISTS(SELECT 1 FROM probe_raw_exports e WHERE {matching}) AND NOT EXISTS(SELECT 1 FROM probe_frontier reached JOIN rust_resolution_unit_summary_exports endpoint ON endpoint.summary_id=reached.summary_id WHERE reached.unit_key=t.target_crate_key AND endpoint.module_path=t.target_module_path AND endpoint.namespace=t.namespace AND endpoint.name=t.target_name)",
                    FIELDS
                        .iter()
                        .map(|field| format!("t.{field}"))
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
            "lowest member ordinal among duplicate placements" => {
                for index in 7..9 {
                    projection[index] = format!(
                        "CASE WHEN e.origin='declaration' AND t.topology_id IS NOT NULL AND (e.declaration_blob_id IS NOT t.declaration_blob_id OR e.declaration_site IS NOT t.declaration_site) AND {duplicate_witness} THEN t.{} ELSE {} END",
                        FIELDS[index], projection[index]
                    );
                }
            }
            _ => unreachable!(),
        }
        let columns = projection
            .iter()
            .zip(FIELDS)
            .map(|(expression, name)| format!("{expression} AS {name}"))
            .collect::<Vec<_>>()
            .join(",");
        let diagnostic = pair
            .summary
            .replace("probe_exports AS (", "probe_raw_exports AS (")
            .replace(
                "probe_sources AS (",
                &format!("probe_exports AS (SELECT {columns} {join} {extra}),\nprobe_sources AS ("),
            );
        let next = values(conn, &diagnostic)?;
        final_diagnostic = diagnostic;
        let (removed, added) = difference(previous, next.clone());
        comparison.categories.insert(
            category,
            removed.values().sum::<usize>() + added.values().sum::<usize>(),
        );
        previous = next;
    }
    (
        comparison.unexplained_topology,
        comparison.unexplained_summary,
    ) = difference(expected, previous);
    if let Some(destination) = destination(pair.name) {
        let topology = apply_destination(conn, &pair.topology, destination)?;
        assert!(
            matches!(topology, Destination::Rows(_)),
            "production INSERT failed at replay: {topology:?}"
        );
        let summary = apply_destination(conn, &pair.summary, destination)?;
        let explained = apply_destination(conn, &final_diagnostic, destination)?;
        comparison.unexplained_destination = topology != explained;
        comparison.topology_destination = Some(topology);
        comparison.summary_destination = Some(summary);
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub enum Destination {
    Rows(Multiset),
    Rejected(String),
}

fn destination(reader: &str) -> Option<(&'static str, &'static str)> {
    match reader {
        "FOREIGN_SQL" | "FOREIGN_CONFLICT_SQL" | "FOREIGN_ROOT_SQL" => {
            Some(("cr_binding_targets", "INSERT INTO"))
        }
        "CANONICAL_DEPENDENCY_DECLARATIONS_SQL" => Some(("cr_exports", "INSERT INTO")),
        "IMPL_DECLARATIONS_SQL" => Some(("cr_impl_declarations", "INSERT INTO")),
        "PUBLIC_SURFACE_LOOKUP_SQL"
        | "PUBLIC_SURFACE_LOOKUP_ALIASES_SQL"
        | "PUBLIC_SURFACE_LOOKUP_ALIASES_ROUTES_SQL" => Some(("cr_surface_lookup", "INSERT INTO")),
        "PUBLIC_SURFACE_ALIASES_SQL" | "PUBLIC_SURFACE_ALIASES_ROUTES_SQL" => {
            Some(("cr_surface_aliases", "INSERT INTO"))
        }
        "CONTAINERS_SQL" => Some(("cr_containers_all", "INSERT INTO")),
        "FOREIGN_REEXPORT_STEPS_SQL" => Some(("cr_reexport_steps", "INSERT INTO")),
        "FOREIGN_GLOB_STEPS_SQL" => Some(("cr_glob_steps", "INSERT INTO")),
        "PUBLIC_SURFACE_GLOBS_SQL" => Some(("cr_surface_requests", "INSERT INTO")),
        "MACRO_USE_IMPORTS_SQL" => Some(("cr_imports", "INSERT OR IGNORE INTO")),
        _ => None,
    }
}

// Each leg applies the actual INSERT conflict policy to the same captured
// destination, then rolls it back. A raw candidate may violate NOT NULL: keep
// that error as evidence, and require the documented explanatory leg to match.
fn apply_destination(
    conn: &Connection,
    projection: &str,
    (table, insert): (&str, &str),
) -> rusqlite::Result<Destination> {
    conn.execute_batch("SAVEPOINT export_probe_destination")?;
    let suffix = if insert == "INSERT INTO" {
        " WHERE true ON CONFLICT DO NOTHING"
    } else {
        ""
    };
    let result = (|| match conn.execute(
        &format!("{insert} {table} SELECT * FROM ({projection}){suffix}"),
        [],
    ) {
        Ok(_) => Ok(Destination::Rows(values(
            conn,
            &format!("SELECT * FROM {table}"),
        )?)),
        Err(error) => Ok(Destination::Rejected(error.to_string())),
    })();
    conn.execute_batch("ROLLBACK TO export_probe_destination; RELEASE export_probe_destination")?;
    result
}
