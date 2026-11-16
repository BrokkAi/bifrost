//! Schema-derived liveness for blobs and their cascade-owned facts.

use std::collections::{BTreeMap, HashMap};

use rusqlite::Connection;

#[derive(Debug)]
struct ForeignKey {
    child: String,
    id: i64,
    parent: String,
    action: String,
    columns: Vec<(String, String)>,
}

fn quote(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

// A path lists cascade edges from a descendant back to its collectable owner. Iterative
// construction bounds stack use even when a future schema has deep ownership.
struct RootPlan {
    collectable: &'static str,
    statements: Vec<(String, String)>,
    prune: Option<String>,
    #[cfg(test)]
    certificates: BTreeMap<(String, i64), String>,
}

fn foreign_keys(conn: &Connection) -> rusqlite::Result<Vec<ForeignKey>> {
    let mut query = conn.prepare(
        "SELECT s.name, f.id, f.\"table\", f.on_delete, f.\"from\", f.\"to\"
         FROM sqlite_schema s JOIN pragma_foreign_key_list(s.name) f
         WHERE s.type = 'table' ORDER BY s.name, f.id, f.seq",
    )?;
    let mut keys: Vec<ForeignKey> = Vec::new();
    for row in query.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, Option<String>>(5)?,
        ))
    })? {
        let (child, id, parent, action, from, to) = row?;
        if keys.last().is_none_or(|k| k.child != child || k.id != id) {
            keys.push(ForeignKey {
                child,
                id,
                parent,
                action,
                columns: Vec::new(),
            });
        }
        let key = keys.last_mut().expect("inserted foreign key");
        // SQLite permits omitted parent columns, meaning its primary key.
        let to = match to {
            Some(to) => to,
            None => conn.query_row(
                "SELECT name FROM pragma_table_info(?1) WHERE pk = ?2",
                (&key.parent, key.columns.len() + 1),
                |r| r.get(0),
            )?,
        };
        key.columns.push((from, to));
    }
    Ok(keys)
}

fn root_plan(
    keys: &[ForeignKey],
    root: &'static str,
    root_key: &str,
    prune: Option<&str>,
) -> RootPlan {
    let mut paths: HashMap<String, Vec<usize>> = HashMap::from([(root.into(), vec![])]);
    loop {
        let mut changed = false;
        for (i, key) in keys.iter().enumerate() {
            if key.action == "CASCADE"
                && !paths.contains_key(&key.child)
                && let Some(parent_path) = paths.get(&key.parent)
            {
                let mut path = vec![i];
                path.extend(parent_path);
                paths.insert(key.child.clone(), path);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    // Where possible, carry ownership through FK column equalities without
    // reading ancestors. This also certifies same-owner internal references.
    let owner_column = |table: &str| -> Option<String> {
        let mut column = root_key.to_string();
        for &edge in paths.get(table)?.iter().rev() {
            column = keys[edge]
                .columns
                .iter()
                .find(|(_, to)| *to == column)?
                .0
                .clone();
        }
        Some(column)
    };
    let mut sources: BTreeMap<String, Vec<String>> = BTreeMap::new();
    #[cfg(test)]
    let mut certificates = BTreeMap::new();
    for key in keys {
        let Some(parent_path) = paths.get(&key.parent) else {
            continue;
        };
        if key.action == "CASCADE" {
            #[cfg(test)]
            certificates.insert((key.child.clone(), key.id), "cascade-owned".into());
            continue;
        }
        let parent_column = owner_column(&key.parent);
        let child_column = owner_column(&key.child);
        if let (Some(child), Some(parent)) = (&child_column, &parent_column)
            && key.columns.contains(&(child.clone(), parent.clone()))
        {
            #[cfg(test)]
            certificates.insert(
                (key.child.clone(), key.id),
                format!("same-owner: {child} = {parent}"),
            );
            continue;
        }
        let marker = format!("/* {} FK {} */", quote(&key.child), key.id);
        #[cfg(test)]
        certificates.insert((key.child.clone(), key.id), marker.clone());
        let mut joins = String::new();
        let target = if key.parent == root && key.columns.iter().any(|(_, to)| to == root_key) {
            // FK validity proves the referenced owner exists; avoid a join.
            format!(
                "source.{}",
                quote(
                    &key.columns
                        .iter()
                        .find(|(_, to)| to == root_key)
                        .expect("root FK includes its key")
                        .0
                )
            )
        } else {
            joins.push_str(&format!(
                " JOIN {} AS target ON {}",
                quote(&key.parent),
                equalities(&key.columns, "source", "target")
            ));
            if let Some(column) = parent_column {
                format!("target.{}", quote(&column))
            } else {
                let (ancestry, owner) = ancestor_joins(keys, parent_path, "target", "target_owner");
                joins.push_str(&ancestry);
                format!("{owner}.{}", quote(root_key))
            }
        };
        let owned = if let Some(column) = child_column {
            format!(" AND source.{} IS NOT {target}", quote(&column))
        } else if let Some(path) = paths.get(&key.child) {
            let (ancestry, owner) = ancestor_joins(keys, path, "source", "source_owner");
            // Each ancestor join starts from this source row, never scans the
            // referencing relation again. LEFT joins preserve nullable owners.
            joins.push_str(&ancestry.replace(" JOIN ", " LEFT JOIN "));
            format!(" AND {owner}.{} IS NOT {target}", quote(root_key))
        } else {
            String::new()
        };
        // SQLite's MATCH SIMPLE ignores a whole FK group if any component
        // is NULL, including direct-to-owner references optimized without a join.
        let mut present = key
            .columns
            .iter()
            .map(|(from, _)| format!("source.{} IS NOT NULL", quote(from)))
            .collect::<Vec<_>>();
        let target_present = format!("{target} IS NOT NULL");
        if !present.contains(&target_present) {
            present.push(target_present);
        }
        sources.entry(key.child.clone()).or_default().push(format!(
            "{marker} SELECT {target} AS root_id FROM gc_source AS source{joins} WHERE {}{owned}",
            present.join(" AND ")
        ));
    }
    let statements = sources.into_iter().map(|(table, branches)| {
        let sql = format!("WITH gc_source AS MATERIALIZED (SELECT * FROM {}) INSERT OR IGNORE INTO temp.gc_roots(kind,row_id) SELECT '{root}', root_id FROM ({}) AS rooted",
            quote(&table), branches.join(" UNION ALL "));
        (table, sql)
    }).collect();
    let prune = prune.map(|sql| format!("{sql} AND NOT EXISTS (SELECT 1 FROM temp.gc_roots AS gc_root WHERE gc_root.kind='{root}' AND gc_root.row_id={}.{})", quote(root), quote(root_key)));
    RootPlan {
        collectable: root,
        statements,
        prune,
        #[cfg(test)]
        certificates,
    }
}

fn plans(conn: &Connection) -> rusqlite::Result<Vec<RootPlan>> {
    let keys = foreign_keys(conn)?;
    Ok(vec![
        root_plan(
            &keys,
            "resolution_unit_summaries",
            "summary_id",
            Some(super::DELETE_UNBOUND_SUMMARIES_SQL),
        ),
        root_plan(
            &keys,
            "rust_crate_topologies",
            "topology_id",
            Some(super::DELETE_UNBOUND_TOPOLOGIES_SQL),
        ),
        root_plan(&keys, "blobs", "id", None),
    ])
}

fn equalities(columns: &[(String, String)], child: &str, parent: &str) -> String {
    columns
        .iter()
        .map(|(from, to)| format!("{child}.{} = {parent}.{}", quote(from), quote(to)))
        .collect::<Vec<_>>()
        .join(" AND ")
}

fn ancestor_joins(
    keys: &[ForeignKey],
    path: &[usize],
    start: &str,
    prefix: &str,
) -> (String, String) {
    let mut previous = start.to_string();
    let mut joins = String::new();
    for (i, &edge) in path.iter().enumerate() {
        let alias = format!("{prefix}_{i}");
        let key = &keys[edge];
        joins.push_str(&format!(
            " JOIN {} AS {alias} ON {}",
            quote(&key.parent),
            equalities(&key.columns, &previous, &alias)
        ));
        previous = alias;
    }
    (joins, previous)
}

const CREATE_ROOTS: &str = "CREATE TEMP TABLE IF NOT EXISTS gc_roots(kind TEXT NOT NULL, row_id INTEGER NOT NULL, PRIMARY KEY(kind,row_id)) WITHOUT ROWID; DELETE FROM temp.gc_roots;";

// Read live sources in deletion order: pruning a header first removes its
// cascade children before they could incorrectly root a blob in the last phase.
// Every phase shares the caller's immediate transaction and the one schema read.
pub(super) fn materialize(conn: &Connection) -> rusqlite::Result<()> {
    let plans = plans(conn)?;
    conn.execute_batch(CREATE_ROOTS)?;
    for plan in plans {
        debug_assert!(!plan.collectable.is_empty());
        for (_, sql) in plan.statements {
            conn.execute(&sql, [])?;
        }
        if let Some(sql) = plan.prune {
            conn.execute(&sql, [])?;
        }
    }
    Ok(())
}

#[cfg(any(test, feature = "test-support"))]
pub fn gc_root_setup_sql_for_test() -> &'static str {
    CREATE_ROOTS
}

#[cfg(any(test, feature = "test-support"))]
pub struct GcRootPhaseForTest {
    pub collectable: String,
    pub sources: Vec<(String, String)>,
    pub prune: Option<String>,
}

#[cfg(any(test, feature = "test-support"))]
pub fn gc_root_phases_for_test(conn: &Connection) -> rusqlite::Result<Vec<GcRootPhaseForTest>> {
    Ok(plans(conn)?
        .into_iter()
        .map(|p| GcRootPhaseForTest {
            collectable: p.collectable.into(),
            sources: p.statements,
            prune: p.prune,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#11197: live topology references were absent from GC roots")]
    fn schema_foreign_keys_are_covered_by_gc_roots() {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::cache_db::configure_connection(&mut conn).unwrap();
        crate::cache_db::migrate(&mut conn).unwrap();
        let plans = plans(&conn).unwrap();
        for plan in &plans {
            // Independent SQL graph walk over the migrated schema. UNION makes
            // cycles finite. Every incoming FK group needs a certificate, including
            // composite keys and owned edges which intentionally emit no roots.
            let mut stmt = conn
                .prepare(
                    "WITH RECURSIVE owned(name) AS (
               VALUES(?1) UNION
               SELECT s.name FROM sqlite_schema s
               JOIN pragma_foreign_key_list(s.name) f
               JOIN owned o ON o.name = f.\"table\"
               WHERE s.type='table' AND f.on_delete='CASCADE')
             SELECT DISTINCT s.name,f.id,f.on_delete FROM sqlite_schema s
             JOIN pragma_foreign_key_list(s.name) f
             JOIN owned o ON o.name=f.\"table\" WHERE s.type='table'",
                )
                .unwrap();
            for entry in stmt
                .query_map([plan.collectable], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                })
                .unwrap()
            {
                let (table, id, action) = entry.unwrap();
                let certificate = plan
                    .certificates
                    .get(&(table.clone(), id))
                    .unwrap_or_else(|| panic!("uncovered {table} FK {id}"));
                if action == "CASCADE" {
                    assert_eq!(certificate, "cascade-owned");
                } else if !certificate.starts_with("same-owner:") {
                    assert!(
                        plan.statements
                            .iter()
                            .any(|(_, sql)| sql.contains(certificate)),
                        "missing {certificate}"
                    );
                }
            }
        }
        materialize(&conn).unwrap();
        // The other explicit deletion targets in core GC have only owned
        // incoming edges today. Any new non-cascade reference must first gain
        // generated roots before their existing pruning can remain safe.
        let uncovered = conn.prepare("WITH RECURSIVE owned(name) AS (
            VALUES('csharp_compilation_sets'),('csharp_source_condition_symbols'),('csharp_undecided_chains')
            UNION SELECT s.name FROM sqlite_schema s JOIN pragma_foreign_key_list(s.name) f
            JOIN owned o ON o.name=f.\"table\" WHERE s.type='table' AND f.on_delete='CASCADE')
            SELECT DISTINCT s.name,f.id,f.\"table\",f.on_delete FROM sqlite_schema s
            JOIN pragma_foreign_key_list(s.name) f JOIN owned o ON o.name=f.\"table\"
            WHERE s.type='table' AND f.on_delete<>'CASCADE'")
            .unwrap().query_map([], |r| Ok((r.get::<_,String>(0)?,r.get::<_,i64>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?)))
            .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert!(
            uncovered.is_empty(),
            "C# GC pruning needs generated roots for {uncovered:?}"
        );
        // Newly introduced references must enter the generated query without a
        // hand-maintained inventory update.
        conn.execute_batch(
            "CREATE TABLE future_root(blob INTEGER REFERENCES blobs(id) ON DELETE SET NULL);",
        )
        .unwrap();
        let expanded = root_plan(&foreign_keys(&conn).unwrap(), "blobs", "id", None);
        assert!(
            expanded
                .statements
                .iter()
                .any(|(_, sql)| sql.contains("\"future_root\" FK 0"))
        );
    }

    #[test]
    #[hardwon("#11197: references to cascade descendants must root their owning blob")]
    fn cascade_descendants_and_cross_blob_references_are_roots() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys=ON;
             CREATE TABLE blobs(id INTEGER PRIMARY KEY, kind TEXT DEFAULT 'blob', UNIQUE(id,kind));
             CREATE TABLE direct(blob_id INTEGER, kind TEXT, FOREIGN KEY(blob_id,kind) REFERENCES blobs(id,kind) ON DELETE SET NULL);
             CREATE TABLE facts(blob_id INTEGER REFERENCES blobs(id) ON DELETE CASCADE,
                 site INTEGER, PRIMARY KEY(blob_id,site));
             CREATE TABLE uses(blob_id INTEGER REFERENCES blobs(id) ON DELETE CASCADE,
                 target_blob INTEGER, site INTEGER,
                 FOREIGN KEY(target_blob,site) REFERENCES facts(blob_id,site));
             CREATE TABLE live(target_blob INTEGER, site INTEGER,
                 FOREIGN KEY(target_blob,site) REFERENCES facts(blob_id,site) ON DELETE SET DEFAULT);
             INSERT INTO blobs(id) VALUES(1),(2),(3),(4);
             INSERT INTO direct VALUES(4,NULL);
             INSERT INTO facts VALUES(1,10),(2,20),(3,30);
             INSERT INTO uses VALUES(1,1,10),(1,2,20);
             INSERT INTO live VALUES(3,30);",
        ).unwrap();
        conn.execute_batch(CREATE_ROOTS).unwrap();
        for (_, sql) in root_plan(&foreign_keys(&conn).unwrap(), "blobs", "id", None).statements {
            conn.execute(&sql, []).unwrap();
        }
        let roots = conn
            .prepare("SELECT row_id FROM gc_roots WHERE kind='blobs' ORDER BY row_id")
            .unwrap()
            .query_map([], |r| r.get::<_, i64>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(roots, [2, 3]);
        conn.execute(
            "DELETE FROM blobs WHERE id NOT IN (SELECT row_id FROM gc_roots WHERE kind='blobs')",
            [],
        )
        .unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM blobs", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            2
        );
    }
    #[test]
    #[hardwon("#11197: pruning a topology must release its blob roots in the same collection")]
    fn pruning_releases_owned_blob_roots_and_keeps_cross_owner_targets() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON;
            CREATE TABLE blobs(id INTEGER PRIMARY KEY);
            CREATE TABLE resolution_unit_summaries(summary_id INTEGER PRIMARY KEY);
            CREATE TABLE resolution_unit_summary_versions(summary_id INTEGER REFERENCES resolution_unit_summaries(summary_id));
            CREATE TABLE summary_use(summary_id INTEGER REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
                consumed INTEGER REFERENCES resolution_unit_summaries(summary_id) ON DELETE SET NULL);
            CREATE TABLE rust_crate_topologies(topology_id INTEGER PRIMARY KEY);
            CREATE TABLE rust_crate_versions(topology_id INTEGER REFERENCES rust_crate_topologies(topology_id));
            CREATE TABLE rust_resolution_unit_summary_versions(topology_id INTEGER REFERENCES rust_crate_topologies(topology_id));
            CREATE TABLE topology_fact(fact_id INTEGER PRIMARY KEY,
                topology_id INTEGER REFERENCES rust_crate_topologies(topology_id) ON DELETE CASCADE,
                parent_fact_id INTEGER REFERENCES topology_fact(fact_id),
                blob_id INTEGER REFERENCES blobs(id));
            INSERT INTO resolution_unit_summaries VALUES(1),(2),(3);
            INSERT INTO resolution_unit_summary_versions VALUES(1);
            INSERT INTO summary_use VALUES(1,2),(3,3);
            INSERT INTO blobs VALUES(1),(2),(3);
            INSERT INTO rust_crate_topologies VALUES(1),(2),(3);
            INSERT INTO rust_crate_versions VALUES(1);
            INSERT INTO topology_fact VALUES(1,1,NULL,1),(2,2,NULL,2),(3,3,3,3),(4,1,2,NULL);").unwrap();
        materialize(&conn).unwrap();
        for table in ["resolution_unit_summaries", "rust_crate_topologies"] {
            assert_eq!(
                conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                2
            );
        }
        assert_eq!(
            conn.query_row(
                "SELECT consumed FROM summary_use WHERE summary_id=1",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            2
        );
        conn.execute("DELETE FROM blobs WHERE NOT EXISTS (SELECT 1 FROM gc_roots WHERE kind='blobs' AND row_id=blobs.id)", []).unwrap();
        assert_eq!(
            conn.query_row("SELECT group_concat(id) FROM blobs", [], |r| r
                .get::<_, String>(0))
                .unwrap(),
            "1,2"
        );
    }
}
