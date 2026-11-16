//! What a Rust unit's output digest says about the child rows that other units read
//! (#11173 D4).
//!
//! A derivation that reads another unit's rows records that unit with its output
//! digest, and reuses its own summary only while that digest is unchanged. The shared
//! output digest covers the exports a dependent can see by identity, but a Rust
//! consumer also reads module paths, re-export endpoints, effective bindings, trait
//! endpoints and routes of units it is not a direct dependent of. Those are hashed
//! here, so that a change of a name-level column of a consumed unit derives its
//! consumers again.
//!
//! Soundness rule: every column a foreign reader reads of another unit's rows is in
//! [`COLUMNS`] as `Hashed`, or as `Dense` with the reason it may be left out, and no
//! dense coordinate is hashed. A dense coordinate (a member, scope, import, route or
//! site number) moves when a file is edited without any name changing, so hashing one
//! would derive consumers again for a body edit. The structural test at the end of
//! this file prepares the SQL of every foreign reader under SQLite's authorizer, which
//! reports each column the statement reads, and fails on a column that is in neither
//! list. It also fails on a column of these tables that no list names, so adding a
//! column forces its classification.

use super::Result;
use crate::analyzer::canonical_hash::CanonicalHasher;
use rusqlite::{Connection, types::ValueRef};

/// How a column of a Rust child table is treated by [`digest`].
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Coverage {
    /// Name-level: in the supplement digest.
    Hashed,
    /// A dense coordinate, left out. The reason says why no foreign reader's result
    /// can depend on it, or what else covers it.
    Dense(&'static str),
    /// The summary id, or a spelling of a hashed column.
    Key(&'static str),
}

#[cfg(test)]
pub(super) const EXPORTS: &str = "rust_resolution_unit_summary_exports";
#[cfg(test)]
pub(super) const BINDINGS: &str = "rust_resolution_unit_summary_effective_bindings";
#[cfg(test)]
pub(super) const TRAIT_ENDPOINTS: &str = "rust_resolution_unit_summary_trait_endpoints";
#[cfg(test)]
pub(super) const ROUTES: &str = "rust_resolution_unit_summary_reexport_routes";
#[cfg(test)]
pub(super) const CONTAINERS: &str = "rust_resolution_unit_summary_container_attributes";

/// Every column of the Rust child tables that a foreign reader can reach, and how the
/// output digest treats it.
#[cfg(test)]
pub(super) const COLUMNS: &[(&str, &str, Coverage)] = {
    use Coverage::{Dense, Hashed, Key};
    const SUMMARY: Coverage = Key("the summary's own id: a join key");
    &[
        (EXPORTS, "summary_id", SUMMARY),
        (EXPORTS, "module_path", Hashed),
        (EXPORTS, "namespace", Hashed),
        (EXPORTS, "name", Hashed),
        // The identity digest, not the store-local row id.
        (EXPORTS, "identity_id", Hashed),
        (EXPORTS, "visibility", Hashed),
        (EXPORTS, "restricted_module_path", Hashed),
        (EXPORTS, "origin", Hashed),
        (
            EXPORTS,
            "declaration_member_ordinal",
            Dense("a member number; only the unit's own endpoint reads it, never a foreign row's"),
        ),
        (
            EXPORTS,
            "declaration_site",
            Dense(
                "no foreign reader reads it: the trait-endpoint read is by the declaring \
                 item's module and name, which the topology row carries",
            ),
        ),
        (
            EXPORTS,
            "alias_dependency_ordinal",
            Dense("a dependency number; the shared digest hashes the dependency key instead"),
        ),
        (EXPORTS, "target_unit_key", Hashed),
        (EXPORTS, "alias_identity_id", Hashed),
        (EXPORTS, "target_module_path", Hashed),
        (EXPORTS, "target_name", Hashed),
        (BINDINGS, "summary_id", SUMMARY),
        (
            BINDINGS,
            "member_ordinal",
            Dense("a member number; a consumer assigns its own"),
        ),
        (BINDINGS, "module_path", Hashed),
        (
            BINDINGS,
            "binder_scope",
            Dense("a scope number; a consumer assigns its own"),
        ),
        (BINDINGS, "name", Hashed),
        (BINDINGS, "namespace", Hashed),
        (BINDINGS, "visibility_kind", Hashed),
        (BINDINGS, "visibility_crate_root", Hashed),
        (BINDINGS, "visibility_module_path", Hashed),
        (BINDINGS, "target_unit_key", Hashed),
        (BINDINGS, "target_identity_id", Hashed),
        (BINDINGS, "target_module_path", Hashed),
        (BINDINGS, "target_name", Hashed),
        (
            BINDINGS,
            "route_provenance_ordinal",
            Dense("an insertion counter of the unit's own rows; a consumer numbers its own"),
        ),
        (
            BINDINGS,
            "source_import_id",
            Dense("an import number of the unit's own file; not read of a foreign row"),
        ),
        (
            BINDINGS,
            "source_import_ordinal",
            Dense("an import number of the unit's own file; not read of a foreign row"),
        ),
        (TRAIT_ENDPOINTS, "summary_id", SUMMARY),
        (
            TRAIT_ENDPOINTS,
            "member_ordinal",
            Dense("a member number; used only to pair the two ends of one impl"),
        ),
        (TRAIT_ENDPOINTS, "owner_module_path", Hashed),
        (
            TRAIT_ENDPOINTS,
            "source_relation_key",
            Dense("a per-file relation number; used only to pair the two ends of one impl"),
        ),
        (TRAIT_ENDPOINTS, "endpoint_role", Hashed),
        (TRAIT_ENDPOINTS, "endpoint_state", Hashed),
        (
            TRAIT_ENDPOINTS,
            "impl_site",
            Dense("a site number of the impl's own file"),
        ),
        (
            TRAIT_ENDPOINTS,
            "impl_declaration_id",
            Dense("a declaration number of the impl's own file"),
        ),
        (TRAIT_ENDPOINTS, "target_unit_key", Hashed),
        (TRAIT_ENDPOINTS, "target_module_path", Hashed),
        (TRAIT_ENDPOINTS, "target_identity_id", Hashed),
        (
            TRAIT_ENDPOINTS,
            "local_target_member_ordinal",
            Dense("a member number of the unit's own target"),
        ),
        (
            TRAIT_ENDPOINTS,
            "dependency_ordinal",
            Dense("a dependency number; target_unit_key names the unit"),
        ),
        (TRAIT_ENDPOINTS, "unresolved_spelling", Hashed),
        (TRAIT_ENDPOINTS, "unresolved_reason", Hashed),
        (ROUTES, "summary_id", SUMMARY),
        (ROUTES, "module_path", Hashed),
        (ROUTES, "bound_name", Hashed),
        (ROUTES, "target_unit_key", Hashed),
        (
            ROUTES,
            "dependency_ordinal",
            Dense("a dependency number; target_unit_key names the unit"),
        ),
        (ROUTES, "target_module_path", Hashed),
        (ROUTES, "target_name", Hashed),
        (ROUTES, "visibility", Hashed),
        (ROUTES, "restricted_module_path", Hashed),
        (CONTAINERS, "summary_id", SUMMARY),
        (
            CONTAINERS,
            "container_path",
            Key("the same value as module_path, spelled '' for the crate root"),
        ),
        (CONTAINERS, "module_path", Hashed),
        (CONTAINERS, "kind", Hashed),
    ]
};

/// Every distinct name-level export, of every visibility. Identities are hashed by their
/// digest: a row id is local to one store. Positions 1 to 11 are the sort key, which makes
/// the set order independent of the insertion order of the rows.
pub(crate) const EXPORTS_SQL: &str = "SELECT DISTINCT exports.module_path, exports.namespace,
        exports.name, exports.visibility, exports.restricted_module_path, exports.origin,
        identity.identity_digest, alias.identity_digest, exports.target_unit_key,
        exports.target_module_path, exports.target_name
    FROM main.rust_resolution_unit_summary_exports AS exports
    JOIN main.resolution_identities AS identity ON identity.id = exports.identity_id
    LEFT JOIN main.resolution_identities AS alias ON alias.id = exports.alias_identity_id
    WHERE exports.summary_id = ?1
    ORDER BY 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11";

pub(crate) const BINDINGS_SQL: &str = "SELECT DISTINCT bindings.module_path, bindings.name,
        bindings.namespace, bindings.visibility_kind, bindings.visibility_crate_root,
        bindings.visibility_module_path, bindings.target_unit_key, identity.identity_digest,
        bindings.target_module_path, bindings.target_name
    FROM main.rust_resolution_unit_summary_effective_bindings AS bindings
    LEFT JOIN main.resolution_identities AS identity ON identity.id = bindings.target_identity_id
    WHERE bindings.summary_id = ?1
    ORDER BY 1, 2, 3, 4, 5, 6, 7, 8, 9, 10";

pub(crate) const ROUTES_SQL: &str = "SELECT DISTINCT routes.module_path, routes.bound_name,
        routes.target_unit_key, routes.target_module_path, routes.target_name,
        routes.visibility, routes.restricted_module_path
    FROM main.rust_resolution_unit_summary_reexport_routes AS routes
    WHERE routes.summary_id = ?1
    ORDER BY 1, 2, 3, 4, 5, 6, 7";

pub(crate) const CONTAINERS_SQL: &str = "SELECT containers.module_path, containers.kind
    FROM main.rust_resolution_unit_summary_container_attributes AS containers
    WHERE containers.summary_id = ?1
    ORDER BY 1, 2";

/// The two ends of one impl are paired by the impl's member and relation numbers, which
/// order the rows and are not hashed.
pub(crate) const TRAIT_ENDPOINTS_SQL: &str = "SELECT endpoints.member_ordinal,
        endpoints.source_relation_key, endpoints.owner_module_path, endpoints.endpoint_role,
        endpoints.endpoint_state, endpoints.target_unit_key, endpoints.target_module_path,
        identity.identity_digest, endpoints.unresolved_spelling, endpoints.unresolved_reason
    FROM main.rust_resolution_unit_summary_trait_endpoints AS endpoints
    LEFT JOIN main.resolution_identities AS identity ON identity.id = endpoints.target_identity_id
    WHERE endpoints.summary_id = ?1
    ORDER BY endpoints.member_ordinal, endpoints.owner_module_path,
             endpoints.source_relation_key, endpoints.endpoint_role";

/// One column value, with its type, so that NULL, an empty string and a number differ.
fn put(hash: &mut CanonicalHasher, value: ValueRef<'_>) {
    match value {
        ValueRef::Null => hash.field("null", &[]),
        ValueRef::Integer(value) => hash.field("integer", &value.to_be_bytes()),
        ValueRef::Text(text) => hash.field("text", text),
        ValueRef::Blob(blob) => hash.field("blob", blob),
        ValueRef::Real(_) => unreachable!("a Rust child row holds no real number"),
    }
}

/// Hash every row of `sql`, all of its columns, under `label`.
fn put_rows(
    conn: &Connection,
    hash: &mut CanonicalHasher,
    label: &str,
    sql: &str,
    summary_id: i64,
) -> Result<()> {
    hash.field("rows", label.as_bytes());
    let mut statement = conn.prepare_cached(sql)?;
    let columns = statement.column_count();
    let mut rows = statement.query([summary_id])?;
    while let Some(row) = rows.next()? {
        for column in 0..columns {
            put(hash, row.get_ref(column)?);
        }
        hash.field("row", &[]);
    }
    Ok(())
}

/// The supplement digest of the Rust child rows of `summary_id`, which must be written.
pub(super) fn digest(conn: &Connection, summary_id: i64) -> Result<[u8; 32]> {
    let mut hash = CanonicalHasher::new(b"bifrost-rust-unit-summary-child-rows:v1");
    put_rows(conn, &mut hash, "exports", EXPORTS_SQL, summary_id)?;
    put_rows(conn, &mut hash, "bindings", BINDINGS_SQL, summary_id)?;
    put_rows(conn, &mut hash, "routes", ROUTES_SQL, summary_id)?;
    put_rows(conn, &mut hash, "containers", CONTAINERS_SQL, summary_id)?;

    // One digest per impl: its owner module and its ends by role. Two impls that read the
    // same are two equal digests, so the set keeps its multiplicity.
    let mut impls: Vec<[u8; 32]> = Vec::new();
    let mut statement = conn.prepare_cached(TRAIT_ENDPOINTS_SQL)?;
    let mut rows = statement.query([summary_id])?;
    let mut current: Option<((i64, String, i64), CanonicalHasher)> = None;
    while let Some(row) = rows.next()? {
        let key = (
            row.get::<_, i64>(0)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(1)?,
        );
        if current.as_ref().is_none_or(|(open, _)| *open != key) {
            if let Some((_, finished)) = current.take() {
                impls.push(finished.finish());
            }
            let mut impl_hash = CanonicalHasher::new(b"bifrost-rust-unit-summary-impl-ends:v1");
            impl_hash.field("owner", key.1.as_bytes());
            current = Some((key, impl_hash));
        }
        let (_, impl_hash) = current.as_mut().expect("an impl is open");
        for column in 3..row.as_ref().column_count() {
            put(impl_hash, row.get_ref(column)?);
        }
        impl_hash.field("end", &[]);
    }
    if let Some((_, finished)) = current.take() {
        impls.push(finished.finish());
    }
    impls.sort_unstable();
    hash.field("rows", b"trait_endpoints");
    for digest in impls {
        hash.field("impl", &digest);
    }
    Ok(hash.finish())
}

#[cfg(test)]
mod tests {
    use super::super::{
        CLOSURE_BINDINGS_IN_MODULE_SQL, CLOSURE_BINDINGS_NAMED_SQL, RESOLVED_ENDPOINTS_SQL,
        TRAIT_ENDPOINT_NAME_SQL, export_walk,
    };
    use super::*;
    use crate::analyzer::store::{AnalyzerStore, connection_authorizer};
    use rusqlite::hooks::{AuthAction, Authorization};
    use std::collections::BTreeSet;
    use std::sync::{Arc, Mutex};

    /// The `(table, column)` pairs of the Rust child tables that SQLite reports a
    /// statement reads when it is prepared: the select list, the joins and the filters.
    fn columns_read(conn: &Connection, sql: &str) -> BTreeSet<(String, String)> {
        let reads = Arc::new(Mutex::new(BTreeSet::new()));
        let sink = Arc::clone(&reads);
        connection_authorizer::compose_guard(conn, move |ctx| {
            if let AuthAction::Read {
                table_name,
                column_name,
            } = ctx.action
                && COLUMNS.iter().any(|(table, ..)| *table == table_name)
            {
                sink.lock()
                    .unwrap()
                    .insert((table_name.to_owned(), column_name.to_owned()));
            }
            Authorization::Allow
        })
        .unwrap();
        conn.prepare(sql)
            .unwrap_or_else(|error| panic!("prepare {sql}: {error}"));
        conn.authorizer(None::<fn(rusqlite::hooks::AuthContext<'_>) -> Authorization>)
            .unwrap();
        std::mem::take(&mut *reads.lock().unwrap())
    }

    fn classified(table: &str, column: &str) -> Option<Coverage> {
        COLUMNS
            .iter()
            .find(|(t, c, _)| *t == table && *c == column)
            .map(|(_, _, coverage)| *coverage)
    }

    #[test]
    fn every_column_a_foreign_reader_reads_is_hashed_or_marked_dense() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().unwrap();
        let _fixture = crate::analyzer::store::sealed_families::Fixture::new(&conn);

        // Every statement that reads another unit's Rust child rows when a unit is derived:
        // the walk, the closure bindings of an import target and provider, and the read of a
        // trait impl's declaring unit by name.
        let foreign_readers: [(&str, &str); 8] = [
            ("walk endpoint", export_walk::ENDPOINT_ROW_SQL),
            ("walk alias modules", export_walk::ALIAS_MODULES_SQL),
            ("walk module rows", export_walk::MODULE_ROWS_SQL),
            ("walk route rows", export_walk::ROUTE_ROWS_SQL),
            ("walk containers", export_walk::CONTAINERS_SQL),
            (
                "closure bindings of a module",
                CLOSURE_BINDINGS_IN_MODULE_SQL,
            ),
            ("closure bindings of a name", CLOSURE_BINDINGS_NAMED_SQL),
            ("trait endpoint declaring export", TRAIT_ENDPOINT_NAME_SQL),
        ];
        // The authorizer reports select-list columns and predicate columns alike.
        assert_eq!(
            columns_read(&conn, export_walk::ENDPOINT_ROW_SQL)
                .into_iter()
                .map(|(_, column)| column)
                .collect::<Vec<_>>(),
            [
                "module_path",
                "name",
                "namespace",
                "summary_id",
                "visibility"
            ]
        );
        // The statement that places each endpoint reads no other unit's summary rows; the
        // declaring unit's export is read by name, and by nothing else (no site, no blob).
        assert_eq!(
            columns_read(&conn, RESOLVED_ENDPOINTS_SQL),
            BTreeSet::new(),
            "the endpoint placement statement reads a child row of a summary"
        );
        assert_eq!(
            columns_read(&conn, TRAIT_ENDPOINT_NAME_SQL)
                .into_iter()
                .map(|(_, column)| column)
                .collect::<Vec<_>>(),
            [
                "declaration_member_ordinal",
                "identity_id",
                "module_path",
                "name",
                "namespace",
                "origin",
                "summary_id"
            ]
        );
        let mut unclassified = Vec::new();
        let mut hashed_read = BTreeSet::new();
        for (reader, sql) in foreign_readers {
            let reads = columns_read(&conn, sql);
            assert!(!reads.is_empty(), "{reader} reads no Rust child column");
            for (table, column) in reads {
                match classified(&table, &column) {
                    None => unclassified.push(format!("{reader}: {table}.{column}")),
                    Some(Coverage::Hashed) => {
                        hashed_read.insert((table, column));
                    }
                    Some(Coverage::Dense(_) | Coverage::Key(_)) => {}
                }
            }
        }
        assert!(
            unclassified.is_empty(),
            "foreign readers read columns that the output digest neither hashes nor marks dense: \
             {unclassified:?}"
        );

        // The supplement reads every column it claims to hash, and nothing dense beyond the
        // columns that only order and pair rows.
        let mut supplement_reads = BTreeSet::new();
        for sql in [
            EXPORTS_SQL,
            BINDINGS_SQL,
            ROUTES_SQL,
            CONTAINERS_SQL,
            TRAIT_ENDPOINTS_SQL,
        ] {
            supplement_reads.extend(columns_read(&conn, sql));
        }
        let hashed: BTreeSet<_> = COLUMNS
            .iter()
            .filter(|(_, _, coverage)| *coverage == Coverage::Hashed)
            .map(|(table, column, _)| ((*table).to_owned(), (*column).to_owned()))
            .collect();
        assert_eq!(
            hashed.difference(&supplement_reads).collect::<Vec<_>>(),
            Vec::<&(String, String)>::new(),
            "columns claimed hashed that the supplement does not read"
        );
        let dense_read: Vec<_> = supplement_reads
            .iter()
            .filter(|(table, column)| matches!(classified(table, column), Some(Coverage::Dense(_))))
            .collect();
        assert_eq!(
            dense_read,
            [
                &(TRAIT_ENDPOINTS.to_owned(), "member_ordinal".to_owned()),
                &(TRAIT_ENDPOINTS.to_owned(), "source_relation_key".to_owned()),
            ],
            "the supplement reads a dense column only to pair the two ends of an impl"
        );
        assert!(
            hashed_read.len() > 10,
            "foreign readers read hashed columns: {hashed_read:?}"
        );

        // A column added to these tables must be classified before it can be read.
        let mut missing = Vec::new();
        for table in [EXPORTS, BINDINGS, TRAIT_ENDPOINTS, ROUTES, CONTAINERS] {
            let mut statement = conn
                .prepare(&format!("SELECT name FROM pragma_table_xinfo('{table}')"))
                .unwrap();
            for column in statement
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
            {
                let column = column.unwrap();
                if classified(table, &column).is_none() {
                    missing.push(format!("{table}.{column}"));
                }
            }
            for (listed_table, column, _) in COLUMNS {
                if *listed_table == table {
                    let exists: bool = conn
                        .query_row(
                            &format!(
                                "SELECT EXISTS(SELECT 1 FROM pragma_table_xinfo('{table}') \
                                 WHERE name = ?1)"
                            ),
                            [column],
                            |row| row.get(0),
                        )
                        .unwrap();
                    assert!(exists, "{table}.{column} is classified but is not a column");
                }
            }
        }
        assert!(
            missing.is_empty(),
            "columns of the Rust child tables that no coverage list names: {missing:?}"
        );
    }
}
