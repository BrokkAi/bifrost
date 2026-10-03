//! Readback for the canonical source-owned import facts.
//!
//! This reader hydrates the normalized import rows without reconstructing
//! paths, ranges, or identities from any display projection.  The publication
//! manifest and dense ordinals are part of the read contract: a missing or
//! incomplete family is corruption, not an empty import list.

use brokk_bifrost_core::analyzer::model::StructuredImportPathKind;
use brokk_bifrost_core::analyzer::parsed_file::{SourceImportFact, SourceImportPathFact};
use brokk_bifrost_core::analyzer::source_facts::SourceImportId;
use rusqlite::{Connection, OptionalExtension, params};

use super::super::{Result, StoreError};
use super::{SOURCE_FACTS_VERSION, nonnegative_usize, source_occurrence, strict_bool};

fn source_import(value: i64, label: &str) -> Result<SourceImportId> {
    let value = u32::try_from(value)
        .map_err(|_| StoreError::new(format!("invalid {label} source import id {value}")))?;
    Ok(SourceImportId::new(value))
}

fn path_kind(value: Option<String>, label: &str) -> Result<Option<StructuredImportPathKind>> {
    value
        .map(|value| {
            StructuredImportPathKind::from_persist_tag(&value).ok_or_else(|| {
                StoreError::new(format!(
                    "invalid {label} structured import path kind {value:?}"
                ))
            })
        })
        .transpose()
}

fn import_path_mut<'a>(
    imports: &'a mut [SourceImportFact],
    import_id: i64,
    label: &str,
) -> Result<&'a mut SourceImportPathFact> {
    let import_id = source_import(import_id, label)?;
    let import = imports.get_mut(import_id.index()).ok_or_else(|| {
        StoreError::new(format!(
            "{label} references missing source import id {:?}",
            import_id
        ))
    })?;
    import.path.as_mut().ok_or_else(|| {
        StoreError::new(format!(
            "{label} references unavailable path for source import {import_id:?}"
        ))
    })
}

pub(in crate::analyzer) fn read_source_imports(
    conn: &Connection,
    blob_id: i64,
    keep_going: &dyn Fn() -> bool,
) -> Result<Option<Vec<SourceImportFact>>> {
    if !keep_going() {
        return Ok(None);
    }

    let manifest: Option<(String, i64, i64, i64, i64, i64)> = conn
        .query_row(
            "SELECT publication_state, facts_version, import_count,
                    import_segment_count, import_scope_count, import_prefix_count
               FROM source_fact_manifests
              WHERE blob_id = ?1",
            params![blob_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    let Some((
        publication_state,
        facts_version,
        import_count,
        segment_count,
        scope_count,
        prefix_count,
    )) = manifest
    else {
        return Err(StoreError::new(format!(
            "source import facts for blob {blob_id} have no publication manifest"
        )));
    };
    if publication_state != "complete" || facts_version != SOURCE_FACTS_VERSION {
        return Err(StoreError::new(format!(
            "source import facts for blob {blob_id} are not complete: state={publication_state:?}, facts_version={facts_version}"
        )));
    }
    let expected_imports = nonnegative_usize(import_count, "source import count")?;
    let expected_segments = nonnegative_usize(segment_count, "source import segment count")?;
    let expected_scopes = nonnegative_usize(scope_count, "source import scope count")?;
    let expected_prefixes = nonnegative_usize(prefix_count, "source import prefix count")?;

    let mut imports = Vec::new();
    let mut statement = conn.prepare_cached(
        "SELECT import_id, statement, is_wildcard, is_global,
                identifier, alias, path_kind, declaration_occurrence_id,
                target_occurrence_id, alias_occurrence_id, has_structured_path, is_macro_use
           FROM source_imports
          WHERE blob_id = ?1
          ORDER BY import_id",
    )?;
    let mut rows = statement.query(params![blob_id])?;
    while let Some(row) = rows.next()? {
        if !keep_going() {
            return Ok(None);
        }
        let import_id = source_import(row.get(0)?, "source import")?;
        if import_id.index() != imports.len() {
            return Err(StoreError::new(format!(
                "source import ids are not dense for blob {blob_id}: got {:?}, expected {}",
                import_id,
                imports.len()
            )));
        }
        let declaration = source_occurrence(row.get(7)?, "source import declaration")?;
        let target = row
            .get::<_, Option<i64>>(8)?
            .map(|value| source_occurrence(value, "source import target"))
            .transpose()?;
        let alias_occurrence = row
            .get::<_, Option<i64>>(9)?
            .map(|value| source_occurrence(value, "source import alias"))
            .transpose()?;
        let has_path = strict_bool(row.get(10)?, "source import path availability")?;
        let kind = path_kind(row.get(6)?, "source import")?;
        if !has_path && kind.is_some() {
            return Err(StoreError::new(format!(
                "unavailable source import path {import_id:?} has kind {kind:?}"
            )));
        }
        imports.push(SourceImportFact {
            declaration,
            target,
            alias_occurrence,
            statement: row.get(1)?,
            is_wildcard: strict_bool(row.get(2)?, "source import wildcard")?,
            is_global: strict_bool(row.get(3)?, "source import global")?,
            is_macro_use: strict_bool(row.get(11)?, "source import macro use")?,
            identifier: row.get(4)?,
            alias: row.get(5)?,
            path: has_path.then(|| SourceImportPathFact {
                kind,
                segments: Vec::new(),
                lexical_prefixes: Vec::new(),
                lexical_scopes: Vec::new(),
            }),
        });
    }
    drop(rows);
    drop(statement);
    if imports.len() != expected_imports {
        return Err(StoreError::new(format!(
            "source import count mismatch for blob {blob_id}: manifest={expected_imports}, imports={imports:?}"
        )));
    }

    let mut segments = 0usize;
    let mut statement = conn.prepare_cached(
        "SELECT import_id, ordinal, segment
           FROM source_import_segments
          WHERE blob_id = ?1
          ORDER BY import_id, ordinal",
    )?;
    let mut rows = statement.query(params![blob_id])?;
    while let Some(row) = rows.next()? {
        if !keep_going() {
            return Ok(None);
        }
        let ordinal = nonnegative_usize(row.get(1)?, "source import segment ordinal")?;
        let import = import_path_mut(&mut imports, row.get(0)?, "source import segment")?;
        if ordinal != import.segments.len() {
            return Err(StoreError::new(format!(
                "source import segment ordinals are not dense: got {ordinal}, expected {}",
                import.segments.len()
            )));
        }
        import.segments.push(row.get(2)?);
        segments += 1;
    }
    drop(rows);
    drop(statement);
    if segments != expected_segments {
        return Err(StoreError::new(format!(
            "source import segment count mismatch for blob {blob_id}: manifest={expected_segments}, rows={segments}, imports={imports:?}"
        )));
    }

    let mut scopes = 0usize;
    let mut statement = conn.prepare_cached(
        "SELECT import_id, ordinal, occurrence_id
           FROM source_import_scopes
          WHERE blob_id = ?1
          ORDER BY import_id, ordinal",
    )?;
    let mut rows = statement.query(params![blob_id])?;
    while let Some(row) = rows.next()? {
        if !keep_going() {
            return Ok(None);
        }
        let ordinal = nonnegative_usize(row.get(1)?, "source import scope ordinal")?;
        let occurrence = source_occurrence(row.get(2)?, "source import scope")?;
        let import = import_path_mut(&mut imports, row.get(0)?, "source import scope")?;
        if ordinal != import.lexical_scopes.len() {
            return Err(StoreError::new(format!(
                "source import scope ordinals are not dense: got {ordinal}, expected {}",
                import.lexical_scopes.len()
            )));
        }
        import.lexical_scopes.push(occurrence);
        scopes += 1;
    }
    drop(rows);
    drop(statement);
    if scopes != expected_scopes {
        return Err(StoreError::new(format!(
            "source import scope count mismatch for blob {blob_id}: manifest={expected_scopes}, rows={scopes}, imports={imports:?}"
        )));
    }

    let mut prefixes = 0usize;
    let mut statement = conn.prepare_cached(
        "SELECT import_id, ordinal, prefix
           FROM source_import_prefixes
          WHERE blob_id = ?1
          ORDER BY import_id, ordinal",
    )?;
    let mut rows = statement.query(params![blob_id])?;
    while let Some(row) = rows.next()? {
        if !keep_going() {
            return Ok(None);
        }
        let ordinal = nonnegative_usize(row.get(1)?, "source import prefix ordinal")?;
        let import = import_path_mut(&mut imports, row.get(0)?, "source import prefix")?;
        if ordinal != import.lexical_prefixes.len() {
            return Err(StoreError::new(format!(
                "source import prefix ordinals are not dense: got {ordinal}, expected {}",
                import.lexical_prefixes.len()
            )));
        }
        import.lexical_prefixes.push(row.get(2)?);
        prefixes += 1;
    }
    if prefixes != expected_prefixes {
        return Err(StoreError::new(format!(
            "source import prefix count mismatch for blob {blob_id}: manifest={expected_prefixes}, rows={prefixes}, imports={imports:?}"
        )));
    }

    if !keep_going() {
        return Ok(None);
    }
    Ok(Some(imports))
}

#[cfg(test)]
mod tests {
    use super::read_source_imports;
    use crate::analyzer::rust::RustAdapter;
    use crate::analyzer::store::AnalyzerStore;
    use crate::analyzer::store::tests::{oid_for, parse_state};
    use crate::inline_project::InlineTestProject;
    use git2::Oid;
    use rusqlite::{Connection, params};

    const IMPORT_SOURCE: &str = concat!(
        "use crate::service::{self as svc, run as execute, *};\n",
        "use crate::{};\n",
        "mod local { use super::{Local, LocalAlias as LocalName}; }\n",
        "macro_rules! wrap { ($($item:item)*) => { $($item)* }; }\n",
        "wrap! { use crate::Embedded; }\n",
        "wrap! { use crate::{}; }\n",
    );

    fn blob_id(conn: &Connection, oid: Oid) -> i64 {
        conn.query_row(
            "SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'rust'",
            [oid.to_string()],
            |row| row.get(0),
        )
        .expect("published Rust blob id")
    }

    #[test]
    fn canonical_import_readback_preserves_embedded_local_grouped_and_empty_inputs() {
        let fixture = InlineTestProject::new()
            .file("src/lib.rs", IMPORT_SOURCE)
            .build();
        let state = parse_state(&RustAdapter, &fixture.file("src/lib.rs"));
        let expected = state
            .source_facts
            .as_ref()
            .expect("Rust source facts")
            .imports
            .clone();
        assert!(
            expected.len() >= 6,
            "fixture should retain grouped, local, and embedded leaves: {expected:?}"
        );
        assert_eq!(
            expected
                .iter()
                .filter(|import| import.statement.contains("service"))
                .count(),
            3,
            "grouped leaves retain producer order and normalized statements"
        );
        assert!(
            expected.iter().any(|import| import
                .path
                .as_ref()
                .is_some_and(|path| !path.lexical_scopes.is_empty())),
            "local or embedded import must retain lexical source scopes"
        );
        assert!(
            expected
                .iter()
                .any(|import| import.statement.contains("Embedded")),
            "embedded macro import must be source-owned"
        );
        assert!(
            expected
                .iter()
                .all(|import| import.statement != "use crate::{};"),
            "empty import groups do not create leaf facts"
        );

        let oid = oid_for(IMPORT_SOURCE.as_bytes());
        let store = AnalyzerStore::open_ephemeral().expect("ephemeral analyzer store");
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &state)
            .expect("canonical import fixture publishes");
        let actual = store.conn.execute(move |conn| {
            let id = blob_id(conn, oid);
            read_source_imports(conn, id, &|| true)
        });
        assert_eq!(actual.unwrap().unwrap(), expected);
    }

    #[test]
    fn canonical_import_readback_cancellation_and_manifest_corruption_are_reported() {
        let fixture = InlineTestProject::new()
            .file("src/lib.rs", IMPORT_SOURCE)
            .build();
        let state = parse_state(&RustAdapter, &fixture.file("src/lib.rs"));
        let oid = oid_for(IMPORT_SOURCE.as_bytes());
        let store = AnalyzerStore::open_ephemeral().expect("ephemeral analyzer store");
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &state)
            .expect("canonical import fixture publishes");

        let cancelled = store.conn.execute(move |conn| {
            let id = blob_id(conn, oid);
            read_source_imports(conn, id, &|| false)
        });
        assert!(cancelled.unwrap().is_none());

        let corrupted = store.conn.execute(move |conn| {
            let id = blob_id(conn, oid);
            conn.execute_batch(
                "SAVEPOINT import_reader_corruption;
                 DROP TRIGGER source_import_segments_no_delete_after_seal;",
            )
            .expect("open canonical import corruption savepoint");
            let changed = conn
                .execute(
                    "DELETE FROM source_import_segments
                      WHERE blob_id = ?1
                        AND import_id = (SELECT MIN(import_id)
                                           FROM source_import_segments WHERE blob_id = ?1)
                        AND ordinal = (SELECT MAX(ordinal)
                                         FROM source_import_segments
                                        WHERE blob_id = ?1
                                          AND import_id = (SELECT MIN(import_id)
                                                             FROM source_import_segments
                                                            WHERE blob_id = ?1))",
                    params![id],
                )
                .expect("delete one canonical import segment inside savepoint");
            assert_eq!(changed, 1, "fixture must publish a canonical segment");
            let result = read_source_imports(conn, id, &|| true);
            conn.execute_batch(
                "ROLLBACK TO import_reader_corruption;
                 RELEASE import_reader_corruption;",
            )
            .expect("restore canonical import rows");
            result
        });
        let error = corrupted.expect_err("manifest segment count mismatch must fail readback");
        assert!(
            error
                .to_string()
                .contains("source import segment count mismatch")
        );
    }
}
