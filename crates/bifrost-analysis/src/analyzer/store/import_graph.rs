use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use rusqlite::trace::TraceEventCodes;
use rusqlite::{OptionalExtension, params, params_from_iter, trace::TraceEvent, types::Value};
use std::sync::{LazyLock, Mutex};

use super::{AnalyzerStore, Result, StoreError, WorkspaceId};

pub(crate) const IMPORT_GRAPH_PATH_BATCH: usize = 256;
pub(crate) const IMPORT_GRAPH_ORDINAL_BATCH: usize = 256;
pub(crate) const IMPORT_GRAPH_ROW_BATCH: usize = 64;

pub(crate) const DYNAMIC_IMPORT_SOURCES_SQL: &str = "SELECT files.lang, files.rel_path
FROM source_imports AS imports INDEXED BY idx_source_imports_dynamic_include_blob
JOIN live_workspace_files AS files ON files.blob_id = imports.blob_id
WHERE imports.path_kind = 'dynamic_include'
  AND (?1 IS NULL OR EXISTS (
    SELECT 1 FROM json_each(?1) AS seed
    WHERE json_extract(seed.value, '$[0]') = files.lang
      AND json_extract(seed.value, '$[1]') = files.rel_path
  ))";

#[derive(Debug, Default)]
struct ImportGraphStatementProfile {
    calls: u64,
    total_ns: u128,
    max_ns: u128,
}

static IMPORT_GRAPH_STATEMENT_PROFILE: LazyLock<
    Mutex<std::collections::BTreeMap<String, ImportGraphStatementProfile>>,
> = LazyLock::new(|| Mutex::new(std::collections::BTreeMap::new()));

fn record_import_graph_statement_profile(event: TraceEvent<'_>) {
    if let TraceEvent::Profile(statement, duration) = event {
        let mut profile = IMPORT_GRAPH_STATEMENT_PROFILE
            .lock()
            .expect("import graph SQL profile lock");
        let entry = profile.entry(statement.sql().into_owned()).or_default();
        let elapsed_ns = duration.as_nanos();
        entry.calls += 1;
        entry.total_ns += elapsed_ns;
        entry.max_ns = entry.max_ns.max(elapsed_ns);
    }
}

fn insert_row_values_sql(column_count: usize, row_count: usize) -> String {
    assert!((1..=IMPORT_GRAPH_ROW_BATCH).contains(&row_count));
    let row = format!(
        "({})",
        std::iter::repeat_n("?", column_count)
            .collect::<Vec<_>>()
            .join(",")
    );
    std::iter::repeat_n(row.as_str(), row_count)
        .collect::<Vec<_>>()
        .join(",")
}

fn import_graph_insert_sql(
    table: &str,
    columns: &str,
    column_count: usize,
    row_count: usize,
) -> String {
    format!(
        "INSERT INTO {table} ({columns}) VALUES {}",
        insert_row_values_sql(column_count, row_count)
    )
}

fn import_graph_insert_or_ignore_sql(
    table: &str,
    columns: &str,
    column_count: usize,
    row_count: usize,
) -> String {
    format!(
        "INSERT OR IGNORE INTO {table} ({columns}) VALUES {}",
        insert_row_values_sql(column_count, row_count)
    )
}

fn ordinal_pair_values_sql(ordinal_count: usize) -> String {
    assert!((1..=IMPORT_GRAPH_ORDINAL_BATCH).contains(&ordinal_count));
    std::iter::repeat_n("(?, ?)", ordinal_count)
        .collect::<Vec<_>>()
        .join(",")
}

pub(crate) fn edge_fact_rows_by_ordinals_sql(ordinal_count: usize) -> String {
    format!(
        "SELECT importer_path, import_ordinal, target_path
         FROM workspace_import_edge_facts
         WHERE workspace_id = ? AND (importer_path, import_ordinal) IN (VALUES {})",
        ordinal_pair_values_sql(ordinal_count)
    )
}

pub(crate) fn edge_fact_rows_by_importers_sql(importer_count: usize) -> String {
    assert!((1..=IMPORT_GRAPH_PATH_BATCH).contains(&importer_count));
    format!(
        "SELECT importer_path, import_ordinal, target_path
         FROM workspace_import_edge_facts
         WHERE workspace_id = ?1 AND importer_path IN ({})",
        std::iter::repeat_n("?", importer_count)
            .collect::<Vec<_>>()
            .join(",")
    )
}

pub(crate) fn delete_edge_fact_keys_sql(row_count: usize) -> String {
    assert!((1..=IMPORT_GRAPH_ROW_BATCH).contains(&row_count));
    let keys = std::iter::repeat_n("(?, ?, ?)", row_count)
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "DELETE FROM workspace_import_edge_facts
         WHERE workspace_id = ? AND (importer_path, import_ordinal, target_path) IN (VALUES {keys})"
    )
}

pub(crate) fn upsert_edge_facts_sql(row_count: usize) -> String {
    format!(
        "{} ON CONFLICT(workspace_id, importer_path, import_ordinal, target_path)
         DO UPDATE SET provenance_json = excluded.provenance_json
         WHERE workspace_import_edge_facts.provenance_json IS NOT excluded.provenance_json",
        import_graph_insert_sql(
            "workspace_import_edge_facts",
            "workspace_id, importer_path, import_ordinal, target_path, provenance_json",
            5,
            row_count,
        )
    )
}

pub(crate) fn edge_fact_pairs_by_paths_sql(path_column: &str, path_count: usize) -> String {
    assert!(matches!(path_column, "importer_path" | "target_path"));
    assert!((1..=IMPORT_GRAPH_PATH_BATCH).contains(&path_count));
    let index_hint = match path_column {
        "importer_path" => "",
        "target_path" => " INDEXED BY workspace_import_edge_facts_target_idx",
        _ => unreachable!(),
    };
    format!(
        "SELECT importer_path, target_path FROM workspace_import_edge_facts{index_hint}
         WHERE workspace_id = ?1 AND {path_column} IN ({})",
        std::iter::repeat_n("?", path_count)
            .collect::<Vec<_>>()
            .join(",")
    )
}

pub(crate) fn import_graph_dependency_rows_by_ordinals_sql(
    table: &str,
    ordinal_count: usize,
) -> String {
    let columns = match table {
        "workspace_import_candidate_file_dependencies" => "consulted_path, name",
        "workspace_import_route_dependencies" => "traversed_path, name",
        "workspace_import_missing_module_dependencies" => "module_path_key, ''",
        _ => panic!("unknown import graph dependency table: {table}"),
    };
    format!(
        "SELECT importer_path, import_ordinal, {columns} FROM {table}
         WHERE workspace_id = ? AND (importer_path, import_ordinal) IN (VALUES {})",
        ordinal_pair_values_sql(ordinal_count)
    )
}

pub(crate) fn delete_import_graph_dependency_rows_sql(table: &str, row_count: usize) -> String {
    assert!((1..=IMPORT_GRAPH_ROW_BATCH).contains(&row_count));
    let (columns, width) = match table {
        "workspace_import_candidate_file_dependencies" => {
            ("importer_path, import_ordinal, consulted_path, name", 4)
        }
        "workspace_import_route_dependencies" => {
            ("importer_path, import_ordinal, traversed_path, name", 4)
        }
        "workspace_import_missing_module_dependencies" => {
            ("importer_path, import_ordinal, module_path_key", 3)
        }
        _ => panic!("unknown import graph dependency table: {table}"),
    };
    let row = format!(
        "({})",
        std::iter::repeat_n("?", width)
            .collect::<Vec<_>>()
            .join(", ")
    );
    let values = std::iter::repeat_n(row.as_str(), row_count)
        .collect::<Vec<_>>()
        .join(", ");
    format!("DELETE FROM {table} WHERE workspace_id = ? AND ({columns}) IN (VALUES {values})")
}

fn read_import_graph_dependency_rows(
    transaction: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    table: &str,
    ordinals: &[(String, u32)],
) -> Result<std::collections::HashSet<(String, u32, String, String)>> {
    let mut result = std::collections::HashSet::new();
    for chunk in ordinals.chunks(IMPORT_GRAPH_ORDINAL_BATCH) {
        if chunk.is_empty() {
            continue;
        }
        let sql = import_graph_dependency_rows_by_ordinals_sql(table, chunk.len());
        let mut values = vec![Value::Text(workspace_id.to_owned())];
        for (importer, ordinal) in chunk {
            values.push(Value::Text(importer.clone()));
            values.push(Value::Integer(i64::from(*ordinal)));
        }
        let mut statement = transaction.prepare_cached(&sql)?;
        let rows = statement.query_map(params_from_iter(values.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        for row in rows {
            let (importer, ordinal, path, name) = row?;
            result.insert((
                importer,
                u32::try_from(ordinal).expect("stored import ordinal fits u32"),
                path,
                name,
            ));
        }
    }
    Ok(result)
}

fn delete_stale_import_graph_dependency_rows(
    transaction: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    table: &str,
    old_rows: &std::collections::HashSet<(String, u32, String, String)>,
    new_rows: &std::collections::HashSet<(String, u32, String, String)>,
) -> Result<()> {
    let mut stale_rows = old_rows.difference(new_rows).collect::<Vec<_>>();
    stale_rows.sort_unstable();
    for chunk in stale_rows.chunks(IMPORT_GRAPH_ROW_BATCH) {
        let sql = delete_import_graph_dependency_rows_sql(table, chunk.len());
        let mut values = vec![Value::Text(workspace_id.to_owned())];
        for (importer, ordinal, path, name) in chunk {
            values.push(Value::Text(importer.clone()));
            values.push(Value::Integer(i64::from(*ordinal)));
            values.push(Value::Text(path.clone()));
            if table != "workspace_import_missing_module_dependencies" {
                values.push(Value::Text(name.clone()));
            }
        }
        transaction
            .prepare_cached(&sql)?
            .execute(params_from_iter(values.iter()))?;
    }
    Ok(())
}

fn insert_new_import_graph_dependency_rows(
    transaction: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    table: &str,
    old_rows: &std::collections::HashSet<(String, u32, String, String)>,
    new_rows: &std::collections::HashSet<(String, u32, String, String)>,
) -> Result<()> {
    let mut added_rows = new_rows.difference(old_rows).collect::<Vec<_>>();
    added_rows.sort_unstable();
    let (columns, width) = match table {
        "workspace_import_candidate_file_dependencies" => (
            "workspace_id, importer_path, import_ordinal, consulted_path, name",
            5,
        ),
        "workspace_import_route_dependencies" => (
            "workspace_id, importer_path, import_ordinal, traversed_path, name",
            5,
        ),
        "workspace_import_missing_module_dependencies" => (
            "workspace_id, importer_path, import_ordinal, module_path_key",
            4,
        ),
        _ => panic!("unknown import graph dependency table: {table}"),
    };
    for chunk in added_rows.chunks(IMPORT_GRAPH_ROW_BATCH) {
        let sql = import_graph_insert_or_ignore_sql(table, columns, width, chunk.len());
        let mut values = Vec::with_capacity(chunk.len() * width);
        for (importer, ordinal, path, name) in chunk {
            values.extend([
                Value::Text(workspace_id.to_owned()),
                Value::Text(importer.clone()),
                Value::Integer(i64::from(*ordinal)),
                Value::Text(path.clone()),
            ]);
            if table != "workspace_import_missing_module_dependencies" {
                values.push(Value::Text(name.clone()));
            }
        }
        transaction
            .prepare_cached(&sql)?
            .execute(params_from_iter(values.iter()))?;
    }
    Ok(())
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ImportGraphEdgeFactWriteCounts {
    deleted: i64,
    changed: i64,
    attempted: usize,
}

fn publish_import_graph_edge_fact_delta(
    transaction: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    old_keys: &std::collections::HashSet<(String, i64, String)>,
    edges: &[(String, i64, String, String, Vec<String>)],
) -> Result<ImportGraphEdgeFactWriteCounts> {
    let mut new_keys = std::collections::HashSet::new();
    for (importer, ordinal, target, _, _) in edges {
        assert!(new_keys.insert((importer.clone(), *ordinal, target.clone(),)));
    }
    let mut stale_keys = old_keys.difference(&new_keys).cloned().collect::<Vec<_>>();
    stale_keys.sort_unstable();
    let mut counts = ImportGraphEdgeFactWriteCounts {
        attempted: edges.len(),
        ..ImportGraphEdgeFactWriteCounts::default()
    };
    for chunk in stale_keys.chunks(IMPORT_GRAPH_ROW_BATCH) {
        let sql = delete_edge_fact_keys_sql(chunk.len());
        let mut values = vec![Value::Text(workspace_id.to_owned())];
        for (importer, ordinal, target) in chunk {
            values.extend([
                Value::Text(importer.clone()),
                Value::Integer(*ordinal),
                Value::Text(target.clone()),
            ]);
        }
        counts.deleted += transaction
            .prepare_cached(&sql)?
            .execute(params_from_iter(values.iter()))? as i64;
    }

    for chunk in edges.chunks(IMPORT_GRAPH_ROW_BATCH) {
        let sql = upsert_edge_facts_sql(chunk.len());
        let mut values = Vec::with_capacity(chunk.len() * 5);
        for (importer, ordinal, target, provenance, _) in chunk {
            values.extend([
                Value::Text(workspace_id.to_owned()),
                Value::Text(importer.clone()),
                Value::Integer(*ordinal),
                Value::Text(target.clone()),
                Value::Text(provenance.clone()),
            ]);
        }
        counts.changed += transaction
            .prepare_cached(&sql)?
            .execute(params_from_iter(values.iter()))? as i64;
    }
    Ok(counts)
}

pub(crate) fn delete_importers_sql(table: &str, importer_count: usize) -> String {
    assert!((1..=IMPORT_GRAPH_PATH_BATCH).contains(&importer_count));
    format!(
        "DELETE FROM {table} WHERE workspace_id = ?1 AND importer_path IN ({})",
        std::iter::repeat_n("?", importer_count)
            .collect::<Vec<_>>()
            .join(",")
    )
}

pub(crate) fn delete_edge_facts_by_target_paths_sql(path_count: usize) -> String {
    assert!((1..=IMPORT_GRAPH_PATH_BATCH).contains(&path_count));
    format!(
        "DELETE FROM workspace_import_edge_facts
         INDEXED BY workspace_import_edge_facts_target_idx
         WHERE workspace_id = ?1 AND target_path IN ({})",
        std::iter::repeat_n("?", path_count)
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn edge_pair_values_sql(pair_count: usize) -> String {
    assert!((1..=IMPORT_GRAPH_PATH_BATCH).contains(&pair_count));
    std::iter::repeat_n("(?, ?)", pair_count)
        .collect::<Vec<_>>()
        .join(",")
}

pub(crate) fn existing_edge_pairs_sql(pair_count: usize) -> String {
    format!(
        "SELECT importer_path, target_path FROM workspace_import_edges
         WHERE workspace_id = ?1 AND (importer_path, target_path) IN (VALUES {})",
        edge_pair_values_sql(pair_count)
    )
}

pub(crate) fn edge_pairs_with_facts_sql(pair_count: usize) -> String {
    format!(
        "WITH affected(importer_path, target_path) AS (VALUES {})
         SELECT affected.importer_path, affected.target_path FROM affected
         WHERE EXISTS (
             SELECT 1 FROM workspace_import_edge_facts AS fact
               INDEXED BY workspace_import_edge_facts_source_target_idx
             WHERE fact.workspace_id = ?
               AND fact.importer_path = affected.importer_path
               AND fact.target_path = affected.target_path
         )",
        edge_pair_values_sql(pair_count)
    )
}

pub(crate) fn delete_edge_pairs_sql(pair_count: usize) -> String {
    format!(
        "DELETE FROM workspace_import_edges
         WHERE workspace_id = ?1 AND (importer_path, target_path) IN (VALUES {})",
        edge_pair_values_sql(pair_count)
    )
}

pub(crate) fn insert_edge_pairs_sql(pair_count: usize) -> String {
    assert!((1..=IMPORT_GRAPH_PATH_BATCH).contains(&pair_count));
    let rows = std::iter::repeat_n("(?, ?, ?)", pair_count)
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "INSERT OR IGNORE INTO workspace_import_edges(
             workspace_id, importer_path, target_path
         ) VALUES {rows}"
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkspaceImportDirection {
    Forward,
    Reverse,
}

#[derive(Debug)]
pub(crate) struct WorkspaceImportGraphRead {
    pub edges: Vec<(String, String)>,
    pub exhausted: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct WorkspaceImportGraphSource {
    pub source_path: String,
    pub source_identity: [u8; 32],
    pub module_path_keys: Vec<String>,
    pub complete_resolution_dependencies: bool,
    pub input_digests: Option<crate::analyzer::ImportGraphInputDigests>,
    /// Present only for changed files whose provider supplied current
    /// structured binding rows for the name-level cutoff.
    pub binding_surface: Option<Vec<WorkspaceImportGraphBinding>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct WorkspaceImportGraphBinding {
    pub module_path: String,
    pub name: String,
    pub namespace: String,
    pub visibility_kind: String,
    pub visibility_scope: String,
    pub origin_path: String,
    pub origin_module_path: String,
    pub origin_name: String,
    pub route_path: String,
}

impl WorkspaceImportGraphBinding {
    pub(crate) fn from_provider_surface(
        binding: crate::analyzer::ImportGraphBindingSurface,
    ) -> Vec<Self> {
        let route_paths = binding
            .route_files
            .iter()
            .map(crate::path_utils::rel_path_string)
            .collect::<Vec<_>>();
        assert!(
            !route_paths.is_empty(),
            "effective Rust bindings retain at least their origin route"
        );
        route_paths
            .into_iter()
            .map(|route_path| Self {
                module_path: binding.module_path.clone(),
                name: binding.name.clone(),
                namespace: binding.namespace.clone(),
                visibility_kind: binding.visibility_kind.clone(),
                visibility_scope: binding.visibility_scope.clone(),
                origin_path: crate::path_utils::rel_path_string(&binding.origin_file),
                origin_module_path: binding.origin_module_path.clone(),
                origin_name: binding.origin_name.clone(),
                route_path,
            })
            .collect()
    }
}

#[derive(Debug)]
pub(crate) struct WorkspaceImportGraphEdge {
    pub importer_path: String,
    pub import_ordinal: u32,
    pub target_path: String,
    pub provenance_json: String,
    pub route_dependencies: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct WorkspaceImportGraphDependencies {
    pub importer_path: String,
    pub lookups: Vec<(u32, String, String)>,
    pub missing_module_path_keys: Vec<(u32, String)>,
}

#[derive(Debug)]
pub(crate) struct WorkspaceImportGraphRefreshPlan {
    pub current: bool,
    pub full_rebuild: bool,
    pub previous_identity: Option<[u8; 32]>,
    pub changed_module_path_keys: Vec<String>,
    /// Importers whose source content changed, or every current source for a
    /// full rebuild. Every import in these files must be replaced.
    pub dirty_importer_paths: Vec<String>,
    /// Exact Rust imports invalidated by a consulted file or missing module
    /// key. Their sibling imports remain reusable.
    pub dirty_import_ordinals: Vec<(String, u32)>,
    /// Exact imports whose consulted-file or missing-module lookup rows
    /// changed. Route-only invalidation keeps these lookup rows in place.
    pub dirty_lookup_ordinals: Vec<(String, u32)>,
    pub changed_source_paths: Vec<String>,
    pub removed_source_paths: Vec<String>,
}

impl AnalyzerStore {
    pub(crate) fn read_dynamic_import_sources(
        &self,
        workspace_id: &WorkspaceId,
        seed_paths: Option<&[(String, String)]>,
    ) -> Result<Vec<(String, String)>> {
        let snapshots = self.current_workspace_snapshots(workspace_id)?;
        let connection = self.read_conn_for_workspace(&snapshots)?;
        super::ensure_revisioned_workspace_views(&connection)?;
        let encoded_seeds = seed_paths
            .map(serde_json::to_string)
            .transpose()
            .map_err(|error| StoreError::new(error.to_string()))?;
        let mut statement = connection.prepare_cached(DYNAMIC_IMPORT_SOURCES_SQL)?;
        let rows = statement.query_map([encoded_seeds.as_deref()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|error| StoreError::new(error.to_string()))
    }

    fn current_workspace_snapshots(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<super::WorkspaceSnapshots> {
        let connection = self.read_conn()?;
        let mut statement = connection.prepare_cached(
            "SELECT heads.lang, heads.generation, heads.revision
             FROM workspace_heads AS heads
             LEFT JOIN analysis_epochs AS epochs ON epochs.lang = heads.lang
             WHERE heads.workspace_id = ?1
               AND heads.generation = COALESCE(epochs.generation, 0)",
        )?;
        let rows = statement.query_map([workspace_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        let mut snapshots = super::WorkspaceSnapshots::default();
        for row in rows {
            let (lang, generation, revision) = row?;
            snapshots.insert(
                lang.clone(),
                super::WorkspaceSnapshotId {
                    workspace_id: workspace_id.clone(),
                    lang,
                    generation: super::GenerationId(generation),
                    revision,
                },
            );
        }
        Ok(snapshots)
    }

    pub(crate) fn workspace_import_resolver_identity(
        &self,
        config_debug: String,
        languages: &[String],
    ) -> Result<[u8; 32]> {
        // The epoch and generation identify analyzer fact semantics. Workspace
        // source and module changes are tracked separately by the graph
        // manifest and source rows, so this stays stable across normal edits.
        let mut languages = languages.to_vec();
        languages.sort_unstable();
        languages.dedup();
        self.conn.execute(move |connection| -> Result<[u8; 32]> {
            let mut hasher = CanonicalHasher::new(b"bifrost-workspace-import-resolver:v1");
            hasher.field("config", config_debug.as_bytes());
            for language in languages {
                let epoch = connection
                    .query_row(
                        "SELECT epoch, generation FROM analysis_epochs WHERE lang = ?1",
                        [&language],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
                    )
                    .optional()?;
                let (epoch, generation) = epoch.unwrap_or_default();
                hasher.field(&language, epoch.as_bytes());
                hasher.field("generation", &generation.to_be_bytes());
            }
            Ok(hasher.finish())
        })
    }

    pub(crate) fn plan_workspace_import_graph_refresh(
        &self,
        workspace_id: &WorkspaceId,
        content_identity: &[u8; 32],
        resolver_identity: &[u8; 32],
        sources: &[WorkspaceImportGraphSource],
    ) -> Result<WorkspaceImportGraphRefreshPlan> {
        let workspace_id = workspace_id.as_str().to_owned();
        let content_identity = *content_identity;
        let resolver_identity = *resolver_identity;
        let sources = sources.to_vec();
        self.conn.execute(move |connection| {
            let transaction = connection.unchecked_transaction()?;
            let manifest = transaction
                .query_row(
                    "SELECT content_identity, resolver_identity
                     FROM workspace_import_graphs WHERE workspace_id = ?1",
                    [&workspace_id],
                    |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )
                .optional()?;
            let Some((stored_identity, stored_resolver_identity)) = manifest else {
                transaction.commit()?;
                return Ok(WorkspaceImportGraphRefreshPlan {
                    current: false,
                    full_rebuild: true,
                    previous_identity: None,
                    changed_module_path_keys: Vec::new(),
                    dirty_importer_paths: sources
                        .iter()
                        .map(|source| source.source_path.clone())
                        .collect(),
                    dirty_import_ordinals: Vec::new(),
                    dirty_lookup_ordinals: Vec::new(),
                    changed_source_paths: sources
                        .iter()
                        .map(|source| source.source_path.clone())
                        .collect(),
                    removed_source_paths: Vec::new(),
                });
            };
            let stored_identity: [u8; 32] = stored_identity
                .try_into()
                .expect("schema checks import graph identity width");
            if stored_identity == content_identity
                && stored_resolver_identity.as_slice() == resolver_identity.as_slice()
            {
                transaction.commit()?;
                return Ok(WorkspaceImportGraphRefreshPlan {
                    current: true,
                    full_rebuild: false,
                    previous_identity: Some(stored_identity),
                    changed_module_path_keys: Vec::new(),
                    dirty_importer_paths: Vec::new(),
                    dirty_import_ordinals: Vec::new(),
                    dirty_lookup_ordinals: Vec::new(),
                    changed_source_paths: Vec::new(),
                    removed_source_paths: Vec::new(),
                });
            }
            let resolver_changed =
                stored_resolver_identity.as_slice() != resolver_identity.as_slice();

            let mut previous_sources = std::collections::HashMap::new();
            {
                let mut statement = transaction.prepare_cached(
                    "SELECT source_path, source_identity, complete_resolution_dependencies,
                            binding_surface_digest, import_rows_digest
                     FROM workspace_import_sources WHERE workspace_id = ?1",
                )?;
                let rows = statement.query_map([&workspace_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, bool>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                        row.get::<_, Option<Vec<u8>>>(4)?,
                    ))
                })?;
                for row in rows {
                    let (path, identity, complete_dependencies, binding_digest, import_digest) =
                        row?;
                    previous_sources.insert(
                        path,
                        (
                            identity,
                            complete_dependencies,
                            binding_digest,
                            import_digest,
                        ),
                    );
                }
            }
            let mut previous_module_keys: std::collections::HashMap<
                String,
                std::collections::HashSet<String>,
            > = std::collections::HashMap::new();
            {
                let mut statement = transaction.prepare_cached(
                    "SELECT source_path, module_path_key
                     FROM workspace_import_source_modules WHERE workspace_id = ?1",
                )?;
                let rows = statement.query_map([&workspace_id], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?;
                for row in rows {
                    let (path, key) = row?;
                    previous_module_keys.entry(path).or_default().insert(key);
                }
            }
            let mut current_sources = std::collections::HashMap::with_capacity(sources.len());
            let mut changed_paths = std::collections::HashSet::new();
            for source in &sources {
                assert!(
                    current_sources
                        .insert(source.source_path.as_str(), source.source_identity)
                        .is_none(),
                    "one import graph source identity per path"
                );
                if previous_sources.get(&source.source_path).is_none_or(
                    |(identity, complete_dependencies, _, _)| {
                        identity.as_slice() != source.source_identity.as_slice()
                            || *complete_dependencies != source.complete_resolution_dependencies
                    },
                ) {
                    changed_paths.insert(source.source_path.clone());
                }
            }
            let mut changed_source_paths = changed_paths
                .iter()
                .filter(|path| current_sources.contains_key(path.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            changed_source_paths.sort_unstable();
            let removed_source_paths = previous_sources
                .keys()
                .filter(|path| !current_sources.contains_key(path.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            let current_module_keys = sources
                .iter()
                .map(|source| {
                    (
                        source.source_path.as_str(),
                        source
                            .module_path_keys
                            .iter()
                            .cloned()
                            .collect::<std::collections::HashSet<_>>(),
                    )
                })
                .collect::<std::collections::HashMap<_, _>>();
            let mut changed_module_keys = std::collections::HashSet::new();
            for (path, old_keys) in &previous_module_keys {
                let new_keys = current_module_keys.get(path.as_str());
                for key in old_keys {
                    if new_keys.is_none_or(|keys| !keys.contains(key)) {
                        changed_module_keys.insert(key.clone());
                    }
                }
            }
            for (path, new_keys) in &current_module_keys {
                let old_keys = previous_module_keys.get(*path);
                for key in new_keys {
                    if old_keys.is_none_or(|keys| !keys.contains(key)) {
                        changed_module_keys.insert(key.clone());
                    }
                }
            }
            let mut changed_module_path_keys = changed_module_keys.into_iter().collect::<Vec<_>>();
            changed_module_path_keys.sort_unstable();
            changed_paths.extend(removed_source_paths.iter().cloned());

            let incomplete_removed_source = removed_source_paths.iter().any(|path| {
                previous_sources
                    .get(path)
                    .is_none_or(|(_, complete_dependencies, _, _)| !complete_dependencies)
            });
            let incomplete_changed_source = sources.iter().any(|source| {
                changed_paths.contains(&source.source_path)
                    && !source.complete_resolution_dependencies
            });
            let full_rebuild = resolver_changed
                || changed_paths.is_empty()
                // Providers resolve imports within their own language. An
                // unchanged provider's edges can therefore be carried forward
                // when a different, dependency-complete language changes.
                // Changes to sources whose provider lacks structured lookup
                // dependencies still use the conservative full rebuild.
                || incomplete_changed_source
                || incomplete_removed_source;
            let dirty_importers = if full_rebuild {
                sources
                    .iter()
                    .map(|source| source.source_path.clone())
                    .collect::<std::collections::HashSet<_>>()
            } else {
                changed_paths
                    .iter()
                    .filter(|path| current_sources.contains_key(path.as_str()))
                    .cloned()
                    .collect()
            };
            let mut dirty_import_ordinals = std::collections::HashSet::new();
            let mut dirty_lookup_ordinals = std::collections::HashSet::new();
            if !full_rebuild {
                let mut changed_binding_names: std::collections::HashMap<
                    String,
                    std::collections::HashSet<String>,
                > = std::collections::HashMap::new();
                let mut changed_glob_surfaces = std::collections::HashSet::new();
                let mut coarse_changed_paths = std::collections::HashSet::new();
                for path in &changed_paths {
                    if removed_source_paths.iter().any(|removed| removed == path) {
                        // Source removal can invalidate positive lookups even
                        // when the old module had an empty binding surface.
                        coarse_changed_paths.insert(path.clone());
                        continue;
                    }
                    let source = sources
                        .iter()
                        .find(|source| source.source_path == *path)
                        .expect("changed source path belongs to the current inventory");
                    let Some(new_rows) = &source.binding_surface else {
                        coarse_changed_paths.insert(path.clone());
                        continue;
                    };
                    let mut old_rows = std::collections::HashSet::new();
                    {
                        let mut statement = transaction.prepare_cached(
                            "SELECT module_path, name, namespace, visibility_kind,
                                    visibility_scope, origin_path, origin_module_path,
                                    origin_name, route_path
                             FROM workspace_import_source_bindings
                             WHERE workspace_id = ?1 AND source_path = ?2",
                        )?;
                        let rows = statement.query_map(params![&workspace_id, path], |row| {
                            Ok(WorkspaceImportGraphBinding {
                                module_path: row.get(0)?,
                                name: row.get(1)?,
                                namespace: row.get(2)?,
                                visibility_kind: row.get(3)?,
                                visibility_scope: row.get(4)?,
                                origin_path: row.get(5)?,
                                origin_module_path: row.get(6)?,
                                origin_name: row.get(7)?,
                                route_path: row.get(8)?,
                            })
                        })?;
                        for row in rows {
                            old_rows.insert(row?);
                        }
                    }
                    let new_rows = new_rows
                        .iter()
                        .cloned()
                        .collect::<std::collections::HashSet<_>>();
                    for binding in old_rows.symmetric_difference(&new_rows) {
                        changed_binding_names
                            .entry(path.clone())
                            .or_default()
                            .insert(binding.name.clone());
                    }
                    let old_glob_surface = old_rows
                        .iter()
                        .map(|binding| {
                            (
                                &binding.module_path,
                                &binding.name,
                                &binding.namespace,
                                &binding.visibility_kind,
                                &binding.visibility_scope,
                                &binding.origin_path,
                                &binding.origin_module_path,
                                &binding.origin_name,
                            )
                        })
                        .collect::<std::collections::HashSet<_>>();
                    let new_glob_surface = new_rows
                        .iter()
                        .map(|binding| {
                            (
                                &binding.module_path,
                                &binding.name,
                                &binding.namespace,
                                &binding.visibility_kind,
                                &binding.visibility_scope,
                                &binding.origin_path,
                                &binding.origin_module_path,
                                &binding.origin_name,
                            )
                        })
                        .collect::<std::collections::HashSet<_>>();
                    if old_glob_surface != new_glob_surface {
                        changed_glob_surfaces.insert(path.clone());
                    }
                }
                for chunk in coarse_changed_paths
                    .into_iter()
                    .collect::<Vec<_>>()
                    .chunks(IMPORT_GRAPH_PATH_BATCH)
                {
                    let sql = format!(
                        "SELECT DISTINCT dependency.importer_path, dependency.import_ordinal
                         FROM workspace_import_candidate_file_dependencies AS dependency
                           INDEXED BY workspace_import_candidate_file_dependencies_consulted_idx
                         WHERE dependency.workspace_id = ?1
                           AND dependency.consulted_path IN ({})",
                        std::iter::repeat_n("?", chunk.len())
                            .collect::<Vec<_>>()
                            .join(",")
                    );
                    let mut values = vec![Value::Text(workspace_id.clone())];
                    values.extend(chunk.iter().cloned().map(Value::Text));
                    let mut statement = transaction.prepare_cached(&sql)?;
                    let rows = statement.query_map(params_from_iter(values.iter()), |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                    })?;
                    for row in rows {
                        let (path, ordinal) = row?;
                        let key = (
                            path,
                            u32::try_from(ordinal).expect("import ordinal fits u32"),
                        );
                        dirty_import_ordinals.insert(key.clone());
                        dirty_lookup_ordinals.insert(key);
                    }
                }
                for (consulted_path, names) in changed_binding_names {
                    let mut names = names.into_iter().collect::<Vec<_>>();
                    names.sort_unstable();
                    for chunk in names.chunks(IMPORT_GRAPH_PATH_BATCH) {
                        if chunk.is_empty() {
                            continue;
                        }
                        let placeholders = std::iter::repeat_n("?", chunk.len())
                            .collect::<Vec<_>>()
                            .join(",");
                        for (table, index, path_column) in [
                            (
                                "workspace_import_candidate_file_dependencies",
                                "workspace_import_candidate_file_dependencies_consulted_idx",
                                "consulted_path",
                            ),
                            (
                                "workspace_import_route_dependencies",
                                "workspace_import_route_dependencies_name_idx",
                                "traversed_path",
                            ),
                        ] {
                            let sql = format!(
                                "SELECT DISTINCT importer_path, import_ordinal FROM {table}
                                   INDEXED BY {index}
                                 WHERE workspace_id = ?1 AND {path_column} = ?2
                                   AND name IN ({placeholders})"
                            );
                            let mut values = vec![
                                Value::Text(workspace_id.clone()),
                                Value::Text(consulted_path.clone()),
                            ];
                            values.extend(chunk.iter().cloned().map(Value::Text));
                            let mut statement = transaction.prepare_cached(&sql)?;
                            let rows = statement
                                .query_map(params_from_iter(values.iter()), |row| {
                                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                                })?;
                            for row in rows {
                                let (path, ordinal) = row?;
                                let key = (
                                    path,
                                    u32::try_from(ordinal).expect("import ordinal fits u32"),
                                );
                                dirty_import_ordinals.insert(key.clone());
                                if table == "workspace_import_candidate_file_dependencies" {
                                    dirty_lookup_ordinals.insert(key);
                                }
                            }
                        }
                    }
                }
                for consulted_path in changed_glob_surfaces {
                    for (table, index, path_column) in [
                        (
                            "workspace_import_candidate_file_dependencies",
                            "workspace_import_candidate_file_dependencies_consulted_idx",
                            "consulted_path",
                        ),
                        (
                            "workspace_import_route_dependencies",
                            "workspace_import_route_dependencies_name_idx",
                            "traversed_path",
                        ),
                    ] {
                        let sql = format!(
                            "SELECT DISTINCT importer_path, import_ordinal FROM {table}
                               INDEXED BY {index}
                             WHERE workspace_id = ?1 AND {path_column} = ?2 AND name = '*'"
                        );
                        let mut statement = transaction.prepare_cached(&sql)?;
                        let rows = statement
                            .query_map(params![&workspace_id, consulted_path], |row| {
                                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                            })?;
                        for row in rows {
                            let (path, ordinal) = row?;
                            let key = (
                                path,
                                u32::try_from(ordinal).expect("import ordinal fits u32"),
                            );
                            dirty_import_ordinals.insert(key.clone());
                            if table == "workspace_import_candidate_file_dependencies" {
                                dirty_lookup_ordinals.insert(key);
                            }
                        }
                    }
                }
                for chunk in changed_module_path_keys.chunks(IMPORT_GRAPH_PATH_BATCH) {
                    if chunk.is_empty() {
                        continue;
                    }
                    let sql = format!(
                        "SELECT DISTINCT dependency.importer_path, dependency.import_ordinal
                         FROM workspace_import_missing_module_dependencies AS dependency
                           INDEXED BY workspace_import_missing_module_dependencies_key_idx
                         WHERE dependency.workspace_id = ?1
                           AND dependency.module_path_key IN ({})",
                        std::iter::repeat_n("?", chunk.len())
                            .collect::<Vec<_>>()
                            .join(",")
                    );
                    let mut values = vec![Value::Text(workspace_id.clone())];
                    values.extend(chunk.iter().cloned().map(Value::Text));
                    let mut statement = transaction.prepare_cached(&sql)?;
                    let rows = statement.query_map(params_from_iter(values.iter()), |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                    })?;
                    for row in rows {
                        let (path, ordinal) = row?;
                        let key = (
                            path,
                            u32::try_from(ordinal).expect("import ordinal fits u32"),
                        );
                        dirty_import_ordinals.insert(key.clone());
                        dirty_lookup_ordinals.insert(key);
                    }
                }
            }
            let current_paths = current_sources
                .keys()
                .copied()
                .collect::<std::collections::HashSet<_>>();
            dirty_import_ordinals.retain(|(path, _)| {
                current_paths.contains(path.as_str()) && !dirty_importers.contains(path)
            });
            dirty_lookup_ordinals.retain(|(path, _)| {
                current_paths.contains(path.as_str()) && !dirty_importers.contains(path)
            });
            let mut dirty_importer_paths = dirty_importers.into_iter().collect::<Vec<_>>();
            dirty_importer_paths.sort_unstable();
            let mut dirty_import_ordinals = dirty_import_ordinals.into_iter().collect::<Vec<_>>();
            dirty_import_ordinals.sort_unstable();
            let mut dirty_lookup_ordinals = dirty_lookup_ordinals.into_iter().collect::<Vec<_>>();
            dirty_lookup_ordinals.sort_unstable();
            let mut removed_source_paths = removed_source_paths;
            removed_source_paths.sort_unstable();
            removed_source_paths.dedup();
            transaction.commit()?;
            Ok(WorkspaceImportGraphRefreshPlan {
                current: false,
                full_rebuild,
                previous_identity: Some(stored_identity),
                changed_module_path_keys,
                dirty_importer_paths,
                dirty_import_ordinals,
                dirty_lookup_ordinals,
                changed_source_paths,
                removed_source_paths,
            })
        })
    }

    pub(crate) fn advance_workspace_import_graph_identity(
        &self,
        workspace_id: &WorkspaceId,
        content_identity: &[u8; 32],
        resolver_identity: &[u8; 32],
        plan: &WorkspaceImportGraphRefreshPlan,
        sources: &[WorkspaceImportGraphSource],
    ) -> Result<bool> {
        if plan.full_rebuild
            || !plan.removed_source_paths.is_empty()
            || !plan.changed_module_path_keys.is_empty()
            || plan.changed_source_paths.is_empty()
        {
            return Ok(false);
        }
        let Some(previous_identity) = plan.previous_identity else {
            return Ok(false);
        };
        let mut changed_sources = Vec::with_capacity(plan.changed_source_paths.len());
        for path in &plan.changed_source_paths {
            let Some(source) = sources.iter().find(|source| source.source_path == *path) else {
                return Ok(false);
            };
            let Some(digests) = source.input_digests else {
                return Ok(false);
            };
            if !source.complete_resolution_dependencies {
                return Ok(false);
            }
            changed_sources.push((path.clone(), source.source_identity, digests));
        }
        let workspace_id = workspace_id.as_str().to_owned();
        let content_identity = *content_identity;
        let resolver_identity = *resolver_identity;
        self.conn.execute(move |connection| {
            let transaction =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let manifest = transaction
                .query_row(
                    "SELECT content_identity, resolver_identity
                     FROM workspace_import_graphs WHERE workspace_id = ?1",
                    [&workspace_id],
                    |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )
                .optional()?;
            let Some((stored_identity, stored_resolver_identity)) = manifest else {
                transaction.commit()?;
                return Ok(false);
            };
            if stored_identity.as_slice() == content_identity.as_slice() {
                transaction.commit()?;
                return Ok(true);
            }
            if stored_identity.as_slice() != previous_identity.as_slice()
                || stored_resolver_identity.as_slice() != resolver_identity.as_slice()
            {
                transaction.commit()?;
                return Ok(false);
            }
            {
                let mut update_source = transaction.prepare_cached(
                    "UPDATE workspace_import_sources
                     SET source_identity = ?3
                     WHERE workspace_id = ?1 AND source_path = ?2
                       AND binding_surface_digest = ?4 AND import_rows_digest = ?5",
                )?;
                for (path, source_identity, digests) in &changed_sources {
                    let changed = update_source.execute(params![
                        &workspace_id,
                        path,
                        source_identity.as_slice(),
                        digests.binding_surface.as_slice(),
                        digests.import_rows.as_slice(),
                    ])?;
                    if changed != 1 {
                        return Ok(false);
                    }
                }
            }
            let changed = transaction.execute(
                "UPDATE workspace_import_graphs SET content_identity = ?2
                 WHERE workspace_id = ?1 AND content_identity = ?3
                   AND resolver_identity = ?4",
                params![
                    &workspace_id,
                    content_identity.as_slice(),
                    previous_identity.as_slice(),
                    resolver_identity.as_slice(),
                ],
            )?;
            if changed != 1 {
                return Ok(false);
            }
            transaction.commit()?;
            Ok(true)
        })
    }

    // Keep the snapshot identity, plan, and provider rows explicit at the store boundary.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn publish_workspace_import_graph_refresh(
        &self,
        workspace_id: &WorkspaceId,
        content_identity: &[u8; 32],
        resolver_identity: &[u8; 32],
        plan: &WorkspaceImportGraphRefreshPlan,
        source_count: usize,
        changed_sources: &[WorkspaceImportGraphSource],
        edges: &[WorkspaceImportGraphEdge],
        dependencies: &[WorkspaceImportGraphDependencies],
    ) -> Result<bool> {
        if plan.current {
            return Ok(true);
        }
        let publish_prepare_started = std::time::Instant::now();
        let workspace_id = workspace_id.as_str().to_owned();
        let content_identity = *content_identity;
        let resolver_identity = *resolver_identity;
        let plan_previous = plan.previous_identity;
        let full_importer_paths = plan.dirty_importer_paths.clone();
        let dirty_import_ordinals = plan.dirty_import_ordinals.clone();
        let removed_source_paths = plan.removed_source_paths.clone();
        let changed_source_paths = plan
            .changed_source_paths
            .iter()
            .map(String::as_str)
            .collect::<std::collections::HashSet<_>>();
        let changed_sources = changed_sources
            .iter()
            .filter(|source| {
                plan.full_rebuild || changed_source_paths.contains(source.source_path.as_str())
            })
            .cloned()
            .collect::<Vec<_>>();
        let edges = edges
            .iter()
            .map(|edge| {
                (
                    edge.importer_path.clone(),
                    i64::from(edge.import_ordinal),
                    edge.target_path.clone(),
                    edge.provenance_json.clone(),
                    edge.route_dependencies.clone(),
                )
            })
            .collect::<Vec<_>>();
        let dependencies = dependencies
            .iter()
            .map(|dependency| {
                (
                    dependency.importer_path.clone(),
                    dependency.lookups.clone(),
                    dependency.missing_module_path_keys.clone(),
                )
            })
            .collect::<Vec<_>>();
        let source_count = i64::try_from(source_count)
            .map_err(|_| StoreError::new("workspace import source count exceeds SQLite range"))?;
        let profile_sql = std::env::var_os("BIFROST_IMPORT_GRAPH_SQL_PROFILE").is_some();
        let input_prepare_ns = publish_prepare_started.elapsed().as_nanos();

        self.conn.execute(move |connection| {
            let mut publish_stage_started = std::time::Instant::now();
            let mut publish_stages = vec![("input_preparation", input_prepare_ns)];
            macro_rules! mark_publish_stage {
                ($name:literal) => {
                    if profile_sql {
                        publish_stages.push(($name, publish_stage_started.elapsed().as_nanos()));
                        publish_stage_started = std::time::Instant::now();
                    }
                };
            }
            if profile_sql {
                IMPORT_GRAPH_STATEMENT_PROFILE
                    .lock()
                    .expect("import graph SQL profile lock")
                    .clear();
            }
            let transaction =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let stored_identity = transaction
                .query_row(
                    "SELECT content_identity FROM workspace_import_graphs WHERE workspace_id = ?1",
                    [&workspace_id],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?;
            if stored_identity.as_deref() != plan_previous.as_ref().map(<[u8; 32]>::as_slice) {
                let already_current =
                    stored_identity.as_deref() == Some(content_identity.as_slice());
                transaction.commit()?;
                return Ok(already_current);
            }
            let full_importer_path_set = full_importer_paths
                .iter()
                .map(String::as_str)
                .collect::<std::collections::HashSet<_>>();
            let dirty_import_ordinal_set = dirty_import_ordinals
                .iter()
                .map(|(path, ordinal)| (path.as_str(), *ordinal))
                .collect::<std::collections::HashSet<_>>();
            if profile_sql {
                transaction.trace_v2(
                    TraceEventCodes::SQLITE_TRACE_PROFILE,
                    Some(record_import_graph_statement_profile),
                );
            }
            mark_publish_stage!("transaction_start_and_identity");
            if stored_identity.is_none() {
                transaction.execute(
                    "INSERT INTO workspace_import_graphs(
                        workspace_id, content_identity, resolver_identity, source_count, edge_count
                     ) VALUES(?1, ?2, ?3, 0, 0)",
                    params![
                        &workspace_id,
                        content_identity.as_slice(),
                        resolver_identity.as_slice()
                    ],
                )?;
            }

            let mut affected_pairs = std::collections::HashSet::new();
            let mut old_edge_fact_keys = std::collections::HashSet::new();
            for chunk in full_importer_paths.chunks(IMPORT_GRAPH_PATH_BATCH) {
                if chunk.is_empty() {
                    continue;
                }
                let sql = edge_fact_rows_by_importers_sql(chunk.len());
                let mut values = vec![Value::Text(workspace_id.clone())];
                values.extend(chunk.iter().cloned().map(Value::Text));
                let mut statement = transaction.prepare_cached(&sql)?;
                let rows = statement.query_map(params_from_iter(values.iter()), |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })?;
                for row in rows {
                    let (importer, ordinal, target) = row?;
                    affected_pairs.insert((importer.clone(), target.clone()));
                    assert!(old_edge_fact_keys.insert((importer, ordinal, target)));
                }
            }
            {
                for chunk in dirty_import_ordinals.chunks(IMPORT_GRAPH_ORDINAL_BATCH) {
                    let sql = edge_fact_rows_by_ordinals_sql(chunk.len());
                    let mut values = vec![Value::Text(workspace_id.clone())];
                    for (importer, ordinal) in chunk {
                        values.push(Value::Text(importer.clone()));
                        values.push(Value::Integer(i64::from(*ordinal)));
                    }
                    let mut statement = transaction.prepare_cached(&sql)?;
                    let rows = statement.query_map(
                        params_from_iter(values.iter()),
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, i64>(1)?,
                                row.get::<_, String>(2)?,
                            ))
                        },
                    )?;
                    for row in rows {
                        let (importer, ordinal, target) = row?;
                        affected_pairs.insert((importer.clone(), target.clone()));
                        assert!(old_edge_fact_keys.insert((importer, ordinal, target)));
                    }
                }
            }
            for chunk in removed_source_paths.chunks(IMPORT_GRAPH_PATH_BATCH) {
                if chunk.is_empty() {
                    continue;
                }
                for column in ["importer_path", "target_path"] {
                    let sql = edge_fact_pairs_by_paths_sql(column, chunk.len());
                    let mut values = vec![Value::Text(workspace_id.clone())];
                    values.extend(chunk.iter().cloned().map(Value::Text));
                    let mut statement = transaction.prepare_cached(&sql)?;
                    let rows = statement.query_map(params_from_iter(values.iter()), |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?;
                    affected_pairs.extend(rows.collect::<rusqlite::Result<Vec<_>>>()?);
                }
            }
            affected_pairs.extend(
                edges
                    .iter()
                    .map(|(importer, _, target, _, _)| (importer.clone(), target.clone())),
            );
            let mut affected_pairs = affected_pairs.into_iter().collect::<Vec<_>>();
            affected_pairs.sort_unstable();
            affected_pairs.dedup();
            let mut old_adjacency_pairs = std::collections::HashSet::new();
            for chunk in affected_pairs.chunks(IMPORT_GRAPH_PATH_BATCH) {
                let sql = existing_edge_pairs_sql(chunk.len());
                let mut values = vec![Value::Text(workspace_id.clone())];
                for (importer, target) in chunk {
                    values.push(Value::Text(importer.clone()));
                    values.push(Value::Text(target.clone()));
                }
                let mut statement = transaction.prepare_cached(&sql)?;
                let rows = statement.query_map(params_from_iter(values.iter()), |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?;
                old_adjacency_pairs.extend(rows.collect::<rusqlite::Result<Vec<_>>>()?);
            }

            for table in [
                "workspace_import_candidate_file_dependencies",
                "workspace_import_route_dependencies",
                "workspace_import_missing_module_dependencies",
            ] {
                for chunk in full_importer_paths.chunks(IMPORT_GRAPH_PATH_BATCH) {
                    if chunk.is_empty() {
                        continue;
                    }
                    let sql = delete_importers_sql(table, chunk.len());
                    let mut values = vec![Value::Text(workspace_id.clone())];
                    values.extend(chunk.iter().cloned().map(Value::Text));
                    transaction
                        .prepare_cached(&sql)?
                        .execute(params_from_iter(values.iter()))?;
                }
            }
            let old_candidate_rows = read_import_graph_dependency_rows(
                &transaction,
                &workspace_id,
                "workspace_import_candidate_file_dependencies",
                &dirty_import_ordinals,
            )?;
            let old_route_rows = read_import_graph_dependency_rows(
                &transaction,
                &workspace_id,
                "workspace_import_route_dependencies",
                &dirty_import_ordinals,
            )?;
            let old_missing_rows = read_import_graph_dependency_rows(
                &transaction,
                &workspace_id,
                "workspace_import_missing_module_dependencies",
                &dirty_import_ordinals,
            )?;
            mark_publish_stage!("old_edges_and_dependency_snapshot");

            let mut deleted_edge_fact_count = 0_i64;
            for chunk in removed_source_paths.chunks(IMPORT_GRAPH_PATH_BATCH) {
                if chunk.is_empty() {
                    continue;
                }
                let sql = delete_edge_facts_by_target_paths_sql(chunk.len());
                let mut values = vec![Value::Text(workspace_id.clone())];
                values.extend(chunk.iter().cloned().map(Value::Text));
                deleted_edge_fact_count += transaction
                    .prepare_cached(&sql)?
                    .execute(params_from_iter(values.iter()))? as i64;
            }

            {
                let mut insert = transaction.prepare_cached(
                    "INSERT INTO workspace_import_sources(
                        workspace_id, source_path, source_identity,
                        complete_resolution_dependencies, binding_surface_digest,
                        import_rows_digest
                     ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(workspace_id, source_path)
                     DO UPDATE SET source_identity = excluded.source_identity,
                                   complete_resolution_dependencies = excluded.complete_resolution_dependencies,
                                   binding_surface_digest = excluded.binding_surface_digest,
                                   import_rows_digest = excluded.import_rows_digest",
                )?;
                for source in &changed_sources {
                    insert.execute(params![
                        &workspace_id,
                        &source.source_path,
                        source.source_identity.as_slice(),
                        source.complete_resolution_dependencies,
                        source.input_digests
                            .as_ref()
                            .map(|digests| digests.binding_surface.as_slice()),
                        source.input_digests
                            .as_ref()
                            .map(|digests| digests.import_rows.as_slice()),
                    ])?;
                }
            }
            {
                let mut delete = transaction.prepare_cached(
                    "DELETE FROM workspace_import_sources
                     WHERE workspace_id = ?1 AND source_path = ?2",
                )?;
                for source_path in &removed_source_paths {
                    delete.execute(params![&workspace_id, source_path])?;
                }
            }

            {
                let mut delete = transaction.prepare_cached(
                    "DELETE FROM workspace_import_source_modules
                     WHERE workspace_id = ?1 AND source_path = ?2",
                )?;
                for source in &changed_sources {
                    delete.execute(params![&workspace_id, &source.source_path])?;
                    for chunk in source
                        .module_path_keys
                        .chunks(IMPORT_GRAPH_ROW_BATCH)
                    {
                        let sql = import_graph_insert_sql(
                            "workspace_import_source_modules",
                            "workspace_id, source_path, module_path_key",
                            3,
                            chunk.len(),
                        );
                        let mut values = Vec::with_capacity(chunk.len() * 3);
                        for key in chunk {
                            values.push(Value::Text(workspace_id.clone()));
                            values.push(Value::Text(source.source_path.clone()));
                            values.push(Value::Text(key.clone()));
                        }
                        transaction
                            .prepare_cached(&sql)?
                            .execute(params_from_iter(values.iter()))?;
                    }
                }
            }
            {
                let mut delete = transaction.prepare_cached(
                    "DELETE FROM workspace_import_source_bindings
                     WHERE workspace_id = ?1 AND source_path = ?2",
                )?;
                for source in &changed_sources {
                    delete.execute(params![&workspace_id, &source.source_path])?;
                    if let Some(bindings) = &source.binding_surface {
                        for chunk in bindings.chunks(IMPORT_GRAPH_ROW_BATCH) {
                            let sql = import_graph_insert_sql(
                                "workspace_import_source_bindings",
                                "workspace_id, source_path, module_path, name, namespace,
                                 visibility_kind, visibility_scope, origin_path,
                                 origin_module_path, origin_name, route_path",
                                11,
                                chunk.len(),
                            );
                            let mut values = Vec::with_capacity(chunk.len() * 11);
                            for binding in chunk {
                                values.extend([
                                    Value::Text(workspace_id.clone()),
                                    Value::Text(source.source_path.clone()),
                                    Value::Text(binding.module_path.clone()),
                                    Value::Text(binding.name.clone()),
                                    Value::Text(binding.namespace.clone()),
                                    Value::Text(binding.visibility_kind.clone()),
                                    Value::Text(binding.visibility_scope.clone()),
                                    Value::Text(binding.origin_path.clone()),
                                    Value::Text(binding.origin_module_path.clone()),
                                    Value::Text(binding.origin_name.clone()),
                                    Value::Text(binding.route_path.clone()),
                                ]);
                            }
                            transaction
                                .prepare_cached(&sql)?
                                .execute(params_from_iter(values.iter()))?;
                        }
                    }
                }
            }

            let edge_fact_write_counts = publish_import_graph_edge_fact_delta(
                &transaction,
                &workspace_id,
                &old_edge_fact_keys,
                &edges,
            )?;
            deleted_edge_fact_count += edge_fact_write_counts.deleted;
            let changed_edge_fact_count = edge_fact_write_counts.changed;
            mark_publish_stage!("source_bindings_and_edge_fact_dml");
            let mut names_by_lookup = std::collections::HashMap::new();
            let mut new_candidate_rows = std::collections::HashSet::new();
            let mut new_missing_rows = std::collections::HashSet::new();
            for (importer, lookups, missing_keys) in &dependencies {
                let full_importer = full_importer_path_set.contains(importer.as_str());
                for (ordinal, consulted_path, name) in lookups {
                    names_by_lookup
                        .entry((importer.as_str(), *ordinal, consulted_path.as_str()))
                        .or_insert_with(std::collections::HashSet::new)
                        .insert(name.as_str());
                    if full_importer
                        || dirty_import_ordinal_set.contains(&(importer.as_str(), *ordinal))
                    {
                        new_candidate_rows.insert((
                            importer.clone(),
                            *ordinal,
                            consulted_path.clone(),
                            name.clone(),
                        ));
                    }
                }
                for (ordinal, module_path_key) in missing_keys {
                    if full_importer
                        || dirty_import_ordinal_set.contains(&(importer.as_str(), *ordinal))
                    {
                        new_missing_rows.insert((
                            importer.clone(),
                            *ordinal,
                            module_path_key.clone(),
                            String::new(),
                        ));
                    }
                }
            }

            let mut new_route_rows = std::collections::HashSet::new();
            for (importer, ordinal, _, _, traversed_paths) in &edges {
                let ordinal = u32::try_from(*ordinal).expect("import ordinal fits u32");
                for traversed_path in traversed_paths {
                    if let Some(names) =
                        names_by_lookup.get(&(importer.as_str(), ordinal, traversed_path.as_str()))
                    {
                        for name in names {
                            new_route_rows.insert((
                                importer.clone(),
                                ordinal,
                                traversed_path.clone(),
                                (*name).to_owned(),
                            ));
                        }
                    }
                }
            }
            mark_publish_stage!("dependency_delta_construction");

            delete_stale_import_graph_dependency_rows(
                &transaction,
                &workspace_id,
                "workspace_import_candidate_file_dependencies",
                &old_candidate_rows,
                &new_candidate_rows,
            )?;
            delete_stale_import_graph_dependency_rows(
                &transaction,
                &workspace_id,
                "workspace_import_route_dependencies",
                &old_route_rows,
                &new_route_rows,
            )?;
            delete_stale_import_graph_dependency_rows(
                &transaction,
                &workspace_id,
                "workspace_import_missing_module_dependencies",
                &old_missing_rows,
                &new_missing_rows,
            )?;
            insert_new_import_graph_dependency_rows(
                &transaction,
                &workspace_id,
                "workspace_import_candidate_file_dependencies",
                &old_candidate_rows,
                &new_candidate_rows,
            )?;
            insert_new_import_graph_dependency_rows(
                &transaction,
                &workspace_id,
                "workspace_import_route_dependencies",
                &old_route_rows,
                &new_route_rows,
            )?;
            insert_new_import_graph_dependency_rows(
                &transaction,
                &workspace_id,
                "workspace_import_missing_module_dependencies",
                &old_missing_rows,
                &new_missing_rows,
            )?;
            mark_publish_stage!("dependency_delta_dml");

            let mut new_adjacency_pairs = std::collections::HashSet::new();
            for chunk in affected_pairs.chunks(IMPORT_GRAPH_PATH_BATCH) {
                let sql = edge_pairs_with_facts_sql(chunk.len());
                let mut values = Vec::with_capacity(chunk.len() * 2 + 1);
                for (importer, target) in chunk {
                    values.push(Value::Text(importer.clone()));
                    values.push(Value::Text(target.clone()));
                }
                values.push(Value::Text(workspace_id.clone()));
                let mut statement = transaction.prepare_cached(&sql)?;
                let rows = statement.query_map(params_from_iter(values.iter()), |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?;
                new_adjacency_pairs.extend(rows.collect::<rusqlite::Result<Vec<_>>>()?);
            }
            let mut removed_adjacency_pairs = old_adjacency_pairs
                .difference(&new_adjacency_pairs)
                .cloned()
                .collect::<Vec<_>>();
            removed_adjacency_pairs.sort_unstable();
            let mut added_adjacency_pairs = new_adjacency_pairs
                .difference(&old_adjacency_pairs)
                .cloned()
                .collect::<Vec<_>>();
            added_adjacency_pairs.sort_unstable();
            let deleted_edge_count = removed_adjacency_pairs.len() as i64;
            let mut inserted_edge_count = 0_i64;
            for chunk in removed_adjacency_pairs.chunks(IMPORT_GRAPH_PATH_BATCH) {
                let sql = delete_edge_pairs_sql(chunk.len());
                let mut values = vec![Value::Text(workspace_id.clone())];
                for (importer, target) in chunk {
                    values.push(Value::Text(importer.clone()));
                    values.push(Value::Text(target.clone()));
                }
                transaction
                    .prepare_cached(&sql)?
                    .execute(params_from_iter(values.iter()))?;
            }
            for chunk in added_adjacency_pairs.chunks(IMPORT_GRAPH_PATH_BATCH) {
                let sql = insert_edge_pairs_sql(chunk.len());
                let mut values = Vec::with_capacity(chunk.len() * 3);
                for (importer, target) in chunk {
                    values.push(Value::Text(workspace_id.clone()));
                    values.push(Value::Text(importer.clone()));
                    values.push(Value::Text(target.clone()));
                }
                inserted_edge_count += transaction
                    .prepare_cached(&sql)?
                    .execute(params_from_iter(values.iter()))? as i64;
            }

            let old_edge_count = stored_identity
                .as_ref()
                .map(|_| {
                    transaction.query_row(
                        "SELECT edge_count FROM workspace_import_graphs WHERE workspace_id = ?1",
                        [&workspace_id],
                        |row| row.get::<_, i64>(0),
                    )
                })
                .transpose()?
                .unwrap_or(0);
            let edge_count = old_edge_count - deleted_edge_count + inserted_edge_count;
            assert!(
                edge_count >= 0,
                "import graph edge count cannot be negative"
            );
            transaction.execute(
                "UPDATE workspace_import_graphs
                 SET content_identity = ?2, resolver_identity = ?3,
                     source_count = ?4, edge_count = ?5
                 WHERE workspace_id = ?1",
                params![
                    &workspace_id,
                    content_identity.as_slice(),
                    resolver_identity.as_slice(),
                    source_count,
                    edge_count
                ],
            )?;
            mark_publish_stage!("adjacency_reconciliation_and_metadata");
            transaction.commit()?;
            if profile_sql {
                publish_stages.push(("commit", publish_stage_started.elapsed().as_nanos()));
            }
            if profile_sql {
                connection.trace_v2(TraceEventCodes::empty(), None);
                let mut profile = std::mem::take(
                    &mut *IMPORT_GRAPH_STATEMENT_PROFILE
                        .lock()
                        .expect("import graph SQL profile lock"),
                );
                for (name, elapsed_ns) in &publish_stages {
                    profile.insert(
                        format!("PUBLISH STAGE {name}"),
                        ImportGraphStatementProfile {
                            calls: 1,
                            total_ns: *elapsed_ns,
                            max_ns: *elapsed_ns,
                        },
                    );
                }
                for (name, count) in [
                    ("deleted_edge_facts", deleted_edge_fact_count),
                    ("changed_edge_facts", changed_edge_fact_count),
                    ("edge_fact_upsert_rows", edge_fact_write_counts.attempted as i64),
                    ("deleted_adjacency_pairs", deleted_edge_count),
                    ("inserted_adjacency_pairs", inserted_edge_count),
                ] {
                    profile.insert(
                        format!("PUBLISH COUNTER {name}"),
                        ImportGraphStatementProfile {
                            calls: u64::try_from(count)
                                .expect("import graph publication counter is nonnegative"),
                            total_ns: 0,
                            max_ns: 0,
                        },
                    );
                }
                eprintln!("import_graph_sql_profile={profile:?}");
            }
            Ok(true)
        })
    }

    pub(crate) fn read_workspace_import_graph(
        &self,
        workspace_id: &WorkspaceId,
        content_identity: &[u8; 32],
        direction: WorkspaceImportDirection,
        paths: &[String],
        edge_limit: usize,
    ) -> Result<Option<WorkspaceImportGraphRead>> {
        let mut unique_paths = paths.to_vec();
        unique_paths.sort_unstable();
        unique_paths.dedup();
        if unique_paths.is_empty() {
            return Ok(Some(WorkspaceImportGraphRead {
                edges: Vec::new(),
                exhausted: false,
            }));
        }

        let mut connection = self.read_conn()?;
        let transaction = connection.transaction()?;
        let has_graph = transaction
            .query_row(
                "SELECT 1 FROM workspace_import_graphs
                 WHERE workspace_id = ?1 AND content_identity = ?2",
                params![workspace_id.as_str(), content_identity.as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !has_graph {
            transaction.commit()?;
            return Ok(None);
        }

        let mut known_sources = std::collections::HashSet::with_capacity(unique_paths.len());
        for chunk in unique_paths.chunks(IMPORT_GRAPH_PATH_BATCH) {
            let sql = format!(
                "SELECT source_path FROM workspace_import_sources
                 WHERE workspace_id = ?1 AND source_path IN ({})",
                std::iter::repeat_n("?", chunk.len())
                    .collect::<Vec<_>>()
                    .join(",")
            );
            let mut parameters = vec![Value::Text(workspace_id.as_str().to_owned())];
            parameters.extend(chunk.iter().cloned().map(Value::Text));
            let mut statement = transaction.prepare_cached(&sql)?;
            let found = statement.query_map(params_from_iter(parameters.iter()), |row| {
                row.get::<_, String>(0)
            })?;
            for path in found {
                known_sources.insert(path?);
            }
        }
        if known_sources.len() != unique_paths.len() {
            transaction.commit()?;
            return Ok(None);
        }

        let (seed_column, selected_columns, order) = match direction {
            WorkspaceImportDirection::Forward => (
                "importer_path",
                "importer_path, target_path",
                "importer_path, target_path",
            ),
            WorkspaceImportDirection::Reverse => (
                "target_path",
                "importer_path, target_path",
                "target_path, importer_path",
            ),
        };
        let read_limit = edge_limit.saturating_add(1);
        let mut edges = Vec::with_capacity(read_limit.min(4096));
        for chunk in unique_paths.chunks(IMPORT_GRAPH_PATH_BATCH) {
            if edges.len() >= read_limit {
                break;
            }
            let sql = format!(
                "SELECT {selected_columns} FROM workspace_import_edges
                 WHERE workspace_id = ?1 AND {seed_column} IN ({})
                 ORDER BY {order} LIMIT ?{}",
                std::iter::repeat_n("?", chunk.len())
                    .collect::<Vec<_>>()
                    .join(","),
                chunk.len() + 2
            );
            let mut parameters = vec![Value::Text(workspace_id.as_str().to_owned())];
            parameters.extend(chunk.iter().cloned().map(Value::Text));
            parameters.push(Value::Integer(
                i64::try_from(read_limit - edges.len()).unwrap_or(i64::MAX),
            ));
            let mut statement = transaction.prepare_cached(&sql)?;
            let found = statement.query_map(params_from_iter(parameters.iter()), |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            for edge in found {
                edges.push(edge?);
                if edges.len() >= read_limit {
                    break;
                }
            }
        }
        let exhausted = edges.len() > edge_limit;
        edges.truncate(edge_limit);
        transaction.commit()?;
        Ok(Some(WorkspaceImportGraphRead { edges, exhausted }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
    use rusqlite::{Connection, params};

    fn source(path: &str, identity: u8) -> WorkspaceImportGraphSource {
        WorkspaceImportGraphSource {
            source_path: path.to_owned(),
            source_identity: [identity; 32],
            module_path_keys: Vec::new(),
            complete_resolution_dependencies: true,
            input_digests: None,
            binding_surface: None,
        }
    }

    fn source_with_module(
        path: &str,
        identity: u8,
        module_path_key: &str,
    ) -> WorkspaceImportGraphSource {
        WorkspaceImportGraphSource {
            source_path: path.to_owned(),
            source_identity: [identity; 32],
            module_path_keys: vec![module_path_key.to_owned()],
            complete_resolution_dependencies: true,
            input_digests: None,
            binding_surface: None,
        }
    }

    fn incomplete_source(path: &str, identity: u8) -> WorkspaceImportGraphSource {
        WorkspaceImportGraphSource {
            source_path: path.to_owned(),
            source_identity: [identity; 32],
            module_path_keys: Vec::new(),
            complete_resolution_dependencies: false,
            input_digests: None,
            binding_surface: None,
        }
    }

    fn incomplete_source_with_module(
        path: &str,
        identity: u8,
        module_path_key: &str,
    ) -> WorkspaceImportGraphSource {
        WorkspaceImportGraphSource {
            source_path: path.to_owned(),
            source_identity: [identity; 32],
            module_path_keys: vec![module_path_key.to_owned()],
            complete_resolution_dependencies: false,
            input_digests: None,
            binding_surface: None,
        }
    }

    fn edge(importer: &str, target: &str, dependencies: &[&str]) -> WorkspaceImportGraphEdge {
        edge_with_ordinal(importer, 0, target, dependencies)
    }

    fn edge_with_ordinal(
        importer: &str,
        import_ordinal: u32,
        target: &str,
        dependencies: &[&str],
    ) -> WorkspaceImportGraphEdge {
        WorkspaceImportGraphEdge {
            importer_path: importer.to_owned(),
            import_ordinal,
            target_path: target.to_owned(),
            provenance_json: "[{\"kind\":\"test_import\"}]".to_owned(),
            route_dependencies: dependencies.iter().map(|path| (*path).to_owned()).collect(),
        }
    }

    #[test]
    fn unchanged_rust_inputs_advance_identity_without_rewriting_graph_rows() {
        let store = AnalyzerStore::open_ephemeral().expect("identity-only import graph store");
        let workspace_id = WorkspaceId::for_session();
        let resolver = [8; 32];
        let old_identity = [7; 32];
        let new_identity = [9; 32];
        let unchanged = crate::analyzer::ImportGraphInputDigests {
            binding_surface: [3; 32],
            import_rows: [4; 32],
        };
        let mut lib = source("src/lib.rs", 1);
        lib.input_digests = Some(unchanged);
        let mut main = source("src/main.rs", 2);
        main.input_digests = Some(crate::analyzer::ImportGraphInputDigests {
            binding_surface: [5; 32],
            import_rows: [6; 32],
        });
        let sources = vec![lib.clone(), main];
        let edges = vec![edge("src/main.rs", "src/lib.rs", &["src/lib.rs"])];
        publish_initial(
            &store,
            &workspace_id,
            &old_identity,
            &resolver,
            &sources,
            &edges,
        );
        let previous_facts = stored_import_graph_facts(&store, &workspace_id);

        let mut edited_lib = lib.clone();
        edited_lib.source_identity = [10; 32];
        let edited_sources = vec![edited_lib.clone(), sources[1].clone()];
        let plan = store
            .plan_workspace_import_graph_refresh(
                &workspace_id,
                &new_identity,
                &resolver,
                &edited_sources,
            )
            .expect("plan unchanged input digests");
        assert!(!plan.full_rebuild);
        assert!(plan.changed_module_path_keys.is_empty());
        assert_eq!(plan.changed_source_paths, vec!["src/lib.rs".to_owned()]);

        assert!(
            store
                .advance_workspace_import_graph_identity(
                    &workspace_id,
                    &new_identity,
                    &resolver,
                    &plan,
                    &edited_sources,
                )
                .expect("advance graph identity")
        );
        assert_eq!(
            stored_import_graph_facts(&store, &workspace_id),
            previous_facts,
            "identity-only refresh must preserve edge and dependency rows exactly"
        );
        let connection = store.read_conn().expect("read advanced graph manifest");
        let identities = connection
            .query_row(
                "SELECT g.content_identity, s.source_identity
                 FROM workspace_import_graphs AS g
                 JOIN workspace_import_sources AS s USING(workspace_id)
                 WHERE g.workspace_id = ?1 AND s.source_path = 'src/lib.rs'",
                [workspace_id.as_str()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .expect("read new graph and source identities");
        assert_eq!(identities.0, new_identity);
        assert_eq!(identities.1, edited_lib.source_identity);

        let mut changed_inputs = edited_lib;
        changed_inputs.source_identity = [13; 32];
        changed_inputs.input_digests = Some(crate::analyzer::ImportGraphInputDigests {
            binding_surface: [11; 32],
            import_rows: unchanged.import_rows,
        });
        let changed_sources = vec![changed_inputs, sources[1].clone()];
        let changed_plan = store
            .plan_workspace_import_graph_refresh(
                &workspace_id,
                &[12; 32],
                &resolver,
                &changed_sources,
            )
            .expect("plan changed binding input");
        assert!(!changed_plan.full_rebuild);
        assert!(changed_plan.changed_module_path_keys.is_empty());
        assert!(
            !store
                .advance_workspace_import_graph_identity(
                    &workspace_id,
                    &[12; 32],
                    &resolver,
                    &changed_plan,
                    &changed_sources,
                )
                .expect("changed binding input rejects identity-only advance")
        );
    }

    fn publish_initial(
        store: &AnalyzerStore,
        workspace_id: &WorkspaceId,
        identity: &[u8; 32],
        resolver_identity: &[u8; 32],
        sources: &[WorkspaceImportGraphSource],
        edges: &[WorkspaceImportGraphEdge],
    ) {
        publish_initial_with_dependencies(
            store,
            workspace_id,
            identity,
            resolver_identity,
            sources,
            edges,
            &[],
        );
    }

    fn publish_initial_with_dependencies(
        store: &AnalyzerStore,
        workspace_id: &WorkspaceId,
        identity: &[u8; 32],
        resolver_identity: &[u8; 32],
        sources: &[WorkspaceImportGraphSource],
        edges: &[WorkspaceImportGraphEdge],
        dependencies: &[WorkspaceImportGraphDependencies],
    ) {
        let plan = store
            .plan_workspace_import_graph_refresh(workspace_id, identity, resolver_identity, sources)
            .expect("plan initial graph");
        assert!(plan.full_rebuild);
        store
            .publish_workspace_import_graph_refresh(
                workspace_id,
                identity,
                resolver_identity,
                &plan,
                sources.len(),
                sources,
                edges,
                dependencies,
            )
            .expect("publish initial graph");
    }

    #[test]
    fn edge_fact_publication_counter_excludes_unchanged_rows() {
        let store = AnalyzerStore::open_ephemeral().expect("edge fact delta store");
        let workspace_id = WorkspaceId::for_session();
        let sources = (0..512)
            .map(|index| source(&format!("src/module_{index}.rs"), index as u8))
            .chain(std::iter::once(source("src/lib.rs", 1)))
            .collect::<Vec<_>>();
        let initial_edges = (0..512)
            .map(|index| edge(&format!("src/module_{index}.rs"), "src/lib.rs", &[]))
            .collect::<Vec<_>>();
        publish_initial(
            &store,
            &workspace_id,
            &[7; 32],
            &[8; 32],
            &sources,
            &initial_edges,
        );
        let edges = initial_edges
            .iter()
            .map(|edge| {
                (
                    edge.importer_path.clone(),
                    i64::from(edge.import_ordinal),
                    edge.target_path.clone(),
                    edge.provenance_json.clone(),
                    edge.route_dependencies.clone(),
                )
            })
            .collect::<Vec<_>>();

        let old_keys = edges
            .iter()
            .map(|(importer, ordinal, target, _, _)| (importer.clone(), *ordinal, target.clone()))
            .collect::<std::collections::HashSet<_>>();
        let mut connection = store.conn.lock().expect("lock edge fact delta store");
        let transaction = connection
            .transaction()
            .expect("begin unchanged edge fact delta");
        let unchanged = publish_import_graph_edge_fact_delta(
            &transaction,
            workspace_id.as_str(),
            &old_keys,
            &edges,
        )
        .expect("republish unchanged edge facts");
        assert_eq!(
            unchanged,
            ImportGraphEdgeFactWriteCounts {
                deleted: 0,
                changed: 0,
                attempted: 512,
            }
        );
        transaction.commit().expect("commit unchanged edge facts");

        let mut changed = edges[1..].to_vec();
        changed[0].3 = "[{\"kind\":\"changed_provenance\"}]".to_owned();
        changed.push((
            "src/module_0.rs".to_owned(),
            0,
            "src/other.rs".to_owned(),
            "[{\"kind\":\"test_import\"}]".to_owned(),
            Vec::new(),
        ));
        let transaction = connection
            .transaction()
            .expect("begin changed edge fact delta");
        let counts = publish_import_graph_edge_fact_delta(
            &transaction,
            workspace_id.as_str(),
            &old_keys,
            &changed,
        )
        .expect("write changed edge facts");
        assert_eq!(
            counts,
            ImportGraphEdgeFactWriteCounts {
                deleted: 1,
                changed: 2,
                attempted: 512,
            }
        );
        transaction.commit().expect("commit changed edge facts");
        let fact_count = connection
            .query_row(
                "SELECT COUNT(*) FROM workspace_import_edge_facts WHERE workspace_id = ?1",
                [workspace_id.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .expect("count changed edge facts");
        assert_eq!(fact_count, 512);
        let new_target_exists = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM workspace_import_edge_facts
                    WHERE workspace_id = ?1 AND importer_path = 'src/module_0.rs'
                      AND target_path = 'src/other.rs'
                 )",
                [workspace_id.as_str()],
                |row| row.get::<_, bool>(0),
            )
            .expect("check inserted edge fact");
        assert!(new_target_exists);
        let changed_provenance = connection
            .query_row(
                "SELECT provenance_json FROM workspace_import_edge_facts
                 WHERE workspace_id = ?1 AND importer_path = 'src/module_1.rs'
                   AND target_path = 'src/lib.rs'",
                [workspace_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .expect("read updated edge provenance");
        assert_eq!(changed_provenance, "[{\"kind\":\"changed_provenance\"}]");
    }

    fn rust_graph_sources(
        analyzer: &crate::analyzer::RustAnalyzer,
        files: &[crate::analyzer::ProjectFile],
    ) -> Vec<WorkspaceImportGraphSource> {
        use crate::analyzer::IAnalyzer;

        let provider = analyzer
            .import_analysis_provider()
            .expect("Rust analyzer exposes import graph facts");
        let mut module_path_keys = provider
            .import_graph_module_path_keys_for_files(files)
            .expect("Rust module keys are available for every fixture source");
        let mut binding_surfaces = provider
            .import_graph_binding_surfaces_for_files(files, None)
            .expect("Rust binding surfaces are available for every fixture source");
        files
            .iter()
            .map(|file| {
                let contents = std::fs::read(file.abs_path()).expect("read Rust source identity");
                let mut hasher = CanonicalHasher::new(b"test-rust-import-source:v1");
                hasher.field("path", crate::path_utils::rel_path_string(file).as_bytes());
                hasher.field("contents", &contents);
                let binding_surface = binding_surfaces
                    .remove(file)
                    .expect("Rust provider returns binding surfaces for every source")
                    .into_iter()
                    .flat_map(WorkspaceImportGraphBinding::from_provider_surface)
                    .collect();
                WorkspaceImportGraphSource {
                    source_path: crate::path_utils::rel_path_string(file),
                    source_identity: hasher.finish(),
                    module_path_keys: module_path_keys
                        .remove(file)
                        .expect("Rust provider returns module keys for every source"),
                    complete_resolution_dependencies: true,
                    input_digests: None,
                    binding_surface: Some(binding_surface),
                }
            })
            .collect()
    }

    fn rust_graph_facts(
        analyzer: &crate::analyzer::RustAnalyzer,
        files: &[crate::analyzer::ProjectFile],
        selected_ordinals: Option<&crate::hash::HashMap<crate::analyzer::ProjectFile, Vec<u32>>>,
    ) -> crate::analyzer::structural::derived_cache::RequestLocalDirectImportGraph {
        use crate::analyzer::{AnalyzerQueryScope, QueryScope};
        use crate::cancellation::CancellationToken;

        let analyzed_files = brokk_bifrost_core::analyzer::CodeUnitIndex::analyzed_files(analyzer);
        let mut graph =
            crate::analyzer::structural::derived_cache::RequestLocalDirectImportGraph::from_files(
                analyzed_files,
            );
        let scope = AnalyzerQueryScope::new(analyzer);
        let cancellation = CancellationToken::default();
        let exhausted = if let Some(selected_ordinals) = selected_ordinals {
            graph.ensure_forward_selected(
                analyzer,
                scope.token(),
                files,
                selected_ordinals,
                files.len().saturating_add(1),
                10_000,
                Some(&cancellation),
            )
        } else {
            graph.ensure_complete(
                analyzer,
                scope.token(),
                files.len().saturating_add(1),
                10_000,
                Some(&cancellation),
            )
        };
        assert!(!exhausted, "Rust import graph work fits the test limits");
        graph
    }

    fn store_facts_from_request_graph(
        graph: &crate::analyzer::structural::derived_cache::RequestLocalDirectImportGraph,
    ) -> (
        Vec<WorkspaceImportGraphEdge>,
        Vec<WorkspaceImportGraphDependencies>,
    ) {
        let edges = graph
            .persisted_edges()
            .into_iter()
            .map(|edge| WorkspaceImportGraphEdge {
                importer_path: crate::path_utils::rel_path_string(&edge.importer),
                import_ordinal: edge.import_ordinal,
                target_path: crate::path_utils::rel_path_string(&edge.target),
                provenance_json: edge.provenance_json,
                route_dependencies: edge.route_dependencies,
            })
            .collect();
        let dependencies = graph
            .persisted_resolution_dependencies()
            .into_iter()
            .map(|dependency| WorkspaceImportGraphDependencies {
                importer_path: crate::path_utils::rel_path_string(&dependency.importer),
                lookups: dependency
                    .facts
                    .lookups
                    .into_iter()
                    .map(|lookup| {
                        (
                            lookup.import_ordinal,
                            crate::path_utils::rel_path_string(&lookup.consulted_file),
                            lookup.name,
                        )
                    })
                    .collect(),
                missing_module_path_keys: dependency.facts.missing_module_path_keys,
            })
            .collect();
        (edges, dependencies)
    }

    fn stored_adjacency(
        store: &AnalyzerStore,
        workspace_id: &WorkspaceId,
        identity: &[u8; 32],
        sources: &[WorkspaceImportGraphSource],
    ) -> Vec<(String, String)> {
        store
            .read_workspace_import_graph(
                workspace_id,
                identity,
                WorkspaceImportDirection::Forward,
                &sources
                    .iter()
                    .map(|source| source.source_path.clone())
                    .collect::<Vec<_>>(),
                10_000,
            )
            .expect("read stored Rust graph")
            .expect("graph identity is current")
            .edges
    }

    type StoredFactRow = (String, i64, String, String);
    type StoredImportGraphFacts = (
        Vec<StoredFactRow>,
        Vec<StoredFactRow>,
        Vec<StoredFactRow>,
        Vec<(String, i64, String)>,
    );

    fn stored_import_graph_facts(
        store: &AnalyzerStore,
        workspace_id: &WorkspaceId,
    ) -> StoredImportGraphFacts {
        let connection = store.read_conn().expect("read stored import graph facts");
        let edges = connection
            .prepare(
                "SELECT importer_path, import_ordinal, target_path, provenance_json
                 FROM workspace_import_edge_facts WHERE workspace_id = ?1
                 ORDER BY importer_path, import_ordinal, target_path",
            )
            .expect("prepare stored edge fact read")
            .query_map([workspace_id.as_str()], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .expect("query stored edge facts")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("decode stored edge facts");
        let route_dependencies = connection
            .prepare(
                "SELECT importer_path, import_ordinal, traversed_path, name
                 FROM workspace_import_route_dependencies WHERE workspace_id = ?1
                 ORDER BY importer_path, import_ordinal, traversed_path, name",
            )
            .expect("prepare stored route dependency read")
            .query_map([workspace_id.as_str()], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .expect("query stored route dependencies")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("decode stored route dependencies");
        let candidate_dependencies = connection
            .prepare(
                "SELECT importer_path, import_ordinal, consulted_path, name
                 FROM workspace_import_candidate_file_dependencies WHERE workspace_id = ?1
                 ORDER BY importer_path, import_ordinal, consulted_path, name",
            )
            .expect("prepare stored candidate dependency read")
            .query_map([workspace_id.as_str()], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .expect("query stored candidate dependencies")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("decode stored candidate dependencies");
        let missing_module_dependencies = connection
            .prepare(
                "SELECT importer_path, import_ordinal, module_path_key
                 FROM workspace_import_missing_module_dependencies WHERE workspace_id = ?1
                 ORDER BY importer_path, import_ordinal, module_path_key",
            )
            .expect("prepare stored missing module dependency read")
            .query_map([workspace_id.as_str()], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .expect("query stored missing module dependencies")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("decode stored missing module dependencies");
        (
            edges,
            route_dependencies,
            candidate_dependencies,
            missing_module_dependencies,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn refresh_rust_graph_and_compare_to_fresh(
        store: &AnalyzerStore,
        workspace_id: &WorkspaceId,
        previous_identity: &[u8; 32],
        current_identity: &[u8; 32],
        resolver: &[u8; 32],
        analyzer: &crate::analyzer::RustAnalyzer,
        expected_work: (usize, usize, usize),
        expected_lookup_ordinals: &[(&str, u32)],
    ) {
        let files = brokk_bifrost_core::analyzer::CodeUnitIndex::analyzed_files(analyzer);
        let sources = rust_graph_sources(analyzer, &files);
        assert!(
            store
                .read_workspace_import_graph(
                    workspace_id,
                    previous_identity,
                    WorkspaceImportDirection::Forward,
                    &sources
                        .iter()
                        .map(|source| source.source_path.clone())
                        .collect::<Vec<_>>(),
                    10_000,
                )
                .expect("read previous Rust graph")
                .is_some(),
            "incremental refresh starts from the previous graph identity"
        );
        let plan = store
            .plan_workspace_import_graph_refresh(workspace_id, current_identity, resolver, &sources)
            .expect("plan incremental Rust graph refresh");
        assert!(!plan.full_rebuild);
        assert_eq!(
            plan.dirty_lookup_ordinals,
            expected_lookup_ordinals
                .iter()
                .map(|(path, ordinal)| ((*path).to_owned(), *ordinal))
                .collect::<Vec<_>>(),
            "only imports whose candidate or missing-module lookup rows change are republished"
        );
        let before_facts = stored_import_graph_facts(store, workspace_id);
        let dirty_lookup_ordinals = plan
            .dirty_lookup_ordinals
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<_>>();
        let unchanged_candidate_rows = before_facts
            .2
            .iter()
            .filter(|(path, ordinal, _, _)| {
                plan.dirty_importer_paths.binary_search(path).is_err()
                    && !dirty_lookup_ordinals.contains(&(
                        path.clone(),
                        u32::try_from(*ordinal).expect("stored import ordinal fits u32"),
                    ))
            })
            .cloned()
            .collect::<Vec<_>>();
        let unchanged_missing_module_rows = before_facts
            .3
            .iter()
            .filter(|(path, ordinal, _)| {
                plan.dirty_importer_paths.binary_search(path).is_err()
                    && !dirty_lookup_ordinals.contains(&(
                        path.clone(),
                        u32::try_from(*ordinal).expect("stored import ordinal fits u32"),
                    ))
            })
            .cloned()
            .collect::<Vec<_>>();

        let mut dirty_paths = plan
            .dirty_importer_paths
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<_>>();
        dirty_paths.extend(
            plan.dirty_import_ordinals
                .iter()
                .map(|(path, _)| path.clone()),
        );
        let dirty_files = files
            .iter()
            .filter(|file| dirty_paths.contains(&crate::path_utils::rel_path_string(file)))
            .cloned()
            .collect::<Vec<_>>();
        let mut selected_ordinals = crate::hash::HashMap::default();
        for (path, ordinal) in &plan.dirty_import_ordinals {
            if plan.dirty_importer_paths.binary_search(path).is_ok() {
                continue;
            }
            let file = files
                .iter()
                .find(|file| crate::path_utils::rel_path_string(file) == *path)
                .expect("dirty import ordinal belongs to an analyzed Rust source");
            selected_ordinals
                .entry(file.clone())
                .or_insert_with(Vec::new)
                .push(*ordinal);
        }
        let graph = rust_graph_facts(analyzer, &dirty_files, Some(&selected_ordinals));
        assert_eq!(
            (
                graph.resolved_files(),
                graph.resolved_imports(),
                graph.resolved_edges(),
            ),
            expected_work,
            "incremental refresh recomputes only affected import facts"
        );
        let (edges, dependencies) = store_facts_from_request_graph(&graph);
        store
            .publish_workspace_import_graph_refresh(
                workspace_id,
                current_identity,
                resolver,
                &plan,
                sources.len(),
                &sources,
                &edges,
                &dependencies,
            )
            .expect("publish incremental Rust graph");
        let incremental = stored_adjacency(store, workspace_id, current_identity, &sources);
        let incremental_facts = stored_import_graph_facts(store, workspace_id);
        let carried_candidate_rows = incremental_facts
            .2
            .iter()
            .filter(|(path, ordinal, _, _)| {
                plan.dirty_importer_paths.binary_search(path).is_err()
                    && !dirty_lookup_ordinals.contains(&(
                        path.clone(),
                        u32::try_from(*ordinal).expect("stored import ordinal fits u32"),
                    ))
            })
            .cloned()
            .collect::<Vec<_>>();
        let carried_missing_module_rows = incremental_facts
            .3
            .iter()
            .filter(|(path, ordinal, _)| {
                plan.dirty_importer_paths.binary_search(path).is_err()
                    && !dirty_lookup_ordinals.contains(&(
                        path.clone(),
                        u32::try_from(*ordinal).expect("stored import ordinal fits u32"),
                    ))
            })
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            carried_candidate_rows, unchanged_candidate_rows,
            "route-only invalidation carries candidate lookup rows without republishing them"
        );
        assert_eq!(
            carried_missing_module_rows, unchanged_missing_module_rows,
            "route-only invalidation carries missing-module lookup rows without republishing them"
        );

        let fresh_store = AnalyzerStore::open_ephemeral().expect("fresh Rust graph store");
        let fresh_workspace_id = WorkspaceId::for_session();
        let fresh_graph = rust_graph_facts(analyzer, &files, None);
        let (fresh_edges, fresh_dependencies) = store_facts_from_request_graph(&fresh_graph);
        publish_initial_with_dependencies(
            &fresh_store,
            &fresh_workspace_id,
            current_identity,
            resolver,
            &sources,
            &fresh_edges,
            &fresh_dependencies,
        );
        let fresh_plan = fresh_store
            .plan_workspace_import_graph_refresh(
                &fresh_workspace_id,
                current_identity,
                resolver,
                &sources,
            )
            .expect("read fresh Rust graph plan");
        assert!(fresh_plan.current);
        // Initial publication above intentionally uses the common helper; the
        // already-current plan proves its query-facing rows match the snapshot.
        let fresh = stored_adjacency(
            &fresh_store,
            &fresh_workspace_id,
            current_identity,
            &sources,
        );
        let fresh_facts = stored_import_graph_facts(&fresh_store, &fresh_workspace_id);
        assert_eq!(
            incremental, fresh,
            "incremental graph equals a fresh rebuild"
        );
        assert_eq!(
            incremental_facts, fresh_facts,
            "incremental edge provenance and all dependency rows equal a fresh rebuild"
        );
    }

    #[test]
    fn incremental_refresh_recomputes_changed_sources_and_route_dependents_only() {
        let store = AnalyzerStore::open_ephemeral().expect("import graph store");
        let workspace_id = WorkspaceId::for_session();
        let before = [11; 32];
        let resolver = [21; 32];
        let before_sources = [
            source("src/origin.rs", 1),
            source("src/facade.rs", 2),
            source("src/client.rs", 3),
            source("src/leaf.rs", 4),
            source("src/other.rs", 5),
        ];
        let before_edges = [
            edge(
                "src/facade.rs",
                "src/origin.rs",
                &["src/facade.rs", "src/origin.rs"],
            ),
            edge(
                "src/client.rs",
                "src/origin.rs",
                &["src/client.rs", "src/facade.rs", "src/origin.rs"],
            ),
            edge_with_ordinal(
                "src/client.rs",
                1,
                "src/other.rs",
                &["src/client.rs", "src/other.rs"],
            ),
            edge(
                "src/leaf.rs",
                "src/origin.rs",
                &["src/leaf.rs", "src/origin.rs"],
            ),
            edge(
                "src/other.rs",
                "src/origin.rs",
                &["src/other.rs", "src/origin.rs"],
            ),
        ];
        let before_dependencies = [WorkspaceImportGraphDependencies {
            importer_path: "src/client.rs".to_owned(),
            lookups: vec![
                (0, "src/client.rs".to_owned(), "Widget".to_owned()),
                (0, "src/facade.rs".to_owned(), "Widget".to_owned()),
                (0, "src/origin.rs".to_owned(), "Widget".to_owned()),
                (1, "src/client.rs".to_owned(), "Other".to_owned()),
                (1, "src/other.rs".to_owned(), "Other".to_owned()),
            ],
            missing_module_path_keys: Vec::new(),
        }];
        publish_initial_with_dependencies(
            &store,
            &workspace_id,
            &before,
            &resolver,
            &before_sources,
            &before_edges,
            &before_dependencies,
        );

        let after = [12; 32];
        let after_sources = [
            source("src/origin.rs", 1),
            source("src/facade.rs", 7),
            source("src/client.rs", 3),
            source("src/leaf.rs", 8),
            source("src/other.rs", 5),
        ];
        let plan = store
            .plan_workspace_import_graph_refresh(&workspace_id, &after, &resolver, &after_sources)
            .expect("plan incremental refresh");
        assert!(!plan.full_rebuild);
        assert_eq!(
            plan.dirty_importer_paths,
            vec!["src/facade.rs".to_owned(), "src/leaf.rs".to_owned()]
        );
        assert_eq!(
            plan.dirty_import_ordinals,
            vec![("src/client.rs".to_owned(), 0)]
        );

        let after_edges = [
            edge(
                "src/facade.rs",
                "src/leaf.rs",
                &["src/facade.rs", "src/leaf.rs"],
            ),
            edge(
                "src/client.rs",
                "src/leaf.rs",
                &["src/client.rs", "src/facade.rs", "src/leaf.rs"],
            ),
            edge(
                "src/leaf.rs",
                "src/origin.rs",
                &["src/leaf.rs", "src/origin.rs"],
            ),
        ];
        let after_dependencies = [WorkspaceImportGraphDependencies {
            importer_path: "src/client.rs".to_owned(),
            lookups: vec![
                (0, "src/client.rs".to_owned(), "Widget".to_owned()),
                (0, "src/facade.rs".to_owned(), "Widget".to_owned()),
                (0, "src/leaf.rs".to_owned(), "Widget".to_owned()),
            ],
            missing_module_path_keys: Vec::new(),
        }];
        store
            .publish_workspace_import_graph_refresh(
                &workspace_id,
                &after,
                &resolver,
                &plan,
                after_sources.len(),
                &after_sources,
                &after_edges,
                &after_dependencies,
            )
            .expect("publish incremental refresh");

        let changed = store
            .read_workspace_import_graph(
                &workspace_id,
                &after,
                WorkspaceImportDirection::Reverse,
                &["src/leaf.rs".to_owned()],
                10,
            )
            .expect("read refreshed graph")
            .expect("new graph is current");
        assert_eq!(
            changed.edges,
            vec![
                ("src/client.rs".to_owned(), "src/leaf.rs".to_owned()),
                ("src/facade.rs".to_owned(), "src/leaf.rs".to_owned()),
            ]
        );
        let carried = store
            .read_workspace_import_graph(
                &workspace_id,
                &after,
                WorkspaceImportDirection::Forward,
                &["src/other.rs".to_owned()],
                10,
            )
            .expect("read carried edge")
            .expect("new graph is current");
        assert_eq!(
            carried.edges,
            vec![("src/other.rs".to_owned(), "src/origin.rs".to_owned())]
        );
        let client_edges = store
            .read_workspace_import_graph(
                &workspace_id,
                &after,
                WorkspaceImportDirection::Forward,
                &["src/client.rs".to_owned()],
                10,
            )
            .expect("read recomputed and carried import ordinals")
            .expect("new graph is current");
        assert_eq!(
            client_edges.edges,
            vec![
                ("src/client.rs".to_owned(), "src/leaf.rs".to_owned()),
                ("src/client.rs".to_owned(), "src/other.rs".to_owned()),
            ]
        );
        let connection = store.read_conn().expect("read stored route");
        let route_file_count = connection
            .query_row(
                "SELECT COUNT(*) FROM workspace_import_route_dependencies
                 WHERE workspace_id = ?1 AND importer_path = 'src/client.rs'
                   AND import_ordinal = 0 AND traversed_path = 'src/facade.rs'
                   AND name = 'Widget'",
                [workspace_id.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .expect("read route dependency row");
        assert_eq!(route_file_count, 1);
    }

    #[test]
    fn rust_incremental_import_graph_work_matches_fresh_rebuild_for_reexport_and_leaf_edits() {
        use crate::analyzer::{IAnalyzer, Language, RustAnalyzer, TestProject};

        let temp = tempfile::tempdir().expect("Rust import graph fixture");
        let root = temp.path().canonicalize().expect("canonical fixture root");
        std::fs::create_dir_all(root.join("src")).expect("create fixture source directory");
        for (path, contents) in [
            (
                "Cargo.toml",
                "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            ),
            (
                "src/lib.rs",
                "pub mod client;\npub mod facade;\npub mod leaf;\npub mod origin;\npub mod other;\n",
            ),
            ("src/facade.rs", "pub use crate::origin::Widget;\n"),
            (
                "src/client.rs",
                "use crate::facade::Widget;\nuse crate::leaf::Leaf;\nuse crate::other::Other;\n",
            ),
            ("src/leaf.rs", "pub struct Leaf;\n"),
            ("src/origin.rs", "pub struct Widget;\n"),
            ("src/other.rs", "pub struct Other;\n"),
        ] {
            std::fs::write(root.join(path), contents).expect("write Rust fixture file");
        }
        let analyzer = RustAnalyzer::from_project(TestProject::new(root.clone(), Language::Rust));
        let files = brokk_bifrost_core::analyzer::CodeUnitIndex::analyzed_files(&analyzer);
        let sources = rust_graph_sources(&analyzer, &files);
        let initial_graph = rust_graph_facts(&analyzer, &files, None);
        assert_eq!(initial_graph.resolved_files(), files.len());
        let (initial_edges, initial_dependencies) = store_facts_from_request_graph(&initial_graph);
        let store = AnalyzerStore::open_ephemeral().expect("persistent graph fixture store");
        let workspace_id = WorkspaceId::for_session();
        let initial_identity = [91; 32];
        let resolver = [92; 32];
        publish_initial_with_dependencies(
            &store,
            &workspace_id,
            &initial_identity,
            &resolver,
            &sources,
            &initial_edges,
            &initial_dependencies,
        );

        let facade = crate::analyzer::ProjectFile::new(root.clone(), "src/facade.rs");
        std::fs::write(
            facade.abs_path(),
            "pub use crate::other::Other as Widget;\n",
        )
        .expect("edit re-export source");
        let after_reexport = analyzer.update(&std::collections::BTreeSet::from([facade]));
        let reexport_identity = [93; 32];
        refresh_rust_graph_and_compare_to_fresh(
            &store,
            &workspace_id,
            &initial_identity,
            &reexport_identity,
            &resolver,
            &after_reexport,
            (2, 2, 3),
            &[("src/client.rs", 0)],
        );

        let leaf = crate::analyzer::ProjectFile::new(root.clone(), "src/leaf.rs");
        std::fs::write(leaf.abs_path(), "pub struct Leaf;\npub struct LeafExtra;\n")
            .expect("edit leaf source");
        let after_leaf = after_reexport.update(&std::collections::BTreeSet::from([leaf]));
        refresh_rust_graph_and_compare_to_fresh(
            &store,
            &workspace_id,
            &reexport_identity,
            &[94; 32],
            &resolver,
            &after_leaf,
            (1, 0, 0),
            &[],
        );
    }

    #[test]
    fn rust_name_surface_cutoff_matches_fresh_after_body_item_and_glob_edits() {
        use crate::analyzer::{IAnalyzer, Language, RustAnalyzer, TestProject};

        let temp = tempfile::tempdir().expect("Rust binding surface fixture");
        let root = temp.path().canonicalize().expect("canonical fixture root");
        std::fs::create_dir_all(root.join("src")).expect("create fixture source directory");
        for (path, contents) in [
            (
                "Cargo.toml",
                "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            ),
            (
                "src/lib.rs",
                "pub mod app;\npub mod facade;\npub mod glob_client;\npub mod origin;\npub mod unrelated;\nfn root_body() {}\n",
            ),
            (
                "src/facade.rs",
                "pub use crate::origin::Existing as Alias;\n",
            ),
            ("src/origin.rs", "pub struct Existing;\n"),
            (
                "src/app.rs",
                "use crate::facade::Alias;\nuse crate::origin::Added;\n",
            ),
            ("src/glob_client.rs", "use crate::origin::*;\n"),
            ("src/unrelated.rs", "use crate::origin::NeverAdded;\n"),
        ] {
            std::fs::write(root.join(path), contents).expect("write Rust fixture file");
        }
        let analyzer = RustAnalyzer::from_project(TestProject::new(root.clone(), Language::Rust));
        let files = brokk_bifrost_core::analyzer::CodeUnitIndex::analyzed_files(&analyzer);
        let sources = rust_graph_sources(&analyzer, &files);
        let initial_graph = rust_graph_facts(&analyzer, &files, None);
        let (initial_edges, initial_dependencies) = store_facts_from_request_graph(&initial_graph);
        let store = AnalyzerStore::open_ephemeral().expect("name-granular graph store");
        let workspace_id = WorkspaceId::for_session();
        let initial_identity = [111; 32];
        let resolver = [112; 32];
        publish_initial_with_dependencies(
            &store,
            &workspace_id,
            &initial_identity,
            &resolver,
            &sources,
            &initial_edges,
            &initial_dependencies,
        );

        let crate_root = crate::analyzer::ProjectFile::new(root.clone(), "src/lib.rs");
        std::fs::write(
            crate_root.abs_path(),
            "pub mod app;\npub mod facade;\npub mod glob_client;\npub mod origin;\npub mod unrelated;\nfn root_body() { let _unused = (); }\n",
        )
        .expect("make a body-only crate-root edit");
        let after_body = analyzer.update(&std::collections::BTreeSet::from([crate_root]));
        refresh_rust_graph_and_compare_to_fresh(
            &store,
            &workspace_id,
            &initial_identity,
            &[113; 32],
            &resolver,
            &after_body,
            (1, 0, 0),
            &[],
        );

        let origin = crate::analyzer::ProjectFile::new(root.clone(), "src/origin.rs");
        std::fs::write(
            origin.abs_path(),
            "pub struct Existing;\npub struct Added;\n",
        )
        .expect("add the named binding");
        let after_named = after_body.update(&std::collections::BTreeSet::from([origin.clone()]));
        refresh_rust_graph_and_compare_to_fresh(
            &store,
            &workspace_id,
            &[113; 32],
            &[114; 32],
            &resolver,
            &after_named,
            (3, 2, 2),
            &[("src/app.rs", 1), ("src/glob_client.rs", 0)],
        );

        std::fs::write(
            origin.abs_path(),
            "pub struct Existing;\npub struct Added;\npub struct GlobOnly;\n",
        )
        .expect("change the glob-visible binding set");
        let after_glob = after_named.update(&std::collections::BTreeSet::from([origin]));
        refresh_rust_graph_and_compare_to_fresh(
            &store,
            &workspace_id,
            &[114; 32],
            &[115; 32],
            &resolver,
            &after_glob,
            (2, 1, 1),
            &[("src/glob_client.rs", 0)],
        );
    }

    #[test]
    fn mixed_language_edits_rebuild_when_the_changed_provider_lacks_dependencies() {
        let store = AnalyzerStore::open_ephemeral().expect("mixed import graph store");
        let workspace_id = WorkspaceId::for_session();
        let before = [51; 32];
        let resolver = [61; 32];
        let before_sources = [
            source_with_module("src/lib.rs", 1, "demo::"),
            source_with_module("src/client.rs", 2, "demo::client"),
            incomplete_source("python/app.py", 3),
            incomplete_source("python/helper.py", 6),
        ];
        let before_edges = [
            edge(
                "src/client.rs",
                "src/lib.rs",
                &["src/client.rs", "src/lib.rs"],
            ),
            edge(
                "python/app.py",
                "python/helper.py",
                &["python/app.py", "python/helper.py"],
            ),
        ];
        let before_dependencies = [WorkspaceImportGraphDependencies {
            importer_path: "src/client.rs".to_owned(),
            lookups: vec![
                (0, "src/client.rs".to_owned(), "demo".to_owned()),
                (0, "src/lib.rs".to_owned(), "demo".to_owned()),
            ],
            missing_module_path_keys: Vec::new(),
        }];
        publish_initial_with_dependencies(
            &store,
            &workspace_id,
            &before,
            &resolver,
            &before_sources,
            &before_edges,
            &before_dependencies,
        );

        let after_rust_edit = [52; 32];
        let rust_edited_sources = [
            source_with_module("src/lib.rs", 4, "demo::"),
            before_sources[1].clone(),
            before_sources[2].clone(),
            before_sources[3].clone(),
        ];
        let plan = store
            .plan_workspace_import_graph_refresh(
                &workspace_id,
                &after_rust_edit,
                &resolver,
                &rust_edited_sources,
            )
            .expect("plan Rust edit in mixed workspace");
        assert!(!plan.full_rebuild);
        assert_eq!(plan.dirty_importer_paths, vec!["src/lib.rs".to_owned()]);
        assert_eq!(
            plan.dirty_import_ordinals,
            vec![("src/client.rs".to_owned(), 0)]
        );
        store
            .publish_workspace_import_graph_refresh(
                &workspace_id,
                &after_rust_edit,
                &resolver,
                &plan,
                rust_edited_sources.len(),
                &rust_edited_sources,
                &[edge(
                    "src/client.rs",
                    "src/lib.rs",
                    &["src/client.rs", "src/lib.rs"],
                )],
                &before_dependencies,
            )
            .expect("publish incremental mixed-language rebuild");
        let carried_python_edge = store
            .read_workspace_import_graph(
                &workspace_id,
                &after_rust_edit,
                WorkspaceImportDirection::Forward,
                &["python/app.py".to_owned()],
                10,
            )
            .expect("read carried Python edge")
            .expect("mixed graph is current");
        assert_eq!(
            carried_python_edge.edges,
            vec![("python/app.py".to_owned(), "python/helper.py".to_owned())]
        );
        let carried_rust_edge = store
            .read_workspace_import_graph(
                &workspace_id,
                &after_rust_edit,
                WorkspaceImportDirection::Forward,
                &["src/client.rs".to_owned()],
                10,
            )
            .expect("read refreshed Rust edge")
            .expect("mixed graph is current");
        assert_eq!(
            carried_rust_edge.edges,
            vec![("src/client.rs".to_owned(), "src/lib.rs".to_owned())]
        );

        let after_python_edit = [53; 32];
        let python_edited_sources = [
            rust_edited_sources[0].clone(),
            rust_edited_sources[1].clone(),
            incomplete_source("python/app.py", 5),
            rust_edited_sources[3].clone(),
        ];
        let plan = store
            .plan_workspace_import_graph_refresh(
                &workspace_id,
                &after_python_edit,
                &resolver,
                &python_edited_sources,
            )
            .expect("plan unsupported Python edit");
        assert!(plan.full_rebuild);
        assert_eq!(plan.dirty_importer_paths.len(), python_edited_sources.len());

        let after_python_add = [54; 32];
        let python_added_sources = [
            rust_edited_sources[0].clone(),
            rust_edited_sources[1].clone(),
            rust_edited_sources[2].clone(),
            rust_edited_sources[3].clone(),
            incomplete_source("python/new.py", 7),
        ];
        let plan = store
            .plan_workspace_import_graph_refresh(
                &workspace_id,
                &after_python_add,
                &resolver,
                &python_added_sources,
            )
            .expect("plan unsupported Python addition");
        assert!(plan.full_rebuild);

        let after_python_remove = [55; 32];
        let python_removed_sources = [
            rust_edited_sources[0].clone(),
            rust_edited_sources[1].clone(),
            rust_edited_sources[2].clone(),
        ];
        let plan = store
            .plan_workspace_import_graph_refresh(
                &workspace_id,
                &after_python_remove,
                &resolver,
                &python_removed_sources,
            )
            .expect("plan unsupported Python removal");
        assert!(plan.full_rebuild);

        let after_rust_remove = [56; 32];
        let rust_removed_sources = [
            rust_edited_sources[1].clone(),
            rust_edited_sources[2].clone(),
            rust_edited_sources[3].clone(),
        ];
        let plan = store
            .plan_workspace_import_graph_refresh(
                &workspace_id,
                &after_rust_remove,
                &resolver,
                &rust_removed_sources,
            )
            .expect("plan Rust module removal in mixed workspace");
        assert!(!plan.full_rebuild);
        assert_eq!(plan.removed_source_paths, vec!["src/lib.rs".to_owned()]);
        assert!(plan.dirty_importer_paths.is_empty());
        assert_eq!(
            plan.dirty_import_ordinals,
            vec![("src/client.rs".to_owned(), 0)]
        );
    }

    #[test]
    fn removing_an_incomplete_provider_source_uses_a_full_rebuild() {
        let store = AnalyzerStore::open_ephemeral().expect("incomplete dependency store");
        let workspace_id = WorkspaceId::for_session();
        let resolver = [81; 32];
        let before = [82; 32];
        let before_sources = [
            source_with_module("src/lib.rs", 1, "demo::"),
            incomplete_source_with_module("legacy/app.py", 2, "legacy::app"),
        ];
        publish_initial(
            &store,
            &workspace_id,
            &before,
            &resolver,
            &before_sources,
            &[],
        );

        let after_sources = [before_sources[0].clone()];
        let plan = store
            .plan_workspace_import_graph_refresh(
                &workspace_id,
                &[83; 32],
                &resolver,
                &after_sources,
            )
            .expect("plan incomplete source removal");
        assert!(plan.full_rebuild);
        assert_eq!(plan.removed_source_paths, vec!["legacy/app.py".to_owned()]);
        assert_eq!(plan.dirty_importer_paths, vec!["src/lib.rs".to_owned()]);
    }

    #[test]
    fn removing_a_target_source_deletes_inbound_edge_facts_before_source_removal() {
        let store = AnalyzerStore::open_ephemeral().expect("removed target graph store");
        let workspace_id = WorkspaceId::for_session();
        let resolver = [121; 32];
        let before_identity = [122; 32];
        let before_sources = [source("src/client.rs", 1), source("src/target.rs", 2)];
        publish_initial(
            &store,
            &workspace_id,
            &before_identity,
            &resolver,
            &before_sources,
            &[edge("src/client.rs", "src/target.rs", &["src/target.rs"])],
        );

        let after_identity = [123; 32];
        let after_sources = [before_sources[0].clone()];
        let plan = store
            .plan_workspace_import_graph_refresh(
                &workspace_id,
                &after_identity,
                &resolver,
                &after_sources,
            )
            .expect("plan target-source removal");
        assert_eq!(plan.removed_source_paths, vec!["src/target.rs".to_owned()]);
        store
            .publish_workspace_import_graph_refresh(
                &workspace_id,
                &after_identity,
                &resolver,
                &plan,
                after_sources.len(),
                &[],
                &[],
                &[],
            )
            .expect("publish target-source removal");

        let connection = store.read_conn().expect("read removed target facts");
        let remaining_target_facts = connection
            .query_row(
                "SELECT COUNT(*) FROM workspace_import_edge_facts
                 WHERE workspace_id = ?1 AND target_path = 'src/target.rs'",
                [workspace_id.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .expect("count inbound edge facts");
        assert_eq!(remaining_target_facts, 0);
        drop(connection);
        let remaining_edges = store
            .read_workspace_import_graph(
                &workspace_id,
                &after_identity,
                WorkspaceImportDirection::Forward,
                &["src/client.rs".to_owned()],
                10,
            )
            .expect("read adjacency after target removal")
            .expect("updated graph is current");
        assert!(remaining_edges.edges.is_empty());
    }

    #[test]
    fn candidate_file_and_missing_module_dependencies_invalidate_importers() {
        let store = AnalyzerStore::open_ephemeral().expect("candidate dependency store");
        let workspace_id = WorkspaceId::for_session();
        let before = [31; 32];
        let resolver = [41; 32];
        let before_sources = [
            source_with_module("src/lib.rs", 1, "demo::"),
            source_with_module("src/client.rs", 2, "demo::client"),
            source_with_module("src/existing.rs", 3, "demo::existing"),
        ];
        let dependencies = [WorkspaceImportGraphDependencies {
            importer_path: "src/client.rs".to_owned(),
            lookups: vec![(0, "src/existing.rs".to_owned(), "NewItem".to_owned())],
            missing_module_path_keys: vec![(0, "demo::new_module".to_owned())],
        }];
        let plan = store
            .plan_workspace_import_graph_refresh(&workspace_id, &before, &resolver, &before_sources)
            .expect("plan initial candidate graph");
        store
            .publish_workspace_import_graph_refresh(
                &workspace_id,
                &before,
                &resolver,
                &plan,
                before_sources.len(),
                &before_sources,
                &[],
                &dependencies,
            )
            .expect("publish unresolved candidate facts");

        let after = [32; 32];
        let after_sources = [
            before_sources[0].clone(),
            before_sources[1].clone(),
            source_with_module("src/existing.rs", 4, "demo::existing"),
            source_with_module("src/new_module.rs", 5, "demo::new_module"),
        ];
        let plan = store
            .plan_workspace_import_graph_refresh(&workspace_id, &after, &resolver, &after_sources)
            .expect("plan edit and module addition");
        assert!(!plan.full_rebuild);
        assert_eq!(
            plan.dirty_importer_paths,
            vec!["src/existing.rs".to_owned(), "src/new_module.rs".to_owned()]
        );
        assert_eq!(
            plan.dirty_import_ordinals,
            vec![("src/client.rs".to_owned(), 0)]
        );
        assert_eq!(
            plan.dirty_lookup_ordinals,
            vec![("src/client.rs".to_owned(), 0)],
            "a newly added module changes the importer's missing-module lookup rows"
        );
    }

    fn explain(connection: &Connection, sql: &str, workspace_id: &WorkspaceId) -> Vec<String> {
        let mut statement = connection
            .prepare(sql)
            .expect("prepare import graph query plan");
        statement
            .query_map(params![workspace_id.as_str(), "src/lib.rs", 512], |row| {
                row.get(3)
            })
            .expect("explain import graph index query")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("decode import graph plan")
    }

    fn explain_named(
        connection: &Connection,
        sql: &str,
        workspace_id: &WorkspaceId,
    ) -> Vec<String> {
        let mut statement = connection
            .prepare(sql)
            .expect("prepare name-granular import graph query plan");
        statement
            .query_map(
                params![workspace_id.as_str(), "src/lib.rs", "Widget", 512],
                |row| row.get(3),
            )
            .expect("explain name-granular import graph index query")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("decode name-granular import graph plan")
    }

    #[test]
    fn import_graph_adjacency_and_import_ordinal_invalidation_use_indexes() {
        for statistics in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().expect("import graph plan store");
            let workspace_id = WorkspaceId::for_session();
            let sources = (0..512)
                .map(|index| source(&format!("src/module_{index}.rs"), 1))
                .chain(std::iter::once(source("src/lib.rs", 1)))
                .collect::<Vec<_>>();
            let edges = (0..512)
                .map(|index| {
                    let importer = format!("src/module_{index}.rs");
                    edge(&importer, "src/lib.rs", &[&importer, "src/lib.rs"])
                })
                .collect::<Vec<_>>();
            publish_initial(
                &store,
                &workspace_id,
                &[13; 32],
                &[23; 32],
                &sources,
                &edges,
            );
            let connection = store.conn.lock().expect("lock import graph planner");
            statistics.install(&connection);
            for (sql, required_index) in [
                (
                    "EXPLAIN QUERY PLAN SELECT importer_path, target_path FROM workspace_import_edges WHERE workspace_id = ?1 AND importer_path IN (?2) ORDER BY importer_path, target_path LIMIT ?3",
                    "sqlite_autoindex_workspace_import_edges_1",
                ),
                (
                    "EXPLAIN QUERY PLAN SELECT importer_path, target_path FROM workspace_import_edges WHERE workspace_id = ?1 AND target_path IN (?2) ORDER BY target_path, importer_path LIMIT ?3",
                    "workspace_import_edges_reverse_idx",
                ),
                (
                    "EXPLAIN QUERY PLAN SELECT importer_path, import_ordinal FROM workspace_import_candidate_file_dependencies INDEXED BY workspace_import_candidate_file_dependencies_consulted_idx WHERE workspace_id = ?1 AND consulted_path IN (?2) LIMIT ?3",
                    "workspace_import_candidate_file_dependencies_consulted_idx",
                ),
                (
                    "EXPLAIN QUERY PLAN SELECT importer_path, import_ordinal FROM workspace_import_missing_module_dependencies INDEXED BY workspace_import_missing_module_dependencies_key_idx WHERE workspace_id = ?1 AND module_path_key IN (?2) LIMIT ?3",
                    "workspace_import_missing_module_dependencies_key_idx",
                ),
                (
                    "EXPLAIN QUERY PLAN SELECT importer_path, import_ordinal, target_path FROM workspace_import_edge_facts INDEXED BY workspace_import_edge_facts_target_idx WHERE workspace_id = ?1 AND target_path IN (?2) LIMIT ?3",
                    "workspace_import_edge_facts_target_idx",
                ),
            ] {
                let plan = explain(&connection, sql, &workspace_id);
                assert!(
                    plan.iter().any(|detail| detail.contains(required_index)),
                    "{statistics}: expected {required_index}, got {plan:#?}"
                );
                assert!(
                    plan.iter().all(|detail| !detail.contains("AUTOMATIC")),
                    "{statistics}: automatic import graph index: {plan:#?}"
                );
            }
            for (sql, required_index) in [
                (
                    "EXPLAIN QUERY PLAN SELECT importer_path, import_ordinal FROM workspace_import_candidate_file_dependencies INDEXED BY workspace_import_candidate_file_dependencies_consulted_idx WHERE workspace_id = ?1 AND consulted_path = ?2 AND name IN (?3) LIMIT ?4",
                    "workspace_import_candidate_file_dependencies_consulted_idx",
                ),
                (
                    "EXPLAIN QUERY PLAN SELECT importer_path, import_ordinal FROM workspace_import_route_dependencies INDEXED BY workspace_import_route_dependencies_name_idx WHERE workspace_id = ?1 AND traversed_path = ?2 AND name = ?3 LIMIT ?4",
                    "workspace_import_route_dependencies_name_idx",
                ),
            ] {
                let plan = explain_named(&connection, sql, &workspace_id);
                assert!(
                    plan.iter().any(|detail| detail.contains(required_index)),
                    "{statistics}: expected {required_index}, got {plan:#?}"
                );
                assert!(
                    plan.iter().all(|detail| !detail.contains("AUTOMATIC")),
                    "{statistics}: automatic name-granular import graph index: {plan:#?}"
                );
            }
        }
    }

    #[test]
    fn import_graph_publication_uses_indexed_affected_pair_lookups() {
        use crate::analyzer::store::planner_statistics::pinned_plans::{pinned, plan_rows};

        for statistics in PlannerStatisticsState::BOTH {
            let store =
                AnalyzerStore::open_ephemeral().expect("import graph publication plan store");
            let workspace_id = WorkspaceId::for_session();
            let sources = (0..512)
                .map(|index| source(&format!("src/module_{index}.rs"), 1))
                .chain(std::iter::once(source("src/lib.rs", 1)))
                .collect::<Vec<_>>();
            let edges = (0..512)
                .map(|index| {
                    let importer = format!("src/module_{index}.rs");
                    edge(&importer, "src/lib.rs", &[&importer, "src/lib.rs"])
                })
                .collect::<Vec<_>>();
            let dependencies = (0..512)
                .map(|index| {
                    let importer_path = format!("src/module_{index}.rs");
                    WorkspaceImportGraphDependencies {
                        importer_path: importer_path.clone(),
                        lookups: vec![(0, importer_path, "Widget".to_owned())],
                        missing_module_path_keys: vec![(0, format!("demo::missing_{index}"))],
                    }
                })
                .collect::<Vec<_>>();
            publish_initial_with_dependencies(
                &store,
                &workspace_id,
                &[13; 32],
                &[23; 32],
                &sources,
                &edges,
                &dependencies,
            );
            let connection = store
                .conn
                .lock()
                .expect("lock import graph publication planner");
            statistics.install(&connection);
            for (name, required, forbidden) in [
                (
                    "import_graph_publish_select_existing_edge_pairs_256",
                    "workspace_import_edges_reverse_idx",
                    "SCAN workspace_import_edges",
                ),
                (
                    "import_graph_publish_select_edge_pairs_with_facts_256",
                    "workspace_import_edge_facts_source_target_idx",
                    "SCAN fact",
                ),
                (
                    "import_graph_publish_delete_exact_edge_pairs_256",
                    "workspace_import_edges_reverse_idx",
                    "SCAN workspace_import_edges",
                ),
                (
                    "import_graph_publish_select_edge_facts_by_ordinals_256",
                    "PRIMARY KEY",
                    "SCAN workspace_import_edge_facts",
                ),
                (
                    "import_graph_publish_delete_stale_edge_facts_64",
                    "PRIMARY KEY",
                    "SCAN workspace_import_edge_facts",
                ),
                (
                    "import_graph_publish_delete_candidate_dependency_rows_64",
                    "workspace_import_candidate_file_dependencies_consulted_idx",
                    "SCAN workspace_import_candidate_file_dependencies",
                ),
                (
                    "import_graph_publish_delete_route_dependency_rows_64",
                    "workspace_import_route_dependencies_name_idx",
                    "SCAN workspace_import_route_dependencies",
                ),
                (
                    "import_graph_publish_delete_missing_dependency_rows_64",
                    "workspace_import_missing_module_dependencies_key_idx",
                    "SCAN workspace_import_missing_module_dependencies",
                ),
            ] {
                let mut query = pinned(name);
                let workspace_positions = match name {
                    "import_graph_publish_select_edge_pairs_with_facts_256" => {
                        vec![query.params.len() - 1]
                    }
                    _ => vec![0],
                };
                for position in workspace_positions {
                    query.params[position] = Value::Text(workspace_id.as_str().to_owned());
                }
                let plan = plan_rows(&connection, &query)
                    .unwrap_or_else(|error| panic!("{statistics}: {name}: {error}"));
                assert!(
                    plan.iter().any(|detail| detail.contains(required)),
                    "{statistics}: expected {required} for {name}, got {plan:#?}"
                );
                assert!(
                    plan.iter().all(|detail| !detail.contains(forbidden)),
                    "{statistics}: {name} scans its full target: {plan:#?}"
                );
                assert!(
                    plan.iter().all(|detail| !detail.contains("AUTOMATIC")),
                    "{statistics}: {name} built an automatic index: {plan:#?}"
                );
            }
            for name in [
                "import_graph_publish_select_candidate_dependencies_by_ordinals_256",
                "import_graph_publish_select_route_dependencies_by_ordinals_256",
                "import_graph_publish_select_missing_dependencies_by_ordinals_256",
            ] {
                let mut query = pinned(name);
                query.params[0] = Value::Text(workspace_id.as_str().to_owned());
                let plan = plan_rows(&connection, &query)
                    .unwrap_or_else(|error| panic!("{statistics}: {name}: {error}"));
                assert!(
                    plan.iter().any(|detail| detail.contains("PRIMARY KEY")),
                    "{statistics}: {name} must seek the importer ordinal primary key: {plan:#?}"
                );
                assert!(
                    plan.iter().all(|detail| {
                        !detail.contains("SCAN workspace_import_") && !detail.contains("AUTOMATIC")
                    }),
                    "{statistics}: {name} scans or creates an automatic index: {plan:#?}"
                );
            }
            for (name, table) in [
                (
                    "import_graph_publish_delete_candidate_dependencies_by_importers_256",
                    "workspace_import_candidate_file_dependencies",
                ),
                (
                    "import_graph_publish_delete_route_dependencies_by_importers_256",
                    "workspace_import_route_dependencies",
                ),
                (
                    "import_graph_publish_delete_missing_dependencies_by_importers_256",
                    "workspace_import_missing_module_dependencies",
                ),
                (
                    "import_graph_publish_delete_source_modules",
                    "workspace_import_source_modules",
                ),
                (
                    "import_graph_publish_delete_source_bindings",
                    "workspace_import_source_bindings",
                ),
            ] {
                let mut query = pinned(name);
                query.params[0] = Value::Text(workspace_id.as_str().to_owned());
                let plan = plan_rows(&connection, &query)
                    .unwrap_or_else(|error| panic!("{statistics}: {name}: {error}"));
                assert!(
                    plan.iter()
                        .any(|detail| { detail.contains(table) && detail.contains("PRIMARY KEY") }),
                    "{statistics}: {name} must seek {table}'s primary key, got {plan:#?}"
                );
                assert!(
                    plan.iter()
                        .all(|detail| !detail.contains(&format!("SCAN {table}"))),
                    "{statistics}: {name} scans {table}: {plan:#?}"
                );
                assert!(
                    plan.iter().all(|detail| !detail.contains("AUTOMATIC")),
                    "{statistics}: {name} built an automatic index: {plan:#?}"
                );
            }

            let mut dirty_importer_edge_facts =
                pinned("import_graph_publish_select_edge_fact_keys_by_importers_256");
            dirty_importer_edge_facts.params[0] = Value::Text(workspace_id.as_str().to_owned());
            let dirty_importer_plan = plan_rows(&connection, &dirty_importer_edge_facts)
                .unwrap_or_else(|error| panic!("{statistics}: dirty importer edge facts: {error}"));
            assert!(
                dirty_importer_plan.iter().any(|detail| {
                    detail.contains("workspace_import_edge_facts_source_target_idx")
                        || detail.contains("workspace_import_edge_facts USING PRIMARY KEY")
                }),
                "{statistics}: dirty importer fact snapshot must seek the importer index: {dirty_importer_plan:#?}"
            );
            assert!(
                dirty_importer_plan.iter().all(|detail| !detail
                    .contains("SCAN workspace_import_edge_facts")
                    && !detail.contains("AUTOMATIC")),
                "{statistics}: dirty importer fact snapshot scans or builds an automatic index: {dirty_importer_plan:#?}"
            );

            for (name, required_index) in [
                (
                    "import_graph_publish_select_edge_facts_by_importer_paths_256",
                    "workspace_import_edge_facts_source_target_idx",
                ),
                (
                    "import_graph_publish_select_edge_facts_by_target_paths_256",
                    "workspace_import_edge_facts_target_idx",
                ),
            ] {
                let mut old_edges = pinned(name);
                old_edges.params[0] = Value::Text(workspace_id.as_str().to_owned());
                let plan = plan_rows(&connection, &old_edges)
                    .unwrap_or_else(|error| panic!("{statistics}: {name}: {error}"));
                assert!(
                    plan.iter().any(|detail| detail.contains(required_index)),
                    "{statistics}: {name} must seek {required_index}: {plan:#?}"
                );
                assert!(
                    plan.iter().all(|detail| {
                        !detail.contains("SCAN workspace_import_edge_facts")
                            && !detail.contains("AUTOMATIC")
                    }),
                    "{statistics}: {name} scans or creates an automatic index: {plan:#?}"
                );
            }

            {
                let (name, required_index) = (
                    "import_graph_publish_delete_edge_facts_by_removed_targets_256",
                    "workspace_import_edge_facts_target_idx",
                );
                let mut removed_edges = pinned(name);
                removed_edges.params[0] = Value::Text(workspace_id.as_str().to_owned());
                let plan = plan_rows(&connection, &removed_edges)
                    .unwrap_or_else(|error| panic!("{statistics}: {name}: {error}"));
                assert!(
                    plan.iter().any(|detail| detail.contains(required_index)),
                    "{statistics}: {name} must seek {required_index}: {plan:#?}"
                );
                assert!(
                    plan.iter().all(|detail| {
                        !detail.contains("SCAN workspace_import_edges")
                            && !detail.contains("AUTOMATIC")
                    }),
                    "{statistics}: {name} scans or creates an automatic index: {plan:#?}"
                );
            }

            let mut source_delete = pinned("import_graph_publish_delete_source");
            source_delete.params[0] = Value::Text(workspace_id.as_str().to_owned());
            let source_delete_plan = plan_rows(&connection, &source_delete)
                .unwrap_or_else(|error| panic!("{statistics}: source delete: {error}"));
            for expected in [
                "workspace_import_sources USING INDEX sqlite_autoindex_workspace_import_sources_1",
                "workspace_import_source_bindings USING PRIMARY KEY",
                "workspace_import_route_dependencies USING PRIMARY KEY",
                "workspace_import_edge_facts USING PRIMARY KEY",
                "workspace_import_edges USING COVERING INDEX workspace_import_edges_reverse_idx",
                "workspace_import_edges USING COVERING INDEX sqlite_autoindex_workspace_import_edges_1",
                "workspace_import_missing_module_dependencies USING PRIMARY KEY",
                "workspace_import_candidate_file_dependencies USING PRIMARY KEY",
                "workspace_import_source_modules USING PRIMARY KEY",
            ] {
                assert!(
                    source_delete_plan
                        .iter()
                        .any(|detail| detail.contains(expected)),
                    "{statistics}: source DELETE FK check/cascade must seek {expected}, got {source_delete_plan:#?}"
                );
            }
            assert!(
                source_delete_plan.iter().all(|detail| {
                    !detail.contains("SCAN workspace_import_") && !detail.contains("AUTOMATIC")
                }),
                "{statistics}: source delete has an FK table scan or automatic index: {source_delete_plan:#?}"
            );
            assert_eq!(
                source_delete_plan
                    .iter()
                    .filter(|detail| detail.contains("workspace_import_edge_facts"))
                    .count(),
                1,
                "{statistics}: source deletion must not run a second target-path FK probe: {source_delete_plan:#?}"
            );
            assert!(
                source_delete_plan.iter().any(|detail| {
                    detail.contains("workspace_import_edge_facts USING PRIMARY KEY (workspace_id=? AND importer_path=?)")
                }),
                "{statistics}: source deletion must retain the importer FK's primary-key lookup: {source_delete_plan:#?}"
            );

            let trigger_count = connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master
                     WHERE type = 'trigger' AND tbl_name LIKE 'workspace_import_%'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("count import-graph triggers");
            assert_eq!(
                trigger_count, 0,
                "{statistics}: import-graph triggers add hidden DML"
            );
        }
    }
}
