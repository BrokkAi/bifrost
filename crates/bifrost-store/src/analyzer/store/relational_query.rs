use std::path::Path;

use rusqlite::{OptionalExtension, Row, Transaction, params};

use brokk_bifrost_core::CancellationToken;
use brokk_bifrost_core::analyzer::{
    PackageRelationKind, PackageRelationValue, RelationalCallableFact, RelationalDefinitionQuery,
    RelationalDefinitionRequest, RelationalDefinitionValue, RelationalName,
};

use super::{
    AnalyzerStore, CandidateRow, CandidateRowContainer, FqIdentityHeader, GenerationId,
    HydratedCandidateRow, RelationalUnitFq, Result, StoreError, WorkspaceSnapshots,
    candidate_row_from_row, candidate_row_from_row_at, candidate_rows_for_languages_with,
    hydrate_candidate_rows, hydrate_mounted_candidate_conn, require_generation_map,
    signature_metadata_projection_from_row,
};
use crate::analyzer::store::StoreLanguageAdapter;
use crate::analyzer::{CodeUnit, ProjectFile, sort_units};
use crate::hash::HashMap;

const CANDIDATE_COLUMNS: &str =
    "names.blob_oid, units.lang, units.unit_key, units.kind, units.short_name,
     units.content_qualifier, units.signature, units.synthetic, units.is_type_alias,
     units.top_level_ordinal, units.in_declarations, units.in_definition_lookup,
     units.fq_anchor_kind, units.fq_anchor_pop, units.fq_package_tail_segments,
     units.fq_segment_count, units.exact_fqn_tail, units.fq_segment_bytes,
     units.normalized_fqn_tail, keys.parse_variant AS parse_variant";

const SET_QUERY_MIN_REQUESTS: usize = 64;

// This is deliberately separate from `content_sql`: the ordinary relational
// views are ready-only and therefore cannot witness a matching blob that was
// excluded by the source-facts readiness boundary. The candidate view keeps
// that row with a persisted availability bit for this bounded preflight.
#[doc(hidden)]
pub const CALLABLE_CANDIDATE_AVAILABILITY_SQL: &str = "SELECT EXISTS(
     SELECT 1
     FROM callable_candidate_definition_names AS names
     WHERE names.lang = ?1
       AND names.prefix = ?2
       AND names.tail = ?3
       AND names.exact_parent_tail = ?4
       AND names.identifier = ?5
       AND names.visibility_available = 0
     LIMIT 1
   )";

#[doc(hidden)]
pub fn content_sql(view: &str, predicate: &str) -> String {
    format!(
        "SELECT {CANDIDATE_COLUMNS}, names.rel_path
         FROM {view} AS names
         JOIN code_units AS units
           ON units.blob_id = names.blob_id
          AND units.unit_key = names.unit_key
         JOIN blobs AS keys ON keys.id = units.blob_id
         WHERE names.lang = ?1 AND names.source_kind <> 'path' AND {predicate}
         ORDER BY names.rel_path, names.blob_oid, units.unit_key"
    )
}

#[doc(hidden)]
pub fn render_name<A: StoreLanguageAdapter>(
    adapter: &A,
    name: &RelationalName,
) -> (String, String, String) {
    let interner = crate::analyzer::fq_name::segment_interner();
    (
        name.prefix().display_native(adapter.language(), interner),
        name.tail().display_native(adapter.language(), interner),
        name.full_name()
            .display_native(adapter.language(), interner),
    )
}

fn has_unknown_segments(name: &brokk_bifrost_core::analyzer::fq_name::FqName) -> bool {
    let interner = crate::analyzer::fq_name::segment_interner();
    name.segments().iter().any(|&segment| {
        interner.resolve(segment).1 == brokk_bifrost_core::analyzer::fq_name::SegmentKind::Unknown
    })
}

fn unit_matches_requested_name<A: StoreLanguageAdapter>(
    adapter: &A,
    unit: &CodeUnit,
    requested: &brokk_bifrost_core::analyzer::fq_name::FqName,
    normalized: bool,
) -> bool {
    let actual = if normalized {
        adapter.normalize_fq_name(unit.fq())
    } else {
        unit.fq().clone()
    };
    if has_unknown_segments(requested) {
        actual.same_native_spelling(requested, adapter.language())
    } else {
        actual == *requested
    }
}

fn tail_parent_and_identifier<A: StoreLanguageAdapter>(
    adapter: &A,
    name: &RelationalName,
) -> (String, String) {
    let interner = crate::analyzer::fq_name::segment_interner();
    let parent = name
        .tail()
        .parent()
        .expect("RelationalName guarantees a non-empty tail")
        .display_native(adapter.language(), interner);
    let identifier = interner
        .resolve(
            name.tail()
                .last()
                .expect("RelationalName guarantees a non-empty tail"),
        )
        .0
        .to_string();
    (parent, identifier)
}

fn decorated_identifier_prefix_successor(prefix: &str) -> String {
    let mut bytes = prefix.as_bytes().to_vec();
    let last = bytes
        .last_mut()
        .expect("an identifier-prefix request has a non-empty terminal");
    assert_eq!(
        *last, b'`',
        "identifier-prefix queries are decoration ranges"
    );
    *last = b'a';
    String::from_utf8(bytes).expect("replacing one ASCII byte preserves UTF-8")
}

fn query_content_candidates(
    tx: &Transaction<'_>,
    sql: &str,
    lang: &str,
    values: &[&dyn rusqlite::ToSql],
) -> Result<Vec<(HydratedCandidateRow, String)>> {
    let rows = candidate_rows_for_languages_with(tx, std::iter::once(lang), sql, values, |row| {
        Ok((candidate_row_from_row(row)?, row.get::<_, String>(20)?))
    })?;
    Ok(hydrate_candidate_rows(tx, rows, None)?
        .expect("uncancelled relational candidate hydration completes"))
}

fn hydrate_candidates<A: StoreLanguageAdapter>(
    tx: &Transaction<'_>,
    adapter: &A,
    project_root: &Path,
    rows: Vec<(HydratedCandidateRow, String)>,
) -> Result<Vec<CodeUnit>> {
    let mut units = Vec::with_capacity(rows.len());
    for (row, rel_path) in rows {
        units.push(hydrate_mounted_candidate_conn(
            tx,
            adapter,
            project_root,
            row,
            rel_path,
        )?);
    }
    sort_units(&mut units);
    units.dedup();
    Ok(units)
}

fn batched_request_rows_sql(request_values: &str) -> String {
    format!("SELECT CAST(key AS INTEGER), {request_values}\n             FROM json_each(?1)")
}

#[doc(hidden)]
pub fn batched_content_sql(
    view: &str,
    request_columns: &str,
    request_values: &str,
    join_predicate: &str,
) -> String {
    format!(
        "WITH requests(request_index, {request_columns}) AS MATERIALIZED ({})
         SELECT requests.request_index, {CANDIDATE_COLUMNS}, names.rel_path
         FROM requests
         CROSS JOIN {view} AS names ON names.lang = ?2
          AND names.source_kind <> 'path'
          AND {join_predicate}
         JOIN code_units AS units
           ON units.blob_id = names.blob_id
          AND units.unit_key = names.unit_key
         JOIN blobs AS keys ON keys.id = units.blob_id",
        batched_request_rows_sql(request_values)
    )
}

#[doc(hidden)]
pub fn scanned_content_sql(view: &str, request_values: &str, name_values: &str) -> String {
    format!(
        "WITH requests(request_index, lookup_key) AS MATERIALIZED (
             SELECT CAST(key AS INTEGER), json_array({request_values})
             FROM json_each(?1)
         )
         SELECT requests.request_index, {CANDIDATE_COLUMNS}, names.rel_path
         FROM {view} AS names
         CROSS JOIN requests ON requests.lookup_key = json_array({name_values})
         JOIN code_units AS units
           ON units.blob_id = names.blob_id
          AND units.unit_key = names.unit_key
         JOIN blobs AS keys ON keys.id = units.blob_id
         WHERE names.lang = ?2 AND names.source_kind <> 'path'"
    )
}

#[doc(hidden)]
pub fn batched_definition_order_sql(view: &str) -> String {
    format!(
        "WITH requests(request_index, prefix, parent_tail, identifier) AS MATERIALIZED (
             SELECT CAST(key AS INTEGER),
                    json_extract(value, '$[0]'), json_extract(value, '$[1]'),
                    json_extract(value, '$[2]')
             FROM json_each(?1)
         )
         SELECT requests.request_index, {CANDIDATE_COLUMNS}, names.rel_path,
                (SELECT MIN(ranges.start_byte)
                 FROM unit_ranges AS ranges
                 WHERE ranges.blob_id = units.blob_id
                   AND ranges.unit_key = units.unit_key) AS first_start_byte
         FROM requests
         CROSS JOIN {view} AS names ON names.lang = ?2
          AND names.source_kind <> 'path'
          AND names.prefix = requests.prefix
          AND names.exact_parent_tail = requests.parent_tail
          AND names.identifier = requests.identifier
         JOIN code_units AS units
           ON units.blob_id = names.blob_id
          AND units.unit_key = names.unit_key
         JOIN blobs AS keys ON keys.id = units.blob_id"
    )
}

struct BatchedContentQuery {
    seek_sql: String,
    scan_sql: String,
}

struct StoredDefinitionOrderCandidate<I = FqIdentityHeader> {
    candidate: CandidateRow<I>,
    rel_path: String,
    first_start_byte: Option<usize>,
}

type HydratedStoredDefinitionOrderCandidate = StoredDefinitionOrderCandidate<RelationalUnitFq>;

impl CandidateRowContainer for StoredDefinitionOrderCandidate {
    type Hydrated = HydratedStoredDefinitionOrderCandidate;

    fn candidate(&self) -> &CandidateRow {
        &self.candidate
    }

    fn with_hydrated_fq(self, fq: Option<RelationalUnitFq>) -> Self::Hydrated {
        StoredDefinitionOrderCandidate {
            candidate: super::candidate_with_hydrated_fq(self.candidate, fq),
            rel_path: self.rel_path,
            first_start_byte: self.first_start_byte,
        }
    }
}

impl CandidateRowContainer for (usize, StoredDefinitionOrderCandidate) {
    type Hydrated = (usize, HydratedStoredDefinitionOrderCandidate);

    fn candidate(&self) -> &CandidateRow {
        &self.1.candidate
    }

    fn with_hydrated_fq(self, fq: Option<RelationalUnitFq>) -> Self::Hydrated {
        (self.0, self.1.with_hydrated_fq(fq))
    }
}

#[doc(hidden)]
pub struct DefinitionOrderRow {
    #[doc(hidden)]
    pub unit: CodeUnit,
    #[doc(hidden)]
    pub first_start_byte: Option<usize>,
}

fn query_batched_content_candidates(
    tx: &Transaction<'_>,
    queries: &[BatchedContentQuery],
    request_json: &str,
    storage_languages: &[String],
    live_unit_counts: &HashMap<String, usize>,
    request_count: usize,
) -> Result<Vec<Vec<(HydratedCandidateRow, String)>>> {
    let mut candidates = std::iter::repeat_with(Vec::new)
        .take(request_count)
        .collect::<Vec<_>>();
    for query in queries {
        for lang in storage_languages {
            let scan_names = request_count > live_unit_counts.get(lang).copied().unwrap_or(0);
            let sql = if scan_names {
                &query.scan_sql
            } else {
                &query.seek_sql
            };
            let mut statement = tx.prepare_cached(sql)?;
            let rows = statement.query_map(params![request_json, lang], |row| {
                Ok((
                    candidate_row_from_row_at(row, 1)?,
                    (row.get::<_, usize>(0)?, row.get::<_, String>(21)?),
                ))
            })?;
            let rows = rows.collect::<std::result::Result<Vec<_>, _>>()?;
            drop(statement);
            let rows = hydrate_candidate_rows(tx, rows, None)?
                .expect("uncancelled relational batch hydration completes");
            for (candidate, (request_index, rel_path)) in rows {
                assert!(request_index < candidates.len());
                candidates[request_index].push((candidate, rel_path));
            }
        }
    }
    Ok(candidates)
}

fn query_batched_definition_order_candidates(
    tx: &Transaction<'_>,
    request_json: &str,
    storage_languages: &[String],
    request_count: usize,
) -> Result<Vec<Vec<HydratedStoredDefinitionOrderCandidate>>> {
    let mut flat = Vec::new();
    for view in [
        "live_stable_definition_parent_names",
        "live_anchored_definition_parent_names",
    ] {
        let sql = batched_definition_order_sql(view);
        let mut statement = tx.prepare_cached(&sql)?;
        for lang in storage_languages {
            let rows = statement.query_map(params![request_json, lang], |row| {
                Ok((
                    row.get::<_, usize>(0)?,
                    StoredDefinitionOrderCandidate {
                        candidate: candidate_row_from_row_at(row, 1)?,
                        rel_path: row.get::<_, String>(21)?,
                        first_start_byte: row.get::<_, Option<usize>>(22)?,
                    },
                ))
            })?;
            for row in rows {
                flat.push(row?);
            }
        }
    }
    let flat = hydrate_candidate_rows(tx, flat, None)?
        .expect("uncancelled definition-order hydration completes");
    let mut candidates = std::iter::repeat_with(Vec::new)
        .take(request_count)
        .collect::<Vec<_>>();
    for (request_index, candidate) in flat {
        assert!(request_index < candidates.len());
        candidates[request_index].push(candidate);
    }
    Ok(candidates)
}

/// The path-derived half of a batched set query: one request-relation query
/// against `live_path_symbol_names`, returning the units grouped by request
/// index so each set executor can append them to that request's content units.
///
/// The request relation is the same pattern `batched_content_sql` uses. The
/// Rust side has already serialized the batch's keys as one JSON array, and the
/// SQL reads it with `json_each(?1)`, so the array index is the request index.
/// `CROSS JOIN` keeps the requests as the outer loop, which is what lets SQLite
/// seek `idx_workspace_file_path_symbol_rows_short` / `_package` once per
/// request instead of walking the path rows once for the batch.
///
/// There is no `source_kind` filter and no content join: this view holds only
/// path rows, and a path row's unit comes from
/// `adapter.path_synthetic_module_unit` on the file, not from `code_units`.
#[doc(hidden)]
pub fn batched_path_sql(request_columns: &str, request_values: &str, predicate: &str) -> String {
    format!(
        "WITH requests(request_index, {request_columns}) AS ({})
         SELECT requests.request_index, names.rel_path
         FROM requests
         CROSS JOIN live_path_symbol_names AS names ON names.lang = ?2
          AND {predicate}",
        batched_request_rows_sql(request_values)
    )
}

/// The request-relation shape one set executor hands
/// [`query_batched_path_units`]. Named so the query-plan pin can build the SQL
/// the executor builds rather than a copy of it.
#[doc(hidden)]
pub struct BatchedPathRequest {
    #[doc(hidden)]
    pub columns: &'static str,
    #[doc(hidden)]
    pub values: &'static str,
    #[doc(hidden)]
    pub predicate: &'static str,
}

#[doc(hidden)]
pub const EXACT_PATH_REQUEST: BatchedPathRequest = BatchedPathRequest {
    columns: "prefix, parent_tail, identifier",
    values: "json_extract(value, '$[0]'), json_extract(value, '$[1]'), json_extract(value, '$[2]')",
    predicate: "requests.prefix = '' AND names.package_name = requests.parent_tail
                AND names.short_name = requests.identifier",
};

#[doc(hidden)]
pub const NORMALIZED_PATH_REQUEST: BatchedPathRequest = BatchedPathRequest {
    columns: "prefix, tail",
    values: "json_extract(value, '$[0]'), json_extract(value, '$[1]')",
    predicate: "requests.prefix = '' AND names.normalized_fqn = requests.tail",
};

#[doc(hidden)]
pub const STRUCTURAL_MEMBER_PATH_REQUEST: BatchedPathRequest = BatchedPathRequest {
    columns: "prefix, tail, identifier",
    values: "json_extract(value, '$[0]'), json_extract(value, '$[1]'), json_extract(value, '$[2]')",
    predicate: "requests.prefix = '' AND names.package_name = requests.tail
                AND names.short_name = requests.identifier",
};

#[allow(clippy::too_many_arguments)]
fn query_batched_path_units<A: StoreLanguageAdapter>(
    tx: &Transaction<'_>,
    adapter: &A,
    project_root: &Path,
    storage_languages: &[String],
    request_json: &str,
    request_columns: &str,
    request_values: &str,
    predicate: &str,
    request_count: usize,
) -> Result<Vec<Vec<CodeUnit>>> {
    let mut units = std::iter::repeat_with(Vec::new)
        .take(request_count)
        .collect::<Vec<Vec<CodeUnit>>>();
    if !adapter.has_path_synthetic_module_units() {
        return Ok(units);
    }
    let sql = batched_path_sql(request_columns, request_values, predicate);
    let mut statement = tx.prepare_cached(&sql)?;
    for lang in storage_languages {
        let rows = statement.query_map(params![request_json, lang], |row| {
            Ok((row.get::<_, usize>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (request_index, rel_path) = row?;
            assert!(request_index < units.len());
            let file = ProjectFile::new(project_root.to_path_buf(), rel_path);
            if let Some(unit) = adapter.hydrate_path_synthetic_module_unit_with_conn(tx, &file)? {
                units[request_index].push(unit);
            }
        }
    }
    Ok(units)
}

fn live_unit_counts(
    tx: &Transaction<'_>,
    storage_languages: &[String],
) -> Result<HashMap<String, usize>> {
    let mut statement = tx.prepare_cached(
        "SELECT COALESCE(SUM(meta.stored_unit_count), 0)
         FROM live_workspace_files AS files
         JOIN blob_meta AS meta
           ON meta.blob_id = files.blob_id
         WHERE files.lang = ?1",
    )?;
    storage_languages
        .iter()
        .map(|lang| {
            let count = statement.query_row(params![lang], |row| row.get::<_, usize>(0))?;
            Ok((lang.clone(), count))
        })
        .collect()
}

fn set_queries_need_live_unit_counts(requests: &[RelationalDefinitionRequest]) -> bool {
    let mut exact = 0usize;
    let mut normalized = 0usize;
    let mut structural_members = 0usize;
    for request in requests {
        let count = match request.query {
            RelationalDefinitionQuery::ExactName => &mut exact,
            RelationalDefinitionQuery::NormalizedName => &mut normalized,
            RelationalDefinitionQuery::StructuralMembers { .. } => &mut structural_members,
            _ => continue,
        };
        *count += 1;
        if *count == SET_QUERY_MIN_REQUESTS {
            return true;
        }
    }
    false
}

fn serialize_set_requests<T: serde::Serialize>(requests: &[T]) -> Result<String> {
    serde_json::to_string(requests)
        .map_err(|error| StoreError::new(format!("serializing relational set requests: {error}")))
}

fn hydrate_batched_definition_units<A: StoreLanguageAdapter>(
    tx: &Transaction<'_>,
    adapter: &A,
    project_root: &Path,
    rows: Vec<(HydratedCandidateRow, String)>,
    path_units: Vec<CodeUnit>,
) -> Result<Vec<CodeUnit>> {
    let mut units = hydrate_candidates(tx, adapter, project_root, rows)?;
    units.extend(path_units);
    Ok(units)
}

#[allow(clippy::too_many_arguments)]
fn set_exact_definition_values<A: StoreLanguageAdapter>(
    tx: &Transaction<'_>,
    adapter: &A,
    project_root: &Path,
    storage_languages: &[String],
    live_unit_counts: &HashMap<String, usize>,
    requests: &[RelationalDefinitionRequest],
    values: &mut [RelationalDefinitionValue],
    handled: &mut [bool],
) -> Result<()> {
    let indices = requests
        .iter()
        .enumerate()
        .filter_map(|(index, request)| {
            matches!(request.query, RelationalDefinitionQuery::ExactName).then_some(index)
        })
        .collect::<Vec<_>>();
    if indices.len() < SET_QUERY_MIN_REQUESTS {
        return Ok(());
    }
    let keys = indices
        .iter()
        .map(|&index| {
            let (prefix, _, _) = render_name(adapter, &requests[index].name);
            let (parent, identifier) = tail_parent_and_identifier(adapter, &requests[index].name);
            [prefix, parent, identifier]
        })
        .collect::<Vec<_>>();
    let request_json = serialize_set_requests(&keys)?;
    let queries = [
        "live_stable_definition_parent_names",
        "live_anchored_definition_parent_names",
    ]
    .map(|view| BatchedContentQuery {
        seek_sql: batched_content_sql(
            view,
            "prefix, parent_tail, identifier",
            "json_extract(value, '$[0]'), json_extract(value, '$[1]'), json_extract(value, '$[2]')",
            "names.prefix = requests.prefix
                 AND names.exact_parent_tail = requests.parent_tail
                 AND names.identifier = requests.identifier",
        ),
        scan_sql: scanned_content_sql(
            view,
            "json_extract(value, '$[0]'), json_extract(value, '$[1]'), json_extract(value, '$[2]')",
            "names.prefix, names.exact_parent_tail, names.identifier",
        ),
    });
    let candidates = query_batched_content_candidates(
        tx,
        &queries,
        &request_json,
        storage_languages,
        live_unit_counts,
        indices.len(),
    )?;
    let path_candidates = query_batched_path_units(
        tx,
        adapter,
        project_root,
        storage_languages,
        &request_json,
        EXACT_PATH_REQUEST.columns,
        EXACT_PATH_REQUEST.values,
        EXACT_PATH_REQUEST.predicate,
        indices.len(),
    )?;
    for (((request_index, request), rows), path_units) in indices
        .into_iter()
        .map(|index| (index, &requests[index]))
        .zip(candidates)
        .zip(path_candidates)
    {
        let full_name = request.name.full_name();
        let mut units =
            hydrate_batched_definition_units(tx, adapter, project_root, rows, path_units)?;
        units.retain(|unit| unit_matches_requested_name(adapter, unit, &full_name, false));
        sort_units(&mut units);
        units.dedup();
        values[request_index] = RelationalDefinitionValue::Definitions(units);
        handled[request_index] = true;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn set_normalized_definition_values<A: StoreLanguageAdapter>(
    tx: &Transaction<'_>,
    adapter: &A,
    project_root: &Path,
    storage_languages: &[String],
    live_unit_counts: &HashMap<String, usize>,
    requests: &[RelationalDefinitionRequest],
    values: &mut [RelationalDefinitionValue],
    handled: &mut [bool],
) -> Result<()> {
    let indices = requests
        .iter()
        .enumerate()
        .filter_map(|(index, request)| {
            matches!(request.query, RelationalDefinitionQuery::NormalizedName).then_some(index)
        })
        .collect::<Vec<_>>();
    if indices.len() < SET_QUERY_MIN_REQUESTS {
        return Ok(());
    }
    let keys = indices
        .iter()
        .map(|&index| {
            let (prefix, tail, _) = render_name(adapter, &requests[index].name);
            let (parent, identifier) = tail_parent_and_identifier(adapter, &requests[index].name);
            [prefix, tail, parent, identifier]
        })
        .collect::<Vec<_>>();
    let request_json = serialize_set_requests(&keys)?;
    let changed = [
        "live_stable_definition_normalized_names",
        "live_anchored_definition_normalized_names",
    ]
    .map(|view| BatchedContentQuery {
        seek_sql: batched_content_sql(
            view,
            "prefix, tail",
            "json_extract(value, '$[0]'), json_extract(value, '$[1]')",
            "names.prefix = requests.prefix AND names.tail = requests.tail",
        ),
        scan_sql: scanned_content_sql(
            view,
            "json_extract(value, '$[0]'), json_extract(value, '$[1]')",
            "names.prefix, names.tail",
        ),
    });
    let unchanged = [
        "live_stable_definition_parent_names",
        "live_anchored_definition_parent_names",
    ]
    .map(|view| {
        BatchedContentQuery {
            seek_sql: batched_content_sql(
                view,
                "prefix, tail, parent_tail, identifier",
                "json_extract(value, '$[0]'), json_extract(value, '$[1]'), json_extract(value, '$[2]'), json_extract(value, '$[3]')",
                "names.prefix = requests.prefix
                 AND names.exact_parent_tail = requests.parent_tail
                 AND names.identifier = requests.identifier
                 AND names.tail = requests.tail
                 AND names.normalized_tail IS NULL",
            ),
            scan_sql: scanned_content_sql(
                view,
                "json_extract(value, '$[0]'), json_extract(value, '$[1]')",
                "names.prefix, names.tail",
            ),
        }
    });
    let queries = changed.into_iter().chain(unchanged).collect::<Vec<_>>();
    let candidates = query_batched_content_candidates(
        tx,
        &queries,
        &request_json,
        storage_languages,
        live_unit_counts,
        indices.len(),
    )?;
    let path_candidates = query_batched_path_units(
        tx,
        adapter,
        project_root,
        storage_languages,
        &request_json,
        NORMALIZED_PATH_REQUEST.columns,
        NORMALIZED_PATH_REQUEST.values,
        NORMALIZED_PATH_REQUEST.predicate,
        indices.len(),
    )?;
    for (((request_index, request), rows), path_units) in indices
        .into_iter()
        .map(|index| (index, &requests[index]))
        .zip(candidates)
        .zip(path_candidates)
    {
        let full_name = request.name.full_name();
        let mut units = hydrate_candidates(tx, adapter, project_root, rows)?;
        units.extend(path_units);
        units.retain(|unit| unit_matches_requested_name(adapter, unit, &full_name, true));
        sort_units(&mut units);
        units.dedup();
        values[request_index] = RelationalDefinitionValue::Definitions(units);
        handled[request_index] = true;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn set_structural_member_values<A: StoreLanguageAdapter>(
    tx: &Transaction<'_>,
    adapter: &A,
    project_root: &Path,
    storage_languages: &[String],
    live_unit_counts: &HashMap<String, usize>,
    requests: &[RelationalDefinitionRequest],
    values: &mut [RelationalDefinitionValue],
    handled: &mut [bool],
) -> Result<()> {
    let indices = requests
        .iter()
        .enumerate()
        .filter_map(|(index, request)| {
            matches!(
                request.query,
                RelationalDefinitionQuery::StructuralMembers { .. }
            )
            .then_some(index)
        })
        .collect::<Vec<_>>();
    if indices.len() < SET_QUERY_MIN_REQUESTS {
        return Ok(());
    }
    let keys = indices
        .iter()
        .map(|&index| {
            let request = &requests[index];
            let (prefix, tail, _) = render_name(adapter, &request.name);
            let RelationalDefinitionQuery::StructuralMembers { identifier } = &request.query else {
                unreachable!()
            };
            [prefix, tail, identifier.clone()]
        })
        .collect::<Vec<_>>();
    let request_json = serialize_set_requests(&keys)?;
    let queries = [
        "live_stable_definition_parent_names",
        "live_anchored_definition_parent_names",
    ]
    .map(|view| BatchedContentQuery {
        seek_sql: batched_content_sql(
            view,
            "prefix, parent_tail, identifier",
            "json_extract(value, '$[0]'), json_extract(value, '$[1]'), json_extract(value, '$[2]')",
            "names.prefix = requests.prefix
                 AND names.exact_parent_tail = requests.parent_tail
                 AND names.identifier = requests.identifier",
        ),
        scan_sql: scanned_content_sql(
            view,
            "json_extract(value, '$[0]'), json_extract(value, '$[1]'), json_extract(value, '$[2]')",
            "names.prefix, names.exact_parent_tail, names.identifier",
        ),
    });
    let candidates = query_batched_content_candidates(
        tx,
        &queries,
        &request_json,
        storage_languages,
        live_unit_counts,
        indices.len(),
    )?;
    let path_candidates = query_batched_path_units(
        tx,
        adapter,
        project_root,
        storage_languages,
        &request_json,
        STRUCTURAL_MEMBER_PATH_REQUEST.columns,
        STRUCTURAL_MEMBER_PATH_REQUEST.values,
        STRUCTURAL_MEMBER_PATH_REQUEST.predicate,
        indices.len(),
    )?;
    for ((request_index, rows), path_units) in
        indices.into_iter().zip(candidates).zip(path_candidates)
    {
        let mut units =
            hydrate_batched_definition_units(tx, adapter, project_root, rows, path_units)?;
        sort_units(&mut units);
        units.dedup();
        values[request_index] = RelationalDefinitionValue::Definitions(units);
        handled[request_index] = true;
    }
    Ok(())
}

/// The predicate a path-derived lookup uses over `live_path_symbol_names`,
/// aliased `names`, with its parameter values numbered from `?2` because `?1`
/// is the language.
///
/// A path-derived module unit is a declaration the analyzer invents for a file
/// whose module name comes from its path rather than from anything written in
/// the file: `pkg/service.py` is the module `pkg.service` although no line in
/// it says so. Python, JavaScript, and TypeScript have them; the languages that
/// write their package identity into the file text do not.
///
/// The wide views map a path row onto the shared column names this way, and
/// every predicate below is that mapping read backwards: `prefix` is always the
/// empty string, `identifier` and `simple_type_name` are `short_name`,
/// `exact_parent_tail` and `package_tail` are `package_name`, and `tail` is
/// `exact_fqn` in the exact views and `normalized_fqn` in the normalized one.
/// A request whose rendered prefix is not empty can therefore never match a
/// path row, which is why every shape that carries a prefix returns `None` in
/// that case instead of issuing a query that is provably empty.
///
/// Path-derived `VisibleMembers` shares `StructuralMembers`' predicate. The
/// content-backed view also projects language-specific visibility containers.
///
/// `PackageTypes` and `PackageTypesInPackage` add `names.kind = 0` because the
/// path arm of `live_package_types` carries `WHERE symbols.kind = 0`.
#[doc(hidden)]
pub fn path_view_predicate<A: StoreLanguageAdapter>(
    adapter: &A,
    request: &RelationalDefinitionRequest,
    prefix: &str,
    tail: &str,
) -> Option<(String, Vec<String>)> {
    if !prefix.is_empty()
        && !matches!(
            request.query,
            RelationalDefinitionQuery::Identifier { .. }
                | RelationalDefinitionQuery::IdentifierPrefix { .. }
        )
    {
        return None;
    }
    match &request.query {
        RelationalDefinitionQuery::ExactName => {
            let (parent, identifier) = tail_parent_and_identifier(adapter, &request.name);
            Some((
                "names.package_name = ?2 AND names.short_name = ?3".to_string(),
                vec![parent, identifier],
            ))
        }
        RelationalDefinitionQuery::NormalizedName => Some((
            "names.normalized_fqn = ?2".to_string(),
            vec![tail.to_string()],
        )),
        RelationalDefinitionQuery::StructuralChildren => Some((
            "names.package_name = ?2".to_string(),
            vec![tail.to_string()],
        )),
        RelationalDefinitionQuery::StructuralMembers { identifier }
        | RelationalDefinitionQuery::VisibleMembers { identifier } => Some((
            "names.package_name = ?2 AND names.short_name = ?3".to_string(),
            vec![tail.to_string(), identifier.clone()],
        )),
        RelationalDefinitionQuery::Identifier { file } => {
            let (_, identifier) = tail_parent_and_identifier(adapter, &request.name);
            Some(match file {
                Some(file) => (
                    "names.short_name = ?2 AND names.rel_path = ?3".to_string(),
                    vec![identifier, crate::path_utils::rel_path_string(file)],
                ),
                None => ("names.short_name = ?2".to_string(), vec![identifier]),
            })
        }
        RelationalDefinitionQuery::IdentifierPrefix { file } => {
            let (_, identifier) = tail_parent_and_identifier(adapter, &request.name);
            let upper = decorated_identifier_prefix_successor(&identifier);
            Some(match file {
                Some(file) => (
                    "names.short_name >= ?2 AND names.short_name < ?3 AND names.rel_path = ?4"
                        .to_string(),
                    vec![identifier, upper, crate::path_utils::rel_path_string(file)],
                ),
                None => (
                    "names.short_name >= ?2 AND names.short_name < ?3".to_string(),
                    vec![identifier, upper],
                ),
            })
        }
        RelationalDefinitionQuery::PackageTypes { simple_name } => Some((
            "names.package_name = ?2 AND names.short_name = ?3 AND names.kind = 0".to_string(),
            vec![tail.to_string(), simple_name.clone()],
        )),
        RelationalDefinitionQuery::PackageTypesInPackage => Some((
            "names.package_name = ?2 AND names.kind = 0".to_string(),
            vec![tail.to_string()],
        )),
        RelationalDefinitionQuery::PackageRelation(_)
        | RelationalDefinitionQuery::CallableFacts => None,
    }
}

/// One path-derived point lookup against `live_path_symbol_names`, given a
/// predicate from [`path_view_predicate`].
///
/// There is no `ORDER BY`: `definition_values` sorts and dedups every shape's
/// merged result already, and the SQL sort only adds a temp B-tree.
#[doc(hidden)]
pub fn path_view_sql(predicate: &str) -> String {
    format!(
        "SELECT names.rel_path
         FROM live_path_symbol_names AS names
         WHERE names.lang = ?1 AND {predicate}"
    )
}

fn path_units<A: StoreLanguageAdapter>(
    tx: &Transaction<'_>,
    adapter: &A,
    project_root: &Path,
    lang: &str,
    predicate: &str,
    values: &[&dyn rusqlite::ToSql],
) -> Result<Vec<CodeUnit>> {
    if !adapter.has_path_synthetic_module_units() {
        return Ok(Vec::new());
    }
    let sql = path_view_sql(predicate);
    let mut statement = tx.prepare_cached(&sql)?;
    let parameters = std::iter::once(&lang as &dyn rusqlite::ToSql).chain(values.iter().copied());
    let paths = statement
        .query_map(rusqlite::params_from_iter(parameters), |row| {
            row.get::<_, String>(0)
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut units = paths
        .into_iter()
        .map(|rel_path| {
            adapter.hydrate_path_synthetic_module_unit_with_conn(
                tx,
                &ProjectFile::new(project_root.to_path_buf(), rel_path),
            )
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    sort_units(&mut units);
    units.dedup();
    Ok(units)
}

/// Content-derived candidates for one (view, predicate, values) point query,
/// hydrated into `CodeUnit`s. Shared by the split-view fast path and the
/// single wide-view fallback in [`definition_values`].
fn query_view_candidates<A: StoreLanguageAdapter>(
    tx: &Transaction<'_>,
    adapter: &A,
    project_root: &Path,
    storage_languages: &[String],
    view: &str,
    predicate: &str,
    owned_values: &[String],
) -> Result<Vec<CodeUnit>> {
    let sql = content_sql(view, predicate);
    let values = owned_values
        .iter()
        .map(|value| value as &dyn rusqlite::ToSql)
        .collect::<Vec<_>>();
    let mut units = Vec::new();
    for lang in storage_languages {
        let rows = query_content_candidates(tx, &sql, lang, &values)?;
        units.extend(hydrate_candidates(tx, adapter, project_root, rows)?);
    }
    Ok(units)
}

/// Split-view sources for the point-query shapes that
/// [`set_exact_definition_values`], [`set_normalized_definition_values`],
/// and [`set_structural_member_values`] already serve through the batched
/// path once a request batch reaches `SET_QUERY_MIN_REQUESTS`. Below that
/// threshold -- which is where almost all of `AnalyzerDefinitionLookup`'s
/// per-owner and per-name traffic falls, since it asks about a handful of
/// candidates at a time -- `definition_values` used to fall back to a single
/// query against the wide `UNION ALL` compound views
/// (`live_definition_exact_names`, `live_definition_normalized_names`,
/// `live_structural_members`). Those wide views combine a stable-name arm,
/// an anchored-name arm, and a path-derived-name arm.
///
/// EXPLAIN QUERY PLAN against an empty schema (see
/// `probe_structural_members_point_query_plan` et al. in this module's test
/// suite, kept here as evidence, superseded below by the permanent pin)
/// shows the stable arm correctly seeking its intended partial index
/// (`idx_code_units_stable_parent_identifier` /
/// `idx_code_units_stable_normalized_tail`), because `fq_anchor_kind IS
/// NULL` is a literal condition on that arm. The anchored arm cannot do the
/// same: `fq_anchor_kind`/`fq_anchor_pop` there come from a correlated join
/// to `workspace_file_anchors`, not from a request literal, so SQLite cannot
/// seek `idx_code_units_anchored_parent_identifier` (whose leading columns
/// are `fq_anchor_kind, fq_anchor_pop`) by the request's parent/identifier
/// at all. It instead drives the anchored arm from `workspace_file_anchors`
/// filtered by language alone -- a full per-language scan of every file
/// anchor. The wide view's third (path-derived) arm is pure waste on this
/// call site regardless: its rows always carry `source_kind = 'path'`, and
/// `content_sql`'s `names.source_kind <> 'path'` predicate discards every
/// one of them, but SQLite still fully computes that arm (including, for
/// JavaScript/TypeScript, a correlated `import_statements` existence check
/// per row) before discarding its output.
///
/// Migration `crates/bifrost-core/migrations/cache/0027-relational-definition-set-views.sql`
/// already built four lean views for exactly this problem --
/// `live_stable_definition_parent_names`, `live_anchored_definition_parent_names`,
/// `live_stable_definition_normalized_names`, `live_anchored_definition_normalized_names`
/// -- each forcing its matching partial index with `INDEXED BY` and omitting
/// the path-derived arm entirely. Its header comment states they exist to
/// let "a batch's request rows ... drive the same selective indexes as
/// prepared point queries", but only the batched `set_*` functions were
/// wired up to use them. This function gives prepared point queries the
/// same treatment: query the stable and anchored views directly (two
/// `INDEXED BY`-forced seeks instead of one push-down-dependent compound
/// scan) and union the results in Rust, which `sort_units`/`dedup` in
/// `definition_values` already do for every query shape. Row-for-row output
/// is unchanged: the wide view's stable/anchored arms and the lean views
/// select the same rows under the same predicate, and the path arm never
/// contributed any candidate rows to this call site in the first place.
///
/// `Identifier`/`IdentifierPrefix` (issue #2588 residual cost) get the same
/// treatment for a different reason: `idx_code_units_lang_identifier_lookup`
/// (from `0018-current-baseline.sql`) is keyed on `(lang, identifier)` with
/// no `fq_anchor_kind` prefix, so both the wide view's stable and anchored
/// arms already seek it directly with no correlated-anchor-scan defect. But
/// SQLite still fully materializes the wide compound view as a co-routine
/// before joining it, and still unconditionally computes the wasted path
/// arm described above. Migration
/// `crates/bifrost-core/migrations/cache/0030-relational-definition-identifier-views.sql`
/// adds `live_stable_definition_identifiers` /
/// `live_anchored_definition_identifiers` -- the same stable/anchored split,
/// minus the path arm -- for exactly these two shapes.
/// `AnalyzerDefinitionLookup` issues `Identifier`/`IdentifierPrefix`
/// requests on nearly every exact-name and normalized-name lookup (to check
/// source-spelling and mounted-name compatibility), so this shape sees the
/// same call volume as the four shapes above, not just literal identifier
/// searches.
///
/// Returns `None` for shapes that have no split-view equivalent (they keep
/// using the wide view through the fallback path in `definition_values`).
#[doc(hidden)]
pub fn split_view_sources<A: StoreLanguageAdapter>(
    adapter: &A,
    request: &RelationalDefinitionRequest,
    prefix: &str,
    tail: &str,
) -> Option<Vec<(&'static str, String, Vec<String>)>> {
    match &request.query {
        RelationalDefinitionQuery::ExactName => {
            let (parent, identifier) = tail_parent_and_identifier(adapter, &request.name);
            let predicate =
                "names.prefix = ?2 AND names.exact_parent_tail = ?3 AND names.identifier = ?4"
                    .to_string();
            let values = vec![prefix.to_string(), parent, identifier];
            Some(vec![
                (
                    "live_stable_definition_parent_names",
                    predicate.clone(),
                    values.clone(),
                ),
                ("live_anchored_definition_parent_names", predicate, values),
            ])
        }
        RelationalDefinitionQuery::NormalizedName => {
            let (parent, identifier) = tail_parent_and_identifier(adapter, &request.name);
            let changed_predicate = "names.prefix = ?2 AND names.tail = ?3".to_string();
            let changed_values = vec![prefix.to_string(), tail.to_string()];
            let unchanged_predicate = "names.prefix = ?2 AND names.exact_parent_tail = ?3 \
                 AND names.identifier = ?4 AND names.tail = ?5 AND names.normalized_tail IS NULL"
                .to_string();
            let unchanged_values = vec![prefix.to_string(), parent, identifier, tail.to_string()];
            Some(vec![
                (
                    "live_stable_definition_normalized_names",
                    changed_predicate.clone(),
                    changed_values.clone(),
                ),
                (
                    "live_anchored_definition_normalized_names",
                    changed_predicate,
                    changed_values,
                ),
                (
                    "live_stable_definition_parent_names",
                    unchanged_predicate.clone(),
                    unchanged_values.clone(),
                ),
                (
                    "live_anchored_definition_parent_names",
                    unchanged_predicate,
                    unchanged_values,
                ),
            ])
        }
        RelationalDefinitionQuery::StructuralChildren => {
            let predicate = "names.prefix = ?2 AND names.exact_parent_tail = ?3".to_string();
            let values = vec![prefix.to_string(), tail.to_string()];
            Some(vec![
                (
                    "live_stable_definition_parent_names",
                    predicate.clone(),
                    values.clone(),
                ),
                ("live_anchored_definition_parent_names", predicate, values),
            ])
        }
        RelationalDefinitionQuery::StructuralMembers { identifier } => {
            let predicate =
                "names.prefix = ?2 AND names.exact_parent_tail = ?3 AND names.identifier = ?4"
                    .to_string();
            let values = vec![prefix.to_string(), tail.to_string(), identifier.clone()];
            Some(vec![
                (
                    "live_stable_definition_parent_names",
                    predicate.clone(),
                    values.clone(),
                ),
                ("live_anchored_definition_parent_names", predicate, values),
            ])
        }
        RelationalDefinitionQuery::Identifier { file } => {
            let (_, identifier) = tail_parent_and_identifier(adapter, &request.name);
            let (predicate, values): (String, Vec<String>) = match file {
                Some(file) => (
                    "names.rel_path = ?2 AND names.identifier = ?3".to_string(),
                    vec![crate::path_utils::rel_path_string(file), identifier],
                ),
                None => ("names.identifier = ?2".to_string(), vec![identifier]),
            };
            Some(vec![
                (
                    "live_stable_definition_identifiers",
                    predicate.clone(),
                    values.clone(),
                ),
                ("live_anchored_definition_identifiers", predicate, values),
            ])
        }
        RelationalDefinitionQuery::IdentifierPrefix { file } => {
            let (_, identifier) = tail_parent_and_identifier(adapter, &request.name);
            let upper = decorated_identifier_prefix_successor(&identifier);
            let (predicate, values): (String, Vec<String>) = match file {
                Some(file) => (
                    "names.rel_path = ?2 AND names.identifier >= ?3 AND names.identifier < ?4"
                        .to_string(),
                    vec![crate::path_utils::rel_path_string(file), identifier, upper],
                ),
                None => (
                    "names.identifier >= ?2 AND names.identifier < ?3".to_string(),
                    vec![identifier, upper],
                ),
            };
            Some(vec![
                (
                    "live_stable_definition_identifiers",
                    predicate.clone(),
                    values.clone(),
                ),
                ("live_anchored_definition_identifiers", predicate, values),
            ])
        }
        RelationalDefinitionQuery::PackageTypes { simple_name } => {
            let predicate =
                "names.prefix = ?2 AND names.package_tail = ?3 AND names.simple_type_name = ?4"
                    .to_string();
            let values = vec![prefix.to_string(), tail.to_string(), simple_name.clone()];
            Some(vec![
                (
                    "live_stable_package_types",
                    predicate.clone(),
                    values.clone(),
                ),
                ("live_anchored_package_types", predicate, values),
            ])
        }
        RelationalDefinitionQuery::PackageTypesInPackage => {
            let predicate = "names.prefix = ?2 AND names.package_tail = ?3".to_string();
            let values = vec![prefix.to_string(), tail.to_string()];
            Some(vec![
                (
                    "live_stable_package_types",
                    predicate.clone(),
                    values.clone(),
                ),
                ("live_anchored_package_types", predicate, values),
            ])
        }
        RelationalDefinitionQuery::VisibleMembers { .. }
        | RelationalDefinitionQuery::PackageRelation(_)
        | RelationalDefinitionQuery::CallableFacts => None,
    }
}

fn definition_values<A: StoreLanguageAdapter>(
    tx: &Transaction<'_>,
    adapter: &A,
    project_root: &Path,
    storage_languages: &[String],
    request: &RelationalDefinitionRequest,
) -> Result<Vec<CodeUnit>> {
    let (prefix, tail, _) = render_name(adapter, &request.name);
    let (view, predicate, owned_values): (&str, &str, Vec<String>) = match &request.query {
        RelationalDefinitionQuery::ExactName => {
            let (parent, identifier) = tail_parent_and_identifier(adapter, &request.name);
            (
                "live_definition_exact_names",
                "names.prefix = ?2 AND names.exact_parent_tail = ?3 AND names.identifier = ?4",
                vec![prefix.clone(), parent, identifier],
            )
        }
        RelationalDefinitionQuery::NormalizedName => (
            "live_definition_normalized_names",
            "names.prefix = ?2 AND names.tail = ?3",
            vec![prefix.clone(), tail.clone()],
        ),
        RelationalDefinitionQuery::StructuralChildren => (
            "live_structural_members",
            "names.prefix = ?2 AND names.exact_parent_tail = ?3",
            vec![prefix.clone(), tail.clone()],
        ),
        RelationalDefinitionQuery::StructuralMembers { identifier } => (
            "live_structural_members",
            "names.prefix = ?2 AND names.exact_parent_tail = ?3 AND names.identifier = ?4",
            vec![prefix.clone(), tail.clone(), identifier.clone()],
        ),
        RelationalDefinitionQuery::VisibleMembers { identifier } => (
            "live_visible_members",
            "names.prefix = ?2 AND names.exact_parent_tail = ?3 AND names.identifier = ?4",
            vec![prefix.clone(), tail.clone(), identifier.clone()],
        ),
        RelationalDefinitionQuery::Identifier { file } => {
            let (_, identifier) = tail_parent_and_identifier(adapter, &request.name);
            match file {
                Some(file) => (
                    "live_definition_identifiers",
                    "names.rel_path = ?2 AND names.identifier = ?3",
                    vec![crate::path_utils::rel_path_string(file), identifier],
                ),
                None => (
                    "live_definition_identifiers",
                    "names.identifier = ?2",
                    vec![identifier],
                ),
            }
        }
        RelationalDefinitionQuery::IdentifierPrefix { file } => {
            let (_, identifier) = tail_parent_and_identifier(adapter, &request.name);
            let upper = decorated_identifier_prefix_successor(&identifier);
            match file {
                Some(file) => (
                    "live_definition_identifiers",
                    "names.rel_path = ?2 AND names.identifier >= ?3 AND names.identifier < ?4",
                    vec![crate::path_utils::rel_path_string(file), identifier, upper],
                ),
                None => (
                    "live_definition_identifiers",
                    "names.identifier >= ?2 AND names.identifier < ?3",
                    vec![identifier, upper],
                ),
            }
        }
        RelationalDefinitionQuery::PackageTypes { simple_name } => (
            "live_package_types",
            "names.prefix = ?2 AND names.package_tail = ?3 AND names.simple_type_name = ?4",
            vec![prefix.clone(), tail.clone(), simple_name.clone()],
        ),
        RelationalDefinitionQuery::PackageTypesInPackage => (
            "live_package_types",
            "names.prefix = ?2 AND names.package_tail = ?3",
            vec![prefix.clone(), tail.clone()],
        ),
        RelationalDefinitionQuery::PackageRelation(_)
        | RelationalDefinitionQuery::CallableFacts => {
            unreachable!("non-definition query routed to definition_values")
        }
    };
    let mut units = Vec::new();
    match split_view_sources(adapter, request, &prefix, &tail) {
        Some(sources) => {
            for (source_view, source_predicate, source_values) in &sources {
                units.extend(query_view_candidates(
                    tx,
                    adapter,
                    project_root,
                    storage_languages,
                    source_view,
                    source_predicate,
                    source_values,
                )?);
            }
        }
        None => {
            units.extend(query_view_candidates(
                tx,
                adapter,
                project_root,
                storage_languages,
                view,
                predicate,
                &owned_values,
            )?);
        }
    }
    // Path-derived rows live in exactly one place, `live_path_symbol_names`,
    // whichever way the content rows were fetched. The query is a no-op unless
    // the adapter opts into path-synthetic module units, and
    // `path_view_predicate` declines the shapes no path row can answer.
    if let Some((path_predicate, path_owned_values)) =
        path_view_predicate(adapter, request, &prefix, &tail)
    {
        let path_values = path_owned_values
            .iter()
            .map(|value| value as &dyn rusqlite::ToSql)
            .collect::<Vec<_>>();
        for lang in storage_languages {
            units.extend(path_units(
                tx,
                adapter,
                project_root,
                lang,
                &path_predicate,
                &path_values,
            )?);
        }
    }

    let full_name = request.name.full_name();
    match request.query {
        RelationalDefinitionQuery::ExactName => {
            units.retain(|unit| unit_matches_requested_name(adapter, unit, &full_name, false))
        }
        RelationalDefinitionQuery::NormalizedName => {
            units.retain(|unit| unit_matches_requested_name(adapter, unit, &full_name, true))
        }
        RelationalDefinitionQuery::StructuralChildren
        | RelationalDefinitionQuery::StructuralMembers { .. }
        | RelationalDefinitionQuery::VisibleMembers { .. } => {}
        RelationalDefinitionQuery::Identifier { .. }
        | RelationalDefinitionQuery::IdentifierPrefix { .. }
        | RelationalDefinitionQuery::PackageTypes { .. }
        | RelationalDefinitionQuery::PackageTypesInPackage => {}
        RelationalDefinitionQuery::PackageRelation(_)
        | RelationalDefinitionQuery::CallableFacts => {
            unreachable!()
        }
    }
    sort_units(&mut units);
    units.dedup();
    Ok(units)
}

fn package_relation_value<A: StoreLanguageAdapter>(
    tx: &Transaction<'_>,
    adapter: &A,
    project_root: &Path,
    storage_languages: &[String],
    name: &RelationalName,
    relation: PackageRelationKind,
) -> Result<PackageRelationValue> {
    let package = name.full_name().display_native(
        adapter.language(),
        crate::analyzer::fq_name::segment_interner(),
    );
    match relation {
        PackageRelationKind::Exists => Ok(PackageRelationValue::Exists(package_exists(
            tx,
            storage_languages,
            &package,
        )?)),
        PackageRelationKind::Files => {
            let mut files = Vec::new();
            let mut statement = tx.prepare_cached(
                "SELECT rel_path FROM live_workspace_package_files
                 WHERE lang = ?1 AND package_name = ?2 ORDER BY rel_path",
            )?;
            for lang in storage_languages {
                let paths =
                    statement.query_map(params![lang, package], |row| row.get::<_, String>(0))?;
                for path in paths {
                    files.push(ProjectFile::new(project_root.to_path_buf(), path?));
                }
            }
            files.sort();
            files.dedup();
            Ok(PackageRelationValue::Files(files))
        }
        PackageRelationKind::Children | PackageRelationKind::Descendants => {
            let (sql, child_column) = match relation {
                PackageRelationKind::Children => (
                    "SELECT child_package_name FROM live_workspace_package_edges
                     WHERE lang = ?1 AND parent_package_name = ?2
                     ORDER BY child_package_name",
                    0,
                ),
                PackageRelationKind::Descendants => (
                    "SELECT descendant_package_name FROM live_workspace_package_descendants
                     WHERE lang = ?1 AND ancestor_package_name = ?2
                     ORDER BY descendant_package_name",
                    0,
                ),
                _ => unreachable!(),
            };
            let mut packages = Vec::new();
            let mut statement = tx.prepare_cached(sql)?;
            for lang in storage_languages {
                packages.extend(
                    statement
                        .query_map(params![lang, package], |row| {
                            row.get::<_, String>(child_column)
                        })?
                        .collect::<std::result::Result<Vec<_>, _>>()?,
                );
            }
            packages.sort();
            packages.dedup();
            Ok(PackageRelationValue::Packages(packages))
        }
    }
}

fn package_exists(
    tx: &Transaction<'_>,
    storage_languages: &[String],
    package: &str,
) -> Result<bool> {
    let mut statement = tx.prepare_cached(PACKAGE_EXISTS_SQL)?;
    for lang in storage_languages {
        if statement
            .query_row(params![lang, package], |_| Ok(()))
            .optional()?
            .is_some()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

// `live_workspace_package_files` remains authoritative for liveness. Repeating
// its active-generation equality here gives SQLite all three leading columns
// of the membership primary key; without it, SQLite seeks only `lang` and
// walks every package membership for that language.
#[doc(hidden)]
pub const PACKAGE_EXISTS_SQL: &str = "SELECT 1 FROM live_workspace_package_files
     WHERE lang = ?1
       AND generation = COALESCE(
         (SELECT generation FROM analysis_epochs WHERE lang = ?1), 0
       )
       AND package_name = ?2
     LIMIT 1";

fn callable_metadata(
    row: &Row<'_>,
    base: usize,
) -> rusqlite::Result<Option<crate::analyzer::SignatureMetadata>> {
    if row.get::<_, Option<String>>(base)?.is_none() {
        Ok(None)
    } else {
        signature_metadata_projection_from_row(row, base).map(Some)
    }
}

fn callable_values<A: StoreLanguageAdapter>(
    tx: &Transaction<'_>,
    adapter: &A,
    project_root: &Path,
    storage_languages: &[String],
    request: &RelationalDefinitionRequest,
) -> Result<Vec<RelationalCallableFact>> {
    let (prefix, tail, _) = render_name(adapter, &request.name);
    let (parent, identifier) = tail_parent_and_identifier(adapter, &request.name);
    let candidate_sql = content_sql(
        "live_definition_exact_names",
        "names.prefix = ?2 AND names.exact_parent_tail = ?3 AND names.identifier = ?4",
    );
    let metadata_columns = super::signature_metadata_projection_columns_sql("facts");
    let fact_sql = format!(
        "SELECT facts.ordinal, facts.text,
                {metadata_columns}, facts.pairing_available
         FROM live_callable_facts AS facts
         WHERE facts.blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2 AND parse_variant = ?4)
           AND facts.unit_key = ?3
         ORDER BY facts.ordinal, facts.metadata_ordinal"
    );
    let mut facts = Vec::new();
    for lang in storage_languages {
        let visibility_unavailable = tx
            .prepare_cached(CALLABLE_CANDIDATE_AVAILABILITY_SQL)?
            .query_row(params![lang, &prefix, &tail, &parent, &identifier], |row| {
                row.get::<_, bool>(0)
            })?;
        if visibility_unavailable {
            return Err(StoreError::new(format!(
                "canonical declaration visibility is unavailable for callable candidates in {lang}"
            )));
        }
        let candidates =
            query_content_candidates(tx, &candidate_sql, lang, &[&prefix, &parent, &identifier])?;
        for (candidate, rel_path) in candidates {
            let locator = (
                super::BlobKey {
                    oid: candidate.blob_oid,
                    lang: candidate.lang.clone(),
                    variant: candidate.variant,
                },
                candidate.unit_key,
            );
            let mut units =
                hydrate_candidates(tx, adapter, project_root, vec![(candidate, rel_path)])?;
            let declaration = units.pop().expect("a callable row has one declaration");
            if declaration.fq() != &request.name.full_name() {
                continue;
            }
            let mut statement = tx.prepare_cached(&fact_sql)?;
            let rows = statement.query_map(
                params![
                    locator.0.oid.to_string(),
                    locator.0.lang,
                    locator.1,
                    locator.0.variant
                ],
                |row| {
                    if row
                        .get::<_, Option<bool>>(3 + super::SIGNATURE_METADATA_VALUE_COLUMNS.len())?
                        != Some(true)
                    {
                        return Err(super::rusqlite_error_from_store(StoreError::new(
                            "callable signature/metadata pairing is unavailable",
                        )));
                    }
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        callable_metadata(row, 2)?,
                    ))
                },
            )?;
            for row in rows {
                let (ordinal, signature, metadata) = row?;
                facts.push(RelationalCallableFact {
                    declaration: declaration.clone(),
                    signature_ordinal: usize::try_from(ordinal).map_err(|_| {
                        StoreError::new(format!("negative callable signature ordinal {ordinal}"))
                    })?,
                    signature,
                    metadata,
                });
            }
        }
    }
    facts.sort_by(|left, right| {
        crate::path_utils::rel_path_string(left.declaration.source())
            .cmp(&crate::path_utils::rel_path_string(
                right.declaration.source(),
            ))
            .then_with(|| left.declaration.fq_name().cmp(&right.declaration.fq_name()))
            .then_with(|| left.signature_ordinal.cmp(&right.signature_ordinal))
    });
    facts.dedup();
    Ok(facts)
}

#[doc(hidden)]
pub enum RelationalStoreOutcome {
    Complete(Vec<RelationalDefinitionValue>),
    Cancelled,
}

impl AnalyzerStore {
    /// Execute already-deduplicated relational requests through one reader and
    /// one SQLite snapshot. `None` means cancellation: no prefix of the batch
    /// is ever presented as a complete answer.
    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    pub fn relational_definition_values<A, F>(
        &self,
        adapter: &A,
        project_root: &Path,
        generations: &HashMap<String, GenerationId>,
        storage_languages: &[String],
        workspace_snapshots: &WorkspaceSnapshots,
        requests: &[RelationalDefinitionRequest],
        cancellation: &CancellationToken,
        merge_overlay: F,
    ) -> Result<RelationalStoreOutcome>
    where
        A: StoreLanguageAdapter,
        F: FnOnce(&mut [RelationalDefinitionValue]),
    {
        if cancellation.is_cancelled() {
            return Ok(RelationalStoreOutcome::Cancelled);
        }
        #[cfg(any(test, feature = "test-support"))]
        self.relational_batch_reader_checkouts
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut connection = self.read_conn_for_workspace(workspace_snapshots)?;
        let tx = connection.transaction()?;
        #[cfg(any(test, feature = "test-support"))]
        self.relational_batch_generation_validations
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        #[cfg(any(test, feature = "test-support"))]
        self.relational_batch_distinct_requests
            .fetch_add(requests.len(), std::sync::atomic::Ordering::Relaxed);
        require_generation_map(
            &tx,
            generations,
            storage_languages.iter().map(String::as_str),
        )?;
        let mut values = requests
            .iter()
            .map(|request| RelationalDefinitionValue::empty_for(&request.query))
            .collect::<Vec<_>>();
        let mut handled = vec![false; requests.len()];
        let live_unit_counts = if set_queries_need_live_unit_counts(requests) {
            #[cfg(any(test, feature = "test-support"))]
            self.relational_live_unit_count_queries
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            live_unit_counts(&tx, storage_languages)?
        } else {
            HashMap::default()
        };
        set_exact_definition_values(
            &tx,
            adapter,
            project_root,
            storage_languages,
            &live_unit_counts,
            requests,
            &mut values,
            &mut handled,
        )?;
        if cancellation.is_cancelled() {
            return Ok(RelationalStoreOutcome::Cancelled);
        }
        set_normalized_definition_values(
            &tx,
            adapter,
            project_root,
            storage_languages,
            &live_unit_counts,
            requests,
            &mut values,
            &mut handled,
        )?;
        if cancellation.is_cancelled() {
            return Ok(RelationalStoreOutcome::Cancelled);
        }
        set_structural_member_values(
            &tx,
            adapter,
            project_root,
            storage_languages,
            &live_unit_counts,
            requests,
            &mut values,
            &mut handled,
        )?;
        if cancellation.is_cancelled() {
            return Ok(RelationalStoreOutcome::Cancelled);
        }
        for (index, request) in requests.iter().enumerate() {
            if handled[index] {
                continue;
            }
            if cancellation.is_cancelled() {
                return Ok(RelationalStoreOutcome::Cancelled);
            }
            let value = match request.query {
                RelationalDefinitionQuery::PackageRelation(relation) => {
                    RelationalDefinitionValue::PackageRelation(package_relation_value(
                        &tx,
                        adapter,
                        project_root,
                        storage_languages,
                        &request.name,
                        relation,
                    )?)
                }
                RelationalDefinitionQuery::CallableFacts => {
                    RelationalDefinitionValue::CallableFacts(callable_values(
                        &tx,
                        adapter,
                        project_root,
                        storage_languages,
                        request,
                    )?)
                }
                _ => RelationalDefinitionValue::Definitions(definition_values(
                    &tx,
                    adapter,
                    project_root,
                    storage_languages,
                    request,
                )?),
            };
            values[index] = value;
        }
        merge_overlay(&mut values);
        if cancellation.is_cancelled() {
            return Ok(RelationalStoreOutcome::Cancelled);
        }
        tx.commit()?;
        Ok(RelationalStoreOutcome::Complete(values))
    }

    /// Whether one exact package has a live workspace member in any selected
    /// storage language. This is the direct, allocation-free package relation
    /// used by analyzer hot paths that need only the Boolean answer (#2795).
    #[doc(hidden)]
    pub fn workspace_package_exists_for_langs(
        &self,
        storage_languages: &[String],
        generations: &HashMap<String, GenerationId>,
        workspace_snapshots: &WorkspaceSnapshots,
        package: &str,
    ) -> Result<bool> {
        let mut connection = self.read_conn_for_workspace(workspace_snapshots)?;
        let tx = connection.transaction()?;
        require_generation_map(
            &tx,
            generations,
            storage_languages.iter().map(String::as_str),
        )?;
        let exists = package_exists(&tx, storage_languages, package)?;
        tx.commit()?;
        Ok(exists)
    }

    /// Primary declaration positions for an exact-name batch.
    ///
    /// Relational definition values are sets and therefore publish path-stable
    /// order. Navigation's older `IAnalyzer::definitions` contract instead
    /// ranks equal-name candidates by declaration priority and first source
    /// position. Fetch only that ordering payload for the already-selected
    /// physical identities: one request relation drives the same exact-name
    /// indexes as the ordinary set query, and the correlated range lookup uses
    /// `unit_ranges`' primary key without hydrating complete file states.
    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    pub fn relational_exact_definition_order_rows<A: StoreLanguageAdapter>(
        &self,
        adapter: &A,
        project_root: &Path,
        generations: &HashMap<String, GenerationId>,
        storage_languages: &[String],
        workspace_snapshots: &WorkspaceSnapshots,
        names: &[RelationalName],
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<Vec<DefinitionOrderRow>>>> {
        if names.is_empty() {
            return Ok(Some(Vec::new()));
        }
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let mut connection = self.read_conn_for_workspace(workspace_snapshots)?;
        let tx = connection.transaction()?;
        require_generation_map(
            &tx,
            generations,
            storage_languages.iter().map(String::as_str),
        )?;
        let keys = names
            .iter()
            .map(|name| {
                let (prefix, _, _) = render_name(adapter, name);
                let (parent, identifier) = tail_parent_and_identifier(adapter, name);
                [prefix, parent, identifier]
            })
            .collect::<Vec<_>>();
        let request_json = serialize_set_requests(&keys)?;
        let candidates = query_batched_definition_order_candidates(
            &tx,
            &request_json,
            storage_languages,
            names.len(),
        )?;
        if cancellation.is_cancelled() {
            return Ok(None);
        }

        let mut values = Vec::with_capacity(names.len());
        for (name, rows) in names.iter().zip(candidates) {
            let full_name = name.full_name();
            let mut by_unit: HashMap<CodeUnit, Option<usize>> = HashMap::default();
            for row in rows {
                let mut hydrated = hydrate_candidates(
                    &tx,
                    adapter,
                    project_root,
                    vec![(row.candidate, row.rel_path)],
                )?;
                let unit = hydrated
                    .pop()
                    .expect("one ordering candidate hydrates one declaration");
                if !unit_matches_requested_name(adapter, &unit, &full_name, false) {
                    continue;
                }
                by_unit
                    .entry(unit)
                    .and_modify(|current| {
                        *current = match (*current, row.first_start_byte) {
                            (Some(left), Some(right)) => Some(left.min(right)),
                            (Some(left), None) => Some(left),
                            (None, Some(right)) => Some(right),
                            (None, None) => None,
                        }
                    })
                    .or_insert(row.first_start_byte);
            }
            values.push(
                by_unit
                    .into_iter()
                    .map(|(unit, first_start_byte)| DefinitionOrderRow {
                        unit,
                        first_start_byte,
                    })
                    .collect(),
            );
        }
        tx.commit()?;
        Ok(Some(values))
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn relational_batch_counts_for_test(&self) -> (usize, usize, usize) {
        (
            self.relational_batch_reader_checkouts
                .load(std::sync::atomic::Ordering::Relaxed),
            self.relational_batch_generation_validations
                .load(std::sync::atomic::Ordering::Relaxed),
            self.relational_batch_distinct_requests
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn relational_live_unit_count_queries_for_test(&self) -> usize {
        self.relational_live_unit_count_queries
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod tests {
    #[cfg(test)]
    use brokk_bifrost_test_macros::hardwon;
    #[cfg(test)]
    use rusqlite::params;

    #[cfg(test)]
    use super::CALLABLE_CANDIDATE_AVAILABILITY_SQL;
    #[cfg(test)]
    use super::{
        AnalyzerStore, PACKAGE_EXISTS_SQL, batched_content_sql, batched_definition_order_sql,
        scanned_content_sql,
    };

    #[cfg(test)]
    use crate::analyzer::store::REVISIONED_WORKSPACE_VIEWS_SQL;

    // Every EXPLAIN QUERY PLAN pin below runs its assertions once against a
    // store with no planner statistics and once with the statistics captured
    // from real corpus stores, because production carries the latter (#3016).
    #[cfg(test)]
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;

    #[doc(hidden)]
    pub fn explain_query_plan(
        connection: &rusqlite::Connection,
        label: &str,
        sql: &str,
        bindings: &[&str],
    ) -> Vec<String> {
        let mut statement = connection
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .unwrap_or_else(|error| panic!("prepare {label} query plan: {error}"));
        statement
            .query_map(rusqlite::params_from_iter(bindings), |row| {
                row.get::<_, String>(3)
            })
            .unwrap_or_else(|error| panic!("read {label} query plan: {error}"))
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap_or_else(|error| panic!("collect {label} query plan: {error}"))
    }

    #[cfg(test)]
    #[test]
    #[hardwon(
        "ff7bbbb91467: package existence walked live membership instead of seeking the exact name"
    )]
    fn package_exists_query_seeks_exact_live_membership() {
        for state in PlannerStatisticsState::BOTH {
            package_exists_query_seeks_exact_live_membership_in(state);
        }
    }

    #[cfg(test)]
    fn package_exists_query_seeks_exact_live_membership_in(state: PlannerStatisticsState) {
        let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
        let connection = store.conn.lock().expect("store mutex");
        state.install(&connection);
        let mut statement = connection
            .prepare(&format!("EXPLAIN QUERY PLAN {PACKAGE_EXISTS_SQL}"))
            .expect("prepare exact package-membership query plan");
        let plan = statement
            .query_map(params!["php", "Vendor.Package"], |row| {
                row.get::<_, String>(3)
            })
            .expect("read exact package-membership query plan")
            .collect::<std::result::Result<Vec<_>, _>>()
            .expect("collect exact package-membership query plan");

        assert!(
            plan.iter().any(|detail| {
                detail.contains("idx_workspace_file_package_rows_name")
                    && detail.contains("package_name=?")
            }),
            "exact package membership must seek its package-name index {state}: {plan:#?}"
        );
        // Revision membership must be a keyed lookup, by either of the two
        // keys that reach one file version: the snapshot range
        // (workspace_id, lang, generation) or the row's own integer primary
        // key. Which one the planner picks depends on which relation it drives
        // from, and that legitimately differs between the two states (#3016).
        //
        // With no statistics it drives from the snapshot range and probes the
        // package-name index once per file in the snapshot:
        //
        //     SEARCH versions USING COVERING INDEX
        //       idx_workspace_file_versions_snapshot_blob
        //       (workspace_id=? AND lang=? AND generation=?)
        //     SEARCH versions USING INTEGER PRIMARY KEY (rowid=?)
        //     ...
        //     SEARCH rows USING COVERING INDEX
        //       idx_workspace_file_package_rows_name
        //       (package_name=? AND file_version_id=?)
        //
        // With the captured statistics it drives from the requested package
        // name and reaches each matching file version by its rowid:
        //
        //     SEARCH rows USING COVERING INDEX
        //       idx_workspace_file_package_rows_name (package_name=?)
        //     SEARCH versions USING INTEGER PRIMARY KEY (rowid=?)
        //     SEARCH versions USING INTEGER PRIMARY KEY (rowid=?)
        //
        // The second is the better plan and the one this query is for: it
        // starts from the one requested package instead of walking every file
        // version of the snapshot, which is the same "narrow by name before
        // revision membership" property `definition_point_queries_seek_split_
        // view_indexes` pins for the definition views. Migration 104 added
        // input_kind to the shared workspace-file-version key. Under the
        // captured statistics SQLite can therefore use the generated unique
        // index, which is still a bounded lookup on workspace, language,
        // generation, and input kind. Pin the access property rather than one
        // physical index name. SQLite can also render the exact unique
        // (file_version_id, lang) lookup as an index seek rather than as an
        // INTEGER PRIMARY KEY seek.
        assert!(
            plan.iter().any(|detail| {
                detail.contains("idx_workspace_file_versions_snapshot_blob")
                    || detail.contains("SEARCH versions USING INTEGER PRIMARY KEY")
                    || (detail.starts_with("SEARCH versions USING")
                        && detail.contains("file_version_id=?")
                        && detail.contains("lang=?"))
                    || (detail.contains("sqlite_autoindex_workspace_file_versions_1")
                        && detail.contains("workspace_id=?")
                        && detail.contains("lang=?")
                        && detail.contains("generation=?")
                        && detail.contains("input_kind=?"))
            }),
            "exact package membership must reach revision membership by a key {state}: {plan:#?}"
        );
        assert!(
            plan.iter().all(|detail| !detail.contains("SCAN members")
                && !detail.contains("SCAN versions")
                && !detail.contains("SCAN rows")),
            "exact package membership must not scan workspace_package_files, its file \
             versions, or its package rows {state}: {plan:#?}"
        );
    }

    #[cfg(test)]
    #[test]
    #[hardwon(
        "4871e560ddbe: set-oriented definition queries materialized broad views instead of seeking names"
    )]
    fn set_definition_queries_seek_name_indexes() {
        for state in PlannerStatisticsState::BOTH {
            set_definition_queries_seek_name_indexes_in(state);
        }
    }

    #[cfg(test)]
    fn set_definition_queries_seek_name_indexes_in(state: PlannerStatisticsState) {
        let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
        let connection = store.conn.lock().expect("store mutex");
        state.install(&connection);
        let explain = |sql: String, request_json: &str| {
            let mut statement = connection
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .expect("prepare query plan");
            statement
                .query_map(params![request_json, "scala"], |row| {
                    row.get::<_, String>(3)
                })
                .expect("read query plan")
                .collect::<std::result::Result<Vec<_>, _>>()
                .expect("collect query plan")
        };

        let parent_plan = |view| {
            explain(
                batched_content_sql(
                    view,
                    "prefix, parent_tail, identifier",
                    "json_extract(value, '$[0]'), json_extract(value, '$[1]'), json_extract(value, '$[2]')",
                    "names.prefix = requests.prefix
                     AND names.exact_parent_tail = requests.parent_tail
                     AND names.identifier = requests.identifier",
                ),
                r#"[["","demo.Widget","run"]]"#,
            )
        };
        let normalized_plan = |view| {
            explain(
                batched_content_sql(
                    view,
                    "prefix, tail, parent_tail, identifier",
                    "json_extract(value, '$[0]'), json_extract(value, '$[1]'), json_extract(value, '$[2]'), json_extract(value, '$[3]')",
                    "names.prefix = requests.prefix AND names.tail = requests.tail",
                ),
                r#"[["","demo.Widget","demo","Widget"]]"#,
            )
        };
        let plans = [
            (
                "stable parent",
                parent_plan("live_stable_definition_parent_names"),
                "idx_code_units_stable_parent_identifier",
            ),
            (
                "anchored parent",
                parent_plan("live_anchored_definition_parent_names"),
                "idx_code_units_anchored_parent_identifier",
            ),
            (
                "stable normalized",
                normalized_plan("live_stable_definition_normalized_names"),
                "idx_code_units_stable_normalized_tail",
            ),
            (
                "anchored normalized",
                normalized_plan("live_anchored_definition_normalized_names"),
                "idx_code_units_anchored_normalized_tail",
            ),
        ];

        for (name, plan, index) in plans {
            assert!(
                plan.iter().any(|detail| detail.contains(index)),
                "{name} set query must seek {index} {state}: {plan:#?}"
            );
            assert!(
                plan.iter()
                    .any(|detail| detail.contains("SCAN json_each VIRTUAL TABLE")),
                "{name} set query must drive from its bounded request relation {state}: {plan:#?}"
            );
            assert!(
                plan.iter()
                    .all(|detail| !detail.contains("SCAN code_units")),
                "{name} set query must not scan code_units {state}: {plan:#?}"
            );
        }

        let scanned_plans = [
            (
                "stable parent",
                explain(
                    scanned_content_sql(
                        "live_stable_definition_parent_names",
                        "json_extract(value, '$[0]'), json_extract(value, '$[1]'), json_extract(value, '$[2]')",
                        "names.prefix, names.exact_parent_tail, names.identifier",
                    ),
                    r#"[["","demo.Widget","run"]]"#,
                ),
                "idx_code_units_stable_parent_identifier",
            ),
            (
                "stable normalized",
                explain(
                    scanned_content_sql(
                        "live_stable_definition_normalized_names",
                        "json_extract(value, '$[0]'), json_extract(value, '$[1]')",
                        "names.prefix, names.tail",
                    ),
                    r#"[["","demo.Widget"]]"#,
                ),
                "idx_code_units_stable_normalized_tail",
            ),
        ];
        for (name, plan, index) in scanned_plans {
            assert!(
                plan.iter().any(|detail| detail.contains(index)),
                "{name} names-driven query must walk {index} {state}: {plan:#?}"
            );
            assert!(
                plan.iter().any(|detail| {
                    detail.contains("SEARCH requests USING AUTOMATIC")
                        && detail.contains("COVERING INDEX (lookup_key=?)")
                }),
                "{name} names-driven query must probe a bounded ephemeral request index {state}: {plan:#?}"
            );
            assert!(
                plan.iter()
                    .all(|detail| !detail.contains("SCAN code_units")),
                "{name} names-driven query must not scan code_units {state}: {plan:#?}"
            );
        }

        let order_plan = explain(
            batched_definition_order_sql("live_stable_definition_parent_names"),
            r#"[["","demo.Widget","run"]]"#,
        );
        assert!(
            order_plan
                .iter()
                .any(|detail| detail.contains("idx_code_units_stable_parent_identifier")),
            "definition ordering must seek the exact-name index {state}: {order_plan:#?}"
        );
        assert!(
            order_plan.iter().any(|detail| {
                detail.contains("SEARCH ranges USING PRIMARY KEY")
                    && detail.contains("blob_id=?")
                    && detail.contains("unit_key=?")
            }),
            "definition ordering must seek ranges by their unit key {state}: {order_plan:#?}"
        );
        assert!(
            order_plan.iter().all(
                |detail| !detail.contains("SCAN code_units") && !detail.contains("SCAN ranges")
            ),
            "definition ordering must scan neither code units nor ranges {state}: {order_plan:#?}"
        );
    }

    #[cfg(test)]
    #[test]
    fn callable_candidate_preflight_seeks_stable_and_anchored_name_indexes() {
        let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
        let connection = store.conn.lock().expect("store mutex");
        connection
            .execute_batch(REVISIONED_WORKSPACE_VIEWS_SQL)
            .expect("install revisioned candidate views");
        let mut statement = connection
            .prepare(&format!(
                "EXPLAIN QUERY PLAN {CALLABLE_CANDIDATE_AVAILABILITY_SQL}"
            ))
            .expect("prepare callable candidate availability plan");
        let plan = statement
            .query_map(params!["java", "demo", "Widget", "demo", "Widget"], |row| {
                row.get::<_, String>(3)
            })
            .expect("read callable candidate availability plan")
            .collect::<std::result::Result<Vec<_>, _>>()
            .expect("collect callable candidate availability plan");

        assert!(
            plan.iter()
                .any(|detail| detail.contains("idx_code_units_stable_parent_identifier")),
            "stable callable candidates must seek the stable name index: {plan:#?}"
        );
        assert!(
            plan.iter()
                .any(|detail| detail.contains("idx_code_units_anchored_parent_identifier")),
            "anchored callable candidates must seek the anchored name index: {plan:#?}"
        );
        assert!(
            plan.iter()
                .any(|detail| detail.contains("idx_workspace_file_anchor_rows_package")),
            "anchored callable candidates must seek the package anchor index: {plan:#?}"
        );
        assert!(
            plan.iter()
                .all(|detail| !detail.contains("SCAN units") && !detail.contains("SCAN anchors")),
            "callable candidate preflight must not scan name or anchor rows: {plan:#?}"
        );
    }
}

/// Batched relational lookups against a populated store.
///
/// The fixture writes rows the way the parse-time writer does (one
/// `code_units` row and its `code_unit_fq_segments` per declaration, built
/// from `prepare_unit_fq`) and publishes a workspace snapshot through the
/// production snapshot writer. Every expected answer below is written out by
/// hand from the fixture table. Batches of at least `SET_QUERY_MIN_REQUESTS`
/// requests take the set-oriented SQL, and each batched answer must also equal
/// the answer the same request gets alone, which takes the point-query SQL.
#[cfg(test)]
mod batched_query_tests {
    use std::path::PathBuf;

    use brokk_bifrost_core::CancellationToken;
    use brokk_bifrost_core::analyzer::fq_name::{FqName, SegmentKind, segment_interner};
    use brokk_bifrost_core::analyzer::{
        DefinitionLanguageScope, PackageRelationKind, PackageRelationValue,
        RelationalDefinitionQuery, RelationalDefinitionRequest, RelationalDefinitionValue,
        RelationalName,
    };
    use git2::Oid;
    use rusqlite::params;

    use super::{AnalyzerStore, RelationalStoreOutcome, SET_QUERY_MIN_REQUESTS, live_unit_counts};
    use crate::analyzer::store::{
        GenerationId, PathSymbolRow, StoreLanguageAdapter, WorkspaceAnchorRow, WorkspaceFileRow,
        WorkspacePackageEdgeRow, WorkspacePackageFileRow, WorkspaceSnapshots,
        code_unit_kind_to_i64, prepare_unit_fq, test_blob_oid,
    };
    use crate::analyzer::{
        CodeUnit, CodeUnitType, Language, PackageAnchor, ProjectFile, sort_units,
    };
    use crate::hash::HashMap;

    const P: SegmentKind = SegmentKind::Package;
    const T: SegmentKind = SegmentKind::Type;
    const M: SegmentKind = SegmentKind::Member;
    const N: SegmentKind = SegmentKind::Nested;
    const U: SegmentKind = SegmentKind::Unknown;
    const PADDING_UNITS: usize = 70;

    fn fq(parts: &[(&str, SegmentKind)]) -> FqName {
        let interner = segment_interner();
        let mut name = FqName::new();
        for (text, kind) in parts {
            name.push(interner.intern(text, *kind));
        }
        name
    }

    /// A Java-like adapter with the three hooks the relational reader
    /// consults: a normalization that spells `$`-nested types as ordinary
    /// types, a package anchor that mounts every file under `anchored/` at its
    /// own package, and path-derived module units for the files it lists.
    struct FixtureAdapter {
        path_units: Vec<CodeUnit>,
    }

    impl StoreLanguageAdapter for FixtureAdapter {
        fn language(&self) -> Language {
            Language::Java
        }

        fn normalize_fq_name(&self, name: &FqName) -> FqName {
            let interner = segment_interner();
            let mut normalized = FqName::new();
            for (text, kind) in name.resolved_segments() {
                let kind = if kind == N { T } else { kind };
                normalized.push(interner.intern(text, kind));
            }
            normalized
        }

        fn default_package_anchor(&self) -> Option<PackageAnchor> {
            Some(PackageAnchor::OwnModule { pop: 0 })
        }

        fn resolve_package_anchor(
            &self,
            _anchor: PackageAnchor,
            content_qualifier: &str,
            file: &ProjectFile,
        ) -> Option<FqName> {
            file.rel_path()
                .starts_with("anchored")
                .then(|| fq(&[(content_qualifier, P)]))
        }

        fn path_synthetic_module_unit(&self, file: &ProjectFile) -> Option<CodeUnit> {
            self.path_units
                .iter()
                .find(|unit| unit.source() == file)
                .cloned()
        }

        fn has_path_synthetic_module_units(&self) -> bool {
            true
        }
    }

    /// One stored declaration row and the start bytes of its ranges.
    struct Row {
        unit: CodeUnit,
        starts: Vec<usize>,
    }

    struct Blob {
        lang: &'static str,
        rel_path: &'static str,
        oid: Oid,
        rows: Vec<Row>,
        /// Whether the workspace snapshot lists this blob's file.
        in_workspace: bool,
        /// Whether the blob was ever parsed into the store.
        parsed: bool,
    }

    struct Units {
        widget: CodeUnit,
        run_a: CodeUnit,
        inner: CodeUnit,
        size: CodeUnit,
        run_b: CodeUnit,
        mounted: CodeUnit,
        go: CodeUnit,
        alpha: CodeUnit,
        pads: Vec<CodeUnit>,
    }

    struct Fixture {
        store: AnalyzerStore,
        adapter: FixtureAdapter,
        root: PathBuf,
        snapshots: WorkspaceSnapshots,
        generations: HashMap<String, GenerationId>,
        languages: Vec<String>,
        units: Units,
        blobs: Vec<Blob>,
    }

    fn root() -> PathBuf {
        std::env::temp_dir().join("bifrost-relational-batch-fixture")
    }

    fn unit(
        rel_path: &str,
        kind: CodeUnitType,
        parts: &[(&str, SegmentKind)],
        package_segments: usize,
    ) -> CodeUnit {
        CodeUnit::from_fq(
            ProjectFile::new(root(), rel_path),
            kind,
            fq(parts),
            package_segments,
            None,
            false,
        )
    }

    fn row(unit: &CodeUnit, starts: &[usize]) -> Row {
        Row {
            unit: unit.clone(),
            starts: starts.to_vec(),
        }
    }

    fn insert_blob(conn: &rusqlite::Connection, adapter: &FixtureAdapter, blob: &Blob) {
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, ?2, 0)",
            params![blob.oid.to_string(), blob.lang],
        )
        .unwrap();
        let blob_id = conn.last_insert_rowid();
        let range_count = blob.rows.iter().map(|row| row.starts.len()).sum::<usize>();
        conn.execute(
            "INSERT INTO blob_meta(
               blob_id, lang, contains_tests, content_package, stored_unit_count,
               range_count, signature_count, signature_metadata_count, supertype_count,
               child_count, import_statement_count, type_identifier_count, is_complete
             ) VALUES(?1, ?2, 0, '', ?3, ?4, 0, 0, 0, 0, 0, 0, 1)",
            params![blob_id, blob.lang, blob.rows.len(), range_count],
        )
        .unwrap();
        for (unit_key, row) in blob.rows.iter().enumerate() {
            let unit = &row.unit;
            let qualifier = adapter.storage_content_qualifier(unit, "");
            let prepared = prepare_unit_fq(adapter, unit, &qualifier)
                .unwrap()
                .expect("fixture units have a structured name");
            let segment_bytes = prepared
                .segments
                .iter()
                .map(|(_, kind, text)| kind.len() + text.len())
                .sum::<usize>();
            conn.execute(
                "INSERT INTO code_units(
                   blob_id, lang, unit_key, kind, short_name, identifier, content_qualifier,
                   simple_type_name, signature, synthetic, is_type_alias, top_level_ordinal,
                   in_declarations, in_definition_lookup, fq_anchor_kind, fq_anchor_pop,
                   fq_package_tail_segments, exact_fqn_tail, normalized_fqn_tail,
                   exact_parent_fqn_tail, normalized_parent_fqn_tail, package_fqn_tail,
                   fq_segment_count, fq_segment_bytes
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, 0, 0, NULL, 1, 1, ?9, ?10,
                          ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
                params![
                    blob_id,
                    blob.lang,
                    unit_key,
                    code_unit_kind_to_i64(unit.kind()),
                    unit.short_name(),
                    unit.identifier(),
                    qualifier,
                    unit.is_class().then(|| adapter.simple_type_name(unit)),
                    prepared.anchor_kind,
                    prepared.anchor_pop,
                    prepared.package_tail_segments,
                    prepared.exact_tail,
                    prepared.normalized_tail,
                    prepared.exact_parent_tail,
                    prepared.normalized_parent_tail,
                    prepared.package_tail,
                    prepared.segments.len(),
                    segment_bytes,
                ],
            )
            .unwrap();
            for (ordinal, kind, text) in &prepared.segments {
                conn.execute(
                    "INSERT INTO code_unit_fq_segments(
                       blob_id, lang, unit_key, seg_ordinal, seg_kind, segment
                     ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
                    params![blob_id, blob.lang, unit_key, ordinal, kind, text],
                )
                .unwrap();
            }
            for (ordinal, start) in row.starts.iter().enumerate() {
                conn.execute(
                    "INSERT INTO unit_ranges(
                       blob_id, lang, unit_key, ordinal, start_byte, end_byte, start_line,
                       end_line
                     ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, 0, 0)",
                    params![blob_id, blob.lang, unit_key, ordinal, start, start + 1],
                )
                .unwrap();
            }
        }
    }

    /// The fixture, by file:
    ///
    /// - `src/demo/Widget.java`: `demo.Widget`, `demo.Widget.run` stored twice
    ///   (two rows, one declaration, ranges at 40 and 12), `demo.Widget$Inner`
    ///   and `demo.Widget.size` (no ranges).
    /// - `src/demo/Other.java`: a second `demo.Widget.run`.
    /// - `anchored/Mounted.java`: `mnt.Mounted` and `mnt.Mounted.go`, stored
    ///   as tails under the workspace anchor `mnt`.
    /// - `pad/Pad.java`: `pad.Pad0` .. `pad.Pad69`, so a batch can be smaller
    ///   or larger than the live unit count.
    /// - `paths/alpha.java`: no rows, one path-derived module `paths.alpha`.
    /// - `src/demo/util/Helper.java`: no rows, package `demo.util`.
    /// - `src/gone/Gone.java`: listed in the workspace, never parsed.
    /// - a parsed blob holding `demo.Widget.run` that no workspace file lists.
    /// - a Kotlin blob holding `demo.Widget.run`, live for Kotlin only.
    fn fixture() -> Fixture {
        let root = root();
        let widget_path = "src/demo/Widget.java";
        let units = Units {
            widget: unit(
                widget_path,
                CodeUnitType::Class,
                &[("demo", P), ("Widget", T)],
                1,
            ),
            run_a: unit(
                widget_path,
                CodeUnitType::Function,
                &[("demo", P), ("Widget", T), ("run", M)],
                1,
            ),
            inner: unit(
                widget_path,
                CodeUnitType::Class,
                &[("demo", P), ("Widget", T), ("Inner", N)],
                1,
            ),
            size: unit(
                widget_path,
                CodeUnitType::Field,
                &[("demo", P), ("Widget", T), ("size", M)],
                1,
            ),
            run_b: unit(
                "src/demo/Other.java",
                CodeUnitType::Function,
                &[("demo", P), ("Widget", T), ("run", M)],
                1,
            ),
            mounted: unit(
                "anchored/Mounted.java",
                CodeUnitType::Class,
                &[("mnt", P), ("Mounted", T)],
                1,
            ),
            go: unit(
                "anchored/Mounted.java",
                CodeUnitType::Function,
                &[("mnt", P), ("Mounted", T), ("go", M)],
                1,
            ),
            alpha: CodeUnit::from_fq(
                ProjectFile::new(root.clone(), "paths/alpha.java"),
                CodeUnitType::Module,
                fq(&[("paths", P), ("alpha", P)]),
                1,
                None,
                true,
            ),
            pads: (0..PADDING_UNITS)
                .map(|index| {
                    let name = format!("Pad{index}");
                    unit(
                        "pad/Pad.java",
                        CodeUnitType::Class,
                        &[("pad", P), (name.as_str(), T)],
                        1,
                    )
                })
                .collect(),
        };
        let blob = |lang, rel_path, rows, in_workspace, parsed| Blob {
            lang,
            rel_path,
            oid: test_blob_oid(format!("{lang}:{rel_path}:{in_workspace}")),
            rows,
            in_workspace,
            parsed,
        };
        let stale_run = unit(
            "src/demo/Stale.java",
            CodeUnitType::Function,
            &[("demo", P), ("Widget", T), ("run", M)],
            1,
        );
        let kotlin_run = unit(
            "src/demo/Widget.kt",
            CodeUnitType::Function,
            &[("demo", P), ("Widget", T), ("run", M)],
            1,
        );
        let blobs = vec![
            blob(
                "java",
                widget_path,
                vec![
                    row(&units.widget, &[0]),
                    row(&units.run_a, &[40]),
                    row(&units.run_a, &[12]),
                    row(&units.inner, &[20]),
                    row(&units.size, &[]),
                ],
                true,
                true,
            ),
            blob(
                "java",
                "src/demo/Other.java",
                vec![row(&units.run_b, &[7])],
                true,
                true,
            ),
            blob(
                "java",
                "anchored/Mounted.java",
                vec![row(&units.mounted, &[1]), row(&units.go, &[3])],
                true,
                true,
            ),
            blob(
                "java",
                "pad/Pad.java",
                units.pads.iter().map(|pad| row(pad, &[])).collect(),
                true,
                true,
            ),
            blob("java", "paths/alpha.java", Vec::new(), true, true),
            blob("java", "src/demo/util/Helper.java", Vec::new(), true, true),
            blob("java", "src/gone/Gone.java", Vec::new(), true, false),
            blob(
                "java",
                "src/demo/Stale.java",
                vec![row(&stale_run, &[0])],
                false,
                true,
            ),
            blob(
                "kotlin",
                "src/demo/Widget.kt",
                vec![row(&kotlin_run, &[0])],
                true,
                true,
            ),
        ];
        let adapter = FixtureAdapter {
            path_units: vec![units.alpha.clone()],
        };
        let store = AnalyzerStore::open_ephemeral().unwrap();
        {
            let conn = store.conn.lock().unwrap();
            for blob in blobs.iter().filter(|blob| blob.parsed) {
                insert_blob(&conn, &adapter, blob);
            }
        }
        let oid_of = |rel_path: &str| {
            blobs
                .iter()
                .find(|blob| blob.rel_path == rel_path)
                .unwrap()
                .oid
        };
        let mut snapshots = WorkspaceSnapshots::default();
        for lang in ["java", "kotlin"] {
            let files = blobs
                .iter()
                .filter(|blob| blob.lang == lang && blob.in_workspace)
                .map(|blob| WorkspaceFileRow {
                    rel_path: blob.rel_path.to_string(),
                    blob_oid: blob.oid,
                })
                .collect::<Vec<_>>();
            let java = lang == "java";
            let path_symbols = java
                .then(|| PathSymbolRow {
                    rel_path: "paths/alpha.java".to_string(),
                    blob_oid: oid_of("paths/alpha.java"),
                    kind: CodeUnitType::Module,
                    package_name: "paths".to_string(),
                    short_name: "alpha".to_string(),
                    exact_fqn: "paths.alpha".to_string(),
                    normalized_fqn: "paths.alpha".to_string(),
                    requires_imports: false,
                })
                .into_iter()
                .collect::<Vec<_>>();
            let member = |package_name: &str, rel_path: &str| WorkspacePackageFileRow {
                package_name: package_name.to_string(),
                rel_path: rel_path.to_string(),
            };
            let package_files = if java {
                vec![
                    member("demo", widget_path),
                    member("demo", "src/demo/Other.java"),
                    member("mnt", "anchored/Mounted.java"),
                    member("pad", "pad/Pad.java"),
                    member("paths", "paths/alpha.java"),
                    member("demo.util", "src/demo/util/Helper.java"),
                    member("gone", "src/gone/Gone.java"),
                ]
            } else {
                vec![member("demo", "src/demo/Widget.kt")]
            };
            let package_edges = if java {
                vec![
                    WorkspacePackageEdgeRow {
                        rel_path: widget_path.to_string(),
                        parent_package_name: String::new(),
                        child_package_name: "demo".to_string(),
                    },
                    WorkspacePackageEdgeRow {
                        rel_path: "src/demo/util/Helper.java".to_string(),
                        parent_package_name: "demo".to_string(),
                        child_package_name: "demo.util".to_string(),
                    },
                ]
            } else {
                Vec::new()
            };
            let anchors = java
                .then(|| WorkspaceAnchorRow {
                    rel_path: "anchored/Mounted.java".to_string(),
                    anchor: PackageAnchor::OwnModule { pop: 0 },
                    package_name: "mnt".to_string(),
                })
                .into_iter()
                .collect::<Vec<_>>();
            let snapshot = store
                .sync_workspace_snapshot(
                    lang,
                    GenerationId::BOOTSTRAP,
                    &files,
                    &path_symbols,
                    &[],
                    &package_files,
                    &package_edges,
                    &anchors,
                )
                .unwrap();
            snapshots.insert(lang.to_string(), snapshot);
        }
        Fixture {
            store,
            adapter,
            root,
            snapshots,
            generations: HashMap::from_iter([
                ("java".to_string(), GenerationId::BOOTSTRAP),
                ("kotlin".to_string(), GenerationId::BOOTSTRAP),
            ]),
            languages: vec!["java".to_string()],
            units,
            blobs,
        }
    }

    impl Fixture {
        fn values(
            &self,
            requests: &[RelationalDefinitionRequest],
        ) -> Vec<RelationalDefinitionValue> {
            let outcome = self
                .store
                .relational_definition_values(
                    &self.adapter,
                    &self.root,
                    &self.generations,
                    &self.languages,
                    &self.snapshots,
                    requests,
                    &CancellationToken::new(),
                    |_| {},
                )
                .unwrap();
            match outcome {
                RelationalStoreOutcome::Complete(values) => values,
                RelationalStoreOutcome::Cancelled => panic!("an uncancelled batch completes"),
            }
        }

        /// Run `cases` as one batch, then each case alone, and compare both
        /// with the hand-written expectation.
        fn assert_batch(
            &self,
            label: &str,
            cases: &[(RelationalName, RelationalDefinitionQuery, Vec<CodeUnit>)],
        ) {
            let requests = cases
                .iter()
                .enumerate()
                .map(|(ordinal, (name, query, _))| request(ordinal, name, query))
                .collect::<Vec<_>>();
            let batched = self.values(&requests);
            assert_eq!(batched.len(), cases.len(), "{label}");
            for ((name, query, expected), value) in cases.iter().zip(batched) {
                let mut expected = expected.clone();
                sort_units(&mut expected);
                assert_eq!(
                    value,
                    RelationalDefinitionValue::Definitions(expected),
                    "{label}: batched {query:?} for {name:?}"
                );
                let alone = self.values(&[request(0, name, query)]);
                assert_eq!(
                    alone,
                    vec![value],
                    "{label}: point and batched answers differ for {query:?} on {name:?}"
                );
            }
        }
    }

    fn request(
        ordinal: usize,
        name: &RelationalName,
        query: &RelationalDefinitionQuery,
    ) -> RelationalDefinitionRequest {
        RelationalDefinitionRequest {
            ordinal,
            language_scope: DefinitionLanguageScope::Language(Language::Java),
            name: name.clone(),
            query: query.clone(),
        }
    }

    fn stable(parts: &[(&str, SegmentKind)]) -> RelationalName {
        RelationalName::stable(fq(parts))
    }

    fn mounted(prefix: &str, tail: &[(&str, SegmentKind)]) -> RelationalName {
        RelationalName::new(fq(&[(prefix, P)]), fq(tail))
    }

    /// Requests about the interesting rows, padded with one hit per padding
    /// class until the batch is `size` long.
    fn padded<F>(
        mut cases: Vec<(RelationalName, RelationalDefinitionQuery, Vec<CodeUnit>)>,
        pads: &[CodeUnit],
        size: usize,
        pad_case: F,
    ) -> Vec<(RelationalName, RelationalDefinitionQuery, Vec<CodeUnit>)>
    where
        F: Fn(usize, &CodeUnit) -> (RelationalName, RelationalDefinitionQuery, Vec<CodeUnit>),
    {
        let mut index = 0;
        while cases.len() < size {
            cases.push(pad_case(index, &pads[index % pads.len()]));
            index += 1;
        }
        cases
    }

    fn live_java_rows(fixture: &Fixture) -> usize {
        fixture
            .blobs
            .iter()
            .filter(|blob| blob.lang == "java" && blob.in_workspace && blob.parsed)
            .map(|blob| blob.rows.len())
            .sum()
    }

    /// Runs `cases` padded to one batch no larger than the live Java row count
    /// (the request-driven seek), and then to one larger than it (the
    /// names-driven scan), where every case appears at least twice.
    fn assert_seek_and_scan(
        fixture: &Fixture,
        label: &str,
        cases: Vec<(RelationalName, RelationalDefinitionQuery, Vec<CodeUnit>)>,
        pad_case: impl Fn(
            usize,
            &CodeUnit,
        ) -> (RelationalName, RelationalDefinitionQuery, Vec<CodeUnit>),
    ) {
        let live_rows = live_java_rows(fixture);
        assert!(SET_QUERY_MIN_REQUESTS <= live_rows);
        let seek = padded(
            cases,
            &fixture.units.pads,
            SET_QUERY_MIN_REQUESTS + 8,
            &pad_case,
        );
        assert!(seek.len() <= live_rows);
        fixture.assert_batch(&format!("{label} seek"), &seek);
        let scan = seek.iter().chain(&seek).cloned().collect::<Vec<_>>();
        assert!(scan.len() > live_rows);
        fixture.assert_batch(&format!("{label} scan"), &scan);
    }

    #[test]
    fn batched_exact_names_match_point_lookups_and_the_fixture() {
        let fixture = fixture();
        let u = &fixture.units;
        let exact = RelationalDefinitionQuery::ExactName;
        let cases = vec![
            (
                stable(&[("demo", P), ("Widget", T), ("run", M)]),
                exact.clone(),
                vec![u.run_a.clone(), u.run_b.clone()],
            ),
            (
                stable(&[("demo", P), ("Widget", T)]),
                exact.clone(),
                vec![u.widget.clone()],
            ),
            // A user-typed name carries no kind claims; it matches by spelling.
            (
                stable(&[("demo", P), ("Widget", U), ("run", M)]),
                exact.clone(),
                vec![u.run_a.clone(), u.run_b.clone()],
            ),
            (
                stable(&[("demo", P), ("Widget", T), ("Inner", N)]),
                exact.clone(),
                vec![u.inner.clone()],
            ),
            // Same parent and identifier columns as `Widget$Inner`, but a
            // different structured name and a different spelling.
            (
                stable(&[("demo", P), ("Widget", T), ("Inner", T)]),
                exact.clone(),
                Vec::new(),
            ),
            (
                stable(&[("demo", U), ("Widget", U), ("Inner", U)]),
                exact.clone(),
                Vec::new(),
            ),
            (
                mounted("mnt", &[("Mounted", T), ("go", M)]),
                exact.clone(),
                vec![u.go.clone()],
            ),
            // The anchored rows answer only under their mounted prefix.
            (
                stable(&[("mnt", P), ("Mounted", T), ("go", M)]),
                exact.clone(),
                Vec::new(),
            ),
            (
                stable(&[("paths", P), ("alpha", P)]),
                exact.clone(),
                vec![u.alpha.clone()],
            ),
            (
                stable(&[("demo", P), ("Widget", T), ("size", M)]),
                exact.clone(),
                vec![u.size.clone()],
            ),
            (
                stable(&[("gone", P), ("Gone", T)]),
                exact.clone(),
                Vec::new(),
            ),
        ];
        assert_seek_and_scan(&fixture, "exact", cases, |_, pad| {
            (
                RelationalName::stable(pad.fq().clone()),
                RelationalDefinitionQuery::ExactName,
                vec![pad.clone()],
            )
        });
    }

    #[test]
    fn batched_normalized_names_match_point_lookups_and_the_fixture() {
        let fixture = fixture();
        let u = &fixture.units;
        let normalized = RelationalDefinitionQuery::NormalizedName;
        let cases = vec![
            // `Widget$Inner` normalizes to `Widget.Inner`.
            (
                stable(&[("demo", P), ("Widget", T), ("Inner", T)]),
                normalized.clone(),
                vec![u.inner.clone()],
            ),
            (
                stable(&[("demo", U), ("Widget", U), ("Inner", U)]),
                normalized.clone(),
                vec![u.inner.clone()],
            ),
            (
                stable(&[("demo", P), ("Widget", T), ("Inner", N)]),
                normalized.clone(),
                Vec::new(),
            ),
            // Names the normalization leaves unchanged.
            (
                stable(&[("demo", P), ("Widget", T), ("run", M)]),
                normalized.clone(),
                vec![u.run_a.clone(), u.run_b.clone()],
            ),
            (
                mounted("mnt", &[("Mounted", T), ("go", M)]),
                normalized.clone(),
                vec![u.go.clone()],
            ),
            (
                stable(&[("paths", P), ("alpha", P)]),
                normalized.clone(),
                vec![u.alpha.clone()],
            ),
            (
                stable(&[("gone", P), ("Gone", T)]),
                normalized.clone(),
                Vec::new(),
            ),
        ];
        assert_seek_and_scan(&fixture, "normalized", cases, |_, pad| {
            (
                RelationalName::stable(pad.fq().clone()),
                RelationalDefinitionQuery::NormalizedName,
                vec![pad.clone()],
            )
        });
    }

    #[test]
    fn batched_structural_members_match_point_lookups_and_the_fixture() {
        let fixture = fixture();
        let u = &fixture.units;
        let member = |identifier: &str| RelationalDefinitionQuery::StructuralMembers {
            identifier: identifier.to_string(),
        };
        let widget = stable(&[("demo", P), ("Widget", T)]);
        let cases = vec![
            (
                widget.clone(),
                member("run"),
                vec![u.run_a.clone(), u.run_b.clone()],
            ),
            (widget.clone(), member("Inner"), vec![u.inner.clone()]),
            (widget.clone(), member("missing"), Vec::new()),
            (
                mounted("mnt", &[("Mounted", T)]),
                member("go"),
                vec![u.go.clone()],
            ),
            (
                stable(&[("paths", P)]),
                member("alpha"),
                vec![u.alpha.clone()],
            ),
            (stable(&[("paths", P)]), member("beta"), Vec::new()),
        ];
        assert_seek_and_scan(&fixture, "structural members", cases, |_, pad| {
            (
                stable(&[("pad", P)]),
                RelationalDefinitionQuery::StructuralMembers {
                    identifier: pad.identifier().to_string(),
                },
                vec![pad.clone()],
            )
        });
    }

    #[test]
    fn exact_definition_order_rows_report_each_declarations_first_range() {
        let fixture = fixture();
        let u = &fixture.units;
        let cases = vec![
            (
                stable(&[("demo", P), ("Widget", T), ("run", M)]),
                vec![(u.run_a.clone(), Some(12)), (u.run_b.clone(), Some(7))],
            ),
            (
                stable(&[("demo", P), ("Widget", U), ("run", M)]),
                vec![(u.run_a.clone(), Some(12)), (u.run_b.clone(), Some(7))],
            ),
            (
                stable(&[("demo", P), ("Widget", T)]),
                vec![(u.widget.clone(), Some(0))],
            ),
            (
                stable(&[("demo", P), ("Widget", T), ("Inner", N)]),
                vec![(u.inner.clone(), Some(20))],
            ),
            (
                stable(&[("demo", P), ("Widget", T), ("Inner", T)]),
                Vec::new(),
            ),
            (
                mounted("mnt", &[("Mounted", T), ("go", M)]),
                vec![(u.go.clone(), Some(3))],
            ),
            (
                stable(&[("demo", P), ("Widget", T), ("size", M)]),
                vec![(u.size.clone(), None)],
            ),
            (
                RelationalName::stable(u.pads[5].fq().clone()),
                vec![(u.pads[5].clone(), None)],
            ),
            (stable(&[("gone", P), ("Gone", T)]), Vec::new()),
            // A repeated name gets its own complete answer.
            (
                stable(&[("demo", P), ("Widget", T), ("run", M)]),
                vec![(u.run_a.clone(), Some(12)), (u.run_b.clone(), Some(7))],
            ),
        ];
        let order_rows = |names: &[RelationalName]| {
            fixture
                .store
                .relational_exact_definition_order_rows(
                    &fixture.adapter,
                    &fixture.root,
                    &fixture.generations,
                    &fixture.languages,
                    &fixture.snapshots,
                    names,
                    &CancellationToken::new(),
                )
                .unwrap()
                .expect("an uncancelled batch completes")
        };
        assert!(order_rows(&[]).is_empty());
        let names = cases
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        let rows = order_rows(&names);
        assert_eq!(rows.len(), cases.len());
        for ((name, expected), rows) in cases.iter().zip(rows) {
            let mut actual = rows
                .into_iter()
                .map(|row| (row.unit, row.first_start_byte))
                .collect::<Vec<_>>();
            actual.sort_by(|left, right| left.0.cmp(&right.0));
            let mut expected = expected.clone();
            expected.sort_by(|left, right| left.0.cmp(&right.0));
            assert_eq!(actual, expected, "definition order rows for {name:?}");
        }
    }

    #[test]
    fn live_unit_counts_sum_rows_of_live_workspace_files_per_language() {
        let fixture = fixture();
        let languages = ["java", "kotlin", "python"].map(str::to_string);
        let mut conn = fixture
            .store
            .read_conn_for_workspace(&fixture.snapshots)
            .unwrap();
        let tx = conn.transaction().unwrap();
        let counts = live_unit_counts(&tx, &languages).unwrap();
        // Java: 5 + 1 + 2 + 70 rows in listed, parsed files; the unlisted
        // stale blob's row does not count. Kotlin: its one row. Python has no
        // selected snapshot at all.
        assert_eq!(
            counts,
            HashMap::from_iter([
                ("java".to_string(), 5 + 1 + 2 + PADDING_UNITS),
                ("kotlin".to_string(), 1),
                ("python".to_string(), 0),
            ])
        );
    }

    #[test]
    fn package_relations_distinguish_member_packages_from_ancestors() {
        let fixture = fixture();
        let package = |parts: &[&str]| {
            RelationalName::stable(fq(&parts.iter().map(|part| (*part, P)).collect::<Vec<_>>()))
        };
        let file = |rel_path: &str| ProjectFile::new(fixture.root.clone(), rel_path);
        let relation = RelationalDefinitionQuery::PackageRelation;
        let cases = vec![
            (
                package(&["demo"]),
                PackageRelationKind::Files,
                PackageRelationValue::Files(vec![
                    file("src/demo/Other.java"),
                    file("src/demo/Widget.java"),
                ]),
            ),
            (
                package(&["gone"]),
                PackageRelationKind::Files,
                PackageRelationValue::Files(Vec::new()),
            ),
            (
                package(&[]),
                PackageRelationKind::Children,
                PackageRelationValue::Packages(vec!["demo".to_string()]),
            ),
            (
                package(&[]),
                PackageRelationKind::Descendants,
                PackageRelationValue::Packages(vec!["demo".to_string(), "demo.util".to_string()]),
            ),
            (
                package(&["demo"]),
                PackageRelationKind::Children,
                PackageRelationValue::Packages(vec!["demo.util".to_string()]),
            ),
            (
                package(&["demo", "util"]),
                PackageRelationKind::Descendants,
                PackageRelationValue::Packages(Vec::new()),
            ),
            (
                package(&["demo"]),
                PackageRelationKind::Exists,
                PackageRelationValue::Exists(true),
            ),
            (
                package(&["demo", "util"]),
                PackageRelationKind::Exists,
                PackageRelationValue::Exists(true),
            ),
            // The root package only has children, and `gone` only has a file
            // that was never parsed: neither has a live member file.
            (
                package(&[]),
                PackageRelationKind::Exists,
                PackageRelationValue::Exists(false),
            ),
            (
                package(&["gone"]),
                PackageRelationKind::Exists,
                PackageRelationValue::Exists(false),
            ),
        ];
        let requests = cases
            .iter()
            .enumerate()
            .map(|(ordinal, (name, kind, _))| request(ordinal, name, &relation(*kind)))
            .collect::<Vec<_>>();
        let values = fixture.values(&requests);
        for ((name, kind, expected), value) in cases.iter().zip(values) {
            assert_eq!(
                value,
                RelationalDefinitionValue::PackageRelation(expected.clone()),
                "{kind:?} of {name:?}"
            );
            if let PackageRelationValue::Exists(expected) = expected {
                let rendered = name
                    .full_name()
                    .display_native(Language::Java, segment_interner());
                let direct = fixture
                    .store
                    .workspace_package_exists_for_langs(
                        &fixture.languages,
                        &fixture.generations,
                        &fixture.snapshots,
                        &rendered,
                    )
                    .unwrap();
                assert_eq!(direct, *expected, "direct existence of {rendered:?}");
            }
        }
    }
}

/// `decorated_identifier_prefix_successor` turns a decorated identifier prefix
/// (a terminal backtick, as in C# generic arity) into the exclusive upper bound
/// of a SQLite range. The range
/// `[prefix, successor)` under SQLite's BINARY collation must hold exactly the
/// identifiers that start with the prefix.
#[cfg(test)]
mod identifier_prefix_properties {
    use proptest::prelude::*;

    use super::decorated_identifier_prefix_successor;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]
        #[test]
        fn successor_bounds_exactly_the_identifiers_that_extend_the_prefix(
            stem in "[`a_b\u{e9}]{0,4}",
            kept in 0usize..7,
            tail in "[`a_b\u{e9}]{0,4}",
        ) {
            let prefix = format!("{stem}`");
            let upper = decorated_identifier_prefix_successor(&prefix);
            let candidate = prefix.chars().take(kept).chain(tail.chars()).collect::<String>();
            let conn = rusqlite::Connection::open_in_memory().unwrap();
            let in_range = conn
                .query_row(
                    "SELECT ?1 >= ?2 AND ?1 < ?3",
                    rusqlite::params![candidate, prefix, upper],
                    |row| row.get::<_, bool>(0),
                )
                .unwrap();
            prop_assert_eq!(
                in_range,
                candidate.starts_with(&prefix),
                "candidate {:?} against [{:?}, {:?})",
                candidate,
                prefix,
                upper
            );
        }
    }
}
