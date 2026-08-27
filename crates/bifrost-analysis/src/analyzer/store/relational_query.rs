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
    candidate_row_from_row, candidate_row_from_row_at, hydrate_candidate_rows, hydrate_unit_fq,
    require_generation_map, signature_metadata_from_row,
};
use crate::analyzer::tree_sitter_analyzer::LanguageAdapter;
use crate::analyzer::{CodeUnit, ProjectFile, sort_units};
use crate::hash::HashMap;

const CANDIDATE_COLUMNS: &str =
    "units.blob_oid, units.lang, units.unit_key, units.kind, units.short_name,
     units.content_qualifier, units.signature, units.synthetic, units.is_type_alias,
     units.top_level_ordinal, units.in_declarations, units.in_definition_lookup,
     units.fq_anchor_kind, units.fq_anchor_pop, units.fq_package_tail_segments,
     units.fq_segment_count, units.exact_fqn_tail, units.fq_segment_bytes,
     units.normalized_fqn_tail";

const SET_QUERY_MIN_REQUESTS: usize = 64;

fn content_sql(view: &str, predicate: &str) -> String {
    format!(
        "SELECT {CANDIDATE_COLUMNS}, names.rel_path
         FROM {view} AS names
         JOIN code_units AS units
           ON units.blob_oid = names.blob_oid
          AND units.lang = names.lang
          AND units.unit_key = names.unit_key
         WHERE names.lang = ?1 AND names.source_kind <> 'path' AND {predicate}
         ORDER BY names.rel_path, units.blob_oid, units.unit_key"
    )
}

fn render_name<A: LanguageAdapter>(adapter: &A, name: &RelationalName) -> (String, String, String) {
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

fn unit_matches_requested_name<A: LanguageAdapter>(
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
        actual.display_native(
            adapter.language(),
            crate::analyzer::fq_name::segment_interner(),
        ) == requested.display_native(
            adapter.language(),
            crate::analyzer::fq_name::segment_interner(),
        )
    } else {
        actual == *requested
    }
}

fn tail_parent_and_identifier<A: LanguageAdapter>(
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
    let mut statement = tx.prepare_cached(sql)?;
    let parameters = std::iter::once(&lang as &dyn rusqlite::ToSql).chain(values.iter().copied());
    let rows = statement.query_map(rusqlite::params_from_iter(parameters), |row| {
        Ok((candidate_row_from_row(row)?, row.get::<_, String>(19)?))
    })?;
    let rows = rows.collect::<std::result::Result<Vec<_>, _>>()?;
    drop(statement);
    Ok(hydrate_candidate_rows(tx, rows, None)?
        .expect("uncancelled relational candidate hydration completes"))
}

fn hydrate_candidates<A: LanguageAdapter>(
    adapter: &A,
    project_root: &Path,
    rows: Vec<(HydratedCandidateRow, String)>,
) -> Result<Vec<CodeUnit>> {
    let mut units = Vec::with_capacity(rows.len());
    for (row, rel_path) in rows {
        let file = ProjectFile::new(project_root.to_path_buf(), rel_path);
        let (fq, package_segment_count) =
            hydrate_unit_fq(adapter, row.fq.as_ref(), &row.content_qualifier, &file)?;
        units.push(CodeUnit::from_fq(
            file,
            row.kind,
            fq,
            package_segment_count,
            row.signature,
            row.flags.synthetic,
        ));
    }
    sort_units(&mut units);
    units.dedup();
    Ok(units)
}

fn batched_content_sql(
    view: &str,
    request_columns: &str,
    request_values: &str,
    join_predicate: &str,
) -> String {
    format!(
        "WITH requests(request_index, {request_columns}) AS MATERIALIZED (
             SELECT CAST(key AS INTEGER), {request_values}
             FROM json_each(?1)
         )
         SELECT requests.request_index, {CANDIDATE_COLUMNS}, names.rel_path
         FROM requests
         CROSS JOIN {view} AS names ON names.lang = ?2
          AND names.source_kind <> 'path'
          AND {join_predicate}
         JOIN code_units AS units
           ON units.blob_oid = names.blob_oid
          AND units.lang = names.lang
          AND units.unit_key = names.unit_key"
    )
}

fn scanned_content_sql(view: &str, request_values: &str, name_values: &str) -> String {
    format!(
        "WITH requests(request_index, lookup_key) AS MATERIALIZED (
             SELECT CAST(key AS INTEGER), json_array({request_values})
             FROM json_each(?1)
         )
         SELECT requests.request_index, {CANDIDATE_COLUMNS}, names.rel_path
         FROM {view} AS names
         CROSS JOIN requests ON requests.lookup_key = json_array({name_values})
         JOIN code_units AS units
           ON units.blob_oid = names.blob_oid
          AND units.lang = names.lang
          AND units.unit_key = names.unit_key
         WHERE names.lang = ?2 AND names.source_kind <> 'path'"
    )
}

fn batched_definition_order_sql(view: &str) -> String {
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
                 WHERE ranges.blob_oid = units.blob_oid
                   AND ranges.lang = units.lang
                   AND ranges.unit_key = units.unit_key) AS first_start_byte
         FROM requests
         CROSS JOIN {view} AS names ON names.lang = ?2
          AND names.source_kind <> 'path'
          AND names.prefix = requests.prefix
          AND names.exact_parent_tail = requests.parent_tail
          AND names.identifier = requests.identifier
         JOIN code_units AS units
           ON units.blob_oid = names.blob_oid
          AND units.lang = names.lang
          AND units.unit_key = names.unit_key"
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

pub(crate) struct DefinitionOrderRow {
    pub(crate) unit: CodeUnit,
    pub(crate) first_start_byte: Option<usize>,
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
                    (row.get::<_, usize>(0)?, row.get::<_, String>(20)?),
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
                        rel_path: row.get::<_, String>(20)?,
                        first_start_byte: row.get::<_, Option<usize>>(21)?,
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

fn live_unit_counts(
    tx: &Transaction<'_>,
    storage_languages: &[String],
) -> Result<HashMap<String, usize>> {
    let mut statement = tx.prepare_cached(
        "SELECT COALESCE(SUM(meta.stored_unit_count), 0)
         FROM live_workspace_files AS files
         JOIN blob_meta AS meta
           ON meta.blob_oid = files.blob_oid AND meta.lang = files.lang
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

fn set_queries_need_live_unit_counts<A: LanguageAdapter>(
    adapter: &A,
    requests: &[RelationalDefinitionRequest],
) -> bool {
    if adapter.has_path_synthetic_module_units() {
        return false;
    }

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

#[allow(clippy::too_many_arguments)]
fn set_exact_definition_values<A: LanguageAdapter>(
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
    if indices.len() < SET_QUERY_MIN_REQUESTS || adapter.has_path_synthetic_module_units() {
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
    for ((request_index, request), rows) in indices
        .into_iter()
        .map(|index| (index, &requests[index]))
        .zip(candidates)
    {
        let full_name = request.name.full_name();
        let mut units = hydrate_candidates(adapter, project_root, rows)?;
        units.retain(|unit| unit_matches_requested_name(adapter, unit, &full_name, false));
        sort_units(&mut units);
        units.dedup();
        values[request_index] = RelationalDefinitionValue::Definitions(units);
        handled[request_index] = true;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn set_normalized_definition_values<A: LanguageAdapter>(
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
    if indices.len() < SET_QUERY_MIN_REQUESTS || adapter.has_path_synthetic_module_units() {
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
    for ((request_index, request), rows) in indices
        .into_iter()
        .map(|index| (index, &requests[index]))
        .zip(candidates)
    {
        let full_name = request.name.full_name();
        let mut units = hydrate_candidates(adapter, project_root, rows)?;
        units.retain(|unit| unit_matches_requested_name(adapter, unit, &full_name, true));
        sort_units(&mut units);
        units.dedup();
        values[request_index] = RelationalDefinitionValue::Definitions(units);
        handled[request_index] = true;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn set_structural_member_values<A: LanguageAdapter>(
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
    if indices.len() < SET_QUERY_MIN_REQUESTS || adapter.has_path_synthetic_module_units() {
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
    for (request_index, rows) in indices.into_iter().zip(candidates) {
        values[request_index] = RelationalDefinitionValue::Definitions(hydrate_candidates(
            adapter,
            project_root,
            rows,
        )?);
        handled[request_index] = true;
    }
    Ok(())
}

fn path_units<A: LanguageAdapter>(
    tx: &Transaction<'_>,
    adapter: &A,
    project_root: &Path,
    view: &str,
    lang: &str,
    predicate: &str,
    values: &[&dyn rusqlite::ToSql],
) -> Result<Vec<CodeUnit>> {
    if !adapter.has_path_synthetic_module_units() {
        return Ok(Vec::new());
    }
    let sql = format!(
        "SELECT names.rel_path
         FROM {view} AS names
         WHERE names.lang = ?1 AND names.source_kind = 'path' AND {predicate}
         ORDER BY names.rel_path"
    );
    let mut statement = tx.prepare_cached(&sql)?;
    let parameters = std::iter::once(&lang as &dyn rusqlite::ToSql).chain(values.iter().copied());
    let paths = statement
        .query_map(rusqlite::params_from_iter(parameters), |row| {
            row.get::<_, String>(0)
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut units = paths
        .into_iter()
        .filter_map(|rel_path| {
            adapter
                .path_synthetic_module_unit(&ProjectFile::new(project_root.to_path_buf(), rel_path))
        })
        .collect::<Vec<_>>();
    sort_units(&mut units);
    units.dedup();
    Ok(units)
}

/// Content-derived candidates for one (view, predicate, values) point query,
/// hydrated into `CodeUnit`s. Shared by the split-view fast path and the
/// single wide-view fallback in [`definition_values`].
fn query_view_candidates<A: LanguageAdapter>(
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
        units.extend(hydrate_candidates(adapter, project_root, rows)?);
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
fn split_view_sources<A: LanguageAdapter>(
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
        _ => None,
    }
}

fn definition_values<A: LanguageAdapter>(
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
            // Path-derived rows are not covered by any split view (see
            // `split_view_sources`), so `path_units` still queries the
            // original wide view. It is a no-op unless the adapter opts
            // into path-synthetic module units.
            let values = owned_values
                .iter()
                .map(|value| value as &dyn rusqlite::ToSql)
                .collect::<Vec<_>>();
            for lang in storage_languages {
                units.extend(path_units(
                    tx,
                    adapter,
                    project_root,
                    view,
                    lang,
                    predicate,
                    &values,
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
            let values = owned_values
                .iter()
                .map(|value| value as &dyn rusqlite::ToSql)
                .collect::<Vec<_>>();
            for lang in storage_languages {
                units.extend(path_units(
                    tx,
                    adapter,
                    project_root,
                    view,
                    lang,
                    predicate,
                    &values,
                )?);
            }
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

fn package_relation_value<A: LanguageAdapter>(
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
        PackageRelationKind::Exists => {
            let mut exists = false;
            let mut statement = tx.prepare_cached(PACKAGE_EXISTS_SQL)?;
            for lang in storage_languages {
                exists |= statement
                    .query_row(params![lang, package], |_| Ok(()))
                    .optional()?
                    .is_some();
            }
            Ok(PackageRelationValue::Exists(exists))
        }
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

// `live_workspace_package_files` remains authoritative for liveness. Repeating
// its active-generation equality here gives SQLite all three leading columns
// of the membership primary key; without it, SQLite seeks only `lang` and
// walks every package membership for that language.
const PACKAGE_EXISTS_SQL: &str = "SELECT 1 FROM live_workspace_package_files
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
        signature_metadata_from_row(row, base).map(Some)
    }
}

fn callable_values<A: LanguageAdapter>(
    tx: &Transaction<'_>,
    adapter: &A,
    project_root: &Path,
    storage_languages: &[String],
    request: &RelationalDefinitionRequest,
) -> Result<Vec<RelationalCallableFact>> {
    let (prefix, _, _) = render_name(adapter, &request.name);
    let (parent, identifier) = tail_parent_and_identifier(adapter, &request.name);
    let candidate_sql = content_sql(
        "live_definition_exact_names",
        "names.prefix = ?2 AND names.exact_parent_tail = ?3 AND names.identifier = ?4",
    );
    let fact_sql = "SELECT facts.ordinal, facts.text,
                facts.label, facts.parameters, facts.return_type_text,
                facts.return_type_identity, facts.underlying_type_identity,
                facts.declaration_only, facts.callable_arity_required,
                facts.callable_arity_total, facts.callable_arity_repeated,
                facts.type_parameters, facts.bare_return_type_parameter,
                facts.callable_linkage, facts.dispatch_extensibility,
                facts.extension_receiver_type, facts.extension_receiver_type_identity,
                facts.extension_receiver_is_unconstrained, facts.field_is_static,
                facts.field_is_final, facts.field_has_initializer,
                facts.cpp_field_linkage, facts.companion_object,
                facts.callable_is_static, facts.callable_is_constructor,
                facts.callable_declared_visibility, facts.callable_modifiers_recorded,
                facts.callable_parameter_types, facts.callable_is_native,
                facts.class_like_is_interface, facts.class_like_is_static
         FROM live_callable_facts AS facts
         WHERE facts.blob_oid = ?1 AND facts.lang = ?2 AND facts.unit_key = ?3
         ORDER BY facts.ordinal";
    let mut facts = Vec::new();
    for lang in storage_languages {
        let candidates =
            query_content_candidates(tx, &candidate_sql, lang, &[&prefix, &parent, &identifier])?;
        for (candidate, rel_path) in candidates {
            let locator = (
                candidate.blob_oid.to_string(),
                candidate.lang.clone(),
                candidate.unit_key,
            );
            let mut units = hydrate_candidates(adapter, project_root, vec![(candidate, rel_path)])?;
            let declaration = units.pop().expect("a callable row has one declaration");
            if declaration.fq() != &request.name.full_name() {
                continue;
            }
            let mut statement = tx.prepare_cached(fact_sql)?;
            let rows = statement.query_map(params![locator.0, locator.1, locator.2], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    callable_metadata(row, 2)?,
                ))
            })?;
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

pub(crate) enum RelationalStoreOutcome {
    Complete(Vec<RelationalDefinitionValue>),
    Cancelled,
}

impl AnalyzerStore {
    /// Execute already-deduplicated relational requests through one reader and
    /// one SQLite snapshot. `None` means cancellation: no prefix of the batch
    /// is ever presented as a complete answer.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn relational_definition_values<A, F>(
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
        A: LanguageAdapter,
        F: FnOnce(&mut [RelationalDefinitionValue]),
    {
        if cancellation.is_cancelled() {
            return Ok(RelationalStoreOutcome::Cancelled);
        }
        #[cfg(test)]
        self.relational_batch_reader_checkouts
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut connection = self.read_conn_for_workspace(workspace_snapshots)?;
        let tx = connection.transaction()?;
        #[cfg(test)]
        self.relational_batch_generation_validations
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        #[cfg(test)]
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
        let live_unit_counts = if set_queries_need_live_unit_counts(adapter, requests) {
            #[cfg(test)]
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
    pub(crate) fn relational_exact_definition_order_rows<A: LanguageAdapter>(
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
                let mut hydrated =
                    hydrate_candidates(adapter, project_root, vec![(row.candidate, row.rel_path)])?;
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

    #[cfg(test)]
    pub(crate) fn relational_batch_counts_for_test(&self) -> (usize, usize, usize) {
        (
            self.relational_batch_reader_checkouts
                .load(std::sync::atomic::Ordering::Relaxed),
            self.relational_batch_generation_validations
                .load(std::sync::atomic::Ordering::Relaxed),
            self.relational_batch_distinct_requests
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    #[cfg(test)]
    pub(crate) fn relational_live_unit_count_queries_for_test(&self) -> usize {
        self.relational_live_unit_count_queries
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::params;

    use super::{
        AnalyzerStore, PACKAGE_EXISTS_SQL, batched_content_sql, batched_definition_order_sql,
        content_sql, render_name, scanned_content_sql, split_view_sources,
    };
    use crate::analyzer::Language;
    use crate::analyzer::ProjectFile;
    use crate::analyzer::fq_name::segment_interner;
    use crate::analyzer::java::JavaAdapter;
    use brokk_bifrost_core::analyzer::{
        DefinitionLanguageScope, RelationalDefinitionQuery, RelationalDefinitionRequest,
        RelationalName, symbol_path::parse_symbol_path_fq,
    };

    #[test]
    fn package_exists_query_seeks_exact_live_membership() {
        let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
        let connection = store.conn.lock().expect("store mutex");
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
            "exact package membership must seek its package-name index: {plan:#?}"
        );
        assert!(
            plan.iter()
                .any(|detail| { detail.contains("idx_workspace_file_versions_snapshot_blob") }),
            "exact package membership must seek revision membership: {plan:#?}"
        );
        assert!(
            plan.iter().all(|detail| !detail.contains("SCAN members")),
            "exact package membership must not scan workspace_package_files: {plan:#?}"
        );
    }

    /// Regression pin for issue #2588: `AnalyzerDefinitionLookup` (see
    /// `crates/bifrost-analysis/src/analyzer/analyzer_definition_lookup.rs`)
    /// issues small, per-owner/per-name `ExactName`, `NormalizedName`,
    /// `StructuralChildren`, and `StructuralMembers` requests -- almost
    /// always below `SET_QUERY_MIN_REQUESTS` -- so they are served by the
    /// point-query path in `definition_values` instead of the batched
    /// `set_*` functions above.
    ///
    /// Before the fix, that point-query path queried the wide `UNION ALL`
    /// compound views (`live_definition_exact_names`,
    /// `live_definition_normalized_names`, `live_structural_members`)
    /// directly. Their anchored arm cannot seek
    /// `idx_code_units_anchored_parent_identifier` by the request's
    /// parent/identifier, because that index's leading columns
    /// (`fq_anchor_kind`, `fq_anchor_pop`) are supplied by a correlated join
    /// to `workspace_file_anchors`, not a request literal; SQLite instead
    /// drove that arm from `workspace_file_anchors` filtered by language
    /// alone (`SEARCH anchors USING COVERING INDEX
    /// idx_workspace_file_anchors_lookup (lang=?)`), and unconditionally
    /// computed the path-derived arm's per-language `path_symbol_units` scan
    /// even though `content_sql`'s `source_kind <> 'path'` predicate
    /// discards 100% of its rows.
    ///
    /// This test calls the real `split_view_sources` (the function
    /// `definition_values` uses to decide what to query) with a real
    /// `JavaAdapter` and asserts both that it routes these four shapes
    /// through the lean, `INDEXED BY`-forced views from migration
    /// `0027-relational-definition-set-views.sql`, and that each resulting
    /// query seeks its intended partial index, drives from `units` rather
    /// than `workspace_file_anchors`, and never references
    /// `path_symbol_units`/`import_statements` at all (the split views omit
    /// the path arm by construction). If `split_view_sources` is changed to
    /// return `None` for any of these shapes -- reproducing the pre-fix
    /// behavior of falling back to the wide compound views -- the
    /// `.unwrap_or_else` below panics and this test fails.
    #[test]
    fn definition_point_queries_seek_split_view_indexes() {
        let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
        let connection = store.conn.lock().expect("store mutex");
        let explain = |sql: String, bindings: &[&str]| {
            let mut statement = connection
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .expect("prepare query plan");
            statement
                .query_map(rusqlite::params_from_iter(bindings), |row| {
                    row.get::<_, String>(3)
                })
                .expect("read query plan")
                .collect::<std::result::Result<Vec<_>, _>>()
                .expect("collect query plan")
        };
        let assert_seeks_units_index = |case_name: &str,
                                        view: &str,
                                        index: &str,
                                        plan: &[String]| {
            assert!(
                plan.iter().any(|detail| detail.contains(index)),
                "{case_name} ({view}) must seek {index}: {plan:#?}"
            );
            assert!(
                plan.iter()
                    .all(|detail| !detail.contains("SCAN units")
                        && !detail.contains("SCAN code_units")),
                "{case_name} ({view}) must not scan code_units: {plan:#?}"
            );
            // Revision membership must follow a selective name/anchor seek,
            // never drive the query. On Elasticsearch, allowing `workspace_file_versions`
            // to drive made every definition request walk all 15,711 Java
            // paths before probing the requested name. Stable names drive
            // directly from the partial unit-name index. Anchored names drive
            // from the requested package-name index, which supplies the
            // anchor kind/pop needed for the anchored unit index.
            let units_step = plan
                .iter()
                .position(|detail| detail.contains("units"))
                .expect("the requested units index appears in the plan");
            let anchored = view.contains("anchored");
            let anchor_driven = anchored && index != "idx_code_units_lang_identifier_lookup";
            let versions_step = plan
                .iter()
                .position(|detail| {
                    if anchor_driven {
                        detail.contains("SEARCH files USING INTEGER PRIMARY KEY")
                    } else {
                        detail.contains("idx_workspace_file_versions_snapshot_blob")
                    }
                })
                .unwrap_or_else(|| panic!("revision membership appears in the plan: {plan:#?}"));
            let driver_step = if anchor_driven {
                let anchor_step = plan
                    .iter()
                    .position(|detail| detail.contains("idx_workspace_file_anchor_rows_package"))
                    .expect("anchored lookup starts from the requested package");
                assert!(
                    anchor_step < units_step,
                    "{case_name} ({view}) must bind anchor kind/pop before seeking units: {plan:#?}"
                );
                anchor_step
            } else {
                units_step
            };
            assert!(
                driver_step < versions_step,
                "{case_name} ({view}) must narrow by name before revision membership: {plan:#?}"
            );
            if !anchor_driven {
                assert!(
                    plan.iter().any(|detail| {
                        detail.contains("idx_workspace_file_versions_snapshot_blob")
                    }),
                    "{case_name} ({view}) must seek revision membership by candidate blob: {plan:#?}"
                );
            }
            assert!(
                plan.iter().all(|detail| !detail.contains("SCAN anchors")
                    && !detail.contains("SCAN workspace_file_anchors")),
                "{case_name} ({view}) must not scan workspace_file_anchors: {plan:#?}"
            );
            assert!(
                plan.iter()
                    .all(|detail| !detail.contains("symbols") && !detail.contains("imports")),
                "{case_name} ({view}) must not touch path_symbol_units or import_statements: {plan:#?}"
            );
        };

        let adapter = JavaAdapter;
        let widget_name = RelationalName::stable(parse_symbol_path_fq(
            Language::Java,
            "demo.Widget",
            segment_interner(),
        ));
        let request_for = |query: RelationalDefinitionQuery| RelationalDefinitionRequest {
            ordinal: 0,
            language_scope: DefinitionLanguageScope::Language(Language::Java),
            name: widget_name.clone(),
            query,
        };

        let cases: [(&str, RelationalDefinitionQuery, &[&str]); 4] = [
            (
                "exact name",
                RelationalDefinitionQuery::ExactName,
                &[
                    "idx_code_units_stable_parent_identifier",
                    "idx_code_units_anchored_parent_identifier",
                ],
            ),
            (
                "structural children",
                RelationalDefinitionQuery::StructuralChildren,
                &[
                    "idx_code_units_stable_parent_identifier",
                    "idx_code_units_anchored_parent_identifier",
                ],
            ),
            (
                "structural members",
                RelationalDefinitionQuery::StructuralMembers {
                    identifier: "run".to_string(),
                },
                &[
                    "idx_code_units_stable_parent_identifier",
                    "idx_code_units_anchored_parent_identifier",
                ],
            ),
            (
                "identifier",
                RelationalDefinitionQuery::Identifier { file: None },
                &[
                    "idx_code_units_lang_identifier_lookup",
                    "idx_code_units_lang_identifier_lookup",
                ],
            ),
        ];

        for (case_name, query, expected_indexes) in cases {
            let request = request_for(query);
            let (prefix, tail, _) = render_name(&adapter, &request.name);
            let sources = split_view_sources(&adapter, &request, &prefix, &tail)
                .unwrap_or_else(|| panic!("{case_name} must route through split_view_sources"));
            assert_eq!(
                sources.len(),
                expected_indexes.len(),
                "{case_name} must query exactly the stable and anchored split views"
            );
            for ((view, predicate, values), index) in sources.iter().zip(expected_indexes) {
                let bindings: Vec<&str> = std::iter::once("java")
                    .chain(values.iter().map(String::as_str))
                    .collect();
                let plan = explain(content_sql(view, predicate), &bindings);
                assert_seeks_units_index(case_name, view, index, &plan);
            }
        }

        // NormalizedName additionally covers the "unchanged tail" case
        // (normalized_tail IS NULL, so the exact tail doubles as the
        // normalized one), which falls back to the parent-name views
        // instead of the normalized-name views. Four sources total.
        let normalized_request = request_for(RelationalDefinitionQuery::NormalizedName);
        let (prefix, tail, _) = render_name(&adapter, &normalized_request.name);
        let sources = split_view_sources(&adapter, &normalized_request, &prefix, &tail)
            .expect("normalized name must route through split_view_sources");
        let expected_indexes = [
            "idx_code_units_stable_normalized_tail",
            "idx_code_units_anchored_normalized_tail",
            "idx_code_units_stable_parent_identifier",
            "idx_code_units_anchored_parent_identifier",
        ];
        assert_eq!(
            sources.len(),
            expected_indexes.len(),
            "normalized name must query the changed-tail and unchanged-tail split views"
        );
        for ((view, predicate, values), index) in sources.iter().zip(expected_indexes) {
            let bindings: Vec<&str> = std::iter::once("java")
                .chain(values.iter().map(String::as_str))
                .collect();
            let plan = explain(content_sql(view, predicate), &bindings);
            assert_seeks_units_index("normalized name", view, index, &plan);
        }

        // `IdentifierPrefix`'s terminal segment must already be a decoration
        // range (see `decorated_identifier_prefix_successor`'s own
        // assertion): production only ever builds one from
        // `decorated_identifier_seeks`, which appends a trailing backtick
        // for C#'s CLR-arity spellings (for example ``Widget`1``). Use a
        // name shaped the same way rather than the plain `widget_name` above.
        let decorated_name = RelationalName::stable(parse_symbol_path_fq(
            Language::Java,
            "demo.Widget`",
            segment_interner(),
        ));
        let prefix_request = RelationalDefinitionRequest {
            ordinal: 0,
            language_scope: DefinitionLanguageScope::Language(Language::Java),
            name: decorated_name,
            query: RelationalDefinitionQuery::IdentifierPrefix { file: None },
        };
        let (decorated_prefix, decorated_tail, _) = render_name(&adapter, &prefix_request.name);
        let sources = split_view_sources(
            &adapter,
            &prefix_request,
            &decorated_prefix,
            &decorated_tail,
        )
        .expect("identifier prefix must route through split_view_sources");
        assert_eq!(
            sources.len(),
            2,
            "identifier prefix must query exactly the stable and anchored identifier views"
        );
        for (view, predicate, values) in &sources {
            let bindings: Vec<&str> = std::iter::once("java")
                .chain(values.iter().map(String::as_str))
                .collect();
            let plan = explain(content_sql(view, predicate), &bindings);
            assert_seeks_units_index(
                "identifier prefix",
                view,
                "idx_code_units_lang_identifier_lookup",
                &plan,
            );
        }

        // The file-scoped variants of both shapes (`file: Some(_)`) route
        // through the same two lean views with an added `rel_path`
        // predicate.
        let file = ProjectFile::new(
            std::path::PathBuf::from("/workspace"),
            "demo/Widget.java".to_string(),
        );
        for (case_name, name, query) in [
            (
                "file identifier",
                widget_name.clone(),
                RelationalDefinitionQuery::Identifier {
                    file: Some(file.clone()),
                },
            ),
            (
                "file identifier prefix",
                prefix_request.name.clone(),
                RelationalDefinitionQuery::IdentifierPrefix {
                    file: Some(file.clone()),
                },
            ),
        ] {
            let request = RelationalDefinitionRequest {
                ordinal: 0,
                language_scope: DefinitionLanguageScope::Language(Language::Java),
                name,
                query,
            };
            let (prefix, tail, _) = render_name(&adapter, &request.name);
            let sources = split_view_sources(&adapter, &request, &prefix, &tail)
                .unwrap_or_else(|| panic!("{case_name} must route through split_view_sources"));
            assert_eq!(
                sources.len(),
                2,
                "{case_name} must query exactly the stable and anchored identifier views"
            );
            for (view, predicate, values) in &sources {
                let bindings: Vec<&str> = std::iter::once("java")
                    .chain(values.iter().map(String::as_str))
                    .collect();
                let plan = explain(content_sql(view, predicate), &bindings);
                assert_seeks_units_index(
                    case_name,
                    view,
                    "idx_code_units_lang_identifier_lookup",
                    &plan,
                );
            }
        }

        // Shapes with no split-view equivalent keep using the wide view
        // through `definition_values`'s fallback path.
        assert!(
            split_view_sources(
                &adapter,
                &request_for(RelationalDefinitionQuery::PackageTypesInPackage),
                &prefix,
                &tail,
            )
            .is_none(),
            "PackageTypesInPackage has no split-view equivalent and must stay on the wide-view fallback"
        );
    }

    /// `live_definition_identifiers` (0026) remains in place for its other
    /// caller (the blob-local lookup pinned by
    /// `relational_definition_views_enforce_identity_constraints_and_index_name_lookups`
    /// in `crates/bifrost-core/src/cache_db.rs`) and for `path_units`'s
    /// path-derived-row fallback, which still queries the wide view
    /// directly. This pin documents that its identifier-prefix shape still
    /// seeks the identifier index rather than scanning, even though
    /// `definition_values`'s hot point-query path no longer reaches it for
    /// `IdentifierPrefix` (see
    /// `definition_point_queries_seek_split_view_indexes` for the lean
    /// `live_stable_definition_identifiers` / `live_anchored_definition_identifiers`
    /// route that shape uses instead).
    #[test]
    fn identifier_definition_queries_narrow_before_revision_membership() {
        let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
        let connection = store.conn.lock().expect("store mutex");
        let adapter = JavaAdapter;
        let name = RelationalName::stable(parse_symbol_path_fq(
            Language::Java,
            "demo.Widget`",
            segment_interner(),
        ));
        for query in [
            RelationalDefinitionQuery::Identifier { file: None },
            RelationalDefinitionQuery::IdentifierPrefix { file: None },
        ] {
            let request = RelationalDefinitionRequest {
                ordinal: 0,
                language_scope: DefinitionLanguageScope::Language(Language::Java),
                name: name.clone(),
                query,
            };
            let (prefix, tail, _) = render_name(&adapter, &request.name);
            let sources = split_view_sources(&adapter, &request, &prefix, &tail)
                .expect("identifier lookups use split content views");
            assert_eq!(sources.len(), 2, "stable and anchored identifier views");
            for (view, predicate, values) in sources {
                let sql = content_sql(view, &predicate);
                let bindings = std::iter::once("java")
                    .chain(values.iter().map(String::as_str))
                    .collect::<Vec<_>>();
                let mut statement = connection
                    .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                    .expect("prepare identifier query plan");
                let plan = statement
                    .query_map(rusqlite::params_from_iter(bindings), |row| {
                        row.get::<_, String>(3)
                    })
                    .expect("read identifier query plan")
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .expect("collect identifier query plan");
                let identifier_step = plan
                    .iter()
                    .position(|detail| detail.contains("idx_code_units_lang_identifier_lookup"))
                    .unwrap_or_else(|| panic!("identifier index missing: {plan:#?}"));
                let membership_step = plan
                    .iter()
                    .position(|detail| detail.contains("idx_workspace_file_versions_snapshot_blob"))
                    .unwrap_or_else(|| panic!("revision membership missing: {plan:#?}"));
                assert!(
                    identifier_step < membership_step,
                    "{view} must narrow by identifier before revision membership: {plan:#?}"
                );
                assert!(
                    plan.iter().all(|detail| {
                        !detail.contains("SCAN units")
                            && !detail.contains("SCAN code_units")
                            && !detail.contains("SCAN files")
                    }),
                    "{view} must not scan persisted unit or file tables: {plan:#?}"
                );
            }
        }
    }

    #[test]
    fn set_definition_queries_seek_name_indexes() {
        let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
        let connection = store.conn.lock().expect("store mutex");
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
                "{name} set query must seek {index}: {plan:#?}"
            );
            assert!(
                plan.iter()
                    .any(|detail| detail.contains("SCAN json_each VIRTUAL TABLE")),
                "{name} set query must drive from its bounded request relation: {plan:#?}"
            );
            assert!(
                plan.iter()
                    .all(|detail| !detail.contains("SCAN code_units")),
                "{name} set query must not scan code_units: {plan:#?}"
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
                "{name} names-driven query must walk {index}: {plan:#?}"
            );
            assert!(
                plan.iter().any(|detail| {
                    detail.contains("SEARCH requests USING AUTOMATIC")
                        && detail.contains("COVERING INDEX (lookup_key=?)")
                }),
                "{name} names-driven query must probe a bounded ephemeral request index: {plan:#?}"
            );
            assert!(
                plan.iter()
                    .all(|detail| !detail.contains("SCAN code_units")),
                "{name} names-driven query must not scan code_units: {plan:#?}"
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
            "definition ordering must seek the exact-name index: {order_plan:#?}"
        );
        assert!(
            order_plan.iter().any(|detail| {
                detail.contains("SEARCH ranges USING PRIMARY KEY")
                    && detail.contains("blob_oid=?")
                    && detail.contains("lang=?")
                    && detail.contains("unit_key=?")
            }),
            "definition ordering must seek ranges by their unit key: {order_plan:#?}"
        );
        assert!(
            order_plan.iter().all(
                |detail| !detail.contains("SCAN code_units") && !detail.contains("SCAN ranges")
            ),
            "definition ordering must scan neither code units nor ranges: {order_plan:#?}"
        );
    }
}
