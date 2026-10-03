//! One generation-checked snapshot of Go syntax and its mounted projections.

use crate::analyzer::LanguageAdapter;
use crate::analyzer::store::source_facts::{
    SOURCE_DECLARATION_UNITS_SQL, SOURCE_FACTS_VERSION, read_source_identity_rows, strict_bool,
};
use crate::analyzer::store::{
    AnalyzerStore, GenerationId, Result, StoreError, read_source_unit_map,
};
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::go_facts::*;
use brokk_bifrost_core::analyzer::model::StructuredTypeName;
use brokk_bifrost_core::analyzer::source_facts::{SourceDeclarationId, SourceOccurrenceId};
use brokk_bifrost_core::hash::HashMap;
use brokk_bifrost_go::source_facts::GoFileSourceFacts;
use git2::Oid;
use rusqlite::{OptionalExtension, params};

pub(in crate::analyzer) const GO_SOURCE_HEADER_SQL: &str =
    "SELECT blob.id, marker.logical_rows, marker.payload_bytes,
            source.occurrence_count, source.declaration_count, source.declaration_unit_count,
            marker.membership_digest, marker.has_build_constraints,
            marker.build_selection_facts_version
     FROM blobs AS blob
     JOIN source_go_manifests AS marker ON marker.blob_id = blob.id
     JOIN source_fact_manifests AS source ON source.blob_id = blob.id
     JOIN blob_meta AS meta ON meta.blob_id = blob.id
     JOIN source_fact_readiness AS ready ON ready.blob_id = blob.id
     WHERE blob.blob_oid = ?1 AND blob.lang = 'go' AND blob.generation = ?2
       AND marker.facts_version = ?3 AND source.facts_version = ?4
       AND source.publication_state = 'complete' AND meta.is_complete = 1 AND ready.available = 1";

fn required<T>(value: Option<T>, label: &str) -> Result<T> {
    value.ok_or_else(|| StoreError::new(format!("Go source syntax is missing {label}")))
}

impl AnalyzerStore {
    pub(crate) fn go_source_facts<A: LanguageAdapter>(
        &self,
        oid: Oid,
        generation: GenerationId,
        adapter: &A,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Option<GoFileSourceFacts>> {
        if !keep_going() {
            return Ok(None);
        }
        self.read_source_transaction("go", generation, |tx| {
            let header = tx
                .query_row(
                    GO_SOURCE_HEADER_SQL,
                    params![
                        oid.to_string(),
                        generation.get(),
                        GO_SOURCE_FACTS_VERSION,
                        SOURCE_FACTS_VERSION
                    ],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, usize>(1)?,
                            row.get::<_, usize>(2)?,
                            row.get::<_, usize>(3)?,
                            row.get::<_, usize>(4)?,
                            row.get::<_, usize>(5)?,
                            row.get::<_, Option<Vec<u8>>>(6)?,
                            row.get::<_, bool>(7)?,
                            row.get::<_, i64>(8)?,
                        ))
                    },
                )
                .optional()?;
            let (
                blob_id,
                expected_rows,
                expected_bytes,
                expected_occurrences,
                expected_declarations,
                expected_bridges,
                membership_digest,
                has_build_constraints,
                build_selection_facts_version,
            ) = header.ok_or_else(|| {
                StoreError::new(format!(
                    "canonical Go source facts unavailable for {file:?} ({oid})"
                ))
            })?;

            macro_rules! read_rows {
                ($sql:expr, $row:ident, $body:block) => {{
                    let mut statement = tx.prepare_cached($sql)?;
                    let mut rows = statement.query([blob_id])?;
                    while let Some($row) = rows.next()? {
                        if !keep_going() {
                            return Ok(None);
                        }
                        $body
                    }
                }};
            }
            let Some(source) = read_source_identity_rows(
                tx,
                blob_id,
                expected_occurrences,
                expected_declarations,
                keep_going,
            )?
            else {
                return Ok(None);
            };
            let mut names: HashMap<u32, Vec<String>> = HashMap::default();
            read_rows!(
                "SELECT type_id, ordinal, name FROM source_go_type_names WHERE blob_id = ?1 ORDER BY type_id, ordinal",
                row,
                {
                    let id = row.get(0)?;
                    let ordinal: usize = row.get(1)?;
                    let list = names.entry(id).or_default();
                    if ordinal != list.len() {
                        return Err(StoreError::new("non-dense Go type name"));
                    }
                    list.push(row.get(2)?);
                }
            );
            let mut edges: HashMap<u32, Vec<GoSourceTypeId>> = HashMap::default();
            read_rows!(
                "SELECT type_id, ordinal, child_id FROM source_go_type_children WHERE blob_id = ?1 ORDER BY type_id, ordinal",
                row,
                {
                    let id = row.get(0)?;
                    let ordinal: usize = row.get(1)?;
                    let list = edges.entry(id).or_default();
                    if ordinal != list.len() {
                        return Err(StoreError::new("non-dense Go type children"));
                    }
                    list.push(GoSourceTypeId::new(row.get(2)?));
                }
            );
            let mut facts = GoSourceFacts {
                membership_digest: membership_digest
                    .map(|digest| {
                        <[u8; 32]>::try_from(digest).map_err(|digest| {
                            StoreError::new(format!(
                                "Go membership digest has {} bytes, not 32",
                                digest.len()
                            ))
                        })
                    })
                    .transpose()?,
                has_build_constraints: (build_selection_facts_version
                    == GO_BUILD_SELECTION_FACTS_VERSION)
                    .then_some(has_build_constraints),
                ..GoSourceFacts::default()
            };
            read_rows!("SELECT type_id, occurrence_id, kind, child1, child2, detail_occurrence_id, text, direction, has_named_children
                        FROM source_go_types WHERE blob_id = ?1 ORDER BY type_id", row, {
                let id: u32 = row.get(0)?;
                if id as usize != facts.types.len() { return Err(StoreError::new("non-dense Go type arena")); }
                let occurrence = SourceOccurrenceId::new(row.get(1)?);
                let kind: i64 = row.get(2)?;
                let child1 = row.get::<_, Option<u32>>(3)?.map(GoSourceTypeId::new);
                let child2 = row.get::<_, Option<u32>>(4)?.map(GoSourceTypeId::new);
                let detail = row.get::<_, Option<u32>>(5)?.map(SourceOccurrenceId::new);
                let text: Option<String> = row.get(6)?;
                let direction: Option<i64> = row.get(7)?;
                let has_named_children: Option<i64> = row.get(8)?;
                if matches!(kind, 1..=7 | 11) != child1.is_some() || (kind == 5) != child2.is_some()
                    || matches!(kind, 3 | 7) != detail.is_some()
                    || (kind == 3 && text.is_none())
                    || (!matches!(kind, 3 | 4 | 7 | 12..=14) && text.is_some())
                    || (kind == 6) != direction.is_some() || (kind == 13) != has_named_children.is_some()
                    || (kind == 0) != names.contains_key(&id) || (!matches!(kind, 7..=10) && edges.contains_key(&id)) {
                    return Err(StoreError::new(format!("inconsistent Go type columns for {id}/{kind}")));
                }
                let shape = match kind {
                    0 => GoSourceTypeShape::Named(required(StructuredTypeName::new(names.remove(&id).unwrap_or_default(), Vec::new(), false), "type name")?),
                    1 => GoSourceTypeShape::Pointer(required(child1, "pointer child")?),
                    2 => GoSourceTypeShape::Slice(required(child1, "slice child")?),
                    3 => GoSourceTypeShape::Array { element: required(child1, "array element")?, length: required(detail, "array length")?, length_text: required(text, "array spelling")? },
                    4 => GoSourceTypeShape::ImplicitArray { element: required(child1, "implicit array element")?, text },
                    5 => GoSourceTypeShape::Map { key: required(child1, "map key")?, value: required(child2, "map value")? },
                    6 => GoSourceTypeShape::Channel {
                        direction: match direction { Some(0) => GoChannelDirection::Both, Some(1) => GoChannelDirection::Receive, Some(2) => GoChannelDirection::Send,
                            _ => return Err(StoreError::new(format!("invalid Go channel direction {direction:?}"))) },
                        element: required(child1, "channel element")?,
                    },
                    7 => GoSourceTypeShape::Generic { base: required(child1, "generic base")?, arguments: edges.remove(&id).unwrap_or_default(),
                        argument_list: required(detail, "generic arguments")?, argument_text: text },
                    8..=10 => GoSourceTypeShape::Compound { kind: match kind { 8 => GoTypeCompoundKind::Parenthesized, 9 => GoTypeCompoundKind::Element, _ => GoTypeCompoundKind::Constraint }, children: edges.remove(&id).unwrap_or_default() },
                    11 => GoSourceTypeShape::Negated(required(child1, "negated child")?),
                    12 => GoSourceTypeShape::Struct { text },
                    13 => GoSourceTypeShape::Interface { text, has_named_children: strict_bool(required(has_named_children, "interface emptiness")?, "interface named children")? },
                    14 => GoSourceTypeShape::Opaque { text },
                    _ => return Err(StoreError::new(format!("invalid Go source type kind {kind}"))),
                };
                facts.types.push(GoSourceTypeFact { occurrence, shape });
            });
            if !names.is_empty() || !edges.is_empty() {
                return Err(StoreError::new(format!(
                    "orphan Go type details: {names:?}, {edges:?}"
                )));
            }
            read_rows!(
                "SELECT declaration_id, name, type_id, file_scope FROM source_go_type_declarations WHERE blob_id = ?1 ORDER BY declaration_id",
                row,
                {
                    facts.declarations.push(GoTypeDeclarationFact {
                        declaration: SourceDeclarationId::new(row.get(0)?),
                        name: row.get(1)?,
                        ty: GoSourceTypeId::new(row.get(2)?),
                        file_scope: strict_bool(row.get(3)?, "type file scope")?,
                    });
                }
            );
            read_rows!(
                "SELECT declaration_id, name, target_type_id FROM source_go_aliases WHERE blob_id = ?1 ORDER BY declaration_id",
                row,
                {
                    facts.aliases.push(GoAliasFact {
                        declaration: SourceDeclarationId::new(row.get(0)?),
                        name: row.get(1)?,
                        target: row.get::<_, Option<u32>>(2)?.map(GoSourceTypeId::new),
                    });
                }
            );
            read_rows!(
                "SELECT declaration_id, owner_type_id, type_id, name, embedded FROM source_go_fields WHERE blob_id = ?1 ORDER BY declaration_id",
                row,
                {
                    facts.fields.push(GoFieldFact {
                        declaration: SourceDeclarationId::new(row.get(0)?),
                        owner: GoSourceTypeId::new(row.get(1)?),
                        ty: row.get::<_, Option<u32>>(2)?.map(GoSourceTypeId::new),
                        name: row.get(3)?,
                        embedded: strict_bool(row.get(4)?, "embedded field")?,
                    });
                }
            );
            let mut callable_indices = HashMap::default();
            read_rows!("SELECT declaration_id, name, owner_type_id, receiver_type_id, is_method, parameters_present,
                        result_occurrence_id, body_occurrence_id, file_scope FROM source_go_callables WHERE blob_id = ?1 ORDER BY declaration_id", row, {
                let declaration = SourceDeclarationId::new(row.get(0)?);
                callable_indices.insert(declaration, facts.callables.len());
                facts.callables.push(GoCallableFact { declaration, name: row.get(1)?, owner: row.get::<_, Option<u32>>(2)?.map(GoSourceTypeId::new),
                    receiver: row.get::<_, Option<u32>>(3)?.map(GoSourceTypeId::new), is_method: strict_bool(row.get(4)?, "receiver method")?,
                    parameters: strict_bool(row.get(5)?, "parameter list presence")?.then(Vec::new), results: Vec::new(),
                    result: row.get::<_, Option<u32>>(6)?.map(SourceOccurrenceId::new), body: row.get::<_, Option<u32>>(7)?.map(SourceOccurrenceId::new),
                    file_scope: strict_bool(row.get(8)?, "callable file scope")? });
            });
            read_rows!("SELECT declaration_id, result, ordinal, group_occurrence_id, name_occurrence_id, type_id, variadic
                        FROM source_go_callable_parameters WHERE blob_id = ?1 ORDER BY declaration_id, result, ordinal", row, {
                let declaration = SourceDeclarationId::new(row.get(0)?);
                let index = required(callable_indices.get(&declaration).copied(), "parameter callable")?;
                let callable = &mut facts.callables[index];
                let list = if strict_bool(row.get(1)?, "result parameter")? {
                    if callable.result.is_none() { return Err(StoreError::new("Go results have no written result")); }
                    &mut callable.results
                } else { required(callable.parameters.as_mut(), "written parameter list")? };
                let ordinal: usize = row.get(2)?;
                if ordinal != list.len() { return Err(StoreError::new("non-dense Go callable parameters")); }
                list.push(GoCallableParameterFact { group: SourceOccurrenceId::new(row.get(3)?), name: row.get::<_, Option<u32>>(4)?.map(SourceOccurrenceId::new),
                    ty: row.get::<_, Option<u32>>(5)?.map(GoSourceTypeId::new), variadic: strict_bool(row.get(6)?, "variadic parameter")? });
            });
            read_rows!(
                "SELECT ordinal, owner_type_id, occurrence_id, type_id FROM source_go_embeddings WHERE blob_id = ?1 ORDER BY ordinal",
                row,
                {
                    let ordinal: usize = row.get(0)?;
                    if ordinal != facts.embeddings.len() {
                        return Err(StoreError::new("non-dense Go embeddings"));
                    }
                    facts.embeddings.push(GoEmbeddingFact {
                        owner: GoSourceTypeId::new(row.get(1)?),
                        occurrence: SourceOccurrenceId::new(row.get(2)?),
                        ty: GoSourceTypeId::new(row.get(3)?),
                    });
                }
            );
            if !facts.valid_links(&source)
                || super::source_publication::cost(&facts) != (expected_rows, expected_bytes)
            {
                return Err(StoreError::new(format!(
                    "invalid or incomplete Go source publication: {facts:?}"
                )));
            }
            let Some(units) = read_source_unit_map(
                tx,
                &oid.to_string(),
                "go",
                adapter,
                file,
                keep_going,
            )?
            else {
                return Ok(None);
            };
            let mut declaration_units: HashMap<_, Vec<_>> = HashMap::default();
            let mut bridge_count = 0;
            read_rows!(SOURCE_DECLARATION_UNITS_SQL, row, {
                let declaration = SourceDeclarationId::new(row.get(0)?);
                let key: i64 = row.get(1)?;
                let unit = required(units.get(&key), "declaration unit")?;
                if declaration.index() >= source.declaration_count() {
                    return Err(StoreError::new("Go unit bridge has no declaration"));
                }
                declaration_units
                    .entry(declaration)
                    .or_default()
                    .push(unit.clone());
                bridge_count += 1;
            });
            if bridge_count != expected_bridges {
                return Err(StoreError::new(format!(
                    "incomplete Go declaration bridges: {declaration_units:?}"
                )));
            }
            if !keep_going() {
                return Ok(None);
            }
            Ok(Some(GoFileSourceFacts {
                source,
                facts,
                declaration_units,
            }))
        })
    }
}
