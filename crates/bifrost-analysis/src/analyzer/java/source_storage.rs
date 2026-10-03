//! Generation-selected Java declaration syntax and exact mounted unit bridges.

use crate::analyzer::LanguageAdapter;
use crate::analyzer::store::source_facts::{
    SOURCE_DECLARATION_UNITS_SQL, SOURCE_FACTS_VERSION, read_source_identity_rows, strict_bool,
};
use crate::analyzer::store::{
    AnalyzerStore, GenerationId, Result, StoreError, read_source_unit_map,
};
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::java_facts::*;
use brokk_bifrost_core::analyzer::model::StructuredTypeName;
use brokk_bifrost_core::analyzer::source_facts::{SourceDeclarationId, SourceOccurrenceId};
use brokk_bifrost_core::hash::HashMap;
use brokk_bifrost_jvm::java::source_facts::JavaFileSourceFacts;
use git2::Oid;
use rusqlite::{OptionalExtension, params};

pub(in crate::analyzer) const JAVA_SOURCE_HEADER_SQL: &str =
    "SELECT blob.id, marker.logical_rows, marker.payload_bytes,
            source.occurrence_count, source.declaration_count, source.declaration_unit_count
     FROM blobs AS blob
     JOIN source_java_declaration_manifests AS marker ON marker.blob_id = blob.id
     JOIN source_fact_manifests AS source ON source.blob_id = blob.id
     JOIN blob_meta AS meta ON meta.blob_id = blob.id
     JOIN source_fact_readiness AS ready ON ready.blob_id = blob.id
     WHERE blob.blob_oid = ?1 AND blob.lang = 'java' AND blob.generation = ?2
       AND marker.facts_version = ?3 AND source.facts_version = ?4
       AND source.publication_state = 'complete' AND meta.is_complete = 1 AND ready.available = 1";

fn required<T>(value: Option<T>, label: &str) -> Result<T> {
    value.ok_or_else(|| StoreError::new(format!("Java source syntax is missing {label}")))
}

impl AnalyzerStore {
    pub(crate) fn java_source_facts<A: LanguageAdapter>(
        &self,
        oid: Oid,
        generation: GenerationId,
        adapter: &A,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Option<JavaFileSourceFacts>> {
        if !keep_going() {
            return Ok(None);
        }
        self.read_source_transaction("java", generation, |tx| {
            let header = tx
                .query_row(
                    JAVA_SOURCE_HEADER_SQL,
                    params![
                        oid.to_string(),
                        generation.get(),
                        JAVA_SOURCE_FACTS_VERSION,
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
            ) = header.ok_or_else(|| {
                StoreError::new(format!(
                    "canonical Java source facts unavailable for {file:?} ({oid})"
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
            let mut names: HashMap<(u32, i64), Vec<String>> = HashMap::default();
            read_rows!(
                "SELECT type_id,axis,ordinal,name FROM source_java_type_names WHERE blob_id=?1 ORDER BY type_id,axis,ordinal",
                row,
                {
                    let axis: i64 = row.get(1)?;
                    if !matches!(axis, 0 | 1) {
                        return Err(StoreError::new("invalid Java name axis"));
                    }
                    let list = names.entry((row.get(0)?, axis)).or_default();
                    if row.get::<_, usize>(2)? != list.len() {
                        return Err(StoreError::new("non-dense Java type name"));
                    }
                    list.push(row.get(3)?);
                }
            );
            let mut arguments: HashMap<u32, Vec<JavaSourceTypeId>> = HashMap::default();
            read_rows!(
                "SELECT type_id,ordinal,child_id FROM source_java_type_arguments WHERE blob_id=?1 ORDER BY type_id,ordinal",
                row,
                {
                    let list = arguments.entry(row.get(0)?).or_default();
                    if row.get::<_, usize>(1)? != list.len() {
                        return Err(StoreError::new("non-dense Java arguments"));
                    }
                    list.push(JavaSourceTypeId::new(row.get(2)?));
                }
            );
            let mut facts = JavaSourceFacts::default();
            read_rows!("SELECT type_id,occurrence_id,kind,child_id,parameter_declaration_id,absolute,array_dimensions
                FROM source_java_types WHERE blob_id=?1 ORDER BY type_id", row, {
                let id: u32 = row.get(0)?;
                if id as usize != facts.types.len() { return Err(StoreError::new("non-dense Java type arena")); }
                let kind: i64 = row.get(2)?;
                let child = row.get::<_,Option<u32>>(3)?.map(JavaSourceTypeId::new);
                let parameter = row.get::<_,Option<u32>>(4)?.map(SourceDeclarationId::new);
                let absolute: Option<i64> = row.get(5)?;
                let dimensions: Option<u32> = row.get(6)?;
                if matches!(kind,1..=3) != child.is_some() || (kind==0) != absolute.is_some()
                    || (kind==2) != dimensions.is_some() || (kind!=0 && parameter.is_some())
                    || (kind==0) != names.contains_key(&(id,0)) || (kind!=0 && names.contains_key(&(id,1)))
                    || (kind!=1 && arguments.contains_key(&id)) {
                    return Err(StoreError::new(format!("inconsistent Java type columns for {id}/{kind}")));
                }
                let shape = match kind {
                    0 => JavaTypeSyntaxShape::Named { name: required(StructuredTypeName::new(
                        names.remove(&(id,0)).unwrap_or_default(),names.remove(&(id,1)).unwrap_or_default(),
                        strict_bool(required(absolute,"absolute name")?,"Java absolute name")?),"type name")?, parameter },
                    1 => JavaTypeSyntaxShape::Generic { base: required(child,"generic base")?,arguments: arguments.remove(&id).unwrap_or_default() },
                    2 => JavaTypeSyntaxShape::Array { element: required(child,"array element")?,dimensions: required(dimensions,"array dimensions")? },
                    3 => JavaTypeSyntaxShape::Annotated(required(child,"annotated type")?),
                    4 => JavaTypeSyntaxShape::NonNominal,
                    5 => JavaTypeSyntaxShape::Unknown,
                    _ => return Err(StoreError::new(format!("invalid Java type kind {kind}"))),
                };
                facts.types.push(JavaTypeSyntaxFact { occurrence: SourceOccurrenceId::new(row.get(1)?),shape });
            });
            if !names.is_empty() || !arguments.is_empty() {
                return Err(StoreError::new(format!(
                    "orphan Java type details: {names:?}, {arguments:?}"
                )));
            }
            let mut bounds: HashMap<u32, Vec<JavaSourceTypeId>> = HashMap::default();
            read_rows!(
                "SELECT declaration_id,ordinal,type_id FROM source_java_type_bounds WHERE blob_id=?1 ORDER BY declaration_id,ordinal",
                row,
                {
                    let list = bounds.entry(row.get(0)?).or_default();
                    if row.get::<_, usize>(1)? != list.len() {
                        return Err(StoreError::new("non-dense Java bounds"));
                    }
                    list.push(JavaSourceTypeId::new(row.get(2)?));
                }
            );
            read_rows!(
                "SELECT declaration_id,owner_declaration_id,ordinal,name FROM source_java_type_parameters WHERE blob_id=?1 ORDER BY declaration_id",
                row,
                {
                    let id: u32 = row.get(0)?;
                    facts.type_parameters.push(JavaTypeParameterFact {
                        declaration: SourceDeclarationId::new(id),
                        owner: SourceDeclarationId::new(row.get(1)?),
                        ordinal: row.get(2)?,
                        name: row.get(3)?,
                        bounds: bounds.remove(&id).unwrap_or_default(),
                    });
                }
            );
            if !bounds.is_empty() {
                return Err(StoreError::new(format!("orphan Java bounds: {bounds:?}")));
            }
            read_rows!(
                "SELECT declaration_id,type_id FROM source_java_callable_returns WHERE blob_id=?1 ORDER BY declaration_id",
                row,
                {
                    facts.callable_returns.push(JavaCallableReturnFact {
                        callable: SourceDeclarationId::new(row.get(0)?),
                        ty: row.get::<_, Option<u32>>(1)?.map(JavaSourceTypeId::new),
                    });
                }
            );
            read_rows!(
                "SELECT declaration_id,lexical_scope_occurrence_id FROM source_java_local_types WHERE blob_id=?1 ORDER BY declaration_id",
                row,
                {
                    facts.local_types.push(JavaLocalTypeFact {
                        declaration: SourceDeclarationId::new(row.get(0)?),
                        lexical_scope: SourceOccurrenceId::new(row.get(1)?),
                    });
                }
            );
            let mut entries: HashMap<u32, Vec<JavaAnonymousReturnEntry>> = HashMap::default();
            read_rows!(
                "SELECT declaration_id,ordinal,return_occurrence_id,object_occurrence_id,type_id FROM source_java_anonymous_return_entries WHERE blob_id=?1 ORDER BY declaration_id,ordinal",
                row,
                {
                    let list = entries.entry(row.get(0)?).or_default();
                    if row.get::<_, usize>(1)? != list.len() {
                        return Err(StoreError::new("non-dense Java anonymous returns"));
                    }
                    list.push(JavaAnonymousReturnEntry {
                        return_occurrence: SourceOccurrenceId::new(row.get(2)?),
                        object_creation_occurrence: SourceOccurrenceId::new(row.get(3)?),
                        declared_type: JavaSourceTypeId::new(row.get(4)?),
                    });
                }
            );
            read_rows!(
                "SELECT declaration_id,status FROM source_java_anonymous_returns WHERE blob_id=?1 ORDER BY declaration_id",
                row,
                {
                    let id: u32 = row.get(0)?;
                    let status = match row.get::<_, i64>(1)? {
                        0 => JavaAnonymousReturnStatus::AllAnonymous,
                        1 => JavaAnonymousReturnStatus::Unknown,
                        value => {
                            return Err(StoreError::new(format!(
                                "invalid Java anonymous return status {value}"
                            )));
                        }
                    };
                    facts.anonymous_returns.push(JavaAnonymousReturnFact {
                        callable: SourceDeclarationId::new(id),
                        status,
                        returns: entries.remove(&id).unwrap_or_default(),
                    });
                }
            );
            if !entries.is_empty() {
                return Err(StoreError::new(format!(
                    "orphan Java anonymous returns: {entries:?}"
                )));
            }
            read_rows!(
                "SELECT declaration_id,owner_declaration_id FROM source_java_declaration_owners WHERE blob_id=?1 ORDER BY declaration_id",
                row,
                {
                    facts.declaration_owners.push((
                        SourceDeclarationId::new(row.get(0)?),
                        SourceDeclarationId::new(row.get(1)?),
                    ));
                }
            );
            if !facts.valid_links(&source)
                || super::source_publication::cost(&facts) != (expected_rows, expected_bytes)
            {
                return Err(StoreError::new(format!(
                    "invalid or incomplete Java source publication: {facts:?}"
                )));
            }
            let Some(units) = read_source_unit_map(
                tx,
                &oid.to_string(),
                "java",
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
                    return Err(StoreError::new("Java unit bridge has no declaration"));
                }
                declaration_units
                    .entry(declaration)
                    .or_default()
                    .push(unit.clone());
                bridge_count += 1;
            });
            if bridge_count != expected_bridges {
                return Err(StoreError::new(format!(
                    "incomplete Java declaration bridges: {declaration_units:?}"
                )));
            }
            if !keep_going() {
                return Ok(None);
            }
            Ok(Some(JavaFileSourceFacts {
                source,
                facts,
                declaration_units,
            }))
        })
    }
}
