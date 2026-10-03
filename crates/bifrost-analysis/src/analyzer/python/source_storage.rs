//! Generation-selected Python callable returns without source access.

use crate::analyzer::store::source_facts::{
    SOURCE_FACTS_VERSION, read_source_identity_rows, strict_bool,
};
use crate::analyzer::store::{AnalyzerStore, GenerationId, Result, StoreError};
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::model::{StructuredTypeIdentityBuilder, StructuredTypeName};
use brokk_bifrost_core::analyzer::python_facts::{
    PYTHON_SOURCE_FACTS_VERSION, PythonAnnotationReferenceFact, PythonAnnotationReferenceName,
    PythonCallableReturnFact, PythonSourceFacts,
};
use brokk_bifrost_core::analyzer::source_facts::{SourceDeclarationId, SourceOccurrenceId};
use brokk_bifrost_core::hash::HashMap;
use brokk_bifrost_python::source_facts::PythonFileSourceFacts;
use git2::Oid;
use rusqlite::{OptionalExtension, params};

pub(in crate::analyzer) const PYTHON_SOURCE_HEADER_SQL: &str =
    "SELECT blob.id, marker.logical_rows, marker.payload_bytes,
            source.occurrence_count, source.declaration_count
     FROM blobs AS blob
     JOIN source_python_manifests AS marker ON marker.blob_id = blob.id
     JOIN source_fact_manifests AS source ON source.blob_id = blob.id
     JOIN blob_meta AS meta ON meta.blob_id = blob.id
     JOIN source_fact_readiness AS ready ON ready.blob_id = blob.id
     WHERE blob.blob_oid = ?1 AND blob.lang = 'python' AND blob.generation = ?2
       AND marker.facts_version = ?3 AND meta.python_source_version = marker.facts_version
       AND source.facts_version = ?4 AND source.publication_state = 'complete'
       AND meta.is_complete = 1 AND ready.available = 1";

impl AnalyzerStore {
    pub(crate) fn python_source_facts(
        &self,
        oid: Oid,
        generation: GenerationId,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Option<PythonFileSourceFacts>> {
        if !keep_going() {
            return Ok(None);
        }
        self.read_source_transaction("python", generation, |tx| {
            let header = tx
                .query_row(
                    PYTHON_SOURCE_HEADER_SQL,
                    params![
                        oid.to_string(),
                        generation.get(),
                        PYTHON_SOURCE_FACTS_VERSION,
                        SOURCE_FACTS_VERSION
                    ],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, usize>(1)?,
                            row.get::<_, usize>(2)?,
                            row.get::<_, usize>(3)?,
                            row.get::<_, usize>(4)?,
                        ))
                    },
                )
                .optional()?
                .ok_or_else(|| {
                    StoreError::new(format!(
                        "canonical Python source facts unavailable for {file:?} ({oid})"
                    ))
                })?;
            let (blob_id, expected_rows, expected_bytes, occurrence_count, declaration_count) = header;
            let Some(occurrences) = read_source_identity_rows(
                tx,
                blob_id,
                occurrence_count,
                declaration_count,
                keep_going,
            )?
            else {
                return Ok(None);
            };
            let mut names: HashMap<u32, Vec<String>> = HashMap::default();
            let mut statement = tx.prepare_cached("SELECT declaration_id,ordinal,name FROM source_python_return_names WHERE blob_id=?1 ORDER BY declaration_id,ordinal")?;
            let mut rows = statement.query([blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let path = names.entry(row.get(0)?).or_default();
                if row.get::<_, usize>(1)? != path.len() {
                    return Err(StoreError::new("noncontiguous Python runtime type name"));
                }
                path.push(row.get(2)?);
            }
            drop(rows);
            drop(statement);
            let mut reference_names: HashMap<(u32, usize), Vec<String>> = HashMap::default();
            let mut statement = tx.prepare_cached("SELECT declaration_id,reference_ordinal,ordinal,name FROM source_python_annotation_names WHERE blob_id=?1 ORDER BY declaration_id,reference_ordinal,ordinal")?;
            let mut rows = statement.query([blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let path = reference_names
                    .entry((row.get(0)?, row.get(1)?))
                    .or_default();
                if row.get::<_, usize>(2)? != path.len() {
                    return Err(StoreError::new("noncontiguous Python annotation name"));
                }
                path.push(row.get(3)?);
            }
            drop(rows);
            drop(statement);
            let mut references: HashMap<u32, Vec<PythonAnnotationReferenceFact>> = HashMap::default();
            let mut statement = tx.prepare_cached("SELECT declaration_id,ordinal,occurrence_id,name_kind,lexical_name,subtree_end,lookup_depth FROM source_python_annotation_references WHERE blob_id=?1 ORDER BY declaration_id,ordinal")?;
            let mut rows = statement.query([blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let declaration = row.get::<_, u32>(0)?;
                let ordinal = row.get::<_, usize>(1)?;
                let list = references.entry(declaration).or_default();
                if ordinal != list.len() {
                    return Err(StoreError::new(
                        "noncontiguous Python annotation references",
                    ));
                }
                let lexical = row.get::<_, Option<String>>(4)?;
                let qualified = reference_names.remove(&(declaration, ordinal));
                let name = match (row.get::<_, i64>(3)?, lexical, qualified) {
                    (0, Some(name), None) => PythonAnnotationReferenceName::Lexical(name),
                    (1, None, Some(parts)) => PythonAnnotationReferenceName::Qualified(parts),
                    (2, None, None) => PythonAnnotationReferenceName::Unavailable,
                    _ => return Err(StoreError::new("invalid Python annotation reference name")),
                };
                list.push(PythonAnnotationReferenceFact {
                    occurrence: SourceOccurrenceId::new(row.get(2)?),
                    name,
                    subtree_end: row.get(5)?,
                    lookup_depth: row.get(6)?,
                });
            }
            drop(rows);
            drop(statement);
            let mut facts = PythonSourceFacts::default();
            let mut statement = tx.prepare_cached("SELECT declaration_id,return_annotation_id,runtime_type_present FROM source_python_callable_returns WHERE blob_id=?1 ORDER BY declaration_id")?;
            let mut rows = statement.query([blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let declaration = row.get::<_, u32>(0)?;
                let annotation = row.get::<_, Option<u32>>(1)?.map(SourceOccurrenceId::new);
                let present = strict_bool(row.get(2)?, "Python runtime type presence")?;
                let path = names.remove(&declaration);
                let runtime_type =
                    match (present, path) {
                        (false, None) => None,
                        (true, Some(path)) => {
                            let name = StructuredTypeName::new(path, Vec::new(), false)
                                .ok_or_else(|| StoreError::new("invalid Python runtime type name"))?;
                            let mut builder = StructuredTypeIdentityBuilder::default();
                            let root = builder.named(name).ok_or_else(|| {
                                StoreError::new("Python runtime type exceeds model limits")
                            })?;
                            Some(builder.finish(root).ok_or_else(|| {
                                StoreError::new("invalid Python runtime type identity")
                            })?)
                        }
                        _ => {
                            return Err(StoreError::new(
                                "Python runtime type presence disagrees with name rows",
                            ));
                        }
                    };
                facts.callable_returns.push(PythonCallableReturnFact {
                    declaration: SourceDeclarationId::new(declaration),
                    return_annotation: annotation,
                    runtime_type,
                    annotation_references: references.remove(&declaration).unwrap_or_default(),
                });
            }
            drop(rows);
            drop(statement);
            if !names.is_empty()
                || !references.is_empty()
                || !reference_names.is_empty()
                || !facts.valid_links(&occurrences)
            {
                return Err(StoreError::new(format!(
                    "invalid Python source links: {facts:?}, orphan names: {names:?}, references: {references:?}, annotation names: {reference_names:?}"
                )));
            }
            if super::source_publication::cost(&facts) != (expected_rows, expected_bytes) {
                return Err(StoreError::new(
                    "Python source publication accounting mismatch",
                ));
            }
            if !keep_going() {
                return Ok(None);
            }
            Ok(Some(PythonFileSourceFacts { occurrences, facts }))
        })
    }
}
