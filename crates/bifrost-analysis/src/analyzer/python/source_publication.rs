//! Relational persistence for Python callable return-annotation admission.

use crate::CancellationToken;
use crate::analyzer::store::source_facts::check_cancelled;
use crate::analyzer::store::{Result, SourceFactStorage, usize_to_i64};
use brokk_bifrost_core::analyzer::parsed_file::ParsedSourceFacts;
use brokk_bifrost_core::analyzer::python_facts::{
    PYTHON_SOURCE_FACTS_VERSION, PythonAnnotationReferenceName, PythonSourceFacts,
};
use rusqlite::{Transaction, params};

pub(crate) static SOURCE_STORAGE: SourceFactStorage = SourceFactStorage {
    cost: |source| source.python.as_ref().map(cost),
    insert,
};

pub(crate) fn cost(facts: &PythonSourceFacts) -> (usize, usize) {
    let mut rows = 1usize.saturating_add(facts.callable_returns.len());
    let mut bytes = 0usize;
    for fact in &facts.callable_returns {
        rows = rows.saturating_add(fact.annotation_references.len());
        for reference in &fact.annotation_references {
            match &reference.name {
                PythonAnnotationReferenceName::Lexical(name) => {
                    bytes = bytes.saturating_add(name.len())
                }
                PythonAnnotationReferenceName::Qualified(parts) => {
                    rows = rows.saturating_add(parts.len());
                    for part in parts {
                        bytes = bytes.saturating_add(part.len());
                    }
                }
                PythonAnnotationReferenceName::Unavailable => {}
            }
        }
        if let Some(identity) = &fact.runtime_type {
            let name = identity
                .nominal_name()
                .expect("Python runtime types are nominal");
            rows = rows.saturating_add(name.path().len());
            for part in name.path() {
                bytes = bytes.saturating_add(part.len());
            }
        }
    }
    (rows, bytes)
}

fn insert(
    tx: &Transaction<'_>,
    blob_id: i64,
    source: &ParsedSourceFacts,
    cancellation: &CancellationToken,
) -> Result<()> {
    let Some(facts) = &source.python else {
        return Ok(());
    };
    assert!(
        facts.valid_links(&source.occurrences),
        "invalid Python source facts: {facts:?}"
    );
    let mut returns = tx.prepare_cached(
        "INSERT INTO source_python_callable_returns(
           blob_id, declaration_id, return_annotation_id, runtime_type_present, return_annotation_start_byte, return_annotation_end_byte
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    let mut names = tx.prepare_cached(
        "INSERT INTO source_python_return_names(blob_id,declaration_id,ordinal,name) VALUES(?1,?2,?3,?4)",
    )?;
    let mut references = tx.prepare_cached(
        "INSERT INTO source_python_annotation_references(
           blob_id, declaration_id, ordinal, occurrence_id, name_kind, lexical_name, subtree_end, lookup_depth, start_byte, end_byte
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
    )?;
    let mut reference_names = tx.prepare_cached(
        "INSERT INTO source_python_annotation_names(blob_id,declaration_id,reference_ordinal,ordinal,name) VALUES(?1,?2,?3,?4,?5)",
    )?;
    for fact in &facts.callable_returns {
        check_cancelled(cancellation)?;
        let inline_return_annotation =
            (fact.return_annotation).map(|id| source.occurrences.occurrence(id));
        returns.execute(params![
            blob_id,
            fact.declaration.get(),
            fact.return_annotation.map(|id| id.get()),
            fact.runtime_type.is_some(),
            inline_return_annotation
                .map(|occurrence| usize_to_i64(occurrence.range.start_byte))
                .transpose()?,
            inline_return_annotation
                .map(|occurrence| usize_to_i64(occurrence.range.end_byte))
                .transpose()?,
        ])?;
        if let Some(identity) = &fact.runtime_type {
            let name = identity
                .nominal_name()
                .expect("validated nominal Python runtime type");
            for (ordinal, part) in name.path().iter().enumerate() {
                check_cancelled(cancellation)?;
                names.execute(params![
                    blob_id,
                    fact.declaration.get(),
                    usize_to_i64(ordinal)?,
                    part
                ])?;
            }
        }
        for (ordinal, reference) in fact.annotation_references.iter().enumerate() {
            check_cancelled(cancellation)?;
            let (kind, lexical_name) = match &reference.name {
                PythonAnnotationReferenceName::Lexical(name) => (0, Some(name.as_str())),
                PythonAnnotationReferenceName::Qualified(_) => (1, None),
                PythonAnnotationReferenceName::Unavailable => (2, None),
            };
            let inline_occurrence = source.occurrences.occurrence(reference.occurrence);
            references.execute(params![
                blob_id,
                fact.declaration.get(),
                usize_to_i64(ordinal)?,
                reference.occurrence.get(),
                kind,
                lexical_name,
                usize_to_i64(reference.subtree_end)?,
                reference.lookup_depth,
                usize_to_i64(inline_occurrence.range.start_byte)?,
                usize_to_i64(inline_occurrence.range.end_byte)?,
            ])?;
            if let PythonAnnotationReferenceName::Qualified(parts) = &reference.name {
                for (part_ordinal, part) in parts.iter().enumerate() {
                    check_cancelled(cancellation)?;
                    reference_names.execute(params![
                        blob_id,
                        fact.declaration.get(),
                        usize_to_i64(ordinal)?,
                        usize_to_i64(part_ordinal)?,
                        part
                    ])?;
                }
            }
        }
    }
    drop((returns, names, references, reference_names));
    check_cancelled(cancellation)?;
    let (rows, bytes) = cost(facts);
    tx.execute(
        "INSERT INTO source_python_manifests(blob_id,facts_version,logical_rows,payload_bytes) VALUES(?1,?2,?3,?4)",
        params![blob_id, PYTHON_SOURCE_FACTS_VERSION, usize_to_i64(rows)?, usize_to_i64(bytes)?],
    )?;
    Ok(())
}
