//! Relational publication of Java declaration type syntax.

use crate::CancellationToken;
use crate::analyzer::store::source_facts::check_cancelled;
use crate::analyzer::store::{Result, SourceFactStorage, usize_to_i64};
use brokk_bifrost_core::analyzer::java_facts::*;
use brokk_bifrost_core::analyzer::parsed_file::ParsedSourceFacts;
use rusqlite::{Transaction, params};

pub(crate) static SOURCE_STORAGE: SourceFactStorage = SourceFactStorage {
    cost: |source| source.java.as_ref().map(cost),
    insert,
};

pub(crate) fn cost(facts: &JavaSourceFacts) -> (usize, usize) {
    let mut rows = 1
        + facts.types.len()
        + facts.type_parameters.len()
        + facts.callable_returns.len()
        + facts.local_types.len()
        + facts.anonymous_returns.len()
        + facts.declaration_owners.len();
    let mut bytes = 0;
    for fact in &facts.types {
        match &fact.shape {
            JavaTypeSyntaxShape::Named { name, .. } => {
                rows += name.path().len() + name.lexical_scope().len();
                bytes += name
                    .path()
                    .iter()
                    .chain(name.lexical_scope())
                    .map(String::len)
                    .sum::<usize>();
            }
            JavaTypeSyntaxShape::Generic { arguments, .. } => rows += arguments.len(),
            _ => {}
        }
    }
    for parameter in &facts.type_parameters {
        rows += parameter.bounds.len();
        bytes += parameter.name.len();
    }
    rows += facts
        .anonymous_returns
        .iter()
        .map(|fact| fact.returns.len())
        .sum::<usize>();
    (rows, bytes)
}

fn insert(
    tx: &Transaction<'_>,
    blob_id: i64,
    source: &ParsedSourceFacts,
    cancellation: &CancellationToken,
) -> Result<()> {
    let Some(facts) = &source.java else {
        return Ok(());
    };
    assert!(
        facts.valid_links(&source.occurrences),
        "invalid Java source links: {facts:?}"
    );
    let mut types = tx.prepare_cached("INSERT INTO source_java_types
        (blob_id,type_id,occurrence_id,kind,child_id,parameter_declaration_id,absolute,array_dimensions)
        VALUES(?1,?2,?3,?4,?5,?6,?7,?8)")?;
    let mut names = tx.prepare_cached(
        "INSERT INTO source_java_type_names
        (blob_id,type_id,axis,ordinal,name) VALUES(?1,?2,?3,?4,?5)",
    )?;
    let mut arguments = tx.prepare_cached(
        "INSERT INTO source_java_type_arguments
        (blob_id,type_id,ordinal,child_id) VALUES(?1,?2,?3,?4)",
    )?;
    for (index, fact) in facts.types.iter().enumerate() {
        check_cancelled(cancellation)?;
        let (kind, child, parameter, absolute, dimensions) = match &fact.shape {
            JavaTypeSyntaxShape::Named { name, parameter } => {
                (0, None, *parameter, Some(name.is_absolute()), None)
            }
            JavaTypeSyntaxShape::Generic { base, .. } => (1, Some(*base), None, None, None),
            JavaTypeSyntaxShape::Array {
                element,
                dimensions,
            } => (2, Some(*element), None, None, Some(*dimensions)),
            JavaTypeSyntaxShape::Annotated(inner) => (3, Some(*inner), None, None, None),
            JavaTypeSyntaxShape::NonNominal => (4, None, None, None, None),
            JavaTypeSyntaxShape::Unknown => (5, None, None, None, None),
        };
        types.execute(params![
            blob_id,
            usize_to_i64(index)?,
            fact.occurrence.get(),
            kind,
            child.map(JavaSourceTypeId::get),
            parameter.map(|id| id.get()),
            absolute,
            dimensions
        ])?;
        match &fact.shape {
            JavaTypeSyntaxShape::Named { name, .. } => {
                for (axis, parts) in [(0, name.path()), (1, name.lexical_scope())] {
                    for (ordinal, name) in parts.iter().enumerate() {
                        check_cancelled(cancellation)?;
                        names.execute(params![
                            blob_id,
                            usize_to_i64(index)?,
                            axis,
                            usize_to_i64(ordinal)?,
                            name
                        ])?;
                    }
                }
            }
            JavaTypeSyntaxShape::Generic {
                arguments: children,
                ..
            } => {
                for (ordinal, child) in children.iter().enumerate() {
                    check_cancelled(cancellation)?;
                    arguments.execute(params![
                        blob_id,
                        usize_to_i64(index)?,
                        usize_to_i64(ordinal)?,
                        child.get()
                    ])?;
                }
            }
            _ => {}
        }
    }
    drop((types, names, arguments));
    let mut parameters = tx.prepare_cached(
        "INSERT INTO source_java_type_parameters
        (blob_id,declaration_id,owner_declaration_id,ordinal,name) VALUES(?1,?2,?3,?4,?5)",
    )?;
    let mut bounds = tx.prepare_cached(
        "INSERT INTO source_java_type_bounds
        (blob_id,declaration_id,ordinal,type_id) VALUES(?1,?2,?3,?4)",
    )?;
    for fact in &facts.type_parameters {
        check_cancelled(cancellation)?;
        parameters.execute(params![
            blob_id,
            fact.declaration.get(),
            fact.owner.get(),
            fact.ordinal,
            fact.name
        ])?;
        for (ordinal, bound) in fact.bounds.iter().enumerate() {
            check_cancelled(cancellation)?;
            bounds.execute(params![
                blob_id,
                fact.declaration.get(),
                usize_to_i64(ordinal)?,
                bound.get()
            ])?;
        }
    }
    drop((parameters, bounds));
    let mut statement = tx.prepare_cached(
        "INSERT INTO source_java_callable_returns
        (blob_id,declaration_id,type_id) VALUES(?1,?2,?3)",
    )?;
    for fact in &facts.callable_returns {
        check_cancelled(cancellation)?;
        statement.execute(params![
            blob_id,
            fact.callable.get(),
            fact.ty.map(JavaSourceTypeId::get)
        ])?;
    }
    drop(statement);
    let mut statement = tx.prepare_cached(
        "INSERT INTO source_java_local_types(
           blob_id, declaration_id, lexical_scope_occurrence_id, lexical_scope_start_byte, lexical_scope_end_byte
         ) VALUES(?1, ?2, ?3, ?4, ?5)",
    )?;
    for fact in &facts.local_types {
        check_cancelled(cancellation)?;
        let inline_lexical_scope_occurrence = source.occurrences.occurrence(fact.lexical_scope);
        statement.execute(params![
            blob_id,
            fact.declaration.get(),
            fact.lexical_scope.get(),
            usize_to_i64(inline_lexical_scope_occurrence.range.start_byte)?,
            usize_to_i64(inline_lexical_scope_occurrence.range.end_byte)?,
        ])?;
    }
    drop(statement);
    let mut statement = tx.prepare_cached(
        "INSERT INTO source_java_anonymous_returns
        (blob_id,declaration_id,status) VALUES(?1,?2,?3)",
    )?;
    let mut entries = tx.prepare_cached(
        "INSERT INTO source_java_anonymous_return_entries
        (blob_id,declaration_id,ordinal,return_occurrence_id,object_occurrence_id,type_id)
        VALUES(?1,?2,?3,?4,?5,?6)",
    )?;
    for fact in &facts.anonymous_returns {
        check_cancelled(cancellation)?;
        let status = match fact.status {
            JavaAnonymousReturnStatus::AllAnonymous => 0,
            JavaAnonymousReturnStatus::Unknown => 1,
        };
        statement.execute(params![blob_id, fact.callable.get(), status])?;
        for (ordinal, entry) in fact.returns.iter().enumerate() {
            check_cancelled(cancellation)?;
            entries.execute(params![
                blob_id,
                fact.callable.get(),
                usize_to_i64(ordinal)?,
                entry.return_occurrence.get(),
                entry.object_creation_occurrence.get(),
                entry.declared_type.get()
            ])?;
        }
    }
    drop((statement, entries));
    let mut statement = tx.prepare_cached(
        "INSERT INTO source_java_declaration_owners
        (blob_id,declaration_id,owner_declaration_id) VALUES(?1,?2,?3)",
    )?;
    for (declaration, owner) in &facts.declaration_owners {
        check_cancelled(cancellation)?;
        statement.execute(params![blob_id, declaration.get(), owner.get()])?;
    }
    drop(statement);
    let (rows, bytes) = cost(facts);
    tx.execute("INSERT INTO source_java_declaration_manifests(blob_id,facts_version,logical_rows,payload_bytes)
        VALUES(?1,?2,?3,?4)",params![blob_id,JAVA_SOURCE_FACTS_VERSION,usize_to_i64(rows)?,usize_to_i64(bytes)?])?;
    Ok(())
}
