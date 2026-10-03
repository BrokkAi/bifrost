//! Relational publication of source-owned Go declaration syntax.

use brokk_bifrost_core::analyzer::go_facts::*;
use brokk_bifrost_core::analyzer::parsed_file::ParsedSourceFacts;
use rusqlite::{Transaction, params};

use crate::CancellationToken;
use crate::analyzer::store::source_facts::check_cancelled;
use crate::analyzer::store::{Result, SourceFactStorage, usize_to_i64};

pub(crate) static SOURCE_STORAGE: SourceFactStorage = SourceFactStorage {
    cost: |source| source.go.as_ref().map(cost),
    insert,
};

pub(crate) fn cost(facts: &GoSourceFacts) -> (usize, usize) {
    let mut rows = 1
        + facts.types.len()
        + facts.declarations.len()
        + facts.aliases.len()
        + facts.fields.len()
        + facts.callables.len()
        + facts.embeddings.len();
    let mut bytes = 0usize;
    for fact in &facts.types {
        match &fact.shape {
            GoSourceTypeShape::Named(name) => {
                rows += name.path().len();
                bytes += name.path().iter().map(String::len).sum::<usize>();
            }
            GoSourceTypeShape::Array { length_text, .. } => bytes += length_text.len(),
            GoSourceTypeShape::Generic {
                arguments,
                argument_text,
                ..
            } => {
                rows += arguments.len();
                bytes += argument_text.as_ref().map_or(0, |text| text.len());
            }
            GoSourceTypeShape::Compound { children, .. } => rows += children.len(),
            GoSourceTypeShape::ImplicitArray { text, .. }
            | GoSourceTypeShape::Struct { text }
            | GoSourceTypeShape::Interface { text, .. }
            | GoSourceTypeShape::Opaque { text } => {
                bytes += text.as_ref().map_or(0, |text| text.len());
            }
            _ => {}
        }
    }
    bytes += facts
        .declarations
        .iter()
        .map(|fact| fact.name.len())
        .sum::<usize>();
    bytes += facts
        .aliases
        .iter()
        .map(|fact| fact.name.len())
        .sum::<usize>();
    bytes += facts
        .fields
        .iter()
        .map(|fact| fact.name.len())
        .sum::<usize>();
    for callable in &facts.callables {
        bytes += callable.name.len();
        rows += callable.parameters.as_ref().map_or(0, Vec::len) + callable.results.len();
    }
    (rows, bytes)
}

fn insert(
    tx: &Transaction<'_>,
    blob_id: i64,
    source: &ParsedSourceFacts,
    cancellation: &CancellationToken,
) -> Result<()> {
    let Some(facts) = &source.go else {
        return Ok(());
    };
    assert!(
        facts.valid_links(&source.occurrences),
        "invalid Go source links: {facts:?}"
    );
    let mut types = tx.prepare_cached(
        "INSERT INTO source_go_types
        (blob_id, type_id, occurrence_id, kind, child1, child2, detail_occurrence_id,
         text, direction, has_named_children) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
    )?;
    let mut names = tx.prepare_cached(
        "INSERT INTO source_go_type_names
        (blob_id, type_id, ordinal, name) VALUES(?1, ?2, ?3, ?4)",
    )?;
    let mut edges = tx.prepare_cached(
        "INSERT INTO source_go_type_children
        (blob_id, type_id, ordinal, child_id) VALUES(?1, ?2, ?3, ?4)",
    )?;
    for (index, fact) in facts.types.iter().enumerate() {
        check_cancelled(cancellation)?;
        let mut child1 = None;
        let mut child2 = None;
        let mut occurrence = None;
        let mut text: Option<&str> = None;
        let mut direction = None;
        let mut has_named_children = None;
        let mut children: &[GoSourceTypeId] = &[];
        let mut name_parts: &[String] = &[];
        let kind = match &fact.shape {
            GoSourceTypeShape::Named(name) => {
                assert!(name.path().len() <= 2);
                name_parts = name.path();
                0
            }
            GoSourceTypeShape::Pointer(inner) => {
                child1 = Some(*inner);
                1
            }
            GoSourceTypeShape::Slice(inner) => {
                child1 = Some(*inner);
                2
            }
            GoSourceTypeShape::Array {
                element,
                length,
                length_text,
            } => {
                child1 = Some(*element);
                occurrence = Some(*length);
                text = Some(length_text);
                3
            }
            GoSourceTypeShape::ImplicitArray { element, text: raw } => {
                child1 = Some(*element);
                text = raw.as_deref();
                4
            }
            GoSourceTypeShape::Map { key, value } => {
                child1 = Some(*key);
                child2 = Some(*value);
                5
            }
            GoSourceTypeShape::Channel {
                direction: channel,
                element,
            } => {
                child1 = Some(*element);
                direction = Some(match channel {
                    GoChannelDirection::Both => 0,
                    GoChannelDirection::Receive => 1,
                    GoChannelDirection::Send => 2,
                });
                6
            }
            GoSourceTypeShape::Generic {
                base,
                arguments,
                argument_list,
                argument_text,
            } => {
                child1 = Some(*base);
                children = arguments;
                occurrence = Some(*argument_list);
                text = argument_text.as_deref();
                7
            }
            GoSourceTypeShape::Compound {
                kind,
                children: members,
            } => {
                children = members;
                match kind {
                    GoTypeCompoundKind::Parenthesized => 8,
                    GoTypeCompoundKind::Element => 9,
                    GoTypeCompoundKind::Constraint => 10,
                }
            }
            GoSourceTypeShape::Negated(inner) => {
                child1 = Some(*inner);
                11
            }
            GoSourceTypeShape::Struct { text: raw } => {
                text = raw.as_deref();
                12
            }
            GoSourceTypeShape::Interface {
                text: raw,
                has_named_children: has_children,
            } => {
                text = raw.as_deref();
                has_named_children = Some(*has_children);
                13
            }
            GoSourceTypeShape::Opaque { text: raw } => {
                text = raw.as_deref();
                14
            }
        };
        types.execute(params![
            blob_id,
            usize_to_i64(index)?,
            fact.occurrence.get(),
            kind,
            child1.map(GoSourceTypeId::get),
            child2.map(GoSourceTypeId::get),
            occurrence.map(|id| id.get()),
            text,
            direction,
            has_named_children
        ])?;
        for (ordinal, name) in name_parts.iter().enumerate() {
            names.execute(params![
                blob_id,
                usize_to_i64(index)?,
                usize_to_i64(ordinal)?,
                name
            ])?;
        }
        for (ordinal, child) in children.iter().enumerate() {
            check_cancelled(cancellation)?;
            edges.execute(params![
                blob_id,
                usize_to_i64(index)?,
                usize_to_i64(ordinal)?,
                child.get()
            ])?;
        }
    }
    drop((types, names, edges));
    let mut statement = tx.prepare_cached(
        "INSERT INTO source_go_type_declarations
        (blob_id, declaration_id, name, type_id, file_scope) VALUES(?1, ?2, ?3, ?4, ?5)",
    )?;
    for fact in &facts.declarations {
        check_cancelled(cancellation)?;
        statement.execute(params![
            blob_id,
            fact.declaration.get(),
            fact.name,
            fact.ty.get(),
            fact.file_scope
        ])?;
    }
    drop(statement);
    let mut statement = tx.prepare_cached(
        "INSERT INTO source_go_aliases
        (blob_id, declaration_id, name, target_type_id) VALUES(?1, ?2, ?3, ?4)",
    )?;
    for fact in &facts.aliases {
        check_cancelled(cancellation)?;
        statement.execute(params![
            blob_id,
            fact.declaration.get(),
            fact.name,
            fact.target.map(GoSourceTypeId::get)
        ])?;
    }
    drop(statement);
    let mut statement = tx.prepare_cached("INSERT INTO source_go_fields
        (blob_id, declaration_id, owner_type_id, type_id, name, embedded) VALUES(?1, ?2, ?3, ?4, ?5, ?6)")?;
    for fact in &facts.fields {
        check_cancelled(cancellation)?;
        statement.execute(params![
            blob_id,
            fact.declaration.get(),
            fact.owner.get(),
            fact.ty.map(GoSourceTypeId::get),
            fact.name,
            fact.embedded
        ])?;
    }
    drop(statement);
    let mut statement = tx.prepare_cached(
        "INSERT INTO source_go_callables
        (blob_id, declaration_id, name, owner_type_id, receiver_type_id, is_method,
         parameters_present, result_occurrence_id, body_occurrence_id, file_scope)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
    )?;
    let mut parameters = tx.prepare_cached("INSERT INTO source_go_callable_parameters
        (blob_id, declaration_id, result, ordinal, group_occurrence_id, name_occurrence_id, type_id, variadic)
        VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)")?;
    for fact in &facts.callables {
        check_cancelled(cancellation)?;
        statement.execute(params![
            blob_id,
            fact.declaration.get(),
            fact.name,
            fact.owner.map(GoSourceTypeId::get),
            fact.receiver.map(GoSourceTypeId::get),
            fact.is_method,
            fact.parameters.is_some(),
            fact.result.map(|id| id.get()),
            fact.body.map(|id| id.get()),
            fact.file_scope
        ])?;
        for (result, list) in [
            (false, fact.parameters.as_deref().unwrap_or_default()),
            (true, fact.results.as_slice()),
        ] {
            for (ordinal, parameter) in list.iter().enumerate() {
                check_cancelled(cancellation)?;
                parameters.execute(params![
                    blob_id,
                    fact.declaration.get(),
                    result,
                    usize_to_i64(ordinal)?,
                    parameter.group.get(),
                    parameter.name.map(|id| id.get()),
                    parameter.ty.map(GoSourceTypeId::get),
                    parameter.variadic
                ])?;
            }
        }
    }
    drop((statement, parameters));
    let mut statement = tx.prepare_cached(
        "INSERT INTO source_go_embeddings
        (blob_id, ordinal, owner_type_id, occurrence_id, type_id) VALUES(?1, ?2, ?3, ?4, ?5)",
    )?;
    for (ordinal, fact) in facts.embeddings.iter().enumerate() {
        check_cancelled(cancellation)?;
        statement.execute(params![
            blob_id,
            usize_to_i64(ordinal)?,
            fact.owner.get(),
            fact.occurrence.get(),
            fact.ty.get()
        ])?;
    }
    drop(statement);
    let (rows, bytes) = cost(facts);
    tx.execute(
        "INSERT INTO source_go_manifests(
           blob_id, facts_version, logical_rows, payload_bytes, membership_digest,
           has_build_constraints, build_selection_facts_version
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            blob_id,
            GO_SOURCE_FACTS_VERSION,
            usize_to_i64(rows)?,
            usize_to_i64(bytes)?,
            facts.membership_digest.as_ref().map(<[u8; 32]>::as_slice),
            facts.has_build_constraints.unwrap_or(false),
            facts
                .has_build_constraints
                .map_or(0, |_| GO_BUILD_SELECTION_FACTS_VERSION)
        ],
    )?;
    Ok(())
}
