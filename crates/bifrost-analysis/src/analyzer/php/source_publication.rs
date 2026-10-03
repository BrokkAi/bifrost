//! Relational publication of source-owned PHP declaration facts.

use brokk_bifrost_core::analyzer::parsed_file::ParsedSourceFacts;
use brokk_bifrost_core::analyzer::php_facts::*;
use rusqlite::{Transaction, params};

use crate::CancellationToken;
use crate::analyzer::store::source_facts::check_cancelled;
use crate::analyzer::store::{Result, SourceFactStorage, usize_to_i64};

pub(crate) static SOURCE_STORAGE: SourceFactStorage = SourceFactStorage {
    cost: |source| source.php.as_ref().map(cost),
    insert,
};

pub(crate) fn cost(facts: &PhpSourceFacts) -> (usize, usize) {
    let nominal_rows = facts
        .declarations
        .iter()
        .map(|declaration| match &declaration.declared_type {
            PhpDeclaredSourceType::Nominal(arms) => arms.len(),
            _ => 0,
        })
        .sum::<usize>();
    let supertype_rows = facts
        .declarations
        .iter()
        .map(|declaration| declaration.supertypes.len())
        .sum::<usize>();
    let write_nominal_rows = facts
        .writes
        .iter()
        .map(|write| match &write.value_type {
            PhpDeclaredSourceType::Nominal(arms) => arms.len(),
            _ => 0,
        })
        .sum::<usize>();
    let context_alias_rows = facts
        .contexts
        .iter()
        .map(|context| context.aliases.len())
        .sum::<usize>();
    let rows = 1
        + facts.contexts.len()
        + facts.aliases.len()
        + context_alias_rows
        + facts.declarations.len()
        + nominal_rows
        + supertype_rows
        + facts.writes.len()
        + write_nominal_rows;
    let bytes = facts
        .contexts
        .iter()
        .map(|context| context.namespace.len())
        .sum::<usize>()
        + facts
            .declarations
            .iter()
            .map(|declaration| {
                declaration.doc_nominal_type.as_ref().map_or(0, String::len)
                    + declaration.doc_element_type.as_ref().map_or(0, String::len)
                    + declaration
                        .supertypes
                        .iter()
                        .map(String::len)
                        .sum::<usize>()
                    + match &declaration.declared_type {
                        PhpDeclaredSourceType::Nominal(arms) => {
                            arms.iter().map(String::len).sum::<usize>()
                        }
                        _ => 0,
                    }
            })
            .sum::<usize>()
        + facts
            .writes
            .iter()
            .map(|write| {
                write.field.len()
                    + write.doc_element_type.as_ref().map_or(0, String::len)
                    + match &write.value_type {
                        PhpDeclaredSourceType::Nominal(arms) => {
                            arms.iter().map(String::len).sum::<usize>()
                        }
                        _ => 0,
                    }
            })
            .sum::<usize>();
    (rows, bytes)
}

fn declaration_kind(kind: PhpDeclarationKind) -> i64 {
    match kind {
        PhpDeclarationKind::Class => 0,
        PhpDeclarationKind::Interface => 1,
        PhpDeclarationKind::Trait => 2,
        PhpDeclarationKind::Enum => 3,
        PhpDeclarationKind::Function => 4,
        PhpDeclarationKind::Method => 5,
        PhpDeclarationKind::Property => 6,
        PhpDeclarationKind::Constant => 7,
        PhpDeclarationKind::EnumCase => 8,
        PhpDeclarationKind::PromotedProperty => 9,
    }
}

fn alias_kind(kind: PhpAliasKind) -> i64 {
    match kind {
        PhpAliasKind::Type => 0,
        PhpAliasKind::Function => 1,
        PhpAliasKind::Constant => 2,
    }
}

fn type_kind(ty: &PhpDeclaredSourceType) -> i64 {
    match ty {
        PhpDeclaredSourceType::Unknown => 0,
        PhpDeclaredSourceType::Nominal(_) => 1,
        PhpDeclaredSourceType::DynamicObject => 2,
        PhpDeclaredSourceType::DynamicMixed => 3,
        PhpDeclaredSourceType::SelfType => 4,
        PhpDeclaredSourceType::StaticType => 5,
        PhpDeclaredSourceType::ParentType => 6,
    }
}

fn write_kind(kind: PhpFieldWriteKind) -> i64 {
    match kind {
        PhpFieldWriteKind::Instance => 0,
        PhpFieldWriteKind::Static => 1,
        PhpFieldWriteKind::Indexed => 2,
    }
}

fn insert(
    tx: &Transaction<'_>,
    blob_id: i64,
    source: &ParsedSourceFacts,
    cancellation: &CancellationToken,
) -> Result<()> {
    let Some(facts) = &source.php else {
        return Ok(());
    };
    assert!(
        facts.valid_links(&source.occurrences, &source.imports),
        "invalid PHP source links: {facts:?}"
    );

    let mut contexts = tx.prepare_cached(
        "INSERT INTO source_php_contexts(blob_id, context_id, namespace)
         VALUES(?1, ?2, ?3)",
    )?;
    for (index, context) in facts.contexts.iter().enumerate() {
        check_cancelled(cancellation)?;
        contexts.execute(params![blob_id, usize_to_i64(index)?, context.namespace])?;
    }
    drop(contexts);

    let mut aliases = tx.prepare_cached(
        "INSERT INTO source_php_aliases(blob_id, alias_id, source_import_id, kind)
         VALUES(?1, ?2, ?3, ?4)",
    )?;
    for (index, alias) in facts.aliases.iter().enumerate() {
        check_cancelled(cancellation)?;
        aliases.execute(params![
            blob_id,
            usize_to_i64(index)?,
            alias.import.get(),
            alias_kind(alias.kind),
        ])?;
    }
    drop(aliases);

    let mut context_aliases = tx.prepare_cached(
        "INSERT INTO source_php_context_aliases(blob_id, context_id, ordinal, alias_id)
         VALUES(?1, ?2, ?3, ?4)",
    )?;
    for (context_id, context) in facts.contexts.iter().enumerate() {
        for (ordinal, alias_id) in context.aliases.iter().enumerate() {
            check_cancelled(cancellation)?;
            context_aliases.execute(params![
                blob_id,
                usize_to_i64(context_id)?,
                usize_to_i64(ordinal)?,
                *alias_id,
            ])?;
        }
    }
    drop(context_aliases);

    let mut declarations = tx.prepare_cached(
        "INSERT INTO source_php_declarations(blob_id, declaration_id, kind, context_id,
            declared_type_occurrence_id, declared_type_kind, class_parent_ordinal, has_trait_use,
            doc_nominal_type, doc_element_type) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
    )?;
    let mut nominal_arms = tx.prepare_cached(
        "INSERT INTO source_php_nominal_arms(blob_id, declaration_id, ordinal, arm)
         VALUES(?1, ?2, ?3, ?4)",
    )?;
    let mut supertypes = tx.prepare_cached(
        "INSERT INTO source_php_supertypes(blob_id, declaration_id, ordinal, supertype)
         VALUES(?1, ?2, ?3, ?4)",
    )?;
    for declaration in &facts.declarations {
        check_cancelled(cancellation)?;
        let declaration_id = declaration.declaration.get();
        let class_parent_ordinal = declaration.class_parent.as_ref().map(|parent| {
            declaration
                .supertypes
                .iter()
                .position(|supertype| supertype == parent)
                .expect("PHP class parent must be present in the canonical supertype rows")
        });
        declarations.execute(params![
            blob_id,
            declaration_id,
            declaration_kind(declaration.kind),
            declaration.context.get(),
            declaration.declared_type_occurrence.map(|id| id.get()),
            type_kind(&declaration.declared_type),
            class_parent_ordinal.map(usize_to_i64).transpose()?,
            declaration.has_trait_use,
            declaration.doc_nominal_type,
            declaration.doc_element_type,
        ])?;
        if let PhpDeclaredSourceType::Nominal(arms) = &declaration.declared_type {
            for (ordinal, arm) in arms.iter().enumerate() {
                check_cancelled(cancellation)?;
                nominal_arms.execute(params![
                    blob_id,
                    declaration_id,
                    usize_to_i64(ordinal)?,
                    arm
                ])?;
            }
        }
        for (ordinal, supertype) in declaration.supertypes.iter().enumerate() {
            check_cancelled(cancellation)?;
            supertypes.execute(params![
                blob_id,
                declaration_id,
                usize_to_i64(ordinal)?,
                supertype
            ])?;
        }
    }
    drop((declarations, nominal_arms, supertypes));

    let mut writes = tx.prepare_cached(
        "INSERT INTO source_php_writes(blob_id, ordinal, occurrence_id, class_declaration_id,
            field, kind, directly_in_constructor, value_type_kind, doc_element_type)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    )?;
    let mut write_arms = tx.prepare_cached(
        "INSERT INTO source_php_write_nominal_arms(blob_id, write_ordinal, ordinal, arm)
         VALUES(?1, ?2, ?3, ?4)",
    )?;
    for (ordinal, write) in facts.writes.iter().enumerate() {
        check_cancelled(cancellation)?;
        let write_ordinal = usize_to_i64(ordinal)?;
        writes.execute(params![
            blob_id,
            write_ordinal,
            write.occurrence.get(),
            write.class.get(),
            write.field,
            write_kind(write.kind),
            write.directly_in_constructor,
            type_kind(&write.value_type),
            write.doc_element_type,
        ])?;
        if let PhpDeclaredSourceType::Nominal(arms) = &write.value_type {
            for (arm_ordinal, arm) in arms.iter().enumerate() {
                check_cancelled(cancellation)?;
                write_arms.execute(params![
                    blob_id,
                    write_ordinal,
                    usize_to_i64(arm_ordinal)?,
                    arm,
                ])?;
            }
        }
    }
    drop((writes, write_arms));

    let (rows, bytes) = cost(facts);
    tx.execute(
        "INSERT INTO source_php_manifests(blob_id, facts_version, logical_rows, payload_bytes)
         VALUES(?1, ?2, ?3, ?4)",
        params![
            blob_id,
            PHP_SOURCE_FACTS_VERSION,
            usize_to_i64(rows)?,
            usize_to_i64(bytes)?,
        ],
    )?;
    Ok(())
}
