//! Single-snapshot readback for canonical Rust hierarchy inputs.
//!
//! This reader deliberately hydrates only the normalized rows.  It does not
//! load source text or the complete occurrence arena, and it never rebuilds
//! identity from names or ranges.

use git2::Oid;
use rusqlite::{OptionalExtension, params};

use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::rust_facts::{
    MacroFragmentKind, MacroIdentRole, RustAliasSourceFact, RustCallableParameterSourceFact,
    RustCallableSourceFact, RustDeclarationGenericsSourceFact, RustGenericArgumentsSourceFact,
    RustGenericParameterSourceFact, RustImplSourceFact, RustItemBodyChildSourceFact,
    RustItemImportContextFact, RustItemMacroExpansion, RustItemMacroSourceFact,
    RustItemMacroSourcePosition, RustItemSourceFacts, RustItemSyntaxFact, RustMacroArmSourceFact,
    RustMacroDefinitionSourceFact, RustMacroDelimiter, RustMacroIdentRoleSourceFact,
    RustMacroParseFailure, RustMacroPatternSourceFact, RustMacroPatternSourceKind,
    RustMacroRepetitionOperator, RustSourceContextFact, RustSourceContextKind, RustSourceNameFact,
    RustTraitSourceFact, RustTypeCompoundSourceKind, RustTypePathSegmentSourceFact,
    RustTypeSourceFact, RustTypeSourceShape, RustTypeWrapperSourceFact, RustTypeWrapperSourceKind,
    RustValueSourceFact,
};
use brokk_bifrost_core::analyzer::source_facts::{
    SourceDeclaration, SourceDeclarationId, SourceOccurrenceId,
};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use brokk_bifrost_rust::hierarchy::RustHierarchySourceFacts;

use crate::analyzer::LanguageAdapter;
use crate::analyzer::rust::source_publication::{
    RUST_ITEM_SOURCE_FACTS_VERSION, RUST_MACRO_CONTEXTS_VERSION, RUST_MACRO_FACTS_VERSION,
    RUST_TYPE_FORMS_VERSION, rust_item_source_cost,
};
use crate::analyzer::store::source_facts::{
    SOURCE_DECLARATION_UNITS_SQL, SOURCE_FACTS_VERSION, nonnegative_usize, read_source_imports,
    source_occurrence, strict_bool,
};
use crate::analyzer::store::{
    AnalyzerStore, GenerationId, Result, StoreError, read_source_unit_map,
};

fn source_declaration(value: i64, label: &str) -> Result<SourceDeclarationId> {
    let value = u32::try_from(value)
        .map_err(|_| StoreError::new(format!("invalid {label} source declaration id {value}")))?;
    Ok(SourceDeclarationId::new(value))
}

fn context_kind(value: i64) -> Result<RustSourceContextKind> {
    match value {
        0 => Ok(RustSourceContextKind::FileRoot),
        1 => Ok(RustSourceContextKind::Module),
        2 => Ok(RustSourceContextKind::Trait),
        3 => Ok(RustSourceContextKind::Impl),
        4 => Ok(RustSourceContextKind::Function),
        5 => Ok(RustSourceContextKind::Block),
        6 => Ok(RustSourceContextKind::DeclarationBody),
        7 => Ok(RustSourceContextKind::Type),
        _ => Err(StoreError::new(format!(
            "invalid Rust source context kind {value}"
        ))),
    }
}

/// Where the item-position invocation `invocation` in blob `blob_id` expands
/// to, read from declaration replay's rows: the invocation's item context and
/// that context's parent. An invocation with no expansion row is not in item
/// position, so its items (if any) are lexical where it stands.
fn rust_macro_item_container(
    conn: &rusqlite::Connection,
    blob_id: i64,
    invocation: brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceId,
) -> Result<brokk_bifrost_rust::macro_matcher::RustMacroItemContainer> {
    let kinds = conn
        .prepare_cached(
            "SELECT context.context_kind, parent.context_kind
               FROM source_rust_item_macro_expansions AS expansion
               JOIN source_rust_item_contexts AS context
                 ON context.blob_id = expansion.blob_id
                AND context.occurrence_id = expansion.context_occurrence_id
               LEFT JOIN source_rust_item_contexts AS parent
                 ON parent.blob_id = context.blob_id
                AND parent.occurrence_id = context.parent_occurrence_id
              WHERE expansion.blob_id = ?1 AND expansion.invocation_occurrence_id = ?2",
        )?
        .query_row(params![blob_id, invocation.get()], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?))
        })
        .optional()?;
    let Some((context, parent)) = kinds else {
        return Ok(brokk_bifrost_rust::macro_matcher::RustMacroItemContainer::Lexical);
    };
    Ok(
        brokk_bifrost_rust::macro_matcher::RustMacroItemContainer::of_expansion_context(
            context_kind(context)?,
            parent.map(context_kind).transpose()?,
        ),
    )
}

fn wrapper_kind(value: i64) -> Result<RustTypeWrapperSourceKind> {
    match value {
        0 => Ok(RustTypeWrapperSourceKind::Reference),
        1 => Ok(RustTypeWrapperSourceKind::Pointer),
        2 => Ok(RustTypeWrapperSourceKind::Array),
        3 => Ok(RustTypeWrapperSourceKind::Slice),
        _ => Err(StoreError::new(format!(
            "invalid Rust type wrapper kind {value}"
        ))),
    }
}

fn macro_fragment_kind(value: i64) -> Result<MacroFragmentKind> {
    match value {
        0 => Ok(MacroFragmentKind::Ident),
        1 => Ok(MacroFragmentKind::Path),
        2 => Ok(MacroFragmentKind::Expr),
        3 => Ok(MacroFragmentKind::Ty),
        4 => Ok(MacroFragmentKind::Pat),
        5 => Ok(MacroFragmentKind::Stmt),
        6 => Ok(MacroFragmentKind::Block),
        7 => Ok(MacroFragmentKind::Item),
        8 => Ok(MacroFragmentKind::Meta),
        9 => Ok(MacroFragmentKind::Tt),
        10 => Ok(MacroFragmentKind::Vis),
        11 => Ok(MacroFragmentKind::Lifetime),
        12 => Ok(MacroFragmentKind::Literal),
        _ => Err(StoreError::new(format!(
            "invalid Rust macro fragment kind {value}"
        ))),
    }
}

fn macro_ident_role(value: i64) -> Result<MacroIdentRole> {
    match value {
        0 => Ok(MacroIdentRole::Type),
        1 => Ok(MacroIdentRole::Value),
        2 => Ok(MacroIdentRole::Pattern),
        3 => Ok(MacroIdentRole::Declaration),
        4 => Ok(MacroIdentRole::Mixed),
        5 => Ok(MacroIdentRole::Unused),
        6 => Ok(MacroIdentRole::Undetermined),
        _ => Err(StoreError::new(format!(
            "invalid Rust macro ident role {value}"
        ))),
    }
}

fn macro_delimiter(value: i64) -> Result<RustMacroDelimiter> {
    match value {
        0 => Ok(RustMacroDelimiter::Parenthesis),
        1 => Ok(RustMacroDelimiter::Bracket),
        2 => Ok(RustMacroDelimiter::Brace),
        _ => Err(StoreError::new(format!(
            "invalid Rust macro delimiter {value}"
        ))),
    }
}

fn macro_repetition_operator(value: i64) -> Result<RustMacroRepetitionOperator> {
    match value {
        0 => Ok(RustMacroRepetitionOperator::Star),
        1 => Ok(RustMacroRepetitionOperator::Plus),
        2 => Ok(RustMacroRepetitionOperator::Optional),
        _ => Err(StoreError::new(format!(
            "invalid Rust macro repetition operator {value}"
        ))),
    }
}

fn macro_expansion(kind: i64, root: Option<SourceOccurrenceId>) -> Result<RustItemMacroExpansion> {
    match kind {
        0 => root.map(RustItemMacroExpansion::Parsed).ok_or_else(|| {
            StoreError::new("parsed Rust item macro expansion has no root occurrence")
        }),
        1 => {
            if root.is_some() {
                return Err(StoreError::new(
                    "empty Rust item macro expansion has a root occurrence",
                ));
            }
            Ok(RustItemMacroExpansion::EmptyInterior)
        }
        2 => {
            if root.is_some() {
                return Err(StoreError::new(
                    "missing-interior Rust item macro expansion has a root occurrence",
                ));
            }
            Ok(RustItemMacroExpansion::Unavailable(
                RustMacroParseFailure::MissingInterior,
            ))
        }
        3 => {
            if root.is_some() {
                return Err(StoreError::new(
                    "unavailable Rust item macro expansion has a root occurrence",
                ));
            }
            Ok(RustItemMacroExpansion::Unavailable(
                RustMacroParseFailure::ParseUnavailable,
            ))
        }
        4 => {
            if root.is_some() {
                return Err(StoreError::new(
                    "unrequested Rust item macro expansion has a root occurrence",
                ));
            }
            Ok(RustItemMacroExpansion::NotRequested)
        }
        _ => Err(StoreError::new(format!(
            "invalid Rust item macro expansion kind {kind}"
        ))),
    }
}

fn require_context(
    contexts: &[RustSourceContextFact],
    indices: &HashMap<SourceOccurrenceId, usize>,
    context: SourceOccurrenceId,
    label: &str,
) -> Result<usize> {
    indices.get(&context).copied().ok_or_else(|| {
        StoreError::new(format!(
            "Rust item {label} references missing context {context:?}; contexts={contexts:?}"
        ))
    })
}

fn require_owned_context(
    contexts: &[RustSourceContextFact],
    context_indices: &HashMap<SourceOccurrenceId, usize>,
    owner_context_indices: &HashMap<SourceDeclarationId, usize>,
    owner: SourceDeclarationId,
    containing_context: SourceOccurrenceId,
    expected: RustSourceContextKind,
    label: &str,
) -> Result<usize> {
    let containing_index = require_context(contexts, context_indices, containing_context, label)?;
    let Some(own_index) = owner_context_indices.get(&owner).copied() else {
        return Err(StoreError::new(format!(
            "Rust item {label} has no owned context for declaration {owner:?}; contexts={contexts:?}"
        )));
    };
    let own_context = &contexts[own_index];
    if own_context.kind != expected || own_context.parent != Some(containing_context) {
        return Err(StoreError::new(format!(
            "Rust item {label} owned context is inconsistent: declaration={owner:?}, containing={containing_context:?}, expected_kind={expected:?}, own_context={own_context:?}, contexts={contexts:?}"
        )));
    }
    Ok(containing_index)
}

fn require_type(
    types: &[RustTypeSourceFact],
    indices: &HashMap<SourceOccurrenceId, usize>,
    occurrence: SourceOccurrenceId,
    label: &str,
) -> Result<usize> {
    indices.get(&occurrence).copied().ok_or_else(|| {
        StoreError::new(format!(
            "Rust item {label} references missing type {occurrence:?}; types={types:?}"
        ))
    })
}

fn require_dense_ordinal(ordinal: i64, expected: usize, label: &str) -> Result<usize> {
    let ordinal = nonnegative_usize(ordinal, label)?;
    if ordinal != expected {
        return Err(StoreError::new(format!(
            "Rust item {label} ordinal {ordinal} is not dense at {expected}"
        )));
    }
    Ok(ordinal)
}

impl AnalyzerStore {
    /// Hydrate source-owned items, types, imports, and declarations together
    /// with their mounted CodeUnit links for one current published blob.
    /// The item marker is part of the publication witness: a
    /// complete legacy Rust blob without schema54's marker is an error, never
    /// an empty item inventory.
    pub(crate) fn rust_hierarchy_source_facts<A: LanguageAdapter>(
        &self,
        oid: Oid,
        generation: GenerationId,
        adapter: &A,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Option<RustHierarchySourceFacts>> {
        if !keep_going() {
            return Ok(None);
        }

        self.read_source_transaction("rust", generation, |tx| {
            if !keep_going() {
                return Ok(None);
            }

            let oid_text = oid.to_string();
            type RustPublicationHeader = (i64, i64, i64, Option<i64>, i64, Option<i64>, Option<i64>);
            let witness: Option<RustPublicationHeader> = tx
                .query_row(
                    "SELECT keys.blob_id, item.logical_rows, item.payload_bytes,
                            item.macro_facts_version, module.root_occurrence_id, item.type_forms_version,
                            item.macro_contexts_version
                       FROM rust_published_fact_blobs AS keys
                       JOIN source_fact_manifests AS manifest
                         ON manifest.blob_id = keys.blob_id
                       JOIN source_rust_item_manifests AS item
                         ON item.blob_id = keys.blob_id
                       JOIN source_rust_module_manifests AS module
                         ON module.blob_id = keys.blob_id
                      WHERE keys.blob_oid = ?1 AND keys.lang = 'rust'
                        AND keys.generation = ?2
                        AND manifest.publication_state = 'complete'
                        AND manifest.facts_version = ?3
                        AND item.facts_version = ?4",
                    params![
                        oid_text,
                        generation.get(),
                        SOURCE_FACTS_VERSION,
                        RUST_ITEM_SOURCE_FACTS_VERSION,
                    ],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                        ))
                    },
                )
                .optional()?;
            let Some((
                blob_id,
                expected_rows,
                expected_payload,
                macro_facts_version,
                root_value,
                type_forms_version,
                macro_contexts_version,
            )) = witness
            else {
                return Err(StoreError::new(format!(
                    "published Rust blob {oid} has no complete Rust item/type marker"
                )));
            };
            if macro_facts_version != Some(RUST_MACRO_FACTS_VERSION) {
                return Err(StoreError::new(format!(
                    "published Rust blob {oid} has unavailable macro source facts marker {macro_facts_version:?}"
                )));
            }
            if type_forms_version != Some(RUST_TYPE_FORMS_VERSION) {
                return Err(StoreError::new(format!(
                    "published Rust blob {oid} has unavailable compound type facts marker {type_forms_version:?}"
                )));
            }
            if macro_contexts_version != Some(RUST_MACRO_CONTEXTS_VERSION) {
                return Err(StoreError::new(format!(
                    "published Rust blob {oid} has unavailable macro context facts marker {macro_contexts_version:?}"
                )));
            }
            let expected_rows = nonnegative_usize(expected_rows, "item logical_rows")?;
            let expected_payload = nonnegative_usize(expected_payload, "item payload_bytes")?;
            let expected_root = source_occurrence(root_value, "module root")?;

            if !keep_going() {
                return Ok(None);
            }

            let mut syntax = Vec::new();
            let mut syntax_indices = HashMap::default();
            let mut statement = tx.prepare_cached(
                "SELECT occurrence_id, has_error
                   FROM source_rust_item_syntax
                  WHERE blob_id = ?1 ORDER BY occurrence_id",
            )?;
            let mut rows = statement.query(params![blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let occurrence = source_occurrence(row.get(0)?, "item syntax")?;
                if syntax_indices.insert(occurrence, syntax.len()).is_some() {
                    return Err(StoreError::new(format!(
                        "duplicate Rust item syntax occurrence {occurrence:?}; syntax={syntax:?}"
                    )));
                }
                syntax.push(RustItemSyntaxFact {
                    occurrence,
                    has_error: strict_bool(row.get(1)?, "item syntax has_error")?,
                });
            }
            drop(rows);
            drop(statement);

            let mut contexts = Vec::new();
            let mut context_indices = HashMap::default();
            let mut statement = tx.prepare_cached(
                "SELECT occurrence_id, ordinal, parent_occurrence_id,
                        owner_declaration_id, context_kind
                   FROM source_rust_item_contexts
                  WHERE blob_id = ?1 ORDER BY ordinal",
            )?;
            let mut rows = statement.query(params![blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let ordinal = require_dense_ordinal(row.get(1)?, contexts.len(), "context")?;
                let context = source_occurrence(row.get(0)?, "context")?;
                let parent = row
                    .get::<_, Option<i64>>(2)?
                    .map(|value| source_occurrence(value, "context parent"))
                    .transpose()?;
                let owner = row
                    .get::<_, Option<i64>>(3)?
                    .map(|value| source_declaration(value, "context owner"))
                    .transpose()?;
                let kind = context_kind(row.get(4)?)?;
                match (kind, owner) {
                    (
                        RustSourceContextKind::Module
                        | RustSourceContextKind::Trait
                        | RustSourceContextKind::Impl
                        | RustSourceContextKind::Function
                        | RustSourceContextKind::Type,
                        None,
                    ) => {
                        return Err(StoreError::new(format!(
                            "Rust source context {context:?} of kind {kind:?} has no owner"
                        )));
                    }
                    (
                        RustSourceContextKind::FileRoot
                        | RustSourceContextKind::Block
                        | RustSourceContextKind::DeclarationBody,
                        Some(owner),
                    ) => {
                        return Err(StoreError::new(format!(
                            "Rust source context {context:?} of kind {kind:?} has unexpected owner {owner:?}"
                        )));
                    }
                    _ => {}
                }
                let fact = RustSourceContextFact {
                    context,
                    parent,
                    owner,
                    kind,
                };
                if context_indices.insert(context, ordinal).is_some() {
                    return Err(StoreError::new(format!(
                        "duplicate Rust item context {context:?}; contexts={contexts:?}"
                    )));
                }
                contexts.push(fact);
            }
            drop(rows);
            drop(statement);

            if contexts.is_empty() {
                return Err(StoreError::new(
                    "schema54 Rust item marker has no context root",
                ));
            }
            let parentless = contexts.iter().filter(|row| row.parent.is_none()).count();
            if parentless != 1
                || contexts[0].context != expected_root
                || contexts[0].parent.is_some()
                || contexts[0].owner.is_some()
                || contexts[0].kind != RustSourceContextKind::FileRoot
            {
                return Err(StoreError::new(format!(
                    "invalid Rust item context root expected={expected_root:?}; contexts={contexts:?}"
                )));
            }
            for (index, context) in contexts.iter().enumerate() {
                if !syntax_indices.contains_key(&context.context) {
                    return Err(StoreError::new(format!(
                        "Rust source context has no shared syntax row: context={context:?}, syntax={syntax:?}"
                    )));
                }
                let Some(parent) = context.parent else {
                    continue;
                };
                let parent_index =
                    require_context(&contexts, &context_indices, parent, "context parent")?;
                if parent_index >= index {
                    return Err(StoreError::new(format!(
                        "Rust item context parent is not earlier: child={context:?}, parent={parent:?}, contexts={contexts:?}"
                    )));
                }
            }
            let mut owner_context_indices = HashMap::default();
            for (index, context) in contexts.iter().enumerate() {
                let Some(owner) = context.owner else {
                    continue;
                };
                if owner_context_indices.insert(owner, index).is_some() {
                    return Err(StoreError::new(format!(
                        "multiple Rust source contexts own declaration {owner:?}; contexts={contexts:?}"
                    )));
                }
            }

            let mut impls = Vec::new();
            let mut impl_indices = HashMap::default();
            let mut statement = tx.prepare_cached(
                "SELECT declaration_id, context_occurrence_id, trait_type_occurrence_id,
                        negation_occurrence_id, target_type_occurrence_id, body_occurrence_id
                   FROM source_rust_impl_items
                  WHERE blob_id = ?1 ORDER BY declaration_id",
            )?;
            let mut rows = statement.query(params![blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let declaration = source_declaration(row.get(0)?, "impl")?;
                let context = source_occurrence(row.get(1)?, "impl context")?;
                require_owned_context(
                    &contexts,
                    &context_indices,
                    &owner_context_indices,
                    declaration,
                    context,
                    RustSourceContextKind::Impl,
                    "impl",
                )?;
                if impl_indices.insert(declaration, impls.len()).is_some() {
                    return Err(StoreError::new(format!(
                        "duplicate Rust impl declaration {declaration:?}; impls={impls:?}"
                    )));
                }
                impls.push(RustImplSourceFact {
                    declaration,
                    context,
                    trait_type: row
                        .get::<_, Option<i64>>(2)?
                        .map(|value| source_occurrence(value, "impl trait type"))
                        .transpose()?,
                    negation: row
                        .get::<_, Option<i64>>(3)?
                        .map(|value| source_occurrence(value, "impl negation"))
                        .transpose()?,
                    target_type: row
                        .get::<_, Option<i64>>(4)?
                        .map(|value| source_occurrence(value, "impl target type"))
                        .transpose()?,
                    body: row
                        .get::<_, Option<i64>>(5)?
                        .map(|value| source_occurrence(value, "impl body"))
                        .transpose()?,
                    body_children: Vec::new(),
                });
            }
            drop(rows);
            drop(statement);

            let mut traits = Vec::new();
            let mut trait_indices = HashMap::default();
            let mut statement = tx.prepare_cached(
                "SELECT declaration_id, context_occurrence_id, body_occurrence_id
                   FROM source_rust_trait_items
                  WHERE blob_id = ?1 ORDER BY declaration_id",
            )?;
            let mut rows = statement.query(params![blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let declaration = source_declaration(row.get(0)?, "trait")?;
                let context = source_occurrence(row.get(1)?, "trait context")?;
                require_owned_context(
                    &contexts,
                    &context_indices,
                    &owner_context_indices,
                    declaration,
                    context,
                    RustSourceContextKind::Trait,
                    "trait",
                )?;
                if trait_indices.insert(declaration, traits.len()).is_some() {
                    return Err(StoreError::new(format!(
                        "duplicate Rust trait declaration {declaration:?}; traits={traits:?}"
                    )));
                }
                traits.push(RustTraitSourceFact {
                    declaration,
                    context,
                    body: row
                        .get::<_, Option<i64>>(2)?
                        .map(|value| source_occurrence(value, "trait body"))
                        .transpose()?,
                    body_children: Vec::new(),
                });
            }
            drop(rows);
            drop(statement);

            let mut aliases = Vec::new();
            let mut alias_indices = HashMap::default();
            let mut statement = tx.prepare_cached(
                "SELECT declaration_id, context_occurrence_id, target_type_occurrence_id
                   FROM source_rust_alias_items
                  WHERE blob_id = ?1 ORDER BY declaration_id",
            )?;
            let mut rows = statement.query(params![blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let declaration = source_declaration(row.get(0)?, "alias")?;
                let context = source_occurrence(row.get(1)?, "alias context")?;
                require_context(&contexts, &context_indices, context, "alias")?;
                if alias_indices.insert(declaration, aliases.len()).is_some() {
                    return Err(StoreError::new(format!(
                        "duplicate Rust alias declaration {declaration:?}; aliases={aliases:?}"
                    )));
                }
                aliases.push(RustAliasSourceFact {
                    declaration,
                    context,
                    target_type: row
                        .get::<_, Option<i64>>(2)?
                        .map(|value| source_occurrence(value, "alias target type"))
                        .transpose()?,
                });
            }
            drop(rows);
            drop(statement);

            let mut callables = Vec::new();
            let mut callable_indices = HashMap::default();
            let mut statement = tx.prepare_cached(
                "SELECT declaration_id, context_occurrence_id, parameters_occurrence_id,
                        return_type_occurrence_id
                   FROM source_rust_callable_items
                  WHERE blob_id = ?1 ORDER BY declaration_id",
            )?;
            let mut rows = statement.query(params![blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let declaration = source_declaration(row.get(0)?, "callable")?;
                let context = source_occurrence(row.get(1)?, "callable context")?;
                require_owned_context(
                    &contexts,
                    &context_indices,
                    &owner_context_indices,
                    declaration,
                    context,
                    RustSourceContextKind::Function,
                    "callable",
                )?;
                if callable_indices
                    .insert(declaration, callables.len())
                    .is_some()
                {
                    return Err(StoreError::new(format!(
                        "duplicate Rust callable declaration {declaration:?}; callables={callables:?}"
                    )));
                }
                callables.push(RustCallableSourceFact {
                    declaration,
                    context,
                    parameters: row
                        .get::<_, Option<i64>>(2)?
                        .map(|value| source_occurrence(value, "callable parameters"))
                        .transpose()?,
                    parameter_children: Vec::new(),
                    return_type: row
                        .get::<_, Option<i64>>(3)?
                        .map(|value| source_occurrence(value, "callable return type"))
                        .transpose()?,
                });
            }
            drop(rows);
            drop(statement);

            let mut values = Vec::new();
            let mut statement = tx.prepare_cached(
                "SELECT declaration_id, context_occurrence_id, declared_type_occurrence_id
                   FROM source_rust_value_items
                  WHERE blob_id = ?1 ORDER BY declaration_id",
            )?;
            let mut rows = statement.query(params![blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let declaration = source_declaration(row.get(0)?, "value")?;
                let context = source_occurrence(row.get(1)?, "value context")?;
                require_context(&contexts, &context_indices, context, "value")?;
                values.push(RustValueSourceFact {
                    declaration,
                    context,
                    declared_type: row
                        .get::<_, Option<i64>>(2)?
                        .map(|value| source_occurrence(value, "value declared type"))
                        .transpose()?,
                });
            }
            drop(rows);
            drop(statement);

            let mut generics = Vec::<RustDeclarationGenericsSourceFact>::new();
            let mut statement = tx.prepare_cached(
                "SELECT declaration_id, ordinal, occurrence_id, syntax_kind,
                        name_occurrence_id, name
                   FROM source_rust_item_generic_parameters
                  WHERE blob_id = ?1 ORDER BY declaration_id, ordinal",
            )?;
            let mut rows = statement.query(params![blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let declaration = source_declaration(row.get(0)?, "generic parameter owner")?;
                let parameter = RustGenericParameterSourceFact {
                    occurrence: source_occurrence(row.get(2)?, "generic parameter")?,
                    kind: row.get(3)?,
                    name: match (
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                    ) {
                        (None, None) => None,
                        (Some(occurrence), Some(name)) => Some(RustSourceNameFact {
                            occurrence: source_occurrence(occurrence, "generic parameter name")?,
                            name,
                        }),
                        pair => {
                            return Err(StoreError::new(format!(
                                "incomplete Rust generic parameter name {pair:?}"
                            )));
                        }
                    },
                };
                if generics.last().map(|group| group.declaration) != Some(declaration) {
                    let owner_context = owner_context_indices.get(&declaration).copied()
                        .ok_or_else(|| StoreError::new(format!(
                            "Rust generic parameter has no owner context: declaration={declaration:?}; contexts={contexts:?}"
                        )))?;
                    if !matches!(
                        contexts[owner_context].kind,
                        RustSourceContextKind::Impl
                            | RustSourceContextKind::Trait
                            | RustSourceContextKind::Function
                            | RustSourceContextKind::Type
                    ) {
                        return Err(StoreError::new(format!(
                            "Rust generic parameter has invalid owner context: declaration={declaration:?}; context={:?}",
                            contexts[owner_context]
                        )));
                    }
                    generics.push(RustDeclarationGenericsSourceFact {
                        declaration,
                        parameters: Vec::new(),
                    });
                }
                let group = generics
                    .last_mut()
                    .expect("the parameter owner group was created");
                require_dense_ordinal(
                    row.get(1)?,
                    group.parameters.len(),
                    "declaration generic parameter",
                )?;
                group.parameters.push(parameter);
            }
            drop(rows);
            drop(statement);

            let mut statement = tx.prepare_cached(
                "SELECT owner_declaration_id, ordinal, occurrence_id,
                        declaration_id, syntax_kind
                   FROM source_rust_item_body_children
                  WHERE blob_id = ?1 ORDER BY owner_declaration_id, ordinal",
            )?;
            let mut rows = statement.query(params![blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let owner = source_declaration(row.get(0)?, "body child owner")?;
                let child = RustItemBodyChildSourceFact {
                    occurrence: source_occurrence(row.get(2)?, "body child")?,
                    declaration: row
                        .get::<_, Option<i64>>(3)?
                        .map(|value| source_declaration(value, "body child declaration"))
                        .transpose()?,
                    syntax_kind: row.get(4)?,
                };
                if !syntax_indices.contains_key(&child.occurrence) {
                    return Err(StoreError::new(format!(
                        "Rust body child has no shared syntax row {child:?}; syntax={syntax:?}"
                    )));
                }
                if let Some(index) = impl_indices.get(&owner).copied() {
                    require_dense_ordinal(
                        row.get(1)?,
                        impls[index].body_children.len(),
                        "impl body child",
                    )?;
                    impls[index].body_children.push(child);
                } else if let Some(index) = trait_indices.get(&owner).copied() {
                    require_dense_ordinal(
                        row.get(1)?,
                        traits[index].body_children.len(),
                        "trait body child",
                    )?;
                    traits[index].body_children.push(child);
                } else {
                    return Err(StoreError::new(format!(
                        "Rust body child has missing item owner {owner:?}; impls={impls:?}, traits={traits:?}"
                    )));
                }
            }
            drop(rows);
            drop(statement);

            let mut statement = tx.prepare_cached(
                "SELECT declaration_id, ordinal, occurrence_id, syntax_kind,
                        label_occurrence_id, label
                   FROM source_rust_callable_parameters
                  WHERE blob_id = ?1 ORDER BY declaration_id, ordinal",
            )?;
            let mut rows = statement.query(params![blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let owner = source_declaration(row.get(0)?, "callable parameter owner")?;
                let parameter = RustCallableParameterSourceFact {
                    occurrence: source_occurrence(row.get(2)?, "callable parameter")?,
                    syntax_kind: row.get(3)?,
                    label: match (
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                    ) {
                        (None, None) => None,
                        (Some(occurrence), Some(name)) => Some(RustSourceNameFact {
                            occurrence: source_occurrence(occurrence, "callable parameter label")?,
                            name,
                        }),
                        pair => {
                            return Err(StoreError::new(format!(
                                "incomplete Rust callable parameter label {pair:?}"
                            )));
                        }
                    },
                };
                let Some(index) = callable_indices.get(&owner).copied() else {
                    return Err(StoreError::new(format!(
                        "Rust callable parameter has missing item owner {owner:?}; callables={callables:?}"
                    )));
                };
                require_dense_ordinal(
                    row.get(1)?,
                    callables[index].parameter_children.len(),
                    "callable parameter",
                )?;
                callables[index].parameter_children.push(parameter);
            }
            drop(rows);
            drop(statement);

            let mut macros = Vec::new();
            let mut macro_indices = HashMap::default();
            let mut statement = tx.prepare_cached(
                "SELECT invocation_occurrence_id, context_occurrence_id,
                        expansion_kind, root_occurrence_id, source_position
                   FROM source_rust_item_macro_expansions
                  WHERE blob_id = ?1 ORDER BY invocation_occurrence_id",
            )?;
            let mut rows = statement.query(params![blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let invocation = source_occurrence(row.get(0)?, "item macro invocation")?;
                let context = source_occurrence(row.get(1)?, "item macro context")?;
                require_context(&contexts, &context_indices, context, "item macro")?;
                let root = row
                    .get::<_, Option<i64>>(3)?
                    .map(|value| source_occurrence(value, "item macro root"))
                    .transpose()?;
                let fact = RustItemMacroSourceFact {
                    invocation,
                    context,
                    position: match row.get::<_, Option<i64>>(4)? {
                        Some(0) => RustItemMacroSourcePosition::DirectItem,
                        Some(1) => RustItemMacroSourcePosition::ItemStatement,
                        Some(2) => RustItemMacroSourcePosition::Other,
                        value => {
                            return Err(StoreError::new(format!(
                                "invalid or missing Rust macro source position {value:?}"
                            )));
                        }
                    },
                    expansion: macro_expansion(row.get(2)?, root)?,
                };
                if fact.position == RustItemMacroSourcePosition::DirectItem
                    && fact.expansion == RustItemMacroExpansion::NotRequested
                {
                    return Err(StoreError::new(
                        "direct-item Rust macro has no replay evidence",
                    ));
                }
                if let RustItemMacroExpansion::Parsed(root) = fact.expansion {
                    let root_index =
                        require_context(&contexts, &context_indices, root, "parsed item macro root")?;
                    if contexts[root_index].kind != RustSourceContextKind::FileRoot
                        || contexts[root_index].parent != Some(context)
                    {
                        return Err(StoreError::new(format!(
                            "parsed Rust item macro root is not the child of its invocation context: macro={fact:?}, contexts={contexts:?}"
                        )));
                    }
                }
                if macro_indices.insert(invocation, macros.len()).is_some() {
                    return Err(StoreError::new(format!(
                        "duplicate Rust item macro invocation {invocation:?}; macros={macros:?}"
                    )));
                }
                macros.push(fact);
            }
            drop(rows);
            drop(statement);

            let Some(macro_inputs) = read_rust_macro_input_rows(tx, blob_id, keep_going)? else {
                return Ok(None);
            };
            for input in &macro_inputs {
                if !macro_indices.contains_key(&input.invocation) {
                    return Err(StoreError::corrupt(format!("macro input has no invocation {:?}", input.invocation)));
                }
            }

            let Some(macro_definitions) = read_rust_macro_definition_rows(tx, blob_id, keep_going)? else {
                return Ok(None);
            };

            let mut import_contexts = Vec::new();
            let mut import_indices = HashMap::default();
            let mut statement = tx.prepare_cached(
                "SELECT declaration_occurrence_id, context_occurrence_id
                   FROM source_rust_item_import_contexts
                  WHERE blob_id = ?1 ORDER BY declaration_occurrence_id",
            )?;
            let mut rows = statement.query(params![blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let declaration = source_occurrence(row.get(0)?, "item import declaration")?;
                let context = source_occurrence(row.get(1)?, "item import context")?;
                require_context(&contexts, &context_indices, context, "item import")?;
                if import_indices
                    .insert(declaration, import_contexts.len())
                    .is_some()
                {
                    return Err(StoreError::new(format!(
                        "duplicate Rust item import declaration {declaration:?}; imports={import_contexts:?}"
                    )));
                }
                import_contexts.push(RustItemImportContextFact {
                    declaration,
                    context,
                });
            }
            drop(rows);
            drop(statement);

            let mut types = Vec::new();
            let mut type_indices = HashMap::default();
            let mut statement = tx.prepare_cached(
                "SELECT occurrence_id, path_kind, leading_absolute,
                        unsupported_occurrence_id, unsupported_syntax_kind,
                        compound_occurrence_id, type_parameters_occurrence_id
                   FROM source_rust_types
                  WHERE blob_id = ?1 ORDER BY occurrence_id",
            )?;
            let mut rows = statement.query(params![blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let occurrence = source_occurrence(row.get(0)?, "type")?;
                let compound = row.get::<_, Option<i64>>(5)?;
                let parameters = row.get::<_, Option<i64>>(6)?;
                let shape = match row.get::<_, i64>(1)? {
                    0 => {
                        let leading = row
                            .get::<_, Option<i64>>(2)?
                            .ok_or_else(|| StoreError::new("Rust path type has no leading_absolute"))?;
                        if row.get::<_, Option<i64>>(3)?.is_some()
                            || row.get::<_, Option<String>>(4)?.is_some()
                            || compound.is_some()
                            || parameters.is_some()
                        {
                            return Err(StoreError::new(format!(
                                "Rust path type has unsupported fields: occurrence={occurrence:?}"
                            )));
                        }
                        RustTypeSourceShape::Path {
                            leading_absolute: strict_bool(leading, "type leading_absolute")?,
                            segments: Vec::new(),
                        }
                    }
                    1 => {
                        if row.get::<_, Option<i64>>(2)?.is_some()
                            || compound.is_some()
                            || parameters.is_some()
                        {
                            return Err(StoreError::new(format!(
                                "unsupported Rust type has leading_absolute: occurrence={occurrence:?}"
                            )));
                        }
                        let terminal = row.get::<_, Option<i64>>(3)?.ok_or_else(|| {
                            StoreError::new("unsupported Rust type has no terminal occurrence")
                        })?;
                        let syntax_kind = row.get::<_, Option<String>>(4)?.ok_or_else(|| {
                            StoreError::new("unsupported Rust type has no syntax kind")
                        })?;
                        if syntax_kind.is_empty() {
                            return Err(StoreError::new(
                                "unsupported Rust type has empty syntax kind",
                            ));
                        }
                        RustTypeSourceShape::Unsupported {
                            occurrence: source_occurrence(terminal, "unsupported type")?,
                            syntax_kind,
                        }
                    }
                    kind @ 2..=5 => {
                        if row.get::<_, Option<i64>>(2)?.is_some()
                            || row.get::<_, Option<i64>>(3)?.is_some()
                            || row.get::<_, Option<String>>(4)?.is_some()
                            || (!matches!(kind, 2 | 5) && parameters.is_some())
                        {
                            return Err(StoreError::new(format!(
                                "compound Rust type has incompatible fields: occurrence={occurrence:?}, kind={kind}"
                            )));
                        }
                        let compound = compound.ok_or_else(|| {
                            StoreError::new("compound Rust type has no form occurrence")
                        })?;
                        RustTypeSourceShape::Compound {
                            occurrence: source_occurrence(compound, "compound type")?,
                            kind: match kind {
                                2 => RustTypeCompoundSourceKind::Abstract,
                                3 => RustTypeCompoundSourceKind::Dynamic,
                                4 => RustTypeCompoundSourceKind::Bounded,
                                5 => RustTypeCompoundSourceKind::HigherRanked,
                                _ => unreachable!("matched compound type discriminator"),
                            },
                            children: Vec::new(),
                            type_parameters: parameters
                                .map(|value| source_occurrence(value, "higher-ranked type parameters"))
                                .transpose()?,
                        }
                    }
                    kind => {
                        return Err(StoreError::new(format!(
                            "invalid Rust type path kind {kind}"
                        )));
                    }
                };
                if type_indices.insert(occurrence, types.len()).is_some() {
                    return Err(StoreError::new(format!(
                        "duplicate Rust type occurrence {occurrence:?}; types={types:?}"
                    )));
                }
                types.push(RustTypeSourceFact {
                    occurrence,
                    wrappers: Vec::new(),
                    shape,
                });
            }
            drop(rows);
            drop(statement);

            let mut statement = tx.prepare_cached(
                "SELECT type_occurrence_id, ordinal, occurrence_id
                   FROM source_rust_type_children
                  WHERE blob_id = ?1 ORDER BY type_occurrence_id, ordinal",
            )?;
            let mut rows = statement.query(params![blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let owner = source_occurrence(row.get(0)?, "compound type owner")?;
                let index = require_type(&types, &type_indices, owner, "compound owner")?;
                let child = source_occurrence(row.get(2)?, "compound child")?;
                require_type(&types, &type_indices, child, "compound child")?;
                let RustTypeSourceShape::Compound { children, .. } = &mut types[index].shape else {
                    return Err(StoreError::new(format!(
                        "compound child belongs to a non-compound type: owner={owner:?}, child={child:?}"
                    )));
                };
                require_dense_ordinal(row.get(1)?, children.len(), "compound child")?;
                children.push(child);
            }
            drop(rows);
            drop(statement);

            let mut statement = tx.prepare_cached(
                "SELECT type_occurrence_id, ordinal, occurrence_id, wrapper_kind
                   FROM source_rust_type_wrappers
                  WHERE blob_id = ?1 ORDER BY type_occurrence_id, ordinal",
            )?;
            let mut rows = statement.query(params![blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let type_occurrence = source_occurrence(row.get(0)?, "wrapper type")?;
                let index = require_type(&types, &type_indices, type_occurrence, "wrapper")?;
                require_dense_ordinal(row.get(1)?, types[index].wrappers.len(), "type wrapper")?;
                types[index].wrappers.push(RustTypeWrapperSourceFact {
                    occurrence: source_occurrence(row.get(2)?, "type wrapper")?,
                    kind: wrapper_kind(row.get(3)?)?,
                });
            }
            drop(rows);
            drop(statement);

            let mut statement = tx.prepare_cached(
                "SELECT type_occurrence_id, ordinal, occurrence_id, name
                   FROM source_rust_type_segments
                  WHERE blob_id = ?1 ORDER BY type_occurrence_id, ordinal",
            )?;
            let mut rows = statement.query(params![blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let type_occurrence = source_occurrence(row.get(0)?, "segment type")?;
                let index = require_type(&types, &type_indices, type_occurrence, "segment")?;
                let segment = RustTypePathSegmentSourceFact {
                    occurrence: source_occurrence(row.get(2)?, "type segment")?,
                    name: row.get(3)?,
                    generic_arguments: None,
                };
                let RustTypeSourceShape::Path { segments, .. } = &mut types[index].shape else {
                    return Err(StoreError::new(format!(
                        "unsupported Rust type has a path segment {type_occurrence:?}; types={types:?}"
                    )));
                };
                require_dense_ordinal(row.get(1)?, segments.len(), "type segment")?;
                segments.push(segment);
            }
            drop(rows);
            drop(statement);

            let mut statement = tx.prepare_cached(
                "SELECT type_occurrence_id, segment_ordinal, occurrence_id
                   FROM source_rust_type_generic_lists
                  WHERE blob_id = ?1 ORDER BY type_occurrence_id, segment_ordinal",
            )?;
            let mut rows = statement.query(params![blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let type_occurrence = source_occurrence(row.get(0)?, "generic list type")?;
                let index = require_type(&types, &type_indices, type_occurrence, "generic list")?;
                let segment_ordinal = nonnegative_usize(row.get(1)?, "generic list segment ordinal")?;
                let RustTypeSourceShape::Path { segments, .. } = &mut types[index].shape else {
                    return Err(StoreError::new(format!(
                        "unsupported Rust type has a generic list {type_occurrence:?}; types={types:?}"
                    )));
                };
                let Some(segment) = segments.get_mut(segment_ordinal) else {
                    return Err(StoreError::new(format!(
                        "Rust generic list has missing segment parent type={type_occurrence:?}, segment={segment_ordinal}; types={types:?}"
                    )));
                };
                if segment.generic_arguments.is_some() {
                    return Err(StoreError::new(format!(
                        "duplicate Rust generic list type={type_occurrence:?}, segment={segment_ordinal}"
                    )));
                }
                segment.generic_arguments = Some(RustGenericArgumentsSourceFact {
                    occurrence: source_occurrence(row.get(2)?, "generic list")?,
                    arguments: Vec::new(),
                });
            }
            drop(rows);
            drop(statement);

            let mut statement = tx.prepare_cached(
                "SELECT type_occurrence_id, segment_ordinal, ordinal, occurrence_id
                   FROM source_rust_type_generic_arguments
                  WHERE blob_id = ?1
                  ORDER BY type_occurrence_id, segment_ordinal, ordinal",
            )?;
            let mut rows = statement.query(params![blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let type_occurrence = source_occurrence(row.get(0)?, "generic argument type")?;
                let index = require_type(&types, &type_indices, type_occurrence, "generic argument")?;
                let segment_ordinal =
                    nonnegative_usize(row.get(1)?, "generic argument segment ordinal")?;
                let RustTypeSourceShape::Path { segments, .. } = &mut types[index].shape else {
                    return Err(StoreError::new(format!(
                        "unsupported Rust type has a generic argument {type_occurrence:?}; types={types:?}"
                    )));
                };
                let Some(segment) = segments.get_mut(segment_ordinal) else {
                    return Err(StoreError::new(format!(
                        "Rust generic argument has missing segment parent type={type_occurrence:?}, segment={segment_ordinal}"
                    )));
                };
                let Some(arguments) = segment.generic_arguments.as_mut() else {
                    return Err(StoreError::new(format!(
                        "Rust generic argument has no list fact type={type_occurrence:?}, segment={segment_ordinal}"
                    )));
                };
                require_dense_ordinal(
                    row.get(2)?,
                    arguments.arguments.len(),
                    "type generic argument",
                )?;
                arguments
                    .arguments
                    .push(source_occurrence(row.get(3)?, "type generic argument")?);
            }
            drop(rows);
            drop(statement);

            for item in &impls {
                for (label, occurrence) in [
                    ("impl trait type", item.trait_type),
                    ("impl target type", item.target_type),
                ] {
                    if let Some(occurrence) = occurrence {
                        require_type(&types, &type_indices, occurrence, label)?;
                    }
                }
            }
            for item in &aliases {
                if let Some(occurrence) = item.target_type {
                    require_type(&types, &type_indices, occurrence, "alias target type")?;
                }
            }

            for item in &callables {
                if let Some(occurrence) = item.return_type {
                    require_type(&types, &type_indices, occurrence, "callable return type")?;
                }
            }
            for item in &values {
                if let Some(occurrence) = item.declared_type {
                    require_type(&types, &type_indices, occurrence, "value declared type")?;
                }
            }

            for ty in &types {
                if !ty.wrappers.is_empty() && ty.wrappers[0].occurrence != ty.occurrence {
                    return Err(StoreError::new(format!(
                        "Rust type wrapper chain does not begin at its type root: type={ty:?}"
                    )));
                }
                match &ty.shape {
                    RustTypeSourceShape::Path { segments, .. } => {
                        for argument in segments
                            .iter()
                            .filter_map(|segment| segment.generic_arguments.as_ref())
                            .flat_map(|arguments| &arguments.arguments)
                        {
                            require_type(&types, &type_indices, *argument, "generic argument type")?;
                        }
                        if segments.is_empty() {
                            return Err(StoreError::new(format!(
                                "Rust path type has no segments: type={ty:?}"
                            )));
                        }
                        if segments.iter().any(|segment| segment.name.is_empty()) {
                            return Err(StoreError::new(format!(
                                "Rust path type has an empty segment name: type={ty:?}"
                            )));
                        }
                    }
                    RustTypeSourceShape::Unsupported { syntax_kind, .. } if syntax_kind.is_empty() => {
                        return Err(StoreError::new(format!(
                            "Rust unsupported type has an empty syntax kind: type={ty:?}"
                        )));
                    }
                    RustTypeSourceShape::Unsupported { .. } => {}
                    RustTypeSourceShape::Compound {
                        kind,
                        children,
                        type_parameters,
                        ..
                    } => {
                        if children.is_empty()
                            || (*kind != RustTypeCompoundSourceKind::Bounded && children.len() != 1)
                            || (!matches!(
                                kind,
                                RustTypeCompoundSourceKind::Abstract
                                    | RustTypeCompoundSourceKind::HigherRanked
                            ) && type_parameters.is_some())
                        {
                            return Err(StoreError::new(format!(
                                "Rust compound type has incompatible children or parameters: type={ty:?}"
                            )));
                        }
                        for child in children {
                            if !keep_going() {
                                return Ok(None);
                            }
                            require_type(&types, &type_indices, *child, "compound child")?;
                        }
                    }
                }
            }

            let item_facts = RustItemSourceFacts {
                contexts,
                syntax,
                impls,
                traits,
                aliases,
                callables,
                values,
                generics,
                macros,
                macro_definitions,
                macro_inputs,
                import_contexts,
            };
            let actual_cost = rust_item_source_cost(&item_facts, &types);
            if actual_cost != (expected_rows, expected_payload) {
                return Err(StoreError::new(format!(
                    "Rust item source cost mismatch expected=({expected_rows}, {expected_payload}), actual={actual_cost:?}; items={item_facts:?}, types={types:?}"
                )));
            }
            if !keep_going() {
                return Ok(None);
            }
            // All supporting families are read under the same generation witness
            // and transaction as the item inventory. Never join separate snapshots.
            let (expected_declarations, expected_links): (usize, usize) = tx.query_row(
                "SELECT declaration_count, declaration_unit_count
                   FROM source_fact_manifests WHERE blob_id = ?1",
                [blob_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            let mut declarations = Vec::new();
            let mut statement = tx.prepare_cached(
                "SELECT declaration_id, occurrence_id, name_occurrence_id
                   FROM source_declarations WHERE blob_id = ?1 ORDER BY declaration_id",
            )?;
            let mut rows = statement.query([blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let declaration = source_declaration(row.get(0)?, "hierarchy declaration")?;
                if declaration.index() != declarations.len() {
                    return Err(StoreError::new(format!(
                        "non-dense hierarchy declaration {declaration:?}: declarations={declarations:?}"
                    )));
                }
                declarations.push(SourceDeclaration {
                    occurrence: source_occurrence(row.get(1)?, "hierarchy declaration")?,
                    name: row
                        .get::<_, Option<i64>>(2)?
                        .map(|id| source_occurrence(id, "hierarchy declaration name"))
                        .transpose()?,
                });
            }
            drop(rows);
            drop(statement);
            if declarations.len() != expected_declarations {
                return Err(StoreError::new(format!(
                    "incomplete hierarchy declarations for {oid}: expected {expected_declarations}, declarations={declarations:?}"
                )));
            }
            for definition in &item_facts.macro_definitions {
                if declarations.get(definition.declaration.index()).is_none() {
                    return Err(StoreError::new(format!(
                        "Rust macro definition has missing source declaration {:?}; declarations={declarations:?}",
                        definition.declaration
                    )));
                }
            }

            let mut module_names = HashMap::default();
            let mut statement = tx.prepare_cached(
                "SELECT declaration_id, module_name FROM source_rust_module_declarations
                  WHERE blob_id = ?1 ORDER BY declaration_id",
            )?;
            let mut rows = statement.query([blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let declaration = source_declaration(row.get(0)?, "hierarchy module")?;
                if declarations.get(declaration.index()).is_none() {
                    return Err(StoreError::new(format!(
                        "hierarchy module has no declaration {declaration:?}: declarations={declarations:?}"
                    )));
                }
                module_names.insert(declaration, row.get(1)?);
            }
            drop(rows);
            drop(statement);

            let Some(units) =
                read_source_unit_map(tx, &oid_text, "rust", adapter, file, keep_going)?
            else {
                return Ok(None);
            };
            let mut declaration_units = Vec::new();
            let mut statement = tx.prepare_cached(SOURCE_DECLARATION_UNITS_SQL)?;
            let mut rows = statement.query([blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let declaration = source_declaration(row.get(0)?, "hierarchy unit bridge")?;
                let key: i64 = row.get(1)?;
                if declarations.get(declaration.index()).is_none() {
                    return Err(StoreError::new(format!(
                        "hierarchy unit bridge has no declaration {declaration:?}: declarations={declarations:?}"
                    )));
                }
                let unit = units.get(&key).ok_or_else(|| {
                    StoreError::new(format!(
                        "hierarchy declaration {declaration:?} has no mounted unit {key} for {oid}"
                    ))
                })?;
                declaration_units.push((declaration, unit.clone()));
            }
            drop(rows);
            drop(statement);
            if declaration_units.len() != expected_links {
                return Err(StoreError::new(format!(
                    "incomplete hierarchy declaration bridges for {oid}: expected {expected_links}, links={declaration_units:?}"
                )));
            }
            let Some(imports) = read_source_imports(tx, blob_id, keep_going)?
            else {
                return Ok(None);
            };
            if !keep_going() {
                return Ok(None);
            }
            Ok(Some(RustHierarchySourceFacts {
                items: item_facts,
                types,
                declarations,
                declaration_units,
                module_names,
                imports,
            }))
        })
    }
}

/// Read canonical matcher arms from an already selected, sealed Rust blob.
/// This reader is shared by hierarchy hydration and selected macro replay.
pub(crate) fn read_rust_macro_definition_rows(
    tx: &rusqlite::Connection,
    blob_id: i64,
    keep_going: &dyn Fn() -> bool,
) -> Result<Option<Vec<RustMacroDefinitionSourceFact>>> {
    let mut macro_definitions = Vec::new();
    let mut macro_definition_indices = HashMap::default();
    let mut statement = tx.prepare_cached(
        "SELECT definition.declaration_id, definition.ordinal, definition.is_macro_rules,
                definition.context_occurrence_id,
                EXISTS (SELECT 1 FROM source_rust_item_contexts AS context
                        WHERE context.blob_id = definition.blob_id
                          AND context.occurrence_id = definition.context_occurrence_id)
           FROM source_rust_macro_definitions AS definition
          WHERE definition.blob_id = ?1 ORDER BY definition.ordinal",
    )?;
    let mut rows = statement.query(params![blob_id])?;
    while let Some(row) = rows.next()? {
        if !keep_going() {
            return Ok(None);
        }
        let declaration = source_declaration(row.get(0)?, "macro definition")?;
        require_dense_ordinal(row.get(1)?, macro_definitions.len(), "macro definition")?;
        if macro_definition_indices
            .insert(declaration, macro_definitions.len())
            .is_some()
        {
            return Err(StoreError::new(format!(
                "duplicate Rust macro definition {declaration:?}; definitions={macro_definitions:?}"
            )));
        }
        let context = source_occurrence(row.get(3)?, "macro definition context")?;
        if !strict_bool(row.get(4)?, "macro definition context exists")? {
            return Err(StoreError::corrupt(format!(
                "macro definition {declaration:?} has no source context {context:?}"
            )));
        }
        macro_definitions.push(RustMacroDefinitionSourceFact {
            declaration,
            is_macro_rules: strict_bool(row.get(2)?, "macro definition is_macro_rules")?,
            context,
            arms: Vec::new(),
        });
    }
    drop(rows);
    drop(statement);

    let mut arm_indices = HashMap::default();
    let mut arm_occurrences = HashMap::default();
    let mut statement = tx.prepare_cached(
        "SELECT declaration_id, ordinal, occurrence_id, pattern_occurrence_id
           FROM source_rust_macro_arms
          WHERE blob_id = ?1 ORDER BY declaration_id, ordinal",
    )?;
    let mut rows = statement.query(params![blob_id])?;
    while let Some(row) = rows.next()? {
        if !keep_going() {
            return Ok(None);
        }
        let declaration = source_declaration(row.get(0)?, "macro arm owner")?;
        let Some(definition_index) = macro_definition_indices.get(&declaration).copied() else {
            return Err(StoreError::new(format!(
                "Rust macro arm has missing definition {declaration:?}; definitions={macro_definitions:?}"
            )));
        };
        let definition = &mut macro_definitions[definition_index];
        let arm_ordinal = require_dense_ordinal(row.get(1)?, definition.arms.len(), "macro arm")?;
        let occurrence = source_occurrence(row.get(2)?, "macro arm")?;
        if arm_occurrences
            .insert(occurrence, (declaration, arm_ordinal))
            .is_some()
        {
            return Err(StoreError::new(format!(
                "duplicate Rust macro arm occurrence {occurrence:?}"
            )));
        }
        if arm_indices
            .insert((declaration, arm_ordinal), definition.arms.len())
            .is_some()
        {
            return Err(StoreError::new(format!(
                "duplicate Rust macro arm declaration={declaration:?}, ordinal={arm_ordinal}"
            )));
        }
        definition.arms.push(RustMacroArmSourceFact {
            occurrence,
            pattern: row
                .get::<_, Option<i64>>(3)?
                .map(|value| source_occurrence(value, "macro arm pattern"))
                .transpose()?,
            patterns: Vec::new(),
            ident_roles: Vec::new(),
        });
    }
    drop(rows);
    drop(statement);

    let mut pattern_indices = HashMap::default();
    let mut pattern_binding_names: HashMap<_, HashSet<String>> = HashMap::default();
    let mut statement = tx.prepare_cached(
        "SELECT declaration_id, arm_ordinal, ordinal, occurrence_id,
                parent_occurrence_id, node_kind, literal_kind, literal_text,
                binding_name, fragment_kind, delimiter, separator, operator
           FROM source_rust_macro_pattern_nodes
          WHERE blob_id = ?1 ORDER BY declaration_id, arm_ordinal, ordinal",
    )?;
    let mut rows = statement.query(params![blob_id])?;
    while let Some(row) = rows.next()? {
        if !keep_going() {
            return Ok(None);
        }
        let declaration = source_declaration(row.get(0)?, "macro pattern owner")?;
        let arm_ordinal = nonnegative_usize(row.get(1)?, "macro pattern arm ordinal")?;
        let Some(definition_index) = macro_definition_indices.get(&declaration).copied() else {
            return Err(StoreError::new(format!(
                "Rust macro pattern has missing definition {declaration:?}; definitions={macro_definitions:?}"
            )));
        };
        let Some(&arm_index) = arm_indices.get(&(declaration, arm_ordinal)) else {
            return Err(StoreError::new(format!(
                "Rust macro pattern has missing arm declaration={declaration:?}, ordinal={arm_ordinal}"
            )));
        };
        let arm = &mut macro_definitions[definition_index].arms[arm_index];
        let ordinal = require_dense_ordinal(row.get(2)?, arm.patterns.len(), "macro pattern")?;
        let occurrence = source_occurrence(row.get(3)?, "macro pattern")?;
        let parent = row
            .get::<_, Option<i64>>(4)?
            .map(|value| source_occurrence(value, "macro pattern parent"))
            .transpose()?;
        if pattern_indices.contains_key(&occurrence) {
            return Err(StoreError::new(format!(
                "duplicate Rust macro pattern occurrence {occurrence:?}"
            )));
        }
        if let Some(parent) = parent {
            match pattern_indices.get(&parent) {
                Some((parent_declaration, parent_arm, parent_ordinal))
                    if *parent_declaration == declaration
                        && *parent_arm == arm_ordinal
                        && *parent_ordinal < ordinal => {}
                _ => {
                    return Err(StoreError::new(format!(
                        "Rust macro pattern parent is not earlier in its arm: occurrence={occurrence:?}, parent={parent:?}"
                    )));
                }
            }
        }
        pattern_indices.insert(occurrence, (declaration, arm_ordinal, ordinal));

        let node_kind: i64 = row.get(5)?;
        let literal_kind: Option<String> = row.get(6)?;
        let literal_text: Option<String> = row.get(7)?;
        let binding_name: Option<String> = row.get(8)?;
        let fragment_kind: Option<i64> = row.get(9)?;
        let delimiter: Option<i64> = row.get(10)?;
        let separator: Option<String> = row.get(11)?;
        let operator: Option<i64> = row.get(12)?;
        let kind = match node_kind {
            0 => {
                if literal_kind.is_none()
                    || literal_kind.as_deref().is_some_and(str::is_empty)
                    || literal_text.is_none()
                    || binding_name.is_some()
                    || fragment_kind.is_some()
                    || delimiter.is_some()
                    || separator.is_some()
                    || operator.is_some()
                {
                    return Err(StoreError::new(format!(
                        "invalid Rust literal macro pattern shape occurrence={occurrence:?}"
                    )));
                }
                RustMacroPatternSourceKind::Literal {
                    syntax_kind: literal_kind.expect("literal kind checked above"),
                    text: literal_text.expect("literal text checked above"),
                }
            }
            1 => {
                if binding_name.is_none()
                    || binding_name.as_deref().is_some_and(str::is_empty)
                    || fragment_kind.is_none()
                    || literal_kind.is_some()
                    || literal_text.is_some()
                    || delimiter.is_some()
                    || separator.is_some()
                    || operator.is_some()
                {
                    return Err(StoreError::new(format!(
                        "invalid Rust binding macro pattern shape occurrence={occurrence:?}"
                    )));
                }
                let name = binding_name.expect("binding name checked above");
                let fragment =
                    macro_fragment_kind(fragment_kind.expect("binding fragment checked above"))?;
                if fragment == MacroFragmentKind::Ident {
                    pattern_binding_names
                        .entry((declaration, arm_ordinal))
                        .or_default()
                        .insert(name.clone());
                }
                RustMacroPatternSourceKind::Binding { name, fragment }
            }
            2 => {
                if literal_kind.is_some()
                    || literal_text.is_some()
                    || binding_name.is_some()
                    || fragment_kind.is_some()
                    || separator.is_some()
                    || operator.is_some()
                {
                    return Err(StoreError::new(format!(
                        "invalid Rust group macro pattern shape occurrence={occurrence:?}"
                    )));
                }
                RustMacroPatternSourceKind::Group {
                    delimiter: delimiter.map(macro_delimiter).transpose()?,
                }
            }
            3 => {
                if literal_kind.is_some()
                    || literal_text.is_some()
                    || binding_name.is_some()
                    || fragment_kind.is_some()
                    || delimiter.is_some()
                    || separator.as_deref().is_some_and(str::is_empty)
                    || operator.is_none()
                {
                    return Err(StoreError::new(format!(
                        "invalid Rust repetition macro pattern shape occurrence={occurrence:?}"
                    )));
                }
                RustMacroPatternSourceKind::Repetition {
                    separator,
                    operator: macro_repetition_operator(
                        operator.expect("repetition operator checked above"),
                    )?,
                }
            }
            4 => {
                if literal_kind.is_some()
                    || literal_text.is_some()
                    || binding_name.is_some()
                    || fragment_kind.is_some()
                    || delimiter.is_some()
                    || separator.is_some()
                    || operator.is_some()
                {
                    return Err(StoreError::new(format!(
                        "invalid Rust invalid-pattern shape occurrence={occurrence:?}"
                    )));
                }
                RustMacroPatternSourceKind::Invalid
            }
            _ => {
                return Err(StoreError::new(format!(
                    "invalid Rust macro pattern node kind {node_kind}"
                )));
            }
        };
        arm.patterns.push(RustMacroPatternSourceFact {
            occurrence,
            parent,
            kind,
        });
    }
    drop(rows);
    drop(statement);

    for definition in &macro_definitions {
        for (arm_ordinal, arm) in definition.arms.iter().enumerate() {
            if !keep_going() {
                return Ok(None);
            }
            match arm.pattern {
                Some(root) => {
                    let Some(root_pattern) = arm.patterns.first() else {
                        return Err(StoreError::new(format!(
                            "Rust macro arm root pattern is missing: declaration={:?}, arm={arm_ordinal}, root={root:?}, arm={arm:?}",
                            definition.declaration,
                        )));
                    };
                    if root_pattern.occurrence != root {
                        return Err(StoreError::new(format!(
                            "Rust macro arm root pattern is not first: declaration={:?}, arm={arm_ordinal}, root={root:?}, arm={arm:?}",
                            definition.declaration,
                        )));
                    }
                    if root_pattern.parent.is_some() {
                        return Err(StoreError::new(format!(
                            "Rust macro arm root pattern has a parent: declaration={:?}, arm={arm_ordinal}, root={root:?}, arm={arm:?}",
                            definition.declaration,
                        )));
                    }
                    if !matches!(&root_pattern.kind, RustMacroPatternSourceKind::Group { .. }) {
                        return Err(StoreError::new(format!(
                            "Rust macro arm root pattern is not a group: declaration={:?}, arm={arm_ordinal}, root={root:?}, arm={arm:?}",
                            definition.declaration,
                        )));
                    }
                    for pattern in arm.patterns.iter().skip(1) {
                        if !keep_going() {
                            return Ok(None);
                        }
                        let Some(parent) = pattern.parent else {
                            return Err(StoreError::new(format!(
                                "Rust macro arm has multiple roots: declaration={:?}, arm={arm_ordinal}, arm={arm:?}",
                                definition.declaration,
                            )));
                        };
                        let (_, _, parent_ordinal) = pattern_indices
                            .get(&parent)
                            .expect("macro pattern parent was validated while reading");
                        let parent_pattern = &arm.patterns[*parent_ordinal];
                        if !matches!(
                            &parent_pattern.kind,
                            RustMacroPatternSourceKind::Group { .. }
                                | RustMacroPatternSourceKind::Repetition { .. }
                        ) {
                            return Err(StoreError::new(format!(
                                "Rust macro pattern parent cannot contain children: declaration={:?}, arm={arm_ordinal}, arm={arm:?}",
                                definition.declaration,
                            )));
                        }
                    }
                }
                None if !arm.patterns.is_empty() => {
                    return Err(StoreError::new(format!(
                        "Rust macro arm without a root has pattern nodes: declaration={:?}, arm={arm_ordinal}, arm={arm:?}",
                        definition.declaration,
                    )));
                }
                None => {}
            }
        }
    }

    let mut statement = tx.prepare_cached(
        "SELECT declaration_id, arm_ordinal, ordinal, name, role
           FROM source_rust_macro_ident_roles
          WHERE blob_id = ?1 ORDER BY declaration_id, arm_ordinal, ordinal",
    )?;
    let mut rows = statement.query(params![blob_id])?;
    let mut role_names: HashMap<_, HashSet<String>> = HashMap::default();
    while let Some(row) = rows.next()? {
        if !keep_going() {
            return Ok(None);
        }
        let declaration = source_declaration(row.get(0)?, "macro ident role owner")?;
        let arm_ordinal = nonnegative_usize(row.get(1)?, "macro ident role arm ordinal")?;
        let Some(definition_index) = macro_definition_indices.get(&declaration).copied() else {
            return Err(StoreError::new(format!(
                "Rust macro ident role has missing definition {declaration:?}"
            )));
        };
        let Some(&arm_index) = arm_indices.get(&(declaration, arm_ordinal)) else {
            return Err(StoreError::new(format!(
                "Rust macro ident role has missing arm declaration={declaration:?}, ordinal={arm_ordinal}"
            )));
        };
        let arm = &mut macro_definitions[definition_index].arms[arm_index];
        require_dense_ordinal(row.get(2)?, arm.ident_roles.len(), "macro ident role")?;
        let name: String = row.get(3)?;
        if name.is_empty() {
            return Err(StoreError::new("Rust macro ident role has an empty name"));
        }
        if !pattern_binding_names
            .get(&(declaration, arm_ordinal))
            .is_some_and(|names| names.contains(&name))
        {
            return Err(StoreError::new(format!(
                "Rust macro ident role has no matching pattern binding: declaration={declaration:?}, arm={arm_ordinal}, name={name:?}"
            )));
        }
        arm.ident_roles.push(RustMacroIdentRoleSourceFact {
            name: name.clone(),
            role: macro_ident_role(row.get(4)?)?,
        });
        if !role_names
            .entry((declaration, arm_ordinal))
            .or_default()
            .insert(name)
        {
            return Err(StoreError::new(format!(
                "duplicate Rust macro ident role name: declaration={declaration:?}, arm={arm_ordinal}"
            )));
        }
    }
    drop(rows);
    drop(statement);

    for ((declaration, arm_ordinal), binding_names) in &pattern_binding_names {
        if !keep_going() {
            return Ok(None);
        }
        for binding_name in binding_names {
            if !keep_going() {
                return Ok(None);
            }
            if !role_names
                .get(&(*declaration, *arm_ordinal))
                .is_some_and(|names| names.contains(binding_name))
            {
                return Err(StoreError::new(format!(
                    "Rust macro pattern binding has no identifier role: declaration={declaration:?}, arm={arm_ordinal}, name={binding_name:?}"
                )));
            }
        }
    }
    Ok(Some(macro_definitions))
}

/// Read canonical invocation snapshots without hydrating a source file.
pub(crate) fn read_rust_macro_input_rows(
    tx: &rusqlite::Connection,
    blob_id: i64,
    keep_going: &dyn Fn() -> bool,
) -> Result<Option<Vec<brokk_bifrost_core::analyzer::rust_facts::RustMacroInvocationInputSourceFact>>>
{
    let mut macro_inputs = Vec::new();
    let mut macro_input_indices = HashMap::default();
    let mut statement = tx.prepare_cached("SELECT invocation_occurrence_id, start_byte, source, native_gap_site, native_scope FROM source_rust_macro_inputs WHERE blob_id = ?1 ORDER BY invocation_occurrence_id")?;
    let mut rows = statement.query(params![blob_id])?;
    while let Some(row) = rows.next()? {
        if !keep_going() {
            return Ok(None);
        }
        let invocation = source_occurrence(row.get(0)?, "macro input invocation")?;
        macro_input_indices.insert(invocation, macro_inputs.len());
        let native_frontier = match (row.get::<_, Option<i64>>(3)?, row.get::<_, Option<i64>>(4)?) {
            (None, None) => None,
            (Some(site), Some(scope)) => Some((
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId::new(
                    u32::try_from(site)
                        .map_err(|_| StoreError::corrupt("invalid macro native gap site"))?,
                ),
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId::new(
                    u32::try_from(scope)
                        .map_err(|_| StoreError::corrupt("invalid macro native scope"))?,
                ),
            )),
            fields => {
                return Err(StoreError::corrupt(format!(
                    "partial macro native frontier: {fields:?}"
                )));
            }
        };
        macro_inputs.push(
            brokk_bifrost_core::analyzer::rust_facts::RustMacroInvocationInputSourceFact {
                invocation,
                native_frontier,
                occurrences: Vec::new(),
                tree: brokk_bifrost_core::analyzer::rust_facts::RustMacroTokenTree {
                    start_byte: nonnegative_usize(row.get(1)?, "macro input start")?,
                    source: row.get(2)?,
                    tokens: Vec::new(),
                },
            },
        );
    }
    drop(rows);
    drop(statement);
    let mut statement = tx.prepare_cached("SELECT invocation_occurrence_id, ordinal, parent_ordinal, syntax_kind, start_byte, end_byte, source_occurrence_id FROM source_rust_macro_input_tokens WHERE blob_id = ?1 ORDER BY invocation_occurrence_id, ordinal")?;
    let mut rows = statement.query(params![blob_id])?;
    while let Some(row) = rows.next()? {
        if !keep_going() {
            return Ok(None);
        }
        let invocation = source_occurrence(row.get(0)?, "macro input token invocation")?;
        let index = *macro_input_indices.get(&invocation).ok_or_else(|| {
            StoreError::corrupt(format!("macro input token has no input {invocation:?}"))
        })?;
        macro_inputs[index].occurrences.push(source_occurrence(
            row.get(6)?,
            "macro input token occurrence",
        )?);
        let input = &mut macro_inputs[index].tree;
        require_dense_ordinal(row.get(1)?, input.tokens.len(), "macro input token")?;
        let parent = row
            .get::<_, Option<i64>>(2)?
            .map(|value| {
                u32::try_from(value).map_err(|_| StoreError::corrupt("invalid macro input parent"))
            })
            .transpose()?;
        let start_byte = nonnegative_usize(row.get(4)?, "macro input token start")?;
        let end_byte = nonnegative_usize(row.get(5)?, "macro input token end")?;
        if start_byte < input.start_byte
            || end_byte < start_byte
            || end_byte - input.start_byte > input.source.len()
            || parent.is_some_and(|parent| parent as usize >= input.tokens.len())
            || (parent.is_none() != input.tokens.is_empty())
        {
            return Err(StoreError::corrupt(format!(
                "invalid macro input token: invocation={invocation:?}, parent={parent:?}, start={start_byte}, end={end_byte}"
            )));
        }
        let syntax_kind: String = row.get(3)?;
        if !input.source.is_char_boundary(start_byte - input.start_byte)
            || !input.source.is_char_boundary(end_byte - input.start_byte)
            || syntax_kind.is_empty()
            || parent.is_some_and(|parent| {
                let parent = &input.tokens[parent as usize];
                start_byte < parent.start_byte || end_byte > parent.end_byte
            })
            || (parent.is_none()
                && (syntax_kind != "token_tree"
                    || start_byte != input.start_byte
                    || end_byte - input.start_byte != input.source.len()))
        {
            return Err(StoreError::corrupt(format!(
                "invalid macro input tree for {invocation:?}"
            )));
        }
        input.tokens.push(
            brokk_bifrost_core::analyzer::rust_facts::RustMacroInputToken {
                parent,
                syntax_kind,
                start_byte,
                end_byte,
            },
        );
    }
    drop(rows);
    drop(statement);

    if macro_inputs
        .iter()
        .any(|input| input.tree.tokens.is_empty())
    {
        return Err(StoreError::corrupt("macro input tree has no root"));
    }

    Ok(Some(macro_inputs))
}

/// Rust's registered reader of the macro rows its producer sealed.
///
/// The selected resolution operation reaches these two readers through
/// `LanguageSupport::selected_macro_source_rows` so that framework code asks
/// the selected mount's language for its macro rows instead of naming this
/// module.
pub(crate) struct RustMacroSourceRows;

impl crate::analyzer::store::resolution_operation::SelectedMacroSourceRows for RustMacroSourceRows {
    fn definition_rows(
        &self,
        connection: &rusqlite::Connection,
        blob_id: i64,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Option<Vec<RustMacroDefinitionSourceFact>>> {
        read_rust_macro_definition_rows(connection, blob_id, keep_going)
    }

    fn input_rows(
        &self,
        connection: &rusqlite::Connection,
        blob_id: i64,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<
        Option<Vec<brokk_bifrost_core::analyzer::rust_facts::RustMacroInvocationInputSourceFact>>,
    > {
        read_rust_macro_input_rows(connection, blob_id, keep_going)
    }

    fn item_container(
        &self,
        connection: &rusqlite::Connection,
        blob_id: i64,
        invocation: brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceId,
    ) -> Result<brokk_bifrost_rust::macro_matcher::RustMacroItemContainer> {
        rust_macro_item_container(connection, blob_id, invocation)
    }
}
