//! Relational persistence for Rust's source-owned item and type facts.
//!
//! The producer has already assigned every occurrence and declaration id. This
//! module only writes those ids and the normalized source rows; it does not
//! recover identity from names, ranges, or display declarations.

use crate::CancellationToken;
use brokk_bifrost_core::analyzer::parsed_file::ParsedSourceFacts;
use brokk_bifrost_core::analyzer::rust_facts::{
    MacroFragmentKind, MacroIdentRole, RustItemMacroExpansion, RustItemMacroSourcePosition,
    RustItemSourceFacts, RustMacroDelimiter, RustMacroPatternSourceKind,
    RustMacroRepetitionOperator, RustSourceContextKind, RustTypeCompoundSourceKind,
    RustTypeSourceFact, RustTypeSourceShape, RustTypeWrapperSourceKind,
};
use brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceId;
use rusqlite::{Transaction, params};

use super::super::{Result, usize_to_i64};
use super::check_cancelled;

pub(in crate::analyzer) const RUST_ITEM_SOURCE_FACTS_VERSION: i64 = 1;
pub(in crate::analyzer) const RUST_MACRO_FACTS_VERSION: i64 = 1;
pub(in crate::analyzer) const RUST_TYPE_FORMS_VERSION: i64 = 1;
pub(in crate::analyzer) const RUST_MACRO_CONTEXTS_VERSION: i64 = 1;

/// Stable discriminators for the schema54 source-owned item rows.
fn context_kind(kind: RustSourceContextKind) -> i64 {
    match kind {
        RustSourceContextKind::FileRoot => 0,
        RustSourceContextKind::Module => 1,
        RustSourceContextKind::Trait => 2,
        RustSourceContextKind::Impl => 3,
        RustSourceContextKind::Function => 4,
        RustSourceContextKind::Block => 5,
        RustSourceContextKind::DeclarationBody => 6,
        RustSourceContextKind::Type => 7,
    }
}

fn wrapper_kind(kind: RustTypeWrapperSourceKind) -> i64 {
    match kind {
        RustTypeWrapperSourceKind::Reference => 0,
        RustTypeWrapperSourceKind::Pointer => 1,
        RustTypeWrapperSourceKind::Array => 2,
        RustTypeWrapperSourceKind::Slice => 3,
    }
}

fn macro_expansion_kind(expansion: RustItemMacroExpansion) -> (i64, Option<i64>) {
    match expansion {
        RustItemMacroExpansion::NotRequested => (4, None),
        RustItemMacroExpansion::Parsed(root) => (0, Some(i64::from(root.get()))),
        RustItemMacroExpansion::EmptyInterior => (1, None),
        RustItemMacroExpansion::Unavailable(failure) => {
            let kind = match failure {
                brokk_bifrost_core::analyzer::rust_facts::RustMacroParseFailure::MissingInterior =>
                    2,
                brokk_bifrost_core::analyzer::rust_facts::RustMacroParseFailure::ParseUnavailable =>
                    3,
            };
            (kind, None)
        }
    }
}

fn path_kind(path: &RustTypeSourceShape) -> i64 {
    match path {
        RustTypeSourceShape::Path { .. } => 0,
        RustTypeSourceShape::Unsupported { .. } => 1,
        RustTypeSourceShape::Compound { kind, .. } => match kind {
            RustTypeCompoundSourceKind::Abstract => 2,
            RustTypeCompoundSourceKind::Dynamic => 3,
            RustTypeCompoundSourceKind::Bounded => 4,
            RustTypeCompoundSourceKind::HigherRanked => 5,
        },
    }
}

fn macro_fragment_kind(kind: MacroFragmentKind) -> i64 {
    match kind {
        MacroFragmentKind::Ident => 0,
        MacroFragmentKind::Path => 1,
        MacroFragmentKind::Expr => 2,
        MacroFragmentKind::Ty => 3,
        MacroFragmentKind::Pat => 4,
        MacroFragmentKind::Stmt => 5,
        MacroFragmentKind::Block => 6,
        MacroFragmentKind::Item => 7,
        MacroFragmentKind::Meta => 8,
        MacroFragmentKind::Tt => 9,
        MacroFragmentKind::Vis => 10,
        MacroFragmentKind::Lifetime => 11,
        MacroFragmentKind::Literal => 12,
    }
}

fn macro_ident_role(role: MacroIdentRole) -> i64 {
    match role {
        MacroIdentRole::Type => 0,
        MacroIdentRole::Value => 1,
        MacroIdentRole::Pattern => 2,
        MacroIdentRole::Declaration => 3,
        MacroIdentRole::Mixed => 4,
        MacroIdentRole::Unused => 5,
        MacroIdentRole::Undetermined => 6,
    }
}

fn macro_delimiter(delimiter: Option<RustMacroDelimiter>) -> Option<i64> {
    delimiter.map(|delimiter| match delimiter {
        RustMacroDelimiter::Parenthesis => 0,
        RustMacroDelimiter::Bracket => 1,
        RustMacroDelimiter::Brace => 2,
    })
}

fn macro_repetition_operator(operator: RustMacroRepetitionOperator) -> i64 {
    match operator {
        RustMacroRepetitionOperator::Star => 0,
        RustMacroRepetitionOperator::Plus => 1,
        RustMacroRepetitionOperator::Optional => 2,
    }
}

/// Exact physical rows and UTF-8 string payload for this extension, including
/// its marker. Read validation and publication use the same accounting.
pub(in crate::analyzer) fn rust_item_source_cost(
    items: &RustItemSourceFacts,
    types: &[RustTypeSourceFact],
) -> (usize, usize) {
    let mut rows = 1usize
        .saturating_add(items.syntax.len())
        .saturating_add(items.contexts.len())
        .saturating_add(items.impls.len())
        .saturating_add(items.traits.len())
        .saturating_add(items.aliases.len())
        .saturating_add(items.callables.len())
        .saturating_add(items.values.len())
        .saturating_add(items.macros.len())
        .saturating_add(items.macro_definitions.len())
        .saturating_add(items.import_contexts.len())
        .saturating_add(types.len());
    let mut payload = 0usize;
    for input in &items.macro_inputs {
        rows = rows
            .saturating_add(1)
            .saturating_add(input.tree.tokens.len());
        payload = payload.saturating_add(input.tree.source.len());
        for token in &input.tree.tokens {
            payload = payload.saturating_add(token.syntax_kind.len());
        }
    }
    for definition in &items.macro_definitions {
        for arm in &definition.arms {
            rows = rows
                .saturating_add(1)
                .saturating_add(arm.patterns.len())
                .saturating_add(arm.ident_roles.len());
            for pattern in &arm.patterns {
                payload = payload.saturating_add(match &pattern.kind {
                    RustMacroPatternSourceKind::Literal { syntax_kind, text } => {
                        syntax_kind.len().saturating_add(text.len())
                    }
                    RustMacroPatternSourceKind::Binding { name, .. } => name.len(),
                    RustMacroPatternSourceKind::Group { .. }
                    | RustMacroPatternSourceKind::Invalid => 0,
                    RustMacroPatternSourceKind::Repetition { separator, .. } => {
                        separator.as_ref().map_or(0, |separator| separator.len())
                    }
                });
            }
            for role in &arm.ident_roles {
                payload = payload.saturating_add(role.name.len());
            }
        }
    }
    for group in &items.generics {
        rows = rows.saturating_add(group.parameters.len());
        for parameter in &group.parameters {
            payload = payload
                .saturating_add(parameter.kind.len())
                .saturating_add(parameter.name.as_ref().map_or(0, |name| name.name.len()));
        }
    }
    for children in items
        .impls
        .iter()
        .map(|item| &item.body_children)
        .chain(items.traits.iter().map(|item| &item.body_children))
    {
        rows = rows.saturating_add(children.len());
        for child in children {
            payload = payload.saturating_add(child.syntax_kind.len());
        }
    }
    for callable in &items.callables {
        rows = rows.saturating_add(callable.parameter_children.len());
        for parameter in &callable.parameter_children {
            payload = payload
                .saturating_add(parameter.syntax_kind.len())
                .saturating_add(parameter.label.as_ref().map_or(0, |label| label.name.len()));
        }
    }
    for ty in types {
        rows = rows.saturating_add(ty.wrappers.len());
        match &ty.shape {
            RustTypeSourceShape::Path { segments, .. } => {
                rows = rows.saturating_add(segments.len());
                for segment in segments {
                    payload = payload.saturating_add(segment.name.len());
                    if let Some(arguments) = &segment.generic_arguments {
                        rows = rows
                            .saturating_add(1)
                            .saturating_add(arguments.arguments.len());
                    }
                }
            }
            RustTypeSourceShape::Unsupported { syntax_kind, .. } => {
                payload = payload.saturating_add(syntax_kind.len());
            }
            RustTypeSourceShape::Compound { children, .. } => {
                rows = rows.saturating_add(children.len());
            }
        }
    }
    (rows, payload)
}

/// Insert the schema54 source-owned Rust item/type rows for one Rust blob.
///
/// The caller inserts source occurrences, declarations, and the existing
/// source-facts manifest before this function. Every row below uses the exact
/// producer-assigned identity and is written with a prepared statement so the
/// cancellation boundary remains per physical row.
pub(in crate::analyzer) fn insert_rust_item_source_facts_tx(
    tx: &Transaction<'_>,
    blob_id: i64,
    facts: &ParsedSourceFacts,
    cancellation: &CancellationToken,
) -> Result<()> {
    if facts.rust_modules.is_none() {
        assert!(
            facts.rust_types.is_empty(),
            "non-Rust facts contain Rust type rows"
        );
        assert!(
            facts.rust_items == RustItemSourceFacts::default(),
            "non-Rust facts contain Rust item rows"
        );
        return Ok(());
    }
    let item_facts = &facts.rust_items;
    let (logical_rows, payload_bytes) = rust_item_source_cost(item_facts, &facts.rust_types);
    check_cancelled(cancellation)?;
    tx.execute(
        "INSERT INTO source_rust_item_manifests(
           blob_id, facts_version, macro_facts_version, logical_rows, payload_bytes,
           type_forms_version, macro_contexts_version
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            blob_id,
            RUST_ITEM_SOURCE_FACTS_VERSION,
            RUST_MACRO_FACTS_VERSION,
            usize_to_i64(logical_rows)?,
            usize_to_i64(payload_bytes)?,
            RUST_TYPE_FORMS_VERSION,
            RUST_MACRO_CONTEXTS_VERSION,
        ],
    )?;

    let mut syntax = tx.prepare_cached(
        "INSERT INTO source_rust_item_syntax(
           blob_id, occurrence_id, has_error
         ) VALUES(?1, ?2, ?3)",
    )?;
    // Most occurrence ids below are either looked up in the arena for their
    // inline span or are foreign keys to rows whose ids were. The rest are
    // checked against the arena where they are written.
    let occurrence_count = facts.occurrences.occurrence_count();
    let assert_in_arena = |label: &str, id: SourceOccurrenceId| {
        assert!(
            id.index() < occurrence_count,
            "Rust {label} occurrence {id:?} is outside the blob's {occurrence_count} source occurrences"
        );
    };
    for row in &item_facts.syntax {
        check_cancelled(cancellation)?;
        assert_in_arena("item syntax", row.occurrence);
        syntax.execute(params![
            blob_id,
            i64::from(row.occurrence.get()),
            row.has_error
        ])?;
    }
    drop(syntax);

    // Spans go inline beside the occurrence id wherever a statement reads one
    // (milestone 5, lane ST); the arena is the facts value's own.
    let span_of = |occurrence: SourceOccurrenceId| {
        let range = facts.occurrences.occurrence(occurrence).range;
        (range.start_byte, range.end_byte)
    };
    let mut contexts = tx.prepare_cached(
        "INSERT INTO source_rust_item_contexts(
           blob_id, occurrence_id, ordinal, parent_occurrence_id,
           owner_declaration_id, context_kind, start_byte, end_byte, provenance
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    )?;
    for (ordinal, row) in item_facts.contexts.iter().enumerate() {
        check_cancelled(cancellation)?;
        contexts.execute(params![
            blob_id,
            i64::from(row.context.get()),
            usize_to_i64(ordinal)?,
            row.parent.map(|id| i64::from(id.get())),
            row.owner.map(|id| i64::from(id.get())),
            context_kind(row.kind),
            usize_to_i64(span_of(row.context).0)?,
            usize_to_i64(span_of(row.context).1)?,
            i64::from(super::provenance_code(
                facts.occurrences.occurrence(row.context).provenance,
            )),
        ])?;
    }
    drop(contexts);

    let mut impls = tx.prepare_cached(
        "INSERT INTO source_rust_impl_items(
           blob_id, declaration_id, context_occurrence_id, trait_type_occurrence_id, negation_occurrence_id, target_type_occurrence_id, body_occurrence_id, body_start_byte, body_end_byte, negation_start_byte, negation_end_byte
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
    )?;
    for row in &item_facts.impls {
        check_cancelled(cancellation)?;
        let inline_body_occurrence = (row.body).map(|id| facts.occurrences.occurrence(id));
        let inline_negation_occurrence = (row.negation).map(|id| facts.occurrences.occurrence(id));
        impls.execute(params![
            blob_id,
            i64::from(row.declaration.get()),
            i64::from(row.context.get()),
            row.trait_type.map(|id| i64::from(id.get())),
            row.negation.map(|id| i64::from(id.get())),
            row.target_type.map(|id| i64::from(id.get())),
            row.body.map(|id| i64::from(id.get())),
            inline_body_occurrence
                .map(|occurrence| usize_to_i64(occurrence.range.start_byte))
                .transpose()?,
            inline_body_occurrence
                .map(|occurrence| usize_to_i64(occurrence.range.end_byte))
                .transpose()?,
            inline_negation_occurrence
                .map(|occurrence| usize_to_i64(occurrence.range.start_byte))
                .transpose()?,
            inline_negation_occurrence
                .map(|occurrence| usize_to_i64(occurrence.range.end_byte))
                .transpose()?,
        ])?;
    }
    drop(impls);

    let mut traits = tx.prepare_cached(
        "INSERT INTO source_rust_trait_items(
           blob_id, declaration_id, context_occurrence_id, body_occurrence_id, body_start_byte, body_end_byte
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    for row in &item_facts.traits {
        check_cancelled(cancellation)?;
        let inline_body_occurrence = (row.body).map(|id| facts.occurrences.occurrence(id));
        traits.execute(params![
            blob_id,
            i64::from(row.declaration.get()),
            i64::from(row.context.get()),
            row.body.map(|id| i64::from(id.get())),
            inline_body_occurrence
                .map(|occurrence| usize_to_i64(occurrence.range.start_byte))
                .transpose()?,
            inline_body_occurrence
                .map(|occurrence| usize_to_i64(occurrence.range.end_byte))
                .transpose()?,
        ])?;
    }
    drop(traits);

    let mut aliases = tx.prepare_cached(
        "INSERT INTO source_rust_alias_items(
           blob_id, declaration_id, context_occurrence_id, target_type_occurrence_id
         ) VALUES(?1, ?2, ?3, ?4)",
    )?;
    for row in &item_facts.aliases {
        check_cancelled(cancellation)?;
        aliases.execute(params![
            blob_id,
            i64::from(row.declaration.get()),
            i64::from(row.context.get()),
            row.target_type.map(|id| i64::from(id.get())),
        ])?;
    }
    drop(aliases);

    let mut callables = tx.prepare_cached(
        "INSERT INTO source_rust_callable_items(
           blob_id, declaration_id, context_occurrence_id, parameters_occurrence_id, return_type_occurrence_id, parameters_start_byte, parameters_end_byte
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )?;
    for row in &item_facts.callables {
        check_cancelled(cancellation)?;
        let inline_parameters_occurrence =
            (row.parameters).map(|id| facts.occurrences.occurrence(id));
        callables.execute(params![
            blob_id,
            i64::from(row.declaration.get()),
            i64::from(row.context.get()),
            row.parameters.map(|id| i64::from(id.get())),
            row.return_type.map(|id| i64::from(id.get())),
            inline_parameters_occurrence
                .map(|occurrence| usize_to_i64(occurrence.range.start_byte))
                .transpose()?,
            inline_parameters_occurrence
                .map(|occurrence| usize_to_i64(occurrence.range.end_byte))
                .transpose()?,
        ])?;
    }
    drop(callables);

    let mut values = tx.prepare_cached(
        "INSERT INTO source_rust_value_items(
           blob_id, declaration_id, context_occurrence_id, declared_type_occurrence_id
         ) VALUES(?1, ?2, ?3, ?4)",
    )?;
    for row in &item_facts.values {
        check_cancelled(cancellation)?;
        values.execute(params![
            blob_id,
            i64::from(row.declaration.get()),
            i64::from(row.context.get()),
            row.declared_type.map(|id| i64::from(id.get())),
        ])?;
    }
    drop(values);

    let mut generic_parameters = tx.prepare_cached(
        "INSERT INTO source_rust_item_generic_parameters(
           blob_id, declaration_id, ordinal, occurrence_id, syntax_kind, name_occurrence_id, name, start_byte, end_byte, name_start_byte, name_end_byte
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
    )?;
    for group in &item_facts.generics {
        assert!(
            !group.parameters.is_empty(),
            "source generic groups contain at least one parameter"
        );
        for (ordinal, row) in group.parameters.iter().enumerate() {
            check_cancelled(cancellation)?;
            let inline_occurrence = facts.occurrences.occurrence(row.occurrence);
            let inline_name_occurrence = (row.name.as_ref().map(|name| name.occurrence))
                .map(|id| facts.occurrences.occurrence(id));
            generic_parameters.execute(params![
                blob_id,
                i64::from(group.declaration.get()),
                usize_to_i64(ordinal)?,
                i64::from(row.occurrence.get()),
                &row.kind,
                row.name
                    .as_ref()
                    .map(|name| i64::from(name.occurrence.get())),
                row.name.as_ref().map(|name| &name.name),
                usize_to_i64(inline_occurrence.range.start_byte)?,
                usize_to_i64(inline_occurrence.range.end_byte)?,
                inline_name_occurrence
                    .map(|occurrence| usize_to_i64(occurrence.range.start_byte))
                    .transpose()?,
                inline_name_occurrence
                    .map(|occurrence| usize_to_i64(occurrence.range.end_byte))
                    .transpose()?,
            ])?;
        }
    }
    drop(generic_parameters);

    let mut body_children = tx.prepare_cached(
        "INSERT INTO source_rust_item_body_children(
           blob_id, owner_declaration_id, ordinal, occurrence_id, declaration_id, syntax_kind, start_byte, end_byte
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )?;
    for (declaration, rows) in item_facts
        .impls
        .iter()
        .map(|row| (row.declaration, row.body_children.as_slice()))
        .chain(
            item_facts
                .traits
                .iter()
                .map(|row| (row.declaration, row.body_children.as_slice())),
        )
    {
        for (ordinal, row) in rows.iter().enumerate() {
            check_cancelled(cancellation)?;
            let inline_occurrence = facts.occurrences.occurrence(row.occurrence);
            body_children.execute(params![
                blob_id,
                i64::from(declaration.get()),
                usize_to_i64(ordinal)?,
                i64::from(row.occurrence.get()),
                row.declaration.map(|id| i64::from(id.get())),
                &row.syntax_kind,
                usize_to_i64(inline_occurrence.range.start_byte)?,
                usize_to_i64(inline_occurrence.range.end_byte)?,
            ])?;
        }
    }
    drop(body_children);

    let mut callable_parameters = tx.prepare_cached(
        "INSERT INTO source_rust_callable_parameters(
           blob_id, declaration_id, ordinal, occurrence_id, syntax_kind, label_occurrence_id, label, start_byte, end_byte, label_start_byte, label_end_byte
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
    )?;
    for row in &item_facts.callables {
        for (ordinal, parameter) in row.parameter_children.iter().enumerate() {
            check_cancelled(cancellation)?;
            let inline_occurrence = facts.occurrences.occurrence(parameter.occurrence);
            let inline_label_occurrence = (parameter.label.as_ref().map(|label| label.occurrence))
                .map(|id| facts.occurrences.occurrence(id));
            callable_parameters.execute(params![
                blob_id,
                i64::from(row.declaration.get()),
                usize_to_i64(ordinal)?,
                i64::from(parameter.occurrence.get()),
                &parameter.syntax_kind,
                parameter
                    .label
                    .as_ref()
                    .map(|label| i64::from(label.occurrence.get())),
                parameter.label.as_ref().map(|label| &label.name),
                usize_to_i64(inline_occurrence.range.start_byte)?,
                usize_to_i64(inline_occurrence.range.end_byte)?,
                inline_label_occurrence
                    .map(|occurrence| usize_to_i64(occurrence.range.start_byte))
                    .transpose()?,
                inline_label_occurrence
                    .map(|occurrence| usize_to_i64(occurrence.range.end_byte))
                    .transpose()?,
            ])?;
        }
    }
    drop(callable_parameters);

    let mut macros = tx.prepare_cached(
        "INSERT INTO source_rust_item_macro_expansions(
           blob_id, invocation_occurrence_id, context_occurrence_id,
           expansion_kind, root_occurrence_id, source_position,
           invocation_start_byte, invocation_end_byte
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )?;
    for row in &item_facts.macros {
        check_cancelled(cancellation)?;
        if let RustItemMacroExpansion::Parsed(root) = row.expansion {
            assert_in_arena("item macro expansion root", root);
        }
        let (kind, expansion) = macro_expansion_kind(row.expansion);
        macros.execute(params![
            blob_id,
            i64::from(row.invocation.get()),
            i64::from(row.context.get()),
            kind,
            expansion,
            match row.position {
                RustItemMacroSourcePosition::DirectItem => 0,
                RustItemMacroSourcePosition::ItemStatement => 1,
                RustItemMacroSourcePosition::Other => 2,
            },
            usize_to_i64(span_of(row.invocation).0)?,
            usize_to_i64(span_of(row.invocation).1)?,
        ])?;
    }
    drop(macros);
    let mut inputs = tx.prepare_cached("INSERT INTO source_rust_macro_inputs(blob_id, invocation_occurrence_id, start_byte, source, native_gap_site, native_scope, invocation_start_byte) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)")?;
    let mut tokens = tx.prepare_cached("INSERT INTO source_rust_macro_input_tokens(blob_id, invocation_occurrence_id, ordinal, parent_ordinal, syntax_kind, start_byte, end_byte, source_occurrence_id) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)")?;
    for input in &item_facts.macro_inputs {
        check_cancelled(cancellation)?;
        inputs.execute(params![
            blob_id,
            i64::from(input.invocation.get()),
            usize_to_i64(input.tree.start_byte)?,
            &input.tree.source,
            input.native_frontier.map(|(site, _)| i64::from(site.get())),
            input
                .native_frontier
                .map(|(_, scope)| i64::from(scope.get())),
            usize_to_i64(span_of(input.invocation).0)?,
        ])?;
        assert_eq!(
            input.tree.tokens.len(),
            input.occurrences.len(),
            "each macro token has source identity"
        );
        for (ordinal, token) in input.tree.tokens.iter().enumerate() {
            check_cancelled(cancellation)?;
            let source = facts
                .occurrences
                .occurrence(input.occurrences[ordinal])
                .range;
            assert!(
                (source.start_byte, source.end_byte) == (token.start_byte, token.end_byte),
                "macro input token {ordinal} {token:?} disagrees with its source occurrence {:?} {source:?}",
                input.occurrences[ordinal]
            );
            tokens.execute(params![
                blob_id,
                i64::from(input.invocation.get()),
                usize_to_i64(ordinal)?,
                token.parent.map(i64::from),
                &token.syntax_kind,
                usize_to_i64(token.start_byte)?,
                usize_to_i64(token.end_byte)?,
                i64::from(input.occurrences[ordinal].get()),
            ])?;
        }
    }
    drop(inputs);
    drop(tokens);

    let mut macro_definitions = tx.prepare_cached(
        "INSERT INTO source_rust_macro_definitions(
           blob_id, declaration_id, ordinal, is_macro_rules, context_occurrence_id
         ) VALUES(?1, ?2, ?3, ?4, ?5)",
    )?;
    let mut macro_arms = tx.prepare_cached(
        "INSERT INTO source_rust_macro_arms(
           blob_id, declaration_id, ordinal, occurrence_id, pattern_occurrence_id, start_byte, end_byte, provenance
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )?;
    let mut macro_pattern_nodes = tx.prepare_cached(
        "INSERT INTO source_rust_macro_pattern_nodes(
           blob_id, declaration_id, arm_ordinal, ordinal, occurrence_id, parent_occurrence_id, node_kind, literal_kind, literal_text, binding_name, fragment_kind, delimiter, separator, operator, start_byte, end_byte, provenance
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
    )?;
    let mut macro_ident_roles = tx.prepare_cached(
        "INSERT INTO source_rust_macro_ident_roles(
           blob_id, declaration_id, arm_ordinal, ordinal, name, role
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    for (definition_ordinal, definition) in item_facts.macro_definitions.iter().enumerate() {
        check_cancelled(cancellation)?;
        macro_definitions.execute(params![
            blob_id,
            i64::from(definition.declaration.get()),
            usize_to_i64(definition_ordinal)?,
            definition.is_macro_rules,
            i64::from(definition.context.get()),
        ])?;
        for (arm_ordinal, arm) in definition.arms.iter().enumerate() {
            check_cancelled(cancellation)?;
            let inline_occurrence = facts.occurrences.occurrence(arm.occurrence);
            macro_arms.execute(params![
                blob_id,
                i64::from(definition.declaration.get()),
                usize_to_i64(arm_ordinal)?,
                i64::from(arm.occurrence.get()),
                arm.pattern.map(|id| i64::from(id.get())),
                usize_to_i64(inline_occurrence.range.start_byte)?,
                usize_to_i64(inline_occurrence.range.end_byte)?,
                crate::analyzer::store::source_facts::provenance_code(inline_occurrence.provenance),
            ])?;
            for (pattern_ordinal, pattern) in arm.patterns.iter().enumerate() {
                check_cancelled(cancellation)?;
                let (
                    node_kind,
                    literal_kind,
                    literal_text,
                    binding_name,
                    fragment_kind,
                    delimiter,
                    separator,
                    operator,
                ) = match &pattern.kind {
                    RustMacroPatternSourceKind::Literal { syntax_kind, text } => (
                        0,
                        Some(syntax_kind),
                        Some(text),
                        None,
                        None,
                        None,
                        None,
                        None,
                    ),
                    RustMacroPatternSourceKind::Binding { name, fragment } => (
                        1,
                        None,
                        None,
                        Some(name),
                        Some(macro_fragment_kind(*fragment)),
                        None,
                        None,
                        None,
                    ),
                    RustMacroPatternSourceKind::Group { delimiter } => (
                        2,
                        None,
                        None,
                        None,
                        None,
                        macro_delimiter(*delimiter),
                        None,
                        None,
                    ),
                    RustMacroPatternSourceKind::Repetition {
                        separator,
                        operator,
                    } => (
                        3,
                        None,
                        None,
                        None,
                        None,
                        None,
                        separator.as_deref(),
                        Some(macro_repetition_operator(*operator)),
                    ),
                    RustMacroPatternSourceKind::Invalid => {
                        (4, None, None, None, None, None, None, None)
                    }
                };
                let inline_occurrence = facts.occurrences.occurrence(pattern.occurrence);
                macro_pattern_nodes.execute(params![
                    blob_id,
                    i64::from(definition.declaration.get()),
                    usize_to_i64(arm_ordinal)?,
                    usize_to_i64(pattern_ordinal)?,
                    i64::from(pattern.occurrence.get()),
                    pattern.parent.map(|id| i64::from(id.get())),
                    node_kind,
                    literal_kind,
                    literal_text,
                    binding_name,
                    fragment_kind,
                    delimiter,
                    separator,
                    operator,
                    usize_to_i64(inline_occurrence.range.start_byte)?,
                    usize_to_i64(inline_occurrence.range.end_byte)?,
                    crate::analyzer::store::source_facts::provenance_code(
                        inline_occurrence.provenance
                    ),
                ])?;
            }
            for (role_ordinal, role) in arm.ident_roles.iter().enumerate() {
                check_cancelled(cancellation)?;
                macro_ident_roles.execute(params![
                    blob_id,
                    i64::from(definition.declaration.get()),
                    usize_to_i64(arm_ordinal)?,
                    usize_to_i64(role_ordinal)?,
                    &role.name,
                    macro_ident_role(role.role),
                ])?;
            }
        }
    }
    drop(macro_definitions);
    drop(macro_arms);
    drop(macro_pattern_nodes);
    drop(macro_ident_roles);

    let mut import_contexts = tx.prepare_cached(
        "INSERT INTO source_rust_item_import_contexts(
           blob_id, declaration_occurrence_id, context_occurrence_id
         ) VALUES(?1, ?2, ?3)",
    )?;
    for row in &item_facts.import_contexts {
        check_cancelled(cancellation)?;
        assert_in_arena("item import declaration", row.declaration);
        import_contexts.execute(params![
            blob_id,
            i64::from(row.declaration.get()),
            i64::from(row.context.get()),
        ])?;
    }
    drop(import_contexts);

    let mut type_headers = tx.prepare_cached(
        "INSERT INTO source_rust_types(
           blob_id, occurrence_id, path_kind, leading_absolute, unsupported_occurrence_id, unsupported_syntax_kind, compound_occurrence_id, type_parameters_occurrence_id, start_byte, end_byte, provenance, unsupported_start_byte, unsupported_end_byte, unsupported_provenance, compound_start_byte, compound_end_byte, compound_provenance, type_parameters_start_byte, type_parameters_end_byte, type_parameters_provenance
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
    )?;
    for row in facts.rust_types.iter() {
        check_cancelled(cancellation)?;
        let (leading_absolute, unsupported_occurrence, unsupported, compound, parameters) =
            match &row.shape {
                RustTypeSourceShape::Path {
                    leading_absolute, ..
                } => (Some(i64::from(*leading_absolute)), None, None, None, None),
                RustTypeSourceShape::Unsupported {
                    occurrence,
                    syntax_kind,
                } => (None, Some(*occurrence), Some(syntax_kind), None, None),
                RustTypeSourceShape::Compound {
                    occurrence,
                    type_parameters,
                    ..
                } => (None, None, None, Some(*occurrence), *type_parameters),
            };
        let inline_occurrence = facts.occurrences.occurrence(row.occurrence);
        let inline_unsupported_occurrence =
            (unsupported_occurrence).map(|id| facts.occurrences.occurrence(id));
        let inline_compound_occurrence = (compound).map(|id| facts.occurrences.occurrence(id));
        let inline_type_parameters_occurrence =
            (parameters).map(|id| facts.occurrences.occurrence(id));
        type_headers.execute(params![
            blob_id,
            i64::from(row.occurrence.get()),
            path_kind(&row.shape),
            leading_absolute,
            unsupported_occurrence.map(|id| i64::from(id.get())),
            unsupported,
            compound.map(|id| i64::from(id.get())),
            parameters.map(|id| i64::from(id.get())),
            usize_to_i64(inline_occurrence.range.start_byte)?,
            usize_to_i64(inline_occurrence.range.end_byte)?,
            crate::analyzer::store::source_facts::provenance_code(inline_occurrence.provenance),
            inline_unsupported_occurrence
                .map(|occurrence| usize_to_i64(occurrence.range.start_byte))
                .transpose()?,
            inline_unsupported_occurrence
                .map(|occurrence| usize_to_i64(occurrence.range.end_byte))
                .transpose()?,
            inline_unsupported_occurrence.map(|occurrence| {
                crate::analyzer::store::source_facts::provenance_code(occurrence.provenance)
            }),
            inline_compound_occurrence
                .map(|occurrence| usize_to_i64(occurrence.range.start_byte))
                .transpose()?,
            inline_compound_occurrence
                .map(|occurrence| usize_to_i64(occurrence.range.end_byte))
                .transpose()?,
            inline_compound_occurrence.map(|occurrence| {
                crate::analyzer::store::source_facts::provenance_code(occurrence.provenance)
            }),
            inline_type_parameters_occurrence
                .map(|occurrence| usize_to_i64(occurrence.range.start_byte))
                .transpose()?,
            inline_type_parameters_occurrence
                .map(|occurrence| usize_to_i64(occurrence.range.end_byte))
                .transpose()?,
            inline_type_parameters_occurrence.map(|occurrence| {
                crate::analyzer::store::source_facts::provenance_code(occurrence.provenance)
            }),
        ])?;
    }
    drop(type_headers);

    let mut type_children = tx.prepare_cached(
        "INSERT INTO source_rust_type_children(
           blob_id, type_occurrence_id, ordinal, occurrence_id
         ) VALUES(?1, ?2, ?3, ?4)",
    )?;
    for row in &facts.rust_types {
        check_cancelled(cancellation)?;
        let RustTypeSourceShape::Compound { children, .. } = &row.shape else {
            continue;
        };
        for (ordinal, child) in children.iter().enumerate() {
            check_cancelled(cancellation)?;
            type_children.execute(params![
                blob_id,
                i64::from(row.occurrence.get()),
                usize_to_i64(ordinal)?,
                i64::from(child.get()),
            ])?;
        }
    }
    drop(type_children);

    let mut type_wrappers = tx.prepare_cached(
        "INSERT INTO source_rust_type_wrappers(
           blob_id, type_occurrence_id, ordinal, occurrence_id, wrapper_kind, start_byte, end_byte, provenance
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )?;
    for row in &facts.rust_types {
        for (ordinal, wrapper) in row.wrappers.iter().enumerate() {
            check_cancelled(cancellation)?;
            let inline_occurrence = facts.occurrences.occurrence(wrapper.occurrence);
            type_wrappers.execute(params![
                blob_id,
                i64::from(row.occurrence.get()),
                usize_to_i64(ordinal)?,
                i64::from(wrapper.occurrence.get()),
                wrapper_kind(wrapper.kind),
                usize_to_i64(inline_occurrence.range.start_byte)?,
                usize_to_i64(inline_occurrence.range.end_byte)?,
                crate::analyzer::store::source_facts::provenance_code(inline_occurrence.provenance),
            ])?;
        }
    }
    drop(type_wrappers);

    let mut type_segments = tx.prepare_cached(
        "INSERT INTO source_rust_type_segments(
           blob_id, type_occurrence_id, ordinal, occurrence_id, name, start_byte, end_byte, provenance
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )?;
    let mut type_generic_lists = tx.prepare_cached(
        "INSERT INTO source_rust_type_generic_lists(
           blob_id, type_occurrence_id, segment_ordinal, occurrence_id, start_byte, end_byte, provenance
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )?;
    let mut type_generic_arguments = tx.prepare_cached(
        "INSERT INTO source_rust_type_generic_arguments(
           blob_id, type_occurrence_id, segment_ordinal, ordinal,
           occurrence_id
         ) VALUES(?1, ?2, ?3, ?4, ?5)",
    )?;
    for row in &facts.rust_types {
        let RustTypeSourceShape::Path { segments, .. } = &row.shape else {
            continue;
        };
        for (segment_ordinal, segment) in segments.iter().enumerate() {
            check_cancelled(cancellation)?;
            let inline_occurrence = facts.occurrences.occurrence(segment.occurrence);
            type_segments.execute(params![
                blob_id,
                i64::from(row.occurrence.get()),
                usize_to_i64(segment_ordinal)?,
                i64::from(segment.occurrence.get()),
                &segment.name,
                usize_to_i64(inline_occurrence.range.start_byte)?,
                usize_to_i64(inline_occurrence.range.end_byte)?,
                crate::analyzer::store::source_facts::provenance_code(inline_occurrence.provenance),
            ])?;
            let Some(generic_arguments) = segment.generic_arguments.as_ref() else {
                continue;
            };
            check_cancelled(cancellation)?;
            let inline_occurrence = facts.occurrences.occurrence(generic_arguments.occurrence);
            type_generic_lists.execute(params![
                blob_id,
                i64::from(row.occurrence.get()),
                usize_to_i64(segment_ordinal)?,
                i64::from(generic_arguments.occurrence.get()),
                usize_to_i64(inline_occurrence.range.start_byte)?,
                usize_to_i64(inline_occurrence.range.end_byte)?,
                crate::analyzer::store::source_facts::provenance_code(inline_occurrence.provenance),
            ])?;
            for (ordinal, argument) in generic_arguments.arguments.iter().enumerate() {
                check_cancelled(cancellation)?;
                type_generic_arguments.execute(params![
                    blob_id,
                    i64::from(row.occurrence.get()),
                    usize_to_i64(segment_ordinal)?,
                    usize_to_i64(ordinal)?,
                    i64::from(argument.get()),
                ])?;
            }
        }
    }
    drop(type_segments);
    drop(type_generic_lists);
    drop(type_generic_arguments);
    Ok(())
}
