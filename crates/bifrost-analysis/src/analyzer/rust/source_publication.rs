//! Relational publication of Rust's canonical source-owned families.
//!
//! Rust has one source publication capability.  It owns the Rust extension
//! rows and their admission accounting; the shared source writer owns the
//! common manifest, transaction, and final publication seal.

use brokk_bifrost_core::analyzer::parsed_file::ParsedSourceFacts;
use brokk_bifrost_core::analyzer::rust_facts::{
    RustDeclarationBoundary, RustDeclarationKind, RustModuleSourceFacts,
};
use brokk_bifrost_core::hash::HashMap;
use rusqlite::{Transaction, params};

use crate::CancellationToken;
use crate::analyzer::store::source_facts::{check_cancelled, rust_items};
use crate::analyzer::store::{Result, SourceFactStorage, usize_to_i64};

pub(in crate::analyzer) use rust_items::{
    RUST_ITEM_SOURCE_FACTS_VERSION, RUST_MACRO_CONTEXTS_VERSION, RUST_MACRO_FACTS_VERSION,
    RUST_TYPE_FORMS_VERSION, rust_item_source_cost,
};

pub(crate) const RUST_MODULE_SOURCE_FACTS_VERSION: i64 = 1;

/// Rust owns the formulas for these legacy shared-manifest columns. The common
/// source writer leaves their schema defaults in place; this capability fills
/// them before the shared publication seal validates the complete families.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RustManifestCounts {
    pub import_contexts: usize,
    pub declaration_properties: usize,
    pub constructor_fields: usize,
}

pub(crate) static SOURCE_STORAGE: SourceFactStorage = SourceFactStorage {
    cost: |source| source.rust_modules.as_ref().map(|_| cost(source)),
    insert,
};

pub(crate) fn rust_manifest_counts(facts: &ParsedSourceFacts) -> RustManifestCounts {
    let constructor_fields = facts
        .rust_declaration_properties
        .iter()
        .filter_map(|property| property.value_constructor.as_ref())
        .map(|constructor| constructor.field_visibilities.len())
        .fold(0usize, usize::saturating_add);
    RustManifestCounts {
        import_contexts: facts.rust_import_contexts.len(),
        declaration_properties: facts.rust_declaration_properties.len(),
        constructor_fields,
    }
}

/// Return the physical Rust extension cost, including every Rust marker.
/// `None` is an unavailable Rust family; `Some(empty)` is a valid published
/// family only when the producer supplied the module marker and all extension
/// rows are empty.
pub(crate) fn cost(facts: &ParsedSourceFacts) -> (usize, usize) {
    assert!(
        facts.rust_modules.is_some(),
        "Rust source publication cost requires the Rust module family"
    );
    let (module_rows, module_payload) = rust_module_source_cost(facts);
    let (item_rows, item_payload) = rust_item_source_cost(&facts.rust_items, &facts.rust_types);
    let counts = rust_manifest_counts(facts);
    let context_payload = facts
        .rust_import_contexts
        .iter()
        .map(|context| {
            context
                .owner_module
                .len()
                .saturating_add(
                    brokk_bifrost_core::analyzer::rust_facts::encode_rust_visibility(
                        &context.visibility,
                    )
                    .len(),
                )
                .saturating_add(
                    brokk_bifrost_core::analyzer::rust_facts::encode_rust_cfg_condition(
                        &context.cfg_condition,
                    )
                    .len(),
                )
        })
        .fold(0usize, usize::saturating_add);
    let property_payload = facts
        .rust_declaration_properties
        .iter()
        .map(|property| {
            brokk_bifrost_core::analyzer::rust_facts::encode_rust_visibility(&property.visibility)
                .len()
                .saturating_add(
                    brokk_bifrost_core::analyzer::rust_facts::encode_rust_cfg_condition(
                        &property.cfg_condition,
                    )
                    .len(),
                )
                .saturating_add(
                    property
                        .value_constructor
                        .as_ref()
                        .map_or(0, |constructor| {
                            constructor
                                .field_visibilities
                                .iter()
                                .map(|visibility| {
                                    brokk_bifrost_core::analyzer::rust_facts::encode_rust_visibility(
                                        visibility,
                                    )
                                    .len()
                                })
                                .fold(0usize, usize::saturating_add)
                        }),
                )
        })
        .fold(0usize, usize::saturating_add);
    let extension_rows = counts
        .import_contexts
        .saturating_add(counts.declaration_properties)
        .saturating_add(counts.constructor_fields)
        .saturating_add(module_rows)
        .saturating_add(item_rows);
    (
        extension_rows,
        context_payload
            .saturating_add(property_payload)
            .saturating_add(module_payload)
            .saturating_add(item_payload),
    )
}

fn encode_rust_declaration_boundary(boundary: RustDeclarationBoundary) -> i64 {
    match boundary {
        RustDeclarationBoundary::ModuleOrFile => 0,
        RustDeclarationBoundary::LocalBlockOrFunction => 1,
        RustDeclarationBoundary::Impl => 2,
        RustDeclarationBoundary::Trait => 3,
    }
}

fn encode_rust_declaration_kind(kind: RustDeclarationKind) -> i64 {
    match kind {
        RustDeclarationKind::Struct => 0,
        RustDeclarationKind::Enum => 1,
        RustDeclarationKind::Union => 2,
        RustDeclarationKind::Trait => 3,
        RustDeclarationKind::InlineModule => 4,
        RustDeclarationKind::ExternalModule => 5,
        RustDeclarationKind::Function => 6,
        RustDeclarationKind::FunctionSignature => 7,
        RustDeclarationKind::Field => 8,
        RustDeclarationKind::EnumVariant => 9,
        RustDeclarationKind::Const => 10,
        RustDeclarationKind::Static => 11,
        RustDeclarationKind::Macro => 12,
        RustDeclarationKind::TypeAlias => 13,
        RustDeclarationKind::AssociatedType => 14,
    }
}

fn insert(
    tx: &Transaction<'_>,
    blob_id: i64,
    facts: &ParsedSourceFacts,
    cancellation: &CancellationToken,
) -> Result<()> {
    let Some(module_facts) = facts.rust_modules.as_ref() else {
        assert!(facts.rust_import_contexts.is_empty());
        assert!(facts.rust_declaration_properties.is_empty());
        assert!(facts.rust_types.is_empty());
        assert_eq!(facts.rust_items, Default::default());
        return Ok(());
    };

    // Spans go inline beside the occurrence id wherever a statement reads one
    // (milestone 5, lane ST). The arena is the facts value's own.
    let span_of = |occurrence: brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceId| {
        let range = facts.occurrences.occurrence(occurrence).range;
        (range.start_byte, range.end_byte)
    };

    let mut import_contexts = tx.prepare_cached(
        "INSERT INTO source_rust_import_contexts(
           blob_id, declaration_occurrence_id, owner_module, owner_scope_occurrence_id, local_scope_occurrence_id, visibility, cfg_condition, native_scope, owner_scope_start_byte, owner_scope_end_byte, local_scope_start_byte, local_scope_end_byte, declaration_start_byte, declaration_end_byte
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
    )?;
    for context in &facts.rust_import_contexts {
        check_cancelled(cancellation)?;
        let inline_declaration_occurrence = facts.occurrences.occurrence(context.declaration);
        import_contexts.execute(params![
            blob_id,
            i64::from(context.declaration.get()),
            &context.owner_module,
            context.owner_scope.map(|id| i64::from(id.get())),
            context.local_scope.map(|id| i64::from(id.get())),
            brokk_bifrost_core::analyzer::rust_facts::encode_rust_visibility(&context.visibility),
            brokk_bifrost_core::analyzer::rust_facts::encode_rust_cfg_condition(
                &context.cfg_condition,
            ),
            context.native_scope.map(|scope| i64::from(scope.get())),
            context
                .owner_scope
                .map(span_of)
                .map(|(start, _)| usize_to_i64(start))
                .transpose()?,
            context
                .owner_scope
                .map(span_of)
                .map(|(_, end)| usize_to_i64(end))
                .transpose()?,
            context
                .local_scope
                .map(span_of)
                .map(|(start, _)| usize_to_i64(start))
                .transpose()?,
            context
                .local_scope
                .map(span_of)
                .map(|(_, end)| usize_to_i64(end))
                .transpose()?,
            usize_to_i64(inline_declaration_occurrence.range.start_byte)?,
            usize_to_i64(inline_declaration_occurrence.range.end_byte)?,
        ])?;
    }
    drop(import_contexts);

    let mut properties = tx.prepare_cached(
        "INSERT INTO source_rust_declaration_properties(
           blob_id, declaration_id, visibility, cfg_condition, constructor_non_exhaustive,
           declaration_kind, macro_exported, trait_impl_member,
           has_impl_or_trait_ancestor, nearest_declaration_boundary, serde_helper_derive
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
    )?;
    let mut constructor_fields = tx.prepare_cached(
        "INSERT INTO source_rust_constructor_fields(blob_id, declaration_id, ordinal, visibility)
         VALUES(?1, ?2, ?3, ?4)",
    )?;
    for property in &facts.rust_declaration_properties {
        check_cancelled(cancellation)?;
        let declaration = i64::from(property.declaration.get());
        properties.execute(params![
            blob_id,
            declaration,
            brokk_bifrost_core::analyzer::rust_facts::encode_rust_visibility(&property.visibility),
            brokk_bifrost_core::analyzer::rust_facts::encode_rust_cfg_condition(
                &property.cfg_condition,
            ),
            property
                .value_constructor
                .as_ref()
                .map(|constructor| constructor.non_exhaustive),
            encode_rust_declaration_kind(property.kind),
            property.macro_exported,
            property.trait_impl_member,
            property.has_impl_or_trait_ancestor,
            encode_rust_declaration_boundary(property.nearest_declaration_boundary),
            property.serde_helper_derive.map(|derive| derive.name()),
        ])?;
        if let Some(constructor) = &property.value_constructor {
            for (ordinal, visibility) in constructor.field_visibilities.iter().enumerate() {
                check_cancelled(cancellation)?;
                constructor_fields.execute(params![
                    blob_id,
                    declaration,
                    usize_to_i64(ordinal)?,
                    brokk_bifrost_core::analyzer::rust_facts::encode_rust_visibility(visibility),
                ])?;
            }
        }
    }
    drop((properties, constructor_fields));

    insert_rust_module_source_facts_tx(tx, blob_id, module_facts, facts, cancellation)?;
    rust_items::insert_rust_item_source_facts_tx(tx, blob_id, facts, cancellation)?;
    let counts = rust_manifest_counts(facts);
    tx.execute(
        "UPDATE source_fact_manifests
         SET rust_import_context_count = ?2,
             rust_declaration_property_count = ?3,
             rust_constructor_field_count = ?4
         WHERE blob_id = ?1",
        params![
            blob_id,
            usize_to_i64(counts.import_contexts)?,
            usize_to_i64(counts.declaration_properties)?,
            usize_to_i64(counts.constructor_fields)?,
        ],
    )?;
    Ok(())
}

fn rust_module_source_cost(facts: &ParsedSourceFacts) -> (usize, usize) {
    let Some(modules) = facts.rust_modules.as_ref() else {
        return (0, 0);
    };
    assert!(
        !modules.inventory.is_empty(),
        "canonical Rust module inventory is nonempty"
    );

    let mut declaration_names = HashMap::default();
    for declaration in &modules.declarations {
        assert!(
            declaration_names
                .insert(declaration.declaration, declaration.name.as_str())
                .is_none(),
            "one canonical module declaration name per source declaration"
        );
    }

    let mut scope_name_lengths: Vec<usize> = Vec::with_capacity(modules.scopes.len());
    for (ordinal, scope) in modules.scopes.iter().enumerate() {
        if ordinal == 0 {
            assert!(scope.parent.is_none(), "Rust module root has no parent");
            assert!(
                scope.declaration.is_none(),
                "Rust module root has no declaration"
            );
            scope_name_lengths.push(0);
            continue;
        }
        let parent = scope
            .parent
            .expect("non-root Rust module scope has a parent");
        assert!(
            parent < ordinal,
            "Rust module scopes are parent-before-child"
        );
        let declaration = scope
            .declaration
            .expect("non-root Rust module scope has a declaration");
        let name = declaration_names
            .get(&declaration)
            .copied()
            .expect("module scope declaration has a canonical name");
        let full_name_length = if scope_name_lengths[parent] == 0 {
            name.len()
        } else {
            scope_name_lengths[parent]
                .saturating_add(1)
                .saturating_add(name.len())
        };
        scope_name_lengths.push(full_name_length);
    }

    let declaration_payload = modules
        .declarations
        .iter()
        .map(|declaration| {
            declaration
                .name
                .len()
                .saturating_add(declaration.path_attribute.as_ref().map_or(0, String::len))
        })
        .fold(0usize, usize::saturating_add);
    let invocation_payload = modules
        .invocations
        .iter()
        .map(|invocation| invocation.name.len())
        .fold(0usize, usize::saturating_add);
    let scope_payload = scope_name_lengths
        .iter()
        .copied()
        .fold(0usize, usize::saturating_add);
    let inventory_payload = modules
        .inventory
        .iter()
        .enumerate()
        .map(|(ordinal, inventory)| {
            if ordinal == 0 {
                assert!(
                    inventory.declaration.is_none(),
                    "Rust module inventory root has no declaration"
                );
                assert_eq!(
                    inventory.parent_scope, 0,
                    "Rust module inventory root scope is zero"
                );
                return 0;
            }
            let declaration = inventory
                .declaration
                .expect("non-root Rust module inventory has a declaration");
            assert!(
                inventory.parent_scope < scope_name_lengths.len(),
                "Rust module inventory parent scope exists"
            );
            let name = declaration_names
                .get(&declaration)
                .copied()
                .expect("module inventory declaration has a canonical name");
            if scope_name_lengths[inventory.parent_scope] == 0 {
                name.len()
            } else {
                scope_name_lengths[inventory.parent_scope]
                    .saturating_add(1)
                    .saturating_add(name.len())
            }
        })
        .fold(0usize, usize::saturating_add);
    let gate_count = modules
        .routes
        .iter()
        .map(|route| route.gates.len())
        .fold(0usize, usize::saturating_add);
    let logical_rows = 1usize
        .saturating_add(modules.declarations.len())
        .saturating_add(modules.invocations.len())
        .saturating_add(modules.scopes.len())
        .saturating_add(modules.inventory.len())
        .saturating_add(modules.routes.len())
        .saturating_add(gate_count);
    (
        logical_rows,
        declaration_payload
            .saturating_add(invocation_payload)
            .saturating_add(scope_payload)
            .saturating_add(inventory_payload),
    )
}

fn insert_rust_module_source_facts_tx(
    tx: &Transaction<'_>,
    blob_id: i64,
    module_facts: &RustModuleSourceFacts,
    facts: &ParsedSourceFacts,
    cancellation: &CancellationToken,
) -> Result<()> {
    check_cancelled(cancellation)?;
    let (inventory, scopes, routes) =
        module_facts.materialize(&facts.occurrences, &facts.rust_declaration_properties);
    assert_eq!(
        inventory.len(),
        module_facts.inventory.len(),
        "canonical Rust module inventory materializes one row per source entry"
    );
    assert_eq!(
        scopes.len(),
        module_facts.scopes.len(),
        "canonical Rust module scopes materialize one row per source entry"
    );
    assert_eq!(
        routes.len(),
        module_facts.routes.len(),
        "canonical Rust module routes materialize one row per source entry"
    );
    check_cancelled(cancellation)?;

    let span_of = |occurrence: brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceId| {
        let range = facts.occurrences.occurrence(occurrence).range;
        (range.start_byte, range.end_byte)
    };
    let (root_start, root_end) = span_of(module_facts.root);
    tx.execute(
        "INSERT INTO source_rust_module_manifests(
           blob_id, facts_version, root_occurrence_id, root_start_byte, root_end_byte, root_provenance
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            blob_id,
            RUST_MODULE_SOURCE_FACTS_VERSION,
            i64::from(module_facts.root.get()),
            usize_to_i64(root_start)?,
            usize_to_i64(root_end)?,
            crate::analyzer::store::source_facts::provenance_code(facts.occurrences.occurrence(module_facts.root).provenance),
        ],
    )?;

    let mut attributes = tx.prepare_cached(
        "INSERT INTO source_rust_inner_attributes(blob_id, ordinal, name, arguments)
         VALUES(?1, ?2, ?3, ?4)",
    )?;
    for (ordinal, attribute) in module_facts.inner_attributes.iter().enumerate() {
        check_cancelled(cancellation)?;
        attributes.execute(params![
            blob_id,
            usize_to_i64(ordinal)?,
            &attribute.name,
            serde_json::to_string(&attribute.arguments)
                .expect("attribute arguments serialize as a JSON array of strings"),
        ])?;
    }

    let mut declarations = tx.prepare_cached(
        "INSERT INTO source_rust_module_declarations(
           blob_id, declaration_id, module_name, body_occurrence_id, path_attribute, macro_use, test_gated, body_start_byte, body_end_byte, body_provenance
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
    )?;
    for declaration in &module_facts.declarations {
        check_cancelled(cancellation)?;
        let inline_body_occurrence = (declaration.body).map(|id| facts.occurrences.occurrence(id));
        declarations.execute(params![
            blob_id,
            i64::from(declaration.declaration.get()),
            &declaration.name,
            declaration
                .body
                .map(|occurrence| i64::from(occurrence.get())),
            &declaration.path_attribute,
            i64::from(declaration.macro_use),
            i64::from(declaration.test_gated),
            declaration
                .body
                .map(span_of)
                .map(|(start, _)| usize_to_i64(start))
                .transpose()?,
            declaration
                .body
                .map(span_of)
                .map(|(_, end)| usize_to_i64(end))
                .transpose()?,
            inline_body_occurrence.map(|occurrence| {
                crate::analyzer::store::source_facts::provenance_code(occurrence.provenance)
            }),
        ])?;
    }
    drop(declarations);

    let mut invocations = tx.prepare_cached(
        "INSERT INTO source_rust_macro_invocations(
           blob_id, occurrence_id, macro_name, start_byte, end_byte, provenance
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    for invocation in &module_facts.invocations {
        check_cancelled(cancellation)?;
        let (start_byte, end_byte) = span_of(invocation.occurrence);
        let inline_occurrence = facts.occurrences.occurrence(invocation.occurrence);
        invocations.execute(params![
            blob_id,
            i64::from(invocation.occurrence.get()),
            &invocation.name,
            usize_to_i64(start_byte)?,
            usize_to_i64(end_byte)?,
            crate::analyzer::store::source_facts::provenance_code(inline_occurrence.provenance),
        ])?;
    }
    drop(invocations);

    let mut scope_names: Vec<String> = Vec::with_capacity(scopes.len());
    let mut scope_rows = tx.prepare_cached(
        "INSERT INTO source_rust_module_scopes(
           blob_id, ordinal, parent_ordinal, declaration_id, module_name,
           imports_macros, resolution_scope
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )?;
    for (ordinal, scope) in scopes.iter().enumerate() {
        check_cancelled(cancellation)?;
        let full_name = if ordinal == 0 {
            assert!(scope.parent.is_none(), "Rust module root has no parent");
            assert!(
                module_facts.scopes[ordinal].declaration.is_none(),
                "Rust module root has no declaration"
            );
            String::new()
        } else {
            let parent = scope
                .parent
                .expect("non-root Rust module scope has a parent");
            assert!(
                parent < ordinal,
                "Rust module scopes are parent-before-child"
            );
            if scope_names[parent].is_empty() {
                scope.module_name.clone()
            } else {
                format!("{}.{}", scope_names[parent], scope.module_name)
            }
        };
        scope_names.push(full_name.clone());
        let source_scope = &module_facts.scopes[ordinal];
        scope_rows.execute(params![
            blob_id,
            usize_to_i64(ordinal)?,
            scope.parent.map(usize_to_i64).transpose()?,
            source_scope
                .declaration
                .map(|declaration| i64::from(declaration.get())),
            full_name,
            i64::from(scope.imports_macros),
            scope
                .resolution_scope
                .map(|resolution_scope| i64::from(resolution_scope.get())),
        ])?;
    }
    drop(scope_rows);

    let mut inventory_rows = tx.prepare_cached(
        "INSERT INTO source_rust_module_inventory(
           blob_id, ordinal, parent_scope_ordinal, declaration_id, module_name
         ) VALUES(?1, ?2, ?3, ?4, ?5)",
    )?;
    for (ordinal, (module, source_inventory)) in
        inventory.iter().zip(&module_facts.inventory).enumerate()
    {
        check_cancelled(cancellation)?;
        if ordinal == 0 {
            assert!(
                source_inventory.declaration.is_none(),
                "Rust module inventory root has no declaration"
            );
            assert_eq!(source_inventory.parent_scope, 0);
        } else {
            assert!(
                source_inventory.declaration.is_some(),
                "non-root Rust module inventory has a declaration"
            );
        }
        assert!(
            source_inventory.parent_scope < scopes.len(),
            "Rust module inventory parent scope exists"
        );
        inventory_rows.execute(params![
            blob_id,
            usize_to_i64(ordinal)?,
            usize_to_i64(source_inventory.parent_scope)?,
            source_inventory
                .declaration
                .map(|declaration| i64::from(declaration.get())),
            &module.module_name,
        ])?;
    }
    drop(inventory_rows);

    let mut route_rows = tx.prepare_cached(
        "INSERT INTO source_rust_module_routes(
           blob_id, ordinal, scope_ordinal, declaration_id, imports_macros
         ) VALUES(?1, ?2, ?3, ?4, ?5)",
    )?;
    let mut gate_rows = tx.prepare_cached(
        "INSERT INTO source_rust_module_route_gates(
           blob_id, route_ordinal, gate_ordinal, invocation_occurrence_id
         ) VALUES(?1, ?2, ?3, ?4)",
    )?;
    for (ordinal, (route, source_route)) in routes.iter().zip(&module_facts.routes).enumerate() {
        check_cancelled(cancellation)?;
        assert_eq!(
            route.scope, source_route.scope,
            "canonical Rust module route scope is stable during materialization"
        );
        assert!(
            route.scope < scopes.len(),
            "canonical Rust module route scope exists"
        );
        route_rows.execute(params![
            blob_id,
            usize_to_i64(ordinal)?,
            usize_to_i64(route.scope)?,
            i64::from(source_route.declaration.get()),
            i64::from(route.imports_macros),
        ])?;
        for (gate_ordinal, occurrence) in source_route.gates.iter().enumerate() {
            check_cancelled(cancellation)?;
            gate_rows.execute(params![
                blob_id,
                usize_to_i64(ordinal)?,
                usize_to_i64(gate_ordinal)?,
                i64::from(occurrence.get()),
            ])?;
        }
    }
    drop(route_rows);
    drop(gate_rows);
    Ok(())
}
