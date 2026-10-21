//! Rust selection rules over the shared modeled callable surface.

use crate::analyzer::rust::native_points;

use crate::analyzer::rust::rust_import_binder_visible_at_byte;

use crate::analyzer::semantic_model::{
    SemanticModelCallApplication, SemanticModelCallableDisposition, SemanticModelCallableKey,
    SemanticModelSymbol, SemanticModelSymbolKind, TypeRef, symbol_kind_is_callable,
};
use brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome;

use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;

use brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::query_token::QueryScope;

use brokk_bifrost_core::analyzer::model::Range;

use crate::analyzer::RustAnalyzer;

use crate::analyzer::RustOverlayCrates;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
use brokk_bifrost_rust::declarations::rust_node_text;
use brokk_bifrost_rust::lexical_scope::rust_lexical_scope_index;
use brokk_bifrost_rust::prelude::{
    RustEdition, RustPreludeCrate, RustPreludeNamespace, rust_prelude_name,
};

/// A trait fixed by a UFCS path, with its structurally selected type arguments.
pub(crate) struct UfcsTrait<'tree> {
    pub owner: String,
    pub arguments: Option<Vec<tree_sitter::Node<'tree>>>,
}

/// Return the declaring owner, never the written receiver owner, of one
/// applicable member. All collections belong to this call query only.
#[allow(clippy::too_many_arguments)]
pub(crate) fn select<'analyzer>(
    analyzer: &'analyzer dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    site: &ResolvedReferenceSite,
    owner: &str,
    has_receiver: bool,
    parameter_count: u32,
    factory: Option<&native_points::RustDefinitionOperationFactory<'analyzer>>,
    mut operation: Option<&mut SelectedResolutionOperation<'analyzer, '_>>,
    named_trait: Option<&UfcsTrait<'_>>,
) -> Option<String> {
    let overlay = analyzer.semantic_model_overlay()?;
    let active = analyzer.active_semantic_models()?;
    let owner = RustOverlayCrates::new(Some(&overlay)).referenceable_symbol(owner)?;
    let rust = resolve_analyzer::<RustAnalyzer>(analyzer)?;
    let scope = AnalyzerQueryScope::new(analyzer);
    let prepared = rust.prepared_syntax(scope.token(), file)?;
    if prepared.source() != source {
        crate::analyzer::rust::std_types::incomplete_proof("source_mismatch");
        return None;
    }
    let tree = prepared.tree();
    let callee = crate::analyzer::rust::external_calls::call_path_for_site(tree, site)?;
    let terminal = callee
        .child_by_field_name("field")
        .or_else(|| callee.child_by_field_name("name"))?;
    let member = rust_node_text(terminal, source);
    let application = SemanticModelCallApplication::positional(parameter_count);
    let callable_on = |declaring: &SemanticModelSymbol| {
        overlay.callable_for_application(
            SemanticModelCallableKey::new(
                "rust",
                &declaring.qualified_name,
                member,
                has_receiver,
                parameter_count,
            ),
            &application,
        )
    };
    // A direct family has precedence even when incomplete or inapplicable:
    // another trait cannot repair an uncertain inherent declaration.
    if named_trait.is_none()
        && overlay
            .members_of(&owner.id)
            .records
            .iter()
            .any(|record| record.name == member && symbol_kind_is_callable(record.kind))
    {
        let matched = callable_on(owner);
        return callable_is_proven(&matched).then(|| owner.qualified_name.clone());
    }
    let candidates = overlay.callable_owners_on_surface(&active, owner, member)?;
    if candidates.is_empty() {
        return None;
    }
    let candidates = if let Some(named) = named_trait {
        candidates
            .into_iter()
            .filter(|candidate| candidate.owner.qualified_name == named.owner)
            .collect::<Vec<_>>()
    } else {
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::default();
        let prelude = match operation.as_deref_mut() {
            Some(operation) => operation.rust_prelude_for_caller(file.rel_path(), &cancellation),
            None => {
                let owned_factory;
                let factory = match factory {
                    Some(factory) => factory,
                    None => {
                        owned_factory = native_points::RustDefinitionOperationFactory::new(
                            analyzer,
                            &cancellation,
                        )?;
                        &owned_factory
                    }
                };
                match factory.open(&cancellation) {
                    Ok(SelectedResolutionOperationOpenOutcome::Ready(operation)) => {
                        operation.rust_prelude_for_caller(file.rel_path(), &cancellation)
                    }
                    Ok(_) => {
                        crate::analyzer::rust::std_types::incomplete_proof(
                            "selected_operation_unavailable",
                        );
                        return None;
                    }
                    Err(error) => {
                        eprintln!("opening selected Rust trait scope: {error}");
                        crate::analyzer::rust::std_types::incomplete_proof("store_error");
                        return None;
                    }
                }
            }
        }
        .unwrap_or_else(|error| {
            eprintln!("reading selected Rust trait prelude: {error}");
            crate::analyzer::rust::std_types::incomplete_proof("store_error");
            None
        })?;
        let imports = analyzer.import_analysis_provider_for_file(file)?;
        let imports = imports.import_info_of(scope.token(), file);
        let visible_imports = imports
            .iter()
            .filter(|import| {
                import.path.as_ref().is_some_and(|path| {
                    rust_import_binder_visible_at_byte(path, terminal.start_byte())
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut source_traits =
            brokk_bifrost_rust::imports::rust_imported_code_units(rust, file, &visible_imports);
        let mut external_imports = Vec::new();
        for import in &visible_imports {
            let Some((written, focused)) =
                crate::analyzer::rust::external_calls::import_path_in_tree(import, tree, source)
            else {
                continue;
            };
            // Selected import definitions include local-module routes and aliases
            // that the legacy FQ-name adapter cannot normalize by itself.
            let text = rust_node_text(focused, source);
            let import_site = ResolvedReferenceSite {
                path: text.to_owned(),
                text: text.to_owned(),
                range: Range {
                    start_byte: focused.start_byte(),
                    end_byte: focused.end_byte(),
                    start_line: focused.start_position().row + 1,
                    end_line: focused.end_position().row + 1,
                },
                focus_start_byte: focused.start_byte(),
                focus_end_byte: focused.end_byte(),
            };
            let query = BoundedReceiverQuery {
                analyzer,
                file,
                source,
                tree: Some(tree),
                site: &import_site,
                budget: INTERACTIVE_TYPE_LOOKUP_BUDGET,
                cancellation: Some(&cancellation),
            };
            let resolved = match operation.as_deref_mut() {
                Some(operation) => {
                    native_points::resolve_rust_definition_in_operation(query, operation)
                }
                None => match factory {
                    Some(factory) => factory.resolve_bounded(query),
                    None => native_points::resolve_rust_definition_bounded(query),
                },
            };
            crate::analyzer::rust::std_types::observe_proof_resolution(&resolved);
            let BoundedResolution::Complete { value, .. } = resolved else {
                return None;
            };
            for definition in value.definitions {
                if import.is_wildcard {
                    source_traits.extend(rust.get_direct_children(&definition));
                }
                source_traits.insert(definition);
            }
            if crate::analyzer::rust::external_calls::native_external_root_with_resolver(
                analyzer,
                scope.token(),
                file,
                source,
                tree,
                written.root,
                None,
                |query| match operation.as_deref_mut() {
                    Some(operation) => {
                        native_points::resolve_rust_definition_in_operation(query, operation)
                    }
                    None => match factory {
                        Some(factory) => factory.resolve_bounded(query),
                        None => native_points::resolve_rust_definition_bounded(query),
                    },
                },
            ) {
                external_imports.push(import);
            }
        }
        let lexical = rust_lexical_scope_index(tree.root_node(), source);
        let visible = |candidate: &SemanticModelSymbol| {
            let imported = external_imports.iter().any(|import| {
                let Some(path) = &import.path else {
                    return false;
                };
                if !rust_import_binder_visible_at_byte(path, terminal.start_byte()) {
                    return false;
                }
                let mut segments = path.segments.clone();
                if import.is_wildcard {
                    segments.push(candidate.name.clone());
                }
                RustOverlayCrates::new(Some(&overlay))
                    .referenceable_symbol(&segments.join("."))
                    .is_some_and(|symbol| symbol.id == candidate.id)
            });
            if imported {
                return true;
            }
            let (edition, crate_name) = &prelude;
            let Some(edition) = RustEdition::from_crate_row(edition) else {
                return false;
            };
            let prelude_crate = match crate_name.as_str() {
                "std" => RustPreludeCrate::Std,
                "core" => RustPreludeCrate::Core,
                _ => return false,
            };
            let standard_owner = matches!(
                candidate.qualified_name.as_str(),
                "std.clone.Clone"
                    | "core.clone.Clone"
                    | "std.string.ToString"
                    | "alloc.string.ToString"
                    | "std.convert.From"
                    | "core.convert.From"
                    | "std.borrow.ToOwned"
                    | "alloc.borrow.ToOwned"
            );
            // Method lookup retains prelude traits even when an item or import
            // shadows the trait's name for path lookup. For example, importing
            // OtherClone as Clone does not remove std::clone::Clone as a method
            // candidate; both applicable methods must remain ambiguous.
            standard_owner
                && rust_prelude_name(
                    &candidate.name,
                    RustPreludeNamespace::Type,
                    edition,
                    prelude_crate,
                )
                .is_some()
        };
        // The native source inventory can expose traits that packs do not
        // enumerate. Reuse its exact import/declaration identities, including
        // traits in other files and default methods. Without a complete external
        // implementation inventory, such a source candidate keeps applicability
        // open; it must not be erased by one modeled trait's summary.
        let wildcard_imports = visible_imports
            .iter()
            .filter(|import| import.is_wildcard)
            .cloned()
            .collect::<Vec<_>>();
        for namespace in
            brokk_bifrost_rust::imports::rust_imported_code_units(rust, file, &wildcard_imports)
        {
            source_traits.extend(rust.get_direct_children(&namespace));
        }
        source_traits.extend(
            rust.declarations(file)
                .into_iter()
                .filter(|unit| lexical.item_bound_at(unit.identifier(), terminal.start_byte())),
        );
        for candidate in source_traits
            .into_iter()
            .filter(|candidate| candidate.is_class())
        {
            let is_trait = match brokk_bifrost_rust::graph_support::is_rust_trait_declaration(
                rust, &candidate,
            ) {
                Ok(is_trait) => is_trait,
                Err(error) => {
                    eprintln!("reading source trait candidate {candidate:?}: {error:?}");
                    crate::analyzer::rust::std_types::incomplete_proof(
                        "source_trait_scope_unknown",
                    );
                    return None;
                }
            };
            if is_trait
                && rust
                    .get_direct_children(&candidate)
                    .iter()
                    .any(|member_candidate| {
                        member_candidate.is_function() && member_candidate.identifier() == member
                    })
            {
                return None;
            }
        }
        candidates
            .into_iter()
            .filter(|candidate| visible(candidate.owner))
            .collect::<Vec<_>>()
    };
    let call = callee
        .parent()
        .filter(|node| node.kind() == "call_expression")?;
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let mut arguments = arguments.named_children(&mut cursor).collect::<Vec<_>>();
    if has_receiver && callee.kind() != "field_expression" {
        arguments = arguments.into_iter().skip(1).collect();
    }
    let mut selected = None;
    for candidate in candidates {
        if candidate.hierarchy.is_empty() || candidate.owner.kind != SemanticModelSymbolKind::Trait
        {
            continue;
        }
        let matched = callable_on(candidate.owner);
        if !callable_is_proven(&matched) {
            return None;
        }
        let edge = candidate.hierarchy.last()?;
        let trait_arguments = match &edge.target {
            TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } => arguments,
            _ => return None,
        };
        if let Some(written) = named_trait.and_then(|named| named.arguments.as_ref()) {
            if written.len() != trait_arguments.len() {
                continue;
            }
            let mut applicable = true;
            for (actual, model) in written.iter().zip(trait_arguments) {
                let actual = crate::analyzer::rust::call_conversion::type_conversion_type(
                    analyzer, file, source, *actual,
                )
                .ok()?;
                applicable &=
                    crate::analyzer::rust::call_conversion::matches_model_type(&actual, model)?;
            }
            if !applicable {
                continue;
            }
        }
        if !trait_arguments.is_empty() {
            let declarations = active.types_with_id(&candidate.owner.id);
            let [declaration] = declarations.records.as_slice() else {
                return None;
            };
            if declaration.record.type_parameters.len() != trait_arguments.len() {
                return None;
            }
            let mut applicable = true;
            for record in &matched.records {
                let signature = record.structured_signature.as_ref()?;
                for (formal, actual) in signature.parameters.iter().zip(&arguments) {
                    let TypeRef::TypeParameter { name } = &formal.r#type else {
                        return None;
                    };
                    let index = declaration
                        .record
                        .type_parameters
                        .iter()
                        .position(|parameter| parameter == name)?;
                    let actual =
                        crate::analyzer::rust::call_conversion::expression_conversion_type(
                            analyzer, file, source, *actual,
                        )
                        .ok()?;
                    applicable &= crate::analyzer::rust::call_conversion::matches_model_type(
                        &actual,
                        &trait_arguments[index],
                    )?;
                }
            }
            if !applicable {
                continue;
            }
        }
        match &selected {
            Some(_) => return None, // More than one applicable typed impl remains ambiguous.
            None => selected = Some(candidate.owner.qualified_name.clone()),
        }
    }
    selected
}

fn callable_is_proven(
    matched: &crate::analyzer::semantic_model::SemanticModelCallableMatch<'_>,
) -> bool {
    matched
        .records
        .iter()
        .all(|record| record.externally_visible())
        && match matched.disposition {
            SemanticModelCallableDisposition::Unique => true,
            SemanticModelCallableDisposition::CompatibleLayout => {
                matched.callable_family_id().is_some()
            }
            _ => false,
        }
}
