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

/// Classify the receiver that selected a member, after any dereference.
/// A trait declaration (including a bound or dyn receiver) cannot close a call.
/// Primitive model aliases are recognized by their selected canonical identity.
pub(crate) fn receiver_dispatch_extensibility(
    kind: SemanticModelSymbolKind,
    model_identity: Option<&str>,
) -> Option<brokk_bifrost_core::analyzer::model::DispatchExtensibility> {
    let primitive_alias = kind == SemanticModelSymbolKind::TypeAlias
        && model_identity
            .is_some_and(|name| super::call_conversion::modeled_primitive(name).is_some());
    (primitive_alias
        || matches!(
            kind,
            SemanticModelSymbolKind::Class
                | SemanticModelSymbolKind::Struct
                | SemanticModelSymbolKind::Enum
                | SemanticModelSymbolKind::Union
        ))
    .then_some(brokk_bifrost_core::analyzer::model::DispatchExtensibility::Closed)
}

/// A trait fixed by a UFCS path, with its structurally selected type arguments.
pub(crate) struct UfcsTrait<'tree> {
    pub owner: String,
    pub arguments: Option<Vec<tree_sitter::Node<'tree>>>,
}

/// Declaration identity and the implementation evidence proved at this probe.
/// A trait declaration alone never closes its implementation set.
pub(crate) struct SelectedMember {
    pub owner: String,
    extensibility: brokk_bifrost_core::analyzer::model::DispatchExtensibility,
}

impl SelectedMember {
    pub(crate) fn proof(
        &self,
        member: &str,
        parameter_count: u32,
    ) -> brokk_bifrost_analysis::analyzer::usages::get_definition::ExactExternalCallProof {
        use brokk_bifrost_analysis::analyzer::usages::get_definition::ExactExternalCallProof;
        use brokk_bifrost_core::analyzer::model::DispatchExtensibility;
        match self.extensibility {
            DispatchExtensibility::Closed => ExactExternalCallProof::rust_bound_external_member(
                &self.owner,
                member,
                parameter_count,
            ),
            DispatchExtensibility::Open => {
                ExactExternalCallProof::rust_trait_declaration(&self.owner, member, parameter_count)
            }
        }
    }
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
    receiver_application: Option<&TypeRef>,
) -> Option<SelectedMember> {
    use brokk_bifrost_core::analyzer::model::DispatchExtensibility;
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
    let receiver_facts = super::semantic::RustReceiverTypeFacts::from_tree(source, tree);
    let expression = callee.child_by_field_name("value");
    let lexical_traits = (owner.kind == SemanticModelSymbolKind::Trait)
        .then(|| {
            let model = super::trait_applicability::ModelApplicability::new(
                analyzer, rust, &overlay, &active,
            );
            let ty = receiver_facts.declared_receiver_type(source, tree, expression?)?;
            super::trait_applicability::lexical_receiver_traits(
                analyzer, file, source, tree, ty, &model,
            )
        })
        .flatten();
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
    // Scope must be known before certifying even an inherent family: a
    // by-value trait method can precede an inherent borrowed-self method.
    let mut selected_receiver_extensibility =
        receiver_dispatch_extensibility(owner.kind, Some(&owner.qualified_name));
    let candidates = if let Some(named) = named_trait {
        overlay
            .callable_owners_on_surface(&active, &owner, member)?
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
            let standard_owner =
                brokk_bifrost_rust::prelude::rust_prelude_trait_module(&candidate.name)
                    .and_then(|module| {
                        RustOverlayCrates::new(Some(&overlay)).unique_symbol(&format!(
                            "{}.{}.{}",
                            prelude_crate.name(),
                            module,
                            candidate.name
                        ))
                    })
                    .is_some_and(|symbol| symbol.id == candidate.id);
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
        source_traits.extend(rust.declarations(file).into_iter().filter(|unit| {
            rust.ranges_of(unit).iter().any(|range| {
                lexical.item_declaration_visible_at(
                    unit.identifier(),
                    range.start_byte,
                    terminal.start_byte(),
                )
            })
        }));
        let mut source_rivals = Vec::new();
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
                source_rivals.push(candidate);
            }
        }
        let mut applicability =
            super::trait_applicability::ModelApplicability::new(analyzer, rust, &overlay, &active);
        // Static and UFCS paths have no field receiver. Their explicit owner
        // still drives the existing typed trait route (for example From::from).
        let mut receiver_type = receiver_application
            .cloned()
            .or_else(|| {
                expression
                    .and_then(|expression| {
                        receiver_facts.declared_receiver_type(source, tree, expression)
                    })
                    .and_then(|ty| applicability.receiver_type(analyzer, file, source, ty))
            })
            .or_else(|| {
                super::std_types::RustTypeProof::new(analyzer)?
                    .modeled_receiver_type(file, expression?)
            })
            .unwrap_or_else(|| applicability.abstract_receiver(&owner));
        let borrowed = expression.and_then(|mut expression| {
            while expression.kind() == "parenthesized_expression" {
                expression = expression.named_child(0)?;
            }
            Some(
                expression.kind() == "reference_expression"
                    || receiver_facts.implicit_receiver_is_borrowed(tree, expression),
            )
        });
        if borrowed == Some(true) {
            receiver_type = crate::analyzer::semantic_model::TypeRef::ByRef {
                element: Box::new(receiver_type),
                reference_kind: crate::analyzer::semantic_model::TypeRefReferenceKind::Lvalue,
            };
        }
        if expression.is_some()
            && owner.kind == SemanticModelSymbolKind::Trait
            && lexical_traits.is_none()
        {
            return None;
        }
        let mut receiver = owner;
        let mut visited = std::collections::HashSet::new();
        let candidates = loop {
            selected_receiver_extensibility =
                receiver_dispatch_extensibility(receiver.kind, Some(&receiver.qualified_name));
            if !visited.insert(receiver.id.clone()) {
                return None;
            }
            let direct = overlay.members_of(&receiver.id);
            let family = direct
                .records
                .iter()
                .filter(|record| {
                    lexical_traits.is_none()
                        && record.name == member
                        && symbol_kind_is_callable(record.kind)
                })
                .cloned()
                .collect::<Vec<_>>();
            for candidate in &source_rivals {
                if lexical_traits.is_some()
                    || super::trait_applicability::workspace_trait_may_apply(
                        analyzer,
                        rust,
                        candidate,
                        &receiver,
                        &applicability,
                    )?
                {
                    return None;
                }
            }
            let in_scope = overlay
                .trait_owners_with_callable_member(member)
                .into_iter()
                .filter(|candidate| {
                    visible(candidate)
                        || lexical_traits.as_ref().is_some_and(|traits| {
                            traits.iter().any(|bound| bound.id == candidate.id)
                        })
                })
                .collect::<Vec<_>>();
            let mut has_inherent = false;
            let mut has_trait = false;
            for method in &family {
                match applicability.member(method)?.implemented_trait.as_ref() {
                    None => has_inherent = true,
                    Some(trait_type) => {
                        let trait_owner = applicability.owner(trait_type)?;
                        if in_scope
                            .iter()
                            .any(|candidate| candidate.id == trait_owner.id)
                        {
                            has_trait = true;
                        }
                    }
                }
            }
            if has_inherent && has_trait {
                return None;
            }
            use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::{
                CandidateAssessment, adapter, select_candidate_indices,
            };
            use brokk_bifrost_analysis::analyzer::resolution::{SemanticId, SharedNameId};
            use brokk_bifrost_core::analyzer::structural::callable::CallableRejectionReason;
            let mut assessments = Vec::new();
            for (index, candidate) in in_scope.iter().enumerate() {
                let in_family = family.iter().any(|method| {
                    applicability
                        .member(method)
                        .and_then(|fact| fact.implemented_trait.clone())
                        .and_then(|trait_type| applicability.owner(&trait_type))
                        .is_some_and(|trait_owner| trait_owner.id == candidate.id)
                });
                // Even a trait already represented in the artifact family can
                // acquire a distinct downstream impl with a local argument.
                let possible = if lexical_traits.is_some() {
                    true
                } else {
                    applicability.additional_implementation_may_apply(
                        &receiver,
                        candidate,
                        &receiver_type,
                        || in_family || applicability.provably_absent(&receiver, candidate),
                    )?
                };
                let id =
                    SemanticId::shared_name(SharedNameId::per_request(u32::try_from(index).ok()?));
                assessments.push(if !possible {
                    CandidateAssessment::inapplicable(
                        id,
                        CallableRejectionReason::ReceiverContractMismatch,
                    )
                } else {
                    CandidateAssessment::unknown(id)
                });
            }
            let possible = select_candidate_indices(
                adapter(brokk_bifrost_core::analyzer::model::Language::Rust),
                &assessments,
                &Default::default(),
            );
            if !possible.is_empty() {
                if family.is_empty() && possible.len() == 1 {
                    let trait_ = in_scope[possible[0]].clone();
                    let matched = callable_on(&trait_);
                    // Preserve the existing exact implementation route before
                    // falling back to declaration-only evidence. Its complete
                    // callable contract and positive hierarchy path are a
                    // stronger claim than a trait's closed declaration list.
                    if lexical_traits.is_none()
                        && (!has_receiver
                            || (callable_is_proven(&matched)
                                && implementation_is_proven(&trait_, &matched)))
                        && let Some(surface) =
                            overlay.callable_owners_on_surface(&active, &receiver, member)
                    {
                        let reachable = surface
                            .into_iter()
                            .filter(|candidate| candidate.owner.id == trait_.id)
                            .collect::<Vec<_>>();
                        if !reachable.is_empty() {
                            break reachable;
                        }
                    }
                    if has_receiver {
                        let self_forms_known = matched.records.iter().all(|method| {
                            applicability.member(method).is_some_and(|fact| {
                                matches!(fact.self_form,
                                Some(crate::analyzer::semantic_model::RustSelfForm::Value
                                    | crate::analyzer::semantic_model::RustSelfForm::Shared
                                    | crate::analyzer::semantic_model::RustSelfForm::Mutable))
                            })
                        });
                        return (self_forms_known && callable_is_proven(&matched)).then(|| {
                            SelectedMember {
                                owner: trait_.qualified_name.clone(),
                                extensibility: DispatchExtensibility::Open,
                            }
                        });
                    }
                }
                return None;
            }
            if !family.is_empty() {
                if !has_inherent && !has_trait {
                    return None;
                }
                let matched = callable_on(&receiver);
                let extensibility =
                    selected_receiver_extensibility.unwrap_or(DispatchExtensibility::Open);
                return callable_is_proven(&matched).then(|| SelectedMember {
                    owner: receiver.qualified_name.clone(),
                    extensibility,
                });
            }
            let mut dereferenced = &receiver_type;
            while let crate::analyzer::semantic_model::TypeRef::ByRef { element, .. } = dereferenced
            {
                dereferenced = element;
            }
            let Some(target) = applicability.deref_target(&receiver, dereferenced) else {
                break Vec::new();
            };
            receiver = applicability.owner(&target)?;
            receiver_type = target;
        };
        candidates
            .into_iter()
            .filter(|candidate| visible(&candidate.owner))
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
        let matched = callable_on(&candidate.owner);
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
            let declaration =
                brokk_bifrost_analysis::analyzer::semantic_model::overlay::owner_declaration(
                    &active,
                    &candidate.owner,
                )?;
            if declaration.type_parameters.len() != trait_arguments.len() {
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
            None => {
                selected = Some(SelectedMember {
                    owner: candidate.owner.qualified_name.clone(),
                    extensibility: if implementation_is_proven(&candidate.owner, &matched) {
                        selected_receiver_extensibility.unwrap_or(DispatchExtensibility::Open)
                    } else {
                        DispatchExtensibility::Open
                    },
                })
            }
        }
    }
    selected
}

fn callable_is_proven(
    matched: &crate::analyzer::semantic_model::SemanticModelCallableMatch,
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

fn implementation_is_proven(
    owner: &SemanticModelSymbol,
    matched: &crate::analyzer::semantic_model::SemanticModelCallableMatch,
) -> bool {
    use crate::analyzer::semantic_model::SemanticModelCompleteness;
    debug_assert!(!matched.records.is_empty());
    matched
        .records
        .iter()
        .all(|record| record.callable_family_complete)
        || (owner.provenance.completeness == SemanticModelCompleteness::Complete
            && matched.records.iter().all(|record| {
                record.provenance.completeness == SemanticModelCompleteness::Complete
            }))
}
