//! Per-impl body selection. This does not change the existing family census.

use super::*;
use brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustOwnerSelectionReason {
    OwnItem,
    Default,
    ContractUnavailable,
    BodyUnavailable,
    DeclarationLinks,
    GeneratedSurface,
    ConditionalSurface,
    UnresolvedSelf,
    GenericOwner,
    NoDefaultBody,
}

#[derive(Debug, Clone)]
pub struct RustOwnerSelection {
    pub file: ProjectFile,
    pub declaration: SourceDeclarationId,
    pub resolved_self: Option<CodeUnit>,
    pub selected_method: Option<CodeUnit>,
    pub reason: RustOwnerSelectionReason,
}

/// Resolve the exact trait contract, then read every known impl's own source
/// table. The trait plan is the same recorded-read route as member families;
/// unlike that census this reader never stops at an open inventory.
pub fn rust_member_owner_selections(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    member: &CodeUnit,
) -> Result<Option<(CodeUnit, Vec<RustOwnerSelection>)>, RustCargoRouteError> {
    let Some(trait_unit) = owning_trait_of_member(rust, token, member)? else {
        return Ok(None);
    };
    let trait_facts = rust.canonical_rust_hierarchy_source_facts(trait_unit.source(), &|| true)?;
    let trait_index = RustHierarchyFileIndex::new(&trait_facts, &|| true)?;
    let trait_sources: Vec<_> = trait_facts
        .items
        .traits
        .iter()
        .filter(|source| {
            trait_index
                .declarations
                .get(&source.declaration)
                .is_some_and(|units| units.as_slice() == [&trait_unit])
        })
        .collect();
    let [trait_source] = trait_sources.as_slice() else {
        return Ok(None);
    };
    let impl_arity = authored_impl_method_arity(rust, member)?;
    let contract = match read_trait_method_table(&trait_index, trait_source) {
        TraitMethodTable::Read {
            methods,
            complete: true,
            ..
        } => {
            // Use the family census's exact-trait name/arity rule for an
            // authored impl item; a trait item must match its own identity.
            let mut exact = methods.into_iter().filter(|method| {
                method.unit == *member
                    || impl_arity.is_some_and(|arity| {
                        method.name == member.identifier() && method.arity == Some(arity)
                    })
            });
            let first = exact.next();
            if exact.next().is_some() { None } else { first }
        }
        _ => None,
    };
    let member = contract.as_ref().map_or(member, |contract| &contract.unit);
    let properties = rust.declaration_source_properties(trait_unit.source(), &|| true)?;
    let trait_syntax = rust.prepared_syntax(token, trait_unit.source());
    let contract_admission =
        complete_item_table(&trait_index, trait_source.body, &trait_source.body_children).and_then(
            |()| {
                if contract.is_none() {
                    return Err(RustOwnerSelectionReason::ContractUnavailable);
                }
                let syntax = trait_syntax
                    .as_ref()
                    .ok_or(RustOwnerSelectionReason::BodyUnavailable)?;
                let node = syntax
                    .declaration_node(member)
                    .ok_or(RustOwnerSelectionReason::BodyUnavailable)?;
                source_item_admission(node, syntax.source())?;
                for unit in [member, &trait_unit] {
                    let Some([property]) = properties.get(unit).map(Vec::as_slice) else {
                        return Err(RustOwnerSelectionReason::DeclarationLinks);
                    };
                    if property.generated_surface {
                        return Err(RustOwnerSelectionReason::GeneratedSurface);
                    }
                    if property.cfg_condition != RustCfgCondition::Always {
                        return Err(RustOwnerSelectionReason::ConditionalSurface);
                    }
                }
                Ok(())
            },
        );
    let default = contract_admission.and_then(|()| {
        let Some(contract) = contract.as_ref() else {
            return Err(RustOwnerSelectionReason::ContractUnavailable);
        };
        let child = trait_source
            .body_children
            .iter()
            .find(|child| {
                child
                    .declaration
                    .and_then(|id| trait_index.declarations.get(&id))
                    .is_some_and(|units| units.as_slice() == [&contract.unit])
            })
            .ok_or(RustOwnerSelectionReason::DeclarationLinks)?;
        if child.syntax_kind == "function_item" {
            Ok(())
        } else {
            Err(RustOwnerSelectionReason::NoDefaultBody)
        }
    });

    let plan = TraitImplPlan::read(rust, &trait_unit)?;
    let mut files: Vec<_> = plan.files().collect();
    files.sort();
    files.dedup();
    let mut owners = Vec::new();
    for file in files {
        let facts = rust.canonical_rust_hierarchy_source_facts(&file, &|| true)?;
        let index = RustHierarchyFileIndex::new(&facts, &|| true)?;
        let syntax = rust.prepared_syntax(token, &file);
        for source in &facts.items.impls {
            let Some(trait_type) = source
                .trait_type
                .and_then(|id| index.types.get(&id))
                .copied()
            else {
                continue;
            };
            let binder = index
                .contexts
                .visible_import_binder(&facts, source.context, &|| true)?;
            let bound = plan
                .bound
                .get(&file)
                .is_some_and(|impls| impls.contains_key(&source.declaration.get()));
            if !bound
                && resolve_rust_hierarchy_source_ref(
                    rust,
                    token,
                    &file,
                    &index.contexts,
                    &facts,
                    source.context,
                    &binder,
                    trait_type,
                    |candidate| is_rust_trait_declaration(rust, candidate),
                )?
                .as_ref()
                    != Some(&trait_unit)
            {
                continue;
            }
            // Resolve only a non-generic nominal Self. No substitution,
            // unification or blanket applicability is attempted here.
            let target = source
                .target_type
                .and_then(|id| index.types.get(&id))
                .copied();
            let generic = index.generics.contains_key(&source.declaration)
                || matches!(&trait_type.shape, RustTypeSourceShape::Path { segments, .. }
                    if segments.iter().any(|segment| segment.generic_arguments.is_some()))
                || target.is_some_and(|target| match &target.shape {
                    RustTypeSourceShape::Path { segments, .. } => {
                        segments.iter().any(|s| s.generic_arguments.is_some())
                    }
                    _ => false,
                });
            let mut resolved_self = if generic {
                None
            } else if let Some(target) = target {
                if target.wrappers.is_empty() {
                    match resolve_rust_hierarchy_source_ref(
                        rust,
                        token,
                        &file,
                        &index.contexts,
                        &facts,
                        source.context,
                        &binder,
                        target,
                        |candidate| {
                            Ok(is_rust_struct_declaration(rust, candidate)?
                                || is_rust_enum_declaration(rust, candidate)?
                                || crate::graph_support::is_rust_union_declaration(
                                    rust, candidate,
                                )?
                                || is_rust_type_alias_declaration(rust, candidate)?)
                        },
                    )? {
                        // Hierarchy's nominal alias projection erases reference
                        // wrappers. It is not an exact Self identity (#13148).
                        Some(unit) if is_rust_type_alias_declaration(rust, &unit)? => None,
                        Some(unit) => Some(unit),
                        None => None,
                    }
                } else {
                    None
                }
            } else {
                None
            };
            // A bare nominal path may still name a generic declaration whose
            // required substitution is absent from this source header.
            let mut generic_self = false;
            if let Some(unit) = &resolved_self {
                let self_facts =
                    rust.canonical_rust_hierarchy_source_facts(unit.source(), &|| true)?;
                generic_self = self_facts.declaration_units.iter().any(|(id, candidate)| {
                    candidate == unit
                        && self_facts
                            .items
                            .generics
                            .iter()
                            .any(|row| row.declaration == *id)
                });
                if generic_self {
                    resolved_self = None;
                }
            }
            let selection = (|| {
                if generic || generic_self {
                    return Err(RustOwnerSelectionReason::GenericOwner);
                }
                if resolved_self.is_none() {
                    return Err(RustOwnerSelectionReason::UnresolvedSelf);
                }
                if source.negation.is_some() {
                    return Err(RustOwnerSelectionReason::ContractUnavailable);
                }
                if !index
                    .contexts
                    .is_primary(&facts, source.context)
                    .map_err(|_| RustOwnerSelectionReason::GeneratedSurface)?
                {
                    return Err(RustOwnerSelectionReason::GeneratedSurface);
                }
                let syntax = syntax
                    .as_ref()
                    .ok_or(RustOwnerSelectionReason::BodyUnavailable)?;
                let &(start, end) = facts
                    .impl_spans
                    .get(&source.declaration)
                    .ok_or(RustOwnerSelectionReason::BodyUnavailable)?;
                let node = syntax
                    .tree()
                    .root_node()
                    .descendant_for_byte_range(start, end)
                    .filter(|node| {
                        node.kind() == "impl_item"
                            && node.start_byte() == start
                            && node.end_byte() == end
                    })
                    .ok_or(RustOwnerSelectionReason::BodyUnavailable)?;
                source_item_admission(node, syntax.source())?;
                complete_item_table(&index, source.body, &source.body_children)?;
                contract_admission?;
                let contract = contract
                    .as_ref()
                    .ok_or(RustOwnerSelectionReason::ContractUnavailable)?;
                let candidates: Vec<_> = source
                    .body_children
                    .iter()
                    // Types and methods have separate Rust namespaces. The
                    // complete table above still admits every child, but only
                    // callable items can override this method's contract.
                    .filter(|child| {
                        matches!(
                            child.syntax_kind.as_str(),
                            "function_item" | "function_signature_item"
                        )
                    })
                    .filter_map(|child| {
                        let declaration = child.declaration?;
                        let [unit] = index.declarations.get(&declaration)?.as_slice() else {
                            return None;
                        };
                        (unit.identifier() == contract.name).then_some((child, *unit, declaration))
                    })
                    .collect();
                match candidates.as_slice() {
                    [] => {
                        default?;
                        Ok((member.clone(), RustOwnerSelectionReason::Default))
                    }
                    [(child, unit, declaration)] if child.syntax_kind == "function_item" => {
                        let callable = index
                            .callables
                            .get(declaration)
                            .ok_or(RustOwnerSelectionReason::BodyUnavailable)?;
                        let arity = callable
                            .parameter_children
                            .iter()
                            .filter(|parameter| parameter.syntax_kind != "attribute_item")
                            .count();
                        if callable.parameters.is_none() || Some(arity) != contract.arity {
                            return Err(RustOwnerSelectionReason::ContractUnavailable);
                        }
                        Ok(((*unit).clone(), RustOwnerSelectionReason::OwnItem))
                    }
                    _ => Err(RustOwnerSelectionReason::DeclarationLinks),
                }
            })();
            let (selected_method, reason) = match selection {
                Ok((method, reason)) => (Some(method), reason),
                Err(reason) => (None, reason),
            };
            owners.push(RustOwnerSelection {
                file: file.clone(),
                declaration: source.declaration,
                resolved_self,
                selected_method,
                reason,
            });
        }
    }
    owners.sort_by(|a, b| (&a.file, a.declaration).cmp(&(&b.file, b.declaration)));
    Ok(Some((trait_unit, owners)))
}

/// Read the same source-owned method discriminator the family census records
/// in PendingImplMember. Only one authored impl item can supply this key.
fn authored_impl_method_arity(
    rust: &dyn RustFactSource,
    member: &CodeUnit,
) -> Result<Option<usize>, RustCargoRouteError> {
    let facts = rust.canonical_rust_hierarchy_source_facts(member.source(), &|| true)?;
    let declarations = member_declarations(&facts, member);
    let mut declaration_ids = declarations.iter();
    let (Some(declaration), None) = (declaration_ids.next(), declaration_ids.next()) else {
        return Ok(None);
    };
    let mut owners = facts
        .items
        .impls
        .iter()
        .filter(|owner| declares_any(&owner.body_children, &declarations));
    let (Some(owner), None) = (owners.next(), owners.next()) else {
        return Ok(None);
    };
    let index = RustHierarchyFileIndex::new(&facts, &|| true)?;
    let Some([unit]) = index.declarations.get(declaration).map(Vec::as_slice) else {
        return Ok(None);
    };
    if *unit != member || !member.is_function() || index.source_count_by_unit[member] != 1 {
        return Ok(None);
    }
    if owner.trait_type.is_none()
        || owner.negation.is_some()
        || !index.contexts.is_primary(&facts, owner.context)?
    {
        return Ok(None);
    }
    let child = owner
        .body_children
        .iter()
        .find(|child| child.declaration == Some(*declaration))
        .expect("the impl owner was selected by its exact member declaration");
    if child.syntax_kind != "function_item" || index.syntax.get(&child.occurrence) != Some(&false) {
        return Ok(None);
    }
    let Some(callable) = index.callables.get(declaration) else {
        return Ok(None);
    };
    Ok(callable.parameters.map(|_| {
        callable
            .parameter_children
            .iter()
            .filter(|parameter| parameter.syntax_kind != "attribute_item")
            .count()
    }))
}

/// An enclosing attribute macro may add items to an otherwise readable impl
/// or trait. Inspect only the item's ancestry, so an unrelated sibling's
/// generated surface does not erase this owner's readable evidence.
fn source_item_admission(
    node: tree_sitter::Node<'_>,
    source: &str,
) -> Result<(), RustOwnerSelectionReason> {
    if node.has_error() {
        return Err(RustOwnerSelectionReason::BodyUnavailable);
    }
    if crate::lexical_scope::rust_effective_cfg_condition(node, source) != RustCfgCondition::Always
    {
        return Err(RustOwnerSelectionReason::ConditionalSurface);
    }
    let mut current = Some(crate::syntax::unwrap_attributes(node));
    while let Some(item) = current {
        if crate::resolution::rust_item_has_generated_surface_boundary(item, source) {
            return Err(RustOwnerSelectionReason::GeneratedSurface);
        }
        current = crate::syntax::parent_outside_attributes(item);
    }
    Ok(())
}

/// A negative witness is valid only after every direct child was admitted.
/// Opaque wrappers and macro invocations remain visible in the source facts.
fn complete_item_table(
    index: &RustHierarchyFileIndex<'_>,
    body: Option<SourceOccurrenceId>,
    children: &[RustItemBodyChildSourceFact],
) -> Result<(), RustOwnerSelectionReason> {
    let body = body.ok_or(RustOwnerSelectionReason::BodyUnavailable)?;
    if index.syntax.get(&body) != Some(&false) {
        return Err(RustOwnerSelectionReason::BodyUnavailable);
    }
    for child in children {
        if index.syntax.get(&child.occurrence) != Some(&false) {
            return Err(RustOwnerSelectionReason::BodyUnavailable);
        }
        match child.syntax_kind.as_str() {
            "line_comment" | "block_comment" => continue,
            "macro_invocation" => return Err(RustOwnerSelectionReason::GeneratedSurface),
            "function_item"
            | "function_signature_item"
            | "type_item"
            | "associated_type"
            | "const_item" => {}
            _ => return Err(RustOwnerSelectionReason::ConditionalSurface),
        }
        let declaration = child
            .declaration
            .ok_or(RustOwnerSelectionReason::DeclarationLinks)?;
        let Some([unit]) = index.declarations.get(&declaration).map(Vec::as_slice) else {
            return Err(RustOwnerSelectionReason::DeclarationLinks);
        };
        if index.source_count_by_unit[unit] != 1 {
            return Err(RustOwnerSelectionReason::DeclarationLinks);
        }
    }
    Ok(())
}
