//! Selected native Result/Option payload effects. Stored syntax IR stays inert.

use super::*;
use brokk_bifrost_analysis::analyzer::languages::LanguageSupport;
use brokk_bifrost_analysis::analyzer::semantic::partial_flow::HeapSelector;
use brokk_bifrost_analysis::analyzer::semantic::{
    AccessPath, AccessPathRoot, AccessPathTail, AccessSelector, CallContinuationKind,
    PatternProjectionStep, ProcedureHandle, ProcedurePortHandle, SelectedPayloadEvent,
    SelectedPayloadProjection, SelectedPayloadRelation, SemanticEffect, SemanticOutcome,
    SemanticProviderError, SemanticRequest, SemanticWork, StableDigest, ValueFlowEndpoint,
    ValueFlowKind, ValueFlowRelationKind,
};
use brokk_bifrost_analysis::analyzer::semantic_model::{
    ActiveSemanticModelSnapshot, SemanticModelSymbol, SemanticModelSymbolKind, TypeKind,
};
use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;

struct PayloadLayout {
    owner: Arc<SemanticModelSymbol>,
    variants: Vec<Arc<SemanticModelSymbol>>,
}

fn family(owner: &str) -> Option<&'static str> {
    match owner {
        "std.result.Result" | "core.result.Result" => Some("Result"),
        "std.option.Option" | "core.option.Option" => Some("Option"),
        _ => None,
    }
}

fn selected_layout(snapshot: &ActiveSemanticModelSnapshot, name: &str) -> Option<PayloadLayout> {
    let overlay = snapshot.semantic_model_overlay()?;
    let path = match name {
        "Result" => "core.result.Result",
        "Option" => "core.option.Option",
        _ => unreachable!(),
    };
    let owner = super::super::crate_identity::RustOverlayCrates::new(Some(overlay))
        .referenceable_owner(path)?;
    let declaration = brokk_bifrost_analysis::analyzer::semantic_model::overlay::owner_declaration(
        snapshot.active_models(),
        &owner,
    )?;
    if declaration.type_kind != TypeKind::Enum {
        return None;
    }
    let names: &[&str] = match name {
        "Result" => &["Ok", "Err"],
        "Option" => &["Some", "None"],
        _ => unreachable!(),
    };
    if declaration.type_parameters.len() != if name == "Result" { 2 } else { 1 } {
        return None;
    }
    let mut variants = Vec::new();
    for (index, name) in names.iter().enumerate() {
        let member = overlay
            .members_named_for_provider(&owner.id, name, "rust", &owner.provenance.pack_digest)
            .unique()?;
        if member.kind != SemanticModelSymbolKind::Constant
            || member.owner_id.as_deref() != Some(owner.id.as_str())
            || member.provenance.pack_digest != owner.provenance.pack_digest
        {
            return None;
        }
        let signature = member.structured_signature.as_ref()?;
        let empty = *name == "None";
        if signature.returns.is_some() || signature.parameters.len() != usize::from(!empty) {
            return None;
        }
        if !empty {
            let parameter = &signature.parameters[0];
            let parameter_index = if *name == "Err" { 1 } else { 0 };
            if parameter.optional
                || parameter.variadic
                || parameter.r#type
                    != (TypeRef::TypeParameter {
                        name: declaration.type_parameters[parameter_index].clone(),
                    })
            {
                return None;
            }
        }
        debug_assert!(index < 2);
        variants.push(member);
    }
    Some(PayloadLayout { owner, variants })
}

fn declared_family(
    proof: &RustTypeProof<'_>,
    source: &RustSource,
    ty: Node<'_>,
) -> Option<&'static str> {
    application_family(proof, &proof.expand_written_type(source, ty)?)
}

fn application_family(
    proof: &RustTypeProof<'_>,
    application: &super::super::call_conversion::selected_type::AliasTypeExpr,
) -> Option<&'static str> {
    let super::super::call_conversion::selected_type::AliasTypeExpr::Constructor { site, .. } =
        application
    else {
        return None;
    };
    let declared = proof.source(&site.file)?;
    let head = proof.constructor_head(site, &declared)?;
    // The unqualified Result proof assumes its caller checked the spelling.
    // Scoped paths are checked structurally by standard_result_type_path.
    if (head.kind() != "type_identifier" || declared.node_text(head) == Some("Result"))
        && checked_result_type(proof, &declared, head)
    {
        return Some("Result");
    }
    // Owner proof checks generic arity. Keep the source-backed application,
    // rather than asking it to prove the bare head of Option<T>.
    let application = head
        .parent()
        .filter(|parent| {
            parent.kind() == "generic_type" && parent.child_by_field_name("type") == Some(head)
        })
        .unwrap_or(head);
    let RustReceiverOwner::Path(owner) = proof.declared_receiver_owner(&declared, application)?
    else {
        return None;
    };
    family(&owner)
}

fn checked_result_type(proof: &RustTypeProof<'_>, source: &RustSource, head: Node<'_>) -> bool {
    debug_assert!(
        head.kind() != "type_identifier" || source.node_text(head) == Some("Result"),
        "the unresolved Result fallback requires a checked identifier"
    );
    proof.standard_result_type(source, head)
}

// Return members are frontiers, not taint facts. Retain the complete typed
// path of nested payloads so a caller can demand them without collapsing an
// enclosing Result into its sibling variant.
fn declared_payload_paths(
    proof: &RustTypeProof<'_>,
    source: &RustSource,
    ty: Node<'_>,
    layouts: &HashMap<&str, PayloadLayout>,
    limitations: &mut Vec<Box<str>>,
) -> Vec<Vec<Arc<SemanticModelSymbol>>> {
    use super::super::call_conversion::selected_type::{AliasTypeExpr, expand_alias_head};
    let Some(application) = proof.expand_written_type(source, ty) else {
        return Vec::new();
    };
    let mut pending = vec![(application, Vec::new())];
    let mut paths = Vec::new();
    while let Some((application, prefix)) = pending.pop() {
        let application = match application {
            AliasTypeExpr::Constructor { ref site, .. } if site.kind != "primitive_type" => {
                let Ok(expanded) = expand_alias_head(
                    proof.analyzer,
                    application,
                    &CancellationToken::default(),
                    0,
                    false,
                ) else {
                    limitations.push("a nested returned payload type is unproven".into());
                    continue;
                };
                expanded
            }
            other => other,
        };
        let Some(name) = application_family(proof, &application) else {
            continue;
        };
        let Some(layout) = layouts.get(name) else {
            limitations
                .push("a nested returned payload declaration is unavailable or ambiguous".into());
            continue;
        };
        let AliasTypeExpr::Constructor { arguments, .. } = application else {
            unreachable!();
        };
        for (index, variant) in layout.variants.iter().enumerate() {
            if variant
                .structured_signature
                .as_ref()
                .expect("checked signature")
                .parameters
                .is_empty()
            {
                continue;
            }
            let mut path = prefix.clone();
            path.push(Arc::clone(variant));
            if path.len().saturating_mul(2)
                > brokk_bifrost_analysis::analyzer::semantic::OracleLimits::default()
                    .access_path_length()
            {
                limitations
                    .push("a nested returned payload exceeds the access-path length limit".into());
                continue;
            }
            paths.push(path.clone());
            if let Some(argument) = arguments.get(index) {
                pending.push((argument.clone(), path));
            }
        }
    }
    paths
}

fn operand_family<'s>(
    proof: &RustTypeProof<'_>,
    source: &'s RustSource,
    mut node: Node<'s>,
) -> Option<&'static str> {
    for _ in 0..PROOF_DEPTH {
        if let Some(RustReceiverOwner::Path(owner)) = proof.receiver_owner(source, node)
            && let Some(name) = family(&owner)
        {
            return Some(name);
        }
        match node.kind() {
            "identifier" => {
                if let Some(ty) = proof.declared_binding_type(source, node) {
                    return declared_family(proof, source, ty);
                }
                node = proof.binding_initializer(source, node)?;
            }
            "parenthesized_expression" => node = *named_children(node).first()?,
            "call_expression" => {
                let function = call_function_target(node.child_by_field_name("function")?);
                if let Some(fact) = proof.standard_constructor_fact(source, function) {
                    return match fact.constructs {
                        "Result" => Some("Result"),
                        "Option" => Some("Option"),
                        _ => None,
                    };
                }
                let unit = proof.callee_definition(source, node)?;
                let declared = proof.source(unit.source())?;
                let declaration = proof.declaration(&declared, &unit)?;
                if super::super::semantic::function_is_async(declaration) {
                    return None;
                }
                return declared_family(
                    proof,
                    &declared,
                    declaration.child_by_field_name("return_type")?,
                );
            }
            _ => return None,
        }
    }
    None
}

fn operand_application<'s>(
    proof: &RustTypeProof<'_>,
    source: &'s RustSource,
    mut operand: Node<'s>,
) -> Option<super::super::call_conversion::selected_type::AliasTypeExpr> {
    for _ in 0..PROOF_DEPTH {
        match operand.kind() {
            "identifier" => {
                if let Some(ty) = proof.declared_binding_type(source, operand) {
                    return proof.expand_written_type(source, ty);
                }
                operand = proof.binding_initializer(source, operand)?;
            }
            "parenthesized_expression" => operand = *named_children(operand).first()?,
            "call_expression" => {
                let unit = proof.callee_definition(source, operand)?;
                let declared = proof.source(unit.source())?;
                let item = proof.declaration(&declared, &unit)?;
                if super::super::semantic::function_is_async(item) {
                    return None;
                }
                return proof
                    .expand_written_type(&declared, item.child_by_field_name("return_type")?);
            }
            _ => return None,
        }
    }
    None
}

// Conservative certificate for selected standard applications with resolved
// primitive leaves. Unknown, inferred, non-selected and unsupported shapes
// refuse rather than acquiring a spelling-based type identity.
fn resolved_application(
    proof: &RustTypeProof<'_>,
    application: super::super::call_conversion::selected_type::AliasTypeExpr,
    layouts: &HashMap<&str, PayloadLayout>,
) -> Option<TypeRef> {
    use super::super::call_conversion::selected_type::{AliasTypeExpr, expand_alias_head};
    enum Step {
        Visit(AliasTypeExpr),
        Assemble(String, usize),
    }
    let mut pending = vec![Step::Visit(application)];
    let mut built = Vec::new();
    let mut remaining = 256usize;
    while let Some(step) = pending.pop() {
        match step {
            Step::Assemble(id, count) => {
                let arguments = built.split_off(built.len().checked_sub(count)?);
                built.push(TypeRef::Declared {
                    id,
                    arguments,
                    nullable: false,
                });
            }
            Step::Visit(application) => {
                remaining = remaining.checked_sub(1)?;
                let application = match application {
                    AliasTypeExpr::Constructor { ref site, .. }
                        if site.kind != "primitive_type" =>
                    {
                        expand_alias_head(
                            proof.analyzer,
                            application,
                            &CancellationToken::default(),
                            0,
                            false,
                        )
                        .ok()?
                    }
                    other => other,
                };
                let AliasTypeExpr::Constructor { ref site, .. } = application else {
                    return None;
                };
                if site.kind == "primitive_type" {
                    let declared = proof.source(&site.file)?;
                    let node = proof.constructor_head(site, &declared)?;
                    let name = declared.node_text(node)?;
                    super::super::call_conversion::primitive_for_spelling(name)?;
                    built.push(TypeRef::Named {
                        name: format!("core.primitive.{name}"),
                        arguments: Vec::new(),
                        nullable: false,
                    });
                    continue;
                }
                let name = application_family(proof, &application)?;
                let layout = layouts.get(name)?;
                let AliasTypeExpr::Constructor { arguments, .. } = application else {
                    unreachable!();
                };
                let arguments = arguments
                    .into_iter()
                    .filter(|argument| !matches!(argument, AliasTypeExpr::Lifetime))
                    .collect::<Vec<_>>();
                if arguments.len() != if name == "Result" { 2 } else { 1 } {
                    return None;
                }
                pending.push(Step::Assemble(layout.owner.id.clone(), arguments.len()));
                pending.extend(arguments.into_iter().rev().map(Step::Visit));
            }
        }
    }
    let [result] = built.as_slice() else {
        return None;
    };
    Some(result.clone())
}

fn application_error(
    proof: &RustTypeProof<'_>,
    application: super::super::call_conversion::selected_type::AliasTypeExpr,
) -> Option<super::super::call_conversion::selected_type::AliasTypeExpr> {
    use super::super::call_conversion::selected_type::AliasTypeExpr;
    if application_family(proof, &application)? != "Result" {
        return None;
    }
    let AliasTypeExpr::Constructor { arguments, .. } = application else {
        return None;
    };
    let mut arguments = arguments
        .into_iter()
        .filter(|argument| !matches!(argument, AliasTypeExpr::Lifetime));
    let (Some(_), Some(error), None) = (arguments.next(), arguments.next(), arguments.next())
    else {
        return None;
    };
    Some(error)
}

fn value_root(
    procedure: &ProcedureHandle,
    value: crate::analyzer::semantic::ValueId,
) -> AccessPathRoot {
    match ValueFlowEndpoint::for_value(
        procedure
            .value_handle(value)
            .expect("a live payload carrier"),
    ) {
        ValueFlowEndpoint::Value(value) => AccessPathRoot::Value(value),
        ValueFlowEndpoint::Port(port) => AccessPathRoot::ProcedurePort(port),
        ValueFlowEndpoint::Location(_) => unreachable!("a value is not a heap location"),
    }
}

fn payload_location(
    procedure: &ProcedureHandle,
    root: AccessPathRoot,
    variant: &SemanticModelSymbol,
) -> Result<ValueFlowEndpoint, SemanticProviderError> {
    payload_path_location(procedure, root, std::iter::once(variant))
}

fn payload_path_location<'a>(
    procedure: &ProcedureHandle,
    root: AccessPathRoot,
    variants: impl IntoIterator<Item = &'a SemanticModelSymbol>,
) -> Result<ValueFlowEndpoint, SemanticProviderError> {
    let steps = variants.into_iter().flat_map(|variant| {
        [
            PatternProjectionStep::Variant {
                declaration: variant.id.clone().into(),
            },
            PatternProjectionStep::Tuple(0),
        ]
    });
    let mut selectors = Vec::new();
    for step in steps {
        let Some(HeapSelector::Field(member)) = super::super::RustSupport
            .summary_endpoint_projection_selector(procedure.semantics().locator(), &step)
        else {
            unreachable!("Rust payload steps select canonical fields");
        };
        let scoped = brokk_bifrost_analysis::analyzer::semantic::ScopedSemanticLocator::new(
            Arc::clone(procedure.artifact()),
            member,
        )
        .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
        selectors.push(AccessSelector::Field(scoped));
    }
    let path = AccessPath::bounded(root, selectors, AccessPathTail::Exact, Default::default())
        .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
    ValueFlowEndpoint::for_path(path)
        .map_err(|error| SemanticProviderError::internal(error.to_string()))
}

fn source_node<'a>(
    source: &'a RustSource,
    procedure: &ProcedureHandle,
    mapping: crate::analyzer::semantic::SourceMappingId,
) -> Option<Node<'a>> {
    let span = procedure
        .semantics()
        .source_mapping(mapping)?
        .locator
        .anchor()
        .span();
    let node = source
        .tree()
        .root_node()
        .named_descendant_for_byte_range(span.start_byte() as usize, span.end_byte() as usize)?;
    (node.byte_range() == (span.start_byte() as usize..span.end_byte() as usize)).then_some(node)
}

fn unavailable(
    procedure: &ProcedureHandle,
    snapshot: Option<&ActiveSemanticModelSnapshot>,
    reason: &str,
) -> SemanticOutcome<SelectedPayloadProjection> {
    let mut digest = CanonicalHasher::new(b"rust-selected-payload-unavailable:v1");
    digest.value(procedure.artifact().key().fingerprint().as_bytes());
    if let Some(snapshot) = snapshot {
        digest.value(snapshot.active_models().active_model_set_hash().as_bytes());
    }
    SemanticOutcome::Unknown {
        partial: Some(SelectedPayloadProjection {
            identity: Some(StableDigest::from_array(digest.finish())),
            replacements: Box::default(),
            limitations: vec![reason.into()].into_boxed_slice(),
        }),
        work: Default::default(),
    }
}

pub(crate) fn select(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    snapshot: Option<&ActiveSemanticModelSnapshot>,
    request: &mut SemanticRequest<'_>,
) -> Result<SemanticOutcome<SelectedPayloadProjection>, SemanticProviderError> {
    // All absence decisions also read the artifact and active-model snapshot
    // through the shared selection owner. No source/model-dependent blob rows.
    let file = ProjectFile::new(
        workspace.analyzer().project().root(),
        procedure.artifact().key().path().as_path(),
    );
    if request.cancellation.is_cancelled() {
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work: Default::default(),
        });
    }
    let Some(mut proof) = RustTypeProof::new(workspace.analyzer()) else {
        return Ok(unavailable(
            procedure,
            snapshot,
            "the selected Rust type-proof provider is unavailable",
        ));
    };
    proof.resolver.cancellation = Some(request.cancellation.clone());
    let Some(source) = proof.source(&file) else {
        return Ok(unavailable(
            procedure,
            snapshot,
            "the exact payload source is unavailable",
        ));
    };
    if brokk_bifrost_analysis::analyzer::semantic::type_flow::validate_prepared_syntax_source_for_procedure(
        workspace, procedure, &file, Arc::clone(&source.prepared),
    ).is_err() {
        return Ok(unavailable(procedure, snapshot, "the payload source revision differs from the procedure"));
    }
    let mut callable = source_node(&source, procedure, procedure.semantics().source());
    while let Some(node) = callable {
        if is_procedure_boundary(node.kind()) {
            break;
        }
        callable = node.parent();
    }
    let return_family = callable
        .and_then(|node| node.child_by_field_name("return_type"))
        .and_then(|ty| declared_family(&proof, &source, ty));
    let mut layouts = HashMap::new();
    if let Some(snapshot) = snapshot {
        for name in ["Result", "Option"] {
            if let Some(layout) = selected_layout(snapshot, name) {
                layouts.insert(name, layout);
            }
        }
    }
    let residual_output = std::cell::OnceCell::<Option<TypeRef>>::new();
    let mut limitations = Vec::<Box<str>>::new();
    let return_paths = return_family
        .and(callable)
        .and_then(|node| node.child_by_field_name("return_type"))
        .map(|ty| declared_payload_paths(&proof, &source, ty, &layouts, &mut limitations))
        .unwrap_or_default();
    let mut selected = SelectedPayloadProjection::default();
    let mut digest = CanonicalHasher::new(b"rust-selected-payload-projection:v1");
    let mut affected = false;
    let mut rows = Vec::new();
    let mut work = SemanticWork::default();
    for point in procedure.semantics().points() {
        work.program_points = work.program_points.saturating_add(1);
        for (event, row) in point.events.iter().enumerate() {
            if request.cancellation.is_cancelled() {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: Default::default(),
                });
            }
            work.events = work.events.saturating_add(1);
            let event = u32::try_from(event).expect("event count fits u32");
            let mut replacements = Vec::new();
            let mut constructor_path = None;
            match row.effect {
                SemanticEffect::CallContinuation {
                    call_site,
                    kind: CallContinuationKind::Normal,
                } => {
                    let call = procedure
                        .semantics()
                        .call_site(call_site)
                        .expect("a live continuation call");
                    let Some(node) = source_node(&source, procedure, call.source)
                        .filter(|node| node.kind() == "call_expression")
                    else {
                        continue;
                    };
                    let Some(function) = node
                        .child_by_field_name("function")
                        .map(call_function_target)
                    else {
                        continue;
                    };
                    let Some(fact) = proof.standard_constructor_fact(&source, function) else {
                        continue;
                    };
                    if !matches!(fact.constructs, "Result" | "Option") {
                        continue;
                    }
                    affected = true;
                    let Some(layout) = layouts.get(fact.constructs) else {
                        limitations.push(
                            "the constructor payload declaration is unavailable or ambiguous"
                                .into(),
                        );
                        continue;
                    };
                    let Some(variant) = layout
                        .variants
                        .iter()
                        .find(|variant| variant.name == fact.name)
                    else {
                        continue;
                    };
                    let (Some(result), [argument]) = (call.result, call.arguments.as_ref()) else {
                        continue;
                    };
                    constructor_path = Some(
                        vec![
                            PatternProjectionStep::Variant {
                                declaration: variant.id.clone().into(),
                            },
                            PatternProjectionStep::Tuple(0),
                        ]
                        .into_boxed_slice(),
                    );
                    digest.value(fact.constructs.as_bytes());
                    digest.value(variant.id.as_bytes());
                    replacements.push(SelectedPayloadRelation {
                        kind: ValueFlowRelationKind::MemoryStore,
                        source: ValueFlowEndpoint::for_value(
                            procedure
                                .value_handle(argument.value)
                                .expect("a live constructor argument"),
                        ),
                        target: payload_location(
                            procedure,
                            value_root(procedure, result),
                            variant,
                        )?,
                    });
                }
                SemanticEffect::Assignment { target, value } => {
                    let Some(node) = source_node(&source, procedure, row.source)
                        .filter(|node| node.kind() == "try_expression")
                    else {
                        continue;
                    };
                    affected = true;
                    let Some(operand) = named_children(node).first().copied() else {
                        continue;
                    };
                    let Some(name) = operand_family(&proof, &source, operand) else {
                        limitations.push("the question-mark operand type is unproven".into());
                        continue;
                    };
                    let Some(layout) = layouts.get(name) else {
                        limitations.push(
                            "the selected payload declaration is unavailable or ambiguous".into(),
                        );
                        continue;
                    };
                    digest.value(name.as_bytes());
                    let residual = point.events.iter().any(|event| {
                        matches!(event.effect, SemanticEffect::ProcedureReturn { .. })
                    });
                    if residual && name == "Option" && return_family == Some("Option") {
                        // The selected standard Option residual is payload-free None.
                        // An empty replacement excludes the raw Some-to-return copy.
                    } else {
                        let source_root = value_root(procedure, value);
                        let source_variant = &layout.variants[usize::from(residual)];
                        let from = payload_location(procedure, source_root, source_variant)?;
                        let to = if residual {
                            let Some(output) = return_family
                                .and_then(|name| layouts.get(name))
                                .filter(|_| return_family == Some("Result"))
                            else {
                                limitations.push(
                                    "the residual's enclosing Result declaration is unavailable"
                                        .into(),
                                );
                                continue;
                            };
                            payload_location(
                                procedure,
                                value_root(procedure, target),
                                &output.variants[1],
                            )?
                        } else {
                            ValueFlowEndpoint::for_value(
                                procedure
                                    .value_handle(target)
                                    .expect("a live continued value"),
                            )
                        };
                        if residual {
                            let output = residual_output.get_or_init(|| {
                                let application = proof.expand_written_type(
                                    &source,
                                    callable?.child_by_field_name("return_type")?,
                                )?;
                                resolved_application(
                                    &proof,
                                    application_error(&proof, application)?,
                                    &layouts,
                                )
                            });
                            let input = operand_application(&proof, &source, operand)
                                .and_then(|application| application_error(&proof, application))
                                .and_then(|error| resolved_application(&proof, error, &layouts));
                            // A callee type can change without changing this
                            // procedure's bytes. Bind the complete proof inputs,
                            // including refusal, into every projected product.
                            digest.value(
                                &serde_json::to_vec(&(input.as_ref(), output.as_ref()))
                                    .expect("resolved type proof serializes"),
                            );
                            let certificate = input
                                .as_ref()
                                .zip(output.as_ref())
                                .is_some_and(|(input, output)| input == output);
                            // Equal fully resolved E selects reflexive impl<T>
                            // From<T> for T: identity, with no user code. Only
                            // exact member suffixes gain transport; the broad
                            // residual remains LanguageDefined, never an alias.
                            if certificate {
                                for path in return_paths.iter().filter(|path| {
                                    path.len() > 1 && path[0].id == layout.variants[1].id
                                }) {
                                    replacements.push(SelectedPayloadRelation {
                                        kind: ValueFlowRelationKind::MemoryLoad,
                                        source: payload_path_location(
                                            procedure,
                                            value_root(procedure, value),
                                            path.iter().map(AsRef::as_ref),
                                        )?,
                                        target: payload_path_location(
                                            procedure,
                                            value_root(procedure, target),
                                            path.iter().map(AsRef::as_ref),
                                        )?,
                                    });
                                }
                            }
                        }
                        replacements.push(SelectedPayloadRelation {
                            kind: if residual {
                                ValueFlowRelationKind::LanguageDefined
                            } else {
                                ValueFlowRelationKind::MemoryLoad
                            },
                            source: from,
                            target: to,
                        });
                    }
                }
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Return,
                    source: value,
                    ..
                } => {
                    let Some(name) = return_family else {
                        continue;
                    };
                    affected = true;
                    let Some(_) = layouts.get(name) else {
                        limitations.push(
                            "the returned payload declaration is unavailable or ambiguous".into(),
                        );
                        continue;
                    };
                    digest.value(name.as_bytes());
                    let root = procedure.value_handle(value).expect("a live return value");
                    let port = ProcedurePortHandle::normal_return(procedure.clone());
                    replacements.push(SelectedPayloadRelation {
                        kind: ValueFlowRelationKind::NormalReturn,
                        source: ValueFlowEndpoint::for_value(root.clone()),
                        target: ValueFlowEndpoint::Port(port.clone()),
                    });
                    for path in &return_paths {
                        replacements.push(SelectedPayloadRelation {
                            kind: ValueFlowRelationKind::NormalReturn,
                            source: payload_path_location(
                                procedure,
                                value_root(procedure, root.id()),
                                path.iter().map(AsRef::as_ref),
                            )?,
                            target: payload_path_location(
                                procedure,
                                AccessPathRoot::ProcedurePort(port.clone()),
                                path.iter().map(AsRef::as_ref),
                            )?,
                        });
                    }
                }
                _ => continue,
            }
            rows.push(SelectedPayloadEvent {
                point: point.id,
                event,
                relations: replacements.into_boxed_slice(),
                constructor_path,
            });
        }
    }
    rows.sort_by_key(|row| (row.point, row.event));
    selected.replacements = rows.into_boxed_slice();
    selected.limitations = limitations.into_boxed_slice();
    request.budget.charge_work(work);
    let retained = selected.retained_census();
    if let Err(exceeded) = request.budget.admit(retained) {
        return Ok(SemanticOutcome::ExceededBudget {
            partial: None,
            exceeded,
            work,
        });
    }
    work = work.conservative_add(retained);
    if affected {
        // A return alias can change in another file while this procedure and
        // the selected layouts stay unchanged. Bind the ordered typed paths,
        // including their boundaries, just as we bind residual proof inputs.
        let return_path_ids = return_paths
            .iter()
            .map(|path| {
                path.iter()
                    .map(|variant| variant.id.as_str())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        digest.value(&serde_json::to_vec(&return_path_ids).expect("return paths serialize"));
        for row in &selected.replacements {
            digest.value(&row.point.get().to_le_bytes());
            digest.value(&row.event.to_le_bytes());
        }
        for reason in &selected.limitations {
            digest.value(reason.as_bytes());
        }
        if let Some(snapshot) = snapshot {
            digest.value(snapshot.active_models().active_model_set_hash().as_bytes());
        }
        for name in ["Result", "Option"] {
            if let Some(layout) = layouts.get(name) {
                digest.value(layout.owner.id.as_bytes());
                digest.value(layout.owner.provenance.pack_digest.as_bytes());
                for variant in &layout.variants {
                    digest.value(variant.id.as_bytes());
                    digest.value(
                        &serde_json::to_vec(&variant.structured_signature)
                            .expect("signature serializes"),
                    );
                }
            }
        }
        selected.identity = Some(StableDigest::from_array(digest.finish()));
    }
    Ok(SemanticOutcome::Complete {
        value: selected,
        work,
    })
}
