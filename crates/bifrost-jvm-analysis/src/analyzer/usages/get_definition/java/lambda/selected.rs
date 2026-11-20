//! Selected supertype arguments for the source SAM adapter.

use super::*;
use brokk_bifrost_analysis::analyzer::resolution::{
    LoweredBindingProjection, LoweredDeclaredTypeArgument, LoweredIntrinsicSeed,
    LoweredSupertypeArguments, LoweredTypeComponent, LoweredTypedFrontier, ResolutionCompletion,
    SelectedTypedFactSource, SemanticId, TypedFactPageVisitor, TypedFactRequest,
};
use brokk_bifrost_analysis::analyzer::store::Result as StoreResult;
use brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_direct_supertypes::{
    JvmHierarchyQuery, JvmHierarchyReadReceipts,
};
use brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::HierarchyCrosswalkCache;
use brokk_bifrost_analysis::analyzer::store::resolution_operation::{
    LocatedSemantic, SelectedNativeDefinition, SelectedNativeDefinitions,
    SelectedResolutionOperation,
};
use brokk_bifrost_core::analyzer::resolution_facts::{
    BindingProjectionKind, ResolutionTypeComponentKind, ResolutionTypeConstructorKind,
};
use std::collections::{HashMap, HashSet};

#[derive(Default, Clone)]
struct Slot {
    frontiers: Vec<LoweredTypedFrontier>,
    projections: Vec<LoweredBindingProjection>,
    components: Vec<LoweredTypeComponent>,
    arguments: Vec<LoweredDeclaredTypeArgument>,
    seeds: Vec<LoweredIntrinsicSeed>,
    complete: bool,
}

#[derive(Clone, Copy)]
enum Node<'a> {
    Slot(SemanticId),
    Model(&'a TypeRef),
}
enum Form<'a> {
    Nominal(SourceReference, Vec<Node<'a>>),
    Primitive(brokk_bifrost_jvm::java::primitives::JavaPrimitive),
    Array(Node<'a>),
    Variable(usize),
    Open,
}

pub(super) struct SelectedSourceHierarchy<
    'a,
    'store,
    'input,
    'query,
    'source,
    R: JvmHierarchyReadReceipts,
> {
    operation: &'a SelectedResolutionOperation<'store, 'input>,
    query: &'a mut JvmHierarchyQuery<'query, 'source, R>,
    typed: &'a dyn SelectedTypedFactSource,
    models: &'a SemanticModelOverlay,
    jdk_digest: &'a str,
    session: &'a JavaResolutionSession<'a>,
    cancellation: &'a CancellationToken,
    definitions: HashMap<FunctionalOwner, SemanticId>,
    crosswalk: HierarchyCrosswalkCache,
    slots: HashMap<SemanticId, Slot>,
    native_cache: HashMap<SemanticId, Option<Arc<SelectedNativeDefinition>>>,
    parameter_cache: HashMap<(ProjectFile, std::ops::Range<usize>), Option<SemanticId>>,
}

impl<'a, 'store, 'input, 'query, 'source, R: JvmHierarchyReadReceipts>
    SelectedSourceHierarchy<'a, 'store, 'input, 'query, 'source, R>
{
    pub(super) fn new(
        operation: &'a SelectedResolutionOperation<'store, 'input>,
        query: &'a mut JvmHierarchyQuery<'query, 'source, R>,
        typed: &'a dyn SelectedTypedFactSource,
        models: &'a SemanticModelOverlay,
        jdk_digest: &'a str,
        session: &'a JavaResolutionSession<'a>,
        cancellation: &'a CancellationToken,
    ) -> Self {
        Self {
            operation,
            query,
            typed,
            models,
            jdk_digest,
            session,
            cancellation,
            definitions: HashMap::new(),
            crosswalk: HierarchyCrosswalkCache::default(),
            slots: HashMap::new(),
            native_cache: HashMap::new(),
            parameter_cache: HashMap::new(),
        }
    }

    fn charge(&self) -> bool {
        !self.cancellation.is_cancelled() && self.session.charge_scope_step()
    }

    fn native(
        &mut self,
        definition: SemanticId,
    ) -> StoreResult<Option<Arc<SelectedNativeDefinition>>> {
        if let Some(value) = self.native_cache.get(&definition) {
            return Ok(value.clone());
        }
        let SelectedNativeDefinitions::Ready(definitions) =
            self.operation.selected_hierarchy_definition_units(
                &[definition],
                self.cancellation,
                &self.session.resolution,
            )?
        else {
            self.native_cache.insert(definition, None);
            return Ok(None);
        };
        let value = definitions
            .into_iter()
            .find_map(|(id, value)| (id == definition).then(|| Arc::new(value)));
        self.native_cache.insert(definition, value.clone());
        Ok(value)
    }

    fn model(
        &self,
        owner: &brokk_bifrost_analysis::analyzer::resolution::ExternalOwnerIdentity,
    ) -> Option<Arc<SemanticModelSymbol>> {
        let matched = self.models.symbols_named_for(&owner.owner_fqn, "java");
        if matches!(
            matched.disposition,
            SemanticModelOverlayDisposition::Open(_)
        ) {
            return None;
        }
        let mut selected = matched.records.iter().filter(|symbol| {
            !symbol.provenance.ambiguous
                && symbol.provenance.pack_digest == owner.provider_id.as_ref()
        });
        let symbol = selected.next()?;
        if selected.next().is_some() {
            return None;
        }
        Some(Arc::clone(symbol))
    }

    fn owner(&mut self, definition: SemanticId) -> StoreResult<Option<FunctionalOwner>> {
        Ok(match self.native(definition)?.as_deref() {
            Some(SelectedNativeDefinition::Unit(unit)) => {
                Some(FunctionalOwner::Source(unit.clone()))
            }
            Some(SelectedNativeDefinition::ExternalOwner { owner, .. }) => self
                .model(owner)
                .map(|symbol| FunctionalOwner::External(symbol.id.clone())),
            _ => None,
        })
    }

    pub(super) fn edges(
        &mut self,
        owner: &FunctionalOwner,
        parameters: Option<&[SourceVariable]>,
        expected_content: Option<git2::Oid>,
    ) -> StoreResult<Option<SourceEdges>> {
        if !self.charge() {
            return Ok(None);
        }
        if let FunctionalOwner::Source(unit) = owner {
            let path = brokk_bifrost_core::path_utils::rel_path_string(unit.source());
            if self
                .operation
                .mount_table()
                .blob_oid_for_path("java", &path)?
                != expected_content
            {
                return Ok(None);
            }
        }
        let definition = match self.definitions.get(owner) {
            Some(definition) => *definition,
            None => {
                let FunctionalOwner::Source(unit) = owner else {
                    return Ok(None);
                };
                let LocatedSemantic::Found(definition) =
                    self.operation.selected_hierarchy_definition_cached(
                        unit,
                        &mut self.crosswalk,
                        self.cancellation,
                        &self.session.resolution,
                    )?
                else {
                    return Ok(None);
                };
                self.definitions.insert(owner.clone(), definition);
                definition
            }
        };
        let answer = self.query.jvm_direct_supertype_answer(definition)?;
        if answer.completion != ResolutionCompletion::Complete {
            return Ok(None);
        }
        let slots = answer
            .parents
            .iter()
            .filter_map(|edge| match &edge.applied_arguments {
                Some(LoweredSupertypeArguments::Source(slots)) => Some(slots.as_ref()),
                _ => None,
            })
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        self.prefetch(&slots)?;
        let context = match owner {
            FunctionalOwner::External(id) => {
                let selected = self.models.symbols_with_id(id);
                selected.records.first().cloned()
            }
            FunctionalOwner::Source(_) => None,
        };
        let mut edges = Vec::new();
        for edge in answer.parents {
            if !self.charge() || edge.completion != ResolutionCompletion::Complete {
                return Ok(None);
            }
            let [target] = edge.targets.as_slice() else {
                return Ok(None);
            };
            let Some(parent) = self.owner(*target)? else {
                return Ok(None);
            };
            self.definitions.insert(parent.clone(), *target);
            let arguments = match &edge.applied_arguments {
                None => None,
                Some(LoweredSupertypeArguments::Source(slots)) => {
                    let mut arguments = Vec::with_capacity(slots.len());
                    for slot in slots.iter() {
                        arguments.push(self.argument(
                            Node::Slot(*slot),
                            parameters,
                            context.as_deref(),
                        )?);
                    }
                    Some(arguments)
                }
                Some(LoweredSupertypeArguments::External(types)) => {
                    let mut arguments = Vec::with_capacity(types.len());
                    for ty in types.iter() {
                        arguments.push(self.argument(
                            Node::Model(ty),
                            parameters,
                            context.as_deref(),
                        )?);
                    }
                    Some(arguments)
                }
            };
            edges.push((parent, arguments));
        }
        Ok(Some(edges))
    }

    /// Each level batches the five selected row questions by immutable blob.
    fn prefetch(&mut self, roots: &[SemanticId]) -> StoreResult<()> {
        let mut pending = roots.to_vec();
        while !pending.is_empty() {
            pending.sort_unstable();
            pending.dedup();
            pending.retain(|slot| !self.slots.contains_key(slot));
            if pending.is_empty() {
                break;
            }
            if !self.charge() {
                return Ok(());
            }
            let mut nodes = pending
                .iter()
                .map(|slot| {
                    (
                        *slot,
                        Slot {
                            complete: true,
                            ..Slot::default()
                        },
                    )
                })
                .collect::<HashMap<_, _>>();
            let frontiers = self.typed.visit_typed_frontier_pages(
                TypedFactRequest::new(&pending),
                self.cancellation,
                &mut TypedFactPageVisitor::new(&mut |page| {
                    for row in page {
                        if let Some(node) = nodes.get_mut(&row.row().slot()) {
                            node.frontiers.push(*row.row());
                        }
                    }
                    Ok(true)
                }),
            )?;
            let projections = self.typed.visit_binding_projection_pages_for_outputs(
                TypedFactRequest::new(&pending),
                self.cancellation,
                &mut TypedFactPageVisitor::new(&mut |page| {
                    for row in page {
                        if let Some(node) = nodes.get_mut(&row.row().output_slot()) {
                            node.projections.push(*row.row());
                        }
                    }
                    Ok(true)
                }),
            )?;
            let components = self.typed.visit_type_component_pages_for_containers(
                TypedFactRequest::new(&pending),
                self.cancellation,
                &mut TypedFactPageVisitor::new(&mut |page| {
                    for row in page {
                        if let Some(node) = nodes.get_mut(&row.row().container()) {
                            node.components.push(*row.row());
                        }
                    }
                    Ok(true)
                }),
            )?;
            let arguments = self.typed.visit_declared_type_argument_pages_for_owners(
                TypedFactRequest::new(&pending),
                self.cancellation,
                &mut TypedFactPageVisitor::new(&mut |page| {
                    for row in page {
                        if let Some(node) = nodes.get_mut(&row.row().owner()) {
                            node.arguments.push(*row.row());
                        }
                    }
                    Ok(true)
                }),
            )?;
            let seeds = self.typed.visit_intrinsic_seed_pages_for_slots(
                TypedFactRequest::new(&pending),
                self.cancellation,
                &mut TypedFactPageVisitor::new(&mut |page| {
                    for row in page {
                        if let Some(node) = nodes.get_mut(&row.row().frontier().slot()) {
                            node.seeds.push(row.row().clone());
                        }
                    }
                    Ok(true)
                }),
            )?;
            let complete = [&frontiers, &projections, &components, &arguments, &seeds]
                .iter()
                .all(|outcome| {
                    outcome.is_exhausted() && outcome.evidence() == &ResolutionCompletion::Complete
                });
            pending.clear();
            for (slot, mut node) in nodes {
                node.complete &= complete;
                pending.extend(
                    node.components
                        .iter()
                        .map(|component| component.component()),
                );
                pending.extend(node.arguments.iter().map(|argument| argument.argument()));
                self.slots.insert(slot, node);
            }
        }
        Ok(())
    }

    fn source_form<'n>(
        &mut self,
        slot: SemanticId,
        parameters: Option<&[SourceVariable]>,
    ) -> StoreResult<Form<'n>> {
        let Some(node) = self.slots.get(&slot).cloned() else {
            return Ok(Form::Open);
        };
        if !node.complete {
            return Ok(Form::Open);
        }
        if !node.components.is_empty() {
            let [component] = node.components.as_slice() else {
                return Ok(Form::Open);
            };
            return Ok(
                if component.constructor() == ResolutionTypeConstructorKind::Sequence
                    && component.kind() == ResolutionTypeComponentKind::Element
                {
                    Form::Array(Node::Slot(component.component()))
                } else {
                    Form::Open
                },
            );
        }
        let mut references = node
            .frontiers
            .iter()
            .filter_map(|frontier| {
                frontier
                    .type_identity_reference()
                    .map(|(reference, _)| reference)
            })
            .chain(node.projections.iter().filter_map(|projection| {
                (projection.kind() == BindingProjectionKind::TargetTypeIdentity)
                    .then_some(projection.reference())
            }))
            .collect::<Vec<_>>();
        references.sort_unstable();
        references.dedup();
        let reference = if let [reference] = references.as_slice() {
            *reference
        } else {
            let [seed] = node.seeds.as_slice() else {
                return Ok(Form::Open);
            };
            return Ok(
                brokk_bifrost_jvm::java::primitives::primitive_for_name(seed.spelling())
                    .map_or(Form::Open, Form::Primitive),
            );
        };
        let Some(answer) = self.query.type_argument_reference_answer(reference)? else {
            return Ok(Form::Open);
        };
        if answer.binding().completion() != &ResolutionCompletion::Complete {
            return Ok(Form::Open);
        }
        let [target] = answer.binding().targets() else {
            return Ok(Form::Open);
        };
        if node.arguments.is_empty()
            && let Some(parameters) = parameters
        {
            use brokk_bifrost_analysis::analyzer::resolution::SelectedSemanticLocator;
            use brokk_bifrost_analysis::analyzer::store::resolution_lexical::SelectedSemanticLookupOutcome;
            for (position, parameter) in parameters.iter().enumerate() {
                let SourceVariable::Source(file, range, _, _, _, _) = parameter else {
                    continue;
                };
                let locator = SelectedSemanticLocator::for_declaration_range(
                    "java".to_owned(),
                    brokk_bifrost_core::path_utils::rel_path_string(file),
                    range.start,
                    range.end,
                );
                if !self.charge() {
                    return Ok(Form::Open);
                }
                let key = (file.clone(), range.clone());
                let definition = if let Some(cached) = self.parameter_cache.get(&key) {
                    *cached
                } else {
                    let answer = self
                        .operation
                        .ready()
                        .lexical_source()
                        .lookup_semantic_sites(
                            &locator,
                            self.cancellation,
                            &self.session.resolution,
                        )?;
                    let definition = match answer {
                        SelectedSemanticLookupOutcome::Found(sites) if sites.len() == 1 => {
                            Some(sites[0].semantic())
                        }
                        _ => None,
                    };
                    self.parameter_cache.insert(key, definition);
                    definition
                };
                if definition == Some(*target) {
                    return Ok(Form::Variable(position));
                }
            }
        }
        let native = self.native(*target)?;
        let reference = match native.as_deref() {
            Some(SelectedNativeDefinition::Unit(unit)) if unit.kind() == CodeUnitType::Class => {
                SourceReference::Source(unit.clone(), 0)
            }
            Some(SelectedNativeDefinition::ExternalOwner { owner, .. }) => {
                let Some(symbol) = self.model(owner) else {
                    return Ok(Form::Open);
                };
                SourceReference::Model(ErasedReference {
                    element: ErasedElement::Declared(symbol.id.clone()),
                    dimensions: 0,
                })
            }
            Some(SelectedNativeDefinition::Intrinsic { canonical_name, .. }) => {
                if let Some(kind) =
                    brokk_bifrost_jvm::java::primitives::primitive_for_name(canonical_name)
                {
                    return Ok(Form::Primitive(kind));
                }
                // The intrinsic resolver supplies a canonical Java identity. Bridge
                // it only to the declaration in this source's selected JDK artifact.
                let found = self.models.symbols_named_for(canonical_name, "java");
                if matches!(found.disposition, SemanticModelOverlayDisposition::Open(_)) {
                    return Ok(Form::Open);
                }
                let mut selected = found.records.iter().filter(|symbol| {
                    symbol.qualified_name == *canonical_name
                        && !symbol.provenance.ambiguous
                        && symbol
                            .provenance
                            .activation
                            .matched_evidence
                            .artifact_sha256
                            .as_deref()
                            == Some(self.jdk_digest)
                });
                let Some(symbol) = selected.next() else {
                    return Ok(Form::Open);
                };
                if selected.next().is_some() {
                    return Ok(Form::Open);
                }
                SourceReference::Model(ErasedReference {
                    element: ErasedElement::Declared(symbol.id.clone()),
                    dimensions: 0,
                })
            }
            _ => return Ok(Form::Open),
        };
        let mut arguments = node.arguments;
        arguments.sort_by_key(|argument| argument.position());
        if arguments
            .iter()
            .enumerate()
            .any(|(position, argument)| argument.position() as usize != position)
        {
            return Ok(Form::Open);
        }
        Ok(Form::Nominal(
            reference,
            arguments
                .into_iter()
                .map(|argument| Node::Slot(argument.argument()))
                .collect(),
        ))
    }

    fn form<'n>(
        &mut self,
        node: Node<'n>,
        parameters: Option<&[SourceVariable]>,
        context: Option<&SemanticModelSymbol>,
    ) -> StoreResult<Form<'n>> {
        let Node::Model(ty) = node else {
            let Node::Slot(slot) = node else {
                unreachable!()
            };
            return self.source_form(slot, parameters);
        };
        Ok(match ty {
            TypeRef::Array { element } => Form::Array(Node::Model(element)),
            TypeRef::TypeParameter { name } => parameters.and_then(|parameters| parameters.iter().position(|parameter| matches!(parameter, SourceVariable::Model((_, parameter, _)) if parameter == name))).map_or(Form::Open, Form::Variable),
            TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } => {
                let Some(context) = context else { return Ok(Form::Open); };
                match source_model_functional_type(self.models.java_functional_type(ty, context)) {
                    FunctionalType::Reference(reference) => Form::Nominal(reference, arguments.iter().map(Node::Model).collect()),
                    FunctionalType::Primitive(kind) => Form::Primitive(kind),
                    _ => Form::Open,
                }
            }
            _ => Form::Open,
        })
    }

    fn argument(
        &mut self,
        root: Node<'_>,
        parameters: Option<&[SourceVariable]>,
        context: Option<&SemanticModelSymbol>,
    ) -> StoreResult<JavaArgument<SourceClosedArgument>> {
        enum Visit<'n> {
            Node(Node<'n>),
            Exit(SemanticId),
        }
        let mut pending = vec![Visit::Node(root)];
        let mut active = HashSet::new();
        let mut shape = Vec::new();
        let mut ty = None;
        let mut dimensions = 0;
        let mut parameterized = false;
        while let Some(visit) = pending.pop() {
            if !self.charge() {
                return Ok(JavaArgument::Open);
            }
            let node = match visit {
                Visit::Exit(slot) => {
                    active.remove(&slot);
                    continue;
                }
                Visit::Node(node) => node,
            };
            if let Node::Slot(slot) = node {
                if !active.insert(slot) {
                    return Ok(JavaArgument::Open);
                }
                pending.push(Visit::Exit(slot));
            }
            match self.form(node, parameters, context)? {
                Form::Variable(position) if shape.is_empty() => {
                    return Ok(JavaArgument::Position(position));
                }
                Form::Variable(_) | Form::Open => return Ok(JavaArgument::Open),
                Form::Array(element) => {
                    shape.push(SourceClosedToken::Array);
                    if ty.is_none() {
                        dimensions += 1;
                    }
                    pending.push(Visit::Node(element));
                }
                Form::Primitive(kind) => {
                    shape.push(SourceClosedToken::Primitive(kind));
                    if ty.is_none() {
                        if dimensions == 0 {
                            return Ok(JavaArgument::Open);
                        }
                        ty = Some(FunctionalType::Reference(SourceReference::Model(
                            ErasedReference {
                                element: ErasedElement::Primitive(kind),
                                dimensions,
                            },
                        )));
                    }
                }
                Form::Nominal(reference, arguments) => {
                    if !arguments.is_empty() {
                        shape.push(SourceClosedToken::Applied(arguments.len()));
                        parameterized = true;
                    }
                    shape.push(SourceClosedToken::Reference(reference.clone()));
                    if ty.is_none() {
                        let mut reference = reference;
                        add_reference_dimensions(&mut reference, dimensions);
                        ty = Some(FunctionalType::Reference(reference));
                    }
                    pending.extend(arguments.into_iter().rev().map(Visit::Node));
                }
            }
        }
        Ok(ty.map_or(JavaArgument::Open, |ty| {
            JavaArgument::Closed(SourceClosedArgument {
                ty,
                shape,
                parameterized,
            })
        }))
    }
}
