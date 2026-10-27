//! File-local typed syntax. Candidate roles never prove builtin identity.
use super::*;

mod member_operations;

struct Typed<'a, 'source, 'collector> {
    p: &'a mut Producer<'source, 'collector>,
    scopes: &'a HashMap<usize, ResolutionScopeId>,
    references: HashMap<(usize, usize), ResolutionSiteId>,
    values: HashMap<usize, ResolutionTypeSlotId>,
    type_nodes: HashSet<usize>,
}

impl Typed<'_, '_, '_> {
    fn slot(&mut self, node: Node<'_>, role: ResolutionTypeSlotRole) -> ResolutionTypeSlotId {
        let site = self.p.site(
            node,
            self.scopes[&node.id()],
            ResolutionSiteKind::UnsupportedExpression,
        );
        self.p.facts.allocate_type_slot(site, role)
    }

    fn unknown(&mut self, node: Node<'_>) -> ResolutionTypeSlotId {
        let slot = self.slot(node, ResolutionTypeSlotRole::ExpressionValue);
        self.p.facts.add_gap(
            self.p.facts.type_slots[slot.index()].site,
            ResolutionGapKind::UnsupportedExpressionType,
        );
        slot
    }

    fn transfer(
        &mut self,
        input: ResolutionTypeSlotId,
        output: ResolutionTypeSlotId,
        kind: ResolutionTypeTransferKind,
        value_transform: ResolutionTypeTransferValueTransform,
    ) {
        self.p
            .facts
            .type_transfers
            .push(ResolutionTypeTransferFact {
                input,
                output,
                kind,
                indirection_delta: 0,
                reference_indirection_delta: 0,
                value_transform,
            });
    }

    fn reference(
        &mut self,
        node: Node<'_>,
        kind: ResolutionSiteKind,
        namespace: ResolutionNamespace,
    ) -> ResolutionSiteId {
        let key = (node.start_byte(), node.end_byte());
        if let Some(&site) = self.references.get(&key) {
            let fact = &mut self.p.facts.sites[site.index()];
            fact.kind = kind;
            self.p
                .facts
                .identifiers
                .iter_mut()
                .find(|id| id.site == site)
                .expect("reference identifier")
                .namespace = namespace;
            site
        } else {
            let site = self.p.identifier(
                node,
                self.scopes[&node.id()],
                kind,
                ResolutionIdentifierRole::Reference,
                namespace,
            );
            self.references.insert(key, site);
            site
        }
    }

    /// Expression dependencies are evaluated iteratively, including call chains.
    fn expression(&mut self, root: Node<'_>) -> ResolutionTypeSlotId {
        let mut pending = vec![(root, false)];
        while let Some((node, ready)) = pending.pop() {
            if self.values.contains_key(&node.id()) {
                continue;
            }
            if !ready {
                pending.push((node, true));
                let dependencies = match node.kind() {
                    "attribute" => node
                        .child_by_field_name("object")
                        .into_iter()
                        .collect::<Vec<_>>(),
                    "call" => {
                        let mut deps = node
                            .child_by_field_name("function")
                            .into_iter()
                            .collect::<Vec<_>>();
                        if let Some(args) = node.child_by_field_name("arguments") {
                            deps.extend(named_children_iter(args).map(argument_value));
                        }
                        deps
                    }
                    "parenthesized_expression" => named_children_iter(node).take(1).collect(),
                    _ => Vec::new(),
                };
                for dependency in dependencies.into_iter().rev() {
                    pending.push((dependency, false));
                }
                continue;
            }
            let slot = match node.kind() {
                "identifier" => {
                    let site = self.reference(
                        node,
                        ResolutionSiteKind::ValueReference,
                        ResolutionNamespace::Value,
                    );
                    let slot = self
                        .p
                        .facts
                        .allocate_type_slot(site, ResolutionTypeSlotRole::ExpressionValue);
                    self.p
                        .facts
                        .binding_projections
                        .push(BindingProjectionFact {
                            reference: site,
                            output: slot,
                            kind: BindingProjectionKind::TargetTypeOrDeclaredValueType,
                        });
                    slot
                }
                "attribute" => {
                    if let (Some(object), Some(attribute)) = (
                        node.child_by_field_name("object"),
                        node.child_by_field_name("attribute"),
                    ) {
                        let object_slot = self.values[&object.id()];
                        let receiver = self.slot(node, ResolutionTypeSlotRole::Receiver);
                        self.transfer(
                            object_slot,
                            receiver,
                            ResolutionTypeTransferKind::Receiver,
                            ResolutionTypeTransferValueTransform::Preserve,
                        );
                        let site = self.reference(
                            attribute,
                            ResolutionSiteKind::MemberReference,
                            ResolutionNamespace::Value,
                        );
                        self.p
                            .facts
                            .identifiers
                            .iter_mut()
                            .find(|id| id.site == site)
                            .unwrap()
                            .qualifier = Some(receiver);
                        // Module imports and local values share Python's Value
                        // namespace. The selected temporal binding, not syntax,
                        // decides whether this prefix can continue as a module.
                        if object.kind() == "identifier" {
                            let prefix_reference =
                                self.p.facts.type_slots[object_slot.index()].site;
                            let name = self
                                .p
                                .facts
                                .identifiers
                                .iter()
                                .find(|identifier| identifier.site == prefix_reference)
                                .expect("a spelled operand has a reference identifier")
                                .name;
                            self.p
                                .facts
                                .root_references
                                .push(ResolutionRootReferenceFact {
                                    reference: site,
                                    root_scope: ResolutionScopeId::new(0),
                                    anchor: ResolutionRootImportAnchor::Lexical,
                                    prefix_reference: Some(prefix_reference),
                                    owner_continued: false,
                                });
                            self.p.facts.root_reference_segments.push(
                                ResolutionRootReferenceSegmentFact {
                                    reference: site,
                                    position: 0,
                                    name,
                                },
                            );
                        }
                        let slot = self
                            .p
                            .facts
                            .allocate_type_slot(site, ResolutionTypeSlotRole::ExpressionValue);
                        self.p.facts.binding_projections.push(
                            BindingProjectionFact::target_declared_value_type(site, slot),
                        );
                        slot
                    } else {
                        self.unknown(node)
                    }
                }
                "call" => self.call(node),
                "parenthesized_expression" => named_children_iter(node)
                    .next()
                    .map(|child| self.values[&child.id()])
                    .unwrap_or_else(|| self.unknown(node)),
                _ => self.unknown(node),
            };
            self.values.insert(node.id(), slot);
        }
        self.values[&root.id()]
    }

    fn call(&mut self, node: Node<'_>) -> ResolutionTypeSlotId {
        let Some(function) = node.child_by_field_name("function") else {
            return self.unknown(node);
        };
        let input = self.values[&function.id()];
        let callee_node = if function.kind() == "attribute" {
            function.child_by_field_name("attribute")
        } else if function.kind() == "identifier" {
            Some(function)
        } else {
            None
        };
        let (callee, qualifier) = if let Some(callee_node) = callee_node {
            let callee = self.reference(
                callee_node,
                if function.kind() == "attribute" {
                    ResolutionSiteKind::MemberReference
                } else {
                    ResolutionSiteKind::CallableReference
                },
                ResolutionNamespace::Value,
            );
            let qualifier = self
                .p
                .facts
                .identifiers
                .iter()
                .find(|id| id.site == callee)
                .unwrap()
                .qualifier;
            (callee, qualifier)
        } else {
            // Preserve indirect call syntax and its argument labels even while
            // callable-value selection remains an explicit frontier.
            let callee = self.p.site(
                function,
                self.scopes[&function.id()],
                ResolutionSiteKind::UnsupportedExpression,
            );
            let value = self
                .p
                .facts
                .allocate_type_slot(callee, ResolutionTypeSlotRole::ExpressionValue);
            self.p
                .facts
                .add_gap(callee, ResolutionGapKind::UnsupportedCallApplicability);
            self.transfer(
                input,
                value,
                ResolutionTypeTransferKind::ExpressionResult,
                ResolutionTypeTransferValueTransform::Preserve,
            );
            (callee, None)
        };
        let call = self
            .p
            .site(node, self.scopes[&node.id()], ResolutionSiteKind::Call);
        let result = self
            .p
            .facts
            .allocate_type_slot(call, ResolutionTypeSlotRole::CallResult);
        let receiver = qualifier.map(|input| {
            let receiver = self
                .p
                .facts
                .allocate_type_slot(call, ResolutionTypeSlotRole::Receiver);
            self.transfer(
                input,
                receiver,
                ResolutionTypeTransferKind::Receiver,
                ResolutionTypeTransferValueTransform::Preserve,
            );
            receiver
        });
        self.p
            .facts
            .add_single_result_call(call, callee, receiver, result, 0);
        self.p
            .facts
            .call_argument_lists
            .push(ResolutionCallArgumentListFact {
                call,
                list_ordinal: 0,
            });
        if callee_node.is_some() {
            self.p
                .facts
                .binding_projections
                .push(BindingProjectionFact {
                    reference: callee,
                    output: result,
                    kind: BindingProjectionKind::TargetCallableResultType,
                });
        } else {
            self.p
                .facts
                .add_gap(call, ResolutionGapKind::UnsupportedExpressionType);
        }
        // Invocation validity stays on the callee obligation. It cannot change
        // the declaration identity carried by an otherwise proved result.
        self.p
            .facts
            .add_gap(callee, ResolutionGapKind::UnsupportedCallApplicability);
        // The expression value is retained for future callable-value selection.
        // A call does not turn this value into a type object or an allocation.
        debug_assert!(matches!(
            self.p.facts.type_slots[input.index()].role,
            ResolutionTypeSlotRole::ExpressionValue | ResolutionTypeSlotRole::CallResult
        ));
        if let Some(args) = node.child_by_field_name("arguments") {
            for (ordinal, arg) in named_children_iter(args).enumerate() {
                let ordinal = dense_ordinal(ordinal, "Python argument");
                let value = self.values[&argument_value(arg).id()];
                let argument = self
                    .p
                    .facts
                    .allocate_type_slot(call, ResolutionTypeSlotRole::Argument);
                self.transfer(
                    value,
                    argument,
                    ResolutionTypeTransferKind::Argument,
                    ResolutionTypeTransferValueTransform::Preserve,
                );
                let label = arg
                    .child_by_field_name("name")
                    .filter(|_| arg.kind() == "keyword_argument");
                let label = label.map(|label| {
                    let reference = self.p.identifier(
                        label,
                        self.scopes[&label.id()],
                        ResolutionSiteKind::ValueReference,
                        ResolutionIdentifierRole::Reference,
                        ResolutionNamespace::Value,
                    );
                    let name = self.p.facts.identifiers.last().unwrap().name;
                    self.p
                        .facts
                        .named_argument_labels
                        .push(ResolutionNamedArgumentLabelFact {
                            call,
                            reference,
                            label: name,
                        });
                    name
                });
                self.p
                    .facts
                    .call_arguments
                    .push(ResolutionCallArgumentFact {
                        call,
                        list_ordinal: 0,
                        ordinal,
                        value: argument,
                        label,
                    });
                let kind = match arg.kind() {
                    "keyword_argument" => PythonNativeArgumentKind::Keyword,
                    "list_splat" => PythonNativeArgumentKind::Star,
                    "dictionary_splat" => PythonNativeArgumentKind::DoubleStar,
                    _ => PythonNativeArgumentKind::Positional,
                };
                self.p
                    .facts
                    .python_call_arguments
                    .push(PythonNativeCallArgumentFact {
                        call,
                        ordinal,
                        kind,
                    });
            }
        }
        result
    }

    fn type_expression(&mut self, root: Node<'_>) -> ResolutionTypeSlotId {
        // Annotations are independent evidence, not eager runtime evaluation.
        let mut pending = vec![(root, false)];
        let mut slots = HashMap::default();
        while let Some((node, ready)) = pending.pop() {
            if !ready {
                pending.push((node, true));
                if node.kind() != "string" {
                    for child in named_children_iter(node)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                    {
                        pending.push((child, false));
                    }
                }
                continue;
            }
            self.type_nodes.insert(node.id());
            let slot = match node.kind() {
                "string" => self.quoted_annotation(node),
                "identifier" => {
                    let site = self.reference(
                        node,
                        ResolutionSiteKind::TypeReference,
                        ResolutionNamespace::Type,
                    );
                    let slot = self
                        .p
                        .facts
                        .allocate_type_slot(site, ResolutionTypeSlotRole::TargetTypeIdentity);
                    self.p
                        .facts
                        .binding_projections
                        .push(BindingProjectionFact::target_type_identity(site, slot));
                    if &self.p.source[node.byte_range()] == "__class__" {
                        self.p
                            .facts
                            .add_gap(site, ResolutionGapKind::UnsupportedScopeOrBinder);
                    }
                    slot
                }
                "attribute" => {
                    let attribute = node
                        .child_by_field_name("attribute")
                        .expect("attribute token");
                    let object = node
                        .child_by_field_name("object")
                        .expect("attribute object");
                    let site = self.reference(
                        attribute,
                        ResolutionSiteKind::MemberReference,
                        ResolutionNamespace::Type,
                    );
                    let qualifier = slots[&object.id()];
                    self.p
                        .facts
                        .identifiers
                        .iter_mut()
                        .find(|id| id.site == site)
                        .unwrap()
                        .qualifier = Some(qualifier);
                    // The terminal identifier already owns this type projection.
                    slots[&attribute.id()]
                }
                "member_type" => {
                    let children = named_children_iter(node).collect::<Vec<_>>();
                    let object = children
                        .iter()
                        .find(|child| child.kind() == "type")
                        .copied()
                        .expect("member type owner");
                    let attribute = children
                        .iter()
                        .find(|child| child.kind() == "identifier")
                        .copied()
                        .expect("member type name");
                    let site = self.reference(
                        attribute,
                        ResolutionSiteKind::MemberReference,
                        ResolutionNamespace::Type,
                    );
                    self.p
                        .facts
                        .identifiers
                        .iter_mut()
                        .find(|id| id.site == site)
                        .unwrap()
                        .qualifier = Some(slots[&object.id()]);
                    slots[&attribute.id()]
                }
                "type" if node.named_child_count() == 1 => {
                    slots[&node.named_child(0).unwrap().id()]
                }
                _ => {
                    let slot = self.slot(node, ResolutionTypeSlotRole::TargetTypeIdentity);
                    self.p.facts.add_gap(
                        self.p.facts.type_slots[slot.index()].site,
                        ResolutionGapKind::UnsupportedExpressionType,
                    );
                    slot
                }
            };
            slots.insert(node.id(), slot);
        }
        slots[&root.id()]
    }

    fn quoted_annotation(&mut self, node: Node<'_>) -> ResolutionTypeSlotId {
        // A direct annotation can wrap its string in a type node. Mark both so
        // the leftover pass does not publish the same omitted reference twice.
        self.type_nodes.insert(node.id());
        for child in named_children_iter(node).filter(|child| child.kind() == "string") {
            self.type_nodes.insert(child.id());
        }
        let slot = self.slot(node, ResolutionTypeSlotRole::TargetTypeIdentity);
        let site = self.p.facts.type_slots[slot.index()].site;
        self.p.facts.add_route_gap(
            site,
            ResolutionRouteGap::OmittedReference {
                scope: self.scopes[&node.id()],
                terminal: None,
                namespace: Some(ResolutionNamespace::Type),
            },
        );
        slot
    }

    fn annotation(
        &mut self,
        owner: ResolutionSiteId,
        node: Node<'_>,
        deferred: bool,
    ) -> Option<ResolutionTypeSlotId> {
        let quoted = named_children_iter(node).any(|child| child.kind() == "string")
            || node.kind() == "string";
        let slot = if quoted {
            self.quoted_annotation(node)
        } else {
            self.type_expression(node)
        };
        let site = self.p.facts.type_slots[slot.index()].site;
        self.p
            .facts
            .python_annotations
            .push(PythonNativeAnnotationFact {
                owner,
                syntax_site: site,
                type_slot: slot,
                mode: if quoted {
                    PythonNativeAnnotationMode::Quoted
                } else if deferred {
                    PythonNativeAnnotationMode::Deferred
                } else {
                    PythonNativeAnnotationMode::Eager
                },
            });
        (!quoted).then_some(slot)
    }
}

fn argument_value(node: Node<'_>) -> Node<'_> {
    match node.kind() {
        "keyword_argument" => node.child_by_field_name("value").unwrap_or(node),
        "list_splat" | "dictionary_splat" => named_children_iter(node).next().unwrap_or(node),
        _ => node,
    }
}

pub(super) fn produce(
    p: &mut Producer<'_, '_>,
    nodes: &[Node<'_>],
    scopes: &HashMap<usize, ResolutionScopeId>,
    scope_nodes: &HashMap<usize, ResolutionScopeId>,
    event_by_token: &HashMap<usize, u32>,
) {
    let references = p
        .facts
        .identifiers
        .iter()
        .filter(|id| id.role == ResolutionIdentifierRole::Reference)
        .map(|id| {
            let site = p.facts.sites[id.site.index()];
            ((site.start_byte, site.end_byte), id.site)
        })
        .collect();
    let mut t = Typed {
        p,
        scopes,
        references,
        values: HashMap::default(),
        type_nodes: HashSet::default(),
    };
    let mut declarations = HashMap::default();
    for node in nodes.iter().copied().filter(|node| {
        matches!(
            node.kind(),
            "class_definition" | "function_definition" | "lambda"
        )
    }) {
        let body_scope = scope_nodes[&node.id()];
        let authored = if let Some(owner) = t.p.facts.scopes[body_scope.index()].owner {
            owner
        } else {
            assert_eq!(node.kind(), "lambda");
            let site = t.p.site(
                node,
                scopes[&node.id()],
                ResolutionSiteKind::CallableDeclaration,
            );
            let declaration = t.p.collector.declare_node(node, None);
            t.p.declarations.push((site, declaration));
            t.p.facts.scopes[body_scope.index()].owner = Some(site);
            // Anonymous callables need identity, but have no lexical name.
            t.p.facts
                .callable_signatures
                .push(ResolutionCallableSignatureFact {
                    callable: site,
                    type_parameter_count: 0,
                    result_types: Vec::new(),
                });
            site
        };
        declarations.insert(node.id(), authored);
        let value =
            t.p.facts
                .allocate_type_slot(authored, ResolutionTypeSlotRole::ExpressionValue);
        t.p.facts
            .declaration_values
            .push(ResolutionDeclarationValueFact {
                declaration: authored,
                output: value,
                kind: if node.kind() == "class_definition" {
                    ResolutionDeclarationValueKind::TypeObject
                } else {
                    ResolutionDeclarationValueKind::Callable
                },
            });
        t.p.facts
            .add_gap(authored, ResolutionGapKind::UnsupportedExpressionType);
        t.values.insert(node.id(), value);
        if let Some(name) = node.child_by_field_name("name") {
            t.values.insert(name.id(), value);
        }
    }
    let suspended_scopes = nodes
        .iter()
        .filter(|node| node.kind() == "yield")
        .map(|node| scopes[&node.id()])
        .collect::<HashSet<_>>();
    let deferred = nodes
        .iter()
        .filter(|node| node.kind() == "future_import_statement")
        .any(|node| {
            let mut cursor = node.walk();
            node.children_by_field_name("name", &mut cursor)
                .any(|name| {
                    let imported = if name.kind() == "aliased_import" {
                        name.child_by_field_name("name")
                            .expect("future import name")
                    } else {
                        name
                    };
                    &t.p.source[imported.byte_range()] == "annotations"
                })
        });
    for node in nodes
        .iter()
        .copied()
        .filter(|node| matches!(node.kind(), "function_definition" | "lambda"))
    {
        let callable = declarations[&node.id()];
        t.p.facts
            .callable_parameter_lists
            .push(ResolutionCallableParameterListFact {
                callable,
                list_ordinal: 0,
                contextual: false,
            });
        if node.kind() == "lambda" {
            t.p.facts
                .add_gap(callable, ResolutionGapKind::UnsupportedCallApplicability);
        }
        let mut ordinal = 0;
        if let Some(params) = node.child_by_field_name("parameters") {
            let mut keyword_only = false;
            let mut ordinary = Vec::<usize>::new();
            for param in named_children_iter(params) {
                if param.kind() == "positional_separator" {
                    for index in ordinary.drain(..) {
                        t.p.facts.python_parameters[index].kind =
                            PythonNativeParameterKind::PositionalOnly;
                    }
                    continue;
                }
                if param.kind() == "keyword_separator" {
                    keyword_only = true;
                    continue;
                }
                let Some(token) = python_parameter_node(param) else {
                    continue;
                };
                let Some(&event) = event_by_token.get(&token.id()) else {
                    continue;
                };
                let parameter = t.p.facts.binding_events[event as usize]
                    .authored_declaration
                    .expect("a parameter event owns its authored value declaration");
                let splat = named_children_iter(param)
                    .find(|child| {
                        matches!(
                            child.kind(),
                            "list_splat_pattern" | "dictionary_splat_pattern"
                        )
                    })
                    .unwrap_or(param);
                let kind = match splat.kind() {
                    "list_splat_pattern" => {
                        keyword_only = true;
                        PythonNativeParameterKind::VarPositional
                    }
                    "dictionary_splat_pattern" => PythonNativeParameterKind::VarKeyword,
                    _ if keyword_only => PythonNativeParameterKind::KeywordOnly,
                    _ => PythonNativeParameterKind::PositionalOrKeyword,
                };
                if kind == PythonNativeParameterKind::PositionalOrKeyword {
                    ordinary.push(t.p.facts.python_parameters.len());
                }
                t.p.facts.python_parameters.push(PythonNativeParameterFact {
                    callable,
                    parameter,
                    ordinal,
                    kind,
                });
                let value =
                    t.p.facts
                        .allocate_type_slot(parameter, ResolutionTypeSlotRole::DeclaredValue);
                t.p.facts
                    .declaration_type_slots
                    .push(DeclarationTypeSlotFact {
                        declaration: parameter,
                        slot: value,
                        role: DeclarationTypeRole::Parameter,
                    });
                if let Some(annotation) = param.child_by_field_name("type") {
                    let input = t.annotation(parameter, annotation, deferred);
                    if matches!(
                        kind,
                        PythonNativeParameterKind::VarPositional
                            | PythonNativeParameterKind::VarKeyword
                    ) {
                        // The annotation describes elements, not the runtime tuple/dict.
                        t.p.facts
                            .add_gap(parameter, ResolutionGapKind::UnsupportedExpressionType);
                    } else if let Some(input) = input {
                        t.transfer(
                            input,
                            value,
                            ResolutionTypeTransferKind::DeclaredType,
                            ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                        );
                    }
                } else {
                    t.p.facts
                        .add_gap(parameter, ResolutionGapKind::UnsupportedExpressionType);
                }
                t.p.facts
                    .callable_parameters
                    .push(ResolutionCallableParameterFact {
                        callable,
                        list_ordinal: 0,
                        ordinal,
                        parameter,
                        value_type: value,
                        repeated: false,
                    });
                let label =
                    t.p.facts
                        .identifiers
                        .iter()
                        .find(|id| id.site == parameter)
                        .unwrap()
                        .name;
                t.p.facts.callable_parameter_semantics.push(
                    ResolutionCallableParameterSemanticsFact {
                        callable,
                        parameter,
                        list_ordinal: 0,
                        ordinal,
                        label,
                        has_default: param.child_by_field_name("value").is_some(),
                    },
                );
                ordinal += 1;
            }
        }
        // Shared repeated parameters must be terminal in their written list.
        // Python keyword-only/**kwargs shapes cannot be encoded as a curried
        // list or as fixed parameters. Keep their complete Python inventory and
        // the applicability gap, as other producers do for unrepresentable lists.
        let parameters =
            t.p.facts
                .python_parameters
                .iter()
                .filter(|row| row.callable == callable)
                .collect::<Vec<_>>();
        let represented = parameters.iter().enumerate().all(|(i, row)| {
            row.kind != PythonNativeParameterKind::VarKeyword
                && (row.kind != PythonNativeParameterKind::VarPositional
                    || i + 1 == parameters.len())
        });
        if represented {
            for row in
                t.p.facts
                    .callable_parameters
                    .iter_mut()
                    .filter(|row| row.callable == callable)
            {
                row.repeated = parameters[row.ordinal as usize].kind
                    == PythonNativeParameterKind::VarPositional;
            }
        } else {
            t.p.facts
                .callable_parameters
                .retain(|row| row.callable != callable);
            t.p.facts
                .callable_parameter_semantics
                .retain(|row| row.callable != callable);
        }
        if let Some(annotation) = node.child_by_field_name("return_type") {
            let input = t.annotation(callable, annotation, deferred);
            let mut cursor = node.walk();
            let asynchronous = node
                .children(&mut cursor)
                .any(|child| child.kind() == "async");
            if let Some(input) = input
                .filter(|_| !asynchronous && !suspended_scopes.contains(&scope_nodes[&node.id()]))
            {
                let value =
                    t.p.facts
                        .allocate_type_slot(callable, ResolutionTypeSlotRole::DeclaredValue);
                t.transfer(
                    input,
                    value,
                    ResolutionTypeTransferKind::DeclaredType,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                );
                t.p.facts
                    .callable_signatures
                    .iter_mut()
                    .find(|sig| sig.callable == callable)
                    .unwrap()
                    .result_types
                    .push(ResolutionCallableResultTypeFact {
                        ordinal: 0,
                        value_type: value,
                    });
                t.p.facts
                    .declaration_type_slots
                    .push(DeclarationTypeSlotFact {
                        declaration: callable,
                        slot: value,
                        role: DeclarationTypeRole::Return,
                    });
            }
        }
    }
    for node in nodes.iter().copied() {
        if node.kind() == "future_import_statement" {
            // Compiler-mode evidence is known, but the runtime _Feature binding
            // is not yet supplied by the native import producer.
            let site = t.p.site(
                node,
                scopes[&node.id()],
                ResolutionSiteKind::UnsupportedExpression,
            );
            t.p.facts
                .add_gap(site, ResolutionGapKind::UnsupportedScopeOrBinder);
            t.p.facts
                .add_reference_enumeration_gap(site, ResolutionGapKind::UnsupportedScopeOrBinder);
        }
        if node.kind() == "decorated_definition" {
            let Some(declaration_node) = node.child_by_field_name("definition") else {
                continue;
            };
            let Some(&declaration) = declarations.get(&declaration_node.id()) else {
                continue;
            };
            for (ordinal, decorator) in named_children_iter(node)
                .filter(|child| child.kind() == "decorator")
                .enumerate()
            {
                let Some(expression) = named_children_iter(decorator).next() else {
                    continue;
                };
                let value_slot = t.expression(expression);
                // This is a source spelling candidate, never builtin identity proof.
                let token = if expression.kind() == "attribute" {
                    expression.child_by_field_name("attribute")
                } else {
                    Some(expression)
                };
                let role = match token.map(|token| &t.p.source[token.byte_range()]) {
                    Some("property") => PythonNativeDecoratorRole::Property,
                    Some("classmethod") => PythonNativeDecoratorRole::ClassMethod,
                    Some("staticmethod") => PythonNativeDecoratorRole::StaticMethod,
                    Some("getter") => PythonNativeDecoratorRole::PropertyGetter,
                    Some("setter") => PythonNativeDecoratorRole::PropertySetter,
                    Some("deleter") => PythonNativeDecoratorRole::PropertyDeleter,
                    _ => PythonNativeDecoratorRole::Other,
                };
                t.p.facts.python_decorators.push(PythonNativeDecoratorFact {
                    declaration,
                    ordinal: dense_ordinal(ordinal, "Python decorator"),
                    expression_site: t.p.facts.type_slots[value_slot.index()].site,
                    value_slot,
                    role,
                });
            }
            let unknown = t.unknown(node);
            if let Some(name) = declaration_node.child_by_field_name("name") {
                t.values.insert(name.id(), unknown);
            }
        }
        if node.kind() == "class_definition" {
            let class = declarations[&node.id()];
            let mut metaclass_expression = None;
            let mut hierarchy_incomplete = node.has_error();
            if let Some(bases) = node.child_by_field_name("superclasses") {
                let mut ordinal = 0;
                for (written_ordinal, operand) in named_children_iter(bases).enumerate() {
                    if matches!(operand.kind(), "keyword_argument" | "dictionary_splat") {
                        let value = t.expression(argument_value(operand));
                        let name = operand.child_by_field_name("name").map(|name| {
                            t.p.facts
                                .intern_name(&mut t.p.names, &t.p.source[name.byte_range()])
                        });
                        if name.is_some_and(|name| {
                            t.p.facts.names[name.index()].spelling == "metaclass"
                        }) {
                            metaclass_expression = Some(t.p.facts.type_slots[value.index()].site);
                        }
                        t.p.facts
                            .python_class_keywords
                            .push(PythonNativeClassKeywordFact {
                                class,
                                ordinal: dense_ordinal(written_ordinal, "Python class keyword"),
                                expression_site: t.p.facts.type_slots[value.index()].site,
                                value,
                                name,
                            });
                        continue;
                    }
                    let plain = matches!(operand.kind(), "identifier" | "attribute");
                    hierarchy_incomplete |= !plain;
                    let slot = if plain {
                        t.type_expression(operand)
                    } else {
                        let slot = t.slot(operand, ResolutionTypeSlotRole::TargetTypeIdentity);
                        t.p.facts.add_gap(
                            t.p.facts.type_slots[slot.index()].site,
                            ResolutionGapKind::UnsupportedExpressionType,
                        );
                        slot
                    };
                    let site = t.p.facts.type_slots[slot.index()].site;
                    t.p.facts
                        .python_base_operands
                        .push(PythonNativeBaseOperandFact {
                            class,
                            ordinal,
                            expression_site: site,
                            slot,
                            kind: if operand.kind() == "list_splat" {
                                PythonNativeBaseKind::Star
                            } else {
                                PythonNativeBaseKind::Plain
                            },
                        });
                    if plain {
                        t.p.facts
                            .add_gap(site, ResolutionGapKind::UnsupportedHierarchyTraversal);
                        t.p.facts.supertypes.push(ResolutionSupertypeFact {
                            subtype: class,
                            parent_ordinal: ordinal,
                            supertype_reference: site,
                            supertype_slot: slot,
                            kind: ResolutionSupertypeKind::Superclass,
                        });
                    }
                    ordinal += 1;
                }
            }
            t.p.facts.python_classes.push(PythonNativeClassFact {
                class,
                metaclass_expression,
                bases_complete: !node.has_error(),
            });
            if hierarchy_incomplete {
                // Without a normalized edge, no exact parent proof can retire
                // this obligation. Ordinary base-less classes use implicit object.
                t.p.facts
                    .add_gap(class, ResolutionGapKind::UnsupportedHierarchyTraversal);
            }
        }
        if node.kind() == "assignment"
            && let Some(left) = node
                .child_by_field_name("left")
                .filter(|left| left.kind() == "attribute")
            && left.child_by_field_name("object").is_some()
        {
            let target = t.expression(left);
            let site = t.p.facts.type_slots[target.index()].site;
            let receiver =
                t.p.facts
                    .identifiers
                    .iter()
                    .find(|row| row.site == site)
                    .expect("attribute write target")
                    .qualifier
                    .expect("attribute receiver");
            let value = node
                .child_by_field_name("right")
                .map(|right| t.expression(right));
            t.p.facts
                .python_receiver_writes
                .push(PythonNativeReceiverWriteFact {
                    site,
                    receiver,
                    value,
                });
        }
        if node.kind() == "return_statement" || node.kind() == "lambda" {
            let return_scope = if node.kind() == "lambda" {
                scope_nodes[&node.id()]
            } else {
                scopes[&node.id()]
            };
            // A class body is not a return continuation of an enclosing function.
            let callable = find_scope_in_chain(
                Some(return_scope),
                |scope| t.p.facts.scopes[scope.index()].parent,
                |scope| {
                    let row = t.p.facts.scopes[scope.index()];
                    row.kind == ResolutionScopeKind::TypeBody
                        || row.owner.is_some_and(|owner| {
                            t.p.facts.sites[owner.index()].kind
                                == ResolutionSiteKind::CallableDeclaration
                        })
                },
            )
            .and_then(|scope| t.p.facts.scopes[scope.index()].owner)
            .filter(|owner| {
                t.p.facts.sites[owner.index()].kind == ResolutionSiteKind::CallableDeclaration
            });
            if let Some(callable) = callable {
                let expression = if node.kind() == "lambda" {
                    node.child_by_field_name("body")
                } else {
                    named_children_iter(node).next()
                };
                let input = expression
                    .map(|expression| t.expression(expression))
                    .unwrap_or_else(|| t.unknown(node));
                let return_site = t.p.site(
                    node,
                    return_scope,
                    ResolutionSiteKind::UnsupportedExpression,
                );
                let value =
                    t.p.facts
                        .allocate_type_slot(return_site, ResolutionTypeSlotRole::ReturnValue);
                t.transfer(
                    input,
                    value,
                    ResolutionTypeTransferKind::Return,
                    ResolutionTypeTransferValueTransform::Preserve,
                );
                t.p.facts
                    .callable_returns
                    .push(ResolutionCallableReturnFact {
                        callable,
                        return_site: t.p.facts.type_slots[value.index()].site,
                        value,
                    });
            } else {
                t.p.gap(
                    node,
                    return_scope,
                    ResolutionGapKind::UnsupportedScopeOrBinder,
                );
            }
        }
    }
    let by_id = nodes
        .iter()
        .map(|node| (node.id(), *node))
        .collect::<HashMap<_, _>>();
    let mut ordered_events = event_by_token
        .iter()
        .map(|(&token, &event)| (event, token))
        .collect::<Vec<_>>();
    ordered_events.sort_unstable();
    for (event, token_id) in ordered_events {
        let row = t.p.facts.binding_events[event as usize];
        if matches!(
            row.kind,
            ResolutionBindingEventKind::Delete
                | ResolutionBindingEventKind::Annotation
                | ResolutionBindingEventKind::Parameter
        ) {
            continue;
        }
        let token = by_id[&token_id];
        let operation = binding_operation(token).1;
        let value = match row.kind {
            ResolutionBindingEventKind::Function | ResolutionBindingEventKind::Class => {
                t.values.get(&token_id).copied()
            }
            ResolutionBindingEventKind::Assign => Some(
                operation
                    .child_by_field_name("right")
                    .or_else(|| operation.child_by_field_name("value"))
                    .map(|rhs| t.expression(rhs))
                    .unwrap_or_else(|| t.unknown(token)),
            ),
            // An augmented result, iteration element, context-manager entry or
            // exception value is not the operation's RHS/iterable value.
            _ => Some(t.unknown(token)),
        };
        t.p.facts.binding_events[event as usize].value = value;
        // Only a direct assignment target receives the RHS value itself.
        // Destructuring, augmented assignments and computed values are not
        // direct alias observations, even when they have a value projection.
        if row.kind == ResolutionBindingEventKind::Assign
            && operation
                .child_by_field_name("left")
                .is_some_and(|left| left.id() == token_id)
            && let Some(value) = value
        {
            let sources =
                t.p.facts
                    .binding_projections
                    .iter()
                    .filter(|projection| {
                        projection.output == value
                            && matches!(
                                projection.kind,
                                BindingProjectionKind::TargetDeclaredValueType
                                    | BindingProjectionKind::TargetTypeOrDeclaredValueType
                            )
                    })
                    .map(|projection| projection.reference)
                    .collect::<Vec<_>>();
            assert!(
                sources.len() <= 1,
                "one direct assignment value has one source reference: {sources:?}"
            );
            t.p.facts.binding_events[event as usize].source_reference = sources.first().copied();
        }
    }
    for node in nodes.iter().copied() {
        if matches!(node.kind(), "call" | "attribute")
            && !t.type_nodes.contains(&node.id())
            && !python_node_is_in_annotation(node)
            && find_ancestor(node, |ancestor| ancestor.kind() == "type_parameter").is_none()
        {
            t.expression(node);
        }
    }
    member_operations::produce(&mut t, nodes, event_by_token);
    // Source-contained class members. Their role does not certify access semantics.
    let events = t.p.facts.binding_events.clone();
    let mut fields = HashSet::default();
    let by_range = nodes
        .iter()
        .map(|node| ((node.start_byte(), node.end_byte()), *node))
        .collect::<HashMap<_, _>>();
    for event in events {
        let scope = t.p.facts.sites[event.slot.index()].scope;
        let Some(owner) = t.p.facts.scopes[scope.index()].owner else {
            continue;
        };
        if t.p.facts.scopes[scope.index()].kind != ResolutionScopeKind::TypeBody {
            continue;
        }
        let (member, kind) = if let Some(authored) = event.authored_declaration {
            (
                authored,
                match t.p.facts.sites[authored.index()].kind {
                    ResolutionSiteKind::TypeDeclaration => ResolutionMemberKind::NestedType,
                    ResolutionSiteKind::CallableDeclaration => ResolutionMemberKind::Method,
                    ResolutionSiteKind::ValueDeclaration => ResolutionMemberKind::Field,
                    kind => panic!(
                        "class member has an invalid authored site kind: {kind:?}; {event:?}"
                    ),
                },
            )
        } else {
            if event.kind == ResolutionBindingEventKind::Delete {
                continue;
            }
            let site = t.p.facts.sites[event.target.index()];
            let token = by_range[&(site.start_byte, site.end_byte)];
            if event.kind == ResolutionBindingEventKind::Annotation
                && binding_operation(token).1.kind() != "assignment"
            {
                continue;
            }
            if !fields.insert(event.slot) {
                continue;
            }
            let member = t.p.identifier(
                token,
                scope,
                ResolutionSiteKind::ValueDeclaration,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Value,
            );
            let declaration = t.p.collector.declare_node(token, Some(token));
            t.p.declarations.push((member, declaration));
            t.p.facts.binding_events[event.ordinal as usize].authored_declaration = Some(member);
            (member, ResolutionMemberKind::Field)
        };
        t.p.facts.member_owners.push(ResolutionMemberOwnerFact {
            member,
            owner,
            kind,
            access: if kind == ResolutionMemberKind::Method {
                ResolutionMemberAccess::Instance
            } else {
                ResolutionMemberAccess::Type
            },
            qualifier_compatibility: ResolutionMemberQualifierCompatibility::RuntimeOrType,
        });
        let decorator =
            t.p.facts
                .python_decorators
                .iter()
                .find(|row| row.declaration == member);
        let role = match decorator.map(|row| row.role) {
            Some(
                PythonNativeDecoratorRole::Property
                | PythonNativeDecoratorRole::PropertyGetter
                | PythonNativeDecoratorRole::PropertySetter
                | PythonNativeDecoratorRole::PropertyDeleter,
            ) => PythonNativeMemberRole::PropertyCandidate,
            Some(PythonNativeDecoratorRole::ClassMethod) => {
                PythonNativeMemberRole::ClassMethodCandidate
            }
            Some(PythonNativeDecoratorRole::StaticMethod) => {
                PythonNativeMemberRole::StaticMethodCandidate
            }
            Some(_) => PythonNativeMemberRole::Unknown,
            None if kind == ResolutionMemberKind::Method => {
                let name =
                    t.p.facts
                        .identifiers
                        .iter()
                        .find(|id| id.site == member)
                        .expect("method identifier")
                        .name;
                match t.p.facts.names[name.index()].spelling.as_str() {
                    "__get__" | "__set__" | "__delete__" => {
                        PythonNativeMemberRole::DescriptorCandidate
                    }
                    _ => PythonNativeMemberRole::OrdinaryFunction,
                }
            }
            _ => PythonNativeMemberRole::OrdinaryValue,
        };
        let site = t.p.facts.sites[member.index()];
        let direct_class_method = by_range[&(site.start_byte, site.end_byte)]
            .parent()
            .filter(|node| node.kind() == "function_definition")
            .and_then(|function| {
                let statement = function
                    .parent()
                    .filter(|parent| parent.kind() == "decorated_definition")
                    .unwrap_or(function);
                statement.parent()
            })
            .is_some_and(|body| {
                body.parent().is_some_and(|class| {
                    class.kind() == "class_definition"
                        && class.child_by_field_name("body") == Some(body)
                })
            });
        let receiver_parameter =
            t.p.facts
                .python_parameters
                .iter()
                .find(|row| {
                    direct_class_method
                        && row.callable == member
                        && matches!(
                            row.kind,
                            PythonNativeParameterKind::PositionalOnly
                                | PythonNativeParameterKind::PositionalOrKeyword
                        )
                })
                .map(|row| row.parameter);
        t.p.facts
            .python_member_roles
            .push(PythonNativeMemberRoleFact {
                owner,
                member,
                kind: role,
                callable: (kind == ResolutionMemberKind::Method).then_some(member),
                receiver_parameter,
            });
    }
    // Annotation-only fields acquire their authored member above. All Value
    // properties use that declaration identity, including initialized fields.
    for node in nodes
        .iter()
        .copied()
        .filter(|node| node.kind() == "assignment")
    {
        if let (Some(annotation), Some(left)) = (
            node.child_by_field_name("type"),
            node.child_by_field_name("left"),
        ) && let Some(&event) = event_by_token.get(&left.id())
        {
            let event = t.p.facts.binding_events[event as usize];
            let input = t.annotation(
                event.authored_declaration.unwrap_or(event.target),
                annotation,
                deferred,
            );
            let Some(owner) = event.authored_declaration else {
                // A local/module annotation without a value is not a runtime
                // binding. Retain its syntax, without typing the binding slot.
                t.p.facts
                    .add_gap(event.target, ResolutionGapKind::UnsupportedExpressionType);
                continue;
            };
            if let Some(input) = input {
                if t.p
                    .facts
                    .declaration_type_slots
                    .iter()
                    .any(|row| row.declaration == owner && row.role == DeclarationTypeRole::Value)
                {
                    t.p.facts
                        .add_gap(owner, ResolutionGapKind::UnsupportedExpressionType);
                    continue;
                }
                let value =
                    t.p.facts
                        .allocate_type_slot(owner, ResolutionTypeSlotRole::DeclaredValue);
                t.transfer(
                    input,
                    value,
                    ResolutionTypeTransferKind::DeclaredType,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                );
                t.p.facts
                    .declaration_type_slots
                    .push(DeclarationTypeSlotFact {
                        declaration: owner,
                        slot: value,
                        role: DeclarationTypeRole::Value,
                    });
            }
        }
    }
    // Computed assignment targets have no name-binder event. Their quoted
    // annotations still own omitted references, even without an annotation row.
    // Run after assignment annotations so every owned string is already marked.
    for node in nodes.iter().copied() {
        if node.kind() == "string"
            && python_node_is_in_annotation(node)
            && !t.type_nodes.contains(&node.id())
        {
            t.quoted_annotation(node);
        }
    }
    // An ordinary authored assignment reads the RHS through its declaration.
    // Preserve the value category: assigning a class object is not allocation,
    // while assigning a guarded call result retains its runtime instance.
    // An annotation already supplies this property and remains authoritative.
    for event in t.p.facts.binding_events.clone() {
        if event.kind != ResolutionBindingEventKind::Assign {
            continue;
        }
        let (Some(owner), Some(input)) = (event.authored_declaration, event.value) else {
            continue;
        };
        let site = t.p.facts.sites[event.target.index()];
        let token = by_range[&(site.start_byte, site.end_byte)];
        let operation = binding_operation(token).1;
        if operation
            .child_by_field_name("left")
            .is_none_or(|left| left != token)
            || t.p
                .facts
                .declaration_type_slots
                .iter()
                .any(|row| row.declaration == owner && row.role == DeclarationTypeRole::Value)
        {
            continue;
        }
        let value =
            t.p.facts
                .allocate_type_slot(owner, ResolutionTypeSlotRole::DeclaredValue);
        t.transfer(
            input,
            value,
            ResolutionTypeTransferKind::Initialization,
            ResolutionTypeTransferValueTransform::Preserve,
        );
        t.p.facts
            .declaration_type_slots
            .push(DeclarationTypeSlotFact {
                declaration: owner,
                slot: value,
                role: DeclarationTypeRole::Value,
            });
    }
    // Retain every structured call's compiler context, independently of callee
    // spelling. Only ordinary selected resolution may prove the builtin later.
    for call in t.p.facts.calls.clone() {
        let site = t.p.facts.sites[call.call.index()];
        let Some(&node) = by_range.get(&(site.start_byte, site.end_byte)) else {
            continue;
        };
        // Comprehensions have their own implicit frame; their first iterator
        // is not the enclosing method's receiver for zero-argument proxy calls.
        let callable_node = find_ancestor(node, |ancestor| {
            matches!(ancestor.kind(), "function_definition" | "lambda")
                || is_comprehension(ancestor.kind())
        })
        .filter(|ancestor| !is_comprehension(ancestor.kind()));
        let callable = callable_node.and_then(|node| declarations.get(&node.id()).copied());
        let class = callable_node
            .and_then(|node| find_ancestor(node, |ancestor| ancestor.kind() == "class_definition"))
            .and_then(|node| declarations.get(&node.id()).copied());
        // CPython requests the class cell for these structured identifier uses.
        // This is compiler capture eligibility, not builtin-role selection.
        let has_cell = callable_node.is_some_and(|node| {
            t.p.facts.identifiers.iter().any(|id| {
                let site = t.p.facts.sites[id.site.index()];
                id.role == ResolutionIdentifierRole::Reference
                    && site.start_byte >= node.start_byte()
                    && site.end_byte <= node.end_byte()
                    && matches!(
                        t.p.facts.names[id.name.index()].spelling.as_str(),
                        "__class__" | "super"
                    )
            })
        });
        let first_parameter = callable.and_then(|callable| {
            t.p.facts
                .python_parameters
                .iter()
                .find(|row| {
                    row.callable == callable
                        && row.ordinal == 0
                        && matches!(
                            row.kind,
                            PythonNativeParameterKind::PositionalOnly
                                | PythonNativeParameterKind::PositionalOrKeyword
                        )
                })
                .map(|row| row.parameter)
        });
        t.p.facts
            .python_super_contexts
            .push(PythonNativeSuperContextFact {
                call: call.call,
                callee: call.callee,
                callable,
                class_cell: class.filter(|_| has_cell),
                first_parameter,
            });
    }
    // Annotation identifiers now have structured type references. Retire only
    // scope gaps whose exact source range has such a reference; quoted/PEP695
    // and implicit class-cell gaps remain intact.
    let structured =
        t.p.facts
            .identifiers
            .iter()
            .filter(|row| {
                row.role == ResolutionIdentifierRole::Reference
                    && row.namespace == ResolutionNamespace::Type
                    && t.p.facts.names[row.name.index()].spelling != "__class__"
            })
            .map(|row| {
                let site = t.p.facts.sites[row.site.index()];
                (site.start_byte, site.end_byte)
            })
            .collect::<HashSet<_>>();
    let argument_containers = nodes
        .iter()
        .filter(|node| node.kind() == "type_parameter" && t.type_nodes.contains(&node.id()))
        .map(|node| (node.start_byte(), node.end_byte()))
        .collect::<HashSet<_>>();
    let covered =
        t.p.facts
            .sites
            .iter()
            .filter(|site| {
                structured.contains(&(site.start_byte, site.end_byte))
                    || argument_containers.contains(&(site.start_byte, site.end_byte))
            })
            .map(|site| site.id)
            .collect::<HashSet<_>>();
    t.p.facts.gaps.retain(|gap| {
        !(gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder && covered.contains(&gap.site))
    });
    t.p.facts.reference_enumeration_gaps.retain(|gap| {
        !(gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder && covered.contains(&gap.site))
    });
    // Include exact authored containment on every reference, with header lookup
    // scopes still separate. Lambda and module references have explicit owners.
    for id in &t.p.facts.identifiers {
        if id.role != ResolutionIdentifierRole::Reference {
            continue;
        }
        let site = t.p.facts.sites[id.site.index()];
        let owner = by_range
            .get(&(site.start_byte, site.end_byte))
            .and_then(|node| {
                find_ancestor(*node, |ancestor| declarations.contains_key(&ancestor.id()))
            })
            .map(|node| declarations[&node.id()]);
        t.p.facts
            .reference_owners
            .push(ResolutionReferenceOwnerFact {
                reference: id.site,
                owner,
            });
    }
}
