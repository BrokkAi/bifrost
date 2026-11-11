//! File-local typed syntax. Candidate roles never prove builtin identity.
use super::*;
use crate::structural::python_unwrap_type;

mod member_operations;

struct Typed<'a, 'source, 'collector, 'tree> {
    p: &'a mut Producer<'source, 'collector>,
    scopes: HashMap<usize, ResolutionScopeId>,
    quoted_roots: HashMap<usize, Node<'tree>>,
    references: HashMap<(usize, usize), ResolutionSiteId>,
    values: HashMap<usize, ResolutionTypeSlotId>,
    type_nodes: HashSet<usize>,
}

impl Typed<'_, '_, '_, '_> {
    fn slot(&mut self, node: Node<'_>, role: ResolutionTypeSlotRole) -> ResolutionTypeSlotId {
        let site = self.p.site(
            node,
            self.scopes[&node.id()],
            ResolutionSiteKind::UnsupportedExpression,
        );
        self.p.facts.allocate_type_slot(site, role)
    }

    // Implicit None has a real return-statement or body anchor, even though
    // that node does not contain a literal token.
    fn none_value(&mut self, anchor: Node<'_>) -> ResolutionTypeSlotId {
        let slot = self.slot(anchor, ResolutionTypeSlotRole::ExpressionValue);
        self.seed_none_type(slot);
        slot
    }

    fn seed_none_type(&mut self, slot: ResolutionTypeSlotId) {
        let name = self
            .p
            .facts
            .intern_name(&mut self.p.names, "types.NoneType");
        self.p
            .facts
            .intrinsic_type_seeds
            .push(IntrinsicTypeSeedFact::direct(
                slot,
                name,
                IntrinsicTypeKind::LanguageBuiltin,
            ));
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

    fn initialize_value(&mut self, owner: ResolutionSiteId, input: ResolutionTypeSlotId) {
        let value = self
            .p
            .facts
            .allocate_type_slot(owner, ResolutionTypeSlotRole::DeclaredValue);
        self.transfer(
            input,
            value,
            ResolutionTypeTransferKind::Initialization,
            ResolutionTypeTransferValueTransform::Preserve,
        );
        self.p
            .facts
            .declaration_type_slots
            .push(DeclarationTypeSlotFact {
                declaration: owner,
                slot: value,
                role: DeclarationTypeRole::Value,
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

    // Module imports and local values share Python's Value bindings. The
    // selected temporal binding decides whether an attribute prefix is a module,
    // including attributes used as types rather than runtime values.
    fn attribute_root(&mut self, object: Node<'_>, reference: ResolutionSiteId) {
        let object = python_unwrap_type(object);
        // Only identifier-rooted attribute chains have a lexical route. Calls,
        // subscripts and other expressions retain their typed receiver handling.
        if crate::syntax::python_static_attribute_path(object).is_none() {
            return;
        }
        let token = match object.kind() {
            "identifier" => Some(object),
            "attribute" => object.child_by_field_name("attribute"),
            _ => None,
        };
        if let Some(token) = token {
            let Some(&prefix_reference) =
                self.references.get(&(token.start_byte(), token.end_byte()))
            else {
                // A recovered operand without a structured reference retains
                // its expression gap; it cannot supply a module continuation.
                return;
            };
            // The route's first segment is the prefix identifier's semantic
            // name, including Python's class-private name mangling.
            let name = self.p.semantic_name(token);
            self.p
                .facts
                .root_references
                .push(ResolutionRootReferenceFact {
                    reference,
                    root_scope: ResolutionScopeId::new(0),
                    anchor: ResolutionRootImportAnchor::Lexical,
                    prefix_reference: Some(prefix_reference),
                    owner_continued: false,
                });
            self.p
                .facts
                .root_reference_segments
                .push(ResolutionRootReferenceSegmentFact {
                    reference,
                    position: 0,
                    name,
                });
        }
    }

    /// The member reference of `object.attribute`, qualified by the object's
    /// value. The caller decides which projection the reference publishes.
    fn member_reference(
        &mut self,
        node: Node<'_>,
        object: Node<'_>,
        attribute: Node<'_>,
    ) -> ResolutionSiteId {
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
        self.attribute_root(object, site);
        site
    }

    /// Lower the callee reference of a call. Its only projection is the call's
    /// callable result, which call() publishes.
    fn callee(&mut self, function: Node<'_>) {
        if function.kind() == "identifier" {
            self.reference(
                function,
                ResolutionSiteKind::CallableReference,
                ResolutionNamespace::Value,
            );
        } else {
            let object = function
                .child_by_field_name("object")
                .expect("callee attribute object");
            let attribute = function
                .child_by_field_name("attribute")
                .expect("callee attribute token");
            self.member_reference(function, object, attribute);
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
                    "subscript" => named_children_iter(node).collect(),
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
            if python_call_callee(node) {
                // A callee publishes only its call's callable-result
                // projection (see call()), as Go and Rust do. It has no value
                // slot of its own for anything to read.
                self.callee(node);
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
                "none" => self.none_value(node),
                "attribute" => {
                    if let (Some(object), Some(attribute)) = (
                        node.child_by_field_name("object"),
                        node.child_by_field_name("attribute"),
                    ) {
                        let site = self.member_reference(node, object, attribute);
                        let slot = self
                            .p
                            .facts
                            .allocate_type_slot(site, ResolutionTypeSlotRole::ExpressionValue);
                        // Attribute and bare-name reads share Python's value
                        // namespace: a selected class is a type object, while
                        // fields retain their declared value projection.
                        self.p
                            .facts
                            .binding_projections
                            .push(BindingProjectionFact {
                                reference: site,
                                output: slot,
                                kind: BindingProjectionKind::TargetTypeOrDeclaredValueType,
                            });
                        slot
                    } else {
                        self.unknown(node)
                    }
                }
                "subscript" => self.subscript(node),
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

    fn subscript(&mut self, node: Node<'_>) -> ResolutionTypeSlotId {
        let Some(object) = node.child_by_field_name("value") else {
            return self.unknown(node);
        };
        let call = self
            .p
            .site(node, self.scopes[&node.id()], ResolutionSiteKind::Call);
        let receiver = self
            .p
            .facts
            .allocate_type_slot(call, ResolutionTypeSlotRole::Receiver);
        self.transfer(
            self.values[&object.id()],
            receiver,
            ResolutionTypeTransferKind::Receiver,
            ResolutionTypeTransferValueTransform::RuntimeOnly,
        );
        // Indexing invokes the class's implicit protocol, not an attribute
        // spelled by the program. Callable marks this protocol demand; normal
        // Python attributes and calls continue to select the Value namespace.
        let reference = self.p.site(
            node,
            self.scopes[&node.id()],
            ResolutionSiteKind::MemberReference,
        );
        let name = self.p.facts.intern_name(&mut self.p.names, "__getitem__");
        self.p.facts.identifiers.push(PositionedIdentifierFact {
            site: reference,
            name,
            role: ResolutionIdentifierRole::Reference,
            namespace: ResolutionNamespace::Callable,
            qualifier: Some(receiver),
        });
        let result = self
            .p
            .facts
            .allocate_type_slot(call, ResolutionTypeSlotRole::CallResult);
        self.p
            .facts
            .add_single_result_call(call, reference, Some(receiver), result, 0);
        self.p
            .facts
            .call_argument_lists
            .push(ResolutionCallArgumentListFact {
                call,
                list_ordinal: 0,
            });
        let indices = named_children_iter(node)
            .filter(|child| child.id() != object.id())
            .collect::<Vec<_>>();
        let index = if let [index] = indices.as_slice() {
            self.values[&index.id()]
        } else {
            self.unknown(node)
        };
        let argument = self
            .p
            .facts
            .allocate_type_slot(call, ResolutionTypeSlotRole::Argument);
        self.transfer(
            index,
            argument,
            ResolutionTypeTransferKind::Argument,
            ResolutionTypeTransferValueTransform::Preserve,
        );
        self.p
            .facts
            .call_arguments
            .push(ResolutionCallArgumentFact {
                call,
                list_ordinal: 0,
                ordinal: 0,
                value: argument,
                label: None,
            });
        self.p
            .facts
            .python_call_arguments
            .push(PythonNativeCallArgumentFact {
                call,
                ordinal: 0,
                kind: PythonNativeArgumentKind::Positional,
            });
        self.p
            .facts
            .add_gap(reference, ResolutionGapKind::UnsupportedCallApplicability);
        self.p
            .facts
            .binding_projections
            .push(BindingProjectionFact {
                reference,
                output: result,
                kind: BindingProjectionKind::TargetCallableResultType,
            });
        result
    }

    fn call(&mut self, node: Node<'_>) -> ResolutionTypeSlotId {
        let Some(function) = node.child_by_field_name("function") else {
            return self.unknown(node);
        };
        let callee_node = if !python_call_callee(function) {
            None
        } else if function.kind() == "attribute" {
            function.child_by_field_name("attribute")
        } else {
            Some(function)
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
            let input = self.values[&function.id()];
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
            // The expression value is retained for future callable-value selection.
            // A call does not turn this value into a type object or an allocation.
            debug_assert!(matches!(
                self.p.facts.type_slots[input.index()].role,
                ResolutionTypeSlotRole::ExpressionValue | ResolutionTypeSlotRole::CallResult
            ));
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
                    // The owner of a qualified type is an ordinary Python
                    // expression. Only its terminal is a type reference.
                    for child in named_children_iter(node)
                        .filter(|child| match node.kind() {
                            "attribute" => node.child_by_field_name("attribute") == Some(*child),
                            "member_type" => child.kind() == "identifier",
                            _ => true,
                        })
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
                    let qualifier = self.expression(object);
                    self.p
                        .facts
                        .identifiers
                        .iter_mut()
                        .find(|id| id.site == site)
                        .unwrap()
                        .qualifier = Some(qualifier);
                    self.attribute_root(object, site);
                    // The terminal identifier already owns this type projection.
                    slots[&attribute.id()]
                }
                "member_type" => {
                    let children = named_children_iter(node).collect::<Vec<_>>();
                    let mut object = children
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
                    while object.kind() == "type" && object.named_child_count() == 1 {
                        object = object.named_child(0).unwrap();
                    }
                    let qualifier = self.expression(object);
                    self.p
                        .facts
                        .identifiers
                        .iter_mut()
                        .find(|id| id.site == site)
                        .unwrap()
                        .qualifier = Some(qualifier);
                    self.attribute_root(object, site);
                    slots[&attribute.id()]
                }
                "generic_type" | "subscript" => {
                    let head = python_annotation_application_head(node).expect("generic head");
                    let application = slots[&head.id()];
                    let arguments = if node.kind() == "subscript" {
                        let mut cursor = node.walk();
                        node.children_by_field_name("subscript", &mut cursor)
                            .collect::<Vec<_>>()
                    } else {
                        named_children_iter(node)
                            .filter(|child| child.kind() == "type_parameter")
                            .flat_map(named_children_iter)
                            .collect::<Vec<_>>()
                    };
                    for (ordinal, argument) in arguments.into_iter().enumerate() {
                        self.p
                            .facts
                            .type_arguments
                            .push(ResolutionTypeArgumentFact {
                                application,
                                ordinal: ordinal as u32,
                                argument: slots[&argument.id()],
                                indirection_delta: 0,
                                reference_indirection_delta: 0,
                            });
                    }
                    // An application names its outer class, never an argument.
                    // A typing form such as `Optional` or `Generator` is an
                    // external import whose provider stays open, so its
                    // application stays open too instead of naming a class.
                    // `type[X]` denotes the class object of X, which a type
                    // identity cannot express, so it keeps its gap. The name
                    // test only refuses; a shadowed `type` stays open as well.
                    let slot = self.slot(node, ResolutionTypeSlotRole::TargetTypeIdentity);
                    let terminal = match head.kind() {
                        "attribute" => head.child_by_field_name("attribute"),
                        _ => Some(head),
                    };
                    if terminal
                        .is_some_and(|terminal| &self.p.source[terminal.byte_range()] == "type")
                    {
                        self.p.facts.add_gap(
                            self.p.facts.type_slots[slot.index()].site,
                            ResolutionGapKind::UnsupportedExpressionType,
                        );
                    } else {
                        self.transfer(
                            application,
                            slot,
                            ResolutionTypeTransferKind::TypeIdentity,
                            ResolutionTypeTransferValueTransform::Preserve,
                        );
                    }
                    slot
                }
                // PEP 604 `X | Y`: every member is a possible type of the
                // annotated value, including `None`.
                "union_type" | "binary_operator"
                    if node.kind() == "union_type"
                        || node
                            .child_by_field_name("operator")
                            .is_some_and(|operator| operator.kind() == "|") =>
                {
                    let slot = self.slot(node, ResolutionTypeSlotRole::TargetTypeIdentity);
                    for member in named_children_iter(node).collect::<Vec<_>>() {
                        self.transfer(
                            slots[&member.id()],
                            slot,
                            ResolutionTypeTransferKind::TypeUnion,
                            ResolutionTypeTransferValueTransform::Preserve,
                        );
                    }
                    slot
                }
                // `None` as a union member denotes NoneType. A bare `None`
                // annotation keeps its existing gap.
                "none" if python_annotation_union_member(node) => {
                    let slot = self.slot(node, ResolutionTypeSlotRole::TargetTypeIdentity);
                    self.seed_none_type(slot);
                    slot
                }
                "type" | "module" | "expression_statement" | "parenthesized_expression"
                    if node.named_child_count() == 1 =>
                {
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
        // the leftover pass does not publish the same annotation twice.
        self.type_nodes.insert(node.id());
        for child in named_children_iter(node).filter(|child| child.kind() == "string") {
            self.type_nodes.insert(child.id());
        }
        let slot = self.slot(node, ResolutionTypeSlotRole::TargetTypeIdentity);
        let site = self.p.facts.type_slots[slot.index()].site;
        let string = if node.kind() == "string" {
            Some(node)
        } else {
            named_children_iter(node).find(|child| child.kind() == "string")
        };
        let root = string.and_then(|string| self.quoted_roots.get(&string.id()).copied());
        if let Some(root) = root {
            // Only original-source strings have embedded roots. Strings inside
            // an embedded tree cannot recursively expand another annotation.
            let input = self.type_expression(root);
            self.transfer(
                input,
                slot,
                ResolutionTypeTransferKind::TypeIdentity,
                ResolutionTypeTransferValueTransform::Preserve,
            );
            self.p
                .facts
                .python_annotations
                .push(PythonNativeAnnotationFact {
                    owner: site,
                    syntax_site: site,
                    type_slot: slot,
                    mode: PythonNativeAnnotationMode::Quoted,
                });
        } else {
            self.p.facts.add_route_gap(
                site,
                ResolutionRouteGap::OmittedReference {
                    scope: self.scopes[&node.id()],
                    terminal: None,
                    namespace: Some(ResolutionNamespace::Type),
                },
            );
        }
        slot
    }

    fn annotation(
        &mut self,
        owner: ResolutionSiteId,
        node: Node<'_>,
        deferred: bool,
    ) -> Option<ResolutionTypeSlotId> {
        let annotation_start = self.p.facts.python_annotations.len();
        let quoted = named_children_iter(node).any(|child| child.kind() == "string")
            || node.kind() == "string";
        let slot = if quoted {
            self.quoted_annotation(node)
        } else {
            self.type_expression(node)
        };
        let site = self.p.facts.type_slots[slot.index()].site;
        let node = python_unwrap_type(node);
        let syntax = if node.kind() == "string" {
            self.quoted_roots.get(&node.id()).copied().unwrap_or(node)
        } else {
            node
        };
        let syntax_head = python_annotation_application_head(syntax).and_then(|head| {
            let token = match head.kind() {
                "attribute" => head.child_by_field_name("attribute")?,
                "member_type" => {
                    named_children_iter(head).find(|child| child.kind() == "identifier")?
                }
                _ => head,
            };
            self.references
                .get(&(token.start_byte(), token.end_byte()))
                .copied()
        });

        let supported = !quoted
            || self.p.facts.python_annotations[annotation_start..]
                .iter()
                .any(|annotation| annotation.syntax_site == site);
        // Nested quoted operands retain their own postponed observation, even
        // when the enclosing annotation is eager.
        for annotation in &mut self.p.facts.python_annotations[annotation_start..] {
            annotation.owner = owner;
        }
        if !self.p.facts.python_annotations[annotation_start..]
            .iter()
            .any(|annotation| annotation.syntax_site == site)
        {
            self.p
                .facts
                .python_annotations
                .push(PythonNativeAnnotationFact {
                    owner,
                    syntax_site: syntax_head.unwrap_or(site),
                    type_slot: slot,
                    mode: if quoted {
                        PythonNativeAnnotationMode::Quoted
                    } else if deferred {
                        PythonNativeAnnotationMode::Deferred
                    } else {
                        PythonNativeAnnotationMode::Eager
                    },
                });
        }
        supported.then_some(slot)
    }
}

/// Whether an annotation node is a member of a PEP 604 union, through any
/// `type` wrappers the grammar puts around union members.
fn python_annotation_union_member(node: Node<'_>) -> bool {
    let mut parent = node.parent();
    while let Some(wrapper) = parent.filter(|parent| parent.kind() == "type") {
        parent = wrapper.parent();
    }
    parent.is_some_and(|parent| {
        parent.kind() == "union_type"
            || (parent.kind() == "binary_operator"
                && parent
                    .child_by_field_name("operator")
                    .is_some_and(|operator| operator.kind() == "|"))
    })
}

fn python_annotation_application_head(node: Node<'_>) -> Option<Node<'_>> {
    let node = python_unwrap_type(node);
    match node.kind() {
        "generic_type" => named_children_iter(node).find(|child| child.kind() == "identifier"),
        "subscript" => node.child_by_field_name("value"),
        _ => None,
    }
}

/// A name or attribute that is the `function` of a call. Such a reference
/// publishes the call's callable-result projection, not a value projection.
fn python_call_callee(node: Node<'_>) -> bool {
    let named = match node.kind() {
        "identifier" => true,
        "attribute" => {
            node.child_by_field_name("object").is_some()
                && node.child_by_field_name("attribute").is_some()
        }
        _ => false,
    };
    named
        && node.parent().is_some_and(|parent| {
            parent.kind() == "call" && parent.child_by_field_name("function") == Some(node)
        })
}

fn argument_value(node: Node<'_>) -> Node<'_> {
    match node.kind() {
        "keyword_argument" => node.child_by_field_name("value").unwrap_or(node),
        "list_splat" | "dictionary_splat" => named_children_iter(node).next().unwrap_or(node),
        _ => node,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn produce(
    p: &mut Producer<'_, '_>,
    nodes: &[Node<'_>],
    mut scopes: HashMap<usize, ResolutionScopeId>,
    scope_nodes: &HashMap<usize, ResolutionScopeId>,
    event_by_token: &HashMap<usize, u32>,
    formal_lists: &HashSet<usize>,
    units: &HashMap<SourceDeclarationId, &CodeUnit>,
    receiver_fields: &HashMap<CodeUnit, (SourceDeclarationId, CodeUnit)>,
) {
    // Retain each embedded tree for this file's typed production. Its node IDs
    // remain live alongside the original tree, so per-node maps cannot alias
    // nodes from a subsequently parsed quoted annotation.
    let quoted_trees = nodes
        .iter()
        .filter_map(|node| {
            crate::syntax::python_deferred_annotation_tree(*node, p.source, None)
                .map(|tree| (node.id(), scopes[&node.id()], tree))
        })
        .collect::<Vec<_>>();
    let mut quoted_roots = HashMap::default();
    for (string, scope, tree) in &quoted_trees {
        let guard = p.node_guards.get(string).copied();
        let root = tree.root_node();
        quoted_roots.insert(*string, root);
        let mut pending = vec![root];
        while let Some(node) = pending.pop() {
            assert!(scopes.insert(node.id(), *scope).is_none());
            if let Some(guard) = guard {
                assert!(p.node_guards.insert(node.id(), guard).is_none());
            }
            pending.extend(named_children_iter(node));
        }
    }
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
        quoted_roots,
        references,
        values: HashMap::default(),
        type_nodes: HashSet::default(),
    };
    for node in nodes.iter().copied() {
        if formal_lists.contains(&node.id()) {
            for formal in named_children_iter(node).filter(|formal| !formal.is_extra()) {
                let formal = python_unwrap_type(formal);
                if formal.kind() == "constrained_type" {
                    for bound in named_children_iter(formal)
                        .filter(|bound| !bound.is_extra())
                        .skip(1)
                    {
                        t.type_expression(bound);
                    }
                }
            }
        } else if node.kind() == "type_alias_statement"
            && let Some(rhs) = node.child_by_field_name("right")
        {
            t.type_expression(rhs);
        }
    }
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
                t.scopes[&node.id()],
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
        // Decorators are siblings of the declaration inside this wrapper.
        // Authored containment assigns their references to the decorated
        // declaration, independently of their header evaluation scope.
        if let Some(parent) = node.parent().filter(|p| p.kind() == "decorated_definition") {
            declarations.insert(parent.id(), authored);
        }
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
        .map(|node| t.scopes[&node.id()])
        .collect::<HashSet<_>>();
    let deferred = super::future_annotations_enabled(nodes, t.p.source);
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
    let mut return_inputs = HashMap::<ResolutionSiteId, Vec<_>>::default();
    for node in nodes.iter().copied() {
        if node.kind() == "future_import_statement" {
            // Compiler-mode evidence is known, but the runtime _Feature binding
            // is not yet supplied by the native import producer.
            let site = t.p.site(
                node,
                t.scopes[&node.id()],
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
                t.scopes[&node.id()]
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
                    named_children_iter(node).find(|child| !child.is_extra())
                };
                let expression_input = expression.map(|expression| t.expression(expression));
                if node.kind() == "return_statement" {
                    return_inputs
                        .entry(callable)
                        .or_default()
                        .push((node, expression_input));
                }
                let input = expression_input.unwrap_or_else(|| t.unknown(node));
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
            ResolutionBindingEventKind::Assign if operation.kind() == "type_alias_statement" => {
                // A TypeAliasType object is not its lazily evaluated RHS value.
                Some(t.unknown(token))
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
            && !python_call_callee(node)
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
    // The declaration collector owns admission and deduplication of receiver
    // fields. Reuse those exact source identities, independently of lexical
    // binding events: assigning an attribute never binds a local variable.
    let owner_scopes =
        t.p.facts
            .scopes
            .iter()
            .filter(|scope| scope.kind == ResolutionScopeKind::TypeBody)
            .filter_map(|scope| scope.owner.map(|owner| (owner, scope.id)))
            .collect::<HashMap<_, _>>();
    let owner_definitions =
        t.p.facts
            .definition_units
            .iter()
            // Type aliases have public type units but do not own a class body.
            .filter(|row| row.unit.is_class() && owner_scopes.contains_key(&row.declaration))
            .map(|row| {
                (
                    row.unit.clone(),
                    (row.declaration, owner_scopes[&row.declaration]),
                )
            })
            .collect::<HashMap<_, _>>();
    let receiver_initializers =
        t.p.facts
            .python_receiver_writes
            .iter()
            .map(|write| (write.site, write.value))
            .collect::<HashMap<_, _>>();
    // Preserve source order for deterministic definition and crosswalk keys.
    let mut receiver_fields = receiver_fields.values().collect::<Vec<_>>();
    receiver_fields.sort_unstable_by_key(|(declaration, _)| declaration.get());
    for (declaration, owner_unit) in receiver_fields {
        let Some(unit) = units.get(declaration) else {
            // Replacing a class can withdraw its public descendants.
            continue;
        };
        let (owner, scope) = owner_definitions[owner_unit];
        let source = t.p.collector.declaration(*declaration);
        let range = t.p.collector.occurrence(source.occurrence).range;
        let token = by_range[&(range.start_byte, range.end_byte)];
        let member = t.p.identifier(
            token,
            scope,
            ResolutionSiteKind::ValueDeclaration,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
        );
        t.p.declarations.push((member, *declaration));
        // The retained direct write already selected the initializer. Patterns
        // without an element projection retain an explicit unknown value.
        let reference = t.references[&(range.start_byte, range.end_byte)];
        let input = receiver_initializers
            .get(&reference)
            .copied()
            .flatten()
            .unwrap_or_else(|| t.unknown(token));
        t.initialize_value(member, input);

        t.p.facts
            .definition_units
            .push(ResolutionDefinitionUnitFact {
                declaration: member,
                unit: (*unit).clone(),
            });
        t.p.facts.member_owners.push(ResolutionMemberOwnerFact {
            member,
            owner,
            kind: ResolutionMemberKind::Field,
            access: ResolutionMemberAccess::Instance,
            qualifier_compatibility: ResolutionMemberQualifierCompatibility::RuntimeOnly,
        });
        t.p.facts
            .python_member_roles
            .push(PythonNativeMemberRoleFact {
                owner,
                member,
                kind: PythonNativeMemberRole::OrdinaryValue,
                callable: None,
                receiver_parameter: None,
            });
    }
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
            let statement =
                find_ancestor(token, |node| node.kind() == "expression_statement").unwrap_or(token);
            let declaration = t.p.collector.declare_node(statement, Some(token));
            t.p.declarations.push((member, declaration));
            if let Some(unit) = units.get(&declaration) {
                t.p.facts
                    .definition_units
                    .push(ResolutionDefinitionUnitFact {
                        declaration: member,
                        unit: (*unit).clone(),
                    });
            }
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
        let class_method = by_range[&(site.start_byte, site.end_byte)]
            .parent()
            .filter(|node| node.kind() == "function_definition")
            .and_then(crate::syntax::python_method_owner)
            .is_some();
        let receiver_parameter =
            t.p.facts
                .python_parameters
                .iter()
                .find(|row| {
                    class_method
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
    // A total body-return proof is separate from the individual observations.
    // The shared value join combines alternatives and retains every input gap.
    let methods =
        t.p.facts
            .member_owners
            .iter()
            .filter(|row| row.kind == ResolutionMemberKind::Method)
            .map(|row| row.member)
            .collect::<HashSet<_>>();
    let signature_indices =
        t.p.facts
            .callable_signatures
            .iter()
            .enumerate()
            .map(|(index, row)| (row.callable, index))
            .collect::<HashMap<_, _>>();
    for function in nodes
        .iter()
        .copied()
        .filter(|node| node.kind() == "function_definition")
    {
        let callable = declarations[&function.id()];
        let mut cursor = function.walk();
        if function.child_by_field_name("return_type").is_some()
            || function
                .children(&mut cursor)
                .any(|child| child.kind() == "async")
            || suspended_scopes.contains(&scope_nodes[&function.id()])
            || function.has_error()
        {
            continue;
        }
        // Free decorated functions have no callable-preservation proof yet.
        // Methods use the existing query-time decorator_role admission.
        if function
            .parent()
            .is_some_and(|parent| parent.kind() == "decorated_definition")
            && !methods.contains(&callable)
        {
            continue;
        }
        let body = function.child_by_field_name("body").expect("function body");
        let mut inputs = return_inputs
            .remove(&callable)
            .unwrap_or_default()
            .into_iter()
            .map(|(node, input)| input.unwrap_or_else(|| t.none_value(node)))
            .collect::<Vec<_>>();
        if body_end_is_reachable(body) {
            inputs.push(t.none_value(body));
        }
        let result =
            t.p.facts
                .allocate_type_slot(callable, ResolutionTypeSlotRole::DeclaredValue);
        if inputs.is_empty() {
            // A body that only raises has a complete empty result, not None.
            let input = t.slot(body, ResolutionTypeSlotRole::TargetTypeIdentity);
            t.seed_none_type(input);
            t.transfer(
                input,
                result,
                ResolutionTypeTransferKind::DeclaredType,
                ResolutionTypeTransferValueTransform::ToNoValue,
            );
        } else {
            let joined = t.slot(body, ResolutionTypeSlotRole::ExpressionValue);
            for input in inputs {
                t.transfer(
                    input,
                    joined,
                    ResolutionTypeTransferKind::ValueJoin,
                    ResolutionTypeTransferValueTransform::Preserve,
                );
            }
            t.transfer(
                joined,
                result,
                ResolutionTypeTransferKind::Initialization,
                ResolutionTypeTransferValueTransform::Preserve,
            );
        }
        t.p.facts
            .declaration_type_slots
            .push(DeclarationTypeSlotFact {
                declaration: callable,
                slot: result,
                role: DeclarationTypeRole::Return,
            });
        let signature = &mut t.p.facts.callable_signatures[signature_indices[&callable]];
        assert!(
            signature.result_types.is_empty(),
            "unannotated function has no declared result"
        );
        signature
            .result_types
            .push(ResolutionCallableResultTypeFact {
                ordinal: 0,
                value_type: result,
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
    // annotations still own structured type references without a binding event.
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
        t.initialize_value(owner, input);
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
    // A receiver identity is stronger than a receiver type. Only an ordinary,
    // undecorated method's unchanged first positional parameter proves it.
    // Count the whole cell inventory before visiting members: even a later write
    // or a nested nonlocal write withdraws identity from every observation.
    let mut writers = HashMap::<ResolutionSiteId, Vec<&ResolutionBindingEventFact>>::default();
    for event in &t.p.facts.binding_events {
        if event.kind != ResolutionBindingEventKind::Annotation {
            writers.entry(event.slot).or_default().push(event);
        }
    }
    let mut receivers = HashMap::default();
    for function in nodes
        .iter()
        .copied()
        .filter(|node| node.kind() == "function_definition")
    {
        let Some(class) = crate::syntax::python_method_owner(function) else {
            continue;
        };
        let method_name = function.child_by_field_name("name").expect("method name");
        // Python gives these undecorated definitions class/static binding.
        if matches!(
            &t.p.source[method_name.byte_range()],
            "__new__" | "__init_subclass__" | "__class_getitem__"
        ) {
            continue;
        }
        let callable = declarations[&function.id()];
        let Some(definition) = t.p.facts.binding_events.iter().find(|event| {
            event.kind == ResolutionBindingEventKind::Function
                && event.authored_declaration == Some(callable)
        }) else {
            continue;
        };
        // A class-body replacement such as helper = staticmethod(helper)
        // changes how the first argument is supplied, even inside the def.
        if t.p.facts.sites[definition.slot.index()].scope != scope_nodes[&class.id()]
            || writers[&definition.slot].iter().any(|writer| {
                writer.kind != ResolutionBindingEventKind::Function
                    || writer.authored_declaration.is_none_or(|declaration| {
                        t.p.facts
                            .python_decorators
                            .iter()
                            .any(|decorator| decorator.declaration == declaration)
                    })
            })
        {
            continue;
        }
        let Some(parameter) = t.p.facts.python_parameters.iter().find(|row| {
            row.callable == callable
                && row.ordinal == 0
                && matches!(
                    row.kind,
                    PythonNativeParameterKind::PositionalOnly
                        | PythonNativeParameterKind::PositionalOrKeyword
                )
        }) else {
            continue;
        };
        let Some(event) = t.p.facts.binding_events.iter().find(|event| {
            event.kind == ResolutionBindingEventKind::Parameter
                && event.authored_declaration == Some(parameter.parameter)
        }) else {
            continue;
        };
        // Definition guards control member availability, not the parameter
        // supplied when this callable runs. Actual parameter writes still veto
        // receiver identity, including conditional and nonlocal writes.
        if writers[&event.slot].len() != 1 {
            continue;
        }
        let name =
            t.p.facts
                .identifiers
                .iter()
                .find(|id| id.site == event.target)
                .expect("a parameter writer has an identifier")
                .name;
        // An unchanged first instance parameter has the enclosing nominal class.
        // Absence of an annotation is not an unsupported expression type.
        t.p.facts.gaps.retain(|gap| {
            !(gap.site == parameter.parameter
                && gap.kind == ResolutionGapKind::UnsupportedExpressionType)
        });
        receivers.insert(scope_nodes[&function.id()], name);
    }
    for member in nodes
        .iter()
        .copied()
        .filter(|node| node.kind() == "attribute")
    {
        let object = member
            .child_by_field_name("object")
            .expect("attribute object");
        let attribute = member
            .child_by_field_name("attribute")
            .expect("attribute name");
        if object.kind() != "identifier" {
            continue;
        }
        let Some(&receiver_name) = receivers.get(&t.scopes[&object.id()]) else {
            // Nested functions, lambdas and comprehension frames never inherit
            // their enclosing method's receiver identity.
            continue;
        };
        let Some(&object_site) = t.references.get(&(object.start_byte(), object.end_byte())) else {
            continue;
        };
        if !t
            .p
            .facts
            .identifiers
            .iter()
            .any(|id| id.site == object_site && id.name == receiver_name)
        {
            continue;
        }
        let Some(&reference) = t
            .references
            .get(&(attribute.start_byte(), attribute.end_byte()))
        else {
            continue;
        };
        if t.p.facts.sites[reference.index()].kind != ResolutionSiteKind::MemberReference
            || !t
                .p
                .facts
                .identifiers
                .iter()
                .any(|id| id.site == reference && id.namespace == ResolutionNamespace::Value)
        {
            continue;
        }
        t.p.facts
            .callable_receiver_origins
            .push(ResolutionCallableReceiverOriginFact {
                reference,
                origin: ResolutionCallableReceiverOrigin::CurrentInstance,
            });
    }
    // Annotation identifiers have structured type references; their qualified
    // owners are value expressions. Retire scope gaps only at these exact
    // reference ranges. Quoted and implicit class-cell gaps remain intact.
    let type_references =
        t.p.facts
            .identifiers
            .iter()
            .filter(|row| {
                row.role == ResolutionIdentifierRole::Reference
                    && row.namespace == ResolutionNamespace::Type
            })
            .map(|row| row.site)
            .collect::<HashSet<_>>();
    let type_prefixes =
        t.p.facts
            .root_references
            .iter()
            .filter(|root| type_references.contains(&root.reference))
            .filter_map(|root| root.prefix_reference)
            .collect::<HashSet<_>>();
    let structured = t
        .p
        .facts
        .identifiers
        .iter()
        .filter(|row| {
            row.role == ResolutionIdentifierRole::Reference
                && (row.namespace == ResolutionNamespace::Type || type_prefixes.contains(&row.site))
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

/// Only these structured tails prove that the end of the body is unreachable.
/// Loops, cleanup constructs and unknown syntax conservatively fall through.
fn body_end_is_reachable(body: Node<'_>) -> bool {
    let mut pending = vec![body];
    while let Some(block) = pending.pop() {
        let Some(last) = named_children_iter(block)
            .filter(|node| !node.is_extra())
            .last()
        else {
            return true;
        };
        match last.kind() {
            "return_statement" | "raise_statement" => {}
            "if_statement" => {
                let Some(consequence) = last.child_by_field_name("consequence") else {
                    return true;
                };
                pending.push(consequence);
                let mut has_else = false;
                for branch in named_children_iter(last) {
                    match branch.kind() {
                        "elif_clause" => {
                            let Some(consequence) = branch.child_by_field_name("consequence")
                            else {
                                return true;
                            };
                            pending.push(consequence);
                        }
                        "else_clause" => {
                            let Some(body) = branch.child_by_field_name("body") else {
                                return true;
                            };
                            has_else = true;
                            pending.push(body);
                        }
                        _ => {}
                    }
                }
                if !has_else {
                    return true;
                }
            }
            _ => return true,
        }
    }
    false
}
