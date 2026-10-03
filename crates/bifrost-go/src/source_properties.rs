//! Go source properties captured by the coordinated primary producer.
//!
//! This module owns the Go-specific syntax that cannot be recovered from the
//! language-neutral structural or resolution rows.  The type representation
//! is a post-order arena keyed by the exact source occurrence of each AST
//! type node.  It intentionally does not resolve package names or declaration
//! targets; those are graph concerns.

use brokk_bifrost_core::analyzer::go_facts::{
    GoAliasFact, GoCallableFact, GoCallableParameterFact, GoChannelDirection, GoEmbeddingFact,
    GoFieldFact, GoSourceFacts, GoSourceTypeFact, GoSourceTypeId, GoSourceTypeShape,
    GoTypeCompoundKind, GoTypeDeclarationFact,
};
use brokk_bifrost_core::analyzer::model::{
    StructuredTypeIdentity, StructuredTypeIdentityBuilder, StructuredTypeName, StructuredTypeNodeId,
};
use brokk_bifrost_core::analyzer::source_facts::{
    PrimarySourceFactCollector, SourceDeclarationId, SourceOccurrenceId,
};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use tree_sitter::Node;

use crate::declarations::{children_by_field, go_node_text, named_children};

pub(crate) struct GoSourcePropertyCollector<'source> {
    source: &'source str,
    facts: GoSourceFacts,
    type_ids: HashMap<usize, GoSourceTypeId>,
    embedded_type_ids: HashMap<usize, GoSourceTypeId>,
    identities: HashMap<GoSourceTypeId, Option<StructuredTypeIdentity>>,
}

impl<'source> GoSourcePropertyCollector<'source> {
    pub(crate) fn new(source: &'source str) -> Self {
        Self {
            source,
            facts: GoSourceFacts::default(),
            type_ids: HashMap::default(),
            embedded_type_ids: HashMap::default(),
            identities: HashMap::default(),
        }
    }

    pub(crate) fn capture_node(
        &mut self,
        node: Node<'_>,
        source_collector: &mut PrimarySourceFactCollector<'source>,
    ) {
        if is_go_type_node(node) {
            self.capture_type(node, source_collector);
        }

        match node.kind() {
            "function_declaration" | "method_declaration" | "method_elem" | "function_type" => {
                self.capture_callable_type_roots(node, source_collector);
            }
            "type_spec"
            | "type_alias"
            | "var_spec"
            | "const_spec"
            | "field_declaration"
            | "parameter_declaration"
            | "variadic_parameter_declaration"
            | "composite_literal" => {
                if let Some(ty) = node.child_by_field_name("type") {
                    self.capture_type(ty, source_collector);
                }
            }
            "parameter_list" => self.capture_parameter_list(node, source_collector),
            "type_parameter_declaration" => {
                if let Some(ty) = node.child_by_field_name("type") {
                    self.capture_type(ty, source_collector);
                }
            }
            _ => {}
        }
    }

    pub(crate) fn capture_type(
        &mut self,
        root: Node<'_>,
        source_collector: &mut PrimarySourceFactCollector<'source>,
    ) -> Option<GoSourceTypeId> {
        if let Some(id) = self.type_ids.get(&root.id()) {
            return Some(*id);
        }

        enum Frame<'tree> {
            Visit(Node<'tree>),
            Build(Node<'tree>),
        }

        let mut stack = vec![Frame::Visit(root)];
        while let Some(frame) = stack.pop() {
            let node = match frame {
                Frame::Visit(node) => {
                    if self.type_ids.contains_key(&node.id()) {
                        continue;
                    }
                    let children = type_children(node);
                    if children.is_empty() {
                        self.append_type(node, &[], source_collector);
                        continue;
                    }
                    stack.push(Frame::Build(node));
                    for child in children.into_iter().rev() {
                        if !self.type_ids.contains_key(&child.id()) {
                            stack.push(Frame::Visit(child));
                        }
                    }
                    continue;
                }
                Frame::Build(node) => node,
            };

            if self.type_ids.contains_key(&node.id()) {
                continue;
            }
            let children = type_children(node);
            let ids = children
                .iter()
                .map(|child| {
                    *self
                        .type_ids
                        .get(&child.id())
                        .expect("Go type children are captured before their parent")
                })
                .collect::<Vec<_>>();
            self.append_type(node, &ids, source_collector);
        }

        self.type_ids.get(&root.id()).copied()
    }

    pub(crate) fn capture_method_key_type(
        &mut self,
        root: Node<'_>,
        source_collector: &mut PrimarySourceFactCollector<'source>,
    ) -> Option<GoSourceTypeId> {
        let id = self.capture_type(root, source_collector)?;
        let mut stack = vec![(root, id)];
        while let Some((node, id)) = stack.pop() {
            self.ensure_method_key_presentation(node, id);
            let children = match node.kind() {
                // The old generic MethodKey renderer renders the base
                // recursively but treats its type_arguments node as raw text.
                "generic_type" => node.child_by_field_name("type").into_iter().collect(),
                _ => type_children(node),
            };
            for child in children {
                if let Some(child_id) = self.type_ids.get(&child.id()).copied() {
                    stack.push((child, child_id));
                }
            }
        }
        Some(id)
    }

    pub(crate) fn type_id_for_node(&self, node: Node<'_>) -> Option<GoSourceTypeId> {
        self.type_ids.get(&node.id()).copied()
    }

    /// Capture the complete declared type of an anonymous field. Tree-sitter
    /// represents the `*` in `*T` as an anonymous token on the field rather
    /// than as a pointer_type node, so retain one arena wrapper with the star
    /// token as its source occurrence. This lets hierarchy consumers preserve
    /// pointer promotion without adding a parallel boolean property.
    pub(crate) fn capture_embedded_type(
        &mut self,
        field: Node<'_>,
        type_node: Node<'_>,
        source_collector: &mut PrimarySourceFactCollector<'source>,
    ) -> Option<GoSourceTypeId> {
        if let Some(id) = self.embedded_type_ids.get(&field.id()) {
            return Some(*id);
        }
        let base = self.capture_type(type_node, source_collector)?;
        let mut cursor = field.walk();
        let Some(pointer) = field
            .children(&mut cursor)
            .find(|child| !child.is_named() && child.kind() == "*")
        else {
            self.embedded_type_ids.insert(field.id(), base);
            return Some(base);
        };
        let occurrence = source_collector.intern_node(pointer);
        let id = GoSourceTypeId::try_from_index(self.facts.types.len())
            .expect("Go source type count exceeds u32");
        self.facts.types.push(GoSourceTypeFact {
            occurrence,
            shape: GoSourceTypeShape::Pointer(base),
        });
        assert!(self.embedded_type_ids.insert(field.id(), id).is_none());
        Some(id)
    }

    pub(crate) fn type_shape(&self, type_id: GoSourceTypeId) -> &GoSourceTypeShape {
        &self.facts.types[type_id.index()].shape
    }

    pub(crate) fn identity_for_type(
        &mut self,
        type_id: GoSourceTypeId,
    ) -> Option<StructuredTypeIdentity> {
        if let Some(identity) = self.identities.get(&type_id) {
            return identity.clone();
        }

        let identity = self.build_identity(type_id);
        self.identities.insert(type_id, identity.clone());
        identity
    }

    pub(crate) fn add_type_declaration(
        &mut self,
        declaration: SourceDeclarationId,
        name: &str,
        ty: GoSourceTypeId,
        file_scope: bool,
    ) {
        self.facts.declarations.push(GoTypeDeclarationFact {
            declaration,
            name: name.to_string(),
            ty,
            file_scope,
        });
    }

    pub(crate) fn add_alias(
        &mut self,
        declaration: SourceDeclarationId,
        name: &str,
        target: Option<GoSourceTypeId>,
    ) {
        self.facts.aliases.push(GoAliasFact {
            declaration,
            name: name.to_string(),
            target,
        });
    }

    pub(crate) fn add_field(
        &mut self,
        declaration: SourceDeclarationId,
        owner: GoSourceTypeId,
        ty: Option<GoSourceTypeId>,
        name: &str,
        embedded: bool,
    ) {
        self.facts.fields.push(GoFieldFact {
            declaration,
            owner,
            ty,
            name: name.to_string(),
            embedded,
        });
    }

    pub(crate) fn add_callable(&mut self, callable: GoCallableFact) {
        self.facts.callables.push(callable);
    }

    pub(crate) fn add_embedding(
        &mut self,
        owner: GoSourceTypeId,
        occurrence: SourceOccurrenceId,
        ty: GoSourceTypeId,
    ) {
        self.facts.embeddings.push(GoEmbeddingFact {
            owner,
            occurrence,
            ty,
        });
    }

    pub(crate) fn finish(self) -> GoSourceFacts {
        self.facts
    }

    fn capture_callable_type_roots(
        &mut self,
        node: Node<'_>,
        source_collector: &mut PrimarySourceFactCollector<'source>,
    ) {
        if let Some(receiver) = node.child_by_field_name("receiver") {
            self.capture_method_key_parameter_list(receiver, source_collector);
        }
        if let Some(parameters) = node.child_by_field_name("parameters") {
            self.capture_method_key_parameter_list(parameters, source_collector);
        }
        if let Some(result) = node.child_by_field_name("result") {
            if result.kind() == "parameter_list" {
                self.capture_method_key_parameter_list(result, source_collector);
            } else {
                self.capture_method_key_type(result, source_collector);
            }
        }
    }

    fn capture_parameter_list(
        &mut self,
        list: Node<'_>,
        source_collector: &mut PrimarySourceFactCollector<'source>,
    ) {
        for parameter in named_children(list) {
            if matches!(
                parameter.kind(),
                "parameter_declaration" | "variadic_parameter_declaration"
            ) {
                if let Some(ty) = parameter.child_by_field_name("type") {
                    self.capture_type(ty, source_collector);
                } else if let Some(ty) =
                    parameter.named_child(parameter.named_child_count().saturating_sub(1))
                {
                    self.capture_type(ty, source_collector);
                }
            }
        }
    }

    fn capture_method_key_parameter_list(
        &mut self,
        list: Node<'_>,
        source_collector: &mut PrimarySourceFactCollector<'source>,
    ) {
        for parameter in named_children(list) {
            if !matches!(
                parameter.kind(),
                "parameter_declaration" | "variadic_parameter_declaration"
            ) {
                continue;
            }
            let ty = parameter
                .child_by_field_name("type")
                .or_else(|| parameter.named_child(parameter.named_child_count().saturating_sub(1)));
            if let Some(ty) = ty {
                self.capture_method_key_type(ty, source_collector);
            }
        }
    }

    fn append_type(
        &mut self,
        node: Node<'_>,
        children: &[GoSourceTypeId],
        source_collector: &mut PrimarySourceFactCollector<'source>,
    ) -> GoSourceTypeId {
        let occurrence = source_collector.intern_node(node);
        let shape = self.shape(node, children, source_collector);
        let id = GoSourceTypeId::try_from_index(self.facts.types.len())
            .expect("Go source type count exceeds u32");
        self.facts
            .types
            .push(GoSourceTypeFact { occurrence, shape });
        assert!(self.type_ids.insert(node.id(), id).is_none());
        id
    }

    fn ensure_method_key_presentation(&mut self, node: Node<'_>, id: GoSourceTypeId) {
        match &mut self.facts.types[id.index()].shape {
            GoSourceTypeShape::ImplicitArray { text: stored, .. }
            | GoSourceTypeShape::Struct { text: stored }
            | GoSourceTypeShape::Interface { text: stored, .. }
            | GoSourceTypeShape::Opaque { text: stored }
                if stored.is_none() =>
            {
                let presentation = go_node_text(node, self.source).trim();
                if !presentation.is_empty() {
                    *stored = Some(presentation.to_string());
                }
            }
            GoSourceTypeShape::Generic { argument_text, .. } if argument_text.is_none() => {
                if let Some(arguments) = node.child_by_field_name("type_arguments") {
                    let presentation = go_node_text(arguments, self.source).trim();
                    if !presentation.is_empty() {
                        *argument_text = Some(presentation.to_string());
                    }
                }
            }
            _ => {}
        }
    }

    fn shape(
        &mut self,
        node: Node<'_>,
        children: &[GoSourceTypeId],
        source_collector: &mut PrimarySourceFactCollector<'source>,
    ) -> GoSourceTypeShape {
        match node.kind() {
            "type_identifier" | "identifier" => {
                let name = go_node_text(node, self.source).trim();
                match StructuredTypeName::new(vec![name.to_string()], Vec::new(), false) {
                    Some(name) => GoSourceTypeShape::Named(name),
                    None => self.opaque(),
                }
            }
            "qualified_type" => {
                let package = node
                    .child_by_field_name("package")
                    .map(|child| go_node_text(child, self.source).trim().to_string());
                let name = node
                    .child_by_field_name("name")
                    .map(|child| go_node_text(child, self.source).trim().to_string());
                match (package, name) {
                    (Some(package), Some(name)) if !package.is_empty() && !name.is_empty() => {
                        match StructuredTypeName::new(vec![package, name], Vec::new(), false) {
                            Some(name) => GoSourceTypeShape::Named(name),
                            None => self.opaque(),
                        }
                    }
                    _ => self.opaque(),
                }
            }
            "pointer_type" => children
                .first()
                .copied()
                .map(GoSourceTypeShape::Pointer)
                .unwrap_or_else(|| self.opaque()),
            "slice_type" => children
                .first()
                .copied()
                .map(GoSourceTypeShape::Slice)
                .unwrap_or_else(|| self.opaque()),
            "array_type" => {
                let Some(length_node) = node.child_by_field_name("length") else {
                    return self.opaque();
                };
                let Some(element) = children.first().copied() else {
                    return self.opaque();
                };
                let length_text = go_node_text(length_node, self.source).trim().to_string();
                if length_text.is_empty() {
                    return self.opaque();
                }
                GoSourceTypeShape::Array {
                    element,
                    length: source_collector.intern_node(length_node),
                    length_text,
                }
            }
            "implicit_length_array_type" => match children.first().copied() {
                Some(element) => GoSourceTypeShape::ImplicitArray {
                    element,
                    text: None,
                },
                None => self.opaque(),
            },
            "map_type" => GoSourceTypeShape::Map {
                key: match children.first().copied() {
                    Some(key) => key,
                    None => return self.opaque(),
                },
                value: match children.get(1).copied() {
                    Some(value) => value,
                    None => return self.opaque(),
                },
            },
            "channel_type" => {
                let direction = channel_direction(node);
                match children.first().copied() {
                    Some(element) => GoSourceTypeShape::Channel { direction, element },
                    None => self.opaque(),
                }
            }
            "generic_type" => {
                let Some(arguments) = node.child_by_field_name("type_arguments") else {
                    return self.opaque();
                };
                let Some((base, arguments_ids)) = children.split_first() else {
                    return self.opaque();
                };
                let argument_list = source_collector.intern_node(arguments);
                GoSourceTypeShape::Generic {
                    base: *base,
                    arguments: arguments_ids.to_vec(),
                    argument_list,
                    argument_text: None,
                }
            }
            "parenthesized_type" => GoSourceTypeShape::Compound {
                kind: GoTypeCompoundKind::Parenthesized,
                children: children.to_vec(),
            },
            "type_elem" => GoSourceTypeShape::Compound {
                kind: GoTypeCompoundKind::Element,
                children: children.to_vec(),
            },
            "type_constraint" => GoSourceTypeShape::Compound {
                kind: GoTypeCompoundKind::Constraint,
                children: children.to_vec(),
            },
            "negated_type" => children
                .first()
                .copied()
                .map(GoSourceTypeShape::Negated)
                .unwrap_or_else(|| self.opaque()),
            "struct_type" => GoSourceTypeShape::Struct { text: None },
            "interface_type" => GoSourceTypeShape::Interface {
                text: None,
                has_named_children: named_children(node)
                    .iter()
                    .any(|child| child.kind() != "comment"),
            },
            _ => self.opaque(),
        }
    }

    fn opaque(&self) -> GoSourceTypeShape {
        GoSourceTypeShape::Opaque { text: None }
    }

    fn build_identity(&self, root: GoSourceTypeId) -> Option<StructuredTypeIdentity> {
        go_source_type_identity(&self.facts, root)
    }
}

/// Project one captured source type through the same canonical identity rules
/// used by declaration metadata and graph resolution. Keep this centralized so
/// tree-backed and persisted Go consumers cannot drift on arrays, generics,
/// wrappers, or intentionally unsupported shapes.
pub(crate) fn go_source_type_identity(
    facts: &GoSourceFacts,
    root: GoSourceTypeId,
) -> Option<StructuredTypeIdentity> {
    let mut order = Vec::new();
    let mut pending = vec![(root, false)];
    let mut visited = HashSet::default();
    while let Some((id, finishing)) = pending.pop() {
        if finishing {
            order.push(id);
            continue;
        }
        if !visited.insert(id) {
            continue;
        }
        pending.push((id, true));
        for child in shape_children(&facts.types[id.index()].shape)
            .into_iter()
            .rev()
        {
            pending.push((child, false));
        }
    }

    let mut identity_ids: HashMap<GoSourceTypeId, StructuredTypeNodeId> = HashMap::default();
    let mut builder = StructuredTypeIdentityBuilder::default();
    for id in order {
        let shape = &facts.types[id.index()].shape;
        let identity = match shape {
            GoSourceTypeShape::Named(name) => builder.named(name.clone()),
            GoSourceTypeShape::Pointer(inner) => builder.pointer(*identity_ids.get(inner)?),
            GoSourceTypeShape::Slice(inner) => builder.slice(*identity_ids.get(inner)?),
            GoSourceTypeShape::Array { element, .. }
            | GoSourceTypeShape::ImplicitArray { element, .. } => {
                builder.array(*identity_ids.get(element)?)
            }
            GoSourceTypeShape::Map { key, value } => {
                builder.map(*identity_ids.get(key)?, *identity_ids.get(value)?)
            }
            GoSourceTypeShape::Generic {
                base, arguments, ..
            } => builder.generic(
                *identity_ids.get(base)?,
                arguments
                    .iter()
                    .map(|argument| identity_ids.get(argument).copied())
                    .collect::<Option<Vec<_>>>()?,
            ),
            GoSourceTypeShape::Compound { kind, children } => match kind {
                GoTypeCompoundKind::Parenthesized | GoTypeCompoundKind::Element => (children.len()
                    == 1)
                    .then(|| identity_ids.get(&children[0]).copied())
                    .flatten(),
                GoTypeCompoundKind::Constraint => None,
            },
            // The old StructuredTypeIdentity helper intentionally erased
            // negation while preserving its child identity.
            GoSourceTypeShape::Negated(inner) => identity_ids.get(inner).copied(),
            GoSourceTypeShape::Interface {
                has_named_children: false,
                ..
            } => builder.empty_interface(),
            GoSourceTypeShape::Channel { .. }
            | GoSourceTypeShape::Struct { .. }
            | GoSourceTypeShape::Interface { .. }
            | GoSourceTypeShape::Opaque { .. } => None,
        }?;
        identity_ids.insert(id, identity);
    }
    builder.finish(*identity_ids.get(&root)?)
}

fn is_go_type_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "type_identifier"
            | "function_type"
            | "qualified_type"
            | "pointer_type"
            | "slice_type"
            | "array_type"
            | "implicit_length_array_type"
            | "map_type"
            | "channel_type"
            | "generic_type"
            | "parenthesized_type"
            | "type_elem"
            | "type_constraint"
            | "negated_type"
            | "struct_type"
            | "interface_type"
    )
}

fn is_type_child_node(node: &Node<'_>) -> bool {
    is_go_type_node(*node) || node.kind() == "identifier"
}

fn type_children(node: Node<'_>) -> Vec<Node<'_>> {
    match node.kind() {
        "pointer_type" | "slice_type" | "implicit_length_array_type" => node
            .child_by_field_name("type")
            .or_else(|| node.child_by_field_name("element"))
            .or_else(|| node.named_child(0))
            .into_iter()
            .collect(),
        "array_type" => node.child_by_field_name("element").into_iter().collect(),
        "map_type" => [
            node.child_by_field_name("key"),
            node.child_by_field_name("value"),
        ]
        .into_iter()
        .flatten()
        .collect(),
        "channel_type" => node.child_by_field_name("value").into_iter().collect(),
        "generic_type" => {
            let mut children = Vec::new();
            if let Some(base) = node.child_by_field_name("type") {
                children.push(base);
            }
            if let Some(arguments) = node.child_by_field_name("type_arguments") {
                children.extend(
                    named_children(arguments)
                        .into_iter()
                        .filter(is_type_child_node),
                );
            }
            children
        }
        "parenthesized_type" | "negated_type" => named_children(node)
            .into_iter()
            .filter(is_type_child_node)
            .collect(),
        "type_elem" | "type_constraint" => named_children(node)
            .into_iter()
            .filter(is_type_child_node)
            .collect(),
        _ => Vec::new(),
    }
}

fn shape_children(shape: &GoSourceTypeShape) -> Vec<GoSourceTypeId> {
    match shape {
        GoSourceTypeShape::Pointer(inner)
        | GoSourceTypeShape::Slice(inner)
        | GoSourceTypeShape::ImplicitArray { element: inner, .. }
        | GoSourceTypeShape::Negated(inner) => vec![*inner],
        GoSourceTypeShape::Array { element, .. } => vec![*element],
        GoSourceTypeShape::Map { key, value } => vec![*key, *value],
        GoSourceTypeShape::Channel { element, .. } => vec![*element],
        GoSourceTypeShape::Generic {
            base, arguments, ..
        } => std::iter::once(*base)
            .chain(arguments.iter().copied())
            .collect(),
        GoSourceTypeShape::Compound { children, .. } => children.clone(),
        GoSourceTypeShape::Named(_)
        | GoSourceTypeShape::Struct { .. }
        | GoSourceTypeShape::Interface { .. }
        | GoSourceTypeShape::Opaque { .. } => Vec::new(),
    }
}

fn channel_direction(node: Node<'_>) -> GoChannelDirection {
    let mut cursor = node.walk();
    let mut chan_start = None;
    let mut arrow_start = None;
    for child in node.children(&mut cursor) {
        match child.kind() {
            "chan" => chan_start = Some(child.start_byte()),
            "<-" => arrow_start = Some(child.start_byte()),
            _ => {}
        }
    }
    match (arrow_start, chan_start) {
        (Some(arrow), Some(chan)) if arrow < chan => GoChannelDirection::Receive,
        (Some(_), Some(_)) => GoChannelDirection::Send,
        _ => GoChannelDirection::Both,
    }
}

pub(crate) fn callable_parameters(
    node: Node<'_>,
    source: &str,
    source_collector: &mut PrimarySourceFactCollector<'_>,
    types: &GoSourcePropertyCollector<'_>,
) -> Option<Vec<GoCallableParameterFact>> {
    let list = node.child_by_field_name("parameters")?;
    Some(parameter_facts(list, source, source_collector, types))
}

pub(crate) fn result_parameters(
    node: Node<'_>,
    source: &str,
    source_collector: &mut PrimarySourceFactCollector<'_>,
    types: &GoSourcePropertyCollector<'_>,
) -> (Vec<GoCallableParameterFact>, Option<SourceOccurrenceId>) {
    let Some(result) = node.child_by_field_name("result") else {
        return (Vec::new(), None);
    };
    let occurrence = source_collector.intern_node(result);
    if result.kind() == "parameter_list" {
        (
            parameter_facts(result, source, source_collector, types),
            Some(occurrence),
        )
    } else {
        let ty = types.type_id_for_node(result);
        (
            vec![GoCallableParameterFact {
                group: occurrence,
                name: None,
                ty,
                variadic: false,
            }],
            Some(occurrence),
        )
    }
}

fn parameter_facts(
    list: Node<'_>,
    _source: &str,
    source_collector: &mut PrimarySourceFactCollector<'_>,
    types: &GoSourcePropertyCollector<'_>,
) -> Vec<GoCallableParameterFact> {
    let group = source_collector.intern_node(list);
    let mut facts = Vec::new();
    for parameter in named_children(list) {
        if !matches!(
            parameter.kind(),
            "parameter_declaration" | "variadic_parameter_declaration"
        ) {
            continue;
        }
        let ty = parameter
            .child_by_field_name("type")
            .or_else(|| parameter.named_child(parameter.named_child_count().saturating_sub(1)))
            .and_then(|node| types.type_id_for_node(node));
        let names = children_by_field(parameter, "name");
        let variadic = parameter.kind() == "variadic_parameter_declaration";
        if names.is_empty() {
            facts.push(GoCallableParameterFact {
                group,
                name: None,
                ty,
                variadic,
            });
        } else {
            for name in names {
                facts.push(GoCallableParameterFact {
                    group,
                    name: Some(source_collector.intern_node(name)),
                    ty,
                    variadic,
                });
            }
        }
    }
    facts
}
