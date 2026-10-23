//! Source-owned Rust item structure.
//!
//! This collector is deliberately independent of declaration display and
//! native resolution. It records the source relationships that those
//! projections may later consume, including malformed or macro-shaped body
//! children that would otherwise be lost when a projection declines a node.

use brokk_bifrost_core::analyzer::rust_facts::{
    RustAliasSourceFact, RustCallableParameterSourceFact, RustCallableSourceFact,
    RustDeclarationGenericsSourceFact, RustGenericParameterSourceFact, RustImplSourceFact,
    RustItemBodyChildSourceFact, RustItemImportContextFact, RustItemMacroExpansion,
    RustItemMacroSourceFact, RustItemMacroSourcePosition, RustItemSourceFacts, RustItemSyntaxFact,
    RustMacroParseFailure, RustSourceContextFact, RustSourceContextKind, RustSourceNameFact,
    RustTraitSourceFact, RustValueSourceFact,
};
use brokk_bifrost_core::analyzer::source_facts::PrimarySourceFactCollector;
use brokk_bifrost_core::analyzer::source_facts::{
    SourceDeclarationId, SourceOccurrenceId, SourceOccurrenceSink,
};
use brokk_bifrost_core::hash::HashMap;
use tree_sitter::Node;

use crate::declaration_properties::is_rust_named_declaration_kind;
use crate::declarations::{rust_node_text, rust_parameter_label_node};
use crate::macro_source_capture::capture_macro_definition;
use crate::type_syntax::RustTypeSourceCollector;

pub(crate) fn declare_primary_node(
    collector: &mut PrimarySourceFactCollector<'_>,
    node: Node<'_>,
) -> SourceDeclarationId {
    collector.declare_node(node, node.child_by_field_name("name"))
}

/// The declaration bridge used by the primary and embedded walks. The bridge
/// owns the source arena, so this collector never creates a second identity
/// space for unnamed impls or malformed declarations.
pub(crate) trait RustItemSourceSink: SourceOccurrenceSink {
    fn cfg_condition(
        &mut self,
        node: Node<'_>,
        source: &str,
    ) -> crate::lexical_scope::RustCfgCondition {
        crate::lexical_scope::rust_effective_cfg_condition(node, source)
    }

    fn declare_node(&mut self, node: Node<'_>) -> SourceDeclarationId;
}

#[derive(Default)]
pub(crate) struct RustItemSourceCollector {
    facts: RustItemSourceFacts,
    syntax_by_occurrence: HashMap<SourceOccurrenceId, usize>,
    macro_by_invocation: HashMap<SourceOccurrenceId, usize>,
    context_stack: Vec<SourceOccurrenceId>,
    /// Parallel to `context_stack`: the `facts.contexts` index of each
    /// enclosing context, so an attribute start can be attached without a
    /// search.
    context_fact_indices: Vec<usize>,
    /// One entry for every enter call, including anonymous syntax nodes. This
    /// keeps exit synchronized with the shared iterative tree walk.
    context_frames: Vec<Option<SourceOccurrenceId>>,
}

impl RustItemSourceCollector {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn enter(
        &mut self,
        node: Node<'_>,
        source: &str,
        sink: &mut dyn RustItemSourceSink,
        types: &mut RustTypeSourceCollector,
    ) -> Option<RustItemMacroSourcePosition> {
        let parent = self.context_stack.last().copied();
        if matches!(node.kind(), "attribute_item" | "inner_attribute_item")
            && crate::resolution::rust_attribute_item_can_expand(node, source)
        {
            let fact_index = *self
                .context_fact_indices
                .last()
                .expect("an expanding Rust attribute has an enclosing source context");
            let starts = &mut self.facts.contexts[fact_index].expanding_attribute_starts;
            assert!(
                starts
                    .last()
                    .is_none_or(|previous| *previous < node.start_byte()),
                "Rust source item walk visits context attributes in ascending source order"
            );
            starts.push(node.start_byte());
        }
        let source_position = (node.kind() == "macro_invocation").then(|| {
            let invocation = sink.intern_node(node);
            let position = crate::declarations::rust_macro_invocation_source_position(node);
            if let Some(arguments) = crate::declarations::rust_macro_invocation_arguments(node) {
                let (tree, occurrences) = crate::macro_matcher::capture_macro_input_with(
                    arguments,
                    source,
                    &|| true,
                    |node| sink.intern_node(node),
                )
                .expect("source macro input capture cannot be interrupted");
                self.facts.macro_inputs.push(
                    brokk_bifrost_core::analyzer::rust_facts::RustMacroInvocationInputSourceFact {
                        invocation,
                        macro_name: crate::declarations::rust_macro_invocation_path_name(
                            node, source,
                        ),
                        cfg_condition: sink.cfg_condition(node, source),
                        native_frontier: None,
                        tree,
                        occurrences,
                    },
                );
            }
            let index = self.facts.macros.len();
            assert!(
                self.macro_by_invocation.insert(invocation, index).is_none(),
                "one Rust source macro descriptor has one invocation occurrence"
            );
            self.facts.macros.push(RustItemMacroSourceFact {
                invocation,
                context: parent.expect("Rust item macro evidence has an enclosing source context"),
                position,
                expansion: RustItemMacroExpansion::NotRequested,
            });
            position
        });
        let mut entered_context = None;

        if let Some((kind, owner)) = context_kind(node, sink) {
            let context = sink.intern_node(node);
            self.record_syntax(context, node.has_error());
            let fact_index = self.facts.contexts.len();
            self.facts.contexts.push(RustSourceContextFact {
                context,
                parent,
                owner,
                kind,
                expanding_attribute_starts: Vec::new(),
            });
            self.context_stack.push(context);
            self.context_fact_indices.push(fact_index);
            entered_context = Some(context);
        }

        if let Some(context) = parent {
            self.record_item(node, source, sink, types, context);
        } else {
            assert!(
                node.parent().is_none(),
                "Rust source item walk starts at its file root"
            );
        }

        self.context_frames.push(entered_context);
        source_position
    }

    pub(crate) fn exit(&mut self) {
        let entered_context = self
            .context_frames
            .pop()
            .expect("Rust source item exit has a matching enter");
        if let Some(context) = entered_context {
            assert_eq!(
                self.context_stack.pop(),
                Some(context),
                "Rust source item contexts exit in source order"
            );
            self.context_fact_indices
                .pop()
                .expect("Rust source item context facts unwind with their context");
        }
    }

    pub(crate) fn record_macro(
        &mut self,
        invocation: SourceOccurrenceId,
        expansion: Result<Option<SourceOccurrenceId>, RustMacroParseFailure>,
    ) {
        let expansion = match expansion {
            Ok(Some(root)) => RustItemMacroExpansion::Parsed(root),
            Ok(None) => RustItemMacroExpansion::EmptyInterior,
            Err(error) => RustItemMacroExpansion::Unavailable(error),
        };
        let index = *self
            .macro_by_invocation
            .get(&invocation)
            .expect("Rust item macro replay updates a descriptor created by enter");
        assert_eq!(
            self.facts.macros[index].expansion,
            RustItemMacroExpansion::NotRequested,
            "Rust item macro replay records one outcome per invocation"
        );
        self.facts.macros[index].expansion = expansion;
    }

    pub(crate) fn into_facts(self) -> RustItemSourceFacts {
        assert!(
            self.context_frames.is_empty()
                && self.context_stack.is_empty()
                && self.context_fact_indices.is_empty(),
            "Rust source item collector is fully unwound before publication"
        );
        self.facts
    }

    fn record_syntax(&mut self, occurrence: SourceOccurrenceId, has_error: bool) {
        if let Some(index) = self.syntax_by_occurrence.get(&occurrence).copied() {
            assert_eq!(
                self.facts.syntax[index].has_error, has_error,
                "one Rust source occurrence cannot have conflicting parser-error state"
            );
            return;
        }
        assert!(
            self.syntax_by_occurrence
                .insert(occurrence, self.facts.syntax.len())
                .is_none(),
            "one Rust source occurrence receives one syntax observation"
        );
        self.facts.syntax.push(RustItemSyntaxFact {
            occurrence,
            has_error,
        });
    }

    fn record_item(
        &mut self,
        node: Node<'_>,
        source: &str,
        sink: &mut dyn RustItemSourceSink,
        types: &mut RustTypeSourceCollector,
        context: SourceOccurrenceId,
    ) {
        if matches!(
            node.kind(),
            "impl_item"
                | "trait_item"
                | "function_item"
                | "function_signature_item"
                | "struct_item"
                | "enum_item"
                | "union_item"
                | "type_item"
                | "associated_type"
        ) {
            self.record_generics(node, source, sink);
        }
        match node.kind() {
            "macro_definition" => {
                self.facts
                    .macro_definitions
                    .push(capture_macro_definition(node, source, sink, context));
            }
            "use_declaration" | "extern_crate_declaration" => {
                self.facts.import_contexts.push(RustItemImportContextFact {
                    declaration: sink.intern_node(node),
                    context,
                });
            }
            "impl_item" => self.record_impl(node, source, sink, types, context),
            "trait_item" => self.record_trait(node, sink, context),
            "type_item" | "associated_type" => {
                self.record_syntax(sink.intern_node(node), node.has_error());
                self.record_alias(node, source, sink, types, context)
            }
            "function_item" | "function_signature_item" => {
                self.record_callable(node, source, sink, types, context)
            }
            "field_declaration" if node.child_by_field_name("name").is_some() => {
                self.record_value(node, source, sink, types, context)
            }
            "const_item" | "static_item" | "enum_variant" => {
                self.record_value(node, source, sink, types, context)
            }
            _ => {}
        }
    }

    fn record_impl(
        &mut self,
        node: Node<'_>,
        source: &str,
        sink: &mut dyn RustItemSourceSink,
        types: &mut RustTypeSourceCollector,
        context: SourceOccurrenceId,
    ) {
        let declaration = sink.declare_node(node);
        let trait_type = node
            .child_by_field_name("trait")
            .map(|r#type| types.record_type(r#type, source, sink).occurrence);
        let target_type = node
            .child_by_field_name("type")
            .map(|r#type| types.record_type(r#type, source, sink).occurrence);
        let negation = node
            .children(&mut node.walk())
            .find(|child| child.kind() == "!")
            .map(|token| sink.intern_node(token));
        let (body, body_children) = self.record_body(node, sink);
        self.facts.impls.push(RustImplSourceFact {
            declaration,
            context,
            trait_type,
            negation,
            target_type,
            body,
            body_children,
        });
    }

    fn record_trait(
        &mut self,
        node: Node<'_>,
        sink: &mut dyn RustItemSourceSink,
        context: SourceOccurrenceId,
    ) {
        let declaration = sink.declare_node(node);
        let (body, body_children) = self.record_body(node, sink);
        self.facts.traits.push(RustTraitSourceFact {
            declaration,
            context,
            body,
            body_children,
        });
    }

    fn record_alias(
        &mut self,
        node: Node<'_>,
        source: &str,
        sink: &mut dyn RustItemSourceSink,
        types: &mut RustTypeSourceCollector,
        context: SourceOccurrenceId,
    ) {
        let declaration = sink.declare_node(node);
        let target_type = node
            .child_by_field_name("type")
            .map(|r#type| types.record_type(r#type, source, sink).occurrence);
        self.facts.aliases.push(RustAliasSourceFact {
            declaration,
            context,
            target_type,
        });
    }

    fn record_callable(
        &mut self,
        node: Node<'_>,
        source: &str,
        sink: &mut dyn RustItemSourceSink,
        types: &mut RustTypeSourceCollector,
        context: SourceOccurrenceId,
    ) {
        let declaration = sink.declare_node(node);
        let parameters_node = node.child_by_field_name("parameters");
        let parameters = parameters_node.map(|parameters| sink.intern_node(parameters));
        let parameter_children = parameters_node
            .map(|parameters| callable_parameters(parameters, source, sink))
            .unwrap_or_default();
        let return_type = node
            .child_by_field_name("return_type")
            .map(|r#type| types.record_type(r#type, source, sink).occurrence);
        self.facts.callables.push(RustCallableSourceFact {
            declaration,
            context,
            parameters,
            parameter_children,
            return_type,
        });
    }

    fn record_value(
        &mut self,
        node: Node<'_>,
        source: &str,
        sink: &mut dyn RustItemSourceSink,
        types: &mut RustTypeSourceCollector,
        context: SourceOccurrenceId,
    ) {
        self.record_syntax(sink.intern_node(node), node.has_error());
        let declaration = sink.declare_node(node);
        let declared_type = node
            .child_by_field_name("type")
            .map(|r#type| types.record_type(r#type, source, sink).occurrence);
        self.facts.values.push(RustValueSourceFact {
            declaration,
            context,
            declared_type,
        });
    }

    fn body_children(
        &mut self,
        body: Node<'_>,
        sink: &mut dyn RustItemSourceSink,
    ) -> Vec<RustItemBodyChildSourceFact> {
        let mut cursor = body.walk();
        body.named_children(&mut cursor)
            .map(|child| {
                let occurrence = sink.intern_node(child);
                self.record_syntax(occurrence, child.has_error());
                let declaration = if child.kind() == "impl_item"
                    || is_rust_named_declaration_kind(child.kind())
                {
                    Some(sink.declare_node(child))
                } else {
                    None
                };
                RustItemBodyChildSourceFact {
                    occurrence,
                    declaration,
                    syntax_kind: child.kind().to_string(),
                }
            })
            .collect()
    }

    fn record_body(
        &mut self,
        node: Node<'_>,
        sink: &mut dyn RustItemSourceSink,
    ) -> (Option<SourceOccurrenceId>, Vec<RustItemBodyChildSourceFact>) {
        let Some(body) = node.child_by_field_name("body") else {
            return (None, Vec::new());
        };
        let body_occurrence = sink.intern_node(body);
        let children = self.body_children(body, sink);
        (Some(body_occurrence), children)
    }

    fn record_generics(&mut self, node: Node<'_>, source: &str, sink: &mut dyn RustItemSourceSink) {
        let parameters = generic_parameters(node, source, sink);
        if parameters.is_empty() {
            return;
        }
        let declaration = sink.declare_node(node);
        self.facts.generics.push(RustDeclarationGenericsSourceFact {
            declaration,
            parameters,
        });
    }
}

fn context_kind(
    node: Node<'_>,
    sink: &mut dyn RustItemSourceSink,
) -> Option<(RustSourceContextKind, Option<SourceDeclarationId>)> {
    let kind = match node.kind() {
        // Tree-sitter can return an ERROR root for a parsed token-tree
        // fragment. It still owns a file-root context and checked syntax;
        // its children must not inherit the invoking tree's scope directly.
        _ if node.parent().is_none() => RustSourceContextKind::FileRoot,
        "mod_item" => RustSourceContextKind::Module,
        "struct_item" | "enum_item" | "union_item" | "type_item" | "associated_type" => {
            RustSourceContextKind::Type
        }
        "trait_item" => RustSourceContextKind::Trait,
        "impl_item" => RustSourceContextKind::Impl,
        "function_item" | "function_signature_item" => RustSourceContextKind::Function,
        "block" => RustSourceContextKind::Block,
        "declaration_list" => RustSourceContextKind::DeclarationBody,
        _ => return None,
    };
    let owner = matches!(
        kind,
        RustSourceContextKind::Module
            | RustSourceContextKind::Type
            | RustSourceContextKind::Trait
            | RustSourceContextKind::Impl
            | RustSourceContextKind::Function
    )
    .then(|| sink.declare_node(node));
    Some((kind, owner))
}

fn generic_parameters(
    node: Node<'_>,
    source: &str,
    sink: &mut dyn RustItemSourceSink,
) -> Vec<RustGenericParameterSourceFact> {
    let Some(parameters) = node.child_by_field_name("type_parameters") else {
        return Vec::new();
    };
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .map(|parameter| {
            let occurrence = sink.intern_node(parameter);
            let name = generic_parameter_name_node(parameter)
                .and_then(|name| source_name(name, source, sink));
            RustGenericParameterSourceFact {
                occurrence,
                kind: parameter.kind().to_string(),
                name,
            }
        })
        .collect()
}

fn generic_parameter_name_node(parameter: Node<'_>) -> Option<Node<'_>> {
    match parameter.kind() {
        // Bare type parameters are represented by the identifier itself in
        // tree-sitter-rust rather than by a named wrapper node.
        "type_identifier" | "identifier" | "lifetime" => Some(parameter),
        // Bounds/defaults wrap the exact name in a structured field.
        "constrained_type_parameter" => parameter.child_by_field_name("left"),
        "optional_type_parameter" => parameter.child_by_field_name("name"),
        _ => parameter.child_by_field_name("name"),
    }
}

fn callable_parameters(
    parameters: Node<'_>,
    source: &str,
    sink: &mut dyn RustItemSourceSink,
) -> Vec<RustCallableParameterSourceFact> {
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .map(|parameter| {
            let label = rust_parameter_label_node(parameter)
                .and_then(|label| source_name(label, source, sink));
            RustCallableParameterSourceFact {
                occurrence: sink.intern_node(parameter),
                syntax_kind: parameter.kind().to_string(),
                label,
            }
        })
        .collect()
}

fn source_name(
    node: Node<'_>,
    source: &str,
    sink: &mut dyn RustItemSourceSink,
) -> Option<RustSourceNameFact> {
    let name = rust_node_text(node, source).trim();
    (!name.is_empty()).then(|| RustSourceNameFact {
        occurrence: sink.intern_node(node),
        name: name.to_string(),
    })
}
