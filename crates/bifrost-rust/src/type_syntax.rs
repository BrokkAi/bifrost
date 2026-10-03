//! Source-owned Rust type syntax retained for later owner projections.
//!
//! This module records the structured syntax that the parser already exposed;
//! it does not evaluate generic arguments or resolve a path to a declaration.
//! Every retained identity is anchored to the shared source-occurrence arena,
//! so embedded and primary trees use the same content-local identity contract.

use brokk_bifrost_core::analyzer::common::node_ident_text;
use brokk_bifrost_core::analyzer::rust_facts::{
    RustGenericArgumentsSourceFact, RustTypeCompoundSourceKind, RustTypePathSegmentSourceFact,
    RustTypeSourceFact, RustTypeSourceShape, RustTypeWrapperSourceFact, RustTypeWrapperSourceKind,
};
use brokk_bifrost_core::analyzer::source_facts::{SourceOccurrenceId, SourceOccurrenceSink};
use brokk_bifrost_core::hash::HashMap;
use tree_sitter::Node;

use crate::declarations::RUST_IDENTIFIER_SIGIL;
use crate::graph_support::{rust_path_is_leading_absolute, rust_path_segments};

/// Collect structured type syntax once for each canonical source occurrence.
/// The occurrence key is producer-owned, so repeated requests for one live
/// AST node reuse the original interpretation while distinct replay trees keep
/// their separate occurrence and fact rows.
#[derive(Default)]
pub(crate) struct RustTypeSourceCollector {
    facts: Vec<RustTypeSourceFact>,
    by_occurrence: HashMap<SourceOccurrenceId, usize>,
}

impl RustTypeSourceCollector {
    pub(crate) fn new() -> Self {
        Self {
            facts: Vec::new(),
            by_occurrence: HashMap::default(),
        }
    }

    pub(crate) fn record_type(
        &mut self,
        node: Node<'_>,
        source: &str,
        sink: &mut dyn SourceOccurrenceSink,
    ) -> &RustTypeSourceFact {
        let occurrence = sink.intern_node(node);
        if let Some(index) = self.by_occurrence.get(&occurrence).copied() {
            return &self.facts[index];
        }
        let mut pending = vec![node];
        while let Some(current) = pending.pop() {
            let current_occurrence = sink.intern_node(current);
            if self.by_occurrence.contains_key(&current_occurrence) {
                continue;
            }
            let fact = rust_type_source_fact(current, source, sink, &mut pending);
            assert_eq!(
                fact.occurrence, current_occurrence,
                "type interpretation must retain the occurrence used as its key"
            );
            let index = self.facts.len();
            assert!(
                self.by_occurrence
                    .insert(current_occurrence, index)
                    .is_none(),
                "one source occurrence cannot own two type interpretations"
            );
            self.facts.push(fact);
        }
        let index = self
            .by_occurrence
            .get(&occurrence)
            .copied()
            .expect("the requested type occurrence was recorded");
        &self.facts[index]
    }

    pub(crate) fn into_facts(self) -> Vec<RustTypeSourceFact> {
        self.facts
    }
}

/// Extract one parser-backed type occurrence without retaining the parser tree.
///
/// The walk is iterative in both the wrapper and path projections. Generic
/// arguments are retained as exact occurrence links; the collector enqueues
/// those argument nodes for their own facts. Lifetime and syntactically literal
/// arguments therefore remain explicit `Unsupported` facts rather than being
/// interpreted as types.
fn rust_type_source_fact<'tree>(
    node: Node<'tree>,
    source: &str,
    sink: &mut dyn SourceOccurrenceSink,
    pending: &mut Vec<Node<'tree>>,
) -> RustTypeSourceFact {
    let occurrence = sink.intern_node(node);
    let mut wrappers = Vec::new();
    let mut current = node;

    let shape = loop {
        if let Some((kind, inner)) = wrapper_parts(current) {
            wrappers.push(RustTypeWrapperSourceFact {
                occurrence: sink.intern_node(current),
                kind,
            });
            let Some(inner) = inner else {
                break unsupported_shape(current, sink);
            };
            current = inner;
            continue;
        }
        let shape = match current.kind() {
            "abstract_type" | "dynamic_type" | "bounded_type" | "higher_ranked_trait_bound" => {
                compound_shape(current, sink, pending)
            }
            "generic_type"
            | "scoped_identifier"
            | "scoped_type_identifier"
            | "identifier"
            | "type_identifier"
            | "primitive_type"
            | "self"
            | "super"
            | "crate" => source_path(current, source, sink, pending),
            _ => unsupported_shape(current, sink),
        };
        break shape;
    };

    RustTypeSourceFact {
        occurrence,
        wrappers,
        shape,
    }
}

/// Return the path usable by the legacy nominal owner projection.
///
/// Wrappers are intentionally peeled because that is the existing owner
/// projection's contract. A generic qualifier on a prefix segment is not
/// peeled or flattened: it changes the path authority and therefore makes the
/// owner projection unavailable. A generic terminal remains attached to the
/// returned segment for a later consumer to decide.
pub(crate) fn declaration_owner_path(
    fact: &RustTypeSourceFact,
) -> Option<&[RustTypePathSegmentSourceFact]> {
    let RustTypeSourceShape::Path { segments, .. } = &fact.shape else {
        return None;
    };
    let (_, prefix) = segments.split_last()?;
    if prefix
        .iter()
        .any(|segment| segment.generic_arguments.is_some())
    {
        return None;
    }
    Some(segments)
}

fn source_path<'tree>(
    node: Node<'tree>,
    source: &str,
    sink: &mut dyn SourceOccurrenceSink,
    pending: &mut Vec<Node<'tree>>,
) -> RustTypeSourceShape {
    // A primitive spelling is classified by token, not by binding: `impl f16`
    // in a crate that declares its own `f16` names that declaration, so the
    // terminal is a one-segment path. Only a source declaration can publish a
    // nominal workspace type, so admitting the spelling here cannot invent one.
    let segment_nodes =
        rust_path_segments(node).or_else(|| (node.kind() == "primitive_type").then(|| vec![node]));
    let Some(segment_nodes) = segment_nodes else {
        return unsupported_shape(node, sink);
    };
    if segment_nodes.is_empty() {
        return unsupported_shape(node, sink);
    }

    let mut generic_attachments = HashMap::default();
    let mut current = node;
    loop {
        match current.kind() {
            "generic_type" => {
                let Some(base) = current.child_by_field_name("type") else {
                    return unsupported_shape(current, sink);
                };
                let Some(type_arguments) = current.child_by_field_name("type_arguments") else {
                    return unsupported_shape(current, sink);
                };
                let terminal = match base.kind() {
                    "scoped_identifier" | "scoped_type_identifier" => {
                        base.child_by_field_name("name")
                    }
                    "identifier" | "type_identifier" | "primitive_type" | "self" | "super"
                    | "crate" => Some(base),
                    _ => None,
                };
                let Some(terminal) = terminal else {
                    return unsupported_shape(base, sink);
                };
                if generic_attachments
                    .insert(
                        terminal.id(),
                        generic_arguments(type_arguments, sink, pending),
                    )
                    .is_some()
                {
                    return unsupported_shape(current, sink);
                }
                current = base;
            }
            "scoped_identifier" | "scoped_type_identifier" => {
                let Some(path) = current.child_by_field_name("path") else {
                    break;
                };
                current = path;
            }
            "identifier" | "type_identifier" | "primitive_type" | "self" | "super" | "crate" => {
                break;
            }
            _ => return unsupported_shape(current, sink),
        }
    }

    let mut segments = Vec::with_capacity(segment_nodes.len());
    for segment in segment_nodes {
        let name = node_ident_text(segment, source, true, &RUST_IDENTIFIER_SIGIL);
        if name.is_empty() {
            return unsupported_shape(segment, sink);
        }
        let generic_arguments = generic_attachments.remove(&segment.id());
        segments.push(RustTypePathSegmentSourceFact {
            occurrence: sink.intern_node(segment),
            name: name.to_string(),
            generic_arguments,
        });
    }
    assert!(
        generic_attachments.is_empty(),
        "generic lists belong to retained path segments"
    );

    RustTypeSourceShape::Path {
        leading_absolute: rust_path_is_leading_absolute(node),
        segments,
    }
}

fn wrapper_parts(node: Node<'_>) -> Option<(RustTypeWrapperSourceKind, Option<Node<'_>>)> {
    match node.kind() {
        "reference_type" => Some((
            RustTypeWrapperSourceKind::Reference,
            node.child_by_field_name("type"),
        )),
        "pointer_type" => Some((
            RustTypeWrapperSourceKind::Pointer,
            node.child_by_field_name("type"),
        )),
        "array_type" => Some((
            if node.child_by_field_name("length").is_some() {
                RustTypeWrapperSourceKind::Array
            } else {
                RustTypeWrapperSourceKind::Slice
            },
            node.child_by_field_name("element"),
        )),
        _ => None,
    }
}

fn generic_arguments<'tree>(
    type_arguments: Node<'tree>,
    sink: &mut dyn SourceOccurrenceSink,
    pending: &mut Vec<Node<'tree>>,
) -> RustGenericArgumentsSourceFact {
    let occurrence = sink.intern_node(type_arguments);
    let mut cursor = type_arguments.walk();
    let mut arguments = Vec::new();
    for argument in type_arguments.named_children(&mut cursor) {
        arguments.push(sink.intern_node(argument));
        pending.push(argument);
    }
    RustGenericArgumentsSourceFact {
        occurrence,
        arguments,
    }
}

fn compound_shape<'tree>(
    node: Node<'tree>,
    sink: &mut dyn SourceOccurrenceSink,
    pending: &mut Vec<Node<'tree>>,
) -> RustTypeSourceShape {
    let (kind, child_field) = match node.kind() {
        "abstract_type" => (RustTypeCompoundSourceKind::Abstract, Some("trait")),
        "dynamic_type" => (RustTypeCompoundSourceKind::Dynamic, Some("trait")),
        "bounded_type" => (RustTypeCompoundSourceKind::Bounded, None),
        "higher_ranked_trait_bound" => (RustTypeCompoundSourceKind::HigherRanked, Some("type")),
        _ => unreachable!("compound_shape receives a compound type node"),
    };
    let children = if let Some(field) = child_field {
        let Some(child) = node.child_by_field_name(field) else {
            return unsupported_shape(node, sink);
        };
        vec![child]
    } else {
        let mut cursor = node.walk();
        node.named_children(&mut cursor).collect::<Vec<_>>()
    };
    if children.is_empty() {
        return unsupported_shape(node, sink);
    }
    let children = children
        .into_iter()
        .map(|child| {
            let occurrence = sink.intern_node(child);
            pending.push(child);
            occurrence
        })
        .collect();
    let type_parameters = match kind {
        RustTypeCompoundSourceKind::Abstract => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find(|child| child.kind() == "type_parameters")
        }
        RustTypeCompoundSourceKind::HigherRanked => node.child_by_field_name("type_parameters"),
        RustTypeCompoundSourceKind::Dynamic | RustTypeCompoundSourceKind::Bounded => None,
    }
    .map(|parameters| sink.intern_node(parameters));
    RustTypeSourceShape::Compound {
        occurrence: sink.intern_node(node),
        kind,
        children,
        type_parameters,
    }
}

fn unsupported_shape(node: Node<'_>, sink: &mut dyn SourceOccurrenceSink) -> RustTypeSourceShape {
    RustTypeSourceShape::Unsupported {
        occurrence: sink.intern_node(node),
        syntax_kind: node.kind().to_string(),
    }
}

/// The type inside a parenthesized type such as `&(dyn Trait + Send)`.
///
/// The grammar has no parenthesized-type node: `(T)` parses as a
/// `tuple_type` with one element. A one-element tuple needs a trailing comma
/// (`(T,)`), so a `tuple_type` with exactly one named child and no `,` token
/// is the parenthesized type `T`. Any other node answers `None`.
pub(crate) fn rust_parenthesized_type_inner(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "tuple_type" || node.named_child_count() != 1 {
        return None;
    }
    let mut cursor = node.walk();
    if node.children(&mut cursor).any(|child| child.kind() == ",") {
        return None;
    }
    node.named_child(0)
}

#[cfg(test)]
#[path = "type_forms_tests.rs"]
mod type_forms_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::source_facts::{
        PrimarySourceFactCollector, SourceOccurrenceProvenance,
    };
    use tree_sitter::Parser;

    fn target<'tree>(tree: &'tree tree_sitter::Tree) -> Node<'tree> {
        tree.root_node()
            .named_child(0)
            .expect("impl item")
            .child_by_field_name("type")
            .expect("impl target")
    }

    fn parse_fact(
        source: &str,
    ) -> (
        RustTypeSourceFact,
        brokk_bifrost_core::analyzer::source_facts::SourceFactRows,
    ) {
        let (fact, _, rows) = parse_collected(source);
        (fact, rows)
    }

    fn parse_collected(
        source: &str,
    ) -> (
        RustTypeSourceFact,
        Vec<RustTypeSourceFact>,
        brokk_bifrost_core::analyzer::source_facts::SourceFactRows,
    ) {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust grammar");
        let tree = parser.parse(source, None).expect("parse Rust source");
        assert!(
            !tree.root_node().has_error(),
            "type syntax fixture must parse without errors"
        );
        let mut sink = PrimarySourceFactCollector::new(source);
        let mut collector = RustTypeSourceCollector::new();
        let fact = collector
            .record_type(target(&tree), source, &mut sink)
            .clone();
        let facts = collector.into_facts();
        (fact, facts, sink.finish())
    }

    #[test]
    fn retains_raw_name_and_primary_occurrence() {
        let source = "impl r#Type {}";
        let (fact, rows) = parse_fact(source);
        let RustTypeSourceShape::Path { segments, .. } = fact.shape else {
            panic!("raw identifier is a path");
        };
        assert_eq!(segments[0].name, "Type");
        assert_eq!(fact.occurrence, segments[0].occurrence);
        assert_eq!(
            rows.occurrence(fact.occurrence).provenance,
            SourceOccurrenceProvenance::PrimaryNode
        );
    }

    #[test]
    fn retains_leading_absolute_path() {
        let (fact, _) = parse_fact("impl ::external::Type {}");
        let RustTypeSourceShape::Path {
            leading_absolute,
            segments,
        } = fact.shape
        else {
            panic!("absolute path is supported");
        };
        assert!(leading_absolute);
        assert_eq!(
            segments
                .iter()
                .map(|segment| segment.name.as_str())
                .collect::<Vec<_>>(),
            ["external", "Type"]
        );
    }

    #[test]
    fn keeps_terminal_generic_but_rejects_qualified_generic_owner() {
        let source = "impl module::Type<T, { 3 }> {}";
        let (terminal, rows) = parse_fact(source);
        assert!(declaration_owner_path(&terminal).is_some());
        let segments = declaration_owner_path(&terminal).expect("terminal generic owner");
        assert!(segments[0].generic_arguments.is_none());
        let arguments = segments[1]
            .generic_arguments
            .as_ref()
            .expect("terminal generic list");
        let span = rows.occurrence(arguments.occurrence).range;
        assert_eq!(&source[span.start_byte..span.end_byte], "<T, { 3 }>");
        let argument_text: Vec<_> = arguments
            .arguments
            .iter()
            .map(|id| {
                let span = rows.occurrence(*id).range;
                &source[span.start_byte..span.end_byte]
            })
            .collect();
        assert_eq!(argument_text, ["T", "{ 3 }"]);

        let (qualified, _) = parse_fact("impl Outer<T>::Assoc {}");
        let RustTypeSourceShape::Path { segments, .. } = &qualified.shape else {
            panic!("qualified path remains structured");
        };
        assert!(segments[0].generic_arguments.is_some());
        assert!(declaration_owner_path(&qualified).is_none());
    }

    #[test]
    fn preserves_wrapper_order_and_slice_shape() {
        let (fact, _) = parse_fact("impl &*const [Type; 3] {}");
        assert_eq!(
            fact.wrappers
                .iter()
                .map(|wrapper| wrapper.kind)
                .collect::<Vec<_>>(),
            [
                RustTypeWrapperSourceKind::Reference,
                RustTypeWrapperSourceKind::Pointer,
                RustTypeWrapperSourceKind::Array,
            ]
        );
        let (slice, _) = parse_fact("impl &[Type] {}");
        assert_eq!(slice.wrappers[1].kind, RustTypeWrapperSourceKind::Slice);
    }

    #[test]
    fn qualified_type_is_explicitly_unsupported() {
        let (fact, _) = parse_fact("impl <T as Trait>::Assoc {}");
        assert!(matches!(
            fact.shape,
            RustTypeSourceShape::Unsupported { occurrence, ref syntax_kind }
                if occurrence == fact.occurrence && syntax_kind == "scoped_type_identifier"
        ));
    }

    #[test]
    fn deeply_nested_references_use_iterative_walk() {
        let source = format!("impl {}Type {{}}", "&".repeat(2048));
        let (fact, _) = parse_fact(&source);
        assert_eq!(fact.wrappers.len(), 2048);
        assert!(declaration_owner_path(&fact).is_some());
    }

    #[test]
    fn repeated_primary_type_capture_reuses_one_fact() {
        let source = "impl Outer<Inner<T>> {}";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust grammar");
        let tree = parser.parse(source, None).expect("parse Rust source");
        let node = target(&tree);
        let mut sink = PrimarySourceFactCollector::new(source);
        let mut collector = RustTypeSourceCollector::new();
        let first_occurrence = collector.record_type(node, source, &mut sink).occurrence;
        let second_occurrence = collector.record_type(node, source, &mut sink).occurrence;
        assert_eq!(first_occurrence, second_occurrence);
        assert_eq!(collector.into_facts().len(), 3);
    }

    #[test]
    fn nested_generic_arguments_have_exact_type_facts() {
        let source = "impl Outer<Inner<'a, 3>, Leaf<T>> {}";
        let (fact, facts, rows) = parse_collected(source);
        let RustTypeSourceShape::Path { segments, .. } = &fact.shape else {
            panic!("generic owner is a structured path");
        };
        let arguments = segments[0]
            .generic_arguments
            .as_ref()
            .expect("outer generic arguments");
        assert_eq!(arguments.arguments.len(), 2);

        for argument in &arguments.arguments {
            let nested = facts
                .iter()
                .find(|candidate| candidate.occurrence == *argument)
                .expect("each generic argument has a source fact");
            let range = rows.occurrence(*argument).range;
            assert!(!source[range.start_byte..range.end_byte].is_empty());
            assert_eq!(nested.occurrence, *argument);
        }

        let inner = facts
            .iter()
            .find(|candidate| {
                let RustTypeSourceShape::Path { segments, .. } = &candidate.shape else {
                    return false;
                };
                segments
                    .first()
                    .is_some_and(|segment| segment.name == "Inner")
            })
            .expect("nested type argument");
        let RustTypeSourceShape::Path { segments, .. } = &inner.shape else {
            panic!("nested type argument is a path");
        };
        let nested_arguments = segments[0]
            .generic_arguments
            .as_ref()
            .expect("inner generic arguments");
        assert_eq!(nested_arguments.arguments.len(), 2);
        for argument in &nested_arguments.arguments {
            let nested = facts
                .iter()
                .find(|candidate| candidate.occurrence == *argument)
                .expect("lifetime and literal arguments retain facts");
            assert!(matches!(
                &nested.shape,
                RustTypeSourceShape::Unsupported { occurrence, .. }
                    if *occurrence == *argument
            ));
        }
    }
}
