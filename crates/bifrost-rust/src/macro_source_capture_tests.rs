use super::*;

use crate::item_sources::RustItemSourceSink;
use brokk_bifrost_core::analyzer::rust_facts::{RustMacroDelimiter, RustMacroRepetitionOperator};
use brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceSink;
use brokk_bifrost_core::analyzer::source_facts::{
    PrimarySourceFactCollector, SourceDeclarationId, SourceFactRows, SourceOccurrenceId,
    SourceOccurrenceProvenance,
};
use std::collections::HashMap;
use tree_sitter::{Node, Parser, Tree};

struct PrimarySink<'source> {
    collector: PrimarySourceFactCollector<'source>,
}

impl RustItemSourceSink for PrimarySink<'_> {
    fn declare_node(&mut self, node: Node<'_>) -> SourceDeclarationId {
        let occurrence = self.collector.intern_node(node);
        let name = node
            .child_by_field_name("name")
            .map(|name| self.collector.intern_node(name));
        self.collector.declare(occurrence, name)
    }
}

impl SourceOccurrenceSink for PrimarySink<'_> {
    fn intern_node(&mut self, node: Node<'_>) -> SourceOccurrenceId {
        self.collector.intern_node(node)
    }

    fn intern_subspan_bytes(
        &mut self,
        start_byte: usize,
        end_byte: usize,
        provenance: SourceOccurrenceProvenance,
    ) -> SourceOccurrenceId {
        self.collector
            .intern_subspan_bytes(start_byte, end_byte, provenance)
    }
}

struct EmbeddedSink<'source> {
    collector: PrimarySourceFactCollector<'source>,
    occurrences: HashMap<usize, SourceOccurrenceId>,
}

impl SourceOccurrenceSink for EmbeddedSink<'_> {
    fn intern_node(&mut self, node: Node<'_>) -> SourceOccurrenceId {
        if let Some(occurrence) = self.occurrences.get(&node.id()).copied() {
            return occurrence;
        }
        let occurrence = self.collector.intern_subspan_bytes(
            node.start_byte(),
            node.end_byte(),
            SourceOccurrenceProvenance::Embedded,
        );
        assert!(self.occurrences.insert(node.id(), occurrence).is_none());
        occurrence
    }

    fn intern_subspan_bytes(
        &mut self,
        start_byte: usize,
        end_byte: usize,
        provenance: SourceOccurrenceProvenance,
    ) -> SourceOccurrenceId {
        self.collector
            .intern_subspan_bytes(start_byte, end_byte, provenance)
    }
}

impl RustItemSourceSink for EmbeddedSink<'_> {
    fn declare_node(&mut self, node: Node<'_>) -> SourceDeclarationId {
        let occurrence = self.intern_node(node);
        let name = node
            .child_by_field_name("name")
            .map(|name| self.intern_node(name));
        self.collector.declare(occurrence, name)
    }
}

fn parse(source: &str) -> Tree {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .expect("Rust grammar");
    parser.parse(source, None).expect("Rust tree")
}

fn macro_definition(tree: &Tree) -> Node<'_> {
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "macro_definition" {
            return node;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    panic!("macro definition")
}

fn occurrence_text<'source>(
    source: &'source str,
    rows: &SourceFactRows,
    occurrence: SourceOccurrenceId,
) -> &'source str {
    let range = rows.occurrence(occurrence).range;
    &source[range.start_byte..range.end_byte]
}

#[test]
fn captures_nested_pattern_literals_and_transcriber_roles() {
    let source = "macro_rules! build { ($name:ident, $ty:ty) => { struct $name($ty); }; }";
    let tree = parse(source);
    let definition = macro_definition(&tree);
    let mut sink = PrimarySink {
        collector: PrimarySourceFactCollector::new(source),
    };
    let context = sink.collector.intern_node(tree.root_node());
    let fact = capture_macro_definition(definition, source, &mut sink, context);
    let rows = sink.collector.finish();
    let arm = &fact.arms[0];
    assert!(fact.is_macro_rules);
    assert_eq!(fact.context, context);
    assert_eq!(arm.patterns[0].parent, None);
    assert!(matches!(
        &arm.patterns[0].kind,
        RustMacroPatternSourceKind::Group {
            delimiter: Some(RustMacroDelimiter::Parenthesis)
        }
    ));
    assert!(arm.patterns.iter().any(|pattern| matches!(
        &pattern.kind,
        RustMacroPatternSourceKind::Literal { text, .. } if text == ","
    )));
    let bindings = arm
        .patterns
        .iter()
        .filter_map(|pattern| match &pattern.kind {
            RustMacroPatternSourceKind::Binding { name, fragment } => Some((name, fragment)),
            _ => None,
        })
        .map(|(name, fragment)| (name.clone(), *fragment))
        .collect::<HashMap<_, _>>();
    assert_eq!(bindings.get("name"), Some(&MacroFragmentKind::Ident));
    assert_eq!(bindings.get("ty"), Some(&MacroFragmentKind::Ty));
    let roles = arm
        .ident_roles
        .iter()
        .map(|role| (role.name.as_str(), role.role))
        .collect::<HashMap<_, _>>();
    assert_eq!(roles.get("name"), Some(&MacroIdentRole::Declaration));
    // Transcriber roles are collected only for `ident` metavariables.  The
    // `ty` binding remains a pattern fact but is intentionally absent here.
    assert!(!roles.contains_key("ty"));
    assert_eq!(
        occurrence_text(source, &rows, arm.patterns[0].occurrence),
        "($name:ident, $ty:ty)"
    );
}

#[test]
fn captures_repetition_structure_and_repeated_identity() {
    let source = "macro_rules! list { ($(($name:ident)),*) => {}; }";
    let tree = parse(source);
    let definition = macro_definition(&tree);
    let mut sink = PrimarySink {
        collector: PrimarySourceFactCollector::new(source),
    };
    let context = sink.collector.intern_node(tree.root_node());
    let first = capture_macro_definition(definition, source, &mut sink, context);
    let second = capture_macro_definition(definition, source, &mut sink, context);
    assert_eq!(first, second);
    let patterns = &first.arms[0].patterns;
    assert!(matches!(
        &patterns[1].kind,
        RustMacroPatternSourceKind::Repetition {
            separator: Some(_),
            operator: RustMacroRepetitionOperator::Star
        }
    ));
    assert!(matches!(
        &patterns[2].kind,
        RustMacroPatternSourceKind::Group {
            delimiter: Some(RustMacroDelimiter::Parenthesis)
        }
    ));
    assert_eq!(patterns[1].parent, Some(patterns[0].occurrence));
    assert_eq!(patterns[2].parent, Some(patterns[1].occurrence));
    assert_eq!(patterns[3].parent, Some(patterns[2].occurrence));
}

#[test]
fn captures_empty_pattern_in_parser_recovery_tree() {
    // `macro_rule.left` is required by the Rust grammar.  A valid empty
    // matcher therefore has a present group with no children; `pattern: None`
    // is reserved for parser-recovery nodes that cannot be produced by this
    // grammar fixture.
    let source = "macro_rules! broken { () => {};";
    let tree = parse(source);
    assert!(tree.root_node().has_error());
    let definition = macro_definition(&tree);
    let mut sink = PrimarySink {
        collector: PrimarySourceFactCollector::new(source),
    };
    let context = sink.collector.intern_node(tree.root_node());
    let fact = capture_macro_definition(definition, source, &mut sink, context);
    assert!(fact.arms.iter().any(|arm| {
        arm.pattern.is_some()
            && arm.patterns.len() == 1
            && matches!(
                &arm.patterns[0].kind,
                RustMacroPatternSourceKind::Group { .. }
            )
    }));
    assert_eq!(fact.arms.len(), 1);
    assert!(fact.arms.iter().all(|arm| arm.pattern.is_some()));
}

#[test]
fn embedded_capture_retains_embedded_occurrence_provenance() {
    let source = "macro_rules! embedded { ($name:ident) => {}; }";
    let tree = parse(source);
    let definition = macro_definition(&tree);
    let mut sink = EmbeddedSink {
        collector: PrimarySourceFactCollector::new(source),
        occurrences: HashMap::new(),
    };
    let context = sink.intern_node(tree.root_node());
    let fact = capture_macro_definition(definition, source, &mut sink, context);
    let rows = sink.collector.finish();
    assert!(
        fact.arms[0]
            .patterns
            .iter()
            .all(|pattern| rows.occurrence(pattern.occurrence).provenance
                == SourceOccurrenceProvenance::Embedded)
    );
}
