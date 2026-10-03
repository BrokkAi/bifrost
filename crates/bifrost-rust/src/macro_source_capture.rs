//! Source-owned matcher facts for Rust `macro_rules!` definitions.
//!
//! The capture happens while the declaration walk still owns the live syntax
//! tree. Consumers can therefore match from canonical occurrence ids without
//! rereading or reparsing the definition source.

use brokk_bifrost_core::analyzer::rust_facts::{
    MacroFragmentKind, MacroIdentRole, RustMacroArmSourceFact, RustMacroDefinitionSourceFact,
    RustMacroIdentRoleSourceFact, RustMacroPatternSourceFact, RustMacroPatternSourceKind,
};
use brokk_bifrost_core::analyzer::source_facts::{SourceOccurrenceId, SourceOccurrenceSink};
use brokk_bifrost_core::hash::HashSet;
use tree_sitter::Node;

use crate::declarations::rust_node_text;
use crate::item_sources::RustItemSourceSink;
use crate::macro_matcher::{
    ident_transcriber_role, interior_tokens, is_macro_rules_definition, macro_delimiter,
    metavar_spelling, parse_repetition,
};

/// Capture one live `macro_definition`, including malformed arms. The caller
/// supplies the same occurrence sink used by the primary or embedded walk, so
/// every id belongs to that walk's canonical source arena.
pub(crate) fn capture_macro_definition<'tree>(
    definition: Node<'tree>,
    source: &str,
    sink: &mut dyn RustItemSourceSink,
    context: SourceOccurrenceId,
) -> RustMacroDefinitionSourceFact {
    assert_eq!(definition.kind(), "macro_definition");
    let declaration = sink.declare_node(definition);
    let is_macro_rules = is_macro_rules_definition(definition);
    let mut cursor = definition.walk();
    let arms = definition
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "macro_rule")
        .map(|arm| capture_arm(arm, source, sink))
        .collect();
    RustMacroDefinitionSourceFact {
        declaration,
        context,
        is_macro_rules,
        arms,
    }
}

fn capture_arm<'tree>(
    arm: Node<'tree>,
    source: &str,
    sink: &mut dyn SourceOccurrenceSink,
) -> RustMacroArmSourceFact {
    let occurrence = sink.intern_node(arm);
    let Some(left) = arm.child_by_field_name("left") else {
        return RustMacroArmSourceFact {
            occurrence,
            pattern: None,
            patterns: Vec::new(),
            ident_roles: Vec::new(),
        };
    };
    let root_occurrence = sink.intern_node(left);
    let mut patterns = vec![RustMacroPatternSourceFact {
        occurrence: root_occurrence,
        parent: None,
        kind: RustMacroPatternSourceKind::Group {
            delimiter: macro_delimiter(left),
        },
    }];
    let mut pending = interior_tokens(left)
        .0
        .into_iter()
        .rev()
        .map(|node| (node, root_occurrence))
        .collect::<Vec<_>>();
    while let Some((node, parent)) = pending.pop() {
        let occurrence = sink.intern_node(node);
        let (kind, children) = pattern_kind_and_children(node, source);
        patterns.push(RustMacroPatternSourceFact {
            occurrence,
            parent: Some(parent),
            kind,
        });
        pending.extend(children.into_iter().rev().map(|child| (child, occurrence)));
    }

    let mut seen = HashSet::default();
    let ident_names = patterns
        .iter()
        .filter_map(|pattern| match &pattern.kind {
            RustMacroPatternSourceKind::Binding {
                name,
                fragment: MacroFragmentKind::Ident,
            } => Some(name.as_str()),
            _ => None,
        })
        .filter(|name| seen.insert(*name))
        .collect::<Vec<_>>();
    let right = arm.child_by_field_name("right");
    let ident_roles = ident_names
        .into_iter()
        .map(|name| RustMacroIdentRoleSourceFact {
            role: right
                .map(|right| ident_transcriber_role(right, source, name))
                .unwrap_or(MacroIdentRole::Undetermined),
            name: name.to_string(),
        })
        .collect();

    RustMacroArmSourceFact {
        occurrence,
        pattern: Some(root_occurrence),
        patterns,
        ident_roles,
    }
}

fn pattern_kind_and_children<'tree>(
    node: Node<'tree>,
    source: &str,
) -> (RustMacroPatternSourceKind, Vec<Node<'tree>>) {
    match node.kind() {
        "token_tree_pattern" => (
            RustMacroPatternSourceKind::Group {
                delimiter: macro_delimiter(node),
            },
            interior_tokens(node).0,
        ),
        "token_binding_pattern" => {
            let name = node
                .child_by_field_name("name")
                .map(|name| metavar_spelling(rust_node_text(name, source)))
                .unwrap_or_default();
            let fragment = node.child_by_field_name("type").and_then(|fragment| {
                MacroFragmentKind::from_specifier(rust_node_text(fragment, source))
            });
            match (name.is_empty(), fragment) {
                (false, Some(fragment)) => (
                    RustMacroPatternSourceKind::Binding { name, fragment },
                    Vec::new(),
                ),
                _ => (RustMacroPatternSourceKind::Invalid, Vec::new()),
            }
        }
        "token_repetition_pattern" => {
            let Some(spec) = parse_repetition(node, source) else {
                return (RustMacroPatternSourceKind::Invalid, Vec::new());
            };
            (
                RustMacroPatternSourceKind::Repetition {
                    separator: spec.separator,
                    operator: spec.operator,
                },
                spec.contents,
            )
        }
        _ => (
            RustMacroPatternSourceKind::Literal {
                syntax_kind: node.kind().to_string(),
                text: rust_node_text(node, source).trim().to_string(),
            },
            Vec::new(),
        ),
    }
}

#[cfg(test)]
#[path = "macro_source_capture_tests.rs"]
mod macro_source_capture_tests;
