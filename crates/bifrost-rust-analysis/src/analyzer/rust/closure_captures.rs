//! The free variables of one Rust closure-like body, resolved through lexical
//! scopes.
//!
//! Two callers share this walk so that they cannot disagree about what a
//! closure captures: the semantic lowering prepass, which records `Capture`
//! rows, and the `std_types` value classifier, which proves that a closure's
//! environment is inert (#12483). The lowering caller walks every
//! closure-like procedure and relays captures through its own procedure table.
//! The classifier follows [`RustCallableFreeVariables::nested_callables`]
//! with an explicit worklist.

use std::ops::Range;

use brokk_bifrost_analysis::analyzer::lexical_definitions::{
    LexicalBindingResolution, LexicalLookupOutcome, resolve_lexical_binding_with_candidate_index,
};
use brokk_bifrost_core::analyzer::model::Language;
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_core::analyzer::structural::spec::EmbeddedSyntaxForest;
use brokk_bifrost_rust::lexical_scope::{RustPatternName, rust_pattern_name_bounded};
use tree_sitter::Node;

use crate::analyzer::rust::semantic::{is_rust_nested_execution_boundary, named_children};

/// One reference inside a closure body to a binding declared outside it.
pub(crate) struct RustFreeVariableReference<'tree> {
    pub name: Box<str>,
    /// Start byte of the binding's name; with `name` it identifies the variable.
    pub declaration_start: usize,
    /// Byte range of the declaration that introduces the binding.
    pub declaration_range: Range<usize>,
    pub reference: Node<'tree>,
}

pub(crate) struct RustCallableFreeVariables<'tree> {
    /// Every reference to a binding declared outside `callable`, in walk order.
    /// The same variable can appear more than once.
    pub references: Vec<RustFreeVariableReference<'tree>>,
    /// Closure, `async` and `gen` blocks directly inside the body. Their bodies
    /// are not walked here, and they can capture bindings of this callable's
    /// enclosing scopes. Nested `fn` items cannot capture and are omitted.
    pub nested_callables: Vec<Node<'tree>>,
    /// A lookup was refused, or an opaque token tree could not be read, so the
    /// reference set may be incomplete.
    pub unresolved: bool,
    /// The walk visited a macro invocation. The classifier has no parsed
    /// operands, so it cannot see implicit captures such as `format!("{x}")`.
    pub saw_macro_invocation: bool,
}

/// Resolve the free variables of `callable`, whose body is `body`.
///
/// `forest` links parsed macro operands to their lexical host; `None` walks
/// plain syntax. `charge` is called with one entry for each visited node and
/// with the entries a pattern classification walks. It is also called with `0`
/// to give the caller a cancellation checkpoint after each lookup. It must
/// fail when the caller must stop, and the error propagates.
pub(crate) fn rust_callable_free_variables<'tree, E>(
    callable: Node<'tree>,
    body: Node<'tree>,
    prepared: &'tree PreparedSyntaxTree,
    forest: Option<&'tree EmbeddedSyntaxForest>,
    charge: &mut dyn FnMut(usize) -> Result<(), E>,
) -> Result<RustCallableFreeVariables<'tree>, E> {
    let mut result = RustCallableFreeVariables {
        references: Vec::new(),
        nested_callables: Vec::new(),
        unresolved: false,
        saw_macro_invocation: false,
    };
    let mut nodes = vec![body];
    while let Some(node) = nodes.pop() {
        charge(1)?;
        if node.id() != body.id() && is_rust_nested_execution_boundary(node) {
            if node.kind() != "function_item" {
                result.nested_callables.push(node);
            }
            continue;
        }
        if node.kind() == "token_tree" && node.has_error() {
            result.unresolved = true;
            continue;
        }
        if node.kind() == "macro_invocation" {
            result.saw_macro_invocation = true;
        }
        if matches!(node.kind(), "identifier" | "self") {
            note_identifier(callable, node, prepared, forest, charge, &mut result)?;
        }
        if let Some(operands) = forest.and_then(|forest| forest.children(node.id())) {
            nodes.extend(operands.rev());
        } else {
            nodes.extend(named_children(node).into_iter().rev());
        }
    }
    Ok(result)
}

fn note_identifier<'tree, E>(
    callable: Node<'tree>,
    node: Node<'tree>,
    prepared: &'tree PreparedSyntaxTree,
    forest: Option<&'tree EmbeddedSyntaxForest>,
    charge: &mut dyn FnMut(usize) -> Result<(), E>,
    result: &mut RustCallableFreeVariables<'tree>,
) -> Result<(), E> {
    let source = prepared.source();
    if brokk_bifrost_rust::field_roles::rust_token_follows_dot(node) {
        // Parsed field identifiers are excluded above. An opaque token stream
        // cannot prove that `. name` is member access rather than a macro
        // operand referring to a lexical local.
        result.unresolved = true;
        return Ok(());
    }
    let Some(name) = source.get(node.byte_range()) else {
        return Ok(());
    };
    // Rust items cannot close over enclosing invocation locals. The forest
    // links parsed macro operands back to their lexical host.
    let resolution = resolve_lexical_binding_with_candidate_index(
        Language::Rust,
        node,
        source,
        node.start_byte(),
        name,
        None,
        &|node| {
            if matches!(
                node.kind(),
                "function_item"
                    | "impl_item"
                    | "trait_item"
                    | "mod_item"
                    | "const_item"
                    | "static_item"
            ) {
                None
            } else if let Some(forest) = forest {
                forest.logical_parent(prepared.tree(), *node)
            } else {
                node.parent()
            }
        },
    );
    charge(0)?;
    #[cfg(test)]
    let resolution = if refused_capture_resolution_for_test(name) {
        LexicalLookupOutcome::Unresolved(
            brokk_bifrost_analysis::analyzer::lexical_definitions::LexicalBindingUnproven::Unknown,
        )
    } else {
        resolution
    };
    let binding = match resolution {
        LexicalLookupOutcome::Binding(binding) => binding,
        LexicalLookupOutcome::ProvenNonLocal => return Ok(()),
        LexicalLookupOutcome::Unresolved(_) => {
            result.unresolved = true;
            return Ok(());
        }
    };
    let (LexicalBindingResolution::Parameter(definition)
    | LexicalBindingResolution::OtherLocal(definition)) = binding;
    let binding_root = forest
        .map_or(prepared.tree(), |forest| {
            forest.tree_for_range(
                prepared.tree(),
                definition.name_range.start_byte,
                definition.name_range.end_byte,
            )
        })
        .root_node();
    let name_node = binding_root
        .named_descendant_for_byte_range(
            definition.name_range.start_byte,
            definition.name_range.end_byte,
        )
        .expect("resolved lexical binding name belongs to its syntax tree");
    // Bare pattern names may denote value items, and a glob import can make
    // that distinction unknown. Match the lowerer: Unknown still creates a
    // tentative local, whose Values gap carries the uncertainty into captures.
    match rust_pattern_name_bounded(
        prepared.tree().root_node(),
        source,
        name_node,
        &mut |entries| charge(entries),
    )? {
        RustPatternName::Binding | RustPatternName::Unknown => {}
        RustPatternName::ValueItem => return Ok(()),
    }
    if callable.start_byte() <= definition.declaration_range.start_byte
        && definition.declaration_range.end_byte <= callable.end_byte()
    {
        return Ok(());
    }
    result.references.push(RustFreeVariableReference {
        name: Box::from(name),
        declaration_start: definition.name_range.start_byte,
        declaration_range: definition.declaration_range.start_byte
            ..definition.declaration_range.end_byte,
        reference: node,
    });
    Ok(())
}

#[cfg(test)]
fn refused_capture_resolution_for_test(name: &str) -> bool {
    // A reserved fixture name works across the lowerer's worker threads.
    name == "__bifrost_refused_capture_11830"
}

/// Recognize a binder by its AST path, excluding constructor/type and field
/// labels. Visibility is decided separately, by the enclosing language rule.
pub(super) fn pattern_binding_declaration(name: Node<'_>) -> Option<Node<'_>> {
    if !matches!(name.kind(), "identifier" | "shorthand_field_identifier") {
        return None;
    }
    let mut current = name;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "let_condition" | "let_declaration" | "for_expression" | "match_arm" => {
                return (parent.child_by_field_name("pattern") == Some(current)).then_some(parent);
            }
            "tuple_struct_pattern" | "struct_pattern" => {
                if parent.child_by_field_name("type") == Some(current) {
                    return None;
                }
            }
            "field_pattern" => {
                if parent.child_by_field_name("pattern").is_some()
                    && parent.child_by_field_name("pattern") != Some(current)
                {
                    return None;
                }
            }
            "match_pattern" if parent.child_by_field_name("condition") == Some(current) => {
                return None;
            }
            "match_pattern" | "tuple_pattern" | "slice_pattern" | "mut_pattern" | "ref_pattern"
            | "reference_pattern" | "captured_pattern" | "or_pattern" => {}
            _ => return None,
        }
        current = parent;
    }
    None
}

pub(super) fn pattern_binding_visible(declaration: Node<'_>, focus: Node<'_>) -> Option<bool> {
    let contains = |node: Node<'_>| {
        node.start_byte() <= focus.start_byte() && focus.end_byte() <= node.end_byte()
    };
    match declaration.kind() {
        "for_expression" => Some(contains(declaration.child_by_field_name("body")?)),
        "let_declaration" => Some(declaration.end_byte() <= focus.start_byte()),
        "match_arm" => {
            // The guard is a child of match_pattern in the Rust grammar. Only
            // the actual pattern is excluded; the guard and body see binders.
            let pattern = declaration.child_by_field_name("pattern")?;
            let guard = pattern.child_by_field_name("condition");
            Some(contains(declaration) && (!contains(pattern) || guard.is_some_and(contains)))
        }
        "let_condition" => {
            let mut current = declaration;
            while let Some(parent) = current.parent() {
                match parent.kind() {
                    "let_chain" => {
                        // Earlier binders are in scope for later chain operands,
                        // but never for their own scrutinee.
                        if contains(parent) {
                            return Some(declaration.end_byte() <= focus.start_byte());
                        }
                    }
                    "if_expression" => {
                        return Some(contains(parent.child_by_field_name("consequence")?));
                    }
                    "while_expression" => {
                        return Some(contains(parent.child_by_field_name("body")?));
                    }
                    _ => return None,
                }
                current = parent;
            }
            None
        }
        _ => None,
    }
}
