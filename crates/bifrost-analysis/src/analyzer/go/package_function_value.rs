//! Whether a Go package variable holds exactly its function-literal
//! initializer wherever the analyzed workspace calls it (issue #3787).
//!
//! `var Eager = func() T { ... }` declares a mutable variable, not a function.
//! A call `Eager()` therefore runs the literal only while nothing has assigned
//! another value to the variable. Go semantic lowering is per file and cannot
//! see writes in other files, so its stable-callable rule covers only local
//! bindings. This module owns the workspace half of the proof. It runs at
//! dispatch time, where the whole workspace is available, and accepts only
//! this shape:
//!
//! - the declaration is one package-level `var` spec naming one variable,
//!   initialized by exactly one function literal;
//! - the structured usage census of that variable is complete and proven;
//! - every reference the census reports is the callee of a call expression,
//!   either `Eager(...)` or `pkg.Eager(...)`.
//!
//! An assignment, an address-taking `&Eager`, a value read such as
//! `f := Eager` or `run(Eager)`, or any unproven reference refuses the proof
//! with its reason. A refused call stays an open dispatch boundary.

use brokk_bifrost_go::declarations::go_identifier_is_exported;
use tree_sitter::{Node, Tree};

use crate::analyzer::semantic::StablePackageValueScope;
use crate::analyzer::usages::get_definition::parse_go_tree;
use crate::analyzer::usages::reference_site::smallest_named_node_covering;
use crate::analyzer::usages::{FuzzyResult, UsageHit, UsageHitKind, find_usages};
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile};
use crate::hash::HashMap;

/// A proof that every workspace call through one package variable runs its
/// function-literal initializer.
#[derive(Debug, Clone)]
pub(crate) struct GoStablePackageFunctionValue {
    /// Byte span of the initializer's `func_literal` node in the declaring
    /// file.
    pub(crate) initializer_start: usize,
    pub(crate) initializer_end: usize,
    /// Every reference the census found. Each one is a direct call.
    pub(crate) references: Vec<UsageHit>,
    pub(crate) scope: StablePackageValueScope,
}

/// Prove that `variable` holds its function-literal initializer at every
/// call in the workspace, or return why the proof does not hold.
///
/// `None` means `variable` is not declared by a package-level `var` spec, so
/// this rule does not apply to it: a struct field, for example, keeps its
/// ordinary boundary. `declaring_source` must be the exact source of
/// `variable`'s file that the caller's semantic artifact was built from.
pub(crate) fn prove_stable_package_function_value(
    analyzer: &dyn IAnalyzer,
    variable: &CodeUnit,
    declaring_source: &str,
) -> Option<Result<GoStablePackageFunctionValue, String>> {
    let tree = parse_go_tree(declaring_source)?;
    let specs = analyzer
        .ranges(variable)
        .into_iter()
        .flat_map(|range| {
            package_var_specs(
                &tree,
                declaring_source,
                range.start_byte,
                range.end_byte,
                variable.identifier(),
            )
        })
        .collect::<Vec<_>>();
    if specs.is_empty() {
        return None;
    }
    Some(prove_package_var_spec(analyzer, variable, &specs))
}

fn prove_package_var_spec(
    analyzer: &dyn IAnalyzer,
    variable: &CodeUnit,
    specs: &[Node<'_>],
) -> Result<GoStablePackageFunctionValue, String> {
    let [spec] = specs else {
        return Err(format!(
            "the variable has {} package-level declarations, not one",
            specs.len()
        ));
    };
    let mut cursor = spec.walk();
    let names = spec
        .children_by_field_name("name", &mut cursor)
        .collect::<Vec<_>>();
    let [name] = names.as_slice() else {
        return Err(format!(
            "its var spec declares {} names, not one",
            names.len()
        ));
    };
    let initializer = single_function_literal_initializer(*spec)?;

    let hits = match find_usages(analyzer, std::slice::from_ref(variable)) {
        FuzzyResult::Success {
            mut hits_by_overload,
            unproven_by_overload,
            unproven_total_by_overload,
        } => {
            let unproven = unproven_total_by_overload
                .get(variable)
                .copied()
                .unwrap_or_default()
                .max(
                    unproven_by_overload
                        .get(variable)
                        .map_or(0, |hits| hits.len()),
                );
            if unproven > 0 {
                return Err(format!(
                    "the usage census has {unproven} unproven references"
                ));
            }
            hits_by_overload.remove(variable).unwrap_or_default()
        }
        FuzzyResult::Incomplete { diagnostics, .. } => {
            return Err(format!("the usage census is incomplete: {diagnostics:?}"));
        }
        other => {
            return Err(format!("the usage census did not succeed: {other:?}"));
        }
    };

    let mut trees = HashMap::<ProjectFile, Tree>::default();
    let mut references = Vec::with_capacity(hits.len());
    for hit in hits {
        if hit.file == *variable.source()
            && hit.start_offset == name.start_byte()
            && hit.end_offset == name.end_byte()
        {
            // The declaring name itself is not a use.
            continue;
        }
        if hit.kind != UsageHitKind::Reference {
            return Err(format!(
                "the reference at {}:{} is a {:?} use",
                hit.file, hit.line, hit.kind
            ));
        }
        if !trees.contains_key(&hit.file) {
            let source = analyzer
                .indexed_source(&hit.file)
                .ok_or_else(|| format!("{} has no indexed source", hit.file))?;
            let tree =
                parse_go_tree(&source).ok_or_else(|| format!("{} does not parse", hit.file))?;
            trees.insert(hit.file.clone(), tree);
        }
        let tree = &trees[&hit.file];
        if !reference_is_direct_call(tree, hit.start_offset, hit.end_offset) {
            return Err(format!(
                "the reference at {}:{} is not the callee of a call",
                hit.file, hit.line
            ));
        }
        references.push(hit);
    }

    Ok(GoStablePackageFunctionValue {
        initializer_start: initializer.start_byte(),
        initializer_end: initializer.end_byte(),
        references,
        scope: if go_identifier_is_exported(variable.identifier()) {
            StablePackageValueScope::Workspace
        } else {
            StablePackageValueScope::Package
        },
    })
}

/// Every package-level `var` spec inside `[start, end)` that names
/// `identifier`.
fn package_var_specs<'tree>(
    tree: &'tree Tree,
    source: &str,
    start: usize,
    end: usize,
    identifier: &str,
) -> Vec<Node<'tree>> {
    let Some(covering) = smallest_named_node_covering(tree.root_node(), start, end) else {
        return Vec::new();
    };
    let mut specs = Vec::new();
    let mut stack = vec![covering];
    while let Some(node) = stack.pop() {
        if node.kind() == "var_spec" {
            let mut cursor = node.walk();
            if node
                .children_by_field_name("name", &mut cursor)
                .any(|name| name.utf8_text(source.as_bytes()).ok() == Some(identifier))
                && declared_at_package_level(node)
            {
                specs.push(node);
            }
            continue;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    specs
}

fn declared_at_package_level(spec: Node<'_>) -> bool {
    let mut ancestor = spec.parent();
    while let Some(node) = ancestor {
        match node.kind() {
            "var_spec_list" | "var_declaration" => ancestor = node.parent(),
            "source_file" => return true,
            _ => return false,
        }
    }
    false
}

/// The spec's value when it is exactly one function literal.
fn single_function_literal_initializer(spec: Node<'_>) -> Result<Node<'_>, String> {
    let values = spec
        .child_by_field_name("value")
        .ok_or("the variable has no initializer".to_owned())?;
    let mut cursor = values.walk();
    let values = values.named_children(&mut cursor).collect::<Vec<_>>();
    match values.as_slice() {
        [value] if value.kind() == "func_literal" => Ok(*value),
        [value] => Err(format!(
            "the initializer is a {}, not a function literal",
            value.kind()
        )),
        _ => Err(format!(
            "the spec has {} initializer values, not one",
            values.len()
        )),
    }
}

/// Whether the reference token at `[start, end)` is the whole callee of a
/// call: `name(...)` or `pkg.name(...)`.
fn reference_is_direct_call(tree: &Tree, start: usize, end: usize) -> bool {
    let Some(token) = smallest_named_node_covering(tree.root_node(), start, end)
        .filter(|node| node.start_byte() == start && node.end_byte() == end)
    else {
        return false;
    };
    let callee = match token.kind() {
        "identifier" => token,
        "field_identifier" => match token.parent() {
            Some(selector)
                if selector.kind() == "selector_expression"
                    && selector
                        .child_by_field_name("field")
                        .is_some_and(|field| field.id() == token.id()) =>
            {
                selector
            }
            _ => return false,
        },
        _ => return false,
    };
    callee.parent().is_some_and(|call| {
        call.kind() == "call_expression"
            && call
                .child_by_field_name("function")
                .is_some_and(|function| function.id() == callee.id())
    })
}
