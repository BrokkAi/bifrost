use super::*;
use crate::analyzer::usages::scala_graph::{ScalaNameResolver, ScalaProjectTypes};
use std::sync::Arc;
use tree_sitter::{Node, Parser};

impl TypeHierarchyProvider for ScalaAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if let Some(cached) = self.direct_ancestors.get(code_unit) {
            return (*cached).clone();
        }

        let ancestors = self.resolve_direct_ancestors(code_unit);
        self.direct_ancestors
            .insert(code_unit.clone(), Arc::new(ancestors.clone()));
        ancestors
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        if let Some(cached) = self.direct_descendants.get(code_unit) {
            return (*cached).clone();
        }

        let descendants = self
            .direct_descendant_index
            .get_or_init(|| build_direct_descendant_index(self, self))
            .get(&code_unit.fq_name())
            .map(|descendants| descendants.as_ref().clone())
            .unwrap_or_default();
        self.direct_descendants
            .insert(code_unit.clone(), Arc::new(descendants.clone()));
        descendants
    }
}

impl ScalaAnalyzer {
    fn resolve_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if !code_unit.is_class() {
            return Vec::new();
        }

        let Ok(source) = self.inner.project().read_source(code_unit.source()) else {
            return Vec::new();
        };
        let Some(tree) = parse_scala_source(&source) else {
            return Vec::new();
        };
        let Some(declaration) =
            declaration_node_for_unit(tree.root_node(), &source, code_unit, self)
        else {
            return Vec::new();
        };
        let Some(extends_clause) = declaration.child_by_field_name("extend") else {
            return Vec::new();
        };

        let types = ScalaProjectTypes::build(self);
        let resolver = ScalaNameResolver::for_file(self, code_unit.source(), &types);
        let mut ancestors = Vec::new();
        let mut seen = HashSet::default();
        for parent in direct_parent_type_nodes(extends_clause) {
            let raw = node_text(parent, &source);
            let Some(fqn) = resolver.resolve(raw) else {
                continue;
            };
            if !seen.insert(fqn.clone()) {
                continue;
            }
            if let Some(definition) = self.definitions(&fqn).find(|unit| unit.is_class()).cloned() {
                ancestors.push(definition);
            }
        }
        ancestors
    }
}

fn parse_scala_source(source: &str) -> Option<tree_sitter::Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_scala::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

fn declaration_node_for_unit<'tree>(
    root: Node<'tree>,
    source: &str,
    code_unit: &CodeUnit,
    analyzer: &ScalaAnalyzer,
) -> Option<Node<'tree>> {
    let ranges = analyzer.ranges(code_unit);
    let start = ranges.iter().map(|range| range.start_byte).min()?;
    let end = ranges.iter().map(|range| range.end_byte).max()?;
    let expected_name = code_unit.identifier().trim_end_matches('$');
    let mut stack = vec![root];
    let mut best: Option<Node<'tree>> = None;

    while let Some(node) = stack.pop() {
        if node.end_byte() < start || node.start_byte() > end {
            continue;
        }
        if is_type_declaration(node)
            && node.start_byte() >= start
            && node.end_byte() <= end
            && declaration_name(node, source).as_deref() == Some(expected_name)
        {
            best = match best {
                Some(current) if node.byte_range().len() >= current.byte_range().len() => {
                    Some(current)
                }
                _ => Some(node),
            };
        }

        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            if child.end_byte() >= start && child.start_byte() <= end {
                stack.push(child);
            }
        }
    }

    best
}

fn is_type_declaration(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "class_definition" | "object_definition" | "trait_definition" | "enum_definition"
    )
}

fn declaration_name(node: Node<'_>, source: &str) -> Option<String> {
    node.child_by_field_name("name")
        .map(|name| node_text(name, source).trim().to_string())
        .filter(|name| !name.is_empty())
}

fn direct_parent_type_nodes(extends_clause: Node<'_>) -> Vec<Node<'_>> {
    let mut parents = Vec::new();
    let mut cursor = extends_clause.walk();
    for child in extends_clause.named_children(&mut cursor) {
        collect_parent_type_roots(child, &mut parents);
    }
    parents
}

fn collect_parent_type_roots<'tree>(node: Node<'tree>, parents: &mut Vec<Node<'tree>>) {
    match node.kind() {
        "arguments" | "annotation" | "structural_type" | "tuple_type" | "named_tuple_type"
        | "wildcard" => {}
        "type_identifier"
        | "stable_type_identifier"
        | "generic_type"
        | "projected_type"
        | "applied_constructor_type"
        | "singleton_type" => parents.push(node),
        "compound_type" | "annotated_type" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                collect_parent_type_roots(child, parents);
            }
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                collect_parent_type_roots(child, parents);
            }
        }
    }
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}
