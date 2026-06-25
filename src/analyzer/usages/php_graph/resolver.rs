use crate::analyzer::usages::common::language_for_file;
pub(in crate::analyzer::usages) use crate::analyzer::usages::common::node_text;
use crate::analyzer::{
    CodeUnit, IAnalyzer, Language, PhpAnalyzer, PhpFileContext, ProjectFile, Range,
    TypeHierarchyProvider, resolve_php_type,
};
use crate::hash::{HashMap, HashSet};
use crate::text_utils::find_line_index_for_offset;
use tree_sitter::Node;

pub(super) enum TargetKind {
    Type,
    Constructor,
    Method,
    Field,
    Constant,
    Function,
}

pub(super) struct TargetSpec {
    pub(super) target: CodeUnit,
    pub(super) kind: TargetKind,
    pub(super) owner_fq_name: Option<String>,
    pub(super) target_fq_name: String,
    pub(super) member_name: String,
}

impl TargetSpec {
    pub(super) fn from_target(php: &PhpAnalyzer, target: &CodeUnit) -> Option<Self> {
        if target.is_class() {
            return Some(Self {
                target: target.clone(),
                kind: TargetKind::Type,
                owner_fq_name: None,
                target_fq_name: target.fq_name(),
                member_name: target.identifier().to_string(),
            });
        }

        let parent = php.parent_of(target);
        let kind = if target.is_function() {
            if parent.is_some() && target.identifier() == "__construct" {
                TargetKind::Constructor
            } else if parent.is_some() {
                TargetKind::Method
            } else {
                TargetKind::Function
            }
        } else if target.is_field() {
            if parent.is_some() {
                TargetKind::Field
            } else {
                TargetKind::Constant
            }
        } else {
            return None;
        };

        Some(Self {
            target: target.clone(),
            kind,
            owner_fq_name: parent.map(|owner| owner.fq_name()),
            target_fq_name: target.fq_name(),
            member_name: target.identifier().to_string(),
        })
    }
}

#[derive(Default)]
pub(super) struct PhpHierarchyIndex {
    ancestors: HashMap<String, HashSet<String>>,
    interfaces: HashSet<String>,
}

impl PhpHierarchyIndex {
    pub(super) fn build(php: &PhpAnalyzer, files: &HashSet<ProjectFile>) -> Self {
        let mut hierarchy = Self::default();
        for file in files {
            if language_for_file(file) != Language::Php {
                continue;
            }
            for code_unit in php.declarations(file).filter(|unit| unit.is_class()) {
                let type_name = code_unit.fq_name();
                if php.is_interface(code_unit) {
                    hierarchy.interfaces.insert(type_name.clone());
                }
                let ancestors = php
                    .get_direct_ancestors(code_unit)
                    .into_iter()
                    .map(|ancestor| ancestor.fq_name())
                    .collect::<HashSet<_>>();
                if !ancestors.is_empty() {
                    hierarchy.ancestors.insert(type_name, ancestors);
                }
            }
        }
        hierarchy
    }

    fn is_subtype(&self, receiver_fq_name: &str, owner: &str) -> bool {
        let mut stack: Vec<&str> = self
            .ancestors
            .get(receiver_fq_name)
            .map(|ancestors| ancestors.iter().map(String::as_str).collect())
            .unwrap_or_default();
        let mut visited: HashSet<&str> = HashSet::default();
        while let Some(candidate) = stack.pop() {
            if candidate == owner {
                return true;
            }
            if !visited.insert(candidate) {
                continue;
            }
            if let Some(ancestors) = self.ancestors.get(candidate) {
                stack.extend(ancestors.iter().map(String::as_str));
            }
        }
        false
    }
}

pub(super) fn receiver_type_matches(
    receiver_fq_name: &str,
    owner: &str,
    hierarchy: &PhpHierarchyIndex,
) -> bool {
    if receiver_fq_name == owner {
        return !hierarchy.interfaces.contains(owner);
    }
    hierarchy.is_subtype(receiver_fq_name, owner)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn static_receiver_matches(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    start: usize,
    end: usize,
    line_starts: &[usize],
    receiver: &str,
    owner: &str,
    ctx: &PhpFileContext,
    hierarchy: &PhpHierarchyIndex,
) -> bool {
    match receiver {
        "self" | "static" => {
            receiver_is_enclosing_subtype(analyzer, file, start, end, line_starts, owner, hierarchy)
        }
        "parent" => enclosing_owner_at(analyzer, file, start, end, line_starts)
            .is_some_and(|enclosing_owner| hierarchy.is_subtype(&enclosing_owner, owner)),
        _ => resolve_php_type(receiver, ctx)
            .is_some_and(|fq| receiver_type_matches(&fq, owner, hierarchy)),
    }
}

pub(super) fn receiver_is_enclosing_subtype(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    start: usize,
    end: usize,
    line_starts: &[usize],
    owner: &str,
    hierarchy: &PhpHierarchyIndex,
) -> bool {
    enclosing_owner_at(analyzer, file, start, end, line_starts)
        .is_some_and(|receiver| receiver_type_matches(&receiver, owner, hierarchy))
}

fn enclosing_owner_at(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    start: usize,
    end: usize,
    line_starts: &[usize],
) -> Option<String> {
    let range = Range {
        start_byte: start,
        end_byte: end,
        start_line: find_line_index_for_offset(line_starts, start),
        end_line: find_line_index_for_offset(line_starts, end),
    };
    analyzer
        .enclosing_code_unit(file, &range)
        .and_then(|enclosing| analyzer.parent_of(&enclosing).or(Some(enclosing)))
        .map(|enclosing_owner| enclosing_owner.fq_name())
}

pub(in crate::analyzer::usages) fn qualified_candidate_text(
    node: Node<'_>,
    source: &str,
) -> String {
    let mut candidate = node;
    let mut parent = node.parent();
    while let Some(ancestor) = parent {
        if matches!(ancestor.kind(), "namespace_name" | "qualified_name") {
            candidate = ancestor;
            parent = ancestor.parent();
        } else {
            break;
        }
    }
    node_text(candidate, source).trim().to_string()
}

pub(super) fn is_object_creation_type_name(node: Node<'_>) -> bool {
    semantic_parent(node).is_some_and(|parent| parent.kind() == "object_creation_expression")
}

pub(super) fn is_function_call_name(node: Node<'_>) -> bool {
    semantic_parent(node).is_some_and(|parent| parent.kind() == "function_call_expression")
}

pub(super) fn is_member_or_scoped_access_name(node: Node<'_>) -> bool {
    semantic_parent(node).is_some_and(|parent| {
        matches!(
            parent.kind(),
            "member_access_expression"
                | "member_call_expression"
                | "class_constant_access_expression"
                | "scoped_call_expression"
        )
    })
}

pub(super) fn is_const_declaration_name(node: Node<'_>) -> bool {
    node.parent()
        .is_some_and(|parent| parent.kind() == "const_element")
}

pub(super) fn is_function_declaration_name(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        matches!(
            parent.kind(),
            "function_definition" | "method_declaration" | "anonymous_function_creation"
        )
    })
}

fn semantic_parent(node: Node<'_>) -> Option<Node<'_>> {
    let mut candidate = node;
    while let Some(parent) = candidate.parent() {
        if matches!(parent.kind(), "namespace_name" | "qualified_name") {
            candidate = parent;
        } else {
            return Some(parent);
        }
    }
    None
}
