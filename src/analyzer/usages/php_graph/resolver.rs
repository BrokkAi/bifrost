pub(in crate::analyzer::usages) use crate::analyzer::usages::common::node_text;
use crate::analyzer::{
    CodeUnit, IAnalyzer, PhpAnalyzer, PhpFileContext, ProjectFile, Range, TypeHierarchyProvider,
    resolve_php_type,
};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use crate::text_utils::find_line_index_for_offset;
use std::cell::RefCell;
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
    pub(super) owner: Option<CodeUnit>,
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
                owner: None,
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
        let owner_fq_name = parent.as_ref().map(|owner| owner.fq_name());

        Some(Self {
            target: target.clone(),
            kind,
            owner: parent,
            owner_fq_name,
            target_fq_name: target.fq_name(),
            member_name: target.identifier().to_string(),
        })
    }
}

#[derive(Default)]
pub(super) struct PhpHierarchyIndex {
    owner_fq_name: Option<String>,
    owner_is_interface: bool,
    subtype_matches: RefCell<HashMap<String, bool>>,
}

impl PhpHierarchyIndex {
    pub(super) fn for_target_owner(php: &PhpAnalyzer, spec: &TargetSpec) -> Self {
        let Some(owner) = spec.owner.as_ref() else {
            return Self::default();
        };
        let owner_fq_name = owner.fq_name();
        Self {
            owner_fq_name: Some(owner_fq_name),
            owner_is_interface: php.is_interface(owner),
            subtype_matches: RefCell::default(),
        }
    }

    fn is_subtype(&self, php: &PhpAnalyzer, receiver_fq_name: &str, owner: &str) -> bool {
        if self.owner_fq_name.as_deref() != Some(owner) {
            return false;
        }
        // A usage scan visits the same receiver types at many call sites. Keep
        // the scoped proof lazy, but perform each persisted definition lookup
        // and ancestry walk at most once per query.
        if let Some(result) = self.subtype_matches.borrow().get(receiver_fq_name) {
            return *result;
        }
        let result = php
            .definitions(receiver_fq_name)
            .filter(CodeUnit::is_class)
            .any(|unit| class_is_subtype_of_owner(php, &unit, owner));
        self.subtype_matches
            .borrow_mut()
            .insert(receiver_fq_name.to_string(), result);
        result
    }

    pub(super) fn overriding_methods(
        &self,
        php: &PhpAnalyzer,
        spec: &TargetSpec,
        files: &HashSet<ProjectFile>,
        cancellation: Option<&CancellationToken>,
    ) -> Vec<CodeUnit> {
        if !self.owner_is_interface || !matches!(spec.kind, TargetKind::Method) {
            return Vec::new();
        }
        let Some(owner_fq_name) = spec.owner_fq_name.as_deref() else {
            return Vec::new();
        };

        files
            .iter()
            .take_while(|_| !cancellation.is_some_and(CancellationToken::is_cancelled))
            .flat_map(|file| php.declarations(file))
            .filter(|unit| unit.is_class())
            .filter(|unit| self.is_subtype(php, &unit.fq_name(), owner_fq_name))
            .flat_map(|owner| php.direct_children(&owner))
            .filter(|child| child.is_function() && child.identifier() == spec.member_name)
            .collect()
    }
}

fn class_is_subtype_of_owner(
    php: &PhpAnalyzer,
    class_unit: &CodeUnit,
    owner_fq_name: &str,
) -> bool {
    let mut stack = php.get_direct_ancestors(class_unit);
    let mut visited = HashSet::default();
    while let Some(candidate) = stack.pop() {
        let candidate_fq_name = candidate.fq_name();
        if candidate_fq_name == owner_fq_name {
            return true;
        }
        if visited.insert(candidate_fq_name) {
            stack.extend(php.get_direct_ancestors(&candidate));
        }
    }
    false
}

pub(super) fn receiver_type_matches(
    php: &PhpAnalyzer,
    receiver_fq_name: &str,
    owner: &str,
    hierarchy: &PhpHierarchyIndex,
) -> bool {
    if receiver_fq_name == owner {
        return true;
    }
    hierarchy.is_subtype(php, receiver_fq_name, owner)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn static_receiver_matches(
    php: &PhpAnalyzer,
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
        "self" | "static" => receiver_is_enclosing_subtype(
            php,
            analyzer,
            file,
            start,
            end,
            line_starts,
            owner,
            hierarchy,
        ),
        "parent" => enclosing_owner_fq_name_at(analyzer, file, start, end, line_starts)
            .is_some_and(|enclosing_owner| hierarchy.is_subtype(php, &enclosing_owner, owner)),
        _ => resolve_php_type(receiver, ctx)
            .is_some_and(|fq| receiver_type_matches(php, &fq, owner, hierarchy)),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn receiver_is_enclosing_subtype(
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    start: usize,
    end: usize,
    line_starts: &[usize],
    owner: &str,
    hierarchy: &PhpHierarchyIndex,
) -> bool {
    enclosing_owner_fq_name_at(analyzer, file, start, end, line_starts)
        .is_some_and(|receiver| receiver_type_matches(php, &receiver, owner, hierarchy))
}

pub(super) fn enclosing_owner_fq_name_at(
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
                | "nullsafe_member_access_expression"
                | "member_call_expression"
                | "nullsafe_member_call_expression"
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
