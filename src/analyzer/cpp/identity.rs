use super::{CppAnalyzer, include_paths, resolve_include_targets_with_index};
use crate::analyzer::declaration_range::node_for_exact_range;
use crate::analyzer::tree_walk::subtree_contains;
use crate::analyzer::{CallableLinkage, CodeUnit, IAnalyzer, ProjectFile, Range, resolve_analyzer};
use crate::path_utils::rel_path_string;
use tree_sitter::{Node, Parser, Tree};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CppCallableUnitRole {
    DeclarationOnly,
    Definition,
    Both,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CppOccurrenceRole {
    DeclarationOnly,
    Definition,
    Both,
    Unknown,
}

impl CppOccurrenceRole {
    pub(crate) fn api_label(self) -> Option<&'static str> {
        match self {
            Self::DeclarationOnly => Some("declaration"),
            Self::Definition => Some("definition"),
            Self::Both | Self::Unknown => None,
        }
    }
}

pub(crate) struct CppOccurrenceClassifier {
    tree: Tree,
}

impl CppOccurrenceClassifier {
    pub(crate) fn new(source: &str) -> Option<Self> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .ok()?;
        parser.parse(source, None).map(|tree| Self { tree })
    }

    pub(crate) fn classify(&self, candidate: &CodeUnit, range: &Range) -> CppOccurrenceRole {
        cpp_occurrence_role_for_range(self.tree.root_node(), candidate, range)
    }
}

pub(crate) fn cpp_callable_unit_role(
    analyzer: &dyn IAnalyzer,
    callable: &CodeUnit,
) -> CppCallableUnitRole {
    if !callable.is_callable() {
        return CppCallableUnitRole::Unknown;
    }
    let mut declaration = false;
    let mut definition = false;
    for metadata in analyzer.signature_metadata(callable) {
        if metadata.is_declaration_only() {
            declaration = true;
        } else {
            definition = true;
        }
    }
    match (declaration, definition) {
        (true, false) => CppCallableUnitRole::DeclarationOnly,
        (false, true) => CppCallableUnitRole::Definition,
        (true, true) => CppCallableUnitRole::Both,
        (false, false) => CppCallableUnitRole::Unknown,
    }
}

pub(crate) fn cpp_indexed_callable_linkage(
    analyzer: &dyn IAnalyzer,
    callable: &CodeUnit,
) -> Option<CallableLinkage> {
    let mut external = false;
    for metadata in analyzer.signature_metadata(callable) {
        match metadata.callable_linkage() {
            Some(CallableLinkage::Internal) => return Some(CallableLinkage::Internal),
            Some(CallableLinkage::External) => external = true,
            None => {}
        }
    }
    external.then_some(CallableLinkage::External)
}

pub(crate) fn cpp_callable_definitions_share_identity_evidence(
    analyzer: &dyn IAnalyzer,
    left: &CodeUnit,
    right: &CodeUnit,
) -> bool {
    left.source() == right.source()
        || (left.fq_name() == right.fq_name()
            && left.signature() == right.signature()
            && matches!(
                cpp_indexed_callable_linkage(analyzer, left),
                Some(CallableLinkage::External)
            )
            && matches!(
                cpp_indexed_callable_linkage(analyzer, right),
                Some(CallableLinkage::External)
            )
            && cpp_header_body_files_are_related(analyzer, left.source(), right.source()))
}

/// Direct include evidence relates one header declaration to one implementation
/// file without pretending that every external name in a workspace belongs to
/// one linker unit.
pub(crate) fn cpp_header_body_files_are_related(
    analyzer: &dyn IAnalyzer,
    left: &ProjectFile,
    right: &ProjectFile,
) -> bool {
    let (header, implementation) = if cpp_source_path_is_header(left) {
        (left, right)
    } else if cpp_source_path_is_header(right) {
        (right, left)
    } else {
        return false;
    };
    if cpp_source_path_is_header(implementation) {
        return false;
    }
    let Some(cpp) = resolve_analyzer::<CppAnalyzer>(analyzer) else {
        return false;
    };
    let include_targets = cpp.include_target_index();
    analyzer
        .import_statements(implementation)
        .into_iter()
        .flat_map(|import| include_paths(std::slice::from_ref(&import)))
        .any(|include| {
            let targets =
                resolve_include_targets_with_index(implementation, &include, include_targets);
            targets.len() == 1 && targets.first() == Some(header)
        })
}

pub(crate) fn cpp_source_path_is_header(source: &ProjectFile) -> bool {
    let path = rel_path_string(source).to_ascii_lowercase();
    matches!(path.rsplit('.').next(), Some("h" | "hh" | "hpp" | "hxx"))
}

pub(crate) fn cpp_occurrence_role_for_range(
    root: Node<'_>,
    candidate: &CodeUnit,
    range: &Range,
) -> CppOccurrenceRole {
    if !candidate.is_callable() && !candidate.is_class() {
        return CppOccurrenceRole::Both;
    }
    let Some(node) = cpp_declaration_node_for_range(root, range) else {
        return CppOccurrenceRole::Unknown;
    };
    if candidate.is_callable() {
        return if subtree_contains(node, |descendant| {
            descendant.kind() == "function_definition"
                && descendant.child_by_field_name("body").is_some()
        }) {
            CppOccurrenceRole::Definition
        } else {
            CppOccurrenceRole::DeclarationOnly
        };
    }
    if node.kind() == "function_definition" && node.child_by_field_name("body").is_some() {
        return CppOccurrenceRole::Definition;
    }
    if !subtree_contains(node, |descendant| {
        matches!(
            descendant.kind(),
            "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier"
        )
    }) {
        return CppOccurrenceRole::Both;
    }
    if subtree_contains(node, |descendant| {
        matches!(
            descendant.kind(),
            "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier"
        ) && descendant.child_by_field_name("body").is_some()
    }) {
        CppOccurrenceRole::Definition
    } else {
        CppOccurrenceRole::DeclarationOnly
    }
}

fn cpp_declaration_node_for_range<'tree>(root: Node<'tree>, range: &Range) -> Option<Node<'tree>> {
    node_for_exact_range(root, range).or_else(|| {
        root.descendant_for_byte_range(range.start_byte, range.end_byte)
            .and_then(|mut node| {
                while node.start_byte() > range.start_byte || node.end_byte() < range.end_byte {
                    node = node.parent()?;
                }
                Some(node)
            })
    })
}
