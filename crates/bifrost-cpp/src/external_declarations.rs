//! Structured declaration extraction for external C++ headers.
//!
//! This module is the language-only scanner shared by dependency-pack
//! production and external-boundary evidence. It emits neutral records so this
//! crate stays below `brokk-bifrost-analysis` in the dependency graph.

use crate::adapter::parse_cpp_file;
use crate::declarations::{
    CppParameterType, cpp_callable_parameter_type_identities, cpp_function_declarator_at, node_text,
};
use crate::graph::resolver::cpp_name_for;
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::model::{CodeUnit, CodeUnitType, StructuredTypeIdentity};
use brokk_bifrost_core::analyzer::tree_walk::collect_parse_errors;
use brokk_bifrost_core::hash::HashMap;
use std::path::{Path, PathBuf};
use tree_sitter::{Node, Parser};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CppExternalDeclarationLimits {
    pub max_records: usize,
}

impl Default for CppExternalDeclarationLimits {
    fn default() -> Self {
        Self {
            max_records: 250_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CppExternalDeclarationCompleteness {
    Complete,
    Partial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CppExternalMemberKind {
    Function,
    Field,
    Macro,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CppExternalVisibility {
    Public,
    Protected,
    Private,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppExternalType {
    pub name: String,
    pub source_name: String,
    pub visibility: CppExternalVisibility,
    pub source_path: PathBuf,
    pub direct_bases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppExternalMember {
    pub owner: Option<String>,
    pub name: String,
    pub qualified_name: String,
    pub kind: CppExternalMemberKind,
    pub visibility: CppExternalVisibility,
    pub is_constructor: bool,
    pub signature: Option<String>,
    /// The structured type of each invocation parameter, or `None` when the
    /// declaration is not a callable or its parameter list was not reached.
    ///
    /// These are structured identities rather than rendered spellings because
    /// the consumer publishes them into a type model, and a spelling such as
    /// `const T&` is a source text, not a type name.
    pub parameter_types: Option<Vec<CppParameterType>>,
    pub return_type: Option<StructuredTypeIdentity>,
    pub source_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppExternalDeclarationDiagnostic {
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppExternalDeclarationSet {
    pub types: Vec<CppExternalType>,
    pub members: Vec<CppExternalMember>,
    pub completeness: CppExternalDeclarationCompleteness,
    pub diagnostics: Vec<CppExternalDeclarationDiagnostic>,
}

/// Return the literal paths from angle-bracket includes in one C++ source.
///
/// Quoted and computed includes are not external-root evidence. Conditional
/// includes are retained because compile-context resolution still proves the
/// root, while pack completeness records preprocessor uncertainty separately.
pub fn external_angle_include_paths(source: &str) -> Vec<PathBuf> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .expect("the linked tree-sitter-cpp grammar matches this tree-sitter version");
    let tree = parser.parse(source, None).expect("uncancelled C++ parse");
    external_angle_include_paths_from_root(source, tree.root_node())
}

/// Return literal unconditional angle includes from an existing C++ syntax tree.
///
/// The source and root must describe the same immutable snapshot. Analyzer
/// callers use this form to reuse prepared workspace syntax; standalone
/// external headers use [`external_angle_include_paths`].
pub fn external_angle_include_paths_from_root(source: &str, root: Node<'_>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "preproc_include"
            && !has_conditional_preprocessor_ancestor(node)
            && let Some(path) = node.child_by_field_name("path")
            && path.kind() == "system_lib_string"
            && let Some(path) = node_text(path, source)
                .strip_prefix('<')
                .and_then(|path| path.strip_suffix('>'))
                .filter(|path| !path.is_empty())
        {
            paths.push(PathBuf::from(path));
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    paths.sort();
    paths.dedup();
    paths
}

fn has_conditional_preprocessor_ancestor(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "preproc_if" | "preproc_ifdef" | "preproc_ifndef" | "preproc_elif" | "preproc_else"
        ) {
            return true;
        }
        node = parent;
    }
    false
}

/// Extract declarations from one exact header source entry.
///
/// `source_path` is relative to `source_set_root`. The caller owns source-set
/// containment, byte limits, cancellation, and stable hashing. This function
/// owns only C++ syntax interpretation and its record limit.
pub fn extract_external_declarations(
    source_set_root: &Path,
    source_path: &Path,
    source: &str,
    limits: CppExternalDeclarationLimits,
) -> CppExternalDeclarationSet {
    let file = ProjectFile::new(source_set_root.to_path_buf(), source_path.to_path_buf());
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .expect("the linked tree-sitter-cpp grammar matches this tree-sitter version");
    let tree = parser.parse(source, None).expect("uncancelled C++ parse");

    let mut diagnostics = Vec::new();
    let mut completeness = CppExternalDeclarationCompleteness::Complete;
    let mut parse_errors = Vec::new();
    collect_parse_errors(tree.root_node(), &mut parse_errors);
    if !parse_errors.is_empty() {
        completeness = CppExternalDeclarationCompleteness::Partial;
        diagnostics.push(CppExternalDeclarationDiagnostic {
            code: "cpp.external.parse_error",
            message: format!(
                "external header `{}` has parse errors",
                source_path.display()
            ),
        });
    }
    if has_unsupported_preprocessing(tree.root_node()) {
        completeness = CppExternalDeclarationCompleteness::Partial;
        diagnostics.push(CppExternalDeclarationDiagnostic {
            code: "cpp.external.preprocessor_partial",
            message: format!(
                "external header `{}` has conditional or generated declarations",
                source_path.display()
            ),
        });
    }

    let parsed = parse_cpp_file(&file, source, &tree);
    let mut parent_by_child = HashMap::default();
    for (parent, children) in &parsed.children {
        for child in children {
            parent_by_child.insert(child.clone(), parent.clone());
        }
    }

    let mut declarations = parsed.declarations().iter().cloned().collect::<Vec<_>>();
    declarations.sort_by_key(|declaration| {
        (
            declaration.fq_name(),
            declaration.kind(),
            declaration.signature().map(str::to_owned),
        )
    });

    let mut types = Vec::new();
    let mut members = Vec::new();
    for declaration in declarations {
        if types.len().saturating_add(members.len()) >= limits.max_records {
            completeness = CppExternalDeclarationCompleteness::Partial;
            diagnostics.push(CppExternalDeclarationDiagnostic {
                code: "cpp.external.record_limit",
                message: format!(
                    "external header `{}` exceeded the declaration record limit",
                    source_path.display()
                ),
            });
            break;
        }
        match declaration.kind() {
            CodeUnitType::Class => types.push(CppExternalType {
                name: declaration.fq_name(),
                source_name: cpp_name_for(&declaration),
                visibility: parsed
                    .ranges
                    .get(&declaration)
                    .and_then(|ranges| ranges.iter().map(|range| range.start_byte).min())
                    .map(|start| cpp_member_visibility(tree.root_node(), source, start))
                    .unwrap_or(CppExternalVisibility::Private),
                source_path: source_path.to_path_buf(),
                direct_bases: parsed
                    .raw_supertypes
                    .get(&declaration)
                    .cloned()
                    .unwrap_or_default(),
            }),
            CodeUnitType::Function | CodeUnitType::Field | CodeUnitType::Macro => {
                let metadata = parsed
                    .signature_metadata
                    .get(&declaration)
                    .and_then(|records| records.first());
                let declaration_start = parsed
                    .ranges
                    .get(&declaration)
                    .and_then(|ranges| ranges.iter().map(|range| range.start_byte).min());
                let parameter_types = (declaration.kind() == CodeUnitType::Function)
                    .then(|| {
                        declaration_start
                            .and_then(|start| cpp_function_declarator_at(tree.root_node(), start))
                            .map(|declarator| {
                                cpp_callable_parameter_type_identities(declarator, source)
                            })
                    })
                    .flatten();
                members.push(CppExternalMember {
                    owner: nearest_type_owner(&declaration, &parent_by_child),
                    name: declaration.terminal_name().to_owned(),
                    qualified_name: cpp_name_for(&declaration),
                    kind: match declaration.kind() {
                        CodeUnitType::Function => CppExternalMemberKind::Function,
                        CodeUnitType::Field => CppExternalMemberKind::Field,
                        CodeUnitType::Macro => CppExternalMemberKind::Macro,
                        _ => unreachable!("the outer match admits exactly member kinds"),
                    },
                    visibility: declaration_start
                        .map(|start| cpp_member_visibility(tree.root_node(), source, start))
                        .unwrap_or(CppExternalVisibility::Private),
                    is_constructor: metadata
                        .is_some_and(|metadata| metadata.callable_is_constructor()),
                    signature: declaration.signature().map(str::to_owned),
                    parameter_types,
                    return_type: metadata
                        .and_then(|metadata| metadata.return_type_identity())
                        .cloned(),
                    source_path: source_path.to_path_buf(),
                });
            }
            CodeUnitType::Module | CodeUnitType::FileScope => {}
        }
    }

    CppExternalDeclarationSet {
        types,
        members,
        completeness,
        diagnostics,
    }
}

fn cpp_member_visibility(root: Node<'_>, source: &str, start_byte: usize) -> CppExternalVisibility {
    let mut current = root.descendant_for_byte_range(start_byte, start_byte);
    while let Some(node) = current {
        let Some(parent) = node.parent() else {
            break;
        };
        if parent.kind() == "field_declaration_list" {
            let default = match parent.parent().map(|owner| owner.kind()) {
                Some("struct_specifier" | "union_specifier") => CppExternalVisibility::Public,
                _ => CppExternalVisibility::Private,
            };
            let mut visibility = default;
            let mut cursor = parent.walk();
            for child in parent.named_children(&mut cursor) {
                if child.start_byte() > start_byte {
                    break;
                }
                if child.kind() == "access_specifier" {
                    visibility = match node_text(child, source).trim_end_matches(':').trim() {
                        "public" => CppExternalVisibility::Public,
                        "protected" => CppExternalVisibility::Protected,
                        "private" => CppExternalVisibility::Private,
                        _ => CppExternalVisibility::Private,
                    };
                }
            }
            return visibility;
        }
        current = Some(parent);
    }
    CppExternalVisibility::Public
}

fn nearest_type_owner(
    declaration: &CodeUnit,
    parent_by_child: &HashMap<CodeUnit, CodeUnit>,
) -> Option<String> {
    let mut current = declaration;
    while let Some(parent) = parent_by_child.get(current) {
        if parent.kind() == CodeUnitType::Class {
            return Some(parent.fq_name());
        }
        current = parent;
    }
    None
}

fn has_unsupported_preprocessing(root: Node<'_>) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if matches!(
            node.kind(),
            "preproc_def"
                | "preproc_function_def"
                | "preproc_if"
                | "preproc_ifdef"
                | "preproc_ifndef"
                | "preproc_elif"
                | "preproc_else"
        ) {
            return true;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extract(source: &str) -> CppExternalDeclarationSet {
        let temp = tempfile::tempdir().expect("temp root");
        extract_external_declarations(
            temp.path(),
            Path::new("vector"),
            source,
            CppExternalDeclarationLimits::default(),
        )
    }

    #[test]
    fn extracts_only_literal_angle_include_paths() {
        let source = "#include <vector>\n#include \"local.hpp\"\n#include HEADER\n#if FEATURE\n#include <conditional.hpp>\n#endif\n";
        assert_eq!(
            vec![PathBuf::from("vector")],
            external_angle_include_paths(source)
        );
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("C++ grammar");
        let tree = parser.parse(source, None).expect("tree");
        assert_eq!(
            vec![PathBuf::from("vector")],
            external_angle_include_paths_from_root(source, tree.root_node())
        );
    }

    #[test]
    fn extracts_namespaced_template_type_and_owned_members() {
        let declarations = extract(
            r#"
            namespace std {
            template <typename T> class vector : public sequence<T> {
            public:
                vector();
                void push_back(const T& value);
                T size;
            };
            }
            "#,
        );

        assert_eq!(
            CppExternalDeclarationCompleteness::Complete,
            declarations.completeness
        );
        assert!(
            declarations.types.iter().any(|record| {
                record.name == "std.vector" && record.direct_bases == ["sequence<T>"]
            }),
            "{declarations:#?}"
        );
        assert!(
            declarations.members.iter().any(|record| {
                record.owner.as_deref() == Some("std.vector")
                    && record.name == "push_back"
                    && record.visibility == CppExternalVisibility::Public
            }),
            "{declarations:#?}"
        );
        assert!(
            declarations.members.iter().any(|record| {
                record.owner.as_deref() == Some("std.vector") && record.name == "size"
            }),
            "{declarations:#?}"
        );
    }

    #[test]
    fn keeps_same_short_names_under_distinct_owners() {
        let declarations = extract(
            "namespace first { class box { void add(int); }; }\nnamespace second { class box { void add(int); }; }",
        );
        let mut owners = declarations
            .members
            .iter()
            .filter(|member| member.name == "add")
            .filter_map(|member| member.owner.clone())
            .collect::<Vec<_>>();
        owners.sort();

        assert_eq!(vec!["first.box", "second.box"], owners);
        assert!(
            declarations
                .members
                .iter()
                .filter(|member| member.name == "add")
                .all(|member| member.visibility == CppExternalVisibility::Private)
        );
    }

    #[test]
    fn nested_type_visibility_follows_the_enclosing_access_section() {
        let declarations = extract(
            "class Outer { class Hidden {}; public: struct Visible {}; protected: class Guarded {}; };",
        );
        assert!(declarations.types.iter().any(|record| {
            record.name == "Outer$Hidden" && record.visibility == CppExternalVisibility::Private
        }));
        assert!(declarations.types.iter().any(|record| {
            record.name == "Outer$Visible" && record.visibility == CppExternalVisibility::Public
        }));
        assert!(declarations.types.iter().any(|record| {
            record.name == "Outer$Guarded" && record.visibility == CppExternalVisibility::Protected
        }));
    }

    #[test]
    fn preprocessor_and_record_limits_make_the_surface_partial() {
        let temp = tempfile::tempdir().expect("temp root");
        let declarations = extract_external_declarations(
            temp.path(),
            Path::new("limited.hpp"),
            "#ifdef FEATURE\nclass Conditional {};\n#endif\nclass Always {};",
            CppExternalDeclarationLimits { max_records: 1 },
        );

        assert_eq!(
            CppExternalDeclarationCompleteness::Partial,
            declarations.completeness
        );
        assert!(
            declarations
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "cpp.external.preprocessor_partial")
        );
        assert!(
            declarations
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "cpp.external.record_limit")
        );
    }
}
