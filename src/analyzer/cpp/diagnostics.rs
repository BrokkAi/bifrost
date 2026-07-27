use super::{CppAnalyzer, CppCompileContext};
use crate::analyzer::semantic_diagnostics::{node_range, node_text};
use crate::analyzer::tree_sitter_analyzer::collect_parse_errors;
use crate::analyzer::{ProjectFile, SemanticDiagnostic};
use crate::hash::HashSet;
use crate::text_utils::compute_line_starts;
use tree_sitter::{Node, Parser, Tree};

pub(crate) const CPP_UNRECOGNIZED_SYMBOL: &str = "cpp_unrecognized_symbol";
pub(crate) const CPP_SEMANTIC_DIAGNOSTIC_SOURCE: &str = "bifrost-cpp";
const MAX_CPP_SEMANTIC_DIAGNOSTIC_BYTES: usize = 512 * 1024;
const MAX_CPP_SEMANTIC_DIAGNOSTICS: usize = 200;

pub(crate) fn collect_cpp_semantic_diagnostics(
    analyzer: &CppAnalyzer,
    file: &ProjectFile,
    source: &str,
) -> Vec<SemanticDiagnostic> {
    if source.len() > MAX_CPP_SEMANTIC_DIAGNOSTIC_BYTES {
        return Vec::new();
    }
    let Some(context) = analyzer.compile_context_for(file) else {
        return Vec::new();
    };
    let Some(tree) = parse_cpp_tree(source) else {
        return Vec::new();
    };
    let Some(known_type_names) = proven_project_type_names(file, source, context) else {
        return Vec::new();
    };

    let line_starts = compute_line_starts(source);
    let mut diagnostics = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if diagnostics.len() >= MAX_CPP_SEMANTIC_DIAGNOSTICS {
            break;
        }
        if node.kind() == "type_identifier" && is_plain_type_reference(node) {
            let name = node_text(node, source);
            if !name.is_empty()
                && !context.defined_macros.contains(name)
                && !known_type_names.contains(name)
            {
                diagnostics.push(SemanticDiagnostic {
                    range: node_range(node, &line_starts),
                    source: CPP_SEMANTIC_DIAGNOSTIC_SOURCE,
                    kind: CPP_UNRECOGNIZED_SYMBOL,
                    message: format!("Unrecognized C++ type `{name}`"),
                });
            }
        }
        push_named_children(&mut stack, node);
    }
    diagnostics
}

fn parse_cpp_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

fn has_parse_errors(root: Node<'_>) -> bool {
    let mut errors = Vec::new();
    collect_parse_errors(root, &mut errors);
    !errors.is_empty()
}

fn proven_project_type_names(
    source_file: &ProjectFile,
    source: &str,
    context: &CppCompileContext,
) -> Option<HashSet<String>> {
    if !context.forced_includes.is_empty() || !context.system_include_roots.is_empty() {
        return None;
    }

    let mut visited = HashSet::default();
    let mut known_type_names = HashSet::default();
    let mut pending = vec![(source_file.clone(), source.to_string())];
    while let Some((file, source)) = pending.pop() {
        if !visited.insert(file.abs_path()) {
            continue;
        }
        let tree = parse_cpp_tree(&source)?;
        if has_parse_errors(tree.root_node()) {
            return None;
        }
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            match node.kind() {
                "preproc_include" => {
                    let include = quoted_include_path(node, &source)?;
                    let header = resolve_project_header(&file, &include, context)?;
                    let Ok(header_source) = header.read_to_string() else {
                        return None;
                    };
                    pending.push((header, header_source));
                }
                "preproc_def"
                | "preproc_function_def"
                | "preproc_if"
                | "preproc_ifdef"
                | "preproc_ifndef"
                | "preproc_elif"
                | "preproc_else"
                | "preproc_call" => return None,
                "class_specifier" | "struct_specifier" | "enum_specifier" => {
                    if let Some(name) = declared_type_name(node, &source) {
                        known_type_names.insert(name);
                    }
                    push_named_children(&mut stack, node);
                }
                _ => push_named_children(&mut stack, node),
            }
        }
    }
    Some(known_type_names)
}

fn declared_type_name(node: Node<'_>, source: &str) -> Option<String> {
    let name = node.child_by_field_name("name").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .find(|child| matches!(child.kind(), "type_identifier" | "identifier"))
    })?;
    let name = node_text(name, source).trim();
    (!name.is_empty()).then(|| name.to_string())
}

fn quoted_include_path(node: Node<'_>, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    let literal = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "string_literal")?;
    let text = node_text(literal, source);
    text.strip_prefix('"')?
        .strip_suffix('"')
        .filter(|path| !path.is_empty())
        .map(ToOwned::to_owned)
}

fn resolve_project_header(
    source_file: &ProjectFile,
    include: &str,
    context: &CppCompileContext,
) -> Option<ProjectFile> {
    let mut candidates = HashSet::default();
    let source_parent = source_file.abs_path().parent()?.to_path_buf();
    for root in std::iter::once(source_parent).chain(context.project_include_roots.iter().cloned())
    {
        let candidate = root.join(include);
        if candidate.is_file() && candidate.starts_with(source_file.root()) {
            candidates.insert(candidate);
        }
    }
    (candidates.len() == 1).then(|| {
        ProjectFile::new(
            source_file.root().to_path_buf(),
            candidates
                .into_iter()
                .next()
                .expect("one candidate")
                .strip_prefix(source_file.root())
                .expect("candidate inside project")
                .to_path_buf(),
        )
    })
}

fn is_plain_type_reference(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if !matches!(
        parent.kind(),
        "declaration" | "type_descriptor" | "sized_type_specifier"
    ) {
        return false;
    }
    let mut current = parent;
    while let Some(ancestor) = current.parent() {
        if matches!(
            ancestor.kind(),
            "class_specifier"
                | "struct_specifier"
                | "enum_specifier"
                | "template_declaration"
                | "template_parameter_list"
                | "template_type"
                | "qualified_identifier"
                | "scoped_type_identifier"
        ) {
            return false;
        }
        current = ancestor;
    }
    true
}

fn push_named_children<'tree>(stack: &mut Vec<Node<'tree>>, node: Node<'tree>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.named_children(&mut cursor).collect();
    stack.extend(children.into_iter().rev());
}

#[cfg(test)]
mod tests {
    use super::{CPP_UNRECOGNIZED_SYMBOL, collect_cpp_semantic_diagnostics};
    use crate::analyzer::{CppAnalyzer, Language, ProjectFile, TestProject};

    fn analyzer_fixture(files: &[(&str, &str)]) -> (tempfile::TempDir, CppAnalyzer, ProjectFile) {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        for (path, source) in files {
            ProjectFile::new(root.clone(), path)
                .write(source)
                .expect("fixture file");
        }
        let project = TestProject::new(root.clone(), Language::Cpp);
        let analyzer = CppAnalyzer::from_project(project);
        let file = ProjectFile::new(root, "src/main.cpp");
        (temp, analyzer, file)
    }

    #[test]
    fn no_compile_context_means_no_semantic_diagnostics() {
        let (_temp, analyzer, file) = analyzer_fixture(&[("src/main.cpp", "MissingType value;")]);
        assert!(
            collect_cpp_semantic_diagnostics(&analyzer, &file, "MissingType value;").is_empty()
        );
    }

    #[test]
    fn matching_context_reports_a_clear_unknown_type() {
        let (_temp, analyzer, file) = analyzer_fixture(&[
            ("src/main.cpp", "MissingType value;"),
            (
                "compile_commands.json",
                r#"[{"directory":".","file":"src/main.cpp","arguments":["clang++","-c","src/main.cpp"]}]"#,
            ),
        ]);
        let diagnostics = collect_cpp_semantic_diagnostics(&analyzer, &file, "MissingType value;");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(CPP_UNRECOGNIZED_SYMBOL, diagnostics[0].kind);
    }

    #[test]
    fn included_project_type_is_not_diagnosed() {
        let (_temp, analyzer, file) = analyzer_fixture(&[
            ("include/project_type.hpp", "struct ProjectType {};"),
            (
                "src/main.cpp",
                "#include \"project_type.hpp\"\nProjectType value;",
            ),
            (
                "compile_commands.json",
                r#"[{"directory":".","file":"src/main.cpp","arguments":["clang++","-I","include","-c","src/main.cpp"]}]"#,
            ),
        ]);
        let source = "#include \"project_type.hpp\"\nProjectType value;";
        assert!(collect_cpp_semantic_diagnostics(&analyzer, &file, source).is_empty());
    }

    #[test]
    fn preprocessing_and_templates_remain_silent() {
        let (_temp, analyzer, file) = analyzer_fixture(&[
            (
                "src/main.cpp",
                "FEATURE value;\ntemplate <typename T> T value_for();",
            ),
            (
                "compile_commands.json",
                r#"[{"directory":".","file":"src/main.cpp","arguments":["clang++","-D","FEATURE","-c","src/main.cpp"]}]"#,
            ),
        ]);
        let source = "FEATURE value;\ntemplate <typename T> T value_for();";
        assert!(collect_cpp_semantic_diagnostics(&analyzer, &file, source).is_empty());
    }
}
