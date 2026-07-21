use crate::analyzer::{Language, Range};
use tree_sitter::Node;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReferenceCandidateRanges {
    Complete(Vec<Range>),
    LimitExceeded { limit: usize, ranges: Vec<Range> },
}

/// Collect grammar-derived terminal nodes that may denote source references.
///
/// The traversal is iterative so deeply nested generated source cannot exhaust the
/// Rust stack. A zero limit is valid and reports overflow as soon as a candidate is
/// encountered.
pub(crate) fn reference_candidate_ranges(
    root: Node<'_>,
    language: Language,
    limit: usize,
) -> ReferenceCandidateRanges {
    collect_candidate_ranges(
        root,
        language,
        limit,
        CandidateFrontier::References,
        &|| false,
    )
    .expect("non-cancellable collection cannot be cancelled")
}

pub(crate) fn reference_candidate_ranges_cancellable(
    root: Node<'_>,
    language: Language,
    limit: usize,
    is_cancelled: &dyn Fn() -> bool,
) -> Option<ReferenceCandidateRanges> {
    collect_candidate_ranges(
        root,
        language,
        limit,
        CandidateFrontier::References,
        is_cancelled,
    )
}

/// Preserve the LSP's identifier-only token frontier. Semantic tokens resolve
/// declarations for coloring, so receiver keywords and compound callable names
/// must not become tokens merely because the differential engine scans them.
pub(crate) fn semantic_token_candidate_ranges(
    root: Node<'_>,
    language: Language,
    limit: usize,
) -> ReferenceCandidateRanges {
    collect_candidate_ranges(
        root,
        language,
        limit,
        CandidateFrontier::SemanticTokens,
        &|| false,
    )
    .expect("non-cancellable collection cannot be cancelled")
}

#[derive(Clone, Copy)]
enum CandidateFrontier {
    References,
    SemanticTokens,
}

fn collect_candidate_ranges(
    root: Node<'_>,
    language: Language,
    limit: usize,
    frontier: CandidateFrontier,
    is_cancelled: &dyn Fn() -> bool,
) -> Option<ReferenceCandidateRanges> {
    let mut ranges = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if is_cancelled() {
            return None;
        }
        let compound = matches!(frontier, CandidateFrontier::References)
            && is_compound_reference_candidate(language, node.kind());
        let candidate = match frontier {
            CandidateFrontier::References => is_reference_candidate_node(language, node.kind()),
            CandidateFrontier::SemanticTokens => {
                is_semantic_token_identifier_node(language, node.kind())
            }
        };
        if candidate
            && !is_excluded_reference_candidate(language, node, frontier)
            && (node.named_child_count() == 0 || compound)
            && node.start_byte() < node.end_byte()
        {
            if ranges.len() == limit {
                ranges.sort_unstable();
                ranges.dedup();
                return Some(ReferenceCandidateRanges::LimitExceeded { limit, ranges });
            }
            ranges.push(Range {
                start_byte: node.start_byte(),
                end_byte: node.end_byte(),
                start_line: node.start_position().row,
                end_line: node.end_position().row,
            });
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    ranges.sort_unstable();
    ranges.dedup();
    Some(ReferenceCandidateRanges::Complete(ranges))
}

fn is_excluded_reference_candidate(
    language: Language,
    node: Node<'_>,
    frontier: CandidateFrontier,
) -> bool {
    if !matches!(frontier, CandidateFrontier::References) {
        return false;
    }

    match language {
        Language::Go => is_go_field_or_type_declaration_name(node),
        Language::CSharp => is_csharp_tuple_element_name(node),
        Language::JavaScript | Language::TypeScript => is_js_ts_export_alias(node),
        _ => false,
    }
}

fn is_js_ts_export_alias(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    parent.kind() == "export_specifier"
        && parent
            .child_by_field_name("alias")
            .is_some_and(|alias| alias == node)
}

fn is_go_field_or_type_declaration_name(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        matches!(
            parent.kind(),
            "field_declaration" | "type_alias" | "type_spec"
        ) && node_is_field(parent, node, "name")
    })
}

fn is_csharp_tuple_element_name(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "tuple_element" && node_is_field(parent, node, "name")
    })
}

fn node_is_field(parent: Node<'_>, node: Node<'_>, field: &str) -> bool {
    (0..parent.child_count()).any(|index| {
        parent.child(index).is_some_and(|child| child == node)
            && parent.field_name_for_child(index as u32) == Some(field)
    })
}

fn is_semantic_token_identifier_node(language: Language, kind: &str) -> bool {
    if language == Language::None {
        return false;
    }
    if kind == "identifier" || kind.ends_with("_identifier") {
        return true;
    }
    match language {
        Language::Php => kind == "name",
        Language::Ruby => matches!(
            kind,
            "constant" | "instance_variable" | "class_variable" | "global_variable"
        ),
        _ => false,
    }
}

pub(crate) fn is_reference_candidate_node(language: Language, kind: &str) -> bool {
    if is_semantic_token_identifier_node(language, kind) {
        return true;
    }
    match language {
        Language::None => false,
        Language::Java | Language::Go | Language::Python | Language::Php | Language::Scala => false,
        Language::Cpp => matches!(kind, "operator_name" | "destructor_name" | "this"),
        Language::JavaScript | Language::TypeScript => matches!(kind, "this"),
        Language::Rust => matches!(kind, "self" | "super" | "crate"),
        Language::CSharp => matches!(kind, "this" | "base"),
        Language::Ruby => kind == "self",
    }
}

fn is_compound_reference_candidate(language: Language, kind: &str) -> bool {
    language == Language::Cpp && matches!(kind, "operator_name" | "destructor_name")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::ProjectFile;
    use crate::analyzer::usages::get_definition::parse_tree_for_language;

    fn reference_candidate_offsets(language: Language, path: &str, source: &str) -> Vec<usize> {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(&root, path);
        let tree = parse_tree_for_language(&file, language, source)
            .unwrap_or_else(|| panic!("failed to parse {language:?}"));
        let ReferenceCandidateRanges::Complete(ranges) =
            reference_candidate_ranges(tree.root_node(), language, 100)
        else {
            panic!("reference candidate budget exceeded for {language:?}");
        };
        ranges.into_iter().map(|range| range.start_byte).collect()
    }

    #[test]
    fn js_ts_reference_frontier_excludes_export_alias_but_semantic_frontier_keeps_it() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let cases = [
            (Language::JavaScript, "index.js"),
            (Language::TypeScript, "index.ts"),
        ];

        for (language, path) in cases {
            let source = "const value = 1; export { value as renamed };\n";
            let file = ProjectFile::new(&root, path);
            let tree = parse_tree_for_language(&file, language, source)
                .unwrap_or_else(|| panic!("failed to parse {language:?}"));
            let export_start = source.find("export").expect("export statement");
            let value_start = source[export_start..]
                .find("value")
                .map(|offset| export_start + offset)
                .expect("export value");
            let alias_start = source.find("renamed").expect("export alias");

            let ReferenceCandidateRanges::Complete(reference_ranges) =
                reference_candidate_ranges(tree.root_node(), language, 100)
            else {
                panic!("reference candidate budget exceeded for {language:?}");
            };
            assert!(
                reference_ranges
                    .iter()
                    .any(|range| range.start_byte == value_start),
                "export value must remain a reference candidate for {language:?}: {reference_ranges:?}"
            );
            assert!(
                reference_ranges
                    .iter()
                    .all(|range| range.start_byte != alias_start),
                "export alias must not be a reference candidate for {language:?}: {reference_ranges:?}"
            );

            let ReferenceCandidateRanges::Complete(semantic_ranges) =
                semantic_token_candidate_ranges(tree.root_node(), language, 100)
            else {
                panic!("semantic candidate budget exceeded for {language:?}");
            };
            assert!(
                semantic_ranges
                    .iter()
                    .any(|range| range.start_byte == value_start),
                "semantic tokens must retain the export value for {language:?}: {semantic_ranges:?}"
            );
            assert!(
                semantic_ranges
                    .iter()
                    .any(|range| range.start_byte == alias_start),
                "semantic tokens must retain the export alias for {language:?}: {semantic_ranges:?}"
            );
        }
    }

    #[test]
    fn go_reference_frontier_excludes_field_and_type_names_but_keeps_type_and_member_uses() {
        let source = r#"package sample

type Repository struct {
    Query Query
}
type Query struct{}
type Alias = Query

func use(repository Repository) Alias {
    return repository.Query
}
"#;
        let offsets = reference_candidate_offsets(Language::Go, "sample.go", source);
        let field_declaration = source.find("Query Query").expect("field declaration");
        let declarations = [
            source.find("Repository struct").expect("repository type"),
            field_declaration,
            source.find("Query struct").expect("query type"),
            source.find("Alias =").expect("type alias"),
        ];
        for declaration in declarations {
            assert!(
                !offsets.contains(&declaration),
                "Go declaration name at byte {declaration} must not enter the reference frontier: {offsets:?}"
            );
        }

        let references = [
            field_declaration + "Query ".len(),
            source.find("= Query").expect("alias target") + "= ".len(),
            source
                .find("repository Repository")
                .expect("parameter type")
                + "repository ".len(),
            source.rfind("Query").expect("member reference"),
        ];
        for reference in references {
            assert!(
                offsets.contains(&reference),
                "neighboring Go type/reference at byte {reference} must remain in the frontier: {offsets:?}"
            );
        }
    }

    #[test]
    fn csharp_reference_frontier_excludes_tuple_name_but_keeps_type_and_member_uses() {
        let source = r#"class StylesWriter {
    TableRegion? Read((TableRegion? TableRegion, int Count) value) {
        return value.TableRegion;
    }
}
"#;
        let offsets = reference_candidate_offsets(Language::CSharp, "StylesWriter.cs", source);
        let tuple = source
            .find("(TableRegion? TableRegion, int Count)")
            .expect("tuple declaration");
        let tuple_type = tuple + 1;
        let tuple_name = tuple_type + "TableRegion? ".len();
        let member_reference = source.rfind("TableRegion").expect("member reference");

        assert!(
            !offsets.contains(&tuple_name),
            "C# tuple element name must not enter the reference frontier: {offsets:?}"
        );
        for reference in [tuple_type, member_reference] {
            assert!(
                offsets.contains(&reference),
                "neighboring C# type/reference at byte {reference} must remain in the frontier: {offsets:?}"
            );
        }
    }
}
