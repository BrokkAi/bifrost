use crate::analyzer::cpp::cpp_is_range_for_binding_name;
use crate::analyzer::{Language, Range};
use tree_sitter::Node;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferenceCandidateRanges {
    Complete(Vec<Range>),
    LimitExceeded { limit: usize, ranges: Vec<Range> },
}

/// Collect grammar-derived terminal nodes that may denote source references.
///
/// The traversal is iterative so deeply nested generated source cannot exhaust the
/// Rust stack. A zero limit is valid and reports overflow as soon as a candidate is
/// encountered.
pub fn reference_candidate_ranges(
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

/// Return whether a structured reference range must use a point lookup.
///
/// Some C++ names are composite grammar nodes that begin with the lexical
/// token `operator`. Definition lookup must receive a point inside that token,
/// while callers retain the complete structured range as the reference
/// identity.
pub fn reference_candidate_requires_point_lookup(
    root: Node<'_>,
    language: Language,
    range: &Range,
) -> bool {
    if language != Language::Cpp {
        return false;
    }
    let Some(mut node) = root.named_descendant_for_byte_range(range.start_byte, range.end_byte)
    else {
        return false;
    };
    loop {
        if matches!(
            node.kind(),
            "operator_name" | "operator_cast" | "literal_operator_name"
        ) {
            return true;
        }
        let Some(parent) = node.parent() else {
            return false;
        };
        if parent.start_byte() != range.start_byte || parent.end_byte() != range.end_byte {
            return false;
        }
        node = parent;
    }
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
pub fn semantic_token_candidate_ranges(
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

/// The raw tree-sitter identifier census: every identifier-class leaf token plus
/// the receiver keywords and compound callable names, with NO per-language
/// reference exclusions. This is the census-seeded FIRD probe frontier
/// (`--probe-seed census`): it is deliberately ignorant of the analyzer's
/// declaration index, so it proposes occurrences the index-filtered
/// [`reference_candidate_ranges`] frontier never surfaces. Comment and string
/// contents are excluded structurally, because they are not identifier-class
/// leaf nodes. Declaration and local-binding occurrences are recorded here and
/// filtered downstream by the engine (they are not usage probes). Tree-sitter
/// ERROR subtrees are excluded, because their identifiers are artifacts of
/// error recovery rather than source occurrences the engine can grade.
pub fn census_identifier_ranges(
    root: Node<'_>,
    language: Language,
    limit: usize,
) -> ReferenceCandidateRanges {
    collect_candidate_ranges(root, language, limit, CandidateFrontier::Census, &|| false)
        .expect("non-cancellable collection cannot be cancelled")
}

#[derive(Clone, Copy)]
enum CandidateFrontier {
    References,
    SemanticTokens,
    Census,
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
        // Tree-sitter error recovery destroys the enclosing declaration nodes,
        // so the identifiers it leaves behind describe the recovery, not the
        // source: a Flow class-property name recovers as a bare
        // `property_identifier` and a Flow type keyword recovers as an
        // object-pattern binding. The census grades what it proposes, so it
        // must stop at the ERROR subtree instead of grading misparse fallout.
        // The test is per-subtree, not per-file: a locally recoverable ERROR
        // leaves the rest of the file proposed. The index-filtered and
        // semantic-token frontiers keep their existing reach, because the LSP
        // still colors and resolves inside a broken edit.
        if matches!(frontier, CandidateFrontier::Census) && node.is_error() {
            continue;
        }
        let compound = matches!(
            frontier,
            CandidateFrontier::References | CandidateFrontier::Census
        ) && is_compound_reference_candidate(language, node.kind());
        let candidate = match frontier {
            CandidateFrontier::References => is_reference_candidate_node(language, node.kind()),
            CandidateFrontier::SemanticTokens => {
                is_semantic_token_identifier_node(language, node.kind())
            }
            // The census is the maximal grammar-only identifier frontier: the
            // identifier-class leaves the semantic-token frontier keeps, unioned
            // with the receiver keywords and compound callable names the
            // reference frontier adds. No index knowledge, no exclusions.
            CandidateFrontier::Census => {
                is_semantic_token_identifier_node(language, node.kind())
                    || is_reference_candidate_node(language, node.kind())
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
        Language::Cpp => cpp_is_range_for_binding_name(node),
        Language::Go => is_go_declaration_name(node),
        Language::CSharp => is_csharp_tuple_element_name(node),
        Language::Rust => is_rust_associated_type_declaration_name(node),
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

fn is_go_declaration_name(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        (matches!(
            parent.kind(),
            "field_declaration" | "type_alias" | "type_spec" | "import_spec" | "package_clause"
        ) && node_is_field(parent, node, "name"))
            || (parent.kind() == "package_clause"
                && matches!(node.kind(), "identifier" | "package_identifier"))
    })
}

fn is_csharp_tuple_element_name(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "tuple_element" && node_is_field(parent, node, "name")
    })
}

fn is_rust_associated_type_declaration_name(node: Node<'_>) -> bool {
    let Some(declaration) = node.parent() else {
        return false;
    };
    node_is_field(declaration, node, "name")
        && match declaration.kind() {
            "associated_type" => true,
            "type_item" => rust_type_item_is_associated(declaration),
            _ => false,
        }
}

fn rust_type_item_is_associated(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        match parent.kind() {
            "impl_item" | "trait_item" => return true,
            "function_item" | "mod_item" | "source_file" => return false,
            _ => node = parent,
        }
    }
    false
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

pub fn is_reference_candidate_node(language: Language, kind: &str) -> bool {
    if is_semantic_token_identifier_node(language, kind) {
        return true;
    }
    match language {
        Language::None => false,
        Language::Java
        | Language::Go
        | Language::Python
        | Language::Php
        | Language::Scala
        | Language::Kotlin => false,
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

    fn census_ranges(language: Language, path: &str, source: &str) -> Vec<Range> {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(&root, path);
        let tree = parse_tree_for_language(&file, language, source)
            .unwrap_or_else(|| panic!("failed to parse {language:?}"));
        let ReferenceCandidateRanges::Complete(ranges) =
            census_identifier_ranges(tree.root_node(), language, 1000)
        else {
            panic!("census budget exceeded for {language:?}");
        };
        ranges
    }

    fn census_offsets(language: Language, path: &str, source: &str) -> Vec<usize> {
        census_ranges(language, path, source)
            .into_iter()
            .map(|range| range.start_byte)
            .collect()
    }

    fn census_texts<'a>(language: Language, path: &str, source: &'a str) -> Vec<&'a str> {
        census_ranges(language, path, source)
            .into_iter()
            .map(|range| &source[range.start_byte..range.end_byte])
            .collect()
    }

    #[test]
    fn census_frontier_is_a_superset_of_the_reference_frontier() {
        // The census keeps identifier occurrences the index-filtered reference
        // frontier deliberately drops: the JS export alias and the Go field and
        // type declaration names. This is the whole point of census seeding -
        // it proposes sites the analyzer's own frontier never surfaces.
        let js = "const value = 1; export { value as renamed };\n";
        let js_census = census_offsets(Language::JavaScript, "index.js", js);
        let alias_start = js.find("renamed").expect("export alias");
        assert!(
            js_census.contains(&alias_start),
            "census must keep the JS export alias the reference frontier drops: {js_census:?}"
        );

        let go = "package sample\n\ntype Repository struct {\n    Query Query\n}\n";
        let go_census = census_offsets(Language::Go, "sample.go", go);
        let field_decl = go.find("Query Query").expect("field declaration");
        assert!(
            go_census.contains(&field_decl),
            "census must keep the Go field declaration name: {go_census:?}"
        );
        // And the census is a strict superset: every reference candidate is a
        // census candidate.
        let go_reference = reference_candidate_offsets(Language::Go, "sample.go", go);
        for offset in go_reference {
            assert!(
                go_census.contains(&offset),
                "census dropped a reference-frontier candidate at {offset}: {go_census:?}"
            );
        }
    }

    /// Tree-sitter error recovery destroys enclosing declaration nodes: a
    /// Flow-typed `.js` file parsed with the plain JavaScript grammar loses the
    /// whole class declaration into one ERROR node. The identifiers inside it
    /// are misparse fallout, not source references, so the census must not
    /// propose them (#1784): `registries` is a Flow class-property declaration
    /// name that forward resolution would chase through an import binder into
    /// another module, and `boolean` is a Flow type keyword that the JavaScript
    /// grammar mistakes for an object-pattern binding.
    #[test]
    fn census_skips_identifiers_inside_error_subtrees() {
        let source = concat!(
            "import {registries} from './registries.js';\n",
            "export default class Install {\n",
            "  registries: Array<RegistryNames>;\n",
            "  run(opts: {bailout: boolean}) {\n",
            "    return call(opts);\n",
            "  }\n",
            "}\n",
        );
        let offsets = census_offsets(Language::JavaScript, "install.js", source);
        let flow_property = source
            .find("registries: Array")
            .expect("flow class property");
        let flow_keyword = source.find("boolean").expect("misparsed flow type keyword");
        for excluded in [flow_property, flow_keyword] {
            assert!(
                !offsets.contains(&excluded),
                "identifier at byte {excluded} is inside an ERROR subtree and must not be proposed: {:?}",
                census_texts(Language::JavaScript, "install.js", source)
            );
        }

        // Recovery swallows everything from `export` through the closing brace
        // into a single ERROR node, so the import specifier is the only intact
        // identifier the file still has.
        let import_specifier = source.find("registries").expect("import specifier");
        assert_eq!(
            offsets,
            vec![import_specifier],
            "only the ERROR-free import specifier may be proposed: {:?}",
            census_texts(Language::JavaScript, "install.js", source)
        );
    }

    /// A locally recoverable ERROR must not disqualify the rest of the file.
    /// Here recovery consumes only `r:`; `P` recovers as a field definition and
    /// the method body parses cleanly, so every neighbor stays proposed.
    #[test]
    fn census_keeps_neighbors_of_a_locally_recoverable_error() {
        let source = concat!(
            "class W {\n",
            "  r: P;\n",
            "  m() { return call(x); }\n",
            "}\n",
            "function after() { return other(); }\n",
        );
        let offsets = census_offsets(Language::JavaScript, "widget.js", source);
        let annotation_name = source.find("r: P").expect("flow annotation name");
        assert!(
            !offsets.contains(&annotation_name),
            "the annotation name inside the ERROR subtree must not be proposed: {:?}",
            census_texts(Language::JavaScript, "widget.js", source)
        );

        let expected = vec![
            source.find('W').expect("class name"),
            source.find("P;").expect("recovered field definition"),
            source.find("m()").expect("method name"),
            source.find("call(x)").expect("call callee"),
            source.find("x)").expect("call argument"),
            source.find("after").expect("following function name"),
            source.find("other()").expect("following call callee"),
        ];
        assert_eq!(
            offsets,
            expected,
            "a local ERROR must leave the surrounding file proposed: {:?}",
            census_texts(Language::JavaScript, "widget.js", source)
        );
    }

    /// Tree-sitter MISSING nodes are zero-width fabricated tokens with no
    /// source text. They need no dedicated frontier rule: the grammars insert
    /// them as anonymous leaves that the named-child walk never visits, and the
    /// non-empty range guard would reject them regardless. An inserted token
    /// also does not contaminate its neighbors, so the real identifiers around
    /// it stay proposed. Here the JavaScript grammar inserts a MISSING `)`.
    #[test]
    fn census_ignores_missing_tokens_without_dropping_their_neighbors() {
        let source = concat!(
            "function f() { return call(x; }\n",
            "function after() { return other(); }\n",
        );
        let ranges = census_ranges(Language::JavaScript, "missing.js", source);
        assert!(
            ranges.iter().all(|range| range.start_byte < range.end_byte),
            "a zero-width fabricated token must never become a candidate: {ranges:?}"
        );

        let offsets: Vec<usize> = ranges.iter().map(|range| range.start_byte).collect();
        let expected = vec![
            source.find("f()").expect("function name"),
            source.find("call").expect("call callee"),
            source.find("x;").expect("call argument"),
            source.find("after").expect("following function name"),
            source.find("other").expect("following call callee"),
        ];
        assert_eq!(
            offsets,
            expected,
            "an inserted MISSING token must not disqualify its neighbors: {:?}",
            census_texts(Language::JavaScript, "missing.js", source)
        );
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
    fn cpp_reference_frontier_excludes_range_for_binders_but_keeps_range_and_body_uses() {
        let source = r#"void consume(int);

void check() {
    for (auto value : values) {
        consume(value);
    }
    for (auto* pointer : pointers) {
        consume(pointer);
    }
    for (auto& reference : references) {
        consume(reference);
    }
    for (const auto& const_reference : const_references) {
        consume(const_reference);
    }
    for (auto [key, mapped] : entries) {
        consume(key);
        consume(mapped);
    }
    for (auto array_value[bound] : array_values) {
        consume(array_value);
    }
    for (auto attributed [[gnu::annotate(attr)]] : attributed_values) {
        consume(attributed);
    }
    for (auto (__cdecl *callback)() : callbacks) {
        consume(callback);
    }
}
"#;
        let offsets = reference_candidate_offsets(Language::Cpp, "sample.cpp", source);
        let cases = [
            ("value", "values"),
            ("pointer", "pointers"),
            ("reference", "references"),
            ("const_reference", "const_references"),
        ];

        for (binding, range) in cases {
            let binding_start = source
                .find(&format!("{binding} :"))
                .expect("range-for binding");
            let range_start = source.find(range).expect("range-for range expression");
            let body_start = source
                .rfind(&format!("consume({binding});"))
                .expect("range-for body use")
                + "consume(".len();
            assert!(
                !offsets.contains(&binding_start),
                "C++ range-for binding at byte {binding_start} must not enter the reference frontier: {offsets:?}"
            );
            for reference in [range_start, body_start] {
                assert!(
                    offsets.contains(&reference),
                    "C++ range-for use at byte {reference} must remain in the reference frontier: {offsets:?}"
                );
            }
        }

        let key_binding = source.find("[key").expect("structured binding key") + 1;
        let mapped_binding = source.find(", mapped").expect("structured binding mapped") + 2;
        let key_body = source.rfind("key").expect("structured binding key use");
        let mapped_body = source
            .rfind("mapped")
            .expect("structured binding mapped use");
        let entries = source
            .find("entries")
            .expect("structured binding range expression");
        for binding in [key_binding, mapped_binding] {
            assert!(
                !offsets.contains(&binding),
                "C++ structured binding at byte {binding} must not enter the reference frontier: {offsets:?}"
            );
        }
        for reference in [entries, key_body, mapped_body] {
            assert!(
                offsets.contains(&reference),
                "C++ structured binding use at byte {reference} must remain in the reference frontier: {offsets:?}"
            );
        }

        for (binding, range) in [
            (
                source.find("array_value[").expect("array binding"),
                source.find("array_values").expect("array range"),
            ),
            (
                source.find("attributed [[").expect("attributed binding"),
                source.find("attributed_values").expect("attributed range"),
            ),
            (
                source
                    .find("callback)()")
                    .expect("function-pointer binding"),
                source.find("callbacks").expect("function-pointer range"),
            ),
        ] {
            assert!(
                !offsets.contains(&binding),
                "C++ wrapped range-for binding at byte {binding} must not enter the reference frontier: {offsets:?}"
            );
            assert!(
                offsets.contains(&range),
                "C++ wrapped range expression at byte {range} must remain in the reference frontier: {offsets:?}"
            );
        }

        for (reference, description) in [
            (source.find("bound").expect("array bound"), "array bound"),
            (
                source.find("annotate(attr)").expect("attribute argument") + "annotate(".len(),
                "attribute argument",
            ),
        ] {
            assert!(
                offsets.contains(&reference),
                "C++ {description} at byte {reference} must remain in the reference frontier: {offsets:?}"
            );
        }
    }

    #[test]
    fn go_reference_frontier_excludes_package_and_import_declaration_names() {
        let source = r#"package main

import alias "example.com/app/sub"
import _ "example.com/app/sidefx"
import . "example.com/app/dot"

func run() {
    alias.Helper()
    Helper()
}
"#;
        let offsets = reference_candidate_offsets(Language::Go, "main.go", source);
        let package_name = source.find("main").expect("package name");
        let alias_name = source.find("alias").expect("import alias");
        let blank_name = source.find("_ ").expect("blank import alias");
        let dot_name = source.find(". \"").expect("dot import alias");

        for declaration in [package_name, alias_name, blank_name, dot_name] {
            assert!(
                !offsets.contains(&declaration),
                "Go declaration name at byte {declaration} must not enter the reference frontier: {offsets:?}"
            );
        }

        let references = [
            source.rfind("alias").expect("alias qualifier in call"),
            source.rfind("Helper()").expect("dot-imported helper call"),
        ];
        for reference in references {
            assert!(
                offsets.contains(&reference),
                "Go reference at byte {reference} must remain in the frontier: {offsets:?}"
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

    #[test]
    fn rust_reference_frontier_excludes_associated_type_declaration_name_but_keeps_uses() {
        let source = r#"trait Service {
    type Item;

    fn make(&self) -> Self::Item;
}

impl Service for Worker {
    type Item = Output;

    fn make(&self) -> Self::Item {
        todo!()
    }
}
"#;
        let offsets = reference_candidate_offsets(Language::Rust, "lib.rs", source);
        let trait_decl = source.find("type Item;").expect("trait associated type");
        let impl_decl = source.find("type Item =").expect("impl associated type");
        let trait_use = source
            .find("Self::Item;")
            .expect("trait associated type use")
            + "Self::".len();
        let impl_use = source
            .rfind("Self::Item")
            .expect("impl associated type use")
            + "Self::".len();
        let impl_value = source.find("= Output").expect("impl value type") + "= ".len();

        for declaration in [trait_decl + "type ".len(), impl_decl + "type ".len()] {
            assert!(
                !offsets.contains(&declaration),
                "Rust associated type declaration name at byte {declaration} must not enter the reference frontier: {offsets:?}"
            );
        }

        for reference in [trait_use, impl_use, impl_value] {
            assert!(
                offsets.contains(&reference),
                "neighboring Rust associated type reference at byte {reference} must remain in the frontier: {offsets:?}"
            );
        }
    }
}
