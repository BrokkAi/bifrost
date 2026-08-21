//! The C++ answers behind `CppAdapter`.
//!
//! `LanguageAdapter` is analysis-owned, so the trait impl itself stays in
//! `analyzer/cpp/adapter.rs`; every answer it gives comes from here or from
//! [`crate::test_detection`] and [`crate::queries`].

use crate::declarations::{CppVisitor, collect_cpp_identifiers, recover_quoted_includes};
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::cognitive_complexity;
use brokk_bifrost_core::analyzer::model::{Language, LanguageDialect};
use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
use brokk_bifrost_core::hash::HashMap;
use std::sync::LazyLock;
use tree_sitter::{Node, Tree};

/// The file extension `CppAdapter` reports. `Language::Cpp` also covers `.c`,
/// `.cc`, `.cxx` and the header spellings; this is only the canonical one.
pub const CPP_FILE_EXTENSION: &str = "cpp";

/// Tree-sitter node-kind mapping used by the cognitive-complexity scorer for
/// C++. Node names are from the tree-sitter-cpp grammar.
pub static CPP_COGNITIVE_CONFIG: LazyLock<cognitive_complexity::Config> =
    LazyLock::new(|| cognitive_complexity::Config {
        if_types: &["if_statement"],
        loop_types: &["for_statement", "while_statement", "do_statement"],
        catch_types: &["catch_clause"],
        conditional_types: &["conditional_expression"],
        case_types: &["case_statement"],
        binary_types: &["binary_expression"],
        logical_operators: &["&&", "||", "and", "or"],
        jump_types: &["break_statement", "continue_statement"],
        named_function_boundary_types: &["function_definition"],
        anonymous_function_types: &["lambda_expression"],
        else_clause_types: &["else_clause"],
        default_case_predicate: Some(cpp_is_default_case),
        ..cognitive_complexity::Config::empty()
    });

fn cpp_is_default_case(node: Node<'_>, _source: &str) -> bool {
    node.child_by_field_name("value").is_none()
}

/// Extract `file` under the dialect its own path selects.
pub fn parse_cpp_file(file: &ProjectFile, source: &str, tree: &Tree) -> ParsedFile {
    parse_cpp_file_in_dialect(
        file,
        source,
        tree,
        LanguageDialect::for_path(Language::Cpp, file.rel_path()),
    )
}

/// Extract `file` under an explicitly named dialect.
///
/// A header carries no compilation language of its own, so its blob has two
/// legitimate readings: under [`LanguageDialect::CppC`] a tag declared inside
/// an aggregate member list has file scope (C17 6.2.1), under the plain C++
/// dialect it is a nested class. Milestone 3 of
/// `.agents/plans/c-compilation-language-tag-scope.md` stores both readings of
/// a header when they differ, so extraction has to be reachable under a
/// dialect the path itself does not name.
pub fn parse_cpp_file_in_dialect(
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    dialect: LanguageDialect,
) -> ParsedFile {
    let mut parsed = ParsedFile::new(String::new());
    let root = tree.root_node();

    collect_cpp_identifiers(root, source, &mut parsed.type_identifiers);

    let mut visitor = CppVisitor {
        file,
        source,
        parsed: &mut parsed,
        c_tag_semantics: dialect == LanguageDialect::CppC,
        recovered_class_sibling_scopes: HashMap::default(),
        consumed_fragment_regions: Vec::new(),
    };
    visitor.visit_container(root, "", None, None, None, Vec::new());
    recover_quoted_includes(source, &mut parsed);
    parsed.finalize_deferred_replacements();

    parsed
}

/// Whether two readings of one blob disagree about any identity-bearing
/// output: which declarations exist, what they are named, which are top level
/// or definition-lookup entries, where they start and end, what they are
/// nested in, and how they are signed.
///
/// This is the "differs" test behind storing a header's C projection only when
/// it says something the C++ projection does not (issue #1970): absence of the
/// second row-set must unambiguously mean "identical", so anything a
/// resolution surface can observe has to be compared here.
pub fn cpp_projections_differ(left: &ParsedFile, right: &ParsedFile) -> bool {
    left.declarations() != right.declarations()
        || left.top_level_declarations != right.top_level_declarations
        || left.definition_lookup_units != right.definition_lookup_units
        || left.children != right.children
        || left.ranges != right.ranges
        || left.signatures != right.signatures
        || left.type_aliases != right.type_aliases
}

pub fn cpp_extract_call_receiver(reference: &str) -> Option<String> {
    let trimmed = reference.trim();
    let before_args = trimmed
        .split_once('(')
        .map(|(head, _)| head)
        .unwrap_or(trimmed);
    before_args
        .rsplit_once("::")
        .or_else(|| before_args.rsplit_once('.'))
        .map(|(receiver, _)| receiver.to_string())
}
