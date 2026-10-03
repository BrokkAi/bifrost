//! The C++ answers behind `CppAdapter`.
//!
//! `LanguageAdapter` is analysis-owned, so the trait impl itself stays in
//! `analyzer/cpp/adapter.rs`; every answer it gives comes from here or from
//! [`crate::test_detection`] and [`crate::queries`].

use crate::declarations::{parse_cpp_readings, parse_cpp_readings_with_object_macro_fields};
use crate::graph::syntax::ObjectMacroReplacement;
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::cognitive_complexity;
use brokk_bifrost_core::analyzer::model::{Language, LanguageDialect};
use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
use brokk_bifrost_core::analyzer::tree_walk::ParentIndex;
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

/// Extract a source after seeding its object-like field-list environment from
/// include-visible declarations. The seed is consumed structurally by the
/// ordinary declaration walk; local definitions and undef directives retain
/// their source-order semantics.
pub fn parse_cpp_file_with_object_macro_fields(
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    object_macro_fields: HashMap<String, ObjectMacroReplacement>,
) -> ParsedFile {
    let root = tree.root_node();
    let ancestry = ParentIndex::new(root);
    parse_cpp_readings_with_object_macro_fields(
        file,
        source,
        root,
        &ancestry,
        &[LanguageDialect::for_path(Language::Cpp, file.rel_path())],
        object_macro_fields,
    )
    .pop()
    .expect("one dialect reading")
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
///
/// This entry point owns the whole tree's work, including the parent index the
/// walk asks its ancestor questions of.
pub fn parse_cpp_file_in_dialect(
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    dialect: LanguageDialect,
) -> ParsedFile {
    let root = tree.root_node();
    let ancestry = ParentIndex::new(root);
    parse_cpp_readings(file, source, root, &ancestry, &[dialect])
        .pop()
        .expect("one dialect reading")
}

/// Extract the primary dialect from a caller-owned tree and parent index.
pub fn parse_cpp_file_with_ancestry<'tree>(
    file: &ProjectFile,
    source: &str,
    root: Node<'tree>,
    ancestry: &ParentIndex<'tree>,
) -> ParsedFile {
    let dialect = LanguageDialect::for_path(Language::Cpp, file.rel_path());
    parse_cpp_readings(file, source, root, ancestry, &[dialect])
        .pop()
        .expect("one dialect reading")
}

/// Extract a header's C++ and C readings together. Both declaration policies
/// consume one primary event stream. Exact construction-ID finalization gives
/// each dialect stable content-owned source and structural projections. The C
/// reading is absent when the primary declaration walk proves identical tag scope.
pub fn parse_cpp_file_with_readings<'tree>(
    file: &ProjectFile,
    source: &str,
    root: Node<'tree>,
    ancestry: &ParentIndex<'tree>,
) -> (ParsedFile, Option<ParsedFile>) {
    let mut readings = parse_cpp_readings(
        file,
        source,
        root,
        ancestry,
        &[
            LanguageDialect::for_path(Language::Cpp, file.rel_path()),
            LanguageDialect::CppC,
        ],
    );
    let c = (readings.len() == 2).then(|| readings.pop().expect("C reading"));
    let primary = readings.pop().expect("primary reading");
    (primary, c)
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
        || left.resolution_facts != right.resolution_facts
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

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::resolution_facts::{ResolutionNameFact, ResolutionNameId};
    use tree_sitter::Parser;

    fn cpp_tree(source: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("C++ grammar");
        parser.parse(source, None).expect("C++ tree")
    }

    /// Everything one reading publishes, rendered so that two readings can be
    /// compared without depending on hash iteration order.
    fn published_facts(parsed: &ParsedFile) -> Vec<String> {
        let mut facts = vec![
            format!("package={}", parsed.package_name),
            format!("content_qualifier={}", parsed.content_qualifier),
            format!("top_level={:?}", parsed.top_level_declarations),
            format!("imports={:?}", parsed.imports),
            format!("materializations={:?}", parsed.materialization_records),
            format!("rust_usage_facts={:?}", parsed.rust_usage_facts),
        ];
        let mut unordered = |label: &str, mut entries: Vec<String>| {
            entries.sort();
            facts.push(format!("{label}={entries:?}"));
        };
        unordered(
            "declarations",
            parsed.declarations().iter().map(debug_of).collect(),
        );
        unordered(
            "definition_lookup",
            parsed
                .definition_lookup_units
                .iter()
                .map(debug_of)
                .collect(),
        );
        unordered(
            "type_identifiers",
            parsed.type_identifiers.iter().map(debug_of).collect(),
        );
        unordered(
            "type_aliases",
            parsed.type_aliases.iter().map(debug_of).collect(),
        );
        unordered(
            "scala_traits",
            parsed.scala_traits.iter().map(debug_of).collect(),
        );
        unordered(
            "test_region_units",
            parsed.test_region_units.iter().map(debug_of).collect(),
        );
        unordered(
            "navigation_truncated",
            parsed
                .navigation_ranges_truncated
                .iter()
                .map(debug_of)
                .collect(),
        );
        unordered("children", pairs(&parsed.children));
        unordered("ranges", pairs(&parsed.ranges));
        unordered("navigation_ranges", pairs(&parsed.navigation_ranges));
        unordered("signatures", pairs(&parsed.signatures));
        unordered("signature_metadata", pairs(&parsed.signature_metadata));
        unordered("raw_supertypes", pairs(&parsed.raw_supertypes));
        unordered(
            "supertype_lookup_paths",
            pairs(&parsed.supertype_lookup_paths),
        );
        unordered("scala_exports", pairs(&parsed.scala_exports));
        unordered(
            "cpp_template_metadata",
            pairs(&parsed.cpp_template_metadata),
        );
        unordered(
            "ruby_method_dispatch_modes",
            pairs(&parsed.ruby_method_dispatch_modes),
        );
        facts
    }

    fn debug_of<T: std::fmt::Debug>(value: T) -> String {
        format!("{value:?}")
    }

    fn pairs<K: std::fmt::Debug, V: std::fmt::Debug>(
        map: &brokk_bifrost_core::hash::HashMap<K, V>,
    ) -> Vec<String> {
        map.iter().map(|entry| format!("{entry:?}")).collect()
    }

    /// The two readings of one header, taken the way production takes them,
    /// publish exactly what two independent extractions publish.
    ///
    /// Milestone 3b of `.agents/plans/immutable-revision-persisted-fact-reuse.md`
    /// stopped the C reading from rebuilding the parent index, re-sweeping
    /// includes and identifiers, and re-running the quoted-include line scan
    /// that the C++ reading of the same tree had already produced. That is a
    /// deduplication and nothing else: if any published fact moved, something
    /// believed dialect-insensitive is not.
    ///
    /// The error-recovery shapes are the interesting half. Their walks reparse
    /// byte regions into trees of their own and re-own sibling nodes under
    /// recovered class scopes, so they are where a shared index would show up
    /// if sharing were unsound.
    #[test]
    fn a_shared_reading_publishes_what_an_independent_one_publishes() {
        let fixtures: &[(&str, &str, bool, bool)] = &[
            (
                "nested tag inside an aggregate, plus a nested include",
                r#"
#include <vector>
struct outer {
#include "member_list.def"
    struct inner { int v; } i;
};
struct inner *p;
                "#,
                true,
                true,
            ),
            (
                "a quoted include only the line scan can recover",
                r#"
#include "visible.h"
class Broken {
    void method(
#include "hidden.h"
                "#,
                false,
                false,
            ),
            (
                "forward declarations replaced by their definitions",
                r#"
typedef unsigned long long u64;
namespace generated {
struct tag0;
struct tag1;
struct tag1 {
    struct nested { int v; } n;
    u64 first;
};
struct tag0 { int second; };
}
                "#,
                true,
                true,
            ),
            (
                "a fragmented export-macro class body",
                r#"
#define SIMPLECPP_LIB
namespace simplecpp {
using TokenString = std::string;
struct Location { int line{}; };
class SIMPLECPP_LIB Token {
  TokenString prefix;
  void prefix_method() {}
 public:
  Token(const TokenString &s, const Location &loc, bool wsahead = false) :
      whitespaceahead(wsahead), location(loc), string(s)
      {
      flags();
  }
  struct Nested { int v; } nested;
  TokenString string;
  bool whitespaceahead;
  Location location;
 private:
  void flags() {
      whitespaceahead = true;
  }
};
}
                "#,
                true,
                true,
            ),
            (
                "nested struct, union, and enum tags",
                r#"
struct StructOwner { struct StructTag { int value; }; };
struct UnionOwner { union UnionTag { int value; }; };
struct EnumOwner { enum EnumTag { value }; };
"#,
                true,
                true,
            ),
            (
                "C++ class and anonymous tag near misses",
                r#"
struct Owner {
    class NestedClass { int value; };
    struct { int anonymous_value; } anonymous_member;
};
struct TopLevel { int value; };
"#,
                false,
                false,
            ),
            (
                "tag reparsed under a recovered export class",
                r#"
namespace api {

/**
* Doc comment
*/
class PROJECT_PUBLIC_API(2, 0) RecoveryOwner : public virtual BaseKey {
   public:
      /** Construct from a point. */
      RecoveryOwner(const Group& group, const Point& point) : BaseKey(group, point) {}

#if defined(PROJECT_HAS_LEGACY_POINT)
      /** Construct from a legacy point. */
      RecoveryOwner(const Group& group, const LegacyPoint& point) : BaseKey(group, point) {}
#endif

      struct RecoveredTag { int value; };
      std::string algo_name() const override;
      AlgorithmIdentifier algorithm_identifier() const override;
};
}
"#,
                true,
                true,
            ),
        ];

        for (name, source, expected_witness, expected_differs) in fixtures {
            let file = ProjectFile::new(
                std::env::current_dir().expect("test working directory must be available"),
                "src/widget.h",
            );
            let tree = cpp_tree(source);
            let root = tree.root_node();

            let independent_primary = parse_cpp_file(&file, source, &tree);
            let independent_c =
                parse_cpp_file_in_dialect(&file, source, &tree, LanguageDialect::CppC);
            let independent_primary_facts = published_facts(&independent_primary);
            let independent_c_facts = published_facts(&independent_c);
            let independent_differs = cpp_projections_differ(&independent_primary, &independent_c);
            assert_eq!(
                independent_differs,
                *expected_differs,
                "independent C/C++ projection difference for {name}; root.has_error()={}; CST={}; C++ declarations={:#?}; C declarations={:#?}; C++ facts: {independent_primary_facts:#?}; C facts: {independent_c_facts:#?}",
                root.has_error(),
                root.to_sexp(),
                independent_primary.declarations(),
                independent_c.declarations(),
            );

            let ancestry = ParentIndex::new(root);
            let (shared_primary, shared_c) =
                parse_cpp_file_with_readings(&file, source, root, &ancestry);
            let c_tag_scope_witness = shared_c.is_some();
            if *name == "tag reparsed under a recovered export class" {
                assert!(
                    root.has_error(),
                    "the recovery fixture must parse with errors"
                );
                let recovered_owner = independent_primary
                    .declarations()
                    .iter()
                    .find(|unit| unit.is_class() && unit.fq_name() == "api.RecoveryOwner")
                    .expect("the malformed export-class head must recover its owner");
                let owner_range = independent_primary
                    .ranges
                    .get(recovered_owner)
                    .and_then(|ranges| ranges.first())
                    .expect("the recovered owner must retain its class range");
                let mut pending = vec![root];
                let mut recognized_recovery = false;
                while let Some(node) = pending.pop() {
                    if crate::declarations::recovered_fragmented_class_has_body(
                        node,
                        source,
                        "RecoveryOwner",
                        owner_range,
                    ) {
                        recognized_recovery = true;
                        break;
                    }
                    let mut cursor = node.walk();
                    pending.extend(node.named_children(&mut cursor));
                }
                assert!(
                    recognized_recovery,
                    "the fixture must enter the fragmented export-class recovery path"
                );
                let mut pending = vec![root];
                let mut tag = None;
                while let Some(node) = pending.pop() {
                    if matches!(
                        node.kind(),
                        "struct_specifier" | "union_specifier" | "enum_specifier"
                    ) && node.child_by_field_name("name").is_some_and(|name| {
                        name.utf8_text(source.as_bytes())
                            .is_ok_and(|text| text == "RecoveredTag")
                    }) {
                        tag = Some(node);
                        break;
                    }
                    let mut cursor = node.walk();
                    pending.extend(node.named_children(&mut cursor));
                }
                let tag = tag.expect("the original recovered fixture exposes its tag node");
                let mut ancestor = ancestry.parent(tag);
                while let Some(node) = ancestor {
                    assert!(
                        !matches!(
                            node.kind(),
                            "class_specifier" | "struct_specifier" | "union_specifier"
                        ),
                        "the original CST must not already give RecoveredTag an aggregate owner"
                    );
                    ancestor = ancestry.parent(node);
                }
            }

            assert_eq!(
                c_tag_scope_witness,
                *expected_witness,
                "unexpected C tag-scope witness for {name}; root.has_error()={}; CST={}; C++ declarations={:#?}; C declarations={:#?}; independent C++ facts: {independent_primary_facts:#?}; independent C facts: {independent_c_facts:#?}",
                root.has_error(),
                root.to_sexp(),
                independent_primary.declarations(),
                independent_c.declarations(),
            );
            assert_eq!(
                independent_primary_facts,
                published_facts(&shared_primary),
                "C++ reading of {name}"
            );
            if *expected_witness {
                let shared_c = shared_c.expect("a witnessed C reading is emitted");
                assert_eq!(
                    independent_c_facts,
                    published_facts(&shared_c),
                    "C reading of {name}"
                );
            } else {
                assert_eq!(
                    independent_primary_facts, independent_c_facts,
                    "a false witness must imply identical complete readings for {name}"
                );
                assert!(
                    !independent_differs,
                    "a false witness must make the existing publication comparator agree for {name}"
                );
            }
        }
    }

    /// A tag nested in an aggregate is the whole reason the second reading
    /// exists, so the fixture above must actually produce two different
    /// readings; otherwise the comparison would pass on two empty answers.
    #[test]
    fn the_nested_tag_fixture_really_has_two_readings() {
        let source = "struct outer { struct inner { int v; } i; };\nstruct inner *p;\n";
        let file = ProjectFile::new(
            std::env::current_dir().expect("test working directory must be available"),
            "src/widget.h",
        );
        let tree = cpp_tree(source);
        let root = tree.root_node();
        let ancestry = ParentIndex::new(root);
        let (primary, c_reading) = parse_cpp_file_with_readings(&file, source, root, &ancestry);
        let c_reading = c_reading.expect("nested tag requires a C reading");
        assert!(
            cpp_projections_differ(&primary, &c_reading),
            "the C reading should mint `inner` at file scope: {:#?} vs {:#?}",
            primary.declarations(),
            c_reading.declarations()
        );
    }

    #[test]
    fn projection_difference_includes_resolution_facts() {
        let source = "struct Widget {};\n";
        let file = ProjectFile::new(
            std::env::current_dir().expect("test working directory must be available"),
            "src/widget.h",
        );
        let tree = cpp_tree(source);
        let primary = parse_cpp_file(&file, source, &tree);
        let mut fact_only_difference = primary.clone();
        assert!(!cpp_projections_differ(&primary, &fact_only_difference));

        fact_only_difference
            .resolution_facts
            .names
            .push(ResolutionNameFact {
                id: ResolutionNameId::new(0),
                spelling: "fact-only-difference".to_owned(),
            });
        assert!(cpp_projections_differ(&primary, &fact_only_difference));
    }

    /// Every `#include` is an include claim, wherever it is written. The
    /// declaration walk descends only through declaration scopes, so a
    /// directive inside a function body (llama.cpp's `sycl/info/aspects.def`
    /// inside a `switch`) or inside a class body (Eigen's
    /// `EIGEN_DENSEBASE_PLUGIN` in `DenseBase.h`) used to be invisible.
    ///
    /// The nested directive here is not a quoted include, so the established
    /// `recover_quoted_includes` line scan cannot supply it: only the preorder
    /// sweep over the tree can.
    #[test]
    fn includes_are_recorded_at_every_depth() {
        let source = r#"
#include <vector>

class Widget {
public:
    int value() const;
};

int run() {
    switch (0) {
#include <sycl/info/aspects.def>
    default:
        return 0;
    }
}
"#;
        let file = ProjectFile::new(
            std::env::current_dir().expect("test working directory must be available"),
            "src/widget.cpp",
        );
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("C++ grammar");
        let tree = parser.parse(source, None).expect("C++ tree");

        let parsed = parse_cpp_file(&file, source, &tree);
        let includes = parsed
            .imports
            .iter()
            .map(|import| import.raw_snippet.clone())
            .collect::<Vec<_>>();

        assert_eq!(
            includes,
            vec![
                "#include <vector>".to_string(),
                "#include <sycl/info/aspects.def>".to_string(),
            ]
        );
        assert!(!parsed.declarations().is_empty());
    }
}
