//! The C++ answers behind `CppAdapter`.
//!
//! `LanguageAdapter` is analysis-owned, so the trait impl itself stays in
//! `analyzer/cpp/adapter.rs`; every answer it gives comes from here or from
//! [`crate::test_detection`] and [`crate::queries`].

use crate::declarations::{
    CppVisitor, collect_cpp_identifiers, collect_cpp_includes, recover_quoted_includes,
};
use crate::graph::resolver::OrphanedNamespaceScopeIndex;
use crate::graph::syntax::ObjectMacroReplacement;
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::cognitive_complexity;
use brokk_bifrost_core::analyzer::model::{Language, LanguageDialect};
use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
use brokk_bifrost_core::analyzer::tree_walk::ParentIndex;
use brokk_bifrost_core::hash::{HashMap, HashSet};
use std::sync::LazyLock;
use tree_sitter::{Node, Tree};

/// A primary reading plus evidence for whether a C tag reading can differ.
/// The witness covers the complete visitor, including recovery.
#[derive(Debug)]
pub struct CppPrimaryReading {
    pub parsed: ParsedFile,
    pub c_tag_scope_witness: bool,
}

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
    let orphaned_namespaces = OrphanedNamespaceScopeIndex::build(root, source);
    parse_cpp_reading_with_object_macro_fields(
        file,
        source,
        root,
        LanguageDialect::for_path(Language::Cpp, file.rel_path()),
        &ancestry,
        object_macro_fields,
        &orphaned_namespaces,
    )
    .parsed
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
/// walk asks its ancestor questions of. A caller that wants both readings of
/// one tree must use [`parse_cpp_file_with_ancestry`] and
/// [`parse_cpp_c_reading`] instead, which share that index.
pub fn parse_cpp_file_in_dialect(
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    dialect: LanguageDialect,
) -> ParsedFile {
    let root = tree.root_node();
    let ancestry = ParentIndex::new(root);
    let orphaned_namespaces = OrphanedNamespaceScopeIndex::build(root, source);
    parse_cpp_reading(file, source, root, dialect, &ancestry, &orphaned_namespaces).parsed
}

/// Extract `file` under the dialect its own path selects, asking its ancestor
/// questions of a caller-owned index over the same tree.
///
/// The index costs one hash entry per node and is a property of the tree, not
/// of the reading, so a header that gets both readings builds it once. See
/// [`parse_cpp_c_reading`] for the second reading.
pub fn parse_cpp_file_with_ancestry<'tree>(
    file: &ProjectFile,
    source: &str,
    root: Node<'tree>,
    ancestry: &ParentIndex<'tree>,
) -> ParsedFile {
    let orphaned_namespaces = OrphanedNamespaceScopeIndex::build(root, source);
    parse_cpp_file_with_ancestry_and_orphaned_namespaces(
        file,
        source,
        root,
        ancestry,
        &orphaned_namespaces,
    )
    .parsed
}

/// Extract the primary reading and its C tag-scope execution witness using
/// caller-owned recovery state.
///
/// The recovery index is a property of the tree and source, rather than of a
/// dialect reading. Callers that need both the C++ and C readings should build
/// it once and pass it to this function and
/// [`parse_cpp_c_reading_with_orphaned_namespaces`]. The witness remains
/// sticky across the root walk, all recovery work, and every queued reparse.
pub fn parse_cpp_file_with_ancestry_and_orphaned_namespaces<'tree>(
    file: &ProjectFile,
    source: &str,
    root: Node<'tree>,
    ancestry: &ParentIndex<'tree>,
    orphaned_namespaces: &OrphanedNamespaceScopeIndex,
) -> CppPrimaryReading {
    parse_cpp_reading(
        file,
        source,
        root,
        LanguageDialect::for_path(Language::Cpp, file.rel_path()),
        ancestry,
        orphaned_namespaces,
    )
}

/// The C reading of a tree whose other reading is already in hand.
///
/// The dialect decides exactly one thing: where a struct/union/enum tag
/// declared inside another aggregate's member list is declared (the
/// `c_tag_semantics` readers in [`crate::declarations`]). Everything else this
/// file's extraction produces is a property of the tree and of the source text
/// -- the parent index, the `#include` sweep, the identifier sweep, and the
/// quoted-include line recovery -- so the C reading takes those from `primary`
/// rather than recomputing them over the same bytes. A debug build re-runs the
/// sweeps and asserts they agree, which is what holds the claim honest if a
/// future walk ever starts contributing to one of those families.
pub fn parse_cpp_c_reading<'tree>(
    file: &ProjectFile,
    source: &str,
    root: Node<'tree>,
    ancestry: &ParentIndex<'tree>,
    primary: &ParsedFile,
) -> ParsedFile {
    let orphaned_namespaces = OrphanedNamespaceScopeIndex::build(root, source);
    parse_cpp_c_reading_with_orphaned_namespaces(
        file,
        source,
        root,
        ancestry,
        primary,
        &orphaned_namespaces,
    )
}

/// Extract the C reading while reusing the primary reading's recovery index.
///
/// The declaration walk remains separate because C tag scope changes the
/// identity and ownership of declarations. Only recovery state proven to be
/// dialect-independent is shared.
pub fn parse_cpp_c_reading_with_orphaned_namespaces<'tree>(
    file: &ProjectFile,
    source: &str,
    root: Node<'tree>,
    ancestry: &ParentIndex<'tree>,
    primary: &ParsedFile,
    orphaned_namespaces: &OrphanedNamespaceScopeIndex,
) -> ParsedFile {
    let mut parsed = ParsedFile::new(String::new());
    parsed.imports = primary.imports.clone();
    parsed.type_identifiers = primary.type_identifiers.clone();
    {
        let mut visitor = CppVisitor {
            file,
            source,
            parsed: &mut parsed,
            c_tag_semantics: true,
            c_tag_scope_witness: false,
            recovered_class_sibling_scopes: HashMap::default(),
            consumed_fragment_regions: Vec::new(),
            orphaned_namespaces,
            partitioned_regions: Vec::new(),
            namespace_forward_scans: HashMap::default(),
            field_owners: None,
            recovery_captures: Vec::new(),
            object_macro_fields: HashMap::default(),
            ambiguous_object_macro_fields: HashSet::default(),
        };
        visitor.visit_container(root, ancestry, "", None, None, None, Vec::new());
    }
    parsed.finalize_deferred_replacements();

    #[cfg(debug_assertions)]
    {
        let mut recomputed = ParsedFile::new(String::new());
        collect_cpp_includes(root, source, &mut recomputed);
        collect_cpp_identifiers(root, source, &mut recomputed.type_identifiers);
        recover_quoted_includes(source, &mut recomputed);
        assert_eq!(
            parsed.imports, recomputed.imports,
            "the C reading's includes are the C++ reading's includes: {:?}",
            file
        );
        assert_eq!(
            parsed.type_identifiers, recomputed.type_identifiers,
            "the C reading's identifiers are the C++ reading's identifiers: {:?}",
            file
        );
    }

    parsed
}

/// One complete reading of `root`, sweeps included.
fn parse_cpp_reading<'tree>(
    file: &ProjectFile,
    source: &str,
    root: Node<'tree>,
    dialect: LanguageDialect,
    ancestry: &ParentIndex<'tree>,
    orphaned_namespaces: &OrphanedNamespaceScopeIndex,
) -> CppPrimaryReading {
    parse_cpp_reading_with_object_macro_fields(
        file,
        source,
        root,
        dialect,
        ancestry,
        HashMap::default(),
        orphaned_namespaces,
    )
}

fn parse_cpp_reading_with_object_macro_fields<'tree>(
    file: &ProjectFile,
    source: &str,
    root: Node<'tree>,
    dialect: LanguageDialect,
    ancestry: &ParentIndex<'tree>,
    object_macro_fields: HashMap<String, ObjectMacroReplacement>,
    orphaned_namespaces: &OrphanedNamespaceScopeIndex,
) -> CppPrimaryReading {
    let mut parsed = ParsedFile::new(String::new());

    collect_cpp_includes(root, source, &mut parsed);
    collect_cpp_identifiers(root, source, &mut parsed.type_identifiers);

    let c_tag_scope_witness;
    {
        let mut visitor = CppVisitor {
            file,
            source,
            parsed: &mut parsed,
            c_tag_semantics: dialect == LanguageDialect::CppC,
            c_tag_scope_witness: false,
            recovered_class_sibling_scopes: HashMap::default(),
            consumed_fragment_regions: Vec::new(),
            orphaned_namespaces,
            partitioned_regions: Vec::new(),
            namespace_forward_scans: HashMap::default(),
            field_owners: None,
            recovery_captures: Vec::new(),
            object_macro_fields,
            ambiguous_object_macro_fields: HashSet::default(),
        };
        visitor.visit_container(root, ancestry, "", None, None, None, Vec::new());
        c_tag_scope_witness = visitor.c_tag_scope_witness;
    }
    // A line scan over the source rather than a tree walk: it recovers the
    // quoted directives a parse error hid from the tree, skipping any snippet
    // the sweep above already recorded.
    recover_quoted_includes(source, &mut parsed);
    parsed.finalize_deferred_replacements();
    CppPrimaryReading {
        parsed,
        c_tag_scope_witness,
    }
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

#[cfg(test)]
mod tests {
    use super::*;
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
            let orphaned_namespaces = OrphanedNamespaceScopeIndex::build(root, source);
            let primary = parse_cpp_file_with_ancestry_and_orphaned_namespaces(
                &file,
                source,
                root,
                &ancestry,
                &orphaned_namespaces,
            );
            let c_tag_scope_witness = primary.c_tag_scope_witness;
            let shared_primary = primary.parsed;

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
                let shared_c = parse_cpp_c_reading_with_orphaned_namespaces(
                    &file,
                    source,
                    root,
                    &ancestry,
                    &shared_primary,
                    &orphaned_namespaces,
                );
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
        let primary = parse_cpp_file_with_ancestry(&file, source, root, &ancestry);
        let c_reading = parse_cpp_c_reading(&file, source, root, &ancestry, &primary);
        assert!(
            cpp_projections_differ(&primary, &c_reading),
            "the C reading should mint `inner` at file scope: {:#?} vs {:#?}",
            primary.declarations(),
            c_reading.declarations()
        );
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
