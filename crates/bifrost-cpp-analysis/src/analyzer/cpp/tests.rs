//! C++'s analyzer-bound fixture suites, kept beside the analyzer they build.
//!
//! The production half -- `cpp_contains_tests`, `detect_cpp_test_assertion_smells`
//! and the four framework regex families -- moved to
//! [`brokk_bifrost_cpp::test_detection`]. What remains needs a real
//! `CppAnalyzer` over a temp workspace, so it cannot cross the crate line.

use crate::analyzer::cpp::*;

use brokk_bifrost_core::analyzer::model::CodeUnitType;

use brokk_bifrost_core::analyzer::definition_lookup::DefinitionLanguageScope;

use brokk_bifrost_core::analyzer::definition_lookup::RelationalBatchOutcome;

use brokk_bifrost_core::analyzer::definition_lookup::RelationalDefinitionQuery;

use brokk_bifrost_core::analyzer::definition_lookup::RelationalDefinitionRequest;

use brokk_bifrost_core::analyzer::definition_lookup::RelationalDefinitionValue;
use brokk_bifrost_test_macros::hardwon;
use std::collections::BTreeSet;

fn macro_composed_fields_fixture() -> (
    crate::inline_project::BuiltInlineTestProject,
    ProjectFile,
    CppAnalyzer,
) {
    let fixture = crate::inline_project::InlineTestProject::with_language(Language::Cpp)
        .file("fields.h", "#define OWNER_FIELDS int value;\n")
        .file(
            "owner.c",
            "#include \"fields.h\"\nstruct Owner { OWNER_FIELDS };\n",
        )
        .file(
            "unrelated.c",
            "#include \"unrelated_fields.h\"\nstruct Unrelated { UNRELATED_FIELDS };\n",
        )
        .file(
            "unrelated_fields.h",
            "#define UNRELATED_FIELDS int value;\n",
        )
        .build();
    let owner = fixture.file("owner.c");
    let analyzer = CppAnalyzer::from_project(fixture.project().clone());
    (fixture, owner, analyzer)
}

#[test]
#[hardwon("#3078: an incomplete type lookup was cached as an empty include boundary")]
fn cancelled_macro_composed_fields_does_not_poison_cache() {
    let (_fixture, owner, analyzer) = macro_composed_fields_fixture();
    let cancellation = brokk_bifrost_core::cancellation::CancellationToken::new();
    cancellation.cancel();

    {
        let _scope = AnalyzerQueryScope::with_cancellation(&analyzer, &cancellation);
        assert!(
            analyzer.macro_composed_fields(&owner).is_empty(),
            "a cancelled macro-field producer must return no partial fields"
        );
    }

    let definitions = analyzer.get_definitions("Owner.value");
    assert!(
        definitions
            .iter()
            .any(|unit| unit.is_field() && unit.fq_name() == "Owner.value"),
        "a cancelled producer must not cache an empty overlay: {definitions:?}"
    );
}

#[test]
#[hardwon("#3078: a nested cancelled type read lost incompleteness from the outer query")]
fn nested_cancelled_macro_composed_field_read_marks_outer_scope_incomplete() {
    let (_fixture, owner, analyzer) = macro_composed_fields_fixture();
    let owner_unit = analyzer
        .get_definitions("Owner")
        .into_iter()
        .find(CodeUnit::is_class)
        .expect("fixture owner class");
    let outer_scope = AnalyzerQueryScope::new(&analyzer);
    let cancellation = brokk_bifrost_core::cancellation::CancellationToken::new();
    cancellation.cancel();

    {
        let _inner_scope = AnalyzerQueryScope::with_cancellation(&analyzer, &cancellation);
        assert!(analyzer.macro_composed_fields(&owner).is_empty());
    }

    assert!(analyzer.active_query_cancellation().is_none());
    assert!(
        matches!(
            outer_scope.read_completion(),
            Err(brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadIncomplete::Cancelled)
        ),
        "an outer query must retain cancellation observed by a nested read"
    );
    let later_scope = AnalyzerQueryScope::new(&analyzer);
    assert!(
        matches!(
            later_scope.read_completion(),
            Err(brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadIncomplete::Cancelled)
        ),
        "a later scope sharing the request memos must inherit their incompleteness"
    );
    assert!(analyzer.get_direct_ancestors(&owner_unit).is_empty());
    assert!(
        analyzer.direct_ancestors.get(&owner_unit).is_none(),
        "an incomplete dependency must neither panic nor publish an ancestor cache entry"
    );
}

#[test]
fn macro_owner_queries_preserve_anchored_name_provenance() {
    use brokk_bifrost_core::analyzer::RelationalName;

    let parse = |name| {
        brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path_fq(
            Language::Cpp,
            name,
            brokk_bifrost_core::analyzer::fq_name::segment_interner(),
        )
    };
    let prefix = parse("mount");
    let expected_owner = RelationalName::new(prefix.clone(), parse("Owner"));
    for (name, query) in [
        (
            RelationalName::new(prefix, parse("Owner.value")),
            RelationalDefinitionQuery::ExactName,
        ),
        (
            expected_owner.clone(),
            RelationalDefinitionQuery::StructuralChildren,
        ),
    ] {
        let request = RelationalDefinitionRequest {
            ordinal: 0,
            language_scope: DefinitionLanguageScope::Language(Language::Cpp),
            name,
            query,
        };
        let owner = CppAnalyzer::macro_composed_field_owner_name(&request)
            .expect("a generated field query has an owner");
        assert_eq!(owner, expected_owner);
        assert_ne!(owner, RelationalName::stable(owner.full_name()));
    }
}

#[test]
#[hardwon(
    "bfd4320020de: generated-field range queries, bounded and unbounded, rebuilt unrelated C macro overlays"
)]
fn generated_field_range_queries_only_build_their_source_overlay() {
    let (_fixture, owner, analyzer) = macro_composed_fields_fixture();
    let field = analyzer
        .declarations(&owner)
        .into_iter()
        .find(|unit| unit.is_field() && unit.fq_name() == "Owner.value")
        .expect("owner macro field");

    analyzer.reset_macro_composed_fields_build_count_for_test();
    assert!(!analyzer.ranges(&field).is_empty());
    assert_eq!(
        analyzer.macro_composed_fields_build_count_for_test(),
        0,
        "ranges for a generated field must reuse the field's source overlay"
    );

    analyzer.reset_macro_composed_fields_build_count_for_test();
    let (ranges, total, complete) = analyzer.ranges_with_limit(
        &field,
        1,
        &brokk_bifrost_core::cancellation::CancellationToken::new(),
    );
    assert_eq!(ranges.len(), 1, "generated field range: {ranges:?}");
    assert_eq!(total, 1, "generated field range total: {ranges:?}");
    assert!(complete, "generated field range query: {ranges:?}");
    assert_eq!(
        analyzer.macro_composed_fields_build_count_for_test(),
        0,
        "limited ranges for a generated field must reuse its source overlay"
    );
}

#[test]
#[hardwon("bfd4320020de: file-scoped C identifier queries rebuilt the owning macro overlay")]
fn file_scoped_identifier_queries_only_build_the_requested_source_overlay() {
    let (_fixture, owner, analyzer) = macro_composed_fields_fixture();
    let field = analyzer
        .declarations(&owner)
        .into_iter()
        .find(|unit| unit.is_field() && unit.fq_name() == "Owner.value")
        .expect("owner macro field");
    let name = brokk_bifrost_core::analyzer::RelationalName::stable(
        brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path_fq(
            Language::Cpp,
            "value",
            brokk_bifrost_core::analyzer::fq_name::segment_interner(),
        ),
    );
    let request = RelationalDefinitionRequest {
        ordinal: 0,
        language_scope: DefinitionLanguageScope::Language(Language::Cpp),
        name,
        query: RelationalDefinitionQuery::Identifier {
            file: Some(owner.clone()),
        },
    };

    analyzer.reset_macro_composed_fields_build_count_for_test();
    let RelationalBatchOutcome::Complete(mut results) = analyzer.relational_definition_batch(
        &[request],
        &brokk_bifrost_core::cancellation::CancellationToken::new(),
    ) else {
        panic!("file-scoped identifier query must complete");
    };
    let RelationalDefinitionValue::Definitions(units) = results.remove(0).value else {
        panic!("identifier query returned the wrong result shape");
    };
    assert!(units.contains(&field), "generated field missing: {units:?}");
    assert_eq!(
        analyzer.macro_composed_fields_build_count_for_test(),
        0,
        "a file-scoped identifier query must reuse the requested source overlay"
    );
}

#[test]
#[hardwon(
    "bfd4320020de: workspace identifier queries dropped generated fields outside the first source overlay"
)]
fn workspace_identifier_queries_retain_generated_fields_from_all_overlays() {
    let (_fixture, _owner, analyzer) = macro_composed_fields_fixture();
    let name = brokk_bifrost_core::analyzer::RelationalName::stable(
        brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path_fq(
            Language::Cpp,
            "value",
            brokk_bifrost_core::analyzer::fq_name::segment_interner(),
        ),
    );
    let request = RelationalDefinitionRequest {
        ordinal: 0,
        language_scope: DefinitionLanguageScope::Language(Language::Cpp),
        name,
        query: RelationalDefinitionQuery::Identifier { file: None },
    };

    let RelationalBatchOutcome::Complete(mut results) = analyzer.relational_definition_batch(
        &[request],
        &brokk_bifrost_core::cancellation::CancellationToken::new(),
    ) else {
        panic!("workspace identifier query must complete");
    };
    let RelationalDefinitionValue::Definitions(units) = results.remove(0).value else {
        panic!("identifier query returned the wrong result shape");
    };
    assert!(
        units.iter().any(|unit| unit.fq_name() == "Owner.value"),
        "owner generated field missing: {units:?}"
    );
    assert!(
        units.iter().any(|unit| unit.fq_name() == "Unrelated.value"),
        "workspace-wide query must retain the unrelated generated field: {units:?}"
    );
    assert!(
        analyzer.macro_composed_fields_build_count_for_test() >= 2,
        "workspace-wide query should inspect both source overlays"
    );
}

#[test]
#[hardwon(
    "4d3fd0ce1133: a bare compatibility name triggered an owner-qualified macro-field overlay scan"
)]
fn bare_rendered_macro_lookup_does_not_build_field_overlays() {
    let (_fixture, _owner, analyzer) = macro_composed_fields_fixture();

    analyzer.reset_macro_composed_fields_build_count_for_test();
    let definitions = analyzer.get_definitions("OWNER_FIELDS");

    assert!(
        definitions
            .iter()
            .any(|unit| unit.identifier() == "OWNER_FIELDS"),
        "the source-spelling compatibility lookup must retain the macro: {definitions:?}"
    );
    assert_eq!(
        analyzer.macro_composed_fields_build_count_for_test(),
        0,
        "a bare rendered name cannot address an owner-qualified generated field"
    );

    analyzer.reset_macro_composed_fields_build_count_for_test();
    assert!(analyzer.get_definitions("MISSING_SYMBOL").is_empty());
    assert_eq!(
        analyzer.macro_composed_fields_build_count_for_test(),
        0,
        "a missing bare rendered name cannot address an owner-qualified generated field"
    );
}

#[test]
#[hardwon("847c70e0ee8c: bounded C++ definition lookup scanned unrelated macro-field overlays")]
fn exact_field_queries_only_build_the_requested_owner_overlay() {
    let (_fixture, _owner, analyzer) = macro_composed_fields_fixture();

    analyzer.reset_macro_composed_fields_build_count_for_test();
    let definitions = analyzer.get_definitions("Owner.value");
    assert_eq!(
        definitions.len(),
        1,
        "owner field definitions: {definitions:?}"
    );
    assert_eq!(definitions[0].fq_name(), "Owner.value");
    assert_eq!(
        analyzer.macro_composed_fields_build_count_for_test(),
        1,
        "an exact owner-qualified query must not inspect unrelated source overlays"
    );
}

#[test]
#[hardwon(
    "#3035: usage-catalog enumeration built macro overlays for fields its graph filter discarded"
)]
fn workspace_usage_inventory_does_not_build_filtered_macro_field_overlays() {
    let (_fixture, _owner, analyzer) = macro_composed_fields_fixture();
    analyzer.reset_macro_composed_fields_build_count_for_test();

    let declarations = analyzer
        .workspace_declarations_with_primary_ranges(
            &brokk_bifrost_core::cancellation::CancellationToken::new(),
        )
        .expect("uncancelled declaration inventory");

    assert!(
        declarations.iter().any(|(unit, _)| unit.is_class()),
        "the persisted C++ declaration inventory must remain available"
    );
    assert!(
        declarations.iter().all(|(unit, _)| !unit.is_field()),
        "macro-composed fields are not usage-graph declarations"
    );
    assert_eq!(
        analyzer.macro_composed_fields_build_count_for_test(),
        0,
        "a catalog inventory must not build overlays that its graph filter discards"
    );
}

#[test]
#[hardwon(
    "8f407bc939e1: an inline constructor re-entered class reconciliation without signature metadata"
)]
fn reconciliation_does_not_reenter_for_inline_constructor_without_metadata() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    ProjectFile::new(root.clone(), "temp_dir.cpp")
        .write(
            r#"class TempDir {
public:
    TempDir() {}
};
"#,
        )
        .expect("write constructor fixture");
    let analyzer = CppAnalyzer::from_project(
        brokk_bifrost_core::analyzer::project::TestProject::new(root, Language::Cpp),
    );

    let definitions = analyzer.get_definitions("TempDir");
    assert!(
        definitions
            .iter()
            .any(|unit| unit.is_class() && unit.fq_name() == "TempDir"),
        "the class lookup must complete without constructor reconciliation re-entry: {definitions:#?}"
    );
}

#[test]
#[hardwon("4c36b5b86e83: partial-specialization metadata leaked into an ordinary nested class")]
fn class_template_metadata_does_not_leak_into_ordinary_nested_classes() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let file = ProjectFile::new(root.clone(), "nested.h");
    file.write(
        r#"namespace metadata_scope {
template <typename T> class envelope {
 public:
  class nested { public: int pick() const; };
};
}
"#,
    )
    .expect("write nested template fixture");
    let analyzer = CppAnalyzer::from_project(
        brokk_bifrost_core::analyzer::project::TestProject::new(root, Language::Cpp),
    );
    let declarations = analyzer.get_all_declarations();
    let envelope = declarations
        .iter()
        .find(|unit| {
            unit.kind() == CodeUnitType::Class && unit.fq_name() == "metadata_scope.envelope"
        })
        .expect("outer class template");
    let nested = declarations
        .iter()
        .find(|unit| {
            unit.kind() == CodeUnitType::Class
                && unit.identifier() == "nested"
                && analyzer.parent_of(unit).as_ref() == Some(envelope)
        })
        .expect("ordinary nested class");

    assert!(analyzer.template_metadata(envelope).is_some());
    assert!(analyzer.template_metadata(nested).is_none());
}

#[test]
#[hardwon("#1707: C++ navigation hydrated full FileState values for persisted import rows")]
fn cpp_import_lines_use_persisted_projection() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let files: Vec<_> = (0..129)
        .map(|index| {
            let file = ProjectFile::new(root.clone(), format!("unit{index}.hpp"));
            file.write("#include \"shared.hpp\"\nstruct Value {};\n")
                .expect("write header");
            file
        })
        .collect();
    ProjectFile::new(root.clone(), "shared.hpp")
        .write("struct Shared {};\n")
        .expect("write shared header");
    let analyzer = CppAnalyzer::from_project(
        brokk_bifrost_core::analyzer::project::TestProject::new(root, Language::Cpp),
    );

    analyzer.reset_full_hydration_count_for_test();
    for file in &files {
        assert_eq!(
            IAnalyzer::import_statements(&analyzer, file),
            vec!["#include \"shared.hpp\""],
        );
        assert_eq!(
            CppWorkspaceSource::import_statements(&analyzer, file),
            vec!["#include \"shared.hpp\""],
        );
    }
    assert_eq!(
        analyzer.full_hydration_count_for_test(),
        0,
        "persisted C++ import rows must not hydrate FileState values"
    );
}

#[test]
#[hardwon("#1524: recovered exported-class bodies swallowed following sibling declarations")]
fn exported_class_body_does_not_swallow_sibling_classes_1524() {
    // Issue #1524: the exported-class recovery for `class MACRO Name { ... }`
    // mis-nested every following namespace-scope sibling class when the body
    // contained a private/protected-section method with a declaration-init
    // braced for-loop: tree-sitter's bogus `function_definition` body runs
    // past the class's true closing `};`, and the recovery re-owned the
    // swallowed tail as members.
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let file = ProjectFile::new(root.clone(), "t.h");
    file.write(
        r#"namespace v8 {
namespace internal {
class V8_EXPORT_PRIVATE FreeListManyCached : public FreeListMany {
 public:
  FreeListManyCached();

 protected:
 private:
  void ResetCache() {
    for (int i = 0; i < 3; i++) {
    }
  }
};

class FreeListManyCachedFastPathForNewSpace {};
}  // namespace internal
}  // namespace v8
"#,
    )
    .expect("write fixture");
    let analyzer = CppAnalyzer::from_project(
        brokk_bifrost_core::analyzer::project::TestProject::new(root, Language::Cpp),
    );
    let declarations = analyzer.get_all_declarations();
    let sibling = declarations
        .iter()
        .find(|unit| {
            unit.kind() == CodeUnitType::Class
                && unit.identifier() == "FreeListManyCachedFastPathForNewSpace"
        })
        .expect("sibling class indexed");
    assert_eq!(
        sibling.fq_name(),
        "v8::internal.FreeListManyCachedFastPathForNewSpace",
        "sibling class must stay at namespace scope, not nest under the exported class"
    );
    let member = declarations
        .iter()
        .find(|unit| unit.kind() == CodeUnitType::Function && unit.identifier() == "ResetCache")
        .expect("member method indexed");
    assert_eq!(
        member.fq_name(),
        "v8::internal.FreeListManyCached.ResetCache",
        "the for-loop method belongs to the exported class"
    );
}

#[cfg(test)]
#[test]
#[hardwon(
    "#1566: C++ reconciliation performed include-closure work for unrelated same-named members"
)]
fn reconcile_skips_same_named_members_of_unrelated_classes_1566() {
    // Issue #1566: #1134 reconciliation probed every same-named member in the
    // repo and built the include-visible class table of each candidate's file
    // -- on whale repos a gtest-shaped member name (SetUp) matches 10k+ units
    // and each unrelated class's file pays a full include-closure BFS. Only a
    // candidate whose terminal owner segment can re-key onto the queried name
    // may reach the class-table build; an identical member name in an
    // unrelated class must be skipped before that work runs.
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    ProjectFile::new(root.clone(), "nested.h")
        .write(
            r#"namespace log4cxx {
class Outer {
 public:
  class Inner { public: int method() const; };
};
}
"#,
        )
        .expect("write header");
    ProjectFile::new(root.clone(), "impl.cpp")
        .write(
            r#"#include "nested.h"
using namespace log4cxx;
int Outer::Inner::method() const { return 2; }
"#,
        )
        .expect("write impl");
    ProjectFile::new(root.clone(), "decoy.h")
        .write(
            r#"namespace log4cxx {
class DecoyOuter {
 public:
  class DecoyInner { public: int method() const; };
};
}
"#,
        )
        .expect("write decoy header");
    ProjectFile::new(root.clone(), "decoy.cpp")
        .write(
            r#"#include "decoy.h"
using namespace log4cxx;
int DecoyOuter::DecoyInner::method() const { return 3; }
"#,
        )
        .expect("write decoy impl");
    let analyzer = CppAnalyzer::from_project(
        brokk_bifrost_core::analyzer::project::TestProject::new(root, Language::Cpp),
    );

    analyzer.reset_visible_type_units_build_count_for_test();
    analyzer.reset_reconcile_counts_for_test();
    let definitions: Vec<_> = analyzer.definitions("log4cxx.Outer$Inner.method").collect();

    assert!(
        definitions
            .iter()
            .any(|unit| unit.source().rel_path() == std::path::Path::new("impl.cpp")),
        "the out-of-line definition must still reconcile onto the canonical name: {definitions:?}"
    );
    assert_eq!(
        analyzer.visible_type_units_build_count_for_test(),
        1,
        "the owner-bounded query may build only the matching candidate's class table"
    );
    assert_eq!(
        analyzer.reconcile_stored_signature_metadata_count_for_test(),
        analyzer.reconcile_candidate_evaluation_count_for_test(),
        "every reconcile candidate must read raw stored signature facts instead of the overlay-aware metadata surface"
    );

    let parsed = |name: &str| {
        brokk_bifrost_core::analyzer::RelationalName::stable(
            brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path_fq(
                Language::Cpp,
                name,
                brokk_bifrost_core::analyzer::fq_name::segment_interner(),
            ),
        )
    };
    let member_name = "log4cxx.Outer$Inner.method";
    let owner_name = "log4cxx.Outer$Inner";
    let requests = [
        (parsed(member_name), RelationalDefinitionQuery::ExactName),
        (
            parsed(member_name),
            RelationalDefinitionQuery::NormalizedName,
        ),
        (
            parsed(owner_name),
            RelationalDefinitionQuery::StructuralChildren,
        ),
        (
            parsed(owner_name),
            RelationalDefinitionQuery::StructuralMembers {
                identifier: "method".to_string(),
            },
        ),
        (
            parsed(owner_name),
            RelationalDefinitionQuery::VisibleMembers {
                identifier: "method".to_string(),
            },
        ),
        (
            parsed("method"),
            RelationalDefinitionQuery::Identifier { file: None },
        ),
        (
            parsed(member_name),
            RelationalDefinitionQuery::CallableFacts,
        ),
    ]
    .into_iter()
    .enumerate()
    .map(|(ordinal, (name, query))| RelationalDefinitionRequest {
        ordinal,
        language_scope: DefinitionLanguageScope::Language(Language::Cpp),
        name,
        query,
    })
    .collect::<Vec<_>>();
    let RelationalBatchOutcome::Complete(results) = analyzer.relational_definition_batch(
        &requests,
        &brokk_bifrost_core::cancellation::CancellationToken::new(),
    ) else {
        panic!("the cross-shape relational reconciliation batch must complete");
    };
    for result in results {
        let declarations = match result.value {
            RelationalDefinitionValue::Definitions(units) => units,
            RelationalDefinitionValue::CallableFacts(facts) => {
                facts.into_iter().map(|fact| fact.declaration).collect()
            }
            RelationalDefinitionValue::PackageRelation(_) => {
                panic!("the reconciliation batch contains no package queries")
            }
        };
        assert!(
            declarations.iter().any(|unit| {
                unit.fq_name() == member_name
                    && unit.source().rel_path() == std::path::Path::new("impl.cpp")
            }),
            "query ordinal {} must include the reconciled out-of-line definition: {declarations:?}",
            result.ordinal
        );
    }
}

/// #3520: a nested terminal type's canonical `$` identity is a first-class
/// `definitions` question. Extraction always indexed these declarations
/// (`Top$Only`, `ns.Outer$Inner`); the exact-name *request* was the defect,
/// because the shared client-path splitter takes `$` as segment text, so the
/// owner/terminal boundary it asked the store for was `""` + `Top$Only`
/// instead of the persisted `Top` + `Only`. The owner, member and literal-`$`
/// control lookups around it already worked and must keep working.
#[test]
#[hardwon("#3520: exact-name lookup missed nested terminal C++ type identities")]
fn definitions_reach_nested_terminal_types_by_exact_name() {
    let fixture = crate::inline_project::InlineTestProject::with_language(Language::Cpp)
        .file(
            "nested.cpp",
            "struct Top { struct Only { int b; }; };\n\
             namespace ns { struct Outer { struct Inner { int a; }; }; }\n\
             struct Dollar { int foo$bar; };\n\
             struct Buck$Stop { int c; };\n",
        )
        .build();
    let analyzer = CppAnalyzer::from_project(fixture.project().clone());

    let defined = |name: &str| {
        let mut names: Vec<String> = analyzer
            .definitions(name)
            .map(|unit| unit.fq_name())
            .collect();
        names.sort();
        names
    };

    // The defect: the nested terminal type's own canonical identity.
    assert_eq!(defined("Top$Only"), ["Top$Only"]);
    assert_eq!(defined("ns.Outer$Inner"), ["ns.Outer$Inner"]);
    // Controls: owners and members, already working before the fix.
    assert_eq!(defined("Top"), ["Top"]);
    assert_eq!(defined("ns.Outer"), ["ns.Outer"]);
    assert_eq!(defined("Top$Only.b"), ["Top$Only.b"]);
    assert_eq!(defined("ns.Outer$Inner.a"), ["ns.Outer$Inner.a"]);
    // A `$` inside a source identifier is not a nesting join (#2140). The
    // identifier fallback has to keep answering both the member and the type.
    assert_eq!(defined("Dollar.foo$bar"), ["Dollar.foo$bar"]);
    assert_eq!(defined("Buck$Stop"), ["Buck$Stop"]);

    // The multi-language lookup route asks through the language provider's
    // rendered-name construction rather than its own splitter.
    let lookup =
        brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::AnalyzerDefinitionLookup::new(
            &analyzer,
            Language::Cpp,
        );
    let lookup_defined = |name: &str| {
        let mut names: Vec<String> = lookup
            .fqn(name)
            .into_iter()
            .map(|unit| unit.fq_name())
            .collect();
        names.sort();
        names
    };
    assert_eq!(lookup_defined("Top$Only"), ["Top$Only"]);
    assert_eq!(lookup_defined("ns.Outer$Inner"), ["ns.Outer$Inner"]);
    assert_eq!(lookup_defined("Dollar.foo$bar"), ["Dollar.foo$bar"]);
    assert_eq!(lookup_defined("Buck$Stop"), ["Buck$Stop"]);

    // #3631: the source spelling uses `::`. The canonical `$` query above
    // already answered; this one used to come back empty.
    assert_eq!(defined("Top::Only"), ["Top$Only"]);
    assert_eq!(defined("ns::Outer::Inner"), ["ns.Outer$Inner"]);
    assert_eq!(defined("Top::Only::b"), ["Top$Only.b"]);
    assert_eq!(defined("ns::Outer::Inner::a"), ["ns.Outer$Inner.a"]);

    // The lookup route and both batched prefetches answer the `::` spelling
    // with the same persisted rows. Each prefetch runs on a fresh lookup, so
    // the point ask afterwards reads what that prefetch memoized.
    assert_eq!(lookup_defined("Top::Only"), ["Top$Only"]);
    let names = |units: Vec<CodeUnit>| {
        let mut names: Vec<String> = units.into_iter().map(|unit| unit.fq_name()).collect();
        names.sort();
        names
    };
    let prefetched =
        brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::AnalyzerDefinitionLookup::new(
            &analyzer,
            Language::Cpp,
        );
    prefetched.prefetch_fqns(&["Top::Only".to_string()]);
    assert_eq!(names(prefetched.fqn("Top::Only")), ["Top$Only"]);
    let prefetched =
        brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::AnalyzerDefinitionLookup::new(
            &analyzer,
            Language::Cpp,
        );
    prefetched.prefetch_fqn_in_language(Language::Cpp, &["ns::Outer::Inner".to_string()]);
    assert_eq!(
        names(prefetched.fqn("ns::Outer::Inner")),
        ["ns.Outer$Inner"]
    );
}

#[test]
#[hardwon(
    "c406a1edeecb: retained workspace queries lost their original content snapshot after update"
)]
fn retained_analyzer_reads_callable_facts_from_its_content_snapshot() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let file = ProjectFile::new(root.clone(), "retained.cpp");
    file.write("int Original(int value) { return value; }\n")
        .unwrap();
    let analyzer = CppAnalyzer::from_project(
        brokk_bifrost_core::analyzer::project::TestProject::new(root, Language::Cpp),
    );
    let original = analyzer
        .get_definitions("Original")
        .into_iter()
        .next()
        .expect("original definition");

    file.write("int Successor(int value) { return value + 1; }\n")
        .unwrap();
    let successor = analyzer.update(&BTreeSet::from([file]));
    assert!(successor.get_definitions("Original").is_empty());

    let request = RelationalDefinitionRequest {
        ordinal: 0,
        language_scope: DefinitionLanguageScope::Language(Language::Cpp),
        name: brokk_bifrost_core::analyzer::RelationalName::stable(original.fq().clone()),
        query: RelationalDefinitionQuery::CallableFacts,
    };
    let RelationalBatchOutcome::Complete(mut results) = analyzer.relational_definition_batch(
        &[request],
        &brokk_bifrost_core::cancellation::CancellationToken::new(),
    ) else {
        panic!("retained callable request must complete");
    };
    let RelationalDefinitionValue::CallableFacts(facts) = results.remove(0).value else {
        panic!("callable request returned the wrong value shape");
    };
    assert!(
        facts.iter().any(|fact| fact.declaration == original),
        "retained callable facts: {facts:?}"
    );
}

#[test]
#[hardwon("#1573: error recovery produced an empty owner chain after a UI property macro")]
fn global_out_of_line_ctor_after_ui_property_macro_keeps_owner_1573() {
    // #1573: chromium's side_panel_content_proxy.cc panicked the workspace
    // build: a DEFINE_OWNED_UI_CLASS_PROPERTY_KEY macro invocation immediately
    // followed by a single-segment out-of-line constructor produced a Function
    // unit with an empty owner chain (package="", short=".X", fq="X").
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    ProjectFile::new(root.clone(), "side_panel_content_proxy.h")
        .write(
            r#"#ifndef CHROME_BROWSER_UI_SIDE_PANEL_SIDE_PANEL_CONTENT_PROXY_H_
#define CHROME_BROWSER_UI_SIDE_PANEL_SIDE_PANEL_CONTENT_PROXY_H_

class SidePanelContentProxy final {
 public:
  explicit SidePanelContentProxy(bool available = true);
  SidePanelContentProxy(const SidePanelContentProxy&) = delete;
  SidePanelContentProxy& operator=(const SidePanelContentProxy&) = delete;
  ~SidePanelContentProxy();

  bool IsAvailable() { return available_; }
  void SetAvailable(bool available);
  void ResetAvailableCallback();

 private:
  bool available_;
};

extern const ui::ClassProperty<SidePanelContentProxy*>* const
    kSidePanelContentProxyKey;

#endif  // CHROME_BROWSER_UI_SIDE_PANEL_SIDE_PANEL_CONTENT_PROXY_H_
"#,
        )
        .expect("write proxy header fixture");
    ProjectFile::new(root.clone(), "side_panel_content_proxy.cc")
        .write(
            r#"#include "chrome/browser/ui/side_panel/side_panel_content_proxy.h"

#include "ui/base/class_property.h"

DEFINE_UI_CLASS_PROPERTY_TYPE(SidePanelContentProxy*)
DEFINE_OWNED_UI_CLASS_PROPERTY_KEY(SidePanelContentProxy,
                                   kSidePanelContentProxyKey)

SidePanelContentProxy::SidePanelContentProxy(bool available)
    : available_(available) {}

SidePanelContentProxy::~SidePanelContentProxy() = default;

void SidePanelContentProxy::SetAvailable(bool available) {
  available_ = available;
  if (available && available_callback_) {
    std::move(available_callback_).Run();
  }
}

void SidePanelContentProxy::ResetAvailableCallback() {
  available_callback_.Reset();
}
"#,
        )
        .expect("write proxy fixture");
    let analyzer = CppAnalyzer::from_project(
        brokk_bifrost_core::analyzer::project::TestProject::new(root, Language::Cpp),
    );
    let declarations = analyzer.get_all_declarations();

    for unit in &declarations {
        assert!(
            !unit.short_name().starts_with('.'),
            "declaration must not carry an empty owner chain: {unit:?}"
        );
    }
    // The error envelope swallows the ctor's leading identifier, so the
    // recovered spelling is the explicitly-global `::SidePanelContentProxy`:
    // a free function, not an empty-owner member.
    assert!(
        declarations.iter().any(|unit| {
            unit.kind() == CodeUnitType::Function && unit.fq_name() == "SidePanelContentProxy"
        }),
        "recovered ctor must land as a global free function: {declarations:?}"
    );
    // Members whose qualifier survived recovery keep their owner.
    assert!(
        declarations.iter().any(|unit| {
            unit.kind() == CodeUnitType::Function
                && unit.fq_name() == "SidePanelContentProxy.SetAvailable"
        }),
        "normally-qualified member keeps its owner chain: {declarations:?}"
    );
}

/// Tests for [`HeaderLanguageAttribution`] and the transitive reverse-include closure it
/// is built on. `header_language_attribution` and
/// `transitive_reaching_translation_units` are `pub(crate)` analyzer
/// capabilities with no consumer yet, so these are crate-internal fixture
/// tests beside the analyzer (like the rest of this file) rather than
/// integration tests through the public facade.
#[cfg(test)]
mod header_language_attribution_tests {

    use crate::analyzer::cpp::tests::*;

    #[test]
    fn compile_database_evidence_overrides_extension_evidence() {
        // main.cpp is a `.cpp` translation unit, which extension evidence
        // alone would attribute C++, but its compile-database entry forces
        // `-x c`, so shared.h -- reached only through main.cpp -- attributes
        // C instead.
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        ProjectFile::new(root.clone(), "shared.h")
            .write("struct Widget { int value; };\n")
            .expect("write header");
        ProjectFile::new(root.clone(), "main.cpp")
            .write("#include \"shared.h\"\n")
            .expect("write translation unit");
        ProjectFile::new(root.clone(), "compile_commands.json")
            .write(
                r#"[{"directory":".","file":"main.cpp","arguments":["clang","-x","c","-c","main.cpp"]}]"#,
            )
            .expect("write compile database");
        let analyzer = CppAnalyzer::from_project(
            brokk_bifrost_core::analyzer::project::TestProject::new(root, Language::Cpp),
        );
        let header = ProjectFile::new(analyzer.inner.project().root().to_path_buf(), "shared.h");

        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        assert_eq!(
            HeaderLanguageAttribution::C,
            analyzer.header_language_attribution(token, &header)
        );
    }

    /// The workspace mount asks "does any translation unit compile this file
    /// as C?" of every analyzed file. `files_compiled_as_c` answers it by
    /// propagating three bits over the include graph; `header_language_attribution`
    /// answers it by materializing the reaching-translation-unit set of every
    /// file. They must agree file for file, or the `cpp:c` mount changes.
    ///
    /// The fixture exercises every tier the two share: a `.c` and a `.cpp`
    /// translation unit, a header each reaches alone and a header both reach,
    /// a chain that reaches a leaf only transitively, an include cycle (which
    /// the propagation must terminate on), a `.cpp` unit forced to C by its
    /// compile-database entry, a header named directly by the database, and an
    /// orphan nothing reaches.
    #[test]
    fn predicate_agrees_with_the_transitive_index_over_a_mixed_workspace() {
        let (_temp, analyzer) = mixed_c_and_cpp_workspace();
        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();

        let files = analyzer.inner.analyzed_files();
        let predicate = analyzer.files_compiled_as_c(token, &files);
        let mut from_index = BTreeSet::new();
        for file in &files {
            if matches!(
                analyzer.header_language_attribution(token, file),
                HeaderLanguageAttribution::C | HeaderLanguageAttribution::Mixed
            ) {
                from_index.insert(file.clone());
            }
        }
        assert_eq!(
            from_index,
            predicate.iter().cloned().collect::<BTreeSet<_>>(),
            "the predicate and the transitive index must name the same C-compiled files"
        );
        // Not a vacuous agreement: the fixture has to produce all three
        // shapes, or the comparison above proves nothing.
        let project_root = analyzer.inner.project().root().to_path_buf();
        for name in ["c_only.h", "shared.h", "forced_c.h", "database_named.h"] {
            assert!(
                from_index.contains(&ProjectFile::new(project_root.clone(), name)),
                "{name} must be C-compiled: {from_index:?}"
            );
        }
        for name in ["cpp_only.h", "orphan.h", "unit.cpp", "mixed_evidence.h"] {
            assert!(
                !from_index.contains(&ProjectFile::new(project_root.clone(), name)),
                "{name} must not be C-compiled: {from_index:?}"
            );
        }
        assert!(
            from_index.contains(&ProjectFile::new(project_root.clone(), "chain_leaf.h")),
            "the transitive chain must reach the leaf through the cycle: {from_index:?}"
        );
    }

    /// A workspace with both dialects, a header each reaches alone and one
    /// both reach, a transitive chain, an include cycle, a `.cpp` unit the
    /// compile database forces to C, a header the database names directly,
    /// and an orphan.
    fn mixed_c_and_cpp_workspace() -> (tempfile::TempDir, CppAnalyzer) {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        for (name, source) in [
            // Reached by the C unit only.
            ("c_only.h", "struct COnly { int value; };\n"),
            // Reached by the C++ unit only.
            ("cpp_only.h", "struct CppOnly { int value; };\n"),
            // Reached by both.
            (
                "shared.h",
                "#include \"chain_top.h\"\nstruct Shared { int value; };\n",
            ),
            // Reached only through shared.h, and cyclic with its own child.
            (
                "chain_top.h",
                "#include \"chain_leaf.h\"\nstruct ChainTop { int value; };\n",
            ),
            (
                "chain_leaf.h",
                "#include \"chain_top.h\"\nstruct ChainLeaf { int value; };\n",
            ),
            // Named directly by the compile database, reached by nothing.
            ("database_named.h", "struct DatabaseNamed { int value; };\n"),
            // Reached only by a .cpp unit the database forces to C.
            ("forced_c.h", "struct ForcedC { int value; };\n"),
            // Reached by nothing at all.
            ("orphan.h", "struct Orphan { int value; };\n"),
            // Reached by a `.c` unit the database does not name and by a
            // `.cpp` unit it does. Tier 2 answers whenever any reaching unit
            // has an entry, so the database's C++ verdict decides and the `.c`
            // extension never gets a vote: this file is NOT C-compiled. It is
            // the case that separates the tiered rule from "any C evidence
            // wins".
            ("mixed_evidence.h", "struct MixedEvidence { int value; };\n"),
            (
                "db_cpp.cpp",
                "#include \"mixed_evidence.h\"\nint db_cpp_main() { return 0; }\n",
            ),
            (
                "unit.c",
                "#include \"c_only.h\"\n#include \"shared.h\"\n#include \"mixed_evidence.h\"\nint c_main(void) { return 0; }\n",
            ),
            (
                "unit.cpp",
                "#include \"cpp_only.h\"\n#include \"shared.h\"\nint cpp_main() { return 0; }\n",
            ),
            (
                "forced.cpp",
                "#include \"forced_c.h\"\nint forced_main() { return 0; }\n",
            ),
            (
                "compile_commands.json",
                r#"[{"directory":".","file":"forced.cpp","arguments":["clang","-x","c","-c","forced.cpp"]},
                    {"directory":".","file":"db_cpp.cpp","arguments":["clang++","-c","db_cpp.cpp"]},
                    {"directory":".","file":"database_named.h","arguments":["clang","-x","c","-c","database_named.h"]}]"#,
            ),
        ] {
            ProjectFile::new(root.clone(), name)
                .write(source)
                .expect("write fixture file");
        }
        let analyzer = CppAnalyzer::from_project(
            brokk_bifrost_core::analyzer::project::TestProject::new(root, Language::Cpp),
        );
        (temp, analyzer)
    }

    /// The `cpp:c` rows are a pure function of the file list the mount hands
    /// to `sync_content_reading_workspace_files`, so comparing that list
    /// against the attribution-driven formulation it replaced is comparing the
    /// published rows. The fixture is the mixed workspace above, which
    /// exercises every tier.
    /// #3763: two publishers share `cpp:c`. The ordinary workspace sync owns
    /// the `.c` files and the C-reading mount owns the headers C compiles.
    /// When each replaced the whole membership, the first dropped the
    /// headers and the second put them back, so every warm start advanced
    /// the `cpp:c` revision twice. A warm start over unchanged files, and an
    /// update naming unchanged files, must publish no revision in either
    /// storage language.
    #[test]
    #[hardwon(
        "#3763: duplicate C and C++ publishers changed the revision on an unchanged workspace"
    )]
    fn a_no_op_warm_start_or_update_publishes_no_workspace_revision() {
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Cpp)
            .file(
                "shared.h",
                "struct Outer { struct Inner { int value; } inner; };\n",
            )
            .file(
                "main.c",
                "#include \"shared.h\"\nint main(void) { return 0; }\n",
            )
            .build();
        let project = fixture.project_dyn();
        let store = Arc::new(
            brokk_bifrost_analysis::analyzer::store::AnalyzerStore::open_persistent(
                &fixture.root().join("warm-start.db"),
            )
            .expect("persistent store"),
        );
        let start = || {
            CppAnalyzer::new_with_config_store_context(
                Arc::clone(&project),
                AnalyzerConfig::default(),
                brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::revision_image_store_context(
                    project.as_ref(),
                    Arc::clone(&store),
                ),
                None,
            )
            .expect("analyzer over the persistent store")
        };
        let revisions = |analyzer: &CppAnalyzer| {
            let snapshots = analyzer.inner.selected_workspace_snapshots();
            [
                "cpp",
                crate::analyzer::cpp::adapter::CPP_C_STORAGE_LANGUAGE_KEY,
            ]
            .map(|lang| {
                snapshots
                    .get(lang)
                    .unwrap_or_else(|| panic!("no {lang} snapshot in {snapshots:?}"))
                    .revision
            })
        };

        let cold = start();
        let header = fixture.file("shared.h");
        {
            let scope = AnalyzerQueryScope::new(&cold);
            assert!(
                cold.c_reading_workspace_files(scope.token())
                    .contains(&header),
                "the header must be mounted under cpp:c, or the test proves nothing"
            );
        }
        let cold_revisions = revisions(&cold);
        drop(cold);

        let warm = start();
        assert_eq!(
            revisions(&warm),
            cold_revisions,
            "a warm start over unchanged files published a revision"
        );

        let updated = warm.update(&BTreeSet::from([header, fixture.file("main.c")]));
        assert_eq!(
            revisions(&updated),
            cold_revisions,
            "an update naming unchanged files published a revision"
        );
    }

    #[test]
    fn a_direct_database_entry_naming_the_header_is_decisive() {
        // The compile database has no entry for the reaching translation
        // unit at all (only for the header itself), so tier 2 (database TUs
        // in the closure) and tier 3 (extension evidence) would both say
        // nothing; the direct entry alone must still decide.
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        ProjectFile::new(root.clone(), "shared.h")
            .write("struct Widget { int value; };\n")
            .expect("write header");
        ProjectFile::new(root.clone(), "main.cpp")
            .write("#include \"shared.h\"\n")
            .expect("write translation unit");
        ProjectFile::new(root.clone(), "compile_commands.json")
            .write(r#"[{"directory":".","file":"shared.h","arguments":["clang","-x","c","-c","shared.h"]}]"#)
            .expect("write compile database");
        let analyzer = CppAnalyzer::from_project(
            brokk_bifrost_core::analyzer::project::TestProject::new(root, Language::Cpp),
        );
        let header = ProjectFile::new(analyzer.inner.project().root().to_path_buf(), "shared.h");

        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        assert_eq!(
            HeaderLanguageAttribution::C,
            analyzer.header_language_attribution(token, &header)
        );
    }
}

/// #2899: the transitive reverse translation-unit index. The build collapses
/// the include graph's strongly connected components and unions each
/// component's translation-unit bitset into its successors' in topological
/// order, so what it costs is the graph's edges and not the reachability
/// relation those edges carry. The worklist it replaced re-propagated a whole
/// downstream closure for every unit that arrived late at a root, which is how
/// envoy's 5.05M memberships came to take 1,362 s.
#[cfg(test)]
mod transitive_reverse_tu_index_tests {

    use crate::analyzer::cpp::tests::*;

    use crate::analyzer::cpp::imports::TransitiveReverseTuIndex;

    use crate::analyzer::cpp::imports::build_transitive_reverse_tu_index;
    use std::collections::VecDeque;

    /// The index's answer as owned files, the shape the assertions compare.
    fn reaching(index: &TransitiveReverseTuIndex, file: &ProjectFile) -> Vec<ProjectFile> {
        index.reaching_translation_units(file).cloned().collect()
    }

    /// `header -> its direct includers` -- the shape `referencing_files_of`
    /// produces and the index consumes -- from `(includer, target)` edges.
    fn direct_reverse(
        edges: &[(ProjectFile, ProjectFile)],
    ) -> HashMap<ProjectFile, Arc<HashSet<ProjectFile>>> {
        let mut includers: HashMap<ProjectFile, HashSet<ProjectFile>> = HashMap::default();
        for (includer, target) in edges {
            includers
                .entry(target.clone())
                .or_default()
                .insert(includer.clone());
        }
        includers
            .into_iter()
            .map(|(target, set)| (target, Arc::new(set)))
            .collect()
    }

    #[test]
    #[hardwon(
        "#2899: repeated graph traversal made C++ reverse include indexing prohibitively slow"
    )]
    fn a_deep_chain_under_many_units_visits_each_include_edge_once() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        // 300 translation units on the head of a 200-header chain: every unit
        // reaches every header, so the relation is 60,000 memberships over 499
        // edges. The worklist form re-walked the chain once per unit that
        // arrived at its head.
        let depth = 200;
        let unit_count = 300;
        let headers = (0..depth)
            .map(|index| ProjectFile::new(root.clone(), format!("h{index:03}.h")))
            .collect::<Vec<_>>();
        // Zero-padded so path order and ordinal order agree, which is the
        // index's contract for the units it is given.
        let translation_units = (0..unit_count)
            .map(|index| ProjectFile::new(root.clone(), format!("u{index:03}.cc")))
            .collect::<Vec<_>>();
        let mut edges = translation_units
            .iter()
            .map(|unit| (unit.clone(), headers[0].clone()))
            .collect::<Vec<_>>();
        edges.extend(
            headers
                .windows(2)
                .map(|pair| (pair[0].clone(), pair[1].clone())),
        );

        let build = build_transitive_reverse_tu_index(&direct_reverse(&edges), &translation_units);

        assert_eq!(
            edges.len(),
            build.edge_visits,
            "the component ordering must look at each include edge once, not once per unit reaching it"
        );
        assert_eq!(
            depth * unit_count + unit_count,
            build.index.total_membership(),
            "every header is reached by every unit, and every unit reaches itself"
        );
        for header in &headers {
            assert_eq!(
                translation_units,
                reaching(&build.index, header),
                "a chain header must report every unit, ascending by path: {header:?}"
            );
        }
    }

    #[test]
    #[hardwon(
        "#2899: the optimized reverse include index must match an independent per-unit BFS over cycles and joins"
    )]
    fn the_closure_equals_a_breadth_first_search_from_every_translation_unit() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = |name: &str| ProjectFile::new(root.clone(), name);
        // A diamond, a second unit joining it halfway down, a mutually
        // including pair below both, and a header nothing includes.
        let edges = vec![
            (file("a.cc"), file("top.h")),
            (file("b.cc"), file("side.h")),
            (file("top.h"), file("left.h")),
            (file("top.h"), file("right.h")),
            (file("side.h"), file("right.h")),
            (file("left.h"), file("bottom.h")),
            (file("right.h"), file("bottom.h")),
            (file("bottom.h"), file("cycle_a.h")),
            (file("cycle_a.h"), file("cycle_b.h")),
            (file("cycle_b.h"), file("cycle_a.h")),
        ];
        let translation_units = vec![file("a.cc"), file("b.cc")];

        let index =
            build_transitive_reverse_tu_index(&direct_reverse(&edges), &translation_units).index;

        // The oracle: walk forward from each unit and record where it arrives.
        let mut forward: HashMap<ProjectFile, Vec<ProjectFile>> = HashMap::default();
        for (includer, target) in &edges {
            forward
                .entry(includer.clone())
                .or_default()
                .push(target.clone());
        }
        let mut expected: HashMap<ProjectFile, Vec<ProjectFile>> = HashMap::default();
        for unit in &translation_units {
            let mut seen: HashSet<ProjectFile> = HashSet::default();
            seen.insert(unit.clone());
            let mut queue = VecDeque::from([unit.clone()]);
            while let Some(current) = queue.pop_front() {
                expected
                    .entry(current.clone())
                    .or_default()
                    .push(unit.clone());
                for target in forward.get(&current).into_iter().flatten() {
                    if seen.insert(target.clone()) {
                        queue.push_back(target.clone());
                    }
                }
            }
        }

        let mut files = edges
            .iter()
            .flat_map(|(includer, target)| [includer.clone(), target.clone()])
            .collect::<BTreeSet<_>>();
        files.insert(file("orphan.h"));
        for candidate in &files {
            assert_eq!(
                expected.get(candidate).cloned().unwrap_or_default(),
                reaching(&index, candidate),
                "the index must agree with a per-unit search at {candidate:?}"
            );
        }
        // Not a vacuous agreement: the fixture has to produce a file both
        // units reach, one only the diamond's own unit reaches, and one
        // nothing reaches.
        assert_eq!(translation_units, reaching(&index, &file("bottom.h")));
        assert_eq!(vec![file("a.cc")], reaching(&index, &file("left.h")));
        assert!(reaching(&index, &file("orphan.h")).is_empty());
    }
}

/// A header blob is stored twice when its C and C++ readings disagree, and
/// once when they agree.
#[cfg(test)]
mod header_c_projection_storage_tests {

    use crate::analyzer::cpp::tests::*;

    fn analyzer_over(files: &[(&str, &str)]) -> (tempfile::TempDir, CppAnalyzer) {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        for (name, source) in files {
            ProjectFile::new(root.clone(), *name)
                .write(source)
                .expect("write fixture file");
        }
        let analyzer = CppAnalyzer::from_project(
            brokk_bifrost_core::analyzer::project::TestProject::new(root, Language::Cpp),
        );
        (temp, analyzer)
    }

    #[test]
    fn nested_tag_header_stores_a_distinct_c_reading() {
        let (_temp, analyzer) = analyzer_over(&[
            (
                "xdr.h",
                "struct XDR {\n    struct xdr_ops {\n        int dummy;\n    };\n};\n",
            ),
            ("use.c", "#include \"xdr.h\"\n"),
        ]);
        let header = ProjectFile::new(analyzer.inner.project().root().to_path_buf(), "xdr.h");

        let reading = analyzer
            .c_reading(&header)
            .expect("a nested tag makes the two readings disagree");
        let mut c_only: Vec<String> = reading.c_only.iter().map(CodeUnit::fq_name).collect();
        let mut cpp_only: Vec<String> = reading.cpp_only.iter().map(CodeUnit::fq_name).collect();
        c_only.sort();
        cpp_only.sort();
        assert_eq!(
            vec!["xdr_ops".to_string(), "xdr_ops.dummy".to_string()],
            c_only,
            "C gives the inner tag file scope, and its member follows it"
        );
        assert_eq!(
            vec!["XDR$xdr_ops".to_string(), "XDR$xdr_ops.dummy".to_string()],
            cpp_only
        );

        let file_scope_tag = reading
            .c_only
            .iter()
            .find(|unit| unit.is_class())
            .expect("the C reading mints a file-scope tag");
        let nested_tag = reading
            .cpp_only
            .iter()
            .find(|unit| unit.is_class())
            .expect("the C++ reading mints a nested class");
        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        assert_eq!(
            vec![nested_tag.clone()],
            analyzer.site_equivalent_units(token, file_scope_tag),
            "the two identities share one declaration site"
        );
        assert_eq!(
            vec![file_scope_tag.clone()],
            analyzer.site_equivalent_units(token, nested_tag)
        );
    }

    #[test]
    fn recovered_export_class_reparse_keeps_its_c_reading() {
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Cpp)
            .file(
                "recovered.h",
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
            )
            .file("use.c", "#include \"recovered.h\"\n")
            .build();
        let header = fixture.file("recovered.h");
        let analyzer = CppAnalyzer::from_project(fixture.project().clone());

        let reading = analyzer
            .c_reading(&header)
            .expect("the recovered C tag must keep the alternate reading published");
        assert!(
            reading
                .c_only
                .iter()
                .any(|unit| { unit.is_class() && unit.fq_name() == "api.RecoveredTag" })
        );
        assert!(
            reading.cpp_only.iter().any(|unit| {
                unit.is_class() && unit.fq_name() == "api.RecoveryOwner$RecoveredTag"
            })
        );
    }
}

#[test]
#[hardwon(
    "#2488+#5868: a physical C++ body must retain its confirmed lexical owner and header identity"
)]
fn canonical_member_reads_preserve_physical_facts_and_cancelled_reads_do_not_poison_cache() {
    let project = crate::inline_project::InlineTestProject::with_language(Language::Cpp)
        .file(
            "owner.h",
            "namespace Other {}\nclass Owner { public: void run(); };\n",
        )
        .file(
            "owner.cpp",
            "#include \"owner.h\"\nusing namespace Other;\nvoid Owner::run() {}\n",
        )
        .file(
            "lexical.h",
            "class ScopeOwner { public: void hit(); void root(); };\n\
             namespace rival { class ScopeOwner { public: void hit(); void root(); }; }\n\
             namespace sibling { class ScopeOwner { public: void hit(); }; }\n\
             namespace outer { class ParentOwner { public: void hit(); };\n\
             namespace inner { class ScopeOwner { public: void hit(); }; }}\n",
        )
        .file(
            "lexical.cpp",
            "#include \"lexical.h\"\n\
             namespace sibling { void ScopeOwner::hit() {} }\n\
             void ScopeOwner::hit() {}\n\
             namespace outer::inner { void ScopeOwner::hit() {}\n\
             void ParentOwner::hit() {} }\n",
        )
        .file(
            "absolute.cpp",
            "#include \"lexical.h\"\n\
             using namespace rival;\n\
             void ::ScopeOwner::root() {}\n",
        )
        .file(
            "tier.h",
            "struct N { struct C { void f(); }; };\n\
             namespace { namespace N { struct C { void f(); }; } }\n",
        )
        .file(
            "tier.cpp",
            "#include \"tier.h\"\n\
             namespace {\n\
             namespace N {\n\
             void C::f() {}\n\
             }\n\
             }\n",
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let physical = analyzer
        .all_declarations()
        .find(|unit| unit.source().rel_path() == std::path::Path::new("owner.cpp"))
        .unwrap();
    let ranges = analyzer.ranges(&physical);
    let cancelled = brokk_bifrost_core::cancellation::CancellationToken::new();
    cancelled.cancel();
    {
        let scope = AnalyzerQueryScope::new(&analyzer);
        assert_eq!(
            analyzer.canonical_code_unit(&physical, Some(&cancelled)),
            physical
        );
        assert!(matches!(
            scope.read_completion(),
            Err(brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadIncomplete::Cancelled)
        ));
    }
    assert_eq!(
        analyzer
            .reconcile_candidate_scan_count
            .load(std::sync::atomic::Ordering::Relaxed),
        0,
        "a cold cancelled identity read must not start candidate work"
    );
    let canonical = {
        let scope = AnalyzerQueryScope::new(&analyzer);
        let unit = analyzer.canonical_code_unit(&physical, None);
        assert!(scope.read_completion().is_ok());
        unit
    };
    let metadata = analyzer.signature_metadata(&physical);
    let ledger = Arc::new(brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger::new());
    {
        let scope = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&ledger));
        assert_eq!(analyzer.canonical_code_unit(&physical, None), canonical);
        assert!(scope.read_completion().is_ok());
    }
    assert!(
        ledger.keys().iter().any(|key| matches!(
            key,
            brokk_bifrost_analysis::analyzer::semantic::read_ledger::ReadKey::Scope { .. }
        )),
        "a warm ownership read must retain its snapshot dependency: {:?}",
        ledger.keys()
    );
    assert_eq!(canonical.fq_name(), "Owner.run");
    assert_eq!(canonical.source(), physical.source());
    assert_eq!(canonical.signature(), physical.signature());
    assert_eq!(
        canonical.fq_segments_debug(),
        vec![("Type", "Owner".into()), ("Member", "run".into())]
    );
    assert_eq!(analyzer.ranges(&canonical), ranges);
    let canonical_metadata = analyzer.signature_metadata(&canonical);
    assert_eq!(canonical_metadata.len(), metadata.len());
    for (canonical_fact, physical_fact) in canonical_metadata.iter().zip(&metadata) {
        // Public semantic properties may inherit the header's visibility;
        // the body's own signature facts and source provenance stay intact.
        assert_eq!(canonical_fact.label(), physical_fact.label());
        assert_eq!(canonical_fact.parameters(), physical_fact.parameters());
        assert_eq!(
            canonical_fact.return_type_identity(),
            physical_fact.return_type_identity()
        );
        assert_eq!(
            canonical_fact.callable_arity(),
            physical_fact.callable_arity()
        );
        assert_eq!(
            canonical_fact.callable_linkage(),
            physical_fact.callable_linkage()
        );
    }
    assert_eq!(analyzer.signature_metadata(&physical), metadata);
    let token = brokk_bifrost_core::cancellation::CancellationToken::new();
    assert_eq!(
        analyzer.ranges_with_limit(&canonical, 1, &token),
        analyzer.ranges_with_limit(&physical, 1, &token)
    );
    assert!(
        analyzer
            .all_declarations()
            .any(|unit| unit == physical && unit.fq_name() == "Other.Owner.run")
    );
    // Same short owners in distinct namespaces must retain their own bodies.
    // No private corpus is needed for this physical/canonical contract.
    for (file, expected, line) in [
        ("lexical.cpp", "sibling.ScopeOwner.hit", 2),
        ("lexical.cpp", "ScopeOwner.hit", 3),
        ("lexical.cpp", "outer::inner.ScopeOwner.hit", 4),
        ("lexical.cpp", "outer.ParentOwner.hit", 5),
        ("absolute.cpp", "ScopeOwner.root", 3),
        ("tier.cpp", "N.C.f", 4),
    ] {
        let scope = AnalyzerQueryScope::new(&analyzer);
        let expected_header = if file == "tier.cpp" {
            "tier.h"
        } else {
            "lexical.h"
        };
        if file == "tier.cpp" {
            // These are distinct legal scopes: global nested N$C versus N.C
            // inside an unnamed namespace. Both are real visible candidates.
            let visible = analyzer.visible_type_units(&project.file(file));
            for owner in ["N$C", "N.C"] {
                assert!(
                    visible.iter().any(|unit| unit.fq_name() == owner),
                    "missing competing owner {owner}: {visible:?}"
                );
            }
        }
        let physical = analyzer
            .all_declarations()
            .find(|unit| {
                unit.source().rel_path() == std::path::Path::new(file)
                    && unit.is_callable()
                    && analyzer
                        .inner
                        .ranges(unit)
                        .iter()
                        .any(|range| range.start_line == line)
            })
            .unwrap_or_else(|| panic!("missing physical body {file}:{line} for {expected}"));
        let physical_ranges = analyzer.inner.ranges(&physical);
        let metadata = analyzer.stored_signature_metadata(&physical);
        let canonical = analyzer.canonical_code_unit(&physical, None);
        assert_eq!(canonical.fq_name(), expected, "{physical:?}");
        if (file == "lexical.cpp" && expected != "outer.ParentOwner.hit") || file == "tier.cpp" {
            assert_eq!(canonical, physical, "lexical body keeps self identity");
        }
        assert_eq!(canonical.source(), physical.source());
        assert_eq!(canonical.signature(), physical.signature());
        assert_eq!(analyzer.ranges(&canonical), physical_ranges);
        let canonical_metadata = analyzer.signature_metadata(&canonical);
        assert_eq!(canonical_metadata.len(), metadata.len());
        for (canonical_fact, physical_fact) in canonical_metadata.iter().zip(&metadata) {
            assert_eq!(canonical_fact.label(), physical_fact.label());
            assert_eq!(canonical_fact.parameters(), physical_fact.parameters());
            assert_eq!(
                canonical_fact.callable_arity(),
                physical_fact.callable_arity()
            );
        }
        let definitions: Vec<_> = analyzer.definitions(expected).collect();
        assert!(
            definitions.contains(&canonical),
            "{expected}: {definitions:?}"
        );
        assert!(
            definitions
                .iter()
                .any(|unit| unit.source().rel_path() == std::path::Path::new(expected_header)),
            "header/body identity must agree: {expected}: {definitions:?}"
        );
        let header = definitions
            .iter()
            .find(|unit| unit.source().rel_path() == std::path::Path::new(expected_header))
            .unwrap();
        let header_ranges = analyzer.ranges(header);
        assert_eq!(analyzer.canonical_code_unit(header, None), *header);
        assert_eq!(analyzer.ranges(header), header_ranges);
        assert!(scope.read_completion().is_ok());
    }
    // The same request contract holds even when reconciliation is cached.
    let scope = AnalyzerQueryScope::new(&analyzer);
    assert_eq!(
        analyzer.canonical_code_unit(&physical, Some(&cancelled)),
        physical
    );
    assert!(matches!(
        scope.read_completion(),
        Err(brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadIncomplete::Cancelled)
    ));
}
