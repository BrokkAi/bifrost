//! C++'s analyzer-bound fixture suites, kept beside the analyzer they build.
//!
//! The production half -- `cpp_contains_tests`, `detect_cpp_test_assertion_smells`
//! and the four framework regex families -- moved to
//! [`brokk_bifrost_cpp::test_detection`]. What remains needs a real
//! `CppAnalyzer` over a temp workspace, so it cannot cross the crate line.

use super::*;
use crate::analyzer::{
    CodeUnitType, DefinitionLanguageScope, RelationalBatchOutcome, RelationalDefinitionQuery,
    RelationalDefinitionRequest, RelationalDefinitionValue,
};
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
fn generated_field_ranges_only_build_their_source_overlay() {
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
}

#[test]
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
            crate::analyzer::fq_name::segment_interner(),
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
    let RelationalBatchOutcome::Complete(mut results) =
        analyzer.relational_definition_batch(&[request], &crate::CancellationToken::new())
    else {
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
fn workspace_identifier_queries_retain_generated_fields_from_all_overlays() {
    let (_fixture, _owner, analyzer) = macro_composed_fields_fixture();
    let name = brokk_bifrost_core::analyzer::RelationalName::stable(
        brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path_fq(
            Language::Cpp,
            "value",
            crate::analyzer::fq_name::segment_interner(),
        ),
    );
    let request = RelationalDefinitionRequest {
        ordinal: 0,
        language_scope: DefinitionLanguageScope::Language(Language::Cpp),
        name,
        query: RelationalDefinitionQuery::Identifier { file: None },
    };

    let RelationalBatchOutcome::Complete(mut results) =
        analyzer.relational_definition_batch(&[request], &crate::CancellationToken::new())
    else {
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
fn generated_field_ranges_with_limit_only_use_their_source_overlay() {
    let (_fixture, owner, analyzer) = macro_composed_fields_fixture();
    let field = analyzer
        .declarations(&owner)
        .into_iter()
        .find(|unit| unit.is_field() && unit.fq_name() == "Owner.value")
        .expect("owner macro field");

    analyzer.reset_macro_composed_fields_build_count_for_test();
    let (ranges, total, complete) =
        analyzer.ranges_with_limit(&field, 1, &crate::CancellationToken::new());
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
    let analyzer = CppAnalyzer::from_project(crate::TestProject::new(root, Language::Cpp));

    let definitions = analyzer.get_definitions("TempDir");
    assert!(
        definitions
            .iter()
            .any(|unit| unit.is_class() && unit.fq_name() == "TempDir"),
        "the class lookup must complete without constructor reconciliation re-entry: {definitions:#?}"
    );
}

#[test]
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
    let analyzer = CppAnalyzer::from_project(crate::TestProject::new(root, Language::Cpp));
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
    let analyzer = CppAnalyzer::from_project(crate::TestProject::new(root, Language::Cpp));

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

#[cfg(test)]
mod cache_tests {
    use super::*;
    use crate::analyzer::FileSetProject;
    use std::path::PathBuf;

    #[test]
    fn project_sensitive_caches_are_isolated_across_snapshots_and_updates() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let project: Arc<dyn Project> = Arc::new(FileSetProject::new(
            root.clone(),
            std::iter::empty::<PathBuf>(),
        ));
        let analyzer = CppAnalyzer::new(Arc::clone(&project));
        let snapshot = analyzer.clone_with_project(Arc::clone(&project));
        let updated = analyzer.with_updated_inner(analyzer.inner.clone());
        let file = ProjectFile::new(root, "sample.cpp");

        snapshot
            .imported_code_units
            .insert(file.clone(), Arc::new(HashSet::default()));
        snapshot
            .referencing_files
            .insert(file.clone(), Arc::new(HashSet::default()));
        assert!(analyzer.imported_code_units.get(&file).is_none());
        assert!(analyzer.referencing_files.get(&file).is_none());

        analyzer
            .imported_code_units
            .insert(file.clone(), Arc::new(HashSet::default()));
        analyzer
            .referencing_files
            .insert(file.clone(), Arc::new(HashSet::default()));

        assert!(updated.imported_code_units.get(&file).is_none());
        assert!(updated.referencing_files.get(&file).is_none());
    }
}

#[test]
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
    let analyzer = CppAnalyzer::from_project(crate::TestProject::new(root, Language::Cpp));
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
    let analyzer = CppAnalyzer::from_project(crate::TestProject::new(root, Language::Cpp));

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
                crate::analyzer::fq_name::segment_interner(),
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
    let RelationalBatchOutcome::Complete(results) =
        analyzer.relational_definition_batch(&requests, &crate::CancellationToken::new())
    else {
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

#[test]
fn retained_analyzer_reads_callable_facts_from_its_content_snapshot() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let file = ProjectFile::new(root.clone(), "retained.cpp");
    file.write("int Original(int value) { return value; }\n")
        .unwrap();
    let analyzer = CppAnalyzer::from_project(crate::TestProject::new(root, Language::Cpp));
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
    let RelationalBatchOutcome::Complete(mut results) =
        analyzer.relational_definition_batch(&[request], &crate::CancellationToken::new())
    else {
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
    let analyzer = CppAnalyzer::from_project(crate::TestProject::new(root, Language::Cpp));
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

/// ExecPlan Milestone 2 (`.agents/plans/c-compilation-language-tag-scope.md`):
/// [`HeaderLanguageAttribution`] and the transitive reverse-include closure it
/// is built on. `header_language_attribution` and
/// `transitive_reaching_translation_units` are `pub(crate)` analyzer
/// capabilities with no consumer yet, so these are crate-internal fixture
/// tests beside the analyzer (like the rest of this file) rather than
/// integration tests through the public facade.
#[cfg(test)]
mod header_language_attribution_tests {
    use super::*;
    use brokk_bifrost_cpp::graph::resolver::is_c_source_file;

    #[test]
    fn header_included_only_by_a_c_file_is_attributed_c() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        ProjectFile::new(root.clone(), "shared.h")
            .write("struct Widget { int value; };\n")
            .expect("write header");
        ProjectFile::new(root.clone(), "a.c")
            .write("#include \"shared.h\"\n")
            .expect("write C translation unit");
        let analyzer = CppAnalyzer::from_project(crate::TestProject::new(root, Language::Cpp));
        let header = ProjectFile::new(analyzer.inner.project().root().to_path_buf(), "shared.h");

        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        assert_eq!(
            HeaderLanguageAttribution::C,
            analyzer.header_language_attribution(token, &header)
        );
    }

    #[test]
    fn header_included_only_by_a_cpp_file_is_attributed_cpp() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        ProjectFile::new(root.clone(), "shared.h")
            .write("struct Widget { int value; };\n")
            .expect("write header");
        ProjectFile::new(root.clone(), "a.cpp")
            .write("#include \"shared.h\"\n")
            .expect("write C++ translation unit");
        let analyzer = CppAnalyzer::from_project(crate::TestProject::new(root, Language::Cpp));
        let header = ProjectFile::new(analyzer.inner.project().root().to_path_buf(), "shared.h");

        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        assert_eq!(
            HeaderLanguageAttribution::Cpp,
            analyzer.header_language_attribution(token, &header)
        );
    }

    #[test]
    fn header_included_by_both_a_c_and_a_cpp_file_is_mixed() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        ProjectFile::new(root.clone(), "shared.h")
            .write("struct Widget { int value; };\n")
            .expect("write header");
        ProjectFile::new(root.clone(), "a.c")
            .write("#include \"shared.h\"\n")
            .expect("write C translation unit");
        ProjectFile::new(root.clone(), "b.cpp")
            .write("#include \"shared.h\"\n")
            .expect("write C++ translation unit");
        let analyzer = CppAnalyzer::from_project(crate::TestProject::new(root, Language::Cpp));
        let header = ProjectFile::new(analyzer.inner.project().root().to_path_buf(), "shared.h");

        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        assert_eq!(
            HeaderLanguageAttribution::Mixed,
            analyzer.header_language_attribution(token, &header)
        );
    }

    #[test]
    fn orphan_header_nothing_reaches_is_unknown() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        ProjectFile::new(root.clone(), "orphan.h")
            .write("struct Widget { int value; };\n")
            .expect("write orphan header");
        ProjectFile::new(root.clone(), "unrelated.cpp")
            .write("int main() { return 0; }\n")
            .expect("write unrelated translation unit");
        let analyzer = CppAnalyzer::from_project(crate::TestProject::new(root, Language::Cpp));
        let header = ProjectFile::new(analyzer.inner.project().root().to_path_buf(), "orphan.h");

        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        assert_eq!(
            HeaderLanguageAttribution::Unknown,
            analyzer.header_language_attribution(token, &header)
        );
        assert!(
            analyzer
                .transitive_reaching_translation_units(token, &header)
                .is_empty()
        );
    }

    #[test]
    fn transitive_chain_through_an_intermediate_header_attributes_the_leaf_c() {
        // a.c -> x.h -> y.h: y.h is not directly included by any translation
        // unit, only reached through the direct reverse-include index's
        // fixed-point closure.
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        ProjectFile::new(root.clone(), "y.h")
            .write("struct Leaf { int value; };\n")
            .expect("write leaf header");
        ProjectFile::new(root.clone(), "x.h")
            .write("#include \"y.h\"\n")
            .expect("write intermediate header");
        ProjectFile::new(root.clone(), "a.c")
            .write("#include \"x.h\"\n")
            .expect("write C translation unit");
        let analyzer = CppAnalyzer::from_project(crate::TestProject::new(root, Language::Cpp));
        let project_root = analyzer.inner.project().root().to_path_buf();
        let leaf = ProjectFile::new(project_root.clone(), "y.h");
        let translation_unit = ProjectFile::new(project_root, "a.c");

        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        assert_eq!(
            HeaderLanguageAttribution::C,
            analyzer.header_language_attribution(token, &leaf)
        );
        assert!(
            analyzer
                .transitive_reaching_translation_units(token, &leaf)
                .contains(&translation_unit),
            "the transitive closure must reach through the intermediate header"
        );
    }

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
        let analyzer = CppAnalyzer::from_project(crate::TestProject::new(root, Language::Cpp));
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
        let analyzer = CppAnalyzer::from_project(crate::TestProject::new(root, Language::Cpp));
        (temp, analyzer)
    }

    /// The `cpp:c` rows are a pure function of the file list the mount hands
    /// to `sync_content_reading_workspace_files`, so comparing that list
    /// against the attribution-driven formulation it replaced is comparing the
    /// published rows. The fixture is the mixed workspace above, which
    /// exercises every tier.
    #[test]
    fn the_mount_publishes_the_same_files_the_attribution_would() {
        let (_temp, analyzer) = mixed_c_and_cpp_workspace();
        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();

        let analyzed_files = analyzer.inner.analyzed_files();
        let has_c_translation_unit = analyzed_files.iter().any(is_c_source_file);
        let as_attributed = analyzed_files
            .iter()
            .filter(|file| {
                is_c_source_file(file)
                    || (has_c_translation_unit
                        && !imports::is_cpp_translation_unit(file)
                        && matches!(
                            analyzer.header_language_attribution(token, file),
                            HeaderLanguageAttribution::C | HeaderLanguageAttribution::Mixed
                        ))
            })
            .cloned()
            .collect::<Vec<_>>();

        assert_eq!(
            as_attributed,
            analyzer.c_reading_workspace_files(token),
            "the mount must publish the same files, in the same order"
        );
        assert!(
            !as_attributed.is_empty(),
            "a fixture that mounts nothing would prove nothing"
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
        let analyzer = CppAnalyzer::from_project(crate::TestProject::new(root, Language::Cpp));
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
    use super::*;
    use crate::analyzer::cpp::imports::{
        TransitiveReverseTuIndex, build_transitive_reverse_tu_index,
    };
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

    #[test]
    fn mutually_including_headers_report_the_same_reaching_units() {
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Cpp)
            .file(
                "first.h",
                "#ifndef FIRST_H\n#define FIRST_H\n#include \"second.h\"\nstruct First { int value; };\n#endif\n",
            )
            .file(
                "second.h",
                "#ifndef SECOND_H\n#define SECOND_H\n#include \"first.h\"\nstruct Second { int value; };\n#endif\n",
            )
            .file(
                "unit.cc",
                "#include \"first.h\"\nint unit_main() { return 0; }\n",
            )
            .build();
        let analyzer = CppAnalyzer::from_project(fixture.project().clone());
        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();

        let unit = fixture.file("unit.cc");
        assert_eq!(
            vec![unit.clone()],
            analyzer.transitive_reaching_translation_units(token, &fixture.file("first.h")),
            "the directly included half of the cycle is reached by the unit"
        );
        assert_eq!(
            vec![unit],
            analyzer.transitive_reaching_translation_units(token, &fixture.file("second.h")),
            "so is the half that only the cycle reaches back into"
        );
    }
}

/// ExecPlan Milestone 3 (`.agents/plans/c-compilation-language-tag-scope.md`):
/// a header blob is stored twice when its C and C++ readings disagree, and
/// once when they agree.
#[cfg(test)]
mod header_c_projection_storage_tests {
    use super::*;

    fn analyzer_over(files: &[(&str, &str)]) -> (tempfile::TempDir, CppAnalyzer) {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        for (name, source) in files {
            ProjectFile::new(root.clone(), *name)
                .write(source)
                .expect("write fixture file");
        }
        let analyzer = CppAnalyzer::from_project(crate::TestProject::new(root, Language::Cpp));
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
    fn header_without_a_nested_tag_stores_no_c_reading() {
        let (_temp, analyzer) = analyzer_over(&[
            ("plain.h", "struct Widget { int value; };\n"),
            ("use.c", "#include \"plain.h\"\n"),
        ]);
        let header = ProjectFile::new(analyzer.inner.project().root().to_path_buf(), "plain.h");

        assert!(
            analyzer.c_reading(&header).is_none(),
            "absence of `cpp:c` rows must mean the readings are identical"
        );
        assert_eq!(
            CodeUnitIndex::declarations(&analyzer, &header),
            analyzer.declarations_in_reading(&header, true),
            "the C view of an identical header is the file's own row-set"
        );
    }

    #[test]
    fn a_translation_unit_never_carries_a_second_reading() {
        let (_temp, analyzer) = analyzer_over(&[(
            "unit.c",
            "struct XDR {\n    struct xdr_ops {\n        int dummy;\n    };\n};\n",
        )]);
        let unit = ProjectFile::new(analyzer.inner.project().root().to_path_buf(), "unit.c");

        assert!(analyzer.c_reading(&unit).is_none());
        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        assert!(
            !analyzer.header_uses_c_semantics(token, &unit),
            "a translation unit's dialect is settled by its own extension"
        );
    }
}
