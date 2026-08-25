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
