//! C++'s analyzer-bound fixture suites, kept beside the analyzer they build.
//!
//! The production half -- `cpp_contains_tests`, `detect_cpp_test_assertion_smells`
//! and the four framework regex families -- moved to
//! [`brokk_bifrost_cpp::test_detection`]. What remains needs a real
//! `CppAnalyzer` over a temp workspace, so it cannot cross the crate line.

use super::*;
use crate::analyzer::CodeUnitType;

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
        "only the matching candidate's file may pay the class-table build"
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
