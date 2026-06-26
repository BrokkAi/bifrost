// require / require_relative resolution. Covers ISC-6.

mod common;

use brokk_bifrost::{IAnalyzer, ImportAnalysisProvider, ProjectFile, RubyAnalyzer, TestProject};
use common::ruby_analyzer_with_files;

fn analyzer() -> RubyAnalyzer {
    RubyAnalyzer::from_project(TestProject::new(
        std::fs::canonicalize("tests/fixtures/testcode-ruby").unwrap(),
        brokk_bifrost::Language::Ruby,
    ))
}

fn file(analyzer: &RubyAnalyzer, rel: &str) -> ProjectFile {
    ProjectFile::new(analyzer.project().root().to_path_buf(), rel)
}

#[test]
fn require_relative_imports_target_declarations() {
    let analyzer = analyzer();
    let main = file(&analyzer, "requires/main.rb");

    let imported = analyzer.imported_code_units_of(&main);
    assert!(
        imported.iter().any(|cu| cu.identifier() == "Helper"),
        "expected Helper imported via require_relative, got {:?}",
        imported.iter().map(|cu| cu.fq_name()).collect::<Vec<_>>()
    );
}

#[test]
fn require_relative_records_reverse_edge() {
    let analyzer = analyzer();
    let helper = file(&analyzer, "requires/helper.rb");
    let main = file(&analyzer, "requires/main.rb");

    let referencing = analyzer.referencing_files_of(&helper);
    assert!(
        referencing.contains(&main),
        "expected main.rb to reference helper.rb, got {:?}",
        referencing
    );
}

#[test]
fn require_imports_project_local_target_declarations() {
    let (project, analyzer) = ruby_analyzer_with_files(&[
        (
            "app/main.rb",
            r#"
require "app/models/user"

class App
  def run
    User.new
  end
end
"#,
        ),
        (
            "app/models/user.rb",
            r#"
class User
end
"#,
        ),
    ]);

    let imported = analyzer.imported_code_units_of(&project.file("app/main.rb"));
    assert!(
        imported.iter().any(|cu| cu.identifier() == "User"),
        "expected User imported via project-local require, got {:?}",
        imported.iter().map(|cu| cu.fq_name()).collect::<Vec<_>>()
    );
    assert!(
        analyzer
            .referencing_files_of(&project.file("app/models/user.rb"))
            .contains(&project.file("app/main.rb"))
    );
}

#[test]
fn require_relative_resolves_same_and_parent_directory_targets() {
    let (project, analyzer) = ruby_analyzer_with_files(&[
        (
            "app/main.rb",
            r#"
require_relative "models/user"
require_relative "../lib/audit"
"#,
        ),
        (
            "app/models/user.rb",
            r#"
class User
end
"#,
        ),
        (
            "lib/audit.rb",
            r#"
class Audit
end
"#,
        ),
    ]);

    let imported = analyzer.imported_code_units_of(&project.file("app/main.rb"));
    let identifiers: Vec<_> = imported.iter().map(|cu| cu.identifier()).collect();
    assert!(identifiers.contains(&"User"), "got {identifiers:?}");
    assert!(identifiers.contains(&"Audit"), "got {identifiers:?}");
}

#[test]
fn require_resolves_directory_index_only_when_index_exists() {
    let (project, analyzer) = ruby_analyzer_with_files(&[
        (
            "app/main.rb",
            r#"
require "lib/widget"
require "lib/missing"
"#,
        ),
        (
            "lib/widget/index.rb",
            r#"
class Widget
end
"#,
        ),
        (
            "lib/missing/not_index.rb",
            r#"
class Missing
end
"#,
        ),
    ]);

    let imported = analyzer.imported_code_units_of(&project.file("app/main.rb"));
    assert!(
        imported.iter().any(|cu| cu.identifier() == "Widget"),
        "expected Widget from lib/widget/index.rb, got {:?}",
        imported.iter().map(|cu| cu.fq_name()).collect::<Vec<_>>()
    );
    assert!(
        imported.iter().all(|cu| cu.identifier() != "Missing"),
        "did not expect non-index directory entry, got {:?}",
        imported.iter().map(|cu| cu.fq_name()).collect::<Vec<_>>()
    );
}

#[test]
fn require_relative_does_not_resolve_directory_index() {
    let (project, analyzer) = ruby_analyzer_with_files(&[
        (
            "app/main.rb",
            r#"
require_relative "../lib/widget"
"#,
        ),
        (
            "lib/widget/index.rb",
            r#"
class Widget
end
"#,
        ),
    ]);

    let imported = analyzer.imported_code_units_of(&project.file("app/main.rb"));
    assert!(
        imported.is_empty(),
        "require_relative must not resolve directory index files, got {imported:?}"
    );
    assert!(
        analyzer
            .referencing_files_of(&project.file("lib/widget/index.rb"))
            .is_empty()
    );
}

#[test]
fn unresolved_external_require_produces_no_edge() {
    let (project, analyzer) = ruby_analyzer_with_files(&[
        (
            "app/main.rb",
            r#"
require "json"

class App
end
"#,
        ),
        (
            "app/models/user.rb",
            r#"
class User
end
"#,
        ),
    ]);

    let imported = analyzer.imported_code_units_of(&project.file("app/main.rb"));
    assert!(imported.is_empty(), "got {imported:?}");
    assert!(
        analyzer
            .referencing_files_of(&project.file("app/models/user.rb"))
            .is_empty()
    );
}

#[test]
fn reverse_require_expansion_includes_indirect_importers() {
    let (project, analyzer) = ruby_analyzer_with_files(&[
        (
            "app/main.rb",
            r#"
require "app/services/user_service"
"#,
        ),
        (
            "app/services/user_service.rb",
            r#"
require "app/models/user"

class UserService
end
"#,
        ),
        (
            "app/models/user.rb",
            r#"
class User
end
"#,
        ),
    ]);

    let referencing = analyzer.referencing_files_of(&project.file("app/models/user.rb"));
    assert!(
        referencing.contains(&project.file("app/services/user_service.rb")),
        "expected direct importer, got {referencing:?}"
    );
    assert!(
        referencing.contains(&project.file("app/main.rb")),
        "expected indirect importer, got {referencing:?}"
    );
}

#[test]
fn cyclic_requires_do_not_return_target_as_its_own_referencer() {
    let (project, analyzer) = ruby_analyzer_with_files(&[
        (
            "app/a.rb",
            r#"
require "app/b"

class A
end
"#,
        ),
        (
            "app/b.rb",
            r#"
require "app/a"

class B
end
"#,
        ),
    ]);

    let a = project.file("app/a.rb");
    let b = project.file("app/b.rb");
    let referencing = analyzer.referencing_files_of(&a);
    assert!(
        referencing.contains(&b),
        "expected b.rb, got {referencing:?}"
    );
    assert!(
        !referencing.contains(&a),
        "a.rb must not reference itself through the cycle, got {referencing:?}"
    );
}

#[test]
fn import_info_records_both_require_forms() {
    let analyzer = analyzer();
    let main = file(&analyzer, "requires/main.rb");
    let imports = analyzer.import_info_of(&main);
    // require_relative "helper" and require "json"
    assert_eq!(imports.len(), 2, "got {imports:?}");
    assert!(
        imports
            .iter()
            .any(|i| i.raw_snippet.contains("require_relative"))
    );
    assert!(imports.iter().any(|i| i.raw_snippet.contains("\"json\"")));
}
