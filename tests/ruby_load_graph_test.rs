// Project-local require/load graph (#264): resolve `require "a/b/c"` to project
// files, keep require_relative, support indirect reverse expansion, and leave
// external requires unresolved.

mod common;

use brokk_bifrost::{IAnalyzer, ImportAnalysisProvider, Language, RubyAnalyzer};
use common::InlineTestProject;

fn imported_identifiers(analyzer: &RubyAnalyzer, rel: &str) -> Vec<String> {
    let file = analyzer
        .get_analyzed_files()
        .into_iter()
        .find(|f| f.rel_path().to_string_lossy() == rel)
        .unwrap_or_else(|| panic!("no analyzed file {rel}"));
    analyzer
        .imported_code_units_of(&file)
        .into_iter()
        .map(|cu| cu.identifier().to_string())
        .collect()
}

#[test]
fn resolves_project_local_require_from_root() {
    let built = InlineTestProject::with_language(Language::Ruby)
        .file("app/models/user.rb", "class User\n  def save\n  end\nend\n")
        .file("main.rb", "require \"app/models/user\"\n\nUser.new\n")
        .build();
    let analyzer = RubyAnalyzer::new(built.project_dyn());

    let imported = imported_identifiers(&analyzer, "main.rb");
    assert!(imported.contains(&"User".to_string()), "got {imported:?}");
}

#[test]
fn resolves_project_local_require_under_lib() {
    let built = InlineTestProject::with_language(Language::Ruby)
        .file(
            "lib/helpers/format.rb",
            "module Format\n  def self.call\n  end\nend\n",
        )
        .file("run.rb", "require \"helpers/format\"\n\nFormat.call\n")
        .build();
    let analyzer = RubyAnalyzer::new(built.project_dyn());

    let imported = imported_identifiers(&analyzer, "run.rb");
    assert!(imported.contains(&"Format".to_string()), "got {imported:?}");
}

#[test]
fn require_relative_still_resolves() {
    let built = InlineTestProject::with_language(Language::Ruby)
        .file(
            "lib/helper.rb",
            "module Helper\n  def self.assist\n  end\nend\n",
        )
        .file(
            "lib/app.rb",
            "require_relative \"helper\"\n\nHelper.assist\n",
        )
        .build();
    let analyzer = RubyAnalyzer::new(built.project_dyn());

    let imported = imported_identifiers(&analyzer, "lib/app.rb");
    assert!(imported.contains(&"Helper".to_string()), "got {imported:?}");
}

#[test]
fn external_require_produces_no_edge() {
    let built = InlineTestProject::with_language(Language::Ruby)
        .file(
            "main.rb",
            "require \"json\"\nrequire \"set\"\n\nclass App\nend\n",
        )
        .build();
    let analyzer = RubyAnalyzer::new(built.project_dyn());

    let imported = imported_identifiers(&analyzer, "main.rb");
    assert!(
        imported.is_empty(),
        "stdlib requires must not resolve, got {imported:?}"
    );
}

#[test]
fn indirect_reverse_expansion_includes_transitive_requirers() {
    // a -> b -> c. Usages of declarations in c should consider a as a candidate.
    let built = InlineTestProject::with_language(Language::Ruby)
        .file("c.rb", "class C\n  def work\n  end\nend\n")
        .file("b.rb", "require_relative \"c\"\n\nclass B\nend\n")
        .file("a.rb", "require_relative \"b\"\n\nclass A\nend\n")
        .build();
    let analyzer = RubyAnalyzer::new(built.project_dyn());

    let c = built.file("c.rb");
    let referencing: Vec<String> = analyzer
        .referencing_files_of(&c)
        .into_iter()
        .map(|f| f.rel_path().to_string_lossy().to_string())
        .collect();
    assert!(
        referencing.contains(&"b.rb".to_string()),
        "direct, got {referencing:?}"
    );
    assert!(
        referencing.contains(&"a.rb".to_string()),
        "indirect, got {referencing:?}"
    );
}
