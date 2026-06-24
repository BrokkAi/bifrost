// require / require_relative resolution. Covers ISC-6.

use brokk_bifrost::{IAnalyzer, ImportAnalysisProvider, ProjectFile, RubyAnalyzer, TestProject};

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
