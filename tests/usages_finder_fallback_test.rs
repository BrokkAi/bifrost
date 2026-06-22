mod common;

use brokk_bifrost::hash::HashSet;
use brokk_bifrost::usages::{CandidateFileProvider, FuzzyResult, UsageFinder};
use brokk_bifrost::{
    CSharpAnalyzer, CodeUnit, CodeUnitType, IAnalyzer, JavascriptAnalyzer, Language, ProjectFile,
    TypescriptAnalyzer,
};
use common::InlineTestProject;

fn definition(analyzer: &dyn IAnalyzer, predicate: impl Fn(&CodeUnit) -> bool) -> CodeUnit {
    analyzer
        .all_declarations()
        .find(|unit| predicate(unit))
        .cloned()
        .expect("definition not found")
}

struct FixedCandidateProvider {
    files: HashSet<ProjectFile>,
}

impl CandidateFileProvider for FixedCandidateProvider {
    fn find_candidates(
        &self,
        _target: &CodeUnit,
        _analyzer: &dyn IAnalyzer,
    ) -> HashSet<ProjectFile> {
        self.files.clone()
    }
}

#[test]
fn usage_finder_returns_graph_success_without_regex_fallback() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("base.ts", "export class BaseClass {}\n")
        .file(
            "consumer.ts",
            r#"
import { BaseClass } from "./base";

export function build(): BaseClass {
    return new BaseClass();
}
"#,
        )
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    let base_file = project.file("base.ts");
    let target = definition(&analyzer, |unit| {
        unit.is_class() && unit.identifier() == "BaseClass" && unit.source() == &base_file
    });

    let hits = UsageFinder::new()
        .find_usages_default(&analyzer, std::slice::from_ref(&target))
        .into_either()
        .expect("graph success");

    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("consumer.ts")),
        "expected graph hit in importing TypeScript file"
    );
}

#[test]
fn usage_finder_reports_fallback_safe_graph_failure_without_regex() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Domain/Target.cs",
            r#"
namespace Domain {
    public class Target {
        public void Run() {}
        public void Execute() {
            Run();
        }
    }
}
"#,
        )
        .build();
    let analyzer = CSharpAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, |unit| unit.fq_name() == "Domain.Target.Run");

    let query = UsageFinder::new().query(&analyzer, std::slice::from_ref(&target), 1000, 1000);
    let diagnostic = query
        .graph_failure
        .as_ref()
        .expect("graph failure diagnostic");
    assert_eq!("CSharpUsageGraphStrategy", diagnostic.strategy);
    assert_eq!("unsafe_inference", diagnostic.reason_kind);

    assert!(
        matches!(query.result, FuzzyResult::Failure { .. }),
        "fallback-safe graph failure should surface as a failure, got {:?}",
        query.result
    );
}

#[test]
fn usage_finder_routes_unsupported_graph_language_directly_to_regex() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "app.js",
            r#"
export function run() {
    return Ghost();
}
"#,
        )
        .file("notes.txt", "Ghost\n")
        .build();
    let analyzer = JavascriptAnalyzer::from_project(project.project().clone());
    let target = CodeUnit::with_signature(
        project.file("notes.txt"),
        CodeUnitType::Function,
        "",
        "Ghost",
        None,
        true,
    );
    let provider = FixedCandidateProvider {
        files: [project.file("app.js")].into_iter().collect(),
    };

    let result = UsageFinder::new().query_with_provider(
        &analyzer,
        std::slice::from_ref(&target),
        Some(&provider),
        1000,
        1000,
    );

    assert!(
        matches!(result.result, FuzzyResult::Success { .. }),
        "unsupported graph language should go directly to regex, got {:?}",
        result.result
    );
    assert_eq!(1, result.result.into_either().expect("regex success").len());
}
