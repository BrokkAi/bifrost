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
fn usage_finder_reports_csharp_unproven_sites_without_regex_failure() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Domain/Target.cs",
            r#"
namespace Domain {
    public class Target {
        public void Run() {}
    }
}
"#,
        )
        .file(
            "App/Consumer.cs",
            r#"
using Domain;

namespace App {
    public class Consumer {
        public void Execute(dynamic value) {
            value.Run();
        }
    }
}
"#,
        )
        .build();
    let analyzer = CSharpAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, |unit| unit.fq_name() == "Domain.Target.Run");

    let query = UsageFinder::new().query(&analyzer, std::slice::from_ref(&target), 1000, 1000);
    assert!(
        query.graph_failure.is_none(),
        "unproven C# sites should not surface as a graph failure: {:?}",
        query.graph_failure
    );

    match query.result {
        FuzzyResult::Success {
            hits_by_overload,
            unproven_total_by_overload,
            ..
        } => {
            assert!(
                hits_by_overload
                    .get(&target)
                    .is_none_or(|hits| hits.is_empty()),
                "dynamic receiver must not be a proven hit"
            );
            assert_eq!(Some(&1), unproven_total_by_overload.get(&target));
        }
        other => panic!("expected success with unproven C# site, got {other:#?}"),
    }
}

#[test]
fn usage_finder_reports_unsupported_language_without_regex() {
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

    let diagnostic = result
        .graph_failure
        .as_ref()
        .expect("unsupported-language diagnostic");
    assert_eq!("UsageFinder", diagnostic.strategy);
    assert_eq!("unsupported_target_language", diagnostic.reason_kind);
    assert!(
        matches!(
            result.result,
            FuzzyResult::Failure { ref reason_kind, .. }
                if reason_kind == "unsupported_target_language"
        ),
        "unsupported graph language should fail without regex, got {:?}",
        result.result
    );
}
