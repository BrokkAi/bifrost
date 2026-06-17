mod common;

use brokk_bifrost::code_quality::{
    ReportDeadCodeAndUnusedAbstractionSmellsParams, report_dead_code_and_unused_abstraction_smells,
};
use brokk_bifrost::{CSharpAnalyzer, CodeUnit, CodeUnitType, IAnalyzer, Language};
use common::InlineTestProject;

fn csharp_analyzer_with_files(
    files: &[(&str, &str)],
) -> (common::BuiltInlineTestProject, CSharpAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::CSharp);
    for (path, contents) in files {
        builder = builder.file(*path, *contents);
    }
    let project = builder.build();
    let analyzer = CSharpAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn definition_by<F>(analyzer: &CSharpAnalyzer, mut predicate: F) -> CodeUnit
where
    F: FnMut(&CodeUnit) -> bool,
{
    let declarations = analyzer.get_all_declarations();
    declarations
        .iter()
        .find(|unit| predicate(unit))
        .cloned()
        .unwrap_or_else(|| panic!("missing matching C# declaration in {declarations:#?}"))
}

fn csharp_definition(analyzer: &CSharpAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing C# definition for {fq_name}"))
}

fn member_function(analyzer: &CSharpAnalyzer, owner: &str, name: &str) -> CodeUnit {
    definition_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.identifier() == name
            && analyzer
                .parent_of(unit)
                .is_some_and(|parent| parent.fq_name() == owner)
    })
}

fn member_function_with_signature(
    analyzer: &CSharpAnalyzer,
    owner: &str,
    name: &str,
    signature: &str,
) -> CodeUnit {
    definition_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.identifier() == name
            && unit.signature() == Some(signature)
            && analyzer
                .parent_of(unit)
                .is_some_and(|parent| parent.fq_name() == owner)
    })
}

fn member_field(analyzer: &CSharpAnalyzer, owner: &str, name: &str) -> CodeUnit {
    definition_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Field
            && unit.identifier() == name
            && analyzer
                .parent_of(unit)
                .is_some_and(|parent| parent.fq_name() == owner)
    })
}

fn report(
    analyzer: &dyn IAnalyzer,
    params: ReportDeadCodeAndUnusedAbstractionSmellsParams,
) -> String {
    report_dead_code_and_unused_abstraction_smells(analyzer, params).report
}

#[test]
fn csharp_dead_code_smell_reports_unused_private_method() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[(
        "Service.cs",
        r#"
namespace App {
    class Service {
        private void Helper() {}
        void Entry() {}
    }
}
"#,
    )]);
    let helper = member_function(&analyzer, "App.Service", "Helper");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["Service.cs".to_string()],
            fq_names: vec![helper.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("App.Service.Helper"), "{report}");
    assert!(report.contains("no non-self usages found"), "{report}");
    assert!(report.contains("| 0 | 0 |"), "{report}");
    assert!(
        report.contains("C# tree-sitter analysis and may be generated residue"),
        "{report}"
    );
}

#[test]
fn csharp_dead_code_smell_reports_one_call_method() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[(
        "Service.cs",
        r#"
namespace App {
    class Service {
        void Wrapper() {
            Leaf();
        }

        void Leaf() {}
    }
}
"#,
    )]);
    let leaf = member_function(&analyzer, "App.Service", "Leaf");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["Service.cs".to_string()],
            fq_names: vec![leaf.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("App.Service.Leaf"), "{report}");
    assert!(
        report.contains("one workspace inbound edge from App.Service.Wrapper"),
        "{report}"
    );
    assert!(report.contains("| 1 | 0 |"), "{report}");
}

#[test]
fn csharp_type_usage_from_another_file_prevents_finding() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Domain/Target.cs",
            "namespace Domain { public class Target {} }\n",
        ),
        (
            "App/Consumer.cs",
            r#"
using Domain;

namespace App {
    class Consumer {
        Target First() { return new Target(); }
        Target Second() { return new Target(); }
    }
}
"#,
        ),
    ]);
    let target = csharp_definition(&analyzer, "Domain.Target");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["Domain/Target.cs".to_string()],
            fq_names: vec![target.fq_name()],
            ..Default::default()
        },
    );

    assert!(!report.contains("Domain.Target |"), "{report}");
    assert!(
        report.contains("No dead code or unused abstraction smells"),
        "{report}"
    );
}

#[test]
fn csharp_symbol_with_two_distinct_inbound_callers_is_not_flagged() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[(
        "Service.cs",
        r#"
namespace App {
    class Service {
        int First() { return Helper(); }
        int Second() { return Helper(); }
        int Helper() { return 1; }
    }
}
"#,
    )]);
    let helper = member_function(&analyzer, "App.Service", "Helper");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["Service.cs".to_string()],
            fq_names: vec![helper.fq_name()],
            ..Default::default()
        },
    );

    assert!(!report.contains("App.Service.Helper |"), "{report}");
    assert!(
        report.contains("No dead code or unused abstraction smells"),
        "{report}"
    );
}

#[test]
fn csharp_dead_code_smell_honors_usage_candidate_file_cap() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Service.cs",
            r#"
namespace App {
    class Service {
        void Helper() {}
    }
}
"#,
        ),
        ("Other.cs", "namespace App { class Other {} }\n"),
    ]);
    let helper = member_function(&analyzer, "App.Service", "Helper");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["Service.cs".to_string()],
            fq_names: vec![helper.fq_name()],
            max_usage_candidate_files: 1,
            ..Default::default()
        },
    );

    assert!(
        report.contains("usage candidate files exceeded cap 1"),
        "{report}"
    );
    assert!(!report.contains("App.Service.Helper |"), "{report}");
}

#[test]
fn csharp_dead_code_smell_honors_usage_cap() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[(
        "Service.cs",
        r#"
namespace App {
    class Service {
        int First() { return Helper(); }
        int Second() { return Helper(); }
        int Helper() { return 1; }
    }
}
"#,
    )]);
    let helper = member_function(&analyzer, "App.Service", "Helper");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["Service.cs".to_string()],
            fq_names: vec![helper.fq_name()],
            max_usages_per_symbol: 1,
            ..Default::default()
        },
    );

    assert!(
        report.contains("too many workspace inbound call sites (2, limit 1)"),
        "{report}"
    );
    assert!(!report.contains("App.Service.Helper |"), "{report}");
}

#[test]
fn csharp_public_api_uses_conservative_wording_and_score() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[(
        "Api.cs",
        r#"
namespace App {
    public class Api {
        public void ExtensionPoint() {}
    }
}
"#,
    )]);
    let extension_point = member_function(&analyzer, "App.Api", "ExtensionPoint");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["Api.cs".to_string()],
            fq_names: vec![extension_point.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("App.Api.ExtensionPoint"), "{report}");
    assert!(
        report.contains("public C# symbol is unreferenced in workspace"),
        "{report}"
    );
    assert!(report.contains("0.55"), "{report}");
    assert!(!report.contains("generated residue"), "{report}");
}

#[test]
fn csharp_public_class_with_private_member_uses_conservative_wording() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[(
        "Api.cs",
        r#"
namespace App {
    public class Api {
        private readonly int value;
    }
}
"#,
    )]);
    let api = csharp_definition(&analyzer, "App.Api");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["Api.cs".to_string()],
            fq_names: vec![api.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("App.Api"), "{report}");
    assert!(
        report.contains("public C# symbol is unreferenced in workspace"),
        "{report}"
    );
    assert!(report.contains("0.55"), "{report}");
    assert!(!report.contains("generated residue"), "{report}");
}

#[test]
fn csharp_constructor_candidate_stays_on_precise_path() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[(
        "Target.cs",
        r#"
namespace App {
    class Target {
        public Target() {}
    }

    class Consumer {
        Target Build() { return new Target(); }
    }
}
"#,
    )]);
    let constructor = member_function(&analyzer, "App.Target", "Target");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["Target.cs".to_string()],
            fq_names: vec![constructor.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("App.Target.Target"), "{report}");
    assert!(report.contains("only usage: Target.cs"), "{report}");
    assert!(!report.contains("one workspace inbound edge"), "{report}");
}

#[test]
fn csharp_overloaded_methods_stay_on_precise_path() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[(
        "Service.cs",
        r#"
namespace App {
    class Service {
        void Use() {
            Run(1);
        }

        void Run() {}
        void Run(int value) {}
    }
}
"#,
    )]);
    let one_arg = member_function_with_signature(&analyzer, "App.Service", "Run", "(int)");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["Service.cs".to_string()],
            fq_names: vec![one_arg.fq_name()],
            ..Default::default()
        },
    );

    assert!(
        report.contains("CSharpUsageGraphStrategy: no proven structured hits"),
        "{report}"
    );
    assert!(!report.contains("one workspace inbound edge"), "{report}");
    assert!(!report.contains("no non-self usages found"), "{report}");
}

#[test]
fn csharp_field_candidate_stays_on_precise_path() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[(
        "Service.cs",
        r#"
namespace App {
    class Service {
        int value;
        int Read() { return value; }
    }
}
"#,
    )]);
    let field = member_field(&analyzer, "App.Service", "value");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["Service.cs".to_string()],
            fq_names: vec![field.fq_name()],
            ..Default::default()
        },
    );

    assert!(
        report.contains("CSharpUsageGraphStrategy: no proven structured hits"),
        "{report}"
    );
    assert!(!report.contains("one workspace inbound edge"), "{report}");
    assert!(!report.contains("no non-self usages found"), "{report}");
}

#[test]
fn csharp_static_using_method_stays_on_precise_path() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Target.cs",
            r#"
namespace Shared {
    public class Target {
        public static void Run() {}
    }
}
"#,
        ),
        (
            "Consumer.cs",
            r#"
using static Shared.Target;

namespace App {
    class Consumer {
        void Use() {
            Run();
        }
    }
}
"#,
        ),
    ]);
    let run = member_function(&analyzer, "Shared.Target", "Run");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["Target.cs".to_string()],
            fq_names: vec![run.fq_name()],
            ..Default::default()
        },
    );

    assert!(!report.contains("no non-self usages found"), "{report}");
    assert!(!report.contains("one workspace inbound edge"), "{report}");
}

#[test]
fn csharp_static_using_with_whitespace_stays_on_precise_path() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Target.cs",
            r#"
namespace Shared {
    public class Target {
        public static void Run() {}
    }
}
"#,
        ),
        (
            "Consumer.cs",
            r#"
using	static Shared.Target;

namespace App {
    class Consumer {
        void Use() {
            Run();
        }
    }
}
"#,
        ),
    ]);
    let run = member_function(&analyzer, "Shared.Target", "Run");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["Target.cs".to_string()],
            fq_names: vec![run.fq_name()],
            ..Default::default()
        },
    );

    assert!(!report.contains("no non-self usages found"), "{report}");
    assert!(!report.contains("one workspace inbound edge"), "{report}");
}

#[test]
fn csharp_alias_using_method_stays_on_precise_path() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Target.cs",
            r#"
namespace Shared {
    public class Target {
        public static void Run() {}
    }
}
"#,
        ),
        (
            "Consumer.cs",
            r#"
using Alias = Shared.Target;

namespace App {
    class Consumer {
        void Use() {
            Alias.Run();
        }
    }
}
"#,
        ),
    ]);
    let run = member_function(&analyzer, "Shared.Target", "Run");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["Target.cs".to_string()],
            fq_names: vec![run.fq_name()],
            ..Default::default()
        },
    );

    assert!(!report.contains("no non-self usages found"), "{report}");
    assert!(!report.contains("one workspace inbound edge"), "{report}");
}

#[test]
fn csharp_main_and_test_methods_are_not_dead_code_candidates() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[(
        "Program.cs",
        r#"
using Xunit;

namespace App {
    class Program {
        static void Main(string[] args) {}

        [Xunit.Fact]
        public void TestParser() {}
    }
}
"#,
    )]);
    let main = member_function(&analyzer, "App.Program", "Main");
    let test = member_function(&analyzer, "App.Program", "TestParser");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["Program.cs".to_string()],
            fq_names: vec![main.fq_name(), test.fq_name()],
            ..Default::default()
        },
    );

    assert!(
        report.contains("No dead code or unused abstraction smells"),
        "{report}"
    );
    assert!(!report.contains("App.Program.Main |"), "{report}");
    assert!(!report.contains("App.Program.TestParser |"), "{report}");
}

#[test]
fn csharp_non_static_main_is_still_dead_code_candidate() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[(
        "Worker.cs",
        r#"
namespace App {
    class Worker {
        private void Main() {}
    }
}
"#,
    )]);
    let main = member_function(&analyzer, "App.Worker", "Main");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["Worker.cs".to_string()],
            fq_names: vec![main.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("App.Worker.Main"), "{report}");
    assert!(report.contains("no non-self usages found"), "{report}");
}
