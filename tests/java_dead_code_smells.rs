mod common;

use brokk_bifrost::code_quality::{
    ReportDeadCodeAndUnusedAbstractionSmellsParams, report_dead_code_and_unused_abstraction_smells,
};
use brokk_bifrost::{
    AnalyzerDelegate, CodeUnit, IAnalyzer, JavaAnalyzer, Language, MultiAnalyzer, ScalaAnalyzer,
};
use common::InlineTestProject;
use std::collections::BTreeMap;

fn java_analyzer_with_files(
    files: &[(&str, &str)],
) -> (common::BuiltInlineTestProject, JavaAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::Java);
    for (path, contents) in files {
        builder = builder.file(*path, *contents);
    }
    let project = builder.build();
    let analyzer = JavaAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn mixed_jvm_analyzer_with_files(
    files: &[(&str, &str)],
) -> (common::BuiltInlineTestProject, MultiAnalyzer) {
    let mut builder = InlineTestProject::new();
    for (path, contents) in files {
        builder = builder.file(*path, *contents);
    }
    let project = builder.build();
    let java = JavaAnalyzer::from_project(project.project().clone());
    let scala = ScalaAnalyzer::from_project(project.project().clone());
    let multi = MultiAnalyzer::new(BTreeMap::from([
        (Language::Java, AnalyzerDelegate::Java(java)),
        (Language::Scala, AnalyzerDelegate::Scala(scala)),
    ]));
    (project, multi)
}

fn java_definition(analyzer: &JavaAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing Java definition for {fq_name}"))
}

fn report(
    analyzer: &dyn IAnalyzer,
    params: ReportDeadCodeAndUnusedAbstractionSmellsParams,
) -> String {
    report_dead_code_and_unused_abstraction_smells(analyzer, params).report
}

#[test]
fn java_dead_code_smell_reports_unused_private_helper() {
    let (_project, analyzer) = java_analyzer_with_files(&[(
        "com/example/Service.java",
        r#"
package com.example;

class Service {
    private void helper() {}

    void entry() {}
}
"#,
    )]);
    let helper = java_definition(&analyzer, "com.example.Service.helper");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["com/example/Service.java".to_string()],
            fq_names: vec![helper.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("com.example.Service.helper"), "{report}");
    assert!(report.contains("no non-self usages found"), "{report}");
    assert!(report.contains("| 0 | 0 |"), "{report}");
}

#[test]
fn java_dead_code_smell_reports_one_call_wrapper() {
    let (_project, analyzer) = java_analyzer_with_files(&[(
        "com/example/Service.java",
        r#"
package com.example;

class Service {
    void wrapper() {
        leaf();
    }

    void leaf() {}
}
"#,
    )]);
    let leaf = java_definition(&analyzer, "com.example.Service.leaf");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["com/example/Service.java".to_string()],
            fq_names: vec![leaf.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("com.example.Service.leaf"), "{report}");
    assert!(
        report.contains("one workspace inbound edge from com.example.Service.wrapper"),
        "{report}"
    );
    assert!(report.contains("| 1 | 0 |"), "{report}");
}

#[test]
fn java_dead_code_smell_does_not_flag_symbol_with_multiple_inbound_edges() {
    let (_project, analyzer) = java_analyzer_with_files(&[(
        "com/example/Service.java",
        r#"
package com.example;

class Service {
    void caller() {
        helper();
        helper();
    }

    void helper() {}
}
"#,
    )]);
    let helper = java_definition(&analyzer, "com.example.Service.helper");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["com/example/Service.java".to_string()],
            fq_names: vec![helper.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("No dead code"), "{report}");
    assert!(
        !report.contains("| `function` | `com.example.Service.helper`"),
        "{report}"
    );
}

#[test]
fn java_bulk_unproven_receiver_usage_is_inconclusive_not_dead() {
    let (_project, analyzer) = java_analyzer_with_files(&[(
        "com/example/Service.java",
        r#"
package com.example;

class Target {
    void run() {}
}

class Consumer {
    void execute(Object value) {
        value.run();
    }
}
"#,
    )]);
    let run = java_definition(&analyzer, "com.example.Target.run");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["com/example/Service.java".to_string()],
            fq_names: vec![run.fq_name()],
            ..Default::default()
        },
    );

    assert!(
        report.contains("could not be proven or disproven"),
        "untyped receiver should make bulk evidence inconclusive: {report}"
    );
    assert!(
        !report.contains("| `function` | `com.example.Target.run`"),
        "unproven-only bulk evidence must not report the target as dead: {report}"
    );
}

#[test]
fn java_dead_code_smell_honors_usage_candidate_file_cap() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Service.java",
            "package com.example; class Service { void helper() {} }\n",
        ),
        (
            "com/example/Other.java",
            "package com.example; class Other {}\n",
        ),
    ]);
    let helper = java_definition(&analyzer, "com.example.Service.helper");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec![
                "com/example/Service.java".to_string(),
                "com/example/Other.java".to_string(),
            ],
            fq_names: vec![helper.fq_name()],
            max_usage_candidate_files: 1,
            ..Default::default()
        },
    );

    assert!(
        report.contains("usage candidate files exceeded cap 1"),
        "{report}"
    );
    assert!(
        !report.contains("| `function` | `com.example.Service.helper`"),
        "{report}"
    );
}

#[test]
fn java_dead_code_smell_honors_usage_cap() {
    let (_project, analyzer) = java_analyzer_with_files(&[(
        "com/example/Service.java",
        r#"
package com.example;

class Service {
    void caller() {
        helper();
        helper();
    }

    void helper() {}
}
"#,
    )]);
    let helper = java_definition(&analyzer, "com.example.Service.helper");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["com/example/Service.java".to_string()],
            fq_names: vec![helper.fq_name()],
            max_usages_per_symbol: 1,
            ..Default::default()
        },
    );

    assert!(
        report.contains("too many workspace inbound call sites (2, limit 1)"),
        "{report}"
    );
    assert!(
        !report.contains("| `function` | `com.example.Service.helper`"),
        "{report}"
    );
}

#[test]
fn java_constructor_candidate_stays_on_precise_path() {
    let (_project, analyzer) = java_analyzer_with_files(&[(
        "com/example/Target.java",
        r#"
package com.example;

class Target {
    Target() {}

    static Target create() {
        return new Target();
    }
}
"#,
    )]);
    let constructor = java_definition(&analyzer, "com.example.Target.Target");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["com/example/Target.java".to_string()],
            fq_names: vec![constructor.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("com.example.Target.Target"), "{report}");
    assert!(
        report.contains("only usage: com/example/Target.java"),
        "{report}"
    );
    assert!(!report.contains("no non-self usages found"), "{report}");
}

#[test]
fn java_overloaded_methods_stay_on_precise_path() {
    let (_project, analyzer) = java_analyzer_with_files(&[(
        "com/example/Service.java",
        r#"
package com.example;

class Service {
    void call() {
        overloaded(1);
    }

    void overloaded() {}

    void overloaded(int value) {}
}
"#,
    )]);
    let overload = java_definition(&analyzer, "com.example.Service.overloaded");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["com/example/Service.java".to_string()],
            fq_names: vec![overload.fq_name()],
            ..Default::default()
        },
    );

    assert!(
        report.contains("com.example.Service.overloaded"),
        "{report}"
    );
    assert!(report.contains("no non-self usages found"), "{report}");
}

#[test]
fn java_class_candidate_uses_precise_path_when_scala_files_are_present() {
    let (_project, analyzer) = mixed_jvm_analyzer_with_files(&[
        (
            "com/example/Target.java",
            "package com.example; public class Target {}\n",
        ),
        (
            "app/Consumer.scala",
            r#"
package app

import com.example.Target

class Consumer {
  val target: Target = new Target()
}
"#,
        ),
    ]);

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec![
                "com/example/Target.java".to_string(),
                "app/Consumer.scala".to_string(),
            ],
            fq_names: vec!["com.example.Target".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("No dead code"), "{report}");
    assert!(
        !report.contains("| `class` | `com.example.Target`"),
        "{report}"
    );
}

#[test]
fn java_field_candidate_stays_on_precise_path_for_bare_identifier_reads() {
    let (_project, analyzer) = java_analyzer_with_files(&[(
        "com/example/Service.java",
        r#"
package com.example;

class Service {
    private int cached;

    int read() {
        return cached;
    }
}
"#,
    )]);
    let cached = java_definition(&analyzer, "com.example.Service.cached");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["com/example/Service.java".to_string()],
            fq_names: vec![cached.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("com.example.Service.cached"), "{report}");
    assert!(
        report.contains("only usage: com/example/Service.java"),
        "{report}"
    );
    assert!(!report.contains("no non-self usages found"), "{report}");
}

#[test]
fn java_method_candidate_stays_on_precise_path_when_static_imports_are_present() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Target.java",
            r#"
package com.example;

public class Target {
    static void run() {}
}
"#,
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

import static com.example.Target.run;

class Consumer {
    void call() {
        run();
    }
}
"#,
        ),
    ]);
    let run = java_definition(&analyzer, "com.example.Target.run");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec![
                "com/example/Target.java".to_string(),
                "com/example/Consumer.java".to_string(),
            ],
            fq_names: vec![run.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("com.example.Target.run"), "{report}");
    assert!(
        report.contains("only usage: com/example/Consumer.java"),
        "{report}"
    );
    assert!(!report.contains("no non-self usages found"), "{report}");
}

#[test]
fn java_public_api_uses_conservative_wording_and_score() {
    let (_project, analyzer) = java_analyzer_with_files(&[(
        "com/example/PublicApi.java",
        r#"
package com.example;

public class PublicApi {
    public void extensionPoint() {}
}
"#,
    )]);
    let extension_point = java_definition(&analyzer, "com.example.PublicApi.extensionPoint");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["com/example/PublicApi.java".to_string()],
            fq_names: vec![extension_point.fq_name()],
            ..Default::default()
        },
    );

    assert!(
        report.contains("com.example.PublicApi.extensionPoint"),
        "{report}"
    );
    assert!(
        report.contains("public Java symbol is unreferenced in workspace"),
        "{report}"
    );
    assert!(report.contains("0.55"), "{report}");
    assert!(!report.contains("generated residue"), "{report}");
}
