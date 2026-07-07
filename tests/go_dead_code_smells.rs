mod common;

use brokk_bifrost::IAnalyzer;
use brokk_bifrost::code_quality::{
    ReportDeadCodeAndUnusedAbstractionSmellsParams, report_dead_code_and_unused_abstraction_smells,
};
use common::{definition, go_analyzer_with_files};

fn report(
    analyzer: &dyn IAnalyzer,
    params: ReportDeadCodeAndUnusedAbstractionSmellsParams,
) -> String {
    report_dead_code_and_unused_abstraction_smells(analyzer, params).report
}

#[test]
fn go_dead_code_smell_reports_unused_unexported_helper() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "helper.go",
        r#"
package main

func helper() int {
    return 1
}

func entry() int {
    return 2
}
"#,
    )]);
    let helper = definition(&analyzer, "example.com/app.helper");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["helper.go".to_string()],
            fq_names: vec![helper.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("example.com/app.helper"), "{report}");
    assert!(report.contains("no non-self usages found"), "{report}");
    assert!(report.contains("| 0 | 0 |"), "{report}");
    assert!(
        report.contains("Go tree-sitter analysis and may be generated residue"),
        "{report}"
    );
}

#[test]
fn go_dead_code_smell_reports_one_call_unexported_helper() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "helper.go",
        r#"
package main

func wrapper() int {
    return leaf()
}

func leaf() int {
    return 1
}
"#,
    )]);
    let leaf = definition(&analyzer, "example.com/app.leaf");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["helper.go".to_string()],
            fq_names: vec![leaf.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("example.com/app.leaf"), "{report}");
    assert!(
        report.contains("one workspace inbound edge from example.com/app.wrapper"),
        "{report}"
    );
    assert!(report.contains("| 1 | 1 |"), "{report}");
}

#[test]
fn go_type_usage_from_another_file_prevents_finding() {
    let (_project, analyzer) = go_analyzer_with_files(&[
        (
            "model/model.go",
            r#"
package model

type Target struct{}
"#,
        ),
        (
            "main.go",
            r#"
package main

import "example.com/app/model"

func first() model.Target {
    return model.Target{}
}

func second() model.Target {
    return model.Target{}
}
"#,
        ),
    ]);
    let target = definition(&analyzer, "example.com/app/model.Target");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["model/model.go".to_string()],
            fq_names: vec![target.fq_name()],
            ..Default::default()
        },
    );

    assert!(
        !report.contains("example.com/app/model.Target |"),
        "{report}"
    );
    assert!(
        report.contains("No dead code or unused abstraction smells"),
        "{report}"
    );
}

#[test]
fn go_symbol_with_two_distinct_inbound_callers_is_not_flagged() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "helper.go",
        r#"
package main

func first() int {
    return helper()
}

func second() int {
    return helper()
}

func helper() int {
    return 1
}
"#,
    )]);
    let helper = definition(&analyzer, "example.com/app.helper");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["helper.go".to_string()],
            fq_names: vec![helper.fq_name()],
            ..Default::default()
        },
    );

    assert!(!report.contains("example.com/app.helper |"), "{report}");
    assert!(
        report.contains("No dead code or unused abstraction smells"),
        "{report}"
    );
}

#[test]
fn go_bulk_unproven_receiver_usage_is_inconclusive_not_dead() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "target.go",
        r#"
package main

type Target struct{}

func (Target) Run() {}

func execute(value any) {
    value.Run()
}
"#,
    )]);
    let run = definition(&analyzer, "example.com/app.Target.Run");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["target.go".to_string()],
            fq_names: vec![run.fq_name()],
            ..Default::default()
        },
    );

    assert!(
        report.contains("could not be proven or disproven"),
        "`any` receiver should make bulk evidence inconclusive: {report}"
    );
    assert!(
        !report.contains("| `function` | `example.com/app.Target.Run`"),
        "unproven-only bulk evidence must not report the target as dead: {report}"
    );
}

#[test]
fn go_runtime_and_test_entry_points_are_not_dead_code_candidates() {
    let (_project, analyzer) = go_analyzer_with_files(&[
        (
            "main.go",
            r#"
package main

func init() {}

func main() {}
"#,
        ),
        (
            "parser_test.go",
            r#"
package main

import "testing"

func TestParser(t *testing.T) {}

func BenchmarkParser(b *testing.B) {}

func ExampleParser() {}
"#,
        ),
    ]);

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["main.go".to_string(), "parser_test.go".to_string()],
            fq_names: vec![
                definition(&analyzer, "example.com/app.init").fq_name(),
                definition(&analyzer, "example.com/app.main").fq_name(),
                definition(&analyzer, "example.com/app.TestParser").fq_name(),
                definition(&analyzer, "example.com/app.BenchmarkParser").fq_name(),
                definition(&analyzer, "example.com/app.ExampleParser").fq_name(),
            ],
            ..Default::default()
        },
    );

    assert!(
        report.contains("No dead code or unused abstraction smells"),
        "{report}"
    );
    assert!(!report.contains("example.com/app.main |"), "{report}");
    assert!(!report.contains("example.com/app.init |"), "{report}");
    assert!(!report.contains("example.com/app.TestParser |"), "{report}");
    assert!(
        !report.contains("example.com/app.BenchmarkParser |"),
        "{report}"
    );
    assert!(
        !report.contains("example.com/app.ExampleParser |"),
        "{report}"
    );
}

#[test]
fn go_package_initializers_count_as_inbound_callers() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "helper.go",
        r#"
package main

var firstValue = helper()
var secondValue = helper()

type Target struct{}

var firstTarget = Target{}
var secondTarget = Target{}

func helper() int {
    return 1
}
"#,
    )]);
    let helper = definition(&analyzer, "example.com/app.helper");
    let target = definition(&analyzer, "example.com/app.Target");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["helper.go".to_string()],
            fq_names: vec![helper.fq_name(), target.fq_name()],
            ..Default::default()
        },
    );

    assert!(
        report.contains("No dead code or unused abstraction smells"),
        "{report}"
    );
    assert!(!report.contains("example.com/app.helper |"), "{report}");
    assert!(!report.contains("example.com/app.Target |"), "{report}");
}

#[test]
fn go_dead_code_smell_honors_usage_candidate_file_cap() {
    let (_project, analyzer) = go_analyzer_with_files(&[
        (
            "helper.go",
            r#"
package main

func helper() int {
    return 1
}
"#,
        ),
        (
            "other.go",
            r#"
package main

func other() int {
    return 2
}
"#,
        ),
    ]);
    let helper = definition(&analyzer, "example.com/app.helper");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["helper.go".to_string()],
            fq_names: vec![helper.fq_name()],
            max_usage_candidate_files: 1,
            ..Default::default()
        },
    );

    assert!(
        report.contains("Go usage graph candidate files exceeded cap 1"),
        "{report}"
    );
    assert!(!report.contains("example.com/app.helper |"), "{report}");
}

#[test]
fn go_dead_code_smell_honors_usage_cap() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "helper.go",
        r#"
package main

func first() int {
    return helper()
}

func second() int {
    return helper()
}

func helper() int {
    return 1
}
"#,
    )]);
    let helper = definition(&analyzer, "example.com/app.helper");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["helper.go".to_string()],
            fq_names: vec![helper.fq_name()],
            max_usages_per_symbol: 1,
            ..Default::default()
        },
    );

    assert!(
        report.contains("too many workspace inbound call sites (2, limit 1)"),
        "{report}"
    );
    assert!(!report.contains("example.com/app.helper |"), "{report}");
}

#[test]
fn go_exported_function_uses_conservative_wording_and_score() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "api.go",
        r#"
package main

func ExportedHook() {}
"#,
    )]);
    let hook = definition(&analyzer, "example.com/app.ExportedHook");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["api.go".to_string()],
            fq_names: vec![hook.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("example.com/app.ExportedHook"), "{report}");
    assert!(
        report.contains("exported Go symbol is unreferenced in workspace"),
        "{report}"
    );
    assert!(report.contains("0.55"), "{report}");
    assert!(!report.contains("generated residue"), "{report}");
}

#[test]
fn go_exported_type_uses_conservative_wording_and_score() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "api.go",
        r#"
package main

type ExportedType struct{}
"#,
    )]);
    let exported_type = definition(&analyzer, "example.com/app.ExportedType");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["api.go".to_string()],
            fq_names: vec![exported_type.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("example.com/app.ExportedType"), "{report}");
    assert!(
        report.contains("exported Go symbol is unreferenced in workspace"),
        "{report}"
    );
    assert!(report.contains("0.55"), "{report}");
    assert!(!report.contains("generated residue"), "{report}");
}

#[test]
fn go_field_candidate_stays_on_precise_path() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "model/album.go",
        r#"
package model

type Album struct {
    imageFiles string
}

func read(album Album) string {
    return album.imageFiles
}
"#,
    )]);
    let field = definition(&analyzer, "example.com/app/model.Album.imageFiles");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["model/album.go".to_string()],
            fq_names: vec![field.fq_name()],
            ..Default::default()
        },
    );

    assert!(
        report.contains("example.com/app/model.Album.imageFiles"),
        "{report}"
    );
    assert!(report.contains("only usage: model/album.go"), "{report}");
    assert!(!report.contains("one workspace inbound edge"), "{report}");
    assert!(!report.contains("no non-self usages found"), "{report}");
}
