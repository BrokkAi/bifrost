mod common;

use brokk_bifrost::usages::{CppUsageGraphStrategy, FuzzyResult, UsageAnalyzer, UsageFinder};
use brokk_bifrost::{CodeUnit, CodeUnitType, CppAnalyzer, IAnalyzer, Language};
use common::InlineTestProject;

fn cpp_analyzer_with_files(
    files: &[(&str, &str)],
) -> (common::BuiltInlineTestProject, CppAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::Cpp);
    for (path, contents) in files {
        builder = builder.file(path, *contents);
    }
    let project = builder.build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn definition_by<F>(analyzer: &CppAnalyzer, mut predicate: F) -> CodeUnit
where
    F: FnMut(&CodeUnit) -> bool,
{
    let declarations = analyzer.get_all_declarations();
    declarations
        .iter()
        .find(|unit| predicate(unit))
        .cloned()
        .unwrap_or_else(|| panic!("missing matching C++ declaration in {declarations:#?}"))
}

fn class_definition(analyzer: &CppAnalyzer, name: &str) -> CodeUnit {
    definition_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Class && unit.identifier() == name
    })
}

fn function_definition(analyzer: &CppAnalyzer, name: &str) -> CodeUnit {
    definition_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Function && unit.identifier() == name
    })
}

fn field_definition(analyzer: &CppAnalyzer, name: &str) -> CodeUnit {
    definition_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Field && unit.identifier() == name
    })
}

fn member_function_definition(analyzer: &CppAnalyzer, owner: &str, name: &str) -> CodeUnit {
    definition_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.identifier() == name
            && analyzer
                .parent_of(unit)
                .is_some_and(|parent| parent.identifier() == owner)
    })
}

fn constructor_definition(analyzer: &CppAnalyzer, owner: &str) -> CodeUnit {
    definition_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.identifier() == owner
            && analyzer
                .parent_of(unit)
                .is_some_and(|parent| parent.identifier() == owner)
    })
}

#[test]
fn usage_finder_routes_cpp_targets_through_graph_strategy() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "target.h",
            r#"
class Target {
public:
    void run();
};

class Other {
public:
    void run();
};
"#,
        ),
        (
            "consumer.cpp",
            r#"
#include "target.h"

void call(Target& target, Other& other) {
    target.run();
    other.run();
}
"#,
        ),
    ]);

    let target = member_function_definition(&analyzer, "Target", "run");
    let hits = UsageFinder::new()
        .find_usages_default(&analyzer, std::slice::from_ref(&target))
        .into_either()
        .expect("cpp graph success");

    assert_eq!(1, hits.len());
    let hit = hits.iter().next().expect("one hit");
    assert_eq!(project.file("consumer.cpp"), hit.file);
    assert!(hit.snippet.contains("target.run()"));
}

#[test]
fn cpp_graph_finds_include_aware_namespaced_type_and_free_function_usages() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "api/target.h",
            r#"
namespace ns {
struct Target {};
void run(Target target);
}
"#,
        ),
        (
            "consumer.cpp",
            r#"
#include "api/target.h"

void call() {
    ns::Target target;
    ns::run(target);
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = CppUsageGraphStrategy::new();
    let class_target = class_definition(&analyzer, "Target");
    let function_target = function_definition(&analyzer, "run");

    let type_hits = strategy
        .find_usages(
            &analyzer,
            std::slice::from_ref(&class_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("type success");
    assert!(
        type_hits
            .iter()
            .any(|hit| hit.file == project.file("consumer.cpp")
                && hit.snippet.contains("ns::Target"))
    );

    let function_hits = strategy
        .find_usages(
            &analyzer,
            std::slice::from_ref(&function_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("free function success");
    assert_eq!(1, function_hits.len());
    assert!(
        function_hits
            .iter()
            .any(|hit| hit.file == project.file("consumer.cpp") && hit.snippet.contains("ns::run"))
    );
}

#[test]
fn cpp_graph_finds_constructors_methods_and_field_accesses_for_typed_receivers() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "target.h",
            r#"
struct Target {
    Target();
    void run();
    int value;
};
"#,
        ),
        (
            "consumer.cpp",
            r#"
#include "target.h"

void call(Target* ptr) {
    Target stack;
    Target braced{};
    auto heap = new Target();
    stack.run();
    ptr->run();
    stack.value = 1;
    int copy = ptr->value;
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = CppUsageGraphStrategy::new();
    let constructor = constructor_definition(&analyzer, "Target");
    let method = member_function_definition(&analyzer, "Target", "run");
    let field = field_definition(&analyzer, "value");

    let constructor_hits = strategy
        .find_usages(
            &analyzer,
            std::slice::from_ref(&constructor),
            &candidates,
            1000,
        )
        .into_either()
        .expect("constructor success");
    assert!(
        constructor_hits.len() >= 3,
        "expected stack, braced, and heap construction hits, got {constructor_hits:?}"
    );

    let method_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&method), &candidates, 1000)
        .into_either()
        .expect("method success");
    assert_eq!(2, method_hits.len());

    let field_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&field), &candidates, 1000)
        .into_either()
        .expect("field success");
    assert_eq!(2, field_hits.len());
}

#[test]
fn cpp_graph_finds_globals_enum_values_and_alias_references() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "target.h",
            r#"
struct Target {};
using Alias = Target;
extern int global_value;
enum Mode { Ready, Done };
"#,
        ),
        (
            "consumer.cpp",
            r#"
#include "target.h"

void call() {
    using LocalAlias = Target;
    Alias alias;
    Target target;
    int copy = global_value;
    Mode mode = Ready;
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = CppUsageGraphStrategy::new();
    let target_type = class_definition(&analyzer, "Target");
    let global = field_definition(&analyzer, "global_value");
    let enum_value = field_definition(&analyzer, "Ready");

    let type_hits = strategy
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target_type),
            &candidates,
            1000,
        )
        .into_either()
        .expect("type success");
    assert!(
        type_hits
            .iter()
            .any(|hit| hit.file == project.file("consumer.cpp")
                && hit.snippet.contains("using LocalAlias = Target"))
    );
    assert!(type_hits.iter().any(
        |hit| hit.file == project.file("consumer.cpp") && hit.snippet.contains("Target target")
    ));

    let global_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&global), &candidates, 1000)
        .into_either()
        .expect("global success");
    assert_eq!(1, global_hits.len());

    let enum_hits = strategy
        .find_usages(
            &analyzer,
            std::slice::from_ref(&enum_value),
            &candidates,
            1000,
        )
        .into_either()
        .expect("enum value success");
    assert_eq!(1, enum_hits.len());
}

#[test]
fn cpp_graph_rejects_unrelated_same_name_without_include_visibility() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        ("target.h", "struct Target { void run(); };\n"),
        (
            "consumer.cpp",
            r#"
struct Target { void run(); };

void call(Target& target) {
    target.run();
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.identifier() == "run"
            && unit.source().rel_path().to_string_lossy() == "target.h"
    });
    let result = CppUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    assert!(
        result.into_either().is_err(),
        "unproven same-name receiver should force fallback"
    );
}

#[test]
fn cpp_graph_respects_candidate_files_and_max_usages() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        ("target.h", "struct Target { void run(); };\n"),
        (
            "one.cpp",
            r#"
#include "target.h"
void one(Target& target) { target.run(); }
"#,
        ),
        (
            "two.cpp",
            r#"
#include "target.h"
void two(Target& target) { target.run(); }
"#,
        ),
    ]);

    let target = member_function_definition(&analyzer, "Target", "run");
    let restricted_candidates = [project.file("one.cpp")].into_iter().collect();
    let strategy = CppUsageGraphStrategy::new();
    let hits = strategy
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &restricted_candidates,
            1000,
        )
        .into_either()
        .expect("restricted success");
    assert_eq!(1, hits.len());
    assert_eq!(project.file("one.cpp"), hits.iter().next().unwrap().file);

    let all_candidates = analyzer.get_analyzed_files().into_iter().collect();
    let result = strategy.find_usages(&analyzer, std::slice::from_ref(&target), &all_candidates, 1);
    assert!(matches!(
        result,
        FuzzyResult::TooManyCallsites {
            total_callsites: 2,
            limit: 1,
            ..
        }
    ));
}
