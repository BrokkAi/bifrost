mod common;

use brokk_bifrost::usages::{
    CppUsageGraphStrategy, ExplicitCandidateProvider, FuzzyResult, UsageAnalyzer, UsageFinder,
};
use brokk_bifrost::{
    AnalyzerConfig, CodeUnit, CodeUnitType, CppAnalyzer, IAnalyzer, Language, ProjectFile,
    WorkspaceAnalyzer,
};
use common::InlineTestProject;
use std::collections::BTreeSet;
use std::sync::Arc;

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

fn function_definition_in_package_with_arity(
    analyzer: &CppAnalyzer,
    package_name: &str,
    name: &str,
    arity: usize,
) -> CodeUnit {
    definition_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.package_name() == package_name
            && unit.identifier() == name
            && signature_arity(unit.signature()) == arity
    })
}

fn function_definition_with_short_name_and_arity(
    analyzer: &CppAnalyzer,
    short_name: &str,
    arity: usize,
) -> CodeUnit {
    definition_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.short_name() == short_name
            && signature_arity(unit.signature()) == arity
    })
}

fn function_definition_with_signature(
    analyzer: &CppAnalyzer,
    short_name: &str,
    signature: &str,
) -> CodeUnit {
    definition_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.short_name() == short_name
            && unit.signature() == Some(signature)
    })
}

fn parity_overload_analyzer() -> (common::BuiltInlineTestProject, CppAnalyzer) {
    cpp_analyzer_with_files(&[
        (
            "include/parity.h",
            r#"#pragma once
#include <string>
namespace parity {
struct AuditSink {
    std::string last;
    void record(const std::string& value);
};
class BaseHandler {
public:
    virtual ~BaseHandler() = default;
    virtual std::string handle(const std::string& name) = 0;
};
class ConsoleHandler : public BaseHandler {
public:
    explicit ConsoleHandler(AuditSink& sink);
    std::string handle(const std::string& name) override;
private:
    AuditSink& sink_;
};
std::string format(const std::string& value);
std::string format(int value);
} // namespace parity
"#,
        ),
        (
            "src/parity.cpp",
            r#"#include "parity.h"
namespace parity {
void AuditSink::record(const std::string& value) { last = value; }
ConsoleHandler::ConsoleHandler(AuditSink& sink) : sink_(sink) {}
std::string ConsoleHandler::handle(const std::string& name) {
    sink_.record(name);
    return name;
}
std::string format(const std::string& value) { return "s:" + value; }
std::string format(int value) { return "i:" + std::to_string(value); }
} // namespace parity
"#,
        ),
        (
            "src/main.cpp",
            r#"#include "parity.h"
namespace app {
std::string run() {
    parity::AuditSink sink;
    parity::ConsoleHandler handler(sink);
    parity::BaseHandler& base = handler;
    auto first = base.handle("Ada");
    auto formatted = parity::format(first);
    auto number = parity::format(7);
    return formatted + number;
}
} // namespace app
"#,
        ),
    ])
}

fn parity_format_header_overload(analyzer: &CppAnalyzer, signature_fragment: &str) -> CodeUnit {
    definition_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.fq_name() == "parity.format"
            && slash_path(unit.source()) == "include/parity.h"
            && unit
                .signature()
                .is_some_and(|signature| signature.contains(signature_fragment))
    })
}

fn field_definition(analyzer: &CppAnalyzer, name: &str) -> CodeUnit {
    definition_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Field && unit.identifier() == name
    })
}

fn field_definition_with_owner(analyzer: &CppAnalyzer, owner: &str, name: &str) -> CodeUnit {
    definition_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Field
            && unit.identifier() == name
            && analyzer
                .parent_of(unit)
                .is_some_and(|parent| parent.identifier() == owner)
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

fn member_function_definition_in_source(
    analyzer: &CppAnalyzer,
    owner: &str,
    name: &str,
    source: &str,
) -> CodeUnit {
    definition_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.identifier() == name
            && slash_path(unit.source()) == source
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

fn constructor_definition_with_arity(
    analyzer: &CppAnalyzer,
    owner: &str,
    arity: usize,
) -> CodeUnit {
    definition_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.identifier() == owner
            && signature_arity(unit.signature()) == arity
            && analyzer
                .parent_of(unit)
                .is_some_and(|parent| parent.identifier() == owner)
    })
}

#[test]
fn cpp_this_receiver_is_editor_only_member_usage() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[(
        "foo.cpp",
        r#"
struct Foo {
  void target() {}
  void caller() {
    this->target();
    target();
  }
};
"#,
    )]);

    let target = member_function_definition(&analyzer, "Foo", "target");
    let result = UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target));

    assert!(
        result.all_hits().is_empty(),
        "scan_usages/external surface must not count self-receiver hits: {:?}",
        result.all_hits()
    );
    let editor_hits = result.all_hits_including_imports();
    assert_eq!(2, editor_hits.len(), "editor hits: {editor_hits:?}");
    assert!(
        editor_hits
            .iter()
            .all(|hit| hit.snippet.contains("target();")),
        "editor hits: {editor_hits:?}"
    );
}

#[test]
fn cpp_self_receiver_hits_do_not_trigger_external_usage_cap() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[(
        "foo.cpp",
        r#"
struct Foo {
  void target() {}
  void caller() {
    this->target();
    target();
  }
};
"#,
    )]);

    let target = member_function_definition(&analyzer, "Foo", "target");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let result = CppUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        0,
    );

    assert!(
        !matches!(result, FuzzyResult::TooManyCallsites { .. }),
        "self-receiver hits are editor-visible but must not count against the external usage cap: {result:?}"
    );
    assert!(result.all_hits().is_empty(), "result: {result:?}");
    assert_eq!(2, result.all_hits_including_imports().len());
}

#[test]
fn cpp_explicit_same_owner_receiver_counts_as_external_usage() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[(
        "foo.cpp",
        r#"
struct Foo {
  void target() {}
  void caller(Foo& other) {
    other.target();
  }
};
"#,
    )]);

    let target = member_function_definition(&analyzer, "Foo", "target");
    let result = UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target));
    let hits = result.into_either().expect("cpp graph success");

    assert_eq!(1, hits.len(), "external hits: {hits:?}");
    assert!(
        hits.iter().any(|hit| hit.snippet.contains("other.target")),
        "explicit object receiver should remain an external usage: {hits:?}"
    );
}

#[test]
fn cpp_scan_reuses_enclosing_owner_resolution_within_each_file_batch() {
    const EXPECTED_HITS: usize = 4;
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "target.h",
            r#"namespace demo { struct Target {}; }
"#,
        ),
        (
            "consumer.cpp",
            r#"#include "target.h"
namespace demo {
struct Consumer {
    void run() {
        Target first;
        Target second;
        Target third;
        Target fourth;
    }
};
}
"#,
        ),
    ]);
    let target = class_definition(&analyzer, "Target");
    let consumer = project.file("consumer.cpp");
    let candidates = std::iter::once(consumer).collect();
    let strategy = CppUsageGraphStrategy::new();

    analyzer.reset_enclosing_parent_query_counts_for_test();
    let first_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("first C++ graph batch");
    let first_enclosing_queries = analyzer.enclosing_code_unit_query_count_for_test();
    let first_parent_queries = analyzer.sql_definitions_query_count_for_test();

    analyzer.reset_enclosing_parent_query_counts_for_test();
    let second_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("second C++ graph batch");
    let second_enclosing_queries = analyzer.enclosing_code_unit_query_count_for_test();
    let second_parent_queries = analyzer.sql_definitions_query_count_for_test();

    for hits in [&first_hits, &second_hits] {
        assert_eq!(hits.len(), EXPECTED_HITS, "type-reference hits: {hits:#?}");
        assert!(
            hits.iter()
                .all(|hit| hit.enclosing.fq_name() == "demo.Consumer.run"),
            "every hit should retain the same structured enclosing declaration: {hits:#?}"
        );
    }
    assert_eq!(
        (first_enclosing_queries, second_enclosing_queries),
        (EXPECTED_HITS, EXPECTED_HITS),
        "distinct hit nodes still require enclosing-code-unit lookup in each fresh scan batch"
    );
    assert_eq!(
        (first_parent_queries, second_parent_queries),
        (1, 1),
        "the enclosing declaration's owner should be resolved once per file scan, with no cache shared across batches"
    );
}

#[test]
fn cpp_scan_caches_missing_enclosing_owner_within_the_file_batch() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        ("target.h", "struct Target {};\n"),
        (
            "consumer.cpp",
            r#"#include "target.h"
void Missing::run() {
    Target first;
    Target second;
    Target third;
}
"#,
        ),
    ]);
    let target = class_definition(&analyzer, "Target");
    let candidates = std::iter::once(project.file("consumer.cpp")).collect();

    analyzer.reset_enclosing_parent_query_counts_for_test();
    let hits = CppUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("C++ graph batch with unresolved enclosing owner");

    assert_eq!(hits.len(), 3, "type-reference hits: {hits:#?}");
    assert!(
        hits.iter()
            .all(|hit| hit.enclosing.fq_name() == "Missing.run"),
        "the malformed out-of-line method still supplies one structured enclosing unit: {hits:#?}"
    );
    assert_eq!(analyzer.enclosing_code_unit_query_count_for_test(), 3);
    assert_eq!(
        analyzer.sql_definitions_query_count_for_test(),
        1,
        "a cached missing owner must not repeat the same SQL definition miss"
    );
}

fn signature_arity(signature: Option<&str>) -> usize {
    let Some(signature) = signature else {
        return 0;
    };
    let inner = signature
        .find('(')
        .and_then(|open| {
            signature[open + 1..]
                .find(')')
                .map(|close| &signature[open + 1..open + 1 + close])
        })
        .unwrap_or(signature)
        .trim();
    if inner.is_empty() {
        0
    } else {
        split_top_level_commas(inner).count()
    }
}

fn split_top_level_commas(value: &str) -> impl Iterator<Item = &str> {
    struct TopLevelCommaSplit<'a> {
        value: &'a str,
        start: usize,
        angle: usize,
        paren: usize,
        brace: usize,
        bracket: usize,
    }

    impl<'a> Iterator for TopLevelCommaSplit<'a> {
        type Item = &'a str;

        fn next(&mut self) -> Option<Self::Item> {
            if self.start > self.value.len() {
                return None;
            }
            for (offset, ch) in self.value[self.start..].char_indices() {
                let absolute = self.start + offset;
                match ch {
                    '<' => self.angle += 1,
                    '>' => self.angle = self.angle.saturating_sub(1),
                    '(' => self.paren += 1,
                    ')' => self.paren = self.paren.saturating_sub(1),
                    '{' => self.brace += 1,
                    '}' => self.brace = self.brace.saturating_sub(1),
                    '[' => self.bracket += 1,
                    ']' => self.bracket = self.bracket.saturating_sub(1),
                    ',' if self.angle == 0
                        && self.paren == 0
                        && self.brace == 0
                        && self.bracket == 0 =>
                    {
                        let item = self.value[self.start..absolute].trim();
                        self.start = absolute + ch.len_utf8();
                        return Some(item);
                    }
                    _ => {}
                }
            }
            let item = self.value[self.start..].trim();
            self.start = self.value.len() + 1;
            Some(item)
        }
    }

    TopLevelCommaSplit {
        value,
        start: 0,
        angle: 0,
        paren: 0,
        brace: 0,
        bracket: 0,
    }
    .filter(|item| !item.is_empty())
}

#[derive(Debug)]
struct HitSummary {
    file: String,
    line: String,
}

fn usage_hits(analyzer: &CppAnalyzer, target: &CodeUnit) -> Vec<HitSummary> {
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    CppUsageGraphStrategy::new()
        .find_usages(analyzer, std::slice::from_ref(target), &candidates, 1000)
        .into_either()
        .expect("cpp graph success")
        .into_iter()
        .map(hit_summary)
        .collect()
}

fn editor_usage_hits(analyzer: &CppAnalyzer, target: &CodeUnit) -> Vec<HitSummary> {
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    CppUsageGraphStrategy::new()
        .find_usages(analyzer, std::slice::from_ref(target), &candidates, 1000)
        .all_hits_including_imports()
        .into_iter()
        .map(hit_summary)
        .collect()
}

fn hit_summary(hit: brokk_bifrost::usages::UsageHit) -> HitSummary {
    let line = hit
        .file
        .read_to_string()
        .ok()
        .and_then(|source| {
            source
                .lines()
                .nth(hit.line.saturating_sub(1))
                .map(str::to_string)
        })
        .unwrap_or_default();
    HitSummary {
        file: slash_path(&hit.file),
        line,
    }
}

fn slash_path(file: &ProjectFile) -> String {
    file.rel_path()
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn assert_hit_contains(hits: &[HitSummary], file: &str, snippet: &str) {
    assert!(
        hits.iter()
            .any(|hit| hit.file == file && hit.line.contains(snippet)),
        "missing hit in {file} containing {snippet:?}; hits were {hits:#?}"
    );
}

fn assert_no_hit_contains(hits: &[HitSummary], snippet: &str) {
    assert!(
        hits.iter().all(|hit| !hit.line.contains(snippet)),
        "unexpected hit containing {snippet:?}; hits were {hits:#?}"
    );
}

fn assert_success_counts(
    result: FuzzyResult,
    target: &CodeUnit,
    proven_count: usize,
    unproven_count: usize,
) {
    let FuzzyResult::Success {
        hits_by_overload,
        unproven_total_by_overload,
        ..
    } = result
    else {
        panic!("expected success, got {result:?}");
    };
    assert_eq!(
        proven_count,
        hits_by_overload
            .get(target)
            .map(|hits| hits.len())
            .unwrap_or_default(),
        "proven hits: {hits_by_overload:#?}"
    );
    assert_eq!(
        unproven_count,
        unproven_total_by_overload
            .get(target)
            .copied()
            .unwrap_or_default(),
        "unproven hits: {unproven_total_by_overload:#?}"
    );
}

fn authoritative_exact_ranges(
    analyzer: &CppAnalyzer,
    targets: &[CodeUnit],
    candidate: &ProjectFile,
) -> BTreeSet<(usize, usize)> {
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(candidate.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(analyzer, targets, Some(&provider), 1, 1000);
    assert_eq!(
        query.candidate_files,
        std::iter::once(candidate.clone()).collect(),
        "authoritative query must remain limited to the explicit consumer"
    );
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = query.result
    else {
        panic!("expected authoritative C++ success");
    };
    hits_by_overload
        .values()
        .flatten()
        .map(|hit| {
            assert_eq!(&hit.file, candidate);
            (hit.start_offset, hit.end_offset)
        })
        .collect()
}

fn fixture_token_range(source: &str, labeled_line: &str, token: &str) -> (usize, usize) {
    let line_start = source
        .find(labeled_line)
        .unwrap_or_else(|| panic!("missing fixture line {labeled_line:?}"));
    let token_start = labeled_line
        .find(token)
        .unwrap_or_else(|| panic!("missing token {token:?} in fixture line {labeled_line:?}"));
    let start = line_start + token_start;
    (start, start + token.len())
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
fn cpp_graph_counts_unqualified_fields_inside_out_of_line_method_body() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "include/service.h",
            r#"#pragma once
#include <string>
namespace example {
struct Repository {
    std::string last;
    std::string save(const std::string& value);
};
}
"#,
        ),
        (
            "src/service.cpp",
            r#"#include "service.h"
namespace example {
std::string Repository::save(const std::string& value) {
    last = value;
    return last;
}
}
"#,
        ),
        (
            "src/main.cpp",
            r#"#include "service.h"
namespace example {
std::string run_demo() {
    Repository repository;
    return repository.last;
}
}
"#,
        ),
    ]);

    let last = field_definition_with_owner(&analyzer, "Repository", "last");
    let hits = usage_hits(&analyzer, &last);

    assert_eq!(3, hits.len(), "{hits:#?}");
    assert_hit_contains(&hits, "src/service.cpp", "last = value");
    assert_hit_contains(&hits, "src/service.cpp", "return last");
    assert_hit_contains(&hits, "src/main.cpp", "repository.last");
}

#[test]
fn cpp_graph_seeds_direct_initialized_receivers_for_method_usages() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "parity.h",
            r#"
namespace std { class string {}; }
struct Sink {};
class ConsoleHandler {
public:
    ConsoleHandler(Sink& sink);
    std::string handle(const std::string& value);
};
"#,
        ),
        (
            "main.cpp",
            r#"
#include "parity.h"

void call(Sink& sink) {
    ConsoleHandler handler(sink);
    ConsoleHandler braced{sink};
    handler.handle("Ben");
    braced.handle("Ada");
}
"#,
        ),
    ]);

    let handle = member_function_definition(&analyzer, "ConsoleHandler", "handle");
    let hits = usage_hits(&analyzer, &handle);

    assert_hit_contains(&hits, "main.cpp", "handler.handle(\"Ben\")");
    assert_hit_contains(&hits, "main.cpp", "braced.handle(\"Ada\")");
}

#[test]
fn cpp_graph_resolves_using_alias_concrete_override_receiver_call() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "include/parity.h",
            r#"#pragma once
#include <string>
namespace parity {
struct AuditSink {
    void record(const std::string& value);
};
class BaseHandler {
public:
    virtual ~BaseHandler() = default;
    virtual std::string handle(const std::string& name) = 0;
};
class ConsoleHandler : public BaseHandler {
public:
    explicit ConsoleHandler(AuditSink& sink);
    std::string handle(const std::string& name) override;
};
using HandlerAlias = ConsoleHandler;
}
"#,
        ),
        (
            "src/parity.cpp",
            r#"#include "parity.h"
namespace parity {
void AuditSink::record(const std::string& value) {}
ConsoleHandler::ConsoleHandler(AuditSink& sink) {}
std::string ConsoleHandler::handle(const std::string& name) {
    return name;
}
}
"#,
        ),
        (
            "src/main.cpp",
            r#"#include "parity.h"
namespace app {
std::string run() {
    parity::AuditSink sink;
    parity::HandlerAlias handler(sink);
    auto result = handler.handle("Ben");
    return result;
}
}
"#,
        ),
    ]);

    let handle = member_function_definition_in_source(
        &analyzer,
        "ConsoleHandler",
        "handle",
        "include/parity.h",
    );
    let hits = usage_hits(&analyzer, &handle);

    assert_eq!(2, hits.len(), "{hits:#?}");
    assert_hit_contains(&hits, "src/parity.cpp", "ConsoleHandler::handle");
    assert_hit_contains(&hits, "src/main.cpp", "handler.handle(\"Ben\")");
}

#[test]
fn cpp_graph_includes_out_of_line_member_qualifiers_as_class_usages() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "include/parity.h",
            r#"
#pragma once
#include <string>
namespace parity {
struct Sink {};
class ConsoleHandler {
public:
    explicit ConsoleHandler(Sink& s);
    std::string handle(const std::string& value);
    std::string alias_handle(const std::string& value);
};
using HandlerAlias = ConsoleHandler;
}
namespace other {
struct OtherSink {};
class ConsoleHandler {
public:
    explicit ConsoleHandler(OtherSink& s);
    std::string handle(const std::string& value);
};
}
"#,
        ),
        (
            "src/parity.cpp",
            r#"
#include "../include/parity.h"
namespace parity {
ConsoleHandler::ConsoleHandler(Sink& s) {}
std::string ConsoleHandler::handle(const std::string& value) { return value; }
std::string HandlerAlias::alias_handle(const std::string& value) { return value; }
}
"#,
        ),
        (
            "src/main.cpp",
            r#"
#include "../include/parity.h"
void run(parity::Sink& sink) {
    parity::HandlerAlias handler(sink);
}
"#,
        ),
    ]);

    let target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.identifier() == "ConsoleHandler"
            && unit.package_name() == "parity"
    });
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = CppUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("cpp graph success");
    let summaries = hits.iter().cloned().map(hit_summary).collect::<Vec<_>>();

    assert_hit_contains(
        &summaries,
        "src/parity.cpp",
        "ConsoleHandler::ConsoleHandler",
    );
    assert_hit_contains(&summaries, "src/parity.cpp", "ConsoleHandler::handle");
    assert_hit_contains(&summaries, "src/parity.cpp", "HandlerAlias::alias_handle");
    assert_hit_contains(&summaries, "src/main.cpp", "parity::HandlerAlias handler");
    assert_no_hit_contains(&summaries, "class ConsoleHandler");

    let selected_texts = hits
        .iter()
        .map(|hit| {
            let source = hit.file.read_to_string().expect("hit source");
            source[hit.start_offset..hit.end_offset].to_string()
        })
        .collect::<Vec<_>>();
    let selected_texts_by_file = hits
        .iter()
        .map(|hit| {
            let source = hit.file.read_to_string().expect("hit source");
            (
                slash_path(&hit.file),
                source[hit.start_offset..hit.end_offset].to_string(),
            )
        })
        .collect::<Vec<_>>();
    assert!(
        !selected_texts.iter().any(|text| text == "handle"),
        "class query must not select out-of-line member declarator parts: {selected_texts:?}"
    );
    assert!(
        !selected_texts
            .iter()
            .any(|text| text == "ConsoleHandler::handle"),
        "class query must select only the class qualifier, not the full member declarator: {selected_texts:?}"
    );
    assert_eq!(
        2,
        selected_texts_by_file
            .iter()
            .filter(|(file, text)| file == "src/parity.cpp" && text == "ConsoleHandler")
            .count(),
        "constructor and method qualifiers should both select the class token: {selected_texts_by_file:?}"
    );
    assert!(
        selected_texts_by_file
            .iter()
            .any(|(file, text)| file == "src/parity.cpp" && text == "HandlerAlias"),
        "alias-qualified member definition should select the alias qualifier as a class usage: {selected_texts_by_file:?}"
    );
    let main_source = project
        .file("src/main.cpp")
        .read_to_string()
        .expect("main source");
    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("src/main.cpp")
                && main_source[hit.start_offset..hit.end_offset] == *"parity::HandlerAlias"),
        "alias-typed declaration site should resolve through the alias: {selected_texts:?}"
    );

    let other_target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.identifier() == "ConsoleHandler"
            && unit.package_name() == "other"
    });
    let other_summaries = CppUsageGraphStrategy::new()
        .find_usages(&analyzer, &[other_target], &candidates, 1000)
        .into_either()
        .expect("cpp graph success")
        .into_iter()
        .map(hit_summary)
        .collect::<Vec<_>>();
    assert_no_hit_contains(&other_summaries, "HandlerAlias::alias_handle");
}

#[test]
fn cpp_graph_does_not_seed_namespace_scope_function_declarations_as_receivers() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "parity.h",
            r#"
namespace std { class string {}; }
struct Sink {};
class ConsoleHandler {
public:
    std::string handle(const std::string& value);
};
"#,
        ),
        (
            "main.cpp",
            r#"
#include "parity.h"

ConsoleHandler handler(Sink);

void call() {
    handler.handle("Ben");
}
"#,
        ),
    ]);

    let handle = member_function_definition(&analyzer, "ConsoleHandler", "handle");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let result = CppUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&handle),
        &candidates,
        1000,
    );

    assert!(
        result.all_hits().is_empty(),
        "namespace-scope prototype must not seed a receiver binding: {result:?}"
    );
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
fn authoritative_cpp_usage_finds_global_receiver_of_member_access() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "boot.h",
            r#"struct Boot {
    int cluster_size;
    Boot* next;
};
extern struct Boot bs;
extern struct Boot* bs_ptr;
"#,
        ),
        (
            "consumer.cpp",
            r#"#include "boot.h"

struct Other { Boot bs; };

int read_cluster_size() {
    return bs.cluster_size
        + bs.next->cluster_size
        + bs.next->next->cluster_size;
}

int read_other_cluster_size(Other& other) {
    return other.bs.cluster_size;
}

int read_shadowed_cluster_size() {
    Boot bs{};
    return bs.cluster_size;
}

int read_after_local_type() {
    struct Local { Boot bs; };
    return bs.cluster_size;
}

int read_pointer_cluster_size() {
    return bs_ptr->cluster_size;
}
"#,
        ),
    ]);

    let target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Field
            && unit.identifier() == "bs"
            && unit.source().rel_path().to_string_lossy() == "boot.h"
    });
    let pointer_target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Field
            && unit.identifier() == "bs_ptr"
            && unit.source().rel_path().to_string_lossy() == "boot.h"
    });
    let consumer = project.file("consumer.cpp");
    let source = consumer.read_to_string().expect("consumer source");
    let receiver_starts = source
        .match_indices("bs.")
        .map(|(start, _)| start)
        .collect::<Vec<_>>();
    assert_eq!(6, receiver_starts.len(), "test fixture receiver count");
    let global_receiver_starts = [
        receiver_starts[0],
        receiver_starts[1],
        receiver_starts[2],
        receiver_starts[5],
    ];
    let non_global_receiver_starts = [receiver_starts[3], receiver_starts[4]];
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));

    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        );
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = query.result
    else {
        panic!(
            "expected authoritative C++ usage success, got {:#?}",
            query.result
        );
    };
    let hits = hits_by_overload
        .get(&target)
        .expect("global target should have a proven-hit bucket");
    assert_eq!(
        global_receiver_starts.len(),
        hits.len(),
        "only global receiver-chain occurrences should be proven: {hits:#?}"
    );
    for receiver_start in &global_receiver_starts {
        let receiver_end = receiver_start + "bs".len();
        assert!(
            hits.iter().any(|hit| {
                hit.file == consumer
                    && hit.start_offset <= *receiver_start
                    && receiver_end <= hit.end_offset
            }),
            "authoritative inverse lookup should prove global receiver at {receiver_start}: {hits:#?}"
        );
    }
    for receiver_start in &non_global_receiver_starts {
        assert!(
            hits.iter().all(|hit| {
                !(hit.start_offset <= *receiver_start
                    && receiver_start + "bs".len() <= hit.end_offset)
            }),
            "member and shadowed receivers must not be attributed to global `bs`: {hits:#?}"
        );
    }

    let pointer_start = source
        .find("bs_ptr->cluster_size")
        .expect("direct global pointer receiver");
    let pointer_end = pointer_start + "bs_ptr".len();
    let pointer_query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&pointer_target),
            Some(&provider),
            1,
            1000,
        );
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = pointer_query.result
    else {
        panic!(
            "expected authoritative C++ pointer usage success, got {:#?}",
            pointer_query.result
        );
    };
    let pointer_hits = hits_by_overload
        .get(&pointer_target)
        .expect("global pointer target should have a proven-hit bucket");
    assert!(
        pointer_hits.iter().any(|hit| {
            hit.file == consumer
                && hit.start_offset <= pointer_start
                && pointer_end <= hit.end_offset
        }),
        "authoritative inverse lookup should prove direct global pointer receiver: {pointer_hits:#?}"
    );
}

#[test]
fn authoritative_cpp_usage_finds_terminal_fields_through_nested_member_chains() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "model.h",
            r#"struct Leaf { int value; };
struct Mid {
    Leaf leaf;
    Leaf* leaf_ptr;
    Leaf leaves[2];
};
struct Root {
    Mid mid;
    Mid* mid_ptr;
    int read_member_values() const;
};
extern Root* root;
extern Root by_value;
namespace ns { extern Root* qualified_root; }

struct WrongLeaf { int value; };
struct WrongMid {
    WrongLeaf leaf;
    WrongLeaf* leaf_ptr;
};
struct WrongRoot {
    WrongMid mid;
    WrongMid* mid_ptr;
};
extern WrongRoot* wrong;
namespace wrong_ns { extern WrongRoot* qualified_root; }
"#,
        ),
        (
            "consumer.cpp",
            r#"#include "model.h"

int read_values() {
    return root->mid.leaf.value
        + root->mid.leaf_ptr->value
        + root->mid_ptr->leaf.value
        + by_value.mid.leaf.value
        + (root->mid).leaf.value
        + root->mid.leaves[0].value;
}

int Root::read_member_values() const {
    return this->mid.leaf.value
        + (*this).mid_ptr->leaf.value
        + mid.leaf.value;
}

int read_qualified_value() {
    return ns::qualified_root->mid.leaf.value;
}

int read_wrong_value() {
    return wrong->mid.leaf.value;
}

int read_shadowed_value(WrongRoot* root) {
    return root->mid.leaf.value;
}

int read_wrong_qualified_value() {
    return wrong_ns::qualified_root->mid.leaf.value;
}
"#,
        ),
    ]);

    let target = field_definition_with_owner(&analyzer, "Leaf", "value");
    let consumer = project.file("consumer.cpp");
    let source = consumer.read_to_string().expect("consumer source");
    let mut terminal_starts = source
        .match_indices(".value")
        .map(|(start, _)| start + 1)
        .chain(source.match_indices("->value").map(|(start, _)| start + 2))
        .collect::<Vec<_>>();
    terminal_starts.sort_unstable();
    assert_eq!(13, terminal_starts.len(), "test fixture terminal count");
    let positive_starts = &terminal_starts[..10];
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));

    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        );
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = query.result
    else {
        panic!(
            "expected authoritative nested C++ field success, got {:#?}",
            query.result
        );
    };
    let hits = hits_by_overload
        .get(&target)
        .expect("Leaf.value should have a proven-hit bucket");
    assert_eq!(
        positive_starts.len(),
        hits.len(),
        "only terminals reached through Leaf should be proven: {hits:#?}"
    );
    for terminal_start in positive_starts {
        let terminal_end = terminal_start + "value".len();
        assert!(
            hits.iter().any(|hit| {
                hit.file == consumer
                    && hit.start_offset <= *terminal_start
                    && terminal_end <= hit.end_offset
            }),
            "nested Leaf.value terminal at {terminal_start} should be proven: {hits:#?}"
        );
    }
}

#[test]
fn authoritative_cpp_usage_finds_member_fields_nested_beneath_receiver_ancestors() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "model.h",
            r#"struct Leaf { void touch(); };
struct Holder {
    Leaf child;
    void touch();
    Holder* operator->();
    Leaf& operator[](int index);
};
enum class Mode { field };
struct Builder {
    Builder& set(const Holder& value);
    Builder& set_mode(Mode value);
    void finish();
};
Builder make_builder();
struct Owner {
    inline static Holder field;
    void exercise();
    void parameter_shadow(Holder field);
    void function_shadow();
    void block_shadow();
};
struct WrongOwner { inline static Holder field; };
struct Container { Holder field; };
extern Container container;
"#,
        ),
        (
            "consumer.cpp",
            r#"#include "model.h"

void Owner::exercise() {
    field.touch(); // positive-dot
    field->touch(); // positive-arrow
    field[0].touch(); // positive-subscript
    field.child.touch(); // positive-nested
    make_builder().set(field).finish(); // positive-fluent-bare-argument
    make_builder().set(Owner::field).finish(); // positive-fluent-qualified-argument

    make_builder().set_mode(Mode::field).finish(); // negative-enum-owner
    WrongOwner::field.touch(); // negative-static-owner
    container.field.touch(); // negative-selected-terminal
}

void Owner::parameter_shadow(Holder field) {
    field.touch(); // negative-parameter-shadow
}

void Owner::function_shadow() {
    Holder field;
    field.touch(); // negative-function-shadow
}

void Owner::block_shadow() {
    {
        Holder field;
        field.touch(); // negative-block-shadow
    }
    field.touch(); // positive-after-block-shadow
}
"#,
        ),
    ]);

    let target = field_definition_with_owner(&analyzer, "Owner", "field");
    let consumer = project.file("consumer.cpp");
    let source = consumer.read_to_string().expect("consumer source");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        );
    let FuzzyResult::Success {
        hits_by_overload,
        unproven_total_by_overload,
        ..
    } = query.result
    else {
        panic!(
            "expected authoritative member-field receiver success, got {:#?}",
            query.result
        );
    };
    let hits = hits_by_overload
        .get(&target)
        .expect("Owner.field should have a proven-hit bucket");
    let labeled_field_start = |label: &str| {
        let line_start = source
            .find(label)
            .unwrap_or_else(|| panic!("missing fixture line {label:?}"));
        line_start
            + label
                .rfind("field")
                .unwrap_or_else(|| panic!("missing field token in fixture line {label:?}"))
    };
    let positives = [
        "    field.touch(); // positive-dot",
        "    field->touch(); // positive-arrow",
        "    field[0].touch(); // positive-subscript",
        "    field.child.touch(); // positive-nested",
        "    make_builder().set(field).finish(); // positive-fluent-bare-argument",
        "    make_builder().set(Owner::field).finish(); // positive-fluent-qualified-argument",
        "    field.touch(); // positive-after-block-shadow",
    ];
    let negatives = [
        "    make_builder().set_mode(Mode::field).finish(); // negative-enum-owner",
        "    WrongOwner::field.touch(); // negative-static-owner",
        "    container.field.touch(); // negative-selected-terminal",
        "    field.touch(); // negative-parameter-shadow",
        "    field.touch(); // negative-function-shadow",
        "        field.touch(); // negative-block-shadow",
    ];
    let covers = |start: usize| {
        hits.iter().any(|hit| {
            hit.file == consumer
                && hit.start_offset <= start
                && start + "field".len() <= hit.end_offset
        })
    };
    let missing = positives
        .iter()
        .filter(|label| !covers(labeled_field_start(label)))
        .copied()
        .collect::<Vec<_>>();
    let false_positives = negatives
        .iter()
        .filter(|label| covers(labeled_field_start(label)))
        .copied()
        .collect::<Vec<_>>();

    assert!(
        missing.is_empty() && false_positives.is_empty() && hits.len() == positives.len(),
        "expected {} exact Owner.field hits; observed {} proven and {} unproven; missing={missing:#?}; false_positives={false_positives:#?}; hits={hits:#?}",
        positives.len(),
        hits.len(),
        unproven_total_by_overload
            .get(&target)
            .copied()
            .unwrap_or_default(),
    );
}

#[test]
fn authoritative_cpp_usage_matches_single_out_of_line_method_target_to_visible_declaration() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "graph.h",
            r#"namespace demo {
struct Rect {};
#define API(component)
class API(demo) Graph {
public:
    void Layout(Rect& rect, Graph* peer);
    void Layout(int mode);
};
void Layout(Rect& rect, Graph* peer);
class WrongGraph {
public:
    void Layout(Rect& rect, Graph* peer);
};
class Page {
public:
    void Draw(Rect& rect);
    void DrawShadowed(WrongGraph cpu_idle_, Rect& rect);
private:
    Graph cpu_idle_;
    Graph cpu_user_;
    WrongGraph wrong_;
};
}
"#,
        ),
        (
            "graph.cc",
            r#"#include "graph.h"
namespace demo {
void Graph::Layout(Rect& rect, Graph* peer) {}
void Graph::Layout(int mode) {}
void Layout(Rect& rect, Graph* peer) {}
}
"#,
        ),
        (
            "consumer.cc",
            r#"#include "graph.h"
namespace demo {
void Page::Draw(Rect& rect) {
    cpu_idle_.Layout(rect, &cpu_user_); // positive-visible-declaration
    cpu_idle_.Layout(7); // negative-overload
    wrong_.Layout(rect, &cpu_user_); // negative-owner
    Layout(rect, &cpu_user_); // negative-namespace-free-function
}
void Page::DrawShadowed(WrongGraph cpu_idle_, Rect& rect) {
    cpu_idle_.Layout(rect, &cpu_user_); // negative-parameter-shadow-owner
}
}
"#,
        ),
        (
            "hidden/graph.h",
            r#"namespace demo {
struct Rect {};
class Graph {
public:
    void Layout(Rect& rect, Graph* peer);
    void Layout(int mode);
};
}
"#,
        ),
        (
            "hidden_consumer.cc",
            r#"#include "hidden/graph.h"
void hidden_call(demo::Graph& graph, demo::Rect& rect) {
    graph.Layout(rect, &graph); // negative-hidden-same-fqn-owner
}
"#,
        ),
    ]);

    let method_in = |path: &str| {
        definition_by(&analyzer, |unit| {
            unit.kind() == CodeUnitType::Function
                && unit.fq_name() == "demo.Graph.Layout"
                && unit
                    .signature()
                    .is_some_and(|signature| signature.contains("Rect"))
                && slash_path(unit.source()) == path
        })
    };
    let implementation = method_in("graph.cc");
    let declaration = method_in("graph.h");
    assert_eq!(implementation.signature(), declaration.signature());
    let owner_in = |path: &str| {
        definition_by(&analyzer, |unit| {
            unit.kind() == CodeUnitType::Class
                && unit.fq_name() == "demo.Graph"
                && slash_path(unit.source()) == path
        })
    };
    let declaration_owner = owner_in("graph.h");
    assert_eq!(declaration_owner.fq_name(), "demo.Graph");
    assert!(
        analyzer
            .get_definitions("demo.Graph")
            .iter()
            .all(|unit| slash_path(unit.source()) != "graph.cc"),
        "the out-of-line target must not have a same-source class parent"
    );
    let targets = [implementation.clone()];
    let consumer = project.file("consumer.cc");
    let hidden_consumer = project.file("hidden_consumer.cc");
    let provider = ExplicitCandidateProvider::new(Arc::new(
        [consumer.clone(), hidden_consumer.clone()]
            .into_iter()
            .collect(),
    ));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(&analyzer, &targets, Some(&provider), 2, 1000);
    assert_eq!(
        query.candidate_files,
        [consumer.clone(), hidden_consumer.clone()]
            .into_iter()
            .collect(),
        "authoritative scanning must remain confined to consumer files"
    );
    let FuzzyResult::Success {
        hits_by_overload,
        unproven_total_by_overload,
        ..
    } = query.result
    else {
        panic!(
            "expected authoritative out-of-line method success, got {:#?}",
            query.result
        );
    };
    let hits = hits_by_overload
        .get(&implementation)
        .expect("implementation target should own the result bucket");

    assert_eq!(
        hits.len(),
        1,
        "only the matching visible declaration call should be proven: {hits:#?}"
    );
    assert!(
        hits.iter().any(|hit| hit.file == consumer && hit.line == 4),
        "the production-shaped member receiver should resolve through the visible header declaration: {hits:#?}"
    );
    assert!(
        hits.iter().all(|hit| hit.file != hidden_consumer),
        "the unimported same-FQN owner must not match by logical identity alone: {hits:#?}"
    );
    assert_eq!(
        unproven_total_by_overload
            .get(&implementation)
            .copied()
            .unwrap_or_default(),
        0,
        "wrong-owner, overload, and shadow calls are proven negatives; the hidden same-FQN call must not enter this target's candidate set"
    );
}

#[test]
fn persisted_authoritative_cpp_usage_is_invariant_to_equivalent_method_target_order() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("aaa/gurl_forward.h", "class GURL;\n")
        .file("base/gurl_forward.h", "class GURL;\n")
        .file(
            "url/gurl.h",
            r#"#pragma once
#define COMPONENT_EXPORT(component)
class COMPONENT_EXPORT(URL) GURL {
public:
    void Swap(GURL* other);
    void Swap(int value);
    bool is_empty() const;
};
class WrongGURL {
public:
    void Swap(GURL* other);
};
"#,
        )
        .file(
            "url/gurl.cc",
            r#"#include "url/gurl.h"
void GURL::Swap(GURL* other) {}
void GURL::Swap(int value) {}
void WrongGURL::Swap(GURL* other) {}
"#,
        )
        .file(
            "net/url_request/url_request.cc",
            r#"#include "aaa/gurl_forward.h"
#include "base/gurl_forward.h"
#include "url/gurl.h"
namespace net {
class URLRequest {
public:
    void BeforeRequestComplete();
private:
    GURL delegate_redirect_url_;
    WrongGURL wrong_;
};
void URLRequest::BeforeRequestComplete() {
    if (false) {
    } else if (!delegate_redirect_url_.is_empty()) {
        GURL new_url;
        new_url.Swap(&delegate_redirect_url_); // positive
        new_url.Swap(7); // negative-overload
        wrong_.Swap(&delegate_redirect_url_); // negative-owner
    }
}
}
"#,
        )
        .file(
            "hidden/gurl.h",
            r#"class GURL {
public:
    void Swap(GURL* other);
};
"#,
        )
        .file(
            "hidden/consumer.cc",
            r#"#include "hidden/gurl.h"
void hidden_call(GURL& value, GURL& other) {
    value.Swap(&other); // negative-non-visible-owner
}
"#,
        )
        .build();
    let project_handle = project.project_dyn();
    let cold =
        WorkspaceAnalyzer::build_persisted(Arc::clone(&project_handle), AnalyzerConfig::default())
            .expect("persisted analyzer should build");
    drop(cold);
    let reopened = WorkspaceAnalyzer::build_persisted(project_handle, AnalyzerConfig::default())
        .expect("persisted analyzer should reopen");
    let analyzer = reopened.analyzer();

    let method_in = |path: &str| {
        let declarations = analyzer.get_all_declarations();
        declarations
            .iter()
            .find(|unit| {
                unit.kind() == CodeUnitType::Function
                    && unit.fq_name() == "GURL.Swap"
                    && unit
                        .signature()
                        .is_some_and(|signature| signature.contains("GURL *"))
                    && slash_path(unit.source()) == path
            })
            .cloned()
            .unwrap_or_else(|| panic!("missing GURL.Swap(GURL*) in {path}: {declarations:#?}"))
    };
    let implementation = method_in("url/gurl.cc");
    let declaration = method_in("url/gurl.h");
    assert!(!implementation.is_synthetic());
    assert!(declaration.is_synthetic());
    assert_eq!(implementation.fq_name(), declaration.fq_name());
    assert_eq!(implementation.signature(), declaration.signature());
    let declaration_owner = analyzer
        .parent_of(&declaration)
        .expect("the synthetic header method should retain its structural GURL parent");
    assert_eq!(declaration_owner.fq_name(), "GURL");
    let implementation_owner = analyzer
        .parent_of(&implementation)
        .expect("the real out-of-line method should recover the directly included GURL parent");
    assert_eq!(
        implementation_owner, declaration_owner,
        "both persisted physical method representations should recover one logical owner"
    );

    let consumer = project.file("net/url_request/url_request.cc");
    let source = consumer.read_to_string().expect("consumer source");
    let positive = source
        .find("Swap(&delegate_redirect_url_); // positive")
        .unwrap();
    let negative_overload = source.find("Swap(7); // negative-overload").unwrap();
    let negative_owner = source
        .find("Swap(&delegate_redirect_url_); // negative-owner")
        .unwrap();
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let query = |targets: &[CodeUnit]| {
        UsageFinder::new()
            .with_authoritative_scope(true)
            .query_with_provider(analyzer, targets, Some(&provider), 1, 1)
            .result
    };

    for targets in [
        [declaration.clone(), implementation.clone()],
        [implementation.clone(), declaration.clone()],
    ] {
        let FuzzyResult::Success {
            hits_by_overload,
            unproven_total_by_overload,
            ..
        } = query(&targets)
        else {
            panic!("expected persisted authoritative success for {targets:#?}");
        };
        let hits = hits_by_overload
            .get(&targets[0])
            .expect("the first requested physical target should retain the result bucket");
        let covers = |start: usize| {
            hits.iter().any(|hit| {
                hit.file == consumer
                    && hit.start_offset <= start
                    && start + "Swap".len() <= hit.end_offset
            })
        };
        assert_eq!(
            hits.len(),
            1,
            "equivalent target order must prove exactly one semantic call: targets={targets:#?}, hits={hits:#?}"
        );
        assert!(
            covers(positive),
            "missing positive for {targets:#?}: {hits:#?}"
        );
        assert!(
            !covers(negative_overload),
            "wrong overload matched for {targets:#?}: {hits:#?}"
        );
        assert!(
            !covers(negative_owner),
            "wrong owner matched for {targets:#?}: {hits:#?}"
        );
        assert_eq!(
            unproven_total_by_overload
                .get(&targets[0])
                .copied()
                .unwrap_or_default(),
            0,
            "the overload and owner negatives should be proven exclusions"
        );
    }

    let hidden_consumer = project.file("hidden/consumer.cc");
    let hidden_provider = ExplicitCandidateProvider::new(Arc::new(
        std::iter::once(hidden_consumer.clone()).collect(),
    ));
    let hidden_query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            analyzer,
            &[implementation.clone(), declaration.clone()],
            Some(&hidden_provider),
            1,
            1000,
        );
    assert_eq!(
        hidden_query.candidate_files,
        std::iter::once(hidden_consumer).collect(),
        "the hidden-owner negative must scan only its explicit consumer"
    );
    let FuzzyResult::Success {
        hits_by_overload,
        unproven_total_by_overload,
        ..
    } = hidden_query.result
    else {
        panic!("expected hidden-owner authoritative success");
    };
    assert!(
        hits_by_overload
            .get(&implementation)
            .is_none_or(|hits| hits.is_empty()),
        "a same-FQN owner from a different, non-visible header must not match: {hits_by_overload:#?}"
    );
    assert_eq!(
        unproven_total_by_overload
            .get(&implementation)
            .copied()
            .unwrap_or_default(),
        1,
        "the physically non-visible same-FQN owner must remain conservative rather than becoming a proven target"
    );
}

#[test]
fn authoritative_cpp_usage_keeps_two_direct_owner_declarations_ambiguous() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "one/graph.h",
            "namespace demo { class Graph { public: void Layout(); }; }\n",
        ),
        (
            "two/graph.h",
            "namespace demo { class Graph { public: void Layout(); }; }\n",
        ),
        (
            "graph.cc",
            "#include \"one/graph.h\"\n#include \"two/graph.h\"\nnamespace demo { void Graph::Layout() {} }\n",
        ),
        (
            "consumer.cc",
            "#include \"one/graph.h\"\nvoid call(demo::Graph& graph) { graph.Layout(); }\n",
        ),
    ]);
    let target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.fq_name() == "demo.Graph.Layout"
            && slash_path(unit.source()) == "graph.cc"
    });
    let consumer = project.file("consumer.cc");
    let provider =
        ExplicitCandidateProvider::new(Arc::new([consumer.clone()].into_iter().collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        );
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = query.result
    else {
        panic!("expected ambiguous-owner success, got {:#?}", query.result);
    };
    assert!(
        hits_by_overload
            .get(&target)
            .is_none_or(|hits| hits.is_empty()),
        "two directly included exact-FQN owners must not choose an arbitrary declaration: {hits_by_overload:#?}"
    );
}

#[test]
fn authoritative_cpp_usage_does_not_choose_an_ambiguous_short_field_type() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "model.h",
            r#"namespace alpha { struct Leaf { int value; }; }
namespace beta { struct Leaf { int value; }; }
struct Root { Leaf leaf; };
extern Root root;
"#,
        ),
        (
            "consumer.cpp",
            r#"#include "model.h"

int read_value() {
    return root.leaf.value;
}
"#,
        ),
    ]);

    let alpha = definition_by(&analyzer, |unit| unit.fq_name() == "alpha.Leaf.value");
    let beta = definition_by(&analyzer, |unit| unit.fq_name() == "beta.Leaf.value");
    let consumer = project.file("consumer.cpp");
    let provider = ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer).collect()));

    for target in [alpha, beta] {
        let query = UsageFinder::new()
            .with_authoritative_scope(true)
            .query_with_provider(
                &analyzer,
                std::slice::from_ref(&target),
                Some(&provider),
                1,
                1000,
            );
        let FuzzyResult::Success {
            hits_by_overload, ..
        } = query.result
        else {
            panic!(
                "expected authoritative ambiguous-type C++ success, got {:#?}",
                query.result
            );
        };
        assert!(
            hits_by_overload
                .get(&target)
                .is_some_and(|hits| hits.is_empty()),
            "ambiguous short field type must not be assigned to either declaration: {hits_by_overload:#?}"
        );
    }
}

#[test]
fn authoritative_cpp_usage_does_not_reinterpret_untyped_global_as_same_named_type() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "model.h",
            r#"struct Leaf { int value; };
struct root { Leaf leaf; };
extern MissingType root;
"#,
        ),
        (
            "consumer.cpp",
            r#"#include "model.h"

int read_value() {
    return root.leaf.value;
}
"#,
        ),
    ]);

    let target = field_definition_with_owner(&analyzer, "Leaf", "value");
    let consumer = project.file("consumer.cpp");
    let provider = ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        );
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = query.result
    else {
        panic!(
            "expected authoritative unresolved-global C++ success, got {:#?}",
            query.result
        );
    };
    assert!(
        hits_by_overload
            .get(&target)
            .is_some_and(|hits| hits.is_empty()),
        "an unresolved global variable must not be reinterpreted as its same-named type: {hits_by_overload:#?}"
    );
}

#[test]
fn authoritative_cpp_usage_follows_inline_tagged_typedef_member_chain() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "model.h",
            r#"typedef struct stats_tag {
    int omcast;
} stats_alias;

typedef struct entry_tag {
    stats_alias stats;
} entry_alias;
"#,
        ),
        (
            "consumer.c",
            r#"#include "model.h"

int read_value(entry_alias *new_vals) {
    return new_vals->stats.omcast;
}
"#,
        ),
    ]);

    let target = field_definition_with_owner(&analyzer, "stats_tag", "omcast");
    let consumer = project.file("consumer.c");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        );
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = query.result
    else {
        panic!(
            "expected authoritative tagged-typedef C++ success, got {:#?}",
            query.result
        );
    };
    let hits = hits_by_overload
        .get(&target)
        .expect("stats_tag.omcast should have a proven-hit bucket");
    let terminal_start = consumer
        .read_to_string()
        .expect("consumer source")
        .rfind("omcast")
        .expect("terminal member");
    assert!(
        hits.iter().any(|hit| {
            hit.file == consumer
                && hit.start_offset <= terminal_start
                && terminal_start + "omcast".len() <= hit.end_offset
        }),
        "nested member through inline tagged typedefs should be proven: {hits:#?}"
    );
}

#[test]
fn authoritative_cpp_usage_follows_same_name_inline_tagged_typedef_chain() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "model.h",
            r#"typedef struct Leaf {
    int value;
} Leaf;

typedef struct Root {
    Leaf leaf;
} Root;
"#,
        ),
        (
            "consumer.c",
            r#"#include "model.h"

int read_value(Root *root) {
    return root->leaf.value;
}
"#,
        ),
    ]);

    let target = field_definition_with_owner(&analyzer, "Leaf", "value");
    let consumer = project.file("consumer.c");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        );
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = query.result
    else {
        panic!(
            "expected authoritative same-name tagged-typedef C++ success, got {:#?}",
            query.result
        );
    };
    let hits = hits_by_overload
        .get(&target)
        .expect("Leaf.value should have a proven-hit bucket");
    let terminal_start = consumer
        .read_to_string()
        .expect("consumer source")
        .rfind("value")
        .expect("terminal member");
    assert!(
        hits.iter().any(|hit| {
            hit.file == consumer
                && hit.start_offset <= terminal_start
                && terminal_start + "value".len() <= hit.end_offset
        }),
        "same-name inline tagged typedef chain should be proven: {hits:#?}"
    );
}

#[test]
fn authoritative_cpp_usage_follows_separate_typedef_direct_member_receiver() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "model.h",
            r#"struct Owner { int value; };
typedef struct Owner OwnerAlias;
"#,
        ),
        (
            "consumer.c",
            r#"#include "model.h"

int read(OwnerAlias *p) {
    return p->value;
}
"#,
        ),
    ]);

    let target = field_definition_with_owner(&analyzer, "Owner", "value");
    let consumer = project.file("consumer.c");
    let source = consumer.read_to_string().expect("consumer source");
    let terminal_start = source.rfind("value").expect("terminal member");
    let line_start = source[..terminal_start]
        .rfind('\n')
        .map_or(0, |newline| newline + 1);
    let line = source[..terminal_start]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1;
    let column = source[line_start..terminal_start].chars().count() + 1;
    let forward = brokk_bifrost::searchtools::get_definitions_by_location(
        &analyzer,
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                path: "consumer.c".to_string(),
                line: Some(line),
                column: Some(column),
            }],
        },
    );
    let forward_result = &forward.results[0];
    assert_eq!("resolved", forward_result.status, "{forward_result:#?}");
    assert!(
        forward_result
            .definitions
            .iter()
            .any(|definition| definition.fqn.as_deref() == Some("Owner.value")),
        "forward lookup should resolve the exact Owner.value declaration: {forward_result:#?}"
    );

    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        );
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = query.result
    else {
        panic!(
            "expected authoritative separate-typedef C++ success, got {:#?}",
            query.result
        );
    };
    let hits = hits_by_overload
        .get(&target)
        .expect("Owner.value should have a proven-hit bucket");
    assert!(
        hits.iter().any(|hit| {
            hit.file == consumer
                && hit.start_offset <= terminal_start
                && terminal_start + "value".len() <= hit.end_offset
        }),
        "direct member receiver through a separate typedef should be proven: {hits:#?}"
    );
}

#[test]
fn authoritative_cpp_usage_follows_canonical_typedef_type_references() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "model.h",
            r#"typedef struct Canonical { int value; } CanonicalAlias;
typedef CanonicalAlias CanonicalArray[1];
"#,
        ),
        (
            "consumer.c",
            r#"#include "model.h"

CanonicalAlias direct_value;
CanonicalArray array_value;
"#,
        ),
    ]);

    let target = class_definition(&analyzer, "Canonical");
    let consumer = project.file("consumer.c");
    let source = consumer.read_to_string().expect("consumer source");
    let token_starts = ["CanonicalAlias", "CanonicalArray"].map(|token| {
        let start = source.find(token).expect("consumer type token");
        let line_start = source[..start].rfind('\n').map_or(0, |newline| newline + 1);
        let line = source[..start]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1;
        let column = source[line_start..start].chars().count() + 1;
        let forward = brokk_bifrost::searchtools::get_definitions_by_location(
            &analyzer,
            brokk_bifrost::searchtools::GetDefinitionParams {
                references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                    path: "consumer.c".to_string(),
                    line: Some(line),
                    column: Some(column),
                }],
            },
        );
        let forward_result = &forward.results[0];
        assert_eq!(
            "resolved", forward_result.status,
            "forward lookup should resolve {token}: {forward_result:#?}"
        );
        assert!(
            forward_result
                .definitions
                .iter()
                .any(|definition| definition.fqn.as_deref() == Some("Canonical")),
            "forward lookup should canonicalize {token} to Canonical: {forward_result:#?}"
        );
        (token, start)
    });

    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        );
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = query.result
    else {
        panic!(
            "expected authoritative canonical-typedef C++ success, got {:#?}",
            query.result
        );
    };
    let hits = hits_by_overload
        .get(&target)
        .expect("Canonical should have a proven-hit bucket");
    for (token, start) in token_starts {
        assert!(
            hits.iter().any(|hit| {
                hit.file == consumer
                    && hit.start_offset <= start
                    && start + token.len() <= hit.end_offset
            }),
            "canonical type reference through {token} should be proven: {hits:#?}"
        );
    }
}

#[test]
fn authoritative_c_usage_preserves_typedef_alias_target_identity() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "aliases.h",
            r#"typedef unsigned char ByteAlias;
typedef struct ContainerTag { int value; } ContainerAlias;
"#,
        ),
        (
            "consumer.c",
            r#"#include "aliases.h"

ByteAlias make(void) {
    ByteAlias local = 0;
    return local;
}

void use(ContainerAlias *container) {
    (void)container;
}
"#,
        ),
    ]);

    let consumer = project.file("consumer.c");
    let source = consumer.read_to_string().expect("consumer source");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let mut missing_alias_usages = Vec::new();

    for (alias, expected_starts) in [
        (
            "ByteAlias",
            source
                .match_indices("ByteAlias")
                .map(|(start, _)| start)
                .collect::<Vec<_>>(),
        ),
        (
            "ContainerAlias",
            source
                .match_indices("ContainerAlias")
                .map(|(start, _)| start)
                .collect::<Vec<_>>(),
        ),
    ] {
        let target = definition_by(&analyzer, |unit| {
            unit.kind() == CodeUnitType::Class
                && unit.identifier() == alias
                && unit.source().rel_path().to_string_lossy() == "aliases.h"
        });
        assert_eq!(alias, target.fq_name());
        assert!(!expected_starts.is_empty(), "missing {alias} reference");

        if alias == "ByteAlias" {
            for &start in &expected_starts {
                let line_start = source[..start].rfind('\n').map_or(0, |newline| newline + 1);
                let line = source[..start]
                    .bytes()
                    .filter(|byte| *byte == b'\n')
                    .count()
                    + 1;
                let column = source[line_start..start].chars().count() + 1;
                let forward = brokk_bifrost::searchtools::get_definitions_by_location(
                    &analyzer,
                    brokk_bifrost::searchtools::GetDefinitionParams {
                        references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                            path: "consumer.c".to_string(),
                            line: Some(line),
                            column: Some(column),
                        }],
                    },
                );
                let forward_result = &forward.results[0];
                assert_eq!(
                    "resolved", forward_result.status,
                    "forward lookup should resolve {alias} at {start}: {forward_result:#?}"
                );
                assert!(
                    forward_result
                        .definitions
                        .iter()
                        .any(|definition| definition.fqn.as_deref() == Some(alias)),
                    "forward lookup should preserve primitive typedef alias target {alias} at {start}: {forward_result:#?}"
                );
            }
        }

        let query = UsageFinder::new()
            .with_authoritative_scope(true)
            .query_with_provider(
                &analyzer,
                std::slice::from_ref(&target),
                Some(&provider),
                1,
                1000,
            );
        let FuzzyResult::Success {
            hits_by_overload, ..
        } = query.result
        else {
            panic!(
                "expected authoritative typedef-alias C success for {alias}, got {:#?}",
                query.result
            );
        };
        let hits = hits_by_overload
            .get(&target)
            .unwrap_or_else(|| panic!("{alias} should have a proven-hit bucket"));
        for &start in &expected_starts {
            if !hits.iter().any(|hit| {
                hit.file == consumer
                    && hit.start_offset <= start
                    && start + alias.len() <= hit.end_offset
            }) {
                missing_alias_usages.push(format!(
                    "inverse {alias}@{start} was not proven (hits: {hits:#?})"
                ));
            }
        }
    }

    assert!(
        missing_alias_usages.is_empty(),
        "exact typedef-alias type_identifiers should resolve to their alias targets: {missing_alias_usages:#?}"
    );
}

#[test]
fn authoritative_c_usage_resolves_tagged_typedef_despite_member_type_reference() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "pcb.h",
            r#"typedef struct _PCB { int x; } PCB_t;
struct Holder {
    struct _PCB *pcb;
    struct Nested;
};
"#,
        ),
        (
            "consumer.c",
            r#"#include "pcb.h"

void configure(void) {
    PCB_t *pcbp = 0;
    (void)pcbp;
}
"#,
        ),
    ]);

    let target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.fq_name() == "_PCB"
            && unit.source().rel_path().to_string_lossy() == "pcb.h"
    });
    assert!(
        analyzer.get_all_declarations().iter().any(|unit| {
            unit.kind() == CodeUnitType::Class
                && unit.fq_name() == "Holder$Nested"
                && unit.source().rel_path().to_string_lossy() == "pcb.h"
        }),
        "a true nested forward declaration should remain represented"
    );
    assert!(
        analyzer.get_all_declarations().iter().any(|unit| {
            unit.kind() == CodeUnitType::Field
                && unit.fq_name() == "Holder.pcb"
                && unit.source().rel_path().to_string_lossy() == "pcb.h"
        }),
        "the real pointer field should remain persisted"
    );

    let consumer = project.file("consumer.c");
    let source = consumer.read_to_string().expect("consumer source");
    let token = "PCB_t";
    let start = source.find(token).expect("PCB_t type reference");
    let line_start = source[..start].rfind('\n').map_or(0, |newline| newline + 1);
    let line = source[..start]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1;
    let column = source[line_start..start].chars().count() + 1;
    let forward = brokk_bifrost::searchtools::get_definitions_by_location(
        &analyzer,
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                path: "consumer.c".to_string(),
                line: Some(line),
                column: Some(column),
            }],
        },
    );
    let forward_result = &forward.results[0];
    assert_eq!("resolved", forward_result.status, "{forward_result:#?}");
    assert!(
        forward_result
            .definitions
            .iter()
            .any(|definition| definition.fqn.as_deref() == Some("_PCB")),
        "forward lookup should resolve PCB_t to canonical _PCB: {forward_result:#?}"
    );

    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        );
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = query.result
    else {
        panic!(
            "expected authoritative canonical _PCB success, got {:#?}",
            query.result
        );
    };
    let hits = hits_by_overload
        .get(&target)
        .expect("_PCB should have a proven-hit bucket");
    assert!(
        hits.iter().any(|hit| {
            hit.file == consumer
                && hit.start_offset <= start
                && start + token.len() <= hit.end_offset
        }),
        "exact PCB_t type_identifier should resolve to canonical _PCB: {hits:#?}"
    );
}

#[test]
fn authoritative_cpp_usage_recovers_macro_decorated_function_return_type() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        ("routerstatus.h", "struct routerstatus_t { int value; };\n"),
        (
            "consumer.cpp",
            r#"#include "routerstatus.h"
#define STATIC static

STATIC const routerstatus_t *
choose(void) { return 0; }
"#,
        ),
    ]);

    let target = class_definition(&analyzer, "routerstatus_t");
    let consumer = project.file("consumer.cpp");
    let source = consumer.read_to_string().expect("consumer source");
    let token = "routerstatus_t";
    let token_start = source.find(token).expect("return type token");
    let line_start = source[..token_start]
        .rfind('\n')
        .map_or(0, |newline| newline + 1);
    let line = source[..token_start]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1;
    let column = source[line_start..token_start].chars().count() + 1;
    let forward = brokk_bifrost::searchtools::get_definitions_by_location(
        &analyzer,
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                path: "consumer.cpp".to_string(),
                line: Some(line),
                column: Some(column),
            }],
        },
    );
    let forward_result = &forward.results[0];
    assert_eq!("resolved", forward_result.status, "{forward_result:#?}");
    assert!(
        forward_result
            .definitions
            .iter()
            .any(|definition| definition.fqn.as_deref() == Some("routerstatus_t")),
        "forward lookup should resolve the exact recovered return type: {forward_result:#?}"
    );

    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        );
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = query.result
    else {
        panic!(
            "expected authoritative macro-return-type success, got {:#?}",
            query.result
        );
    };
    let hits = hits_by_overload
        .get(&target)
        .expect("routerstatus_t should have a proven-hit bucket");
    assert!(
        hits.iter().any(|hit| {
            hit.file == consumer
                && hit.start_offset <= token_start
                && token_start + token.len() <= hit.end_offset
        }),
        "macro-recovered return type should be proven: {hits:#?}"
    );
}

#[test]
fn authoritative_cpp_usage_owns_designated_initializer_fields() {
    // Reduced from arch/powerpc/kernel/cputable.c. The branch transitions are
    // significant: tree-sitter recovers the second cpu_features as an
    // init_declarator below ERROR rather than as a field_designator.
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "cpu_spec.h",
            r#"struct cpu_spec {
    int pvr_mask;
    int cpu_features;
};
"#,
        ),
        (
            "consumer.c",
            r#"#include "cpu_spec.h"
#define __initdata
#define DECLARE static

DECLARE int first = 1, second = 2;

static struct cpu_spec __initdata cpu_specs[] = {
#ifdef CONFIG_PPC_BOOK3S_64
    {   /* default match */
        .pvr_mask = 0x00000000,
        .pvr_value = 0x00000000,
        .cpu_name = "POWER4 (compatible)",
        .other_features = CPU_FTRS_COMPATIBLE,
        .cpu_user_features = COMMON_USER_PPC64,
        .mmu_features = MMU_FTRS_DEFAULT_HPTE_ARCH_V2,
        .icache_bsize = 128,
        .dcache_bsize = 128,
        .num_pmcs = 6,
        .pmc_type = PPC_PMC_IBM,
        .platform = "power4",
    }
#endif /* CONFIG_PPC_BOOK3S_64 */

#ifdef CONFIG_PPC32
#if CLASSIC_PPC
    {   /* 601 */
        .pvr_mask = 0xffff0000,
        .pvr_value = 0x00010000,
        .cpu_name = "601",
        .other_features = CPU_FTRS_PPC601,
        .cpu_user_features = COMMON_USER | PPC_FEATURE_601_INSTR |
            PPC_FEATURE_UNIFIED_CACHE | PPC_FEATURE_NO_TB,
        .mmu_features = MMU_FTR_HPTE_TABLE,
        .icache_bsize = 32,
        .dcache_bsize = 32,
        .machine_check = machine_check_generic,
        .platform = "ppc601",
    },
#endif /* CLASSIC_PPC */
#ifdef CONFIG_8xx
    {   /* 8xx */
        .pvr_mask = 0xffff0000,
        .pvr_value = 0x00500000,
        .cpu_name = "8xx",
        .other_features = CPU_FTRS_8XX,
        .cpu_user_features = PPC_FEATURE_32 | PPC_FEATURE_HAS_MMU,
        .mmu_features = MMU_FTR_TYPE_8xx,
        .icache_bsize = 16,
        .dcache_bsize = 16,
        .platform = "ppc823",
    },
#endif /* CONFIG_8xx */
#ifdef CONFIG_40x
    {   /* 403GC */
        .pvr_mask = 0xffffff00,
        .pvr_value = 0x00200200,
        .cpu_name = "403GC",
        .other_features = CPU_FTRS_40X,
        .cpu_user_features = PPC_FEATURE_32 | PPC_FEATURE_HAS_MMU,
        .mmu_features = MMU_FTR_TYPE_40x,
        .icache_bsize = 16,
        .dcache_bsize = 16,
        .machine_check = machine_check_4xx,
        .platform = "ppc403",
    },
    {   /* APM8018X */
        .pvr_mask = 0xffff0000,
        .pvr_value = 0x7ff11432,
        .cpu_name = "APM8018X",
        .other_features = CPU_FTRS_40X,
        .cpu_user_features = PPC_FEATURE_32 |
            PPC_FEATURE_HAS_MMU | PPC_FEATURE_HAS_4xxMAC,
        .mmu_features = MMU_FTR_TYPE_40x,
        .icache_bsize = 32,
        .dcache_bsize = 32,
        .machine_check = machine_check_4xx,
        .platform = "ppc405",
    },
    {   /* default match */
        .pvr_mask = 0x00000000,
        .pvr_value = 0x00000000,
        .cpu_name = "(generic 40x PPC)",
        .cpu_features = CPU_FTRS_40X,
        .cpu_user_features = PPC_FEATURE_32 |
            PPC_FEATURE_HAS_MMU | PPC_FEATURE_HAS_4xxMAC,
        .mmu_features = MMU_FTR_TYPE_40x,
        .icache_bsize = 32,
        .dcache_bsize = 32,
        .machine_check = machine_check_4xx,
        .platform = "ppc405",
    }

#endif /* CONFIG_40x */
#ifdef CONFIG_44x
    {
        .pvr_mask = 0xf0000fff,
        .pvr_value = 0x40000850,
        .cpu_name = "440GR Rev. A",
        .cpu_features = CPU_FTRS_44X,
        .cpu_user_features = COMMON_USER_BOOKE,
        .mmu_features = MMU_FTR_TYPE_44x,
        .icache_bsize = 32,
        .dcache_bsize = 32,
        .machine_check = machine_check_4xx,

int ordinary = 0;
"#,
        ),
    ]);

    let target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Field && unit.fq_name() == "cpu_spec.cpu_features"
    });
    let consumer = project.file("consumer.c");
    let source = consumer.read_to_string().expect("consumer source");
    let token = "cpu_features";
    let starts = source
        .match_indices(token)
        .map(|(start, _)| start)
        .collect::<Vec<_>>();
    assert_eq!(2, starts.len(), "test fixture designated initializer count");

    for start in &starts {
        let line_start = source[..*start]
            .rfind('\n')
            .map_or(0, |newline| newline + 1);
        let line = source[..*start]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1;
        let column = source[line_start..*start].chars().count() + 1;
        let forward = brokk_bifrost::searchtools::get_definitions_by_location(
            &analyzer,
            brokk_bifrost::searchtools::GetDefinitionParams {
                references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                    path: "consumer.c".to_string(),
                    line: Some(line),
                    column: Some(column),
                }],
            },
        );
        let result = &forward.results[0];
        assert_eq!("resolved", result.status, "{result:#?}");
        assert_eq!(
            vec![Some("cpu_spec.cpu_features")],
            result
                .definitions
                .iter()
                .map(|definition| definition.fqn.as_deref())
                .collect::<Vec<_>>(),
            "designated field must resolve only through its cpu_spec owner: {result:#?}"
        );
    }

    let declarations = analyzer.get_declarations(&consumer);
    for name in ["first", "second", "cpu_specs", "ordinary"] {
        assert!(
            declarations
                .iter()
                .any(|unit| unit.is_field() && unit.identifier() == name),
            "ordinary global {name} should remain indexed: {declarations:#?}"
        );
    }
    assert!(
        declarations
            .iter()
            .all(|unit| unit.fq_name() != "cpu_features"),
        "designators must not create a bare pseudo-global: {declarations:#?}"
    );

    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        );
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = query.result
    else {
        panic!(
            "expected authoritative designated-initializer success, got {:#?}",
            query.result
        );
    };
    let hits = hits_by_overload
        .get(&target)
        .expect("cpu_features should have a proven-hit bucket");
    for start in starts {
        assert!(
            hits.iter().any(|hit| {
                hit.file == consumer
                    && hit.start_offset <= start
                    && start + token.len() <= hit.end_offset
            }),
            "designated cpu_features at {start} should be proven: {hits:#?}"
        );
    }
}

#[test]
fn authoritative_cpp_usage_owns_structured_designator_forms() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "types.h",
            r#"struct cpu_spec { int cpu_features; };
struct wrapper { struct cpu_spec inner; };
"#,
        ),
        (
            "consumer.c",
            r#"#include "types.h"
void consume(struct cpu_spec value);
int cpu_features = 99;

void configure(void) {
    struct cpu_spec direct = { .cpu_features = 1 };
    struct cpu_spec array[] = { { .cpu_features = 2 } };
    consume((struct cpu_spec) { .cpu_features = 3 });
    struct wrapper nested = { .inner = { .cpu_features = 4 } };
}
"#,
        ),
        (
            "recovered_only.c",
            r#"#include "types.h"
static struct cpu_spec .cpu_features = 1;
"#,
        ),
    ]);

    let target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Field && unit.fq_name() == "cpu_spec.cpu_features"
    });
    let consumer = project.file("consumer.c");
    let recovered_only = project.file("recovered_only.c");
    assert!(
        analyzer
            .get_declarations(&recovered_only)
            .iter()
            .all(|unit| unit.identifier() != "cpu_features"),
        "a declaration containing only a recovered designator must not persist it"
    );
    let source = consumer.read_to_string().expect("consumer source");
    let token = "cpu_features";
    let all_starts = source
        .match_indices(token)
        .map(|(start, _)| start)
        .collect::<Vec<_>>();
    assert_eq!(5, all_starts.len(), "test fixture cpu_features count");
    let starts = all_starts[1..].to_vec();

    for (index, start) in starts.iter().enumerate() {
        let line_start = source[..*start]
            .rfind('\n')
            .map_or(0, |newline| newline + 1);
        let line = source[..*start]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1;
        let column = source[line_start..*start].chars().count() + 1;
        let forward = brokk_bifrost::searchtools::get_definitions_by_location(
            &analyzer,
            brokk_bifrost::searchtools::GetDefinitionParams {
                references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                    path: "consumer.c".to_string(),
                    line: Some(line),
                    column: Some(column),
                }],
            },
        );
        let result = &forward.results[0];
        if index < 3 {
            assert_eq!("resolved", result.status, "{result:#?}");
            assert_eq!(
                vec![Some("cpu_spec.cpu_features")],
                result
                    .definitions
                    .iter()
                    .map(|definition| definition.fqn.as_deref())
                    .collect::<Vec<_>>(),
                "direct designator must resolve through its cpu_spec owner: {result:#?}"
            );
        } else {
            assert_eq!("no_definition", result.status, "{result:#?}");
            assert!(
                result.definitions.is_empty(),
                "unresolved nested aggregate must not fall through to the same-named global: {result:#?}"
            );
        }
    }

    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        );
    let FuzzyResult::Success {
        hits_by_overload,
        unproven_by_overload,
        ..
    } = query.result
    else {
        panic!(
            "expected authoritative designated-initializer success, got {:#?}",
            query.result
        );
    };
    let hits = hits_by_overload
        .get(&target)
        .expect("cpu_features should have a proven-hit bucket");
    for start in &starts[..3] {
        assert!(
            hits.iter().any(|hit| {
                hit.file == consumer
                    && hit.start_offset <= *start
                    && *start + token.len() <= hit.end_offset
            }),
            "direct designator at {start} should be proven: {hits:#?}"
        );
    }
    assert!(
        hits.iter().all(|hit| {
            !(hit.file == consumer
                && hit.start_offset <= starts[3]
                && starts[3] + token.len() <= hit.end_offset)
        }),
        "unresolved nested aggregate designator must not be proven: {hits:#?}"
    );
    let unproven = unproven_by_overload
        .get(&target)
        .expect("unresolved nested designator should remain reviewable");
    assert!(
        unproven.iter().any(|hit| {
            hit.file == consumer
                && hit.start_offset <= starts[3]
                && starts[3] + token.len() <= hit.end_offset
        }),
        "unresolved nested aggregate designator should be unproven: {unproven:#?}"
    );

    let global_target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Field
            && unit.source() == &consumer
            && unit.fq_name() == "cpu_features"
    });
    let global_query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&global_target),
            Some(&provider),
            1,
            1000,
        );
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = global_query.result
    else {
        panic!(
            "expected authoritative global-field success, got {:#?}",
            global_query.result
        );
    };
    assert!(
        hits_by_overload
            .get(&global_target)
            .into_iter()
            .flatten()
            .all(|hit| starts.iter().all(|start| {
                !(hit.file == consumer
                    && hit.start_offset <= *start
                    && *start + token.len() <= hit.end_offset)
            })),
        "structured designators must not fall through to a same-named global"
    );
}

#[test]
fn cpp_macro_decorated_pointer_field_keeps_only_real_field_identity() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "port.h",
            r#"struct Reg {};
#define __iomem

struct Port {
    struct Reg __iomem *ip_serial_regs;
};
"#,
        ),
        (
            "consumer.c",
            r#"#include "port.h"

struct Reg *registers(struct Port *port) {
    return port->ip_serial_regs;
}
"#,
        ),
    ]);

    let header = project.file("port.h");
    let header_source = header.read_to_string().expect("header source");
    let macro_token = "__iomem";
    let macro_start = header_source
        .rfind(macro_token)
        .expect("declaration macro token");
    let macro_line_start = header_source[..macro_start]
        .rfind('\n')
        .map_or(0, |newline| newline + 1);
    let macro_line = header_source[..macro_start]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1;
    let macro_column = header_source[macro_line_start..macro_start].chars().count() + 1;
    let macro_forward = brokk_bifrost::searchtools::get_definitions_by_location(
        &analyzer,
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                path: "port.h".to_string(),
                line: Some(macro_line),
                column: Some(macro_column),
            }],
        },
    );
    assert_eq!(
        "no_definition", macro_forward.results[0].status,
        "declaration macro must not be a field reference: {:#?}",
        macro_forward.results[0]
    );

    let declarations = analyzer.get_declarations(&header);
    assert!(
        declarations
            .iter()
            .any(|unit| unit.is_field() && unit.fq_name() == "Port.ip_serial_regs"),
        "real pointer field should remain indexed: {declarations:#?}"
    );
    assert!(
        declarations
            .iter()
            .all(|unit| unit.fq_name() != "Port.__iomem"),
        "macro decoration must not create a pseudo-field: {declarations:#?}"
    );

    let consumer = project.file("consumer.c");
    let consumer_source = consumer.read_to_string().expect("consumer source");
    let use_token = "ip_serial_regs";
    let use_start = consumer_source.rfind(use_token).expect("pointer field use");
    let use_line_start = consumer_source[..use_start]
        .rfind('\n')
        .map_or(0, |newline| newline + 1);
    let use_line = consumer_source[..use_start]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1;
    let use_column = consumer_source[use_line_start..use_start].chars().count() + 1;
    let use_forward = brokk_bifrost::searchtools::get_definitions_by_location(
        &analyzer,
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                path: "consumer.c".to_string(),
                line: Some(use_line),
                column: Some(use_column),
            }],
        },
    );
    let use_result = &use_forward.results[0];
    assert_eq!("resolved", use_result.status, "{use_result:#?}");
    assert_eq!(
        vec![Some("Port.ip_serial_regs")],
        use_result
            .definitions
            .iter()
            .map(|definition| definition.fqn.as_deref())
            .collect::<Vec<_>>(),
        "pointer field use must resolve only to Port.ip_serial_regs: {use_result:#?}"
    );
}

#[test]
fn authoritative_cpp_usage_rejects_ambiguous_and_cyclic_typedef_type_references() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "canonical.h",
            r#"typedef struct Canonical { int value; } CanonicalAlias;
"#,
        ),
        (
            "left.h",
            r#"#include "canonical.h"
typedef CanonicalAlias SharedAlias;
"#,
        ),
        (
            "right.h",
            r#"typedef struct Other { int value; } OtherAlias;
typedef OtherAlias SharedAlias;
"#,
        ),
        (
            "cycle.h",
            r#"typedef CycleB CycleA;
typedef CycleA CycleB;
"#,
        ),
        (
            "consumer.c",
            r#"#include "left.h"
#include "right.h"
#include "cycle.h"

SharedAlias ambiguous_value;
CycleA cyclic_value;
"#,
        ),
    ]);

    let target = class_definition(&analyzer, "Canonical");
    let consumer = project.file("consumer.c");
    let provider = ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        );
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = query.result
    else {
        panic!(
            "expected authoritative ambiguous/cyclic typedef C++ success, got {:#?}",
            query.result
        );
    };
    assert!(
        hits_by_overload
            .get(&target)
            .is_some_and(|hits| hits.is_empty()),
        "ambiguous and cyclic typedef references must remain unproven: {hits_by_overload:#?}"
    );
}

#[test]
fn authoritative_cpp_usage_accepts_variadic_calls_above_fixed_minimum() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        ("trace.h", "void trace(const char *fmt, ...);\n"),
        (
            "consumer.c",
            r#"#include "trace.h"

void run(void) {
    trace("value=%d", 1);
    trace("pair=%d,%d", 1, 2);
    trace();
}
"#,
        ),
    ]);

    let target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.fq_name() == "trace"
            && slash_path(unit.source()) == "trace.h"
    });
    let consumer = project.file("consumer.c");
    let source = consumer.read_to_string().expect("consumer source");
    let trace_starts = source
        .match_indices("trace(")
        .map(|(start, _)| start)
        .collect::<Vec<_>>();
    assert_eq!(3, trace_starts.len(), "test fixture call count");

    let valid_start = trace_starts[0];
    let line_start = source[..valid_start]
        .rfind('\n')
        .map_or(0, |newline| newline + 1);
    let line = source[..valid_start]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1;
    let column = source[line_start..valid_start].chars().count() + 1;
    let forward = brokk_bifrost::searchtools::get_definitions_by_location(
        &analyzer,
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                path: "consumer.c".to_string(),
                line: Some(line),
                column: Some(column),
            }],
        },
    );
    let forward_result = &forward.results[0];
    assert_eq!("resolved", forward_result.status, "{forward_result:#?}");
    assert!(
        forward_result
            .definitions
            .iter()
            .any(|definition| definition.fqn.as_deref() == Some("trace")),
        "forward lookup should resolve the variadic header declaration: {forward_result:#?}"
    );

    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        );
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = query.result
    else {
        panic!(
            "expected authoritative variadic C++ success, got {:#?}",
            query.result
        );
    };
    let hits = hits_by_overload
        .get(&target)
        .expect("trace should have a proven-hit bucket");
    assert_eq!(
        2,
        hits.len(),
        "only calls meeting the fixed minimum should be proven; target={target:#?}, hits={hits:#?}"
    );
    for valid_start in &trace_starts[..2] {
        assert!(
            hits.iter().any(|hit| {
                hit.file == consumer
                    && hit.start_offset <= *valid_start
                    && *valid_start + "trace".len() <= hit.end_offset
            }),
            "valid variadic call at {valid_start} should be proven: {hits:#?}"
        );
    }
    let invalid_start = trace_starts[2];
    assert!(
        hits.iter().all(|hit| {
            hit.file != consumer
                || invalid_start < hit.start_offset
                || hit.end_offset < invalid_start + "trace".len()
        }),
        "zero-argument call below the fixed minimum must not be proven: {hits:#?}"
    );
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
    assert_success_counts(result, &target, 0, 1);
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

#[test]
fn cpp_graph_v2_handles_transitive_cycles_relative_and_angle_includes() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        ("target.h", "struct Target { void run(); };\n"),
        (
            "cycle_a.h",
            "#include \"cycle_b.h\"\n#include \"target.h\"\n",
        ),
        ("cycle_b.h", "#include \"cycle_a.h\"\n"),
        (
            "src/consumer.cpp",
            r#"
#include "../cycle_a.h"
#include <vector>

void call(Target& target) {
    target.run();
}
"#,
        ),
    ]);

    let target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.identifier() == "run"
            && unit.source().rel_path().to_string_lossy() == "target.h"
    });
    let hits = usage_hits(&analyzer, &target);
    assert_eq!(1, hits.len(), "expected only the quoted include-chain call");
    assert_hit_contains(&hits, "src/consumer.cpp", "target.run()");
}

#[test]
fn cpp_graph_v2_keeps_namespace_and_nested_owner_identity_narrow() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "ns1.h",
            r#"
namespace ns1 {
struct Target { void run(); };
}
"#,
        ),
        (
            "ns2.h",
            r#"
namespace ns2 {
struct Target { void run(); };
}
"#,
        ),
        (
            "widgets_a.h",
            r#"
namespace ui::widgets {
struct Widget { void render(); };
}
"#,
        ),
        (
            "widgets_b.h",
            r#"
namespace ui::widgets {
void paint(Widget& widget);
}
"#,
        ),
        (
            "nested.h",
            r#"
struct Outer {
    struct Inner { void run(); };
    struct Sibling { void run(); };
    void run();
};
"#,
        ),
        (
            "consumer.cpp",
            r#"
#include "ns1.h"
#include "ns2.h"
#include "widgets_a.h"
#include "widgets_b.h"
#include "nested.h"

void call(ns1::Target& one, ns2::Target& two, ui::widgets::Widget& widget, Outer& outer, Outer::Inner& inner, Outer::Sibling& sibling) {
    one.run();
    two.run();
    ui::widgets::paint(widget);
    outer.run();
    inner.run();
    sibling.run();
}
"#,
        ),
    ]);

    let ns1_run = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.identifier() == "run"
            && unit.package_name() == "ns1"
    });
    let ns1_hits = usage_hits(&analyzer, &ns1_run);
    assert_eq!(1, ns1_hits.len());
    assert_hit_contains(&ns1_hits, "consumer.cpp", "one.run()");
    assert_no_hit_contains(&ns1_hits, "two.run()");

    let paint = function_definition(&analyzer, "paint");
    let paint_hits = usage_hits(&analyzer, &paint);
    assert_eq!(1, paint_hits.len());
    assert_hit_contains(&paint_hits, "consumer.cpp", "ui::widgets::paint(widget)");

    let inner_run = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.identifier() == "run"
            && analyzer
                .parent_of(unit)
                .is_some_and(|parent| parent.short_name().ends_with("Inner"))
    });
    let inner_hits = usage_hits(&analyzer, &inner_run);
    assert_eq!(1, inner_hits.len());
    assert_hit_contains(&inner_hits, "consumer.cpp", "inner.run()");
    assert_no_hit_contains(&inner_hits, "outer.run()");
    assert_no_hit_contains(&inner_hits, "sibling.run()");
}

#[test]
fn cpp_graph_v2_counts_broad_type_reference_forms() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "target.h",
            r#"
namespace ns {
struct Target {};
}
"#,
        ),
        (
            "consumer.cpp",
            r#"
#include "target.h"
#include <vector>

ns::Target make();
void take(ns::Target value, const ns::Target* ptr, ns::Target& ref) {
    ns::Target local;
    const ns::Target* local_ptr = ptr;
    std::vector<ns::Target> values;
    auto casted = static_cast<ns::Target*>(ptr);
}
"#,
        ),
    ]);

    let target = class_definition(&analyzer, "Target");
    let hits = usage_hits(&analyzer, &target);
    assert_hit_contains(&hits, "consumer.cpp", "ns::Target make()");
    assert_hit_contains(&hits, "consumer.cpp", "void take(ns::Target value");
    assert_hit_contains(&hits, "consumer.cpp", "const ns::Target* ptr");
    assert_hit_contains(&hits, "consumer.cpp", "ns::Target& ref");
    assert_hit_contains(&hits, "consumer.cpp", "ns::Target local");
    assert_hit_contains(&hits, "consumer.cpp", "std::vector<ns::Target>");
    assert_hit_contains(&hits, "consumer.cpp", "static_cast<ns::Target*>");
    assert_no_hit_contains(&hits, "struct Target {}");
}

#[test]
fn cpp_graph_v2_keeps_free_function_overloads_and_headers_narrow() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "target.h",
            r#"
namespace ns {
void run();
void run(int value);
}
"#,
        ),
        (
            "other.h",
            r#"
namespace other {
void run();
}
"#,
        ),
        (
            "consumer.cpp",
            r#"
#include "target.h"
#include "other.h"

void call() {
    ns::run();
    ns::run(1);
    other::run();
}
"#,
        ),
    ]);

    let zero_arg = function_definition_in_package_with_arity(&analyzer, "ns", "run", 0);
    let one_arg = function_definition_in_package_with_arity(&analyzer, "ns", "run", 1);

    let zero_hits = usage_hits(&analyzer, &zero_arg);
    assert_eq!(1, zero_hits.len());
    assert_hit_contains(&zero_hits, "consumer.cpp", "ns::run();");
    assert_no_hit_contains(&zero_hits, "ns::run(1)");
    assert_no_hit_contains(&zero_hits, "other::run()");

    let one_hits = usage_hits(&analyzer, &one_arg);
    assert_eq!(1, one_hits.len());
    assert_hit_contains(&one_hits, "consumer.cpp", "ns::run(1)");
    assert_no_hit_contains(&one_hits, "ns::run();");
    assert_no_hit_contains(&one_hits, "other::run()");
}

#[test]
fn cpp_graph_filters_same_arity_free_function_overloads_by_argument_type() {
    let (_project, analyzer) = parity_overload_analyzer();
    let string_overload = parity_format_header_overload(&analyzer, "std::string");
    let int_overload = parity_format_header_overload(&analyzer, "int");

    let string_hits = usage_hits(&analyzer, &string_overload);
    assert_eq!(2, string_hits.len(), "string hits: {string_hits:#?}");
    assert_hit_contains(
        &string_hits,
        "src/parity.cpp",
        "std::string format(const std::string& value)",
    );
    assert_hit_contains(&string_hits, "src/main.cpp", "parity::format(first)");
    assert_no_hit_contains(&string_hits, "parity::format(7)");

    let int_hits = usage_hits(&analyzer, &int_overload);
    assert_eq!(2, int_hits.len(), "int hits: {int_hits:#?}");
    assert_hit_contains(&int_hits, "src/parity.cpp", "std::string format(int value)");
    assert_hit_contains(&int_hits, "src/main.cpp", "parity::format(7)");
    assert_no_hit_contains(&int_hits, "parity::format(first)");
}

#[test]
fn cpp_graph_keeps_unknown_argument_overload_calls_conservative() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "include/parity.h",
            r#"#pragma once
#include <string>
namespace parity {
struct AuditSink {
    std::string last;
};
std::string format(const std::string& value);
std::string format(int value);
}
"#,
        ),
        (
            "src/main.cpp",
            r#"#include "parity.h"
namespace app {
std::string run() {
    parity::AuditSink sink;
    auto formatted = parity::format(sink.last);
    return formatted;
}
}
"#,
        ),
    ]);
    let string_overload = parity_format_header_overload(&analyzer, "std::string");
    let int_overload = parity_format_header_overload(&analyzer, "int");

    let string_hits = usage_hits(&analyzer, &string_overload);
    assert_hit_contains(&string_hits, "src/main.cpp", "parity::format(sink.last)");

    let int_hits = usage_hits(&analyzer, &int_overload);
    assert_hit_contains(&int_hits, "src/main.cpp", "parity::format(sink.last)");
}

#[test]
fn cpp_graph_v2_covers_constructor_forms_and_arity() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "target.h",
            r#"
struct Target {
    Target();
    Target(int value);
};
"#,
        ),
        (
            "consumer.cpp",
            r#"
#include "target.h"

void call() {
    Target stack;
    Target braced{};
    Target commented_paren(/* constructor comment */);
    Target commented_brace{/* constructor comment */};
    Target paren(1);
    auto direct = Target{1};
    auto heap0 = new Target;
    auto heap1 = new Target(1);
}
"#,
        ),
    ]);

    let zero_arg = constructor_definition_with_arity(&analyzer, "Target", 0);
    let one_arg = constructor_definition_with_arity(&analyzer, "Target", 1);

    let zero_hits = usage_hits(&analyzer, &zero_arg);
    assert_hit_contains(&zero_hits, "consumer.cpp", "Target stack");
    assert_hit_contains(&zero_hits, "consumer.cpp", "Target braced{}");
    assert_hit_contains(&zero_hits, "consumer.cpp", "Target commented_paren");
    assert_hit_contains(&zero_hits, "consumer.cpp", "Target commented_brace");
    assert_hit_contains(&zero_hits, "consumer.cpp", "new Target");
    assert_no_hit_contains(&zero_hits, "Target paren(1)");
    assert_no_hit_contains(&zero_hits, "Target{1}");
    assert_no_hit_contains(&zero_hits, "new Target(1)");

    let one_hits = usage_hits(&analyzer, &one_arg);
    assert_hit_contains(&one_hits, "consumer.cpp", "Target paren(1)");
    assert_hit_contains(&one_hits, "consumer.cpp", "Target{1}");
    assert_hit_contains(&one_hits, "consumer.cpp", "new Target(1)");
    assert_no_hit_contains(&one_hits, "Target stack");
    assert_no_hit_contains(&one_hits, "Target braced{}");
    assert_no_hit_contains(&one_hits, "Target commented_paren");
    assert_no_hit_contains(&one_hits, "Target commented_brace");
}

#[test]
fn cpp_graph_counts_namespace_scope_object_constructors() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[(
        "consumer.cpp",
        r#"
class Target {
public:
    Target();
    explicit Target(int value);
};

Target global;

namespace ns {
Target cached(1);
}
"#,
    )]);

    let zero_arg = constructor_definition_with_arity(&analyzer, "Target", 0);
    let one_arg = constructor_definition_with_arity(&analyzer, "Target", 1);

    let zero_hits = usage_hits(&analyzer, &zero_arg);
    assert_hit_contains(&zero_hits, "consumer.cpp", "Target global;");
    assert_no_hit_contains(&zero_hits, "Target cached(1);");

    let one_hits = usage_hits(&analyzer, &one_arg);
    assert_hit_contains(&one_hits, "consumer.cpp", "Target cached(1);");
    assert_no_hit_contains(&one_hits, "Target global;");
}

#[test]
fn cpp_graph_v2_handles_static_methods_aliases_and_receiver_shadowing() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "target.h",
            r#"
namespace ns {
struct Target {
    static void stat();
    void run();
};
struct Other {
    void run();
};
}
"#,
        ),
        (
            "consumer.cpp",
            r#"
#include "target.h"

void call(ns::Target& obj, ns::Target* ptr, ns::Other& other) {
    ns::Target& ref = obj;
    auto alias = obj;
    obj.run();
    ptr->run();
    ref.run();
    alias.run();
    ns::Target::stat();
    ns::Other target;
    target.run();
    other.run();
}
"#,
        ),
    ]);

    let run = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.package_name() == "ns"
            && unit.short_name() == "Target.run"
    });
    let run_hits = usage_hits(&analyzer, &run);
    assert_eq!(4, run_hits.len());
    assert_hit_contains(&run_hits, "consumer.cpp", "obj.run()");
    assert_hit_contains(&run_hits, "consumer.cpp", "ptr->run()");
    assert_hit_contains(&run_hits, "consumer.cpp", "ref.run()");
    assert_hit_contains(&run_hits, "consumer.cpp", "alias.run()");
    assert_no_hit_contains(&run_hits, "target.run()");
    assert_no_hit_contains(&run_hits, "other.run()");

    let stat = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.package_name() == "ns"
            && unit.short_name() == "Target.stat"
    });
    let stat_hits = usage_hits(&analyzer, &stat);
    assert_eq!(1, stat_hits.len());
    assert_hit_contains(&stat_hits, "consumer.cpp", "ns::Target::stat()");
}

#[test]
fn cpp_graph_counts_static_qualifier_references_for_class_targets() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "target.h",
            r#"
namespace ns {
struct Target {
    static const int VALUE = 7;
    static Target build();
};
struct Other {
    void touch();
};
}
"#,
        ),
        (
            "consumer.cpp",
            r#"
#include "target.h"

void call() {
    ns::Target::build();
    int value = ns::Target::VALUE;
    ns::Other Target;
    Target.touch();
}
"#,
        ),
    ]);

    let target = class_definition(&analyzer, "Target");
    let hits = usage_hits(&analyzer, &target);

    assert_hit_contains(&hits, "consumer.cpp", "ns::Target::build()");
    assert_hit_contains(&hits, "consumer.cpp", "ns::Target::VALUE");
    assert_no_hit_contains(&hits, "Target.touch()");
}

#[test]
fn cpp_graph_v2_handles_static_fields_globals_and_scoped_enums() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "target.h",
            r#"
struct Target {
    static int value;
    int member;
};
extern int global_value;
enum Mode { Ready, Done };
enum class ScopedMode { Ready, Done };
"#,
        ),
        (
            "consumer.cpp",
            r#"
#include "target.h"

void call(Target& target) {
    target.member = 1;
    int copy = target.member;
    Target::value = 2;
    int static_copy = Target::value;
    global_value = static_copy;
    int global_copy = global_value;
    Mode mode = Ready;
    auto scoped = ScopedMode::Ready;
}
"#,
        ),
    ]);

    let member = field_definition_with_owner(&analyzer, "Target", "member");
    let member_hits = usage_hits(&analyzer, &member);
    assert_eq!(2, member_hits.len());
    assert_hit_contains(&member_hits, "consumer.cpp", "target.member = 1");
    assert_hit_contains(&member_hits, "consumer.cpp", "target.member");

    let static_value = field_definition_with_owner(&analyzer, "Target", "value");
    let static_hits = usage_hits(&analyzer, &static_value);
    assert_eq!(2, static_hits.len());
    assert_hit_contains(&static_hits, "consumer.cpp", "Target::value = 2");
    assert_hit_contains(&static_hits, "consumer.cpp", "Target::value");

    let global = field_definition(&analyzer, "global_value");
    let global_hits = usage_hits(&analyzer, &global);
    assert_eq!(2, global_hits.len());

    let ready = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Field && unit.short_name() == "Mode.Ready"
    });
    let ready_hits = usage_hits(&analyzer, &ready);
    assert_eq!(1, ready_hits.len());
    assert_hit_contains(&ready_hits, "consumer.cpp", "Mode mode = Ready");

    let scoped_ready = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Field && unit.short_name() == "ScopedMode.Ready"
    });
    let scoped_hits = usage_hits(&analyzer, &scoped_ready);
    assert_eq!(1, scoped_hits.len());
    assert_hit_contains(&scoped_hits, "consumer.cpp", "ScopedMode::Ready");
}

#[test]
fn cpp_graph_v2_guardrails_cover_limits_fallback_zero_hits_and_extensions() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "target.hpp",
            "struct Target { void run(); };\nvoid free_fn(Target& target);\n",
        ),
        (
            "a.cc",
            "#include \"target.hpp\"\nvoid a(Target& target) { target.run(); }\n",
        ),
        (
            "b.cxx",
            "#include \"target.hpp\"\nvoid b(Target& target) { target.run(); }\n",
        ),
        (
            "c.hxx",
            "#include \"target.hpp\"\nvoid c(Target& target) { target.run(); }\n",
        ),
        (
            "d.c",
            "#include \"target.hpp\"\nvoid d(Target* target) { free_fn(*target); }\n",
        ),
        ("zero.cpp", "#include \"target.hpp\"\nvoid zero() {}\n"),
        (
            "fallback.cpp",
            "auto make_unknown();\nvoid fallback() { auto target = make_unknown(); target.run(); }\n",
        ),
    ]);

    let run = member_function_definition_in_source(&analyzer, "Target", "run", "target.hpp");
    let candidates = [
        project.file("target.hpp"),
        project.file("a.cc"),
        project.file("b.cxx"),
        project.file("c.hxx"),
        project.file("d.c"),
    ]
    .into_iter()
    .collect();
    let too_many = CppUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&run),
        &candidates,
        2,
    );
    assert!(
        matches!(
            too_many,
            FuzzyResult::TooManyCallsites {
                total_callsites: 3,
                limit: 2,
                ..
            }
        ),
        "expected TooManyCallsites for extension hits, got {too_many:#?}"
    );

    let restricted = [project.file("a.cc")].into_iter().collect();
    let restricted_hits = CppUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&run), &restricted, 1000)
        .into_either()
        .expect("restricted success");
    assert_eq!(1, restricted_hits.len());
    assert_eq!(
        project.file("a.cc"),
        restricted_hits.iter().next().unwrap().file
    );

    let free_fn = function_definition(&analyzer, "free_fn");
    let free_hits = usage_hits(&analyzer, &free_fn);
    assert_eq!(1, free_hits.len());
    assert_hit_contains(&free_hits, "d.c", "free_fn(*target)");

    let zero_candidates = [project.file("zero.cpp")].into_iter().collect();
    let zero_result = CppUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&run),
        &zero_candidates,
        1000,
    );
    assert!(
        zero_result
            .into_either()
            .expect("zero-hit graph success")
            .is_empty(),
        "graph success with zero hits should remain zero hits"
    );

    let fallback_query = UsageFinder::new()
        .with_file_filter(|file| file.rel_path().to_string_lossy() == "fallback.cpp")
        .query(&analyzer, std::slice::from_ref(&run), 1000, 1000);
    assert!(
        fallback_query.graph_failure.is_none(),
        "unproven C++ sites should not be graph failures: {:?}",
        fallback_query.graph_failure
    );
    assert_success_counts(fallback_query.result, &run, 0, 1);
}

#[test]
fn cpp_graph_v3_covers_templates_and_alias_type_references() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "target.h",
            r#"
struct Target {};
template <typename T> struct Box {};
template <typename K, typename V> struct Map {};
template <typename T> void templated(T value);
using Alias = Target;
typedef Target LegacyAlias;
typedef Target* TargetPtrAlias;
typedef Target& TargetRefAlias;
void hidden_alias_scope() { using HiddenAlias = Target; }
void overloaded();
template <typename T> void overloaded(T value);
"#,
        ),
        (
            "consumer.cpp",
            r#"
#include "target.h"

void call(Target target) {
    Box<Target> boxed;
    Map<int, Target> mapped;
    Box<Map<int, Target>> nested;
    templated<Target>(target);
    Alias alias;
    LegacyAlias legacy;
    TargetPtrAlias ptr_alias;
    TargetRefAlias ref_alias = target;
    HiddenAlias hidden;
    overloaded();
    overloaded<Target>(target);
}
"#,
        ),
    ]);

    let target = class_definition(&analyzer, "Target");
    let type_hits = usage_hits(&analyzer, &target);
    assert_hit_contains(&type_hits, "consumer.cpp", "Box<Target> boxed");
    assert_hit_contains(&type_hits, "consumer.cpp", "Map<int, Target> mapped");
    assert_hit_contains(&type_hits, "consumer.cpp", "Box<Map<int, Target>> nested");
    assert_hit_contains(&type_hits, "consumer.cpp", "templated<Target>(target)");
    assert_hit_contains(&type_hits, "consumer.cpp", "Alias alias");
    assert_hit_contains(&type_hits, "consumer.cpp", "LegacyAlias legacy");
    assert_hit_contains(&type_hits, "consumer.cpp", "TargetPtrAlias ptr_alias");
    assert_hit_contains(&type_hits, "consumer.cpp", "TargetRefAlias ref_alias");
    assert_no_hit_contains(&type_hits, "HiddenAlias hidden");
    assert_no_hit_contains(&type_hits, "struct Target {}");

    let zero_arg = function_definition_with_short_name_and_arity(&analyzer, "overloaded", 0);
    let one_arg = function_definition_with_short_name_and_arity(&analyzer, "overloaded", 1);

    let zero_hits = usage_hits(&analyzer, &zero_arg);
    assert_eq!(1, zero_hits.len());
    assert_hit_contains(&zero_hits, "consumer.cpp", "overloaded();");
    assert_no_hit_contains(&zero_hits, "overloaded<Target>(target)");

    let one_hits = usage_hits(&analyzer, &one_arg);
    assert_eq!(1, one_hits.len());
    assert_hit_contains(&one_hits, "consumer.cpp", "overloaded<Target>(target)");
    assert_no_hit_contains(&one_hits, "overloaded();");
}

#[test]
fn cpp_graph_v3_handles_out_of_line_members_this_and_owner_context() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "target.h",
            r#"
struct Target {
    static int value;
    void run();
    void inside();
};
struct Other {
    int value;
    void run();
    void inside();
};
"#,
        ),
        (
            "target.cpp",
            r#"
#include "target.h"

int Target::value = 0;
void Target::run() {}
void Target::inside() {
    run();
    this->run();
    value = 1;
    this->value = 2;
}
void Other::run() {}
void Other::inside() {
    run();
    this->run();
    value = 3;
    this->value = 4;
}
void outside(Target& target, Other& other) {
    target.run();
    other.run();
    Target::value = 5;
}
"#,
        ),
    ]);

    let run = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.short_name() == "Target.run"
            && slash_path(unit.source()) == "target.cpp"
    });
    let run_hits = usage_hits(&analyzer, &run);
    assert_eq!(1, run_hits.len(), "run hits were {run_hits:#?}");
    assert_hit_contains(&run_hits, "target.cpp", "target.run();");
    assert_no_hit_contains(&run_hits, "    run();");
    assert_no_hit_contains(&run_hits, "this->run();");
    assert_no_hit_contains(&run_hits, "Other::run");
    assert_no_hit_contains(&run_hits, "other.run()");

    let editor_run_hits = editor_usage_hits(&analyzer, &run);
    assert_eq!(
        3,
        editor_run_hits.len(),
        "editor run hits were {editor_run_hits:#?}"
    );
    assert_hit_contains(&editor_run_hits, "target.cpp", "run();");
    assert_hit_contains(&editor_run_hits, "target.cpp", "this->run();");
    assert_hit_contains(&editor_run_hits, "target.cpp", "target.run();");

    let value = field_definition_with_owner(&analyzer, "Target", "value");
    let value_hits = usage_hits(&analyzer, &value);
    assert_hit_contains(&value_hits, "target.cpp", "value = 1");
    assert_hit_contains(&value_hits, "target.cpp", "this->value = 2");
    assert_hit_contains(&value_hits, "target.cpp", "Target::value = 5");
    assert_no_hit_contains(&value_hits, "int Target::value = 0");
    assert_no_hit_contains(&value_hits, "value = 3");
    assert_no_hit_contains(&value_hits, "this->value = 4");
}

#[test]
fn cpp_graph_v3_keeps_method_overloads_const_refs_and_operators_conservative() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "target.h",
            r#"
struct Target {
    void run();
    void run(int value);
    void run(int left, int right);
    void inspect() const;
    void mutate();
    void operator()();
};
struct Other {
    void operator()();
};
bool operator==(const Target& left, const Target& right);
"#,
        ),
        (
            "consumer.cpp",
            r#"
#include "target.h"

void call(Target& target, const Target& frozen) {
    Other other;
    target.run();
    target.run(1);
    target.run(1, 2);
    frozen.inspect();
    target.mutate();
    target.operator()();
    other.operator()();
    target();
    bool same = target == target;
}
"#,
        ),
    ]);

    let run0 = function_definition_with_short_name_and_arity(&analyzer, "Target.run", 0);
    let run1 = function_definition_with_short_name_and_arity(&analyzer, "Target.run", 1);
    let run2 = function_definition_with_short_name_and_arity(&analyzer, "Target.run", 2);

    let run0_hits = usage_hits(&analyzer, &run0);
    assert_eq!(1, run0_hits.len());
    assert_hit_contains(&run0_hits, "consumer.cpp", "target.run();");

    let run1_hits = usage_hits(&analyzer, &run1);
    assert_eq!(1, run1_hits.len());
    assert_hit_contains(&run1_hits, "consumer.cpp", "target.run(1)");

    let run2_hits = usage_hits(&analyzer, &run2);
    assert_eq!(1, run2_hits.len());
    assert_hit_contains(&run2_hits, "consumer.cpp", "target.run(1, 2)");

    let inspect = function_definition_with_signature(&analyzer, "Target.inspect", "() const");
    let inspect_hits = usage_hits(&analyzer, &inspect);
    assert_eq!(1, inspect_hits.len());
    assert_hit_contains(&inspect_hits, "consumer.cpp", "frozen.inspect()");

    let call_operator =
        function_definition_with_short_name_and_arity(&analyzer, "Target.operator()", 0);
    let operator_hits = usage_hits(&analyzer, &call_operator);
    assert_eq!(1, operator_hits.len());
    assert_hit_contains(&operator_hits, "consumer.cpp", "target.operator()()");
    assert_no_hit_contains(&operator_hits, "other.operator()()");

    let equality = function_definition_with_short_name_and_arity(&analyzer, "operator==", 2);
    let equality_hits = CppUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&equality),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("operator syntax without a call_expression name should be proven zero-hit");
    assert!(
        equality_hits.is_empty(),
        "operator syntax without a call_expression name should not invent graph hits"
    );
}

#[test]
fn cpp_graph_v3_hardens_constructors_and_initializer_forms() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "target.h",
            r#"
namespace std { template <typename T> T&& move(T& value); }
struct Target {
    int field;
    Target();
    Target(int value);
    Target(const Target& other);
};
struct Owner {
    const Target target;
    Owner();
    Owner(int value);
};
"#,
        ),
        (
            "consumer.cpp",
            r#"
#include "target.h"

Owner::Owner() : target() {}
Owner::Owner(int value) : target(value) {}

void call(Target original) {
    Target copy = original;
    Target direct_copy(original);
    Target moved(std::move(original));
    Target aggregate{.field = 1};
}
"#,
        ),
    ]);

    let zero_arg = constructor_definition_with_arity(&analyzer, "Target", 0);
    let one_arg = constructor_definition_with_arity(&analyzer, "Target", 1);

    let zero_hits = usage_hits(&analyzer, &zero_arg);
    assert_hit_contains(&zero_hits, "consumer.cpp", "target() {}");
    assert_no_hit_contains(&zero_hits, "target(value)");
    assert_no_hit_contains(&zero_hits, "Target copy = original");

    let one_hits = usage_hits(&analyzer, &one_arg);
    assert_hit_contains(&one_hits, "consumer.cpp", "Target copy = original");
    assert_hit_contains(&one_hits, "consumer.cpp", "target(value)");
    assert_hit_contains(&one_hits, "consumer.cpp", "Target direct_copy(original)");
    assert_hit_contains(
        &one_hits,
        "consumer.cpp",
        "Target moved(std::move(original))",
    );
    assert_hit_contains(&one_hits, "consumer.cpp", "Target aggregate{.field = 1}");
    assert_no_hit_contains(&one_hits, "Target();");
}

#[test]
fn cpp_graph_v3_resolves_include_path_ambiguity_precisely() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        ("a/target.h", "struct Target { void run(); };\n"),
        ("b/target.h", "struct Target { void run(); };\n"),
        ("a/wrapper.h", "#include \"target.h\"\n"),
        (
            "use_a.cpp",
            "#include \"a/wrapper.h\"\nvoid use_a(Target& target) { target.run(); }\n",
        ),
        (
            "use_b.cpp",
            "#include \"b/target.h\"\nvoid use_b(Target& target) { target.run(); }\n",
        ),
        (
            "missing.cpp",
            "struct Target { void run(); };\nvoid missing(Target& target) { target.run(); }\n",
        ),
        (
            "angle.cpp",
            "#include <target.h>\nvoid angle(Target& target) { target.run(); }\n",
        ),
    ]);

    let a_run = member_function_definition_in_source(&analyzer, "Target", "run", "a/target.h");
    let a_candidates = [project.file("use_a.cpp")].into_iter().collect();
    let a_hits = CppUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&a_run), &a_candidates, 1000)
        .into_either()
        .expect("a include success")
        .into_iter()
        .map(|hit| HitSummary {
            file: slash_path(&hit.file),
            line: hit
                .file
                .read_to_string()
                .ok()
                .and_then(|source| {
                    source
                        .lines()
                        .nth(hit.line.saturating_sub(1))
                        .map(str::to_string)
                })
                .unwrap_or_default(),
        })
        .collect::<Vec<_>>();
    assert_eq!(1, a_hits.len());
    assert_hit_contains(&a_hits, "use_a.cpp", "target.run()");
    assert_no_hit_contains(&a_hits, "use_b");
    assert_no_hit_contains(&a_hits, "missing");
    assert_no_hit_contains(&a_hits, "angle");

    let b_run = member_function_definition_in_source(&analyzer, "Target", "run", "b/target.h");
    let b_candidates = [project.file("use_b.cpp")].into_iter().collect();
    let b_hits = CppUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&b_run), &b_candidates, 1000)
        .into_either()
        .expect("b include success")
        .into_iter()
        .map(|hit| HitSummary {
            file: slash_path(&hit.file),
            line: hit
                .file
                .read_to_string()
                .ok()
                .and_then(|source| {
                    source
                        .lines()
                        .nth(hit.line.saturating_sub(1))
                        .map(str::to_string)
                })
                .unwrap_or_default(),
        })
        .collect::<Vec<_>>();
    assert_eq!(1, b_hits.len());
    assert_hit_contains(&b_hits, "use_b.cpp", "target.run()");
    assert_no_hit_contains(&b_hits, "use_a");
}

#[test]
fn cpp_graph_v3_follows_absolute_slash_normalized_includes() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("include/target.h", "struct Target { void run(); };\n")
        .file(
            "consumer.cpp",
            "void call(Target& target) { target.run(); }\n",
        )
        .build();
    let include_path = project
        .root()
        .join("include/target.h")
        .to_string_lossy()
        .replace('\\', "/");
    project
        .file("consumer.cpp")
        .write(format!(
            "# include \"{include_path}\"\nvoid call(Target& target) {{ target.run(); }}\n"
        ))
        .unwrap();
    let analyzer = CppAnalyzer::from_project(project.project().clone());

    let run = member_function_definition_in_source(&analyzer, "Target", "run", "include/target.h");
    let hits = usage_hits(&analyzer, &run);

    assert_eq!(1, hits.len());
    assert_hit_contains(&hits, "consumer.cpp", "target.run()");
}

#[test]
fn cpp_graph_v3_preserves_declaration_filtering_and_fallback_boundaries() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "target.h",
            r#"
struct Target {
    void run();
};
"#,
        ),
        (
            "target.cpp",
            "#include \"target.h\"\nvoid Target::run() {}\n",
        ),
        (
            "hit.cpp",
            "#include \"target.h\"\nvoid hit(Target& target) { target.run(); }\n",
        ),
        (
            "ambiguous.cpp",
            r#"
struct Target { void run(); };
struct Other { void run(); };
void ambiguous(Target& target, Other& other) {
    target.run();
    other.run();
}
"#,
        ),
        ("zero.cpp", "#include \"target.h\"\nvoid zero() {}\n"),
    ]);

    let run = member_function_definition_in_source(&analyzer, "Target", "run", "target.h");
    let restricted = [project.file("hit.cpp")].into_iter().collect();
    let hits = CppUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&run), &restricted, 1000)
        .into_either()
        .expect("restricted success")
        .into_iter()
        .map(|hit| HitSummary {
            file: slash_path(&hit.file),
            line: hit
                .file
                .read_to_string()
                .ok()
                .and_then(|source| {
                    source
                        .lines()
                        .nth(hit.line.saturating_sub(1))
                        .map(str::to_string)
                })
                .unwrap_or_default(),
        })
        .collect::<Vec<_>>();
    assert_eq!(1, hits.len());
    assert_hit_contains(&hits, "hit.cpp", "target.run()");
    assert_no_hit_contains(&hits, "void Target::run() {}");

    let restricted_hits = CppUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&run), &restricted, 1000)
        .into_either()
        .expect("restricted success");
    assert_eq!(1, restricted_hits.len());

    let zero_candidates = [project.file("zero.cpp")].into_iter().collect();
    let zero_hits = CppUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&run),
            &zero_candidates,
            1000,
        )
        .into_either()
        .expect("zero-hit graph success");
    assert!(zero_hits.is_empty());

    let ambiguous_candidates = [project.file("ambiguous.cpp")].into_iter().collect();
    let ambiguous_result = CppUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&run),
        &ambiguous_candidates,
        1000,
    );
    assert_success_counts(ambiguous_result, &run, 0, 1);
}

#[test]
fn cpp_graph_review_resolves_visible_header_declaration_from_source_definition() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        ("api.h", "void run();\n"),
        ("api.cpp", "#include \"api.h\"\nvoid run() {}\n"),
        (
            "consumer.cpp",
            "#include \"api.h\"\nvoid call() { run(); }\n",
        ),
        ("unseen.h", "void run();\n"),
    ]);

    let definition = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.identifier() == "run"
            && unit.source().rel_path().to_string_lossy() == "api.cpp"
    });
    let hits = usage_hits(&analyzer, &definition);
    assert_eq!(1, hits.len());
    assert_hit_contains(&hits, "consumer.cpp", "run();");
    assert_no_hit_contains(&hits, "unseen");
}

#[test]
fn cpp_graph_review_rejects_text_only_comments_strings_and_preprocessor_hits() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "target.h",
            r#"
struct Target { Target(); };
extern int global_value;
"#,
        ),
        (
            "consumer.cpp",
            r#"
#include "target.h"
#define MENTION Target(

void call() {
    const char* text = "Target(";
    // global_value
    /* Target( */
}
"#,
        ),
    ]);

    let constructor = constructor_definition(&analyzer, "Target");
    let constructor_hits = usage_hits(&analyzer, &constructor);
    assert!(
        constructor_hits.is_empty(),
        "hits were {constructor_hits:#?}"
    );

    let global = field_definition(&analyzer, "global_value");
    let global_hits = usage_hits(&analyzer, &global);
    assert!(global_hits.is_empty(), "hits were {global_hits:#?}");
}

#[test]
fn cpp_graph_review_returns_mixed_proven_and_unproven_member_matches() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        ("target.h", "struct Target { void run(); };\n"),
        (
            "consumer.cpp",
            r#"
#include "target.h"

Target make_target();
auto make_unknown();
void call(Target& target) {
    target.run();
    auto unknown = make_unknown();
    unknown.run();
}
"#,
        ),
    ]);

    let target = member_function_definition(&analyzer, "Target", "run");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let result = CppUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    assert_success_counts(result, &target, 1, 1);
}

#[test]
fn cpp_graph_review_counts_arity_with_nested_commas() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "target.h",
            r#"
namespace std { template <typename A, typename B> struct pair {}; }
struct Target {
    void run(std::pair<int, int> value);
    Target(std::pair<int, int> value);
};
"#,
        ),
        (
            "consumer.cpp",
            r#"
#include "target.h"

void call(Target& target, std::pair<int, int> pair) {
    target.run(pair);
    Target copy(pair);
}
"#,
        ),
    ]);

    let run = function_definition_with_short_name_and_arity(&analyzer, "Target.run", 1);
    let run_hits = usage_hits(&analyzer, &run);
    assert_eq!(1, run_hits.len());
    assert_hit_contains(&run_hits, "consumer.cpp", "target.run(pair)");

    let constructor = constructor_definition_with_arity(&analyzer, "Target", 1);
    let constructor_hits = usage_hits(&analyzer, &constructor);
    assert_hit_contains(&constructor_hits, "consumer.cpp", "Target copy(pair)");
}

#[test]
fn cpp_graph_review_keeps_enum_enumerators_single_sourced() {
    let (_project, analyzer) =
        cpp_analyzer_with_files(&[("target.h", "enum Mode { Ready = 1, Done = 2 };\n")]);

    let ready: Vec<_> = analyzer
        .get_all_declarations()
        .into_iter()
        .filter(|unit| unit.kind() == CodeUnitType::Field && unit.short_name() == "Mode.Ready")
        .collect();
    assert_eq!(1, ready.len(), "Ready declarations were {ready:#?}");
}

/// Asserts the graph strategy returns a structured `Success` (never a `FallbackSafe`/`Failure`
/// diagnostic), then returns the hit lines. Once the regex/text fallback is removed, anything but
/// `Success` here means the reference is silently lost, so the regression must pin it down.
fn graph_success_hits(analyzer: &CppAnalyzer, target: &CodeUnit) -> Vec<HitSummary> {
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let result = CppUsageGraphStrategy::new().find_usages(
        analyzer,
        std::slice::from_ref(target),
        &candidates,
        1000,
    );
    assert!(
        matches!(result, FuzzyResult::Success { .. }),
        "expected structured Success for {}, got {result:?}",
        target.fq_name()
    );
    usage_hits(analyzer, target)
}

#[test]
fn cpp_graph_resolves_namespace_function_method_and_constant_refs() {
    // Issue #230: graph-only resolution of namespace-scoped free functions, instance methods whose
    // receiver type is inferred from a free-function call, and namespace-scoped constants referenced
    // both unqualified (inside the namespace) and qualified (outside).
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "include/service.h",
            r#"#pragma once
#include <string>
namespace example {
class Service {
public:
    std::string execute() const;
};
inline constexpr const char* DefaultPrefix = "svc";
Service build_service();
}
"#,
        ),
        (
            "src/service.cpp",
            r#"#include "service.h"
namespace example {
std::string Service::execute() const { return DefaultPrefix; }
Service build_service() { return Service{}; }
}
"#,
        ),
        (
            "src/main.cpp",
            r#"#include "service.h"
int main() {
    auto service = example::build_service();
    auto value = service.execute();
    return value == example::DefaultPrefix ? 0 : 1;
}
"#,
        ),
    ]);

    // Free function: `example::build_service()` called from main.cpp.
    let build_service = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.identifier() == "build_service"
            && slash_path(unit.source()) == "src/service.cpp"
    });
    let build_hits = graph_success_hits(&analyzer, &build_service);
    assert_eq!(
        1,
        build_hits.len(),
        "build_service hits were {build_hits:#?}"
    );
    assert_hit_contains(&build_hits, "src/main.cpp", "example::build_service()");

    // Instance method: `service.execute()`, where `service` is bound to the return type of
    // `example::build_service()`.
    let execute =
        member_function_definition_in_source(&analyzer, "Service", "execute", "src/service.cpp");
    let execute_hits = graph_success_hits(&analyzer, &execute);
    assert_eq!(1, execute_hits.len(), "execute hits were {execute_hits:#?}");
    assert_hit_contains(&execute_hits, "src/main.cpp", "service.execute()");

    // Namespace constant: unqualified inside the namespace (service.cpp) and qualified outside it
    // (main.cpp).
    let prefix = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Field && unit.identifier() == "DefaultPrefix"
    });
    let prefix_hits = graph_success_hits(&analyzer, &prefix);
    assert_eq!(
        2,
        prefix_hits.len(),
        "DefaultPrefix hits were {prefix_hits:#?}"
    );
    assert_hit_contains(&prefix_hits, "src/service.cpp", "return DefaultPrefix");
    assert_hit_contains(&prefix_hits, "src/main.cpp", "example::DefaultPrefix");
}

#[test]
fn cpp_graph_resolves_header_declaration_to_out_of_line_definition_sites() {
    // Issue #248 keeps function/method header declarations connected to their out-of-line
    // definition sites. Issue #290 narrows constructor queries back to real construction sites.
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "include/service.h",
            r#"#pragma once

#include <string>

namespace example {

struct Repository {
    std::string last;
    std::string save(const std::string& value);
};

class Service {
public:
    explicit Service(Repository& repository);
    std::string execute(const std::string& name);

private:
    Repository& repository_;
};

Service build_service(Repository& repository);

} // namespace example
"#,
        ),
        (
            "src/service.cpp",
            r#"#include "service.h"

namespace example {

Service::Service(Repository& repository) : repository_(repository) {}

std::string Service::execute(const std::string& name) {
    auto stored = repository_.save(name);
    return stored;
}

Service build_service(Repository& repository) {
    return Service(repository);
}

} // namespace example
"#,
        ),
        (
            "src/main.cpp",
            r#"#include "service.h"

std::string run_demo() {
    example::Repository repository;
    auto service = example::build_service(repository);
    return service.execute("Ada");
}
"#,
        ),
        (
            "src/unrelated.cpp",
            r#"#include "service.h"

namespace other {

struct Repository {};

class Service {
public:
    std::string execute(const std::string& name);
};

Service build_service(Repository& repository) {
    return Service{};
}

std::string Service::execute(const std::string& name) {
    return name;
}

} // namespace other
"#,
        ),
    ]);

    let build_service_header = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.identifier() == "build_service"
            && slash_path(unit.source()) == "include/service.h"
    });
    let build_hits = graph_success_hits(&analyzer, &build_service_header);
    assert_eq!(
        2,
        build_hits.len(),
        "build_service hits were {build_hits:#?}"
    );
    assert_hit_contains(
        &build_hits,
        "src/service.cpp",
        "Service build_service(Repository& repository)",
    );
    assert_hit_contains(
        &build_hits,
        "src/main.cpp",
        "example::build_service(repository)",
    );
    assert_no_hit_contains(&build_hits, "src/unrelated.cpp");

    let execute_header = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.short_name() == "Service.execute"
            && slash_path(unit.source()) == "include/service.h"
    });
    let execute_hits = graph_success_hits(&analyzer, &execute_header);
    assert_eq!(2, execute_hits.len(), "execute hits were {execute_hits:#?}");
    assert_hit_contains(
        &execute_hits,
        "src/service.cpp",
        "std::string Service::execute(const std::string& name)",
    );
    assert_hit_contains(&execute_hits, "src/main.cpp", "service.execute(\"Ada\")");
    assert_no_hit_contains(&execute_hits, "src/unrelated.cpp");

    let constructor_header = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.identifier() == "Service"
            && slash_path(unit.source()) == "include/service.h"
    });
    let constructor_hits = graph_success_hits(&analyzer, &constructor_header);
    assert_eq!(
        1,
        constructor_hits.len(),
        "constructor hits were {constructor_hits:#?}"
    );
    assert_hit_contains(&constructor_hits, "src/service.cpp", "Service(repository)");
    assert_no_hit_contains(
        &constructor_hits,
        "Service::Service(Repository& repository)",
    );
    assert_no_hit_contains(
        &constructor_hits,
        "Service build_service(Repository& repository)",
    );
    assert_no_hit_contains(&constructor_hits, "src/unrelated.cpp");

    let service_class = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.identifier() == "Service"
            && unit.package_name() == "example"
            && slash_path(unit.source()) == "include/service.h"
    });
    let service_class_hits = graph_success_hits(&analyzer, &service_class);
    assert_hit_contains(
        &service_class_hits,
        "include/service.h",
        "Service build_service(Repository& repository)",
    );
    assert_hit_contains(
        &service_class_hits,
        "src/service.cpp",
        "Service build_service(Repository& repository)",
    );
    assert_hit_contains(
        &service_class_hits,
        "src/service.cpp",
        "Service::Service(Repository& repository)",
    );
    assert_hit_contains(
        &service_class_hits,
        "src/service.cpp",
        "std::string Service::execute(const std::string& name)",
    );
    assert_no_hit_contains(&service_class_hits, "src/unrelated.cpp");
}

#[test]
fn cpp_graph_definition_sites_respect_overload_signatures_and_void_arity() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "include/api.h",
            r#"#pragma once
namespace example {
int parse(int value);
int parse(double value);
int ping(void);
}
"#,
        ),
        (
            "src/api.cpp",
            r#"#include "api.h"
namespace example {
int parse(int value) { return value; }
int parse(double value) { return static_cast<int>(value); }
int ping(void) { return 1; }
}
"#,
        ),
    ]);

    let parse_int = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.identifier() == "parse"
            && slash_path(unit.source()) == "include/api.h"
            && unit.signature() == Some("(int)")
    });
    let parse_hits = graph_success_hits(&analyzer, &parse_int);
    assert_eq!(1, parse_hits.len(), "parse hits were {parse_hits:#?}");
    assert_hit_contains(&parse_hits, "src/api.cpp", "int parse(int value)");
    assert_no_hit_contains(&parse_hits, "int parse(double value)");

    let ping = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.identifier() == "ping"
            && slash_path(unit.source()) == "include/api.h"
    });
    let ping_hits = graph_success_hits(&analyzer, &ping);
    assert_eq!(1, ping_hits.len(), "ping hits were {ping_hits:#?}");
    assert_hit_contains(&ping_hits, "src/api.cpp", "int ping(void)");
}

// Issue #230 / #220: a bare constant reference that also matches a same-named
// constant in a different namespace is ambiguous and must never be recorded as a
// (hash-order-dependent) false-positive hit for the target.
#[test]
fn cpp_graph_does_not_attribute_bare_constant_across_namespaces() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "include/a.h",
            "#pragma once\nnamespace example { inline constexpr int DefaultPrefix = 1; }\n",
        ),
        (
            "include/b.h",
            "#pragma once\nnamespace other { inline constexpr int DefaultPrefix = 2; }\n",
        ),
        (
            "src/use.cpp",
            r#"#include "a.h"
#include "b.h"
namespace other {
int pick() { return DefaultPrefix; }
}
"#,
        ),
    ]);

    let prefix = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Field
            && unit.identifier() == "DefaultPrefix"
            && unit.fq_name().contains("example")
    });
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let result = CppUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&prefix),
        &candidates,
        1000,
    );
    // The reference resolves to `other::DefaultPrefix`, so it must not be a proven hit
    // for `example::DefaultPrefix`. Ambiguity surfaces conservatively as a structured
    // fallback; either way the invariant is no false-positive hit.
    if let FuzzyResult::Success {
        hits_by_overload, ..
    } = &result
    {
        assert!(
            hits_by_overload.values().all(|hits| hits.is_empty()),
            "bare DefaultPrefix in namespace other must not be attributed to example: {result:?}",
        );
    }
}

#[test]
fn cpp_graph_uses_call_arity_for_auto_return_type_inference() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "include/service.h",
            r#"#pragma once
namespace example {
class Service {
public:
    void execute() const;
};
class Other {
public:
    void execute() const;
};
Service make();
Other make(int value);
}
"#,
        ),
        (
            "src/main.cpp",
            r#"#include "service.h"
int main() {
    auto service = example::make();
    service.execute();
    auto other = example::make(1);
    other.execute();
}
"#,
        ),
    ]);

    let service_execute = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function && unit.short_name() == "Service.execute"
    });
    let service_hits = graph_success_hits(&analyzer, &service_execute);
    assert_eq!(
        1,
        service_hits.len(),
        "Service.execute hits were {service_hits:#?}"
    );
    assert_hit_contains(&service_hits, "src/main.cpp", "service.execute()");

    let other_execute = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function && unit.short_name() == "Other.execute"
    });
    let other_hits = graph_success_hits(&analyzer, &other_execute);
    assert_eq!(
        1,
        other_hits.len(),
        "Other.execute hits were {other_hits:#?}"
    );
    assert_hit_contains(&other_hits, "src/main.cpp", "other.execute()");
}

#[test]
fn cpp_graph_infers_return_type_when_function_name_appears_in_return_type() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "include/service.h",
            r#"#pragma once
namespace make {
class Result {
public:
    void execute() const;
};
}
make::Result make();
"#,
        ),
        (
            "src/main.cpp",
            r#"#include "service.h"
int main() {
    auto result = make();
    result.execute();
}
"#,
        ),
    ]);

    let execute = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function && unit.short_name() == "Result.execute"
    });
    let hits = graph_success_hits(&analyzer, &execute);
    assert_eq!(1, hits.len(), "Result.execute hits were {hits:#?}");
    assert_hit_contains(&hits, "src/main.cpp", "result.execute()");
}

#[test]
fn cpp_graph_infers_noexcept_trailing_return_type() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "include/service.h",
            r#"#pragma once
namespace example {
class Service {
public:
    void execute() const;
};
auto make_service() noexcept -> Service;
}
"#,
        ),
        (
            "src/main.cpp",
            r#"#include "service.h"
int main() {
    auto service = example::make_service();
    service.execute();
}
"#,
        ),
    ]);

    let execute = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function && unit.short_name() == "Service.execute"
    });
    let hits = graph_success_hits(&analyzer, &execute);
    assert_eq!(1, hits.len(), "Service.execute hits were {hits:#?}");
    assert_hit_contains(&hits, "src/main.cpp", "service.execute()");
}

#[test]
fn cpp_graph_prefers_enclosing_namespace_for_factory_return_inference() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "include/service.h",
            r#"#pragma once
namespace example {
class Service {
public:
    void execute() const;
};
Service make();
}
namespace other {
class Other {
public:
    void execute() const;
};
Other make();
}
"#,
        ),
        (
            "src/main.cpp",
            r#"#include "service.h"
namespace example {
void run() {
    auto service = make();
    service.execute();
}
}
"#,
        ),
    ]);

    let service_execute = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function && unit.short_name() == "Service.execute"
    });
    let hits = graph_success_hits(&analyzer, &service_execute);
    assert_eq!(1, hits.len(), "Service.execute hits were {hits:#?}");
    assert_hit_contains(&hits, "src/main.cpp", "service.execute()");
}

#[test]
fn cpp_graph_prefers_enclosing_namespace_for_bare_constants() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "include/a.h",
            "#pragma once\nnamespace example { inline constexpr int DefaultPrefix = 1; }\n",
        ),
        (
            "include/b.h",
            "#pragma once\nnamespace other { inline constexpr int DefaultPrefix = 2; }\n",
        ),
        (
            "src/use.cpp",
            r#"#include "a.h"
#include "b.h"
namespace other {
int pick() { return DefaultPrefix; }
}
"#,
        ),
    ]);

    let other_prefix = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Field
            && unit.identifier() == "DefaultPrefix"
            && unit.fq_name().contains("other")
    });
    let hits = graph_success_hits(&analyzer, &other_prefix);
    assert_eq!(1, hits.len(), "other::DefaultPrefix hits were {hits:#?}");
    assert_hit_contains(&hits, "src/use.cpp", "return DefaultPrefix");
}

#[test]
fn cpp_graph_keeps_unresolved_qualified_free_function_alias_unproven() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "include/service.h",
            r#"#pragma once
namespace example {
void build_service();
}
"#,
        ),
        (
            "src/main.cpp",
            r#"#include "service.h"
namespace ex = example;
int main() {
    ex::build_service();
}
"#,
        ),
    ]);

    let build_service = function_definition(&analyzer, "build_service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let result = CppUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&build_service),
        &candidates,
        1000,
    );
    assert_success_counts(result, &build_service, 0, 1);
}

#[test]
fn authoritative_cpp_usage_resolves_relative_and_templated_qualified_owners_lexically() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "owners.h",
            r#"#pragma once
namespace outer {
struct Owner { static void run(); };
namespace inner {
struct Owner { static void run(); };
}
template <typename T>
struct Supplement { static void trace(); };
}

namespace wrong {
struct Owner { static void run(); };
template <typename T>
struct Supplement { static void trace(); };
}

struct Owner { static void run(); };
template <typename T>
struct Supplement { static void trace(); };
"#,
        ),
        (
            "consumer.cpp",
            r#"#include "owners.h"
namespace outer {
void consume() {
    Owner::run();                         // outer-relative
    ::outer::Owner::run();                // outer-fully-qualified
    inner::Owner::run();                  // inner-relative
    ::outer::inner::Owner::run();         // inner-fully-qualified
    Supplement<int>::trace();             // template-relative
    ::outer::Supplement<int>::trace();    // template-fully-qualified

    ::wrong::Owner::run();                // wrong-namespace
    ::Owner::run();                       // wrong-global
    ::wrong::Supplement<int>::trace();    // wrong-template-namespace
    ::Supplement<int>::trace();           // wrong-template-global
}
}
"#,
        ),
    ]);

    let method = |owner_fq_name: &str, member_name: &str| {
        definition_by(&analyzer, |unit| {
            unit.kind() == CodeUnitType::Function
                && unit.identifier() == member_name
                && unit.fq_name() == format!("{owner_fq_name}.{member_name}")
        })
    };
    let outer_run = method("outer.Owner", "run");
    let inner_run = method("outer::inner.Owner", "run");
    let supplement_trace = method("outer.Supplement", "trace");
    let consumer = project.file("consumer.cpp");
    let source = consumer.read_to_string().expect("consumer source");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));

    let terminal_range = |needle: &str, terminal: &str| {
        let occurrence = source
            .find(needle)
            .unwrap_or_else(|| panic!("missing {needle}"));
        let terminal_offset = needle
            .find(terminal)
            .unwrap_or_else(|| panic!("missing terminal {terminal} in {needle}"));
        let start = occurrence + terminal_offset;
        (start, start + terminal.len())
    };
    let outer_ranges = [
        terminal_range(
            "Owner::run();                         // outer-relative",
            "run",
        ),
        terminal_range(
            "::outer::Owner::run();                // outer-fully-qualified",
            "run",
        ),
    ];
    let inner_ranges = [
        terminal_range(
            "inner::Owner::run();                  // inner-relative",
            "run",
        ),
        terminal_range(
            "::outer::inner::Owner::run();         // inner-fully-qualified",
            "run",
        ),
    ];
    let supplement_ranges = [
        terminal_range(
            "Supplement<int>::trace();             // template-relative",
            "trace",
        ),
        terminal_range(
            "::outer::Supplement<int>::trace();    // template-fully-qualified",
            "trace",
        ),
    ];

    let assert_exact_authoritative_hits =
        |target: &CodeUnit, expected_ranges: &[(usize, usize)]| {
            let query = UsageFinder::new()
                .with_authoritative_scope(true)
                .query_with_provider(
                    &analyzer,
                    std::slice::from_ref(target),
                    Some(&provider),
                    1,
                    1000,
                );
            assert_eq!(
                query.candidate_files,
                std::iter::once(consumer.clone()).collect(),
                "authoritative query must scan only the explicit consumer"
            );
            let FuzzyResult::Success {
                hits_by_overload,
                unproven_by_overload,
                unproven_total_by_overload,
                ..
            } = query.result
            else {
                panic!("expected authoritative C++ success for {target:#?}");
            };
            let hits = hits_by_overload.get(target).cloned().unwrap_or_default();
            assert_eq!(
                hits.len(),
                expected_ranges.len(),
                "expected only relative and fully-qualified target hits for {target:#?}: {hits:#?}"
            );
            for (start, end) in expected_ranges {
                assert!(
                    hits.iter().any(|hit| {
                        hit.file == consumer && hit.start_offset == *start && hit.end_offset == *end
                    }),
                    "missing exact terminal range {start}..{end} for {target:#?}: {hits:#?}"
                );
            }
            assert_eq!(
                unproven_total_by_overload
                    .get(target)
                    .copied()
                    .unwrap_or_default(),
                0,
                "wrong namespace/global same-name sites must be known non-targets: {unproven_by_overload:#?}"
            );
        };

    assert_exact_authoritative_hits(&outer_run, &outer_ranges);
    assert_exact_authoritative_hits(&inner_run, &inner_ranges);
    assert_exact_authoritative_hits(&supplement_trace, &supplement_ranges);
}

#[test]
fn authoritative_cpp_usage_lets_nearer_lexical_owner_veto_legacy_qualified_matches() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "owners.h",
            r#"#pragma once
struct Owner {
    static void run();
    static int value;
};
namespace outer {
struct Owner {
    static void run();
    static int value;
};
namespace near {
struct Owner {
    static void run();
    static int value;
};
}
}
"#,
        ),
        (
            "consumer.cpp",
            r#"#include "owners.h"
namespace outer {
namespace near {
void Owner::run() {}
int read() { return Owner::value; }
}
}
"#,
        ),
    ]);

    let target = |fq_name: &str, kind: CodeUnitType| {
        definition_by(&analyzer, |unit| {
            unit.kind() == kind && unit.fq_name() == fq_name
        })
    };
    let targets = [
        target("Owner.run", CodeUnitType::Function),
        target("outer.Owner.run", CodeUnitType::Function),
        target("Owner.value", CodeUnitType::Field),
        target("outer.Owner.value", CodeUnitType::Field),
    ];
    let consumer = project.file("consumer.cpp");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));

    for target in targets {
        let query = UsageFinder::new()
            .with_authoritative_scope(true)
            .query_with_provider(
                &analyzer,
                std::slice::from_ref(&target),
                Some(&provider),
                1,
                1000,
            );
        assert_eq!(
            query.candidate_files,
            std::iter::once(consumer.clone()).collect(),
            "authoritative query must scan only the explicit consumer"
        );
        assert_success_counts(query.result, &target, 0, 0);
    }
}

#[test]
fn authoritative_cpp_usage_resolves_relative_owner_through_enclosing_class_tiers() {
    let (project, analyzer) = cpp_analyzer_with_files(&[(
        "consumer.cpp",
        r#"namespace outer {
struct Container {
    struct Nested { static void run(); };
    void inline_call() { Nested::run(); }
    void out_of_line_call();
};

void Container::out_of_line_call() {
    Nested::run();
}
}
"#,
    )]);

    let target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function && unit.fq_name() == "outer.Container$Nested.run"
    });
    let consumer = project.file("consumer.cpp");
    let source = consumer.read_to_string().expect("consumer source");
    let expected = source
        .match_indices("Nested::run();")
        .map(|(start, _)| {
            let terminal = start + "Nested::".len();
            (terminal, terminal + "run".len())
        })
        .collect::<Vec<_>>();
    assert_eq!(expected.len(), 2, "inline fixture call count");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        );
    let FuzzyResult::Success {
        hits_by_overload,
        unproven_total_by_overload,
        ..
    } = query.result
    else {
        panic!("expected authoritative enclosing-class success");
    };
    let hits = hits_by_overload.get(&target).cloned().unwrap_or_default();
    assert_eq!(
        hits.len(),
        expected.len(),
        "enclosing-class hits: {hits:#?}"
    );
    for (start, end) in expected {
        assert!(
            hits.iter().any(|hit| {
                hit.file == consumer && hit.start_offset == start && hit.end_offset == end
            }),
            "missing exact enclosing-class terminal {start}..{end}: {hits:#?}"
        );
    }
    assert_eq!(
        unproven_total_by_overload
            .get(&target)
            .copied()
            .unwrap_or_default(),
        0,
        "enclosing-class relative owners should resolve without unproven hits"
    );
}

#[test]
fn authoritative_cpp_usage_keeps_relative_owner_unproven_when_enclosing_owner_is_missing() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "targets.h",
            r#"#pragma once
namespace outer {
struct Nested { static void run(); };
}
"#,
        ),
        (
            "consumer.cpp",
            r#"#include "targets.h"
namespace outer {
void MissingContainer::call() {
    Nested::run();
}
}
"#,
        ),
    ]);

    let target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function && unit.fq_name() == "outer.Nested.run"
    });
    let consumer = project.file("consumer.cpp");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        );

    assert_eq!(
        query.candidate_files,
        std::iter::once(consumer).collect(),
        "authoritative query must scan only the partial-workspace consumer"
    );
    assert_success_counts(query.result, &target, 0, 1);
}

#[test]
fn authoritative_cpp_usage_routes_default_argument_redeclarations_in_either_target_order() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "include/api.h",
            r#"#pragma once
namespace demo {
void route(int required, int optional = 0);
}
"#,
        ),
        (
            "src/api.cc",
            r#"#include "../include/api.h"
namespace demo {
void route(int required, int optional) {}
}
"#,
        ),
        (
            "app/consumer.cc",
            r#"#include "../include/api.h"
void consume() {
    demo::route(1);
}
"#,
        ),
    ]);

    let physical_route = |path: &str| {
        definition_by(&analyzer, |unit| {
            unit.kind() == CodeUnitType::Function
                && unit.fq_name() == "demo.route"
                && slash_path(unit.source()) == path
        })
    };
    let implementation = physical_route("src/api.cc");
    let declaration = physical_route("include/api.h");
    assert_ne!(implementation.source(), declaration.source());
    assert_eq!(implementation.fq_name(), declaration.fq_name());

    let consumer = project.file("app/consumer.cc");
    let source = consumer.read_to_string().expect("consumer source");
    let call = source.find("demo::route(1)").expect("route call");
    let start = call;
    let end = start + "demo::route".len();
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));

    for targets in [
        [implementation.clone(), declaration.clone()],
        [declaration.clone(), implementation.clone()],
    ] {
        let query = UsageFinder::new()
            .with_authoritative_scope(true)
            .query_with_provider(&analyzer, &targets, Some(&provider), 1, 1000);
        assert_eq!(
            query.candidate_files,
            std::iter::once(consumer.clone()).collect(),
            "authoritative query must scan only the explicit consumer"
        );
        let FuzzyResult::Success {
            hits_by_overload,
            unproven_total_by_overload,
            ..
        } = query.result
        else {
            panic!("expected authoritative route success for {targets:#?}");
        };
        let hits = hits_by_overload
            .get(&targets[0])
            .cloned()
            .unwrap_or_default();
        assert_eq!(hits.len(), 1, "target-order route hits: {hits:#?}");
        assert!(
            hits.iter().any(|hit| {
                hit.file == consumer && hit.start_offset == start && hit.end_offset == end
            }),
            "missing exact route terminal {start}..{end}: {hits:#?}"
        );
        assert_eq!(
            unproven_total_by_overload
                .get(&targets[0])
                .copied()
                .unwrap_or_default(),
            0,
            "default-argument call should be proven in either physical target order"
        );
    }

    for targets in [
        [implementation.clone(), declaration.clone()],
        [declaration.clone(), implementation.clone()],
    ] {
        let query = UsageFinder::new().query(&analyzer, &targets, 100, 1000);
        assert!(
            query.candidate_files.contains(&consumer),
            "every target must contribute default routing candidates: {targets:#?}, candidates={:#?}",
            query.candidate_files
        );
        let FuzzyResult::Success {
            hits_by_overload, ..
        } = query.result
        else {
            panic!("expected routed route success for {targets:#?}");
        };
        let hits = hits_by_overload
            .get(&targets[0])
            .cloned()
            .unwrap_or_default();
        assert_eq!(
            hits.len(),
            1,
            "queried physical target definitions must not leak into grouped results: {targets:#?}, hits={hits:#?}"
        );
        assert!(
            hits.iter().any(|hit| {
                hit.file == consumer && hit.start_offset == start && hit.end_offset == end
            }),
            "later-target routing must reach the exact consumer call: {targets:#?}, hits={hits:#?}"
        );
        assert!(
            hits.iter().all(|hit| hit.file == consumer),
            "only the consumer call should remain after exact target-group suppression: {targets:#?}, hits={hits:#?}"
        );
    }
}

#[test]
fn authoritative_cpp_usage_routes_overload_group_in_either_target_order() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "api.h",
            r#"#pragma once
namespace demo {
void choose(int value);
void choose(const char* value);
}
"#,
        ),
        (
            "api.cc",
            r#"#include "api.h"
namespace demo {
void choose(int value) {}
void choose(const char* value) {}
}
"#,
        ),
        (
            "consumer.cc",
            r#"#include "api.h"
void consume(char selected) {
    demo::choose(&selected);
}
"#,
        ),
    ]);

    let declared_overload = |matches_signature: fn(&str) -> bool| {
        definition_by(&analyzer, |unit| {
            unit.kind() == CodeUnitType::Function
                && unit.fq_name() == "demo.choose"
                && slash_path(unit.source()) == "api.h"
                && unit.signature().is_some_and(matches_signature)
        })
    };
    let integer = declared_overload(|signature| signature == "(int)");
    let character_pointer = declared_overload(|signature| signature.contains("char"));

    let consumer = project.file("consumer.cc");
    let source = consumer.read_to_string().expect("consumer source");
    let call = source.find("demo::choose(&selected)").expect("choose call");
    let start = call;
    let end = start + "demo::choose".len();
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));

    for targets in [
        [integer.clone(), character_pointer.clone()],
        [character_pointer.clone(), integer.clone()],
    ] {
        let query = UsageFinder::new()
            .with_authoritative_scope(true)
            .query_with_provider(&analyzer, &targets, Some(&provider), 1, 1000);
        assert_eq!(
            query.candidate_files,
            std::iter::once(consumer.clone()).collect(),
            "authoritative query must scan only the explicit consumer"
        );
        let FuzzyResult::Success {
            hits_by_overload,
            unproven_total_by_overload,
            ..
        } = query.result
        else {
            panic!("expected authoritative overload-group success for {targets:#?}");
        };
        let hits = hits_by_overload
            .get(&targets[0])
            .cloned()
            .unwrap_or_default();
        assert_eq!(hits.len(), 1, "target-order overload hits: {hits:#?}");
        assert!(
            hits.iter().any(|hit| {
                hit.file == consumer && hit.start_offset == start && hit.end_offset == end
            }),
            "missing exact choose terminal {start}..{end}: {hits:#?}"
        );
        assert_eq!(
            unproven_total_by_overload
                .get(&targets[0])
                .copied()
                .unwrap_or_default(),
            0,
            "the selected overload should be proven in either target order"
        );
    }
}

#[test]
fn authoritative_cpp_usage_resolves_constructor_owner_from_malformed_export_definition() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        ("widget_fwd.h", "namespace views { class Widget; }\n"),
        (
            "widget.h",
            r#"#define VIEWS_EXPORT
namespace views {
class VIEWS_EXPORT Widget : public internal::NativeWidgetDelegate,
                            public ui::EventSource,
                            public FocusTraversable,
                            public ui::NativeThemeObserver,
                            public ui::ColorProviderSource,
                            public ui::PropertyHandler,
                            public ui::AXModeObserver,
                            public ui::metadata::MetaDataProvider {
    ADVANCED_MEMORY_SAFETY_CHECKS();

 public:
    Widget();
};
}
"#,
        ),
        (
            "widget.cc",
            r#"#include "widget_fwd.h"
#include "widget.h"
views::Widget::Widget() = default;
"#,
        ),
        (
            "consumer.cc",
            r#"#include "widget.h"
void consume() {
    auto* widget = new views::Widget;
}
"#,
        ),
    ]);

    let widget_header = project.file("widget.h");
    let header_source = widget_header.read_to_string().expect("widget header");
    let classes: Vec<_> = analyzer
        .get_all_declarations()
        .into_iter()
        .filter(|unit| {
            unit.kind() == CodeUnitType::Class
                && unit.fq_name() == "views.Widget"
                && unit.source() == &widget_header
                && !unit.is_synthetic()
        })
        .collect();
    assert_eq!(classes.len(), 1, "Widget class identities: {classes:#?}");
    let ranges = analyzer.ranges(&classes[0]);
    assert_eq!(ranges.len(), 1, "Widget class ranges: {ranges:#?}");
    let expected_start = header_source.find("class VIEWS_EXPORT Widget").unwrap();
    let prefix = "ADVANCED_MEMORY_SAFETY_CHECKS();";
    let expected_end =
        header_source[expected_start..].find(prefix).unwrap() + expected_start + prefix.len();
    assert_eq!(ranges[0].start_byte, expected_start);
    assert_eq!(ranges[0].end_byte, expected_end);

    let constructor = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.fq_name() == "views.Widget.Widget"
            && slash_path(unit.source()) == "widget.cc"
            && !unit.is_synthetic()
    });
    let consumer = project.file("consumer.cc");
    let source = consumer.read_to_string().expect("consumer source");
    let expression = source.find("new views::Widget").expect("new expression");
    let start = expression + "new ".len();
    let end = start + "views::Widget".len();
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&constructor),
            Some(&provider),
            1,
            1000,
        );

    assert_eq!(
        query.candidate_files,
        std::iter::once(consumer.clone()).collect(),
        "authoritative query must scan only the explicit consumer"
    );
    let FuzzyResult::Success {
        hits_by_overload,
        unproven_total_by_overload,
        ..
    } = query.result
    else {
        panic!("expected authoritative Widget constructor success");
    };
    let hits = hits_by_overload
        .get(&constructor)
        .cloned()
        .unwrap_or_default();
    assert_eq!(hits.len(), 1, "Widget constructor hits: {hits:#?}");
    assert!(
        hits.iter().any(|hit| {
            hit.file == consumer && hit.start_offset == start && hit.end_offset == end
        }),
        "missing exact new-expression type range {start}..{end}: {hits:#?}"
    );
    assert_eq!(
        unproven_total_by_overload
            .get(&constructor)
            .copied()
            .unwrap_or_default(),
        0,
        "the recovered full class definition plus a forward declaration should resolve precisely"
    );
}

#[test]
fn authoritative_cpp_usage_resolves_constructor_owner_from_unique_transitive_definition() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        ("widget_fwd.h", "namespace demo { class Widget; }\n"),
        (
            "widget.h",
            r#"namespace demo {
class Widget {
public:
    Widget();
};
}
"#,
        ),
        ("bridge.h", "#include \"widget.h\"\n"),
        (
            "widget.cc",
            r#"#include "widget_fwd.h"
#include "bridge.h"
namespace demo {
Widget::Widget() = default;
}
"#,
        ),
        (
            "consumer.cc",
            r#"#include "widget.h"
void consume() {
    auto* widget = new demo::Widget;
}
"#,
        ),
    ]);

    let constructor = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.fq_name() == "demo.Widget.Widget"
            && slash_path(unit.source()) == "widget.cc"
            && !unit.is_synthetic()
    });
    let consumer = project.file("consumer.cc");
    let provider = ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer).collect()));
    let result = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&constructor),
            Some(&provider),
            1,
            1000,
        )
        .result;

    assert_success_counts(result, &constructor, 1, 0);
}

#[test]
fn authoritative_cpp_usage_keeps_constructor_owner_unresolved_with_only_direct_forwards() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        ("one/widget_fwd.h", "namespace demo { class Widget; }\n"),
        ("two/widget_fwd.h", "namespace demo { class Widget; }\n"),
        (
            "widget.h",
            r#"namespace demo {
class Widget {
public:
    Widget();
};
}
"#,
        ),
        (
            "widget.cc",
            r#"#include "one/widget_fwd.h"
#include "two/widget_fwd.h"
namespace demo {
Widget::Widget() = default;
}
"#,
        ),
        (
            "consumer.cc",
            r#"#include "widget.h"
void consume() {
    auto* widget = new demo::Widget;
}
"#,
        ),
    ]);

    let constructor = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.fq_name() == "demo.Widget.Widget"
            && slash_path(unit.source()) == "widget.cc"
            && !unit.is_synthetic()
    });
    let consumer = project.file("consumer.cc");
    let provider = ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer).collect()));
    let result = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&constructor),
            Some(&provider),
            1,
            1000,
        )
        .result;

    assert_success_counts(result, &constructor, 0, 0);
}

#[test]
fn authoritative_cpp_usage_keeps_constructor_owner_ambiguous_with_two_transitive_definitions() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        ("widget_fwd.h", "namespace demo { class Widget; }\n"),
        (
            "one/widget.h",
            r#"namespace demo {
class Widget {
public:
    Widget();
};
}
"#,
        ),
        (
            "two/widget.h",
            r#"namespace demo {
class Widget {
public:
    Widget();
};
}
"#,
        ),
        (
            "bridge.h",
            r#"#include "one/widget.h"
#include "two/widget.h"
"#,
        ),
        (
            "widget.cc",
            r#"#include "widget_fwd.h"
#include "bridge.h"
namespace demo {
Widget::Widget() = default;
}
"#,
        ),
        (
            "consumer.cc",
            r#"#include "one/widget.h"
void consume() {
    auto* widget = new demo::Widget;
}
"#,
        ),
    ]);

    let constructor = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.fq_name() == "demo.Widget.Widget"
            && slash_path(unit.source()) == "widget.cc"
            && !unit.is_synthetic()
    });
    let consumer = project.file("consumer.cc");
    let provider = ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer).collect()));
    let result = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&constructor),
            Some(&provider),
            1,
            1000,
        )
        .result;

    assert_success_counts(result, &constructor, 0, 0);
}

#[test]
fn authoritative_cpp_usage_resolves_qualified_method_value_to_exact_owner() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "worker.h",
            r#"#pragma once
namespace demo {
class Worker {
public:
    void OnDone();
    void Arm();
};
class Other {
public:
    void OnDone();
};
}
"#,
        )
        .file(
            "worker.cc",
            r#"#include "worker.h"
namespace demo {
void Worker::OnDone() {}
void Other::OnDone() {}
void Worker::Arm() {
    auto callback = &Worker::OnDone;
    auto wrong_owner = &Other::OnDone;
}
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.fq_name() == "demo.Worker.OnDone"
            && slash_path(unit.source()) == "worker.cc"
            && !unit.is_synthetic()
    });
    let worker = project.file("worker.cc");
    let source = worker.read_to_string().expect("worker source");
    let positive = source.find("&Worker::OnDone").expect("Worker method value");
    let positive_start = positive + "&Worker::".len();
    let positive_end = positive_start + "OnDone".len();
    let wrong_owner = source.find("&Other::OnDone").expect("Other method value");
    let wrong_owner_start = wrong_owner + "&Other::".len();
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(worker.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        );

    assert_eq!(
        query.candidate_files,
        std::iter::once(worker.clone()).collect(),
        "authoritative scan must remain limited to worker.cc"
    );
    let FuzzyResult::Success {
        hits_by_overload,
        unproven_total_by_overload,
        ..
    } = query.result
    else {
        panic!("expected authoritative C++ method-value success");
    };
    let hits = hits_by_overload.get(&target).cloned().unwrap_or_default();
    assert_eq!(hits.len(), 1, "Worker::OnDone hits: {hits:#?}");
    assert!(
        hits.iter().any(|hit| {
            hit.file == worker
                && hit.start_offset == positive_start
                && hit.end_offset == positive_end
        }),
        "missing exact OnDone member-token hit {positive_start}..{positive_end}: {hits:#?}"
    );
    assert!(
        hits.iter().all(|hit| {
            !(hit.start_offset <= wrong_owner_start
                && wrong_owner_start + "OnDone".len() <= hit.end_offset)
        }),
        "Other::OnDone must not cross over to Worker::OnDone: {hits:#?}"
    );
    assert_eq!(
        unproven_total_by_overload
            .get(&target)
            .copied()
            .unwrap_or_default(),
        0,
        "owner-qualified method values should be proven, not fuzzy"
    );
}

#[test]
fn authoritative_cpp_usage_keeps_overloaded_qualified_method_value_unproven() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "worker.h",
            r#"#pragma once
namespace demo {
class Worker {
public:
    void OnDone();
    void OnDone(int value);
    void Arm();
};
}
"#,
        )
        .file(
            "worker.cc",
            r#"#include "worker.h"
namespace demo {
void Worker::OnDone() {}
void Worker::OnDone(int value) {}
void Worker::Arm() {
    auto callback = &Worker::OnDone;
}
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.fq_name() == "demo.Worker.OnDone"
            && unit.signature() == Some("()")
            && slash_path(unit.source()) == "worker.cc"
            && !unit.is_synthetic()
    });
    let worker = project.file("worker.cc");
    let provider = ExplicitCandidateProvider::new(Arc::new(std::iter::once(worker).collect()));
    let result = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        )
        .result;

    assert_success_counts(result, &target, 0, 1);
}

#[test]
fn authoritative_cpp_method_usage_rejects_qualified_namespace_function_value() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "worker.h",
            r#"#pragma once
namespace demo {
void OnDone();
class Worker {
public:
    void OnDone();
    void Arm();
};
}
"#,
        )
        .file(
            "worker.cc",
            r#"#include "worker.h"
namespace demo {
void OnDone() {}
void Worker::OnDone() {}
void Worker::Arm() {
    auto callback = &demo::OnDone;
}
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.fq_name() == "demo.Worker.OnDone"
            && slash_path(unit.source()) == "worker.cc"
            && !unit.is_synthetic()
    });
    let worker = project.file("worker.cc");
    let provider = ExplicitCandidateProvider::new(Arc::new(std::iter::once(worker).collect()));
    let result = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        )
        .result;

    assert_success_counts(result, &target, 0, 0);
}

#[test]
fn authoritative_cpp_method_values_apply_lexical_type_and_namespace_shadowing() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "worker.h",
            r#"#pragma once
namespace Worker {
void OnDone();
}
namespace outer {
namespace inner {
void helper();
}
class Worker {
public:
    void OnDone();
    void helper();
    void Arm();
};
}
"#,
        )
        .file(
            "worker.cc",
            r#"#include "worker.h"
namespace Worker {
void OnDone() {}
}
namespace outer {
namespace inner {
void helper() {}
}
void Worker::OnDone() {}
void Worker::helper() {}
void Worker::Arm() {
    auto method_value = &Worker::OnDone;
    auto function_value = &inner::helper;
}
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let source = project.file("worker.cc");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(source.clone()).collect()));
    let method = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.fq_name() == "outer.Worker.OnDone"
            && slash_path(unit.source()) == "worker.cc"
            && !unit.is_synthetic()
    });
    let method_result = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&method),
            Some(&provider),
            1,
            1000,
        )
        .result;
    assert_success_counts(method_result, &method, 1, 0);

    let namesake_method = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.fq_name() == "outer.Worker.helper"
            && slash_path(unit.source()) == "worker.cc"
            && !unit.is_synthetic()
    });
    let namespace_result = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&namesake_method),
            Some(&provider),
            1,
            1000,
        )
        .result;
    assert_success_counts(namespace_result, &namesake_method, 0, 0);
}

#[test]
fn authoritative_cpp_usage_preserves_pointer_to_data_member_reference() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "worker.h",
            r#"#pragma once
namespace demo {
class Worker {
public:
    int state;
    void Arm();
};
}
"#,
        )
        .file(
            "worker.cc",
            r#"#include "worker.h"
namespace demo {
void Worker::Arm() {
    auto member = &Worker::state;
}
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Field
            && unit.fq_name() == "demo.Worker.state"
            && slash_path(unit.source()) == "worker.h"
    });
    let worker = project.file("worker.cc");
    let provider = ExplicitCandidateProvider::new(Arc::new(std::iter::once(worker).collect()));
    let result = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        )
        .result;

    assert_success_counts(result, &target, 1, 0);
}

#[test]
fn authoritative_cpp_usage_resolves_leading_global_qualified_method_value() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "worker.h",
            r#"#pragma once
namespace demo {
class Worker {
public:
    void OnDone();
    void Arm();
};
}
"#,
        )
        .file(
            "worker.cc",
            r#"#include "worker.h"
namespace demo {
void Worker::OnDone() {}
void Worker::Arm() {
    auto callback = &::demo::Worker::OnDone;
}
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.fq_name() == "demo.Worker.OnDone"
            && slash_path(unit.source()) == "worker.cc"
            && !unit.is_synthetic()
    });
    let worker = project.file("worker.cc");
    let source = worker.read_to_string().expect("worker source");
    let qualified = source
        .find("&::demo::Worker::OnDone")
        .expect("leading-global method value");
    let start = qualified + "&::demo::Worker::".len();
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(worker.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        );
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = query.result
    else {
        panic!("expected leading-global method-value success");
    };
    let hits = hits_by_overload.get(&target).cloned().unwrap_or_default();
    assert_eq!(hits.len(), 1, "leading-global hits: {hits:#?}");
    assert!(
        hits.iter().any(|hit| {
            hit.file == worker
                && hit.start_offset == start
                && hit.end_offset == start + "OnDone".len()
        }),
        "missing exact leading-global terminal hit: {hits:#?}"
    );
}

#[test]
fn authoritative_cpp_usage_covers_qualified_and_short_alias_redeclarations() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "bridge.h",
            r#"#pragma once
namespace demo {
class ArcBluetoothBridge {
public:
    using AdapterStateCallback = void (*)(bool);
    void OnPoweredOn(AdapterStateCallback callback, bool powered);
    void Arm();
};
}
"#,
        )
        .file(
            "bridge.cc",
            r#"#include "bridge.h"
namespace demo {
void ArcBluetoothBridge::OnPoweredOn(
    ArcBluetoothBridge::AdapterStateCallback callback,
    bool powered) {}
void ArcBluetoothBridge::Arm() {
    auto callback = &ArcBluetoothBridge::OnPoweredOn;
}
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let declarations = analyzer.get_all_declarations();
    let mut targets = declarations
        .iter()
        .filter(|unit| {
            unit.kind() == CodeUnitType::Function
                && unit.fq_name() == "demo.ArcBluetoothBridge.OnPoweredOn"
        })
        .cloned()
        .collect::<Vec<_>>();
    targets.sort_by_key(|unit| unit.is_synthetic());
    assert_eq!(targets.len(), 2, "physical targets: {targets:#?}");
    assert!(
        targets.iter().any(|unit| {
            unit.signature() == Some("(ArcBluetoothBridge::AdapterStateCallback, bool)")
        }) && targets
            .iter()
            .any(|unit| unit.signature() == Some("(AdapterStateCallback, bool)")),
        "fixture must preserve qualified-vs-short physical signatures: {targets:#?}"
    );
    let source = project.file("bridge.cc");
    let provider = ExplicitCandidateProvider::new(Arc::new(std::iter::once(source).collect()));
    let result = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(&analyzer, &targets, Some(&provider), 1, 1000)
        .result;

    assert_success_counts(result, &targets[0], 1, 0);
}

#[test]
fn authoritative_cpp_class_usage_keeps_owner_header_parameter_type() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "owner.h",
            r#"namespace ns {
class Owner {
public:
    Owner& operator=(const Owner&) = delete;
};
}
"#,
        ),
        (
            "consumer.cc",
            r#"#include "owner.h"
void consume(const ns::Owner* value);
"#,
        ),
    ]);
    let target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class && unit.fq_name() == "ns.Owner" && !unit.is_synthetic()
    });
    let owner = project.file("owner.h");
    let source = owner.read_to_string().expect("owner header");
    let return_start = source
        .find("Owner& operator")
        .expect("operator return type");
    let return_end = return_start + "Owner".len();
    let parameter = source.find("const Owner&").expect("operator parameter");
    let parameter_start = parameter + "const ".len();
    let parameter_end = parameter_start + "Owner".len();
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(owner.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        );
    assert_eq!(
        query.candidate_files,
        std::iter::once(owner.clone()).collect(),
        "authoritative query must scan only owner.h"
    );
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = query.result
    else {
        panic!("expected authoritative owner-header class usage success");
    };
    let hits = hits_by_overload.get(&target).cloned().unwrap_or_default();
    assert_eq!(
        hits.len(),
        2,
        "only the operator return and parameter types are Class usages: {hits:#?}"
    );
    assert_eq!(
        hits.iter()
            .map(|hit| {
                assert_eq!(hit.file, owner);
                (hit.start_offset, hit.end_offset)
            })
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([(return_start, return_end), (parameter_start, parameter_end),]),
        "exact Owner type_identifiers must survive while declaration names stay excluded"
    );
}

#[test]
fn authoritative_cpp_class_usage_keeps_consumer_qualified_parameter_type() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "owner.h",
            r#"namespace ns {
class Owner {
public:
    Owner& operator=(const Owner&) = delete;
};
}

"#,
        ),
        (
            "consumer.cc",
            r#"#include "owner.h"
void consume(const ns::Owner* value);
"#,
        ),
    ]);
    let target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class && unit.fq_name() == "ns.Owner" && !unit.is_synthetic()
    });
    let consumer = project.file("consumer.cc");
    let source = consumer.read_to_string().expect("consumer source");
    let expected_start = source.find("ns::Owner").expect("qualified parameter type");
    let expected_end = expected_start + "ns::Owner".len();
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        );
    assert_eq!(
        query.candidate_files,
        std::iter::once(consumer.clone()).collect(),
        "authoritative query must scan only consumer.cc"
    );
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = query.result
    else {
        panic!("expected authoritative consumer class usage success");
    };
    let hits = hits_by_overload.get(&target).cloned().unwrap_or_default();
    assert_eq!(
        hits.len(),
        1,
        "only the qualified parameter type is a Class usage: {hits:#?}"
    );
    let hit = hits.iter().next().expect("one consumer type hit");
    assert_eq!(hit.file, consumer);
    assert_eq!(
        (hit.start_offset, hit.end_offset),
        (expected_start, expected_end),
        "the exact ns::Owner type node must be returned, excluding value"
    );
}

#[test]
fn authoritative_cpp_class_usage_distinguishes_named_and_abstract_declarators() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        ("owner.h", "namespace ns { class Owner {}; }\n"),
        (
            "consumer.cc",
            r#"#include "owner.h"
void named_pointer(const ns::Owner* Owner);
void unnamed_pointer(const ns::Owner*);
void named_reference(const ns::Owner& Owner);
void unnamed_reference(const ns::Owner&);
void named_array(const ns::Owner Owner[2]);
void unnamed_array(const ns::Owner [2]);
void named_function(void (*Owner)(ns::Owner));
void unnamed_function(void (*)(ns::Owner));
typedef ns::Owner Owner;
"#,
        ),
    ]);
    let target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class && unit.fq_name() == "ns.Owner" && !unit.is_synthetic()
    });
    let consumer = project.file("consumer.cc");
    let source = consumer.read_to_string().expect("consumer source");
    let expected = source
        .match_indices("ns::Owner")
        .map(|(start, text)| (start, start + text.len()))
        .collect::<BTreeSet<_>>();
    assert_eq!(expected.len(), 9, "fixture type occurrences");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        );
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = query.result
    else {
        panic!("expected named/abstract declarator class usage success");
    };
    let hits = hits_by_overload.get(&target).cloned().unwrap_or_default();
    assert_eq!(
        hits.iter()
            .map(|hit| {
                assert_eq!(hit.file, consumer);
                (hit.start_offset, hit.end_offset)
            })
            .collect::<BTreeSet<_>>(),
        expected,
        "all named/unnamed pointer, reference, array, function, and alias RHS types must hit exactly; actual Owner declarator names must not"
    );
}

#[test]
fn authoritative_cpp_class_usage_resolves_bare_type_in_lexical_namespace() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "types.h",
            r#"#pragma once
namespace alpha {
class Value {};
}

namespace beta {
class Value {};
}
"#,
        )
        .file(
            "consumer.cc",
            r#"#include "types.h"
namespace alpha {
void consume() {
    Value local;
    ::alpha::Value explicit_alpha;
    beta::Value explicit_beta;
}
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.fq_name() == "alpha.Value"
            && !unit.is_synthetic()
    });
    let consumer = project.file("consumer.cc");
    let source = consumer.read_to_string().expect("consumer source");
    let bare_start = source.find("Value local").expect("bare lexical type");
    let bare_end = bare_start + "Value".len();
    let line_start = source[..bare_start]
        .rfind('\n')
        .map_or(0, |newline| newline + 1);
    let line = source[..bare_start]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1;
    let column = source[line_start..bare_start].chars().count() + 1;
    let forward = brokk_bifrost::searchtools::get_definitions_by_location(
        &analyzer,
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                path: "consumer.cc".to_string(),
                line: Some(line),
                column: Some(column),
            }],
        },
    );
    let forward_result = &forward.results[0];
    assert_eq!("resolved", forward_result.status, "{forward_result:#?}");
    assert!(
        forward_result
            .definitions
            .iter()
            .any(|definition| definition.fqn.as_deref() == Some("alpha.Value")),
        "bare Value must forward-resolve through namespace alpha: {forward_result:#?}"
    );
    assert!(
        !forward_result
            .definitions
            .iter()
            .any(|definition| definition.fqn.as_deref() == Some("beta.Value")),
        "bare Value must not forward-resolve to beta.Value: {forward_result:#?}"
    );

    let explicit_start = source.find("::alpha::Value").expect("explicit alpha type");
    let explicit_end = explicit_start + "::alpha::Value".len();
    let expected = BTreeSet::from([(bare_start, bare_end), (explicit_start, explicit_end)]);
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        );
    assert_eq!(
        query.candidate_files,
        std::iter::once(consumer.clone()).collect(),
        "authoritative query must scan only consumer.cc"
    );
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = query.result
    else {
        panic!("expected authoritative lexical-type usage success");
    };
    let hits = hits_by_overload.get(&target).cloned().unwrap_or_default();
    let actual = hits
        .iter()
        .map(|hit| {
            assert_eq!(hit.file, consumer);
            (hit.start_offset, hit.end_offset)
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual, expected,
        "bare and explicit alpha types must hit exactly; beta.Value and declarator names must not: {hits:#?}"
    );
}

#[test]
fn authoritative_cpp_type_resolution_preserves_global_nested_template_and_alias_tiers() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "types.h",
            r#"#pragma once
class Value {};
namespace alpha {
class Value {};
class Canonical {};
using Alias = Canonical;
template <typename T> class Box {};
class Outer { public: class Inner {}; };
}
namespace beta {
class Value {};
class Canonical {};
using Alias = Canonical;
}
"#,
        )
        .file(
            "consumer.cc",
            r#"#include "types.h"
namespace alpha {
void consume() {
    Value lexical_value;
    ::Value global_value;
    ::alpha::Value explicit_alpha;
    beta::Value explicit_beta;
    Alias lexical_alias;
    beta::Alias explicit_beta_alias;
    Outer::Inner nested_value;
    Box<Value> templated_value;
}
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let consumer = project.file("consumer.cc");
    let source = consumer.read_to_string().expect("consumer source");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let target = |fq_name: &str| {
        definition_by(&analyzer, |unit| {
            unit.kind() == CodeUnitType::Class && unit.fq_name() == fq_name && !unit.is_synthetic()
        })
    };
    let exact_hits = |target: &CodeUnit| {
        let result = UsageFinder::new()
            .with_authoritative_scope(true)
            .query_with_provider(
                &analyzer,
                std::slice::from_ref(target),
                Some(&provider),
                1,
                1000,
            )
            .result;
        let FuzzyResult::Success {
            hits_by_overload, ..
        } = result
        else {
            panic!("expected authoritative type usage success for {target:#?}");
        };
        hits_by_overload
            .get(target)
            .into_iter()
            .flatten()
            .map(|hit| {
                assert_eq!(hit.file, consumer);
                (hit.start_offset, hit.end_offset)
            })
            .collect::<BTreeSet<_>>()
    };
    let range = |line: &str, token: &str| {
        let line_start = source
            .find(line)
            .unwrap_or_else(|| panic!("missing fixture line {line}"));
        let token_start = line
            .find(token)
            .unwrap_or_else(|| panic!("missing {token} in {line}"));
        let start = line_start + token_start;
        (start, start + token.len())
    };

    assert_eq!(
        exact_hits(&target("alpha.Value")),
        BTreeSet::from([
            range("Value lexical_value;", "Value"),
            range("::alpha::Value explicit_alpha;", "::alpha::Value"),
            range("Box<Value> templated_value;", "Value"),
        ])
    );
    assert_eq!(
        exact_hits(&target("Value")),
        BTreeSet::from([range("::Value global_value;", "::Value")])
    );
    assert_eq!(
        exact_hits(&target("alpha.Canonical")),
        BTreeSet::from([range("Alias lexical_alias;", "Alias")])
    );
    assert_eq!(
        exact_hits(&target("beta.Canonical")),
        BTreeSet::from([range("beta::Alias explicit_beta_alias;", "beta::Alias",)])
    );
    assert_eq!(
        exact_hits(&target("alpha.Outer$Inner")),
        BTreeSet::from([range("Outer::Inner nested_value;", "Outer::Inner")])
    );
}

#[test]
fn authoritative_cpp_type_resolution_rejects_ambiguous_nearest_alias_tier() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "types.h",
            r#"class Canonical {};
using Choice = Canonical;
namespace alpha { class Canonical {}; }
"#,
        )
        .file(
            "left.h",
            r#"#include "types.h"
namespace alpha { using Choice = Canonical; }
"#,
        )
        .file(
            "right.h",
            r#"#include "types.h"
namespace alpha { using Choice = ::Canonical; }
"#,
        )
        .file(
            "consumer.cc",
            r#"#include "left.h"
#include "right.h"
namespace alpha {
void consume() {
    Choice ambiguous;
    ::Canonical global_control;
    ::alpha::Canonical alpha_control;
}
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let consumer = project.file("consumer.cc");
    let source = consumer.read_to_string().expect("consumer source");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let exact_hits = |fq_name: &str| {
        let target = definition_by(&analyzer, |unit| {
            unit.kind() == CodeUnitType::Class && unit.fq_name() == fq_name && !unit.is_synthetic()
        });
        let result = UsageFinder::new()
            .with_authoritative_scope(true)
            .query_with_provider(
                &analyzer,
                std::slice::from_ref(&target),
                Some(&provider),
                1,
                1000,
            )
            .result;
        let FuzzyResult::Success {
            hits_by_overload, ..
        } = result
        else {
            panic!("expected authoritative ambiguous-tier query success");
        };
        hits_by_overload
            .get(&target)
            .into_iter()
            .flatten()
            .map(|hit| (hit.start_offset, hit.end_offset))
            .collect::<BTreeSet<_>>()
    };
    let range = |token: &str| {
        let start = source
            .find(token)
            .unwrap_or_else(|| panic!("missing {token}"));
        (start, start + token.len())
    };

    assert_eq!(
        exact_hits("Canonical"),
        BTreeSet::from([range("::Canonical")]),
        "conflicting alpha::Choice must not fall through to global Choice"
    );
    assert_eq!(
        exact_hits("alpha.Canonical"),
        BTreeSet::from([range("::alpha::Canonical")]),
        "conflicting alpha::Choice must not choose either canonical owner"
    );
}

#[test]
fn authoritative_cpp_nested_type_keeps_outer_owner_qualifier_usage() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "types.h",
            r#"namespace alpha {
class Outer {
public:
    class Inner {};
};
}
namespace beta {
class Outer {
public:
    class Inner {};
};
}
"#,
        )
        .file(
            "consumer.cc",
            r#"#include "types.h"
namespace alpha {
void consume() {
    Outer::Inner value;
}
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.fq_name() == "alpha.Outer"
            && !unit.is_synthetic()
    });
    let consumer = project.file("consumer.cc");
    let source = consumer.read_to_string().expect("consumer source");
    let expected_start = source.find("Outer::Inner").expect("nested type");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let result = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        )
        .result;
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = result
    else {
        panic!("expected authoritative outer-owner query success");
    };
    let hits = hits_by_overload.get(&target).cloned().unwrap_or_default();

    assert_eq!(
        hits.len(),
        1,
        "only Outer is an outer-owner usage: {hits:#?}"
    );
    let hit = hits.iter().next().expect("outer owner hit");
    assert_eq!(hit.file, consumer);
    assert_eq!(
        (hit.start_offset, hit.end_offset),
        (expected_start, expected_start + "Outer".len()),
        "nested full-type resolution must retain its exact outer qualifier usage"
    );

    let beta_target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class && unit.fq_name() == "beta.Outer" && !unit.is_synthetic()
    });
    let beta_result = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&beta_target),
            Some(&provider),
            1,
            1000,
        )
        .result;
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = beta_result
    else {
        panic!("expected authoritative beta outer-owner query success");
    };
    assert!(
        hits_by_overload
            .get(&beta_target)
            .is_some_and(BTreeSet::is_empty),
        "lexical alpha Outer qualifier must not leak to beta.Outer: {hits_by_overload:#?}"
    );
}

#[test]
fn authoritative_cpp_template_alias_resolves_to_canonical_type() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "canonical.h",
            r#"#pragma once
namespace jni_zero {
template <typename T>
class ScopedJavaGlobalRef {};
class Plain {};
}
"#,
        )
        .file(
            "aliases.h",
            r#"#pragma once
#include "canonical.h"
namespace base::android {
using Plain = jni_zero::Plain;
template <typename T>
using ScopedJavaGlobalRef = jni_zero::ScopedJavaGlobalRef<T>;
}
"#,
        )
        .file(
            "consumer.cc",
            r#"#include "aliases.h"
namespace content {
struct Params {
    base::android::Plain plain;
    base::android::ScopedJavaGlobalRef<int> java_ref;
};
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let consumer = project.file("consumer.cc");
    let source = consumer.read_to_string().expect("consumer source");
    let terminal_start = source
        .find("ScopedJavaGlobalRef")
        .expect("template alias terminal");
    let line_start = source[..terminal_start]
        .rfind('\n')
        .map_or(0, |newline| newline + 1);
    let line = source[..terminal_start]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1;
    let column = source[line_start..terminal_start].chars().count() + 1;
    let forward = brokk_bifrost::searchtools::get_definitions_by_location(
        &analyzer,
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                path: "consumer.cc".to_string(),
                line: Some(line),
                column: Some(column),
            }],
        },
    );
    let forward_result = &forward.results[0];
    assert_eq!("resolved", forward_result.status, "{forward_result:#?}");
    assert!(
        forward_result.definitions.iter().any(|definition| {
            definition.fqn.as_deref() == Some("jni_zero.ScopedJavaGlobalRef")
        }),
        "template alias terminal must forward-resolve to the canonical template: {forward_result:#?}"
    );

    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let canonical_target = |fq_name: &str| {
        definition_by(&analyzer, |unit| {
            unit.kind() == CodeUnitType::Class && unit.fq_name() == fq_name && !unit.is_synthetic()
        })
    };
    let plain_target = canonical_target("jni_zero.Plain");
    let template_target = canonical_target("jni_zero.ScopedJavaGlobalRef");
    let exact_hits = |target: &CodeUnit| {
        let query = UsageFinder::new()
            .with_authoritative_scope(true)
            .query_with_provider(
                &analyzer,
                std::slice::from_ref(target),
                Some(&provider),
                1,
                1000,
            );
        assert_eq!(
            query.candidate_files,
            std::iter::once(consumer.clone()).collect(),
            "authoritative query must scan only consumer.cc"
        );
        let FuzzyResult::Success {
            hits_by_overload, ..
        } = query.result
        else {
            panic!("expected authoritative alias query success for {target:#?}");
        };
        hits_by_overload
            .get(target)
            .into_iter()
            .flatten()
            .map(|hit| {
                assert_eq!(hit.file, consumer);
                (hit.start_offset, hit.end_offset)
            })
            .collect::<BTreeSet<_>>()
    };
    let plain = "base::android::Plain";
    let plain_start = source.find(plain).expect("plain alias type");
    let template_alias = "base::android::ScopedJavaGlobalRef<int>";
    let template_start = source
        .find(template_alias)
        .expect("qualified template alias type");

    assert_eq!(
        exact_hits(&plain_target),
        BTreeSet::from([(plain_start, plain_start + plain.len())]),
        "non-template alias control must remain canonical and exclude declarator plain"
    );
    assert_eq!(
        exact_hits(&template_target),
        BTreeSet::from([(template_start, template_start + template_alias.len(),)]),
        "qualified template alias must hit the canonical template exactly and exclude java_ref"
    );
}

#[test]
fn authoritative_cpp_nested_out_of_line_owner_token_resolves_as_nested_class() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "owners.h",
            r#"#pragma once
namespace n {
struct Outer {
    void g();
    struct Inner {
        void f();
    };
};
struct Wrong {
    struct Inner { void f(); };
};
}
"#,
        )
        .file(
            "consumer.cc",
            r#"#include "owners.h"
void n::Outer::Inner::f() {} // positive-definition
void n::Wrong::Inner::f() {} // negative-wrong-owner
void n::Outer::Missing::f() { g(); } // negative-missing-terminal-owner-body
void consume(n::Outer::Inner* value) {} // positive-ordinary-type-control
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let inner_target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.fq_name() == "n.Outer$Inner"
            && slash_path(unit.source()) == "owners.h"
            && !unit.is_synthetic()
    });
    let outer_target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.fq_name() == "n.Outer"
            && slash_path(unit.source()) == "owners.h"
            && !unit.is_synthetic()
    });
    let g_target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.fq_name() == "n.Outer.g"
            && slash_path(unit.source()) == "owners.h"
    });
    let consumer = project.file("consumer.cc");
    let source = consumer.read_to_string().expect("consumer source");
    let positive = fixture_token_range(
        &source,
        "void n::Outer::Inner::f() {} // positive-definition",
        "Inner",
    );
    let line_start = source[..positive.0]
        .rfind('\n')
        .map_or(0, |newline| newline + 1);
    let line = source[..positive.0]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1;
    let column = source[line_start..positive.0].chars().count() + 1;
    let forward = brokk_bifrost::searchtools::get_definitions_by_location(
        &analyzer,
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                path: "consumer.cc".to_string(),
                line: Some(line),
                column: Some(column),
            }],
        },
    );
    assert_eq!(forward.results[0].status, "resolved", "{forward:#?}");
    assert!(
        forward.results[0]
            .definitions
            .iter()
            .any(|definition| definition.fqn.as_deref() == Some("n.Outer$Inner")),
        "the nested owner token must forward-resolve as Inner: {forward:#?}"
    );
    let outer = fixture_token_range(
        &source,
        "void n::Outer::Inner::f() {} // positive-definition",
        "Outer",
    );
    let outer_column = source[line_start..outer.0].chars().count() + 1;
    let outer_forward = brokk_bifrost::searchtools::get_definitions_by_location(
        &analyzer,
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                path: "consumer.cc".to_string(),
                line: Some(line),
                column: Some(outer_column),
            }],
        },
    );
    assert_eq!(
        outer_forward.results[0].status, "resolved",
        "{outer_forward:#?}"
    );
    assert!(
        outer_forward.results[0]
            .definitions
            .iter()
            .any(|definition| definition.fqn.as_deref() == Some("n.Outer")),
        "the outer owner token must forward-resolve as Outer: {outer_forward:#?}"
    );

    let ordinary_control = fixture_token_range(
        &source,
        "void consume(n::Outer::Inner* value) {} // positive-ordinary-type-control",
        "n::Outer::Inner",
    );
    let wrong_owner = fixture_token_range(
        &source,
        "void n::Wrong::Inner::f() {} // negative-wrong-owner",
        "Inner",
    );
    let hits =
        authoritative_exact_ranges(&analyzer, std::slice::from_ref(&inner_target), &consumer);
    let outer_hits =
        authoritative_exact_ranges(&analyzer, std::slice::from_ref(&outer_target), &consumer);
    let g_hits = authoritative_exact_ranges(&analyzer, std::slice::from_ref(&g_target), &consumer);
    let covers =
        |range: (usize, usize)| hits.iter().any(|hit| hit.0 <= range.0 && range.1 <= hit.1);
    let expected = [positive, ordinary_control];
    let no_extra_hits = hits.iter().all(|hit| {
        expected
            .iter()
            .any(|range| hit.0 <= range.0 && range.1 <= hit.1)
    });
    assert!(
        expected.iter().copied().all(covers) && no_extra_hits && !covers(wrong_owner),
        "nested owner and ordinary type must be the only span-tolerant exact hits; actual={hits:#?}, expected={expected:#?}, wrong_owner={wrong_owner:?}"
    );
    let malformed_outer = fixture_token_range(
        &source,
        "void n::Outer::Missing::f() { g(); } // negative-missing-terminal-owner-body",
        "Outer",
    );
    let ordinary_outer = fixture_token_range(
        &source,
        "void consume(n::Outer::Inner* value) {} // positive-ordinary-type-control",
        "Outer",
    );
    assert_eq!(
        outer_hits,
        BTreeSet::from([outer, malformed_outer, ordinary_outer]),
        "each structurally resolved outer owner qualifier must be emitted as an exact inverse reference"
    );
    assert!(
        g_hits.is_empty(),
        "a missing terminal owner must not attribute its function body to the last resolved prefix: {g_hits:#?}"
    );
}

#[test]
fn authoritative_cpp_method_return_receiver_chain_resolves_terminal_method() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "receiver.h",
            r#"#pragma once
namespace demo {
struct T {
    void m();
    T* get();
};
struct Other { void m(); };
struct AmbiguousFactory {
    T* get(int value = 0);
    Other* get(double value = 0);
};
void run();
}
"#,
        )
        .file(
            "consumer.cc",
            r#"#include "receiver.h"
namespace demo {
void T::m() {}
demo::T* T::get() { return this; }
void run() {
    T local;
    T* p = &local;
    p->m(); // positive-pointer
    p->get()->m(); // positive-pointer-return-chain
    Other wrong;
    wrong.m(); // negative-wrong-owner
    AmbiguousFactory factory;
    factory.get()->m(); // negative-ambiguous-return-owner
}
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.fq_name() == "demo.T.m"
            && slash_path(unit.source()) == "consumer.cc"
            && !unit.is_synthetic()
    });
    let consumer = project.file("consumer.cc");
    let source = consumer.read_to_string().expect("consumer source");
    let terminal = |line: &str, expression_through_m: &str| {
        let expression = fixture_token_range(&source, line, expression_through_m);
        (expression.1 - "m".len(), expression.1)
    };
    let expected = BTreeSet::from([
        terminal("    p->m(); // positive-pointer", "p->m"),
        terminal(
            "    p->get()->m(); // positive-pointer-return-chain",
            "p->get()->m",
        ),
    ]);
    let wrong = terminal("    wrong.m(); // negative-wrong-owner", "wrong.m");
    let hits = authoritative_exact_ranges(&analyzer, std::slice::from_ref(&target), &consumer);
    assert_eq!(
        hits, expected,
        "direct pointer control and method-return receiver chain must be the only exact hits; wrong_owner={wrong:?}"
    );
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let ambiguous = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        )
        .result;
    let FuzzyResult::Success {
        unproven_total_by_overload,
        ..
    } = ambiguous
    else {
        panic!("expected ambiguous receiver return to remain a successful conservative scan");
    };
    assert_eq!(
        unproven_total_by_overload
            .get(&target)
            .copied()
            .unwrap_or_default(),
        1,
        "the conflicting same-arity return owners must retain the terminal m as unproven"
    );
}

#[test]
fn authoritative_cpp_ambiguous_same_spelling_return_owner_fails_closed() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "receiver.h",
            r#"#pragma once
namespace left { struct Result { void m(); }; }
namespace right { struct Result { void m(); }; }
namespace api { struct Factory { Result* get(); }; }
"#,
        )
        .file(
            "consumer.cc",
            r#"#include "receiver.h"
void run(api::Factory& factory) {
    factory.get()->m();
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function && unit.fq_name() == "left.Result.m"
    });
    let consumer = project.file("consumer.cc");
    assert!(
        authoritative_exact_ranges(&analyzer, std::slice::from_ref(&target), &consumer).is_empty(),
        "an ambiguous unqualified persisted return type must not choose the first same-spelling owner"
    );
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let result = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        )
        .result;
    let FuzzyResult::Success {
        unproven_total_by_overload,
        ..
    } = result
    else {
        panic!("expected conservative same-spelling return-owner scan");
    };
    assert_eq!(
        unproven_total_by_overload
            .get(&target)
            .copied()
            .unwrap_or_default(),
        1,
        "the ambiguous same-spelling return owner must retain the terminal call as unproven"
    );
}

#[test]
fn authoritative_cpp_macro_decorated_return_metadata_fails_closed() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "receiver.h",
            r#"#pragma once
#define API_EXPORT
namespace demo {
struct T { void m(); };
struct Factory { API_EXPORT T* get(); };
}
"#,
        )
        .file(
            "consumer.cc",
            r#"#include "receiver.h"
void run(demo::Factory& factory) {
    factory.get()->m();
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function && unit.fq_name() == "demo.T.m"
    });
    let consumer = project.file("consumer.cc");
    assert!(
        authoritative_exact_ranges(&analyzer, std::slice::from_ref(&target), &consumer).is_empty(),
        "macro decoration must not resurrect an untrusted persisted return type"
    );
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let result = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        )
        .result;
    let FuzzyResult::Success {
        unproven_total_by_overload,
        ..
    } = result
    else {
        panic!("expected conservative macro-return scan");
    };
    assert_eq!(
        unproven_total_by_overload
            .get(&target)
            .copied()
            .unwrap_or_default(),
        1,
        "the terminal call must remain unproven when structured return metadata is absent"
    );
}

#[test]
fn authoritative_cpp_structured_owner_context_covers_inherited_calls_and_fields() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "consumer.cc",
            r#"namespace demo {
void inherited();
int field;
struct Base {
    void inherited();
    int field;
};
struct OtherBase {
    void inherited();
    int field;
};
struct Derived : Base {
    void inline_body() {
        inherited(); // positive-inline-inherited-call
        field = 1; // positive-inline-inherited-field
    }
    void out_of_line();
    void shadowed(void (*inherited)(), int field) {
        inherited(); // negative-parameter-shadow-call
        field = 2; // negative-parameter-shadow-field
    }
};
void Derived::out_of_line() {
    inherited(); // positive-out-of-line-inherited-call
    field = 3; // positive-out-of-line-inherited-field
}
void free_body() {
    inherited(); // negative-namespace-free-call
    field = 4; // negative-namespace-free-field
}
struct Wrong : OtherBase {
    void body() {
        inherited(); // negative-wrong-owner-call
        field = 5; // negative-wrong-owner-field
    }
};
struct Override : Base {
    void inherited();
    int field;
    void body() {
        inherited(); // negative-override-call
        field = 6; // negative-override-field
    }
};
struct Multiple : Base, OtherBase {
    void body() {
        inherited(); // negative-multiple-inheritance-call
        field = 7; // negative-multiple-inheritance-field
    }
};
struct LeftDiamond : Base {};
struct RightDiamond : Base {};
struct Diamond : LeftDiamond, RightDiamond {
    void body() {
        inherited(); // negative-nonvirtual-diamond-call
    }
};
struct DeepBranch : Base {};
struct NearBranch : OtherBase {};
struct DepthSkew : DeepBranch, NearBranch {
    void body() {
        inherited(); // negative-depth-skew-call
    }
};
struct Composite : DeepBranch, NearBranch {};
struct NestedDepthSkew : Composite {
    void body() {
        inherited(); // negative-nested-depth-skew-call
    }
};
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let method = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function && unit.fq_name() == "demo.Base.inherited"
    });
    let field = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Field && unit.fq_name() == "demo.Base.field"
    });
    let consumer = project.file("consumer.cc");
    let source = consumer.read_to_string().expect("consumer source");
    let method_expected = BTreeSet::from([
        fixture_token_range(
            &source,
            "        inherited(); // positive-inline-inherited-call",
            "inherited",
        ),
        fixture_token_range(
            &source,
            "    inherited(); // positive-out-of-line-inherited-call",
            "inherited",
        ),
    ]);
    let field_expected = BTreeSet::from([
        fixture_token_range(
            &source,
            "        field = 1; // positive-inline-inherited-field",
            "field",
        ),
        fixture_token_range(
            &source,
            "    field = 3; // positive-out-of-line-inherited-field",
            "field",
        ),
    ]);
    let method_hits =
        authoritative_exact_ranges(&analyzer, std::slice::from_ref(&method), &consumer);
    let field_hits = authoritative_exact_ranges(&analyzer, std::slice::from_ref(&field), &consumer);

    assert!(
        method_hits == method_expected && field_hits == field_expected,
        "method and field scanning must share the same structured owner context; method actual={method_hits:#?}, expected={method_expected:#?}; field actual={field_hits:#?}, expected={field_expected:#?}"
    );
}

#[test]
fn authoritative_cpp_using_enum_is_lexical_source_ordered_and_shadow_aware() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "consumer.cc",
            r#"namespace demo {
enum class Color { Red, Blue };
enum class Other { Red, Blue };
enum struct Shade { Dark };
int Red = 0; // block using-enum imports below must outrank this namespace value
int qualified = Color::Red; // positive-qualified-control
void source_order() {
    int before = Red; // negative-before-using-enum
    using enum Color;
    int after = Red; // positive-after-using-enum
}
void nested_scope() {
    {
        using enum Color;
        int inside = Blue; // positive-inside-using-enum
    }
    int outside = Blue; // negative-outside-using-enum
}
void shadowed() {
    using enum Color;
    int Red = 0;
    int value = Red; // negative-local-shadow
}
void wrong_enum() {
    using enum Other;
    int value = Red; // negative-wrong-enum
}
void ambiguous_enum() {
    using enum Color;
    using enum Other;
    int value = Red; // negative-ambiguous-enum
}
void enum_struct_control() {
    int before = Dark; // negative-enum-struct-before-import
    using enum Shade;
    int value = Dark; // positive-enum-struct-import
}
int enum_struct_outside = Dark; // negative-enum-struct-outside-import
struct ClassShadow {
    using enum Color;
    using enum Other;
    int Red;
    int read() { return Red; } // negative-class-member-shadow
};
namespace nested {
using enum demo::Color;
using enum demo::Other;
int Red = 0;
int read() { return Red; } // negative-namespace-value-shadow
}
struct CompleteClass {
    int early() { return Blue; } // positive-complete-class-late-import
    using enum Color;
    int out();
};
struct BaseShadow { int Red; };
struct DerivedImport : BaseShadow {
    using enum Color;
    int read() { return Red; } // positive-derived-import-beats-inherited-member
};
struct DirectBlockImport {
    int Red;
    int read() {
        using enum Color;
        return Red; // positive-block-import-beats-direct-member
    }
};
struct InheritedBlockImport : BaseShadow {
    int read() {
        using enum Color;
        return Red; // positive-block-import-beats-inherited-member
    }
};
namespace inherited_namespace {
using enum demo::Color;
struct Base { int Red; };
struct Derived : Base {
    int read() { return Red; } // negative-namespace-import-loses-to-inherited-member
};
}
struct {
    using enum Color;
    int read() { return Red; } // negative-unsupported-anonymous-class-import
} anonymous_holder;
int after_anonymous = Red; // negative-anonymous-class-import-must-not-leak
int CompleteClass::out() { return Red; } // positive-out-of-line-class-import
namespace reopened { using enum demo::Color; }
namespace reopened {
int value = Red; // positive-reopened-namespace-import
}
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let red = field_definition_with_owner(&analyzer, "Color", "Red");
    let blue = field_definition_with_owner(&analyzer, "Color", "Blue");
    let dark = field_definition_with_owner(&analyzer, "Shade", "Dark");
    let color = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class && unit.fq_name() == "demo.Color"
    });
    let consumer = project.file("consumer.cc");
    let source = consumer.read_to_string().expect("consumer source");
    let red_hits = authoritative_exact_ranges(&analyzer, std::slice::from_ref(&red), &consumer);
    let blue_hits = authoritative_exact_ranges(&analyzer, std::slice::from_ref(&blue), &consumer);
    let color_hits = authoritative_exact_ranges(&analyzer, std::slice::from_ref(&color), &consumer);
    let dark_hits = authoritative_exact_ranges(&analyzer, std::slice::from_ref(&dark), &consumer);
    let covers = |hits: &BTreeSet<(usize, usize)>, range: (usize, usize)| {
        hits.iter().any(|hit| hit.0 <= range.0 && range.1 <= hit.1)
    };
    let qualified = fixture_token_range(
        &source,
        "int qualified = Color::Red; // positive-qualified-control",
        "Red",
    );
    let after = fixture_token_range(
        &source,
        "    int after = Red; // positive-after-using-enum",
        "Red",
    );
    let before = fixture_token_range(
        &source,
        "    int before = Red; // negative-before-using-enum",
        "Red",
    );
    let inside = fixture_token_range(
        &source,
        "        int inside = Blue; // positive-inside-using-enum",
        "Blue",
    );
    let outside = fixture_token_range(
        &source,
        "    int outside = Blue; // negative-outside-using-enum",
        "Blue",
    );
    let shadow = fixture_token_range(
        &source,
        "    int value = Red; // negative-local-shadow",
        "Red",
    );
    let wrong = fixture_token_range(
        &source,
        "    int value = Red; // negative-wrong-enum",
        "Red",
    );
    let imported_owner = fixture_token_range(&source, "    using enum Color;", "Color");
    let ambiguous = fixture_token_range(
        &source,
        "    int value = Red; // negative-ambiguous-enum",
        "Red",
    );
    let class_shadow = fixture_token_range(
        &source,
        "    int read() { return Red; } // negative-class-member-shadow",
        "Red",
    );
    let namespace_shadow = fixture_token_range(
        &source,
        "int read() { return Red; } // negative-namespace-value-shadow",
        "Red",
    );
    let complete_class = fixture_token_range(
        &source,
        "    int early() { return Blue; } // positive-complete-class-late-import",
        "Blue",
    );
    let out_of_line_class = fixture_token_range(
        &source,
        "int CompleteClass::out() { return Red; } // positive-out-of-line-class-import",
        "Red",
    );
    let reopened_namespace = fixture_token_range(
        &source,
        "int value = Red; // positive-reopened-namespace-import",
        "Red",
    );
    let derived_import = fixture_token_range(
        &source,
        "    int read() { return Red; } // positive-derived-import-beats-inherited-member",
        "Red",
    );
    let direct_block_import = fixture_token_range(
        &source,
        "        return Red; // positive-block-import-beats-direct-member",
        "Red",
    );
    let inherited_block_import = fixture_token_range(
        &source,
        "        return Red; // positive-block-import-beats-inherited-member",
        "Red",
    );
    let enum_struct = fixture_token_range(
        &source,
        "    int value = Dark; // positive-enum-struct-import",
        "Dark",
    );
    let enum_struct_before = fixture_token_range(
        &source,
        "    int before = Dark; // negative-enum-struct-before-import",
        "Dark",
    );
    let enum_struct_outside = fixture_token_range(
        &source,
        "int enum_struct_outside = Dark; // negative-enum-struct-outside-import",
        "Dark",
    );
    let inherited_namespace_shadow = fixture_token_range(
        &source,
        "    int read() { return Red; } // negative-namespace-import-loses-to-inherited-member",
        "Red",
    );
    let anonymous_class = fixture_token_range(
        &source,
        "    int read() { return Red; } // negative-unsupported-anonymous-class-import",
        "Red",
    );
    let anonymous_leak = fixture_token_range(
        &source,
        "int after_anonymous = Red; // negative-anonymous-class-import-must-not-leak",
        "Red",
    );

    let positives_hold = covers(&red_hits, qualified)
        && covers(&red_hits, after)
        && covers(&red_hits, out_of_line_class)
        && covers(&red_hits, reopened_namespace)
        && covers(&red_hits, derived_import)
        && covers(&red_hits, direct_block_import)
        && covers(&red_hits, inherited_block_import)
        && covers(&blue_hits, inside)
        && covers(&blue_hits, complete_class)
        && covers(&dark_hits, enum_struct);
    let negatives_hold = !covers(&red_hits, before)
        && !covers(&red_hits, shadow)
        && !covers(&red_hits, wrong)
        && !covers(&red_hits, ambiguous)
        && !covers(&red_hits, class_shadow)
        && !covers(&red_hits, namespace_shadow)
        && !covers(&red_hits, inherited_namespace_shadow)
        && !covers(&red_hits, anonymous_class)
        && !covers(&red_hits, anonymous_leak)
        && !covers(&dark_hits, enum_struct_before)
        && !covers(&dark_hits, enum_struct_outside)
        && !covers(&blue_hits, outside);
    let red_expected = [
        qualified,
        after,
        out_of_line_class,
        reopened_namespace,
        derived_import,
        direct_block_import,
        inherited_block_import,
    ];
    let red_has_no_extras = red_hits.iter().all(|hit| {
        red_expected
            .iter()
            .any(|range| hit.0 <= range.0 && range.1 <= hit.1)
    });
    let blue_expected = [inside, complete_class];
    let blue_has_no_extras = blue_hits.iter().all(|hit| {
        blue_expected
            .iter()
            .any(|range| hit.0 <= range.0 && range.1 <= hit.1)
    });
    let dark_has_no_extras = dark_hits
        .iter()
        .all(|hit| hit.0 <= enum_struct.0 && enum_struct.1 <= hit.1);
    assert!(
        positives_hold
            && negatives_hold
            && red_has_no_extras
            && blue_has_no_extras
            && dark_has_no_extras,
        "using enum must be lexical, source ordered, shadow aware, and ambiguity safe; Red actual={red_hits:#?}, expected qualified={qualified:?} plus after={after:?}; Blue actual={blue_hits:#?}, expected inside={inside:?}; negative ranges before={before:?}, shadow={shadow:?}, wrong={wrong:?}, ambiguous={ambiguous:?}, class={class_shadow:?}, namespace={namespace_shadow:?}, outside={outside:?}"
    );
    assert!(
        covers(&color_hits, imported_owner),
        "the structured using-enum declaration must also retain its enum-owner type reference; actual={color_hits:#?}, expected owner token={imported_owner:?}"
    );
}

#[test]
fn authoritative_cpp_using_enum_ambiguity_is_unproven_unless_a_closer_name_shadows_it() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "enums.h",
            r#"#pragma once
namespace demo {
enum class Color { Red };
enum class Other { Red };
}
"#,
        )
        .file(
            "ambiguous.cc",
            r#"#include "enums.h"
namespace demo {
void read() {
    using enum Color;
    using enum Other;
    int value = Red;
}
}
"#,
        )
        .file(
            "shadowed.cc",
            r#"#include "enums.h"
namespace demo {
struct Holder {
    using enum Color;
    using enum Other;
    int Red;
    int read() { return Red; }
};
namespace nested {
using enum demo::Color;
using enum demo::Other;
int Red = 0;
int read() { return Red; }
}
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let target = field_definition_with_owner(&analyzer, "Color", "Red");
    let unproven_total = |file: ProjectFile| {
        let provider = ExplicitCandidateProvider::new(Arc::new(std::iter::once(file).collect()));
        let result = UsageFinder::new()
            .with_authoritative_scope(true)
            .query_with_provider(
                &analyzer,
                std::slice::from_ref(&target),
                Some(&provider),
                1,
                1000,
            )
            .result;
        let FuzzyResult::Success {
            unproven_total_by_overload,
            ..
        } = result
        else {
            panic!("expected conservative using-enum ambiguity scan");
        };
        unproven_total_by_overload
            .get(&target)
            .copied()
            .unwrap_or_default()
    };
    assert_eq!(unproven_total(project.file("ambiguous.cc")), 1);
    assert_eq!(
        unproven_total(project.file("shadowed.cc")),
        0,
        "closer class and namespace declarations must suppress lower-tier import ambiguity"
    );
}

#[test]
fn authoritative_cpp_cross_file_class_using_enum_stays_unproven_over_lower_tiers() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "types.h",
            r#"#pragma once
namespace demo {
enum class Color { Red };
enum class Other { Red };
struct Base { int Red; };
struct Derived : Base {
    using enum Color;
    int read();
};
struct MissingDerived : Base {
    using enum Color;
    int read();
};
struct ImportedBase { using enum Color; };
}
"#,
        )
        .file(
            "consumer.cc",
            r#"#include "types.h"
namespace demo {
using enum Other;
int Derived::read() { return Red; }
struct LocalDerived : ImportedBase {
    int read() { return Red; }
};
}
"#,
        )
        .file(
            "missing.cc",
            r#"#include "types.h"
namespace demo {
int MissingDerived::read() { return Red; }
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let target = field_definition_with_owner(&analyzer, "Color", "Red");
    let unproven_total = |file: ProjectFile| {
        assert!(
            authoritative_exact_ranges(&analyzer, std::slice::from_ref(&target), &file).is_empty(),
            "unseen class-tier import evidence must not be replaced by namespace or inherited lookup"
        );
        let provider = ExplicitCandidateProvider::new(Arc::new(std::iter::once(file).collect()));
        let result = UsageFinder::new()
            .with_authoritative_scope(true)
            .query_with_provider(
                &analyzer,
                std::slice::from_ref(&target),
                Some(&provider),
                1,
                1000,
            )
            .result;
        let FuzzyResult::Success {
            unproven_total_by_overload,
            ..
        } = result
        else {
            panic!("expected conservative cross-file class using-enum scan");
        };
        unproven_total_by_overload
            .get(&target)
            .copied()
            .unwrap_or_default()
    };
    assert_eq!(
        unproven_total(project.file("consumer.cc")),
        2,
        "OOL and inherited external class imports must remain unproven when class evidence is cross-file"
    );
    assert_eq!(
        unproven_total(project.file("missing.cc")),
        1,
        "Active Missing must remain unproven over an inherited same-name field"
    );
}

#[test]
fn authoritative_cpp_template_alias_ambiguity_and_cycle_fail_closed() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "canonical.h",
            r#"#pragma once
namespace canonical {
template <typename T> class Left {};
template <typename T> class Right {};
template <typename T> class Loop {};
}
"#,
        )
        .file(
            "left.h",
            r#"#pragma once
#include "canonical.h"
namespace api {
template <typename T> using Choice = canonical::Left<T>;
}
"#,
        )
        .file(
            "right.h",
            r#"#pragma once
#include "canonical.h"
namespace api {
template <typename T> using Choice = canonical::Right<T>;
}
"#,
        )
        .file(
            "cycle.h",
            r#"#pragma once
namespace cycle {
template <typename T> using Loop = Loop<T>;
}
"#,
        )
        .file(
            "consumer.cc",
            r#"#include "left.h"
#include "right.h"
#include "cycle.h"
void consume() {
    api::Choice<int> ambiguous;
    cycle::Loop<int> cyclic;
    canonical::Left<int> left_control;
    canonical::Right<int> right_control;
    canonical::Loop<int> loop_control;
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let consumer = project.file("consumer.cc");
    let source = consumer.read_to_string().expect("consumer source");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let exact_hits = |fq_name: &str| {
        let target = definition_by(&analyzer, |unit| {
            unit.kind() == CodeUnitType::Class && unit.fq_name() == fq_name && !unit.is_synthetic()
        });
        let result = UsageFinder::new()
            .with_authoritative_scope(true)
            .query_with_provider(
                &analyzer,
                std::slice::from_ref(&target),
                Some(&provider),
                1,
                1000,
            )
            .result;
        let FuzzyResult::Success {
            hits_by_overload, ..
        } = result
        else {
            panic!("expected authoritative fail-closed alias query for {target:#?}");
        };
        hits_by_overload
            .get(&target)
            .into_iter()
            .flatten()
            .map(|hit| (hit.start_offset, hit.end_offset))
            .collect::<BTreeSet<_>>()
    };
    let range = |token: &str| {
        let start = source
            .find(token)
            .unwrap_or_else(|| panic!("missing fixture token {token}"));
        (start, start + token.len())
    };

    assert_eq!(
        exact_hits("canonical.Left"),
        BTreeSet::from([range("canonical::Left<int>")]),
        "conflicting template aliases must not choose Left"
    );
    assert_eq!(
        exact_hits("canonical.Right"),
        BTreeSet::from([range("canonical::Right<int>")]),
        "conflicting template aliases must not choose Right"
    );
    assert_eq!(
        exact_hits("canonical.Loop"),
        BTreeSet::from([range("canonical::Loop<int>")]),
        "a cyclic template alias must not fan out by terminal name"
    );
}
