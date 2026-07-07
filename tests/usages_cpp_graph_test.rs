mod common;

use brokk_bifrost::usages::{CppUsageGraphStrategy, FuzzyResult, UsageAnalyzer, UsageFinder};
use brokk_bifrost::{CodeUnit, CodeUnitType, CppAnalyzer, IAnalyzer, Language, ProjectFile};
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
