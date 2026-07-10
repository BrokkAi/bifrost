mod common;

use brokk_bifrost::{
    CSharpAnalyzer, CppAnalyzer, GoAnalyzer, IAnalyzer, JavaAnalyzer, JavascriptAnalyzer, Language,
    PhpAnalyzer, RustAnalyzer, ScalaAnalyzer, TypescriptAnalyzer,
    searchtools::{
        ScanUsagesByReferenceParams, ScanUsagesEntry, ScanUsagesResult, ScanUsagesStatus,
        SearchSymbolsParams, SymbolLookupParams, SymbolSourcesResult, get_symbol_ancestors,
        get_symbol_locations, get_symbol_sources, scan_usages_by_reference, search_symbols,
    },
};
use common::InlineTestProject;

fn single_found_usage(result: &ScanUsagesResult) -> &ScanUsagesEntry {
    assert_eq!(1, result.results.len(), "{result:#?}");
    assert_eq!(
        ScanUsagesStatus::Found,
        result.results[0].status,
        "{result:#?}"
    );
    &result.results[0]
}

#[test]
fn javascript_constructor_assigned_field_is_searchable_by_property_name() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "src/components.js",
            r#"export const DEFAULT_TITLE = "Welcome";

export class Greeter {
  constructor(title = DEFAULT_TITLE) {
    this.title = title;
  }

  greet(user) {
    return `${this.title}, ${user.name}`;
  }
}
"#,
        )
        .build();
    let analyzer = JavascriptAnalyzer::from_project(project.project().clone());

    let search = search_symbols(
        &analyzer,
        SearchSymbolsParams {
            patterns: vec!["title".to_string()],
            include_tests: true,
            limit: 20,
        },
    );

    let components = search
        .files
        .iter()
        .find(|file| file.path == "src/components.js")
        .unwrap_or_else(|| panic!("missing components.js in {search:#?}"));
    assert!(
        components
            .fields
            .iter()
            .any(|hit| hit.symbol == "Greeter.title" && hit.line == 5),
        "expected Greeter.title on constructor assignment line: {search:#?}"
    );
}

#[test]
fn javascript_object_literal_method_is_searchable_as_function_symbol() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "src/library.js",
            r#"const helpers = {
  formatTask(task) {
    return task.label;
  },
};
"#,
        )
        .build();
    let analyzer = JavascriptAnalyzer::from_project(project.project().clone());

    let search = search_symbols(
        &analyzer,
        SearchSymbolsParams {
            patterns: vec!["formatTask".to_string()],
            include_tests: true,
            limit: 20,
        },
    );

    let library = search
        .files
        .iter()
        .find(|file| file.path == "src/library.js")
        .unwrap_or_else(|| panic!("missing library.js in {search:#?}"));
    assert!(
        library
            .functions
            .iter()
            .any(|hit| hit.symbol == "library.js.helpers.formatTask" && hit.line == 2),
        "expected object-literal method in functions bucket: {search:#?}"
    );
}

#[test]
fn scan_usages_resolves_public_typescript_static_method_symbol() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/api.ts",
            r#"export class ApiClient {
  static create(baseUrl: string): ApiClient {
    return new ApiClient(baseUrl);
  }

  constructor(private readonly baseUrl: string) {}
}

export default function createClient(): ApiClient {
  return ApiClient.create("/api");
}
"#,
        )
        .file(
            "src/app.ts",
            r#"import { ApiClient } from "./api";

const direct = ApiClient.create("/direct");
"#,
        )
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());

    let search = search_symbols(
        &analyzer,
        SearchSymbolsParams {
            patterns: vec!["create".to_string()],
            include_tests: true,
            limit: 20,
        },
    );
    let api = search
        .files
        .iter()
        .find(|file| file.path == "src/api.ts")
        .unwrap_or_else(|| panic!("missing api.ts in {search:#?}"));
    assert!(
        api.functions
            .iter()
            .any(|hit| hit.symbol == "ApiClient.create" && hit.line == 2),
        "expected public static method symbol without internal suffix: {search:#?}"
    );

    let result = scan_usages_by_reference(
        &analyzer,
        ScanUsagesByReferenceParams {
            symbols: vec!["ApiClient.create".to_string()],
            include_tests: true,
            paths: None,
        },
    );

    let usage = single_found_usage(&result);
    let lines = usage
        .files
        .iter()
        .flat_map(|file| {
            file.hits
                .iter()
                .map(move |hit| (file.path.as_str(), hit.line))
        })
        .collect::<Vec<_>>();
    assert!(
        lines.contains(&("src/api.ts", 10)) && lines.contains(&("src/app.ts", 3)),
        "expected both static method call sites: {result:#?}"
    );
}

#[test]
fn scan_usages_file_anchor_prefers_exact_scala_class_over_companion_object() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "src/main/scala/example/Service.scala",
            r#"package example

class Repository
class Service(repository: Repository)

object Service {
  def build(repository: Repository): Service =
    new Service(repository)
}
"#,
        )
        .build();
    let analyzer = ScalaAnalyzer::from_project(project.project().clone());

    let result = scan_usages_by_reference(
        &analyzer,
        ScanUsagesByReferenceParams {
            symbols: vec!["src/main/scala/example/Service.scala#example.Service".to_string()],
            include_tests: true,
            paths: None,
        },
    );

    let usage = single_found_usage(&result);
    assert!(
        usage.files.iter().any(|file| {
            file.path == "src/main/scala/example/Service.scala"
                && file.hits.iter().any(|hit| {
                    hit.line == 8
                        && hit
                            .snippet
                            .as_deref()
                            .unwrap_or_default()
                            .contains("new Service(repository)")
                })
        }),
        "expected constructor usage for exact class target: {result:#?}"
    );
}

#[test]
fn java_annotated_method_search_symbol_uses_name_line() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/main/java/example/parity/ConsoleHandler.java",
            r#"package example.parity;

public class ConsoleHandler {
    @Override
    public String handle(String value) {
        return value.trim();
    }
}
"#,
        )
        .build();
    let analyzer = JavaAnalyzer::from_project(project.project().clone());

    let search = search_symbols(
        &analyzer,
        SearchSymbolsParams {
            patterns: vec!["handle".to_string()],
            include_tests: true,
            limit: 20,
        },
    );

    let file = search
        .files
        .iter()
        .find(|file| file.path == "src/main/java/example/parity/ConsoleHandler.java")
        .unwrap_or_else(|| panic!("missing ConsoleHandler.java in {search:#?}"));
    assert!(
        file.functions
            .iter()
            .any(|hit| hit.symbol == "example.parity.ConsoleHandler.handle" && hit.line == 5),
        "expected annotated method on name line, not annotation line: {search:#?}"
    );
}

#[test]
fn php_symbol_sources_accept_common_foreign_delimiters() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/SMTP.php",
            r#"<?php
namespace PHPMailer\PHPMailer;
class SMTP {
    public function authenticate() {
        return true;
    }
}
"#,
        )
        .build();
    let analyzer = PhpAnalyzer::from_project(project.project().clone());

    for symbol in [
        "SMTP::authenticate",
        r"PHPMailer\PHPMailer\SMTP::authenticate",
        "PHPMailer/PHPMailer/SMTP.authenticate",
    ] {
        let result = source_for(&analyzer, symbol);
        assert!(result.not_found.is_empty(), "{symbol}");
        assert!(result.ambiguous.is_empty(), "{symbol}");
        assert_eq!(1, result.sources.len(), "{symbol}");
        assert_eq!(
            "PHPMailer.PHPMailer.SMTP.authenticate",
            result.sources[0].label
        );
    }
}

#[test]
fn fuzzy_lookup_accepts_java_cpp_and_csharp_delimiter_spellings() {
    let java_project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/pkg/Thing.java",
            r#"package pkg;
class Thing {
    void method() {}
}
"#,
        )
        .build();
    let java = JavaAnalyzer::from_project(java_project.project().clone());
    let java_result = source_for(&java, "pkg/Thing.method");
    assert_eq!("pkg.Thing.method", java_result.sources[0].label);

    let cpp_project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "thing.cpp",
            r#"namespace ns {
class C {
public:
    void method();
};
void C::method() {}
}
"#,
        )
        .build();
    let cpp = CppAnalyzer::from_project(cpp_project.project().clone());
    let cpp_result = source_for(&cpp, "ns::C::method");
    assert_eq!("ns.C.method", cpp_result.sources[0].label);

    let csharp_project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Nested.cs",
            r#"namespace N {
class Outer {
    class Inner {
        void Method() {}
    }
}
}
"#,
        )
        .build();
    let csharp = CSharpAnalyzer::from_project(csharp_project.project().clone());
    let csharp_result = source_for(&csharp, "N.Outer+Inner.Method");
    assert_eq!("N.Outer.Inner.Method", csharp_result.sources[0].label);
}

#[test]
fn symbol_sources_prefers_exact_cpp_namespace_symbol_over_path_selector() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("fmt", "not a source file\n")
        .file(
            "src/fmt.cpp",
            r#"namespace fmt {
struct formatter {
    void write();
};
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());

    let result = get_symbol_sources(
        &analyzer,
        SymbolLookupParams {
            symbols: vec!["fmt::formatter".to_string()],
        },
    );

    assert!(result.not_found.is_empty(), "{result:#?}");
    assert!(result.ambiguous_paths.is_empty(), "{result:#?}");
    assert_eq!(1, result.sources.len(), "{result:#?}");
    assert_eq!("fmt.formatter", result.sources[0].label);
    assert_eq!("src/fmt.cpp", result.sources[0].path);
}

#[test]
fn scan_usages_normalizes_go_pointer_receiver_method_selector() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module github.com/example/app\n\ngo 1.22\n")
        .file(
            "store/options.go",
            r#"
package store

type Options struct{}
type Box[T any] struct{}

func (o *Options) IsEmpty() bool {
    return true
}

func (b *Box[T]) Empty() bool {
    return true
}

func caller(options *Options, box *Box[int]) bool {
    return options.IsEmpty() && box.Empty()
}
"#,
        )
        .build();
    let analyzer = GoAnalyzer::from_project(project.project().clone());

    for (symbol, snippet) in [
        (
            "github.com/example/app/store.(*Options).IsEmpty",
            "options.IsEmpty()",
        ),
        (
            "github.com/example/app/store.(*Box[T]).Empty",
            "box.Empty()",
        ),
    ] {
        let result = scan_usages_by_reference(
            &analyzer,
            ScanUsagesByReferenceParams {
                symbols: vec![symbol.to_string()],
                include_tests: true,
                paths: None,
            },
        );

        let usage = single_found_usage(&result);
        assert_eq!(Some(symbol), usage.symbol.as_deref());
        assert_eq!(Some(1), usage.total_hits, "{result:#?}");
        assert!(
            usage
                .files
                .iter()
                .any(|file| file.path == "store/options.go"
                    && file.hits.iter().any(|hit| {
                        hit.snippet.as_deref().unwrap_or_default().contains(snippet)
                    })),
            "{result:#?}"
        );
    }
}

#[test]
fn scan_usages_reports_path_qualified_symbol_selector_as_unsupported() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("src/cli.ts", "export function main() {}\n")
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());

    let result = scan_usages_by_reference(
        &analyzer,
        ScanUsagesByReferenceParams {
            symbols: vec!["src/cli.ts::main".to_string()],
            include_tests: true,
            paths: None,
        },
    );

    assert_eq!(1, result.results.len(), "{result:#?}");
    let entry = &result.results[0];
    assert_eq!(ScanUsagesStatus::NotFound, entry.status, "{result:#?}");
    let message = entry.message.as_deref().unwrap_or_default();
    assert!(
        message.contains("unsupported path::symbol selector"),
        "{message}"
    );
    assert!(message.contains("symbols:[\"main\"]"), "{message}");
    assert!(message.contains("paths:[\"src/cli.ts\"]"), "{message}");
}

#[test]
fn scan_usages_reports_plain_path_symbol_with_path_guidance() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("src/cli.ts", "export function main() {}\n")
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());

    let result = scan_usages_by_reference(
        &analyzer,
        ScanUsagesByReferenceParams {
            symbols: vec!["src/cli.ts".to_string()],
            include_tests: true,
            paths: None,
        },
    );

    assert_eq!(1, result.results.len(), "{result:#?}");
    let entry = &result.results[0];
    assert_eq!(ScanUsagesStatus::NotFound, entry.status, "{result:#?}");
    let message = entry.message.as_deref().unwrap_or_default();
    assert!(
        message.contains("expects workspace symbols, not file paths"),
        "{message}"
    );
    assert!(message.contains("use `paths` only to narrow"), "{message}");
    assert!(message.contains("scan_usages_by_reference"), "{message}");
    assert!(!message.contains("`targets`"), "{message}");
}

#[test]
fn scan_usages_bounds_ambiguous_path_qualified_selector_message() {
    let mut builder = InlineTestProject::with_language(Language::TypeScript);
    for index in 0..7 {
        builder = builder.file(
            format!("dir{index}/index.ts"),
            format!("export const value{index} = {index};\n"),
        );
    }
    let project = builder.build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());

    let result = scan_usages_by_reference(
        &analyzer,
        ScanUsagesByReferenceParams {
            symbols: vec!["index.ts::missing".to_string()],
            include_tests: true,
            paths: None,
        },
    );

    assert_eq!(1, result.results.len(), "{result:#?}");
    let entry = &result.results[0];
    assert_eq!(ScanUsagesStatus::NotFound, entry.status, "{result:#?}");
    let message = entry.message.as_deref().unwrap_or_default();
    assert!(
        message.contains("unsupported path::symbol selector"),
        "{message}"
    );
    assert!(
        message.contains("showing first 5 of 7"),
        "expected capped match list in {message}"
    );
    assert!(message.contains("dir0/index.ts"), "{message}");
    assert!(message.contains("dir4/index.ts"), "{message}");
    assert!(!message.contains("dir5/index.ts"), "{message}");
    assert!(!message.contains("dir6/index.ts"), "{message}");
}

#[test]
fn scala_symbol_tools_accept_nested_object_spellings_and_drop_kind_filter() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "src/ai/brokk/ScalaObjects.scala",
            r#"package ai.brokk

object ir {
  object PrimOp {
    case object AsClockOp
    case object AsAsyncResetOp
    case object AsUIntOp
  }
}

object InstanceChoiceControl {
  def select: Unit = {}
}
"#,
        )
        .build();
    let analyzer = ScalaAnalyzer::from_project(project.project().clone());

    for symbol in [
        "ai.brokk.ir.PrimOp.AsClockOp",
        "ai.brokk.ir$.PrimOp$.AsClockOp",
        "ai.brokk.ir.PrimOp.AsAsyncResetOp",
        "ai.brokk.ir$.PrimOp$.AsAsyncResetOp",
        "ai.brokk.InstanceChoiceControl.select",
        "ai.brokk.InstanceChoiceControl$.select",
    ] {
        let result = source_for(&analyzer, symbol);
        assert!(
            result.not_found.is_empty(),
            "{symbol}: {:?}",
            result.not_found
        );
        assert!(
            result.ambiguous.is_empty(),
            "{symbol}: {:?}",
            result.ambiguous
        );
        assert_eq!(1, result.sources.len(), "{symbol}: {result:#?}");
    }

    let case_object = source_for(&analyzer, "ai.brokk.ir$.PrimOp$.AsClockOp");
    assert_eq!("ai.brokk.ir.PrimOp.AsClockOp", case_object.sources[0].label);
    assert_eq!(None, case_object.sources[0].presentation.as_deref());
    assert_eq!(
        "src/ai/brokk/ScalaObjects.scala",
        case_object.sources[0].path
    );
    assert!(
        case_object.sources[0]
            .text
            .contains("case object AsClockOp"),
        "{case_object:#?}"
    );

    let object_method = source_for(&analyzer, "ai.brokk.InstanceChoiceControl$.select");
    assert_eq!(
        "ai.brokk.InstanceChoiceControl.select",
        object_method.sources[0].label
    );
    assert_eq!(None, object_method.sources[0].presentation.as_deref());

    let locations = get_symbol_locations(
        &analyzer,
        SymbolLookupParams {
            symbols: vec![
                "ai.brokk.ir$.PrimOp$.AsUIntOp".to_string(),
                "ai.brokk.InstanceChoiceControl.select".to_string(),
            ],
        },
    );
    assert!(locations.not_found.is_empty(), "{locations:#?}");
    assert_eq!(
        vec![
            "ai.brokk.ir.PrimOp.AsUIntOp".to_string(),
            "ai.brokk.InstanceChoiceControl.select".to_string()
        ],
        locations
            .locations
            .iter()
            .map(|location| location.symbol.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn indexed_suffix_lookup_preserves_scala_dollar_full_match_precedence() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "src/pkg/Foo/Bar.scala",
            r#"package pkg.Foo
class Bar
"#,
        )
        .file(
            "src/pkg/DollarAlias.scala",
            r#"package pkg
class Foo$Bar
"#,
        )
        .build();
    let analyzer = ScalaAnalyzer::from_project(project.project().clone());

    let locations = get_symbol_locations(
        &analyzer,
        SymbolLookupParams {
            symbols: vec!["Foo.Bar".to_string()],
        },
    );

    assert!(locations.not_found.is_empty(), "{locations:#?}");
    assert_eq!(1, locations.locations.len(), "{locations:#?}");
    assert_eq!("pkg.Foo$Bar", locations.locations[0].symbol);
    assert_eq!("src/pkg/DollarAlias.scala", locations.locations[0].path);
}

#[test]
fn get_symbol_sources_returns_flat_top_level_symbols_for_file_paths() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/pkg/Thing.java",
            r#"package pkg;
class Thing {
    void method() {}
    static class Inner {}
}
"#,
        )
        .build();
    let analyzer = JavaAnalyzer::from_project(project.project().clone());

    let result = source_for(&analyzer, "src/pkg/Thing.java");
    assert!(result.not_found.is_empty(), "{result:#?}");
    assert!(result.ambiguous.is_empty(), "{result:#?}");
    assert_eq!(1, result.sources.len(), "{result:#?}");

    let source = &result.sources[0];
    assert_eq!("src/pkg/Thing.java", source.label);
    assert_eq!("src/pkg/Thing.java", source.path);
    assert_eq!(1, source.start_line);
    assert_eq!(2, source.end_line);
    assert_eq!(None, source.presentation.as_deref());
    assert!(source.text.contains("# pkg"), "{source:#?}");
    assert!(source.text.contains("- Thing"), "{source:#?}");
    assert!(!source.text.contains("method"), "{source:#?}");
    assert!(!source.text.contains("Inner"), "{source:#?}");
}

#[test]
fn extended_symbol_lookup_reports_path_inputs_as_symbols() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/pkg/Thing.java",
            r#"package pkg;
class Thing {
    void method() {}
}
"#,
        )
        .build();
    let analyzer = JavaAnalyzer::from_project(project.project().clone());

    let locations = get_symbol_locations(
        &analyzer,
        SymbolLookupParams {
            symbols: vec!["src/pkg/Thing.java".to_string()],
        },
    );
    assert!(locations.locations.is_empty(), "{locations:#?}");
    assert_eq!(1, locations.not_found.len(), "{locations:#?}");
    let location_note = locations.not_found[0].note.as_deref().unwrap_or_default();
    assert!(
        location_note.contains("expects a workspace symbol, not a file path"),
        "{location_note}"
    );
    assert!(
        location_note.contains("use list_symbols"),
        "{location_note}"
    );
    assert!(
        !location_note.contains("get_symbol_sources"),
        "{location_note}"
    );

    let ancestors = get_symbol_ancestors(
        &analyzer,
        SymbolLookupParams {
            symbols: vec!["src/pkg/Thing.java".to_string()],
        },
    );
    assert!(ancestors.ancestors.is_empty(), "{ancestors:#?}");
    assert_eq!(1, ancestors.not_found.len(), "{ancestors:#?}");
    let ancestor_note = ancestors.not_found[0].note.as_deref().unwrap_or_default();
    assert!(
        ancestor_note.contains("expects a workspace symbol, not a file path"),
        "{ancestor_note}"
    );
    assert!(
        ancestor_note.contains("use list_symbols"),
        "{ancestor_note}"
    );
    assert!(
        !ancestor_note.contains("get_symbol_sources"),
        "{ancestor_note}"
    );
}

#[test]
fn get_symbol_sources_supports_mixed_file_and_symbol_inputs() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/pkg/Thing.java",
            r#"package pkg;
class Thing {
    void method() {}
}
"#,
        )
        .file(
            "src/pkg/Other.java",
            r#"package pkg;
class Other {
    void run() {}
}
"#,
        )
        .build();
    let analyzer = JavaAnalyzer::from_project(project.project().clone());

    let result = get_symbol_sources(
        &analyzer,
        SymbolLookupParams {
            symbols: vec![
                "src/pkg/Thing.java".to_string(),
                "pkg.Other.run".to_string(),
                "src/pkg/Missing.java".to_string(),
            ],
        },
    );

    assert!(result.ambiguous.is_empty(), "{result:#?}");
    assert_eq!(
        vec!["src/pkg/Missing.java".to_string()],
        result
            .not_found
            .iter()
            .map(|item| item.input.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        vec![
            "src/pkg/Thing.java".to_string(),
            "pkg.Other.run".to_string()
        ],
        result
            .sources
            .iter()
            .map(|source| source.label.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn get_symbol_sources_file_input_uses_include_fallback_when_outline_is_empty() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "src/only_includes.h",
            "#pragma once\n#include \"only/include.h\"\n#include <stdint.h>\n",
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());

    let result = get_symbol_sources(
        &analyzer,
        SymbolLookupParams {
            symbols: vec!["src/only_includes.h".to_string()],
        },
    );

    assert!(result.not_found.is_empty(), "{result:#?}");
    assert!(result.ambiguous.is_empty(), "{result:#?}");
    assert_eq!(1, result.sources.len(), "{result:#?}");
    let source = &result.sources[0];
    assert_eq!("src/only_includes.h", source.label);
    assert_eq!("src/only_includes.h", source.path);
    assert_eq!(2, source.start_line);
    assert_eq!(3, source.end_line);
    assert_eq!(None, source.presentation.as_deref());
    assert_eq!(
        "#include \"only/include.h\"\n#include <stdint.h>",
        source.text
    );
    assert_eq!(
        Some(
            "no indexed declarations found in this file; showing its top-level #include lines, not the full source"
        ),
        source.note.as_deref()
    );
}

#[test]
fn get_symbol_sources_file_input_uses_sampled_excerpt_fallback_when_no_outline_or_includes() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "src/emptyish_large.h",
            (1..=60)
                .map(|line| format!("// line {line}"))
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());

    let result = get_symbol_sources(
        &analyzer,
        SymbolLookupParams {
            symbols: vec!["src/emptyish_large.h".to_string()],
        },
    );

    assert!(result.not_found.is_empty(), "{result:#?}");
    assert!(result.ambiguous.is_empty(), "{result:#?}");
    assert_eq!(1, result.sources.len(), "{result:#?}");
    let source = &result.sources[0];
    assert_eq!("src/emptyish_large.h", source.label);
    assert_eq!("src/emptyish_large.h", source.path);
    assert_eq!(1, source.start_line);
    assert_eq!(60, source.end_line);
    assert_eq!(Some("sampled_excerpt"), source.presentation.as_deref());
    assert_eq!(
        Some(
            "no indexed declarations or top-level includes found in this file; showing a head/tail sample with the first 25 and last 25 of its 60 lines (the middle is omitted)"
        ),
        source.note.as_deref()
    );
    assert!(source.text.contains("// line 1"), "{source:#?}");
    assert!(source.text.contains("// line 25"), "{source:#?}");
    assert!(
        source.text.contains("----- OMITTED 10 LINES -----"),
        "{source:#?}"
    );
    assert!(source.text.contains("// line 36"), "{source:#?}");
    assert!(source.text.contains("// line 60"), "{source:#?}");
}

#[test]
fn cpp_macro_and_function_lookup_supports_locations_sources_and_search() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "src/detection/codec/codec.h",
            r#"#pragma once
#include "common/option.h"

#define FF_CODEC_UNKNOWN 0
#define FF_AUTO_CLOSE(name) \
    do { \
        close(name); \
    } while (0)

const char* ffDetectCodec(void);
"#,
        )
        .file(
            "src/detection/bootmgr/bootmgr_apple.c",
            r#"#include "bootmgr.h"

static const char* detectSecureBoot(void) {
    return NULL;
}

const char* ffDetectBootmgr(FFBootmgrResult* result) {
    return "iBoot";
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());

    let search = search_symbols(
        &analyzer,
        SearchSymbolsParams {
            patterns: vec!["FF_".to_string()],
            include_tests: true,
            limit: 20,
        },
    );
    assert_eq!(1, search.files.len(), "{search:#?}");
    assert_eq!(
        vec!["FF_CODEC_UNKNOWN".to_string(), "FF_AUTO_CLOSE".to_string()],
        search.files[0]
            .macros
            .iter()
            .map(|hit| hit.symbol.clone())
            .collect::<Vec<_>>()
    );

    let locations = get_symbol_locations(
        &analyzer,
        SymbolLookupParams {
            symbols: vec!["FF_CODEC_UNKNOWN".to_string()],
        },
    );
    assert!(locations.not_found.is_empty(), "{locations:#?}");
    assert_eq!(1, locations.locations.len(), "{locations:#?}");
    assert_eq!("FF_CODEC_UNKNOWN", locations.locations[0].symbol);
    assert_eq!("src/detection/codec/codec.h", locations.locations[0].path);
    assert_eq!(4, locations.locations[0].start_line);

    let macro_source = source_for(&analyzer, "FF_AUTO_CLOSE");
    assert!(macro_source.not_found.is_empty(), "{macro_source:#?}");
    assert_eq!(1, macro_source.sources.len(), "{macro_source:#?}");
    assert!(
        macro_source.sources[0]
            .text
            .contains("#define FF_AUTO_CLOSE(name) \\"),
        "{macro_source:#?}"
    );
    assert!(
        macro_source.sources[0].text.contains("close(name);"),
        "{macro_source:#?}"
    );

    let function_source = source_for(&analyzer, "ffDetectBootmgr");
    assert!(function_source.not_found.is_empty(), "{function_source:#?}");
    assert_eq!(1, function_source.sources.len(), "{function_source:#?}");
    assert_eq!("ffDetectBootmgr", function_source.sources[0].label);
    assert!(
        function_source.sources[0]
            .text
            .contains("const char* ffDetectBootmgr(FFBootmgrResult* result)"),
        "{function_source:#?}"
    );
    assert!(
        function_source.sources[0]
            .text
            .contains("return \"iBoot\";"),
        "{function_source:#?}"
    );
}

#[test]
fn rust_wrapped_macro_rules_lookup_supports_sources_search_and_file_outline() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/macros/join.rs",
            r#"
macro_rules! doc {
    ($join:item) => { $join };
}

#[cfg(doc)]
doc! {macro_rules! join {
    ($(biased;)? $($future:expr),*) => { unimplemented!() }
}}

#[cfg(not(doc))]
doc! {macro_rules! join {
    (@ { rotator_select=$rotator_select:ty; ( $($s:tt)* ) ( $($n:tt)* ) $($t:tt)* } $e:expr, $($r:tt)* ) => {
        $crate::join!(@{ rotator_select=$rotator_select; ($($s)* _) ($($n)* + 1) $($t)* ($($s)*) $e, } $($r)*)
    };

    ( $($e:expr),+ $(,)? ) => {
        $crate::join!(@{ rotator_select=$crate::macros::support::SelectNormal; () (0) } $($e,)*)
    };
}}
"#,
        )
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());

    let search = search_symbols(
        &analyzer,
        SearchSymbolsParams {
            patterns: vec!["join".to_string()],
            include_tests: true,
            limit: 20,
        },
    );
    assert_eq!(1, search.files.len(), "{search:#?}");
    assert_eq!("src/macros/join.rs", search.files[0].path);
    assert!(
        search.files[0]
            .macros
            .iter()
            .any(|hit| hit.symbol == "macros.join.join"),
        "{search:#?}"
    );

    let macro_source = source_for(&analyzer, "join");
    assert!(macro_source.not_found.is_empty(), "{macro_source:#?}");
    assert!(
        macro_source
            .sources
            .iter()
            .any(|source| source.text.contains("( $($e:expr),+ $(,)? )")),
        "{macro_source:#?}"
    );
    assert!(
        macro_source
            .sources
            .iter()
            .any(|source| source.text.contains("rotator_select=$rotator_select:ty")),
        "{macro_source:#?}"
    );

    let file_outline = source_for(&analyzer, "src/macros/join.rs");
    assert!(file_outline.not_found.is_empty(), "{file_outline:#?}");
    assert_eq!(1, file_outline.sources.len(), "{file_outline:#?}");
    assert!(
        file_outline.sources[0].text.contains("- join"),
        "{file_outline:#?}"
    );
}

#[test]
fn search_symbols_ranks_cpp_implementations_ahead_of_headers_and_noise() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "src/detection/bootmgr/bootmgr.h",
            r#"#pragma once

const char* ffDetectBootmgr(void);
"#,
        )
        .file(
            "src/detection/bootmgr/bootmgr_apple.c",
            r#"#include "bootmgr.h"

static const char* detectSecureBoot(void) {
    return NULL;
}

const char* ffDetectBootmgr(void) {
    return "iBoot";
}
"#,
        )
        .file(
            "src/common/bootmgr_utils.c",
            r#"const char* ffDetectBootmgrFallback(void) {
    return "fallback";
}
"#,
        )
        .file(
            "generated/bootmgr.generated.h",
            r#"const char* ffDetectBootmgrGenerated(void);
"#,
        )
        .file(
            "tests/bootmgr_test.cpp",
            r#"const char* ffDetectBootmgr(void) {
    return "test";
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());

    let result = search_symbols(
        &analyzer,
        SearchSymbolsParams {
            patterns: vec!["ffDetectBootmgr".to_string()],
            include_tests: false,
            limit: 10,
        },
    );

    assert!(
        result.files.len() >= 3,
        "expected implementation, header, and noise files: {result:#?}"
    );
    assert_eq!(
        "src/detection/bootmgr/bootmgr_apple.c",
        result.files[0].path
    );
    assert_eq!(
        vec!["ffDetectBootmgr".to_string()],
        result.files[0]
            .functions
            .iter()
            .map(|hit| hit.symbol.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!("src/detection/bootmgr/bootmgr.h", result.files[1].path);
    assert!(
        result
            .files
            .iter()
            .all(|file| file.path != "tests/bootmgr_test.cpp"),
        "{result:#?}"
    );
    let generated_index = result
        .files
        .iter()
        .position(|file| file.path == "generated/bootmgr.generated.h")
        .unwrap();
    let header_index = result
        .files
        .iter()
        .position(|file| file.path == "src/detection/bootmgr/bootmgr.h")
        .unwrap();
    assert!(generated_index > header_index, "{result:#?}");
}

#[test]
fn search_symbols_prefers_concrete_bootmgr_declarations_over_broad_utility_files() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "src/detection/bootmgr/bootmgr_apple.c",
            r#"const char* ffDetectBootmgr(void) {
    return "iBoot";
}

const char* detectBootmgrDevice(void) {
    return "apfs";
}
"#,
        )
        .file(
            "src/detection/bootmgr/bootmgr.h",
            r#"const char* ffDetectBootmgr(void);
"#,
        )
        .file(
            "src/common/utility.c",
            r#"const char* BootmgrSupportName(void) { return "support"; }
const char* normalizeBootmgrInput(void) { return "normalize"; }
const char* BootmgrTelemetryKey(void) { return "telemetry"; }
const char* BootmgrFormatterValue(void) { return "formatter"; }
const char* BootmgrLegacyAlias(void) { return "legacy"; }
const char* BootmgrRuntimeLabel(void) { return "runtime"; }
const char* BootmgrCacheValue(void) { return "cache"; }
const char* BootmgrExtraInfo(void) { return "extra"; }
const char* BootmgrBroadNoise(void) { return "noise"; }
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());

    let result = search_symbols(
        &analyzer,
        SearchSymbolsParams {
            patterns: vec!["Bootmgr".to_string()],
            include_tests: false,
            limit: 10,
        },
    );

    assert_eq!(
        "src/detection/bootmgr/bootmgr_apple.c",
        result.files[0].path
    );
    let utility_index = result
        .files
        .iter()
        .position(|file| file.path == "src/common/utility.c")
        .unwrap();
    let header_index = result
        .files
        .iter()
        .position(|file| file.path == "src/detection/bootmgr/bootmgr.h")
        .unwrap();
    assert!(utility_index > header_index, "{result:#?}");
}

#[test]
fn fuzzy_lookup_reports_ambiguity_instead_of_picking_a_suffix_match() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/a/C.java",
            r#"package a;
class C {
    void m() {}
}
"#,
        )
        .file(
            "src/b/C.java",
            r#"package b;
class C {
    void m() {}
}
"#,
        )
        .build();
    let analyzer = JavaAnalyzer::from_project(project.project().clone());

    let result = source_for(&analyzer, "C::m");
    assert!(result.sources.is_empty());
    assert!(result.not_found.is_empty());
    assert_eq!(1, result.ambiguous.len());
    assert_eq!("C::m", result.ambiguous[0].target);
    assert_eq!(
        vec!["a.C.m".to_string(), "b.C.m".to_string()],
        result.ambiguous[0].matches
    );
}

#[test]
fn fuzzy_lookup_preserves_cpp_operator_tokens() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "operators.cpp",
            r#"struct S {
    void operator()() const;
    S operator+(const S&) const;
};
void S::operator()() const {}
S S::operator+(const S&) const { return S{}; }
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());

    let call_operator = source_for(&analyzer, "S::operator()");
    assert_eq!("S.operator()", call_operator.sources[0].label);

    let plus_operator = source_for(&analyzer, "S::operator+");
    assert_eq!("S.operator+", plus_operator.sources[0].label);
}

#[test]
fn fuzzy_lookup_does_not_treat_arrow_or_hash_as_symbol_delimiters() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "A.java",
            r#"class A {
    void method() {}
}
"#,
        )
        .build();
    let analyzer = JavaAnalyzer::from_project(project.project().clone());

    for symbol in ["A->method", "A#method"] {
        let result = source_for(&analyzer, symbol);
        assert!(result.sources.is_empty(), "{symbol}");
        assert_eq!(
            vec![symbol.to_string()],
            result
                .not_found
                .iter()
                .map(|item| item.input.clone())
                .collect::<Vec<_>>(),
            "{symbol}"
        );
        assert!(result.ambiguous.is_empty(), "{symbol}");
    }
}

#[test]
fn scan_usages_uses_the_common_fuzzy_symbol_resolver() {
    let project = InlineTestProject::with_language(Language::Java)
        .file("A", "not Java source\n")
        .file(
            "A.java",
            r#"class A {
    void method() {}
    void caller() {
        method();
    }
}
"#,
        )
        .build();
    let analyzer = JavaAnalyzer::from_project(project.project().clone());

    let result = scan_usages_by_reference(
        &analyzer,
        ScanUsagesByReferenceParams {
            symbols: vec!["A::method".to_string()],
            include_tests: true,
            paths: None,
        },
    );

    let usage = single_found_usage(&result);
    assert_eq!(Some("A::method"), usage.symbol.as_deref());
}

#[test]
fn scan_usages_finds_c_function_callers_through_header_declaration() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("repository.h", "void initialize_the_repository(void);\n")
        .file(
            "repository.c",
            "#include \"repository.h\"\nvoid initialize_the_repository(void) {}\n",
        )
        .file(
            "common-main.c",
            "#include \"repository.h\"\nint main(void) { initialize_the_repository(); }\n",
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());

    let result = scan_usages_by_reference(
        &analyzer,
        ScanUsagesByReferenceParams {
            symbols: vec!["initialize_the_repository".to_string()],
            include_tests: true,
            paths: None,
        },
    );

    let usage = single_found_usage(&result);
    assert!(
        usage.files.iter().any(|file| file.path == "common-main.c"
            && file.hits.iter().any(|hit| {
                hit.snippet
                    .as_deref()
                    .unwrap_or_default()
                    .contains("initialize_the_repository()")
            })),
        "{result:#?}",
    );
}

fn source_for(analyzer: &dyn IAnalyzer, symbol: &str) -> SymbolSourcesResult {
    get_symbol_sources(
        analyzer,
        SymbolLookupParams {
            symbols: vec![symbol.to_string()],
        },
    )
}
