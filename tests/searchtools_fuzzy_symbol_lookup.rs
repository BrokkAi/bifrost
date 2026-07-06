mod common;

use brokk_bifrost::{
    CSharpAnalyzer, CppAnalyzer, IAnalyzer, JavaAnalyzer, JavascriptAnalyzer, Language,
    PhpAnalyzer, RustAnalyzer, ScalaAnalyzer, TypescriptAnalyzer,
    searchtools::{
        ScanUsagesParams, SearchSymbolsParams, SymbolLookupParams, SymbolSourcesResult,
        get_symbol_locations, get_symbol_sources, scan_usages, search_symbols,
    },
};
use common::InlineTestProject;

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

    let result = scan_usages(
        &analyzer,
        ScanUsagesParams {
            symbols: Some(vec!["ApiClient.create".to_string()]),
            targets: Vec::new(),
            include_tests: true,
            paths: None,
        },
    );

    assert!(result.not_found.is_empty(), "{result:#?}");
    assert!(result.ambiguous.is_empty(), "{result:#?}");
    assert!(result.failures.is_empty(), "{result:#?}");
    assert_eq!(1, result.usages.len(), "{result:#?}");
    let lines = result.usages[0]
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
    assert_eq!(
        Some("file_listing"),
        case_object.sources[0].presentation.as_deref()
    );
    assert_eq!(
        "src/ai/brokk/ScalaObjects.scala",
        case_object.sources[0].path
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

    let result = scan_usages(
        &analyzer,
        ScanUsagesParams {
            symbols: Some(vec!["A::method".to_string()]),
            targets: Vec::new(),
            include_tests: true,
            paths: None,
        },
    );

    assert!(result.not_found.is_empty());
    assert!(result.ambiguous.is_empty());
    assert_eq!(1, result.usages.len());
    assert_eq!("A::method", result.usages[0].symbol);
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

    let result = scan_usages(
        &analyzer,
        ScanUsagesParams {
            symbols: Some(vec!["initialize_the_repository".to_string()]),
            targets: Vec::new(),
            include_tests: true,
            paths: None,
        },
    );

    assert!(result.not_found.is_empty(), "{result:#?}");
    assert!(result.ambiguous.is_empty(), "{result:#?}");
    assert_eq!(1, result.usages.len(), "{result:#?}");
    assert!(
        result.usages[0]
            .files
            .iter()
            .any(|file| file.path == "common-main.c"
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
