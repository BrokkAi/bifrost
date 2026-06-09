mod common;

use brokk_bifrost::{
    CSharpAnalyzer, CppAnalyzer, IAnalyzer, JavaAnalyzer, Language, PhpAnalyzer, ScalaAnalyzer,
    searchtools::{
        ScanUsagesParams, SymbolLookupParams, SymbolSourcesResult, get_symbol_locations,
        get_symbol_sources, scan_usages,
    },
};
use common::InlineTestProject;

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
        assert_eq!(Vec::<String>::new(), result.not_found, "{symbol}");
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
    assert_eq!("N.Outer$Inner.Method", csharp_result.sources[0].label);
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
        assert_eq!(vec![symbol.to_string()], result.not_found, "{symbol}");
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
            symbols: vec!["A::method".to_string()],
            include_tests: true,
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
            symbols: vec!["initialize_the_repository".to_string()],
            include_tests: true,
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
                && file
                    .hits
                    .iter()
                    .any(|hit| hit.snippet.contains("initialize_the_repository()"))),
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
