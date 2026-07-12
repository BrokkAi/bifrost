mod common;

use common::lsp_click::{
    ClickCase, ClickExpectation, ClickFixture, ClickOperation, assert_click_cases,
};
use common::{
    InlineTestProject,
    lsp_client::{LspServer, uri_for},
};
use serde_json::json;

#[test]
fn callable_parameters_resolve_and_hover_in_every_supported_language() {
    let fixture = ClickFixture::new("cross_language_parameter_definitions")
        .file("go.mod", "module example.com/params\n")
        .file(
            "JavaParams.java",
            "class JavaParams { int use(int <java_decl>value) { return <java_ref>value; } }\n",
        )
        .file(
            "params.go",
            "package params\nfunc goUse(<go_decl>value int) int { return <go_ref>value }\n",
        )
        .file(
            "params.cpp",
            "int cppUse(int <cpp_decl>value) { return <cpp_ref>value; }\n",
        )
        .file(
            "params.js",
            "function jsUse(<js_decl>value) { return <js_ref>value; }\n",
        )
        .file(
            "params.ts",
            "function tsUse(<ts_decl>value: number): number { return <ts_ref>value; }\n",
        )
        .file(
            "params.py",
            "def py_use(<py_decl>value: int) -> int:\n    return <py_ref>value\n",
        )
        .file(
            "params.rs",
            "fn rust_use(<rust_decl>value: i32) -> i32 { <rust_ref>value }\n",
        )
        .file(
            "params.php",
            "<?php\nfunction phpUse(int <php_target>$<php_decl>value): int { return $<php_ref>value; }\n",
        )
        .file(
            "Params.scala",
            "object Params { def use(<scala_decl>value: Int): Int = <scala_ref>value }\n",
        )
        .file(
            "Params.cs",
            "class Params { int Use(int <csharp_decl>value) { return <csharp_ref>value; } }\n",
        )
        .file(
            "params.rb",
            "def ruby_use(<ruby_decl>value)\n  <ruby_ref>value\nend\n",
        );

    let mut cases = Vec::new();
    macro_rules! add_language {
        ($language:literal, $declaration:literal, $reference:literal, $hover:literal) => {
            cases.push(ClickCase::new(
                concat!($language, " reference resolves to parameter"),
                $reference,
                ClickOperation::Definition,
                ClickExpectation::Locations(&[$declaration]),
            ));
            cases.push(ClickCase::new(
                concat!($language, " declaration resolves to itself"),
                $declaration,
                ClickOperation::Definition,
                ClickExpectation::Locations(&[$declaration]),
            ));
            cases.push(ClickCase::new(
                concat!($language, " parameter hover renders declaration"),
                $reference,
                ClickOperation::Hover,
                ClickExpectation::HoverContains($hover),
            ));
        };
    }
    add_language!("java", "java_decl", "java_ref", "int value");
    add_language!("go", "go_decl", "go_ref", "value int");
    add_language!("cpp", "cpp_decl", "cpp_ref", "int value");
    add_language!("js", "js_decl", "js_ref", "value");
    add_language!("ts", "ts_decl", "ts_ref", "value: number");
    add_language!("py", "py_decl", "py_ref", "value: int");
    add_language!("rust", "rust_decl", "rust_ref", "value: i32");
    cases.push(ClickCase::new(
        "php reference resolves to parameter",
        "php_ref",
        ClickOperation::Definition,
        ClickExpectation::Locations(&["php_target"]),
    ));
    cases.push(ClickCase::new(
        "php declaration resolves to itself",
        "php_decl",
        ClickOperation::Definition,
        ClickExpectation::Locations(&["php_target"]),
    ));
    cases.push(ClickCase::new(
        "php parameter hover renders declaration",
        "php_ref",
        ClickOperation::Hover,
        ClickExpectation::HoverContains("int $value"),
    ));
    add_language!("scala", "scala_decl", "scala_ref", "value: Int");
    add_language!("csharp", "csharp_decl", "csharp_ref", "int value");
    add_language!("ruby", "ruby_decl", "ruby_ref", "value");

    assert_click_cases(fixture, &cases);
}

#[test]
fn receiver_constructor_closure_destructuring_and_shadowing_forms_resolve_structurally() {
    let fixture = ClickFixture::new("parameter_special_forms")
        .file("go.mod", "module example.com/special\n")
        .file(
            "receivers.go",
            "package special\ntype Service struct { value int }\nfunc (<go_receiver_decl>s *Service) read() int { return <go_receiver_ref>s.value }\n",
        )
        .file(
            "receivers.rs",
            "struct Counter { value: i32 }\nimpl Counter { fn read(&<rust_receiver_decl>self) -> i32 { <rust_receiver_ref>self.value } }\nfn shadow(<rust_outer_decl>value: i32) -> i32 { { let value = 1; <rust_shadow_ref>value } }\n",
        )
        .file(
            "RecordBox.java",
            "record RecordBox(int <java_record_decl>value) { int read() { return <java_record_ref>value; } }\n",
        )
        .file(
            "Primary.cs",
            "class Primary(int <csharp_primary_decl>value) { int Read() => <csharp_primary_ref>value; }\n",
        )
        .file(
            "Primary.scala",
            "class Primary(<scala_class_decl>value: Int) { def read: Int = <scala_class_ref>value }\n",
        )
        .file(
            "promoted.php",
            "<?php\nclass Promoted { function __construct(public int <php_promoted_target>$<php_promoted_decl>value) { echo $<php_promoted_ref>value; } }\n",
        )
        .file(
            "closure.js",
            "function outer(value) { return (<js_inner_decl>value) => <js_inner_ref>value; }\nfunction destructure({ nested: { <js_destructured_decl>value } }) { return <js_destructured_ref>value; }\n",
        );

    assert_click_cases(
        fixture,
        &[
            ClickCase::new(
                "Go explicit receiver",
                "go_receiver_ref",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["go_receiver_decl"]),
            ),
            ClickCase::new(
                "Rust self receiver",
                "rust_receiver_ref",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["rust_receiver_decl"]),
            ),
            ClickCase::new(
                "Java record constructor parameter",
                "java_record_ref",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["java_record_decl"]),
            ),
            ClickCase::new(
                "C# primary constructor parameter",
                "csharp_primary_ref",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["csharp_primary_decl"]),
            ),
            ClickCase::new(
                "Scala class parameter",
                "scala_class_ref",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["scala_class_decl"]),
            ),
            ClickCase::new(
                "PHP promoted constructor parameter",
                "php_promoted_ref",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["php_promoted_target"]),
            ),
            ClickCase::new(
                "nested JavaScript closure parameter",
                "js_inner_ref",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["js_inner_decl"]),
            ),
            ClickCase::new(
                "JavaScript destructured parameter leaf",
                "js_destructured_ref",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["js_destructured_decl"]),
            ),
            ClickCase::new(
                "nearer Rust local blocks outer parameter",
                "rust_shadow_ref",
                ClickOperation::Definition,
                ClickExpectation::Empty,
            ),
        ],
    );
}

#[test]
fn open_document_overlay_drives_parameter_definition_and_hover() {
    let disk = "fn use_param(original: i32) -> i32 { original }\n";
    let overlay = "fn use_param(changed: &str) -> &str { changed }\n";
    let changed = "fn use_param(latest: bool) -> bool { latest }\n";
    let project = InlineTestProject::new().file("params.rs", disk).build();
    let file = project.file("params.rs");
    let uri = uri_for(&file.abs_path());
    let mut server = LspServer::start(project.root());

    server.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": uri,
                "languageId": "rust",
                "version": 1,
                "text": overlay
            }
        }),
    );
    let overlay_reference = overlay.rfind("changed").expect("overlay reference") as u64;
    let overlay_declaration = overlay.find("changed").expect("overlay declaration") as u64;
    let definition = server.text_document_position_response(
        "textDocument/definition",
        &uri,
        0,
        overlay_reference,
    );
    assert_eq!(
        definition["result"][0]["range"]["start"]["character"], overlay_declaration,
        "definition should use didOpen content: {definition}"
    );
    let hover = server.hover_response(&uri, 0, overlay_reference);
    let hover_value = hover["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_else(|| panic!("expected overlay hover, got {hover}"));
    assert!(hover_value.contains("changed: &str"), "{hover}");
    assert!(!hover_value.contains("original"), "{hover}");

    server.notify(
        "textDocument/didChange",
        json!({
            "textDocument": {"uri": uri, "version": 2},
            "contentChanges": [{"text": changed}]
        }),
    );
    let changed_reference = changed.rfind("latest").expect("changed reference") as u64;
    let hover = server.hover_response(&uri, 0, changed_reference);
    let hover_value = hover["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_else(|| panic!("expected changed hover, got {hover}"));
    assert!(hover_value.contains("latest: bool"), "{hover}");
    assert!(!hover_value.contains("changed: &str"), "{hover}");

    server.shutdown();
}

#[test]
fn closure_and_lambda_parameters_resolve_in_every_language_that_supports_them() {
    let fixture = ClickFixture::new("cross_language_closure_parameters")
        .file("go.mod", "module example.com/closures\n")
        .file(
            "JavaClosures.java",
            "import java.util.function.IntUnaryOperator; class JavaClosures { IntUnaryOperator f = (int <java_lambda_decl>value) -> <java_lambda_ref>value; }\n",
        )
        .file(
            "closures.go",
            "package closures\nvar goClosure = func(<go_lambda_decl>value int) int { return <go_lambda_ref>value }\n",
        )
        .file(
            "closures.cpp",
            "auto cppClosure = [](int <cpp_lambda_decl>value) { return <cpp_lambda_ref>value; };\n",
        )
        .file(
            "closures.js",
            "const jsClosure = (<js_lambda_decl>value) => <js_lambda_ref>value;\n",
        )
        .file(
            "closures.ts",
            "const tsClosure = (<ts_lambda_decl>value: number): number => <ts_lambda_ref>value;\n",
        )
        .file(
            "closures.py",
            "py_closure = lambda <py_lambda_decl>value: <py_lambda_ref>value\n",
        )
        .file(
            "closures.rs",
            "fn closures() { let rust_closure = |<rust_lambda_decl>value: i32| <rust_lambda_ref>value; }\n",
        )
        .file(
            "closures.php",
            "<?php\n$phpClosure = fn(int <php_lambda_target>$<php_lambda_decl>value): int => $<php_lambda_ref>value;\n",
        )
        .file(
            "Closures.scala",
            "object Closures { val f = (<scala_lambda_decl>value: Int) => <scala_lambda_ref>value }\n",
        )
        .file(
            "Closures.cs",
            "using System; class Closures { Func<int, int> F = (int <csharp_lambda_decl>value) => <csharp_lambda_ref>value; }\n",
        )
        .file(
            "closures.rb",
            "ruby_closure = ->(<ruby_lambda_decl>value) { <ruby_lambda_ref>value }\n",
        );

    assert_click_cases(
        fixture,
        &[
            ClickCase::new(
                "Java lambda",
                "java_lambda_ref",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["java_lambda_decl"]),
            ),
            ClickCase::new(
                "Go function literal",
                "go_lambda_ref",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["go_lambda_decl"]),
            ),
            ClickCase::new(
                "C++ lambda",
                "cpp_lambda_ref",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["cpp_lambda_decl"]),
            ),
            ClickCase::new(
                "JavaScript arrow",
                "js_lambda_ref",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["js_lambda_decl"]),
            ),
            ClickCase::new(
                "TypeScript arrow",
                "ts_lambda_ref",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["ts_lambda_decl"]),
            ),
            ClickCase::new(
                "Python lambda",
                "py_lambda_ref",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["py_lambda_decl"]),
            ),
            ClickCase::new(
                "Rust closure",
                "rust_lambda_ref",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["rust_lambda_decl"]),
            ),
            ClickCase::new(
                "PHP arrow",
                "php_lambda_ref",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["php_lambda_target"]),
            ),
            ClickCase::new(
                "Scala lambda",
                "scala_lambda_ref",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["scala_lambda_decl"]),
            ),
            ClickCase::new(
                "C# lambda",
                "csharp_lambda_ref",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["csharp_lambda_decl"]),
            ),
            ClickCase::new(
                "Ruby lambda",
                "ruby_lambda_ref",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["ruby_lambda_decl"]),
            ),
        ],
    );
}
