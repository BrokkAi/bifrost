//! End-to-end cognitive-complexity tests per language.
//!
//! Each test materializes a temporary workspace, builds the language
//! analyzer, and asserts the scorer's output for a named function. Fixtures
//! and expected scores are ported verbatim from
//! `brokk-shared/src/test/java/ai/brokk/analyzer/complexity/*CognitiveComplexityTest.java`,
//! so divergences here mean the bifrost port has drifted from brokk-shared
//! and the MCP outputs will no longer match byte-for-byte.

use crate::test_support::AnalyzerFixture;

fn score(files: &[(&str, &str)], file_rel: &str, fn_identifier: &str) -> u32 {
    let fix = AnalyzerFixture::new(files);
    let analyzer = fix.analyzer.analyzer();
    let project = analyzer.project();
    let file = project
        .file_by_rel_path(std::path::Path::new(file_rel))
        .expect("file in project");
    let complexities = analyzer.compute_cognitive_complexities(&file);
    complexities
        .into_iter()
        .find(|(cu, _)| cu.identifier() == fn_identifier)
        .map(|(_, c)| c)
        .unwrap_or_else(|| panic!("function `{fn_identifier}` not scored in {file_rel}"))
}

// ===== Rust =====

#[test]
fn rust_simple_function_is_zero() {
    assert_eq!(
        score(
            &[("src/lib.rs", "fn method() -> i32 { 0 }\n")],
            "src/lib.rs",
            "method",
        ),
        0
    );
}

#[test]
fn rust_if_nested_if_and_else_if() {
    let src = "fn method(a: i32, b: i32) -> i32 {\n\
        if a > 0 {\n\
            if b > 0 { return 1; }\n\
        } else if a < 0 {\n\
            return -1;\n\
        }\n\
        0\n\
    }\n";
    assert_eq!(score(&[("src/lib.rs", src)], "src/lib.rs", "method"), 4);
}

#[test]
fn rust_loops_match_logical_and_closure() {
    let src = "fn method(x: i32) -> i32 {\n\
        let f = || { if x > 0 { 1 } else { 0 } };\n\
        'outer: for i in 0..x {\n\
            if x > 0 && i > 0 || i < 10 { break 'outer; }\n\
        }\n\
        while x > 0 { continue; }\n\
        match x { 1 => f(), _ => 0 }\n\
    }\n";
    assert_eq!(score(&[("src/lib.rs", src)], "src/lib.rs", "method"), 10);
}

#[test]
fn rust_impl_method_only_counts_inner_control_flow() {
    let src = "struct S;\nimpl S {\n    \
        fn method(&self, x: i32) -> i32 {\n        \
            if x > 0 { return 1; }\n        \
            0\n    \
        }\n\
    }\n";
    assert_eq!(score(&[("src/lib.rs", src)], "src/lib.rs", "method"), 1);
}

// ===== Java =====

const JAVA_FILE: &str = "com/example/Test.java";

fn java_score(method_body: &str, identifier: &str) -> u32 {
    let source = format!(
        "package com.example;\n\
         public class Test {{\n\
         {method_body}\n\
         }}\n"
    );
    score(&[(JAVA_FILE, source.as_str())], JAVA_FILE, identifier)
}

#[test]
fn java_simple_method_is_zero() {
    assert_eq!(java_score("    public void method() {}", "method"), 0);
}

#[test]
fn java_if_increment_is_one() {
    let body = "    public void method(boolean a) {\n        \
        if (a) System.out.println(\"a\");\n    }";
    assert_eq!(java_score(body, "method"), 1);
}

#[test]
fn java_nested_if_picks_up_nesting() {
    let body = "    public void method(boolean a, boolean b) {\n        \
        if (a) {\n            \
            if (b) {\n                \
                System.out.println(\"b\");\n            \
            }\n        \
        }\n    }";
    assert_eq!(java_score(body, "method"), 3);
}

#[test]
fn java_else_if_flattens() {
    let body = "    public void method(int x) {\n        \
        if (x > 0) {}\n        \
        else if (x < 0) {}\n    }";
    assert_eq!(java_score(body, "method"), 2);
}

#[test]
fn java_switch_cases_default_does_not_count() {
    let body = "    public void method(int x) {\n        \
        switch (x) {\n            \
            case 1: break;\n            \
            case 2: break;\n            \
            default: break;\n        \
        }\n    }";
    assert_eq!(java_score(body, "method"), 2);
}

#[test]
fn java_try_catch_increment() {
    let body = "    public void method() {\n        \
        try {\n        \
        } catch (Exception e) {\n        \
        }\n    }";
    assert_eq!(java_score(body, "method"), 1);
}

#[test]
fn java_ternary_increment() {
    let body = "    public int method(boolean a) {\n        \
        return a ? 1 : 0;\n    }";
    assert_eq!(java_score(body, "method"), 1);
}

#[test]
fn java_boolean_operator_sequences_count_distinct_runs() {
    let body = "    public void method(boolean a, boolean b, boolean c) {\n        \
        if (a && b || c) {}\n    }";
    assert_eq!(java_score(body, "method"), 3);
}

#[test]
fn java_labeled_break_and_continue_count_extra() {
    let body = "    public void method(boolean a) {\n        \
        outer:\n        \
        while (a) {\n            \
            for (int i = 0; i < 10; i++) {\n                \
                if (i == 1) {\n                    \
                    break outer;\n                \
                }\n                \
                continue outer;\n            \
            }\n        \
        }\n    }";
    assert_eq!(java_score(body, "method"), 8);
}

#[test]
fn java_unlabeled_break_and_continue_are_free() {
    let body = "    public void method(boolean a) {\n        \
        while (a) {\n            \
            break;\n        \
        }\n        \
        for (int i = 0; i < 10; i++) {\n            \
            continue;\n        \
        }\n    }";
    assert_eq!(java_score(body, "method"), 2);
}

#[test]
fn java_lambda_body_counts_inside_enclosing_method() {
    let body = "    public void method(boolean a) {\n        \
        Runnable r = () -> {\n            \
            if (a) {\n            \
            }\n        \
        };\n    }";
    assert_eq!(java_score(body, "method"), 2);
}

// ===== Python =====

const PYTHON_FILE: &str = "complexity_test.py";

fn python_score(src: &str, identifier: &str) -> u32 {
    score(&[(PYTHON_FILE, src)], PYTHON_FILE, identifier)
}

#[test]
fn python_simple_function_is_zero() {
    assert_eq!(python_score("def method():\n    pass\n", "method"), 0);
}

#[test]
fn python_if_increment() {
    assert_eq!(
        python_score("def method(a):\n    if a:\n        print(a)\n", "method"),
        1
    );
}

#[test]
fn python_nested_if_picks_up_nesting() {
    let src = "def method(a, b):\n    \
        if a:\n        \
            if b:\n            \
                print(b)\n";
    assert_eq!(python_score(src, "method"), 3);
}

#[test]
fn python_elif_does_not_add_nesting() {
    let src = "def method(x):\n    \
        if x > 0:\n        \
            return 1\n    \
        elif x < 0:\n        \
            return -1\n    \
        else:\n        \
            return 0\n";
    assert_eq!(python_score(src, "method"), 2);
}

#[test]
fn python_loops_increment() {
    let src = "def method(items, ready):\n    \
        for item in items:\n        \
            print(item)\n    \
        while ready:\n        \
            break\n";
    assert_eq!(python_score(src, "method"), 2);
}

#[test]
fn python_try_except() {
    let src = "def method():\n    \
        try:\n        \
            do_something()\n    \
        except ValueError:\n        \
            handle_value()\n    \
        except Exception:\n        \
            handle_exception()\n";
    assert_eq!(python_score(src, "method"), 2);
}

#[test]
fn python_boolean_operator_sequences_count_distinct_runs() {
    let src = "def method(a, b, c):\n    \
        if a and b or c:\n        \
            pass\n";
    assert_eq!(python_score(src, "method"), 3);
}

#[test]
fn python_conditional_expression() {
    let src = "def method(x):\n    \
        return \"high\" if x > 10 else \"low\"\n";
    assert_eq!(python_score(src, "method"), 1);
}

#[test]
fn python_match_case_underscore_does_not_count() {
    let src = "def method(status):\n    \
        match status:\n        \
            case 200:\n            \
                return \"OK\"\n        \
            case 404:\n            \
                return \"Not Found\"\n        \
            case _:\n            \
                return \"Error\"\n";
    assert_eq!(python_score(src, "method"), 3);
}

#[test]
fn python_lambda_body_counts_inside_enclosing_function() {
    let src = "def method(a):\n    \
        f = lambda value: 1 if a else 0\n    \
        return f(1)\n";
    assert_eq!(python_score(src, "method"), 2);
}

#[test]
fn python_nested_function_body_is_not_counted() {
    let src = "def outer(a, b):\n    \
        def helper():\n        \
            if a:\n            \
                if b:\n                \
                    return 1\n        \
            return 0\n    \
        return helper()\n";
    assert_eq!(python_score(src, "outer"), 0);
}
