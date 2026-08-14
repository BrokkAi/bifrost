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

// ===== Kotlin =====
//
// Unlike the ports above, Kotlin has no `brokk-shared` reference
// implementation to match byte-for-byte (issue #1243 is new coverage, not a
// port), so these assert plausible scores derived by hand-tracing the
// scorer against `KOTLIN_COGNITIVE_CONFIG` rather than a reference fixture.
// Fixtures are deliberately multi-line: the Kotlin grammar emits a
// MISSING `_automatic_semicolon` error node for a single-line function body,
// which would make `compute_cognitive_complexities` see an unparseable file.

const KOTLIN_FILE: &str = "com/example/Test.kt";

fn kotlin_score(method_body: &str, identifier: &str) -> u32 {
    let source = format!(
        "package com.example\n\n\
         class Test {{\n\
         {method_body}\n\
         }}\n"
    );
    score(&[(KOTLIN_FILE, source.as_str())], KOTLIN_FILE, identifier)
}

#[test]
fn kotlin_simple_function_is_zero() {
    let body = "    fun method(): Int {\n        \
        return 0\n    \
    }";
    assert_eq!(kotlin_score(body, "method"), 0);
}

#[test]
fn kotlin_flat_function_with_calls_does_not_flag() {
    let body = "    fun method(a: Int, b: Int): Int {\n        \
        val sum = a + b\n        \
        val doubled = sum * 2\n        \
        return doubled\n    \
    }";
    assert_eq!(kotlin_score(body, "method"), 0);
}

#[test]
fn kotlin_nested_if_picks_up_nesting() {
    let body = "    fun method(a: Int, b: Int): Int {\n        \
        if (a > 0) {\n            \
            if (b > 0) {\n                \
                return 1\n            \
            }\n        \
        }\n        \
        return 0\n    \
    }";
    // Outer if at nesting 0 (+1), inner if at nesting 1 (+2): matches the
    // same shape and score as the Java/Python nested-if ports above.
    assert_eq!(kotlin_score(body, "method"), 3);
}

#[test]
fn kotlin_when_if_loop_and_conjunction_score_plausibly() {
    let body = "    fun method(x: Int): Int {\n        \
        for (i in 0 until x) {\n            \
            if (x > 0 && i > 0 || i < 10) {\n                \
                break\n            \
            }\n        \
        }\n        \
        while (x > 0) {\n            \
            continue\n        \
        }\n        \
        return when (x) {\n            \
            1 -> x\n            \
            else -> 0\n        \
        }\n    \
    }";
    // for (+1) -> if at nesting 1 (+2) with && / || counted as two distinct
    // operator runs (+2) -> while (+1) -> when's one non-default entry (+1),
    // its `else` arm contributing nothing.
    assert_eq!(kotlin_score(body, "method"), 7);
}

#[test]
fn kotlin_labeled_break_counts_extra_but_unlabeled_is_free() {
    let labeled_body = "    fun method(x: Int): Int {\n        \
        outer@ for (i in 0 until x) {\n            \
            for (j in 0 until x) {\n                \
                if (j == 1) {\n                    \
                    break@outer\n                \
                }\n            \
            }\n        \
        }\n        \
        return 0\n    \
    }";
    // Outer for (+1) -> inner for at nesting 1 (+2) -> if at nesting 2 (+3)
    // -> labeled `break@outer` (+1).
    assert_eq!(kotlin_score(labeled_body, "method"), 7);

    let unlabeled_body = "    fun method(x: Int): Int {\n        \
        for (i in 0 until x) {\n            \
            if (i == 1) {\n                \
                break\n            \
            }\n        \
        }\n        \
        return 0\n    \
    }";
    // Outer for (+1) -> if at nesting 1 (+2) -> unlabeled `break` (+0).
    assert_eq!(kotlin_score(unlabeled_body, "method"), 3);
}

// ===== Go =====

#[test]
fn go_nested_if_and_else_if_match_reference() {
    let src = r#"package main
func method(a, b int) int {
    if a > 0 {
        if b > 0 { return 1 }
    } else if a < 0 {
        return -1
    }
    return 0
}
"#;
    assert_eq!(score(&[("main.go", src)], "main.go", "method"), 4);
}

#[test]
fn go_loops_switch_select_logical_and_function_literal_match_reference() {
    let src = r#"package main
func method(ch chan int, x int) int {
    f := func() int { if x > 0 { return 1 }; return 0 }
outer:
    for i := 0; i < x; i++ {
        if x > 0 && i > 0 || i < 10 { break outer }
    }
    switch x { case 1: return f(); default: return 0 }
    select { case <-ch: return 1; default: return 0 }
}
"#;
    assert_eq!(score(&[("main.go", src)], "main.go", "method"), 10);
}

#[test]
fn go_repeated_logical_operator_and_unlabeled_break_are_near_misses() {
    let src = r#"package main
func method(a, b, c bool) {
    for {
        if a && b && c { break }
    }
}
"#;
    assert_eq!(score(&[("main.go", src)], "main.go", "method"), 4);
}

// ===== C / C++ =====

#[test]
fn cpp_nested_if_and_else_if_match_reference() {
    let src = r#"int method(int a, int b) {
    if (a > 0) {
        if (b > 0) return 1;
    } else if (a < 0) {
        return -1;
    }
    return 0;
}
"#;
    assert_eq!(score(&[("main.cpp", src)], "main.cpp", "method"), 4);
}

#[test]
fn cpp_control_flow_logical_lambda_and_defaults_match_reference() {
    let src = r#"int method(int x) {
    auto f = [&]() { if (x > 0) return 1; return 0; };
label:
    for (int i = 0; i < x; i++) {
        if (x > 0 && i > 0 || i < 10) break label;
    }
    while (x-- > 0) continue;
    switch (x) { case 1: return f(); default: return 0; }
    try { risky(); } catch (...) { recover(); }
    return x > 0 ? 1 : 0;
}
"#;
    assert_eq!(score(&[("main.cpp", src)], "main.cpp", "method"), 11);
}

#[test]
fn c_extension_uses_cpp_config_and_near_misses_remain_free() {
    let src = r#"int method(int a, int b, int c) {
    while (a) {
        if (a && b && c) break;
    }
    switch (a) { default: return a + b * c; }
}
"#;
    assert_eq!(score(&[("main.c", src)], "main.c", "method"), 4);
}

// ===== JavaScript / JSX =====

#[test]
fn javascript_nesting_else_if_and_logical_sequences_are_scored() {
    let src = r#"function method(a, b, c) {
    if (a && b || c) {
        if (b) return 1;
    } else if (c) {
        return -1;
    }
    return 0;
}
"#;
    assert_eq!(score(&[("main.js", src)], "main.js", "method"), 6);
}

#[test]
fn javascript_language_specific_control_flow_and_defaults_are_scored() {
    let src = r#"function method(items, ready, value) {
    for (const item in items) {
        if (item && ready) continue;
    }
    do {} while (ready);
    try { risky(); } catch (error) { recover(error); }
    switch (value) { case 1: return value ?? 0; default: return ready ? 1 : 0; }
}
"#;
    assert_eq!(score(&[("main.js", src)], "main.js", "method"), 9);
}

#[test]
fn javascript_nested_named_function_body_is_not_counted() {
    let src = r#"function outer(a, b) {
    function helper() {
        if (a) { if (b) return 1; }
        return 0;
    }
    return helper();
}
"#;
    assert_eq!(score(&[("main.js", src)], "main.js", "outer"), 0);
}

#[test]
fn jsx_arrow_function_is_scored_with_shared_config() {
    let src = r#"const method = (ready) => {
    if (ready) return <span>ready</span>;
    return <span>waiting</span>;
};
"#;
    assert_eq!(score(&[("view.jsx", src)], "view.jsx", "method"), 1);
}

// ===== TypeScript / TSX =====

#[test]
fn typescript_typed_control_flow_matches_reference() {
    let src = r#"function method(a: number, b?: string): number {
    if (a > 10 && b !== undefined) {
        for (let i = 0; i < a; i++) {
            if (i % 2 === 0) return i;
        }
    }
    return b ?? "default" ? 1 : 0;
}
"#;
    assert_eq!(score(&[("main.ts", src)], "main.ts", "method"), 9);
}

#[test]
fn typescript_nested_arrow_body_is_not_counted() {
    let src = r#"function outer(values: number[]): number {
    const helper = (value: number): number => {
        if (value > 0) { if (value % 2 === 0) return value; }
        return 0;
    };
    return values.length;
}
"#;
    assert_eq!(score(&[("main.ts", src)], "main.ts", "outer"), 0);
}

#[test]
fn tsx_method_uses_typescript_config() {
    let src = r#"function method(ready: boolean) {
    if (ready) return <span>ready</span>;
    return <span>waiting</span>;
}
"#;
    assert_eq!(score(&[("view.tsx", src)], "view.tsx", "method"), 1);
}

// ===== PHP =====

#[test]
fn php_nested_if_and_else_if_match_reference() {
    let src = r#"<?php
function method($a, $b) {
    if ($a > 0) {
        if ($b > 0) return 1;
    } elseif ($a < 0) {
        return -1;
    }
    return 0;
}
"#;
    assert_eq!(score(&[("main.php", src)], "main.php", "method"), 4);
}

#[test]
fn php_control_flow_logical_anonymous_function_and_defaults_match_reference() {
    let src = r#"<?php
function method($items, $x) {
    $f = function() use ($x) { if ($x > 0) return 1; return 0; };
    foreach ($items as $item) {
        if ($x > 0 && $item || $x ?? false) break;
    }
    switch ($x) { case 1: return $f(); default: return 0; }
    try { risky(); } catch (Exception $e) { recover(); }
    return $x > 0 ? 1 : 0;
}
"#;
    assert_eq!(score(&[("main.php", src)], "main.php", "method"), 11);
}

#[test]
fn php_repeated_operator_and_unlabeled_jump_are_near_misses() {
    let src = r#"<?php
function method($a, $b, $c) {
    while ($a) {
        if ($a && $b && $c) break;
    }
}
"#;
    assert_eq!(score(&[("main.php", src)], "main.php", "method"), 4);
}

// ===== Scala =====

#[test]
fn scala_nested_if_and_else_if_match_reference() {
    let src = r#"def method(a: Int, b: Int): Int = {
  if (a > 0) {
    if (b > 0) return 1
  } else if (a < 0) {
    return -1
  }
  0
}
"#;
    assert_eq!(score(&[("Main.scala", src)], "Main.scala", "method"), 4);
}

#[test]
fn scala_loops_match_logical_lambda_and_wildcard_match_reference() {
    let src = r#"def method(xs: List[Int], x: Int): Int = {
  val f = (y: Int) => { if (y > 0) 1 else 0 }
  for (item <- xs) {
    if (x > 0 && item > 0 || item < 10) return f(item)
  }
  try risky() catch { case _: Exception => recover() }
  x match { case 1 => f(x); case _ => 0 }
}
"#;
    assert_eq!(score(&[("Main.scala", src)], "Main.scala", "method"), 9);
}

#[test]
fn scala_repeated_logical_operator_and_wildcard_are_near_misses() {
    let src = r#"def method(a: Boolean, b: Boolean, c: Boolean, x: Int): Int = {
  if (a && b && c) {
    x match { case _ => 0 }
  } else 0
}
"#;
    assert_eq!(score(&[("Main.scala", src)], "Main.scala", "method"), 2);
}

// ===== C# =====

#[test]
fn csharp_nested_if_and_else_if_are_scored() {
    let src = r#"class Service {
    int method(int a, int b) {
        if (a > 0) {
            if (b > 0) return 1;
        } else if (a < 0) {
            return -1;
        }
        return 0;
    }
}
"#;
    assert_eq!(score(&[("Service.cs", src)], "Service.cs", "method"), 4);
}

#[test]
fn csharp_unbraced_nested_if_is_not_flattened_as_else_if() {
    let src = r#"class Service {
    int method(bool a, bool b) {
        if (a)
            if (b) return 1;
        return 0;
    }
}
"#;
    assert_eq!(score(&[("Service.cs", src)], "Service.cs", "method"), 3);
}

#[test]
fn csharp_nested_loop_and_logical_operator_sequences_are_scored() {
    let src = r#"class Service {
    void method(bool a, bool b, bool c, int x) {
        for (var i = 0; i < x; i++) {
            if (a && b || c) continue;
        }
    }
}
"#;
    assert_eq!(score(&[("Service.cs", src)], "Service.cs", "method"), 5);
}

#[test]
fn csharp_loops_and_catch_are_scored() {
    let src = r#"class Service {
    int method(bool ready, int x) {
        for (var i = 0; i < x; i++) {}
        while (ready) break;
        do { x--; } while (ready);
        try { risky(); } catch (System.Exception) { recover(); }
        return x;
    }
    void risky() {}
    void recover() {}
}
"#;
    assert_eq!(score(&[("Service.cs", src)], "Service.cs", "method"), 4);
}

#[test]
fn csharp_switch_statement_counts_case_but_not_default() {
    let src = r#"class Service {
    int method(int x) {
        switch (x) { case 1: x++; break; default: x--; break; }
        return x;
    }
}
"#;
    assert_eq!(score(&[("Service.cs", src)], "Service.cs", "method"), 1);
}

#[test]
fn csharp_conditional_expression_is_scored() {
    let src = r#"class Service {
    int method(bool ready) {
        return ready ? 1 : 0;
    }
}
"#;
    assert_eq!(score(&[("Service.cs", src)], "Service.cs", "method"), 1);
}

#[test]
fn csharp_defaults_repeated_operator_and_unlabeled_jumps_are_near_misses() {
    let src = r#"class Service {
    int method(bool a, bool b, bool c, int x) {
        while (a) {
            if (a && b && c) break;
            continue;
        }
        switch (x) { default: return x + 1; }
    }
}
"#;
    assert_eq!(score(&[("Service.cs", src)], "Service.cs", "method"), 4);
}

#[test]
fn csharp_switch_expression_discard_arm_is_a_default_near_miss() {
    let src = r#"class Service {
    int method(int x) {
        return x switch { 1 => 1, _ => 0 };
    }
}
"#;
    assert_eq!(score(&[("Service.cs", src)], "Service.cs", "method"), 1);
}

#[test]
fn csharp_discard_in_case_body_or_arm_value_is_not_a_default() {
    let src = r#"class Service {
    int capture(out int value) { value = 0; return value; }

    int method(int x) {
        switch (x) { case 1: capture(out _); break; default: break; }
        return x switch { 1 => capture(out _), _ => 0 };
    }
}
"#;
    assert_eq!(score(&[("Service.cs", src)], "Service.cs", "method"), 2);
}

#[test]
fn csharp_guarded_discard_cases_are_not_defaults() {
    let src = r#"class Service {
    int method(int x) {
        switch (x) { case _ when x > 0: x++; break; default: break; }
        return x switch { _ when x < 0 => -1, _ => 0 };
    }
}
"#;
    assert_eq!(score(&[("Service.cs", src)], "Service.cs", "method"), 2);
}

#[test]
fn csharp_switch_section_counts_each_non_default_label() {
    let src = r#"class Service {
    int method(int x) {
        switch (x) {
            case 1:
            case 2: x++; break;
            case 3:
            default: break;
        }
        return x;
    }
}
"#;
    assert_eq!(score(&[("Service.cs", src)], "Service.cs", "method"), 3);
}

#[test]
fn csharp_wrapped_irrefutable_patterns_are_defaults_but_tuple_discard_is_not() {
    let src = r#"class Service {
    int method((int, int) value) {
        return value switch { (_) => 0, var _ => 1, (1, _) => 2 };
    }
}
"#;
    assert_eq!(score(&[("Service.cs", src)], "Service.cs", "method"), 1);
}

#[test]
fn csharp_goto_label_is_scored_but_break_and_continue_are_not() {
    let src = r#"class Service {
    int method(bool ready) {
        while (ready) {
            if (ready) goto done;
            break;
        }
    done:
        return 0;
    }
}
"#;
    assert_eq!(score(&[("Service.cs", src)], "Service.cs", "method"), 4);
}

#[test]
fn csharp_all_goto_forms_are_scored() {
    let src = r#"class Service {
    int method(int x) {
        switch (x) {
            case 0: goto case 1;
            case 1: goto default;
            default: goto done;
        }
    done:
        return 0;
    }
}
"#;
    assert_eq!(score(&[("Service.cs", src)], "Service.cs", "method"), 5);
}

#[test]
fn csharp_lambda_adds_nesting_inside_enclosing_method() {
    let src = r#"using System;
class Service {
    int method(bool ready) {
        Func<int> nested = () => { if (ready) return 1; return 0; };
        return nested();
    }
}
"#;
    assert_eq!(score(&[("Service.cs", src)], "Service.cs", "method"), 2);
}

#[test]
fn csharp_nested_local_function_body_is_not_counted() {
    let src = r#"class Service {
    int outer(bool a, bool b) {
        int helper() {
            if (a) { if (b) return 1; }
            return 0;
        }
        return helper();
    }
}
"#;
    assert_eq!(score(&[("Service.cs", src)], "Service.cs", "outer"), 0);
}
