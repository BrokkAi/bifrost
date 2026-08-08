//! C and C++ callable activation points (issue #1813).
//!
//! A C or C++ function name becomes visible at the end of its declarator, so a
//! function body can call itself without a forward prototype. A declaration
//! under a preprocessor guard is visible to a reference that stands under the
//! same guard.

use crate::common::InlineTestProject;
use brokk_bifrost::searchtools::{
    DefinitionReferenceQuery, GetDefinitionParams, get_definitions_by_location,
};
use brokk_bifrost::usages::{ExplicitCandidateProvider, UsageFinder};
use brokk_bifrost::{CodeUnitIndex, CodeUnitType, CppAnalyzer, Language};
use std::sync::Arc;

/// Point at the first `token` of the first fixture line that contains `line`.
fn location(path: &str, source: &str, line: &str, token: &str) -> DefinitionReferenceQuery {
    let line_start = source
        .find(line)
        .unwrap_or_else(|| panic!("missing fixture line {line:?}"));
    let token_start = line_start
        + line
            .find(token)
            .unwrap_or_else(|| panic!("missing token {token:?} in fixture line {line:?}"));
    let preceding_newline = source[..token_start]
        .rfind('\n')
        .map_or(0, |newline| newline + 1);
    DefinitionReferenceQuery {
        path: path.to_string(),
        line: Some(
            source[..token_start]
                .bytes()
                .filter(|b| *b == b'\n')
                .count()
                + 1,
        ),
        column: Some(source[preceding_newline..token_start].chars().count() + 1),
    }
}

/// The status plus the `path#fqn` of every definition the location resolves to.
fn definitions_at(
    analyzer: &CppAnalyzer,
    query: DefinitionReferenceQuery,
) -> (String, Vec<String>) {
    let result = get_definitions_by_location(
        analyzer,
        GetDefinitionParams {
            references: vec![query],
        },
    )
    .results
    .into_iter()
    .next()
    .expect("one definition result per reference");
    let rendered = result
        .definitions
        .iter()
        .map(|definition| {
            format!(
                "{}#{}",
                definition.path,
                definition.fqn.as_deref().unwrap_or("<none>")
            )
        })
        .collect();
    (result.status, rendered)
}

#[test]
fn c_function_is_visible_to_its_own_body_without_a_prototype() {
    // fx13: the defect shape. fx14 and fx15 are the prototype controls that
    // masked it in prototype-heavy code.
    let recursive = r#"static int fact(int n) {
    if (n <= 1) return 1;
    return n * fact(n - 1);
}

int use(void) { return fact(5); }
"#;
    let prototyped = r#"static int fact(int n);

static int fact(int n) {
    if (n <= 1) return 1;
    return n * fact(n - 1);
}

int use(void) { return fact(5); }
"#;
    let mutual = r#"static int even(int n);
static int odd(int n);

static int even(int n) { return n == 0 ? 1 : odd(n - 1); }
static int odd(int n) { return n == 0 ? 0 : even(n - 1); }

int use(void) { return even(4); }
"#;

    for (name, source, call_line, token, expected_fqn) in [
        (
            "fx14",
            prototyped,
            "    return n * fact(n - 1);",
            "fact",
            "fact",
        ),
        (
            "fx15",
            mutual,
            "static int even(int n) { return n == 0 ? 1 : odd(n - 1); }",
            "odd(n - 1)",
            "odd",
        ),
        (
            "fx13",
            recursive,
            "    return n * fact(n - 1);",
            "fact",
            "fact",
        ),
    ] {
        let project = InlineTestProject::with_language(Language::Cpp)
            .file("a.c", source)
            .build();
        let analyzer = CppAnalyzer::from_project(project.project().clone());
        let (status, definitions) =
            definitions_at(&analyzer, location("a.c", source, call_line, token));
        assert_eq!(status, "resolved", "{name}: {definitions:?}");
        assert_eq!(
            definitions,
            vec![format!("a.c#{expected_fqn}")],
            "{name} must resolve the call to the function in the same translation unit"
        );
    }
}

#[test]
fn c_function_stays_invisible_before_its_declarator() {
    // Near miss: C activates a name at the end of its declarator, so a
    // reference that stands before the declarator sees nothing.
    let source = r#"int seed = fact(1);

static int fact(int n) {
    if (n <= 1) return 1;
    return n * fact(n - 1);
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("a.c", source)
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let (status, definitions) = definitions_at(
        &analyzer,
        location("a.c", source, "int seed = fact(1);", "fact"),
    );
    assert_eq!(
        status, "no_definition",
        "a use before the declarator must not resolve: {definitions:?}"
    );
    assert!(definitions.is_empty(), "{definitions:?}");

    let (recursive_status, recursive_definitions) = definitions_at(
        &analyzer,
        location("a.c", source, "    return n * fact(n - 1);", "fact"),
    );
    assert_eq!(
        recursive_status, "resolved",
        "the same file must still resolve the recursive call: {recursive_definitions:?}"
    );
}

#[test]
fn c_declaration_under_the_reference_guard_is_visible() {
    // fx16: declaration and reference stand under one guard, so the guard
    // cannot separate them. fx17 is the unguarded control.
    let guarded = r#"#ifdef FEATURE_X
static void guarded(int v) { (void)v; }

void caller(void) {
    guarded(1);
}
#endif
"#;
    let plain = r#"static void guarded(int v) { (void)v; }

void caller(void) {
    guarded(1);
}
"#;
    let nested = r#"#ifdef FEATURE_X
#ifdef FEATURE_Y
static void guarded(int v) { (void)v; }
#endif

void caller(void) {
#ifdef FEATURE_Y
    guarded(1);
#endif
}
#endif
"#;

    for (name, source) in [("fx17", plain), ("fx16", guarded), ("nested", nested)] {
        let project = InlineTestProject::with_language(Language::Cpp)
            .file("a.c", source)
            .build();
        let analyzer = CppAnalyzer::from_project(project.project().clone());
        let (status, definitions) = definitions_at(
            &analyzer,
            location("a.c", source, "    guarded(1);", "guarded"),
        );
        assert_eq!(status, "resolved", "{name}: {definitions:?}");
        assert_eq!(
            definitions,
            vec!["a.c#guarded".to_string()],
            "{name} must resolve a call that stands under the declaration's guard"
        );
    }
}

#[test]
fn c_declaration_under_a_disjoint_guard_stays_invisible() {
    // Near miss: the two guards never hold together, so the declaration is not
    // co-active with the reference.
    let disjoint = r#"#ifdef FEATURE_A
static void guarded(int v) { (void)v; }
#endif

#ifdef FEATURE_B
void caller(void) {
    guarded(1);
}
#endif
"#;
    let unguarded_reference = r#"#ifdef FEATURE_A
static void guarded(int v) { (void)v; }
#endif

void caller(void) {
    guarded(1);
}
"#;

    for (name, source) in [
        ("disjoint", disjoint),
        ("unguarded_reference", unguarded_reference),
    ] {
        let project = InlineTestProject::with_language(Language::Cpp)
            .file("a.c", source)
            .build();
        let analyzer = CppAnalyzer::from_project(project.project().clone());
        let (status, definitions) = definitions_at(
            &analyzer,
            location("a.c", source, "    guarded(1);", "guarded"),
        );
        assert_eq!(
            status, "no_definition",
            "{name} must not borrow a declaration from another guard: {definitions:?}"
        );
        assert!(definitions.is_empty(), "{name}: {definitions:?}");
    }
}

#[test]
fn cpp_free_and_member_recursion_resolve() {
    // The C++ analyzer shares the same resolver. A member function body sees
    // its own name through the complete class, a free function through its
    // declarator.
    let source = r#"struct Counter {
    int down(int n) { return n <= 0 ? 0 : down(n - 1); }
};

static int fact(int n) {
    if (n <= 1) return 1;
    return n * fact(n - 1);
}

int use() { return fact(5) + Counter().down(3); }
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("a.cpp", source)
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());

    let (member_status, member_definitions) = definitions_at(
        &analyzer,
        location(
            "a.cpp",
            source,
            "    int down(int n) { return n <= 0 ? 0 : down(n - 1); }",
            "down(n - 1)",
        ),
    );
    assert_eq!(member_status, "resolved", "{member_definitions:?}");
    assert_eq!(
        member_definitions,
        vec!["a.cpp#Counter.down".to_string()],
        "a member function must stay visible to its own body"
    );

    let (free_status, free_definitions) = definitions_at(
        &analyzer,
        location("a.cpp", source, "    return n * fact(n - 1);", "fact"),
    );
    assert_eq!(free_status, "resolved", "{free_definitions:?}");
    assert_eq!(
        free_definitions,
        vec!["a.cpp#fact".to_string()],
        "a free function must stay visible to its own body"
    );

    let (call_status, call_definitions) = definitions_at(
        &analyzer,
        location("a.cpp", source, "int use() { return fact(5)", "fact"),
    );
    assert_eq!(call_status, "resolved", "{call_definitions:?}");
    assert_eq!(call_definitions, vec!["a.cpp#fact".to_string()]);
}

#[test]
fn c_recursive_call_keeps_the_inverse_surface_of_the_usage_scan() {
    // The usage scan reads the same activation seam, so the recursive call now
    // resolves to the function there too. A same-file recursive call still
    // reaches no usage surface: `push_recursive_reference_hit` drops a site
    // that stands inside the target's own declaration range, which for a
    // definition-only function is its whole body. That drop is a separate seam
    // from the activation point, and this fixture pins the surface it leaves.
    let source = r#"static int fact(int n) {
    if (n <= 1) return 1;
    return n * fact(n - 1);
}

int use(void) { return fact(5); }
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("a.c", source)
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let candidate = project.file("a.c");
    let target = analyzer
        .get_all_declarations()
        .iter()
        .find(|unit| unit.kind() == CodeUnitType::Function && unit.identifier() == "fact")
        .cloned()
        .expect("the recursive function must be indexed");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(candidate.clone()).collect()));
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

    let range_of = |line: &str| {
        let line_start = source.find(line).expect("fixture line");
        let start = line_start + line.find("fact").expect("fixture token");
        (start, start + "fact".len())
    };
    let recursive_call = range_of("    return n * fact(n - 1);");
    let plain_call = range_of("int use(void) { return fact(5); }");
    let editor_hits = result.all_hits_including_imports();
    assert!(
        editor_hits
            .iter()
            .any(|hit| (hit.start_offset, hit.end_offset) == plain_call),
        "the ordinary call must be an inverse hit: {editor_hits:#?}"
    );
    assert!(
        editor_hits
            .iter()
            .all(|hit| (hit.start_offset, hit.end_offset) != recursive_call),
        "a same-file recursive call stays outside every usage surface: {editor_hits:#?}"
    );
    assert!(
        result
            .all_hits()
            .iter()
            .all(|hit| (hit.start_offset, hit.end_offset) != recursive_call),
        "a recursive call must not become an external usage edge: {:#?}",
        result.all_hits()
    );
}
