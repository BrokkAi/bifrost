//! Conformance fixtures for the lexical-resolution surface (#1474, M6),
//! query side.
//!
//! Every scenario below is a *pair*: two sources that differ in exactly one
//! structural fact, run through one query, with opposite answers. The spelling
//! is always the control variable -- it never moves between the halves -- so a
//! verdict that changes can only be about where a name is bound, which tier
//! selected it, or which boundary the resolver reached.
//!
//! The families are the ones the issue mandates: sibling imports versus true
//! targets, before/after-use declarations, local and global namesakes,
//! type/value namespace collisions, several namespaces in one file, unindexed
//! declared dependencies, wildcard ambiguity, and the authoritative-boundary
//! anti-fallback contract.
//!
//! `policy_resolution_conformance.rs` in `suite_bench_policy` runs the same
//! shapes through the assertion surface. Two rules hold in both files: every
//! test reads the run's completion before reading its rows, because an
//! incomplete run returns an empty answer that is not a negative one; and no
//! assertion here reads a source spelling to decide a structural question.

use crate::common::InlineTestProject;
use brokk_bifrost::analyzer::structural::{
    CodeQuery, CodeQueryCompletion, CodeQueryResult, execute_workspace,
};
use brokk_bifrost::{AnalyzerConfig, WorkspaceAnalyzer};
use serde_json::{Value, json};

/// Execute `query` over an inline project and require a complete run.
///
/// Completion is checked here rather than in each test because every
/// conformance claim below is a claim about rows, and rows from an incomplete
/// run prove nothing either way.
fn complete(files: &[(&str, &str)], query: Value) -> Value {
    let mut project = InlineTestProject::new();
    for (path, source) in files {
        project = project.file(*path, *source);
    }
    let project = project.build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&query).expect("query should parse");
    let result: CodeQueryResult = execute_workspace(&workspace, &query);
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "a conformance verdict must be read from a complete run: {:?}",
        result.diagnostics
    );
    serde_json::to_value(&result).expect("query result should serialize")
}

fn rows(value: &Value) -> &Vec<Value> {
    value["results"].as_array().expect("results array")
}

fn field(value: &Value, name: &str) -> Vec<String> {
    rows(value)
        .iter()
        .filter_map(|row| row[name].as_str().map(str::to_string))
        .collect()
}

// ---------------------------------------------------------------------------
// Scenario 1 -- sibling imports versus the true target (Java).
// ---------------------------------------------------------------------------

/// The target both halves resolve to. It never moves, so the tier is the only
/// thing the two halves can disagree about.
const API_WIDGET: &str =
    "package api;\n\npublic class Widget {\n    public int size() { return 1; }\n}\n";

const HOST_EXPLICIT_IMPORT: &str = "package app;\n\nimport api.Widget;\n\nclass Host {\n    int run() {\n        Widget widget = new Widget();\n        return widget.size();\n    }\n}\n";

const HOST_WILDCARD_IMPORT: &str = "package app;\n\nimport api.*;\n\nclass Host {\n    int run() {\n        Widget widget = new Widget();\n        return widget.size();\n    }\n}\n";

/// Two files that resolve `Widget` to the same declaration by two different
/// routes. The mined regressions in this family picked a sibling import over
/// the true target and could not be caught because the *route* was invisible;
/// here the route is the row.
#[test]
fn an_explicit_import_and_a_wildcard_import_reach_one_target_at_different_tiers() {
    let query = json!({
        "languages": ["java"],
        "occurrences": { "role": ["type_operand"] },
        "steps": [{ "op": "candidates_of", "outcome": ["selected"] }]
    });

    let explicit = complete(
        &[
            ("api/Widget.java", API_WIDGET),
            ("app/Host.java", HOST_EXPLICIT_IMPORT),
        ],
        query.clone(),
    );
    assert!(
        !rows(&explicit).is_empty(),
        "the explicit half resolves: {explicit:#}"
    );
    for row in rows(&explicit) {
        assert_eq!(
            row["tier"],
            json!("explicit_import"),
            "an explicitly imported type is selected at the import tier: {row:#}"
        );
        assert_eq!(row["candidate"]["unit"]["fq_name"], json!("api.Widget"));
    }

    let wildcard = complete(
        &[
            ("api/Widget.java", API_WIDGET),
            ("app/Host.java", HOST_WILDCARD_IMPORT),
        ],
        query,
    );
    assert!(!rows(&wildcard).is_empty());
    for row in rows(&wildcard) {
        assert_eq!(
            row["tier"],
            json!("wildcard_import"),
            "the same target reached on demand is a weaker route: {row:#}"
        );
        assert_eq!(
            row["candidate"]["unit"]["fq_name"],
            json!("api.Widget"),
            "the target is the control variable; only the route moves: {row:#}"
        );
    }
}

// ---------------------------------------------------------------------------
// Scenario 2 -- before/after-use declarations (Java).
// ---------------------------------------------------------------------------

const READ_AFTER_DECLARATION: &str = "class Order {\n    int run() {\n        int seed = 1;\n        int copy = seed;\n        return copy;\n    }\n}\n";

const READ_BEFORE_DECLARATION: &str = "class Order {\n    int run() {\n        int copy = seed;\n        int seed = 1;\n        return copy;\n    }\n}\n";

/// The two halves are the same four tokens in a different order. A Java local
/// is in effect only after its declarator, so the read below the declaration
/// has a reaching binding and the read above it has none -- and "none" is a
/// complete answer, not a gap.
#[test]
fn a_local_read_reaches_its_binder_only_after_the_declaration() {
    let query = json!({
        "languages": ["java"],
        // Seeds name the roles they need. A `class` seed would pull in every
        // reference role, including ones Java's adapter declares unsupported,
        // and an unrelated gap would then decide this verdict.
        "occurrences": { "role": ["value_reference"] },
        "steps": [{ "op": "reaching_binding" }]
    });

    let after = complete(&[("app/Order.java", READ_AFTER_DECLARATION)], query.clone());
    assert!(
        field(&after, "name").contains(&"seed".to_string()),
        "the read below the declarator reaches it: {after:#}"
    );

    // `copy` is read in both halves and reaches its binder in both, which is
    // what makes the disappearance of `seed` a statement about position rather
    // than about the query returning nothing.
    let before = complete(&[("app/Order.java", READ_BEFORE_DECLARATION)], query);
    let reached = field(&before, "name");
    assert!(
        reached.contains(&"copy".to_string()),
        "the near-miss half still reaches bindings: {before:#}"
    );
    assert!(
        !reached.contains(&"seed".to_string()),
        "a Java local is not in effect above its declarator: {before:#}"
    );
}

// ---------------------------------------------------------------------------
// Scenario 3 -- local versus outer namesakes (Rust).
// ---------------------------------------------------------------------------

const RUST_OUTER_NAMESAKE: &str =
    "fn render() -> usize {\n    let value = 1;\n    {\n        return value;\n    }\n}\n";

const RUST_INNER_NAMESAKE: &str = "fn render() -> usize {\n    let value = 1;\n    {\n        let value = 2;\n        return value;\n    }\n}\n";

/// One `let` moves into the inner block and nothing else changes. The read is
/// spelled identically in both halves, so the declaring scope of its reaching
/// binding is the only thing that can differ -- which is exactly the predicate
/// the loop-invariance rule is built on.
#[test]
fn a_namesake_in_a_nested_block_moves_the_reaching_binding_into_that_block() {
    let query = json!({
        "languages": ["rust"],
        "occurrences": { "role": ["value_reference"] },
        "steps": [{ "op": "reaching_binding" }, { "op": "scope_of" }]
    });

    let outer = complete(&[("src/render.rs", RUST_OUTER_NAMESAKE)], query.clone());
    let inner = complete(&[("src/render.rs", RUST_INNER_NAMESAKE)], query);

    let outer_scope = rows(&outer)
        .iter()
        .map(|row| row["index"].as_u64().expect("scope index"))
        .max()
        .expect("the read reaches a binding");
    let inner_scope = rows(&inner)
        .iter()
        .map(|row| row["index"].as_u64().expect("scope index"))
        .max()
        .expect("the read reaches a binding");
    assert!(
        inner_scope > outer_scope,
        "the nearer binder wins, and its scope is deeper: outer {outer_scope}, inner {inner_scope}"
    );

    // The shadowed outer binding is still stateable -- it is a labelled extra
    // row rather than an answer that disappeared.
    let shadowed = complete(
        &[("src/render.rs", RUST_INNER_NAMESAKE)],
        json!({
            "languages": ["rust"],
            "occurrences": { "role": ["value_reference"] },
            "steps": [{ "op": "reaching_binding", "include_shadowed": true }]
        }),
    );
    assert!(
        rows(&shadowed)
            .iter()
            .any(|row| row["shadowed"] == json!(true)),
        "the loser is published, not dropped: {shadowed:#}"
    );
}

// ---------------------------------------------------------------------------
// Scenario 4 -- type/value namespace collision (Java).
// ---------------------------------------------------------------------------

/// Legal Java in which one spelling is a class, a local variable, two type
/// operands and one read. Nothing here is a near-miss of the *spelling*; the
/// near-miss is the position.
const JAVA_NAMESPACE_COLLISION: &str = "package app;\n\nclass Item {\n    int weigh() { return 2; }\n}\n\nclass Holder {\n    int run() {\n        Item Item = new Item();\n        return Item.weigh();\n    }\n}\n";

/// The same file with the value read removed: the local and both type operands
/// remain, so the spelling is untouched and only the value-position occurrence
/// is gone.
const JAVA_NAMESPACE_COLLISION_TYPE_ONLY: &str = "package app;\n\nclass Item {\n    int weigh() { return 2; }\n}\n\nclass Holder {\n    int run() {\n        Item Item = new Item();\n        return 0;\n    }\n}\n";

/// A type operand never reaches a value binding, however identically it is
/// spelled. This is the collision the mined regressions resolved by name.
#[test]
fn a_type_operand_never_reaches_the_value_binding_that_shares_its_spelling() {
    let files = [("app/Item.java", JAVA_NAMESPACE_COLLISION)];

    let type_operands = complete(
        &files,
        json!({
            "languages": ["java"],
            "occurrences": { "role": ["type_operand"] },
            "steps": [{ "op": "reaching_binding" }]
        }),
    );
    assert!(
        rows(&type_operands).is_empty(),
        "a type operand resolves in the type namespace, where this file binds nothing: {type_operands:#}"
    );

    let value_positions = complete(
        &files,
        json!({
            "languages": ["java"],
            "occurrences": { "role": ["receiver_position"] },
            "steps": [{ "op": "reaching_binding" }]
        }),
    );
    assert_eq!(
        field(&value_positions, "name"),
        vec!["Item".to_string()],
        "the value-position occurrence of the same spelling does reach the local: {value_positions:#}"
    );
    assert_eq!(
        field(&value_positions, "namespace"),
        vec!["value".to_string()]
    );

    // The near-miss half: drop only the value read. Every type operand stays,
    // and the answer goes to empty -- so the earlier row came from the
    // position, not from the name.
    let type_only = complete(
        &[("app/Item.java", JAVA_NAMESPACE_COLLISION_TYPE_ONLY)],
        json!({
            "languages": ["java"],
            "occurrences": { "role": ["receiver_position"] },
            "steps": [{ "op": "reaching_binding" }]
        }),
    );
    assert!(
        rows(&type_only).is_empty(),
        "no value-position occurrence remains to reach anything: {type_only:#}"
    );
}

// ---------------------------------------------------------------------------
// Scenario 5 -- several namespaces in one file (Java).
// ---------------------------------------------------------------------------

/// One file, one spelling, four occurrence rows in two namespaces, and exactly
/// one binding row. The binding side of the environment has a value namespace
/// only: no adapter classifies a type parameter as a binder today, which is a
/// stated gap rather than a claim that type names are never bound.
#[test]
fn one_file_carries_occurrences_in_both_namespaces_and_binds_only_in_the_value_one() {
    let files = [("app/Item.java", JAVA_NAMESPACE_COLLISION)];

    let occurrences = complete(
        &files,
        json!({
            "languages": ["java"],
            "occurrences": { "role": ["binder", "type_operand", "receiver_position"] }
        }),
    );
    let item_namespaces = rows(&occurrences)
        .iter()
        .filter(|row| row["raw_spelling"] == json!("Item"))
        .map(|row| {
            (
                row["role"].as_str().unwrap_or_default().to_string(),
                row["namespace"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect::<Vec<_>>();
    assert!(
        item_namespaces.contains(&("binder".to_string(), "value".to_string())),
        "{item_namespaces:?}"
    );
    assert!(
        item_namespaces.contains(&("type_operand".to_string(), "type".to_string())),
        "{item_namespaces:?}"
    );
    assert!(
        item_namespaces.contains(&("receiver_position".to_string(), "value".to_string())),
        "{item_namespaces:?}"
    );

    let bindings = complete(
        &files,
        json!({
            "languages": ["java"],
            "bindings": { "name": ["Item"] }
        }),
    );
    assert_eq!(
        field(&bindings, "namespace"),
        vec!["value".to_string()],
        "one binding, in the value namespace: {bindings:#}"
    );
}

// ---------------------------------------------------------------------------
// Scenario 6 -- an unindexed declared dependency (Java).
// ---------------------------------------------------------------------------

const HOST_EXTERNAL_DEPENDENCY: &str = "package app;\n\nimport java.util.Collections;\nimport java.util.List;\n\nclass Host {\n    void run(List<String> rows) {\n        Collections.sort(rows);\n    }\n}\n";

/// `java.util` is declared by the import and absent from the workspace, so the
/// resolver reaches an authoritative boundary. The row states the boundary and
/// the refusal; it is never a clean empty answer, and it is never a selection.
#[test]
fn an_unindexed_declared_dependency_is_a_boundary_row_rather_than_an_empty_answer() {
    let external = complete(
        &[("app/Host.java", HOST_EXTERNAL_DEPENDENCY)],
        json!({
            "languages": ["java"],
            "occurrences": { "role": ["type_operand", "receiver_position"] },
            "steps": [{ "op": "candidates_of", "boundary": ["external_unknown"] }]
        }),
    );
    assert!(
        !rows(&external).is_empty(),
        "the boundary is stated as rows: {external:#}"
    );
    for row in rows(&external) {
        assert_eq!(row["outcome"], json!("rejected"));
        assert_eq!(row["rejection_reason"], json!("boundary_blocked"));
        assert_eq!(row["tier"], json!("external_root"));
        assert_eq!(
            row["candidate"]["candidate_kind"],
            json!("external_route"),
            "a boundary has a route, not a declaration: {row:#}"
        );
    }

    // The near-miss: the same import shape against a target that *is* in the
    // workspace. One structural fact differs -- whether the declared
    // dependency is present -- and the boundary follows it.
    let local = complete(
        &[
            ("api/Widget.java", API_WIDGET),
            ("app/Host.java", HOST_EXPLICIT_IMPORT),
        ],
        json!({
            "languages": ["java"],
            "occurrences": { "role": ["type_operand"] },
            "steps": [{ "op": "candidates_of" }]
        }),
    );
    assert!(!rows(&local).is_empty());
    for row in rows(&local) {
        assert_eq!(
            row["boundary"],
            json!("workspace_local"),
            "an indexed target crosses no boundary: {row:#}"
        );
        assert_eq!(row["outcome"], json!("selected"));
    }
}

// ---------------------------------------------------------------------------
// Scenario 7 -- wildcard ambiguity stays explicit (Java).
// ---------------------------------------------------------------------------

const TWO_WILDCARDS: &str = "package app;\n\nimport api.*;\nimport util.*;\n\nclass Host {\n    int run() { return 1; }\n}\n";

const ONE_WILDCARD: &str =
    "package app;\n\nimport api.*;\n\nclass Host {\n    int run() { return 1; }\n}\n";

/// Adding one wildcard import makes a selection through that tier unprovable,
/// and the row says so instead of reporting a confident target. The wildcard
/// binder is named `*` rather than any identifier, so it can never be mistaken
/// for a binding of a name.
#[test]
fn a_second_wildcard_import_makes_the_wildcard_tier_ambiguous() {
    let query = json!({
        "languages": ["java"],
        "bindings": { "kind": ["import_binder"] }
    });

    let two = complete(&[("app/Host.java", TWO_WILDCARDS)], query.clone());
    assert_eq!(rows(&two).len(), 2, "{two:#}");
    for row in rows(&two) {
        assert_eq!(row["name"], json!("*"), "a wildcard binds no name: {row:#}");
        assert_eq!(row["import"]["wildcard"], json!(true));
        assert_eq!(
            row["import"]["wildcard_ambiguous"],
            json!(true),
            "two on-demand routes cannot both be the unique one: {row:#}"
        );
    }

    let one = complete(&[("app/Host.java", ONE_WILDCARD)], query);
    assert_eq!(rows(&one).len(), 1);
    assert_eq!(
        rows(&one)[0]["import"]["wildcard_ambiguous"],
        json!(false),
        "a single on-demand route is unambiguous: {one:#}"
    );
}

// ---------------------------------------------------------------------------
// Scenario 8 -- the authoritative-boundary anti-fallback contract.
// ---------------------------------------------------------------------------

/// No resolver in the workspace selects at `name_only_fallback`; the tier
/// exists so the prohibition has something to name. This test is the standing
/// evidence for that claim across the four claimed languages, and it is the
/// reason the assertion-surface boundary fixture asserts a clean run rather
/// than a seeded firing: faking a violation would mean writing a resolver that
/// commits the offence.
#[test]
fn no_candidate_row_in_any_claimed_language_selects_at_the_name_only_fallback_tier() {
    let candidates = complete(
        &[
            ("app/Host.java", HOST_EXTERNAL_DEPENDENCY),
            ("src/render.rs", RUST_INNER_NAMESAKE),
            (
                "pkg/widget.py",
                "import os\n\n\ndef render(rows):\n    total = rows\n    return os.sep + str(total)\n",
            ),
            (
                "src/widget.ts",
                "import { readFileSync } from \"fs\";\n\nexport function render(rows: string[]): string {\n    const first = rows[0];\n    return readFileSync(first, \"utf8\");\n}\n",
            ),
        ],
        json!({
            "occurrences": { "role": ["value_reference", "receiver_position", "type_operand"] },
            "steps": [{ "op": "candidates_of" }]
        }),
    );
    assert!(
        !rows(&candidates).is_empty(),
        "the sweep must actually see candidates: {candidates:#}"
    );
    for row in rows(&candidates) {
        assert_ne!(
            row["tier"],
            json!("name_only_fallback"),
            "a resolver that falls back by bare name must say so, and none does: {row:#}"
        );
    }
}

/// Python and JS/TS record selections but not rejections, and every row they
/// produce says so. An absent rejection row in those languages is a silence,
/// never a statement that nothing was rejected.
#[test]
fn a_selection_only_language_labels_every_row_it_produces() {
    for (path, source) in [
        (
            "pkg/widget.py",
            "def render(rows):\n    total = rows\n    return total\n",
        ),
        (
            "src/widget.ts",
            "export function render(rows: string[]): string {\n    const first = rows[0];\n    return first;\n}\n",
        ),
    ] {
        let candidates = complete(
            &[(path, source)],
            json!({
                "occurrences": { "role": ["value_reference"] },
                "steps": [{ "op": "candidates_of" }]
            }),
        );
        assert!(!rows(&candidates).is_empty(), "{candidates:#}");
        for row in rows(&candidates) {
            assert_eq!(
                row["trace_completeness"],
                json!("selection_only"),
                "{path} must not imply it recorded the whole considered set: {row:#}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Scenario 9 -- deferred bodies inside a loop (Java).
// ---------------------------------------------------------------------------

const JAVA_DEFERRED_BODY: &str = "import java.util.ArrayList;\nimport java.util.Collections;\nimport java.util.List;\n\nclass Deferred {\n    void run() {\n        List<String> rows = new ArrayList<>();\n        int index = 0;\n        while (index < 3) {\n            Runnable task = () -> Collections.sort(rows);\n            task.run();\n            index = index + 1;\n        }\n    }\n}\n";

/// The boundary the repository policy requires to be pinned rather than
/// claimed: a call written inside a closure body inside a loop.
///
/// Lexical containment says the call is inside the loop, because it is; what
/// containment cannot say is how many times the closure runs. The rows below
/// state exactly what is true -- the receiver's binding is declared outside the
/// loop, and the call's scope chain passes through the loop -- so a rule built
/// on them reports this shape as a lexical positive. The assertion-surface
/// fixture makes that the tested, documented behaviour instead of a silent
/// one.
#[test]
fn a_call_inside_a_closure_inside_a_loop_is_a_lexical_positive_by_construction() {
    let files = [("app/Deferred.java", JAVA_DEFERRED_BODY)];

    let reached = complete(
        &files,
        json!({
            "languages": ["java"],
            "occurrences": { "role": ["value_reference", "receiver_position"] },
            "steps": [{ "op": "reaching_binding" }]
        }),
    );
    let rows_binding = rows(&reached)
        .iter()
        .find(|row| row["name"] == json!("rows"))
        .expect("the closure's receiver reaches the outer local");
    let declaring_scope = rows_binding["declaring_scope_index"]
        .as_u64()
        .expect("a binding names its declaring scope");

    let scopes = complete(&files, json!({ "languages": ["java"], "scopes": {} }));
    let loop_scope = rows(&scopes)
        .iter()
        .find(|row| row["kind"] == json!("while_loop"))
        .expect("the fixture has one loop");
    let declaring = rows(&scopes)
        .iter()
        .find(|row| row["index"].as_u64() == Some(declaring_scope))
        .expect("every declaring scope is a scope row");

    assert!(
        declaring["start_byte"].as_u64() < loop_scope["start_byte"].as_u64(),
        "the receiver is declared before and outside the loop: {declaring:#} {loop_scope:#}"
    );
}
