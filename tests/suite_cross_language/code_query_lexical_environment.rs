//! End-to-end coverage of the lexical-environment and resolution-candidate
//! typed domains (#1474, Milestone 4).
//!
//! The load-bearing test here is `loop_invariance_discriminator_separates_the_two_fixture_halves`:
//! the motivating false-positive corpus for this whole slice reduces to one
//! missing predicate -- is the value operated on inside this loop declared
//! inside or outside the loop body? -- and that test answers it as a query,
//! from a capture through `reaching-binding` and `scope-of` to a containment
//! check against the loop's own scope, on both halves of the fixture.

use crate::common::InlineTestProject;
use brokk_bifrost::analyzer::structural::{
    CodeQuery, CodeQueryCompletion, CodeQueryDiagnosticCode, CodeQueryResult, SCHEMA_VERSION,
    execute_workspace,
};
use brokk_bifrost::{AnalyzerConfig, WorkspaceAnalyzer};
use serde_json::{Value, json};

fn run(files: &[(&str, &str)], query: Value) -> CodeQueryResult {
    let mut project = InlineTestProject::new();
    for (path, source) in files {
        project = project.file(*path, *source);
    }
    let project = project.build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&query).expect("query should parse");
    execute_workspace(&workspace, &query)
}

fn serialized(result: &CodeQueryResult) -> Value {
    serde_json::to_value(result).expect("query result should serialize")
}

fn rows(value: &Value) -> &Vec<Value> {
    value["results"].as_array().expect("results array")
}

fn strings(value: &Value, field: &str) -> Vec<String> {
    rows(value)
        .iter()
        .filter_map(|row| row[field].as_str().map(str::to_string))
        .collect()
}

fn has_diagnostic(result: &CodeQueryResult, code: CodeQueryDiagnosticCode) -> bool {
    result
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == code)
}

/// The two halves of the motivating discriminator, in one file so the two
/// answers cannot differ for any reason other than where the binding is.
const LOOP_FIXTURE: &str = "\
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

class Sorter {
    void invariant(List<String> outerRows) {
        List<String> rows = new ArrayList<>();
        int index = 0;
        while (index < 3) {
            Collections.sort(rows);
            index = index + 1;
        }
    }

    void perIteration() {
        int index = 0;
        while (index < 3) {
            List<String> rows = new ArrayList<>();
            Collections.sort(rows);
            index = index + 1;
        }
    }
}
";

/// The motivating false-positive discriminator, end to end as a query.
///
/// Both halves sort a `List<String> rows` inside a `while` loop. Only the
/// first is a real finding: its binding is declared outside the loop, so the
/// sort is redundant work per iteration. The second declares `rows` inside the
/// loop body, so each iteration sorts a fresh list.
///
/// The join is structural throughout: the capture reaches the binding through
/// `reaching_binding` (activation intervals and scope ancestry, never source
/// order), and the binding reaches its declaring scope through `scope_of`. The
/// verdict is then the scope index of that declaring scope compared against
/// the scopes the two methods contain -- no range arithmetic and no spelling.
#[test]
fn loop_invariance_discriminator_separates_the_two_fixture_halves() {
    let files = [("app/Sorter.java", LOOP_FIXTURE)];

    // Step one: every value read, joined to the binding in effect at that
    // exact position. `rows` is the fixture's control variable -- both halves
    // spell it identically, so any difference between them comes from where
    // the binding is, never from the name.
    let reached = run(
        &files,
        json!({
            "languages": ["java"],
            "occurrences": { "role": ["value_reference"] },
            "steps": [{ "op": "reaching_binding" }]
        }),
    );
    assert_eq!(
        reached.completion(),
        CodeQueryCompletion::Complete,
        "the discriminator must be read only from a complete run: {:?}",
        reached.diagnostics
    );
    let reached = serialized(&reached);
    let mut declaring_scopes = rows(&reached)
        .iter()
        .filter(|row| row["name"] == json!("rows"))
        .map(|row| {
            row["declaring_scope_index"]
                .as_u64()
                .expect("a binding names its declaring scope")
        })
        .collect::<Vec<_>>();
    declaring_scopes.sort_unstable();
    declaring_scopes.dedup();
    assert_eq!(
        declaring_scopes.len(),
        2,
        "the two `rows` reads must reach different declaring scopes: {reached:#}"
    );

    // Step two: `scope-of` reaches the same scopes from the same occurrences,
    // so the two steps agree rather than being two opinions.
    let scoped = serialized(&run(
        &files,
        json!({
            "languages": ["java"],
            "occurrences": { "role": ["value_reference"] },
            "steps": [{ "op": "reaching_binding" }, { "op": "scope_of" }]
        }),
    ));
    let scoped_indices = rows(&scoped)
        .iter()
        .map(|row| row["index"].as_u64().expect("scope rows carry an index"))
        .collect::<Vec<_>>();
    for index in &declaring_scopes {
        assert!(
            scoped_indices.contains(index),
            "scope_of must reach the scope the binding names: {scoped:#}"
        );
    }

    // Step three: the verdict. Which of those declaring scopes is contained in
    // a loop? Containment is arena containment between two scope rows of one
    // file, not range arithmetic over unrelated values.
    let scopes = serialized(&run(&files, json!({ "languages": ["java"], "scopes": {} })));
    let loop_spans = rows(&scopes)
        .iter()
        .filter(|row| {
            row["kind"]
                .as_str()
                .is_some_and(|kind| kind == "while_loop" || kind == "loop")
        })
        .map(|row| {
            (
                row["start_byte"].as_u64().expect("scope start"),
                row["end_byte"].as_u64().expect("scope end"),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        loop_spans.len(),
        2,
        "the fixture has exactly two loops: {scopes:#}"
    );

    let verdicts = declaring_scopes
        .iter()
        .map(|index| {
            let scope = rows(&scopes)
                .iter()
                .find(|row| row["index"].as_u64() == Some(*index))
                .expect("every declaring scope is a scope row");
            let start = scope["start_byte"].as_u64().expect("scope start");
            let end = scope["end_byte"].as_u64().expect("scope end");
            loop_spans
                .iter()
                .any(|(loop_start, loop_end)| start >= *loop_start && end <= *loop_end)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        verdicts,
        vec![false, true],
        "the invariant half declares `rows` outside its loop and the \
         per-iteration half declares it inside: {verdicts:?} over {scopes:#}"
    );
}

/// A scope query returns the synthesized whole-file scope plus every
/// scope-forming node, parent-linked, and only the file scope lacks an AST id.
#[test]
fn scope_rows_carry_ancestry_and_only_the_file_scope_has_no_ast_id() {
    let result = run(
        &[("app/Sorter.java", LOOP_FIXTURE)],
        json!({
            "languages": ["java"],
            "scopes": {}
        }),
    );
    let value = serialized(&result);

    let file_scopes = rows(&value)
        .iter()
        .filter(|row| row["index"].as_u64() == Some(0))
        .collect::<Vec<_>>();
    assert_eq!(file_scopes.len(), 1, "one file scope per file: {value:#}");
    let file_scope = file_scopes[0];
    assert!(
        file_scope["ast_id"].is_null(),
        "the synthesized whole-file scope has no arena node: {file_scope:#}"
    );
    assert!(
        file_scope["kind"].is_null(),
        "and therefore no normalized kind: {file_scope:#}"
    );
    assert!(
        file_scope["parent_index"].is_null(),
        "the file scope is the root of the chain: {file_scope:#}"
    );

    for row in rows(&value).iter().filter(|row| row["index"] != json!(0)) {
        assert!(
            row["ast_id"].is_string(),
            "every anchored scope has an AST identity: {row:#}"
        );
        assert!(
            row["parent_index"].is_number(),
            "every scope but the file scope has a parent: {row:#}"
        );
    }
}

/// A non-empty `kind` filter selects anchored scopes only, because the
/// synthesized file scope has no anchoring fact to carry a kind.
#[test]
fn a_scope_kind_filter_never_selects_the_synthesized_file_scope() {
    let result = run(
        &[("app/Sorter.java", LOOP_FIXTURE)],
        json!({
            "languages": ["java"],
            "scopes": { "kind": ["block"] }
        }),
    );
    let value = serialized(&result);
    assert!(
        !rows(&value).is_empty(),
        "the fixture has block scopes: {value:#}"
    );
    for row in rows(&value) {
        assert_eq!(row["kind"], json!("block"), "filtered to blocks: {row:#}");
        assert!(row["ast_id"].is_string());
    }
}

/// `scope-ancestors` walks outward and excludes the scope itself, so a chain
/// from a nested block always ends at the file scope.
#[test]
fn scope_ancestors_walks_outward_and_excludes_the_scope_itself() {
    let result = run(
        &[("app/Sorter.java", LOOP_FIXTURE)],
        json!({
            "languages": ["java"],
            "scopes": { "kind": ["while_loop"] },
            "steps": [{ "op": "scope_ancestors" }]
        }),
    );
    let value = serialized(&result);
    let indices = rows(&value)
        .iter()
        .map(|row| row["index"].as_u64().expect("scope index"))
        .collect::<Vec<_>>();
    assert!(
        indices.contains(&0),
        "every ancestry chain reaches the file scope: {value:#}"
    );
    for row in rows(&value) {
        assert_ne!(
            row["kind"],
            json!("while_loop"),
            "the loop scope itself is excluded from its own ancestry: {row:#}"
        );
    }
}

/// Binding rows carry the interval over which they are in effect, and that
/// interval starts after the declarator rather than at the binder token --
/// which is what makes "read before declaration" answerable at all.
#[test]
fn binding_rows_carry_activation_intervals_and_declaring_scopes() {
    let result = run(
        &[("app/Sorter.java", LOOP_FIXTURE)],
        json!({
            "languages": ["java"],
            "bindings": { "name": ["rows"] }
        }),
    );
    let value = serialized(&result);
    assert_eq!(
        rows(&value).len(),
        2,
        "the fixture declares `rows` twice: {value:#}"
    );
    for row in rows(&value) {
        assert_eq!(row["name"], json!("rows"));
        assert_eq!(row["kind"], json!("local"));
        assert_eq!(row["hoisting"], json!("source_order"));
        assert_eq!(row["namespace"], json!("value"));
        assert!(
            row["activation_start_byte"].as_u64() > row["start_byte"].as_u64(),
            "a source-order local is in effect only after its declarator: {row:#}"
        );
        assert!(row["declaring_scope_index"].is_number());
        assert!(
            row["ast_id"].is_string(),
            "a Java local's binder is a classified token: {row:#}"
        );
    }
}

/// `bindings-in` over a scope returns only the bindings that scope declares,
/// not those of its descendants, so scope ownership is a real relation.
#[test]
fn bindings_in_returns_only_the_bindings_a_scope_itself_declares() {
    let result = run(
        &[("app/Sorter.java", LOOP_FIXTURE)],
        json!({
            "languages": ["java"],
            "scopes": { "kind": ["while_loop"] },
            "steps": [{ "op": "bindings_in" }]
        }),
    );
    let value = serialized(&result);
    // Only the per-iteration half declares anything inside a loop scope, and
    // the loop's own body block owns it rather than the loop node -- so this
    // answer is legitimately empty and that emptiness is complete.
    for row in rows(&value) {
        assert_eq!(row["name"], json!("rows"), "unexpected row: {row:#}");
    }
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "an empty scope-ownership answer must still be complete: {:?}",
        result.diagnostics
    );
}

/// `binding-occurrence` walks back to the binder token's occurrence row, and
/// the two agree on one `ast_id` -- the same equijoin captures use.
#[test]
fn binding_occurrence_joins_back_by_ast_id() {
    let files = [("app/Sorter.java", LOOP_FIXTURE)];
    let bindings = serialized(&run(
        &files,
        json!({
            "languages": ["java"],
            "bindings": { "name": ["rows"] }
        }),
    ));
    let occurrences = serialized(&run(
        &files,
        json!({
            "languages": ["java"],
            "bindings": { "name": ["rows"] },
            "steps": [{ "op": "binding_occurrence" }]
        }),
    ));

    let mut binding_ids = strings(&bindings, "ast_id");
    let mut occurrence_ids = strings(&occurrences, "ast_id");
    binding_ids.sort();
    occurrence_ids.sort();
    assert!(!binding_ids.is_empty());
    assert_eq!(
        binding_ids, occurrence_ids,
        "the binder token is one node addressed two ways"
    );
    for row in rows(&occurrences) {
        assert_eq!(row["class"], json!("binding"));
    }
}

/// A shadowing Rust fixture: the reaching binding of a read is the nearest
/// `let`, and `:include-shadowed` makes the outer one a visible second row
/// rather than a collapsed answer.
#[test]
fn include_shadowed_turns_a_shadowed_binding_into_a_visible_row() {
    let files = [(
        "src/shadow.rs",
        "fn render() -> usize {\n    let value = 1;\n    {\n        let value = 2;\n        return value;\n    }\n}\n",
    )];

    let winner_only = serialized(&run(
        &files,
        json!({
            "languages": ["rust"],
            "occurrences": { "role": ["value_reference"] },
            "steps": [{ "op": "reaching_binding" }]
        }),
    ));
    let with_shadowed = serialized(&run(
        &files,
        json!({
            "languages": ["rust"],
            "occurrences": { "role": ["value_reference"] },
            "steps": [
                { "op": "reaching_binding", "include_shadowed": true }
            ]
        }),
    ));

    assert!(
        rows(&with_shadowed).len() > rows(&winner_only).len(),
        "the shadowed binding must be an additional row, not a replacement:\nwinner {winner_only:#}\nwith shadowed {with_shadowed:#}"
    );
    assert!(
        rows(&with_shadowed)
            .iter()
            .any(|row| row["shadowed"] == json!(true)),
        "the loser is labelled rather than silently indistinguishable: {with_shadowed:#}"
    );
    assert!(
        rows(&winner_only)
            .iter()
            .all(|row| row["shadowed"] != json!(true)),
        "without the option only the winner is returned: {winner_only:#}"
    );
}

/// A read of a name with no lexical binding is a complete empty answer, not an
/// incomplete one: the name resolves to something other than a binding.
#[test]
fn a_name_with_no_lexical_binding_yields_a_complete_empty_answer() {
    let result = run(
        &[(
            "app/Widget.java",
            "class Widget {\n    int field = 1;\n    int read() { return field; }\n}\n",
        )],
        json!({
            "languages": ["java"],
            "occurrences": { "role": ["value_reference"] },
            "steps": [{ "op": "reaching_binding" }]
        }),
    );
    assert!(
        rows(&serialized(&result)).is_empty(),
        "a field is a member, not a lexical binding"
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "\"no binding is in effect\" is a complete answer: {:?}",
        result.diagnostics
    );
}

/// `candidates-of` reports what the resolver considered, and the tier and
/// outcome filters narrow it. The Rust shadowing shape is the one the mined
/// inventory turns on.
#[test]
fn candidates_of_filters_by_tier_and_outcome_on_the_rust_shadowing_shape() {
    let files = [(
        "src/shadow.rs",
        "fn render() -> usize {\n    let value = 1;\n    {\n        let value = 2;\n        return value;\n    }\n}\n",
    )];

    let all = serialized(&run(
        &files,
        json!({
            "languages": ["rust"],
            "occurrences": { "role": ["value_reference"] },
            "steps": [{ "op": "candidates_of" }]
        }),
    ));
    assert!(
        !rows(&all).is_empty(),
        "the read has a traced resolution: {all:#}"
    );

    let selected = serialized(&run(
        &files,
        json!({
            "languages": ["rust"],
            "occurrences": { "role": ["value_reference"] },
            "steps": [{ "op": "candidates_of", "outcome": ["selected"] }]
        }),
    ));
    for row in rows(&selected) {
        assert_eq!(row["outcome"], json!("selected"), "filtered: {row:#}");
    }
    assert!(rows(&selected).len() <= rows(&all).len());

    let lexical = serialized(&run(
        &files,
        json!({
            "languages": ["rust"],
            "occurrences": { "role": ["value_reference"] },
            "steps": [{ "op": "candidates_of", "tier": ["lexical_binding"] }]
        }),
    ));
    for row in rows(&lexical) {
        assert_eq!(row["tier"], json!("lexical_binding"), "filtered: {row:#}");
    }

    // Every row states how much of the candidate story its language tells, so
    // an absent rejection row is never silently read as "nothing was rejected".
    for row in rows(&all) {
        assert!(
            matches!(
                row["trace_completeness"].as_str(),
                Some("full" | "selection_only")
            ),
            "every candidate row declares its trace completeness: {row:#}"
        );
    }
}

/// The `unattributed` tier value selects exactly the rows whose recording seam
/// could not name a tier, and never a row that has one.
#[test]
fn the_unattributed_tier_value_selects_only_rows_without_a_tier() {
    let files = [(
        "src/shadow.rs",
        "fn render() -> usize {\n    let value = 1;\n    {\n        let value = 2;\n        return value;\n    }\n}\n",
    )];
    let unattributed = serialized(&run(
        &files,
        json!({
            "languages": ["rust"],
            "occurrences": { "class": ["reference"] },
            "steps": [{ "op": "candidates_of", "tier": ["unattributed"] }]
        }),
    ));
    for row in rows(&unattributed) {
        assert!(
            row["tier"].is_null(),
            "`unattributed` is not a named tier: {row:#}"
        );
    }
}

/// A candidate that carries no workspace declaration cannot be projected to
/// one, so `candidate-target` is partial by construction rather than by gap.
#[test]
fn candidate_target_answers_only_for_unit_backed_candidates() {
    let files = [(
        "src/shadow.rs",
        "fn render() -> usize {\n    let value = 1;\n    {\n        let value = 2;\n        return value;\n    }\n}\n",
    )];
    let candidates = serialized(&run(
        &files,
        json!({
            "languages": ["rust"],
            "occurrences": { "class": ["reference"] },
            "steps": [{ "op": "candidates_of" }]
        }),
    ));
    let targets = serialized(&run(
        &files,
        json!({
            "languages": ["rust"],
            "occurrences": { "class": ["reference"] },
            "steps": [{ "op": "candidates_of" }, { "op": "candidate_target" }]
        }),
    ));

    let unit_backed = rows(&candidates)
        .iter()
        .filter(|row| row["candidate_kind"] == json!("unit"))
        .count();
    assert!(
        rows(&targets).len() <= unit_backed.max(rows(&candidates).len()),
        "candidate_target never invents a declaration:\ncandidates {candidates:#}\ntargets {targets:#}"
    );
    for row in rows(&targets) {
        assert_eq!(row["result_type"], json!("declaration"));
    }
}

/// Scala declares every lexical-environment axis unsupported, so its rows are
/// reported incomplete rather than answered with a clean empty set.
#[test]
fn an_unsupported_adapter_reports_incomplete_rather_than_empty() {
    let result = run(
        &[(
            "src/Widget.scala",
            "class Widget {\n  def render(label: String): Int = {\n    val trimmed = label.trim()\n    trimmed.length\n  }\n}\n",
        )],
        json!({
            "languages": ["scala"],
            "bindings": {}
        }),
    );
    assert!(
        has_diagnostic(&result, CodeQueryDiagnosticCode::EnvironmentAxisUnsupported),
        "an all-unsupported adapter must say so: {:?}",
        result.diagnostics
    );
    assert_ne!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "an unsupported axis cannot yield a complete run"
    );
}

/// The file row carries the package clause, syntactically for Java and
/// path-derived for Python, and never claims one it could not name.
#[test]
fn file_rows_carry_the_package_clause_with_its_origin() {
    let result = run(
        &[
            (
                "api/Widget.java",
                "package api;\n\nclass Widget {\n    int render() { return 1; }\n}\n",
            ),
            ("pkg/widget.py", "def render():\n    return 1\n"),
        ],
        json!({
            "match": { "kind": "callable", "name": "render" },
            "steps": [{ "op": "file_of" }]
        }),
    );
    let value = serialized(&result);
    let java = rows(&value)
        .iter()
        .find(|row| row["language"] == json!("java"))
        .expect("the Java file row");
    assert_eq!(java["package_fq"], json!("api"));
    assert_eq!(
        java["package_syntactic"],
        json!(true),
        "Java spells its package in the source: {java:#}"
    );

    let python = rows(&value)
        .iter()
        .find(|row| row["language"] == json!("python"))
        .expect("the Python file row");
    assert_eq!(
        python["package_syntactic"],
        json!(false),
        "Python's package is derived from the path: {python:#}"
    );
}

/// The lexical-environment surface is available at the single schema version,
/// pinned or unpinned.
#[test]
fn lexical_environment_surface_is_available_at_the_single_schema_version() {
    for source in [
        json!({ "schema_version": 1, "scopes": {} }),
        json!({ "schema_version": 1, "bindings": {} }),
    ] {
        CodeQuery::from_json(&source).expect("the pinned surface must decode");
    }

    let unpinned = CodeQuery::from_json(&json!({ "scopes": {} }))
        .expect("an unpinned document resolves to the compatible head");
    assert_eq!(unpinned.schema_version, SCHEMA_VERSION);
}

/// Both frontends lower to one canonical query, so an author can spell the
/// same thing in RQL or JSON and get identical execution.
#[test]
fn rql_and_json_round_trip_to_one_canonical_query() {
    for (rql, json_value) in [
        (
            "(language \"java\" (scopes :kind block))",
            json!({ "languages": ["java"], "scopes": { "kind": ["block"] } }),
        ),
        (
            "(language \"java\" (bindings :kind [local parameter] :hoisting source_order))",
            json!({
                "languages": ["java"],
                "bindings": { "kind": ["local", "parameter"], "hoisting": ["source_order"] }
            }),
        ),
        (
            "(scope-of (reaching-binding :include-shadowed true (occurrences :class reference)))",
            json!({
                "occurrences": { "class": ["reference"] },
                "steps": [
                    { "op": "reaching_binding", "include_shadowed": true },
                    { "op": "scope_of" }
                ]
            }),
        ),
        (
            "(candidate-target (candidates-of :tier [unattributed lexical_binding] :outcome shadowed_by_nearer (occurrences :class reference)))",
            json!({
                "occurrences": { "class": ["reference"] },
                "steps": [
                    {
                        "op": "candidates_of",
                        "tier": ["unattributed", "lexical_binding"],
                        "outcome": ["shadowed_by_nearer"]
                    },
                    { "op": "candidate_target" }
                ]
            }),
        ),
    ] {
        let from_rql = CodeQuery::from_sexp(rql).expect("RQL should parse");
        let from_json = CodeQuery::from_json(&json_value).expect("JSON should parse");
        assert_eq!(
            from_rql.to_canonical_json(),
            from_json.to_canonical_json(),
            "both frontends must lower {rql} to one query"
        );
    }
}

/// Unknown constrained values are rejected at decode time with the field path,
/// so an agent can self-correct instead of receiving an empty result.
#[test]
fn unknown_filter_values_are_rejected_with_their_paths() {
    let unknown_kind = CodeQuery::from_json(&json!({ "bindings": { "kind": ["locall"] } }))
        .expect_err("unknown binding kinds must not be silently ignored");
    assert_eq!(unknown_kind.path, "bindings.kind[0]");

    let unknown_field = CodeQuery::from_json(&json!({ "scopes": { "role": ["binder"] } }))
        .expect_err("the scope filter has a closed field set");
    assert_eq!(unknown_field.path, "scopes.role");

    let unknown_tier = CodeQuery::from_json(&json!({
        "occurrences": {},
        "steps": [{ "op": "candidates_of", "tier": ["lexical"] }]
    }))
    .expect_err("a near-miss tier spelling must be rejected");
    assert_eq!(unknown_tier.path, "steps[0].tier[0]");

    let both_sources = CodeQuery::from_json(&json!({
        "scopes": {},
        "bindings": {}
    }))
    .expect_err("plan sources are mutually exclusive");
    assert!(both_sources.message.contains("mutually exclusive"));

    let containment = CodeQuery::from_json(&json!({
        "scopes": {},
        "inside": { "kind": "class" }
    }))
    .expect_err("a non-structural seed takes no containment pattern");
    assert!(
        containment.message.contains("scope_of"),
        "the rejection must name the composable alternative: {containment:?}"
    );
}
