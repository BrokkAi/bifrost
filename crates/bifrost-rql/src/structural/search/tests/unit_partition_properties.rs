//! The partition property: merging one execution per seed file equals one
//! whole execution.
//!
//! The oracle is the whole execution itself, which is independent of the merge
//! under test: the executor does not know it is being partitioned, and the
//! merge never reads the whole run. The claim holds only while no cumulative
//! cap was reached, so every case asserts that from the whole run's own
//! counters before comparing.

use super::inline_project::BuiltInlineTestProject;
use super::*;
use crate::PlanPartitioning;
use crate::structural::search::units::{
    CodeQueryExecutionScope, MergedLimit, execute_code_query_unit, merge_unit_rows, seed_file_order,
};
use proptest::prelude::*;

/// At least eight files, so the whole execution clears the auto
/// structural-index admission rule (`MIN_AUTO_STRUCTURAL_INDEX_FILES`) and
/// takes the indexed path while every one-file unit takes scan access. A
/// divergence between the two paths is a bug in the index or in the
/// definite-absence prefilter, and this is where it would show.
const MIN_FILES: usize = 8;
const MAX_FILES: usize = 10;

/// One generated TypeScript project: functions that call each other across
/// files.
#[derive(Debug, Clone)]
struct GeneratedProject {
    /// How many functions each file declares.
    functions_per_file: Vec<usize>,
    /// For each function, in global declaration order, the function it calls.
    /// `None` when it calls nothing.
    call_targets: Vec<Option<usize>>,
}

impl GeneratedProject {
    /// The file each function is declared in, in global declaration order.
    fn owning_files(&self) -> Vec<usize> {
        let mut owners = Vec::new();
        for (file, count) in self.functions_per_file.iter().enumerate() {
            owners.extend(std::iter::repeat_n(file, *count));
        }
        owners
    }

    fn sources(&self) -> Vec<(String, String)> {
        let owners = self.owning_files();
        let mut first_function = vec![0; self.functions_per_file.len()];
        let mut running = 0;
        for (file, count) in self.functions_per_file.iter().enumerate() {
            first_function[file] = running;
            running += count;
        }

        let mut sources = Vec::new();
        for (file, count) in self.functions_per_file.iter().enumerate() {
            let functions = first_function[file]..first_function[file] + count;
            // One import line per file this file calls into, so the resolver
            // has a declared binding for every cross-file call.
            let mut imports: Vec<(usize, usize)> = functions
                .clone()
                .filter_map(|function| self.call_targets[function])
                .filter(|target| owners[*target] != file)
                .map(|target| (owners[target], target))
                .collect();
            imports.sort_unstable();
            imports.dedup();

            let mut source = String::new();
            for (target_file, target) in imports {
                source.push_str(&format!(
                    "import {{ fn{target} }} from './mod{target_file}';\n"
                ));
            }
            for function in functions {
                let body = match self.call_targets[function] {
                    Some(target) if target != function => format!("  return fn{target}();\n"),
                    _ => format!("  return {function};\n"),
                };
                source.push_str(&format!("export function fn{function}() {{\n{body}}}\n"));
            }
            sources.push((format!("src/mod{file}.ts"), source));
        }
        sources
    }

    fn build(&self) -> BuiltInlineTestProject {
        let mut project = InlineTestProject::with_language(Language::TypeScript);
        for (path, source) in self.sources() {
            project = project.file(path, source);
        }
        project.build()
    }
}

fn generated_project() -> impl Strategy<Value = GeneratedProject> {
    proptest::collection::vec(1_usize..=2, MIN_FILES..=MAX_FILES).prop_flat_map(
        |functions_per_file| {
            let functions: usize = functions_per_file.iter().sum();
            (
                Just(functions_per_file),
                proptest::collection::vec(proptest::option::of(0..functions), functions),
            )
                .prop_map(|(functions_per_file, call_targets)| GeneratedProject {
                    functions_per_file,
                    call_targets,
                })
        },
    )
}

/// The plans the property runs, one of each partitionable shape: a seed-only
/// structural plan, a row-local step, a derived-value step, a union, a flat
/// and a nested except of file-keyed rows, and a non-structural seed family.
fn partitioned_plans() -> Vec<(&'static str, CodeQuery)> {
    let query = |label: &'static str, value: serde_json::Value| {
        (
            label,
            CodeQuery::from_json(&value).expect("property query should parse"),
        )
    };
    let mut plans = vec![
        query(
            "structural seed",
            json!({
                "schema_version": 1,
                "match": { "kind": "function" },
                "limit": 500,
                "result_detail": "full"
            }),
        ),
        query(
            "row-local step",
            json!({
                "schema_version": 1,
                "match": { "kind": "function" },
                "steps": [{ "op": "enclosing_decl" }, { "op": "file_of" }],
                "limit": 500,
                "result_detail": "full"
            }),
        ),
        query(
            "derived-value step",
            json!({
                "schema_version": 1,
                "match": { "kind": "function" },
                "steps": [{ "op": "enclosing_decl" }, { "op": "callers" }],
                "limit": 500,
                "result_detail": "full"
            }),
        ),
        query(
            "overlapping union",
            json!({
                "schema_version": 1,
                "union": [
                    { "match": { "kind": "function", "name": { "regex": "^fn[0-9]$" } } },
                    { "match": { "kind": "function" } }
                ],
                "limit": 500,
                "result_detail": "full"
            }),
        ),
        query(
            "file-keyed except",
            json!({
                "schema_version": 1,
                "except": [
                    { "match": { "kind": "function" } },
                    { "match": { "kind": "function", "name": { "regex": "^fn[0-9]$" } } }
                ],
                "limit": 500,
                "result_detail": "full"
            }),
        ),
        query(
            "nested except",
            json!({
                "schema_version": 1,
                "except": [
                    { "except": [
                        { "match": { "kind": "function" } },
                        { "match": { "kind": "function", "name": { "regex": "^fn1[0-9]$" } } }
                    ] },
                    { "match": { "kind": "function", "name": { "regex": "^fn[0-4]$" } } }
                ],
                "limit": 500,
                "result_detail": "full"
            }),
        ),
        query(
            "union minuend except",
            json!({
                "schema_version": 1,
                "except": [
                    { "union": [
                        {
                            "match": { "kind": "function", "name": { "regex": "^fn[0-9]$" } },
                            "steps": [{ "op": "filter", "where": [{ "field": "name", "op": "is_not_null" }] }]
                        },
                        { "match": { "kind": "function" } }
                    ] },
                    { "match": { "kind": "function", "name": { "regex": "^fn0$" } } }
                ],
                "limit": 500,
                "result_detail": "full"
            }),
        ),
        query(
            "empty union minuend except",
            json!({
                "schema_version": 1,
                "except": [
                    { "union": [
                        { "match": { "kind": "function", "name": { "regex": "^absent$" } } },
                        { "match": { "kind": "function", "name": { "regex": "^fn0$" } } }
                    ] },
                    { "match": { "kind": "function" } }
                ],
                "limit": 500,
                "result_detail": "full"
            }),
        ),
        query(
            "mixed root union",
            json!({
                "schema_version": 1,
                "union": [
                    { "except": [
                        { "match": { "kind": "function" } },
                        { "match": { "kind": "function", "name": { "regex": "^fn0$" } } }
                    ] },
                    { "except": [
                        { "union": [
                            { "match": { "kind": "function", "name": { "regex": "^fn[0-9]$" } } },
                            { "match": { "kind": "function" } }
                        ] },
                        { "match": { "kind": "function", "name": { "regex": "^absent$" } } }
                    ] }
                ],
                "limit": 500,
                "result_detail": "full"
            }),
        ),
        query(
            "occurrence seed",
            json!({
                "schema_version": 1,
                "occurrences": { "class": "reference" },
                "limit": 500,
                "result_detail": "full"
            }),
        ),
    ];
    for (label, source) in [
        (
            "depth one",
            "(callees :depth 1 (enclosing-decl (function)))",
        ),
        (
            "depth two",
            "(callees :depth 2 (enclosing-decl (function)))",
        ),
        (
            "erased depth answer",
            "(filter :where ((fq_name regex \"^never/\")) (callees :depth 1 (enclosing-decl (function))))",
        ),
    ] {
        let mut parsed = CodeQuery::from_sexp(source).unwrap();
        parsed.limit = 500;
        plans.push((label, parsed));
    }
    plans
}

/// The rendered rows, with the one coordinate a merge cannot reproduce removed
/// from every row nested inside another row.
///
/// A row's own `node_range` is compared. A `node_range` on a declaration
/// nested inside a row -- a resolved reference target, a provenance value --
/// is not, because the executor fills it only when some row of the same
/// execution already retained that file's source
/// (`PipelineRenderCache::seal_source_loads`). A unit scoped to one seed file
/// retains one file, so it cannot publish a coordinate for a declaration
/// elsewhere that a whole execution publishes opportunistically. The
/// deterministic case is pinned by
/// `units::a_nested_reference_target_renders_the_same_detail_in_a_unit_and_a_whole_run`,
/// which is ignored until that public `query_code` output question is decided.
fn comparable_rendering(items: &[UnitRowItem]) -> String {
    let mut value = serde_json::to_value(items).expect("projected rows serialize");
    // A projected row states its own display region as `range`, so every
    // `node_range` in the value tree belongs to a provenance reference and is
    // exactly the opportunistic coordinate this normalization removes.
    strip_nested_node_ranges(&mut value);
    serde_json::to_string(&value).expect("normalized rows serialize")
}

fn canonical_rows(
    items: &[UnitRowItem],
    evidence: &[DetailedCodeQueryEvidence],
) -> Vec<(String, DetailedCodeQueryEvidence)> {
    canonical_rows_with(items, evidence, |item| {
        comparable_rendering(std::slice::from_ref(item))
    })
}

/// New set-minuend controls compare every rendered field, including nested
/// coordinates. Only result indices are neutralized because cross-file order
/// is explicitly outside the result contract.
fn exact_rows(
    items: &[UnitRowItem],
    evidence: &[DetailedCodeQueryEvidence],
) -> Vec<(String, DetailedCodeQueryEvidence)> {
    canonical_rows_with(items, evidence, |item| {
        serde_json::to_string(item).expect("rendered item serializes")
    })
}

fn canonical_rows_with(
    items: &[UnitRowItem],
    evidence: &[DetailedCodeQueryEvidence],
    render: impl Fn(&UnitRowItem) -> String,
) -> Vec<(String, DetailedCodeQueryEvidence)> {
    let mut rows = items
        .iter()
        .zip(evidence)
        .map(|(item, proof)| {
            let mut proof = proof.clone();
            proof.result_index = 0; // The cross-file result order is not a contract.
            (render(item), proof)
        })
        .collect::<Vec<_>>();
    assert_eq!(items.len(), evidence.len(), "every row has evidence");
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    rows
}

/// Remove every `node_range` from one rendered value, iteratively: a rendered
/// row nests arbitrarily and a recursive walk over untrusted depth is what the
/// repository's traversal rule forbids.
fn strip_nested_node_ranges(value: &mut serde_json::Value) {
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            serde_json::Value::Object(fields) => {
                fields.remove("node_range");
                pending.extend(fields.values_mut());
            }
            serde_json::Value::Array(items) => pending.extend(items.iter_mut()),
            _ => {}
        }
    }
}

/// Assert the whole execution stayed under every cumulative cap, so its rows
/// are the complete answer the merge is compared against.
fn assert_no_cap_was_reached(
    label: &str,
    detailed: &DetailedCodeQueryResult,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
) -> Result<(), TestCaseError> {
    prop_assert!(
        !detailed.result.truncated,
        "{label}: the whole execution must not truncate"
    );
    prop_assert!(
        detailed.result.results.len() < query.limit,
        "{label}: limit"
    );
    prop_assert!(
        detailed.work.scanned_files < limits.max_scanned_files as u64,
        "{label}: max_scanned_files"
    );
    prop_assert!(
        detailed.work.scanned_source_bytes < limits.max_scanned_source_bytes as u64,
        "{label}: max_scanned_source_bytes"
    );
    prop_assert!(
        detailed.work.fact_nodes + detailed.work.examined_references < limits.max_fact_nodes as u64,
        "{label}: max_fact_nodes"
    );
    prop_assert!(
        detailed.work.pipeline_rows + detailed.budgeted_work.provenance_steps
            < limits.max_pipeline_rows as u64,
        "{label}: max_pipeline_rows"
    );
    // The final step's cap is the root limit, every earlier step's is
    // `max_pipeline_rows`, and the root limit is the smaller here.
    prop_assert!(
        detailed.budgeted_work.max_step_outputs()
            < query.limit.min(limits.max_pipeline_rows) as u64,
        "{label}: max_step_outputs"
    );
    Ok(())
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "69e0507ebf4b: legacy Unknown caller inventory must remain unknown across moved seeds"
)]
fn legacy_caller_inventory_keeps_merged_membership_unknown() {
    let generated = GeneratedProject {
        functions_per_file: vec![1, 2, 1, 2, 2, 1, 2, 2, 1, 1],
        call_targets: vec![
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(8),
            None,
            Some(1),
            Some(4),
            Some(9),
            Some(4),
            Some(0),
            None,
        ],
    };
    for move_seeds in [false, true] {
        let mut layout = generated.clone();
        if move_seeds {
            layout.functions_per_file.reverse();
        }
        let project = layout.build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let query = CodeQuery::from_sexp("(callers :depth 1 (enclosing-decl (function)))").unwrap();
        let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
        let whole = execute_code_query_detailed_eager_index(
            workspace.analyzer(),
            &flow,
            &query,
            CodeQueryExecutionLimits::default(),
            None,
        );
        assert_eq!(
            whole.result.depth_bound_status,
            Some(DepthBoundStatus::Unknown)
        );
        let mut files = workspace.analyzer().analyzed_files();
        files.sort_by(seed_file_order);
        let products = files
            .iter()
            .map(|file| {
                execute_code_query_unit(
                    workspace.analyzer(),
                    &flow,
                    None,
                    &query,
                    CodeQueryExecutionLimits::default(),
                    None,
                    CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(file), &files),
                )
            })
            .collect::<Vec<_>>();
        for reverse in [false, true] {
            let mut ordered = products.clone();
            if reverse {
                ordered.reverse();
            }
            assert_eq!(
                merge_unit_rows(&query, ordered).depth_bound_status,
                whole.result.depth_bound_status,
                "moved={move_seeds}, reversed={reverse}"
            );
        }
    }
}

proptest! {
    // Two cases: each builds a workspace analyzer over up to ten files and
    // runs whole and seed-scoped executions for the partitionable plan family.
    // Seed allocation varies with functions_per_file; merges also vary unit order. The nightly
    // property-stress job cranks PROPTEST_CASES.
    #![proptest_config(ProptestConfig::with_cases(2))]

    #[test]
    fn merging_one_execution_per_seed_file_equals_one_whole_execution(
        generated in generated_project(),
    ) {
        let project = generated.build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let limits = CodeQueryExecutionLimits::default();
        let mut files = workspace.analyzer().analyzed_files();
        files.sort_by(seed_file_order);
        prop_assert!(files.len() >= MIN_FILES, "the fixture keeps the indexed path viable");

        for (label, query) in partitioned_plans() {
            let whole = execute_code_query_detailed_eager_index(
                workspace.analyzer(),
    &brokk_bifrost_flow::FlowWorkspaceState::default(),
                &query,
                limits,
                None,
            );
            assert_no_cap_was_reached(label, &whole, &query, limits)?;

            let units = files
                .iter()
                .map(|file| {
                    execute_code_query_unit(
                        workspace.analyzer(),
    &brokk_bifrost_flow::FlowWorkspaceState::default(),
                        None,
                        &query,
                        limits,
                        None,
                        CodeQueryExecutionScope::for_seed_files(
                            std::slice::from_ref(file),
                            &files,
                        ),
                    )
                })
                .collect::<Vec<_>>();
            for reversed in [false, true] {
                let mut ordered = units.clone();
                if reversed { ordered.reverse(); }
                let status = merge_unit_rows(&query, ordered).depth_bound_status;
                prop_assert_eq!(status, whole.result.depth_bound_status, "{}: depth status reversed={}", label, reversed);
            }
            if units.len() > 1 {
                let mut rotated = units.clone();
                rotated.rotate_left(1);
                prop_assert_eq!(merge_unit_rows(&query, rotated).depth_bound_status,
                    whole.result.depth_bound_status, "{}: rotated depth status", label);
            }
            let merged = merge_unit_rows(&query, units);
            if matches!(label, "union minuend except" | "mixed root union") {
                let divisor = PlanPartitioning::fair_share_divisor(&query.plan)
                    .expect("the accepted set has a fair-share divisor");
                prop_assert_eq!(
                    divisor,
                    if label == "mixed root union" { 8 } else { 4 },
                    "{}: maximal nested fair share",
                    label
                );
                let spent = merged.work.scanned_files
                    + merged.budgeted_work.import_files_resolved;
                let threshold = usize::try_from(spent).unwrap() * divisor;
                let mut at_boundary = limits;
                at_boundary.max_scanned_files = threshold;
                prop_assert_eq!(
                    merged.reached_limit(&at_boundary, query.limit),
                    Some(MergedLimit::ScannedFiles),
                    "{}: equality at the fair-share cap widens",
                    label
                );
                let mut below_boundary = limits;
                below_boundary.max_scanned_files = threshold + divisor;
                prop_assert_eq!(
                    merged.reached_limit(&below_boundary, query.limit),
                    None,
                    "{}: one more scanned-file share leaves headroom",
                    label
                );
                if !merged.items.is_empty() {
                    prop_assert_eq!(
                        merged.reached_limit(&limits, merged.items.len()),
                        Some(MergedLimit::ResultLimit),
                        "{}: the root cap applies after the merge",
                        label
                    );
                }
            }

            let merged_evidence = merged.detailed_evidence(project.root());
            let whole_items = whole.result.results.iter().map(UnitRowItem::project).collect::<Vec<_>>();
            let compare = if matches!(
                label,
                "union minuend except" | "empty union minuend except" | "mixed root union"
            ) {
                exact_rows
            } else {
                canonical_rows
            };
            let merged_bytes = compare(&merged.items, &merged_evidence);
            let whole_bytes = compare(&whole_items, &whole.evidence);
            prop_assert_eq!(
                &merged_bytes,
                &whole_bytes,
                "{}: each keyed row and its evidence must match the whole execution",
                label
            );
            if label == "mixed root union" {
                prop_assert_eq!(merged.truncated, whole.result.truncated, "{}: truncation", label);
                prop_assert_eq!(
                    merged.items.iter().map(|item| serde_json::to_value(item).unwrap()).collect::<Vec<_>>(),
                    whole_items.iter().map(|item| serde_json::to_value(item).unwrap()).collect::<Vec<_>>(),
                    "{}: ordered full native payloads",
                    label
                );
                let mut actual_evidence = merged_evidence.clone();
                let mut expected_evidence = whole.evidence.clone();
                for evidence in &mut actual_evidence { evidence.result_index = 0; }
                for evidence in &mut expected_evidence { evidence.result_index = 0; }
                prop_assert_eq!(actual_evidence, expected_evidence, "{}: ordered evidence", label);
                prop_assert_eq!(&merged.diagnostics, &whole.result.diagnostics, "{}: diagnostics", label);
            }
            prop_assert_eq!(
                merged.completion(),
                whole.result.completion(),
                "{}: completion",
                label
            );

            // A merge concatenates its units' diagnostics, so a diagnostic
            // one execution states once appears once per unit that stated it.
            // What must agree is which diagnostics were stated: that set is
            // what completion is derived from, and any diagnostic at all
            // widens the policy to a whole evaluation anyway.
            //
            // BroadQuery is excluded and is the one diagnostic that cannot
            // agree. It is a cost advisory whose message is a rendering of the
            // execution's own scan counters, raised when one unanchored
            // execution scanned at least
            // BROAD_QUERY_SCANNED_FILE_HINT_THRESHOLD files; a unit scoped to
            // one seed file never scans that much, and even a synthesized
            // merged advisory would carry the summed counters rather than the
            // whole run's. What it advises about is the cost of a query, not
            // the meaning of its rows. The example test
            // `a_broad_query_advises_on_the_execution_that_paid_for_it` pins
            // the divergence, and the policy layer must decide whether the
            // report's equivalence contract excludes it the way it already
            // excludes the per-run work counters.
            let distinct = |diagnostics: &[CodeQueryDiagnostic]| {
                let mut rendered: Vec<String> = diagnostics
                    .iter()
                    .filter(|diagnostic| diagnostic.code != CodeQueryDiagnosticCode::BroadQuery)
                    .map(|diagnostic| {
                        format!(
                            "{:?}/{:?}/{}",
                            diagnostic.code, diagnostic.impact, diagnostic.message
                        )
                    })
                    .collect();
                rendered.sort();
                rendered.dedup();
                rendered
            };
            prop_assert_eq!(
                distinct(&merged.diagnostics),
                distinct(&whole.result.diagnostics),
                "{}: diagnostics",
                label
            );

            prop_assert!(merged.work.scanned_files >= whole.work.scanned_files, "{}: scanned_files", label);
            prop_assert!(
                merged.work.scanned_source_bytes >= whole.work.scanned_source_bytes,
                "{}: scanned_source_bytes",
                label
            );
            prop_assert!(merged.work.fact_nodes >= whole.work.fact_nodes, "{}: fact_nodes", label);
            prop_assert!(
                merged.work.pipeline_rows >= whole.work.pipeline_rows,
                "{}: pipeline_rows",
                label
            );
            prop_assert!(
                merged.work.examined_references >= whole.work.examined_references,
                "{}: examined_references",
                label
            );
            prop_assert!(
                merged.budgeted_work.provenance_steps >= whole.budgeted_work.provenance_steps,
                "{}: provenance_steps",
                label
            );
            prop_assert!(
                merged.budgeted_work.import_files_resolved
                    >= whole.budgeted_work.import_files_resolved,
                "{}: import_files_resolved",
                label
            );
            prop_assert!(
                merged.budgeted_work.import_edges_resolved
                    >= whole.budgeted_work.import_edges_resolved,
                "{}: import_edges_resolved",
                label
            );
            for (index, outputs) in whole.budgeted_work.step_outputs.iter().enumerate() {
                prop_assert!(
                    merged.budgeted_work.step_outputs[index] >= *outputs,
                    "{}: step {} outputs",
                    label,
                    index
                );
            }
        }
    }
}

#[test]
fn set_minuend_except_preserves_distinct_native_fields_per_key() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("a.py", "print('a')\n")
        .file("b.py", "print('b')\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let limits = CodeQueryExecutionLimits::default();
    let named = "(project :columns ((name x)) (language python (call)))";
    let literal = "(project :columns ((string_value x)) (language python (call)))";
    let subtract = "(project :columns ((name x)) (language python (call :name \"absent\")))";
    for (first, second, expected) in [(named, literal, Some("print")), (literal, named, None)] {
        let query = CodeQuery::from_sexp(&format!(
            "(result-detail full (except (union {first} {second}) {subtract}))"
        ))
        .expect("the projected set has a compatible schema");
        assert_eq!(
            PlanPartitioning::classify(&query.plan),
            PlanPartitioning::BySeedExcept
        );
        let whole = execute_code_query_detailed_eager_index(
            workspace.analyzer(),
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            &query,
            limits,
            None,
        );
        let files = crate::structural::search::units::plan_seed_files(
            &query.plan,
            &workspace.analyzer().analyzed_files(),
        );
        let units = files
            .iter()
            .map(|file| {
                execute_code_query_unit(
                    workspace.analyzer(),
                    &brokk_bifrost_flow::FlowWorkspaceState::default(),
                    None,
                    &query,
                    limits,
                    None,
                    CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(file), &files),
                )
            })
            .collect::<Vec<_>>();
        let merged = merge_unit_rows(&query, units);
        assert_eq!(merged.completion(), whole.result.completion());
        let whole_items = whole
            .result
            .results
            .iter()
            .map(UnitRowItem::project)
            .collect::<Vec<_>>();
        assert_eq!(
            exact_rows(&merged.items, &merged.detailed_evidence(project.root())),
            exact_rows(&whole_items, &whole.evidence),
            "whole and per-file items, fields, provenance, and evidence"
        );
        assert_eq!(merged.items.len(), 2);
        for item in &merged.items {
            let actual = item.field("x").expect("the projected alias exists");
            match expected {
                Some(expected) => assert!(
                    matches!(actual, Some(CodeQueryRowScalarRef::String(value)) if value == expected)
                ),
                None => assert!(actual.is_none(), "{actual:#?}"),
            }
        }
    }
}

#[test]
fn root_union_of_excepts_keeps_first_native_payload_and_both_paths() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("a.py", "print('a')\n")
        .file("b.py", "print('b')\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_sexp(
        "(result-detail full (union
            (except
              (project :columns ((name x)) (language python (call)))
              (project :columns ((name x)) (language python (call :name \"absent\"))))
            (except
              (project :columns ((string_value x)) (language python (call)))
              (project :columns ((string_value x)) (language python (call :name \"absent\"))))))",
    )
    .expect("mixed root set parses");
    assert_eq!(
        PlanPartitioning::classify(&query.plan),
        PlanPartitioning::BySeedSetUnion
    );
    let limits = CodeQueryExecutionLimits::default();
    let whole = execute_code_query_detailed_eager_index(
        workspace.analyzer(),
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        &query,
        limits,
        None,
    );
    let files = crate::structural::search::units::plan_seed_files(
        &query.plan,
        &workspace.analyzer().analyzed_files(),
    );
    let units = files.iter().map(|file| {
        execute_code_query_unit(
            workspace.analyzer(),
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            None,
            &query,
            limits,
            None,
            CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(file), &files),
        )
    });
    let merged = merge_unit_rows(&query, units);
    assert_eq!(merged.completion(), whole.result.completion());
    assert_eq!(merged.diagnostics, whole.result.diagnostics);
    let whole_items = whole
        .result
        .results
        .iter()
        .map(UnitRowItem::project)
        .collect::<Vec<_>>();
    assert_eq!(merged.items, whole_items, "ordered native rows and traces");
    let mut merged_evidence = merged.detailed_evidence(project.root());
    let mut whole_evidence = whole.evidence;
    for evidence in &mut merged_evidence {
        evidence.result_index = 0;
    }
    for evidence in &mut whole_evidence {
        evidence.result_index = 0;
    }
    assert_eq!(merged_evidence, whole_evidence, "ordered evidence");
    for row in &merged.items {
        assert!(
            row.provenance
                .iter()
                .any(|trace| trace.branch.first() == Some(&0))
        );
        assert!(
            row.provenance
                .iter()
                .any(|trace| trace.branch.first() == Some(&1))
        );
        assert!(
            matches!(row.field("x"), Ok(Some(CodeQueryRowScalarRef::String(value))) if value == "print")
        );
    }
}

#[test]
fn root_union_enumerates_subtrahend_only_empty_minuend_files() {
    let project = InlineTestProject::new()
        .file("a.ts", "export function keep() { return 1; }\n")
        .file("b.py", "def remove():\n    pass\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_sexp(
        "(result-detail full (union
            (except
              (language typescript (function :name \"keep\"))
              (language python (function)))
            (except
              (language typescript (function :name \"absent\"))
              (language python (function)))))",
    )
    .expect("mixed set parses");
    assert_eq!(
        PlanPartitioning::classify(&query.plan),
        PlanPartitioning::BySeedSetUnion
    );
    let files = crate::structural::search::units::plan_seed_files(
        &query.plan,
        &workspace.analyzer().analyzed_files(),
    );
    assert_eq!(files.len(), 2, "subtrahend-only b.py must be enumerated");
    assert!(
        files
            .iter()
            .any(|file| file.rel_path().to_str() == Some("b.py"))
    );
    let limits = CodeQueryExecutionLimits::default();
    let whole = execute_code_query_detailed_eager_index(
        workspace.analyzer(),
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        &query,
        limits,
        None,
    );
    let units = files
        .iter()
        .map(|file| {
            execute_code_query_unit(
                workspace.analyzer(),
                &brokk_bifrost_flow::FlowWorkspaceState::default(),
                None,
                &query,
                limits,
                None,
                CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(file), &files),
            )
        })
        .collect::<Vec<_>>();
    let python_unit = files
        .iter()
        .position(|file| file.rel_path().to_str() == Some("b.py"))
        .expect("Python subtrahend seed is selected");
    assert!(units[python_unit].rows.is_empty());
    assert!(units[python_unit].work.scanned_files > 0);
    let merged = merge_unit_rows(&query, units);
    let whole_items = whole
        .result
        .results
        .iter()
        .map(UnitRowItem::project)
        .collect::<Vec<_>>();
    assert_eq!(merged.items, whole_items);
    let mut merged_evidence = merged.detailed_evidence(project.root());
    let mut whole_evidence = whole.evidence;
    for evidence in &mut merged_evidence {
        evidence.result_index = 0;
    }
    for evidence in &mut whole_evidence {
        evidence.result_index = 0;
    }
    assert_eq!(merged_evidence, whole_evidence);
    assert_eq!(merged.completion(), whole.result.completion());
    assert_eq!(merged.diagnostics, whole.result.diagnostics);
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#8389: an empty per-file intersect operand skipped a later branch's work and gap"
)]
fn intersect_minuends_keep_the_whole_execution_and_late_budget_gap() {
    let mut heavy = String::new();
    for index in 0..64 {
        heavy.push_str(&format!(
            "export function other{index}() {{ return {index}; }}\n"
        ));
    }
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("f.ts", &heavy)
        .file("g.ts", "export function target() { return 1; }\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
    let a = json!({"match": {"kind": "function", "name": {"regex": "^target$"}}});
    let b = json!({"match": {"kind": "function"}});
    let c = json!({"match": {"kind": "function", "name": {"regex": "^absent$"}}});
    let a_query = CodeQuery::from_json(&a).expect("A parses");
    let b_query = CodeQuery::from_json(&b).expect("B parses");
    let files = workspace.analyzer().analyzed_files();
    let f = files
        .iter()
        .find(|file| file.rel_path().to_str() == Some("f.ts"))
        .unwrap();
    let g = files
        .iter()
        .find(|file| file.rel_path().to_str() == Some("g.ts"))
        .unwrap();
    let run_leaf = |query: &CodeQuery, file: &ProjectFile, limits| {
        execute_code_query_unit(
            workspace.analyzer(),
            &flow,
            None,
            query,
            limits,
            None,
            CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(file), &files),
        )
    };
    let unlimited = CodeQueryExecutionLimits::default();
    let a_f = run_leaf(&a_query, f, unlimited);
    let a_g = run_leaf(&a_query, g, unlimited);
    let b_f = run_leaf(&b_query, f, unlimited);
    let b_g = run_leaf(&b_query, g, unlimited);
    assert!(a_f.rows.is_empty());
    assert_eq!(a_f.completion, CodeQueryCompletion::Complete);
    assert_eq!(a_g.rows.len(), 1);
    assert_eq!(b_f.rows.len(), 64);
    assert_eq!(b_g.rows.len(), 1);
    let late_b = run_leaf(
        &b_query,
        f,
        CodeQueryExecutionLimits {
            max_pipeline_rows: 16,
            ..unlimited
        },
    );
    assert!(late_b.truncated);
    assert!(late_b.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == CodeQueryDiagnosticCode::PipelineBudgetExhausted
            || diagnostic.code == CodeQueryDiagnosticCode::ExecutionBudgetExhausted
    }));
    let cases = [
        (
            "root",
            json!({"intersect": [a.clone(), b.clone()]}),
            c.clone(),
            true,
        ),
        (
            "nested",
            json!({"union": [
                {"intersect": [a.clone(), b.clone()]}, a.clone()
            ]}),
            c.clone(),
            true,
        ),
        (
            "subtrahend",
            json!({"union": [a.clone(), a.clone()]}),
            json!({"intersect": [a.clone(), b.clone()]}),
            true,
        ),
        (
            "globally empty",
            json!({"intersect": [c.clone(), b.clone()]}),
            a.clone(),
            false,
        ),
    ];
    for (label, minuend, subtrahend, should_gap) in cases {
        let query = CodeQuery::from_json(&json!({
            "schema_version": 1,
            "except": [minuend, subtrahend],
            "limit": 500,
            "result_detail": "full"
        }))
        .expect("intersect control parses");
        assert_eq!(
            PlanPartitioning::classify(&query.plan),
            PlanPartitioning::Whole(crate::PlanWidenDetail::ExceptNonLeafMinuend)
        );
        for limits in [
            CodeQueryExecutionLimits::default(),
            CodeQueryExecutionLimits {
                max_pipeline_rows: 16,
                ..CodeQueryExecutionLimits::default()
            },
        ] {
            let whole = execute_code_query_detailed_eager_index(
                workspace.analyzer(),
                &flow,
                &query,
                limits,
                None,
            );
            let unit = execute_code_query_unit(
                workspace.analyzer(),
                &flow,
                None,
                &query,
                limits,
                None,
                CodeQueryExecutionScope::whole_workspace(),
            );
            let capped = limits.max_pipeline_rows == 16;
            if capped && should_gap {
                assert!(
                    whole.result.truncated,
                    "{label}: {:?}",
                    whole.result.diagnostics
                );
                assert!(
                    whole.result.diagnostics.iter().any(|diagnostic| {
                        diagnostic.code == CodeQueryDiagnosticCode::PipelineBudgetExhausted
                            || diagnostic.code == CodeQueryDiagnosticCode::ExecutionBudgetExhausted
                    }),
                    "{label}: {:?}",
                    whole.result.diagnostics
                );
            }
            if capped && !should_gap {
                assert!(!whole.result.truncated, "{label}: globally empty A skips B");
            }
            assert_eq!(unit.completion, whole.result.completion(), "{label}");
            assert_eq!(unit.work, whole.work, "{label}");
            assert_eq!(unit.diagnostics, whole.result.diagnostics, "{label}");
            let merged = merge_unit_rows(&query, vec![unit]);
            let whole_items = whole
                .result
                .results
                .iter()
                .map(UnitRowItem::project)
                .collect::<Vec<_>>();
            assert_eq!(
                exact_rows(&merged.items, &merged.detailed_evidence(project.root())),
                exact_rows(&whole_items, &whole.evidence),
                "{label}"
            );
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2))]

    /// Capped import unions return correct subsets with reported truncation.
    #[test]
    fn capped_import_union_merge_returns_a_correct_subset(
        generated in generated_project(),
        eighths in proptest::array::uniform4(1usize..=24),
    ) {
        let project = generated.build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
        let mut files = workspace.analyzer().analyzed_files();
        files.sort_by(seed_file_order);
        let scan = json!({"match": {"kind": "function"}});
        let absent = json!({"languages": ["python"], "match": {"kind": "function"}});
        let mut exercised_imports = false;
        for op in ["imports_of", "importers_of"] {
            let importing = json!({"match": {"kind": "function"},
                "steps": [{"op": "file_of"}, {"op": op}]});
            for branches in [
                vec![importing.clone(), scan.clone()],
                vec![scan.clone(), importing.clone()],
                vec![absent.clone(), importing.clone(), scan.clone()],
            ] {
                let query = CodeQuery::from_json(&json!({
                    "schema_version": 1, "union": branches,
                    "limit": 500, "result_detail": "full",
                })).expect("import union parses");
                prop_assert!(crate::PlanPartitioning::classify(&query.plan).is_seed_union(),
                    "{}", op);
                let units: Vec<_> = files.iter().map(|file| execute_code_query_unit(
                    workspace.analyzer(), &flow, None, &query,
                    CodeQueryExecutionLimits::default(), None,
                    CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(file), &files),
                )).collect();
                let merged = merge_unit_rows(&query, units);
                exercised_imports |= merged.budgeted_work.import_files_resolved > 0
                    || merged.budgeted_work.import_edges_resolved > 0;
                let whole = execute_code_query_detailed_eager_index(
                    workspace.analyzer(), &flow, &query, CodeQueryExecutionLimits::default(), None,
                );
                prop_assert!(!whole.result.truncated);
                let complete = whole.result.results.iter().map(UnitRowItem::project).collect::<Vec<_>>();
                let totals = [
                    merged.work.scanned_files + merged.budgeted_work.import_files_resolved,
                    merged.work.scanned_source_bytes,
                    merged.work.fact_nodes + merged.work.examined_references,
                    merged.work.pipeline_rows + merged.budgeted_work.provenance_steps
                        + merged.budgeted_work.import_edges_resolved,
                ];
                for (lane, total) in totals.into_iter().enumerate() {
                    let cap = (total as usize * eighths[lane] / 8).max(1);
                    let mut limits = CodeQueryExecutionLimits::default();
                    match lane {
                        0 => limits.max_scanned_files = cap,
                        1 => limits.max_scanned_source_bytes = cap,
                        2 => limits.max_fact_nodes = cap,
                        3 => limits.max_pipeline_rows = cap,
                        _ => unreachable!(),
                    }
                    let capped_units = files.iter().map(|file| execute_code_query_unit(
                        workspace.analyzer(), &flow, None, &query, limits, None,
                        CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(file), &files),
                    ));
                    let mut capped = merge_unit_rows(&query, capped_units);
                    capped.apply_result_limit(query.limit);
                    prop_assert!(capped.items.iter().all(|row| complete.iter().any(|candidate| { let mut row = row.clone(); let mut candidate = candidate.clone(); row.provenance.clear(); candidate.provenance.clear(); row == candidate })), "{}: lane {}, cap {}", op, lane, cap);
                    if !capped.truncated {
                        prop_assert_eq!(comparable_rendering(&capped.items), comparable_rendering(&complete));
                    } else {
                        prop_assert!(!capped.diagnostics.is_empty());
                    }
                }
            }
        }
        // Resolving the import graph charges work even when a generated file
        // has no outgoing imports; keep the property from becoming vacuous.
        prop_assert!(exercised_imports, "import resolution must be exercised");
    }
}
