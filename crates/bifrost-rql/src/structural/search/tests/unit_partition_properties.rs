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
use crate::structural::search::units::{
    CodeQueryExecutionScope, execute_code_query_unit, merge_unit_rows, seed_file_order,
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
/// structural plan, a row-local step, a derived-value step, and a
/// non-structural seed family.
fn partitioned_plans() -> Vec<(&'static str, CodeQuery)> {
    let query = |label: &'static str, value: serde_json::Value| {
        (
            label,
            CodeQuery::from_json(&value).expect("property query should parse"),
        )
    };
    vec![
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
            "occurrence seed",
            json!({
                "schema_version": 1,
                "occurrences": { "class": "reference" },
                "limit": 500,
                "result_detail": "full"
            }),
        ),
    ]
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

proptest! {
    // Two cases: each builds a workspace analyzer over up to ten files and
    // runs one whole execution plus one execution per seed file for four
    // plans, which is about forty executions per case. The nightly
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
            let merged = merge_unit_rows(units);

            let merged_bytes = comparable_rendering(&merged.items);
            let whole_bytes = comparable_rendering(
                &whole
                    .result
                    .results
                    .iter()
                    .map(UnitRowItem::project)
                    .collect::<Vec<_>>(),
            );
            prop_assert_eq!(
                &merged_bytes,
                &whole_bytes,
                "{}: merged rows must serialize byte for byte as the whole execution's",
                label
            );
            prop_assert_eq!(
                merged.detailed_evidence(project.root()),
                whole.evidence,
                "{}: evidence must match row for row",
                label
            );
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
