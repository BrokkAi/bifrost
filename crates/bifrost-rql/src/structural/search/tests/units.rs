use super::inline_project::BuiltInlineTestProject;
use super::*;
use crate::structural::search::units::{
    CodeQueryExecutionScope, MergedUnitRows, UnitExecutionResult, execute_code_query_unit,
    merge_unit_rows, seed_file_order,
};

/// Eight files so the whole execution clears the auto structural-index
/// admission rule (`MIN_AUTO_STRUCTURAL_INDEX_FILES`), which a one-file unit
/// never can: the two access paths must agree on the match set.
fn eight_file_project() -> BuiltInlineTestProject {
    let mut project = InlineTestProject::with_language(Language::TypeScript);
    for index in 0..8 {
        project = project.file(
            format!("src/mod{index}.ts"),
            format!(
                "export function target{index}() {{\n  return {index};\n}}\n\
                 export function caller{index}() {{\n  return target{index}();\n}}\n"
            ),
        );
    }
    project.build()
}

fn function_query() -> CodeQuery {
    CodeQuery::from_json(&json!({
        "schema_version": 1,
        "match": { "kind": "function" },
        "limit": 500,
        "result_detail": "full"
    }))
    .expect("structural function query")
}

fn occurrence_query() -> CodeQuery {
    CodeQuery::from_json(&json!({
        "schema_version": 1,
        "occurrences": { "class": "reference" },
        "limit": 500,
        "result_detail": "full"
    }))
    .expect("occurrence seed query")
}

fn callers_query() -> CodeQuery {
    CodeQuery::from_json(&json!({
        "schema_version": 1,
        "match": { "kind": "function", "name": { "regex": "^target" } },
        "steps": [{ "op": "enclosing_decl" }, { "op": "callers" }],
        "limit": 100,
        "result_detail": "full"
    }))
    .expect("callers query")
}

/// The whole execution's rows in the projection a unit product carries.
///
/// A unit merges projected rows, not rendered ones, so the partition property
/// compares what the merge actually produces against the same projection of
/// the whole run.
fn projected(items: &[CodeQueryResultItem]) -> Vec<UnitRowItem> {
    items.iter().map(UnitRowItem::project).collect()
}

fn whole_execution(workspace: &WorkspaceAnalyzer, query: &CodeQuery) -> DetailedCodeQueryResult {
    execute_code_query_detailed_eager_index(
        workspace.analyzer(),
        query,
        CodeQueryExecutionLimits::default(),
        None,
    )
}

fn units(
    workspace: &WorkspaceAnalyzer,
    query: &CodeQuery,
    seed_files: &[ProjectFile],
) -> Vec<UnitExecutionResult> {
    seed_files
        .iter()
        .map(|file| {
            execute_code_query_unit(
                workspace.analyzer(),
                None,
                query,
                CodeQueryExecutionLimits::default(),
                None,
                CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(file), seed_files),
            )
        })
        .collect()
}

fn merged(
    workspace: &WorkspaceAnalyzer,
    query: &CodeQuery,
    seed_files: &[ProjectFile],
) -> MergedUnitRows {
    merge_unit_rows(units(workspace, query, seed_files))
}

fn seed_files_of(workspace: &WorkspaceAnalyzer) -> Vec<ProjectFile> {
    let mut files = workspace.analyzer().analyzed_files();
    files.sort_by(seed_file_order);
    files
}

#[test]
fn merged_structural_units_reproduce_the_whole_execution() {
    let project = eight_file_project();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let files = seed_files_of(&workspace);
    let query = function_query();

    let whole = whole_execution(&workspace, &query);
    assert!(!whole.result.results.is_empty());

    let merged = merged(&workspace, &query, &files);
    assert_eq!(merged.items, projected(&whole.result.results));
    assert_eq!(
        merged.detailed_evidence(project.root()),
        whole.evidence,
        "the evidence projection rebuilds the executor's own evidence"
    );
    assert_eq!(merged.completion(), whole.result.completion());
}

#[test]
fn merged_occurrence_units_reproduce_the_whole_execution() {
    let project = eight_file_project();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let files = seed_files_of(&workspace);
    let query = occurrence_query();

    let whole = whole_execution(&workspace, &query);
    assert!(!whole.result.results.is_empty());

    let merged = merged(&workspace, &query, &files);
    assert_eq!(merged.items, projected(&whole.result.results));
    assert_eq!(merged.detailed_evidence(project.root()), whole.evidence);
}

#[test]
fn a_row_two_seed_files_reach_keeps_the_first_row_and_folds_both_traces() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("src/a.ts", "export function targetA() {\n  return 1;\n}\n")
        .file("src/b.ts", "export function targetB() {\n  return 2;\n}\n")
        .file(
            "src/caller.ts",
            "import { targetA } from './a';\nimport { targetB } from './b';\n\
             export function caller() {\n  return targetA() + targetB();\n}\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let files = seed_files_of(&workspace);
    let query = callers_query();

    let whole = whole_execution(&workspace, &query);
    assert_eq!(
        whole.result.results.len(),
        1,
        "both seeds reach the one caller, which the pipeline deduplicates"
    );
    assert_eq!(
        whole.result.results[0].provenance.len(),
        2,
        "the surviving row keeps a trace for each seed that reached it"
    );

    let merged = merged(&workspace, &query, &files);
    assert_eq!(merged.items, projected(&whole.result.results));
    assert_eq!(merged.detailed_evidence(project.root()), whole.evidence);
}

#[test]
fn a_unit_still_expands_a_derived_value_over_the_whole_workspace() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/callee.ts",
            "export function target() {\n  return 1;\n}\n",
        )
        .file(
            "src/caller.ts",
            "import { target } from './callee';\nexport function caller() {\n  return target();\n}\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let callee = project.file("src/callee.ts");
    let files = seed_files_of(&workspace);

    let unit = execute_code_query_unit(
        workspace.analyzer(),
        None,
        &callers_query(),
        CodeQueryExecutionLimits::default(),
        None,
        CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(&callee), &files),
    );

    let callers: Vec<String> = unit
        .rows
        .iter()
        .map(|row| match &row.item.terminal {
            Some(UnitRowItemTerminal::Declaration { fq_name, .. }) => fq_name.to_string(),
            other => panic!("expected a declaration row, got {other:?}"),
        })
        .collect();
    assert_eq!(
        callers,
        vec!["caller".to_string()],
        "a unit seeded in one file still resolves callers in another"
    );
}

#[test]
fn a_seed_scope_outside_the_query_scope_yields_no_rows() {
    let project = eight_file_project();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let files = seed_files_of(&workspace);
    let query = CodeQuery::from_json(&json!({
        "schema_version": 1,
        "match": { "kind": "function" },
        "where": ["src/mod0.ts"],
        "limit": 500,
        "result_detail": "full"
    }))
    .expect("path-scoped structural query");

    let outside = project.file("src/mod3.ts");
    let unit = execute_code_query_unit(
        workspace.analyzer(),
        None,
        &query,
        CodeQueryExecutionLimits::default(),
        None,
        CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(&outside), &files),
    );
    assert!(
        unit.rows.is_empty(),
        "the seed scope narrows, it never widens the authored where-globs"
    );
}

#[test]
fn a_row_key_and_its_evidence_are_the_same_at_two_workspace_roots() {
    let sources = [
        (
            "src/callee.ts",
            "export function target() {\n  return 1;\n}\n",
        ),
        (
            "src/caller.ts",
            "import { target } from './callee';\nexport function caller() {\n  return target();\n}\n",
        ),
    ];
    let query = CodeQuery::from_json(&json!({
        "schema_version": 1,
        "match": { "kind": "function" },
        "steps": [{ "op": "enclosing_decl" }],
        "limit": 100,
        "result_detail": "full"
    }))
    .expect("declaration query");

    let rows_at_one_root = || {
        let mut project = InlineTestProject::with_language(Language::TypeScript);
        for (path, source) in sources {
            project = project.file(path, source);
        }
        let project = project.build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let files = seed_files_of(&workspace);
        let merged = merged(&workspace, &query, &files);
        let keys: Vec<_> = units(&workspace, &query, &files)
            .into_iter()
            .flat_map(|unit| unit.rows.into_iter().map(|row| row.key))
            .collect();
        (project.root().to_path_buf(), keys, merged.evidence)
    };

    let (first_root, first_keys, first_evidence) = rows_at_one_root();
    let (second_root, second_keys, second_evidence) = rows_at_one_root();

    assert_ne!(first_root, second_root, "the two projects have two roots");
    assert!(!first_keys.is_empty());
    assert_eq!(
        first_keys, second_keys,
        "a row key names workspace-relative and content-derived identities only"
    );
    assert_eq!(
        first_evidence, second_evidence,
        "an evidence projection carries no workspace root"
    );
}

#[test]
fn an_execution_exports_the_budgeted_lanes_its_public_work_drops() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/callee.ts",
            "export function target() {\n  return 1;\n}\n",
        )
        .file(
            "src/caller.ts",
            "import { target } from './callee';\nexport function caller() {\n  return target();\n}\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = callers_query();

    let unit = execute_code_query_unit(
        workspace.analyzer(),
        None,
        &query,
        CodeQueryExecutionLimits::default(),
        None,
        CodeQueryExecutionScope::whole_workspace(),
    );

    assert!(
        unit.budgeted_work.provenance_steps > 0,
        "a call-expansion step charges provenance steps against max_pipeline_rows"
    );
    assert_eq!(
        unit.budgeted_work.max_step_outputs(),
        u64::try_from(unit.rows.len()).expect("row count fits"),
        "the final step's output count is the row count it produced"
    );
    assert!(
        unit.budgeted_work.step_outputs.len() >= query.plan.steps.len(),
        "every plan operator has an entry, so every step has one"
    );
}

#[test]
fn an_execution_exports_the_import_lanes_it_charged() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/callee.ts",
            "export function target() {\n  return 1;\n}\n",
        )
        .file(
            "src/caller.ts",
            "import { target } from './callee';\nexport function caller() {\n  return target();\n}\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "schema_version": 1,
        "match": { "kind": "function", "name": "caller" },
        "steps": [{ "op": "file_of" }, { "op": "imports_of" }],
        "limit": 100,
        "result_detail": "full"
    }))
    .expect("imports query");

    let unit = execute_code_query_unit(
        workspace.analyzer(),
        None,
        &query,
        CodeQueryExecutionLimits::default(),
        None,
        CodeQueryExecutionScope::whole_workspace(),
    );

    assert!(
        !unit.rows.is_empty(),
        "the import traversal reaches the imported file"
    );
    assert!(
        unit.budgeted_work.import_files_resolved > 0,
        "import resolution charges the file lane against max_scanned_files"
    );
    assert!(
        unit.budgeted_work.import_edges_resolved > 0,
        "import resolution charges the edge lane against max_pipeline_rows"
    );
}

#[test]
fn per_unit_counter_sums_cover_the_whole_execution() {
    let project = eight_file_project();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let files = seed_files_of(&workspace);
    let query = CodeQuery::from_json(&json!({
        "schema_version": 1,
        "match": { "kind": "function" },
        "steps": [{ "op": "enclosing_decl" }],
        "limit": 500,
        "result_detail": "full"
    }))
    .expect("declaration query");

    let whole = whole_execution(&workspace, &query);
    let merged = merged(&workspace, &query, &files);

    assert!(merged.work.scanned_files >= whole.work.scanned_files);
    assert!(merged.work.pipeline_rows >= whole.work.pipeline_rows);
    assert!(merged.budgeted_work.provenance_steps >= whole.budgeted_work.provenance_steps);
    assert!(
        merged.budgeted_work.import_files_resolved >= whole.budgeted_work.import_files_resolved
    );
    assert!(
        merged.budgeted_work.import_edges_resolved >= whole.budgeted_work.import_edges_resolved
    );
    for (index, whole_outputs) in whole.budgeted_work.step_outputs.iter().enumerate() {
        assert!(
            merged.budgeted_work.step_outputs[index] >= *whole_outputs,
            "per-unit sums over-count, so they can only widen more often than the whole run"
        );
    }
}

/// The one diagnostic a merge cannot reproduce, pinned as the behavior it is.
///
/// `BroadQuery` is a cost advisory: it fires when one unanchored execution
/// scanned at least `BROAD_QUERY_SCANNED_FILE_HINT_THRESHOLD` files, and its
/// message is a rendering of that execution's own scan counters. A unit scoped
/// to one seed file never scans that much, so a sliced evaluation of a broad
/// selector does not carry the advisory a whole evaluation carries, even though
/// the rows are identical. The advisory has `Advisory` impact, so it changes no
/// completion; it does reach the policy report as a `Note`, which is a contract
/// decision for the incremental report's equivalence rule, not an executor bug.
#[test]
fn a_broad_query_advises_on_the_execution_that_paid_for_it() {
    let project = eight_file_project();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let files = seed_files_of(&workspace);
    // Unanchored on purpose: the advisory only fires for a query with no
    // source anchors, no where-globs and no language filter.
    let query = CodeQuery::from_json(&json!({
        "schema_version": 1,
        "match": { "kind": "function" },
        "steps": [{ "op": "enclosing_decl" }, { "op": "callers" }],
        "limit": 500,
        "result_detail": "full"
    }))
    .expect("unanchored callers query");

    let whole = whole_execution(&workspace, &query);
    let broad = |diagnostics: &[CodeQueryDiagnostic]| {
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == CodeQueryDiagnosticCode::BroadQuery)
    };
    assert!(
        broad(&whole.result.diagnostics),
        "the whole execution scans past the broad-query hint threshold"
    );

    let units = units(&workspace, &query, &files);
    assert!(
        units.iter().all(|unit| !broad(&unit.diagnostics)),
        "no single-file unit scans enough to raise the advisory"
    );

    let merged = merge_unit_rows(units);
    assert_eq!(
        merged.items,
        projected(&whole.result.results),
        "the rows are the same; only the cost advice differs"
    );
    assert_eq!(
        merged.completion(),
        whole.result.completion(),
        "an advisory changes no completion"
    );
}

/// The rendered detail a merge cannot reproduce, pinned as a deterministic
/// case.
///
/// `PipelineRenderCache` seals its source loads after the first row is
/// rendered, so a nested reference target's `node_range` is filled only when
/// some row of the same execution already retained that target's file. A whole
/// execution that renders a row in `src/a.ts` before the row in `src/b.ts`
/// that resolves into it therefore publishes a `node_range` no unit scoped to
/// `src/b.ts` can publish. The rows, their identities and their evidence are
/// otherwise identical; only this opportunistic coordinate differs.
///
/// This is not a cap the widening rule can see and not a defect the merge can
/// repair: it is the executor's own rule that rendered detail depends on what
/// the execution loaded, which already makes a path-scoped `query_code` answer
/// differ from an unscoped one for the same row. Closing it is a decision about
/// public `query_code` output -- either drop the opportunistic coordinate so a
/// row renders the same everywhere, or load the target's source for every
/// nested unit -- so it is reported rather than decided here.
#[test]
#[ignore = "finds a real divergence: nested target node_range depends on what else the execution rendered; needs a query_code output decision"]
fn a_nested_reference_target_renders_the_same_detail_in_a_unit_and_a_whole_run() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/a.ts",
            "import { helper } from './c';\nexport function target() {\n  return helper();\n}\n",
        )
        .file(
            "src/b.ts",
            "import { target } from './a';\nexport function caller() {\n  return target();\n}\n",
        )
        .file("src/c.ts", "export function helper() {\n  return 1;\n}\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let files = seed_files_of(&workspace);
    let query = occurrence_query();

    let whole = whole_execution(&workspace, &query);
    let merged = merged(&workspace, &query, &files);
    assert_eq!(merged.items, projected(&whole.result.results));
}

/// Execute one unit with a read ledger attached to the outermost request
/// boundary.
///
/// The executor opens nested scopes of its own and never carries a ledger on
/// them; the analyzer's broadcast is what puts their reads on this one.
fn unit_read_keys(
    workspace: &WorkspaceAnalyzer,
    query: &CodeQuery,
    seed: &ProjectFile,
    files: &[ProjectFile],
) -> Vec<crate::analyzer::ReadKey> {
    let ledger = std::sync::Arc::new(crate::analyzer::read_ledger::ReadLedger::new());
    {
        let _scope = crate::analyzer::AnalyzerQueryScope::with_read_ledger(
            workspace.analyzer(),
            std::sync::Arc::clone(&ledger),
        );
        execute_code_query_unit(
            workspace.analyzer(),
            None,
            query,
            CodeQueryExecutionLimits::default(),
            None,
            CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(seed), files),
        );
    }
    ledger.keys()
}

fn two_file_project() -> BuiltInlineTestProject {
    InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/callee.ts",
            "export function target() {\n  return 1;\n}\n",
        )
        .file(
            "src/caller.ts",
            "import { target } from './callee';\nexport function caller() {\n  return target();\n}\n",
        )
        .build()
}

/// A unit's seed enumeration depends on the files it opened, not on the
/// language it enumerated over.
///
/// Recording the whole-language scope for a narrowed enumeration would make
/// every edit anywhere invalidate every unit, which is exactly the reuse this
/// plan exists to keep. A row-local plan over one seed file therefore records
/// `File` keys for what it hydrated and no `Scope` key at all.
#[test]
fn a_row_local_unit_records_no_language_scope() {
    let project = two_file_project();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let files = seed_files_of(&workspace);
    let callee = project.file("src/callee.ts");
    let keys = unit_read_keys(&workspace, &function_query(), &callee, &files);

    assert!(
        keys.iter().any(
            |key| matches!(key, crate::analyzer::ReadKey::File { rel_path, .. }
                if rel_path.as_ref() == "src/callee.ts")
        ),
        "the unit must record the seed file it hydrated: {keys:?}"
    );
    assert!(
        !keys
            .iter()
            .any(|key| matches!(key, crate::analyzer::ReadKey::Scope { .. })),
        "a row-local unit must record no whole-scope dependency: {keys:?}"
    );
}

/// A step whose answer is a whole-workspace derived value still records that
/// value, because a change anywhere in it changes the unit's rows.
#[test]
fn a_callers_unit_records_the_whole_workspace_value_it_consumed() {
    let project = two_file_project();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let files = seed_files_of(&workspace);
    let callee = project.file("src/callee.ts");
    let keys = unit_read_keys(&workspace, &callers_query(), &callee, &files);

    assert!(
        keys.iter().any(|key| matches!(
            key,
            crate::analyzer::ReadKey::Scope { .. } | crate::analyzer::ReadKey::Artifact { .. }
        )),
        "a callers step consumes a whole-workspace derived value and must record it: {keys:?}"
    );
    assert!(
        keys.iter().any(|key| matches!(
            key,
            crate::analyzer::ReadKey::Lookup {
                kind: crate::analyzer::LookupKind::Callers,
                ..
            }
        )),
        "the callers answer is itself a recorded input: {keys:?}"
    );
}
