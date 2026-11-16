use super::inline_project::BuiltInlineTestProject;
use super::*;
use crate::structural::search::units::{
    CodeQueryExecutionScope, MergedUnitRows, UnitExecutionResult, execute_code_query_unit,
    merge_unit_rows, plan_seed_files, seed_file_order, unit_row_key,
};
use brokk_bifrost_test_macros::hardwon;

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

fn overlapping_union_query() -> CodeQuery {
    CodeQuery::from_json(&json!({
        "schema_version": 1,
        "union": [
            { "match": { "kind": "function", "name": { "regex": "^target" } } },
            { "match": { "kind": "function" } }
        ],
        "limit": 500,
        "result_detail": "full"
    }))
    .expect("overlapping union query")
}

fn nested_union_query() -> CodeQuery {
    CodeQuery::from_json(&json!({
        "schema_version": 1,
        "union": [
            {
                "union": [
                    { "match": { "kind": "function", "name": { "regex": "^target" } } },
                    { "match": { "kind": "function" } }
                ]
            },
            { "match": { "kind": "function", "name": "caller0" } }
        ],
        "limit": 500,
        "result_detail": "full"
    }))
    .expect("nested union query")
}

#[test]
#[hardwon("#8925: reused occurrence prefixes dropped their resolved target payload")]
fn derived_occurrence_intersect_prefix_is_not_cacheable() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            "pub fn target() {}\npub fn caller() { target(); }\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_sexp("(result-detail full (intersect (filter :where ((role eq (enum callee_position)) (target_kind eq (enum resolved))) (occurrences-in :class reference :role callee_position (language rust (call :callee (name \"target\"))))) (occurrences-in :class reference :role callee_position (language rust (call :callee (name \"target\"))))))")
        .expect("reviewer occurrence intersect");
    let whole = whole_execution(&workspace, &query);
    assert_eq!(
        whole.result.results.len(),
        1,
        "{}",
        whole.result.render_text()
    );
    assert!(!whole.result.render_text().is_empty());
    let CodeQueryResultValue::Occurrence { value } = &whole.result.results[0].value else {
        panic!("intersect must retain an occurrence");
    };
    let crate::structural::search::CodeQueryOccurrenceTarget::Resolved { units } = &value.target
    else {
        panic!("target must be resolved: {:?}", value.target);
    };
    assert_eq!(units.len(), 1);
    assert_eq!(units[0].path, "src/lib.rs");
    assert_eq!(units[0].start_line, 1);
    assert_eq!(units[0].fq_name, "target");
    let files = seed_files_of(&workspace);
    let prefixes: Vec<_> = files
        .iter()
        .map(|seed| {
            crate::structural::search::execute_intersect_prefix(
                workspace.analyzer(),
                &brokk_bifrost_flow::FlowWorkspaceState::default(),
                Some(&workspace),
                &query,
                CodeQueryExecutionLimits::default(),
                None,
                CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(seed), &files),
            )
        })
        .collect();
    assert!(
        prefixes
            .iter()
            .any(|prefix| prefix.encode_product_json(&query.plan).is_err()),
        "derived occurrence payload must not be persisted"
    );
    let cold = crate::structural::search::continue_intersect_prefix(
        workspace.analyzer(),
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        Some(&workspace),
        &query,
        CodeQueryExecutionLimits::default(),
        None,
        &files,
        prefixes,
        CodeQueryExecutionScope::whole_workspace(),
    );
    let detailed = cold.detailed.expect("cold continuation");
    assert_eq!(detailed.result.render_text(), whole.result.render_text());
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
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        query,
        CodeQueryExecutionLimits::default(),
        None,
    )
}

fn decoded_intersect_execution(
    workspace: &WorkspaceAnalyzer,
    query: &CodeQuery,
) -> crate::structural::search::IntersectContinuationResult {
    let files = plan_seed_files(&query.plan, &workspace.analyzer().analyzed_files());
    let prefixes = files
        .iter()
        .map(|seed| {
            let prefix = crate::structural::search::execute_intersect_prefix(
                workspace.analyzer(),
                &brokk_bifrost_flow::FlowWorkspaceState::default(),
                Some(workspace),
                query,
                CodeQueryExecutionLimits::default(),
                None,
                CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(seed), &files),
            );
            let product = prefix
                .encode_product_json(&query.plan)
                .expect("complete typed prefix product");
            crate::structural::search::IntersectPrefixProduct::decode_product_json_with_workspace(
                workspace.analyzer(),
                Some(workspace),
                &query.plan,
                seed.clone(),
                prefix.reads.clone(),
                product,
            )
            .expect("hydrate typed prefix")
        })
        .collect();
    crate::structural::search::continue_intersect_prefix(
        workspace.analyzer(),
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        Some(workspace),
        query,
        CodeQueryExecutionLimits::default(),
        None,
        &files,
        prefixes,
        CodeQueryExecutionScope::whole_workspace(),
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
                &brokk_bifrost_flow::FlowWorkspaceState::default(),
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
    merge_unit_rows(query, units(workspace, query, seed_files))
}

fn assert_merged_units_match_whole(
    project: &BuiltInlineTestProject,
    workspace: &WorkspaceAnalyzer,
    query: &CodeQuery,
    files: &[ProjectFile],
    whole: &DetailedCodeQueryResult,
) -> MergedUnitRows {
    let merged = merged(workspace, query, files);
    assert_eq!(merged.items, projected(&whole.result.results));
    assert_eq!(merged.detailed_evidence(project.root()), whole.evidence);
    merged
}

fn seed_files_of(workspace: &WorkspaceAnalyzer) -> Vec<ProjectFile> {
    let mut files = workspace.analyzer().analyzed_files();
    files.sort_by(seed_file_order);
    files
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "853aed79cfec: partition-local frontier witnesses disagreed with the whole bounded answer"
)]
fn merged_call_depth_equals_whole_across_partition_seed_roots() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            "mod mid; mod leaf;\nfn root() { mid::child(); }\n",
        )
        .file("src/mid.rs", "pub fn child() { crate::leaf::leaf(); }\n")
        .file("src/leaf.rs", "pub fn leaf() {}\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query =
        CodeQuery::from_sexp("(callees :depth 1 (enclosing-decl (language rust (function))))")
            .unwrap();
    let whole = whole_execution(&workspace, &query);
    let files = plan_seed_files(&query.plan, &workspace.analyzer().analyzed_files());
    let merged = merged(&workspace, &query, &files);
    assert_eq!(whole.result.completion(), CodeQueryCompletion::Complete);
    assert_eq!(
        whole.result.depth_bound_status,
        Some(DepthBoundStatus::NotReached)
    );
    assert_eq!(merged.depth_bound_status, whole.result.depth_bound_status);
}

#[test]
fn depth_members_survive_projection_and_remain_traversal_local() {
    for colocated in [false, true] {
        let mut project = InlineTestProject::with_language(Language::Rust);
        if colocated {
            project = project
                .file("src/lib.rs", "mod mid; fn root() { mid::child(); }\n")
                .file(
                    "src/mid.rs",
                    "pub fn child() { leaf(); }\npub fn leaf() {}\n",
                );
        } else {
            project = project
                .file(
                    "src/lib.rs",
                    "mod mid; mod leaf; fn root() { mid::child(); }\n",
                )
                .file("src/mid.rs", "pub fn child() { crate::leaf::leaf(); }\n")
                .file("src/leaf.rs", "pub fn leaf() {}\n");
        }
        let project = project.build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let first = "(callees :depth 1 (enclosing-decl (language rust (function :name \"root\"))))";
        let filtered = format!("(filter :where ((fq_name regex \"^never/\")) {first})");
        let second =
            "(callees :depth 1 (enclosing-decl (language rust (function :name \"leaf\"))))";
        for (source, empty, prefix, expected) in [
            (filtered.clone(), true, false, DepthBoundStatus::Reached),
            (
                format!("(union {first} {second})"),
                false,
                false,
                DepthBoundStatus::Reached,
            ),
            (
                format!("(callees :depth 1 {first})"),
                false,
                false,
                DepthBoundStatus::Reached,
            ),
            (
                "(filter :where ((fq_name regex \"^never/\")) (intersect (callers :depth 1 (enclosing-decl (language rust (function :name \"leaf\")))) (enclosing-decl (language rust (function)))))".to_owned(),
                true,
                true,
                DepthBoundStatus::Reached,
            ),
            (
                "(callees :depth 1 (union (enclosing-decl (language rust (function :name \"root\"))) (enclosing-decl (language rust (function :name \"leaf\")))))".to_owned(),
                false,
                false,
                DepthBoundStatus::NotReached,
            ),
        ] {
            let query = CodeQuery::from_sexp(&source).unwrap();
            let whole = whole_execution(&workspace, &query);
            assert_eq!(
                whole.result.depth_bound_status,
                Some(expected),
                "{source}: {whole:?}"
            );
            if empty {
                assert!(whole.result.results.is_empty(), "{source}");
            }
            if prefix {
                let continued = decoded_intersect_execution(&workspace, &query);
                assert_eq!(
                    continued.depth_bound_status, whole.result.depth_bound_status,
                    "prefix: {source}"
                );
                continue;
            }
            let files = plan_seed_files(&query.plan, &workspace.analyzer().analyzed_files());
            let products = units(&workspace, &query, &files);
            let added_bytes = products
                .iter()
                .map(|product| {
                    let mut value = serde_json::to_value(product).unwrap();
                    let before = serde_json::to_vec(&value).unwrap().len();
                    value.as_object_mut().unwrap().remove("depth_answers");
                    before - serde_json::to_vec(&value).unwrap().len()
                })
                .sum::<usize>();
            eprintln!(
                "depth-product-size colocated={colocated} units={} bytes_added={added_bytes} query={source}",
                products.len()
            );
            for reverse in [false, true] {
                let mut replayed = products
                    .iter()
                    .map(|product| {
                        serde_json::from_slice::<UnitExecutionResult>(
                            &serde_json::to_vec(product).unwrap(),
                        )
                        .unwrap()
                    })
                    .collect::<Vec<_>>();
                if reverse {
                    replayed.reverse();
                }
                let actual = merge_unit_rows(&query, replayed);
                assert_eq!(
                    actual.depth_bound_status, whole.result.depth_bound_status,
                    "{source} reverse={reverse}"
                );
                if empty {
                    assert!(actual.items.is_empty());
                }
            }
        }
    }
}

#[test]
#[hardwon(
    "69e0507ebf4b: middle-empty intersects used depth answers from whole-query skipped operands"
)]
fn middle_empty_intersect_discards_skipped_frontier_answers() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            "fn leaf() {}\nfn root() { leaf(); }\nfn beyond() { root(); }\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    for target in ["leaf", "root"] {
        let query = CodeQuery::from_sexp(&format!(
            "(intersect (enclosing-decl (language rust (function :name \"leaf\"))) (enclosing-decl (language rust (function :name \"missing\"))) (callers :depth 1 (enclosing-decl (language rust (function :name \"{target}\")))))"
        )).unwrap();
        let whole = whole_execution(&workspace, &query);
        assert!(whole.result.results.is_empty());
        assert_eq!(
            whole.result.depth_bound_status,
            Some(DepthBoundStatus::NotReached)
        );
        assert_eq!(whole.result.completion(), CodeQueryCompletion::Complete);
        let continued = decoded_intersect_execution(&workspace, &query);
        assert_eq!(
            continued.depth_bound_status, whole.result.depth_bound_status,
            "{target}"
        );
        assert_eq!(continued.completion, whole.result.completion());
        assert!(continued.detailed.unwrap().result.results.is_empty());
    }
}

#[test]
#[hardwon(
    "3b2d094964ec: suffix truncation lost negative depth uncertainty during prefix reconciliation"
)]
fn truncated_suffix_preserves_whole_depth_uncertainty() {
    for (beyond_body, expected) in [
        ("", DepthBoundStatus::Unknown),
        ("root();", DepthBoundStatus::Reached),
    ] {
        let calls = "other();".repeat(40);
        let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            format!("fn root() {{ leaf(); {calls} }}\nfn leaf() {{}}\nfn other() {{}}\nfn beyond() {{ {beyond_body} }}\n"),
        )
        .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let query = CodeQuery::from_sexp(
        "(uses (intersect (callers :depth 1 (enclosing-decl (language rust (function :name \"leaf\")))) (enclosing-decl (language rust (function :name \"root\")))))"
    ).unwrap();
        let limits = CodeQueryExecutionLimits {
            max_pipeline_rows: 16,
            ..Default::default()
        };
        let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
        let files = seed_files_of(&workspace);
        let whole = execute_code_query_detailed_eager_index(
            workspace.analyzer(),
            &flow,
            &query,
            limits,
            None,
        );
        assert_eq!(whole.result.depth_bound_status, Some(expected));
        assert_ne!(whole.result.completion(), CodeQueryCompletion::Complete);
        let prefixes = files
            .iter()
            .map(|seed| {
                let prefix = crate::structural::search::execute_intersect_prefix(
                    workspace.analyzer(),
                    &flow,
                    Some(&workspace),
                    &query,
                    limits,
                    None,
                    CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(seed), &files),
                );
                assert_eq!(prefix.completion, CodeQueryCompletion::Complete);
                assert_eq!(
                    prefix.depth_bound_status,
                    Some(if expected == DepthBoundStatus::Reached {
                        expected
                    } else {
                        DepthBoundStatus::NotReached
                    })
                );
                prefix
            })
            .collect();
        let continued = crate::structural::search::continue_intersect_prefix(
            workspace.analyzer(),
            &flow,
            Some(&workspace),
            &query,
            limits,
            None,
            &files,
            prefixes,
            CodeQueryExecutionScope::whole_workspace(),
        );
        assert!(continued.detailed.is_some());
        assert_eq!(
            continued.depth_bound_status,
            whole.result.depth_bound_status
        );
        assert_eq!(continued.completion, whole.result.completion());
        let withheld = crate::structural::search::continue_intersect_prefix(
            workspace.analyzer(),
            &flow,
            Some(&workspace),
            &query,
            limits,
            None,
            &files,
            Vec::new(),
            CodeQueryExecutionScope::whole_workspace(),
        );
        assert!(withheld.detailed.is_none());
        assert_eq!(withheld.depth_bound_status, Some(DepthBoundStatus::Unknown));
    }
}

#[test]
fn merged_depth_retains_the_entire_natural_frontier() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            "mod mid; mod leaves; fn root() { mid::child(); }\n",
        )
        .file(
            "src/mid.rs",
            "pub fn child() { crate::leaves::first(); crate::leaves::second(); }\n",
        )
        .file("src/leaves.rs", "pub fn first() {}\npub fn second() {}\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["rust"], "match": {"kind": "function", "name": {"regex": "^(root|first)$"}},
        "steps": [{"op":"enclosing_decl"}, {"op":"callees", "depth":1}]
    }))
    .unwrap();
    let whole = whole_execution(&workspace, &query);
    assert_eq!(
        whole.result.depth_bound_status,
        Some(DepthBoundStatus::Reached)
    );
    let files = plan_seed_files(&query.plan, &workspace.analyzer().analyzed_files());
    let products = units(&workspace, &query, &files);
    assert!(
        products
            .iter()
            .flat_map(|unit| &unit.depth_answers)
            .any(|answer| answer.frontier.len() >= 2)
    );
    assert_eq!(
        merge_unit_rows(&query, products).depth_bound_status,
        whole.result.depth_bound_status
    );
}

fn depth_status_rank(status: Option<DepthBoundStatus>) -> u8 {
    match status {
        Some(DepthBoundStatus::Reached) => 2,
        Some(DepthBoundStatus::Unknown) => 1,
        Some(DepthBoundStatus::NotReached) | None => 0,
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "e0b09002ed4d: empty-operand continuation rejected structural seed order exposed by pgcat"
)]
fn repeated_depth_selector_keeps_its_authored_branch_position() {
    use crate::analyzer::{AnalyzerQueryScope, read_ledger::ReadLedger};
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "mod mid; fn root() { mid::child(); }\n")
        .file(
            "src/mid.rs",
            "pub mod leaf; pub fn child() { leaf::leaf(); }\n",
        )
        .file("src/mid/leaf.rs", "pub fn leaf() {}\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let branch = "(callers :depth 1 (enclosing-decl (language rust (function :name \"leaf\"))))";
    let query = CodeQuery::from_sexp(&format!(
        "(intersect (filter :where ((fq_name regex \"^never/\")) {branch}) {branch})"
    ))
    .unwrap();
    let whole = whole_execution(&workspace, &query);
    assert!(whole.result.results.is_empty());
    assert_eq!(
        whole.result.depth_bound_status,
        Some(DepthBoundStatus::Reached)
    );
    let CodeQueryPlanSource::Set { branches, .. } = &query.plan.source else {
        unreachable!()
    };
    let operand = CodeQuery {
        plan: branches[0].clone(),
        limit: usize::MAX,
        ..query.clone()
    };
    let files = plan_seed_files(&query.plan, &workspace.analyzer().analyzed_files());
    assert!(
        files.windows(2).any(|pair| pair[0] > pair[1]),
        "the structural scan order must differ from ProjectFile component order"
    );
    let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
    let probes = files
        .iter()
        .map(|file| {
            let ledger = std::sync::Arc::new(ReadLedger::new());
            let _capture = AnalyzerQueryScope::with_read_ledger(
                workspace.analyzer(),
                std::sync::Arc::clone(&ledger),
            );
            let seed_read = workspace
                .analyzer()
                .structural_fact_providers()
                .into_iter()
                .filter(|provider| provider.structural_language() == file.language())
                .find_map(|provider| provider.structural_file_read_key(file))
                .unwrap();
            workspace.analyzer().record_read(seed_read);
            let unit = execute_code_query_unit(
                workspace.analyzer(),
                &flow,
                None,
                &operand,
                CodeQueryExecutionLimits::default(),
                None,
                CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(file), &files),
            );
            (unit, ledger.keys())
        })
        .collect();
    let continued = crate::structural::search::continue_empty_operand_zero(
        workspace.analyzer(),
        &flow,
        None,
        &query,
        CodeQueryExecutionLimits::default(),
        None,
        &files,
        crate::structural::search::CompleteEmptyFromOperandZero { probes },
        CodeQueryExecutionScope::whole_workspace(),
    );
    assert_eq!(
        continued.depth_bound_status,
        whole.result.depth_bound_status
    );
    assert!(continued.into_merged_rows(&query).items.is_empty());
}

#[test]
fn merged_call_depth_never_loses_a_whole_query_continuation() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            "mod mid; mod leaf;\nfn root() { mid::child(); }\n",
        )
        .file("src/mid.rs", "pub fn child() { crate::leaf::leaf(); }\n")
        .file("src/leaf.rs", "pub fn leaf() {}\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_sexp(
        "(callees :depth 1 (enclosing-decl (language rust (function (name \"root\")))))",
    )
    .unwrap();
    let whole = whole_execution(&workspace, &query);
    let files = plan_seed_files(&query.plan, &workspace.analyzer().analyzed_files());
    let merged = merged(&workspace, &query, &files);
    assert_eq!(
        whole.result.depth_bound_status,
        Some(DepthBoundStatus::Reached)
    );
    assert!(
        depth_status_rank(merged.depth_bound_status)
            >= depth_status_rank(whole.result.depth_bound_status)
    );
}

#[test]
fn merged_structural_units_reproduce_the_whole_execution() {
    let project = eight_file_project();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let files = seed_files_of(&workspace);
    let query = function_query();

    let whole = whole_execution(&workspace, &query);
    assert!(!whole.result.results.is_empty());

    let merged = assert_merged_units_match_whole(&project, &workspace, &query, &files, &whole);
    assert_eq!(merged.completion(), whole.result.completion());
}

#[test]
fn merged_overlapping_union_units_reproduce_branch_order_and_evidence() {
    let project = eight_file_project();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let files = plan_seed_files(
        &overlapping_union_query().plan,
        &workspace.analyzer().analyzed_files(),
    );
    let query = overlapping_union_query();
    let whole = whole_execution(&workspace, &query);
    let merged = assert_merged_units_match_whole(&project, &workspace, &query, &files, &whole);
    assert_eq!(merged.completion(), whole.result.completion());
}

#[test]
fn merged_nested_union_units_reproduce_full_branch_paths() {
    let project = eight_file_project();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = nested_union_query();
    let files = plan_seed_files(&query.plan, &workspace.analyzer().analyzed_files());
    let whole = whole_execution(&workspace, &query);
    assert_merged_units_match_whole(&project, &workspace, &query, &files, &whole);
}

/// Seven TypeScript files under `big/` and one under `small/`, so a branch's
/// seed path scope sets its scanned-file charge (7, 1, or 8 for both), and a
/// branch over a language the project lacks charges nothing.
fn split_charge_project() -> BuiltInlineTestProject {
    let mut project = InlineTestProject::with_language(Language::TypeScript);
    for (dir, count) in [("big", 7), ("small", 1)] {
        for index in 0..count {
            project = project.file(
                format!("{dir}/mod{index}.ts"),
                format!("export function {dir}{index}() {{\n  return {index};\n}}\n"),
            );
        }
    }
    project.build()
}

/// Capped partitions return a defensible subset and report omitted rows.
#[test]
#[hardwon("#8287: merged-limit check summed every union branch against cap/max-divisor")]
fn union_merge_admission_is_sound_against_the_whole_executor() {
    let project = split_charge_project();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let branch = |languages: &str, path: Option<&str>| {
        let mut seed = json!({"languages": [languages], "match": {"kind": "function"}});
        if let Some(path) = path {
            seed["where"] = json!([path]);
        }
        seed
    };
    let big = branch("typescript", Some("big/*.ts"));
    let small = branch("typescript", Some("small/*.ts"));
    let all = branch("typescript", None);
    let none = |language: &str| branch(language, None);
    let union = |branches: Vec<serde_json::Value>| json!({"union": branches});
    let flask_shape = union(vec![
        none("python"),
        all.clone(),
        none("go"),
        none("java"),
        none("rust"),
        none("cpp"),
        none("csharp"),
        none("php"),
        none("ruby"),
    ]);
    // Exercise empty, dominant, overlapping and nested branch layouts.
    let cases = [
        (
            "union leaf exhausts allowance",
            union(vec![all.clone(), all.clone()]),
            1,
        ),
        (
            "late single branch",
            union(vec![none("python"), all.clone()]),
            9,
        ),
        ("equal branches", union(vec![all.clone(), all.clone()]), 17),
        (
            "equal branches at the cap",
            union(vec![all.clone(), all.clone()]),
            16,
        ),
        (
            "dominant first branch",
            union(vec![big.clone(), small.clone()]),
            12,
        ),
        (
            "dominant late branch",
            union(vec![small.clone(), big.clone()]),
            12,
        ),
        ("flask shape", flask_shape, 72),
        (
            "nested smaller cap",
            union(vec![union(vec![big.clone(), small.clone()]), none("go")]),
            24,
        ),
        (
            "nested larger cap",
            union(vec![union(vec![big.clone(), small.clone()]), none("go")]),
            30,
        ),
    ];
    for (layout, plan, cap) in cases {
        let mut json = plan;
        json["limit"] = json!(500);
        json["result_detail"] = json!("full");
        let query = CodeQuery::from_json(&json).expect("union layout query");
        let files = plan_seed_files(&query.plan, &workspace.analyzer().analyzed_files());
        let limits = CodeQueryExecutionLimits {
            max_scanned_files: cap,
            ..Default::default()
        };
        for result_limit in [500, 3] {
            let mut query = query.clone();
            query.limit = result_limit;
            let products = files.iter().map(|file| {
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
            let mut merged = merge_unit_rows(&query, products);
            merged.apply_result_limit(query.limit);
            let mut complete_query = query.clone();
            complete_query.limit = 500;
            let whole = whole_execution(&workspace, &complete_query);
            let complete = projected(&whole.result.results);
            assert!(
                merged
                    .items
                    .iter()
                    .all(|row| complete.iter().any(|candidate| {
                        let mut row = row.clone();
                        let mut candidate = candidate.clone();
                        row.provenance.clear();
                        candidate.provenance.clear();
                        row == candidate
                    })),
                "{layout}"
            );
            if !merged.truncated {
                assert_eq!(merged.items, complete, "{layout}");
            } else {
                assert!(
                    !merged.diagnostics.is_empty(),
                    "{layout}: truncation must be reported"
                );
            }
            assert!(merged.items.len() <= result_limit);
        }
    }

    // Both units cut, then the merged root can cut again. Even a root with
    // enough headroom must deduplicate diagnostics inherited from its units.
    let project = InlineTestProject::with_language(Language::Rust)
        .file("a.rs", "pub fn a() {} pub fn aa() {} pub fn aaa() {}")
        .file("b.rs", "pub fn b() {} pub fn bb() {} pub fn bbb() {}")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let files = seed_files_of(&workspace);
    let query = CodeQuery::from_json(&json!({
        "languages": ["rust"], "match": {"kind": "function"}, "limit": 1,
    }))
    .unwrap();
    let products: Vec<_> = files
        .iter()
        .map(|file| {
            execute_code_query_unit(
                workspace.analyzer(),
                &brokk_bifrost_flow::FlowWorkspaceState::default(),
                Some(&workspace),
                &query,
                Default::default(),
                None,
                CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(file), &files),
            )
        })
        .collect();
    assert_eq!(products.len(), 2);
    assert!(
        products
            .iter()
            .all(|unit| unit.truncated && unit.rows.len() == 1)
    );
    for limit in [10, 1] {
        let mut merged = merge_unit_rows(&query, products.clone());
        assert_eq!(
            merged
                .diagnostics
                .iter()
                .filter(|d| d.code == CodeQueryDiagnosticCode::ResultLimitReached)
                .count(),
            2
        );
        merged.apply_result_limit(limit);
        assert_eq!(
            merged
                .diagnostics
                .iter()
                .filter(|d| d.code == CodeQueryDiagnosticCode::ResultLimitReached)
                .count(),
            1
        );
        assert_eq!(merged.items.len(), 2.min(limit));
    }
}

/// Isolate output headroom from independently charged work: counts are a
/// physical-plan certificate, and an exact intermediate boundary is unsafe.
#[test]
#[hardwon(
    "#2445: the merge proof compared intermediate step outputs with the findings cap, so complete policies ran in full"
)]
fn intermediate_step_outputs_report_truncation_at_the_pipeline_cap() {
    let query = CodeQuery::from_json(&json!({
        "schema_version": 1,
        "match": { "kind": "function" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "filter", "where": [{ "field": "fq_name", "op": "eq", "value": { "string": "missing" } }] }
        ],
        "limit": 3
    }))
    .expect("inventory followed by empty filter");
    let project = eight_file_project();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let files = workspace.analyzer().analyzed_files();
    for cap in [1, 20] {
        let limits = CodeQueryExecutionLimits {
            max_pipeline_rows: cap,
            ..Default::default()
        };
        let products = files.iter().map(|file| {
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
        let merged = merge_unit_rows(&query, products);
        assert!(merged.items.is_empty());
        if cap == 1 {
            assert!(merged.truncated);
            assert!(
                merged
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code.is_execution_state())
            );
        } else {
            assert!(!merged.truncated);
            assert_eq!(merged.completion(), CodeQueryCompletion::Complete);
        }
    }
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
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
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
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
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
    let merged_steps = merged.budgeted_work.step_outputs.as_ref().unwrap();
    for (index, whole_outputs) in whole
        .budgeted_work
        .step_outputs
        .as_ref()
        .unwrap()
        .iter()
        .enumerate()
    {
        assert!(
            merged_steps[index] >= *whole_outputs,
            "per-unit sums over-count, so they can only widen more often than the whole run"
        );
    }
}

#[test]
#[hardwon(
    "#11709: a unit cancelled before it started counted no steps, and merging it with a counted unit panicked on the length"
)]
fn a_unit_stopped_before_it_started_merges_with_counted_units() {
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
    let uncancelled = units(&workspace, &query, &files);

    let mut counted_and_unknown = 0;
    let mut finished = false;
    for checks in 0..2000 {
        let token = CancellationToken::cancel_after_checks_for_test(checks);
        let stopped: Vec<_> = files
            .iter()
            .map(|file| {
                execute_code_query_unit(
                    workspace.analyzer(),
                    &brokk_bifrost_flow::FlowWorkspaceState::default(),
                    None,
                    &query,
                    CodeQueryExecutionLimits::default(),
                    Some(&token),
                    CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(file), &files),
                )
            })
            .collect();
        for (unit, whole) in stopped.iter().zip(&uncancelled) {
            if !unit.truncated {
                assert_eq!(
                    unit.budgeted_work, whole.budgeted_work,
                    "checks={checks}: a unit that finished counts what it counts uncancelled"
                );
            }
        }
        finished = stopped.iter().all(|unit| !unit.truncated);
        let any_unknown = stopped
            .iter()
            .any(|unit| unit.budgeted_work.step_outputs.is_none());
        let any_counted = stopped
            .iter()
            .any(|unit| unit.budgeted_work.step_outputs.is_some());

        let merged = merge_unit_rows(&query, stopped);
        if any_unknown {
            assert_eq!(merged.budgeted_work.step_outputs, None, "checks={checks}");
            assert_eq!(
                merged.reached_limit(&CodeQueryExecutionLimits::default(), query.limit),
                Some(MergedLimit::UnitTruncated),
                "checks={checks}: unknown per-step counts decide no cap"
            );
            counted_and_unknown += usize::from(any_counted);
        }
        if finished {
            break;
        }
    }
    assert!(finished, "the sweep reaches an undisturbed execution");
    assert!(
        counted_and_unknown > 0,
        "the sweep stops a unit mid-way and the units after it before they start"
    );
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

    let merged = merge_unit_rows(&query, units);
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
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
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

#[test]
fn intersect_prefix_records_seed_file_and_keeps_typed_operands() {
    let project = two_file_project();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let files = seed_files_of(&workspace);
    let query = CodeQuery::from_json(&json!({
        "schema_version": 1,
        "intersect": [
            { "match": { "kind": "function" } },
            { "match": { "kind": "function" } }
        ],
        "limit": 500,
        "result_detail": "full"
    }))
    .expect("intersect query");
    let prefix = crate::structural::search::execute_intersect_prefix(
        workspace.analyzer(),
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        None,
        &query,
        CodeQueryExecutionLimits::default(),
        None,
        CodeQueryExecutionScope::for_seed_files(&files[..1], &files),
    );
    assert_eq!(prefix.completion, CodeQueryCompletion::Complete);
    assert_eq!(prefix.operand_row_counts().count(), 2);
    assert!(prefix.reads_closed);
    let seed_read = workspace
        .analyzer()
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == files[0].language())
        .and_then(|provider| provider.structural_file_read_key(&files[0]))
        .expect("seed read key");
    assert!(prefix.reads.contains(&seed_read), "{:?}", prefix.reads);
}

#[test]
fn intersect_prefix_codec_properties() {
    let project = two_file_project();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let files = seed_files_of(&workspace);
    let query = CodeQuery::from_json(&json!({
        "schema_version": 1,
        "intersect": [
            { "match": { "kind": "function" } },
            { "match": { "kind": "function" } }
        ],
        "limit": 500,
        "result_detail": "full"
    }))
    .expect("raw structural intersect");
    for seed in &files {
        let run = || {
            crate::structural::search::execute_intersect_prefix(
                workspace.analyzer(),
                &brokk_bifrost_flow::FlowWorkspaceState::default(),
                None,
                &query,
                CodeQueryExecutionLimits::default(),
                None,
                CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(seed), &files),
            )
        };
        let mut prefix = run();
        let identity = |product: &crate::structural::search::IntersectPrefixProduct| {
            product
                .operands
                .iter()
                .map(|rows| {
                    rows.iter()
                        .map(|row| {
                            assert!(row.row_projection.is_empty());
                            (
                                row.value.key(),
                                row.traces
                                    .iter()
                                    .map(|trace| (trace.branch.clone(), trace.seed.fact_match.node))
                                    .collect::<Vec<_>>(),
                                row.provenance_truncated,
                            )
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        };
        let before = identity(&prefix);
        let product_json = prefix
            .encode_product_json(&query.plan)
            .expect("complete product");
        let mut old_product = product_json.clone();
        old_product.as_object_mut().unwrap().remove("admission");
        assert!(
            crate::structural::search::IntersectPrefixProduct::decode_product_json(
                workspace.analyzer(),
                &query.plan,
                seed.clone(),
                prefix.reads.clone(),
                old_product,
            )
            .is_err(),
            "old prefixes must recompute rather than assume zero admission"
        );
        let decoded = crate::structural::search::IntersectPrefixProduct::decode_product_json(
            workspace.analyzer(),
            &query.plan,
            seed.clone(),
            prefix.reads.clone(),
            product_json.clone(),
        )
        .expect("hydrate complete product");
        assert_eq!(identity(&decoded), before);
        assert_eq!(decoded.work, prefix.work);
        assert_eq!(decoded.budgeted_work, prefix.budgeted_work);
        let limits = CodeQueryExecutionLimits::default();
        let fresh_remaining = remaining_unit_limits(limits, &prefix.work, &prefix.budgeted_work);
        let mut stored_telemetry = decoded.work;
        stored_telemetry.scanned_source_bytes =
            stored_telemetry.scanned_source_bytes.saturating_add(10_000);
        assert_eq!(
            fresh_remaining,
            remaining_unit_limits(limits, &stored_telemetry, &decoded.budgeted_work),
            "decoded stored prefix and fresh prefix leave the same next-unit allowance despite telemetry differences",
        );
        assert_eq!(decoded.completion, prefix.completion);
        assert_eq!(decoded.reads, prefix.reads);
        assert_eq!(
            decoded.encode_product_json(&query.plan).unwrap(),
            product_json
        );
        let different_plan = CodeQuery::from_json(&json!({
            "schema_version": 1,
            "intersect": [
                { "match": { "kind": "function" } },
                { "match": { "kind": "function" } },
                { "match": { "kind": "function" } }
            ],
            "limit": 500
        }))
        .expect("different authored cut");
        assert!(
            crate::structural::search::IntersectPrefixProduct::decode_product_json(
                workspace.analyzer(),
                &different_plan.plan,
                seed.clone(),
                prefix.reads.clone(),
                product_json.clone(),
            )
            .is_err(),
            "operand slots must resolve against the authored cut"
        );
        let mut corrupt_product = product_json.clone();
        corrupt_product["read_set_digest"] = json!("wrong receipt");
        assert!(
            crate::structural::search::IntersectPrefixProduct::decode_product_json(
                workspace.analyzer(),
                &query.plan,
                seed.clone(),
                prefix.reads.clone(),
                corrupt_product,
            )
            .is_err()
        );
        let encoded = prefix
            .encode_rows_json(&query.plan)
            .expect("encode raw rows");
        prefix.operands.iter_mut().for_each(Vec::clear);
        prefix
            .decode_rows_json(workspace.analyzer(), &query.plan, encoded.clone())
            .expect("hydrate exact seed blob");
        assert_eq!(identity(&prefix), before);
        assert_eq!(
            prefix.encode_rows_json(&query.plan).expect("re-encode"),
            encoded
        );

        let reads = std::mem::take(&mut prefix.reads);
        assert!(
            prefix
                .decode_rows_json(workspace.analyzer(), &query.plan, encoded.clone())
                .is_err(),
            "hydration without the file receipt cannot authorize reuse"
        );
        prefix.reads = reads;

        let mut bad_slot = encoded.clone();
        bad_slot[0][0]["traces"][0]["steps"] = json!([{
            "source_path": [0],
            "index": usize::MAX,
            "value": { "type": "structural_match", "rel_path": "unused", "node": 0 },
            "via": null
        }]);
        assert!(
            prefix
                .decode_rows_json(workspace.analyzer(), &query.plan, bad_slot)
                .is_err(),
            "an unresolved authored step slot is corrupt"
        );

        let mut corrupt = encoded.clone();
        corrupt[0][0]["node"] = json!(u32::MAX);
        assert!(
            prefix
                .decode_rows_json(workspace.analyzer(), &query.plan, corrupt)
                .is_err()
        );
        let recomputed = run();
        assert_eq!(
            recomputed.encode_rows_json(&query.plan).expect("recompute"),
            encoded
        );
    }
}

#[test]
fn rust_call_intersect_decoded_prefix_matches_whole() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            "pub fn target() {}\npub fn caller() { target(); }\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let files = seed_files_of(&workspace);
    let query = CodeQuery::from_sexp(
        "(result-detail full (intersect (language rust (call :callee (name \"target\"))) (language rust (call))))",
    )
    .expect("observed Rust call intersect shape");
    let prefixes = files
        .iter()
        .map(|seed| {
            let mut prefix = crate::structural::search::execute_intersect_prefix(
                workspace.analyzer(),
                &brokk_bifrost_flow::FlowWorkspaceState::default(),
                None,
                &query,
                CodeQueryExecutionLimits::default(),
                None,
                CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(seed), &files),
            );
            let encoded = prefix
                .encode_rows_json(&query.plan)
                .expect("Rust call identity codec");
            prefix.operands.iter_mut().for_each(Vec::clear);
            prefix
                .decode_rows_json(workspace.analyzer(), &query.plan, encoded)
                .expect("hydrate call facts");
            prefix
        })
        .collect();
    let continued = crate::structural::search::continue_intersect_prefix(
        workspace.analyzer(),
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        None,
        &query,
        CodeQueryExecutionLimits::default(),
        None,
        &files,
        prefixes,
        CodeQueryExecutionScope::whole_workspace(),
    );
    let whole = whole_execution(&workspace, &query);
    let detailed = continued.detailed.expect("complete decoded prefix");
    assert_eq!(continued.completion, whole.result.completion());
    assert_eq!(
        projected(&detailed.result.results),
        projected(&whole.result.results)
    );
    assert_eq!(detailed.evidence, whole.evidence);
}

#[test]
fn xmlreader_intersect_decoded_prefix_matches_whole() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Readers.cs",
            r#"
using System.IO;
using System.Xml;
class Readers {
    XmlReader Open(Stream input) {
        XmlReaderSettings settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Parse;
        return XmlReader.Create(input, settings);
    }
}

"#,
        )
        .file("Other.cs", "class Other { void Run() {} }")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let files = seed_files_of(&workspace);
    let query = CodeQuery::from_sexp(
        r#"
    (result-detail full
      (intersect
        (binding-occurrence
          (binding-of
            (occurrences-in :class reference :role receiver_position
              (language csharp
                (assignment :left (field_access :name "DtdProcessing")
                            :right (field_access :name "Parse"))))))
        (binding-occurrence
          (binding-of
            (occurrences-in :class reference :role value_reference
              (language csharp (call :callee (name "Create"))))))))
    "#,
    )
    .expect("XMLReader selector");
    assert!(matches!(
        crate::query::PlanPartitioning::classify_for_prefix(&query.plan),
        crate::query::PlanPartitioning::Prefix { .. }
    ));
    let prefixes: Vec<_> = files
        .iter()
        .map(|seed| {
            let prefix = crate::structural::search::execute_intersect_prefix(
                workspace.analyzer(),
                &brokk_bifrost_flow::FlowWorkspaceState::default(),
                Some(&workspace),
                &query,
                CodeQueryExecutionLimits::default(),
                None,
                CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(seed), &files),
            );
            let product = prefix
                .encode_product_json(&query.plan)
                .expect("XMLReader typed product");
            crate::structural::search::IntersectPrefixProduct::decode_product_json_with_workspace(
                workspace.analyzer(),
                Some(&workspace),
                &query.plan,
                seed.clone(),
                prefix.reads.clone(),
                product,
            )
            .expect("XMLReader hydrated product")
        })
        .collect();
    assert!(
        prefixes
            .iter()
            .flat_map(
                |prefix: &crate::structural::search::IntersectPrefixProduct| prefix
                    .operands
                    .iter()
                    .flatten()
            )
            .flat_map(|row| row.traces.iter().flat_map(|trace| &trace.steps))
            .any(|step| matches!(step.value, PipelineTraceValue::Binding(_)))
    );
    let continued = crate::structural::search::continue_intersect_prefix(
        workspace.analyzer(),
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        Some(&workspace),
        &query,
        CodeQueryExecutionLimits::default(),
        None,
        &files,
        prefixes,
        CodeQueryExecutionScope::whole_workspace(),
    );
    let whole = whole_execution(&workspace, &query);
    let detailed = continued.detailed.expect("complete XMLReader continuation");
    assert_eq!(continued.completion, whole.result.completion());
    assert_eq!(
        projected(&detailed.result.results),
        projected(&whole.result.results)
    );
    assert_eq!(detailed.evidence, whole.evidence);
    assert!(!detailed.result.results.is_empty());

    let changed_file = ProjectFile::new(project.root(), "Readers.cs");
    let changed_source = changed_file
        .read_to_string()
        .expect("fixture source")
        .replace("DtdProcessing.Parse", "DtdProcessing.Prohibit");
    changed_file.write(&changed_source).expect("edit one seed");
    let changed = project.workspace_analyzer(AnalyzerConfig::default());
    let continued = decoded_intersect_execution(&changed, &query);
    let whole = whole_execution(&changed, &query);
    let detailed = continued
        .detailed
        .expect("complete edited XMLReader continuation");
    assert_eq!(continued.completion, whole.result.completion());
    assert_eq!(
        projected(&detailed.result.results),
        projected(&whole.result.results)
    );
    assert_eq!(detailed.evidence, whole.evidence);
    assert!(detailed.result.results.is_empty());
}

#[test]
fn rust_ctor_intersect_decoded_prefix_matches_whole() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/startup.rs",
            r#"
#[ctor::ctor]
pub fn bad_ctor() { std_helper(); }
#[ctor::ctor]
pub fn good_ctor() { libc_helper(); }
pub fn libc_helper() {}
pub fn std_helper() { let _ = std::fs::read("startup-state"); }
"#,
        )
        .file("src/other.rs", "pub fn unrelated() {}")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let files = seed_files_of(&workspace);
    let query = CodeQuery::from_sexp(
        r#"
      (result-detail full
        (intersect
          (enclosing-decl
            (language rust (function :decorators
              [(name/regex "^(ctor|ctor::ctor|dtor|dtor::dtor)$")])))
          (union
            (enclosing-decl
              (filter :where ((target_fq_name regex "^(std[.]|<std::)"))
                (language rust (dispatch-targets (call)))))
            (callers :depth 2 :proof proven
              (enclosing-decl
                (filter :where ((target_fq_name regex "^(std[.]|<std::)"))
                  (language rust (dispatch-targets (call)))))))))
    "#,
    )
    .expect("constructor selector");
    assert!(matches!(
        crate::query::PlanPartitioning::classify_for_prefix(&query.plan),
        crate::query::PlanPartitioning::Prefix { .. }
    ));
    let prefixes: Vec<_> = files
        .iter()
        .map(|seed| {
            let prefix = crate::structural::search::execute_intersect_prefix(
                workspace.analyzer(),
                &brokk_bifrost_flow::FlowWorkspaceState::default(),
                Some(&workspace),
                &query,
                CodeQueryExecutionLimits::default(),
                None,
                CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(seed), &files),
            );
            let product = prefix
                .encode_product_json(&query.plan)
                .expect("constructor typed product");
            crate::structural::search::IntersectPrefixProduct::decode_product_json_with_workspace(
                workspace.analyzer(),
                Some(&workspace),
                &query.plan,
                seed.clone(),
                prefix.reads.clone(),
                product,
            )
            .expect("constructor hydrated product")
        })
        .collect();
    let steps = prefixes
        .iter()
        .flat_map(
            |prefix: &crate::structural::search::IntersectPrefixProduct| {
                prefix.operands.iter().flatten()
            },
        )
        .flat_map(|row| row.traces.iter().flat_map(|trace| &trace.steps))
        .collect::<Vec<_>>();
    assert!(
        steps
            .iter()
            .any(|step| matches!(step.value, PipelineTraceValue::DispatchTarget(_)))
    );
    assert!(
        steps
            .iter()
            .any(|step| matches!(step.via, Some(PipelineVia::CallSite(_))))
    );
    let continued = crate::structural::search::continue_intersect_prefix(
        workspace.analyzer(),
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        Some(&workspace),
        &query,
        CodeQueryExecutionLimits::default(),
        None,
        &files,
        prefixes,
        CodeQueryExecutionScope::whole_workspace(),
    );
    let whole = crate::structural::search::execute_code_query_detailed_eager_index_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        &query,
        CodeQueryExecutionLimits::default(),
        None,
    );
    let detailed = continued
        .detailed
        .expect("complete constructor continuation");
    assert_eq!(continued.completion, whole.result.completion());
    assert_eq!(
        projected(&detailed.result.results),
        projected(&whole.result.results)
    );
    assert_eq!(detailed.evidence, whole.evidence);
    assert!(!detailed.result.results.is_empty());

    let changed_file = ProjectFile::new(project.root(), "src/startup.rs");
    let changed_source = changed_file
        .read_to_string()
        .expect("fixture source")
        .replace("std::fs::read(\"startup-state\")", "libc_helper()");
    changed_file.write(&changed_source).expect("edit one seed");
    let changed = project.workspace_analyzer(AnalyzerConfig::default());
    let continued = decoded_intersect_execution(&changed, &query);
    let whole = crate::structural::search::execute_code_query_detailed_eager_index_workspace(
        &changed,
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        &query,
        CodeQueryExecutionLimits::default(),
        None,
    );
    let detailed = continued
        .detailed
        .expect("complete edited constructor continuation");
    assert_eq!(continued.completion, whole.result.completion());
    assert_eq!(
        projected(&detailed.result.results),
        projected(&whole.result.results)
    );
    assert_eq!(detailed.evidence, whole.evidence);
    assert!(detailed.result.results.is_empty());
}

#[test]
#[hardwon("#10500: prefix continuation rejected structural order for mid.rs beside mid/leaf.rs")]
fn intersect_prefix_accepts_structural_seed_order() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "mod mid;\n")
        .file("src/mid.rs", "pub mod leaf; pub fn middle() {}\n")
        .file("src/mid/leaf.rs", "pub fn leaf() {}\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    for (left, expected) in [("(function)", 2), ("(function :name \"absent\")", 0)] {
        let query = CodeQuery::from_sexp(&format!(
            "(intersect (enclosing-decl (language rust {left}))
                (enclosing-decl (language rust (function))))"
        ))
        .unwrap();
        let files = plan_seed_files(&query.plan, &workspace.analyzer().analyzed_files());
        assert!(files.windows(2).any(|pair| pair[0] > pair[1]));
        let whole = whole_execution(&workspace, &query);
        assert_eq!(whole.result.completion(), CodeQueryCompletion::Complete);
        let detailed = decoded_intersect_execution(&workspace, &query)
            .detailed
            .expect("valid structural prefix continuation");
        assert_eq!(detailed.result.results.len(), expected);
        assert_eq!(
            projected(&detailed.result.results),
            projected(&whole.result.results)
        );
        assert_eq!(detailed.evidence, whole.evidence);
    }
}

#[test]
fn intersect_continuation_matches_whole_before_and_after_one_seed_edit() {
    let project = two_file_project();
    let query = CodeQuery::from_json(&json!({
        "schema_version": 1,
        "intersect": [
            { "match": { "kind": "function" } },
            { "union": [
                { "match": { "kind": "function", "name": { "regex": "^target" } } },
                { "match": { "kind": "function", "name": { "regex": "^caller" } } }
            ] }
        ],
        "steps": [{ "op": "filter", "where": [{ "field": "name", "op": "is_not_null" }] }],
        "limit": 500,
        "result_detail": "full"
    }))
    .expect("intersect query");
    let run = |workspace: &WorkspaceAnalyzer| {
        let files = seed_files_of(workspace);
        let prefixes = files
            .iter()
            .map(|seed| {
                let mut prefix = crate::structural::search::execute_intersect_prefix(
                    workspace.analyzer(),
                    &brokk_bifrost_flow::FlowWorkspaceState::default(),
                    None,
                    &query,
                    CodeQueryExecutionLimits::default(),
                    None,
                    CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(seed), &files),
                );
                let encoded = prefix
                    .encode_rows_json(&query.plan)
                    .expect("raw structural codec");
                prefix.operands.iter_mut().for_each(Vec::clear);
                prefix
                    .decode_rows_json(workspace.analyzer(), &query.plan, encoded)
                    .expect("hydrate the seed facts");
                prefix
            })
            .collect();
        let continued = crate::structural::search::continue_intersect_prefix(
            workspace.analyzer(),
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            None,
            &query,
            CodeQueryExecutionLimits::default(),
            None,
            &files,
            prefixes,
            CodeQueryExecutionScope::whole_workspace(),
        );
        let whole = whole_execution(workspace, &query);
        let detailed = continued.detailed.expect("complete prefix continuation");
        assert_eq!(continued.completion, whole.result.completion());
        assert_eq!(
            projected(&detailed.result.results),
            projected(&whole.result.results)
        );
        assert_eq!(detailed.evidence, whole.evidence);
    };
    let base = project.workspace_analyzer(AnalyzerConfig::default());
    run(&base);
    let files = seed_files_of(&base);
    let mut prefixes: Vec<_> = files
        .iter()
        .map(|seed| {
            crate::structural::search::execute_intersect_prefix(
                base.analyzer(),
                &brokk_bifrost_flow::FlowWorkspaceState::default(),
                None,
                &query,
                CodeQueryExecutionLimits::default(),
                None,
                CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(seed), &files),
            )
        })
        .collect();
    prefixes[0].reads_closed = false;
    let withheld = crate::structural::search::continue_intersect_prefix(
        base.analyzer(),
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        None,
        &query,
        CodeQueryExecutionLimits::default(),
        None,
        &files,
        prefixes,
        CodeQueryExecutionScope::whole_workspace(),
    );
    assert!(withheld.detailed.is_none());
    assert!(matches!(
        withheld.completion,
        CodeQueryCompletion::Incomplete { .. }
    ));
    project
        .file("src/caller.ts")
        .write("export function changed() { return 2; }\n")
        .expect("edit one seed");
    let head = project.workspace_analyzer(AnalyzerConfig::default());
    run(&head);
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

/// A caller expansion records the exact questions it asks, including the
/// empty at-bound question used to certify the frontier.
#[test]
#[hardwon("#11836: broad Scope reads invalidated unchanged caller expansions")]
fn a_callers_unit_records_every_consulted_answer() {
    let project = InlineTestProject::with_language(Language::Go)
        .with_git()
        .file("go.mod", "module example.com/repro\n\ngo 1.23\n")
        .file("target.go", "package repro\nfunc target() {}\n")
        .file("caller.go", "package repro\nfunc caller() { target() }\n")
        .file("other.go", "package repro\nfunc other() {}\n")
        .build();
    let base = project.workspace_analyzer(AnalyzerConfig::default());
    let keys = unit_read_keys(
        &base,
        &callers_query(),
        &project.file("target.go"),
        &seed_files_of(&base),
    );
    let callers = |keys: Vec<crate::analyzer::ReadKey>| {
        keys.into_iter()
            .filter(|key| {
                matches!(
                    key,
                    crate::analyzer::ReadKey::Lookup {
                        kind: crate::analyzer::LookupKind::Callers,
                        ..
                    }
                )
            })
            .collect::<Vec<_>>()
    };
    let reads = callers(keys);
    let mut names = reads
        .iter()
        .filter_map(|key| match key {
            crate::analyzer::ReadKey::Lookup {
                question: crate::analyzer::LookupQuestion::Declaration { fq_name, .. },
                ..
            } => Some(fq_name.as_ref()),
            _ => None,
        })
        .collect::<Vec<_>>();
    names.sort_unstable();
    assert_eq!(
        names,
        ["example.com/repro.caller", "example.com/repro.target"],
        "{reads:?}"
    );
    // Verify only these relation dependencies so incidental provider reads
    // cannot make a missing caller question pass the staleness checks.
    for (path, source, expected_unchanged, truncated) in [
        (
            "other.go",
            "package repro\nfunc other() {}\nfunc added() { other() }\n",
            true,
            false,
        ),
        (
            "other.go",
            "package repro\nfunc other() {}\nfunc added() { target() }\n",
            false,
            false,
        ),
        (
            "other.go",
            "package repro\nfunc other() {}\nfunc added() { caller() }\n",
            false,
            false,
        ),
        (
            "caller.go",
            "package repro\nfunc caller() {}\n",
            false,
            false,
        ),
        (
            "other.go",
            "package repro\nfunc other() { var x = 1; _ = x }\n",
            false,
            true,
        ),
    ] {
        project
            .file("other.go")
            .write("package repro\nfunc other() {}\n")
            .expect("reset other");
        project
            .file("caller.go")
            .write("package repro\nfunc caller() { target() }\n")
            .expect("reset caller");
        project
            .file(path)
            .write(source)
            .expect("edit caller fixture");
        let head = project.workspace_analyzer(AnalyzerConfig::default());
        let changed = crate::analyzer::ChangedFacts::between(&base, &head);
        let artifact = crate::analyzer::invalidation::DerivedArtifactId::new(
            crate::analyzer::invalidation::DerivedArtifactKind::PolicyEvaluationUnit,
            crate::analyzer::read_ledger::read_set_digest(&reads).digest(),
        );
        let mut replay_limits = crate::analyzer::LookupReplayLimits::default();
        if truncated {
            replay_limits.call_relations.max_candidates = 0;
        }
        let verdict = crate::analyzer::verify_read_set_for_artifact(
            artifact,
            &head,
            &changed,
            &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
            &reads,
            replay_limits,
            &crate::analyzer::NoSummaryAnswers,
            &mut crate::analyzer::LookupMemo::new(),
        );
        assert_eq!(
            verdict == crate::analyzer::ReadVerdict::Unchanged,
            expected_unchanged,
            "{source}: {verdict:?}"
        );
    }
}

// A warm hierarchy memo must retain the cross-file authority of its cold build.
// Other initially has no edge to Target, so the unit never opens other.go.
#[test]
#[hardwon("#7496: warm Go hierarchy reads omit the interface that changes supertypes")]
fn go_warm_supertypes_unit_rejects_an_unread_interface_edit() {
    use crate::analyzer::invalidation::{DerivedArtifactId, DerivedArtifactKind};
    use crate::analyzer::{
        ChangedFacts, LookupMemo, LookupReplayLimits, NoSummaryAnswers, ReadVerdict,
        verify_read_set_for_artifact,
    };

    let project = InlineTestProject::with_language(Language::Go)
        .with_git()
        .file("go.mod", "module example.com/repro\n\ngo 1.23\n")
        .file(
            "target.go",
            "package repro\ntype Target struct {}\nfunc (Target) Ping() {}\n",
        )
        .file(
            "other.go",
            "package repro\ntype Other interface { Missing() }\n",
        )
        .build();
    let base = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "schema_version": 1,
        "match": { "kind": "class", "name": { "regex": "Target$" } },
        "steps": [{ "op": "enclosing_decl" }, { "op": "supertypes" }],
        "limit": 100,
        "result_detail": "full"
    }))
    .expect("supertypes query");
    assert_eq!(
        crate::query::PlanPartitioning::classify(&query.plan),
        crate::query::PlanPartitioning::BySeed
    );
    let files = seed_files_of(&base);
    let seed = project.file("target.go");
    let run = |workspace: &WorkspaceAnalyzer, files: &[ProjectFile]| {
        execute_code_query_unit(
            workspace.analyzer(),
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            None,
            &query,
            CodeQueryExecutionLimits::default(),
            None,
            CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(&seed), files),
        )
    };
    // Warm the generation memo before attaching the unit's ledger.
    let go = brokk_bifrost_analysis::analyzer::resolve_analyzer::<GoAnalyzer>(base.analyzer())
        .expect("Go analyzer");
    assert_eq!(go.workspace_indexes_build_count_for_test(), 0);
    let warm = run(&base, &files);
    assert_eq!(go.workspace_indexes_build_count_for_test(), 1);
    assert!(
        warm.rows.is_empty(),
        "Target does not initially implement Other: {warm:?}"
    );
    let ledger = std::sync::Arc::new(crate::analyzer::read_ledger::ReadLedger::new());
    let before = {
        let _scope = crate::analyzer::AnalyzerQueryScope::with_read_ledger(
            base.analyzer(),
            std::sync::Arc::clone(&ledger),
        );
        run(&base, &files)
    };
    assert_eq!(
        go.workspace_indexes_build_count_for_test(),
        1,
        "unit used warm memo"
    );
    assert_eq!(before.rows, warm.rows);
    assert!(ledger.is_bounded(), "unit must be publishable");
    let reads = ledger.keys();
    assert!(
        reads.iter().any(|key| matches!(key,
            crate::analyzer::ReadKey::Lookup {
                question: crate::analyzer::LookupQuestion::WorkspaceFact {
                    family: crate::analyzer::WorkspaceFactFamily::GoWorkspaceIndexes,
                    language: Language::Go,
                    subject: crate::analyzer::FactSubject::Named { name },
                },
                ..
            } if name.as_ref() == "example.com/repro.Target"
        )),
        "the warm memo must record its replacement certificate: {reads:?}"
    );
    assert!(
        !reads.iter().any(|key| matches!(key,
            crate::analyzer::ReadKey::File { rel_path, .. } if rel_path.as_ref() == "other.go"
        )),
        "the edited file must not be directly read: {reads:?}"
    );
    project
        .file("other.go")
        .write("package repro\ntype Other interface { Ping() }\n")
        .expect("edit unread interface");
    let head = project.workspace_analyzer(AnalyzerConfig::default());
    let changed = ChangedFacts::between(&base, &head);
    assert!(changed.is_complete(), "{:?}", changed.incompleteness());
    assert_eq!(changed.changed_path_count(), 1);
    let artifact = DerivedArtifactId::new(
        DerivedArtifactKind::PolicyEvaluationUnit,
        crate::analyzer::read_ledger::read_set_digest(&reads).digest(),
    );
    let inputs = brokk_bifrost_analysis::test_support::read_ledger_test_inputs();
    let verdict = verify_read_set_for_artifact(
        artifact,
        &head,
        &changed,
        &inputs,
        &reads,
        LookupReplayLimits::default(),
        &NoSummaryAnswers,
        &mut LookupMemo::new(),
    );
    let after = run(&head, &seed_files_of(&head));
    eprintln!("GO_AUTHORITY reads={reads:?} verdict={verdict:?}");
    eprintln!(
        "GO_AUTHORITY before={:?} after={:?}",
        before.rows, after.rows
    );
    assert_ne!(before.rows, after.rows, "mutation must change the answer");
    assert_ne!(verdict, ReadVerdict::Unchanged, "accepted stale unit");
}

// The ancestor memo depends on global aliases collected across the workspace.
// Its warm answer must retain the authority of the global-using scan.
#[test]
#[hardwon("#7496: warm C# ancestors omit the global alias that selects the base type")]
fn csharp_warm_global_alias_unit_rejects_an_unread_using_edit() {
    use crate::analyzer::invalidation::{DerivedArtifactId, DerivedArtifactKind};
    use crate::analyzer::{
        ChangedFacts, LookupMemo, LookupReplayLimits, NoSummaryAnswers, ReadVerdict,
        verify_read_set_for_artifact,
    };

    let project = InlineTestProject::with_language(Language::CSharp)
        .with_git()
        .file("Globals.cs", "global using Parent = A.Base;\n")
        .file(
            "Parents.cs",
            "namespace A { public class Base {} }\nnamespace B { public class Base {} }\n",
        )
        .file(
            "Warm.cs",
            "namespace Warm { public class Target : Parent {} }\n",
        )
        .file("Target.cs", "public class Target : Parent {}\n")
        .build();
    let base = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "schema_version": 1,
        "match": { "kind": "class", "name": { "regex": "Target$" } },
        "steps": [{ "op": "enclosing_decl" }, { "op": "supertypes" }],
        "limit": 100,
        "result_detail": "full"
    }))
    .expect("supertypes query");
    assert_eq!(
        crate::query::PlanPartitioning::classify(&query.plan),
        crate::query::PlanPartitioning::BySeed
    );
    let files = seed_files_of(&base);
    let seed = project.file("Target.cs");
    let run = |workspace: &WorkspaceAnalyzer, seed: &ProjectFile, files: &[ProjectFile]| {
        execute_code_query_unit(
            workspace.analyzer(),
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            None,
            &query,
            CodeQueryExecutionLimits::default(),
            None,
            CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(seed), files),
        )
    };
    // Warm the workspace globals through a different seed, leaving Target's
    // own ancestor cache cold for the next evaluation.
    let warm = run(&base, &project.file("Warm.cs"), &files);
    assert_eq!(
        warm.rows.len(),
        1,
        "global alias resolves the warm seed: {warm:?}"
    );
    // Warm the captured seed too, so a cold per-type cache cannot contribute
    // incidental scope reads that disappear on the next unit evaluation.
    let warm_target = run(&base, &seed, &files);
    assert_eq!(warm_target.rows.len(), 1);
    let ledger = std::sync::Arc::new(crate::analyzer::read_ledger::ReadLedger::new());
    let before = {
        let _scope = crate::analyzer::AnalyzerQueryScope::with_read_ledger(
            base.analyzer(),
            std::sync::Arc::clone(&ledger),
        );
        run(&base, &seed, &files)
    };
    assert_eq!(
        before.rows.len(),
        1,
        "global alias resolves Target: {before:?}"
    );
    assert_eq!(before.rows, warm_target.rows);
    assert!(ledger.is_bounded(), "unit must be publishable");
    let reads = ledger.keys();
    assert!(
        reads.iter().any(|key| matches!(
            key,
            crate::analyzer::ReadKey::Lookup {
                question: crate::analyzer::LookupQuestion::WorkspaceFact {
                    family: crate::analyzer::WorkspaceFactFamily::CSharpGlobalUsingAliases,
                    language: Language::CSharp,
                    subject: crate::analyzer::FactSubject::Whole,
                },
                ..
            }
        )),
        "the warm memo must record its replacement certificate: {reads:?}"
    );
    assert!(
        !reads.iter().any(|key| matches!(key,
            crate::analyzer::ReadKey::File { rel_path, .. } if rel_path.as_ref() == "Globals.cs"
        )),
        "the edited file must not be directly read: {reads:?}"
    );
    project
        .file("Globals.cs")
        .write("global using Parent = B.Base;\n")
        .expect("edit unread global alias");
    let head = project.workspace_analyzer(AnalyzerConfig::default());
    let changed = ChangedFacts::between(&base, &head);
    assert!(changed.is_complete(), "{:?}", changed.incompleteness());
    assert_eq!(changed.changed_path_count(), 1);
    let artifact = DerivedArtifactId::new(
        DerivedArtifactKind::PolicyEvaluationUnit,
        crate::analyzer::read_ledger::read_set_digest(&reads).digest(),
    );
    let inputs = brokk_bifrost_analysis::test_support::read_ledger_test_inputs();
    let verdict = verify_read_set_for_artifact(
        artifact,
        &head,
        &changed,
        &inputs,
        &reads,
        LookupReplayLimits::default(),
        &NoSummaryAnswers,
        &mut LookupMemo::new(),
    );
    let after = run(&head, &seed, &seed_files_of(&head));
    eprintln!("CSHARP_AUTHORITY reads={reads:?} verdict={verdict:?}");
    eprintln!(
        "CSHARP_AUTHORITY before={:?} after={:?}",
        before.rows, after.rows
    );
    assert_ne!(before.rows, after.rows, "mutation must change the answer");
    assert_ne!(verdict, ReadVerdict::Unchanged, "accepted stale unit");
}

// The warm ancestor memo must retain the reads of its include-visible inputs.
#[test]
#[hardwon("#7496: warm C++ ancestors omit the included alias that selects the base type")]
fn cpp_warm_supertypes_unit_rejects_an_unread_header_edit() {
    use crate::analyzer::invalidation::{DerivedArtifactId, DerivedArtifactKind};
    use crate::analyzer::{
        ChangedFacts, LookupMemo, LookupReplayLimits, NoSummaryAnswers, ReadVerdict,
        verify_read_set_for_artifact,
    };

    let project = InlineTestProject::with_language(Language::Cpp)
        .with_git()
        .file(
            "parents.hpp",
            "namespace A { class Base {}; }\nnamespace B { class Base {}; }\n",
        )
        .file(
            "alias.hpp",
            "#include \"parents.hpp\"\nusing Parent = A::Base;\n",
        )
        .file(
            "target.cpp",
            "#include \"alias.hpp\"\nclass Target : public Parent {};\n",
        )
        .build();
    let base = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "schema_version": 1,
        "match": { "kind": "class", "name": { "regex": "Target$" } },
        "steps": [{ "op": "enclosing_decl" }, { "op": "supertypes" }],
        "limit": 100,
        "result_detail": "full"
    }))
    .expect("supertypes query");
    assert_eq!(
        crate::query::PlanPartitioning::classify(&query.plan),
        crate::query::PlanPartitioning::BySeed
    );
    let files = seed_files_of(&base);
    let seed = project.file("target.cpp");
    let run = |workspace: &WorkspaceAnalyzer, seed: &ProjectFile, files: &[ProjectFile]| {
        execute_code_query_unit(
            workspace.analyzer(),
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            None,
            &query,
            CodeQueryExecutionLimits::default(),
            None,
            CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(seed), files),
        )
    };
    // Warm the include-visible type table and the per-type ancestor memo.
    let cpp = brokk_bifrost_analysis::analyzer::resolve_analyzer::<CppAnalyzer>(base.analyzer())
        .expect("C++ analyzer");
    assert_eq!(cpp.visible_type_units_build_count_for_test(), 0);
    let warm_target = run(&base, &seed, &files);
    assert_eq!(
        warm_target.rows.len(),
        1,
        "included alias resolves a base: {warm_target:?}"
    );
    assert_eq!(cpp.visible_type_units_build_count_for_test(), 1);
    let ledger = std::sync::Arc::new(crate::analyzer::read_ledger::ReadLedger::new());
    let before = {
        let _scope = crate::analyzer::AnalyzerQueryScope::with_read_ledger(
            base.analyzer(),
            std::sync::Arc::clone(&ledger),
        );
        run(&base, &seed, &files)
    };
    assert_eq!(
        before.rows.len(),
        1,
        "included alias resolves Target: {before:?}"
    );
    assert_eq!(before.rows, warm_target.rows);
    assert_eq!(
        cpp.visible_type_units_build_count_for_test(),
        1,
        "captured unit uses warm memo"
    );
    assert!(ledger.is_bounded(), "unit must be publishable");
    let reads = ledger.keys();
    assert!(
        reads.iter().any(|key| matches!(key,
            crate::analyzer::ReadKey::File { rel_path, .. } if rel_path.as_ref() == "alias.hpp"
        )),
        "the warm memo must replay the edited header key: {reads:?}"
    );
    project
        .file("alias.hpp")
        .write("#include \"parents.hpp\"\nusing Parent = B::Base;\n")
        .expect("edit unread header alias");
    let head = project.workspace_analyzer(AnalyzerConfig::default());
    let changed = ChangedFacts::between(&base, &head);
    assert!(changed.is_complete(), "{:?}", changed.incompleteness());
    assert_eq!(changed.changed_path_count(), 1);
    let artifact = DerivedArtifactId::new(
        DerivedArtifactKind::PolicyEvaluationUnit,
        crate::analyzer::read_ledger::read_set_digest(&reads).digest(),
    );
    let inputs = brokk_bifrost_analysis::test_support::read_ledger_test_inputs();
    let verdict = verify_read_set_for_artifact(
        artifact,
        &head,
        &changed,
        &inputs,
        &reads,
        LookupReplayLimits::default(),
        &NoSummaryAnswers,
        &mut LookupMemo::new(),
    );
    let after = run(&head, &seed, &seed_files_of(&head));
    eprintln!("CPP_AUTHORITY reads={reads:?} verdict={verdict:?}");
    eprintln!(
        "CPP_AUTHORITY before={:?} after={:?}",
        before.rows, after.rows
    );
    assert_ne!(before.rows, after.rows, "mutation must change the answer");
    assert_ne!(verdict, ReadVerdict::Unchanged, "accepted stale unit");
}

// A warm ancestor vector must retain the reads that resolved its imported base.
#[test]
#[hardwon("#7496: warm Java ancestors omit the imported base declaration")]
fn java_warm_supertypes_unit_rejects_an_unread_base_edit() {
    use crate::analyzer::invalidation::{DerivedArtifactId, DerivedArtifactKind};
    use crate::analyzer::{
        ChangedFacts, LookupMemo, LookupReplayLimits, NoSummaryAnswers, ReadVerdict,
        verify_read_set_for_artifact,
    };

    let project = InlineTestProject::with_language(Language::Java)
        .with_git()
        .file("lib/Base.java", "package lib; public class Base {}\n")
        .file(
            "app/Target.java",
            "package app; import lib.Base; public class Target extends Base {}\n",
        )
        .build();
    let base = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "schema_version": 1,
        "match": { "kind": "class", "name": { "regex": "Target$" } },
        "steps": [{ "op": "enclosing_decl" }, { "op": "supertypes" }],
        "limit": 100,
        "result_detail": "full"
    }))
    .expect("supertypes query");
    assert_eq!(
        crate::query::PlanPartitioning::classify(&query.plan),
        crate::query::PlanPartitioning::BySeed
    );
    let files = seed_files_of(&base);
    let seed = project.file("app/Target.java");
    let run = |workspace: &WorkspaceAnalyzer, seed: &ProjectFile, files: &[ProjectFile]| {
        execute_code_query_unit(
            workspace.analyzer(),
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            None,
            &query,
            CodeQueryExecutionLimits::default(),
            None,
            CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(seed), files),
        )
    };
    // Warm the generation's per-type ancestor memo before attaching a ledger.
    let warm_target = run(&base, &seed, &files);
    assert_eq!(
        warm_target.rows.len(),
        1,
        "initial base resolves: {warm_target:?}"
    );
    let ledger = std::sync::Arc::new(crate::analyzer::read_ledger::ReadLedger::new());
    let before = {
        let _scope = crate::analyzer::AnalyzerQueryScope::with_read_ledger(
            base.analyzer(),
            std::sync::Arc::clone(&ledger),
        );
        run(&base, &seed, &files)
    };
    assert_eq!(
        before.rows.len(),
        1,
        "warm base resolves Target: {before:?}"
    );
    assert_eq!(before.rows, warm_target.rows);
    assert!(ledger.is_bounded(), "unit must be publishable");
    let reads = ledger.keys();
    assert!(
        reads.iter().any(|key| matches!(key,
            crate::analyzer::ReadKey::File { rel_path, .. } if rel_path.as_ref() == "lib/Base.java"
        )),
        "the shared file-state hit must retain the base input: {reads:?}"
    );
    project
        .file("lib/Base.java")
        .write("package lib; class Replacement {}\n")
        .expect("edit unread base input");
    let head = project.workspace_analyzer(AnalyzerConfig::default());
    let changed = ChangedFacts::between(&base, &head);
    assert!(changed.is_complete(), "{:?}", changed.incompleteness());
    assert_eq!(changed.changed_path_count(), 1);
    let artifact = DerivedArtifactId::new(
        DerivedArtifactKind::PolicyEvaluationUnit,
        crate::analyzer::read_ledger::read_set_digest(&reads).digest(),
    );
    let inputs = brokk_bifrost_analysis::test_support::read_ledger_test_inputs();
    let verdict = verify_read_set_for_artifact(
        artifact,
        &head,
        &changed,
        &inputs,
        &reads,
        LookupReplayLimits::default(),
        &NoSummaryAnswers,
        &mut LookupMemo::new(),
    );
    let after = run(&head, &seed, &seed_files_of(&head));
    eprintln!("JAVA_AUTHORITY reads={reads:?} verdict={verdict:?}");
    eprintln!(
        "JAVA_AUTHORITY before={:?} after={:?}",
        before.rows, after.rows
    );
    assert_ne!(before.rows, after.rows, "mutation must change the answer");
    assert_ne!(verdict, ReadVerdict::Unchanged, "accepted stale unit");
}

// A warm ancestor vector must retain the reads that resolved its imported base.
#[test]
#[hardwon("#7496: warm Kotlin ancestors omit the imported base declaration")]
fn kotlin_warm_supertypes_unit_rejects_an_unread_base_edit() {
    use crate::analyzer::invalidation::{DerivedArtifactId, DerivedArtifactKind};
    use crate::analyzer::{
        ChangedFacts, LookupMemo, LookupReplayLimits, NoSummaryAnswers, ReadVerdict,
        verify_read_set_for_artifact,
    };

    let project = InlineTestProject::with_language(Language::Kotlin)
        .with_git()
        .file("lib/Base.kt", "package lib\nopen class Base\n")
        .file(
            "app/Target.kt",
            "package app\nimport lib.Base\nclass Target : Base()\n",
        )
        .build();
    let base = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "schema_version": 1,
        "match": { "kind": "class", "name": { "regex": "Target$" } },
        "steps": [{ "op": "enclosing_decl" }, { "op": "supertypes" }],
        "limit": 100,
        "result_detail": "full"
    }))
    .expect("supertypes query");
    assert_eq!(
        crate::query::PlanPartitioning::classify(&query.plan),
        crate::query::PlanPartitioning::BySeed
    );
    let files = seed_files_of(&base);
    let seed = project.file("app/Target.kt");
    let run = |workspace: &WorkspaceAnalyzer, seed: &ProjectFile, files: &[ProjectFile]| {
        execute_code_query_unit(
            workspace.analyzer(),
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            None,
            &query,
            CodeQueryExecutionLimits::default(),
            None,
            CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(seed), files),
        )
    };
    // Warm the generation's per-type ancestor memo before attaching a ledger.
    let warm_target = run(&base, &seed, &files);
    assert_eq!(
        warm_target.rows.len(),
        1,
        "initial base resolves: {warm_target:?}"
    );
    let ledger = std::sync::Arc::new(crate::analyzer::read_ledger::ReadLedger::new());
    let before = {
        let _scope = crate::analyzer::AnalyzerQueryScope::with_read_ledger(
            base.analyzer(),
            std::sync::Arc::clone(&ledger),
        );
        run(&base, &seed, &files)
    };
    assert_eq!(
        before.rows.len(),
        1,
        "warm base resolves Target: {before:?}"
    );
    assert_eq!(before.rows, warm_target.rows);
    assert!(ledger.is_bounded(), "unit must be publishable");
    let reads = ledger.keys();
    assert!(
        reads.iter().any(|key| matches!(key,
            crate::analyzer::ReadKey::File { rel_path, .. } if rel_path.as_ref() == "lib/Base.kt"
        )),
        "the warm ancestor hit must replay the base input: {reads:?}"
    );
    project
        .file("lib/Base.kt")
        .write("package lib\nclass Replacement\n")
        .expect("edit unread base input");
    let head = project.workspace_analyzer(AnalyzerConfig::default());
    let changed = ChangedFacts::between(&base, &head);
    assert!(changed.is_complete(), "{:?}", changed.incompleteness());
    assert_eq!(changed.changed_path_count(), 1);
    let artifact = DerivedArtifactId::new(
        DerivedArtifactKind::PolicyEvaluationUnit,
        crate::analyzer::read_ledger::read_set_digest(&reads).digest(),
    );
    let inputs = brokk_bifrost_analysis::test_support::read_ledger_test_inputs();
    let verdict = verify_read_set_for_artifact(
        artifact,
        &head,
        &changed,
        &inputs,
        &reads,
        LookupReplayLimits::default(),
        &NoSummaryAnswers,
        &mut LookupMemo::new(),
    );
    let after = run(&head, &seed, &seed_files_of(&head));
    eprintln!("KOTLIN_AUTHORITY reads={reads:?} verdict={verdict:?}");
    eprintln!(
        "KOTLIN_AUTHORITY before={:?} after={:?}",
        before.rows, after.rows
    );
    assert_ne!(before.rows, after.rows, "mutation must change the answer");
    assert_ne!(verdict, ReadVerdict::Unchanged, "accepted stale unit");
}

// Reexport resolution reads bridge.py on a cold build, beyond the seed file.
#[test]
#[hardwon("#7496: warm Python ancestors omit the reexport that selects the base class")]
fn python_warm_supertypes_unit_rejects_an_unread_reexport_edit() {
    use crate::analyzer::invalidation::{DerivedArtifactId, DerivedArtifactKind};
    use crate::analyzer::{
        ChangedFacts, LookupMemo, LookupReplayLimits, NoSummaryAnswers, ReadVerdict,
        verify_read_set_for_artifact,
    };

    let project = InlineTestProject::with_language(Language::Python)
        .with_git()
        .file("a.py", "class Base:\n    pass\n")
        .file("b.py", "class Base:\n    pass\n")
        .file("bridge.py", "from a import Base as Parent\n")
        .file(
            "target.py",
            "from bridge import Parent\nclass Target(Parent):\n    pass\n",
        )
        .build();
    let base = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "schema_version": 1,
        "match": { "kind": "class", "name": { "regex": "Target$" } },
        "steps": [{ "op": "enclosing_decl" }, { "op": "supertypes" }],
        "limit": 100,
        "result_detail": "full"
    }))
    .expect("supertypes query");
    assert_eq!(
        crate::query::PlanPartitioning::classify(&query.plan),
        crate::query::PlanPartitioning::BySeed
    );
    let files = seed_files_of(&base);
    let seed = project.file("target.py");
    let run = |workspace: &WorkspaceAnalyzer, seed: &ProjectFile, files: &[ProjectFile]| {
        execute_code_query_unit(
            workspace.analyzer(),
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            None,
            &query,
            CodeQueryExecutionLimits::default(),
            None,
            CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(seed), files),
        )
    };
    // Warm the generation's per-type ancestor memo before attaching a ledger.
    let warm_target = run(&base, &seed, &files);
    assert_eq!(
        warm_target.rows.len(),
        1,
        "initial base resolves: {warm_target:?}"
    );
    let ledger = std::sync::Arc::new(crate::analyzer::read_ledger::ReadLedger::new());
    let before = {
        let _scope = crate::analyzer::AnalyzerQueryScope::with_read_ledger(
            base.analyzer(),
            std::sync::Arc::clone(&ledger),
        );
        run(&base, &seed, &files)
    };
    assert_eq!(
        before.rows.len(),
        1,
        "warm base resolves Target: {before:?}"
    );
    assert_eq!(before.rows, warm_target.rows);
    assert!(ledger.is_bounded(), "unit must be publishable");
    let reads = ledger.keys();
    assert!(
        reads.iter().any(|key| matches!(key,
            crate::analyzer::ReadKey::File { rel_path, .. } if rel_path.as_ref() == "bridge.py"
        )),
        "the warm ancestor hit must replay the reexport input: {reads:?}"
    );
    project
        .file("bridge.py")
        .write("from b import Base as Parent\n")
        .expect("edit unread base input");
    let head = project.workspace_analyzer(AnalyzerConfig::default());
    let changed = ChangedFacts::between(&base, &head);
    assert!(changed.is_complete(), "{:?}", changed.incompleteness());
    assert_eq!(changed.changed_path_count(), 1);
    let artifact = DerivedArtifactId::new(
        DerivedArtifactKind::PolicyEvaluationUnit,
        crate::analyzer::read_ledger::read_set_digest(&reads).digest(),
    );
    let inputs = brokk_bifrost_analysis::test_support::read_ledger_test_inputs();
    let verdict = verify_read_set_for_artifact(
        artifact,
        &head,
        &changed,
        &inputs,
        &reads,
        LookupReplayLimits::default(),
        &NoSummaryAnswers,
        &mut LookupMemo::new(),
    );
    let after = run(&head, &seed, &seed_files_of(&head));
    eprintln!("PYTHON_AUTHORITY reads={reads:?} verdict={verdict:?}");
    eprintln!(
        "PYTHON_AUTHORITY before={:?} after={:?}",
        before.rows, after.rows
    );
    assert_ne!(before.rows, after.rows, "mutation must change the answer");
    assert_ne!(verdict, ReadVerdict::Unchanged, "accepted stale unit");
}

fn reference_kind_fixture() -> ReferenceSiteValue {
    let file = ProjectFile::new(std::env::temp_dir(), "reference-kind.rs");
    let range = Range {
        start_byte: 10,
        end_byte: 20,
        start_line: 2,
        end_line: 2,
    };
    ReferenceSiteValue {
        file: file.clone(),
        range,
        target: DeclarationValue::new(
            CodeUnit::new(file.clone(), CodeUnitType::Function, "", "target"),
            range,
        ),
        enclosing: Some(DeclarationValue::new(
            CodeUnit::new(file, CodeUnitType::Function, "", "caller"),
            range,
        )),
        usage_kind: UsageHitKind::Reference,
        proof: UsageProof::Proven,
        reference_facets: brokk_bifrost_core::analyzer::usages::model::facets_from_classified(None),
    }
}

#[test]
fn call_site_unit_key_distinguishes_external_target_arms() {
    let file = ProjectFile::new(std::env::temp_dir(), "target-arms.rs");
    let range = Range {
        start_byte: 20,
        end_byte: 32,
        start_line: 2,
        end_line: 2,
    };
    let site = CallSite {
        file: file.clone(),
        range,
        callee_range: range,
        caller: CodeUnit::new(file.clone(), CodeUnitType::Function, "", "root"),
        callee: CodeUnit::file_scope(file),
        kind: CallSyntaxKind::Function,
        proof: UsageProof::Proven,
        receiver: None,
        arguments: Vec::new(),
    };
    let mut first = CallSiteValue::new(
        site,
        CallBindingStatus::Unavailable,
        None,
        CallSiteIdentityFacts::default(),
    );
    first.6 = Some(CallSiteTargetEvidence {
        static_proof: None,
        target_id: Some("external-one".to_string()),
        target_fq_name: Some("std.io.stdout".to_string()),
        boundary_kind: Some("external"),
        proof: "proven",
        completeness: "partial",
        coverage: "exhaustive",
        reason: None,
    });
    let key = unit_row_key(&PipelineValue::CallSite(first.clone()).key());
    for changed in [
        CallSiteTargetEvidence {
            target_id: Some("external-two".to_string()),
            ..first.6.clone().unwrap()
        },
        CallSiteTargetEvidence {
            boundary_kind: Some("unresolved"),
            ..first.6.clone().unwrap()
        },
        CallSiteTargetEvidence {
            coverage: "open",
            ..first.6.clone().unwrap()
        },
    ] {
        let mut other = first.clone();
        other.6 = Some(changed);
        assert_ne!(key, unit_row_key(&PipelineValue::CallSite(other).key()));
    }
}

#[test]
#[hardwon(
    "#3628: reference-site intersection must merge coarse and exact declaration-kind evidence"
)]
fn reference_site_intersection_merges_both_declaration_kinds() {
    let coarse = reference_kind_fixture();
    let mut exact = coarse.clone();
    exact.target = exact.target.with_structural_kind(NormalizedKind::Method);
    exact.enclosing = exact
        .enclosing
        .map(|decl| decl.with_structural_kind(NormalizedKind::Method));
    for enclosing in [false, true] {
        let mut coarse = coarse.clone();
        let mut exact = exact.clone();
        if !enclosing {
            coarse.enclosing = None;
            exact.enclosing = None;
        }
        for (left, right) in [
            (coarse.clone(), exact.clone()),
            (exact.clone(), coarse.clone()),
        ] {
            let mut value = PipelineValue::ReferenceSite(left);
            let other = PipelineValue::ReferenceSite(right);
            let key = value.key();
            assert_eq!(key, other.key());
            assert_eq!(unit_row_key(&key), unit_row_key(&other.key()));
            value.merge_intersect_evidence(other);
            assert_eq!(value.key(), key);
            let PipelineValue::ReferenceSite(site) = value else {
                unreachable!()
            };
            assert_eq!(site.target.kind_label(), "method");
            assert_eq!(
                site.enclosing.as_ref().map(DeclarationValue::kind_label),
                enclosing.then_some("method")
            );
        }
    }
}

/// The reference-site unit key is a persisted identity. Kind evidence and the
/// intersection merge must leave its recipe unchanged: the site, the target
/// declaration and range, the enclosing declaration by id alone, then usage
/// kind and proof; facet classification belongs to the row content.
#[test]
#[hardwon("#3628: declaration-kind evidence must not change persisted reference-site identity")]
fn reference_site_unit_key_is_independent_of_kind_evidence() {
    let coarse = reference_kind_fixture();
    let mut exact = coarse.clone();
    exact.target = exact.target.with_structural_kind(NormalizedKind::Method);
    exact.enclosing = exact
        .enclosing
        .map(|decl| decl.with_structural_kind(NormalizedKind::Method));
    let rendered = |value: &PipelineValue| {
        let key = unit_row_key(&value.key());
        std::iter::once(key.arm())
            .chain(key.parts().iter().map(|part| &**part))
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    let enclosing = coarse.enclosing.as_ref().unwrap();
    let expected = vec![
        "reference_site".to_string(),
        "reference-kind.rs".to_string(),
        "10:20:2:2".to_string(),
        coarse.target.unit.declaration_id().as_str().to_string(),
        "10:20:2:2".to_string(),
        format!("={}", enclosing.unit.declaration_id().as_str()),
        "reference".to_string(),
        "proven".to_string(),
    ];
    for (left, right) in [
        (coarse.clone(), exact.clone()),
        (exact.clone(), coarse.clone()),
    ] {
        let mut value = PipelineValue::ReferenceSite(left);
        assert_eq!(rendered(&value), expected);
        value.merge_intersect_evidence(PipelineValue::ReferenceSite(right));
        assert_eq!(rendered(&value), expected);
    }

    let key = unit_row_key(&PipelineValue::ReferenceSite(coarse.clone()).key());
    let mut absent = coarse.clone();
    absent.enclosing = None;
    let mut changed_target = coarse.clone();
    changed_target.target.range.end_byte += 1;
    let mut changed_site = coarse;
    changed_site.range.start_byte += 1;
    for distinct in [absent, changed_target, changed_site] {
        assert_ne!(
            key,
            unit_row_key(&PipelineValue::ReferenceSite(distinct).key())
        );
    }
}

#[test]
#[hardwon("#3628: reference-site unions must preserve declaration and target evidence identity")]
fn reference_site_union_keeps_whole_and_sliced_evidence_equal() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("Cargo.toml", "[package]\nname = \"reference-kinds\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
        .file("src/lib.rs", "pub mod caller;\npub struct PriceCalculator;\nimpl PriceCalculator { pub fn total() -> u64 { 42 } }\n")
        .file("src/caller.rs", "pub fn price() -> u64 { crate::PriceCalculator::total() }\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let files = seed_files_of(&workspace);
    let members = r#"(references-of (members (enclosing-decl (class :name "PriceCalculator"))))"#;
    let structural = r#"(references-of (enclosing-decl (method :name "total")))"#;
    for (left, right, expected) in [
        (members, structural, "function"),
        (structural, members, "method"),
    ] {
        let query = CodeQuery::from_sexp(&format!("(union {left} {right})")).unwrap();
        let whole = whole_execution(&workspace, &query);
        assert_eq!(whole.result.results.len(), 1, "{:#?}", whole.result);
        let CodeQueryResultValue::ReferenceSite { value } = &whole.result.results[0].value else {
            panic!("expected a reference site")
        };
        assert_eq!(value.target.kind, expected);
        let merged = merged(&workspace, &query, &files);
        assert_eq!(merged.items, projected(&whole.result.results));
        assert_eq!(merged.detailed_evidence(project.root()), whole.evidence);
    }
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
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
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
        Some(u64::try_from(unit.rows.len()).expect("row count fits")),
        "the final step's output count is the row count it produced"
    );
    assert!(
        unit.budgeted_work.step_outputs.as_ref().unwrap().len() >= query.plan.steps.len(),
        "every plan operator has an entry, so every step has one"
    );
}

#[hardwon(
    "#5294: persisted query units must preserve exact diagnostic sites and read older products"
)]
#[test]
fn python_format_diagnostic_sources_survive_persisted_unit_round_trip() {
    let source = "message = get_template().format()\n";
    let project = InlineTestProject::with_language(Language::Python)
        .file("formatting.py", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let files = seed_files_of(&workspace);
    let query = CodeQuery::from_sexp(
        "(filter :where ((relation eq str_format_mixed_fields) (outcome eq issue))
            (python-format-issues (language python (call))))",
    )
    .expect("format diagnostic query");
    let [unit]: [UnitExecutionResult; 1] = units(&workspace, &query, &files)
        .try_into()
        .expect("one unit");
    let encoded = serde_json::to_value(&unit).expect("persisted row product");
    let decoded: UnitExecutionResult =
        serde_json::from_value(encoded.clone()).expect("read row product");
    assert_eq!(serde_json::to_value(&decoded).unwrap(), encoded);
    let [diagnostic, predicate] = decoded.diagnostics.as_slice() else {
        panic!("the selected format relation and its row predicate are incomplete: {decoded:#?}");
    };
    assert_eq!(
        predicate.code,
        CodeQueryDiagnosticCode::RowPredicateUndecided
    );
    assert_eq!(
        predicate.withheld_rows_path.as_deref(),
        Some("formatting.py")
    );
    let location = diagnostic.source.as_ref().expect("persisted source span");
    assert_eq!(location.path, "formatting.py");
    assert_eq!((location.start_byte, location.end_byte), (10, 33));
    assert_eq!(
        location.range,
        CodeQueryRange {
            start_line: 1,
            start_column: 11,
            end_line: 1,
            end_column: 34,
        }
    );
    assert_eq!(
        &source[location.start_byte..location.end_byte],
        "get_template().format()"
    );

    // Old row products remain readable; cache identity forces their recomputation.
    let mut legacy = encoded;
    for diagnostic in legacy["diagnostics"].as_array_mut().unwrap() {
        diagnostic.as_object_mut().unwrap().remove("source");
    }
    let decoded: UnitExecutionResult =
        serde_json::from_value(legacy).expect("read legacy row product");
    assert!(
        decoded
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.source.is_none())
    );
}

#[hardwon("#5294: flattened nested unions used inherited alias filters to hide diagnostic gaps")]
#[test]
fn python_format_nested_union_filters_preserve_whole_diagnostic_scope_and_aliases() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("first.py", "message = \"{0} {}\".format(*values)\n")
        .file("second.py", "message = \"{0} {}\".format(*values)\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let diagnostics = |items: &[CodeQueryDiagnostic]| {
        let mut items = items
            .iter()
            .filter(|diagnostic| {
                diagnostic.code == CodeQueryDiagnosticCode::SemanticAnalysisPartial
            })
            .map(|diagnostic| serde_json::to_string(diagnostic).expect("diagnostic wire value"))
            .collect::<Vec<_>>();
        items.sort();
        items
    };
    for (local_relation, expected_diagnostics, expected_rows) in [
        // *values leaves only the two positional argument relations open.
        (None, 12, 2),
        (Some("str_format_mixed_fields"), 0, 2),
        (Some("str_format_missing_argument"), 6, 0),
    ] {
        let source = "(project :columns ((relation selected) outcome proof completeness)
            (python-format-issues (language python (call))))";
        let selected = local_relation.map_or_else(
            || source.to_string(),
            |relation| format!("(filter :where ((selected eq {relation})) {source})"),
        );
        let leaf = selected;
        let nested = format!(
            "(project :columns ((selected renamed) outcome proof completeness)
              (filter :where ((selected eq str_format_mixed_fields))
                (union {leaf} {leaf})))"
        );
        let other =
            format!("(project :columns ((selected renamed) outcome proof completeness) {leaf})");
        let query = CodeQuery::from_sexp(&format!(
            "(filter :where ((renamed eq str_format_mixed_fields))
                (union {nested} {other}))"
        ))
        .expect("nested format union with source aliases");
        assert!(matches!(
            crate::query::PlanPartitioning::classify(&query.plan),
            crate::query::PlanPartitioning::Whole(_)
        ));
        let whole = whole_execution(&workspace, &query);
        assert_eq!(
            whole.result.results.len(),
            expected_rows,
            "{local_relation:?}"
        );
        let whole_diagnostics = diagnostics(&whole.result.diagnostics);
        assert_eq!(
            whole_diagnostics.len(),
            expected_diagnostics,
            "{whole_diagnostics:#?}"
        );
        assert!(
            whole
                .result
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.source.is_some()),
            "{:#?}",
            whole.result.diagnostics
        );
    }
}

#[hardwon("#5310: union and intersection discarded projected aliases before outer filters")]
#[test]
fn set_operators_preserve_projected_aliases_and_survivor_evidence() {
    let source = "message = \"{0} {}\".format(\"a\", \"b\")\n";
    let project = InlineTestProject::with_language(Language::Python)
        .file("formatting.py", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let leaf = "(project :columns ((relation selected) outcome proof completeness)
        (python-format-issues (language python (call))))";
    for input in [
        leaf.to_string(),
        format!("(union {leaf} {leaf})"),
        format!("(intersect {leaf} {leaf})"),
        format!("(except {leaf} (filter :where ((outcome eq no_issue)) {leaf}))"),
    ] {
        let query = CodeQuery::from_sexp(&format!(
            "(result-detail full
                (filter :where ((renamed eq str_format_mixed_fields) (outcome eq issue))
                  (project :columns ((selected renamed) outcome proof completeness) {input})))"
        ))
        .expect("set query preserves the compatible projected schema");
        let whole = whole_execution(&workspace, &query);
        assert_eq!(
            whole.result.completion(),
            CodeQueryCompletion::Complete,
            "{whole:#?}"
        );
        let [item] = whole.result.results.as_slice() else {
            panic!("one mixed-fields issue for {input}: {whole:#?}");
        };
        let projected = UnitRowItem::project(item);
        assert!(matches!(
            projected.field("renamed").expect("surviving alias"),
            Some(CodeQueryRowScalarRef::ConstrainedEnum(
                "str_format_mixed_fields"
            ))
        ));
        let [evidence] = whole.evidence.as_slice() else {
            panic!("one source-backed row: {whole:#?}");
        };
        assert_eq!(evidence.result_index, 0);
        let span = evidence.byte_span.as_ref().expect("exact finding span");
        assert_eq!(&source[span.clone()], "\"{0} {}\"");
        assert!(evidence.source_slice_sha256.is_some());
        assert_eq!(evidence.provenance.len(), item.provenance.len());
        assert!(!item.provenance_truncated);
    }
}

#[hardwon("#5310: flattened union rows retained aliases that whole-query sets discarded")]
#[test]
fn projected_nested_union_units_match_whole_rows_and_detailed_evidence() {
    let project = eight_file_project();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let files = seed_files_of(&workspace);
    let leaf = "(filter :where ((selected is-not-null))
        (project :columns ((name selected)) (language typescript (call))))";
    let nested = format!("(project :columns ((selected renamed)) (union {leaf} {leaf}))");
    let query = CodeQuery::from_sexp(&format!(
        "(result-detail full
            (project :columns ((renamed final_name))
              (union {nested} (project :columns ((selected renamed)) {leaf}))))"
    ))
    .expect("nested union preserves compatible aliases across sets");
    assert_eq!(
        crate::query::PlanPartitioning::classify(&query.plan),
        crate::query::PlanPartitioning::BySeedUnion
    );
    let whole = whole_execution(&workspace, &query);
    assert_eq!(
        whole.result.completion(),
        CodeQueryCompletion::Complete,
        "{whole:#?}"
    );
    assert_eq!(whole.result.results.len(), 8, "{whole:#?}");
    let merged = assert_merged_units_match_whole(&project, &workspace, &query, &files, &whole);
    assert_eq!(merged.completion(), whole.result.completion());
    for item in &merged.items {
        assert!(matches!(
            item.field("final_name").expect("nested alias"),
            Some(CodeQueryRowScalarRef::String(_))
        ));
        assert_eq!(item.provenance.len(), 3);
    }
}

#[hardwon("#5310: compatible schemas can map the survivor's alias to different native fields")]
#[test]
fn projected_set_collisions_keep_the_first_rows_native_field_mapping() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("calls.py", "print(\"a\")\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let files = seed_files_of(&workspace);
    let named = "(project :columns ((name x)) (language python (call)))";
    let literal = "(project :columns ((string_value x)) (language python (call)))";
    for op in ["union", "intersect"] {
        for (first, second, expected) in [
            (named, literal, Some("print")),
            (literal, named, None),
            (named, named, Some("print")),
            (literal, literal, None),
        ] {
            let query =
                CodeQuery::from_sexp(&format!("(result-detail full ({op} {first} {second}))"))
                    .expect("native fields share one compatible optional-string schema");
            let whole = whole_execution(&workspace, &query);
            assert_eq!(
                whole.result.completion(),
                CodeQueryCompletion::Complete,
                "{whole:#?}"
            );
            if op == "union" {
                assert_eq!(
                    crate::query::PlanPartitioning::classify(&query.plan),
                    crate::query::PlanPartitioning::BySeedUnion
                );
                assert_merged_units_match_whole(&project, &workspace, &query, &files, &whole);
                let renamed = CodeQuery::from_sexp(&format!(
                    "(result-detail full (project :columns ((x selected)) (union {first} {second})))"
                )).expect("project-only union suffix");
                assert_eq!(
                    crate::query::PlanPartitioning::classify(&renamed.plan),
                    crate::query::PlanPartitioning::BySeedUnion
                );
                let renamed_whole = whole_execution(&workspace, &renamed);
                assert_merged_units_match_whole(
                    &project,
                    &workspace,
                    &renamed,
                    &files,
                    &renamed_whole,
                );
            }
            let [item]: [UnitRowItem; 1] = projected(&whole.result.results)
                .try_into()
                .expect("one call");
            let actual = item.field("x").expect("first row owns the alias");
            match expected {
                Some(expected) => assert!(
                    matches!(actual, Some(CodeQueryRowScalarRef::String(value)) if value == expected)
                ),
                None => assert!(actual.is_none(), "{actual:#?}"),
            }
        }
    }
    for (first, second, expected_rows) in [(named, literal, 0), (literal, named, 1)] {
        let query = CodeQuery::from_sexp(&format!(
            "(result-detail full (filter :where ((x is-null)) (union {first} {second})))"
        ))
        .expect("compatible projection counterexample");
        assert!(matches!(
            crate::query::PlanPartitioning::classify(&query.plan),
            crate::query::PlanPartitioning::Whole(_)
        ));
        let whole = whole_execution(&workspace, &query);
        assert_eq!(
            whole.result.completion(),
            CodeQueryCompletion::Complete,
            "{whole:#?}"
        );
        assert_eq!(
            whole.result.results.len(),
            expected_rows,
            "first writer must be chosen before filtering"
        );
    }
}

#[test]
#[hardwon("#5310: a union filter must read the first merged native field mapping in each file")]
fn seed_local_union_filters_match_whole_after_first_writer_merge() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("a.py", "print(\"a\")\n")
        .file("b.py", "print(\"b\")\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let files = seed_files_of(&workspace);
    let named = "(project :columns ((name x)) (language python (call)))";
    let literal = "(project :columns ((string_value x)) (language python (call)))";
    for (first, second, expected_rows) in [(named, literal, 0), (literal, named, 2)] {
        let query = CodeQuery::from_sexp(&format!(
            "(result-detail full (filter :where ((x is-null)) (union {first} {second})))"
        ))
        .expect("compatible projection counterexample");
        assert_eq!(
            crate::query::PlanPartitioning::classify(&query.plan),
            crate::query::PlanPartitioning::Whole(
                crate::query::PlanWidenDetail::UnionNonProjectSuffix
            )
        );
        let whole = whole_execution(&workspace, &query);
        assert_eq!(whole.result.results.len(), expected_rows);
        assert_merged_units_match_whole(&project, &workspace, &query, &files, &whole);
    }
}

#[test]
#[hardwon("#2445: a warm negative posting answer skipped the selected file's read key")]
fn warm_negative_postings_record_selected_files_without_hydration() {
    use crate::analyzer::{AnalyzerQueryScope, ReadLedger};
    use brokk_bifrost_analysis::analyzer::structural::index::StructuralIndexAcquisition;
    use std::sync::Arc;

    let project = two_file_project();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let providers = analyzer.structural_fact_providers();
    let provider = providers
        .iter()
        .find(|provider| provider.structural_language() == Language::TypeScript)
        .unwrap();
    let cache = provider.snapshot_structural_index_cache().unwrap().inner();
    assert!(matches!(
        cache.acquire(*provider, &CancellationToken::default()),
        StructuralIndexAcquisition::Ready { .. }
    ));
    let query = CodeQuery::from_json(&json!({
        "schema_version": 1,
        "match": { "kind": "function", "name": { "regex": "^absent$" } },
        "limit": 100,
        "result_detail": "full"
    }))
    .unwrap();
    let seed = project.file("src/callee.ts");
    let files = seed_files_of(&workspace);
    for _ in 0..2 {
        let ledger = Arc::new(ReadLedger::new());
        let before = cache.verdicts().totals();
        let result = {
            let _scope = AnalyzerQueryScope::with_read_ledger(analyzer, Arc::clone(&ledger));
            execute_code_query_unit(
                analyzer,
                &brokk_bifrost_flow::FlowWorkspaceState::default(),
                None,
                &query,
                CodeQueryExecutionLimits::default(),
                None,
                CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(&seed), &files),
            )
        };
        assert!(result.rows.is_empty());
        assert_eq!(result.completion, CodeQueryCompletion::Complete);
        assert_eq!(
            result.work.fact_nodes, 0,
            "the warmed index must avoid fact hydration"
        );
        assert!(
            cache.verdicts().totals().0 > before.0,
            "the complete cache must actually hit"
        );
        assert!(ledger.keys().iter().any(|key| matches!(key, crate::analyzer::ReadKey::File { rel_path, .. } if rel_path.as_ref() == "src/callee.ts")), "a negative hit still reads its selected file: {:?}", ledger.keys());
        assert!(
            !ledger
                .keys()
                .iter()
                .any(|key| matches!(key, crate::analyzer::ReadKey::Scope { .. }))
        );
    }
}

#[test]
fn dispatch_target_rows_keep_root_and_call_site_separate() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/startup.rs",
            "#[ctor]\n#[dtor]\n#[custom::ctor]\nfn startup() { let _ = std::fs::read(\"a\"); let _ = std::fs::read(\"b\"); }\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_sexp(
        r#"(result-detail full
          (filter :where ((target_fq_name regex "^std[.]"))
            (dispatch-targets
              (call-sites-from
                (enclosing-decl
                  (language rust
                    (decorator (name/regex "(^|::)(ctor|dtor)$"))))))))"#,
    )
    .expect("ctor root query");
    let detailed = crate::structural::search::execute_code_query_detailed_eager_index_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        &query,
        CodeQueryExecutionLimits::default(),
        None,
    );
    let targets = detailed
        .result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::DispatchTarget { value } => Some(value),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(targets.len(), 6, "{}", detailed.result.render_text());
    let roots = targets
        .iter()
        .map(|row| row.root_id.as_str())
        .collect::<HashSet<_>>();
    let sites = targets
        .iter()
        .map(|row| row.site_id.as_str())
        .collect::<HashSet<_>>();
    assert_eq!(roots.len(), 3);
    assert_eq!(sites.len(), 2);
    assert!(targets.iter().all(|row| row.target_count == Some(1)));
    assert!(
        targets
            .iter()
            .all(|row| row.boundary_reason == Some("external_body_unavailable"))
    );
    assert!(targets.iter().all(|row| row.range.start_line == 4));
    assert!(
        targets
            .iter()
            .all(|row| row.range.start_column != row.range.end_column)
    );
}

#[test]
fn java_parameter_annotation_keeps_lexical_enclosing_method() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "A.java",
            "class A { void method(@Valid String value) {} }\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_sexp("(enclosing-decl (language java (decorator)))")
        .expect("Java parameter decorator query");
    let result = crate::structural::search::execute_code_query_detailed_eager_index_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        &query,
        CodeQueryExecutionLimits::default(),
        None,
    );
    assert!(
        result.result.results.iter().any(|item| matches!(
            &item.value,
            CodeQueryResultValue::Declaration { value }
                if value.fq_name.ends_with(".method")
        )),
        "{}",
        result.result.render_text()
    );
}

#[test]
fn rust_callees_depth_is_a_complete_query_bound() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            "fn root() { helper(); }\nfn helper() { leaf(); }\nfn leaf() {}\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_sexp(
        r#"(callees :depth 1 (enclosing-decl (language rust (function (name "root")))))"#,
    )
    .expect("bounded callees query");
    let result = crate::structural::search::execute_code_query_detailed_eager_index_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        &query,
        CodeQueryExecutionLimits::default(),
        None,
    );
    assert_eq!(result.result.completion(), CodeQueryCompletion::Complete);
    let names = result
        .result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::Declaration { value } => Some(value.fq_name.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(names.len(), 1, "{names:?}");
    assert_eq!(names[0], "helper");
}

#[test]
fn rust_call_sites_from_excludes_unreached_nested_callable() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            "fn root() { let deferred = || std::fs::read(\"later\"); let _ = std::fs::read(\"now\"); }\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_sexp(
        r#"(call-sites-from (enclosing-decl (language rust (function (name "root")))))"#,
    )
    .expect("source call sites query");
    let result = crate::structural::search::execute_code_query_detailed_eager_index_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        &query,
        CodeQueryExecutionLimits::default(),
        None,
    );
    assert_eq!(
        result.result.results.len(),
        1,
        "{}",
        result.result.render_text()
    );
}

#[test]
fn rust_call_sites_from_preserves_internal_external_and_unresolved_sites() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            "fn root() { local(); let _ = std::fs::read(\"x\"); missing(); }\nfn local() {}\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_sexp(
        r#"(call-sites-from (enclosing-decl (language rust (function (name "root")))))"#,
    )
    .expect("source call sites query");
    let result = crate::structural::search::execute_code_query_detailed_eager_index_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        &query,
        CodeQueryExecutionLimits::default(),
        None,
    );
    let sites = result
        .result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::CallSite { value } => Some(value.as_ref()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(sites.len(), 3, "{}", result.result.render_text());
    assert_eq!(sites.iter().filter(|site| site.callee.is_some()).count(), 1);
    assert!(
        sites
            .iter()
            .any(|site| site.target_fq_name.as_deref() == Some("std.fs.read"))
    );
    assert!(
        sites
            .iter()
            .any(|site| site.boundary_kind == Some("unresolved"))
    );
}

#[test]
fn rust_call_sites_from_marks_opaque_macro_body_incomplete() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            "macro_rules! invoke { () => { local(); } }\nfn root() { invoke!(); }\nfn local() {}\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_sexp(
        r#"(call-sites-from (enclosing-decl (language rust (function (name "root")))))"#,
    )
    .expect("macro call site query");
    let result = crate::structural::search::execute_code_query_detailed_eager_index_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        &query,
        CodeQueryExecutionLimits::default(),
        None,
    );
    assert!(
        matches!(
            result.result.completion(),
            CodeQueryCompletion::Incomplete { .. }
        ),
        "{}",
        result.result.render_text()
    );
}

#[test]
fn opaque_macro_does_not_hide_other_root_dispatch_targets() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            "macro_rules! invoke { () => { hidden(); } }\n#[ctor]\nfn first() { invoke!(); }\n#[ctor]\nfn second() { let _ = std::fs::read(\"now\"); }\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_sexp(
        r#"(dispatch-targets (call-sites-from (enclosing-decl (language rust (decorator (name/regex "(^|::)ctor$"))))))"#,
    )
    .expect("ctor dispatch targets");
    let result = crate::structural::search::execute_code_query_detailed_eager_index_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        &query,
        CodeQueryExecutionLimits::default(),
        None,
    );
    assert!(
        result.result.results.iter().any(|item| matches!(
            &item.value,
            CodeQueryResultValue::DispatchTarget { value }
                if value.target_fq_name.as_deref() == Some("std.fs.read")
        )),
        "{}",
        result.result.render_text()
    );
    assert!(matches!(
        result.result.completion(),
        CodeQueryCompletion::Incomplete { .. }
    ));
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "dc6a9b891853: non-opt-in prefix replay synthesized depth evidence for a skipped operand"
)]
fn depth_consumer_absence_survives_encoded_prefix_replay() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            "pub fn target() {} pub fn middle() { target(); } pub fn root() { middle(); }",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    // Empty operand zero exercises exact skipped-traversal reconciliation too.
    for name in ["middle", "missing"] {
        let query = CodeQuery::from_sexp(&format!(
            "(intersect (enclosing-decl (language rust (function :name \"{name}\"))) (callers :depth 1 :proof proven (enclosing-decl (language rust (function :name \"target\")))))"
        )).unwrap();
        let files = seed_files_of(&workspace);
        for opted_in in [false, true] {
            let scope =
                CodeQueryExecutionScope::whole_workspace().with_depth_bound_status(opted_in);
            let whole = execute_code_query_detailed_eager_index_workspace_in_scope(
                &workspace,
                &brokk_bifrost_flow::FlowWorkspaceState::default(),
                &query,
                CodeQueryExecutionLimits::default(),
                None,
                scope.clone(),
            );
            let prefixes = files.iter().map(|seed| {
                let prefix = crate::structural::search::execute_intersect_prefix(
                    workspace.analyzer(), &brokk_bifrost_flow::FlowWorkspaceState::default(),
                    Some(&workspace), &query, CodeQueryExecutionLimits::default(), None,
                    CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(seed), &files).with_depth_bound_status(opted_in));
                let json = prefix.encode_product_json(&query.plan).unwrap();
                assert_eq!(json.get("depth_bound_status").is_some(), opted_in);
                assert_eq!(json.get("depth_answers").is_some(), opted_in);
                crate::structural::search::IntersectPrefixProduct::decode_product_json_with_workspace(
                    workspace.analyzer(), Some(&workspace), &query.plan, seed.clone(), prefix.reads.clone(), json).unwrap()
            }).collect();
            let continued = crate::structural::search::continue_intersect_prefix(
                workspace.analyzer(),
                &brokk_bifrost_flow::FlowWorkspaceState::default(),
                Some(&workspace),
                &query,
                CodeQueryExecutionLimits::default(),
                None,
                &files,
                prefixes,
                scope,
            );
            assert_eq!(
                continued.depth_bound_status,
                whole.result.depth_bound_status
            );
            if !opted_in {
                assert_eq!(continued.depth_bound_status, None);
                assert!(continued.detailed.unwrap().depth_answers.is_empty());
            }
        }
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "891ba9efd037: an absent selector language yielded no units and lost depth completion"
)]
fn empty_partition_depth_status_equals_whole_in_both_consumer_modes() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", "pub fn unrelated() {}")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let seed = "(enclosing-decl (language typescript (function :name \"missing\")))";
    for source in [
        seed.to_owned(),
        format!("(callers :depth 1 {seed})"),
        format!("(callees :depth 1 {seed})"),
        format!("(union {seed} (callers :depth 1 {seed}))"),
        format!("(except {seed} (callers :depth 1 {seed}))"),
        format!("(intersect {seed} (callers :depth 1 {seed}))"),
        format!("(callees :depth 1 (except {seed} (callers :depth 1 {seed})))"),
    ] {
        let query = CodeQuery::from_sexp(&source).unwrap();
        assert!(plan_seed_files(&query.plan, &workspace.analyzer().analyzed_files()).is_empty());
        for opted_in in [false, true] {
            let scope =
                CodeQueryExecutionScope::whole_workspace().with_depth_bound_status(opted_in);
            let whole = execute_code_query_detailed_eager_index_workspace_in_scope(
                &workspace,
                &brokk_bifrost_flow::FlowWorkspaceState::default(),
                &query,
                CodeQueryExecutionLimits::default(),
                None,
                scope.clone(),
            );
            if matches!(
                crate::query::PlanPartitioning::classify_for_prefix(&query.plan),
                crate::query::PlanPartitioning::Prefix { .. }
            ) {
                let prefix = crate::structural::search::continue_intersect_prefix(
                    workspace.analyzer(),
                    &brokk_bifrost_flow::FlowWorkspaceState::default(),
                    Some(&workspace),
                    &query,
                    CodeQueryExecutionLimits::default(),
                    None,
                    &[],
                    Vec::new(),
                    scope.clone(),
                );
                assert_eq!(
                    prefix.depth_bound_status, whole.result.depth_bound_status,
                    "empty prefix: {source}, opted_in={opted_in}"
                );
            }
            let merged = merge_unit_rows_in_scope(&query, [], scope);
            assert_eq!(
                merged.depth_bound_status, whole.result.depth_bound_status,
                "{source}, opted_in={opted_in}"
            );
            if !opted_in {
                assert_eq!(merged.depth_bound_status, None);
            }
        }
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "891ba9efd037: a cancelled union leaf lost Unknown when it retained no depth answer rows"
)]
fn cancelled_seed_union_preserves_leaf_depth_status_without_answers() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", "pub fn target() {}")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_sexp(
        "(union (callers :depth 1 (enclosing-decl (language rust (function :name \"target\")))) (callees :depth 1 (enclosing-decl (language rust (function :name \"target\")))))"
    ).unwrap();
    assert!(crate::query::PlanPartitioning::classify(&query.plan).is_seed_union());
    assert!(!crate::query::PlanPartitioning::union_has_post_merge_suffix(&query.plan));
    let files = workspace.analyzer().analyzed_files();
    assert_eq!(files.len(), 1);
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    for opted_in in [false, true] {
        let unit = execute_code_query_unit(
            workspace.analyzer(),
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            Some(&workspace),
            &query,
            CodeQueryExecutionLimits::default(),
            Some(&cancellation),
            CodeQueryExecutionScope::for_seed_files(&files, &files)
                .with_depth_bound_status(opted_in),
        );
        assert!(unit.truncated);
        assert!(unit.depth_answers.is_empty());
        assert_eq!(
            unit.depth_bound_status,
            opted_in.then_some(DepthBoundStatus::Unknown)
        );
    }
}

#[test]
#[hardwon("6e42bd3c51b4: incomplete upstream seed selection falsely certified a depth witness")]
fn incomplete_seed_selection_cannot_certify_depth_witness() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", "fn target() {} fn middle() { target(); } pub fn root() { middle(); } pub fn extra() { let _unknown = || {}; }")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    for incomplete in [false, true] {
        let seed = if incomplete {
            "(enclosing-decl (language rust (callable :visibility public)))"
        } else {
            "(enclosing-decl (language rust (function :name \"root\")))"
        };
        let input = whole_execution(&workspace, &CodeQuery::from_sexp(seed).unwrap());
        assert!(!input.result.results.is_empty());
        assert_eq!(
            input.result.completion() != CodeQueryCompletion::Complete,
            incomplete
        );
        if incomplete {
            assert!(
                input
                    .result
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code
                        == CodeQueryDiagnosticCode::UnsupportedStructuralFeature
                        && diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete)
            );
        }
        let query = CodeQuery::from_sexp(&format!("(callees :depth 1 {seed})")).unwrap();
        let whole = whole_execution(&workspace, &query);
        assert_eq!(
            whole.result.depth_bound_status,
            Some(if incomplete {
                DepthBoundStatus::Unknown
            } else {
                DepthBoundStatus::Reached
            })
        );
        let files = plan_seed_files(&query.plan, &workspace.analyzer().analyzed_files());
        let merged = merge_unit_rows(&query, units(&workspace, &query, &files));
        assert_eq!(merged.depth_bound_status, whole.result.depth_bound_status);
    }
}

#[test]
#[hardwon(
    "73424603f285: seed excepts retained right depth proofs after a merged complete-empty left"
)]
fn exact_empty_set_prefix_discards_only_skipped_depth_answers() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            "pub fn leaf() {} pub fn root() { leaf(); } pub fn beyond() { root(); }",
        )
        .file("other.rs", "pub fn unrelated() {}")
        .build();
    // Persisted wire contract from dc6a9b891853, before the except proof field.
    #[derive(serde::Serialize)]
    struct PreviousUnitProduct<'a> {
        rows: &'a Vec<crate::structural::search::units::UnitRow>,
        work: CodeQueryExecutionWork,
        budgeted_work: &'a CodeQueryBudgetedWork,
        completion: &'a CodeQueryCompletion,
        #[serde(skip_serializing_if = "Option::is_none")]
        depth_bound_status: Option<DepthBoundStatus>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        depth_answers: &'a Vec<crate::structural::search::units::BoundedCallAnswer>,
        diagnostics: &'a Vec<CodeQueryDiagnostic>,
        truncated: bool,
    }
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let empty = "(enclosing-decl (language rust (function :name \"missing\")))";
    let reached = "(callers :depth 1 (enclosing-decl (language rust (function :name \"leaf\"))))";
    let reached_empty = format!("(filter :where ((fq_name regex \"^never/\")) {reached})");
    for operator in ["except", "intersect"] {
        for (left, expected) in [
            (empty.to_owned(), DepthBoundStatus::NotReached),
            (reached_empty.clone(), DepthBoundStatus::Reached),
        ] {
            let query = CodeQuery::from_sexp(&format!("({operator} {left} {reached})")).unwrap();
            let files = plan_seed_files(&query.plan, &workspace.analyzer().analyzed_files());
            assert_eq!(
                files.len(),
                2,
                "a non-empty seed inventory must not be confused with no units"
            );
            for file in &files {
                let product = execute_code_query_unit(
                    workspace.analyzer(),
                    &brokk_bifrost_flow::FlowWorkspaceState::default(),
                    Some(&workspace),
                    &query,
                    CodeQueryExecutionLimits::default(),
                    None,
                    CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(file), &files)
                        .with_depth_bound_status(false),
                );
                assert_eq!(product.except_left_complete_empty, None);
                assert_eq!(product.depth_bound_status, None);
                assert!(product.depth_answers.is_empty());
                let previous = PreviousUnitProduct {
                    rows: &product.rows,
                    work: product.work,
                    budgeted_work: &product.budgeted_work,
                    completion: &product.completion,
                    depth_bound_status: product.depth_bound_status,
                    depth_answers: &product.depth_answers,
                    diagnostics: &product.diagnostics,
                    truncated: product.truncated,
                };
                assert_eq!(
                    serde_json::to_vec(&product).unwrap(),
                    serde_json::to_vec(&previous).unwrap(),
                    "opted-out wire bytes changed: {operator}: {left}"
                );
            }
            let whole = whole_execution(&workspace, &query);
            assert!(whole.result.results.is_empty());
            assert_eq!(whole.result.completion(), CodeQueryCompletion::Complete);
            assert_eq!(
                whole.result.depth_bound_status,
                Some(expected),
                "{operator}: {left}"
            );
            for _ in 0..2 {
                let products = units(&workspace, &query, &files);
                if operator == "except" {
                    assert!(
                        products
                            .iter()
                            .all(|product| product.except_left_complete_empty == Some(true))
                    );
                    let replayed = products
                        .iter()
                        .map(|product| {
                            serde_json::from_value::<UnitExecutionResult>(
                                serde_json::to_value(product).unwrap(),
                            )
                            .unwrap()
                        })
                        .collect::<Vec<_>>();
                    let merged = merge_unit_rows(&query, replayed);
                    assert_eq!(merged.depth_bound_status, Some(expected));
                }
                let continued = decoded_intersect_execution(&workspace, &query);
                assert_eq!(
                    continued.depth_bound_status,
                    Some(expected),
                    "prefix {operator}: {left}"
                );
                assert!(continued.detailed.unwrap().result.results.is_empty());
            }
        }
    }
    let local = CodeQuery::from_sexp(&format!(
        "(except {empty} (enclosing-decl (language rust (function))))"
    ))
    .unwrap();
    assert_eq!(
        crate::query::PlanPartitioning::classify(&local.plan),
        crate::query::PlanPartitioning::BySeedExcept
    );
    let files = plan_seed_files(&local.plan, &workspace.analyzer().analyzed_files());
    assert!(
        units(&workspace, &local, &files)
            .iter()
            .all(|unit| unit.except_left_complete_empty == Some(true))
    );
}

#[test]
#[hardwon(
    "7710ee31a0ec: empty union operands incorrectly discarded other operands' depth witnesses"
)]
fn union_empty_operand_never_discards_depth_witnesses() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            "pub fn root() { middle(); } fn middle() { target(); } fn target() {}",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let empty = "(callers :depth 1 (enclosing-decl (language rust (function :name \"missing\"))))";
    let reached = "(callers :depth 1 (enclosing-decl (language rust (function :name \"target\"))))";
    for source in [
        format!("(union {empty} {reached})"),
        format!("(union {reached} {empty})"),
    ] {
        let query = CodeQuery::from_sexp(&source).unwrap();
        let whole = whole_execution(&workspace, &query);
        assert_eq!(
            whole.result.depth_bound_status,
            Some(DepthBoundStatus::Reached)
        );
        for _ in 0..2 {
            let continued = decoded_intersect_execution(&workspace, &query);
            assert_eq!(
                continued.depth_bound_status, whole.result.depth_bound_status,
                "{source}"
            );
        }
    }
}

#[test]
#[hardwon("#11267: retained pointer rows lost source evidence and independent sources")]
fn pointer_sources_survive_retained_terminal_json() {
    // Pin legacy non-pointer bytes as well as the new, plural wire boundary.
    let legacy = r#"{"terminal_kind":"source_position"}"#;
    let old: UnitRowItemTerminal = serde_json::from_str(legacy).expect("legacy terminal");
    assert_eq!(serde_json::to_string(&old).unwrap(), legacy);
    let range = CodeQueryRange {
        start_line: 1,
        start_column: 1,
        end_line: 1,
        end_column: 3,
    };
    let sources = vec![
        CodeQuerySourceSpan {
            path: "first.rs".into(),
            range,
            start_byte: 0,
            end_byte: 2,
        },
        CodeQuerySourceSpan {
            path: "second.rs".into(),
            range,
            start_byte: 0,
            end_byte: 2,
        },
    ];
    let terminal = UnitRowItemTerminal::RustPointerFinding {
        source_ranges: sources.clone(),
        source_ranges_omitted: brokk_bifrost_core::omission::OmissionCount::lower_bound(1),
    };
    let bytes = serde_json::to_vec(&terminal).expect("retained pointer terminal");
    let decoded: UnitRowItemTerminal =
        serde_json::from_slice(&bytes).expect("replayed pointer terminal");
    assert_eq!(decoded, terminal);
    assert_eq!(serde_json::to_vec(&decoded).unwrap(), bytes);
    let UnitRowItemTerminal::RustPointerFinding {
        source_ranges,
        source_ranges_omitted,
    } = decoded
    else {
        panic!("pointer terminal");
    };
    assert_eq!(source_ranges, sources);
    assert_eq!(
        source_ranges_omitted,
        brokk_bifrost_core::omission::OmissionCount::lower_bound(1)
    );
}

#[test]
#[hardwon("#11552: nested source diagnostics kept inner paths and panicked in an outer union leaf")]
fn call_reachability_nested_source_diagnostics_keep_the_outer_leaf_path() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("app.rs", "fn unrelated() { selected_sink_0(); unknown_external(); }\nfn selected_sink_0() {}\nfn entry_1() { selected_sink_1(); }\nfn selected_sink_1() {}\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let files = seed_files_of(&workspace);
    assert_eq!(files.len(), 1);
    let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
    let partial = r#"(callees (enclosing-decl (language rust (function :name "unrelated"))))"#;
    let definite = r#"(language rust (function :name "entry_1"))"#;
    for incomplete_branch in [0, 1] {
        let sources = if incomplete_branch == 0 {
            format!("(union {partial} {definite})")
        } else {
            format!("(union {definite} {partial})")
        };
        let query = CodeQuery::from_source(&format!(
            r#"(union (call-reachability
                    :sources (language rust (function :name "missing"))
                    :sinks (language rust (call :callee (name "selected_sink_1"))))
                (call-reachability :sources {sources}
                    :sinks (language rust (call :callee (name "selected_sink_1")))))"#,
        ))
        .unwrap();
        assert!(
            crate::query::PlanPartitioning::classify(&query.plan).is_seed_union(),
            "the regression must execute authored union leaves, not widen"
        );
        let cold = execute_code_query_unit(
            workspace.analyzer(),
            &flow,
            Some(&workspace),
            &query,
            CodeQueryExecutionLimits::default(),
            None,
            CodeQueryExecutionScope::whole_workspace(),
        );
        assert_ne!(cold.completion, CodeQueryCompletion::Complete);
        assert_eq!(
            cold.rows.len(),
            1,
            "the independently certified path remains additive"
        );
        let CodeQueryPlanSource::Set { branches, .. } = &query.plan.source else {
            panic!("outer union");
        };
        let CodeQueryPlanSource::CallReachability(operator) = &branches[1].source else {
            panic!("projecting leaf");
        };
        for prepared in [false, true] {
            let mut scope = CodeQueryExecutionScope::for_seed_files(&files, &files);
            if prepared {
                let source_query = CodeQuery {
                    plan: operator.sources.clone(),
                    limit: usize::MAX,
                    ..query.clone()
                };
                let source = execute_call_reachability_source(
                    workspace.analyzer(),
                    &flow,
                    Some(&workspace),
                    &source_query,
                    CodeQueryExecutionLimits::default(),
                    None,
                    CodeQueryExecutionScope::for_seed_files(&files, &files),
                );
                let mut operands = CallReachabilityOperands::default();
                operands.insert_source(&operator.sources, source);
                scope = scope.with_call_reachability_operands(std::sync::Arc::new(operands));
            }
            // Inner branch 0 differs from the outer leaf's 1. Inner branch 1
            // coincides with it, so starts_with cannot detect an omitted prefix.
            // Prepared operands must receive that prefix exactly once as well.
            let narrowed = execute_code_query_unit(
                workspace.analyzer(),
                &flow,
                Some(&workspace),
                &query,
                CodeQueryExecutionLimits::default(),
                None,
                scope,
            );
            assert_eq!(narrowed.completion, cold.completion);
            assert_eq!(
                serde_json::to_value(&narrowed.rows).unwrap(),
                serde_json::to_value(&cold.rows).unwrap()
            );
            let expected = vec![1, incomplete_branch];
            assert!(
                narrowed
                    .diagnostics
                    .iter()
                    .any(
                        |diagnostic| diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete
                            && diagnostic.branch == expected
                    ),
                "inner diagnostic belongs to {expected:?}: {:?}",
                narrowed.diagnostics
            );
            for diagnostic in &narrowed.diagnostics {
                if diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete {
                    assert!(
                        diagnostic.branch == [1] || diagnostic.branch == expected,
                        "an outer prefix is neither omitted nor duplicated: {diagnostic:?}"
                    );
                }
            }
        }
    }
}

#[test]
#[hardwon("#11836: an earlier caller query's scan work consumed a later query's allowance")]
fn caller_budget_ignores_unrelated_scan_work_increase() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .with_git()
        .file(
            "target.ts",
            "export function earlier() {}\nexport function later() {}\n",
        )
        .file(
            "caller.ts",
            "import { later } from './target';\nexport function caller() { later(); }\n",
        )
        .file("other.ts", "export function unrelated() { return 1; }\n")
        .build();
    // The aggregate user cap must cover both physical scans to isolate admission from scan work.
    let limits = CodeQueryExecutionLimits {
        max_scanned_source_bytes: 65_536,
        ..CodeQueryExecutionLimits::default()
    };
    let run = |workspace: &WorkspaceAnalyzer| {
        let analyzer = workspace.analyzer();
        let declarations = analyzer.declarations(&project.file("target.ts"));
        let earlier = declarations
            .iter()
            .find(|unit| unit.fq_name().to_string().ends_with("earlier"))
            .expect("earlier");
        let later = declarations
            .iter()
            .find(|unit| unit.fq_name().to_string().ends_with("later"))
            .expect("later");
        let ledger = std::sync::Arc::new(crate::analyzer::read_ledger::ReadLedger::new());
        let scope = AnalyzerQueryScope::with_read_ledger(analyzer, std::sync::Arc::clone(&ledger));
        let mut cache = CallTraversalCache::default();
        let mut budget = CodeQueryExecutionBudget::default();
        let first = cached_call_relation(
            analyzer,
            scope.token(),
            earlier,
            true,
            &mut cache,
            &mut budget,
            limits,
            None,
            &mut Vec::new(),
            &mut None,
        );
        let fresh = budgeted_execution_work(budget, Some(Vec::new()), Some(0));
        let mut reused_budget = CodeQueryExecutionBudget::default();
        let reused = cached_call_relation(
            analyzer,
            scope.token(),
            earlier,
            true,
            &mut cache,
            &mut reused_budget,
            limits,
            None,
            &mut Vec::new(),
            &mut None,
        );
        assert!(!reused.truncated);
        let replayed = budgeted_execution_work(reused_budget, Some(Vec::new()), Some(0));
        assert_eq!(fresh.admission, replayed.admission);
        assert_eq!(
            remaining_unit_limits(limits, &CodeQueryExecutionWork::default(), &fresh),
            remaining_unit_limits(limits, &CodeQueryExecutionWork::default(), &replayed),
            "fresh and reused earlier answers leave the same next-unit allowances",
        );
        let second = cached_call_relation(
            analyzer,
            scope.token(),
            later,
            true,
            &mut cache,
            &mut budget,
            limits,
            None,
            &mut Vec::new(),
            &mut None,
        );
        assert!(
            !first.truncated && !second.truncated,
            "{first:?} {second:?}"
        );
        let reads = ledger
            .keys()
            .into_iter()
            .filter(|key| {
                matches!(
                    key,
                    crate::analyzer::ReadKey::Lookup {
                        kind: crate::analyzer::LookupKind::Callers,
                        ..
                    }
                )
            })
            .collect::<Vec<_>>();
        (first.work.scanned_source_bytes, second.sites.len(), reads)
    };
    let base = project.workspace_analyzer(AnalyzerConfig::default());
    let before = run(&base);
    project
        .file("other.ts")
        .write(format!(
            "export function unrelated() {{ return 1; }}\n/*{}*/\n",
            "x\n".repeat(10_000)
        ))
        .expect("raise unrelated scan work");
    let head = project.workspace_analyzer(AnalyzerConfig::default());
    let after = run(&head);
    assert!(
        after.0 > before.0,
        "earlier scan work must increase: {before:?} {after:?}"
    );
    assert_eq!(before.1, after.1, "later fresh answer");
    assert_eq!(before.2, after.2, "both consumed answers stay equal");
    let changed = crate::analyzer::ChangedFacts::between(&base, &head);
    let artifact = crate::analyzer::invalidation::DerivedArtifactId::new(
        crate::analyzer::invalidation::DerivedArtifactKind::PolicyEvaluationUnit,
        crate::analyzer::read_ledger::read_set_digest(&before.2).digest(),
    );
    assert_eq!(
        crate::analyzer::verify_read_set_for_artifact(
            artifact,
            &head,
            &changed,
            &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
            &before.2,
            crate::analyzer::LookupReplayLimits::default(),
            &crate::analyzer::NoSummaryAnswers,
            &mut crate::analyzer::LookupMemo::new(),
        ),
        crate::analyzer::ReadVerdict::Unchanged
    );
}

#[test]
#[hardwon("#11836: a single caller answer exceeded the remaining traversal allowance")]
fn caller_answer_allowance_cuts_warm_and_cold_identically() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("target.ts", "export function target() {}\nexport function caller() { target(); target(); target(); target(); }\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let declarations = analyzer.declarations(&project.file("target.ts"));
    let target = declarations
        .iter()
        .find(|unit| unit.fq_name().to_string().ends_with("target"))
        .unwrap();
    let scope = AnalyzerQueryScope::with_read_ledger(
        analyzer,
        std::sync::Arc::new(crate::analyzer::read_ledger::ReadLedger::new()),
    );
    let mut cache = CallTraversalCache::default();
    let limits = CodeQueryExecutionLimits {
        max_call_answers: 3,
        ..CodeQueryExecutionLimits::default()
    };
    let mut answers = Vec::new();
    for _ in 0..2 {
        let mut budget = CodeQueryExecutionBudget::default();
        let mut diagnostics = Vec::new();
        let answer = cached_call_relation(
            analyzer,
            scope.token(),
            target,
            true,
            &mut cache,
            &mut budget,
            limits,
            None,
            &mut diagnostics,
            &mut None,
        );
        assert_eq!(answer.sites.len(), 2);
        assert!(answer.truncated);
        assert_eq!(
            budget.call_declarations + budget.call_sites + budget.call_terminals,
            3
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code
                    == CodeQueryDiagnosticCode::ExecutionBudgetExhausted)
        );
        answers.push(format!("{:?}", answer.sites));
    }
    assert_eq!(answers[0], answers[1]);
    cache
        .incoming
        .read_mut(&memo_attribution(analyzer), |memo| {
            assert_eq!(memo.get(target).unwrap().sites.len(), 4)
        });
}

#[test]
#[hardwon("#11836: incoming-file prefetch cached answers using default scan limits")]
fn caller_prefetch_uses_request_scan_limits() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"prefetch_limits\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file("src/lib.rs", "mod zcaller;\npub fn target() {}\n")
        .file(
            "src/zcaller.rs",
            format!(
                "pub fn caller() {{ crate::target(); }}\n/*{}*/\n",
                "padding".repeat(100)
            ),
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["rust"],
        "match": {"kind": "callable", "name": "target"},
        "steps": [{"op": "enclosing_decl"}, {"op": "call_sites_to"}],
        "limit": 100
    }))
    .unwrap();
    let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
    let files = workspace.analyzer().analyzed_files();
    let file = project.file("src/zcaller.rs");
    let run = |limits| {
        execute_code_query_unit(
            workspace.analyzer(),
            &flow,
            Some(&workspace),
            &query,
            limits,
            None,
            CodeQueryExecutionScope::for_reverse_entered_file(&file, &files),
        )
    };
    let full = run(CodeQueryExecutionLimits::default());
    assert_eq!(full.completion, CodeQueryCompletion::Complete, "{full:?}");
    assert_eq!(full.rows.len(), 1);
    let limited = run(CodeQueryExecutionLimits {
        max_scanned_source_bytes: 100,
        ..CodeQueryExecutionLimits::default()
    });
    assert_ne!(
        limited.completion,
        CodeQueryCompletion::Complete,
        "{limited:?}"
    );
    assert!(
        limited
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.incompleteness
                == Incompleteness::Operational(DiagnosticExecutionCause::Budget)),
        "{limited:?}"
    );
}

#[test]
#[hardwon(
    "#11836: a callers expansion could rescan the workspace once per declaration without an aggregate bound"
)]
fn callers_physical_allowance_memo_hits_and_retry() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "target.ts",
            "export function first() {}\nexport function second() {}\nexport function third() {}\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let declarations = analyzer.declarations(&project.file("target.ts"));
    let scope = AnalyzerQueryScope::with_read_ledger(
        analyzer,
        std::sync::Arc::new(crate::analyzer::read_ledger::ReadLedger::new()),
    );
    let run = |cache: &mut CallTraversalCache, limits| {
        let mut budget = CodeQueryExecutionBudget::default();
        let mut diagnostics = Vec::new();
        let answers = declarations
            .iter()
            .map(|unit| {
                cached_call_relation(
                    analyzer,
                    scope.token(),
                    unit,
                    true,
                    cache,
                    &mut budget,
                    limits,
                    None,
                    &mut diagnostics,
                    &mut None,
                )
            })
            .collect::<Vec<_>>();
        (answers, budget, diagnostics)
    };
    let mut cache = CallTraversalCache::default();
    let (cold, cold_work, diagnostics) = run(&mut cache, CodeQueryExecutionLimits::default());
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    assert!(cold.iter().all(|answer| !answer.truncated));
    assert!(cold_work.call_scanned_files > 0);
    let small = CodeQueryExecutionLimits {
        max_call_scanned_files: 0,
        max_call_scanned_source_bytes: 0,
        ..CodeQueryExecutionLimits::default()
    };
    let (warm, warm_work, diagnostics) = run(&mut cache, small);
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    assert_eq!(warm_work.call_scanned_files, 0);
    assert_eq!(warm_work.call_scanned_source_bytes, 0);
    assert_eq!(format!("{cold:?}"), format!("{warm:?}"));

    // Outgoing work earlier in the pipeline leaves the incoming allowance intact.
    let mut mixed_cache = CallTraversalCache::default();
    let mut mixed_budget = CodeQueryExecutionBudget::default();
    let mut mixed_diagnostics = Vec::new();
    for unit in &declarations {
        let answer = cached_call_relation(
            analyzer,
            scope.token(),
            unit,
            false,
            &mut mixed_cache,
            &mut mixed_budget,
            CodeQueryExecutionLimits::default(),
            None,
            &mut mixed_diagnostics,
            &mut None,
        );
        assert!(!answer.truncated);
    }
    assert!(
        mixed_budget.call_scanned_files > 0,
        "outgoing queries scanned source"
    );
    assert_eq!(mixed_budget.callers_scanned_files, 0);
    assert_eq!(mixed_budget.callers_scanned_source_bytes, 0);
    let exact = CodeQueryExecutionLimits {
        max_call_scanned_files: cold_work.callers_scanned_files,
        max_call_scanned_source_bytes: cold_work.callers_scanned_source_bytes,
        ..CodeQueryExecutionLimits::default()
    };
    let mixed = declarations
        .iter()
        .map(|unit| {
            cached_call_relation(
                analyzer,
                scope.token(),
                unit,
                true,
                &mut mixed_cache,
                &mut mixed_budget,
                exact,
                None,
                &mut mixed_diagnostics,
                &mut None,
            )
        })
        .collect::<Vec<_>>();
    assert!(mixed_diagnostics.is_empty(), "{mixed_diagnostics:?}");
    assert_eq!(format!("{cold:?}"), format!("{mixed:?}"));

    // This hardwon guard originally allowed one crossing scan. The allowance
    // now bounds the provider grant, so refusal must happen without overshoot.
    for (limits, code) in [
        (
            CodeQueryExecutionLimits {
                max_call_scanned_source_bytes: 1,
                max_scanned_files: 1,
                ..Default::default()
            },
            CodeQueryDiagnosticCode::SemanticBudgetExhausted,
        ),
        (
            CodeQueryExecutionLimits {
                max_call_scanned_files: 1,
                ..Default::default()
            },
            CodeQueryDiagnosticCode::SemanticBudgetExhausted,
        ),
        (
            CodeQueryExecutionLimits {
                max_scanned_source_bytes: 1,
                ..Default::default()
            },
            CodeQueryDiagnosticCode::ExecutionBudgetExhausted,
        ),
        (
            CodeQueryExecutionLimits {
                max_scanned_source_bytes: 1,
                max_call_scanned_source_bytes: 1,
                ..Default::default()
            },
            CodeQueryDiagnosticCode::ExecutionBudgetExhausted,
        ),
        (
            CodeQueryExecutionLimits {
                max_scanned_files: 1,
                ..Default::default()
            },
            CodeQueryDiagnosticCode::ExecutionBudgetExhausted,
        ),
        (
            CodeQueryExecutionLimits {
                max_scanned_files: 1,
                max_call_scanned_files: 1,
                ..Default::default()
            },
            CodeQueryDiagnosticCode::ExecutionBudgetExhausted,
        ),
    ] {
        let mut stopped_cache = CallTraversalCache::default();
        let (stopped, work, diagnostics) = run(&mut stopped_cache, limits);
        assert!(
            work.call_scanned_source_bytes
                <= limits
                    .max_scanned_source_bytes
                    .min(limits.max_call_scanned_source_bytes),
            "{limits:?}: {work:?}"
        );
        assert!(
            work.call_scanned_files <= limits.max_scanned_files.min(limits.max_call_scanned_files),
            "{limits:?}: {work:?}"
        );
        assert!(
            stopped.iter().all(|answer| answer.truncated),
            "{limits:?}: {stopped:?}"
        );
        assert!(!diagnostics.is_empty(), "{limits:?}");
        assert!(
            diagnostics.iter().all(|diagnostic| {
                diagnostic.code == code
                    && diagnostic.incompleteness
                        == Incompleteness::Operational(DiagnosticExecutionCause::Budget)
            }),
            "{limits:?}: {diagnostics:?}"
        );
        stopped_cache
            .incoming
            .read_mut(&memo_attribution(analyzer), |memo| {
                assert!(declarations.iter().all(|unit| memo.get(unit).is_none()));
            });
        let (retry, _, diagnostics) = run(&mut stopped_cache, CodeQueryExecutionLimits::default());
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert_eq!(format!("{cold:?}"), format!("{retry:?}"));
    }
}

#[test]
#[hardwon(
    "#11836: a callers expansion could rescan the workspace once per declaration without an aggregate bound"
)]
fn callers_physical_allowance_marks_unit_operational() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "target.ts",
            "export function first() {}\nexport function second() {}\nexport function third() {}\nexport function driver() { first(); }\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["typescript"],
        "match": {"kind": "callable"},
        "steps": [{"op": "enclosing_decl"}, {"op": "callers"}],
        "limit": 100
    }))
    .unwrap();
    let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
    let files = workspace.analyzer().analyzed_files();
    let run = |limits| {
        execute_code_query_unit(
            workspace.analyzer(),
            &flow,
            Some(&workspace),
            &query,
            limits,
            None,
            CodeQueryExecutionScope::for_seed_files(
                std::slice::from_ref(&project.file("target.ts")),
                &files,
            ),
        )
    };
    let mixed_query = CodeQuery::from_json(&json!({
        "languages": ["typescript"],
        "match": {"kind": "callable", "name": "driver"},
        "steps": [{"op": "enclosing_decl"}, {"op": "callees"}, {"op": "callers"}],
        "limit": 100
    }))
    .unwrap();
    // One source file causes multiple physical file events: incoming candidate
    // scanning also reads outgoing edges to recover recursion. Measure that
    // cold incoming work, without any preceding outgoing pipeline work.
    let declarations = workspace
        .analyzer()
        .declarations(&project.file("target.ts"));
    let target = declarations
        .iter()
        .find(|unit| unit.fq_name().to_string().ends_with("first"))
        .unwrap();
    let scope = AnalyzerQueryScope::new(workspace.analyzer());
    let mut cold_budget = CodeQueryExecutionBudget::default();
    let mut cold_diagnostics = Vec::new();
    let cold = cached_call_relation(
        workspace.analyzer(),
        scope.token(),
        target,
        true,
        &mut CallTraversalCache::default(),
        &mut cold_budget,
        CodeQueryExecutionLimits::default(),
        None,
        &mut cold_diagnostics,
        &mut None,
    );
    assert!(!cold.truncated, "{cold:?}");
    assert!(cold_diagnostics.is_empty(), "{cold_diagnostics:?}");
    assert!(cold_budget.callers_scanned_files > 1, "{cold_budget:?}");
    drop(scope);
    let mixed = execute_code_query_unit(
        workspace.analyzer(),
        &flow,
        Some(&workspace),
        &mixed_query,
        CodeQueryExecutionLimits {
            max_call_scanned_files: cold_budget.callers_scanned_files,
            max_call_scanned_source_bytes: cold_budget.callers_scanned_source_bytes,
            ..CodeQueryExecutionLimits::default()
        },
        None,
        CodeQueryExecutionScope::for_seed_files(
            std::slice::from_ref(&project.file("target.ts")),
            &files,
        ),
    );
    assert_eq!(mixed.completion, CodeQueryCompletion::Complete, "{mixed:?}");
    assert!(
        mixed.work.scanned_files > cold_budget.callers_scanned_files as u64,
        "pipeline performs extra outgoing work without spending the incoming allowance: {mixed:?}"
    );
    assert_eq!(
        mixed.rows.len(),
        1,
        "outgoing then incoming pipeline returns driver"
    );

    let ledger = std::sync::Arc::new(crate::analyzer::read_ledger::ReadLedger::new());
    let ledger_scope = AnalyzerQueryScope::with_read_ledger(workspace.analyzer(), ledger.clone());
    let stopped = run(CodeQueryExecutionLimits {
        max_call_scanned_files: 1,
        ..CodeQueryExecutionLimits::default()
    });
    assert_ne!(
        stopped.completion,
        CodeQueryCompletion::Complete,
        "{stopped:?}"
    );
    assert!(
        stopped.diagnostics.iter().any(|diagnostic| {
            diagnostic.incompleteness
                == Incompleteness::Operational(DiagnosticExecutionCause::Budget)
                && diagnostic.message.contains("callers expansion")
        }),
        "{stopped:?}"
    );
    // The unit's consumer joins the verdict the execution returned.
    assert!(!stopped.reuse.is_content(), "{stopped:?}");
    ledger.join_verdict(stopped.reuse);
    assert!(
        !ledger.is_bounded(),
        "operationally stopped unit cannot be published"
    );
    drop(ledger_scope);
    let retry = run(CodeQueryExecutionLimits::default());
    assert_eq!(retry.completion, CodeQueryCompletion::Complete, "{retry:?}");
}

#[test]
#[hardwon("#11836: depth-probe memo hits bypassed call-answer admission")]
fn depth_probe_memo_hits_obey_call_answer_admission() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "fn root() { middle(); }\nfn middle() { a(); b(); c(); }\nfn a() {}\nfn b() {}\nfn c() {}\n")
        .build();
    let workspace = project.workspace_analyzer(Default::default());
    let analyzer = workspace.analyzer();
    let root = analyzer
        .declarations(&project.file("src/lib.rs"))
        .into_iter()
        .find(|unit| unit.fq_name() == "root")
        .unwrap();
    let declaration = IndexedDeclarations::default().get(analyzer, &root).unwrap();
    let scope = AnalyzerQueryScope::new(analyzer);
    let filter = CallTraversalFilter::default();
    let step = QueryStep::Callees(filter.clone());
    let mut cache = CallTraversalCache::default();
    let mut run = || {
        let mut input = CallDepthProbeInput::default();
        let (_, exhausted) = call_declaration_expansions(
            analyzer,
            scope.token(),
            &declaration,
            &step,
            &filter,
            &mut IndexedDeclarations::default(),
            &mut cache,
            &mut CodeQueryExecutionBudget::default(),
            CodeQueryExecutionLimits::default(),
            16,
            None,
            &mut Vec::new(),
            &mut None,
            &mut input,
            None,
        );
        assert!(!exhausted);
        let mut budget = CodeQueryExecutionBudget::default();
        let status = probe_call_depth_bound(
            analyzer,
            scope.token(),
            &step,
            &filter,
            &mut cache,
            &mut budget,
            CodeQueryExecutionLimits {
                max_call_answers: 2,
                ..CodeQueryExecutionLimits::default()
            },
            None,
            &mut input,
        );
        let answer = input.answer.unwrap();
        assert!(answer.budget_stopped);
        assert_eq!(answer.frontier.len(), 1);
        assert_eq!(
            (
                budget.call_declarations,
                budget.call_sites,
                budget.call_terminals
            ),
            (1, 1, 0)
        );
        (status, format!("{answer:?}"), budget.call_scanned_files)
    };
    let cold = run();
    let warm = run();
    assert_eq!(cold.0, DepthBoundStatus::Reached);
    assert_eq!(cold.0, warm.0);
    assert_eq!(cold.1, warm.1);
    assert_eq!(warm.2, 0, "memo hits perform no physical scan");
}

#[test]
#[hardwon("#11836: the user's max_scanned_source_bytes stopped bounding call-relation scans")]
fn caller_scans_obey_user_physical_limits() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("old.ts", "export function target() {}\n")
        .file(
            "app.ts",
            "import { target } from './old';\nexport function caller() { target(); }\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["typescript"],
        "match": {"kind": "callable", "name": "target"},
        "steps": [{"op": "enclosing_decl"}, {"op": "call_sites_to"}],
        "limit": 100
    }))
    .unwrap();
    let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
    let files = workspace.analyzer().analyzed_files();
    let run = |limits| {
        execute_code_query_unit(
            workspace.analyzer(),
            &flow,
            Some(&workspace),
            &query,
            limits,
            None,
            CodeQueryExecutionScope::for_seed_files(
                std::slice::from_ref(&project.file("old.ts")),
                &files,
            ),
        )
    };
    for limits in [
        CodeQueryExecutionLimits {
            max_scanned_source_bytes: 1,
            ..Default::default()
        },
        CodeQueryExecutionLimits {
            max_scanned_files: 1,
            ..Default::default()
        },
    ] {
        let ledger = std::sync::Arc::new(crate::analyzer::read_ledger::ReadLedger::new());
        let scope = AnalyzerQueryScope::with_read_ledger(workspace.analyzer(), ledger.clone());
        let stopped = run(limits);
        assert_ne!(
            stopped.completion,
            CodeQueryCompletion::Complete,
            "{stopped:?}"
        );
        assert!(
            stopped.diagnostics.iter().any(|diagnostic| {
                diagnostic.incompleteness
                    == Incompleteness::Operational(DiagnosticExecutionCause::Budget)
            }),
            "{stopped:?}"
        );
        assert!(!stopped.reuse.is_content(), "{stopped:?}");
        ledger.join_verdict(stopped.reuse);
        assert!(
            !ledger.is_bounded(),
            "operational stop must not be published"
        );
        drop(scope);
    }
    let retry = run(CodeQueryExecutionLimits::default());
    assert_eq!(retry.completion, CodeQueryCompletion::Complete, "{retry:?}");
    assert_eq!(retry.rows.len(), 1);
}

fn assert_call_projection_cancellation(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    provider: &dyn Fn(&CancellationToken) -> CallRelationResult,
    query: &dyn Fn(
        &CancellationToken,
        &mut CallTraversalCache,
        &mut Vec<CodeQueryDiagnostic>,
    ) -> CallRelationResult,
) {
    // Warm both routes before counting checkpoints, so memo initialization
    // cannot shift the provider's cancellation window between the two runs.
    let complete = provider(&CancellationToken::new());
    assert!(!complete.cancelled && !complete.truncated, "{complete:?}");
    assert_eq!(complete.sites.len(), 3);
    let warm = query(
        &CancellationToken::new(),
        &mut CallTraversalCache::default(),
        &mut Vec::new(),
    );
    assert_eq!(warm.sites, complete.sites);
    let mut projection_checkpoints = Vec::new();
    let mut finished = false;
    // The first untripped run counts the complete path. Every preceding
    // checkpoint must preserve the provider's cancellation and partial sites.
    for checks in 0..=4096 {
        let provider_token = CancellationToken::cancel_after_checks_for_test(checks);
        let expected = provider(&provider_token);
        let cancellation = CancellationToken::cancel_after_checks_for_test(checks);
        let mut cache = CallTraversalCache::default();
        let mut diagnostics = Vec::new();
        let answer = query(&cancellation, &mut cache, &mut diagnostics);
        let tripped = provider_token.cancel_after_checks_tripped_for_test();
        assert_eq!(
            cancellation.cancel_after_checks_tripped_for_test(),
            tripped,
            "checks={checks}: provider and RQL must poll the same projection"
        );
        if !tripped {
            assert!(!expected.cancelled && !answer.cancelled);
            assert_eq!(expected.sites, complete.sites);
            assert_eq!(answer.sites, complete.sites);
            finished = true;
            break;
        }
        assert!(expected.cancelled, "checks={checks}: {expected:?}");
        assert!(
            answer.cancelled,
            "checks={checks}: {answer:?} {diagnostics:?}"
        );
        assert_eq!(answer.sites, expected.sites, "checks={checks}");
        assert_eq!(answer.diagnostics, expected.diagnostics, "checks={checks}");
        assert!(
            diagnostics.iter().all(|diagnostic| {
                diagnostic.code != CodeQueryDiagnosticCode::ExecutionBudgetExhausted
                    && diagnostic.code != CodeQueryDiagnosticCode::SemanticBudgetExhausted
            }),
            "checks={checks}: {diagnostics:?}"
        );
        for memo in [&mut cache.incoming, &mut cache.outgoing] {
            memo.read_mut(&memo_attribution(analyzer), |memo| {
                assert!(
                    memo.get(unit).is_none(),
                    "cancelled answers must not be memoized"
                );
            });
        }
        if expected.work.scanned_source_bytes > 0
            && !expected.sites.is_empty()
            && expected.sites.len() < complete.sites.len()
        {
            projection_checkpoints.push(checks);
        }
        let retry = query(&CancellationToken::new(), &mut cache, &mut Vec::new());
        assert!(!retry.cancelled, "checks={checks}: {retry:?}");
        assert_eq!(retry.sites, complete.sites, "checks={checks}: retry");
    }
    assert!(finished, "must reach the untripped complete projection");
    assert!(
        !projection_checkpoints.is_empty(),
        "must cancel inside projection after scanning and retaining a strict partial set of sites"
    );
}

#[test]
#[hardwon(
    "549ad74f88ba: a truncated call relation below the candidate cap was reported as a budget stop, hiding cancellation"
)]
fn call_relation_projection_preserves_cancellation() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("target.ts", "export function target() {}\n")
        .file("caller.ts", "import { target } from './target';\nexport function caller() { target(); target(); target(); }\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let target = analyzer
        .declarations(&project.file("target.ts"))
        .into_iter()
        .find(|unit| unit.identifier() == "target")
        .unwrap();
    let scope = AnalyzerQueryScope::new(analyzer);
    let limits = CodeQueryExecutionLimits::default();
    let relation_limits = remaining_call_scan_limits(&CodeQueryExecutionBudget::default(), limits);
    assert_call_projection_cancellation(
        analyzer,
        &target,
        &|cancellation| {
            CallRelationService::incoming_bounded(
                analyzer,
                scope.token(),
                &target,
                relation_limits,
                Some(cancellation),
            )
        },
        &|cancellation, cache, diagnostics| {
            cached_call_relation(
                analyzer,
                scope.token(),
                &target,
                true,
                cache,
                &mut CodeQueryExecutionBudget::default(),
                limits,
                Some(cancellation),
                diagnostics,
                &mut None,
            )
        },
    );
}

#[test]
#[hardwon(
    "549ad74f88ba: outgoing call projection stopped on cancellation but reported cancelled=false"
)]
fn outgoing_call_relation_projection_preserves_cancellation() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("target.ts", "export function target() {}\n")
        .file("caller.ts", "import { target } from './target';\nexport function caller() { target(); target(); target(); }\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let caller = analyzer
        .declarations(&project.file("caller.ts"))
        .into_iter()
        .find(|unit| unit.identifier() == "caller")
        .unwrap();
    let scope = AnalyzerQueryScope::new(analyzer);
    let limits = CodeQueryExecutionLimits::default();
    let relation_limits = remaining_call_scan_limits(&CodeQueryExecutionBudget::default(), limits);
    assert_call_projection_cancellation(
        analyzer,
        &caller,
        &|cancellation| {
            CallRelationService::outgoing_bounded(
                analyzer,
                scope.token(),
                &caller,
                relation_limits,
                Some(cancellation),
            )
        },
        &|cancellation, cache, diagnostics| {
            cached_call_relation(
                analyzer,
                scope.token(),
                &caller,
                false,
                cache,
                &mut CodeQueryExecutionBudget::default(),
                limits,
                Some(cancellation),
                diagnostics,
                &mut None,
            )
        },
    );
}
