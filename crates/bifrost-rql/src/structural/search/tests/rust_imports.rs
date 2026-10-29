use super::inline_project::BuiltInlineTestProject;
use super::*;
use brokk_bifrost_test_macros::hardwon;
use std::collections::BTreeSet;

fn reexport_workspace() -> BuiltInlineTestProject {
    InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[workspace]\nmembers = [\"source\", \"facade\", \"chain\", \"glob_facade\", \"module_facade\", \"single_client\", \"chain_client\", \"glob_client\", \"module_client\", \"chain_helper_client\"]\nresolver = \"2\"\n",
        )
        .file(
            "source/Cargo.toml",
            "[package]\nname = \"source\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file(
            "source/src/lib.rs",
            "pub mod inner;\npub mod other;\npub fn root_marker() {}\n",
        )
        .file("source/src/inner.rs", "pub fn exported_target() {}\n")
        .file("source/src/other.rs", "pub fn alternate_target() {}\n")
        .file(
            "facade/Cargo.toml",
            "[package]\nname = \"facade\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nsource = { path = \"../source\" }\n",
        )
        .file(
            "facade/src/lib.rs",
            "pub use source::inner::exported_target;\n",
        )
        .file(
            "chain/Cargo.toml",
            "[package]\nname = \"chain\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nfacade = { path = \"../facade\" }\n",
        )
        .file(
            "chain/src/lib.rs",
            "pub use facade::exported_target;\npub fn helper() {}\n",
        )
        .file(
            "glob_facade/Cargo.toml",
            "[package]\nname = \"glob_facade\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nsource = { path = \"../source\" }\n",
        )
        .file(
            "glob_facade/src/lib.rs",
            "pub use source::inner::*;\n",
        )
        .file(
            "module_facade/Cargo.toml",
            "[package]\nname = \"module_facade\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nsource = { path = \"../source\" }\n",
        )
        .file(
            "module_facade/src/lib.rs",
            "pub use source::inner;\n",
        )
        .file(
            "single_client/Cargo.toml",
            "[package]\nname = \"single_client\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nfacade = { path = \"../facade\" }\n",
        )
        .file(
            "single_client/src/lib.rs",
            "use facade::exported_target;\npub fn run() { exported_target(); }\n",
        )
        .file(
            "chain_client/Cargo.toml",
            "[package]\nname = \"chain_client\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nchain = { path = \"../chain\" }\n",
        )
        .file(
            "chain_client/src/lib.rs",
            "use chain::exported_target;\npub fn run() { exported_target(); }\n",
        )
        .file(
            "glob_client/Cargo.toml",
            "[package]\nname = \"glob_client\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nglob_facade = { path = \"../glob_facade\" }\n",
        )
        .file(
            "glob_client/src/lib.rs",
            "use glob_facade::exported_target;\npub fn run() { exported_target(); }\n",
        )
        .file(
            "module_client/Cargo.toml",
            "[package]\nname = \"module_client\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nmodule_facade = { path = \"../module_facade\" }\n",
        )
        .file(
            "module_client/src/lib.rs",
            "pub use module_facade::inner::exported_target;\npub fn run() { exported_target(); }\n",
        )
        .file(
            "chain_helper_client/Cargo.toml",
            "[package]\nname = \"chain_helper_client\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nchain = { path = \"../chain\" }\n",
        )
        .file(
            "chain_helper_client/src/lib.rs",
            "use chain::helper;\npub fn run() { helper(); }\n",
        )
        .build()
}

fn assert_incremental_matches_fresh(
    project: &BuiltInlineTestProject,
    workspace: &WorkspaceAnalyzer,
    changed_files: impl IntoIterator<Item = ProjectFile>,
    query: &CodeQuery,
) -> (WorkspaceAnalyzer, DetailedCodeQueryResult) {
    let updated = workspace.update(&changed_files.into_iter().collect());
    let incremental = execute_code_query_with_access_mode(
        updated.analyzer(),
        query,
        CodeQueryExecutionLimits::default(),
        StructuralAccessMode::IndexedRequired,
        true,
    )
    .expect("incremental persisted import graph query");
    let fresh_workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let fresh = execute_code_query_detailed_eager_index(
        fresh_workspace.analyzer(),
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        query,
        CodeQueryExecutionLimits::default(),
        None,
    );
    assert_eq!(
        serde_json::to_value(&incremental.result).expect("incremental result"),
        serde_json::to_value(&fresh.result).expect("from-scratch result")
    );
    (updated, incremental)
}

fn candidate_dependency_workspace() -> BuiltInlineTestProject {
    InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[workspace]\nmembers = [\"source\", \"facade\", \"client\"]\nresolver = \"2\"\n",
        )
        .file(
            "source/Cargo.toml",
            "[package]\nname = \"source\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file(
            "source/src/lib.rs",
            "pub mod api;\npub mod parent;\npub mod glob_one;\npub mod glob_two;\npub mod file_pending;\n",
        )
        .file("source/src/api.rs", "pub fn existing() {}\n")
        .file("source/src/parent.rs", "pub fn parent_marker() {}\n")
        .file("source/src/glob_one.rs", "pub fn shadowed() {}\n")
        .file("source/src/glob_two.rs", "pub fn other() {}\n")
        .file("source/src/new_module.rs", "pub fn added() {}\n")
        .file(
            "facade/Cargo.toml",
            "[package]\nname = \"facade\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nsource = { path = \"../source\" }\n",
        )
        .file("facade/src/lib.rs", "pub use source::api::existing;\n")
        .file(
            "client/Cargo.toml",
            "[package]\nname = \"client\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nsource = { path = \"../source\" }\nfacade = { path = \"../facade\" }\n",
        )
        .file(
            "client/src/lib.rs",
            "use source::new_module::added;\nuse source::file_pending::file_added;\nuse source::api::late_item;\nuse source::parent::inline_child::inline_item;\nuse facade::late_export;\nuse source::glob_one::*;\nuse source::glob_two::*;\npub fn run() { added(); file_added(); late_item(); inline_item(); late_export(); shadowed(); }\n",
        )
        .build()
}

fn local_import_workspace() -> BuiltInlineTestProject {
    InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[workspace]\nmembers = [\"source\", \"client\"]\nresolver = \"2\"\n",
        )
        .file(
            "source/Cargo.toml",
            "[package]\nname = \"source\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file("source/src/lib.rs", "pub mod api;\npub mod inner;\npub mod other;\n")
        .file(
            "source/src/api.rs",
            "pub use crate::inner::target;\npub struct Datum;\n",
        )
        .file("source/src/inner.rs", "pub fn target() {}\n")
        .file("source/src/other.rs", "pub struct A;\npub struct B;\n")
        .file(
            "client/Cargo.toml",
            "[package]\nname = \"client\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nsource = { path = \"../source\" }\n",
        )
        .file(
            "client/src/lib.rs",
            "use source::other::{A, B};\npub fn caller() { use source::api::Datum; let _: Option<Datum> = None; let _: Option<(A, B)> = None; }\n",
        )
        .build()
}

fn file_paths(result: &DetailedCodeQueryResult) -> BTreeSet<String> {
    result
        .result
        .results
        .iter()
        .map(|item| match &item.value {
            CodeQueryResultValue::File { value } => value.path.clone(),
            other => panic!("expected file result, got {other:?}"),
        })
        .collect()
}

fn import_refresh_work(result: &DetailedCodeQueryResult) -> (u64, u64) {
    let profile = result.profile.as_ref().expect("import query profile");
    let adjacency_rows = u64::try_from(result.result.results.len()).expect("result count fits u64");
    (
        profile.work.import_files_resolved,
        profile
            .work
            .import_edges_resolved
            .saturating_sub(adjacency_rows),
    )
}

fn file_ref_path(reference: &CodeQueryResultRef) -> &str {
    match reference {
        CodeQueryResultRef::File { path } => path,
        other => panic!("expected file provenance, got {other:?}"),
    }
}

fn importer_query(name: &str, hops: usize) -> CodeQuery {
    let mut steps = vec![json!({"op": "file_of"})];
    steps.extend((0..hops).map(|_| json!({"op": "importers_of"})));
    CodeQuery::from_json(&json!({
        "languages": ["rust"],
        "match": { "kind": "function", "name": name },
        "steps": steps,
        "limit": 100,
        "result_detail": "full"
    }))
    .expect("Rust importer query")
}

fn importer_query_at(name: &str, path: &str) -> CodeQuery {
    CodeQuery::from_json(&json!({
        "languages": ["rust"],
        "where": [path],
        "match": { "kind": "function", "name": name },
        "steps": [{ "op": "file_of" }, { "op": "importers_of" }],
        "limit": 100,
        "result_detail": "full"
    }))
    .expect("Rust importer query at path")
}

#[test]
#[hardwon("a0211e4871b7: body-only Rust edits reuse persisted import edges without refresh work")]
fn persistent_rust_import_graph_reuses_edges_and_invalidates_reexport_routes() {
    let project = reexport_workspace();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let original_query = importer_query_at("exported_target", "source/src/inner.rs");
    let limits = CodeQueryExecutionLimits::default();
    let first = execute_code_query_with_access_mode(
        workspace.analyzer(),
        &original_query,
        limits,
        StructuralAccessMode::IndexedRequired,
        true,
    )
    .expect("build the persisted import graph");
    assert_eq!(first.result.completion(), CodeQueryCompletion::Complete);
    let original_importers = file_paths(&first);
    assert!(original_importers.contains("facade/src/lib.rs"));

    let warm = execute_code_query_with_access_mode(
        workspace.analyzer(),
        &original_query,
        limits,
        StructuralAccessMode::IndexedRequired,
        true,
    )
    .expect("read warm import adjacency");
    assert_eq!(
        serde_json::to_value(&warm.result).expect("warm result"),
        serde_json::to_value(&first.result).expect("first result")
    );
    let warm_profile = warm.profile.as_ref().expect("warm profile");
    assert_eq!(warm_profile.work.import_files_resolved, 0);
    assert_eq!(
        warm_profile.work.import_edges_resolved,
        u64::try_from(file_paths(&warm).len()).expect("result count fits u64")
    );

    let reexport = project.file("facade/src/lib.rs");
    reexport
        .write("pub use source::other::alternate_target as exported_target;\n")
        .expect("edit facade route");
    let updated = workspace.update(&BTreeSet::from([reexport]));
    let moved_route = execute_code_query_with_access_mode(
        updated.analyzer(),
        &importer_query_at("alternate_target", "source/src/other.rs"),
        limits,
        StructuralAccessMode::IndexedRequired,
        true,
    )
    .expect("rebuild graph after the non-local re-export edit");
    assert_eq!(
        moved_route.result.completion(),
        CodeQueryCompletion::Complete
    );
    let moved_importers = file_paths(&moved_route);
    for importer in [
        "facade/src/lib.rs",
        "chain/src/lib.rs",
        "chain_client/src/lib.rs",
        "single_client/src/lib.rs",
    ] {
        assert!(
            moved_importers.contains(importer),
            "updated route did not include {importer}: {moved_importers:#?}"
        );
    }
    let (reexport_files_resolved, reexport_edges_resolved) = import_refresh_work(&moved_route);
    assert_eq!(
        reexport_files_resolved, 4,
        "only route dependents are refreshed"
    );
    assert_eq!(
        reexport_edges_resolved, 7,
        "only refreshed file edges are resolved"
    );
    let fresh_moved_route = execute_code_query_detailed_eager_index(
        updated.analyzer(),
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        &importer_query_at("alternate_target", "source/src/other.rs"),
        limits,
        None,
    );
    assert_eq!(
        serde_json::to_value(&moved_route.result).expect("incremental route result"),
        serde_json::to_value(&fresh_moved_route.result).expect("fresh route result")
    );

    let leaf = project.file("chain_helper_client/src/lib.rs");
    leaf.write("use chain::helper;\npub fn run() { helper(); helper(); }\n")
        .expect("edit leaf importer");
    let leaf_updated = updated.update(&BTreeSet::from([leaf]));
    let leaf_query = importer_query_at("helper", "chain/src/lib.rs");
    let leaf_result = execute_code_query_with_access_mode(
        leaf_updated.analyzer(),
        &leaf_query,
        limits,
        StructuralAccessMode::IndexedRequired,
        true,
    )
    .expect("refresh graph after a leaf edit");
    assert_eq!(
        leaf_result.result.completion(),
        CodeQueryCompletion::Complete
    );
    assert!(file_paths(&leaf_result).contains("chain_helper_client/src/lib.rs"));
    // #4431 advances graph identity when the structured Rust import
    // inputs are unchanged, retaining the persisted leaf edge.
    let (leaf_files_resolved, leaf_edges_resolved) = import_refresh_work(&leaf_result);
    assert_eq!(
        leaf_files_resolved, 0,
        "body-only edit does not refresh the unchanged leaf importer"
    );
    assert_eq!(
        leaf_edges_resolved, 0,
        "body-only edit reuses the unchanged leaf import edge"
    );
    let fresh_leaf_result = execute_code_query_detailed_eager_index(
        leaf_updated.analyzer(),
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        &leaf_query,
        limits,
        None,
    );
    assert_eq!(
        serde_json::to_value(&leaf_result.result).expect("incremental leaf result"),
        serde_json::to_value(&fresh_leaf_result.result).expect("fresh leaf result")
    );
}

#[test]
#[hardwon("#4955: reused Rust consumer summaries lost moved re-export origins")]
fn auto_import_queries_reuse_persisted_sql_graph_across_workspace_builds() {
    let project = reexport_workspace();
    let query = importer_query_at("exported_target", "source/src/inner.rs");
    let limits = CodeQueryExecutionLimits::default();
    let first_workspace = WorkspaceAnalyzer::build_persisted_without_automatic_gc(
        project.project_dyn(),
        AnalyzerConfig::default(),
    )
    .expect("open first persisted workspace");
    let first = execute_code_query_with_access_mode(
        first_workspace.analyzer(),
        &query,
        limits,
        StructuralAccessMode::Auto,
        true,
    )
    .expect("build durable import graph for Auto query");
    assert_eq!(first.result.completion(), CodeQueryCompletion::Complete);
    assert!(first.profile.as_ref().unwrap().work.import_files_resolved > 0);
    assert!(file_paths(&first).contains("facade/src/lib.rs"));

    // MCP may rebuild its WorkspaceAnalyzer between requests. The durable
    // SQLite rows must still serve the next Auto query without graph work.
    let reopened_workspace = WorkspaceAnalyzer::build_persisted_without_automatic_gc(
        project.project_dyn(),
        AnalyzerConfig::default(),
    )
    .expect("reopen persisted workspace for the next request");
    let warm = execute_code_query_with_access_mode(
        reopened_workspace.analyzer(),
        &query,
        limits,
        StructuralAccessMode::Auto,
        true,
    )
    .expect("read warm SQL adjacency in Auto mode");
    assert_eq!(
        serde_json::to_value(&warm.result).expect("warm result"),
        serde_json::to_value(&first.result).expect("first result")
    );
    assert_eq!(warm.profile.as_ref().unwrap().work.import_files_resolved, 0);
    assert_eq!(
        warm.profile.as_ref().unwrap().work.import_edges_resolved,
        u64::try_from(file_paths(&warm).len()).expect("returned rows fit u64")
    );

    let reexport = project.file("facade/src/lib.rs");
    reexport
        .write("pub use source::other::alternate_target as exported_target;\n")
        .expect("edit re-export source");
    let edited_workspace = WorkspaceAnalyzer::build_persisted_without_automatic_gc(
        project.project_dyn(),
        AnalyzerConfig::default(),
    )
    .expect("refresh persisted workspace after edit");
    let edited_query = importer_query_at("alternate_target", "source/src/other.rs");
    let edited = execute_code_query_with_access_mode(
        edited_workspace.analyzer(),
        &edited_query,
        limits,
        StructuralAccessMode::Auto,
        true,
    )
    .expect("incrementally update durable graph in Auto mode");
    assert_eq!(edited.result.completion(), CodeQueryCompletion::Complete);
    let (files_resolved, edges_resolved) = import_refresh_work(&edited);
    assert_eq!(files_resolved, 4);
    assert_eq!(edges_resolved, 7);
    assert!(file_paths(&edited).contains("chain_client/src/lib.rs"));
}

#[test]
#[hardwon(
    "#4955+#5661+#5898: missing modules and scoped glob ambiguity forced whole-workspace refreshes"
)]
fn rust_candidate_dependencies_cover_add_edit_reexport_and_glob_changes() {
    let project = candidate_dependency_workspace();
    let mut workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let baseline = execute_code_query_with_access_mode(
        workspace.analyzer(),
        &importer_query_at("existing", "source/src/api.rs"),
        CodeQueryExecutionLimits::default(),
        StructuralAccessMode::IndexedRequired,
        true,
    )
    .expect("build the baseline persisted import graph");
    assert_eq!(baseline.result.completion(), CodeQueryCompletion::Complete);

    let pending_module = project.file("source/src/file_pending.rs");
    pending_module
        .write("pub fn file_added() {}\n")
        .expect("add the previously missing module file");
    let file_add_query = importer_query_at("file_added", "source/src/file_pending.rs");
    let (updated, file_added) =
        assert_incremental_matches_fresh(&project, &workspace, [pending_module], &file_add_query);
    assert!(file_paths(&file_added).contains("client/src/lib.rs"));
    assert_eq!(
        file_added
            .profile
            .as_ref()
            .expect("file add profile")
            .work
            .import_files_resolved,
        2,
        "the added module and its missing-module dependent are recomputed"
    );
    workspace = updated;

    let source_root = project.file("source/src/lib.rs");
    source_root
        .write("pub mod api;\npub mod parent;\npub mod glob_one;\npub mod glob_two;\npub mod file_pending;\npub mod new_module;\n")
        .expect("add the module declaration that resolves the earlier import");
    let add_query = importer_query_at("added", "source/src/new_module.rs");
    let (updated, added) =
        assert_incremental_matches_fresh(&project, &workspace, [source_root], &add_query);
    assert!(file_paths(&added).contains("client/src/lib.rs"));
    assert_eq!(
        added
            .profile
            .as_ref()
            .expect("module declaration profile")
            .work
            .import_files_resolved,
        2,
        "the changed module declaration and the importer that looked up its name are recomputed"
    );
    workspace = updated;

    let api = project.file("source/src/api.rs");
    api.write("pub fn existing() {}\npub fn late_item() {}\n")
        .expect("add the previously missing item");
    let item_query = importer_query_at("late_item", "source/src/api.rs");
    let (updated, item) =
        assert_incremental_matches_fresh(&project, &workspace, [api], &item_query);
    assert!(file_paths(&item).contains("client/src/lib.rs"));
    assert_eq!(
        item.profile
            .as_ref()
            .expect("item profile")
            .work
            .import_files_resolved,
        2,
        "only the changed item file and the importer that looked up its name are recomputed"
    );
    workspace = updated;

    let parent = project.file("source/src/parent.rs");
    parent
        .write("pub fn parent_marker() {}\npub mod inline_child { pub fn inline_item() {} }\n")
        .expect("add an inline module that resolves an earlier import");
    let module_query = importer_query_at("inline_item", "source/src/parent.rs");
    let (updated, inline_module) =
        assert_incremental_matches_fresh(&project, &workspace, [parent], &module_query);
    assert!(file_paths(&inline_module).contains("client/src/lib.rs"));
    assert_eq!(
        inline_module
            .profile
            .as_ref()
            .expect("inline module profile")
            .work
            .import_files_resolved,
        2,
        "only the changed module file and its importer are recomputed"
    );
    workspace = updated;

    let facade = project.file("facade/src/lib.rs");
    facade
        .write("pub use source::api::existing;\npub use source::api::late_item as late_export;\n")
        .expect("add a re-export for the formerly unresolved import");
    let reexport_query = importer_query_at("late_item", "source/src/api.rs");
    let (updated, reexport) =
        assert_incremental_matches_fresh(&project, &workspace, [facade], &reexport_query);
    assert!(file_paths(&reexport).contains("facade/src/lib.rs"));
    assert!(file_paths(&reexport).contains("client/src/lib.rs"));
    assert_eq!(
        reexport
            .profile
            .as_ref()
            .expect("re-export profile")
            .work
            .import_files_resolved,
        2,
        "only the re-exporting file and its dependent importer are recomputed"
    );
    workspace = updated;

    let glob_source = project.file("source/src/glob_two.rs");
    glob_source
        .write("pub fn other() {}\npub fn shadowed() {}\n")
        .expect("introduce a name that shadows the other glob source");
    let glob_query = importer_query_at("shadowed", "source/src/glob_two.rs");
    let (_, glob_change) =
        assert_incremental_matches_fresh(&project, &workspace, [glob_source], &glob_query);
    assert!(file_paths(&glob_change).contains("client/src/lib.rs"));
    assert_eq!(
        glob_change
            .profile
            .as_ref()
            .expect("glob profile")
            .work
            .import_files_resolved,
        2,
        "only the changed glob source and its importer are recomputed"
    );
}

#[test]
#[hardwon("#3829+#4955: follow Rust module and named re-exports back to the defining file")]
fn rust_importers_follow_named_chained_glob_and_module_reexports_across_crates() {
    let project = reexport_workspace();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());

    let target = execute_code_query_detailed_eager_index(
        workspace.analyzer(),
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        &importer_query("exported_target", 1),
        CodeQueryExecutionLimits::default(),
        None,
    );
    assert_eq!(target.result.completion(), CodeQueryCompletion::Complete);
    assert_eq!(
        file_paths(&target),
        BTreeSet::from([
            "chain/src/lib.rs".to_string(),
            "chain_client/src/lib.rs".to_string(),
            "facade/src/lib.rs".to_string(),
            "glob_client/src/lib.rs".to_string(),
            "glob_facade/src/lib.rs".to_string(),
            "module_client/src/lib.rs".to_string(),
            "module_facade/src/lib.rs".to_string(),
            "single_client/src/lib.rs".to_string(),
        ])
    );

    let module = execute_code_query_detailed_eager_index(
        workspace.analyzer(),
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        &importer_query("root_marker", 1),
        CodeQueryExecutionLimits::default(),
        None,
    );
    assert_eq!(module.result.completion(), CodeQueryCompletion::Complete);
    assert_eq!(
        file_paths(&module),
        BTreeSet::from(["module_facade/src/lib.rs".to_string()])
    );

    let chained = execute_code_query_detailed_eager_index(
        workspace.analyzer(),
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        &importer_query("exported_target", 2),
        CodeQueryExecutionLimits::default(),
        None,
    );
    let helper = chained
        .result
        .results
        .iter()
        .find(|item| matches!(&item.value, CodeQueryResultValue::File { value } if value.path == "chain_helper_client/src/lib.rs"))
        .expect("the file importing the chain's helper is reachable in two file hops");
    let trace = helper
        .provenance
        .iter()
        .find(|trace| {
            trace.steps.len() == 3
                && file_ref_path(&trace.steps[1].result) == "chain/src/lib.rs"
                && file_ref_path(&trace.steps[2].result) == "chain_helper_client/src/lib.rs"
        })
        .expect("both importers-of links remain in result provenance");
    assert_eq!(trace.steps[0].op, "file_of");
    assert_eq!(trace.steps[1].op, "importers_of");
    assert_eq!(trace.steps[2].op, "importers_of");
    assert_eq!(file_ref_path(&trace.steps[0].result), "source/src/inner.rs");

    let source_root = project.file("source/src/lib.rs");
    source_root
        .write("pub fn root_marker() {}\npub mod other;\npub mod inner;\n")
        .expect("reorder source declarations without changing its exported names");
    let updated = workspace.update(&BTreeSet::from([source_root]));
    let module_after_reorder = execute_code_query_detailed_eager_index(
        updated.analyzer(),
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        &importer_query("root_marker", 1),
        CodeQueryExecutionLimits::default(),
        None,
    );
    assert_eq!(
        file_paths(&module_after_reorder),
        BTreeSet::from(["module_facade/src/lib.rs".to_string()])
    );
}

#[test]
fn rust_import_graph_includes_block_local_importers() {
    let project = local_import_workspace();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = importer_query("target", 2);

    let persisted = execute_code_query_with_access_mode(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits::default(),
        StructuralAccessMode::IndexedRequired,
        true,
    )
    .expect("persist the Rust import graph");
    let fresh = execute_code_query_detailed_eager_index(
        workspace.analyzer(),
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        &query,
        CodeQueryExecutionLimits::default(),
        None,
    );

    assert_eq!(persisted.result.completion(), CodeQueryCompletion::Complete);
    assert_eq!(fresh.result.completion(), CodeQueryCompletion::Complete);
    assert_eq!(file_paths(&persisted), file_paths(&fresh));
    assert!(file_paths(&persisted).contains("client/src/lib.rs"));
}

mod import_graph_properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 2,
            max_shrink_iters: 16,
            ..ProptestConfig::default()
        })]

        #[test]
        fn incremental_import_graph_matches_fresh_after_edit_sequences(
            edits in prop::collection::vec(0u8..3, 1..=2)
        ) {
            let project = InlineTestProject::with_language(Language::Rust)
                .file(
                    "Cargo.toml",
                    "[workspace]\nmembers = [\"source\", \"client\"]\nresolver = \"2\"\n",
                )
                .file(
                    "source/Cargo.toml",
                    "[package]\nname = \"source\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
                )
                .file(
                    "source/src/lib.rs",
                    "pub mod first;\npub mod second;\npub mod dynamic;\n",
                )
                .file("source/src/first.rs", "pub fn stable() {}\n")
                .file("source/src/second.rs", "pub fn stable() {}\n")
                .file("source/src/dynamic.rs", "")
                .file(
                    "client/Cargo.toml",
                    "[package]\nname = \"client\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nsource = { path = \"../source\" }\n",
                )
                .file(
                    "client/src/lib.rs",
                    "use source::first::stable;\nuse source::dynamic::arriving;\npub fn call() { stable(); arriving(); }\n",
                )
                .build();
            let mut workspace = project.workspace_analyzer(AnalyzerConfig::default());
            let baseline = execute_code_query_with_access_mode(
                workspace.analyzer(),
                &importer_query_at("stable", "source/src/first.rs"),
                CodeQueryExecutionLimits::default(),
                StructuralAccessMode::IndexedRequired,
                true,
            )
            .expect("build the baseline persisted graph");
            prop_assert_eq!(baseline.result.completion(), CodeQueryCompletion::Complete);
            let mut target = "source/src/first.rs";
            for edit in edits {
                let changed = match edit {
                    0 => {
                        let file = project.file("client/src/lib.rs");
                        file.write("use source::second::stable;\nuse source::dynamic::arriving;\npub fn call() { stable(); arriving(); }\n")
                            .expect("change the selected crate route");
                        target = "source/src/second.rs";
                        file
                    }
                    1 => {
                        let file = project.file("source/src/dynamic.rs");
                        file.write("pub fn arriving() {}\n")
                            .expect("add the previously unresolved item");
                        target = "source/src/dynamic.rs";
                        file
                    }
                    _ => {
                        let file = project.file("source/src/second.rs");
                        file.write("pub fn stable() {}\npub fn extra_second() {}\n")
                            .expect("edit the second target");
                        file
                    }
                };
                let query = importer_query_at("stable", target);
                let (updated, result) = assert_incremental_matches_fresh(
                    &project,
                    &workspace,
                    [changed],
                    &query,
                );
                prop_assert_eq!(result.result.completion(), CodeQueryCompletion::Complete);
                workspace = updated;
            }
        }
    }
}
