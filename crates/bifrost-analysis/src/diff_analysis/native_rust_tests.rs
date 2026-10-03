use super::*;
use crate::OverlayProject;
use crate::analyzer::{CodeUnitIndex, RustAnalyzer};
use crate::analyzer::{
    RustNativeWorkspaceGraphOutcome, build_rust_native_workspace_graph_for_files,
};
use crate::inline_project::InlineTestProject;
use crate::searchtools::{UsageGraphResult, selected_usage_graph_result};
use std::sync::Arc;

fn rooted_graph(rust: &RustAnalyzer, caller: &ProjectFile) -> UsageGraphResult {
    let cancellation = crate::CancellationToken::new();
    let outcome = build_rust_native_workspace_graph_for_files(
        rust,
        std::slice::from_ref(caller),
        1,
        &cancellation,
    )
    .expect("native rooted graph");
    let (complete, graph) = match outcome {
        RustNativeWorkspaceGraphOutcome::Complete(graph) => (true, graph),
        RustNativeWorkspaceGraphOutcome::Incomplete(graph) => (false, graph),
        RustNativeWorkspaceGraphOutcome::Cancelled => panic!("unexpected cancellation"),
        RustNativeWorkspaceGraphOutcome::Stale(reason) => panic!("unexpected stale: {reason}"),
        RustNativeWorkspaceGraphOutcome::Unavailable(reason) => {
            panic!("unexpected unavailable: {reason}")
        }
    };
    selected_usage_graph_result(graph, complete, &cancellation)
        .expect("shared graph rendering completes")
}

#[test]
fn native_rooted_two_world_diff_retains_foreign_endpoints_and_completion() {
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"native_diff\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file(
            "src/lib.rs",
            "pub mod api; pub mod caller; pub mod hidden;\n",
        )
        .file("src/api.rs", "pub fn left() {}\npub fn right() {}\n")
        .file(
            "src/caller.rs",
            "pub fn caller() {\n    crate::api::left(); crate::api::left();\n}\n",
        )
        .file("src/hidden.rs", "unknown_macro!();\n")
        .build();
    let base = RustAnalyzer::new(fixture.project_dyn());
    let caller_file = fixture.file("src/caller.rs");
    let api_file = fixture.file("src/api.rs");
    let before = rooted_graph(&base, &caller_file);
    assert!(before.complete, "{before:?}");
    let [old_edge] = before.edges.as_slice() else {
        panic!("one rooted foreign call edge: {before:?}");
    };
    assert_eq!(
        old_edge.weight, 1,
        "same-line references share one call site"
    );
    assert_eq!(
        old_edge.sites,
        [UsageGraphCallSite {
            path: "src/caller.rs".into(),
            line: 2
        }]
    );
    let base_api = base.declarations(&api_file);
    let left = base_api
        .iter()
        .find(|unit| unit.identifier() == "left")
        .unwrap();
    let right = base_api
        .iter()
        .find(|unit| unit.identifier() == "right")
        .unwrap();
    assert_eq!(old_edge.to_id, left.declaration_id());

    for (suffix, expected_complete) in [("", true), ("include!(\"generated.rs\");\n", false)] {
        let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
        assert!(overlay.set(
            caller_file.abs_path(),
            format!("pub fn caller() {{\n\n    crate::api::right();\n}}\n{suffix}"),
        ));
        let target = base.clone_with_project(Arc::new(overlay.snapshot()));
        assert!(!target.declarations(&caller_file).is_empty());
        let after = rooted_graph(&target, &caller_file);
        assert_eq!(after.complete, expected_complete, "{after:?}");
        assert_eq!(
            after.incomplete_reasons.is_empty(),
            expected_complete,
            "{after:?}"
        );
        let [new_edge] = after.edges.as_slice() else {
            panic!("one positive foreign edge survives either completion state: {after:?}");
        };
        assert_eq!(new_edge.from_id, old_edge.from_id);
        assert_eq!(new_edge.to_id, right.declaration_id());
        assert_eq!(
            new_edge.sites,
            [UsageGraphCallSite {
                path: "src/caller.rs".into(),
                line: 3
            }]
        );
        assert!(after.nodes.iter().all(|node| node.path != "src/hidden.rs"));

        // Compare only the sound positive graphs. The target's separate
        // completeness remains false when omitted syntax prevents absence
        // certification; diff reduction must not erase that evidence.
        let postimage = symbol_snapshot_map(&target, true);
        let diff = diff_call_edges(&before.edges, &after.edges, &HashMap::default(), &postimage);
        assert_eq!(diff.deltas.len(), 1);
        let delta = &diff.deltas[&(new_edge.from.clone(), new_edge.language.clone())];
        assert_eq!(delta.added.len(), 1);
        assert_eq!(delta.removed.len(), 1);
        assert_eq!(delta.added[0].to, right.fq_name());
        assert_eq!(delta.removed[0].to, left.fq_name());
        assert_eq!(delta.added[0].sites, new_edge.sites);
        assert_eq!(delta.removed[0].sites, old_edge.sites);
        assert_eq!(diff.dependency_symbols.len(), 1);
        assert_eq!(diff.dependency_symbols[0].fqn, right.fq_name());
        assert_eq!(diff.dependency_symbols[0].path, "src/api.rs");

        let unchanged =
            diff_call_edges(&after.edges, &after.edges, &HashMap::default(), &postimage);
        assert!(unchanged.deltas.is_empty());
        assert!(unchanged.dependency_symbols.is_empty());
        assert_eq!(after.complete, expected_complete);
    }
}
