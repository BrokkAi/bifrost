//! Shared source-backed ICFGs used by multiple data-flow behaviors.

use brokk_bifrost::{AnalyzerConfig, Language};

use crate::common::{
    InlineTestProject,
    semantic_graph::{CallContextSelector, IcfgGraph, PointSelector},
};

pub fn rust_choose_icfg() -> IcfgGraph {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
                pub fn choose(flag: bool) -> i32 {
                    if flag { 1 } else { 2 }
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = IcfgGraph::materialize(
        &project,
        &analyzer,
        "lib.rs",
        PointSelector::new("pub fn choose")
            .procedure("choose")
            .effect("entry"),
    );
    graph.bind_node(
        "root",
        "lib.rs",
        PointSelector::new("pub fn choose")
            .procedure("choose")
            .effect("entry"),
        CallContextSelector::root(),
    );
    graph
}

pub fn rust_deferred_call_icfg() -> IcfgGraph {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "leaf.rs",
            r#"
                pub async fn async_leaf() -> i32 {
                    7
                }
            "#,
        )
        .file(
            "lib.rs",
            r#"
                mod leaf;
                use crate::leaf::async_leaf;

                pub fn make_future() {
                    let _pending = async_leaf();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = IcfgGraph::materialize(
        &project,
        &analyzer,
        "lib.rs",
        PointSelector::new("pub fn make_future")
            .procedure("make_future")
            .effect("entry"),
    );
    graph.bind_node(
        "root",
        "lib.rs",
        PointSelector::new("pub fn make_future")
            .procedure("make_future")
            .effect("entry"),
        CallContextSelector::root(),
    );
    graph
}
