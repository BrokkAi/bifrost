mod common;

use brokk_bifrost::Language;
use common::InlineTestProject;
use common::usage_graph::{has_edge, usage_graph_at};
use std::fmt::Write as _;
use std::sync::mpsc;
use std::time::Duration;

/// Regression test for issue #549: the JS/TS usage-graph scan runs under a rayon
/// `par_iter`, and receiver analysis inside the scan can lazily initialize the
/// analyzer-cached `JsTsUsageIndex`, whose builder also uses rayon. With a blocking
/// once-cell that interleaving deadlocks: workers park on the cell, and the
/// initializing worker — while waiting for inner parse tasks stolen by idle
/// workers — pops a pending outer scan task from its own deque and re-enters the
/// cell it is initializing.
///
/// The deadlock needs most files to NOT trigger the index lookup (so workers go
/// idle and steal the initializer's inner parse tasks instead of parking
/// immediately) and a few files that DO trigger it (so the initializer can
/// re-enter via a popped outer task). The mix below hangs reliably on the
/// pre-fix code and completes in seconds on the fixed code.
#[test]
fn jsts_usage_graph_receiver_analysis_does_not_deadlock_on_pool() {
    let mut project = InlineTestProject::with_language(Language::JavaScript).file(
        "lib.js",
        r#"
export function makeThing() {
    return {
        frob() {
            return 1;
        }
    };
}
"#,
    );

    // Noise files: no imports, so their scan never consults the shared index.
    // They keep workers busy and then idle (stealing inner parse work) while the
    // first triggering file initializes the index.
    for index in 0..300 {
        let mut body = String::new();
        for line in 0..40 {
            writeln!(
                body,
                "export function noise{index}_{line}() {{ return {index} + {line}; }}"
            )
            .expect("write noise body");
        }
        project = project.file(format!("noise{index}.js"), body);
    }

    // Large late-sorting files: their parses are the slow tasks inside the
    // index builder's own par_iter. An idle worker steals one while the
    // initializing worker drains its local deque and pops a pending consumer
    // scan task — the reentrant get_or_init the pre-fix code deadlocks on.
    for index in 0..8 {
        let mut body = String::new();
        for line in 0..4000 {
            writeln!(
                body,
                "export function big{index}_{line}() {{ return {index} * {line}; }}"
            )
            .expect("write big body");
        }
        project = project.file(format!("zz_big{index}.js"), body);
    }

    // Triggering files: an imported-function call whose receiver analysis
    // consults the analyzer-cached JS/TS usage index from inside the scan.
    for index in 0..24 {
        project = project.file(
            format!("zzz_consumer{index}.js"),
            format!(
                r#"
import {{ makeThing }} from "./lib.js";

export function run{index}() {{
    const thing = makeThing();
    return thing.frob();
}}
"#
            ),
        );
    }

    let project = project.build();
    let root = project.root().to_path_buf();
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let result = std::panic::catch_unwind(|| {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(4)
                .build()
                .expect("rayon pool");
            pool.install(|| usage_graph_at(&root, "{}"))
        });
        tx.send(result).expect("send usage_graph result");
    });

    let graph = rx
        .recv_timeout(Duration::from_secs(240))
        .expect("JS/TS usage_graph hung while receiver analysis initialized usage indexes");
    let graph = match graph {
        Ok(graph) => graph,
        Err(payload) => std::panic::resume_unwind(payload),
    };

    assert!(
        has_edge(&graph, "run0", "makeThing"),
        "the triggering imported call must remain a cross-file usage edge: {}",
        graph["edges"]
    );
}
