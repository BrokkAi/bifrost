use super::JavaAnalyzer;
use crate::inline_project::InlineTestProject;
use brokk_bifrost_analysis::analyzer::i_analyzer::{AnalyzerQueryScope, IAnalyzer};
use brokk_bifrost_analysis::analyzer::read_ledger::{ReadKey, ReadLedger};
use brokk_bifrost_core::analyzer::model::Language;
use brokk_bifrost_core::analyzer::project::{OverlayProject, Project};
use brokk_bifrost_test_macros::hardwon;
use std::sync::Arc;

#[test]
#[hardwon("#7424: enum-switch proofs depend on another file and its current snapshot")]
fn enum_switch_cache_replays_reads_and_tracks_overlay_changes() {
    let original_enum = "enum Mode { A, B }";
    let project = InlineTestProject::with_language(Language::Java)
        .file("Mode.java", original_enum)
        .file(
            "Use.java",
            "class Use { void run(Mode m) { switch (m) { case A: break; } } }",
        )
        .build();
    let analyzer = JavaAnalyzer::new(project.project_dyn());
    let use_file = project.file("Use.java");
    let enum_file = project.file("Mode.java");
    let enum_oid = git2::Oid::hash_object(git2::ObjectType::Blob, original_enum.as_bytes())
        .expect("enum blob hash");

    let query = || {
        let ledger = Arc::new(ReadLedger::new());
        let scope = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&ledger));
        let rows = analyzer.statement_source_facts(&use_file).expect("facts");
        drop(scope);
        (rows, ledger.keys())
    };
    let (cold, cold_reads) = query();
    let (warm, warm_reads) = query();
    assert!(cold.switches[0].missing_enum_case, "{cold:?}");
    assert!(
        Arc::ptr_eq(&cold, &warm),
        "the second read must hit the cache"
    );
    assert_eq!(cold_reads, warm_reads);
    assert!(
        warm_reads.contains(&ReadKey::file(Language::Java, "Mode.java", enum_oid)),
        "enum declaration must be a replayed input: {warm_reads:?}"
    );

    let overlay = OverlayProject::new(project.project_dyn());
    assert!(overlay.set(enum_file.abs_path(), "enum Mode { A }".into()));
    let complete = analyzer.clone_with_project(Arc::new(overlay.snapshot()) as Arc<dyn Project>);
    let rows = complete
        .statement_source_facts(&use_file)
        .expect("overlay facts");
    assert!(!rows.switches[0].missing_enum_case, "{rows:?}");
    assert!(!rows.switches[0].enum_proof_undecided, "{rows:?}");

    assert!(overlay.set(enum_file.abs_path(), "enum Mode { A, B, C }".into()));
    let missing = analyzer.clone_with_project(Arc::new(overlay.snapshot()) as Arc<dyn Project>);
    let rows = missing
        .statement_source_facts(&use_file)
        .expect("updated facts");
    assert!(rows.switches[0].missing_enum_case, "{rows:?}");
    let rows = complete
        .statement_source_facts(&use_file)
        .expect("old snapshot facts");
    assert!(!rows.switches[0].missing_enum_case, "{rows:?}");
}
