use brokk_bifrost_analysis::analyzer::AnalyzerQueryScope;
use brokk_bifrost_analysis::analyzer::i_analyzer::capture_query_reads;
use brokk_bifrost_analysis::analyzer::i_analyzer::{IAnalyzer, SearchSymbolPatternBatch};
use brokk_bifrost_analysis::analyzer::read_ledger::{
    FactSubject, LookupQuestion, ReadKey, WorkspaceFactFamily,
};
use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;
use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
use brokk_bifrost_core::analyzer::model::{CodeUnitType, Language};
use brokk_bifrost_core::analyzer::project::OverlayProject;
use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;
use brokk_bifrost_test_macros::hardwon;
use std::sync::Arc;
use std::sync::atomic::Ordering;

#[test]
fn overlay_identifier_candidate_memo_replays_overlay_authority() {
    let fixture = crate::inline_project::InlineTestProject::with_language(Language::Java)
        .file("Worker.java", "class Worker {}\n")
        .build();
    let disk = TreeSitterAnalyzer::new(fixture.project_dyn(), JavaAdapter);
    let overlay = OverlayProject::new(fixture.project_dyn());
    assert!(overlay.set(
        fixture.file("Worker.java").abs_path(),
        "class Worker { int edited; }\n".to_string()
    ));
    let request = disk.clone_with_project(Arc::new(overlay.snapshot()));
    let _scope = AnalyzerQueryScope::for_identifier_candidate_memo(&request);
    let (first, first_reads) = capture_query_reads(&request, || {
        request.lookup_declarations_by_identifier_limited("Worker", 100, || true)
    });
    let (second, second_reads) = capture_query_reads(&request, || {
        request.lookup_declarations_by_identifier_limited("Worker", 100, || true)
    });
    let executions = request
        .query_read_cache_lock()
        .identifier_candidate_query_executions
        .load(Ordering::Relaxed);
    assert_eq!(
        executions, 1,
        "the overlay fill must be memoized within its request"
    );
    let first_keys = first_reads.keys();
    assert_eq!(
        first_keys,
        second_reads.keys(),
        "the overlay hit must replay every fill read"
    );
    assert!(first_keys.iter().any(|key| matches!(key, ReadKey::File { rel_path, .. } if rel_path.as_ref() == "Worker.java")), "{first_keys:?}");
    assert!(
        first_keys.iter().any(|key| matches!(
            key,
            ReadKey::Lookup {
                question: LookupQuestion::WorkspaceFact {
                    family: WorkspaceFactFamily::WorkspaceOverlayMembership,
                    subject: FactSubject::Whole,
                    ..
                },
                ..
            }
        )),
        "{first_keys:?}"
    );
    assert_eq!(first, second);
    drop(_scope);

    // A later disk request has a separate memo and cannot inherit the
    // overlay-specific file and membership receipt.
    let _disk_scope = AnalyzerQueryScope::for_identifier_candidate_memo(&disk);
    let (disk_rows, disk_reads) = capture_query_reads(&disk, || {
        disk.lookup_declarations_by_identifier_limited("Worker", 100, || true)
    });
    assert!(disk_rows.complete);
    assert_eq!(
        disk.query_read_cache_lock()
            .identifier_candidate_query_executions
            .load(Ordering::Relaxed),
        1
    );
    assert_ne!(first_keys, disk_reads.keys());
}

#[test]
#[hardwon("#7821: bounded declaration lookups and hierarchy facts ignored unsaved-buffer overlays")]
fn overlay_bounded_declarations_match_fresh_disk_after_class_rename() {
    let fixture = crate::inline_project::InlineTestProject::with_language(Language::Java)
        .file("Example.java", "package demo; class Before {}\n")
        .build();
    let disk = TreeSitterAnalyzer::new(fixture.project_dyn(), JavaAdapter);
    let baseline = disk.lookup_declarations_by_identifier_limited("Before", 100, || true);
    assert!(baseline.complete, "persisted baseline: {baseline:?}");
    assert!(baseline.inspected > 0, "baseline must read persisted rows");
    assert_eq!(baseline.rows.len(), 1, "persisted baseline: {baseline:?}");

    let edited = "package demo; class After {}\n";
    let file = fixture.file("Example.java");
    let overlay = OverlayProject::new(fixture.project_dyn());
    assert!(overlay.set(file.abs_path(), edited.to_string()));
    let request = disk.clone_with_project(Arc::new(overlay.snapshot()));
    assert!(request.workspace_declaration_identities_authoritative());

    // Collect every bounded result before an unbounded read can hydrate the
    // overlay. Each result records completeness as well as declaration names.
    let observations = |analyzer: &TreeSitterAnalyzer<JavaAdapter>| {
        let mut results = Vec::new();
        for name in ["After", "Before"] {
            // Give symbol search its own cold request so earlier bounded
            // lookups cannot update its live paths and hide stale candidates.
            let symbols = analyzer.clone_with_project(Arc::clone(&analyzer.project));
            let patterns = SearchSymbolPatternBatch::compile(vec![name.to_string()], false, None);
            let symbols = symbols.search_symbol_candidates(&patterns, None);
            results.push((
                format!("symbol_search({name})"),
                symbols.complete,
                symbols
                    .rows
                    .iter()
                    .map(|row| row.code_unit.fq_name())
                    .collect(),
            ));
            let fqn = format!("demo.{name}");
            for (entry, result) in [
                (
                    "identifier",
                    analyzer.lookup_declarations_by_identifier_limited(name, 100, || true),
                ),
                (
                    "non_module_identifier",
                    analyzer.lookup_non_module_declarations_by_identifier_limited(
                        name,
                        100,
                        || true,
                    ),
                ),
                (
                    "fqn",
                    analyzer.lookup_declarations_by_fqn_limited(&fqn, 100, || true),
                ),
                (
                    "non_module_fqn",
                    analyzer.lookup_non_module_declarations_by_fqn_limited(&fqn, 100, || true),
                ),
            ] {
                let names = result
                    .rows
                    .iter()
                    .map(|unit| unit.fq_name())
                    .collect::<Vec<_>>();
                results.push((format!("{entry}({name})"), result.complete, names));
            }
        }
        let hierarchy = analyzer
            .hierarchy_declaration_facts_by_kind(CodeUnitType::Class)
            .expect("hierarchy query succeeds");
        results.push((
            "hierarchy(Class)".to_string(),
            true,
            hierarchy
                .iter()
                .map(|row| row.declaration.fq_name())
                .collect(),
        ));
        results
    };
    let actual = observations(&request);
    eprintln!("overlay bounded/hierarchy observations: {actual:#?}");
    let unbounded = request
        .get_all_declarations()
        .into_iter()
        .filter(|unit| unit.is_class())
        .map(|unit| unit.fq_name())
        .collect::<Vec<_>>();
    assert_eq!(unbounded, ["demo.After"], "overlay was attached correctly");

    // The oracle is a new analyzer over the edited bytes on disk, not an
    // alternate query on the request whose caches may already be warmed.
    file.write(edited)
        .expect("write edited source for fresh oracle");
    let fresh = TreeSitterAnalyzer::new(fixture.project_dyn(), JavaAdapter);
    let expected = observations(&fresh);
    eprintln!("fresh disk bounded/hierarchy observations: {expected:#?}");
    assert!(expected.iter().all(|(_, complete, _)| *complete));
    assert_eq!(expected[0].2, ["demo.After"], "oracle must find new name");
    assert!(expected[5].2.is_empty(), "oracle must omit old name");
    assert_eq!(
        actual, expected,
        "bounded overlay queries must match fresh disk"
    );
}
