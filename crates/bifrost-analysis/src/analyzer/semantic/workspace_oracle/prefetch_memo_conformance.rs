use super::*;
use crate::analyzer::usages::common::{
    QueryMemoOwner, assert_memo_owner_conformance_for_test, replay_memo_reads,
};

pub fn concrete_prefetch_memo_completion() {
    // Native prefetch requires independent reader connections and parallel workers.
    rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build()
        .unwrap()
        .install(|| {
            let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
                .with_git()
                .file(
                    "Cargo.toml",
                    concat!(
                        "[package]\n",
                        "name = \"memo-prefetch\"\n",
                        "version = \"0.1.0\"\n",
                        "edition = \"2021\"\n"
                    ),
                )
                .file("src/lib.rs", "fn target() {} pub fn run() { target(); }")
                .build();
            let workspace = crate::analyzer::WorkspaceAnalyzer::build_persisted_for_languages(
                project.certified_project_dyn(),
                Default::default(),
                &std::collections::BTreeSet::from([Language::Rust]),
            )
            .unwrap();
            let analyzer = workspace.analyzer();
            let caller = analyzer
                .search_definitions("run", false)
                .into_iter()
                .next()
                .unwrap();
            let scope = AnalyzerQueryScope::new(analyzer);
            let sites = CallRelationService::outgoing_bounded(
                analyzer,
                scope.token(),
                &caller,
                crate::analyzer::usages::call_relations::CallRelationLimits {
                    max_files: usize::MAX,
                    max_source_bytes: usize::MAX,
                    max_candidates: usize::MAX,
                },
                None,
            )
            .sites;
            assert_eq!(sites.len(), 1);
            let file = sites[0].file.clone();
            let oracle = WorkspaceSemanticOracle::new(&workspace);
            let cancellation = crate::cancellation::CancellationToken::new();
            assert_memo_owner_conformance_for_test(
                QueryMemoOwner::DispatchPrefetch,
                analyzer,
                || oracle.prepare_workspace_dispatch_pool(),
                |pool| {
                    if pool.prefetched.lock().unwrap().is_empty() {
                        let mut budget = crate::analyzer::semantic::SemanticBudget::default();
                        pool.prefetch_callers(
                            &sites,
                            &SemanticRequest::new(&mut budget, &cancellation),
                        )
                        .unwrap();
                    }
                    // The real producer fills the speculative product. Inspect the
                    // same receipt that the consuming dispatch session removes/replays.
                    if let Some((product, reads)) = pool.prefetched.lock().unwrap().get(&file) {
                        assert_eq!(product.outcomes.len(), 1);
                        replay_memo_reads(reads, analyzer);
                    }
                },
                |pool| !pool.prefetched.lock().unwrap().is_empty(),
            );
        });
}
