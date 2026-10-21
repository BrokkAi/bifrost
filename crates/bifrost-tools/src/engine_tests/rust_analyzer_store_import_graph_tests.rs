#[cfg(test)]
mod rust_departing_tests_tests {

    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;

    use brokk_bifrost_analysis::analyzer::store::WorkspaceId;

    use brokk_bifrost_analysis::analyzer::store::import_graph::WorkspaceImportDirection;

    use brokk_bifrost_analysis::analyzer::store::import_graph::WorkspaceImportGraphBinding;

    use brokk_bifrost_analysis::analyzer::store::import_graph::WorkspaceImportGraphDependencies;

    use brokk_bifrost_analysis::analyzer::store::import_graph::WorkspaceImportGraphEdge;

    use brokk_bifrost_analysis::analyzer::store::import_graph::WorkspaceImportGraphSource;

    use brokk_bifrost_analysis::analyzer::store::import_graph::rust_tests_test_support::publish_initial_with_dependencies;

    use brokk_bifrost_analysis::analyzer::store::import_graph::rust_tests_test_support::stored_import_graph_facts;
    fn rust_graph_sources(
        analyzer: &brokk_bifrost_rust_analysis::RustAnalyzer,
        files: &[brokk_bifrost_core::analyzer::model::ProjectFile],
    ) -> Vec<WorkspaceImportGraphSource> {
        use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

        let provider = analyzer
            .import_analysis_provider()
            .expect("Rust analyzer exposes import graph facts");
        let mut module_path_keys = provider
            .import_graph_module_path_keys_for_files(files)
            .expect("Rust module keys are available for every fixture source");
        let mut binding_surfaces = provider
            .import_graph_binding_surfaces_for_files(files, None)
            .expect("Rust binding surfaces are available for every fixture source");
        files
            .iter()
            .map(|file| {
                let contents = std::fs::read(file.abs_path()).expect("read Rust source identity");
                let mut hasher = CanonicalHasher::new(b"test-rust-import-source:v1");
                hasher.field(
                    "path",
                    brokk_bifrost_core::path_utils::rel_path_string(file).as_bytes(),
                );
                hasher.field("contents", &contents);
                let binding_surface = binding_surfaces
                    .remove(file)
                    .expect("Rust provider returns binding surfaces for every source")
                    .into_iter()
                    .flat_map(WorkspaceImportGraphBinding::from_provider_surface)
                    .collect();
                WorkspaceImportGraphSource {
                    source_path: brokk_bifrost_core::path_utils::rel_path_string(file),
                    source_identity: hasher.finish(),
                    module_path_keys: module_path_keys
                        .remove(file)
                        .expect("Rust provider returns module keys for every source"),
                    complete_resolution_dependencies: true,
                    input_digests: None,
                    binding_surface: Some(binding_surface),
                }
            })
            .collect()
    }

    fn rust_graph_facts(
        analyzer: &brokk_bifrost_rust_analysis::RustAnalyzer,
        files: &[brokk_bifrost_core::analyzer::model::ProjectFile],
        selected_ordinals: Option<
            &brokk_bifrost_core::hash::HashMap<
                brokk_bifrost_core::analyzer::model::ProjectFile,
                Vec<u32>,
            >,
        >,
    ) -> brokk_bifrost_analysis::analyzer::structural::derived_cache::RequestLocalDirectImportGraph
    {
        use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

        use brokk_bifrost_core::analyzer::query_token::QueryScope;

        use brokk_bifrost_core::cancellation::CancellationToken;

        let analyzed_files = brokk_bifrost_core::analyzer::CodeUnitIndex::analyzed_files(analyzer);
        let mut graph =
            brokk_bifrost_analysis::analyzer::structural::derived_cache::RequestLocalDirectImportGraph::from_files(
                analyzed_files,
            );
        let scope = AnalyzerQueryScope::new(analyzer);
        let cancellation = CancellationToken::default();
        let exhausted = if let Some(selected_ordinals) = selected_ordinals {
            graph.ensure_forward_selected(
                analyzer,
                scope.token(),
                files,
                selected_ordinals,
                files.len().saturating_add(1),
                10_000,
                Some(&cancellation),
            )
        } else {
            graph.ensure_complete(
                analyzer,
                scope.token(),
                files.len().saturating_add(1),
                10_000,
                Some(&cancellation),
            )
        };
        assert!(!exhausted, "Rust import graph work fits the test limits");
        graph
    }

    fn store_facts_from_request_graph(
        graph: &brokk_bifrost_analysis::analyzer::structural::derived_cache::RequestLocalDirectImportGraph,
    ) -> (
        Vec<WorkspaceImportGraphEdge>,
        Vec<WorkspaceImportGraphDependencies>,
    ) {
        let edges = graph
            .persisted_edges()
            .into_iter()
            .map(|edge| WorkspaceImportGraphEdge {
                importer_path: brokk_bifrost_core::path_utils::rel_path_string(&edge.importer),
                import_ordinal: edge.import_ordinal,
                target_path: brokk_bifrost_core::path_utils::rel_path_string(&edge.target),
                provenance_json: edge.provenance_json,
                route_dependencies: edge.route_dependencies,
            })
            .collect();
        let dependencies = graph
            .persisted_resolution_dependencies()
            .into_iter()
            .map(|dependency| WorkspaceImportGraphDependencies {
                importer_path: brokk_bifrost_core::path_utils::rel_path_string(
                    &dependency.importer,
                ),
                lookups: dependency
                    .facts
                    .lookups
                    .into_iter()
                    .map(|lookup| {
                        (
                            lookup.import_ordinal,
                            brokk_bifrost_core::path_utils::rel_path_string(&lookup.consulted_file),
                            lookup.name,
                        )
                    })
                    .collect(),
                missing_module_path_keys: dependency.facts.missing_module_path_keys,
            })
            .collect();
        (edges, dependencies)
    }

    fn stored_adjacency(
        store: &AnalyzerStore,
        workspace_id: &WorkspaceId,
        identity: &[u8; 32],
        sources: &[WorkspaceImportGraphSource],
    ) -> Vec<(String, String)> {
        store
            .read_workspace_import_graph(
                workspace_id,
                identity,
                WorkspaceImportDirection::Forward,
                &sources
                    .iter()
                    .map(|source| source.source_path.clone())
                    .collect::<Vec<_>>(),
                10_000,
            )
            .expect("read stored Rust graph")
            .expect("graph identity is current")
            .edges
    }

    #[allow(clippy::too_many_arguments)]
    fn refresh_rust_graph_and_compare_to_fresh(
        store: &AnalyzerStore,
        workspace_id: &WorkspaceId,
        previous_identity: &[u8; 32],
        current_identity: &[u8; 32],
        resolver: &[u8; 32],
        analyzer: &brokk_bifrost_rust_analysis::RustAnalyzer,
        expected_work: (usize, usize, usize),
        expected_lookup_ordinals: &[(&str, u32)],
    ) {
        let files = brokk_bifrost_core::analyzer::CodeUnitIndex::analyzed_files(analyzer);
        let sources = rust_graph_sources(analyzer, &files);
        assert!(
            store
                .read_workspace_import_graph(
                    workspace_id,
                    previous_identity,
                    WorkspaceImportDirection::Forward,
                    &sources
                        .iter()
                        .map(|source| source.source_path.clone())
                        .collect::<Vec<_>>(),
                    10_000,
                )
                .expect("read previous Rust graph")
                .is_some(),
            "incremental refresh starts from the previous graph identity"
        );
        let plan = store
            .plan_workspace_import_graph_refresh(workspace_id, current_identity, resolver, &sources)
            .expect("plan incremental Rust graph refresh");
        assert!(!plan.full_rebuild);
        assert_eq!(
            plan.dirty_lookup_ordinals,
            expected_lookup_ordinals
                .iter()
                .map(|(path, ordinal)| ((*path).to_owned(), *ordinal))
                .collect::<Vec<_>>(),
            "only imports whose candidate or missing-module lookup rows change are republished"
        );
        let before_facts = stored_import_graph_facts(store, workspace_id);
        let dirty_lookup_ordinals = plan
            .dirty_lookup_ordinals
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<_>>();
        let unchanged_candidate_rows = before_facts
            .2
            .iter()
            .filter(|(path, ordinal, _, _)| {
                plan.dirty_importer_paths.binary_search(path).is_err()
                    && !dirty_lookup_ordinals.contains(&(
                        path.clone(),
                        u32::try_from(*ordinal).expect("stored import ordinal fits u32"),
                    ))
            })
            .cloned()
            .collect::<Vec<_>>();
        let unchanged_missing_module_rows = before_facts
            .3
            .iter()
            .filter(|(path, ordinal, _)| {
                plan.dirty_importer_paths.binary_search(path).is_err()
                    && !dirty_lookup_ordinals.contains(&(
                        path.clone(),
                        u32::try_from(*ordinal).expect("stored import ordinal fits u32"),
                    ))
            })
            .cloned()
            .collect::<Vec<_>>();

        let mut dirty_paths = plan
            .dirty_importer_paths
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<_>>();
        dirty_paths.extend(
            plan.dirty_import_ordinals
                .iter()
                .map(|(path, _)| path.clone()),
        );
        let dirty_files = files
            .iter()
            .filter(|file| {
                dirty_paths.contains(&brokk_bifrost_core::path_utils::rel_path_string(file))
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut selected_ordinals = brokk_bifrost_core::hash::HashMap::default();
        for (path, ordinal) in &plan.dirty_import_ordinals {
            if plan.dirty_importer_paths.binary_search(path).is_ok() {
                continue;
            }
            let file = files
                .iter()
                .find(|file| brokk_bifrost_core::path_utils::rel_path_string(file) == *path)
                .expect("dirty import ordinal belongs to an analyzed Rust source");
            selected_ordinals
                .entry(file.clone())
                .or_insert_with(Vec::new)
                .push(*ordinal);
        }
        let graph = rust_graph_facts(analyzer, &dirty_files, Some(&selected_ordinals));
        assert_eq!(
            (
                graph.resolved_files(),
                graph.resolved_imports(),
                graph.resolved_edges(),
            ),
            expected_work,
            "incremental refresh recomputes only affected import facts"
        );
        let (edges, dependencies) = store_facts_from_request_graph(&graph);
        store
            .publish_workspace_import_graph_refresh(
                workspace_id,
                current_identity,
                resolver,
                &plan,
                sources.len(),
                &sources,
                &edges,
                &dependencies,
            )
            .expect("publish incremental Rust graph");
        let incremental = stored_adjacency(store, workspace_id, current_identity, &sources);
        let incremental_facts = stored_import_graph_facts(store, workspace_id);
        let carried_candidate_rows = incremental_facts
            .2
            .iter()
            .filter(|(path, ordinal, _, _)| {
                plan.dirty_importer_paths.binary_search(path).is_err()
                    && !dirty_lookup_ordinals.contains(&(
                        path.clone(),
                        u32::try_from(*ordinal).expect("stored import ordinal fits u32"),
                    ))
            })
            .cloned()
            .collect::<Vec<_>>();
        let carried_missing_module_rows = incremental_facts
            .3
            .iter()
            .filter(|(path, ordinal, _)| {
                plan.dirty_importer_paths.binary_search(path).is_err()
                    && !dirty_lookup_ordinals.contains(&(
                        path.clone(),
                        u32::try_from(*ordinal).expect("stored import ordinal fits u32"),
                    ))
            })
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            carried_candidate_rows, unchanged_candidate_rows,
            "route-only invalidation carries candidate lookup rows without republishing them"
        );
        assert_eq!(
            carried_missing_module_rows, unchanged_missing_module_rows,
            "route-only invalidation carries missing-module lookup rows without republishing them"
        );

        let fresh_store = AnalyzerStore::open_ephemeral().expect("fresh Rust graph store");
        let fresh_workspace_id = WorkspaceId::for_session();
        let fresh_graph = rust_graph_facts(analyzer, &files, None);
        let (fresh_edges, fresh_dependencies) = store_facts_from_request_graph(&fresh_graph);
        publish_initial_with_dependencies(
            &fresh_store,
            &fresh_workspace_id,
            current_identity,
            resolver,
            &sources,
            &fresh_edges,
            &fresh_dependencies,
        );
        let fresh_plan = fresh_store
            .plan_workspace_import_graph_refresh(
                &fresh_workspace_id,
                current_identity,
                resolver,
                &sources,
            )
            .expect("read fresh Rust graph plan");
        assert!(fresh_plan.current);
        // Initial publication above intentionally uses the common helper; the
        // already-current plan proves its query-facing rows match the snapshot.
        let fresh = stored_adjacency(
            &fresh_store,
            &fresh_workspace_id,
            current_identity,
            &sources,
        );
        let fresh_facts = stored_import_graph_facts(&fresh_store, &fresh_workspace_id);
        assert_eq!(
            incremental, fresh,
            "incremental graph equals a fresh rebuild"
        );
        assert_eq!(
            incremental_facts, fresh_facts,
            "incremental edge provenance and all dependency rows equal a fresh rebuild"
        );
    }

    #[test]
    fn rust_incremental_import_graph_work_matches_fresh_rebuild_for_reexport_and_leaf_edits() {
        use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_rust_analysis::RustAnalyzer;

        use brokk_bifrost_core::analyzer::project::TestProject;

        let temp = tempfile::tempdir().expect("Rust import graph fixture");
        let root = temp.path().canonicalize().expect("canonical fixture root");
        std::fs::create_dir_all(root.join("src")).expect("create fixture source directory");
        for (path, contents) in [
            (
                "Cargo.toml",
                "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            ),
            (
                "src/lib.rs",
                "pub mod client;\npub mod facade;\npub mod leaf;\npub mod origin;\npub mod other;\n",
            ),
            ("src/facade.rs", "pub use crate::origin::Widget;\n"),
            (
                "src/client.rs",
                "use crate::facade::Widget;\nuse crate::leaf::Leaf;\nuse crate::other::Other;\n",
            ),
            ("src/leaf.rs", "pub struct Leaf;\n"),
            ("src/origin.rs", "pub struct Widget;\n"),
            ("src/other.rs", "pub struct Other;\n"),
        ] {
            std::fs::write(root.join(path), contents).expect("write Rust fixture file");
        }
        let analyzer = RustAnalyzer::from_project(TestProject::new(root.clone(), Language::Rust));
        let files = brokk_bifrost_core::analyzer::CodeUnitIndex::analyzed_files(&analyzer);
        let sources = rust_graph_sources(&analyzer, &files);
        let initial_graph = rust_graph_facts(&analyzer, &files, None);
        assert_eq!(initial_graph.resolved_files(), files.len());
        let (initial_edges, initial_dependencies) = store_facts_from_request_graph(&initial_graph);
        let store = AnalyzerStore::open_ephemeral().expect("persistent graph fixture store");
        let workspace_id = WorkspaceId::for_session();
        let initial_identity = [91; 32];
        let resolver = [92; 32];
        publish_initial_with_dependencies(
            &store,
            &workspace_id,
            &initial_identity,
            &resolver,
            &sources,
            &initial_edges,
            &initial_dependencies,
        );

        let facade =
            brokk_bifrost_core::analyzer::model::ProjectFile::new(root.clone(), "src/facade.rs");
        std::fs::write(
            facade.abs_path(),
            "pub use crate::other::Other as Widget;\n",
        )
        .expect("edit re-export source");
        let after_reexport = analyzer.update(&std::collections::BTreeSet::from([facade]));
        let reexport_identity = [93; 32];
        refresh_rust_graph_and_compare_to_fresh(
            &store,
            &workspace_id,
            &initial_identity,
            &reexport_identity,
            &resolver,
            &after_reexport,
            (2, 2, 3),
            &[("src/client.rs", 0)],
        );

        let leaf =
            brokk_bifrost_core::analyzer::model::ProjectFile::new(root.clone(), "src/leaf.rs");
        std::fs::write(leaf.abs_path(), "pub struct Leaf;\npub struct LeafExtra;\n")
            .expect("edit leaf source");
        let after_leaf = after_reexport.update(&std::collections::BTreeSet::from([leaf]));
        refresh_rust_graph_and_compare_to_fresh(
            &store,
            &workspace_id,
            &reexport_identity,
            &[94; 32],
            &resolver,
            &after_leaf,
            (1, 0, 0),
            &[],
        );
    }

    #[test]
    fn rust_name_surface_cutoff_matches_fresh_after_body_item_and_glob_edits() {
        use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_rust_analysis::RustAnalyzer;

        use brokk_bifrost_core::analyzer::project::TestProject;

        let temp = tempfile::tempdir().expect("Rust binding surface fixture");
        let root = temp.path().canonicalize().expect("canonical fixture root");
        std::fs::create_dir_all(root.join("src")).expect("create fixture source directory");
        for (path, contents) in [
            (
                "Cargo.toml",
                "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            ),
            (
                "src/lib.rs",
                "pub mod app;\npub mod facade;\npub mod glob_client;\npub mod origin;\npub mod unrelated;\nfn root_body() {}\n",
            ),
            (
                "src/facade.rs",
                "pub use crate::origin::Existing as Alias;\n",
            ),
            ("src/origin.rs", "pub struct Existing;\n"),
            (
                "src/app.rs",
                "use crate::facade::Alias;\nuse crate::origin::Added;\n",
            ),
            ("src/glob_client.rs", "use crate::origin::*;\n"),
            ("src/unrelated.rs", "use crate::origin::NeverAdded;\n"),
        ] {
            std::fs::write(root.join(path), contents).expect("write Rust fixture file");
        }
        let analyzer = RustAnalyzer::from_project(TestProject::new(root.clone(), Language::Rust));
        let files = brokk_bifrost_core::analyzer::CodeUnitIndex::analyzed_files(&analyzer);
        let sources = rust_graph_sources(&analyzer, &files);
        let initial_graph = rust_graph_facts(&analyzer, &files, None);
        let (initial_edges, initial_dependencies) = store_facts_from_request_graph(&initial_graph);
        let store = AnalyzerStore::open_ephemeral().expect("name-granular graph store");
        let workspace_id = WorkspaceId::for_session();
        let initial_identity = [111; 32];
        let resolver = [112; 32];
        publish_initial_with_dependencies(
            &store,
            &workspace_id,
            &initial_identity,
            &resolver,
            &sources,
            &initial_edges,
            &initial_dependencies,
        );

        let crate_root =
            brokk_bifrost_core::analyzer::model::ProjectFile::new(root.clone(), "src/lib.rs");
        std::fs::write(
            crate_root.abs_path(),
            "pub mod app;\npub mod facade;\npub mod glob_client;\npub mod origin;\npub mod unrelated;\nfn root_body() { let _unused = (); }\n",
        )
        .expect("make a body-only crate-root edit");
        let after_body = analyzer.update(&std::collections::BTreeSet::from([crate_root]));
        refresh_rust_graph_and_compare_to_fresh(
            &store,
            &workspace_id,
            &initial_identity,
            &[113; 32],
            &resolver,
            &after_body,
            (1, 0, 0),
            &[],
        );

        let origin =
            brokk_bifrost_core::analyzer::model::ProjectFile::new(root.clone(), "src/origin.rs");
        std::fs::write(
            origin.abs_path(),
            "pub struct Existing;\npub struct Added;\n",
        )
        .expect("add the named binding");
        let after_named = after_body.update(&std::collections::BTreeSet::from([origin.clone()]));
        refresh_rust_graph_and_compare_to_fresh(
            &store,
            &workspace_id,
            &[113; 32],
            &[114; 32],
            &resolver,
            &after_named,
            (3, 2, 2),
            &[("src/app.rs", 1), ("src/glob_client.rs", 0)],
        );

        std::fs::write(
            origin.abs_path(),
            "pub struct Existing;\npub struct Added;\npub struct GlobOnly;\n",
        )
        .expect("change the glob-visible binding set");
        let after_glob = after_named.update(&std::collections::BTreeSet::from([origin]));
        refresh_rust_graph_and_compare_to_fresh(
            &store,
            &workspace_id,
            &[114; 32],
            &[115; 32],
            &resolver,
            &after_glob,
            (2, 1, 1),
            &[("src/glob_client.rs", 0)],
        );
    }
}
