#[cfg(test)]
mod tests {

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::CATALOG_DECLARATION_IDENTITIES;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::CATALOG_FILES_ENUMERATED;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_core::analyzer::model::CodeUnit;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::WorkspaceUsageCatalog;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::is_graph_declaration;

    use brokk_bifrost_analysis::analyzer::common::is_java_module_descriptor_file;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::range_key;

    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::cpp_test_support::CATALOG_TEST_LOCK;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::cpp_test_support::catalog_node_fields;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::cpp_test_support::parity_inventory;

    use brokk_bifrost_test_macros::hardwon;

    use std::ffi::OsStr;

    #[test]
    fn batched_catalog_enumeration_matches_authoritative_inventory_without_file_projections() {
        let _guard = CATALOG_TEST_LOCK.lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let analyzer = persisted_multilanguage_analyzer(root);

        let mut authoritative = analyzer.all_declarations_with_primary_ranges();
        for file in analyzer.analyzed_files() {
            if is_java_module_descriptor_file(&file) {
                let file_scope = CodeUnit::file_scope(file.clone());
                let range = analyzer
                    .ranges(&file_scope)
                    .into_iter()
                    .min_by_key(range_key);
                authoritative.push((file_scope, range));
            }
        }
        let expected =
            WorkspaceUsageCatalog::from_declarations(authoritative, &CancellationToken::default())
                .expect("uncancelled authoritative catalog");

        CATALOG_FILES_ENUMERATED.store(0, std::sync::atomic::Ordering::Relaxed);
        let actual = WorkspaceUsageCatalog::build(&analyzer);
        let expected_nodes = catalog_node_fields(&expected);
        let actual_nodes = catalog_node_fields(&actual);
        assert_eq!(
            actual_nodes, expected_nodes,
            "batched enumeration must preserve exact catalog identity, ranges, duplicates, and order"
        );
        assert!(
            actual.nodes.iter().any(|node| {
                node.primary.identifier() == "run"
                    && node.primary.source().rel_path().file_name()
                        == Some(OsStr::new("Service.scala"))
            }),
            "per-file enumeration must retain the `run` method declared inside \
             Service.scala's anonymous class: {:?}",
            actual
                .nodes
                .iter()
                .map(|node| node.primary.clone())
                .collect::<Vec<_>>()
        );

        assert_eq!(
            CATALOG_FILES_ENUMERATED.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "unrooted catalog construction must not open any per-file summary projection"
        );

        let rooted_files = analyzer
            .analyzed_files()
            .into_iter()
            .take(2)
            .collect::<Vec<_>>();
        CATALOG_FILES_ENUMERATED.store(0, std::sync::atomic::Ordering::Relaxed);
        let rooted = WorkspaceUsageCatalog::build_for_files(&analyzer, &rooted_files);
        assert!(!rooted.nodes.is_empty());
        assert_eq!(
            CATALOG_FILES_ENUMERATED.load(std::sync::atomic::Ordering::Relaxed),
            rooted_files.len(),
            "rooted catalog construction must remain bounded to its supplied files"
        );

        assert!(
            actual.nodes.iter().any(|node| {
                node.primary.is_file_scope()
                    && node.primary.source().rel_path() == std::path::Path::new("module-info.java")
            }),
            "batched declaration enumeration must retain the graph-only Java module descriptor"
        );

        let cancelled = CancellationToken::default();
        cancelled.cancel();
        assert!(
            WorkspaceUsageCatalog::build_with_cancellation(&analyzer, &cancelled).is_none(),
            "a cancelled inventory must not publish a partial catalog"
        );

        // Five checks let the first delegate enter its store query and read its
        // mounted rows, then cancel before hydration can publish that batch.
        let cancelled_during_enumeration = CancellationToken::cancel_after_checks_for_test(5);
        assert!(
            WorkspaceUsageCatalog::build_with_cancellation(
                &analyzer,
                &cancelled_during_enumeration
            )
            .is_none(),
            "cancellation after reading a mounted batch must discard the whole inventory"
        );
    }

    /// The cost shape the parallel grouping exists to fix.
    ///
    /// The ordered-map grouping hashed each row's declaration identity about
    /// three times -- once for the group key, once for the node key, once for
    /// the node's identity list -- and `declaration_id` is a SHA-256 over
    /// every identity field. Grouping now makes one identity pass over the row
    /// set and carries the result through, so this pins one identity per graph
    /// declaration and no more.
    #[test]
    #[hardwon(
        "2d6e0d05e77f: The analyzer-backed catalog build checks one identity calculation per persisted graph declaration"
    )]
    fn catalog_grouping_makes_one_identity_pass_over_the_row_set() {
        let _guard = CATALOG_TEST_LOCK.lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let analyzer = persisted_multilanguage_analyzer(root.clone());
        let declarations = parity_inventory(&analyzer, &root);
        let graph_rows = declarations
            .iter()
            .filter(|(unit, _)| is_graph_declaration(unit))
            .count();
        assert!(graph_rows > 0, "the fixture must produce graph rows");

        CATALOG_DECLARATION_IDENTITIES.store(0, std::sync::atomic::Ordering::Relaxed);
        let catalog =
            WorkspaceUsageCatalog::from_declarations(declarations, &CancellationToken::default())
                .expect("uncancelled catalog");
        assert_eq!(
            CATALOG_DECLARATION_IDENTITIES.load(std::sync::atomic::Ordering::Relaxed),
            graph_rows,
            "grouping {} rows into {} nodes must compute exactly one declaration identity per row",
            graph_rows,
            catalog.nodes.len()
        );
    }

    /// Grouping is complete-or-nothing, like enumeration.
    ///
    /// The token trips after a fixed number of checks, so it cancels while
    /// grouping is partway through the row set.
    #[test]
    #[hardwon(
        "2d6e0d05e77f: Cancellation midway through grouping discards the partial catalog, and the identical rows succeed on retry"
    )]
    fn catalog_grouping_publishes_nothing_when_the_token_trips_partway() {
        let _guard = CATALOG_TEST_LOCK.lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let analyzer = persisted_multilanguage_analyzer(root.clone());
        let declarations = parity_inventory(&analyzer, &root);

        let token = CancellationToken::cancel_after_checks_for_test(3);
        assert!(
            WorkspaceUsageCatalog::from_declarations(declarations.clone(), &token).is_none(),
            "a token that trips partway through grouping must discard the whole catalog"
        );

        // The same rows still build a complete catalog once nothing cancels,
        // so the check above failed on cancellation and not on the fixture.
        assert!(
            WorkspaceUsageCatalog::from_declarations(declarations, &CancellationToken::default())
                .is_some()
        );
    }

    use crate::language_test_support::persisted_multilanguage_analyzer;
}
