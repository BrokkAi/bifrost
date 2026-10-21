#[cfg(test)]
mod rust_departing_wave2_root_tests {
    use crate::engine_tests::rust_analyzer_store_resolution_operation_tests::rust_departing_root_tests::*;

    use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use std::path::Path;

    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;

    use brokk_bifrost_analysis::analyzer::resolution::batch::ResolutionBatchMetrics;

    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole;

    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;

    use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

    use brokk_bifrost_rust::selected_context::RustSelectedManifestMount;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::selected_sql_trace::SelectedMountCallerTrace;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionContextMetrics;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionLocated;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOutcome;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedRustContextOutcome;

    use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedSemanticLocator;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::selected_sql_trace::begin_production_selected_sql_trace;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::selected_sql_trace::checkpoint_production_selected_sql_trace;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::selected_sql_trace::finish_production_selected_sql_trace;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::tests::rust_root_test_support::site_for_identifier as site_for_identifier;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;
    /// The three R2.3 work axes for one point request.
    ///
    /// Named here rather than read off `ResolutionBatchMetrics` at each call site,
    /// because the pin is about these three quantities and nothing else. The full
    /// metrics are still printed beside them.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct PointWorkAxes {
        /// Charged prefix and receiver evaluation steps for this request.
        prefix_evaluations: usize,
        /// Distinct candidate partial paths hydrated.
        hydrations: usize,
        /// Distinct candidate matches read from the source.
        candidate_reads: usize,
    }

    fn point_work_axes(measurement: &ProductionRustPointScaleMeasurement) -> PointWorkAxes {
        PointWorkAxes {
            prefix_evaluations: measurement.receiver_work.scope_nodes,
            hydrations: measurement.point_metrics.distinct_path_hydrations(),
            candidate_reads: measurement.point_metrics.distinct_candidate_matches(),
        }
    }

    /// R2.3 work axes for the same request against growing unrelated inventory.
    ///
    /// All three axes are constant now: candidate reads and hydrations remain
    /// four and charged scope work remains 330 at 256, 1,024 and 2,048 mounts.
    /// The pin asserted a linear bound while the interior's candidate index was
    /// keyed by the endpoint node alone, which charged a request two rejected
    /// root halves per selected mount. The index is keyed by the first fixed
    /// symbol admission checks as well, so nothing here scales with the
    /// inventory and the assertion is constancy. Row-backed preparation issues no
    /// SQL. Search statement/row counts are recorded separately and still include
    /// selected-inventory work; they are not asserted constant.
    ///
    /// The open column is the *cold* open: each size gets a fresh fixture, so this
    /// is the first open of that workspace and it is expected to scale. R2.1's
    /// retained selection is about the second and later opens of the same
    /// workspace, which this pin does not exercise and must not be read as
    /// contradicting.
    #[test]
    #[ignore = "explicit stack-graph R2.3 unrelated-inventory point work pin"]
    fn ignored_rust_point_work_axes_across_unrelated_mounts() {
        let mut rows = Vec::new();
        for source_mount_count in [256, 1_024, 2_048] {
            let measurement = measure_production_rust_point_scale(
                &RustRootResolutionOperationFixture::new_with_source_mount_count(
                    source_mount_count,
                ),
            );
            let axes = point_work_axes(&measurement);
            println!(
                "{{\"pin\":\"rust_point_work_axes\",\"source_mounts\":{source_mount_count},\"prefix_evaluations\":{},\"hydrations\":{},\"candidate_reads\":{},\"cold_open_statements\":{},\"cold_open_decoded_rows\":{},\"context_statements\":{},\"context_decoded_rows\":{},\"resolve_statements\":{},\"resolve_decoded_rows\":{},\"search_statements\":{},\"search_decoded_rows\":{},\"reference_seeds\":{},\"composition_attempts\":{},\"successful_stitches\":{},\"worklist_rounds\":{}}}",
                axes.prefix_evaluations,
                axes.hydrations,
                axes.candidate_reads,
                measurement.open.statement_count(),
                measurement.open.decoded_rows,
                measurement.context.statement_count(),
                measurement.context.decoded_rows,
                measurement.resolve.statement_count(),
                measurement.resolve.decoded_rows,
                measurement.search.statement_count(),
                measurement.search.decoded_rows,
                measurement.point_metrics.reference_seeds(),
                measurement.point_metrics.composition_attempts(),
                measurement.point_metrics.successful_stitches(),
                measurement.point_metrics.worklist_rounds(),
            );
            rows.push((source_mount_count, axes));
        }
        for window in rows.windows(2) {
            let (smaller, small_axes) = window[0];
            let (larger, large_axes) = window[1];
            assert_eq!(
                small_axes.hydrations, large_axes.hydrations,
                "hydrations moved between {smaller} and {larger} unrelated mounts"
            );
            assert_eq!(
                small_axes.candidate_reads, large_axes.candidate_reads,
                "candidate reads moved between {smaller} and {larger} unrelated mounts"
            );
            // The request's charged work does not depend on how much unrelated
            // inventory the workspace holds. A linear bound used to be the most
            // this could claim; nothing on the path scales with the inventory
            // now, so equality is the property and a linear bound would hide a
            // regression back into per-mount work.
            assert_eq!(
                small_axes.prefix_evaluations, large_axes.prefix_evaluations,
                "charged prefix evaluations moved between {smaller} and {larger} unrelated mounts"
            );
        }
    }

    #[doc(hidden)]
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::heap_pin_bytes;

    fn heap_pin_fixture(files: usize, profiles: usize) -> RustRootResolutionOperationFixture {
        assert!(profiles >= 4 && profiles.is_multiple_of(2));
        assert_eq!(
            AnalyzerConfig::default().parallelism(),
            1,
            "heap pins require synchronous context construction (BIFROST_PARALLELISM=1)"
        );
        let mut fixture = RustRootResolutionOperationFixture::new_with_source_mount_count(files);
        let mut manifest = String::from(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\nautobins = false\n[dependencies]\nengine = { path = \"../engine\" }\n",
        );
        for index in 0..profiles / 2 - 2 {
            manifest.push_str(&format!(
                "[[bin]]\nname = \"profile_{index}\"\npath = \"src/scale_{index:04}.rs\"\n"
            ));
        }
        fixture.selected_manifests[0] =
            RustSelectedManifestMount::from_source("app/Cargo.toml", &manifest)
                .expect("heap pin manifest");
        let snapshot = sync_rust_operation_inputs(
            &fixture.store,
            &fixture.workspace_id,
            fixture.generation,
            fixture._project_root.path(),
            &fixture.source_rows(),
            &fixture.selected_manifests,
        )
        .expect("publish heap pin profiles");
        fixture.snapshots.get_mut("rust").unwrap().revision = snapshot.revision;
        fixture
    }

    /// A lexical source retains nothing that scales with the selection.
    ///
    /// Source construction formerly retained maps sized by the mount count. The
    /// inventory now owns ordinal/path authority and both row readers use
    /// SelectedResolutionAuthority. Subtract the typed reader's construction
    /// cost to isolate the lexical reader's additional retained bytes; this
    /// amount must not grow with the selected mount count.
    #[test]
    fn rust_lexical_source_retained_bytes_are_independent_of_the_selection() {
        let rows = [8_usize, 64].map(|files| {
            let fixture = RustRootResolutionOperationFixture::new_with_source_mount_count(files);
            let cancellation = CancellationToken::default();
            let operation = fixture.open_ready(&cancellation);
            let mounts = operation.mount_table().mount_count();

            let before_typed = heap_pin_bytes();
            let typed = operation.ready.typed_source();
            let typed_retained = heap_pin_bytes() - before_typed;
            drop(typed);

            let before_lexical = heap_pin_bytes();
            let lexical = operation.ready.lexical_source();
            let lexical_retained = heap_pin_bytes() - before_lexical;
            drop(lexical);

            (files, mounts, lexical_retained - typed_retained)
        });
        eprintln!(
            "lexical source retained beyond its typed source (files, selected mounts, bytes): {rows:?}"
        );
        assert!(
            rows[1].1 > rows[0].1,
            "the larger workspace must hold more selected mounts for this pin to mean anything: {rows:?}"
        );
        assert_eq!(
            rows[0].2, rows[1].2,
            "lexical source construction must retain the same bytes whatever the selection holds: {rows:?}"
        );
    }

    /// A query's rebaser learns nothing from a persisted mount.
    ///
    /// It used to learn everything. `register_identity_catalog` walked a blob's
    /// whole identity catalog into the rebaser the first time any reader opened
    /// that mount, and a frontier opens every blob that carries a candidate site,
    /// so one tract reverse frontier taught it 1,974,097 semantics, 394,894
    /// nodes, 432,242 paths and 156,273 stack variables and held 1.24 GiB of live
    /// heap (RM-2). A fragment-local runtime ID now names its own mount in bytes
    /// 0..8 and a persisted node, path or stack variable carries its storage-local
    /// key in its last eight bytes, so a reader that wants a coordinate decodes
    /// one, and a fragment-local semantic's key is the position it occupies in its
    /// mount's persisted identity catalog, read by its requested key.
    ///
    /// The measurement is the rebaser's own fragment-local entry count at the end
    /// of a whole-workspace point request, and the oracle is the one every other
    /// pin here uses: run the same request over selections of different sizes and
    /// require the number not to move. Files and crates vary independently, so a
    /// per-mount or per-crate residue shows up as growth.
    #[test]
    fn rust_whole_workspace_point_rebaser_identities_are_independent_of_the_selection() {
        let rows = [(32, 8), (64, 8), (64, 16)].map(|(files, profiles)| {
        let fixture = heap_pin_fixture(files, profiles);
        let reference = site_for_identifier(
            &fixture.consumer_facts,
            "alias",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Value,
        );
        let range = fixture
            .consumer_facts
            .sites
            .iter()
            .find(|site| site.id == reference)
            .unwrap();
        let locator = SelectedSemanticLocator::for_reference_range(
            "rust",
            RUST_ROOT_CONSUMER_PATH,
            range.start_byte,
            range.end_byte,
        );
        let cancellation = CancellationToken::default();
        let mut operation = fixture.open_ready(&cancellation);
        let mounts = operation.mount_table().mount_count();
        let _ = brokk_bifrost_analysis::analyzer::store::resolution_operation::take_rebaser_identities_at_handback_for_test();
        operation
            .resolve_rust_reference_for_caller_bounded(
                Path::new(RUST_ROOT_CONSUMER_PATH),
                &locator,
                ReceiverAnalysisBudget::default(),
                &cancellation,
                &mut SelectedResolutionContextMetrics,
                &mut ResolutionBatchMetrics::default(),
            )
            .expect("the whole-workspace point request answers");
        let identities = brokk_bifrost_analysis::analyzer::store::resolution_operation::take_rebaser_identities_at_handback_for_test();
        (files, profiles / 2, mounts, identities)
    });
        eprintln!(
            "whole-workspace point rebaser fragment-local identities \
         (files, crates, selected mounts, [semantics, nodes, paths, variables]): {rows:?}"
        );
        assert!(
            rows[1].2 > rows[0].2,
            "the larger workspace must hold more selected mounts for this pin to mean anything: {rows:?}"
        );
        assert_eq!(
            rows[0].3, rows[1].3,
            "a point request must retain the same rebaser identities whatever the file count: {rows:?}"
        );
        assert_eq!(
            rows[1].3, rows[2].3,
            "a point request must retain the same rebaser identities whatever the crate count: {rows:?}"
        );
    }

    #[test]
    fn rust_whole_workspace_point_retained_bytes_are_bounded_by_shared_name_cache() {
        fn statement_storage_release(
            reader: brokk_bifrost_analysis::analyzer::store::ReaderGuard<'_>,
        ) -> (usize, i64) {
            // Called only after original retained bytes have been captured. This
            // diagnostic measures Rust destructor releases, not SQLite C memory,
            // and does not use post-disposal heap as the acceptance measurement.
            let mut statements = 0;
            unsafe {
                let mut statement =
                    rusqlite::ffi::sqlite3_next_stmt(reader.handle(), std::ptr::null_mut());
                while !statement.is_null() {
                    statements += 1;
                    statement = rusqlite::ffi::sqlite3_next_stmt(reader.handle(), statement);
                }
            }
            // cache_db.rs configures this existing production cache with 256
            // entries. This is a pin of that cap, not a new retention allowance.
            assert!(
                statements <= 256,
                "existing prepared statement entry cap: {statements}"
            );
            let before = heap_pin_bytes();
            reader.flush_prepared_statement_cache();
            let released = before - heap_pin_bytes();
            (statements, released)
        }

        let rows = [(32, 8), (64, 8), (64, 16)].map(|(files, profiles)| {
        let control = heap_pin_fixture(files, profiles);
        let control_statements =
            statement_storage_release(control.store.active_read_conn().unwrap());
        drop(control);
        let fixture = heap_pin_fixture(files, profiles);
        let reference = site_for_identifier(
            &fixture.consumer_facts,
            "alias",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Value,
        );
        let range = fixture
            .consumer_facts
            .sites
            .iter()
            .find(|site| site.id == reference)
            .unwrap();
        let locator = SelectedSemanticLocator::for_reference_range(
            "rust",
            RUST_ROOT_CONSUMER_PATH,
            range.start_byte,
            range.end_byte,
        );
        let cancellation = CancellationToken::default();
        let shared_names = fixture.store.resolution_shared_name_cache().clone();
        let cache_before = shared_names.allocated_bytes();
        let static_sql_before = brokk_bifrost_analysis::analyzer::store::resolution_selection::selected_static_sql_capacities();
        let before = heap_pin_bytes();
        let operation = fixture.open_ready(&cancellation);
        let request_reader_handle =
            unsafe { operation.ready.inventory.connection().handle() as usize };
        let SelectedRustContextOutcome::Ready(context) = operation
            .rust_context_for_all_crates(&cancellation)
            .unwrap()
        else {
            panic!("fixture has a complete selected Rust workspace");
        };
        // The context is the whole workspace's, but the request still answers
        // one file's reference, so the scope it binds inside is that file's
        // crates, exactly as a production point request's is.
        let crate_keys = operation
            .rust_crate_keys_for_file(Path::new(RUST_ROOT_CONSUMER_PATH), &cancellation)
            .unwrap();
        let outcome = operation
            .with_rust_forward_queries_in_session(
                context,
                &crate_keys,
                &[Path::new(RUST_ROOT_CONSUMER_PATH)],
                &cancellation,
                &mut SelectedResolutionContextMetrics,
                &ResolutionSession::unbounded(),
                |queries| {
                    let SelectedResolutionOperationOutcome::Native(
                        SelectedResolutionLocated::Found(answer),
                    ) = queries
                        .resolve_reference(&locator, &mut ResolutionBatchMetrics::default())?
                    else {
                        panic!("whole-workspace point must produce a native answer");
                    };
                    assert_eq!(answer.definitions.len(), 1);
                    Ok(())
                },
            )
            .unwrap();
        assert!(matches!(
            outcome,
            SelectedResolutionOperationOutcome::Native(())
        ));
        // Capture the original post-request measurement before diagnostic
        // disposal. Attribute only measured growth of bounded caches and
        // naturally initialized fixed SQL, never a capacity allowance or
        // post-flush heap value.
        let retained = heap_pin_bytes() - before;
        let cache_growth = shared_names.allocated_bytes() - cache_before;
        let raw_outside_shared = retained - cache_growth;
        let diagnostic_reader = fixture.store.active_read_conn().unwrap();
        assert_eq!(
            unsafe { diagnostic_reader.handle() as usize },
            request_reader_handle,
            "statement storage attribution must inspect the completed request's SQLite reader"
        );
        let request_statements = statement_storage_release(diagnostic_reader);
        let static_sql_after = brokk_bifrost_analysis::analyzer::store::resolution_selection::selected_static_sql_capacities();
        eprintln!("static SQL allocation ownership files={files} profiles={profiles}: before={static_sql_before:?}, after={static_sql_after:?}");
        let statement_growth = request_statements.1 - control_statements.1;
        let static_sql_growth: i64 = static_sql_before
            .into_iter()
            .zip(static_sql_after)
            .map(|((before_name, before), (after_name, after))| {
                assert_eq!(before_name, after_name);
                (after as i64 - before as i64).max(0)
            })
            .sum();
        let outside_owned_storage =
            (raw_outside_shared - statement_growth.max(0) - static_sql_growth).max(0);
        (
            files,
            profiles / 2,
            retained,
            cache_growth,
            control_statements,
            request_statements,
            statement_growth,
            raw_outside_shared,
            static_sql_growth,
            outside_owned_storage,
        )
    });
        eprintln!(
            "whole-workspace point retained (files, crates, raw bytes, shared growth, control statement(count,bytes), request statement(count,bytes), signed statement growth, raw outside shared, natural fixed SQL growth, adjusted outside bounded caches and fixed SQL; statement cap=64): {rows:?}"
        );
        let minimum_outside_storage = rows.iter().map(|row| row.9).min().unwrap();
        let maximum_outside_storage = rows.iter().map(|row| row.9).max().unwrap();
        assert!(
            maximum_outside_storage <= 16 * 1024
                && maximum_outside_storage - minimum_outside_storage <= 16 * 1024,
            "query-retained bytes beyond measured growth of the existing shared-name cache, 64-entry statement cache, and naturally initialized fixed SQL strings must have only the existing 16 KiB allowance independent of workspace files and crates: {rows:?}"
        );
    }

    /// One point request's SQL work is independent of unrelated workspace files.
    #[test]
    fn rust_point_request_sql_work_does_not_grow_with_the_workspace() {
        let rows = [32usize, 64].map(|files| {
            let fixture = RustRootResolutionOperationFixture::new_with_source_mount_count(files);
            let reference = site_for_identifier(
                &fixture.consumer_facts,
                "alias",
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Value,
            );
            let range = fixture
                .consumer_facts
                .sites
                .iter()
                .find(|site| site.id == reference)
                .expect("the consumer reference site");
            let locator = SelectedSemanticLocator::for_reference_range(
                "rust",
                RUST_ROOT_CONSUMER_PATH,
                range.start_byte,
                range.end_byte,
            );
            let cancellation = CancellationToken::default();
            begin_production_selected_sql_trace(&fixture.store);
            let mut operation = fixture.open_ready(&cancellation);
            let _open = checkpoint_production_selected_sql_trace();
            let answer = operation
                .resolve_rust_reference_for_caller_bounded(
                    Path::new(RUST_ROOT_CONSUMER_PATH),
                    &locator,
                    ReceiverAnalysisBudget::default(),
                    &cancellation,
                    &mut SelectedResolutionContextMetrics,
                    &mut ResolutionBatchMetrics::default(),
                )
                .expect("the point request answers");
            assert!(
                matches!(answer, BoundedResolution::Complete { .. }),
                "the point fixture must answer inside its budget at {files} files"
            );
            drop(operation);
            let work = finish_production_selected_sql_trace(&fixture.store);
            (files, work.statement_count(), work.decoded_rows)
        });
        eprintln!("request SQL work (files, statements, decoded rows): {rows:?}");
        assert_eq!(
            (rows[0].1, rows[0].2),
            (rows[1].1, rows[1].2),
            "unrelated files must not add request SQL statements or decoded rows: {rows:?}"
        );
    }

    /// A member call whose receiver type is unknown opens the blobs that declare
    /// that member, not the blobs that mention its name.
    ///
    /// `visit_deferred_member_owner_pages_for_lookup_names` used to take its mounts
    /// from a name-mention relation that said which blobs mention an identity
    /// anywhere. For an ordinary member name that is most of the workspace, and
    /// lane CP measured the read opening those interiors as 88 percent of a
    /// reverse confirmation's productions. It now takes them from the
    /// `DeferredMemberOwnerLookup` rows of `resolution_typed_fact_lookups`, one row
    /// per blob per lookup a deferred member owner is actually declared under.
    ///
    /// The fixture separates the two sets on purpose: every scale blob calls
    /// `shared_member` on a receiver it cannot resolve, so every scale blob
    /// mentions the name, and exactly one declares a member under it. Under the
    /// membership relation the productions grow with the file count; under the
    /// declaring relation they do not, which is what this pins.
    #[test]
    fn deferred_member_lookup_sql_work_does_not_grow_with_the_workspace() {
        let rows = [8usize, 24].map(|files| {
            let fixture =
                RustRootResolutionOperationFixture::new_with_deferred_member_lookup_scale(files);
            let reference = site_for_identifier(
                &fixture.consumer_facts,
                "shared_member",
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Callable,
            );
            let range = fixture
                .consumer_facts
                .sites
                .iter()
                .find(|site| site.id == reference)
                .expect("the consumer member reference site");
            let locator = SelectedSemanticLocator::for_reference_range(
                "rust",
                RUST_ROOT_CONSUMER_PATH,
                range.start_byte,
                range.end_byte,
            );
            let cancellation = CancellationToken::default();
            begin_production_selected_sql_trace(&fixture.store);
            let mut operation = fixture.open_ready(&cancellation);
            let _open = checkpoint_production_selected_sql_trace();
            let mount_callers = SelectedMountCallerTrace::begin();
            operation
                .resolve_rust_reference_for_caller_bounded(
                    Path::new(RUST_ROOT_CONSUMER_PATH),
                    &locator,
                    ReceiverAnalysisBudget::default(),
                    &cancellation,
                    &mut SelectedResolutionContextMetrics,
                    &mut ResolutionBatchMetrics::default(),
                )
                .expect("the member point request answers");
            drop(operation);
            let work = finish_production_selected_sql_trace(&fixture.store);
            drop(mount_callers);
            eprintln!(
                "deferred member SQL families at {files} files: {:?}",
                work.rows_by_shape()
            );
            (files, work.statement_count(), work.decoded_rows)
        });
        eprintln!("request SQL work (files, statements, decoded rows): {rows:?}");
        assert_eq!(
            (rows[0].1, rows[0].2),
            (rows[1].1, rows[1].2),
            "unrelated files must not add request SQL statements or decoded rows: {rows:?}"
        );
    }

    /// A member call on a primitive receiver opens only the blobs that can answer.
    ///
    /// The forward member evaluation reaches the intrinsic-seed read with every
    /// owner that has no member scope, because `usize` has none either and an
    /// intrinsic owner is a boundary the route may decide rather than a producer
    /// shortfall. It also asks that owner for its visibility, its member scope,
    /// its construction requirements and its property gaps. For a primitive
    /// receiver all five requests name the same workspace-shared identity, so all
    /// five take `semantic_coordinates`' shared branch, and this is what each of
    /// them now resolves to:
    ///
    /// - `IntrinsicSeedTypeIdentity` names the blobs that seed `usize`, which in
    ///   this fixture is every scale blob, and it grows with the workspace. That
    ///   is correct and no header family can bound it: an intrinsic identity
    ///   enters a blob's catalog only where the seed loop puts it, so the blobs
    ///   that mention one are the blobs that seed one. Lane G1 measured that
    ///   equality on the Bifrost store; this measures it from a point request.
    /// - the four definition-keyed relations name **no blob at all**, at either
    ///   size. An intrinsic identity is no blob's definition, so no blob holds a
    ///   visibility, member scope, construction requirement or property gap row
    ///   under it. Through the name-mention relation each of these four opened
    ///   the same set the intrinsic read opens, because for an intrinsic identity
    ///   mention and seed are the same set. The point request's shared reads
    ///   therefore go from five mount sets of that size to one.
    ///
    /// This is the call lane G1 looked for and did not find. G1 wrote a standalone
    /// intrinsic-seed family, measured it as answering nothing, and removed it;
    /// what the generic family buys here is not on the intrinsic read at all, it
    /// is on the four reads asked the same question that cannot possibly answer.
    #[test]
    fn an_intrinsic_owner_opens_only_the_blobs_that_seed_it() {
        use brokk_bifrost_analysis::analyzer::store::resolution::TypedFactRelation;

        use brokk_bifrost_analysis::analyzer::store::resolution_typed::shared_request_probe;

        const CANNOT_ANSWER: [TypedFactRelation; 4] = [
            TypedFactRelation::DeclarationVisibilityDefinition,
            TypedFactRelation::MemberScopeDefinition,
            TypedFactRelation::ConstructionRequirementDefinition,
            TypedFactRelation::DefinitionPropertyGapDefinition,
        ];

        let rows = [8usize, 24].map(|files| {
            let fixture = RustRootResolutionOperationFixture::new_with_intrinsic_owner_scale(files);
            let reference = site_for_identifier(
                &fixture.consumer_facts,
                "shared_member",
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Callable,
            );
            let range = fixture
                .consumer_facts
                .sites
                .iter()
                .find(|site| site.id == reference)
                .expect("the consumer member reference site");
            let locator = SelectedSemanticLocator::for_reference_range(
                "rust",
                RUST_ROOT_CONSUMER_PATH,
                range.start_byte,
                range.end_byte,
            );
            let cancellation = CancellationToken::default();
            let mut operation = fixture.open_ready(&cancellation);
            shared_request_probe::reset();
            operation
                .resolve_rust_reference_for_caller_bounded(
                    Path::new(RUST_ROOT_CONSUMER_PATH),
                    &locator,
                    ReceiverAnalysisBudget::default(),
                    &cancellation,
                    &mut SelectedResolutionContextMetrics,
                    &mut ResolutionBatchMetrics::default(),
                )
                .expect("the member point request answers");
            let entered = shared_request_probe::observed_all();
            let seed = shared_request_probe::observed(TypedFactRelation::IntrinsicSeedTypeIdentity);
            let cannot = CANNOT_ANSWER.map(shared_request_probe::observed);
            (files, entered, seed, cannot)
        });
        for (files, entered, seed, cannot) in &rows {
            eprintln!(
                "intrinsic owner, {files} files: shared reads {entered:?}; \
             intrinsic seed {seed:?}; cannot answer {cannot:?}"
            );
            assert!(
                seed.0 > 0,
                "the intrinsic-seed read must be entered with a shared owner \
             identity at {files} files, or this pin measures nothing"
            );
            for (relation, observed) in CANNOT_ANSWER.into_iter().zip(*cannot) {
                assert!(
                    observed.0 > 0,
                    "{} must be asked about the same owner at {files} files",
                    relation.label()
                );
                assert_eq!(
                    observed.1,
                    0,
                    "{} must name no blob for an intrinsic owner at {files} files",
                    relation.label()
                );
            }
        }
        assert!(
            rows[1].2.1 > rows[0].2.1,
            "the blobs that seed the owner grow with the workspace, and the \
         intrinsic read must open them: {:?} then {:?}",
            rows[0].2,
            rows[1].2
        );
    }
}
