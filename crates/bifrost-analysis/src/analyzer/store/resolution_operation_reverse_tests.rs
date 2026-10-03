use super::*;

/// The main hydration statement must seek a fixed requested declaration,
/// even when the workspace or that declaration's own blob grows. VM steps
/// measure SQLite work; the mount-visit regression below measures Rust work.
#[test]
fn selected_definition_hydration_vm_work_is_bounded_by_requested_keys() {
    use crate::analyzer::CodeUnitType;
    use crate::analyzer::store::selected_definition::{
        SELECTED_DEFINITION_UNITS_SQL, SelectedDefinitionUnitReadOutcome,
        take_selected_definition_unit_sql_work,
    };

    let mut old_workspace_growth = Vec::new();
    for sampled_statistics in [false, true] {
        let mut measurements = Vec::new();
        for (mounts, extra_units) in [(16, 0), (48, 0), (3, 16), (3, 512)] {
            let suffix = (0..extra_units)
                .map(|index| format!("pub fn unrelated_unit_{index:04}() {{}}\n"))
                .collect::<String>();
            let fixture = if extra_units == 0 {
                // Three base mounts plus the unrelated crate's root and files.
                // The requested consumer source is identical at both sizes.
                RustRootResolutionOperationFixture::new_with_unrelated_crate_source_count(
                    mounts - 4,
                )
            } else {
                RustRootResolutionOperationFixture::new_with_scale_sources(
                    3,
                    0,
                    &suffix,
                    default_scale_source,
                )
            };
            let caller_oid = fixture
                .selected_sources
                .iter()
                .find(|source| source.relative_path == Path::new(RUST_ROOT_CONSUMER_PATH))
                .expect("fixture source authority for caller")
                .content_oid;
            fixture
                .store
                .clear_planner_statistics()
                .expect("clear fixture statistics");
            if sampled_statistics {
                fixture
                    .store
                    .refresh_planner_statistics()
                    .expect("production sampled statistics and reader recycling");
            }
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let inventory = &operation.ready.inventory;
            let conn = inventory.connection();
            let selected_blobs: usize = conn
                .query_row(
                    "SELECT COUNT(DISTINCT blob_id) FROM temp.selected_resolution_mounts",
                    [],
                    |row| row.get(0),
                )
                .expect("observed selected blobs");
            assert_eq!(selected_blobs, mounts);
            let caller_units: usize = conn.query_row(
                "SELECT COUNT(*) FROM code_units WHERE blob_id=(SELECT blob_id FROM temp.selected_resolution_mounts WHERE persisted_relative_path=?1)",
                [RUST_ROOT_CONSUMER_PATH], |row| row.get(0),
            ).expect("observed requested-blob units");
            let coordinates = conn.prepare(
                "SELECT mount.mount_ordinal, crosswalk.definition_semantic_key, units.short_name
                 FROM temp.selected_resolution_mounts AS mount
                 JOIN resolution_definition_unit_crosswalks AS crosswalk ON crosswalk.blob_id=mount.blob_id
                 JOIN code_units AS units ON units.blob_id=crosswalk.blob_id AND units.unit_key=crosswalk.unit_key
                 WHERE (mount.persisted_relative_path=?1 AND units.short_name='caller')
                    OR (mount.persisted_relative_path=?2 AND units.short_name='target')
                 ORDER BY mount.mount_ordinal, crosswalk.definition_semantic_key"
            ).expect("known parsed declaration coordinates").query_map(
                rusqlite::params![RUST_ROOT_CONSUMER_PATH, RUST_ROOT_PROVIDER_PATH],
                |row| Ok((SelectedResolutionMountOrdinal::new(row.get(0)?),
                    ResolutionLocalKey::new(row.get(1)?), row.get::<_, String>(2)?)),
            ).expect("query known declarations").collect::<rusqlite::Result<Vec<_>>>()
                .expect("known declarations");
            assert_eq!(coordinates.len(), 2);
            let caller = coordinates.iter().find(|row| row.2 == "caller").unwrap();
            let request = [(caller.0, caller.1)];

            take_selected_definition_unit_sql_work();
            let SelectedDefinitionUnitReadOutcome::Ready(empty) = inventory
                .selected_definition_units(&[], &cancellation)
                .expect("empty projection")
            else {
                panic!("empty projection is ready")
            };
            assert!(empty.is_empty());
            assert_eq!(take_selected_definition_unit_sql_work(), (0, 0));
            let SelectedDefinitionUnitReadOutcome::Ready(rows) = inventory
                .selected_definition_units(&request, &cancellation)
                .expect("caller projection")
            else {
                panic!("caller projection is ready")
            };
            let work = take_selected_definition_unit_sql_work();
            assert_eq!(work.0, 1);
            assert_eq!(rows.len(), 1);
            assert_eq!((rows[0].0, rows[0].1), request[0]);
            assert_eq!(rows[0].2.blob_oid, caller_oid);
            assert_eq!(rows[0].2.lang, "rust");
            assert_eq!(rows[0].2.short_name, "caller");
            assert_eq!(rows[0].2.kind, CodeUnitType::Function);
            assert!(
                rows[0].2.fq.is_some(),
                "parsed declaration identity is hydrated"
            );

            // Run the pre-correction query against the very same populated
            // production request table. This is the causal control, not the
            // oracle for the requested declaration's expected answer.
            let mut old_sql = SELECTED_DEFINITION_UNITS_SQL.to_string();
            for table in [
                "temp.selected_resolution_mounts",
                "main.resolution_fragment_interiors",
                "main.resolution_definition_unit_crosswalks",
                "main.code_units",
                "main.blobs",
                "main.blob_meta",
            ] {
                let keyed_join = format!("CROSS JOIN {table} AS ");
                assert_eq!(old_sql.matches(&keyed_join).count(), 1);
                old_sql = old_sql.replacen(&keyed_join, &format!("JOIN {table} AS "), 1);
            }
            let mut old = conn.prepare(&old_sql).expect("old hydration statement");
            let old_names = old
                .query_map([], |row| row.get::<_, String>(4))
                .expect("old hydration query")
                .collect::<rusqlite::Result<Vec<_>>>()
                .expect("old hydration rows");
            assert_eq!(old_names, ["caller"]);
            let old_steps = old.get_status(rusqlite::StatementStatus::VmStep);
            drop(old);

            let batch = coordinates
                .iter()
                .map(|row| (row.0, row.1))
                .collect::<Vec<_>>();
            let SelectedDefinitionUnitReadOutcome::Ready(rows) = inventory
                .selected_definition_units(&batch, &cancellation)
                .expect("batched projection")
            else {
                panic!("batch projection is ready")
            };
            assert_eq!(
                rows.iter()
                    .map(|row| row.2.short_name.as_str())
                    .collect::<Vec<_>>(),
                coordinates
                    .iter()
                    .map(|row| row.2.as_str())
                    .collect::<Vec<_>>()
            );
            assert_eq!(take_selected_definition_unit_sql_work().0, 1);
            assert!(
                inventory
                    .selected_definition_units(&[request[0], request[0]], &cancellation)
                    .is_err()
            );
            assert_eq!(take_selected_definition_unit_sql_work(), (0, 0));
            let cancelled = CancellationToken::new();
            cancelled.cancel();
            assert!(matches!(
                inventory
                    .selected_definition_units(&request, &cancelled)
                    .unwrap(),
                SelectedDefinitionUnitReadOutcome::Cancelled
            ));
            assert_eq!(take_selected_definition_unit_sql_work(), (0, 0));
            for (_, _, row) in rows.iter() {
                let path = match row.short_name.as_str() {
                    "caller" => RUST_ROOT_CONSUMER_PATH,
                    "target" => RUST_ROOT_PROVIDER_PATH,
                    name => panic!("unexpected parsed declaration {name}"),
                };
                let source = fixture
                    .selected_sources
                    .iter()
                    .find(|source| source.relative_path == Path::new(path))
                    .unwrap();
                assert_eq!(row.blob_oid, source.content_oid);
                assert_eq!(row.lang, "rust");
            }
            measurements.push((
                mounts,
                extra_units,
                caller.1,
                work.1,
                old_steps,
                selected_blobs,
                caller_units,
            ));
        }
        eprintln!(
            "main hydration VM steps sampled_statistics={sampled_statistics}: {measurements:?}"
        );
        assert_eq!((measurements[0].5, measurements[1].5), (16, 48));
        assert_eq!(
            measurements[0].6, measurements[1].6,
            "workspace axis preserves requested-blob units"
        );
        assert_eq!((measurements[2].5, measurements[3].5), (3, 3));
        assert_eq!(
            measurements[3].6 - measurements[2].6,
            512 - 16,
            "same-blob axis adds only the specified unrelated declarations"
        );
        assert_eq!(
            measurements[0].2, measurements[1].2,
            "workspace growth keeps the requested key"
        );
        assert_eq!(
            measurements[2].2, measurements[3].2,
            "same-blob growth keeps the requested key"
        );
        assert_eq!(
            measurements[0].3, measurements[1].3,
            "unrelated mounts add no main-query VM work"
        );
        assert_eq!(
            measurements[2].3, measurements[3].3,
            "unrelated units add no main-query VM work"
        );
        old_workspace_growth.push((sampled_statistics, measurements[0].4, measurements[1].4));
    }
    assert!(
        old_workspace_growth
            .iter()
            .any(|(_, small, large)| large > small),
        "the old query must expose workspace-proportional VM work: {old_workspace_growth:?}"
    );
}

/// A reverse answer's projection and a graph build's definition projection ask
/// the mount table a fixed number of questions, whatever the selection holds.
///
/// Both used to `find` linearly through the operation's mount table: once per
/// reference in the reverse answer (`selected_reference_source_sites`) and once
/// per projected definition (`project_rust_source_definitions`, which is what
/// `stage_rust_reference_edge_batches_in_files` calls for every reference
/// batch). Each lookup was therefore O(selection), and the per-request cost was
/// the product of the two.
///
/// The oracle is the same one `rust_point_request_interior_productions_do_not_
/// grow_with_the_workspace` uses: run the identical request at two workspace
/// sizes and require the measurement to be equal. The measurement here counts
/// mount-table entries the readers examined, so a walk shows up as growth with
/// the selection and an index does not. The per-item assertions state the shape
/// the audit asked for; the totals are equal because the fixture asks the same
/// question of both workspaces.
#[test]
fn a_reverse_answer_and_a_definition_projection_do_not_walk_the_mount_table() {
    let rows = [16usize, 48].map(|files| {
        let fixture = RustRootResolutionOperationFixture::new_with_source_mount_count(files);
        let cancellation = CancellationToken::new();
        let operation = fixture.open_ready(&cancellation);
        assert_eq!(
            operation.mount_table().mount_count(),
            files,
            "the fixture selects one mount per source file"
        );
        let SelectedRustBindingDefinitionUnitsOutcome::Ready(units) = operation
            .rust_binding_definition_units(&cancellation)
            .expect("selected declaration inventory")
        else {
            panic!("fixture inventory must be ready");
        };
        let target = units
            .values()
            .find(|unit| {
                unit.source().rel_path() == std::path::Path::new(RUST_ROOT_PROVIDER_PATH)
                    && unit.short_name() == "target"
            })
            .cloned()
            .expect("provider target declaration");
        let provider = operation
            .rust_definition_mount_for_target(&target)
            .expect("the provider target names a selected mount")
            .expect("the provider target is selected");
        let SelectedRustDefinitionSemanticMapOutcome::Ready(semantics) = operation
            .selected_rust_definition_semantics_for_mount(provider, &cancellation)
            .expect("provider definition semantics")
        else {
            panic!("provider definition semantics must be ready");
        };
        let mut definitions = semantics.into_values().collect::<Vec<_>>();
        definitions.sort_unstable();

        take_selected_mount_table_visits_for_test();
        let SelectedRustDefinitionProjection::Complete(projected) = operation
            .project_rust_definitions(&definitions, &cancellation)
            .expect("the provider definitions project")
        else {
            panic!("the provider definitions must project completely");
        };
        let projection_visits = take_selected_mount_table_visits_for_test();

        let SelectedRustContextOutcome::Ready(context) = operation
            .rust_context_for_all_crates(&cancellation)
            .expect("selected crate-key context")
        else {
            panic!("fixture context must be ready");
        };
        take_selected_mount_table_visits_for_test();
        let outcome = operation
            .references_to_rust_definition(
                context,
                64,
                &target,
                &cancellation,
                &mut SelectedResolutionContextMetrics,
                &mut FactReverseResolutionMetrics::default(),
            )
            .expect("the reverse answer is an operational result");
        let reverse_visits = take_selected_mount_table_visits_for_test();
        let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(answer)) =
            outcome
        else {
            panic!("the provider target must have a native reverse answer");
        };
        (
            files,
            projected.len(),
            projection_visits,
            answer.source_sites.len(),
            reverse_visits,
        )
    });
    eprintln!(
        "mount-table visits (files, definitions, projection visits, references, reverse visits): {rows:?}"
    );
    assert!(
        rows[0].1 > 0 && rows[0].3 > 0,
        "the measurement is vacuous unless both projections produce items: {rows:?}"
    );
    assert_eq!(
        (rows[0].1, rows[0].3),
        (rows[1].1, rows[1].3),
        "both workspace sizes must be asked the same question: {rows:?}"
    );
    assert_eq!(
        rows[0].2, rows[1].2,
        "a definition projection must examine the same mount-table entries at both workspace sizes: {rows:?}"
    );
    assert_eq!(
        rows[0].4, rows[1].4,
        "a reverse answer must examine the same mount-table entries at both workspace sizes: {rows:?}"
    );
    assert_eq!(
        rows[1].2, rows[1].1,
        "a definition projection must examine one mount-table entry per projected definition: {rows:?}"
    );
}

#[test]
fn root_prefix_public_reader_preserves_admission_order_pages_and_cancellation() {
    use crate::analyzer::resolution::{
        BatchCandidateMatch, BatchCandidateRequest, BatchResolutionFragmentSource,
        CandidatePathIdentity, EndpointSignature, PartialPathId, PartialScopedSymbol, StackPattern,
        StackVariableId,
    };
    let fixture = RustRootResolutionOperationFixture::new();
    let cancellation = CancellationToken::new();
    let operation = fixture.open_ready(&cancellation);
    let source = operation.ready.lexical_source();
    let connection = operation.ready.inventory.connection();
    let mut candidates = Vec::new();
    for mount in operation.ready.inventory.mounts().unwrap() {
        let identities = connection
            .prepare(
                "SELECT path FROM resolution_paths WHERE blob_id=?1 AND end_node=-1 ORDER BY path",
            )
            .unwrap()
            .query_map([mount.blob_id()], |row| row.get::<_, u32>(0))
            .unwrap()
            .map(|path| {
                CandidatePathIdentity::new(
                    mount.fragment_id(),
                    PartialPathId::local(mount.ordinal().get(), path.unwrap()),
                )
            })
            .collect::<Vec<_>>();
        for page in identities.chunks(256) {
            candidates.extend(source.hydrate_candidate_paths(page, &cancellation).unwrap());
        }
    }
    assert!(!candidates.is_empty());
    let mut requests = candidates
        .iter()
        .take(15)
        .enumerate()
        .map(|(ordinal, (_, path))| BatchCandidateRequest::new(ordinal, path.end().clone()))
        .collect::<Vec<_>>();
    requests.push(BatchCandidateRequest::new(
        requests.len(),
        EndpointSignature::new_scoped(
            crate::analyzer::resolution::BindingNodeId::universal_root(),
            StackPattern::new(
                Vec::<PartialScopedSymbol>::new(),
                Some(StackVariableId::operation_local(0)),
            ),
            StackPattern::new(
                Vec::<crate::analyzer::resolution::BindingNodeId>::new(),
                None,
            ),
        ),
    ));
    let mut actual = Vec::new();
    let completion = source
        .visit_reverse_candidate_match_pages(&requests, &cancellation, &mut |page| {
            assert!(page.len() <= 256);
            actual.extend_from_slice(page);
            Ok(true)
        })
        .unwrap();
    let mut expected = requests
        .iter()
        .enumerate()
        .flat_map(|(ordinal, request)| {
            candidates.iter().filter_map(move |(identity, path)| {
                request
                    .admits_candidate(path.end())
                    .then_some(BatchCandidateMatch::new(*identity, ordinal))
            })
        })
        .collect::<Vec<_>>();
    expected.sort_unstable();
    let mut sorted = actual.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, expected);
    let mut ordered = BTreeMap::<_, Vec<_>>::new();
    for row in &actual {
        ordered
            .entry((row.request_ordinal(), row.candidate().fragment()))
            .or_default()
            .push(row.candidate());
    }
    for identities in ordered.values() {
        assert!(
            identities.windows(2).all(|pair| pair[0] < pair[1]),
            "{identities:?}"
        );
    }
    let mut first_page = Vec::new();
    let stopped = source
        .visit_reverse_candidate_match_pages(&requests, &cancellation, &mut |page| {
            first_page.extend_from_slice(page);
            Ok(false)
        })
        .unwrap();
    assert_eq!(first_page, actual[..first_page.len()]);
    assert_eq!(stopped, completion);
    let cancelled = CancellationToken::new();
    let result = source
        .visit_reverse_candidate_match_pages(&requests, &cancelled, &mut |_| {
            cancelled.cancel();
            Ok(true)
        })
        .unwrap();
    assert!(cancelled.is_cancelled());
    assert!(
        matches!(result.unconditional_completion(), crate::analyzer::resolution::ResolutionCompletion::Incomplete(reasons) if reasons.iter().any(|reason| *reason == crate::analyzer::resolution::ResolutionIncompleteReason::Cancelled))
    );
    assert_eq!(result.branch_completions(), completion.branch_completions());
}
