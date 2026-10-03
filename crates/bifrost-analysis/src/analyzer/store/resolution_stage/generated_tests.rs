use super::super::lexical_readers;
use super::*;
use crate::analyzer::Language;
use crate::analyzer::resolution::{
    BindingFragmentId, EndpointSignature, ResolutionCompletion, ResolutionIncompleteReason,
    ResolutionLookupSemanticRecipe, SelectedResolutionMountOrdinal, StackPattern, StackVariableId,
    WitnessStep,
};
use crate::analyzer::store::resolution_selection::{
    SelectedResolutionMountInventory, tests::SelectionFixture,
};
use brokk_bifrost_core::analyzer::resolution_facts::{ResolutionNamespace, ResolutionScopeId};
use brokk_bifrost_core::analyzer::rust_facts::{
    RustCfgCondition, RustImportTargetFact, RustVisibility,
};
use brokk_bifrost_core::analyzer::source_facts::SourceImportId;

const BASE: u32 = 1 << 31;

fn host(
    selection: &SelectedResolutionMountInventory<'_>,
    ordinal: u32,
) -> std::sync::Arc<SelectedResolutionMountRecord> {
    selection
        .persisted_mount_record(SelectedResolutionMountOrdinal::new(ordinal))
        .unwrap()
        .unwrap()
}

fn snapshot(connection: &Connection) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
    [
        "producers",
        "nodes",
        "node_owners",
        "paths",
        "semantic_coordinates",
        "node_coordinates",
        "path_coordinates",
        "variable_coordinates",
        "recipes",
        "allocation_counters",
    ]
    .into_iter()
    .map(|family| {
        let mut statement = connection
            .prepare(&format!(
                "SELECT * FROM temp.selected_resolution_stage_{family} ORDER BY 1,2"
            ))
            .unwrap();
        let width = statement.column_count();
        statement
            .query_map([], |row| (0..width).map(|index| row.get(index)).collect())
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    })
    .collect()
}

// SQL storage alpha-normalizes variables per path. The model key retains
// exact endpoint identities and variable aliasing across both endpoint stacks;
// the allocation ceiling is derived metadata, not part of that behavior.
fn assert_path_body(actual: &PartialPath, expected: &PartialPath) {
    assert_eq!(
        actual
            .stack_effect_alpha_key_with_poll(&mut || false)
            .unwrap(),
        expected
            .stack_effect_alpha_key_with_poll(&mut || false)
            .unwrap(),
    );
    assert_eq!(actual.precedence(), expected.precedence());
    assert_eq!(actual.witness(), expected.witness());
    assert_eq!(actual.completion(), expected.completion());
}

fn assert_paths(
    selection: &SelectedResolutionMountInventory<'_>,
    fragments: &[LoweredResolutionFragment],
) {
    let expected = fragments
        .iter()
        .flat_map(|fragment| {
            fragment.paths().iter().map(|(path, body)| {
                (
                    CandidatePathIdentity::new(fragment.fragment(), *path),
                    body.clone(),
                )
            })
        })
        .collect::<Vec<_>>();
    let keys = expected.iter().map(|(key, _)| *key).collect::<Vec<_>>();
    let actual =
        lexical_readers::hydrate_candidate_paths(selection, &keys, &CancellationToken::new())
            .unwrap()
            .unwrap();
    assert_eq!(actual.len(), expected.len());
    for (actual, (identity, expected)) in actual.iter().zip(&expected) {
        let actual = actual
            .as_ref()
            .unwrap_or_else(|| panic!("missing path {identity:?}"));
        assert_path_body(actual, expected);
    }
}

#[test]
fn macro_pair_preserves_constructor_paths_same_host_and_cross_host_and_repeats() {
    for target in [0, 1] {
        let fixture = SelectionFixture::shared_blob(2);
        let selection = fixture.open_ready(&[]);
        let stage = SelectedResolutionStage::new(&selection);
        let source = host(&selection, 0);
        let target_host = host(&selection, target);
        let reference = SemanticId::context_local((1 << 53) + 31);
        let reference_node = BindingNodeId::operation_local((1 << 53) + 41);
        let definition = SemanticId::operation_local((1 << 53) + 51);
        let definition_node = BindingNodeId::context_local((1 << 53) + 61);
        let cancellation = CancellationToken::new();
        let admit = || {
            stage.admit_macro_head_pair(
                &source,
                reference,
                reference_node,
                &target_host,
                definition,
                definition_node,
                &cancellation,
            )
        };
        let epoch = selection.stage_content_epoch_for_test();
        assert_eq!(admit().unwrap(), Some(()));
        assert_eq!(selection.stage_content_epoch_for_test(), epoch + 1);
        let boundary = BindingNodeId::local(0, BASE);
        let source_path = PartialPathId::local(0, BASE);
        let target_path = PartialPathId::local(target, BASE + u32::from(target == 0));
        assert_ne!(source_path, target_path);
        assert_paths(
            &selection,
            &[
                LoweredResolutionFragment::selected_macro_head_bridge(
                    source.fragment_id(),
                    reference,
                    reference_node,
                    boundary,
                    source_path,
                ),
                LoweredResolutionFragment::selected_macro_head_definition(
                    target_host.fragment_id(),
                    definition,
                    definition_node,
                    boundary,
                    target_path,
                ),
            ],
        );
        let rows = snapshot(selection.connection());
        let fingerprint = selection.candidate_coverage_fingerprint();
        assert_eq!(admit().unwrap(), Some(()));
        assert_eq!(snapshot(selection.connection()), rows);
        assert_eq!(selection.candidate_coverage_fingerprint(), fingerprint);
        assert_eq!(selection.stage_content_epoch_for_test(), epoch + 1);
        assert!(
            stage
                .admit_macro_head_pair(
                    &source,
                    reference,
                    reference_node,
                    &target_host,
                    definition,
                    BindingNodeId::context_local((1 << 53) + 62),
                    &cancellation
                )
                .is_err()
        );
        assert_eq!(snapshot(selection.connection()), rows);
        assert_eq!(selection.candidate_coverage_fingerprint(), fingerprint);
    }
}

fn original_path(end: BindingNodeId, reason: u64) -> PartialPath {
    let variable = StackVariableId::operation_local((1 << 53) + 11);
    let semantic = SemanticId::context_local((1 << 53) + 12);
    PartialPath::new(
        EndpointSignature::new(
            BindingNodeId::context_local((1 << 53) + 13),
            StackPattern::open(vec![semantic], variable),
            StackPattern::closed([]),
        ),
        EndpointSignature::new(
            end,
            StackPattern::open(vec![semantic], variable),
            StackPattern::closed([]),
        ),
        Vec::new(),
        vec![WitnessStep::Node(end)],
        ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
            SemanticId::context_local(reason),
        )]),
    )
}

#[test]
fn include_pair_preserves_borrowed_runtime_body_and_allocates_fresh_after_clear() {
    for origin in [0, 1] {
        let fixture = SelectionFixture::shared_blob(2);
        let selection = fixture.open_ready(&[]);
        let stage = SelectedResolutionStage::new(&selection);
        let destination_host = host(&selection, 0);
        let origin_host = host(&selection, origin);
        let destination = BindingNodeId::context_local((1 << 53) + 21);
        let end = BindingNodeId::operation_local((1 << 53) + 22);
        let definition = SemanticId::context_local((1 << 53) + 23);
        let original = original_path(end, 71);
        let original_identity = CandidatePathIdentity::new(
            origin_host.fragment_id(),
            PartialPathId::operation_local((1 << 53) + 24),
        );
        let cancellation = CancellationToken::new();
        let epoch = selection.stage_content_epoch_for_test();
        let admit = || {
            stage.admit_include_binding_pair(
                &destination_host,
                destination,
                &origin_host,
                original_identity,
                &original,
                BindingNodeKind::Definition(definition),
                &cancellation,
            )
        };
        assert_eq!(admit().unwrap(), Some(()));
        assert_eq!(selection.stage_content_epoch_for_test(), epoch + 1);
        let boundary = BindingNodeId::local(0, BASE);
        assert_paths(
            &selection,
            &[
                LoweredResolutionFragment::selected_include_binding(
                    destination_host.fragment_id(),
                    destination,
                    boundary,
                    PartialPathId::local(0, BASE),
                    &original,
                ),
                LoweredResolutionFragment::selected_include_continuation(
                    origin_host.fragment_id(),
                    boundary,
                    PartialPathId::local(origin, BASE + u32::from(origin == 0)),
                    BindingNodeKind::Definition(definition),
                    &original,
                ),
            ],
        );
        let rows = snapshot(selection.connection());
        let fingerprint = selection.candidate_coverage_fingerprint();
        assert_eq!(admit().unwrap(), Some(()));
        assert_eq!(snapshot(selection.connection()), rows);
        assert_eq!(selection.candidate_coverage_fingerprint(), fingerprint);
        let changed = original_path(end, 72);
        assert!(
            stage
                .admit_include_binding_pair(
                    &destination_host,
                    destination,
                    &origin_host,
                    original_identity,
                    &changed,
                    BindingNodeKind::Definition(definition),
                    &cancellation
                )
                .is_err()
        );
        assert_eq!(snapshot(selection.connection()), rows);
        assert_eq!(selection.candidate_coverage_fingerprint(), fingerprint);
        stage.clear_facts().unwrap();
        let cleared_epoch = selection.stage_content_epoch_for_test();
        assert_eq!(admit().unwrap(), Some(()));
        assert_eq!(selection.stage_content_epoch_for_test(), cleared_epoch + 1);
        let next_path = BASE + if origin == 0 { 2 } else { 1 };
        assert_paths(
            &selection,
            &[
                LoweredResolutionFragment::selected_include_binding(
                    destination_host.fragment_id(),
                    destination,
                    BindingNodeId::local(0, BASE + 1),
                    PartialPathId::local(0, next_path),
                    &original,
                ),
                LoweredResolutionFragment::selected_include_continuation(
                    origin_host.fragment_id(),
                    BindingNodeId::local(0, BASE + 1),
                    PartialPathId::local(origin, if origin == 0 { BASE + 3 } else { BASE + 1 }),
                    BindingNodeKind::Definition(definition),
                    &original,
                ),
            ],
        );
    }
}

fn glob(
    selection: &SelectedResolutionMountInventory<'_>,
    name: &str,
    module: &[&str],
) -> (LoweredResolutionFragment, ResolutionIdentityCatalog) {
    let import = RustImportTargetFact {
        native_scope: Some(ResolutionScopeId::new(91)),
        source_import_id: Some(SourceImportId::new(92)),
        module_path: module.iter().map(|segment| (*segment).to_owned()).collect(),
        bound_name: None,
        imported_name: None,
        is_glob: true,
        leading_absolute: false,
        is_extern_crate: false,
        is_macro_use: false,
        visibility: RustVisibility::Private,
        cfg_condition: RustCfgCondition::Always,
        owner_module: String::new(),
        owner_start: 0,
        owner_end: 20,
        local_extent: None,
        source_occurrences: None,
    };
    LoweredResolutionFragment::selected_include_glob(
        BindingFragmentId::at_ordinal(0),
        &selection
            .shared_name_table()
            .interner(selection.connection()),
        &import,
        &ResolutionLookupSemanticRecipe::new(Language::Rust, ResolutionNamespace::Value, name),
    )
}

#[test]
fn include_glob_replays_variables_projects_recipes_and_checks_complete_repeated_body() {
    let fixture = SelectionFixture::new(1);
    let selection = fixture.open_ready(&[]);
    let stage = SelectedResolutionStage::new(&selection);
    let host = host(&selection, 0);
    let cancellation = CancellationToken::new();
    let (lexical, catalog) = glob(&selection, "value", &["alpha", "beta"]);
    let recipe_count = catalog.lookup_recipes().len();
    let first = stage
        .admit_include_glob(&host, lexical, catalog, &cancellation)
        .unwrap()
        .unwrap();
    let epoch = selection.stage_content_epoch_for_test();
    let actual = lexical_readers::hydrate_candidate_paths(&selection, &[first.0], &cancellation)
        .unwrap()
        .unwrap();
    assert_eq!(actual.len(), 1);
    assert_path_body(
        actual[0].as_ref().expect("the admitted glob path exists"),
        &first.1,
    );
    let stored_recipes: usize = selection
        .connection()
        .query_row(
            "SELECT count(*) FROM temp.selected_resolution_stage_recipes",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored_recipes, recipe_count);
    assert!(stored_recipes > 0);
    let rows = snapshot(selection.connection());
    let (lexical, catalog) = glob(&selection, "value", &["alpha", "beta"]);
    assert_eq!(
        stage
            .admit_include_glob(&host, lexical, catalog, &cancellation)
            .unwrap()
            .unwrap(),
        first
    );
    assert_eq!(snapshot(selection.connection()), rows);
    assert_eq!(selection.stage_content_epoch_for_test(), epoch);
    // Reordering the same route names preserves the catalog and path identity.
    // Complete body comparison must still reject the changed symbol order.
    let (lexical, catalog) = glob(&selection, "value", &["beta", "alpha"]);
    let error = stage
        .admit_include_glob(&host, lexical, catalog, &cancellation)
        .unwrap_err();
    assert!(error.to_string().contains("complete descriptor"), "{error}");
    assert_eq!(snapshot(selection.connection()), rows);
    assert_eq!(selection.stage_content_epoch_for_test(), epoch);
    let (lexical, catalog) = glob(&selection, "another", &["alpha", "beta"]);
    let second = stage
        .admit_include_glob(&host, lexical, catalog, &cancellation)
        .unwrap()
        .unwrap();
    assert_ne!(first.0, second.0);
    assert_ne!(
        first.1.start().symbols().tail(),
        second.1.start().symbols().tail()
    );
    assert_eq!(selection.stage_content_epoch_for_test(), epoch + 1);
}

#[test]
fn cancelled_second_half_rolls_back_both_halves_and_all_counter_reservations() {
    for target in [0, 1] {
        let fixture = SelectionFixture::shared_blob(2);
        let selection = fixture.open_ready(&[]);
        let stage = SelectedResolutionStage::new(&selection);
        let source = host(&selection, 0);
        let target_host = host(&selection, target);
        let token = CancellationToken::new();
        let callback_token = token.clone();
        selection
            .connection()
            .create_scalar_function(
                "cancel_generated_pair",
                0,
                rusqlite::functions::FunctionFlags::SQLITE_UTF8,
                move |_| {
                    callback_token.cancel();
                    Ok(0)
                },
            )
            .unwrap();
        selection.with_owned_temp_write(|connection| {
            connection.execute_batch("CREATE TEMP TRIGGER cancel_generated_second_half AFTER INSERT ON selected_resolution_stage_producers WHEN (SELECT count(*) FROM selected_resolution_stage_producers)=2 BEGIN SELECT cancel_generated_pair(); END;")?;
            Ok(())
        }).unwrap();
        let rows = snapshot(selection.connection());
        let fingerprint = selection.candidate_coverage_fingerprint();
        let epoch = selection.stage_content_epoch_for_test();
        assert_eq!(
            stage
                .admit_macro_head_pair(
                    &source,
                    SemanticId::context_local(10),
                    BindingNodeId::context_local(11),
                    &target_host,
                    SemanticId::context_local(20),
                    BindingNodeId::context_local(21),
                    &token
                )
                .unwrap(),
            None
        );
        assert!(
            token.is_cancelled(),
            "second producer insertion reached the cancellation boundary"
        );
        assert_eq!(snapshot(selection.connection()), rows);
        assert_eq!(selection.candidate_coverage_fingerprint(), fingerprint);
        assert_eq!(selection.stage_content_epoch_for_test(), epoch);
        assert!(selection.connection().is_autocommit());
        selection
            .with_owned_temp_write(|connection| {
                connection.execute_batch("DROP TRIGGER cancel_generated_second_half")?;
                Ok(())
            })
            .unwrap();
        assert_eq!(
            stage
                .admit_macro_head_pair(
                    &source,
                    SemanticId::context_local(10),
                    BindingNodeId::context_local(11),
                    &target_host,
                    SemanticId::context_local(20),
                    BindingNodeId::context_local(21),
                    &CancellationToken::new()
                )
                .unwrap(),
            Some(())
        );
        assert_eq!(selection.stage_content_epoch_for_test(), epoch + 1);
    }
}

#[test]
fn existing_source_half_still_validates_its_body_and_rebuilds_missing_target_atomically() {
    let fixture = SelectionFixture::shared_blob(2);
    let selection = fixture.open_ready(&[]);
    let stage = SelectedResolutionStage::new(&selection);
    let source = host(&selection, 0);
    let target = host(&selection, 1);
    let cancellation = CancellationToken::new();
    let reference = SemanticId::context_local(10);
    let reference_node = BindingNodeId::context_local(11);
    let definition = SemanticId::context_local(20);
    let definition_node = BindingNodeId::context_local(21);
    assert_eq!(
        stage
            .admit_macro_head_pair(
                &source,
                reference,
                reference_node,
                &target,
                definition,
                definition_node,
                &cancellation
            )
            .unwrap(),
        Some(())
    );
    selection
        .with_owned_temp_write(|connection| {
            connection.execute(
                "DELETE FROM temp.selected_resolution_stage_producers WHERE host_ordinal=1",
                [],
            )?;
            Ok(())
        })
        .unwrap();
    let rows = snapshot(selection.connection());
    let epoch = selection.stage_content_epoch_for_test();
    assert!(
        stage
            .admit_macro_head_pair(
                &source,
                reference,
                BindingNodeId::context_local(12),
                &target,
                definition,
                definition_node,
                &cancellation
            )
            .is_err()
    );
    assert_eq!(snapshot(selection.connection()), rows);
    assert_eq!(selection.stage_content_epoch_for_test(), epoch);
    assert_eq!(
        stage
            .admit_macro_head_pair(
                &source,
                reference,
                reference_node,
                &target,
                definition,
                definition_node,
                &cancellation
            )
            .unwrap(),
        Some(())
    );
    assert_eq!(selection.stage_content_epoch_for_test(), epoch + 1);
    assert_paths(
        &selection,
        &[
            LoweredResolutionFragment::selected_macro_head_bridge(
                source.fragment_id(),
                reference,
                reference_node,
                BindingNodeId::local(0, BASE),
                PartialPathId::local(0, BASE),
            ),
            LoweredResolutionFragment::selected_macro_head_definition(
                target.fragment_id(),
                definition,
                definition_node,
                BindingNodeId::local(0, BASE),
                PartialPathId::local(1, BASE + 1),
            ),
        ],
    );
}

#[test]
fn existing_target_mismatch_rolls_back_a_new_source_half() {
    let fixture = SelectionFixture::shared_blob(2);
    let selection = fixture.open_ready(&[]);
    let stage = SelectedResolutionStage::new(&selection);
    let source = host(&selection, 0);
    let target = host(&selection, 1);
    let cancellation = CancellationToken::new();
    let reference = SemanticId::context_local(10);
    let reference_node = BindingNodeId::context_local(11);
    let definition = SemanticId::context_local(20);
    assert_eq!(
        stage
            .admit_macro_head_pair(
                &source,
                reference,
                reference_node,
                &target,
                definition,
                BindingNodeId::context_local(21),
                &cancellation
            )
            .unwrap(),
        Some(())
    );
    selection
        .with_owned_temp_write(|connection| {
            connection.execute(
                "DELETE FROM temp.selected_resolution_stage_producers WHERE host_ordinal=0",
                [],
            )?;
            Ok(())
        })
        .unwrap();
    let rows = snapshot(selection.connection());
    let epoch = selection.stage_content_epoch_for_test();
    let fingerprint = selection.candidate_coverage_fingerprint();
    let error = stage
        .admit_macro_head_pair(
            &source,
            reference,
            reference_node,
            &target,
            definition,
            BindingNodeId::context_local(22),
            &cancellation,
        )
        .unwrap_err();
    assert!(error.to_string().contains("complete descriptor"), "{error}");
    assert_eq!(snapshot(selection.connection()), rows);
    assert_eq!(selection.stage_content_epoch_for_test(), epoch);
    assert_eq!(selection.candidate_coverage_fingerprint(), fingerprint);
}

#[test]
fn include_glob_cancellation_rolls_back_all_four_coordinate_domains() {
    let fixture = SelectionFixture::new(1);
    let selection = fixture.open_ready(&[]);
    let stage = SelectedResolutionStage::new(&selection);
    let host = host(&selection, 0);
    let token = CancellationToken::new();
    let callback_token = token.clone();
    selection
        .connection()
        .create_scalar_function(
            "cancel_glob_path",
            0,
            rusqlite::functions::FunctionFlags::SQLITE_UTF8,
            move |_| {
                callback_token.cancel();
                Ok(0)
            },
        )
        .unwrap();
    selection.with_owned_temp_write(|connection| {
        connection.execute_batch("CREATE TEMP TRIGGER cancel_glob_projection AFTER INSERT ON selected_resolution_stage_paths BEGIN SELECT cancel_glob_path(); END;")?;
        Ok(())
    }).unwrap();
    let (lexical, catalog) = glob(&selection, "value", &["alpha", "beta"]);
    let rows = snapshot(selection.connection());
    let epoch = selection.stage_content_epoch_for_test();
    let fingerprint = selection.candidate_coverage_fingerprint();
    assert_eq!(
        stage
            .admit_include_glob(&host, lexical, catalog, &token)
            .unwrap(),
        None
    );
    assert!(
        token.is_cancelled(),
        "path insertion reached the cancellation boundary after allocation"
    );
    assert_eq!(snapshot(selection.connection()), rows);
    assert_eq!(selection.stage_content_epoch_for_test(), epoch);
    assert_eq!(selection.candidate_coverage_fingerprint(), fingerprint);
    assert!(selection.connection().is_autocommit());
}
