#[cfg(test)]
mod rust_departing_root_tests {

    use brokk_bifrost_analysis::analyzer::resolution::model::BindingFragmentId;

    use brokk_bifrost_analysis::analyzer::resolution::model::BindingNodeId;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::resolution::model::PartialPath;

    use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedResolutionMountOrdinal;

    use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;

    use brokk_bifrost_analysis::analyzer::resolution::model::BindingNodeKind;

    use brokk_bifrost_analysis::analyzer::resolution::model::EndpointSignature;

    use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweredResolutionFragment;

    use brokk_bifrost_analysis::analyzer::resolution::model::PartialPathId;

    use brokk_bifrost_analysis::analyzer::resolution::model::PartialScopedSymbol;

    use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

    use brokk_bifrost_analysis::analyzer::resolution::model::StackPattern;

    use brokk_bifrost_analysis::analyzer::store::resolution_lexical::SelectedResolutionLexicalSource;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::selection_test_support::SelectionFixture;
    use rusqlite::params;
    #[test]
    fn prefix_spellings_use_the_path_producer_recipe_and_both_selected_hosts() {
        use brokk_bifrost_analysis::analyzer::resolution::local_identity::ResolutionLookupSemanticRecipe;

        use brokk_bifrost_analysis::analyzer::resolution::local_identity::SharedNameInterner;
        use brokk_bifrost_core::analyzer::{
            model::Language, resolution_facts::ResolutionNamespace,
        };
        let fixture = SelectionFixture::custom_source(
            2,
            "class Dependency {} class Model extends Dependency {}",
        );
        let selection = fixture.open_ready(&[]);
        let cancellation = CancellationToken::default();
        let names = selection
            .shared_name_table()
            .interner(selection.connection());
        let reference = SemanticId::operation_local((1 << 53) + 2001);
        let node = BindingNodeId::operation_local((1 << 53) + 2002);
        let recipe = ResolutionLookupSemanticRecipe::new(
            Language::Rust,
            ResolutionNamespace::Type,
            "dependency",
        );
        let lookup = SemanticId::shared_name(names.intern(recipe.name_digest()));
        let stage =
            brokk_bifrost_analysis::analyzer::store::resolution_stage::SelectedResolutionStage::new(
                &selection,
            );
        let publish =
            |host: u32,
             identity: u8,
             lowered: &LoweredResolutionFragment,
             recipes: &[(SemanticId, ResolutionLookupSemanticRecipe)]| {
                let mount = selection
                    .persisted_mount_record(SelectedResolutionMountOrdinal::new(host))
                    .unwrap()
                    .unwrap();
                assert!(matches!(
            stage
                .insert_generated_bridge(
                    &mount,
                    [identity; 32],
                    lowered,
                    None,
                    recipes,
                    &[],
                    &cancellation
                )
                .unwrap(),
            brokk_bifrost_analysis::analyzer::store::resolution_stage::SelectedResolutionStageOutcome::Ready
        ));
            };
        let owner = LoweredResolutionFragment::selected_macro_head_bridge(
            BindingFragmentId::at_ordinal(0),
            reference,
            node,
            BindingNodeId::operation_local((1 << 53) + 2003),
            PartialPathId::operation_local((1 << 53) + 2004),
        );
        let target = BindingNodeId::operation_local((1 << 53) + 2005);
        let original = PartialPath::new(
            EndpointSignature::new_scoped(
                target,
                StackPattern::closed([]),
                StackPattern::closed([]),
            ),
            EndpointSignature::new_scoped(
                target,
                StackPattern::closed([PartialScopedSymbol::unscoped(lookup)]),
                StackPattern::closed([]),
            ),
            Vec::new(),
            Vec::new(),
            ResolutionCompletion::Complete,
        );
        let path = LoweredResolutionFragment::selected_include_continuation(
            BindingFragmentId::at_ordinal(1),
            node,
            PartialPathId::operation_local((1 << 53) + 2006),
            BindingNodeKind::Scope,
            &original,
        );
        publish(0, 201, &owner, &[(lookup, recipe.clone())]);
        publish(1, 202, &path, &[]);
        let source = SelectedResolutionLexicalSource::new_on_demand(&selection);
        assert!(
            source
                .reference_lookup_spellings(&[reference], ResolutionNamespace::Type, &cancellation)
                .unwrap()
                .is_empty(),
            "a recipe on another producer cannot explain this path's endpoint"
        );
        stage.clear_facts().unwrap();
        publish(0, 201, &owner, &[]);
        publish(1, 202, &path, &[(lookup, recipe)]);
        assert_eq!(
            source
                .reference_lookup_spellings(&[reference], ResolutionNamespace::Type, &cancellation)
                .unwrap()
                .get(&reference)
                .map(String::as_str),
            Some("dependency")
        );
        let shared_reference = SemanticId::shared_name(names.intern([198; 32]));
        let shared_node = BindingNodeId::operation_local((1 << 53) + 2010);
        let shared_owner = LoweredResolutionFragment::selected_macro_head_bridge(
            BindingFragmentId::at_ordinal(0),
            shared_reference,
            shared_node,
            BindingNodeId::operation_local((1 << 53) + 2011),
            PartialPathId::operation_local((1 << 53) + 2012),
        );
        let shared_path = LoweredResolutionFragment::selected_include_continuation(
            BindingFragmentId::at_ordinal(1),
            shared_node,
            PartialPathId::operation_local((1 << 53) + 2013),
            BindingNodeKind::Scope,
            &original,
        );
        publish(0, 206, &shared_owner, &[]);
        publish(
            1,
            207,
            &shared_path,
            &[(
                lookup,
                ResolutionLookupSemanticRecipe::new(
                    Language::Rust,
                    ResolutionNamespace::Type,
                    "dependency",
                ),
            )],
        );
        assert_eq!(
            source
                .reference_lookup_spellings(
                    &[reference, shared_reference],
                    ResolutionNamespace::Type,
                    &cancellation
                )
                .unwrap()
                .get(&shared_reference)
                .map(String::as_str),
            Some("dependency")
        );
        for hidden in [0, 1] {
            selection
                .with_owned_temp_write(|connection| {
                    connection.execute(
                        "DELETE FROM temp.selected_resolution_scope_mounts WHERE mount_ordinal=?1",
                        [hidden],
                    )?;
                    Ok(())
                })
                .unwrap();
            assert!(
                source
                    .reference_lookup_spellings(
                        &[reference],
                        ResolutionNamespace::Type,
                        &cancellation
                    )
                    .unwrap()
                    .is_empty(),
                "both the reference owner and the foreign path host must be selected: {hidden}"
            );
            selection
                .with_owned_temp_write(|connection| {
                    connection.execute(
                    "INSERT INTO temp.selected_resolution_scope_mounts(mount_ordinal) VALUES(?1)",
                    [hidden],
                )?;
                    Ok(())
                })
                .unwrap();
        }
        let host = selection
            .persisted_mount_record(SelectedResolutionMountOrdinal::new(0))
            .unwrap()
            .unwrap();
        let (ordinary_key, ordinary_spelling): (u32, String) = selection.connection().query_row(
        "SELECT p.start_node,i.spelling FROM main.resolution_paths p JOIN main.resolution_sites s ON s.blob_id=p.blob_id AND s.site=p.start_node AND s.role=0 JOIN main.resolution_identities i ON i.id=p.end_lead_identity WHERE p.blob_id=?1 AND i.namespace=?2 ORDER BY p.path LIMIT 1",
        params![host.blob_id(),brokk_bifrost_analysis::analyzer::store::resolution_prepare::resolution_rows::namespace_code(ResolutionNamespace::Type)],
        |row| Ok((row.get(0)?,row.get(1)?)),
    ).unwrap();
        let ordinary_reference = SemanticId::local(0, ordinary_key);
        let ordinary_node = BindingNodeId::local(0, ordinary_key);
        assert_eq!(
            source
                .reference_lookup_spellings(
                    &[ordinary_reference],
                    ResolutionNamespace::Type,
                    &cancellation
                )
                .unwrap()
                .get(&ordinary_reference),
            Some(&ordinary_spelling)
        );
        let ordinary_owner = LoweredResolutionFragment::selected_macro_head_bridge(
            BindingFragmentId::at_ordinal(0),
            ordinary_reference,
            ordinary_node,
            BindingNodeId::operation_local((1 << 53) + 2020),
            PartialPathId::operation_local((1 << 53) + 2021),
        );
        publish(0, 203, &ordinary_owner, &[]);
        for (index, spelling) in [ordinary_spelling.as_str(), "different_dependency"]
            .into_iter()
            .enumerate()
        {
            let recipe = ResolutionLookupSemanticRecipe::new(
                Language::Rust,
                ResolutionNamespace::Type,
                spelling,
            );
            let lookup = SemanticId::shared_name(names.intern(recipe.name_digest()));
            let endpoint = EndpointSignature::new_scoped(
                target,
                StackPattern::closed([PartialScopedSymbol::unscoped(lookup)]),
                StackPattern::closed([]),
            );
            let original = PartialPath::new(
                endpoint.clone(),
                endpoint,
                Vec::new(),
                Vec::new(),
                ResolutionCompletion::Complete,
            );
            let path = LoweredResolutionFragment::selected_include_continuation(
                BindingFragmentId::at_ordinal(0),
                ordinary_node,
                PartialPathId::operation_local((1 << 53) + 2030 + index as u64),
                BindingNodeKind::Scope,
                &original,
            );
            publish(0, 204 + index as u8, &path, &[(lookup, recipe)]);
            let actual = source.reference_lookup_spellings(
                &[ordinary_reference],
                ResolutionNamespace::Type,
                &cancellation,
            );
            if index == 0 {
                assert_eq!(
                    actual.unwrap().get(&ordinary_reference),
                    Some(&ordinary_spelling),
                    "equal ordinary/stage spelling authority agrees"
                );
            } else {
                assert!(
                    actual.is_err(),
                    "conflicting actual Type routes cannot silently pick a spelling"
                );
            }
        }
        cancellation.cancel();
        assert!(
            source
                .reference_lookup_spellings(&[reference], ResolutionNamespace::Type, &cancellation)
                .unwrap()
                .is_empty()
        );
    }
}
