#[cfg(test)]
mod rust_departing_tests_tests {
    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionMountInventoryOutcome;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionUnavailable;

    use crate::engine_tests::rust_selection_fixture::RustSelectionFixture as SelectionFixture;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;

    use brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshots;

    #[test]
    fn requested_language_permutation_has_one_deterministic_missing_reason() {
        let fixture = SelectionFixture::new(0);
        for languages in [
            vec![
                SelectedResolutionLanguage::new("rust", Language::Rust),
                fixture.language(),
            ],
            vec![
                fixture.language(),
                SelectedResolutionLanguage::new("rust", Language::Rust),
            ],
        ] {
            let outcome = fixture
                .store
                .open_selected_resolution_mount_inventory(
                    &fixture.workspace_id,
                    &WorkspaceSnapshots::default(),
                    &languages,
                    &[],
                    &CancellationToken::default(),
                )
                .unwrap();
            assert!(matches!(
                outcome,
                SelectedResolutionMountInventoryOutcome::Unavailable(
                    SelectedResolutionUnavailable::MissingWorkspaceSnapshot {
                        storage_language
                    }
                ) if storage_language == "java"
            ));
        }
    }
}
