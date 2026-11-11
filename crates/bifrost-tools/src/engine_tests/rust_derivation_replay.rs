//! Public-surface control for Rust route reads persisted as policy-unit keys.
#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;
    use brokk_bifrost_analysis::analyzer::read_ledger::{
        LookupKind, ReadKey, ReadLedger, read_set_digest,
    };
    use brokk_bifrost_analysis::analyzer::read_verification::{
        ChangedFacts, HeadInputs, LookupMemo, LookupReplayLimits, NoSummaryAnswers, ReadVerdict,
        verify_read_set_for_artifact,
    };
    use brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest;
    use brokk_bifrost_analysis::analyzer::semantic::invalidation::DerivedArtifactId;
    use brokk_bifrost_analysis::analyzer::store::policy_units::{
        PolicyUnitPartitionRow, PolicyUnitRow, PolicyUnitRowKey,
    };
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::{
        SelectedResolutionOperationInput, SelectedResolutionOperationOpenOutcome,
    };
    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;
    use brokk_bifrost_analysis::analyzer::store::{
        GenerationId, WorkspaceId, WorkspaceSnapshotId, WorkspaceSnapshots,
    };
    use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;
    use brokk_bifrost_core::analyzer::model::Language;
    use brokk_bifrost_core::analyzer::project::{FilesystemProject, WorkspaceFileListingCache};
    use brokk_bifrost_core::cancellation::CancellationToken;
    use brokk_bifrost_rust::graph_support::RustSource;
    use brokk_bifrost_rust_analysis::analyzer::rust::RustAnalyzer;

    use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};

    fn project() -> BuiltInlineTestProject {
        InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[workspace]\nmembers=['a','b']\nresolver='2'\n",
            )
            .file(
                "a/Cargo.toml",
                "[package]\nname='a'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file(
                "b/Cargo.toml",
                "[package]\nname='b'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file("a/src/lib.rs", "pub fn a() {}\n")
            .file("b/src/lib.rs", "pub fn b() {}\n")
            .build()
    }

    fn listed_analyzer(project: &BuiltInlineTestProject) -> WorkspaceAnalyzer {
        let cache = Arc::new(WorkspaceFileListingCache::new(project.root().to_path_buf()));
        let filesystem =
            Arc::new(FilesystemProject::with_cached_listing(project.root(), cache).unwrap());
        WorkspaceAnalyzer::build_ephemeral_footgun(filesystem, AnalyzerConfig::default()).unwrap()
    }

    fn record(
        project: &BuiltInlineTestProject,
        analyzer: &WorkspaceAnalyzer,
    ) -> (Vec<ReadKey>, bool, usize) {
        let WorkspaceAnalyzer::Multi(multi) = analyzer else {
            panic!("missing Rust delegate")
        };
        let delegate = multi.delegates().get(&Language::Rust).unwrap().analyzer();
        let rust = (delegate as &dyn std::any::Any)
            .downcast_ref::<RustAnalyzer>()
            .unwrap();
        let ledger = Arc::new(ReadLedger::new());
        let answer = {
            let _scope = AnalyzerQueryScope::with_read_ledger(analyzer.analyzer(), ledger.clone());
            RustSource::file_routes(rust, &project.file("a/src/lib.rs"), None).unwrap()
        };
        (
            ledger.keys(),
            answer.is_complete(),
            ledger.persistence_refusals(),
        )
    }

    fn verify(
        base: &WorkspaceAnalyzer,
        head: &WorkspaceAnalyzer,
        reads: &[ReadKey],
    ) -> ReadVerdict {
        let digest = StableDigest::sha256(b"route-read-control");
        verify_read_set_for_artifact(
            DerivedArtifactId::semantic_artifact(digest),
            head,
            &ChangedFacts::between(base, head),
            &HeadInputs {
                models: digest,
                policy_semantic_hash: digest,
                policy_source: digest,
                configuration: digest,
                epoch: digest,
            },
            reads,
            LookupReplayLimits::default(),
            &NoSummaryAnswers,
            &mut LookupMemo::new(),
        )
    }

    #[test]
    fn rust_derivation_reads_survive_policy_storage_and_replay() {
        let project = project();
        let base = listed_analyzer(&project);
        let (reads, complete, refusals) = record(&project, &base);
        assert!(complete);
        assert_eq!(refusals, 0);
        assert!(
            reads.iter().any(|key| matches!(
                key,
                ReadKey::Lookup {
                    kind: LookupKind::Derivation(_),
                    ..
                }
            )),
            "{reads:?}"
        );

        let digest = StableDigest::sha256(b"route-read-control");
        let key = PolicyUnitRowKey {
            policy_semantic_hash: digest.to_string(),
            family: "match".into(),
            partition: PolicyUnitPartitionRow::Whole,
            configuration_fingerprint: digest.to_string(),
            active_model_set_hash: digest.to_string(),
            engine_epoch: digest.to_string(),
        };
        base.store()
            .unwrap()
            .publish_policy_units(vec![PolicyUnitRow {
                seed_parse_variant: None,
                key: key.clone(),
                product_kind: "rows".into(),
                product: "{\"rows\":[]}".into(),
                read_set_digest: *read_set_digest(&reads).digest().as_bytes(),
                reads: reads.clone(),
                snapshots: vec![[1; 32]],
            }])
            .unwrap();
        let decoded = base
            .store()
            .unwrap()
            .policy_units_for_keys(&[key])
            .unwrap()
            .remove(0)
            .unwrap()
            .reads;
        assert_eq!(decoded, reads);
        assert_eq!(verify(&base, &base, &decoded), ReadVerdict::Unchanged);
        let store = base.store().unwrap();
        let (workspace, generation, revision): (String, i64, i64) = store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT workspace_id,generation,revision FROM workspace_heads WHERE lang='rust'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let workspace = WorkspaceId(workspace);
        let snapshots = std::iter::once((
            "rust".into(),
            WorkspaceSnapshotId {
                workspace_id: workspace.clone(),
                lang: "rust".into(),
                generation: GenerationId::from_persisted(generation),
                revision,
            },
        ))
        .collect::<WorkspaceSnapshots>();
        let languages = [SelectedResolutionLanguage::new(
            "rust".to_string(),
            Language::Rust,
        )];
        let input = SelectedResolutionOperationInput::new(
            project.project(),
            &workspace,
            &snapshots,
            &languages,
            &[],
        );
        let SelectedResolutionOperationOpenOutcome::Ready(operation) = store
            .open_selected_resolution_operation(input, &CancellationToken::default())
            .unwrap()
        else {
            panic!("selected operation unavailable")
        };
        let refused = verify(&base, &base, &decoded);
        assert!(matches!(refused.changed().unwrap().reason,
            brokk_bifrost_analysis::analyzer::invalidation::InvalidationReason::ReverseDependencyEvidenceMissing { .. }));
        drop(operation);

        std::fs::write(
            project.root().join("b/src/lib.rs"),
            "pub fn b() { let n = 1; }\n",
        )
        .unwrap();
        let unrelated = listed_analyzer(&project);
        assert_eq!(verify(&base, &unrelated, &decoded), ReadVerdict::Unchanged);
        std::fs::write(
            project.root().join("a/src/lib.rs"),
            "pub mod added; pub fn a() {}\n",
        )
        .unwrap();
        std::fs::write(project.root().join("a/src/added.rs"), "pub fn added() {}\n").unwrap();
        let member = listed_analyzer(&project);
        assert!(verify(&base, &member, &decoded).changed().is_some());
    }

    // An unknown Cargo target key makes route reads incomplete. What this test
    // pins is that an incomplete read replays as unchanged until its manifest
    // input changes.
    #[test]
    fn incomplete_rust_route_read_replays_until_target_key_is_fixed() {
        let project = project();
        std::fs::write(
            project.root().join("a/Cargo.toml"),
            "[package]\nname='a'\nversion='0.1.0'\nedition='2021'\n[lib]\nmystery=true\n",
        )
        .unwrap();
        let base = project.workspace_analyzer(AnalyzerConfig::default());
        let (reads, complete, refusals) = record(&project, &base);
        assert!(!complete);
        assert_eq!(refusals, 0);
        assert!(reads.iter().any(|key| matches!(
            key,
            ReadKey::Lookup {
                kind: LookupKind::Derivation(_),
                ..
            }
        )));
        let same = project.workspace_analyzer(AnalyzerConfig::default());
        assert_eq!(verify(&base, &same, &reads), ReadVerdict::Unchanged);
        std::fs::write(
            project.root().join("a/Cargo.toml"),
            "[package]\nname='a'\nversion='0.1.0'\nedition='2021'\n",
        )
        .unwrap();
        let completed = project.workspace_analyzer(AnalyzerConfig::default());
        assert!(verify(&base, &completed, &reads).changed().is_some());
    }

    /// A read set that names the memory-only call-site kind cannot be written
    /// by the encoder, but a store from before the kind was refused may hold
    /// one. Replay has no lent operation to compute it on, so it must report
    /// the evidence missing, which recomputes the unit, instead of reaching the
    /// kind's compute.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9755: replaying a persisted call-site lookup reached the kind's compute with no bound operation"
    )]
    fn a_persisted_call_site_lookup_replays_to_missing() {
        use brokk_bifrost_analysis::analyzer::read_ledger::LookupQuestion;
        use brokk_bifrost_semantic::analyzer::semantic::derivation::{
            DerivationKindId, DerivationQuestion,
        };

        let project = project();
        let base = listed_analyzer(&project);
        let reads = vec![ReadKey::lookup(
            LookupKind::Derivation(DerivationKindId("derivation:rust_call_site_resolution:v1")),
            LookupQuestion::Derivation(DerivationQuestion {
                language: Some(Language::Rust),
                subject: Some([7; 32]),
                rel_path: Some("a/src/lib.rs".into()),
                name: Some("0:3".into()),
            }),
            StableDigest::sha256(b"stored site answer"),
        )];
        let verdict = verify(&base, &base, &reads);
        assert!(
            matches!(
                verdict.changed().expect("the lookup is not served").reason,
                brokk_bifrost_analysis::analyzer::invalidation::InvalidationReason::ReverseDependencyEvidenceMissing { .. }
            ),
            "{verdict:?}"
        );
    }

    #[test]
    fn recipe_less_route_recording_refuses_policy_publication() {
        use brokk_bifrost_analysis::analyzer::derivation_host::AnalyzerDerivations;
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionMountInventoryOutcome;
        use brokk_bifrost_core::retention_budget::RetentionBudget;
        use brokk_bifrost_rust_analysis::analyzer::rust::route_kinds::RustFileUnits;

        let project = project();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let (workspace, generation, revision): (String, i64, i64) = store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT workspace_id,generation,revision FROM workspace_heads WHERE lang='rust'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let workspace = WorkspaceId(workspace);
        let snapshots = std::iter::once((
            "rust".into(),
            WorkspaceSnapshotId {
                workspace_id: workspace.clone(),
                lang: "rust".into(),
                generation: GenerationId::from_persisted(generation),
                revision,
            },
        ))
        .collect::<WorkspaceSnapshots>();
        let SelectedResolutionMountInventoryOutcome::Ready(inventory) = store
            .open_selected_resolution_mount_inventory(
                &workspace,
                &snapshots,
                &[SelectedResolutionLanguage::new(
                    "rust".to_string(),
                    Language::Rust,
                )],
                &[],
                &CancellationToken::default(),
            )
            .unwrap()
        else {
            panic!("selection unavailable")
        };
        let budget = RetentionBudget::new(1_000_000);
        let host = AnalyzerDerivations::without_declared_recipes(&budget);
        let ledger = Arc::new(ReadLedger::new());
        {
            let _scope = AnalyzerQueryScope::with_read_ledger(analyzer.analyzer(), ledger.clone());
            let _ = host.demand::<RustFileUnits>(
                analyzer.analyzer(),
                &inventory,
                &"a/src/lib.rs".to_string(),
            );
        }
        // unit_execution::recompute_unit publishes only what
        // ReadLedger::publishable_keys returns; this is the state it reads.
        assert!(ledger.persistence_refusals() > 0);
        assert!(ledger.publishable_keys().is_none());
    }
}
