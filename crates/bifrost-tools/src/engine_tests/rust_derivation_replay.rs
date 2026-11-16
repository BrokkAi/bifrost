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
    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;
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

    const PRODUCTION_OPERATIONS: [&str; 7] = [
        "routes",
        "package-files",
        "package-contains",
        "crate-packages",
        "inverse",
        "incoming",
        "logging-dispatch",
    ];

    const PRODUCTION_OUTER_KINDS: [&str; 9] = [
        "derivation:unit_summary:v1",
        "derivation:rust_unit_dependency_identities:v1",
        "derivation:rust_file_units:v1",
        "derivation:rust_broad_file_units:v1",
        "derivation:rust_crate_name_units:v2",
        "derivation:rust_package_units:v1",
        "derivation:rust_unit_routes:v1",
        "derivation:rust_target_reachability:v2",
        "derivation:rust_unit_package_rows:v1",
    ];

    const PRODUCTION_NESTED_KINDS: [&str; 4] = [
        "derivation:rust_selected_units_known:v1",
        "derivation:rust_unit_inputs:v2",
        "derivation:rust_unit_naming:v1",
        "derivation:rust_unit_dependents:v1",
    ];

    fn production_receipt_key(operation: &str) -> PolicyUnitRowKey {
        let digest = StableDigest::sha256(b"production-derivation-receipts");
        PolicyUnitRowKey {
            policy_semantic_hash: digest.to_string(),
            family: "match".into(),
            partition: PolicyUnitPartitionRow::Whole,
            configuration_fingerprint: StableDigest::sha256(operation.as_bytes()).to_string(),
            active_model_set_hash: digest.to_string(),
            engine_epoch: digest.to_string(),
        }
    }

    fn production_derivation_counters(
        analyzer: &WorkspaceAnalyzer,
    ) -> Vec<(
        &'static str,
        brokk_bifrost_semantic::analyzer::semantic::derivation::KindCounters,
    )> {
        let WorkspaceAnalyzer::Multi(multi) = analyzer else {
            panic!("Rust delegate")
        };
        let host = multi
            .delegates()
            .get(&Language::Rust)
            .unwrap()
            .analyzer()
            .snapshot_caches()
            .unwrap()
            .derivations();
        PRODUCTION_OUTER_KINDS
            .iter()
            .chain(PRODUCTION_NESTED_KINDS.iter())
            .copied()
            .map(|kind| {
                (
                    kind,
                    host.counters(
                        brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationKindId(
                            kind,
                        ),
                    ),
                )
            })
            .collect()
    }

    #[test]
    fn production_derivation_receipts_reopen_under_a_fresh_owner() {
        use brokk_bifrost_analysis::analyzer::i_analyzer::QueryScope;
        use brokk_bifrost_analysis::analyzer::usages::call_relations::{
            CallRelationLimits, CallRelationService, CallerInventoryCoverage, ExactCallLocation,
        };
        use brokk_bifrost_core::retention_budget::RetentionBudget;
        use std::collections::BTreeSet;

        const CHILD_ROOT: &str = "BIFROST_RUST_DERIVATION_REPLAY_CHILD_ROOT";
        const CHILD_SUCCESS: &str = "rust derivation persisted process replay complete";
        if let Some(root) = std::env::var_os(CHILD_ROOT) {
            let budget = RetentionBudget::for_test_capacity(64 * 1024 * 1024);
            let analyzer = WorkspaceAnalyzer::build_persisted_with_budget(
                crate::inline_project::certified_project_at(std::path::Path::new(&root)),
                AnalyzerConfig::default(),
                &budget,
            )
            .unwrap();
            let before = production_derivation_counters(&analyzer);
            eprintln!("child Rust derivation counters before SQL load and replay: {before:?}");
            for operation in PRODUCTION_OPERATIONS {
                let key = production_receipt_key(operation);
                let row = analyzer
                    .store()
                    .unwrap()
                    .policy_units_for_keys(std::slice::from_ref(&key))
                    .unwrap()
                    .remove(0)
                    .expect(operation);
                assert_eq!(row.key, key, "{operation}");
                assert!(!row.reads.is_empty(), "{operation}");
                assert_eq!(
                    row.read_set_digest,
                    *read_set_digest(&row.reads).digest().as_bytes(),
                    "{operation}"
                );
                assert_eq!(
                    verify(&analyzer, &analyzer, &row.reads),
                    ReadVerdict::Unchanged,
                    "{operation}: {:?}",
                    row.reads
                );
            }
            let after = production_derivation_counters(&analyzer);
            eprintln!("child Rust derivation counters after replay: {after:?}");
            for ((kind, before), (_, after)) in before.iter().zip(&after) {
                assert!(
                    after.recomputed > before.recomputed,
                    "child {kind}: before {before:?}, after {after:?}"
                );
            }
            println!("\n{CHILD_SUCCESS}");
            return;
        }

        let project = InlineTestProject::new()
            .file("Cargo.toml", "[workspace]\nmembers=['app','core']\nresolver='2'\n")
            .file("app/Cargo.toml", "[package]\nname='app'\nversion='0.1.0'\nedition='2021'\n[dependencies]\ncore={path='../core'}\nlog='0.4'\n")
            .file("core/Cargo.toml", "[package]\nname='core'\nversion='0.1.0'\nedition='2021'\n")
            .file("core/src/lib.rs", "pub fn target() {}\n")
            .file("app/src/lib.rs", "mod logging; pub fn run() { core::target(); }\n")
            .file("app/src/logging.rs", "use log; pub fn log(s: &str) { log::info!(\"{}\", s); }\n")
            .build();
        let build = |budget: &RetentionBudget| {
            let cache = Arc::new(WorkspaceFileListingCache::new(project.root().to_path_buf()));
            let filesystem =
                Arc::new(FilesystemProject::with_cached_listing(project.root(), cache).unwrap());
            WorkspaceAnalyzer::build_persisted_with_budget(
                filesystem,
                AnalyzerConfig::default(),
                budget,
            )
            .unwrap()
        };
        let budget = RetentionBudget::for_test_capacity(64 * 1024 * 1024);
        let base = build(&budget);
        let WorkspaceAnalyzer::Multi(multi) = &base else {
            panic!("Rust delegate")
        };
        let rust = (multi.delegates().get(&Language::Rust).unwrap().analyzer()
            as &dyn std::any::Any)
            .downcast_ref::<RustAnalyzer>()
            .unwrap();
        let app = project.file("app/src/lib.rs");
        let core = project.file("core/src/lib.rs");
        let mut receipts = Vec::new();
        for operation in PRODUCTION_OPERATIONS {
            let ledger = Arc::new(ReadLedger::new());
            {
                let scope = AnalyzerQueryScope::with_read_ledger(base.analyzer(), ledger.clone());
                match operation {
                    "routes" => {
                        let answer = rust.file_routes(&app, None).unwrap();
                        assert!(answer.is_complete());
                        assert!(!answer.target_roots(&app).is_empty());
                    }
                    "package-files" => {
                        let answer = rust.package_files_of(scope.token(), "core", None).unwrap();
                        assert!(answer.complete);
                        assert!(answer.value.contains(&core), "{answer:?}");
                    }
                    "package-contains" => {
                        let answer = rust.package_contains(scope.token(), &app, None).unwrap();
                        assert!(answer.complete && answer.value);
                    }
                    "crate-packages" => {
                        let answer = rust
                            .crate_package_names(scope.token(), "core", None)
                            .unwrap();
                        assert!(answer.complete);
                        assert!(!answer.value.is_empty());
                    }
                    "inverse" => {
                        let answer = rust
                            .files_that_can_reference_target_of(&core, None)
                            .unwrap();
                        assert!(answer.complete);
                        assert!(answer.value.contains(&app), "{answer:?}");
                    }
                    "incoming" => {
                        let targets = base
                            .analyzer()
                            .get_all_declarations()
                            .into_iter()
                            .filter(|unit| unit.fq_name().to_string().ends_with("target"))
                            .collect::<Vec<_>>();
                        assert_eq!(targets.len(), 1, "{targets:?}");
                        let answers = CallRelationService::incoming_in_file(
                            base.analyzer(),
                            scope.token(),
                            &app,
                            &targets,
                            CallRelationLimits {
                                max_files: usize::MAX,
                                max_source_bytes: usize::MAX,
                                max_candidates: usize::MAX,
                            },
                            None,
                        )
                        .unwrap();
                        assert_eq!(answers.len(), 1);
                        let answer = &answers[0];
                        assert_eq!(
                            answer.caller_inventory,
                            CallerInventoryCoverage::Complete,
                            "{answer:?}"
                        );
                        assert!(
                            !answer.cancelled && !answer.truncated && !answer.sites.is_empty(),
                            "{answer:?}"
                        );
                    }
                    "logging-dispatch" => {
                        let file = project.file("app/src/logging.rs");
                        let syntax = rust.prepared_syntax(scope.token(), &file).unwrap();
                        let mut stack = vec![syntax.tree().root_node()];
                        let mut macros = Vec::new();
                        while let Some(node) = stack.pop() {
                            if node.kind() == "macro_invocation" {
                                macros.push(node);
                            }
                            let mut cursor = node.walk();
                            stack.extend(node.named_children(&mut cursor));
                        }
                        assert_eq!(macros.len(), 1);
                        let node = macros[0];
                        let call_span = brokk_bifrost_analysis::analyzer::Range {
                            start_byte: node.start_byte(),
                            end_byte: node.end_byte(),
                            start_line: node.start_position().row + 1,
                            end_line: node.end_position().row + 1,
                        };
                        let answer = CallRelationService::dispatch_at_bounded(
                            base.analyzer(),
                            scope.token(),
                            &ExactCallLocation { file, call_span },
                            Arc::from(syntax.source()),
                            CallRelationLimits {
                                max_files: usize::MAX,
                                max_source_bytes: usize::MAX,
                                max_candidates: usize::MAX,
                            },
                            None,
                        );
                        assert_eq!(
                            answer.status,
                            Some(DefinitionLookupStatus::Resolved),
                            "{answer:?}"
                        );
                        assert!(
                            !answer.cancelled && !answer.truncated && !answer.budget_exhausted,
                            "{answer:?}"
                        );
                        let proof = answer
                            .exact_external_call
                            .as_ref()
                            .expect("real external logging callable");
                        assert_eq!(proof.canonical_callee.as_ref(), "log::__private_api::log");
                        assert!(!answer.boundaries.is_empty(), "{answer:?}");
                    }
                    _ => unreachable!(),
                }
            }
            assert_eq!(ledger.persistence_refusals(), 0, "{operation}");
            let reads = ledger.publishable_keys().expect(operation);
            assert!(!reads.is_empty(), "{operation}");
            receipts.push((operation, reads));
        }
        let kinds = receipts
            .iter()
            .flat_map(|(_, reads)| reads)
            .filter_map(|key| match key {
                ReadKey::Lookup {
                    kind: LookupKind::Derivation(kind),
                    ..
                } => Some(kind.0),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(kinds, BTreeSet::from(PRODUCTION_OUTER_KINDS));
        // Nested recipes keep their reads in non-forwarding captures. Prove
        // those real fills without adding child keys to the outer receipts.

        let host = multi
            .delegates()
            .get(&Language::Rust)
            .unwrap()
            .analyzer()
            .snapshot_caches()
            .unwrap()
            .derivations();
        for kind in PRODUCTION_OUTER_KINDS
            .iter()
            .chain(PRODUCTION_NESTED_KINDS.iter())
            .copied()
        {
            let counters = host.counters(
                brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationKindId(kind),
            );
            assert!(counters.recomputed > 0, "{kind}: {counters:?}");
        }
        let keys = receipts
            .iter()
            .map(|(operation, _)| production_receipt_key(operation))
            .collect::<Vec<_>>();
        base.store()
            .unwrap()
            .publish_policy_units(
                receipts
                    .iter()
                    .zip(&keys)
                    .map(|((_, reads), key)| PolicyUnitRow {
                        seed_parse_variant: None,
                        key: key.clone(),
                        product_kind: "rows".into(),
                        product: "{\"rows\":[]}".into(),
                        read_set_digest: *read_set_digest(reads).digest().as_bytes(),
                        reads: reads.clone(),
                        snapshots: vec![[1; 32]],
                    })
                    .collect(),
            )
            .unwrap();
        drop(base);
        drop(budget);
        let fresh_budget = RetentionBudget::for_test_capacity(64 * 1024 * 1024);
        let fresh = build(&fresh_budget);
        let before = production_derivation_counters(&fresh);
        eprintln!("fresh Rust derivation counters before SQL load and replay: {before:?}");
        let decoded = keys
            .iter()
            .map(|key| {
                fresh
                    .store()
                    .unwrap()
                    .policy_units_for_keys(std::slice::from_ref(key))
                    .unwrap()
                    .remove(0)
            })
            .collect::<Vec<_>>();
        for ((operation, reads), row) in receipts.iter().zip(decoded) {
            let row = row.expect(operation);
            // SQL membership has no ledger insertion-order contract. Compare
            // every complete structured key, retaining duplicate cardinality.
            let mut actual = row.reads.iter().collect::<Vec<_>>();
            let mut expected = reads.iter().collect::<Vec<_>>();
            actual.sort_unstable();
            expected.sort_unstable();
            assert_eq!(
                actual, expected,
                "{operation}: exact labels, questions and digests"
            );
            assert_eq!(
                row.read_set_digest,
                *read_set_digest(reads).digest().as_bytes()
            );
            assert_eq!(
                verify(&fresh, &fresh, &row.reads),
                ReadVerdict::Unchanged,
                "{operation}"
            );
        }
        let after = production_derivation_counters(&fresh);
        eprintln!("fresh Rust derivation counters after replay: {after:?}");
        // Replay itself must reconstruct every outer and nested recipe.
        for ((kind, before), (_, after)) in before.iter().zip(&after) {
            assert!(
                after.recomputed > before.recomputed,
                "fresh owner {kind}: before {before:?}, after {after:?}"
            );
        }
        // Keep the fixture's TempDir alive, but release every analyzer/store
        // owner before the separate process opens the persisted filesystem.
        drop(fresh);
        drop(fresh_budget);
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "engine_tests::rust_derivation_replay::tests::production_derivation_receipts_reopen_under_a_fresh_owner",
                "--nocapture",
            ])
            .env(CHILD_ROOT, project.root())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "child status {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
            output.status
        );
        assert!(
            stdout.lines().any(|line| line == CHILD_SUCCESS),
            "child success marker missing\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        assert!(
            stdout.lines().any(|line| line
                .starts_with("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured;")),
            "child must execute exactly one test\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        eprintln!("persisted replay child stdout:\n{stdout}\nstderr:\n{stderr}");
    }

    // Hard-won: 40457c5a89: token meaning changed without a version bump
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "40457c5a8974: RustUnitInputs token meaning changed without a version bump"
    )]
    fn rust_unit_inputs_v2_persisted_validation() {
        use brokk_bifrost_analysis::analyzer::derivation_host::ReplayResult;
        use brokk_bifrost_semantic::analyzer::semantic::derivation::{
            DerivationKindId, DerivationQuestion,
        };
        use std::collections::BTreeSet;
        let project = InlineTestProject::new()
            .file("Cargo.toml", "[workspace]\nmembers=['a','b']\nresolver='2'\n")
            .file("a/Cargo.toml", "[package]\nname='a'\nversion='0.1.0'\nedition='2021'\n[features]\nextra=[]\n")
            .file("b/Cargo.toml", "[package]\nname='b'\nversion='0.1.0'\nedition='2021'\n[dependencies]\na={path='../a'}\n")
            .file("a/src/lib.rs", "#[cfg(feature=\"extra\")] pub fn extra() {}\npub fn a() {}\n")
            .file("b/src/lib.rs", "pub fn b() {}\n")
            .build();
        let base = listed_analyzer(&project);
        let (route_reads, complete, _) = record(&project, &base);
        assert!(complete);
        let subject = route_reads.iter().find_map(|r| match r {
            ReadKey::Lookup { kind: LookupKind::Derivation(k), question: brokk_bifrost_analysis::analyzer::read_ledger::LookupQuestion::Derivation(q), .. }
                if k.0 == "derivation:rust_unit_routes:v1" => q.subject,
            _ => None,
        }).expect("route unit");
        let question = DerivationQuestion {
            language: Some(Language::Rust),
            subject: Some(subject),
            rel_path: None,
            name: None,
        };
        fn host(
            analyzer: &WorkspaceAnalyzer,
        ) -> &brokk_bifrost_analysis::analyzer::derivation_host::AnalyzerDerivations {
            let WorkspaceAnalyzer::Multi(multi) = analyzer else {
                panic!("Rust delegate")
            };
            multi
                .delegates()
                .get(&Language::Rust)
                .unwrap()
                .analyzer()
                .snapshot_caches()
                .unwrap()
                .derivations()
        }
        let kind = DerivationKindId("derivation:rust_unit_inputs:v2");
        let ReplayResult::Identity(identity) = host(&base).replay(base.analyzer(), kind, &question)
        else {
            panic!("v2 replay")
        };
        let read = ReadKey::Lookup {
            kind: LookupKind::Derivation(kind),
            question: brokk_bifrost_analysis::analyzer::read_ledger::LookupQuestion::Derivation(
                question.clone(),
            ),
            digest: identity.0,
        };
        let key = production_receipt_key("unit-inputs-v2");
        base.store()
            .unwrap()
            .publish_policy_units(vec![PolicyUnitRow {
                seed_parse_variant: None,
                key: key.clone(),
                product_kind: "rows".into(),
                product: "{\"rows\":[]}".into(),
                read_set_digest: *read_set_digest(std::slice::from_ref(&read))
                    .digest()
                    .as_bytes(),
                reads: vec![read],
                snapshots: vec![[1; 32]],
            }])
            .unwrap();
        let loaded = base
            .store()
            .unwrap()
            .policy_units_for_keys(&[key])
            .unwrap()
            .remove(0)
            .unwrap();
        assert_eq!(verify(&base, &base, &loaded.reads), ReadVerdict::Unchanged);
        std::fs::write(
            project.root().join("b/src/lib.rs"),
            "pub fn b() { let _x = 1; }\n",
        )
        .unwrap();
        let head = base.update(&BTreeSet::from([project.file("b/src/lib.rs")]));
        let before = host(&head).counters(kind).recomputed;
        let repeated_reads = [loaded.reads.clone(), loaded.reads.clone()].concat();
        assert_eq!(
            verify(&base, &head, &repeated_reads),
            ReadVerdict::Unchanged
        );
        let count = host(&head).counters(kind).recomputed - before;
        eprintln!("RustUnitInputs recomputes in warm request: {count}");
        assert_eq!(count, 1);
        // Historical ledgers decode, but v1 has no registered computation and
        // cannot certify a consumer even if its digest equals today's output.
        let old = ReadKey::Lookup {
            kind: LookupKind::Derivation(DerivationKindId("derivation:rust_unit_inputs:v1")),
            question: brokk_bifrost_analysis::analyzer::read_ledger::LookupQuestion::Derivation(
                question.clone(),
            ),
            digest: identity.0,
        };
        let old_key = production_receipt_key("unit-inputs-v1");
        base.store()
            .unwrap()
            .publish_policy_units(vec![PolicyUnitRow {
                seed_parse_variant: None,
                key: old_key.clone(),
                product_kind: "rows".into(),
                product: "{\"rows\":[]}".into(),
                read_set_digest: *read_set_digest(std::slice::from_ref(&old))
                    .digest()
                    .as_bytes(),
                reads: vec![old],
                snapshots: vec![[1; 32]],
            }])
            .unwrap();
        let old_loaded = base
            .store()
            .unwrap()
            .policy_units_for_keys(&[old_key])
            .unwrap()
            .remove(0)
            .unwrap();
        assert_ne!(
            verify(&base, &head, &old_loaded.reads),
            ReadVerdict::Unchanged
        );
        // A consumer whose historical ledger misses must recompute with v2.
        let before = host(&head).counters(kind).recomputed;
        assert_eq!(
            host(&head).replay(head.analyzer(), kind, &question),
            ReplayResult::Identity(identity)
        );
        assert_eq!(host(&head).counters(kind).recomputed - before, 1);
        assert_eq!(
            host(&head)
                .counters(DerivationKindId("derivation:rust_unit_inputs:v1"))
                .recomputed,
            0
        );
        let source = std::fs::read(project.root().join("a/src/lib.rs")).unwrap();
        let manifest = std::fs::read(project.root().join("a/Cargo.toml")).unwrap();
        let sibling_manifest = std::fs::read(project.root().join("b/Cargo.toml")).unwrap();
        std::fs::write(project.root().join("b/Cargo.toml"), "[package]\nname='b'\nversion='0.1.0'\nedition='2021'\n[dependencies]\na={path='../a',features=['extra']}\n").unwrap();
        let enabled = head.update(&BTreeSet::from([project.file("b/Cargo.toml")]));
        // A workspace member already activates every declared feature, and a
        // sibling's manifest is not an input to the selected unit. Feature
        // projection invalidation is covered by
        // rust_feature_projection_tracks_consumers_and_config_candidates.
        assert_eq!(
            verify(&base, &enabled, &loaded.reads),
            ReadVerdict::Unchanged
        );
        assert_eq!(
            source,
            std::fs::read(project.root().join("a/src/lib.rs")).unwrap()
        );
        assert_eq!(
            manifest,
            std::fs::read(project.root().join("a/Cargo.toml")).unwrap()
        );
        std::fs::write(project.root().join("b/Cargo.toml"), sibling_manifest).unwrap();
        std::fs::write(
            project.root().join("a/Cargo.toml"),
            [manifest.as_slice(), b"\n# unrelated comment\n"].concat(),
        )
        .unwrap();
        let edited = head.update(&BTreeSet::from([project.file("a/Cargo.toml")]));
        assert_ne!(
            verify(&base, &edited, &loaded.reads),
            ReadVerdict::Unchanged,
            "manifest OID conservatively invalidates"
        );
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
                models:
                    brokk_bifrost_analysis::analyzer::i_analyzer::current_model_set_read_digest(
                        head.analyzer(),
                    )
                    .expect("fixture model authorities are coherent"),
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
        let budget = RetentionBudget::for_test_capacity(1_000_000);
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

    #[test]
    fn rust_inverse_receipt_revalidates_a_not_supplied_source_listing() {
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::operation_fixture_support::MutableGenerationProject;
        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
        use brokk_bifrost_core::analyzer::project::{
            Project, WorkspaceFileOmission, WorkspaceFileOmissionReason,
        };
        use brokk_bifrost_core::retention_budget::RetentionBudget;
        use brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationKindId;
        use std::collections::BTreeSet;
        use std::path::PathBuf;

        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[workspace]\nmembers=['app','core']\nresolver='2'\n",
            )
            .file(
                "app/Cargo.toml",
                "[package]\nname='app'\nversion='0.1.0'\nedition='2021'\n[dependencies]\ncore={path='../core'}\n",
            )
            .file(
                "core/Cargo.toml",
                "[package]\nname='core'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file("core/src/lib.rs", "pub fn target() {}\n")
            .file("app/src/lib.rs", "pub fn caller() { core::target(); }\n")
            .build();
        let root = fixture.root().to_path_buf();
        let listing_project = Arc::new(MutableGenerationProject::new(&root, Language::Rust));
        listing_project.set_omissions(Vec::new());
        let project: Arc<dyn Project> = listing_project.clone();
        let budget = RetentionBudget::for_test_capacity(64 * 1024 * 1024);
        let base = WorkspaceAnalyzer::build_persisted_with_budget(
            project,
            AnalyzerConfig::default(),
            &budget,
        )
        .unwrap();
        let WorkspaceAnalyzer::Multi(multi) = &base else {
            panic!("Rust delegate")
        };
        let delegate = multi.delegates().get(&Language::Rust).unwrap().analyzer();
        let rust = (delegate as &dyn std::any::Any)
            .downcast_ref::<RustAnalyzer>()
            .unwrap();
        let core = fixture.file("core/src/lib.rs");
        let app = fixture.file("app/src/lib.rs");
        let derivations = delegate.snapshot_caches().unwrap().derivations();
        let selected_known_kind = DerivationKindId("derivation:rust_selected_units_known:v1");
        let selected_known_before = derivations.counters(selected_known_kind);
        let ledger = Arc::new(ReadLedger::new());
        let answer = {
            let _scope = AnalyzerQueryScope::with_read_ledger(base.analyzer(), ledger.clone());
            rust.files_that_can_reference_target_of(&core, None)
                .unwrap()
        };
        assert!(answer.complete, "{answer:?}; reads: {:#?}", ledger.keys());
        assert!(answer.value.contains(&app), "{answer:?}");
        assert_eq!(ledger.persistence_refusals(), 0, "{:#?}", ledger.keys());
        let reads = ledger.publishable_keys().expect("complete inverse receipt");
        assert!(!reads.is_empty(), "{reads:#?}");
        let target_reachability_kind = DerivationKindId("derivation:rust_target_reachability:v2");
        assert!(
            reads.iter().any(|key| matches!(
                key,
                ReadKey::Lookup {
                    kind: LookupKind::Derivation(kind),
                    ..
                } if *kind == target_reachability_kind
            )),
            "outer TargetReachability read missing; full reads: {reads:#?}"
        );
        let selected_known_after = derivations.counters(selected_known_kind);
        assert!(
            selected_known_after.recomputed > selected_known_before.recomputed,
            "SelectedUnitsKnown was not filled by the public inverse call: before={selected_known_before:?}, after={selected_known_after:?}, reads={reads:#?}"
        );
        let digest = StableDigest::sha256(b"rust-inverse-listing-staleness");
        let key = PolicyUnitRowKey {
            policy_semantic_hash: digest.to_string(),
            family: "match".into(),
            partition: PolicyUnitPartitionRow::Whole,
            configuration_fingerprint: digest.to_string(),
            active_model_set_hash: digest.to_string(),
            engine_epoch: digest.to_string(),
        };
        let store = base.store().unwrap();
        store
            .publish_policy_units(vec![PolicyUnitRow {
                seed_parse_variant: None,
                key: key.clone(),
                product_kind: "rows".into(),
                product: "{\"rows\":[]}".into(),
                read_set_digest: *read_set_digest(&reads).digest().as_bytes(),
                reads: reads.clone(),
                snapshots: vec![[2; 32]],
            }])
            .unwrap();
        let loaded = store
            .policy_units_for_keys(std::slice::from_ref(&key))
            .unwrap()
            .remove(0)
            .expect("persisted inverse receipt");
        let mut loaded_keys = loaded.reads.iter().collect::<Vec<_>>();
        let mut captured_keys = reads.iter().collect::<Vec<_>>();
        loaded_keys.sort_unstable();
        captured_keys.sort_unstable();
        assert_eq!(loaded_keys, captured_keys, "full persisted key multiset");
        assert_eq!(
            loaded.read_set_digest,
            *read_set_digest(&reads).digest().as_bytes(),
            "persisted receipt digest"
        );

        let visible_files_before = listing_project.all_files().unwrap();
        let cargo_bytes_before = ["Cargo.toml", "app/Cargo.toml", "core/Cargo.toml"]
            .map(|path| std::fs::read(root.join(path)).unwrap());
        listing_project.set_omissions(vec![WorkspaceFileOmission {
            path: PathBuf::from("core/src/lib.rs"),
            reason: WorkspaceFileOmissionReason::NotSupplied,
        }]);
        let head = base.update(&BTreeSet::new());
        assert_eq!(listing_project.all_files().unwrap(), visible_files_before);
        assert_eq!(
            ["Cargo.toml", "app/Cargo.toml", "core/Cargo.toml"]
                .map(|path| std::fs::read(root.join(path)).unwrap()),
            cargo_bytes_before,
            "listing-only mutation changed Cargo bytes"
        );
        let head_row = head
            .store()
            .unwrap()
            .policy_units_for_keys(std::slice::from_ref(&key))
            .unwrap()
            .remove(0)
            .expect("stored inverse receipt remains available after update");
        let mut head_keys = head_row.reads.iter().collect::<Vec<_>>();
        head_keys.sort_unstable();
        let direct_keys = head_row
            .reads
            .iter()
            .filter(|key| {
                !matches!(
                    key,
                    ReadKey::Lookup {
                        kind: LookupKind::Derivation(_),
                        ..
                    }
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        eprintln!("stored inverse receipt: {reads:#?}; direct isolation keys: {direct_keys:#?}");
        assert_eq!(
            head_keys, captured_keys,
            "full updated stored key multiset; reads={reads:#?}; direct keys={direct_keys:#?}"
        );
        assert_eq!(
            head_row.read_set_digest,
            *read_set_digest(&reads).digest().as_bytes(),
            "updated stored receipt digest; reads={reads:#?}; direct keys={direct_keys:#?}"
        );
        for direct_key in &direct_keys {
            let verdict = verify(&base, &head, std::slice::from_ref(direct_key));
            assert_eq!(
                verdict,
                ReadVerdict::Unchanged,
                "non-derivation key moved: {direct_key:?}; direct keys={direct_keys:#?}; full reads={reads:#?}; full verdict={:?}",
                verify(&base, &head, &head_row.reads)
            );
        }
        let verdict = verify(&base, &head, &head_row.reads);
        let changed = verdict.changed().unwrap_or_else(|| {
            panic!(
                "full inverse receipt did not stale from the changed child input: reads={reads:#?}; direct keys={direct_keys:#?}; verdict={verdict:?}"
            )
        });
        assert!(
            matches!(
                &changed.key,
                ReadKey::Lookup {
                    kind: LookupKind::Derivation(_),
                    ..
                }
            ) && matches!(
                &changed.reason,
                brokk_bifrost_analysis::analyzer::invalidation::InvalidationReason::DependencyFingerprintChanged { .. }
            ),
            "receipt changed without a recomputed derivation answer changing: changed={changed:?}; reads={reads:#?}; direct keys={direct_keys:#?}"
        );
        let head_ledger = Arc::new(ReadLedger::new());
        let head_answer = {
            let WorkspaceAnalyzer::Multi(head_multi) = &head else {
                panic!("Rust delegate after listing update")
            };
            let head_delegate = head_multi
                .delegates()
                .get(&Language::Rust)
                .unwrap()
                .analyzer();
            let head_rust = (head_delegate as &dyn std::any::Any)
                .downcast_ref::<RustAnalyzer>()
                .unwrap();
            let _scope = AnalyzerQueryScope::with_read_ledger(head.analyzer(), head_ledger.clone());
            head_rust
                .files_that_can_reference_target_of(&core, None)
                .unwrap()
        };
        assert!(
            !head_answer.complete,
            "head inverse remained complete: answer={head_answer:?}; reads={reads:#?}; direct keys={direct_keys:#?}; baseline receipt verdict={verdict:?}"
        );
    }

    #[test]
    fn rust_inverse_receipt_revalidates_selected_module_membership() {
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::operation_fixture_support::MutableGenerationProject;
        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
        use brokk_bifrost_core::analyzer::project::Project;
        use brokk_bifrost_core::retention_budget::RetentionBudget;
        use brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationKindId;
        use std::collections::BTreeSet;

        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[workspace]\nmembers=['app','core']\nresolver='2'\n",
            )
            .file(
                "app/Cargo.toml",
                "[package]\nname='app'\nversion='0.1.0'\nedition='2021'\n[dependencies]\ncore={path='../core'}\n",
            )
            .file(
                "core/Cargo.toml",
                "[package]\nname='core'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file("core/src/lib.rs", "pub fn target() {}\n")
            .file("app/src/lib.rs", "#[path=\"left.rs\"] mod chosen;\n")
            .file(
                "app/src/left.rs",
                "pub fn caller() { core::target(); }\n",
            )
            .file(
                "app/src/right.rs",
                "pub fn caller() { core::target(); }\n",
            )
            .build();
        let root = fixture.root().to_path_buf();
        let listing_project = Arc::new(MutableGenerationProject::new(&root, Language::Rust));
        listing_project.set_omissions(Vec::new());
        let project: Arc<dyn Project> = listing_project.clone();
        let budget = RetentionBudget::for_test_capacity(64 * 1024 * 1024);
        let base = WorkspaceAnalyzer::build_persisted_with_budget(
            project,
            AnalyzerConfig::default(),
            &budget,
        )
        .unwrap();
        let WorkspaceAnalyzer::Multi(multi) = &base else {
            panic!("Rust delegate")
        };
        let delegate = multi.delegates().get(&Language::Rust).unwrap().analyzer();
        let rust = (delegate as &dyn std::any::Any)
            .downcast_ref::<RustAnalyzer>()
            .unwrap();
        let core = fixture.file("core/src/lib.rs");
        let app_lib = fixture.file("app/src/lib.rs");
        let app_lib_path = root.join("app/src/lib.rs");
        let left = fixture.file("app/src/left.rs");
        let right = fixture.file("app/src/right.rs");
        let derivations = delegate.snapshot_caches().unwrap().derivations();
        let inputs_kind = DerivationKindId("derivation:rust_unit_inputs:v2");
        let inputs_before = derivations.counters(inputs_kind);
        let ledger = Arc::new(ReadLedger::new());
        let base_answer = {
            let _scope = AnalyzerQueryScope::with_read_ledger(base.analyzer(), ledger.clone());
            rust.files_that_can_reference_target_of(&core, None)
                .unwrap()
        };
        assert!(
            base_answer.complete,
            "base inverse incomplete: answer={base_answer:?}; reads={:#?}",
            ledger.keys()
        );
        assert!(
            base_answer.value.contains(&left) && !base_answer.value.contains(&right),
            "base inverse did not select only left.rs: answer={base_answer:?}; reads={:#?}",
            ledger.keys()
        );
        assert_eq!(ledger.persistence_refusals(), 0, "{:#?}", ledger.keys());
        let reads = ledger
            .publishable_keys()
            .expect("complete inverse receipt with persistable reads");
        assert!(!reads.is_empty(), "empty inverse receipt: {reads:#?}");
        let inputs_after_base = derivations.counters(inputs_kind);
        assert!(
            inputs_after_base.recomputed > inputs_before.recomputed,
            "public inverse did not recompute RustUnitInputs: before={inputs_before:?}; after={inputs_after_base:?}; reads={reads:#?}"
        );

        let digest = StableDigest::sha256(b"rust-inverse-module-membership-staleness");
        let key = PolicyUnitRowKey {
            policy_semantic_hash: digest.to_string(),
            family: "match".into(),
            partition: PolicyUnitPartitionRow::Whole,
            configuration_fingerprint: digest.to_string(),
            active_model_set_hash: digest.to_string(),
            engine_epoch: digest.to_string(),
        };
        let store = base.store().unwrap();
        store
            .publish_policy_units(vec![PolicyUnitRow {
                seed_parse_variant: None,
                key: key.clone(),
                product_kind: "rows".into(),
                product: "{\"rows\":[]}".into(),
                read_set_digest: *read_set_digest(&reads).digest().as_bytes(),
                reads: reads.clone(),
                snapshots: vec![[3; 32]],
            }])
            .unwrap();
        let loaded = store
            .policy_units_for_keys(std::slice::from_ref(&key))
            .unwrap()
            .remove(0)
            .expect("persisted full inverse receipt");
        let mut loaded_keys = loaded.reads.iter().collect::<Vec<_>>();
        let mut captured_keys = reads.iter().collect::<Vec<_>>();
        loaded_keys.sort_unstable();
        captured_keys.sort_unstable();
        assert_eq!(loaded_keys, captured_keys, "persisted full receipt keys");
        assert_eq!(
            loaded.read_set_digest,
            *read_set_digest(&reads).digest().as_bytes(),
            "persisted full receipt digest"
        );

        let files_before = listing_project.all_files().unwrap();
        let cargo_paths = ["Cargo.toml", "app/Cargo.toml", "core/Cargo.toml"];
        let cargo_bytes_before = cargo_paths.map(|path| std::fs::read(root.join(path)).unwrap());
        let original_lib = std::fs::read_to_string(&app_lib_path).unwrap();
        let changed_lib = original_lib.replace("left.rs", "right.rs");
        assert_ne!(changed_lib, original_lib);
        std::fs::write(&app_lib_path, changed_lib).unwrap();
        let head = base.update(&BTreeSet::from([app_lib.clone()]));
        assert_eq!(
            listing_project.all_files().unwrap(),
            files_before,
            "module selection edit changed listed paths"
        );
        assert_eq!(
            cargo_paths.map(|path| std::fs::read(root.join(path)).unwrap()),
            cargo_bytes_before,
            "module selection edit changed Cargo manifest bytes"
        );

        let head_ledger = Arc::new(ReadLedger::new());
        let head_answer = {
            let WorkspaceAnalyzer::Multi(head_multi) = &head else {
                panic!("Rust delegate after source update")
            };
            let head_delegate = head_multi
                .delegates()
                .get(&Language::Rust)
                .unwrap()
                .analyzer();
            let head_rust = (head_delegate as &dyn std::any::Any)
                .downcast_ref::<RustAnalyzer>()
                .unwrap();
            let head_inputs_before = head_delegate
                .snapshot_caches()
                .unwrap()
                .derivations()
                .counters(inputs_kind);
            let _scope = AnalyzerQueryScope::with_read_ledger(head.analyzer(), head_ledger.clone());
            let answer = head_rust
                .files_that_can_reference_target_of(&core, None)
                .unwrap();
            let head_inputs_after = head_delegate
                .snapshot_caches()
                .unwrap()
                .derivations()
                .counters(inputs_kind);
            assert!(
                head_inputs_after.recomputed > head_inputs_before.recomputed,
                "head public inverse did not recompute RustUnitInputs: before={head_inputs_before:?}; after={head_inputs_after:?}; reads={:#?}",
                head_ledger.keys()
            );
            answer
        };
        assert!(
            head_answer.complete,
            "head inverse incomplete: answer={head_answer:?}; reads={:#?}",
            head_ledger.keys()
        );
        assert!(
            head_answer.value.contains(&right) && !head_answer.value.contains(&left),
            "head inverse did not exchange the selected potential caller: answer={head_answer:?}; reads={:#?}",
            head_ledger.keys()
        );
        assert_eq!(
            head_ledger.persistence_refusals(),
            0,
            "{:#?}",
            head_ledger.keys()
        );
        let head_reads = head_ledger
            .publishable_keys()
            .expect("complete head inverse receipt with persistable reads");
        assert!(!head_reads.is_empty(), "empty head inverse receipt");

        let head_row = head
            .store()
            .unwrap()
            .policy_units_for_keys(std::slice::from_ref(&key))
            .unwrap()
            .remove(0)
            .expect("persisted inverse receipt remains available after source update");
        let mut head_row_keys = head_row.reads.iter().collect::<Vec<_>>();
        head_row_keys.sort_unstable();
        assert_eq!(
            head_row_keys, captured_keys,
            "stored full receipt key multiset changed; base reads={reads:#?}; head query reads={head_reads:#?}"
        );
        assert_eq!(
            head_row.read_set_digest,
            *read_set_digest(&reads).digest().as_bytes(),
            "stored full receipt digest changed; base reads={reads:#?}; head query reads={head_reads:#?}"
        );
        let direct_keys = loaded
            .reads
            .iter()
            .filter(|key| {
                !matches!(
                    key,
                    ReadKey::Lookup {
                        kind: LookupKind::Derivation(_),
                        ..
                    }
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        eprintln!(
            "base full inverse receipt: {reads:#?}; head public reads: {head_reads:#?}; direct isolation keys: {direct_keys:#?}"
        );
        for direct_key in &direct_keys {
            let direct_verdict = verify(&base, &head, std::slice::from_ref(direct_key));
            assert_eq!(
                direct_verdict,
                ReadVerdict::Unchanged,
                "non-derivation direct key changed: {direct_key:?}; all direct keys={direct_keys:#?}; base reads={reads:#?}; head reads={head_reads:#?}; full verdict={:?}",
                verify(&base, &head, &loaded.reads)
            );
        }
        let verdict = verify(&base, &head, &loaded.reads);
        let changed = verdict.changed().unwrap_or_else(|| {
            panic!(
                "full persisted inverse receipt did not stale after selected module membership changed: verdict={verdict:?}; direct keys={direct_keys:#?}; base reads={reads:#?}; head reads={head_reads:#?}; base answer={base_answer:?}; head answer={head_answer:?}"
            )
        });
        assert!(
            matches!(
                &changed.key,
                ReadKey::Lookup {
                    kind: LookupKind::Derivation(_),
                    ..
                }
            ) && matches!(
                &changed.reason,
                brokk_bifrost_analysis::analyzer::invalidation::InvalidationReason::DependencyFingerprintChanged { .. }
            ),
            "full receipt changed for the wrong cause: changed={changed:?}; direct keys={direct_keys:#?}; base reads={reads:#?}; head reads={head_reads:#?}; base answer={base_answer:?}; head answer={head_answer:?}"
        );
    }
}
