#[cfg(test)]
mod js_ts_extraction_tests {
    use brokk_bifrost_analysis::analyzer::semantic::DependencyFingerprint;

    use brokk_bifrost_analysis::IAnalyzer;
    use brokk_bifrost_analysis::analyzer::semantic::ConfigurationFingerprint;
    use brokk_bifrost_analysis::analyzer::semantic::ids::AdapterSemanticsVersion;
    use brokk_bifrost_analysis::analyzer::semantic::ids::SemanticArtifactKey;
    use brokk_bifrost_analysis::analyzer::semantic::ids::SourceRevision;
    use brokk_bifrost_analysis::analyzer::semantic::ir::artifact::ProcedureSemantics;
    use brokk_bifrost_analysis::analyzer::semantic::ir::artifact::SemanticArtifact;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticOutcome;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticProviderError;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticWork;
    use brokk_bifrost_analysis::analyzer::semantic::service::CompleteSemanticArtifactCache;
    use brokk_bifrost_analysis::analyzer::semantic::service::ProgramSemanticsLowerer;
    use brokk_bifrost_analysis::analyzer::semantic::service::SemanticAdapterIdentity;
    use brokk_bifrost_analysis::analyzer::semantic::service::SemanticCacheRevivalCensus;
    use brokk_bifrost_analysis::analyzer::semantic::service::current_artifact_source_with_lowerer;
    use brokk_bifrost_analysis::analyzer::semantic::service::materialize_with_lowerer;
    use brokk_bifrost_analysis::analyzer::semantic::service::retained_artifact_base_bytes;
    use brokk_bifrost_analysis::analyzer::semantic::service::retained_artifact_bytes;
    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;
    use brokk_bifrost_core::analyzer::model::ProjectFile;
    use std::sync::Arc;

    use brokk_bifrost_analysis::analyzer::semantic::ProcedureSemanticsParts;
    use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
    use std::collections::BTreeSet;
    use std::sync::Condvar;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use brokk_bifrost_analysis::analyzer::semantic::service::*;

    use brokk_bifrost_analysis::analyzer::semantic::SemanticArtifactCollector;

    use brokk_bifrost_analysis::analyzer::semantic::SemanticBudget;

    use brokk_bifrost_js_ts_analysis::analyzer::typescript::TypescriptAdapter;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::project::OverlayProject;

    use brokk_bifrost_core::analyzer::project::Project;

    use brokk_bifrost_core::analyzer::project::TestProject;

    use brokk_bifrost_core::test_support::write_file;
    #[derive(Clone, Copy)]
    enum FakeMode {
        Complete,
        PartialThenComplete,
        Cancel,
        CancelUnknownPartial,
        CancelWithPartial,
    }
    struct FakeLowerer {
        calls: AtomicUsize,
        mode: FakeMode,
    }
    impl FakeLowerer {
        fn new(mode: FakeMode) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                mode,
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }
    impl ProgramSemanticsLowerer for FakeLowerer {
        fn identity(&self) -> SemanticAdapterIdentity {
            SemanticAdapterIdentity {
                adapter: AdapterSemanticsVersion::hash_bytes("fake-typescript", b"v1")
                    .expect("adapter name"),
                configuration: ConfigurationFingerprint::hash_bytes(b"fake-config"),
                dependencies: DependencyFingerprint::hash_bytes(b"fake-dependencies"),
            }
        }

        fn lower(
            &self,
            _file: &ProjectFile,
            _prepared: &PreparedSyntaxTree,
            _budget: &SemanticBudget,
            cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
        ) -> Result<SemanticOutcome<Vec<ProcedureSemanticsParts>>, SemanticProviderError> {
            let call = self.calls.fetch_add(1, Ordering::Relaxed);
            match self.mode {
                FakeMode::Complete => Ok(SemanticOutcome::Complete {
                    value: Vec::new(),
                    work: SemanticWork::default(),
                }),
                FakeMode::PartialThenComplete if call == 0 => Ok(SemanticOutcome::Unknown {
                    partial: Some(Vec::new()),
                    work: SemanticWork::default(),
                }),
                FakeMode::PartialThenComplete => Ok(SemanticOutcome::Complete {
                    value: Vec::new(),
                    work: SemanticWork::default(),
                }),
                FakeMode::Cancel => {
                    cancellation.cancel();
                    Ok(SemanticOutcome::Complete {
                        value: Vec::new(),
                        work: SemanticWork::default(),
                    })
                }
                FakeMode::CancelUnknownPartial => {
                    cancellation.cancel();
                    Ok(SemanticOutcome::Unknown {
                        partial: Some(Vec::new()),
                        work: SemanticWork::default(),
                    })
                }
                FakeMode::CancelWithPartial => Ok(SemanticOutcome::Cancelled {
                    partial: Some(Vec::new()),
                    work: SemanticWork::default(),
                }),
            }
        }
    }
    struct IdentityOnlyLowerer(SemanticAdapterIdentity);
    impl ProgramSemanticsLowerer for IdentityOnlyLowerer {
        fn identity(&self) -> SemanticAdapterIdentity {
            self.0.clone()
        }

        fn lower(
            &self,
            _file: &ProjectFile,
            _prepared: &PreparedSyntaxTree,
            _budget: &SemanticBudget,
            _cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
        ) -> Result<SemanticOutcome<Vec<ProcedureSemanticsParts>>, SemanticProviderError> {
            panic!("artifact-key lookup must not invoke semantic lowering")
        }
    }
    struct BlockingLowerer {
        calls: AtomicUsize,
        entered: mpsc::Sender<()>,
        released: Mutex<bool>,
        release: Condvar,
    }
    impl BlockingLowerer {
        fn new(entered: mpsc::Sender<()>) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                entered,
                released: Mutex::new(false),
                release: Condvar::new(),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }

        fn release(&self) {
            *self
                .released
                .lock()
                .expect("blocking lowerer mutex poisoned") = true;
            self.release.notify_all();
        }
    }
    impl ProgramSemanticsLowerer for BlockingLowerer {
        fn identity(&self) -> SemanticAdapterIdentity {
            SemanticAdapterIdentity {
                adapter: AdapterSemanticsVersion::hash_bytes("blocking-typescript", b"v1")
                    .expect("adapter name"),
                configuration: ConfigurationFingerprint::hash_bytes(b"blocking-config"),
                dependencies: DependencyFingerprint::hash_bytes(b"blocking-dependencies"),
            }
        }

        fn lower(
            &self,
            _file: &ProjectFile,
            _prepared: &PreparedSyntaxTree,
            _budget: &SemanticBudget,
            _cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
        ) -> Result<SemanticOutcome<Vec<ProcedureSemanticsParts>>, SemanticProviderError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.entered
                .send(())
                .expect("blocking lowerer entry receiver");
            let mut released = self
                .released
                .lock()
                .expect("blocking lowerer mutex poisoned");
            while !*released {
                released = self
                    .release
                    .wait(released)
                    .expect("blocking lowerer mutex poisoned while waiting");
            }
            Ok(SemanticOutcome::Complete {
                value: Vec::new(),
                work: SemanticWork::default(),
            })
        }
    }
    fn analyzer(root: &std::path::Path) -> TreeSitterAnalyzer<TypescriptAdapter> {
        TreeSitterAnalyzer::new(
            Arc::new(TestProject::new(root.to_path_buf(), Language::TypeScript)),
            TypescriptAdapter,
        )
    }
    fn current_artifact_key_with_lowerer(
        analyzer: &TreeSitterAnalyzer<TypescriptAdapter>,
        lowerer: &dyn ProgramSemanticsLowerer,
        file: &ProjectFile,
        max_source_bytes: usize,
    ) -> Result<Option<SemanticArtifactKey>, SemanticProviderError> {
        current_artifact_source_with_lowerer(analyzer, lowerer, file, max_source_bytes)
            .map(|snapshot| snapshot.map(|snapshot| snapshot.key().clone()))
    }
    fn materialize(
        analyzer: &TreeSitterAnalyzer<TypescriptAdapter>,
        cache: &CompleteSemanticArtifactCache,
        lowerer: &dyn ProgramSemanticsLowerer,
        file: &ProjectFile,
        budget: &mut SemanticBudget,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> SemanticOutcome<Arc<SemanticArtifact>> {
        materialize_with_lowerer(
            analyzer,
            cache,
            lowerer,
            file,
            &mut SemanticRequest::new(budget, cancellation),
        )
        .expect("materialization")
    }
    fn wait_for_waiter(cache: &CompleteSemanticArtifactCache) {
        brokk_bifrost_core::test_support::wait_for_nonzero_count(
            || cache.waiting_count(),
            "same-key request did not enter the single-flight wait",
        );
    }
    /// A budget that read the file pays exactly that file once, plus the whole
    /// retained census of the artifact it now holds.
    fn assert_source_and_artifact_charged(
        budget: &SemanticBudget,
        file: &ProjectFile,
        artifact: &SemanticArtifact,
    ) {
        assert_census_charged(
            budget,
            file.read_to_string().expect("fixture source").len(),
            artifact,
        );
    }
    /// A budget served an artifact for a source the workspace already
    /// identified pays the census -- it holds and walks that material -- and no
    /// source bytes at all, because it neither read nor hashed the file.
    fn assert_artifact_charged_without_reading(
        budget: &SemanticBudget,
        artifact: &SemanticArtifact,
    ) {
        assert_census_charged(budget, 0, artifact);
    }
    fn assert_census_charged(
        budget: &SemanticBudget,
        source_bytes: usize,
        artifact: &SemanticArtifact,
    ) {
        let mut retained = budget.used();
        assert_eq!(retained.source_bytes, source_bytes);
        retained.source_bytes = 0;
        assert_eq!(retained, artifact.work());
    }
    /// One artifact's retained census, plus room for `repeats` repeat lookups
    /// and for exactly one read of the source.
    ///
    /// One read's worth of `source_bytes` is deliberate and is what makes the
    /// repeat-charge claim below falsifiable: a second charged read of this
    /// file would exceed the budget rather than pass unnoticed.
    ///
    /// Every limit must be positive, so a census dimension the fixture never
    /// uses still gets one row of headroom; that headroom is far below one
    /// extra census, which is what this test's fail-before depends on.
    fn budget_for_one_census(
        census: SemanticWork,
        source_bytes: usize,
        repeats: usize,
    ) -> SemanticBudget {
        let lane = |value: usize| value.max(1);
        SemanticBudget::new(SemanticWork {
            source_bytes: source_bytes.max(1),
            procedures: lane(census.procedures),
            blocks: lane(census.blocks),
            program_points: lane(census.program_points),
            values: lane(census.values),
            allocations: lane(census.allocations),
            call_sites: lane(census.call_sites),
            memory_locations: lane(census.memory_locations),
            captures: lane(census.captures),
            source_mappings: lane(census.source_mappings),
            evidence: lane(census.evidence),
            gaps: lane(census.gaps),
            events: lane(census.events),
            control_edges: lane(census.control_edges),
            nested_entries: lane(census.nested_entries).saturating_add(repeats),
            owned_text_bytes: lane(census.owned_text_bytes),
        })
        .expect("every limit is positive")
    }
    #[test]
    fn current_artifact_key_tracks_source_adapter_and_configuration_without_lowering() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 1;\n");
        let analyzer = analyzer(&root);
        let identity = |adapter: &[u8], configuration: &[u8], dependencies: &[u8]| {
            IdentityOnlyLowerer(SemanticAdapterIdentity {
                adapter: AdapterSemanticsVersion::hash_bytes("identity-only", adapter)
                    .expect("adapter name"),
                configuration: ConfigurationFingerprint::hash_bytes(configuration),
                dependencies: DependencyFingerprint::hash_bytes(dependencies),
            })
        };

        let baseline_lowerer = identity(b"adapter-v1", b"config-v1", b"dependencies-v1");
        assert_eq!(
            current_artifact_key_with_lowerer(
                &analyzer,
                &baseline_lowerer,
                &file,
                "export const value = 1;\n".len() - 1,
            )
            .expect("bounded key lookup"),
            None
        );
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 0);

        let baseline =
            current_artifact_key_with_lowerer(&analyzer, &baseline_lowerer, &file, usize::MAX)
                .expect("baseline key lookup")
                .expect("baseline key");
        let adapter_changed = current_artifact_key_with_lowerer(
            &analyzer,
            &identity(b"adapter-v2", b"config-v1", b"dependencies-v1"),
            &file,
            usize::MAX,
        )
        .expect("adapter key lookup")
        .expect("adapter key");
        let configuration_changed = current_artifact_key_with_lowerer(
            &analyzer,
            &identity(b"adapter-v1", b"config-v2", b"dependencies-v1"),
            &file,
            usize::MAX,
        )
        .expect("configuration key lookup")
        .expect("configuration key");
        let dependencies_changed = current_artifact_key_with_lowerer(
            &analyzer,
            &identity(b"adapter-v1", b"config-v1", b"dependencies-v2"),
            &file,
            usize::MAX,
        )
        .expect("dependency key lookup")
        .expect("dependency key");

        assert_ne!(baseline, adapter_changed);
        assert_ne!(baseline, configuration_changed);
        assert_ne!(baseline, dependencies_changed);

        file.write("export const value = 2;\n")
            .expect("rewrite fixture");
        let source_changed =
            current_artifact_key_with_lowerer(&analyzer, &baseline_lowerer, &file, usize::MAX)
                .expect("updated source key lookup")
                .expect("updated source key");
        assert_ne!(baseline, source_changed);
        assert_eq!(
            analyzer.prepared_syntax_parse_count_for_test(&file),
            0,
            "freshness identity must not parse source"
        );
    }
    #[test]
    fn current_artifact_source_reuses_atomic_overlay_source_and_revision() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const disk = 0;\n");
        let base: Arc<dyn brokk_bifrost_core::analyzer::project::Project> =
            Arc::new(TestProject::new(root.clone(), Language::TypeScript));
        let overlay = Arc::new(OverlayProject::new(base));
        let source = "export const value = 1;\n";
        assert!(overlay.set(file.abs_path(), source.to_owned()));
        let project_source = overlay
            .read_source_snapshot(&file)
            .expect("first atomic overlay snapshot")
            .into_source();
        let analyzer = TreeSitterAnalyzer::new(
            Arc::clone(&overlay) as Arc<dyn brokk_bifrost_core::analyzer::project::Project>,
            TypescriptAdapter,
        );
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);

        let first = {
            let _scope = AnalyzerQueryScope::new(&analyzer);
            current_artifact_source_with_lowerer(&analyzer, &lowerer, &file, source.len())
                .expect("first artifact source lookup")
                .expect("first artifact source")
        };
        let first_key = first.key().clone();
        let (_, first_source) = first.into_parts();
        assert!(Arc::ptr_eq(&project_source, &first_source));
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 0);

        let artifact = {
            let _scope = AnalyzerQueryScope::new(&analyzer);
            let mut budget = SemanticBudget::default();
            materialize(
                &analyzer,
                &cache,
                &lowerer,
                &file,
                &mut budget,
                &brokk_bifrost_core::cancellation::CancellationToken::default(),
            )
            .available_value()
            .cloned()
            .expect("first overlay artifact")
        };
        assert_eq!(artifact.key(), &first_key);

        // A new overlay revision invalidates the old artifact even when its
        // source bytes (and therefore content identity) are unchanged.
        assert!(overlay.set(file.abs_path(), source.to_owned()));
        let second = {
            let _scope = AnalyzerQueryScope::new(&analyzer);
            current_artifact_source_with_lowerer(&analyzer, &lowerer, &file, source.len())
                .expect("second artifact source lookup")
                .expect("second artifact source")
        };
        assert_eq!(second.source(), source);
        assert_eq!(
            first_key.revision().content(),
            second.key().revision().content()
        );
        assert_ne!(artifact.key(), second.key());

        let _scope = AnalyzerQueryScope::new(&analyzer);
        assert!(
            current_artifact_source_with_lowerer(&analyzer, &lowerer, &file, source.len() - 1,)
                .expect("bounded overlay lookup")
                .is_none()
        );
    }
    #[test]
    fn complete_cache_reuses_arc_but_charges_each_request() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export function main() {}\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);

        let mut first_budget = SemanticBudget::default();
        let first = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut first_budget,
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        );
        let SemanticOutcome::Complete { value: first, .. } = first else {
            panic!("first complete artifact")
        };
        assert_source_and_artifact_charged(&first_budget, &file, &first);

        let mut second_budget = SemanticBudget::default();
        let second = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut second_budget,
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        );
        let SemanticOutcome::Complete { value: second, .. } = second else {
            panic!("cached complete artifact")
        };
        assert!(Arc::ptr_eq(&first, &second));
        // Re-derived: the second request is charged the artifact's census
        // again, because it holds that material too, but not the file's bytes.
        // The first request already derived this content's identity, and the
        // workspace can prove the file has not changed since, so the second
        // request neither reads nor hashes it.
        assert_artifact_charged_without_reading(&second_budget, &second);
        assert_eq!(lowerer.calls(), 1);
        assert_eq!(cache.len(), 1);
    }
    #[test]
    fn semantic_cache_invalidation_witnesses_are_distinct_clone_shared_and_one_shot() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export function main() {}\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::default();

        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: held, .. } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &cancellation,
        ) else {
            panic!("initial complete artifact")
        };

        let cloned_cache = cache.clone();
        cloned_cache.arm_selector_continuation_invalidation_for_test();
        cache.invalidate_evaluation_root_continuation_if_armed_for_test();
        assert_eq!(cache.len(), 1, "the evaluation witness is not armed");
        cache.invalidate_selector_continuation_if_armed_for_test();
        assert_eq!(
            cache.selector_continuation_revival_census_for_test(),
            SemanticCacheRevivalCensus::default()
        );
        assert_eq!(
            cache.evaluation_root_continuation_revival_census_for_test(),
            SemanticCacheRevivalCensus::default()
        );
        assert_eq!(cache.len(), 0);

        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: revived, .. } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &cancellation,
        ) else {
            panic!("revived complete artifact")
        };
        assert!(Arc::ptr_eq(&held, &revived));
        assert_eq!(
            cache.selector_continuation_revival_census_for_test(),
            SemanticCacheRevivalCensus {
                operations: 1,
                distinct_artifacts: 1,
            }
        );
        assert_eq!(
            cache.evaluation_root_continuation_revival_census_for_test(),
            SemanticCacheRevivalCensus::default()
        );

        cache.inner.invalidate_all_for_test();
        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: revived, .. } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &cancellation,
        ) else {
            panic!("same artifact revived a second time")
        };
        assert!(Arc::ptr_eq(&held, &revived));
        assert_eq!(
            cache.selector_continuation_revival_census_for_test(),
            SemanticCacheRevivalCensus {
                operations: 2,
                distinct_artifacts: 1,
            }
        );

        cloned_cache.arm_evaluation_root_continuation_invalidation_for_test();
        cache.invalidate_selector_continuation_if_armed_for_test();
        assert_eq!(cache.len(), 1, "the selector witness is no longer armed");
        cache.invalidate_evaluation_root_continuation_if_armed_for_test();
        assert_eq!(
            cache.selector_continuation_revival_census_for_test(),
            SemanticCacheRevivalCensus {
                operations: 2,
                distinct_artifacts: 1,
            }
        );
        assert_eq!(
            cache.evaluation_root_continuation_revival_census_for_test(),
            SemanticCacheRevivalCensus::default()
        );
        assert_eq!(cache.len(), 0);

        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: revived, .. } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &cancellation,
        ) else {
            panic!("second revived complete artifact")
        };
        assert!(Arc::ptr_eq(&held, &revived));
        assert_eq!(
            cache.selector_continuation_revival_census_for_test(),
            SemanticCacheRevivalCensus {
                operations: 2,
                distinct_artifacts: 1,
            }
        );
        assert_eq!(
            cache.evaluation_root_continuation_revival_census_for_test(),
            SemanticCacheRevivalCensus {
                operations: 1,
                distinct_artifacts: 1,
            }
        );

        cache.invalidate_evaluation_root_continuation_if_armed_for_test();
        assert_eq!(
            cache.selector_continuation_revival_census_for_test(),
            SemanticCacheRevivalCensus {
                operations: 2,
                distinct_artifacts: 1,
            }
        );
        assert_eq!(
            cache.evaluation_root_continuation_revival_census_for_test(),
            SemanticCacheRevivalCensus {
                operations: 1,
                distinct_artifacts: 1,
            }
        );
        assert_eq!(cache.len(), 1);
        assert_eq!(lowerer.calls(), 1);
    }
    /// #2295: one budget pays one artifact's retained census once, however many
    /// complete-artifact cache hits it serves.
    ///
    /// `DispatchOracle::resolve_call` materializes a callee's file once for each
    /// declaration group it resolves, so a request that reaches one file from
    /// many call sites used to be charged that file's whole census once per call
    /// site even though the file was lowered once. A budget sized for the
    /// material the request actually holds then aborted a request that had
    /// performed no new work. Each repeat now pays
    /// one nested-entry lookup unit, which is what a repeat performs: derive
    /// the key, look it up, clone an `Arc`.
    #[test]
    fn one_budget_charges_one_artifact_census_once_however_many_cache_hits() {
        const REPEATS: usize = 8;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let source = "function target(value: number): number { return value; }\n\
             export function main(): number { return target(1); }\n";
        let file = write_file(&root, "src/calls.ts", source);
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer =
            brokk_bifrost_js_ts_analysis::analyzer::js_ts::semantic::JsTsSemanticLowerer::typescript();

        // Lower once against its own budget, so every materialization below is
        // a cache hit and the census is known exactly.
        let mut warming_budget = SemanticBudget::default();
        let SemanticOutcome::Complete {
            value: artifact, ..
        } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut warming_budget,
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        )
        else {
            panic!("the fixture must lower completely")
        };
        let census = artifact.work();
        assert!(
            census.program_points > 1,
            "the fixture must retain enough rows for one census to be measurable: {census:?}"
        );

        let mut budget = budget_for_one_census(census, source.len(), REPEATS);
        for hit in 0..=REPEATS {
            let outcome = materialize(
                &analyzer,
                &cache,
                &lowerer,
                &file,
                &mut budget,
                &brokk_bifrost_core::cancellation::CancellationToken::default(),
            );
            let SemanticOutcome::Complete { value, .. } = outcome else {
                panic!(
                    "cache hit {hit} must not exhaust a budget sized for one census: {outcome:?}"
                )
            };
            assert!(Arc::ptr_eq(&value, &artifact));
        }

        let used = budget.used();
        assert_eq!(
            used.program_points, census.program_points,
            "the census is charged once, not once per hit"
        );
        assert_eq!(used.values, census.values);
        assert_eq!(
            used.nested_entries,
            census.nested_entries + REPEATS,
            "each repeat hit charges exactly one traversal step"
        );
        assert_eq!(
            used.source_bytes, 0,
            "no call re-read or re-hashed a source whose content the workspace \
             had already identified"
        );
        assert_eq!(
            budget.charged_artifact_count(),
            1,
            "one artifact key was charged in this scope"
        );
    }
    /// A fresh budget is a fresh scope: it pays the census again.
    ///
    /// This is what keeps the change coherent with the per-region reset in
    /// `PolicySelectorSession::reset_region_semantic_budget` and the per-batch
    /// reset in `TaintExecutionBudget::reset_per_batch_solve_budget`. Both
    /// replace the budget value, so both start a scope that pays again for the
    /// material it newly pulls in.
    #[test]
    fn a_fresh_budget_pays_the_census_again() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(
            &root,
            "src/calls.ts",
            "export function main(): number { return 1; }\n",
        );
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer =
            brokk_bifrost_js_ts_analysis::analyzer::js_ts::semantic::JsTsSemanticLowerer::typescript();

        // The lowering budget is deliberately not compared against the census:
        // lowering also charges bounded traversal steps that no retained row
        // represents, so it costs more than the artifact it produces.
        let mut lowering_budget = SemanticBudget::default();
        let SemanticOutcome::Complete {
            value: artifact, ..
        } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut lowering_budget,
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        )
        else {
            panic!("the fixture must lower completely")
        };

        for scope in 0..3 {
            let mut budget = SemanticBudget::default();
            assert!(
                materialize(
                    &analyzer,
                    &cache,
                    &lowerer,
                    &file,
                    &mut budget,
                    &brokk_bifrost_core::cancellation::CancellationToken::default(),
                )
                .is_complete()
            );
            // Re-derived: every fresh scope still pays the census, which is
            // what this test is about. It no longer pays the file's bytes,
            // because the lowering scope above already derived this content's
            // identity and no scope after it reads the file.
            assert_artifact_charged_without_reading(&budget, &artifact);
            assert_eq!(
                budget.charged_artifact_count(),
                1,
                "scope {scope} pays for the artifact it holds"
            );
        }
    }
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5113: released semantic allocations kept spending the resident ledger"
    )]
    fn provider_budget_refunds_evicted_artifacts_after_the_last_handle_drops() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/resident.ts", "export const value = 1;\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);
        let mut budget = SemanticBudget::default();
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::default();
        let SemanticOutcome::Complete {
            value: artifact, ..
        } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &cancellation,
        )
        else {
            panic!("complete artifact")
        };
        let work = budget.used();
        let census = artifact.work();
        assert_eq!(budget.resident().nested_entries, census.nested_entries);
        assert_eq!(budget.resident().owned_text_bytes, census.owned_text_bytes);
        let key = artifact.key().clone();
        let prepared_pin = CachedSemanticArtifact::new(&artifact);
        drop(artifact);
        assert_eq!(cache.len(), 1, "the artifact remains in the ready cache");
        assert_eq!(
            budget.resident().owned_text_bytes,
            0,
            "complete-cache and prepared-pool pins alone consume no root allowance"
        );
        let mut continuation = SemanticBudget::new_child(budget.limits(), &budget.scope_snapshot());
        let artifact = cache
            .get_ready(&key, &cancellation)
            .expect("cached artifact");
        continuation
            .charge_complete_artifact(&artifact)
            .expect("new consumer admission");
        assert_eq!(
            continuation.resident().owned_text_bytes,
            census.owned_text_bytes,
            "a cache-only parent identity cannot exempt a continuation's new consumer"
        );
        assert_eq!(
            budget.resident().owned_text_bytes,
            census.owned_text_bytes,
            "a live root handle restores its exact census"
        );
        drop(prepared_pin);
        cache.inner.invalidate_all_for_test();
        assert_eq!(
            cache.len(),
            0,
            "drain Moka invalidation before testing eviction"
        );
        assert_eq!(
            budget.resident().nested_entries,
            census.nested_entries,
            "a live handle still pins the evicted allocation"
        );
        let allocation = Arc::downgrade(&artifact);
        drop(artifact);
        // Logical eviction precedes Moka's epoch-reclamation grace period.
        // Cache-only ownership is already excluded from the resident census.
        brokk_bifrost_core::test_support::wait_for_nonzero_count(
            || {
                assert_eq!(cache.len(), 0);
                usize::from(allocation.strong_count() == 0)
            },
            "evicted semantic allocation did not finish epoch reclamation",
        );
        assert_eq!(budget.resident().nested_entries, 0);
        assert_eq!(budget.resident().owned_text_bytes, 0);
        assert_eq!(
            budget.used(),
            work,
            "eviction does not refund performed work"
        );
        let SemanticOutcome::Complete {
            value: artifact, ..
        } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &cancellation,
        )
        else {
            panic!("re-admitted artifact")
        };
        assert_eq!(
            budget.resident().nested_entries,
            artifact.work().nested_entries
        );
        assert!(budget.used().owned_text_bytes > work.owned_text_bytes);
        let second_cache = CompleteSemanticArtifactCache::default();
        let mut warming_budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: second, .. } = materialize(
            &analyzer,
            &second_cache,
            &lowerer,
            &file,
            &mut warming_budget,
            &cancellation,
        ) else {
            panic!("independent allocation")
        };
        assert_eq!(artifact.key(), second.key());
        assert!(!Arc::ptr_eq(&artifact, &second));
        let hit = materialize(
            &analyzer,
            &second_cache,
            &lowerer,
            &file,
            &mut budget,
            &cancellation,
        );
        assert!(hit.is_complete());
        assert_eq!(
            budget.resident().nested_entries,
            artifact.work().nested_entries + second.work().nested_entries,
            "equal content does not make distinct live allocations free"
        );
        drop(hit);
        let mut tight_limits =
            brokk_bifrost_analysis::analyzer::semantic::SemanticWork::default_limits();
        tight_limits.nested_entries = artifact.work().nested_entries.max(1);
        tight_limits.owned_text_bytes = artifact.work().owned_text_bytes;
        let mut tight = SemanticBudget::new(tight_limits).expect("exact resident grant");
        let first_hit = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut tight,
            &cancellation,
        );
        assert!(first_hit.is_complete());
        let repeated_hit = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut tight,
            &cancellation,
        );
        assert!(
            repeated_hit.is_complete(),
            "a repeat lookup only increments performed work"
        );
        assert_eq!(
            tight.resident().owned_text_bytes,
            tight_limits.owned_text_bytes
        );
        assert!(tight.used().nested_entries > tight.resident().nested_entries);
        budget.release_resident();
        assert_eq!(
            budget.resident().nested_entries,
            0,
            "window close releases its admission even while the shared cache owns the artifact"
        );
    }
    #[test]
    fn complete_cache_capacity_is_retained_bytes_not_entry_count() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let first_file = write_file(&root, "src/first.ts", "export const value = 1;\n");
        let second_file = write_file(&root, "src/other.ts", "export const value = 2;\n");
        let analyzer = analyzer(&root);
        let staging_cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);

        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: first, .. } = materialize(
            &analyzer,
            &staging_cache,
            &lowerer,
            &first_file,
            &mut budget,
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        ) else {
            panic!("first artifact")
        };
        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: second, .. } = materialize(
            &analyzer,
            &staging_cache,
            &lowerer,
            &second_file,
            &mut budget,
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        ) else {
            panic!("second artifact")
        };

        let first_weight = retained_artifact_bytes(first.key(), &first);
        let second_weight = retained_artifact_bytes(second.key(), &second);
        assert_eq!(first_weight, second_weight, "equal-sized fixtures");
        assert!(first_weight > 1);
        let cache = CompleteSemanticArtifactCache::new(first_weight);
        cache.insert(first.key().clone(), Arc::clone(&first));
        cache.insert(second.key().clone(), Arc::clone(&second));

        assert_eq!(cache.len(), 1, "two byte-weighted entries exceed capacity");
    }
    #[test]
    fn analyzer_update_preserves_unchanged_content_keyed_artifacts() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let unchanged = write_file(&root, "src/unchanged.ts", "export const stable = 1;\n");
        let changed = write_file(&root, "src/changed.ts", "export const changing = 1;\n");
        let analyzer = analyzer(&root);
        let lowerer = FakeLowerer::new(FakeMode::Complete);
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: before, .. } = analyzer
            .materialize_semantics_with_lowerer(
                &lowerer,
                &unchanged,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("initial materialization")
        else {
            panic!("initial complete artifact")
        };

        changed
            .write("export const changing = 2;\n")
            .expect("update changed fixture");
        let updated = analyzer.update(&BTreeSet::from([changed]));
        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: after, .. } = updated
            .materialize_semantics_with_lowerer(
                &lowerer,
                &unchanged,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("post-update materialization")
        else {
            panic!("post-update complete artifact")
        };

        assert!(Arc::ptr_eq(&before, &after));
        assert_eq!(lowerer.calls(), 1);
    }
    #[test]
    fn concurrent_same_key_materialization_runs_one_lowerer() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 1;\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::new(1);
        let (entered_tx, entered_rx) = mpsc::channel();
        let lowerer = Arc::new(BlockingLowerer::new(entered_tx));

        let first_analyzer = analyzer.clone();
        let first_cache = cache.clone();
        let first_file = file.clone();
        let first_lowerer = Arc::clone(&lowerer);
        let first = thread::spawn(move || {
            let mut budget = SemanticBudget::default();
            materialize(
                &first_analyzer,
                &first_cache,
                first_lowerer.as_ref(),
                &first_file,
                &mut budget,
                &brokk_bifrost_core::cancellation::CancellationToken::default(),
            )
        });
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("first lowerer entry");

        let second_analyzer = analyzer.clone();
        let second_cache = cache.clone();
        let second_file = file.clone();
        let second_lowerer = Arc::clone(&lowerer);
        let second = thread::spawn(move || {
            let mut budget = SemanticBudget::default();
            materialize(
                &second_analyzer,
                &second_cache,
                second_lowerer.as_ref(),
                &second_file,
                &mut budget,
                &brokk_bifrost_core::cancellation::CancellationToken::default(),
            )
        });

        wait_for_waiter(&cache);
        assert_eq!(lowerer.calls(), 1);
        lowerer.release();
        let SemanticOutcome::Complete {
            value: first_value, ..
        } = first.join().expect("first materialization thread")
        else {
            panic!("first complete artifact")
        };
        let SemanticOutcome::Complete {
            value: second_value,
            ..
        } = second.join().expect("second materialization thread")
        else {
            panic!("second complete artifact")
        };
        assert!(Arc::ptr_eq(&first_value, &second_value));
        assert_eq!(lowerer.calls(), 1);
        assert_eq!(
            cache.len(),
            0,
            "an oversize artifact is shared with current waiters but not retained"
        );
    }
    #[test]
    fn cancelled_same_key_waiter_does_not_publish_or_lower() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 1;\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let (entered_tx, entered_rx) = mpsc::channel();
        let lowerer = Arc::new(BlockingLowerer::new(entered_tx));

        let first_analyzer = analyzer.clone();
        let first_cache = cache.clone();
        let first_file = file.clone();
        let first_lowerer = Arc::clone(&lowerer);
        let first = thread::spawn(move || {
            let mut budget = SemanticBudget::default();
            materialize(
                &first_analyzer,
                &first_cache,
                first_lowerer.as_ref(),
                &first_file,
                &mut budget,
                &brokk_bifrost_core::cancellation::CancellationToken::default(),
            )
        });
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("first lowerer entry");

        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::default();
        let waiter_cancellation = cancellation.clone();
        let second_analyzer = analyzer.clone();
        let second_cache = cache.clone();
        let second_file = file.clone();
        let second_lowerer = Arc::clone(&lowerer);
        let second = thread::spawn(move || {
            let mut budget = SemanticBudget::default();
            let outcome = materialize(
                &second_analyzer,
                &second_cache,
                second_lowerer.as_ref(),
                &second_file,
                &mut budget,
                &waiter_cancellation,
            );
            (outcome, budget.used())
        });

        wait_for_waiter(&cache);
        cancellation.cancel();
        let (outcome, used) = second.join().expect("cancelled waiter thread");
        assert!(matches!(
            outcome,
            SemanticOutcome::Cancelled { partial: None, .. }
        ));
        assert_eq!(used, SemanticWork::default());
        assert_eq!(lowerer.calls(), 1);

        lowerer.release();
        assert!(
            first
                .join()
                .expect("leader materialization thread")
                .is_complete()
        );
        assert_eq!(lowerer.calls(), 1);
    }
    #[test]
    fn adjacent_overlay_revisions_do_not_reuse_stale_artifacts() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 0;\n");
        let base: Arc<dyn brokk_bifrost_core::analyzer::project::Project> =
            Arc::new(TestProject::new(root.clone(), Language::TypeScript));
        let overlay = Arc::new(OverlayProject::new(base));
        let analyzer = TreeSitterAnalyzer::new(overlay.clone(), TypescriptAdapter);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);

        assert!(overlay.set(file.abs_path(), "export const value = 1;\n".to_string()));
        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: first, .. } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        ) else {
            panic!("first overlay")
        };
        assert!(overlay.set(file.abs_path(), "export const value = 2;\n".to_string()));
        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: second, .. } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        ) else {
            panic!("second overlay")
        };

        assert_ne!(first.key().revision(), second.key().revision());
        assert!(!Arc::ptr_eq(&first, &second));
        assert!(overlay.set(file.abs_path(), "export const value = 1;\n".to_string()));
        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: third, .. } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        ) else {
            panic!("third overlay")
        };
        assert_ne!(first.key().revision(), third.key().revision());
        assert!(!Arc::ptr_eq(&first, &third));
        assert_eq!(lowerer.calls(), 3);
    }
    #[test]
    fn independently_validated_cancelled_partial_is_charged_but_not_cached() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 1;\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::CancelWithPartial);
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::default();
        let mut budget = SemanticBudget::default();

        let outcome = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &cancellation,
        );
        let SemanticOutcome::Cancelled {
            partial: Some(partial),
            ..
        } = outcome
        else {
            panic!("validated lowerer partial should survive cancellation")
        };
        assert_source_and_artifact_charged(&budget, &file, &partial);
        assert_eq!(cache.len(), 0);
    }
    #[test]
    fn partial_artifacts_are_charged_once_but_never_cached_as_complete() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 1;\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::PartialThenComplete);
        let collector = SemanticArtifactCollector::new();
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::default();

        let mut budget = SemanticBudget::default();
        let first = materialize_with_lowerer(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut SemanticRequest::new(&mut budget, &cancellation)
                .with_artifact_collector(&collector),
        )
        .expect("partial materialization");
        assert!(matches!(
            first,
            SemanticOutcome::Unknown {
                partial: Some(_),
                ..
            }
        ));
        assert_eq!(cache.len(), 0);
        assert_eq!(collector.len(), 0);
        assert!(collector.take_complete(&file).is_empty());

        let mut budget = SemanticBudget::default();
        let completed = materialize_with_lowerer(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut SemanticRequest::new(&mut budget, &cancellation)
                .with_artifact_collector(&collector),
        )
        .expect("complete materialization");
        let SemanticOutcome::Complete { value, .. } = completed else {
            panic!("second materialization must complete")
        };
        let observed = collector.take_complete(&file);
        assert_eq!(observed.len(), 1);
        assert!(Arc::ptr_eq(observed[0].artifact(), &value));
        let mut budget = SemanticBudget::default();
        assert!(
            materialize(
                &analyzer,
                &cache,
                &lowerer,
                &file,
                &mut budget,
                &brokk_bifrost_core::cancellation::CancellationToken::default(),
            )
            .is_complete()
        );
        assert_eq!(lowerer.calls(), 2);
    }
    #[test]
    fn complete_artifact_collector_follows_staged_requests_and_drains_atomically() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let first = write_file(&root, "src/first.ts", "export const first = 1;\n");
        let second = write_file(&root, "src/second.ts", "export const second = 2;\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);
        let collector = SemanticArtifactCollector::new();
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::default();
        let mut parent_budget = SemanticBudget::default();
        let parent_request = SemanticRequest::new(&mut parent_budget, &cancellation)
            .with_artifact_collector(&collector);

        let mut staged_budget = SemanticBudget::default();
        let mut staged_request = parent_request.staged(&mut staged_budget);
        let SemanticOutcome::Complete {
            value: first_artifact,
            ..
        } = materialize_with_lowerer(&analyzer, &cache, &lowerer, &first, &mut staged_request)
            .expect("first staged materialization")
        else {
            panic!("first staged materialization must complete")
        };
        let SemanticOutcome::Complete {
            value: second_artifact,
            ..
        } = materialize_with_lowerer(&analyzer, &cache, &lowerer, &second, &mut staged_request)
            .expect("second staged materialization")
        else {
            panic!("second staged materialization must complete")
        };

        drop(staged_request);
        drop(parent_request);
        assert_eq!(
            parent_budget.used(),
            SemanticWork::default(),
            "staging keeps scalar work isolated from its parent request"
        );
        let drained = collector.take_all_complete();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].file(), &first);
        assert!(Arc::ptr_eq(drained[0].artifact(), &first_artifact));
        assert_eq!(drained[1].file(), &second);
        assert!(Arc::ptr_eq(drained[1].artifact(), &second_artifact));
        assert!(collector.take_all_complete().is_empty());
    }
    #[test]
    fn complete_artifact_collector_retains_distinct_same_key_allocations() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/subject.ts", "export const subject = 1;\n");
        let analyzer = analyzer(&root);
        let first_cache = CompleteSemanticArtifactCache::default();
        let second_cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);
        let collector = SemanticArtifactCollector::new();
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::default();
        let materialize_from = |cache: &CompleteSemanticArtifactCache| {
            let mut budget = SemanticBudget::default();
            let outcome = materialize_with_lowerer(
                &analyzer,
                cache,
                &lowerer,
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation)
                    .with_artifact_collector(&collector),
            )
            .expect("complete materialization");
            let SemanticOutcome::Complete { value, .. } = outcome else {
                panic!("materialization must complete")
            };
            value
        };

        let first = materialize_from(&first_cache);
        let first_repeat = materialize_from(&first_cache);
        let second = materialize_from(&second_cache);
        assert!(Arc::ptr_eq(&first, &first_repeat));
        assert_eq!(first.key(), second.key());
        assert_eq!(first.materialization_id(), second.materialization_id());
        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(lowerer.calls(), 2);

        let retained = collector.take_complete(&file);
        assert_eq!(retained.len(), 2);
        assert!(
            retained
                .iter()
                .any(|lease| Arc::ptr_eq(lease.artifact(), &first))
        );
        assert!(
            retained
                .iter()
                .any(|lease| Arc::ptr_eq(lease.artifact(), &second))
        );
    }
    #[test]
    fn retained_payload_budget_failure_is_atomic() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let source = "export const value = 1;\n";
        let file = write_file(&root, "src/main.ts", source);
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);
        let collector = SemanticArtifactCollector::new();
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::default();
        let mut limits = SemanticBudget::default().limits();
        limits.owned_text_bytes = 1;
        let mut budget = SemanticBudget::new(limits).expect("positive limits");

        let outcome = materialize_with_lowerer(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut SemanticRequest::new(&mut budget, &cancellation)
                .with_artifact_collector(&collector),
        )
        .expect("budget-limited materialization");
        assert!(matches!(
            outcome,
            SemanticOutcome::ExceededBudget { partial: None, .. }
        ));
        assert_eq!(budget.resident(), SemanticWork::default());
        assert_eq!(
            budget.used(),
            SemanticWork {
                source_bytes: source.len(),
                ..SemanticWork::default()
            }
        );
        assert_eq!(cache.len(), 0);
        assert!(
            collector.take_all_complete().is_empty(),
            "a complete lowerer result whose budget commit failed is not observable"
        );
    }
    #[test]
    fn current_artifact_key_matches_materialization_without_running_the_lowerer() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 1;\n");
        let analyzer = analyzer(&root);
        let _scope = AnalyzerQueryScope::new(&analyzer);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);

        let current = current_artifact_source_with_lowerer(&analyzer, &lowerer, &file, usize::MAX)
            .expect("current artifact source lookup")
            .expect("current artifact source");
        assert_eq!(current.source(), "export const value = 1;\n");
        let current = current.key().clone();
        assert_eq!(lowerer.calls(), 0);
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 0);

        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value, .. } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        ) else {
            panic!("complete artifact")
        };
        assert_eq!(value.key(), &current);
        assert_eq!(lowerer.calls(), 1);
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 1);
    }
    #[test]
    fn an_edited_source_derives_a_fresh_key_and_pays_for_its_bytes_again() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let before = "export function main(): number { return 1; }\n";
        let after = "export function main(): number { return 1; }\n\
             export function second(): number { return 2; }\n";
        let file = write_file(&root, "src/edited.ts", before);
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer =
            brokk_bifrost_js_ts_analysis::analyzer::js_ts::semantic::JsTsSemanticLowerer::typescript();

        let mut first_budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: first, .. } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut first_budget,
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        ) else {
            panic!("the fixture must lower completely")
        };
        assert_eq!(
            first_budget.used().source_bytes,
            before.len(),
            "the request that lowered the file pays its bytes once"
        );

        // Unchanged: served without reading, which is the behaviour the edit
        // below has to defeat.
        let mut unchanged_budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: served, .. } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut unchanged_budget,
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        ) else {
            panic!("an unchanged source must still serve a complete artifact")
        };
        assert!(Arc::ptr_eq(&first, &served));
        assert_artifact_charged_without_reading(&unchanged_budget, &served);

        file.write(after).expect("rewrite fixture");
        let updated_analyzer = analyzer.update(&BTreeSet::from([file.clone()]));

        let mut edited_budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: edited, .. } = materialize(
            &updated_analyzer,
            &cache,
            &lowerer,
            &file,
            &mut edited_budget,
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        ) else {
            panic!("the edited fixture must lower completely")
        };
        assert_ne!(
            first.key(),
            edited.key(),
            "an edited source must derive a fresh artifact key"
        );
        assert!(
            !Arc::ptr_eq(&first, &edited),
            "an edited source must not be served the previous artifact"
        );
        assert_eq!(
            edited.procedures().len(),
            2,
            "the edited artifact must describe the edited file"
        );
        assert_eq!(
            edited_budget.used().source_bytes,
            after.len(),
            "the request that re-read and re-hashed the edited file pays its bytes"
        );
    }
    #[test]
    fn complete_cache_weight_includes_derived_call_indexes() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(
            &root,
            "src/calls.ts",
            "function target(value: number): number { return value; }\n\
             export function main(): number { return target(1); }\n",
        );
        let analyzer = analyzer(&root);
        let staging_cache = CompleteSemanticArtifactCache::default();
        let lowerer =
            brokk_bifrost_js_ts_analysis::analyzer::js_ts::semantic::JsTsSemanticLowerer::typescript();
        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete {
            value: artifact, ..
        } = materialize(
            &analyzer,
            &staging_cache,
            &lowerer,
            &file,
            &mut budget,
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        )
        else {
            panic!("call-bearing artifact")
        };

        let call_index_bytes = artifact
            .procedures()
            .iter()
            .map(ProcedureSemantics::call_indexes_retained_bytes)
            .sum::<u64>();
        let value_identity_index_bytes = artifact
            .procedures()
            .iter()
            .map(ProcedureSemantics::value_identity_index_retained_bytes)
            .sum::<u64>();
        let lexical_children_index_bytes = artifact.lexical_children_index_retained_bytes();
        let call_source_extent_bytes = artifact.call_source_extents_retained_bytes();
        assert!(
            call_index_bytes > 0,
            "fixture must retain derived call-phase indexes"
        );
        let base_bytes = retained_artifact_base_bytes(&artifact);
        let retained_bytes = retained_artifact_bytes(artifact.key(), &artifact);
        assert_eq!(
            retained_bytes,
            base_bytes
                .saturating_add(call_index_bytes)
                .saturating_add(value_identity_index_bytes)
                .saturating_add(lexical_children_index_bytes)
                .saturating_add(call_source_extent_bytes),
            "cache weight must include every derived semantic-index allocation"
        );

        let undersized = CompleteSemanticArtifactCache::new(base_bytes);
        undersized.insert(artifact.key().clone(), Arc::clone(&artifact));
        assert_eq!(
            undersized.len(),
            0,
            "the former row-only capacity must not retain the indexed artifact"
        );

        let exact = CompleteSemanticArtifactCache::new(retained_bytes);
        exact.insert(artifact.key().clone(), artifact);
        assert_eq!(exact.len(), 1, "the corrected exact capacity retains it");
    }
    #[test]
    fn dialect_and_source_origin_are_part_of_snapshot_identity() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let source = "export const value = 1;\n";
        let ts = write_file(&root, "src/same.ts", source);
        let tsx = write_file(&root, "src/same.tsx", source);
        let base: Arc<dyn brokk_bifrost_core::analyzer::project::Project> =
            Arc::new(TestProject::new(root.clone(), Language::TypeScript));
        let overlay = Arc::new(OverlayProject::new(base));
        let analyzer = TreeSitterAnalyzer::new(overlay.clone(), TypescriptAdapter);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);

        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: disk, .. } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &ts,
            &mut budget,
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        ) else {
            panic!("disk artifact")
        };
        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete {
            value: tsx_artifact,
            ..
        } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &tsx,
            &mut budget,
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        )
        else {
            panic!("tsx artifact")
        };
        assert_ne!(disk.key().language(), tsx_artifact.key().language());

        assert!(overlay.set(ts.abs_path(), source.to_string()));
        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete {
            value: overlay_artifact,
            ..
        } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &ts,
            &mut budget,
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        )
        else {
            panic!("overlay artifact")
        };
        assert_ne!(disk.key(), overlay_artifact.key());
        assert!(matches!(disk.key().revision(), SourceRevision::Disk { .. }));
        assert!(matches!(
            overlay_artifact.key().revision(),
            SourceRevision::Overlay { .. }
        ));
    }
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5113: failed lowering leaked admissions or rolled back accepted binding work"
    )]
    fn failed_lowering_budget_releases_admissions_and_keeps_work() {
        struct FailingLowerer;
        impl ProgramSemanticsLowerer for FailingLowerer {
            fn identity(&self) -> SemanticAdapterIdentity {
                FakeLowerer::new(FakeMode::Complete).identity()
            }

            fn lower(
                &self,
                _file: &ProjectFile,
                _prepared: &PreparedSyntaxTree,
                budget: &SemanticBudget,
                _cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
            ) -> Result<SemanticOutcome<Vec<ProcedureSemanticsParts>>, SemanticProviderError>
            {
                let work = SemanticWork {
                    nested_entries: 7,
                    ..Default::default()
                };

                budget.note_lowering_work(work);
                Err(SemanticProviderError::internal(
                    "failed after binding traversal",
                ))
            }
        }
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let source = "export const value = 1;\n";
        let file = write_file(&root, "src/main.ts", source);
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::default();
        let mut budget = SemanticBudget::uniform(64).unwrap();
        for attempts in 1..=2 {
            let result = materialize_with_lowerer(
                &analyzer,
                &cache,
                &FailingLowerer,
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            );
            assert!(result.is_err());
            assert_eq!(budget.resident(), SemanticWork::default());
            assert_eq!(budget.used().source_bytes, attempts * source.len());
            assert_eq!(budget.used().nested_entries, attempts * 7);
            assert_eq!(budget.root_work_peak().nested_entries, attempts * 7);
            assert_eq!(cache.len(), 0);
        }
    }
    #[test]
    fn cancellation_discards_unpublished_construction() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 1;\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Cancel);
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::default();
        let mut budget = SemanticBudget::default();

        let outcome = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &cancellation,
        );
        assert!(matches!(
            outcome,
            SemanticOutcome::Cancelled { partial: None, .. }
        ));
        assert_eq!(budget.resident(), SemanticWork::default());
        assert_eq!(
            budget.used().source_bytes,
            "export const value = 1;\n".len()
        );
        assert_eq!(cache.len(), 0);
    }
    #[test]
    fn cancellation_discards_non_cancelled_partial_outcomes_without_residency() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 1;\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::CancelUnknownPartial);
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::default();
        let mut budget = SemanticBudget::default();

        let outcome = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &cancellation,
        );
        assert!(matches!(
            outcome,
            SemanticOutcome::Cancelled { partial: None, .. }
        ));
        assert_eq!(budget.resident(), SemanticWork::default());
        assert_eq!(
            budget.used().source_bytes,
            "export const value = 1;\n".len()
        );
        assert_eq!(cache.len(), 0);
    }
    #[test]
    fn source_limit_is_enforced_before_parsing_or_lowering() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 1;\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);
        let mut limits = SemanticBudget::default().limits();
        limits.source_bytes = 8;
        let mut budget = SemanticBudget::new(limits).expect("positive limits");

        let outcome = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        );
        assert!(matches!(
            outcome,
            SemanticOutcome::ExceededBudget { partial: None, work, .. }
                if work.source_bytes > 8
        ));
        assert_eq!(lowerer.calls(), 0);
        assert_eq!(budget.used(), SemanticWork::default());
    }
    #[test]
    fn empty_source_is_a_valid_exact_snapshot() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/empty.ts", "");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);
        let mut budget = SemanticBudget::default();

        let outcome = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        );
        let SemanticOutcome::Complete { value, .. } = outcome else {
            panic!("empty TypeScript source should publish an empty complete artifact")
        };
        assert!(value.procedures().is_empty());
        assert_source_and_artifact_charged(&budget, &file, &value);
    }
    #[test]
    fn concrete_provider_rejects_foreign_roots_and_languages_before_source_access() {
        let first = tempfile::tempdir().expect("first temp dir");
        let second = tempfile::tempdir().expect("second temp dir");
        let root = first.path().canonicalize().expect("first root");
        let foreign_root = second.path().canonicalize().expect("second root");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::default();

        for file in [
            ProjectFile::new(foreign_root, "src/main.ts"),
            ProjectFile::new(root.clone(), "src/Main.java"),
        ] {
            let mut budget = SemanticBudget::default();
            let error = materialize_with_lowerer(
                &analyzer,
                &cache,
                &lowerer,
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect_err("foreign file identity should be rejected");
            assert!(matches!(error, SemanticProviderError::InvalidIdentity(_)));
            assert_eq!(budget.used(), SemanticWork::default());
        }
        assert_eq!(lowerer.calls(), 0);
    }
}
