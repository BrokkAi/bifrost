//! The Rust cargo-route tests that need a live analyzer.
//!
//! `RustCargoRouteIndex` and the canonical module-route fact reader it consumes
//! live in [`brokk_bifrost_rust::cargo_routes`]; only the assertions that reach
//! the analyzer's live summary queries and the store rows analysis wrote for
//! them to read -- have to be built from a real `RustAnalyzer`, so they stay
//! here (the Go block-2 precedent).
//!
//! The direct half of passthrough-macro discovery -- that coordinated
//! `parse_rust_file` facts plus `module_child_edges` replay only faithful item
//! macros -- is pinned inside the Rust crate by
//! `the_module_route_fixture_exercises_every_declaration_shape` and
//! `module_child_edges_use_coordinated_route_facts`, over the same shapes.

#[cfg(test)]
mod tests {
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9737: the route kinds were registered but their questions were not admitted by the persisted read codec"
    )]
    fn registered_derivation_questions_match_persisted_codec() {
        use brokk_bifrost_analysis::analyzer::derivation_host::AnalyzerDerivations;
        use brokk_bifrost_core::retention_budget::RetentionBudget;
        use brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily;
        let budget = RetentionBudget::new(1_000_000);
        let host = AnalyzerDerivations::new(&budget);
        let shapes = host.registered_question_shapes();
        assert!(
            shapes
                .iter()
                .any(|shape| shape.id.0 == "derivation:rust_file_units:v1")
        );
        assert!(
            shapes
                .iter()
                .any(|shape| shape.id.0 == "derivation:rust_unit_routes:v1")
        );
        for expected in shapes {
            let actual = PersistedDerivationFamily::of(expected.id.0)
                .unwrap_or_else(|| panic!("unpersisted registered derivation: {}", expected.id.0));
            assert_eq!(
                (
                    actual.language,
                    actual.subject,
                    actual.rel_path,
                    actual.name
                ),
                (
                    expected.language,
                    expected.subject,
                    expected.rel_path,
                    expected.name
                ),
                "wrong persisted question shape: {}",
                expected.id.0
            );
        }
    }

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationInput;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome;

    use brokk_bifrost_analysis::analyzer::store::resolution_publication::SelectedResolutionOverlayInputsOutcome;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadIncomplete;

    use crate::analyzer::RustAnalyzer;
    use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
    use brokk_bifrost_core::analyzer::CodeUnitIndex;
    use brokk_bifrost_rust::cargo_routes::RustCargoTargetRelation;
    use brokk_bifrost_rust::graph_support::RustCargoRouteError;
    use brokk_bifrost_rust::graph_support::RustSource;
    use brokk_bifrost_rust::test_helpers::write_fixture_file as write;
    use std::path::PathBuf;

    struct OuterRouteWithUnpersistedChild {
        inner: brokk_bifrost_analysis::analyzer::derivation_host::AnalyzerDerivations,
    }

    impl brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationKind
        for OuterRouteWithUnpersistedChild
    {
        type Key = String;
        type Output = u8;
        const ID: brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationKindId =
            brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationKindId(
                "test:outer_route_unpersisted_child:v1",
            );
        const STRATUM: u16 = 2;
        const CHILDREN: &'static [(
            brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationKindId,
            u16,
        )] = &[(super::super::route_kinds::RustFileUnits::ID, 1)];
        fn question(
            key: &String,
        ) -> brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationQuestion {
            super::super::route_kinds::RustFileUnits::question(key)
        }
        fn key_from_question(
            question: &brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationQuestion,
        ) -> Option<String> {
            super::super::route_kinds::RustFileUnits::key_from_question(question)
        }
        fn compute<
            R: brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationRevision,
            A: brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationAuthority,
        >(
            &self,
            _: &mut brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationFrame<
                '_,
                R,
                A,
            >,
            key: &String,
        ) -> brokk_bifrost_semantic::analyzer::semantic::derivation::Computed<u8> {
            use brokk_bifrost_analysis::analyzer::derivation_host::{
                with_bound_inventory, with_current_analyzer,
            };
            use brokk_bifrost_semantic::analyzer::semantic::derivation::{
                Computed, Demanded, ReuseValidity,
            };
            let answer = with_current_analyzer(|analyzer| {
                with_bound_inventory(|inventory| {
                    self.inner
                        .demand::<super::super::route_kinds::RustFileUnits>(
                            analyzer, inventory, key,
                        )
                })
            });
            assert!(
                matches!(answer, Demanded::Available { .. }),
                "inner demand unavailable"
            );
            Computed::Available {
                value: 1,
                complete: true,
                validity: ReuseValidity::Reusable,
            }
        }
        fn output_projection(
            value: &u8,
            hash: &mut brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher,
        ) {
            hash.value(&[*value]);
        }
    }

    #[test]
    fn retained_outer_replay_refuses_inner_host_persistence_refusal() {
        use brokk_bifrost_analysis::analyzer::IAnalyzer;
        use brokk_bifrost_analysis::analyzer::derivation_host::{
            AnalyzerDerivations, ReplayMissing, ReplayResult,
        };
        use brokk_bifrost_core::retention_budget::RetentionBudget;
        use brokk_bifrost_semantic::analyzer::semantic::derivation::{
            Demanded, DerivationKind, Handle, ReuseValidity,
        };
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"replay\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("src/lib.rs", "pub fn item() {}\n")
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let host = analyzer.inner.derivations().expect("derivation host");
        host.register(OuterRouteWithUnpersistedChild {
            inner: AnalyzerDerivations::without_declared_recipes(&RetentionBudget::new(
                16 * 1024 * 1024,
            )),
        });
        let key = "src/lib.rs".to_string();
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::default();
        let operation = match analyzer
            .open_selected_rust_operation(&cancellation)
            .outcome
            .expect("selected operation")
        {
            SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
            other => panic!("selected operation: {other:?}"),
        };
        let ledger = std::sync::Arc::new(brokk_bifrost_analysis::analyzer::ReadLedger::new());
        let _scope = AnalyzerQueryScope::with_read_ledger(&analyzer, ledger.clone());
        let answer = host.demand::<OuterRouteWithUnpersistedChild>(
            &analyzer,
            &operation.ready.inventory,
            &key,
        );
        assert!(
            matches!(
                answer,
                Demanded::Available {
                    value: Handle::Retained(_),
                    validity: ReuseValidity::Reusable,
                    ..
                }
            ),
            "outer demand was not retained and reusable"
        );
        assert!(ledger.persistence_refusals() > 0);
        drop(_scope);
        drop(operation);
        assert_eq!(
            host.replay(
                &analyzer,
                OuterRouteWithUnpersistedChild::ID,
                &OuterRouteWithUnpersistedChild::question(&key)
            ),
            ReplayResult::Missing(ReplayMissing::Refused)
        );
    }

    struct RefusingNestedRoute {
        analyzer: RustAnalyzer,
    }

    impl brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationKind
        for RefusingNestedRoute
    {
        type Key = String;
        type Output = u8;
        const ID: brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationKindId =
            brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationKindId(
                "test:refusing_nested_rust_route:v1",
            );
        const STRATUM: u16 = 2;
        const CHILDREN: &'static [(
            brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationKindId,
            u16,
        )] = &[(super::super::route_kinds::RustFileUnits::ID, 1)];
        fn question(
            key: &String,
        ) -> brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationQuestion {
            super::super::route_kinds::RustFileUnits::question(key)
        }
        fn key_from_question(
            question: &brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationQuestion,
        ) -> Option<String> {
            super::super::route_kinds::RustFileUnits::key_from_question(question)
        }
        fn compute<
            R: brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationRevision,
            A: brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationAuthority,
        >(
            &self,
            frame: &mut brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationFrame<
                '_,
                R,
                A,
            >,
            key: &String,
        ) -> brokk_bifrost_semantic::analyzer::semantic::derivation::Computed<u8> {
            use brokk_bifrost_semantic::analyzer::semantic::derivation::{
                Computed, Demanded, ReuseValidity, UnavailableCause,
            };
            if !matches!(
                frame.demand::<super::super::route_kinds::RustFileUnits>(key),
                Demanded::Available { .. }
            ) {
                return Computed::Unavailable(UnavailableCause::ChildUnavailable);
            }
            brokk_bifrost_analysis::analyzer::IAnalyzer::record_unattributed_read(&self.analyzer);
            Computed::Available {
                value: 1,
                complete: true,
                validity: ReuseValidity::Reusable,
            }
        }
        fn output_projection(
            value: &u8,
            hash: &mut brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher,
        ) {
            hash.value(&[*value]);
        }
    }

    #[test]
    fn nested_unattributed_receipt_refuses_replay() {
        use brokk_bifrost_analysis::analyzer::IAnalyzer;
        use brokk_bifrost_analysis::analyzer::derivation_host::{ReplayMissing, ReplayResult};
        use brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationKind;
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"replay\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("src/lib.rs", "pub fn item() {}\n")
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let host = analyzer.inner.derivations().expect("derivation host");
        host.register(RefusingNestedRoute {
            analyzer: analyzer.clone(),
        });
        let question = RefusingNestedRoute::question(&"src/lib.rs".to_string());
        assert_eq!(
            host.replay(&analyzer, RefusingNestedRoute::ID, &question),
            ReplayResult::Missing(ReplayMissing::Refused)
        );
    }

    #[test]
    fn recorded_route_question_replays_on_same_head_and_refuses_bad_questions() {
        use brokk_bifrost_analysis::analyzer::IAnalyzer;
        use brokk_bifrost_analysis::analyzer::derivation_host::{
            AnalyzerDerivations, ReplayMissing, ReplayResult,
        };
        use brokk_bifrost_core::retention_budget::RetentionBudget;
        use brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationKindId;
        use brokk_bifrost_semantic::analyzer::semantic::read_ledger::{
            LookupKind, LookupQuestion, ReadKey,
        };

        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"replay\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("src/lib.rs", "pub fn item() {}\n")
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let ledger = std::sync::Arc::new(brokk_bifrost_analysis::analyzer::ReadLedger::new());
        let scope = AnalyzerQueryScope::with_read_ledger(&analyzer, ledger.clone());
        <RustAnalyzer as RustSource>::file_routes(&analyzer, &fixture.file("src/lib.rs"), None)
            .expect("record route question");
        drop(scope);
        let (kind, question, identity) = ledger
            .keys()
            .into_iter()
            .find_map(|read| match read {
                ReadKey::Lookup {
                    kind: LookupKind::Derivation(kind),
                    question: LookupQuestion::Derivation(question),
                    digest,
                } => Some((kind, question, digest)),
                _ => None,
            })
            .expect("recorded derivation");
        let current = analyzer.inner.derivations().expect("derivation host");
        assert_eq!(
            current.replay(&analyzer, kind, &question),
            ReplayResult::Identity(
                brokk_bifrost_semantic::analyzer::semantic::derivation::OutputIdentity(identity)
            )
        );
        let fresh = AnalyzerDerivations::new(&RetentionBudget::new(16 * 1024 * 1024));
        assert_eq!(
            fresh.replay(&analyzer, kind, &question),
            ReplayResult::Identity(
                brokk_bifrost_semantic::analyzer::semantic::derivation::OutputIdentity(identity)
            )
        );
        assert_eq!(
            fresh.replay(&analyzer, DerivationKindId("unregistered"), &question),
            ReplayResult::Missing(ReplayMissing::InvalidQuestion)
        );
        let mut malformed = question.clone();
        malformed.name = Some("unexpected".into());
        assert_eq!(
            fresh.replay(&analyzer, kind, &malformed),
            ReplayResult::Missing(ReplayMissing::InvalidQuestion)
        );
        let snapshot = analyzer.inner.selected_workspace_snapshots()["rust"].clone();
        let frame = brokk_bifrost_analysis::analyzer::derivation_host::rust_route_question_identity(
            &analyzer,
            analyzer.analyzer_store(),
            snapshot,
        );
        let in_frame =
            brokk_bifrost_analysis::analyzer::derivation_host::read_frame::with_query_read_frame(
                frame,
                || panic!("replay must refuse before opening the frame"),
                || fresh.replay(&analyzer, kind, &malformed),
            );
        assert_eq!(
            in_frame,
            ReplayResult::Missing(ReplayMissing::ActiveSelection)
        );

        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::default();
        let operation = match analyzer
            .open_selected_rust_operation(&cancellation)
            .outcome
            .expect("selected operation")
        {
            SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
            other => panic!("selected operation: {other:?}"),
        };
        let mut operation_identity =
            brokk_bifrost_analysis::analyzer::derivation_host::rust_route_question_identity(
                &analyzer,
                analyzer.analyzer_store(),
                brokk_bifrost_analysis::analyzer::derivation_host::selected_rust_snapshot(
                    &operation.ready.inventory,
                )
                .expect("Rust snapshot"),
            );
        operation_identity.selection = Some(operation.ready.inventory.fingerprint());
        operation_identity.operation = Some(&operation as *const _ as usize);
        assert_eq!(
            brokk_bifrost_analysis::analyzer::derivation_host::read_frame::with_operation_read_frame(
                operation_identity,
                &operation,
                || fresh.replay(&analyzer, kind, &malformed),
            ).expect("operation frame"),
            ReplayResult::Missing(ReplayMissing::ActiveSelection)
        );
        drop(operation);

        let tiny = AnalyzerDerivations::new(&RetentionBudget::new(1));
        assert_eq!(
            tiny.replay(&analyzer, kind, &question),
            ReplayResult::Missing(ReplayMissing::Refused)
        );
    }

    #[test]
    fn recorded_route_question_tracks_own_crate_but_not_unrelated_body() {
        use brokk_bifrost_analysis::analyzer::IAnalyzer;
        use brokk_bifrost_analysis::analyzer::derivation_host::{
            AnalyzerDerivations, ReplayResult,
        };
        use brokk_bifrost_core::retention_budget::RetentionBudget;
        use brokk_bifrost_semantic::analyzer::semantic::read_ledger::{
            LookupKind, LookupQuestion, ReadKey,
        };
        use std::collections::BTreeSet;

        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[workspace]\nmembers = [\"app\", \"other\"]\nresolver = \"2\"\n",
            )
            .file(
                "app/Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("app/src/lib.rs", "mod missing;\n")
            .file(
                "other/Cargo.toml",
                "[package]\nname = \"other\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("other/src/lib.rs", "pub fn body() {}\n")
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let app = fixture.file("app/src/lib.rs");
        let other = fixture.file("other/src/lib.rs");
        let ledger = std::sync::Arc::new(brokk_bifrost_analysis::analyzer::ReadLedger::new());
        let scope = AnalyzerQueryScope::with_read_ledger(&analyzer, ledger.clone());
        <RustAnalyzer as RustSource>::file_routes(&analyzer, &app, None).expect("file routes");
        drop(scope);
        let (kind, question, digest) = ledger
            .keys()
            .into_iter()
            .find_map(|read| match read {
                ReadKey::Lookup {
                    kind: LookupKind::Derivation(kind),
                    question: LookupQuestion::Derivation(question),
                    digest,
                } if kind.0 == "derivation:rust_unit_routes:v1" => Some((kind, question, digest)),
                _ => None,
            })
            .expect("recorded derivation");
        let expected = ReplayResult::Identity(
            brokk_bifrost_semantic::analyzer::semantic::derivation::OutputIdentity(digest),
        );
        let replay = AnalyzerDerivations::new(&RetentionBudget::new(16 * 1024 * 1024));
        assert_eq!(replay.replay(&analyzer, kind, &question), expected);

        write(
            other.root(),
            "other/src/lib.rs",
            "pub fn body() { let _value = 1; }\n",
        );
        let analyzer = analyzer.update(&BTreeSet::from([other]));
        assert_eq!(
            replay.replay(&analyzer, kind, &question),
            expected,
            "an unrelated crate body must preserve the route identity"
        );

        write(app.root(), "app/src/missing.rs", "pub struct Found;\n");
        let added = fixture.file("app/src/missing.rs");
        let analyzer = analyzer.update(&BTreeSet::from([added]));
        let resolved = replay.replay(&analyzer, kind, &question);
        assert!(matches!(resolved, ReplayResult::Identity(_)));
        assert_ne!(
            resolved, expected,
            "resolving the missing module must change the incomplete identity"
        );

        write(app.root(), "app/src/lib.rs", "mod missing;\nmod extra;\n");
        write(app.root(), "app/src/extra.rs", "pub struct Extra;\n");
        let analyzer = analyzer.update(&BTreeSet::from([app, fixture.file("app/src/extra.rs")]));
        let expanded = replay.replay(&analyzer, kind, &question);
        assert!(matches!(expanded, ReplayResult::Identity(_)));
        assert_ne!(
            expanded, resolved,
            "a newly declared module changes membership"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9737: incomplete exports incorrectly blocked complete Rust route inventories"
    )]
    fn incomplete_exports_and_partial_membership_keep_file_routes_available() {
        let unresolved = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"routes\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file(
                "src/lib.rs",
                "pub mod a;\npub use missing_dependency::Thing;\n",
            )
            .file("src/a.rs", "pub struct Item;\n")
            .build();
        let analyzer = RustAnalyzer::new(unresolved.project_dyn());
        let file = unresolved.file("src/a.rs");
        let incomplete_exports: i64 = analyzer
            .analyzer_store()
            .read_conn()
            .expect("summary reader")
            .query_row(
                "SELECT COUNT(*) FROM resolution_unit_summaries WHERE lang='rust' AND publication_state='complete' AND complete=0",
                [],
                |row| row.get(0),
            )
            .expect("incomplete export summary");
        assert!(
            incomplete_exports > 0,
            "fixture must publish incomplete exports"
        );
        let ledger = std::sync::Arc::new(brokk_bifrost_analysis::analyzer::ReadLedger::new());
        let _scope = AnalyzerQueryScope::with_read_ledger(&analyzer, ledger.clone());
        let fragment = <RustAnalyzer as RustSource>::file_routes(&analyzer, &file, None)
            .expect("file routes despite incomplete exports");
        assert_eq!(
            fragment.target_roots(&file),
            vec![unresolved.file("src/lib.rs")]
        );
        assert!(ledger.keys().iter().any(|key| matches!(
            key,
            brokk_bifrost_semantic::analyzer::semantic::read_ledger::ReadKey::Lookup {
                kind:
                    brokk_bifrost_semantic::analyzer::semantic::read_ledger::LookupKind::Derivation(
                        _
                    ),
                ..
            }
        )));
        assert!(!ledger.reuse_refused());

        let missing = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"routes\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("src/lib.rs", "mod missing;\n")
            .build();
        let analyzer = RustAnalyzer::new(missing.project_dyn());
        assert!(
            <RustAnalyzer as RustSource>::file_routes(&analyzer, &missing.file("src/lib.rs"), None)
                .is_ok()
        );

        let dependency = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[workspace]\nmembers = [\"app\", \"dep\"]\nresolver = \"2\"\n")
            .file("dep/Cargo.toml", "[package]\nname = \"dep\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
            .file("dep/src/lib.rs", "mod missing;\n")
            .file("app/Cargo.toml", "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\ndep = { path = \"../dep\" }\n")
            .file("app/src/lib.rs", "pub use dep::Item;\n")
            .build();
        let analyzer = RustAnalyzer::new(dependency.project_dyn());
        assert!(
            <RustAnalyzer as RustSource>::file_routes(
                &analyzer,
                &dependency.file("app/src/lib.rs"),
                None
            )
            .is_ok()
        );
    }

    #[test]
    fn partial_file_routes_do_not_certify_negative_membership() {
        fn fixture(complete: bool) -> BuiltInlineTestProject {
            let project = InlineTestProject::with_language(Language::Rust)
                .file(
                    "Cargo.toml",
                    "[workspace]\nmembers = [\"app\", \"dep\"]\nresolver = \"2\"\n",
                )
                .file(
                    "app/Cargo.toml",
                    "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
                )
                .file("app/src/lib.rs", "pub struct App;\n")
                .file(
                    "dep/Cargo.toml",
                    if complete {
                        "[package]\nname = \"dep\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
                    } else {
                        "[package]\nname = \"dep\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[lib]\nmystery = true\n"
                    },
                )
                .file("dep/src/lib.rs", "#[cfg(test)] mod only;\nmod missing;\n")
                .file("dep/src/only.rs", "pub struct Only;\n");
            if complete {
                project
                    .file("dep/src/missing.rs", "pub struct Missing;\n")
                    .build()
            } else {
                project.build()
            }
        }
        for complete in [false, true] {
            let project = fixture(complete);
            let analyzer = RustAnalyzer::new(project.project_dyn());
            let app = project.file("app/src/lib.rs");
            let dep = project.file("dep/src/only.rs");
            let app_routes =
                <RustAnalyzer as RustSource>::file_routes(&analyzer, &app, None).unwrap();
            let dep_routes =
                <RustAnalyzer as RustSource>::file_routes(&analyzer, &dep, None).unwrap();
            let broad_complete: bool = analyzer.analyzer_store().read_conn().unwrap().query_row(
                "SELECT coalesce(min(t.broad_complete), 1) FROM rust_crate_versions v JOIN rust_crate_topologies t USING(topology_id) WHERE v.lang='rust' AND v.valid_until IS NULL",
                [],
                |row| row.get(0),
            ).unwrap();
            let expected_complete = complete && broad_complete;
            assert_eq!(app_routes.is_complete(), expected_complete);
            assert_eq!(dep_routes.is_complete(), expected_complete);
            assert_eq!(
                app_routes.target_relation(&app, &dep_routes, &dep),
                if expected_complete {
                    RustCargoTargetRelation::Disjoint
                } else {
                    RustCargoTargetRelation::Unknown
                }
            );
            assert_eq!(dep_routes.file_is_test_only(&dep), expected_complete);
            let candidates: Vec<_> = analyzer.declarations(&dep).into_iter().collect();
            assert!(!candidates.is_empty());
            let candidate_routes = std::iter::once((dep.clone(), dep_routes)).collect();
            let filtered =
                app_routes.candidates_in_same_target_root(&app, candidates, &candidate_routes);
            assert_eq!(filtered.is_none(), !expected_complete);
            if expected_complete {
                assert!(filtered.unwrap().is_empty());
            }
        }
    }

    /// The per-file route memo and the package view's memos live in the request
    /// memos of the outermost query scope. A nested scope shares them, the end of
    /// the request drops them, and a hit replays the reasons its build recorded.
    #[test]
    fn route_request_memo_lives_for_one_request_and_replays_its_reasons() {
        use super::super::RustRouteRequestMemo;
        use brokk_bifrost_rust::graph_support::RustSource;
        use std::sync::Arc;
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"memo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[lib]\nmystery = true\n",
            )
            .file("src/lib.rs", "mod missing;\n")
            .build();
        let analyzer = RustAnalyzer::new(project.project_dyn());
        let file = project.file("src/lib.rs");
        let keys = |memo: &RustRouteRequestMemo| {
            (
                format!("{:?}", memo.file_routes),
                format!("{:?}", memo.package_membership),
            )
        };
        let gap = |reasons: &[QueryReadIncomplete]| {
            reasons
                .iter()
                .filter_map(|reason| match reason {
                    QueryReadIncomplete::SemanticEvidenceGap(text)
                        if text.starts_with("Rust route evidence is incomplete for units") =>
                    {
                        Some(text.to_string())
                    }
                    _ => None,
                })
                .collect::<Vec<_>>()
        };
        assert!(
            analyzer
                .inner
                .active_query_request_memo::<RustRouteRequestMemo>()
                .is_none(),
            "outside a request scope nothing is retained"
        );

        let first_request = {
            let request = AnalyzerQueryScope::new(&analyzer);
            let memo = analyzer
                .inner
                .active_query_request_memo::<RustRouteRequestMemo>()
                .expect("a request scope has request memos");
            assert_eq!(
                keys(&memo),
                (
                    "KeyedPoolSafeMemo { keys: 0, .. }".into(),
                    "KeyedPoolSafeMemo { keys: 0, .. }".into()
                )
            );
            let read = |capture: &AnalyzerQueryScope<'_>| {
                let routes =
                    <RustAnalyzer as RustSource>::file_routes(&analyzer, &file, None).unwrap();
                let membership = analyzer.package_view().contains(&file, None).unwrap();
                (
                    routes.is_complete(),
                    membership.complete,
                    capture.captured_read_incompleteness(),
                )
            };
            let filled = {
                let capture = AnalyzerQueryScope::capturing_read_incompleteness(&analyzer);
                read(&capture)
            };
            assert!(
                !filled.0 && !filled.1,
                "the unknown target key makes both answers partial"
            );
            assert_eq!(
                gap(&filled.2).len(),
                1,
                "the view records one gap: {:?}",
                filled.2
            );
            assert_eq!(
                keys(&memo),
                (
                    "KeyedPoolSafeMemo { keys: 1, .. }".into(),
                    "KeyedPoolSafeMemo { keys: 1, .. }".into()
                )
            );
            // A hit replays the receipt: the consumer's scope sees the same
            // reasons although no kind ran for it.
            let hit = {
                let capture = AnalyzerQueryScope::capturing_read_incompleteness(&analyzer);
                read(&capture)
            };
            assert_eq!((hit.0, hit.1), (false, false));
            assert_eq!(hit.2, filled.2, "a memo hit replays the stable reasons");
            // A nested scope is the same request.
            {
                let _nested = AnalyzerQueryScope::new(&analyzer);
                let nested = analyzer
                    .inner
                    .active_query_request_memo::<RustRouteRequestMemo>()
                    .unwrap();
                assert!(Arc::ptr_eq(&memo, &nested));
            }
            drop(request);
            memo
        };

        let _second = AnalyzerQueryScope::new(&analyzer);
        let second_memo = analyzer
            .inner
            .active_query_request_memo::<RustRouteRequestMemo>()
            .unwrap();
        assert!(
            !Arc::ptr_eq(&first_request, &second_memo),
            "the next request starts with fresh memos"
        );
        assert_eq!(
            keys(&second_memo),
            (
                "KeyedPoolSafeMemo { keys: 0, .. }".into(),
                "KeyedPoolSafeMemo { keys: 0, .. }".into()
            ),
            "no answer crosses the request boundary"
        );
    }

    #[test]
    fn overlay_route_inventory_carries_mask_and_overlay_authority() {
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionMountInventoryOutcome;
        use brokk_bifrost_core::analyzer::project::OverlayProject;
        use std::sync::Arc;

        let fixture = readiness_fixture();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let overlay = OverlayProject::new(fixture.project_dyn());
        let file = fixture.file("src/part.rs");
        assert!(overlay.set(file.abs_path(), "pub fn changed() {}\n".to_owned()));
        let prepared = disk.clone_with_project(Arc::new(overlay.snapshot()));
        assert!(!prepared.declarations(&file).is_empty());
        let inventory = match prepared
            .open_selected_rust_inventory(
                &brokk_bifrost_core::cancellation::CancellationToken::default(),
            )
            .unwrap()
        {
            SelectedResolutionMountInventoryOutcome::Ready(inventory) => inventory,
            _ => panic!("overlay inventory unavailable"),
        };
        assert!(
            inventory
                .overlay_masks()
                .unwrap()
                .iter()
                .any(|mask| mask.persisted_relative_path() == "src/part.rs")
        );
        let authority: i64 = inventory.connection().query_row(
            "SELECT overlay_authority_kind FROM temp.selected_resolution_content_mounts WHERE persisted_relative_path='src/part.rs'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(authority, 1, "live overlay authority");
        assert!(!inventory.reader_binding().unwrap().proves_main_selection());
        let ledger = Arc::new(brokk_bifrost_analysis::analyzer::ReadLedger::new());
        let _scope = AnalyzerQueryScope::with_read_ledger(&prepared, ledger.clone());
        let _ = <RustAnalyzer as RustSource>::file_routes(&prepared, &file, None);
        assert!(ledger.reuse_refused());
    }

    #[test]
    fn unavailable_route_demand_records_failure_without_publishing_receipt() {
        use super::super::route_kinds::{RustFileUnits, RustUnitRoutes};
        use brokk_bifrost_analysis::analyzer::derivation_host::AnalyzerDerivations;
        use brokk_bifrost_core::analyzer::pool_memo::PoolSafeMemo;
        use brokk_bifrost_core::retention_budget::RetentionBudget;
        use brokk_bifrost_semantic::analyzer::semantic::derivation::{Demanded, UnavailableCause};

        let fixture = readiness_fixture();
        let workspace = fixture.certified_workspace_analyzer(
            brokk_bifrost_core::analyzer::config::AnalyzerConfig::default(),
        );
        let analyzer = brokk_bifrost_analysis::analyzer::resolve_analyzer::<RustAnalyzer>(
            workspace.analyzer(),
        )
        .expect("Rust analyzer");
        let host = AnalyzerDerivations::new(&RetentionBudget::new(1_000_000));
        let unit = analyzer
            .with_selected_route_demands(None, |inventory| {
                match host.demand::<RustFileUnits>(analyzer, inventory, &"src/lib.rs".to_owned()) {
                    Demanded::Available { value, .. } => Ok(value[0].clone()),
                    Demanded::Unavailable(cause) => Err(cause),
                }
            })
            .expect("selected library unit");
        analyzer.analyzer_store().drop_rust_modules_table_for_test();
        let memo = PoolSafeMemo::new();
        let scope = AnalyzerQueryScope::new(analyzer);
        let demanded = std::cell::Cell::new(false);
        let result = analyzer.memoized_route_index(&memo, &|| true, || {
            analyzer.with_selected_route_demands(None, |inventory| {
                match host.demand::<RustUnitRoutes>(analyzer, inventory, &unit) {
                    Demanded::Unavailable(cause @ UnavailableCause::Failed(_)) => {
                        demanded.set(true);
                        Err::<(), _>(cause)
                    }
                    _ => panic!("expected failed route demand"),
                }
            })
        });
        assert!(demanded.get(), "the route demand must execute");
        assert!(matches!(result, Err(RustCargoRouteError::Unavailable)));
        assert!(scope.store_error().is_some());
        // The memo entry owns the captured read receipt. A failed request
        // must publish neither an answer nor that receipt for later reuse.
        assert!(memo.get().is_none());
    }

    fn readiness_fixture() -> BuiltInlineTestProject {
        InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"routes\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "pub mod part;\n")
            .file("src/part.rs", "pub fn target() {}\n")
            .build()
    }

    fn module_route_fixture(temp: &tempfile::TempDir) -> PathBuf {
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[package]\nname = \"routes\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        write(&root, "src/lib.rs", "pub mod plain;\n");
        write(&root, "src/plain.rs", "pub struct Marker;\n");
        root
    }

    #[test]
    fn incomplete_live_blob_is_not_filtered_out_of_route_readiness() {
        let fixture = readiness_fixture();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/part.rs");
        let oid = analyzer
            .live_path_snapshot()
            .oid_for_path(&file)
            .expect("live file identity");
        analyzer
            .analyzer_store()
            .mark_parsed_blob_incomplete_for_test(&brokk_bifrost_core::gitblob::BlobKey::unvaried(
                oid, "rust",
            ));
        {
            let scope = AnalyzerQueryScope::new(&analyzer);
            assert!(matches!(
                analyzer.file_routes(&fixture.file("src/lib.rs"), Some(&|| true)),
                Err(RustCargoRouteError::Unavailable)
            ));
            assert!(scope.store_error().is_some());
        }
        analyzer.warm_usage_facts();
        assert!(analyzer.rust_usage_facts_ready());
        let routes = analyzer
            .file_routes(&fixture.file("src/lib.rs"), Some(&|| true))
            .expect("repaired live publication");
        assert_eq!(routes.target_roots(&file), vec![fixture.file("src/lib.rs")]);
    }

    #[test]
    fn cancelled_route_read_can_be_retried() {
        let fixture = readiness_fixture();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        assert!(matches!(
            analyzer.file_routes(&fixture.file("src/lib.rs"), Some(&|| false)),
            Err(RustCargoRouteError::Cancelled)
        ));
        assert!(
            analyzer
                .file_routes(&fixture.file("src/lib.rs"), Some(&|| true))
                .is_ok()
        );
    }
    #[test]
    fn unparseable_live_rust_files_do_not_break_canonical_routes() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"routes\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "pub mod part;\n")
            .file("src/part.rs", "pub fn target() {}\n")
            .file("tests/ui/rust-macro.rs", "fn main() {\0}\n")
            .build();
        let file = fixture.file("tests/ui/rust-macro.rs");
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let scope = AnalyzerQueryScope::new(&analyzer);

        let routes = analyzer
            .file_routes(&fixture.file("src/lib.rs"), None)
            .expect("unparseable source does not withhold published routes");

        assert_eq!(
            routes.target_roots(&fixture.file("src/part.rs")),
            vec![fixture.file("src/lib.rs")]
        );
        assert!(
            analyzer
                .rust_files_without_facts()
                .expect("unparseable source is outside the catch-up set")
                .is_empty()
        );
        let snapshots = analyzer.inner.selected_workspace_snapshots();
        let overlays = analyzer
            .inner
            .selected_rust_resolution_overlay_inputs(
                snapshots.as_ref(),
                &brokk_bifrost_core::cancellation::CancellationToken::default(),
            )
            .expect("selected overlays are available");
        let SelectedResolutionOverlayInputsOutcome::Ready {
            masks,
            content_mounts,
        } = overlays
        else {
            panic!("unparseable source does not withhold selected overlays");
        };
        assert!(
            content_mounts
                .iter()
                .all(|mount| mount.persisted_relative_path() != "tests/ui/rust-macro.rs")
        );
        let languages = [SelectedResolutionLanguage::new("rust", Language::Rust)];
        let input = SelectedResolutionOperationInput::new(
            analyzer.inner.project(),
            analyzer.inner.workspace_id(),
            snapshots.as_ref(),
            &languages,
            &masks,
        )
        .with_content_mounts(content_mounts);
        let selected_operation = analyzer
            .inner
            .analyzer_store()
            .open_selected_resolution_operation(
                input,
                &brokk_bifrost_core::cancellation::CancellationToken::default(),
            )
            .expect("selected operation is available");
        assert!(
            matches!(
                &selected_operation,
                SelectedResolutionOperationOpenOutcome::Ready(_)
            ),
            "selected operation outcome: {selected_operation:?}"
        );
        drop(selected_operation);
        assert!(scope.read_completion().is_err());
        let refused = analyzer
            .file_routes(&file, None)
            .expect("refused source yields partial routes");
        assert!(!refused.is_complete());
        assert!(scope.store_error().is_none());
        analyzer.warm_usage_facts();
        assert!(analyzer.rust_usage_facts_ready());
    }

    // Pins the replay rule: a stable reason recorded while the memoized route
    // index was built is reported by every later retained fill in the request.
    // Whether a real unparseable member reaches that recorder is open (#8655).
    #[test]
    fn route_memo_replays_structure_gap_in_later_retained_fill() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"routes\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "pub mod part;\n")
            .file("src/part.rs", "pub fn target() {\0}\n")
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let malformed = fixture.file("src/part.rs");
        let oid = analyzer
            .live_path_snapshot()
            .oid_for_path(&malformed)
            .expect("live malformed member");
        let cold = std::sync::atomic::AtomicBool::new(true);
        let keep_going = || {
            // Refused files are absent from selected summary rows. Exercise the
            // same recorder at the route builder's read boundary.
            if cold.load(std::sync::atomic::Ordering::Relaxed) {
                assert!(
                    analyzer
                        .inner
                        .record_structure_unavailable_if_unparseable(&malformed, oid)
                );
            }
            true
        };
        let _request = AnalyzerQueryScope::new(&analyzer);
        for pass in 0..2 {
            let fill = AnalyzerQueryScope::for_retained_fill(&analyzer);
            let _routes = analyzer
                .file_routes(&fixture.file("src/lib.rs"), Some(&keep_going))
                .expect("published Cargo routes");
            cold.store(false, std::sync::atomic::Ordering::Relaxed);
            let completion = fill.read_completion();
            assert!(
                matches!(
                    completion,
                    Err(QueryReadIncomplete::StructureUnavailable(_))
                ),
                "pass {pass}: {completion:?}"
            );
        }
    }

    // Two policy units run in one outer request scope: the first fills the route
    // and package memos, the second hits them. The hit must leave the second
    // unit's ledger holding every read the fill recorded, or an edit that
    // changes the fill's input fails the first unit's reuse and not the second's.
    // As in the test above, the recorder is called at the build's read boundary
    // because a real refused member does not reach it (#8655).
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#7262: a Rust route memo hit dropped the fill's file read"
    )]
    fn route_memo_hit_records_the_fills_file_read_in_the_second_units_ledger() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"routes\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "pub mod part;\n")
            .file("src/part.rs", "pub fn target() {\0}\n")
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let malformed = fixture.file("src/part.rs");
        let oid = analyzer
            .live_path_snapshot()
            .oid_for_path(&malformed)
            .expect("live malformed member");
        let cold = std::sync::atomic::AtomicBool::new(true);
        let keep_going = || {
            if cold.load(std::sync::atomic::Ordering::Relaxed) {
                assert!(
                    analyzer
                        .inner
                        .record_structure_unavailable_if_unparseable(&malformed, oid)
                );
            }
            true
        };
        let _request = AnalyzerQueryScope::new(&analyzer);
        let mut unit_keys = Vec::new();
        for unit in 0..2 {
            let ledger = std::sync::Arc::new(brokk_bifrost_analysis::analyzer::ReadLedger::new());
            let scope = AnalyzerQueryScope::with_read_ledger(&analyzer, ledger.clone());
            let token = brokk_bifrost_analysis::analyzer::QueryScope::token(&scope);
            analyzer
                .file_routes(&fixture.file("src/lib.rs"), Some(&keep_going))
                .expect("published Cargo routes");
            <RustAnalyzer as RustSource>::package_contains(
                &analyzer,
                token,
                &fixture.file("src/lib.rs"),
                Some(&keep_going),
            )
            .expect("published package membership");
            cold.store(false, std::sync::atomic::Ordering::Relaxed);
            let mut keys = ledger.keys();
            keys.sort_by_cached_key(|key| format!("{key:?}"));
            assert!(!keys.is_empty(), "unit {unit} recorded no read");
            unit_keys.push(keys);
        }
        assert_eq!(
            unit_keys[0], unit_keys[1],
            "the memo hit recorded fewer reads than the fill"
        );
    }

    #[test]
    fn malformed_empty_inner_attribute_keeps_canonical_route_publication() {
        let malformed = "#![]\n#![p = ]\n#![p::]\n#![p:: =]\n#![unsafe]\n#![unsafe =]\n";
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"routes\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "pub mod part;\n")
            .file("src/part.rs", "pub fn target() {}\n")
            .file("tests/ui/rust-macro.rs", malformed)
            .build();
        let file = fixture.file("tests/ui/rust-macro.rs");
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let scope = AnalyzerQueryScope::new(&analyzer);

        let routes = analyzer
            .file_routes(&fixture.file("src/lib.rs"), None)
            .expect("recovered syntax still publishes the file-root route facts");

        assert_eq!(
            routes.target_roots(&fixture.file("src/part.rs")),
            vec![fixture.file("src/lib.rs")]
        );
        assert!(
            scope.store_error().is_none(),
            "store error for {file:?}: {:?}",
            scope.store_error()
        );
    }

    #[test]
    fn duplicate_rust_declarations_keep_visibility_specific_metadata_rows() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"routes\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "pub struct Duplicate;\nstruct Duplicate;\n")
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let scope = AnalyzerQueryScope::new(&analyzer);

        analyzer
            .file_routes(&fixture.file("src/lib.rs"), None)
            .expect("source declarations with distinct visibility publish independently");

        assert!(
            scope.store_error().is_none(),
            "store error: {:?}",
            scope.store_error()
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "36d2ca4645e4: passthrough item macros must preserve their Cargo route and lexical visibility"
    )]
    fn passthrough_macro_routes_require_faithful_item_replay_and_lexical_visibility() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[package]\nname = \"macros\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        let source = r#"
macro_rules! replay {
    ($($item:item)*) => { $( #[cfg(any())] $item )* };
}
replay! { mod replayed; }

late! { mod defined_too_late; }
macro_rules! late {
    ($($item:item)*) => { $($item)* };
}

macro_rules! feature_items {
    (#![$meta:meta] $($item:item)*) => { $( #[$meta] $item )* };
}
feature_items! { #![cfg(any())] mod feature_replayed; }

macro_rules! delegated_items {
    ($($item:item)*) => { $( #[cfg(any())] $item )* };
}
macro_rules! nested_delegated_items {
    ($($item:item)*) => {
        #[cfg(unix)]
        delegated_items! { $($item)* }
    };
}
nested_delegated_items! { mod transitively_replayed; }

macro_rules! dropped {
    ($($left:item)* $($right:item)*) => { $($left)* };
}
dropped! { mod dropped_left; mod dropped_right; }

macro_rules! stringified {
    ($($item:item)*) => { stringify!($($item)*) };
}
stringified! { mod stringified_item; }

macro_rules! nested {
    ($($item:item)*) => { wrapper! { $($item)* } };
}
nested! { mod nested_item; }

macro_rules! mixed {
    ($name:ident, $item:item) => { $item };
}
mixed! { marker, mod mixed_item; }

macro_rules! shadowed {
    ($($item:item)*) => { $($item)* };
}
shadowed! { mod before_shadow; }
macro_rules! shadowed {
    (mod $name:ident;) => {};
}
shadowed! { mod after_shadow; }

macro_rules! scoped {
    ($($item:item)*) => { $($item)* };
}
mod inline_scope {
    macro_rules! scoped {
        (mod $name:ident;) => {};
    }
    scoped! { mod inner_shadowed; }

    macro_rules! inline_only {
        ($($item:item)*) => { $($item)* };
    }
    inline_only! { mod inline_replayed; }
}
scoped! { mod outer_replayed; }
inline_only! { mod escaped_inline; }
"#;
        write(&root, "src/lib.rs", source);
        for module in [
            "replayed",
            "feature_replayed",
            "transitively_replayed",
            "defined_too_late",
            "dropped_left",
            "dropped_right",
            "stringified_item",
            "nested_item",
            "mixed_item",
            "before_shadow",
            "after_shadow",
            "inner_shadowed",
            "inline_scope/inline_replayed",
            "outer_replayed",
            "escaped_inline",
        ] {
            write(&root, &format!("src/{module}.rs"), "pub struct Marker;\n");
        }

        let library = ProjectFile::new(root.clone(), "src/lib.rs");
        let analyzer = crate::analyzer::RustAnalyzer::from_project(
            brokk_bifrost_core::analyzer::project::TestProject::new(
                root.clone(),
                brokk_bifrost_core::analyzer::model::Language::Rust,
            ),
        );
        // `feature_items` decorates each item with `#[$meta]`, which can be
        // any attribute: the crate does not decide its invocations
        // (`source_rust_item_macros.decoration_cfg` is NULL), so the route
        // index does not claim the module either. A `cfg` decoration, even
        // one no profile activates (`cfg(any())`), is decided; the index
        // evaluates no profile and leaves that to the crate's module walk.
        for module in [
            "replayed",
            "transitively_replayed",
            "before_shadow",
            "inline_scope/inline_replayed",
            "outer_replayed",
        ] {
            let file = ProjectFile::new(root.clone(), format!("src/{module}.rs"));
            let routes = analyzer.file_routes(&file, None).expect("module routes");
            assert_eq!(
                routes.target_roots(&file),
                std::slice::from_ref(&library),
                "{module} should be emitted by the latest visible passthrough macro"
            );
        }
        for module in [
            "feature_replayed",
            "dropped_left",
            "dropped_right",
            "stringified_item",
            "nested_item",
            "mixed_item",
            "after_shadow",
            "inner_shadowed",
            "escaped_inline",
            "defined_too_late",
        ] {
            let file = ProjectFile::new(root.clone(), format!("src/{module}.rs"));
            let routes = analyzer.file_routes(&file, None).expect("module routes");
            assert!(
                routes.target_roots(&file).is_empty(),
                "{module} must not be claimed through an unproven passthrough macro"
            );
        }
    }
    /// A file inside a dependency package belongs to that package's root even
    /// when another workspace member depends on it; test-only reach also
    /// crosses an external module declaration in the app's test target.
    #[test]
    fn cargo_routes_compose_from_rows_across_a_multi_crate_workspace() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[workspace]\nmembers = [\"app\", \"engine\", \"devonly\"]\nresolver = \"2\"\n",
        );
        write(
            &root,
            "engine/Cargo.toml",
            "[package]\nname = \"engine\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        write(&root, "engine/src/lib.rs", "pub mod part;\n");
        write(&root, "engine/src/part.rs", "pub struct Part;\n");
        write(
            &root,
            "devonly/Cargo.toml",
            "[package]\nname = \"devonly\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        write(&root, "devonly/src/lib.rs", "pub struct DevOnly;\n");
        write(
            &root,
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\ntest = false\n\n[dependencies]\nengine = { path = \"../engine\" }\n\n[dev-dependencies]\ndevonly = { path = \"../devonly\" }\n",
        );
        write(
            &root,
            "app/src/lib.rs",
            "pub mod feature;\n#[cfg(test)]\nmod tests;\n",
        );
        write(&root, "app/src/feature.rs", "pub struct Feature;\n");
        write(&root, "app/src/tests.rs", "mod helpers;\n");
        write(&root, "app/src/tests/helpers.rs", "pub fn helper() {}\n");

        let (_workspace, analyzer) = crate::analyzer::rust::test_support::certified_analyzer(&root);
        let routes = analyzer
            .file_routes(&ProjectFile::new(root.clone(), "app/src/feature.rs"), None)
            .expect("published Cargo routes");
        let engine_routes = analyzer
            .file_routes(&ProjectFile::new(root.clone(), "engine/src/lib.rs"), None)
            .expect("engine routes");

        // A graph consumer inside a selected operation must borrow that
        // operation instead of opening an unframed route selection.
        {
            use brokk_bifrost_analysis::analyzer::derivation_host::{
                read_frame, rust_route_question_identity, selected_rust_snapshot,
            };
            use brokk_bifrost_rust::graph_support::RustSource;
            let cancellation = brokk_bifrost_core::cancellation::CancellationToken::default();
            let operation = match analyzer
                .open_selected_rust_operation(&cancellation)
                .outcome
                .expect("selected operation")
            {
                SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
                other => panic!("selected operation: {other:?}"),
            };
            let snapshot =
                selected_rust_snapshot(&operation.ready.inventory).expect("Rust snapshot");
            let mut identity =
                rust_route_question_identity(&analyzer, analyzer.analyzer_store(), snapshot);
            identity.selection = Some(operation.ready.inventory.fingerprint());
            identity.operation = Some(&operation as *const _ as usize);
            let before = read_frame::unframed_route_questions_for_test();
            read_frame::with_operation_read_frame(identity, &operation, || {
                use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;
                use brokk_bifrost_core::analyzer::query_token::QueryScope;
                use std::sync::atomic::{AtomicUsize, Ordering};
                let feature = ProjectFile::new(root.clone(), "app/src/feature.rs");
                let actual = <RustAnalyzer as RustSource>::file_routes(&analyzer, &feature, None)
                    .expect("file routes");
                assert_eq!(
                    actual.target_roots(&feature),
                    vec![ProjectFile::new(root.clone(), "app/src/lib.rs")]
                );
                let scope = AnalyzerQueryScope::new(&analyzer);
                let calls = AtomicUsize::new(0);
                let keep_going = || {
                    if read_frame::read_frame_depth_for_test() > 0
                        && calls.fetch_add(1, Ordering::Relaxed) == 0
                    {
                        assert_eq!(read_frame::read_frame_depth_for_test(), 1);
                        <RustAnalyzer as RustSource>::file_routes(&analyzer, &feature, None)
                            .expect("nested usage route question");
                    }
                    true
                };
                brokk_bifrost_rust::usage::usage_binding_seeds_while(
                    &analyzer,
                    scope.token(),
                    &std::collections::BTreeSet::new(),
                    &keep_going,
                )
                .expect("usage entry inside selected operation");
                assert!(calls.load(Ordering::Relaxed) > 0);
            })
            .expect("operation frame");
            assert_eq!(read_frame::unframed_route_questions_for_test(), before);
        }

        let app_library = ProjectFile::new(root.clone(), "app/src/lib.rs");
        let engine_library = ProjectFile::new(root.clone(), "engine/src/lib.rs");
        let feature = ProjectFile::new(root.clone(), "app/src/feature.rs");
        let tests = ProjectFile::new(root.clone(), "app/src/tests.rs");
        let helpers = ProjectFile::new(root.clone(), "app/src/tests/helpers.rs");
        let part = ProjectFile::new(root.clone(), "engine/src/part.rs");

        assert_eq!(
            routes.target_roots(&feature),
            std::slice::from_ref(&app_library)
        );
        assert_eq!(
            engine_routes.target_roots(&part),
            std::slice::from_ref(&engine_library)
        );
        assert_eq!(
            routes.resolve_crate_root_file_or_unscoped(&feature, "engine", &|name| {
                <RustAnalyzer as RustSource>::unscoped_libraries(&analyzer, name, None)
                    .expect("library routes")
            }),
            Some(engine_library.clone()),
            "a path dependency still resolves across crates"
        );
        assert_eq!(
            routes.resolve_crate_root_file(&feature, "devonly"),
            None,
            "a library with test routing disabled cannot resolve a dev dependency"
        );
        assert_eq!(
            routes.target_relation(&feature, &engine_routes, &part),
            RustCargoTargetRelation::Disjoint
        );
        assert!(
            routes.file_is_test_only(&tests) && routes.file_is_test_only(&helpers),
            "test-only reachability still propagates through the module graph"
        );
        assert!(
            !routes.file_is_test_only(&feature),
            "a production module must stay production"
        );
        let declared: Vec<_> = routes
            .module_declarations_targeting(&tests)
            .declarations
            .into_iter()
            .chain(routes.module_declarations_targeting(&helpers).declarations)
            .map(|declaration| {
                (
                    declaration.declaring_file.rel_path().to_path_buf(),
                    declaration.declaring_module.clone(),
                    declaration.target_file.rel_path().to_path_buf(),
                    declaration.test_gated,
                )
            })
            .collect();
        assert!(
            declared.contains(&(
                PathBuf::from("app/src/lib.rs"),
                "app".to_string(),
                PathBuf::from("app/src/tests.rs"),
                true,
            )),
            "declarations: {declared:?}"
        );
        assert!(
            declared.contains(&(
                PathBuf::from("app/src/tests.rs"),
                "app.tests".to_string(),
                PathBuf::from("app/src/tests/helpers.rs"),
                false,
            )),
            "declarations: {declared:?}"
        );
    }

    #[test]
    fn missing_canonical_routes_are_unavailable_and_retry_after_preparation() {
        let fixture = readiness_fixture();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        assert_eq!(analyzer.get_analyzed_files().len(), 2);
        analyzer.analyzer_store().delete_rust_facts_for_test("rust");
        {
            let scope = AnalyzerQueryScope::new(&analyzer);
            assert!(matches!(
                analyzer.file_routes(&fixture.file("src/lib.rs"), Some(&|| true)),
                Err(RustCargoRouteError::Unavailable)
            ));
            assert!(matches!(
                analyzer.file_routes(&fixture.file("src/lib.rs"), None),
                Err(RustCargoRouteError::Unavailable)
            ));
            assert!(scope.store_error().is_some());
        }
        assert_eq!(analyzer.module_route_fact_fallback_count_for_test(), 0);
        assert!(!analyzer.rust_usage_facts_ready());
        analyzer.warm_usage_facts();
        assert!(analyzer.rust_usage_facts_ready());
        let routes = analyzer
            .file_routes(&fixture.file("src/lib.rs"), Some(&|| true))
            .expect("retry after canonical preparation");
        assert_eq!(
            routes.target_roots(&fixture.file("src/part.rs")),
            vec![fixture.file("src/lib.rs")]
        );
    }

    #[test]
    fn failed_canonical_route_read_never_publishes_a_partial_index() {
        let fixture = readiness_fixture();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        assert_eq!(analyzer.get_analyzed_files().len(), 2);
        analyzer.analyzer_store().drop_rust_modules_table_for_test();
        let scope = AnalyzerQueryScope::new(&analyzer);
        assert!(matches!(
            analyzer.file_routes(&fixture.file("src/lib.rs"), Some(&|| true)),
            Err(RustCargoRouteError::Unavailable)
        ));
        let error = scope
            .store_error()
            .expect("route SQL error must reach the query boundary");
        assert!(error.to_string().contains("Rust"), "{error}");
        assert_eq!(analyzer.module_route_fact_fallback_count_for_test(), 0);
    }

    #[test]
    fn published_files_without_cargo_have_valid_empty_routes() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", "pub fn target() {}\n")
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let routes = analyzer
            .file_routes(&fixture.file("src/lib.rs"), Some(&|| true))
            .expect("no manifest is not missing publication");
        assert!(routes.target_roots(&fixture.file("src/lib.rs")).is_empty());
    }

    #[test]
    fn composing_the_cargo_route_index_parses_no_workspace_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = module_route_fixture(&temp);
        let analyzer = crate::analyzer::RustAnalyzer::from_project(
            brokk_bifrost_core::analyzer::project::TestProject::new(
                root.clone(),
                brokk_bifrost_core::analyzer::model::Language::Rust,
            ),
        );
        // Analysis is what writes the fact rows. A freshly analyzed workspace
        // does not need the catch-up that repairs a live blob analysis did not
        // reach.
        analyzer.reset_module_route_fact_fallback_count_for_test();

        let routes = analyzer
            .file_routes(&ProjectFile::new(root.clone(), "src/lib.rs"), None)
            .expect("published Cargo routes");

        let library = ProjectFile::new(root.clone(), "src/lib.rs");
        assert_eq!(
            routes.target_roots(&ProjectFile::new(root.clone(), "src/plain.rs")),
            std::slice::from_ref(&library),
            "the index still answers from rows"
        );
        assert_eq!(
            analyzer.module_route_fact_fallback_count_for_test(),
            0,
            "composing the Cargo routes must not parse a single workspace file"
        );
    }
}
