#[cfg(test)]
mod go_extraction_tests_global {
    mod go_move_0 {

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::fixture_names::reference_node;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::fixture_names::root_export_token;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::fixture_names::root_import_anchor_semantic;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::fixture_names::root_import_token;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::fixture_names::root_reference_token;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::fixture_names::scope_choice;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::fixture_names::scope_head_node;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::fixture_names::site_type_frontier_semantic;

        use brokk_bifrost_analysis::analyzer::resolution::test_support::binder;
        use brokk_bifrost_core::analyzer::resolution_facts::{
            PositionedIdentifierFact, ResolutionBinderKind, ResolutionCallFact, ResolutionGapFact,
            ResolutionIdentifierRole, ResolutionNameFact, ResolutionSiteKind,
            ResolutionTypeSlotFact, ResolutionTypeSlotRole,
        };

        use brokk_bifrost_core::cancellation::CancellationToken;

        use brokk_bifrost_analysis::analyzer::resolution::batch::BatchResolutionEngine;

        use brokk_bifrost_analysis::analyzer::resolution::local_identity::MountRebaser;

        use brokk_bifrost_analysis::analyzer::resolution::local_identity::ResolutionSemanticIdentitySpace;

        use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedResolutionMountOrdinal;

        use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedSemanticProvenance;

        use brokk_bifrost_analysis::analyzer::resolution::positioned_identifier_for_test as identifier;

        use brokk_bifrost_analysis::analyzer::resolution::model::BindingFragmentId;

        use brokk_bifrost_analysis::analyzer::resolution::model::BindingNodeId;

        use brokk_bifrost_analysis::analyzer::resolution::model::BindingNodeKind;

        use brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts;

        use brokk_bifrost_core::analyzer::structural::resolution::HoistingClass;

        use brokk_bifrost_core::analyzer::Language;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweredCandidateDirection;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweredSemanticRole;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweringCoverageFrontier;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweringGapOrigin;

        use brokk_bifrost_analysis::analyzer::resolution::model::PrecedenceStep;

        use brokk_bifrost_core::analyzer::structural::resolution::PrecedenceTier;

        use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionEngineRuleKind;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind;

        use brokk_bifrost_core::analyzer::structural::resolution::ResolutionGapOriginKind;

        use brokk_bifrost_analysis::analyzer::resolution::local_identity::ResolutionLookupSemanticRecipe;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNameId;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootImportAnchor;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootReferenceSegmentFact;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeSlotId;

        use brokk_bifrost_analysis::analyzer::resolution::model::WitnessStep;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::go_spelling_choice_identity;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lookup_semantic;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::root_import_token_identity;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::root_reference_path_identity;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::go_global_support_0::fragment;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::go_global_support_0::resolve_with_coverage;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::go_global_support_0::root_route_facts;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::go_global_support_0::scope;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::go_global_support_0::semantic;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::go_global_support_0::site;

        #[test]
        fn root_routes_are_source_owned_anchored_and_remount_provisional_to_final() {
            let facts = root_route_facts();
            let provisional = BindingFragmentId::for_test(b"root-route-provisional");
            let final_fragment = BindingFragmentId::for_test(b"root-route-final");
            let provisional_artifact =
                brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
                    provisional,
                    Language::Go,
                    &facts,
                );
            let final_artifact =
                brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
                    final_fragment,
                    Language::Go,
                    &facts,
                );
            let provisional_again =
                brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
                    provisional,
                    Language::Go,
                    &facts,
                );
            let final_again =
                brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
                    final_fragment,
                    Language::Go,
                    &facts,
                );
            let assert_same_artifact =
            |left: &brokk_bifrost_analysis::analyzer::resolution::LoweredResolutionFactsWithIdentityCatalog,
             right: &brokk_bifrost_analysis::analyzer::resolution::LoweredResolutionFactsWithIdentityCatalog| {
                assert_eq!(left.lexical(), right.lexical());
                assert_eq!(left.typed(), right.typed());
                assert_eq!(left.identities(), right.identities());
            };
            assert_same_artifact(&provisional_artifact, &provisional_again);
            assert_same_artifact(&final_artifact, &final_again);

            let import_site = ResolutionSiteId::new(0);
            let root_scope = ResolutionScopeId::new(1);
            let reference = ResolutionSiteId::new(2);
            let namespace = ResolutionNamespace::Type;
            let expected_shared_route = ["example.com", "repo", "dep"].map(|spelling| {
                lookup_semantic(
                    brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(
                    ),
                    Language::Go,
                    namespace,
                    spelling,
                )
            });
            let expected_lookup = lookup_semantic(
                brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
                Language::Go,
                namespace,
                "Item",
            );

            let inspect = |artifact: &brokk_bifrost_analysis::analyzer::resolution::LoweredResolutionFactsWithIdentityCatalog,
                       mounted_fragment| {
            let import_token = root_import_token(mounted_fragment, import_site, namespace);
            let export_token = root_export_token(mounted_fragment, root_scope, namespace);
            let (import_id, import_path) = artifact
                .lexical()
                .paths()
                .iter()
                .find_map(|(id, path)| {
                    path.end()
                        .symbols()
                        .fixed()
                        .iter()
                        .any(|symbol| symbol.symbol() == import_token)
                        .then_some((*id, path))
                })
                .expect("source-owned root import path");
            let (export_id, export_path) = artifact
                .lexical()
                .paths()
                .iter()
                .find_map(|(id, path)| {
                    path.start()
                        .symbols()
                        .fixed()
                        .iter()
                        .any(|symbol| symbol.symbol() == export_token)
                        .then_some((*id, path))
                })
                .expect("source-owned root export path");

            assert_eq!(
                import_path.start().node(),
                scope_head_node(mounted_fragment, root_scope)
            );
            assert_eq!(
                import_path
                    .start()
                    .symbols()
                    .fixed()
                    .iter()
                    .map(|symbol| symbol.symbol())
                    .collect::<Vec<_>>(),
                [expected_lookup]
            );
            assert_eq!(import_path.end().node(), BindingNodeId::universal_root());
            let mut expected_import_root = vec![root_import_anchor_semantic(
                mounted_fragment,
                ResolutionRootImportAnchor::Lexical,
            )];
            expected_import_root.extend(expected_shared_route);
            expected_import_root.extend([import_token, expected_lookup]);
            assert_eq!(
                import_path
                    .end()
                    .symbols()
                    .fixed()
                    .iter()
                    .map(|symbol| symbol.symbol())
                    .collect::<Vec<_>>(),
                expected_import_root
            );
            assert_eq!(
                import_path.start().symbols().tail(),
                import_path.end().symbols().tail()
            );
            assert_eq!(import_path.precedence().len(), 1);
            assert_eq!(
                import_path.precedence()[0],
                PrecedenceStep {
                    tier: PrecedenceTier::LexicalBinding,
                    ordinal: 0,
                    semantic: artifact
                        .identities()
                        .semantic_for_identity(go_spelling_choice_identity(root_scope, None))
                        .expect("Go dot import uses its lexical spelling choice"),
                }
            );
            assert_eq!(
                import_path.witness(),
                [WitnessStep::Node(BindingNodeId::universal_root())]
            );
            assert_eq!(import_path.completion(), &ResolutionCompletion::Complete);

            assert_eq!(export_path.start().node(), BindingNodeId::universal_root());
            assert_eq!(
                export_path
                    .start()
                    .symbols()
                    .fixed()
                    .iter()
                    .map(|symbol| symbol.symbol())
                    .collect::<Vec<_>>(),
                [expected_lookup, export_token]
            );
            assert!(export_path.end().symbols().fixed().is_empty());
            assert_eq!(
                export_path.start().symbols().tail(),
                export_path.end().symbols().tail()
            );
            assert_eq!(export_path.precedence().len(), 1);
            assert_eq!(
                export_path.precedence()[0].tier,
                PrecedenceTier::PackageOrModule
            );
            assert_eq!(export_path.precedence()[0].semantic, export_token);
            assert_eq!(
                export_path.witness(),
                [WitnessStep::Node(export_path.end().node())]
            );
            assert_eq!(export_path.completion(), &ResolutionCompletion::Complete);

            let reference_token = root_reference_token(mounted_fragment, reference, namespace);
            let mut reference_paths = artifact.lexical().paths().iter().filter_map(|(_, path)| {
                (path.start().node() == reference_node(mounted_fragment, reference)).then_some(path)
            });
            let reference_path = reference_paths
                .next()
                .expect("source-owned direct root reference path");
            assert!(
                reference_paths.next().is_none(),
                "a direct root reference must not retain a lexical decoy route"
            );
            assert_eq!(
                reference_path.start().node(),
                reference_node(mounted_fragment, reference)
            );
            assert!(reference_path.start().symbols().fixed().is_empty());
            assert!(reference_path.start().symbols().tail().is_none());
            let mut expected_reference_root = vec![root_import_anchor_semantic(
                mounted_fragment,
                ResolutionRootImportAnchor::Absolute,
            )];
            expected_reference_root.extend(expected_shared_route);
            expected_reference_root.extend([reference_token, expected_lookup]);
            assert_eq!(
                reference_path
                    .end()
                    .symbols()
                    .fixed()
                    .iter()
                    .map(|symbol| symbol.symbol())
                    .collect::<Vec<_>>(),
                expected_reference_root
            );
            assert!(reference_path.end().symbols().tail().is_none());
            assert_eq!(
                reference_path.precedence(),
                [PrecedenceStep {
                    tier: PrecedenceTier::PackageOrModule,
                    ordinal: 0,
                    semantic: scope_choice(mounted_fragment, root_scope, namespace),
                }]
            );
            assert_eq!(
                reference_path.witness(),
                [
                    WitnessStep::Node(scope_head_node(mounted_fragment, root_scope)),
                    WitnessStep::Node(BindingNodeId::universal_root()),
                ]
            );
            assert_eq!(reference_path.completion(), &ResolutionCompletion::Complete);
            assert_eq!(
                artifact
                    .lexical()
                    .semantics()
                    .iter()
                    .find(|semantic| semantic.site() == reference)
                    .and_then(|semantic| semantic.site_metadata())
                    .map(|metadata| metadata.unqualified()),
                Some(false)
            );

            let catalog = artifact.identities();
            assert_eq!(
                catalog
                    .semantic_identity(import_token)
                    .expect("root-import token identity")
                    .space(),
                ResolutionSemanticIdentitySpace::FragmentLocal
            );
            assert_eq!(
                catalog
                    .semantic_identity(export_token)
                    .expect("root-export token identity")
                    .space(),
                ResolutionSemanticIdentitySpace::FragmentLocal
            );
            assert_eq!(
                catalog
                    .semantic_identity(reference_token)
                    .expect("root-reference token identity")
                    .space(),
                ResolutionSemanticIdentitySpace::FragmentLocal
            );
            assert_eq!(
                catalog
                    .semantic_identity(import_path.end().symbols().fixed()[0].symbol())
                    .expect("root-import anchor identity")
                    .space(),
                ResolutionSemanticIdentitySpace::FragmentLocal,
            );
            for root_first in [
                import_path.end().symbols().fixed()[1].symbol(),
                export_path.start().symbols().fixed()[0].symbol(),
            ] {
                assert_eq!(
                    catalog
                        .semantic_identity(root_first)
                        .expect("root-leading lookup identity")
                        .space(),
                    ResolutionSemanticIdentitySpace::Shared,
                    "indexed root endpoints must lead with a Shared lookup semantic"
                );
            }
            let import_identity = catalog
                .path_identity(import_id)
                .expect("dense root-import path identity");
            let export_identity = catalog
                .path_identity(export_id)
                .expect("dense root-export path identity");
            assert_ne!(import_identity, export_identity);
            assert!(artifact.lexical().nodes().iter().all(|(node, kind)| {
                *node != BindingNodeId::universal_root() && *kind != BindingNodeKind::Root
            }));
            (import_token, export_token, import_id, export_id)
        };

            let provisional_rows = inspect(&provisional_artifact, provisional);
            let final_rows = inspect(&final_artifact, final_fragment);
            assert_ne!(provisional_rows, final_rows);
            assert_eq!(
                root_import_token_identity(import_site, namespace),
                provisional_artifact
                    .identities()
                    .semantic_identity(provisional_rows.0)
                    .expect("provisional root-import token identity")
            );
            assert_eq!(
                root_import_token_identity(import_site, namespace),
                final_artifact
                    .identities()
                    .semantic_identity(final_rows.0)
                    .expect("final root-import token identity")
            );

            let mut rebaser = MountRebaser::new();
            let ordinal = SelectedResolutionMountOrdinal::new(final_fragment.ordinal());
            let mount = rebaser.register_mount(ordinal);
            assert!(rebaser.register_identity_catalog(
                ordinal,
                final_artifact.identities(),
                &CancellationToken::new(),
            ));
            let SelectedSemanticProvenance::FragmentLocal(provenance) = rebaser
                .registered_semantic_provenance(final_rows.0)
                .expect("mounted root-import token provenance")
            else {
                panic!("root-import token lost fragment-local provenance")
            };
            assert_eq!(provenance.mount(), mount);
            assert_eq!(
                provenance.identity(),
                root_import_token_identity(import_site, namespace)
            );
            assert_eq!(
            rebaser.registered_semantic_provenance(expected_shared_route[0]),
            Some(SelectedSemanticProvenance::Shared(
                ResolutionLookupSemanticRecipe::new(Language::Go, namespace, "example.com")
                    .identity(brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names()),
            ))
        );

            let provisional_import_token = provisional_rows.0;
            let final_import_path = final_artifact
                .lexical()
                .paths()
                .iter()
                .find_map(|(id, path)| (id == &final_rows.2).then_some(path))
                .expect("final root-import path");
            assert!(
                final_import_path
                    .end()
                    .symbols()
                    .fixed()
                    .iter()
                    .all(|symbol| symbol.symbol() != provisional_import_token),
                "final lowering must not retain a provisional mounted token"
            );

            let mut permuted = facts.clone();
            permuted.root_import_segments.reverse();
            permuted.root_import_demands.reverse();
            permuted.root_exports.reverse();
            let permuted =
                brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
                    final_fragment,
                    Language::Go,
                    &permuted,
                );
            assert_same_artifact(&final_artifact, &permuted);
        }
        #[test]
        fn root_route_fact_index_rejects_sparse_ambiguous_or_unowned_rows() {
            let rejected = |mutate: fn(&mut FileResolutionFacts)| {
                let mut facts = root_route_facts();
                mutate(&mut facts);
                std::panic::catch_unwind(|| {
                let _ = brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_lexical_for_test(
                    fragment(),
                    Language::Go,
                    &facts,
                )
                .0;
            })
            .is_err()
            };

            assert!(rejected(|facts| {
                facts.root_import_segments[1].position = 3;
            }));
            assert!(rejected(|facts| {
                facts.root_import_demands[0].namespace = ResolutionNamespace::TypeOrValue;
            }));
            assert!(rejected(|facts| {
                facts.root_import_segments[0].import_site = ResolutionSiteId::new(99);
            }));
            assert!(rejected(|facts| {
                facts.root_reference_segments[1].position = 3;
            }));
            assert!(rejected(|facts| {
                facts.root_references[0].root_scope = ResolutionScopeId::new(99);
            }));
            assert!(rejected(|facts| {
                facts.root_reference_segments[0].reference = ResolutionSiteId::new(99);
            }));
            assert!(rejected(|facts| {
                facts
                    .identifiers
                    .iter_mut()
                    .find(|identifier| identifier.site == ResolutionSiteId::new(2))
                    .expect("root reference fixture identifier")
                    .role = ResolutionIdentifierRole::Declaration;
            }));
            assert!(rejected(|facts| {
                facts.binders[0].hoisting = HoistingClass::SourceOrder;
            }));
        }
        #[test]
        fn go_root_reference_lowers_both_type_or_value_routes() {
            let facts = root_route_facts();
            let mut ambiguous_facts = facts.clone();
            ambiguous_facts.names.push(ResolutionNameFact {
                id: ResolutionNameId::new(4),
                spelling: "model".to_owned(),
            });
            ambiguous_facts
                .sites
                .push(site(3, 1, ResolutionSiteKind::ValueReference, 30));
            ambiguous_facts.identifiers.push(PositionedIdentifierFact {
                site: ResolutionSiteId::new(3),
                name: ResolutionNameId::new(4),
                role: ResolutionIdentifierRole::Reference,
                namespace: ResolutionNamespace::TypeOrValue,
                qualifier: None,
            });
            ambiguous_facts.root_references[0].anchor = ResolutionRootImportAnchor::Lexical;
            ambiguous_facts.root_references[0].prefix_reference = Some(ResolutionSiteId::new(3));
            ambiguous_facts.root_reference_segments = vec![ResolutionRootReferenceSegmentFact {
                reference: ResolutionSiteId::new(2),
                position: 0,
                name: ResolutionNameId::new(4),
            }];
            ambiguous_facts
                .identifiers
                .iter_mut()
                .find(|identifier| identifier.site == ResolutionSiteId::new(2))
                .expect("root reference fixture identifier")
                .namespace = ResolutionNamespace::TypeOrValue;
            let (ambiguous, identities) =
                brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_lexical_for_test(
                    fragment(),
                    Language::Go,
                    &ambiguous_facts,
                );
            for namespace in [ResolutionNamespace::Value, ResolutionNamespace::Type] {
                let identity = root_reference_path_identity(ResolutionSiteId::new(2), namespace);
                assert!(
                    ambiguous
                        .paths()
                        .iter()
                        .any(|(path, _)| { identities.path_identity(*path) == Some(identity) }),
                    "Go root terminal keeps its {namespace:?} route"
                );
            }
            let mut qualified_ambiguous_facts = ambiguous_facts.clone();
            qualified_ambiguous_facts
                .identifiers
                .iter_mut()
                .find(|identifier| identifier.site == ResolutionSiteId::new(2))
                .expect("Go root terminal")
                .qualifier = Some(ResolutionTypeSlotId::new(0));
            qualified_ambiguous_facts
                .type_slots
                .push(ResolutionTypeSlotFact {
                    id: ResolutionTypeSlotId::new(0),
                    site: ResolutionSiteId::new(2),
                    role: ResolutionTypeSlotRole::Receiver,
                });
            let (qualified_ambiguous, _) =
                brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_lexical_for_test(
                    fragment(),
                    Language::Go,
                    &qualified_ambiguous_facts,
                );
            assert!(
                !qualified_ambiguous.gaps().iter().any(|gap| {
                    gap.site() == ResolutionSiteId::new(2)
                        && gap.origin() == LoweringGapOrigin::QualifiedReference
                }),
                "a Go type-or-value root terminal is resolved by the selected root route"
            );
            let anchors = brokk_bifrost_analysis::analyzer::resolution::selected_context::CatalogRootImportAnchors::new(&identities);
            let reference_halves = ambiguous
            .paths()
            .iter()
            .filter_map(|(path, partial)| {
                brokk_bifrost_analysis::analyzer::resolution::selected_context::classify_selected_root_path_half(
                    &anchors,
                    brokk_bifrost_analysis::analyzer::resolution::batch::CandidatePathIdentity::new(fragment(), *path),
                    partial,
                    &brokk_bifrost_core::cancellation::CancellationToken::default(),
                )
                .expect("catalog answers its own root import anchors")
            })
            .filter_map(|half| match half {
                brokk_bifrost_analysis::analyzer::resolution::selected_context::SelectedRootPathHalf::Reference {
                    prefix_reference: Some(_),
                    route,
                    ..
                } => Some(route),
                _ => None,
            })
            .collect::<Vec<_>>();
            assert_eq!(reference_halves.len(), 2);
            assert!(reference_halves.iter().all(|route| route.is_empty()));
            // Rust's root prefix rule names a type and publishes no
            // type-or-value terminal, so the Go-shaped fact is rejected there.
            assert!(
            std::panic::catch_unwind(|| {
                let _ = brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_lexical_for_test(
                    fragment(),
                    Language::Rust,
                    &ambiguous_facts,
                );
            })
            .is_err()
        );
        }
        #[test]
        fn root_import_accepts_an_owned_package_attachment_scope() {
            let mut facts = root_route_facts();
            facts.scopes[1].owner = Some(ResolutionSiteId::new(1));

            let lowered =
            brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_lexical_for_test(fragment(), Language::Go, &facts).0;
            assert!(!lowered.paths().is_empty());
        }
        #[test]
        fn unsupported_expression_type_is_a_type_frontier_not_an_inventory_gap() {
            let facts = FileResolutionFacts {
                scopes: vec![scope(0, None, 0, 100)],
                sites: vec![site(0, 0, ResolutionSiteKind::UnsupportedExpression, 20)],
                gaps: vec![ResolutionGapFact::new(
                    ResolutionSiteId::new(0),
                    ResolutionGapKind::UnsupportedExpressionType,
                )],
                ..FileResolutionFacts::default()
            };
            let lowered =
            brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_lexical_for_test(fragment(), Language::Go, &facts).0;
            assert!(!lowered.gaps().iter().any(|gap| {
                matches!(
                    gap.frontier(),
                    LoweringCoverageFrontier::Enumeration
                        | LoweringCoverageFrontier::CandidateInventory {
                            direction: LoweredCandidateDirection::Reverse,
                        }
                )
            }));
            assert!(lowered.gaps().iter().any(|gap| {
                gap.origin()
                    == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedExpressionType)
                    && gap.frontier()
                        == LoweringCoverageFrontier::Type {
                            frontier: site_type_frontier_semantic(
                                fragment(),
                                ResolutionSiteId::new(0),
                            ),
                        }
            }));
            assert_eq!(
                LoweringGapOrigin::from_kind(ResolutionGapOriginKind::UnsupportedExpressionType)
                    .kind(),
                ResolutionGapOriginKind::UnsupportedExpressionType
            );
        }
        #[test]
        fn pending_call_applicability_is_local_across_point_reverse_and_broad_reads() {
            let facts = FileResolutionFacts {
                names: vec![ResolutionNameFact {
                    id: ResolutionNameId::new(0),
                    spelling: "call".into(),
                }],
                scopes: vec![scope(0, None, 0, 100)],
                sites: vec![
                    site(0, 0, ResolutionSiteKind::CallableDeclaration, 1),
                    site(1, 0, ResolutionSiteKind::CallableReference, 20),
                    site(2, 0, ResolutionSiteKind::Call, 20),
                ],
                identifiers: vec![
                    identifier(
                        0,
                        0,
                        ResolutionIdentifierRole::Declaration,
                        ResolutionNamespace::Callable,
                    ),
                    identifier(
                        1,
                        0,
                        ResolutionIdentifierRole::Reference,
                        ResolutionNamespace::Callable,
                    ),
                ],
                binders: vec![binder(
                    0,
                    0,
                    ResolutionBinderKind::Callable,
                    HoistingClass::ScopeWide,
                    0,
                    100,
                )],
                type_slots: vec![ResolutionTypeSlotFact {
                    id: ResolutionTypeSlotId::new(0),
                    site: ResolutionSiteId::new(2),
                    role: ResolutionTypeSlotRole::CallResult,
                }],
                calls: vec![ResolutionCallFact {
                    call: ResolutionSiteId::new(2),
                    callee: ResolutionSiteId::new(1),
                    receiver: None,
                    result: ResolutionTypeSlotId::new(0),
                    extra_result_slots: Vec::new(),
                    explicit_type_argument_count: 0,
                }],
                gaps: vec![ResolutionGapFact::new(
                    ResolutionSiteId::new(1),
                    ResolutionGapKind::UnsupportedCallApplicability,
                )],
                ..FileResolutionFacts::default()
            };
            let lowered =
            brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
            assert!(!lowered.gaps().iter().any(|gap| {
                matches!(
                    gap.frontier(),
                    LoweringCoverageFrontier::Fragment
                        | LoweringCoverageFrontier::Enumeration
                        | LoweringCoverageFrontier::CandidateInventory { .. }
                )
            }));
            let definition = semantic(&lowered, 0, LoweredSemanticRole::Definition);
            let point = resolve_with_coverage(lowered.clone(), 1);
            assert_eq!(point.targets(), &[definition]);
            assert!(matches!(
                point.completion(),
                ResolutionCompletion::Incomplete(_)
            ));

            let source =
            brokk_bifrost_analysis::analyzer::resolution::engine::PreloadedFragmentSource::from_lowered_fragments([lowered]);
            let reverse = BatchResolutionEngine::new(&source)
                .references_to(definition, &CancellationToken::new())
                .expect("reverse callable lookup");
            assert_eq!(reverse.references().len(), 1);
            assert!(matches!(
                reverse.completion(),
                ResolutionCompletion::Incomplete(_)
            ));
            let broad = BatchResolutionEngine::new(&source)
                .stream_all_reference_batches(8, &CancellationToken::new(), &mut |_| Ok(()))
                .expect("broad callable lookup");
            assert!(matches!(
                broad.completion(),
                ResolutionCompletion::Incomplete(_)
            ));

            let mut go_facts = facts.clone();
            go_facts.engine_rule_eligibilities.push(
            brokk_bifrost_core::analyzer::resolution_facts::ResolutionEngineRuleEligibilityFact {
                site: ResolutionSiteId::new(2),
                rule: ResolutionEngineRuleKind::ArgumentIndependentBinding,
            },
        );
            let go_lowered = brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_lexical_for_test(
            fragment(),
            Language::Go,
            &go_facts,
        )
        .0;
            assert!(!go_lowered.gaps().iter().any(|gap| {
                gap.origin()
                    == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedCallApplicability)
                    && matches!(gap.frontier(), LoweringCoverageFrontier::Reference { .. })
            }));
            let go_definition = semantic(&go_lowered, 0, LoweredSemanticRole::Definition);
            let go_point = resolve_with_coverage(go_lowered.clone(), 1);
            assert_eq!(go_point.targets(), &[go_definition]);
            assert_eq!(go_point.completion(), &ResolutionCompletion::Complete);
            let go_source =
            brokk_bifrost_analysis::analyzer::resolution::engine::PreloadedFragmentSource::from_lowered_fragments([go_lowered]);
            let go_reverse = BatchResolutionEngine::new(&go_source)
                .references_to(go_definition, &CancellationToken::new())
                .expect("Go reverse callable lookup");
            assert_eq!(go_reverse.references().len(), 1);
            assert_eq!(go_reverse.completion(), &ResolutionCompletion::Complete);
        }
    }
    mod go_move_1 {

        use brokk_bifrost_core::analyzer::Language;
        use brokk_bifrost_core::analyzer::resolution_facts::{
            ResolutionNamespace, ResolutionRootImportAnchor, ResolutionScopeId, ResolutionSiteId,
        };

        use brokk_bifrost_analysis::analyzer::resolution::model::BindingFragmentId;

        use brokk_bifrost_analysis::analyzer::resolution::model::BindingNodeId;

        use brokk_bifrost_core::cancellation::CancellationToken;

        use brokk_bifrost_analysis::analyzer::resolution::batch::CandidatePathIdentity;

        use brokk_bifrost_analysis::analyzer::resolution::model::PartialPath;

        use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

        use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionIncompleteReason;

        use brokk_bifrost_analysis::analyzer::resolution::local_identity::ResolutionLookupSemanticRecipe;

        use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

        use brokk_bifrost_analysis::analyzer::resolution::selected_context::SelectedContextIdentities;

        use brokk_bifrost_analysis::analyzer::resolution::selected_context::SelectedContextOverlayCompilation;

        use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedResolutionMountOrdinal;

        use brokk_bifrost_analysis::analyzer::resolution::selected_context::SelectedRootBridgeDescriptor;

        use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;

        use brokk_bifrost_analysis::analyzer::resolution::selected_context::compile_bridge;

        use brokk_bifrost_analysis::analyzer::resolution::selected_context::compile_selected_context_overlay;

        use brokk_bifrost_analysis::analyzer::resolution::selected_context::compile_selected_context_overlay_in_session;

        use brokk_bifrost_analysis::analyzer::resolution::selected_context::compile_selected_root_bridge;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::root_import_anchor_semantic_identity;

        use brokk_bifrost_analysis::analyzer::resolution::selected_context::go_global_support_1::GoMountTable;

        use brokk_bifrost_analysis::analyzer::resolution::selected_context::go_global_support_1::go_mount_context;

        #[test]
        fn root_bridge_extension_preserves_inventory_and_relation_evidence_at_exact_work_boundary()
        {
            use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
            for count in [0_u32, 1, 128] {
                // One step per added bridge, so a budget of the bridge count is
                // exactly enough and the boundary sits there.
                for limit in [count as usize, count as usize + 1] {
                    let mut source = go_mount_context(0);
                    let target = go_mount_context(1);
                    let reason = ResolutionIncompleteReason::UnsupportedSemantic(
                        SemanticId::for_test(b"inventory-gap"),
                    );
                    source.root_reverse_inventory_completion = ResolutionCompletion::Incomplete(
                        if count == 1 {
                            vec![reason, reason]
                        } else {
                            Vec::new()
                        }
                        .into(),
                    );
                    let demand = ResolutionLookupSemanticRecipe::new(
                        Language::Go,
                        ResolutionNamespace::Value,
                        "Item",
                    );
                    let bridges = (0..count)
                        .map(|ordinal| {
                            SelectedRootBridgeDescriptor::for_test(
                                source.fragment(),
                                Language::Go,
                                ResolutionSiteId::new(ordinal),
                                ResolutionRootImportAnchor::Lexical,
                                target.fragment(),
                                Language::Go,
                                ResolutionScopeId::new(0),
                                vec![demand.clone()],
                                demand.clone(),
                                demand.clone(),
                                ResolutionCompletion::incomplete([
                                    ResolutionIncompleteReason::UnsupportedSemantic(
                                        SemanticId::for_test(ordinal.to_be_bytes()),
                                    ),
                                ]),
                            )
                        })
                        .collect::<Vec<_>>();
                    let oracle = source.root_reverse_inventory_completion.clone();
                    let source_fragment = source.fragment();
                    let table = GoMountTable::from(vec![source.clone(), target]);
                    let lookup = table.lookup();
                    let session = ResolutionSession::bounded(
                        ReceiverAnalysisBudget {
                            max_scope_nodes: limit,
                            ..ReceiverAnalysisBudget::default()
                        },
                        None,
                    );
                    let result = table
                        .context(vec![source])
                        .unwrap()
                        .extend_root_bridges(
                            bridges.clone(),
                            &CancellationToken::default(),
                            Some(&session),
                            &lookup,
                        )
                        .unwrap();
                    let context = result.expect("a budget of one step per added bridge is enough");
                    // The target mount carries neither a relation nor evidence of
                    // its own, so the sparse set keeps only the source.
                    assert_eq!(context.mounts.len(), 1);
                    assert_eq!(context.mounts[0].fragment(), source_fragment);
                    assert_eq!(context.mounts[0].root_reverse_inventory_completion, oracle);
                    assert_eq!(context.mounts[0].root_bridges.as_ref(), bridges.as_slice());
                    assert_eq!(session.finish(()).work().scope_nodes, count as usize);
                }
            }
        }
        /// A context whose mount count differs from the operation's is the one
        /// mistake a caller can still make, and it is rejected before any work.
        #[test]
        fn exact_mount_validation_rejects_a_context_built_for_another_operation() {
            let mount_count = 300_u32;
            // Every mount is complete and carries no bridge, so the context set is
            // empty over three hundred selected mounts.
            let table =
                GoMountTable::from((0..mount_count).map(go_mount_context).collect::<Vec<_>>());
            let context = table
                .context(table.carried())
                .expect("ordered Go mounts form one exact selected context");
            let cancellation = CancellationToken::new();
            let expected = (0..mount_count - 1).map(|ordinal| {
                (
                    SelectedResolutionMountOrdinal::new(ordinal),
                    BindingFragmentId::for_test(ordinal.to_be_bytes()),
                    Language::Go,
                )
            });

            let Err(error) =
                context.validate_exact_mounts(expected.len(), &table.lookup(), &cancellation)
            else {
                panic!("a context wider than the operation is a structural error")
            };
            assert!(
                error
                    .to_string()
                    .contains("more entries than the operation"),
                "{error}"
            );
        }

        #[test]
        fn bridge_compilation_preserves_exact_shared_route_and_mounted_tokens() {
            let source = BindingFragmentId::for_test(b"selected-root-source");
            let target = BindingFragmentId::for_test(b"selected-root-target");
            let route = ResolutionLookupSemanticRecipe::new(
                Language::Go,
                ResolutionNamespace::Value,
                "example.com/dep",
            );
            let source_demand = ResolutionLookupSemanticRecipe::new(
                Language::Go,
                ResolutionNamespace::Value,
                "LocalItem",
            );
            let target_demand = ResolutionLookupSemanticRecipe::new(
                Language::Go,
                ResolutionNamespace::Value,
                "Item",
            );
            let bridge = SelectedRootBridgeDescriptor::for_test(
                source,
                Language::Go,
                ResolutionSiteId::new(7),
                ResolutionRootImportAnchor::Lexical,
                target,
                Language::Go,
                ResolutionScopeId::new(0),
                vec![route.clone()],
                source_demand.clone(),
                target_demand.clone(),
                ResolutionCompletion::Complete,
            );
            let identities = SelectedContextIdentities::new();
            let compiled = compile_selected_context_overlay(
            &brokk_bifrost_analysis::analyzer::resolution::engine::PreloadedFragmentSource::from_lowered_fragments([]),
            &identities,
            std::slice::from_ref(&bridge),
            brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
            &ResolutionCompletion::Complete,
            &CancellationToken::default(),
        )
        .expect("bridge compilation");
            let SelectedContextOverlayCompilation::Ready(compiled) = compiled else {
                panic!("live bridge compilation cannot cancel");
            };
            assert_eq!(compiled.added_candidate_paths.len(), 1);
            let path = &compiled.added_candidate_paths[0].1;
            assert_eq!(
            path.start()
                .symbols()
                .fixed()
                .iter()
                .map(|symbol| symbol.symbol())
                .collect::<Vec<_>>(),
            vec![
                bridge.source_import_anchor,
                route.semantic(brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names()),
                bridge.source_import_token,
                source_demand.semantic(brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names()),
            ]
        );
            assert_eq!(
            path.end()
                .symbols()
                .fixed()
                .iter()
                .map(|symbol| symbol.symbol())
                .collect::<Vec<_>>(),
            vec![
                target_demand.semantic(brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names()),
                bridge.target_export_token,
            ]
        );
            assert!(path.start().scopes().fixed().is_empty());
            assert!(path.end().scopes().fixed().is_empty());
            let mut expected_shared = vec![
                route.identity(
                    brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(
                    ),
                ),
                source_demand.identity(
                    brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(
                    ),
                ),
                target_demand.identity(
                    brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(
                    ),
                ),
            ];
            expected_shared.sort_unstable();
            expected_shared.dedup();
            assert_eq!(compiled.shared_semantic_identities(), expected_shared);
            assert_eq!(
                compiled.fragment_local_semantic_identities(),
                &[(
                    source,
                    root_import_anchor_semantic_identity(ResolutionRootImportAnchor::Lexical),
                )]
            );

            let projection_session = ResolutionSession::bounded(Default::default(), None);
            let projection = compile_selected_root_bridge(
            &brokk_bifrost_analysis::analyzer::resolution::engine::PreloadedFragmentSource::from_lowered_fragments([]),
            &identities,
            &bridge,
            brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
            &CancellationToken::default(),
            &projection_session,
        )
        .expect("one descriptor compiles for stage publication")
        .expect("live descriptor cannot cancel");
            assert_eq!(projection.lexical.fragment(), source);
            assert_eq!(projection.typed.fragment(), source);
            assert_eq!(
                projection.lexical.paths(),
                &[(compiled.added_candidate_paths[0].0.path(), path.clone())],
                "per-producer publication preserves the existing executable relation"
            );
            assert_eq!(
                projection.local_anchor,
                compiled.fragment_local_semantic_identities()[0]
            );
            assert_eq!(
            projection.recipes,
            [route, source_demand, target_demand]
                .into_iter()
                .map(|recipe| (
                    recipe.semantic(brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names()),
                    recipe
                ))
                .collect::<Vec<_>>()
        );
            let repeated_session = ResolutionSession::bounded(Default::default(), None);
            for _ in 0..2 {
                let repeated = compile_selected_root_bridge(
                &brokk_bifrost_analysis::analyzer::resolution::engine::PreloadedFragmentSource::from_lowered_fragments([]),
                &identities,
                &bridge,
                brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
                &CancellationToken::default(),
                &repeated_session,
            )
            .unwrap()
            .unwrap();
                assert_eq!(repeated.identity, projection.identity);
                assert_eq!(repeated.lexical.paths(), projection.lexical.paths());
            }
            assert_eq!(
                repeated_session.finish(()).work().scope_nodes,
                2 * projection_session.finish(()).work().scope_nodes,
                "every derivation is charged before stage admission deduplicates it"
            );
            let cancelled = CancellationToken::default();
            cancelled.cancel();
            assert!(
            compile_selected_root_bridge(
                &brokk_bifrost_analysis::analyzer::resolution::PreloadedFragmentSource::from_lowered_fragments([]),
                &identities,
                &bridge,
                brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
                &cancelled,
                &ResolutionSession::bounded(Default::default(), None),
            )
            .unwrap()
            .is_none()
        );

            let mut other_target = bridge.clone();
            other_target.target_definition =
                Some(BindingNodeId::for_test(b"other-target-definition"));
            let compile_set = |bridges: &[SelectedRootBridgeDescriptor]| {
                let SelectedContextOverlayCompilation::Ready(overlay) =
                compile_selected_context_overlay(
                    &brokk_bifrost_analysis::analyzer::resolution::engine::PreloadedFragmentSource::from_lowered_fragments([]),
                    &SelectedContextIdentities::new(),
                    bridges,
                    brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
                    &ResolutionCompletion::Complete,
                    &CancellationToken::default(),
                )
                .expect("equal derivations form a canonical relation set")
            else {
                panic!("uncancelled relation projection must finish");
            };
                overlay.added_candidate_paths
            };
            // Two compilations are two operations. A path id and a stack variable
            // id are `Operation` identities: the number is the minting
            // operation's own and orders by the order the bridges arrived in, so
            // it says nothing about the relation set. The set therefore compares
            // blind to those numbers, and as a set: sorted, with every other
            // identity -- the fragment-local tokens and the shared route --
            // compared exactly.
            let as_a_set = |paths: &[(CandidatePathIdentity, PartialPath)]| {
                use brokk_bifrost_analysis::analyzer::resolution::mounted::OperationBlind;

                use brokk_bifrost_analysis::analyzer::resolution::mounted::SpliceMount;
                let mut blinded = paths
                    .iter()
                    .map(|(identity, path)| {
                        format!(
                            "{:?}",
                            (
                                identity.splice(&OperationBlind),
                                path.splice(&OperationBlind)
                            )
                        )
                    })
                    .collect::<Vec<_>>();
                blinded.sort();
                blinded
            };
            let expected = compile_set(&[bridge.clone(), other_target.clone()]);
            assert_eq!(expected.len(), 2, "different targets must remain distinct");
            assert_eq!(
                as_a_set(&compile_set(&[
                    other_target.clone(),
                    bridge.clone(),
                    other_target,
                    bridge.clone(),
                ])),
                as_a_set(&expected),
                "set union must be idempotent and independent of derivation order"
            );
            let single_session = ResolutionSession::bounded(Default::default(), None);
            let duplicate_session = ResolutionSession::bounded(Default::default(), None);
            for (derivations, session) in [
                (vec![bridge.clone()], &single_session),
                (vec![bridge.clone(), bridge.clone()], &duplicate_session),
            ] {
                assert!(matches!(
                compile_selected_context_overlay_in_session(
                    &brokk_bifrost_analysis::analyzer::resolution::PreloadedFragmentSource::from_lowered_fragments([]),
                    &SelectedContextIdentities::new(),
                    &derivations,
                    brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
                    &ResolutionCompletion::Complete,
                    &CancellationToken::default(),
                    session,
                )
                .expect("charge every input derivation"),
                SelectedContextOverlayCompilation::Ready(_)
            ));
            }
            assert!(
                duplicate_session.finish(()).work().scope_nodes
                    > single_session.finish(()).work().scope_nodes
            );

            let mut incomplete = bridge.clone();
            incomplete.completion = ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::for_test(
                    b"different-bridge-evidence",
                )),
            ]);
            assert_eq!(
            compile_bridge(
                &brokk_bifrost_analysis::analyzer::resolution::PreloadedFragmentSource::from_lowered_fragments([]),
                &SelectedContextIdentities::new(),
                &bridge,
                brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
                &CancellationToken::default()
            )
            .unwrap()
            .0,
            compile_bridge(
                &brokk_bifrost_analysis::analyzer::resolution::PreloadedFragmentSource::from_lowered_fragments([]),
                &SelectedContextIdentities::new(),
                &incomplete,
                brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
                &CancellationToken::default()
            )
            .unwrap()
            .0
        );
            for derivations in [[bridge.clone(), incomplete.clone()], [incomplete, bridge]] {
                let error = compile_selected_context_overlay(
                &brokk_bifrost_analysis::analyzer::resolution::engine::PreloadedFragmentSource::from_lowered_fragments([]),
                &SelectedContextIdentities::new(),
                &derivations,
                brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
                &ResolutionCompletion::Complete,
                &CancellationToken::default(),
            )
            .err()
            .expect("different completion cannot collapse under one path identity");
                assert!(error.to_string().contains("conflicting derivations"));
            }
        }
    }
    mod go_move_2 {

        use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchBoundaryKind;

        use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchLookup;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

        use brokk_bifrost_core::analyzer::model::Range;

        use brokk_bifrost_analysis::analyzer::usages::call_relations::apply_dispatch_outcome;

        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupOutcome;

        use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;

        #[test]
        fn go_no_definition_does_not_fabricate_an_external_package_identity() {
            let reference = ResolvedReferenceSite {
                path: "main.go".to_owned(),
                text: "missing.Open".to_owned(),
                range: Range {
                    start_byte: 0,
                    end_byte: 12,
                    start_line: 1,
                    end_line: 1,
                },
                focus_start_byte: 8,
                focus_end_byte: 12,
            };
            let outcome = |status| DefinitionLookupOutcome {
                modeled_definitions: Vec::new(),
                status,
                reference: Some(reference.clone()),
                definitions: Vec::new(),
                lexical_definition: None,
                diagnostics: Vec::new(),
            };

            let mut unresolved = CallDispatchLookup::default();
            apply_dispatch_outcome(
                &mut unresolved,
                outcome(DefinitionLookupStatus::NoDefinition),
                1,
                Language::Go,
            );
            assert_eq!(
                unresolved.boundaries,
                vec![CallDispatchBoundaryKind::Unresolved(
                    DefinitionLookupStatus::NoDefinition
                )],
                "dotted spelling without an import-binding proof stays unresolved"
            );

            let mut imported = CallDispatchLookup::default();
            apply_dispatch_outcome(
                &mut imported,
                outcome(DefinitionLookupStatus::UnresolvableImportBoundary),
                1,
                Language::Go,
            );
            assert!(
                matches!(
                    imported.boundaries.as_slice(),
                    [CallDispatchBoundaryKind::External { .. }]
                ),
                "the resolver's proven imported-package boundary remains external: {imported:#?}"
            );
        }
    }
    mod go_move_3 {
        use crate::engine_tests::go_extraction::go_extraction_tests::go_move_11::*;

        use brokk_bifrost_core::cancellation::CancellationToken;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweredSemanticRole;

        use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionContextMetrics;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionLocated;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOutcome;

        use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedSemanticLocator;

        #[test]
        fn go_universe_lookup_survives_the_selected_context_overlay() {
            let consumer = "package consumer\nfunc caller(values []int) { _ = len(values) }\n";
            let fixture = GoRootResolutionOperationFixture::with_consumer(consumer);
            let cancellation = CancellationToken::default();
            let reference = fixture
                .consumer_facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Reference
                        && fixture.consumer_facts.names[identifier.name.index()].spelling == "len"
                        && fixture.consumer_facts.sites[identifier.site.index()].start_byte
                            == consumer.find("len(values)").unwrap()
                })
                .expect("the Go builtin call has a structured callee reference");
            let operation = fixture.open_ready(&cancellation);
            let contexts = operation
                .empty_contexts(&ResolutionCompletion::Complete)
                .expect("empty Go context is available");
            let locator = SelectedSemanticLocator::new(
                "go",
                GO_ROOT_CONSUMER_PATH,
                reference.site,
                LoweredSemanticRole::Reference,
            );
            let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                answer,
            )) = operation
                .resolve_reference(
                    contexts,
                    &locator,
                    &cancellation,
                    &mut SelectedResolutionContextMetrics,
                )
                .expect("selected Go builtin lookup succeeds")
            else {
                panic!("Go builtin answer must be native")
            };
            assert_eq!(answer.binding().targets().len(), 1, "{answer:#?}");
            assert_eq!(
                answer.binding().completion(),
                &ResolutionCompletion::Complete,
                "{answer:#?}"
            );
        }
    }
    mod go_move_4 {
        use crate::engine_tests::go_extraction::go_extraction_tests::go_move_11::*;
        use brokk_bifrost_analysis::native_resolution_test_support::SelectedTypedFactSource;

        use brokk_bifrost_core::cancellation::CancellationToken;

        use brokk_bifrost_test_macros::hardwon;

        use brokk_bifrost_analysis :: analyzer :: store :: resolution_operation :: tests :: native_query_plan_tests :: shared_support :: registry ;

        #[test]
        fn go_target_key_acquisition_access_cost() {
            use brokk_bifrost_analysis::analyzer::store::{AnalyzerStore, PersistBatchTargets};
            use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;
            use brokk_bifrost_core::analyzer::Language;
            use brokk_bifrost_go_analysis::analyzer::go::adapter::GoAdapter;
            use git2::{ObjectType, Oid};
            use rusqlite::{StatementStatus, params};

            const IDENTIFIER_QUERY: &str = "SELECT unit_key FROM code_units WHERE lang = ?1 AND identifier = ?2 AND (in_declarations = 1 OR in_definition_lookup = 1) AND in_declarations = 1 AND blob_id = ?3";
            const BLOB_QUERY: &str = "SELECT unit_key FROM code_units WHERE blob_id = ?1 AND identifier = ?2 AND in_declarations = 1";

            let root = tempfile::tempdir().expect("Go access cost project root");
            let store = AnalyzerStore::open_ephemeral().expect("Go access cost store");
            let generation = store
                .ensure_language_epoch_value("go", "go-access-cost-v1")
                .expect("Go access cost language epoch");
            store
                .ensure_resolution_producer_epoch("go", Language::Go)
                .expect("Go access cost producer epoch");
            let adapter = GoAdapter;

            for size in [20, 100, 300] {
                let mut prepared = Vec::new();
                for ordinal in (if size == 20 {
                    0
                } else if size == 100 {
                    20
                } else {
                    100
                })..size
                {
                    let package = ordinal / 20;
                    let source = format!(
                        "package p{package}\ntype Widget{ordinal} struct{{}}\nfunc (Widget{ordinal}) String() string {{ return \"{ordinal}\" }}\nfunc (Widget{ordinal}) Close() error {{ return nil }}\nfunc Helper{ordinal}() {{}}\n"
                    );
                    let path = format!("p{package}/file{ordinal}.go");
                    let (state, _) = parsed_go_state(root.path(), &path, &source);
                    let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes())
                        .expect("hash Go access cost source");
                    prepared.push(
                        AnalyzerStore::prepare_parsed_blob(
                            &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "go"),
                            generation,
                            &adapter,
                            state,
                        )
                        .expect("prepare Go access cost blob"),
                    );
                }
                let (outcomes, _) =
                    store.persist_prepared_blobs(prepared, PersistBatchTargets::PRODUCTION);
                assert!(
                    outcomes.iter().all(|outcome| outcome.error.is_none()),
                    "{outcomes:#?}"
                );

                store.conn.execute(move |conn| {
                    // Production refreshes planner statistics after building a workspace.
                    conn.execute_batch("PRAGMA analysis_limit = 1000; ANALYZE")
                        .expect("refresh Go access cost statistics");
                    let blob_id: i64 = conn.query_row(
                        "SELECT blob_id FROM code_units WHERE lang = 'go' AND identifier = 'String' AND in_declarations = 1 LIMIT 1",
                        [],
                        |row| row.get(0),
                    ).expect("find a Go String declaration");
                    let mut baseline = None;
                    for (name, sql) in [("identifier", IDENTIFIER_QUERY), ("blob", BLOB_QUERY)] {
                        let explain = format!("EXPLAIN QUERY PLAN {sql}");
                        let mut plan_statement = conn.prepare(&explain).unwrap();
                        let plan: Vec<String> = if name == "identifier" {
                            plan_statement.query_map(params!["go", "String", blob_id], |row| row.get::<_, String>(3)).unwrap()
                                .map(|row| row.unwrap()).collect()
                        } else {
                            plan_statement.query_map(params![blob_id, "String"], |row| row.get::<_, String>(3)).unwrap()
                                .map(|row| row.unwrap()).collect()
                        };
                        let mut statement = conn.prepare(sql).unwrap();
                        let mut rows: Vec<i64> = if name == "identifier" {
                            statement.query_map(params!["go", "String", blob_id], |row| row.get(0)).unwrap()
                                .map(|row| row.unwrap()).collect()
                        } else {
                            statement.query_map(params![blob_id, "String"], |row| row.get(0)).unwrap()
                                .map(|row| row.unwrap()).collect()
                        };
                        rows.sort();
                        assert!(!rows.is_empty(), "{size} files: no target units");
                        if let Some(expected) = &baseline {
                            assert_eq!(&rows, expected, "{size} files: candidate queries disagree");
                        } else {
                            baseline = Some(rows.clone());
                        }
                        eprintln!("go_target_key_access size={size} query={name} plan={plan:?} vm_steps={} fullscan_steps={} rows={}", statement.get_status(StatementStatus::VmStep), statement.get_status(StatementStatus::FullscanStep), rows.len());
                        if name == "identifier" {
                            let steps = statement.get_status(StatementStatus::VmStep);
                            // The full (lang, identifier, blob_id) index from cache
                            // migration 0292 reads the row to check in_declarations,
                            // which the dropped partial index carried: a constant
                            // per candidate row, not growth with the workspace.
                            assert!(steps <= 27, "Query A VM steps grew at {size}: {steps}");
                        }
                    }
                });
            }
        }

        #[test]
        fn go_target_key_selected_query_cost_across_blobs() {
            use brokk_bifrost_analysis::analyzer::store::{AnalyzerStore, PersistBatchTargets};
            use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;
            use brokk_bifrost_go_analysis::analyzer::go::adapter::GoAdapter;
            use git2::{ObjectType, Oid};
            use rusqlite::StatementStatus;

            let fixture = GoRootResolutionOperationFixture::with_sources([
                "package consumer; type Widget struct{}; func (Widget) String() string { return \"x\" }",
                "package provider; func Other() {}",
                "package provider",
            ]);
            publish_go_root_fixture_context(&fixture, "example.test/root/consumer");
            anchor_consumer(&fixture);
            let generation = fixture
                .store
                .ensure_language_epoch_value("go", "resolution-operation-go-root-test-v1")
                .unwrap();
            let adapter = GoAdapter;
            let mut smallest: Option<[i32; 3]> = None;
            for (prior, size) in [(3, 20), (20, 100), (100, 300)] {
                let mut prepared = Vec::new();
                for ordinal in prior..size {
                    let source = format!(
                        "package p; type Widget{ordinal} struct{{}}; func (Widget{ordinal}) String() string {{ return \"x\" }}"
                    );
                    let path = format!("extra/file{ordinal}.go");
                    let (state, _) = parsed_go_state(fixture._project_root.path(), &path, &source);
                    let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();
                    prepared.push(
                        AnalyzerStore::prepare_parsed_blob(
                            &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "go"),
                            generation,
                            &adapter,
                            state,
                        )
                        .unwrap(),
                    );
                }
                let (outcomes, _) = fixture
                    .store
                    .persist_prepared_blobs(prepared, PersistBatchTargets::PRODUCTION);
                assert!(
                    outcomes.iter().all(|outcome| outcome.error.is_none()),
                    "{outcomes:#?}"
                );
                fixture.store.conn.execute(|conn| {
                    conn.execute_batch("PRAGMA analysis_limit = 1000; ANALYZE")
                        .unwrap()
                });
                let cancellation = CancellationToken::new();
                let operation = fixture.open_ready(&cancellation);
                let conn = operation.ready.inventory.connection();
                let (ordinal, blob_id): (i64, i64) = conn.query_row(
                    "SELECT mount_ordinal,blob_id FROM temp.selected_resolution_mounts WHERE persisted_relative_path=?1",
                    [GO_ROOT_CONSUMER_PATH], |row| Ok((row.get(0)?, row.get(1)?)),
                ).unwrap();
                let keys: Vec<i64> = conn.prepare("SELECT unit_key FROM main.code_units WHERE blob_id=?1 AND identifier='String' AND in_declarations=1")
                    .unwrap().query_map([blob_id], |row| row.get(0)).unwrap().map(Result::unwrap).collect();
                assert!(!keys.is_empty());
                let keys_json = serde_json::to_string(&keys).unwrap();
                let mut steps = Vec::new();
                for (name, sql, binds) in [
                    ("acquisition", brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::go_target_key_acquisition_sql_for_test(), vec![rusqlite::types::Value::Integer(ordinal), rusqlite::types::Value::Text("go".to_owned()), rusqlite::types::Value::Text("String".to_owned())]),
                    ("unresolved", brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::go_unresolved_route_sql_for_test(), vec![rusqlite::types::Value::Integer(ordinal)]),
                    ("nomination", brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::go_target_nominated_semantics_sql_for_test(), vec![rusqlite::types::Value::Integer(ordinal), rusqlite::types::Value::Text(keys_json.clone())]),
                ] {
                    let plan: Vec<String> = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                        .unwrap().query_map(rusqlite::params_from_iter(binds.iter()), |row| row.get(3))
                        .unwrap().map(Result::unwrap).collect();
                    let mut statement = conn.prepare(sql).unwrap();
                    let rows: Vec<rusqlite::types::Value> = statement.query_map(rusqlite::params_from_iter(binds.iter()), |row| row.get(0))
                        .unwrap().map(Result::unwrap).collect();
                    let vm = statement.get_status(StatementStatus::VmStep);
                    let fullscan = statement.get_status(StatementStatus::FullscanStep);
                    eprintln!("go_selected_cost size={size} query={name} plan={plan:?} vm_steps={vm} fullscan_steps={fullscan} rows={}", rows.len());
                    assert_eq!(fullscan, 0, "{name} size={size}: {plan:?}");
                    if name == "acquisition" {
                        assert!(plan.iter().any(|line| line.contains("SEARCH units") && line.contains("blob_id=?")), "{name}: {plan:?}");
                    } else {
                        assert!(plan.iter().any(|line| line.contains("SEARCH semantic") && line.contains("blob_id=?")), "{name}: {plan:?}");
                        for alias in ["semantic", "direct", "direct_unit", "bridge", "link", "linked_unit"] {
                            assert!(plan.iter().filter(|line| line.contains(&format!("SEARCH {alias} "))).all(|line| line.contains("blob_id=?")), "{name} {alias}: {plan:?}");
                            assert!(!plan.iter().any(|line| line.contains(&format!("SCAN {alias} "))), "{name} {alias}: {plan:?}");
                        }
                    }
                    steps.push(vm);
                }
                if let Some(first) = smallest {
                    assert!(
                        steps[0] <= first[0],
                        "acquisition grew from {} to {} at {size}",
                        first[0],
                        steps[0]
                    );
                    assert!(
                        steps[1] <= first[1],
                        "unresolved grew from {} to {} at {size}",
                        first[1],
                        steps[1]
                    );
                    assert!(
                        steps[2] <= first[2],
                        "nomination grew from {} to {} at {size}",
                        first[2],
                        steps[2]
                    );
                } else {
                    smallest = Some([steps[0], steps[1], steps[2]]);
                }
            }
        }

        fn anchor_consumer(fixture: &GoRootResolutionOperationFixture) {
            fixture.store.conn.execute(|connection| {
                let version: i64 = connection.query_row(
                    "SELECT file_version_id FROM workspace_file_versions WHERE lang='go' AND rel_path=?1",
                    [GO_ROOT_CONSUMER_PATH],
                    |row| row.get(0),
                ).unwrap();
                connection.execute(
                    "INSERT INTO workspace_file_anchor_rows(file_version_id,anchor_kind,anchor_pop,package_name) VALUES(?1,'own_module',0,'example.test/root/consumer')",
                    [version],
                ).unwrap();
            });
        }

        fn selected_consumer_unit(
            unit: &brokk_bifrost_core::analyzer::model::CodeUnit,
        ) -> brokk_bifrost_core::analyzer::model::CodeUnit {
            let mut fq =
                brokk_bifrost_go::declarations::go_package_fq("example.test/root/consumer");
            for segment in unit.fq().segments().iter().skip(1) {
                fq.push(*segment);
            }
            brokk_bifrost_core::analyzer::model::CodeUnit::from_fq(
                unit.source().clone(),
                unit.kind(),
                fq,
                3,
                unit.signature().map(str::to_owned),
                unit.is_synthetic(),
            )
        }

        #[test]
        fn go_target_keys_match_full_units_and_selected_anchor() {
            use brokk_bifrost_analysis::analyzer::resolution::SelectedResolutionMountOrdinal;
            use brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::GoTargetKeys;
            use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

            let source = "package consumer\ntype Left struct{}\ntype Right struct{}\nfunc (Left) Run() {}\nfunc (Right) Run() {}\nfunc Helper() {}\n";
            let fixture = GoRootResolutionOperationFixture::with_sources([
                source,
                "package provider; func Missing() {}",
                "package provider",
            ]);
            publish_go_root_fixture_context(&fixture, "example.test/root/consumer");
            anchor_consumer(&fixture);
            let (state, _) =
                parsed_go_state(fixture._project_root.path(), GO_ROOT_CONSUMER_PATH, source);
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let conn = operation.ready.inventory.connection();
            let ordinal: u32 = conn.query_row(
                "SELECT mount_ordinal FROM temp.selected_resolution_mounts WHERE persisted_relative_path=?1",
                [GO_ROOT_CONSUMER_PATH], |row| row.get(0),
            ).unwrap();
            let ordinal = SelectedResolutionMountOrdinal::new(ordinal);
            let sql = brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::go_target_key_acquisition_sql_for_test();
            let plan: Vec<String> = conn
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .unwrap()
                .query_map(
                    rusqlite::params![i64::from(ordinal.get()), "go", "Run"],
                    |row| row.get(3),
                )
                .unwrap()
                .map(Result::unwrap)
                .collect();
            assert!(
                plan.iter()
                    .any(|line| line.contains("idx_code_units_lang_identifier (")
                        && line.contains("blob_id=?")),
                "{plan:?}"
            );
            let session = ResolutionSession::unbounded();
            let run_units: Vec<_> = state
                .declarations
                .iter()
                .filter(|unit| unit.identifier() == "Run")
                .collect();
            assert_eq!(run_units.len(), 2);
            for unit in run_units {
                let target = selected_consumer_unit(unit);
                assert_eq!(target.identifier(), "Run");
                let GoTargetKeys::Keys(keys) = operation
                    .ready
                    .go_target_keys_for_test(ordinal, &target, &cancellation, &session)
                    .unwrap()
                else {
                    panic!("Run key unavailable")
                };
                assert_eq!(keys.len(), 1, "receiver identity must disambiguate Run");
            }
            let helper = state
                .declarations
                .iter()
                .find(|unit| unit.identifier() == "Helper")
                .unwrap();
            let target = selected_consumer_unit(helper);
            assert_eq!(target.identifier(), "Helper");
            assert!(
                matches!(operation.ready.go_target_keys_for_test(ordinal, &target, &cancellation, &session).unwrap(), GoTargetKeys::Keys(keys) if keys.len() == 1)
            );
            let (other, _) = parsed_go_state(
                fixture._project_root.path(),
                "other.go",
                "package consumer; func Missing() {}",
            );
            let target = selected_consumer_unit(
                other
                    .declarations
                    .iter()
                    .find(|unit| unit.identifier() == "Missing")
                    .unwrap(),
            );
            assert!(
                matches!(operation.ready.go_target_keys_for_test(ordinal, &target, &cancellation, &session).unwrap(), GoTargetKeys::Keys(keys) if keys.is_empty())
            );
        }

        #[test]
        fn go_target_keys_keep_equal_rows_and_refuse_broken_hydration() {
            use brokk_bifrost_analysis::analyzer::resolution::SelectedResolutionMountOrdinal;
            use brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::GoTargetKeys;
            use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
            use rusqlite::params;

            // "equal" copies the target row under a second key; "corrupt"
            // deletes its structured identity; "unanchored" leaves the module
            // anchor unpublished, so the unit cannot be rebuilt.
            for mode in ["equal", "corrupt", "unanchored"] {
                let corrupt = mode == "corrupt";
                let source = "package consumer; func Helper() {}";
                let fixture = GoRootResolutionOperationFixture::with_sources([
                    source,
                    "package provider",
                    "package provider",
                ]);
                publish_go_root_fixture_context(&fixture, "example.test/root/consumer");
                if mode != "unanchored" {
                    anchor_consumer(&fixture);
                }
                let (state, _) =
                    parsed_go_state(fixture._project_root.path(), GO_ROOT_CONSUMER_PATH, source);
                let target = selected_consumer_unit(
                    state
                        .declarations
                        .iter()
                        .find(|unit| unit.identifier() == "Helper")
                        .unwrap(),
                );
                // Fixture rows: code_units belongs to the sealed blob-row family.
                fixture.store.conn.execute_fixture(move |conn| {
                    conn.execute_batch("PRAGMA foreign_keys = ON; DROP TRIGGER code_unit_fq_segments_no_insert_after_completion; DROP TRIGGER code_unit_fq_segments_no_delete_after_completion").unwrap();
                    let (blob, key): (i64, i64) = conn.query_row(
                        "SELECT blob_id,unit_key FROM code_units WHERE identifier='Helper' AND in_declarations=1 LIMIT 1",
                        [], |row| Ok((row.get(0)?,row.get(1)?)),
                    ).unwrap();
                    if corrupt {
                        conn.execute("DELETE FROM code_unit_fq_segments WHERE blob_id=?1 AND unit_key=?2", params![blob,key]).unwrap();
                    } else if mode == "equal" {
                        let columns: Vec<String> = conn.prepare("PRAGMA table_info(code_units)").unwrap()
                            .query_map([], |row| row.get(1)).unwrap().map(Result::unwrap).collect();
                        let new_key: i64 = conn.query_row("SELECT MAX(unit_key)+1 FROM code_units WHERE blob_id=?1", [blob], |row| row.get(0)).unwrap();
                        let select = columns.iter().map(|column| if column == "unit_key" { "?3".to_string() } else { format!("\"{column}\"") }).collect::<Vec<_>>().join(",");
                        let names = columns.iter().map(|column| format!("\"{column}\"")).collect::<Vec<_>>().join(",");
                        conn.execute(&format!("INSERT INTO code_units ({names}) SELECT {select} FROM code_units WHERE blob_id=?1 AND unit_key=?2"), params![blob,key,new_key]).unwrap();
                        conn.execute("INSERT INTO code_unit_fq_segments(blob_id,lang,unit_key,seg_ordinal,seg_kind,segment) SELECT blob_id,lang,?3,seg_ordinal,seg_kind,segment FROM code_unit_fq_segments WHERE blob_id=?1 AND unit_key=?2", params![blob,key,new_key]).unwrap();
                    }
                    let violations: Vec<String> = conn.prepare("PRAGMA foreign_key_check").unwrap().query_map([], |row| row.get(0)).unwrap().map(Result::unwrap).collect();
                    assert!(violations.is_empty(), "{violations:?}");
                });
                let cancellation = CancellationToken::new();
                let operation = fixture.open_ready(&cancellation);
                let ordinal: u32 = operation.ready.inventory.connection().query_row(
                    "SELECT mount_ordinal FROM temp.selected_resolution_mounts WHERE persisted_relative_path=?1",
                    [GO_ROOT_CONSUMER_PATH], |row| row.get(0),
                ).unwrap();
                let result = operation.ready.go_target_keys_for_test(
                    SelectedResolutionMountOrdinal::new(ordinal),
                    &target,
                    &cancellation,
                    &ResolutionSession::unbounded(),
                );
                match mode {
                    "equal" => assert!(
                        matches!(&result, Ok(GoTargetKeys::Keys(keys)) if keys.len() == 2),
                        "{result:?}"
                    ),
                    "corrupt" => {
                        let error = result.expect_err("a corrupt identity row is a store error");
                        assert!(error.to_string().contains("FqName expected"), "{error:?}");
                    }
                    _ => assert!(
                        matches!(&result, Ok(GoTargetKeys::Unavailable)),
                        "{result:?}"
                    ),
                }
            }
        }

        #[test]
        fn go_unresolved_route_boundary_shapes() {
            use brokk_bifrost_analysis::analyzer::resolution::SelectedResolutionMountOrdinal;
            use brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::GoUnresolvedRoute;
            use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
            use rusqlite::params;

            for mode in [
                "clean",
                "missing_direct",
                "inactive_direct",
                "no_route",
                "root_import",
                "no_links",
                "lexical_no_links",
                "lexical_direct_no_links",
                "without_unit_no_links",
                "anonymous_no_links",
                "inactive_link",
                "direct_no_links",
                "other_file",
                "missing_link_fk",
            ] {
                let source = "package consumer; func Helper() {}";
                let fixture = GoRootResolutionOperationFixture::with_sources([
                    source,
                    "package provider; func Other() {}",
                    "package provider",
                ]);
                publish_go_root_fixture_context(&fixture, "example.test/root/consumer");
                anchor_consumer(&fixture);
                let (state, _) =
                    parsed_go_state(fixture._project_root.path(), GO_ROOT_CONSUMER_PATH, source);
                let target = selected_consumer_unit(
                    state
                        .declarations
                        .iter()
                        .find(|unit| unit.identifier() == "Helper")
                        .unwrap(),
                );
                fixture.store.conn.execute_fixture(move |conn| {
                    conn.execute_batch("PRAGMA foreign_keys=ON; DROP TRIGGER source_declaration_units_no_delete_after_seal; DROP TRIGGER source_declaration_units_no_update_after_seal; DROP TRIGGER source_native_declaration_bridges_no_delete_after_seal; DROP TRIGGER source_declarations_no_update_after_seal; DROP TRIGGER source_go_types_no_insert_after_seal").unwrap();
                    let identifier = if mode == "other_file" { "Other" } else { "Helper" };
                    let (blob, key): (i64, i64) = conn.query_row("SELECT blob_id,unit_key FROM code_units WHERE identifier=?1 AND in_declarations=1 LIMIT 1", [identifier], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
                    let missing_key: i64 = conn.query_row("SELECT MAX(unit_key)+100 FROM code_units WHERE blob_id=?1", [blob], |row| row.get(0)).unwrap();
                    if matches!(mode, "missing_direct" | "inactive_direct" | "direct_no_links" | "lexical_direct_no_links") {
                        let semantic_key: i64 = conn.query_row("SELECT semantic.semantic_key FROM resolution_semantic_sites AS semantic JOIN source_native_declaration_bridges AS bridge ON bridge.blob_id=semantic.blob_id AND bridge.source_site=semantic.source_site JOIN source_declaration_units AS link ON link.blob_id=bridge.blob_id AND link.declaration_id=bridge.declaration_id WHERE semantic.blob_id=?1 AND semantic.semantic_role='definition' AND link.unit_key=?2", params![blob,key], |row| row.get(0)).unwrap();
                        conn.execute("INSERT INTO resolution_definition_unit_crosswalks(blob_id,definition_semantic_key,unit_key,identity_digest) VALUES(?1,?2,?3,zeroblob(32)) ON CONFLICT(blob_id,definition_semantic_key) DO UPDATE SET unit_key=excluded.unit_key", params![blob,semantic_key,key]).unwrap();
                    }
                    match mode {
                        "missing_direct" => {
                            conn.execute("UPDATE resolution_definition_unit_crosswalks SET unit_key=?3 WHERE blob_id=?1 AND unit_key=?2", params![blob,key,missing_key]).unwrap();
                        }
                        "inactive_direct" => { conn.execute("UPDATE code_units SET in_declarations=0 WHERE blob_id=?1 AND unit_key=?2", params![blob,key]).unwrap(); }
                        "no_route" | "root_import" => {
                            if mode == "root_import" {
                                let site: i64 = conn.query_row("SELECT bridge.source_site FROM source_native_declaration_bridges AS bridge JOIN source_declaration_units AS link ON link.blob_id=bridge.blob_id AND link.declaration_id=bridge.declaration_id WHERE link.blob_id=?1 AND link.unit_key=?2", params![blob,key], |row| row.get(0)).unwrap();
                                conn.execute("INSERT INTO resolution_root_imports(blob_id,import_site,root_scope,anchor,position,kind,bound_name) VALUES(?1,?2,0,'lexical',NULL,'named','Helper')", params![blob,site]).unwrap();
                            }
                            conn.execute("DELETE FROM resolution_definition_unit_crosswalks WHERE blob_id=?1 AND unit_key=?2", params![blob,key]).unwrap();
                            conn.execute("DELETE FROM source_native_declaration_bridges WHERE blob_id=?1 AND declaration_id IN (SELECT declaration_id FROM source_declaration_units WHERE blob_id=?1 AND unit_key=?2)", params![blob,key]).unwrap();
                        }
                        "no_links" | "anonymous_no_links" | "direct_no_links" | "lexical_no_links" | "lexical_direct_no_links" | "without_unit_no_links" => {
                            if !matches!(mode, "direct_no_links" | "lexical_direct_no_links") { conn.execute("DELETE FROM resolution_definition_unit_crosswalks WHERE blob_id=?1 AND unit_key=?2", params![blob,key]).unwrap(); }
                            if matches!(mode, "lexical_no_links" | "lexical_direct_no_links" | "without_unit_no_links") {
                                let declaration_id: i64 = conn.query_row("SELECT declaration_id FROM source_declaration_units WHERE blob_id=?1 AND unit_key=?2", params![blob,key], |row| row.get(0)).unwrap();
                                if mode == "without_unit_no_links" {
                                    conn.execute("UPDATE source_declarations SET lexical_kind=NULL, lexical_identifier=NULL WHERE blob_id=?1 AND declaration_id=?2", params![blob,declaration_id]).unwrap();
                                } else {
                                    conn.execute("UPDATE source_declarations SET lexical_kind='parameter', lexical_identifier='Helper' WHERE blob_id=?1 AND declaration_id=?2", params![blob,declaration_id]).unwrap();
                                }
                            }
                            if mode == "anonymous_no_links" {
                                let (declaration_id, occurrence_id): (i64,i64) = conn.query_row("SELECT declaration.declaration_id,declaration.occurrence_id FROM source_declarations AS declaration JOIN source_declaration_units AS link ON link.blob_id=declaration.blob_id AND link.declaration_id=declaration.declaration_id WHERE link.blob_id=?1 AND link.unit_key=?2", params![blob,key], |row| Ok((row.get(0)?,row.get(1)?))).unwrap();
                                conn.execute("UPDATE source_declarations SET name_occurrence_id=NULL,name_start_byte=NULL,name_end_byte=NULL,name_start_line=NULL,name_end_line=NULL WHERE blob_id=?1 AND declaration_id=?2", params![blob,declaration_id]).unwrap();
                                conn.execute("INSERT INTO source_go_types(blob_id,type_id,occurrence_id,kind) VALUES(?1,(SELECT COALESCE(MAX(type_id),-1)+1 FROM source_go_types WHERE blob_id=?1),?2,12)", params![blob,occurrence_id]).unwrap();
                            }
                            conn.execute("DELETE FROM source_declaration_units WHERE blob_id=?1 AND unit_key=?2", params![blob,key]).unwrap();
                        }
                        "inactive_link" => {
                            conn.execute("DELETE FROM resolution_definition_unit_crosswalks WHERE blob_id=?1 AND unit_key=?2", params![blob,key]).unwrap();
                            conn.execute("UPDATE code_units SET in_declarations=0 WHERE blob_id=?1 AND unit_key=?2", params![blob,key]).unwrap();
                        }
                        "missing_link_fk" => {
                            let result = conn.execute("UPDATE source_declaration_units SET unit_key=?3 WHERE blob_id=?1 AND unit_key=?2", params![blob,key,missing_key]);
                            assert!(matches!(result, Err(rusqlite::Error::SqliteFailure(error, _)) if error.extended_code == 787), "SQLite must reject a link to a missing unit through its foreign key");
                        }
                        _ => {}
                    }
                    let violations: Vec<String> = conn.prepare("PRAGMA foreign_key_check").unwrap().query_map([], |row| row.get(0)).unwrap().map(Result::unwrap).collect();
                    assert!(violations.is_empty(), "{mode}: {violations:?}");
                });
                let cancellation = CancellationToken::new();
                let operation = fixture.open_ready(&cancellation);
                let ordinal: u32 = operation.ready.inventory.connection().query_row("SELECT mount_ordinal FROM temp.selected_resolution_mounts WHERE persisted_relative_path=?1", [GO_ROOT_CONSUMER_PATH], |row| row.get(0)).unwrap();
                let result = operation
                    .ready
                    .go_unresolved_route_check_for_test(
                        SelectedResolutionMountOrdinal::new(ordinal),
                        &target,
                        &cancellation,
                        &ResolutionSession::unbounded(),
                    )
                    .unwrap();
                let expected = if matches!(
                    mode,
                    "clean"
                        | "other_file"
                        | "missing_link_fk"
                        | "root_import"
                        | "anonymous_no_links"
                        | "lexical_no_links"
                ) {
                    GoUnresolvedRoute::Clear
                } else {
                    GoUnresolvedRoute::Unavailable
                };
                assert_eq!(result, expected, "{mode}");
            }
        }

        #[test]
        fn go_unresolved_route_selected_blob_plan() {
            use rusqlite::StatementStatus;
            let fixture = GoRootResolutionOperationFixture::with_sources([
                "package consumer; func Helper() {}",
                "package provider; func Other() {}",
                "package provider",
            ]);
            publish_go_root_fixture_context(&fixture, "example.test/root/consumer");
            anchor_consumer(&fixture);
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let conn = operation.ready.inventory.connection();
            let ordinal: i64 = conn.query_row("SELECT mount_ordinal FROM temp.selected_resolution_mounts WHERE persisted_relative_path=?1", [GO_ROOT_CONSUMER_PATH], |row| row.get(0)).unwrap();
            let sql = brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::go_unresolved_route_sql_for_test();
            let plan: Vec<String> = conn
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .unwrap()
                .query_map([ordinal], |row| row.get(3))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            assert!(
                plan.iter()
                    .any(|line| line.contains("SEARCH semantic") && line.contains("blob_id=?")),
                "{plan:?}"
            );
            assert!(
                !plan.iter().any(|line| line.contains("SCAN semantic")
                    || line.contains("SCAN direct_unit")
                    || line.contains("SCAN linked_unit")),
                "{plan:?}"
            );
            let mut statement = conn.prepare(sql).unwrap();
            let rows: Vec<i64> = statement
                .query_map([ordinal], |row| row.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            eprintln!(
                "go_unresolved_route_plan plan={plan:?} vm_steps={} fullscan_steps={} rows={}",
                statement.get_status(StatementStatus::VmStep),
                statement.get_status(StatementStatus::FullscanStep),
                rows.len()
            );
            assert_eq!(statement.get_status(StatementStatus::FullscanStep), 0);
        }

        #[test]
        fn go_target_nomination_uses_keyed_semantic_site_search() {
            use rusqlite::StatementStatus;
            let fixture = GoRootResolutionOperationFixture::with_sources([
                "package consumer; func Helper() {}",
                "package provider; func Other() {}",
                "package provider",
            ]);
            publish_go_root_fixture_context(&fixture, "example.test/root/consumer");
            anchor_consumer(&fixture);
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let conn = operation.ready.inventory.connection();
            let (ordinal, blob_id): (i64, i64) = conn.query_row(
                "SELECT mount_ordinal,blob_id FROM temp.selected_resolution_mounts WHERE persisted_relative_path=?1",
                [GO_ROOT_CONSUMER_PATH],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).unwrap();
            let unit_key: i64 = conn.query_row(
                "SELECT unit_key FROM main.code_units WHERE blob_id=?1 AND identifier='Helper' LIMIT 1",
                [blob_id], |row| row.get(0),
            ).unwrap();
            let keys = serde_json::to_string(&[unit_key]).unwrap();
            let sql = brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::go_target_nominated_semantics_sql_for_test();
            let plan: Vec<String> = conn
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .unwrap()
                .query_map(rusqlite::params![ordinal, keys], |row| row.get(3))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            assert!(
                plan.iter().any(|line| line.contains("SEARCH semantic")
                    && (line.contains("semantic_key") || line.contains("source_site"))),
                "{plan:?}"
            );
            assert!(
                plan.iter()
                    .filter(|line| line.contains("SEARCH semantic"))
                    .all(|line| line.contains("semantic_key") || line.contains("source_site")),
                "{plan:?}"
            );
            assert!(
                !plan.iter().any(|line| line.contains("SCAN semantic")),
                "{plan:?}"
            );
            let mut statement = conn.prepare(sql).unwrap();
            let rows: Vec<i64> = statement
                .query_map(rusqlite::params![ordinal, keys], |row| row.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            eprintln!(
                "go_target_nomination plan={plan:?} vm_steps={} rows={rows:?}",
                statement.get_status(StatementStatus::VmStep)
            );
            assert!(!rows.is_empty());
            assert!(statement.get_status(StatementStatus::VmStep) < 2000);
        }

        #[test]
        fn go_reverse_target_ignores_unrelated_multi_unit_struct_method() {
            use brokk_bifrost_analysis::analyzer::store::resolution_operation::go_reverse_rows::GoReverseCandidateOutcome;
            let source = "package consumer\ntype Outer struct { A, B struct { X int } }\ntype Worker struct{}\nfunc (Worker) Run() error { return nil }\n";
            let fixture = GoRootResolutionOperationFixture::with_sources([
                source,
                "package provider",
                "package provider",
            ]);
            let context = publish_go_root_fixture_context(&fixture, "example.test/root/consumer");
            anchor_consumer(&fixture);
            let (state, _) =
                parsed_go_state(fixture._project_root.path(), GO_ROOT_CONSUMER_PATH, source);
            let unit = |name: &str| {
                state
                    .declarations
                    .iter()
                    .find(|unit| unit.short_name() == name)
                    .unwrap_or_else(|| panic!("missing {name}"))
                    .clone()
            };
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let worker = selected_consumer_unit(&unit("Worker.Run"));
            let match_result = operation.go_hierarchy_definition_match(&worker, &cancellation, &brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession::unbounded()).unwrap();
            assert!(matches!(match_result, brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::GoHierarchyDefinitionMatch::Found(_)), "{match_result:?}");
            let result = operation
                .go_reverse_candidate_sites(&worker, context, true, &[0; 32], &cancellation)
                .unwrap();
            assert!(
                matches!(result, GoReverseCandidateOutcome::Ready(_)),
                "Worker reverse target must be covered"
            );
            let field = selected_consumer_unit(&unit("Outer.A.X"));
            let result = operation
                .go_reverse_candidate_sites(&field, context, true, &[0; 32], &cancellation)
                .unwrap();
            assert!(
                matches!(result, GoReverseCandidateOutcome::Unavailable(_)),
                "multi-unit target stays refused"
            );
        }

        #[test]
        #[hardwon(
            "#9224: an unrelated malformed definition made every target match in its file Unavailable"
        )]
        fn go_target_match_keeps_unrelated_conflicts_out_of_scope() {
            use brokk_bifrost_analysis::analyzer::store::resolution_operation::go_reverse_rows::GoReverseCandidateOutcome;
            use brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::GoHierarchyDefinitionMatch;
            use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
            use rusqlite::params;

            const SOURCE: &str =
                "package consumer\nfunc Target() {}\nfunc Other() {}\nfunc Third() {}\n";
            for mode in [
                "clean",
                "target_conflict",
                "missing_route",
                "unrelated_conflict",
            ] {
                let fixture = GoRootResolutionOperationFixture::with_sources([
                    SOURCE,
                    "package provider; func Missing() {}",
                    "package provider",
                ]);
                let context =
                    publish_go_root_fixture_context(&fixture, "example.test/root/consumer");
                anchor_consumer(&fixture);
                let (state, _) =
                    parsed_go_state(fixture._project_root.path(), GO_ROOT_CONSUMER_PATH, SOURCE);
                let target = selected_consumer_unit(
                    state
                        .declarations
                        .iter()
                        .find(|unit| unit.identifier() == "Target")
                        .unwrap(),
                );
                let (absent_state, _) = parsed_go_state(
                    fixture._project_root.path(),
                    GO_ROOT_CONSUMER_PATH,
                    "package consumer; func Absent() {}",
                );
                let missing = selected_consumer_unit(
                    absent_state
                        .declarations
                        .iter()
                        .find(|unit| unit.identifier() == "Absent")
                        .unwrap(),
                );
                fixture.store.conn.execute_fixture(move |conn| {
                    conn.execute_batch("PRAGMA foreign_keys=ON").unwrap();
                    if mode == "clean" {
                        let (direct, link_only, multi_link): (i64, i64, i64) = conn.query_row(
                            "SELECT SUM(has_direct), SUM(NOT has_direct AND link_count > 0), SUM(link_count > 1) FROM (SELECT semantic.semantic_key, EXISTS(SELECT 1 FROM resolution_definition_unit_crosswalks direct WHERE direct.blob_id=semantic.blob_id AND direct.definition_semantic_key=semantic.semantic_key) AS has_direct, (SELECT COUNT(*) FROM source_native_declaration_bridges bridge JOIN source_declaration_units link ON link.blob_id=bridge.blob_id AND link.declaration_id=bridge.declaration_id WHERE bridge.blob_id=semantic.blob_id AND bridge.source_site=semantic.source_site) AS link_count FROM resolution_semantic_sites semantic WHERE semantic.semantic_role='definition' AND semantic.blob_id=(SELECT blob_id FROM code_units WHERE identifier='Target' AND in_declarations=1 LIMIT 1))",
                            [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                        ).unwrap();
                        eprintln!("go_target_published_shapes direct={direct} link_only={link_only} multi_link={multi_link}");
                    }
                    if mode != "clean" {
                        let (blob, target_key): (i64, i64) = conn.query_row("SELECT blob_id,unit_key FROM code_units WHERE identifier='Target' AND in_declarations=1 LIMIT 1", [], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
                        let other_key: i64 = conn.query_row("SELECT unit_key FROM code_units WHERE blob_id=?1 AND identifier='Other' AND in_declarations=1", [blob], |row| row.get(0)).unwrap();
                        let third_key: i64 = conn.query_row("SELECT unit_key FROM code_units WHERE blob_id=?1 AND identifier='Third' AND in_declarations=1", [blob], |row| row.get(0)).unwrap();
                        let (link_key, direct_key) = match mode {
                            "target_conflict" => (target_key, other_key),
                            "missing_route" => (other_key, third_key + 1000),
                            "unrelated_conflict" => (other_key, third_key),
                            _ => unreachable!(),
                        };
                        let semantic_key: i64 = conn.query_row("SELECT semantic.semantic_key FROM resolution_semantic_sites AS semantic JOIN source_native_declaration_bridges AS bridge ON bridge.blob_id=semantic.blob_id AND bridge.source_site=semantic.source_site JOIN source_declaration_units AS link ON link.blob_id=bridge.blob_id AND link.declaration_id=bridge.declaration_id WHERE semantic.blob_id=?1 AND semantic.semantic_role='definition' AND link.unit_key=?2", params![blob, link_key], |row| row.get(0)).unwrap();
                        conn.execute("INSERT INTO resolution_definition_unit_crosswalks(blob_id,definition_semantic_key,unit_key,identity_digest) VALUES(?1,?2,?3,zeroblob(32)) ON CONFLICT(blob_id,definition_semantic_key) DO UPDATE SET unit_key=excluded.unit_key", params![blob,semantic_key,direct_key]).unwrap();
                    }
                    let violations: Vec<String> = conn.prepare("PRAGMA foreign_key_check").unwrap().query_map([], |row| row.get(0)).unwrap().map(Result::unwrap).collect();
                    assert!(violations.is_empty(), "{mode}: {violations:?}");
                });
                let cancellation = CancellationToken::new();
                let operation = fixture.open_ready(&cancellation);
                let answer = operation
                    .go_hierarchy_definition_match(
                        &target,
                        &cancellation,
                        &ResolutionSession::unbounded(),
                    )
                    .unwrap();
                match mode {
                    "clean" | "unrelated_conflict" => assert!(
                        matches!(answer, GoHierarchyDefinitionMatch::Found(_)),
                        "{mode}: {answer:?}"
                    ),
                    _ => assert_eq!(answer, GoHierarchyDefinitionMatch::Unavailable, "{mode}"),
                }
                if mode == "unrelated_conflict" {
                    // The old full-file projection returned Unavailable for both targets.
                    let answer = operation
                        .go_hierarchy_definition_match(
                            &missing,
                            &cancellation,
                            &ResolutionSession::unbounded(),
                        )
                        .unwrap();
                    assert_eq!(answer, GoHierarchyDefinitionMatch::Missing);
                    let reverse = operation
                        .go_reverse_candidate_sites(&target, context, true, &[0; 32], &cancellation)
                        .unwrap();
                    assert!(
                        matches!(reverse, GoReverseCandidateOutcome::Ready(_)),
                        "target sites must survive the unrelated malformed definition"
                    );
                    let reverse_absent = operation
                        .go_reverse_candidate_sites(
                            &missing,
                            context,
                            true,
                            &[0; 32],
                            &cancellation,
                        )
                        .unwrap();
                    assert!(
                        matches!(
                            reverse_absent,
                            GoReverseCandidateOutcome::TargetUncovered(_)
                        ),
                        "absent target has no selected definition sites"
                    );
                }
                cancellation.cancel();
                let stopped = operation
                    .go_hierarchy_definition_match(
                        &target,
                        &cancellation,
                        &ResolutionSession::unbounded(),
                    )
                    .unwrap();
                assert!(
                    matches!(stopped, GoHierarchyDefinitionMatch::Stopped { .. }),
                    "{stopped:?}"
                );
            }

            // The same path selects a new published blob: a target from the first
            // view must be absent when that definition is removed from the file.
            let fixture = GoRootResolutionOperationFixture::with_sources([
                "package consumer; func Other() {}",
                "package provider; func Missing() {}",
                "package provider",
            ]);
            publish_go_root_fixture_context(&fixture, "example.test/root/consumer");
            anchor_consumer(&fixture);
            let (old_state, _) =
                parsed_go_state(fixture._project_root.path(), GO_ROOT_CONSUMER_PATH, SOURCE);
            let old_target = selected_consumer_unit(
                old_state
                    .declarations
                    .iter()
                    .find(|unit| unit.identifier() == "Target")
                    .unwrap(),
            );
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let answer = operation
                .go_hierarchy_definition_match(
                    &old_target,
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            assert_eq!(answer, GoHierarchyDefinitionMatch::Missing);
        }

        #[test]
        fn go_import_spec_does_not_refuse_hierarchy_or_reverse_targets() {
            use brokk_bifrost_analysis::analyzer::store::resolution_operation::go_reverse_rows::GoReverseCandidateOutcome;
            use brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::GoHierarchyDefinitionMatch;
            use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

            let mut observed = Vec::new();
            for import in ["", "import \"example.test/root/provider\"\n"] {
                let source = format!(
                    "package consumer\n{import}type Runner interface {{ Run() error }}\ntype Worker struct{{}}\nfunc (Worker) Run() error {{ return nil }}\n"
                );
                let fixture = GoRootResolutionOperationFixture::with_sources([
                    source.as_str(),
                    "package provider",
                    "package provider",
                ]);
                let context =
                    publish_go_root_fixture_context(&fixture, "example.test/root/consumer");
                anchor_consumer(&fixture);
                let (state, _) =
                    parsed_go_state(fixture._project_root.path(), GO_ROOT_CONSUMER_PATH, &source);
                let cancellation = CancellationToken::new();
                let operation = fixture.open_ready(&cancellation);
                let mut shape = Vec::new();
                for name in ["Runner", "Worker.Run"] {
                    let unit = selected_consumer_unit(
                        state
                            .declarations
                            .iter()
                            .find(|unit| unit.short_name() == name)
                            .expect(name),
                    );
                    let hierarchy = operation
                        .go_hierarchy_definition_match(
                            &unit,
                            &cancellation,
                            &ResolutionSession::unbounded(),
                        )
                        .unwrap();
                    let reverse = operation
                        .go_reverse_candidate_sites(&unit, context, true, &[0; 32], &cancellation)
                        .unwrap();
                    shape.push((
                        matches!(hierarchy, GoHierarchyDefinitionMatch::Found(_)),
                        matches!(reverse, GoReverseCandidateOutcome::Ready(_)),
                    ));
                }
                observed.push(shape);
            }
            assert_eq!(observed[0], observed[1]);
            assert_eq!(observed[1], vec![(true, true), (true, true)]);
        }

        #[test]
        fn go_inline_interface_neighbor_reverse_target_must_cover_worker() {
            use brokk_bifrost_analysis::analyzer::store::resolution_operation::go_reverse_rows::GoReverseCandidateOutcome;
            let source = "package consumer\ntype Outer struct { A, B interface { Run() error } }\ntype Worker struct{}\nfunc (Worker) Run() error { return nil }\n";
            let fixture = GoRootResolutionOperationFixture::with_sources([
                source,
                "package provider",
                "package provider",
            ]);
            let context = publish_go_root_fixture_context(&fixture, "example.test/root/consumer");
            anchor_consumer(&fixture);
            let (state, _) =
                parsed_go_state(fixture._project_root.path(), GO_ROOT_CONSUMER_PATH, source);
            let worker = selected_consumer_unit(
                state
                    .declarations
                    .iter()
                    .find(|unit| unit.short_name() == "Worker.Run")
                    .expect("Worker.Run"),
            );
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let match_result = operation.go_hierarchy_definition_match(&worker, &cancellation, &brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession::unbounded()).unwrap();
            assert!(matches!(match_result, brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::GoHierarchyDefinitionMatch::Found(_)), "{match_result:?}");
            let result = operation
                .go_reverse_candidate_sites(&worker, context, true, &[0; 32], &cancellation)
                .unwrap();
            assert!(
                matches!(result, GoReverseCandidateOutcome::Ready(_)),
                "Worker reverse target must be covered"
            );
        }

        #[test]
        fn go_hierarchy_lookup_blobs_and_selection_coverage() {
            use brokk_bifrost_analysis::analyzer::resolution::fact_source::TypedFactPageVisitor;
            use brokk_bifrost_analysis::analyzer::resolution::model::{SemanticId, SharedNameId};
            use brokk_bifrost_analysis::analyzer::store::resolution::TypedFactRelation;
            use brokk_bifrost_analysis::analyzer::store::resolution_operation::go_context::GoHierarchySelectionCoverage;
            use rusqlite::params;

            let fixture = GoRootResolutionOperationFixture::with_sources([
                "package consumer; type Target struct{}; type Wrap struct{ Target }",
                "package provider; type Target struct{}; type I interface{ M() }",
                "package provider; type Other struct{ Target }; type J interface{ M() }",
            ]);
            let context = publish_go_root_fixture_context(&fixture, "example.test/root/provider");
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let conn = operation.ready.inventory.connection();
            assert_eq!(
                operation
                    .go_hierarchy_selection_coverage(context, "go")
                    .unwrap(),
                GoHierarchySelectionCoverage::Workspace
            );
            let source = operation.ready.typed_source();
            for (relation, spelling, expected_paths) in [
                (
                    TypedFactRelation::EmbeddedTypeLookup,
                    "Target",
                    vec![GO_ROOT_CONSUMER_PATH, GO_ROOT_DECOY_PATH],
                ),
                (
                    TypedFactRelation::InterfaceMethodLookup,
                    "M",
                    vec![GO_ROOT_PROVIDER_PATH, GO_ROOT_DECOY_PATH],
                ),
            ] {
                let id: i64 = conn.query_row(
                    "SELECT lookup.identity_id FROM resolution_typed_fact_lookups lookup JOIN resolution_identities name ON name.id=lookup.identity_id WHERE lookup.relation=?1 AND name.spelling=?2 LIMIT 1",
                    params![relation.code(), spelling],
                    |row| row.get(0),
                ).unwrap();
                let name = SemanticId::shared_name(SharedNameId::interned(id));
                let mut found = Vec::new();
                let mut callback = |page: &[brokk_bifrost_analysis::analyzer::store::resolution_typed::GoLookupCandidate]| {
                    found.extend_from_slice(page);
                    Ok(true)
                };
                let mut visitor = TypedFactPageVisitor::new(&mut callback);
                let outcome = match relation {
                    TypedFactRelation::EmbeddedTypeLookup => source
                        .visit_go_embedded_type_candidate_pages(
                            &[name],
                            &cancellation,
                            &mut visitor,
                        ),
                    TypedFactRelation::InterfaceMethodLookup => source
                        .visit_go_interface_method_candidate_pages(
                            &[name],
                            &cancellation,
                            &mut visitor,
                        ),
                    _ => unreachable!(),
                }
                .unwrap();
                assert!(outcome.is_exhausted());
                let mut expected = expected_paths
                    .into_iter()
                    .map(|path| {
                        conn.query_row(
                            "SELECT blob_id FROM temp.selected_resolution_mounts WHERE storage_language='go' AND persisted_relative_path=?1",
                            [path],
                            |row| row.get::<_, i64>(0),
                        ).unwrap()
                    })
                    .collect::<Vec<_>>();
                expected.sort_unstable();
                let mut actual = found.iter().map(|row| row.blob_id).collect::<Vec<_>>();
                actual.sort_unstable();
                assert_eq!(actual, expected, "{relation:?}");
                let keys = source
                    .go_lookup_read_keys(&[name], relation, &cancellation)
                    .unwrap()
                    .unwrap();
                assert_eq!(keys.len(), 1);
                assert_eq!(keys[0].relation, relation);
                assert_eq!(keys[0].name, name);
                assert_eq!(keys[0].identity_id, Some(id));
                assert_eq!(
                    keys[0].selection_fingerprint,
                    operation.ready.inventory.fingerprint()
                );
            }
            let missing = SemanticId::shared_name(SharedNameId::per_request(999));
            let missing_keys = source
                .go_lookup_read_keys(
                    &[missing],
                    TypedFactRelation::EmbeddedTypeLookup,
                    &cancellation,
                )
                .unwrap()
                .unwrap();
            assert_eq!(missing_keys.len(), 1);
            assert_eq!(missing_keys[0].identity_id, None);
            assert_eq!(
                missing_keys[0].selection_fingerprint,
                operation.ready.inventory.fingerprint()
            );
            // Both relations use this same indexed membership statement; only
            // the relation literal differs.
            let pin =
                brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned(
                    "selected_typed_shared_membership",
                );
            let plan = conn
                .prepare(&format!("EXPLAIN QUERY PLAN {}", pin.sql))
                .unwrap()
                .query_map(params![0_i64, 1_i64], |row| row.get::<_, String>(3))
                .unwrap()
                .map(Result::unwrap)
                .collect::<Vec<_>>();
            assert!(
                plan.iter()
                    .any(|line| line.contains("resolution_typed_fact_lookups_identity")),
                "{plan:?}"
            );
            assert!(
                plan.iter()
                    .all(|line| !line.contains("SCAN resolution_typed_fact_lookups")),
                "{plan:?}"
            );
            let excluded = operation
                .mount_table()
                .mount_for_path("go", GO_ROOT_DECOY_PATH)
                .unwrap()
                .unwrap()
                .ordinal();
            conn.execute(
                "DELETE FROM temp.selected_resolution_scope_mounts WHERE mount_ordinal=?1",
                [excluded.get()],
            )
            .unwrap();
            assert_eq!(
                operation
                    .go_hierarchy_selection_coverage(context, "go")
                    .unwrap(),
                GoHierarchySelectionCoverage::Partial
            );
            let (ordinal, key): (u32, u32) = conn.query_row(
                "SELECT mount.mount_ordinal,semantic.semantic_key FROM temp.selected_resolution_mounts mount JOIN source_go_type_declarations declaration ON declaration.blob_id=mount.blob_id JOIN source_native_declaration_bridges bridge ON bridge.blob_id=declaration.blob_id AND bridge.declaration_id=declaration.declaration_id JOIN resolution_semantic_sites semantic ON semantic.blob_id=bridge.blob_id AND semantic.source_site=bridge.source_site AND semantic.semantic_role='definition' WHERE mount.persisted_relative_path=?1 AND declaration.name='Target'",
                [GO_ROOT_CONSUMER_PATH],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).unwrap();
            let answer = operation.go_direct_subtypes(
                context,
                "go",
                SemanticId::local(ordinal, key),
                &cancellation,
                &brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession::unbounded(),
            ).unwrap();
            assert!(
                answer
                    .open_reasons
                    .contains(&"selection does not cover workspace"),
                "{answer:?}"
            );
            assert!(!answer.is_complete());
            assert_eq!(answer.read_keys.coverage.unwrap().context_id, context);
            assert!(
                answer
                    .read_keys
                    .names
                    .iter()
                    .any(|key| key.relation == TypedFactRelation::EmbeddedTypeLookup)
            );
        }

        #[test]
        fn go_selected_type_support_is_local_and_role_filtered() {
            use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;
            use brokk_bifrost_analysis::analyzer::store::resolution_operation::go_hierarchy::GoTypeSupport;
            use rusqlite::params;

            let fixture = GoRootResolutionOperationFixture::with_sources([
                "package consumer; type Target struct{}; type Alias = Target",
                "package provider; type Other struct{}",
                "package provider; type Third struct{}",
            ]);
            let context = publish_go_root_fixture_context(&fixture, "example.test/root/provider");
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let conn = operation.ready.inventory.connection();
            let ordinal: u32 = conn.query_row(
                "SELECT mount_ordinal FROM temp.selected_resolution_mounts WHERE persisted_relative_path=?1",
                [GO_ROOT_CONSUMER_PATH],
                |row| row.get(0),
            ).unwrap();
            {
                let name = "Target";
                let expected = GoTypeSupport::Supported;
                let key: u32 = conn.query_row(
                    "SELECT semantic.semantic_key FROM temp.selected_resolution_mounts mount JOIN source_native_declaration_bridges bridge ON bridge.blob_id=mount.blob_id LEFT JOIN source_go_type_declarations declaration ON declaration.blob_id=bridge.blob_id AND declaration.declaration_id=bridge.declaration_id LEFT JOIN source_go_aliases alias ON alias.blob_id=bridge.blob_id AND alias.declaration_id=bridge.declaration_id JOIN resolution_semantic_sites semantic ON semantic.blob_id=bridge.blob_id AND semantic.source_site=bridge.source_site AND semantic.semantic_role='definition' WHERE mount.mount_ordinal=?1 AND COALESCE(declaration.name,alias.name)=?2",
                    params![ordinal, name],
                    |row| row.get(0),
                ).unwrap();
                let definition = SemanticId::local(ordinal, key);
                assert_eq!(
                    operation
                        .go_type_supports(context, "go", definition, &cancellation)
                        .unwrap(),
                    expected
                );
                assert_eq!(
                    operation
                        .go_type_supports(context, "test", definition, &cancellation)
                        .unwrap(),
                    expected
                );
            }
        }

        #[test]
        #[brokk_bifrost_test_macros::hardwon(
            "#7509: a bridged Go interface alias (a grouped spec on master) skipped the typed interface proof and stayed Open"
        )]
        fn go_alias_type_support_uses_typed_interface_evidence_with_or_without_bridge() {
            use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;
            use brokk_bifrost_analysis::analyzer::store::resolution_operation::go_hierarchy::GoTypeSupport;
            use rusqlite::params;

            let fixture = GoRootResolutionOperationFixture::with_sources([
                "package consumer; type Item struct{}; type Solo = interface { M() }; type ( Group = interface { M() } ); type Concrete = Item; type Empty = interface{}",
                "package provider; type Other struct{}",
                "package provider; type Third struct{}",
            ]);
            let context = publish_go_root_fixture_context(&fixture, "example.test/root/provider");
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let conn = operation.ready.inventory.connection();
            let mut definitions = std::collections::HashMap::new();
            for name in ["Solo", "Group", "Concrete", "Empty"] {
                let (ordinal, key): (u32, u32) = conn
                    .query_row(
                        "SELECT mount.mount_ordinal, semantic.semantic_key
                         FROM temp.selected_resolution_mounts mount
                         JOIN source_go_aliases alias ON alias.blob_id=mount.blob_id
                         JOIN source_native_declaration_bridges bridge
                           ON bridge.blob_id=alias.blob_id
                          AND bridge.declaration_id=alias.declaration_id
                         JOIN resolution_semantic_sites semantic
                           ON semantic.blob_id=bridge.blob_id
                          AND semantic.source_site=bridge.source_site
                          AND semantic.semantic_role='definition'
                         WHERE mount.persisted_relative_path=?1 AND alias.name=?2",
                        params![GO_ROOT_CONSUMER_PATH, name],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .unwrap();
                definitions.insert(name, SemanticId::local(ordinal, key));
            }
            for (name, expected) in [
                ("Solo", GoTypeSupport::Supported),
                ("Group", GoTypeSupport::Supported),
                ("Concrete", GoTypeSupport::Open),
                ("Empty", GoTypeSupport::Open),
            ] {
                assert_eq!(
                    operation
                        .go_type_supports(context, "go", definitions[name], &cancellation)
                        .unwrap(),
                    expected,
                    "{name}"
                );
            }
            let cancelled = CancellationToken::new();
            cancelled.cancel();
            assert_eq!(
                operation
                    .go_type_supports(context, "go", definitions["Solo"], &cancelled)
                    .unwrap(),
                GoTypeSupport::Open
            );
            drop(operation);

            fixture.store.conn.execute(|conn| {
                // Model an already-published blob from the old producer, which
                // emitted this alias without a bridge. This store is isolated.
                conn.execute_batch(
                    "DROP TRIGGER source_native_declaration_bridges_no_delete_after_seal",
                )
                .unwrap();
                conn.execute(
                    "DELETE FROM source_native_declaration_bridges
                     WHERE (blob_id, declaration_id) IN
                       (SELECT blob_id, declaration_id FROM source_go_aliases WHERE name='Group')",
                    [],
                )
                .unwrap();
            });
            let operation = fixture.open_ready(&cancellation);
            assert_eq!(
                operation
                    .go_type_supports(context, "go", definitions["Group"], &cancellation)
                    .unwrap(),
                GoTypeSupport::Supported,
                "old unbridged alias shape must keep its typed interface proof"
            );
        }

        #[test]
        #[brokk_bifrost_test_macros::hardwon(
            "#7509: sole-spec Go alias bridge missed its parser Field declaration"
        )]
        fn go_alias_bridge_reaches_its_selected_field_unit() {
            let fixture = GoRootResolutionOperationFixture::with_sources([
                "package consumer\ntype Target struct{}\ntype Alias = Target\ntype (\n Grouped = Target\n Other = Target\n)\n",
                "package provider; type Other struct{}",
                "package provider; type Third struct{}",
            ]);
            let _context = publish_go_root_fixture_context(&fixture, "example.test/root/provider");
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let conn = operation.ready.inventory.connection();
            let mut statement = conn
                .prepare(
                    "SELECT alias.name, declaration.declaration_id,
                        declaration.occurrence_id, declaration.name_occurrence_id,
                        (SELECT count(*) FROM source_declaration_units link
                          WHERE link.blob_id=declaration.blob_id
                            AND link.declaration_id=declaration.declaration_id),
                        (SELECT count(*) FROM source_native_declaration_bridges bridge
                          WHERE bridge.blob_id=declaration.blob_id
                            AND bridge.declaration_id=declaration.declaration_id)
                   FROM temp.selected_resolution_mounts mount
                   JOIN source_go_aliases alias ON alias.blob_id=mount.blob_id
                   JOIN source_declarations parser ON parser.blob_id=alias.blob_id
                    AND parser.declaration_id=alias.declaration_id
                   JOIN source_declarations declaration ON declaration.blob_id=parser.blob_id
                    AND declaration.name_occurrence_id=parser.name_occurrence_id
                  WHERE mount.persisted_relative_path=?1
                    AND alias.name IN ('Alias','Grouped','Other')
                  ORDER BY alias.name,declaration.declaration_id",
                )
                .unwrap();
            let rows = statement
                .query_map([GO_ROOT_CONSUMER_PATH], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            eprintln!("GO_ALIAS_OWNER_ROWS {rows:?}");

            let selected: Vec<(i64, String)> = conn
                .prepare(
                    "SELECT semantic.semantic_key,units.short_name
                   FROM temp.selected_resolution_mounts mount
                   JOIN resolution_fragment_interiors interior ON interior.blob_id=mount.blob_id
                    AND interior.producer_epoch=mount.producer_epoch
                    AND interior.interior_digest=mount.interior_digest
                    AND interior.publication_state='complete'
                   JOIN source_fact_manifests source ON source.blob_id=interior.blob_id
                    AND source.publication_state='complete'
                   JOIN source_go_aliases alias ON alias.blob_id=mount.blob_id
                   JOIN source_native_declaration_bridges bridge ON bridge.blob_id=alias.blob_id
                    AND bridge.declaration_id=alias.declaration_id
                   JOIN resolution_semantic_sites semantic ON semantic.blob_id=bridge.blob_id
                    AND semantic.source_site=bridge.source_site
                    AND semantic.semantic_role='definition'
                   JOIN source_declaration_units link ON link.blob_id=bridge.blob_id
                    AND link.declaration_id=bridge.declaration_id
                   JOIN code_units units ON units.blob_id=link.blob_id
                    AND units.unit_key=link.unit_key
                  WHERE mount.persisted_relative_path=?1 AND alias.name='Alias'
                    AND units.in_declarations=1",
                )
                .unwrap()
                .query_map([GO_ROOT_CONSUMER_PATH], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            eprintln!("GO_ALIAS_SELECTED_UNITS {selected:?}");
            assert_eq!(
                selected.len(),
                1,
                "selected alias definition must reach its Field unit: {selected:?}"
            );
            assert_eq!(selected[0].1, "_module_.Alias");

            for name in ["Alias", "Grouped", "Other"] {
                let owned = rows.iter().filter(|row| row.0 == name).collect::<Vec<_>>();
                assert_eq!(owned.len(), 1, "{name}: {rows:?}");
                assert_eq!((owned[0].4, owned[0].5), (1, 1), "{name}: {rows:?}");
            }
        }

        fn go_hierarchy_store() -> (GoRootResolutionOperationFixture, i64) {
            use rusqlite::params;
            let fixture = GoRootResolutionOperationFixture::with_sources([
                "package consumer; import p \"example.test/root/provider\"; type Wrap struct{p.Base}; type Mix struct{p.Base;p.Other}; type Mid struct{p.Base}; type Leaf struct{Mid}; type J interface{p.I}; type J2 interface{M()}; type SJ struct{J2}; type Alias = interface{M()}; type OtherAlias = interface{X()}; type SA struct{}; func (SA) M(){}",
                "package provider; type Base struct{}; func (Base) M(){}; type Other struct{}; func (Other) N(){}; type I interface{M()}; type I2 interface{M();N()}; type Any interface{}",
                "package provider; type Other struct{}; type Jtest interface{M()}",
            ]);
            let context = publish_go_root_fixture_context(&fixture, "example.test/root/provider");
            fixture.store.conn.execute(move |conn| {
                conn.execute(
                    "UPDATE go_context_publications SET complete=1 WHERE context_id=?1",
                    [context],
                )
                .unwrap();
                conn.execute(
                    "UPDATE go_package_instances SET complete=1 WHERE context_id=?1",
                    [context],
                )
                .unwrap();
                conn.execute(
                    "UPDATE go_package_imports SET complete=1 WHERE context_id=?1",
                    [context],
                )
                .unwrap();
                conn.execute(
                    "UPDATE go_package_files SET source_role='test' WHERE package_id=(SELECT package_id FROM go_package_instances WHERE context_id=?1 AND tool_import_path='example.test/root/other/provider') AND rel_path=?2",
                    params![context, GO_ROOT_DECOY_PATH],
                ).unwrap();
                conn.execute(
                    "UPDATE go_package_instances SET for_test='example.test/root/other/provider' WHERE context_id=?1 AND tool_import_path='example.test/root/other/provider'",
                    [context],
                ).unwrap();
            });
            (fixture, context)
        }

        fn go_hierarchy_declaration(
            conn: &rusqlite::Connection,
            path: &str,
            name: &str,
        ) -> brokk_bifrost_analysis::analyzer::resolution::model::SemanticId {
            use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;
            use rusqlite::params;
            let (ordinal, key): (u32, u32) = conn.query_row(
                "SELECT mount.mount_ordinal,semantic.semantic_key FROM temp.selected_resolution_mounts mount JOIN source_go_type_declarations declaration ON declaration.blob_id=mount.blob_id JOIN source_native_declaration_bridges bridge ON bridge.blob_id=declaration.blob_id AND bridge.declaration_id=declaration.declaration_id JOIN resolution_semantic_sites semantic ON semantic.blob_id=bridge.blob_id AND semantic.source_site=bridge.source_site AND semantic.semantic_role='definition' WHERE mount.persisted_relative_path=?1 AND declaration.name=?2",
                params![path, name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).unwrap();
            SemanticId::local(ordinal, key)
        }

        #[test]
        #[hardwon(
            "#8751: review found a parenthesized interface-literal alias target made direct subtypes falsely Complete"
        )]
        fn go_alias_interface_literal_wrappers_are_definite() {
            use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;
            use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
            use rusqlite::params;
            for source in [
                "package provider; type I interface{ M() }; type Alias = interface{ M() }; type S struct{}; func (S) M() {}",
                "package provider; type I interface{ M() }; type Alias = (interface{ M() }); type S struct{}; func (S) M() {}",
            ] {
                let fixture = GoRootResolutionOperationFixture::with_sources([
                    "package consumer",
                    source,
                    "package provider; type Other struct{}",
                ]);
                let context =
                    publish_go_root_fixture_context(&fixture, "example.test/root/provider");
                fixture.store.conn.execute(move |conn| {
                    for table in [
                        "go_context_publications",
                        "go_package_instances",
                        "go_package_imports",
                    ] {
                        conn.execute(
                            &format!("UPDATE {table} SET complete=1 WHERE context_id=?1"),
                            [context],
                        )
                        .unwrap();
                    }
                });
                let cancellation = CancellationToken::new();
                let operation = fixture.open_ready(&cancellation);
                let conn = operation.ready.inventory.connection();
                let interface = go_hierarchy_declaration(conn, GO_ROOT_PROVIDER_PATH, "I");
                let implementer = go_hierarchy_declaration(conn, GO_ROOT_PROVIDER_PATH, "S");
                let subtype = operation
                    .go_direct_subtypes(
                        context,
                        "go",
                        interface,
                        &cancellation,
                        &ResolutionSession::unbounded(),
                    )
                    .unwrap();
                assert!(subtype.is_complete(), "{source}: {subtype:?}");
                assert!(
                    subtype.edges.contains(&implementer),
                    "{source}: {subtype:?}"
                );
                let (alias_mount, alias_key): (u32, u32) = conn.query_row(
                    "SELECT mount.mount_ordinal,member.definition_key FROM temp.selected_resolution_mounts mount JOIN resolution_package_members member ON member.blob_id=mount.blob_id AND member.namespace='type' JOIN resolution_semantic_catalog catalog ON catalog.blob_id=member.blob_id AND catalog.local_key=member.lookup_key JOIN resolution_identities identity ON identity.id=catalog.shared_identity JOIN source_go_aliases alias ON alias.blob_id=member.blob_id AND alias.name=identity.spelling WHERE mount.persisted_relative_path=?1 AND alias.name='Alias'",
                    [GO_ROOT_PROVIDER_PATH], |row| Ok((row.get(0)?,row.get(1)?)),
                ).unwrap();
                let alias_subtypes = operation
                    .go_direct_subtypes(
                        context,
                        "go",
                        SemanticId::local(alias_mount, alias_key),
                        &cancellation,
                        &ResolutionSession::unbounded(),
                    )
                    .unwrap();
                assert!(
                    alias_subtypes.is_complete() && alias_subtypes.edges.contains(&implementer),
                    "{source}: {alias_subtypes:?}"
                );
                let (mount, key): (u32, u32) = conn
                    .query_row(
                        "SELECT mount.mount_ordinal,semantic.semantic_key FROM temp.selected_resolution_mounts mount JOIN source_go_type_declarations owner ON owner.blob_id=mount.blob_id JOIN source_go_callables method ON method.blob_id=owner.blob_id AND method.owner_type_id=owner.type_id JOIN source_native_declaration_bridges bridge ON bridge.blob_id=method.blob_id AND bridge.declaration_id=method.declaration_id JOIN resolution_semantic_sites semantic ON semantic.blob_id=bridge.blob_id AND semantic.source_site=bridge.source_site AND semantic.semantic_role='definition' WHERE mount.persisted_relative_path=?1 AND owner.name='I' AND method.name='M'",
                        params![GO_ROOT_PROVIDER_PATH],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .unwrap();
                let family = operation
                    .go_native_method_family(
                        context,
                        "go",
                        SemanticId::local(mount, key),
                        &cancellation,
                        &ResolutionSession::unbounded(),
                    )
                    .unwrap();
                assert!(family.implemented_by.is_complete(), "{source}: {family:?}");
                let (s_mount, s_key): (u32, u32) = conn.query_row(
                    "SELECT mount.mount_ordinal,semantic.semantic_key FROM temp.selected_resolution_mounts mount JOIN source_go_callables method ON method.blob_id=mount.blob_id AND method.name='M' AND method.receiver_type_id IS NOT NULL JOIN source_native_declaration_bridges bridge ON bridge.blob_id=method.blob_id AND bridge.declaration_id=method.declaration_id JOIN resolution_semantic_sites semantic ON semantic.blob_id=bridge.blob_id AND semantic.source_site=bridge.source_site AND semantic.semantic_role='definition' WHERE mount.persisted_relative_path=?1",
                    [GO_ROOT_PROVIDER_PATH], |row| Ok((row.get(0)?,row.get(1)?)),
                ).unwrap();
                assert!(
                    family
                        .implemented_by
                        .methods
                        .contains(&SemanticId::local(s_mount, s_key)),
                    "{source}: {family:?}"
                );
            }
        }

        #[test]
        #[hardwon(
            "#8852: review found a pointer-to-interface alias was classified as the interface"
        )]
        fn go_pointer_and_partial_interface_aliases_stay_open() {
            use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;
            use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
            let deep = format!("{}interface{{M()}}{}", "(".repeat(33), ")".repeat(33));
            let source = format!(
                "package provider; type I interface{{N()}}; type P = *interface{{M()}}; type Mixed = interface{{I; M()}}; type Constraint = interface{{~int; M()}}; type Deep = {deep}; type S struct{{}}; func (S) M() {{}}"
            );
            let fixture = GoRootResolutionOperationFixture::with_sources([
                "package consumer",
                &source,
                "package provider; type Other struct{}",
            ]);
            let context = publish_go_root_fixture_context(&fixture, "example.test/root/provider");
            fixture.store.conn.execute(move |conn| {
                for table in [
                    "go_context_publications",
                    "go_package_instances",
                    "go_package_imports",
                ] {
                    conn.execute(
                        &format!("UPDATE {table} SET complete=1 WHERE context_id=?1"),
                        [context],
                    )
                    .unwrap();
                }
            });
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let conn = operation.ready.inventory.connection();
            for name in ["P", "Mixed", "Constraint", "Deep"] {
                let (mount,key): (u32,u32) = conn.query_row(
                    "SELECT mount.mount_ordinal,member.definition_key FROM temp.selected_resolution_mounts mount JOIN resolution_package_members member ON member.blob_id=mount.blob_id AND member.namespace='type' JOIN resolution_semantic_catalog catalog ON catalog.blob_id=member.blob_id AND catalog.local_key=member.lookup_key JOIN resolution_identities identity ON identity.id=catalog.shared_identity JOIN source_go_aliases alias ON alias.blob_id=member.blob_id AND alias.name=identity.spelling WHERE mount.persisted_relative_path=?1 AND alias.name=?2",
                    rusqlite::params![GO_ROOT_PROVIDER_PATH,name], |row| Ok((row.get(0)?,row.get(1)?)),
                ).unwrap();
                let alias = SemanticId::local(mount, key);
                assert_eq!(
                    format!(
                        "{:?}",
                        operation
                            .go_type_supports(context, "go", alias, &cancellation)
                            .unwrap()
                    ),
                    "Open",
                    "{name}"
                );
                let inventory = operation
                    .ready
                    .typed_source()
                    .go_member_declarations(&[alias], &cancellation)
                    .unwrap()
                    .unwrap();
                assert!(!inventory.iter().any(|entry| entry.definition == alias && matches!(entry.kind, brokk_bifrost_analysis::analyzer::resolution::GoMemberDeclarationKind::Interface { .. })), "{name}: {inventory:?}");
                let answer = operation
                    .go_direct_subtypes(
                        context,
                        "go",
                        alias,
                        &cancellation,
                        &ResolutionSession::unbounded(),
                    )
                    .unwrap();
                assert!(
                    !answer.is_complete() && answer.edges.is_empty(),
                    "{name}: {answer:?}"
                );
            }
        }

        #[test]
        #[hardwon(
            "#8852: review found an unprojected deep alias literal let a named interface's subtypes close without its embedder"
        )]
        fn go_unprojected_alias_literals_keep_inverse_open() {
            use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;
            use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
            let deep = format!("{}interface{{M()}}{}", "(".repeat(33), ")".repeat(33));
            for (case, alias, extra) in [
                ("Deep", deep, ""),
                (
                    "Mixed",
                    "interface{ J; M() }".to_string(),
                    "type J interface{ N() }; func (S) N() {}",
                ),
                ("P", "*interface{ M() }".to_string(), ""),
            ] {
                let source = format!(
                    "package provider; type I interface{{ M() }}; type {case} = {alias}; type S struct{{ {case} }}; {extra}"
                );
                let fixture = GoRootResolutionOperationFixture::with_sources([
                    "package consumer",
                    &source,
                    "package provider; type Other struct{}",
                ]);
                let context =
                    publish_go_root_fixture_context(&fixture, "example.test/root/provider");
                fixture.store.conn.execute(move |conn| {
                    for table in [
                        "go_context_publications",
                        "go_package_instances",
                        "go_package_imports",
                    ] {
                        conn.execute(
                            &format!("UPDATE {table} SET complete=1 WHERE context_id=?1"),
                            [context],
                        )
                        .unwrap();
                    }
                });
                let cancellation = CancellationToken::new();
                let operation = fixture.open_ready(&cancellation);
                let conn = operation.ready.inventory.connection();
                let interface = go_hierarchy_declaration(conn, GO_ROOT_PROVIDER_PATH, "I");
                let subtype = operation
                    .go_direct_subtypes(
                        context,
                        "go",
                        interface,
                        &cancellation,
                        &ResolutionSession::unbounded(),
                    )
                    .unwrap();
                let (mount,key): (u32,u32) = conn.query_row(
                    "SELECT mount.mount_ordinal,semantic.semantic_key FROM temp.selected_resolution_mounts mount JOIN source_go_type_declarations owner ON owner.blob_id=mount.blob_id AND owner.name='I' JOIN source_go_callables method ON method.blob_id=owner.blob_id AND method.owner_type_id=owner.type_id AND method.name='M' JOIN source_native_declaration_bridges bridge ON bridge.blob_id=method.blob_id AND bridge.declaration_id=method.declaration_id JOIN resolution_semantic_sites semantic ON semantic.blob_id=bridge.blob_id AND semantic.source_site=bridge.source_site AND semantic.semantic_role='definition' WHERE mount.persisted_relative_path=?1",
                    [GO_ROOT_PROVIDER_PATH], |row| Ok((row.get(0)?,row.get(1)?)),
                ).unwrap();
                let family = operation
                    .go_native_method_family(
                        context,
                        "go",
                        SemanticId::local(mount, key),
                        &cancellation,
                        &ResolutionSession::unbounded(),
                    )
                    .unwrap();
                assert!(!subtype.is_complete(), "{case}: {subtype:?}");
                assert!(
                    subtype
                        .open_reasons
                        .contains(&"interface method has no declaring interface identity"),
                    "{case}: {subtype:?}"
                );
                assert!(!family.implemented_by.is_complete(), "{case}: {family:?}");
                assert!(
                    family
                        .implemented_by
                        .open_reasons
                        .contains(&"interface method has no declaring interface identity"),
                    "{case}: {family:?}"
                );
            }
        }

        #[test]
        fn go_embedded_interface_literal_stays_open() {
            use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
            let fixture = GoRootResolutionOperationFixture::with_sources([
                "package consumer",
                "package provider; type I interface{M()}; type J interface{interface{M()}}; type S struct{}; func (S) M(){}",
                "package provider; type Other struct{}",
            ]);
            let context = publish_go_root_fixture_context(&fixture, "example.test/root/provider");
            fixture.store.conn.execute(move |conn| {
                for table in [
                    "go_context_publications",
                    "go_package_instances",
                    "go_package_imports",
                ] {
                    conn.execute(
                        &format!("UPDATE {table} SET complete=1 WHERE context_id=?1"),
                        [context],
                    )
                    .unwrap();
                }
            });
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let interface = go_hierarchy_declaration(
                operation.ready.inventory.connection(),
                GO_ROOT_PROVIDER_PATH,
                "J",
            );
            let answer = operation
                .go_direct_subtypes(
                    context,
                    "go",
                    interface,
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            assert!(
                answer
                    .open_reasons
                    .contains(&"interface method set is incomplete"),
                "{answer:?}"
            );
            assert!(!answer.is_complete(), "{answer:?}");
        }

        #[test]
        fn go_direct_supertypes_confirm_selected_struct_and_interface_embeddings() {
            use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
            let (fixture, context) = go_hierarchy_store();
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let conn = operation.ready.inventory.connection();
            let declaration = |path: &str, name: &str| go_hierarchy_declaration(conn, path, name);
            for (child, parent) in [("Wrap", "Base"), ("J", "I")] {
                let answer = operation
                    .go_direct_supertypes(
                        context,
                        "go",
                        declaration(GO_ROOT_CONSUMER_PATH, child),
                        &cancellation,
                        &ResolutionSession::unbounded(),
                    )
                    .unwrap();
                assert!(
                    answer.embeddings_complete() && !answer.forward_satisfaction_enumerated,
                    "{answer:?}"
                );
                assert!(
                    answer.parents.iter().any(
                        |edge| edge.targets == vec![declaration(GO_ROOT_PROVIDER_PATH, parent)]
                    ),
                    "{answer:?}"
                );
            }
        }

        #[test]
        fn go_forward_supertypes_confirm_structural_targets_and_inherited_interfaces() {
            use brokk_bifrost_analysis::analyzer::resolution::ResolutionTypeRef;
            use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::go_methods::GoMethodSatisfaction;
            use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
            let fixture = GoRootResolutionOperationFixture::with_sources([
                "package consumer; import p \"example.test/root/provider\"; type Use struct{p.T}",
                "package provider; type T struct{}; func (T) Foo(){}; func (T) F() Missing { panic(0) }; type J interface{Foo()}; type I interface{J}; type K interface{I}; type Cut interface{J; Missing}; type E interface{}; type EU interface{Missing}; type Io interface{F() Missing}; type J2 interface{Foo(); Bar()}; type P struct{}; func (*P) Ptr(){}; type IP interface{Ptr()}; type W struct{E}; func (W) Foo(){}; type S struct{}; func (*S) Promoted(){}; type EmbeddedPointer struct{*S}; type IM interface{Promoted()}",
                "package provider; type Decoy struct{}",
            ]);
            let context = publish_go_root_fixture_context(&fixture, "example.test/root/provider");
            fixture.store.conn.execute(move |conn| {
                for table in [
                    "go_context_publications",
                    "go_package_instances",
                    "go_package_imports",
                ] {
                    conn.execute(
                        &format!("UPDATE {table} SET complete=1 WHERE context_id=?1"),
                        [context],
                    )
                    .unwrap();
                }
            });
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let conn = operation.ready.inventory.connection();
            let declaration =
                |name: &str| go_hierarchy_declaration(conn, GO_ROOT_PROVIDER_PATH, name);
            let census = operation
                .go_forward_package_census(
                    context,
                    "go",
                    None,
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            assert_eq!(census, None, "selected source census: {census:?}");
            let stopped_session = ResolutionSession::bounded_with_total_work(
                Default::default(),
                1,
                Some(&cancellation),
            );
            let stopped = operation
                .go_forward_package_census(context, "go", None, &cancellation, &stopped_session)
                .unwrap();
            assert_eq!(stopped, Some("forward census was stopped"));
            let parents = |name: &str| {
                operation
                    .go_direct_supertypes(
                        context,
                        "go",
                        declaration(name),
                        &cancellation,
                        &ResolutionSession::unbounded(),
                    )
                    .unwrap()
            };
            let t = parents("T");
            for name in ["J", "I", "K", "E"] {
                assert!(
                    t.parents
                        .iter()
                        .any(|parent| parent.targets == vec![declaration(name)]),
                    "{name}: {t:?}"
                );
            }
            for name in ["Cut", "EU", "Io"] {
                assert!(
                    !t.parents
                        .iter()
                        .any(|parent| parent.targets == vec![declaration(name)]),
                    "{name}: {t:?}"
                );
            }
            assert!(!t.forward_open_reasons.is_empty(), "{t:?}");
            assert!(
                t.forward_open_reasons
                    .iter()
                    .any(|reason| reason.contains("target closure")),
                "target closure gap must coexist with J, I, K and E: {t:?}"
            );
            let j2 = parents("J2");
            assert!(
                j2.parents
                    .iter()
                    .any(|parent| parent.targets == vec![declaration("I")]),
                "{j2:?}"
            );
            let p = parents("P");
            assert!(
                !p.parents
                    .iter()
                    .any(|parent| parent.targets == vec![declaration("IP")]),
                "{p:?}"
            );
            assert!(!p.forward_satisfaction_enumerated, "{p:?}");
            let p_id = declaration("P");
            let ip_id = declaration("IP");
            let value_proof = operation
                .go_selected_type_satisfaction_for_test(
                    context,
                    "go",
                    ResolutionTypeRef::new(p_id, 0),
                    ip_id,
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap()
                .unwrap();
            let pointer_proof = operation
                .go_selected_type_satisfaction_for_test(
                    context,
                    "go",
                    ResolutionTypeRef::new(p_id, 1),
                    ip_id,
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap()
                .unwrap();
            assert_ne!(value_proof, GoMethodSatisfaction::Satisfies);
            assert_eq!(pointer_proof, GoMethodSatisfaction::Satisfies);
            let inverse = operation
                .go_direct_subtypes(
                    context,
                    "go",
                    ip_id,
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            assert!(inverse.is_complete(), "{inverse:?}");
            assert!(!inverse.edges.contains(&p_id), "{inverse:?}");
            let embedded_pointer = declaration("EmbeddedPointer");
            let im = declaration("IM");
            assert_eq!(
                operation
                    .go_selected_type_satisfaction_for_test(
                        context,
                        "go",
                        ResolutionTypeRef::new(embedded_pointer, 0),
                        im,
                        &cancellation,
                        &ResolutionSession::unbounded(),
                    )
                    .unwrap(),
                Some(GoMethodSatisfaction::Satisfies)
            );
            let promoted_parents = parents("EmbeddedPointer");
            assert!(
                promoted_parents
                    .parents
                    .iter()
                    .any(|parent| parent.targets == vec![im]),
                "{promoted_parents:?}"
            );
            let promoted_inverse = operation
                .go_direct_subtypes(
                    context,
                    "go",
                    im,
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            assert!(
                promoted_inverse.edges.contains(&embedded_pointer),
                "{promoted_inverse:?}"
            );
            let value_inverse = operation
                .go_direct_subtypes(
                    context,
                    "go",
                    declaration("J"),
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            assert!(
                value_inverse.edges.contains(&declaration("T")),
                "{value_inverse:?}"
            );
            let (ordinal, key): (u32, u32) = conn.query_row(
                "SELECT mount.mount_ordinal, semantic.semantic_key FROM temp.selected_resolution_mounts mount JOIN source_go_type_declarations owner ON owner.blob_id=mount.blob_id JOIN source_go_callables method ON method.blob_id=owner.blob_id AND method.owner_type_id=owner.type_id JOIN source_native_declaration_bridges bridge ON bridge.blob_id=method.blob_id AND bridge.declaration_id=method.declaration_id JOIN resolution_semantic_sites semantic ON semantic.blob_id=bridge.blob_id AND semantic.source_site=bridge.source_site AND semantic.semantic_role='definition' WHERE mount.persisted_relative_path=?1 AND owner.name='IP' AND method.name='Ptr'",
                [GO_ROOT_PROVIDER_PATH],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).unwrap();
            let family = operation
                .go_native_method_family(
                    context,
                    "go",
                    brokk_bifrost_analysis::analyzer::resolution::model::SemanticId::local(
                        ordinal, key,
                    ),
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            let (pointer_ordinal, pointer_key): (u32, u32) = conn.query_row(
                "SELECT mount.mount_ordinal, semantic.semantic_key FROM temp.selected_resolution_mounts mount JOIN source_go_callables method ON method.blob_id=mount.blob_id AND method.receiver_type_id IS NOT NULL JOIN source_native_declaration_bridges bridge ON bridge.blob_id=method.blob_id AND bridge.declaration_id=method.declaration_id JOIN resolution_semantic_sites semantic ON semantic.blob_id=bridge.blob_id AND semantic.source_site=bridge.source_site AND semantic.semantic_role='definition' WHERE mount.persisted_relative_path=?1 AND method.name='Ptr'",
                [GO_ROOT_PROVIDER_PATH],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).unwrap();
            assert!(
                family.implemented_by.methods.contains(
                    &brokk_bifrost_analysis::analyzer::resolution::model::SemanticId::local(
                        pointer_ordinal,
                        pointer_key
                    )
                ),
                "{family:?}"
            );
            let mut cut = None;
            for total_work_limit in [32, 64, 128, 256, 512, 1024, 2048, 4096] {
                let session = ResolutionSession::bounded_with_total_work(
                    Default::default(),
                    total_work_limit,
                    Some(&cancellation),
                );
                let answer = operation
                    .go_direct_supertypes(context, "go", declaration("W"), &cancellation, &session)
                    .unwrap();
                if answer
                    .parents
                    .iter()
                    .any(|parent| parent.targets == vec![declaration("E")])
                    && answer
                        .forward_open_reasons
                        .contains(&"forward interface target closure was stopped")
                {
                    cut = Some((total_work_limit, answer));
                    break;
                }
            }
            let (total_work_limit, cut) =
                cut.expect("a bounded target closure cut after E was proven");
            assert!(
                !cut.forward_satisfaction_enumerated,
                "{total_work_limit}: {cut:?}"
            );
            assert!(
                cut.parents
                    .iter()
                    .any(|parent| parent.targets == vec![declaration("E")]),
                "{total_work_limit}: {cut:?}"
            );
            assert!(
                !cut.parents
                    .iter()
                    .any(|parent| parent.targets == vec![declaration("Cut")]),
                "{total_work_limit}: {cut:?}"
            );
        }

        #[test]
        fn go_forward_census_refuses_recovered_and_sourceless_peers() {
            use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
            for variant in ["recovered", "sourceless"] {
                let provider = if variant == "recovered" {
                    "package provider; type T struct{}; func (T) M(){}; type I interface{M()}; func broken("
                } else {
                    "package provider; type T struct{}; func (T) M(){}; type I interface{M()}"
                };
                let fixture = GoRootResolutionOperationFixture::with_sources([
                    "package consumer; import p \"example.test/root/provider\"; type Use struct{p.T}",
                    provider,
                    "package provider; type Other struct{}",
                ]);
                let context =
                    publish_go_root_fixture_context(&fixture, "example.test/root/provider");
                fixture.store.conn.execute(move |conn| {
                    conn.execute("UPDATE go_context_publications SET complete=1 WHERE context_id=?1", [context]).unwrap();
                    conn.execute("UPDATE go_package_instances SET complete=1 WHERE context_id=?1", [context]).unwrap();
                    match variant {
                        "recovered" => {
                            let recovered: i64 = conn.query_row("SELECT count(*) FROM source_structural_recovered_regions", [], |row| row.get(0)).unwrap();
                            assert!(recovered > 0, "fixture must publish a recovered peer");
                        }
                        "sourceless" => { conn.execute("INSERT INTO go_package_instances(context_id,tool_import_path,package_name,for_test,provider_directory,provider_digest,complete,gaps,provider_kind,unit_key) VALUES(?1,'example.test/root/empty','empty','','',zeroblob(32),1,jsonb('[]'),'workspace',randomblob(32))", [context]).unwrap(); }
                        _ => unreachable!(),
                    }
                });
                let cancellation = CancellationToken::new();
                let operation = fixture.open_ready(&cancellation);
                let census = operation
                    .go_forward_package_census(
                        context,
                        "go",
                        None,
                        &cancellation,
                        &ResolutionSession::unbounded(),
                    )
                    .unwrap();
                assert!(census.is_some(), "{variant}: {census:?}");
                let scan = operation
                    .go_forward_empty_interface_scan(
                        context,
                        "go",
                        &cancellation,
                        &ResolutionSession::unbounded(),
                    )
                    .unwrap();
                let declaration = go_hierarchy_declaration(
                    operation.ready.inventory.connection(),
                    GO_ROOT_PROVIDER_PATH,
                    "T",
                );
                let answer = operation
                    .go_direct_supertypes_with_scan(
                        context,
                        "go",
                        declaration,
                        &scan,
                        &cancellation,
                        &ResolutionSession::unbounded(),
                    )
                    .unwrap();
                assert!(
                    !answer.forward_satisfaction_enumerated
                        && !answer.forward_open_reasons.is_empty(),
                    "{variant}: {answer:?}"
                );
            }
        }

        #[test]
        fn go_forward_satisfaction_closes_clean_named_inventory_but_not_inline_alias() {
            use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
            for alias in [0, 1, 2, 3, 4] {
                let provider = match alias {
                    0 => {
                        "package provider; type T struct{}; func (T) M(){}; type I interface{M()}; type E interface{}".to_string()
                    }
                    1 => {
                        "package provider; type T struct{}; func (T) M(){}; type I interface{M()}; type E = interface{}".to_string()
                    }
                    2 => {
                        "package provider; type T struct{}; func (T) M(){}; type I interface{M()}; type E = (interface{})"
                            .to_string()
                    }
                    3 => format!(
                        "package provider; type T struct{{}}; func (T) M(){{}}; type I interface{{M()}}; type E = {}interface{{}}{}",
                        "(".repeat(40), ")".repeat(40)
                    ),
                    _ => "package provider; type T struct{}; func (T) M(){}; type I interface{M()}; type N = (((int)))".to_string(),
                };
                let fixture = GoRootResolutionOperationFixture::with_sources([
                    "package consumer; import p \"example.test/root/provider\"; type Use struct{p.T}",
                    &provider,
                    "package provider; type Other struct{}",
                ]);
                let context =
                    publish_go_root_fixture_context(&fixture, "example.test/root/provider");
                fixture.store.conn.execute(move |conn| {
                    for table in [
                        "go_context_publications",
                        "go_package_instances",
                        "go_package_imports",
                    ] {
                        conn.execute(
                            &format!("UPDATE {table} SET complete=1 WHERE context_id=?1"),
                            [context],
                        )
                        .unwrap();
                    }
                });
                let cancellation = CancellationToken::new();
                let operation = fixture.open_ready(&cancellation);
                if alias == 3 {
                    let wrappers: i64 = operation
                        .ready
                        .inventory
                        .connection()
                        .query_row(
                            "SELECT count(*) FROM temp.selected_resolution_mounts mount \
                         JOIN main.source_go_aliases alias ON alias.blob_id=mount.blob_id \
                         JOIN main.source_go_types ty ON ty.blob_id=alias.blob_id \
                         WHERE mount.persisted_relative_path=?1 AND alias.name='E' AND ty.kind=8",
                            [GO_ROOT_PROVIDER_PATH],
                            |row| row.get(0),
                        )
                        .unwrap();
                    assert!(wrappers > 32, "deep alias was not published: {wrappers}");
                }
                let root = go_hierarchy_declaration(
                    operation.ready.inventory.connection(),
                    GO_ROOT_PROVIDER_PATH,
                    "T",
                );
                let interface = go_hierarchy_declaration(
                    operation.ready.inventory.connection(),
                    GO_ROOT_PROVIDER_PATH,
                    "I",
                );
                let answer = operation
                    .go_direct_supertypes(
                        context,
                        "go",
                        root,
                        &cancellation,
                        &ResolutionSession::unbounded(),
                    )
                    .unwrap();
                assert!(
                    answer
                        .parents
                        .iter()
                        .any(|parent| parent.targets == vec![interface]),
                    "{alias}: {answer:?}"
                );
                if (1..=3).contains(&alias) {
                    assert!(!answer.forward_satisfaction_enumerated, "{answer:?}");
                    assert!(
                        answer
                            .forward_open_reasons
                            .iter()
                            .any(|reason| reason.contains("inline interface alias")),
                        "{answer:?}"
                    );
                } else {
                    assert!(answer.forward_satisfaction_enumerated, "{answer:?}");
                }
            }
        }

        #[test]
        fn go_forward_empty_scan_selected_interface_shapes() {
            use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
            let provider = "package provider; type T struct{}; func (T) M(){}; type E interface{}; type EC interface{/* comment */}; type F interface{E}; type P interface{(E)}; type Q interface{missing.X}; type A = E; type FA interface{A}; type C interface{~int | ~string}; type Comparable interface{comparable}; type U interface{M(); missing.X}; type I interface{M()}";
            let fixture = GoRootResolutionOperationFixture::with_sources([
                "package consumer; import p \"example.test/root/provider\"; type Use struct{p.T}",
                provider,
                "package provider; type Other struct{}",
            ]);
            let context = publish_go_root_fixture_context(&fixture, "example.test/root/provider");
            fixture.store.conn.execute(move |conn| {
                for table in [
                    "go_context_publications",
                    "go_package_instances",
                    "go_package_imports",
                ] {
                    conn.execute(
                        &format!("UPDATE {table} SET complete=1 WHERE context_id=?1"),
                        [context],
                    )
                    .unwrap();
                }
            });
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let conn = operation.ready.inventory.connection();
            for (name, expected) in [
                ("E", 0),
                ("EC", 0),
                ("F", 1),
                ("P", 1),
                ("Q", 1),
                ("FA", 1),
                ("C", 1),
                ("Comparable", 1),
                ("U", 1),
                ("I", 1),
            ] {
                let flag: i64 = conn.query_row(
                    "SELECT ty.has_named_children FROM temp.selected_resolution_mounts mount JOIN source_go_type_declarations declaration ON declaration.blob_id=mount.blob_id JOIN source_go_types ty ON ty.blob_id=declaration.blob_id AND ty.type_id=declaration.type_id AND ty.kind=13 WHERE mount.persisted_relative_path=?1 AND declaration.name=?2",
                    rusqlite::params![GO_ROOT_PROVIDER_PATH, name], |row| row.get(0)
                ).unwrap();
                assert_eq!(flag, expected, "{name}");
            }
            let scan = operation
                .go_forward_empty_interface_scan(
                    context,
                    "go",
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            let declaration = |name| go_hierarchy_declaration(conn, GO_ROOT_PROVIDER_PATH, name);
            let answer = operation
                .go_direct_supertypes_with_scan(
                    context,
                    "go",
                    declaration("T"),
                    &scan,
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            for name in ["E", "EC", "F"] {
                assert!(
                    answer
                        .parents
                        .iter()
                        .any(|parent| parent.targets == vec![declaration(name)]),
                    "{name}: {answer:?}"
                );
            }
            assert!(
                !answer
                    .parents
                    .iter()
                    .any(|parent| parent.targets == vec![declaration("C")]),
                "{answer:?}"
            );
            assert!(
                !scan.is_complete(),
                "unresolved or constraint inventories keep the scan open: {scan:?}"
            );
        }

        #[test]
        fn go_forward_empty_scan_excludes_own_method_with_unresolved_embedding() {
            use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
            let fixture = GoRootResolutionOperationFixture::with_sources([
                "package consumer; import p \"example.test/root/provider\"; type Use struct{p.T}",
                "package provider; type R struct{}; type T struct{}; func (T) M(){}; type E interface{}; type U interface{M(); missing.X}",
                "package provider; type Other struct{}",
            ]);
            let context = publish_go_root_fixture_context(&fixture, "example.test/root/provider");
            fixture.store.conn.execute(move |conn| {
                for table in [
                    "go_context_publications",
                    "go_package_instances",
                    "go_package_imports",
                ] {
                    conn.execute(
                        &format!("UPDATE {table} SET complete=1 WHERE context_id=?1"),
                        [context],
                    )
                    .unwrap();
                }
            });
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let conn = operation.ready.inventory.connection();
            let declaration = |name| go_hierarchy_declaration(conn, GO_ROOT_PROVIDER_PATH, name);
            let scan = operation
                .go_forward_empty_interface_scan(
                    context,
                    "go",
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            assert!(scan.is_complete(), "{scan:?}");
            let r = operation
                .go_direct_supertypes_with_scan(
                    context,
                    "go",
                    declaration("R"),
                    &scan,
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            assert!(r.forward_satisfaction_enumerated, "{r:?}");
            assert!(
                r.parents
                    .iter()
                    .any(|parent| parent.targets == vec![declaration("E")]),
                "{r:?}"
            );
            let t = operation
                .go_direct_supertypes_with_scan(
                    context,
                    "go",
                    declaration("T"),
                    &scan,
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            assert!(!t.forward_satisfaction_enumerated, "{t:?}");
            assert!(
                t.forward_open_reasons
                    .iter()
                    .any(|reason| reason.contains("inventory")),
                "{t:?}"
            );
            assert!(
                !t.parents
                    .iter()
                    .any(|parent| parent.targets == vec![declaration("U")]),
                "{t:?}"
            );
        }

        #[test]
        #[hardwon(
            "#7509: go_direct_subtypes listed the queried interface as its own direct subtype"
        )]
        fn go_direct_subtypes_confirm_embedded_and_combined_method_receivers() {
            use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
            let (fixture, context) = go_hierarchy_store();
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let conn = operation.ready.inventory.connection();
            let declaration = |path: &str, name: &str| go_hierarchy_declaration(conn, path, name);
            let reverse = operation
                .go_direct_subtypes(
                    context,
                    "go",
                    declaration(GO_ROOT_PROVIDER_PATH, "Base"),
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            assert!(reverse.is_complete(), "{reverse:?}");
            assert_eq!(
                reverse.edges,
                vec![
                    declaration(GO_ROOT_CONSUMER_PATH, "Wrap"),
                    declaration(GO_ROOT_CONSUMER_PATH, "Mix"),
                    declaration(GO_ROOT_CONSUMER_PATH, "Mid"),
                ]
            );
            let interface_reverse = operation
                .go_direct_subtypes(
                    context,
                    "go",
                    declaration(GO_ROOT_PROVIDER_PATH, "I"),
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            let interface = declaration(GO_ROOT_PROVIDER_PATH, "I");
            assert!(
                !interface_reverse.edges.contains(&interface),
                "{interface_reverse:?}"
            );
            assert!(
                !interface_reverse.ambiguous.contains(&interface),
                "{interface_reverse:?}"
            );
            assert!(
                !interface_reverse.open.contains(&interface),
                "{interface_reverse:?}"
            );
            assert!(
                interface_reverse
                    .edges
                    .contains(&declaration(GO_ROOT_CONSUMER_PATH, "J")),
                "{interface_reverse:?}"
            );
            assert!(
                interface_reverse
                    .edges
                    .contains(&declaration(GO_ROOT_PROVIDER_PATH, "Base")),
                "{interface_reverse:?}"
            );
            assert!(
                interface_reverse
                    .edges
                    .contains(&declaration(GO_ROOT_CONSUMER_PATH, "Wrap")),
                "{interface_reverse:?}"
            );
            for name in ["Mid", "Leaf"] {
                assert!(
                    interface_reverse
                        .edges
                        .contains(&declaration(GO_ROOT_CONSUMER_PATH, name)),
                    "{name}: {interface_reverse:?}"
                );
            }
            assert!(
                interface_reverse
                    .edges
                    .contains(&declaration(GO_ROOT_CONSUMER_PATH, "SJ")),
                "{interface_reverse:?}"
            );
            assert!(
                interface_reverse
                    .edges
                    .contains(&declaration(GO_ROOT_CONSUMER_PATH, "SA")),
                "{interface_reverse:?}"
            );
            assert!(interface_reverse.is_complete(), "{interface_reverse:?}");
            let (alias_mount, alias_key): (u32, u32) = conn
                .query_row(
                    "SELECT mount.mount_ordinal,member.definition_key FROM temp.selected_resolution_mounts mount JOIN resolution_package_members member ON member.blob_id=mount.blob_id AND member.namespace='type' JOIN resolution_semantic_catalog catalog ON catalog.blob_id=member.blob_id AND catalog.local_key=member.lookup_key JOIN resolution_identities identity ON identity.id=catalog.shared_identity JOIN source_go_aliases alias ON alias.blob_id=member.blob_id AND alias.name=identity.spelling WHERE mount.persisted_relative_path=?1 AND alias.name='Alias'",
                    [GO_ROOT_CONSUMER_PATH],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(
                operation
                    .go_point_type_name(
                        brokk_bifrost_analysis::analyzer::resolution::model::SemanticId::local(
                            alias_mount,
                            alias_key,
                        ),
                        &cancellation,
                    )
                    .unwrap(),
                Some("Alias".to_string())
            );
            let alias_reverse = operation
                .go_direct_subtypes(
                    context,
                    "go",
                    brokk_bifrost_analysis::analyzer::resolution::model::SemanticId::local(
                        alias_mount,
                        alias_key,
                    ),
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            assert!(alias_reverse.is_complete(), "{alias_reverse:?}");
            assert!(
                alias_reverse
                    .edges
                    .contains(&declaration(GO_ROOT_CONSUMER_PATH, "SA")),
                "{alias_reverse:?}"
            );
            assert!(
                alias_reverse
                    .edges
                    .contains(&declaration(GO_ROOT_PROVIDER_PATH, "Base")),
                "cross-blob implementer missing: {alias_reverse:?}"
            );
            let alias = brokk_bifrost_analysis::analyzer::resolution::model::SemanticId::local(
                alias_mount,
                alias_key,
            );
            let member_key: u32 = conn.query_row(
                "SELECT owner.definition_semantic_key FROM temp.selected_resolution_mounts mount JOIN resolution_package_members member ON member.blob_id=mount.blob_id AND member.namespace='type' JOIN resolution_semantic_catalog catalog ON catalog.blob_id=member.blob_id AND catalog.local_key=member.lookup_key JOIN resolution_identities identity ON identity.id=catalog.shared_identity AND identity.spelling='Alias' JOIN resolution_declaration_types alias_type ON alias_type.blob_id=member.blob_id AND alias_type.definition=member.definition_key AND alias_type.role=3 JOIN resolution_type_transfers transfer ON transfer.blob_id=alias_type.blob_id AND transfer.target_slot=alias_type.slot JOIN resolution_declaration_types literal_type ON literal_type.blob_id=transfer.blob_id AND literal_type.slot=transfer.source_slot AND literal_type.role=3 JOIN resolution_member_owner_properties owner ON owner.blob_id=literal_type.blob_id AND owner.owner_definition_semantic_key=literal_type.definition AND owner.member_name='M' WHERE mount.persisted_relative_path=?1",
                [GO_ROOT_CONSUMER_PATH], |row| row.get(0),
            ).unwrap();
            let inventory = operation
                .ready
                .typed_source()
                .go_member_declarations(&[alias], &cancellation)
                .unwrap()
                .unwrap();
            assert!(
                matches!(&inventory[..], [brokk_bifrost_analysis::analyzer::resolution::GoMemberDeclaration { kind: brokk_bifrost_analysis::analyzer::resolution::GoMemberDeclarationKind::Interface { methods }, .. }] if methods.len() == 1 && methods[0].definition == Some(brokk_bifrost_analysis::analyzer::resolution::model::SemanticId::local(alias_mount, member_key))),
                "{inventory:?}"
            );
            let (sa_mount, sa_key): (u32, u32) = conn.query_row(
                "SELECT mount.mount_ordinal,semantic.semantic_key FROM temp.selected_resolution_mounts mount JOIN source_go_callables method ON method.blob_id=mount.blob_id AND method.name='M' AND method.receiver_type_id IS NOT NULL JOIN source_native_declaration_bridges bridge ON bridge.blob_id=method.blob_id AND bridge.declaration_id=method.declaration_id JOIN resolution_semantic_sites semantic ON semantic.blob_id=bridge.blob_id AND semantic.source_site=bridge.source_site AND semantic.semantic_role='definition' WHERE mount.persisted_relative_path=?1",
                [GO_ROOT_CONSUMER_PATH],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).unwrap();
            let alias_family = operation
                .go_native_method_family(
                    context,
                    "go",
                    brokk_bifrost_analysis::analyzer::resolution::model::SemanticId::local(
                        alias_mount,
                        member_key,
                    ),
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            assert!(
                alias_family.implemented_by.is_complete(),
                "{alias_family:?}"
            );
            assert!(
                alias_family.implemented_by.methods.contains(
                    &brokk_bifrost_analysis::analyzer::resolution::model::SemanticId::local(
                        sa_mount, sa_key
                    )
                ),
                "{alias_family:?}"
            );
            let combined = operation
                .go_direct_subtypes(
                    context,
                    "go",
                    declaration(GO_ROOT_PROVIDER_PATH, "I2"),
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            assert!(combined.is_complete(), "{combined:?}");
            assert!(
                combined
                    .edges
                    .contains(&declaration(GO_ROOT_CONSUMER_PATH, "Mix")),
                "{combined:?}"
            );
            assert!(
                !combined
                    .edges
                    .contains(&declaration(GO_ROOT_PROVIDER_PATH, "Base")),
                "{combined:?}"
            );
            let unenumerable = operation
                .go_direct_subtypes(
                    context,
                    "go",
                    declaration(GO_ROOT_PROVIDER_PATH, "Any"),
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            assert!(!unenumerable.is_complete(), "{unenumerable:?}");
            assert!(
                unenumerable
                    .open_reasons
                    .iter()
                    .any(|reason| reason.contains("unenumerable")),
                "{unenumerable:?}"
            );
            let tiny = ResolutionSession::bounded_with_total_work(
                brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget::default(),
                1,
                Some(&cancellation),
            );
            let exhausted = operation
                .go_direct_subtypes(
                    context,
                    "go",
                    declaration(GO_ROOT_PROVIDER_PATH, "Base"),
                    &cancellation,
                    &tiny,
                )
                .unwrap();
            assert!(!exhausted.is_complete(), "{exhausted:?}");
            assert!(
                exhausted
                    .open_reasons
                    .iter()
                    .any(|reason| reason.contains("budget")),
                "{exhausted:?}"
            );
        }

        #[test]
        #[hardwon(
            "#7509: go_native_method_family listed the queried method in its own Implements and ImplementedBy"
        )]
        fn go_native_method_family_confirms_both_directions_and_source_roles() {
            use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;
            use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
            use rusqlite::params;
            let (fixture, context) = go_hierarchy_store();
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let conn = operation.ready.inventory.connection();
            let method = |owner: &str, name: &str| {
                let (ordinal, key): (u32, u32) = conn.query_row(
                    "SELECT mount.mount_ordinal,semantic.semantic_key FROM temp.selected_resolution_mounts mount JOIN source_go_type_declarations owner ON owner.blob_id=mount.blob_id JOIN source_go_callables callable ON callable.blob_id=owner.blob_id JOIN source_native_declaration_bridges bridge ON bridge.blob_id=callable.blob_id AND bridge.declaration_id=callable.declaration_id JOIN resolution_semantic_sites semantic ON semantic.blob_id=bridge.blob_id AND semantic.source_site=bridge.source_site AND semantic.semantic_role='definition' WHERE mount.persisted_relative_path=?1 AND owner.name=?2 AND callable.name=?3 AND (callable.owner_type_id=owner.type_id OR (owner.name='Base' AND callable.owner_type_id IS NULL))",
                    params![GO_ROOT_PROVIDER_PATH, owner, name],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                ).unwrap();
                SemanticId::local(ordinal, key)
            };
            let family = operation
                .go_native_method_family(
                    context,
                    "go",
                    method("Base", "M"),
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            assert!(!family.implements.is_complete(), "{family:?}");
            assert!(
                family
                    .implements
                    .open_reasons
                    .contains(&"promoted method selection does not certify earlier formal IDs")
            );
            assert!(
                !family.implements.methods.contains(&method("Base", "M")),
                "{family:?}"
            );
            assert!(
                family.implements.methods.contains(&method("I", "M")),
                "{family:?}"
            );
            let inverse = operation
                .go_native_method_family(
                    context,
                    "go",
                    method("I", "M"),
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            assert!(inverse.implemented_by.is_complete(), "{inverse:?}");
            assert!(
                !inverse.implements.methods.contains(&method("I", "M")),
                "{inverse:?}"
            );
            assert!(
                !inverse.implemented_by.methods.contains(&method("I", "M")),
                "{inverse:?}"
            );
            assert!(
                inverse.implemented_by.methods.len() >= 3,
                "embedded interface promotions missing from ImplementedBy: {inverse:?}"
            );
            assert!(
                inverse
                    .implemented_by
                    .methods
                    .contains(&method("Base", "M")),
                "{inverse:?}"
            );
            assert!(family.implements.read_keys.coverage.is_some());
            assert!(family.implements.read_keys.names.iter().any(|key| {
                key.relation == brokk_bifrost_analysis::analyzer::store::resolution::TypedFactRelation::InterfaceMethodLookup
            }));
            let decoy_method: (u32, u32) = conn.query_row(
                "SELECT mount.mount_ordinal,semantic.semantic_key FROM temp.selected_resolution_mounts mount JOIN source_go_callables callable ON callable.blob_id=mount.blob_id JOIN source_native_declaration_bridges bridge ON bridge.blob_id=callable.blob_id AND bridge.declaration_id=callable.declaration_id JOIN resolution_semantic_sites semantic ON semantic.blob_id=bridge.blob_id AND semantic.source_site=bridge.source_site AND semantic.semantic_role='definition' WHERE mount.persisted_relative_path=?1 AND callable.name='M'",
                [GO_ROOT_DECOY_PATH],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).unwrap();
            let decoy_method = SemanticId::local(decoy_method.0, decoy_method.1);
            assert!(
                !family.implements.methods.contains(&decoy_method),
                "{family:?}"
            );
            let test_family = operation
                .go_native_method_family(
                    context,
                    "test",
                    method("Base", "M"),
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            assert!(
                test_family.implements.methods.contains(&decoy_method),
                "{test_family:?}"
            );
            let cancelled = CancellationToken::new();
            cancelled.cancel();
            let stopped = operation
                .go_native_method_family(
                    context,
                    "go",
                    method("Base", "M"),
                    &cancelled,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            assert!(!stopped.implements.is_complete(), "{stopped:?}");
            assert!(!stopped.implemented_by.is_complete(), "{stopped:?}");
            assert!(
                stopped
                    .implements
                    .open_reasons
                    .iter()
                    .any(|reason| reason.contains("cancelled")),
                "{stopped:?}"
            );
            assert!(
                stopped
                    .implemented_by
                    .open_reasons
                    .iter()
                    .any(|reason| reason.contains("cancelled")),
                "{stopped:?}"
            );
        }

        #[test]
        #[hardwon(
            "#7509: anonymous interface method family returned a closed empty implementor set"
        )]
        fn go_anonymous_interface_method_family_probe() {
            use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;
            use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
            use rusqlite::{OptionalExtension, params};
            let cases = [
                (
                    "parameter",
                    "package provider; type T struct{}; func (T) M(){}; func f(x interface{ M() }) { x.M() }",
                    "M",
                ),
                (
                    "field",
                    "package provider; type T struct{}; func (T) Y(){}; type W struct{ f interface{ Y() } }",
                    "Y",
                ),
                (
                    "deep_alias",
                    &format!(
                        "package provider; type T struct{{}}; func (T) M(){{}}; type E = {}interface{{ M() }}{}",
                        "(".repeat(40),
                        ")".repeat(40)
                    ),
                    "M",
                ),
                (
                    "named",
                    "package provider; type T struct{}; func (T) M(){}; type I interface{ M() }",
                    "M",
                ),
            ];
            let mut false_closed = Vec::new();
            for (case, source, name) in cases {
                let fixture = GoRootResolutionOperationFixture::with_sources([
                    "package consumer",
                    source,
                    "package provider; type Other struct{}",
                ]);
                let context =
                    publish_go_root_fixture_context(&fixture, "example.test/root/provider");
                fixture.store.conn.execute(move |conn| {
                    for table in [
                        "go_context_publications",
                        "go_package_instances",
                        "go_package_imports",
                    ] {
                        conn.execute(
                            &format!("UPDATE {table} SET complete=1 WHERE context_id=?1"),
                            [context],
                        )
                        .unwrap();
                    }
                });
                let cancellation = CancellationToken::new();
                let operation = fixture.open_ready(&cancellation);
                let conn = operation.ready.inventory.connection();
                let method: Option<(u32, u32)> = conn.query_row(
                    "SELECT mount.mount_ordinal, semantic.semantic_key FROM temp.selected_resolution_mounts mount JOIN source_go_callables callable ON callable.blob_id=mount.blob_id JOIN source_go_types owner ON owner.blob_id=callable.blob_id AND owner.type_id=callable.owner_type_id AND owner.kind=13 JOIN source_native_declaration_bridges bridge ON bridge.blob_id=callable.blob_id AND bridge.declaration_id=callable.declaration_id JOIN resolution_semantic_sites semantic ON semantic.blob_id=bridge.blob_id AND semantic.source_site=bridge.source_site AND semantic.semantic_role='definition' WHERE mount.persisted_relative_path=?1 AND callable.name=?2 AND callable.is_method=1 LIMIT 1",
                    params![GO_ROOT_PROVIDER_PATH, name], |row| Ok((row.get(0)?, row.get(1)?)),
                ).optional().unwrap();
                eprintln!("{case}: selected interface method = {method:?}");
                if case == "field" || case == "named" {
                    assert!(method.is_some(), "{case}: missing selected method");
                }
                if let Some((mount, key)) = method {
                    let family = operation
                        .go_native_method_family(
                            context,
                            "go",
                            SemanticId::local(mount, key),
                            &cancellation,
                            &ResolutionSession::unbounded(),
                        )
                        .unwrap();
                    eprintln!("{case}: native family = {family:?}");
                    if case == "field" {
                        assert!(
                            family
                                .implemented_by
                                .open_reasons
                                .contains(&"interface method has no declaring interface identity"),
                            "{family:?}"
                        );
                        assert!(family.implements.open_reasons.is_empty(), "{family:?}");
                    }
                    if case == "named" {
                        let (receiver_mount, receiver_key): (u32, u32) = conn.query_row(
                            "SELECT mount.mount_ordinal, semantic.semantic_key FROM temp.selected_resolution_mounts mount JOIN source_go_callables callable ON callable.blob_id=mount.blob_id AND callable.receiver_type_id IS NOT NULL JOIN source_native_declaration_bridges bridge ON bridge.blob_id=callable.blob_id AND bridge.declaration_id=callable.declaration_id JOIN resolution_semantic_sites semantic ON semantic.blob_id=bridge.blob_id AND semantic.source_site=bridge.source_site AND semantic.semantic_role='definition' WHERE mount.persisted_relative_path=?1 AND callable.name='M'",
                            [GO_ROOT_PROVIDER_PATH], |row| Ok((row.get(0)?, row.get(1)?)),
                        ).unwrap();
                        assert!(family.implemented_by.is_complete(), "{family:?}");
                        assert!(
                            family
                                .implemented_by
                                .methods
                                .contains(&SemanticId::local(receiver_mount, receiver_key)),
                            "{family:?}"
                        );
                    }
                    if family.implemented_by.is_complete()
                        && family.implemented_by.methods.is_empty()
                        && case != "named"
                    {
                        false_closed.push(case);
                    }
                }
            }
            assert!(false_closed.is_empty(), "false closed: {false_closed:?}");
        }

        #[test]
        #[hardwon(
            "#7509: native Go Implements missed promoted receivers and returned a complete negative"
        )]
        fn go_method_family_closes_promoted_receiver_forms() {
            use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;
            use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
            use rusqlite::params;

            let fixture = GoRootResolutionOperationFixture::with_sources([
                "package consumer",
                r#"package provider
type I interface { A(); B() }
type m struct{}
func (*m) A() {}
type s struct{}
func (*s) B() {}
type c struct { *m; s }
type p struct{}
func (*p) A() {}
func (*p) B() {}
type v struct{}
func (v) A() {}
func (v) B() {}
type w struct { v }
type upper struct { c }
type lower struct { upper; *s }
type shadow struct { *m; s }
func (*shadow) A() {}
type left struct{}
func (*left) A() {}
type right struct{}
func (*right) A() {}
type ambiguous struct { *left; *right; s }
type J interface { I }
type D int
func (D) A() {}
func (D) B() {}
type valueEmbed struct { v }
type pointerEmbed struct { *v }
type definedPointer *v
type Alias = v
type aliasEmbed struct { Alias }
"#,
                "package provider; type Decoy struct{}",
            ]);
            let context = publish_go_root_fixture_context(&fixture, "example.test/root/provider");
            fixture.store.conn.execute(move |conn| {
                for table in [
                    "go_context_publications",
                    "go_package_instances",
                    "go_package_imports",
                ] {
                    conn.execute(
                        &format!("UPDATE {table} SET complete=1 WHERE context_id=?1"),
                        [context],
                    )
                    .unwrap();
                }
            });
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let conn = operation.ready.inventory.connection();
            let method = |owner: &str, name: &str| {
                let (ordinal, key): (u32, u32) = conn.query_row(
                    "SELECT mount.mount_ordinal, semantic.semantic_key FROM temp.selected_resolution_mounts mount JOIN source_go_callables callable ON callable.blob_id=mount.blob_id LEFT JOIN source_go_type_declarations owner ON owner.blob_id=callable.blob_id AND owner.type_id=callable.owner_type_id LEFT JOIN source_go_types receiver ON receiver.blob_id=callable.blob_id AND receiver.type_id=callable.receiver_type_id LEFT JOIN source_go_types base ON base.blob_id=receiver.blob_id AND base.type_id=CASE WHEN receiver.kind=1 THEN receiver.child1 ELSE receiver.type_id END LEFT JOIN source_go_type_names receiver_name ON receiver_name.blob_id=base.blob_id AND receiver_name.type_id=base.type_id AND receiver_name.ordinal=0 JOIN source_native_declaration_bridges bridge ON bridge.blob_id=callable.blob_id AND bridge.declaration_id=callable.declaration_id JOIN resolution_semantic_sites semantic ON semantic.blob_id=bridge.blob_id AND semantic.source_site=bridge.source_site AND semantic.semantic_role='definition' WHERE mount.persisted_relative_path=?1 AND (owner.name=?2 OR receiver_name.name=?2) AND callable.name=?3",
                    params![GO_ROOT_PROVIDER_PATH, owner, name],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                ).unwrap_or_else(|error| panic!("method {owner}.{name}: {error}"));
                SemanticId::local(ordinal, key)
            };
            let interface = method("I", "A");
            // Every returned method ID is checked, including the absence of a
            // promoted owner behind shadowing and equal-depth ambiguity.
            for owner in ["m", "p", "v", "D", "shadow", "left", "right"] {
                let concrete = method(owner, "A");
                let forward = operation
                    .go_native_method_family(
                        context,
                        "go",
                        concrete,
                        &cancellation,
                        &ResolutionSession::unbounded(),
                    )
                    .unwrap();
                let expected = if ["m", "left", "right"].contains(&owner) {
                    Vec::new()
                } else {
                    vec![interface]
                };
                assert_eq!(forward.implements.methods, expected, "{owner}: {forward:?}");
                if owner == "m" {
                    assert!(!forward.implements.is_complete(), "{owner}: {forward:?}");
                    assert!(forward.implements.open_reasons.contains(
                        &"promoted method selection does not certify earlier formal IDs"
                    ));
                }
            }
            let inverse = operation
                .go_native_method_family(
                    context,
                    "go",
                    interface,
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            let mut expected = ["m", "p", "v", "D", "shadow"]
                .into_iter()
                .map(|owner| method(owner, "A"))
                .collect::<Vec<_>>();
            expected.sort();
            let mut actual = inverse.implemented_by.methods.clone();
            actual.sort();
            assert_eq!(actual, expected, "{inverse:?}");
            let cancelled = CancellationToken::new();
            cancelled.cancel();
            let stopped = operation
                .go_native_method_family(
                    context,
                    "go",
                    method("m", "A"),
                    &cancelled,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            assert!(!stopped.implements.is_complete(), "{stopped:?}");
            assert!(!stopped.implemented_by.is_complete(), "{stopped:?}");
            let interface_subtypes = operation
                .go_direct_subtypes(
                    context,
                    "go",
                    go_hierarchy_declaration(conn, GO_ROOT_PROVIDER_PATH, "I"),
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            let mut expected_subtypes = [
                "J",
                "v",
                "w",
                "D",
                "valueEmbed",
                "pointerEmbed",
                "aliasEmbed",
                "lower",
            ]
            .into_iter()
            .map(|name| go_hierarchy_declaration(conn, GO_ROOT_PROVIDER_PATH, name))
            .collect::<Vec<_>>();
            expected_subtypes.sort();
            let mut actual_subtypes = interface_subtypes.edges.clone();
            actual_subtypes.sort();
            assert_eq!(actual_subtypes, expected_subtypes, "{interface_subtypes:?}");
            assert!(interface_subtypes.is_complete(), "{interface_subtypes:?}");
            let subtype = operation
                .go_direct_subtypes(
                    context,
                    "go",
                    go_hierarchy_declaration(conn, GO_ROOT_PROVIDER_PATH, "m"),
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            assert!(
                subtype
                    .edges
                    .contains(&go_hierarchy_declaration(conn, GO_ROOT_PROVIDER_PATH, "c")),
                "{subtype:?}"
            );
        }

        #[test]
        fn go_alias_embeddings_follow_chains_and_fail_closed() {
            use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;
            use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
            use rusqlite::params;

            let fixture = GoRootResolutionOperationFixture::with_sources([
                "package consumer; import p \"example.test/root/provider\"; type Alias = p.Base; type Wrap struct{Alias}; type A1 = p.Base; type A2 = A1; type Deep struct{A2}; type P = *p.WrappedBase; type S struct{P}; type Q = (p.WrappedBase); type U struct{Q}; type C1 = C2; type C2 = C1; type CycleWrap struct{C1}; type Self = Self; type SelfWrap struct{Self}; type Missing = p.Nope; type MissingWrap struct{Missing}; type Direct struct{p.Base}",
                "package provider; type Base struct{}; type WrappedBase struct{}",
                "package provider; type Decoy struct{}",
            ]);
            let context = publish_go_root_fixture_context(&fixture, "example.test/root/provider");
            fixture.store.conn.execute(move |conn| {
                conn.execute(
                    "UPDATE go_context_publications SET complete=1 WHERE context_id=?1",
                    [context],
                )
                .unwrap();
                conn.execute(
                    "UPDATE go_package_instances SET complete=1 WHERE context_id=?1",
                    [context],
                )
                .unwrap();
                conn.execute(
                    "UPDATE go_package_imports SET complete=1 WHERE context_id=?1",
                    [context],
                )
                .unwrap();
            });
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let conn = operation.ready.inventory.connection();
            let declaration = |path: &str, name: &str| {
                let (ordinal, key): (u32, u32) = conn.query_row(
                    "SELECT mount.mount_ordinal,semantic.semantic_key FROM temp.selected_resolution_mounts mount JOIN source_go_type_declarations declaration ON declaration.blob_id=mount.blob_id JOIN source_native_declaration_bridges bridge ON bridge.blob_id=declaration.blob_id AND bridge.declaration_id=declaration.declaration_id JOIN resolution_semantic_sites semantic ON semantic.blob_id=bridge.blob_id AND semantic.source_site=bridge.source_site AND semantic.semantic_role='definition' WHERE mount.persisted_relative_path=?1 AND declaration.name=?2",
                    params![path, name],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                ).unwrap();
                SemanticId::local(ordinal, key)
            };
            let mut statement = conn
                .prepare(
                    "SELECT identity.spelling FROM temp.selected_resolution_mounts mount \
                 JOIN resolution_typed_fact_lookups lookup ON lookup.blob_id=mount.blob_id \
                 JOIN resolution_identities identity ON identity.id=lookup.identity_id \
                 WHERE mount.persisted_relative_path=?1 AND lookup.relation=?2 \
                 ORDER BY identity.spelling",
                )
                .unwrap();
            let alias_target_names = statement.query_map(
                params![
                    GO_ROOT_CONSUMER_PATH,
                    brokk_bifrost_analysis::analyzer::store::resolution::TypedFactRelation::AliasTargetLookup.code(),
                ],
                |row| row.get::<_, String>(0),
            ).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            assert_eq!(
                alias_target_names,
                ["A1", "Base", "C1", "C2", "Nope", "Self", "WrappedBase"]
            );
            drop(statement);
            let direct = operation
                .go_direct_supertypes(
                    context,
                    "go",
                    declaration(GO_ROOT_CONSUMER_PATH, "Direct"),
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            assert!(direct.embeddings_complete(), "{direct:?}");
            assert!(
                !direct.forward_satisfaction_enumerated
                    && direct
                        .forward_open_reasons
                        .contains(&"alias target has no complete selected terminal"),
                "{direct:?}"
            );
            assert_eq!(
                direct.parents[0].targets,
                vec![declaration(GO_ROOT_PROVIDER_PATH, "Base")]
            );
            let alias = operation
                .go_direct_supertypes(
                    context,
                    "go",
                    declaration(GO_ROOT_CONSUMER_PATH, "Wrap"),
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            assert!(
                alias.embeddings_complete() && !alias.forward_satisfaction_enumerated,
                "{alias:?}"
            );
            assert_eq!(
                alias.parents[0].targets,
                vec![declaration(GO_ROOT_PROVIDER_PATH, "Base")]
            );
            let deep = operation
                .go_direct_supertypes(
                    context,
                    "go",
                    declaration(GO_ROOT_CONSUMER_PATH, "Deep"),
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            assert!(
                deep.embeddings_complete() && !deep.forward_satisfaction_enumerated,
                "{deep:?}"
            );
            assert_eq!(
                deep.parents[0].targets,
                vec![declaration(GO_ROOT_PROVIDER_PATH, "Base")]
            );
            for name in ["S", "U"] {
                let wrapped = operation
                    .go_direct_supertypes(
                        context,
                        "go",
                        declaration(GO_ROOT_CONSUMER_PATH, name),
                        &cancellation,
                        &ResolutionSession::unbounded(),
                    )
                    .unwrap();
                assert!(
                    wrapped.embeddings_complete() && !wrapped.forward_satisfaction_enumerated,
                    "{name}: {wrapped:?}"
                );
                assert_eq!(
                    wrapped.parents[0].targets,
                    vec![declaration(GO_ROOT_PROVIDER_PATH, "WrappedBase")],
                    "{name}: {wrapped:?}"
                );
            }
            let inverse = operation
                .go_direct_subtypes(
                    context,
                    "go",
                    declaration(GO_ROOT_PROVIDER_PATH, "Base"),
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            assert!(inverse.is_complete(), "{inverse:?}");
            for name in ["Direct", "Wrap", "Deep"] {
                assert!(
                    inverse
                        .edges
                        .contains(&declaration(GO_ROOT_CONSUMER_PATH, name)),
                    "{name}: {inverse:?}"
                );
            }
            let wrapped_inverse = operation
                .go_direct_subtypes(
                    context,
                    "go",
                    declaration(GO_ROOT_PROVIDER_PATH, "WrappedBase"),
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            assert!(wrapped_inverse.is_complete(), "{wrapped_inverse:?}");
            for name in ["S", "U"] {
                assert!(
                    wrapped_inverse
                        .edges
                        .contains(&declaration(GO_ROOT_CONSUMER_PATH, name)),
                    "{name}: {wrapped_inverse:?}"
                );
            }
            for (name, reason) in [
                ("CycleWrap", "alias target cycle"),
                ("SelfWrap", "alias target cycle"),
                ("MissingWrap", "alias target is unresolved"),
            ] {
                let result = operation
                    .go_direct_supertypes(
                        context,
                        "go",
                        declaration(GO_ROOT_CONSUMER_PATH, name),
                        &cancellation,
                        &ResolutionSession::unbounded(),
                    )
                    .unwrap();
                assert!(!result.is_complete(), "{name}: {result:?}");
                assert!(
                    result
                        .parents
                        .iter()
                        .any(|parent| parent.open_reason == Some(reason)),
                    "{name}: {result:?}"
                );
            }
        }

        #[test]
        #[hardwon("#5658: Go alias summaries materialized occurrence arenas for unrelated blobs")]
        fn native_query_plan_go_alias_rows_are_identical() {
            let fixture = GoRootResolutionOperationFixture::with_sources([
                "package consumer; import provider \"example.test/root/provider\"; type Alias = provider.Item; type Local = Alias; type Slice = []int; type Unknown = missing.Type",
                "package provider; type Item struct {}; type Alias = Item",
                "package provider; type Decoy struct {}; type Alias = Decoy",
            ]);
            let context = publish_go_root_fixture_context(&fixture, "example.test/root/provider");
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let conn = operation.ready.inventory.connection();
            brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::prepare_pin_context(conn);
            let snapshot = &fixture.snapshots["go"];
            conn.execute("DELETE FROM temp.go_summary_snapshot", [])
                .unwrap();
            conn.execute(
                "INSERT INTO temp.go_summary_snapshot VALUES(?1,'go',?2,?3)",
                rusqlite::params![
                    snapshot.workspace_id.as_str(),
                    snapshot.generation.get(),
                    snapshot.revision
                ],
            )
            .unwrap();
            let registry = registry();
            let sql = &registry
                .statements
                .iter()
                .find(|(name, _)| name.ends_with("::UNIT_ALIAS_EXPORTS_SQL"))
                .unwrap()
                .1;
            let begin = sql.find("     -- Filter the join view").unwrap();
            let end = sql.find("       ON target_occurrence.blob_id").unwrap();
            let old = format!(
                "{}     LEFT JOIN main.source_occurrences AS target_occurrence\n{}",
                &sql[..begin],
                &sql[end..]
            );
            let generation = fixture.snapshots["go"].generation.get();
            let epoch: String = conn
                .query_row(
                    "SELECT producer_epoch FROM resolution_producer_epochs WHERE lang='go'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let packages: Vec<i64> = conn
                .prepare("SELECT package_id FROM go_package_instances WHERE context_id=?1")
                .unwrap()
                .query_map([context], |row| row.get(0))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            let mut count = 0;
            for package in packages {
                let read = |sql: &str| {
                    let mut statement = conn.prepare(sql).unwrap();
                    let columns = statement.column_count();
                    let mut rows: Vec<String> = statement
                        .query_map(
                            rusqlite::params![context, package, "go", generation, epoch],
                            |row| {
                                let values = (0..columns)
                                    .map(|column| row.get::<_, rusqlite::types::Value>(column))
                                    .collect::<rusqlite::Result<Vec<_>>>()?;
                                Ok(format!("{values:?}"))
                            },
                        )
                        .unwrap()
                        .collect::<rusqlite::Result<_>>()
                        .unwrap();
                    rows.sort();
                    rows
                };
                let expected = read(&old);
                assert_eq!(expected, read(sql), "package {package}");
                count += expected.len();
                eprintln!("package {package}: {expected:#?}");
            }
            assert!(
                count >= 6,
                "expected populated local, qualified and unnamed aliases, found {count}"
            );
        }
    }
    mod go_move_5 {
        use crate::engine_tests::go_extraction::go_extraction_tests::go_move_11::*;

        use std::collections::BTreeSet;

        use brokk_bifrost_core::cancellation::CancellationToken;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;

        use brokk_bifrost_analysis :: analyzer :: store :: resolution_operation :: resolution_operation_tests_go_support :: operation_fixture_support :: site_for_identifier ;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::package_context::SelectedPackageRows;

        #[test]
        fn selected_go_package_members_group_matches_per_lookup_with_staged_rename() {
            use brokk_bifrost_analysis::analyzer::store::resolution_stage::codec::encode_node;

            use brokk_bifrost_analysis::analyzer::store::resolution_stage::codec::encode_semantic;

            let provider = "package provider; type Item struct{}; type Replacement struct{}";
            let fixture = GoRootResolutionOperationFixture::with_sources([
                GO_ROOT_CONSUMER_SOURCE,
                provider,
                GO_ROOT_DECOY_SOURCE,
            ]);
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let mount = operation
                .mount_table()
                .mount_for_path("go", GO_ROOT_PROVIDER_PATH)
                .unwrap()
                .unwrap();
            let SelectedPackageRows::Ready(ordinary) = operation
                .ready
                .selected_package_members_by_lookup(mount.ordinal(), &cancellation)
                .unwrap()
            else {
                panic!("not cancelled");
            };
            let mut members = ordinary.values().flatten().copied().collect::<Vec<_>>();
            let item = members
                .iter()
                .find(|member| {
                    member.source_site
                        == site_for_identifier(
                            &fixture.provider_facts,
                            "Item",
                            ResolutionIdentifierRole::Declaration,
                            ResolutionNamespace::Type,
                        )
                })
                .copied()
                .expect("Item package member");
            let replacement_lookup = members
                .iter()
                .find(|member| member.lookup != item.lookup)
                .map(|member| member.lookup)
                .expect("Replacement package member lookup");
            members
                .iter_mut()
                .find(|member| {
                    member.definition == item.definition && member.namespace == item.namespace
                })
                .expect("Item package member identity")
                .lookup = replacement_lookup;
            let lookups = ordinary.keys().copied().collect::<BTreeSet<_>>();

            operation
        .ready
        .inventory
        .with_owned_temp_write(|connection| {
            connection.execute(
                "INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(?1,?2,?3)",
                rusqlite::params![mount.ordinal().get(), [41_u8; 32].as_slice(), [42_u8; 32].as_slice()],
            )?;
            let producer = connection.last_insert_rowid();
            for member in &members {
                connection.execute(
                    "INSERT INTO temp.selected_resolution_stage_package_members(host_ordinal,producer_id,token_key,domain_shared,definition_key,source_site,root_scope_key,namespace,lookup_shared) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                    rusqlite::params![
                        mount.ordinal().get(),
                        producer,
                        encode_semantic(member.token),
                        member.domain.shared_name_id().unwrap().get(),
                        encode_semantic(member.definition),
                        member.source_site.get(),
                        encode_node(member.root_scope),
                        member.namespace.label(),
                        member.lookup.shared_name_id().unwrap().get(),
                    ],
                )?;
            }
            Ok(())
        })
        .unwrap();

            let SelectedPackageRows::Ready(grouped) = operation
                .ready
                .selected_package_members_by_lookup(mount.ordinal(), &cancellation)
                .unwrap()
            else {
                panic!("not cancelled");
            };
            let actual = grouped.values().flatten().copied().collect::<BTreeSet<_>>();
            let mut oracle = BTreeSet::new();
            for lookup in lookups {
                let SelectedPackageRows::Ready(members) = operation
                    .ready
                    .selected_package_members_for_lookup(mount.ordinal(), lookup, &cancellation)
                    .unwrap()
                else {
                    panic!("not cancelled");
                };
                oracle.extend(members);
            }
            assert_eq!(actual, oracle);
            assert!(
                !actual.contains(&item),
                "the staged rename withdraws the old key"
            );
            assert!(
                actual
                    .iter()
                    .any(|member| member.definition == item.definition
                        && member.lookup == replacement_lookup),
                "the staged rename retains Item under its replacement lookup"
            );
        }
        #[test]
        fn selected_go_package_member_mount_queries_seek_in_both_statistics_states() {
            use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::explain_pin;

            use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned;
            use brokk_bifrost_core::cache_gc::PlannerStatisticsState;

            for statistics in PlannerStatisticsState::BOTH {
                let fixture = GoRootResolutionOperationFixture::new();
                fixture
                    .store
                    .conn
                    .execute(move |connection| statistics.install(connection));
                let cancellation = CancellationToken::new();
                let operation = fixture.open_ready(&cancellation);
                let mount = operation
                    .mount_table()
                    .mount_for_path("go", GO_ROOT_PROVIDER_PATH)
                    .unwrap()
                    .unwrap();
                for (name, index) in [
                    ("native_package_members_by_mount", "PRIMARY KEY"),
                    (
                        "native_stage_package_members_by_mount",
                        "selected_resolution_stage_package_members_host",
                    ),
                ] {
                    let mut pin = pinned(name);
                    pin.params = vec![rusqlite::types::Value::Integer(i64::from(
                        mount.ordinal().get(),
                    ))];
                    let plan = explain_pin(operation.ready.inventory.connection(), &pin);
                    assert!(
                        plan.iter()
                            .any(|detail| detail.starts_with("SEARCH p USING")
                                && detail.contains(index)),
                        "{name} with {statistics}: {plan:?}"
                    );
                    assert!(
                        plan.iter().all(|detail| !detail.starts_with("SCAN p")
                            && !detail.contains("AUTOMATIC")
                            && !detail.contains("TEMP B-TREE")),
                        "{name} with {statistics}: {plan:?}"
                    );
                }
            }
        }
    }
    mod go_move_6 {

        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_core::analyzer::model::ProjectFile;

        use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;

        use brokk_bifrost_analysis::analyzer::usages::get_type::parse_tree_for_type_lookup;

        use brokk_bifrost_analysis::analyzer::usages::get_type::validate_caller_reference_site;

        #[test]
        #[brokk_bifrost_test_macros::hardwon(
            "#4811: the type validator rejected files whose parsed root starts after leading whitespace"
        )]
        fn caller_reference_root_accepts_trivia_and_rejects_uncovered_ranges() {
            for (language, path, source, reference) in [
                (
                    Language::Python,
                    "app.py",
                    "\nclass Widget:\n    pass\n\n",
                    "Widget",
                ),
                (
                    Language::Php,
                    "app.php",
                    "\n<?php class Widget {}\n\n",
                    "Widget",
                ),
                (
                    Language::Ruby,
                    "app.rb",
                    "\nclass Widget\nend\n\n",
                    "Widget",
                ),
                (
                    Language::Go,
                    "app.go",
                    "\npackage main\ntype Widget struct {}\n\n",
                    "Widget",
                ),
            ] {
                let root = std::env::current_dir().expect("absolute project root");
                let file = ProjectFile::new(root, path);
                let tree =
                    parse_tree_for_type_lookup(&file, language, source).expect("grammar parses");
                let start = source.find(reference).unwrap();
                let mut site = ResolvedReferenceSite {
                    path: path.to_string(),
                    text: reference.to_string(),
                    range: brokk_bifrost_core::analyzer::model::Range {
                        start_byte: start,
                        end_byte: start + reference.len(),
                        start_line: 0,
                        end_line: 0,
                    },
                    focus_start_byte: start,
                    focus_end_byte: start + reference.len(),
                };
                let syntax_root = tree.root_node();
                eprintln!(
                    "{language:?}: root {}..{}, source {}",
                    syntax_root.start_byte(),
                    syntax_root.end_byte(),
                    source.len()
                );
                if language == Language::Python {
                    assert!(syntax_root.start_byte() > 0);
                }
                assert!(validate_caller_reference_site(&file, source, Some(&tree), &site).is_ok());
                // The same parsed tree remains valid when the supplied source has
                // trailing trivia beyond its root, but not for a reference there.
                let padded = format!("{source}   ");
                assert!(validate_caller_reference_site(&file, &padded, Some(&tree), &site).is_ok());
                let extended = format!("{source}{reference}");
                site.range.start_byte = source.len();
                site.range.end_byte = extended.len();
                site.focus_start_byte = site.range.start_byte;
                site.focus_end_byte = site.range.end_byte;
                assert!(
                    validate_caller_reference_site(&file, &extended, Some(&tree), &site).is_err()
                );
                assert!(
                    validate_caller_reference_site(
                        &file,
                        reference,
                        Some(&tree),
                        &ResolvedReferenceSite {
                            range: brokk_bifrost_core::analyzer::model::Range {
                                start_byte: 0,
                                end_byte: reference.len(),
                                start_line: 0,
                                end_line: 0
                            },
                            focus_start_byte: 0,
                            focus_end_byte: reference.len(),
                            ..site
                        }
                    )
                    .is_err()
                );
            }
        }
    }
    mod go_move_7 {

        use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::ArgumentFormalBinding;

        use brokk_bifrost_core::analyzer::Language;

        use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredCallApplicabilityObligation;

        use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredCallableSignatureProperty;

        use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::MappingAssessment;

        use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;

        use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::adapter;

        #[test]
        fn go_maps_every_extra_argument_to_the_trailing_variadic_formal() {
            use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

            use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredCallArgumentProperty;

            use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredCallableParameterApplicability;

            use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredCallableParameterProperty;

            let id = |label: &'static [u8]| SemanticId::for_test(label);
            let call = LoweredCallApplicabilityObligation::new(
                id(b"call"),
                id(b"reference"),
                None,
                id(b"result"),
                vec![id(b"first"), id(b"second")],
                Vec::new(),
                0,
                id(b"reason"),
                ResolutionCompletion::Complete,
            )
            .with_argument_shape(
                Language::Go,
                vec![
                    LoweredCallArgumentProperty::new(0, 0, id(b"first"), None),
                    LoweredCallArgumentProperty::new(0, 1, id(b"second"), None),
                ],
                vec![0],
            );
            let signature = LoweredCallableSignatureProperty::new(
                id(b"callable"),
                0,
                vec![LoweredCallableParameterProperty::new(
                    0,
                    id(b"variadic"),
                    id(b"variadic-type"),
                    true,
                )],
                ResolutionCompletion::Complete,
            )
            .with_applicability_shape(
                vec![0],
                vec![LoweredCallableParameterApplicability::new(
                    0, 0, None, false, true,
                )],
                None,
            );

            assert_eq!(
                adapter(Language::Go).map_arguments(&call, &signature),
                MappingAssessment::Mapped {
                    bindings: vec![
                        ArgumentFormalBinding {
                            argument_index: 0,
                            parameter_index: 0,
                        },
                        ArgumentFormalBinding {
                            argument_index: 1,
                            parameter_index: 0,
                        },
                    ],
                    used_defaults: 0,
                    used_vararg: true,
                    result_application_lists: vec![],
                }
            );
        }
    }

    mod go_named_alias_terminal_controls {
        use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
        use brokk_bifrost_analysis::CodeUnitIndex;
        use brokk_bifrost_analysis::analyzer::AnalyzerQueryScope;
        use brokk_bifrost_analysis::analyzer::usages::member_family::{
            MemberFamilyProvider, member_family_id,
        };
        use brokk_bifrost_core::analyzer::capabilities::{HierarchyAnswer, TypeHierarchyProvider};
        use brokk_bifrost_core::analyzer::model::{CodeUnit, Language};
        use brokk_bifrost_core::analyzer::structural::resolution::{
            MemberFamilyOutcome, MethodFamilyRelation,
        };
        use brokk_bifrost_go_analysis::analyzer::go::{
            GoAnalyzer, persist_live_go_sources_for_test,
        };
        use brokk_bifrost_test_macros::hardwon;

        fn fixture(alias: &str, package: Option<&str>) -> (BuiltInlineTestProject, GoAnalyzer) {
            unsafe { std::env::set_var("BIFROST_TRIAL_NATIVE_GO_HIERARCHY", "1") };
            let source = format!(
                "package app\n{alias}\n\
                 type Runner interface {{ Run() error }}\n\
                 type Worker struct{{}}\nfunc (Worker) Run() error {{ return nil }}\n"
            );
            let mut builder = InlineTestProject::with_language(Language::Go)
                .file("go.mod", "module example.test/alias\n\ngo 1.22\n")
                .file("dep/types.go", "package dep\ntype Present struct{}\n")
                .file("app.go", &source);
            if let Some(package) = package {
                builder = builder.file("pkg/types.go", package);
            }
            let project = builder.build();
            let go = GoAnalyzer::new(project.project_dyn());
            persist_live_go_sources_for_test(&go);
            (project, go)
        }

        fn unit(
            project: &BuiltInlineTestProject,
            go: &GoAnalyzer,
            owner: &str,
            name: &str,
        ) -> CodeUnit {
            go.declarations(&project.file("app.go"))
                .into_iter()
                .find(|unit| unit.identifier() == name && unit.owner_identifier() == Some(owner))
                .unwrap_or_else(|| panic!("missing {owner}.{name}"))
        }

        fn runner(project: &BuiltInlineTestProject, go: &GoAnalyzer) -> CodeUnit {
            go.declarations(&project.file("app.go"))
                .into_iter()
                .find(|unit| unit.identifier() == "Runner")
                .expect("Runner")
        }

        fn direct(go: &GoAnalyzer, root: &CodeUnit) -> HierarchyAnswer {
            let mut answer = None;
            go.with_hierarchy_query(&mut |query| answer = Some(query.direct_ancestors(root)));
            answer.expect("hierarchy query ran")
        }

        #[test]
        fn go_missing_named_alias_opens_direct_forward() {
            let (project, go) = fixture(
                "import \"example.test/alias/dep\"\ntype Alias = dep.Missing",
                None,
            );
            let _scope = AnalyzerQueryScope::new(&go);
            let root = runner(&project, &go);
            let answer = direct(&go, &root);
            assert!(!answer.open.is_empty(), "{answer:?}");
        }

        #[test]
        #[hardwon(
            "#7509: trial differential found the landed family facade (6330e7644b) certified forward absence despite an unresolved selected alias"
        )]
        fn go_missing_named_alias_opens_only_family_forward() {
            let (project, go) = fixture(
                "import \"example.test/alias/dep\"\ntype Alias = dep.Missing",
                None,
            );
            let _scope = AnalyzerQueryScope::new(&go);
            let method = unit(&project, &go, "Runner", "Run");
            let answer = go.member_family(&method, None);
            assert_eq!(
                answer.ancestors.outcome,
                MemberFamilyOutcome::Incomplete,
                "{answer:?}"
            );
            assert_eq!(
                answer.descendants.outcome,
                MemberFamilyOutcome::Proven,
                "{answer:?}"
            );
            assert!(
                answer
                    .edges
                    .iter()
                    .any(|edge| edge.relation == MethodFamilyRelation::ImplementedBy
                        && edge.target.owner_identifier() == Some("Worker")),
                "{answer:?}"
            );
            assert!(member_family_id(&go, &answer).is_none(), "{answer:?}");
        }

        #[test]
        fn go_resolved_named_interface_alias_keeps_forward_closed() {
            let (project, go) = fixture(
                "import pkg \"example.test/alias/pkg\"\ntype A = pkg.Iface",
                Some("package pkg\ntype Iface interface { Run() error }"),
            );
            let _scope = AnalyzerQueryScope::new(&go);
            let direct = direct(&go, &runner(&project, &go));
            assert!(direct.open.is_empty(), "{direct:?}");
            let family = go.member_family(&unit(&project, &go, "Runner", "Run"), None);
            assert_eq!(
                family.ancestors.outcome,
                MemberFamilyOutcome::Proven,
                "{family:?}"
            );
            assert_eq!(
                family.descendants.outcome,
                MemberFamilyOutcome::Proven,
                "{family:?}"
            );
            drop(_scope);
            let (plain_project, plain_go) = fixture(
                "import pkg \"example.test/alias/pkg\"",
                Some("package pkg\ntype Iface interface { Run() error }"),
            );
            let _plain_scope = AnalyzerQueryScope::new(&plain_go);
            let plain =
                plain_go.member_family(&unit(&plain_project, &plain_go, "Runner", "Run"), None);
            let shape = |answer: &brokk_bifrost_analysis::analyzer::usages::member_family::MemberFamilyAnswer| {
                let mut edges = answer.edges.iter().map(|edge| {
                    (edge.target.owner_identifier().unwrap_or("").to_owned(),
                     edge.target.identifier().to_owned(),
                     format!("{:?}", edge.relation))
                }).collect::<Vec<_>>();
                edges.sort();
                let mut roots = answer.roots.iter().map(|root| root.identifier().to_owned()).collect::<Vec<_>>();
                roots.sort();
                (answer.outcome, answer.reason, answer.ancestors.outcome,
                 answer.descendants.outcome, edges, roots)
            };
            assert_eq!(
                shape(&family),
                shape(&plain),
                "alias: {family:?}; plain: {plain:?}"
            );
        }

        #[test]
        fn go_named_alias_chain_requires_terminal() {
            for (tail, open) in [("dep.Missing", true), ("Runner", false)] {
                let import = if open {
                    "import \"example.test/alias/dep\"\n"
                } else {
                    ""
                };
                let alias = format!("{import}type A = B\ntype B = {tail}");
                let (project, go) = fixture(&alias, None);
                let _scope = AnalyzerQueryScope::new(&go);
                let answer = direct(&go, &runner(&project, &go));
                assert_eq!(!answer.open.is_empty(), open, "{tail}: {answer:?}");
            }
        }

        #[test]
        fn go_builtin_named_alias_terminal_is_open_without_selected_declaration() {
            let (project, go) = fixture("type E = error\ntype Any = any", None);
            let _scope = AnalyzerQueryScope::new(&go);
            let answer = direct(&go, &runner(&project, &go));
            assert!(!answer.open.is_empty(), "{answer:?}");
        }
    }

    mod go_forward_scan_receipt_controls {
        use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
        use brokk_bifrost_analysis::CodeUnitIndex;
        use brokk_bifrost_analysis::analyzer::{AnalyzerQueryScope, capture_query_reads};
        use brokk_bifrost_core::analyzer::capabilities::{
            HierarchyAnswer, HierarchyOpenReason, TypeHierarchyProvider,
        };
        use brokk_bifrost_core::analyzer::model::{CodeUnit, Language};
        use brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyReason;
        use brokk_bifrost_go_analysis::analyzer::go::{
            GoAnalyzer, persist_live_go_sources_for_test, stop_next_go_forward_scan_for_test,
            take_go_forward_scan_probe_for_test,
        };

        fn fixture() -> (BuiltInlineTestProject, GoAnalyzer) {
            let project = InlineTestProject::with_language(Language::Go)
                .file("go.mod", "module example.test/receipt\n\ngo 1.22\n")
                .file(
                    "types.go",
                    "package receipt\ntype A struct{}\ntype B struct{}\ntype Empty interface{}\n",
                )
                .build();
            let go = GoAnalyzer::new(project.project_dyn());
            persist_live_go_sources_for_test(&go);
            (project, go)
        }

        fn roots(project: &BuiltInlineTestProject, go: &GoAnalyzer) -> [CodeUnit; 2] {
            let declarations = go.declarations(&project.file("types.go"));
            let find = |name: &str| {
                declarations
                    .iter()
                    .find(|unit| unit.identifier() == name)
                    .unwrap_or_else(|| panic!("missing {name} in {declarations:?}"))
                    .clone()
            };
            [find("A"), find("B")]
        }

        fn render(answer: &HierarchyAnswer) -> String {
            format!("{answer:?}")
        }

        #[test]
        fn go_forward_scan_replays_one_context_receipt_across_roots() {
            unsafe { std::env::set_var("BIFROST_TRIAL_NATIVE_GO_HIERARCHY", "1") };
            let (project, go) = fixture();
            let [a, b] = roots(&project, &go);
            let _scope = AnalyzerQueryScope::new(&go);
            take_go_forward_scan_probe_for_test();
            let mut warm = Vec::new();
            go.with_hierarchy_query(&mut |query| {
                let (first, first_reads) = capture_query_reads(&go, || query.direct_ancestors(&a));
                let (second, second_reads) =
                    capture_query_reads(&go, || query.direct_ancestors(&b));
                assert!(
                    first_reads.unattributed_reads() > 0,
                    "first root must capture census dependencies"
                );
                assert!(
                    second_reads.unattributed_reads() > 0,
                    "second root must replay the census receipt"
                );
                warm.extend([render(&first), render(&second)]);
            });
            assert_eq!(
                take_go_forward_scan_probe_for_test(),
                (1, 1),
                "two roots in one walk must share a completed scan"
            );
            let mut cold = Vec::new();
            for root in [&a, &b] {
                go.with_hierarchy_query(&mut |query| {
                    cold.push(render(&query.direct_ancestors(root)))
                });
            }
            assert_eq!(
                take_go_forward_scan_probe_for_test(),
                (2, 2),
                "separate walks each need a cold scan"
            );
            assert_eq!(warm, cold);
        }

        #[test]
        fn go_forward_scan_stop_never_caches_a_complete_negative() {
            unsafe { std::env::set_var("BIFROST_TRIAL_NATIVE_GO_HIERARCHY", "1") };
            let (project, go) = fixture();
            let [a, b] = roots(&project, &go);
            let _scope = AnalyzerQueryScope::new(&go);
            take_go_forward_scan_probe_for_test();
            stop_next_go_forward_scan_for_test();
            go.with_hierarchy_query(&mut |query| {
                for root in [&a, &b] {
                    let answer = query.direct_ancestors(root);
                    assert!(
                        answer.open.iter().any(|reason| matches!(
                            reason,
                            HierarchyOpenReason::MemberFamily(
                                MemberFamilyReason::HierarchyTruncated
                            )
                        )),
                        "stopped walk root {root:?} returned {answer:?}"
                    );
                }
            });
            let (scans, inserts) = take_go_forward_scan_probe_for_test();
            assert_eq!(
                scans, 1,
                "first root reaches the stopped scan; later root may stop earlier"
            );
            assert_eq!(
                inserts, 0,
                "stopped scan must not fill a complete negative cache"
            );
        }
    }

    mod go_forward_proof_stop_controls {
        use crate::inline_project::InlineTestProject;
        use brokk_bifrost_analysis::CodeUnitIndex;
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::go_hierarchy::GoForwardProofStopProbe;
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::go_hierarchy::GoHierarchyPreparationStopProbe;
        use brokk_bifrost_analysis::analyzer::{AnalyzerQueryScope, capture_query_reads};
        use brokk_bifrost_core::analyzer::capabilities::{
            HierarchyOpenReason, TypeHierarchyProvider,
        };
        use brokk_bifrost_core::analyzer::model::Language;
        use brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyReason;
        use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverBudgetLimit;
        use brokk_bifrost_go_analysis::analyzer::go::{
            GoAnalyzer, persist_live_go_sources_for_test,
        };

        #[test]
        fn go_hierarchy_reused_preparation_observes_latched_stop() {
            unsafe { std::env::set_var("BIFROST_TRIAL_NATIVE_GO_HIERARCHY", "1") };
            let project = InlineTestProject::with_language(Language::Go)
                .file("go.mod", "module example.test/prepstop\n\ngo 1.22\n")
                .file("types.go", "package prepstop\ntype A struct{}\nfunc (A) M(){}\ntype B struct{}\nfunc (B) M(){}\ntype I interface{M()}\n")
                .build();
            let go = GoAnalyzer::new(project.project_dyn());
            persist_live_go_sources_for_test(&go);
            let declarations = go.declarations(&project.file("types.go"));
            let root = |name: &str| {
                declarations
                    .iter()
                    .find(|unit| unit.identifier() == name)
                    .unwrap()
                    .clone()
            };
            let a = root("A");
            let b = root("B");
            let _scope = AnalyzerQueryScope::new(&go);
            let mut probe = None;
            let (answer, reads) = capture_query_reads(&go, || {
                let mut result = None;
                go.with_hierarchy_query(&mut |query| {
                    let first = query.direct_ancestors(&a);
                    assert!(first.open.is_empty(), "{first:?}");
                    probe = Some(GoHierarchyPreparationStopProbe::arm());
                    result = Some(query.direct_ancestors(&b));
                });
                result.unwrap()
            });
            let probe = probe.unwrap();
            assert_eq!(probe.fired_limit(), Some(ReceiverBudgetLimit::ScopeNodes));
            assert!(reads.execution_dependences() > 0, "stop must enter receipt");
            assert!(
                answer.open.iter().any(|reason| matches!(
                    reason,
                    HierarchyOpenReason::MemberFamily(MemberFamilyReason::HierarchyTruncated)
                )),
                "{answer:?}"
            );
        }

        #[test]
        fn go_forward_proof_budget_stop_is_execution_incomplete() {
            unsafe { std::env::set_var("BIFROST_TRIAL_NATIVE_GO_HIERARCHY", "1") };
            let project = InlineTestProject::with_language(Language::Go)
                .file("go.mod", "module example.test/forwardproof\n\ngo 1.22\n")
                .file(
                    "types.go",
                    "package forwardproof\ntype A struct{}\ntype Empty interface{}\n",
                )
                .build();
            let go = GoAnalyzer::new(project.project_dyn());
            persist_live_go_sources_for_test(&go);
            let root = go
                .declarations(&project.file("types.go"))
                .into_iter()
                .find(|unit| unit.identifier() == "A")
                .expect("A declaration");
            let _scope = AnalyzerQueryScope::new(&go);
            let probe = GoForwardProofStopProbe::arm();
            let (answer, reads) = capture_query_reads(&go, || {
                let mut result = None;
                go.with_hierarchy_query(&mut |query| {
                    result = Some(query.direct_ancestors(&root));
                });
                result.expect("public hierarchy walk ran")
            });
            assert_eq!(probe.fired_limit(), Some(ReceiverBudgetLimit::ScopeNodes));
            assert!(
                reads.unattributed_reads() > 0,
                "the public walk must retain captured census reads"
            );
            assert!(
                answer.open.iter().any(|reason| matches!(
                    reason,
                    HierarchyOpenReason::MemberFamily(MemberFamilyReason::HierarchyTruncated)
                )),
                "forward proof stop must report truncation: {answer:?}"
            );
            assert!(
                !answer.open.iter().any(|reason| matches!(
                    reason,
                    HierarchyOpenReason::ForwardSatisfactionIncomplete
                )),
                "a stopped proof must not become content-only incompleteness: {answer:?}"
            );
            assert!(
                reads.execution_dependences() > 0,
                "typed read capture must retain the budget stop"
            );
        }

        #[test]
        fn go_unstopped_forward_gap_stays_content_incomplete() {
            unsafe { std::env::set_var("BIFROST_TRIAL_NATIVE_GO_HIERARCHY", "1") };
            let project = InlineTestProject::with_language(Language::Go)
                .file("go.mod", "module example.test/forwardgap\n\ngo 1.22\n")
                .file("types.go", "package forwardgap\ntype T struct{}\nfunc (T) M(){}\ntype U interface{ M(); missing.X }\n")
                .build();
            let go = GoAnalyzer::new(project.project_dyn());
            persist_live_go_sources_for_test(&go);
            let root = go
                .declarations(&project.file("types.go"))
                .into_iter()
                .find(|unit| unit.identifier() == "T")
                .expect("T declaration");
            let _scope = AnalyzerQueryScope::new(&go);
            let (answer, reads) = capture_query_reads(&go, || {
                let mut result = None;
                go.with_hierarchy_query(&mut |query| result = Some(query.direct_ancestors(&root)));
                result.expect("public hierarchy walk ran")
            });
            assert!(
                answer.open.iter().any(|reason| matches!(
                    reason,
                    HierarchyOpenReason::ForwardSatisfactionIncomplete
                )),
                "unstopped unresolved interface coverage must stay Open: {answer:?}"
            );
            assert!(
                !answer.open.iter().any(|reason| matches!(
                    reason,
                    HierarchyOpenReason::MemberFamily(MemberFamilyReason::HierarchyTruncated)
                )),
                "unstopped content gap must not become truncation: {answer:?}"
            );
            assert!(
                reads.unattributed_reads() > 0,
                "public capture must retain census dependencies"
            );
        }
    }

    mod go_native_family_positive_controls {
        use crate::inline_project::InlineTestProject;
        use brokk_bifrost_analysis::CodeUnitIndex;
        use brokk_bifrost_analysis::TypeHierarchyProvider;
        use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::{
            ImplementorTargets, virtual_dispatch_implementor_targets,
        };
        use brokk_bifrost_analysis::analyzer::usages::member_family::MemberFamilyAnswer;
        use brokk_bifrost_analysis::analyzer::usages::member_family::{
            MemberFamilyProvider, member_family_id,
        };
        use brokk_bifrost_analysis::analyzer::{
            AnalyzerQueryScope, IAnalyzer, capture_query_reads,
        };
        use brokk_bifrost_analysis::analyzer::{DeclarationInfo, Project, ProjectFile, Range};
        use brokk_bifrost_core::analyzer::model::{CodeUnit, CodeUnitType, Language};
        use brokk_bifrost_core::analyzer::structural::resolution::{
            MemberFamilyCapability, MemberFamilyOutcome, MemberFamilyReason, MethodFamilyRelation,
        };
        use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverBudgetLimit;
        use brokk_bifrost_core::cancellation::CancellationToken;
        use brokk_bifrost_go_analysis::analyzer::go::{
            GoAnalyzer, GoFamilyPositiveStopProbe, assemble_go_member_family_for_test,
            persist_live_go_sources_for_test,
        };
        use std::collections::BTreeSet;

        struct FamilyDispatchBoundary {
            go: GoAnalyzer,
            answer: MemberFamilyAnswer,
        }
        impl CodeUnitIndex for FamilyDispatchBoundary {
            fn project(&self) -> &dyn Project {
                self.go.project()
            }
            fn languages(&self) -> BTreeSet<Language> {
                BTreeSet::from([Language::Go])
            }
            fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
                Box::new(std::iter::empty())
            }
            fn ranges(&self, _: &CodeUnit) -> Vec<Range> {
                unimplemented!()
            }
            fn search_definitions(&self, _: &str, _: bool) -> BTreeSet<CodeUnit> {
                unimplemented!()
            }
            fn enclosing_code_unit(&self, _: &ProjectFile, _: &Range) -> Option<CodeUnit> {
                unimplemented!()
            }
            fn enclosing_code_unit_for_lines(
                &self,
                _: &ProjectFile,
                _: usize,
                _: usize,
            ) -> Option<CodeUnit> {
                unimplemented!()
            }
            fn get_skeleton(&self, _: &CodeUnit) -> Option<String> {
                unimplemented!()
            }
            fn get_skeleton_header(&self, _: &CodeUnit) -> Option<String> {
                unimplemented!()
            }
            fn get_sources(&self, _: &CodeUnit, _: bool) -> BTreeSet<String> {
                unimplemented!()
            }
        }
        impl MemberFamilyProvider for FamilyDispatchBoundary {
            fn member_family_capability(&self, _: &CodeUnit) -> MemberFamilyCapability {
                MemberFamilyCapability::ParameterTypeSpellings
            }
            fn member_family(
                &self,
                _: &CodeUnit,
                _: Option<&CancellationToken>,
            ) -> MemberFamilyAnswer {
                self.answer.clone()
            }
        }
        impl IAnalyzer for FamilyDispatchBoundary {
            fn update(&self, _: &BTreeSet<ProjectFile>) -> Self {
                unimplemented!()
            }
            fn update_with_listing(
                &self,
                _: &BTreeSet<ProjectFile>,
                _listing: Option<
                    &brokk_bifrost_core::analyzer::project::SharedWorkspaceFileListing,
                >,
            ) -> Self {
                unimplemented!()
            }
            fn update_all(&self) -> Self {
                unimplemented!()
            }
            fn is_access_expression(&self, _: &ProjectFile, _: usize, _: usize) -> bool {
                unimplemented!()
            }
            fn find_nearest_declaration(
                &self,
                _: &ProjectFile,
                _: usize,
                _: usize,
                _: &str,
            ) -> Option<DeclarationInfo> {
                unimplemented!()
            }
            fn member_family_provider(&self) -> Option<&dyn MemberFamilyProvider> {
                Some(self)
            }
        }

        fn fixture() -> (crate::inline_project::BuiltInlineTestProject, GoAnalyzer) {
            let project = InlineTestProject::with_language(Language::Go)
                .file("go.mod", "module example.test/familypositive\n\ngo 1.22\n")
                .file("types.go", "package familypositive\ntype I interface{ M() }\ntype Holder struct{ F interface{ M() } }\ntype A struct{}\nfunc (A) M(){}\ntype B struct{}\nfunc (B) M(){}\n")
                .build();
            let go = GoAnalyzer::new(project.project_dyn());
            persist_live_go_sources_for_test(&go);
            (project, go)
        }

        fn member(
            go: &GoAnalyzer,
            project: &crate::inline_project::BuiltInlineTestProject,
            owner: &str,
        ) -> CodeUnit {
            go.declarations(&project.file("types.go"))
                .into_iter()
                .find(|unit| {
                    unit.is_function()
                        && unit.identifier() == "M"
                        && unit.owner_identifier() == Some(owner)
                })
                .unwrap_or_else(|| panic!("missing {owner}.M"))
        }

        #[test]
        fn go_family_adapter_to_dispatch_boundary_keeps_inverse_positive() {
            let (project, go) = fixture();
            // This boundary control uses a language without Go's same-module
            // dispatch hook, which downcasts the analyzer to GoAnalyzer.
            let source = ProjectFile::new(project.file("types.go").root(), "types.java");
            let interface = CodeUnit::new(source.clone(), CodeUnitType::Function, "example", "I.M");
            let target = CodeUnit::new(source.clone(), CodeUnitType::Function, "example", "A.M");
            let owner = CodeUnit::new(source, CodeUnitType::Class, "example", "A");
            // Explicit certified hydration at the adapter assembly boundary.
            let answer = assemble_go_member_family_for_test(
                MemberFamilyCapability::ParameterTypeSpellings,
                &interface,
                Vec::new(),
                Some(MemberFamilyReason::CoverageIncomplete),
                vec![(target.clone(), owner)],
                None,
            );
            assert_eq!(answer.outcome, MemberFamilyOutcome::Incomplete);
            assert_eq!(answer.descendants.outcome, MemberFamilyOutcome::Proven);
            assert!(member_family_id(&go, &answer).is_none());
            let boundary = FamilyDispatchBoundary { go, answer };
            let dispatch = virtual_dispatch_implementor_targets(
                &boundary,
                &interface,
                &CancellationToken::new(),
            );
            assert!(
                matches!(dispatch, ImplementorTargets::Proven(ref targets) if targets == &vec![target]),
                "{dispatch:?}"
            );
        }

        #[test]
        fn go_family_inverse_open_keeps_public_dispatch_established_targets() {
            unsafe { std::env::set_var("BIFROST_TRIAL_NATIVE_GO_HIERARCHY", "1") };
            let (project, go) = fixture();
            let interface = member(&go, &project, "I");
            let _scope = AnalyzerQueryScope::new(&go);
            let family = go.member_family(&interface, None);
            assert_eq!(
                family.descendants.outcome,
                MemberFamilyOutcome::Incomplete,
                "{family:?}"
            );
            assert!(
                family
                    .edges
                    .iter()
                    .any(|edge| edge.relation == MethodFamilyRelation::ImplementedBy)
            );
            assert!(member_family_id(&go, &family).is_none());
            let dispatch =
                virtual_dispatch_implementor_targets(&go, &interface, &CancellationToken::new());
            assert!(
                matches!(dispatch, ImplementorTargets::Unproven { ref established, .. } if !established.is_empty()),
                "{dispatch:?}"
            );
        }

        #[test]
        fn go_family_complete_empty_inverse_proves_absence() {
            unsafe { std::env::set_var("BIFROST_TRIAL_NATIVE_GO_HIERARCHY", "1") };
            let project = InlineTestProject::with_language(Language::Go)
                .file("go.mod", "module example.test/familyempty\n\ngo 1.22\n")
                .file(
                    "types.go",
                    "package familyempty\ntype I interface { Z() }\n",
                )
                .build();
            let go = GoAnalyzer::new(project.project_dyn());
            persist_live_go_sources_for_test(&go);
            let interface = go
                .declarations(&project.file("types.go"))
                .into_iter()
                .find(|unit| unit.is_function() && unit.identifier() == "Z")
                .expect("I.Z");
            let _scope = AnalyzerQueryScope::new(&go);
            let family = go.member_family(&interface, None);
            assert_eq!(
                family.descendants.outcome,
                MemberFamilyOutcome::Proven,
                "{family:?}"
            );
            assert!(
                !family
                    .edges
                    .iter()
                    .any(|edge| edge.relation == MethodFamilyRelation::ImplementedBy)
            );
            let dispatch =
                virtual_dispatch_implementor_targets(&go, &interface, &CancellationToken::new());
            assert!(
                matches!(dispatch, ImplementorTargets::Proven(ref targets) if targets.is_empty()),
                "{dispatch:?}"
            );
        }

        #[test]
        fn go_family_stop_after_inverse_positive_retains_edge_and_first_cause() {
            unsafe { std::env::set_var("BIFROST_TRIAL_NATIVE_GO_HIERARCHY", "1") };
            let (project, go) = fixture();
            let interface = member(&go, &project, "I");
            let _scope = AnalyzerQueryScope::new(&go);
            let probe = GoFamilyPositiveStopProbe::arm_inverse();
            let (family, reads) = capture_query_reads(&go, || go.member_family(&interface, None));
            assert_eq!(probe.fired_limit(), Some(ReceiverBudgetLimit::ScopeNodes));
            assert!(
                reads.execution_dependences() > 0,
                "stop must enter typed receipt"
            );
            assert_eq!(family.reason, Some(MemberFamilyReason::HierarchyTruncated));
            assert_eq!(family.descendants.outcome, MemberFamilyOutcome::Incomplete);
            assert!(
                family
                    .edges
                    .iter()
                    .any(|edge| edge.relation == MethodFamilyRelation::ImplementedBy)
            );
            assert!(member_family_id(&go, &family).is_none());
            drop(probe);
            let second_probe = GoFamilyPositiveStopProbe::arm_inverse();
            let dispatch =
                virtual_dispatch_implementor_targets(&go, &interface, &CancellationToken::new());
            assert_eq!(
                second_probe.fired_limit(),
                Some(ReceiverBudgetLimit::ScopeNodes)
            );
            assert!(
                matches!(dispatch, ImplementorTargets::Unproven { .. }),
                "{dispatch:?}"
            );
        }

        #[test]
        fn go_inline_field_methods_remain_open_while_top_level_function_has_no_family() {
            unsafe { std::env::set_var("BIFROST_TRIAL_NATIVE_GO_HIERARCHY", "1") };
            let project = InlineTestProject::with_language(Language::Go)
                .file("go.mod", "module example.com/app\n\ngo 1.24\n")
                .file(
                    "service.go",
                    "package app\ntype Outer struct { A, B interface { Run() error } }\ntype Worker struct{}\nfunc (Worker) Run() error { return nil }\nfunc Top() {}\n",
                )
                .build();
            let go = GoAnalyzer::new(project.project_dyn());
            persist_live_go_sources_for_test(&go);
            let declarations = go.declarations(&project.file("service.go"));
            let find = |owner: Option<&str>, name: &str| {
                declarations
                    .iter()
                    .find(|unit| {
                        unit.is_function()
                            && unit.identifier() == name
                            && unit.owner_identifier() == owner
                    })
                    .unwrap_or_else(|| panic!("missing {owner:?}.{name}"))
            };
            let _scope = AnalyzerQueryScope::new(&go);
            for field in ["A", "B"] {
                let family = go.member_family(find(Some(field), "Run"), None);
                assert_eq!(
                    family.outcome,
                    MemberFamilyOutcome::Incomplete,
                    "{family:?}"
                );
                // The current file-wide crosswalk refusal reports ProviderUnavailable.
                assert_eq!(family.reason, Some(MemberFamilyReason::ProviderUnavailable));
                assert!(family.edges.is_empty());
                assert_eq!(family.descendants.outcome, MemberFamilyOutcome::Incomplete);
                assert!(member_family_id(&go, &family).is_none());
            }
            let top_unit = declarations
                .iter()
                .find(|unit| {
                    unit.is_function()
                        && unit.identifier() == "Top"
                        && unit.declaration_segment_count() == 1
                })
                .expect("top-level Top");
            let top = go.member_family(top_unit, None);
            assert_eq!(top.outcome, MemberFamilyOutcome::NoFamily);
            assert_eq!(top.reason, Some(MemberFamilyReason::NotAMethod));
        }

        #[test]
        fn go_multi_unit_struct_neighbor_does_not_poison_worker_family() {
            unsafe { std::env::set_var("BIFROST_TRIAL_NATIVE_GO_HIERARCHY", "1") };
            let project = InlineTestProject::with_language(Language::Go)
                .file("go.mod", "module example.com/app\n\ngo 1.24\n")
                .file("service.go", "package app\ntype Outer struct { A, B struct { X int } }\ntype Worker struct{}\nfunc (Worker) Run() error { return nil }\n")
                .build();
            let go = GoAnalyzer::new(project.project_dyn());
            persist_live_go_sources_for_test(&go);
            let declarations = go.declarations(&project.file("service.go"));
            let worker = declarations
                .iter()
                .find(|unit| unit.is_function() && unit.short_name() == "Worker.Run")
                .expect("Worker.Run");
            let _scope = AnalyzerQueryScope::new(&go);
            let family = go.member_family(worker, None);
            assert_eq!(family.outcome, MemberFamilyOutcome::Proven, "{family:?}");
            assert!(family.edges.is_empty(), "{family:?}");
            let mut hierarchy = None;
            go.with_hierarchy_query(&mut |query| hierarchy = Some(query.direct_ancestors(worker)));
            let hierarchy = hierarchy.expect("direct hierarchy query");
            assert!(
                !hierarchy.open.iter().any(|reason| matches!(
                    reason,
                    brokk_bifrost_core::analyzer::capabilities::HierarchyOpenReason::MemberFamily(
                        MemberFamilyReason::ProviderUnavailable
                    )
                )),
                "{hierarchy:?}"
            );
        }

        #[test]
        fn go_inline_interface_neighbor_must_not_poison_worker() {
            unsafe { std::env::set_var("BIFROST_TRIAL_NATIVE_GO_HIERARCHY", "1") };
            let project = InlineTestProject::with_language(Language::Go)
                .file("go.mod", "module example.com/app\n\ngo 1.24\n")
                .file("service.go", "package app\ntype Outer struct { A, B interface { Run() error } }\ntype Worker struct{}\nfunc (Worker) Run() error { return nil }\n")
                .build();
            let go = GoAnalyzer::new(project.project_dyn());
            persist_live_go_sources_for_test(&go);
            let worker = go
                .declarations(&project.file("service.go"))
                .into_iter()
                .find(|unit| unit.short_name() == "Worker.Run")
                .expect("Worker.Run");
            let _scope = AnalyzerQueryScope::new(&go);
            let family = go.member_family(&worker, None);
            assert_eq!(family.outcome, MemberFamilyOutcome::Proven, "{family:?}");
        }

        #[test]
        fn go_empty_interface_neighbor_must_not_poison_worker() {
            unsafe { std::env::set_var("BIFROST_TRIAL_NATIVE_GO_HIERARCHY", "1") };
            let project = InlineTestProject::with_language(Language::Go)
                .file("go.mod", "module example.com/app\n\ngo 1.24\n")
                .file("service.go", "package app\nvar Empty interface{}\ntype Worker struct{}\nfunc (Worker) Run() error { return nil }\n")
                .build();
            let go = GoAnalyzer::new(project.project_dyn());
            persist_live_go_sources_for_test(&go);
            let worker = go
                .declarations(&project.file("service.go"))
                .into_iter()
                .find(|unit| unit.short_name() == "Worker.Run")
                .expect("Worker.Run");
            let _scope = AnalyzerQueryScope::new(&go);
            let family = go.member_family(&worker, None);
            assert_eq!(family.outcome, MemberFamilyOutcome::Proven, "{family:?}");
        }
    }
}
