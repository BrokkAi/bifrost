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
            assert!(
            std::panic::catch_unwind(|| {
                let _ = brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_lexical_for_test(
                    fragment(),
                    Language::Java,
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

        use brokk_bifrost_core::cancellation::CancellationToken;

        use brokk_bifrost_test_macros::hardwon;

        use brokk_bifrost_analysis :: analyzer :: store :: resolution_operation :: native_query_plan_go_support :: go_global_support_4 :: registry ;

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

        use brokk_bifrost_analysis :: analyzer :: store :: resolution_operation :: resolution_operation_tests_go_support :: go_extraction_support_11 :: site_for_identifier ;

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
                .selected_package_members_by_lookup(mount.ordinal(), &cancellation)
                .unwrap()
            else {
                panic!("not cancelled");
            };
            let actual = grouped.values().flatten().copied().collect::<BTreeSet<_>>();
            let mut oracle = BTreeSet::new();
            for lookup in lookups {
                let SelectedPackageRows::Ready(members) = operation
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
}
