#[cfg(test)]
mod go_extraction_tests_more {
    mod go_move_0 {

        use brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweringCoverageFrontier;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweringGapOrigin;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapFact;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeSlotId;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeSlotRole;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeTransferFact;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeTransferKind;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeTransferValueTransform;

        use brokk_bifrost_analysis::analyzer::resolution::local_writes::go_extraction_support_0::fixture;

        use brokk_bifrost_analysis::analyzer::resolution::local_writes::go_extraction_support_0::normalize;

        use brokk_bifrost_analysis::analyzer::resolution::test_support::fragment;

        use brokk_bifrost_core::analyzer::Language;
        use brokk_bifrost_core::analyzer::resolution_facts::{
            IntrinsicTypeKind, IntrinsicTypeSeedFact, ResolutionNameId, ResolutionScopeId,
        };

        use brokk_bifrost_test_macros::hardwon;
        fn joined_inputs(facts: &FileResolutionFacts, declaration: u32) -> Vec<u32> {
            let observed = facts
                .type_slots
                .iter()
                .find(|slot| {
                    slot.site == ResolutionSiteId::new(declaration)
                        && slot.role == ResolutionTypeSlotRole::AssignmentValue
                })
                .expect("observed slot")
                .id;
            let assignment = facts
                .type_transfers
                .iter()
                .find(|transfer| transfer.output == observed)
                .expect("single assignment");
            assert_eq!(assignment.kind, ResolutionTypeTransferKind::Assignment);
            let mut inputs = facts
                .type_transfers
                .iter()
                .filter(|transfer| transfer.output == assignment.input)
                .map(|transfer| {
                    assert_eq!(transfer.kind, ResolutionTypeTransferKind::ValueJoin);
                    transfer.input.get()
                })
                .collect::<Vec<_>>();
            inputs.sort_unstable();
            inputs
        }
        #[test]
        #[hardwon(
            "#5015: lexical writes lost their alternatives or violated the single assignment producer"
        )]
        fn local_write_publication_uses_native_shadow_order_and_keeps_rhs_gaps() {
            let facts = fixture();
            let normalized = normalize(&facts);
            assert_eq!(joined_inputs(&normalized, 0), vec![4, 6, 8]);
            assert_eq!(joined_inputs(&normalized, 1), vec![5, 7]);
            for initialization in normalized
                .type_transfers
                .iter()
                .filter(|transfer| transfer.kind == ResolutionTypeTransferKind::Initialization)
            {
                assert!(
                    normalized
                        .type_transfers
                        .iter()
                        .any(
                            |transfer| transfer.kind == ResolutionTypeTransferKind::Assignment
                                && transfer.input == initialization.input
                        )
                );
            }
            let published =
                brokk_bifrost_analysis::analyzer::resolution::lower_resolution_facts_with_identity_catalog(
                    fragment("local-writes"),
                    Language::Go,
                    &facts,
                );
            assert_eq!(
                published
                    .typed()
                    .transfers()
                    .iter()
                    .filter(|transfer| transfer.kind() == ResolutionTypeTransferKind::Assignment)
                    .count(),
                2
            );
            assert_eq!(
                published
                    .typed()
                    .transfers()
                    .iter()
                    .filter(|transfer| transfer.kind() == ResolutionTypeTransferKind::ValueJoin)
                    .count(),
                5
            );
            for site in [5, 10, 11] {
                assert!(published.lexical().gaps().iter().any(|gap| gap.site()
                    == ResolutionSiteId::new(site)
                    && gap.origin()
                        == LoweringGapOrigin::Extracted(
                            ResolutionGapKind::UnsupportedExpressionType
                        )));
            }
        }
        #[test]
        #[hardwon(
            "#5015: incomplete lexical writes must not become complete initializer-only bindings"
        )]
        fn incomplete_attachment_marks_the_known_binder_without_attaching_the_rhs() {
            let mut facts = fixture();
            facts.gaps.push(ResolutionGapFact::unsupported_route(
                ResolutionSiteId::new(2),
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionRouteGap::UnknownBinder {
                    scope: ResolutionScopeId::new(0),
                    name: None,
                    namespace: None,
                    may_publish: false,
                },
            ));
            let normalized = normalize(&facts);
            assert_eq!(joined_inputs(&normalized, 0), vec![4, 8]);
            assert!(normalized.gaps.contains(&ResolutionGapFact::new(
                ResolutionSiteId::new(0),
                ResolutionGapKind::UnsupportedExpressionType
            )));
            let published =
                brokk_bifrost_analysis::analyzer::resolution::lower_resolution_facts_with_identity_catalog(
                    fragment("incomplete-local-write"),
                    Language::Go,
                    &facts,
                );
            assert!(
                published
                    .lexical()
                    .gaps()
                    .iter()
                    .any(|gap| gap.site() == ResolutionSiteId::new(0)
                        && matches!(gap.frontier(), LoweringCoverageFrontier::Type { .. }))
            );
        }
        #[test]
        #[hardwon(
            "#5015: write joins must retain static types without inventing an uninitialized value"
        )]
        fn local_write_joins_keep_static_types_and_do_not_invent_initializers() {
            let mut facts = fixture();
            let identity = facts.allocate_type_slot(
                ResolutionSiteId::new(6),
                ResolutionTypeSlotRole::TargetTypeIdentity,
            );
            facts
                .intrinsic_type_seeds
                .push(IntrinsicTypeSeedFact::direct(
                    identity,
                    ResolutionNameId::new(2),
                    IntrinsicTypeKind::Primitive,
                ));
            let declared_type = ResolutionTypeTransferFact::new(
                identity,
                ResolutionTypeSlotId::new(0),
                ResolutionTypeTransferKind::DeclaredType,
                0,
                0,
                ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
            );
            facts.type_transfers[0] = declared_type;
            facts
                .type_transfers
                .retain(|transfer| !matches!(transfer.output.get(), 2 | 3));
            facts.type_slots.retain(|slot| slot.id.get() != 3);
            let normalized = normalize(&facts);
            assert!(normalized.type_transfers.contains(&declared_type));
            assert_eq!(joined_inputs(&normalized, 0), vec![4, 6, 8]);
            assert_eq!(joined_inputs(&normalized, 1), vec![7]);
            let initializations = normalized
                .type_transfers
                .iter()
                .filter(|transfer| transfer.kind == ResolutionTypeTransferKind::Initialization)
                .collect::<Vec<_>>();
            assert_eq!(initializations.len(), 1);
            let initialization = initializations[0];
            assert_eq!(initialization.output, ResolutionTypeSlotId::new(2));
            assert_eq!(
                initialization.value_transform,
                ResolutionTypeTransferValueTransform::Preserve
            );
            assert_eq!(
                normalized
                    .type_transfers
                    .iter()
                    .filter(|transfer| transfer.output == initialization.input)
                    .map(|transfer| (transfer.kind, transfer.input))
                    .collect::<Vec<_>>(),
                vec![(
                    ResolutionTypeTransferKind::ValueJoin,
                    ResolutionTypeSlotId::new(7)
                )],
                "the inferred value reads only the real write through the join"
            );
            let published =
                brokk_bifrost_analysis::analyzer::resolution::lower_resolution_facts_with_identity_catalog(
                    fragment("static-and-uninitialized-local-writes"),
                    Language::Go,
                    &facts,
                );
            assert_eq!(
                published
                    .typed()
                    .transfers()
                    .iter()
                    .filter(|transfer| transfer.kind() == ResolutionTypeTransferKind::Assignment)
                    .count(),
                2
            );
        }
    }
    mod go_move_1 {

        use brokk_bifrost_analysis::analyzer::resolution::model::BindingFragmentId;

        use brokk_bifrost_core::cancellation::CancellationToken;

        use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::FactReferenceEdgeCatalog;

        use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::FactReferenceEdgeSelectedFragment;

        use brokk_bifrost_analysis::analyzer::resolution::batch::MAX_REFERENCE_SEEDS_PER_BATCH;

        use crate::engine_tests::jvm_fact_reference_support::go_extraction_support_1::PROJECTOR_SOURCE;

        use brokk_bifrost_core::analyzer::model::ProjectFile;

        use crate::engine_tests::jvm_fact_reference_support::go_extraction_support_1::native_edge_catalog;

        use crate::engine_tests::jvm_fact_reference_support::go_extraction_support_1::native_edge_projection_fixture;

        use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::stage_selected_reference_edge_batches;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweredResolutionFragment;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweredSemanticRole;

        use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredTypedFragment;

        use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::PreloadedFactResolutionService;

        use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::SelectedFactResolutionEngine;

        use brokk_bifrost_go_analysis::GoAnalyzer;

        use crate::inline_project::InlineTestProject;

        use brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts;
        use brokk_bifrost_core::analyzer::{CodeUnitIndex, Language};

        use std::collections::BTreeSet;

        #[test]
        fn selected_fragment_catalog_is_atomic_for_mismatch_duplicate_and_cancellation() {
            let fixture = native_edge_projection_fixture();
            let stale_source = PROJECTOR_SOURCE.replacen("value", "other", 1);
            assert_eq!(
                stale_source.len(),
                PROJECTOR_SOURCE.len(),
                "the stale-source law must not rely on a length mismatch"
            );
            let stale = FactReferenceEdgeCatalog::from_selected_fragments(
                &fixture.analyzer,
                [FactReferenceEdgeSelectedFragment::new(
                    fixture.file.clone(),
                    &stale_source,
                    &fixture.facts,
                    &fixture.lexical,
                    &fixture.typed,
                    brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(
                    ),
                )],
                &CancellationToken::new(),
            );
            let error = match stale {
                Ok(_) => {
                    panic!("same-length stale source and current analyzer bytes must not join")
                }
                Err(error) => error,
            };
            assert!(
                error.to_string().contains("differs byte-for-byte"),
                "unexpected stale-source error: {error}"
            );

            let foreign_typed =
                brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
                    BindingFragmentId::for_test(b"foreign-selected-edge-typed-fragment"),
                    Language::Java,
                    &fixture.facts,
                )
                .typed()
                .clone();
            let mismatch = FactReferenceEdgeCatalog::from_selected_fragments(
                &fixture.analyzer,
                [FactReferenceEdgeSelectedFragment::new(
                    fixture.file.clone(),
                    PROJECTOR_SOURCE,
                    &fixture.facts,
                    &fixture.lexical,
                    &foreign_typed,
                    brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(
                    ),
                )],
                &CancellationToken::new(),
            );
            let error = match mismatch {
                Ok(_) => {
                    panic!("lexical and typed fragments with different identities must not join")
                }
                Err(error) => error,
            };
            assert!(
                error
                    .to_string()
                    .contains("lexical and typed fragments disagree"),
                "unexpected typed-fragment identity error: {error}"
            );

            let hostile_fragment = BindingFragmentId::for_test(b"hostile-edge-language-fragment");
            let empty_facts = FileResolutionFacts::default();
            let go_lexical =
                brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
                    hostile_fragment,
                    Language::Go,
                    &FileResolutionFacts::default(),
                )
                .lexical()
                .clone();
            let java_typed =
                brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
                    hostile_fragment,
                    Language::Java,
                    &FileResolutionFacts::default(),
                )
                .typed()
                .clone();
            let mismatch = FactReferenceEdgeCatalog::from_selected_fragments(
                &fixture.analyzer,
                [FactReferenceEdgeSelectedFragment::new(
                    fixture.file.clone(),
                    PROJECTOR_SOURCE,
                    &empty_facts,
                    &go_lexical,
                    &java_typed,
                    brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(
                    ),
                )],
                &CancellationToken::new(),
            );
            let error = match mismatch {
                Ok(_) => {
                    panic!("lexical and typed fragments with different languages must not join")
                }
                Err(error) => error,
            };
            assert!(
                error.to_string().contains("fragment languages disagree"),
                "unexpected typed-fragment language error: {error}"
            );

            let go_typed =
                brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
                    hostile_fragment,
                    Language::Go,
                    &FileResolutionFacts::default(),
                )
                .typed()
                .clone();
            let mismatch = FactReferenceEdgeCatalog::from_selected_fragments(
                &fixture.analyzer,
                [FactReferenceEdgeSelectedFragment::new(
                    fixture.file.clone(),
                    PROJECTOR_SOURCE,
                    &empty_facts,
                    &go_lexical,
                    &go_typed,
                    brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(
                    ),
                )],
                &CancellationToken::new(),
            );
            let error = match mismatch {
                Ok(_) => panic!("Go artifacts must not join a Java source file"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains(
                    "declaration language shared by the analyzer-owned file and artifacts"
                ),
                "unexpected artifact/file language error: {error}"
            );

            let hostile_file = ProjectFile::new(
                fixture.file.root().to_path_buf(),
                "src/main/go/demo/Projector.go",
            );
            let mismatch = FactReferenceEdgeCatalog::from_selected_fragments(
                &fixture.analyzer,
                [FactReferenceEdgeSelectedFragment::new(
                    hostile_file,
                    PROJECTOR_SOURCE,
                    &fixture.facts,
                    &fixture.lexical,
                    &fixture.typed,
                    brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(
                    ),
                )],
                &CancellationToken::new(),
            );
            let error = match mismatch {
                Ok(_) => panic!("Java artifacts must not join a Go source file"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains(
                    "declaration language shared by the analyzer-owned file and artifacts"
                ),
                "unexpected source/artifact language error: {error}"
            );

            let mismatch = FactReferenceEdgeCatalog::from_selected_fragments(
                &fixture.analyzer,
                [FactReferenceEdgeSelectedFragment::new(
                    fixture.file.clone(),
                    PROJECTOR_SOURCE,
                    &empty_facts,
                    &fixture.lexical,
                    &fixture.typed,
                    brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(
                    ),
                )],
                &CancellationToken::new(),
            );
            let error = match mismatch {
                Ok(_) => panic!("misaligned facts and lowering must fail atomically"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains("has no aligned fact semantic"),
                "unexpected selected-fragment mismatch error: {error}"
            );

            let duplicate = FactReferenceEdgeCatalog::from_selected_fragments(
                &fixture.analyzer,
                [
                    FactReferenceEdgeSelectedFragment::new(
                        fixture.file.clone(),
                        PROJECTOR_SOURCE,
                        &fixture.facts,
                        &fixture.lexical,
                        &fixture.typed,
                        brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
                    ),
                    FactReferenceEdgeSelectedFragment::new(
                        fixture.file.clone(),
                        PROJECTOR_SOURCE,
                        &fixture.facts,
                        &fixture.lexical,
                        &fixture.typed,
                        brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
                    ),
                ],
                &CancellationToken::new(),
            );
            let error = match duplicate {
                Ok(_) => panic!("duplicate selected fragments must fail atomically"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains("duplicate selected"),
                "unexpected duplicate selected-fragment error: {error}"
            );

            let cancellation = CancellationToken::new();
            cancellation.cancel();
            let cancelled = FactReferenceEdgeCatalog::from_selected_fragments(
                &fixture.analyzer,
                [FactReferenceEdgeSelectedFragment::new(
                    fixture.file.clone(),
                    PROJECTOR_SOURCE,
                    &fixture.facts,
                    &fixture.lexical,
                    &fixture.typed,
                    brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(
                    ),
                )],
                &cancellation,
            )
            .expect("cancellation is an explicit non-error outcome");
            assert!(cancelled.is_none(), "cancellation must publish no catalog");

            let retry = native_edge_catalog(&fixture);
            assert_eq!(
                retry.generation(),
                fixture.analyzer.project().analysis_generation()
            );
        }
        #[test]
        fn selected_go_type_references_stage_through_shared_edges_and_reject_file_mismatch() {
            const SOURCE: &str = "package demo\n\ntype Item struct{}\n\nfunc Echo(input *Item) *Item {\n    return input\n}\n";

            let project = InlineTestProject::with_language(Language::Go)
                .file("fixture.go", SOURCE)
                .build();
            let file = project.file("fixture.go");
            let analyzer = GoAnalyzer::new(project.project_dyn());
            let mut parser = tree_sitter::Parser::new();
            parser
                .set_language(&tree_sitter_go::LANGUAGE.into())
                .expect("Go grammar must match the shared tree-sitter runtime");
            let tree = parser
                .parse(SOURCE, None)
                .expect("Go edge fixture must produce a syntax tree");
            let facts = brokk_bifrost_go::declarations::parse_go_file(&file, SOURCE, &tree)
                .resolution_facts;
            let fragment = BindingFragmentId::for_test(b"selected-go-edge-law");
            let lexical =
                brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
                    fragment,
                    Language::Go,
                    &facts,
                )
                .lexical()
                .clone();
            let typed =
                brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
                    fragment,
                    Language::Go,
                    &facts,
                )
                .typed()
                .clone();
            let catalog = FactReferenceEdgeCatalog::from_selected_fragments(
                &analyzer,
                [FactReferenceEdgeSelectedFragment::new(
                    file.clone(),
                    SOURCE,
                    &facts,
                    &lexical,
                    &typed,
                    brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(
                    ),
                )],
                &CancellationToken::new(),
            )
            .expect("matching Go source and artifacts must form a catalog")
            .expect("uncancelled Go catalog construction must publish");
            let service = PreloadedFactResolutionService::from_lowered_fragments(
                [lexical.clone()],
                [typed.clone()],
            );
            let snapshot = SelectedFactResolutionEngine::new(&service)
                .snapshot(&CancellationToken::new())
                .expect("Go selected membership needs no Java placement context");
            let mut batches = Vec::new();
            let summary = stage_selected_reference_edge_batches(
                &snapshot,
                &catalog,
                MAX_REFERENCE_SEEDS_PER_BATCH,
                &CancellationToken::new(),
                &mut |batch| {
                    batches.push(batch.clone());
                    Ok(())
                },
            )
            .expect("Go references must stage through the canonical edge path");

            let item_targets = analyzer
                .get_declarations(&file)
                .into_iter()
                .filter(|declaration| declaration.terminal_name() == "Item")
                .collect::<Vec<_>>();
            let [item_target] = item_targets.as_slice() else {
                panic!("one indexed Go Item declaration is required: {item_targets:?}");
            };
            let actual_ranges = batches
                .iter()
                .flat_map(|batch| batch.edges())
                .filter(|edge| &edge.target == item_target)
                .map(|edge| (edge.site.range.start_byte, edge.site.range.end_byte))
                .collect::<BTreeSet<_>>();
            let expected_ranges = SOURCE
                .match_indices("Item")
                .skip(1)
                .map(|(start, spelling)| (start, start + spelling.len()))
                .collect::<BTreeSet<_>>();
            assert_eq!(actual_ranges, expected_ranges);
            assert_eq!(
                summary.edge_count(),
                batches
                    .iter()
                    .map(|batch| batch.edges().len())
                    .sum::<usize>()
            );
            assert_eq!(summary.batch_count(), batches.len());

            let java_named_file = ProjectFile::new(file.root().to_path_buf(), "fixture.java");
            let mismatch = FactReferenceEdgeCatalog::from_selected_fragments(
                &analyzer,
                [FactReferenceEdgeSelectedFragment::new(
                    java_named_file,
                    SOURCE,
                    &facts,
                    &lexical,
                    &typed,
                    brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(
                    ),
                )],
                &CancellationToken::new(),
            );
            let error = match mismatch {
                Ok(_) => panic!("Go artifacts must not join a Java-named source file"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains(
                    "declaration language shared by the analyzer-owned file and artifacts"
                ),
                "unexpected Go source/artifact mismatch error: {error}"
            );
        }
        #[test]
        fn source_owned_membership_rejects_missing_and_extra_catalog_fragments_including_zero_rows()
        {
            let fixture = native_edge_projection_fixture();
            let zero_fragment = BindingFragmentId::for_test(b"selected-zero-row-membership-law");
            let zero_facts = FileResolutionFacts::default();
            let zero_lexical =
                brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
                    zero_fragment,
                    Language::Go,
                    &zero_facts,
                )
                .lexical()
                .clone();
            let zero_typed =
                brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
                    zero_fragment,
                    Language::Go,
                    &zero_facts,
                )
                .typed()
                .clone();
            assert!(
                zero_lexical
                    .semantics()
                    .iter()
                    .all(|site| site.role() != LoweredSemanticRole::Reference),
                "the zero-row law must not infer membership from reference facts"
            );
            let zero_service = PreloadedFactResolutionService::from_lowered_fragments(
                [zero_lexical],
                [zero_typed],
            );
            let zero_snapshot = SelectedFactResolutionEngine::new(&zero_service)
                .snapshot(&CancellationToken::new())
                .expect("a zero-reference source fragment still forms selected membership");
            assert_eq!(
                zero_snapshot.selected_fragments(),
                Some([zero_fragment].as_slice())
            );
            let empty_catalog = FactReferenceEdgeCatalog::from_selected_fragments(
                &fixture.analyzer,
                std::iter::empty::<FactReferenceEdgeSelectedFragment<'_>>(),
                &CancellationToken::new(),
            )
            .expect("an empty selected catalog is structurally valid")
            .expect("a live empty catalog publishes");
            let missing = stage_selected_reference_edge_batches(
                &zero_snapshot,
                &empty_catalog,
                MAX_REFERENCE_SEEDS_PER_BATCH,
                &CancellationToken::new(),
                &mut |_| Ok(()),
            )
            .expect_err("a catalog missing a zero-reference source fragment must fail closed");
            assert!(
                missing.to_string().contains("cover different fragments"),
                "unexpected missing-fragment error: {missing}"
            );

            let empty_service = PreloadedFactResolutionService::from_lowered_fragments(
                std::iter::empty::<LoweredResolutionFragment>(),
                std::iter::empty::<LoweredTypedFragment>(),
            );
            let empty_snapshot = SelectedFactResolutionEngine::new(&empty_service)
                .snapshot(&CancellationToken::new())
                .expect("an empty selected source forms an exact empty snapshot");
            assert_eq!(
                empty_snapshot.selected_fragments(),
                Some(&[] as &[BindingFragmentId])
            );
            let extra_catalog = native_edge_catalog(&fixture);
            let extra = stage_selected_reference_edge_batches(
                &empty_snapshot,
                &extra_catalog,
                MAX_REFERENCE_SEEDS_PER_BATCH,
                &CancellationToken::new(),
                &mut |_| Ok(()),
            )
            .expect_err("a catalog fragment absent from the source inventory must fail closed");
            assert!(
                extra.to_string().contains("cover different fragments"),
                "unexpected extra-fragment error: {extra}"
            );
        }
    }
    mod go_move_2 {

        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_go_analysis::analyzer::go::adapter::GoAdapter;

        use brokk_bifrost_go_analysis::analyzer::go::source_storage::GoSourceStorage;

        use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;

        use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

        use brokk_bifrost_analysis::analyzer::store::test_blob_oid as oid_for;

        use crate::inline_project::InlineTestProject;
        use brokk_bifrost_analysis::analyzer::store::test_support::parse_state;
        const SOURCE: &str = r#"package example
type Base struct{}
type Alias = Base
type Outer struct { X, Y struct { Nested *Base }; Base }
type Service interface { Run(a, b [4]*Base, tail ...chan<- Base) (Base, error) }
func (value *Outer) Run(a, b [4]*Base, tail ...chan<- Base) (Base, error) { return Base{}, nil }
func Make() *Outer { return &Outer{} }
"#;
        #[test]
        fn go_source_reader_rejects_corrupt_type_edges_without_panicking() {
            let fixture = InlineTestProject::with_language(Language::Go)
                .file("types.go", SOURCE)
                .build();
            let file = fixture.file("types.go");
            let state = parse_state(&GoAdapter, &file);
            let oid = oid_for(SOURCE.as_bytes());
            let store = AnalyzerStore::open_ephemeral().unwrap();
            let generation = store.current_generation("go").unwrap();
            store
                .write_parsed_blob(oid, "go", &GoAdapter, &state)
                .unwrap();
            store
                .conn
                .execute(|conn| {
                    assert!(
                        conn.execute("UPDATE source_go_types SET child1=type_id WHERE kind=1", [])
                            .is_err()
                    );
                    conn.execute_batch(
                        "DROP TRIGGER source_go_types_no_update_after_seal;
            PRAGMA ignore_check_constraints=ON;
            UPDATE source_go_types SET child1=type_id WHERE kind=1;
            PRAGMA ignore_check_constraints=OFF;",
                    )?;
                    Ok::<_, brokk_bifrost_analysis::analyzer::store::StoreError>(())
                })
                .unwrap();
            assert!(
                store
                    .go_source_facts(oid, generation, &GoAdapter, &file, &|| true)
                    .is_err()
            );
        }
        #[test]
        fn go_source_lookup_seeks_populated_publications_before_and_after_statistics() {
            let fixture = InlineTestProject::with_language(Language::Go)
                .file("types.go", SOURCE)
                .build();
            let file = fixture.file("types.go");
            let state = parse_state(&GoAdapter, &file);
            let store = AnalyzerStore::open_ephemeral().unwrap();
            let generation = store.current_generation("go").unwrap();
            let oid = oid_for(SOURCE.as_bytes());
            store
                .write_parsed_blob(oid, "go", &GoAdapter, &state)
                .unwrap();
            // Distinct content identities populate the publication inventory without
            // introducing extra parser work into a query-planner regression.
            for index in 0..32 {
                let other = oid_for(format!("planner publication {index}").as_bytes());
                store
                    .write_parsed_blob(other, "go", &GoAdapter, &state)
                    .unwrap();
            }
            brokk_bifrost_analysis::analyzer::store::source_facts::assert_source_lookup_plan(
                &store,
                |conn| {
                    conn.prepare(&format!(
                        "EXPLAIN QUERY PLAN {}",
                        brokk_bifrost_go_analysis::analyzer::go::source_storage::GO_SOURCE_HEADER_SQL
                    ))
                    .unwrap()
                    .query_map(
                        rusqlite::params![
                            oid.to_string(),
                            generation.get(),
                            1,
                            brokk_bifrost_analysis::analyzer::store::source_facts::SOURCE_FACTS_VERSION
                        ],
                        |row| row.get::<_, String>(3),
                    )
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap()
                },
                || {
                    store
                        .go_source_facts(oid, generation, &GoAdapter, &file, &|| true)
                        .unwrap()
                        .is_some()
                },
            );
            store
                .conn
                .execute(|conn| {
                    conn.execute("DELETE FROM blobs", [])?;
                    let count: i64 =
                        conn.query_row("SELECT COUNT(*) FROM source_go_manifests", [], |row| {
                            row.get(0)
                        })?;
                    assert_eq!(
                        count, 0,
                        "blob deletion must cascade sealed source publications"
                    );
                    Ok::<_, brokk_bifrost_analysis::analyzer::store::StoreError>(())
                })
                .unwrap();
        }
        #[test]
        fn go_source_reader_keeps_unversioned_build_selection_metadata_unknown() {
            let fixture = InlineTestProject::with_language(Language::Go)
                .file("types.go", SOURCE)
                .build();
            let file = fixture.file("types.go");
            let state = parse_state(&GoAdapter, &file);
            let store = AnalyzerStore::open_ephemeral().unwrap();
            let generation = store.current_generation("go").unwrap();
            let oid = oid_for(SOURCE.as_bytes());
            store
                .write_parsed_blob(oid, "go", &GoAdapter, &state)
                .unwrap();
            let oid_text = oid.to_string();
            store
        .conn
        .execute(move |conn| {
            conn.execute_batch("DROP TRIGGER source_go_manifests_no_update_after_seal;")?;
            conn.execute(
                "UPDATE source_go_manifests SET build_selection_facts_version=0 WHERE blob_id=(SELECT id FROM blobs WHERE blob_oid=?1 AND lang='go')",
                rusqlite::params![oid_text],
            )?;
            Ok::<_, brokk_bifrost_analysis::analyzer::store::StoreError>(())
        })
        .unwrap();

            let facts = store
                .go_source_facts(oid, generation, &GoAdapter, &file, &|| true)
                .unwrap()
                .unwrap();
            assert_eq!(facts.facts.has_build_constraints, None);
        }
        #[test]
        fn go_declaration_source_facts_reopen_without_source_and_mount_exact_bridges() {
            let fixture = InlineTestProject::with_language(Language::Go)
                .file("first/types.go", SOURCE)
                .file("second/types.go", SOURCE)
                .build();
            let file = fixture.file("first/types.go");
            let second = fixture.file("second/types.go");
            let state = parse_state(&GoAdapter, &file);
            let expected = state.source_facts.as_ref().unwrap().go.as_ref().unwrap();
            assert!(!expected.callables.is_empty());
            assert!(!expected.aliases.is_empty());
            let oid = oid_for(SOURCE.as_bytes());
            let path = fixture.root().join("go-source.db");
            {
                let store = AnalyzerStore::open_persistent(&path).unwrap();
                store
                    .write_parsed_blob(oid, "go", &GoAdapter, &state)
                    .unwrap();
            }
            std::fs::remove_file(file.abs_path()).unwrap();
            let store = AnalyzerStore::open_persistent(&path).unwrap();
            let generation = store.current_generation("go").unwrap();
            let (first, mounted) =
                brokk_bifrost_analysis::analyzer::store::source_facts::assert_source_facts_match_across_mounts(
                    &store,
                    generation,
                    &file,
                    &second,
                    |store, generation, file, cancellation| {
                        store.go_source_facts(oid, generation, &GoAdapter, file, cancellation)
                    },
                    |read| &read.facts,
                );
            assert_eq!(&first.facts, expected);
            assert_eq!(
                first.source,
                state.source_facts.as_ref().unwrap().occurrences
            );
            assert!(
                first
                    .declaration_units
                    .values()
                    .flatten()
                    .all(|unit| unit.source() == &file)
            );
            assert!(
                mounted
                    .declaration_units
                    .values()
                    .flatten()
                    .all(|unit| unit.source() == &second)
            );
            let nested = first
                .facts
                .fields
                .iter()
                .find(|field| field.name == "Nested")
                .unwrap();
            let units = &first.declaration_units[&nested.declaration];
            assert_eq!(
                units.len(),
                2,
                "one written nested field must retain both projections: {units:?}"
            );
            brokk_bifrost_analysis::analyzer::store::source_facts::assert_source_read_cancellation_retries(
                |cancellation| {
                    store.go_source_facts(oid, generation, &GoAdapter, &file, cancellation)
                },
            );
        }
        #[test]
        fn go_source_publication_distinguishes_empty_missing_and_sealed() {
            let fixture = InlineTestProject::with_language(Language::Go)
                .file("empty.go", "package example\n")
                .build();
            let file = fixture.file("empty.go");
            let mut state = parse_state(&GoAdapter, &file);
            let oid = oid_for(state.source.as_bytes());
            let store = AnalyzerStore::open_ephemeral().unwrap();
            let generation = store.current_generation("go").unwrap();
            let facts = state.source_facts.as_mut().unwrap().go.take().unwrap();
            assert!(
                store
                    .write_parsed_blob(oid, "go", &GoAdapter, &state)
                    .is_err()
            );
            state.source_facts.as_mut().unwrap().go = Some(facts);
            store
                .write_parsed_blob(oid, "go", &GoAdapter, &state)
                .unwrap();
            let read = store
                .go_source_facts(oid, generation, &GoAdapter, &file, &|| true)
                .unwrap()
                .unwrap();
            assert!(read.facts.declarations.is_empty());
            assert!(read.facts.callables.is_empty());
            store
                .conn
                .execute(|conn| {
                    assert!(
                        conn.execute(
                            "UPDATE source_go_manifests SET payload_bytes = payload_bytes",
                            []
                        )
                        .is_err()
                    );
                    conn.execute("UPDATE blob_meta SET is_complete = 0", [])?;
                    assert!(
                        conn.execute("UPDATE blob_meta SET go_source_version = NULL", [])
                            .is_err()
                    );
                    conn.execute("UPDATE blob_meta SET is_complete = 1", [])?;
                    conn.execute_batch(
                        "DROP TRIGGER source_go_manifests_no_delete_after_seal;
                            DELETE FROM source_go_manifests;",
                    )?;
                    Ok::<_, brokk_bifrost_analysis::analyzer::store::StoreError>(())
                })
                .unwrap();
            brokk_bifrost_analysis::analyzer::store::source_facts::assert_missing_then_republished(
                || store.go_source_facts(oid, generation, &GoAdapter, &file, &|| true),
                || store.write_parsed_blob(oid, "go", &GoAdapter, &state),
            );
        }
    }
    mod go_move_3 {

        use brokk_bifrost_test_macros::hardwon;

        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_go_analysis::analyzer::go::adapter::GoAdapter;

        use brokk_bifrost_analysis::analyzer::store::test_support::parse_state;

        use crate::inline_project::InlineTestProject;

        use crate::engine_tests::go_publication::go_publication_tests::go_extraction_support_3::assert_published_canonical_source;

        #[test]
        fn go_canonical_publication_reopens_import_aliases_structural_rows_and_native_links() {
            let source = r#"package p
import (
    alias "example.com/alias"
    . "example.com/dot"
    _ "example.com/blank"
)
type Thing struct { Field int }
func helper(value int) int { return value }
func use() { value := helper(1); _ = value; var thing Thing; _ = thing.Field }
"#;
            let fixture = InlineTestProject::with_language(Language::Go)
                .file("go.mod", "module example.com/test\n")
                .file("pkg/sample.go", source)
                .build();
            let state = parse_state(&GoAdapter, &fixture.file("pkg/sample.go"));
            let facts = state.source_facts.as_ref().expect("Go source facts");
            assert_eq!(facts.imports.len(), 3);
            assert_eq!(
                facts
                    .imports
                    .iter()
                    .map(|import| import.alias.as_deref())
                    .collect::<Vec<_>>(),
                vec![Some("alias"), Some("."), Some("_")]
            );
            assert!(
                facts
                    .imports
                    .iter()
                    .all(|import| import.alias_occurrence.is_some())
            );
            assert!(!facts.structural.nodes().is_empty());
            assert!(!facts.native_declaration_sources.is_empty());
            assert_published_canonical_source(&fixture, "pkg/sample.go", "go", &GoAdapter, &state);
        }
        #[test]
        #[hardwon(
            "#5074: anonymous struct fields and decoded tags did not survive source publication"
        )]
        fn go_anonymous_struct_fields_and_tags_survive_reopening() {
            let source = r#"package p
 type Options struct{}
 func TestCreate() {
     tests := []struct {
         opts *Options `json:"opts"`
         ctx struct { Client *Options }
     }{}
     for _, tt := range tests { _ = tt.opts; _ = tt.ctx.Client }
     type localOptions struct { opts *Options }
     _ = localOptions{}
 }
"#;
            let fixture = InlineTestProject::with_language(Language::Go)
                .file("go.mod", "module example.com/test\n")
                .file("pkg/sample_test.go", source)
                .build();
            let state = parse_state(&GoAdapter, &fixture.file("pkg/sample_test.go"));
            let go = state.source_facts.as_ref().unwrap().go.as_ref().unwrap();
            assert_eq!(go.fields.len(), 4, "{go:#?}");
            assert!(
                go.fields
                    .iter()
                    .any(|field| field.tag.as_deref() == Some(b"json:\"opts\""))
            );
            assert_published_canonical_source(
                &fixture,
                "pkg/sample_test.go",
                "go",
                &GoAdapter,
                &state,
            );
        }
    }
    mod go_move_4 {

        use brokk_bifrost_analysis::analyzer::resolution::engine::PreloadedFragmentSource;

        use brokk_bifrost_core::cancellation::CancellationToken;

        use brokk_bifrost_core::analyzer::Language;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::package::LoweredGoPackageImport;

        use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGoPackageImportKind;

        use brokk_bifrost_analysis::analyzer::resolution::local_identity::ResolutionLookupSemanticRecipe;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootImportAnchor;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId;

        use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;

        use brokk_bifrost_analysis::analyzer::resolution::selected_context::SelectedContextIdentities;

        use brokk_bifrost_analysis::analyzer::resolution::selected_context::go_import::SelectedGoImportBindingDescriptor;

        use brokk_bifrost_analysis::analyzer::resolution::selected_context::SelectedResolutionContextSet;

        use brokk_bifrost_analysis::analyzer::resolution::selected_context::SelectedResolutionContextValidationOutcome;

        use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedResolutionMountOrdinal;

        use brokk_bifrost_analysis::analyzer::resolution::selected_context::SelectedRootBridgeDescriptor;

        use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;

        use brokk_bifrost_analysis::analyzer::resolution::test_support::fragment as fixture_fragment;

        use brokk_bifrost_analysis::analyzer::resolution::test_support::node;

        use brokk_bifrost_analysis::analyzer::resolution::test_support::semantic;

        #[test]
        fn selected_import_authority_survives_context_extensions_and_cancels_atomically() {
            let fragment = fixture_fragment("selected-go-import-source");
            let ordinal = SelectedResolutionMountOrdinal::new(fragment.ordinal());
            let lookup = |candidate| Ok((candidate == fragment).then_some((ordinal, Language::Go)));
            let identities = SelectedContextIdentities::new();
            let cancellation = CancellationToken::new();
            let binding = SelectedGoImportBindingDescriptor::new(
                fragment,
                &LoweredGoPackageImport {
                    definition: semantic("selected-go-import-definition"),
                    source_site: ResolutionSiteId::new(7),
                    file_scope: node("selected-go-import-file-scope"),
                    spelling_choice: semantic("selected-go-import-choice"),
                    start_byte: 10,
                    end_byte: 20,
                    kind: ResolutionGoPackageImportKind::Named,
                },
                node("selected-go-import-definition-node"),
                SemanticId::shared_name(
                    brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names().intern(
                        brokk_bifrost_core::analyzer::canonical_hash::hash_domain_bytes(
                            b"bifrost-fixture-go-package-lookup:v1",
                            b"Package",
                        ),
                    ),
                ),
                ResolutionCompletion::Complete,
            );
            let expected = binding
                .compile(
                    &identities,
                    &PreloadedFragmentSource::new([], []),
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap();
            let context =
                SelectedResolutionContextSet::new(identities.clone(), Vec::new(), 1, &lookup)
                    .unwrap()
                    .extend_go_import_bindings(vec![binding.clone()], &cancellation, &lookup)
                    .unwrap()
                    .unwrap();
            let root_bridge = SelectedRootBridgeDescriptor::for_test(
                fragment,
                Language::Go,
                ResolutionSiteId::new(7),
                ResolutionRootImportAnchor::Lexical,
                fragment,
                Language::Go,
                ResolutionScopeId::new(0),
                Vec::new(),
                ResolutionLookupSemanticRecipe::new(
                    Language::Go,
                    ResolutionNamespace::Type,
                    "Item",
                ),
                ResolutionLookupSemanticRecipe::new(
                    Language::Go,
                    ResolutionNamespace::Type,
                    "Item",
                ),
                ResolutionCompletion::Complete,
            );
            let extended = context
                .clone()
                .extend_root_bridges(vec![root_bridge], &cancellation, None, &lookup)
                .unwrap()
                .unwrap()
                .extend_package_bridges(Vec::new(), &cancellation, &lookup)
                .unwrap()
                .unwrap();
            let SelectedResolutionContextValidationOutcome::Ready(input) = extended
                .validate_exact_mounts(1, &lookup, &cancellation)
                .unwrap()
            else {
                panic!("live selected import context must validate");
            };
            let (_, _, _, _, assigned, _, imports, _) = input.into_parts();
            assert_eq!(imports.as_ref(), std::slice::from_ref(&binding));
            assert_eq!(
                imports[0]
                    .compile(
                        &assigned,
                        &PreloadedFragmentSource::new([], []),
                        &cancellation,
                        &ResolutionSession::unbounded()
                    )
                    .unwrap(),
                expected
            );
            cancellation.cancel();
            assert!(
                context
                    .extend_go_import_bindings(vec![binding], &cancellation, &lookup)
                    .unwrap()
                    .is_none()
            );
        }
    }
    mod go_move_5 {

        use brokk_bifrost_go_analysis::analyzer::go::adapter::GoAdapter;

        use brokk_bifrost_analysis::analyzer::resolution::model::BindingFragmentId;

        use brokk_bifrost_analysis::analyzer::resolution::model::BindingNodeId;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::FactIndex;

        use brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts;

        use brokk_bifrost_core::analyzer::Language;

        use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;

        use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::package::namespaces;

        use brokk_bifrost_analysis::analyzer::resolution::LoweredResolutionFactsWithIdentityCatalog;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test;

        use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::LanguageAdapter;

        use brokk_bifrost_core::analyzer::model::ProjectFile;
        use std::collections::{BTreeMap, BTreeSet};
        fn parsed(
            label: &str,
            source: &str,
        ) -> (
            FileResolutionFacts,
            LoweredResolutionFactsWithIdentityCatalog,
        ) {
            let file = ProjectFile::new(std::env::temp_dir(), format!("{label}.go"));
            let adapter = GoAdapter;
            let mut parser = tree_sitter::Parser::new();
            parser
                .set_language(&adapter.parser_language_for_file(&file))
                .unwrap();
            let tree = parser.parse(source, None).unwrap();
            let facts = adapter.parse_file(&file, source, &tree).resolution_facts;
            let artifact = lower_for_test(BindingFragmentId::for_test(label), Language::Go, &facts);
            (facts, artifact)
        }
        #[test]
        fn repeated_go_package_references_share_one_path_per_lookup() {
            let uses = (0..20)
                .flat_map(|_| ["_ = c", "_ = x"])
                .collect::<Vec<_>>()
                .join("\n");
            let source = format!("package p\nfunc use() {{\n{uses}\n}}\n");
            let (facts, lowered) = parsed("go-shared-package-reference", &source);
            let index = FactIndex::new(Language::Go, &facts);
            let mut names = BTreeMap::<String, usize>::new();
            for fact in &facts.package_references {
                let identifier = index.identifiers_by_site[&fact.reference]
                    .iter()
                    .find(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
                    .expect("Go package reference has a source identifier");
                let name = index.name(identifier.name);
                if name != "_" {
                    *names.entry(name.to_owned()).or_default() += 1;
                }
            }
            assert_eq!(
                names,
                BTreeMap::from([("c".to_owned(), 20), ("x".to_owned(), 20)])
            );

            let references = &lowered.common().package_references;
            assert_eq!(
                references.len(),
                facts.package_references.len()
                    * namespaces(Language::Go, ResolutionNamespace::Value).len()
            );
            let mut sites_by_group = BTreeMap::<
                (BindingNodeId, ResolutionNamespace, SemanticId),
                (SemanticId, BTreeSet<SemanticId>, BTreeSet<ResolutionSiteId>),
            >::new();
            let mut per_site = BTreeSet::new();
            for reference in references {
                let identifier = index.identifiers_by_site[&reference.source_site]
                    .iter()
                    .find(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
                    .expect("Go package reference has a source identifier");
                if index.name(identifier.name) == "_" {
                    continue;
                }
                assert!(per_site.insert((reference.reference, reference.namespace)));
                let group = (reference.root_scope, reference.namespace, reference.lookup);
                let (token, source_references, source_sites) = sites_by_group
                    .entry(group)
                    .or_insert_with(|| (reference.token, BTreeSet::new(), BTreeSet::new()));
                assert_eq!(*token, reference.token);
                source_references.insert(reference.reference);
                source_sites.insert(reference.source_site);
            }
            assert_eq!(sites_by_group.len(), 6);
            for (group, (_, source_references, source_sites)) in &sites_by_group {
                assert_eq!(source_references.len(), 20, "group {group:?}");
                assert_eq!(source_sites.len(), 20, "group {group:?}");
            }

            let path_groups = references
                .iter()
                .map(|reference| {
                    (
                        reference.root_scope,
                        reference.domain,
                        reference.token,
                        reference.lookup,
                    )
                })
                .collect::<BTreeSet<_>>();
            let package_paths = lowered
                .lexical()
                .paths()
                .iter()
                .filter(|(_, path)| {
                    let symbols = path.end().symbols().fixed();
                    path.end().node() == BindingNodeId::universal_root()
                        && symbols.len() == 3
                        && path_groups.contains(&(
                            path.start().node(),
                            symbols[0].symbol(),
                            symbols[1].symbol(),
                            symbols[2].symbol(),
                        ))
                })
                .collect::<Vec<_>>();
            assert_eq!(package_paths.len(), path_groups.len());
            assert!(
                package_paths
                    .iter()
                    .all(|(_, path)| { path.completion() == &ResolutionCompletion::Complete })
            );
        }
        #[test]
        fn kotlin_and_scala_package_references_publish_all_jvm_namespaces() {
            let (facts, _) = parsed(
                "jvm-package-reference",
                "package p\nfunc use(){ _ = remote }\n",
            );
            let reference_site = facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Reference
                        && facts.names[identifier.name.index()].spelling == "remote"
                })
                .unwrap()
                .site;
            for language in [Language::Kotlin, Language::Scala] {
                let lowered = lower_for_test(
                    BindingFragmentId::for_test(language.config_label()),
                    language,
                    &facts,
                );
                let namespaces = lowered
                    .common()
                    .package_references
                    .iter()
                    .filter(|reference| reference.source_site == reference_site)
                    .map(|reference| reference.namespace)
                    .collect::<BTreeSet<_>>();
                assert_eq!(
                    namespaces,
                    BTreeSet::from([
                        ResolutionNamespace::Callable,
                        ResolutionNamespace::Type,
                        ResolutionNamespace::Value,
                    ])
                );
            }
        }
        #[test]
        fn scala_package_object_export_becomes_package_membership() {
            let (mut facts, _) = parsed(
                "scala-package-object-export",
                "package p\ntype Box struct {}\nvar Exported int\n",
            );
            let declaration_site = |spelling: &str| {
                facts
                    .identifiers
                    .iter()
                    .find(|identifier| {
                        identifier.role == ResolutionIdentifierRole::Declaration
                            && facts.names[identifier.name.index()].spelling == spelling
                    })
                    .expect("hand-built package-object export declaration")
                    .site
            };
            let package_object = declaration_site("Box");
            let member = declaration_site("Exported");
            let package_scope =
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId::new(1);
            facts.packages.push(
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionPackageFact {
                    root_scope: package_scope,
                    declaration: None,
                    placement_gap_site: package_object,
                },
            );
            facts.package_object_exports.push(
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionPackageObjectExportFact {
                    package_object,
                    package_scope,
                    member,
                },
            );

            let lowered = lower_for_test(
                BindingFragmentId::for_test("scala-package-object-export"),
                Language::Scala,
                &facts,
            );
            let package_root = lowered
                .common()
                .package_members
                .iter()
                .find(|row| row.source_site == package_object)
                .unwrap()
                .root_scope;
            assert!(lowered.common().package_members.iter().any(|row| {
                row.source_site == member
                    && row.root_scope == package_root
                    && row.namespace == ResolutionNamespace::Value
            }));
            assert!(
                lowered
                    .common()
                    .shared_language
                    .package_object_exports
                    .iter()
                    .any(|row| {
                        row.package_object == package_object
                            && row.package_scope == package_root
                            && row.member == member
                    })
            );
        }
    }
}
