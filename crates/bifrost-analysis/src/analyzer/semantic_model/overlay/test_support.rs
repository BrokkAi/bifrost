use brokk_bifrost_analysis::analyzer::semantic_model::model::Signature;
use brokk_bifrost_analysis::analyzer::semantic_model::model::Visibility;
use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelActivationProvenance;
use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelCompleteness;
use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelLocation;
use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelMatchedEvidence;
use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOriginKind;
use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay;
use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelProof;
use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelProvenance;
use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelRange;
use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelRelation;
use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelSymbol;
use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelSymbolKind;
use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelVirtualLocation;
use brokk_bifrost_analysis::analyzer::semantic_model::overlay::render_callable_shape;
use brokk_bifrost_analysis::analyzer::semantic_model::overlay::render_signature;
use brokk_bifrost_analysis::analyzer::semantic_model::overlay::signature_has_complete_callable_shape;
use brokk_bifrost_core::hash::HashMap;

/// Build an overlay straight from records. The pack pipeline that
/// ordinarily produces them is exercised by the semantic-model suites; what
/// these tests pin is the ancestor walk and the surface gate over an
/// arbitrary published shape, including shapes a producer emits only when
/// half a dependency set is indexed.
#[doc(hidden)]
pub fn overlay(
    mut symbols: Vec<SemanticModelSymbol>,
    mut relations: Vec<SemanticModelRelation>,
) -> SemanticModelOverlay {
    super::composition::freeze_symbol_order(&mut symbols);
    super::composition::freeze_relation_order(relations.iter_mut());
    let budget = brokk_bifrost_core::retention_budget::RetentionBudget::for_tests();
    let mut overlay = SemanticModelOverlay {
        identity: super::trait_owner_memo::OverlayIdentity::new(),
        rust_reexport_roots: Default::default(),
        rust_reexport_shards: Default::default(),
        rust_reexport_published_roots: Default::default(),
        active_models: None,
        rust_cargo_graph: None,
        row_source: None,
        selected_source: None,
        declared_type_names: Default::default(),
        active_model_set_hash: "test".to_string(),
        model_member_cache: brokk_bifrost_core::budgeted_value_cache::BudgetedValueCache::new(
            budget.region("analysis.model_member", Some(128)),
        ),
        model_result_cache: brokk_bifrost_core::budgeted_value_cache::BudgetedValueCache::new(
            budget.region("analysis.model_result", Some(128)),
        ),
        composition_diagnostics: Vec::new(),
        charge: Default::default(),
        extraction_gaps: Vec::new(),
        extraction_gap_by_declaration: HashMap::default(),
        packs_naming_every_loss: Default::default(),
        declaration_surface_languages: Vec::new(),
        complete_declaration_surface_languages: Vec::new(),
        generated_function_languages: symbols
            .iter()
            .filter(|s| s.is_rule_generated_function())
            .map(|s| s.language.clone())
            .collect(),
        symbols: symbols.into_iter().map(std::sync::Arc::new).collect(),
        relations: relations.into_iter().map(std::sync::Arc::new).collect(),
        symbols_by_id: HashMap::default(),
        symbols_by_name: HashMap::default(),
        symbols_by_uri: HashMap::default(),
        symbols_by_authored_path: HashMap::default(),
        symbols_by_owner: HashMap::default(),
        relations_from: HashMap::default(),
        relations_to: HashMap::default(),
        runtime_values: Vec::new(),
        collection_flows: Vec::new(),
        collection_flows_by_callable: HashMap::default(),
        conditional_type_refinements: Vec::new(),
        conditional_types_by_callable: HashMap::default(),
        deferred_yields: Vec::new(),
        deferred_yields_by_scope: HashMap::default(),
    };
    overlay
        .rebuild_indexes(&brokk_bifrost_core::cancellation::CancellationToken::default())
        .expect("indexes build");
    overlay
}

#[doc(hidden)]
pub fn provenance(completeness: SemanticModelCompleteness) -> SemanticModelProvenance {
    SemanticModelProvenance {
        extraction: None,
        active_model_set_hash: "test".to_string(),
        pack_digest: "digest".to_string(),
        pack_id: "test.pack".to_string(),
        pack_version: "1.0.0".to_string(),
        producer: "test".to_string(),
        producer_version: "1.0.0".to_string(),
        record_id: "record".to_string(),
        rule_id: None,
        origin: SemanticModelOriginKind::DependencySource,
        activation: SemanticModelActivationProvenance {
            approximate: false,
            approximation: None,
            status: "active".to_string(),
            reason: "test".to_string(),
            source_kind: "test".to_string(),
            source_id: "test".to_string(),
            matched_evidence: SemanticModelMatchedEvidence {
                language: "python".to_string(),
                ecosystem: "python".to_string(),
                package: None,
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            },
        },
        proof: SemanticModelProof::PackFact,
        completeness,
        ambiguous: false,
    }
}

/// A published class. Its identity is deliberately distinct from its
/// qualified name so a test can tell an identity resolution apart from a
/// name one.
#[doc(hidden)]
pub fn class(qualified_name: &str, language: &str) -> SemanticModelSymbol {
    SemanticModelSymbol {
        callable_group: Default::default(),
        callable_family_target_independent: false,
        pre_composition_qualified_name: None,
        semantic_contributors: Vec::new(),
        jvm_owner_family_enumerated: false,
        python_runtime_bases: None,
        non_overridable: None,
        ambient_use: None,
        id: format!("type.{qualified_name}"),
        owner_id: None,
        name: qualified_name
            .rsplit('.')
            .next()
            .expect("a qualified name has a terminal segment")
            .to_string(),
        qualified_name: qualified_name.to_string(),
        language: language.to_string(),
        kind: SemanticModelSymbolKind::Class,
        visibility: Visibility::Public,
        is_static: false,
        declaration_is_abstract: false,
        declaration_is_sealed: false,
        declaration_is_final: None,
        callable_surface_complete: false,
        source_completeness:
            brokk_bifrost_semantic::analyzer::semantic_model::model::Completeness::Complete,
        values_complete: false,
        supertypes_complete: false,
        signature: None,
        structured_signature: None,
        has_explicit_type_terms: false,
        callable_shape: None,
        callable_shape_evidence_complete: false,
        callable_family_complete: false,
        exact_return_classes: Vec::new(),
        aliases: Vec::new(),
        type_parameter_constraints: Vec::new(),
        underlying_type: None,
        value_semantics: None,
        embedded_types: Vec::new(),
        receiver: None,
        implicit_operation: None,
        explicit_operation: None,
        value_type: None,
        proxied_type: None,
        extension_receiver: None,
        extension_receiver_constraints: Vec::new(),
        locator_path: None,
        locator_symbol: None,
        rust_generated_scope: None,
        promoted_from: None,
        members_state: brokk_bifrost_semantic::analyzer::semantic_model::ModelMembersState::Exact,
        location: SemanticModelLocation::Model(SemanticModelVirtualLocation {
            uri: format!("bifrost-model://v1/{qualified_name}"),
            range: SemanticModelRange {
                start_byte: 0,
                end_byte: 0,
                start_line: 0,
                end_line: 0,
            },
        }),
        provenance: provenance(SemanticModelCompleteness::Complete),
    }
}

#[doc(hidden)]
pub fn method(
    owner: &SemanticModelSymbol,
    id: &str,
    name: &str,
    signature: Option<Signature>,
) -> SemanticModelSymbol {
    let mut symbol = SemanticModelSymbol {
        callable_group: Default::default(),
        callable_family_target_independent: false,
        pre_composition_qualified_name: None,
        semantic_contributors: Vec::new(),
        jvm_owner_family_enumerated: false,
        python_runtime_bases: None,
        non_overridable: None,
        ambient_use: None,
        id: id.to_string(),
        owner_id: Some(owner.id.clone()),
        name: name.to_string(),
        qualified_name: format!("{}.{}", owner.qualified_name, name),
        language: owner.language.clone(),
        kind: SemanticModelSymbolKind::Method,
        visibility: Visibility::Public,
        is_static: false,
        declaration_is_abstract: false,
        declaration_is_sealed: false,
        declaration_is_final: None,
        callable_surface_complete: false,
        source_completeness:
            brokk_bifrost_semantic::analyzer::semantic_model::model::Completeness::Complete,
        values_complete: false,
        supertypes_complete: false,
        signature: signature
            .as_ref()
            .map(|value| render_signature(name, value)),
        structured_signature: signature,
        has_explicit_type_terms: false,
        callable_shape: None,
        callable_shape_evidence_complete: false,
        callable_family_complete: false,
        exact_return_classes: Vec::new(),
        aliases: Vec::new(),
        type_parameter_constraints: Vec::new(),
        underlying_type: None,
        value_semantics: None,
        embedded_types: Vec::new(),
        receiver: None,
        implicit_operation: None,
        explicit_operation: None,
        value_type: None,
        proxied_type: None,
        extension_receiver: None,
        extension_receiver_constraints: Vec::new(),
        locator_path: None,
        locator_symbol: None,
        rust_generated_scope: None,
        promoted_from: None,
        members_state: brokk_bifrost_semantic::analyzer::semantic_model::ModelMembersState::Exact,
        location: SemanticModelLocation::Model(SemanticModelVirtualLocation {
            uri: format!("bifrost-model://v1/{}", owner.qualified_name),
            range: SemanticModelRange {
                start_byte: 0,
                end_byte: 0,
                start_line: 0,
                end_line: 0,
            },
        }),
        provenance: provenance(SemanticModelCompleteness::Complete),
    };
    symbol.callable_shape = symbol
        .structured_signature
        .as_ref()
        .map(render_callable_shape);
    symbol.callable_shape_evidence_complete = symbol
        .structured_signature
        .as_ref()
        .is_some_and(signature_has_complete_callable_shape);
    symbol
}

#[doc(hidden)]
pub fn extends(from: &SemanticModelSymbol, to: &str) -> SemanticModelRelation {
    SemanticModelRelation {
        pre_composition_endpoints: None,
        id: format!("hierarchy:{}:extends:{to}", from.id),
        kind: "extends".to_string(),
        from: from.id.clone(),
        to: to.to_string(),
        declaration_ordinal: Some(0),
        provenance: provenance(SemanticModelCompleteness::Complete),
    }
}

/// The record-only test constructor has no active shards to decode. Treat its
/// explicitly supplied projected symbols as the test input; production eager
/// overlays always retain their decoded-shard source.
pub(super) fn selected_fixture_groups(
    symbols: &[std::sync::Arc<SemanticModelSymbol>],
    language: &str,
    reference: &super::TypeRef,
    selection: &super::ModelProviderSelection,
    cancellation: &crate::CancellationToken,
) -> Result<Vec<Vec<SemanticModelSymbol>>, super::SemanticModelOverlayBuildError> {
    let mut symbols = symbols
        .iter()
        .filter(|s| {
            s.language == language && selection.contains(&super::ModelProvider::from(&s.provenance))
        })
        .map(|s| (**s).clone())
        .collect::<Vec<_>>();
    super::model_composition_language(language).augment_group(
        &mut symbols,
        &mut Vec::new(),
        cancellation,
    )?;
    let groups = super::composition::alias_groups(&symbols, cancellation)?;
    Ok(groups
        .into_iter()
        .filter_map(|owners| {
            let selected = owners.iter().any(|&index| match reference {
                super::TypeRef::Named { name, .. } => {
                    symbols[index].qualified_name == *name || symbols[index].aliases.contains(name)
                }
                super::TypeRef::Declared { id, .. } => {
                    symbols[index].id == *id
                        || symbols.iter().any(|member| {
                            member.id == *id
                                && member.owner_id.as_deref() == Some(symbols[index].id.as_str())
                                && super::ModelProvider::from(&member.provenance)
                                    == super::ModelProvider::from(&symbols[index].provenance)
                        })
                }
                _ => false,
            });
            selected.then(|| {
                symbols
                    .iter()
                    .filter(|s| {
                        owners.iter().any(|&index| {
                            let owner = &symbols[index];
                            (s.id == owner.id || s.owner_id.as_deref() == Some(owner.id.as_str()))
                                && super::ModelProvider::from(&s.provenance)
                                    == super::ModelProvider::from(&owner.provenance)
                        })
                    })
                    .cloned()
                    .collect()
            })
        })
        .collect())
}

/// Compare the complete question family with the uncached row path after a fill.
/// Callers may attach SQL row listeners to the counter to verify warm reads.
pub fn assert_indexed_binding_questions(
    published: &SemanticModelOverlay,
    realm: Option<&str>,
    rows: Option<&std::sync::atomic::AtomicUsize>,
) -> (
    crate::analyzer::store::semantic_composition::SearchCandidateKey,
    [u8; 32],
) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let unused_counter = AtomicUsize::new(0);
    let rows = rows.unwrap_or(&unused_counter);
    let token = crate::CancellationToken::new();
    let overlay = published.row_source.as_ref().expect("row-backed fixture");
    let mut ordinary = overlay.as_ref().clone();
    ordinary.cache = None;
    let patterns =
        crate::analyzer::SearchSymbolPatternBatch::compile(vec![".*".into()], false, None);
    let (symbols, complete) =
        ordinary.with_search_symbols(&patterns, Some(&token), realm, |records, complete| {
            (
                records
                    .into_iter()
                    .map(|symbol| symbol.to_shared())
                    .collect::<Vec<_>>(),
                complete,
            )
        });
    assert!(complete);
    assert!(!symbols.is_empty());
    use crate::analyzer::store::cache_budget::RetainedBytes;
    use crate::analyzer::store::semantic_composition::SearchCandidateKey;
    let owner = overlay
        .active
        .request_source()
        .unwrap()
        .jvm_reader(&overlay.active)
        .unwrap();
    let key = SearchCandidateKey {
        realm: realm.map(str::to_owned),
        build: overlay.build_identity,
        jvm_binding: Some(owner.binding),
    };
    let mut names = vec!["missing.spelling".to_owned()];
    let mut ids = vec!["missing.id".to_owned()];
    for symbol in &symbols {
        names.extend([symbol.name.clone(), symbol.qualified_name.clone()]);
        names.extend(symbol.aliases.clone());
        ids.push(symbol.id.clone());
        ids.extend(
            symbol
                .semantic_contributors
                .iter()
                .map(|contributor| contributor.record_id.clone()),
        );
        if let Some(owner) = &symbol.owner_id {
            names.push(format!("{owner}.{}", symbol.name));
            for alias in &symbol.aliases {
                names.push(format!("{owner}.{alias}"));
            }
        }
    }
    for warm in [false, true] {
        if warm {
            overlay.with_search_symbols(&patterns, Some(&token), realm, |_, complete| {
                assert!(complete)
            });
            let entry = overlay
                .cache
                .as_ref()
                .expect("budgeted row overlay")
                .composed_search_inputs
                .get_ready(&overlay.effective_search_inputs(&key).digest(), &token)
                .expect("complete exact-key entry");
            // Exercise the resident augmentation on both the project and JDK
            // carriers that use this shared boundary oracle.
            let language = realm.map(|_| "java");
            for limit in [0, 1, 3, usize::MAX] {
                let expected = match language {
                    Some(language) => published.search_with_limit_filter_in_family(
                        &patterns,
                        limit,
                        None,
                        language,
                        |s| s.owner_id.is_none(),
                    ),
                    None => published
                        .search_with_limit_filter(&patterns, limit, None, |s| s.owner_id.is_none()),
                };
                let accepted = std::cell::Cell::new(0usize);
                let actual = published.augmentation_symbols(&patterns, limit, language, |s| {
                    let matches = s.owner_id.is_none();
                    if matches {
                        accepted.set(accepted.get() + 1);
                    }
                    matches
                });
                assert_eq!((expected.0, expected.2), actual);
                assert_eq!(
                    accepted.get(),
                    actual.0.len(),
                    "stop after the last accepted slot"
                );
            }
            assert_eq!(entry.records.capacity(), entry.records.len());
            assert_eq!(entry.groups.capacity(), entry.groups.len());
            for group in &entry.groups {
                assert_eq!(group.capacity(), group.len());
            }
            eprintln!(
                "SemanticModelSymbol size={}",
                std::mem::size_of::<crate::analyzer::semantic_model::SemanticModelSymbol>()
            );
            eprintln!(
                "realm={realm:?} base_bytes={} index_bytes={}",
                entry.retained_bytes() - entry.index.retained_bytes(),
                entry.index.retained_bytes()
            );
        }
        for name in &names {
            let expected = ordinary.symbols_named_scoped(name, realm);
            assert!(expected.1.is_none());
            rows.store(0, Ordering::Relaxed);
            assert_eq!(
                overlay.symbols_named_scoped(name, realm),
                expected,
                "name={name}"
            );
            if warm {
                assert_eq!(rows.load(Ordering::Relaxed), 0);
            }
        }
        for id in &ids {
            let expected = ordinary.symbols_with_id_scoped(id, realm);
            assert!(expected.1.is_none());
            rows.store(0, Ordering::Relaxed);
            assert_eq!(overlay.symbols_with_id_scoped(id, realm), expected);
            if warm {
                assert_eq!(rows.load(Ordering::Relaxed), 0);
            }
            let expected = ordinary.members_of_scoped(id, realm);
            assert!(expected.1.is_none());
            rows.store(0, Ordering::Relaxed);
            assert_eq!(overlay.members_of_scoped(id, realm), expected);
            if warm {
                assert_eq!(rows.load(Ordering::Relaxed), 0);
            }
            // Relations are not in the fill: they read their owners' rows.
            let expected = ordinary.relations_from_scoped(id, realm);
            assert!(expected.1.is_none());
            assert_eq!(overlay.relations_from_scoped(id, realm), expected);
            let expected = ordinary.relations_to_scoped(id, realm);
            assert!(expected.1.is_none());
            assert_eq!(overlay.relations_to_scoped(id, realm), expected);
        }
    }
    let digest = overlay.effective_search_inputs(&key).digest();
    (key, digest)
}

/// Verify that reactivation selects a new certificate, even if the old entry
/// remains in the shared budget. Compare cold and warm questions with row reads.
pub fn assert_reactivated_binding_questions(
    published: &SemanticModelOverlay,
    realm: Option<&str>,
    previous: &(
        crate::analyzer::store::semantic_composition::SearchCandidateKey,
        [u8; 32],
    ),
) {
    let overlay = published.row_source.as_ref().expect("row-backed fixture");
    let owner = overlay
        .active
        .request_source()
        .unwrap()
        .jvm_reader(&overlay.active)
        .unwrap();
    assert_ne!(previous.0.jvm_binding.as_ref(), Some(&owner.binding));
    let key = crate::analyzer::store::semantic_composition::SearchCandidateKey {
        realm: realm.map(str::to_owned),
        build: overlay.build_identity,
        jvm_binding: Some(owner.binding),
    };
    assert_ne!(&key, &previous.0);
    let cache = &overlay.cache.as_ref().unwrap().composed_search_inputs;
    let token = crate::CancellationToken::new();
    eprintln!(
        "reactivation realm={realm:?} old_entry_resident={}",
        cache.get_ready(&previous.1, &token).is_some()
    );
    // Another realm may already have filled the replacement's equal inputs.
    assert_ne!(overlay.effective_search_inputs(&key).digest(), previous.1);
    assert_eq!(
        assert_indexed_binding_questions(published, realm, None),
        (key.clone(), overlay.effective_search_inputs(&key).digest())
    );
}
