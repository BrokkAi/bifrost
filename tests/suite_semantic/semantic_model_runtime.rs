use brokk_bifrost::CancellationToken;
use brokk_bifrost::analyzer::semantic_model::*;
use brokk_bifrost::analyzer::store::AnalyzerStore;
use brokk_bifrost::{AnalyzerConfig, Language};
use semver::{Version, VersionReq};
use serde_json::{Value, json};
use std::sync::Arc;

use crate::common::InlineTestProject;

const DECLARATIONS_JSON: &[u8] =
    include_bytes!("../fixtures/semantic-model-packs/declarations-v1.json");
const RULES_JSON: &[u8] =
    include_bytes!("../fixtures/semantic-model-packs/generator-rules-v1.json");

fn compile(source: &[u8]) -> CompiledSemanticModelPack {
    compile_source(SourceFormat::Json, source, &CompilerOptions::default())
        .unwrap_or_else(|diagnostics| panic!("fixture compilation failed: {diagnostics:#?}"))
}

fn evidence() -> SemanticModelActivationEvidence {
    SemanticModelActivationEvidence {
        language: "java".to_owned(),
        ecosystem: "maven".to_owned(),
        package: Some(CatalogCoordinate {
            name: "com.acme:widget".to_owned(),
            version: Some(Version::parse("1.5.0").unwrap()),
        }),
        module: None,
        toolchain: Some(CatalogCoordinate {
            name: "jdk".to_owned(),
            version: Some(Version::parse("17.0.1").unwrap()),
        }),
        target: Some("jvm".to_owned()),
        configuration: Some("release".to_owned()),
        artifact_sha256: None,
    }
}

fn request(evidence: Vec<SemanticModelActivationEvidence>) -> SemanticModelActivationRequest {
    SemanticModelActivationRequest {
        bifrost_version: Version::parse("0.8.17").unwrap(),
        evidence,
        controls: Vec::new(),
        limits: SemanticModelRuntimeLimits::default(),
    }
}

fn ready(outcome: SemanticModelResolutionOutcome) -> ResolvedActiveSemanticModels {
    match outcome {
        SemanticModelResolutionOutcome::Ready(active) => active,
        other => panic!("expected ready semantic models, got {other:#?}"),
    }
}

#[test]
fn strict_evidence_activates_only_a_fully_satisfied_shard() {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let pack = compile(DECLARATIONS_JSON);
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "fixture".to_owned(),
            },
        )
        .unwrap();

    let active = ready(resolve_active_semantic_models(
        &catalog,
        &request(vec![evidence()]),
        &CancellationToken::default(),
    ));
    assert_eq!(active.shards().len(), 1);
    assert!(
        active
            .activation_report()
            .explanations
            .iter()
            .any(|entry| entry.status == SemanticModelActivationStatus::Active)
    );

    for mutate in [
        |row: &mut SemanticModelActivationEvidence| row.target = None,
        |row: &mut SemanticModelActivationEvidence| row.configuration = None,
        |row: &mut SemanticModelActivationEvidence| row.package = None,
        |row: &mut SemanticModelActivationEvidence| row.toolchain = None,
    ] {
        let mut near_miss = evidence();
        mutate(&mut near_miss);
        let inactive = ready(resolve_active_semantic_models(
            &catalog,
            &request(vec![near_miss]),
            &CancellationToken::default(),
        ));
        assert!(inactive.shards().is_empty());
        assert!(
            inactive
                .activation_report()
                .explanations
                .iter()
                .any(|entry| entry.status == SemanticModelActivationStatus::Incompatible)
        );
    }
}

#[test]
fn review_required_rules_need_a_compatible_explicit_enable() {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let pack = compile(RULES_JSON);
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "rules".to_owned(),
            },
        )
        .unwrap();
    let mut rules_evidence = evidence();
    rules_evidence.package = Some(CatalogCoordinate {
        name: "com.acme:builders".to_owned(),
        version: Some(Version::parse("1.5.0").unwrap()),
    });
    rules_evidence.toolchain = None;
    rules_evidence.target = None;
    rules_evidence.configuration = None;

    let inactive = ready(resolve_active_semantic_models(
        &catalog,
        &request(vec![rules_evidence.clone()]),
        &CancellationToken::default(),
    ));
    assert!(inactive.shards().is_empty());
    assert!(
        inactive
            .activation_report()
            .explanations
            .iter()
            .any(|entry| { entry.status == SemanticModelActivationStatus::ReviewRequired })
    );

    let mut enabled_request = request(vec![rules_evidence]);
    enabled_request
        .controls
        .push(SemanticModelActivationControl {
            scope: SemanticModelControlScope::Workspace,
            action: SemanticModelControlAction::Enable,
            selector: SemanticModelPackSelector {
                pack_id: "acme.builders".to_owned(),
                version: Some(VersionReq::parse("^1.0").unwrap()),
                manifest_digest: None,
            },
        });
    assert_eq!(
        ready(resolve_active_semantic_models(
            &catalog,
            &enabled_request,
            &CancellationToken::default(),
        ))
        .shards()
        .len(),
        1
    );
}

#[test]
fn semantic_hash_ignores_equivalent_source_attribution_and_input_order() {
    let pack = compile(DECLARATIONS_JSON);
    let first_catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    first_catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "first".to_owned(),
            },
        )
        .unwrap();
    let first = ready(resolve_active_semantic_models(
        &first_catalog,
        &request(vec![evidence(), evidence()]),
        &CancellationToken::default(),
    ));

    let second_catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    second_catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "second".to_owned(),
            },
        )
        .unwrap();
    let second = ready(resolve_active_semantic_models(
        &second_catalog,
        &request(vec![evidence()]),
        &CancellationToken::default(),
    ));

    assert_eq!(
        first.active_model_set_hash(),
        second.active_model_set_hash()
    );
}

#[test]
fn cancellation_and_invalid_digest_never_report_ready() {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let cancelled = CancellationToken::default();
    cancelled.cancel();
    assert!(matches!(
        resolve_active_semantic_models(&catalog, &request(vec![evidence()]), &cancelled),
        SemanticModelResolutionOutcome::Cancelled(_)
    ));

    let mut invalid = evidence();
    invalid.artifact_sha256 = Some("NOT-A-DIGEST".to_owned());
    assert!(matches!(
        resolve_active_semantic_models(
            &catalog,
            &request(vec![invalid]),
            &CancellationToken::default(),
        ),
        SemanticModelResolutionOutcome::Unavailable(_)
    ));

    let mut contradictory = request(vec![evidence()]);
    for action in [
        SemanticModelControlAction::Enable,
        SemanticModelControlAction::Disable,
    ] {
        contradictory.controls.push(SemanticModelActivationControl {
            scope: SemanticModelControlScope::Workspace,
            action,
            selector: SemanticModelPackSelector {
                pack_id: "acme.widget".to_owned(),
                version: None,
                manifest_digest: None,
            },
        });
    }
    assert!(matches!(
        resolve_active_semantic_models(&catalog, &contradictory, &CancellationToken::default(),),
        SemanticModelResolutionOutcome::Unavailable(_)
    ));
}

#[test]
fn matcher_owns_exact_postings_after_the_catalog_is_dropped() {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let pack = compile(DECLARATIONS_JSON);
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "declarations".to_owned(),
            },
        )
        .unwrap();
    let active = ready(resolve_active_semantic_models(
        &catalog,
        &request(vec![evidence()]),
        &CancellationToken::default(),
    ));
    drop(catalog);

    let by_name = active.types_named("com.acme.Widget");
    assert_eq!(by_name.disposition, SemanticModelMatchDisposition::Unique);
    assert_eq!(by_name.records[0].id, "type.widget");
    assert_eq!(
        active.types_named("com.acme.LegacyWidget").records[0].id,
        "type.widget"
    );
    assert_eq!(
        active.members_named("type.widget", "create").records[0].id,
        "member.widget.create"
    );
    assert_eq!(
        active
            .members_named("type.other", "create")
            .candidates_examined,
        0
    );
    assert_eq!(
        active.relations_from("member.widget.create").records[0].id,
        "relation.widget.navigation"
    );
    assert_eq!(
        active.relations_to("type.widget").records[0].id,
        "relation.widget.navigation"
    );
    assert!(active.retained_bytes() > 0);
}

#[test]
fn matcher_indexes_every_schema_v1_rule_trigger_without_fallback_scans() {
    let mut source: Value = serde_json::from_slice(RULES_JSON).unwrap();
    let template = source["shards"][0]["payload"]["rules"][0].clone();
    let triggers = [
        json!({"kind": "language_construct", "construct": "record"}),
        json!({"kind": "annotation", "name": "com.acme.GenerateBuilder"}),
        json!({"kind": "macro_invocation", "name": "builder"}),
        json!({"kind": "generator_invocation", "name": "generateBuilder"}),
        json!({"kind": "resolved_owner", "owner": "type.widget"}),
        json!({"kind": "resolved_call", "owner": "type.widget", "name": "create"}),
    ];
    source["shards"][0]["payload"]["rules"] = Value::Array(
        triggers
            .into_iter()
            .enumerate()
            .map(|(index, trigger)| {
                let mut rule = template.clone();
                rule["id"] = Value::String(format!("rule.{index}"));
                rule["trigger"] = trigger;
                rule
            })
            .collect(),
    );
    let bytes = serde_json::to_vec(&source).unwrap();
    let pack = compile(&bytes);
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "rules".to_owned(),
            },
        )
        .unwrap();
    let mut rules_evidence = evidence();
    rules_evidence.package = Some(CatalogCoordinate {
        name: "com.acme:builders".to_owned(),
        version: Some(Version::parse("1.5.0").unwrap()),
    });
    rules_evidence.toolchain = None;
    rules_evidence.target = None;
    rules_evidence.configuration = None;
    let mut activation = request(vec![rules_evidence]);
    activation.controls.push(SemanticModelActivationControl {
        scope: SemanticModelControlScope::Workspace,
        action: SemanticModelControlAction::Enable,
        selector: SemanticModelPackSelector {
            pack_id: "acme.builders".to_owned(),
            version: None,
            manifest_digest: None,
        },
    });
    let active = ready(resolve_active_semantic_models(
        &catalog,
        &activation,
        &CancellationToken::default(),
    ));

    for trigger in [
        RuleTriggerKey::LanguageConstruct("record"),
        RuleTriggerKey::Annotation("com.acme.GenerateBuilder"),
        RuleTriggerKey::MacroInvocation("builder"),
        RuleTriggerKey::GeneratorInvocation("generateBuilder"),
        RuleTriggerKey::ResolvedOwner("type.widget"),
        RuleTriggerKey::ResolvedCall {
            owner: "type.widget",
            name: "create",
        },
    ] {
        let matched = active.rules_for(trigger);
        assert_eq!(matched.disposition, SemanticModelMatchDisposition::Unique);
        assert_eq!(matched.candidates_examined, 1);
        assert_eq!(matched.fallback_candidates_examined, 0);
    }
    assert_eq!(
        active
            .rules_for(RuleTriggerKey::ResolvedCall {
                owner: "type.other",
                name: "create",
            })
            .candidates_examined,
        0
    );
}

#[test]
fn equal_rank_facts_conflict_and_higher_source_rank_shadows_them() {
    let first = compile(DECLARATIONS_JSON);
    let mut changed: Value = serde_json::from_slice(DECLARATIONS_JSON).unwrap();
    changed["pack_id"] = Value::String("acme.widget.alternate".to_owned());
    changed["shards"][0]["payload"]["types"][0]["name"] =
        Value::String("com.acme.AlternateWidget".to_owned());
    let second = compile(&serde_json::to_vec(&changed).unwrap());

    let conflicting_catalog =
        SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    for (pack, source_id) in [(&first, "first"), (&second, "second")] {
        conflicting_catalog
            .register_session_pack(
                pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: source_id.to_owned(),
                },
            )
            .unwrap();
    }
    let conflict = ready(resolve_active_semantic_models(
        &conflicting_catalog,
        &request(vec![evidence()]),
        &CancellationToken::default(),
    ));
    assert_eq!(
        conflict.types_with_id("type.widget").disposition,
        SemanticModelMatchDisposition::Conflict
    );

    let shadowing_catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    shadowing_catalog
        .register_session_pack(
            &first,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "shipped".to_owned(),
            },
        )
        .unwrap();
    shadowing_catalog
        .register_session_pack(
            &second,
            &SessionPackSource {
                kind: SessionPackSourceKind::EphemeralWorkspace,
                source_id: "workspace".to_owned(),
            },
        )
        .unwrap();
    let shadowed = ready(resolve_active_semantic_models(
        &shadowing_catalog,
        &request(vec![evidence()]),
        &CancellationToken::default(),
    ));
    let matched = shadowed.types_with_id("type.widget");
    assert_eq!(matched.disposition, SemanticModelMatchDisposition::Unique);
    assert_eq!(matched.records[0].name, "com.acme.AlternateWidget");
    assert_eq!(matched.candidates_examined, 2);
}

#[test]
fn matcher_budget_failure_is_not_reported_as_ready() {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let pack = compile(DECLARATIONS_JSON);
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "fixture".to_owned(),
            },
        )
        .unwrap();
    let mut bounded = request(vec![evidence()]);
    bounded.limits.max_index_entries = 1;
    assert!(matches!(
        resolve_active_semantic_models(&catalog, &bounded, &CancellationToken::default()),
        SemanticModelResolutionOutcome::Unavailable(_)
    ));
}

#[test]
fn one_analyzer_snapshot_reuses_one_complete_runtime_value() {
    let project = InlineTestProject::with_language(Language::Java)
        .file("src/Main.java", "final class Main {}")
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let pack = compile(DECLARATIONS_JSON);
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "fixture".to_owned(),
            },
        )
        .unwrap();
    let activation = request(vec![evidence()]);
    let store = AnalyzerStore::open_in_memory().unwrap();
    let persistence = SemanticModelActivationPersistence {
        scope_id: "inline-java",
        store: &store,
    };

    let SemanticModelRuntimeOutcome::Ready {
        active: first,
        lifecycle: first_lifecycle,
    } = acquire_active_semantic_models(
        analyzer.analyzer(),
        &catalog,
        Some(persistence),
        &activation,
        &CancellationToken::default(),
    )
    else {
        panic!("first semantic-model runtime acquisition must be ready");
    };
    assert_eq!(first_lifecycle, SemanticModelRuntimeLifecycle::Built);

    let SemanticModelRuntimeOutcome::Ready {
        active: second,
        lifecycle: second_lifecycle,
    } = acquire_active_semantic_models(
        analyzer.analyzer(),
        &catalog,
        Some(persistence),
        &activation,
        &CancellationToken::default(),
    )
    else {
        panic!("second semantic-model runtime acquisition must be ready");
    };
    assert_eq!(second_lifecycle, SemanticModelRuntimeLifecycle::Cached);
    assert!(Arc::ptr_eq(&first, &second));
    let published = store
        .semantic_pack_active_set()
        .unwrap()
        .expect("complete runtime must publish its active catalog references");
    assert_eq!(published.members.len(), 1);
    assert_eq!(published.members[0].source_id, "fixture");
}
