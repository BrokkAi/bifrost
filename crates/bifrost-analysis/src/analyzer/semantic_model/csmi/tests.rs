use super::*;
use crate::CancellationToken;
use crate::analyzer::semantic_model::{
    AuthoredClassDecoratorIdentity, AuthoredConcurrencyEffect, AuthoredNormalReturnTypeRefinement,
    AuthoredPayload, AuthoredProcedureSummary, AuthoredProcedureTarget, AuthoredSemanticModelPack,
    AuthoredShard, AuthoredSummaryEffect, AuthoredSummaryExitKind, AuthoredSummaryInput,
    AuthoredSummaryOutput, AuthoredSummaryTransfer, CatalogCoordinate, CatalogOptions,
    CompilerOptions, Completeness, ConditionalTypeRefinementFact,
    ConditionalTypeRefinementsPayload, DecodeLimits, ImplicitOperation, Locator, MemberKind,
    ProcedureSummaryTargetKey, RuntimeContractAuthorization, RuntimeSourceForm, RuntimeStaticKey,
    SemanticModelActivationEvidence, SemanticModelActivationRequest,
    SemanticModelResolutionOutcome, SemanticPackCatalog, SessionPackSource, SessionPackSourceKind,
    SourceFormat, SummaryValueTransfer, SummaryValueTransferKind, SummaryValueTransferOperation,
    TypeCopySemantics, TypeFact, TypeKind, TypeValueSemantics, Visibility, compile_pack,
    compile_source, decide_runtime_contract_activation, decode_shard,
    resolve_active_semantic_models,
};
use semver::Version;
use serde_json::{Value, json};
use std::path::Path;

const VALID_PROCEDURE_SUMMARY: &[u8] =
    include_bytes!("../../../../../../schemas/csmi/0.1/fixtures/valid/procedure-summary.json");
const VALID_PARTIAL_SUMMARY: &[u8] =
    include_bytes!("../../../../../../schemas/csmi/0.1/fixtures/valid/partial-summary.json");
const VALID_RECEIVER_SUMMARY: &[u8] =
    include_bytes!("../../../../../../schemas/csmi/0.1/fixtures/valid/receiver-summary.json");
const VALID_PACK_MANIFEST: &[u8] =
    include_bytes!("../../../../../../schemas/csmi/0.1/fixtures/valid/pack-manifest.json");
const VALID_JAVASCRIPT_TYPESCRIPT_NODE: &[u8] = include_bytes!(
    "../../../../../../schemas/csmi/0.1/fixtures/valid/javascript-typescript-node.json"
);
const VALID_JAVA_JVM_MAPPING: &[u8] =
    include_bytes!("../../../../../../schemas/csmi/0.1/fixtures/valid/java-jvm-mapping.json");
const VALID_INDETERMINATE_JAVA_JVM_MAPPING: &[u8] = include_bytes!(
    "../../../../../../schemas/csmi/0.1/profiles/java-jvm/0.1/fixtures/valid/mapping-indeterminate-relocation.json"
);
const VALID_CPP_BASIC_STRING_COPY: &[u8] = include_bytes!(
    "../../../../../../schemas/csmi/0.1/profiles/value-transfer/0.1/fixtures/valid/basic-string-copy.json"
);
const VALID_CPP_COPY_CONSTRUCTOR: &[u8] = include_bytes!(
    "../../../../../../schemas/csmi/0.1/profiles/cpp/0.1/fixtures/valid/copy-constructor.json"
);
const VALID_RUNTIME_VALUES: &[u8] = include_bytes!("profiles/runtime-values.fixture.json");
const VALID_RUNTIME_CONTRACTS: &[u8] = include_bytes!("profiles/runtime-values-v2.fixture.json");
const DECLARATIONS_JSON: &[u8] =
    include_bytes!("../../../../testdata/semantic-model-packs/declarations-v1.json");
const GENERATOR_RULES_JSON: &[u8] =
    include_bytes!("../../../../testdata/semantic-model-packs/generator-rules-v1.json");

fn diagnostics_contain(diagnostics: &[CsmiDiagnostic], code: &str) -> bool {
    diagnostics.iter().any(|diagnostic| diagnostic.code == code)
}

#[test]
fn embedded_profile_schemas_match_the_provenanced_assets_byte_for_byte() {
    for (name, embedded, provenanced) in [
        (
            "javascript-typescript",
            include_bytes!("profiles/javascript-typescript.schema.json").as_slice(),
            include_bytes!(
                "../../../../../../schemas/csmi/0.1/profiles/javascript-typescript/0.1/schema.json"
            )
            .as_slice(),
        ),
        (
            "node-compatibility",
            include_bytes!("profiles/node-compatibility.schema.json").as_slice(),
            include_bytes!(
                "../../../../../../schemas/csmi/0.1/profiles/node-compatibility/0.1/schema.json"
            )
            .as_slice(),
        ),
        (
            "python",
            include_bytes!("profiles/python.schema.json").as_slice(),
            include_bytes!("../../../../../../schemas/csmi/0.1/profiles/python/0.1/schema.json")
                .as_slice(),
        ),
        (
            "rust",
            include_bytes!("profiles/rust.schema.json").as_slice(),
            include_bytes!("../../../../../../schemas/csmi/0.1/profiles/rust/0.1/schema.json")
                .as_slice(),
        ),
        (
            "value-transfer",
            include_bytes!("profiles/value-transfer.schema.json").as_slice(),
            include_bytes!(
                "../../../../../../schemas/csmi/0.1/profiles/value-transfer/0.1/schema.json"
            )
            .as_slice(),
        ),
        (
            "cpp",
            include_bytes!("profiles/cpp.schema.json").as_slice(),
            include_bytes!("../../../../../../schemas/csmi/0.1/profiles/cpp/0.1/schema.json")
                .as_slice(),
        ),
        (
            "java-source-identity",
            include_bytes!("profiles/java-source-identity.schema.json").as_slice(),
            include_bytes!("../../../../../../schemas/csmi/0.1/profiles/java-jvm/0.1/java-source-identity.schema.json").as_slice(),
        ),
        (
            "jvm-binary-identity",
            include_bytes!("profiles/jvm-binary-identity.schema.json").as_slice(),
            include_bytes!("../../../../../../schemas/csmi/0.1/profiles/java-jvm/0.1/jvm-binary-identity.schema.json").as_slice(),
        ),
        (
            "java-jvm-mapping",
            include_bytes!("profiles/java-jvm-mapping.schema.json").as_slice(),
            include_bytes!("../../../../../../schemas/csmi/0.1/profiles/java-jvm/0.1/java-jvm-mapping.schema.json").as_slice(),
        ),
        (
            "jvm-compatibility",
            include_bytes!("profiles/jvm-compatibility.schema.json").as_slice(),
            include_bytes!("../../../../../../schemas/csmi/0.1/profiles/java-jvm/0.1/jvm-compatibility.schema.json").as_slice(),
        ),
    ] {
        assert_eq!(embedded, provenanced, "embedded {name} schema drifted");
    }
}

#[test]
fn pinned_profile_fixture_matrix_matches_structural_schemas() {
    let repository_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let profile_directories = [
        (
            include_str!("profiles/value-transfer.schema.json"),
            "schemas/csmi/0.1/profiles/value-transfer/0.1/fixtures",
        ),
        (
            include_str!("profiles/cpp.schema.json"),
            "schemas/csmi/0.1/profiles/cpp/0.1/fixtures",
        ),
    ];

    for (schema, fixture_root) in profile_directories {
        let schema: Value = serde_json::from_str(schema).expect("profile schema is valid JSON");
        let validator =
            jsonschema::draft202012::new(&schema).expect("profile schema is valid Draft 2020-12");
        for group in ["valid", "invalid"] {
            let directory = repository_root.join(fixture_root).join(group);
            for entry in std::fs::read_dir(&directory).expect("fixture directory is readable") {
                let path = entry.expect("fixture entry is readable").path();
                if path.extension().is_none_or(|extension| extension != "json") {
                    continue;
                }
                let value: Value = serde_json::from_str(
                    &std::fs::read_to_string(&path).expect("fixture is readable UTF-8"),
                )
                .expect("fixture is valid JSON");
                if value.get("documentType").is_some() {
                    let validation = validate_csmi_document(
                        &serde_json::to_vec(&value).expect("document serializes"),
                        &CsmiVocabularySupport::new(vec![
                            CsmiSupportedVocabulary {
                                identifier: CSMI_VALUE_TRANSFER_PROFILE_ID.to_owned(),
                                version: CSMI_VALUE_TRANSFER_PROFILE_VERSION.to_owned(),
                                schema: CSMI_VALUE_TRANSFER_PROFILE_SCHEMA.to_owned(),
                            },
                            CsmiSupportedVocabulary {
                                identifier: CSMI_C_CPP_RESOLUTION_PROFILE_ID.to_owned(),
                                version: CSMI_CPP_PROFILE_VERSION.to_owned(),
                                schema: CSMI_CPP_PROFILE_SCHEMA.to_owned(),
                            },
                            CsmiSupportedVocabulary {
                                identifier: CSMI_CPP_PROFILE_ID.to_owned(),
                                version: CSMI_CPP_PROFILE_VERSION.to_owned(),
                                schema: CSMI_CPP_PROFILE_SCHEMA.to_owned(),
                            },
                        ]),
                    );
                    assert_eq!(
                        validation.valid(),
                        group == "valid",
                        "unexpected document outcome for {}: {:?}",
                        path.display(),
                        validation.diagnostics
                    );
                    continue;
                }
                let valid = validator.is_valid(&value);
                assert_eq!(
                    valid,
                    group == "valid",
                    "unexpected outcome for {}",
                    path.display()
                );
            }
        }
    }
}

fn artifact_digest() -> String {
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned()
}

fn runtime_values_profile_support() -> CsmiVocabularySupport {
    CsmiVocabularySupport::support(
        CSMI_RUNTIME_VALUES_PROFILE_ID,
        CSMI_RUNTIME_VALUES_PROFILE_VERSION,
        CSMI_RUNTIME_VALUES_PROFILE_SCHEMA,
    )
}

fn runtime_values_fixture_pack() -> CsmiLogicalPack {
    let semantic_bytes =
        canonical_json_bytes(VALID_RUNTIME_VALUES).expect("runtime-values fixture canonicalizes");
    let path = "models/runtime-values.csmi.json".to_owned();
    let resources = InMemoryCsmiResourceResolver::new([(path.clone(), semantic_bytes.clone())])
        .expect("runtime-values fixture resource path is valid");
    CsmiLogicalPack::new(
        CsmiPackManifest {
            document_type: "pack-manifest".to_owned(),
            schema: CSMI_SCHEMA_URI.to_owned(),
            pack_format_version: CSMI_PACK_FORMAT_VERSION.to_owned(),
            assembler: CsmiProducerIdentity {
                identifier: "https://example.org/tools/csmi-pack".to_owned(),
                version: "1.0.0".to_owned(),
            },
            license: "Apache-2.0".to_owned(),
            created_at: None,
            resources: vec![CsmiResourceDescriptor {
                path,
                role: CsmiResourceRole::SemanticDocument,
                media_type: CSMI_SEMANTIC_DOCUMENT_MEDIA_TYPE.to_owned(),
                size: semantic_bytes.len() as u64,
                digest: CsmiContentDigest {
                    algorithm: CsmiContentDigestAlgorithm::Sha256,
                    value: sha256_hex(&semantic_bytes),
                },
                license: None,
                schema_identifier: None,
                license_reference: None,
            }],
            derived_from: Vec::new(),
        },
        resources,
    )
}

fn runtime_values_fixture_with<F>(mutate: F) -> CsmiLogicalPack
where
    F: FnOnce(&mut Value),
{
    let mut value: Value =
        serde_json::from_slice(VALID_RUNTIME_VALUES).expect("runtime-values fixture is JSON");
    mutate(&mut value);
    let bytes = canonical_json_value(&value).expect("mutated runtime-values fixture canonicalizes");
    let path = "models/runtime-values.csmi.json".to_owned();
    let resources = InMemoryCsmiResourceResolver::new([(path.clone(), bytes.clone())])
        .expect("runtime-values fixture resource path is valid");
    CsmiLogicalPack::new(
        CsmiPackManifest {
            document_type: "pack-manifest".to_owned(),
            schema: CSMI_SCHEMA_URI.to_owned(),
            pack_format_version: CSMI_PACK_FORMAT_VERSION.to_owned(),
            assembler: CsmiProducerIdentity {
                identifier: "https://example.org/tools/csmi-pack".to_owned(),
                version: "1.0.0".to_owned(),
            },
            license: "Apache-2.0".to_owned(),
            created_at: None,
            resources: vec![CsmiResourceDescriptor {
                path,
                role: CsmiResourceRole::SemanticDocument,
                media_type: CSMI_SEMANTIC_DOCUMENT_MEDIA_TYPE.to_owned(),
                size: bytes.len() as u64,
                digest: CsmiContentDigest {
                    algorithm: CsmiContentDigestAlgorithm::Sha256,
                    value: sha256_hex(&bytes),
                },
                license: None,
                schema_identifier: None,
                license_reference: None,
            }],
            derived_from: Vec::new(),
        },
        resources,
    )
}

fn runtime_contract_profile_support() -> CsmiVocabularySupport {
    CsmiVocabularySupport::support(
        CSMI_RUNTIME_VALUES_PROFILE_ID,
        CSMI_RUNTIME_CONTRACTS_PROFILE_VERSION,
        CSMI_RUNTIME_CONTRACTS_PROFILE_SCHEMA,
    )
}

fn runtime_contract_fixture_pack() -> CsmiLogicalPack {
    let semantic_bytes = canonical_json_bytes(VALID_RUNTIME_CONTRACTS)
        .expect("runtime-contract fixture canonicalizes");
    let path = "models/runtime-contracts.csmi.json".to_owned();
    let resources = InMemoryCsmiResourceResolver::new([(path.clone(), semantic_bytes.clone())])
        .expect("runtime-contract fixture resource path is valid");
    CsmiLogicalPack::new(
        CsmiPackManifest {
            document_type: "pack-manifest".to_owned(),
            schema: CSMI_SCHEMA_URI.to_owned(),
            pack_format_version: CSMI_PACK_FORMAT_VERSION.to_owned(),
            assembler: CsmiProducerIdentity {
                identifier: "https://example.org/tools/csmi-pack".to_owned(),
                version: "1.0.0".to_owned(),
            },
            license: "Apache-2.0".to_owned(),
            created_at: None,
            resources: vec![CsmiResourceDescriptor {
                path,
                role: CsmiResourceRole::SemanticDocument,
                media_type: CSMI_SEMANTIC_DOCUMENT_MEDIA_TYPE.to_owned(),
                size: semantic_bytes.len() as u64,
                digest: CsmiContentDigest {
                    algorithm: CsmiContentDigestAlgorithm::Sha256,
                    value: sha256_hex(&semantic_bytes),
                },
                license: None,
                schema_identifier: None,
                license_reference: None,
            }],
            derived_from: Vec::new(),
        },
        resources,
    )
}

#[test]
fn runtime_contracts_fixture_imports_compiles_decodes_exports_and_reimports() {
    let support = runtime_contract_profile_support();
    let fixture = runtime_contract_fixture_pack();
    let semantic_bytes = fixture
        .resources
        .get("models/runtime-contracts.csmi.json")
        .expect("fixture resource exists");
    let validation = validate_csmi_document(semantic_bytes, &support);
    assert!(
        validation.valid(),
        "runtime-contract fixture diagnostics: {:#?}",
        validation.diagnostics
    );
    assert!(validation.interpretable);

    let imported = import_logical_csmi_pack_for_language(
        &fixture,
        &support,
        &CompilerOptions::default(),
        "javascript",
    )
    .expect("runtime-contract fixture imports");
    assert_eq!(imported.pack.language, "javascript");
    assert_eq!(imported.pack.ecosystem, "npm");
    let carrier = imported.pack.shards[0]
        .runtime_contracts
        .as_ref()
        .expect("typed five-family payload is retained");
    carrier
        .validate()
        .expect("typed payload and retained envelope validate together");
    assert_eq!(carrier.payload.contracts.len(), 1);
    assert_eq!(carrier.payload.targets.len(), 1);
    assert_eq!(carrier.payload.activations.len(), 1);
    assert_eq!(carrier.payload.bindings.len(), 1);
    assert_eq!(carrier.payload.observations.len(), 1);
    assert!(carrier.envelope.is_some());

    let activation = &carrier.payload.activations[0];
    let unknown = decide_runtime_contract_activation(
        carrier,
        &activation.activation_id,
        &RuntimeContractAuthorization::default(),
    )
    .expect("activation decision is deterministic");
    assert_eq!(
        unknown.outcome,
        super::super::RuntimeContractActivationOutcome::ReviewRequired
    );
    let policy = &activation.policy;
    let review = &activation.reviews[0];
    let authorized = decide_runtime_contract_activation(
        carrier,
        &activation.activation_id,
        &RuntimeContractAuthorization {
            accepted_policy_digests: vec![
                crate::analyzer::semantic_model::runtime_contract_digest(policy)
                    .expect("policy canonicalizes"),
            ],
            accepted_review_digests: vec![
                crate::analyzer::semantic_model::runtime_contract_digest(review)
                    .expect("review canonicalizes"),
            ],
        },
    )
    .expect("authorized activation decision is deterministic");
    assert_eq!(
        authorized.outcome,
        super::super::RuntimeContractActivationOutcome::Matched
    );
    assert_eq!(authorized.selected_ids, vec!["node-env-portable"]);

    let compiled = imported
        .compile(&CompilerOptions::default())
        .expect("runtime-contract fixture compiles");
    assert_eq!(
        compiled.manifest.schema_version,
        super::super::SEMANTIC_MODEL_SCHEMA_VERSION
    );
    let decoded = decode_shard(
        &compiled.shards[0].descriptor,
        &compiled.shards[0].bytes,
        &DecodeLimits::default(),
    )
    .expect("compiled runtime-contract shard decodes");
    let mut normalized_carrier = carrier.clone();
    super::super::normalize_runtime_contract_payload(&mut normalized_carrier.payload).unwrap();
    super::super::normalize_runtime_contract_envelope(
        normalized_carrier.envelope.as_mut().unwrap(),
    )
    .unwrap();
    assert_eq!(decoded.runtime_contracts(), Some(&normalized_carrier));

    let exported = export_runtime_contracts_csmi_pack(&compiled, &CsmiExportOptions::default())
        .expect("portable runtime-contract fixture exports without artifact evidence");
    let reimported = import_logical_csmi_pack_for_language(
        &exported,
        &support,
        &CompilerOptions::default(),
        "javascript",
    )
    .expect("exported runtime-contract fixture reimports");
    let recompiled = reimported.compile(&CompilerOptions::default()).unwrap();
    let redecoded = decode_shard(
        &recompiled.shards[0].descriptor,
        &recompiled.shards[0].bytes,
        &DecodeLimits::default(),
    )
    .unwrap();
    // The enclosing pack identity includes the assembler and resource path,
    // which may change on export. The portable evidence must stay identical.
    assert_eq!(redecoded.runtime_contracts(), decoded.runtime_contracts());
}

#[test]
fn runtime_contract_compilation_is_invariant_to_fact_and_nested_set_order() {
    let support = runtime_contract_profile_support();
    let imported = import_logical_csmi_pack_for_language(
        &runtime_contract_fixture_pack(),
        &support,
        &CompilerOptions::default(),
        "javascript",
    )
    .expect("runtime-contract fixture imports");
    let baseline = imported
        .compile(&CompilerOptions::default())
        .expect("baseline runtime-contract fixture compiles");

    let mut reordered = imported.pack.clone();
    let carrier = reordered.shards[0]
        .runtime_contracts
        .as_mut()
        .expect("typed runtime-contract payload exists");
    carrier.payload.contracts.reverse();
    carrier.payload.targets.reverse();
    carrier.payload.activations.reverse();
    carrier.payload.bindings.reverse();
    carrier.payload.observations.reverse();
    carrier.payload.contracts[0].definition.languages.reverse();
    carrier.payload.contracts[0]
        .definition
        .assumptions
        .reverse();
    carrier.payload.contracts[0]
        .definition
        .context
        .platform
        .reverse();
    carrier.payload.activations[0].candidate_ids.reverse();
    carrier.payload.activations[0].reviews.reverse();
    carrier
        .envelope
        .as_mut()
        .expect("retained runtime-contract envelope exists")["semanticModels"][0]["extensionFacts"]
        .as_array_mut()
        .expect("extension facts are an array")
        .reverse();
    let reordered = compile_pack(&reordered, &CompilerOptions::default())
        .expect("reordered runtime-contract fixture compiles");
    assert_eq!(
        baseline.shards[0].descriptor.semantic_sha256,
        reordered.shards[0].descriptor.semantic_sha256,
        "fact and schema-declared set order does not alter the compiled semantic digest"
    );
}

#[test]
fn runtime_values_fixture_validates_imports_and_retains_all_four_families() {
    let support = runtime_values_profile_support();
    let bytes = canonical_json_bytes(VALID_RUNTIME_VALUES).expect("fixture canonicalizes");
    let validation = validate_csmi_document(&bytes, &support);
    assert!(
        validation.valid(),
        "runtime-values fixture diagnostics: {:#?}",
        validation.diagnostics
    );
    assert!(validation.interpretable);
    assert_eq!(validation.profiles.len(), 1);
    assert!(validation.profiles[0].semantically_supported);

    let imported = import_logical_csmi_pack_for_language(
        &runtime_values_fixture_pack(),
        &support,
        &CompilerOptions::default(),
        "javascript",
    )
    .expect("runtime-values fixture imports");
    let runtime = imported.pack.shards[0]
        .runtime_values
        .as_ref()
        .expect("runtime-values payload is retained on the declaration shard");
    assert_eq!(runtime.exposures.len(), 1);
    assert_eq!(runtime.behaviors.len(), 1);
    assert_eq!(runtime.binding_evidence.len(), 1);
    assert_eq!(runtime.observations.len(), 1);
    assert_eq!(
        runtime.exposures[0].provenance,
        vec!["runtime-values-fixture".to_owned()]
    );
    assert_eq!(runtime.observations[0].source_form, RuntimeSourceForm::Dot);
    assert_eq!(
        runtime.observations[0].key,
        RuntimeStaticKey::Property {
            value: "DFB_INPUT".to_owned()
        }
    );

    let compiled = imported
        .compile(&CompilerOptions::default())
        .expect("imported runtime-values fixture compiles");
    let decoded = decode_shard(
        &compiled.shards[0].descriptor,
        &compiled.shards[0].bytes,
        &DecodeLimits::default(),
    )
    .expect("compiled runtime-values shard decodes");
    assert_eq!(decoded.runtime_values(), Some(runtime));

    let artifact = CsmiArtifactEvidence::new(
        "pkg:generic/nodejs.org/node@22.11.0",
        "1111111111111111111111111111111111111111111111111111111111111111",
    )
    .with_coverage("official-distribution-archive");
    let exported = export_csmi_pack(&compiled, &artifact, &CsmiExportOptions::default())
        .expect("runtime-values fixture exports");
    let reimported = import_logical_csmi_pack_for_language(
        &exported,
        &support,
        &CompilerOptions::default(),
        "javascript",
    )
    .expect("exported runtime-values fixture reimports");
    assert_eq!(
        reimported.pack.shards[0].runtime_values, imported.pack.shards[0].runtime_values,
        "all four runtime-values families survive export/import"
    );
}

#[test]
fn runtime_values_import_selects_an_explicit_supported_language() {
    let support = runtime_values_profile_support();
    let error = import_logical_csmi_pack(
        &runtime_values_fixture_pack(),
        &support,
        &CompilerOptions::default(),
    )
    .expect_err("multi-language runtime imports require an explicit target");
    assert!(matches!(
        error,
        CsmiImportError::Unsupported { path, .. } if path == "runtime-global-exposure.languages"
    ));

    for (requested, expected_pack_language) in [
        ("javascript", "javascript"),
        ("typescript", "typescript"),
        ("tsx", "typescript"),
    ] {
        let imported = import_logical_csmi_pack_for_language(
            &runtime_values_fixture_pack(),
            &support,
            &CompilerOptions::default(),
            requested,
        )
        .expect("explicit runtime language is accepted");
        assert_eq!(imported.pack.language, expected_pack_language);
        let runtime = imported.pack.shards[0]
            .runtime_values
            .as_ref()
            .expect("runtime payload remains attached to the imported shard");
        assert_eq!(
            runtime.exposures[0].languages,
            vec![
                "javascript".to_owned(),
                "typescript".to_owned(),
                "tsx".to_owned()
            ]
        );
    }

    let error = import_logical_csmi_pack_for_language(
        &runtime_values_fixture_pack(),
        &support,
        &CompilerOptions::default(),
        "python",
    )
    .expect_err("a target language outside the exposure must be rejected");
    assert!(matches!(
        error,
        CsmiImportError::Unsupported { path, .. } if path == "import.target_language"
    ));
}

#[test]
fn runtime_values_import_rejects_dangling_and_mismatched_semantics() {
    let support = runtime_values_profile_support();
    type RuntimeFixtureMutation = (&'static str, Box<dyn Fn(&mut Value)>);
    let cases: [RuntimeFixtureMutation; 4] = [
        (
            "dangling behavior reference",
            Box::new(|value| {
                value["semanticModels"][0]["extensionFacts"][3]["payload"]["behaviorId"] =
                    json!("missing-behavior");
            }),
        ),
        (
            "owner digest mismatch",
            Box::new(|value| {
                value["semanticModels"][0]["extensionFacts"][3]["payload"]["baseValue"]["ownerDigest"] =
                    json!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            }),
        ),
        (
            "activation profile mismatch",
            Box::new(|value| {
                value["semanticModels"][0]["extensionFacts"][2]["payload"]["activation"]["runtimeProfileDigest"] =
                    json!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            }),
        ),
        (
            "exact observation before effects",
            Box::new(|value| {
                value["semanticModels"][0]["extensionFacts"][3]["payload"]["phase"] =
                    json!("before-effects");
            }),
        ),
    ];
    for (name, mutate) in cases {
        let pack = runtime_values_fixture_with(mutate);
        let error =
            import_logical_csmi_pack(&pack, &support, &CompilerOptions::default()).expect_err(name);
        assert!(
            matches!(error, CsmiImportError::InvalidPack(_)),
            "{name} returned the wrong error: {error:?}"
        );
    }
}

#[test]
fn canonical_json_uses_rfc_8785_number_and_key_encoding() {
    let value = json!({
        "numbers": [333_333_333.333_333_3_f64, 1e30_f64, 4.50_f64, 2e-3_f64, 1e-27_f64],
        "\r": "Carriage Return",
        "1": "One",
        "\u{0080}": "Control",
        "ö": "Latin Small Letter O With Diaeresis",
        "€": "Euro Sign",
        "😀": "Emoji: Grinning Face"
    });
    let canonical = String::from_utf8(canonical_json_value(&value).unwrap()).unwrap();
    assert_eq!(
        canonical,
        "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"\u{0080}\":\"Control\",\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",\"😀\":\"Emoji: Grinning Face\"}"
    );
}

#[test]
fn canonical_set_duplicates_normalize_like_reordered_sets() {
    let with_duplicates = json!({
        "symbols": [{"id": "type.a"}, {"id": "type.a"}, {"id": "type.b"}]
    });
    let without_duplicates = json!({
        "symbols": [{"id": "type.b"}, {"id": "type.a"}]
    });
    assert_eq!(
        canonical_json_value(&with_duplicates).unwrap(),
        canonical_json_value(&without_duplicates).unwrap()
    );
}

#[test]
fn supported_upstream_fixtures_are_classified_as_valid() {
    for (name, bytes) in [
        ("procedure-summary", VALID_PROCEDURE_SUMMARY),
        ("partial-summary", VALID_PARTIAL_SUMMARY),
        ("receiver-summary", VALID_RECEIVER_SUMMARY),
        ("pack-manifest", VALID_PACK_MANIFEST),
    ] {
        let canonical = canonical_json_bytes(bytes).expect("fixture canonicalizes");
        let result = validate_csmi_document(&canonical, &CsmiVocabularySupport::empty());
        assert!(
            result.structural_valid,
            "{name} diagnostics: {:#?}",
            result.diagnostics
        );
        assert!(
            result.semantic_valid,
            "{name} diagnostics: {:#?}",
            result.diagnostics
        );
        assert!(
            result.valid(),
            "{name} diagnostics: {:#?}",
            result.diagnostics
        );
    }
}

#[test]
fn upstream_invalid_fixtures_fail_at_the_expected_boundary() {
    let structural = [
        (
            "unknown-root-property",
            include_bytes!(
                "../../../../../../schemas/csmi/0.1/fixtures/invalid/unknown-root-property.json"
            )
            .as_slice(),
        ),
        (
            "unknown-core-field",
            include_bytes!(
                "../../../../../../schemas/csmi/0.1/fixtures/invalid/unknown-core-field.json"
            )
            .as_slice(),
        ),
        (
            "unknown-type-variant",
            include_bytes!(
                "../../../../../../schemas/csmi/0.1/fixtures/invalid/unknown-type-variant.json"
            )
            .as_slice(),
        ),
        (
            "invalid-resource-digest",
            include_bytes!(
                "../../../../../../schemas/csmi/0.1/fixtures/invalid/invalid-resource-digest.json"
            )
            .as_slice(),
        ),
        (
            "nul-resource-path",
            include_bytes!(
                "../../../../../../schemas/csmi/0.1/fixtures/invalid/nul-resource-path.json"
            )
            .as_slice(),
        ),
        (
            "unsafe-resource-path",
            include_bytes!(
                "../../../../../../schemas/csmi/0.1/fixtures/invalid/unsafe-resource-path.json"
            )
            .as_slice(),
        ),
        (
            "trailing-resource-path",
            include_bytes!(
                "../../../../../../schemas/csmi/0.1/fixtures/invalid/trailing-resource-path.json"
            )
            .as_slice(),
        ),
        (
            "indexed-receiver-root",
            include_bytes!(
                "../../../../../../schemas/csmi/0.1/fixtures/invalid/indexed-receiver-root.json"
            )
            .as_slice(),
        ),
        (
            "invalid-boundary-root",
            include_bytes!(
                "../../../../../../schemas/csmi/0.1/fixtures/invalid/invalid-boundary-root.json"
            )
            .as_slice(),
        ),
    ];
    for (name, bytes) in structural {
        let result = parse_csmi_document(bytes);
        assert!(
            !result.structural_valid,
            "{name} unexpectedly parsed: {:#?}",
            result
        );
    }

    let remaining_invalid = [
        (
            "exact-purl-with-version-range",
            include_bytes!("../../../../../../schemas/csmi/0.1/fixtures/invalid/exact-purl-with-version-range.json")
                .as_slice(),
        ),
        (
            "named-parameter-without-label",
            include_bytes!("../../../../../../schemas/csmi/0.1/fixtures/invalid/named-parameter-without-label.json")
                .as_slice(),
        ),
        (
            "partial-without-limitation",
            include_bytes!("../../../../../../schemas/csmi/0.1/fixtures/invalid/partial-without-limitation.json")
                .as_slice(),
        ),
        (
            "purl-with-subpath",
            include_bytes!("../../../../../../schemas/csmi/0.1/fixtures/invalid/purl-with-subpath.json")
                .as_slice(),
        ),
        (
            "versionless-purl-without-range",
            include_bytes!("../../../../../../schemas/csmi/0.1/fixtures/invalid/versionless-purl-without-range.json")
                .as_slice(),
        ),
    ];
    for (name, bytes) in remaining_invalid {
        let result = validate_csmi_document(bytes, &CsmiVocabularySupport::empty());
        assert!(!result.valid(), "{name} unexpectedly valid");
    }
}

#[test]
fn upstream_semantic_invalid_fixtures_remain_structurally_readable_but_invalid() {
    let fixtures = [
        include_bytes!("../../../../../../schemas/csmi/0.1/fixtures/semantic-invalid/duplicate-completeness-scope.json").as_slice(),
        include_bytes!("../../../../../../schemas/csmi/0.1/fixtures/semantic-invalid/missing-declaration-dependency.json").as_slice(),
        include_bytes!("../../../../../../schemas/csmi/0.1/fixtures/semantic-invalid/missing-provenance.json").as_slice(),
        include_bytes!("../../../../../../schemas/csmi/0.1/fixtures/semantic-invalid/noncontiguous-parameters.json").as_slice(),
        include_bytes!("../../../../../../schemas/csmi/0.1/fixtures/semantic-invalid/undeclared-vocabulary.json").as_slice(),
        include_bytes!("../../../../../../schemas/csmi/0.1/fixtures/semantic-invalid/unresolved-symbol.json").as_slice(),
    ];
    for bytes in fixtures {
        let canonical = canonical_json_bytes(bytes).expect("fixture canonicalizes");
        let result = validate_csmi_document(&canonical, &CsmiVocabularySupport::empty());
        assert!(
            result.structural_valid,
            "structural diagnostics: {:#?}",
            result.diagnostics
        );
        assert!(
            !result.semantic_valid,
            "unexpectedly valid: {:#?}",
            result.diagnostics
        );
    }
}

fn logical_fixture_pack() -> CsmiLogicalPack {
    let semantic_bytes = canonical_json_bytes(VALID_PROCEDURE_SUMMARY)
        .expect("procedure summary fixture canonicalizes");
    let path = "models/normalize.csmi.json".to_owned();
    let resources = InMemoryCsmiResourceResolver::new([(path.clone(), semantic_bytes.clone())])
        .expect("fixture resource path is valid");
    let manifest = CsmiPackManifest {
        document_type: "pack-manifest".to_owned(),
        schema: CSMI_SCHEMA_URI.to_owned(),
        pack_format_version: CSMI_PACK_FORMAT_VERSION.to_owned(),
        assembler: CsmiProducerIdentity {
            identifier: "https://example.org/tools/csmi-pack".to_owned(),
            version: "1.0.0".to_owned(),
        },
        license: "Apache-2.0".to_owned(),
        created_at: None,
        resources: vec![CsmiResourceDescriptor {
            path,
            role: CsmiResourceRole::SemanticDocument,
            media_type: CSMI_SEMANTIC_DOCUMENT_MEDIA_TYPE.to_owned(),
            size: semantic_bytes.len() as u64,
            digest: CsmiContentDigest {
                algorithm: CsmiContentDigestAlgorithm::Sha256,
                value: sha256_hex(&semantic_bytes),
            },
            license: None,
            schema_identifier: None,
            license_reference: None,
        }],
        derived_from: Vec::new(),
    };
    CsmiLogicalPack::new(manifest, resources)
}

pub(crate) fn logical_pack_from_semantic(bytes: &[u8]) -> CsmiLogicalPack {
    let semantic_bytes = canonical_json_bytes(bytes).expect("semantic fixture canonicalizes");
    let path = "models/profile.csmi.json".to_owned();
    let resources = InMemoryCsmiResourceResolver::new([(path.clone(), semantic_bytes.clone())])
        .expect("fixture resource path is valid");
    CsmiLogicalPack::new(
        CsmiPackManifest {
            document_type: "pack-manifest".to_owned(),
            schema: CSMI_SCHEMA_URI.to_owned(),
            pack_format_version: CSMI_PACK_FORMAT_VERSION.to_owned(),
            assembler: CsmiProducerIdentity {
                identifier: "https://example.org/tools/csmi-pack".to_owned(),
                version: "1.0.0".to_owned(),
            },
            license: "Apache-2.0".to_owned(),
            created_at: None,
            resources: vec![CsmiResourceDescriptor {
                path,
                role: CsmiResourceRole::SemanticDocument,
                media_type: CSMI_SEMANTIC_DOCUMENT_MEDIA_TYPE.to_owned(),
                size: semantic_bytes.len() as u64,
                digest: CsmiContentDigest {
                    algorithm: CsmiContentDigestAlgorithm::Sha256,
                    value: sha256_hex(&semantic_bytes),
                },
                license: None,
                schema_identifier: None,
                license_reference: None,
            }],
            derived_from: Vec::new(),
        },
        resources,
    )
}

fn cpp_profile_support() -> CsmiVocabularySupport {
    CsmiVocabularySupport::new(vec![
        CsmiSupportedVocabulary {
            identifier: CSMI_VALUE_TRANSFER_PROFILE_ID.to_owned(),
            version: CSMI_VALUE_TRANSFER_PROFILE_VERSION.to_owned(),
            schema: CSMI_VALUE_TRANSFER_PROFILE_SCHEMA.to_owned(),
        },
        CsmiSupportedVocabulary {
            identifier: CSMI_C_CPP_RESOLUTION_PROFILE_ID.to_owned(),
            version: CSMI_C_CPP_RESOLUTION_PROFILE_VERSION.to_owned(),
            schema: CSMI_CPP_PROFILE_SCHEMA.to_owned(),
        },
        CsmiSupportedVocabulary {
            identifier: CSMI_CPP_PROFILE_ID.to_owned(),
            version: CSMI_CPP_PROFILE_VERSION.to_owned(),
            schema: CSMI_CPP_PROFILE_SCHEMA.to_owned(),
        },
    ])
}

fn cpp_fixture_with_special_member() -> Value {
    let mut fixture: Value =
        serde_json::from_slice(VALID_CPP_BASIC_STRING_COPY).expect("C++ fixture is JSON");
    fixture["semanticModels"][0]["completenessStatements"]
        .as_array_mut()
        .expect("completeness statements are an array")
        .push(json!({
            "family": "declaration-records",
            "scope": {
                "scheme": CSMI_CPP_DECLARATION_IDENTITY_SCHEME,
                "schemeVersion": CSMI_CPP_DECLARATION_IDENTITY_SCHEME_VERSION
            },
            "status": "complete"
        }));
    let mut special: Value =
        serde_json::from_slice(VALID_CPP_COPY_CONSTRUCTOR).expect("special-member fixture is JSON");
    special["owner"] = json!("basicString");
    special["member"] = json!("copyConstructor");
    fixture["semanticModels"][0]["extensionFacts"]
        .as_array_mut()
        .expect("extension facts are an array")
        .push(json!({
            "vocabulary": CSMI_CPP_PROFILE_ID,
            "version": CSMI_CPP_PROFILE_VERSION,
            "family": "special-member",
            "scope": {
                "owner": "basicString",
                "operation": "copy-constructor"
            },
            "payload": special
        }));
    fixture["semanticModels"][0]["vocabularyUses"][2]["affects"]
        .as_array_mut()
        .expect("C++ affects are an array")
        .push(json!({
            "kind": "fact-family",
            "family": "special-member",
            "scope": {
                "owner": "basicString",
                "operation": "copy-constructor"
            }
        }));
    fixture
}

fn semantic_resource_index(pack: &CsmiLogicalPack) -> usize {
    pack.manifest
        .resources
        .iter()
        .position(|resource| resource.role == CsmiResourceRole::SemanticDocument)
        .expect("logical pack has a semantic document resource")
}

fn semantic_value(pack: &CsmiLogicalPack) -> Value {
    let resource = &pack.manifest.resources[semantic_resource_index(pack)];
    serde_json::from_slice(
        &pack
            .resource_bytes(resource)
            .expect("semantic resource verifies"),
    )
    .expect("semantic resource is JSON")
}

fn pack_with_semantic_bytes(pack: &CsmiLogicalPack, semantic_bytes: Vec<u8>) -> CsmiLogicalPack {
    let semantic_index = semantic_resource_index(pack);
    let original_resources = pack.manifest.resources.clone();
    let mut manifest = pack.manifest.clone();
    let mut resource_bytes = Vec::with_capacity(original_resources.len());
    for (index, resource) in original_resources.iter().enumerate() {
        let bytes = if index == semantic_index {
            semantic_bytes.clone()
        } else {
            pack.resource_bytes(resource)
                .expect("logical pack resource verifies")
        };
        if index == semantic_index {
            manifest.resources[index].size = bytes.len() as u64;
            manifest.resources[index].digest.value = sha256_hex(&bytes);
        }
        resource_bytes.push((resource.path.clone(), bytes));
    }
    let resources = InMemoryCsmiResourceResolver::new(resource_bytes)
        .expect("mutated semantic resource paths remain valid");
    CsmiLogicalPack::new(manifest, resources)
}

fn pack_with_semantic_value<F>(pack: &CsmiLogicalPack, mutate: F) -> CsmiLogicalPack
where
    F: FnOnce(&mut Value),
{
    let mut value = semantic_value(pack);
    mutate(&mut value);
    let bytes = canonical_json_value(&value).expect("mutated semantic value canonicalizes");
    pack_with_semantic_bytes(pack, bytes)
}

fn pack_with_second_semantic_resource(pack: &CsmiLogicalPack) -> CsmiLogicalPack {
    let semantic_index = semantic_resource_index(pack);
    let source = &pack.manifest.resources[semantic_index];
    let bytes = pack
        .resource_bytes(source)
        .expect("semantic resource verifies");
    let mut manifest = pack.manifest.clone();
    let mut duplicate = source.clone();
    duplicate.path.push_str(".second");
    manifest.resources.push(duplicate);
    let mut resources = pack
        .manifest
        .resources
        .iter()
        .map(|resource| {
            (
                resource.path.clone(),
                pack.resource_bytes(resource)
                    .expect("logical pack resource verifies"),
            )
        })
        .collect::<Vec<_>>();
    resources.push((manifest.resources.last().unwrap().path.clone(), bytes));
    let resources = InMemoryCsmiResourceResolver::new(resources)
        .expect("second semantic resource path is valid");
    CsmiLogicalPack::new(manifest, resources)
}

fn first_callable_mut(value: &mut Value) -> &mut Value {
    value["semanticModels"][0]["declarations"]
        .as_array_mut()
        .expect("semantic model declarations are an array")
        .iter_mut()
        .find(|declaration| declaration["category"] == "callable")
        .expect("semantic model has a callable declaration")
}

fn import_error_after_mutation<F>(pack: &CsmiLogicalPack, mutate: F) -> CsmiImportError
where
    F: FnOnce(&mut Value),
{
    let mutated = pack_with_semantic_value(pack, mutate);
    import_logical_csmi_pack(
        &mutated,
        &CsmiVocabularySupport::empty(),
        &CompilerOptions::default(),
    )
    .expect_err("mutated CSMI pack must be rejected")
}

#[test]
fn canonical_logical_pack_verifies_resources_and_detects_digest_tampering() {
    let pack = logical_fixture_pack();
    let manifest_bytes = pack
        .canonical_manifest_bytes()
        .expect("manifest canonicalizes");
    let expected_pack_digest = sha256_hex(&manifest_bytes);
    assert_eq!(
        pack.pack_digest().expect("pack digest computes"),
        expected_pack_digest
    );
    assert_eq!(pack.verify_resources(), Ok(()));
    let validation = validate_csmi_pack(
        &manifest_bytes,
        &pack.resources,
        &CsmiVocabularySupport::empty(),
    );
    assert!(
        validation.valid(),
        "validation diagnostics: {:#?}",
        validation.diagnostics
    );

    let semantic_resource = &pack.manifest.resources[semantic_resource_index(&pack)];
    let mut tampered_bytes = pack
        .resource_bytes(semantic_resource)
        .expect("semantic resource verifies");
    tampered_bytes[0] = b'[';
    let tampered_resources =
        InMemoryCsmiResourceResolver::new([("models/normalize.csmi.json", tampered_bytes)])
            .expect("fixture resource path is valid");
    let tampered_validation = validate_csmi_pack(
        &manifest_bytes,
        &tampered_resources,
        &CsmiVocabularySupport::empty(),
    );
    assert!(!tampered_validation.integrity_valid);
    assert!(
        diagnostics_contain(
            &tampered_validation.diagnostics,
            "integrity.resource_digest"
        ) || diagnostics_contain(&tampered_validation.diagnostics, "integrity.resource_size"),
        "diagnostics: {:#?}",
        tampered_validation.diagnostics
    );
}

#[test]
fn canonical_pack_manifest_and_resources_reject_noncanonical_bytes() {
    let pack = exported_import_fixture();
    let canonical = pack
        .canonical_manifest_bytes()
        .expect("manifest canonicalizes");
    let noncanonical = serde_json::to_vec(&pack.manifest).expect("manifest serializes");
    assert_ne!(noncanonical, canonical);
    let manifest_validation =
        validate_csmi_document(&noncanonical, &CsmiVocabularySupport::empty());
    assert!(!manifest_validation.structural_valid);
    assert!(diagnostics_contain(
        &manifest_validation.diagnostics,
        "structural.non_canonical_json"
    ));

    let semantic = semantic_value(&pack);
    let pretty = serde_json::to_vec_pretty(&semantic).expect("semantic resource serializes");
    let noncanonical_pack = pack_with_semantic_bytes(&pack, pretty);
    let result = validate_csmi_pack(
        &noncanonical_pack.canonical_manifest_bytes().unwrap(),
        &noncanonical_pack.resources,
        &CsmiVocabularySupport::empty(),
    );
    assert!(!result.integrity_valid);
    assert!(diagnostics_contain(
        &result.diagnostics,
        "integrity.resource_non_canonical_json"
    ));
}

#[test]
fn importer_rejects_multiple_semantic_documents_and_models() {
    let pack = logical_fixture_pack();
    let second_document = pack_with_second_semantic_resource(&pack);
    let error = import_logical_csmi_pack(
        &second_document,
        &CsmiVocabularySupport::empty(),
        &CompilerOptions::default(),
    )
    .expect_err("multiple semantic documents must be rejected");
    assert!(matches!(error, CsmiImportError::Unsupported { path, .. } if path == "resources"));

    let error = import_error_after_mutation(&pack, |value| {
        let mut model = value["semanticModels"][0].clone();
        model["artifactSelectors"][0]["purl"] = json!("pkg:maven/org.example/normalize@1.4.3");
        value["semanticModels"]
            .as_array_mut()
            .expect("semanticModels is an array")
            .push(model);
    });
    assert!(matches!(error, CsmiImportError::Unsupported { path, .. } if path == "semanticModels"));
}

#[test]
fn importer_rejects_ambiguous_maven_digests() {
    let pack = exported_import_fixture();
    let error = import_error_after_mutation(&pack, |value| {
        let selectors = value["semanticModels"][0]["artifactSelectors"]
            .as_array_mut()
            .expect("artifactSelectors is an array");
        selectors[0]["digests"]
            .as_array_mut()
            .expect("digests is an array")
            .push(json!({
                "algorithm": "sha-384",
                "coverage": "artifact",
                "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }));
    });
    assert!(
        matches!(error, CsmiImportError::Selector(message) if message.contains("exactly one sha-256"))
    );
}

#[test]
fn importer_rejects_unresolved_unknown_intrinsic_and_multi_result_shapes() {
    let pack = exported_import_fixture();
    let unresolved = import_error_after_mutation(&pack, |value| {
        let callable_symbol = value["semanticModels"][0]["declarations"]
            .as_array()
            .expect("declarations is an array")
            .iter()
            .find(|declaration| declaration["category"] == "callable")
            .expect("semantic model has a callable declaration")["symbol"]
            .clone();
        {
            let symbols = value["semanticModels"][0]["symbols"]
                .as_array_mut()
                .expect("symbols is an array");
            let callable = symbols
                .iter_mut()
                .find(|symbol| symbol["id"] == callable_symbol)
                .expect("callable symbol exists");
            callable["descriptors"] = json!([{
                "role": "callable",
                "name": "create"
            }]);
        }
        let callable = first_callable_mut(value);
        callable["callable"]["parameters"][0]["type"]["symbol"] = callable_symbol;
    });
    assert!(
        matches!(&unresolved, CsmiImportError::Identity(message) if message.contains("unresolved type symbol") && message.contains("declarations.callable.parameters[0].type")),
        "unexpected unresolved-symbol error: {unresolved:?}"
    );

    let unknown = import_error_after_mutation(&pack, |value| {
        let callable = first_callable_mut(value);
        callable["callable"]["parameters"][0]["type"] = json!({"kind": "unknown"});
    });
    assert!(
        matches!(unknown, CsmiImportError::Unsupported { semantic, .. } if semantic.contains("unknown type"))
    );

    let intrinsic = import_error_after_mutation(&pack, |value| {
        let callable = first_callable_mut(value);
        callable["callable"]["parameters"][0]["type"] = json!({
            "kind": "intrinsic",
            "vocabulary": "https://example.org/vocabulary",
            "version": "1.0",
            "identifier": "string",
            "scheme": "jvm",
            "schemeVersion": "1",
            "steps": []
        });
    });
    assert!(matches!(
        intrinsic,
        CsmiImportError::Unsupported { .. }
            | CsmiImportError::InvalidPack(_)
            | CsmiImportError::Uninterpretable(_)
    ));

    let multiple_results = import_error_after_mutation(&pack, |value| {
        let callable = first_callable_mut(value);
        let result = callable["callable"]["results"][0].clone();
        let mut second_result = result;
        second_result["position"] = json!(1);
        callable["callable"]["results"]
            .as_array_mut()
            .expect("results is an array")
            .push(second_result);
    });
    assert!(
        matches!(multiple_results, CsmiImportError::Unsupported { semantic, .. } if semantic.contains("multiple result"))
    );

    let missing_parameter_type = import_error_after_mutation(&pack, |value| {
        first_callable_mut(value)["callable"]["parameters"][0]
            .as_object_mut()
            .expect("parameter is an object")
            .remove("type");
    });
    assert!(
        matches!(missing_parameter_type, CsmiImportError::Unsupported { semantic, .. } if semantic.contains("missing its type"))
    );

    let unsupported_kind = import_error_after_mutation(&pack, |value| {
        first_callable_mut(value)["callable"]["kind"] = json!("operator");
    });
    assert!(
        matches!(unsupported_kind, CsmiImportError::Unsupported { semantic, .. } if semantic.contains("callable kind"))
    );
}

fn authored_exact_pack() -> AuthoredSemanticModelPack {
    let mut pack: AuthoredSemanticModelPack =
        serde_json::from_slice(DECLARATIONS_JSON).expect("declaration fixture is valid");
    let AuthoredPayload::DeclarationFacts {
        types,
        members: _,
        relations,
    } = &mut pack.shards[0].payload
    else {
        panic!("declaration fixture has no declaration facts");
    };
    relations.clear();
    types.push(TypeFact {
        ambient_use: None,
        id: "type.java.lang.string".to_owned(),
        name: "java.lang.String".to_owned(),
        type_kind: TypeKind::Class,
        visibility: Visibility::Public,
        is_abstract: false,
        is_sealed: false,
        callable_surface_complete: false,
        has_explicit_type_terms: false,
        type_parameters: Vec::new(),
        type_parameter_constraints: Vec::new(),
        underlying_type: None,
        value_semantics: None,
        embedded_types: Vec::new(),
        hierarchy: Vec::new(),
        aliases: Vec::new(),
        extension_surfaces: Vec::new(),
        guard: None,
        locator: Locator::Artifact {
            path: "java/lang/String.class".to_owned(),
            symbol: "java.lang.String".to_owned(),
        },
    });
    let activation = pack.shards[0].activation.clone();
    pack.shards.push(AuthoredShard {
        id: "summaries.widget".to_owned(),
        activation,
        payload: AuthoredPayload::ProcedureSummaries {
            summaries: vec![AuthoredProcedureSummary {
                id: "summary.widget.create".to_owned(),
                target: AuthoredProcedureTarget {
                    path: "com.acme.Widget".to_owned(),
                    symbol: "create".to_owned(),
                    has_receiver: false,
                    variadic: false,
                    parameter_count: 1,
                },
                completeness: Completeness::Complete,
                ordinary_heap_unchanged: false,
                no_concurrency_effects: false,
                covers_overrides: false,
                normal_continuation_absent: false,
                normal_result_count: None,
                locations: Vec::new(),
                transfers: vec![AuthoredSummaryTransfer {
                    input: AuthoredSummaryInput::Parameter { ordinal: 0 },
                    exit_kind: AuthoredSummaryExitKind::Normal,
                    output: AuthoredSummaryOutput::NormalReturn {},
                    value_transfer: None,
                }],
                transfer_partitions: Vec::new(),
                effects: Vec::new(),
                concurrency_effects: Vec::new(),
                declared_effects: Vec::new(),
                preconditions: None,
                result_contracts: Vec::new(),
                result_use_obligations: Vec::new(),
                conditional_result_refinements: Vec::new(),
                conditional_indirect_writes: Vec::new(),
                normal_return_refinements: Vec::new(),
                normal_return_type_refinements: Vec::new(),
                class_decorator_identity: None,
            }],
        },
        runtime_values: None,
        runtime_contracts: None,
        collection_flows: None,
        deferred_yields: None,
        conditional_type_refinements: None,
    });
    pack
}

fn exported_import_fixture() -> CsmiLogicalPack {
    let authored = authored_exact_pack();
    let compiled = compile_pack(&authored, &CompilerOptions::default())
        .expect("exact declaration and summary fixture compiles");
    let artifact = CsmiArtifactEvidence::new("pkg:maven/com.acme/widget@1.2.0", artifact_digest());
    export_csmi_pack(&compiled, &artifact, &CsmiExportOptions::default())
        .expect("exact authored fixture exports")
}

#[test]
fn authored_declarations_and_summary_round_trip_through_csmi() {
    let authored = authored_exact_pack();
    let compiled = compile_pack(&authored, &CompilerOptions::default())
        .expect("exact declaration and summary fixture compiles");
    assert_eq!(compiled.shards.len(), 2);
    let artifact = CsmiArtifactEvidence::new("pkg:maven/com.acme/widget@1.2.0", artifact_digest());
    let options = CsmiExportOptions::default();
    let exported = export_csmi_pack(&compiled, &artifact, &options).expect("export succeeds");
    assert_eq!(exported.verify_resources(), Ok(()));
    let manifest_bytes = exported
        .canonical_manifest_bytes()
        .expect("exported manifest canonicalizes");
    let validation = validate_csmi_pack(
        &manifest_bytes,
        &exported.resources,
        &CsmiVocabularySupport::empty(),
    );
    assert!(
        validation.valid(),
        "export diagnostics: {:#?}",
        validation.diagnostics
    );
    assert_eq!(validation.semantic_documents.len(), 1);
    let model = &validation.semantic_documents[0].semantic_models[0];
    assert_eq!(model.declarations.len(), 3);
    assert_eq!(model.procedure_summaries.len(), 1);
    assert_eq!(model.procedure_summaries[0].transfers.len(), 1);

    let imported = import_logical_csmi_pack(
        &exported,
        &CsmiVocabularySupport::empty(),
        &CompilerOptions::default(),
    )
    .expect("import succeeds");
    let recompiled = imported
        .compile(&CompilerOptions::default())
        .expect("imported pack compiles");

    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    catalog
        .register_session_pack(
            &recompiled,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "csmi-round-trip".to_owned(),
            },
        )
        .unwrap();
    let activation = |sha256: String| SemanticModelActivationRequest {
        bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        evidence: vec![SemanticModelActivationEvidence {
            language: "java".to_owned(),
            ecosystem: "maven".to_owned(),
            package: Some(CatalogCoordinate {
                name: "com.acme:widget".to_owned(),
                version: Some(Version::parse("1.2.0").unwrap()),
            }),
            module: None,
            toolchain: None,
            target: None,
            configuration: None,
            artifact_sha256: Some(sha256),
        }],
        controls: Vec::new(),
        limits: Default::default(),
    };
    let active = match resolve_active_semantic_models(
        &catalog,
        &activation(artifact_digest()),
        &CancellationToken::default(),
    ) {
        SemanticModelResolutionOutcome::Ready(active) => active,
        other => panic!("imported CSMI pack did not activate: {other:#?}"),
    };
    let target = ProcedureSummaryTargetKey::new("java", "com.acme.Widget", "create", false, 1);
    assert_eq!(active.procedure_summaries_for(target).records.len(), 1);

    let mut near_digest = artifact_digest();
    near_digest.replace_range(63..64, "e");
    let inactive = match resolve_active_semantic_models(
        &catalog,
        &activation(near_digest),
        &CancellationToken::default(),
    ) {
        SemanticModelResolutionOutcome::Ready(active) => active,
        other => panic!("near-miss activation did not resolve: {other:#?}"),
    };
    assert!(inactive.procedure_summaries_for(target).records.is_empty());

    let reexported =
        export_csmi_pack(&recompiled, &artifact, &options).expect("re-export succeeds");
    let first_semantic = exported
        .resource_bytes(&exported.manifest.resources[0])
        .expect("first semantic resource verifies");
    let second_semantic = reexported
        .resource_bytes(&reexported.manifest.resources[0])
        .expect("second semantic resource verifies");
    assert_eq!(first_semantic, second_semantic);
}

#[test]
fn complete_empty_summary_exports_without_licensing_partial_or_missing_evidence() {
    let artifact = CsmiArtifactEvidence::new("pkg:maven/com.acme/widget@1.2.0", artifact_digest());
    let options = CsmiExportOptions::default();

    let mut complete = authored_exact_pack();
    let AuthoredPayload::ProcedureSummaries { summaries } = &mut complete.shards[1].payload else {
        panic!("summary shard has the wrong payload");
    };
    summaries[0].transfers.clear();
    let exported = export_authored_csmi_pack(&complete, &artifact, &options)
        .expect("complete empty summary exports");
    let validation = validate_csmi_pack(
        &exported.canonical_manifest_bytes().unwrap(),
        &exported.resources,
        &CsmiVocabularySupport::empty(),
    );
    assert!(
        validation.valid(),
        "diagnostics: {:#?}",
        validation.diagnostics
    );
    let model = &validation.semantic_documents[0].semantic_models[0];
    let summary = &model.procedure_summaries[0];
    assert!(summary.transfers.is_empty());
    assert!(model.completeness_statements.iter().any(|statement| {
        statement.family == "procedure-summaries"
            && statement.scope.get("callable").and_then(Value::as_str)
                == Some(summary.callable.as_str())
            && statement.status == CsmiCoverageStatus::Complete
    }));

    let mut partial = complete.clone();
    let AuthoredPayload::ProcedureSummaries { summaries } = &mut partial.shards[1].payload else {
        panic!("summary shard has the wrong payload");
    };
    summaries[0].completeness = Completeness::Partial;
    let diagnostics = compile_pack(&partial, &CompilerOptions::default())
        .expect_err("partial empty summary must not compile");
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "summary.empty"),
        "diagnostics: {diagnostics:#?}"
    );

    let mut missing = complete;
    missing.shards.pop();
    let exported = export_authored_csmi_pack(&missing, &artifact, &options)
        .expect("pack without summary evidence exports declarations");
    let validation = validate_csmi_pack(
        &exported.canonical_manifest_bytes().unwrap(),
        &exported.resources,
        &CsmiVocabularySupport::empty(),
    );
    assert!(
        validation.valid(),
        "diagnostics: {:#?}",
        validation.diagnostics
    );
    let model = &validation.semantic_documents[0].semantic_models[0];
    assert!(model.procedure_summaries.is_empty());
    assert!(
        model
            .completeness_statements
            .iter()
            .all(|statement| statement.family != "procedure-summaries")
    );
}

#[test]
fn value_transfer_profile_round_trips_through_native_pack() {
    let mut authored = authored_exact_pack();
    let (type_id, member_id) = {
        let AuthoredPayload::DeclarationFacts { types, members, .. } =
            &mut authored.shards[0].payload
        else {
            panic!("declaration shard has the wrong payload");
        };
        members[0].member_kind = MemberKind::Constructor;
        members[0].implicit_operation = Some(ImplicitOperation::CopyConstructor);
        let type_id = types[0].id.clone();
        let member_id = members[0].id.clone();
        types[0].value_semantics = Some(TypeValueSemantics {
            copy: Some(TypeCopySemantics::ViaMember {
                member: member_id.clone(),
            }),
            move_semantics: None,
        });
        (type_id, member_id)
    };
    let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[1].payload else {
        panic!("summary shard has the wrong payload");
    };
    summaries[0].transfers[0].value_transfer = Some(SummaryValueTransfer {
        kind: SummaryValueTransferKind::Copy {},
        operation: SummaryValueTransferOperation::Implicit {
            member: member_id.clone(),
        },
    });

    let artifact = CsmiArtifactEvidence::new("pkg:maven/com.acme/widget@1.2.0", artifact_digest());
    let options = CsmiExportOptions::default();
    let exported = export_authored_csmi_pack(&authored, &artifact, &options).unwrap();
    let support = CsmiVocabularySupport::support(
        CSMI_VALUE_TRANSFER_PROFILE_ID,
        CSMI_VALUE_TRANSFER_PROFILE_VERSION,
        CSMI_VALUE_TRANSFER_PROFILE_SCHEMA,
    );
    let imported = import_logical_csmi_pack(&exported, &support, &CompilerOptions::default())
        .expect("value-transfer profile imports");
    let AuthoredPayload::DeclarationFacts { types, members, .. } = &imported.pack.shards[0].payload
    else {
        panic!("imported declaration shard has the wrong payload");
    };
    assert!(types.iter().any(|fact| matches!(
        &fact.value_semantics,
        Some(TypeValueSemantics { copy: Some(TypeCopySemantics::ViaMember { member }), .. })
            if members.iter().any(|candidate| candidate.id == *member
                && candidate.implicit_operation == Some(ImplicitOperation::CopyConstructor))
    )));
    let AuthoredPayload::ProcedureSummaries { summaries } = &imported.pack.shards[1].payload else {
        panic!("imported summary shard has the wrong payload");
    };
    assert!(matches!(
        &summaries[0].transfers[0].value_transfer,
        Some(SummaryValueTransfer {
            kind: SummaryValueTransferKind::Copy {},
            operation: SummaryValueTransferOperation::Implicit { member },
        }) if members.iter().any(|candidate| candidate.id == *member)
    ));
    let recompiled = imported.compile(&CompilerOptions::default()).unwrap();
    let reexported = export_csmi_pack(&recompiled, &artifact, &options).unwrap();
    assert_eq!(
        exported
            .resource_bytes(&exported.manifest.resources[0])
            .unwrap(),
        reexported
            .resource_bytes(&reexported.manifest.resources[0])
            .unwrap()
    );
    assert!(!type_id.is_empty());
}

#[test]
fn cpp_profile_round_trips_through_typed_native_portability_evidence() {
    let fixture_value = cpp_fixture_with_special_member();
    let fixture = logical_pack_from_semantic(
        &serde_json::to_vec(&fixture_value).expect("C++ fixture serializes"),
    );
    let imported = import_logical_csmi_pack(
        &fixture,
        &cpp_profile_support(),
        &CompilerOptions::default(),
    )
    .expect("portable C++ profile imports");
    let evidence = imported
        .pack
        .cpp_portability
        .as_ref()
        .expect("C++ evidence is retained");
    assert_eq!(1, evidence.resolution_contexts.len());
    assert_eq!(2, evidence.symbols.len());
    assert_eq!(1, evidence.special_members.len());
    assert!(evidence.symbols.iter().any(|record| {
        record.key.descriptors.last().is_some_and(|descriptor| {
            descriptor.disambiguator
                == "cppsig-0.1:670e0719b1b6b5ae53e61b7e9b5d04dffd8beb7fbe6514a93b2a6b6d276b0bbb"
        })
    }));
    let compiled = imported.compile(&CompilerOptions::default()).unwrap();
    let artifact = CsmiArtifactEvidence::new(
        "pkg:generic/cpp-reference-headers@1.0.0",
        "1111111111111111111111111111111111111111111111111111111111111111",
    )
    .with_coverage("canonical-header-tree");
    let exported = export_csmi_pack(&compiled, &artifact, &CsmiExportOptions::default())
        .expect("portable C++ profile exports");
    let reimported = import_logical_csmi_pack(
        &exported,
        &cpp_profile_support(),
        &CompilerOptions::default(),
    )
    .expect("re-exported C++ profile imports");
    assert_eq!(
        imported.pack.cpp_portability,
        reimported.pack.cpp_portability
    );
    let recompiled = reimported.compile(&CompilerOptions::default()).unwrap();
    let reexported = export_csmi_pack(&recompiled, &artifact, &CsmiExportOptions::default())
        .expect("reimported C++ profile re-exports");
    assert_eq!(
        exported
            .resource_bytes(&exported.manifest.resources[0])
            .unwrap(),
        reexported
            .resource_bytes(&reexported.manifest.resources[0])
            .unwrap(),
        "portable C++ export/import/export must be byte deterministic"
    );
}

#[test]
fn cpp_special_member_rejects_a_mismatched_structured_disambiguator() {
    let mut fixture = cpp_fixture_with_special_member();
    let facts = fixture["semanticModels"][0]["extensionFacts"]
        .as_array_mut()
        .expect("extension facts are an array");
    let special = facts
        .iter_mut()
        .find(|fact| fact["family"] == "special-member")
        .expect("special-member fact exists");
    special["payload"]["memberDisambiguator"] =
        json!("cppsig-0.1:0000000000000000000000000000000000000000000000000000000000000000");
    let bytes = canonical_json_value(&fixture).expect("mutated C++ fixture canonicalizes");
    let result = validate_csmi_document(&bytes, &cpp_profile_support());
    assert!(
        result.structural_valid,
        "diagnostics: {:#?}",
        result.diagnostics
    );
    assert!(!result.semantic_valid);
    assert!(diagnostics_contain(
        &result.diagnostics,
        "semantic.cpp_signature_digest"
    ));
}

#[test]
fn cpp_special_member_family_scope_must_match_the_payload_key() {
    let mut fixture = cpp_fixture_with_special_member();
    let facts = fixture["semanticModels"][0]["extensionFacts"]
        .as_array_mut()
        .expect("extension facts are an array");
    let special = facts
        .iter_mut()
        .find(|fact| fact["family"] == "special-member")
        .expect("special-member fact exists");
    special["scope"]["owner"] = json!("copyConstructor");
    let bytes = canonical_json_value(&fixture).expect("mutated C++ fixture canonicalizes");
    let result = validate_csmi_document(&bytes, &cpp_profile_support());
    assert!(
        result.structural_valid,
        "diagnostics: {:#?}",
        result.diagnostics
    );
    assert!(!result.semantic_valid);
    assert!(diagnostics_contain(
        &result.diagnostics,
        "semantic.cpp_special_member_family_scope"
    ));
}

#[test]
fn cpp_fact_cannot_bind_a_digest_for_a_c_resolution_context() {
    let mut fixture = cpp_fixture_with_special_member();
    let context_value = &mut fixture["semanticModels"][0]["compatibilityConstraints"][0]["value"];
    context_value["language"] = json!("c");
    let context: CsmiResolutionContext =
        serde_json::from_value(context_value.clone()).expect("C context remains structural");
    let digest = canonical_digest(&context).expect("C context canonicalizes");
    let facts = fixture["semanticModels"][0]["extensionFacts"]
        .as_array_mut()
        .expect("extension facts are an array");
    let special = facts
        .iter_mut()
        .find(|fact| fact["family"] == "special-member")
        .expect("special-member fact exists");
    special["payload"]["resolutionContext"]["contextDigest"] = json!(digest);
    let bytes = canonical_json_value(&fixture).expect("mutated C++ fixture canonicalizes");
    let result = validate_csmi_document(&bytes, &cpp_profile_support());
    assert!(
        result.structural_valid,
        "diagnostics: {:#?}",
        result.diagnostics
    );
    assert!(!result.semantic_valid);
    assert!(diagnostics_contain(
        &result.diagnostics,
        "semantic.cpp_context_reference"
    ));
}

#[test]
fn complete_type_value_scope_rejects_conflicting_facts() {
    let mut fixture: Value =
        serde_json::from_slice(VALID_CPP_BASIC_STRING_COPY).expect("C++ fixture is JSON");
    fixture["semanticModels"][0]["extensionFacts"]
        .as_array_mut()
        .expect("extension facts are an array")
        .push(json!({
            "vocabulary": CSMI_VALUE_TRANSFER_PROFILE_ID,
            "version": CSMI_VALUE_TRANSFER_PROFILE_VERSION,
            "family": "type-value-semantics",
            "scope": {"type": "basicString", "aspect": "copy"},
            "payload": {
                "kind": "type-value-semantics",
                "type": "basicString",
                "aspect": "copy",
                "semantics": {"kind": "trivial"}
            }
        }));
    let bytes =
        canonical_json_value(&fixture).expect("mutated value-transfer fixture canonicalizes");
    let result = validate_csmi_document(&bytes, &cpp_profile_support());
    assert!(
        result.structural_valid,
        "diagnostics: {:#?}",
        result.diagnostics
    );
    assert!(!result.semantic_valid);
    assert!(diagnostics_contain(
        &result.diagnostics,
        "semantic.value_transfer_complete_conflict"
    ));
}

#[test]
fn native_cpp_evidence_recomputes_context_signature_and_operation_shape() {
    let fixture = cpp_fixture_with_special_member();
    let logical =
        logical_pack_from_semantic(&serde_json::to_vec(&fixture).expect("C++ fixture serializes"));
    let imported = import_logical_csmi_pack(
        &logical,
        &cpp_profile_support(),
        &CompilerOptions::default(),
    )
    .expect("portable C++ profile imports");

    let mut forged_signature = imported.clone();
    let evidence = forged_signature.pack.cpp_portability.as_mut().unwrap();
    evidence.special_members[0].member_disambiguator = format!("cppsig-0.1:{}", "0".repeat(64));
    let error = forged_signature
        .compile(&CompilerOptions::default())
        .expect_err("forged cppsig must fail");
    assert!(
        error
            .to_string()
            .contains("cpp_portability.member_disambiguator")
    );

    let mut wrong_shape = imported.clone();
    let evidence = wrong_shape.pack.cpp_portability.as_mut().unwrap();
    evidence.special_members[0].signature.callable_kind =
        crate::analyzer::semantic_model::CppCallableKind::Method;
    let error = wrong_shape
        .compile(&CompilerOptions::default())
        .expect_err("operation-incompatible signature must fail");
    assert!(
        error
            .to_string()
            .contains("cpp_portability.signature_shape")
    );

    let mut forged_context = imported;
    let evidence = forged_context.pack.cpp_portability.as_mut().unwrap();
    evidence.resolution_contexts[0].translation_unit = "src/other.cpp".to_owned();
    let error = forged_context
        .compile(&CompilerOptions::default())
        .expect_err("forged context digest must fail");
    assert!(
        error
            .to_string()
            .contains("cpp_portability.context_digest_mismatch")
    );
}

#[test]
fn cpp_alias_exports_core_alias_target_and_exact_profile_fact() {
    let mut fixture_value: Value =
        serde_json::from_slice(VALID_CPP_BASIC_STRING_COPY).expect("C++ fixture is JSON");
    fixture_value["semanticModels"][0]["completenessStatements"]
        .as_array_mut()
        .expect("completeness statements are an array")
        .push(json!({
            "family": "declaration-records",
            "scope": {
                "scheme": CSMI_CPP_DECLARATION_IDENTITY_SCHEME,
                "schemeVersion": CSMI_CPP_DECLARATION_IDENTITY_SCHEME_VERSION
            },
            "status": "complete"
        }));
    let fixture = logical_pack_from_semantic(
        &serde_json::to_vec(&fixture_value).expect("C++ fixture serializes"),
    );
    let mut imported = import_logical_csmi_pack(
        &fixture,
        &cpp_profile_support(),
        &CompilerOptions::default(),
    )
    .expect("portable C++ profile imports");
    let evidence = imported
        .pack
        .cpp_portability
        .as_mut()
        .expect("C++ evidence is retained");
    let target_symbol = evidence
        .symbols
        .iter()
        .find(|symbol| {
            symbol.key.descriptors.last().is_some_and(|descriptor| {
                descriptor.role == crate::analyzer::semantic_model::CppDescriptorRole::Type
            })
        })
        .expect("C++ fixture has a type symbol");
    let target = target_symbol.native_id.clone();
    let mut alias_key = target_symbol.key.clone();
    let alias_descriptor = alias_key
        .descriptors
        .last_mut()
        .expect("type key has a descriptor");
    alias_descriptor.name = "string".to_owned();
    alias_descriptor.disambiguator = "type-alias".to_owned();
    let alias = "cpp.std.string.alias".to_owned();
    evidence
        .symbols
        .push(crate::analyzer::semantic_model::CppPortableSymbolRecord {
            native_id: alias.clone(),
            key: alias_key,
        });
    let context = &evidence.resolution_contexts[0];
    evidence
        .type_aliases
        .push(crate::analyzer::semantic_model::CppTypeAliasEvidence {
            alias: alias.clone(),
            target: crate::analyzer::semantic_model::CppCanonicalType::Declared { symbol: target },
            resolution_context: crate::analyzer::semantic_model::CppResolutionContextRef {
                vocabulary: CSMI_C_CPP_RESOLUTION_PROFILE_ID.to_owned(),
                version: CSMI_C_CPP_RESOLUTION_PROFILE_VERSION.to_owned(),
                context_digest: context.context_digest.clone(),
                language: context.language,
                header_closure: context.header_closure,
            },
        });
    let AuthoredPayload::DeclarationFacts { types, .. } = &mut imported.pack.shards[0].payload
    else {
        panic!("imported declaration shard has the wrong payload");
    };
    let mut alias_type = types[0].clone();
    alias_type.id = alias;
    alias_type.name = "string".to_owned();
    alias_type.type_kind = TypeKind::TypeAlias;
    alias_type.value_semantics = None;
    types.push(alias_type);

    let artifact = CsmiArtifactEvidence::new(
        "pkg:generic/cpp-reference-headers@1.0.0",
        "1111111111111111111111111111111111111111111111111111111111111111",
    )
    .with_coverage("canonical-header-tree");
    let exported = export_csmi_pack(
        &imported.compile(&CompilerOptions::default()).unwrap(),
        &artifact,
        &CsmiExportOptions::default(),
    )
    .expect("C++ alias exports");
    let document: CsmiSemanticDocument = serde_json::from_slice(
        exported
            .resources
            .get(DEFAULT_SEMANTIC_RESOURCE_PATH)
            .unwrap(),
    )
    .unwrap();
    let model = &document.semantic_models[0];
    let alias_declaration = model
        .declarations
        .iter()
        .find(|declaration| declaration.category == CsmiDeclarationCategory::TypeAlias)
        .expect("core type-alias declaration is emitted");
    assert!(matches!(
        alias_declaration.alias_target,
        Some(CsmiTypeExpression::Reference(_))
    ));
    assert!(
        model
            .extension_facts
            .iter()
            .any(|fact| { fact.vocabulary == CSMI_CPP_PROFILE_ID && fact.family == "type-alias" })
    );
    let reimported = import_logical_csmi_pack(
        &exported,
        &cpp_profile_support(),
        &CompilerOptions::default(),
    )
    .expect("exported C++ alias reimports");
    assert_eq!(
        reimported
            .pack
            .cpp_portability
            .as_ref()
            .unwrap()
            .type_aliases
            .len(),
        1
    );
}

#[test]
fn cpp_identity_rejects_non_sha256_core_digest_instead_of_relabeling_it() {
    let mut fixture_value: Value =
        serde_json::from_slice(VALID_CPP_BASIC_STRING_COPY).expect("C++ fixture is JSON");
    fixture_value["semanticModels"][0]["artifactSelectors"][0]["digests"]
        .as_array_mut()
        .expect("digests are an array")
        .push(json!({
            "algorithm": "sha-512",
            "coverage": "canonical-header-tree",
            "value": "22".repeat(64)
        }));
    let fixture = logical_pack_from_semantic(
        &serde_json::to_vec(&fixture_value).expect("C++ fixture serializes"),
    );
    let error = import_logical_csmi_pack(
        &fixture,
        &cpp_profile_support(),
        &CompilerOptions::default(),
    )
    .expect_err("C++ identity cannot losslessly retain sha-512");
    assert!(matches!(
        error,
        CsmiImportError::Unsupported { path, .. }
            if path == "symbols.artifactSelectors.digests.algorithm"
    ));
}

#[test]
fn importer_pack_completeness_uses_declaration_records_only() {
    let pack = exported_import_fixture();
    let imported = import_logical_csmi_pack(
        &pack,
        &CsmiVocabularySupport::empty(),
        &CompilerOptions::default(),
    )
    .expect("complete declaration-records statement imports");
    assert_eq!(imported.pack.completeness, Completeness::Complete);

    let without_declaration_completeness = pack_with_semantic_value(&pack, |value| {
        value["semanticModels"][0]["completenessStatements"]
            .as_array_mut()
            .expect("completenessStatements is an array")
            .retain(|statement| statement["family"] != "declaration-records");
    });
    let error = import_logical_csmi_pack(
        &without_declaration_completeness,
        &CsmiVocabularySupport::empty(),
        &CompilerOptions::default(),
    )
    .expect_err("complete procedure summaries cannot exceed partial pack completeness");
    assert!(
        matches!(error, CsmiImportError::Compile(message) if message.contains("summary.completeness_exceeds_pack"))
    );
}

#[test]
fn declared_type_ids_resolve_to_portable_jvm_names() {
    let mut authored = authored_exact_pack();
    let AuthoredPayload::DeclarationFacts { members, .. } = &mut authored.shards[0].payload else {
        panic!("declaration fixture has no declaration facts");
    };
    members[0]
        .signature
        .as_mut()
        .expect("member is callable")
        .returns = Some(crate::analyzer::semantic_model::TypeRef::Declared {
        id: "type.widget".to_owned(),
        arguments: Vec::new(),
        nullable: false,
    });

    let artifact = CsmiArtifactEvidence::new("pkg:maven/com.acme/widget@1.2.0", artifact_digest());
    let exported = export_authored_csmi_pack(&authored, &artifact, &CsmiExportOptions::default())
        .expect("declared type identity exports");
    let validation = validate_csmi_pack(
        &exported.canonical_manifest_bytes().unwrap(),
        &exported.resources,
        &CsmiVocabularySupport::empty(),
    );
    assert!(
        validation.valid(),
        "diagnostics: {:#?}",
        validation.diagnostics
    );
}

#[test]
fn maven_digest_near_miss_remains_an_exact_distinct_selector() {
    let authored = authored_exact_pack();
    let exact = CsmiArtifactEvidence::new("pkg:maven/com.acme/widget@1.2.0", artifact_digest());
    let mut near_digest = artifact_digest();
    near_digest.replace_range(63..64, "e");
    let near = CsmiArtifactEvidence::new("pkg:maven/com.acme/widget@1.2.0", near_digest.clone());
    let exact_pack = export_authored_csmi_pack(&authored, &exact, &CsmiExportOptions::default())
        .expect("exact evidence exports");
    let near_pack = export_authored_csmi_pack(&authored, &near, &CsmiExportOptions::default())
        .expect("valid near-miss evidence still has a valid digest shape");
    let exact_model = validate_csmi_pack(
        &exact_pack.canonical_manifest_bytes().unwrap(),
        &exact_pack.resources,
        &CsmiVocabularySupport::empty(),
    );
    let near_model = validate_csmi_pack(
        &near_pack.canonical_manifest_bytes().unwrap(),
        &near_pack.resources,
        &CsmiVocabularySupport::empty(),
    );
    assert!(exact_model.valid());
    assert!(near_model.valid());
    let exact_selector =
        &exact_model.semantic_documents[0].semantic_models[0].artifact_selectors[0];
    let near_selector = &near_model.semantic_documents[0].semantic_models[0].artifact_selectors[0];
    assert_ne!(
        exact_selector.digests[0].value,
        near_selector.digests[0].value
    );
    assert_eq!(near_selector.digests[0].value, near_digest);
}

#[test]
fn unsupported_effects_fail_closed_and_value_transfer_facts_export() {
    let artifact = CsmiArtifactEvidence::new("pkg:maven/com.acme/widget@1.2.0", artifact_digest());
    let options = CsmiExportOptions::default();

    let mut effects = authored_exact_pack();
    let AuthoredPayload::ProcedureSummaries { summaries } = &mut effects.shards[1].payload else {
        panic!("summary shard has the wrong payload");
    };
    summaries[0]
        .effects
        .push(AuthoredSummaryEffect::UnknownCallBoundary {
            event: "event.widget.unknown".to_owned(),
        });
    let effect_error = export_authored_csmi_pack(&effects, &artifact, &options)
        .expect_err("unsupported effects must not be approximated");
    assert!(matches!(
        effect_error,
        CsmiExportError::Unsupported { path, .. } if path.contains("procedureSummaries")
    ));

    let mut type_refinement = authored_exact_pack();
    {
        let AuthoredPayload::DeclarationFacts { members, .. } =
            &mut type_refinement.shards[0].payload
        else {
            panic!("declaration shard has the wrong payload");
        };
        let signature = members[0]
            .signature
            .as_mut()
            .expect("callable fixture has a signature");
        let mut parameter = signature.parameters[0].clone();
        parameter.name = Some("class".to_owned());
        signature.parameters.push(parameter);
    }
    let AuthoredPayload::ProcedureSummaries { summaries } = &mut type_refinement.shards[1].payload
    else {
        panic!("summary shard has the wrong payload");
    };
    summaries[0].target.parameter_count = 2;
    summaries[0].normal_return_type_refinements = vec![AuthoredNormalReturnTypeRefinement {
        parameter_ordinal: 0,
        class_parameter_ordinal: 1,
        required_receiver_members: Vec::new(),
    }];
    let type_refinement_error = export_authored_csmi_pack(&type_refinement, &artifact, &options)
        .expect_err("normal-return type refinements must not be approximated in CSMI core");
    assert!(matches!(
        type_refinement_error,
        CsmiExportError::Unsupported { path, semantic }
            if path.contains("procedureSummaries")
                && semantic.contains("normal-return type refinements")
    ));

    let mut decorator_identity = authored_exact_pack();
    let AuthoredPayload::ProcedureSummaries { summaries } =
        &mut decorator_identity.shards[1].payload
    else {
        panic!("summary shard has the wrong payload");
    };
    summaries[0].class_decorator_identity = Some(AuthoredClassDecoratorIdentity {
        direct: true,
        factory_keywords: None,
    });
    let decorator_identity_error =
        export_authored_csmi_pack(&decorator_identity, &artifact, &options)
            .expect_err("class decorator identity must not be approximated in CSMI core");
    assert!(matches!(
        decorator_identity_error,
        CsmiExportError::Unsupported { path, semantic }
            if path.contains("procedureSummaries")
                && semantic.contains("class decorator identity")
    ));

    let mut concurrency = authored_exact_pack();
    let AuthoredPayload::ProcedureSummaries { summaries } = &mut concurrency.shards[1].payload
    else {
        panic!("summary shard has the wrong payload");
    };
    summaries[0]
        .concurrency_effects
        .push(AuthoredConcurrencyEffect::TaskSpawn {
            callable: AuthoredSummaryInput::Parameter { ordinal: 0 },
            group: None,
            condition: None,
            timer: None,
        });
    let concurrency_error = export_authored_csmi_pack(&concurrency, &artifact, &options)
        .expect_err("unsupported concurrency effects must not be approximated");
    assert!(matches!(
        concurrency_error,
        CsmiExportError::Unsupported { path, .. } if path.contains("procedureSummaries")
    ));

    let mut value_semantics = authored_exact_pack();
    {
        let AuthoredPayload::DeclarationFacts { types, .. } =
            &mut value_semantics.shards[0].payload
        else {
            panic!("declaration shard has the wrong payload");
        };
        types[0].value_semantics = Some(TypeValueSemantics {
            copy: Some(TypeCopySemantics::Trivial),
            move_semantics: None,
        });
    }
    let exported = export_authored_csmi_pack(&value_semantics, &artifact, &options)
        .expect("standardized type-wide value semantics export");
    let document: CsmiSemanticDocument = serde_json::from_slice(
        exported
            .resources
            .get(DEFAULT_SEMANTIC_RESOURCE_PATH)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        document.semantic_models[0].extension_facts[0].family,
        "type-value-semantics"
    );

    {
        let AuthoredPayload::DeclarationFacts { types, members, .. } =
            &mut value_semantics.shards[0].payload
        else {
            panic!("declaration shard has the wrong payload");
        };
        types[0].value_semantics = None;
        members[0].member_kind = MemberKind::Constructor;
        members[0].implicit_operation = Some(ImplicitOperation::CopyConstructor);
    }
    let exported = export_authored_csmi_pack(&value_semantics, &artifact, &options)
        .expect("standardized implicit-operation identity exports");
    let document: CsmiSemanticDocument = serde_json::from_slice(
        exported
            .resources
            .get(DEFAULT_SEMANTIC_RESOURCE_PATH)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        document.semantic_models[0].extension_facts[0].family,
        "implicit-operations"
    );

    let rules: AuthoredSemanticModelPack =
        serde_json::from_slice(GENERATOR_RULES_JSON).expect("generator fixture is valid");
    let rules_error = export_authored_csmi_pack(&rules, &artifact, &options)
        .expect_err("generator rules are outside the CSMI core");
    assert!(matches!(
        rules_error,
        CsmiExportError::Unsupported { path, .. } if path == "shards.payload"
    ));
}

#[test]
fn required_unsupported_vocabulary_is_rejected_until_support_is_declared() {
    let mut value: Value = serde_json::from_slice(VALID_PROCEDURE_SUMMARY).expect("valid JSON");
    let vocabulary = &mut value["semanticModels"][0]["vocabularyUses"][0];
    vocabulary["requirement"] = json!("required");
    let identifier = vocabulary["identifier"].as_str().unwrap().to_owned();
    let version = vocabulary["version"].as_str().unwrap().to_owned();
    let schema = vocabulary["schema"].as_str().unwrap().to_owned();
    let bytes = canonical_json_value(&value).expect("mutated JSON canonicalizes");

    let unsupported = validate_csmi_document(&bytes, &CsmiVocabularySupport::empty());
    assert!(
        unsupported.structural_valid,
        "diagnostics: {:#?}",
        unsupported.diagnostics
    );
    assert!(
        unsupported.semantic_valid,
        "unsupported vocabulary is not semantic invalidity: {:#?}",
        unsupported.diagnostics
    );
    assert!(!unsupported.interpretable);
    assert!(diagnostics_contain(
        &unsupported.diagnostics,
        "interpretability.unsupported_required_vocabulary"
    ));

    let supported = validate_csmi_document(
        &bytes,
        &CsmiVocabularySupport::support(identifier, version, schema),
    );
    assert!(
        supported.usable(),
        "diagnostics: {:#?}",
        supported.diagnostics
    );
}

#[test]
fn recognized_profile_schemas_are_validated_without_claiming_semantic_support() {
    let bytes = canonical_json_bytes(VALID_JAVASCRIPT_TYPESCRIPT_NODE)
        .expect("profile fixture canonicalizes");
    let result = validate_csmi_document(&bytes, &CsmiVocabularySupport::empty());
    assert!(
        result.structural_valid,
        "diagnostics: {:#?}",
        result.diagnostics
    );
    // This normative profile fixture omits callable shapes that Bifrost's
    // existing semantic validator requires. Profile-schema success remains
    // independently observable from that semantic disagreement.
    assert!(!result.semantic_valid);
    assert!(!result.interpretable);
    assert_eq!(result.profiles.len(), 3);
    assert!(result.profiles.iter().all(|profile| profile.recognized));
    assert!(
        result
            .profiles
            .iter()
            .all(|profile| profile.structural_valid)
    );
    assert!(
        result
            .profiles
            .iter()
            .all(|profile| !profile.semantically_supported)
    );
}

#[test]
fn recognized_profile_payload_schema_violations_are_structural() {
    let mut value: Value = serde_json::from_slice(VALID_JAVASCRIPT_TYPESCRIPT_NODE)
        .expect("profile fixture is valid JSON");
    value["semanticModels"][0]["symbols"][1]["extensions"][0]["payload"]["unknownField"] =
        json!(true);
    let bytes = canonical_json_value(&value).expect("mutated profile fixture canonicalizes");
    let result = validate_csmi_document(&bytes, &CsmiVocabularySupport::empty());
    assert!(!result.structural_valid);
    assert!(!result.valid());
    assert!(diagnostics_contain(
        &result.diagnostics,
        "structural.profile_schema_violation"
    ));
}

#[test]
fn known_profile_with_wrong_schema_fails_at_profile_recognition_boundary() {
    let mut value: Value = serde_json::from_slice(VALID_JAVASCRIPT_TYPESCRIPT_NODE)
        .expect("profile fixture is valid JSON");
    value["semanticModels"][0]["vocabularyUses"][0]["schema"] =
        json!("https://example.org/wrong-profile-schema.json");
    let bytes = canonical_json_value(&value).expect("mutated profile fixture canonicalizes");
    let result = validate_csmi_document(&bytes, &CsmiVocabularySupport::empty());
    assert!(!result.structural_valid);
    assert!(!result.profiles[0].recognized);
    assert!(diagnostics_contain(
        &result.diagnostics,
        "structural.profile_schema_mismatch"
    ));
}

#[test]
fn recognized_indeterminate_profile_value_remains_uninterpretable() {
    let mut value: Value =
        serde_json::from_slice(VALID_JAVA_JVM_MAPPING).expect("profile fixture is valid JSON");
    let mut indeterminate: Value = serde_json::from_slice(VALID_INDETERMINATE_JAVA_JVM_MAPPING)
        .expect("indeterminate mapping fixture is valid JSON");
    indeterminate
        .as_object_mut()
        .expect("mapping fixture is an object")
        .remove("$profileSchema");
    value["semanticModels"][0]["extensionFacts"][0]["payload"] = indeterminate;
    let bytes = canonical_json_value(&value).expect("mutated profile fixture canonicalizes");
    let result = validate_csmi_document(&bytes, &CsmiVocabularySupport::empty());
    assert!(
        result.structural_valid,
        "diagnostics: {:#?}",
        result.diagnostics
    );
    assert!(
        result.semantic_valid,
        "diagnostics: {:#?}",
        result.diagnostics
    );
    assert!(result.valid());
    assert!(!result.interpretable);
    assert!(result.profiles.iter().all(|profile| profile.recognized));
    assert!(
        result
            .profiles
            .iter()
            .all(|profile| !profile.semantically_supported)
    );
}

#[test]
fn conditional_type_refinement_round_trip_retains_target_arguments() {
    let mut authored = authored_exact_pack();
    let AuthoredPayload::DeclarationFacts { types, members, .. } = &mut authored.shards[0].payload
    else {
        panic!("expected declaration facts");
    };
    members[0].callable_family_complete = true;
    let callable = members[0].id.clone();
    let target = types[0].id.clone();
    authored.shards[0].conditional_type_refinements = Some(ConditionalTypeRefinementsPayload {
        refinements: vec![ConditionalTypeRefinementFact {
            payload: serde_json::from_value(json!({
                "kind": "conditional-type-refinement", "callable": callable,
                "subject": {"kind": "parameter", "position": 0},
                "outcome": {"kind": "supported", "semantics": "positive-only",
                    "target": {"kind": "reference", "symbol": target, "arguments": [
                        {"kind": "reference", "symbol": target}
                    ]}}
            }))
            .unwrap(),
            coverage: Some(CsmiCoverageStatus::Complete),
            provenance: Vec::new(),
        }],
    });
    let artifact = CsmiArtifactEvidence::new("pkg:maven/com.acme/widget@1.2.0", artifact_digest());
    let options = CsmiExportOptions::default();
    let exported = export_authored_csmi_pack(&authored, &artifact, &options).unwrap();
    let support = CsmiVocabularySupport::support(
        CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_ID,
        CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_VERSION,
        CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_SCHEMA,
    );
    let imported =
        import_logical_csmi_pack(&exported, &support, &CompilerOptions::default()).unwrap();
    let compiled = imported.compile(&CompilerOptions::default()).unwrap();
    assert_eq!(
        compiled
            .shards
            .iter()
            .map(
                |shard| decode_shard(&shard.descriptor, &shard.bytes, &DecodeLimits::default())
                    .unwrap()
            )
            .filter_map(|shard| shard
                .conditional_type_refinements()
                .map(|payload| payload.refinements.len()))
            .sum::<usize>(),
        1
    );
    let reexported = export_csmi_pack(&compiled, &artifact, &options).unwrap();
    let refinement = |pack: &CsmiLogicalPack| {
        semantic_value(pack)["semanticModels"][0]["extensionFacts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|fact| fact["vocabulary"] == CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_ID)
            .unwrap()["payload"]
            .clone()
    };
    assert_eq!(refinement(&exported), refinement(&reexported));
    for coverage in [
        None,
        Some(CsmiCoverageStatus::Unknown),
        Some(CsmiCoverageStatus::Partial),
    ] {
        authored.shards[0]
            .conditional_type_refinements
            .as_mut()
            .unwrap()
            .refinements[0]
            .coverage = coverage;
        let exported = export_authored_csmi_pack(&authored, &artifact, &options).unwrap();
        let imported =
            import_logical_csmi_pack(&exported, &support, &CompilerOptions::default()).unwrap();
        assert_eq!(
            imported.pack.shards[0]
                .conditional_type_refinements
                .as_ref()
                .unwrap()
                .refinements[0]
                .coverage,
            coverage
        );
    }
}

#[test]
fn python_native_annotation_exports_the_standard_refinement_with_exact_identity() {
    use crate::analyzer::semantic_model::TypeRef;
    let artifact = CsmiArtifactEvidence::new(
        "pkg:generic/python-runtime@3.12.0?component=stdlib&implementation=cpython",
        "a".repeat(64),
    );
    let mut support = CsmiVocabularySupport::support(
        CSMI_PYTHON_PROFILE_ID,
        CSMI_PYTHON_PROFILE_VERSION,
        CSMI_PYTHON_PROFILE_SCHEMA,
    );
    support.add(
        CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_ID,
        CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_VERSION,
        CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_SCHEMA,
    );
    let portable =
        logical_pack_from_semantic(include_bytes!("fixtures/python-runtime-refinement.json"));
    let imported = import_logical_csmi_pack(&portable, &support, &CompilerOptions::default())
        .expect("exact Python runtime pack imports");
    assert_eq!(imported.pack.language, "python");
    let original = imported.pack.shards[0]
        .conditional_type_refinements
        .clone()
        .unwrap();
    let mut native = imported.pack;
    for shard in &mut native.shards {
        shard.conditional_type_refinements = None;
        if let AuthoredPayload::DeclarationFacts { members, .. } = &mut shard.payload {
            for member in members {
                member.signature.as_mut().unwrap().returns = Some(TypeRef::Named {
                    name: "typing.TypeIs".to_owned(),
                    arguments: vec![TypeRef::Named {
                        name: "builtins.type".to_owned(),
                        arguments: vec![TypeRef::Named {
                            name: "builtins.object".to_owned(),
                            arguments: Vec::new(),
                            nullable: false,
                        }],
                        nullable: false,
                    }],
                    nullable: false,
                });
            }
        }
    }
    let stale = compile_pack(&native, &CompilerOptions::default())
        .expect_err("changed native result invalidates the imported shape claim");
    assert!(
        stale
            .iter()
            .any(|diagnostic| diagnostic.code == "locator.interchange_callable_shape"),
        "{stale:?}"
    );
    for shard in &mut native.shards {
        if let AuthoredPayload::DeclarationFacts { members, .. } = &mut shard.payload {
            for member in members {
                let Locator::Interchange {
                    callable_shape_evidence: Some(old),
                    ..
                } = &member.locator
                else {
                    panic!("imported callable has a shape claim");
                };
                let mut statement = old.statement.clone();
                let mut provenance = old.provenance_records[0].clone();
                provenance.id = "native-annotation-shape".to_owned();
                statement.provenance = vec![provenance.id.clone()];
                let evidence = author_python_callable_shape_evidence(member, statement, provenance)
                    .expect("explicit new shape claim binds to changed native member");
                let Locator::Interchange {
                    callable_shape_evidence,
                    ..
                } = &mut member.locator
                else {
                    unreachable!("authoring preserved the locator");
                };
                *callable_shape_evidence = Some(Box::new(evidence));
            }
        }
    }
    compile_pack(&native, &CompilerOptions::default())
        .expect("fresh shape evidence compiles with the changed member");
    let conflicting_options = CsmiExportOptions {
        provenance_id: "native-annotation-shape".to_owned(),
        ..Default::default()
    };
    assert!(
        export_authored_csmi_pack(&native, &artifact, &conflicting_options).is_err(),
        "a second producer record cannot reuse the newly authored shape record ID"
    );
    let exported = export_authored_csmi_pack(&native, &artifact, &CsmiExportOptions::default())
        .expect("native annotation exports through the standard profile");
    let restored = import_logical_csmi_pack(&exported, &support, &CompilerOptions::default())
        .expect("exported Python pack imports");
    let restored_facts = restored.pack.shards[0]
        .conditional_type_refinements
        .as_ref()
        .unwrap();
    assert_eq!(
        restored_facts.refinements[0].payload,
        original.refinements[0].payload
    );
    assert_eq!(
        restored_facts.refinements[0].coverage,
        original.refinements[0].coverage
    );
}

#[test]
fn python_callable_shape_authoring_requires_explicit_complete_local_evidence() {
    let portable =
        logical_pack_from_semantic(include_bytes!("fixtures/python-runtime-refinement.json"));
    let mut support = CsmiVocabularySupport::support(
        CSMI_PYTHON_PROFILE_ID,
        CSMI_PYTHON_PROFILE_VERSION,
        CSMI_PYTHON_PROFILE_SCHEMA,
    );
    support.add(
        CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_ID,
        CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_VERSION,
        CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_SCHEMA,
    );
    let imported = import_logical_csmi_pack(&portable, &support, &CompilerOptions::default())
        .expect("runtime fixture imports");
    let member = imported
        .pack
        .shards
        .iter()
        .find_map(|shard| match &shard.payload {
            AuthoredPayload::DeclarationFacts { members, .. } => members.first(),
            _ => None,
        })
        .expect("fixture callable")
        .clone();
    let Locator::Interchange {
        callable_shape_evidence: Some(old),
        ..
    } = &member.locator
    else {
        panic!("fixture has imported shape evidence");
    };
    let mut statement = old.statement.clone();
    let mut record = old.provenance_records[0].clone();
    record.id = "new-shape-review".to_owned();
    statement.provenance = vec![record.id.clone()];
    let evidence =
        author_python_callable_shape_evidence(&member, statement.clone(), record.clone())
            .expect("same producer may explicitly author a new record");
    assert_eq!(
        evidence.provenance_records[0].producer,
        old.provenance_records[0].producer
    );
    assert_eq!(evidence.default_provenance, None);
    assert_eq!(
        evidence.native_sha256,
        super::python::native_callable_shape_digest(&member)
    );

    let mut wrong_scope = statement.clone();
    wrong_scope.scope = json!({"symbol":"other","aspect":"callable-shape"});
    assert!(matches!(
        author_python_callable_shape_evidence(&member, wrong_scope, record.clone()),
        Err(CsmiShapeAuthoringError::InvalidStatement(_))
    ));
    for status in [CsmiCoverageStatus::Partial, CsmiCoverageStatus::Unknown] {
        let mut incomplete = statement.clone();
        incomplete.status = status;
        assert!(matches!(
            author_python_callable_shape_evidence(&member, incomplete, record.clone()),
            Err(CsmiShapeAuthoringError::InvalidStatement(_))
        ));
    }
    let mut stale_record = record.clone();
    stale_record.id = old.provenance_records[0].id.clone();
    let mut stale_statement = statement.clone();
    stale_statement.provenance = vec![stale_record.id.clone()];
    assert!(matches!(
        author_python_callable_shape_evidence(&member, stale_statement, stale_record),
        Err(CsmiShapeAuthoringError::InvalidProvenance(_))
    ));
    let mut zero_result = member.clone();
    zero_result.signature.as_mut().unwrap().returns = None;
    let zero_result_evidence =
        author_python_callable_shape_evidence(&zero_result, statement.clone(), record.clone())
            .expect("explicitly reviewed zero-result shape is representable");
    assert_ne!(zero_result_evidence.native_sha256, evidence.native_sha256);
    let mut missing_label = member.clone();
    missing_label.signature.as_mut().unwrap().parameters[0].name = None;
    assert!(matches!(
        author_python_callable_shape_evidence(&missing_label, statement.clone(), record.clone()),
        Err(CsmiShapeAuthoringError::UnsupportedMember(_))
    ));
    let mut pointer_receiver = member;
    pointer_receiver.receiver =
        Some(crate::analyzer::semantic_model::ReceiverFact { pointer: true });
    assert!(matches!(
        author_python_callable_shape_evidence(&pointer_receiver, statement, record),
        Err(CsmiShapeAuthoringError::UnsupportedMember(_))
    ));
    let mut extension_receiver = zero_result.clone();
    extension_receiver.extension_receiver = Some(crate::analyzer::semantic_model::TypeRef::Named {
        name: "builtins.object".to_owned(),
        arguments: Vec::new(),
        nullable: false,
    });
    let mut extension_statement = evidence.statement.clone();
    let extension_record = evidence.provenance_records[0].clone();
    extension_statement.provenance = vec![extension_record.id.clone()];
    assert!(matches!(
        author_python_callable_shape_evidence(
            &extension_receiver,
            extension_statement,
            extension_record
        ),
        Err(CsmiShapeAuthoringError::UnsupportedMember(_))
    ));

    let mut zero_result_pack = imported.pack;
    for shard in &mut zero_result_pack.shards {
        shard.conditional_type_refinements = None;
        if let AuthoredPayload::DeclarationFacts { members, .. } = &mut shard.payload {
            let mut authored = zero_result.clone();
            let Locator::Interchange {
                callable_shape_evidence,
                ..
            } = &mut authored.locator
            else {
                unreachable!("imported callable has a portable locator");
            };
            *callable_shape_evidence = Some(Box::new(zero_result_evidence.clone()));
            members[0] = authored;
        }
    }
    let artifact = CsmiArtifactEvidence::new(
        "pkg:generic/python-runtime@3.12.0?component=stdlib&implementation=cpython",
        "a".repeat(64),
    );
    let exported =
        export_authored_csmi_pack(&zero_result_pack, &artifact, &CsmiExportOptions::default())
            .expect("explicit complete zero-result shape exports");
    let restored = import_logical_csmi_pack(&exported, &support, &CompilerOptions::default())
        .expect("zero-result shape round trips");
    let restored_member = restored
        .pack
        .shards
        .iter()
        .find_map(|shard| match &shard.payload {
            AuthoredPayload::DeclarationFacts { members, .. } => members.first(),
            _ => None,
        })
        .expect("round-tripped callable");
    assert_eq!(restored_member.signature.as_ref().unwrap().returns, None);
}

#[test]
fn python_distribution_requires_resolved_import_root_and_callable_binding() {
    let mut value = json!({
        "artifactSelectors": [{
            "purl": "pkg:pypi/beautifulsoup4@4.13.0",
            "digests": [{"algorithm":"sha-256", "coverage":"artifact", "value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]
        }],
        "vocabularyUses": [{
            "identifier": "csmi.python", "version": "0.1.0",
            "schema": "https://csmi.brokk.ai/schema/profiles/python/0.1/schema.json",
            "requirement": "required",
            "affects": [
                {"kind":"core-slot", "slot":"symbol-identity-scheme", "target":{"model":"self"}},
                {"kind":"fact-family", "family":"distribution-imports", "scope":{"artifact":"model"}},
                {"kind":"fact-family", "family":"import-bindings", "scope":{"module":"bs4"}}
            ]
        }],
        "symbols": [
            {"id":"bs4", "scheme":"csmi.python", "schemeVersion":"0.1.0", "stability":"portable",
             "descriptors":[{"role":"namespace", "name":"bs4"}]},
            {"id":"parse", "scheme":"csmi.python", "schemeVersion":"0.1.0", "stability":"portable",
             "descriptors":[{"role":"namespace", "name":"bs4"}, {"role":"callable", "name":"parse"}]}
        ],
        "declarations": [
            {"symbol":"bs4", "category":"namespace"},
            {"symbol":"parse", "category":"callable", "owner":"bs4",
             "callable":{"kind":"function", "parameters":[{"position":0,"binding":"positional-or-named","label":"value","required":true}], "results":[{"position":0}]}}
        ],
        "procedureSummaries": [{"callable":"parse", "transfers":[{
            "source":{"root":{"phase":"input","role":"parameter","position":0}},
            "destination":{"root":{"phase":"output","role":"result","position":0}}
        }]}],
        "extensionFacts": [
            {"vocabulary":"csmi.python", "version":"0.1.0", "family":"distribution-imports", "scope":{"artifact":"model"},
             "payload":{"kind":"distribution-imports", "importRoots":[["bs4"]]}},
            {"vocabulary":"csmi.python", "version":"0.1.0", "family":"import-bindings", "scope":{"module":"bs4"},
             "payload":{"kind":"import-bindings", "bindings":[{"name":"parse","bindingKind":"definition","target":"parse"}]}}
        ]
    });
    let model: CsmiSemanticModel = serde_json::from_value(value.clone()).unwrap();
    super::python::validate_model(&model).expect("PyPI name need not resemble import root");

    for (vocabulary, version) in [("csmi.other", "0.1.0"), ("csmi.python", "0.2.0")] {
        let mut unsupported_constraint = value.clone();
        unsupported_constraint["compatibilityConstraints"] = json!([{
            "vocabulary": vocabulary,
            "version": version,
            "value": {"kind":"compatibility", "python":"3.12.0"}
        }]);
        let unsupported_constraint: CsmiSemanticModel =
            serde_json::from_value(unsupported_constraint).unwrap();
        assert!(super::python::validate_model(&unsupported_constraint).is_err());
    }
    let mut missing_compatibility_use = value.clone();
    missing_compatibility_use["compatibilityConstraints"] = json!([{
        "vocabulary":"csmi.python", "version":"0.1.0",
        "value":{"kind":"compatibility", "python":"3.12.0"}
    }]);
    let missing_compatibility_use: CsmiSemanticModel =
        serde_json::from_value(missing_compatibility_use).unwrap();
    assert!(super::python::validate_model(&missing_compatibility_use).is_err());
    let mut optional_compatibility_use = value.clone();
    optional_compatibility_use["vocabularyUses"][0]["requirement"] = json!("optional");
    optional_compatibility_use["compatibilityConstraints"] = json!([{
        "vocabulary":"csmi.python", "version":"0.1.0",
        "value":{"kind":"compatibility", "python":"3.12.0"}
    }]);
    let optional_compatibility_use: CsmiSemanticModel =
        serde_json::from_value(optional_compatibility_use).unwrap();
    assert!(super::python::validate_model(&optional_compatibility_use).is_err());

    let mut malformed_fact_condition = value.clone();
    malformed_fact_condition["extensionFacts"][0]["payload"]["conditions"] =
        json!({"implementation":"cpython"});
    let malformed_fact_condition: CsmiSemanticModel =
        serde_json::from_value(malformed_fact_condition).unwrap();
    assert!(super::python::validate_model(&malformed_fact_condition).is_err());
    let mut malformed_binding_condition = value.clone();
    malformed_binding_condition["extensionFacts"][1]["payload"]["bindings"][0]["conditions"] =
        json!({"implementation":"cpython"});
    let malformed_binding_condition: CsmiSemanticModel =
        serde_json::from_value(malformed_binding_condition).unwrap();
    assert!(super::python::validate_model(&malformed_binding_condition).is_err());

    value["extensionFacts"][1]["payload"]["bindings"] = json!([
        {"name":"parse", "bindingKind":"definition", "target":"parse"},
        {"name":"parse_alias", "bindingKind":"alias", "target":"parse"},
        {"name":"parse_export", "bindingKind":"re-export", "target":"parse"}
    ]);
    let retained_aliases: CsmiSemanticModel = serde_json::from_value(value.clone()).unwrap();
    super::python::validate_model(&retained_aliases)
        .expect("extra aliases may retain the exact defining target");
    value["extensionFacts"][1]["payload"]["bindings"] = json!([
        {"name":"parse", "bindingKind":"definition", "target":"parse"}
    ]);

    value["extensionFacts"][0]["payload"]["importRoots"] = json!([["beautifulsoup4"]]);
    let wrong_root: CsmiSemanticModel = serde_json::from_value(value.clone()).unwrap();
    assert!(super::python::validate_model(&wrong_root).is_err());
    value["extensionFacts"][0]["payload"]["importRoots"] = json!([["bs4"]]);
    for binding_kind in ["alias", "re-export"] {
        value["extensionFacts"][1]["payload"]["bindings"][0]["bindingKind"] = json!(binding_kind);
        let unresolved_alias: CsmiSemanticModel = serde_json::from_value(value.clone()).unwrap();
        assert!(super::python::validate_model(&unresolved_alias).is_err());
    }
    value["extensionFacts"][1]["payload"]["bindings"][0]["bindingKind"] = json!("definition");
    value["extensionFacts"][1]["payload"]["bindings"][0]["name"] = json!("other");
    let wrong_name: CsmiSemanticModel = serde_json::from_value(value.clone()).unwrap();
    assert!(super::python::validate_model(&wrong_name).is_err());
    value["extensionFacts"][1]["payload"]["bindings"][0]["name"] = json!("parse");
    value["extensionFacts"][1]["payload"]["bindings"][0]["target"] = json!("bs4");
    let wrong_binding: CsmiSemanticModel = serde_json::from_value(value).unwrap();
    assert!(super::python::validate_model(&wrong_binding).is_err());
}

pub(crate) fn rewrite_raw_declaration_shard(
    compiled: &mut crate::analyzer::semantic_model::CompiledSemanticModelPack,
    change: impl FnOnce(
        &mut Vec<crate::analyzer::semantic_model::TypeFact>,
        &mut Vec<crate::analyzer::semantic_model::MemberFact>,
    ),
) {
    use crate::analyzer::semantic_model::artifact::{
        canonical_json, content_digest, manifest_content_digest, manifest_semantic_digest,
        semantic_digest, stored_digest,
    };
    use crate::analyzer::semantic_model::{CompiledPayload, DecodeLimits, decode_shard};
    let shard = compiled
        .shards
        .iter_mut()
        .find(|shard| {
            shard.descriptor.payload_kind
                == crate::analyzer::semantic_model::PayloadKind::DeclarationFacts
        })
        .unwrap();
    let mut decoded =
        decode_shard(&shard.descriptor, &shard.bytes, &DecodeLimits::default()).unwrap();
    let CompiledPayload::DeclarationFacts { types, members, .. } = &mut decoded.payload else {
        unreachable!();
    };
    change(types, members);
    let raw = canonical_json(&decoded).unwrap();
    shard.descriptor.raw_size = raw.len() as u64;
    shard.descriptor.stored_size = raw.len() as u64;
    shard.descriptor.semantic_sha256 = semantic_digest(&decoded).unwrap();
    shard.descriptor.content_sha256 = content_digest(&raw);
    shard.descriptor.stored_sha256 = stored_digest(&raw);
    shard.bytes = raw;
    let descriptor = compiled
        .manifest
        .shards
        .iter_mut()
        .find(|descriptor| descriptor.shard_id == shard.descriptor.shard_id)
        .unwrap();
    *descriptor = shard.descriptor.clone();
    compiled.manifest.semantic_sha256 = manifest_semantic_digest(&compiled.manifest).unwrap();
    compiled.manifest.content_sha256 = manifest_content_digest(&compiled.manifest).unwrap();
    compiled.manifest_bytes = canonical_json(&compiled.manifest).unwrap();
}

#[test]
fn python_distribution_round_trip_retains_resolver_facts_and_provenance() {
    let source = include_bytes!("fixtures/python-distribution-beautifulsoup4.json");
    let mut original: Value = serde_json::from_slice(source).unwrap();
    let project_config = json!({
        "algorithm":"sha-256",
        "coverage":"resolver-affecting-config",
        "canonicalization":"https://brokk.ai/bifrost/python-declared-environment/v1",
        "value":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    });
    let model = &mut original["semanticModels"][0];
    model["vocabularyUses"][0]["affects"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "kind":"core-slot",
            "slot":"artifact-compatibility",
            "target":{"semanticModel":"current"}
        }));
    model["compatibilityConstraints"] = json!([{
        "vocabulary":"csmi.python",
        "version":"0.1.0",
        "value":{"kind":"compatibility", "python":"3.12.0", "projectConfig":project_config.clone()}
    }]);
    model["extensionFacts"][0]["payload"]["conditions"] = json!({
        "python":"3.12.0",
        "projectConfig":project_config.clone()
    });
    model["extensionFacts"][1]["payload"]["bindings"][0]["conditions"] = json!({
        "implementation":["cpython"],
        "projectConfig":project_config.clone()
    });
    let source = serde_json::to_vec(&original).unwrap();
    let support = CsmiVocabularySupport::support(
        CSMI_PYTHON_PROFILE_ID,
        CSMI_PYTHON_PROFILE_VERSION,
        CSMI_PYTHON_PROFILE_SCHEMA,
    );
    let portable = logical_pack_from_semantic(&source);
    let imported = import_logical_csmi_pack(&portable, &support, &CompilerOptions::default())
        .expect("resolver-proven distribution imports");
    assert!(super::python::validate_native_identities(&imported.pack).is_empty());
    assert!(super::python::validate_profile_evidence(&imported.pack).is_empty());
    let profile = imported
        .pack
        .shards
        .iter()
        .find_map(|shard| match &shard.payload {
            AuthoredPayload::DeclarationFacts { types, members, .. } => types
                .iter()
                .map(|fact| &fact.locator)
                .chain(members.iter().map(|fact| &fact.locator))
                .find_map(|locator| match locator {
                    crate::analyzer::semantic_model::Locator::Interchange {
                        profile_evidence: Some(evidence),
                        ..
                    } => Some(evidence),
                    _ => None,
                }),
            _ => None,
        })
        .expect("Python profile evidence is retained on a declaration");
    assert_eq!(
        serde_json::to_value(&profile.compatibility_constraints).unwrap(),
        original["semanticModels"][0]["compatibilityConstraints"]
    );
    let mut wrong_constraint_kind = original.clone();
    wrong_constraint_kind["semanticModels"][0]["compatibilityConstraints"][0]["value"] =
        original["semanticModels"][0]["extensionFacts"][0]["payload"].clone();
    let wrong_constraint_pack =
        logical_pack_from_semantic(&serde_json::to_vec(&wrong_constraint_kind).unwrap());
    assert!(
        import_logical_csmi_pack(
            &wrong_constraint_pack,
            &support,
            &CompilerOptions::default()
        )
        .is_err(),
        "a schema-valid distribution payload cannot act as a compatibility constraint"
    );
    let artifact = CsmiArtifactEvidence::new("pkg:pypi/beautifulsoup4@4.13.0", "a".repeat(64));
    let exported =
        export_authored_csmi_pack(&imported.pack, &artifact, &CsmiExportOptions::default())
            .expect("distribution profile evidence exports");
    let output = semantic_value(&exported);
    assert_eq!(
        output["semanticModels"][0]["compatibilityConstraints"],
        original["semanticModels"][0]["compatibilityConstraints"]
    );
    let output_facts = output["semanticModels"][0]["extensionFacts"]
        .as_array()
        .unwrap();
    for fact in original["semanticModels"][0]["extensionFacts"]
        .as_array()
        .unwrap()
    {
        assert!(output_facts.contains(fact), "resolver fact changed: {fact}");
    }
    assert!(
        output["provenanceRecords"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["id"] == "resolver"
                && record["producer"]["identifier"] == "https://example.org/python-resolver")
    );
    assert_eq!(
        output["semanticModels"][0]["procedureSummaries"][0]["transfers"],
        original["semanticModels"][0]["procedureSummaries"][0]["transfers"]
    );
    let restored = import_logical_csmi_pack(&exported, &support, &CompilerOptions::default())
        .expect("exported distribution imports with retained facts");
    assert_eq!(restored.pack.language, "python");

    let compiled = imported
        .compile(&CompilerOptions {
            compression: crate::analyzer::semantic_model::CompressionPolicy::AlwaysRaw,
            ..CompilerOptions::default()
        })
        .expect("distribution compiles to native shards");
    let fresh_manifest = crate::analyzer::semantic_model::decode_manifest(
        &compiled.manifest_bytes,
        &crate::analyzer::semantic_model::DecodeLimits::default(),
    )
    .unwrap();
    let mut fresh = crate::analyzer::semantic_model::CompiledSemanticModelPack {
        manifest: fresh_manifest,
        manifest_bytes: compiled.manifest_bytes.clone(),
        shards: compiled.shards.clone(),
    };
    assert!(fresh.shards.len() > 1);
    fresh.shards.reverse();
    for shard in &fresh.shards {
        crate::analyzer::semantic_model::decode_shard_for_manifest(
            &fresh.manifest,
            &shard.descriptor,
            &shard.bytes,
            &crate::analyzer::semantic_model::DecodeLimits::default(),
        )
        .expect("fresh shard decodes against canonical manifest");
    }
    let reexported = export_csmi_pack(&fresh, &artifact, &CsmiExportOptions::default())
        .expect("reordered fresh native shards retain full-pack evidence");
    let native_output = semantic_value(&reexported);
    assert_eq!(
        native_output["semanticModels"][0]["compatibilityConstraints"],
        original["semanticModels"][0]["compatibilityConstraints"]
    );
    assert_eq!(
        native_output["semanticModels"][0]["extensionFacts"],
        output["semanticModels"][0]["extensionFacts"]
    );

    let mut changed_fact = fresh.clone();
    rewrite_raw_declaration_shard(&mut changed_fact, |_, members| {
        members[0].signature.as_mut().unwrap().parameters[0].name = Some("renamed".to_owned());
    });
    let changed_shard = changed_fact
        .shards
        .iter()
        .find(|shard| {
            shard.descriptor.payload_kind
                == crate::analyzer::semantic_model::PayloadKind::DeclarationFacts
        })
        .unwrap();
    let decode_error = decode_shard(
        &changed_shard.descriptor,
        &changed_shard.bytes,
        &DecodeLimits::default(),
    )
    .unwrap_err();
    assert!(
        matches!(decode_error, crate::analyzer::semantic_model::ArtifactError::SemanticValidation(ref diagnostics) if diagnostics.iter().any(|diagnostic| diagnostic.code == "locator.interchange_callable_shape")),
        "rebuilt-hash member shard should reject stale shape evidence: {decode_error:?}"
    );
    assert!(matches!(
        export_csmi_pack(&changed_fact, &artifact, &CsmiExportOptions::default()),
        Err(CsmiExportError::Canonical(_))
    ));

    let mut changed_member_authored = imported.pack.clone();
    for shard in &mut changed_member_authored.shards {
        if let AuthoredPayload::DeclarationFacts { members, .. } = &mut shard.payload {
            members[0].signature.as_mut().unwrap().parameters[0].name = Some("renamed".to_owned());
        }
    }
    assert!(
        super::python::validate_native_identities(&changed_member_authored)
            .iter()
            .any(|diagnostic| diagnostic.code == "locator.interchange_callable_shape"),
        "member-local evidence must reject a changed signature"
    );

    let mut changed_other_fact = fresh.clone();
    rewrite_raw_declaration_shard(&mut changed_other_fact, |types, _| {
        types[0].visibility = Visibility::Private;
    });
    assert!(matches!(
        export_csmi_pack(
            &changed_other_fact,
            &artifact,
            &CsmiExportOptions::default()
        ),
        Err(CsmiExportError::Canonical(_))
    ));
    let mut changed_other_authored = imported.pack.clone();
    for shard in &mut changed_other_authored.shards {
        if let AuthoredPayload::DeclarationFacts { types, .. } = &mut shard.payload {
            types[0].visibility = Visibility::Private;
        }
    }
    assert!(
        super::python::validate_profile_evidence(&changed_other_authored)
            .iter()
            .any(|diagnostic| diagnostic.code == "python.profile_evidence_mismatch"),
        "full-pack carrier must reject a changed unrelated type fact"
    );

    let mut missing_carrier = fresh.clone();
    rewrite_raw_declaration_shard(&mut missing_carrier, |types, _| {
        for fact in types {
            if let crate::analyzer::semantic_model::Locator::Interchange {
                profile_evidence, ..
            } = &mut fact.locator
            {
                *profile_evidence = None;
            }
        }
    });
    let error =
        export_csmi_pack(&missing_carrier, &artifact, &CsmiExportOptions::default()).unwrap_err();
    assert!(format!("{error:?}").contains("python.profile_evidence_count"));

    let mut duplicate_carrier = fresh.clone();
    rewrite_raw_declaration_shard(&mut duplicate_carrier, |types, _| {
        let evidence = types
            .iter()
            .find_map(|fact| match &fact.locator {
                crate::analyzer::semantic_model::Locator::Interchange {
                    profile_evidence, ..
                } => profile_evidence.clone(),
                _ => None,
            })
            .unwrap();
        let other = types
            .iter_mut()
            .find(|fact| {
                matches!(
                    &fact.locator,
                    crate::analyzer::semantic_model::Locator::Interchange {
                        profile_evidence: None,
                        ..
                    }
                )
            })
            .unwrap();
        if let crate::analyzer::semantic_model::Locator::Interchange {
            profile_evidence, ..
        } = &mut other.locator
        {
            *profile_evidence = Some(evidence);
        }
    });
    let error =
        export_csmi_pack(&duplicate_carrier, &artifact, &CsmiExportOptions::default()).unwrap_err();
    assert!(format!("{error:?}").contains("python.profile_evidence_count"));

    let wrong_digest = CsmiArtifactEvidence::new("pkg:pypi/beautifulsoup4@4.13.0", "b".repeat(64));
    assert!(
        export_authored_csmi_pack(&imported.pack, &wrong_digest, &CsmiExportOptions::default())
            .is_err()
    );
    let mut changed = imported.pack;
    for shard in &mut changed.shards {
        if let AuthoredPayload::DeclarationFacts { members, .. } = &mut shard.payload {
            members
                .iter_mut()
                .find(|member| member.name == "parse")
                .unwrap()
                .name = "replaced".to_owned();
        }
    }
    assert!(export_authored_csmi_pack(&changed, &artifact, &CsmiExportOptions::default()).is_err());
}

#[test]
fn python_distribution_round_trip_preserves_formal_binding_slots() {
    let mut original: Value = serde_json::from_slice(include_bytes!(
        "fixtures/python-distribution-beautifulsoup4.json"
    ))
    .unwrap();
    let parameters = [
        ("positional-only", "first"),
        ("positional-or-named", "second"),
        ("variadic-positional", "args"),
        ("named-only", "option"),
        ("variadic-named", "kwargs"),
    ]
    .into_iter()
    .enumerate()
    .map(|(position, (binding, label))| {
        json!({
            "position": position,
            "binding": binding,
            "label": label,
            "required": position < 2,
            "type": {"kind": "reference", "symbol": "Text"}
        })
    })
    .collect::<Vec<_>>();
    original["semanticModels"][0]["declarations"][2]["callable"]["parameters"] = json!(parameters);
    original["semanticModels"][0]["procedureSummaries"][0]["transfers"][0]["source"]["root"]["position"] =
        json!(3);
    let source = serde_json::to_vec(&original).unwrap();
    let support = CsmiVocabularySupport::support(
        CSMI_PYTHON_PROFILE_ID,
        CSMI_PYTHON_PROFILE_VERSION,
        CSMI_PYTHON_PROFILE_SCHEMA,
    );
    let imported = import_logical_csmi_pack(
        &logical_pack_from_semantic(&source),
        &support,
        &CompilerOptions::default(),
    )
    .expect("all five formal binding kinds import structurally");
    let native_member = imported
        .pack
        .shards
        .iter()
        .find_map(|shard| match &shard.payload {
            AuthoredPayload::DeclarationFacts { members, .. } => members.first(),
            _ => None,
        })
        .unwrap();
    assert!(
        !native_member.callable_family_complete,
        "one complete CSMI shape does not close a native variadic callable family"
    );
    let artifact = CsmiArtifactEvidence::new("pkg:pypi/beautifulsoup4@4.13.0", "a".repeat(64));
    let exported =
        export_authored_csmi_pack(&imported.pack, &artifact, &CsmiExportOptions::default())
            .expect("formal binding kinds export without positional reinterpretation");
    let output = semantic_value(&exported);
    let exported_callable = output["semanticModels"][0]["declarations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|declaration| declaration["symbol"] == "parse")
        .unwrap();
    assert_eq!(
        exported_callable["callable"]["parameters"],
        original["semanticModels"][0]["declarations"][2]["callable"]["parameters"]
    );
    assert_eq!(
        output["semanticModels"][0]["procedureSummaries"][0]["transfers"],
        original["semanticModels"][0]["procedureSummaries"][0]["transfers"]
    );

    let mut changed = imported.pack.clone();
    for shard in &mut changed.shards {
        if let AuthoredPayload::DeclarationFacts { members, .. } = &mut shard.payload {
            members[0].signature.as_mut().unwrap().parameters[3].name = Some("changed".to_owned());
        }
    }
    assert!(
        export_authored_csmi_pack(&changed, &artifact, &CsmiExportOptions::default()).is_err(),
        "mutated native shape cannot borrow retained complete shape evidence"
    );
}

#[test]
fn python_distribution_partial_and_unknown_shape_coverage_survives_round_trip() {
    for status in ["partial", "unknown"] {
        let mut value: Value = serde_json::from_slice(include_bytes!(
            "fixtures/python-distribution-beautifulsoup4.json"
        ))
        .unwrap();
        let statements = value["semanticModels"][0]["completenessStatements"]
            .as_array_mut()
            .unwrap();
        let shape = statements
            .iter_mut()
            .find(|statement| statement["family"] == "declaration-aspects")
            .unwrap();
        shape["status"] = json!(status);
        shape["limitations"] = json!([{"kind":"coverage-limited"}]);
        let support = CsmiVocabularySupport::support(
            CSMI_PYTHON_PROFILE_ID,
            CSMI_PYTHON_PROFILE_VERSION,
            CSMI_PYTHON_PROFILE_SCHEMA,
        );
        let imported = import_logical_csmi_pack(
            &logical_pack_from_semantic(&serde_json::to_vec(&value).unwrap()),
            &support,
            &CompilerOptions::default(),
        )
        .expect("partial or unknown shape does not imply callable-family closure");
        let artifact = CsmiArtifactEvidence::new("pkg:pypi/beautifulsoup4@4.13.0", "a".repeat(64));
        let exported =
            export_authored_csmi_pack(&imported.pack, &artifact, &CsmiExportOptions::default())
                .expect("shape coverage exports without promotion");
        let output = semantic_value(&exported);
        let shape = output["semanticModels"][0]["completenessStatements"]
            .as_array()
            .unwrap()
            .iter()
            .find(|statement| statement["family"] == "declaration-aspects")
            .unwrap();
        assert_eq!(shape["status"], status);
        assert_eq!(shape["limitations"], json!([{"kind":"coverage-limited"}]));
    }
}

#[test]
fn python_two_artifact_shards_select_independently() {
    let stub_purl = "pkg:pypi/types-beautifulsoup4@4.13.0";
    let runtime_purl = "pkg:pypi/beautifulsoup4@4.13.0";
    let stub_digest = "a".repeat(64);
    let runtime_digest = "b".repeat(64);
    let source = json!({
        "schema_version": 2,
        "pack_id": "test.python-two-artifact-activation",
        "version": "1.0.0",
        "producer": {"name":"two-artifact-test", "version":"1.0.0"},
        "language": "python",
        "ecosystem": "python",
        "compatibility": {"bifrost": ">=0.8.0, <1.0.0"},
        "provenance": {"source":"checked-in two-artifact activation test"},
        "license": "Apache-2.0",
        "completeness": "complete",
        "safety": {"generated_code_only":false, "review_required":false},
        "shards": [{
            "id":"python.stub",
            "activation":[{"package":{"name":stub_purl},"artifact_sha256":stub_digest.clone()}],
            "payload":{"kind":"declaration_facts","types":[{
                "id":"stub.bs4", "name":"bs4", "type_kind":"module",
                "visibility":"public", "locator":{"kind":"artifact","path":"bs4/__init__.pyi","symbol":"bs4"}
            }],"members":[],"relations":[]}
        },{
            "id":"python.runtime",
            "activation":[{"package":{"name":runtime_purl},"artifact_sha256":runtime_digest.clone()}],
            "payload":{"kind":"procedure_summaries","summaries":[{
                "id":"summary.bs4.parse",
                "target":{"path":"bs4/__init__.py","symbol":"bs4.parse(value)","has_receiver":false,"parameter_count":1},
                "completeness":"partial",
                "transfers":[{"input":{"kind":"parameter","ordinal":0},"exit_kind":"normal","output":{"kind":"normal_return"}}]
            }]}
        }]
    });
    let compiled = compile_source(
        SourceFormat::Json,
        &serde_json::to_vec(&source).unwrap(),
        &CompilerOptions::default(),
    )
    .expect("the two-artifact pack admits both exact shards together");
    assert_eq!(compiled.shards.len(), 2);
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    catalog
        .register_session_pack(
            &compiled,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "python-two-artifact-test".to_owned(),
            },
        )
        .expect("whole-pack admission verifies both shards");
    let row = |purl: &str, digest: String| SemanticModelActivationEvidence {
        language: "python".to_owned(),
        ecosystem: "python".to_owned(),
        package: Some(CatalogCoordinate {
            name: purl.to_owned(),
            version: None,
        }),
        module: None,
        toolchain: None,
        target: None,
        configuration: None,
        artifact_sha256: Some(digest),
    };
    let summary =
        ProcedureSummaryTargetKey::new("python", "bs4/__init__.py", "bs4.parse(value)", false, 1);
    for (evidence, expected_shards, expected_summaries) in [
        (
            vec![row(stub_purl, stub_digest.clone())],
            vec!["python.stub"],
            0,
        ),
        (
            vec![row(runtime_purl, runtime_digest.clone())],
            vec!["python.runtime"],
            1,
        ),
        (
            vec![
                row(stub_purl, stub_digest.clone()),
                row(runtime_purl, runtime_digest.clone()),
            ],
            vec!["python.runtime", "python.stub"],
            1,
        ),
        (
            vec![
                row(stub_purl, stub_digest.clone()),
                row(runtime_purl, "c".repeat(64)),
            ],
            vec!["python.stub"],
            0,
        ),
    ] {
        let request = SemanticModelActivationRequest {
            bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
            evidence,
            controls: Vec::new(),
            limits: Default::default(),
        };
        let active =
            match resolve_active_semantic_models(&catalog, &request, &CancellationToken::default())
            {
                SemanticModelResolutionOutcome::Ready(active) => active,
                other => panic!("two-artifact activation was not ready: {other:#?}"),
            };
        let mut selected = active
            .shards()
            .iter()
            .map(|shard| shard.shard.shard_id())
            .collect::<Vec<_>>();
        selected.sort_unstable();
        assert_eq!(selected, expected_shards);
        assert_eq!(
            active.procedure_summaries_for(summary).records.len(),
            expected_summaries
        );
    }
}

#[test]
fn python_cross_artifact_correspondence_survives_durable_round_trip() {
    use crate::analyzer::semantic_model::{
        CatalogOpenMode, DurablePackSource, DurablePackSourceKind,
    };
    let source = include_bytes!("fixtures/python-stub-runtime-correspondence.json");
    let support = CsmiVocabularySupport::support(
        CSMI_PYTHON_PROFILE_ID,
        CSMI_PYTHON_PROFILE_VERSION,
        CSMI_PYTHON_PROFILE_SCHEMA,
    );
    let imported = import_logical_csmi_pack(
        &logical_pack_from_semantic(source),
        &support,
        &CompilerOptions::default(),
    )
    .expect("explicit exact stub/runtime correspondence imports");
    let relation = imported
        .pack
        .python_correspondence
        .as_ref()
        .expect("correspondence has a typed native carrier");
    assert_eq!(relation.mappings.len(), 2);
    assert!(
        relation
            .mappings
            .iter()
            .any(|mapping| mapping.declaration == "parse" && mapping.runtime == "runtime-parse")
    );
    assert_eq!(relation.provenance_records[0].id, "resolver");
    assert_eq!(relation.default_provenance.as_deref(), Some("resolver"));
    let compiled = imported.compile(&CompilerOptions::default()).unwrap();
    let root = tempfile::tempdir().unwrap();
    let catalog = SemanticPackCatalog::open(
        root.path(),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    catalog
        .install(
            &compiled,
            &DurablePackSource {
                kind: DurablePackSourceKind::Installed,
                source_id: "python-stub-runtime-test".to_owned(),
            },
        )
        .expect("whole multi-artifact pack admits before activation");
    drop(catalog);
    let reopened = SemanticPackCatalog::open(
        root.path(),
        CatalogOpenMode::ReadOnly,
        CatalogOptions::default(),
    )
    .unwrap();
    let stub_purl = "pkg:pypi/types-beautifulsoup4@4.13.0";
    let runtime_purl = "pkg:pypi/beautifulsoup4@4.13.0";
    let row = |purl: &str, digest: String| SemanticModelActivationEvidence {
        language: "python".to_owned(),
        ecosystem: "python".to_owned(),
        package: Some(CatalogCoordinate {
            name: purl.to_owned(),
            version: None,
        }),
        module: None,
        toolchain: None,
        target: None,
        configuration: None,
        artifact_sha256: Some(digest),
    };
    let target = ProcedureSummaryTargetKey::new("python", "bs4", "bs4.parse", false, 1);
    for (evidence, expected_summaries) in [
        (vec![row(stub_purl, "b".repeat(64))], 0),
        (vec![row(runtime_purl, "a".repeat(64))], 1),
        (
            vec![
                row(stub_purl, "b".repeat(64)),
                row(runtime_purl, "a".repeat(64)),
            ],
            1,
        ),
        (
            vec![
                row(stub_purl, "b".repeat(64)),
                row(runtime_purl, "c".repeat(64)),
            ],
            0,
        ),
    ] {
        let request = SemanticModelActivationRequest {
            bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
            evidence,
            controls: Vec::new(),
            limits: Default::default(),
        };
        let active = match resolve_active_semantic_models(
            &reopened,
            &request,
            &CancellationToken::default(),
        ) {
            SemanticModelResolutionOutcome::Ready(active) => active,
            other => panic!("cross-artifact activation was not ready: {other:#?}"),
        };
        assert_eq!(
            active.procedure_summaries_for(target).records.len(),
            expected_summaries
        );
    }
    let exported = export_csmi_pack(
        &compiled,
        &CsmiArtifactEvidence::new(stub_purl, "b".repeat(64)),
        &CsmiExportOptions::default(),
    )
    .expect("reopened exact relation exports without flattening its condition");
    let output = semantic_value(&exported);
    let original: Value = serde_json::from_slice(source).unwrap();
    for family in ["declaration-records", "procedure-summaries"] {
        let statement = |document: &Value| {
            document["semanticModels"][0]["completenessStatements"]
                .as_array()
                .unwrap()
                .iter()
                .find(|statement| statement["family"] == family)
                .unwrap()
                .clone()
        };
        assert_eq!(statement(&output), statement(&original));
    }
    let mappings = output["semanticModels"][0]["extensionFacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|fact| fact["family"] == "declaration-correspondence")
        .unwrap()["payload"]["mappings"]
        .as_array()
        .unwrap();
    assert_eq!(
        mappings
            .iter()
            .find(|mapping| mapping["declaration"] == "parse")
            .unwrap()["conditions"]["python"],
        "3.13.0"
    );
    assert!(
        output["provenanceRecords"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["id"] == "resolver")
    );
    let reimported = import_logical_csmi_pack(&exported, &support, &CompilerOptions::default())
        .expect("exported correspondence reimports");
    assert_eq!(
        reimported
            .pack
            .python_correspondence
            .as_ref()
            .unwrap()
            .mappings,
        relation.mappings
    );
}

#[test]
fn python_cross_artifact_correspondence_revalidates_carrier_and_native_facts() {
    let source = include_bytes!("fixtures/python-stub-runtime-correspondence.json");
    let support = CsmiVocabularySupport::support(
        CSMI_PYTHON_PROFILE_ID,
        CSMI_PYTHON_PROFILE_VERSION,
        CSMI_PYTHON_PROFILE_SCHEMA,
    );
    let imported = import_logical_csmi_pack(
        &logical_pack_from_semantic(source),
        &support,
        &CompilerOptions::default(),
    )
    .unwrap();
    let mut reordered = imported.pack.clone();
    reordered
        .python_correspondence
        .as_mut()
        .unwrap()
        .mappings
        .reverse();
    assert!(super::python::validate_profile_evidence(&reordered).is_empty());

    let mut missing = imported.pack.clone();
    missing.python_correspondence = None;
    assert!(!super::python::validate_profile_evidence(&missing).is_empty());

    let mut duplicate = imported.pack.clone();
    {
        let evidence = duplicate.python_correspondence.as_mut().unwrap();
        evidence.mappings.push(evidence.mappings[0].clone());
    }
    let digest = super::python::native_correspondence_digest(&duplicate);
    duplicate
        .python_correspondence
        .as_mut()
        .unwrap()
        .native_sha256 = digest;
    assert!(
        super::python::validate_profile_evidence(&duplicate)
            .iter()
            .any(|diagnostic| diagnostic.code == "python.correspondence_duplicate_mapping")
    );

    let mut invalid_condition = imported.pack.clone();
    let evidence = invalid_condition.python_correspondence.as_mut().unwrap();
    let mapping = evidence
        .mappings
        .iter_mut()
        .find(|mapping| mapping.declaration == "parse")
        .unwrap();
    mapping.conditions = Some(json!({"futureCondition":"trusted"}));
    let fact = evidence
        .extension_facts
        .iter_mut()
        .find(|fact| fact.family == "declaration-correspondence")
        .unwrap();
    fact.payload["mappings"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|mapping| mapping["declaration"] == "parse")
        .unwrap()["conditions"] = json!({"futureCondition":"trusted"});
    let digest = super::python::native_correspondence_digest(&invalid_condition);
    invalid_condition
        .python_correspondence
        .as_mut()
        .unwrap()
        .native_sha256 = digest;
    assert!(
        super::python::validate_profile_evidence(&invalid_condition)
            .iter()
            .any(|diagnostic| diagnostic.code == "python.correspondence_payload_schema")
    );

    let mut lost_producer = imported.pack.clone();
    lost_producer
        .python_correspondence
        .as_mut()
        .unwrap()
        .provenance_records
        .clear();
    lost_producer
        .python_correspondence
        .as_mut()
        .unwrap()
        .native_sha256 = super::python::native_correspondence_digest(&lost_producer);
    assert!(
        super::python::validate_profile_evidence(&lost_producer)
            .iter()
            .any(|diagnostic| diagnostic.code == "python.correspondence_provenance_missing")
    );

    let mut lost_core = imported.pack.clone();
    lost_core
        .python_correspondence
        .as_mut()
        .unwrap()
        .core_completeness_statements
        .clear();
    lost_core
        .python_correspondence
        .as_mut()
        .unwrap()
        .native_sha256 = super::python::native_correspondence_digest(&lost_core);
    assert!(
        super::python::validate_profile_evidence(&lost_core)
            .iter()
            .any(|diagnostic| diagnostic.code == "python.correspondence_core_coverage_missing")
    );

    let mut contradictory_core = imported.pack.clone();
    let core = &mut contradictory_core
        .python_correspondence
        .as_mut()
        .unwrap()
        .core_completeness_statements;
    assert_eq!(
        core.iter()
            .filter(|statement| statement.family == "declaration-records")
            .count(),
        1
    );
    let declaration_coverage = core
        .iter_mut()
        .find(|statement| statement.family == "declaration-records")
        .unwrap();
    declaration_coverage.status = CsmiCoverageStatus::Complete;
    declaration_coverage.limitations.clear();
    contradictory_core
        .python_correspondence
        .as_mut()
        .unwrap()
        .native_sha256 = super::python::native_correspondence_digest(&contradictory_core);
    assert!(
        super::python::validate_profile_evidence(&contradictory_core)
            .iter()
            .any(|diagnostic| diagnostic.code == "python.correspondence_core_coverage_status")
    );

    let mut orphaned_symbol = imported.pack.clone();
    orphaned_symbol
        .python_correspondence
        .as_mut()
        .unwrap()
        .symbols[0]
        .provenance = vec!["missing-original-record".to_owned()];
    orphaned_symbol
        .python_correspondence
        .as_mut()
        .unwrap()
        .native_sha256 = super::python::native_correspondence_digest(&orphaned_symbol);
    assert!(
        super::python::validate_profile_evidence(&orphaned_symbol)
            .iter()
            .any(|diagnostic| diagnostic.code == "python.correspondence_provenance_missing")
    );

    for (name, code, pack) in [
        (
            "lost-core",
            "python.correspondence_core_coverage_missing",
            &lost_core,
        ),
        (
            "contradictory-core",
            "python.correspondence_core_coverage_status",
            &contradictory_core,
        ),
        (
            "orphaned-symbol",
            "python.correspondence_provenance_missing",
            &orphaned_symbol,
        ),
    ] {
        let diagnostics = crate::analyzer::semantic_model::compiler::compile_pack(
            pack,
            &CompilerOptions::default(),
        )
        .expect_err("invalid correspondence must fail compilation");
        assert!(
            diagnostics.iter().any(|diagnostic| diagnostic.code == code),
            "{name} rejected by compiler without expected diagnostic: {diagnostics:?}"
        );
    }

    let mut rebuilt_hash = imported
        .compile(&CompilerOptions {
            compression: crate::analyzer::semantic_model::CompressionPolicy::AlwaysRaw,
            ..CompilerOptions::default()
        })
        .unwrap();
    rewrite_raw_declaration_shard(&mut rebuilt_hash, |types, _| {
        types[0].visibility = Visibility::Private;
    });
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let result = catalog.install(
        &rebuilt_hash,
        &crate::analyzer::semantic_model::DurablePackSource {
            kind: crate::analyzer::semantic_model::DurablePackSourceKind::Installed,
            source_id: "python-rebuilt-correspondence".to_owned(),
        },
    );
    assert!(
        result.is_err(),
        "rebuilt outer hashes cannot bless stale correspondence"
    );
}

#[test]
fn python_distribution_catalog_admission_checks_rebuilt_hash_carrier_mutations() {
    use crate::analyzer::semantic_model::{
        CatalogOptions, DurablePackSource, DurablePackSourceKind, SemanticPackCatalog,
    };
    let source = include_bytes!("fixtures/python-distribution-beautifulsoup4.json");
    let support = CsmiVocabularySupport::support(
        CSMI_PYTHON_PROFILE_ID,
        CSMI_PYTHON_PROFILE_VERSION,
        CSMI_PYTHON_PROFILE_SCHEMA,
    );
    let imported = import_logical_csmi_pack(
        &logical_pack_from_semantic(source),
        &support,
        &CompilerOptions::default(),
    )
    .unwrap();
    let valid = imported
        .compile(&CompilerOptions {
            compression: crate::analyzer::semantic_model::CompressionPolicy::AlwaysRaw,
            ..CompilerOptions::default()
        })
        .unwrap();
    assert!(valid.shards.len() > 1);
    let source = DurablePackSource {
        kind: DurablePackSourceKind::Installed,
        source_id: "python-distribution-regression".to_owned(),
    };
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    catalog
        .install(&valid, &source)
        .expect("valid multishard pack enters verified catalog state");

    let mut changed = valid.clone();
    rewrite_raw_declaration_shard(&mut changed, |_, members| {
        members[0].signature.as_mut().unwrap().parameters[0].name = Some("changed".to_owned());
    });
    let mut missing = valid.clone();
    rewrite_raw_declaration_shard(&mut missing, |types, _| {
        for fact in types {
            if let crate::analyzer::semantic_model::Locator::Interchange {
                profile_evidence, ..
            } = &mut fact.locator
            {
                *profile_evidence = None;
            }
        }
    });
    let mut duplicate = valid;
    rewrite_raw_declaration_shard(&mut duplicate, |types, _| {
        let evidence = types
            .iter()
            .find_map(|fact| match &fact.locator {
                crate::analyzer::semantic_model::Locator::Interchange {
                    profile_evidence, ..
                } => profile_evidence.clone(),
                _ => None,
            })
            .unwrap();
        let other = types
            .iter_mut()
            .find(|fact| {
                matches!(
                    &fact.locator,
                    crate::analyzer::semantic_model::Locator::Interchange {
                        profile_evidence: None,
                        ..
                    }
                )
            })
            .unwrap();
        if let crate::analyzer::semantic_model::Locator::Interchange {
            profile_evidence, ..
        } = &mut other.locator
        {
            *profile_evidence = Some(evidence);
        }
    });
    for mutated in [&changed, &missing, &duplicate] {
        let candidate = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        assert!(
            candidate.install(mutated, &source).is_err(),
            "rebuilt hashes cannot bypass full-pack admission"
        );
    }
}

#[test]
fn python_core_transfer_round_trips_without_closing_partial_callable() {
    let mut value: Value =
        serde_json::from_slice(include_bytes!("fixtures/python-runtime-refinement.json")).unwrap();
    value["semanticModels"][0]["procedureSummaries"] = json!([{
        "callable":"isclass",
        "transfers":[{
            "source":{"root":{"phase":"input","role":"parameter","position":0}},
            "destination":{"root":{"phase":"output","role":"result","position":0}}
        }]
    }]);
    value["semanticModels"][0]["completenessStatements"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "family":"procedure-summaries", "scope":{"callable":"isclass"},
            "status":"partial", "limitations":[{"kind":"coverage-limited"}]
        }));
    value["semanticModels"][0]["completenessStatements"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|statement| {
            statement["family"] == "declaration-aspects"
                && statement["scope"] == json!({"symbol":"isclass","aspect":"callable-shape"})
        })
        .unwrap()["provenance"] = json!(["fixture"]);
    let portable = logical_pack_from_semantic(&serde_json::to_vec(&value).unwrap());
    let mut support = CsmiVocabularySupport::support(
        CSMI_PYTHON_PROFILE_ID,
        CSMI_PYTHON_PROFILE_VERSION,
        CSMI_PYTHON_PROFILE_SCHEMA,
    );
    support.add(
        CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_ID,
        CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_VERSION,
        CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_SCHEMA,
    );
    let imported = import_logical_csmi_pack(&portable, &support, &CompilerOptions::default())
        .expect("exact Python runtime summary imports");
    let runtime_member = imported
        .pack
        .shards
        .iter()
        .find_map(|shard| match &shard.payload {
            AuthoredPayload::DeclarationFacts { members, .. } => members.first(),
            _ => None,
        })
        .unwrap();
    assert!(
        !runtime_member.callable_family_complete,
        "runtime callable shape does not establish native overload-family closure"
    );
    let summaries = imported
        .pack
        .shards
        .iter()
        .find_map(|shard| match &shard.payload {
            AuthoredPayload::ProcedureSummaries { summaries } => Some(summaries),
            _ => None,
        })
        .unwrap();
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].completeness, Completeness::Partial);
    assert_eq!(summaries[0].transfers.len(), 1);
    let artifact = CsmiArtifactEvidence::new(
        "pkg:generic/python-runtime@3.12.0?component=stdlib&implementation=cpython",
        "a".repeat(64),
    );
    let exported =
        export_authored_csmi_pack(&imported.pack, &artifact, &CsmiExportOptions::default())
            .expect("positive transfer exports");
    let output = semantic_value(&exported);
    assert_eq!(output["defaultProvenance"], "fixture");
    assert!(
        output["provenanceRecords"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["id"] == "fixture"
                && record["producer"]["identifier"] == "https://example.org/python-fixture")
    );
    assert!(
        output["semanticModels"][0]["completenessStatements"]
            .as_array()
            .unwrap()
            .iter()
            .any(|statement| statement["family"] == "declaration-aspects"
                && statement["scope"] == json!({"symbol":"isclass","aspect":"callable-shape"})
                && statement["status"] == "complete"
                && statement["provenance"] == json!(["fixture"]))
    );
    let conflicting_options = CsmiExportOptions {
        provenance_id: "fixture".to_owned(),
        ..Default::default()
    };
    assert!(
        export_authored_csmi_pack(&imported.pack, &artifact, &conflicting_options).is_err(),
        "a new composition record cannot replace the original fixture producer"
    );
    let mut dangling = imported.pack.clone();
    for shard in &mut dangling.shards {
        if let AuthoredPayload::DeclarationFacts { members, .. } = &mut shard.payload
            && let Locator::Interchange {
                callable_shape_evidence: Some(evidence),
                ..
            } = &mut members[0].locator
        {
            evidence.provenance_records.clear();
        }
    }
    assert!(
        export_authored_csmi_pack(&dangling, &artifact, &CsmiExportOptions::default()).is_err(),
        "dangling shape provenance cannot pass native validation"
    );
    let mut changed_producer = imported.pack.clone();
    for shard in &mut changed_producer.shards {
        if let AuthoredPayload::DeclarationFacts { members, .. } = &mut shard.payload
            && let Locator::Interchange {
                callable_shape_evidence: Some(evidence),
                ..
            } = &mut members[0].locator
        {
            evidence.provenance_records[0].producer.identifier =
                "https://example.org/changed-producer".to_owned();
        }
    }
    assert!(
        export_authored_csmi_pack(&changed_producer, &artifact, &CsmiExportOptions::default())
            .is_err(),
        "changed original producer must invalidate the evidence digest"
    );
    let restored = import_logical_csmi_pack(&exported, &support, &CompilerOptions::default())
        .expect("positive transfer re-imports");
    let restored_summaries = restored
        .pack
        .shards
        .iter()
        .find_map(|shard| match &shard.payload {
            AuthoredPayload::ProcedureSummaries { summaries } => Some(summaries),
            _ => None,
        })
        .unwrap();
    assert_eq!(restored_summaries[0].completeness, Completeness::Partial);
    assert_eq!(restored_summaries[0].transfers, summaries[0].transfers);
    let wrong_digest = CsmiArtifactEvidence::new(artifact.purl, "b".repeat(64));
    assert!(
        export_authored_csmi_pack(&imported.pack, &wrong_digest, &CsmiExportOptions::default())
            .is_err()
    );
}

#[test]
fn python_complete_empty_partition_keeps_callable_partial() {
    let mut value: Value =
        serde_json::from_slice(include_bytes!("fixtures/python-runtime-refinement.json")).unwrap();
    value["semanticModels"][0]["procedureSummaries"] = json!([{
        "callable":"isclass", "transfers":[]
    }]);
    let scope = json!({
        "callable":"isclass", "exit":"normal",
        "destination":{"phase":"output","role":"result","position":0},
        "source":{"kind":"all-inputs"}
    });
    value["semanticModels"][0]["completenessStatements"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "vocabulary":"csmi.transfer-partitions", "version":"0.1.0",
            "family":"transfer-partitions", "scope":scope, "status":"complete"
        }));
    value["semanticModels"][0]["vocabularyUses"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "identifier":"csmi.transfer-partitions", "version":"0.1.0",
            "schema":"https://csmi.brokk.ai/schema/profiles/transfer-partitions/0.1/schema.json",
            "requirement":"required", "affects":[{
                "kind":"fact-family", "family":"transfer-partitions", "scope":scope
            }]
        }));
    let mut support = CsmiVocabularySupport::support(
        CSMI_PYTHON_PROFILE_ID,
        CSMI_PYTHON_PROFILE_VERSION,
        CSMI_PYTHON_PROFILE_SCHEMA,
    );
    support.add(
        CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_ID,
        CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_VERSION,
        CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_SCHEMA,
    );
    support.add(
        CSMI_TRANSFER_PARTITIONS_PROFILE_ID,
        CSMI_TRANSFER_PARTITIONS_PROFILE_VERSION,
        CSMI_TRANSFER_PARTITIONS_PROFILE_SCHEMA,
    );
    let portable = logical_pack_from_semantic(&serde_json::to_vec(&value).unwrap());
    let imported = import_logical_csmi_pack(&portable, &support, &CompilerOptions::default())
        .expect("complete empty input-to-result partition imports");
    let summary = imported
        .pack
        .shards
        .iter()
        .find_map(|shard| match &shard.payload {
            AuthoredPayload::ProcedureSummaries { summaries } => summaries.first(),
            _ => None,
        })
        .unwrap();
    assert_eq!(summary.completeness, Completeness::Partial);
    assert!(summary.transfers.is_empty());
    assert_eq!(summary.transfer_partitions.len(), 1);
    assert_eq!(
        summary.transfer_partitions[0].status,
        crate::analyzer::semantic_model::TransferPartitionStatus::Complete
    );
    let artifact = CsmiArtifactEvidence::new(
        "pkg:generic/python-runtime@3.12.0?component=stdlib&implementation=cpython",
        "a".repeat(64),
    );
    let exported =
        export_authored_csmi_pack(&imported.pack, &artifact, &CsmiExportOptions::default())
            .expect("complete empty partition exports");
    let restored = import_logical_csmi_pack(&exported, &support, &CompilerOptions::default())
        .expect("complete empty partition re-imports");
    let restored_summary = restored
        .pack
        .shards
        .iter()
        .find_map(|shard| match &shard.payload {
            AuthoredPayload::ProcedureSummaries { summaries } => summaries.first(),
            _ => None,
        })
        .unwrap();
    assert_eq!(restored_summary.completeness, Completeness::Partial);
    assert_eq!(restored_summary.transfer_partitions.len(), 1);
    assert_eq!(
        restored_summary.transfer_partitions[0].source,
        summary.transfer_partitions[0].source
    );
    assert_eq!(
        restored_summary.transfer_partitions[0].status,
        summary.transfer_partitions[0].status
    );
    assert_eq!(restored_summary.transfer_partitions[0].normal_result, 0);
    assert!(
        restored_summary.transfer_partitions[0]
            .limitations
            .is_empty()
    );
    let exported_document: Value = serde_json::from_slice(
        &exported
            .resource_bytes(&exported.manifest.resources[0])
            .unwrap(),
    )
    .unwrap();
    let statement = exported_document["semanticModels"][0]["completenessStatements"]
        .as_array()
        .unwrap()
        .iter()
        .find(|statement| statement["family"] == "transfer-partitions")
        .unwrap();
    assert_eq!(statement["scope"]["destination"]["position"], 0);
    assert_eq!(statement["status"], "complete");
    assert!(
        statement["limitations"]
            .as_array()
            .is_none_or(Vec::is_empty)
    );
    let origin = statement["provenance"].as_array().unwrap()[0]
        .as_str()
        .unwrap();
    assert!(
        exported_document["provenanceRecords"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["id"] == origin)
    );

    let valid_value = value.clone();

    value["semanticModels"][0]["completenessStatements"]
        .as_array_mut()
        .unwrap()
        .last_mut()
        .unwrap()["scope"]["destination"]["position"] = json!(1);
    value["semanticModels"][0]["vocabularyUses"]
        .as_array_mut()
        .unwrap()
        .last_mut()
        .unwrap()["affects"][0]["scope"]["destination"]["position"] = json!(1);
    let wrong_result = logical_pack_from_semantic(&serde_json::to_vec(&value).unwrap());
    assert!(
        import_logical_csmi_pack(&wrong_result, &support, &CompilerOptions::default()).is_err()
    );

    for status in ["partial", "unknown"] {
        let mut incomplete = value.clone();
        incomplete["semanticModels"][0]["completenessStatements"]
            .as_array_mut()
            .unwrap()
            .last_mut()
            .unwrap()["scope"]["destination"]["position"] = json!(0);
        incomplete["semanticModels"][0]["vocabularyUses"]
            .as_array_mut()
            .unwrap()
            .last_mut()
            .unwrap()["affects"][0]["scope"]["destination"]["position"] = json!(0);
        let statement = incomplete["semanticModels"][0]["completenessStatements"]
            .as_array_mut()
            .unwrap()
            .last_mut()
            .unwrap();
        statement["status"] = json!(status);
        if status == "partial" {
            statement["limitations"] = json!([{"kind":"unmodeled"}]);
        }
        let portable = logical_pack_from_semantic(&serde_json::to_vec(&incomplete).unwrap());
        assert!(
            import_logical_csmi_pack(&portable, &support, &CompilerOptions::default()).is_err(),
            "an empty {status} partition cannot make the summary substantive"
        );
    }
    let mut duplicate = valid_value.clone();
    let mut duplicate_statement = duplicate["semanticModels"][0]["completenessStatements"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    duplicate_statement["status"] = json!("partial");
    duplicate_statement["limitations"] = json!([{"kind":"unmodeled"}]);
    duplicate["semanticModels"][0]["completenessStatements"]
        .as_array_mut()
        .unwrap()
        .push(duplicate_statement);
    let duplicate = logical_pack_from_semantic(&serde_json::to_vec(&duplicate).unwrap());
    let validation = validate_csmi_pack(
        &duplicate.canonical_manifest_bytes().unwrap(),
        &duplicate.resources,
        &support,
    );
    assert!(diagnostics_contain(
        &validation.diagnostics,
        "semantic.duplicate_completeness_scope"
    ));
    let mut unsupported = valid_value;
    unsupported["semanticModels"][0]["vocabularyUses"]
        .as_array_mut()
        .unwrap()
        .last_mut()
        .unwrap()["version"] = json!("9.9.9");
    let unsupported = logical_pack_from_semantic(&serde_json::to_vec(&unsupported).unwrap());
    let validation = validate_csmi_pack(
        &unsupported.canonical_manifest_bytes().unwrap(),
        &unsupported.resources,
        &support,
    );
    assert!(diagnostics_contain(
        &validation.diagnostics,
        "structural.profile_schema_mismatch"
    ));
}

#[test]
fn export_does_not_silently_drop_callable_inventory_coverage() {
    let mut authored: AuthoredSemanticModelPack =
        serde_json::from_slice(DECLARATIONS_JSON).unwrap();
    authored.schema_version = crate::analyzer::semantic_model::CALLABLE_SURFACE_MIN_SCHEMA_VERSION;
    let AuthoredPayload::DeclarationFacts { types, .. } = &mut authored.shards[0].payload else {
        unreachable!()
    };
    types[0].callable_surface_complete = true;
    let artifact = CsmiArtifactEvidence::new("pkg:maven/example/fixture@1.0.0", "a".repeat(64));
    let error =
        export_authored_csmi_pack(&authored, &artifact, &CsmiExportOptions::default()).unwrap_err();
    assert!(
        matches!(error, CsmiExportError::Unsupported { path, .. } if path.ends_with("callable_surface_complete"))
    );
}

#[test]
fn export_does_not_silently_drop_non_overridable_evidence() {
    let mut authored: AuthoredSemanticModelPack =
        serde_json::from_slice(DECLARATIONS_JSON).unwrap();
    let AuthoredPayload::DeclarationFacts { members, .. } = &mut authored.shards[0].payload else {
        unreachable!()
    };
    let method = members
        .iter_mut()
        .find(|m| m.member_kind == MemberKind::Method && !m.is_static)
        .unwrap();
    method.is_virtual = false;
    method.is_abstract = false;
    method.non_overridable =
        Some(crate::analyzer::semantic_model::NonOverridableEvidence::JavaFinalMethod);
    let artifact = CsmiArtifactEvidence::new("pkg:maven/example/fixture@1.0.0", "a".repeat(64));
    let error =
        export_authored_csmi_pack(&authored, &artifact, &CsmiExportOptions::default()).unwrap_err();
    assert!(
        matches!(error, CsmiExportError::Unsupported { path, .. } if path.ends_with("non_overridable"))
    );
}
