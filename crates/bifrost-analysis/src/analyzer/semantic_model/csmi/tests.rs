use super::*;
use crate::CancellationToken;
use crate::analyzer::semantic_model::{
    AuthoredConcurrencyEffect, AuthoredPayload, AuthoredProcedureSummary, AuthoredProcedureTarget,
    AuthoredSemanticModelPack, AuthoredShard, AuthoredSummaryEffect, AuthoredSummaryExitKind,
    AuthoredSummaryInput, AuthoredSummaryOutput, AuthoredSummaryTransfer, CatalogCoordinate,
    CatalogOptions, CompilerOptions, Completeness, ImplicitOperation, Locator, MemberKind,
    ProcedureSummaryTargetKey, SemanticModelActivationEvidence, SemanticModelActivationRequest,
    SemanticModelResolutionOutcome, SemanticPackCatalog, SessionPackSource, SessionPackSourceKind,
    SummaryValueTransfer, SummaryValueTransferKind, SummaryValueTransferOperation,
    TypeCopySemantics, TypeFact, TypeKind, TypeValueSemantics, Visibility, compile_pack,
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

fn logical_pack_from_semantic(bytes: &[u8]) -> CsmiLogicalPack {
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
        matches!(unresolved, CsmiImportError::Identity(message) if message.contains("unresolved JVM type symbol"))
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
        id: "type.java.lang.string".to_owned(),
        name: "java.lang.String".to_owned(),
        type_kind: TypeKind::Class,
        visibility: Visibility::Public,
        is_abstract: false,
        is_sealed: false,
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
                effects: Vec::new(),
                concurrency_effects: Vec::new(),
                declared_effects: Vec::new(),
                preconditions: None,
                result_contracts: Vec::new(),
                conditional_result_refinements: Vec::new(),
                conditional_indirect_writes: Vec::new(),
                normal_return_refinements: Vec::new(),
            }],
        },
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
