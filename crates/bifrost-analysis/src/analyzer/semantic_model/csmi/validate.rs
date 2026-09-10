//! Structural and semantic conformance checks for CSMI v0.1.

use super::canonical::{
    canonical_digest, canonical_json, canonical_pack_manifest, canonical_semantic_document,
    sha256_hex,
};
use super::model::*;
use super::pack::{
    CsmiResourceError, CsmiResourceResolver, validate_resource_path, verify_resources,
};
use serde::Serialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::OnceLock;

const CSMI_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/analyzer/semantic_model/csmi/schema.json"
));

const JAVASCRIPT_TYPESCRIPT_SCHEMA_JSON: &str =
    include_str!("profiles/javascript-typescript.schema.json");
const NODE_COMPATIBILITY_SCHEMA_JSON: &str =
    include_str!("profiles/node-compatibility.schema.json");
const PYTHON_SCHEMA_JSON: &str = include_str!("profiles/python.schema.json");
const RUST_SCHEMA_JSON: &str = include_str!("profiles/rust.schema.json");
const VALUE_TRANSFER_SCHEMA_JSON: &str = include_str!("profiles/value-transfer.schema.json");
const CPP_SCHEMA_JSON: &str = include_str!("profiles/cpp.schema.json");
const JAVA_SOURCE_IDENTITY_SCHEMA_JSON: &str =
    include_str!("profiles/java-source-identity.schema.json");
const JVM_BINARY_IDENTITY_SCHEMA_JSON: &str =
    include_str!("profiles/jvm-binary-identity.schema.json");
const JAVA_JVM_MAPPING_SCHEMA_JSON: &str = include_str!("profiles/java-jvm-mapping.schema.json");
const JVM_COMPATIBILITY_SCHEMA_JSON: &str = include_str!("profiles/jvm-compatibility.schema.json");
const RUNTIME_VALUES_SCHEMA_JSON: &str = include_str!("profiles/runtime-values.schema.json");
const COLLECTION_FLOW_SCHEMA_JSON: &str = include_str!("profiles/collection-flow.schema.json");
const DEFERRED_YIELD_SCHEMA_JSON: &str = include_str!("profiles/deferred-yield.schema.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsmiDiagnosticSeverity {
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsmiDiagnostic {
    pub severity: CsmiDiagnosticSeverity,
    pub code: String,
    pub path: String,
    pub message: String,
}

impl CsmiDiagnostic {
    pub fn error(
        code: impl Into<String>,
        path: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            severity: CsmiDiagnosticSeverity::Error,
            code: code.into(),
            path: path.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for CsmiDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} at {}: {}",
            self.code, self.path, self.message
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CsmiValidationStage {
    Structural,
    Semantic,
    Integrity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsmiDocumentValidation {
    pub document: Option<CsmiDocument>,
    pub structural_valid: bool,
    pub semantic_valid: bool,
    pub interpretable: bool,
    pub profiles: Vec<CsmiProfileValidation>,
    pub diagnostics: Vec<CsmiDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsmiProfileValidation {
    pub identifier: String,
    pub version: String,
    pub schema: String,
    pub recognized: bool,
    pub structural_valid: bool,
    pub semantically_supported: bool,
}

impl CsmiDocumentValidation {
    pub fn valid(&self) -> bool {
        self.structural_valid && self.semantic_valid
    }

    pub fn usable(&self) -> bool {
        self.valid() && self.interpretable
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsmiPackValidation {
    pub manifest: Option<CsmiPackManifest>,
    pub semantic_documents: Vec<CsmiSemanticDocument>,
    pub structural_valid: bool,
    pub semantic_valid: bool,
    pub integrity_valid: bool,
    pub interpretable: bool,
    pub profiles: Vec<CsmiProfileValidation>,
    pub diagnostics: Vec<CsmiDiagnostic>,
}

impl CsmiPackValidation {
    pub fn valid(&self) -> bool {
        self.structural_valid && self.semantic_valid && self.integrity_valid
    }

    pub fn usable(&self) -> bool {
        self.valid() && self.interpretable
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsmiVocabularySupport {
    supported: Vec<CsmiSupportedVocabulary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsmiSupportedVocabulary {
    pub identifier: String,
    pub version: String,
    pub schema: String,
}

impl CsmiVocabularySupport {
    pub fn empty() -> Self {
        Self {
            supported: Vec::new(),
        }
    }

    pub fn new(supported: Vec<CsmiSupportedVocabulary>) -> Self {
        Self { supported }
    }

    pub fn support(
        identifier: impl Into<String>,
        version: impl Into<String>,
        schema: impl Into<String>,
    ) -> Self {
        Self::new(vec![CsmiSupportedVocabulary {
            identifier: identifier.into(),
            version: version.into(),
            schema: schema.into(),
        }])
    }

    pub fn add(
        &mut self,
        identifier: impl Into<String>,
        version: impl Into<String>,
        schema: impl Into<String>,
    ) {
        self.supported.push(CsmiSupportedVocabulary {
            identifier: identifier.into(),
            version: version.into(),
            schema: schema.into(),
        });
    }

    pub fn supports(&self, identifier: &str, version: &str, schema: &str) -> bool {
        self.supported.iter().any(|supported| {
            supported.identifier == identifier
                && supported.version == version
                && supported.schema == schema
        })
    }
}

impl Default for CsmiVocabularySupport {
    fn default() -> Self {
        Self::empty()
    }
}

pub fn parse_csmi_document(bytes: &[u8]) -> CsmiDocumentValidation {
    let mut diagnostics = Vec::new();
    let value: Value = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(error) => {
            return CsmiDocumentValidation {
                document: None,
                structural_valid: false,
                semantic_valid: false,
                interpretable: false,
                profiles: Vec::new(),
                diagnostics: vec![CsmiDiagnostic::error(
                    "structural.invalid_json",
                    "$",
                    error.to_string(),
                )],
            };
        }
    };
    let Some(document_type) = value.get("documentType").and_then(Value::as_str) else {
        return CsmiDocumentValidation {
            document: None,
            structural_valid: false,
            semantic_valid: false,
            interpretable: false,
            profiles: Vec::new(),
            diagnostics: vec![CsmiDiagnostic::error(
                "structural.missing_document_type",
                "$.documentType",
                "documentType is required",
            )],
        };
    };
    let schema_violations = csmi_schema_validator()
        .iter_errors(&value)
        .map(|violation| {
            CsmiDiagnostic::error(
                "structural.schema_violation",
                violation.instance_path().to_string(),
                violation.to_string(),
            )
        })
        .collect::<Vec<_>>();
    if !schema_violations.is_empty() {
        return CsmiDocumentValidation {
            document: None,
            structural_valid: false,
            semantic_valid: false,
            interpretable: false,
            profiles: Vec::new(),
            diagnostics: schema_violations,
        };
    }
    let document: Result<CsmiDocument, serde_json::Error> = match document_type {
        "semantic-document" => {
            serde_json::from_value::<CsmiSemanticDocument>(value).map(CsmiDocument::Semantic)
        }
        "pack-manifest" => {
            serde_json::from_value::<CsmiPackManifest>(value).map(CsmiDocument::Manifest)
        }
        other => {
            return CsmiDocumentValidation {
                document: None,
                structural_valid: false,
                semantic_valid: false,
                interpretable: false,
                profiles: Vec::new(),
                diagnostics: vec![CsmiDiagnostic::error(
                    "structural.unsupported_document_type",
                    "$.documentType",
                    format!("unsupported documentType {other:?}"),
                )],
            };
        }
    };
    let document = match document {
        Ok(document) => document,
        Err(error) => {
            diagnostics.push(CsmiDiagnostic::error(
                "structural.schema_violation",
                "$",
                error.to_string(),
            ));
            return CsmiDocumentValidation {
                document: None,
                structural_valid: false,
                semantic_valid: false,
                interpretable: false,
                profiles: Vec::new(),
                diagnostics,
            };
        }
    };
    if let CsmiDocument::Manifest(manifest) = &document {
        match canonical_pack_manifest(manifest) {
            Ok(canonical) if canonical == bytes => {}
            Ok(_) => {
                return CsmiDocumentValidation {
                    document: None,
                    structural_valid: false,
                    semantic_valid: false,
                    interpretable: false,
                    profiles: Vec::new(),
                    diagnostics: vec![CsmiDiagnostic::error(
                        "structural.non_canonical_json",
                        "$",
                        "manifest bytes must equal the canonical CSMI representation",
                    )],
                };
            }
            Err(error) => {
                return CsmiDocumentValidation {
                    document: None,
                    structural_valid: false,
                    semantic_valid: false,
                    interpretable: false,
                    profiles: Vec::new(),
                    diagnostics: vec![CsmiDiagnostic::error(
                        "structural.canonicalization",
                        "$",
                        error.to_string(),
                    )],
                };
            }
        }
    }
    let mut structural_valid = match &document {
        CsmiDocument::Semantic(document) => {
            validate_semantic_document_shape(document, &mut diagnostics)
        }
        CsmiDocument::Manifest(manifest) => validate_manifest_shape(manifest, &mut diagnostics),
    };
    let profiles = match &document {
        CsmiDocument::Semantic(document) if structural_valid => {
            let profiles = validate_profile_schemas(
                document,
                &CsmiVocabularySupport::empty(),
                &mut diagnostics,
            );
            structural_valid = profiles.iter().all(|profile| profile.structural_valid);
            profiles
        }
        CsmiDocument::Semantic(_) | CsmiDocument::Manifest(_) => Vec::new(),
    };
    // Parsing establishes only JSON-schema and DTO shape. Semantic validity
    // depends on the caller's supported vocabulary set and is computed by
    // `validate_csmi_document`; doing it here with an empty support set would
    // leave stale unsupported-vocabulary diagnostics in a later supported run.
    let semantic_valid = structural_valid && matches!(document, CsmiDocument::Manifest(_));
    sort_diagnostics(&mut diagnostics);
    CsmiDocumentValidation {
        document: Some(document),
        structural_valid,
        semantic_valid,
        interpretable: semantic_valid,
        profiles,
        diagnostics,
    }
}

fn csmi_schema_validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        let schema: Value =
            serde_json::from_str(CSMI_SCHEMA_JSON).expect("pinned CSMI schema is valid JSON");
        jsonschema::draft202012::new(&schema).expect("pinned CSMI schema is valid Draft 2020-12")
    })
}

#[derive(Clone, Copy)]
struct KnownProfile {
    identifier: &'static str,
    version: &'static str,
    schema: &'static str,
    schema_json: &'static str,
    payload_definitions: &'static [&'static str],
}

const KNOWN_PROFILES: &[KnownProfile] = &[
    KnownProfile {
        identifier: CSMI_COLLECTION_FLOW_PROFILE_ID,
        version: CSMI_COLLECTION_FLOW_PROFILE_VERSION,
        schema: CSMI_COLLECTION_FLOW_PROFILE_SCHEMA,
        schema_json: COLLECTION_FLOW_SCHEMA_JSON,
        payload_definitions: &["$root"],
    },
    KnownProfile {
        identifier: CSMI_RUNTIME_VALUES_PROFILE_ID,
        version: CSMI_RUNTIME_VALUES_PROFILE_VERSION,
        schema: CSMI_RUNTIME_VALUES_PROFILE_SCHEMA,
        schema_json: RUNTIME_VALUES_SCHEMA_JSON,
        payload_definitions: &[
            "runtimeGlobalExposure",
            "keyedReadBehavior",
            "runtimeGlobalBindingEvidence",
            "keyedReadObservation",
        ],
    },
    KnownProfile {
        identifier: CSMI_DEFERRED_YIELD_PROFILE_ID,
        version: CSMI_DEFERRED_YIELD_PROFILE_VERSION,
        schema: CSMI_DEFERRED_YIELD_PROFILE_SCHEMA,
        schema_json: DEFERRED_YIELD_SCHEMA_JSON,
        payload_definitions: &["$root"],
    },
    KnownProfile {
        identifier: "csmi.javascript-typescript",
        version: "0.1.0",
        schema: "https://csmi.brokk.ai/schema/profiles/javascript-typescript/0.1/schema.json",
        schema_json: JAVASCRIPT_TYPESCRIPT_SCHEMA_JSON,
        payload_definitions: &["moduleBinding", "runtimeDeclarationBinding"],
    },
    KnownProfile {
        identifier: "csmi.node-compatibility",
        version: "0.1.0",
        schema: "https://csmi.brokk.ai/schema/profiles/node-compatibility/0.1/schema.json",
        schema_json: NODE_COMPATIBILITY_SCHEMA_JSON,
        payload_definitions: &[
            "nodeRuntime",
            "nodeModuleResolution",
            "typescriptResolution",
        ],
    },
    KnownProfile {
        identifier: "csmi.python",
        version: "0.1.0",
        schema: "https://csmi.brokk.ai/schema/profiles/python/0.1/schema.json",
        schema_json: PYTHON_SCHEMA_JSON,
        payload_definitions: &[
            "compatibility",
            "distributionImports",
            "importBindings",
            "declarationCorrespondence",
        ],
    },
    KnownProfile {
        identifier: "csmi.rust",
        version: "0.1.0",
        schema: "https://csmi.brokk.ai/schema/profiles/rust/0.1/schema.json",
        schema_json: RUST_SCHEMA_JSON,
        payload_definitions: &[
            "configuration",
            "crateTarget",
            "workspace",
            "dependencyBinding",
            "sysrootCrate",
            "reexport",
            "implementation",
            "generation",
            "nativeMapping",
        ],
    },
    KnownProfile {
        identifier: CSMI_VALUE_TRANSFER_PROFILE_ID,
        version: CSMI_VALUE_TRANSFER_PROFILE_VERSION,
        schema: CSMI_VALUE_TRANSFER_PROFILE_SCHEMA,
        schema_json: VALUE_TRANSFER_SCHEMA_JSON,
        payload_definitions: &[
            "transferAttachment",
            "typeValueSemantics",
            "implicitOperation",
        ],
    },
    KnownProfile {
        identifier: CSMI_C_CPP_RESOLUTION_PROFILE_ID,
        version: CSMI_C_CPP_RESOLUTION_PROFILE_VERSION,
        schema: CSMI_C_CPP_RESOLUTION_PROFILE_SCHEMA,
        schema_json: CPP_SCHEMA_JSON,
        payload_definitions: &["resolutionContext"],
    },
    KnownProfile {
        identifier: CSMI_CPP_PROFILE_ID,
        version: CSMI_CPP_PROFILE_VERSION,
        schema: CSMI_CPP_PROFILE_SCHEMA,
        schema_json: CPP_SCHEMA_JSON,
        payload_definitions: &["typeAlias", "specialMember"],
    },
    KnownProfile {
        identifier: "csmi.java-source-identity",
        version: "0.1",
        schema: "https://csmi.brokk.ai/schema/profiles/java-jvm/0.1/java-source-identity.schema.json",
        schema_json: JAVA_SOURCE_IDENTITY_SCHEMA_JSON,
        payload_definitions: &[],
    },
    KnownProfile {
        identifier: "csmi.jvm-binary-identity",
        version: "0.1",
        schema: "https://csmi.brokk.ai/schema/profiles/java-jvm/0.1/jvm-binary-identity.schema.json",
        schema_json: JVM_BINARY_IDENTITY_SCHEMA_JSON,
        payload_definitions: &[],
    },
    KnownProfile {
        identifier: "csmi.java-jvm-mapping",
        version: "0.1",
        schema: "https://csmi.brokk.ai/schema/profiles/java-jvm/0.1/java-jvm-mapping.schema.json",
        schema_json: JAVA_JVM_MAPPING_SCHEMA_JSON,
        payload_definitions: &["$root"],
    },
    KnownProfile {
        identifier: "csmi.jvm-compatibility",
        version: "0.1",
        schema: "https://csmi.brokk.ai/schema/profiles/java-jvm/0.1/jvm-compatibility.schema.json",
        schema_json: JVM_COMPATIBILITY_SCHEMA_JSON,
        payload_definitions: &["$root"],
    },
];

fn known_profile(identifier: &str, schema: &str) -> Option<(usize, KnownProfile)> {
    KNOWN_PROFILES
        .iter()
        .copied()
        .enumerate()
        .find(|(_, profile)| profile.identifier == identifier)
        .or_else(|| {
            KNOWN_PROFILES
                .iter()
                .copied()
                .enumerate()
                .find(|(_, profile)| profile.schema == schema)
        })
}

fn profile_schema_validators() -> &'static Vec<Option<jsonschema::Validator>> {
    static VALIDATORS: OnceLock<Vec<Option<jsonschema::Validator>>> = OnceLock::new();
    VALIDATORS.get_or_init(|| {
        KNOWN_PROFILES
            .iter()
            .map(|profile| {
                let mut schema: Value = serde_json::from_str(profile.schema_json)
                    .expect("pinned CSMI profile schema is valid JSON");
                if profile.payload_definitions.is_empty() {
                    jsonschema::draft202012::new(&schema)
                        .expect("pinned CSMI profile schema is valid Draft 2020-12");
                    return None;
                }
                if profile.payload_definitions != ["$root"] {
                    schema["oneOf"] = Value::Array(
                        profile
                            .payload_definitions
                            .iter()
                            .map(|definition| {
                                serde_json::json!({"$ref": format!("#/$defs/{definition}")})
                            })
                            .collect(),
                    );
                }
                Some(
                    jsonschema::draft202012::new(&schema)
                        .expect("pinned CSMI profile schema is valid Draft 2020-12"),
                )
            })
            .collect()
    })
}

fn validate_profile_schemas(
    document: &CsmiSemanticDocument,
    support: &CsmiVocabularySupport,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> Vec<CsmiProfileValidation> {
    let mut outcomes = Vec::new();
    for (model_index, model) in document.semantic_models.iter().enumerate() {
        let model_value = serde_json::to_value(model).expect("CSMI semantic model serializes");
        for (use_index, use_) in model.vocabulary_uses.iter().enumerate() {
            let path = format!("$.semanticModels[{model_index}].vocabularyUses[{use_index}]");
            let Some((profile_index, profile)) = known_profile(&use_.identifier, &use_.schema)
            else {
                outcomes.push(CsmiProfileValidation {
                    identifier: use_.identifier.clone(),
                    version: use_.version.clone(),
                    schema: use_.schema.clone(),
                    recognized: false,
                    structural_valid: true,
                    semantically_supported: support.supports(
                        &use_.identifier,
                        &use_.version,
                        &use_.schema,
                    ),
                });
                continue;
            };
            let recognized = use_.version == profile.version && use_.schema == profile.schema;
            let mut structural_valid = recognized;
            if !recognized {
                error(
                    diagnostics,
                    "structural.profile_schema_mismatch",
                    path,
                    format!(
                        "known profile {} requires version {} and schema {}",
                        profile.identifier, profile.version, profile.schema
                    ),
                );
            } else if let Some(validator) = &profile_schema_validators()[profile_index] {
                let mut stack = vec![(format!("$.semanticModels[{model_index}]"), &model_value)];
                while let Some((value_path, value)) = stack.pop() {
                    match value {
                        Value::Array(values) => {
                            for (index, child) in values.iter().enumerate().rev() {
                                stack.push((format!("{value_path}[{index}]"), child));
                            }
                        }
                        Value::Object(object) => {
                            let vocabulary_matches = object
                                .get("vocabulary")
                                .and_then(Value::as_str)
                                .is_some_and(|identifier| identifier == profile.identifier)
                                && object
                                    .get("version")
                                    .and_then(Value::as_str)
                                    .is_some_and(|version| version == profile.version);
                            if vocabulary_matches {
                                let profiled_value =
                                    object.get("payload").or_else(|| object.get("value"));
                                if let Some(profiled_value) = profiled_value {
                                    for violation in validator.iter_errors(profiled_value) {
                                        error(
                                            diagnostics,
                                            "structural.profile_schema_violation",
                                            format!(
                                                "{value_path}.{}{}",
                                                if object.contains_key("payload") {
                                                    "payload"
                                                } else {
                                                    "value"
                                                },
                                                violation.instance_path()
                                            ),
                                            violation.to_string(),
                                        );
                                        structural_valid = false;
                                    }
                                }
                            }
                            for (key, child) in object.iter().rev() {
                                stack.push((format!("{value_path}.{key}"), child));
                            }
                        }
                        _ => {}
                    }
                }
            }
            outcomes.push(CsmiProfileValidation {
                identifier: use_.identifier.clone(),
                version: use_.version.clone(),
                schema: use_.schema.clone(),
                recognized,
                structural_valid,
                semantically_supported: support.supports(
                    &use_.identifier,
                    &use_.version,
                    &use_.schema,
                ),
            });
        }
    }
    outcomes
}

pub fn validate_csmi_document(
    bytes: &[u8],
    support: &CsmiVocabularySupport,
) -> CsmiDocumentValidation {
    let mut result = parse_csmi_document(bytes);
    if result.structural_valid
        && let Some(document) = &result.document
    {
        result.semantic_valid = match document {
            CsmiDocument::Semantic(document) => {
                validate_semantic_document(document, &mut result.diagnostics)
            }
            CsmiDocument::Manifest(_) => true,
        };
        result.interpretable = match document {
            CsmiDocument::Semantic(document) => {
                validate_interpretability(document, support, &mut result.diagnostics)
            }
            CsmiDocument::Manifest(_) => true,
        };
        for profile in &mut result.profiles {
            profile.semantically_supported =
                support.supports(&profile.identifier, &profile.version, &profile.schema);
        }
    }
    sort_diagnostics(&mut result.diagnostics);
    result
}

pub fn validate_csmi_pack(
    manifest_bytes: &[u8],
    resources: &dyn CsmiResourceResolver,
    support: &CsmiVocabularySupport,
) -> CsmiPackValidation {
    let manifest_result = validate_csmi_document(manifest_bytes, support);
    let Some(document) = manifest_result.document else {
        return CsmiPackValidation {
            manifest: None,
            semantic_documents: Vec::new(),
            structural_valid: false,
            semantic_valid: false,
            integrity_valid: false,
            interpretable: false,
            profiles: Vec::new(),
            diagnostics: manifest_result.diagnostics,
        };
    };
    let CsmiDocument::Manifest(manifest) = document else {
        let mut diagnostics = manifest_result.diagnostics;
        diagnostics.push(CsmiDiagnostic::error(
            "pack.root_not_manifest",
            "$.documentType",
            "logical pack root must be a pack-manifest",
        ));
        sort_diagnostics(&mut diagnostics);
        return CsmiPackValidation {
            manifest: None,
            semantic_documents: Vec::new(),
            structural_valid: false,
            semantic_valid: false,
            integrity_valid: false,
            interpretable: false,
            profiles: Vec::new(),
            diagnostics,
        };
    };
    let mut diagnostics = manifest_result.diagnostics;
    let manifest_is_canonical = canonical_pack_manifest(&manifest)
        .map(|canonical| canonical == manifest_bytes)
        .unwrap_or(false);
    if !manifest_is_canonical {
        diagnostics.push(CsmiDiagnostic::error(
            "integrity.manifest_non_canonical_json",
            "$",
            "manifest bytes must equal the canonical CSMI representation",
        ));
        sort_diagnostics(&mut diagnostics);
        return CsmiPackValidation {
            manifest: None,
            semantic_documents: Vec::new(),
            structural_valid: false,
            semantic_valid: false,
            integrity_valid: false,
            interpretable: false,
            profiles: Vec::new(),
            diagnostics,
        };
    }
    let mut integrity_valid = match verify_resources(&manifest, resources) {
        Ok(()) => true,
        Err(errors) => {
            for error in errors {
                diagnostics.push(resource_diagnostic(error));
            }
            false
        }
    };
    let mut semantic_documents = Vec::new();
    let mut structural_valid = manifest_result.structural_valid;
    let mut semantic_valid = manifest_result.semantic_valid;
    let mut interpretable = manifest_result.interpretable;
    let mut profiles = manifest_result.profiles;
    for (index, resource) in manifest.resources.iter().enumerate() {
        if resource.role != CsmiResourceRole::SemanticDocument {
            continue;
        }
        let bytes = match resources.read_resource(&resource.path, resource.size) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        let result = validate_csmi_document(&bytes, support);
        if !result.structural_valid {
            structural_valid = false;
        }
        if !result.structural_valid || !result.semantic_valid {
            semantic_valid = false;
        }
        if !result.interpretable {
            interpretable = false;
        }
        profiles.extend(result.profiles.iter().cloned());
        diagnostics.extend(result.diagnostics.into_iter().map(|mut diagnostic| {
            diagnostic.path = format!("$.resources[{index}]{}", diagnostic.path);
            diagnostic
        }));
        let resource_is_canonical = match result.document.as_ref() {
            Some(CsmiDocument::Semantic(document)) => Some(
                canonical_semantic_document(document).is_ok_and(|canonical| canonical == bytes),
            ),
            Some(CsmiDocument::Manifest(_)) | None => None,
        };
        if resource_is_canonical == Some(false) {
            structural_valid = false;
            semantic_valid = false;
            integrity_valid = false;
            error(
                &mut diagnostics,
                "integrity.resource_non_canonical_json",
                format!("$.resources[{index}].path"),
                "semantic-document resource bytes must equal the canonical CSMI representation",
            );
        }
        if resource_is_canonical == Some(true)
            && let Some(CsmiDocument::Semantic(document)) = result.document
        {
            semantic_documents.push(document);
        }
    }
    sort_diagnostics(&mut diagnostics);
    CsmiPackValidation {
        manifest: Some(manifest),
        semantic_documents,
        structural_valid,
        semantic_valid,
        integrity_valid,
        interpretable,
        profiles,
        diagnostics,
    }
}

fn validate_semantic_document_shape(
    document: &CsmiSemanticDocument,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let mut valid = true;
    if document.document_type != "semantic-document" {
        error(
            diagnostics,
            "structural.document_type",
            "$.documentType",
            "must be semantic-document",
        );
        valid = false;
    }
    if document.schema != CSMI_SCHEMA_URI {
        error(
            diagnostics,
            "structural.schema_identifier",
            "$.schema",
            "must use the pinned CSMI v0.1 schema URI",
        );
        valid = false;
    }
    if document.semantic_model_version != CSMI_SEMANTIC_MODEL_VERSION {
        error(
            diagnostics,
            "structural.semantic_model_version",
            "$.semanticModelVersion",
            "unsupported semantic model version",
        );
        valid = false;
    }
    if document.serialization_version != CSMI_SERIALIZATION_VERSION {
        error(
            diagnostics,
            "structural.serialization_version",
            "$.serializationVersion",
            "unsupported JSON serialization version",
        );
        valid = false;
    }
    if document.provenance_records.is_empty() {
        error(
            diagnostics,
            "structural.empty_provenance",
            "$.provenanceRecords",
            "at least one provenance record is required",
        );
        valid = false;
    }
    if document.semantic_models.is_empty() {
        error(
            diagnostics,
            "structural.empty_models",
            "$.semanticModels",
            "at least one semantic model is required",
        );
        valid = false;
    }
    for (index, record) in document.provenance_records.iter().enumerate() {
        if record.generation_method != CsmiGenerationMethod::ManualAuthoring
            && record.inputs.is_empty()
        {
            error(
                diagnostics,
                "structural.provenance_inputs",
                format!("$.provenanceRecords[{index}].inputs"),
                "inputs are required unless generationMethod is manual-authoring",
            );
            valid = false;
        }
        if record.generation_method == CsmiGenerationMethod::Other && record.diagnostic.is_none() {
            error(
                diagnostics,
                "structural.provenance_diagnostic",
                format!("$.provenanceRecords[{index}].diagnostic"),
                "other generation methods require diagnostic metadata",
            );
            valid = false;
        }
    }
    valid
}

fn validate_value_transfer_affect(
    affect: &CsmiAffectedUnit,
    symbols: &HashSet<String>,
    declaration_categories: &HashMap<String, CsmiDeclarationCategory>,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    match affect {
        CsmiAffectedUnit::FactFamily(family) => {
            if family.kind != CsmiAffectedFactFamilyKind::FactFamily {
                return false;
            }
            validate_value_transfer_scope(
                &family.family,
                &family.scope,
                symbols,
                declaration_categories,
                &format!("{path}.scope"),
                diagnostics,
            )
        }
        CsmiAffectedUnit::Attachment(attachment) => {
            let callable = attachment.target.get("callable").and_then(Value::as_str);
            let expected = callable.map(|callable| serde_json::json!({"callable": callable}));
            let mut valid = attachment.kind == CsmiAffectedAttachmentKind::Attachment
                && attachment.attachment_point == "procedure-summary-transfer"
                && expected.as_ref() == Some(&attachment.target);
            if !valid {
                error(
                    diagnostics,
                    "semantic.value_transfer_attachment_scope",
                    path,
                    "value-transfer attachments require procedure-summary-transfer and an exact callable target",
                );
            }
            if let Some(callable) = callable
                && (!symbols.contains(callable)
                    || !matches!(
                        declaration_categories.get(callable),
                        Some(CsmiDeclarationCategory::Callable)
                    ))
            {
                error(
                    diagnostics,
                    "semantic.value_transfer_callable",
                    format!("{path}.target.callable"),
                    "attachment target must be a local callable declaration",
                );
                valid = false;
            }
            valid
        }
        CsmiAffectedUnit::CoreSlot(_) => {
            error(
                diagnostics,
                "semantic.value_transfer_affect_kind",
                path,
                "value-transfer uses may affect only their attachment and fact families",
            );
            false
        }
    }
}

fn validate_value_transfer_scope(
    family: &str,
    scope: &Value,
    symbols: &HashSet<String>,
    declaration_categories: &HashMap<String, CsmiDeclarationCategory>,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let mut valid = true;
    match family {
        "type-value-semantics" => {
            let type_id = scope.get("type").and_then(Value::as_str);
            let aspect = scope.get("aspect").and_then(Value::as_str);
            match (type_id, aspect) {
                (Some(type_id), Some("copy" | "move")) => {
                    valid &= require_value_transfer_type(
                        type_id,
                        symbols,
                        declaration_categories,
                        &format!("{path}.type"),
                        diagnostics,
                    );
                }
                _ => valid = false,
            }
            let expected = type_id
                .zip(aspect)
                .map(|(type_id, aspect)| serde_json::json!({"type": type_id, "aspect": aspect}));
            if expected.as_ref() != Some(scope) {
                valid = false;
            }
        }
        "implicit-operations" => {
            let owner = scope.get("owner").and_then(Value::as_str);
            let operation = scope.get("operation").and_then(Value::as_str);
            let operation = operation.and_then(|value| {
                serde_json::from_value::<CsmiImplicitOperationRole>(Value::String(value.to_owned()))
                    .ok()
            });
            match (owner, operation) {
                (Some(owner), Some(_)) => {
                    valid &= require_value_transfer_type(
                        owner,
                        symbols,
                        declaration_categories,
                        &format!("{path}.owner"),
                        diagnostics,
                    );
                }
                _ => valid = false,
            }
            if operation == Some(CsmiImplicitOperationRole::ConversionOperator) {
                let target = scope.get("target").and_then(Value::as_str);
                if let Some(target) = target {
                    valid &= require_value_transfer_type(
                        target,
                        symbols,
                        declaration_categories,
                        &format!("{path}.target"),
                        diagnostics,
                    );
                } else {
                    valid = false;
                }
            }
            let expected = owner.zip(operation).map(|(owner, operation)| {
                let mut expected = serde_json::json!({"owner": owner, "operation": operation});
                if operation == CsmiImplicitOperationRole::ConversionOperator {
                    expected["target"] = scope.get("target").cloned().unwrap_or(Value::Null);
                }
                expected
            });
            if expected.as_ref() != Some(scope) {
                valid = false;
            }
        }
        "identity-separating-transfers" => {
            let callable = scope.get("callable").and_then(Value::as_str);
            if callable.is_none()
                || !symbols.contains(callable.expect("checked above"))
                || !matches!(
                    declaration_categories.get(callable.expect("checked above")),
                    Some(CsmiDeclarationCategory::Callable)
                )
            {
                valid = false;
            }
            let expected = callable.map(|callable| serde_json::json!({"callable": callable}));
            if expected.as_ref() != Some(scope) {
                valid = false;
            }
        }
        _ => {
            valid = false;
        }
    }
    if !valid {
        error(
            diagnostics,
            "semantic.value_transfer_scope",
            path,
            "value-transfer affected scopes must use the exact profile family shape",
        );
    }
    valid
}

fn require_value_transfer_type(
    id: &str,
    symbols: &HashSet<String>,
    declaration_categories: &HashMap<String, CsmiDeclarationCategory>,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    if !symbols.contains(id) {
        error(
            diagnostics,
            "semantic.value_transfer_local_type",
            path,
            format!("type {id:?} is not a local symbol"),
        );
        return false;
    }
    if !matches!(
        declaration_categories.get(id),
        Some(CsmiDeclarationCategory::Type | CsmiDeclarationCategory::TypeAlias)
    ) {
        error(
            diagnostics,
            "semantic.value_transfer_local_type",
            path,
            "value-transfer type references must target a type or type-alias declaration",
        );
        return false;
    }
    true
}

fn require_value_transfer_callable(
    id: &str,
    symbols: &HashSet<String>,
    declaration_categories: &HashMap<String, CsmiDeclarationCategory>,
    callable_declarations: &HashMap<String, &CsmiCallableShape>,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    if !symbols.contains(id)
        || !matches!(
            declaration_categories.get(id),
            Some(CsmiDeclarationCategory::Callable)
        )
        || !callable_declarations.contains_key(id)
    {
        error(
            diagnostics,
            "semantic.value_transfer_local_callable",
            path,
            "value-transfer callable references must target one local callable declaration",
        );
        return false;
    }
    true
}

fn declaration_owner<'a>(model: &'a CsmiSemanticModel, symbol: &str) -> Option<&'a str> {
    model
        .declarations
        .iter()
        .find(|declaration| declaration.symbol == symbol)
        .and_then(|declaration| declaration.owner.as_deref())
}

fn validate_value_semantics(
    value: &CsmiTypeValueSemantics,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let valid = match value.aspect {
        CsmiTypeValueSemanticsAspect::Copy => matches!(
            value.semantics,
            CsmiTypeSemantics::Trivial {}
                | CsmiTypeSemantics::ViaMember { .. }
                | CsmiTypeSemantics::Unknown { .. }
                | CsmiTypeSemantics::Unsupported { .. }
        ),
        CsmiTypeValueSemanticsAspect::Move => matches!(
            value.semantics,
            CsmiTypeSemantics::Invalidating {}
                | CsmiTypeSemantics::Unknown { .. }
                | CsmiTypeSemantics::Unsupported { .. }
        ),
    };
    let limitation_valid = match &value.semantics {
        CsmiTypeSemantics::Unknown { limitation } => validate_profile_limitation(
            limitation,
            &format!("{path}.semantics.limitation"),
            diagnostics,
        ),
        CsmiTypeSemantics::Unsupported { reason } => {
            reason.as_ref().is_some_and(|reason| !reason.is_empty())
        }
        _ => true,
    };
    if !valid {
        error(
            diagnostics,
            "semantic.value_transfer_semantics",
            format!("{path}.payload.semantics"),
            "copy and move aspects permit only their corresponding semantic variants",
        );
    }
    if !limitation_valid {
        error(
            diagnostics,
            "semantic.value_transfer_limitation",
            format!("{path}.payload.semantics"),
            "unknown and unsupported semantics require a typed non-empty limitation",
        );
    }
    valid && limitation_valid
}

fn validate_profile_limitation(
    limitation: &CsmiProfileLimitation,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    if limitation.kind == CsmiProfileLimitationKind::Other
        && !limitation
            .message
            .as_ref()
            .is_some_and(|message| !message.is_empty())
    {
        error(
            diagnostics,
            "semantic.value_transfer_limitation",
            path,
            "an other limitation requires a non-empty message",
        );
        false
    } else {
        true
    }
}

fn validate_value_operation_shape(
    operation: &CsmiImplicitOperationFact,
    callable_declarations: &HashMap<String, &CsmiCallableShape>,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let Some(shape) = callable_declarations.get(&operation.symbol) else {
        return false;
    };
    let expected = match operation.operation {
        CsmiImplicitOperationRole::CopyConstructor | CsmiImplicitOperationRole::MoveConstructor => {
            CsmiCallableKind::Constructor
        }
        CsmiImplicitOperationRole::CopyAssignment
        | CsmiImplicitOperationRole::MoveAssignment
        | CsmiImplicitOperationRole::ConversionOperator => CsmiCallableKind::Method,
    };
    if shape.kind != expected {
        error(
            diagnostics,
            "semantic.value_transfer_operation_shape",
            format!("{path}.payload.symbol"),
            "implicit operation role is incompatible with the callable declaration kind",
        );
        false
    } else {
        true
    }
}

fn value_fact_affect(value: &CsmiTypeValueSemantics) -> CsmiAffectedUnit {
    CsmiAffectedUnit::FactFamily(CsmiAffectedFactFamily {
        kind: CsmiAffectedFactFamilyKind::FactFamily,
        family: "type-value-semantics".to_owned(),
        scope: serde_json::json!({"type": value.r#type, "aspect": value.aspect}),
    })
}

fn operation_fact_affect(value: &CsmiImplicitOperationFact) -> CsmiAffectedUnit {
    let mut scope = serde_json::json!({"owner": value.owner, "operation": value.operation});
    if value.operation == CsmiImplicitOperationRole::ConversionOperator {
        scope["target"] = serde_json::json!(value.target);
    }
    CsmiAffectedUnit::FactFamily(CsmiAffectedFactFamily {
        kind: CsmiAffectedFactFamilyKind::FactFamily,
        family: "implicit-operations".to_owned(),
        scope,
    })
}

fn require_value_transfer_affect(
    model: &CsmiSemanticModel,
    expected: &CsmiAffectedUnit,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let exact_uses = model.vocabulary_uses.iter().filter(|use_| {
        use_.identifier == CSMI_VALUE_TRANSFER_PROFILE_ID
            && use_.version == CSMI_VALUE_TRANSFER_PROFILE_VERSION
            && use_.schema == CSMI_VALUE_TRANSFER_PROFILE_SCHEMA
    });
    let mut declared = false;
    let mut required = false;
    for use_ in exact_uses {
        if use_.affects.iter().any(|affect| affect == expected) {
            declared = true;
            required |= use_.requirement == CsmiVocabularyRequirement::Required;
        }
    }
    if !declared {
        error(
            diagnostics,
            "semantic.value_transfer_affects",
            path,
            "the exact value-transfer fact or attachment scope is not declared by vocabularyUses",
        );
    } else if !required {
        error(
            diagnostics,
            "semantic.value_transfer_required_use",
            path,
            "a participating value-transfer vocabulary use must be required",
        );
    }
    declared && required
}

fn validate_value_transfer_attachment(
    attachment: &CsmiValueTransferAttachment,
    implicit_facts: &[CsmiImplicitOperationFact],
    symbols: &HashSet<String>,
    declaration_categories: &HashMap<String, CsmiDeclarationCategory>,
    callable_declarations: &HashMap<String, &CsmiCallableShape>,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let mut valid = true;
    match &attachment.operation {
        CsmiValueTransferOperation::None {} => {}
        CsmiValueTransferOperation::Unknown { limitation } => {
            if !validate_profile_limitation(
                limitation,
                &format!("{path}.extensions.operation.limitation"),
                diagnostics,
            ) {
                valid = false;
            }
        }
        CsmiValueTransferOperation::Implicit { symbol } => {
            if !require_value_transfer_callable(
                symbol,
                symbols,
                declaration_categories,
                callable_declarations,
                &format!("{path}.extensions.operation.symbol"),
                diagnostics,
            ) {
                valid = false;
            }
            let candidates = implicit_facts
                .iter()
                .filter(|fact| fact.symbol == *symbol)
                .collect::<Vec<_>>();
            if candidates.len() != 1 {
                error(
                    diagnostics,
                    "semantic.value_transfer_operation_fact",
                    format!("{path}.extensions.operation.symbol"),
                    "an implicit operation reference must resolve to exactly one fact",
                );
                valid = false;
            } else if !value_transfer_role_compatible(
                &attachment.transfer_kind,
                candidates[0].operation,
            ) {
                error(
                    diagnostics,
                    "semantic.value_transfer_operation_role",
                    format!("{path}.extensions.operation.symbol"),
                    "the referenced implicit operation role is incompatible with transfer kind",
                );
                valid = false;
            }
        }
    }
    if value_transfer_has_unknown_detail(attachment) {
        // Unknown details are valid positive evidence; completeness rejects
        // them separately and must not erase the typed uncertainty here.
    }
    valid
}

fn value_transfer_role_compatible(
    transfer_kind: &CsmiValueTransferKind,
    operation: CsmiImplicitOperationRole,
) -> bool {
    match transfer_kind {
        CsmiValueTransferKind::Copy {} | CsmiValueTransferKind::AggregateCopy {} => matches!(
            operation,
            CsmiImplicitOperationRole::CopyConstructor | CsmiImplicitOperationRole::CopyAssignment
        ),
        CsmiValueTransferKind::Move { .. } => matches!(
            operation,
            CsmiImplicitOperationRole::MoveConstructor | CsmiImplicitOperationRole::MoveAssignment
        ),
        CsmiValueTransferKind::Conversion { .. } => {
            operation == CsmiImplicitOperationRole::ConversionOperator
        }
        CsmiValueTransferKind::Boxing {} | CsmiValueTransferKind::Unboxing {} => false,
    }
}

fn value_transfer_has_unknown_detail(attachment: &CsmiValueTransferAttachment) -> bool {
    match &attachment.transfer_kind {
        CsmiValueTransferKind::Move { invalidation } => {
            *invalidation == CsmiMoveInvalidation::Unknown
        }
        CsmiValueTransferKind::Conversion { preservation } => {
            *preservation == CsmiValuePreservation::Unknown
        }
        _ => matches!(
            attachment.operation,
            CsmiValueTransferOperation::Unknown { .. }
        ),
    }
}

fn validate_non_transfer_value_attachments(
    extensions: &[CsmiExtensionAttachment],
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
    allow_transfer: bool,
) -> bool {
    let mut valid = true;
    for (index, extension) in extensions.iter().enumerate() {
        if extension.vocabulary == CSMI_VALUE_TRANSFER_PROFILE_ID
            && extension.version == CSMI_VALUE_TRANSFER_PROFILE_VERSION
            && !allow_transfer
        {
            error(
                diagnostics,
                "semantic.value_transfer_attachment_point",
                format!("{path}[{index}]"),
                "value-transfer payloads attach only to a procedure-summary transfer",
            );
            valid = false;
        }
    }
    valid
}

fn validate_cpp_semantics(
    model: &CsmiSemanticModel,
    prefix: &str,
    symbols: &HashSet<String>,
    declaration_categories: &HashMap<String, CsmiDeclarationCategory>,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let mut valid = true;
    for (index, use_) in model.vocabulary_uses.iter().enumerate() {
        if matches!(
            use_.identifier.as_str(),
            CSMI_C_CPP_RESOLUTION_PROFILE_ID | CSMI_CPP_PROFILE_ID
        ) && use_.requirement != CsmiVocabularyRequirement::Required
        {
            error(
                diagnostics,
                "semantic.cpp_required_use",
                format!("{prefix}.vocabularyUses[{index}].requirement"),
                "portable C/C++ identity and applicability vocabularies must be required",
            );
            valid = false;
        }
    }

    let mut contexts = HashMap::new();
    for (index, constraint) in model.compatibility_constraints.iter().enumerate() {
        if constraint.vocabulary != CSMI_C_CPP_RESOLUTION_PROFILE_ID
            || constraint.version != CSMI_C_CPP_RESOLUTION_PROFILE_VERSION
        {
            continue;
        }
        let path = format!("{prefix}.compatibilityConstraints[{index}].value");
        match serde_json::from_value::<CsmiResolutionContext>(constraint.value.clone()) {
            Ok(context) => match canonical_digest(&context) {
                Ok(digest) => {
                    if contexts.insert(digest, context.language).is_some() {
                        error(
                            diagnostics,
                            "semantic.cpp_duplicate_context",
                            path,
                            "resolution context digest is repeated",
                        );
                        valid = false;
                    }
                }
                Err(cause) => {
                    error(
                        diagnostics,
                        "semantic.cpp_context_digest",
                        path,
                        cause.to_string(),
                    );
                    valid = false;
                }
            },
            Err(cause) => {
                error(
                    diagnostics,
                    "semantic.cpp_resolution_context",
                    path,
                    cause.to_string(),
                );
                valid = false;
            }
        }
    }

    let cpp_symbols: HashMap<&str, CsmiCppSymbolKey> = model
        .symbols
        .iter()
        .filter(|symbol| symbol.scheme == CSMI_CPP_DECLARATION_IDENTITY_SCHEME)
        .map(|symbol| {
            let selectors = symbol
                .artifact_selectors
                .as_deref()
                .unwrap_or(&model.artifact_selectors);
            (
                symbol.id.as_str(),
                CsmiCppSymbolKey {
                    artifact_selectors: selectors
                        .iter()
                        .map(|selector| CsmiCppArtifactSelector {
                            purl: selector.purl.clone(),
                            digests: selector
                                .digests
                                .iter()
                                .filter(|digest| digest.algorithm == CsmiDigestAlgorithm::Sha256)
                                .map(|digest| CsmiCppArtifactDigest {
                                    algorithm: CsmiCppDigestAlgorithm::Sha256,
                                    coverage: digest.coverage.clone(),
                                    canonicalization: digest.canonicalization.clone(),
                                    value: digest.value.clone(),
                                })
                                .collect(),
                        })
                        .collect(),
                    scheme: symbol.scheme.clone(),
                    scheme_version: symbol.scheme_version.clone(),
                    stability: CsmiCppIdentityStability::Portable,
                    descriptors: symbol
                        .descriptors
                        .iter()
                        .filter_map(|descriptor| {
                            Some(CsmiCppDescriptor {
                                role: match descriptor.role {
                                    CsmiDescriptorRole::Namespace => {
                                        CsmiCppDescriptorRole::Namespace
                                    }
                                    CsmiDescriptorRole::Type => CsmiCppDescriptorRole::Type,
                                    CsmiDescriptorRole::Callable => CsmiCppDescriptorRole::Callable,
                                    _ => return None,
                                },
                                name: descriptor.name.clone()?,
                                disambiguator: descriptor.disambiguator.clone()?,
                            })
                        })
                        .collect(),
                },
            )
        })
        .collect();
    for (id, key) in &cpp_symbols {
        if !validate_cpp_symbol_key(key, &format!("{prefix}.symbols[{id}]"), diagnostics) {
            valid = false;
        }
    }

    let mut alias_facts: HashMap<String, &Value> = HashMap::new();
    let mut special_member_facts: HashMap<String, &Value> = HashMap::new();
    for (index, fact) in model.extension_facts.iter().enumerate() {
        if fact.vocabulary != CSMI_CPP_PROFILE_ID || fact.version != CSMI_CPP_PROFILE_VERSION {
            continue;
        }
        let path = format!("{prefix}.extensionFacts[{index}]");
        let payload = match serde_json::from_value::<CsmiCppProfilePayload>(fact.payload.clone()) {
            Ok(payload) => payload,
            Err(cause) => {
                error(
                    diagnostics,
                    "semantic.cpp_payload",
                    format!("{path}.payload"),
                    cause.to_string(),
                );
                valid = false;
                continue;
            }
        };
        match &payload {
            CsmiCppProfilePayload::ResolutionContext(_) => {
                error(
                    diagnostics,
                    "semantic.cpp_context_location",
                    format!("{path}.payload"),
                    "resolution-context belongs in compatibilityConstraints",
                );
                valid = false;
            }
            CsmiCppProfilePayload::TypeAlias(alias) => {
                let expected_scope = serde_json::json!({"alias": alias.alias});
                if fact.family != "type-alias" || fact.scope != expected_scope {
                    error(
                        diagnostics,
                        "semantic.cpp_alias_family_scope",
                        format!("{path}.scope"),
                        "type-alias fact family and scope must be keyed by its alias",
                    );
                    valid = false;
                }
                if alias_facts
                    .insert(alias.alias.clone(), &fact.payload)
                    .is_some_and(|prior| prior != &fact.payload)
                {
                    error(
                        diagnostics,
                        "semantic.cpp_alias_conflict",
                        &path,
                        "equal type-alias keys carry conflicting facts",
                    );
                    valid = false;
                }
                if declaration_categories.get(&alias.alias)
                    != Some(&CsmiDeclarationCategory::TypeAlias)
                {
                    error(
                        diagnostics,
                        "semantic.cpp_alias_symbol",
                        format!("{path}.payload.alias"),
                        "type-alias fact must name a declared type alias",
                    );
                    valid = false;
                }
                if !validate_cpp_type(
                    &alias.target,
                    &cpp_symbols,
                    &format!("{path}.payload.target"),
                    diagnostics,
                ) {
                    valid = false;
                }
                if !validate_cpp_context_ref(
                    &alias.resolution_context,
                    &contexts,
                    &format!("{path}.payload.resolutionContext"),
                    diagnostics,
                ) {
                    valid = false;
                }
            }
            CsmiCppProfilePayload::SpecialMember(member) => {
                let expected_scope = serde_json::json!({
                    "owner": member.owner,
                    "operation": member.operation
                });
                if fact.family != "special-member" || fact.scope != expected_scope {
                    error(
                        diagnostics,
                        "semantic.cpp_special_member_family_scope",
                        format!("{path}.scope"),
                        "special-member fact family and scope must be keyed by owner and operation",
                    );
                    valid = false;
                }
                let special_key = format!("{}:{:?}", member.owner, member.operation);
                if special_member_facts
                    .insert(special_key, &fact.payload)
                    .is_some_and(|prior| prior != &fact.payload)
                {
                    error(
                        diagnostics,
                        "semantic.cpp_special_member_conflict",
                        &path,
                        "equal special-member keys carry conflicting facts",
                    );
                    valid = false;
                }
                if declaration_categories.get(&member.owner) != Some(&CsmiDeclarationCategory::Type)
                    || declaration_categories.get(&member.member)
                        != Some(&CsmiDeclarationCategory::Callable)
                    || declaration_owner(model, &member.member) != Some(member.owner.as_str())
                {
                    error(
                        diagnostics,
                        "semantic.cpp_special_member_identity",
                        format!("{path}.payload.member"),
                        "special member must name an exact callable and owner",
                    );
                    valid = false;
                }
                if !symbols.contains(&member.owner) || !symbols.contains(&member.member) {
                    valid = false;
                }
                let expected = canonical_digest(&member.signature)
                    .map(|digest| format!("cppsig-0.1:{digest}"));
                if !expected
                    .as_ref()
                    .is_ok_and(|value| value == &member.member_disambiguator)
                {
                    error(
                        diagnostics,
                        "semantic.cpp_signature_digest",
                        format!("{path}.payload.memberDisambiguator"),
                        "member disambiguator must equal the RFC 8785 signature digest",
                    );
                    valid = false;
                }
                if cpp_symbols.get(member.owner.as_str()) != Some(&member.signature.owner) {
                    error(
                        diagnostics,
                        "semantic.cpp_signature_owner",
                        format!("{path}.payload.signature.owner"),
                        "canonical signature owner must equal the declared owner key",
                    );
                    valid = false;
                }
                if !csmi_cpp_signature_matches_operation(
                    member.operation,
                    &member.signature,
                    &member.signature.owner,
                ) {
                    error(
                        diagnostics,
                        "semantic.cpp_signature_shape",
                        format!("{path}.payload.signature"),
                        "canonical signature shape must match the special-member operation",
                    );
                    valid = false;
                }
                for (suffix, value) in member
                    .signature
                    .receiver
                    .iter()
                    .map(|value| ("receiver".to_owned(), value))
                    .chain(
                        member
                            .signature
                            .parameters
                            .iter()
                            .enumerate()
                            .map(|(index, value)| (format!("parameters[{index}]"), value)),
                    )
                    .chain(
                        member
                            .signature
                            .result
                            .iter()
                            .map(|value| ("result".to_owned(), value)),
                    )
                {
                    if !validate_cpp_type(
                        value,
                        &cpp_symbols,
                        &format!("{path}.payload.signature.{suffix}"),
                        diagnostics,
                    ) {
                        valid = false;
                    }
                }
                if !validate_cpp_context_ref(
                    &member.resolution_context,
                    &contexts,
                    &format!("{path}.payload.resolutionContext"),
                    diagnostics,
                ) {
                    valid = false;
                }
            }
        }
    }
    valid
}

fn validate_cpp_context_ref(
    reference: &CsmiCppResolutionContext,
    contexts: &HashMap<String, CsmiCppLanguage>,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let valid = reference.version == CSMI_C_CPP_RESOLUTION_PROFILE_VERSION
        && reference.language == CsmiCppProfileLanguage::Cpp
        && contexts.get(&reference.context_digest) == Some(&CsmiCppLanguage::Cpp);
    if !valid {
        error(
            diagnostics,
            "semantic.cpp_context_reference",
            path,
            "C++ facts require an exact declared complete resolution context",
        );
    }
    valid
}

fn csmi_cpp_signature_matches_operation(
    operation: CsmiCppSpecialMemberOperation,
    signature: &CsmiCppCallableSignature,
    owner: &CsmiCppSymbolKey,
) -> bool {
    match operation {
        CsmiCppSpecialMemberOperation::CopyConstructor => {
            signature.callable_kind == CsmiCppCallableKind::Constructor
                && signature.receiver.is_none()
                && signature.result.is_none()
                && signature.parameters.len() == 1
                && csmi_cpp_reference_to_owner(
                    &signature.parameters[0],
                    CsmiCppReferenceKind::Lvalue,
                    true,
                    owner,
                )
        }
        CsmiCppSpecialMemberOperation::CopyAssignment => {
            signature.callable_kind == CsmiCppCallableKind::Method
                && signature.receiver.as_ref().is_some_and(|value| {
                    csmi_cpp_reference_to_owner(value, CsmiCppReferenceKind::Lvalue, false, owner)
                })
                && signature.parameters.len() == 1
                && csmi_cpp_reference_to_owner(
                    &signature.parameters[0],
                    CsmiCppReferenceKind::Lvalue,
                    true,
                    owner,
                )
                && signature.result.as_ref().is_some_and(|value| {
                    csmi_cpp_reference_to_owner(value, CsmiCppReferenceKind::Lvalue, false, owner)
                })
        }
        CsmiCppSpecialMemberOperation::MoveConstructor => {
            signature.callable_kind == CsmiCppCallableKind::Constructor
                && signature.receiver.is_none()
                && signature.result.is_none()
                && signature.parameters.len() == 1
                && csmi_cpp_reference_to_owner(
                    &signature.parameters[0],
                    CsmiCppReferenceKind::Rvalue,
                    false,
                    owner,
                )
        }
    }
}

fn csmi_cpp_reference_to_owner(
    value: &CsmiCppCanonicalType,
    expected_kind: CsmiCppReferenceKind,
    expect_const: bool,
    owner: &CsmiCppSymbolKey,
) -> bool {
    let CsmiCppCanonicalType::Reference(reference) = value else {
        return false;
    };
    if reference.reference_kind != expected_kind {
        return false;
    }
    let referent = if expect_const {
        let CsmiCppCanonicalType::Qualified(qualified) = reference.referent.as_ref() else {
            return false;
        };
        if qualified.qualifiers.as_slice() != [CsmiCppTypeQualifier::Const] {
            return false;
        }
        qualified.r#type.as_ref()
    } else {
        reference.referent.as_ref()
    };
    matches!(referent, CsmiCppCanonicalType::Declared(declared) if &declared.symbol == owner)
}

fn validate_cpp_symbol_key(
    key: &CsmiCppSymbolKey,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let mut valid = key.scheme == CSMI_CPP_DECLARATION_IDENTITY_SCHEME
        && key.scheme_version == CSMI_CPP_DECLARATION_IDENTITY_SCHEME_VERSION
        && !key.artifact_selectors.is_empty()
        && !key.descriptors.is_empty();
    for selector in &key.artifact_selectors {
        if !selector.purl.contains('@')
            || selector.digests.is_empty()
            || selector.digests.iter().any(|digest| {
                digest.value.len() != 64
                    || !digest
                        .value
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
        {
            valid = false;
        }
    }
    if !valid {
        error(
            diagnostics,
            "semantic.cpp_symbol_key",
            path,
            "portable C++ keys require the exact scheme, descriptors, and artifact SHA-256",
        );
    }
    valid
}

fn validate_cpp_type(
    value: &CsmiCppCanonicalType,
    symbols: &HashMap<&str, CsmiCppSymbolKey>,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let mut valid = true;
    let mut stack = vec![(path.to_owned(), value)];
    while let Some((current_path, current)) = stack.pop() {
        match current {
            CsmiCppCanonicalType::Fundamental(_) => {}
            CsmiCppCanonicalType::Declared(value) => {
                if !symbols.values().any(|key| key == &value.symbol) {
                    error(
                        diagnostics,
                        "semantic.cpp_type_symbol",
                        current_path,
                        "declared canonical type must use a model portable symbol key",
                    );
                    valid = false;
                }
            }
            CsmiCppCanonicalType::TemplateSpecialization(value) => {
                if !symbols.values().any(|key| key == &value.primary) {
                    error(
                        diagnostics,
                        "semantic.cpp_template_primary",
                        format!("{current_path}.primary"),
                        "template primary must use a model portable symbol key",
                    );
                    valid = false;
                }
                for (index, argument) in value.arguments.iter().enumerate().rev() {
                    stack.push((format!("{current_path}.arguments[{index}]"), argument));
                }
            }
            CsmiCppCanonicalType::Qualified(value) => {
                stack.push((format!("{current_path}.type"), &value.r#type));
            }
            CsmiCppCanonicalType::Reference(value) => {
                stack.push((format!("{current_path}.referent"), &value.referent));
            }
        }
    }
    valid
}

fn validate_manifest_shape(
    manifest: &CsmiPackManifest,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let mut valid = true;
    if manifest.document_type != "pack-manifest" {
        error(
            diagnostics,
            "structural.document_type",
            "$.documentType",
            "must be pack-manifest",
        );
        valid = false;
    }
    if manifest.schema != CSMI_SCHEMA_URI {
        error(
            diagnostics,
            "structural.schema_identifier",
            "$.schema",
            "must use the pinned CSMI v0.1 schema URI",
        );
        valid = false;
    }
    if manifest.pack_format_version != CSMI_PACK_FORMAT_VERSION {
        error(
            diagnostics,
            "structural.pack_format_version",
            "$.packFormatVersion",
            "unsupported pack format version",
        );
        valid = false;
    }
    if manifest.resources.is_empty() {
        error(
            diagnostics,
            "structural.empty_resources",
            "$.resources",
            "at least one resource is required",
        );
        valid = false;
    }
    if !manifest
        .resources
        .iter()
        .any(|resource| resource.role == CsmiResourceRole::SemanticDocument)
    {
        error(
            diagnostics,
            "structural.missing_semantic_resource",
            "$.resources",
            "a pack must contain a semantic-document resource",
        );
        valid = false;
    }
    for (index, resource) in manifest.resources.iter().enumerate() {
        if let Err(reason) = validate_resource_path(&resource.path) {
            error(
                diagnostics,
                "structural.resource_path",
                format!("$.resources[{index}].path"),
                reason,
            );
            valid = false;
        }
        if resource.digest.algorithm != CsmiContentDigestAlgorithm::Sha256
            || resource.digest.value.len() != 64
            || !resource
                .digest
                .value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            error(
                diagnostics,
                "structural.resource_digest",
                format!("$.resources[{index}].digest.value"),
                "resource digest must be lowercase SHA-256 hex",
            );
            valid = false;
        }
        if resource.role == CsmiResourceRole::SemanticDocument
            && resource.media_type != CSMI_SEMANTIC_DOCUMENT_MEDIA_TYPE
        {
            error(
                diagnostics,
                "structural.semantic_media_type",
                format!("$.resources[{index}].mediaType"),
                "semantic-document resource has the wrong media type",
            );
            valid = false;
        }
        if resource.role == CsmiResourceRole::VocabularySchema
            && resource.schema_identifier.is_none()
        {
            error(
                diagnostics,
                "structural.vocabulary_schema_identifier",
                format!("$.resources[{index}].schemaIdentifier"),
                "vocabulary-schema resources require schemaIdentifier",
            );
            valid = false;
        }
    }
    valid
}

fn validate_semantic_document(
    document: &CsmiSemanticDocument,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let mut valid = true;
    let provenance_ids = unique_ids(
        document
            .provenance_records
            .iter()
            .map(|record| record.id.as_str()),
        "$.provenanceRecords",
        diagnostics,
    );
    if let Some(default) = &document.default_provenance {
        require_id(
            &provenance_ids,
            default,
            "$.defaultProvenance",
            "provenance record",
            diagnostics,
        );
    }
    for (index, record) in document.provenance_records.iter().enumerate() {
        validate_provenance_references(
            &record.inputs,
            &format!("$.provenanceRecords[{index}].inputs"),
            diagnostics,
        );
    }
    for (index, model) in document.semantic_models.iter().enumerate() {
        if !validate_model(model, document, index, diagnostics) {
            valid = false;
        }
    }
    valid
        && !diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code.starts_with("semantic."))
}

fn validate_interpretability(
    document: &CsmiSemanticDocument,
    support: &CsmiVocabularySupport,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let mut interpretable = true;
    for (model_index, model) in document.semantic_models.iter().enumerate() {
        for (use_index, use_) in model.vocabulary_uses.iter().enumerate() {
            if use_.requirement == CsmiVocabularyRequirement::Required
                && !support.supports(&use_.identifier, &use_.version, &use_.schema)
            {
                error(
                    diagnostics,
                    "interpretability.unsupported_required_vocabulary",
                    format!("$.semanticModels[{model_index}].vocabularyUses[{use_index}]"),
                    format!(
                        "required vocabulary {} {} is unsupported",
                        use_.identifier, use_.version
                    ),
                );
                interpretable = false;
            }
        }
    }
    interpretable
}

fn validate_model(
    model: &CsmiSemanticModel,
    document: &CsmiSemanticDocument,
    model_index: usize,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let prefix = format!("$.semanticModels[{model_index}]");
    let mut valid = true;
    if model.artifact_selectors.is_empty() {
        error(
            diagnostics,
            "semantic.artifact_selectors",
            format!("{prefix}.artifactSelectors"),
            "at least one artifact selector is required",
        );
        valid = false;
    }
    for (index, selector) in model.artifact_selectors.iter().enumerate() {
        if !validate_selector(
            selector,
            &format!("{prefix}.artifactSelectors[{index}]"),
            diagnostics,
        ) {
            valid = false;
        }
    }
    let symbols = unique_ids(
        model.symbols.iter().map(|symbol| symbol.id.as_str()),
        &format!("{prefix}.symbols"),
        diagnostics,
    );
    let mut declaration_categories = HashMap::new();
    for (index, declaration) in model.declarations.iter().enumerate() {
        let path = format!("{prefix}.declarations[{index}]");
        if !require_id(
            &symbols,
            &declaration.symbol,
            format!("{path}.symbol"),
            "symbol",
            diagnostics,
        ) {
            valid = false;
        }
        if declaration_categories
            .insert(declaration.symbol.clone(), declaration.category)
            .is_some()
        {
            error(
                diagnostics,
                "semantic.duplicate_declaration",
                format!("{path}.symbol"),
                "a symbol has more than one declaration",
            );
            valid = false;
        }
        if declaration.category == CsmiDeclarationCategory::Callable
            && declaration.callable.is_none()
        {
            error(
                diagnostics,
                "semantic.callable_shape_missing",
                format!("{path}.callable"),
                "callable declarations require callable shape",
            );
            valid = false;
        }
        if declaration.category != CsmiDeclarationCategory::Callable
            && declaration.callable.is_some()
        {
            error(
                diagnostics,
                "semantic.callable_shape_unexpected",
                format!("{path}.callable"),
                "only callable declarations may carry callable shape",
            );
            valid = false;
        }
        if declaration.category == CsmiDeclarationCategory::TypeAlias
            && declaration.alias_target.is_none()
        {
            error(
                diagnostics,
                "semantic.alias_target_missing",
                format!("{path}.aliasTarget"),
                "type-alias declarations require aliasTarget",
            );
            valid = false;
        }
        if declaration.category != CsmiDeclarationCategory::TypeAlias
            && declaration.alias_target.is_some()
        {
            error(
                diagnostics,
                "semantic.alias_target_unexpected",
                format!("{path}.aliasTarget"),
                "only type-alias declarations may carry aliasTarget",
            );
            valid = false;
        }
        if let Some(alias_target) = &declaration.alias_target
            && !validate_type_expression(
                alias_target,
                &symbols,
                &format!("{path}.aliasTarget"),
                diagnostics,
            )
        {
            valid = false;
        }
        if let Some(owner) = &declaration.owner {
            require_id(
                &symbols,
                owner,
                format!("{path}.owner"),
                "owner symbol",
                diagnostics,
            );
        }
        if let Some(shape) = &declaration.callable
            && !validate_callable_shape(shape, &format!("{path}.callable"), &symbols, diagnostics)
        {
            valid = false;
        }
        validate_provenance_ids(
            &declaration.provenance,
            &format!("{path}.provenance"),
            document,
            diagnostics,
        );
    }
    let mut callable_declarations = HashMap::new();
    for declaration in &model.declarations {
        if let Some(shape) = &declaration.callable {
            callable_declarations.insert(declaration.symbol.clone(), shape);
        }
    }
    for (index, relationship) in model.relationships.iter().enumerate() {
        let path = format!("{prefix}.relationships[{index}]");
        let (subject, object) = match relationship {
            CsmiRelationship::Type(relationship) => (&relationship.subject, &relationship.object),
            CsmiRelationship::Member(relationship) => (&relationship.subject, &relationship.object),
        };
        if !require_id(
            &symbols,
            subject,
            format!("{path}.subject"),
            "symbol",
            diagnostics,
        ) {
            valid = false;
        }
        if !require_id(
            &symbols,
            object,
            format!("{path}.object"),
            "symbol",
            diagnostics,
        ) {
            valid = false;
        }
        if let CsmiRelationship::Type(relationship) = relationship {
            for (argument_index, argument) in relationship.type_arguments.iter().enumerate() {
                if !validate_type_expression(
                    argument,
                    &symbols,
                    &format!("{path}.typeArguments[{argument_index}]"),
                    diagnostics,
                ) {
                    valid = false;
                }
            }
        }
    }
    for (index, summary) in model.procedure_summaries.iter().enumerate() {
        let path = format!("{prefix}.procedureSummaries[{index}]");
        let Some(shape) = callable_declarations.get(&summary.callable) else {
            error(
                diagnostics,
                "semantic.summary_target",
                format!("{path}.callable"),
                "procedure summary must target a declared callable",
            );
            valid = false;
            continue;
        };
        if !validate_summary(summary, shape, &path, &symbols, diagnostics) {
            valid = false;
        }
    }
    let uses = collect_vocabulary_uses(model);
    for (index, use_) in model.vocabulary_uses.iter().enumerate() {
        if use_.affects.is_empty() {
            error(
                diagnostics,
                "semantic.vocabulary_affects",
                format!("{prefix}.vocabularyUses[{index}].affects"),
                "a vocabulary use must affect at least one unit",
            );
            valid = false;
        }
    }
    for (index, fact) in model.extension_facts.iter().enumerate() {
        let path = format!("{prefix}.extensionFacts[{index}]");
        if !uses.contains(&(fact.vocabulary.clone(), fact.version.clone())) {
            error(
                diagnostics,
                "semantic.undeclared_vocabulary",
                format!("{path}.vocabulary"),
                "extension fact uses a vocabulary not declared by vocabularyUses",
            );
            valid = false;
        }
        validate_provenance_ids(
            &fact.provenance,
            &format!("{path}.provenance"),
            document,
            diagnostics,
        );
    }
    let mut completeness_scopes = HashSet::new();
    for (index, statement) in model.completeness_statements.iter().enumerate() {
        let path = format!("{prefix}.completenessStatements[{index}]");
        let key = format!(
            "{}:{}:{}:{}",
            statement.vocabulary.as_deref().unwrap_or("core"),
            statement.version.as_deref().unwrap_or(""),
            statement.family,
            canonical_scope(&statement.scope)
        );
        if !completeness_scopes.insert(key) {
            error(
                diagnostics,
                "semantic.duplicate_completeness_scope",
                &path,
                "completeness scope is repeated",
            );
            valid = false;
        }
        if statement.status == CsmiCoverageStatus::Partial && statement.limitations.is_empty() {
            error(
                diagnostics,
                "semantic.partial_without_limitation",
                format!("{path}.limitations"),
                "partial coverage requires a limitation",
            );
            valid = false;
        }
        if statement.status == CsmiCoverageStatus::Complete && !statement.limitations.is_empty() {
            error(
                diagnostics,
                "semantic.complete_with_limitation",
                format!("{path}.limitations"),
                "complete coverage cannot carry limitations",
            );
            valid = false;
        }
        if statement.family == "procedure-summaries" {
            if let Some(callable) = statement.scope.get("callable").and_then(Value::as_str) {
                require_id(
                    &symbols,
                    callable,
                    format!("{path}.scope.callable"),
                    "callable symbol",
                    diagnostics,
                );
            } else {
                error(
                    diagnostics,
                    "semantic.completeness_scope",
                    format!("{path}.scope.callable"),
                    "procedure-summaries scope requires callable",
                );
                valid = false;
            }
        }
        validate_provenance_ids(
            &statement.provenance,
            &format!("{path}.provenance"),
            document,
            diagnostics,
        );
    }
    for (index, dependency) in model.consumer_resolved_dependencies.iter().enumerate() {
        let path = format!("{prefix}.consumerResolvedDependencies[{index}]");
        if !require_id(
            &symbols,
            &dependency.symbol,
            format!("{path}.symbol"),
            "dependency symbol",
            diagnostics,
        ) {
            valid = false;
        }
        if dependency.aspect == CsmiDependencyAspect::Relationships
            && (dependency.predicate.is_none() || dependency.object.is_none())
        {
            error(
                diagnostics,
                "semantic.relationship_dependency",
                path.clone(),
                "relationship dependencies require predicate and object",
            );
            valid = false;
        }
        for (argument_index, argument) in dependency.type_arguments.iter().enumerate() {
            if !validate_type_expression(
                argument,
                &symbols,
                &format!("{path}.typeArguments[{argument_index}]"),
                diagnostics,
            ) {
                valid = false;
            }
        }
    }
    if !validate_value_transfer_semantics(
        model,
        &prefix,
        &symbols,
        &declaration_categories,
        &callable_declarations,
        diagnostics,
    ) {
        valid = false;
    }
    if !validate_cpp_semantics(
        model,
        &prefix,
        &symbols,
        &declaration_categories,
        diagnostics,
    ) {
        valid = false;
    }
    if !validate_runtime_values_semantics(model, &prefix, diagnostics) {
        valid = false;
    }
    if !validate_collection_flow_semantics(
        model,
        &prefix,
        &symbols,
        &declaration_categories,
        &callable_declarations,
        diagnostics,
    ) {
        valid = false;
    }
    if !validate_deferred_yield_semantics(
        model,
        &prefix,
        &symbols,
        &declaration_categories,
        &callable_declarations,
        diagnostics,
    ) {
        valid = false;
    }
    valid
}

fn validate_deferred_yield_semantics(
    model: &CsmiSemanticModel,
    prefix: &str,
    symbols: &HashSet<String>,
    declaration_categories: &HashMap<String, CsmiDeclarationCategory>,
    callable_declarations: &HashMap<String, &CsmiCallableShape>,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let uses: Vec<(usize, &CsmiVocabularyUse)> = model
        .vocabulary_uses
        .iter()
        .enumerate()
        .filter(|(_, use_)| use_.identifier == CSMI_DEFERRED_YIELD_PROFILE_ID)
        .collect();
    let facts: Vec<(usize, &CsmiExtensionFact)> = model
        .extension_facts
        .iter()
        .enumerate()
        .filter(|(_, fact)| fact.vocabulary == CSMI_DEFERRED_YIELD_PROFILE_ID)
        .collect();
    if uses.is_empty() && facts.is_empty() {
        return true;
    }
    let mut valid = true;
    let mut affects = HashSet::new();
    for (index, use_) in &uses {
        let path = format!("{prefix}.vocabularyUses[{index}]");
        if use_.version != CSMI_DEFERRED_YIELD_PROFILE_VERSION
            || use_.schema != CSMI_DEFERRED_YIELD_PROFILE_SCHEMA
        {
            error(
                diagnostics,
                "semantic.deferred_yield_profile_identity",
                &path,
                "deferred-yield requires exact version 0.1.0 and schema URI",
            );
            valid = false;
            continue;
        }
        if use_.requirement != CsmiVocabularyRequirement::Required {
            error(
                diagnostics,
                "semantic.deferred_yield_required_use",
                format!("{path}.requirement"),
                "deferred-yield facts require an exact required vocabulary use",
            );
            valid = false;
        }
        for (affect_index, affect) in use_.affects.iter().enumerate() {
            let affect_path = format!("{path}.affects[{affect_index}]");
            let CsmiAffectedUnit::FactFamily(family) = affect else {
                error(
                    diagnostics,
                    "semantic.deferred_yield_affect_kind",
                    affect_path,
                    "deferred-yield affects must identify a fact family",
                );
                valid = false;
                continue;
            };
            if family.kind != CsmiAffectedFactFamilyKind::FactFamily
                || family.family != "deferred-yields"
                || !deferred_yield_scope_shape(
                    &family.scope,
                    symbols,
                    declaration_categories,
                    &format!("{affect_path}.scope"),
                    diagnostics,
                )
            {
                error(
                    diagnostics,
                    "semantic.deferred_yield_affect_scope",
                    affect_path,
                    "deferred-yield affects must use family deferred-yields and an exact linked scope",
                );
                valid = false;
                continue;
            }
            affects.insert(canonical_scope(&family.scope));
        }
    }
    if facts
        .iter()
        .any(|(_, fact)| fact.version != CSMI_DEFERRED_YIELD_PROFILE_VERSION)
        || !uses.iter().any(|(_, use_)| {
            use_.version == CSMI_DEFERRED_YIELD_PROFILE_VERSION
                && use_.schema == CSMI_DEFERRED_YIELD_PROFILE_SCHEMA
        })
    {
        return false;
    }
    let mut scoped_payloads: HashMap<String, Vec<CsmiDeferredYieldPayload>> = HashMap::new();
    for (index, fact) in facts {
        let path = format!("{prefix}.extensionFacts[{index}]");
        if fact.family != "deferred-yields" {
            error(
                diagnostics,
                "semantic.deferred_yield_family",
                format!("{path}.family"),
                "deferred-yield facts must use family deferred-yields",
            );
            valid = false;
            continue;
        }
        let Some(scope) = deferred_yield_scope(
            &fact.scope,
            symbols,
            declaration_categories,
            &format!("{path}.scope"),
            diagnostics,
        ) else {
            valid = false;
            continue;
        };
        let expected_scope = serde_json::json!({
            "factory": scope.0,
            "resume": scope.1,
            "handleType": scope.2,
        });
        if fact.scope != expected_scope {
            error(
                diagnostics,
                "semantic.deferred_yield_scope",
                format!("{path}.scope"),
                "deferred-yield scope must be exactly factory, resume, and handleType",
            );
            valid = false;
        }
        let payload: CsmiDeferredYieldPayload = match serde_json::from_value(fact.payload.clone()) {
            Ok(payload) => payload,
            Err(cause) => {
                error(
                    diagnostics,
                    "semantic.deferred_yield_payload",
                    format!("{path}.payload"),
                    cause.to_string(),
                );
                valid = false;
                continue;
            }
        };
        if payload.kind != CsmiDeferredYieldKind::DeferredYield
            || payload.factory != scope.0
            || payload.resume != scope.1
            || payload.handle_type != scope.2
        {
            error(
                diagnostics,
                "semantic.deferred_yield_payload_scope",
                format!("{path}.payload"),
                "payload kind and linked endpoint identities must match the fact scope",
            );
            valid = false;
        }
        if !validate_deferred_yield_payload(
            &payload,
            model,
            symbols,
            declaration_categories,
            callable_declarations,
            &format!("{path}.payload"),
            diagnostics,
        ) {
            valid = false;
        }
        let scope_key = canonical_scope(&expected_scope);
        if !affects.contains(&scope_key) {
            error(
                diagnostics,
                "semantic.deferred_yield_missing_affect",
                format!("{path}.scope"),
                "deferred-yield fact scope must be listed in vocabularyUses.affects",
            );
            valid = false;
        }
        scoped_payloads.entry(scope_key).or_default().push(payload);
    }
    let mut coverage_scopes = HashSet::new();
    for (index, statement) in model.completeness_statements.iter().enumerate() {
        if statement.vocabulary.as_deref() != Some(CSMI_DEFERRED_YIELD_PROFILE_ID) {
            continue;
        }
        let path = format!("{prefix}.completenessStatements[{index}]");
        if statement.version.as_deref() != Some(CSMI_DEFERRED_YIELD_PROFILE_VERSION)
            || statement.family != "deferred-yields"
            || !coverage_scopes.insert(canonical_scope(&statement.scope))
        {
            error(
                diagnostics,
                "semantic.deferred_yield_completeness_identity",
                &path,
                "coverage requires the exact version, family, and unique linked scope",
            );
            valid = false;
        }
        if !deferred_yield_scope_shape(
            &statement.scope,
            symbols,
            declaration_categories,
            &format!("{path}.scope"),
            diagnostics,
        ) || !affects.contains(&canonical_scope(&statement.scope))
        {
            error(
                diagnostics,
                "semantic.deferred_yield_completeness_scope",
                format!("{path}.scope"),
                "deferred-yield completeness must use an affected exact linked scope",
            );
            valid = false;
        }
        if statement.status == CsmiCoverageStatus::Complete {
            let Some(payloads) = scoped_payloads.get(&canonical_scope(&statement.scope)) else {
                error(
                    diagnostics,
                    "semantic.deferred_yield_missing_fact",
                    format!("{path}.status"),
                    "complete deferred-yield coverage requires a matching fact",
                );
                valid = false;
                continue;
            };
            let scope = deferred_yield_scope(
                &statement.scope,
                symbols,
                declaration_categories,
                &format!("{path}.scope"),
                diagnostics,
            );
            let endpoint_shapes_complete = scope.is_some_and(|(factory, resume, _)| {
                [factory, resume].into_iter().all(|symbol| {
                    model.completeness_statements.iter().any(|candidate| {
                        candidate.vocabulary.is_none()
                            && candidate.version.is_none()
                            && candidate.family == "declaration-aspects"
                            && candidate.status == CsmiCoverageStatus::Complete
                            && candidate.scope.get("symbol").and_then(Value::as_str) == Some(symbol)
                            && candidate.scope.get("aspect").and_then(Value::as_str)
                                == Some("callable-shape")
                    })
                })
            });
            if !endpoint_shapes_complete
                || payloads.iter().any(deferred_yield_payload_uncertain)
                || payloads.windows(2).any(|window| window[0] != window[1])
            {
                error(
                    diagnostics,
                    "semantic.deferred_yield_incomplete_claim",
                    format!("{path}.status"),
                    "complete deferred-yield coverage cannot contain uncertainty or conflicting records",
                );
                valid = false;
            }
        }
    }
    valid
}

/// Validate deferred-yield facts embedded in a native authored shard.
///
/// Native producers already hold the CSMI typed payload, so they bypass JSON
/// Schema deserialization. Rebuild the small declaration index from the
/// semantic model and run the same linked-scope joins used for imported wire
/// documents before allowing a complete fact to be published.
pub(crate) fn validate_native_deferred_yield_model(
    model: &CsmiSemanticModel,
) -> Vec<CsmiDiagnostic> {
    let mut symbols: HashSet<String> = model
        .declarations
        .iter()
        .map(|declaration| declaration.symbol.clone())
        .collect();
    symbols.extend(model.symbols.iter().map(|symbol| symbol.id.clone()));
    let declaration_categories: HashMap<String, CsmiDeclarationCategory> = model
        .declarations
        .iter()
        .map(|declaration| (declaration.symbol.clone(), declaration.category))
        .collect();
    let callable_declarations: HashMap<String, &CsmiCallableShape> = model
        .declarations
        .iter()
        .filter_map(|declaration| {
            declaration
                .callable
                .as_ref()
                .map(|shape| (declaration.symbol.clone(), shape))
        })
        .collect();
    let mut diagnostics = Vec::new();
    let (profile_index, _) = known_profile(
        CSMI_DEFERRED_YIELD_PROFILE_ID,
        CSMI_DEFERRED_YIELD_PROFILE_SCHEMA,
    )
    .expect("deferred-yield profile is registered");
    let schema = profile_schema_validators()[profile_index]
        .as_ref()
        .expect("payload schema");
    for fact in model
        .extension_facts
        .iter()
        .filter(|fact| fact.vocabulary == CSMI_DEFERRED_YIELD_PROFILE_ID)
    {
        for violation in schema.iter_errors(&fact.payload) {
            error(
                &mut diagnostics,
                "deferred_yield.schema",
                "$",
                violation.to_string(),
            );
        }
    }
    let valid = validate_deferred_yield_semantics(
        model,
        "$",
        &symbols,
        &declaration_categories,
        &callable_declarations,
        &mut diagnostics,
    );
    if !valid && diagnostics.is_empty() {
        error(
            &mut diagnostics,
            "deferred_yield.invalid",
            "$",
            "invalid deferred-yield contract",
        );
    }
    diagnostics
}

fn deferred_yield_scope<'a>(
    scope: &'a Value,
    symbols: &HashSet<String>,
    declaration_categories: &HashMap<String, CsmiDeclarationCategory>,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> Option<(&'a str, &'a str, &'a str)> {
    let object = scope.as_object()?;
    if object.len() != 3 {
        error(
            diagnostics,
            "semantic.deferred_yield_scope",
            path,
            "deferred-yield scope must contain exactly three linked identities",
        );
        return None;
    }
    let factory = object.get("factory")?.as_str()?;
    let resume = object.get("resume")?.as_str()?;
    let handle_type = object.get("handleType")?.as_str()?;
    let callable = |id: &str| {
        symbols.contains(id)
            && matches!(
                declaration_categories.get(id),
                Some(CsmiDeclarationCategory::Callable)
            )
    };
    let mut valid = true;
    if !callable(factory) || !callable(resume) || factory == resume {
        error(
            diagnostics,
            "semantic.deferred_yield_scope_callable",
            path,
            "factory and resume must be distinct local callable declarations",
        );
        valid = false;
    }
    if !symbols.contains(handle_type)
        || !matches!(
            declaration_categories.get(handle_type),
            Some(CsmiDeclarationCategory::Type | CsmiDeclarationCategory::TypeAlias)
        )
    {
        error(
            diagnostics,
            "semantic.deferred_yield_scope_type",
            path,
            "handleType must be a local type declaration",
        );
        valid = false;
    }
    valid.then_some((factory, resume, handle_type))
}

fn validate_deferred_yield_payload(
    payload: &CsmiDeferredYieldPayload,
    model: &CsmiSemanticModel,
    symbols: &HashSet<String>,
    declaration_categories: &HashMap<String, CsmiDeclarationCategory>,
    callable_declarations: &HashMap<String, &CsmiCallableShape>,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let mut valid = true;
    let Some(factory_shape) = callable_declarations.get(&payload.factory) else {
        return false;
    };
    let Some(resume_shape) = callable_declarations.get(&payload.resume) else {
        return false;
    };
    if !validate_deferred_yield_substitution(
        payload.receiver_substitution.as_ref(),
        model,
        factory_shape,
        &format!("{path}.receiverSubstitution"),
        diagnostics,
    ) {
        valid = false;
    }
    let mut roots: HashMap<String, CsmiDeferredYieldShape> = HashMap::new();
    for (index, root) in payload.roots.iter().enumerate() {
        let root_path = format!("{path}.roots[{index}]");
        let key = deferred_yield_root_key(&root.callable, &root.root);
        if roots.insert(key, root.shape.clone()).is_some() {
            error(
                diagnostics,
                "semantic.deferred_yield_duplicate_root",
                format!("{root_path}.root"),
                "deferred-yield roots must be unique",
            );
            valid = false;
        }
        if !symbols.contains(&root.callable)
            || !matches!(
                declaration_categories.get(&root.callable),
                Some(CsmiDeclarationCategory::Callable)
            )
        {
            error(
                diagnostics,
                "semantic.deferred_yield_root_callable",
                format!("{root_path}.callable"),
                "root callable must be a local callable declaration",
            );
            valid = false;
        }
        if !validate_deferred_yield_shape(
            &root.shape,
            declaration_categories,
            &format!("{root_path}.shape"),
            diagnostics,
        ) {
            valid = false;
        }
    }
    if !validate_deferred_yield_location(
        &payload.construction.source,
        &payload.factory,
        "input",
        factory_shape,
        &roots,
        &format!("{path}.construction.source"),
        diagnostics,
    ) || !validate_deferred_yield_location(
        &payload.construction.handle,
        &payload.factory,
        "output",
        factory_shape,
        &roots,
        &format!("{path}.construction.handle"),
        diagnostics,
    ) {
        valid = false;
    }
    let handle_shape = deferred_yield_shape_at_location(
        &payload.construction.handle,
        &roots,
        factory_shape,
        &format!("{path}.construction.handle"),
        diagnostics,
    );
    let resume_handle_shape = deferred_yield_shape_at_location(
        &payload.resume_contract.handle_input,
        &roots,
        resume_shape,
        &format!("{path}.resumeContract.handleInput"),
        diagnostics,
    );
    if let (Some(factory_handle), Some(resume_handle)) = (&handle_shape, &resume_handle_shape)
        && (factory_handle != resume_handle
            || !deferred_yield_shape_is_handle_type(factory_handle, &payload.handle_type))
    {
        error(
            diagnostics,
            "semantic.deferred_yield_handle_shape",
            format!("{path}.resumeContract"),
            "factory handle output and resume handle input must have the exact declared handleType",
        );
        valid = false;
    }
    if !validate_deferred_yield_location(
        &payload.resume_contract.handle_input,
        &payload.resume,
        "input",
        resume_shape,
        &roots,
        &format!("{path}.resumeContract.handleInput"),
        diagnostics,
    ) || !validate_deferred_yield_location(
        &payload.resume_contract.yielded_result,
        &payload.resume,
        "output",
        resume_shape,
        &roots,
        &format!("{path}.resumeContract.yieldedResult"),
        diagnostics,
    ) {
        valid = false;
    }
    let item_shape = deferred_yield_shape_at_location(
        &payload.resume_contract.yielded_result,
        &roots,
        resume_shape,
        &format!("{path}.resumeContract.yieldedResult"),
        diagnostics,
    );
    if payload.resume_contract.factory_result_flow.kind
        != CsmiDeferredYieldFactoryResultFlowKind::RequiredConsumerProof
        || payload.resume_contract.factory_result_flow.factory_result != payload.construction.handle
        || payload.resume_contract.factory_result_flow.resume_input
            != payload.resume_contract.handle_input
    {
        error(
            diagnostics,
            "semantic.deferred_yield_flow",
            format!("{path}.resumeContract.factoryResultFlow"),
            "factory-result flow must repeat the exact construction handle and resume input",
        );
        valid = false;
    }
    if !validate_deferred_yield_retention(
        &payload.construction.retention,
        &format!("{path}.construction.retention"),
        diagnostics,
    ) || !validate_deferred_yield_validity(
        &payload.construction.validity,
        &format!("{path}.construction.validity"),
        diagnostics,
    ) {
        valid = false;
    }
    if payload.yield_contract.timing != CsmiDeferredYieldTiming::AfterConstruction
        || payload.yield_contract.per_resume != CsmiDeferredYieldPerResume::ZeroOrOne
        || payload.yield_contract.per_handle != CsmiDeferredYieldPerHandle::ZeroOrMore
        || payload.yield_contract.members.is_empty()
    {
        error(
            diagnostics,
            "semantic.deferred_yield_multiplicity",
            format!("{path}.yield"),
            "deferred-yield timing and multiplicity must use the exact profile constants",
        );
        valid = false;
    }
    let mut positions = HashSet::new();
    let mut source_observations = HashSet::new();
    let mut roles = HashSet::new();
    for (index, member) in payload.yield_contract.members.iter().enumerate() {
        let member_path = format!("{path}.yield.members[{index}]");
        if !positions.insert(member.position) || member.position as usize != index {
            error(
                diagnostics,
                "semantic.deferred_yield_member_position",
                format!("{member_path}.position"),
                "yield member positions must be unique and contiguous",
            );
            valid = false;
        }
        if member.source.root != payload.construction.source.root
            || !source_observations
                .insert(serde_json::to_string(&member.source).expect("typed location serializes"))
        {
            error(
                diagnostics,
                "semantic.deferred_yield_member_source",
                &member_path,
                "yield members require unique observations of the construction source",
            );
            valid = false;
        }
        if !validate_deferred_yield_location(
            &member.source,
            &payload.factory,
            "input",
            factory_shape,
            &roots,
            &format!("{member_path}.source"),
            diagnostics,
        ) {
            valid = false;
        }
        if !validate_deferred_yield_delivery(
            &member.delivery,
            &format!("{member_path}.delivery"),
            diagnostics,
        ) {
            valid = false;
        }
        if !roles.insert(member.role) {
            error(
                diagnostics,
                "semantic.deferred_yield_member_role",
                format!("{member_path}.role"),
                "yield member roles must be distinct",
            );
            valid = false;
        }
        let steps = member
            .source
            .projection
            .as_ref()
            .map(|projection| projection.steps.as_slice())
            .unwrap_or(&[]);
        match member.role {
            CsmiDeferredYieldMemberRole::Key
                if !matches!(
                    steps.last(),
                    Some(CsmiDeferredYieldProjectionStep::EntryKey)
                ) =>
            {
                error(
                    diagnostics,
                    "semantic.deferred_yield_member_projection",
                    format!("{member_path}.source"),
                    "key role requires an explicit entry-key projection",
                );
                valid = false;
            }
            CsmiDeferredYieldMemberRole::Value
                if !matches!(
                    steps.last(),
                    Some(CsmiDeferredYieldProjectionStep::EntryValue)
                ) =>
            {
                error(
                    diagnostics,
                    "semantic.deferred_yield_member_projection",
                    format!("{member_path}.source"),
                    "value role requires an explicit entry-value projection",
                );
                valid = false;
            }
            CsmiDeferredYieldMemberRole::Key | CsmiDeferredYieldMemberRole::Value => {}
            CsmiDeferredYieldMemberRole::Item => {}
        }
        if let (Some(item_shape), Some(source_shape)) = (
            item_shape.as_ref(),
            deferred_yield_shape_at_location(
                &member.source,
                &roots,
                factory_shape,
                &format!("{member_path}.source"),
                diagnostics,
            )
            .as_ref(),
        ) && let CsmiDeferredYieldShape::Product { components } = item_shape
        {
            let Some(destination_shape) = components.get(member.position as usize) else {
                error(
                    diagnostics,
                    "semantic.deferred_yield_member_position",
                    format!("{member_path}.position"),
                    "yield member position must be present in the yielded result shape",
                );
                valid = false;
                continue;
            };
            if !matches!(
                member.delivery,
                CsmiDeferredYieldDelivery::Mode(CsmiDeferredYieldDeliveryMode::Derived)
            ) && source_shape != destination_shape
            {
                error(
                    diagnostics,
                    "semantic.deferred_yield_member_shape",
                    format!("{member_path}.source"),
                    "non-derived member source and yielded result component must have identical shapes",
                );
                valid = false;
            }
        }
        if matches!(
            (&payload.construction.retention, &member.delivery),
            (
                CsmiDeferredYieldRetention::Mode(CsmiDeferredYieldRetentionMode::BorrowedShared),
                CsmiDeferredYieldDelivery::Mode(
                    CsmiDeferredYieldDeliveryMode::ExclusiveBorrow
                        | CsmiDeferredYieldDeliveryMode::Move
                )
            ) | (
                CsmiDeferredYieldRetention::Mode(CsmiDeferredYieldRetentionMode::BorrowedExclusive),
                CsmiDeferredYieldDelivery::Mode(CsmiDeferredYieldDeliveryMode::Move)
            )
        ) {
            error(
                diagnostics,
                "semantic.deferred_yield_retention_delivery",
                format!("{member_path}.delivery"),
                "delivery cannot exceed the construction retention relationship",
            );
            valid = false;
        }
    }
    valid
        && positions
            .iter()
            .copied()
            .all(|position| position < payload.yield_contract.members.len() as u32)
        && positions.len() == payload.yield_contract.members.len()
}

fn deferred_yield_root_key(callable: &str, root: &CsmiDeferredYieldBoundaryRoot) -> String {
    format!(
        "{callable}:{}",
        serde_json::to_string(root).expect("CSMI root serializes")
    )
}

fn validate_deferred_yield_substitution(
    substitution: Option<&CsmiDeferredYieldSubstitution>,
    model: &CsmiSemanticModel,
    factory: &CsmiCallableShape,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let Some(substitution) = substitution else {
        return true;
    };
    match substitution {
        CsmiDeferredYieldSubstitution::Unknown { limitation }
        | CsmiDeferredYieldSubstitution::Unsupported { limitation } => {
            validate_profile_limitation(limitation, &format!("{path}.limitation"), diagnostics)
        }
        CsmiDeferredYieldSubstitution::ReceiverArguments { declaration } => {
            let Some(record) = model
                .declarations
                .iter()
                .find(|record| record.symbol == *declaration)
            else {
                error(
                    diagnostics,
                    "semantic.deferred_yield_substitution",
                    path,
                    "receiver substitution declaration must be local",
                );
                return false;
            };
            if !matches!(
                record.category,
                CsmiDeclarationCategory::Type | CsmiDeclarationCategory::TypeAlias
            ) {
                error(
                    diagnostics,
                    "semantic.deferred_yield_substitution",
                    path,
                    "receiver substitution declaration must be a type",
                );
                return false;
            }
            let matches_factory = factory.receiver.as_ref().is_some_and(|receiver| {
                matches!(
                    receiver.receiver_type.as_ref(),
                    Some(CsmiTypeExpression::Reference(reference))
                        if reference.symbol == *declaration
                )
            });
            if !matches_factory {
                error(
                    diagnostics,
                    "semantic.deferred_yield_substitution",
                    path,
                    "receiver substitution must bind the factory receiver declaration",
                );
            }
            let Some(receiver_type) = factory
                .receiver
                .as_ref()
                .and_then(|receiver| receiver.receiver_type.as_ref())
            else {
                return false;
            };
            let CsmiTypeExpression::Reference(receiver_reference) = receiver_type else {
                return false;
            };
            validate_receiver_generic_arguments(
                receiver_reference,
                record,
                "semantic.deferred_yield_receiver_arguments",
                path,
                diagnostics,
            ) && matches_factory
        }
    }
}

fn validate_receiver_generic_arguments(
    receiver_reference: &CsmiReferenceType,
    declaration: &CsmiDeclaration,
    diagnostic_code: &str,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let parameters = &declaration.generic_parameters;
    if parameters
        .iter()
        .map(|parameter| &parameter.symbol)
        .collect::<HashSet<_>>()
        .len()
        != parameters.len()
    {
        error(
            diagnostics,
            diagnostic_code,
            path,
            "receiver declaration generic parameter symbols must be unique",
        );
        return false;
    }
    if receiver_reference.arguments.len() != parameters.len() {
        error(
            diagnostics,
            diagnostic_code,
            path,
            "receiver type arguments must cover every declaration generic parameter",
        );
        return false;
    }
    let mut valid = true;
    for (index, parameter) in parameters.iter().enumerate() {
        if parameter.position != index as u32
            || !matches!(
                receiver_reference.arguments.get(index),
                Some(CsmiTypeExpression::Parameter(argument))
                    if argument.symbol == parameter.symbol
            )
        {
            error(
                diagnostics,
                diagnostic_code,
                path,
                "receiver generic arguments must preserve declaration order",
            );
            valid = false;
        }
    }
    valid
}

fn validate_deferred_yield_shape(
    shape: &CsmiDeferredYieldShape,
    declarations: &HashMap<String, CsmiDeclarationCategory>,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let mut stack = vec![(shape, path.to_owned())];
    let mut valid = true;
    while let Some((shape, path)) = stack.pop() {
        match shape {
            CsmiDeferredYieldShape::Value { r#type } => {
                if !validate_deferred_yield_type_expression(
                    r#type,
                    declarations,
                    &format!("{path}.type"),
                    diagnostics,
                ) {
                    valid = false;
                }
            }
            CsmiDeferredYieldShape::Product { components } => {
                if components.is_empty() {
                    error(
                        diagnostics,
                        "semantic.deferred_yield_shape_product",
                        path,
                        "product shapes require at least one component",
                    );
                    valid = false;
                    continue;
                }
                for (index, component) in components.iter().enumerate().rev() {
                    stack.push((component, format!("{path}.components[{index}]")));
                }
            }
            CsmiDeferredYieldShape::Keyed {
                key,
                value,
                entry_components,
            } => {
                stack.push((value, format!("{path}.value")));
                stack.push((key, format!("{path}.key")));
                if let Some(components) = entry_components
                    && (components.len() != 2
                        || components.iter().collect::<HashSet<_>>().len() != 2)
                {
                    error(
                        diagnostics,
                        "semantic.deferred_yield_entry_components",
                        format!("{path}.entryComponents"),
                        "entryComponents must list key and value exactly once",
                    );
                    valid = false;
                }
            }
            CsmiDeferredYieldShape::Unknown { limitation } => {
                if !validate_profile_limitation(
                    limitation,
                    &format!("{path}.limitation"),
                    diagnostics,
                ) {
                    valid = false;
                }
            }
        }
    }
    valid
}

fn validate_deferred_yield_type_expression(
    expression: &CsmiDeferredYieldTypeExpression,
    declarations: &HashMap<String, CsmiDeclarationCategory>,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let mut stack = vec![(expression, path.to_owned())];
    let mut valid = true;
    while let Some((expression, path)) = stack.pop() {
        match expression {
            CsmiTypeExpression::Unknown(_) => {}
            CsmiTypeExpression::Reference(reference) => {
                if !matches!(
                    declarations.get(&reference.symbol),
                    Some(CsmiDeclarationCategory::Type | CsmiDeclarationCategory::TypeAlias)
                ) {
                    error(
                        diagnostics,
                        "semantic.deferred_yield_shape_type",
                        &path,
                        "reference type must name a local type declaration",
                    );
                    valid = false;
                }
                for (index, argument) in reference.arguments.iter().enumerate().rev() {
                    stack.push((argument, format!("{path}.arguments[{index}]")));
                }
            }
            CsmiTypeExpression::Parameter(parameter) => {
                if declarations.get(&parameter.symbol)
                    != Some(&CsmiDeclarationCategory::TypeParameter)
                {
                    error(
                        diagnostics,
                        "semantic.deferred_yield_shape_type",
                        &path,
                        "parameter type must name a local type-parameter declaration",
                    );
                    valid = false;
                }
            }
            CsmiTypeExpression::Intrinsic(_) => {
                error(
                    diagnostics,
                    "semantic.deferred_yield_shape_type",
                    &path,
                    "intrinsic type expressions are not part of deferred-yield 0.1",
                );
                valid = false;
            }
        }
    }
    valid
}

fn deferred_yield_shape_at_location(
    location: &CsmiDeferredYieldLocation,
    roots: &HashMap<String, CsmiDeferredYieldShape>,
    callable: &CsmiCallableShape,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> Option<CsmiDeferredYieldShape> {
    let key = deferred_yield_root_key(&location.callable, &location.root);
    let mut current = roots.get(&key)?.clone();
    let Some(projection) = &location.projection else {
        return Some(current);
    };
    for (index, step) in projection.steps.iter().enumerate() {
        let step_path = format!("{path}.projection.steps[{index}]");
        match step {
            CsmiDeferredYieldProjectionStep::Entry { args } => {
                let CsmiDeferredYieldShape::Keyed { key, value, .. } = current else {
                    error(
                        diagnostics,
                        "semantic.deferred_yield_projection_shape",
                        step_path,
                        "entry projection requires a keyed shape",
                    );
                    return None;
                };
                if let CsmiDeferredYieldEntrySelector::Parameter { position } = args.key
                    && position as usize >= callable.parameters.len()
                {
                    return None;
                }
                current = CsmiDeferredYieldShape::Product {
                    components: vec![*key, *value],
                };
            }
            CsmiDeferredYieldProjectionStep::EntryKey => {
                let CsmiDeferredYieldShape::Product { components } = current else {
                    return None;
                };
                if components.len() != 2 {
                    return None;
                }
                current = components.into_iter().next().expect("two components");
            }
            CsmiDeferredYieldProjectionStep::EntryValue => {
                let CsmiDeferredYieldShape::Product { components } = current else {
                    return None;
                };
                if components.len() != 2 {
                    return None;
                }
                current = components.into_iter().nth(1).expect("two components");
            }
        }
    }
    Some(current)
}

fn deferred_yield_shape_is_handle_type(shape: &CsmiDeferredYieldShape, handle_type: &str) -> bool {
    matches!(
        shape,
        CsmiDeferredYieldShape::Value {
            r#type: CsmiTypeExpression::Reference(reference)
        } if reference.symbol == handle_type
    )
}

fn validate_deferred_yield_location(
    location: &CsmiDeferredYieldLocation,
    expected_callable: &str,
    phase: &str,
    callable: &CsmiCallableShape,
    roots: &HashMap<String, CsmiDeferredYieldShape>,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let mut valid = location.callable == expected_callable;
    if !valid {
        error(
            diagnostics,
            "semantic.deferred_yield_location_callable",
            format!("{path}.callable"),
            "location callable must match its linked endpoint",
        );
    }
    let root_phase = match &location.root {
        CsmiDeferredYieldBoundaryRoot::InputReceiver(_) => {
            if phase != "input" || callable.receiver.is_none() {
                valid = false;
            }
            Some("input")
        }
        CsmiDeferredYieldBoundaryRoot::InputParameter(root) => {
            if phase != "input" || root.position as usize >= callable.parameters.len() {
                valid = false;
            }
            Some("input")
        }
        CsmiDeferredYieldBoundaryRoot::OutputResult(root) => {
            if phase != "output" || root.position as usize >= callable.results.len() {
                valid = false;
            }
            Some("output")
        }
    };
    if root_phase != Some(phase) {
        valid = false;
    }
    let key = deferred_yield_root_key(&location.callable, &location.root);
    let Some(root_shape) = roots.get(&key) else {
        error(
            diagnostics,
            "semantic.deferred_yield_missing_shape",
            format!("{path}.root"),
            "location root must have a shape declared by the payload",
        );
        return false;
    };
    if let Some(projection) = &location.projection
        && !validate_deferred_yield_projection(
            projection,
            root_shape,
            callable,
            &format!("{path}.projection"),
            diagnostics,
        )
    {
        valid = false;
    }
    valid
}

fn validate_deferred_yield_projection(
    projection: &CsmiDeferredYieldProjection,
    root_shape: &CsmiDeferredYieldShape,
    callable: &CsmiCallableShape,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let mut valid = projection.scheme == CSMI_DEFERRED_YIELD_PROFILE_ID
        && projection.scheme_version == CSMI_DEFERRED_YIELD_PROFILE_VERSION
        && !projection.steps.is_empty();
    if !valid {
        error(
            diagnostics,
            "semantic.deferred_yield_projection_identity",
            path,
            "projection must use the exact deferred-yield scheme and a non-empty step list",
        );
    }
    let mut current = root_shape.clone();
    let mut entry_open = false;
    for (index, step) in projection.steps.iter().enumerate() {
        let step_path = format!("{path}.steps[{index}]");
        match step {
            CsmiDeferredYieldProjectionStep::Entry { args } => {
                let CsmiDeferredYieldShape::Keyed { key, value, .. } = &current else {
                    error(
                        diagnostics,
                        "semantic.deferred_yield_projection_shape",
                        &step_path,
                        "entry projection requires a keyed shape",
                    );
                    valid = false;
                    continue;
                };
                if let CsmiDeferredYieldEntrySelector::Parameter { position } = &args.key
                    && *position as usize >= callable.parameters.len()
                {
                    error(
                        diagnostics,
                        "semantic.deferred_yield_projection_args",
                        &step_path,
                        "entry parameter selector is outside the callable shape",
                    );
                    valid = false;
                }
                current = CsmiDeferredYieldShape::Product {
                    components: vec![(**key).clone(), (**value).clone()],
                };
                entry_open = true;
            }
            CsmiDeferredYieldProjectionStep::EntryKey
            | CsmiDeferredYieldProjectionStep::EntryValue => {
                if !entry_open
                    || !matches!(&current, CsmiDeferredYieldShape::Product { components } if components.len() == 2)
                {
                    error(
                        diagnostics,
                        "semantic.deferred_yield_projection_shape",
                        &step_path,
                        "entry member projection requires a preceding entry projection",
                    );
                    valid = false;
                    continue;
                }
                current = match (&current, step) {
                    (
                        CsmiDeferredYieldShape::Product { components },
                        CsmiDeferredYieldProjectionStep::EntryKey,
                    ) => components[0].clone(),
                    (
                        CsmiDeferredYieldShape::Product { components },
                        CsmiDeferredYieldProjectionStep::EntryValue,
                    ) => components[1].clone(),
                    _ => unreachable!("entry projection shape checked above"),
                };
                entry_open = false;
            }
        }
    }
    valid
}

fn validate_deferred_yield_retention(
    retention: &CsmiDeferredYieldRetention,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    match retention {
        CsmiDeferredYieldRetention::Mode(_) => true,
        CsmiDeferredYieldRetention::Uncertain(uncertainty) => validate_profile_limitation(
            &uncertainty.limitation,
            &format!("{path}.limitation"),
            diagnostics,
        ),
    }
}

fn validate_deferred_yield_validity(
    validity: &CsmiDeferredYieldValidity,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    match validity {
        CsmiDeferredYieldValidity::Unknown { limitation }
        | CsmiDeferredYieldValidity::Unsupported { limitation } => {
            validate_profile_limitation(limitation, &format!("{path}.limitation"), diagnostics)
        }
        CsmiDeferredYieldValidity::SourceRetained { invalidation }
        | CsmiDeferredYieldValidity::HandleRetained { invalidation }
        | CsmiDeferredYieldValidity::Independent { invalidation } => {
            validate_deferred_yield_invalidation(
                invalidation,
                &format!("{path}.invalidation"),
                diagnostics,
            )
        }
    }
}

fn validate_deferred_yield_invalidation(
    invalidation: &CsmiDeferredYieldInvalidation,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    match invalidation {
        CsmiDeferredYieldInvalidation::Unknown { limitation }
        | CsmiDeferredYieldInvalidation::Unsupported { limitation } => {
            validate_profile_limitation(limitation, &format!("{path}.limitation"), diagnostics)
        }
        CsmiDeferredYieldInvalidation::SourceMutation { .. }
        | CsmiDeferredYieldInvalidation::HandleDrop { .. }
        | CsmiDeferredYieldInvalidation::NoneAsserted => true,
    }
}

fn validate_deferred_yield_delivery(
    delivery: &CsmiDeferredYieldDelivery,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    match delivery {
        CsmiDeferredYieldDelivery::Mode(_) => true,
        CsmiDeferredYieldDelivery::Uncertain(uncertainty) => validate_profile_limitation(
            &uncertainty.limitation,
            &format!("{path}.limitation"),
            diagnostics,
        ),
    }
}

fn deferred_yield_payload_uncertain(payload: &CsmiDeferredYieldPayload) -> bool {
    let retention_unknown = matches!(
        &payload.construction.retention,
        CsmiDeferredYieldRetention::Uncertain(_)
    );
    let validity_unknown = matches!(
        &payload.construction.validity,
        CsmiDeferredYieldValidity::Unknown { .. } | CsmiDeferredYieldValidity::Unsupported { .. }
    );
    let invalidation_unknown = match &payload.construction.validity {
        CsmiDeferredYieldValidity::SourceRetained { invalidation }
        | CsmiDeferredYieldValidity::HandleRetained { invalidation }
        | CsmiDeferredYieldValidity::Independent { invalidation } => matches!(
            invalidation,
            CsmiDeferredYieldInvalidation::Unknown { .. }
                | CsmiDeferredYieldInvalidation::Unsupported { .. }
        ),
        CsmiDeferredYieldValidity::Unknown { .. }
        | CsmiDeferredYieldValidity::Unsupported { .. } => false,
    };
    retention_unknown
        || validity_unknown
        || invalidation_unknown
        || payload
            .receiver_substitution
            .as_ref()
            .is_some_and(|substitution| {
                matches!(
                    substitution,
                    CsmiDeferredYieldSubstitution::Unknown { .. }
                        | CsmiDeferredYieldSubstitution::Unsupported { .. }
                )
            })
        || payload
            .yield_contract
            .members
            .iter()
            .any(|member| matches!(&member.delivery, CsmiDeferredYieldDelivery::Uncertain(_)))
        || payload
            .roots
            .iter()
            .any(|root| deferred_yield_shape_uncertain(&root.shape))
}

fn deferred_yield_shape_uncertain(shape: &CsmiDeferredYieldShape) -> bool {
    let mut shapes = vec![shape];
    let mut types = Vec::new();
    while let Some(shape) = shapes.pop() {
        match shape {
            CsmiDeferredYieldShape::Unknown { .. } => return true,
            CsmiDeferredYieldShape::Value { r#type } => types.push(r#type),
            CsmiDeferredYieldShape::Product { components } => shapes.extend(components),
            CsmiDeferredYieldShape::Keyed { key, value, .. } => {
                shapes.push(key);
                shapes.push(value);
            }
        }
    }
    while let Some(ty) = types.pop() {
        match ty {
            CsmiTypeExpression::Unknown(_) => return true,
            CsmiTypeExpression::Reference(reference) => types.extend(&reference.arguments),
            CsmiTypeExpression::Parameter(_) | CsmiTypeExpression::Intrinsic(_) => {}
        }
    }
    false
}

fn deferred_yield_scope_shape(
    scope: &Value,
    symbols: &HashSet<String>,
    declaration_categories: &HashMap<String, CsmiDeclarationCategory>,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    deferred_yield_scope(scope, symbols, declaration_categories, path, diagnostics).is_some()
}

fn validate_collection_flow_semantics(
    model: &CsmiSemanticModel,
    prefix: &str,
    symbols: &HashSet<String>,
    declaration_categories: &HashMap<String, CsmiDeclarationCategory>,
    callable_declarations: &HashMap<String, &CsmiCallableShape>,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let uses: Vec<(usize, &CsmiVocabularyUse)> = model
        .vocabulary_uses
        .iter()
        .enumerate()
        .filter(|(_, use_)| use_.identifier == CSMI_COLLECTION_FLOW_PROFILE_ID)
        .collect();
    let facts: Vec<(usize, &CsmiExtensionFact)> = model
        .extension_facts
        .iter()
        .enumerate()
        .filter(|(_, fact)| fact.vocabulary == CSMI_COLLECTION_FLOW_PROFILE_ID)
        .collect();
    if facts.is_empty() && uses.is_empty() {
        return true;
    }
    let mut valid = true;
    let exact_use = uses.iter().filter(|(_, use_)| {
        use_.version == CSMI_COLLECTION_FLOW_PROFILE_VERSION
            && use_.schema == CSMI_COLLECTION_FLOW_PROFILE_SCHEMA
    });
    let mut affects = HashSet::new();
    for (index, use_) in &uses {
        let path = format!("{prefix}.vocabularyUses[{index}]");
        if use_.version != CSMI_COLLECTION_FLOW_PROFILE_VERSION
            || use_.schema != CSMI_COLLECTION_FLOW_PROFILE_SCHEMA
        {
            continue;
        }
        if use_.requirement != CsmiVocabularyRequirement::Required {
            error(
                diagnostics,
                "semantic.collection_flow_required_use",
                format!("{path}.requirement"),
                "collection-flow facts require an exact required vocabulary use",
            );
            valid = false;
        }
        for (affect_index, affect) in use_.affects.iter().enumerate() {
            let affect_path = format!("{path}.affects[{affect_index}]");
            let CsmiAffectedUnit::FactFamily(family) = affect else {
                error(
                    diagnostics,
                    "semantic.collection_flow_affect_kind",
                    affect_path,
                    "collection-flow affects must identify a fact family",
                );
                valid = false;
                continue;
            };
            if family.kind != CsmiAffectedFactFamilyKind::FactFamily
                || family.family != "collection-flows"
                || family
                    .scope
                    .get("callable")
                    .and_then(Value::as_str)
                    .is_none()
            {
                error(
                    diagnostics,
                    "semantic.collection_flow_affect_scope",
                    affect_path,
                    "collection-flow affects must use family collection-flows and a callable scope",
                );
                valid = false;
                continue;
            }
            affects.insert(canonical_scope(&family.scope));
        }
    }
    if facts
        .iter()
        .any(|(_, fact)| fact.version != CSMI_COLLECTION_FLOW_PROFILE_VERSION)
        || exact_use.count() == 0
    {
        return false;
    }
    let mut fact_scopes = HashSet::new();
    for (index, fact) in facts {
        let path = format!("{prefix}.extensionFacts[{index}]");
        if fact.version != CSMI_COLLECTION_FLOW_PROFILE_VERSION {
            error(
                diagnostics,
                "semantic.collection_flow_version",
                format!("{path}.version"),
                "collection-flow fact version must be exactly 0.1.0",
            );
            valid = false;
            continue;
        }
        if fact.family != "collection-flows" {
            error(
                diagnostics,
                "semantic.collection_flow_family",
                format!("{path}.family"),
                "collection-flow facts must use family collection-flows",
            );
            valid = false;
        }
        let Some(callable) = fact.scope.get("callable").and_then(Value::as_str) else {
            error(
                diagnostics,
                "semantic.collection_flow_scope",
                format!("{path}.scope.callable"),
                "collection-flow scope requires one callable",
            );
            valid = false;
            continue;
        };
        let scope = serde_json::json!({"callable": callable});
        if fact.scope != scope || !fact_scopes.insert(canonical_scope(&fact.scope)) {
            error(
                diagnostics,
                "semantic.collection_flow_scope",
                format!("{path}.scope"),
                "collection-flow scope must be exactly {callable} and unique",
            );
            valid = false;
        }
        if !symbols.contains(callable)
            || !matches!(
                declaration_categories.get(callable),
                Some(CsmiDeclarationCategory::Callable)
            )
            || !callable_declarations.contains_key(callable)
        {
            error(
                diagnostics,
                "semantic.collection_flow_callable",
                format!("{path}.scope.callable"),
                "collection-flow callable must name a local callable declaration",
            );
            valid = false;
            continue;
        }
        let payload: CsmiCollectionFlowPayload = match serde_json::from_value(fact.payload.clone())
        {
            Ok(payload) => payload,
            Err(error_value) => {
                error(
                    diagnostics,
                    "semantic.collection_flow_payload",
                    format!("{path}.payload"),
                    error_value.to_string(),
                );
                valid = false;
                continue;
            }
        };
        if payload.kind != CsmiCollectionFlowKind::CollectionFlow || payload.callable != callable {
            error(
                diagnostics,
                "semantic.collection_flow_payload_scope",
                format!("{path}.payload.callable"),
                "payload kind and callable must match the fact scope",
            );
            valid = false;
        }
        let shape = callable_declarations[callable];
        if !validate_collection_flow_payload(
            &payload,
            shape,
            model,
            symbols,
            &format!("{path}.payload"),
            diagnostics,
        ) {
            valid = false;
        }
        if !affects.contains(&canonical_scope(&scope)) {
            error(
                diagnostics,
                "semantic.collection_flow_missing_affect",
                format!("{path}.scope"),
                "collection-flow fact scope must be listed in vocabularyUses.affects",
            );
            valid = false;
        }
    }
    valid
}

fn validate_collection_flow_payload(
    payload: &CsmiCollectionFlowPayload,
    callable: &CsmiCallableShape,
    model: &CsmiSemanticModel,
    symbols: &HashSet<String>,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let mut valid = true;
    let mut root_shapes = HashMap::new();
    for (index, root) in payload.roots.iter().enumerate() {
        let root_path = format!("{path}.roots[{index}]");
        let key = serde_json::to_string(&root.root).expect("CSMI roots are serializable");
        if root_shapes.insert(key, &root.shape).is_some() {
            error(
                diagnostics,
                "semantic.collection_flow_duplicate_root",
                format!("{root_path}.root"),
                "collection-flow roots must be unique",
            );
            valid = false;
        }
        if !validate_collection_flow_shape(
            &root.shape,
            symbols,
            &format!("{root_path}.shape"),
            diagnostics,
        ) {
            valid = false;
        }
    }
    if !validate_collection_flow_receiver_substitution(
        payload.receiver_substitution.as_ref(),
        callable,
        model,
        &format!("{path}.receiverSubstitution"),
        diagnostics,
    ) {
        valid = false;
    }
    for (index, transfer) in payload.transfers.iter().enumerate() {
        let transfer_path = format!("{path}.transfers[{index}]");
        if !validate_input_location(
            &transfer.source,
            callable,
            symbols,
            &format!("{transfer_path}.source"),
            diagnostics,
        ) {
            valid = false;
        }
        if !validate_output_location(
            &transfer.destination,
            callable,
            symbols,
            &format!("{transfer_path}.destination"),
            diagnostics,
        ) {
            valid = false;
        }
        if !validate_collection_flow_location(
            &transfer.source.root,
            transfer.source.projection.as_ref(),
            &root_shapes,
            callable,
            &format!("{transfer_path}.source"),
            diagnostics,
        ) {
            valid = false;
        }
        if !validate_collection_flow_location(
            &transfer.destination.root,
            transfer.destination.projection.as_ref(),
            &root_shapes,
            callable,
            &format!("{transfer_path}.destination"),
            diagnostics,
        ) {
            valid = false;
        }
    }
    for (index, invocation) in payload.invocations.iter().enumerate() {
        let invocation_path = format!("{path}.invocations[{index}]");
        if !validate_input_location(
            &invocation.callback,
            callable,
            symbols,
            &format!("{invocation_path}.callback"),
            diagnostics,
        ) {
            valid = false;
        }
        if !validate_collection_flow_location(
            &invocation.callback.root,
            invocation.callback.projection.as_ref(),
            &root_shapes,
            callable,
            &format!("{invocation_path}.callback"),
            diagnostics,
        ) {
            valid = false;
        }
        for (parameter_index, parameter) in invocation.parameters.iter().enumerate() {
            if !validate_collection_flow_shape(
                parameter,
                symbols,
                &format!("{invocation_path}.parameters[{parameter_index}]"),
                diagnostics,
            ) {
                valid = false;
            }
        }
        if invocation.arguments.len() != invocation.parameters.len() {
            error(
                diagnostics,
                "semantic.collection_flow_callback_arity",
                format!("{invocation_path}.arguments"),
                "callback arguments must match the declared callback parameter arity",
            );
            valid = false;
        }
        let mut argument_parameters = HashSet::new();
        for (argument_index, argument) in invocation.arguments.iter().enumerate() {
            let argument_path = format!("{invocation_path}.arguments[{argument_index}]");
            if argument.parameter as usize >= invocation.parameters.len()
                || !argument_parameters.insert(argument.parameter)
            {
                error(
                    diagnostics,
                    "semantic.collection_flow_callback_parameter",
                    format!("{argument_path}.parameter"),
                    "callback argument parameter must be unique and within the declared arity",
                );
                valid = false;
            }
            if !validate_input_location(
                &argument.source,
                callable,
                symbols,
                &format!("{argument_path}.source"),
                diagnostics,
            ) {
                valid = false;
            }
            if !validate_collection_flow_location(
                &argument.source.root,
                argument.source.projection.as_ref(),
                &root_shapes,
                callable,
                &format!("{argument_path}.source"),
                diagnostics,
            ) {
                valid = false;
            }
        }
    }
    valid
}

fn validate_collection_flow_shape(
    shape: &CsmiCollectionFlowShape,
    symbols: &HashSet<String>,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    match shape {
        CsmiCollectionFlowShape::Value { r#type } => {
            validate_type_expression(r#type, symbols, &format!("{path}.type"), diagnostics)
        }
        CsmiCollectionFlowShape::Product { components } => {
            let mut valid = !components.is_empty();
            if components.is_empty() {
                error(
                    diagnostics,
                    "semantic.collection_flow_product_shape",
                    path,
                    "product shapes require at least one component",
                );
            }
            for (index, component) in components.iter().enumerate() {
                if !validate_collection_flow_shape(
                    component,
                    symbols,
                    &format!("{path}.components[{index}]"),
                    diagnostics,
                ) {
                    valid = false;
                }
            }
            valid
        }
        CsmiCollectionFlowShape::Keyed {
            key,
            value,
            entry_components,
        } => {
            let mut valid =
                validate_collection_flow_shape(key, symbols, &format!("{path}.key"), diagnostics)
                    && validate_collection_flow_shape(
                        value,
                        symbols,
                        &format!("{path}.value"),
                        diagnostics,
                    );
            if let Some(components) = entry_components {
                let expected = [
                    CsmiCollectionFlowEntryComponent::Key,
                    CsmiCollectionFlowEntryComponent::Value,
                ];
                if components.as_slice() != expected {
                    error(
                        diagnostics,
                        "semantic.collection_flow_entry_components",
                        format!("{path}.entryComponents"),
                        "entryComponents must be exactly [key, value]",
                    );
                    valid = false;
                }
            }
            valid
        }
        CsmiCollectionFlowShape::Unknown { limitation } => {
            validate_profile_limitation(limitation, &format!("{path}.limitation"), diagnostics)
        }
    }
}

fn validate_collection_flow_receiver_substitution(
    substitution: Option<&CsmiCollectionFlowSubstitution>,
    callable: &CsmiCallableShape,
    model: &CsmiSemanticModel,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let Some(substitution) = substitution else {
        return true;
    };
    match substitution {
        CsmiCollectionFlowSubstitution::Unknown { limitation }
        | CsmiCollectionFlowSubstitution::Unsupported { limitation } => {
            validate_profile_limitation(limitation, &format!("{path}.limitation"), diagnostics)
        }
        CsmiCollectionFlowSubstitution::ReceiverArguments { declaration } => {
            let Some(declaration_record) = model
                .declarations
                .iter()
                .find(|candidate| candidate.symbol == *declaration)
            else {
                error(
                    diagnostics,
                    "semantic.collection_flow_receiver_declaration",
                    format!("{path}.declaration"),
                    "receiver substitution declaration must be local",
                );
                return false;
            };
            if !matches!(
                declaration_record.category,
                CsmiDeclarationCategory::Type | CsmiDeclarationCategory::TypeAlias
            ) {
                error(
                    diagnostics,
                    "semantic.collection_flow_receiver_declaration",
                    format!("{path}.declaration"),
                    "receiver substitution declaration must be a type declaration",
                );
                return false;
            }
            let Some(receiver_type) = callable
                .receiver
                .as_ref()
                .and_then(|receiver| receiver.receiver_type.as_ref())
            else {
                error(
                    diagnostics,
                    "semantic.collection_flow_receiver_shape",
                    path,
                    "receiver-arguments substitution requires a typed receiver",
                );
                return false;
            };
            let CsmiTypeExpression::Reference(receiver_reference) = receiver_type else {
                error(
                    diagnostics,
                    "semantic.collection_flow_receiver_shape",
                    format!("{path}.declaration"),
                    "receiver type must reference the substituted declaration",
                );
                return false;
            };
            receiver_reference.symbol == *declaration
                && validate_receiver_generic_arguments(
                    receiver_reference,
                    declaration_record,
                    "semantic.collection_flow_receiver_arguments",
                    &format!("{path}.declaration"),
                    diagnostics,
                )
        }
    }
}

fn validate_collection_flow_location(
    root: &impl Serialize,
    projection: Option<&CsmiProjection>,
    root_shapes: &HashMap<String, &CsmiCollectionFlowShape>,
    callable: &CsmiCallableShape,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let key = serde_json::to_string(root).expect("CSMI roots are serializable");
    let Some(shape) = root_shapes.get(&key) else {
        error(
            diagnostics,
            "semantic.collection_flow_missing_shape",
            format!("{path}.root"),
            "collection-flow location root must have a declared shape",
        );
        return false;
    };
    let Some(projection) = projection else {
        return true;
    };
    let mut valid = projection.scheme == CSMI_COLLECTION_FLOW_PROFILE_ID
        && projection.scheme_version == CSMI_COLLECTION_FLOW_PROFILE_VERSION
        && !projection.steps.is_empty();
    if !valid {
        error(
            diagnostics,
            "semantic.collection_flow_projection_identity",
            format!("{path}.projection"),
            "projection must use the exact collection-flow scheme and a non-empty step list",
        );
    }
    let mut current = (*shape).clone();
    let mut entry_projection = false;
    for (index, step) in projection.steps.iter().enumerate() {
        let step_path = format!("{path}.projection.steps[{index}]");
        match step.kind.as_str() {
            "entry" => {
                let Some(args) = step.args.as_ref().and_then(Value::as_object) else {
                    error(
                        diagnostics,
                        "semantic.collection_flow_projection_args",
                        &step_path,
                        "entry projection requires key selector arguments",
                    );
                    valid = false;
                    continue;
                };
                let Some(selector) = args.get("key").and_then(Value::as_object) else {
                    error(
                        diagnostics,
                        "semantic.collection_flow_projection_args",
                        &step_path,
                        "entry projection requires a key selector",
                    );
                    valid = false;
                    continue;
                };
                match selector.get("kind").and_then(Value::as_str) {
                    Some("all") => {}
                    Some("parameter") => {
                        let Some(position) = selector.get("position").and_then(Value::as_u64)
                        else {
                            error(
                                diagnostics,
                                "semantic.collection_flow_projection_args",
                                &step_path,
                                "parameter key selector requires a non-negative position",
                            );
                            valid = false;
                            continue;
                        };
                        if position as usize >= callable.parameters.len() {
                            error(
                                diagnostics,
                                "semantic.collection_flow_projection_args",
                                &step_path,
                                "parameter key selector is outside the callable shape",
                            );
                            valid = false;
                        }
                    }
                    _ => {
                        error(
                            diagnostics,
                            "semantic.collection_flow_projection_args",
                            &step_path,
                            "entry selector must be all or parameter",
                        );
                        valid = false;
                    }
                }
                let CsmiCollectionFlowShape::Keyed { key, value, .. } = &current else {
                    error(
                        diagnostics,
                        "semantic.collection_flow_projection_shape",
                        &step_path,
                        "entry projection requires a keyed shape",
                    );
                    valid = false;
                    continue;
                };
                current = CsmiCollectionFlowShape::Product {
                    components: vec![(**key).clone(), (**value).clone()],
                };
                entry_projection = true;
            }
            "entry-key" | "entry-value" => {
                if !entry_projection {
                    error(
                        diagnostics,
                        "semantic.collection_flow_projection_shape",
                        &step_path,
                        "entry-key and entry-value require a preceding entry projection",
                    );
                    valid = false;
                    continue;
                }
                let CsmiCollectionFlowShape::Product { components } = &current else {
                    valid = false;
                    continue;
                };
                if components.len() != 2 {
                    error(
                        diagnostics,
                        "semantic.collection_flow_projection_shape",
                        &step_path,
                        "entry projection must produce a two-component product",
                    );
                    valid = false;
                    continue;
                }
                current = components[usize::from(step.kind == "entry-value")].clone();
                entry_projection = false;
            }
            "component" => {
                let Some(position) = step
                    .args
                    .as_ref()
                    .and_then(Value::as_object)
                    .and_then(|args| args.get("position"))
                    .and_then(Value::as_u64)
                else {
                    error(
                        diagnostics,
                        "semantic.collection_flow_projection_args",
                        &step_path,
                        "component projection requires a non-negative position",
                    );
                    valid = false;
                    continue;
                };
                let CsmiCollectionFlowShape::Product { components } = &current else {
                    error(
                        diagnostics,
                        "semantic.collection_flow_projection_shape",
                        &step_path,
                        "component projection requires a product shape",
                    );
                    valid = false;
                    continue;
                };
                let Some(component) = components.get(position as usize) else {
                    error(
                        diagnostics,
                        "semantic.collection_flow_projection_args",
                        &step_path,
                        "component position is outside the product shape",
                    );
                    valid = false;
                    continue;
                };
                current = component.clone();
                entry_projection = false;
            }
            _ => {
                error(
                    diagnostics,
                    "semantic.collection_flow_projection_kind",
                    &step_path,
                    "unsupported collection-flow projection step",
                );
                valid = false;
            }
        }
    }
    valid
}

fn validate_runtime_values_semantics(
    model: &CsmiSemanticModel,
    prefix: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let runtime_uses: Vec<(usize, &CsmiVocabularyUse)> = model
        .vocabulary_uses
        .iter()
        .enumerate()
        .filter(|(_, use_)| use_.identifier == CSMI_RUNTIME_VALUES_PROFILE_ID)
        .collect();
    let runtime_fact_count = model
        .extension_facts
        .iter()
        .filter(|fact| fact.vocabulary == CSMI_RUNTIME_VALUES_PROFILE_ID)
        .count();
    let mut valid = true;
    if runtime_fact_count > 0 && runtime_uses.len() != 1 {
        error(
            diagnostics,
            "semantic.runtime_values_use_count",
            format!("{prefix}.vocabularyUses"),
            "runtime-values facts require exactly one vocabulary use",
        );
        valid = false;
    }
    let mut affected = HashSet::new();
    for (index, use_) in &runtime_uses {
        let path = format!("{prefix}.vocabularyUses[{index}]");
        if use_.version != CSMI_RUNTIME_VALUES_PROFILE_VERSION
            || use_.schema != CSMI_RUNTIME_VALUES_PROFILE_SCHEMA
        {
            continue;
        }
        if use_.requirement != CsmiVocabularyRequirement::Required {
            error(
                diagnostics,
                "semantic.runtime_values_required_use",
                format!("{path}.requirement"),
                "csmi.runtime-values uses affecting runtime facts must be required",
            );
            valid = false;
        }
        for (affect_index, affect) in use_.affects.iter().enumerate() {
            let affect_path = format!("{path}.affects[{affect_index}]");
            let CsmiAffectedUnit::FactFamily(family) = affect else {
                error(
                    diagnostics,
                    "semantic.runtime_values_affect_kind",
                    affect_path,
                    "runtime-values affects must identify a fact family",
                );
                valid = false;
                continue;
            };
            if family.kind != CsmiAffectedFactFamilyKind::FactFamily
                || !matches!(
                    family.family.as_str(),
                    "runtime-global-exposures"
                        | "keyed-read-behaviors"
                        | "runtime-global-binding-evidence"
                        | "keyed-read-observations"
                )
            {
                error(
                    diagnostics,
                    "semantic.runtime_values_affect_family",
                    affect_path,
                    "runtime-values affects must use one of the four profile families",
                );
                valid = false;
                continue;
            }
            affected.insert((family.family.clone(), canonical_scope(&family.scope)));
        }
    }

    let mut exposures: HashMap<String, CsmiRuntimeGlobalExposure> = HashMap::new();
    let mut behaviors: HashMap<String, CsmiKeyedReadBehavior> = HashMap::new();
    let mut bindings: HashMap<String, CsmiRuntimeGlobalBindingEvidence> = HashMap::new();
    let mut observations: HashMap<String, CsmiKeyedReadObservation> = HashMap::new();
    let mut fact_keys = HashSet::new();
    for (index, fact) in model.extension_facts.iter().enumerate() {
        if fact.vocabulary != CSMI_RUNTIME_VALUES_PROFILE_ID
            || fact.version != CSMI_RUNTIME_VALUES_PROFILE_VERSION
        {
            continue;
        }
        let path = format!("{prefix}.extensionFacts[{index}]");
        let payload = match serde_json::from_value::<CsmiRuntimeValuesPayload>(fact.payload.clone())
        {
            Ok(payload) => payload,
            Err(cause) => {
                error(
                    diagnostics,
                    "semantic.runtime_values_payload",
                    format!("{path}.payload"),
                    cause.to_string(),
                );
                valid = false;
                continue;
            }
        };
        let (family, identity, expected_scope) = match &payload {
            CsmiRuntimeValuesPayload::RuntimeGlobalExposure(record) => (
                "runtime-global-exposures",
                record.exposure_id.clone(),
                serde_json::json!({"exposureId": record.exposure_id}),
            ),
            CsmiRuntimeValuesPayload::KeyedReadBehavior(record) => (
                "keyed-read-behaviors",
                record.behavior_id.clone(),
                serde_json::json!({"behaviorId": record.behavior_id}),
            ),
            CsmiRuntimeValuesPayload::RuntimeGlobalBindingEvidence(record) => (
                "runtime-global-binding-evidence",
                record.binding_evidence_id.clone(),
                serde_json::json!({"bindingEvidenceId": record.binding_evidence_id}),
            ),
            CsmiRuntimeValuesPayload::KeyedReadObservation(record) => (
                "keyed-read-observations",
                record.observation_id.clone(),
                serde_json::json!({"observationId": record.observation_id}),
            ),
        };
        let fact_key = (family.to_owned(), canonical_scope(&expected_scope));
        if !fact_keys.insert(fact_key.clone()) {
            error(
                diagnostics,
                "semantic.runtime_values_duplicate",
                &path,
                format!("duplicate {family} identity {identity}"),
            );
            valid = false;
        }
        if fact.family != family || fact.scope != expected_scope {
            error(
                diagnostics,
                "semantic.runtime_values_fact_scope",
                format!("{path}.scope"),
                "runtime-values family and scope must repeat the payload kind and identity",
            );
            valid = false;
        }
        if !affected.contains(&fact_key) {
            error(
                diagnostics,
                "semantic.runtime_values_unaffected_fact",
                format!("{path}.scope"),
                "runtime-values fact scope is missing from vocabularyUses.affects",
            );
            valid = false;
        }
        match payload {
            CsmiRuntimeValuesPayload::RuntimeGlobalExposure(record) => {
                if !model.artifact_selectors.iter().any(|selector| {
                    selector.purl == record.runtime.runtime_artifact
                        && selector.digests.iter().any(|digest| {
                            digest.algorithm == CsmiDigestAlgorithm::Sha256
                                && digest.value == record.runtime.runtime_artifact_digest
                        })
                }) {
                    error(
                        diagnostics,
                        "semantic.runtime_values_artifact",
                        format!("{path}.payload.runtime"),
                        "runtime artifact and digest must match a model artifact selector",
                    );
                    valid = false;
                }
                if record.coverage.status == CsmiRuntimeCoverageStatus::Complete
                    && !record.coverage.limitations.is_empty()
                {
                    error(
                        diagnostics,
                        "semantic.runtime_values_complete_limitation",
                        format!("{path}.payload.coverage"),
                        "complete runtime coverage cannot carry limitations",
                    );
                    valid = false;
                }
                if exposures
                    .insert(record.exposure_id.clone(), record)
                    .is_some()
                {
                    valid = false;
                }
            }
            CsmiRuntimeValuesPayload::KeyedReadBehavior(record) => {
                if record.coverage.status == CsmiRuntimeCoverageStatus::Complete
                    && (record.exception_behavior == CsmiRuntimeExceptionBehavior::Unknown
                        || record.mutation_model == CsmiRuntimeMutationModel::Unknown
                        || record.materialization == CsmiRuntimeMaterialization::Unknown)
                {
                    error(
                        diagnostics,
                        "semantic.runtime_values_complete_behavior",
                        format!("{path}.payload"),
                        "complete behavior requires interpreted exception, mutation, and materialization semantics",
                    );
                    valid = false;
                }
                if behaviors
                    .insert(record.behavior_id.clone(), record)
                    .is_some()
                {
                    valid = false;
                }
            }
            CsmiRuntimeValuesPayload::RuntimeGlobalBindingEvidence(record) => {
                if record.root_occurrence.end_byte <= record.root_occurrence.start_byte {
                    error(
                        diagnostics,
                        "semantic.runtime_values_empty_range",
                        format!("{path}.payload.rootOccurrence"),
                        "rootOccurrence must have a non-empty source range",
                    );
                    valid = false;
                }
                if record.coverage.status == CsmiRuntimeCoverageStatus::Complete {
                    let exact = record.activation.outcome == CsmiRuntimeActivationOutcome::Matched
                        && record.lexical_binding == CsmiRuntimeLexicalBinding::Absent
                        && record.rebinding == CsmiRuntimeRebinding::Excluded;
                    let excluded = record.activation.outcome
                        == CsmiRuntimeActivationOutcome::NotMatched
                        && record.lexical_binding == CsmiRuntimeLexicalBinding::Present;
                    if !exact && !excluded {
                        error(
                            diagnostics,
                            "semantic.runtime_values_binding_proof",
                            format!("{path}.payload"),
                            "complete binding evidence requires a matched global or conclusive lexical exclusion",
                        );
                        valid = false;
                    }
                }
                if bindings
                    .insert(record.binding_evidence_id.clone(), record)
                    .is_some()
                {
                    valid = false;
                }
            }
            CsmiRuntimeValuesPayload::KeyedReadObservation(record) => {
                if record.expression.end_byte <= record.expression.start_byte {
                    error(
                        diagnostics,
                        "semantic.runtime_values_empty_range",
                        format!("{path}.payload.expression"),
                        "expression must have a non-empty source range",
                    );
                    valid = false;
                }
                let key_is_property = matches!(&record.key, CsmiRuntimeStaticKey::Property(_));
                let key_is_index = matches!(&record.key, CsmiRuntimeStaticKey::Index(_));
                if (record.source_form == CsmiRuntimeSourceForm::Dot && !key_is_property)
                    || (record.source_form == CsmiRuntimeSourceForm::BracketString
                        && !key_is_property)
                    || (record.source_form == CsmiRuntimeSourceForm::BracketNumber && !key_is_index)
                {
                    error(
                        diagnostics,
                        "semantic.runtime_values_key_form",
                        format!("{path}.payload"),
                        "source form must agree with the static property or index key",
                    );
                    valid = false;
                }
                if record.normal_outcome == CsmiRuntimeNormalOutcome::Exact
                    && record.phase != CsmiRuntimeObservationPhase::AfterEffects
                {
                    error(
                        diagnostics,
                        "semantic.runtime_values_exact_phase",
                        format!("{path}.payload.phase"),
                        "an exact normal load result must be observed after effects",
                    );
                    valid = false;
                }
                if record.coverage.status == CsmiRuntimeCoverageStatus::Complete
                    && (record.normal_outcome != CsmiRuntimeNormalOutcome::Exact
                        || !matches!(
                            record.exception_outcome,
                            CsmiRuntimeExceptionOutcome::Excluded
                                | CsmiRuntimeExceptionOutcome::Possible
                        )
                        || record.source_origin == CsmiRuntimeSourceOrigin::Indeterminate)
                {
                    error(
                        diagnostics,
                        "semantic.runtime_values_complete_observation",
                        format!("{path}.payload"),
                        "complete observation requires exact normal, interpreted exceptional, and determined origin outcomes",
                    );
                    valid = false;
                }
                if observations
                    .insert(record.observation_id.clone(), record)
                    .is_some()
                {
                    valid = false;
                }
            }
        }
    }
    for (family, scope) in &affected {
        if !fact_keys.contains(&(family.clone(), scope.clone())) {
            error(
                diagnostics,
                "semantic.runtime_values_missing_fact",
                format!("{prefix}.vocabularyUses"),
                "runtime-values affects must identify an extension fact",
            );
            valid = false;
        }
    }

    let mut enabled_exposures: Vec<String> = exposures
        .values()
        .filter(|record| record.activation == CsmiRuntimeExposureActivation::Enabled)
        .map(|record| record.exposure_id.clone())
        .collect();
    enabled_exposures.sort();
    let expected_active_set_digest = canonical_json(&enabled_exposures)
        .map(|bytes| sha256_hex(&bytes))
        .expect("a sorted runtime exposure id list is canonical JSON");
    for (id, behavior) in &behaviors {
        let Some(exposure) = exposures.get(&behavior.exposure_id) else {
            error(
                diagnostics,
                "semantic.runtime_values_unknown_exposure",
                format!("{prefix}.extensionFacts.behaviors.{id}.exposureId"),
                "behavior references an unknown exposure",
            );
            valid = false;
            continue;
        };
        if !exposure
            .members
            .iter()
            .any(|member| member == &behavior.container_member)
        {
            error(
                diagnostics,
                "semantic.runtime_values_unknown_member",
                format!("{prefix}.extensionFacts.behaviors.{id}.containerMember"),
                "behavior containerMember must be a member of its exposure",
            );
            valid = false;
        }
    }
    for (id, binding) in &bindings {
        let Some(exposure) = exposures.get(&binding.exposure_id) else {
            error(
                diagnostics,
                "semantic.runtime_values_unknown_exposure",
                format!("{prefix}.extensionFacts.bindings.{id}.exposureId"),
                "binding evidence references an unknown exposure",
            );
            valid = false;
            continue;
        };
        if binding.activation.exposure_id != binding.exposure_id
            || binding.activation.runtime_profile_digest != exposure.runtime_profile_digest
            || binding.activation.model_digest != exposure.evidence.inputs_digest
            || binding.activation.active_exposure_ids != enabled_exposures
            || binding.activation.active_set_digest != expected_active_set_digest
        {
            error(
                diagnostics,
                "semantic.runtime_values_activation_join",
                format!("{prefix}.extensionFacts.bindings.{id}.activation"),
                "activation evidence must join its exposure profile, model, and enabled exposure set",
            );
            valid = false;
        }
        if binding.activation.outcome == CsmiRuntimeActivationOutcome::Matched
            && (exposure.activation != CsmiRuntimeExposureActivation::Enabled
                || enabled_exposures.len() != 1)
        {
            error(
                diagnostics,
                "semantic.runtime_values_activation_outcome",
                format!("{prefix}.extensionFacts.bindings.{id}.activation.outcome"),
                "matched activation requires one unique enabled exposure",
            );
            valid = false;
        }
    }
    for (id, observation) in &observations {
        let (Some(binding), Some(behavior)) = (
            bindings.get(&observation.binding_evidence_id),
            behaviors.get(&observation.behavior_id),
        ) else {
            error(
                diagnostics,
                "semantic.runtime_values_observation_join",
                format!("{prefix}.extensionFacts.observations.{id}"),
                "observation references must resolve to binding evidence and behavior",
            );
            valid = false;
            continue;
        };
        if binding.exposure_id != behavior.exposure_id {
            error(
                diagnostics,
                "semantic.runtime_values_observation_exposure",
                format!("{prefix}.extensionFacts.observations.{id}"),
                "observation binding and behavior must resolve in one exposure",
            );
            valid = false;
        }
        let accepted = match &observation.key {
            CsmiRuntimeStaticKey::Property(_) => CsmiRuntimeAcceptedKeys::StaticProperty,
            CsmiRuntimeStaticKey::Index(_) => CsmiRuntimeAcceptedKeys::StaticIndex,
        };
        if behavior.accepted_keys != accepted {
            error(
                diagnostics,
                "semantic.runtime_values_behavior_key",
                format!("{prefix}.extensionFacts.observations.{id}.key"),
                "observation key must be accepted by its behavior",
            );
            valid = false;
        }
        if observation.expression.resource_digest != binding.root_occurrence.resource_digest {
            error(
                diagnostics,
                "semantic.runtime_values_source_join",
                format!("{prefix}.extensionFacts.observations.{id}.expression.resourceDigest"),
                "binding and observation source artifacts must match",
            );
            valid = false;
        }
        let source_digest = observation.expression.resource_digest.as_str();
        if [
            &observation.base_value.owner_digest,
            &observation.load_operation.owner_digest,
            &observation.result_value.owner_digest,
            &observation.observation_point.owner_digest,
        ]
        .iter()
        .any(|digest| digest.as_str() != source_digest)
            || observation.base_value.kind != CsmiRuntimeIdentityKind::Value
            || observation.load_operation.kind != CsmiRuntimeIdentityKind::Operation
            || observation.result_value.kind != CsmiRuntimeIdentityKind::Value
            || observation.observation_point.kind != CsmiRuntimeIdentityKind::Point
            || binding.scope_identity.kind != CsmiRuntimeIdentityKind::Scope
            || binding.scope_identity.owner_digest != binding.root_occurrence.resource_digest
        {
            error(
                diagnostics,
                "semantic.runtime_values_identity_join",
                format!("{prefix}.extensionFacts.observations.{id}"),
                "runtime operation, value, point, and scope identities must retain their source owner and kinds",
            );
            valid = false;
        }
        if observation.source_origin == CsmiRuntimeSourceOrigin::PristineRuntimeInput
            && (behavior.mutation_model != CsmiRuntimeMutationModel::PristineInputUntilWrite
                || binding.rebinding != CsmiRuntimeRebinding::Excluded
                || binding.coverage.status != CsmiRuntimeCoverageStatus::Complete)
        {
            error(
                diagnostics,
                "semantic.runtime_values_pristine_origin",
                format!("{prefix}.extensionFacts.observations.{id}.sourceOrigin"),
                "pristine origin requires complete binding and mutation proof",
            );
            valid = false;
        }
        if observation.coverage.status == CsmiRuntimeCoverageStatus::Complete
            && behavior.coverage.status != CsmiRuntimeCoverageStatus::Complete
        {
            error(
                diagnostics,
                "semantic.runtime_values_complete_behavior",
                format!("{prefix}.extensionFacts.observations.{id}.coverage"),
                "complete observation requires complete behavior coverage",
            );
            valid = false;
        }
    }
    valid
}

fn validate_selector(
    selector: &CsmiArtifactSelector,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let mut valid = true;
    if !selector.purl.starts_with("pkg:") {
        error(
            diagnostics,
            "semantic.invalid_purl",
            format!("{path}.purl"),
            "PURL must start with pkg:",
        );
        valid = false;
    }
    if selector.purl.contains("#") {
        error(
            diagnostics,
            "semantic.purl_subpath",
            format!("{path}.purl"),
            "PURL subpath is not supported by CSMI v0.1",
        );
        valid = false;
    }
    let has_version = selector
        .purl
        .split_once('@')
        .is_some_and(|(_, value)| !value.is_empty());
    if has_version == selector.version_range.is_some() {
        error(
            diagnostics,
            "semantic.selector_version",
            path,
            "selector must contain exactly one exact PURL version or versionRange",
        );
        valid = false;
    }
    if let Some(version_range) = &selector.version_range
        && !version_range.starts_with("vers:")
    {
        error(
            diagnostics,
            "semantic.invalid_version_range",
            format!("{path}.versionRange"),
            "versionRange must use a VERS scheme",
        );
        valid = false;
    }
    for (index, digest) in selector.digests.iter().enumerate() {
        let expected = match digest.algorithm {
            CsmiDigestAlgorithm::Sha256 => 64,
            CsmiDigestAlgorithm::Sha384 => 96,
            CsmiDigestAlgorithm::Sha512 => 128,
        };
        if digest.value.len() != expected
            || !digest
                .value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            error(
                diagnostics,
                "semantic.digest_encoding",
                format!("{path}.digests[{index}].value"),
                "digest must be lowercase hexadecimal with the algorithm's full length",
            );
            valid = false;
        }
    }
    valid
}

fn validate_callable_shape(
    shape: &CsmiCallableShape,
    path: &str,
    symbols: &HashSet<String>,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let mut valid = true;
    if let Some(receiver) = &shape.receiver
        && receiver.receiver_type.is_none()
    {
        error(
            diagnostics,
            "semantic.receiver_type",
            format!("{path}.receiver.type"),
            "receiver requires a type expression",
        );
        valid = false;
    }
    if let Some(receiver) = &shape.receiver
        && let Some(receiver_type) = &receiver.receiver_type
        && !validate_type_expression(
            receiver_type,
            symbols,
            &format!("{path}.receiver.type"),
            diagnostics,
        )
    {
        valid = false;
    }
    for (index, parameter) in shape.parameters.iter().enumerate() {
        let expected = u32::try_from(index).expect("parameter index fits u32");
        if parameter.position != expected {
            error(
                diagnostics,
                "semantic.noncontiguous_parameters",
                format!("{path}.parameters[{index}].position"),
                "parameter positions must be contiguous from zero",
            );
            valid = false;
        }
        if matches!(
            parameter.binding,
            CsmiParameterBinding::PositionalOrNamed | CsmiParameterBinding::NamedOnly
        ) && parameter.label.is_none()
        {
            error(
                diagnostics,
                "semantic.named_parameter_label",
                format!("{path}.parameters[{index}].label"),
                "named parameters require a label",
            );
            valid = false;
        }
        if let Some(symbol) = &parameter.symbol
            && !require_id(
                symbols,
                symbol,
                format!("{path}.parameters[{index}].symbol"),
                "parameter symbol",
                diagnostics,
            )
        {
            valid = false;
        }
        if let Some(parameter_type) = &parameter.parameter_type
            && !validate_type_expression(
                parameter_type,
                symbols,
                &format!("{path}.parameters[{index}].type"),
                diagnostics,
            )
        {
            valid = false;
        }
    }
    for (index, result) in shape.results.iter().enumerate() {
        let expected = u32::try_from(index).expect("result index fits u32");
        if result.position != expected {
            error(
                diagnostics,
                "semantic.noncontiguous_results",
                format!("{path}.results[{index}].position"),
                "result positions must be contiguous from zero",
            );
            valid = false;
        }
        if let Some(result_type) = &result.result_type
            && !validate_type_expression(
                result_type,
                symbols,
                &format!("{path}.results[{index}].type"),
                diagnostics,
            )
        {
            valid = false;
        }
    }
    valid
}

fn validate_type_expression(
    expression: &CsmiTypeExpression,
    symbols: &HashSet<String>,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    match expression {
        CsmiTypeExpression::Reference(reference) => {
            let mut valid = require_id(
                symbols,
                &reference.symbol,
                format!("{path}.symbol"),
                "type symbol",
                diagnostics,
            );
            for (index, argument) in reference.arguments.iter().enumerate() {
                if !validate_type_expression(
                    argument,
                    symbols,
                    &format!("{path}.arguments[{index}]"),
                    diagnostics,
                ) {
                    valid = false;
                }
            }
            valid
        }
        // Intrinsics and unknown types are deliberately left opaque here.
        // The importer must reject any form it cannot map losslessly instead
        // of turning it into an ordinary named type.
        CsmiTypeExpression::Unknown(_)
        | CsmiTypeExpression::Parameter(_)
        | CsmiTypeExpression::Intrinsic(_) => true,
    }
}

fn validate_summary(
    summary: &CsmiProcedureSummary,
    shape: &CsmiCallableShape,
    path: &str,
    symbols: &HashSet<String>,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let mut valid = true;
    for (index, transfer) in summary.transfers.iter().enumerate() {
        let path = format!("{path}.transfers[{index}]");
        if !validate_input_location(
            &transfer.source,
            shape,
            symbols,
            &format!("{path}.source"),
            diagnostics,
        ) {
            valid = false;
        }
        if !validate_output_location(
            &transfer.destination,
            shape,
            symbols,
            &format!("{path}.destination"),
            diagnostics,
        ) {
            valid = false;
        }
    }
    valid
}

fn validate_value_transfer_semantics(
    model: &CsmiSemanticModel,
    prefix: &str,
    symbols: &HashSet<String>,
    declaration_categories: &HashMap<String, CsmiDeclarationCategory>,
    callable_declarations: &HashMap<String, &CsmiCallableShape>,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let mut valid = true;

    for (index, use_) in model.vocabulary_uses.iter().enumerate() {
        if use_.identifier != CSMI_VALUE_TRANSFER_PROFILE_ID {
            continue;
        }
        let path = format!("{prefix}.vocabularyUses[{index}]");
        if use_.version != CSMI_VALUE_TRANSFER_PROFILE_VERSION
            || use_.schema != CSMI_VALUE_TRANSFER_PROFILE_SCHEMA
        {
            continue;
        }
        if use_.requirement != CsmiVocabularyRequirement::Required {
            error(
                diagnostics,
                "semantic.value_transfer_required_use",
                format!("{path}.requirement"),
                "csmi.value-transfer uses affecting a payload must be required",
            );
            valid = false;
        }
        for (affect_index, affect) in use_.affects.iter().enumerate() {
            if !validate_value_transfer_affect(
                affect,
                symbols,
                declaration_categories,
                &format!("{path}.affects[{affect_index}]"),
                diagnostics,
            ) {
                valid = false;
            }
        }
    }

    let mut value_facts = Vec::new();
    let mut implicit_facts = Vec::new();
    for (index, fact) in model.extension_facts.iter().enumerate() {
        if fact.vocabulary != CSMI_VALUE_TRANSFER_PROFILE_ID
            || fact.version != CSMI_VALUE_TRANSFER_PROFILE_VERSION
        {
            continue;
        }
        let path = format!("{prefix}.extensionFacts[{index}]");
        let payload =
            match serde_json::from_value::<CsmiValueTransferProfilePayload>(fact.payload.clone()) {
                Ok(payload) => payload,
                Err(error_value) => {
                    error(
                        diagnostics,
                        "semantic.value_transfer_payload",
                        format!("{path}.payload"),
                        format!(
                            "payload does not match the typed value-transfer profile: {error_value}"
                        ),
                    );
                    valid = false;
                    continue;
                }
            };
        match &payload {
            CsmiValueTransferProfilePayload::Transfer(_) => {
                error(
                    diagnostics,
                    "semantic.value_transfer_fact_attachment",
                    format!("{path}.payload"),
                    "transfer payloads belong on procedure-summary-transfer attachments",
                );
                valid = false;
            }
            CsmiValueTransferProfilePayload::TypeValue(value) => {
                let expected_scope = serde_json::json!({
                    "type": value.r#type,
                    "aspect": value.aspect,
                });
                if fact.family != "type-value-semantics" || fact.scope != expected_scope {
                    error(
                        diagnostics,
                        "semantic.value_transfer_fact_scope",
                        format!("{path}.scope"),
                        "type-value-semantics scope must exactly repeat type and aspect",
                    );
                    valid = false;
                }
                if !require_value_transfer_type(
                    &value.r#type,
                    symbols,
                    declaration_categories,
                    &format!("{path}.payload.type"),
                    diagnostics,
                ) {
                    valid = false;
                }
                if !validate_value_semantics(value, &path, diagnostics) {
                    valid = false;
                }
                value_facts.push(value.clone());
            }
            CsmiValueTransferProfilePayload::ImplicitOperation(operation) => {
                let mut expected_scope = serde_json::json!({
                    "owner": operation.owner,
                    "operation": operation.operation,
                });
                if operation.operation == CsmiImplicitOperationRole::ConversionOperator {
                    expected_scope["target"] = serde_json::json!(operation.target);
                }
                if fact.family != "implicit-operations" || fact.scope != expected_scope {
                    error(
                        diagnostics,
                        "semantic.value_transfer_fact_scope",
                        format!("{path}.scope"),
                        "implicit-operations scope must exactly repeat owner, operation, and conversion target",
                    );
                    valid = false;
                }
                if !require_value_transfer_type(
                    &operation.owner,
                    symbols,
                    declaration_categories,
                    &format!("{path}.payload.owner"),
                    diagnostics,
                ) {
                    valid = false;
                }
                if !require_value_transfer_callable(
                    &operation.symbol,
                    symbols,
                    declaration_categories,
                    callable_declarations,
                    &format!("{path}.payload.symbol"),
                    diagnostics,
                ) {
                    valid = false;
                }
                if declaration_owner(model, &operation.symbol) != Some(operation.owner.as_str()) {
                    error(
                        diagnostics,
                        "semantic.value_transfer_owner",
                        format!("{path}.payload.symbol"),
                        "implicit operation symbol must be declared with the scoped owner",
                    );
                    valid = false;
                }
                if let Some(target) = &operation.target {
                    if operation.operation != CsmiImplicitOperationRole::ConversionOperator
                        || !require_value_transfer_type(
                            target,
                            symbols,
                            declaration_categories,
                            &format!("{path}.payload.target"),
                            diagnostics,
                        )
                    {
                        if operation.operation != CsmiImplicitOperationRole::ConversionOperator {
                            error(
                                diagnostics,
                                "semantic.value_transfer_operation_target",
                                format!("{path}.payload.target"),
                                "only conversion operators may carry a target",
                            );
                        }
                        valid = false;
                    }
                } else if operation.operation == CsmiImplicitOperationRole::ConversionOperator {
                    error(
                        diagnostics,
                        "semantic.value_transfer_operation_target",
                        format!("{path}.payload.target"),
                        "conversion operators require a local target type",
                    );
                    valid = false;
                }
                if !validate_value_operation_shape(
                    operation,
                    callable_declarations,
                    &path,
                    diagnostics,
                ) {
                    valid = false;
                }
                implicit_facts.push(operation.clone());
            }
        }
    }

    // The previous pass parses and checks fact-local shape.  Check every
    // typed fact against its exact required fact-family declaration here.
    for (index, fact) in model.extension_facts.iter().enumerate() {
        if fact.vocabulary != CSMI_VALUE_TRANSFER_PROFILE_ID
            || fact.version != CSMI_VALUE_TRANSFER_PROFILE_VERSION
        {
            continue;
        }
        let path = format!("{prefix}.extensionFacts[{index}]");
        let Ok(payload) =
            serde_json::from_value::<CsmiValueTransferProfilePayload>(fact.payload.clone())
        else {
            continue;
        };
        let expected = match payload {
            CsmiValueTransferProfilePayload::TypeValue(value) => value_fact_affect(&value),
            CsmiValueTransferProfilePayload::ImplicitOperation(operation) => {
                operation_fact_affect(&operation)
            }
            CsmiValueTransferProfilePayload::Transfer(_) => continue,
        };
        if !require_value_transfer_affect(model, &expected, &path, diagnostics) {
            valid = false;
        }
    }

    for (summary_index, summary) in model.procedure_summaries.iter().enumerate() {
        for (transfer_index, transfer) in summary.transfers.iter().enumerate() {
            let path =
                format!("{prefix}.procedureSummaries[{summary_index}].transfers[{transfer_index}]");
            if !validate_non_transfer_value_attachments(
                &transfer.extensions,
                &format!("{path}.extensions"),
                diagnostics,
                true,
            ) {
                valid = false;
            }
            let attachments = transfer
                .extensions
                .iter()
                .filter(|extension| {
                    extension.vocabulary == CSMI_VALUE_TRANSFER_PROFILE_ID
                        && extension.version == CSMI_VALUE_TRANSFER_PROFILE_VERSION
                })
                .collect::<Vec<_>>();
            if attachments.is_empty() {
                continue;
            }
            if attachments.len() != 1 {
                error(
                    diagnostics,
                    "semantic.value_transfer_duplicate_attachment",
                    format!("{path}.extensions"),
                    "a transfer has exactly one value-transfer attachment",
                );
                valid = false;
            }
            let payload = match serde_json::from_value::<CsmiValueTransferProfilePayload>(
                attachments[0].payload.clone(),
            ) {
                Ok(CsmiValueTransferProfilePayload::Transfer(payload)) => payload,
                Ok(_) => {
                    error(
                        diagnostics,
                        "semantic.value_transfer_attachment_payload",
                        format!("{path}.extensions"),
                        "a procedure-summary-transfer extension must contain a transfer payload",
                    );
                    valid = false;
                    continue;
                }
                Err(error_value) => {
                    error(
                        diagnostics,
                        "semantic.value_transfer_attachment_payload",
                        format!("{path}.extensions"),
                        format!("invalid transfer attachment payload: {error_value}"),
                    );
                    valid = false;
                    continue;
                }
            };
            let expected = CsmiAffectedUnit::Attachment(CsmiAffectedAttachment {
                kind: CsmiAffectedAttachmentKind::Attachment,
                attachment_point: "procedure-summary-transfer".to_owned(),
                target: serde_json::json!({"callable": summary.callable}),
            });
            if !require_value_transfer_affect(model, &expected, &path, diagnostics) {
                valid = false;
            }
            let identity_expected = CsmiAffectedUnit::FactFamily(CsmiAffectedFactFamily {
                kind: CsmiAffectedFactFamilyKind::FactFamily,
                family: "identity-separating-transfers".to_owned(),
                scope: serde_json::json!({"callable": summary.callable}),
            });
            if !require_value_transfer_affect(model, &identity_expected, &path, diagnostics) {
                valid = false;
            }
            if !validate_value_transfer_attachment(
                &payload,
                &implicit_facts,
                symbols,
                declaration_categories,
                callable_declarations,
                &path,
                diagnostics,
            ) {
                valid = false;
            }
        }
    }

    for (index, statement) in model.completeness_statements.iter().enumerate() {
        if statement.vocabulary.as_deref() != Some(CSMI_VALUE_TRANSFER_PROFILE_ID) {
            continue;
        }
        let path = format!("{prefix}.completenessStatements[{index}]");
        if statement.vocabulary.as_deref() != Some(CSMI_VALUE_TRANSFER_PROFILE_ID)
            || statement.version.as_deref() != Some(CSMI_VALUE_TRANSFER_PROFILE_VERSION)
        {
            error(
                diagnostics,
                "semantic.value_transfer_completeness_identity",
                &path,
                "value-transfer completeness must declare the exact vocabulary and version",
            );
            valid = false;
            continue;
        }
        if !validate_value_transfer_scope(
            &statement.family,
            &statement.scope,
            symbols,
            declaration_categories,
            &format!("{path}.scope"),
            diagnostics,
        ) {
            valid = false;
        }
        let expected = CsmiAffectedUnit::FactFamily(CsmiAffectedFactFamily {
            kind: CsmiAffectedFactFamilyKind::FactFamily,
            family: statement.family.clone(),
            scope: statement.scope.clone(),
        });
        if !require_value_transfer_affect(model, &expected, &path, diagnostics) {
            valid = false;
        }
        if statement.status != CsmiCoverageStatus::Complete {
            continue;
        }
        match statement.family.as_str() {
            "type-value-semantics" => {
                let matches = value_facts.iter().filter(|fact| {
                    value_fact_affect(fact)
                        == CsmiAffectedUnit::FactFamily(CsmiAffectedFactFamily {
                            kind: CsmiAffectedFactFamilyKind::FactFamily,
                            family: statement.family.clone(),
                            scope: statement.scope.clone(),
                        })
                });
                let matching = matches.collect::<Vec<_>>();
                if matching.is_empty() {
                    error(
                        diagnostics,
                        "semantic.value_transfer_complete_empty",
                        &path,
                        "complete type-value coverage requires a typed fact",
                    );
                    valid = false;
                }
                if matching.first().is_some_and(|first| {
                    matching
                        .iter()
                        .skip(1)
                        .any(|fact| fact.semantics != first.semantics)
                }) {
                    error(
                        diagnostics,
                        "semantic.value_transfer_complete_conflict",
                        &path,
                        "complete type-value coverage cannot contain conflicting semantics",
                    );
                    valid = false;
                }
                if matching.iter().any(|fact| {
                    matches!(
                        fact.semantics,
                        CsmiTypeSemantics::Unknown { .. } | CsmiTypeSemantics::Unsupported { .. }
                    )
                }) {
                    error(
                        diagnostics,
                        "semantic.value_transfer_complete_unknown",
                        &path,
                        "complete type-value coverage cannot retain unknown or unsupported semantics",
                    );
                    valid = false;
                }
            }
            "implicit-operations" => {
                if !implicit_facts.iter().any(|operation| {
                    operation_fact_affect(operation)
                        == CsmiAffectedUnit::FactFamily(CsmiAffectedFactFamily {
                            kind: CsmiAffectedFactFamilyKind::FactFamily,
                            family: statement.family.clone(),
                            scope: statement.scope.clone(),
                        })
                }) {
                    error(
                        diagnostics,
                        "semantic.value_transfer_complete_empty",
                        &path,
                        "complete implicit-operation coverage requires a typed fact",
                    );
                    valid = false;
                }
            }
            "identity-separating-transfers" => {
                let callable = statement.scope.get("callable").and_then(Value::as_str);
                let Some(callable) = callable else {
                    continue;
                };
                let Some(summary) = model
                    .procedure_summaries
                    .iter()
                    .find(|summary| summary.callable == callable)
                else {
                    error(
                        diagnostics,
                        "semantic.value_transfer_complete_empty",
                        &path,
                        "complete transfer classification requires the scoped procedure summary",
                    );
                    valid = false;
                    continue;
                };
                for (transfer_index, transfer) in summary.transfers.iter().enumerate() {
                    let attachments = transfer
                        .extensions
                        .iter()
                        .filter(|extension| {
                            extension.vocabulary == CSMI_VALUE_TRANSFER_PROFILE_ID
                                && extension.version == CSMI_VALUE_TRANSFER_PROFILE_VERSION
                        })
                        .collect::<Vec<_>>();
                    if attachments.len() != 1 {
                        error(
                            diagnostics,
                            "semantic.value_transfer_complete_unclassified",
                            format!("{path}.scope.transfers[{transfer_index}]"),
                            "complete identity-separating coverage requires one classified transfer attachment",
                        );
                        valid = false;
                        continue;
                    }
                    if let Ok(CsmiValueTransferProfilePayload::Transfer(attachment)) =
                        serde_json::from_value(attachments[0].payload.clone())
                        && value_transfer_has_unknown_detail(&attachment)
                    {
                        error(
                            diagnostics,
                            "semantic.value_transfer_complete_unknown",
                            format!("{path}.scope.transfers[{transfer_index}]"),
                            "complete identity-separating coverage cannot retain unknown transfer details",
                        );
                        valid = false;
                    }
                }
            }
            _ => {}
        }
    }

    // Value-transfer attachments are point-specific.  Keep an extension on a
    // fact or another core object from silently changing its meaning.
    if !validate_non_transfer_value_attachments(
        &model.extensions,
        &format!("{prefix}.extensions"),
        diagnostics,
        false,
    ) {
        valid = false;
    }
    for (index, symbol) in model.symbols.iter().enumerate() {
        if !validate_non_transfer_value_attachments(
            &symbol.extensions,
            &format!("{prefix}.symbols[{index}].extensions"),
            diagnostics,
            false,
        ) {
            valid = false;
        }
    }
    for (index, declaration) in model.declarations.iter().enumerate() {
        let path = format!("{prefix}.declarations[{index}]");
        if !validate_non_transfer_value_attachments(
            &declaration.extensions,
            &format!("{path}.extensions"),
            diagnostics,
            false,
        ) {
            valid = false;
        }
        for (generic_index, generic) in declaration.generic_parameters.iter().enumerate() {
            if !validate_non_transfer_value_attachments(
                &generic.extensions,
                &format!("{path}.genericParameters[{generic_index}].extensions"),
                diagnostics,
                false,
            ) {
                valid = false;
            }
        }
        if let Some(shape) = &declaration.callable {
            if !validate_non_transfer_value_attachments(
                &shape.extensions,
                &format!("{path}.callable.extensions"),
                diagnostics,
                false,
            ) {
                valid = false;
            }
            if let Some(receiver) = &shape.receiver
                && !validate_non_transfer_value_attachments(
                    &receiver.extensions,
                    &format!("{path}.callable.receiver.extensions"),
                    diagnostics,
                    false,
                )
            {
                valid = false;
            }
            for (parameter_index, parameter) in shape.parameters.iter().enumerate() {
                if !validate_non_transfer_value_attachments(
                    &parameter.extensions,
                    &format!("{path}.callable.parameters[{parameter_index}].extensions"),
                    diagnostics,
                    false,
                ) {
                    valid = false;
                }
            }
            for (result_index, result) in shape.results.iter().enumerate() {
                if !validate_non_transfer_value_attachments(
                    &result.extensions,
                    &format!("{path}.callable.results[{result_index}].extensions"),
                    diagnostics,
                    false,
                ) {
                    valid = false;
                }
            }
        }
    }
    for (index, relationship) in model.relationships.iter().enumerate() {
        let extensions = match relationship {
            CsmiRelationship::Type(relationship) => &relationship.extensions,
            CsmiRelationship::Member(relationship) => &relationship.extensions,
        };
        if !validate_non_transfer_value_attachments(
            extensions,
            &format!("{prefix}.relationships[{index}].extensions"),
            diagnostics,
            false,
        ) {
            valid = false;
        }
    }
    for (index, summary) in model.procedure_summaries.iter().enumerate() {
        if !validate_non_transfer_value_attachments(
            &summary.extensions,
            &format!("{prefix}.procedureSummaries[{index}].extensions"),
            diagnostics,
            false,
        ) {
            valid = false;
        }
    }
    for (index, fact) in model.extension_facts.iter().enumerate() {
        if !validate_non_transfer_value_attachments(
            &fact.extensions,
            &format!("{prefix}.extensionFacts[{index}].extensions"),
            diagnostics,
            false,
        ) {
            valid = false;
        }
    }
    valid
}

fn validate_input_location(
    location: &CsmiInputLocation,
    shape: &CsmiCallableShape,
    symbols: &HashSet<String>,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    match &location.root {
        CsmiInputBoundaryRoot::Receiver(_) if shape.receiver.is_none() => {
            error(
                diagnostics,
                "semantic.receiver_root",
                path,
                "input receiver root requires a callable receiver",
            );
            false
        }
        CsmiInputBoundaryRoot::Parameter(root)
            if root.position as usize >= shape.parameters.len() =>
        {
            error(
                diagnostics,
                "semantic.parameter_root",
                path,
                "input parameter position is outside callable shape",
            );
            false
        }
        CsmiInputBoundaryRoot::Capture(root) => {
            require_id(symbols, &root.symbol, path, "capture symbol", diagnostics)
        }
        _ => true,
    }
}

fn validate_output_location(
    location: &CsmiOutputLocation,
    shape: &CsmiCallableShape,
    symbols: &HashSet<String>,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    match &location.root {
        CsmiOutputBoundaryRoot::Receiver(_)
            if shape.receiver.is_none() && shape.kind != CsmiCallableKind::Constructor =>
        {
            error(
                diagnostics,
                "semantic.receiver_root",
                path,
                "output receiver root requires a callable receiver",
            );
            false
        }
        CsmiOutputBoundaryRoot::Parameter(root)
            if root.position as usize >= shape.parameters.len() =>
        {
            error(
                diagnostics,
                "semantic.parameter_root",
                path,
                "output parameter position is outside callable shape",
            );
            false
        }
        CsmiOutputBoundaryRoot::Result(root) if root.position as usize >= shape.results.len() => {
            error(
                diagnostics,
                "semantic.result_root",
                path,
                "output result position is outside callable shape",
            );
            false
        }
        CsmiOutputBoundaryRoot::Capture(root) => {
            require_id(symbols, &root.symbol, path, "capture symbol", diagnostics)
        }
        _ => true,
    }
}

fn validate_provenance_ids(
    ids: &[LocalId],
    path: &str,
    document: &CsmiSemanticDocument,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) {
    let known: HashSet<&str> = document
        .provenance_records
        .iter()
        .map(|record| record.id.as_str())
        .collect();
    for (index, id) in ids.iter().enumerate() {
        require_id(
            &known,
            id,
            format!("{path}[{index}]"),
            "provenance record",
            diagnostics,
        );
    }
}

fn validate_provenance_references(
    inputs: &[CsmiProvenanceInput],
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) {
    for (index, input) in inputs.iter().enumerate() {
        let count = usize::from(input.identifier.is_some())
            + usize::from(input.purl.is_some())
            + usize::from(input.digest.is_some())
            + usize::from(input.pack_digest.is_some())
            + usize::from(input.semantic_document_digest.is_some());
        if count == 0 {
            error(
                diagnostics,
                "semantic.provenance_input_identity",
                format!("{path}[{index}]"),
                "provenance input requires at least one identity",
            );
        }
    }
}

fn collect_vocabulary_uses(model: &CsmiSemanticModel) -> HashSet<(String, String)> {
    model
        .vocabulary_uses
        .iter()
        .map(|use_| (use_.identifier.clone(), use_.version.clone()))
        .collect()
}

fn unique_ids<'a>(
    values: impl IntoIterator<Item = &'a str>,
    path: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> HashSet<String> {
    let mut ids = HashSet::new();
    for id in values {
        if !ids.insert(id.to_owned()) {
            error(
                diagnostics,
                "semantic.duplicate_id",
                path,
                format!("duplicate local id {id:?}"),
            );
        }
    }
    ids
}

fn require_id<T: std::borrow::Borrow<str>>(
    known: &HashSet<T>,
    id: &str,
    path: impl Into<String>,
    kind: &str,
    diagnostics: &mut Vec<CsmiDiagnostic>,
) -> bool {
    if known.iter().any(|known| known.borrow() == id) {
        true
    } else {
        error(
            diagnostics,
            "semantic.unresolved_handle",
            path,
            format!("{kind} {id:?} is not defined in this scope"),
        );
        false
    }
}

fn canonical_scope(value: &Value) -> String {
    // Scope equality ignores object insertion order, including when another
    // workspace crate enables serde_json's preserve_order feature.
    let mut value = value.clone();
    value.sort_all_objects();
    serde_json::to_string(&value).expect("JSON values are serializable")
}

fn error(
    diagnostics: &mut Vec<CsmiDiagnostic>,
    code: impl Into<String>,
    path: impl Into<String>,
    message: impl Into<String>,
) {
    diagnostics.push(CsmiDiagnostic::error(code, path, message));
}

fn resource_diagnostic(error: CsmiResourceError) -> CsmiDiagnostic {
    let message = error.to_string();
    match error {
        CsmiResourceError::Missing { path } => CsmiDiagnostic::error(
            "integrity.resource_missing",
            format!("$.resources[{path:?}]"),
            message,
        ),
        CsmiResourceError::InvalidPath { path, .. } => {
            CsmiDiagnostic::error("integrity.resource_path", path, message)
        }
        CsmiResourceError::SizeMismatch { path, .. } => {
            CsmiDiagnostic::error("integrity.resource_size", path, message)
        }
        CsmiResourceError::DigestMismatch { path, .. } => {
            CsmiDiagnostic::error("integrity.resource_digest", path, message)
        }
        CsmiResourceError::DuplicatePath { path } => {
            CsmiDiagnostic::error("integrity.duplicate_resource", path, message)
        }
        CsmiResourceError::UnexpectedPath { path } => {
            CsmiDiagnostic::error("integrity.unexpected_resource", path, message)
        }
    }
}

fn sort_diagnostics(diagnostics: &mut Vec<CsmiDiagnostic>) {
    diagnostics.sort_by(|left, right| {
        (&left.path, &left.code, &left.message).cmp(&(&right.path, &right.code, &right.message))
    });
    diagnostics.dedup();
}

#[cfg(test)]
mod scope_key_tests {
    use super::canonical_scope;
    use serde_json::Value;

    #[test]
    fn scope_keys_ignore_nested_object_order_but_preserve_array_order() {
        let left: Value = serde_json::from_str(
            r#"{"kind":"yield","items":[{"factory":"f","resume":"r"},"next"]}"#,
        )
        .unwrap();
        let reordered: Value = serde_json::from_str(
            r#"{"items":[{"resume":"r","factory":"f"},"next"],"kind":"yield"}"#,
        )
        .unwrap();
        assert_eq!(left, reordered);
        assert_eq!(canonical_scope(&left), canonical_scope(&reordered));

        let mut different = reordered.clone();
        different["items"].as_array_mut().unwrap().reverse();
        assert_ne!(left, different);
        assert_ne!(canonical_scope(&left), canonical_scope(&different));
        different = reordered;
        different["items"][0]["resume"] = Value::String("other".to_owned());
        assert_ne!(canonical_scope(&left), canonical_scope(&different));
    }
}
