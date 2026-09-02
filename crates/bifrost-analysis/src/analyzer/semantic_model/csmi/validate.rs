//! Structural and semantic conformance checks for CSMI v0.1.

use super::canonical::{canonical_pack_manifest, canonical_semantic_document};
use super::model::*;
use super::pack::{
    CsmiResourceError, CsmiResourceResolver, validate_resource_path, verify_resources,
};
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
const JAVA_SOURCE_IDENTITY_SCHEMA_JSON: &str =
    include_str!("profiles/java-source-identity.schema.json");
const JVM_BINARY_IDENTITY_SCHEMA_JSON: &str =
    include_str!("profiles/jvm-binary-identity.schema.json");
const JAVA_JVM_MAPPING_SCHEMA_JSON: &str = include_str!("profiles/java-jvm-mapping.schema.json");
const JVM_COMPATIBILITY_SCHEMA_JSON: &str = include_str!("profiles/jvm-compatibility.schema.json");

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
        .find(|(_, profile)| profile.identifier == identifier || profile.schema == schema)
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
        let key = format!("{}:{}", statement.family, canonical_scope(&statement.scope));
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
        CsmiOutputBoundaryRoot::Receiver(_) if shape.receiver.is_none() => {
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
    serde_json::to_string(value).expect("JSON values are serializable")
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
