use crate::analyzer::semantic_model::model::*;

use brokk_bifrost_core::analyzer::canonical_hash::is_lower_sha256;

use brokk_bifrost_core::analyzer::identifier::validate_identifier;

use crate::analyzer::semantic_model::DeferredYieldsPayload;

use crate::analyzer::semantic::workspace_document::has_portable_windows_path_prefix;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnostic {
    pub severity: DiagnosticSeverity,
    pub code: String,
    pub path: String,
    pub message: String,
}

impl Diagnostic {
    pub(crate) fn error(
        code: impl Into<String>,
        path: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            severity: DiagnosticSeverity::Error,
            code: code.into(),
            path: path.into(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[doc(hidden)]
pub struct ValidationLimits {
    pub max_shards: usize,
    pub max_records_per_shard: usize,
    pub max_records_per_pack: usize,
    pub max_text_bytes: usize,
    pub max_depth: usize,
}

fn valid_go_import_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.chars().any(char::is_whitespace)
        && !value.chars().any(char::is_control)
        && value
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn valid_go_source_range(range: SourceByteRange) -> bool {
    range.start < range.end
}

fn contains_source_range(outer: SourceByteRange, inner: SourceByteRange) -> bool {
    outer.start <= inner.start && inner.end <= outer.end
}

fn contains_strict_source_range(outer: SourceByteRange, inner: SourceByteRange) -> bool {
    outer.start < inner.start && inner.end < outer.end
}

pub(crate) fn validate_pack(
    pack: &AuthoredSemanticModelPack,
    limits: ValidationLimits,
) -> Vec<Diagnostic> {
    validate_pack_internal(pack, limits, true).0
}

#[doc(hidden)]
pub fn validate_pack_locally(
    pack: &AuthoredSemanticModelPack,
    limits: ValidationLimits,
) -> Vec<Diagnostic> {
    validate_pack_internal(pack, limits, false).0
}

#[doc(hidden)]
pub fn validate_csmi_profile_evidence(pack: &AuthoredSemanticModelPack) -> Vec<Diagnostic> {
    let mut diagnostics =
        crate::analyzer::semantic_model::csmi::python::validate_profile_evidence(pack);
    diagnostics
        .extend(crate::analyzer::semantic_model::csmi::python::validate_native_identities(pack));
    diagnostics
}

/// Validates `pack` at its declared schema version and also returns the
/// lowest version whose gates admit every field the pack uses.
pub(crate) fn validate_pack_internal(
    pack: &AuthoredSemanticModelPack,
    limits: ValidationLimits,
    validate_references: bool,
) -> (Vec<Diagnostic>, u32) {
    let mut validator = Validator {
        language: pack.language.clone(),
        go_packages_by_type_id: HashMap::new(),
        go_local_types: HashSet::new(),
        go_current_package: None,
        diagnostics: Vec::new(),
        limits,
        stable_ids: HashMap::new(),
        declaration_ids: HashSet::new(),
        anonymous_callable_ids: HashSet::new(),
        type_ids: HashSet::new(),
        type_kinds_by_id: HashMap::new(),
        type_kinds_by_name: HashMap::new(),
        member_ids: HashSet::new(),
        member_owners: HashMap::new(),
        member_family_complete: HashMap::new(),
        member_operations: HashMap::new(),
        procedure_ids: HashSet::new(),
        procedure_targets: HashMap::new(),
        type_parameters_by_id: HashMap::new(),
        pack_completeness: pack.completeness,
        pack_id_bytes: pack.pack_id.len(),
        schema_version: pack.schema_version,
        required_schema_version: VERSION_INDEPENDENT_COMPATIBILITY_SCHEMA_VERSION,
        validate_references,
    };
    validator.validate(pack);
    validator
        .diagnostics
        .extend(crate::analyzer::semantic_model::csmi::python::validate_native_identities(pack));
    if validate_references {
        validator
            .diagnostics
            .extend(crate::analyzer::semantic_model::csmi::python::validate_profile_evidence(pack));
    }
    validator
        .diagnostics
        .sort_by(|left, right| (&left.path, &left.code).cmp(&(&right.path, &right.code)));
    (validator.diagnostics, validator.required_schema_version)
}

struct Validator {
    language: String,
    go_packages_by_type_id: HashMap<String, String>,
    go_local_types: HashSet<(String, String)>,
    go_current_package: Option<String>,
    diagnostics: Vec<Diagnostic>,
    limits: ValidationLimits,
    stable_ids: HashMap<String, String>,
    declaration_ids: HashSet<String>,
    anonymous_callable_ids: HashSet<String>,
    type_ids: HashSet<String>,
    type_kinds_by_id: HashMap<String, TypeKind>,
    type_kinds_by_name: HashMap<String, Option<TypeKind>>,
    member_ids: HashSet<String>,
    member_owners: HashMap<String, String>,
    member_family_complete: HashMap<String, bool>,
    member_operations: HashMap<String, Option<ImplicitOperation>>,
    procedure_ids: HashSet<String>,
    procedure_targets: HashMap<(String, String), String>,
    type_parameters_by_id: HashMap<String, Vec<String>>,
    pack_completeness: Completeness,
    pack_id_bytes: usize,
    schema_version: u32,
    /// The highest schema version whose gated fields this pack uses, never
    /// below the version-independent floor. See `predates_schema`.
    required_schema_version: u32,
    validate_references: bool,
}

impl Validator {
    fn validate(&mut self, pack: &AuthoredSemanticModelPack) {
        if !SEMANTIC_MODEL_SUPPORTED_SCHEMA_VERSIONS.contains(&pack.schema_version) {
            self.error(
                "schema.unsupported_version",
                "$.schema_version",
                format!(
                    "expected one of schema versions {SEMANTIC_MODEL_SUPPORTED_SCHEMA_VERSIONS:?}, found {}",
                    pack.schema_version
                ),
            );
        }
        if let Some(extraction) = &pack.extraction {
            if self.predates_schema(19) {
                self.error(
                    "extraction.schema_version",
                    "$.extraction",
                    "artifact extraction requires schema 19",
                );
            }
            if !brokk_bifrost_core::analyzer::canonical_hash::is_lower_sha256(extraction.digest()) {
                self.error(
                    "extraction.digest",
                    "$.extraction",
                    "extraction inputs require a lowercase SHA-256 digest",
                );
            }
        }
        self.stable_id("$.pack_id", &pack.pack_id);
        self.version("$.version", &pack.version);
        self.text("$.producer.name", &pack.producer.name);
        self.version("$.producer.version", &pack.producer.version);
        self.stable_component("$.language", &pack.language);
        self.stable_component("$.ecosystem", &pack.ecosystem);
        if let Some(requirement) = &pack.compatibility.bifrost {
            self.text("$.compatibility.bifrost", requirement);
        }
        if SEMANTIC_MODEL_SUPPORTED_SCHEMA_VERSIONS.contains(&pack.schema_version)
            && let Err(error) = pack.compatibility.validate_for_schema(pack.schema_version)
        {
            let (code, message) = match error {
                CompatibilityError::InvalidLegacyRequirement => (
                    "version.invalid_requirement",
                    "expected a semantic-version requirement",
                ),
                _ => ("compatibility.schema_shape", "invalid compatibility shape"),
            };
            self.error(
                code,
                "$.compatibility.bifrost",
                format!("{message}: {error}"),
            );
        }
        for (index, toolchain) in pack.compatibility.toolchains.iter().enumerate() {
            self.stable_component(
                &format!("$.compatibility.toolchains[{index}].name"),
                &toolchain.name,
            );
            self.version_requirement(
                &format!("$.compatibility.toolchains[{index}].requirement"),
                &toolchain.requirement,
            );
        }
        self.text("$.provenance.source", &pack.provenance.source);
        if let Some(revision) = &pack.provenance.revision {
            self.text("$.provenance.revision", revision);
        }
        self.text("$.license", &pack.license);
        if let Err(error) = spdx::Expression::parse(&pack.license) {
            self.error(
                "license.invalid_spdx",
                "$.license",
                format!("invalid SPDX expression: {error}"),
            );
        }
        if pack
            .carried_sources
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            self.error(
                "carried_sources.unsorted",
                "$.carried_sources",
                "carried sources must be unique ascending paths",
            );
        }
        for (index, path) in pack.carried_sources.iter().enumerate() {
            self.locator_path(&format!("$.carried_sources[{index}]"), path);
        }
        if pack.shards.len() > self.limits.max_shards {
            self.error(
                "limit.shards",
                "$.shards",
                format!("pack has more than {} shards", self.limits.max_shards),
            );
        }
        if pack.shards.is_empty() {
            self.error(
                "pack.no_shards",
                "$.shards",
                "a semantic-model pack must contain at least one shard",
            );
        }

        for shard in &pack.shards {
            if let AuthoredPayload::DeclarationFacts { types, members, .. } = &shard.payload {
                self.declaration_ids
                    .extend(types.iter().map(|fact| fact.id.clone()));
                self.type_ids
                    .extend(types.iter().map(|fact| fact.id.clone()));
                for fact in types {
                    if self.language == "go" {
                        let parts =
                            brokk_bifrost_go::declarations::go_model_type_name_parts(&fact.name);
                        if fact.type_kind != TypeKind::Module
                            && let Some((package, simple)) = parts
                        {
                            self.go_local_types
                                .insert((package.to_owned(), simple.to_owned()));
                        }
                        let package = brokk_bifrost_go::declarations::go_model_owner_package(
                            &fact.name,
                            fact.type_kind == TypeKind::Module,
                        );
                        if let Some(package) = package {
                            self.go_packages_by_type_id
                                .insert(fact.id.clone(), package.to_owned());
                        }
                    }
                    self.type_kinds_by_id
                        .insert(fact.id.clone(), fact.type_kind);
                    self.type_kinds_by_name
                        .entry(fact.name.clone())
                        .and_modify(|kind| *kind = None)
                        .or_insert(Some(fact.type_kind));
                }
                self.declaration_ids
                    .extend(members.iter().map(|fact| fact.id.clone()));
                self.member_ids
                    .extend(members.iter().map(|fact| fact.id.clone()));
                self.member_owners.extend(
                    members
                        .iter()
                        .map(|fact| (fact.id.clone(), fact.owner.clone())),
                );
                self.member_family_complete.extend(
                    members
                        .iter()
                        .map(|fact| (fact.id.clone(), fact.callable_family_complete)),
                );
                self.member_operations.extend(
                    members
                        .iter()
                        .map(|fact| (fact.id.clone(), fact.implicit_operation.clone())),
                );
                self.type_parameters_by_id.extend(
                    types
                        .iter()
                        .map(|fact| (fact.id.clone(), fact.type_parameters.clone())),
                );
            }
            if let AuthoredPayload::ProcedureSummaries { summaries } = &shard.payload {
                self.procedure_ids
                    .extend(summaries.iter().map(|summary| summary.id.clone()));
            }
            if let Some(runtime_values) = &shard.runtime_values {
                self.runtime_values(
                    &format!("$.shards[{}/runtime_values]", shard.id),
                    runtime_values,
                    &shard.activation,
                );
            }
            if let Some(runtime_contracts) = &shard.runtime_contracts {
                self.runtime_contracts(
                    &format!("$.shards[{}/runtime_contracts]", shard.id),
                    runtime_contracts,
                    &shard.activation,
                );
            }
            if let Some(collection_flows) = &shard.collection_flows {
                self.collection_flows(
                    &format!("$.shards[{}/collection_flows]", shard.id),
                    collection_flows,
                );
            }
            if let Some(deferred_yields) = &shard.deferred_yields {
                self.deferred_yields(
                    &format!("$.shards[{}/deferred_yields]", shard.id),
                    deferred_yields,
                );
            }
        }
        let mut anonymous_id_counts = HashMap::<&str, usize>::new();
        for identity in pack
            .shards
            .iter()
            .filter_map(|shard| shard.callable_values.as_ref())
            .flat_map(|payload| payload.anonymous_callables.iter())
        {
            *anonymous_id_counts.entry(&identity.id).or_default() += 1;
        }
        for shard in &pack.shards {
            let Some(payload) = &shard.callable_values else {
                continue;
            };
            for (index, identity) in payload.anonymous_callables.iter().enumerate() {
                let identity_path = format!(
                    "$.shards[{}/callable_values].anonymous_callables[{index}]",
                    shard.id
                );
                let id_path = format!("{identity_path}.id");
                self.stable_id(&id_path, &identity.id);
                let structurally_valid =
                    self.anonymous_callable_identity(&identity_path, identity, &shard.activation);
                if anonymous_id_counts.get(identity.id.as_str()).copied() != Some(1) {
                    self.error(
                        "callable_values.anonymous_duplicate_id",
                        id_path,
                        format!(
                            "anonymous callable ID `{}` must identify exactly one source identity in the pack",
                            identity.id
                        ),
                    );
                    continue;
                }
                let collides = self.declaration_ids.contains(&identity.id)
                    || self.procedure_ids.contains(&identity.id)
                    || self
                        .stable_ids
                        .get(&identity.id)
                        .is_some_and(|first_path| first_path != &id_path);
                if collides {
                    self.error(
                        "callable_values.anonymous_id_collision",
                        id_path,
                        "anonymous callable ID collides with another pack identity",
                    );
                    continue;
                }
                if structurally_valid {
                    self.anonymous_callable_ids.insert(identity.id.clone());
                    self.declaration_ids.insert(identity.id.clone());
                }
            }
        }
        let callable_members = pack
            .shards
            .iter()
            .filter_map(|shard| match &shard.payload {
                AuthoredPayload::DeclarationFacts { members, .. } => Some(members),
                _ => None,
            })
            .flatten()
            .filter(|member| {
                matches!(
                    member.member_kind,
                    MemberKind::Constructor | MemberKind::Method | MemberKind::Function
                )
            })
            .map(|member| (member.id.as_str(), member))
            .collect::<HashMap<_, _>>();
        let anonymous_callable_ids = self.anonymous_callable_ids.clone();
        for shard in &pack.shards {
            if let Some(callable_values) = &shard.callable_values {
                self.callable_values(
                    &format!("$.shards[{}/callable_values]", shard.id),
                    callable_values,
                    &callable_members,
                    &anonymous_callable_ids,
                );
            }
        }
        if pack.shards.iter().any(|shard| {
            shard.deferred_yields.is_some()
                || shard.conditional_type_refinements.is_some()
                || shard.runtime_contracts.is_some()
                || shard.callable_values.is_some()
        }) {
            if native_profile_depth_within(pack, self.limits.max_depth) {
                if self.validate_references {
                    self.diagnostics
                        .extend(validate_native_profile_contracts(pack));
                } else {
                    let model = native_contract_model(pack);
                    self.diagnostics.extend(
                        crate::analyzer::semantic_model::csmi::validate_native_deferred_yield_model(&model)
                            .into_iter()
                            .chain(crate::analyzer::semantic_model::csmi::validate_native_conditional_type_payloads(
                                &model,
                            ))
                            .map(|diagnostic| {
                                Diagnostic::error(
                                    diagnostic.code,
                                    diagnostic.path,
                                    diagnostic.message,
                                )
                            }),
                    );
                }
            } else {
                self.error(
                    "limit.deferred_depth",
                    "$.shards",
                    "standard-profile type or shape nesting exceeds the configured depth budget",
                );
            }
        }
        if let Some(evidence) = &pack.cpp_portability {
            self.cpp_portability(evidence);
        }

        let mut total_records = 0usize;
        for (index, shard) in pack.shards.iter().enumerate() {
            let path = format!("$.shards[{index}]");
            self.stable_id(&format!("{path}.id"), &shard.id);
            if shard.activation.is_empty() {
                self.error(
                    "selector.missing",
                    format!("{path}.activation"),
                    "a shard must declare at least one activation selector",
                );
            }
            for (selector_index, selector) in shard.activation.iter().enumerate() {
                self.selector(
                    &format!("{path}.activation[{selector_index}]"),
                    selector,
                    &pack.compatibility.toolchains,
                );
            }
            let records = shard
                .payload
                .record_count()
                .saturating_add(
                    shard
                        .runtime_values
                        .as_ref()
                        .map_or(0, RuntimeValuesPayload::record_count),
                )
                .saturating_add(
                    shard
                        .runtime_contracts
                        .as_ref()
                        .map_or(0, RuntimeContractsPayload::record_count),
                )
                .saturating_add(
                    shard
                        .collection_flows
                        .as_ref()
                        .map_or(0, CollectionFlowsPayload::record_count),
                );
            let records = records
                .saturating_add(
                    shard
                        .deferred_yields
                        .as_ref()
                        .map_or(0, DeferredYieldsPayload::record_count),
                )
                .saturating_add(
                    shard
                        .conditional_type_refinements
                        .as_ref()
                        .map_or(0, ConditionalTypeRefinementsPayload::record_count),
                )
                .saturating_add(
                    shard
                        .callable_values
                        .as_ref()
                        .map_or(0, CallableValuesPayload::record_count),
                );
            if shard.callable_values.is_some()
                && self.predates_schema(CALLABLE_VALUES_MIN_SCHEMA_VERSION)
            {
                self.error(
                    "schema.callable_values_version",
                    format!("{path}.callable_values"),
                    format!(
                        "callable-values transport requires schema version {CALLABLE_VALUES_MIN_SCHEMA_VERSION}"
                    ),
                );
            }
            if records == 0 {
                self.error(
                    "shard.empty_payload",
                    format!("{path}.payload"),
                    "a shard payload must contain at least one record",
                );
            }
            total_records = total_records.saturating_add(records);
            if records > self.limits.max_records_per_shard {
                self.error(
                    "limit.shard_records",
                    format!("{path}.payload"),
                    format!(
                        "shard has more than {} records",
                        self.limits.max_records_per_shard
                    ),
                );
            }
            self.payload(&format!("{path}.payload"), &shard.payload);
        }
        if total_records > self.limits.max_records_per_pack {
            self.error(
                "limit.pack_records",
                "$.shards",
                format!(
                    "pack has more than {} total records",
                    self.limits.max_records_per_pack
                ),
            );
        }
    }

    fn anonymous_callable_identity(
        &mut self,
        path: &str,
        identity: &AnonymousCallableIdentity,
        activation: &[ActivationSelector],
    ) -> bool {
        let mut valid = true;
        if self.language != "go" {
            self.error(
                "callable_values.anonymous_language",
                path,
                "anonymous callable source identities are supported only for Go packs",
            );
            valid = false;
        }
        self.text(
            &format!("{path}.artifact_sha256"),
            &identity.artifact_sha256,
        );
        if !is_lower_sha256(&identity.artifact_sha256) {
            self.error(
                "callable_values.anonymous_artifact",
                format!("{path}.artifact_sha256"),
                "anonymous callable artifact identity must be a lowercase SHA-256 digest",
            );
            valid = false;
        }
        if !activation.iter().any(|selector| {
            selector.artifact_sha256.as_deref() == Some(identity.artifact_sha256.as_str())
        }) {
            self.error(
                "callable_values.anonymous_artifact",
                format!("{path}.artifact_sha256"),
                "anonymous callable digest must match an artifact-pinned shard activation selector",
            );
            valid = false;
        }

        self.text(
            &format!("{path}.package_import_path"),
            &identity.package_identity,
        );
        if !valid_go_import_path(&identity.package_identity) {
            self.error(
                "callable_values.anonymous_package",
                format!("{path}.package_import_path"),
                "Go package import path must be relative, canonical, and contain no empty, dot, or parent components",
            );
            valid = false;
        }

        self.locator_path(&format!("{path}.anchor.file"), &identity.anchor.file);
        if identity.anchor.kind != SourceDeclarationKind::FunctionLiteral {
            self.error(
                "callable_values.anonymous_anchor_kind",
                format!("{path}.anchor.kind"),
                "anonymous callable anchor must identify a Go function literal",
            );
            valid = false;
        }
        if !valid_go_source_range(identity.anchor.byte_range) {
            self.error(
                "callable_values.anonymous_range",
                format!("{path}.anchor.byte_range"),
                "source ranges must be non-empty half-open byte ranges",
            );
            valid = false;
        }

        if identity.lexical_owner_chain.len() > self.limits.max_depth {
            self.error(
                "limit.callable_values_anonymous_owners",
                format!("{path}.lexical_owner_chain"),
                format!("lexical owner depth exceeds {}", self.limits.max_depth),
            );
            valid = false;
        } else {
            let mut parent = None;
            for (index, owner) in identity.lexical_owner_chain.iter().enumerate() {
                let owner_path = format!("{path}.lexical_owner_chain[{index}]");
                self.locator_path(&format!("{owner_path}.file"), &owner.file);
                if owner.file != identity.anchor.file
                    || !matches!(
                        owner.kind,
                        SourceDeclarationKind::Function
                            | SourceDeclarationKind::Method
                            | SourceDeclarationKind::FunctionLiteral
                    )
                {
                    self.error(
                        "callable_values.anonymous_owner",
                        owner_path.clone(),
                        "lexical owners must be enclosing Go functions, methods, or function literals in the same file",
                    );
                    valid = false;
                }
                if !valid_go_source_range(owner.byte_range) {
                    self.error(
                        "callable_values.anonymous_range",
                        format!("{owner_path}.byte_range"),
                        "source ranges must be non-empty half-open byte ranges",
                    );
                    valid = false;
                }
                if let Some(parent_range) = parent
                    && !contains_strict_source_range(parent_range, owner.byte_range)
                {
                    self.error(
                        "callable_values.anonymous_owner",
                        format!("{owner_path}.byte_range"),
                        "lexical owner ranges must be strictly nested from outermost to innermost",
                    );
                    valid = false;
                }
                parent = Some(owner.byte_range);
            }
            if let Some(parent_range) = parent
                && !contains_strict_source_range(parent_range, identity.anchor.byte_range)
            {
                self.error(
                    "callable_values.anonymous_owner",
                    format!("{path}.anchor.byte_range"),
                    "the function literal must be strictly contained by its innermost lexical owner",
                );
                valid = false;
            }
        }

        let signature = &identity.signature;
        self.text(
            &format!("{path}.signature.function_type.file"),
            &signature.function_type.file,
        );
        let signature_range = signature.function_type.byte_range;
        if signature.function_type.file != identity.anchor.file
            || !valid_go_source_range(signature_range)
            || signature_range.start != identity.anchor.byte_range.start
            || signature_range.end > identity.anchor.byte_range.end
        {
            self.error(
                "callable_values.anonymous_signature",
                format!("{path}.signature.function_type"),
                "literal signature range must start at the function literal and remain inside its exact source anchor",
            );
            valid = false;
        }
        if !signature.declaration_chain.is_empty() {
            self.error(
                "callable_values.anonymous_signature",
                format!("{path}.signature.declaration_chain"),
                "function literal signature provenance cannot claim package-scope type declaration bindings",
            );
            valid = false;
        }

        let shape_record_count = signature
            .parameters
            .len()
            .saturating_add(signature.results.len());
        if shape_record_count > self.limits.max_records_per_shard {
            self.error(
                "limit.callable_values_anonymous_shape",
                format!("{path}.signature"),
                format!(
                    "signature shape has more than {} parameter and result groups",
                    self.limits.max_records_per_shard
                ),
            );
            valid = false;
            return valid;
        }
        for (kind, items) in [
            ("parameters", signature.parameters.as_slice()),
            ("results", signature.results.as_slice()),
        ] {
            for (index, item) in items.iter().enumerate() {
                let item_path = format!("{path}.signature.{kind}[{index}]");
                self.text(&format!("{item_path}.type_node.file"), &item.type_node.file);
                if item.arity == 0 {
                    self.error(
                        "callable_values.anonymous_signature",
                        format!("{item_path}.arity"),
                        "AST parameter and result groups must have positive arity",
                    );
                    valid = false;
                }
                if item.type_node.file != identity.anchor.file
                    || !valid_go_source_range(item.type_node.byte_range)
                    || !contains_source_range(signature_range, item.type_node.byte_range)
                {
                    self.error(
                        "callable_values.anonymous_signature",
                        format!("{item_path}.type_node"),
                        "parameter and result type nodes must be anchored inside the literal signature in the same file",
                    );
                    valid = false;
                }
                if item.variadic && (kind == "results" || index + 1 != items.len()) {
                    self.error(
                        "callable_values.anonymous_signature",
                        format!("{item_path}.variadic"),
                        "only the final parameter group may be variadic",
                    );
                    valid = false;
                }
            }
        }
        valid
    }

    fn callable_values(
        &mut self,
        path: &str,
        payload: &CallableValuesPayload,
        callable_members: &HashMap<&str, &MemberFact>,
        anonymous_callable_ids: &HashSet<String>,
    ) {
        use crate::analyzer::semantic_model::csmi::CsmiCallableValuesArgument;

        use crate::analyzer::semantic_model::csmi::CsmiCallableValuesPayload;

        if payload.facts.is_empty()
            && payload.coverage.is_empty()
            && payload.anonymous_callables.is_empty()
        {
            self.error(
                "callable_values.empty",
                path,
                "callable-values carrier must contain a fact or coverage row",
            );
        }

        for (index, fact) in payload.facts.iter().enumerate() {
            let fact_path = format!("{path}.facts[{index}]");
            let permitted_anonymous_target = match &fact.payload {
                CsmiCallableValuesPayload::ReturnedCallable { target, .. }
                    if anonymous_callable_ids.contains(target)
                        && payload
                            .anonymous_callables
                            .iter()
                            .any(|identity| identity.id.as_str() == target.as_str()) =>
                {
                    Some(target.as_str())
                }
                _ => None,
            };
            let mut remapped = fact.payload.clone();
            if let Err(error) = remapped.remap_symbols(|symbol| {
                (self.declaration_ids.contains(symbol)
                    && (!anonymous_callable_ids.contains(symbol)
                        || permitted_anonymous_target == Some(symbol)))
                .then(|| symbol.to_owned())
                .ok_or_else(|| symbol.to_owned())
            }) {
                self.error(
                    "callable_values.symbol_reference",
                    format!("{fact_path}.payload"),
                    format!("callable-values payload has an unknown symbol or unsupported projection: {error:?}"),
                );
            }

            match &fact.payload {
                CsmiCallableValuesPayload::ReturnedCallable {
                    callable,
                    result,
                    target,
                } => {
                    let Some(factory) = callable_members.get(callable.as_str()).copied() else {
                        self.error(
                            "callable_values.factory",
                            format!("{fact_path}.payload.callable"),
                            format!("returned-callable factory `{callable}` is not an indexed callable member"),
                        );
                        continue;
                    };
                    let Some(signature) = factory.signature.as_ref() else {
                        self.error(
                            "callable_values.factory",
                            format!("{fact_path}.payload.callable"),
                            format!(
                                "returned-callable factory `{callable}` has no callable signature"
                            ),
                        );
                        continue;
                    };
                    let normal_results = match &signature.returns {
                        None => 0,
                        Some(TypeRef::Tuple { elements }) => {
                            u32::try_from(elements.len()).expect("model result count fits a u32")
                        }
                        Some(_) => 1,
                    };
                    if *result >= normal_results {
                        self.error(
                            "callable_values.result",
                            format!("{fact_path}.payload.result"),
                            format!("returned-callable result {result} is outside the factory's {normal_results} normal result ports"),
                        );
                    }
                    let Some(target_member) = callable_members.get(target.as_str()).copied() else {
                        if anonymous_callable_ids.contains(target)
                            && payload
                                .anonymous_callables
                                .iter()
                                .any(|identity| identity.id.as_str() == target.as_str())
                        {
                            continue;
                        }
                        self.error(
                            "callable_values.target",
                            format!("{fact_path}.payload.target"),
                            format!("returned-callable target `{target}` is not an indexed callable member or unique validated Go function literal"),
                        );
                        continue;
                    };
                    if target_member.signature.is_none() {
                        self.error(
                            "callable_values.target",
                            format!("{fact_path}.payload.target"),
                            format!(
                                "returned-callable target `{target}` has no callable signature"
                            ),
                        );
                    }
                }
                CsmiCallableValuesPayload::CallbackInvocation {
                    callable,
                    callback,
                    shape,
                    arguments,
                    ..
                } => {
                    let Some(factory) = callable_members.get(callable.as_str()).copied() else {
                        self.error(
                            "callable_values.factory",
                            format!("{fact_path}.payload.callable"),
                            format!(
                                "callback factory `{callable}` is not an indexed callable member"
                            ),
                        );
                        continue;
                    };
                    let Some(signature) = factory.signature.as_ref() else {
                        self.error(
                            "callable_values.factory",
                            format!("{fact_path}.payload.callable"),
                            format!("callback factory `{callable}` has no callable signature"),
                        );
                        continue;
                    };
                    if arguments.len() != usize::from(shape.parameters) {
                        self.error(
                            "callable_values.argument_arity",
                            format!("{fact_path}.payload.arguments"),
                            format!("known callback arguments count {} does not equal shape.parameters {}", arguments.len(), shape.parameters),
                        );
                    }
                    self.callable_values_location_root(
                        &format!("{fact_path}.payload.callback"),
                        callback,
                        factory,
                        signature,
                    );
                    for (argument_index, argument) in arguments.iter().enumerate() {
                        if let CsmiCallableValuesArgument::Input { source } = argument {
                            self.callable_values_location_root(
                                &format!("{fact_path}.payload.arguments[{argument_index}].source"),
                                source,
                                factory,
                                signature,
                            );
                        }
                    }
                }
            }
        }

        for (index, coverage) in payload.coverage.iter().enumerate() {
            let path = format!("{path}.coverage[{index}].callable");
            let Some(member) = callable_members.get(coverage.callable.as_str()).copied() else {
                self.error(
                    "callable_values.coverage_callable",
                    path,
                    format!(
                        "coverage callable `{}` is not an indexed callable member",
                        coverage.callable
                    ),
                );
                continue;
            };
            if member.signature.is_none() {
                self.error(
                    "callable_values.coverage_callable",
                    path,
                    format!(
                        "coverage callable `{}` has no callable signature",
                        coverage.callable
                    ),
                );
            }
        }
    }

    fn callable_values_location_root(
        &mut self,
        path: &str,
        location: &crate::analyzer::semantic_model::csmi::CsmiInputLocation,
        factory: &MemberFact,
        signature: &Signature,
    ) {
        use crate::analyzer::semantic_model::csmi::CsmiInputBoundaryRoot;

        match &location.root {
            CsmiInputBoundaryRoot::Receiver(_) if factory.receiver.is_none() => self.error(
                "callable_values.receiver_root",
                format!("{path}.root"),
                "callable-values location uses a receiver root but the factory has no receiver",
            ),
            CsmiInputBoundaryRoot::Parameter(parameter)
                if parameter.position as usize >= signature.parameters.len() => self.error(
                    "callable_values.parameter_root",
                    format!("{path}.root.position"),
                    format!(
                        "parameter root {} is outside the factory arity {}",
                        parameter.position,
                        signature.parameters.len()
                    ),
                ),
            CsmiInputBoundaryRoot::Capture(_) => self.error(
                "callable_values.capture_root",
                format!("{path}.root"),
                "callable-values callback locations require a factory receiver or formal parameter root",
            ),
            _ => {}
        }
    }

    fn selector(
        &mut self,
        path: &str,
        selector: &ActivationSelector,
        compatible_toolchains: &[VersionConstraint],
    ) {
        let selectors = [
            ("package", selector.package.as_ref()),
            ("module", selector.module.as_ref()),
            ("toolchain", selector.toolchain.as_ref()),
        ];
        // An empty coordinate selector is the explicit language-intrinsic
        // activation form. Runtime matching still requires matching language
        // and ecosystem evidence for the shard.
        if let Some(toolchain) = &selector.toolchain
            && !compatible_toolchains
                .iter()
                .any(|compatible| compatible.name == toolchain.name)
        {
            self.error(
                "selector.incompatible",
                format!("{path}.toolchain.name"),
                "toolchain selector is not declared by pack compatibility metadata",
            );
        }
        for (field, selected) in selectors {
            if let Some(selected) = selected {
                self.text(&format!("{path}.{field}.name"), &selected.name);
                if let Some(requirement) = &selected.version {
                    self.version_requirement(&format!("{path}.{field}.version"), requirement);
                }
            }
        }
        for (index, target) in selector.targets.iter().enumerate() {
            self.stable_component(&format!("{path}.targets[{index}]"), target);
        }
        for (index, configuration) in selector.configurations.iter().enumerate() {
            let configuration_path = format!("{path}.configurations[{index}]");
            if configuration.starts_with("typescript-lib:") {
                self.text(&configuration_path, configuration);
            } else {
                self.stable_component(&configuration_path, configuration);
            }
        }
        if let Some(digest) = &selector.artifact_sha256
            && !is_lower_sha256(digest)
        {
            self.error(
                "selector.invalid_digest",
                format!("{path}.artifact_sha256"),
                "artifact digest must be 64 lowercase hexadecimal characters",
            );
        }
    }

    fn cpp_portability(&mut self, evidence: &CppPortabilityEvidence) {
        if evidence.resolution_contexts.is_empty() || evidence.symbols.is_empty() {
            self.error(
                "cpp_portability.empty",
                "$.cpp_portability",
                "C++ portability evidence requires a resolution context and portable symbols",
            );
        }
        let mut contexts = HashMap::new();
        for (index, context) in evidence.resolution_contexts.iter().enumerate() {
            let path = format!("$.cpp_portability.resolution_contexts[{index}]");
            if !is_lower_sha256(&context.context_digest) {
                self.error(
                    "cpp_portability.invalid_context_digest",
                    format!("{path}.context_digest"),
                    "context digest must be lowercase SHA-256",
                );
            }
            let expected_context_digest = crate::analyzer::semantic_model::csmi::canonical_digest(
                &crate::analyzer::semantic_model::csmi::csmi_resolution_context(context),
            );
            if !expected_context_digest
                .as_ref()
                .is_ok_and(|expected| expected == &context.context_digest)
            {
                self.error(
                    "cpp_portability.context_digest_mismatch",
                    format!("{path}.context_digest"),
                    "context digest must equal the RFC 8785 resolution-context digest",
                );
            }
            if contexts
                .insert(context.context_digest.as_str(), context.language)
                .is_some()
            {
                self.error(
                    "cpp_portability.duplicate_context",
                    format!("{path}.context_digest"),
                    "resolution context digest is repeated",
                );
            }
            if !is_lower_sha256(&context.compile_arguments_digest) {
                self.error(
                    "cpp_portability.invalid_arguments_digest",
                    format!("{path}.compile_arguments_digest"),
                    "compiler argument digest must be lowercase SHA-256",
                );
            }
            self.text(
                &format!("{path}.translation_unit"),
                &context.translation_unit,
            );
            if context.direct_headers.is_empty() {
                self.error(
                    "cpp_portability.empty_headers",
                    format!("{path}.direct_headers"),
                    "a complete context must identify every directly reached header",
                );
            }
            for (header_index, header) in context.direct_headers.iter().enumerate() {
                let header_path = format!("{path}.direct_headers[{header_index}]");
                self.text(&format!("{header_path}.include_name"), &header.include_name);
                self.cpp_selector(&format!("{header_path}.artifact"), &header.artifact);
            }
        }
        let mut symbol_ids = HashSet::new();
        for (index, symbol) in evidence.symbols.iter().enumerate() {
            let path = format!("$.cpp_portability.symbols[{index}]");
            self.stable_reference(&format!("{path}.native_id"), &symbol.native_id);
            if self.validate_references && !self.declaration_ids.contains(&symbol.native_id) {
                self.error(
                    "cpp_portability.unknown_symbol",
                    format!("{path}.native_id"),
                    "portable symbol must name a native declaration",
                );
            }
            if !symbol_ids.insert(symbol.native_id.as_str()) {
                self.error(
                    "cpp_portability.duplicate_symbol",
                    format!("{path}.native_id"),
                    "portable symbol is repeated",
                );
            }
            if symbol.key.scheme != CPP_DECLARATION_SCHEME
                || symbol.key.scheme_version != CPP_DECLARATION_SCHEME_VERSION
            {
                self.error(
                    "cpp_portability.identity_scheme",
                    format!("{path}.key.scheme"),
                    "portable symbols require csmi.cpp.declaration 0.1.0",
                );
            }
            if symbol.key.artifact_selectors.is_empty() || symbol.key.descriptors.is_empty() {
                self.error(
                    "cpp_portability.incomplete_symbol",
                    format!("{path}.key"),
                    "portable symbols require exact artifacts and structured descriptors",
                );
            }
            for (selector_index, selector) in symbol.key.artifact_selectors.iter().enumerate() {
                self.cpp_selector(
                    &format!("{path}.key.artifact_selectors[{selector_index}]"),
                    selector,
                );
            }
            for (descriptor_index, descriptor) in symbol.key.descriptors.iter().enumerate() {
                let descriptor_path = format!("{path}.key.descriptors[{descriptor_index}]");
                self.text(&format!("{descriptor_path}.name"), &descriptor.name);
                self.text(
                    &format!("{descriptor_path}.disambiguator"),
                    &descriptor.disambiguator,
                );
                if descriptor.role == CppDescriptorRole::Callable
                    && (!descriptor
                        .disambiguator
                        .starts_with(CPP_SIGNATURE_DISAMBIGUATOR_PREFIX)
                        || !descriptor
                            .disambiguator
                            .strip_prefix(CPP_SIGNATURE_DISAMBIGUATOR_PREFIX)
                            .is_some_and(is_lower_sha256))
                {
                    self.error(
                        "cpp_portability.callable_disambiguator",
                        format!("{descriptor_path}.disambiguator"),
                        "callable descriptors require cppsig-0.1 plus lowercase SHA-256",
                    );
                }
            }
        }
        for (index, alias) in evidence.type_aliases.iter().enumerate() {
            let path = format!("$.cpp_portability.type_aliases[{index}]");
            if self.validate_references && !symbol_ids.contains(alias.alias.as_str()) {
                self.error(
                    "cpp_portability.unknown_alias",
                    format!("{path}.alias"),
                    "alias must have a portable declaration key",
                );
            }
            self.cpp_type(&format!("{path}.target"), &alias.target, &symbol_ids);
            self.cpp_context_ref(
                &format!("{path}.resolution_context"),
                &alias.resolution_context,
                &contexts,
            );
        }
        let symbol_keys: HashMap<String, &CppPortableSymbolKey> = evidence
            .symbols
            .iter()
            .map(|symbol| (symbol.native_id.clone(), &symbol.key))
            .collect();
        for (index, member) in evidence.special_members.iter().enumerate() {
            let path = format!("$.cpp_portability.special_members[{index}]");
            if self.validate_references
                && (!symbol_ids.contains(member.owner.as_str())
                    || !symbol_ids.contains(member.member.as_str()))
            {
                self.error(
                    "cpp_portability.unknown_special_member",
                    &path,
                    "special member owner and member require portable symbol keys",
                );
            }
            if self.validate_references
                && self.member_owners.get(&member.member) != Some(&member.owner)
            {
                self.error(
                    "cpp_portability.special_member_owner",
                    format!("{path}.member"),
                    "special member must be declared by its exact owner",
                );
            }
            let expected = match member.operation {
                CppSpecialMemberOperation::CopyConstructor => ImplicitOperation::CopyConstructor,
                CppSpecialMemberOperation::CopyAssignment => ImplicitOperation::CopyAssignment,
                CppSpecialMemberOperation::MoveConstructor => ImplicitOperation::MoveConstructor,
            };
            if self.validate_references
                && self
                    .member_operations
                    .get(&member.member)
                    .and_then(Option::as_ref)
                    != Some(&expected)
            {
                self.error(
                    "cpp_portability.special_member_operation",
                    format!("{path}.operation"),
                    "portable special-member operation must match the native declaration",
                );
            }
            if member.signature.owner != member.owner {
                self.error(
                    "cpp_portability.signature_owner",
                    format!("{path}.signature.owner"),
                    "canonical signature owner must match the fact owner",
                );
            }
            let expected_disambiguator = crate::analyzer::semantic_model::csmi::csmi_cpp_signature(
                &member.signature,
                &symbol_keys,
            )
            .and_then(|signature| {
                crate::analyzer::semantic_model::csmi::canonical_digest(&signature).map_err(
                    |error| {
                        crate::analyzer::semantic_model::csmi::CsmiExportError::Canonical(
                            error.to_string(),
                        )
                    },
                )
            })
            .map(|digest| format!("{CPP_SIGNATURE_DISAMBIGUATOR_PREFIX}{digest}"));
            if !expected_disambiguator
                .as_ref()
                .is_ok_and(|expected| expected == &member.member_disambiguator)
            {
                self.error(
                    "cpp_portability.member_disambiguator",
                    format!("{path}.member_disambiguator"),
                    "special member disambiguator must equal the RFC 8785 signature digest",
                );
            }
            if !cpp_signature_matches_operation(member.operation, &member.signature, &member.owner)
            {
                self.error(
                    "cpp_portability.signature_shape",
                    format!("{path}.signature"),
                    "canonical signature shape must match the special-member operation",
                );
            }
            if let Some(receiver) = &member.signature.receiver {
                self.cpp_type(&format!("{path}.signature.receiver"), receiver, &symbol_ids);
            }
            for (parameter_index, parameter) in member.signature.parameters.iter().enumerate() {
                self.cpp_type(
                    &format!("{path}.signature.parameters[{parameter_index}]"),
                    parameter,
                    &symbol_ids,
                );
            }
            if let Some(result) = &member.signature.result {
                self.cpp_type(&format!("{path}.signature.result"), result, &symbol_ids);
            }
            self.cpp_context_ref(
                &format!("{path}.resolution_context"),
                &member.resolution_context,
                &contexts,
            );
        }
    }

    fn cpp_selector(&mut self, path: &str, selector: &CppArtifactSelector) {
        self.text(&format!("{path}.purl"), &selector.purl);
        if !selector.purl.starts_with("pkg:") || !selector.purl.contains('@') {
            self.error(
                "cpp_portability.invalid_purl",
                format!("{path}.purl"),
                "portable C++ artifacts require an exact versioned PURL",
            );
        }
        if selector.digests.is_empty() {
            self.error(
                "cpp_portability.missing_digest",
                format!("{path}.digests"),
                "portable C++ artifacts require SHA-256 bytes",
            );
        }
        for (index, digest) in selector.digests.iter().enumerate() {
            if !is_lower_sha256(&digest.value) {
                self.error(
                    "cpp_portability.invalid_digest",
                    format!("{path}.digests[{index}].value"),
                    "artifact digest must be lowercase SHA-256",
                );
            }
            self.text(
                &format!("{path}.digests[{index}].coverage"),
                &digest.coverage,
            );
        }
    }

    fn cpp_context_ref(
        &mut self,
        path: &str,
        reference: &CppResolutionContextRef,
        contexts: &HashMap<&str, CppLanguage>,
    ) {
        if reference.vocabulary != CPP_RESOLUTION_VOCABULARY
            || reference.version != CPP_RESOLUTION_VERSION
            || reference.language != CppLanguage::Cpp
            || reference.header_closure != CppHeaderClosure::Complete
            || contexts.get(reference.context_digest.as_str()) != Some(&CppLanguage::Cpp)
        {
            self.error(
                "cpp_portability.invalid_context_reference",
                path,
                "C++ facts require an exact complete declared C/C++ resolution context",
            );
        }
    }

    fn cpp_type(&mut self, path: &str, value: &CppCanonicalType, symbols: &HashSet<&str>) {
        let mut stack = vec![(path.to_owned(), value)];
        while let Some((current_path, current)) = stack.pop() {
            match current {
                CppCanonicalType::Fundamental { .. } => {}
                CppCanonicalType::Declared { symbol } => {
                    if !symbols.contains(symbol.as_str()) {
                        self.error(
                            "cpp_portability.unknown_type_symbol",
                            current_path,
                            "canonical declared type is not portable",
                        );
                    }
                }
                CppCanonicalType::TemplateSpecialization { primary, arguments } => {
                    if !symbols.contains(primary.as_str()) {
                        self.error(
                            "cpp_portability.unknown_template_primary",
                            format!("{current_path}.primary"),
                            "canonical template primary is not portable",
                        );
                    }
                    for (index, argument) in arguments.iter().enumerate().rev() {
                        stack.push((format!("{current_path}.arguments[{index}]"), argument));
                    }
                }
                CppCanonicalType::Qualified { qualifiers, r#type } => {
                    if qualifiers.windows(2).any(|pair| pair[0] >= pair[1]) {
                        self.error(
                            "cpp_portability.qualifier_order",
                            format!("{current_path}.qualifiers"),
                            "qualifiers must be unique and ascending",
                        );
                    }
                    stack.push((format!("{current_path}.type"), r#type));
                }
                CppCanonicalType::Reference { referent, .. } => {
                    stack.push((format!("{current_path}.referent"), referent))
                }
            }
        }
    }

    fn assembly_reference(&mut self, path: &str, identity: &AssemblyReference) {
        self.text(&format!("{path}.name"), &identity.name);
        if identity.name.is_empty() {
            self.error(
                "assembly.name",
                format!("{path}.name"),
                "assembly name must not be empty",
            );
        }
        self.text(&format!("{path}.version"), &identity.version);
        if let Some(culture) = &identity.culture {
            self.text(&format!("{path}.culture"), culture);
        }
        if let Some(token) = &identity.public_key_token {
            self.text(&format!("{path}.public_key_token"), token);
        }
        if identity.version_components().is_none() {
            self.error(
                "assembly.version",
                format!("{path}.version"),
                "assembly version must have four unsigned 16-bit parts",
            );
        }
        if identity.public_key_token.as_ref().is_some_and(|token| {
            token.len() != 16
                || !token
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }) {
            self.error(
                "assembly.public_key_token",
                format!("{path}.public_key_token"),
                "public key token must contain sixteen lower-case hexadecimal digits",
            );
        }
    }

    fn payload(&mut self, path: &str, payload: &AuthoredPayload) {
        self.go_current_package = None;
        match payload {
            AuthoredPayload::DeclarationFacts {
                types,
                members,
                relations,
                assembly_identity,
                type_forwards,
            } => {
                if assembly_identity.is_some()
                    && self.predates_schema(ASSEMBLY_IDENTITY_MIN_SCHEMA_VERSION)
                {
                    self.error("schema.assembly_identity_version", format!("{path}.assembly_identity"),
                        format!("assembly identity requires schema version {ASSEMBLY_IDENTITY_MIN_SCHEMA_VERSION}"));
                }
                if !type_forwards.is_empty()
                    && self.predates_schema(TYPE_FORWARDS_MIN_SCHEMA_VERSION)
                {
                    self.error("schema.type_forwards_version", format!("{path}.type_forwards"),
                        format!("type forwards require schema version {TYPE_FORWARDS_MIN_SCHEMA_VERSION}"));
                }
                if let Some(identity) = assembly_identity {
                    self.assembly_reference(&format!("{path}.assembly_identity"), identity);
                }
                let mut forwards = HashMap::new();
                for (index, forward) in type_forwards.iter().enumerate() {
                    let forward_path = format!("{path}.type_forwards[{index}]");
                    self.qualified_name(&format!("{forward_path}.name"), &forward.name);
                    if !forward.namespace.is_empty() {
                        self.qualified_name(
                            &format!("{forward_path}.namespace"),
                            &forward.namespace,
                        );
                    }
                    self.assembly_reference(&format!("{forward_path}.target"), &forward.target);
                    if forwards.insert(&forward.name, forward).is_some() {
                        self.error(
                            "identity.duplicate_type_forward",
                            &forward_path,
                            "forwarded names must be unique",
                        );
                    }
                }
                for (index, forward) in type_forwards.iter().enumerate() {
                    if let Some(outer) = &forward.outer {
                        let valid = forwards.get(outer).is_some_and(|parent| {
                            parent.target == forward.target
                                && parent.namespace == forward.namespace
                                && forward.name.starts_with(&format!("{outer}."))
                        });
                        if !valid {
                            self.error(
                                "reference.type_forward_outer",
                                format!("{path}.type_forwards[{index}].outer"),
                                "outer must name a containing export with the same namespace and target",
                            );
                        }
                    }
                }
                for (index, fact) in types.iter().enumerate() {
                    self.go_current_package = self.go_packages_by_type_id.get(&fact.id).cloned();
                    if fact.callable_surface_complete
                        && self.predates_schema(CALLABLE_SURFACE_MIN_SCHEMA_VERSION)
                    {
                        self.error(
                            "schema.callable_surface_version",
                            format!("{path}.types[{index}].callable_surface_complete"),
                            format!("callable surface coverage requires schema version {CALLABLE_SURFACE_MIN_SCHEMA_VERSION}"),
                        );
                    }
                    let fact_path = format!("{path}.types[{index}]");
                    self.stable_id(&format!("{fact_path}.id"), &fact.id);
                    self.qualified_name(&format!("{fact_path}.name"), &fact.name);
                    self.unique_names(
                        &format!("{fact_path}.type_parameters"),
                        &fact.type_parameters,
                    );
                    let mut constrained_parameters = HashSet::new();
                    for (constraint_index, constraint) in
                        fact.type_parameter_constraints.iter().enumerate()
                    {
                        let constraint_path =
                            format!("{fact_path}.type_parameter_constraints[{constraint_index}]");
                        self.language_identifier(
                            &format!("{constraint_path}.parameter"),
                            &constraint.parameter,
                        );
                        if !fact.type_parameters.contains(&constraint.parameter) {
                            self.error(
                                "reference.unknown_type_parameter",
                                format!("{constraint_path}.parameter"),
                                format!(
                                    "constraint references undeclared type parameter `{}`",
                                    constraint.parameter
                                ),
                            );
                        }
                        if !constrained_parameters.insert(constraint.parameter.clone()) {
                            self.error(
                                "identity.duplicate_type_parameter_constraint",
                                format!("{constraint_path}.parameter"),
                                "type parameter has more than one constraint record",
                            );
                        }
                        self.structured_type_expression(
                            &format!("{constraint_path}.constraint"),
                            &constraint.constraint,
                            &fact.type_parameters,
                        );
                    }
                    if let Some(underlying) = &fact.underlying_type {
                        self.structured_type_expression(
                            &format!("{fact_path}.underlying_type"),
                            underlying,
                            &fact.type_parameters,
                        );
                    }
                    if let Some(value_semantics) = &fact.value_semantics {
                        if value_semantics.copy.is_none()
                            && value_semantics.move_semantics.is_none()
                        {
                            self.error(
                                "declaration.empty_value_semantics",
                                format!("{fact_path}.value_semantics"),
                                "value_semantics must state copy or move behavior",
                            );
                        }
                        if let Some(TypeCopySemantics::ViaMember { member }) = &value_semantics.copy
                        {
                            self.stable_reference(
                                &format!("{fact_path}.value_semantics.copy.member"),
                                member,
                            );
                            if self.validate_references && !self.member_ids.contains(member) {
                                self.error(
                                    "reference.missing_member",
                                    format!("{fact_path}.value_semantics.copy.member"),
                                    format!("unknown member declaration id `{member}`"),
                                );
                            } else if let Some(owner) = self.member_owners.get(member)
                                && owner != &fact.id
                            {
                                self.error(
                                        "reference.member_owner_mismatch",
                                        format!("{fact_path}.value_semantics.copy.member"),
                                        format!("copy member `{member}` is owned by `{owner}`, not type `{}`", fact.id),
                                    );
                            } else if self.validate_references
                                && !matches!(
                                    self.member_operations.get(member),
                                    Some(Some(ImplicitOperation::CopyConstructor))
                                )
                            {
                                self.error(
                                        "reference.copy_member_role_mismatch",
                                        format!("{fact_path}.value_semantics.copy.member"),
                                        format!(
                                            "copy member `{member}` must carry the copy_constructor implicit-operation role"
                                        ),
                                    );
                            }
                        }
                    }
                    if fact.ambient_use.is_some() {
                        self.ambient_use_version(&fact_path);
                    }
                    for (embedded_index, embedded) in fact.embedded_types.iter().enumerate() {
                        self.type_ref(
                            &format!("{fact_path}.embedded_types[{embedded_index}].target"),
                            &embedded.target,
                            &fact.type_parameters,
                        );
                    }
                    for (type_index, hierarchy) in fact.hierarchy.iter().enumerate() {
                        let hierarchy_target_path =
                            format!("{fact_path}.hierarchy[{type_index}].target");
                        if hierarchy.target.contains_unknown() {
                            self.error(
                                "hierarchy.unknown_target",
                                &hierarchy_target_path,
                                "hierarchy relations require a concrete target type",
                            );
                        }
                        self.type_ref(
                            &hierarchy_target_path,
                            &hierarchy.target,
                            &fact.type_parameters,
                        );
                    }
                    if !fact.type_parameter_defaults.is_empty()
                        || !fact.implemented_traits.is_empty()
                        || !fact.generic_trait_impls.is_empty()
                    {
                        self.rust_contract_version(&fact_path);
                    }
                    if fact.implemented_traits_complete || fact.generic_trait_impls_complete {
                        if self.predates_schema(19) {
                            self.error(
                                "declaration.impl_inventory_schema_version",
                                &fact_path,
                                "implementation inventories require schema version 19",
                            );
                        }
                        self.rust_contract_version(&fact_path);
                        if fact.generic_trait_impls_complete && fact.type_kind != TypeKind::Trait {
                            self.error(
                                "declaration.generic_impl_owner",
                                &fact_path,
                                "generic rule inventory must be owned by a trait",
                            );
                        }
                    }
                    let mut parameters = fact.type_parameters.clone();
                    parameters.push("Self".to_owned());
                    if !fact.type_parameter_defaults.is_empty()
                        && fact.type_parameter_defaults.len() != fact.type_parameters.len()
                    {
                        self.error(
                            "declaration.generic_default_arity",
                            &fact_path,
                            "generic defaults must be parallel to type_parameters",
                        );
                    }
                    for (index, default) in fact.type_parameter_defaults.iter().enumerate() {
                        let default_path = format!("{fact_path}.type_parameter_defaults[{index}]");
                        match default {
                            Some(GenericParameterDefault::Type { r#type }) => {
                                self.type_ref(&default_path, r#type, &parameters)
                            }
                            Some(GenericParameterDefault::Const { value }) => {
                                self.text(&default_path, value)
                            }
                            None => {}
                        }
                    }
                    for (index, implementation) in fact.implemented_traits.iter().enumerate() {
                        self.implemented_trait(
                            &format!("{fact_path}.implemented_traits[{index}]"),
                            implementation,
                            &parameters,
                        );
                    }
                    for (index, implementation) in fact.generic_trait_impls.iter().enumerate() {
                        let impl_path = format!("{fact_path}.generic_trait_impls[{index}]");
                        if fact.type_kind != TypeKind::Trait {
                            self.error(
                                "declaration.generic_impl_owner",
                                &impl_path,
                                "generic trait impls must be owned by the implemented trait",
                            );
                        }
                        self.unique_names(
                            &format!("{impl_path}.type_parameters"),
                            &implementation.type_parameters,
                        );
                        let mut implicit_self = false;
                        let mut references = vec![&implementation.implementation.trait_type];
                        references.extend(
                            implementation
                                .implementation
                                .associated_types
                                .iter()
                                .map(|binding| &binding.r#type),
                        );
                        for bound in &implementation.bounds {
                            references.extend([&bound.subject, &bound.bound.trait_type]);
                            references.extend(
                                bound
                                    .bound
                                    .associated_types
                                    .iter()
                                    .map(|binding| &binding.r#type),
                            );
                        }
                        let mut patterns = vec![&implementation.self_pattern];
                        while let Some(pattern) = patterns.pop() {
                            match pattern {
                                RustSelfPattern::Parameter { name } => {
                                    implicit_self |= name == "Self"
                                }
                                RustSelfPattern::Reference { inner, .. } => patterns.push(inner),
                                RustSelfPattern::Constructor { owner, arguments } => {
                                    references.push(owner);
                                    patterns.extend(arguments);
                                }
                            }
                        }
                        crate::analyzer::semantic::common::visit_type_refs(references, |ty| {
                            implicit_self |=
                                matches!(ty, TypeRef::TypeParameter { name } if name == "Self");
                        });
                        if implicit_self && self.predates_schema(19) {
                            self.error(
                                "declaration.impl_self_schema_version",
                                &impl_path,
                                "implicit Self in generic implementation rules requires schema 19",
                            );
                        }
                        // Rust's implicit Self names this rule's instantiated
                        // self pattern, independently of its explicit binders.
                        let mut impl_parameters = implementation.type_parameters.clone();
                        impl_parameters.push("Self".to_owned());
                        self.rust_self_pattern(
                            &impl_path,
                            &implementation.self_pattern,
                            &impl_parameters,
                        );
                        for bound in &implementation.bounds {
                            self.type_ref(&impl_path, &bound.subject, &impl_parameters);
                            self.implemented_trait(&impl_path, &bound.bound, &impl_parameters);
                        }
                        self.implemented_trait(
                            &impl_path,
                            &implementation.implementation,
                            &impl_parameters,
                        );
                    }
                    if let Some(bases) = &fact.runtime_bases {
                        let bases_path = format!("{fact_path}.runtime_bases");
                        if self.predates_schema(RUNTIME_BASES_MIN_SCHEMA_VERSION) {
                            self.error("declaration.runtime_bases_schema_version", &bases_path,
                                format!("runtime_bases requires schema version {RUNTIME_BASES_MIN_SCHEMA_VERSION}"));
                        }
                        if self.language != "python" || fact.type_kind != TypeKind::Class {
                            self.error(
                                "declaration.runtime_bases_owner",
                                &bases_path,
                                "runtime_bases is only valid on Python class facts",
                            );
                        }
                        for (base_index, base) in bases.iter().enumerate() {
                            let base_path = format!("{bases_path}[{base_index}]");
                            self.type_ref(&base_path, base, &[]);
                            let known_non_class = match base {
                                TypeRef::Named {
                                    name,
                                    arguments,
                                    nullable: false,
                                } if arguments.is_empty() => self
                                    .type_kinds_by_name
                                    .get(name)
                                    .copied()
                                    .flatten()
                                    .is_some_and(|kind| kind != TypeKind::Class),
                                TypeRef::Declared {
                                    id,
                                    arguments,
                                    nullable: false,
                                } if arguments.is_empty() => {
                                    self.type_kinds_by_id.get(id).map_or_else(
                                        || self.declaration_ids.contains(id),
                                        |kind| *kind != TypeKind::Class,
                                    )
                                }
                                _ => {
                                    self.error("declaration.runtime_base_shape", &base_path,
                                        "runtime bases require non-nullable, non-parameterized named or declared class references");
                                    continue;
                                }
                            };
                            // Only a unique local declaration is known here. Missing or
                            // ambiguous active named targets remain a query-time boundary.
                            if known_non_class {
                                self.error(
                                    "declaration.runtime_base_non_class",
                                    base_path,
                                    "runtime base refers to a non-class declaration",
                                );
                            }
                        }
                    }
                    for (alias_index, alias) in fact.aliases.iter().enumerate() {
                        self.qualified_name(&format!("{fact_path}.aliases[{alias_index}]"), alias);
                    }
                    for (surface_index, surface) in fact.extension_surfaces.iter().enumerate() {
                        self.qualified_name(
                            &format!("{fact_path}.extension_surfaces[{surface_index}]"),
                            surface,
                        );
                    }
                    self.declaration_guard(&fact_path, fact.guard.as_ref());
                    self.locator(&format!("{fact_path}.locator"), &fact.locator);
                }
                for (index, fact) in members.iter().enumerate() {
                    self.go_current_package = self.go_packages_by_type_id.get(&fact.owner).cloned();
                    let fact_path = format!("{path}.members[{index}]");
                    if fact.implemented_trait.is_some() || fact.self_form.is_some() {
                        self.rust_contract_version(&fact_path);
                        let mut parameters = self
                            .type_parameters_by_id
                            .get(&fact.owner)
                            .cloned()
                            .unwrap_or_default();
                        parameters.push("Self".to_owned());
                        if let Some(trait_type) = &fact.implemented_trait {
                            self.type_ref(&fact_path, trait_type, &parameters);
                        }
                        if let Some(RustSelfForm::Other { pattern }) = &fact.self_form {
                            self.rust_self_pattern(&fact_path, pattern, &parameters);
                        }
                    }
                    if fact.non_overridable.is_some()
                        && (self.language != "java"
                            || fact.member_kind != MemberKind::Method
                            || fact.is_static
                            || fact.is_virtual
                            || fact.is_abstract)
                    {
                        self.error("declaration.non_overridable", format!("{fact_path}.non_overridable"), "Java final-method evidence requires a non-static, non-abstract Java method with non-virtual declaration metadata");
                    }
                    self.stable_id(&format!("{fact_path}.id"), &fact.id);
                    self.language_identifier(&format!("{fact_path}.name"), &fact.name);
                    self.locator(&format!("{fact_path}.locator"), &fact.locator);
                    if fact.proxied_type.is_some() && fact.value_type.is_none() {
                        self.error(
                            "declaration.proxied_type_without_value_type",
                            format!("{fact_path}.proxied_type"),
                            "a proxied module value type requires its declared value type",
                        );
                    }
                    for (field_name, declared_type) in [
                        ("value_type", fact.value_type.as_ref()),
                        ("proxied_type", fact.proxied_type.as_ref()),
                    ] {
                        let Some(declared_type) = declared_type else {
                            continue;
                        };
                        let type_path = format!("{fact_path}.{field_name}");
                        if self.predates_schema(TYPED_VALUES_AND_PARAMETER_ROLES_MIN_SCHEMA_VERSION)
                        {
                            self.error(
                                "declaration.module_value_type_schema_version",
                                &type_path,
                                format!(
                                    "declared module value types require schema version {TYPED_VALUES_AND_PARAMETER_ROLES_MIN_SCHEMA_VERSION}"
                                ),
                            );
                        }
                        if fact.member_kind != MemberKind::Field {
                            self.error(
                                "declaration.module_value_type_requires_field",
                                &type_path,
                                "declared module value types are valid only on field facts",
                            );
                        }
                        let is_class_type = match declared_type {
                            TypeRef::Named {
                                arguments,
                                nullable,
                                ..
                            }
                            | TypeRef::Declared {
                                arguments,
                                nullable,
                                ..
                            } => arguments.is_empty() && !nullable,
                            _ => false,
                        };
                        if !is_class_type {
                            self.error(
                                "declaration.module_value_type_shape",
                                &type_path,
                                "declared module value types must name one non-null class without type arguments",
                            );
                        }
                        let owner_parameters = self
                            .type_parameters_by_id
                            .get(&fact.owner)
                            .cloned()
                            .unwrap_or_default();
                        self.type_ref(&type_path, declared_type, &owner_parameters);
                    }
                    if fact.ambient_use.is_some() {
                        self.ambient_use_version(&fact_path);
                    }
                    if let Some(operation) = &fact.implicit_operation {
                        match operation {
                            ImplicitOperation::CopyConstructor
                            | ImplicitOperation::MoveConstructor
                            | ImplicitOperation::ValuePreservingConstructor
                                if !matches!(fact.member_kind, MemberKind::Constructor) =>
                            {
                                self.error(
                                    "declaration.implicit_operation_requires_constructor",
                                    format!("{fact_path}.implicit_operation"),
                                    "constructor value-operation roles require member_kind: constructor",
                                );
                            }
                            ImplicitOperation::CopyAssignment
                            | ImplicitOperation::MoveAssignment
                                if !matches!(fact.member_kind, MemberKind::Method) =>
                            {
                                self.error(
                                    "declaration.implicit_assignment_requires_method",
                                    format!("{fact_path}.implicit_operation"),
                                    "copy and move assignment roles require member_kind: method",
                                );
                            }
                            ImplicitOperation::ConversionOperator { target } => {
                                if !matches!(fact.member_kind, MemberKind::Method) {
                                    self.error(
                                        "declaration.implicit_conversion_requires_method",
                                        format!("{fact_path}.implicit_operation"),
                                        "conversion operator role requires member_kind: method",
                                    );
                                }
                                let owner_parameters = self
                                    .type_parameters_by_id
                                    .get(&fact.owner)
                                    .cloned()
                                    .unwrap_or_default();
                                self.type_ref(
                                    &format!("{fact_path}.implicit_operation.target"),
                                    target,
                                    &owner_parameters,
                                );
                            }
                            _ => {}
                        }
                    }
                    if let Some(operation) = fact.explicit_operation {
                        if !matches!(fact.member_kind, MemberKind::Method) {
                            self.error(
                                "declaration.explicit_operation_requires_method",
                                format!("{fact_path}.explicit_operation"),
                                "an explicitly written value-operation role requires member_kind: method",
                            );
                        }
                        // A consumer selects the role by the argument count the
                        // source writes, so the role and the declared shape have
                        // to agree here rather than at every call site.
                        let expected_parameters = match operation {
                            ExplicitValueOperation::ReceiverAssign
                            | ExplicitValueOperation::ReceiverExtend
                            | ExplicitValueOperation::ArgumentExpiringCast => 1,
                            ExplicitValueOperation::ReceiverProjection => 0,
                        };
                        match fact.signature.as_ref() {
                            None => self.error(
                                "declaration.explicit_operation_requires_signature",
                                format!("{fact_path}.explicit_operation"),
                                "an explicitly written value-operation role requires a signature so a consumer can match the written argument count",
                            ),
                            Some(signature) if signature.parameters.len() != expected_parameters => {
                                self.error(
                                    "declaration.explicit_operation_parameter_count",
                                    format!("{fact_path}.explicit_operation"),
                                    format!(
                                        "the `{}` role describes a member with {expected_parameters} parameter(s), not {}",
                                        operation.label(),
                                        signature.parameters.len()
                                    ),
                                );
                            }
                            Some(_) => {}
                        }
                    }
                    if fact.callable_family_complete {
                        if !matches!(
                            fact.member_kind,
                            MemberKind::Constructor | MemberKind::Method | MemberKind::Function
                        ) {
                            self.error(
                                "declaration.callable_family_complete_on_non_callable",
                                format!("{fact_path}.callable_family_complete"),
                                "callable_family_complete requires a constructor, method, or function",
                            );
                        }
                        if fact.signature.is_none() {
                            self.error(
                                "declaration.callable_family_complete_without_signature",
                                format!("{fact_path}.callable_family_complete"),
                                "callable_family_complete requires a structured signature",
                            );
                        }
                    }
                    if !fact.exact_return_classes.is_empty() {
                        if self.predates_schema(EXACT_RETURN_CLASSES_MIN_SCHEMA_VERSION) {
                            self.error(
                                "declaration.exact_return_classes_schema_version",
                                format!("{fact_path}.exact_return_classes"),
                                format!(
                                    "exact runtime return-class sets require schema version {EXACT_RETURN_CLASSES_MIN_SCHEMA_VERSION}"
                                ),
                            );
                        }
                        let mut class_identities = HashSet::new();
                        let mut valid_classes = true;
                        for (class_index, class) in fact.exact_return_classes.iter().enumerate() {
                            self.type_ref(
                                &format!("{fact_path}.exact_return_classes[{class_index}]"),
                                class,
                                &[],
                            );
                            let identity = match class {
                                TypeRef::Named {
                                    name,
                                    nullable: false,
                                    ..
                                } if !name.is_empty() => format!("named:{name}"),
                                TypeRef::Declared {
                                    id,
                                    nullable: false,
                                    ..
                                } if self.type_ids.contains(id) => format!("declared:{id}"),
                                _ => {
                                    valid_classes = false;
                                    continue;
                                }
                            };
                            if !class_identities.insert(identity) {
                                self.error(
                                    "declaration.exact_return_classes_duplicate",
                                    format!("{fact_path}.exact_return_classes[{class_index}]"),
                                    "exact_return_classes cannot repeat a runtime class",
                                );
                                valid_classes = false;
                            }
                        }
                        if !matches!(
                            fact.member_kind,
                            MemberKind::Constructor
                                | MemberKind::Method
                                | MemberKind::Function
                                | MemberKind::Static
                                | MemberKind::Property
                        ) || fact.signature.is_none()
                            || !valid_classes
                        {
                            self.error(
                                "declaration.exact_return_classes",
                                format!("{fact_path}.exact_return_classes"),
                                "exact_return_classes requires a callable signature and a non-empty set of unique, non-null nominal classes",
                            );
                        }
                    }
                    if let Some(signature) = &fact.signature {
                        let owner_parameters = self
                            .type_parameters_by_id
                            .get(&fact.owner)
                            .cloned()
                            .unwrap_or_default();
                        self.signature(
                            &format!("{fact_path}.signature"),
                            signature,
                            &owner_parameters,
                        );
                    }
                    for (alias_index, alias) in fact.aliases.iter().enumerate() {
                        self.qualified_name(&format!("{fact_path}.aliases[{alias_index}]"), alias);
                    }
                    self.declaration_guard(&fact_path, fact.guard.as_ref());
                }
                for (index, relation) in relations.iter().enumerate() {
                    self.stable_id(&format!("{path}.relations[{index}].id"), &relation.id);
                }
                for (index, fact) in members.iter().enumerate() {
                    self.stable_reference(&format!("{path}.members[{index}].owner"), &fact.owner);
                    if self.validate_references && !self.declaration_ids.contains(&fact.owner) {
                        self.error(
                            "reference.missing_owner",
                            format!("{path}.members[{index}].owner"),
                            format!("unknown declaration id `{}`", fact.owner),
                        );
                    }
                }
                for (index, relation) in relations.iter().enumerate() {
                    for (field, target) in [("from", &relation.from), ("to", &relation.to)] {
                        self.stable_reference(
                            &format!("{path}.relations[{index}].{field}"),
                            target,
                        );
                        if self.validate_references && !self.declaration_ids.contains(target) {
                            self.error(
                                "reference.missing_declaration",
                                format!("{path}.relations[{index}].{field}"),
                                format!("unknown declaration id `{target}`"),
                            );
                        }
                    }
                }
            }
            AuthoredPayload::GeneratorRules { rules } => {
                for (index, rule) in rules.iter().enumerate() {
                    self.rule(&format!("{path}.rules[{index}]"), rule);
                }
            }
            AuthoredPayload::ProcedureSummaries { summaries } => {
                for (index, summary) in summaries.iter().enumerate() {
                    self.procedure_summary(&format!("{path}.summaries[{index}]"), summary);
                }
            }
        }
    }

    fn collection_flows(&mut self, path: &str, payload: &CollectionFlowsPayload) {
        let mut callables = HashSet::new();
        for (index, flow) in payload.flows.iter().enumerate() {
            let current = format!("{path}.flows[{index}]");
            self.stable_reference(&format!("{current}.callable"), &flow.callable);
            if !callables.insert(flow.callable.as_str()) {
                self.error(
                    "collection_flow.duplicate_callable",
                    &current,
                    "collection-flow payload contains duplicate callable facts",
                );
            }
            if flow.payload.kind
                != crate::analyzer::semantic_model::csmi::CsmiCollectionFlowKind::CollectionFlow
            {
                self.error(
                    "collection_flow.kind",
                    format!("{current}.payload.kind"),
                    "collection-flow payload kind must be collection-flow",
                );
            }
            if flow.payload.callable != flow.callable {
                self.error(
                    "collection_flow.callable_scope",
                    format!("{current}.payload.callable"),
                    "payload callable must equal its native fact scope",
                );
            }
        }
    }

    fn deferred_yields(&mut self, path: &str, payload: &DeferredYieldsPayload) {
        for (index, fact) in payload.yields.iter().enumerate() {
            let current = format!("{path}.yields[{index}]");
            if fact.payload.factory != fact.factory
                || fact.payload.resume != fact.resume
                || fact.payload.handle_type != fact.handle_type
            {
                self.error(
                    "deferred_yield.scope",
                    &current,
                    "payload identities must equal the native fact scope",
                );
            }
        }
    }

    fn runtime_values(
        &mut self,
        path: &str,
        payload: &RuntimeValuesPayload,
        activation: &[ActivationSelector],
    ) {
        let mut exposure_ids = HashSet::new();
        for (index, exposure) in payload.exposures.iter().enumerate() {
            let current = format!("{path}.exposures[{index}]");
            self.stable_reference(&format!("{current}.exposure_id"), &exposure.exposure_id);
            if !exposure_ids.insert(exposure.exposure_id.as_str()) {
                self.error(
                    "runtime.duplicate_exposure",
                    &current,
                    "duplicate exposure id",
                );
            }
            if exposure.languages.is_empty() || exposure.members.is_empty() {
                self.error(
                    "runtime.exposure_shape",
                    &current,
                    "runtime exposure requires languages and members",
                );
            }
            self.unique_names(&format!("{current}.languages"), &exposure.languages);
            self.stable_component(&format!("{current}.binding_name"), &exposure.binding_name);
            self.runtime_applicability(&format!("{current}.runtime"), &exposure.runtime);
            self.runtime_digest(
                &format!("{current}.runtime_profile_digest"),
                &exposure.runtime_profile_digest,
            );
            if !activation.iter().any(|selector| {
                runtime_artifact_matches_selector(&exposure.runtime, selector)
                    && selector
                        .configurations
                        .contains(&exposure.runtime_profile_digest)
            }) {
                self.error(
                    "runtime.activation_profile_unbound",
                    &current,
                    "runtime artifact, digest, and profile digest must be bound by one activation selector",
                );
            }
            self.runtime_root_identity(
                &format!("{current}.root_identity"),
                &exposure.root_identity,
                &exposure.runtime.runtime_family,
                &exposure.binding_name,
            );
            self.runtime_unique_references(&format!("{current}.members"), &exposure.members);
            self.runtime_evidence(&format!("{current}.evidence"), &exposure.evidence);
            self.runtime_extensions(&format!("{current}.extensions"), &exposure.extensions);
            self.runtime_coverage(&format!("{current}.coverage"), &exposure.coverage);
        }
        let exposures: HashMap<&str, &RuntimeGlobalExposure> = payload
            .exposures
            .iter()
            .map(|record| (record.exposure_id.as_str(), record.as_ref()))
            .collect();
        let mut behavior_ids = HashSet::new();
        for (index, behavior) in payload.behaviors.iter().enumerate() {
            let current = format!("{path}.behaviors[{index}]");
            self.stable_reference(&format!("{current}.behavior_id"), &behavior.behavior_id);
            if !behavior_ids.insert(behavior.behavior_id.as_str()) {
                self.error(
                    "runtime.duplicate_behavior",
                    &current,
                    "duplicate behavior id",
                );
            }
            let exposure = exposures.get(behavior.exposure_id.as_str()).copied();
            if self.validate_references && exposure.is_none() {
                self.error(
                    "runtime.unknown_exposure",
                    format!("{current}.exposure_id"),
                    "behavior references an unknown exposure",
                );
            }
            if let Some(exposure) = exposure
                && !exposure
                    .members
                    .iter()
                    .any(|member| member == &behavior.container_member)
            {
                self.error(
                    "runtime.unknown_container_member",
                    format!("{current}.container_member"),
                    "behavior container member is not published by its exposure",
                );
            }
            self.stable_reference(&format!("{current}.exposure_id"), &behavior.exposure_id);
            self.stable_reference(
                &format!("{current}.container_member"),
                &behavior.container_member,
            );
            self.runtime_evidence(&format!("{current}.evidence"), &behavior.evidence);
            self.runtime_extensions(&format!("{current}.extensions"), &behavior.extensions);
            if behavior.coverage.status == RuntimeCoverageStatus::Complete
                && (behavior.exception_behavior == RuntimeExceptionBehavior::Unknown
                    || behavior.mutation_model == RuntimeMutationModel::Unknown
                    || behavior.materialization == RuntimeMaterialization::Unknown)
            {
                self.error(
                    "runtime.complete_behavior_unknown",
                    &current,
                    "complete behavior requires interpreted exception, mutation, and materialization semantics",
                );
            }
            self.runtime_coverage(&format!("{current}.coverage"), &behavior.coverage);
        }
        let mut enabled_exposure_ids = payload
            .exposures
            .iter()
            .filter(|exposure| exposure.activation == RuntimeExposureActivation::Enabled)
            .map(|exposure| exposure.exposure_id.clone())
            .collect::<Vec<_>>();
        enabled_exposure_ids.sort_unstable();
        let expected_active_set_digest = runtime_active_set_digest(&enabled_exposure_ids);
        for (index, evidence) in payload.binding_evidence.iter().enumerate() {
            let current = format!("{path}.binding_evidence[{index}]");
            self.stable_reference(
                &format!("{current}.binding_evidence_id"),
                &evidence.binding_evidence_id,
            );
            if !payload
                .binding_evidence
                .iter()
                .take(index)
                .all(|previous| previous.binding_evidence_id != evidence.binding_evidence_id)
            {
                self.error(
                    "runtime.duplicate_binding_evidence",
                    &current,
                    "duplicate binding evidence id",
                );
            }
            let exposure = exposures.get(evidence.exposure_id.as_str()).copied();
            if self.validate_references && exposure.is_none() {
                self.error(
                    "runtime.unknown_exposure",
                    format!("{current}.exposure_id"),
                    "binding evidence references an unknown exposure",
                );
            }
            self.stable_reference(&format!("{current}.exposure_id"), &evidence.exposure_id);
            self.runtime_activation(
                &format!("{current}.activation"),
                &evidence.activation,
                exposure,
                &enabled_exposure_ids,
                &expected_active_set_digest,
            );
            self.text(&format!("{current}.language"), &evidence.language);
            self.text(&format!("{current}.dialect"), &evidence.dialect);
            self.runtime_source_range(
                &format!("{current}.root_occurrence"),
                &evidence.root_occurrence,
            );
            self.runtime_identity(
                &format!("{current}.scope_identity"),
                &evidence.scope_identity,
                RuntimeIdentityKind::Scope,
            );
            self.runtime_evidence(&format!("{current}.evidence"), &evidence.evidence);
            self.runtime_extensions(&format!("{current}.extensions"), &evidence.extensions);
            if evidence.coverage.status == RuntimeCoverageStatus::Complete
                && !(evidence.activation.outcome == RuntimeActivationOutcome::Matched
                    && evidence.lexical_binding == RuntimeLexicalBinding::Absent
                    && evidence.rebinding == RuntimeRebinding::Excluded)
                && !(evidence.activation.outcome == RuntimeActivationOutcome::NotMatched
                    && evidence.lexical_binding == RuntimeLexicalBinding::Present)
            {
                self.error(
                    "runtime.complete_binding_proof",
                    &current,
                    "complete binding evidence requires a matched global or conclusive lexical exclusion",
                );
            }
            self.runtime_coverage(&format!("{current}.coverage"), &evidence.coverage);
        }
        let behaviors: HashSet<&str> = payload
            .behaviors
            .iter()
            .map(|record| record.behavior_id.as_str())
            .collect();
        let binding: HashSet<&str> = payload
            .binding_evidence
            .iter()
            .map(|record| record.binding_evidence_id.as_str())
            .collect();
        for (index, observation) in payload.observations.iter().enumerate() {
            let current = format!("{path}.observations[{index}]");
            self.stable_reference(
                &format!("{current}.observation_id"),
                &observation.observation_id,
            );
            if !payload
                .observations
                .iter()
                .take(index)
                .all(|previous| previous.observation_id != observation.observation_id)
            {
                self.error(
                    "runtime.duplicate_observation",
                    &current,
                    "duplicate observation id",
                );
            }
            if self.validate_references && !behaviors.contains(observation.behavior_id.as_str()) {
                self.error(
                    "runtime.unknown_behavior",
                    format!("{current}.behavior_id"),
                    "observation references an unknown behavior",
                );
            }
            if self.validate_references
                && !binding.contains(observation.binding_evidence_id.as_str())
            {
                self.error(
                    "runtime.unknown_binding_evidence",
                    format!("{current}.binding_evidence_id"),
                    "observation references unknown binding evidence",
                );
            }
            self.stable_reference(&format!("{current}.behavior_id"), &observation.behavior_id);
            self.stable_reference(
                &format!("{current}.binding_evidence_id"),
                &observation.binding_evidence_id,
            );
            let binding_record = payload
                .binding_evidence
                .iter()
                .find(|binding| binding.binding_evidence_id == observation.binding_evidence_id);
            let behavior_record = payload
                .behaviors
                .iter()
                .find(|behavior| behavior.behavior_id == observation.behavior_id);
            if let (Some(binding), Some(behavior)) = (binding_record, behavior_record) {
                if binding.exposure_id != behavior.exposure_id {
                    self.error(
                        "runtime.observation_exposure",
                        &current,
                        "observation binding and behavior must resolve in one exposure",
                    );
                }
                if let Some(exposure) = exposures.get(binding.exposure_id.as_str())
                    && behavior.container_member.is_empty()
                {
                    self.error(
                        "runtime.empty_container_member",
                        &current,
                        format!(
                            "exposure {} has an empty behavior container member",
                            exposure.exposure_id
                        ),
                    );
                }
                if binding.activation.runtime_profile_digest
                    != exposures
                        .get(binding.exposure_id.as_str())
                        .map_or("", |exposure| exposure.runtime_profile_digest.as_str())
                {
                    self.error(
                        "runtime.activation_profile_mismatch",
                        &current,
                        "binding activation profile must match the exposure profile",
                    );
                }
                if observation.source_origin == RuntimeSourceOrigin::PristineRuntimeInput
                    && (behavior.mutation_model != RuntimeMutationModel::PristineInputUntilWrite
                        || binding.rebinding != RuntimeRebinding::Excluded
                        || binding.coverage.status != RuntimeCoverageStatus::Complete)
                {
                    self.error(
                        "runtime.pristine_origin_without_proof",
                        &current,
                        "pristine origin requires complete binding and mutation proof",
                    );
                }
                if observation.coverage.status == RuntimeCoverageStatus::Complete
                    && behavior.coverage.status != RuntimeCoverageStatus::Complete
                {
                    self.error(
                        "runtime.complete_observation_without_behavior",
                        &current,
                        "complete observation requires complete behavior coverage",
                    );
                }
            }
            self.runtime_identity(
                &format!("{current}.base_value"),
                &observation.base_value,
                RuntimeIdentityKind::Value,
            );
            self.runtime_identity(
                &format!("{current}.load_operation"),
                &observation.load_operation,
                RuntimeIdentityKind::Operation,
            );
            self.runtime_identity(
                &format!("{current}.result_value"),
                &observation.result_value,
                RuntimeIdentityKind::Value,
            );
            self.runtime_identity(
                &format!("{current}.observation_point"),
                &observation.observation_point,
                RuntimeIdentityKind::Point,
            );
            self.runtime_source_range(&format!("{current}.expression"), &observation.expression);
            if observation.expression.resource_digest
                != binding_record.map_or("", |binding| {
                    binding.root_occurrence.resource_digest.as_str()
                })
            {
                self.error(
                    "runtime.observation_source_mismatch",
                    &current,
                    "observation expression must use the binding source artifact",
                );
            }
            match (&observation.key, observation.source_form) {
                (
                    RuntimeStaticKey::Property { value },
                    RuntimeSourceForm::Dot | RuntimeSourceForm::BracketString,
                ) => {
                    self.text(&format!("{current}.key.value"), value);
                }
                (RuntimeStaticKey::Index { .. }, RuntimeSourceForm::BracketNumber) => {}
                _ => self.error(
                    "runtime.key_form_mismatch",
                    format!("{current}.key"),
                    "source form must agree with the static key kind",
                ),
            }
            if observation.normal_outcome == RuntimeNormalOutcome::Exact
                && observation.phase != RuntimeObservationPhase::AfterEffects
            {
                self.error(
                    "runtime.exact_before_effects",
                    format!("{current}.phase"),
                    "an exact normal load result must be observed after effects",
                );
            }
            if observation.coverage.status == RuntimeCoverageStatus::Complete
                && (observation.normal_outcome != RuntimeNormalOutcome::Exact
                    || !matches!(
                        observation.exception_outcome,
                        RuntimeExceptionOutcome::Excluded | RuntimeExceptionOutcome::Possible
                    )
                    || observation.source_origin == RuntimeSourceOrigin::Indeterminate)
            {
                self.error(
                    "runtime.complete_observation_outcomes",
                    &current,
                    "complete observation requires exact normal, interpreted exceptional, and determined origin outcomes",
                );
            }
            self.runtime_evidence(&format!("{current}.evidence"), &observation.evidence);
            self.runtime_extensions(&format!("{current}.extensions"), &observation.extensions);
            self.runtime_coverage(&format!("{current}.coverage"), &observation.coverage);
        }
    }

    fn runtime_contracts(
        &mut self,
        path: &str,
        payload: &RuntimeContractsPayload,
        activation: &[ActivationSelector],
    ) {
        if self.predates_schema(RUNTIME_CONTRACTS_MIN_SCHEMA_VERSION) {
            self.error(
                "runtime_contracts.schema_version",
                path,
                format!(
                    "runtime-contracts 0.2 requires schema version at least {RUNTIME_CONTRACTS_MIN_SCHEMA_VERSION}"
                ),
            );
        }
        if payload.envelope.is_none() {
            self.error(
                "runtime_contracts.envelope_missing",
                path,
                "runtime-contracts 0.2 requires the retained CSMI semantic-model envelope",
            );
        }
        if payload.payload.is_empty() {
            self.error(
                "runtime_contracts.empty",
                path,
                "runtime-contracts payload must contain at least one record",
            );
        }
        let expected = payload
            .payload
            .contracts
            .iter()
            .flat_map(|record| record.definition.applicability.selectors.iter())
            .count();
        if expected > 0 && activation.is_empty() {
            self.error(
                "runtime_contracts.activation_missing",
                path,
                "runtime-contracts facts require shard activation selectors",
            );
        }
    }

    fn runtime_applicability(&mut self, path: &str, runtime: &RuntimeApplicability) {
        for (field, value) in [
            ("runtime_family", runtime.runtime_family.as_str()),
            ("realm", runtime.realm.as_str()),
            (
                "initialization_boundary",
                runtime.initialization_boundary.as_str(),
            ),
        ] {
            self.text(&format!("{path}.{field}"), value);
        }
        if let Some(module_mode) = &runtime.module_mode {
            self.text(&format!("{path}.module_mode"), module_mode);
        }
        // An artifact claim is all-or-nothing: a record that names one must
        // name its digest too, so an activation selector can bind both.
        match (&runtime.runtime_artifact, &runtime.runtime_artifact_digest) {
            (Some(artifact), Some(digest)) => {
                self.text(&format!("{path}.runtime_artifact"), artifact);
                if !artifact.starts_with("pkg:")
                    || artifact
                        .split_once('@')
                        .is_none_or(|(_, version)| version.is_empty())
                {
                    self.error(
                        "runtime.invalid_artifact",
                        format!("{path}.runtime_artifact"),
                        "runtime artifact must be an exact versioned PURL",
                    );
                }
                self.runtime_digest(&format!("{path}.runtime_artifact_digest"), digest);
            }
            (None, None) => {}
            _ => self.error(
                "runtime.invalid_artifact",
                format!("{path}.runtime_artifact"),
                "a runtime artifact and its digest must be declared together",
            ),
        }
        if let Some(platform) = &runtime.platform {
            self.text(&format!("{path}.platform"), platform);
        }
        if let Some(architecture) = &runtime.architecture {
            self.text(&format!("{path}.architecture"), architecture);
        }
        for (index, assumption) in runtime.host_assumptions.iter().enumerate() {
            self.text(&format!("{path}.host_assumptions[{index}]"), assumption);
        }
        let mut assumptions = HashSet::new();
        for (index, assumption) in runtime.host_assumptions.iter().enumerate() {
            if !assumptions.insert(assumption) {
                self.error(
                    "runtime.duplicate_host_assumption",
                    format!("{path}.host_assumptions[{index}]"),
                    "host assumptions must be unique",
                );
            }
        }
    }

    fn runtime_root_identity(
        &mut self,
        path: &str,
        identity: &RuntimeRootIdentity,
        runtime_family: &str,
        binding_name: &str,
    ) {
        self.text(&format!("{path}.scheme"), &identity.scheme);
        self.text(&format!("{path}.scheme_version"), &identity.scheme_version);
        if identity.scheme != "csmi.runtime-global" || identity.scheme_version != "0.1.0" {
            self.error(
                "runtime.root_identity_scheme",
                path,
                "runtime root identity must use csmi.runtime-global 0.1.0",
            );
        }
        if identity.descriptors.len() != 2 {
            self.error(
                "runtime.root_identity_shape",
                format!("{path}.descriptors"),
                "runtime root identity requires runtime and global descriptors",
            );
            return;
        }
        let expected = [
            (RuntimeRootRole::Runtime, runtime_family),
            (RuntimeRootRole::Global, binding_name),
        ];
        for (index, (descriptor, (role, name))) in
            identity.descriptors.iter().zip(expected).enumerate()
        {
            self.text(
                &format!("{path}.descriptors[{index}].name"),
                &descriptor.name,
            );
            if descriptor.role != role || descriptor.name != name {
                self.error(
                    "runtime.root_identity_descriptor",
                    format!("{path}.descriptors[{index}]"),
                    "runtime root descriptor does not identify the published runtime and global",
                );
            }
        }
    }

    fn runtime_evidence(&mut self, path: &str, evidence: &RuntimeEvidence) {
        self.text(&format!("{path}.producer"), &evidence.producer);
        self.text(&format!("{path}.method"), &evidence.method);
        self.runtime_digest(&format!("{path}.inputs_digest"), &evidence.inputs_digest);
    }

    fn runtime_source_range(&mut self, path: &str, range: &RuntimeSourceRange) {
        self.text(&format!("{path}.resource"), &range.resource);
        self.runtime_digest(&format!("{path}.resource_digest"), &range.resource_digest);
        if range.end_byte <= range.start_byte {
            self.error(
                "runtime.empty_source_range",
                path,
                "runtime source ranges must be non-empty",
            );
        }
    }

    fn runtime_identity(
        &mut self,
        path: &str,
        identity: &RuntimeScopedIdentity,
        expected_kind: RuntimeIdentityKind,
    ) {
        self.runtime_digest(&format!("{path}.owner_digest"), &identity.owner_digest);
        self.runtime_digest(&format!("{path}.locator_digest"), &identity.locator_digest);
        if identity.kind != expected_kind {
            self.error(
                "runtime.identity_kind",
                format!("{path}.kind"),
                "runtime identity kind does not match its field",
            );
        }
    }

    fn runtime_activation(
        &mut self,
        path: &str,
        activation: &RuntimeActivationEvidence,
        exposure: Option<&RuntimeGlobalExposure>,
        enabled_exposure_ids: &[String],
        expected_active_set_digest: &str,
    ) {
        self.runtime_digest(
            &format!("{path}.runtime_profile_digest"),
            &activation.runtime_profile_digest,
        );
        self.runtime_digest(
            &format!("{path}.active_set_digest"),
            &activation.active_set_digest,
        );
        self.runtime_digest(&format!("{path}.model_digest"), &activation.model_digest);
        self.text(
            &format!("{path}.activation_source"),
            &activation.activation_source,
        );
        self.stable_reference(&format!("{path}.exposure_id"), &activation.exposure_id);
        let mut active_ids = HashSet::new();
        for (index, id) in activation.active_exposure_ids.iter().enumerate() {
            self.stable_reference(&format!("{path}.active_exposure_ids[{index}]"), id);
            if !active_ids.insert(id) {
                self.error(
                    "runtime.duplicate_active_exposure",
                    format!("{path}.active_exposure_ids[{index}]"),
                    "active exposure ids must be unique",
                );
            }
        }
        if activation.active_exposure_ids != enabled_exposure_ids
            || activation.active_set_digest != expected_active_set_digest
        {
            self.error(
                "runtime.active_set_mismatch",
                path,
                "activation evidence must name the enabled exposures and their canonical digest",
            );
        }
        if let Some(exposure) = exposure {
            if activation.exposure_id != exposure.exposure_id
                || activation.runtime_profile_digest != exposure.runtime_profile_digest
                || activation.model_digest != exposure.evidence.inputs_digest
            {
                self.error(
                    "runtime.activation_join",
                    path,
                    "activation evidence must join its exposure profile, model, and identity",
                );
            }
            if activation.outcome == RuntimeActivationOutcome::Matched
                && (exposure.activation != RuntimeExposureActivation::Enabled
                    || enabled_exposure_ids.len() != 1)
            {
                self.error(
                    "runtime.matched_activation",
                    path,
                    "matched activation requires one unique enabled exposure",
                );
            }
        }
    }

    fn runtime_extensions(&mut self, path: &str, extensions: &[RuntimeValueExtension]) {
        for (index, extension) in extensions.iter().enumerate() {
            let current = format!("{path}[{index}]");
            self.stable_component(&format!("{current}.vocabulary"), &extension.vocabulary);
            self.version(&format!("{current}.version"), &extension.version);
            match serde_json::to_vec(&extension.payload) {
                Ok(value) if value.len() <= self.limits.max_text_bytes => {}
                Ok(_) => self.error(
                    "limit.runtime_extension_bytes",
                    format!("{current}.payload"),
                    format!(
                        "runtime extension payload exceeds {} bytes",
                        self.limits.max_text_bytes
                    ),
                ),
                Err(error) => self.error(
                    "runtime.extension_payload",
                    format!("{current}.payload"),
                    format!("runtime extension payload is not serializable: {error}"),
                ),
            }
        }
    }

    fn runtime_unique_references(&mut self, path: &str, values: &[String]) {
        let mut seen = HashSet::new();
        for (index, value) in values.iter().enumerate() {
            self.stable_reference(&format!("{path}[{index}]"), value);
            if !seen.insert(value) {
                self.error(
                    "runtime.duplicate_reference",
                    format!("{path}[{index}]"),
                    "runtime references must be unique",
                );
            }
        }
    }

    fn runtime_digest(&mut self, path: &str, value: &str) {
        if !is_lower_sha256(value) {
            self.error(
                "runtime.invalid_digest",
                path,
                "runtime digest must be 64 lowercase hexadecimal characters",
            );
        }
    }

    fn runtime_coverage(&mut self, path: &str, coverage: &RuntimeCoverage) {
        if coverage.status == RuntimeCoverageStatus::Complete && !coverage.limitations.is_empty() {
            self.error(
                "runtime.complete_with_limitations",
                path,
                "complete runtime coverage cannot retain limitations",
            );
        }
        if coverage.status != RuntimeCoverageStatus::Complete && coverage.limitations.is_empty() {
            self.error(
                "runtime.incomplete_without_limitation",
                path,
                "incomplete runtime coverage requires a typed limitation",
            );
        }
    }

    fn procedure_summary(&mut self, path: &str, summary: &AuthoredProcedureSummary) {
        self.stable_id(&format!("{path}.id"), &summary.id);
        if self
            .pack_id_bytes
            .saturating_add(1)
            .saturating_add(summary.id.len())
            > MAX_PROCEDURE_SUMMARY_MODEL_ID_BYTES
        {
            self.error(
                "limit.summary_model_id_bytes",
                format!("{path}.id"),
                format!(
                    "derived procedure model id exceeds {MAX_PROCEDURE_SUMMARY_MODEL_ID_BYTES} bytes"
                ),
            );
        }
        self.locator_path(&format!("{path}.target.path"), &summary.target.path);
        self.text(&format!("{path}.target.symbol"), &summary.target.symbol);
        if summary.target.parameter_count > MAX_PROCEDURE_SUMMARY_ORDINAL.saturating_add(1) {
            self.error(
                "summary.invalid_parameter_count",
                format!("{path}.target.parameter_count"),
                format!(
                    "parameter count exceeds {}",
                    MAX_PROCEDURE_SUMMARY_ORDINAL.saturating_add(1)
                ),
            );
        }
        if summary.target.variadic && summary.target.parameter_count == 0 {
            self.error(
                "summary.invalid_variadic_parameter_count",
                format!("{path}.target.parameter_count"),
                "a variadic target must declare its variadic final formal parameter",
            );
        }
        if !summary.target.formals.is_empty() {
            if self.predates_schema(PROCEDURE_FORMALS_MIN_SCHEMA_VERSION) {
                self.error(
                    "summary.formals_schema_version",
                    format!("{path}.target.formals"),
                    format!(
                        "structured procedure formals require schema version {PROCEDURE_FORMALS_MIN_SCHEMA_VERSION}"
                    ),
                );
            }
            if summary.target.variadic
                && self.predates_schema(PROCEDURE_VARIADIC_FORMALS_MIN_SCHEMA_VERSION)
            {
                self.error(
                    "summary.formals_variadic_target",
                    format!("{path}.target.formals"),
                    format!(
                        "structured variadic procedure formals require schema version {PROCEDURE_VARIADIC_FORMALS_MIN_SCHEMA_VERSION}"
                    ),
                );
            }
            if summary.target.formals.len() != summary.target.parameter_count as usize {
                self.error(
                    "summary.formals_count_mismatch",
                    format!("{path}.target.formals"),
                    format!(
                        "expected {} structured formals, found {}",
                        summary.target.parameter_count,
                        summary.target.formals.len()
                    ),
                );
            }
            let mut names = HashSet::new();
            let variadic_formals = summary
                .target
                .formals
                .iter()
                .enumerate()
                .filter_map(|(index, formal)| formal.variadic_kind.map(|kind| (index, kind)))
                .collect::<Vec<_>>();
            if !variadic_formals.is_empty()
                && self.predates_schema(PROCEDURE_VARIADIC_FORMALS_MIN_SCHEMA_VERSION)
            {
                self.error(
                    "summary.variadic_formals_schema_version",
                    format!("{path}.target.formals"),
                    format!(
                        "variadic formal kinds require schema version {PROCEDURE_VARIADIC_FORMALS_MIN_SCHEMA_VERSION}"
                    ),
                );
            }
            if self.schema_version >= PROCEDURE_VARIADIC_FORMALS_MIN_SCHEMA_VERSION {
                let target_variadic_formal_is_exact =
                    summary.target.variadic == !variadic_formals.is_empty();
                if !target_variadic_formal_is_exact {
                    self.error(
                        "summary.formals_variadic_target_mismatch",
                        format!("{path}.target.formals"),
                        "a structured variadic target must declare at least one variadic formal, and a fixed target must declare none",
                    );
                }
                let positional_variadics = variadic_formals
                    .iter()
                    .filter_map(|(index, kind)| kind.accepts_positional().then_some(*index))
                    .collect::<Vec<_>>();
                let keyword_variadics = variadic_formals
                    .iter()
                    .filter_map(|(index, kind)| kind.accepts_named().then_some(*index))
                    .collect::<Vec<_>>();
                if positional_variadics.len() > 1 || keyword_variadics.len() > 1 {
                    self.error(
                        "summary.variadic_formal_domain_conflict",
                        format!("{path}.target.formals"),
                        "a structured signature may declare at most one rest formal per argument domain",
                    );
                }
                if let Some(index) = keyword_variadics.first()
                    && *index + 1 != summary.target.formals.len()
                {
                    self.error(
                        "summary.variadic_formal_not_final",
                        format!("{path}.target.formals[{index}]"),
                        "the keyword-rest formal must be final",
                    );
                }
                if let Some(index) = positional_variadics.first()
                    && summary.target.formals[*index + 1..]
                        .iter()
                        .any(|formal| formal.passing_mode.accepts_positional())
                {
                    self.error(
                        "summary.variadic_formal_order",
                        format!("{path}.target.formals[{index}]"),
                        "a positional-rest formal may be followed only by named-only fixed formals or keyword-rest",
                    );
                }
                for (index, kind) in &variadic_formals {
                    let formal = &summary.target.formals[*index];
                    let expected_mode = match kind {
                        AuthoredProcedureFormalVariadicKind::Positional => {
                            AuthoredProcedureFormalPassingMode::PositionalOnly
                        }
                        AuthoredProcedureFormalVariadicKind::Keyword => {
                            AuthoredProcedureFormalPassingMode::NamedOnly
                        }
                        AuthoredProcedureFormalVariadicKind::Both => {
                            AuthoredProcedureFormalPassingMode::PositionalOrNamed
                        }
                    };
                    if formal.passing_mode != expected_mode {
                        self.error(
                            "summary.variadic_formal_passing_mode",
                            format!("{path}.target.formals[{index}].passing_mode"),
                            "the formal passing mode must match its positional, keyword, or both-domain variadic kind",
                        );
                    }
                }
            }
            for (index, formal) in summary.target.formals.iter().enumerate() {
                let formal_path = format!("{path}.target.formals[{index}]");
                self.text(&format!("{formal_path}.name"), &formal.name);
                if !names.insert(formal.name.as_str()) {
                    self.error(
                        "summary.duplicate_formal_name",
                        format!("{formal_path}.name"),
                        format!("formal name {:?} is already declared", formal.name),
                    );
                }
            }
        }
        let target = (summary.target.path.clone(), summary.target.symbol.clone());
        if let Some(first_path) = self.procedure_targets.insert(target, path.to_owned()) {
            self.error(
                "summary.duplicate_target",
                format!("{path}.target"),
                format!("procedure target was already declared at {first_path}.target"),
            );
        }
        if matches!(summary.completeness, Completeness::Complete)
            && matches!(self.pack_completeness, Completeness::Partial)
        {
            self.error(
                "summary.completeness_exceeds_pack",
                format!("{path}.completeness"),
                "a complete procedure summary requires a complete pack envelope",
            );
        }

        if summary.no_concurrency_effects
            && self.predates_schema(NO_CONCURRENCY_EFFECTS_MIN_SCHEMA_VERSION)
        {
            self.error(
                "summary.no_concurrency_effects_schema_version",
                format!("{path}.no_concurrency_effects"),
                format!(
                    "no_concurrency_effects requires schema version {NO_CONCURRENCY_EFFECTS_MIN_SCHEMA_VERSION}"
                ),
            );
        }

        // #2371: `covers_overrides` is an author's claim that every
        // implementation of this member outside the workspace conforms to the
        // summary. A partial summary does not describe even its own target, so
        // it cannot describe every implementation of it, and a receiverless
        // target has no overrides to claim in the first place -- there is
        // exactly one callable it could ever name.
        if summary.covers_overrides {
            if matches!(summary.completeness, Completeness::Partial) {
                self.error(
                    "summary.covers_overrides_on_partial_summary",
                    format!("{path}.covers_overrides"),
                    "covers_overrides requires completeness: complete",
                );
            }
            if !summary.target.has_receiver {
                self.error(
                    "summary.covers_overrides_on_receiverless_target",
                    format!("{path}.covers_overrides"),
                    "covers_overrides requires a receiver target: a receiverless callee has no overrides to cover",
                );
            }
        }

        let identity_return = summary.transfers.iter().any(|transfer| {
            transfer.exit_kind == AuthoredSummaryExitKind::Normal
                && matches!(transfer.output, AuthoredSummaryOutput::NormalReturn {})
                && matches!(
                    transfer.value_transfer.as_ref().map(|value| &value.kind),
                    Some(SummaryValueTransferKind::Conversion {
                        preservation: SummaryValuePreservation::Identity,
                    })
                )
        });
        if identity_return
            && summary.effects.iter().any(|effect| {
                matches!(
                    effect,
                    AuthoredSummaryEffect::Allocation {
                        output: AuthoredSummaryOutput::NormalReturn {},
                        ..
                    }
                )
            })
        {
            self.error(
                "summary.identity_return_allocation_conflict",
                format!("{path}.effects"),
                "an Identity normal-return transfer cannot also allocate NormalReturn",
            );
        }

        self.ordinary_heap_unchanged(path, summary);
        self.no_concurrency_effects(path, summary);

        let has_channel_close_effect = summary
            .concurrency_effects
            .iter()
            .chain(
                summary
                    .returned_callables
                    .iter()
                    .flat_map(|callable| callable.concurrency_effects.iter()),
            )
            .any(|effect| {
                matches!(
                    effect,
                    AuthoredConcurrencyEffect::ChannelClose { .. }
                        | AuthoredConcurrencyEffect::ChannelCloseAsync { .. }
                        | AuthoredConcurrencyEffect::ChannelClosePropagate { .. }
                )
            });
        if (has_channel_close_effect || !summary.returned_callables.is_empty())
            && self.predates_schema(CHANNEL_CLOSE_EFFECTS_MIN_SCHEMA_VERSION)
        {
            self.error(
                "summary.channel_close_schema_version",
                format!("{path}.concurrency_effects"),
                format!(
                    "channel-close effects and returned-callable models require schema version {CHANNEL_CLOSE_EFFECTS_MIN_SCHEMA_VERSION}"
                ),
            );
        }

        if let Some(normal_result_count) = summary.normal_result_count
            && normal_result_count > MAX_PROCEDURE_SUMMARY_ORDINAL.saturating_add(1)
        {
            self.error(
                "summary.invalid_normal_result_count",
                format!("{path}.normal_result_count"),
                format!(
                    "normal result count exceeds {}",
                    MAX_PROCEDURE_SUMMARY_ORDINAL.saturating_add(1)
                ),
            );
        }

        if summary.locations.len() > MAX_PROCEDURE_SUMMARY_LOCATIONS {
            self.error(
                "limit.summary_locations",
                format!("{path}.locations"),
                format!("summary has more than {MAX_PROCEDURE_SUMMARY_LOCATIONS} locations"),
            );
        }
        if summary.transfers.len() > MAX_PROCEDURE_SUMMARY_TRANSFERS {
            self.error(
                "limit.summary_transfers",
                format!("{path}.transfers"),
                format!("summary has more than {MAX_PROCEDURE_SUMMARY_TRANSFERS} transfers"),
            );
        }
        if summary.effects.len() > MAX_PROCEDURE_SUMMARY_EFFECTS {
            self.error(
                "limit.summary_effects",
                format!("{path}.effects"),
                format!("summary has more than {MAX_PROCEDURE_SUMMARY_EFFECTS} effects"),
            );
        }
        if summary.concurrency_effects.len() > MAX_PROCEDURE_SUMMARY_EFFECTS {
            self.error(
                "limit.summary_concurrency_effects",
                format!("{path}.concurrency_effects"),
                format!(
                    "summary has more than {MAX_PROCEDURE_SUMMARY_EFFECTS} concurrency effects"
                ),
            );
        }
        if summary.returned_callables.len() > MAX_PROCEDURE_SUMMARY_EFFECTS {
            self.error(
                "limit.summary_returned_callables",
                format!("{path}.returned_callables"),
                format!("summary has more than {MAX_PROCEDURE_SUMMARY_EFFECTS} returned callables"),
            );
        }
        let effect_references = summary.effects.iter().fold(0usize, |count, effect| {
            count.saturating_add(match effect {
                AuthoredSummaryEffect::Call { .. } => 1,
                AuthoredSummaryEffect::AmbiguousCall { candidates, .. } => candidates.len(),
                AuthoredSummaryEffect::Allocation { .. }
                | AuthoredSummaryEffect::Escape { .. }
                | AuthoredSummaryEffect::UnknownCall { .. }
                | AuthoredSummaryEffect::UnknownCallBoundary { .. }
                | AuthoredSummaryEffect::Sanitize { .. } => 0,
            })
        });
        if effect_references > MAX_PROCEDURE_SUMMARY_EFFECT_REFERENCES {
            self.error(
                "limit.summary_effect_references",
                format!("{path}.effects"),
                format!(
                    "summary has more than {MAX_PROCEDURE_SUMMARY_EFFECT_REFERENCES} effect references"
                ),
            );
        }
        // A complete empty summary is an explicit negative claim: the author
        // reviewed the procedure's complete transfer scope and found no
        // transfer. A partial empty summary proves nothing and remains invalid.
        //
        // A declared effect (#2437) is metadata about the procedure, not a
        // modeled port, so it deliberately does not satisfy this rule. Result
        // contracts, result-use obligations, conditional-result refinements,
        // and conditional indirect
        // writes do: they are substantive relations among modeled ports even
        // when the summary moves no values.
        if summary.transfers.is_empty()
            && !summary
                .transfer_partitions
                .iter()
                .any(|partition| partition.status == TransferPartitionStatus::Complete)
            && summary.effects.is_empty()
            && summary.concurrency_effects.is_empty()
            && summary.preconditions.is_none()
            && summary.result_contracts.is_empty()
            && summary.result_use_obligations.is_empty()
            && summary.conditional_result_refinements.is_empty()
            && summary.conditional_indirect_writes.is_empty()
            && summary.normal_return_refinements.is_empty()
            && summary.normal_return_type_refinements.is_empty()
            && summary.class_decorator_identity.is_none()
            && !summary.normal_continuation_absent
            && summary.completeness != Completeness::Complete
        {
            self.error(
                "summary.empty",
                path,
                "a partial procedure summary must declare at least one transfer, transfer partition, effect, concurrency effect, operation precondition review, result contract, result-use obligation, conditional-result refinement, conditional indirect write, normal-return refinement, or absent normal continuation",
            );
        }

        if summary.normal_continuation_absent {
            for (index, transfer) in summary.transfers.iter().enumerate() {
                if matches!(transfer.exit_kind, AuthoredSummaryExitKind::Normal) {
                    self.error(
                        "summary.normal_continuation_conflict",
                        format!("{path}.transfers[{index}].exit_kind"),
                        "normal_continuation_absent conflicts with a normal transfer",
                    );
                }
            }
            for (index, effect) in summary.effects.iter().enumerate() {
                if matches!(
                    effect,
                    AuthoredSummaryEffect::Allocation {
                        output: AuthoredSummaryOutput::NormalReturn {}
                            | AuthoredSummaryOutput::IndexedNormalReturn { .. },
                        ..
                    } | AuthoredSummaryEffect::Sanitize {
                        output: AuthoredSummaryOutput::NormalReturn {}
                            | AuthoredSummaryOutput::IndexedNormalReturn { .. },
                        ..
                    }
                ) {
                    self.error(
                        "summary.normal_continuation_conflict",
                        format!("{path}.effects[{index}].output"),
                        "normal_continuation_absent conflicts with a normal-return effect output",
                    );
                }
            }
            if !summary.result_contracts.is_empty() {
                self.error(
                    "summary.normal_continuation_conflict",
                    format!("{path}.result_contracts"),
                    "normal_continuation_absent conflicts with result contracts on a normal return",
                );
            }
            if !summary.result_use_obligations.is_empty() {
                self.error(
                    "summary.normal_continuation_conflict",
                    format!("{path}.result_use_obligations"),
                    "normal_continuation_absent conflicts with obligations on a normal result",
                );
            }
            if !summary.conditional_result_refinements.is_empty() {
                self.error(
                    "summary.normal_continuation_conflict",
                    format!("{path}.conditional_result_refinements"),
                    "normal_continuation_absent conflicts with conditional-result refinements",
                );
            }
            if !summary.conditional_indirect_writes.is_empty() {
                self.error(
                    "summary.normal_continuation_conflict",
                    format!("{path}.conditional_indirect_writes"),
                    "normal_continuation_absent conflicts with conditional indirect writes",
                );
            }
            if !summary.normal_return_refinements.is_empty() {
                self.error(
                    "summary.normal_continuation_conflict",
                    format!("{path}.normal_return_refinements"),
                    "normal_continuation_absent conflicts with normal-return refinements",
                );
            }
            if !summary.normal_return_type_refinements.is_empty() {
                self.error(
                    "summary.normal_continuation_conflict",
                    format!("{path}.normal_return_type_refinements"),
                    "normal_continuation_absent conflicts with normal-return type refinements",
                );
            }
            if summary.class_decorator_identity.is_some() {
                self.error(
                    "summary.normal_continuation_conflict",
                    format!("{path}.class_decorator_identity"),
                    "normal_continuation_absent conflicts with a class decorator identity claim",
                );
            }
        }

        self.declared_effects(path, &summary.declared_effects);
        self.operation_preconditions(path, &summary.preconditions, &summary.target);
        if summary.normal_result_count.is_none()
            && (!summary.result_contracts.is_empty()
                || !summary.result_use_obligations.is_empty()
                || !summary.conditional_result_refinements.is_empty()
                || !summary.conditional_indirect_writes.is_empty()
                || !summary.returned_callables.is_empty())
        {
            self.error(
                "summary.result_count_required",
                format!("{path}.normal_result_count"),
                "normal_result_count is required when result contracts, result-use obligations, conditional-result refinements, conditional indirect writes, or returned-callable models are non-empty",
            );
        }
        self.result_contracts(path, summary.normal_result_count, &summary.result_contracts);
        self.result_use_obligations(path, summary);
        self.conditional_result_refinements(
            path,
            &summary.target,
            summary.normal_result_count,
            &summary.conditional_result_refinements,
        );
        self.conditional_indirect_writes(
            path,
            &summary.target,
            summary.normal_result_count,
            &summary.conditional_indirect_writes,
        );
        self.normal_return_refinements(path, &summary.target, &summary.normal_return_refinements);
        self.normal_return_type_refinements(
            path,
            &summary.target,
            &summary.normal_return_type_refinements,
        );
        self.class_decorator_identity(
            path,
            &summary.target,
            summary.completeness,
            summary.covers_overrides,
            summary.class_decorator_identity.as_ref(),
        );

        let mut locations = HashMap::new();
        for (index, location) in summary.locations.iter().enumerate() {
            let location_path = format!("{path}.locations[{index}]");
            self.stable_component(&format!("{location_path}.id"), &location.id);
            if let Some((_, first_path)) = locations.insert(
                location.id.as_str(),
                (location.location_kind, location_path.clone()),
            ) {
                self.error(
                    "summary.duplicate_location",
                    format!("{location_path}.id"),
                    format!(
                        "location `{}` was already declared at {first_path}.id",
                        location.id
                    ),
                );
            }
        }

        let mut partition_scopes = HashSet::new();
        for (index, partition) in summary.transfer_partitions.iter().enumerate() {
            let partition_path = format!("{path}.transfer_partitions[{index}]");
            if !partition_scopes.insert((partition.source.clone(), partition.normal_result)) {
                self.error(
                    "summary.duplicate_transfer_partition",
                    partition_path.clone(),
                    "duplicate source/result transfer partition",
                );
            }
            if summary
                .normal_result_count
                .is_none_or(|count| partition.normal_result >= count)
            {
                self.error(
                    "summary.transfer_partition_result",
                    format!("{partition_path}.normal_result"),
                    "partition must name a declared normal-result port",
                );
            }
            match &partition.source {
                TransferPartitionSource::AllInputs => {}
                TransferPartitionSource::InputReceiver if !summary.target.has_receiver => {
                    self.error(
                        "summary.transfer_partition_receiver",
                        format!("{partition_path}.source"),
                        "partition names an absent input receiver",
                    );
                }
                TransferPartitionSource::InputParameter { ordinal }
                    if *ordinal >= summary.target.parameter_count =>
                {
                    self.error(
                        "summary.transfer_partition_parameter",
                        format!("{partition_path}.source"),
                        "partition names an absent input parameter",
                    );
                }
                TransferPartitionSource::InputCapture { symbol }
                    if !locations
                        .get(symbol.as_str())
                        .is_some_and(|(kind, _)| *kind == AuthoredSummaryLocationKind::Capture) =>
                {
                    self.error(
                        "summary.transfer_partition_capture",
                        format!("{partition_path}.source"),
                        "partition names an undeclared input capture",
                    );
                }
                _ => {}
            }
            if partition.status == TransferPartitionStatus::Complete
                && !partition.limitations.is_empty()
            {
                self.error(
                    "summary.transfer_partition_complete_with_limitation",
                    format!("{partition_path}.limitations"),
                    "complete partition cannot carry limitations",
                );
            }
            if partition.status == TransferPartitionStatus::Partial
                && partition.limitations.is_empty()
            {
                self.error(
                    "summary.transfer_partition_partial_without_limitation",
                    format!("{partition_path}.limitations"),
                    "partial partition requires a typed limitation",
                );
            }
            for (limitation_index, limitation) in partition.limitations.iter().enumerate() {
                self.text(
                    &format!("{partition_path}.limitations[{limitation_index}].kind"),
                    &limitation.kind,
                );
            }
            for (provenance_index, provenance) in partition.provenance.iter().enumerate() {
                self.text(
                    &format!("{partition_path}.provenance[{provenance_index}]"),
                    provenance,
                );
            }
        }

        self.concurrency_effects(
            path,
            &summary.concurrency_effects,
            &summary.target,
            &locations,
            summary.normal_result_count,
        );
        self.returned_callables(path, summary, &locations);

        for (index, transfer) in summary.transfers.iter().enumerate() {
            let transfer_path = format!("{path}.transfers[{index}]");
            self.summary_input(
                &format!("{transfer_path}.input"),
                &transfer.input,
                &summary.target,
            );
            self.summary_output(
                &format!("{transfer_path}.output"),
                &transfer.output,
                &locations,
                &summary.target,
                summary.normal_result_count,
            );
            if matches!(
                (&transfer.exit_kind, &transfer.output),
                (
                    AuthoredSummaryExitKind::Normal,
                    AuthoredSummaryOutput::ExceptionalReturn {}
                ) | (
                    AuthoredSummaryExitKind::Exceptional,
                    AuthoredSummaryOutput::NormalReturn {}
                        | AuthoredSummaryOutput::IndexedNormalReturn { .. }
                )
            ) {
                self.error(
                    "summary.incompatible_exit_port",
                    &transfer_path,
                    "normal exits cannot use exceptional_return and exceptional exits cannot use normal_return",
                );
            }
            if let Some(value_transfer) = &transfer.value_transfer {
                self.summary_value_transfer(
                    &format!("{transfer_path}.value_transfer"),
                    value_transfer,
                );
            }
        }
        for (index, effect) in summary.effects.iter().enumerate() {
            self.summary_effect(
                &format!("{path}.effects[{index}]"),
                effect,
                &locations,
                &summary.target,
                &summary.transfers,
                summary.normal_result_count,
            );
        }
    }

    fn summary_input(
        &mut self,
        path: &str,
        input: &AuthoredSummaryInput,
        target: &AuthoredProcedureTarget,
    ) {
        match input {
            AuthoredSummaryInput::Receiver {} if !target.has_receiver => self.error(
                "summary.receiver_unavailable",
                path,
                "procedure target does not declare a receiver",
            ),
            AuthoredSummaryInput::Parameter { ordinal }
                if *ordinal > MAX_PROCEDURE_SUMMARY_ORDINAL
                    || *ordinal >= target.parameter_count =>
            {
                self.error(
                    "summary.invalid_ordinal",
                    format!("{path}.ordinal"),
                    format!(
                        "parameter ordinal must be below declared count {} and at most {MAX_PROCEDURE_SUMMARY_ORDINAL}",
                        target.parameter_count
                    ),
                );
            }
            AuthoredSummaryInput::Parameter { ordinal }
                if target.variadic && target.parameter_count.checked_sub(1) == Some(*ordinal) =>
            {
                self.error(
                    "summary.unsupported_variadic_tail_reference",
                    format!("{path}.ordinal"),
                    "semantic claims cannot yet reference a variadic tail formal",
                );
            }
            AuthoredSummaryInput::Receiver {} | AuthoredSummaryInput::Parameter { .. } => {}
        }
    }

    fn concurrency_effects(
        &mut self,
        path: &str,
        effects: &[AuthoredConcurrencyEffect],
        target: &AuthoredProcedureTarget,
        locations: &HashMap<&str, (AuthoredSummaryLocationKind, String)>,
        normal_result_count: Option<u32>,
    ) {
        let mut seen = HashMap::new();
        let mut task_joins = HashSet::new();
        let mut wait_group_waits = HashSet::new();
        for (index, effect) in effects.iter().enumerate() {
            let effect_path = format!("{path}.concurrency_effects[{index}]");
            if let Some(first_index) = seen.insert(effect, index) {
                self.error(
                    "summary.duplicate_concurrency_effect",
                    effect_path.clone(),
                    format!(
                        "concurrency effect duplicates {path}.concurrency_effects[{first_index}]"
                    ),
                );
            }
            match effect {
                AuthoredConcurrencyEffect::Unsupported { protocol } => {
                    if protocol.trim().is_empty() {
                        self.error(
                            "summary.invalid_unsupported_concurrency_protocol",
                            format!("{effect_path}.protocol"),
                            "an unsupported concurrency protocol name must be non-empty",
                        );
                    }
                }
                AuthoredConcurrencyEffect::TaskSpawn {
                    callable,
                    group,
                    timer,
                    ..
                } => {
                    self.summary_input(&format!("{effect_path}.callable"), callable, target);
                    if !matches!(callable, AuthoredSummaryInput::Parameter { .. }) {
                        self.error(
                            "summary.invalid_task_callable",
                            format!("{effect_path}.callable"),
                            "a spawned callable must be a parameter port",
                        );
                    }
                    if let Some(group) = group {
                        self.summary_input(&format!("{effect_path}.group"), group, target);
                        if group == callable {
                            self.error(
                                "summary.conflicting_concurrency_effect",
                                effect_path.clone(),
                                "task callable and task group must be distinct ports",
                            );
                        }
                    }
                    if let Some(timer) = timer {
                        self.summary_output(
                            &format!("{effect_path}.timer"),
                            timer,
                            locations,
                            target,
                            normal_result_count,
                        );
                        // Only the construction call's own result can carry
                        // the timer identity a later stop or reset binds
                        // against: a stored, captured, or escaped timer has no
                        // call result to bind at the spawn site.
                        if !matches!(
                            timer,
                            AuthoredSummaryOutput::NormalReturn {}
                                | AuthoredSummaryOutput::IndexedNormalReturn { .. }
                        ) {
                            self.error(
                                "summary.invalid_timer_output",
                                format!("{effect_path}.timer"),
                                "a spawn timer must name a normal-return port",
                            );
                        }
                    }
                }
                AuthoredConcurrencyEffect::TaskJoin { group } => {
                    self.summary_input(&format!("{effect_path}.group"), group, target);
                    task_joins.insert(group);
                }
                AuthoredConcurrencyEffect::OnceDo { once, callable } => {
                    self.summary_input(&format!("{effect_path}.once"), once, target);
                    self.summary_input(&format!("{effect_path}.callable"), callable, target);
                    if !matches!(callable, AuthoredSummaryInput::Parameter { .. }) {
                        self.error(
                            "summary.invalid_once_callable",
                            format!("{effect_path}.callable"),
                            "a Once callable must be a parameter port",
                        );
                    }
                    if once == callable {
                        self.error(
                            "summary.conflicting_concurrency_effect",
                            &effect_path,
                            "Once object and Once callable must be distinct ports",
                        );
                    }
                }
                AuthoredConcurrencyEffect::LockAcquire { lock, .. }
                | AuthoredConcurrencyEffect::LockRelease { lock, .. } => {
                    self.summary_input(&format!("{effect_path}.lock"), lock, target);
                }
                AuthoredConcurrencyEffect::WaitGroupAdd { group, delta } => {
                    self.summary_input(&format!("{effect_path}.group"), group, target);
                    self.summary_input(&format!("{effect_path}.delta"), delta, target);
                    if group == delta {
                        self.error(
                            "summary.conflicting_concurrency_effect",
                            effect_path,
                            "wait-group receiver and delta must be distinct ports",
                        );
                    }
                }
                AuthoredConcurrencyEffect::WaitGroupDone { group } => {
                    self.summary_input(&format!("{effect_path}.group"), group, target);
                }
                AuthoredConcurrencyEffect::WaitGroupWait { group } => {
                    self.summary_input(&format!("{effect_path}.group"), group, target);
                    wait_group_waits.insert(group);
                }
                AuthoredConcurrencyEffect::Atomic { location, .. } => {
                    self.summary_input(&format!("{effect_path}.location"), location, target);
                }
                AuthoredConcurrencyEffect::CondBind { condition, lock } => {
                    self.summary_input(&format!("{effect_path}.lock"), lock, target);
                    self.summary_output(
                        &format!("{effect_path}.condition"),
                        condition,
                        locations,
                        target,
                        normal_result_count,
                    );
                    // Only a returned object can carry the association to the
                    // caller's value: a stored, captured, or escaped condition
                    // has no call result to bind at the construction site.
                    if !matches!(
                        condition,
                        AuthoredSummaryOutput::NormalReturn {}
                            | AuthoredSummaryOutput::IndexedNormalReturn { .. }
                    ) {
                        self.error(
                            "summary.invalid_condition_output",
                            format!("{effect_path}.condition"),
                            "a condition association must name a normal-return port",
                        );
                    }
                }
                AuthoredConcurrencyEffect::CondWait { condition } => {
                    self.summary_input(&format!("{effect_path}.condition"), condition, target);
                }
                AuthoredConcurrencyEffect::CondNotify { condition, .. } => {
                    self.summary_input(&format!("{effect_path}.condition"), condition, target);
                }
                AuthoredConcurrencyEffect::SyncMap { map, key, .. } => {
                    self.summary_input(&format!("{effect_path}.map"), map, target);
                    if let Some(key) = key {
                        self.summary_input(&format!("{effect_path}.key"), key, target);
                    }
                }
                AuthoredConcurrencyEffect::TimerStop { timer } => {
                    self.summary_input(&format!("{effect_path}.timer"), timer, target);
                }
                AuthoredConcurrencyEffect::TimerReset { timer } => {
                    self.summary_input(&format!("{effect_path}.timer"), timer, target);
                }
                AuthoredConcurrencyEffect::ChannelClose { channel, fresh }
                | AuthoredConcurrencyEffect::ChannelCloseAsync { channel, fresh } => {
                    self.summary_port(
                        &format!("{effect_path}.channel"),
                        channel,
                        locations,
                        target,
                        normal_result_count,
                    );
                    if *fresh && !matches!(channel, AuthoredSummaryPort::Output { .. }) {
                        self.error(
                            "summary.fresh_channel_requires_output",
                            format!("{effect_path}.channel"),
                            "a fresh channel identity must name a normal result port",
                        );
                    }
                }
                AuthoredConcurrencyEffect::ChannelClosePropagate {
                    source,
                    target: output,
                    target_fresh,
                } => {
                    self.summary_port(
                        &format!("{effect_path}.source"),
                        source,
                        locations,
                        target,
                        normal_result_count,
                    );
                    self.summary_port(
                        &format!("{effect_path}.target"),
                        output,
                        locations,
                        target,
                        normal_result_count,
                    );
                    if source == output {
                        self.error(
                            "summary.conflicting_concurrency_effect",
                            &effect_path,
                            "channel-close propagation source and target must be distinct ports",
                        );
                    }
                    if *target_fresh && !matches!(output, AuthoredSummaryPort::Output { .. }) {
                        self.error(
                            "summary.fresh_channel_requires_output",
                            format!("{effect_path}.target"),
                            "a fresh propagated channel identity must name a normal result port",
                        );
                    }
                }
                AuthoredConcurrencyEffect::SubtestRun { callable, group } => {
                    self.summary_input(&format!("{effect_path}.callable"), callable, target);
                    self.summary_input(&format!("{effect_path}.group"), group, target);
                    if !matches!(callable, AuthoredSummaryInput::Parameter { .. }) {
                        self.error(
                            "summary.invalid_subtest_callable",
                            format!("{effect_path}.callable"),
                            "a subtest callback must be a parameter port",
                        );
                    }
                    if group == callable {
                        self.error(
                            "summary.conflicting_concurrency_effect",
                            effect_path,
                            "subtest callback and parent test node must be distinct ports",
                        );
                    }
                }
                AuthoredConcurrencyEffect::SubtestParallel { receiver } => {
                    self.summary_input(&format!("{effect_path}.receiver"), receiver, target);
                }
                AuthoredConcurrencyEffect::SubtestCleanup { callable, group } => {
                    self.summary_input(&format!("{effect_path}.callable"), callable, target);
                    self.summary_input(&format!("{effect_path}.group"), group, target);
                    if !matches!(callable, AuthoredSummaryInput::Parameter { .. }) {
                        self.error(
                            "summary.invalid_subtest_callable",
                            format!("{effect_path}.callable"),
                            "a cleanup callback must be a parameter port",
                        );
                    }
                    if group == callable {
                        self.error(
                            "summary.conflicting_concurrency_effect",
                            effect_path,
                            "cleanup callback and test node must be distinct ports",
                        );
                    }
                }
            }
        }
        for group in task_joins.intersection(&wait_group_waits) {
            self.error(
                "summary.conflicting_concurrency_effect",
                format!("{path}.concurrency_effects"),
                format!("task_join and wait_group_wait make duplicate join claims for {group:?}"),
            );
        }
    }

    fn summary_port(
        &mut self,
        path: &str,
        port: &AuthoredSummaryPort,
        locations: &HashMap<&str, (AuthoredSummaryLocationKind, String)>,
        target: &AuthoredProcedureTarget,
        normal_result_count: Option<u32>,
    ) {
        match port {
            AuthoredSummaryPort::Input { input } => {
                self.summary_input(&format!("{path}.input"), input, target)
            }
            AuthoredSummaryPort::Output { output } => {
                self.summary_output(
                    &format!("{path}.output"),
                    output,
                    locations,
                    target,
                    normal_result_count,
                );
                if !matches!(
                    output,
                    AuthoredSummaryOutput::NormalReturn {}
                        | AuthoredSummaryOutput::IndexedNormalReturn { .. }
                ) {
                    self.error(
                        "summary.invalid_channel_port",
                        path,
                        "a channel identity output must name a normal result port",
                    );
                }
            }
        }
    }

    fn returned_callables(
        &mut self,
        path: &str,
        summary: &AuthoredProcedureSummary,
        locations: &HashMap<&str, (AuthoredSummaryLocationKind, String)>,
    ) {
        let mut seen = HashSet::new();
        for (index, callable) in summary.returned_callables.iter().enumerate() {
            let callable_path = format!("{path}.returned_callables[{index}]");
            if !seen.insert(callable.result_ordinal) {
                self.error(
                    "summary.duplicate_returned_callable",
                    format!("{callable_path}.result_ordinal"),
                    format!(
                        "result ordinal {} is declared callable more than once",
                        callable.result_ordinal
                    ),
                );
            }
            match summary.normal_result_count {
                Some(count) if callable.result_ordinal < count => {}
                Some(count) => self.error(
                    "summary.invalid_returned_callable_ordinal",
                    format!("{callable_path}.result_ordinal"),
                    format!(
                        "result ordinal {} is outside normal_result_count {count}",
                        callable.result_ordinal
                    ),
                ),
                None => self.error(
                    "summary.returned_callable_result_count_required",
                    format!("{path}.normal_result_count"),
                    "normal_result_count is required for a returned-callable model",
                ),
            }
            if summary.completeness != Completeness::Complete {
                self.error(
                    "summary.returned_callable_on_partial_summary",
                    callable_path.clone(),
                    "a returned-callable model requires completeness: complete",
                );
            }
            if callable.concurrency_effects.is_empty() {
                self.error(
                    "summary.returned_callable_without_effect",
                    format!("{callable_path}.concurrency_effects"),
                    "a returned-callable model must declare at least one concurrency effect",
                );
            }
            if callable.at_most_once
                && callable
                    .concurrency_effects
                    .iter()
                    .any(|effect| !matches!(effect, AuthoredConcurrencyEffect::ChannelClose { .. }))
            {
                self.error(
                    "summary.unsupported_once_returned_callable_effect",
                    format!("{callable_path}.concurrency_effects"),
                    "at-most-once returned-callable effects currently support synchronous channel close",
                );
            }
            for (effect_index, effect) in callable.concurrency_effects.iter().enumerate() {
                if !matches!(
                    effect,
                    AuthoredConcurrencyEffect::ChannelClose { .. }
                        | AuthoredConcurrencyEffect::ChannelCloseAsync { .. }
                ) {
                    self.error(
                        "summary.unsupported_returned_callable_effect",
                        format!("{callable_path}.concurrency_effects[{effect_index}]"),
                        "returned-callable models currently support channel-close effects",
                    );
                }
                let channel = match effect {
                    AuthoredConcurrencyEffect::ChannelClose { channel, .. }
                    | AuthoredConcurrencyEffect::ChannelCloseAsync { channel, .. } => channel,
                    _ => continue,
                };
                let target_ordinal = match channel {
                    AuthoredSummaryPort::Output {
                        output: AuthoredSummaryOutput::NormalReturn {},
                    } => Some(0),
                    AuthoredSummaryPort::Output {
                        output: AuthoredSummaryOutput::IndexedNormalReturn { ordinal },
                    } => Some(*ordinal),
                    _ => None,
                };
                if target_ordinal.is_none_or(|ordinal| ordinal == callable.result_ordinal) {
                    self.error(
                        "summary.invalid_returned_callable_effect_target",
                        format!("{callable_path}.concurrency_effects[{effect_index}].channel"),
                        "a returned callable must affect another normal result identity",
                    );
                }
            }
            self.concurrency_effects(
                &callable_path,
                &callable.concurrency_effects,
                &summary.target,
                locations,
                summary.normal_result_count,
            );
        }
    }

    fn ordinary_heap_unchanged(&mut self, path: &str, summary: &AuthoredProcedureSummary) {
        if !summary.ordinary_heap_unchanged {
            return;
        }
        if summary.completeness != Completeness::Complete {
            self.error(
                "summary.ordinary_heap_unchanged_on_partial_summary",
                format!("{path}.ordinary_heap_unchanged"),
                "ordinary_heap_unchanged requires completeness: complete",
            );
        }
        for (index, effect) in summary.effects.iter().enumerate() {
            let conflict = match effect {
                AuthoredSummaryEffect::Allocation {
                    output:
                        AuthoredSummaryOutput::Capture { .. }
                        | AuthoredSummaryOutput::Receiver {}
                        | AuthoredSummaryOutput::Heap { .. },
                    ..
                } => Some("an allocation into ordinary storage is not unchanged"),
                AuthoredSummaryEffect::Allocation { .. } => None,
                AuthoredSummaryEffect::Call { .. } => {
                    Some("a transitive call requires its own heap-preservation certification")
                }
                AuthoredSummaryEffect::Escape { .. } => {
                    Some("an escape contradicts ordinary_heap_unchanged")
                }
                AuthoredSummaryEffect::UnknownCall { .. }
                | AuthoredSummaryEffect::UnknownCallBoundary { .. }
                | AuthoredSummaryEffect::AmbiguousCall { .. } => {
                    Some("unknown or ambiguous behavior contradicts ordinary_heap_unchanged")
                }
                AuthoredSummaryEffect::Sanitize { .. } => None,
            };
            if let Some(conflict) = conflict {
                self.error(
                    "summary.ordinary_heap_unchanged_conflict",
                    format!("{path}.effects[{index}]"),
                    conflict,
                );
            }
        }
        if !summary.conditional_indirect_writes.is_empty() {
            self.error(
                "summary.ordinary_heap_unchanged_conflict",
                format!("{path}.conditional_indirect_writes"),
                "conditional indirect writes contradict ordinary_heap_unchanged",
            );
        }
        for (index, transfer) in summary.transfers.iter().enumerate() {
            if matches!(
                &transfer.output,
                AuthoredSummaryOutput::Capture { .. }
                    | AuthoredSummaryOutput::Receiver {}
                    | AuthoredSummaryOutput::Heap { .. }
            ) {
                self.error(
                    "summary.ordinary_heap_unchanged_conflict",
                    format!("{path}.transfers[{index}].output"),
                    "a transfer into ordinary storage contradicts ordinary_heap_unchanged",
                );
            }
        }
        for (index, effect) in summary.concurrency_effects.iter().enumerate() {
            let conflict = match effect {
                AuthoredConcurrencyEffect::Atomic {
                    operation:
                        AuthoredAtomicOperation::Store | AuthoredAtomicOperation::ReadModifyWrite,
                    ..
                } => Some("an atomic memory mutation contradicts ordinary_heap_unchanged"),
                AuthoredConcurrencyEffect::TaskSpawn { .. } => {
                    Some("a spawned callback contradicts ordinary_heap_unchanged")
                }
                AuthoredConcurrencyEffect::SubtestRun { .. } => {
                    Some("a spawned subtest callback contradicts ordinary_heap_unchanged")
                }
                AuthoredConcurrencyEffect::SubtestCleanup { .. } => {
                    Some("a spawned cleanup callback contradicts ordinary_heap_unchanged")
                }
                AuthoredConcurrencyEffect::OnceDo { .. } => {
                    Some("a conditional Once callback contradicts ordinary_heap_unchanged")
                }
                AuthoredConcurrencyEffect::Unsupported { .. } => {
                    Some("an unsupported concurrency protocol cannot certify heap preservation")
                }
                _ => None,
            };
            if let Some(conflict) = conflict {
                self.error(
                    "summary.ordinary_heap_unchanged_conflict",
                    format!("{path}.concurrency_effects[{index}]"),
                    conflict,
                );
            }
        }
    }

    fn no_concurrency_effects(&mut self, path: &str, summary: &AuthoredProcedureSummary) {
        if !summary.no_concurrency_effects {
            return;
        }
        if summary.completeness != Completeness::Complete {
            self.error(
                "summary.no_concurrency_effects_on_partial_summary",
                format!("{path}.no_concurrency_effects"),
                "no_concurrency_effects requires completeness: complete",
            );
        }
        if !summary.concurrency_effects.is_empty() || !summary.returned_callables.is_empty() {
            self.error(
                "summary.no_concurrency_effects_conflict",
                format!("{path}.concurrency_effects"),
                "no_concurrency_effects conflicts with declared concurrency effects or returned callables",
            );
        }
    }

    fn summary_output(
        &mut self,
        path: &str,
        output: &AuthoredSummaryOutput,
        locations: &HashMap<&str, (AuthoredSummaryLocationKind, String)>,
        target: &AuthoredProcedureTarget,
        normal_result_count: Option<u32>,
    ) {
        let (location, expected_kind) = match output {
            AuthoredSummaryOutput::Capture { location } => {
                (Some(location), Some(AuthoredSummaryLocationKind::Capture))
            }
            AuthoredSummaryOutput::Heap { location } => {
                (Some(location), Some(AuthoredSummaryLocationKind::Heap))
            }
            AuthoredSummaryOutput::Receiver {} if !target.has_receiver => {
                self.error(
                    "summary.receiver_unavailable",
                    path,
                    "procedure target does not declare a receiver",
                );
                (None, None)
            }
            AuthoredSummaryOutput::IndexedNormalReturn { ordinal } => {
                if normal_result_count.is_none() {
                    self.error(
                        "summary.result_count_required",
                        path,
                        "normal_result_count is required for an indexed normal return",
                    );
                } else if let Some(count) = normal_result_count
                    && *ordinal >= count
                {
                    self.error(
                        "summary.result_ordinal_out_of_range",
                        format!("{path}.ordinal"),
                        format!("result ordinal {ordinal} is outside normal_result_count {count}"),
                    );
                }
                (None, None)
            }
            AuthoredSummaryOutput::NormalReturn {}
            | AuthoredSummaryOutput::Receiver {}
            | AuthoredSummaryOutput::ExceptionalReturn {} => (None, None),
        };
        let Some(location) = location else {
            return;
        };
        self.stable_reference(&format!("{path}.location"), location);
        let Some((actual_kind, declaration_path)) = locations.get(location.as_str()) else {
            self.error(
                "summary.unbound_location",
                format!("{path}.location"),
                format!("unknown summary location `{location}`"),
            );
            return;
        };
        let expected_kind = expected_kind.expect("location outputs have an expected kind");
        if *actual_kind != expected_kind {
            self.error(
                "summary.incompatible_location_kind",
                format!("{path}.location"),
                format!("location `{location}` has incompatible kind at {declaration_path}"),
            );
        }
    }

    fn summary_effect(
        &mut self,
        path: &str,
        effect: &AuthoredSummaryEffect,
        locations: &HashMap<&str, (AuthoredSummaryLocationKind, String)>,
        target: &AuthoredProcedureTarget,
        transfers: &[AuthoredSummaryTransfer],
        normal_result_count: Option<u32>,
    ) {
        // A sanitize effect names ports and labels, not an event, so it is
        // validated separately from the event-bearing effects below.
        if let AuthoredSummaryEffect::Sanitize {
            input,
            output,
            removes,
        } = effect
        {
            self.summary_input(&format!("{path}.input"), input, target);
            self.summary_output(
                &format!("{path}.output"),
                output,
                locations,
                target,
                normal_result_count,
            );
            self.sanitize_removes(&format!("{path}.removes"), removes);
            if !transfers
                .iter()
                .any(|transfer| transfer.input == *input && transfer.output == *output)
            {
                self.error(
                    "summary.sanitize_without_transfer",
                    path,
                    "a sanitize effect must match a declared transfer with the same input and output",
                );
            }
            return;
        }
        let event = match effect {
            AuthoredSummaryEffect::Sanitize { .. } => unreachable!("sanitize handled above"),
            AuthoredSummaryEffect::Allocation { event, output } => {
                self.summary_output(
                    &format!("{path}.output"),
                    output,
                    locations,
                    target,
                    normal_result_count,
                );
                event
            }
            AuthoredSummaryEffect::Call { event, callee } => {
                self.summary_callee(&format!("{path}.callee"), callee);
                event
            }
            AuthoredSummaryEffect::Escape { event, input }
            | AuthoredSummaryEffect::UnknownCall { event, input } => {
                self.summary_input(&format!("{path}.input"), input, target);
                event
            }
            AuthoredSummaryEffect::UnknownCallBoundary { event } => event,
            AuthoredSummaryEffect::AmbiguousCall {
                event,
                input,
                candidates,
            } => {
                self.summary_input(&format!("{path}.input"), input, target);
                if candidates.is_empty() {
                    self.error(
                        "summary.empty_ambiguous_candidates",
                        format!("{path}.candidates"),
                        "an ambiguous call must name at least one candidate",
                    );
                }
                if candidates.len() > MAX_PROCEDURE_SUMMARY_AMBIGUOUS_CALLEES {
                    self.error(
                        "limit.summary_ambiguous_callees",
                        format!("{path}.candidates"),
                        format!(
                            "ambiguous call has more than {MAX_PROCEDURE_SUMMARY_AMBIGUOUS_CALLEES} candidates"
                        ),
                    );
                }
                let mut seen = HashSet::new();
                for (index, candidate) in candidates.iter().enumerate() {
                    self.summary_callee(&format!("{path}.candidates[{index}]"), candidate);
                    if !seen.insert(candidate) {
                        self.error(
                            "summary.duplicate_ambiguous_candidate",
                            format!("{path}.candidates[{index}]"),
                            format!("duplicate ambiguous candidate `{candidate}`"),
                        );
                    }
                }
                event
            }
        };
        self.stable_component(&format!("{path}.event"), event);
    }

    fn summary_callee(&mut self, path: &str, callee: &str) {
        self.stable_reference(path, callee);
        if self.validate_references && !self.procedure_ids.contains(callee) {
            self.error(
                "summary.unbound_callee",
                path,
                format!("unknown procedure summary `{callee}`"),
            );
        }
    }

    fn summary_value_transfer(&mut self, path: &str, transfer: &SummaryValueTransfer) {
        if let SummaryValueTransferOperation::Implicit { member } = &transfer.operation {
            self.stable_reference(&format!("{path}.operation.member"), member);
            if self.validate_references && !self.member_ids.contains(member) {
                self.error(
                    "summary.unbound_value_transfer_member",
                    format!("{path}.operation.member"),
                    format!("unknown member declaration id `{member}`"),
                );
            }
        }
        if let SummaryValueTransferOperation::Unknown { limitation } = &transfer.operation
            && matches!(limitation.kind, SummaryValueTransferLimitationKind::Other)
            && limitation.message.as_deref().is_none_or(str::is_empty)
        {
            self.error(
                "summary.value_transfer_limitation_message_required",
                format!("{path}.operation.limitation.message"),
                "an `other` value-transfer limitation must include a non-empty message",
            );
        }
    }

    fn sanitize_removes(&mut self, path: &str, removes: &[String]) {
        if removes.is_empty() {
            self.error(
                "summary.empty_sanitize_labels",
                path,
                "a sanitize effect must remove at least one label",
            );
        }
        if removes.len() > MAX_PROCEDURE_SUMMARY_SANITIZE_LABELS {
            self.error(
                "limit.summary_sanitize_labels",
                path,
                format!(
                    "sanitize effect removes more than {MAX_PROCEDURE_SUMMARY_SANITIZE_LABELS} labels"
                ),
            );
        }
        let mut seen = HashSet::new();
        for (index, label) in removes.iter().enumerate() {
            self.stable_component(&format!("{path}[{index}]"), label);
            if !seen.insert(label) {
                self.error(
                    "summary.duplicate_sanitize_label",
                    format!("{path}[{index}]"),
                    format!("duplicate sanitize label `{label}`"),
                );
            }
        }
    }

    /// Validate the namespaced effect identifiers a summary declares (#2437).
    ///
    /// The identifier rule is the shared `stable_component` rule (dots allowed),
    /// plus a required `.` separator: an unnamespaced `write` would collide the
    /// moment two vendors ship packs for the same language.
    fn declared_effects(&mut self, path: &str, declared: &[AuthoredDeclaredEffect]) {
        if declared.len() > MAX_PROCEDURE_SUMMARY_DECLARED_EFFECTS {
            self.error(
                "limit.summary_declared_effects",
                format!("{path}.declared_effects"),
                format!(
                    "summary declares more than {MAX_PROCEDURE_SUMMARY_DECLARED_EFFECTS} effects"
                ),
            );
        }
        let mut seen = HashSet::new();
        for (index, effect) in declared.iter().enumerate() {
            let effect_path = format!("{path}.declared_effects[{index}]");
            self.stable_component(&format!("{effect_path}.id"), &effect.id);
            if !effect.id.contains('.') {
                self.error(
                    "summary.effect_namespace",
                    format!("{effect_path}.id"),
                    format!(
                        "declared effect `{}` must be namespaced, for example `vendor.effect`",
                        effect.id
                    ),
                );
            }
            if !seen.insert(effect.id.as_str()) {
                self.error(
                    "summary.duplicate_declared_effect",
                    format!("{effect_path}.id"),
                    format!("duplicate declared effect `{}`", effect.id),
                );
            }
        }
    }

    fn operation_preconditions(
        &mut self,
        path: &str,
        preconditions: &Option<Vec<AuthoredOperationPrecondition>>,
        target: &AuthoredProcedureTarget,
    ) {
        let Some(preconditions) = preconditions else {
            return;
        };
        let mut seen = HashMap::new();
        for (index, precondition) in preconditions.iter().enumerate() {
            let precondition_path = format!("{path}.preconditions[{index}]");
            self.summary_input(
                &format!("{precondition_path}.input"),
                &precondition.input,
                target,
            );
            if let Some((first_predicate, first_index)) = seen.get(&precondition.input) {
                let first_path = format!("{path}.preconditions[{first_index}]");
                if *first_predicate == precondition.predicate {
                    self.error(
                        "summary.duplicate_operation_precondition",
                        format!("{precondition_path}.input"),
                        format!("operation precondition duplicates {first_path}"),
                    );
                } else {
                    self.error(
                        "summary.conflicting_operation_precondition",
                        format!("{precondition_path}.predicate"),
                        format!(
                            "operation predicate conflicts with {first_path}.predicate for the same input"
                        ),
                    );
                }
            } else {
                seen.insert(&precondition.input, (precondition.predicate, index));
            }
        }
    }

    fn result_use_obligations(&mut self, path: &str, summary: &AuthoredProcedureSummary) {
        let obligations = &summary.result_use_obligations;
        if obligations.is_empty() {
            return;
        }
        if self.predates_schema(RESULT_USE_OBLIGATIONS_MIN_SCHEMA_VERSION) {
            self.error(
                "summary.result_use_obligations_schema",
                format!("{path}.result_use_obligations"),
                format!(
                    "result-use obligations require schema version {RESULT_USE_OBLIGATIONS_MIN_SCHEMA_VERSION}"
                ),
            );
        }
        if obligations.len() > MAX_PROCEDURE_SUMMARY_RESULT_USE_OBLIGATIONS {
            self.error(
                "limit.summary_result_use_obligations",
                format!("{path}.result_use_obligations"),
                format!(
                    "summary declares more than {MAX_PROCEDURE_SUMMARY_RESULT_USE_OBLIGATIONS} result-use obligations"
                ),
            );
        }
        let mut seen = HashSet::new();
        for (index, obligation) in obligations.iter().enumerate() {
            let obligation_path = format!("{path}.result_use_obligations[{index}]");
            let ordinal = obligation.result_ordinal;
            if ordinal > MAX_PROCEDURE_SUMMARY_ORDINAL {
                self.error(
                    "summary.invalid_result_ordinal",
                    format!("{obligation_path}.result_ordinal"),
                    format!("result ordinal exceeds {MAX_PROCEDURE_SUMMARY_ORDINAL}"),
                );
            }
            if summary
                .normal_result_count
                .is_some_and(|count| ordinal >= count)
            {
                self.error(
                    "summary.result_ordinal_out_of_range",
                    format!("{obligation_path}.result_ordinal"),
                    format!(
                        "result ordinal {ordinal} is outside normal_result_count {}",
                        summary.normal_result_count.expect("checked as some")
                    ),
                );
            }
            if !seen.insert(ordinal) {
                self.error(
                    "summary.duplicate_result_use_obligation",
                    format!("{obligation_path}.result_ordinal"),
                    format!("normal result {ordinal} already has a result-use obligation"),
                );
            }
            if obligation.kind == ResultUseObligationKind::PureTransformationValue
                && !summary.ordinary_heap_unchanged
            {
                self.error(
                    "summary.pure_result_has_unreviewed_heap_effects",
                    format!("{obligation_path}.kind"),
                    "a pure-transformation result requires ordinary_heap_unchanged",
                );
            }
            match (obligation.kind, obligation.failure_predicate) {
                (ResultUseObligationKind::PureTransformationValue, Some(_)) => self.error(
                    "summary.pure_result_has_failure_predicate",
                    format!("{obligation_path}.failure_predicate"),
                    "a pure-transformation result has no failure-status predicate",
                ),
                (ResultUseObligationKind::FallibleStatus, None) => self.error(
                    "summary.fallible_status_needs_failure_predicate",
                    format!("{obligation_path}.failure_predicate"),
                    "a fallible status needs a reviewed failure predicate",
                ),
                _ => {}
            }
        }
    }

    fn result_contracts(
        &mut self,
        path: &str,
        normal_result_count: Option<u32>,
        contracts: &[AuthoredResultContract],
    ) {
        if contracts.len() > MAX_PROCEDURE_SUMMARY_RESULT_CONTRACTS {
            self.error(
                "limit.summary_result_contracts",
                format!("{path}.result_contracts"),
                format!(
                    "summary declares more than {MAX_PROCEDURE_SUMMARY_RESULT_CONTRACTS} result contracts"
                ),
            );
        }
        let mut seen_results = HashSet::new();
        for (index, contract) in contracts.iter().enumerate() {
            let contract_path = format!("{path}.result_contracts[{index}]");
            for (field, ordinal) in [
                ("result_ordinal", Some(contract.result_ordinal)),
                (
                    "condition_result_ordinal",
                    contract.condition_result_ordinal,
                ),
            ]
            .into_iter()
            .filter_map(|(field, ordinal)| ordinal.map(|ordinal| (field, ordinal)))
            {
                if ordinal > MAX_PROCEDURE_SUMMARY_ORDINAL {
                    self.error(
                        "summary.invalid_result_ordinal",
                        format!("{contract_path}.{field}"),
                        format!("result ordinal exceeds {MAX_PROCEDURE_SUMMARY_ORDINAL}"),
                    );
                }
                if normal_result_count.is_some_and(|count| ordinal >= count) {
                    self.error(
                        "summary.result_ordinal_out_of_range",
                        format!("{contract_path}.{field}"),
                        format!(
                            "result ordinal {ordinal} is outside normal_result_count {}",
                            normal_result_count.expect("checked as some")
                        ),
                    );
                }
            }
            match (contract.condition_result_ordinal, contract.predicate) {
                (Some(_), None) | (None, Some(_)) => self.error(
                    "summary.incomplete_result_condition",
                    contract_path.clone(),
                    "condition_result_ordinal and predicate must be present or absent together",
                ),
                (None, None) if contract.result_success_predicate.is_none() => self.error(
                    "summary.direct_result_predicate_required",
                    format!("{contract_path}.result_success_predicate"),
                    "a direct result contract requires result_success_predicate",
                ),
                _ => {}
            }
            if contract.condition_result_ordinal == Some(contract.result_ordinal) {
                self.error(
                    "summary.self_conditioned_result",
                    contract_path.clone(),
                    "use a direct result contract instead of conditioning a result on itself",
                );
            }
            if !seen_results.insert(contract.result_ordinal) {
                self.error(
                    "summary.duplicate_result_contract",
                    format!("{contract_path}.result_ordinal"),
                    format!(
                        "result ordinal {} already has a validity contract",
                        contract.result_ordinal
                    ),
                );
            }
            if contract.member_contracts.len() > MAX_RESULT_CONTRACT_MEMBER_CONTRACTS {
                self.error(
                    "limit.result_member_contracts",
                    format!("{contract_path}.member_contracts"),
                    format!(
                        "result contract declares more than {MAX_RESULT_CONTRACT_MEMBER_CONTRACTS} member contracts"
                    ),
                );
            }
            let mut seen_members = HashSet::new();
            for (member_index, member) in contract.member_contracts.iter().enumerate() {
                let member_path = format!("{contract_path}.member_contracts[{member_index}]");
                self.language_identifier(&format!("{member_path}.member"), &member.member);
                if member.parameter_count > MAX_PROCEDURE_SUMMARY_ORDINAL {
                    self.error(
                        "summary.invalid_member_parameter_count",
                        format!("{member_path}.parameter_count"),
                        format!("member parameter count exceeds {MAX_PROCEDURE_SUMMARY_ORDINAL}"),
                    );
                }
                if !seen_members.insert((member.member.as_str(), member.parameter_count)) {
                    self.error(
                        "summary.duplicate_result_member_contract",
                        member_path.clone(),
                        format!(
                            "duplicate result member contract `{}` with arity {}",
                            member.member, member.parameter_count
                        ),
                    );
                }
                if let Some(preconditions) = &member.preconditions {
                    let mut seen_inputs = HashSet::new();
                    for (precondition_index, precondition) in preconditions.iter().enumerate() {
                        let precondition_path =
                            format!("{member_path}.preconditions[{precondition_index}]");
                        if let AuthoredSummaryInput::Parameter { ordinal } = &precondition.input {
                            if *ordinal > MAX_PROCEDURE_SUMMARY_ORDINAL {
                                self.error(
                                    "summary.invalid_parameter_ordinal",
                                    format!("{precondition_path}.input.ordinal"),
                                    format!(
                                        "parameter ordinal exceeds {MAX_PROCEDURE_SUMMARY_ORDINAL}"
                                    ),
                                );
                            }
                            if *ordinal >= member.parameter_count {
                                self.error(
                                    "summary.parameter_ordinal_out_of_range",
                                    format!("{precondition_path}.input.ordinal"),
                                    format!(
                                        "parameter ordinal {ordinal} is outside member parameter_count {}",
                                        member.parameter_count
                                    ),
                                );
                            }
                        }
                        if !seen_inputs.insert(&precondition.input) {
                            self.error(
                                "summary.duplicate_operation_precondition_input",
                                format!("{precondition_path}.input"),
                                "an operation input can have at most one precondition",
                            );
                        }
                    }
                }
                self.declared_effects(&member_path, &member.declared_effects);
            }
        }
    }

    fn parameter_ordinal(
        &mut self,
        ordinal: u32,
        target: &AuthoredProcedureTarget,
        path: &str,
        subject: &str,
    ) {
        if ordinal > MAX_PROCEDURE_SUMMARY_ORDINAL {
            self.error(
                "summary.invalid_parameter_ordinal",
                path,
                format!("parameter ordinal exceeds {MAX_PROCEDURE_SUMMARY_ORDINAL}"),
            );
        }
        if ordinal >= target.parameter_count {
            self.error(
                "summary.parameter_ordinal_out_of_range",
                path,
                format!(
                    "parameter ordinal {ordinal} is outside parameter_count {}",
                    target.parameter_count
                ),
            );
        } else if target.variadic && target.parameter_count.checked_sub(1) == Some(ordinal) {
            self.error(
                "summary.unsupported_variadic_tail_reference",
                path,
                format!("{subject} cannot reference variadic tail ordinal {ordinal}"),
            );
        }
    }

    fn result_ordinal(&mut self, ordinal: u32, normal_result_count: Option<u32>, path: &str) {
        if ordinal > MAX_PROCEDURE_SUMMARY_ORDINAL {
            self.error(
                "summary.invalid_result_ordinal",
                format!("{path}.result_ordinal"),
                format!("result ordinal exceeds {MAX_PROCEDURE_SUMMARY_ORDINAL}"),
            );
        }
        if let Some(count) = normal_result_count
            && ordinal >= count
        {
            self.error(
                "summary.result_ordinal_out_of_range",
                format!("{path}.result_ordinal"),
                format!("result ordinal {ordinal} is outside normal_result_count {count}"),
            );
        }
    }

    fn conditional_result_refinements(
        &mut self,
        path: &str,
        target: &AuthoredProcedureTarget,
        normal_result_count: Option<u32>,
        refinements: &[AuthoredConditionalResultRefinement],
    ) {
        if refinements.len() > MAX_PROCEDURE_SUMMARY_CONDITIONAL_RESULT_REFINEMENTS {
            self.error(
                "limit.summary_conditional_result_refinements",
                format!("{path}.conditional_result_refinements"),
                format!(
                    "summary declares more than {MAX_PROCEDURE_SUMMARY_CONDITIONAL_RESULT_REFINEMENTS} conditional-result refinements"
                ),
            );
        }

        let mut seen = HashMap::new();
        let mut established = HashMap::new();
        for (index, refinement) in refinements.iter().enumerate() {
            let refinement_path = format!("{path}.conditional_result_refinements[{index}]");
            self.result_ordinal(
                refinement.result_ordinal,
                normal_result_count,
                &refinement_path,
            );
            self.parameter_ordinal(
                refinement.parameter_ordinal,
                target,
                &format!("{refinement_path}.parameter_ordinal"),
                "conditional-result refinement",
            );

            let claim_key = (
                refinement.result_ordinal,
                refinement.outcome,
                refinement.parameter_ordinal,
                refinement.predicate,
            );
            if let Some((first_effect, first_path)) = seen.insert(
                claim_key,
                (refinement.proof_effect, refinement_path.clone()),
            ) {
                if first_effect == refinement.proof_effect {
                    self.error(
                        "summary.duplicate_conditional_result_refinement",
                        refinement_path.clone(),
                        format!("conditional-result refinement duplicates {first_path}"),
                    );
                } else {
                    self.error(
                        "summary.conflicting_conditional_result_refinement",
                        format!("{refinement_path}.proof_effect"),
                        format!(
                            "conditional-result proof effect conflicts with {first_path}.proof_effect"
                        ),
                    );
                }
            }

            if matches!(
                refinement.proof_effect,
                AuthoredPredicateProofEffect::Establishes
            ) {
                let outcome_key = (
                    refinement.result_ordinal,
                    refinement.outcome,
                    refinement.parameter_ordinal,
                );
                if let Some((first_predicate, first_path)) =
                    established.insert(outcome_key, (refinement.predicate, refinement_path.clone()))
                    && first_predicate != refinement.predicate
                {
                    self.error(
                        "summary.conflicting_conditional_result_refinement",
                        format!("{refinement_path}.predicate"),
                        format!(
                            "established predicate conflicts with {first_path}.predicate for the same result outcome and parameter"
                        ),
                    );
                }
            }
        }
    }

    fn conditional_indirect_writes(
        &mut self,
        path: &str,
        target: &AuthoredProcedureTarget,
        normal_result_count: Option<u32>,
        writes: &[AuthoredConditionalIndirectWrite],
    ) {
        if writes.len() > MAX_PROCEDURE_SUMMARY_CONDITIONAL_INDIRECT_WRITES {
            self.error(
                "limit.summary_conditional_indirect_writes",
                format!("{path}.conditional_indirect_writes"),
                format!(
                    "summary declares more than {MAX_PROCEDURE_SUMMARY_CONDITIONAL_INDIRECT_WRITES} conditional indirect writes"
                ),
            );
        }

        let mut seen = HashMap::new();
        for (index, write) in writes.iter().enumerate() {
            let write_path = format!("{path}.conditional_indirect_writes[{index}]");
            self.result_ordinal(write.result_ordinal, normal_result_count, &write_path);
            self.parameter_ordinal(
                write.parameter_ordinal,
                target,
                &format!("{write_path}.parameter_ordinal"),
                "conditional indirect write",
            );

            let key = (
                write.result_ordinal,
                write.outcome,
                write.parameter_ordinal,
                write.target,
            );
            if let Some(first_path) = seen.insert(key, write_path.clone()) {
                self.error(
                    "summary.duplicate_conditional_indirect_write",
                    write_path,
                    format!("conditional indirect write duplicates {first_path}"),
                );
            }
        }
    }

    fn normal_return_refinements(
        &mut self,
        path: &str,
        target: &AuthoredProcedureTarget,
        refinements: &[AuthoredNormalReturnRefinement],
    ) {
        if refinements.len() > MAX_PROCEDURE_SUMMARY_NORMAL_RETURN_REFINEMENTS {
            self.error(
                "limit.summary_normal_return_refinements",
                format!("{path}.normal_return_refinements"),
                format!(
                    "summary declares more than {MAX_PROCEDURE_SUMMARY_NORMAL_RETURN_REFINEMENTS} normal-return refinements"
                ),
            );
        }
        let mut seen = HashSet::new();
        for (index, refinement) in refinements.iter().enumerate() {
            let refinement_path = format!("{path}.normal_return_refinements[{index}]");
            self.parameter_ordinal(
                refinement.parameter_ordinal,
                target,
                &format!("{refinement_path}.parameter_ordinal"),
                "normal-return refinement",
            );
            if !seen.insert(refinement.parameter_ordinal) {
                self.error(
                    "summary.duplicate_normal_return_refinement",
                    format!("{refinement_path}.parameter_ordinal"),
                    format!(
                        "parameter ordinal {} already has a normal-return refinement",
                        refinement.parameter_ordinal
                    ),
                );
            }
        }
    }

    fn normal_return_type_refinements(
        &mut self,
        path: &str,
        target: &AuthoredProcedureTarget,
        refinements: &[AuthoredNormalReturnTypeRefinement],
    ) {
        if refinements.len() > MAX_PROCEDURE_SUMMARY_NORMAL_RETURN_TYPE_REFINEMENTS {
            self.error(
                "limit.summary_normal_return_type_refinements",
                format!("{path}.normal_return_type_refinements"),
                format!(
                    "summary declares more than {MAX_PROCEDURE_SUMMARY_NORMAL_RETURN_TYPE_REFINEMENTS} normal-return type refinements"
                ),
            );
        }
        let mut seen = HashMap::new();
        for (index, refinement) in refinements.iter().enumerate() {
            let refinement_path = format!("{path}.normal_return_type_refinements[{index}]");
            if refinement.required_receiver_members.len()
                > MAX_NORMAL_RETURN_TYPE_REFINEMENT_RECEIVER_MEMBERS
            {
                self.error(
                    "limit.normal_return_type_refinement_receiver_members",
                    format!("{refinement_path}.required_receiver_members"),
                    format!(
                        "normal-return type refinement declares more than {MAX_NORMAL_RETURN_TYPE_REFINEMENT_RECEIVER_MEMBERS} required receiver members"
                    ),
                );
            }
            if !refinement.required_receiver_members.is_empty() && !target.has_receiver {
                self.error(
                    "summary.required_receiver_members_without_receiver",
                    format!("{refinement_path}.required_receiver_members"),
                    "required receiver members need a receiver-bearing procedure target",
                );
            }
            let mut seen_receiver_members = HashSet::new();
            for (member_index, member) in refinement.required_receiver_members.iter().enumerate() {
                let member_path =
                    format!("{refinement_path}.required_receiver_members[{member_index}]");
                self.language_identifier(&member_path, member);
                if !seen_receiver_members.insert(member.as_str()) {
                    self.error(
                        "summary.duplicate_required_receiver_member",
                        member_path,
                        format!("required receiver member `{member}` is duplicated"),
                    );
                }
            }
            for (field, ordinal) in [
                ("parameter_ordinal", refinement.parameter_ordinal),
                (
                    "class_parameter_ordinal",
                    refinement.class_parameter_ordinal,
                ),
            ] {
                if ordinal > MAX_PROCEDURE_SUMMARY_ORDINAL {
                    self.error(
                        "summary.invalid_parameter_ordinal",
                        format!("{refinement_path}.{field}"),
                        format!("parameter ordinal exceeds {MAX_PROCEDURE_SUMMARY_ORDINAL}"),
                    );
                } else if ordinal >= target.parameter_count {
                    self.error(
                        "summary.parameter_ordinal_out_of_range",
                        format!("{refinement_path}.{field}"),
                        format!(
                            "parameter ordinal {} is outside parameter_count {}",
                            ordinal, target.parameter_count
                        ),
                    );
                } else if target.variadic && target.parameter_count.checked_sub(1) == Some(ordinal)
                {
                    self.error(
                        "summary.unsupported_variadic_tail_reference",
                        format!("{refinement_path}.{field}"),
                        format!(
                            "normal-return type refinement cannot reference variadic tail ordinal {}",
                            ordinal
                        ),
                    );
                }
            }
            if refinement.parameter_ordinal == refinement.class_parameter_ordinal {
                self.error(
                    "summary.same_normal_return_type_refinement_parameter",
                    refinement_path.clone(),
                    "normal-return type refinement subject and class parameters must differ",
                );
            }
            let key = refinement.parameter_ordinal;
            if let Some((class_parameter_ordinal, first_path)) = seen.insert(
                key,
                (refinement.class_parameter_ordinal, refinement_path.clone()),
            ) {
                if class_parameter_ordinal == refinement.class_parameter_ordinal {
                    self.error(
                        "summary.duplicate_normal_return_type_refinement",
                        refinement_path,
                        format!("normal-return type refinement duplicates {first_path}"),
                    );
                } else {
                    self.error(
                        "summary.conflicting_normal_return_type_refinement",
                        format!("{path}.normal_return_type_refinements[{index}].class_parameter_ordinal"),
                        format!(
                            "class parameter ordinal conflicts with {first_path}.class_parameter_ordinal"
                        ),
                    );
                }
            }
        }
    }

    fn class_decorator_identity(
        &mut self,
        path: &str,
        target: &AuthoredProcedureTarget,
        completeness: Completeness,
        covers_overrides: bool,
        identity: Option<&AuthoredClassDecoratorIdentity>,
    ) {
        let Some(identity) = identity else {
            return;
        };
        let identity_path = format!("{path}.class_decorator_identity");
        if completeness != Completeness::Complete {
            self.error(
                "summary.class_decorator_identity_requires_complete",
                format!("{identity_path}.direct"),
                "a class decorator identity claim requires a complete procedure summary",
            );
        }
        if target.has_receiver {
            self.error(
                "summary.class_decorator_identity_receiver_target",
                format!("{identity_path}.direct"),
                "a class decorator identity target must not require a receiver",
            );
        }
        if covers_overrides {
            self.error(
                "summary.class_decorator_identity_covers_overrides",
                format!("{identity_path}.direct"),
                "a class decorator identity claim cannot cover receiver overrides",
            );
        }
        if !identity.direct && identity.factory_keywords.is_none() {
            self.error(
                "summary.empty_class_decorator_identity",
                &identity_path,
                "a class decorator identity claim must be direct or describe factory keywords",
            );
        }
        if identity.direct {
            let accepts_implicit_class = if target.variadic {
                target
                    .parameter_count
                    .checked_sub(1)
                    .is_some_and(|minimum| minimum <= 1)
            } else {
                target.parameter_count == 1
            };
            if !accepts_implicit_class {
                self.error(
                    "summary.class_decorator_identity_arity",
                    format!("{identity_path}.direct"),
                    "a direct class decorator must accept exactly the implicit class argument",
                );
            }
        }
        let Some(keywords) = &identity.factory_keywords else {
            return;
        };
        if keywords.len() > MAX_CLASS_DECORATOR_FACTORY_KEYWORDS {
            self.error(
                "limit.class_decorator_factory_keywords",
                format!("{identity_path}.factory_keywords"),
                format!(
                    "class decorator identity declares more than {MAX_CLASS_DECORATOR_FACTORY_KEYWORDS} factory keywords"
                ),
            );
        }
        let mut seen_names = HashSet::new();
        for (index, keyword) in keywords.iter().enumerate() {
            let keyword_path = format!("{identity_path}.factory_keywords[{index}]");
            if keyword.name.is_empty() {
                self.error(
                    "summary.empty_class_decorator_factory_keyword",
                    format!("{keyword_path}.name"),
                    "class decorator factory keyword names must be non-empty",
                );
            }
            self.language_identifier(&format!("{keyword_path}.name"), &keyword.name);
            if !seen_names.insert(keyword.name.as_str()) {
                self.error(
                    "summary.duplicate_class_decorator_factory_keyword",
                    format!("{keyword_path}.name"),
                    format!(
                        "class decorator factory keyword `{}` is duplicated",
                        keyword.name
                    ),
                );
            }
            if keyword.allowed_values.is_empty() {
                self.error(
                    "summary.empty_class_decorator_factory_allowed_values",
                    format!("{keyword_path}.allowed_values"),
                    "class decorator factory keyword allowed_values must be non-empty",
                );
            }
            let mut seen_values = HashSet::new();
            for (value_index, value) in keyword.allowed_values.iter().enumerate() {
                if !seen_values.insert(*value) {
                    self.error(
                        "summary.duplicate_class_decorator_factory_allowed_value",
                        format!("{keyword_path}.allowed_values[{value_index}]"),
                        format!("class decorator factory allowed value `{value}` is duplicated"),
                    );
                }
            }
        }
    }

    fn signature(&mut self, path: &str, signature: &Signature, owner_type_parameters: &[String]) {
        self.unique_names(
            &format!("{path}.type_parameters"),
            &signature.type_parameters,
        );
        let mut available_type_parameters = owner_type_parameters.to_vec();
        available_type_parameters.extend(signature.type_parameters.iter().cloned());
        let mut parameter_names = HashSet::new();
        let mut positional_variadic = false;
        let mut named_variadic = false;
        let mut positional_variadic_index = None;
        for (index, parameter) in signature.parameters.iter().enumerate() {
            let parameter_path = format!("{path}.parameters[{index}]");
            if parameter.role.is_some()
                && self.predates_schema(TYPED_VALUES_AND_PARAMETER_ROLES_MIN_SCHEMA_VERSION)
            {
                self.error(
                    "parameter.role_schema_version",
                    format!("{parameter_path}.role"),
                    format!(
                        "callable parameter roles require schema version {TYPED_VALUES_AND_PARAMETER_ROLES_MIN_SCHEMA_VERSION}"
                    ),
                );
            }
            if positional_variadic_index.is_some()
                && !parameter.variadic
                && parameter.passing_mode.accepts_positional()
            {
                self.error(
                    "parameter.positional_after_variadic",
                    format!("{parameter_path}.passing_mode"),
                    "only named-only parameters may follow a positional variadic parameter",
                );
            }
            if let Some(variadic_kind) = parameter.variadic_kind() {
                if variadic_kind.accepts_positional() {
                    if positional_variadic {
                        self.error(
                            "parameter.duplicate_positional_variadic",
                            format!("{parameter_path}.variadic"),
                            "a signature may declare at most one positional variadic parameter",
                        );
                    }
                    positional_variadic = true;
                    positional_variadic_index = Some(index);
                }
                // A positional vararg may accept its own name without collecting
                // arbitrary keyword arguments. Only a named-only vararg is a
                // keyword collector, matching the formal-layout interpreter.
                if variadic_kind.accepts_keyword() {
                    if named_variadic {
                        self.error(
                            "parameter.duplicate_named_variadic",
                            format!("{parameter_path}.variadic"),
                            "a signature may declare at most one named variadic parameter",
                        );
                    }
                    named_variadic = true;
                    if index + 1 != signature.parameters.len() {
                        self.error(
                            "parameter.named_variadic_not_final",
                            format!("{parameter_path}.variadic"),
                            "a named variadic parameter must be final",
                        );
                    }
                }
            }
            if let Some(name) = &parameter.name {
                self.language_identifier(&format!("{parameter_path}.name"), name);
                if !parameter_names.insert(name) {
                    self.error(
                        "parameter.duplicate",
                        format!("{parameter_path}.name"),
                        format!("duplicate parameter `{name}`"),
                    );
                }
            }
            self.type_ref(
                &format!("{parameter_path}.type"),
                &parameter.r#type,
                &available_type_parameters,
            );
        }
        if let Some(returns) = &signature.returns {
            self.type_ref(
                &format!("{path}.returns"),
                returns,
                &available_type_parameters,
            );
        }
    }

    fn structured_type_expression(
        &mut self,
        path: &str,
        expression: &StructuredTypeExpression,
        type_parameters: &[String],
    ) {
        if expression.display.trim().is_empty() {
            self.error(
                "type_expression.empty_display",
                format!("{path}.display"),
                "structured type expression display must not be empty",
            );
        }
        for (index, type_ref) in expression.referenced_types.iter().enumerate() {
            self.type_ref(
                &format!("{path}.referenced_types[{index}]"),
                type_ref,
                type_parameters,
            );
        }
    }

    fn rust_contract_version(&mut self, path: &str) {
        if self.predates_schema(RUST_DECLARATION_CONTRACT_MIN_SCHEMA_VERSION) {
            self.error(
                "declaration.rust_contract_schema_version",
                path,
                "Rust declaration contracts require schema version 18",
            );
        }
        if self.language != "rust" {
            self.error(
                "declaration.rust_contract_language",
                path,
                "Rust declaration contracts require language rust",
            );
        }
    }

    fn implemented_trait(
        &mut self,
        path: &str,
        fact: &ImplementedTraitFact,
        parameters: &[String],
    ) {
        let mut pending = vec![(fact, parameters.to_vec(), 1usize)];
        while let Some((fact, outer_parameters, depth)) = pending.pop() {
            if depth > self.limits.max_depth {
                self.error(
                    "limit.type_depth",
                    path,
                    "implementation bounds exceeded type depth",
                );
                continue;
            }
            if fact.is_negative
                || fact.self_pattern.is_some()
                || !fact.bounds.is_empty()
                || !fact.type_parameters.is_empty()
            {
                if self.predates_schema(19) {
                    self.error(
                        "declaration.impl_conditions_schema_version",
                        path,
                        "implementation conditions require schema version 19",
                    );
                }
                self.rust_contract_version(path);
            }
            let parameters = if fact.self_pattern.is_some() {
                self.unique_names(path, &fact.type_parameters);
                let mut parameters = fact.type_parameters.clone();
                parameters.push("Self".to_owned());
                parameters
            } else {
                outer_parameters
            };
            self.type_ref(&format!("{path}.trait_type"), &fact.trait_type, &parameters);
            if let Some(pattern) = &fact.self_pattern {
                self.rust_self_pattern(&format!("{path}.self_pattern"), pattern, &parameters);
            }
            let mut names = std::collections::HashSet::new();
            for (index, binding) in fact.associated_types.iter().enumerate() {
                let binding_path = format!("{path}.associated_types[{index}]");
                self.language_identifier(&binding_path, &binding.name);
                if !names.insert(&binding.name) {
                    self.error(
                        "declaration.duplicate_associated_type",
                        &binding_path,
                        "duplicate associated type binding",
                    );
                }
                self.type_ref(&binding_path, &binding.r#type, &parameters);
            }
            for bound in &fact.bounds {
                self.type_ref(path, &bound.subject, &parameters);
                pending.push((&bound.bound, parameters.clone(), depth + 1));
            }
        }
    }

    fn rust_self_pattern(&mut self, path: &str, pattern: &RustSelfPattern, parameters: &[String]) {
        let mut pending = vec![(pattern, 1)];
        while let Some((pattern, depth)) = pending.pop() {
            if depth > self.limits.max_depth {
                self.error(
                    "limit.type_depth",
                    path,
                    "Rust self pattern exceeded type depth",
                );
                continue;
            }
            match pattern {
                RustSelfPattern::Parameter { name } => {
                    if !parameters.contains(name) {
                        self.error(
                            "type.unknown_parameter",
                            path,
                            format!("unknown self pattern parameter {name:?}"),
                        );
                    }
                }
                RustSelfPattern::Reference { inner, .. } => pending.push((inner, depth + 1)),
                RustSelfPattern::Constructor { owner, arguments } => {
                    self.type_ref(path, owner, parameters);
                    pending.extend(arguments.iter().map(|argument| (argument, depth + 1)));
                }
            }
        }
    }

    fn type_ref(&mut self, path: &str, root: &TypeRef, type_parameters: &[String]) {
        let mut stack = vec![(root, 1usize, path.to_owned())];
        while let Some((reference, depth, current_path)) = stack.pop() {
            if depth > self.limits.max_depth {
                self.error(
                    "limit.type_depth",
                    current_path,
                    format!("type nesting exceeds depth {}", self.limits.max_depth),
                );
                continue;
            }
            match reference {
                TypeRef::Projection {
                    owner,
                    trait_type,
                    name,
                    arguments,
                } => {
                    self.rust_contract_version(&current_path);
                    self.language_identifier(&format!("{current_path}.name"), name);
                    stack.push((owner, depth + 1, format!("{current_path}.owner")));
                    if let Some(trait_type) = trait_type {
                        stack.push((trait_type, depth + 1, format!("{current_path}.trait_type")));
                    }
                    stack.extend(arguments.iter().enumerate().map(|(index, ty)| {
                        (ty, depth + 1, format!("{current_path}.arguments[{index}]"))
                    }));
                }
                TypeRef::Named {
                    name, arguments, ..
                } => {
                    self.qualified_name(&format!("{current_path}.name"), name);
                    if let Some(package) = &self.go_current_package
                        && self
                            .go_local_types
                            .contains(&(package.clone(), name.clone()))
                    {
                        self.error(
                            "go.local_type_bare_reference",
                            &current_path,
                            "reference the package-local type with Declared; a bare Named spelling of a Go universe type means the universe type",
                        );
                    }

                    for (index, argument) in arguments.iter().enumerate().rev() {
                        stack.push((
                            argument,
                            depth + 1,
                            format!("{current_path}.arguments[{index}]"),
                        ));
                    }
                }
                TypeRef::Declared { id, arguments, .. } => {
                    self.stable_reference(&format!("{current_path}.id"), id);
                    if self.validate_references && !self.declaration_ids.contains(id) {
                        self.error(
                            "reference.missing_declaration",
                            format!("{current_path}.id"),
                            format!("unknown declaration id `{id}`"),
                        );
                    }
                    for (index, argument) in arguments.iter().enumerate().rev() {
                        stack.push((
                            argument,
                            depth + 1,
                            format!("{current_path}.arguments[{index}]"),
                        ));
                    }
                }
                TypeRef::TypeParameter { name } => {
                    self.language_identifier(&format!("{current_path}.name"), name);
                    if !type_parameters.contains(name) {
                        self.error(
                            "type.unknown_parameter",
                            format!("{current_path}.name"),
                            format!("unknown type parameter `{name}`"),
                        );
                    }
                }
                TypeRef::Array { element }
                | TypeRef::ByRef { element, .. }
                | TypeRef::Pointer { element }
                | TypeRef::Slice { element }
                | TypeRef::Channel { element, .. } => {
                    stack.push((element, depth + 1, format!("{current_path}.element")))
                }
                TypeRef::FixedArray { element, length } => {
                    self.text(&format!("{current_path}.length"), length);
                    stack.push((element, depth + 1, format!("{current_path}.element")));
                }
                TypeRef::Map { key, value } => {
                    stack.push((value, depth + 1, format!("{current_path}.value")));
                    stack.push((key, depth + 1, format!("{current_path}.key")));
                }
                TypeRef::Wildcard { variance, bound } => {
                    if matches!(variance, WildcardVariance::Any) && bound.is_some() {
                        self.error(
                            "type.wildcard_any_bound",
                            &current_path,
                            "an unbounded wildcard cannot declare a bound",
                        );
                    }
                    if !matches!(variance, WildcardVariance::Any) && bound.is_none() {
                        self.error(
                            "type.wildcard_missing_bound",
                            &current_path,
                            "a variant wildcard requires a bound",
                        );
                    }
                    if let Some(bound) = bound {
                        stack.push((bound, depth + 1, format!("{current_path}.bound")));
                    }
                }
                TypeRef::Tuple { elements } => {
                    if elements.is_empty() && self.language == "rust" {
                        self.rust_contract_version(&current_path);
                    } else if elements.is_empty() {
                        self.error(
                            "type.empty_tuple",
                            &current_path,
                            "tuple types must contain at least one element",
                        );
                    }
                    for (index, element) in elements.iter().enumerate().rev() {
                        stack.push((
                            element,
                            depth + 1,
                            format!("{current_path}.elements[{index}]"),
                        ));
                    }
                }
                TypeRef::Function { parameters, result } => {
                    if let Some(result) = result {
                        stack.push((result, depth + 1, format!("{current_path}.result")));
                    }
                    let mut parameter_names = HashSet::new();
                    for (index, parameter) in parameters.iter().enumerate().rev() {
                        let parameter_path = format!("{current_path}.parameters[{index}]");
                        if let Some(name) = &parameter.name {
                            self.language_identifier(&format!("{parameter_path}.name"), name);
                            if !parameter_names.insert(name) {
                                self.error(
                                    "parameter.duplicate",
                                    format!("{parameter_path}.name"),
                                    format!("duplicate parameter `{name}`"),
                                );
                            }
                        }
                        stack.push((
                            &parameter.r#type,
                            depth + 1,
                            format!("{parameter_path}.type"),
                        ));
                    }
                }
                TypeRef::Unknown => {
                    if self.predates_schema(UNKNOWN_TYPE_MIN_SCHEMA_VERSION) {
                        self.error(
                            "schema.unknown_type_version",
                            &current_path,
                            format!(
                                "unknown type references require schema version {UNKNOWN_TYPE_MIN_SCHEMA_VERSION}"
                            ),
                        );
                    }
                }
            }
        }
    }

    fn rule(&mut self, path: &str, rule: &GeneratorRule) {
        self.stable_id(&format!("{path}.id"), &rule.id);
        match &rule.trigger {
            RuleTrigger::LanguageConstruct { construct } => {
                self.stable_component(&format!("{path}.trigger.construct"), construct);
            }
            RuleTrigger::Annotation { name }
            | RuleTrigger::MacroInvocation { name }
            | RuleTrigger::GeneratorInvocation { name } => {
                self.qualified_name(&format!("{path}.trigger.name"), name);
            }
            RuleTrigger::AnnotatedField {
                annotation,
                value,
                excluded_annotations,
                owner_annotation_path,
            } => {
                self.qualified_name(&format!("{path}.trigger.annotation"), annotation);
                if value.as_ref().is_some_and(String::is_empty) {
                    self.error(
                        "trigger.empty_annotation_value",
                        format!("{path}.trigger.value"),
                        "an annotation value must not be empty",
                    );
                }
                for (index, excluded) in excluded_annotations.iter().enumerate() {
                    self.qualified_name(
                        &format!("{path}.trigger.excluded_annotations[{index}]"),
                        excluded,
                    );
                }
                if owner_annotation_path.is_empty() {
                    self.error(
                        "trigger.empty_owner_annotation_path",
                        format!("{path}.trigger.owner_annotation_path"),
                        "owner annotation path must contain at least one identifier",
                    );
                }
                for (index, segment) in owner_annotation_path.iter().enumerate() {
                    self.language_identifier(
                        &format!("{path}.trigger.owner_annotation_path[{index}]"),
                        segment,
                    );
                }
            }
            RuleTrigger::ResolvedOwner { owner } => {
                self.qualified_name(&format!("{path}.trigger.owner"), owner);
            }
            RuleTrigger::ResolvedCall { owner, name } => {
                self.qualified_name(&format!("{path}.trigger.owner"), owner);
                self.language_identifier(&format!("{path}.trigger.name"), name);
            }
        }
        let mut captures = HashMap::new();
        for (index, capture) in rule.captures.iter().enumerate() {
            let capture_path = format!("{path}.captures[{index}].name");
            self.stable_component(&capture_path, &capture.name);
            self.capture_binding(&format!("{path}.captures[{index}]"), capture, &rule.trigger);
            if captures.insert(capture.name.as_str(), capture).is_some() {
                self.error(
                    "capture.duplicate",
                    capture_path,
                    format!("duplicate capture `{}`", capture.name),
                );
            }
        }
        if rule.emissions.is_empty() {
            self.error(
                "rule.no_emissions",
                format!("{path}.emissions"),
                "a generator rule must emit at least one fact",
            );
        }
        for (index, emission) in rule.emissions.iter().enumerate() {
            let emission_path = format!("{path}.emissions[{index}]");
            match emission {
                RuleEmission::Declaration {
                    id,
                    name,
                    anchor,
                    declaration,
                } => {
                    self.template(
                        &format!("{emission_path}.id"),
                        id,
                        &captures,
                        TemplatePosition::StableId,
                    );
                    self.template(
                        &format!("{emission_path}.name"),
                        name,
                        &captures,
                        TemplatePosition::LanguageName,
                    );
                    if let Some(anchor) = anchor {
                        if !matches!(anchor, TemplateExpression::Capture { .. }) {
                            self.error(
                                "anchor.unsupported_expression",
                                format!("{emission_path}.anchor"),
                                "an authored anchor must be one direct capture",
                            );
                        }
                        self.template(
                            &format!("{emission_path}.anchor"),
                            anchor,
                            &captures,
                            TemplatePosition::LanguageName,
                        );
                    }
                    match declaration {
                        EmittedDeclaration::Type {
                            type_parameters,
                            hierarchy,
                            extension_surfaces,
                            ..
                        } => {
                            for (parameter_index, parameter) in type_parameters.iter().enumerate() {
                                self.template(
                                    &format!(
                                        "{emission_path}.declaration.type_parameters[{parameter_index}]"
                                    ),
                                    parameter,
                                    &captures,
                                    TemplatePosition::LanguageName,
                                );
                            }
                            for (hierarchy_index, hierarchy) in hierarchy.iter().enumerate() {
                                self.template_type(
                                    &format!(
                                        "{emission_path}.declaration.hierarchy[{hierarchy_index}].target"
                                    ),
                                    &hierarchy.target,
                                    &captures,
                                );
                            }
                            for (surface_index, surface) in extension_surfaces.iter().enumerate() {
                                self.template(
                                    &format!(
                                        "{emission_path}.declaration.extension_surfaces[{surface_index}]"
                                    ),
                                    surface,
                                    &captures,
                                    TemplatePosition::LanguageName,
                                );
                            }
                        }
                        EmittedDeclaration::Member {
                            owner,
                            member_kind,
                            signature,
                            ..
                        } => {
                            if let Some(owner) = owner {
                                self.template(
                                    &format!("{emission_path}.declaration.owner"),
                                    owner,
                                    &captures,
                                    TemplatePosition::StableId,
                                );
                            } else if !matches!(
                                member_kind,
                                MemberKind::Function | MemberKind::Macro
                            ) {
                                self.error(
                                    "declaration.owner_required",
                                    format!("{emission_path}.declaration.owner"),
                                    "only top-level functions and macros can omit an owner",
                                );
                            }
                            if let Some(signature) = signature {
                                self.template_signature(
                                    &format!("{emission_path}.declaration.signature"),
                                    signature,
                                    &captures,
                                );
                            }
                        }
                    }
                }
                RuleEmission::Alias { id, from, to }
                | RuleEmission::Relation { id, from, to, .. } => {
                    self.template(
                        &format!("{emission_path}.id"),
                        id,
                        &captures,
                        TemplatePosition::StableId,
                    );
                    self.template(
                        &format!("{emission_path}.from"),
                        from,
                        &captures,
                        TemplatePosition::StableId,
                    );
                    self.template(
                        &format!("{emission_path}.to"),
                        to,
                        &captures,
                        TemplatePosition::StableId,
                    );
                }
            }
        }
    }

    fn capture_binding(&mut self, path: &str, capture: &CaptureDeclaration, trigger: &RuleTrigger) {
        let expected_kind = match capture.binding.projection {
            CaptureProjection::Name => CaptureValueKind::Identifier,
            CaptureProjection::StableId => CaptureValueKind::StableId,
            CaptureProjection::Type => CaptureValueKind::Type,
            CaptureProjection::Text => CaptureValueKind::String,
            CaptureProjection::Path => CaptureValueKind::Path,
        };
        if capture.value_kind != expected_kind {
            self.error(
                "capture.binding_type_mismatch",
                format!("{path}.value_kind"),
                format!(
                    "binding projection requires value kind `{}`",
                    capture_value_kind_name(expected_kind)
                ),
            );
        }
        let expected_cardinality = match capture.binding.source {
            CaptureSource::MatchedNode
            | CaptureSource::EnclosingDeclaration
            | CaptureSource::OwningType
            | CaptureSource::ResolvedOwner => CaptureCardinality::One,
            CaptureSource::OwnedFields | CaptureSource::OwnedMutableFields => {
                CaptureCardinality::Many
            }
            CaptureSource::OwnedUninitializedFinalFields => CaptureCardinality::Group,
            CaptureSource::Argument { .. } | CaptureSource::AnnotationArgument { .. } => {
                CaptureCardinality::Optional
            }
            CaptureSource::Arguments { .. } => CaptureCardinality::Many,
        };
        if capture.cardinality != expected_cardinality {
            self.error(
                "capture.binding_cardinality_mismatch",
                format!("{path}.cardinality"),
                format!(
                    "capture source requires cardinality `{}`",
                    capture_cardinality_name(expected_cardinality)
                ),
            );
        }
        let compatible = match capture.binding.source {
            CaptureSource::AnnotationArgument { .. } => {
                matches!(trigger, RuleTrigger::Annotation { .. })
            }
            CaptureSource::Argument { .. } | CaptureSource::Arguments { .. } => matches!(
                trigger,
                RuleTrigger::LanguageConstruct { .. }
                    | RuleTrigger::MacroInvocation { .. }
                    | RuleTrigger::GeneratorInvocation { .. }
                    | RuleTrigger::ResolvedCall { .. }
            ),
            CaptureSource::ResolvedOwner => matches!(
                trigger,
                RuleTrigger::ResolvedOwner { .. } | RuleTrigger::ResolvedCall { .. }
            ),
            CaptureSource::MatchedNode
            | CaptureSource::EnclosingDeclaration
            | CaptureSource::OwningType
            | CaptureSource::OwnedFields
            | CaptureSource::OwnedMutableFields
            | CaptureSource::OwnedUninitializedFinalFields => true,
        };
        if !compatible {
            self.error(
                "capture.binding_incompatible_trigger",
                format!("{path}.binding.source"),
                "capture source is not available from this trigger kind",
            );
        }
        if let CaptureSource::AnnotationArgument { name } = &capture.binding.source {
            self.language_identifier(&format!("{path}.binding.source.name"), name);
        }
    }

    fn template_signature(
        &mut self,
        path: &str,
        signature: &TemplateSignature,
        captures: &HashMap<&str, &CaptureDeclaration>,
    ) {
        for (index, parameter) in signature.type_parameters.iter().enumerate() {
            self.template(
                &format!("{path}.type_parameters[{index}]"),
                parameter,
                captures,
                TemplatePosition::LanguageName,
            );
        }
        for (index, parameter) in signature.parameters.iter().enumerate() {
            self.template(
                &format!("{path}.parameters[{index}].name"),
                &parameter.name,
                captures,
                TemplatePosition::LanguageName,
            );
            self.template_type(
                &format!("{path}.parameters[{index}].type"),
                &parameter.r#type,
                captures,
            );
        }
        for (index, parameter) in signature.repeated_parameters.iter().enumerate() {
            self.template(
                &format!("{path}.repeated_parameters[{index}].name"),
                &parameter.name,
                captures,
                TemplatePosition::LanguageName,
            );
            self.template_type(
                &format!("{path}.repeated_parameters[{index}].type"),
                &parameter.r#type,
                captures,
            );
        }
        if let Some(returns) = &signature.returns {
            self.template_type(&format!("{path}.returns"), returns, captures);
        }
    }

    fn template_type(
        &mut self,
        path: &str,
        root: &TemplateTypeRef,
        captures: &HashMap<&str, &CaptureDeclaration>,
    ) {
        let mut stack = vec![(root, 1usize, path.to_owned())];
        while let Some((reference, depth, current_path)) = stack.pop() {
            if depth > self.limits.max_depth {
                self.error(
                    "limit.template_type_depth",
                    current_path,
                    format!(
                        "template type nesting exceeds depth {}",
                        self.limits.max_depth
                    ),
                );
                continue;
            }
            match reference {
                TemplateTypeRef::Named {
                    name, arguments, ..
                } => {
                    self.template(
                        &format!("{current_path}.name"),
                        name,
                        captures,
                        TemplatePosition::LanguageName,
                    );
                    for (index, argument) in arguments.iter().enumerate().rev() {
                        stack.push((
                            argument,
                            depth + 1,
                            format!("{current_path}.arguments[{index}]"),
                        ));
                    }
                }
                TemplateTypeRef::Capture { name } => match captures.get(name.as_str()) {
                    None => self.error(
                        "capture.unknown",
                        format!("{current_path}.name"),
                        format!("unknown capture `{name}`"),
                    ),
                    Some(capture) if capture.value_kind != CaptureValueKind::Type => self.error(
                        "capture.type_mismatch",
                        format!("{current_path}.name"),
                        format!("capture `{name}` is not a type capture"),
                    ),
                    Some(capture) if capture.cardinality == CaptureCardinality::Optional => self
                        .error(
                            "capture.cardinality",
                            format!("{current_path}.name"),
                            format!("capture `{name}` must have cardinality `one` here"),
                        ),
                    Some(_) => {}
                },
                TemplateTypeRef::Array { element } | TemplateTypeRef::ByRef { element } => {
                    stack.push((element, depth + 1, format!("{current_path}.element")))
                }
            }
        }
    }

    fn template(
        &mut self,
        path: &str,
        root: &TemplateExpression,
        captures: &HashMap<&str, &CaptureDeclaration>,
        position: TemplatePosition,
    ) {
        if matches!(position, TemplatePosition::StableId)
            && !stable_id_template_has_valid_boundaries(root, self.limits.max_depth)
        {
            self.error(
                "template.invalid_identifier_boundary",
                path,
                "stable-id templates must begin and end with a lowercase ASCII alphanumeric",
            );
        }
        let mut stack = vec![(root, 1usize, path.to_owned(), true, position)];
        while let Some((expression, depth, current_path, is_root, position)) = stack.pop() {
            if depth > self.limits.max_depth {
                self.error(
                    "limit.template_depth",
                    current_path,
                    format!("template nesting exceeds depth {}", self.limits.max_depth),
                );
                continue;
            }
            match expression {
                TemplateExpression::Literal { value } => {
                    self.text(&format!("{current_path}.value"), value);
                    match position {
                        TemplatePosition::StableId
                            if is_root && validate_identifier(value, 256, true).is_err() =>
                        {
                            self.error(
                                "template.invalid_identifier_literal",
                                format!("{current_path}.value"),
                                "literal used as a stable id is not valid",
                            );
                        }
                        TemplatePosition::StableId if !is_root && !is_stable_id_fragment(value) => {
                            self.error(
                                "template.invalid_identifier_literal",
                                format!("{current_path}.value"),
                                "stable-id fragments may contain only lowercase ASCII alphanumerics, dot, dash, or underscore",
                            );
                        }
                        TemplatePosition::LanguageName if !is_language_name_fragment(value) => {
                            self.error(
                                "template.invalid_name_literal",
                                format!("{current_path}.value"),
                                "language-name fragments must be printable and contain no whitespace",
                            );
                        }
                        _ => {}
                    }
                }
                TemplateExpression::Capture { name } => match captures.get(name.as_str()) {
                    None => self.error(
                        "capture.unknown",
                        format!("{current_path}.name"),
                        format!("unknown capture `{name}`"),
                    ),
                    Some(capture) if capture.cardinality == CaptureCardinality::Optional => self
                        .error(
                            "capture.cardinality",
                            format!("{current_path}.name"),
                            format!("capture `{name}` must have cardinality `one` here"),
                        ),
                    Some(capture)
                        if matches!(position, TemplatePosition::StableId)
                            && capture.value_kind != CaptureValueKind::StableId =>
                    {
                        self.error(
                            "capture.type_mismatch",
                            format!("{current_path}.name"),
                            format!("capture `{name}` is not a stable-id capture"),
                        );
                    }
                    Some(capture)
                        if matches!(position, TemplatePosition::LanguageName)
                            && !matches!(
                                capture.value_kind,
                                CaptureValueKind::Identifier | CaptureValueKind::StableId
                            ) =>
                    {
                        self.error(
                            "capture.type_mismatch",
                            format!("{current_path}.name"),
                            format!("capture `{name}` is not an identifier capture"),
                        );
                    }
                    Some(_) => {}
                },
                TemplateExpression::Concat { values } => {
                    if values.is_empty() {
                        self.error(
                            "template.empty_concat",
                            &current_path,
                            "concat must contain at least one expression",
                        );
                    }
                    for (index, value) in values.iter().enumerate().rev() {
                        stack.push((
                            value,
                            depth + 1,
                            format!("{current_path}.values[{index}]"),
                            false,
                            position,
                        ));
                    }
                }
                TemplateExpression::Transform { transform, value } => {
                    if matches!(position, TemplatePosition::StableId)
                        && matches!(
                            transform,
                            AsciiTransform::Uppercase
                                | AsciiTransform::PascalCase
                                | AsciiTransform::CamelCase
                        )
                    {
                        self.error(
                            "template.unsupported_transform",
                            format!("{current_path}.transform"),
                            "this transform can emit characters forbidden in stable ids",
                        );
                    }
                    stack.push((
                        value,
                        depth + 1,
                        format!("{current_path}.value"),
                        is_root,
                        position,
                    ))
                }
                TemplateExpression::Conditional {
                    condition,
                    then_value,
                    else_value,
                } => {
                    let (left, right) = match condition {
                        crate::analyzer::semantic_model::TemplateCondition::Equals {
                            left,
                            right,
                        } => (left, right),
                        crate::analyzer::semantic_model::TemplateCondition::StartsWith {
                            value,
                            prefix,
                        } => (value, prefix),
                    };
                    stack.push((
                        else_value,
                        depth + 1,
                        format!("{current_path}.else"),
                        is_root,
                        position,
                    ));
                    stack.push((
                        then_value,
                        depth + 1,
                        format!("{current_path}.then"),
                        is_root,
                        position,
                    ));
                    stack.push((
                        right,
                        depth + 1,
                        format!("{current_path}.condition.right"),
                        false,
                        TemplatePosition::Condition,
                    ));
                    stack.push((
                        left,
                        depth + 1,
                        format!("{current_path}.condition.left"),
                        false,
                        TemplatePosition::Condition,
                    ));
                }
            }
        }
    }

    fn locator(&mut self, path: &str, locator: &Locator) {
        match locator {
            Locator::Source {
                path: value,
                symbol,
            } => {
                self.locator_path(&format!("{path}.path"), value);
                if let Some(symbol) = symbol {
                    self.text(&format!("{path}.symbol"), symbol);
                }
            }
            Locator::Artifact {
                path: value,
                symbol,
            } => {
                self.locator_path(&format!("{path}.path"), value);
                self.text(&format!("{path}.symbol"), symbol);
            }
            Locator::Interchange {
                path: value,
                symbol,
                identity,
                ..
            } => {
                self.locator_path(&format!("{path}.path"), value);
                self.text(&format!("{path}.symbol"), symbol);
                if let Err(message) =
                    crate::analyzer::semantic_model::csmi::python::validate_identity(identity)
                {
                    self.error("locator.interchange_identity", path, message);
                }
            }
        }
    }

    /// A guard names activation targets, so its target names obey the same
    /// text rules as the activation selectors they are compared against.
    fn declaration_guard(&mut self, path: &str, guard: Option<&DeclarationGuard>) {
        let Some(guard) = guard else {
            return;
        };
        for (field, targets) in [
            ("required_targets", &guard.required_targets),
            ("excluded_targets", &guard.excluded_targets),
        ] {
            for (index, target) in targets.iter().enumerate() {
                self.text(&format!("{path}.guard.{field}[{index}]"), target);
            }
        }
    }

    fn stable_id(&mut self, path: &str, value: &str) {
        if let Err(error) = validate_identifier(value, 256, true) {
            self.error("identifier.invalid", path, error.to_string());
        }
        if let Some(first_path) = self.stable_ids.insert(value.to_owned(), path.to_owned()) {
            self.error(
                "identifier.duplicate",
                path,
                format!("stable id `{value}` was already declared at {first_path}"),
            );
        }
    }

    fn stable_component(&mut self, path: &str, value: &str) {
        if let Err(error) = validate_identifier(value, 256, true) {
            self.error("identifier.invalid", path, error.to_string());
        }
    }

    fn stable_reference(&mut self, path: &str, value: &str) {
        if let Err(error) = validate_identifier(value, 256, true) {
            self.error("identifier.invalid_reference", path, error.to_string());
        }
    }

    fn language_identifier(&mut self, path: &str, value: &str) {
        self.text(path, value);
        let scala_escaped = value
            .strip_prefix('`')
            .and_then(|value| value.strip_suffix('`'))
            .is_some_and(|value| {
                !value.is_empty()
                    && !value
                        .chars()
                        .any(|character| character == '`' || character.is_control())
            });
        if !scala_escaped
            && value
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
        {
            self.error(
                "name.invalid_identifier",
                path,
                "language identifiers must contain no whitespace or control characters unless enclosed in Scala backticks",
            );
        }
    }

    fn qualified_name(&mut self, path: &str, value: &str) {
        self.text(path, value);
        if value.trim().is_empty() || value.chars().any(char::is_whitespace) {
            self.error(
                "name.invalid",
                path,
                "qualified names must be non-empty and contain no whitespace",
            );
        }
    }

    fn unique_names(&mut self, path: &str, values: &[String]) {
        let mut seen = HashSet::new();
        for (index, value) in values.iter().enumerate() {
            self.language_identifier(&format!("{path}[{index}]"), value);
            if !seen.insert(value) {
                self.error(
                    "name.duplicate",
                    format!("{path}[{index}]"),
                    format!("duplicate name `{value}`"),
                );
            }
        }
    }

    fn version(&mut self, path: &str, value: &str) {
        self.text(path, value);
        if Version::parse(value).is_err() {
            self.error("version.invalid", path, "expected a semantic version");
        }
    }

    fn version_requirement(&mut self, path: &str, value: &str) {
        self.text(path, value);
        if VersionReq::parse(value).is_err() {
            self.error(
                "version.invalid_requirement",
                path,
                "expected a semantic-version requirement",
            );
        }
    }

    fn text(&mut self, path: &str, value: &str) {
        if value.is_empty() {
            self.error("text.empty", path, "value must not be empty");
        }
        if value.len() > self.limits.max_text_bytes {
            self.error(
                "limit.text_bytes",
                path,
                format!("text exceeds {} bytes", self.limits.max_text_bytes),
            );
        }
        if value.contains('\0') {
            self.error("text.nul", path, "text must not contain NUL characters");
        }
    }

    fn locator_path(&mut self, path: &str, value: &str) {
        self.text(path, value);
        if !is_canonical_relative_path(value) {
            self.error(
                "locator.invalid_path",
                path,
                "locator paths must be relative canonical slash-separated paths",
            );
        }
    }

    fn error(
        &mut self,
        code: impl Into<String>,
        path: impl Into<String>,
        message: impl Into<String>,
    ) {
        self.diagnostics
            .push(Diagnostic::error(code, path, message));
    }

    /// Records that the pack uses a field introduced in schema `minimum` and
    /// returns whether the pack declares an older version. Every per-field
    /// version gate goes through here, so the walk that enforces the gates
    /// also yields the lowest version a pack can be written at (#6251).
    fn predates_schema(&mut self, minimum: u32) -> bool {
        self.required_schema_version = self.required_schema_version.max(minimum);
        self.schema_version < minimum
    }

    /// A reader that accepts more than one schema version must still hold each
    /// pack to the shape its own version number promises. A version-two reader
    /// rejects unknown fields, so a version-two pack carrying `ambient_use`
    /// would load here and fail there, which is the failure the new version
    /// number exists to prevent.
    fn ambient_use_version(&mut self, fact_path: &str) {
        if self.predates_schema(AMBIENT_USE_MIN_SCHEMA_VERSION) {
            self.error(
                "schema.ambient_use_requires_version",
                format!("{fact_path}.ambient_use"),
                format!(
                    "ambient_use requires schema version {AMBIENT_USE_MIN_SCHEMA_VERSION}, found {}",
                    self.schema_version
                ),
            );
        }
    }
}

fn runtime_active_set_digest(exposure_ids: &[String]) -> String {
    let encoded = serde_json::to_vec(exposure_ids)
        .expect("runtime exposure identifiers are always JSON serializable");
    let mut digest = Sha256::new();
    digest.update(encoded);
    format!("{:x}", digest.finalize())
}

/// Whether one activation selector binds exactly the artifact applicability a
/// runtime record claims.
///
/// A record that claims no artifact is bound by a selector that carries no
/// artifact evidence: the reviewed contract is a property of the language, so
/// a selector naming a distribution would bind a claim the record never made.
fn runtime_artifact_matches_selector(
    runtime: &RuntimeApplicability,
    selector: &ActivationSelector,
) -> bool {
    let (Some(artifact), Some(artifact_digest)) = (
        runtime.runtime_artifact.as_deref(),
        runtime.runtime_artifact_digest.as_deref(),
    ) else {
        return selector.artifact_sha256.is_none() && selector.package.is_none();
    };
    if selector.artifact_sha256.as_deref() != Some(artifact_digest) {
        return false;
    }
    let Some(package) = selector.package.as_ref() else {
        return false;
    };
    if package.version.is_none() && package.name == artifact {
        return true;
    }
    let Some(raw) = artifact.strip_prefix("pkg:maven/") else {
        return false;
    };
    let Some((coordinate, version)) = raw.split_once('@') else {
        return false;
    };
    let Some((group, artifact)) = coordinate.rsplit_once('/') else {
        return false;
    };
    package.name == format!("{group}:{artifact}") && package.version.as_deref() == Some(version)
}

fn cpp_signature_matches_operation(
    operation: CppSpecialMemberOperation,
    signature: &CppCallableSignature,
    owner: &str,
) -> bool {
    match operation {
        CppSpecialMemberOperation::CopyConstructor => {
            signature.callable_kind == CppCallableKind::Constructor
                && signature.receiver.is_none()
                && signature.result.is_none()
                && signature.parameters.len() == 1
                && cpp_reference_to_owner(
                    &signature.parameters[0],
                    CppReferenceKind::Lvalue,
                    true,
                    owner,
                )
        }
        CppSpecialMemberOperation::CopyAssignment => {
            signature.callable_kind == CppCallableKind::Method
                && signature.receiver.as_ref().is_some_and(|value| {
                    cpp_reference_to_owner(value, CppReferenceKind::Lvalue, false, owner)
                })
                && signature.parameters.len() == 1
                && cpp_reference_to_owner(
                    &signature.parameters[0],
                    CppReferenceKind::Lvalue,
                    true,
                    owner,
                )
                && signature.result.as_ref().is_some_and(|value| {
                    cpp_reference_to_owner(value, CppReferenceKind::Lvalue, false, owner)
                })
        }
        CppSpecialMemberOperation::MoveConstructor => {
            signature.callable_kind == CppCallableKind::Constructor
                && signature.receiver.is_none()
                && signature.result.is_none()
                && signature.parameters.len() == 1
                && cpp_reference_to_owner(
                    &signature.parameters[0],
                    CppReferenceKind::Rvalue,
                    false,
                    owner,
                )
        }
    }
}

fn cpp_reference_to_owner(
    value: &CppCanonicalType,
    expected_kind: CppReferenceKind,
    expect_const: bool,
    owner: &str,
) -> bool {
    let CppCanonicalType::Reference {
        reference_kind,
        referent,
    } = value
    else {
        return false;
    };
    if *reference_kind != expected_kind {
        return false;
    }
    let referent = if expect_const {
        let CppCanonicalType::Qualified { qualifiers, r#type } = referent.as_ref() else {
            return false;
        };
        if qualifiers.as_slice() != [CppTypeQualifier::Const] {
            return false;
        }
        r#type.as_ref()
    } else {
        referent.as_ref()
    };
    matches!(referent, CppCanonicalType::Declared { symbol } if symbol == owner)
}

#[derive(Debug, Clone, Copy)]
enum TemplatePosition {
    StableId,
    LanguageName,
    Condition,
}

fn is_stable_id_fragment(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        })
}

fn is_language_name_fragment(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|character| !character.is_control() && !character.is_whitespace())
}

fn stable_id_template_has_valid_boundaries(
    expression: &TemplateExpression,
    max_depth: usize,
) -> bool {
    stable_id_template_boundary(expression, true, max_depth)
        && stable_id_template_boundary(expression, false, max_depth)
}

fn stable_id_template_boundary(
    mut expression: &TemplateExpression,
    first: bool,
    max_depth: usize,
) -> bool {
    for _ in 0..max_depth {
        match expression {
            TemplateExpression::Literal { value } => {
                let boundary = if first {
                    value.as_bytes().first()
                } else {
                    value.as_bytes().last()
                };
                return boundary
                    .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
            }
            TemplateExpression::Capture { .. } => return true,
            TemplateExpression::Concat { values } => {
                let next = if first { values.first() } else { values.last() };
                let Some(next) = next else {
                    return false;
                };
                expression = next;
            }
            TemplateExpression::Transform { value, .. } => expression = value,
            TemplateExpression::Conditional {
                then_value,
                else_value,
                ..
            } => {
                return stable_id_template_boundary(then_value, first, max_depth)
                    && stable_id_template_boundary(else_value, first, max_depth);
            }
        }
    }
    false
}

fn capture_value_kind_name(kind: CaptureValueKind) -> &'static str {
    match kind {
        CaptureValueKind::Identifier => "identifier",
        CaptureValueKind::StableId => "stable_id",
        CaptureValueKind::Type => "type",
        CaptureValueKind::String => "string",
        CaptureValueKind::Path => "path",
    }
}

fn capture_cardinality_name(cardinality: CaptureCardinality) -> &'static str {
    match cardinality {
        CaptureCardinality::One => "one",
        CaptureCardinality::Optional => "optional",
        CaptureCardinality::Many => "many",
        CaptureCardinality::Group => "group",
    }
}

/// The path shape every pack locator and carried-source entry must have: a
/// relative, canonical, slash-separated path with no prefix, root, `.`/`..`
/// component, or backslash.
#[doc(hidden)]
pub fn is_canonical_relative_path(value: &str) -> bool {
    use std::path::{Component, Path};

    !(has_portable_windows_path_prefix(value)
        || value.contains('\\')
        || Path::new(value).components().any(|component| {
            matches!(
                component,
                Component::Prefix(_)
                    | Component::RootDir
                    | Component::ParentDir
                    | Component::CurDir
            )
        }))
}

// Use the same neutral semantic checks for native producer payloads and imported
// wire payloads. IDs stay native-local here; no display-name identity is created.
fn validate_native_profile_contracts(pack: &AuthoredSemanticModelPack) -> Vec<Diagnostic> {
    let model = native_contract_model(pack);
    let mut diagnostics =
        crate::analyzer::semantic_model::csmi::validate_native_deferred_yield_model(&model)
            .into_iter()
            .chain(
                crate::analyzer::semantic_model::csmi::validate_native_conditional_type_model(
                    &model,
                ),
            )
            .map(|diagnostic| {
                Diagnostic::error(diagnostic.code, diagnostic.path, diagnostic.message)
            })
            .collect::<Vec<_>>();
    for shard in &pack.shards {
        let Some(runtime_contracts) = &shard.runtime_contracts else {
            continue;
        };
        if let Err(errors) = runtime_contracts.validate() {
            diagnostics.extend(errors.into_iter().map(|diagnostic| {
                Diagnostic::error(
                    diagnostic.code,
                    format!(
                        "$.shards[{}/runtime_contracts]{}",
                        shard.id, diagnostic.path
                    ),
                    diagnostic.message,
                )
            }));
        }
    }
    diagnostics
}

fn native_contract_model(
    pack: &AuthoredSemanticModelPack,
) -> crate::analyzer::semantic_model::csmi::CsmiSemanticModel {
    use crate::analyzer::semantic_model::csmi::*;
    use serde_json::json;

    let mut declarations = Vec::new();
    let mut completeness = Vec::new();
    let mut occupied_declaration_symbols = pack
        .shards
        .iter()
        .filter_map(|shard| match &shard.payload {
            AuthoredPayload::DeclarationFacts { types, members, .. } => Some(
                types
                    .iter()
                    .map(|ty| ty.id.clone())
                    .chain(members.iter().map(|member| member.id.clone())),
            ),
            _ => None,
        })
        .flatten()
        .collect::<HashSet<_>>();
    let mut next_binder_id = 0usize;
    let mut generic_parameters = HashMap::new();
    let mut generic_binders = HashMap::new();
    for ty in pack
        .shards
        .iter()
        .filter_map(|shard| match &shard.payload {
            AuthoredPayload::DeclarationFacts { types, .. } => Some(types),
            _ => None,
        })
        .flatten()
    {
        let binders = native_generic_binder_symbols(
            ty.type_parameters.len(),
            &mut occupied_declaration_symbols,
            &mut next_binder_id,
        );
        generic_parameters.insert(ty.id.clone(), ty.type_parameters.clone());
        generic_binders.insert(ty.id.clone(), binders);
    }
    for shard in &pack.shards {
        let AuthoredPayload::DeclarationFacts { types, members, .. } = &shard.payload else {
            continue;
        };
        for ty in types {
            let category = if ty.type_kind == TypeKind::Module {
                "namespace"
            } else {
                "type"
            };
            let mut declaration = json!({"symbol":ty.id,"category":category});
            if let Some(binders) = generic_binders.get(&ty.id) {
                declaration["genericParameters"] = native_generic_parameters(binders);
                for symbol in binders {
                    declarations.push(json!({
                        "symbol":symbol,
                        "category":"type-parameter",
                    }));
                }
            }
            declarations.push(declaration);
        }
        for member in members {
            let mut declaration =
                json!({"symbol":member.id,"category":"callable","owner":member.owner});
            if let Some(signature) = &member.signature {
                let parameters: Vec<_> = signature.parameters.iter().enumerate().map(|(position, parameter)| {
                    json!({"position":position,"binding":"positional-only","required":!parameter.optional})
                }).collect();
                let results: Vec<_> = signature
                    .returns
                    .iter()
                    .map(|_| json!({"position":0}))
                    .collect();
                let mut shape = json!({"kind":"method","parameters":parameters,"results":results});
                if member.receiver.is_some() {
                    shape["receiver"] = native_receiver_reference(
                        &member.owner,
                        generic_binders
                            .get(&member.owner)
                            .map(Vec::as_slice)
                            .unwrap_or_default(),
                    );
                }
                declaration["callable"] = shape;
            }
            declarations.push(declaration);
            let (status, limitations) = match &member.locator {
                Locator::Interchange {
                    callable_shape_evidence: Some(evidence),
                    ..
                } => (
                    evidence.statement.status,
                    evidence.statement.limitations.clone(),
                ),
                _ => (
                    if member.callable_family_complete {
                        crate::analyzer::semantic_model::csmi::CsmiCoverageStatus::Complete
                    } else {
                        crate::analyzer::semantic_model::csmi::CsmiCoverageStatus::Partial
                    },
                    Vec::new(),
                ),
            };
            completeness.push(json!({"family":"declaration-aspects","scope":{"symbol":member.id,"aspect":"callable-shape"},"status":status,"limitations":limitations}));
        }
    }
    let mut facts = Vec::new();
    let mut affects = Vec::new();
    let mut scopes = HashMap::new();
    for shard in &pack.shards {
        let Some(payload) = &shard.deferred_yields else {
            continue;
        };
        for fact in &payload.yields {
            let mut payload = fact.payload.clone();
            if let Some(CsmiDeferredYieldSubstitution::ReceiverArguments { declaration }) =
                &payload.receiver_substitution
                && let Some(binders) = generic_binders.get(declaration)
                && let Some(parameters) = generic_parameters.get(declaration)
            {
                remap_native_deferred_parameters(&mut payload, parameters, binders);
            }
            let scope =
                json!({"factory":fact.factory,"resume":fact.resume,"handleType":fact.handle_type});
            facts.push(json!({"vocabulary":CSMI_DEFERRED_YIELD_PROFILE_ID,"version":CSMI_DEFERRED_YIELD_PROFILE_VERSION,"family":"deferred-yields","scope":scope,"payload":payload}));
            let key = (
                fact.factory.clone(),
                fact.resume.clone(),
                fact.handle_type.clone(),
            );
            let complete = fact.coverage == Some(Completeness::Complete);
            scopes
                .entry(key)
                .and_modify(|entry: &mut bool| *entry &= complete)
                .or_insert(complete);
        }
    }
    for ((factory, resume, handle_type), complete) in scopes {
        let scope = json!({"factory":factory,"resume":resume,"handleType":handle_type});
        affects.push(json!({"kind":"fact-family","family":"deferred-yields","scope":scope}));
        completeness.push(json!({"vocabulary":CSMI_DEFERRED_YIELD_PROFILE_ID,"version":CSMI_DEFERRED_YIELD_PROFILE_VERSION,"family":"deferred-yields","scope":scope,"status":if complete {"complete"} else {"partial"}}));
    }
    let mut conditional_affects = Vec::new();
    let mut conditional_scopes = HashMap::new();
    for shard in &pack.shards {
        let Some(payload) = &shard.conditional_type_refinements else {
            continue;
        };
        for fact in &payload.refinements {
            let scope = json!({"callable": fact.payload.callable, "subject": fact.payload.subject});
            let key = serde_json::to_string(&scope).expect("conditional scope serializes");
            let complete = fact.coverage == Some(CsmiCoverageStatus::Complete);
            conditional_scopes
                .entry(key)
                .and_modify(|entry: &mut (serde_json::Value, bool)| entry.1 &= complete)
                .or_insert((scope.clone(), complete));
            facts.push(json!({"vocabulary": CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_ID,
                "version": CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_VERSION,
                "family": CSMI_CONDITIONAL_TYPE_REFINEMENT_FAMILY, "scope": scope, "payload": fact.payload}));
        }
    }
    for (scope, complete) in conditional_scopes.into_values() {
        conditional_affects.push(json!({"kind":"fact-family", "family":CSMI_CONDITIONAL_TYPE_REFINEMENT_FAMILY,"scope":scope}));
        completeness.push(
            json!({"vocabulary":CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_ID,
            "version":CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_VERSION,
            "family":CSMI_CONDITIONAL_TYPE_REFINEMENT_FAMILY,"scope":scope,
            "status":if complete {"complete"} else {"partial"}}),
        );
    }
    let model: CsmiSemanticModel = serde_json::from_value(json!({
        "artifactSelectors":[],"declarations":declarations,"extensionFacts":facts,
        "vocabularyUses":[{"identifier":CSMI_DEFERRED_YIELD_PROFILE_ID,"version":CSMI_DEFERRED_YIELD_PROFILE_VERSION,"schema":CSMI_DEFERRED_YIELD_PROFILE_SCHEMA,"requirement":"required","affects":affects},
            {"identifier":CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_ID,"version":CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_VERSION,"schema":CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_SCHEMA,"requirement":"required","affects":conditional_affects}],
        "completenessStatements":completeness
    })).expect("native declaration shape construction is valid");
    model
}

fn native_generic_binder_symbols(
    count: usize,
    occupied: &mut HashSet<String>,
    next_id: &mut usize,
) -> Vec<String> {
    (0..count)
        .map(|_| {
            loop {
                let symbol = format!("type-parameter.{next_id}");
                *next_id += 1;
                if occupied.insert(symbol.clone()) {
                    break symbol;
                }
            }
        })
        .collect()
}

fn remap_native_deferred_parameters(
    payload: &mut crate::analyzer::semantic_model::csmi::CsmiDeferredYieldPayload,
    parameters: &[String],
    binders: &[String],
) {
    use crate::analyzer::semantic_model::csmi::CsmiDeferredYieldShape;

    use crate::analyzer::semantic_model::csmi::CsmiTypeExpression;

    let owner_binders = parameters
        .iter()
        .zip(binders)
        .map(|(parameter, binder)| (format!("type-parameter.{parameter}"), binder.clone()))
        .collect::<HashMap<_, _>>();
    let mut shapes = payload
        .roots
        .iter_mut()
        .map(|root| &mut root.shape)
        .collect::<Vec<_>>();
    while let Some(shape) = shapes.pop() {
        match shape {
            CsmiDeferredYieldShape::Value { r#type } => {
                let mut types = vec![r#type];
                while let Some(r#type) = types.pop() {
                    match r#type {
                        CsmiTypeExpression::Parameter(parameter) => {
                            if let Some(binder) = owner_binders.get(&parameter.symbol) {
                                parameter.symbol.clone_from(binder);
                            }
                        }
                        CsmiTypeExpression::Reference(reference) => {
                            types.extend(reference.arguments.iter_mut());
                        }
                        CsmiTypeExpression::Unknown(_) | CsmiTypeExpression::Intrinsic(_) => {}
                    }
                }
            }
            CsmiDeferredYieldShape::Product { components } => shapes.extend(components),
            CsmiDeferredYieldShape::Keyed { key, value, .. } => {
                shapes.push(key);
                shapes.push(value);
            }
            CsmiDeferredYieldShape::Unknown { .. } => {}
        }
    }
}

fn native_generic_parameters(binders: &[String]) -> serde_json::Value {
    serde_json::Value::Array(
        binders
            .iter()
            .enumerate()
            .map(|(position, symbol)| {
                serde_json::json!({
                    "position":position,
                    "symbol":symbol,
                    "kind":"type",
                })
            })
            .collect(),
    )
}

fn native_receiver_reference(owner: &str, binders: &[String]) -> serde_json::Value {
    serde_json::json!({
        "kind":"instance",
        "type":{
            "kind":"reference",
            "symbol":owner,
            "arguments":binders.iter().map(|symbol| serde_json::json!({
                "kind":"parameter",
                "symbol":symbol,
            })).collect::<Vec<_>>(),
        },
    })
}

fn native_profile_depth_within(pack: &AuthoredSemanticModelPack, max_depth: usize) -> bool {
    use crate::analyzer::semantic_model::csmi::CsmiDeferredYieldShape;

    use crate::analyzer::semantic_model::csmi::CsmiTypeExpression;
    let mut shapes = Vec::new();
    let mut types = Vec::new();
    for shard in &pack.shards {
        if let Some(payload) = &shard.deferred_yields {
            for fact in &payload.yields {
                shapes.extend(fact.payload.roots.iter().map(|root| (&root.shape, 0usize)));
            }
        }
    }
    for shard in &pack.shards {
        if let Some(payload) = &shard.conditional_type_refinements {
            for fact in &payload.refinements {
                if let crate::analyzer::semantic_model::csmi::CsmiConditionalTypeOutcome::Supported { target, .. } = &fact.payload.outcome {
                    types.push((target, 0usize));
                }
            }
        }
    }
    while let Some((shape, depth)) = shapes.pop() {
        if depth > max_depth {
            return false;
        }
        match shape {
            CsmiDeferredYieldShape::Value { r#type } => types.push((r#type, depth + 1)),
            CsmiDeferredYieldShape::Product { components } => {
                shapes.extend(components.iter().map(|component| (component, depth + 1)))
            }
            CsmiDeferredYieldShape::Keyed { key, value, .. } => {
                shapes.push((key, depth + 1));
                shapes.push((value, depth + 1));
            }
            CsmiDeferredYieldShape::Unknown { .. } => {}
        }
    }
    while let Some((ty, depth)) = types.pop() {
        if depth > max_depth {
            return false;
        }
        if let CsmiTypeExpression::Reference(reference) = ty {
            types.extend(
                reference
                    .arguments
                    .iter()
                    .map(|argument| (argument, depth + 1)),
            );
        }
    }
    true
}

#[cfg(test)]
mod native_deferred_bridge_tests {

    use crate::analyzer::semantic_model::validate::*;

    use crate::analyzer::semantic_model::csmi::CSMI_DEFERRED_YIELD_PROFILE_ID;

    use crate::analyzer::semantic_model::csmi::CSMI_DEFERRED_YIELD_PROFILE_SCHEMA;

    use crate::analyzer::semantic_model::csmi::CSMI_DEFERRED_YIELD_PROFILE_VERSION;

    use crate::analyzer::semantic_model::csmi::CsmiSemanticModel;

    use crate::analyzer::semantic_model::csmi::validate_native_deferred_yield_model;
    use serde_json::Value;

    const PROFILE_PAYLOAD: &str = include_str!("csmi/profiles/deferred-yield-shared-entry.json");

    fn remap_profile_payload() -> Value {
        let mut payload: Value = serde_json::from_str(PROFILE_PAYLOAD).expect("valid profile");
        let replacements = [
            ("iter", "map.iter"),
            ("next", "handle.next"),
            ("Iter", "iter-handle"),
        ];
        rewrite_symbols(&mut payload, &replacements);
        rewrite_parameter_shapes(&mut payload);
        payload
    }

    fn rewrite_symbols(value: &mut Value, replacements: &[(&str, &str)]) {
        match value {
            Value::String(text) => {
                if let Some((_, replacement)) = replacements.iter().find(|(old, _)| old == text) {
                    *text = (*replacement).to_owned();
                }
            }
            Value::Array(values) => values
                .iter_mut()
                .for_each(|value| rewrite_symbols(value, replacements)),
            Value::Object(object) => object
                .values_mut()
                .for_each(|value| rewrite_symbols(value, replacements)),
            _ => {}
        }
    }

    fn rewrite_parameter_shapes(value: &mut Value) {
        match value {
            Value::Array(values) => values.iter_mut().for_each(rewrite_parameter_shapes),
            Value::Object(object) => {
                let parameter =
                    if object.get("kind") == Some(&Value::String("reference".to_owned())) {
                        match object.get("symbol").and_then(Value::as_str) {
                            Some("Key") => Some("K"),
                            Some("Value") => Some("V"),
                            _ => None,
                        }
                    } else {
                        None
                    };
                if let Some(parameter) = parameter {
                    object.insert("kind".to_owned(), Value::String("parameter".to_owned()));
                    object.insert(
                        "symbol".to_owned(),
                        Value::String(format!("type-parameter.{parameter}")),
                    );
                }
                object.values_mut().for_each(rewrite_parameter_shapes);
            }
            _ => {}
        }
    }

    fn native_type(symbol: &str, name: &str, parameters: Value) -> Value {
        serde_json::json!({
            "id":symbol,
            "name":name,
            "type_kind":"struct",
            "visibility":"public",
            "is_abstract":false,
            "is_sealed":false,
            "has_explicit_type_terms":false,
            "type_parameters":parameters,
            "locator":{"kind":"artifact","path":"test", "symbol":symbol},
        })
    }

    #[test]
    fn go_local_named_references_require_declaration_ids_per_package() {
        let limits = ValidationLimits {
            max_shards: 100,
            max_records_per_shard: 1000,
            max_records_per_pack: 1000,
            max_text_bytes: 10000,
            max_depth: 64,
        };
        let mut pack = native_pack(serde_json::json!([]));
        pack.language = "go".to_owned();
        pack.ecosystem = "go".to_owned();
        pack.shards[0].deferred_yields = None;
        let ty = |id: &str, name: &str, kind: &str| {
            serde_json::json!({
                "id": id, "name": name, "type_kind": kind, "visibility": "public",
                "locator": {"kind": "artifact", "path": "fixture", "symbol": name}
            })
        };
        pack.shards[0].payload = serde_json::from_value(serde_json::json!({
            "kind": "declaration_facts",
            "types": [ty("p", "gopkg.in/p.v3", "module"),
                      ty("q", "example.com/q", "module"),
                      ty("any", "gopkg.in/p.v3.any", "type_alias"),
                      ty("error", "gopkg.in/p.v3.error", "interface"),
                      ty("custom", "gopkg.in/p.v3.Custom", "struct")],
            "members": [{"id": "function", "owner": "q", "name": "Function",
                "member_kind": "function", "visibility": "public",
                "signature": {"parameters": [], "returns": {"kind": "named", "name": "any"}},
                "locator": {"kind": "artifact", "path": "fixture", "symbol": "Function"}}]
        }))
        .unwrap();
        assert_eq!(validate_pack(&pack, limits), Vec::<Diagnostic>::new());
        let AuthoredPayload::DeclarationFacts { members, .. } = &mut pack.shards[0].payload else {
            unreachable!()
        };
        members[0].owner = "p".to_owned();
        members[0].signature.as_mut().unwrap().returns = Some(TypeRef::Named {
            name: "error".to_owned(),
            arguments: vec![],
            nullable: false,
        });
        let diagnostics = validate_pack(&pack, limits);
        assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
        assert_eq!(diagnostics[0].code, "go.local_type_bare_reference");
        assert_eq!(
            diagnostics[0].path,
            "$.shards[0].payload.members[0].signature.returns"
        );
        let AuthoredPayload::DeclarationFacts { members, .. } = &mut pack.shards[0].payload else {
            unreachable!()
        };
        members[0].signature.as_mut().unwrap().returns = Some(TypeRef::Declared {
            id: "error".to_owned(),
            arguments: vec![],
            nullable: false,
        });
        assert_eq!(validate_pack(&pack, limits), Vec::<Diagnostic>::new());
        // The contract is independent of the universe's current name list.
        let AuthoredPayload::DeclarationFacts { members, .. } = &mut pack.shards[0].payload else {
            unreachable!()
        };
        members[0].signature.as_mut().unwrap().returns = Some(TypeRef::Named {
            name: "Custom".to_owned(),
            arguments: vec![],
            nullable: false,
        });
        assert_eq!(
            validate_pack(&pack, limits)[0].code,
            "go.local_type_bare_reference"
        );
    }

    fn native_pack(map_binders: Value) -> AuthoredSemanticModelPack {
        let mut payload = remap_profile_payload();
        payload["receiverSubstitution"] = serde_json::json!({
            "kind":"receiver-arguments",
            "declaration":"map",
        });
        serde_json::from_value(serde_json::json!({
            "schema_version":2,
            "pack_id":"native.deferred.test",
            "version":"1.0.0",
            "producer":{"name":"test","version":"1.0.0"},
            "language":"rust",
            "ecosystem":"cargo",
            "compatibility":{"bifrost":">=0.0.0"},
            "provenance":{"source":"test","revision":"native-deferred"},
            "license":"MIT",
            "completeness":"partial",
            "safety":{"generated_code_only":false,"review_required":false},
            "shards":[{
                "id":"deferred",
                "activation":[{"targets":[],"configurations":[]}],
                "payload":{"kind":"declaration_facts","types":[
                    native_type("map","std.collections.HashMap",map_binders),
                    native_type("iter-handle","std.collections.hash_map.Iter",serde_json::json!([])),
                    native_type("type-parameter.0","Collision proof",serde_json::json!([])),
                ],"members":[
                    {
                        "id":"map.iter",
                        "owner":"map",
                        "name":"iter",
                        "member_kind":"method",
                        "visibility":"public",
                        "callable_family_complete":true,
                        "signature":{"parameters":[],"returns":{"kind":"declared","id":"iter-handle","arguments":[
                            {"kind":"type_parameter","name":"K"},
                            {"kind":"type_parameter","name":"V"},
                        ],"nullable":false}},
                        "receiver":{"pointer":false},
                        "locator":{"kind":"artifact","path":"test","symbol":"iter"},
                    },
                    {
                        "id":"handle.next",
                        "owner":"iter-handle",
                        "name":"next",
                        "member_kind":"method",
                        "visibility":"public",
                        "callable_family_complete":true,
                        "signature":{"parameters":[],"returns":{"kind":"tuple","elements":[
                            {"kind":"by_ref","element":{"kind":"type_parameter","name":"K"}},
                            {"kind":"by_ref","element":{"kind":"type_parameter","name":"V"}},
                        ]}},
                        "receiver":{"pointer":false},
                        "locator":{"kind":"artifact","path":"test","symbol":"next"},
                    },
                ],"relations":[]},
                "deferred_yields":{"yields":[{
                    "factory":"map.iter",
                    "resume":"handle.next",
                    "handleType":"iter-handle",
                    "payload":payload,
                    "coverage":"complete",
                    "provenance":["test"],
                }]},
            }],
        }))
        .expect("valid native test pack")
    }

    #[test]
    fn native_bridge_preserves_ordered_owner_binders_for_receiver_substitution() {
        let mut occupied = HashSet::from(["type-parameter.0".to_owned()]);
        let mut next_id = 0;
        let binders = native_generic_binder_symbols(2, &mut occupied, &mut next_id);
        assert_eq!(
            binders,
            vec!["type-parameter.1".to_owned(), "type-parameter.2".to_owned()]
        );
        let receiver = native_receiver_reference("map", &binders);
        assert_eq!(
            receiver["type"]["arguments"],
            serde_json::json!([
                {"kind":"parameter","symbol":"type-parameter.1"},
                {"kind":"parameter","symbol":"type-parameter.2"},
            ])
        );
        assert!(
            validate_native_profile_contracts(&native_pack(serde_json::json!(["K", "V"])))
                .is_empty(),
            "ordered binders should satisfy receiver substitution"
        );
    }

    fn substitution_model(receiver_arguments: Value) -> CsmiSemanticModel {
        let mut payload = remap_profile_payload();
        payload["receiverSubstitution"] = serde_json::json!({
            "kind":"receiver-arguments",
            "declaration":"map",
        });
        let binder = |position: u32, symbol: &str| serde_json::json!({"position":position,"symbol":symbol,"kind":"type"});
        let callable = |symbol: &str, receiver: Value| {
            serde_json::json!({
                "symbol":symbol,
                "category":"callable",
                "callable":{
                    "kind":"method",
                    "receiver":{"kind":"instance","type":receiver},
                    "parameters":[],
                    "results":[{"position":0}],
                },
            })
        };
        serde_json::from_value(serde_json::json!({
            "artifactSelectors":[],
            "declarations":[
                {"symbol":"map","category":"type","genericParameters":[
                    binder(0,"type-parameter.map.K"), binder(1,"type-parameter.map.V"),
                ]},
                {"symbol":"type-parameter.map.K","category":"type-parameter"},
                {"symbol":"type-parameter.map.V","category":"type-parameter"},
                {"symbol":"iter-handle","category":"type"},
                callable("map.iter", serde_json::json!({"kind":"reference","symbol":"map","arguments":receiver_arguments})),
                callable("handle.next", serde_json::json!({"kind":"reference","symbol":"iter-handle"})),
            ],
            "extensionFacts":[{
                "vocabulary":CSMI_DEFERRED_YIELD_PROFILE_ID,
                "version":CSMI_DEFERRED_YIELD_PROFILE_VERSION,
                "family":"deferred-yields",
                "scope":{"factory":"map.iter","resume":"handle.next","handleType":"iter-handle"},
                "payload":payload,
            }],
            "vocabularyUses":[{
                "identifier":CSMI_DEFERRED_YIELD_PROFILE_ID,
                "version":CSMI_DEFERRED_YIELD_PROFILE_VERSION,
                "schema":CSMI_DEFERRED_YIELD_PROFILE_SCHEMA,
                "requirement":"required",
                "affects":[{"kind":"fact-family","family":"deferred-yields","scope":{
                    "factory":"map.iter","resume":"handle.next","handleType":"iter-handle",
                }}],
            }],
            "completenessStatements":[
                {"family":"declaration-aspects","scope":{"symbol":"map.iter","aspect":"callable-shape"},"status":"complete"},
                {"family":"declaration-aspects","scope":{"symbol":"handle.next","aspect":"callable-shape"},"status":"complete"},
            ],
        }))
        .expect("valid CSMI test model")
    }

    #[test]
    fn native_deferred_validation_rejects_bad_receiver_binder_sequences() {
        let argument = |symbol: &str| serde_json::json!({"kind":"parameter","symbol":symbol});
        let cases = [
            (
                "missing",
                serde_json::json!([argument("type-parameter.map.K")]),
            ),
            (
                "reordered",
                serde_json::json!([
                    argument("type-parameter.map.V"),
                    argument("type-parameter.map.K")
                ]),
            ),
            (
                "mismatched",
                serde_json::json!([
                    argument("type-parameter.map.K"),
                    argument("type-parameter.other.V")
                ]),
            ),
        ];
        for (name, arguments) in cases {
            let diagnostics = validate_native_deferred_yield_model(&substitution_model(arguments));
            assert!(
                diagnostics.iter().any(|diagnostic| {
                    diagnostic.code == "semantic.deferred_yield_receiver_arguments"
                }),
                "{name} binders must fail closed; diagnostics={diagnostics:?}"
            );
        }
    }
}
