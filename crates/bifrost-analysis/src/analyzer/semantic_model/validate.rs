use super::model::*;
use crate::analyzer::canonical_hash::is_lower_sha256;
use crate::analyzer::identifier::validate_identifier;
use crate::workspace_document::has_portable_windows_path_prefix;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
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
pub(crate) struct ValidationLimits {
    pub max_shards: usize,
    pub max_records_per_shard: usize,
    pub max_records_per_pack: usize,
    pub max_text_bytes: usize,
    pub max_depth: usize,
}

pub(crate) fn validate_pack(
    pack: &AuthoredSemanticModelPack,
    limits: ValidationLimits,
) -> Vec<Diagnostic> {
    validate_pack_internal(pack, limits, true)
}

pub(crate) fn validate_pack_locally(
    pack: &AuthoredSemanticModelPack,
    limits: ValidationLimits,
) -> Vec<Diagnostic> {
    validate_pack_internal(pack, limits, false)
}

fn validate_pack_internal(
    pack: &AuthoredSemanticModelPack,
    limits: ValidationLimits,
    validate_references: bool,
) -> Vec<Diagnostic> {
    let mut validator = Validator {
        diagnostics: Vec::new(),
        limits,
        stable_ids: HashMap::new(),
        declaration_ids: HashSet::new(),
        member_ids: HashSet::new(),
        member_owners: HashMap::new(),
        member_operations: HashMap::new(),
        procedure_ids: HashSet::new(),
        procedure_targets: HashMap::new(),
        type_parameters_by_id: HashMap::new(),
        pack_completeness: pack.completeness,
        pack_id_bytes: pack.pack_id.len(),
        validate_references,
    };
    validator.validate(pack);
    validator
        .diagnostics
        .sort_by(|left, right| (&left.path, &left.code).cmp(&(&right.path, &right.code)));
    validator.diagnostics
}

struct Validator {
    diagnostics: Vec<Diagnostic>,
    limits: ValidationLimits,
    stable_ids: HashMap<String, String>,
    declaration_ids: HashSet<String>,
    member_ids: HashSet<String>,
    member_owners: HashMap<String, String>,
    member_operations: HashMap<String, Option<ImplicitOperation>>,
    procedure_ids: HashSet<String>,
    procedure_targets: HashMap<(String, String), String>,
    type_parameters_by_id: HashMap<String, Vec<String>>,
    pack_completeness: Completeness,
    pack_id_bytes: usize,
    validate_references: bool,
}

impl Validator {
    fn validate(&mut self, pack: &AuthoredSemanticModelPack) {
        if pack.schema_version != SEMANTIC_MODEL_SCHEMA_VERSION {
            self.error(
                "schema.unsupported_version",
                "$.schema_version",
                format!(
                    "expected schema version {SEMANTIC_MODEL_SCHEMA_VERSION}, found {}",
                    pack.schema_version
                ),
            );
        }
        self.stable_id("$.pack_id", &pack.pack_id);
        self.version("$.version", &pack.version);
        self.text("$.producer.name", &pack.producer.name);
        self.version("$.producer.version", &pack.producer.version);
        self.stable_component("$.language", &pack.language);
        self.stable_component("$.ecosystem", &pack.ecosystem);
        self.version_requirement("$.compatibility.bifrost", &pack.compatibility.bifrost);
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
                self.declaration_ids
                    .extend(members.iter().map(|fact| fact.id.clone()));
                self.member_ids
                    .extend(members.iter().map(|fact| fact.id.clone()));
                self.member_owners.extend(
                    members
                        .iter()
                        .map(|fact| (fact.id.clone(), fact.owner.clone())),
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
            let records = shard.payload.record_count();
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
            let expected_context_digest =
                super::csmi::canonical_digest(&super::csmi::csmi_resolution_context(context));
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
            let expected_disambiguator =
                super::csmi::csmi_cpp_signature(&member.signature, &symbol_keys)
                    .and_then(|signature| {
                        super::csmi::canonical_digest(&signature).map_err(|error| {
                            super::csmi::CsmiExportError::Canonical(error.to_string())
                        })
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

    fn payload(&mut self, path: &str, payload: &AuthoredPayload) {
        match payload {
            AuthoredPayload::DeclarationFacts {
                types,
                members,
                relations,
            } => {
                for (index, fact) in types.iter().enumerate() {
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
                    for (embedded_index, embedded) in fact.embedded_types.iter().enumerate() {
                        self.type_ref(
                            &format!("{fact_path}.embedded_types[{embedded_index}].target"),
                            &embedded.target,
                            &fact.type_parameters,
                        );
                    }
                    for (type_index, hierarchy) in fact.hierarchy.iter().enumerate() {
                        self.type_ref(
                            &format!("{fact_path}.hierarchy[{type_index}].target"),
                            &hierarchy.target,
                            &fact.type_parameters,
                        );
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
                    let fact_path = format!("{path}.members[{index}]");
                    self.stable_id(&format!("{fact_path}.id"), &fact.id);
                    self.language_identifier(&format!("{fact_path}.name"), &fact.name);
                    self.locator(&format!("{fact_path}.locator"), &fact.locator);
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
                        match &fact.signature {
                            None => self.error(
                                "declaration.callable_family_complete_without_signature",
                                format!("{fact_path}.callable_family_complete"),
                                "callable_family_complete requires a structured signature",
                            ),
                            Some(signature)
                                if signature
                                    .parameters
                                    .last()
                                    .is_some_and(|parameter| parameter.variadic) =>
                            {
                                self.error(
                                    "declaration.callable_family_complete_on_variadic",
                                    format!("{fact_path}.callable_family_complete"),
                                    "callable_family_complete does not yet support variadic declarations",
                                );
                            }
                            Some(_) => {}
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
        // contracts, conditional-result refinements, and conditional indirect
        // writes do: they are substantive relations among modeled ports even
        // when the summary moves no values.
        if summary.transfers.is_empty()
            && summary.effects.is_empty()
            && summary.concurrency_effects.is_empty()
            && summary.preconditions.is_none()
            && summary.result_contracts.is_empty()
            && summary.conditional_result_refinements.is_empty()
            && summary.conditional_indirect_writes.is_empty()
            && summary.normal_return_refinements.is_empty()
            && !summary.normal_continuation_absent
            && summary.completeness != Completeness::Complete
        {
            self.error(
                "summary.empty",
                path,
                "a partial procedure summary must declare at least one transfer, effect, concurrency effect, operation precondition review, result contract, conditional-result refinement, conditional indirect write, normal-return refinement, or absent normal continuation",
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
        }

        self.declared_effects(path, &summary.declared_effects);
        self.operation_preconditions(path, &summary.preconditions, &summary.target);
        self.concurrency_effects(path, &summary.concurrency_effects, &summary.target);
        if summary.normal_result_count.is_none()
            && (!summary.result_contracts.is_empty()
                || !summary.conditional_result_refinements.is_empty()
                || !summary.conditional_indirect_writes.is_empty())
        {
            self.error(
                "summary.result_count_required",
                format!("{path}.normal_result_count"),
                "normal_result_count is required when result contracts, conditional-result refinements, or conditional indirect writes are non-empty",
            );
        }
        self.result_contracts(path, summary.normal_result_count, &summary.result_contracts);
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
                AuthoredConcurrencyEffect::TaskSpawn { callable, group } => {
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
                                effect_path,
                                "task callable and task group must be distinct ports",
                            );
                        }
                    }
                }
                AuthoredConcurrencyEffect::TaskJoin { group } => {
                    self.summary_input(&format!("{effect_path}.group"), group, target);
                    task_joins.insert(group);
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
            if refinement.result_ordinal > MAX_PROCEDURE_SUMMARY_ORDINAL {
                self.error(
                    "summary.invalid_result_ordinal",
                    format!("{refinement_path}.result_ordinal"),
                    format!("result ordinal exceeds {MAX_PROCEDURE_SUMMARY_ORDINAL}"),
                );
            }
            if normal_result_count.is_some_and(|count| refinement.result_ordinal >= count) {
                self.error(
                    "summary.result_ordinal_out_of_range",
                    format!("{refinement_path}.result_ordinal"),
                    format!(
                        "result ordinal {} is outside normal_result_count {}",
                        refinement.result_ordinal,
                        normal_result_count.expect("checked as some")
                    ),
                );
            }
            if refinement.parameter_ordinal > MAX_PROCEDURE_SUMMARY_ORDINAL {
                self.error(
                    "summary.invalid_parameter_ordinal",
                    format!("{refinement_path}.parameter_ordinal"),
                    format!("parameter ordinal exceeds {MAX_PROCEDURE_SUMMARY_ORDINAL}"),
                );
            }
            if refinement.parameter_ordinal >= target.parameter_count {
                self.error(
                    "summary.parameter_ordinal_out_of_range",
                    format!("{refinement_path}.parameter_ordinal"),
                    format!(
                        "parameter ordinal {} is outside parameter_count {}",
                        refinement.parameter_ordinal, target.parameter_count
                    ),
                );
            } else if target.variadic
                && target.parameter_count.checked_sub(1) == Some(refinement.parameter_ordinal)
            {
                self.error(
                    "summary.unsupported_variadic_tail_reference",
                    format!("{refinement_path}.parameter_ordinal"),
                    format!(
                        "conditional-result refinement cannot reference variadic tail ordinal {}",
                        refinement.parameter_ordinal
                    ),
                );
            }

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
            if write.result_ordinal > MAX_PROCEDURE_SUMMARY_ORDINAL {
                self.error(
                    "summary.invalid_result_ordinal",
                    format!("{write_path}.result_ordinal"),
                    format!("result ordinal exceeds {MAX_PROCEDURE_SUMMARY_ORDINAL}"),
                );
            }
            if normal_result_count.is_some_and(|count| write.result_ordinal >= count) {
                self.error(
                    "summary.result_ordinal_out_of_range",
                    format!("{write_path}.result_ordinal"),
                    format!(
                        "result ordinal {} is outside normal_result_count {}",
                        write.result_ordinal,
                        normal_result_count.expect("checked as some")
                    ),
                );
            }
            if write.parameter_ordinal > MAX_PROCEDURE_SUMMARY_ORDINAL {
                self.error(
                    "summary.invalid_parameter_ordinal",
                    format!("{write_path}.parameter_ordinal"),
                    format!("parameter ordinal exceeds {MAX_PROCEDURE_SUMMARY_ORDINAL}"),
                );
            }
            if write.parameter_ordinal >= target.parameter_count {
                self.error(
                    "summary.parameter_ordinal_out_of_range",
                    format!("{write_path}.parameter_ordinal"),
                    format!(
                        "parameter ordinal {} is outside parameter_count {}",
                        write.parameter_ordinal, target.parameter_count
                    ),
                );
            } else if target.variadic
                && target.parameter_count.checked_sub(1) == Some(write.parameter_ordinal)
            {
                self.error(
                    "summary.unsupported_variadic_tail_reference",
                    format!("{write_path}.parameter_ordinal"),
                    format!(
                        "conditional indirect write cannot reference variadic tail ordinal {}",
                        write.parameter_ordinal
                    ),
                );
            }

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
            if refinement.parameter_ordinal > MAX_PROCEDURE_SUMMARY_ORDINAL {
                self.error(
                    "summary.invalid_parameter_ordinal",
                    format!("{refinement_path}.parameter_ordinal"),
                    format!("parameter ordinal exceeds {MAX_PROCEDURE_SUMMARY_ORDINAL}"),
                );
            }
            if refinement.parameter_ordinal >= target.parameter_count {
                self.error(
                    "summary.parameter_ordinal_out_of_range",
                    format!("{refinement_path}.parameter_ordinal"),
                    format!(
                        "parameter ordinal {} is outside parameter_count {}",
                        refinement.parameter_ordinal, target.parameter_count
                    ),
                );
            } else if target.variadic
                && target.parameter_count.checked_sub(1) == Some(refinement.parameter_ordinal)
            {
                self.error(
                    "summary.unsupported_variadic_tail_reference",
                    format!("{refinement_path}.parameter_ordinal"),
                    format!(
                        "normal-return refinement cannot reference variadic tail ordinal {}",
                        refinement.parameter_ordinal
                    ),
                );
            }
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

    fn signature(&mut self, path: &str, signature: &Signature, owner_type_parameters: &[String]) {
        self.unique_names(
            &format!("{path}.type_parameters"),
            &signature.type_parameters,
        );
        let mut available_type_parameters = owner_type_parameters.to_vec();
        available_type_parameters.extend(signature.type_parameters.iter().cloned());
        let mut parameter_names = HashSet::new();
        for (index, parameter) in signature.parameters.iter().enumerate() {
            let parameter_path = format!("{path}.parameters[{index}]");
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
                TypeRef::Named {
                    name, arguments, ..
                } => {
                    self.qualified_name(&format!("{current_path}.name"), name);
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
                    if elements.is_empty() {
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
                        super::TemplateCondition::Equals { left, right } => (left, right),
                        super::TemplateCondition::StartsWith { value, prefix } => (value, prefix),
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
pub(crate) fn is_canonical_relative_path(value: &str) -> bool {
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
