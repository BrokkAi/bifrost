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
            self.stable_component(&format!("{path}.configurations[{index}]"), configuration);
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
                    self.locator(&format!("{fact_path}.locator"), &fact.locator);
                }
                for (index, fact) in members.iter().enumerate() {
                    let fact_path = format!("{path}.members[{index}]");
                    self.stable_id(&format!("{fact_path}.id"), &fact.id);
                    self.language_identifier(&format!("{fact_path}.name"), &fact.name);
                    self.locator(&format!("{fact_path}.locator"), &fact.locator);
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
        let effect_references = summary.effects.iter().fold(0usize, |count, effect| {
            count.saturating_add(match effect {
                AuthoredSummaryEffect::Call { .. } => 1,
                AuthoredSummaryEffect::AmbiguousCall { candidates, .. } => candidates.len(),
                AuthoredSummaryEffect::Allocation { .. }
                | AuthoredSummaryEffect::Escape { .. }
                | AuthoredSummaryEffect::UnknownCall { .. }
                | AuthoredSummaryEffect::UnknownCallBoundary { .. } => 0,
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
        if summary.transfers.is_empty() && summary.effects.is_empty() {
            self.error(
                "summary.empty",
                path,
                "a procedure summary must declare at least one transfer or effect",
            );
        }

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
            );
            if matches!(
                (&transfer.exit_kind, &transfer.output),
                (
                    AuthoredSummaryExitKind::Normal,
                    AuthoredSummaryOutput::ExceptionalReturn {}
                ) | (
                    AuthoredSummaryExitKind::Exceptional,
                    AuthoredSummaryOutput::NormalReturn {}
                )
            ) {
                self.error(
                    "summary.incompatible_exit_port",
                    transfer_path,
                    "normal exits cannot use exceptional_return and exceptional exits cannot use normal_return",
                );
            }
        }
        for (index, effect) in summary.effects.iter().enumerate() {
            self.summary_effect(
                &format!("{path}.effects[{index}]"),
                effect,
                &locations,
                &summary.target,
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
            AuthoredSummaryInput::Receiver {} | AuthoredSummaryInput::Parameter { .. } => {}
        }
    }

    fn summary_output(
        &mut self,
        path: &str,
        output: &AuthoredSummaryOutput,
        locations: &HashMap<&str, (AuthoredSummaryLocationKind, String)>,
        target: &AuthoredProcedureTarget,
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
    ) {
        let event = match effect {
            AuthoredSummaryEffect::Allocation { event, output } => {
                self.summary_output(&format!("{path}.output"), output, locations, target);
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
                | TypeRef::ByRef { element }
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
                            owner, signature, ..
                        } => {
                            self.template(
                                &format!("{emission_path}.declaration.owner"),
                                owner,
                                &captures,
                                TemplatePosition::StableId,
                            );
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
            | CaptureSource::ResolvedOwner => CaptureCardinality::One,
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
            CaptureSource::MatchedNode | CaptureSource::EnclosingDeclaration => true,
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
                TemplateTypeRef::Array { element } => {
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
        let mut stack = vec![(root, 1usize, path.to_owned(), true)];
        while let Some((expression, depth, current_path, is_root)) = stack.pop() {
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
                    stack.push((value, depth + 1, format!("{current_path}.value"), is_root))
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
        use std::path::{Component, Path};

        self.text(path, value);
        if has_portable_windows_path_prefix(value)
            || value.contains('\\')
            || Path::new(value).components().any(|component| {
                matches!(
                    component,
                    Component::Prefix(_)
                        | Component::RootDir
                        | Component::ParentDir
                        | Component::CurDir
                )
            })
        {
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

#[derive(Debug, Clone, Copy)]
enum TemplatePosition {
    StableId,
    LanguageName,
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
    }
}
