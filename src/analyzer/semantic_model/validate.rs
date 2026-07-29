use super::model::*;
use crate::analyzer::identifier::validate_identifier;
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
    let mut validator = Validator {
        diagnostics: Vec::new(),
        limits,
        stable_ids: HashMap::new(),
        declaration_ids: HashSet::new(),
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

        for shard in &pack.shards {
            if let AuthoredPayload::DeclarationFacts { types, members, .. } = &shard.payload {
                self.declaration_ids
                    .extend(types.iter().map(|fact| fact.id.clone()));
                self.declaration_ids
                    .extend(members.iter().map(|fact| fact.id.clone()));
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
        if selectors.iter().all(|(_, value)| value.is_none()) {
            self.error(
                "selector.empty",
                path,
                "selector must identify a package, module, or toolchain",
            );
        }
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
            && !is_sha256(digest)
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
                    for (type_index, reference) in fact.supertypes.iter().enumerate() {
                        self.type_ref(
                            &format!("{fact_path}.supertypes[{type_index}]"),
                            reference,
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
                    self.stable_component(&format!("{fact_path}.name"), &fact.name);
                    self.locator(&format!("{fact_path}.locator"), &fact.locator);
                    if let Some(signature) = &fact.signature {
                        self.signature(&format!("{fact_path}.signature"), signature);
                    }
                }
                for (index, relation) in relations.iter().enumerate() {
                    self.stable_id(&format!("{path}.relations[{index}].id"), &relation.id);
                }
                for (index, fact) in members.iter().enumerate() {
                    if !self.declaration_ids.contains(&fact.owner) {
                        self.error(
                            "reference.missing_owner",
                            format!("{path}.members[{index}].owner"),
                            format!("unknown declaration id `{}`", fact.owner),
                        );
                    }
                }
                for (index, relation) in relations.iter().enumerate() {
                    for (field, target) in [("from", &relation.from), ("to", &relation.to)] {
                        if !self.declaration_ids.contains(target) {
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
        }
    }

    fn signature(&mut self, path: &str, signature: &Signature) {
        self.unique_names(
            &format!("{path}.type_parameters"),
            &signature.type_parameters,
        );
        let mut parameter_names = HashSet::new();
        for (index, parameter) in signature.parameters.iter().enumerate() {
            let parameter_path = format!("{path}.parameters[{index}]");
            self.stable_component(&format!("{parameter_path}.name"), &parameter.name);
            if !parameter_names.insert(&parameter.name) {
                self.error(
                    "parameter.duplicate",
                    format!("{parameter_path}.name"),
                    format!("duplicate parameter `{}`", parameter.name),
                );
            }
            self.type_ref(
                &format!("{parameter_path}.type"),
                &parameter.r#type,
                &signature.type_parameters,
            );
        }
        if let Some(returns) = &signature.returns {
            self.type_ref(
                &format!("{path}.returns"),
                returns,
                &signature.type_parameters,
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
                TypeRef::Named { id, arguments, .. } => {
                    self.qualified_name(&format!("{current_path}.id"), id);
                    for (index, argument) in arguments.iter().enumerate().rev() {
                        stack.push((
                            argument,
                            depth + 1,
                            format!("{current_path}.arguments[{index}]"),
                        ));
                    }
                }
                TypeRef::TypeParameter { name } => {
                    if !type_parameters.contains(name) {
                        self.error(
                            "type.unknown_parameter",
                            format!("{current_path}.name"),
                            format!("unknown type parameter `{name}`"),
                        );
                    }
                }
                TypeRef::Array { element } => {
                    stack.push((element, depth + 1, format!("{current_path}.element")))
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
                    stack.push((result, depth + 1, format!("{current_path}.result")));
                    for (index, parameter) in parameters.iter().enumerate().rev() {
                        stack.push((
                            parameter,
                            depth + 1,
                            format!("{current_path}.parameters[{index}]"),
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
                self.stable_component(&format!("{path}.trigger.name"), name);
            }
        }
        let mut captures = HashMap::new();
        for (index, capture) in rule.captures.iter().enumerate() {
            let capture_path = format!("{path}.captures[{index}].name");
            self.stable_component(&capture_path, &capture.name);
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
                    owner,
                    r#type,
                    ..
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
                    if let Some(owner) = owner {
                        self.template(
                            &format!("{emission_path}.owner"),
                            owner,
                            &captures,
                            TemplatePosition::StableId,
                        );
                    }
                    if let Some(reference) = r#type {
                        self.template_type(&format!("{emission_path}.type"), reference, &captures);
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
                    Some(capture) if capture.cardinality != CaptureCardinality::One => self.error(
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
                    Some(capture) if capture.cardinality != CaptureCardinality::One => self.error(
                        "capture.cardinality",
                        format!("{current_path}.name"),
                        format!("capture `{name}` must have cardinality `one` here"),
                    ),
                    Some(capture) if capture.value_kind != CaptureValueKind::Identifier => {
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
                self.text(&format!("{path}.path"), value);
                if let Some(symbol) = symbol {
                    self.text(&format!("{path}.symbol"), symbol);
                }
            }
            Locator::Artifact {
                path: value,
                symbol,
            } => {
                self.text(&format!("{path}.path"), value);
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
            self.stable_component(&format!("{path}[{index}]"), value);
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
        if Version::parse(value).is_err() {
            self.error("version.invalid", path, "expected a semantic version");
        }
    }

    fn version_requirement(&mut self, path: &str, value: &str) {
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

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
