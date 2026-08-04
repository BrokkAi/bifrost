use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use super::{
    ActivationSelector, AuthoredPayload, AuthoredSemanticModelPack, CaptureSource, CatalogError,
    CatalogPackInventory, CompiledSemanticModelPack, CompilerOptions, Diagnostic,
    DiagnosticSeverity, EmittedDeclaration, GeneratorRule, ResolvedActiveSemanticModels,
    RuleEmission, RuleTrigger, SemanticModelActivationEvidence, SemanticModelActivationStatus,
    SemanticPackCatalog, SourceFormat, TemplateExpression, TemplateSignature, TemplateTypeRef,
    compile_pack, compile_source,
};
use crate::hash::HashSet;

pub const SEMANTIC_MODEL_VALIDATE_FORMAT: &str = "bifrost_semantic_model_validate/v1";
pub const SEMANTIC_MODEL_LINT_FORMAT: &str = "bifrost_semantic_model_lint/v1";
pub const SEMANTIC_MODEL_WORKSPACE_FORMAT: &str = "bifrost_semantic_model_workspace/v1";
pub const SEMANTIC_MODEL_WRITE_FORMAT: &str = "bifrost_semantic_model_write/v1";
pub const SEMANTIC_MODEL_INVENTORY_FORMAT: &str = "bifrost_semantic_model_inventory/v1";
pub const WORKSPACE_SEMANTIC_MODEL_DIRECTORY: &str = ".bifrost/semantic-models";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthoringDiagnosticSeverity {
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoringDiagnostic {
    pub severity: AuthoringDiagnosticSeverity,
    pub code: String,
    pub path: String,
    pub message: String,
}

impl From<Diagnostic> for AuthoringDiagnostic {
    fn from(diagnostic: Diagnostic) -> Self {
        let severity = match diagnostic.severity {
            DiagnosticSeverity::Error => AuthoringDiagnosticSeverity::Error,
        };
        Self {
            severity,
            code: diagnostic.code,
            path: diagnostic.path,
            message: diagnostic.message,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelSourceReport {
    pub format: &'static str,
    pub source_sha256: String,
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pack_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pack_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_content_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_semantic_sha256: Option<String>,
    pub diagnostics: Vec<AuthoringDiagnostic>,
}

pub fn validate_semantic_model_source(
    format: SourceFormat,
    bytes: &[u8],
    options: &CompilerOptions,
) -> SemanticModelSourceReport {
    match compile_source(format, bytes, options) {
        Ok(compiled) => source_report(
            SEMANTIC_MODEL_VALIDATE_FORMAT,
            bytes,
            Some(&compiled),
            Vec::new(),
        ),
        Err(diagnostics) => source_report(
            SEMANTIC_MODEL_VALIDATE_FORMAT,
            bytes,
            None,
            diagnostics.into_iter().map(Into::into).collect(),
        ),
    }
}

pub fn lint_semantic_model_source(
    format: SourceFormat,
    bytes: &[u8],
    options: &CompilerOptions,
) -> SemanticModelSourceReport {
    let pack = match super::source::parse_source(format, bytes) {
        Ok(pack) => pack,
        Err(diagnostics) => {
            return source_report(
                SEMANTIC_MODEL_LINT_FORMAT,
                bytes,
                None,
                diagnostics.into_iter().map(Into::into).collect(),
            );
        }
    };
    let (compiled, compiler_diagnostics) = match compile_pack(&pack, options) {
        Ok(compiled) => (Some(compiled), Vec::new()),
        Err(diagnostics) => (
            None,
            diagnostics.into_iter().map(Into::into).collect::<Vec<_>>(),
        ),
    };
    let mut diagnostics = compiler_diagnostics;
    diagnostics.extend(lint_semantic_model_pack(&pack));
    sort_diagnostics(&mut diagnostics);
    source_report(
        SEMANTIC_MODEL_LINT_FORMAT,
        bytes,
        compiled.as_ref(),
        diagnostics,
    )
}

pub fn lint_semantic_model_pack(pack: &AuthoredSemanticModelPack) -> Vec<AuthoringDiagnostic> {
    let mut diagnostics = Vec::new();
    let mut rules_by_trigger: BTreeMap<TriggerKey, Vec<(String, &GeneratorRule)>> = BTreeMap::new();

    for (shard_index, shard) in pack.shards.iter().enumerate() {
        lint_activation_selectors(shard_index, &shard.activation, &mut diagnostics);
        let AuthoredPayload::GeneratorRules { rules } = &shard.payload else {
            continue;
        };
        for (rule_index, rule) in rules.iter().enumerate() {
            let path = format!("$.shards[{shard_index}].payload.rules[{rule_index}]");
            lint_rule(&path, rule, &mut diagnostics);
            rules_by_trigger
                .entry(trigger_key(&rule.trigger))
                .or_default()
                .push((path, rule));
        }
    }

    for rules in rules_by_trigger.values() {
        if rules.len() < 2 {
            continue;
        }
        for (path, _) in rules {
            diagnostics.push(warning(
                "selector.ambiguous",
                format!("{path}.trigger"),
                "more than one rule uses this exact trigger selector",
            ));
        }
        for index in 1..rules.len() {
            let (path, rule) = &rules[index];
            let (_, prior) = &rules[index - 1];
            if rule.captures == prior.captures && rule.emissions == prior.emissions {
                diagnostics.push(warning(
                    "rule.shadowed",
                    path.clone(),
                    "this rule is equivalent to the preceding rule for the same trigger",
                ));
            }
        }
        lint_conflicting_emissions(rules, &mut diagnostics);
    }

    sort_diagnostics(&mut diagnostics);
    diagnostics
}

fn source_report(
    format: &'static str,
    bytes: &[u8],
    compiled: Option<&CompiledSemanticModelPack>,
    diagnostics: Vec<AuthoringDiagnostic>,
) -> SemanticModelSourceReport {
    let valid = !diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == AuthoringDiagnosticSeverity::Error);
    SemanticModelSourceReport {
        format,
        source_sha256: sha256(bytes),
        valid,
        pack_id: compiled.map(|compiled| compiled.manifest.pack_id.clone()),
        pack_version: compiled.map(|compiled| compiled.manifest.version.clone()),
        manifest_content_sha256: compiled.map(|compiled| compiled.manifest.content_sha256.clone()),
        manifest_semantic_sha256: compiled
            .map(|compiled| compiled.manifest.semantic_sha256.clone()),
        diagnostics,
    }
}

fn lint_activation_selectors(
    shard_index: usize,
    selectors: &[ActivationSelector],
    diagnostics: &mut Vec<AuthoringDiagnostic>,
) {
    for (selector_index, selector) in selectors.iter().enumerate() {
        if selector.package.is_none()
            && selector.module.is_none()
            && selector.toolchain.is_none()
            && selector.artifact_sha256.is_none()
            && selector.targets.is_empty()
            && selector.configurations.is_empty()
        {
            diagnostics.push(warning(
                "selector.unsafe_wildcard_breadth",
                format!("$.shards[{shard_index}].activation[{selector_index}]"),
                "this selector activates for every matching language and ecosystem row",
            ));
        }
    }
}

fn lint_rule(path: &str, rule: &GeneratorRule, diagnostics: &mut Vec<AuthoringDiagnostic>) {
    let unsupported_trigger = matches!(
        rule.trigger,
        RuleTrigger::ResolvedOwner { .. } | RuleTrigger::ResolvedCall { .. }
    );
    let unsupported_capture = rule
        .captures
        .iter()
        .any(|capture| matches!(capture.binding.source, CaptureSource::ResolvedOwner));
    if unsupported_trigger || unsupported_capture {
        diagnostics.push(error(
            "rule.unreachable",
            path,
            "the production schema-v1 overlay cannot evaluate this structured trigger or capture",
        ));
    }
    if matches!(rule.trigger, RuleTrigger::LanguageConstruct { .. }) {
        diagnostics.push(warning(
            "selector.unsafe_wildcard_breadth",
            format!("{path}.trigger"),
            "a language-construct rule can match every node of that normalized kind",
        ));
    }

    let used = referenced_captures(rule);
    for (capture_index, capture) in rule.captures.iter().enumerate() {
        if !used.contains(&capture.name) {
            diagnostics.push(warning(
                "capture.unbound",
                format!("{path}.captures[{capture_index}]"),
                format!(
                    "capture `{}` is bound but no emission uses it",
                    capture.name
                ),
            ));
        }
    }
}

fn lint_conflicting_emissions(
    rules: &[(String, &GeneratorRule)],
    diagnostics: &mut Vec<AuthoringDiagnostic>,
) {
    let mut by_id: BTreeMap<&str, (&RuleEmission, String)> = BTreeMap::new();
    for (rule_path, rule) in rules {
        for (emission_index, emission) in rule.emissions.iter().enumerate() {
            let Some(id) = literal_emission_id(emission) else {
                continue;
            };
            let path = format!("{rule_path}.emissions[{emission_index}]");
            if let Some((prior, prior_path)) = by_id.get(id) {
                if *prior != emission {
                    diagnostics.push(error(
                        "emission.conflict",
                        path,
                        format!("literal emission id `{id}` conflicts with {prior_path}"),
                    ));
                }
            } else {
                by_id.insert(id, (emission, path));
            }
        }
    }
}

fn literal_emission_id(emission: &RuleEmission) -> Option<&str> {
    let expression = match emission {
        RuleEmission::Declaration { id, .. }
        | RuleEmission::Alias { id, .. }
        | RuleEmission::Relation { id, .. } => id,
    };
    match expression {
        TemplateExpression::Literal { value } => Some(value),
        _ => None,
    }
}

fn referenced_captures(rule: &GeneratorRule) -> HashSet<String> {
    let mut captures = HashSet::default();
    for emission in &rule.emissions {
        match emission {
            RuleEmission::Declaration {
                id,
                name,
                anchor,
                declaration,
            } => {
                collect_expression_captures(id, &mut captures);
                collect_expression_captures(name, &mut captures);
                if let Some(anchor) = anchor {
                    collect_expression_captures(anchor, &mut captures);
                }
                match declaration {
                    EmittedDeclaration::Type {
                        type_parameters,
                        hierarchy,
                        extension_surfaces,
                        ..
                    } => {
                        for expression in type_parameters.iter().chain(extension_surfaces) {
                            collect_expression_captures(expression, &mut captures);
                        }
                        for fact in hierarchy {
                            collect_type_captures(&fact.target, &mut captures);
                        }
                    }
                    EmittedDeclaration::Member {
                        owner, signature, ..
                    } => {
                        if let Some(owner) = owner {
                            collect_expression_captures(owner, &mut captures);
                        }
                        if let Some(signature) = signature {
                            collect_signature_captures(signature, &mut captures);
                        }
                    }
                }
            }
            RuleEmission::Alias { id, from, to } | RuleEmission::Relation { id, from, to, .. } => {
                for expression in [id, from, to] {
                    collect_expression_captures(expression, &mut captures);
                }
            }
        }
    }
    captures
}

fn collect_signature_captures(signature: &TemplateSignature, captures: &mut HashSet<String>) {
    for expression in &signature.type_parameters {
        collect_expression_captures(expression, captures);
    }
    for parameter in &signature.parameters {
        collect_expression_captures(&parameter.name, captures);
        collect_type_captures(&parameter.r#type, captures);
    }
    if let Some(result) = &signature.returns {
        collect_type_captures(result, captures);
    }
}

fn collect_type_captures(root: &TemplateTypeRef, captures: &mut HashSet<String>) {
    let mut stack = vec![root];
    while let Some(reference) = stack.pop() {
        match reference {
            TemplateTypeRef::Named {
                name, arguments, ..
            } => {
                collect_expression_captures(name, captures);
                stack.extend(arguments);
            }
            TemplateTypeRef::Capture { name } => {
                captures.insert(name.clone());
            }
            TemplateTypeRef::Array { element } => stack.push(element),
        }
    }
}

fn collect_expression_captures(root: &TemplateExpression, captures: &mut HashSet<String>) {
    let mut stack = vec![root];
    while let Some(expression) = stack.pop() {
        match expression {
            TemplateExpression::Literal { .. } => {}
            TemplateExpression::Capture { name } => {
                captures.insert(name.clone());
            }
            TemplateExpression::Concat { values } => stack.extend(values),
            TemplateExpression::Transform { value, .. } => stack.push(value),
            TemplateExpression::Conditional {
                condition,
                then_value,
                else_value,
            } => {
                match condition {
                    super::TemplateCondition::Equals { left, right } => {
                        stack.push(left);
                        stack.push(right);
                    }
                    super::TemplateCondition::StartsWith { value, prefix } => {
                        stack.push(value);
                        stack.push(prefix);
                    }
                }
                stack.push(then_value);
                stack.push(else_value);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum TriggerKey {
    LanguageConstruct(String),
    Annotation(String),
    MacroInvocation(String),
    GeneratorInvocation(String),
    ResolvedOwner(String),
    ResolvedCall(String, String),
}

fn trigger_key(trigger: &RuleTrigger) -> TriggerKey {
    match trigger {
        RuleTrigger::LanguageConstruct { construct } => {
            TriggerKey::LanguageConstruct(construct.clone())
        }
        RuleTrigger::Annotation { name } => TriggerKey::Annotation(name.clone()),
        RuleTrigger::MacroInvocation { name } => TriggerKey::MacroInvocation(name.clone()),
        RuleTrigger::GeneratorInvocation { name } => TriggerKey::GeneratorInvocation(name.clone()),
        RuleTrigger::ResolvedOwner { owner } => TriggerKey::ResolvedOwner(owner.clone()),
        RuleTrigger::ResolvedCall { owner, name } => {
            TriggerKey::ResolvedCall(owner.clone(), name.clone())
        }
    }
}

fn error(
    code: impl Into<String>,
    path: impl Into<String>,
    message: impl Into<String>,
) -> AuthoringDiagnostic {
    diagnostic(AuthoringDiagnosticSeverity::Error, code, path, message)
}

fn warning(
    code: impl Into<String>,
    path: impl Into<String>,
    message: impl Into<String>,
) -> AuthoringDiagnostic {
    diagnostic(AuthoringDiagnosticSeverity::Warning, code, path, message)
}

fn diagnostic(
    severity: AuthoringDiagnosticSeverity,
    code: impl Into<String>,
    path: impl Into<String>,
    message: impl Into<String>,
) -> AuthoringDiagnostic {
    AuthoringDiagnostic {
        severity,
        code: code.into(),
        path: path.into(),
        message: message.into(),
    }
}

fn sort_diagnostics(diagnostics: &mut [AuthoringDiagnostic]) {
    diagnostics.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.severity.cmp(&right.severity))
            .then_with(|| left.code.cmp(&right.code))
            .then_with(|| left.message.cmp(&right.message))
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkspaceSemanticModelOptions {
    pub max_files: usize,
    pub compiler: CompilerOptions,
}

impl Default for WorkspaceSemanticModelOptions {
    fn default() -> Self {
        Self {
            max_files: 1_024,
            compiler: CompilerOptions::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSemanticModelFile {
    pub path: String,
    pub source_sha256: String,
    pub source_format: String,
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pack_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_semantic_sha256: Option<String>,
    pub diagnostics: Vec<AuthoringDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSemanticModelReport {
    pub format: &'static str,
    pub directory: &'static str,
    pub enabled: bool,
    pub complete: bool,
    pub files: Vec<WorkspaceSemanticModelFile>,
    pub diagnostics: Vec<AuthoringDiagnostic>,
}

pub fn discover_workspace_semantic_models(
    workspace_root: &Path,
    options: WorkspaceSemanticModelOptions,
) -> WorkspaceSemanticModelReport {
    let mut report = WorkspaceSemanticModelReport {
        format: SEMANTIC_MODEL_WORKSPACE_FORMAT,
        directory: WORKSPACE_SEMANTIC_MODEL_DIRECTORY,
        enabled: false,
        complete: true,
        files: Vec::new(),
        diagnostics: Vec::new(),
    };
    let canonical_root = match fs::canonicalize(workspace_root) {
        Ok(root) if root.is_dir() => root,
        Ok(_) => {
            report.complete = false;
            report.diagnostics.push(error(
                "workspace.invalid_root",
                "$",
                "the workspace root is not a directory",
            ));
            return report;
        }
        Err(error_value) => {
            report.complete = false;
            report.diagnostics.push(error(
                "workspace.invalid_root",
                "$",
                format!("cannot resolve the workspace root: {error_value}"),
            ));
            return report;
        }
    };
    let directory = canonical_root.join(WORKSPACE_SEMANTIC_MODEL_DIRECTORY);
    let metadata = match fs::symlink_metadata(&directory) {
        Ok(metadata) => metadata,
        Err(error_value) if error_value.kind() == std::io::ErrorKind::NotFound => return report,
        Err(error_value) => {
            report.complete = false;
            report.diagnostics.push(error(
                "workspace.directory_unreadable",
                WORKSPACE_SEMANTIC_MODEL_DIRECTORY,
                format!("cannot inspect the workspace rule directory: {error_value}"),
            ));
            return report;
        }
    };
    report.enabled = true;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        report.complete = false;
        report.diagnostics.push(error(
            "workspace.invalid_directory",
            WORKSPACE_SEMANTIC_MODEL_DIRECTORY,
            "the workspace rule location must be a real directory, not a link",
        ));
        return report;
    }
    let canonical_directory = match fs::canonicalize(&directory) {
        Ok(directory) if directory.starts_with(&canonical_root) => directory,
        _ => {
            report.complete = false;
            report.diagnostics.push(error(
                "workspace.path_escape",
                WORKSPACE_SEMANTIC_MODEL_DIRECTORY,
                "the workspace rule directory resolves outside the workspace",
            ));
            return report;
        }
    };

    let mut entries = match fs::read_dir(&canonical_directory) {
        Ok(entries) => entries.filter_map(Result::ok).collect::<Vec<_>>(),
        Err(error_value) => {
            report.complete = false;
            report.diagnostics.push(error(
                "workspace.directory_unreadable",
                WORKSPACE_SEMANTIC_MODEL_DIRECTORY,
                format!("cannot read the workspace rule directory: {error_value}"),
            ));
            return report;
        }
    };
    entries.sort_by_key(|entry| entry.file_name());
    if entries.len() > options.max_files {
        report.complete = false;
        report.diagnostics.push(error(
            "limit.workspace_files",
            WORKSPACE_SEMANTIC_MODEL_DIRECTORY,
            format!(
                "workspace rule files exceed the limit of {}",
                options.max_files
            ),
        ));
        entries.truncate(options.max_files);
    }
    let mut resolved_paths = BTreeSet::new();
    for entry in entries {
        let path = entry.path();
        let relative = match path.strip_prefix(&canonical_root) {
            Ok(relative) => relative,
            Err(_) => continue,
        };
        let Some(format) = source_format_for_path(relative) else {
            continue;
        };
        let display_path = portable_relative_path(relative);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => metadata,
            _ => {
                report.complete = false;
                report.diagnostics.push(error(
                    "workspace.invalid_file",
                    &display_path,
                    "workspace rules must be regular direct-child files, not links",
                ));
                continue;
            }
        };
        if metadata.len() > options.compiler.max_source_bytes as u64 {
            report.complete = false;
            report.diagnostics.push(error(
                "limit.source_bytes",
                &display_path,
                format!(
                    "workspace rule exceeds {} bytes",
                    options.compiler.max_source_bytes
                ),
            ));
            continue;
        }
        let canonical_path = match fs::canonicalize(&path) {
            Ok(path) if path.starts_with(&canonical_directory) => path,
            _ => {
                report.complete = false;
                report.diagnostics.push(error(
                    "workspace.path_escape",
                    &display_path,
                    "workspace rule resolves outside the reviewed directory",
                ));
                continue;
            }
        };
        if !resolved_paths.insert(canonical_path.clone()) {
            report.complete = false;
            report.diagnostics.push(error(
                "workspace.duplicate_file",
                &display_path,
                "more than one entry resolves to the same workspace rule",
            ));
            continue;
        }
        let bytes = match fs::read(&canonical_path) {
            Ok(bytes) => bytes,
            Err(error_value) => {
                report.complete = false;
                report.diagnostics.push(error(
                    "workspace.file_unreadable",
                    &display_path,
                    format!("cannot read the workspace rule: {error_value}"),
                ));
                continue;
            }
        };
        let source = lint_semantic_model_source(format, &bytes, &options.compiler);
        report.files.push(WorkspaceSemanticModelFile {
            path: display_path,
            source_sha256: source.source_sha256,
            source_format: match format {
                SourceFormat::Json => "json",
                SourceFormat::Yaml => "yaml",
            }
            .to_owned(),
            valid: source.valid,
            pack_id: source.pack_id,
            manifest_semantic_sha256: source.manifest_semantic_sha256,
            diagnostics: source.diagnostics,
        });
    }
    report.complete &= report.files.iter().all(|file| file.valid);
    report
}

fn source_format_for_path(path: &Path) -> Option<SourceFormat> {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("json") => Some(SourceFormat::Json),
        Some("yaml" | "yml") => Some(SourceFormat::Yaml),
        _ => None,
    }
}

fn portable_relative_path(path: &Path) -> String {
    let mut value = String::new();
    for component in path.components() {
        let Component::Normal(component) = component else {
            continue;
        };
        if !value.is_empty() {
            value.push('/');
        }
        value.push_str(&component.to_string_lossy());
    }
    value
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledPackWriteReport {
    pub format: &'static str,
    pub manifest_path: String,
    pub manifest_content_sha256: String,
    pub shard_paths: Vec<String>,
}

pub fn write_compiled_semantic_model_pack(
    output_root: &Path,
    compiled: &CompiledSemanticModelPack,
) -> std::io::Result<CompiledPackWriteReport> {
    fs::create_dir_all(output_root)?;
    let shards_root = output_root.join("shards");
    fs::create_dir_all(&shards_root)?;
    write_exact_file(&output_root.join("manifest.json"), &compiled.manifest_bytes)?;
    let mut shard_paths = Vec::with_capacity(compiled.shards.len());
    for shard in &compiled.shards {
        let extension = match shard.descriptor.encoding {
            super::ArtifactEncoding::Raw => "json",
            super::ArtifactEncoding::Deflate => "deflate",
        };
        let relative =
            PathBuf::from("shards").join(format!("{}.{}", shard.descriptor.shard_id, extension));
        write_exact_file(&output_root.join(&relative), &shard.bytes)?;
        shard_paths.push(portable_relative_path(&relative));
    }
    Ok(CompiledPackWriteReport {
        format: SEMANTIC_MODEL_WRITE_FORMAT,
        manifest_path: "manifest.json".to_owned(),
        manifest_content_sha256: compiled.manifest.content_sha256.clone(),
        shard_paths,
    })
}

fn write_exact_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if path.exists() {
        if fs::read(path)? == bytes {
            return Ok(());
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("{} exists with different content", path.display()),
        ));
    }
    let parent = path.parent().expect("compiled output file has a parent");
    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| error.error)?;
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelInventoryCoordinate {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelInventoryEvidence {
    pub language: String,
    pub ecosystem: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<SemanticModelInventoryCoordinate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<SemanticModelInventoryCoordinate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub toolchain: Option<SemanticModelInventoryCoordinate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveSemanticModelInventory {
    pub manifest_content_sha256: String,
    pub manifest_semantic_sha256: String,
    pub pack_id: String,
    pub pack_version: String,
    pub shard_id: String,
    pub payload_kind: String,
    pub source_kind: String,
    pub source_id: String,
    pub activation_status: String,
    pub activation_reason: String,
    pub matched_evidence: SemanticModelInventoryEvidence,
    pub provenance: super::Provenance,
    pub completeness: super::Completeness,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelInventoryExplanation {
    pub manifest_content_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pack_id: Option<String>,
    pub shard_id: String,
    pub source_kind: String,
    pub source_id: String,
    pub status: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelInventoryReport {
    pub format: &'static str,
    pub complete: bool,
    pub installed: Vec<CatalogPackInventory>,
    pub active: Vec<ActiveSemanticModelInventory>,
    pub activation_explanations: Vec<SemanticModelInventoryExplanation>,
}

pub fn semantic_model_inventory(
    catalog: &SemanticPackCatalog,
    active: Option<&ResolvedActiveSemanticModels>,
    max_packs: usize,
) -> Result<SemanticModelInventoryReport, CatalogError> {
    let catalog_inventory = catalog.inventory_bounded(max_packs)?;
    let mut active_packs = Vec::new();
    let mut activation_explanations = Vec::new();
    if let Some(active) = active {
        for shard in active.shards() {
            let explanation = active
                .activation_report()
                .explanations
                .iter()
                .find(|explanation| {
                    explanation.manifest_digest == shard.manifest.content_sha256
                        && explanation.shard_id == shard.shard.shard_id
                        && explanation.source_kind == shard.source_kind
                        && explanation.source_id == shard.source_id
                        && explanation.status == SemanticModelActivationStatus::Active
                });
            active_packs.push(ActiveSemanticModelInventory {
                manifest_content_sha256: shard.manifest.content_sha256.clone(),
                manifest_semantic_sha256: shard.manifest.semantic_sha256.clone(),
                pack_id: shard.manifest.pack_id.clone(),
                pack_version: shard.manifest.version.clone(),
                shard_id: shard.shard.shard_id.clone(),
                payload_kind: payload_kind_name(shard.shard.payload_kind()).to_owned(),
                source_kind: shard.source_kind.as_str().to_owned(),
                source_id: shard.source_id.clone(),
                activation_status: "active".to_owned(),
                activation_reason: explanation
                    .map(|explanation| explanation.reason.clone())
                    .unwrap_or_else(|| "selected by active semantic-model resolution".to_owned()),
                matched_evidence: inventory_evidence(&shard.matched_evidence),
                provenance: shard.manifest.provenance.clone(),
                completeness: shard.manifest.completeness,
            });
        }
        for explanation in &active.activation_report().explanations {
            activation_explanations.push(SemanticModelInventoryExplanation {
                manifest_content_sha256: explanation.manifest_digest.clone(),
                pack_id: explanation.pack_id.clone(),
                shard_id: explanation.shard_id.clone(),
                source_kind: explanation.source_kind.as_str().to_owned(),
                source_id: explanation.source_id.clone(),
                status: activation_status_name(explanation.status).to_owned(),
                reason: explanation.reason.clone(),
            });
        }
    }
    active_packs.sort_by(|left, right| {
        left.pack_id
            .cmp(&right.pack_id)
            .then_with(|| left.pack_version.cmp(&right.pack_version))
            .then_with(|| left.shard_id.cmp(&right.shard_id))
            .then_with(|| left.source_kind.cmp(&right.source_kind))
            .then_with(|| left.source_id.cmp(&right.source_id))
    });
    activation_explanations.sort_by(|left, right| {
        left.pack_id
            .cmp(&right.pack_id)
            .then_with(|| left.shard_id.cmp(&right.shard_id))
            .then_with(|| left.status.cmp(&right.status))
            .then_with(|| left.source_kind.cmp(&right.source_kind))
            .then_with(|| left.source_id.cmp(&right.source_id))
    });
    Ok(SemanticModelInventoryReport {
        format: SEMANTIC_MODEL_INVENTORY_FORMAT,
        complete: catalog_inventory.complete,
        installed: catalog_inventory.packs,
        active: active_packs,
        activation_explanations,
    })
}

fn inventory_evidence(
    evidence: &SemanticModelActivationEvidence,
) -> SemanticModelInventoryEvidence {
    SemanticModelInventoryEvidence {
        language: evidence.language.clone(),
        ecosystem: evidence.ecosystem.clone(),
        package: evidence.package.as_ref().map(inventory_coordinate),
        module: evidence.module.as_ref().map(inventory_coordinate),
        toolchain: evidence.toolchain.as_ref().map(inventory_coordinate),
        target: evidence.target.clone(),
        configuration: evidence.configuration.clone(),
        artifact_sha256: evidence.artifact_sha256.clone(),
    }
}

fn inventory_coordinate(coordinate: &super::CatalogCoordinate) -> SemanticModelInventoryCoordinate {
    SemanticModelInventoryCoordinate {
        name: coordinate.name.clone(),
        version: coordinate.version.as_ref().map(ToString::to_string),
    }
}

fn activation_status_name(status: SemanticModelActivationStatus) -> &'static str {
    match status {
        SemanticModelActivationStatus::Active => "active",
        SemanticModelActivationStatus::Disabled => "disabled",
        SemanticModelActivationStatus::Incompatible => "incompatible",
        SemanticModelActivationStatus::ReviewRequired => "review_required",
        SemanticModelActivationStatus::Shadowed => "shadowed",
        SemanticModelActivationStatus::Conflict => "conflict",
        SemanticModelActivationStatus::Unavailable => "unavailable",
    }
}

fn payload_kind_name(kind: super::PayloadKind) -> &'static str {
    match kind {
        super::PayloadKind::DeclarationFacts => "declaration_facts",
        super::PayloadKind::GeneratorRules => "generator_rules",
        super::PayloadKind::ProcedureSummaries => "procedure_summaries",
    }
}
