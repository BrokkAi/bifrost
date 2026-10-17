//! Files-only JS/TS preparation for #2442/#3868. These transient adapter
//! records are not an inventory, activation path or retained analyzer index.
//! The caller supplies one immutable, bounded batch of snapshot bytes. No I/O
//! or process execution occurs here. Durable publication and query vocabulary
//! must use the shared dependency contract, not serialize these records.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use brokk_bifrost_core::analyzer::configuration::{
    ConfigurationDocumentFacts, ConfigurationNodeKind, ConfigurationRouteSelector,
    ConfigurationSourceRange,
};
use brokk_bifrost_js_ts::workspace_packages::decode_package_manifest;
use serde_json::Value;

use crate::CancellationToken;
use crate::analyzer::canonical_hash::{CanonicalHasher, lower_hex_string};
use crate::analyzer::configuration::{
    ConfigurationIngestionOutcome, ingest_configuration_document,
};
use crate::analyzer::topology::{
    DependencyScope, TopologyCompleteness, TopologyEntity, TopologyEntityKind, TopologyProvenance,
    TopologyProvenanceKind,
};

/// The exact bytes of one already authorized, workspace-relative input.
#[derive(Debug, Clone, Copy)]
pub struct JsTsEvidenceInput<'a> {
    pub path: &'a Path,
    pub bytes: &'a [u8],
}

pub(crate) fn is_js_ts_dependency_input(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|n| n.to_str()),
        Some(
            "package.json"
                | "package-lock.json"
                | "npm-shrinkwrap.json"
                | "pnpm-lock.yaml"
                | "yarn.lock"
        )
    )
}

/// Adapt retained source snapshots to the shared publication contract. The
/// selected blob OID identifies the source, and the raw SHA256 stays a condition.
/// Lossy decoding cannot establish a source citation.
pub(crate) fn js_ts_selected_dependency_file_evidence(
    selected: &[(
        crate::analyzer::ProjectFile,
        crate::analyzer::ProjectSourceSnapshot,
    )],
    limits: &crate::analyzer::semantic_model::DependencyFileEvidenceLimits,
) -> crate::analyzer::semantic_model::DependencyFileEvidence {
    use crate::analyzer::semantic_model::{
        DependencyCondition, DependencyEvidenceGap, DependencyEvidenceGapKind,
    };
    let mut sources = BTreeMap::new();
    let mut inputs = Vec::new();
    let mut gaps = Vec::new();
    for (file, source) in selected
        .iter()
        .filter(|(f, _)| is_js_ts_dependency_input(f.rel_path()))
    {
        let actual = git2::Oid::hash_object(git2::ObjectType::Blob, source.source().as_bytes())
            .expect("hash selected source");
        if actual != source.oid() {
            gaps.push(DependencyEvidenceGap {
                kind: DependencyEvidenceGapKind::Malformed,
                build_file: file.rel_path().into(),
                byte_range: 0..0,
                message: "JS/TS dependency snapshot is not exact UTF-8 evidence".into(),
            });
            continue;
        }
        sources.insert(file.rel_path(), source.oid().to_string());
        inputs.push(JsTsEvidenceInput {
            path: file.rel_path(),
            bytes: source.source().as_bytes(),
        });
    }
    if inputs.is_empty() {
        gaps.push(DependencyEvidenceGap {
            kind: DependencyEvidenceGapKind::Missing,
            build_file: PathBuf::new(),
            byte_range: 0..0,
            message: "no JS/TS manifest or lockfile is selected".into(),
        });
    }
    let mut evidence = discover_js_ts_dependency_file_evidence(&inputs, limits, None);
    evidence.gaps.extend(gaps);
    for row in &mut evidence.rows {
        row.conditions.push(DependencyCondition {
            kind: "js.content_sha256".into(),
            value: row.source_digest.clone(),
        });
        row.source_digest = sources[&row.build_file.as_path()].clone();
    }
    evidence
}

#[derive(Debug, Clone, Copy)]
pub struct JsTsEvidenceLimits {
    pub max_files: usize,
    pub max_file_bytes: usize,
    pub max_total_bytes: usize,
    pub max_rows: usize,
    pub max_diagnostics: usize,
}

impl Default for JsTsEvidenceLimits {
    fn default() -> Self {
        Self {
            max_files: 256,
            max_file_bytes: 8 * 1024 * 1024,
            max_total_bytes: 32 * 1024 * 1024,
            max_rows: 50_000,
            max_diagnostics: 256,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsTsBuildEvidence {
    pub path: PathBuf,
    pub content_sha256: String,
    pub range: ConfigurationSourceRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsTsDependencyCategory {
    Dependency,
    Development,
    Optional,
    Peer,
}

impl JsTsDependencyCategory {
    fn scope(self) -> DependencyScope {
        match self {
            Self::Dependency => DependencyScope::Runtime,
            Self::Development => DependencyScope::Unknown,
            Self::Optional => DependencyScope::Optional,
            Self::Peer => DependencyScope::Provided,
        }
    }
}

/// A declaration is a requirement, never proof of a selected/installed package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsTsDependencyDeclaration {
    pub owner_id: String,
    pub alias: String,
    pub package: String,
    pub specifier: String,
    pub category: JsTsDependencyCategory,
    pub scope: DependencyScope,
    pub peer_optional: bool,
    pub evidence: JsTsBuildEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsTsManifestEvidence {
    pub entity: TopologyEntity,
    pub package: Option<String>,
    pub version: Option<String>,
    /// Only a root workspace declaration establishes membership here.
    pub workspace_member: bool,
    pub declarations: Vec<JsTsDependencyDeclaration>,
    pub toolchain: Vec<JsTsToolchainDeclaration>,
    pub directives: Vec<JsTsResolutionDeclaration>,
    pub evidence: JsTsBuildEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsTsToolchainDeclaration {
    pub tool: String,
    pub requirement: Value,
    pub evidence: JsTsBuildEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsTsResolutionDeclaration {
    pub kind: String,
    /// Preserve nested npm overrides and Yarn resolution selectors as authored.
    /// Applying these declarations is outside this reader's proven support.
    pub value: Value,
    pub evidence: JsTsBuildEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsTsLockedInstance {
    pub id: String,
    pub format: String,
    pub locator: String,
    pub package: String,
    pub version: Option<String>,
    pub source: Option<String>,
    pub integrity: Option<String>,
    pub workspace_link: Option<String>,
    /// Peer constraints and platform conditions remain unevaluated metadata.
    pub conditions: BTreeMap<String, Value>,
    pub evidence: JsTsBuildEvidence,
}

/// A direct consumer edge established by the lock's own dependency mapping.
/// A peer constraint alone never creates an edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsTsLockedAssociation {
    pub owner_id: String,
    pub instance_id: String,
    pub alias: String,
    pub category: JsTsDependencyCategory,
    pub requirement: String,
    pub evidence: JsTsBuildEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsTsEvidenceDiagnosticKind {
    Malformed,
    Unsupported,
    MissingMember,
    Conflict,
    Unresolved,
    Limit,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsTsEvidenceDiagnostic {
    pub kind: JsTsEvidenceDiagnosticKind,
    pub path: PathBuf,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsTsEvidencePreparation {
    pub manifests: Vec<JsTsManifestEvidence>,
    pub instances: Vec<JsTsLockedInstance>,
    pub associations: Vec<JsTsLockedAssociation>,
    pub diagnostics: Vec<JsTsEvidenceDiagnostic>,
    pub omitted_diagnostics: usize,
    pub complete: bool,
    pub files_read: usize,
    pub bytes_read: usize,
}

impl JsTsEvidencePreparation {
    fn diagnose(
        &mut self,
        kind: JsTsEvidenceDiagnosticKind,
        path: &Path,
        message: impl Into<String>,
    ) {
        self.complete = false;
        self.diagnostics.push(JsTsEvidenceDiagnostic {
            kind,
            path: path.to_path_buf(),
            message: message.into(),
        });
    }
}

struct Document {
    path: PathBuf,
    value: Value,
    facts: ConfigurationDocumentFacts,
    digest: String,
    ranges: BTreeMap<Vec<String>, ConfigurationSourceRange>,
}

impl Document {
    fn evidence(&self, keys: &[&str]) -> JsTsBuildEvidence {
        let range = if keys.is_empty() {
            self.facts
                .fact(self.facts.document())
                .expect("validated document")
                .evidence()
        } else {
            *self
                .ranges
                .get(&keys.iter().map(|key| (*key).to_owned()).collect::<Vec<_>>())
                .expect("decoded member must have exact parser evidence")
        };
        JsTsBuildEvidence {
            path: self.path.clone(),
            content_sha256: self.digest.clone(),
            range,
        }
    }
}

fn safe_relative(path: &Path) -> bool {
    !path.is_absolute()
        && path.components().all(|part| match part {
            Component::Normal(value) => !value.to_string_lossy().contains(['\\', ':']),
            _ => false,
        })
        && !path
            .components()
            .any(|part| part.as_os_str() == "node_modules")
        && !path.as_os_str().is_empty()
}

fn decode_document(
    input: JsTsEvidenceInput<'_>,
    limits: &JsTsEvidenceLimits,
) -> Result<Document, String> {
    if !safe_relative(input.path) {
        return Err("input path is not a safe workspace-relative path".to_owned());
    }
    if input.bytes.len() > limits.max_file_bytes {
        return Err("input exceeds file byte limit".to_owned());
    }
    let parser_path = if input
        .path
        .file_name()
        .is_some_and(|name| name == "yarn.lock")
    {
        Path::new("yarn-lock.yaml")
    } else {
        input.path
    };
    let facts = match ingest_configuration_document(parser_path, input.bytes) {
        ConfigurationIngestionOutcome::Facts(facts) if facts.completeness().is_complete() => *facts,
        outcome => {
            return Err(format!(
                "configuration parser did not establish clean input: {outcome:?}"
            ));
        }
    };
    let mut routes = BTreeSet::new();
    let mut ranges = BTreeMap::new();
    for fact in facts.facts() {
        if matches!(fact.kind(), ConfigurationNodeKind::Member { .. }) {
            if fact.route().segments().iter().any(|part| matches!(part.selector(), ConfigurationRouteSelector::Key { occurrence, .. } if *occurrence > 1)) { return Err("duplicate mapping key".to_owned()); }
            let route: Vec<_> = fact
                .route()
                .segments()
                .iter()
                .map(|part| part.selector().clone())
                .collect();
            if !routes.insert(route) {
                return Err("duplicate mapping key".to_owned());
            }
            let keys: Option<Vec<_>> = fact
                .route()
                .segments()
                .iter()
                .map(|part| match part.selector() {
                    ConfigurationRouteSelector::Key { name, .. } => Some(name.clone()),
                    ConfigurationRouteSelector::Index(_) => None,
                })
                .collect();
            if let Some(keys) = keys {
                ranges.insert(keys, fact.evidence());
            }
        }
    }
    let value = if parser_path
        .extension()
        .is_some_and(|extension| extension == "yaml")
    {
        decode_lock_yaml(input.bytes)?
    } else {
        decode_package_manifest(input.bytes, limits.max_file_bytes as u64)?
    };
    use sha2::Digest;
    Ok(Document {
        path: input.path.to_path_buf(),
        value,
        facts,
        digest: format!("{:x}", sha2::Sha256::digest(input.bytes)),
        ranges,
    })
}

/// Decode an npm alias without interpreting arbitrary sources as semver.
fn alias_package<'a>(alias: &'a str, specifier: &'a str) -> &'a str {
    let Some(coordinate) = specifier.strip_prefix("npm:") else {
        return alias;
    };
    let start = usize::from(coordinate.starts_with('@'));
    let name = coordinate
        .get(start..)
        .and_then(|suffix| suffix.rfind('@'))
        .map_or(coordinate, |at| &coordinate[..start + at]);
    if name.is_empty() { alias } else { name }
}

const CATEGORIES: [(&str, JsTsDependencyCategory); 4] = [
    ("dependencies", JsTsDependencyCategory::Dependency),
    ("devDependencies", JsTsDependencyCategory::Development),
    ("optionalDependencies", JsTsDependencyCategory::Optional),
    ("peerDependencies", JsTsDependencyCategory::Peer),
];

fn manifest(document: &Document, out: &mut JsTsEvidencePreparation) -> JsTsManifestEvidence {
    let name = document
        .value
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let entity = TopologyEntity {
        kind: TopologyEntityKind::BuildProject,
        // A manifest path is a declared project coordinate, not a guessed
        // source-file owner. Same-name unrelated manifests remain distinct.
        name: format!(
            "npm:{}:{name}",
            document.path.to_string_lossy().replace('\\', "/")
        ),
        owner: None,
        root: document.path.parent().map(Path::to_path_buf),
        provenance: vec![TopologyProvenance::new(
            &document.path,
            TopologyProvenanceKind::ProjectDeclaration,
        )],
        completeness: TopologyCompleteness::Complete,
    };
    let owner_id = entity.id();
    let mut declarations = Vec::new();
    for (field, category) in CATEGORIES {
        let Some(value) = document.value.get(field) else {
            continue;
        };
        let Some(entries) = value.as_object() else {
            out.diagnose(
                JsTsEvidenceDiagnosticKind::Malformed,
                &document.path,
                format!("{field} must be an object"),
            );
            continue;
        };
        for (alias, value) in entries {
            let Some(specifier) = value.as_str() else {
                out.diagnose(
                    JsTsEvidenceDiagnosticKind::Malformed,
                    &document.path,
                    format!("{field}.{alias} must be a string"),
                );
                continue;
            };
            declarations.push(JsTsDependencyDeclaration {
                owner_id: owner_id.clone(),
                alias: alias.clone(),
                package: alias_package(alias, specifier).to_owned(),
                specifier: specifier.to_owned(),
                category,
                scope: category.scope(),
                peer_optional: document
                    .value
                    .get("peerDependenciesMeta")
                    .and_then(|meta| meta.get(alias))
                    .and_then(|meta| meta.get("optional"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                evidence: document.evidence(&[field, alias]),
            });
        }
    }
    let mut toolchain = Vec::new();
    if let Some(engines) = document.value.get("engines") {
        if let Some(engines) = engines.as_object() {
            for (tool, requirement) in engines {
                toolchain.push(JsTsToolchainDeclaration {
                    tool: tool.clone(),
                    requirement: requirement.clone(),
                    evidence: document.evidence(&["engines", tool]),
                });
            }
        } else {
            out.diagnose(
                JsTsEvidenceDiagnosticKind::Malformed,
                &document.path,
                "engines must be an object",
            );
        }
    }
    for field in ["packageManager", "devEngines"] {
        if let Some(requirement) = document.value.get(field) {
            toolchain.push(JsTsToolchainDeclaration {
                tool: field.to_owned(),
                requirement: requirement.clone(),
                evidence: document.evidence(&[field]),
            });
        }
    }
    let mut directives = Vec::new();
    for field in ["overrides", "resolutions"] {
        if let Some(value) = document.value.get(field) {
            directives.push(JsTsResolutionDeclaration {
                kind: field.to_owned(),
                value: value.clone(),
                evidence: document.evidence(&[field]),
            });
            out.diagnose(
                JsTsEvidenceDiagnosticKind::Unsupported,
                &document.path,
                format!(
                    "{field} retained as declared; effective override selection is not established"
                ),
            );
        }
    }
    JsTsManifestEvidence {
        entity,
        package: document
            .value
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_owned),
        version: document
            .value
            .get("version")
            .and_then(Value::as_str)
            .map(str::to_owned),
        workspace_member: false,
        declarations,
        toolchain,
        directives,
        evidence: document.evidence(&[]),
    }
}

/// Prepare only supported build inputs. Unrelated source bytes are excluded
/// from dependency identity. All state has this preparation call's lifetime.
pub fn prepare_js_ts_dependency_evidence(
    inputs: &[JsTsEvidenceInput<'_>],
    limits: &JsTsEvidenceLimits,
    cancellation: Option<&CancellationToken>,
) -> JsTsEvidencePreparation {
    let mut out = JsTsEvidencePreparation {
        manifests: Vec::new(),
        instances: Vec::new(),
        associations: Vec::new(),
        diagnostics: Vec::new(),
        omitted_diagnostics: 0,
        complete: true,
        files_read: 0,
        bytes_read: 0,
    };
    let mut documents = BTreeMap::new();
    let mut total_bytes = 0usize;
    let mut locks = Vec::new();
    let mut input_count = 0usize;
    let mut repeated_paths = BTreeSet::new();
    for input in inputs {
        let Some(name) = input.path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !matches!(
            name,
            "package.json"
                | "package-lock.json"
                | "npm-shrinkwrap.json"
                | "pnpm-lock.yaml"
                | "yarn.lock"
        ) {
            continue;
        }
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            out.diagnose(
                JsTsEvidenceDiagnosticKind::Cancelled,
                input.path,
                "preparation cancelled",
            );
            break;
        }
        input_count = input_count.saturating_add(1);
        total_bytes = total_bytes.saturating_add(input.bytes.len());
        if input_count > limits.max_files
            || total_bytes > limits.max_total_bytes
            || input.bytes.len() > limits.max_file_bytes
        {
            out.diagnose(
                JsTsEvidenceDiagnosticKind::Limit,
                input.path,
                "input file/total byte limit exceeded",
            );
            break;
        }
        out.files_read = out.files_read.saturating_add(1);
        out.bytes_read = out.bytes_read.saturating_add(input.bytes.len());
        if name != "package.json" {
            locks.push(*input);
            continue;
        }
        if repeated_paths.contains(input.path) {
            continue;
        }
        if documents.remove(input.path).is_some() {
            repeated_paths.insert(input.path.to_path_buf());
            out.diagnose(
                JsTsEvidenceDiagnosticKind::Conflict,
                input.path,
                "duplicate input snapshot for path; neither is authoritative",
            );
            continue;
        }
        match decode_document(*input, limits) {
            Ok(document) => {
                documents.insert(input.path.to_path_buf(), document);
            }
            Err(message) => {
                out.diagnose(JsTsEvidenceDiagnosticKind::Malformed, input.path, message)
            }
        }
    }
    for document in documents.values() {
        let parsed = manifest(document, &mut out);
        out.manifests.push(parsed);
    }
    if let Some(root) = documents.get(Path::new("package.json")) {
        if let Some(workspaces) = root.value.get("workspaces") {
            let patterns = workspaces
                .as_array()
                .or_else(|| workspaces.get("packages").and_then(Value::as_array));
            if let Some(patterns) = patterns {
                for pattern in patterns {
                    let Some(pattern) = pattern.as_str() else {
                        out.diagnose(
                            JsTsEvidenceDiagnosticKind::Malformed,
                            &root.path,
                            "workspace pattern must be a string",
                        );
                        continue;
                    };
                    if !safe_relative(Path::new(pattern)) {
                        out.diagnose(
                            JsTsEvidenceDiagnosticKind::Unsupported,
                            &root.path,
                            format!("unsafe workspace pattern {pattern:?}"),
                        );
                        continue;
                    }
                    let pattern = match glob::Pattern::new(pattern) {
                        Ok(pattern) => pattern,
                        Err(error) => {
                            out.diagnose(
                                JsTsEvidenceDiagnosticKind::Malformed,
                                &root.path,
                                error.to_string(),
                            );
                            continue;
                        }
                    };
                    let mut matched = false;
                    for member in &mut out.manifests {
                        if member.evidence.path != root.path
                            && member.entity.root.as_ref().is_some_and(|path| {
                                pattern.matches_path_with(
                                    path,
                                    glob::MatchOptions {
                                        require_literal_separator: true,
                                        ..Default::default()
                                    },
                                )
                            })
                        {
                            member.workspace_member = true;
                            matched = true;
                        }
                    }
                    if !matched {
                        out.diagnose(
                            JsTsEvidenceDiagnosticKind::MissingMember,
                            &root.path,
                            format!("workspace pattern {pattern} has no supplied member manifest"),
                        );
                    }
                }
            } else {
                out.diagnose(
                    JsTsEvidenceDiagnosticKind::Malformed,
                    &root.path,
                    "workspaces must be an array or object with packages array",
                );
            }
        }
    } else {
        out.diagnose(
            JsTsEvidenceDiagnosticKind::MissingMember,
            Path::new("package.json"),
            "root manifest not supplied",
        );
    }
    if locks.len() > 1 {
        out.diagnose(
            JsTsEvidenceDiagnosticKind::Conflict,
            Path::new("package.json"),
            "multiple lockfiles supplied; no manager/precedence selection established",
        );
    }
    locks.sort_by(|left, right| (left.path, left.bytes).cmp(&(right.path, right.bytes)));
    if locks.is_empty() {
        out.diagnose(
            JsTsEvidenceDiagnosticKind::Unresolved,
            Path::new("package.json"),
            "no lock supplied; evidence is declaration-only",
        );
    }
    for lock in locks {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            out.diagnose(
                JsTsEvidenceDiagnosticKind::Cancelled,
                lock.path,
                "preparation cancelled",
            );
            break;
        }
        match lock.path.file_name().and_then(|name| name.to_str()) {
            Some("package-lock.json" | "npm-shrinkwrap.json") => {
                match decode_document(lock, limits) {
                    Ok(document) => prepare_npm_lock(&document, &mut out, cancellation),
                    Err(message) => {
                        out.diagnose(JsTsEvidenceDiagnosticKind::Malformed, lock.path, message)
                    }
                }
            }
            Some("yarn.lock") => prepare_yarn_lock(lock, limits, &mut out, cancellation),
            Some("pnpm-lock.yaml") => match decode_document(lock, limits) {
                Ok(document) => {
                    prepare_pnpm_lock(&document, &mut out, cancellation);
                }
                Err(message) => {
                    out.diagnose(JsTsEvidenceDiagnosticKind::Unsupported, lock.path, message)
                }
            },
            _ => unreachable!("lock names were filtered above"),
        }
    }
    // Include cancellation during bounded value decoding or reference
    // reconciliation, which do not expose parser progress callbacks.
    if cancellation.is_some_and(CancellationToken::is_cancelled)
        && !out
            .diagnostics
            .iter()
            .any(|gap| gap.kind == JsTsEvidenceDiagnosticKind::Cancelled)
    {
        out.diagnose(
            JsTsEvidenceDiagnosticKind::Cancelled,
            Path::new("package.json"),
            "preparation cancelled before publication",
        );
    }
    let row_count = out
        .manifests
        .iter()
        .map(|manifest| {
            1 + manifest.declarations.len() + manifest.toolchain.len() + manifest.directives.len()
        })
        .sum::<usize>()
        + out.instances.len()
        + out.associations.len();
    if row_count > limits.max_rows {
        out.manifests.clear();
        out.instances.clear();
        out.associations.clear();
        out.diagnose(
            JsTsEvidenceDiagnosticKind::Limit,
            Path::new("package.json"),
            "prepared row limit exceeded; no partial collection published",
        );
    }
    out.omitted_diagnostics = out.diagnostics.len().saturating_sub(limits.max_diagnostics);
    out.diagnostics.truncate(limits.max_diagnostics);
    out
}

fn instance_id(
    path: &Path,
    locator: &str,
    package: &str,
    version: Option<&str>,
    source: Option<&str>,
    snapshot: &str,
) -> String {
    let mut hasher = CanonicalHasher::new(b"bifrost.npm.lock-instance.v1");
    hasher.field(
        "lockfile",
        path.to_string_lossy().replace('\\', "/").as_bytes(),
    );
    hasher.field("locator", locator.as_bytes());
    hasher.field("package", package.as_bytes());
    hasher.field("version", version.unwrap_or("").as_bytes());
    hasher.field("source", source.unwrap_or("").as_bytes());
    hasher.field("snapshot", snapshot.as_bytes());
    lower_hex_string(&hasher.finish())
}

fn lock_conditions(entry: &Value) -> BTreeMap<String, Value> {
    [
        "dev",
        "optional",
        "devOptional",
        "peer",
        "peerDependencies",
        "peerDependenciesMeta",
        "os",
        "cpu",
        "libc",
        "engines",
        "hasInstallScript",
        "dependencies",
        "optionalDependencies",
        "dependenciesMeta",
        "conditions",
        "transitivePeerDependencies",
        "requiresBuild",
        "inBundle",
        "linkType",
    ]
    .into_iter()
    .filter_map(|field| {
        entry
            .get(field)
            .map(|value| (field.to_owned(), value.clone()))
    })
    .collect()
}

/// Validate selected structured values, without treating missing optional maps
/// as empty dependency selections or interpreting unsupported authored values.
fn validate_lock_maps(
    entry: &Value,
    extra_fields: &[&str],
    context: &str,
    document: &Document,
    out: &mut JsTsEvidencePreparation,
) -> bool {
    if !entry.is_object() {
        out.diagnose(
            JsTsEvidenceDiagnosticKind::Malformed,
            &document.path,
            format!("{context} must be a mapping"),
        );
        return false;
    }
    let mut valid = true;
    for field in CATEGORIES
        .iter()
        .map(|(field, _)| *field)
        .chain(["peerDependenciesMeta", "dependenciesMeta", "engines"])
        .chain(extra_fields.iter().copied())
    {
        if entry.get(field).is_some_and(|value| !value.is_object()) {
            out.diagnose(
                JsTsEvidenceDiagnosticKind::Malformed,
                &document.path,
                format!("{context}.{field} must be a mapping"),
            );
            valid = false;
        }
    }
    valid
}

/// npm and pnpm category tables must explicitly retain each authored non-peer
/// edge. An omitted requirement never proves a selected or absent dependency.
fn diagnose_missing_importer_edges(
    owner_id: &str,
    importer: &str,
    entry: &Value,
    document: &Document,
    out: &mut JsTsEvidencePreparation,
) {
    let missing: Vec<_> = out
        .manifests
        .iter()
        .find(|manifest| manifest.entity.id() == owner_id)
        .expect("exact importer has a known manifest")
        .declarations
        .iter()
        .filter(|declaration| declaration.category != JsTsDependencyCategory::Peer)
        .filter(|declaration| {
            entry
                .get(category_label(declaration.category))
                .and_then(|entries| entries.get(&declaration.alias))
                .is_none()
        })
        .map(|declaration| {
            format!(
                "importer {importer}.{}.{} has no lock edge for the authored manifest requirement",
                category_label(declaration.category),
                declaration.alias
            )
        })
        .collect();
    for message in missing {
        out.diagnose(
            JsTsEvidenceDiagnosticKind::Unresolved,
            &document.path,
            message,
        );
    }
}

fn package_at_location(locator: &str) -> Option<String> {
    let components: Vec<_> = Path::new(locator).components().collect();
    let at = components
        .iter()
        .rposition(|part| part.as_os_str() == "node_modules")?;
    let suffix = &components[at + 1..];
    match suffix {
        [Component::Normal(name)] => name.to_str().map(str::to_owned),
        [Component::Normal(scope), Component::Normal(name)]
            if scope.to_str().is_some_and(|scope| scope.starts_with('@')) =>
        {
            Some(format!("{}/{}", scope.to_str()?, name.to_str()?))
        }
        _ => None,
    }
}

fn safe_locator(locator: &str) -> bool {
    // Both separator spellings must be handled consistently across hosts.
    !locator.contains('\\')
        && !locator.contains(':')
        && !Path::new(locator).is_absolute()
        && Path::new(locator)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

fn resolve_npm_location(
    packages: &serde_json::Map<String, Value>,
    consumer: &str,
    alias: &str,
) -> Option<String> {
    if alias.is_empty()
        || alias.contains('\\')
        || alias.contains(':')
        || alias.starts_with('/')
        || alias
            .split('/')
            .any(|part| matches!(part, "" | "." | ".." | "node_modules"))
    {
        return None;
    }
    let mut directory = Path::new(consumer);
    loop {
        let candidate = directory
            .join("node_modules")
            .join(alias)
            .to_string_lossy()
            .replace('\\', "/");
        if packages.contains_key(&candidate) {
            return Some(candidate);
        }
        directory = directory.parent()?;
    }
}

fn prepare_npm_lock(
    document: &Document,
    out: &mut JsTsEvidencePreparation,
    cancellation: Option<&CancellationToken>,
) {
    let packages = match super::external::exact_npm_packages_table(&document.value) {
        Ok(packages) => packages,
        Err(message) => {
            out.diagnose(
                JsTsEvidenceDiagnosticKind::Unsupported,
                &document.path,
                message,
            );
            return;
        }
    };
    let format = format!("npm-packages-v{}", document.value["lockfileVersion"]);
    let mut by_locator = BTreeMap::new();
    let mut valid_entries = BTreeSet::new();
    // Collect alias targets from this lock's own dependency declarations,
    // never from another member's manifest or another lockfile.
    let mut aliases: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (consumer, entry) in packages {
        if !safe_locator(consumer) {
            out.diagnose(
                JsTsEvidenceDiagnosticKind::Malformed,
                &document.path,
                format!("unsafe package locator {consumer:?}"),
            );
            continue;
        }
        for (field, category) in CATEGORIES {
            if category == JsTsDependencyCategory::Peer {
                continue;
            }
            if let Some(declarations) = entry.get(field).and_then(Value::as_object) {
                for (alias, specifier) in declarations {
                    if let Some(specifier) = specifier.as_str()
                        && let Some(location) = resolve_npm_location(packages, consumer, alias)
                    {
                        aliases
                            .entry(location)
                            .or_default()
                            .insert(alias_package(alias, specifier).to_owned());
                    }
                }
            }
        }
    }
    for (locator, entry) in packages {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            out.diagnose(
                JsTsEvidenceDiagnosticKind::Cancelled,
                &document.path,
                "npm preparation cancelled",
            );
            return;
        }
        if !safe_locator(locator) || !entry.is_object() {
            out.diagnose(
                JsTsEvidenceDiagnosticKind::Malformed,
                &document.path,
                format!("invalid package entry {locator:?}"),
            );
            continue;
        }
        if !validate_lock_maps(
            entry,
            &[],
            &format!("npm package {locator:?}"),
            document,
            out,
        ) {
            continue;
        }
        valid_entries.insert(locator.as_str());
        if package_at_location(locator).is_none() {
            let manifest_path = document
                .path
                .parent()
                .expect("relative file has a parent")
                .join(locator)
                .join("package.json");
            if !out
                .manifests
                .iter()
                .any(|manifest| manifest.evidence.path == manifest_path)
            {
                out.diagnose(
                    JsTsEvidenceDiagnosticKind::MissingMember,
                    &document.path,
                    format!("npm package-table member {locator:?} has no supplied manifest"),
                );
            }
            continue;
        } // Root/member tables are consumer evidence, not installed observations.
        let link = entry.get("link").and_then(Value::as_bool).unwrap_or(false);
        let workspace_link = if link {
            entry
                .get("resolved")
                .and_then(Value::as_str)
                .map(str::to_owned)
        } else {
            None
        };
        if link
            && workspace_link
                .as_deref()
                .is_none_or(|target| !safe_locator(target))
        {
            out.diagnose(
                JsTsEvidenceDiagnosticKind::Malformed,
                &document.path,
                format!("unsafe or missing link target for {locator}"),
            );
            continue;
        }
        let inferred_name = aliases
            .get(locator)
            .filter(|names| names.len() == 1)
            .and_then(|names| names.first())
            .cloned();
        if aliases.get(locator).is_some_and(|names| names.len() > 1) {
            out.diagnose(
                JsTsEvidenceDiagnosticKind::Conflict,
                &document.path,
                format!("conflicting alias targets for {locator}"),
            );
        }
        let linked_entry = workspace_link
            .as_deref()
            .and_then(|target| packages.get(target));
        if workspace_link
            .as_ref()
            .is_some_and(|_| linked_entry.is_none())
        {
            out.diagnose(
                JsTsEvidenceDiagnosticKind::MissingMember,
                &document.path,
                format!("workspace link {locator} has no package-table target"),
            );
        }
        let package = entry
            .get("name")
            .and_then(Value::as_str)
            .or_else(|| {
                linked_entry
                    .and_then(|entry| entry.get("name"))
                    .and_then(Value::as_str)
            })
            .map(str::to_owned)
            .or(inferred_name)
            .unwrap_or_else(|| {
                package_at_location(locator).expect("validated installation locator")
            });
        let raw_version = entry
            .get("version")
            .or_else(|| linked_entry.and_then(|entry| entry.get("version")))
            .and_then(Value::as_str);
        let version = raw_version.and_then(exact_npm_version);
        if !link && version.is_none() {
            out.diagnose(
                JsTsEvidenceDiagnosticKind::Unresolved,
                &document.path,
                format!("no exact version for {locator}"),
            );
        }
        let source = entry
            .get("resolved")
            .and_then(Value::as_str)
            .or_else(|| raw_version.filter(|version| exact_npm_version(version).is_none()))
            .map(str::to_owned);
        let id = instance_id(
            &document.path,
            locator,
            &package,
            version.as_deref(),
            source.as_deref(),
            &document.digest,
        );
        by_locator.insert(locator.clone(), id.clone());
        out.instances.push(JsTsLockedInstance {
            id,
            format: format.clone(),
            locator: locator.clone(),
            package,
            version,
            source,
            integrity: entry
                .get("integrity")
                .and_then(Value::as_str)
                .map(str::to_owned),
            workspace_link,
            conditions: lock_conditions(entry),
            evidence: document.evidence(&["packages", locator]),
        });
    }
    let lock_root = document.path.parent().expect("relative file has a parent");
    // Only exact package-table importers justify a consuming manifest edge.
    let missing_importers: Vec<_> = out
        .manifests
        .iter()
        .filter_map(|manifest| {
            let relative = manifest
                .entity
                .root
                .as_ref()?
                .strip_prefix(lock_root)
                .ok()?;
            let locator = relative.to_string_lossy().replace('\\', "/");
            (!packages.contains_key(&locator)).then_some(locator)
        })
        .collect();
    for locator in missing_importers {
        out.diagnose(
            JsTsEvidenceDiagnosticKind::Unresolved,
            &document.path,
            format!("manifest {locator:?} has no npm package-table importer"),
        );
    }
    let consumers: Vec<_> = out
        .manifests
        .iter()
        .filter_map(|manifest| {
            let relative = manifest
                .entity
                .root
                .as_ref()?
                .strip_prefix(lock_root)
                .ok()?;
            let locator = relative.to_string_lossy().replace('\\', "/");
            if !valid_entries.contains(locator.as_str()) {
                return None;
            }
            packages
                .get(&locator)
                .map(|entry| (manifest.entity.id(), locator, entry))
        })
        .collect();
    for (owner_id, locator, entry) in consumers {
        diagnose_missing_importer_edges(&owner_id, &locator, entry, document, out);
        for (field, category) in CATEGORIES {
            if category == JsTsDependencyCategory::Peer {
                continue;
            }
            let Some(declarations) = entry.get(field) else {
                continue;
            };
            let Some(declarations) = declarations.as_object() else {
                out.diagnose(
                    JsTsEvidenceDiagnosticKind::Malformed,
                    &document.path,
                    format!("{locator}.{field} must be an object"),
                );
                continue;
            };
            for (alias, requirement) in declarations {
                let Some(requirement) = requirement.as_str() else {
                    out.diagnose(
                        JsTsEvidenceDiagnosticKind::Malformed,
                        &document.path,
                        format!("{locator}.{field}.{alias} must be a string"),
                    );
                    continue;
                };
                if let Some(manifest) = out
                    .manifests
                    .iter()
                    .find(|manifest| manifest.entity.id() == owner_id)
                    && !manifest.declarations.iter().any(|declaration| {
                        declaration.alias == *alias
                            && declaration.category == category
                            && declaration.specifier == requirement
                    })
                {
                    out.diagnose(
                        JsTsEvidenceDiagnosticKind::Conflict,
                        &document.path,
                        format!("npm lock and manifest disagree for {locator}.{field}.{alias}"),
                    );
                }
                let selected = resolve_npm_location(packages, &locator, alias)
                    .and_then(|locator| by_locator.get(&locator));
                if let Some(instance_id) = selected {
                    out.associations.push(JsTsLockedAssociation {
                        owner_id: owner_id.clone(),
                        instance_id: instance_id.clone(),
                        alias: alias.clone(),
                        category,
                        requirement: requirement.to_owned(),
                        evidence: document.evidence(&["packages", &locator, field, alias]),
                    });
                } else {
                    out.diagnose(
                        JsTsEvidenceDiagnosticKind::Unresolved,
                        &document.path,
                        format!("{locator}.{field}.{alias} has no established lock instance"),
                    );
                }
            }
        }
    }
}

fn decode_lock_yaml(bytes: &[u8]) -> Result<Value, String> {
    use serde_saphyr::{DuplicateKeyPolicy, MergeKeyPolicy};
    let options = serde_saphyr::options! {
        budget: serde_saphyr::budget! {
            max_reader_input_bytes: Some(bytes.len()), max_events: 2_000_000,
            max_aliases: 0, max_anchors: 0, max_depth: 64, max_inclusion_depth: 0,
            max_documents: 1, max_nodes: 1_000_000, max_total_scalar_bytes: bytes.len(),
            max_total_comment_bytes: bytes.len(), max_merge_keys: 0,
        },
        duplicate_keys: DuplicateKeyPolicy::Error,
        merge_keys: MergeKeyPolicy::Error,
        alias_limits: serde_saphyr::alias_limits! {
            max_total_replayed_events: 0, max_replay_stack_depth: 0, max_alias_expansions_per_anchor: 0,
        },
        strict_booleans: true,
        no_schema: true,
    };
    serde_saphyr::from_reader_with_options(std::io::Cursor::new(bytes), options)
        .map_err(|error| error.to_string())
}

fn scalar_text(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

/// pnpm's registry package key includes peer qualifiers on snapshot keys.
/// Parse only the name/version boundary, retaining the complete locator as
/// identity and leaving qualifiers opaque rather than evaluating peers.
fn pnpm_coordinate(locator: &str) -> Option<(&str, &str)> {
    let package_key = locator.split_once('(').map_or(locator, |(base, _)| base);
    package_key
        .rsplit_once('@')
        .filter(|(name, version)| !name.is_empty() && !version.is_empty())
}

fn prepare_pnpm_lock(
    document: &Document,
    out: &mut JsTsEvidencePreparation,
    cancellation: Option<&CancellationToken>,
) {
    let version = document.value.get("lockfileVersion").and_then(scalar_text);
    if version.as_deref() != Some("9.0") {
        out.diagnose(
            JsTsEvidenceDiagnosticKind::Unsupported,
            &document.path,
            format!("supported pnpm lockfileVersion is 9.0, got {version:?}"),
        );
        return;
    }
    let (Some(importers), Some(packages), Some(snapshots)) = (
        document.value.get("importers").and_then(Value::as_object),
        document.value.get("packages").and_then(Value::as_object),
        document.value.get("snapshots").and_then(Value::as_object),
    ) else {
        out.diagnose(
            JsTsEvidenceDiagnosticKind::Malformed,
            &document.path,
            "pnpm 9 requires importer/package/snapshot tables",
        );
        return;
    };
    let mut by_locator = BTreeMap::new();
    for (locator, snapshot) in snapshots {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            out.diagnose(
                JsTsEvidenceDiagnosticKind::Cancelled,
                &document.path,
                "pnpm preparation cancelled",
            );
            return;
        }
        let Some((package, raw_version)) = pnpm_coordinate(locator) else {
            out.diagnose(
                JsTsEvidenceDiagnosticKind::Unsupported,
                &document.path,
                format!("unsupported pnpm snapshot locator {locator:?}"),
            );
            continue;
        };
        let base = locator
            .split_once('(')
            .map_or(locator.as_str(), |(base, _)| base);
        let metadata = packages.get(base);
        if metadata.is_none() {
            out.diagnose(
                JsTsEvidenceDiagnosticKind::Unresolved,
                &document.path,
                format!("snapshot {locator} has no matching package metadata"),
            );
            continue;
        }
        let metadata = metadata.expect("validated above");
        if !validate_lock_maps(
            snapshot,
            &[],
            &format!("pnpm snapshot {locator}"),
            document,
            out,
        ) || !validate_lock_maps(
            metadata,
            &["resolution"],
            &format!("pnpm package {base}"),
            document,
            out,
        ) {
            continue;
        }
        let resolution = metadata.get("resolution");
        let source = resolution
            .and_then(|value| value.get("tarball").or_else(|| value.get("repo")))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let version = exact_npm_version(raw_version);
        let id = instance_id(
            &document.path,
            locator,
            package,
            version.as_deref(),
            source.as_deref(),
            &document.digest,
        );
        by_locator.insert(locator.clone(), id.clone());
        let mut conditions = lock_conditions(metadata);
        conditions.extend(lock_conditions(snapshot));
        conditions.insert("pnpm_snapshot".to_owned(), Value::String(locator.clone()));
        if let Some(resolution) = resolution {
            conditions.insert("resolution".to_owned(), resolution.clone());
        }
        out.instances.push(JsTsLockedInstance {
            id,
            format: "pnpm-9.0".to_owned(),
            locator: locator.clone(),
            package: package.to_owned(),
            version,
            source,
            integrity: resolution
                .and_then(|value| value.get("integrity"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            workspace_link: None,
            conditions,
            evidence: document.evidence(&["snapshots", locator]),
        });
    }
    // Unreferenced package-table entries remain locked candidates, not selected
    // importer closures. A separate package key does not inherit a peer context.
    for (locator, metadata) in packages {
        if by_locator.contains_key(locator) {
            continue;
        }
        if !validate_lock_maps(
            metadata,
            &["resolution"],
            &format!("pnpm package {locator}"),
            document,
            out,
        ) {
            continue;
        }
        let Some((package, raw_version)) = pnpm_coordinate(locator) else {
            out.diagnose(
                JsTsEvidenceDiagnosticKind::Unsupported,
                &document.path,
                format!("unsupported pnpm package locator {locator:?}"),
            );
            continue;
        };
        let resolution = metadata.get("resolution");
        let source = resolution
            .and_then(|value| value.get("tarball").or_else(|| value.get("repo")))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let version = exact_npm_version(raw_version);
        out.instances.push(JsTsLockedInstance {
            id: instance_id(
                &document.path,
                locator,
                package,
                version.as_deref(),
                source.as_deref(),
                &document.digest,
            ),
            format: "pnpm-9.0-package".to_owned(),
            locator: locator.clone(),
            package: package.to_owned(),
            version,
            source,
            integrity: resolution
                .and_then(|value| value.get("integrity"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            workspace_link: None,
            conditions: lock_conditions(metadata),
            evidence: document.evidence(&["packages", locator]),
        });
    }
    let lock_root = document.path.parent().expect("relative file has a parent");
    let owners: BTreeMap<_, _> = out
        .manifests
        .iter()
        .filter_map(|manifest| Some((manifest.entity.root.as_ref()?.clone(), manifest.entity.id())))
        .collect();
    let missing_importers: Vec<_> = out
        .manifests
        .iter()
        .filter_map(|manifest| {
            if !manifest
                .declarations
                .iter()
                .any(|declaration| declaration.category != JsTsDependencyCategory::Peer)
            {
                return None;
            }
            let relative = manifest
                .entity
                .root
                .as_ref()?
                .strip_prefix(lock_root)
                .ok()?;
            let importer = if relative.as_os_str().is_empty() {
                ".".to_owned()
            } else {
                relative.to_string_lossy().replace('\\', "/")
            };
            (!importers.contains_key(&importer)).then_some(importer)
        })
        .collect();
    for importer in missing_importers {
        out.diagnose(
            JsTsEvidenceDiagnosticKind::Unresolved,
            &document.path,
            format!(
                "pnpm manifest {importer:?} has no lock importer for its authored requirements"
            ),
        );
    }
    for (importer, entry) in importers {
        if !validate_lock_maps(
            entry,
            &[],
            &format!("pnpm importer {importer}"),
            document,
            out,
        ) {
            continue;
        }
        if importer != "." && !safe_locator(importer) {
            out.diagnose(
                JsTsEvidenceDiagnosticKind::Malformed,
                &document.path,
                format!("unsafe importer {importer:?}"),
            );
            continue;
        }
        let root = if importer == "." {
            lock_root.to_path_buf()
        } else {
            lock_root.join(importer)
        };
        let Some(owner_id) = owners.get(&root) else {
            out.diagnose(
                JsTsEvidenceDiagnosticKind::MissingMember,
                &document.path,
                format!("importer {importer} has no supplied member manifest"),
            );
            continue;
        };
        diagnose_missing_importer_edges(owner_id, importer, entry, document, out);
        for (field, category) in CATEGORIES {
            if category == JsTsDependencyCategory::Peer {
                continue;
            }
            let Some(declarations) = entry.get(field) else {
                continue;
            };
            let Some(declarations) = declarations.as_object() else {
                out.diagnose(
                    JsTsEvidenceDiagnosticKind::Malformed,
                    &document.path,
                    format!("importer {importer}.{field} must be a map"),
                );
                continue;
            };
            for (alias, dependency) in declarations {
                let (Some(requirement), Some(selected)) = (
                    dependency.get("specifier").and_then(Value::as_str),
                    dependency.get("version").and_then(Value::as_str),
                ) else {
                    out.diagnose(
                        JsTsEvidenceDiagnosticKind::Malformed,
                        &document.path,
                        format!("importer {importer}.{alias} lacks specifier/version"),
                    );
                    continue;
                };
                if let Some(manifest) = out
                    .manifests
                    .iter()
                    .find(|manifest| manifest.entity.id() == *owner_id)
                    && !manifest.declarations.iter().any(|declaration| {
                        declaration.alias == *alias
                            && declaration.category == category
                            && declaration.specifier == requirement
                    })
                {
                    out.diagnose(
                        JsTsEvidenceDiagnosticKind::Conflict,
                        &document.path,
                        format!("pnpm importer and manifest disagree for {importer}.{alias}"),
                    );
                }
                let evidence = document.evidence(&["importers", importer, field, alias]);
                let package = alias_package(alias, requirement);
                let locator = format!("{package}@{selected}");
                let target = by_locator
                    .get(&locator)
                    .or_else(|| by_locator.get(selected));
                let instance_id = if let Some(target) = target {
                    target.clone()
                } else if let Some(link) = selected.strip_prefix("link:") {
                    // A link retains its exact relative source. Do not resolve
                    // it through disk or attach an unrelated package version.
                    let id = instance_id(
                        &document.path,
                        &format!("{importer}:{alias}:{selected}"),
                        package,
                        None,
                        Some(selected),
                        &document.digest,
                    );
                    out.instances.push(JsTsLockedInstance {
                        id: id.clone(),
                        format: "pnpm-9.0-link".to_owned(),
                        locator: format!("{importer}:{alias}:{selected}"),
                        package: package.to_owned(),
                        version: None,
                        source: Some(selected.to_owned()),
                        integrity: None,
                        workspace_link: Some(link.to_owned()),
                        conditions: BTreeMap::new(),
                        evidence: evidence.clone(),
                    });
                    id
                } else {
                    out.diagnose(
                        JsTsEvidenceDiagnosticKind::Unresolved,
                        &document.path,
                        format!(
                            "importer {importer}.{alias} references missing snapshot {selected:?}"
                        ),
                    );
                    continue;
                };
                out.associations.push(JsTsLockedAssociation {
                    owner_id: owner_id.clone(),
                    instance_id,
                    alias: alias.clone(),
                    category,
                    requirement: requirement.to_owned(),
                    evidence,
                });
            }
        }
    }
}

fn prepare_yarn_lock(
    input: JsTsEvidenceInput<'_>,
    limits: &JsTsEvidenceLimits,
    out: &mut JsTsEvidencePreparation,
    cancellation: Option<&CancellationToken>,
) {
    if !safe_relative(input.path) || std::str::from_utf8(input.bytes).is_err() {
        out.diagnose(
            JsTsEvidenceDiagnosticKind::Malformed,
            input.path,
            "Yarn input must be UTF-8 at a safe workspace-relative path",
        );
        return;
    }
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_yarnlock::LANGUAGE.into())
        .expect("released Yarn grammar is compatible with Tree-sitter");
    let mut read = |offset: usize, _| &input.bytes[offset..];
    let mut progress =
        |_: &tree_sitter::ParseState| cancellation.is_some_and(CancellationToken::is_cancelled);
    let Some(tree) = parser.parse_with_options(
        &mut read,
        None,
        Some(tree_sitter::ParseOptions::new().progress_callback(&mut progress)),
    ) else {
        out.diagnose(
            JsTsEvidenceDiagnosticKind::Cancelled,
            input.path,
            "Yarn parsing cancelled",
        );
        return;
    };
    let root = tree.root_node();
    let mut cursor = root.walk();
    let headers: Vec<_> = root
        .named_children(&mut cursor)
        .filter(|node| node.kind() == "comment")
        .filter_map(|node| {
            node.utf8_text(input.bytes)
                .expect("validated UTF-8")
                .strip_prefix("# yarn lockfile ")
                .map(str::trim_end)
        })
        .collect();
    if headers.is_empty() {
        match decode_document(input, limits) {
            Ok(document) => prepare_yarn_berry_lock(&document, out, cancellation),
            Err(message) => out.diagnose(
                JsTsEvidenceDiagnosticKind::Unsupported,
                input.path,
                format!("expected Classic v1 header or supported Berry YAML: {message}"),
            ),
        }
        return;
    }
    if headers != ["v1"] {
        out.diagnose(
            JsTsEvidenceDiagnosticKind::Unsupported,
            input.path,
            format!("supported Classic header is v1, found {headers:?}"),
        );
        return;
    }
    if root.has_error() {
        out.diagnose(
            JsTsEvidenceDiagnosticKind::Malformed,
            input.path,
            "Classic input is malformed or outside tree-sitter-yarnlock 0.2.0 syntax; recovery tree rejected",
        );
        return;
    }
    let parsed = match yarn_lock_parser::parse_str(
        std::str::from_utf8(input.bytes).expect("validated UTF-8"),
    ) {
        Ok(parsed) => parsed,
        Err(error) => {
            out.diagnose(
                JsTsEvidenceDiagnosticKind::Malformed,
                input.path,
                format!("Classic structured decoder rejected input: {error}"),
            );
            return;
        }
    };
    if parsed.version != 1 || parsed.generator != yarn_lock_parser::Generator::Yarn {
        out.diagnose(
            JsTsEvidenceDiagnosticKind::Unsupported,
            input.path,
            "Classic adapter supports Yarn v1, not Bun or other generators/versions",
        );
        return;
    }
    let nodes: Vec<_> = root
        .named_children(&mut root.walk())
        .filter(|node| node.kind() == "dependency")
        .collect();
    if nodes.len() != parsed.entries.len() {
        out.diagnose(
            JsTsEvidenceDiagnosticKind::Malformed,
            input.path,
            "Classic parsers disagree on entry boundaries",
        );
        return;
    }
    use sha2::Digest;
    let digest = lower_hex_string(&sha2::Sha256::digest(input.bytes).into());
    for (node, entry) in nodes.into_iter().zip(&parsed.entries) {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            out.diagnose(
                JsTsEvidenceDiagnosticKind::Cancelled,
                input.path,
                "Classic preparation cancelled",
            );
            return;
        }
        if out.instances.len() >= limits.max_rows {
            out.diagnose(
                JsTsEvidenceDiagnosticKind::Limit,
                input.path,
                "Classic instance row limit exceeded",
            );
            return;
        }
        match classic_instance(node, entry, input, &digest) {
            Ok(instance) => {
                if instance.conditions.contains_key("parser_validation") {
                    out.diagnose(JsTsEvidenceDiagnosticKind::Unsupported, input.path, format!("Classic {}: upstream grammar and structured decoder disagree on dependency-block syntax; strict validation remains unresolved", instance.locator));
                }
                if instance.version.is_none() {
                    out.diagnose(
                        JsTsEvidenceDiagnosticKind::Unresolved,
                        input.path,
                        format!("Classic {} has no supported exact npm version", instance.id),
                    );
                }
                if instance.conditions.contains_key("unresolved_source") {
                    out.diagnose(
                        JsTsEvidenceDiagnosticKind::Unresolved,
                        input.path,
                        format!(
                            "Classic {} has competing descriptor sources without a resolved source",
                            instance.locator
                        ),
                    );
                }
                out.instances.push(instance);
            }
            Err(message) => {
                out.diagnose(JsTsEvidenceDiagnosticKind::Malformed, input.path, message)
            }
        }
    }
    // Classic records descriptor -> package mappings, not importer -> package
    // mappings. Keep all candidates unowned, even when manifests match.
    out.diagnose(
        JsTsEvidenceDiagnosticKind::Unresolved,
        input.path,
        "Classic has no importer/workspace or peer/platform selection table; member ownership and conditional applicability remain unresolved",
    );
    let mut descriptors: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    for instance in out.instances.iter().filter(|instance| {
        instance.evidence.path == input.path
            && instance.evidence.content_sha256 == digest
            && instance.format == "yarn-classic-1"
    }) {
        for descriptor in instance.conditions["descriptors"]
            .as_array()
            .expect("Classic descriptors are pairs")
        {
            let alias = descriptor[0].as_str().expect("descriptor alias").to_owned();
            let requirement = descriptor[1]
                .as_str()
                .expect("descriptor requirement")
                .to_owned();
            descriptors
                .entry((alias, requirement))
                .or_default()
                .insert(instance.id.clone());
        }
    }
    let mut gaps = Vec::new();
    for (descriptor, targets) in &descriptors {
        if targets.len() != 1 {
            gaps.push((
                JsTsEvidenceDiagnosticKind::Conflict,
                format!("Classic descriptor {descriptor:?} selects competing groups {targets:?}"),
            ));
        }
    }
    for instance in out.instances.iter_mut().filter(|instance| {
        instance.evidence.path == input.path
            && instance.evidence.content_sha256 == digest
            && instance.format == "yarn-classic-1"
    }) {
        let mut references = Vec::new();
        for category in ["dependencies", "optionalDependencies"] {
            for reference in instance.conditions[category]
                .as_array()
                .expect("Classic dependency pairs")
            {
                let alias = reference[0].as_str().expect("dependency alias");
                let requirement = reference[1].as_str().expect("dependency requirement");
                let targets = descriptors.get(&(alias.to_owned(), requirement.to_owned()));
                if !targets.is_some_and(|targets| targets.len() == 1) {
                    gaps.push((
                        JsTsEvidenceDiagnosticKind::Unresolved,
                        format!(
                            "Classic {} reference {alias}@{requirement} is missing or ambiguous",
                            instance.id
                        ),
                    ));
                }
                references.push(serde_json::json!({
                    "category": category,
                    "alias": alias,
                    "requirement": requirement,
                    // An ambiguous descriptor does not establish any edge.
                    // Avoid repeating all conflicting candidates per reference.
                    "resolution": match targets { Some(targets) if targets.len() == 1 => "unique", Some(_) => "ambiguous", None => "missing" },
                    "target_instance_ids": targets.filter(|targets| targets.len() == 1).and_then(BTreeSet::first).cloned().into_iter().collect::<Vec<_>>(),
                }));
            }
        }
        instance
            .conditions
            .insert("dependency_references".to_owned(), Value::Array(references));
    }
    for (kind, message) in gaps {
        out.diagnose(kind, input.path, message);
    }
}

fn classic_instance(
    node: tree_sitter::Node<'_>,
    entry: &yarn_lock_parser::Entry<'_>,
    input: JsTsEvidenceInput<'_>,
    digest: &str,
) -> Result<JsTsLockedInstance, String> {
    let text = |node: tree_sitter::Node<'_>| node.utf8_text(input.bytes).expect("validated UTF-8");
    let mut cursor = node.walk();
    let descriptors: Vec<_> = node
        .children_by_field_name("name", &mut cursor)
        .map(|name| {
            let mut requirement = name
                .next_named_sibling()
                .expect("clean descriptor has a requirement");
            while requirement.kind() == "comment" {
                requirement = requirement
                    .next_named_sibling()
                    .expect("descriptor requirement after comment");
            }
            assert!(matches!(requirement.kind(), "semver" | "remote_url"));
            (text(name).to_owned(), text(requirement).to_owned())
        })
        .collect();
    let body = node
        .named_children(&mut node.walk())
        .find(|child| child.kind() == "dependency_body")
        .expect("clean dependency has a body");
    let mut fields = BTreeMap::new();
    let mut cursor = body.walk();
    for child in body
        .named_children(&mut cursor)
        .filter(|child| child.kind() != "comment")
    {
        if fields.insert(child.kind(), child).is_some() {
            return Err(format!(
                "duplicate Classic field {} at {}",
                child.kind(),
                child.start_byte()
            ));
        }
    }
    if descriptors
        .iter()
        .map(|(name, range)| (name.as_str(), range.as_str()))
        .collect::<Vec<_>>()
        != entry.descriptors
    {
        return Err("Classic parsers disagree on descriptor groups".to_owned());
    }
    let version = entry.version;
    let descriptor_sources: BTreeSet<_> = entry
        .descriptors
        .iter()
        .filter_map(|(_, requirement)| source_specifier(requirement))
        .collect();
    let source = (!entry.resolved.is_empty())
        .then(|| entry.resolved.to_owned())
        .or_else(|| {
            (descriptor_sources.len() == 1).then(|| {
                descriptor_sources
                    .first()
                    .expect("one descriptor source")
                    .clone()
            })
        });
    let integrity = (!entry.integrity.is_empty()).then(|| entry.integrity.to_owned());
    let mut conditions = BTreeMap::new();
    if entry.resolved.is_empty() && !descriptor_sources.is_empty() {
        conditions.insert(
            "source_candidates".to_owned(),
            serde_json::json!(descriptor_sources),
        );
        conditions.insert(
            "source_evidence".to_owned(),
            Value::String("descriptor".to_owned()),
        );
        if descriptor_sources.len() > 1 {
            conditions.insert("unresolved_source".to_owned(), Value::Bool(true));
        }
    }
    conditions.insert("descriptors".to_owned(), serde_json::json!(descriptors));
    conditions.insert(
        "locked_version".to_owned(),
        Value::String(version.to_owned()),
    );
    conditions.insert(
        "ownership".to_owned(),
        Value::String("unresolved_no_importer_table".to_owned()),
    );
    for (category, references) in [
        ("dependencies", &entry.dependencies),
        ("optionalDependencies", &entry.optional_dependencies),
    ] {
        let mut names = BTreeSet::new();
        for (name, _) in references {
            if !names.insert(name) {
                return Err(format!("duplicate Classic {category} reference {name}"));
            }
        }
        conditions.insert(category.to_owned(), serde_json::json!(references));
    }
    // Cross-check borrowed reference spans from the structured value decoder
    // against syntax nodes. The upstream grammar can misclassify an optional
    // section as dependency entries. Preserve decoder values, but diagnose
    // that grammar gap rather than repairing its tree inside Bifrost.
    let reference_spans: BTreeSet<_> = entry
        .dependencies
        .iter()
        .chain(&entry.optional_dependencies)
        .map(|(name, requirement)| {
            (
                name.as_ptr(),
                name.len(),
                requirement.as_ptr(),
                requirement.len(),
            )
        })
        .collect();
    let mut stack = vec![body];
    while let Some(child) = stack.pop() {
        let mut cursor = child.walk();
        if child.kind() == "dependency_entry" {
            let values: Vec<_> = child
                .named_children(&mut cursor)
                .filter(|node| node.kind() != "comment")
                .collect();
            assert_eq!(
                values.len(),
                2,
                "clean dependency entry has name and requirement"
            );
            let name_node = text(values[0]);
            let requirement_node = text(values[1]);
            let established = reference_spans.contains(&(
                name_node.as_ptr(),
                name_node.len(),
                requirement_node.as_ptr(),
                requirement_node.len(),
            ));
            if !established {
                conditions.insert(
                    "parser_validation".to_owned(),
                    Value::String("unresolved_dependency_structure".to_owned()),
                );
            }
        } else {
            stack.extend(child.named_children(&mut cursor));
        }
    }
    let packages: BTreeSet<_> = descriptors
        .iter()
        .map(|(alias, requirement)| alias_package(alias, requirement))
        .collect();
    if packages.len() != 1 {
        return Err(format!(
            "Classic descriptor group has incompatible package identities {packages:?}"
        ));
    }
    let package = packages
        .first()
        .expect("clean descriptor group is nonempty")
        .to_string();
    // The ordered descriptor group is the Classic locator. Distinct groups,
    // aliases and versions must never collapse to one package short name.
    let locator = serde_json::to_string(&descriptors).expect("string pairs serialize");
    let exact_version = exact_npm_version(version);
    let id = instance_id(
        input.path,
        &locator,
        &package,
        exact_version.as_deref(),
        source.as_deref(),
        digest,
    );
    // Duplicate descriptor groups are conflicting entries even if coordinates
    // agree. Keep both source-backed candidates and diagnose their ambiguity.
    let mut hasher = CanonicalHasher::new(b"bifrost.yarn-classic.lock-entry.v1");
    hasher.field("instance", id.as_bytes());
    hasher.field("start", &(node.start_byte() as u64).to_le_bytes());
    let id = lower_hex_string(&hasher.finish());
    conditions.insert("lock_instance_id".to_owned(), Value::String(id.clone()));
    Ok(JsTsLockedInstance {
        id,
        format: "yarn-classic-1".to_owned(),
        locator,
        package,
        version: exact_version,
        source,
        integrity,
        workspace_link: None,
        conditions,
        evidence: JsTsBuildEvidence {
            path: input.path.to_path_buf(),
            content_sha256: digest.to_owned(),
            range: ConfigurationSourceRange::new(node.start_byte(), node.end_byte())
                .expect("parser range is ordered"),
        },
    })
}

fn prepare_yarn_berry_lock(
    document: &Document,
    out: &mut JsTsEvidencePreparation,
    cancellation: Option<&CancellationToken>,
) {
    let metadata_version = document
        .value
        .get("__metadata")
        .and_then(|meta| meta.get("version"))
        .and_then(scalar_text);
    if !matches!(metadata_version.as_deref(), Some("4" | "6" | "8")) {
        out.diagnose(
            JsTsEvidenceDiagnosticKind::Unsupported,
            &document.path,
            "supported Yarn locks are Classic v1 and Berry YAML metadata versions 4, 6 and 8",
        );
        return;
    }
    let Some(entries) = document.value.as_object() else {
        out.diagnose(
            JsTsEvidenceDiagnosticKind::Malformed,
            &document.path,
            "Yarn Berry lock must be a mapping",
        );
        return;
    };
    let mut descriptor_resolutions: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
    // The immutable document owns metadata. Only bounded preparation-local
    // references and candidate indexes are needed to reconcile each resolution.
    let mut resolutions: BTreeMap<&str, (&Value, Vec<usize>)> = BTreeMap::new();
    for (descriptor, entry) in entries {
        if descriptor == "__metadata" {
            continue;
        }
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            out.diagnose(
                JsTsEvidenceDiagnosticKind::Cancelled,
                &document.path,
                "Yarn preparation cancelled",
            );
            return;
        }
        if !validate_lock_maps(
            entry,
            &[],
            &format!("Yarn descriptor {descriptor:?}"),
            document,
            out,
        ) {
            continue;
        }
        let Some(resolution) = entry.get("resolution").and_then(Value::as_str) else {
            out.diagnose(
                JsTsEvidenceDiagnosticKind::Malformed,
                &document.path,
                format!("Yarn descriptor {descriptor:?} has no resolution"),
            );
            continue;
        };
        let Some((package, _)) = resolution
            .split_once('@')
            .filter(|(name, _)| !name.is_empty())
            .or_else(|| {
                resolution
                    .strip_prefix('@')
                    .and_then(|value| value.split_once('@'))
                    .map(|(name, version)| (&resolution[..name.len() + 1], version))
            })
        else {
            out.diagnose(
                JsTsEvidenceDiagnosticKind::Malformed,
                &document.path,
                format!("invalid Yarn resolution {resolution:?}"),
            );
            continue;
        };
        let version = entry
            .get("version")
            .and_then(Value::as_str)
            .and_then(exact_npm_version);
        let id = instance_id(
            &document.path,
            descriptor,
            package,
            version.as_deref(),
            Some(resolution),
            &document.digest,
        );
        for descriptor in descriptor.split(", ") {
            descriptor_resolutions
                .entry(descriptor.to_owned())
                .or_default()
                .insert(resolution);
        }
        let (metadata, candidates) = resolutions.entry(resolution).or_insert((entry, Vec::new()));
        if !candidates.is_empty() && *metadata == entry {
            continue; // Equivalent descriptor groups share one resolution.
        }
        let conflict = !candidates.is_empty();
        if conflict {
            out.diagnose(JsTsEvidenceDiagnosticKind::Conflict, &document.path,
                format!("Yarn resolution {resolution:?} has contradictory entry metadata; no consumer selection established"));
            // Earlier alternatives were marked on their insertion. Only the
            // original candidate needs changing at the first disagreement.
            if candidates.len() == 1 {
                out.instances[candidates[0]].conditions.insert(
                    "parser_validation".to_owned(),
                    Value::String("conflicting Yarn resolution metadata".to_owned()),
                );
            }
        }
        candidates.push(out.instances.len());
        let mut conditions = lock_conditions(entry);
        if conflict {
            conditions.insert(
                "parser_validation".to_owned(),
                Value::String("conflicting Yarn resolution metadata".to_owned()),
            );
        }
        out.instances.push(JsTsLockedInstance {
            id,
            format: format!(
                "yarn-berry-{}",
                metadata_version
                    .as_deref()
                    .expect("validated metadata version")
            ),
            locator: resolution.to_owned(),
            package: package.to_owned(),
            version,
            source: Some(resolution.to_owned()),
            integrity: entry.get("checksum").and_then(scalar_text),
            workspace_link: resolution
                .contains("@workspace:")
                .then(|| resolution.to_owned()),
            conditions,
            evidence: document.evidence(&[descriptor]),
        });
    }
    // Two distinct targets disprove uniqueness. All source-backed alternatives
    // remain in instances; do not multiply them into every descriptor lookup.
    let descriptors: BTreeMap<String, BTreeSet<String>> = descriptor_resolutions
        .into_iter()
        .map(|(descriptor, targets)| {
            let ids = targets
                .into_iter()
                .flat_map(|resolution| {
                    resolutions[resolution]
                        .1
                        .iter()
                        .take(2)
                        .map(|&index| out.instances[index].id.clone())
                })
                .collect();
            (descriptor, ids)
        })
        .collect();
    let lock_root = document.path.parent().expect("relative file has a parent");
    let members: Vec<_> = out
        .manifests
        .iter()
        .filter_map(|manifest| {
            let root = manifest
                .entity
                .root
                .as_ref()?
                .strip_prefix(lock_root)
                .ok()?;
            let path = if root.as_os_str().is_empty() {
                ".".to_owned()
            } else {
                root.to_string_lossy().replace('\\', "/")
            };
            let name = manifest.package.as_deref()?;
            Some((manifest.entity.id(), format!("{name}@workspace:{path}")))
        })
        .collect();
    let unnamed: Vec<_> = out
        .manifests
        .iter()
        .filter(|manifest| {
            manifest.package.is_none()
                && manifest
                    .declarations
                    .iter()
                    .any(|declaration| declaration.category != JsTsDependencyCategory::Peer)
        })
        .map(|manifest| manifest.evidence.path.clone())
        .collect();
    for path in unnamed {
        out.diagnose(
            JsTsEvidenceDiagnosticKind::Unresolved,
            &document.path,
            format!(
                "Yarn manifest {} has no package name establishing its workspace importer",
                path.display()
            ),
        );
    }
    for (owner_id, importer) in members {
        if resolutions
            .get(importer.as_str())
            .is_some_and(|(_, candidates)| candidates.len() > 1)
        {
            out.diagnose(JsTsEvidenceDiagnosticKind::Conflict, &document.path,
                format!("Yarn workspace importer {importer:?} has contradictory metadata; consumer ownership remains unresolved"));
            continue;
        }
        let Some((entry, _)) = resolutions.get(importer.as_str()) else {
            out.diagnose(
                JsTsEvidenceDiagnosticKind::Unresolved,
                &document.path,
                format!("no Yarn workspace resolution {importer}"),
            );
            continue;
        };
        let entry = *entry;
        let importer_key = entries
            .iter()
            .find(|(_, candidate)| std::ptr::eq(*candidate, entry))
            .map(|(key, _)| key.as_str())
            .expect("entry is in table");
        // Berry stores dependency categories in the manifest, while its
        // importer declares the actual lock edge. Preserve manifest category
        // only when both alias and authored specifier agree.
        let declarations: Vec<_> = out
            .manifests
            .iter()
            .find(|manifest| manifest.entity.id() == owner_id)
            .expect("known member")
            .declarations
            .clone();
        for declaration in declarations {
            if declaration.category == JsTsDependencyCategory::Peer {
                continue;
            }
            let selected = entry
                .get("dependencies")
                .and_then(|deps| deps.get(&declaration.alias));
            let Some(specifier) = selected.and_then(Value::as_str) else {
                out.diagnose(if selected.is_some() { JsTsEvidenceDiagnosticKind::Malformed } else { JsTsEvidenceDiagnosticKind::Unresolved },
                    &document.path, format!("Yarn importer {importer:?}.{} has no supported string lock edge for its authored manifest requirement", declaration.alias));
                continue;
            };
            if specifier != declaration.specifier
                && specifier.strip_prefix("npm:") != Some(declaration.specifier.as_str())
            {
                out.diagnose(
                    JsTsEvidenceDiagnosticKind::Conflict,
                    &document.path,
                    format!(
                        "Yarn importer and manifest disagree for {}",
                        declaration.alias
                    ),
                );
                continue;
            }
            let descriptor = format!("{}@{}", declaration.alias, specifier);
            let selected = descriptors.get(&descriptor);
            if let Some(selected) = selected.filter(|ids| ids.len() == 1) {
                out.associations.push(JsTsLockedAssociation {
                    owner_id: owner_id.clone(),
                    instance_id: selected.first().expect("one selected instance").clone(),
                    alias: declaration.alias.clone(),
                    category: declaration.category,
                    requirement: declaration.specifier.clone(),
                    evidence: document.evidence(&[
                        importer_key,
                        "dependencies",
                        &declaration.alias,
                    ]),
                });
            } else {
                out.diagnose(
                    JsTsEvidenceDiagnosticKind::Unresolved,
                    &document.path,
                    format!("Yarn descriptor {descriptor:?} is missing or ambiguous"),
                );
            }
        }
    }
}

fn exact_npm_version(raw: &str) -> Option<String> {
    brokk_bifrost_js_ts::npm_version::normalize_exact_npm_version(raw).ok()
}

pub use brokk_bifrost_js_ts::npm_version::{NpmVersionError, NpmVersionRange};

/// Apply an npm predicate to one shared evidence row, without discovery or joins.
/// `None` retains uncertainty for incomplete, non-exact or other-ecosystem facts.
/// A parsed `false` is only a version non-match, never a complete absence claim.
/// Callers must select package/source/owner/locator on this same row and retain
/// acquisition gaps. This function never falls back to `version_requirement`.
pub fn npm_dependency_version_matches(
    row: &crate::analyzer::semantic_model::DependencyEvidence,
    range: &NpmVersionRange,
) -> Result<Option<bool>, NpmVersionError> {
    use crate::analyzer::semantic_model::DependencyEvidenceKind;
    if row.ecosystem != "npm"
        || !row.complete
        || !matches!(
            row.kind,
            DependencyEvidenceKind::Locked | DependencyEvidenceKind::Installed
        )
    {
        return Ok(None);
    }
    row.exact_version
        .as_deref()
        .map(|version| range.matches_exact(version))
        .transpose()
}

/// Project JS-specific parsing into the single #2442 file-fact contract.
/// Lock-table candidates remain unowned; proven importer edges get separate
/// owner-scoped rows with the same source/version/locator. No discovery occurs
/// during query evaluation and no artifact activation is fabricated.
pub fn discover_js_ts_dependency_file_evidence(
    inputs: &[JsTsEvidenceInput<'_>],
    limits: &crate::analyzer::semantic_model::DependencyFileEvidenceLimits,
    cancellation: Option<&CancellationToken>,
) -> crate::analyzer::semantic_model::DependencyFileEvidence {
    use crate::analyzer::semantic_model::{
        DependencyCondition, DependencyEvidence, DependencyEvidenceGap, DependencyEvidenceGapKind,
        DependencyEvidenceKind, DependencyFileEvidence,
    };
    let prepared = prepare_js_ts_dependency_evidence(
        inputs,
        &JsTsEvidenceLimits {
            max_files: limits.max_files,
            max_file_bytes: limits.max_file_bytes,
            max_total_bytes: limits.max_total_bytes,
            max_rows: limits.max_rows,
            max_diagnostics: limits.max_rows.max(1),
        },
        cancellation,
    );
    let mut result = DependencyFileEvidence::default();
    let build_row = |package: String,
                     kind,
                     requirement,
                     version,
                     source,
                     locator,
                     owner,
                     scope,
                     conditions,
                     evidence: &JsTsBuildEvidence,
                     complete| DependencyEvidence {
        ecosystem: "npm".to_owned(),
        package,
        kind,
        version_requirement: requirement,
        exact_version: version,
        source,
        locator,
        declared_by: owner,
        scope,
        conditions,
        build_file: evidence.path.clone(),
        source_digest: evidence.content_sha256.clone(),
        byte_range: evidence.range.start_byte()..evidence.range.end_byte(),
        complete,
    };
    for manifest in &prepared.manifests {
        for declaration in &manifest.declarations {
            result.rows.push(build_row(
                declaration.package.clone(),
                if declaration.category == JsTsDependencyCategory::Peer {
                    DependencyEvidenceKind::Constraint
                } else {
                    DependencyEvidenceKind::Declared
                },
                Some(declaration.specifier.clone()),
                None,
                source_specifier(&declaration.specifier),
                Some(format!(
                    "{}#{}:{}",
                    declaration.evidence.path.to_string_lossy(),
                    category_label(declaration.category),
                    declaration.alias
                )),
                Some(declaration.owner_id.clone()),
                declaration.scope,
                vec![
                    DependencyCondition {
                        kind: "alias".to_owned(),
                        value: declaration.alias.clone(),
                    },
                    DependencyCondition {
                        kind: "category".to_owned(),
                        value: category_label(declaration.category).to_owned(),
                    },
                    DependencyCondition {
                        kind: "peer_optional".to_owned(),
                        value: declaration.peer_optional.to_string(),
                    },
                ],
                &declaration.evidence,
                true,
            ));
        }
        for toolchain in &manifest.toolchain {
            let mut row = build_row(
                toolchain.tool.clone(),
                DependencyEvidenceKind::Constraint,
                Some(
                    toolchain
                        .requirement
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| toolchain.requirement.to_string()),
                ),
                None,
                None,
                Some(format!(
                    "{}#toolchain:{}",
                    toolchain.evidence.path.to_string_lossy(),
                    toolchain.tool
                )),
                Some(manifest.entity.id()),
                DependencyScope::Provided,
                vec![DependencyCondition {
                    kind: "declared_toolchain".to_owned(),
                    value: "does_not_establish_installed_runtime".to_owned(),
                }],
                &toolchain.evidence,
                true,
            );
            row.ecosystem = "npm-toolchain".to_owned();
            result.rows.push(row);
        }
        for directive in &manifest.directives {
            result.rows.push(build_row(
                manifest
                    .package
                    .clone()
                    .unwrap_or_else(|| "workspace".to_owned()),
                DependencyEvidenceKind::Constraint,
                None,
                None,
                None,
                Some(format!(
                    "{}#{}",
                    directive.evidence.path.to_string_lossy(),
                    directive.kind
                )),
                Some(manifest.entity.id()),
                DependencyScope::Unknown,
                vec![DependencyCondition {
                    kind: directive.kind.clone(),
                    value: directive.value.to_string(),
                }],
                &directive.evidence,
                false,
            ));
        }
    }
    let instance_rows: BTreeMap<_, _> = prepared
        .instances
        .iter()
        .map(|instance| {
            let mut conditions: Vec<_> = instance
                .conditions
                .iter()
                .map(|(kind, value)| DependencyCondition {
                    kind: kind.clone(),
                    value: value.to_string(),
                })
                .collect();
            conditions.push(DependencyCondition {
                kind: "lock_format".to_owned(),
                value: instance.format.clone(),
            });
            if let Some(integrity) = &instance.integrity {
                conditions.push(DependencyCondition {
                    kind: "integrity".to_owned(),
                    value: integrity.clone(),
                });
            }
            if let Some(link) = &instance.workspace_link {
                conditions.push(DependencyCondition {
                    kind: "workspace_link".to_owned(),
                    value: link.clone(),
                });
            }
            (
                instance.id.clone(),
                build_row(
                    instance.package.clone(),
                    DependencyEvidenceKind::Locked,
                    None,
                    instance.version.clone(),
                    instance.source.clone(),
                    Some(instance.locator.clone()),
                    None,
                    DependencyScope::Unknown,
                    conditions,
                    &instance.evidence,
                    !instance.conditions.contains_key("parser_validation")
                        && !instance.conditions.contains_key("unresolved_source"),
                ),
            )
        })
        .collect();
    result.rows.extend(instance_rows.values().cloned());
    for association in &prepared.associations {
        let Some(row) = instance_rows.get(&association.instance_id) else {
            unreachable!("association references a prepared instance");
        };
        let mut row = row.clone();
        row.declared_by = Some(association.owner_id.clone());
        row.scope = association.category.scope();
        row.version_requirement = Some(association.requirement.clone());
        row.conditions.push(DependencyCondition {
            kind: "alias".to_owned(),
            value: association.alias.clone(),
        });
        row.conditions.push(DependencyCondition {
            kind: "category".to_owned(),
            value: category_label(association.category).to_owned(),
        });
        row.conditions.push(DependencyCondition {
            kind: "importer_evidence".to_owned(),
            value: format!(
                "{}:{}:{}",
                association.evidence.path.to_string_lossy(),
                association.evidence.range.start_byte(),
                association.evidence.range.end_byte()
            ),
        });
        // The anchor remains the package/snapshot entry, and the importer
        // condition retains the exact second range that established ownership.
        result.rows.push(row);
    }
    for diagnostic in prepared.diagnostics {
        let kind = match diagnostic.kind {
            JsTsEvidenceDiagnosticKind::Malformed => DependencyEvidenceGapKind::Malformed,
            JsTsEvidenceDiagnosticKind::Unsupported => DependencyEvidenceGapKind::Unsupported,
            JsTsEvidenceDiagnosticKind::MissingMember => DependencyEvidenceGapKind::Missing,
            JsTsEvidenceDiagnosticKind::Conflict => DependencyEvidenceGapKind::Conflict,
            JsTsEvidenceDiagnosticKind::Unresolved => DependencyEvidenceGapKind::Unresolved,
            JsTsEvidenceDiagnosticKind::Limit => DependencyEvidenceGapKind::Limit,
            JsTsEvidenceDiagnosticKind::Cancelled => DependencyEvidenceGapKind::Cancelled,
        };
        result.gaps.push(DependencyEvidenceGap {
            kind,
            build_file: diagnostic.path,
            byte_range: 0..0,
            message: diagnostic.message,
        });
    }
    if prepared.omitted_diagnostics > 0 || result.rows.len() > limits.max_rows {
        result.rows.truncate(limits.max_rows);
        result.gaps.push(DependencyEvidenceGap {
            kind: DependencyEvidenceGapKind::Limit,
            build_file: PathBuf::from("package.json"),
            byte_range: 0..0,
            message: "shared evidence row/diagnostic limit exceeded".to_owned(),
        });
    }
    result.files_read = prepared.files_read;
    result.bytes_read = prepared.bytes_read;
    result.rows.sort_by_key(DependencyEvidence::id);
    result
}

fn category_label(category: JsTsDependencyCategory) -> &'static str {
    match category {
        JsTsDependencyCategory::Dependency => "dependencies",
        JsTsDependencyCategory::Development => "devDependencies",
        JsTsDependencyCategory::Optional => "optionalDependencies",
        JsTsDependencyCategory::Peer => "peerDependencies",
    }
}

fn source_specifier(specifier: &str) -> Option<String> {
    [
        "workspace:",
        "file:",
        "link:",
        "git+",
        "git:",
        "http:",
        "https:",
        "github:",
        "gitlab:",
        "bitbucket:",
    ]
    .iter()
    .any(|prefix| specifier.starts_with(prefix))
    .then(|| specifier.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_requirements_do_not_become_installation_or_runtime_observations() {
        let root = br#"{"name":"root","workspaces":["packages/*"],"engines":{"node":">=22"},"overrides":{"lib":"2"}}"#;
        let member = br#"{"name":"member","dependencies":{"alias":"npm:@scope/lib@^1"},"devDependencies":{"test-lib":"git+https://example.invalid/test"},"optionalDependencies":{"native":"file:../native"},"peerDependencies":{"host":"^2"},"peerDependenciesMeta":{"host":{"optional":true}}}"#;
        let inputs = [
            JsTsEvidenceInput {
                path: Path::new("package.json"),
                bytes: root,
            },
            JsTsEvidenceInput {
                path: Path::new("packages/member/package.json"),
                bytes: member,
            },
        ];
        let prepared =
            prepare_js_ts_dependency_evidence(&inputs, &JsTsEvidenceLimits::default(), None);
        assert!(prepared.instances.is_empty());
        assert!(prepared.associations.is_empty());
        assert!(!prepared.complete, "overrides are retained but unresolved");
        let member = prepared
            .manifests
            .iter()
            .find(|manifest| manifest.workspace_member)
            .unwrap();
        assert_eq!(member.declarations.len(), 4);
        let alias = member
            .declarations
            .iter()
            .find(|decl| decl.alias == "alias")
            .unwrap();
        assert_eq!(alias.package, "@scope/lib");
        assert_eq!(alias.specifier, "npm:@scope/lib@^1");
        let range = alias.evidence.range;
        assert_eq!(
            &inputs[1].bytes[range.start_byte()..range.end_byte()],
            br#""alias":"npm:@scope/lib@^1""#
        );
        assert!(
            member
                .declarations
                .iter()
                .find(|decl| decl.alias == "host")
                .unwrap()
                .peer_optional
        );
    }
}
