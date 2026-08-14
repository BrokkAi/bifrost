use super::{
    ExtensionApiVersion, ExtensionWorkspaceDescription, NormalizedRelativePath, StableDigest,
    WorkspaceGeneration,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

pub const EXTENSION_RUN_MANIFEST_SCHEMA: &str = "1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Complete,
    Incomplete,
    Cancelled,
    ExceededBudget,
    Unsupported,
    Stale,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RunPurpose {
    Conformance {
        expectation_role: Box<str>,
        comparison_role: Box<str>,
    },
    DevelopmentExperiment {
        objective: Box<str>,
    },
    ConfirmatoryResult {
        protocol_role: Box<str>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineRunIdentity {
    pub package_version: Box<str>,
    pub commit: Box<str>,
    pub dirty_tree: Option<StableDigest>,
    pub profile: Box<str>,
    pub target: Box<str>,
    pub features: Box<[Box<str>]>,
    pub extension_api: ExtensionApiVersion,
    pub semantic_ir_versions: Box<[Box<str>]>,
    pub adapter_identities: Box<[Box<str>]>,
    pub capability_report_digest: StableDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceRunIdentity {
    pub repository: Box<str>,
    pub commit: Box<str>,
    pub dirty_tree: Option<StableDigest>,
    pub generation: WorkspaceGeneration,
    pub source_inventory_digest: StableDigest,
    pub roots: Box<[Box<str>]>,
    pub exclusions: Box<[Box<str>]>,
    pub dependency_fingerprints: Box<[StableDigest]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionRunIdentity {
    pub name: Box<str>,
    pub version: Box<str>,
    pub commit: Option<Box<str>>,
    pub package_digest: Option<StableDigest>,
    pub configuration_digest: StableDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivatedSemanticsIdentity {
    pub id: Box<str>,
    pub version: Box<str>,
    pub semantic_digest: StableDigest,
    pub manifest_digest: StableDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheStateKind {
    FullyCold,
    PersistentSourceReused,
    ProcessMemoryReused,
    ArtifactReused,
    Rebuilt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheStateDeclaration {
    pub kind: CacheStateKind,
    pub same_process: bool,
    pub persisted_source: bool,
    pub semantic_artifact_reused: bool,
    pub warmup_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentDependency {
    pub role: Box<str>,
    pub digest: StableDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunComponentDescriptor {
    pub role: Box<str>,
    pub path: NormalizedRelativePath,
    pub media_type: Box<str>,
    pub schema: Option<Box<str>>,
    pub byte_length: u64,
    pub content_sha256: StableDigest,
    pub canonical_digest: Option<StableDigest>,
    pub status: RunStatus,
    pub diagnostic_count: u32,
    pub dependencies: Box<[ComponentDependency]>,
}

pub struct RunComponentInput<'a> {
    pub role: Box<str>,
    pub path: NormalizedRelativePath,
    pub media_type: Box<str>,
    pub schema: Option<Box<str>>,
    pub bytes: &'a [u8],
    pub canonical_digest: Option<StableDigest>,
    pub status: RunStatus,
    pub dependencies: Vec<ComponentDependency>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunDeviation {
    pub id: Box<str>,
    pub affected_roles: Box<[Box<str>]>,
    pub justification: Box<str>,
    pub affects_completeness: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct VolatileRunMeasurements {
    pub generated_at: Option<Box<str>>,
    pub elapsed_millis: Option<u64>,
    pub peak_rss_bytes: Option<u64>,
    pub host: Option<Box<str>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionRunManifest {
    pub schema_version: Box<str>,
    pub purpose: RunPurpose,
    pub engine: EngineRunIdentity,
    pub workspace: WorkspaceRunIdentity,
    pub extension: ExtensionRunIdentity,
    pub activated_semantics: Box<[ActivatedSemanticsIdentity]>,
    pub cache: CacheStateDeclaration,
    pub components: Box<[RunComponentDescriptor]>,
    pub deviations: Box<[RunDeviation]>,
    pub status: RunStatus,
    pub manifest_digest: StableDigest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volatile: Option<VolatileRunMeasurements>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestError {
    pub path: Box<str>,
    pub message: Box<str>,
}
impl ManifestError {
    fn new(path: impl Into<Box<str>>, message: impl Into<Box<str>>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}
impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}
impl std::error::Error for ManifestError {}

impl ExtensionRunManifest {
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.schema_version.as_ref() != EXTENSION_RUN_MANIFEST_SCHEMA {
            return Err(ManifestError::new(
                "schema_version",
                "unsupported schema major",
            ));
        }
        validate_commit("engine.commit", &self.engine.commit)?;
        validate_commit("workspace.commit", &self.workspace.commit)?;
        require_sorted_unique("engine.features", &self.engine.features)?;
        require_sorted_unique(
            "engine.semantic_ir_versions",
            &self.engine.semantic_ir_versions,
        )?;
        require_sorted_unique("engine.adapter_identities", &self.engine.adapter_identities)?;
        if self.extension.commit.is_none() && self.extension.package_digest.is_none() {
            return Err(ManifestError::new(
                "extension",
                "commit or package digest is required",
            ));
        }
        if self.cache.kind == CacheStateKind::FullyCold
            && (self.cache.same_process
                || self.cache.persisted_source
                || self.cache.semantic_artifact_reused
                || self.cache.warmup_count != 0)
        {
            return Err(ManifestError::new(
                "cache",
                "fully_cold conflicts with reuse evidence",
            ));
        }
        let mut roles = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for c in &self.components {
            if c.role.is_empty() || !roles.insert(c.role.as_ref()) {
                return Err(ManifestError::new(
                    "components.role",
                    "roles must be nonempty and unique",
                ));
            }
            if c.path.as_str() == "manifest.json" || !paths.insert(c.path.as_str()) {
                return Err(ManifestError::new(
                    "components.path",
                    "paths must be unique and cannot name manifest.json",
                ));
            }
        }
        for c in &self.components {
            for d in &c.dependencies {
                if !roles.contains(d.role.as_ref()) {
                    return Err(ManifestError::new(
                        "components.dependencies",
                        "dangling dependency role",
                    ));
                }
            }
        }
        detect_cycles(&self.components)?;
        let required = match &self.purpose {
            RunPurpose::Conformance {
                expectation_role,
                comparison_role,
            } => vec![expectation_role.as_ref(), comparison_role.as_ref()],
            RunPurpose::ConfirmatoryResult { protocol_role } => vec![protocol_role.as_ref()],
            RunPurpose::DevelopmentExperiment { .. } => vec![],
        };
        for role in required {
            if !roles.contains(role) {
                return Err(ManifestError::new(
                    "purpose",
                    "required component role is absent",
                ));
            }
        }
        if self.status == RunStatus::Complete
            && (self
                .components
                .iter()
                .any(|c| c.status != RunStatus::Complete)
                || self.deviations.iter().any(|d| d.affects_completeness))
        {
            return Err(ManifestError::new(
                "status",
                "complete aggregate contains incomplete evidence",
            ));
        }
        if manifest_digest(self)? != self.manifest_digest {
            return Err(ManifestError::new("manifest_digest", "digest mismatch"));
        }
        Ok(())
    }
}

pub struct RunManifestBuilder {
    manifest: ExtensionRunManifest,
}
impl RunManifestBuilder {
    pub fn from_workspace(
        description: &ExtensionWorkspaceDescription,
        engine: EngineRunIdentity,
        workspace: WorkspaceRunIdentity,
        extension: ExtensionRunIdentity,
        purpose: RunPurpose,
        cache: CacheStateDeclaration,
    ) -> Result<Self, ManifestError> {
        if description.generation != workspace.generation || description.api != engine.extension_api
        {
            return Err(ManifestError::new(
                "workspace",
                "description identity differs from run identity",
            ));
        }
        Ok(Self {
            manifest: ExtensionRunManifest {
                schema_version: EXTENSION_RUN_MANIFEST_SCHEMA.into(),
                purpose,
                engine,
                workspace,
                extension,
                activated_semantics: Box::new([]),
                cache,
                components: Box::new([]),
                deviations: Box::new([]),
                status: RunStatus::Incomplete,
                manifest_digest: zero_digest(),
                volatile: None,
            },
        })
    }
    pub fn activated_semantics(mut self, mut values: Vec<ActivatedSemanticsIdentity>) -> Self {
        values.sort_by(|a, b| a.id.cmp(&b.id));
        self.manifest.activated_semantics = values.into_boxed_slice();
        self
    }
    pub fn add_component(mut self, input: RunComponentInput<'_>) -> Result<Self, ManifestError> {
        let mut values = self.manifest.components.into_vec();
        values.push(RunComponentDescriptor {
            role: input.role,
            path: input.path,
            media_type: input.media_type,
            schema: input.schema,
            byte_length: input.bytes.len() as u64,
            content_sha256: digest(input.bytes),
            canonical_digest: input.canonical_digest,
            status: input.status,
            diagnostic_count: 0,
            dependencies: input.dependencies.into_boxed_slice(),
        });
        values.sort_by(|a, b| (&a.role, a.path.as_str()).cmp(&(&b.role, b.path.as_str())));
        self.manifest.components = values.into_boxed_slice();
        Ok(self)
    }
    pub fn deviations(mut self, mut values: Vec<RunDeviation>) -> Self {
        values.sort_by(|a, b| a.id.cmp(&b.id));
        self.manifest.deviations = values.into_boxed_slice();
        self
    }
    pub fn volatile(mut self, value: VolatileRunMeasurements) -> Self {
        self.manifest.volatile = Some(value);
        self
    }
    pub fn build(mut self, status: RunStatus) -> Result<ExtensionRunManifest, ManifestError> {
        self.manifest.status = status;
        self.manifest.manifest_digest = manifest_digest(&self.manifest)?;
        self.manifest.validate()?;
        Ok(self.manifest)
    }
}

pub fn encode_run_manifest_json(value: &ExtensionRunManifest) -> Result<Vec<u8>, ManifestError> {
    value.validate()?;
    canonical_bytes(value)
}
pub fn decode_canonical_run_manifest_json(
    bytes: &[u8],
) -> Result<ExtensionRunManifest, ManifestError> {
    let value: ExtensionRunManifest = serde_json::from_slice(bytes)
        .map_err(|e| ManifestError::new("manifest", e.to_string().into_boxed_str()))?;
    value.validate()?;
    if canonical_bytes(&value)? != bytes {
        return Err(ManifestError::new("manifest", "input is not canonical"));
    }
    Ok(value)
}
pub fn decode_and_canonicalize_run_manifest_json(
    bytes: &[u8],
) -> Result<(ExtensionRunManifest, Vec<u8>), ManifestError> {
    let value: ExtensionRunManifest = serde_json::from_slice(bytes)
        .map_err(|e| ManifestError::new("manifest", e.to_string().into_boxed_str()))?;
    value.validate()?;
    let encoded = canonical_bytes(&value)?;
    Ok((value, encoded))
}

#[derive(Debug, Clone, Copy)]
pub struct BundleVerificationLimits {
    pub max_manifest_bytes: u64,
    pub max_artifacts: u32,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
}
impl Default for BundleVerificationLimits {
    fn default() -> Self {
        Self {
            max_manifest_bytes: 4 << 20,
            max_artifacts: 256,
            max_file_bytes: 128 << 20,
            max_total_bytes: 512 << 20,
        }
    }
}
#[derive(Debug)]
pub struct VerifiedExtensionBundle {
    root: PathBuf,
    manifest: ExtensionRunManifest,
}
impl VerifiedExtensionBundle {
    pub fn manifest(&self) -> &ExtensionRunManifest {
        &self.manifest
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
}
pub fn verify_extension_bundle(
    root: &Path,
    limits: BundleVerificationLimits,
) -> Result<VerifiedExtensionBundle, Vec<ManifestError>> {
    let mut errors = Vec::new();
    let root = match root.canonicalize() {
        Ok(v) => v,
        Err(e) => {
            return Err(vec![ManifestError::new(
                "bundle",
                e.to_string().into_boxed_str(),
            )]);
        }
    };
    let manifest_path = root.join("manifest.json");
    let meta = match fs::symlink_metadata(&manifest_path) {
        Ok(v) => v,
        Err(e) => {
            return Err(vec![ManifestError::new(
                "manifest.json",
                e.to_string().into_boxed_str(),
            )]);
        }
    };
    if meta.file_type().is_symlink() || meta.len() > limits.max_manifest_bytes {
        return Err(vec![ManifestError::new(
            "manifest.json",
            "symlink or size limit",
        )]);
    }
    let bytes = match fs::read(&manifest_path) {
        Ok(v) => v,
        Err(e) => {
            return Err(vec![ManifestError::new(
                "manifest.json",
                e.to_string().into_boxed_str(),
            )]);
        }
    };
    let manifest = match decode_canonical_run_manifest_json(&bytes) {
        Ok(v) => v,
        Err(e) => return Err(vec![e]),
    };
    if manifest.components.len() > limits.max_artifacts as usize {
        errors.push(ManifestError::new("components", "artifact count limit"));
    }
    let mut total = 0u64;
    for c in &manifest.components {
        let path = root.join(c.path.as_str());
        let meta = match fs::symlink_metadata(&path) {
            Ok(v) => v,
            Err(e) => {
                errors.push(ManifestError::new(
                    c.path.as_str(),
                    e.to_string().into_boxed_str(),
                ));
                continue;
            }
        };
        if meta.file_type().is_symlink() || meta.len() > limits.max_file_bytes {
            errors.push(ManifestError::new(
                c.path.as_str(),
                "symlink or file size limit",
            ));
            continue;
        }
        total = total.saturating_add(meta.len());
        let canonical = match path.canonicalize() {
            Ok(v) => v,
            Err(e) => {
                errors.push(ManifestError::new(
                    c.path.as_str(),
                    e.to_string().into_boxed_str(),
                ));
                continue;
            }
        };
        if !canonical.starts_with(&root) {
            errors.push(ManifestError::new(c.path.as_str(), "path escapes bundle"));
            continue;
        }
        let mut file = match File::open(&canonical) {
            Ok(v) => v,
            Err(e) => {
                errors.push(ManifestError::new(
                    c.path.as_str(),
                    e.to_string().into_boxed_str(),
                ));
                continue;
            }
        };
        let mut hasher = Sha256::new();
        let mut len = 0u64;
        let mut buf = [0u8; 65536];
        loop {
            match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    len += n as u64;
                    hasher.update(&buf[..n])
                }
                Err(e) => {
                    errors.push(ManifestError::new(
                        c.path.as_str(),
                        e.to_string().into_boxed_str(),
                    ));
                    break;
                }
            }
        }
        let actual = StableDigest::parse(format!("{:x}", hasher.finalize())).expect("sha256");
        if len != c.byte_length || actual != c.content_sha256 {
            errors.push(ManifestError::new(
                c.path.as_str(),
                "content length or digest mismatch",
            ));
        }
    }
    if total > limits.max_total_bytes {
        errors.push(ManifestError::new("components", "total byte limit"));
    }
    errors.sort_by(|a, b| a.path.cmp(&b.path).then(a.message.cmp(&b.message)));
    if errors.is_empty() {
        Ok(VerifiedExtensionBundle { root, manifest })
    } else {
        Err(errors)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReproductionMismatchKind {
    Engine,
    Workspace,
    Extension,
    Semantics,
    Environment,
    Cache,
    MissingArtifact,
    ContentDigest,
    UnsupportedOperation,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReproductionMismatch {
    pub kind: ReproductionMismatchKind,
    pub path: Box<str>,
    pub expected: Box<str>,
    pub observed: Option<Box<str>>,
    pub remediation: Box<str>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReproductionMismatchReport {
    pub mismatches: Box<[ReproductionMismatch]>,
}
pub trait ReproductionResolver {
    fn compare(&self, manifest: &ExtensionRunManifest) -> Vec<ReproductionMismatch>;
}
pub struct ReproductionPlan<'a> {
    bundle: &'a VerifiedExtensionBundle,
}
pub fn plan_reproduction<'a, R: ReproductionResolver>(
    bundle: &'a VerifiedExtensionBundle,
    resolver: &R,
) -> Result<ReproductionPlan<'a>, ReproductionMismatchReport> {
    let mut m = resolver.compare(&bundle.manifest);
    m.sort_by(|a, b| (&a.kind, &a.path).cmp(&(&b.kind, &b.path)));
    if m.is_empty() {
        Ok(ReproductionPlan { bundle })
    } else {
        Err(ReproductionMismatchReport {
            mismatches: m.into_boxed_slice(),
        })
    }
}
pub trait ReproductionExecutor {
    fn execute(&self, manifest: &ExtensionRunManifest, staging: &Path)
    -> Result<(), ManifestError>;
}
pub fn execute_reproduction(
    plan: ReproductionPlan<'_>,
    destination: &Path,
    executor: &impl ReproductionExecutor,
) -> Result<VerifiedExtensionBundle, ManifestError> {
    if destination.exists() {
        return Err(ManifestError::new(
            "destination",
            "destination already exists",
        ));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| ManifestError::new("destination", "missing parent"))?;
    let staging = parent.join(format!(".bifrost-reproduction-{}", std::process::id()));
    if staging.exists() {
        return Err(ManifestError::new(
            "destination",
            "staging path already exists",
        ));
    }
    fs::create_dir(&staging)
        .map_err(|e| ManifestError::new("destination", e.to_string().into_boxed_str()))?;
    let result = (|| {
        executor.execute(&plan.bundle.manifest, &staging)?;
        let verified = verify_extension_bundle(&staging, BundleVerificationLimits::default())
            .map_err(|e| {
                e.into_iter()
                    .next()
                    .unwrap_or_else(|| ManifestError::new("bundle", "verification failed"))
            })?;
        if verified.manifest.components != plan.bundle.manifest.components
            || verified.manifest.manifest_digest != plan.bundle.manifest.manifest_digest
        {
            return Err(ManifestError::new(
                "reproduction",
                "deterministic artifacts differ",
            ));
        }
        fs::rename(&staging, destination)
            .map_err(|e| ManifestError::new("destination", e.to_string().into_boxed_str()))?;
        verify_extension_bundle(destination, BundleVerificationLimits::default())
            .map_err(|e| e.into_iter().next().unwrap())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

fn validate_commit(path: &str, value: &str) -> Result<(), ManifestError> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && (!b.is_ascii_alphabetic() || b.is_ascii_lowercase()))
    {
        Err(ManifestError::new(
            path,
            "commit must be 40 lowercase hexadecimal characters",
        ))
    } else {
        Ok(())
    }
}
fn require_sorted_unique(path: &str, values: &[Box<str>]) -> Result<(), ManifestError> {
    if values.windows(2).any(|w| w[0] >= w[1]) {
        Err(ManifestError::new(path, "values must be sorted and unique"))
    } else {
        Ok(())
    }
}
fn detect_cycles(values: &[RunComponentDescriptor]) -> Result<(), ManifestError> {
    let graph: BTreeMap<&str, Vec<&str>> = values
        .iter()
        .map(|c| {
            (
                c.role.as_ref(),
                c.dependencies.iter().map(|d| d.role.as_ref()).collect(),
            )
        })
        .collect();
    for start in graph.keys() {
        let mut stack = vec![(*start, false)];
        let mut active = BTreeSet::new();
        while let Some((node, exit)) = stack.pop() {
            if exit {
                active.remove(node);
                continue;
            }
            if !active.insert(node) {
                return Err(ManifestError::new(
                    "components.dependencies",
                    "dependency cycle",
                ));
            }
            stack.push((node, true));
            if let Some(next) = graph.get(node) {
                for child in next {
                    stack.push((child, false));
                }
            }
        }
    }
    Ok(())
}
fn zero_digest() -> StableDigest {
    StableDigest::parse("0".repeat(64)).expect("valid digest")
}
fn digest(bytes: &[u8]) -> StableDigest {
    StableDigest::parse(format!("{:x}", Sha256::digest(bytes))).expect("sha256")
}
fn manifest_digest(value: &ExtensionRunManifest) -> Result<StableDigest, ManifestError> {
    let mut copy = value.clone();
    copy.manifest_digest = zero_digest();
    copy.volatile = None;
    Ok(digest(&canonical_bytes(&copy)?))
}
fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, ManifestError> {
    let mut value = serde_json::to_value(value)
        .map_err(|e| ManifestError::new("json", e.to_string().into_boxed_str()))?;
    sort_json(&mut value);
    let mut bytes = serde_json::to_vec(&value)
        .map_err(|e| ManifestError::new("json", e.to_string().into_boxed_str()))?;
    bytes.push(b'\n');
    Ok(bytes)
}
fn sort_json(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let old = std::mem::take(map);
            let mut entries: Vec<_> = old.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            for (k, mut v) in entries {
                sort_json(&mut v);
                map.insert(k, v);
            }
        }
        Value::Array(values) => values.iter_mut().for_each(sort_json),
        _ => {}
    }
}
