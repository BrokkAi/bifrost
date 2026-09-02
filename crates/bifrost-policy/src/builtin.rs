use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, OnceLock};

use serde::{Deserialize, Serialize};

use super::{
    CatalogRegistryLimits, PolicyId, PolicyRegistry, PolicyRegistryLimits, PolicySourceIdentity,
    TaintCatalogRegistry,
};

pub const CODE_SMELLS_PACK_ID: &str = "bifrost.code-smells";
pub const SECURITY_PACK_ID: &str = "bifrost.security";
const BUILT_IN_MANIFEST_SCHEMA_VERSION: u32 = 1;

const CODE_SMELLS_MANIFEST_SOURCE: &str =
    include_str!("../policy-packs/bifrost.code-smells/manifest.json");
const SECURITY_MANIFEST_SOURCE: &str =
    include_str!("../policy-packs/bifrost.security/manifest.json");

const CODE_SMELLS_POLICY_SOURCES: &[(&str, &str)] = &[
    (
        "policies/dynamic-evaluation.rqlp",
        include_str!("../policy-packs/bifrost.code-smells/policies/dynamic-evaluation.rqlp"),
    ),
    (
        "policies/unsafe-deserialization.rqlp",
        include_str!("../policy-packs/bifrost.code-smells/policies/unsafe-deserialization.rqlp"),
    ),
    (
        "policies/go-nil-dereference.rqlp",
        include_str!("../policy-packs/bifrost.code-smells/policies/go-nil-dereference.rqlp"),
    ),
    (
        "policies/go-data-race.rqlp",
        include_str!("../policy-packs/bifrost.code-smells/policies/go-data-race.rqlp"),
    ),
    (
        "policies/go-wrong-error-on-failure-path.rqlp",
        include_str!(
            "../policy-packs/bifrost.code-smells/policies/go-wrong-error-on-failure-path.rqlp"
        ),
    ),
    (
        "policies/loop-invariant-sort.rqlp",
        include_str!("../policy-packs/bifrost.code-smells/policies/loop-invariant-sort.rqlp"),
    ),
    (
        "policies/regex-compile-in-loop.rqlp",
        include_str!("../policy-packs/bifrost.code-smells/policies/regex-compile-in-loop.rqlp"),
    ),
    (
        "policies/file-read-in-loop.rqlp",
        include_str!("../policy-packs/bifrost.code-smells/policies/file-read-in-loop.rqlp"),
    ),
    (
        "policies/serialization-in-loop.rqlp",
        include_str!("../policy-packs/bifrost.code-smells/policies/serialization-in-loop.rqlp"),
    ),
    (
        "policies/parsing-in-loop.rqlp",
        include_str!("../policy-packs/bifrost.code-smells/policies/parsing-in-loop.rqlp"),
    ),
    (
        "policies/database-call-in-loop.rqlp",
        include_str!("../policy-packs/bifrost.code-smells/policies/database-call-in-loop.rqlp"),
    ),
    (
        "policies/network-call-in-loop.rqlp",
        include_str!("../policy-packs/bifrost.code-smells/policies/network-call-in-loop.rqlp"),
    ),
    (
        "policies/subprocess-in-loop.rqlp",
        include_str!("../policy-packs/bifrost.code-smells/policies/subprocess-in-loop.rqlp"),
    ),
    (
        "policies/sleep-in-loop.rqlp",
        include_str!("../policy-packs/bifrost.code-smells/policies/sleep-in-loop.rqlp"),
    ),
    (
        "policies/expensive-operation-in-nested-loop.rqlp",
        include_str!(
            "../policy-packs/bifrost.code-smells/policies/expensive-operation-in-nested-loop.rqlp"
        ),
    ),
    (
        "policies/rayon-in-blocking-lazy-init.rqlp",
        include_str!(
            "../policy-packs/bifrost.code-smells/policies/rayon-in-blocking-lazy-init.rqlp"
        ),
    ),
];

const SECURITY_POLICY_SOURCES: &[(&str, &str)] = &[(
    "policies/jvm/servlet-parameter-to-jdbc.rqlp",
    include_str!("../policy-packs/bifrost.security/policies/jvm/servlet-parameter-to-jdbc.rqlp"),
)];

const EMBEDDED_POLICY_PACK_SOURCES: &[(&str, &str)] = &[
    ("bifrost.code-smells", CODE_SMELLS_MANIFEST_SOURCE),
    ("bifrost.security", SECURITY_MANIFEST_SOURCE),
];

const EMBEDDED_POLICY_SOURCES: &[(&str, &[(&str, &str)])] = &[
    ("bifrost.code-smells", CODE_SMELLS_POLICY_SOURCES),
    ("bifrost.security", SECURITY_POLICY_SOURCES),
];

static BUILT_IN_CATALOG: OnceLock<BuiltInPolicyCatalog> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BuiltInPolicyPackManifest {
    pub schema_version: u32,
    pub id: String,
    pub version: String,
    pub name: String,
    pub description: String,
    pub policies: Vec<BuiltInPolicyManifestEntry>,
}

/// The deterministic multi-pack catalog returned by CLI and MCP policy
/// listing. Entries are ordered by stable pack ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BuiltInPolicyCatalogManifest {
    pub schema_version: u32,
    pub packs: Vec<BuiltInPolicyPackManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BuiltInPolicyManifestEntry {
    pub path: String,
    pub id: String,
    pub semantic_hash: String,
    pub category: String,
    pub supported_languages: Vec<String>,
    pub required_capabilities: Vec<String>,
    pub severity_rationale: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BuiltInPolicySelection {
    pub packs: Vec<String>,
    pub categories: Vec<String>,
    pub policy_ids: Vec<String>,
}

impl BuiltInPolicySelection {
    pub fn is_empty(&self) -> bool {
        self.packs.is_empty() && self.categories.is_empty() && self.policy_ids.is_empty()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SelectedBuiltInPolicy {
    manifest: &'static BuiltInPolicyManifestEntry,
    source: &'static str,
    pack_id: &'static str,
}

impl SelectedBuiltInPolicy {
    pub fn manifest(self) -> &'static BuiltInPolicyManifestEntry {
        self.manifest
    }

    pub fn source(self) -> &'static str {
        self.source
    }

    pub fn pack_id(self) -> &'static str {
        self.pack_id
    }

    pub fn source_identity(self) -> PolicySourceIdentity {
        PolicySourceIdentity::new(format!("builtin:{}/{}", self.pack_id, self.manifest.path))
    }
}

#[derive(Debug)]
pub struct BuiltInPolicyCatalog {
    document: BuiltInPolicyCatalogManifest,
    source_by_policy_id: HashMap<String, &'static str>,
    digest: String,
}

impl BuiltInPolicyCatalog {
    fn load() -> Result<Self, BuiltInPolicyError> {
        let mut packs = Vec::with_capacity(EMBEDDED_POLICY_PACK_SOURCES.len());
        let expected_pack_ids = EMBEDDED_POLICY_PACK_SOURCES
            .iter()
            .map(|(pack_id, _)| *pack_id)
            .collect::<BTreeSet<_>>();
        let source_pack_ids = EMBEDDED_POLICY_SOURCES
            .iter()
            .map(|(pack_id, _)| *pack_id)
            .collect::<BTreeSet<_>>();
        if expected_pack_ids != source_pack_ids {
            return Err(BuiltInPolicyError::new(
                "built-in manifest and source tables must register the same pack ids",
            ));
        }
        for &(pack_id, manifest_source) in EMBEDDED_POLICY_PACK_SOURCES {
            let manifest = serde_json::from_str::<BuiltInPolicyPackManifest>(manifest_source)
                .map_err(|error| {
                    BuiltInPolicyError::new(format!(
                        "invalid built-in manifest `{pack_id}`: {error}"
                    ))
                })?;
            validate_manifest_shape(&manifest)?;
            if manifest.id != pack_id {
                return Err(BuiltInPolicyError::new(format!(
                    "built-in manifest file registers `{pack_id}` but declares id `{}`",
                    manifest.id
                )));
            }
            let sources = EMBEDDED_POLICY_SOURCES
                .iter()
                .find(|(embedded_id, _)| *embedded_id == pack_id)
                .map(|(_, sources)| *sources)
                .expect("pack source table and manifest table have the same IDs");
            let manifest_paths = manifest
                .policies
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<BTreeSet<_>>();
            let embedded_paths = sources
                .iter()
                .map(|(path, _)| *path)
                .collect::<BTreeSet<_>>();
            if manifest_paths != embedded_paths {
                return Err(BuiltInPolicyError::new(format!(
                    "built-in manifest `{pack_id}` paths do not exactly match embedded policy sources"
                )));
            }
            packs.push(manifest);
        }
        let document = BuiltInPolicyCatalogManifest {
            schema_version: BUILT_IN_MANIFEST_SCHEMA_VERSION,
            packs,
        };

        let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
            CatalogRegistryLimits::default(),
        ));
        let mut registry =
            PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
        let mut observed = HashMap::new();
        for (pack, entry) in document.packs.iter().flat_map(|pack| {
            EMBEDDED_POLICY_SOURCES
                .iter()
                .find(|(id, _)| id == &pack.id)
                .map(|(_, sources)| sources.iter().map(move |entry| (pack, entry)))
                .into_iter()
                .flatten()
        }) {
            let source = entry.1;
            let identity = PolicySourceIdentity::new(format!("builtin:{}/{}", pack.id, entry.0));
            let loaded = registry
                .register_policy_bytes(identity, source.as_bytes())
                .map_err(|error| {
                    BuiltInPolicyError::new(format!(
                        "failed to load built-in policy `{}`: {error}",
                        entry.0
                    ))
                })?;
            observed.insert(
                (pack.id.as_str(), entry.0),
                (
                    loaded.definition().metadata.id.as_str().to_owned(),
                    loaded.semantic_hash().to_string(),
                ),
            );
        }

        let total_policy_count = document.packs.iter().map(|pack| pack.policies.len()).sum();
        let mut source_by_policy_id = HashMap::with_capacity(total_policy_count);
        for manifest in &document.packs {
            let sources = EMBEDDED_POLICY_SOURCES
                .iter()
                .find(|(pack_id, _)| pack_id == &manifest.id)
                .map(|(_, sources)| *sources)
                .expect("catalog packs exactly match embedded sources");
            for entry in sources {
                let (observed_id, observed_hash) = &observed[&(manifest.id.as_str(), entry.0)];
                let recorded_id = manifest
                    .policies
                    .iter()
                    .find(|record| record.path == entry.0)
                    .map(|record| record.id.as_str())
                    .expect("manifest paths exactly match embedded sources");
                let recorded_hash = manifest
                    .policies
                    .iter()
                    .find(|record| record.path == entry.0)
                    .map(|record| record.semantic_hash.as_str())
                    .expect("manifest paths exactly match embedded sources");
                if observed_id != recorded_id {
                    return Err(BuiltInPolicyError::new(format!(
                        "built-in policy `{}` declares id `{observed_id}` but the manifest records `{recorded_id}`",
                        entry.0
                    )));
                }
                if observed_hash != recorded_hash {
                    return Err(BuiltInPolicyError::new(format!(
                        "built-in policy `{}` has semantic hash `{observed_hash}` but the manifest records `{recorded_hash}`",
                        entry.0
                    )));
                }
                if source_by_policy_id.contains_key(observed_id.as_str()) {
                    return Err(BuiltInPolicyError::new(format!(
                        "built-in policy id `{observed_id}` is declared by more than one pack"
                    )));
                }
                source_by_policy_id.insert(observed_id.to_string(), entry.1);
            }
        }

        let digest = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(
                serde_json::to_vec(&document)
                    .expect("catalog manifest serialization is infallible"),
            );
            hasher
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect()
        };

        Ok(Self {
            document,
            source_by_policy_id,
            digest,
        })
    }

    pub fn document(&self) -> &BuiltInPolicyCatalogManifest {
        &self.document
    }

    /// A stable identity for the shipped catalog: the SHA-256 of the
    /// serialized catalog manifest. Any change to the shipped pack set --
    /// a policy added, removed, re-hashed, or a pack version bump -- changes
    /// this value, so a run pinned to it witnesses exactly which built-in
    /// catalog was active even when a pack version was not bumped.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn manifest(&self) -> &BuiltInPolicyPackManifest {
        self.pack_manifest(CODE_SMELLS_PACK_ID)
            .expect("the compatibility code-smells manifest is embedded")
    }

    pub fn pack_manifest(&self, pack_id: &str) -> Option<&BuiltInPolicyPackManifest> {
        self.document.packs.iter().find(|pack| pack.id == pack_id)
    }

    pub fn select(
        &'static self,
        selection: &BuiltInPolicySelection,
    ) -> Result<Vec<SelectedBuiltInPolicy>, BuiltInPolicyError> {
        let mut selected_ids = HashSet::new();
        for pack in &selection.packs {
            if self.pack_manifest(pack).is_none() {
                return Err(BuiltInPolicyError::new(format!(
                    "unknown built-in policy pack `{pack}`"
                )));
            }
            let manifest = self.pack_manifest(pack).expect("validated pack");
            selected_ids.extend(manifest.policies.iter().map(|entry| entry.id.as_str()));
        }

        for category in &selection.categories {
            let matching = self
                .document
                .packs
                .iter()
                .flat_map(|pack| pack.policies.iter())
                .filter(|entry| &entry.category == category)
                .collect::<Vec<_>>();
            if matching.is_empty() {
                return Err(BuiltInPolicyError::new(format!(
                    "unknown built-in policy category `{category}`"
                )));
            }
            selected_ids.extend(matching.into_iter().map(|entry| entry.id.as_str()));
        }

        for policy_id in &selection.policy_ids {
            if !self.source_by_policy_id.contains_key(policy_id) {
                return Err(BuiltInPolicyError::new(format!(
                    "unknown built-in policy id `{policy_id}`"
                )));
            }
            selected_ids.insert(policy_id.as_str());
        }

        Ok(self
            .document
            .packs
            .iter()
            .flat_map(|pack| pack.policies.iter().map(move |entry| (pack, entry)))
            .filter(|(_, entry)| selected_ids.contains(entry.id.as_str()))
            .map(|(pack, entry)| SelectedBuiltInPolicy {
                manifest: entry,
                source: self.source_by_policy_id[entry.id.as_str()],
                pack_id: pack.id.as_str(),
            })
            .collect())
    }
}

fn validate_manifest_shape(manifest: &BuiltInPolicyPackManifest) -> Result<(), BuiltInPolicyError> {
    if manifest.schema_version != BUILT_IN_MANIFEST_SCHEMA_VERSION {
        return Err(BuiltInPolicyError::new(format!(
            "unsupported built-in manifest schema version {}",
            manifest.schema_version
        )));
    }
    if manifest.version.is_empty() || manifest.name.is_empty() || manifest.description.is_empty() {
        return Err(BuiltInPolicyError::new(
            "built-in manifest version, name, and description must be non-empty",
        ));
    }
    if manifest.policies.is_empty() {
        return Err(BuiltInPolicyError::new(
            "built-in manifest must contain at least one policy",
        ));
    }

    let mut paths = HashSet::new();
    let mut ids = HashSet::new();
    for entry in &manifest.policies {
        if !paths.insert(entry.path.as_str()) {
            return Err(BuiltInPolicyError::new(format!(
                "duplicate built-in policy path `{}`",
                entry.path
            )));
        }
        if !ids.insert(entry.id.as_str()) {
            return Err(BuiltInPolicyError::new(format!(
                "duplicate built-in policy id `{}`",
                entry.id
            )));
        }
        if entry.semantic_hash.len() != 64
            || !entry
                .semantic_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(BuiltInPolicyError::new(format!(
                "built-in policy `{}` must record a lowercase 64-digit semantic hash",
                entry.id
            )));
        }
        let id = PolicyId::new(&entry.id).map_err(|error| {
            BuiltInPolicyError::new(format!(
                "invalid built-in policy id `{}`: {error}",
                entry.id
            ))
        })?;
        if id.as_str() != entry.id {
            return Err(BuiltInPolicyError::new(format!(
                "built-in policy id `{}` is not canonical",
                entry.id
            )));
        }
        if entry.category.is_empty()
            || entry.supported_languages.is_empty()
            || entry.required_capabilities.is_empty()
            || entry.severity_rationale.is_empty()
            || entry.remediation.is_empty()
        {
            return Err(BuiltInPolicyError::new(format!(
                "built-in policy `{}` has incomplete inventory metadata",
                entry.id
            )));
        }
    }
    Ok(())
}

pub fn built_in_policy_catalog() -> Result<&'static BuiltInPolicyCatalog, BuiltInPolicyError> {
    if let Some(catalog) = BUILT_IN_CATALOG.get() {
        return Ok(catalog);
    }
    let catalog = BuiltInPolicyCatalog::load()?;
    Ok(BUILT_IN_CATALOG.get_or_init(|| catalog))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltInPolicyError {
    message: String,
}

impl BuiltInPolicyError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for BuiltInPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for BuiltInPolicyError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PolicyBudget;
    use crate::evaluator::{DefaultPolicyEvaluator, PolicyEvaluationContext, PolicyEvaluator};
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::{AnalyzerConfig, Language};

    #[test]
    #[ignore = "prints hashes while intentionally updating the checked-in manifest"]
    fn print_computed_semantic_hashes() {
        let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
            CatalogRegistryLimits::default(),
        ));
        let mut registry =
            PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
        for (pack_id, entry) in EMBEDDED_POLICY_SOURCES
            .iter()
            .flat_map(|(pack_id, sources)| sources.iter().map(move |entry| (*pack_id, *entry)))
        {
            let source = entry.1;
            let policy = registry
                .register_policy_bytes(
                    PolicySourceIdentity::new(format!("builtin:{}/{}", pack_id, entry.0)),
                    source.as_bytes(),
                )
                .expect("load policy");
            println!(
                "{} {}",
                policy.definition().metadata.id,
                policy.semantic_hash()
            );
        }
    }

    #[test]
    fn checked_in_catalog_is_internally_consistent() {
        let catalog = built_in_policy_catalog().expect("valid built-in catalog");
        assert_eq!(catalog.document().packs.len(), 2);
        assert_eq!(
            catalog
                .pack_manifest(CODE_SMELLS_PACK_ID)
                .expect("code-smells pack")
                .policies
                .len(),
            16
        );
        assert_eq!(
            catalog
                .pack_manifest(SECURITY_PACK_ID)
                .expect("security pack")
                .policies
                .len(),
            1
        );
        assert_eq!(
            catalog
                .select(&BuiltInPolicySelection {
                    packs: vec![CODE_SMELLS_PACK_ID.to_owned()],
                    ..BuiltInPolicySelection::default()
                })
                .expect("select pack")
                .len(),
            16
        );
        let security = catalog
            .select(&BuiltInPolicySelection {
                packs: vec![SECURITY_PACK_ID.to_owned()],
                ..BuiltInPolicySelection::default()
            })
            .expect("select security pack");
        assert_eq!(security.len(), 1);
        assert_eq!(security[0].pack_id(), SECURITY_PACK_ID);
        assert_eq!(
            security[0].source_identity().as_str(),
            "builtin:bifrost.security/policies/jvm/servlet-parameter-to-jdbc.rqlp"
        );
    }

    #[test]
    fn go_data_race_policy_reports_exact_capture_and_context_cancellation_races() {
        let mut project = InlineTestProject::with_language(Language::Go);
        for index in 0..101 {
            project = project.file(
                format!("open{index:03}.go"),
                format!(
                    "package main\n\nfunc unresolvedAliases{index}(values []int, index int) {{\n    go func() {{ values[index] = 1 }}()\n    _ = values[index]\n}}\n"
                ),
            );
        }
        let project = project
            .file(
                "zz_race.go",
                r#"package main

import "context"

func race() int {
    value := 0
    go func() { value = 1 }()
    return value
}

func ordered() int {
    value := 0
    value = 1
    go func() { _ = value }()
    return value
}

func cancellationVsDone(ctx context.Context, stop bool) (err error) {
    done := make(chan struct{})
    go func() {
        defer close(done)
        err = nil
        if stop { return }
        err = nil
    }()
    select {
    case <-ctx.Done():
        return context.Canceled
    case <-done:
    }
    return err
}

type localContext interface { Done() <-chan struct{} }

func lookalikeDone(ctx localContext) (err error) {
    done := make(chan struct{})
    go func() {
        defer close(done)
        err = nil
    }()
    select {
    case <-ctx.Done():
        return context.Canceled
    case <-done:
    }
    return err
}
"#,
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let selected = built_in_policy_catalog()
            .expect("valid built-in catalog")
            .select(&BuiltInPolicySelection {
                policy_ids: vec!["bifrost.correctness.go-data-race".to_string()],
                ..BuiltInPolicySelection::default()
            })
            .expect("select Go data-race policy");
        let [selected] = selected.as_slice() else {
            panic!("one Go data-race policy should be selected")
        };
        let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
            CatalogRegistryLimits::default(),
        ));
        let mut registry =
            PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
        let policy = registry
            .register_policy_bytes(selected.source_identity(), selected.source().as_bytes())
            .expect("load Go data-race policy");
        let flow_state = brokk_bifrost_flow::FlowWorkspaceState::new();
        let context = PolicyEvaluationContext {
            analyzer: workspace.analyzer(),
            workspace: Some(&workspace),
            flow_state: &flow_state,
            cancellation: None,
            cvss_overlays: &[],
            organizational_risk: &[],
            incremental: None,
        };
        let run = DefaultPolicyEvaluator::new()
            .evaluate(policy, &context, &mut PolicyBudget::default())
            .expect("evaluate Go data-race policy");
        assert_eq!(run.findings().len(), 2, "{run:#?}");
        let mut primary_lines = run
            .findings()
            .iter()
            .map(|finding| {
                finding
                    .primary()
                    .region()
                    .expect("race finding is source-backed")
                    .start_line()
            })
            .collect::<Vec<_>>();
        primary_lines.sort_unstable();
        assert_eq!(primary_lines, [7, 28], "{run:#?}");

        let cancellation = run
            .findings()
            .iter()
            .find(|finding| {
                finding
                    .primary()
                    .region()
                    .is_some_and(|region| region.start_line() == 28)
            })
            .expect("context cancellation produces one grouped finding");
        assert_eq!(cancellation.certainty(), &crate::FindingCertainty::Definite);
        assert_eq!(
            cancellation.completeness(),
            &crate::FindingCompleteness::Complete
        );
        let crate::PolicyFindingEvidence::Assertion { evidence } = cancellation.evidence() else {
            panic!("the grouped cancellation finding retains assertion evidence")
        };
        assert_eq!(
            evidence.actual_count(),
            2,
            "two child writes are grouped into one source finding"
        );
        let mut endpoint_lines = cancellation
            .related()
            .iter()
            .filter(|related| related.relationship() == crate::PolicyLocationRelationship::Evidence)
            .filter_map(|related| {
                related
                    .location()
                    .region()
                    .map(|region| region.start_line())
            })
            .collect::<Vec<_>>();
        endpoint_lines.sort_unstable();
        endpoint_lines.dedup();
        assert_eq!(endpoint_lines, [22, 24, 28], "{run:#?}");
        assert!(!cancellation.related_truncated());
        assert!(
            !endpoint_lines.contains(&31),
            "the post-done result read is ordered and must not be an endpoint: {run:#?}"
        );
    }
}
