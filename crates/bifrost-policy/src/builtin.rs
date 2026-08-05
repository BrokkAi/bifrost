use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, OnceLock};

use serde::{Deserialize, Serialize};

use super::{
    CatalogRegistryLimits, PolicyId, PolicyRegistry, PolicyRegistryLimits, PolicySourceIdentity,
    TaintCatalogRegistry,
};

pub const CODE_SMELLS_PACK_ID: &str = "bifrost.code-smells";
const BUILT_IN_MANIFEST_SCHEMA_VERSION: u32 = 1;

const MANIFEST_SOURCE: &str = include_str!("../policy-packs/bifrost.code-smells/manifest.json");

const EMBEDDED_POLICY_SOURCES: &[(&str, &str)] = &[
    (
        "policies/dynamic-evaluation.rqlp",
        include_str!("../policy-packs/bifrost.code-smells/policies/dynamic-evaluation.rqlp"),
    ),
    (
        "policies/unsafe-deserialization.rqlp",
        include_str!("../policy-packs/bifrost.code-smells/policies/unsafe-deserialization.rqlp"),
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
];

static BUILT_IN_CATALOG: OnceLock<BuiltInPolicyCatalog> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuiltInPolicyPackManifest {
    pub schema_version: u32,
    pub id: String,
    pub version: String,
    pub name: String,
    pub description: String,
    pub policies: Vec<BuiltInPolicyManifestEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
}

impl SelectedBuiltInPolicy {
    pub fn manifest(self) -> &'static BuiltInPolicyManifestEntry {
        self.manifest
    }

    pub fn source(self) -> &'static str {
        self.source
    }

    pub fn source_identity(self) -> PolicySourceIdentity {
        PolicySourceIdentity::new(format!(
            "builtin:{}/{}",
            CODE_SMELLS_PACK_ID, self.manifest.path
        ))
    }
}

#[derive(Debug)]
pub struct BuiltInPolicyCatalog {
    manifest: BuiltInPolicyPackManifest,
    source_by_policy_id: HashMap<String, &'static str>,
}

impl BuiltInPolicyCatalog {
    fn load() -> Result<Self, BuiltInPolicyError> {
        let manifest = serde_json::from_str::<BuiltInPolicyPackManifest>(MANIFEST_SOURCE).map_err(
            |error| BuiltInPolicyError::new(format!("invalid built-in manifest: {error}")),
        )?;
        validate_manifest_shape(&manifest)?;

        let embedded_by_path = EMBEDDED_POLICY_SOURCES
            .iter()
            .copied()
            .collect::<HashMap<_, _>>();
        let manifest_paths = manifest
            .policies
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<HashSet<_>>();
        let embedded_paths = embedded_by_path.keys().copied().collect::<HashSet<_>>();
        if manifest_paths != embedded_paths {
            return Err(BuiltInPolicyError::new(
                "built-in manifest paths do not exactly match embedded policy sources",
            ));
        }

        let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
            CatalogRegistryLimits::default(),
        ));
        let mut registry =
            PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
        let mut observed = HashMap::new();
        for entry in &manifest.policies {
            let source = embedded_by_path[entry.path.as_str()];
            let identity =
                PolicySourceIdentity::new(format!("builtin:{}/{}", manifest.id, entry.path));
            let loaded = registry
                .register_policy_bytes(identity, source.as_bytes())
                .map_err(|error| {
                    BuiltInPolicyError::new(format!(
                        "failed to load built-in policy `{}`: {error}",
                        entry.path
                    ))
                })?;
            observed.insert(
                entry.path.as_str(),
                (
                    loaded.definition().metadata.id.as_str().to_owned(),
                    loaded.semantic_hash().to_string(),
                ),
            );
        }

        let mut source_by_policy_id = HashMap::with_capacity(manifest.policies.len());
        for entry in &manifest.policies {
            let (observed_id, observed_hash) = &observed[entry.path.as_str()];
            if observed_id != &entry.id {
                return Err(BuiltInPolicyError::new(format!(
                    "built-in policy `{}` declares id `{observed_id}` but the manifest records `{}`",
                    entry.path, entry.id
                )));
            }
            if observed_hash != &entry.semantic_hash {
                return Err(BuiltInPolicyError::new(format!(
                    "built-in policy `{}` has semantic hash `{observed_hash}` but the manifest records `{}`",
                    entry.id, entry.semantic_hash
                )));
            }
            source_by_policy_id.insert(entry.id.clone(), embedded_by_path[entry.path.as_str()]);
        }

        Ok(Self {
            manifest,
            source_by_policy_id,
        })
    }

    pub fn manifest(&self) -> &BuiltInPolicyPackManifest {
        &self.manifest
    }

    pub fn select(
        &'static self,
        selection: &BuiltInPolicySelection,
    ) -> Result<Vec<SelectedBuiltInPolicy>, BuiltInPolicyError> {
        let mut selected_ids = HashSet::new();
        for pack in &selection.packs {
            if pack != &self.manifest.id {
                return Err(BuiltInPolicyError::new(format!(
                    "unknown built-in policy pack `{pack}`"
                )));
            }
            selected_ids.extend(self.manifest.policies.iter().map(|entry| entry.id.as_str()));
        }

        for category in &selection.categories {
            let matching = self
                .manifest
                .policies
                .iter()
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
            .manifest
            .policies
            .iter()
            .filter(|entry| selected_ids.contains(entry.id.as_str()))
            .map(|entry| SelectedBuiltInPolicy {
                manifest: entry,
                source: self.source_by_policy_id[entry.id.as_str()],
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
    if manifest.id != CODE_SMELLS_PACK_ID {
        return Err(BuiltInPolicyError::new(format!(
            "built-in manifest id must be `{CODE_SMELLS_PACK_ID}`"
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

    #[test]
    #[ignore = "prints hashes while intentionally updating the checked-in manifest"]
    fn print_computed_semantic_hashes() {
        let manifest = serde_json::from_str::<BuiltInPolicyPackManifest>(MANIFEST_SOURCE)
            .expect("parse manifest");
        let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
            CatalogRegistryLimits::default(),
        ));
        let mut registry =
            PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
        for entry in manifest.policies {
            let source = EMBEDDED_POLICY_SOURCES
                .iter()
                .find(|(path, _)| *path == entry.path)
                .map(|(_, source)| *source)
                .expect("embedded source");
            let policy = registry
                .register_policy_bytes(
                    PolicySourceIdentity::new(format!(
                        "builtin:{}/{}",
                        CODE_SMELLS_PACK_ID, entry.path
                    )),
                    source.as_bytes(),
                )
                .expect("load policy");
            println!("{} {}", entry.id, policy.semantic_hash());
        }
    }

    #[test]
    fn checked_in_catalog_is_internally_consistent() {
        let catalog = built_in_policy_catalog().expect("valid built-in catalog");
        assert_eq!(catalog.manifest().policies.len(), 12);
        assert_eq!(
            catalog
                .select(&BuiltInPolicySelection {
                    packs: vec![CODE_SMELLS_PACK_ID.to_owned()],
                    ..BuiltInPolicySelection::default()
                })
                .expect("select pack")
                .len(),
            12
        );
    }
}
