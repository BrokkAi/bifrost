//! Host-supplied policy catalogs and their post-activation resolution.
//!
//! Catalog entries are explicit sources rather than workspace files, so the
//! catalog boundary has no analyzer. Since issue #3316 a built-in policy may
//! name a semantic-model callable by its qualified name (`subprocess.run`).
//! That name is preserved unresolved here and resolved exactly once, after
//! workspace activation, against the pinned active semantic-model snapshot.
//!
//! The two identities are deliberately separate. `authored_hash` is the
//! deterministic catalog/package identity of the authored plan, computed with
//! qualified locators still unresolved, and it is what a catalog listing
//! reports before any workspace exists. `resolved_semantic_hash` is the
//! executable identity and exists only after every qualified locator resolved
//! against an active model, where the active pack identity and provenance are
//! part of the resolved plan's meaning. A source hash is never a substitute
//! for either, and the two are never interchangeable.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use brokk_bifrost_analysis::analyzer::IAnalyzer;
use brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelProvenance;
use brokk_bifrost_analysis::workspace_document::WorkspaceRoot;
use serde::{Deserialize, Serialize};

use super::locator::is_qualified_locator_code;
use super::{
    CatalogRegistryLimits, LoadedPolicy, PolicyId, PolicyRegistry, PolicyRegistryError,
    PolicyRegistryLimits, PolicySemanticHash, PolicySourceIdentity, ResolvedPolicyLocator,
    TaintCatalogRegistry,
};

pub const CODE_SMELLS_PACK_ID: &str = "bifrost.code-smells";
pub const CORRECTNESS_PACK_ID: &str = "bifrost.correctness";
pub const SECURITY_PACK_ID: &str = "bifrost.security";
pub const EFFECTS_PACK_ID: &str = "bifrost.effects";
pub const BUILT_IN_MANIFEST_SCHEMA_VERSION: u32 = 2;
const OPEN_POLICY_PACK_ROOT_ENV: &str = "BIFROST_OPEN_POLICY_PACK_ROOT";

// Retained authoring fixtures support evaluator regressions. Production builds
// contain no product rules; hosts supply a verified external catalog.
#[cfg(test)]
const CODE_SMELLS_MANIFEST_SOURCE: &str =
    include_str!("../policy-packs/bifrost.code-smells/manifest.json");
#[cfg(test)]
const CORRECTNESS_MANIFEST_SOURCE: &str =
    include_str!("../policy-packs/bifrost.correctness/manifest.json");
#[cfg(test)]
const SECURITY_MANIFEST_SOURCE: &str =
    include_str!("../policy-packs/bifrost.security/manifest.json");
#[cfg(test)]
const EFFECTS_MANIFEST_SOURCE: &str = include_str!("../policy-packs/bifrost.effects/manifest.json");

#[cfg(test)]
const CODE_SMELLS_POLICY_SOURCES: &[(&str, &str)] = &[
    (
        "policies/loop-body-never-repeats.rqlp",
        include_str!("../policy-packs/bifrost.code-smells/policies/loop-body-never-repeats.rqlp"),
    ),
    (
        "policies/unreachable-statement.rqlp",
        include_str!("../policy-packs/bifrost.code-smells/policies/unreachable-statement.rqlp"),
    ),
    (
        "policies/contradictory-condition.rqlp",
        include_str!("../policy-packs/bifrost.code-smells/policies/contradictory-condition.rqlp"),
    ),
    (
        "policies/discarded-pure-result.rqlp",
        include_str!("../policy-packs/bifrost.code-smells/policies/discarded-pure-result.rqlp"),
    ),
    (
        "policies/dynamic-evaluation.rqlp",
        include_str!("../policy-packs/bifrost.code-smells/policies/dynamic-evaluation.rqlp"),
    ),
    (
        "policies/identical-conditional-branches.rqlp",
        include_str!(
            "../policy-packs/bifrost.code-smells/policies/identical-conditional-branches.rqlp"
        ),
    ),
    (
        "policies/ignored-status-result.rqlp",
        include_str!("../policy-packs/bifrost.code-smells/policies/ignored-status-result.rqlp"),
    ),
    (
        "policies/repeated-branch-condition.rqlp",
        include_str!("../policy-packs/bifrost.code-smells/policies/repeated-branch-condition.rqlp"),
    ),
    (
        "policies/redundant-boolean-branches.rqlp",
        include_str!(
            "../policy-packs/bifrost.code-smells/policies/redundant-boolean-branches.rqlp"
        ),
    ),
    (
        "policies/unsafe-deserialization.rqlp",
        include_str!("../policy-packs/bifrost.code-smells/policies/unsafe-deserialization.rqlp"),
    ),
    (
        "policies/python-absent-member.rqlp",
        include_str!("../policy-packs/bifrost.code-smells/policies/python-absent-member.rqlp"),
    ),
    (
        "policies/python-absent-member-conditional.rqlp",
        include_str!(
            "../policy-packs/bifrost.code-smells/policies/python-absent-member-conditional.rqlp"
        ),
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
        "policies/empty-failure-handler.rqlp",
        include_str!("../policy-packs/bifrost.code-smells/policies/empty-failure-handler.rqlp"),
    ),
    (
        "policies/c-self-assignment.rqlp",
        include_str!("../policy-packs/bifrost.code-smells/policies/c-self-assignment.rqlp"),
    ),
    (
        "policies/local-self-assignment.rqlp",
        include_str!("../policy-packs/bifrost.code-smells/policies/local-self-assignment.rqlp"),
    ),
    (
        "policies/failed-swap.rqlp",
        include_str!("../policy-packs/bifrost.code-smells/policies/failed-swap.rqlp"),
    ),
    (
        "policies/overwritten-unread-value.rqlp",
        include_str!("../policy-packs/bifrost.code-smells/policies/overwritten-unread-value.rqlp"),
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

#[cfg(test)]
const CORRECTNESS_POLICY_SOURCES: &[(&str, &str)] = &[(
    "policies/resource-lifecycle.rqlp",
    include_str!("../policy-packs/bifrost.correctness/policies/resource-lifecycle.rqlp"),
)];

#[cfg(test)]
const SECURITY_POLICY_SOURCES: &[(&str, &str)] = &[
    (
        "policies/jvm/servlet-parameter-to-jdbc.rqlp",
        include_str!(
            "../policy-packs/bifrost.security/policies/jvm/servlet-parameter-to-jdbc.rqlp"
        ),
    ),
    (
        "policies/jvm/system-getenv-to-runtime-exec.rqlp",
        include_str!(
            "../policy-packs/bifrost.security/policies/jvm/system-getenv-to-runtime-exec.rqlp"
        ),
    ),
    (
        "policies/python/process-input-to-os-system.rqlp",
        include_str!(
            "../policy-packs/bifrost.security/policies/python/process-input-to-os-system.rqlp"
        ),
    ),
    (
        "policies/declared-storage/c-stored-request-to-sql.rqlp",
        include_str!(
            "../policy-packs/bifrost.security/policies/declared-storage/c-stored-request-to-sql.rqlp"
        ),
    ),
    (
        "policies/declared-storage/c-store-requires-validation.rqlp",
        include_str!(
            "../policy-packs/bifrost.security/policies/declared-storage/c-store-requires-validation.rqlp"
        ),
    ),
    (
        "policies/declared-storage/cpp-stored-request-to-sql.rqlp",
        include_str!(
            "../policy-packs/bifrost.security/policies/declared-storage/cpp-stored-request-to-sql.rqlp"
        ),
    ),
    (
        "policies/declared-storage/cpp-store-requires-validation.rqlp",
        include_str!(
            "../policy-packs/bifrost.security/policies/declared-storage/cpp-store-requires-validation.rqlp"
        ),
    ),
    (
        "policies/declared-storage/csharp-stored-request-to-sql.rqlp",
        include_str!(
            "../policy-packs/bifrost.security/policies/declared-storage/csharp-stored-request-to-sql.rqlp"
        ),
    ),
    (
        "policies/declared-storage/csharp-store-requires-validation.rqlp",
        include_str!(
            "../policy-packs/bifrost.security/policies/declared-storage/csharp-store-requires-validation.rqlp"
        ),
    ),
    (
        "policies/declared-storage/go-stored-request-to-sql.rqlp",
        include_str!(
            "../policy-packs/bifrost.security/policies/declared-storage/go-stored-request-to-sql.rqlp"
        ),
    ),
    (
        "policies/declared-storage/go-store-requires-validation.rqlp",
        include_str!(
            "../policy-packs/bifrost.security/policies/declared-storage/go-store-requires-validation.rqlp"
        ),
    ),
    (
        "policies/declared-storage/java-stored-request-to-sql.rqlp",
        include_str!(
            "../policy-packs/bifrost.security/policies/declared-storage/java-stored-request-to-sql.rqlp"
        ),
    ),
    (
        "policies/declared-storage/java-store-requires-validation.rqlp",
        include_str!(
            "../policy-packs/bifrost.security/policies/declared-storage/java-store-requires-validation.rqlp"
        ),
    ),
    (
        "policies/declared-storage/javascript-stored-request-to-sql.rqlp",
        include_str!(
            "../policy-packs/bifrost.security/policies/declared-storage/javascript-stored-request-to-sql.rqlp"
        ),
    ),
    (
        "policies/declared-storage/javascript-store-requires-validation.rqlp",
        include_str!(
            "../policy-packs/bifrost.security/policies/declared-storage/javascript-store-requires-validation.rqlp"
        ),
    ),
    (
        "policies/declared-storage/kotlin-stored-request-to-sql.rqlp",
        include_str!(
            "../policy-packs/bifrost.security/policies/declared-storage/kotlin-stored-request-to-sql.rqlp"
        ),
    ),
    (
        "policies/declared-storage/kotlin-store-requires-validation.rqlp",
        include_str!(
            "../policy-packs/bifrost.security/policies/declared-storage/kotlin-store-requires-validation.rqlp"
        ),
    ),
    (
        "policies/declared-storage/php-stored-request-to-sql.rqlp",
        include_str!(
            "../policy-packs/bifrost.security/policies/declared-storage/php-stored-request-to-sql.rqlp"
        ),
    ),
    (
        "policies/declared-storage/php-store-requires-validation.rqlp",
        include_str!(
            "../policy-packs/bifrost.security/policies/declared-storage/php-store-requires-validation.rqlp"
        ),
    ),
    (
        "policies/declared-storage/python-stored-request-to-sql.rqlp",
        include_str!(
            "../policy-packs/bifrost.security/policies/declared-storage/python-stored-request-to-sql.rqlp"
        ),
    ),
    (
        "policies/declared-storage/python-store-requires-validation.rqlp",
        include_str!(
            "../policy-packs/bifrost.security/policies/declared-storage/python-store-requires-validation.rqlp"
        ),
    ),
    (
        "policies/declared-storage/ruby-stored-request-to-sql.rqlp",
        include_str!(
            "../policy-packs/bifrost.security/policies/declared-storage/ruby-stored-request-to-sql.rqlp"
        ),
    ),
    (
        "policies/declared-storage/ruby-store-requires-validation.rqlp",
        include_str!(
            "../policy-packs/bifrost.security/policies/declared-storage/ruby-store-requires-validation.rqlp"
        ),
    ),
    (
        "policies/declared-storage/rust-stored-request-to-sql.rqlp",
        include_str!(
            "../policy-packs/bifrost.security/policies/declared-storage/rust-stored-request-to-sql.rqlp"
        ),
    ),
    (
        "policies/declared-storage/rust-store-requires-validation.rqlp",
        include_str!(
            "../policy-packs/bifrost.security/policies/declared-storage/rust-store-requires-validation.rqlp"
        ),
    ),
    (
        "policies/declared-storage/scala-stored-request-to-sql.rqlp",
        include_str!(
            "../policy-packs/bifrost.security/policies/declared-storage/scala-stored-request-to-sql.rqlp"
        ),
    ),
    (
        "policies/declared-storage/scala-store-requires-validation.rqlp",
        include_str!(
            "../policy-packs/bifrost.security/policies/declared-storage/scala-store-requires-validation.rqlp"
        ),
    ),
    (
        "policies/declared-storage/typescript-stored-request-to-sql.rqlp",
        include_str!(
            "../policy-packs/bifrost.security/policies/declared-storage/typescript-stored-request-to-sql.rqlp"
        ),
    ),
    (
        "policies/declared-storage/typescript-store-requires-validation.rqlp",
        include_str!(
            "../policy-packs/bifrost.security/policies/declared-storage/typescript-store-requires-validation.rqlp"
        ),
    ),
];

#[cfg(test)]
const EFFECTS_POLICY_SOURCES: &[(&str, &str)] = &[
    (
        "policies/csharp/selected-boundary-no-network-io.rqlp",
        include_str!(
            "../policy-packs/bifrost.effects/policies/csharp/selected-boundary-no-network-io.rqlp"
        ),
    ),
    (
        "policies/go/selected-boundary-no-network-io.rqlp",
        include_str!(
            "../policy-packs/bifrost.effects/policies/go/selected-boundary-no-network-io.rqlp"
        ),
    ),
    (
        "policies/java/selected-boundary-no-network-io.rqlp",
        include_str!(
            "../policy-packs/bifrost.effects/policies/java/selected-boundary-no-network-io.rqlp"
        ),
    ),
    (
        "policies/javascript/selected-boundary-no-network-io.rqlp",
        include_str!(
            "../policy-packs/bifrost.effects/policies/javascript/selected-boundary-no-network-io.rqlp"
        ),
    ),
    (
        "policies/kotlin/selected-boundary-no-network-io.rqlp",
        include_str!(
            "../policy-packs/bifrost.effects/policies/kotlin/selected-boundary-no-network-io.rqlp"
        ),
    ),
    (
        "policies/python/selected-boundary-no-network-io.rqlp",
        include_str!(
            "../policy-packs/bifrost.effects/policies/python/selected-boundary-no-network-io.rqlp"
        ),
    ),
    (
        "policies/ruby/selected-boundary-no-network-io.rqlp",
        include_str!(
            "../policy-packs/bifrost.effects/policies/ruby/selected-boundary-no-network-io.rqlp"
        ),
    ),
    (
        "policies/rust/selected-boundary-no-network-io.rqlp",
        include_str!(
            "../policy-packs/bifrost.effects/policies/rust/selected-boundary-no-network-io.rqlp"
        ),
    ),
    (
        "policies/scala/selected-boundary-no-network-io.rqlp",
        include_str!(
            "../policy-packs/bifrost.effects/policies/scala/selected-boundary-no-network-io.rqlp"
        ),
    ),
    (
        "policies/typescript/selected-boundary-no-network-io.rqlp",
        include_str!(
            "../policy-packs/bifrost.effects/policies/typescript/selected-boundary-no-network-io.rqlp"
        ),
    ),
];

#[cfg(test)]
const EMBEDDED_POLICY_PACK_SOURCES: &[(&str, &str)] = &[
    ("bifrost.code-smells", CODE_SMELLS_MANIFEST_SOURCE),
    ("bifrost.correctness", CORRECTNESS_MANIFEST_SOURCE),
    ("bifrost.security", SECURITY_MANIFEST_SOURCE),
    ("bifrost.effects", EFFECTS_MANIFEST_SOURCE),
];

#[cfg(test)]
const EMBEDDED_POLICY_SOURCES: &[(&str, &[(&str, &str)])] = &[
    ("bifrost.code-smells", CODE_SMELLS_POLICY_SOURCES),
    ("bifrost.correctness", CORRECTNESS_POLICY_SOURCES),
    ("bifrost.security", SECURITY_POLICY_SOURCES),
    ("bifrost.effects", EFFECTS_POLICY_SOURCES),
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

/// How a shipped policy joins a run. `Default` policies join every pack and
/// category selection; an `OptIn` policy runs only when a policy-id selector
/// names it, because its meaning depends on reviewed workspace configuration
/// a default run cannot assume.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyActivation {
    #[default]
    Default,
    OptIn,
}

/// One built-in policy entry under the schema-v2 identity contract.
///
/// `authored_hash` is always present: it is the deterministic identity of the
/// authored plan with qualified semantic-model locators preserved, so a
/// catalog listing is stable before any workspace exists. `resolved_semantic_hash`
/// is present only when the authored source resolves without a model, in which
/// case the two identities are recorded separately and both are verified. A
/// policy with a deferred qualified locator leaves the field absent; its
/// executable identity is minted after activation by
/// [`SelectedBuiltInPolicy::resolve`] and is never pinned to the authored hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BuiltInPolicyManifestEntry {
    pub path: String,
    pub id: String,
    pub authored_hash: String,
    pub resolved_semantic_hash: Option<String>,
    pub category: String,
    pub supported_languages: Vec<String>,
    pub required_capabilities: Vec<String>,
    pub severity_rationale: String,
    pub remediation: String,
    #[serde(default)]
    pub activation: PolicyActivation,
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

/// One built-in-style pack: a manifest document plus its embedded `.rqlp`
/// sources. The shipped catalog is built from these, and a host that embeds
/// its own reviewed pack uses the same construction so both obtain the same
/// authored identity and post-activation resolution contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedPolicyPack {
    manifest: String,
    sources: Vec<(String, String)>,
}

impl EmbeddedPolicyPack {
    pub fn new(manifest: impl Into<String>) -> Self {
        Self {
            manifest: manifest.into(),
            sources: Vec::new(),
        }
    }

    pub fn with_source(mut self, path: impl Into<String>, source: impl Into<String>) -> Self {
        self.sources.push((path.into(), source.into()));
        self
    }

    pub fn manifest(&self) -> &str {
        &self.manifest
    }

    pub fn sources(&self) -> &[(String, String)] {
        &self.sources
    }
}

/// One selected built-in policy before workspace activation.
#[derive(Debug, Clone, Copy)]
pub struct SelectedBuiltInPolicy<'a> {
    manifest: &'a BuiltInPolicyManifestEntry,
    source: &'a str,
    pack_id: &'a str,
}

impl<'a> SelectedBuiltInPolicy<'a> {
    pub fn manifest(self) -> &'a BuiltInPolicyManifestEntry {
        self.manifest
    }

    pub fn source(self) -> &'a str {
        self.source
    }

    pub fn pack_id(self) -> &'a str {
        self.pack_id
    }

    /// The deterministic pre-activation catalog identity of this entry.
    pub fn authored_hash(self) -> &'a str {
        &self.manifest.authored_hash
    }

    /// The checked-in executable identity, recorded only when the source
    /// resolves without an analyzer. A deferred entry returns `None` here and
    /// receives its identity from [`Self::resolve`] after activation.
    pub fn recorded_resolved_semantic_hash(self) -> Option<&'a str> {
        self.manifest.resolved_semantic_hash.as_deref()
    }

    pub fn source_identity(self) -> PolicySourceIdentity {
        PolicySourceIdentity::new(format!("builtin:{}/{}", self.pack_id, self.manifest.path))
    }

    /// Resolve every deferred qualified locator against the pinned analyzer
    /// snapshot and mint the executable identity.
    ///
    /// The resolved plan comes from the same registry boundary that loads a
    /// workspace policy with an analyzer, so a built-in policy and a directly
    /// registered policy with identical sources close to identical plans and
    /// identical semantic hashes. A failure keeps its typed locator diagnostic
    /// code. A resolution that no longer matches the checked-in executable
    /// identity is a changed model family and is refused rather than silently
    /// accepted, and a location that resolves only partially, ambiguously, or
    /// through a conflicting overlay keeps the loader's own typed rejection.
    pub fn resolve(
        self,
        analyzer: &dyn IAnalyzer,
    ) -> Result<ResolvedBuiltInPolicy<'a>, BuiltInPolicyError> {
        let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
            CatalogRegistryLimits::default(),
        ));
        let mut registry =
            PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
        let loaded = registry
            .register_policy_bytes_with_analyzer(
                self.source_identity(),
                self.source.as_bytes(),
                analyzer,
            )
            .map_err(|error| self.resolution_error(error))?;
        let resolved_semantic_hash = loaded.semantic_hash();
        if let Some(recorded) = self.recorded_resolved_semantic_hash()
            && recorded != resolved_semantic_hash.to_string()
        {
            return Err(BuiltInPolicyError::with_code(
                CHANGED_FAMILY_CODE,
                format!(
                    "built-in policy `{}` resolved to semantic hash `{resolved_semantic_hash}` \
                     but the manifest records `{recorded}`; the active model family changed",
                    self.manifest.id
                ),
            ));
        }
        Ok(ResolvedBuiltInPolicy {
            selected: self,
            loaded: loaded.clone(),
            resolved_semantic_hash,
        })
    }

    fn resolution_error(self, error: PolicyRegistryError) -> BuiltInPolicyError {
        match error {
            PolicyRegistryError::Source(source) => BuiltInPolicyError::with_code(
                source.diagnostic.code,
                format!(
                    "built-in policy `{}` could not resolve its qualified locators against the \
                     active semantic-model snapshot: {}",
                    self.manifest.id, source.diagnostic.message
                ),
            ),
            other => BuiltInPolicyError::with_code(
                LOCATOR_RESOLUTION_CODE,
                format!(
                    "built-in policy `{}` failed to load after workspace activation: {other}",
                    self.manifest.id
                ),
            ),
        }
    }
}

const LOCATOR_RESOLUTION_CODE: &str = "built-in-policy-locator-resolution-failed";
const CHANGED_FAMILY_CODE: &str = "built-in-policy-changed-model-family";

/// One built-in policy after every deferred locator resolved against the
/// pinned active semantic-model snapshot.
#[derive(Debug, Clone)]
pub struct ResolvedBuiltInPolicy<'a> {
    selected: SelectedBuiltInPolicy<'a>,
    loaded: LoadedPolicy,
    resolved_semantic_hash: PolicySemanticHash,
}

impl<'a> ResolvedBuiltInPolicy<'a> {
    pub fn selected(&self) -> SelectedBuiltInPolicy<'a> {
        self.selected
    }

    /// The deterministic catalog identity, unchanged by activation.
    pub fn authored_hash(&self) -> &str {
        self.selected.authored_hash()
    }

    /// The executable identity. It varies with the active model family and
    /// provenance that resolved the deferred locators.
    pub const fn resolved_semantic_hash(&self) -> PolicySemanticHash {
        self.resolved_semantic_hash
    }

    /// The fully resolved policy plan and its resolved locator metadata.
    pub fn loaded(&self) -> &LoadedPolicy {
        &self.loaded
    }

    /// The resolved call and receiver locators, including the active
    /// semantic-model pack identity and provenance that affected resolution.
    pub fn resolved_locators(&self) -> impl Iterator<Item = &ResolvedPolicyLocator> {
        self.loaded
            .resolved_selectors()
            .iter()
            .flat_map(|selector| selector.resolved_locators.iter())
    }

    pub fn locator_provenance(&self) -> impl Iterator<Item = &SemanticModelProvenance> {
        self.resolved_locators()
            .filter_map(|locator| locator.provenance.as_ref())
    }

    pub fn to_canonical_semantic_json(&self) -> serde_json::Value {
        self.loaded.to_canonical_semantic_json()
    }
}

#[derive(Debug)]
pub struct BuiltInPolicyCatalog {
    document: BuiltInPolicyCatalogManifest,
    source_by_policy_id: HashMap<String, String>,
    digest: String,
}

impl BuiltInPolicyCatalog {
    /// Load host-supplied rules. A production core without rules has an empty
    /// catalog; acquiring and verifying a release belongs to its host.
    fn load() -> Result<Self, BuiltInPolicyError> {
        if let Some(root) = std::env::var_os(OPEN_POLICY_PACK_ROOT_ENV) {
            if root.is_empty() {
                return Err(BuiltInPolicyError::new(format!(
                    "{OPEN_POLICY_PACK_ROOT_ENV} must name a policy pack root"
                )));
            }
            return load_external_policy_catalog(Path::new(&root));
        }

        // Test-support is explicitly enabled by repository regression suites,
        // never by the default engine/host release features.
        #[cfg(any(test, feature = "test-support"))]
        return Self::load_regression_fixture();
        #[cfg(not(any(test, feature = "test-support")))]
        Self::without_rules()
    }

    /// Construct the core engine's empty catalog, before a host supplies rules.
    pub fn without_rules() -> Result<Self, BuiltInPolicyError> {
        Self::from_embedded_packs(Vec::new())
    }

    /// Build a regression fixture catalog, never a default product catalog.
    #[cfg(any(test, feature = "test-support"))]
    fn load_regression_fixture() -> Result<Self, BuiltInPolicyError> {
        #[cfg(all(not(test), feature = "test-support"))]
        {
            // Repository integration suites explicitly enable test-support.
            // Fixtures are excluded from published crate archives, so a
            // downstream test-support build still defaults to an empty core.
            let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("policy-packs");
            if !root.is_dir() {
                return Self::without_rules();
            }
            let catalog = load_external_policy_catalog(&root)?;
            let packs = [
                CODE_SMELLS_PACK_ID,
                CORRECTNESS_PACK_ID,
                SECURITY_PACK_ID,
                EFFECTS_PACK_ID,
            ]
            .into_iter()
            .map(|id| {
                let manifest = catalog.pack_manifest(id).ok_or_else(|| {
                    BuiltInPolicyError::new(format!("regression fixture pack `{id}` is missing"))
                })?;
                let source = serde_json::to_string(manifest).map_err(|error| {
                    BuiltInPolicyError::new(format!("invalid regression fixture: {error}"))
                })?;
                Ok(manifest.policies.iter().fold(
                    EmbeddedPolicyPack::new(source),
                    |pack, policy| {
                        pack.with_source(
                            policy.path.clone(),
                            catalog.source_by_policy_id[&policy.id].clone(),
                        )
                    },
                ))
            })
            .collect::<Result<Vec<_>, BuiltInPolicyError>>()?;
            Self::from_embedded_packs(packs)
        }
        #[cfg(test)]
        {
            let packs = EMBEDDED_POLICY_PACK_SOURCES
                .iter()
                .map(|(pack_id, manifest_source)| {
                    let sources = EMBEDDED_POLICY_SOURCES
                        .iter()
                        .find(|(embedded_id, _)| embedded_id == pack_id)
                        .map(|(_, sources)| *sources)
                        .unwrap_or_else(|| {
                            panic!("pack `{pack_id}` has a manifest but no embedded source table")
                        });
                    sources.iter().fold(
                        EmbeddedPolicyPack::new(*manifest_source),
                        |pack, (path, source)| pack.with_source(*path, *source),
                    )
                })
                .collect();
            Self::from_embedded_packs(packs)
        }
    }

    /// Build a catalog from embedded packs at the built-in identity boundary.
    ///
    /// Every source is first closed with qualified locators preserved, which
    /// yields the deterministic `authored_hash`. A source that also closes
    /// without an analyzer records its executable identity as
    /// `resolved_semantic_hash`; a source with a deferred locator must leave
    /// that field absent, because its executable meaning depends on the
    /// workspace's pinned active model.
    pub fn from_embedded_packs(packs: Vec<EmbeddedPolicyPack>) -> Result<Self, BuiltInPolicyError> {
        let mut parsed = Vec::with_capacity(packs.len());
        let mut pack_ids = HashSet::new();
        for pack in packs {
            let manifest = serde_json::from_str::<BuiltInPolicyPackManifest>(pack.manifest())
                .map_err(|error| {
                    BuiltInPolicyError::new(format!("invalid built-in manifest: {error}"))
                })?;
            validate_manifest_shape(&manifest)?;
            if !pack_ids.insert(manifest.id.clone()) {
                return Err(BuiltInPolicyError::new(format!(
                    "built-in manifest id `{}` is declared more than once",
                    manifest.id
                )));
            }
            let manifest_paths = manifest
                .policies
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<BTreeSet<_>>();
            let embedded_paths = pack
                .sources()
                .iter()
                .map(|(path, _)| path.as_str())
                .collect::<BTreeSet<_>>();
            if manifest_paths != embedded_paths {
                return Err(BuiltInPolicyError::new(format!(
                    "built-in manifest `{}` paths do not exactly match embedded policy sources",
                    manifest.id
                )));
            }
            parsed.push((manifest, pack));
        }
        let document = BuiltInPolicyCatalogManifest {
            schema_version: BUILT_IN_MANIFEST_SCHEMA_VERSION,
            packs: parsed
                .iter()
                .map(|(manifest, _)| manifest.clone())
                .collect(),
        };

        let mut source_by_policy_id = HashMap::new();
        for (manifest, pack) in &parsed {
            for (path, source) in pack.sources() {
                let identity =
                    PolicySourceIdentity::new(format!("builtin:{}/{}", manifest.id, path));
                let entry = manifest
                    .policies
                    .iter()
                    .find(|entry| &entry.path == path)
                    .expect("manifest paths exactly match embedded sources");
                let authored_hash = authored_identity(&identity, source)?;
                if authored_hash != entry.authored_hash {
                    return Err(BuiltInPolicyError::new(format!(
                        "built-in policy `{path}` has authored hash `{authored_hash}` but the \
                         manifest records `{}`",
                        entry.authored_hash
                    )));
                }
                match resolved_identity(&identity, source) {
                    Ok(resolved_hash) => {
                        if let Some(recorded) = &entry.resolved_semantic_hash
                            && recorded != &resolved_hash
                        {
                            return Err(BuiltInPolicyError::new(format!(
                                "built-in policy `{path}` resolves to `{resolved_hash}` but the \
                                 manifest records `{recorded}`"
                            )));
                        }
                    }
                    Err(rejection) if is_deferred_rejection(&rejection) => {
                        if entry.resolved_semantic_hash.is_some() {
                            return Err(BuiltInPolicyError::new(format!(
                                "built-in policy `{path}` defers a qualified locator and cannot \
                                 record a resolved semantic hash before activation"
                            )));
                        }
                    }
                    Err(rejection) => {
                        return Err(BuiltInPolicyError::new(format!(
                            "failed to load built-in policy `{path}`: {rejection}"
                        )));
                    }
                }
                if source_by_policy_id
                    .insert(entry.id.clone(), source.clone())
                    .is_some()
                {
                    return Err(BuiltInPolicyError::new(format!(
                        "built-in policy id `{}` is declared by more than one pack",
                        entry.id
                    )));
                }
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

    /// Resolve a selection against the shipped catalog.
    ///
    /// Every non-empty dimension is a constraint, not an addition: a policy is
    /// selected when its pack, its category, and its id each satisfy the
    /// dimension the caller provided, and an empty dimension constrains
    /// nothing. So `packs = [p]` with `policy_ids = [i]` runs the single
    /// policy `i` inside `p`, never the whole pack (issue 2923). Output keeps
    /// catalog order, which reports and digests depend on.
    pub fn select<'a>(
        &'a self,
        selection: &BuiltInPolicySelection,
    ) -> Result<Vec<SelectedBuiltInPolicy<'a>>, BuiltInPolicyError> {
        // A caller that names no built-in selector asks for no built-in
        // policy; the whole catalog is requested by naming its packs.
        if selection.is_empty() {
            return Ok(Vec::new());
        }

        for pack in &selection.packs {
            if self.pack_manifest(pack).is_none() {
                return Err(BuiltInPolicyError::new(format!(
                    "unknown built-in policy pack `{pack}`"
                )));
            }
        }

        for category in &selection.categories {
            let known = self
                .document
                .packs
                .iter()
                .flat_map(|pack| pack.policies.iter())
                .any(|entry| &entry.category == category);
            if !known {
                return Err(BuiltInPolicyError::new(format!(
                    "unknown built-in policy category `{category}`"
                )));
            }
        }

        for policy_id in &selection.policy_ids {
            if !self.source_by_policy_id.contains_key(policy_id) {
                return Err(BuiltInPolicyError::new(format!(
                    "unknown built-in policy id `{policy_id}`"
                )));
            }
        }

        let selected = self
            .document
            .packs
            .iter()
            .flat_map(|pack| pack.policies.iter().map(move |entry| (pack, entry)))
            .filter(|(pack, entry)| {
                [
                    (&selection.packs, &pack.id),
                    (&selection.categories, &entry.category),
                    (&selection.policy_ids, &entry.id),
                ]
                .into_iter()
                .all(|(dimension, value)| dimension.is_empty() || dimension.contains(value))
            })
            // An opt-in policy runs only when a policy-id selector names it:
            // its meaning depends on reviewed workspace configuration, and a
            // pack- or category-wide selection must not activate it silently.
            .filter(|(_, entry)| {
                entry.activation != PolicyActivation::OptIn
                    || selection.policy_ids.contains(&entry.id)
            })
            .map(|(pack, entry)| SelectedBuiltInPolicy {
                manifest: entry,
                source: self.source_by_policy_id[entry.id.as_str()].as_str(),
                pack_id: pack.id.as_str(),
            })
            .collect::<Vec<_>>();
        if selected.is_empty() {
            return Err(BuiltInPolicyError::new(format!(
                "built-in policy selection matches no policy: every named selector exists, \
                 but no policy satisfies all of them together (packs {:?}, categories {:?}, \
                 policy ids {:?})",
                selection.packs, selection.categories, selection.policy_ids
            )));
        }
        Ok(selected)
    }
}

const MAX_EXTERNAL_POLICY_DIRECTORY_ENTRIES: usize = 4096;
const MAX_EXTERNAL_POLICY_SOURCE_BYTES: u64 = 16 * 1024 * 1024;

fn load_external_policy_catalog(root: &Path) -> Result<BuiltInPolicyCatalog, BuiltInPolicyError> {
    let metadata = fs::symlink_metadata(root).map_err(|error| {
        BuiltInPolicyError::new(format!(
            "cannot inspect configured policy pack root `{}`: {error}",
            root.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(BuiltInPolicyError::new(format!(
            "configured policy pack root `{}` must be a real rules directory",
            root.display()
        )));
    }
    let root = root.canonicalize().map_err(|error| {
        BuiltInPolicyError::new(format!(
            "cannot resolve configured policy pack root `{}`: {error}",
            root.display()
        ))
    })?;
    let workspace_root = WorkspaceRoot::open(&root).map_err(|error| {
        BuiltInPolicyError::new(format!(
            "cannot open configured policy pack root `{}`: {error}",
            root.display()
        ))
    })?;

    let mut directories = fs::read_dir(&root)
        .map_err(|error| {
            BuiltInPolicyError::new(format!(
                "cannot list configured policy pack root `{}`: {error}",
                root.display()
            ))
        })?
        .take(MAX_EXTERNAL_POLICY_DIRECTORY_ENTRIES + 1)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            BuiltInPolicyError::new(format!(
                "cannot read configured policy pack root `{}`: {error}",
                root.display()
            ))
        })?;
    if directories.len() > MAX_EXTERNAL_POLICY_DIRECTORY_ENTRIES {
        return Err(BuiltInPolicyError::new(format!(
            "configured policy pack root `{}` contains more than {MAX_EXTERNAL_POLICY_DIRECTORY_ENTRIES} entries",
            root.display()
        )));
    }
    directories.sort_by_key(|entry| entry.file_name());
    if directories.is_empty() {
        return Err(BuiltInPolicyError::new(format!(
            "configured policy pack root `{}` contains no policy packs",
            root.display()
        )));
    }

    let mut packs = Vec::with_capacity(directories.len());
    for directory in directories {
        let pack_id = directory.file_name().into_string().map_err(|_| {
            BuiltInPolicyError::new(format!(
                "configured policy pack directory `{}` has a non-UTF-8 name",
                directory.path().display()
            ))
        })?;
        let metadata = fs::symlink_metadata(directory.path()).map_err(|error| {
            BuiltInPolicyError::new(format!(
                "cannot inspect configured policy pack directory `{}`: {error}",
                directory.path().display()
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(BuiltInPolicyError::new(format!(
                "configured policy pack root contains a non-directory or symlink `{}`",
                directory.path().display()
            )));
        }

        let manifest_path = PathBuf::from(&pack_id).join("manifest.json");
        let manifest_source =
            read_external_policy_document(&workspace_root, &manifest_path, "json")?;
        let manifest = serde_json::from_str::<BuiltInPolicyPackManifest>(&manifest_source)
            .map_err(|error| {
                BuiltInPolicyError::new(format!(
                    "invalid configured policy manifest `{}`: {error}",
                    directory.path().join("manifest.json").display()
                ))
            })?;
        validate_manifest_shape(&manifest)?;
        if manifest.id != pack_id {
            return Err(BuiltInPolicyError::new(format!(
                "configured policy pack directory `{pack_id}` does not match manifest id `{}`",
                manifest.id
            )));
        }

        let mut pack = EmbeddedPolicyPack::new(manifest_source);
        for policy in &manifest.policies {
            validate_external_policy_path(&policy.path)?;
            let source_path = PathBuf::from(&pack_id).join(&policy.path);
            let policy_source =
                read_external_policy_document(&workspace_root, &source_path, "rqlp")?;
            pack = pack.with_source(policy.path.clone(), policy_source);
        }
        packs.push(pack);
    }

    BuiltInPolicyCatalog::from_embedded_packs(packs)
}

fn validate_external_policy_path(value: &str) -> Result<(), BuiltInPolicyError> {
    if !value.starts_with("policies/")
        || !value.ends_with(".rqlp")
        || value.contains('\\')
        || value.contains(':')
        || value.contains('\0')
    {
        return Err(BuiltInPolicyError::new(format!(
            "configured policy source path `{value}` must be a portable policies/*.rqlp path"
        )));
    }
    Ok(())
}

fn read_external_policy_document(
    root: &WorkspaceRoot,
    relative_path: &Path,
    extension: &str,
) -> Result<String, BuiltInPolicyError> {
    let parent = relative_path
        .parent()
        .expect("policy files have a parent directory");
    let filename = relative_path
        .file_name()
        .expect("policy files have a filename");
    let directory = root.open_directory(parent).map_err(|error| {
        BuiltInPolicyError::new(format!(
            "invalid or unsafe configured policy path `{}`: {error}",
            relative_path.display()
        ))
    })?;
    let entries = directory
        .entries_up_to(MAX_EXTERNAL_POLICY_DIRECTORY_ENTRIES)
        .map_err(|error| {
            BuiltInPolicyError::new(format!(
                "cannot inspect configured policy directory `{}`: {error}",
                parent.display()
            ))
        })?
        .ok_or_else(|| {
            BuiltInPolicyError::new(format!(
                "configured policy directory `{}` has more than {MAX_EXTERNAL_POLICY_DIRECTORY_ENTRIES} entries",
                parent.display()
            ))
        })?;
    let entry = entries
        .into_iter()
        .find(|entry| entry.relative_path().file_name() == Some(filename))
        .ok_or_else(|| {
            BuiltInPolicyError::new(format!(
                "configured policy source `{}` does not exist",
                relative_path.display()
            ))
        })?;
    let document = entry
        .read_document(&[extension], MAX_EXTERNAL_POLICY_SOURCE_BYTES)
        .map_err(|error| {
            BuiltInPolicyError::new(format!(
                "cannot read configured policy source `{}`: {error}",
                relative_path.display()
            ))
        })?;
    Ok(document.source().to_owned())
}

/// The deterministic authored identity: close the policy with every qualified
/// locator preserved, so the qualified name stays in the plan.
fn authored_identity(
    identity: &PolicySourceIdentity,
    source: &str,
) -> Result<String, BuiltInPolicyError> {
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    let loaded = registry
        .register_policy_bytes_deferred(identity.clone(), source.as_bytes())
        .map_err(|error| {
            BuiltInPolicyError::new(format!(
                "failed to load built-in policy `{identity}`: {error}"
            ))
        })?;
    Ok(loaded.semantic_hash().to_string())
}

/// The analyzer-free executable identity, available only when the source
/// carries no deferred locator. The error keeps the typed locator diagnostic.
fn resolved_identity(
    identity: &PolicySourceIdentity,
    source: &str,
) -> Result<String, PolicyRegistryError> {
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    registry
        .register_policy_bytes(identity.clone(), source.as_bytes())
        .map(|loaded| loaded.semantic_hash().to_string())
}

/// Whether an analyzer-free registration failed only because a qualified
/// locator needs an active model or a workspace-authored endpoint-set import
/// needs the workspace. Every other failure is an authoring defect.
fn is_deferred_rejection(error: &PolicyRegistryError) -> bool {
    match error {
        PolicyRegistryError::Source(source) => is_qualified_locator_code(source.diagnostic.code),
        PolicyRegistryError::EndpointSetImport { error, .. } => {
            error.diagnostic.code == "endpoint-set-import-requires-workspace"
        }
        _ => false,
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
        validate_sha256_field(&entry.id, "authored_hash", &entry.authored_hash)?;
        if let Some(resolved) = &entry.resolved_semantic_hash {
            validate_sha256_field(&entry.id, "resolved_semantic_hash", resolved)?;
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

fn validate_sha256_field(
    policy_id: &str,
    field: &str,
    value: &str,
) -> Result<(), BuiltInPolicyError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(BuiltInPolicyError::new(format!(
            "built-in policy `{policy_id}` must record a lowercase 64-digit {field}"
        )));
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
    code: &'static str,
    message: String,
}

impl BuiltInPolicyError {
    const CATALOG_CODE: &'static str = "built-in-policy-catalog-invalid";

    fn new(message: impl Into<String>) -> Self {
        Self {
            code: Self::CATALOG_CODE,
            message: message.into(),
        }
    }

    fn with_code(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// The typed diagnostic code. Locator failures keep the code raised by the
    /// loaded-policy boundary, such as `qualified-call-locator-inactive-model`
    /// or `qualified-call-locator-ambiguous`.
    pub const fn code(&self) -> &'static str {
        self.code
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
    use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
    use brokk_bifrost_analysis::analyzer::{AnalyzerConfig, Language};

    #[test]
    #[ignore = "prints hashes while intentionally updating the checked-in manifest"]
    fn print_computed_semantic_hashes() {
        for (pack_id, entry) in EMBEDDED_POLICY_SOURCES
            .iter()
            .flat_map(|(pack_id, sources)| sources.iter().map(move |entry| (*pack_id, *entry)))
        {
            let source = entry.1;
            let identity = PolicySourceIdentity::new(format!("builtin:{}/{}", pack_id, entry.0));
            let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
                CatalogRegistryLimits::default(),
            ));
            let mut registry =
                PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
            let authored = registry
                .register_policy_bytes_deferred(identity.clone(), source.as_bytes())
                .expect("authored identity");
            let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
                CatalogRegistryLimits::default(),
            ));
            let mut registry =
                PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
            let resolved = registry.register_policy_bytes(identity, source.as_bytes());
            let resolved = match resolved {
                Ok(policy) => policy.semantic_hash().to_string(),
                Err(error) => format!("deferred({error})"),
            };
            println!(
                "{} authored_hash={} resolved_semantic_hash={}",
                authored.definition().metadata.id,
                authored.semantic_hash(),
                resolved,
            );
        }
    }

    #[test]
    fn core_without_host_rules_has_no_policy_content() {
        let catalog = BuiltInPolicyCatalog::without_rules().expect("empty core catalog");
        assert!(catalog.document().packs.is_empty());
        assert!(catalog.source_by_policy_id.is_empty());
        assert!(
            catalog
                .select(&BuiltInPolicySelection::default())
                .unwrap()
                .is_empty()
        );
        assert!(
            catalog
                .select(&BuiltInPolicySelection {
                    packs: vec![CODE_SMELLS_PACK_ID.to_owned()],
                    ..BuiltInPolicySelection::default()
                })
                .is_err(),
            "an absent product pack must not be implicitly restored"
        );
    }

    #[test]
    fn checked_in_catalog_is_internally_consistent() {
        let catalog = built_in_policy_catalog().expect("valid built-in catalog");
        assert_eq!(catalog.document().packs.len(), 4);
        assert_eq!(
            catalog
                .pack_manifest(CODE_SMELLS_PACK_ID)
                .expect("code-smells pack")
                .policies
                .len(),
            31
        );
        assert_eq!(
            catalog
                .pack_manifest(CORRECTNESS_PACK_ID)
                .expect("correctness pack")
                .policies
                .len(),
            1
        );
        assert_eq!(
            catalog
                .pack_manifest(SECURITY_PACK_ID)
                .expect("security pack")
                .policies
                .len(),
            29
        );
        let effects = catalog
            .pack_manifest(EFFECTS_PACK_ID)
            .expect("effects pack");
        assert_eq!(effects.policies.len(), 10);
        assert_eq!(
            effects
                .policies
                .iter()
                .map(|entry| entry.id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "bifrost.effects.csharp.selected-boundary-no-network-io",
                "bifrost.effects.go.selected-boundary-no-network-io",
                "bifrost.effects.java.selected-boundary-no-network-io",
                "bifrost.effects.javascript.selected-boundary-no-network-io",
                "bifrost.effects.kotlin.selected-boundary-no-network-io",
                "bifrost.effects.python.selected-boundary-no-network-io",
                "bifrost.effects.ruby.selected-boundary-no-network-io",
                "bifrost.effects.rust.selected-boundary-no-network-io",
                "bifrost.effects.scala.selected-boundary-no-network-io",
                "bifrost.effects.typescript.selected-boundary-no-network-io",
            ]
        );
        for entry in &effects.policies {
            assert_eq!(
                entry.required_capabilities,
                vec![
                    "semantic-model-declared-effects",
                    "transitive-procedure-effects",
                    "exhaustive-effect-coverage",
                    "module-identity-declaration-selection",
                    "external-api-identity",
                ],
                "{}",
                entry.id
            );
        }
        assert_eq!(
            catalog
                .select(&BuiltInPolicySelection {
                    packs: vec![CORRECTNESS_PACK_ID.to_owned()],
                    ..BuiltInPolicySelection::default()
                })
                .expect("select correctness pack")
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
            31
        );
        let security = catalog
            .select(&BuiltInPolicySelection {
                packs: vec![SECURITY_PACK_ID.to_owned()],
                ..BuiltInPolicySelection::default()
            })
            .expect("select security pack");
        assert_eq!(security.len(), 3);
        assert_eq!(security[0].pack_id(), SECURITY_PACK_ID);
        assert_eq!(
            security[0].source_identity().as_str(),
            "builtin:bifrost.security/policies/jvm/servlet-parameter-to-jdbc.rqlp"
        );
    }

    /// A built-in-style policy whose only call target is a qualified
    /// semantic-model locator, so the analyzer-free boundary cannot close it.
    const DEFERRED_QUALIFIED_POLICY: &str = r#"(policy
      :schema-version 1
      :id "test.issue-3316.deferred"
      :name "Deferred qualified call locator"
      :message "M"
      :severity warning
      :analysis (analysis
        :type assertion
        (bind :name finding
          :query (rql :schema-version 1
            (resolved-call :resolves-to "subprocess.run" :proof exact
              (call-bindings (call-shape (call :callee (name "run")))))))
        (group :name by-call :by (finding.id)
          (aggregate :name violations :op count))
        (assert :group by-call :value violations :cardinality (exactly 0))))"#;

    /// A built-in-style policy with no qualified locator at all.
    const LOCATOR_FREE_POLICY: &str = r#"(policy
      :schema-version 1
      :id "test.issue-3316.locator-free"
      :name "Locator-free policy"
      :message "M"
      :severity warning
      :analysis (analysis :type match :selector (rql :schema-version 1 (name "run"))))"#;

    fn pack_manifest(
        authored_hash: &str,
        resolved_semantic_hash: Option<&str>,
        path: &str,
        policy_id: &str,
    ) -> String {
        let resolved = match resolved_semantic_hash {
            Some(hash) => format!("\"{hash}\""),
            None => "null".to_owned(),
        };
        format!(
            r#"{{
  "schema_version": 2,
  "id": "test.issue-3316",
  "version": "1.0.0",
  "name": "Issue 3316 fixture",
  "description": "Built-in-style deferred locator fixture.",
  "policies": [
    {{
      "path": "{path}",
      "id": "{policy_id}",
      "authored_hash": "{authored_hash}",
      "resolved_semantic_hash": {resolved},
      "category": "correctness",
      "supported_languages": ["python"],
      "required_capabilities": ["exact-call-target"],
      "severity_rationale": "fixture",
      "remediation": "fixture"
    }}
  ]
}}"#
        )
    }

    fn deferred_catalog(
        resolved_semantic_hash: Option<&str>,
    ) -> Result<BuiltInPolicyCatalog, BuiltInPolicyError> {
        let identity = PolicySourceIdentity::new("builtin:test.issue-3316/policies/deferred.rqlp");
        let authored = authored_identity(&identity, DEFERRED_QUALIFIED_POLICY)?;
        BuiltInPolicyCatalog::from_embedded_packs(vec![
            EmbeddedPolicyPack::new(pack_manifest(
                &authored,
                resolved_semantic_hash,
                "policies/deferred.rqlp",
                "test.issue-3316.deferred",
            ))
            .with_source("policies/deferred.rqlp", DEFERRED_QUALIFIED_POLICY),
        ])
    }

    #[test]
    fn a_deferred_qualified_locator_keeps_a_deterministic_authored_identity() {
        let identity = PolicySourceIdentity::new("builtin:test.issue-3316/policies/deferred.rqlp");
        let authored = authored_identity(&identity, DEFERRED_QUALIFIED_POLICY)
            .expect("the authored boundary preserves the qualified locator");
        let rejection = resolved_identity(&identity, DEFERRED_QUALIFIED_POLICY)
            .expect_err("the analyzer-free boundary cannot close the locator");
        let PolicyRegistryError::Source(source) = rejection else {
            panic!("expected a typed source diagnostic");
        };
        assert_eq!(source.diagnostic.code, "qualified-call-locator-incomplete");
        assert!(is_deferred_rejection(&PolicyRegistryError::Source(source)));

        let catalog = deferred_catalog(None).expect("the deferred entry loads");
        let selected = catalog
            .select(&BuiltInPolicySelection {
                policy_ids: vec!["test.issue-3316.deferred".to_owned()],
                ..BuiltInPolicySelection::default()
            })
            .expect("select the deferred policy");
        let [selected] = selected.as_slice() else {
            panic!("one deferred policy is selected");
        };
        assert_eq!(selected.authored_hash(), authored);
        assert_eq!(selected.recorded_resolved_semantic_hash(), None);
        assert!(
            selected
                .source()
                .contains(":resolves-to \"subprocess.run\"")
        );

        // Listing is deterministic before activation: two independent builds
        // agree on the document and the package digest.
        let rebuilt = deferred_catalog(None).expect("the deferred entry loads again");
        assert_eq!(catalog.document(), rebuilt.document());
        assert_eq!(catalog.digest(), rebuilt.digest());
    }

    #[test]
    fn a_locator_free_source_records_both_identities_separately() {
        let identity = PolicySourceIdentity::new("builtin:test.issue-3316/policies/plain.rqlp");
        let authored =
            authored_identity(&identity, LOCATOR_FREE_POLICY).expect("authored identity");
        let resolved =
            resolved_identity(&identity, LOCATOR_FREE_POLICY).expect("resolved identity");
        assert_eq!(authored, resolved);
        let catalog = BuiltInPolicyCatalog::from_embedded_packs(vec![
            EmbeddedPolicyPack::new(pack_manifest(
                &authored,
                Some(&resolved),
                "policies/plain.rqlp",
                "test.issue-3316.locator-free",
            ))
            .with_source("policies/plain.rqlp", LOCATOR_FREE_POLICY),
        ])
        .expect("both identities match");
        let selected = catalog
            .select(&BuiltInPolicySelection {
                policy_ids: vec!["test.issue-3316.locator-free".to_owned()],
                ..BuiltInPolicySelection::default()
            })
            .expect("select the locator-free policy");
        assert_eq!(
            selected[0].recorded_resolved_semantic_hash(),
            Some(resolved.as_str())
        );
    }

    #[test]
    fn a_deferred_entry_cannot_pin_a_resolved_semantic_hash() {
        let error = deferred_catalog(Some(&"a".repeat(64)))
            .expect_err("a deferred locator has no pre-activation resolved identity");
        assert!(
            error
                .to_string()
                .contains("cannot record a resolved semantic hash"),
            "{error}"
        );
    }

    #[test]
    fn a_wrong_authored_hash_is_refused() {
        let error = BuiltInPolicyCatalog::from_embedded_packs(vec![
            EmbeddedPolicyPack::new(pack_manifest(
                &"0".repeat(64),
                None,
                "policies/deferred.rqlp",
                "test.issue-3316.deferred",
            ))
            .with_source("policies/deferred.rqlp", DEFERRED_QUALIFIED_POLICY),
        ])
        .expect_err("a stale authored hash is a catalog defect");
        assert!(error.to_string().contains("authored hash"), "{error}");
    }

    fn selected_ids(selection: &BuiltInPolicySelection) -> Result<Vec<String>, String> {
        built_in_policy_catalog()
            .expect("valid built-in catalog")
            .select(selection)
            .map(|selected| {
                selected
                    .into_iter()
                    .map(|policy| policy.manifest().id.clone())
                    .collect()
            })
            .map_err(|error| error.to_string())
    }

    #[test]
    fn a_pack_and_an_id_select_only_that_id() {
        assert_eq!(
            selected_ids(&BuiltInPolicySelection {
                packs: vec![CODE_SMELLS_PACK_ID.to_owned()],
                policy_ids: vec!["bifrost.performance.loop-invariant-sort".to_owned()],
                ..BuiltInPolicySelection::default()
            }),
            Ok(vec!["bifrost.performance.loop-invariant-sort".to_owned()])
        );
    }

    #[test]
    fn a_category_narrows_within_the_named_pack() {
        let selected = selected_ids(&BuiltInPolicySelection {
            packs: vec![CODE_SMELLS_PACK_ID.to_owned()],
            categories: vec!["correctness".to_owned()],
            ..BuiltInPolicySelection::default()
        })
        .expect("code-smells correctness policies");
        assert_eq!(
            selected,
            vec![
                "bifrost.correctness.contradictory-condition",
                "bifrost.correctness.discarded-pure-result",
                "bifrost.correctness.dynamic-evaluation",
                "bifrost.correctness.identical-conditional-branches",
                "bifrost.correctness.ignored-status-result",
                "bifrost.correctness.repeated-branch-condition",
                "bifrost.correctness.redundant-boolean-branches",
                "bifrost.correctness.unsafe-deserialization",
                "bifrost.correctness.python-absent-member",
                "bifrost.correctness.python-absent-member-conditional",
                "bifrost.correctness.go-data-race",
                "bifrost.correctness.go-nil-dereference",
                "bifrost.correctness.go-wrong-error-on-failure-path",
                "bifrost.correctness.empty-failure-handler",
                "bifrost.correctness.c-self-assignment",
                "bifrost.correctness.local-self-assignment",
                "bifrost.correctness.failed-swap",
                "bifrost.correctness.overwritten-unread-value",
                "bifrost.correctness.loop-body-never-repeats",
                "bifrost.correctness.unreachable-statement",
                "bifrost.correctness.rayon-in-blocking-lazy-init",
            ]
        );
        // The security pack's only policy is in category `security`, so the
        // category dimension alone never reaches it from this request.
        assert!(
            !selected.contains(&"bifrost.security.java.servlet-parameter-to-jdbc".to_owned()),
            "{selected:?}"
        );
    }

    #[test]
    fn a_category_alone_spans_every_pack_that_declares_it() {
        assert_eq!(
            selected_ids(&BuiltInPolicySelection {
                categories: vec!["security".to_owned()],
                ..BuiltInPolicySelection::default()
            }),
            Ok(vec![
                "bifrost.security.java.servlet-parameter-to-jdbc".to_owned(),
                "bifrost.security.java.system-getenv-to-runtime-exec".to_owned(),
                "bifrost.security.python.process-input-to-os-system".to_owned(),
            ])
        );
    }

    #[test]
    fn an_id_alone_still_selects_that_policy() {
        assert_eq!(
            selected_ids(&BuiltInPolicySelection {
                policy_ids: vec!["bifrost.correctness.go-data-race".to_owned()],
                ..BuiltInPolicySelection::default()
            }),
            Ok(vec!["bifrost.correctness.go-data-race".to_owned()])
        );
    }

    #[test]
    fn several_ids_keep_catalog_order() {
        assert_eq!(
            selected_ids(&BuiltInPolicySelection {
                policy_ids: vec![
                    "bifrost.performance.sleep-in-loop".to_owned(),
                    "bifrost.correctness.dynamic-evaluation".to_owned(),
                ],
                ..BuiltInPolicySelection::default()
            }),
            Ok(vec![
                "bifrost.correctness.dynamic-evaluation".to_owned(),
                "bifrost.performance.sleep-in-loop".to_owned(),
            ])
        );
    }

    #[test]
    fn an_empty_selection_selects_no_built_in_policy() {
        assert_eq!(
            selected_ids(&BuiltInPolicySelection::default()),
            Ok(Vec::new())
        );
    }

    #[test]
    fn an_id_outside_the_named_pack_is_an_error() {
        let error = selected_ids(&BuiltInPolicySelection {
            packs: vec![SECURITY_PACK_ID.to_owned()],
            policy_ids: vec!["bifrost.performance.loop-invariant-sort".to_owned()],
            ..BuiltInPolicySelection::default()
        })
        .expect_err("an id outside the named pack matches nothing");
        assert!(error.contains("matches no policy"), "{error}");
        assert!(error.contains("bifrost.security"), "{error}");
        assert!(
            error.contains("bifrost.performance.loop-invariant-sort"),
            "{error}"
        );
    }

    #[test]
    fn a_category_outside_the_named_pack_is_an_error() {
        let error = selected_ids(&BuiltInPolicySelection {
            packs: vec![SECURITY_PACK_ID.to_owned()],
            categories: vec!["performance".to_owned()],
            ..BuiltInPolicySelection::default()
        })
        .expect_err("no security-pack policy is in category performance");
        assert!(error.contains("matches no policy"), "{error}");
        assert!(error.contains("performance"), "{error}");
    }

    #[test]
    fn unknown_selector_names_are_still_errors() {
        assert_eq!(
            selected_ids(&BuiltInPolicySelection {
                packs: vec!["bifrost.nonexistent".to_owned()],
                ..BuiltInPolicySelection::default()
            }),
            Err("unknown built-in policy pack `bifrost.nonexistent`".to_owned())
        );
        assert_eq!(
            selected_ids(&BuiltInPolicySelection {
                categories: vec!["nonexistent".to_owned()],
                ..BuiltInPolicySelection::default()
            }),
            Err("unknown built-in policy category `nonexistent`".to_owned())
        );
        assert_eq!(
            selected_ids(&BuiltInPolicySelection {
                policy_ids: vec!["bifrost.nonexistent.policy".to_owned()],
                ..BuiltInPolicySelection::default()
            }),
            Err("unknown built-in policy id `bifrost.nonexistent.policy`".to_owned())
        );
        // An unknown name is reported even when another dimension already
        // narrows the request to nothing.
        assert_eq!(
            selected_ids(&BuiltInPolicySelection {
                packs: vec![SECURITY_PACK_ID.to_owned()],
                policy_ids: vec!["bifrost.nonexistent.policy".to_owned()],
                ..BuiltInPolicySelection::default()
            }),
            Err("unknown built-in policy id `bifrost.nonexistent.policy`".to_owned())
        );
    }

    fn evaluate_go_data_race(project: &BuiltInlineTestProject) -> crate::PolicyRun {
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
        DefaultPolicyEvaluator::new()
            .evaluate(policy, &context, &mut PolicyBudget::default())
            .expect("evaluate Go data-race policy")
    }

    /// #3760: the root task's read is ordered before the writer's spawn, but
    /// the first goroutine's read of the same site races the write. The two
    /// task contexts share one conflict row, and the policy must report it.
    #[test]
    fn go_data_race_policy_reports_a_race_that_another_task_context_orders() {
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "fixture.go",
                r#"package fixture

type Pool struct{ stopped bool }

func (p *Pool) Stopped() bool { return p.stopped }

func Run() {
	p := &Pool{}
	_ = p.Stopped()
	go func() {
		_ = p.Stopped()
	}()
	go func() {
		p.stopped = true
	}()
}
"#,
            )
            .build();
        let run = evaluate_go_data_race(&project);
        let [finding] = run.findings() else {
            panic!("the stopped flag has one race finding: {run:#?}")
        };
        let primary_line = finding
            .primary()
            .region()
            .expect("race finding is source-backed")
            .start_line();
        assert_eq!(primary_line, 14, "{run:#?}");
        let mut endpoint_lines = vec![primary_line];
        endpoint_lines.extend(
            finding
                .related()
                .iter()
                .filter(|related| {
                    related.relationship() == crate::PolicyLocationRelationship::Evidence
                })
                .filter_map(|related| {
                    related
                        .location()
                        .region()
                        .map(|region| region.start_line())
                }),
        );
        endpoint_lines.sort_unstable();
        endpoint_lines.dedup();
        assert_eq!(endpoint_lines, [5, 14], "{run:#?}");
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
        let run = evaluate_go_data_race(&project);
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

#[cfg(test)]
mod external_policy_runtime_tests {
    use super::*;
    use std::process::Command;
    use tempfile::{TempDir, tempdir};

    const PACK_ID: &str = CORRECTNESS_PACK_ID;
    const CHILD_MARKER: &str = "BIFROST_TEST_EXTERNAL_POLICY_ROOT_CHILD";

    fn write_embedded_pack(root: &Path) -> PathBuf {
        let pack_root = root.join(PACK_ID);
        let manifest = EMBEDDED_POLICY_PACK_SOURCES
            .iter()
            .find(|(id, _)| *id == PACK_ID)
            .map(|(_, manifest)| *manifest)
            .expect("the correctness pack has an embedded manifest");
        let sources = EMBEDDED_POLICY_SOURCES
            .iter()
            .find(|(id, _)| *id == PACK_ID)
            .map(|(_, sources)| *sources)
            .expect("the correctness pack has embedded policy sources");

        fs::create_dir_all(pack_root.join("policies")).expect("create policy directory");
        fs::write(pack_root.join("manifest.json"), manifest).expect("write embedded manifest");
        for (relative_path, source) in sources {
            fs::write(pack_root.join(relative_path), source).expect("write embedded policy");
        }
        pack_root
    }

    fn external_fixture() -> (TempDir, PathBuf) {
        let root = tempdir().expect("temporary rules root");
        let pack_root = write_embedded_pack(root.path());
        (root, pack_root)
    }

    #[test]
    fn external_rules_root_loads_serialized_embedded_manifest_and_sources() {
        let (root, _) = external_fixture();
        let catalog = load_external_policy_catalog(root.path()).expect("external rules root");
        assert_eq!(catalog.document().packs.len(), 1);
        assert_eq!(catalog.document().packs[0].id, PACK_ID);
        assert_eq!(catalog.document().packs[0].policies.len(), 1);
    }

    #[test]
    fn external_rules_root_reports_a_missing_declared_source() {
        let (root, pack_root) = external_fixture();
        fs::remove_file(pack_root.join("policies/resource-lifecycle.rqlp"))
            .expect("remove declared source");
        let error = load_external_policy_catalog(root.path()).expect_err("missing source fails");
        assert!(error.to_string().contains("does not exist"), "{error}");
    }

    #[test]
    fn external_rules_root_rejects_a_corrupt_source() {
        let (root, pack_root) = external_fixture();
        fs::write(pack_root.join("policies/resource-lifecycle.rqlp"), [0xff])
            .expect("corrupt serialized source");
        let error = load_external_policy_catalog(root.path()).expect_err("corrupt source fails");
        assert!(
            error
                .to_string()
                .contains("cannot read configured policy source"),
            "{error}"
        );
    }

    #[test]
    fn external_rules_root_rejects_manifest_path_traversal() {
        let (root, pack_root) = external_fixture();
        let manifest_path = pack_root.join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
                .expect("parse embedded manifest");
        manifest["policies"][0]["path"] =
            serde_json::Value::String("policies/../../outside.rqlp".to_owned());
        fs::write(
            manifest_path,
            serde_json::to_vec(&manifest).expect("serialize altered manifest"),
        )
        .expect("write altered manifest");
        let error = load_external_policy_catalog(root.path()).expect_err("traversal fails");
        assert!(
            error
                .to_string()
                .contains("invalid or unsafe configured policy path"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn external_rules_root_rejects_a_symlinked_policy_source() {
        use std::os::unix::fs::symlink;

        let (root, pack_root) = external_fixture();
        let outside = tempdir().expect("temporary outside directory");
        let outside_source = outside.path().join("source.rqlp");
        fs::write(&outside_source, "not loaded through a symlink").expect("write outside source");
        let source = pack_root.join("policies/resource-lifecycle.rqlp");
        fs::remove_file(&source).expect("remove original source");
        symlink(&outside_source, &source).expect("create source symlink");

        let error = load_external_policy_catalog(root.path()).expect_err("source symlink fails");
        assert!(
            error
                .to_string()
                .contains("cannot read configured policy source"),
            "{error}"
        );
    }

    #[test]
    fn configured_empty_rules_root_fails_closed_in_a_subprocess() {
        if std::env::var_os(CHILD_MARKER).is_some() {
            let error = built_in_policy_catalog().expect_err("configured empty root must fail");
            assert!(
                error.to_string().contains("contains no policy packs"),
                "{error}"
            );
            return;
        }

        let root = tempdir().expect("empty external rules root");
        let output = Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "builtin::external_policy_runtime_tests::configured_empty_rules_root_fails_closed_in_a_subprocess",
                "--nocapture",
            ])
            .env(OPEN_POLICY_PACK_ROOT_ENV, root.path())
            .env(CHILD_MARKER, "1")
            .output()
            .expect("run isolated environment test");
        assert!(
            output.status.success(),
            "child failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn configured_root_rejects_a_directory_with_no_policy_packs() {
        let root = tempdir().expect("empty rules root");
        let error = load_external_policy_catalog(root.path()).expect_err("empty root fails");
        assert!(
            error.to_string().contains("contains no policy packs"),
            "{error}"
        );
    }
}
