#[doc(hidden)]
pub mod db;
#[doc(hidden)]
pub mod storage;

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;

use crate::analyzer::semantic_model::csmi::CsmiCallableValuesModality;

use crate::analyzer::semantic_model::csmi::CsmiCallableValuesPayload;

use crate::analyzer::semantic_model::csmi::CsmiCallableValuesShape;

use crate::analyzer::semantic_model::csmi::CsmiCallableValuesTiming;

use crate::analyzer::semantic_model::csmi::CsmiCoverageStatus;

use crate::analyzer::semantic_model::csmi::CsmiInputLocation;

use crate::analyzer::semantic_model::model::AnonymousCallableIdentity;

use crate::analyzer::semantic_model::model::CallableValuesCoverage;

use crate::analyzer::semantic_model::model::CallableValuesFact;

use crate::analyzer::semantic_model::model::CallableValuesFamily;

use crate::analyzer::semantic_model::model::CallableValuesPayload;

use crate::analyzer::semantic_model::model::SourceAnchor;

use crate::analyzer::semantic_model::model::SourceByteRange;

use crate::analyzer::semantic_model::model::SourceCallableShape;

use crate::analyzer::semantic_model::model::SourceDeclarationKind;

use crate::analyzer::semantic_model::model::SourceParameterShape;

use crate::analyzer::semantic_model::model::SourceTypeNode;

use crate::analyzer::semantic_model::validate::is_canonical_relative_path;

use crate::analyzer::semantic_model::ActivationSelector;

use crate::analyzer::semantic_model::ArtifactEncoding;

use crate::analyzer::semantic_model::ArtifactProducerLimits;

use crate::analyzer::semantic_model::CompiledPackManifest;

use crate::analyzer::semantic_model::CompiledSemanticModelPack;

use crate::analyzer::semantic_model::CompiledShardDescriptor;

use crate::analyzer::semantic_model::Completeness;

use crate::analyzer::semantic_model::DecodeLimits;

use crate::analyzer::semantic_model::ExactArtifact;

use crate::analyzer::semantic_model::NameSelector;

use crate::analyzer::semantic_model::PayloadKind;

use crate::analyzer::semantic_model::SEMANTIC_MODEL_SUPPORTED_SCHEMA_VERSIONS;

use crate::analyzer::semantic_model::decode_manifest;

use crate::analyzer::semantic_model::decode_validated_shard_for_manifest;

use crate::analyzer::semantic_model::validate_manifest_inventory;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;

use brokk_bifrost_core::analyzer::canonical_hash::is_lower_sha256;

use brokk_bifrost_core::analyzer::canonical_hash::lower_hex_string;

use crate::analyzer::semantic_model::GoPinnedPackage;

/// SQLite schema version used to isolate the generated default catalog from
/// older binaries that cannot open a newer catalog.
pub const CATALOG_SCHEMA_VERSION: i64 = db::CURRENT_CATALOG_VERSION;

/// Cache-compatibility version for locally generated semantic packs.
///
/// Increment this whenever producer or compiler behavior can change the bytes
/// or meaning of a generated pack without changing its other exact inputs.
///
/// 9: the Python stub producer expands wildcard re-exports across a source set,
/// publishing the names a shim module binds and dropping its `*` marker (#2958).
/// 10: exact Java binary tables certify scoped callable-family completeness,
/// and source/JMOD production retains both formal names and that proof (#3006).
/// 11: Python source-set rejects retain their exact source-entry identity for
/// release extraction accounting (#3027).
/// 14: the Python stub producer no longer records `@name.setter` and
/// `@name.deleter` as members of their own. A property with a write half
/// published two competing records for one name, and competing records cannot
/// prove the member present on its owner.
/// 15: the Python stub producer records the implicit `builtins.object` base a
/// stub omits when a class names no other. Without it 196 of the stdlib pack's
/// 560 classes, `int`, `float` and `types.NoneType` among them, had no
/// ancestry, so no consumer could resolve their surface or exclude them from
/// an `isinstance` guard.
/// 17: the Python stub producer resolves imported return annotations and
/// canonicalizes the exact `typing_extensions` aliases for `NoReturn` and
/// `Never`. Warm generated packs carry only the unqualified local spelling.
/// 18: the Rust rustdoc producer emits keyed `std::collections::HashMap`
/// collection-flow facts. Warm generated packs predate those contracts.
/// 19: native compilation preserves and validates deferred-yield contracts.
/// 20: schema version three, and the Scala source-JAR producer classifies every
/// declaration it emits with an `ambient_use` role. Warm generated packs carry
/// no such role, and absence there means "unreviewed", so a stale pack would
/// silently withhold every Scala unused-import proof.
/// 22: C++ header production withholds unproven brace pairings in damaged
/// syntax, including the recovered exported-class partitioning used to emit
/// dependency declarations. Warm generated packs may retain the old shape.
/// 23: the Go source producer parses Go 1.26 new(expr) through the same
/// structured repair as workspace analysis. Warm packs can retain declarations
/// and signatures lost to the old grammar recovery (#3325).
/// 24: the C++ header producer publishes namespace owners and the exact
/// explicit value operations of std::basic_string. Warm generated packs
/// predate those owner and operation facts.
/// 25: producers write native schema four, which admits the portable runtime
/// contract companion. Rebuild generated packs under the new wire contract.
/// 26: Java source and binary producers mark formals as positional-only and
/// publish reviewed stable identities and formal names for selected JDK
/// security endpoints. Warm generated JDK packs predate those facts.
/// 27: the Rust declaration producer unwraps grammar-owned attributes in
/// impl bodies so attributed methods, associated constants, and associated
/// types are retained. Warm generated packs may omit those declarations.
/// 28: the Python stub producer projects the `__call__` signature of a
/// module-level value's class onto the value's name, so `builtins.exit` and
/// `builtins.quit` carry the `_sitebuiltins.Quitter.__call__` contract
/// (#3135). Warm generated packs publish those names as signature-less
/// constants.
/// 29: the Java source-JAR producer records an interface's `extends` clause as
/// an interface-table edge, so a source archive answers the members an
/// inherited interface declares (#3466). Warm generated packs lose every one
/// of those edges.
/// 30: the C++ header producer publishes each file-scope declaration under a
/// module owner for its declaring header instead of dropping it as
/// `cpp.member_owner_unavailable` (#3535). Warm generated packs omit every
/// file-scope function, so a C call could never bind one.
/// 31: reviewed zero-argument `String.trim` and `String.strip` source-JDK
/// methods have complete callable families. Warm generated JDK packs still
/// mark both families incomplete and cannot prove exact calls (#3649).
/// 32: the reviewed static `Files.deleteIfExists(Path)` source-JDK method has
/// a complete callable family. Warm generated packs cannot prove that exact
/// overload for the ignored-status rule (#3649).
/// 33: Java functional-interface inputs retain sealed declarations and do not
/// classify static interface methods as abstract (#3702).
/// 34: concurrent producers added scoped callable inventories (#3702) and
/// reviewed Statement.executeQuery(String) compatibility/formal facts (#3699).
/// 35: the functional-target branch resolves implicit java.lang declarations.
/// 36: merged producer output includes both branches; neither earlier cache
/// epoch represents the combined declaration semantics.
/// 37: Java producers retain explicit final-method evidence independently of virtuality defaults.
/// 38: Python class hierarchy extraction no longer treats `metaclass=` as an instance base.
/// 39: TypeScript default exports retain aliases; unsupported exports make packs partial.
/// 40: native schema8 compatibility invalidates earlier producer outputs.
/// 41: schema9 retains explicitly unknown port types; earlier schema8 outputs
/// and validation certificates cannot certify the combined model.
/// 42: schema10 carries native callable-values facts and scoped coverage;
/// earlier generated outputs cannot certify the combined model.
/// 43: the JMOD producer reads the descriptor's variable-width `opens` table,
/// skips `classes/` resources, and reads only exported packages; Java class
/// producers erase a signature that names a type variable outside its
/// declaration's scope (#3444). Warm JDK packs omit `java.desktop` and
/// `java.security.jgss` and are marked partial.
/// 44: exact Go source selectors and activation evidence carry the selected
/// source-set digest, while the generated production key remains separate.
/// 45: the origin merge combines generated producer inputs from both branches,
/// invalidating cache entries produced from either pre-merge model.
/// 46 (upstream): schema-14 structured variadic procedure formals change the
/// meaning of generated Python standard-library summaries.
/// 46 (#4343 branch): C++ external signatures retain declaration-written
/// formal names so named call-argument selectors can bind generated header
/// models.
/// 47 (#4343 branch): generated C/C++ header variadic declarations retain
/// explicit variadic markers without claiming family completeness, and
/// callable-owner filtering excludes unrelated same-named types from generated
/// header publication.
/// 48: the merge of both branches combines their generated producer changes,
/// so entries produced by either pre-merge producer are stale.
/// 49: CSMI callable summaries now retain structured formal binding slots.
/// 50: CSMI callable summaries retain one exact runtime return-class claim.
/// 51: schema sixteen replaces that claim with the complete exact runtime
/// return-class set, which changes the meaning of generated callable facts.
/// 52: the Python stub producer publishes module-level class aliases and the
/// source order of every declared class base. Warm packs omit alias identities
/// and leave ordered multiple inheritance unavailable to C3 (#4860).
/// 53: C++ grammar 0.24.3 retains the closing language-linkage guard around
/// header overloads. Warm packs parsed from identical bytes lack that guard.
/// 54: Kotlin native declarations retain named-only fixed parameters after a
/// positional vararg. Older generated signatures allow invalid positional tails.
/// 55: Scala source artifacts withhold the flat signature of a callable whose
/// repeated parameter list is followed by another list, keeping its exact
/// declaration identity and a declaration-scoped warning. Older productions
/// carry a positional formal after a vararg, which fails pack validation.
/// 56: recoverable PHP source-syntax warnings retain their exact source entry,
/// changing extraction accounting and the gaps reported by warm productions.
/// 57: Scala operator-named classes retain indexed declarations and constructors;
/// local case-class companions cannot publish fabricated global JVM aliases.
pub const GENERATED_PRODUCTION_CACHE_VERSION: u32 = 57;
pub const SEMANTIC_PACK_CACHE_ROOT_ENV: &str = "BIFROST_SEMANTIC_PACK_CACHE_ROOT";

/// Resolve the generated catalog used when no explicit catalog is configured.
/// By default this shares the analyzer cache's repository and linked-worktree
/// scope. The semantic-pack-only override deliberately permits a host to share
/// content-addressed productions without sharing analyzer databases.
pub fn default_semantic_pack_catalog_root(workspace_root: &Path) -> PathBuf {
    default_semantic_pack_catalog_root_with_override(
        workspace_root,
        std::env::var_os(SEMANTIC_PACK_CACHE_ROOT_ENV).filter(|value| !value.is_empty()),
    )
}

#[doc(hidden)]
pub fn default_semantic_pack_catalog_root_with_override(
    workspace_root: &Path,
    cache_root: Option<std::ffi::OsString>,
) -> PathBuf {
    cache_root
        .map(PathBuf::from)
        .unwrap_or_else(|| brokk_bifrost_core::gitblob::cache_dir_path(workspace_root))
        .join(format!("semantic-pack-catalog.v{CATALOG_SCHEMA_VERSION}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogOpenMode {
    ReadWrite,
    ReadOnly,
}

#[derive(Debug, Clone, Default)]
pub struct CatalogOptions {
    pub decode_limits: DecodeLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionPackSourceKind {
    Embedded,
    EphemeralWorkspace,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPackSource {
    pub kind: SessionPackSourceKind,
    pub source_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CatalogCoordinate {
    pub name: String,
    pub version: Option<Version>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticPackSelectorQuery {
    pub language: String,
    pub ecosystem: String,
    pub package: Option<CatalogCoordinate>,
    pub module: Option<CatalogCoordinate>,
    pub toolchain: Option<CatalogCoordinate>,
    pub target: Option<String>,
    pub configuration: Option<String>,
    pub artifact_sha256: Option<String>,
    pub bifrost_version: Version,
}

#[derive(Debug, Clone, Copy)]
pub struct CatalogCallableValuesQueryLimits {
    /// Maximum matching facts, coverage claims, and expanded target-identity
    /// rows materialized by one request.
    pub max_records: usize,
}

#[derive(Debug, Clone, Copy)]
pub enum CatalogCallableValuesQuestion<'a> {
    ReturnedCallable {
        result: u32,
    },
    CallbackInvocation {
        callback: &'a CsmiInputLocation,
        shape: CsmiCallableValuesShape,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct CatalogCallableValuesQuery<'a> {
    pub manifest_digest: &'a str,
    pub shard_id: &'a str,
    pub callable: &'a str,
    pub question: CatalogCallableValuesQuestion<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogCallableValueFact {
    pub manifest_digest: String,
    pub shard_id: String,
    pub callable: String,
    pub ordinal: i64,
    pub fact: CallableValuesFact,
    /// Present when a returned target has an exact native anonymous identity
    /// in this same manifest and shard.
    pub anonymous_callable: Option<AnonymousCallableIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogCallableValueCoverage {
    pub manifest_digest: String,
    pub shard_id: String,
    pub callable: String,
    pub ordinal: i64,
    pub coverage: CallableValuesCoverage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogCallableValuesQueryGap {
    Cancelled,
    RecordBudgetExhausted {
        max_records: usize,
    },
    UnsupportedProjection(
        crate::analyzer::semantic_model::csmi::CsmiCallableValuesUnsupportedProjection,
    ),
    IndexReconciliationRequired,
}

#[derive(Debug)]
pub struct CatalogCallableValuesQueryResult {
    /// Alternatives remain independent; array order never selects a winner.
    pub facts: Vec<CatalogCallableValueFact>,
    /// Producer claims remain independent from executable completeness.
    pub coverage_claims: Vec<CatalogCallableValueCoverage>,
    /// SQL catalog evidence alone never establishes execution proof.
    pub executable_coverage: CsmiCoverageStatus,
    /// Matching facts, scoped coverage claims, and identity rows materialized
    /// by this SQL request.
    pub examined_records: usize,
    pub gap: Option<CatalogCallableValuesQueryGap>,
}

#[derive(Debug, Clone, Copy)]
pub struct CatalogGoSourceReadLimits {
    pub max_files: usize,
    pub max_source_bytes: u64,
    pub max_path_depth: usize,
}

impl Default for CatalogGoSourceReadLimits {
    fn default() -> Self {
        Self {
            max_files: 100_000,
            max_source_bytes: 256 * 1024 * 1024,
            max_path_depth: 64,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CatalogGoSourceRequest<'a> {
    pub manifest_digest: &'a str,
    pub shard_id: &'a str,
    pub artifact_sha256: &'a str,
    pub package_import_path: &'a str,
    pub file: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogExactGoSourceSet {
    pub artifact: ExactArtifact,
    pub packages: Vec<GoPinnedPackage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallOutcome {
    pub manifest_digest: String,
    pub inserted_manifest: bool,
    pub inserted_objects: usize,
}

/// One declaration that a pack producer could not extract.
///
/// `declaration` is the producer's canonical fully-qualified type name. A
/// member-specific reject may use `Owner.member`; owner-wide checks also
/// consult the owning type. `reason` is stable diagnostic context for humans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackExtractionGap {
    pub declaration: String,
    pub reason: String,
}

/// One artifact-relative source entry that a pack producer could not parse.
///
/// A source entry provides accountability for a file-level reject. Unlike
/// [`PackExtractionGap`], it is not a declaration and must not participate in
/// declaration-gap lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackExtractionSourceEntry {
    pub source_entry: String,
    pub reason: String,
}

/// Complete reject accounting installed from a verified release bundle.
///
/// Ordinary authored and workspace-generated packs have no row of this kind.
/// That distinction is intentional: a partial pack may activate only when its
/// release bundle accounts for every reject as an individually named warning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackExtractionAccounting {
    pub reject_count: u64,
    pub suppressed_reject_count: u64,
    pub error_reject_count: u64,
    pub gaps: Vec<PackExtractionGap>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_entries: Vec<PackExtractionSourceEntry>,
}

impl PackExtractionAccounting {
    pub fn warning_only_and_fully_accounted(&self) -> bool {
        self.suppressed_reject_count == 0
            && self.error_reject_count == 0
            && (self.gaps.len() + self.source_entries.len()) as u64 == self.reject_count
    }
}

/// The single release-verification and activation-readiness definition.
pub fn pack_is_activation_ready(
    completeness: Completeness,
    extraction: Option<&PackExtractionAccounting>,
) -> bool {
    completeness == Completeness::Complete
        || extraction.is_some_and(PackExtractionAccounting::warning_only_and_fully_accounted)
}

pub fn pack_rejects_are_warning_only(extraction: &PackExtractionAccounting) -> bool {
    extraction.error_reject_count == 0
}

const GENERATED_PRODUCTION_DOMAIN: &[u8] = b"bifrost.semantic-pack.generated-production.v1";
const ACQUISITION_REQUEST_DOMAIN: &[u8] = b"bifrost.semantic-pack.acquisition-request.v1";
const ACQUISITION_RELEASE_DOMAIN: &[u8] = b"bifrost.semantic-pack.acquisition-release.v1";
#[doc(hidden)]
pub const ACQUISITION_SOURCE_STATE_DOMAIN: &[u8] = b"bifrost.semantic-pack.acquisition-sources.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcquisitionReceiptRequest {
    GeneratedProduction(GeneratedProductionKey),
    DeclaredPack(Box<SemanticPackSelectorQuery>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquisitionReceiptRelease {
    pub repository: String,
    pub tag: String,
    pub archive_name: String,
    pub archive_digest: String,
    pub bundle_schema_version: u32,
    pub bundle_generator_name: String,
    pub bundle_generator_version: String,
    pub semantic_schema_version: u32,
    pub generated_cache_version: u32,
    pub client_epoch: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquisitionReceiptLookup {
    Satisfied,
    KnownVerifiedAbsence,
    ReceiptMiss,
}

impl AcquisitionReceiptRequest {
    pub fn generated(key: &GeneratedProductionKey) -> Self {
        Self::GeneratedProduction(key.clone())
    }

    pub fn declared(query: &SemanticPackSelectorQuery) -> Self {
        Self::DeclaredPack(Box::new(query.clone()))
    }

    pub fn digest(&self) -> String {
        let mut hasher = CanonicalHasher::new(ACQUISITION_REQUEST_DOMAIN);
        match self {
            Self::GeneratedProduction(key) => {
                hasher.field("kind", b"generated_production");
                hasher.field("production_digest", key.production_digest().as_bytes());
                hasher.field("input_digest", key.input_digest().as_bytes());
                hasher.field("producer_name", key.producer_name().as_bytes());
                hasher.field("producer_version", key.producer_version().as_bytes());
                hasher.field("schema_version", &key.schema_version().to_be_bytes());
                hasher.field(
                    "generated_cache_version",
                    &GENERATED_PRODUCTION_CACHE_VERSION.to_be_bytes(),
                );
            }
            Self::DeclaredPack(query) => {
                hasher.field("kind", b"declared_pack");
                hasher.field("language", query.language.as_bytes());
                hasher.field("ecosystem", query.ecosystem.as_bytes());
                hash_coordinate(&mut hasher, "package", query.package.as_ref());
                hash_coordinate(&mut hasher, "module", query.module.as_ref());
                hash_coordinate(&mut hasher, "toolchain", query.toolchain.as_ref());
                hash_optional(&mut hasher, "target", query.target.as_deref());
                hash_optional(&mut hasher, "configuration", query.configuration.as_deref());
                hash_optional(
                    &mut hasher,
                    "artifact_sha256",
                    query.artifact_sha256.as_deref(),
                );
                hasher.field(
                    "bifrost_version",
                    query.bifrost_version.to_string().as_bytes(),
                );
                hasher.sequence(
                    "supported_semantic_model_schema_versions",
                    SEMANTIC_MODEL_SUPPORTED_SCHEMA_VERSIONS,
                    |hasher, version| hasher.field("version", &version.to_be_bytes()),
                );
            }
        }
        lower_hex_string(&hasher.finish())
    }
}

impl AcquisitionReceiptRelease {
    pub fn digest(&self) -> Result<String, CatalogError> {
        if self.repository.is_empty()
            || self.tag.is_empty()
            || self.archive_name.is_empty()
            || !is_lower_sha256(&self.archive_digest)
            || self.bundle_schema_version == 0
            || self.bundle_generator_name.is_empty()
            || self.bundle_generator_version.is_empty()
            || self.semantic_schema_version == 0
            || self.generated_cache_version == 0
            || self.client_epoch == 0
        {
            return Err(CatalogError::Integrity(
                "acquisition release identity must be complete".to_owned(),
            ));
        }
        let mut hasher = CanonicalHasher::new(ACQUISITION_RELEASE_DOMAIN);
        hasher.field("repository", self.repository.as_bytes());
        hasher.field("tag", self.tag.as_bytes());
        hasher.field("archive_name", self.archive_name.as_bytes());
        hasher.field("archive_digest", self.archive_digest.as_bytes());
        hasher.field(
            "bundle_schema_version",
            &self.bundle_schema_version.to_be_bytes(),
        );
        hasher.field(
            "bundle_generator_name",
            self.bundle_generator_name.as_bytes(),
        );
        hasher.field(
            "bundle_generator_version",
            self.bundle_generator_version.as_bytes(),
        );
        hasher.field(
            "semantic_schema_version",
            &self.semantic_schema_version.to_be_bytes(),
        );
        hasher.field(
            "generated_cache_version",
            &self.generated_cache_version.to_be_bytes(),
        );
        hasher.field("client_epoch", &self.client_epoch.to_be_bytes());
        hasher.field(
            "catalog_schema_version",
            &CATALOG_SCHEMA_VERSION.to_be_bytes(),
        );
        Ok(lower_hex_string(&hasher.finish()))
    }
}

fn hash_optional(hasher: &mut CanonicalHasher, name: &str, value: Option<&str>) {
    hasher.field(name, value.unwrap_or_default().as_bytes());
    hasher.field(&format!("{name}_present"), &[u8::from(value.is_some())]);
}

fn hash_coordinate(
    hasher: &mut CanonicalHasher,
    name: &str,
    coordinate: Option<&CatalogCoordinate>,
) {
    hash_optional(
        hasher,
        &format!("{name}_name"),
        coordinate.map(|coordinate| coordinate.name.as_str()),
    );
    let version = coordinate
        .and_then(|coordinate| coordinate.version.as_ref())
        .map(ToString::to_string);
    hash_optional(hasher, &format!("{name}_version"), version.as_deref());
}

/// Exact semantic inputs that identify one generated semantic-pack production.
///
/// `input_digest` is computed by the ecosystem adapter over its normalized
/// activation evidence and ordered artifact kinds and byte digests. Paths and
/// mtimes must not participate so identical artifacts can be reused by another
/// workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedProductionKey {
    #[doc(hidden)]
    pub production_digest: String,
    input_digest: String,
    producer_name: String,
    producer_version: String,
    schema_version: u32,
}

impl GeneratedProductionKey {
    pub fn new(
        input_digest: impl Into<String>,
        producer_name: impl Into<String>,
        producer_version: impl Into<String>,
        schema_version: u32,
    ) -> Result<Self, CatalogError> {
        let input_digest = input_digest.into();
        let producer_name = producer_name.into();
        let producer_version = producer_version.into();
        if !is_lower_sha256(&input_digest) {
            return Err(CatalogError::Integrity(
                "generated-production input digest must be lowercase SHA-256".to_owned(),
            ));
        }
        if producer_name.is_empty() || producer_version.is_empty() || schema_version == 0 {
            return Err(CatalogError::Integrity(
                "generated-production producer identity and schema version must be non-empty"
                    .to_owned(),
            ));
        }
        let production_digest = generated_production_digest(
            &input_digest,
            &producer_name,
            &producer_version,
            schema_version,
        );
        Ok(Self {
            production_digest,
            input_digest,
            producer_name,
            producer_version,
            schema_version,
        })
    }

    pub fn production_digest(&self) -> &str {
        &self.production_digest
    }

    pub fn input_digest(&self) -> &str {
        &self.input_digest
    }

    pub fn producer_name(&self) -> &str {
        &self.producer_name
    }

    pub fn producer_version(&self) -> &str {
        &self.producer_version
    }

    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn source_id(&self) -> String {
        format!("production:{}", self.production_digest)
    }
}

/// Verify a release-recorded generated-production digest with its recorded
/// cache epoch. This checks the immutable identity without constructing a key
/// under the current cache epoch.
pub fn verify_recorded_generated_production_digest(
    production_digest: &str,
    input_digest: &str,
    producer_name: &str,
    producer_version: &str,
    schema_version: u32,
    cache_version: u32,
) -> Result<bool, CatalogError> {
    let expected = recorded_generated_production_digest(
        input_digest,
        producer_name,
        producer_version,
        schema_version,
        cache_version,
    )?;
    Ok(production_digest == expected)
}

/// Compute the release identity recorded for a generated production at the
/// cache epoch named by the release, including historical bundle entries.
pub fn recorded_generated_production_digest(
    input_digest: &str,
    producer_name: &str,
    producer_version: &str,
    schema_version: u32,
    cache_version: u32,
) -> Result<String, CatalogError> {
    if !is_lower_sha256(input_digest) {
        return Err(CatalogError::Integrity(
            "generated-production digests must be lowercase SHA-256".to_owned(),
        ));
    }
    if producer_name.is_empty()
        || producer_version.is_empty()
        || schema_version == 0
        || cache_version == 0
    {
        return Err(CatalogError::Integrity(
            "generated-production producer identity, schema version, and cache version must be non-empty"
                .to_owned(),
        ));
    }
    Ok(generated_production_digest_for_cache_version(
        input_digest,
        producer_name,
        producer_version,
        schema_version,
        cache_version,
    ))
}

/// An acquired operating-system lock for one exact generated production.
/// Dropping the file releases the lock, including after process termination.
#[doc(hidden)]
pub struct GeneratedProductionLock {
    #[doc(hidden)]
    pub file: File,
}

impl GeneratedProductionLock {
    #[doc(hidden)]
    pub fn try_acquire(&self) -> Result<bool, CatalogError> {
        match self.file.try_lock() {
            Ok(()) => Ok(true),
            Err(std::fs::TryLockError::WouldBlock) => Ok(false),
            Err(std::fs::TryLockError::Error(error)) => {
                Err(CatalogError::io("acquire generated-production lock", error))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedProduction {
    pub key: GeneratedProductionKey,
    pub manifest_digest: String,
    pub completeness: Completeness,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedInstallOutcome {
    pub production: GeneratedProduction,
    pub install: InstallOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogPackInventorySource {
    pub source_kind: String,
    pub source_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogPackInventoryActivation {
    pub scope_id: String,
    pub active_set_digest: String,
    pub source_kind: String,
    pub source_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogPackInventory {
    pub manifest_content_sha256: String,
    pub manifest_semantic_sha256: String,
    pub state: String,
    pub pack_id: String,
    pub pack_version: String,
    pub producer: crate::analyzer::semantic_model::Producer,
    pub language: String,
    pub ecosystem: String,
    pub provenance: crate::analyzer::semantic_model::Provenance,
    pub completeness: Completeness,
    pub extraction: Option<PackExtractionAccounting>,
    pub sources: Vec<CatalogPackInventorySource>,
    pub catalog_activations: Vec<CatalogPackInventoryActivation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogInventory {
    pub complete: bool,
    pub packs: Vec<CatalogPackInventory>,
}

#[doc(hidden)]
pub fn inventory_pack(manifest: &CompiledPackManifest, state: String) -> CatalogPackInventory {
    CatalogPackInventory {
        manifest_content_sha256: manifest.content_sha256.clone(),
        manifest_semantic_sha256: manifest.semantic_sha256.clone(),
        state,
        pack_id: manifest.pack_id.clone(),
        pack_version: manifest.version.clone(),
        producer: manifest.producer.clone(),
        language: manifest.language.clone(),
        ecosystem: manifest.ecosystem.clone(),
        provenance: manifest.provenance.clone(),
        completeness: manifest.completeness,
        extraction: None,
        sources: Vec::new(),
        catalog_activations: Vec::new(),
    }
}

#[derive(Debug, Clone)]
pub struct CatalogGcOptions {
    pub minimum_age: Duration,
    pub max_packs: usize,
    pub max_objects: usize,
}

impl Default for CatalogGcOptions {
    fn default() -> Self {
        Self {
            minimum_age: Duration::from_secs(7 * 24 * 60 * 60),
            max_packs: 1_000,
            max_objects: 4_096,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogGcOutcome {
    pub pruned_packs: usize,
    pub pruned_objects: usize,
    pub reclaimed_bytes: u64,
    pub pruned_expired_leases: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogMiss {
    NotFound,
    Quarantined { reason: String },
    Incompatible { reason: String },
}

/// One pack that names a queried coordinate but rejects its exact version.
///
/// `required` is the exact requirement the pack declares for `coordinate`;
/// `installed` is the version the query carried, absent when discovery found
/// the coordinate without an exact version (#1884).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SemanticPackVersionNearMiss {
    pub pack_id: String,
    pub pack_version: String,
    pub manifest_digest: String,
    /// The rejecting coordinate, for example `toolchain jdk` or
    /// `package com.acme:widget`.
    pub coordinate: String,
    pub installed: Option<String>,
    pub required: String,
}

impl SemanticPackVersionNearMiss {
    /// The one-line statement of this rejection, naming both versions.
    pub fn describe(&self) -> String {
        match &self.installed {
            Some(installed) => format!(
                "semantic pack {}@{} requires {} {}, but the workspace {} is {}",
                self.pack_id,
                self.pack_version,
                self.coordinate,
                self.required,
                self.coordinate,
                installed
            ),
            None => format!(
                "semantic pack {}@{} requires {} {}, but discovery found no exact {} version",
                self.pack_id, self.pack_version, self.coordinate, self.required, self.coordinate
            ),
        }
    }
}

/// One raw `catalog_selectors` join row, before compatibility filtering.
#[doc(hidden)]
pub struct DurableSelectorRow {
    #[doc(hidden)]
    pub manifest_digest: String,
    #[doc(hidden)]
    pub shard_id: String,
    #[doc(hidden)]
    pub descriptor_json: Vec<u8>,
    #[doc(hidden)]
    pub selector_json: Vec<u8>,
    #[doc(hidden)]
    pub source_kind: String,
    #[doc(hidden)]
    pub source_id: String,
}

#[derive(Debug)]
pub enum CatalogError {
    Io {
        operation: &'static str,
        source: std::io::Error,
    },
    Sqlite {
        operation: &'static str,
        source: rusqlite::Error,
    },
    Artifact(String),
    Integrity(String),
    ReadOnly,
    CatalogTooNew {
        found: i64,
        supported: i64,
    },
    ReadOnlySchema {
        found: i64,
        required: i64,
    },
    Cancelled,
    SourceBudgetExhausted {
        max_files: usize,
        max_source_bytes: u64,
    },
    Unavailable,
}

impl CatalogError {
    #[doc(hidden)]
    pub fn io(operation: &'static str, source: std::io::Error) -> Self {
        Self::Io { operation, source }
    }

    #[doc(hidden)]
    pub fn sqlite(operation: &'static str, source: rusqlite::Error) -> Self {
        Self::Sqlite { operation, source }
    }
}

impl From<brokk_bifrost_core::sqlite_template::TemplateIoError> for CatalogError {
    fn from(error: brokk_bifrost_core::sqlite_template::TemplateIoError) -> Self {
        let source = std::io::Error::new(
            error.source.kind(),
            format!("{}: {}", error.path.display(), error.source),
        );
        Self::Io {
            operation: error.operation,
            source,
        }
    }
}

impl fmt::Display for CatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, source } => write!(formatter, "{operation}: {source}"),
            Self::Sqlite { operation, source } => write!(formatter, "{operation}: {source}"),
            Self::Artifact(message) | Self::Integrity(message) => formatter.write_str(message),
            Self::ReadOnly => formatter.write_str("semantic-pack catalog is read-only"),
            Self::CatalogTooNew { found, supported } => write!(
                formatter,
                "semantic-pack catalog schema {found} is newer than supported version {supported}"
            ),
            Self::ReadOnlySchema { found, required } => write!(
                formatter,
                "read-only semantic-pack catalog schema is {found}, expected {required}"
            ),
            Self::Cancelled => formatter.write_str("semantic-pack catalog query was cancelled"),
            Self::SourceBudgetExhausted {
                max_files,
                max_source_bytes,
            } => write!(
                formatter,
                "exact Go source reader budget exhausted (max_files={max_files}, max_source_bytes={max_source_bytes})"
            ),
            Self::Unavailable => formatter.write_str("catalog candidate is unavailable"),
        }
    }
}

impl std::error::Error for CatalogError {}

/// Decoded manifests of one catalog, keyed by their content digest.
///
/// Candidate selection visits one row per (shard, selector) and shard loading
/// visits one row per shard. Both used to deserialize the same stored manifest
/// once per row: one fresh policy process decoded the same two JDK manifests
/// 259 times, 18.8 of its 31 activation seconds (#3101). The key is the
/// manifest's own `content_sha256`, and `decode_manifest` proves that the value
/// it returns hashes to that key, so a hit is the value the miss would return.
/// Catalog mutations cannot make an entry stale: a manifest digest names its
/// exact bytes, and readers keep checking each pack's stored state themselves.
#[doc(hidden)]
pub struct DecodedManifestMemo {
    #[doc(hidden)]
    pub entries: HashMap<String, Arc<CompiledPackManifest>>,
    #[doc(hidden)]
    pub bytes: usize,
}

/// Canonical manifest bytes the memo retains before it starts over.
///
/// Manifests of one pack are adjacent in every ordered reader, so a restart
/// costs one decode per distinct manifest, never one per row. The bound keeps a
/// catalog that serves many packs from retaining unbounded decoded state.
#[doc(hidden)]
pub const DECODED_MANIFEST_MEMO_BYTES: usize = 32 * 1024 * 1024;

// Increment when artifact semantic validation or normalization changes. A
// certificate proves those checks for exact bytes under exact decode limits;
// it never replaces the stored/content digest checks on each load.
// 7: callable families may be complete when their final declaration formal is
// variadic, and schema-14 summary formal shapes receive directional validation.
// 8: schema-16 exact return-class claims receive callable-result validation.
// 9: schema-16 exact return-class sets receive non-empty nominal-set validation.
// 10: distinguish a named positional-vararg slot from a keyword collector,
// matching the formal-layout interpreter while rejecting positional fixed tails.
#[doc(hidden)]
pub const SHARD_VALIDATION_VERSION: u32 = 10;

#[doc(hidden)]
pub fn decode_limits_digest(limits: &DecodeLimits) -> String {
    let mut hasher = CanonicalHasher::new(b"bifrost.semantic-pack.decode-limits.v1");
    for (name, value) in [
        ("manifest_bytes", limits.max_manifest_bytes as u64),
        ("stored_shard_bytes", limits.max_stored_shard_bytes as u64),
        ("raw_shard_bytes", limits.max_raw_shard_bytes as u64),
        ("total_raw_bytes", limits.max_total_raw_bytes),
        ("shards", limits.max_shards as u64),
        ("records_per_shard", limits.max_records_per_shard as u64),
        ("total_records", limits.max_total_records),
        ("text_bytes", limits.max_text_bytes as u64),
        ("depth", limits.max_depth as u64),
    ] {
        hasher.field(name, &value.to_be_bytes());
    }
    lower_hex_string(&hasher.finish())
}

#[doc(hidden)]
pub const SHARED_PRODUCTION_PRESENT_SQL: &str = "SELECT EXISTS(
    SELECT 1 FROM catalog_verified_generated_productions WHERE production_digest = ?1)";

#[doc(hidden)]
pub const CERTIFIED_SHARD_SQL: &str = "SELECT EXISTS(
    SELECT 1 FROM catalog_shard_validations
    WHERE manifest_digest = ?1 AND shard_id = ?2
      AND validation_version = ?3 AND limits_sha256 = ?4)";

#[doc(hidden)]
pub const CALLABLE_VALUES_RETURNED_SQL: &str = "SELECT fact.fact_ordinal,
       fact.result_ordinal, fact.target, fact.provenance_json
FROM catalog_callable_value_facts AS fact
JOIN catalog_packs AS pack ON pack.manifest_digest = fact.manifest_digest
WHERE pack.state = 'verified'
  AND fact.manifest_digest = ?1 AND fact.shard_id = ?2
  AND fact.family = 'returned-callables' AND fact.callable = ?3
  AND fact.result_ordinal = ?4
ORDER BY fact.fact_ordinal
LIMIT ?5";

#[doc(hidden)]
pub const CALLABLE_VALUES_CALLBACK_SQL: &str = "SELECT fact.fact_ordinal,
       fact.callback_location_json, fact.callback_parameters,
       fact.callback_results, fact.arguments_json, fact.timing,
       fact.modality, fact.provenance_json
FROM catalog_callable_value_facts AS fact
JOIN catalog_packs AS pack ON pack.manifest_digest = fact.manifest_digest
WHERE pack.state = 'verified'
  AND fact.manifest_digest = ?1 AND fact.shard_id = ?2
  AND fact.family = 'callback-invocations' AND fact.callable = ?3
  AND fact.callback_location_json = ?4
  AND fact.callback_parameters = ?5 AND fact.callback_results = ?6
ORDER BY fact.fact_ordinal
LIMIT ?7";

#[doc(hidden)]
pub const CALLABLE_VALUES_COVERAGE_SQL: &str = "SELECT coverage.coverage_ordinal,
       coverage.family, coverage.status, coverage.limitations_json,
       coverage.provenance_json
FROM catalog_callable_value_coverage AS coverage
JOIN catalog_packs AS pack ON pack.manifest_digest = coverage.manifest_digest
WHERE pack.state = 'verified'
  AND coverage.manifest_digest = ?1 AND coverage.shard_id = ?2
  AND coverage.family = ?3 AND coverage.callable = ?4
ORDER BY coverage.coverage_ordinal
LIMIT ?5";

#[doc(hidden)]
pub const ANONYMOUS_CALLABLE_IDENTITY_SQL: &str = "SELECT identity.artifact_sha256,
       identity.package_import_path, identity.anchor_file, identity.anchor_start,
       identity.anchor_end, identity.signature_file, identity.signature_start,
       identity.signature_end
FROM catalog_anonymous_callable_identities AS identity
JOIN catalog_packs AS pack ON pack.manifest_digest = identity.manifest_digest
WHERE pack.state = 'verified' AND identity.manifest_digest = ?1
  AND identity.shard_id = ?2 AND identity.callable_id = ?3";

#[doc(hidden)]
pub const ANONYMOUS_CALLABLE_IDENTITY_ANCHORS_SQL: &str = "SELECT 'anchor' AS row_kind,
       chain_kind AS subkind, ordinal, file, byte_start, byte_end,
       declaration_kind, NULL AS variadic, NULL AS arity
FROM catalog_anonymous_callable_identity_anchors
WHERE manifest_digest = ?1 AND shard_id = ?2 AND callable_id = ?3
ORDER BY chain_kind, ordinal
LIMIT ?4";

#[doc(hidden)]
pub const ANONYMOUS_CALLABLE_IDENTITY_SHAPES_SQL: &str = "SELECT 'shape' AS row_kind,
       shape_kind AS subkind, ordinal, file, byte_start, byte_end,
       NULL AS declaration_kind, variadic, arity
FROM catalog_anonymous_callable_signature_shapes
WHERE manifest_digest = ?1 AND shard_id = ?2 AND callable_id = ?3
ORDER BY shape_kind, ordinal
LIMIT ?4";

#[doc(hidden)]
pub fn record_shard_validation(
    connection: &Connection,
    manifest: &str,
    shard: &str,
    limits: &str,
) -> Result<(), CatalogError> {
    connection
        .execute(
            "INSERT OR IGNORE INTO catalog_shard_validations
         (manifest_digest, shard_id, validation_version, limits_sha256)
         VALUES (?1, ?2, ?3, ?4)",
            params![manifest, shard, SHARD_VALIDATION_VERSION, limits],
        )
        .map_err(|error| CatalogError::sqlite("record shard validation", error))?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub struct SemanticPackCatalogCacheIdentity {
    #[doc(hidden)]
    pub instance_identity: u64,
    #[doc(hidden)]
    pub mutation_generation: u64,
    #[doc(hidden)]
    pub sqlite_data_version: u64,
}

#[derive(Clone)]
#[doc(hidden)]
pub struct ValidatedShard {
    #[doc(hidden)]
    pub descriptor: CompiledShardDescriptor,
    #[doc(hidden)]
    pub bytes: Vec<u8>,
    #[doc(hidden)]
    pub selectors: Vec<ActivationSelector>,
    #[doc(hidden)]
    pub callable_values: Option<CallableValuesPayload>,
}

#[doc(hidden)]
pub enum CallableValuesIndexReadiness {
    Ready,
    Cancelled,
    Missing,
}

#[doc(hidden)]
pub enum AnonymousCallableIdentityRead {
    Missing,
    Found {
        identity: Box<AnonymousCallableIdentity>,
        examined: usize,
    },
    RecordBudgetExhausted {
        examined: usize,
    },
    Cancelled {
        examined: usize,
    },
}

#[doc(hidden)]
pub struct ValidatedPack {
    #[doc(hidden)]
    pub manifest: CompiledPackManifest,
    #[doc(hidden)]
    pub shards: Vec<ValidatedShard>,
}

#[doc(hidden)]
pub struct SessionPack {
    #[doc(hidden)]
    pub manifest: Arc<CompiledPackManifest>,
    #[doc(hidden)]
    pub shards: Vec<ValidatedShard>,
    #[doc(hidden)]
    pub source: SessionPackSource,
}

#[doc(hidden)]
pub struct SessionCallableValuesCatalog {
    // Field order closes the SQLite connection before TempDir removes its
    // database and any SQLite sidecars on Windows.
    #[doc(hidden)]
    pub connection: Connection,
    _root: TempDir,
}

#[doc(hidden)]
pub enum CallableValuesQueryConnection<'a> {
    Durable(std::sync::MutexGuard<'a, Connection>),
    Session(std::sync::MutexGuard<'a, Option<SessionCallableValuesCatalog>>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub enum CatalogCandidateLocation {
    Durable,
    Session {
        pack_ordinal: usize,
        shard_ordinal: usize,
    },
}

#[doc(hidden)]
pub fn durable_selector_rows_on(
    connection: &Connection,
    query: &SemanticPackSelectorQuery,
    max_rows: usize,
) -> Result<Vec<DurableSelectorRow>, CatalogError> {
    let supported_schema_versions = SEMANTIC_MODEL_SUPPORTED_SCHEMA_VERSIONS
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let selector_source = if query.package.is_some() {
        "SELECT * FROM catalog_selectors INDEXED BY catalog_selectors_package
         WHERE package_name IS NULL
         UNION ALL
         SELECT * FROM catalog_selectors INDEXED BY catalog_selectors_package
         WHERE package_name = ?3"
    } else if query.module.is_some() {
        "SELECT * FROM catalog_selectors INDEXED BY catalog_selectors_module
         WHERE module_name IS NULL
         UNION ALL
         SELECT * FROM catalog_selectors INDEXED BY catalog_selectors_module
         WHERE module_name = ?4"
    } else if query.toolchain.is_some() {
        "SELECT * FROM catalog_selectors INDEXED BY catalog_selectors_toolchain
         WHERE toolchain_name IS NULL
         UNION ALL
         SELECT * FROM catalog_selectors INDEXED BY catalog_selectors_toolchain
         WHERE toolchain_name = ?5"
    } else if query.artifact_sha256.is_some() {
        "SELECT * FROM catalog_selectors INDEXED BY catalog_selectors_artifact
         WHERE artifact_sha256 IS NULL
         UNION ALL
         SELECT * FROM catalog_selectors INDEXED BY catalog_selectors_artifact
         WHERE artifact_sha256 = ?8"
    } else {
        "SELECT * FROM catalog_selectors"
    };
    let candidate_sql = format!(
        "SELECT p.manifest_digest, ps.shard_id,
                ps.descriptor_json, s.selector_json,
                source.source_kind, source.source_id
         FROM catalog_packs AS p
         JOIN catalog_pack_shards AS ps
           ON ps.manifest_digest = p.manifest_digest
         JOIN ({selector_source}) AS s
           ON s.manifest_digest = ps.manifest_digest
          AND s.shard_id = ps.shard_id
         JOIN catalog_sources AS source
           ON source.manifest_digest = p.manifest_digest
         LEFT JOIN catalog_generated_productions AS generated
           ON source.source_kind = 'generated'
          AND generated.manifest_digest = source.manifest_digest
          AND source.source_id = 'production:' || generated.production_digest
         WHERE p.state = 'verified'
           AND p.schema_version IN ({supported_schema_versions})
           AND (generated.production_digest IS NULL OR generated.generated_cache_version = ?10)
           AND p.language = ?1
           AND p.ecosystem = ?2
           AND (?3 IS NULL OR s.package_name IS NULL OR s.package_name = ?3)
           AND (?4 IS NULL OR s.module_name IS NULL OR s.module_name = ?4)
           AND (?5 IS NULL OR s.toolchain_name IS NULL OR s.toolchain_name = ?5)
           AND (
             ?6 IS NULL
             OR NOT EXISTS(
               SELECT 1 FROM catalog_selector_targets AS targets
               WHERE targets.manifest_digest = s.manifest_digest
                 AND targets.shard_id = s.shard_id
                 AND targets.selector_ordinal = s.selector_ordinal
             )
             OR EXISTS(
               SELECT 1 FROM catalog_selector_targets AS targets
               WHERE targets.manifest_digest = s.manifest_digest
                 AND targets.shard_id = s.shard_id
                 AND targets.selector_ordinal = s.selector_ordinal
                 AND targets.target = ?6
             )
           )
           AND (
             ?7 IS NULL
             OR NOT EXISTS(
               SELECT 1 FROM catalog_selector_configurations AS configurations
               WHERE configurations.manifest_digest = s.manifest_digest
                 AND configurations.shard_id = s.shard_id
                 AND configurations.selector_ordinal = s.selector_ordinal
             )
             OR EXISTS(
               SELECT 1 FROM catalog_selector_configurations AS configurations
               WHERE configurations.manifest_digest = s.manifest_digest
                 AND configurations.shard_id = s.shard_id
                 AND configurations.selector_ordinal = s.selector_ordinal
                 AND configurations.configuration = ?7
             )
           )
           AND (
             ?8 IS NULL OR s.artifact_sha256 IS NULL OR s.artifact_sha256 = ?8
           )
         ORDER BY p.manifest_digest, ps.shard_id,
                  source.source_kind, source.source_id, s.selector_ordinal
         LIMIT ?9"
    );
    let mut statement = connection
        .prepare(&candidate_sql)
        .map_err(|error| CatalogError::sqlite("prepare candidate lookup", error))?;
    let rows = statement
        .query_map(
            params![
                &query.language,
                &query.ecosystem,
                query
                    .package
                    .as_ref()
                    .map(|coordinate| coordinate.name.as_str()),
                query
                    .module
                    .as_ref()
                    .map(|coordinate| coordinate.name.as_str()),
                query
                    .toolchain
                    .as_ref()
                    .map(|coordinate| coordinate.name.as_str()),
                query.target.as_deref(),
                query.configuration.as_deref(),
                query.artifact_sha256.as_deref(),
                i64::try_from(max_rows).unwrap_or(i64::MAX),
                GENERATED_PRODUCTION_CACHE_VERSION,
            ],
            |row| {
                Ok(DurableSelectorRow {
                    manifest_digest: row.get::<_, String>(0)?,
                    shard_id: row.get::<_, String>(1)?,
                    descriptor_json: row.get::<_, Vec<u8>>(2)?,
                    selector_json: row.get::<_, Vec<u8>>(3)?,
                    source_kind: row.get::<_, String>(4)?,
                    source_id: row.get::<_, String>(5)?,
                })
            },
        )
        .map_err(|error| CatalogError::sqlite("query candidates", error))?;
    let mut durable_rows = Vec::new();
    for row in rows {
        durable_rows.push(row.map_err(|error| CatalogError::sqlite("read candidate row", error))?);
    }
    Ok(durable_rows)
}

#[doc(hidden)]
pub fn validate_pack(
    pack: &CompiledSemanticModelPack,
    limits: &DecodeLimits,
) -> Result<ValidatedPack, CatalogError> {
    let manifest = decode_manifest(&pack.manifest_bytes, limits)
        .map_err(|error| CatalogError::Artifact(error.to_string()))?;
    if manifest != pack.manifest {
        return Err(CatalogError::Integrity(
            "compiled pack manifest value does not match its bytes".to_owned(),
        ));
    }
    if pack.shards.len() != manifest.shards.len() {
        return Err(CatalogError::Integrity(
            "compiled pack does not contain every manifest shard".to_owned(),
        ));
    }
    // One inventory validation covers every shard below; validating per shard
    // re-walked every record id of the manifest once per shard (#3101).
    validate_manifest_inventory(&manifest)
        .map_err(|error| CatalogError::Artifact(error.to_string()))?;

    let mut shards = Vec::with_capacity(pack.shards.len());
    let mut python_shards = Vec::new();
    let mut matched = HashSet::with_capacity(pack.shards.len());
    for descriptor in &manifest.shards {
        let mut artifacts = pack
            .shards
            .iter()
            .filter(|artifact| artifact.descriptor == *descriptor);
        let artifact = artifacts.next().ok_or_else(|| {
            CatalogError::Integrity(format!(
                "compiled pack is missing shard {}",
                descriptor.shard_id
            ))
        })?;
        if artifacts.next().is_some() || !matched.insert(descriptor.shard_id.clone()) {
            return Err(CatalogError::Integrity(format!(
                "compiled pack contains duplicate shard {}",
                descriptor.shard_id
            )));
        }
        let decoded =
            decode_validated_shard_for_manifest(&manifest, descriptor, &artifact.bytes, limits)
                .map_err(|error| CatalogError::Artifact(error.to_string()))?;
        let selectors = decoded.activation.clone();
        let callable_values = decoded.callable_values.clone();
        if manifest.language == "python" {
            python_shards.push(decoded);
        }
        shards.push(ValidatedShard {
            descriptor: descriptor.clone(),
            bytes: artifact.bytes.clone(),
            selectors,
            callable_values,
        });
    }
    if manifest.language == "python" {
        let authored = crate::analyzer::semantic_model::artifact::authored_pack_from_decoded_shards(
            &manifest,
            &python_shards,
        );
        let diagnostics =
            crate::analyzer::semantic_model::validate::validate_csmi_profile_evidence(&authored);
        if !diagnostics.is_empty() {
            return Err(CatalogError::Integrity(format!(
                "Python compiled pack has inconsistent full-pack evidence: {diagnostics:?}"
            )));
        }
    }
    Ok(ValidatedPack { manifest, shards })
}

#[doc(hidden)]
pub fn semantic_mutation_epoch(connection: &Connection) -> Result<u64, CatalogError> {
    connection
        .query_row(
            "SELECT mutation_epoch FROM catalog_semantic_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| CatalogError::sqlite("read semantic catalog mutation epoch", error))
}

#[doc(hidden)]
pub fn acquisition_request_satisfied(
    root: &Path,
    connection: &Connection,
    limits: &DecodeLimits,
    request: &AcquisitionReceiptRequest,
) -> Result<bool, CatalogError> {
    match request {
        AcquisitionReceiptRequest::GeneratedProduction(key) => {
            let row = connection
                .query_row(
                    "SELECT gp.input_digest, gp.producer_name, gp.producer_version,
                            gp.schema_version, gp.manifest_digest, p.manifest_bytes
                     FROM catalog_generated_productions AS gp
                     JOIN catalog_packs AS p ON p.manifest_digest = gp.manifest_digest
                     JOIN catalog_sources AS source
                       ON source.manifest_digest = gp.manifest_digest
                      AND source.source_kind = 'generated'
                      AND source.source_id = 'production:' || gp.production_digest
                     WHERE gp.production_digest = ?1 AND p.state = 'verified'",
                    [key.production_digest()],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, u32>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, Vec<u8>>(5)?,
                        ))
                    },
                )
                .optional()
                .map_err(|error| {
                    CatalogError::sqlite("lookup receipt generated production", error)
                })?;
            let Some((input, producer, producer_version, schema, digest, manifest_bytes)) = row
            else {
                return Ok(false);
            };
            let stored_key =
                match GeneratedProductionKey::new(input, producer, producer_version, schema) {
                    Ok(key) => key,
                    Err(CatalogError::Integrity(_)) => return Ok(false),
                    Err(error) => return Err(error),
                };
            let manifest = match decode_manifest(&manifest_bytes, limits) {
                Ok(manifest) => manifest,
                Err(_) => return Ok(false),
            };
            Ok(stored_key == *key
                && manifest.content_sha256 == digest
                && manifest_shard_rows_present(root, connection, &digest, &manifest)?
                && validate_generated_pack_identity(key, &manifest).is_ok())
        }
        AcquisitionReceiptRequest::DeclaredPack(query) => {
            assert!(query_has_exact_coordinate(query));
            let mut manifests = HashMap::<String, Option<Arc<CompiledPackManifest>>>::new();
            for row in durable_selector_rows_on(connection, query, usize::MAX)? {
                let manifest = match manifests
                    .entry(row.manifest_digest.clone())
                    .or_insert_with(|| {
                        stored_manifest_bytes_on(connection, &row.manifest_digest)
                            .ok()
                            .flatten()
                            .and_then(|bytes| decode_manifest(&bytes, limits).ok())
                            .map(Arc::new)
                    })
                    .as_ref()
                {
                    Some(manifest) => Arc::clone(manifest),
                    None => continue,
                };
                if manifest.content_sha256 != row.manifest_digest {
                    continue;
                }
                let selector: ActivationSelector = match serde_json::from_slice(&row.selector_json)
                {
                    Ok(selector) => selector,
                    Err(_) => continue,
                };
                let descriptor: CompiledShardDescriptor =
                    match serde_json::from_slice(&row.descriptor_json) {
                        Ok(descriptor) => descriptor,
                        Err(_) => continue,
                    };
                if manifest_shard_rows_present(root, connection, &row.manifest_digest, &manifest)?
                    && matches!(manifest_compatible(&manifest, query), Ok(true))
                    && matches!(selector_matches(&selector, query), Ok(true))
                    && selector_binds_exact_coordinate(&selector, query)
                    && manifest.shards.iter().any(|expected| {
                        expected.shard_id == row.shard_id && *expected == descriptor
                    })
                {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

/// Read one stored manifest's bytes through a caller-held connection.
///
/// The catalog's own readers go through its decoded-manifest memo instead; this
/// is for the receipt proof, which runs on a catalog transaction.
#[doc(hidden)]
pub fn stored_manifest_bytes_on(
    connection: &Connection,
    manifest_digest: &str,
) -> Result<Option<Vec<u8>>, CatalogError> {
    connection
        .query_row(
            "SELECT manifest_bytes FROM catalog_packs WHERE manifest_digest = ?1",
            [manifest_digest],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(|error| CatalogError::sqlite("read stored manifest", error))
}

#[doc(hidden)]
pub fn manifest_shard_rows_present(
    root: &Path,
    connection: &Connection,
    manifest_digest: &str,
    manifest: &CompiledPackManifest,
) -> Result<bool, CatalogError> {
    let mut statement = connection
        .prepare(
            "SELECT shard.shard_id, shard.stored_digest,
                    object.relative_path, object.stored_size
             FROM catalog_pack_shards AS shard
             JOIN catalog_objects AS object ON object.stored_digest = shard.stored_digest
             WHERE shard.manifest_digest = ?1",
        )
        .map_err(|error| CatalogError::sqlite("prepare receipt shard proof", error))?;
    let rows = statement
        .query_map([manifest_digest], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, u64>(3)?,
            ))
        })
        .map_err(|error| CatalogError::sqlite("query receipt shard proof", error))?;
    let mut stored = HashMap::with_capacity(manifest.shards.len());
    for row in rows {
        let (shard_id, stored_digest, relative_path, stored_size) =
            row.map_err(|error| CatalogError::sqlite("read receipt shard proof", error))?;
        if !receipt_object_is_valid(root, Path::new(&relative_path), &stored_digest, stored_size)? {
            return Ok(false);
        }
        stored.insert(shard_id, stored_digest);
    }
    Ok(stored.len() == manifest.shards.len()
        && missing_manifest_shard_ids(manifest, &stored).is_empty())
}

#[doc(hidden)]
pub fn missing_manifest_shard_ids<'a>(
    manifest: &'a CompiledPackManifest,
    stored: &HashMap<String, String>,
) -> Vec<&'a str> {
    manifest
        .shards
        .iter()
        .filter(|descriptor| stored.get(&descriptor.shard_id) != Some(&descriptor.stored_sha256))
        .map(|descriptor| descriptor.shard_id.as_str())
        .collect()
}

#[doc(hidden)]
pub fn validate_acquisition_receipt_request(
    request: &AcquisitionReceiptRequest,
) -> Result<(), CatalogError> {
    if let AcquisitionReceiptRequest::DeclaredPack(query) = request
        && !query_has_exact_coordinate(query)
    {
        return Err(CatalogError::Integrity(
            "declared-pack acquisition receipts require an exact dependency coordinate".to_owned(),
        ));
    }
    Ok(())
}

#[doc(hidden)]
pub fn receipt_object_is_valid(
    root: &Path,
    relative_path: &Path,
    digest: &str,
    stored_size: u64,
) -> Result<bool, CatalogError> {
    match storage::verify_existing(root, relative_path, digest, stored_size) {
        Ok(()) => Ok(true),
        Err(CatalogError::Integrity(_)) => Ok(false),
        Err(CatalogError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

#[doc(hidden)]
pub fn validate_extraction_accounting(
    extraction: &PackExtractionAccounting,
) -> Result<(), CatalogError> {
    if extraction.error_reject_count > extraction.reject_count {
        return Err(CatalogError::Integrity(
            "error reject count exceeds total reject count".to_owned(),
        ));
    }
    if extraction
        .gaps
        .len()
        .saturating_add(extraction.source_entries.len()) as u64
        > extraction.reject_count
    {
        return Err(CatalogError::Integrity(
            "accounted extraction rejects exceed total reject count".to_owned(),
        ));
    }
    if extraction
        .gaps
        .iter()
        .any(|gap| gap.declaration.is_empty() || gap.reason.is_empty())
    {
        return Err(CatalogError::Integrity(
            "pack extraction gaps require a declaration and reason".to_owned(),
        ));
    }
    if extraction.source_entries.iter().any(|entry| {
        entry.source_entry.is_empty()
            || !is_canonical_relative_path(&entry.source_entry)
            || entry.reason.is_empty()
    }) {
        return Err(CatalogError::Integrity(
            "pack extraction source entries require a canonical relative source entry and reason"
                .to_owned(),
        ));
    }
    Ok(())
}

#[doc(hidden)]
pub fn reconcile_storage(root: &Path, connection: &mut Connection) -> Result<(), CatalogError> {
    const RECONCILIATION_LIMIT: usize = 4_096;
    storage::cleanup_stale_staging(root, Duration::from_secs(60 * 60), RECONCILIATION_LIMIT)?;
    let mut removed_objects = 0;
    storage::visit_object_files(root, |relative_path, digest| {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CatalogError::sqlite("begin catalog object reconciliation", error))?;
        let protected: bool = transaction
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM catalog_objects WHERE stored_digest = ?1
                   UNION ALL
                   SELECT 1 FROM catalog_install_object_reservations
                   WHERE stored_digest = ?1 AND expires_at > ?2
                 )",
                params![&digest, brokk_bifrost_core::cache_db::now_unix_seconds()],
                |row| row.get(0),
            )
            .map_err(|error| CatalogError::sqlite("reconcile catalog object", error))?;
        if !protected {
            storage::delete(
                root,
                relative_path.to_str().ok_or_else(|| {
                    CatalogError::Integrity("catalog object path is not valid Unicode".to_owned())
                })?,
                &digest,
            )?;
            removed_objects += 1;
        }
        transaction
            .commit()
            .map_err(|error| CatalogError::sqlite("commit catalog object reconciliation", error))?;
        Ok(removed_objects < RECONCILIATION_LIMIT)
    })
}

#[doc(hidden)]
pub fn insert_manifest(
    transaction: &Transaction<'_>,
    manifest: &CompiledPackManifest,
    bytes: &[u8],
    now: i64,
) -> Result<bool, CatalogError> {
    let existed: bool = transaction
        .query_row(
            "SELECT EXISTS(
               SELECT 1 FROM catalog_packs WHERE manifest_digest = ?1
             )",
            [&manifest.content_sha256],
            |row| row.get(0),
        )
        .map_err(|error| CatalogError::sqlite("check existing pack manifest", error))?;
    transaction
        .execute(
            "INSERT INTO catalog_packs(
               manifest_digest, semantic_digest, manifest_bytes, schema_version,
               pack_id, pack_version, producer_name, producer_version,
               language, ecosystem, bifrost_compatibility, provenance_json,
               license, completeness, state, installed_at, verified_at
             ) VALUES(
               ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
               ?14, 'verified', ?15, ?15
             )
             ON CONFLICT(manifest_digest) DO UPDATE SET
               semantic_digest = excluded.semantic_digest,
               manifest_bytes = excluded.manifest_bytes,
               schema_version = excluded.schema_version,
               pack_id = excluded.pack_id,
               pack_version = excluded.pack_version,
               producer_name = excluded.producer_name,
               producer_version = excluded.producer_version,
               language = excluded.language,
               ecosystem = excluded.ecosystem,
               bifrost_compatibility = excluded.bifrost_compatibility,
               provenance_json = excluded.provenance_json,
               license = excluded.license,
               completeness = excluded.completeness,
               state = 'verified',
               verified_at = excluded.verified_at",
            params![
                &manifest.content_sha256,
                &manifest.semantic_sha256,
                bytes,
                manifest.schema_version,
                &manifest.pack_id,
                &manifest.version,
                &manifest.producer.name,
                &manifest.producer.version,
                &manifest.language,
                &manifest.ecosystem,
                manifest.compatibility.bifrost.as_deref(),
                serde_json::to_vec(&manifest.provenance)
                    .map_err(|error| CatalogError::Integrity(error.to_string()))?,
                &manifest.license,
                manifest.completeness.label(),
                now
            ],
        )
        .map_err(|error| CatalogError::sqlite("insert pack manifest", error))?;
    Ok(!existed)
}

#[doc(hidden)]
pub fn insert_extraction_accounting(
    transaction: &Transaction<'_>,
    manifest_digest: &str,
    extraction: &PackExtractionAccounting,
) -> Result<(), CatalogError> {
    transaction
        .execute(
            "INSERT INTO catalog_pack_extraction_accounting(
               manifest_digest, reject_count, suppressed_reject_count, error_reject_count
             ) VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(manifest_digest) DO UPDATE SET
               reject_count = excluded.reject_count,
               suppressed_reject_count = excluded.suppressed_reject_count,
               error_reject_count = excluded.error_reject_count",
            params![
                manifest_digest,
                extraction.reject_count,
                extraction.suppressed_reject_count,
                extraction.error_reject_count,
            ],
        )
        .map_err(|error| CatalogError::sqlite("insert pack extraction accounting", error))?;
    transaction
        .execute(
            "DELETE FROM catalog_pack_extraction_gaps WHERE manifest_digest = ?1",
            [manifest_digest],
        )
        .map_err(|error| CatalogError::sqlite("replace pack extraction gaps", error))?;
    for (ordinal, gap) in extraction.gaps.iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO catalog_pack_extraction_gaps(
                   manifest_digest, ordinal, declaration, reason
                 ) VALUES(?1, ?2, ?3, ?4)",
                params![manifest_digest, ordinal, &gap.declaration, &gap.reason],
            )
            .map_err(|error| CatalogError::sqlite("insert pack extraction gap", error))?;
    }
    transaction
        .execute(
            "DELETE FROM catalog_pack_extraction_source_entries WHERE manifest_digest = ?1",
            [manifest_digest],
        )
        .map_err(|error| CatalogError::sqlite("replace pack extraction source entries", error))?;
    for (ordinal, entry) in extraction.source_entries.iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO catalog_pack_extraction_source_entries(
                   manifest_digest, ordinal, source_entry, reason
                 ) VALUES(?1, ?2, ?3, ?4)",
                params![manifest_digest, ordinal, &entry.source_entry, &entry.reason],
            )
            .map_err(|error| CatalogError::sqlite("insert pack extraction source entry", error))?;
    }
    Ok(())
}

fn generated_production_digest(
    input_digest: &str,
    producer_name: &str,
    producer_version: &str,
    schema_version: u32,
) -> String {
    generated_production_digest_for_cache_version(
        input_digest,
        producer_name,
        producer_version,
        schema_version,
        GENERATED_PRODUCTION_CACHE_VERSION,
    )
}

#[doc(hidden)]
pub fn generated_production_digest_for_cache_version(
    input_digest: &str,
    producer_name: &str,
    producer_version: &str,
    schema_version: u32,
    cache_version: u32,
) -> String {
    let mut hasher = CanonicalHasher::new(GENERATED_PRODUCTION_DOMAIN);
    hasher.field("input_digest", input_digest.as_bytes());
    hasher.field("producer_name", producer_name.as_bytes());
    hasher.field("producer_version", producer_version.as_bytes());
    hasher.field("schema_version", &schema_version.to_be_bytes());
    hasher.field("cache_version", &cache_version.to_be_bytes());
    lower_hex_string(&hasher.finish())
}

#[doc(hidden)]
pub fn validate_generated_pack_identity(
    key: &GeneratedProductionKey,
    manifest: &CompiledPackManifest,
) -> Result<(), CatalogError> {
    if !manifest.matches_generated_identity(
        &key.producer_name,
        &key.producer_version,
        key.schema_version,
    ) {
        return Err(CatalogError::Integrity(
            "generated-production producer or schema does not match compiled pack".to_owned(),
        ));
    }
    Ok(())
}

#[doc(hidden)]
pub fn validate_exact_go_source(
    artifact: &ExactArtifact,
    packages: &[GoPinnedPackage],
) -> Result<(), CatalogError> {
    if !is_lower_sha256(artifact.sha256()) {
        return Err(CatalogError::Integrity(
            "exact Go source artifact must carry a lowercase SHA-256 digest".to_owned(),
        ));
    }
    let limits = ArtifactProducerLimits::default();
    let rebuilt = ExactArtifact::from_source_entries(
        PathBuf::from("<exact Go source registration>"),
        artifact
            .source_entries()
            .iter()
            .map(|entry| (entry.relative_path().to_owned(), entry.bytes().to_vec()))
            .collect(),
        limits.max_signature_depth,
        &limits,
    )
    .map_err(|diagnostic| CatalogError::Artifact(diagnostic.message))?;
    if rebuilt.sha256() != artifact.sha256() || rebuilt.bytes() != artifact.bytes() {
        return Err(CatalogError::Integrity(
            "exact Go source artifact digest does not match its canonical source set".to_owned(),
        ));
    }
    if packages.is_empty() {
        return Err(CatalogError::Integrity(
            "exact Go source registration requires at least one package".to_owned(),
        ));
    }

    let source_paths = artifact
        .source_entries()
        .iter()
        .map(|entry| {
            if !is_canonical_relative_path(entry.relative_path()) {
                return Err(CatalogError::Integrity(format!(
                    "exact Go source path is not canonical: {:?}",
                    entry.relative_path()
                )));
            }
            std::str::from_utf8(entry.bytes()).map_err(|_| {
                CatalogError::Integrity(format!(
                    "exact Go source file is not UTF-8: {:?}",
                    entry.relative_path()
                ))
            })?;
            Ok(entry.relative_path())
        })
        .collect::<Result<HashSet<_>, CatalogError>>()?;
    let mut package_imports = HashSet::new();
    let mut package_files = HashSet::new();
    for package in packages {
        if package.import_path.is_empty() || package.name.is_empty() || package.files.is_empty() {
            return Err(CatalogError::Integrity(
                "exact Go package metadata must name a package and at least one file".to_owned(),
            ));
        }
        if !package_imports.insert(package.import_path.as_str()) {
            return Err(CatalogError::Integrity(format!(
                "exact Go package metadata repeats import path {:?}",
                package.import_path
            )));
        }
        let mut package_file_paths = HashSet::new();
        for file in &package.files {
            if !is_canonical_relative_path(file) || !source_paths.contains(file.as_str()) {
                return Err(CatalogError::Integrity(format!(
                    "exact Go package file is outside the selected source set: {file:?}"
                )));
            }
            if !package_file_paths.insert(file.as_str()) || !package_files.insert(file.as_str()) {
                return Err(CatalogError::Integrity(format!(
                    "exact Go source file has duplicate package membership: {file:?}"
                )));
            }
        }
    }
    if package_files.len() != source_paths.len() {
        return Err(CatalogError::Integrity(
            "exact Go package metadata does not cover every selected source file".to_owned(),
        ));
    }
    Ok(())
}

#[doc(hidden)]
pub fn insert_exact_go_source_rows(
    transaction: &Transaction<'_>,
    manifest_digest: &str,
    artifact: &ExactArtifact,
    packages: &[GoPinnedPackage],
) -> Result<(), CatalogError> {
    validate_exact_go_source(artifact, packages)?;
    transaction
        .execute(
            "INSERT OR IGNORE INTO catalog_exact_go_source_sets(
               manifest_digest, artifact_sha256
             ) VALUES(?1, ?2)",
            params![manifest_digest, artifact.sha256()],
        )
        .map_err(|error| CatalogError::sqlite("insert exact Go source set", error))?;
    transaction
        .execute(
            "DELETE FROM catalog_exact_go_package_files
             WHERE manifest_digest = ?1 AND artifact_sha256 = ?2",
            params![manifest_digest, artifact.sha256()],
        )
        .map_err(|error| CatalogError::sqlite("replace exact Go package files", error))?;
    transaction
        .execute(
            "DELETE FROM catalog_exact_go_packages
             WHERE manifest_digest = ?1 AND artifact_sha256 = ?2",
            params![manifest_digest, artifact.sha256()],
        )
        .map_err(|error| CatalogError::sqlite("replace exact Go packages", error))?;
    transaction
        .execute(
            "DELETE FROM catalog_exact_go_source_files
             WHERE manifest_digest = ?1 AND artifact_sha256 = ?2",
            params![manifest_digest, artifact.sha256()],
        )
        .map_err(|error| CatalogError::sqlite("replace exact Go source files", error))?;
    for entry in artifact.source_entries() {
        let source_text = std::str::from_utf8(entry.bytes()).map_err(|_| {
            CatalogError::Integrity(format!(
                "exact Go source file is not UTF-8: {:?}",
                entry.relative_path()
            ))
        })?;
        transaction
            .execute(
                "INSERT INTO catalog_exact_go_source_files(
                   manifest_digest, artifact_sha256, relative_path, source_text
                 ) VALUES(?1, ?2, ?3, ?4)",
                params![
                    manifest_digest,
                    artifact.sha256(),
                    entry.relative_path(),
                    source_text
                ],
            )
            .map_err(|error| CatalogError::sqlite("insert exact Go source file", error))?;
    }
    for (package_ordinal, package) in packages.iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO catalog_exact_go_packages(
                   manifest_digest, artifact_sha256, package_ordinal,
                   import_path, package_name
                 ) VALUES(?1, ?2, ?3, ?4, ?5)",
                params![
                    manifest_digest,
                    artifact.sha256(),
                    package_ordinal,
                    &package.import_path,
                    &package.name,
                ],
            )
            .map_err(|error| CatalogError::sqlite("insert exact Go package", error))?;
        for (file_ordinal, file) in package.files.iter().enumerate() {
            transaction
                .execute(
                    "INSERT INTO catalog_exact_go_package_files(
                       manifest_digest, artifact_sha256, package_ordinal,
                       file_ordinal, relative_path
                     ) VALUES(?1, ?2, ?3, ?4, ?5)",
                    params![
                        manifest_digest,
                        artifact.sha256(),
                        package_ordinal,
                        file_ordinal,
                        file,
                    ],
                )
                .map_err(|error| CatalogError::sqlite("insert exact Go package file", error))?;
        }
    }
    Ok(())
}

#[doc(hidden)]
pub fn insert_generated_production(
    transaction: &Transaction<'_>,
    key: &GeneratedProductionKey,
    manifest: &CompiledPackManifest,
    now: i64,
) -> Result<(), CatalogError> {
    validate_generated_pack_identity(key, manifest)?;
    transaction
        .execute(
            "INSERT INTO catalog_generated_productions(
               production_digest, input_digest, producer_name, producer_version,
               schema_version, manifest_digest, created_at, generated_cache_version
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(production_digest) DO NOTHING",
            params![
                &key.production_digest,
                &key.input_digest,
                &key.producer_name,
                &key.producer_version,
                key.schema_version,
                &manifest.content_sha256,
                now,
                GENERATED_PRODUCTION_CACHE_VERSION,
            ],
        )
        .map_err(|error| CatalogError::sqlite("insert generated production", error))?;
    let stored_manifest: String = transaction
        .query_row(
            "SELECT manifest_digest
             FROM catalog_generated_productions
             WHERE production_digest = ?1",
            [&key.production_digest],
            |row| row.get(0),
        )
        .map_err(|error| CatalogError::sqlite("verify generated production", error))?;
    if stored_manifest != manifest.content_sha256 {
        return Err(CatalogError::Integrity(format!(
            "generated-production key {} is already bound to a different manifest",
            key.production_digest
        )));
    }
    Ok(())
}

#[doc(hidden)]
pub fn insert_object(
    transaction: &Transaction<'_>,
    descriptor: &CompiledShardDescriptor,
    relative_path: &Path,
    now: i64,
) -> Result<(), CatalogError> {
    transaction
        .execute(
            "INSERT INTO catalog_objects(
               stored_digest, relative_path, stored_size, raw_size, encoding, verified_at
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(stored_digest) DO UPDATE SET
               relative_path = excluded.relative_path,
               stored_size = excluded.stored_size,
               raw_size = excluded.raw_size,
               encoding = excluded.encoding,
               verified_at = excluded.verified_at",
            params![
                &descriptor.stored_sha256,
                relative_path.to_string_lossy(),
                descriptor.stored_size,
                descriptor.raw_size,
                encoding_name(descriptor.encoding),
                now
            ],
        )
        .map_err(|error| CatalogError::sqlite("insert catalog object", error))?;
    Ok(())
}

#[doc(hidden)]
pub fn insert_shard(
    transaction: &Transaction<'_>,
    manifest_digest: &str,
    ordinal: usize,
    descriptor: &CompiledShardDescriptor,
) -> Result<(), CatalogError> {
    transaction
        .execute(
            "INSERT OR REPLACE INTO catalog_pack_shards(
               manifest_digest, ordinal, shard_id, payload_kind, stored_digest,
               content_digest, semantic_digest, record_count, descriptor_json
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                manifest_digest,
                ordinal,
                &descriptor.shard_id,
                payload_kind_name(descriptor.payload_kind),
                &descriptor.stored_sha256,
                &descriptor.content_sha256,
                &descriptor.semantic_sha256,
                descriptor.record_count,
                serde_json::to_vec(descriptor)
                    .map_err(|error| CatalogError::Integrity(error.to_string()))?
            ],
        )
        .map_err(|error| CatalogError::sqlite("insert catalog shard", error))?;
    Ok(())
}

#[doc(hidden)]
pub fn publish_callable_value_rows(
    transaction: &Transaction<'_>,
    manifest_digest: &str,
    shard_id: &str,
    payload: Option<&CallableValuesPayload>,
) -> Result<(), CatalogError> {
    // The publication is shared by all source IDs for this manifest/shard.
    // Replace its marker with the rows in the same transaction so registering
    // another source cannot leave a stale marker or duplicate the publication.
    transaction
        .execute(
            "DELETE FROM catalog_callable_values_indexed_shards
             WHERE manifest_digest = ?1 AND shard_id = ?2",
            params![manifest_digest, shard_id],
        )
        .map_err(|error| CatalogError::sqlite("replace callable-value shard marker", error))?;
    transaction
        .execute(
            "DELETE FROM catalog_callable_value_facts
             WHERE manifest_digest = ?1 AND shard_id = ?2",
            params![manifest_digest, shard_id],
        )
        .map_err(|error| CatalogError::sqlite("replace callable-value facts", error))?;
    transaction
        .execute(
            "DELETE FROM catalog_callable_value_coverage
             WHERE manifest_digest = ?1 AND shard_id = ?2",
            params![manifest_digest, shard_id],
        )
        .map_err(|error| CatalogError::sqlite("replace callable-value coverage", error))?;
    transaction
        .execute(
            "DELETE FROM catalog_anonymous_callable_identities
             WHERE manifest_digest = ?1 AND shard_id = ?2",
            params![manifest_digest, shard_id],
        )
        .map_err(|error| CatalogError::sqlite("replace anonymous callable identities", error))?;

    if let Some(payload) = payload {
        for (ordinal, fact) in payload.facts.iter().enumerate() {
            let (
                family,
                result,
                target,
                callback,
                parameters,
                results,
                arguments,
                timing,
                modality,
            ) = match &fact.payload {
                CsmiCallableValuesPayload::ReturnedCallable {
                    callable: _,
                    result,
                    target,
                } => (
                    "returned-callables",
                    Some(*result),
                    Some(target.as_str()),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                ),
                CsmiCallableValuesPayload::CallbackInvocation {
                    callback,
                    shape,
                    arguments,
                    timing,
                    modality,
                    ..
                } => (
                    "callback-invocations",
                    None,
                    None,
                    Some(json_text(callback, "callable callback location")?),
                    Some(shape.parameters),
                    Some(shape.results),
                    Some(json_text(arguments, "callable callback arguments")?),
                    Some(match timing {
                        CsmiCallableValuesTiming::DuringCall => "during-call",
                    }),
                    Some(match modality {
                        CsmiCallableValuesModality::May => "may",
                    }),
                ),
            };
            let callable = match &fact.payload {
                CsmiCallableValuesPayload::ReturnedCallable { callable, .. }
                | CsmiCallableValuesPayload::CallbackInvocation { callable, .. } => callable,
            };
            transaction
                .execute(
                    "INSERT INTO catalog_callable_value_facts(
                       manifest_digest, shard_id, fact_ordinal, family, callable,
                       result_ordinal, target, callback_location_json,
                       callback_parameters, callback_results, arguments_json,
                       timing, modality, provenance_json
                     ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                    params![
                        manifest_digest,
                        shard_id,
                        ordinal,
                        family,
                        callable,
                        result,
                        target,
                        callback,
                        parameters,
                        results,
                        arguments,
                        timing,
                        modality,
                        json_text(&fact.provenance, "callable fact provenance")?,
                    ],
                )
                .map_err(|error| CatalogError::sqlite("publish callable-value fact", error))?;
        }

        for (ordinal, coverage) in payload.coverage.iter().enumerate() {
            transaction
                .execute(
                    "INSERT INTO catalog_callable_value_coverage(
                       manifest_digest, shard_id, coverage_ordinal, family, callable,
                       status, limitations_json, provenance_json
                     ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        manifest_digest,
                        shard_id,
                        ordinal,
                        callable_values_family_name(coverage.family),
                        coverage.callable,
                        coverage_status_name(coverage.status),
                        json_text(&coverage.limitations, "callable coverage limitations")?,
                        json_text(&coverage.provenance, "callable coverage provenance")?,
                    ],
                )
                .map_err(|error| CatalogError::sqlite("publish callable-value coverage", error))?;
        }

        for identity in &payload.anonymous_callables {
            assert_eq!(
                identity.anchor.kind,
                SourceDeclarationKind::FunctionLiteral,
                "anonymous callable identity must point to a function literal"
            );
            validate_source_path(&identity.anchor.file)?;
            validate_source_path(&identity.signature.function_type.file)?;
            transaction
                .execute(
                    "INSERT INTO catalog_anonymous_callable_identities(
                       manifest_digest, shard_id, callable_id, artifact_sha256,
                       package_import_path, anchor_file, anchor_start, anchor_end,
                       anchor_kind, signature_file, signature_start, signature_end
                     ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'function-literal',
                       ?9, ?10, ?11)",
                    params![
                        manifest_digest,
                        shard_id,
                        identity.id,
                        identity.artifact_sha256,
                        identity.package_identity,
                        identity.anchor.file,
                        sql_byte(identity.anchor.byte_range.start)?,
                        sql_byte(identity.anchor.byte_range.end)?,
                        identity.signature.function_type.file,
                        sql_byte(identity.signature.function_type.byte_range.start)?,
                        sql_byte(identity.signature.function_type.byte_range.end)?,
                    ],
                )
                .map_err(|error| {
                    CatalogError::sqlite("publish anonymous callable identity", error)
                })?;
            for (chain_kind, anchors) in [
                ("lexical_owner", identity.lexical_owner_chain.as_slice()),
                (
                    "signature_declaration",
                    identity.signature.declaration_chain.as_slice(),
                ),
            ] {
                for (ordinal, anchor) in anchors.iter().enumerate() {
                    validate_source_path(&anchor.file)?;
                    transaction
                        .execute(
                            "INSERT INTO catalog_anonymous_callable_identity_anchors(
                               manifest_digest, shard_id, callable_id, chain_kind,
                               ordinal, file, byte_start, byte_end, declaration_kind
                             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                            params![
                                manifest_digest,
                                shard_id,
                                identity.id,
                                chain_kind,
                                ordinal,
                                anchor.file,
                                sql_byte(anchor.byte_range.start)?,
                                sql_byte(anchor.byte_range.end)?,
                                source_declaration_kind_name(anchor.kind),
                            ],
                        )
                        .map_err(|error| {
                            CatalogError::sqlite("publish anonymous callable owner anchor", error)
                        })?;
                }
            }
            for (shape_kind, shapes) in [
                ("parameter", identity.signature.parameters.as_slice()),
                ("result", identity.signature.results.as_slice()),
            ] {
                for (ordinal, shape) in shapes.iter().enumerate() {
                    validate_source_path(&shape.type_node.file)?;
                    transaction
                        .execute(
                            "INSERT INTO catalog_anonymous_callable_signature_shapes(
                               manifest_digest, shard_id, callable_id, shape_kind,
                               ordinal, file, byte_start, byte_end, variadic, arity
                             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                            params![
                                manifest_digest,
                                shard_id,
                                identity.id,
                                shape_kind,
                                ordinal,
                                shape.type_node.file,
                                sql_byte(shape.type_node.byte_range.start)?,
                                sql_byte(shape.type_node.byte_range.end)?,
                                i64::from(shape.variadic),
                                sql_byte(shape.arity)?,
                            ],
                        )
                        .map_err(|error| {
                            CatalogError::sqlite(
                                "publish anonymous callable signature shape",
                                error,
                            )
                        })?;
                }
            }
        }
    }

    transaction
        .execute(
            "INSERT INTO catalog_callable_values_indexed_shards(
               manifest_digest, shard_id, index_version
             ) VALUES(?1, ?2, 1)",
            params![manifest_digest, shard_id],
        )
        .map_err(|error| CatalogError::sqlite("publish callable-value shard marker", error))?;
    Ok(())
}

#[doc(hidden)]
pub fn json_text(value: &impl Serialize, description: &str) -> Result<String, CatalogError> {
    serde_json::to_string(value)
        .map_err(|error| CatalogError::Integrity(format!("serialize {description}: {error}")))
}

fn sql_byte(value: usize) -> Result<i64, CatalogError> {
    i64::try_from(value).map_err(|error| {
        CatalogError::Integrity(format!(
            "source byte offset exceeds SQLite integer: {error}"
        ))
    })
}

fn validate_source_path(path: &str) -> Result<(), CatalogError> {
    if !is_canonical_relative_path(path) {
        return Err(CatalogError::Integrity(format!(
            "anonymous callable source path is not canonical and relative: {path:?}"
        )));
    }
    Ok(())
}

fn source_declaration_kind_name(kind: SourceDeclarationKind) -> &'static str {
    match kind {
        SourceDeclarationKind::Function => "function",
        SourceDeclarationKind::Method => "method",
        SourceDeclarationKind::FunctionLiteral => "function-literal",
        SourceDeclarationKind::Type => "type",
        SourceDeclarationKind::TypeAlias => "type-alias",
        SourceDeclarationKind::StructField => "struct-field",
    }
}

fn parse_source_declaration_kind(value: &str) -> Result<SourceDeclarationKind, CatalogError> {
    match value {
        "function" => Ok(SourceDeclarationKind::Function),
        "method" => Ok(SourceDeclarationKind::Method),
        "function-literal" => Ok(SourceDeclarationKind::FunctionLiteral),
        "type" => Ok(SourceDeclarationKind::Type),
        "type-alias" => Ok(SourceDeclarationKind::TypeAlias),
        "struct-field" => Ok(SourceDeclarationKind::StructField),
        _ => Err(CatalogError::Integrity(format!(
            "unknown source declaration kind {value:?}"
        ))),
    }
}

#[doc(hidden)]
pub fn callable_values_family_name(family: CallableValuesFamily) -> &'static str {
    match family {
        CallableValuesFamily::ReturnedCallables => "returned-callables",
        CallableValuesFamily::CallbackInvocations => "callback-invocations",
    }
}

#[doc(hidden)]
pub fn parse_callable_values_family(value: &str) -> Result<CallableValuesFamily, CatalogError> {
    match value {
        "returned-callables" => Ok(CallableValuesFamily::ReturnedCallables),
        "callback-invocations" => Ok(CallableValuesFamily::CallbackInvocations),
        _ => Err(CatalogError::Integrity(format!(
            "unknown callable-value family {value:?}"
        ))),
    }
}

fn coverage_status_name(status: CsmiCoverageStatus) -> &'static str {
    match status {
        CsmiCoverageStatus::Unknown => "unknown",
        CsmiCoverageStatus::Partial => "partial",
        CsmiCoverageStatus::Complete => "complete",
    }
}

#[doc(hidden)]
pub fn parse_coverage_status(value: &str) -> Result<CsmiCoverageStatus, CatalogError> {
    match value {
        "unknown" => Ok(CsmiCoverageStatus::Unknown),
        "partial" => Ok(CsmiCoverageStatus::Partial),
        "complete" => Ok(CsmiCoverageStatus::Complete),
        _ => Err(CatalogError::Integrity(format!(
            "unknown callable-value coverage status {value:?}"
        ))),
    }
}

#[doc(hidden)]
pub fn callable_values_sql_limit(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[doc(hidden)]
pub fn open_session_callable_values_catalog() -> Result<SessionCallableValuesCatalog, CatalogError>
{
    let root = tempfile::Builder::new()
        .prefix("bifrost-session-callable-values-")
        .tempdir()
        .map_err(|error| CatalogError::io("create session callable-values root", error))?;
    let path = root.path().join("session-callable-values.sqlite");
    let mut connection = Connection::open(&path)
        .map_err(|error| CatalogError::sqlite("open session callable-values database", error))?;
    connection.set_transaction_behavior(TransactionBehavior::Immediate);
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|error| {
            CatalogError::sqlite("configure session callable-values timeout", error)
        })?;
    connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(|error| {
            CatalogError::sqlite("enable session callable-values foreign keys", error)
        })?;
    connection
        .pragma_update(None, "cache_size", -8192_i64)
        .map_err(|error| CatalogError::sqlite("bound session callable-values page cache", error))?;
    // This database is deleted with the session; rollback journaling and fsync only add disk flushes.
    let journal_mode: String = connection
        .pragma_update_and_check(None, "journal_mode", "MEMORY", |row| row.get(0))
        .map_err(|error| {
            CatalogError::sqlite("configure session callable-values journal mode", error)
        })?;
    assert_eq!(journal_mode.to_ascii_lowercase(), "memory");
    connection
        .execute_batch(
            "PRAGMA synchronous = OFF;
             PRAGMA temp_store = FILE;
             CREATE TABLE catalog_packs(
               manifest_digest TEXT PRIMARY KEY
                 CHECK(length(manifest_digest) = 64
                   AND manifest_digest NOT GLOB '*[^0-9a-f]*'),
               state TEXT NOT NULL CHECK(state = 'verified')
             ) STRICT;
             CREATE TABLE catalog_pack_shards(
               manifest_digest TEXT NOT NULL,
               shard_id TEXT NOT NULL CHECK(length(shard_id) > 0),
               PRIMARY KEY(manifest_digest, shard_id),
               FOREIGN KEY(manifest_digest)
                 REFERENCES catalog_packs(manifest_digest) ON DELETE CASCADE
             ) STRICT;
             CREATE TABLE catalog_selectors(
               manifest_digest TEXT NOT NULL,
               shard_id TEXT NOT NULL,
               selector_ordinal INTEGER NOT NULL CHECK(selector_ordinal >= 0),
               package_name TEXT,
               package_version TEXT,
               module_name TEXT,
               module_version TEXT,
               toolchain_name TEXT,
               toolchain_version TEXT,
               artifact_sha256 TEXT,
               selector_json BLOB NOT NULL,
               PRIMARY KEY(manifest_digest, shard_id, selector_ordinal),
               FOREIGN KEY(manifest_digest, shard_id)
                 REFERENCES catalog_pack_shards(manifest_digest, shard_id)
                 ON DELETE CASCADE
             ) STRICT;
             CREATE INDEX catalog_selectors_artifact
               ON catalog_selectors(artifact_sha256, manifest_digest, shard_id);
             CREATE TABLE catalog_selector_targets(
               manifest_digest TEXT NOT NULL,
               shard_id TEXT NOT NULL,
               selector_ordinal INTEGER NOT NULL,
               target TEXT NOT NULL,
               PRIMARY KEY(manifest_digest, shard_id, selector_ordinal, target),
               FOREIGN KEY(manifest_digest, shard_id, selector_ordinal)
                 REFERENCES catalog_selectors(
                   manifest_digest, shard_id, selector_ordinal
                 ) ON DELETE CASCADE
             ) STRICT;
             CREATE TABLE catalog_selector_configurations(
               manifest_digest TEXT NOT NULL,
               shard_id TEXT NOT NULL,
               selector_ordinal INTEGER NOT NULL,
               configuration TEXT NOT NULL,
               PRIMARY KEY(manifest_digest, shard_id, selector_ordinal, configuration),
               FOREIGN KEY(manifest_digest, shard_id, selector_ordinal)
                 REFERENCES catalog_selectors(
                   manifest_digest, shard_id, selector_ordinal
                 ) ON DELETE CASCADE
             ) STRICT;",
        )
        .map_err(|error| CatalogError::sqlite("create session callable-values metadata", error))?;
    connection
        .execute_batch(db::CALLABLE_VALUE_ROWS_SQL)
        .map_err(|error| CatalogError::sqlite("create session callable-values rows", error))?;
    connection
        .execute_batch(db::EXACT_GO_SOURCE_ROWS_SQL)
        .map_err(|error| CatalogError::sqlite("create session exact Go source rows", error))?;
    Ok(SessionCallableValuesCatalog {
        connection,
        _root: root,
    })
}

#[doc(hidden)]
pub fn decode_json_column<T: serde::de::DeserializeOwned>(
    value: &str,
    description: &str,
) -> Result<T, CatalogError> {
    serde_json::from_str(value)
        .map_err(|error| CatalogError::Integrity(format!("decode {description}: {error}")))
}

#[doc(hidden)]
pub fn validate_callable_profile_location(
    payload: &CsmiCallableValuesPayload,
) -> Result<(), crate::analyzer::semantic_model::csmi::CsmiCallableValuesUnsupportedProjection> {
    use std::convert::Infallible;

    match payload
        .clone()
        .remap_symbols(|symbol| Ok::<_, Infallible>(symbol.to_owned()))
    {
        Ok(_) => Ok(()),
        Err(crate::analyzer::semantic_model::csmi::CsmiCallableValuesRemapError::UnsupportedProjection(error)) => Err(error),
        Err(crate::analyzer::semantic_model::csmi::CsmiCallableValuesRemapError::Symbol(never)) => match never {},
    }
}

#[doc(hidden)]
pub fn load_anonymous_callable_identity(
    connection: &Connection,
    manifest_digest: &str,
    shard_id: &str,
    callable_id: &str,
    max_records: usize,
    cancellation: &CancellationToken,
) -> Result<AnonymousCallableIdentityRead, CatalogError> {
    if cancellation.is_cancelled() {
        return Ok(AnonymousCallableIdentityRead::Cancelled { examined: 0 });
    }
    let row = connection
        .query_row(
            ANONYMOUS_CALLABLE_IDENTITY_SQL,
            params![manifest_digest, shard_id, callable_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            },
        )
        .optional()
        .map_err(|error| CatalogError::sqlite("lookup anonymous callable identity", error))?;
    let Some((
        artifact_sha256,
        package_import_path,
        anchor_file,
        anchor_start,
        anchor_end,
        signature_file,
        signature_start,
        signature_end,
    )) = row
    else {
        return Ok(AnonymousCallableIdentityRead::Missing);
    };
    let mut examined = 1;
    if examined > max_records {
        return Ok(AnonymousCallableIdentityRead::RecordBudgetExhausted { examined });
    }
    validate_source_path(&anchor_file)?;
    validate_source_path(&signature_file)?;

    let mut lexical_owner_chain = Vec::new();
    let mut declaration_chain = Vec::new();
    let mut parameters = Vec::new();
    let mut results = Vec::new();
    for child_sql in [
        ANONYMOUS_CALLABLE_IDENTITY_ANCHORS_SQL,
        ANONYMOUS_CALLABLE_IDENTITY_SHAPES_SQL,
    ] {
        if cancellation.is_cancelled() {
            return Ok(AnonymousCallableIdentityRead::Cancelled { examined });
        }
        let limit =
            callable_values_sql_limit(max_records.saturating_sub(examined).saturating_add(1));
        let mut statement = connection.prepare(child_sql).map_err(|error| {
            CatalogError::sqlite("prepare anonymous callable identity children", error)
        })?;
        let rows = statement
            .query_map(
                params![manifest_digest, shard_id, callable_id, limit],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, Option<i64>>(7)?,
                        row.get::<_, Option<i64>>(8)?,
                    ))
                },
            )
            .map_err(|error| {
                CatalogError::sqlite("query anonymous callable identity children", error)
            })?;
        for row in rows {
            if cancellation.is_cancelled() {
                return Ok(AnonymousCallableIdentityRead::Cancelled { examined });
            }
            let (
                row_kind,
                subkind,
                ordinal,
                file,
                byte_start,
                byte_end,
                declaration_kind,
                variadic,
                arity,
            ) = row.map_err(|error| {
                CatalogError::sqlite("read anonymous callable identity child", error)
            })?;
            examined += 1;
            if examined > max_records {
                return Ok(AnonymousCallableIdentityRead::RecordBudgetExhausted { examined });
            }
            validate_source_path(&file)?;
            let ordinal = usize::try_from(ordinal).map_err(|error| {
                CatalogError::Integrity(format!("anonymous identity ordinal is invalid: {error}"))
            })?;
            match row_kind.as_str() {
                "anchor" => {
                    let anchor = SourceAnchor {
                        file,
                        byte_range: SourceByteRange {
                            start: usize::try_from(byte_start).map_err(|error| {
                                CatalogError::Integrity(format!(
                                    "anonymous identity start offset is invalid: {error}"
                                ))
                            })?,
                            end: usize::try_from(byte_end).map_err(|error| {
                                CatalogError::Integrity(format!(
                                    "anonymous identity end offset is invalid: {error}"
                                ))
                            })?,
                        },
                        kind: parse_source_declaration_kind(
                            declaration_kind.as_deref().ok_or_else(|| {
                                CatalogError::Integrity(
                                    "anonymous identity anchor has no declaration kind".to_owned(),
                                )
                            })?,
                        )?,
                    };
                    let destination = match subkind.as_str() {
                        "lexical_owner" => &mut lexical_owner_chain,
                        "signature_declaration" => &mut declaration_chain,
                        _ => {
                            return Err(CatalogError::Integrity(format!(
                                "unknown anonymous identity anchor chain {subkind:?}"
                            )));
                        }
                    };
                    if ordinal != destination.len() {
                        return Err(CatalogError::Integrity(format!(
                            "anonymous identity anchor ordinals are not contiguous: {subkind:?} {ordinal}"
                        )));
                    }
                    destination.push(anchor);
                }
                "shape" => {
                    let shape = SourceParameterShape {
                        type_node: SourceTypeNode {
                            file,
                            byte_range: SourceByteRange {
                                start: usize::try_from(byte_start).map_err(|error| {
                                    CatalogError::Integrity(format!(
                                        "anonymous signature start offset is invalid: {error}"
                                    ))
                                })?,
                                end: usize::try_from(byte_end).map_err(|error| {
                                    CatalogError::Integrity(format!(
                                        "anonymous signature end offset is invalid: {error}"
                                    ))
                                })?,
                            },
                        },
                        variadic: match variadic {
                            Some(0) => false,
                            Some(1) => true,
                            other => {
                                return Err(CatalogError::Integrity(format!(
                                    "invalid anonymous signature variadic flag: {other:?}"
                                )));
                            }
                        },
                        arity: usize::try_from(arity.ok_or_else(|| {
                            CatalogError::Integrity(
                                "anonymous signature shape has no arity".to_owned(),
                            )
                        })?)
                        .map_err(|error| {
                            CatalogError::Integrity(format!(
                                "anonymous signature arity is invalid: {error}"
                            ))
                        })?,
                    };
                    let destination = match subkind.as_str() {
                        "parameter" => &mut parameters,
                        "result" => &mut results,
                        _ => {
                            return Err(CatalogError::Integrity(format!(
                                "unknown anonymous signature shape kind {subkind:?}"
                            )));
                        }
                    };
                    if ordinal != destination.len() {
                        return Err(CatalogError::Integrity(format!(
                            "anonymous signature ordinals are not contiguous: {subkind:?} {ordinal}"
                        )));
                    }
                    destination.push(shape);
                }
                _ => {
                    return Err(CatalogError::Integrity(format!(
                        "unknown anonymous identity row kind {row_kind:?}"
                    )));
                }
            }
        }
    }
    Ok(AnonymousCallableIdentityRead::Found {
        identity: Box::new(AnonymousCallableIdentity {
            id: callable_id.to_owned(),
            artifact_sha256,
            package_identity: package_import_path,
            anchor: SourceAnchor {
                file: anchor_file,
                byte_range: SourceByteRange {
                    start: usize::try_from(anchor_start).map_err(|error| {
                        CatalogError::Integrity(format!(
                            "anonymous identity anchor start is invalid: {error}"
                        ))
                    })?,
                    end: usize::try_from(anchor_end).map_err(|error| {
                        CatalogError::Integrity(format!(
                            "anonymous identity anchor end is invalid: {error}"
                        ))
                    })?,
                },
                kind: SourceDeclarationKind::FunctionLiteral,
            },
            lexical_owner_chain,
            signature: SourceCallableShape {
                function_type: SourceTypeNode {
                    file: signature_file,
                    byte_range: SourceByteRange {
                        start: usize::try_from(signature_start).map_err(|error| {
                            CatalogError::Integrity(format!(
                                "anonymous signature start is invalid: {error}"
                            ))
                        })?,
                        end: usize::try_from(signature_end).map_err(|error| {
                            CatalogError::Integrity(format!(
                                "anonymous signature end is invalid: {error}"
                            ))
                        })?,
                    },
                },
                parameters,
                results,
                declaration_chain,
            },
        }),
        examined,
    })
}

#[doc(hidden)]
pub fn insert_selectors(
    transaction: &Transaction<'_>,
    manifest_digest: &str,
    shard_id: &str,
    selectors: &[ActivationSelector],
) -> Result<(), CatalogError> {
    transaction
        .execute(
            "DELETE FROM catalog_selectors
             WHERE manifest_digest = ?1 AND shard_id = ?2",
            params![manifest_digest, shard_id],
        )
        .map_err(|error| CatalogError::sqlite("replace catalog selectors", error))?;
    for (ordinal, selector) in selectors.iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO catalog_selectors(
                   manifest_digest, shard_id, selector_ordinal,
                   package_name, package_version, module_name, module_version,
                   toolchain_name, toolchain_version, artifact_sha256, selector_json
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    manifest_digest,
                    shard_id,
                    ordinal,
                    selector.package.as_ref().map(|value| value.name.as_str()),
                    selector
                        .package
                        .as_ref()
                        .and_then(|value| value.version.as_deref()),
                    selector.module.as_ref().map(|value| value.name.as_str()),
                    selector
                        .module
                        .as_ref()
                        .and_then(|value| value.version.as_deref()),
                    selector.toolchain.as_ref().map(|value| value.name.as_str()),
                    selector
                        .toolchain
                        .as_ref()
                        .and_then(|value| value.version.as_deref()),
                    selector.artifact_sha256.as_deref(),
                    serde_json::to_vec(selector)
                        .map_err(|error| CatalogError::Integrity(error.to_string()))?
                ],
            )
            .map_err(|error| CatalogError::sqlite("insert catalog selector", error))?;
        for target in &selector.targets {
            transaction
                .execute(
                    "INSERT INTO catalog_selector_targets(
                       manifest_digest, shard_id, selector_ordinal, target
                     ) VALUES(?1, ?2, ?3, ?4)",
                    params![manifest_digest, shard_id, ordinal, target],
                )
                .map_err(|error| CatalogError::sqlite("insert selector target", error))?;
        }
        for configuration in &selector.configurations {
            transaction
                .execute(
                    "INSERT INTO catalog_selector_configurations(
                       manifest_digest, shard_id, selector_ordinal, configuration
                     ) VALUES(?1, ?2, ?3, ?4)",
                    params![manifest_digest, shard_id, ordinal, configuration],
                )
                .map_err(|error| CatalogError::sqlite("insert selector configuration", error))?;
        }
    }
    Ok(())
}

#[doc(hidden)]
pub fn insert_routing_keys(
    transaction: &Transaction<'_>,
    manifest_digest: &str,
    shard_id: &str,
    routing_keys: &[String],
) -> Result<(), CatalogError> {
    transaction
        .execute(
            "DELETE FROM catalog_routing_keys
             WHERE manifest_digest = ?1 AND shard_id = ?2",
            params![manifest_digest, shard_id],
        )
        .map_err(|error| CatalogError::sqlite("replace routing keys", error))?;
    for routing_key in routing_keys {
        transaction
            .execute(
                "INSERT INTO catalog_routing_keys(
                   manifest_digest, shard_id, routing_key
                 ) VALUES(?1, ?2, ?3)",
                params![manifest_digest, shard_id, routing_key],
            )
            .map_err(|error| CatalogError::sqlite("insert routing key", error))?;
    }
    Ok(())
}

#[doc(hidden)]
pub fn manifest_compatible(
    manifest: &CompiledPackManifest,
    query: &SemanticPackSelectorQuery,
) -> Result<bool, CatalogError> {
    if !manifest
        .compatibility
        .matches_engine(manifest.schema_version, &query.bifrost_version)
        .map_err(|error| CatalogError::Integrity(error.to_string()))?
    {
        return Ok(false);
    }
    let Some(toolchain) = &query.toolchain else {
        return Ok(true);
    };
    for constraint in &manifest.compatibility.toolchains {
        if constraint.name != toolchain.name {
            continue;
        }
        let Some(version) = &toolchain.version else {
            return Ok(false);
        };
        let requirement = VersionReq::parse(&constraint.requirement)
            .map_err(|error| CatalogError::Integrity(error.to_string()))?;
        if !requirement.matches(version) {
            return Ok(false);
        }
    }
    Ok(true)
}

#[doc(hidden)]
pub fn selector_matches(
    selector: &ActivationSelector,
    query: &SemanticPackSelectorQuery,
) -> Result<bool, CatalogError> {
    if !coordinate_matches(selector.package.as_ref(), query.package.as_ref())?
        || !coordinate_matches(selector.module.as_ref(), query.module.as_ref())?
        || !coordinate_matches(selector.toolchain.as_ref(), query.toolchain.as_ref())?
    {
        return Ok(false);
    }
    if let Some(target) = &query.target
        && !selector.targets.is_empty()
        && !selector.targets.contains(target)
    {
        return Ok(false);
    }
    if let Some(configuration) = &query.configuration
        && !selector.configurations.is_empty()
        && !selector.configurations.contains(configuration)
    {
        return Ok(false);
    }
    if let (Some(expected), Some(actual)) = (&query.artifact_sha256, &selector.artifact_sha256)
        && actual != expected
    {
        return Ok(false);
    }
    Ok(true)
}

#[doc(hidden)]
pub fn query_has_exact_coordinate(query: &SemanticPackSelectorQuery) -> bool {
    [&query.package, &query.module, &query.toolchain]
        .into_iter()
        .flatten()
        .any(|coordinate| coordinate.version.is_some())
}

#[doc(hidden)]
pub fn selector_binds_exact_coordinate(
    selector: &ActivationSelector,
    query: &SemanticPackSelectorQuery,
) -> bool {
    [
        (&selector.package, &query.package),
        (&selector.module, &query.module),
        (&selector.toolchain, &query.toolchain),
    ]
    .into_iter()
    .any(|(selector, query)| {
        matches!(
            (selector, query),
            (Some(selector), Some(query))
                if selector.name == query.name
                    && selector.version.is_some()
                    && query.version.is_some()
        )
    })
}

fn coordinate_matches(
    selector: Option<&NameSelector>,
    query: Option<&CatalogCoordinate>,
) -> Result<bool, CatalogError> {
    match (selector, query) {
        (None, _) | (_, None) => Ok(true),
        (Some(selector), Some(query))
            if !crate::analyzer::semantic_model::runtime::strict_coordinate_names_match(
                Some(selector),
                Some(query),
            ) =>
        {
            Ok(false)
        }
        (Some(selector), Some(query)) => match (&selector.version, &query.version) {
            (None, _) => Ok(true),
            (Some(_), None) => Ok(false),
            (Some(requirement), Some(version)) => {
                crate::analyzer::semantic_model::runtime::coordinate_version_matches(
                    requirement,
                    version,
                )
                .map_err(|error| CatalogError::Integrity(error.to_string()))
            }
        },
    }
}

/// Classify one pack as a version near miss for `query`: every non-version
/// predicate accepts the query, and an exact version requirement rejects it.
/// A pack rejected for a non-version reason is not a near miss and returns
/// `None`.
#[doc(hidden)]
pub fn version_near_miss(
    manifest: &CompiledPackManifest,
    selectors: &[ActivationSelector],
    query: &SemanticPackSelectorQuery,
) -> Result<Option<SemanticPackVersionNearMiss>, CatalogError> {
    if !manifest
        .compatibility
        .matches_engine(manifest.schema_version, &query.bifrost_version)
        .map_err(|error| CatalogError::Integrity(error.to_string()))?
    {
        return Ok(None);
    }
    if let Some(toolchain) = &query.toolchain {
        for constraint in &manifest.compatibility.toolchains {
            if constraint.name != toolchain.name {
                continue;
            }
            let requirement = VersionReq::parse(&constraint.requirement)
                .map_err(|error| CatalogError::Integrity(error.to_string()))?;
            let satisfied = toolchain
                .version
                .as_ref()
                .is_some_and(|version| requirement.matches(version));
            if !satisfied {
                return Ok(Some(near_miss(
                    manifest,
                    format!("toolchain {}", constraint.name),
                    toolchain.version.as_ref(),
                    &constraint.requirement,
                )));
            }
        }
    }
    for selector in selectors {
        if !coordinate_names_match(selector.package.as_ref(), query.package.as_ref())
            || !coordinate_names_match(selector.module.as_ref(), query.module.as_ref())
            || !coordinate_names_match(selector.toolchain.as_ref(), query.toolchain.as_ref())
        {
            continue;
        }
        if let Some(target) = &query.target
            && !selector.targets.is_empty()
            && !selector.targets.contains(target)
        {
            continue;
        }
        if let Some(configuration) = &query.configuration
            && !selector.configurations.is_empty()
            && !selector.configurations.contains(configuration)
        {
            continue;
        }
        if let (Some(expected), Some(actual)) = (&query.artifact_sha256, &selector.artifact_sha256)
            && actual != expected
        {
            continue;
        }
        for (axis, coordinate_selector, coordinate_query) in [
            ("package", selector.package.as_ref(), query.package.as_ref()),
            ("module", selector.module.as_ref(), query.module.as_ref()),
            (
                "toolchain",
                selector.toolchain.as_ref(),
                query.toolchain.as_ref(),
            ),
        ] {
            let (Some(coordinate_selector), Some(coordinate_query)) =
                (coordinate_selector, coordinate_query)
            else {
                continue;
            };
            let Some(requirement_source) = &coordinate_selector.version else {
                continue;
            };
            let requirement = VersionReq::parse(requirement_source)
                .map_err(|error| CatalogError::Integrity(error.to_string()))?;
            let satisfied = coordinate_query
                .version
                .as_ref()
                .is_some_and(|version| requirement.matches(version));
            if !satisfied {
                return Ok(Some(near_miss(
                    manifest,
                    format!("{axis} {}", coordinate_selector.name),
                    coordinate_query.version.as_ref(),
                    requirement_source,
                )));
            }
        }
    }
    Ok(None)
}

#[doc(hidden)]
pub fn near_miss(
    manifest: &CompiledPackManifest,
    coordinate: String,
    installed: Option<&Version>,
    required: &str,
) -> SemanticPackVersionNearMiss {
    SemanticPackVersionNearMiss {
        pack_id: manifest.pack_id.clone(),
        pack_version: manifest.version.clone(),
        manifest_digest: manifest.content_sha256.clone(),
        coordinate,
        installed: installed.map(Version::to_string),
        required: required.to_owned(),
    }
}

/// The name half of `coordinate_matches`: whether the selector could apply to
/// the queried coordinate at some version.
fn coordinate_names_match(
    selector: Option<&NameSelector>,
    query: Option<&CatalogCoordinate>,
) -> bool {
    match (selector, query) {
        (None, _) | (_, None) => true,
        (Some(selector), Some(query)) => selector.name == query.name,
    }
}

#[doc(hidden)]
pub fn count(connection: &Connection, table: &str) -> Result<u64, CatalogError> {
    assert!(matches!(
        table,
        "catalog_objects" | "catalog_pack_shards" | "catalog_sources"
    ));
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .map_err(|error| CatalogError::sqlite("count catalog rows", error))
}

#[doc(hidden)]
pub fn lease_expiry(ttl: Duration) -> Result<i64, CatalogError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    lease_expiry_from(now, ttl)
}

#[doc(hidden)]
pub fn encoding_name(encoding: ArtifactEncoding) -> &'static str {
    match encoding {
        ArtifactEncoding::Raw => "raw",
        ArtifactEncoding::Deflate => "deflate",
    }
}

#[doc(hidden)]
pub fn payload_kind_name(kind: PayloadKind) -> &'static str {
    match kind {
        PayloadKind::DeclarationFacts => "declaration_facts",
        PayloadKind::GeneratorRules => "generator_rules",
        PayloadKind::ProcedureSummaries => "procedure_summaries",
    }
}

#[cfg(test)]
mod acquisition_receipt_tests {
    use brokk_bifrost_test_macros::hardwon;
    use std::fs;

    use semver::Version;
    use tempfile::TempDir;

    use crate::analyzer::semantic_model::catalog::AcquisitionReceiptRequest;

    use crate::analyzer::semantic_model::catalog::CatalogCoordinate;

    use crate::analyzer::semantic_model::catalog::GeneratedProductionKey;

    use crate::analyzer::semantic_model::catalog::SemanticPackSelectorQuery;

    use brokk_bifrost_core::analyzer::canonical_hash::lower_hex_string;

    use crate::analyzer::semantic_model::catalog::receipt_object_is_valid;

    fn generated_key() -> GeneratedProductionKey {
        GeneratedProductionKey::new(
            "a".repeat(64),
            "fixture-producer".to_owned(),
            "1.0.0".to_owned(),
            3,
        )
        .unwrap()
    }

    fn declared_query() -> SemanticPackSelectorQuery {
        SemanticPackSelectorQuery {
            language: "java".to_owned(),
            ecosystem: "maven".to_owned(),
            package: Some(CatalogCoordinate {
                name: "com.acme:widget".to_owned(),
                version: Some(Version::parse("1.0.0").unwrap()),
            }),
            module: None,
            toolchain: None,
            target: None,
            configuration: None,
            artifact_sha256: None,
            bifrost_version: Version::parse("0.8.17").unwrap(),
        }
    }

    #[test]
    #[hardwon("#3357: acquisition absence receipts could replay across different requests")]
    fn receipt_request_digest_binds_kind_coordinate_and_version() {
        let generated = AcquisitionReceiptRequest::generated(&generated_key()).digest();
        let declared = AcquisitionReceiptRequest::declared(&declared_query()).digest();
        assert_ne!(generated, declared);

        let mut changed = declared_query();
        changed.package.as_mut().unwrap().version = Some(Version::parse("1.1.0").unwrap());
        assert_ne!(
            declared,
            AcquisitionReceiptRequest::declared(&changed).digest()
        );
        let mut changed_flags = declared_query();
        changed_flags.target = Some("jvm".to_owned());
        assert_ne!(
            AcquisitionReceiptRequest::declared(&declared_query()).digest(),
            AcquisitionReceiptRequest::declared(&changed_flags).digest()
        );
    }

    #[test]
    #[hardwon("#3357: corrupt or missing receipt objects were accepted as valid")]
    fn receipt_object_validation_rejects_corruption_and_missing_files() {
        let root = TempDir::new().unwrap();
        let bytes = b"receipt-object";
        let digest = lower_hex_string(&brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(
            bytes,
        ));
        let relative = std::path::Path::new("objects/sha256")
            .join(&digest[..2])
            .join(&digest[2..]);
        fs::create_dir_all(root.path().join("objects/sha256").join(&digest[..2])).unwrap();
        fs::write(root.path().join(&relative), bytes).unwrap();
        assert!(
            receipt_object_is_valid(root.path(), &relative, &digest, bytes.len() as u64).unwrap()
        );

        fs::write(root.path().join(&relative), b"corrupt").unwrap();
        assert!(
            !receipt_object_is_valid(root.path(), &relative, &digest, bytes.len() as u64).unwrap()
        );
        fs::remove_file(root.path().join(&relative)).unwrap();
        assert!(
            !receipt_object_is_valid(root.path(), &relative, &digest, bytes.len() as u64).unwrap()
        );
    }
}

#[cfg(test)]
mod stored_manifest_memo_tests {}

/// Round the absolute lease deadline up to the catalog's whole-second clock.
///
/// Rounding the current time down and the TTL up lets a 500 ms lease acquired
/// at 0.99 s expire at the next second boundary, before its TTL elapsed. GC
/// compares `expires_at` against the same whole-second clock, so the deadline
/// must never round down below the requested duration (#5872).
fn lease_expiry_from(now: Duration, ttl: Duration) -> Result<i64, CatalogError> {
    if ttl.is_zero() {
        return Err(CatalogError::Integrity(
            "semantic-pack lease TTL must be positive".to_owned(),
        ));
    }
    let deadline = now.checked_add(ttl).ok_or_else(|| {
        CatalogError::Integrity("semantic-pack lease expiry overflowed".to_owned())
    })?;
    let seconds = i64::try_from(deadline.as_secs()).map_err(|_| {
        CatalogError::Integrity("semantic-pack lease expiry exceeds i64".to_owned())
    })?;
    seconds
        .checked_add(i64::from(deadline.subsec_nanos() != 0))
        .ok_or_else(|| CatalogError::Integrity("semantic-pack lease expiry overflowed".to_owned()))
}

#[cfg(test)]
mod lease_expiry_tests {
    use crate::analyzer::semantic_model::catalog::lease_expiry_from;
    use brokk_bifrost_test_macros::hardwon;
    use std::time::Duration;

    #[test]
    #[hardwon("#5872: a 500 ms lease acquired at 0.9995 s expired at the next whole second")]
    fn subsecond_lease_rounds_up_its_absolute_deadline_across_a_second_boundary() {
        let expires_at =
            lease_expiry_from(Duration::from_micros(999_500), Duration::from_millis(500)).unwrap();

        assert_eq!(expires_at, 2);
        assert!(
            expires_at > 1,
            "the first GC in second 1 must not expire the lease"
        );
    }
}
