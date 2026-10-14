mod db;
mod storage;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;
use uuid::Uuid;

use super::csmi::{
    CsmiCallableValuesModality, CsmiCallableValuesPayload, CsmiCallableValuesShape,
    CsmiCallableValuesTiming, CsmiCoverageStatus, CsmiInputLocation,
};
use super::model::{
    AnonymousCallableIdentity, CallableValuesCoverage, CallableValuesFact, CallableValuesFamily,
    CallableValuesPayload, SourceAnchor, SourceByteRange, SourceCallableShape,
    SourceDeclarationKind, SourceParameterShape, SourceTypeNode,
};
use super::validate::is_canonical_relative_path;
use super::{
    ActivationSelector, ArtifactEncoding, ArtifactProducerLimits, CompiledPackManifest,
    CompiledSemanticModelPack, CompiledShard, CompiledShardDescriptor, Completeness, DecodeLimits,
    ExactArtifact, NameSelector, PayloadKind, SEMANTIC_MODEL_SCHEMA_VERSION,
    SEMANTIC_MODEL_SUPPORTED_SCHEMA_VERSIONS, decode_manifest, decode_validated_shard_for_manifest,
    validate_manifest_inventory,
};
use crate::CancellationToken;
use crate::analyzer::canonical_hash::{CanonicalHasher, is_lower_sha256, lower_hex_string};
use crate::analyzer::semantic_model::GoPinnedPackage;
use crate::analyzer::store::{
    AnalyzerStore, SemanticPackActivationSourceKind, SemanticPackActiveReference,
    SemanticPackActiveSet,
};

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
/// 53: Kotlin native declarations retain named-only fixed parameters after a
/// positional vararg. Older generated signatures allow invalid positional tails.
/// 54: Scala source artifacts retain the exact declaration identity when a
/// repeated parameter list is followed by another list, while withholding only
/// the unrepresentable flat signature.
/// 55: the persisted Scala warning is declaration-scoped and keeps its source
/// location without becoming a file-level source entry. Old dual-subject
/// diagnostics cannot satisfy the release reject accounting contract.
/// 56: C++ grammar 0.24.3 retains the closing language-linkage guard around
/// header overloads. This combined epoch invalidates both earlier producers,
/// including version 55 entries made before the grammar upgrade.
/// 57: recoverable PHP source-syntax warnings retain their exact source entry,
/// changing extraction accounting and the gaps reported by warm productions.
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

fn default_semantic_pack_catalog_root_with_override(
    workspace_root: &Path,
    cache_root: Option<std::ffi::OsString>,
) -> PathBuf {
    cache_root
        .map(PathBuf::from)
        .unwrap_or_else(|| crate::gitblob::cache_dir_path(workspace_root))
        .join(format!("semantic-pack-catalog.v{CATALOG_SCHEMA_VERSION}"))
}

/// Open the generated default catalog after applying the shared cache
/// directory's creation and Git-ignore contract.
pub fn open_default_semantic_pack_catalog(
    workspace_root: &Path,
    options: CatalogOptions,
) -> Result<SemanticPackCatalog, CatalogError> {
    let catalog_root = default_semantic_pack_catalog_root(workspace_root);
    let cache_dir = crate::cache_db::prepare_cache_dir(
        catalog_root
            .parent()
            .expect("the default semantic-pack catalog has a cache parent"),
    )
    .map_err(CatalogError::Integrity)?;
    let directory_name = catalog_root
        .file_name()
        .expect("the default semantic-pack catalog has a directory name");
    let mut catalog = SemanticPackCatalog::open(
        &cache_dir.join(directory_name),
        CatalogOpenMode::ReadWrite,
        options,
    )?;
    // The local catalog owns workspace sources and activation state. Only
    // exact generated productions may cross into the host cache.
    if std::env::var_os(SEMANTIC_PACK_CACHE_ROOT_ENV).is_none_or(|value| value.is_empty()) {
        catalog.shared_generated_root = crate::gitblob::machine_cache_dir().map(|root| {
            root.join(format!(
                "generated-semantic-packs.v{CATALOG_SCHEMA_VERSION}"
            ))
        });
    }
    Ok(catalog)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurablePackSourceKind {
    Installed,
    Generated,
    PreShipped,
    WorkspaceProduced,
}

impl DurablePackSourceKind {
    fn as_str(self) -> &'static str {
        CatalogPackSourceKind::from(self).as_str()
    }

    fn parse(value: &str) -> Result<Self, CatalogError> {
        parse_semantic_pack_activation_source_kind(value)
            .and_then(durable_activation_kind)
            .ok_or_else(|| {
                CatalogError::Integrity(format!("unknown catalog source kind {value:?}"))
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurablePackSource {
    pub kind: DurablePackSourceKind,
    pub source_id: String,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogPackSourceKind {
    Installed,
    Generated,
    PreShipped,
    WorkspaceProduced,
    Embedded,
    EphemeralWorkspace,
}

impl CatalogPackSourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Installed => "installed",
            Self::Generated => "generated",
            Self::PreShipped => "pre_shipped",
            Self::WorkspaceProduced => "workspace_produced",
            Self::Embedded => "embedded",
            Self::EphemeralWorkspace => "ephemeral_workspace",
        }
    }

    pub(crate) const fn precedence(self) -> u8 {
        match self {
            Self::Embedded => 0,
            Self::PreShipped => 1,
            Self::Installed => 2,
            Self::Generated => 3,
            Self::WorkspaceProduced => 4,
            Self::EphemeralWorkspace => 5,
        }
    }

    fn parse(value: &str) -> Result<Self, CatalogError> {
        parse_semantic_pack_activation_source_kind(value)
            .map(activation_catalog_kind)
            .ok_or_else(|| {
                CatalogError::Integrity(format!("unknown catalog source kind {value:?}"))
            })
    }
}

impl From<DurablePackSourceKind> for CatalogPackSourceKind {
    fn from(value: DurablePackSourceKind) -> Self {
        match value {
            DurablePackSourceKind::Installed => Self::Installed,
            DurablePackSourceKind::Generated => Self::Generated,
            DurablePackSourceKind::PreShipped => Self::PreShipped,
            DurablePackSourceKind::WorkspaceProduced => Self::WorkspaceProduced,
        }
    }
}

impl From<SessionPackSourceKind> for CatalogPackSourceKind {
    fn from(value: SessionPackSourceKind) -> Self {
        match value {
            SessionPackSourceKind::Embedded => Self::Embedded,
            SessionPackSourceKind::EphemeralWorkspace => Self::EphemeralWorkspace,
        }
    }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogCandidate {
    manifest_digest: String,
    shard_id: String,
    descriptor: CompiledShardDescriptor,
    completeness: Completeness,
    source_kind: CatalogPackSourceKind,
    source_id: String,
    location: CatalogCandidateLocation,
}

impl CatalogCandidate {
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    pub fn shard_id(&self) -> &str {
        &self.shard_id
    }

    pub fn descriptor(&self) -> &CompiledShardDescriptor {
        &self.descriptor
    }

    pub fn completeness(&self) -> Completeness {
        self.completeness
    }

    pub fn source_kind(&self) -> CatalogPackSourceKind {
        self.source_kind
    }

    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    pub(crate) fn activation_receipt_location(&self) -> ActivationReceiptCandidateLocation {
        match &self.location {
            CatalogCandidateLocation::Durable => ActivationReceiptCandidateLocation::Durable,
            CatalogCandidateLocation::Session {
                pack_ordinal,
                shard_ordinal,
            } => ActivationReceiptCandidateLocation::Session {
                pack_ordinal: *pack_ordinal,
                shard_ordinal: *shard_ordinal,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum ActivationReceiptCandidateLocation {
    Durable,
    Session {
        pack_ordinal: usize,
        shard_ordinal: usize,
    },
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
    RecordBudgetExhausted { max_records: usize },
    UnsupportedProjection(super::csmi::CsmiCallableValuesUnsupportedProjection),
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

/// A cloneable SQL-only bridge for active runtime publication.
///
/// The reader owns fixed database handles and, for an ephemeral catalog, the
/// root keepalive needed by SQLite. It never retains a catalog borrow or a
/// workspace-sized source index.
#[derive(Clone)]
pub struct CatalogRuntimeSourceReader {
    durable_connection: Arc<Mutex<Connection>>,
    session_callable_values: Arc<Mutex<Option<SessionCallableValuesCatalog>>>,
    _ephemeral_root: Option<Arc<TempDir>>,
}

impl fmt::Debug for CatalogRuntimeSourceReader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CatalogRuntimeSourceReader")
            .finish_non_exhaustive()
    }
}

impl CatalogRuntimeSourceReader {
    pub fn query_callable_values(
        &self,
        query: &CatalogCallableValuesQuery<'_>,
        limits: CatalogCallableValuesQueryLimits,
        cancellation: &CancellationToken,
    ) -> Result<CatalogCallableValuesQueryResult, CatalogError> {
        let durable = self
            .durable_connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        if SemanticPackCatalog::callable_values_publication_present(
            &durable,
            query.manifest_digest,
            query.shard_id,
        )? {
            return SemanticPackCatalog::query_callable_values_on_connection(
                &durable,
                query,
                limits,
                cancellation,
            );
        }
        drop(durable);

        let session = self
            .session_callable_values
            .lock()
            .expect("session callable-values connection mutex poisoned");
        let Some(session) = session.as_ref() else {
            return Ok(SemanticPackCatalog::callable_values_index_missing_result(
                limits,
            ));
        };
        if SemanticPackCatalog::callable_values_publication_present(
            &session.connection,
            query.manifest_digest,
            query.shard_id,
        )? {
            return SemanticPackCatalog::query_callable_values_on_connection(
                &session.connection,
                query,
                limits,
                cancellation,
            );
        }
        Ok(SemanticPackCatalog::callable_values_index_missing_result(
            limits,
        ))
    }

    pub fn read_go_source(
        &self,
        request: &CatalogGoSourceRequest<'_>,
        limits: CatalogGoSourceReadLimits,
        cancellation: &CancellationToken,
    ) -> Result<Option<CatalogExactGoSourceSet>, CatalogError> {
        let durable = self
            .durable_connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        if let Some(source) = SemanticPackCatalog::read_go_source_from_connection(
            &durable,
            request,
            limits,
            cancellation,
        )? {
            return Ok(Some(source));
        }
        drop(durable);

        let session = self
            .session_callable_values
            .lock()
            .expect("session callable-values connection mutex poisoned");
        let Some(session) = session.as_ref() else {
            return Ok(None);
        };
        SemanticPackCatalog::read_go_source_from_connection(
            &session.connection,
            request,
            limits,
            cancellation,
        )
    }
}

#[derive(Debug)]
pub struct LoadedCatalogShard {
    /// Shared with the catalog's decoded-manifest memo and with every other
    /// shard of the same pack (#3101).
    pub manifest: Arc<CompiledPackManifest>,
    pub shard: CompiledShard,
    pub source_kind: CatalogPackSourceKind,
    pub source_id: String,
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
const ACQUISITION_SOURCE_STATE_DOMAIN: &[u8] = b"bifrost.semantic-pack.acquisition-sources.v1";

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquisitionReceiptSource {
    release_digest: String,
    manifest_digest: String,
    source: DurablePackSource,
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
    production_digest: String,
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
pub(crate) struct GeneratedProductionLock {
    file: File,
}

impl GeneratedProductionLock {
    pub(crate) fn try_acquire(&self) -> Result<bool, CatalogError> {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogAccounting {
    pub installed_stored_bytes: u64,
    pub active_stored_bytes: u64,
    pub object_count: u64,
    pub logical_shard_count: u64,
    pub active_shard_count: u64,
    pub source_count: u64,
    pub lookup_hits: u64,
    pub lookup_misses: u64,
    pub quarantined_pack_count: u64,
    pub activations: Vec<ActivationSourceCount>,
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
    pub producer: super::Producer,
    pub language: String,
    pub ecosystem: String,
    pub provenance: super::Provenance,
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

fn inventory_pack(manifest: &CompiledPackManifest, state: String) -> CatalogPackInventory {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationSourceCount {
    pub source_kind: CatalogPackSourceKind,
    pub source_id: String,
    pub pack_count: u64,
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

pub struct CatalogLease<'a> {
    catalog: &'a SemanticPackCatalog,
    lease_id: String,
    released: bool,
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
struct DurableSelectorRow {
    manifest_digest: String,
    shard_id: String,
    descriptor_json: Vec<u8>,
    selector_json: Vec<u8>,
    source_kind: String,
    source_id: String,
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
    fn io(operation: &'static str, source: std::io::Error) -> Self {
        Self::Io { operation, source }
    }

    fn sqlite(operation: &'static str, source: rusqlite::Error) -> Self {
        Self::Sqlite { operation, source }
    }
}

impl From<crate::sqlite_template::TemplateIoError> for CatalogError {
    fn from(error: crate::sqlite_template::TemplateIoError) -> Self {
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

pub struct SemanticPackCatalog {
    // Field order is deliberate: all SQLite/session state must drop before an
    // owned ephemeral root is deleted, including on Windows.
    root: PathBuf,
    mode: CatalogOpenMode,
    options: CatalogOptions,
    // Session packs and SQLite data-version counters belong to one opened
    // catalog. Equal counters in another catalog do not identify its content.
    instance_identity: u64,
    connection: Arc<Mutex<Connection>>,
    session_callable_values: Arc<Mutex<Option<SessionCallableValuesCatalog>>>,
    session_packs: Mutex<Vec<SessionPack>>,
    session_activations: Mutex<HashMap<String, SessionActivation>>,
    rejected_manifests: Mutex<HashSet<String>>,
    decoded_manifests: Mutex<DecodedManifestMemo>,
    verified_manifest_inventories: Mutex<HashSet<String>>,
    validated_python_profile_packs: Mutex<HashSet<String>>,
    manifest_decodes: AtomicU64,
    manifest_inventory_validations: AtomicU64,
    shard_validations: AtomicU64,
    lookup_hits: AtomicU64,
    lookup_misses: AtomicU64,
    sql_statements: AtomicU64,
    object_reads: AtomicU64,
    mutation_generation: AtomicU64,
    shared_generated_root: Option<PathBuf>,
    // The opened host catalog at `shared_generated_root`. A read-write open
    // reconciles every stored object, and each dependency lookup that missed
    // locally used to pay it: 433 opens and about 4 s per warm start of an npm
    // workspace (#3748). A failed open is not kept, so the next use retries.
    shared_generated: OnceLock<Box<SemanticPackCatalog>>,
    _ephemeral_root: Option<Arc<TempDir>>,
}

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
struct DecodedManifestMemo {
    entries: HashMap<String, Arc<CompiledPackManifest>>,
    bytes: usize,
}

/// Canonical manifest bytes the memo retains before it starts over.
///
/// Manifests of one pack are adjacent in every ordered reader, so a restart
/// costs one decode per distinct manifest, never one per row. The bound keeps a
/// catalog that serves many packs from retaining unbounded decoded state.
const DECODED_MANIFEST_MEMO_BYTES: usize = 32 * 1024 * 1024;

// Increment when artifact semantic validation or normalization changes. A
// certificate proves those checks for exact bytes under exact decode limits;
// it never replaces the stored/content digest checks on each load.
// 7: callable families may be complete when their final declaration formal is
// variadic, and schema-14 summary formal shapes receive directional validation.
// 8: schema-16 exact return-class claims receive callable-result validation.
// 9: schema-16 exact return-class sets receive non-empty nominal-set validation.
// 10: distinguish a named positional-vararg slot from a keyword collector,
// matching the formal-layout interpreter while rejecting positional fixed tails.
const SHARD_VALIDATION_VERSION: u32 = 10;

fn decode_limits_digest(limits: &DecodeLimits) -> String {
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

const SHARED_PRODUCTION_PRESENT_SQL: &str = "SELECT EXISTS(
    SELECT 1 FROM catalog_verified_generated_productions WHERE production_digest = ?1)";

const CERTIFIED_SHARD_SQL: &str = "SELECT EXISTS(
    SELECT 1 FROM catalog_shard_validations
    WHERE manifest_digest = ?1 AND shard_id = ?2
      AND validation_version = ?3 AND limits_sha256 = ?4)";

const CALLABLE_VALUES_RETURNED_SQL: &str = "SELECT fact.fact_ordinal,
       fact.result_ordinal, fact.target, fact.provenance_json
FROM catalog_callable_value_facts AS fact
JOIN catalog_packs AS pack ON pack.manifest_digest = fact.manifest_digest
WHERE pack.state = 'verified'
  AND fact.manifest_digest = ?1 AND fact.shard_id = ?2
  AND fact.family = 'returned-callables' AND fact.callable = ?3
  AND fact.result_ordinal = ?4
ORDER BY fact.fact_ordinal
LIMIT ?5";

const CALLABLE_VALUES_CALLBACK_SQL: &str = "SELECT fact.fact_ordinal,
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

const CALLABLE_VALUES_COVERAGE_SQL: &str = "SELECT coverage.coverage_ordinal,
       coverage.family, coverage.status, coverage.limitations_json,
       coverage.provenance_json
FROM catalog_callable_value_coverage AS coverage
JOIN catalog_packs AS pack ON pack.manifest_digest = coverage.manifest_digest
WHERE pack.state = 'verified'
  AND coverage.manifest_digest = ?1 AND coverage.shard_id = ?2
  AND coverage.family = ?3 AND coverage.callable = ?4
ORDER BY coverage.coverage_ordinal
LIMIT ?5";

const ANONYMOUS_CALLABLE_IDENTITY_SQL: &str = "SELECT identity.artifact_sha256,
       identity.package_import_path, identity.anchor_file, identity.anchor_start,
       identity.anchor_end, identity.signature_file, identity.signature_start,
       identity.signature_end
FROM catalog_anonymous_callable_identities AS identity
JOIN catalog_packs AS pack ON pack.manifest_digest = identity.manifest_digest
WHERE pack.state = 'verified' AND identity.manifest_digest = ?1
  AND identity.shard_id = ?2 AND identity.callable_id = ?3";

const ANONYMOUS_CALLABLE_IDENTITY_ANCHORS_SQL: &str = "SELECT 'anchor' AS row_kind,
       chain_kind AS subkind, ordinal, file, byte_start, byte_end,
       declaration_kind, NULL AS variadic, NULL AS arity
FROM catalog_anonymous_callable_identity_anchors
WHERE manifest_digest = ?1 AND shard_id = ?2 AND callable_id = ?3
ORDER BY chain_kind, ordinal
LIMIT ?4";

const ANONYMOUS_CALLABLE_IDENTITY_SHAPES_SQL: &str = "SELECT 'shape' AS row_kind,
       shape_kind AS subkind, ordinal, file, byte_start, byte_end,
       NULL AS declaration_kind, variadic, arity
FROM catalog_anonymous_callable_signature_shapes
WHERE manifest_digest = ?1 AND shard_id = ?2 AND callable_id = ?3
ORDER BY shape_kind, ordinal
LIMIT ?4";

fn record_shard_validation(
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
pub(crate) struct SemanticPackCatalogCacheIdentity {
    pub(crate) instance_identity: u64,
    pub(crate) mutation_generation: u64,
    pub(crate) sqlite_data_version: u64,
}

#[derive(Clone)]
struct ValidatedShard {
    descriptor: CompiledShardDescriptor,
    bytes: Vec<u8>,
    selectors: Vec<ActivationSelector>,
    callable_values: Option<CallableValuesPayload>,
}

enum CallableValuesIndexReadiness {
    Ready,
    Cancelled,
    Missing,
}

enum AnonymousCallableIdentityRead {
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

struct ValidatedPack {
    manifest: CompiledPackManifest,
    shards: Vec<ValidatedShard>,
}

struct SessionPack {
    manifest: Arc<CompiledPackManifest>,
    shards: Vec<ValidatedShard>,
    source: SessionPackSource,
}

struct SessionCallableValuesCatalog {
    // Field order closes the SQLite connection before TempDir removes its
    // database and any SQLite sidecars on Windows.
    connection: Connection,
    _root: TempDir,
}

enum CallableValuesQueryConnection<'a> {
    Durable(std::sync::MutexGuard<'a, Connection>),
    Session(std::sync::MutexGuard<'a, Option<SessionCallableValuesCatalog>>),
}

struct SessionActivation {
    active_set: SemanticPackActiveSet,
    owner: Weak<()>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CatalogCandidateLocation {
    Durable,
    Session {
        pack_ordinal: usize,
        shard_ordinal: usize,
    },
}

impl CatalogLease<'_> {
    pub fn renew(&mut self, ttl: Duration) -> Result<(), CatalogError> {
        let expires_at = lease_expiry(ttl)?;
        let connection = self
            .catalog
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let updated = connection
            .execute(
                "UPDATE catalog_leases SET expires_at = ?2 WHERE lease_id = ?1",
                params![&self.lease_id, expires_at],
            )
            .map_err(|error| CatalogError::sqlite("renew semantic-pack lease", error))?;
        if updated == 0 {
            return Err(CatalogError::Unavailable);
        }
        Ok(())
    }

    pub fn release(mut self) -> Result<(), CatalogError> {
        self.release_inner()
    }

    fn release_inner(&mut self) -> Result<(), CatalogError> {
        if self.released {
            return Ok(());
        }
        let connection = self
            .catalog
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        self.catalog.sql_statements.fetch_add(1, Ordering::Relaxed);
        connection
            .execute(
                "DELETE FROM catalog_leases WHERE lease_id = ?1",
                [&self.lease_id],
            )
            .map_err(|error| CatalogError::sqlite("release semantic-pack lease", error))?;
        self.released = true;
        Ok(())
    }
}

impl Drop for CatalogLease<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.release_inner() {
            eprintln!(
                "failed to release semantic-pack lease {}: {error}",
                self.lease_id
            );
        }
    }
}

impl SemanticPackCatalog {
    pub fn open(
        root: &Path,
        mode: CatalogOpenMode,
        options: CatalogOptions,
    ) -> Result<Self, CatalogError> {
        if mode == CatalogOpenMode::ReadOnly && !root.exists() {
            return Err(CatalogError::Integrity(
                "read-only semantic-pack catalog root does not exist".to_owned(),
            ));
        }
        let root = {
            let _scope = crate::profiling::scope("semantic_pack.catalog.prepare_root");
            match mode {
                CatalogOpenMode::ReadWrite => storage::prepare_root(root)?,
                CatalogOpenMode::ReadOnly => storage::open_read_only_root(root)?,
            }
        };
        // SQLite can leave every concurrent first opener in SQLITE_PROTOCOL
        // while they independently negotiate WAL locking on Windows. Elect
        // one initializer through schema migration and storage reconciliation;
        // normal catalog work remains concurrent after this lock is dropped.
        let initialization_lock = {
            let _scope = crate::profiling::scope("semantic_pack.catalog.initialization_lock");
            if mode == CatalogOpenMode::ReadWrite {
                Some(storage::acquire_initialization_lock(&root)?)
            } else {
                None
            }
        };
        let mut connection = {
            let _scope = crate::profiling::scope("semantic_pack.catalog.db_open");
            db::open(&root, mode)?
        };
        if mode == CatalogOpenMode::ReadWrite {
            let _scope = crate::profiling::scope("semantic_pack.catalog.reconcile_storage");
            reconcile_storage(&root, &mut connection)?;
        }
        drop(initialization_lock);
        static NEXT_CATALOG_INSTANCE: AtomicU64 = AtomicU64::new(1);
        let instance_identity = NEXT_CATALOG_INSTANCE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .expect("semantic-pack catalog instance identity space exhausted");
        Ok(Self {
            root,
            mode,
            options,
            instance_identity,
            connection: Arc::new(Mutex::new(connection)),
            session_callable_values: Arc::new(Mutex::new(None)),
            session_packs: Mutex::new(Vec::new()),
            session_activations: Mutex::new(HashMap::new()),
            rejected_manifests: Mutex::new(HashSet::new()),
            decoded_manifests: Mutex::new(DecodedManifestMemo {
                entries: HashMap::new(),
                bytes: 0,
            }),
            verified_manifest_inventories: Mutex::new(HashSet::new()),
            validated_python_profile_packs: Mutex::new(HashSet::new()),
            manifest_decodes: AtomicU64::new(0),
            manifest_inventory_validations: AtomicU64::new(0),
            shard_validations: AtomicU64::new(0),
            lookup_hits: AtomicU64::new(0),
            lookup_misses: AtomicU64::new(0),
            sql_statements: AtomicU64::new(0),
            object_reads: AtomicU64::new(0),
            mutation_generation: AtomicU64::new(0),
            shared_generated_root: None,
            shared_generated: OnceLock::new(),
            _ephemeral_root: None,
        })
    }

    pub fn open_ephemeral(options: CatalogOptions) -> Result<Self, CatalogError> {
        let root = tempfile::Builder::new()
            .prefix("bifrost-semantic-pack-catalog-")
            .tempdir()
            .map_err(|error| CatalogError::io("create ephemeral catalog root", error))?;
        let mut catalog = Self::open(root.path(), CatalogOpenMode::ReadWrite, options)?;
        catalog._ephemeral_root = Some(Arc::new(root));
        Ok(catalog)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn runtime_source_reader(&self) -> CatalogRuntimeSourceReader {
        CatalogRuntimeSourceReader {
            durable_connection: Arc::clone(&self.connection),
            session_callable_values: Arc::clone(&self.session_callable_values),
            _ephemeral_root: self._ephemeral_root.as_ref().map(Arc::clone),
        }
    }

    fn shared_generated_catalog(&self) -> Option<&Self> {
        let root = self.shared_generated_root.as_ref()?;
        if let Some(catalog) = self.shared_generated.get() {
            return Some(catalog);
        }
        match Self::open(root, CatalogOpenMode::ReadWrite, self.options.clone()) {
            // A concurrent first use may have stored its own open; keep that one.
            Ok(catalog) => Some(self.shared_generated.get_or_init(|| Box::new(catalog))),
            Err(error) => {
                eprintln!(
                    "shared generated cache {root:?} is unavailable; using the workspace catalog: {error}"
                );
                None
            }
        }
    }

    // Publication is optional: a verified local production remains usable if
    // the additional host copy cannot be written. Retry on the next local hit.
    fn retain_shared_generated(&self, production: &GeneratedProduction) {
        let Some(shared) = self.shared_generated_catalog() else {
            return;
        };
        let retained = (|| -> Result<(), CatalogError> {
            if shared.has_verified_generated_production(&production.key)? {
                let connection = shared
                    .connection
                    .lock()
                    .expect("semantic-pack catalog connection mutex poisoned");
                connection
                    .execute(
                        "UPDATE catalog_packs SET last_used_at = ?2
                     WHERE manifest_digest = ?1 AND COALESCE(last_used_at, 0) < ?2 - 60",
                        params![
                            production.manifest_digest,
                            crate::cache_db::now_unix_seconds()
                        ],
                    )
                    .map_err(|error| CatalogError::sqlite("touch shared production", error))?;
            } else {
                shared.copy_generated_from(self, production)?;
                // Only publication pays for bounded cleanup. Active imports
                // hold leases; recent host hits refresh the age above.
                shared.garbage_collect(&CatalogGcOptions::default())?;
            }
            Ok(())
        })();
        if let Err(error) = retained {
            eprintln!(
                "could not retain shared generated production {}; the workspace copy remains available and publication will be retried: {error}",
                production.key.production_digest()
            );
        }
    }

    fn has_verified_generated_production(
        &self,
        key: &GeneratedProductionKey,
    ) -> Result<bool, CatalogError> {
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        connection
            .query_row(
                SHARED_PRODUCTION_PRESENT_SQL,
                [key.production_digest()],
                |row| row.get(0),
            )
            .map_err(|error| CatalogError::sqlite("check shared production publication", error))
    }

    // One exact production is the transfer unit. Installed/workspace sources,
    // activation history, pins and configuration never cross this boundary.
    fn copy_generated_from(
        &self,
        source: &Self,
        production: &GeneratedProduction,
    ) -> Result<(), CatalogError> {
        let _scope = crate::profiling::scope("semantic_pack.copy_generated");
        let lease = source.lease(
            &production.manifest_digest,
            "generated-transfer",
            Duration::from_secs(300),
        )?;
        let manifest = source.stored_manifest(&production.manifest_digest)?;
        validate_generated_pack_identity(&production.key, &manifest)?;
        let manifest_bytes = {
            let connection = source
                .connection
                .lock()
                .expect("semantic-pack catalog connection mutex poisoned");
            stored_manifest_bytes_on(&connection, &production.manifest_digest)?
                .ok_or(CatalogError::Unavailable)?
        };
        let mut shards = Vec::with_capacity(manifest.shards.len());
        for descriptor in &manifest.shards {
            let relative = storage::relative_object_path(&descriptor.stored_sha256);
            let bytes = storage::read(
                source.root(),
                &relative.to_string_lossy(),
                &descriptor.stored_sha256,
                descriptor.stored_size,
            )?;
            shards.push(super::CompiledShardArtifact {
                descriptor: descriptor.clone(),
                bytes,
            });
        }
        let pack = CompiledSemanticModelPack {
            manifest: (*manifest).clone(),
            manifest_bytes,
            shards,
        };
        let extraction = source.extraction_accounting(&production.manifest_digest)?;
        if let Some(extraction) = &extraction {
            validate_extraction_accounting(extraction)?;
        }
        self.install_with(
            &pack,
            &DurablePackSource {
                kind: DurablePackSourceKind::Generated,
                source_id: production.key.source_id(),
            },
            |transaction, manifest, now| {
                insert_generated_production(transaction, &production.key, manifest, now)?;
                if let Some(extraction) = &extraction {
                    insert_extraction_accounting(
                        transaction,
                        &manifest.content_sha256,
                        extraction,
                    )?;
                }
                Ok(())
            },
        )?;
        source
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned")
            .execute(
                "UPDATE catalog_packs SET last_used_at = ?2 WHERE manifest_digest = ?1",
                params![
                    production.manifest_digest,
                    crate::cache_db::now_unix_seconds()
                ],
            )
            .map_err(|error| CatalogError::sqlite("touch imported production", error))?;
        lease.release()?;
        Ok(())
    }

    pub(crate) fn generated_production_lock(
        &self,
        key: &GeneratedProductionKey,
    ) -> Result<GeneratedProductionLock, CatalogError> {
        self.require_writable()?;
        let shared = self.shared_generated_catalog();
        let lock_root = shared.map_or(self.root(), Self::root);
        let file = storage::open_generated_production_lock(lock_root, key.production_digest())?;
        Ok(GeneratedProductionLock { file })
    }

    /// Return the number of production catalog SQL statements issued by this instance.
    ///
    /// Semantic-pack lifecycle measurement uses differences between two snapshots.
    /// In-memory matcher and overlay operations do not hold a catalog reference, so
    /// their expected difference is always zero.
    pub fn sql_statement_count(&self) -> u64 {
        self.sql_statements.load(Ordering::Relaxed)
    }

    /// Return the number of catalog object files this instance has read.
    ///
    /// A cached generated-pack lookup must not read shard objects (#2875).
    /// Tests pin that with the difference between two snapshots.
    /// Full semantic shard validations on cache reads, excluding hydration.
    pub fn shard_validation_count(&self) -> u64 {
        self.shard_validations.load(Ordering::Relaxed)
    }

    pub fn object_read_count(&self) -> u64 {
        self.object_reads.load(Ordering::Relaxed)
    }

    /// Return the number of stored-manifest decodes this instance performed.
    ///
    /// A memo hit is not a decode. Selection, near-miss attribution, and shard
    /// loading all read the same stored manifests, so this count is the pin
    /// that each distinct manifest is deserialized once per catalog (#3101).
    pub fn manifest_decode_count(&self) -> u64 {
        self.manifest_decodes.load(Ordering::Relaxed)
    }

    /// Return the number of whole-manifest inventory validations this instance
    /// performed.
    ///
    /// A memo hit is not a validation. Decoding one shard at a time used to
    /// revalidate every record id of the manifest per shard (#3101).
    pub fn manifest_inventory_validation_count(&self) -> u64 {
        self.manifest_inventory_validations.load(Ordering::Relaxed)
    }

    /// Validate one stored manifest's inventory at most once per catalog.
    fn validated_manifest_inventory(
        &self,
        manifest: &CompiledPackManifest,
    ) -> Result<(), CatalogError> {
        let digest = &manifest.content_sha256;
        if self
            .verified_manifest_inventories
            .lock()
            .expect("semantic-pack inventory mutex poisoned")
            .contains(digest)
        {
            return Ok(());
        }
        validate_manifest_inventory(manifest)
            .map_err(|error| CatalogError::Artifact(error.to_string()))?;
        self.manifest_inventory_validations
            .fetch_add(1, Ordering::Relaxed);
        self.verified_manifest_inventories
            .lock()
            .expect("semantic-pack inventory mutex poisoned")
            .insert(digest.clone());
        Ok(())
    }

    /// Decode one shard of a stored manifest after one inventory validation.
    fn decode_stored_shard(
        &self,
        manifest: &CompiledPackManifest,
        descriptor: &CompiledShardDescriptor,
        bytes: &[u8],
    ) -> Result<CompiledShard, CatalogError> {
        self.validated_manifest_inventory(manifest)?;
        self.shard_validations.fetch_add(1, Ordering::Relaxed);
        decode_validated_shard_for_manifest(
            manifest,
            descriptor,
            bytes,
            &self.options.decode_limits,
        )
        .map_err(|error| CatalogError::Artifact(error.to_string()))
    }

    /// A verified row may predate the Python profile evidence check. Recheck
    /// every stored shard once per opened catalog before the first PyPI load;
    /// the manifest digest and content-addressed objects bind later loads to
    /// the exact pack that passed this check.
    fn validate_stored_python_profile_pack(
        &self,
        manifest: &CompiledPackManifest,
    ) -> Result<(), CatalogError> {
        if manifest.language != "python"
            || !manifest.shards.iter().any(|descriptor| {
                descriptor
                    .routing_keys
                    .iter()
                    .any(|key| key.starts_with("package:pkg:pypi/"))
            })
        {
            return Ok(());
        }
        let mut checked = self
            .validated_python_profile_packs
            .lock()
            .expect("Python profile validation mutex poisoned");
        if checked.contains(&manifest.content_sha256) {
            return Ok(());
        }
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let mut decoded = Vec::with_capacity(manifest.shards.len());
        for descriptor in &manifest.shards {
            self.sql_statements.fetch_add(1, Ordering::Relaxed);
            let (relative_path, stored_size) = connection
                .query_row(
                    "SELECT o.relative_path, o.stored_size
                     FROM catalog_packs AS p
                     JOIN catalog_pack_shards AS ps
                       ON ps.manifest_digest = p.manifest_digest
                     JOIN catalog_objects AS o
                       ON o.stored_digest = ps.stored_digest
                     WHERE p.state = 'verified'
                       AND p.manifest_digest = ?1
                       AND ps.shard_id = ?2
                       AND ps.stored_digest = ?3",
                    params![
                        &manifest.content_sha256,
                        &descriptor.shard_id,
                        &descriptor.stored_sha256
                    ],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?)),
                )
                .optional()
                .map_err(|error| CatalogError::sqlite("load Python profile shard", error))?
                .ok_or(CatalogError::Unavailable)?;
            self.object_reads.fetch_add(1, Ordering::Relaxed);
            let bytes = storage::read(
                &self.root,
                &relative_path,
                &descriptor.stored_sha256,
                stored_size,
            )?;
            decoded.push(self.decode_stored_shard(manifest, descriptor, &bytes)?);
        }
        let authored = super::artifact::authored_pack_from_decoded_shards(manifest, &decoded);
        let diagnostics = super::validate::validate_csmi_profile_evidence(&authored);
        if !diagnostics.is_empty() {
            return Err(CatalogError::Integrity(format!(
                "stored Python pack has inconsistent full-pack evidence: {diagnostics:?}"
            )));
        }
        checked.insert(manifest.content_sha256.clone());
        Ok(())
    }

    /// Decode one stored manifest, reusing the decode of an equal digest.
    ///
    /// Callers read stored manifests by digest, so the memo is keyed by that
    /// digest and the decode re-proves it: a value the cache returns for a key
    /// is the value a miss would decode for the same key.
    fn decoded_manifest(
        &self,
        manifest_digest: &str,
        manifest_bytes: &[u8],
    ) -> Result<Arc<CompiledPackManifest>, CatalogError> {
        if let Some(manifest) = self.memoized_manifest(manifest_digest) {
            return Ok(manifest);
        }
        let manifest = Arc::new(
            decode_manifest(manifest_bytes, &self.options.decode_limits)
                .map_err(|error| CatalogError::Artifact(error.to_string()))?,
        );
        if manifest.content_sha256 != manifest_digest {
            return Err(CatalogError::Integrity(
                "catalog manifest key does not match decoded manifest".to_owned(),
            ));
        }
        self.manifest_decodes.fetch_add(1, Ordering::Relaxed);
        let mut memo = self
            .decoded_manifests
            .lock()
            .expect("semantic-pack manifest memo mutex poisoned");
        if memo.bytes.saturating_add(manifest_bytes.len()) > DECODED_MANIFEST_MEMO_BYTES {
            memo.entries.clear();
            memo.bytes = 0;
        }
        memo.bytes = memo.bytes.saturating_add(manifest_bytes.len());
        memo.entries
            .insert(manifest_digest.to_owned(), Arc::clone(&manifest));
        Ok(manifest)
    }

    /// The memoized decode of one stored manifest, when this catalog has it.
    fn memoized_manifest(&self, manifest_digest: &str) -> Option<Arc<CompiledPackManifest>> {
        self.decoded_manifests
            .lock()
            .expect("semantic-pack manifest memo mutex poisoned")
            .entries
            .get(manifest_digest)
            .map(Arc::clone)
    }

    /// Decode one stored manifest, reading its bytes only on a memo miss.
    ///
    /// Candidate selection visits one row per (shard, selector), so a reader
    /// that pulled `manifest_bytes` per row moved the same multi-megabyte blob
    /// out of SQLite dozens of times per pack (#3101). The memo makes the read
    /// and the decode happen once per distinct digest.
    fn stored_manifest(
        &self,
        manifest_digest: &str,
    ) -> Result<Arc<CompiledPackManifest>, CatalogError> {
        if let Some(manifest) = self.memoized_manifest(manifest_digest) {
            return Ok(manifest);
        }
        let bytes = {
            let connection = self
                .connection
                .lock()
                .expect("semantic-pack catalog connection mutex poisoned");
            self.sql_statements.fetch_add(1, Ordering::Relaxed);
            stored_manifest_bytes_on(&connection, manifest_digest)?
                .ok_or(CatalogError::Unavailable)?
        };
        self.decoded_manifest(manifest_digest, &bytes)
    }

    pub fn inventory_bounded(&self, max_packs: usize) -> Result<CatalogInventory, CatalogError> {
        let row_limit = max_packs.saturating_add(1);
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let mut pack_statement = connection
            .prepare(
                "SELECT manifest_digest, manifest_bytes, state
                 FROM catalog_packs
                 ORDER BY pack_id, pack_version, manifest_digest
                 LIMIT ?1",
            )
            .map_err(|error| CatalogError::sqlite("prepare catalog inventory", error))?;
        let pack_rows = pack_statement
            .query_map([i64::try_from(row_limit).unwrap_or(i64::MAX)], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|error| CatalogError::sqlite("query catalog inventory", error))?;
        let mut packs = BTreeMap::new();
        let mut complete = true;
        for row in pack_rows {
            let (manifest_digest, manifest_bytes, state) =
                row.map_err(|error| CatalogError::sqlite("read catalog inventory", error))?;
            let manifest = self.decoded_manifest(&manifest_digest, &manifest_bytes)?;
            if packs.len() >= max_packs {
                complete = false;
                continue;
            }
            packs.insert(
                manifest.content_sha256.clone(),
                inventory_pack(&manifest, state),
            );
        }
        drop(pack_statement);

        let mut source_statement = connection
            .prepare(
                "SELECT manifest_digest, source_kind, source_id
                 FROM catalog_sources
                 ORDER BY manifest_digest, source_kind, source_id",
            )
            .map_err(|error| CatalogError::sqlite("prepare catalog inventory sources", error))?;
        let source_rows = source_statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|error| CatalogError::sqlite("query catalog inventory sources", error))?;
        for row in source_rows {
            let (manifest_digest, source_kind, source_id) =
                row.map_err(|error| CatalogError::sqlite("read catalog inventory source", error))?;
            if let Some(pack) = packs.get_mut(&manifest_digest) {
                let source_kind = DurablePackSourceKind::parse(&source_kind)?;
                pack.sources.push(CatalogPackInventorySource {
                    source_kind: CatalogPackSourceKind::from(source_kind).as_str().to_owned(),
                    source_id,
                });
            }
        }
        drop(source_statement);

        let mut activation_statement = connection
            .prepare(
                "SELECT scope_id, active_set_digest, manifest_digest, source_kind, source_id
                 FROM catalog_activations
                 ORDER BY manifest_digest, scope_id, source_kind, source_id",
            )
            .map_err(|error| {
                CatalogError::sqlite("prepare catalog inventory activations", error)
            })?;
        let activation_rows = activation_statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(|error| CatalogError::sqlite("query catalog inventory activations", error))?;
        for row in activation_rows {
            let (scope_id, active_set_digest, manifest_digest, source_kind, source_id) = row
                .map_err(|error| {
                    CatalogError::sqlite("read catalog inventory activation", error)
                })?;
            if let Some(pack) = packs.get_mut(&manifest_digest) {
                let source_kind = DurablePackSourceKind::parse(&source_kind)?;
                pack.catalog_activations
                    .push(CatalogPackInventoryActivation {
                        scope_id,
                        active_set_digest,
                        source_kind: CatalogPackSourceKind::from(source_kind).as_str().to_owned(),
                        source_id,
                    });
            }
        }
        drop(activation_statement);
        drop(connection);

        for (manifest_digest, pack) in &mut packs {
            pack.extraction = self.extraction_accounting(manifest_digest)?;
        }

        let session_packs = self
            .session_packs
            .lock()
            .expect("semantic-pack session mutex poisoned");
        for session in session_packs.iter() {
            let digest = session.manifest.content_sha256.clone();
            if !packs.contains_key(&digest) && packs.len() >= max_packs {
                complete = false;
                continue;
            }
            let pack = packs
                .entry(digest)
                .or_insert_with(|| inventory_pack(&session.manifest, "session".to_owned()));
            let source = CatalogPackInventorySource {
                source_kind: CatalogPackSourceKind::from(session.source.kind)
                    .as_str()
                    .to_owned(),
                source_id: session.source.source_id.clone(),
            };
            if !pack.sources.contains(&source) {
                pack.sources.push(source);
            }
        }
        drop(session_packs);

        let mut session_activations = self
            .session_activations
            .lock()
            .expect("semantic-pack session activation mutex poisoned");
        session_activations.retain(|_, activation| activation.owner.upgrade().is_some());
        for (scope_id, activation) in session_activations.iter() {
            for member in &activation.active_set.members {
                if let Some(pack) = packs.get_mut(&member.manifest_digest) {
                    pack.catalog_activations
                        .push(CatalogPackInventoryActivation {
                            scope_id: scope_id.clone(),
                            active_set_digest: activation.active_set.active_set_digest.clone(),
                            source_kind: activation_catalog_kind(member.source_kind)
                                .as_str()
                                .to_owned(),
                            source_id: member.source_id.clone(),
                        });
                }
            }
        }
        drop(session_activations);

        let mut packs = packs.into_values().collect::<Vec<_>>();
        for pack in &mut packs {
            pack.sources.sort_by(|left, right| {
                left.source_kind
                    .cmp(&right.source_kind)
                    .then_with(|| left.source_id.cmp(&right.source_id))
            });
            pack.catalog_activations.sort_by(|left, right| {
                left.scope_id
                    .cmp(&right.scope_id)
                    .then_with(|| left.source_kind.cmp(&right.source_kind))
                    .then_with(|| left.source_id.cmp(&right.source_id))
            });
        }
        packs.sort_by(|left, right| {
            left.pack_id
                .cmp(&right.pack_id)
                .then_with(|| left.pack_version.cmp(&right.pack_version))
                .then_with(|| {
                    left.manifest_content_sha256
                        .cmp(&right.manifest_content_sha256)
                })
        });
        Ok(CatalogInventory { complete, packs })
    }

    pub fn install(
        &self,
        pack: &CompiledSemanticModelPack,
        source: &DurablePackSource,
    ) -> Result<InstallOutcome, CatalogError> {
        self.install_with(pack, source, |_, _, _| Ok(()))
    }

    pub fn install_release(
        &self,
        pack: &CompiledSemanticModelPack,
        source: &DurablePackSource,
        extraction: &PackExtractionAccounting,
    ) -> Result<InstallOutcome, CatalogError> {
        validate_extraction_accounting(extraction)?;
        self.install_with(pack, source, |transaction, manifest, _| {
            insert_extraction_accounting(transaction, &manifest.content_sha256, extraction)
        })
    }

    /// Install a release pack and return an opaque proof of the exact source
    /// row committed by the catalog. Callers cannot construct this proof from
    /// asserted release metadata.
    pub fn install_release_for_receipt(
        &self,
        release: &AcquisitionReceiptRelease,
        pack: &CompiledSemanticModelPack,
        source: &DurablePackSource,
        extraction: &PackExtractionAccounting,
    ) -> Result<(InstallOutcome, AcquisitionReceiptSource), CatalogError> {
        let release_digest = release.digest()?;
        validate_extraction_accounting(extraction)?;
        let validated = validate_pack(pack, &self.options.decode_limits)?;
        let install = if self.unchanged_release_install(
            &validated,
            &pack.manifest_bytes,
            source,
            extraction,
        )? {
            InstallOutcome {
                manifest_digest: validated.manifest.content_sha256,
                inserted_manifest: false,
                inserted_objects: 0,
            }
        } else {
            self.install_release(pack, source, extraction)?
        };
        let proof = AcquisitionReceiptSource {
            release_digest,
            manifest_digest: install.manifest_digest.clone(),
            source: source.clone(),
        };
        Ok((install, proof))
    }

    /// Install a release-provided production as an exact generated entry.
    ///
    /// The release source, extraction accounting, generated mapping, manifest,
    /// and shard rows are committed by one catalog transaction. A synthetic
    /// `generated` source row preserves the invariant used by
    /// [`Self::generated_production`], while `source` retains the release
    /// provenance for inventory and garbage-collection purposes.
    pub fn install_release_generated(
        &self,
        key: &GeneratedProductionKey,
        pack: &CompiledSemanticModelPack,
        source: &DurablePackSource,
        extraction: &PackExtractionAccounting,
    ) -> Result<GeneratedInstallOutcome, CatalogError> {
        let generated_source = DurablePackSource {
            kind: DurablePackSourceKind::Generated,
            source_id: key.source_id(),
        };
        self.install_generated_with(
            key,
            pack,
            source,
            || validate_extraction_accounting(extraction),
            |transaction, manifest, now| {
                insert_extraction_accounting(transaction, &manifest.content_sha256, extraction)?;
                insert_generated_production(transaction, key, manifest, now)?;
                insert_source(
                    transaction,
                    &manifest.content_sha256,
                    &generated_source,
                    now,
                )
            },
        )
    }

    /// Install a release-generated pack and return opaque proofs for both the
    /// release provenance and canonical generated-production source rows.
    pub fn install_release_generated_for_receipt(
        &self,
        release: &AcquisitionReceiptRelease,
        key: &GeneratedProductionKey,
        pack: &CompiledSemanticModelPack,
        source: &DurablePackSource,
        extraction: &PackExtractionAccounting,
    ) -> Result<(GeneratedInstallOutcome, Vec<AcquisitionReceiptSource>), CatalogError> {
        let release_digest = release.digest()?;
        validate_generated_pack_identity(key, &pack.manifest)?;
        validate_extraction_accounting(extraction)?;
        let validated = validate_pack(pack, &self.options.decode_limits)?;
        let generated_source = DurablePackSource {
            kind: DurablePackSourceKind::Generated,
            source_id: key.source_id(),
        };
        let unchanged =
            self.unchanged_release_install(&validated, &pack.manifest_bytes, source, extraction)?
                && self.exact_verified_install_present(
                    &validated,
                    &pack.manifest_bytes,
                    &generated_source,
                )?
                && self.generated_production(key)?.is_some_and(|production| {
                    production.manifest_digest == validated.manifest.content_sha256
                });
        let installation = if unchanged {
            GeneratedInstallOutcome {
                production: GeneratedProduction {
                    key: key.clone(),
                    manifest_digest: validated.manifest.content_sha256.clone(),
                    completeness: validated.manifest.completeness,
                },
                install: InstallOutcome {
                    manifest_digest: validated.manifest.content_sha256,
                    inserted_manifest: false,
                    inserted_objects: 0,
                },
            }
        } else {
            self.install_release_generated(key, pack, source, extraction)?
        };
        let manifest_digest = installation.install.manifest_digest.clone();
        Ok((
            installation,
            vec![
                AcquisitionReceiptSource {
                    release_digest: release_digest.clone(),
                    manifest_digest: manifest_digest.clone(),
                    source: source.clone(),
                },
                AcquisitionReceiptSource {
                    release_digest,
                    manifest_digest,
                    source: DurablePackSource {
                        kind: DurablePackSourceKind::Generated,
                        source_id: key.source_id(),
                    },
                },
            ],
        ))
    }

    /// Whether a verified durable pack carries exactly this source identity.
    ///
    /// A source may identify several manifests in one release, so this query
    /// intentionally does not require a manifest digest. It is read-only and
    /// does not hydrate or validate shard bytes.
    pub fn durable_source_present(&self, source: &DurablePackSource) -> Result<bool, CatalogError> {
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        connection
            .query_row(
                "SELECT EXISTS(
                   SELECT 1
                   FROM catalog_sources AS sources
                   JOIN catalog_packs AS packs
                     ON packs.manifest_digest = sources.manifest_digest
                   WHERE sources.source_kind = ?1
                     AND sources.source_id = ?2
                     AND packs.state = 'verified'
                 )",
                params![source.kind.as_str(), &source.source_id],
                |row| row.get(0),
            )
            .map_err(|error| CatalogError::sqlite("check durable pack source", error))
    }

    pub fn extraction_accounting(
        &self,
        manifest_digest: &str,
    ) -> Result<Option<PackExtractionAccounting>, CatalogError> {
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let counts = connection
            .query_row(
                "SELECT reject_count, suppressed_reject_count, error_reject_count
                 FROM catalog_pack_extraction_accounting
                 WHERE manifest_digest = ?1",
                [manifest_digest],
                |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, u64>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| CatalogError::sqlite("read pack extraction accounting", error))?;
        let Some((reject_count, suppressed_reject_count, error_reject_count)) = counts else {
            return Ok(None);
        };
        let mut statement = connection
            .prepare(
                "SELECT declaration, reason
                 FROM catalog_pack_extraction_gaps
                 WHERE manifest_digest = ?1
                 ORDER BY ordinal",
            )
            .map_err(|error| CatalogError::sqlite("prepare pack extraction gaps", error))?;
        let rows = statement
            .query_map([manifest_digest], |row| {
                Ok(PackExtractionGap {
                    declaration: row.get(0)?,
                    reason: row.get(1)?,
                })
            })
            .map_err(|error| CatalogError::sqlite("query pack extraction gaps", error))?;
        let gaps = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| CatalogError::sqlite("read pack extraction gap", error))?;
        let mut statement = connection
            .prepare(
                "SELECT source_entry, reason
                 FROM catalog_pack_extraction_source_entries
                 WHERE manifest_digest = ?1
                 ORDER BY ordinal",
            )
            .map_err(|error| {
                CatalogError::sqlite("prepare pack extraction source entries", error)
            })?;
        let rows = statement
            .query_map([manifest_digest], |row| {
                Ok(PackExtractionSourceEntry {
                    source_entry: row.get(0)?,
                    reason: row.get(1)?,
                })
            })
            .map_err(|error| CatalogError::sqlite("query pack extraction source entries", error))?;
        let source_entries = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| CatalogError::sqlite("read pack extraction source entry", error))?;
        Ok(Some(PackExtractionAccounting {
            reject_count,
            suppressed_reject_count,
            error_reject_count,
            gaps,
            source_entries,
        }))
    }

    pub fn install_generated(
        &self,
        key: &GeneratedProductionKey,
        pack: &CompiledSemanticModelPack,
    ) -> Result<GeneratedInstallOutcome, CatalogError> {
        let source = DurablePackSource {
            kind: DurablePackSourceKind::Generated,
            source_id: key.source_id(),
        };
        self.install_generated_with(
            key,
            pack,
            &source,
            || Ok(()),
            |transaction, manifest, now| {
                insert_generated_production(transaction, key, manifest, now)
            },
        )
    }

    pub fn install_generated_with_exact_go_source(
        &self,
        key: &GeneratedProductionKey,
        pack: &CompiledSemanticModelPack,
        artifact: &ExactArtifact,
        packages: &[GoPinnedPackage],
    ) -> Result<GeneratedInstallOutcome, CatalogError> {
        let source = DurablePackSource {
            kind: DurablePackSourceKind::Generated,
            source_id: key.source_id(),
        };
        self.install_generated_with(
            key,
            pack,
            &source,
            || validate_exact_go_source(artifact, packages),
            |transaction, manifest, now| {
                insert_generated_production(transaction, key, manifest, now)?;
                insert_exact_go_source_rows(
                    transaction,
                    &manifest.content_sha256,
                    artifact,
                    packages,
                )
            },
        )
    }

    fn install_generated_with(
        &self,
        key: &GeneratedProductionKey,
        pack: &CompiledSemanticModelPack,
        source: &DurablePackSource,
        validate_install: impl FnOnce() -> Result<(), CatalogError>,
        record_install: impl FnOnce(
            &Transaction<'_>,
            &CompiledPackManifest,
            i64,
        ) -> Result<(), CatalogError>,
    ) -> Result<GeneratedInstallOutcome, CatalogError> {
        validate_generated_pack_identity(key, &pack.manifest)?;
        validate_install()?;
        let install = self.install_with(pack, source, record_install)?;
        let production = GeneratedProduction {
            key: key.clone(),
            manifest_digest: install.manifest_digest.clone(),
            completeness: pack.manifest.completeness,
        };
        self.retain_shared_generated(&production);
        Ok(GeneratedInstallOutcome {
            production,
            install,
        })
    }

    pub fn register_exact_go_source(
        &self,
        manifest_digest: &str,
        artifact: &ExactArtifact,
        packages: &[GoPinnedPackage],
    ) -> Result<(), CatalogError> {
        self.require_writable()?;
        validate_exact_go_source(artifact, packages)?;
        let mut connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CatalogError::sqlite("begin exact Go source registration", error))?;
        let applicable: bool = transaction
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM catalog_packs
                   WHERE manifest_digest = ?1
                     AND state = 'verified'
                     AND language = 'go')",
                [manifest_digest],
                |row| row.get(0),
            )
            .map_err(|error| CatalogError::sqlite("check exact Go source publication", error))?;
        if !applicable {
            return Err(CatalogError::Unavailable);
        }
        insert_exact_go_source_rows(&transaction, manifest_digest, artifact, packages)?;
        transaction
            .commit()
            .map_err(|error| CatalogError::sqlite("commit exact Go source registration", error))?;
        self.record_mutation();
        Ok(())
    }

    /// Record that `key` can be found again from a read-free source identity.
    ///
    /// The identity is derived by the ecosystem adapter from cheap filesystem
    /// metadata rather than artifact bytes (see
    /// `dependency_source_identity`), so a later process can ask for this
    /// production before it reads anything. The recorded row only names the
    /// production; [`Self::generated_production_by_source_identity`] still
    /// resolves it through the fully verified key path, and the row disappears
    /// with the production it names.
    ///
    /// The row is keyed by the current `GENERATED_PRODUCTION_CACHE_VERSION`, so
    /// a catalog shared by binaries at different cache epochs keeps one mapping
    /// per epoch instead of letting the newest one hide the mapping a running
    /// binary learned.
    pub fn install_generated_source_identity(
        &self,
        source_identity: &str,
        key: &GeneratedProductionKey,
    ) -> Result<(), CatalogError> {
        self.require_writable()?;
        if !is_lower_sha256(source_identity) {
            return Err(CatalogError::Integrity(
                "generated source identity must be a lowercase SHA-256 digest".to_owned(),
            ));
        }
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let inserted = connection
            .execute(
                "INSERT OR REPLACE INTO catalog_generated_source_identities(
                   source_identity, producer_name, producer_version, schema_version,
                   generated_cache_version, production_digest, created_at
                 )
                 SELECT ?1, ?2, ?3, ?4, ?5, gp.production_digest, ?6
                 FROM catalog_generated_productions AS gp
                 WHERE gp.production_digest = ?7
                   AND gp.producer_name = ?2
                   AND gp.producer_version = ?3
                   AND gp.schema_version = ?4",
                params![
                    source_identity,
                    key.producer_name(),
                    key.producer_version(),
                    key.schema_version(),
                    GENERATED_PRODUCTION_CACHE_VERSION,
                    crate::cache_db::now_unix_seconds(),
                    key.production_digest(),
                ],
            )
            .map_err(|error| CatalogError::sqlite("install generated source identity", error))?;
        if inserted != 1 {
            return Err(CatalogError::Integrity(format!(
                "generated production {} is not installed, so its source identity cannot be recorded",
                key.production_digest()
            )));
        }
        drop(connection);
        if let Some(shared) = self.shared_generated_catalog() {
            // Failure of the optional host mapping does not invalidate the
            // local identity just committed. A later local hit retries it.
            if let Err(error) = shared.install_generated_source_identity(source_identity, key) {
                eprintln!(
                    "could not mirror generated source identity to the host cache; retaining the workspace identity: {error}"
                );
            }
        }
        Ok(())
    }

    /// Look up the generated production a read-free source identity was learned
    /// under, without reading or hashing the artifacts that identity describes.
    ///
    /// The row only names a candidate input digest. The returned production
    /// comes from [`Self::generated_production`], which re-validates the key,
    /// the manifest, and every shard row, so a partially deleted or quarantined
    /// production reads as a miss here. Callers treat that miss, and any error,
    /// as "read the artifacts and use the exact path instead".
    pub fn generated_production_by_source_identity(
        &self,
        source_identity: &str,
        producer: &super::Producer,
    ) -> Result<Option<GeneratedProduction>, CatalogError> {
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let row = connection
            .query_row(
                "SELECT gp.production_digest, gp.input_digest
                 FROM catalog_generated_source_identities AS ident
                 JOIN catalog_generated_productions AS gp
                   ON gp.production_digest = ident.production_digest
                 WHERE ident.source_identity = ?1
                   AND ident.producer_name = ?2
                   AND ident.producer_version = ?3
                   AND ident.schema_version = ?4
                   AND ident.generated_cache_version = ?5
                   AND gp.producer_name = ident.producer_name
                   AND gp.producer_version = ident.producer_version
                   AND gp.schema_version = ident.schema_version",
                params![
                    source_identity,
                    &producer.name,
                    &producer.version,
                    SEMANTIC_MODEL_SCHEMA_VERSION,
                    GENERATED_PRODUCTION_CACHE_VERSION,
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|error| CatalogError::sqlite("lookup generated source identity", error))?;
        drop(connection);
        let Some((production_digest, input_digest)) = row else {
            let Some(shared) = self.shared_generated_catalog() else {
                return Ok(None);
            };
            let Some(production) =
                shared.generated_production_by_source_identity(source_identity, producer)?
            else {
                return Ok(None);
            };
            self.copy_generated_from(shared, &production)?;
            self.install_generated_source_identity(source_identity, &production.key)?;
            return Ok(Some(production));
        };
        let key = GeneratedProductionKey::new(
            input_digest,
            &producer.name,
            &producer.version,
            SEMANTIC_MODEL_SCHEMA_VERSION,
        )?;
        debug_assert_eq!(
            key.production_digest(),
            production_digest,
            "a source-identity row must name the production its stored key derives"
        );
        self.generated_production(&key)
    }

    /// Look up the cached generated pack for `key`.
    ///
    /// This lookup is metadata only. It decodes the manifest, checks the key
    /// and producer identity, and confirms in one query that the catalog still
    /// holds a shard row joined to an object row for every manifest
    /// descriptor. It does not read or decode shard bytes. The pack row's
    /// `state = 'verified'`, written inside the install transaction after
    /// `validate_pack` decoded every shard, is the validation record, and the
    /// query requires it. The stored bytes are verified again by
    /// `storage::read` when a shard is loaded, and `load` quarantines a
    /// corrupt object there. Do not re-add a per-lookup decode pass (#2875).
    pub fn generated_production(
        &self,
        key: &GeneratedProductionKey,
    ) -> Result<Option<GeneratedProduction>, CatalogError> {
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let row = connection
            .query_row(
                "SELECT input_digest, producer_name, producer_version,
                        schema_version, manifest_digest, manifest_bytes
                 FROM catalog_verified_generated_productions
                 WHERE production_digest = ?1",
                [&key.production_digest],
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
            .map_err(|error| CatalogError::sqlite("lookup generated production", error))?;
        drop(connection);
        let Some((
            input_digest,
            producer_name,
            producer_version,
            schema_version,
            manifest_digest,
            manifest_bytes,
        )) = row
        else {
            let Some(shared) = self.shared_generated_catalog() else {
                return Ok(None);
            };
            let Some(production) = shared.generated_production(key)? else {
                return Ok(None);
            };
            self.copy_generated_from(shared, &production)?;
            return Ok(Some(production));
        };
        let validated = (|| -> Result<GeneratedProduction, CatalogError> {
            let stored_key = GeneratedProductionKey::new(
                input_digest,
                producer_name,
                producer_version,
                schema_version,
            )?;
            if stored_key != *key {
                return Err(CatalogError::Integrity(
                    "generated-production row does not match its canonical key".to_owned(),
                ));
            }
            let manifest = self.decoded_manifest(&manifest_digest, &manifest_bytes)?;
            validate_generated_pack_identity(key, &manifest)?;
            self.validate_generated_shard_rows(&manifest_digest, &manifest)?;
            Ok(GeneratedProduction {
                key: stored_key,
                manifest_digest: manifest_digest.clone(),
                completeness: manifest.completeness,
            })
        })();
        match validated {
            Ok(production) => {
                self.retain_shared_generated(&production);
                Ok(Some(production))
            }
            Err(error) => {
                self.rejected_manifests
                    .lock()
                    .expect("semantic-pack rejection mutex poisoned")
                    .insert(manifest_digest.clone());
                if self.mode == CatalogOpenMode::ReadWrite {
                    self.quarantine(&manifest_digest, "generated_production_failure", &error)?;
                }
                Ok(None)
            }
        }
    }

    /// Confirm that every manifest descriptor still has its shard row and
    /// object row, in one statement and without reading any object file.
    fn validate_generated_shard_rows(
        &self,
        manifest_digest: &str,
        manifest: &CompiledPackManifest,
    ) -> Result<(), CatalogError> {
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let mut statement = connection
            .prepare(
                "SELECT ps.shard_id, ps.stored_digest
                 FROM catalog_pack_shards AS ps
                 JOIN catalog_objects AS o
                   ON o.stored_digest = ps.stored_digest
                 WHERE ps.manifest_digest = ?1",
            )
            .map_err(|error| CatalogError::sqlite("lookup generated production shards", error))?;
        let rows = statement
            .query_map([manifest_digest], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|error| CatalogError::sqlite("lookup generated production shards", error))?;
        let mut stored = HashMap::with_capacity(manifest.shards.len());
        for row in rows {
            let (shard_id, stored_digest) = row.map_err(|error| {
                CatalogError::sqlite("read generated production shard row", error)
            })?;
            stored.insert(shard_id, stored_digest);
        }
        let missing = missing_manifest_shard_ids(manifest, &stored);
        if !missing.is_empty() {
            return Err(CatalogError::Integrity(format!(
                "generated production is missing shards {missing:?}"
            )));
        }
        Ok(())
    }

    fn install_with(
        &self,
        pack: &CompiledSemanticModelPack,
        source: &DurablePackSource,
        record_install: impl FnOnce(
            &Transaction<'_>,
            &CompiledPackManifest,
            i64,
        ) -> Result<(), CatalogError>,
    ) -> Result<InstallOutcome, CatalogError> {
        self.require_writable()?;
        if source.source_id.is_empty() {
            return Err(CatalogError::Integrity(
                "catalog source id must not be empty".to_owned(),
            ));
        }
        let validated = validate_pack(pack, &self.options.decode_limits)?;
        let installation_id = Uuid::new_v4().to_string();
        self.reserve_install_objects(&installation_id, &validated.shards)?;
        let mut published = Vec::with_capacity(validated.shards.len());
        let mut inserted_objects = 0;
        for shard in &validated.shards {
            let (path, inserted) =
                match storage::publish(&self.root, &shard.descriptor.stored_sha256, &shard.bytes) {
                    Ok(published) => published,
                    Err(error) => {
                        return Err(self.release_after_install_failure(&installation_id, error));
                    }
                };
            inserted_objects += usize::from(inserted);
            published.push(path);
        }

        let now = crate::cache_db::now_unix_seconds();
        let install_result = self.commit_install(
            pack,
            source,
            &validated,
            &published,
            &installation_id,
            now,
            record_install,
        );
        match install_result {
            Ok(inserted_manifest) => {
                self.rejected_manifests
                    .lock()
                    .expect("semantic-pack rejection mutex poisoned")
                    .remove(&validated.manifest.content_sha256);
                self.record_mutation();
                Ok(InstallOutcome {
                    manifest_digest: validated.manifest.content_sha256,
                    inserted_manifest,
                    inserted_objects,
                })
            }
            Err(error) => Err(self.release_after_install_failure(&installation_id, error)),
        }
    }

    fn exact_verified_install_present(
        &self,
        validated: &ValidatedPack,
        manifest_bytes: &[u8],
        source: &DurablePackSource,
    ) -> Result<bool, CatalogError> {
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let provenance_json = serde_json::to_vec(&validated.manifest.provenance)
            .map_err(|error| CatalogError::Integrity(error.to_string()))?;
        let pack = connection
            .query_row(
                "SELECT pack.semantic_digest, pack.manifest_bytes, pack.schema_version,
                        pack.pack_id, pack.pack_version, pack.producer_name,
                        pack.producer_version, pack.language, pack.ecosystem,
                        pack.bifrost_compatibility, pack.provenance_json, pack.license,
                        pack.completeness
                 FROM catalog_packs AS pack
                 JOIN catalog_sources AS source
                   ON source.manifest_digest = pack.manifest_digest
                 WHERE pack.manifest_digest = ?1 AND pack.state = 'verified'
                   AND source.source_kind = ?2 AND source.source_id = ?3",
                params![
                    validated.manifest.content_sha256,
                    source.kind.as_str(),
                    source.source_id,
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, u32>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, Option<String>>(9)?,
                        row.get::<_, Vec<u8>>(10)?,
                        row.get::<_, String>(11)?,
                        row.get::<_, String>(12)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| CatalogError::sqlite("read exact verified manifest", error))?;
        let Some((
            semantic_digest,
            stored_manifest_bytes,
            schema_version,
            pack_id,
            pack_version,
            producer_name,
            producer_version,
            language,
            ecosystem,
            bifrost_compatibility,
            stored_provenance_json,
            license,
            completeness,
        )) = pack
        else {
            return Ok(false);
        };
        if semantic_digest != validated.manifest.semantic_sha256
            || stored_manifest_bytes != manifest_bytes
            || schema_version != validated.manifest.schema_version
            || pack_id != validated.manifest.pack_id
            || pack_version != validated.manifest.version
            || producer_name != validated.manifest.producer.name
            || producer_version != validated.manifest.producer.version
            || language != validated.manifest.language
            || ecosystem != validated.manifest.ecosystem
            || bifrost_compatibility.as_deref()
                != validated.manifest.compatibility.bifrost.as_deref()
            || stored_provenance_json != provenance_json
            || license != validated.manifest.license
            || completeness != validated.manifest.completeness.label()
        {
            return Ok(false);
        }

        let mut statement = connection
            .prepare(
                "SELECT shard.ordinal, shard.shard_id, shard.payload_kind,
                        shard.stored_digest, shard.content_digest, shard.semantic_digest,
                        shard.record_count, shard.descriptor_json,
                        object.relative_path, object.stored_size, object.raw_size,
                        object.encoding
                 FROM catalog_packs AS pack
                 JOIN catalog_sources AS source ON source.manifest_digest = pack.manifest_digest
                 JOIN catalog_pack_shards AS shard ON shard.manifest_digest = pack.manifest_digest
                 JOIN catalog_objects AS object ON object.stored_digest = shard.stored_digest
                 WHERE pack.manifest_digest = ?1 AND pack.state = 'verified'
                   AND source.source_kind = ?2 AND source.source_id = ?3
                 ORDER BY shard.ordinal",
            )
            .map_err(|error| {
                CatalogError::sqlite("prepare exact verified installation check", error)
            })?;
        let rows = statement
            .query_map(
                params![
                    validated.manifest.content_sha256,
                    source.kind.as_str(),
                    source.source_id,
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, u64>(6)?,
                        row.get::<_, Vec<u8>>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, u64>(9)?,
                        row.get::<_, u64>(10)?,
                        row.get::<_, String>(11)?,
                    ))
                },
            )
            .map_err(|error| CatalogError::sqlite("check exact verified installation", error))?;
        let mut stored_shards = Vec::with_capacity(validated.shards.len());
        for row in rows {
            stored_shards.push(row.map_err(|error| {
                CatalogError::sqlite("read exact verified installation", error)
            })?);
        }
        if stored_shards.len() != validated.shards.len() {
            return Ok(false);
        }
        for (ordinal, (shard, row)) in validated.shards.iter().zip(stored_shards).enumerate() {
            let (
                stored_ordinal,
                shard_id,
                payload_kind,
                stored_digest,
                content_digest,
                semantic_digest,
                record_count,
                descriptor_json,
                relative_path,
                stored_size,
                raw_size,
                encoding,
            ) = row;
            let expected_ordinal = i64::try_from(ordinal).map_err(|_| {
                CatalogError::Integrity("catalog shard ordinal exceeds i64".to_owned())
            })?;
            let expected_descriptor_json = serde_json::to_vec(&shard.descriptor)
                .map_err(|error| CatalogError::Integrity(error.to_string()))?;
            if stored_ordinal != expected_ordinal
                || shard_id != shard.descriptor.shard_id
                || payload_kind != payload_kind_name(shard.descriptor.payload_kind)
                || stored_digest != shard.descriptor.stored_sha256
                || content_digest != shard.descriptor.content_sha256
                || semantic_digest != shard.descriptor.semantic_sha256
                || record_count != shard.descriptor.record_count
                || descriptor_json != expected_descriptor_json
                || stored_size != shard.descriptor.stored_size
                || raw_size != shard.descriptor.raw_size
                || encoding != encoding_name(shard.descriptor.encoding)
            {
                return Ok(false);
            }
            if !receipt_object_is_valid(
                &self.root,
                Path::new(&relative_path),
                &stored_digest,
                stored_size,
            )? {
                return Ok(false);
            }
        }

        let mut expected_selectors = Vec::new();
        for shard in &validated.shards {
            for (ordinal, selector) in shard.selectors.iter().enumerate() {
                expected_selectors.push((
                    shard.descriptor.shard_id.clone(),
                    i64::try_from(ordinal).map_err(|_| {
                        CatalogError::Integrity("selector ordinal exceeds i64".to_owned())
                    })?,
                    selector.package.as_ref().map(|value| value.name.clone()),
                    selector
                        .package
                        .as_ref()
                        .and_then(|value| value.version.clone()),
                    selector.module.as_ref().map(|value| value.name.clone()),
                    selector
                        .module
                        .as_ref()
                        .and_then(|value| value.version.clone()),
                    selector.toolchain.as_ref().map(|value| value.name.clone()),
                    selector
                        .toolchain
                        .as_ref()
                        .and_then(|value| value.version.clone()),
                    selector.artifact_sha256.clone(),
                    serde_json::to_vec(selector)
                        .map_err(|error| CatalogError::Integrity(error.to_string()))?,
                ));
            }
        }
        expected_selectors.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
        let mut statement = connection
            .prepare(
                "SELECT shard_id, selector_ordinal, package_name, package_version,
                        module_name, module_version, toolchain_name, toolchain_version,
                        artifact_sha256, selector_json
                 FROM catalog_selectors
                 WHERE manifest_digest = ?1
                 ORDER BY shard_id, selector_ordinal",
            )
            .map_err(|error| CatalogError::sqlite("prepare exact selector check", error))?;
        let rows = statement
            .query_map([&validated.manifest.content_sha256], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                ))
            })
            .map_err(|error| CatalogError::sqlite("query exact selector check", error))?;
        let mut stored_selectors = Vec::with_capacity(expected_selectors.len());
        for row in rows {
            stored_selectors.push(
                row.map_err(|error| CatalogError::sqlite("read exact selector check", error))?,
            );
        }
        if stored_selectors != expected_selectors {
            return Ok(false);
        }

        let mut expected_targets = Vec::new();
        let mut expected_configurations = Vec::new();
        for shard in &validated.shards {
            for (ordinal, selector) in shard.selectors.iter().enumerate() {
                let ordinal = i64::try_from(ordinal).map_err(|_| {
                    CatalogError::Integrity("selector ordinal exceeds i64".to_owned())
                })?;
                expected_targets.extend(
                    selector
                        .targets
                        .iter()
                        .map(|target| (shard.descriptor.shard_id.clone(), ordinal, target.clone())),
                );
                expected_configurations.extend(selector.configurations.iter().map(
                    |configuration| {
                        (
                            shard.descriptor.shard_id.clone(),
                            ordinal,
                            configuration.clone(),
                        )
                    },
                ));
            }
        }
        expected_targets.sort();
        expected_configurations.sort();
        let mut statement = connection
            .prepare(
                "SELECT shard_id, selector_ordinal, target
                 FROM catalog_selector_targets
                 WHERE manifest_digest = ?1
                 ORDER BY shard_id, selector_ordinal, target",
            )
            .map_err(|error| CatalogError::sqlite("prepare exact selector target check", error))?;
        let rows = statement
            .query_map([&validated.manifest.content_sha256], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|error| CatalogError::sqlite("query exact selector target check", error))?;
        let stored_targets = rows
            .collect::<Result<Vec<(String, i64, String)>, _>>()
            .map_err(|error| CatalogError::sqlite("read exact selector target check", error))?;
        if stored_targets != expected_targets {
            return Ok(false);
        }
        let mut statement = connection
            .prepare(
                "SELECT shard_id, selector_ordinal, configuration
                 FROM catalog_selector_configurations
                 WHERE manifest_digest = ?1
                 ORDER BY shard_id, selector_ordinal, configuration",
            )
            .map_err(|error| {
                CatalogError::sqlite("prepare exact selector configuration check", error)
            })?;
        let rows = statement
            .query_map([&validated.manifest.content_sha256], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|error| {
                CatalogError::sqlite("query exact selector configuration check", error)
            })?;
        let stored_configurations = rows
            .collect::<Result<Vec<(String, i64, String)>, _>>()
            .map_err(|error| {
                CatalogError::sqlite("read exact selector configuration check", error)
            })?;
        if stored_configurations != expected_configurations {
            return Ok(false);
        }

        let mut expected_routing_keys = Vec::new();
        for shard in &validated.shards {
            expected_routing_keys.extend(
                shard
                    .descriptor
                    .routing_keys
                    .iter()
                    .map(|routing_key| (shard.descriptor.shard_id.clone(), routing_key.clone())),
            );
        }
        expected_routing_keys.sort();
        let mut statement = connection
            .prepare(
                "SELECT shard_id, routing_key
                 FROM catalog_routing_keys
                 WHERE manifest_digest = ?1
                 ORDER BY shard_id, routing_key",
            )
            .map_err(|error| CatalogError::sqlite("prepare exact routing-key check", error))?;
        let rows = statement
            .query_map([&validated.manifest.content_sha256], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .map_err(|error| CatalogError::sqlite("query exact routing-key check", error))?;
        let stored_routing_keys = rows
            .collect::<Result<Vec<(String, String)>, _>>()
            .map_err(|error| CatalogError::sqlite("read exact routing-key check", error))?;
        Ok(stored_routing_keys == expected_routing_keys)
    }

    fn unchanged_release_install(
        &self,
        validated: &ValidatedPack,
        manifest_bytes: &[u8],
        source: &DurablePackSource,
        extraction: &PackExtractionAccounting,
    ) -> Result<bool, CatalogError> {
        Ok(
            self.exact_verified_install_present(validated, manifest_bytes, source)?
                && self
                    .extraction_accounting(&validated.manifest.content_sha256)?
                    .as_ref()
                    == Some(extraction),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_install(
        &self,
        pack: &CompiledSemanticModelPack,
        source: &DurablePackSource,
        validated: &ValidatedPack,
        published: &[PathBuf],
        installation_id: &str,
        now: i64,
        record_install: impl FnOnce(
            &Transaction<'_>,
            &CompiledPackManifest,
            i64,
        ) -> Result<(), CatalogError>,
    ) -> Result<bool, CatalogError> {
        let mut connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CatalogError::sqlite("begin pack install", error))?;
        for (shard, path) in validated.shards.iter().zip(published) {
            storage::verify_existing(
                &self.root,
                path,
                &shard.descriptor.stored_sha256,
                shard.descriptor.stored_size,
            )?;
        }
        let inserted_manifest =
            insert_manifest(&transaction, &validated.manifest, &pack.manifest_bytes, now)?;
        for (ordinal, ((shard, path), descriptor)) in validated
            .shards
            .iter()
            .zip(published)
            .zip(&validated.manifest.shards)
            .enumerate()
        {
            insert_object(&transaction, descriptor, path, now)?;
            insert_shard(
                &transaction,
                &validated.manifest.content_sha256,
                ordinal,
                descriptor,
            )?;
            record_shard_validation(
                &transaction,
                &validated.manifest.content_sha256,
                &descriptor.shard_id,
                &decode_limits_digest(&self.options.decode_limits),
            )?;
            publish_callable_value_rows(
                &transaction,
                &validated.manifest.content_sha256,
                &descriptor.shard_id,
                shard.callable_values.as_ref(),
            )?;
            insert_selectors(
                &transaction,
                &validated.manifest.content_sha256,
                &descriptor.shard_id,
                &shard.selectors,
            )?;
            insert_routing_keys(
                &transaction,
                &validated.manifest.content_sha256,
                &descriptor.shard_id,
                &descriptor.routing_keys,
            )?;
        }
        insert_source(
            &transaction,
            &validated.manifest.content_sha256,
            source,
            now,
        )?;
        record_install(&transaction, &validated.manifest, now)?;
        transaction
            .execute(
                "UPDATE catalog_packs
                 SET state = 'verified', verified_at = ?2
                 WHERE manifest_digest = ?1",
                params![&validated.manifest.content_sha256, now],
            )
            .map_err(|error| CatalogError::sqlite("verify installed pack", error))?;
        transaction
            .execute(
                "DELETE FROM catalog_install_object_reservations
                 WHERE installation_id = ?1",
                [installation_id],
            )
            .map_err(|error| CatalogError::sqlite("release install reservations", error))?;
        transaction
            .commit()
            .map_err(|error| CatalogError::sqlite("commit pack install", error))?;
        Ok(inserted_manifest)
    }

    fn reserve_install_objects(
        &self,
        installation_id: &str,
        shards: &[ValidatedShard],
    ) -> Result<(), CatalogError> {
        let now = crate::cache_db::now_unix_seconds();
        let expires_at = now.checked_add(300).ok_or_else(|| {
            CatalogError::Integrity("install reservation expiry overflowed".to_owned())
        })?;
        let mut connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CatalogError::sqlite("begin object reservation", error))?;
        transaction
            .execute(
                "DELETE FROM catalog_install_object_reservations
                 WHERE expires_at <= ?1",
                [now],
            )
            .map_err(|error| CatalogError::sqlite("prune install reservations", error))?;
        for shard in shards {
            transaction
                .execute(
                    "INSERT OR IGNORE INTO catalog_install_object_reservations(
                       installation_id, stored_digest, expires_at
                     ) VALUES(?1, ?2, ?3)",
                    params![installation_id, &shard.descriptor.stored_sha256, expires_at],
                )
                .map_err(|error| CatalogError::sqlite("reserve install object", error))?;
        }
        transaction
            .commit()
            .map_err(|error| CatalogError::sqlite("commit object reservation", error))
    }

    fn release_install_reservations(&self, installation_id: &str) -> Result<(), CatalogError> {
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        connection
            .execute(
                "DELETE FROM catalog_install_object_reservations
                 WHERE installation_id = ?1",
                [installation_id],
            )
            .map_err(|error| CatalogError::sqlite("release install reservations", error))?;
        Ok(())
    }

    fn release_after_install_failure(
        &self,
        installation_id: &str,
        error: CatalogError,
    ) -> CatalogError {
        match self.release_install_reservations(installation_id) {
            Ok(()) => error,
            Err(release_error) => CatalogError::Integrity(format!(
                "{error}; failed to release install reservations: {release_error}"
            )),
        }
    }

    pub fn register_session_pack(
        &self,
        pack: &CompiledSemanticModelPack,
        source: &SessionPackSource,
    ) -> Result<String, CatalogError> {
        self.register_session_pack_internal(pack, source, None)
    }

    pub fn register_compiled_pack(
        &self,
        pack: &CompiledSemanticModelPack,
        source: &SessionPackSource,
    ) -> Result<String, CatalogError> {
        self.register_session_pack(pack, source)
    }

    pub fn register_compiled_pack_with_exact_go_source(
        &self,
        pack: &CompiledSemanticModelPack,
        source: &SessionPackSource,
        artifact: &ExactArtifact,
        packages: &[GoPinnedPackage],
    ) -> Result<String, CatalogError> {
        self.register_session_pack_internal(pack, source, Some((artifact, packages)))
    }

    fn register_session_pack_internal(
        &self,
        pack: &CompiledSemanticModelPack,
        source: &SessionPackSource,
        exact_source: Option<(&ExactArtifact, &[GoPinnedPackage])>,
    ) -> Result<String, CatalogError> {
        if source.source_id.is_empty() {
            return Err(CatalogError::Integrity(
                "session pack source id must not be empty".to_owned(),
            ));
        }
        let mut validated = validate_pack(pack, &self.options.decode_limits)?;
        let digest = validated.manifest.content_sha256.clone();
        if let Some((artifact, packages)) = exact_source {
            if validated.manifest.language != "go" {
                return Err(CatalogError::Integrity(
                    "exact Go source can only accompany a Go compiled pack".to_owned(),
                ));
            }
            validate_exact_go_source(artifact, packages)?;
        }
        let mut session_packs = self
            .session_packs
            .lock()
            .expect("semantic-pack session mutex poisoned");
        if !session_packs
            .iter()
            .any(|entry| entry.manifest.content_sha256 == digest && entry.source == *source)
        {
            {
                let mut session_catalog_guard = self
                    .session_callable_values
                    .lock()
                    .expect("session callable-values connection mutex poisoned");
                if session_catalog_guard.is_none() {
                    *session_catalog_guard = Some(open_session_callable_values_catalog()?);
                }
                let session_catalog = session_catalog_guard
                    .as_mut()
                    .expect("session callable-values catalog was just initialized");
                let transaction = session_catalog
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(|error| {
                        CatalogError::sqlite("begin session callable-values publication", error)
                    })?;
                transaction
                    .execute(
                        "INSERT OR IGNORE INTO catalog_packs(manifest_digest, state)
                         VALUES(?1, 'verified')",
                        [&digest],
                    )
                    .map_err(|error| {
                        CatalogError::sqlite("publish session callable-values pack", error)
                    })?;
                for shard in &validated.shards {
                    transaction
                        .execute(
                            "INSERT OR IGNORE INTO catalog_pack_shards(manifest_digest, shard_id)
                             VALUES(?1, ?2)",
                            params![&digest, &shard.descriptor.shard_id],
                        )
                        .map_err(|error| {
                            CatalogError::sqlite("publish session callable-values shard", error)
                        })?;
                    insert_selectors(
                        &transaction,
                        &digest,
                        &shard.descriptor.shard_id,
                        &shard.selectors,
                    )?;
                    publish_callable_value_rows(
                        &transaction,
                        &digest,
                        &shard.descriptor.shard_id,
                        shard.callable_values.as_ref(),
                    )?;
                }
                if let Some((artifact, packages)) = exact_source {
                    insert_exact_go_source_rows(&transaction, &digest, artifact, packages)?;
                }
                transaction.commit().map_err(|error| {
                    CatalogError::sqlite("commit session callable-values publication", error)
                })?;
            }
            for shard in &mut validated.shards {
                // The query path reads only the SQL sidecar. Keep compiled
                // bytes/selectors for activation and hydration without
                // retaining a second Rust fact/coverage/identity index.
                shard.callable_values = None;
            }
            session_packs.push(SessionPack {
                manifest: Arc::new(validated.manifest),
                shards: validated.shards,
                source: source.clone(),
            });
            self.record_mutation();
        }
        Ok(digest)
    }

    pub fn lease(
        &self,
        manifest_digest: &str,
        owner: &str,
        ttl: Duration,
    ) -> Result<CatalogLease<'_>, CatalogError> {
        self.require_writable()?;
        if owner.is_empty() {
            return Err(CatalogError::Integrity(
                "semantic-pack lease owner must not be empty".to_owned(),
            ));
        }
        let lease_id = Uuid::new_v4().to_string();
        let expires_at = lease_expiry(ttl)?;
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        self.sql_statements.fetch_add(1, Ordering::Relaxed);
        let inserted = connection
            .execute(
                "INSERT INTO catalog_leases(lease_id, manifest_digest, owner, expires_at)
                 SELECT ?1, manifest_digest, ?3, ?4
                 FROM catalog_packs
                 WHERE manifest_digest = ?2 AND state = 'verified'",
                params![&lease_id, manifest_digest, owner, expires_at],
            )
            .map_err(|error| CatalogError::sqlite("acquire semantic-pack lease", error))?;
        if inserted == 0 {
            return Err(CatalogError::Unavailable);
        }
        Ok(CatalogLease {
            catalog: self,
            lease_id,
            released: false,
        })
    }

    pub fn pin(&self, manifest_digest: &str, pin_id: &str) -> Result<(), CatalogError> {
        self.require_writable()?;
        if pin_id.is_empty() {
            return Err(CatalogError::Integrity(
                "semantic-pack pin id must not be empty".to_owned(),
            ));
        }
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let inserted = connection
            .execute(
                "INSERT OR IGNORE INTO catalog_pins(manifest_digest, pin_id, created_at)
                 SELECT manifest_digest, ?2, ?3
                 FROM catalog_packs
                 WHERE manifest_digest = ?1 AND state = 'verified'",
                params![manifest_digest, pin_id, crate::cache_db::now_unix_seconds()],
            )
            .map_err(|error| CatalogError::sqlite("pin semantic pack", error))?;
        if inserted == 0 {
            let exists: bool = connection
                .query_row(
                    "SELECT EXISTS(
                       SELECT 1 FROM catalog_pins
                       WHERE manifest_digest = ?1 AND pin_id = ?2
                     )",
                    params![manifest_digest, pin_id],
                    |row| row.get(0),
                )
                .map_err(|error| CatalogError::sqlite("check semantic-pack pin", error))?;
            if !exists {
                return Err(CatalogError::Unavailable);
            }
        }
        Ok(())
    }

    pub fn unpin(&self, manifest_digest: &str, pin_id: &str) -> Result<bool, CatalogError> {
        self.require_writable()?;
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        connection
            .execute(
                "DELETE FROM catalog_pins
                 WHERE manifest_digest = ?1 AND pin_id = ?2",
                params![manifest_digest, pin_id],
            )
            .map(|deleted| deleted != 0)
            .map_err(|error| CatalogError::sqlite("unpin semantic pack", error))
    }

    pub fn remove_source(&self, source: &DurablePackSource) -> Result<bool, CatalogError> {
        self.require_writable()?;
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let removed = connection
            .execute(
                "DELETE FROM catalog_sources
                 WHERE source_kind = ?1 AND source_id = ?2",
                params![source.kind.as_str(), &source.source_id],
            )
            .map(|deleted| deleted != 0)
            .map_err(|error| CatalogError::sqlite("remove semantic-pack source", error))?;
        if removed {
            self.record_mutation();
        }
        Ok(removed)
    }

    pub fn replace_workspace_active_set(
        &self,
        scope_id: &str,
        store: &AnalyzerStore,
        members: &[SemanticPackActiveReference],
    ) -> Result<SemanticPackActiveSet, CatalogError> {
        if scope_id.is_empty() {
            return Err(CatalogError::Integrity(
                "semantic-pack activation scope must not be empty".to_owned(),
            ));
        }
        let desired = SemanticPackActiveSet::from_members(members)
            .map_err(|error| CatalogError::Integrity(error.to_string()))?;
        if store.is_ephemeral() {
            if desired
                .members
                .iter()
                .any(|member| durable_activation_kind(member.source_kind).is_some())
            {
                return Err(CatalogError::Integrity(
                    "ephemeral workspaces can activate only session semantic packs".to_owned(),
                ));
            }
            self.validate_active_members(&desired.members, true, None)?;
            let stored = store
                .replace_semantic_pack_active_set(&desired.members)
                .map_err(|error| CatalogError::Integrity(error.to_string()))?;
            self.replace_session_activations(scope_id, &stored, store);
            return Ok(stored);
        }
        self.validate_active_members(&desired.members, false, Some(scope_id))?;
        if desired
            .members
            .iter()
            .any(|member| durable_activation_kind(member.source_kind).is_none())
        {
            return Err(CatalogError::Integrity(
                "persistent workspaces cannot activate session-only semantic packs".to_owned(),
            ));
        }
        self.require_writable()?;
        let mut leases = self.activation_leases(scope_id, &desired.members)?;
        self.write_activation_rows(scope_id, &desired, false)?;
        let stored = store
            .replace_semantic_pack_active_set(&desired.members)
            .map_err(|error| CatalogError::Integrity(error.to_string()))?;
        self.write_activation_rows(scope_id, &stored, true)?;
        release_leases(&mut leases)?;
        Ok(stored)
    }

    pub fn reconcile_workspace_active_set(
        &self,
        scope_id: &str,
        store: &AnalyzerStore,
    ) -> Result<Option<SemanticPackActiveSet>, CatalogError> {
        if store.is_ephemeral() {
            let active_set = store
                .semantic_pack_active_set()
                .map_err(|error| CatalogError::Integrity(error.to_string()))?;
            let desired = match active_set {
                Some(active_set) => active_set,
                None => SemanticPackActiveSet::from_members(&[])
                    .map_err(|error| CatalogError::Integrity(error.to_string()))?,
            };
            if desired
                .members
                .iter()
                .any(|member| durable_activation_kind(member.source_kind).is_some())
            {
                return Err(CatalogError::Integrity(
                    "ephemeral workspaces can activate only session semantic packs".to_owned(),
                ));
            }
            self.validate_active_members(&desired.members, true, None)?;
            self.replace_session_activations(scope_id, &desired, store);
            return Ok((!desired.members.is_empty()).then_some(desired));
        }
        self.require_writable()?;
        let active_set = store
            .semantic_pack_active_set()
            .map_err(|error| CatalogError::Integrity(error.to_string()))?;
        let desired = match active_set {
            Some(active_set) => active_set,
            None => SemanticPackActiveSet::from_members(&[])
                .map_err(|error| CatalogError::Integrity(error.to_string()))?,
        };
        self.validate_active_members(&desired.members, false, Some(scope_id))?;
        let mut leases = self.activation_leases(scope_id, &desired.members)?;
        self.write_activation_rows(scope_id, &desired, true)?;
        release_leases(&mut leases)?;
        Ok((!desired.members.is_empty()).then_some(desired))
    }

    fn validate_active_members(
        &self,
        members: &[SemanticPackActiveReference],
        allow_session: bool,
        existing_scope: Option<&str>,
    ) -> Result<(), CatalogError> {
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let session_packs = self
            .session_packs
            .lock()
            .expect("semantic-pack session mutex poisoned");
        for member in members {
            if let Some(source_kind) = durable_activation_kind(member.source_kind) {
                let exists: bool = connection
                    .query_row(
                        "SELECT EXISTS(
                           SELECT 1
                           FROM catalog_packs AS packs
                           JOIN catalog_sources AS sources
                             ON sources.manifest_digest = packs.manifest_digest
                           WHERE packs.manifest_digest = ?1
                             AND packs.state = 'verified'
                             AND sources.source_kind = ?2
                             AND sources.source_id = ?3
                           UNION ALL
                           SELECT 1
                           FROM catalog_activations AS activations
                           JOIN catalog_packs AS packs
                             ON packs.manifest_digest = activations.manifest_digest
                           WHERE activations.scope_id = ?4
                             AND activations.manifest_digest = ?1
                             AND activations.source_kind = ?2
                             AND activations.source_id = ?3
                             AND packs.state = 'verified'
                         )",
                        params![
                            &member.manifest_digest,
                            source_kind.as_str(),
                            &member.source_id,
                            existing_scope
                        ],
                        |row| row.get(0),
                    )
                    .map_err(|error| {
                        CatalogError::sqlite("validate durable pack activation", error)
                    })?;
                if !exists {
                    return Err(CatalogError::Unavailable);
                }
            } else {
                if !allow_session {
                    return Err(CatalogError::Integrity(
                        "persistent workspaces cannot activate session-only semantic packs"
                            .to_owned(),
                    ));
                }
                let expected_kind = session_activation_kind(member.source_kind)
                    .expect("non-durable activation kind must be session-scoped");
                if !session_packs.iter().any(|pack| {
                    pack.manifest.content_sha256 == member.manifest_digest
                        && pack.source.kind == expected_kind
                        && pack.source.source_id == member.source_id
                }) {
                    return Err(CatalogError::Unavailable);
                }
            }
        }
        Ok(())
    }

    fn replace_session_activations(
        &self,
        scope_id: &str,
        active_set: &SemanticPackActiveSet,
        store: &AnalyzerStore,
    ) {
        let session_members = active_set
            .members
            .iter()
            .filter(|member| durable_activation_kind(member.source_kind).is_none())
            .cloned()
            .collect::<Vec<_>>();
        let mut activations = self
            .session_activations
            .lock()
            .expect("semantic-pack session activation mutex poisoned");
        if session_members.is_empty() {
            activations.remove(scope_id);
        } else {
            let session_set = SemanticPackActiveSet::from_members(&session_members)
                .expect("validated session activations form a valid active set");
            activations.insert(
                scope_id.to_owned(),
                SessionActivation {
                    active_set: session_set,
                    owner: store.lifetime(),
                },
            );
        }
    }

    fn activation_leases(
        &self,
        scope_id: &str,
        members: &[SemanticPackActiveReference],
    ) -> Result<Vec<CatalogLease<'_>>, CatalogError> {
        let mut leases = Vec::new();
        for member in members {
            if durable_activation_kind(member.source_kind).is_some() {
                leases.push(self.lease(
                    &member.manifest_digest,
                    &format!("activation:{scope_id}"),
                    Duration::from_secs(300),
                )?);
            }
        }
        Ok(leases)
    }

    fn write_activation_rows(
        &self,
        scope_id: &str,
        active_set: &SemanticPackActiveSet,
        replace: bool,
    ) -> Result<(), CatalogError> {
        let now = crate::cache_db::now_unix_seconds();
        let mut connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CatalogError::sqlite("begin activation update", error))?;
        for member in &active_set.members {
            let Some(source_kind) = durable_activation_kind(member.source_kind) else {
                continue;
            };
            let inserted = transaction
                .execute(
                    "INSERT INTO catalog_activations(
                       scope_id, active_set_digest, manifest_digest,
                       source_kind, source_id, activated_at
                     )
                     SELECT ?1, ?2, packs.manifest_digest, ?4, ?5, ?6
                     FROM catalog_packs AS packs
                     WHERE packs.manifest_digest = ?3
                       AND packs.state = 'verified'
                       AND (
                         EXISTS(
                           SELECT 1 FROM catalog_sources AS sources
                           WHERE sources.manifest_digest = packs.manifest_digest
                             AND sources.source_kind = ?4
                             AND sources.source_id = ?5
                         )
                         OR EXISTS(
                           SELECT 1 FROM catalog_activations AS active
                           WHERE active.scope_id = ?1
                             AND active.manifest_digest = packs.manifest_digest
                             AND active.source_kind = ?4
                             AND active.source_id = ?5
                         )
                       )
                     ON CONFLICT(scope_id, manifest_digest) DO UPDATE SET
                       active_set_digest = excluded.active_set_digest,
                       source_kind = excluded.source_kind,
                       source_id = excluded.source_id,
                       activated_at = excluded.activated_at",
                    params![
                        scope_id,
                        &active_set.active_set_digest,
                        &member.manifest_digest,
                        source_kind.as_str(),
                        &member.source_id,
                        now
                    ],
                )
                .map_err(|error| CatalogError::sqlite("publish activation", error))?;
            if inserted == 0 {
                return Err(CatalogError::Unavailable);
            }
        }
        if replace {
            transaction
                .execute(
                    "DELETE FROM catalog_activations
                     WHERE scope_id = ?1 AND active_set_digest <> ?2",
                    params![scope_id, &active_set.active_set_digest],
                )
                .map_err(|error| CatalogError::sqlite("replace activation scope", error))?;
        }
        transaction
            .commit()
            .map_err(|error| CatalogError::sqlite("commit activation update", error))
    }

    pub fn candidates(
        &self,
        query: &SemanticPackSelectorQuery,
    ) -> Result<Vec<CatalogCandidate>, CatalogError> {
        self.candidates_bounded_inner(query, usize::MAX, false)
    }

    /// Select candidates that explicitly bind at least one exact dependency
    /// coordinate carried by `query`.
    ///
    /// An unconstrained selector is useful for intrinsic, explicitly enabled
    /// language models, but it does not prove that the pack models a specific
    /// discovered package, module, or toolchain version. Dependency
    /// preparation must keep those two activation routes separate.
    pub fn dependency_candidates(
        &self,
        query: &SemanticPackSelectorQuery,
    ) -> Result<Vec<CatalogCandidate>, CatalogError> {
        debug_assert!(query_has_exact_coordinate(query));
        self.candidates_bounded_inner(query, usize::MAX, true)
    }

    /// Check an exact acquisition under a transaction that gives a satisfying
    /// candidate precedence over an absence receipt.
    pub fn acquisition_receipt_lookup(
        &self,
        request: &AcquisitionReceiptRequest,
        release: &AcquisitionReceiptRelease,
    ) -> Result<AcquisitionReceiptLookup, CatalogError> {
        self.require_writable()?;
        validate_acquisition_receipt_request(request)?;
        let request_digest = request.digest();
        let release_digest = release.digest()?;
        let mut connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CatalogError::sqlite("begin acquisition receipt lookup", error))?;
        if acquisition_request_satisfied(
            &self.root,
            &transaction,
            &self.options.decode_limits,
            request,
        )? {
            transaction
                .commit()
                .map_err(|error| CatalogError::sqlite("commit satisfied receipt lookup", error))?;
            return Ok(AcquisitionReceiptLookup::Satisfied);
        }
        let mutation_epoch = semantic_mutation_epoch(&transaction)?;
        let receipt = transaction
            .query_row(
                "SELECT catalog_mutation_epoch, source_state_digest, source_count
                 FROM catalog_acquisition_absence_receipts
                 WHERE request_digest = ?1 AND release_digest = ?2
                   AND release_repository = ?3 AND release_tag = ?4
                   AND archive_name = ?5 AND archive_digest = ?6
                   AND bundle_schema_version = ?7
                   AND bundle_generator_name = ?8
                   AND bundle_generator_version = ?9
                   AND semantic_schema_version = ?10
                   AND generated_cache_version = ?11
                   AND client_epoch = ?12
                   AND catalog_schema_version = ?13",
                params![
                    request_digest,
                    release_digest,
                    release.repository,
                    release.tag,
                    release.archive_name,
                    release.archive_digest,
                    release.bundle_schema_version,
                    release.bundle_generator_name,
                    release.bundle_generator_version,
                    release.semantic_schema_version,
                    release.generated_cache_version,
                    release.client_epoch,
                    CATALOG_SCHEMA_VERSION,
                ],
                |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, u64>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| CatalogError::sqlite("read acquisition absence receipt", error))?;
        let valid = if let Some((receipt_epoch, source_state_digest, source_count)) = receipt {
            receipt_epoch == mutation_epoch
                && receipt_source_state_digest(
                    &self.root,
                    &transaction,
                    &self.options.decode_limits,
                    &request_digest,
                    &release_digest,
                    source_count,
                )?
                .is_some_and(|digest| digest == source_state_digest)
        } else {
            false
        };
        transaction
            .commit()
            .map_err(|error| CatalogError::sqlite("commit acquisition receipt lookup", error))?;
        Ok(if valid {
            AcquisitionReceiptLookup::KnownVerifiedAbsence
        } else {
            AcquisitionReceiptLookup::ReceiptMiss
        })
    }

    /// Record verified absence only after the caller has completely verified
    /// and installed the selected release. Every source proof is revalidated
    /// against the same catalog transaction before persistence.
    pub fn record_acquisition_absence(
        &self,
        request: &AcquisitionReceiptRequest,
        release: &AcquisitionReceiptRelease,
        sources: &[AcquisitionReceiptSource],
    ) -> Result<AcquisitionReceiptLookup, CatalogError> {
        self.require_writable()?;
        validate_acquisition_receipt_request(request)?;
        if sources.is_empty() {
            return Err(CatalogError::Integrity(
                "acquisition absence requires at least one verified installed source".to_owned(),
            ));
        }
        let mut sources = sources.to_vec();
        sources.sort_by(|left, right| {
            left.release_digest
                .cmp(&right.release_digest)
                .then_with(|| left.manifest_digest.cmp(&right.manifest_digest))
                .then_with(|| left.source.kind.as_str().cmp(right.source.kind.as_str()))
                .then_with(|| left.source.source_id.cmp(&right.source.source_id))
        });
        sources.dedup();
        let request_digest = request.digest();
        let release_digest = release.digest()?;
        let mut connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CatalogError::sqlite("begin acquisition absence record", error))?;
        if acquisition_request_satisfied(
            &self.root,
            &transaction,
            &self.options.decode_limits,
            request,
        )? {
            transaction
                .commit()
                .map_err(|error| CatalogError::sqlite("commit satisfied absence record", error))?;
            return Ok(AcquisitionReceiptLookup::Satisfied);
        }
        for source in &sources {
            if source.release_digest != release_digest {
                return Err(CatalogError::Integrity(
                    "acquisition receipt source belongs to a different release".to_owned(),
                ));
            }
            let source_state = transaction
                .query_row(
                    "SELECT pack.state, pack.manifest_bytes
                     FROM catalog_sources AS source
                     JOIN catalog_packs AS pack
                       ON pack.manifest_digest = source.manifest_digest
                     WHERE source.manifest_digest = ?1
                       AND source.source_kind = ?2
                       AND source.source_id = ?3",
                    params![
                        source.manifest_digest,
                        source.source.kind.as_str(),
                        source.source.source_id,
                    ],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )
                .optional()
                .map_err(|error| {
                    CatalogError::sqlite("verify acquisition receipt source", error)
                })?;
            let Some((state, manifest_bytes)) = source_state else {
                return Err(CatalogError::Integrity(format!(
                    "acquisition receipt source is not verified: {:?}",
                    source
                )));
            };
            let manifest = self.decoded_manifest(&source.manifest_digest, &manifest_bytes)?;
            if state != "verified"
                || !manifest_shard_rows_present(
                    &self.root,
                    &transaction,
                    &source.manifest_digest,
                    &manifest,
                )?
            {
                return Err(CatalogError::Integrity(format!(
                    "acquisition receipt source is not fully verified: {:?}",
                    source
                )));
            }
        }
        let mutation_epoch = semantic_mutation_epoch(&transaction)?;
        let source_state_digest = acquisition_source_state_digest(&sources);
        let now = crate::cache_db::now_unix_seconds();
        transaction
            .execute(
                "INSERT INTO catalog_acquisition_absence_receipts(
                   request_digest, release_digest, release_repository, release_tag,
                   archive_name, archive_digest, bundle_schema_version,
                   bundle_generator_name, bundle_generator_version,
                   semantic_schema_version, generated_cache_version, client_epoch,
                   catalog_schema_version, catalog_mutation_epoch, source_state_digest,
                   source_count, created_at
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
                 ON CONFLICT(request_digest, release_digest) DO UPDATE SET
                   release_repository = excluded.release_repository,
                   release_tag = excluded.release_tag,
                   archive_name = excluded.archive_name,
                   archive_digest = excluded.archive_digest,
                   bundle_schema_version = excluded.bundle_schema_version,
                   bundle_generator_name = excluded.bundle_generator_name,
                   bundle_generator_version = excluded.bundle_generator_version,
                   semantic_schema_version = excluded.semantic_schema_version,
                   generated_cache_version = excluded.generated_cache_version,
                   client_epoch = excluded.client_epoch,
                   catalog_schema_version = excluded.catalog_schema_version,
                   catalog_mutation_epoch = excluded.catalog_mutation_epoch,
                   source_state_digest = excluded.source_state_digest,
                   source_count = excluded.source_count,
                   created_at = excluded.created_at",
                params![
                    request_digest,
                    release_digest,
                    release.repository,
                    release.tag,
                    release.archive_name,
                    release.archive_digest,
                    release.bundle_schema_version,
                    release.bundle_generator_name,
                    release.bundle_generator_version,
                    release.semantic_schema_version,
                    release.generated_cache_version,
                    release.client_epoch,
                    CATALOG_SCHEMA_VERSION,
                    mutation_epoch,
                    source_state_digest,
                    u64::try_from(sources.len()).unwrap_or(u64::MAX),
                    now,
                ],
            )
            .map_err(|error| CatalogError::sqlite("write acquisition absence receipt", error))?;
        transaction
            .execute(
                "DELETE FROM catalog_acquisition_absence_receipt_sources
                 WHERE request_digest = ?1 AND release_digest = ?2",
                params![request_digest, release_digest],
            )
            .map_err(|error| CatalogError::sqlite("replace acquisition receipt sources", error))?;
        for source in sources {
            transaction
                .execute(
                    "INSERT INTO catalog_acquisition_absence_receipt_sources(
                       request_digest, release_digest, manifest_digest, source_kind, source_id
                     ) VALUES(?1, ?2, ?3, ?4, ?5)",
                    params![
                        request_digest,
                        release_digest,
                        source.manifest_digest,
                        source.source.kind.as_str(),
                        source.source.source_id,
                    ],
                )
                .map_err(|error| CatalogError::sqlite("write acquisition receipt source", error))?;
        }
        transaction
            .commit()
            .map_err(|error| CatalogError::sqlite("commit acquisition absence receipt", error))?;
        Ok(AcquisitionReceiptLookup::KnownVerifiedAbsence)
    }

    pub fn candidates_bounded(
        &self,
        query: &SemanticPackSelectorQuery,
        max_rows: usize,
    ) -> Result<Vec<CatalogCandidate>, CatalogError> {
        self.candidates_bounded_inner(query, max_rows, false)
    }

    fn candidates_bounded_inner(
        &self,
        query: &SemanticPackSelectorQuery,
        max_rows: usize,
        require_exact_coordinate: bool,
    ) -> Result<Vec<CatalogCandidate>, CatalogError> {
        let durable_rows = self.durable_selector_rows(query, max_rows)?;

        let mut candidates = Vec::new();
        let rejected_manifests = self
            .rejected_manifests
            .lock()
            .expect("semantic-pack rejection mutex poisoned");
        let mut corrupt = Vec::new();
        let mut corrupt_digests = HashSet::new();
        for row in durable_rows {
            let DurableSelectorRow {
                manifest_digest,
                shard_id,
                descriptor_json,
                selector_json,
                source_kind,
                source_id,
            } = row;
            if rejected_manifests.contains(&manifest_digest)
                || corrupt_digests.contains(&manifest_digest)
            {
                continue;
            }
            let decoded = (|| -> Result<Option<CatalogCandidate>, CatalogError> {
                let manifest = self.stored_manifest(&manifest_digest)?;
                if !manifest_compatible(&manifest, query)? {
                    return Ok(None);
                }
                let selector: ActivationSelector = serde_json::from_slice(&selector_json)
                    .map_err(|error| CatalogError::Integrity(error.to_string()))?;
                if !selector_matches(&selector, query)? {
                    return Ok(None);
                }
                if require_exact_coordinate && !selector_binds_exact_coordinate(&selector, query) {
                    return Ok(None);
                }
                let descriptor: CompiledShardDescriptor = serde_json::from_slice(&descriptor_json)
                    .map_err(|error| CatalogError::Integrity(error.to_string()))?;
                if manifest
                    .shards
                    .iter()
                    .find(|expected| expected.shard_id == shard_id)
                    != Some(&descriptor)
                {
                    return Err(CatalogError::Integrity(format!(
                        "catalog descriptor does not match manifest shard {shard_id}"
                    )));
                }
                Ok(Some(CatalogCandidate {
                    manifest_digest: manifest_digest.clone(),
                    shard_id,
                    descriptor,
                    completeness: manifest.completeness,
                    source_kind: DurablePackSourceKind::parse(&source_kind)?.into(),
                    source_id,
                    location: CatalogCandidateLocation::Durable,
                }))
            })();
            match decoded {
                Ok(Some(candidate)) if !candidates.contains(&candidate) => {
                    candidates.push(candidate);
                }
                Ok(_) => {}
                Err(error) => {
                    corrupt_digests.insert(manifest_digest.clone());
                    corrupt.push((manifest_digest, error));
                }
            }
        }
        drop(rejected_manifests);
        for (manifest_digest, error) in corrupt {
            candidates.retain(|candidate| candidate.manifest_digest != manifest_digest);
            self.rejected_manifests
                .lock()
                .expect("semantic-pack rejection mutex poisoned")
                .insert(manifest_digest.clone());
            if self.mode == CatalogOpenMode::ReadWrite {
                self.quarantine(&manifest_digest, "candidate_metadata_failure", &error)?;
            }
        }

        let session_packs = self
            .session_packs
            .lock()
            .expect("semantic-pack session mutex poisoned");
        for (pack_ordinal, pack) in session_packs.iter().enumerate() {
            if candidates.len() >= max_rows {
                break;
            }
            if pack.manifest.language != query.language
                || pack.manifest.ecosystem != query.ecosystem
                || !manifest_compatible(&pack.manifest, query)?
            {
                continue;
            }
            for (shard_ordinal, shard) in pack.shards.iter().enumerate() {
                if candidates.len() >= max_rows {
                    break;
                }
                let mut matches = false;
                for selector in &shard.selectors {
                    if selector_matches(selector, query)?
                        && (!require_exact_coordinate
                            || selector_binds_exact_coordinate(selector, query))
                    {
                        matches = true;
                        break;
                    }
                }
                if !matches {
                    continue;
                }
                candidates.push(CatalogCandidate {
                    manifest_digest: pack.manifest.content_sha256.clone(),
                    shard_id: shard.descriptor.shard_id.clone(),
                    descriptor: shard.descriptor.clone(),
                    completeness: pack.manifest.completeness,
                    source_kind: pack.source.kind.into(),
                    source_id: pack.source.source_id.clone(),
                    location: CatalogCandidateLocation::Session {
                        pack_ordinal,
                        shard_ordinal,
                    },
                });
            }
        }
        candidates.sort_by(|left, right| {
            left.source_kind
                .precedence()
                .cmp(&right.source_kind.precedence())
                .then_with(|| left.manifest_digest.cmp(&right.manifest_digest))
                .then_with(|| left.shard_id.cmp(&right.shard_id))
                .then_with(|| left.source_id.cmp(&right.source_id))
        });
        candidates.dedup();
        if candidates.is_empty() {
            self.lookup_misses.fetch_add(1, Ordering::Relaxed);
        }
        Ok(candidates)
    }

    /// Name every pack that `candidates` rejected for `query` only because an
    /// exact version requirement did not accept the queried version.
    ///
    /// Candidate selection deliberately drops such a pack in silence: a wrong
    /// version must never activate. Attribution needs the opposite: a
    /// workspace on JDK 17 with only a JDK 21 pack installed must hear "the
    /// pack requires =21.0.2, the workspace has 17.0.10", not a bare
    /// "no pack found". A pack rejected for a non-version reason (name,
    /// target, configuration, artifact digest, Bifrost compatibility) is not
    /// reported here.
    pub fn version_near_misses(
        &self,
        query: &SemanticPackSelectorQuery,
    ) -> Result<Vec<SemanticPackVersionNearMiss>, CatalogError> {
        let rows = self.durable_selector_rows(query, usize::MAX)?;
        let mut misses: Vec<SemanticPackVersionNearMiss> = Vec::new();
        {
            let rejected_manifests = self
                .rejected_manifests
                .lock()
                .expect("semantic-pack rejection mutex poisoned");
            for row in rows {
                if rejected_manifests.contains(&row.manifest_digest)
                    || misses
                        .iter()
                        .any(|miss| miss.manifest_digest == row.manifest_digest)
                {
                    continue;
                }
                let manifest = self.stored_manifest(&row.manifest_digest)?;
                let selector: ActivationSelector = serde_json::from_slice(&row.selector_json)
                    .map_err(|error| CatalogError::Integrity(error.to_string()))?;
                if let Some(miss) =
                    version_near_miss(&manifest, std::slice::from_ref(&selector), query)?
                {
                    misses.push(miss);
                }
            }
        }
        let session_packs = self
            .session_packs
            .lock()
            .expect("semantic-pack session mutex poisoned");
        for pack in session_packs.iter() {
            if pack.manifest.language != query.language
                || pack.manifest.ecosystem != query.ecosystem
                || misses
                    .iter()
                    .any(|miss| miss.manifest_digest == pack.manifest.content_sha256)
            {
                continue;
            }
            let selectors = pack
                .shards
                .iter()
                .flat_map(|shard| shard.selectors.iter().cloned())
                .collect::<Vec<_>>();
            if let Some(miss) = version_near_miss(&pack.manifest, &selectors, query)? {
                misses.push(miss);
            }
        }
        drop(session_packs);
        misses.sort();
        Ok(misses)
    }

    fn durable_selector_rows(
        &self,
        query: &SemanticPackSelectorQuery,
        max_rows: usize,
    ) -> Result<Vec<DurableSelectorRow>, CatalogError> {
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        self.sql_statements.fetch_add(1, Ordering::Relaxed);
        durable_selector_rows_on(&connection, query, max_rows)
    }

    pub fn load(&self, candidate: &CatalogCandidate) -> Result<LoadedCatalogShard, CatalogMiss> {
        match self.load_inner(candidate) {
            Ok(loaded) => {
                self.lookup_hits.fetch_add(1, Ordering::Relaxed);
                Ok(loaded)
            }
            Err(error) => {
                self.lookup_misses.fetch_add(1, Ordering::Relaxed);
                if matches!(error, CatalogError::Unavailable) {
                    return Err(CatalogMiss::NotFound);
                }
                let mut reason = error.to_string();
                if matches!(candidate.location, CatalogCandidateLocation::Durable) {
                    self.rejected_manifests
                        .lock()
                        .expect("semantic-pack rejection mutex poisoned")
                        .insert(candidate.manifest_digest.clone());
                }
                if matches!(candidate.location, CatalogCandidateLocation::Durable)
                    && self.mode == CatalogOpenMode::ReadWrite
                    && let Err(quarantine_error) =
                        self.quarantine(&candidate.manifest_digest, "load_failure", &error)
                {
                    reason.push_str("; failed to record quarantine: ");
                    reason.push_str(&quarantine_error.to_string());
                }
                Err(CatalogMiss::Quarantined { reason })
            }
        }
    }

    /// Read one exact callable-values question from the normalized catalog
    /// rows. The caller is responsible for intersecting catalog availability
    /// with its active-set and artifact evidence before using returned facts.
    pub fn query_callable_values(
        &self,
        query: &CatalogCallableValuesQuery<'_>,
        limits: CatalogCallableValuesQueryLimits,
        cancellation: &CancellationToken,
    ) -> Result<CatalogCallableValuesQueryResult, CatalogError> {
        let mut result = CatalogCallableValuesQueryResult {
            facts: Vec::new(),
            coverage_claims: Vec::new(),
            executable_coverage: CsmiCoverageStatus::Unknown,
            examined_records: 0,
            gap: None,
        };
        if cancellation.is_cancelled() {
            result.gap = Some(CatalogCallableValuesQueryGap::Cancelled);
            return Ok(result);
        }
        if limits.max_records == 0 {
            result.gap =
                Some(CatalogCallableValuesQueryGap::RecordBudgetExhausted { max_records: 0 });
            return Ok(result);
        }

        let use_durable_catalog = match self.ensure_callable_values_indexed(
            query.manifest_digest,
            query.shard_id,
            cancellation,
        )? {
            CallableValuesIndexReadiness::Ready => true,
            CallableValuesIndexReadiness::Cancelled => {
                result.gap = Some(CatalogCallableValuesQueryGap::Cancelled);
                return Ok(result);
            }
            CallableValuesIndexReadiness::Missing => {
                match self.ensure_session_callable_values_indexed(
                    query.manifest_digest,
                    query.shard_id,
                    cancellation,
                )? {
                    CallableValuesIndexReadiness::Ready => false,
                    CallableValuesIndexReadiness::Cancelled => {
                        result.gap = Some(CatalogCallableValuesQueryGap::Cancelled);
                        return Ok(result);
                    }
                    CallableValuesIndexReadiness::Missing => {
                        result.gap =
                            Some(CatalogCallableValuesQueryGap::IndexReconciliationRequired);
                        return Ok(result);
                    }
                }
            }
        };

        let connection_guard = if use_durable_catalog {
            CallableValuesQueryConnection::Durable(
                self.connection
                    .lock()
                    .expect("semantic-pack catalog connection mutex poisoned"),
            )
        } else {
            CallableValuesQueryConnection::Session(
                self.session_callable_values
                    .lock()
                    .expect("session callable-values connection mutex poisoned"),
            )
        };
        let connection = match &connection_guard {
            CallableValuesQueryConnection::Durable(guard) => &**guard,
            CallableValuesQueryConnection::Session(guard) => {
                &guard
                    .as_ref()
                    .expect("session callable-values index was checked before querying")
                    .connection
            }
        };
        let limit = callable_values_sql_limit(limits.max_records.saturating_add(1));
        let family = match query.question {
            CatalogCallableValuesQuestion::ReturnedCallable { .. } => {
                CallableValuesFamily::ReturnedCallables
            }
            CatalogCallableValuesQuestion::CallbackInvocation { .. } => {
                CallableValuesFamily::CallbackInvocations
            }
        };

        match query.question {
            CatalogCallableValuesQuestion::ReturnedCallable {
                result: result_ordinal,
            } => {
                let mut statement =
                    connection
                        .prepare(CALLABLE_VALUES_RETURNED_SQL)
                        .map_err(|error| {
                            CatalogError::sqlite("prepare returned-callable query", error)
                        })?;
                let rows = statement
                    .query_map(
                        params![
                            query.manifest_digest,
                            query.shard_id,
                            query.callable,
                            result_ordinal,
                            limit,
                        ],
                        |row| {
                            Ok((
                                row.get::<_, i64>(0)?,
                                row.get::<_, i64>(1)?,
                                row.get::<_, String>(2)?,
                                row.get::<_, String>(3)?,
                            ))
                        },
                    )
                    .map_err(|error| CatalogError::sqlite("query returned-callable rows", error))?;
                for row in rows {
                    if cancellation.is_cancelled() {
                        result.gap = Some(CatalogCallableValuesQueryGap::Cancelled);
                        break;
                    }
                    let row = row.map_err(|error| {
                        CatalogError::sqlite("read returned-callable row", error)
                    })?;
                    result.examined_records += 1;
                    if result.examined_records > limits.max_records {
                        result.gap = Some(CatalogCallableValuesQueryGap::RecordBudgetExhausted {
                            max_records: limits.max_records,
                        });
                        break;
                    }
                    let payload = CsmiCallableValuesPayload::ReturnedCallable {
                        callable: query.callable.to_owned(),
                        result: u32::try_from(row.1).map_err(|error| {
                            CatalogError::Integrity(format!(
                                "stored callable result ordinal is outside u32: {error}"
                            ))
                        })?,
                        target: row.2.clone(),
                    };
                    let fact = CallableValuesFact {
                        payload,
                        provenance: decode_json_column(&row.3, "callable fact provenance")?,
                    };
                    let anonymous_callable = match load_anonymous_callable_identity(
                        connection,
                        query.manifest_digest,
                        query.shard_id,
                        &row.2,
                        limits.max_records.saturating_sub(result.examined_records),
                        cancellation,
                    )? {
                        AnonymousCallableIdentityRead::Missing => None,
                        AnonymousCallableIdentityRead::Found { identity, examined } => {
                            result.examined_records += examined;
                            Some(*identity)
                        }
                        AnonymousCallableIdentityRead::RecordBudgetExhausted { examined } => {
                            result.examined_records += examined;
                            result.gap =
                                Some(CatalogCallableValuesQueryGap::RecordBudgetExhausted {
                                    max_records: limits.max_records,
                                });
                            None
                        }
                        AnonymousCallableIdentityRead::Cancelled { examined } => {
                            result.examined_records += examined;
                            result.gap = Some(CatalogCallableValuesQueryGap::Cancelled);
                            None
                        }
                    };
                    result.facts.push(CatalogCallableValueFact {
                        manifest_digest: query.manifest_digest.to_owned(),
                        shard_id: query.shard_id.to_owned(),
                        callable: query.callable.to_owned(),
                        ordinal: row.0,
                        fact,
                        anonymous_callable,
                    });
                    if result.gap.is_some() {
                        break;
                    }
                }
            }
            CatalogCallableValuesQuestion::CallbackInvocation { callback, shape } => {
                let callback_json = json_text(callback, "callback query location")?;
                let mut statement =
                    connection
                        .prepare(CALLABLE_VALUES_CALLBACK_SQL)
                        .map_err(|error| {
                            CatalogError::sqlite("prepare callback-invocation query", error)
                        })?;
                let rows = statement
                    .query_map(
                        params![
                            query.manifest_digest,
                            query.shard_id,
                            query.callable,
                            callback_json,
                            shape.parameters,
                            shape.results,
                            limit,
                        ],
                        |row| {
                            Ok((
                                row.get::<_, i64>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, i64>(2)?,
                                row.get::<_, i64>(3)?,
                                row.get::<_, String>(4)?,
                                row.get::<_, String>(5)?,
                                row.get::<_, String>(6)?,
                                row.get::<_, String>(7)?,
                            ))
                        },
                    )
                    .map_err(|error| {
                        CatalogError::sqlite("query callback-invocation rows", error)
                    })?;
                for row in rows {
                    if cancellation.is_cancelled() {
                        result.gap = Some(CatalogCallableValuesQueryGap::Cancelled);
                        break;
                    }
                    let row = row.map_err(|error| {
                        CatalogError::sqlite("read callback-invocation row", error)
                    })?;
                    result.examined_records += 1;
                    if result.examined_records > limits.max_records {
                        result.gap = Some(CatalogCallableValuesQueryGap::RecordBudgetExhausted {
                            max_records: limits.max_records,
                        });
                        break;
                    }
                    let payload = CsmiCallableValuesPayload::CallbackInvocation {
                        callable: query.callable.to_owned(),
                        callback: decode_json_column(&row.1, "callback input location")?,
                        shape: CsmiCallableValuesShape {
                            parameters: u16::try_from(row.2).map_err(|error| {
                                CatalogError::Integrity(format!(
                                    "stored callback parameter shape is outside u16: {error}"
                                ))
                            })?,
                            results: u16::try_from(row.3).map_err(|error| {
                                CatalogError::Integrity(format!(
                                    "stored callback result shape is outside u16: {error}"
                                ))
                            })?,
                        },
                        arguments: decode_json_column(&row.4, "callback arguments")?,
                        timing: match row.5.as_str() {
                            "during-call" => CsmiCallableValuesTiming::DuringCall,
                            value => {
                                return Err(CatalogError::Integrity(format!(
                                    "unknown callable callback timing {value:?}"
                                )));
                            }
                        },
                        modality: match row.6.as_str() {
                            "may" => CsmiCallableValuesModality::May,
                            value => {
                                return Err(CatalogError::Integrity(format!(
                                    "unknown callable callback modality {value:?}"
                                )));
                            }
                        },
                    };
                    if let Err(error) = validate_callable_profile_location(&payload) {
                        result.gap =
                            Some(CatalogCallableValuesQueryGap::UnsupportedProjection(error));
                        break;
                    }
                    let fact = CallableValuesFact {
                        payload,
                        provenance: decode_json_column(&row.7, "callable fact provenance")?,
                    };
                    result.facts.push(CatalogCallableValueFact {
                        manifest_digest: query.manifest_digest.to_owned(),
                        shard_id: query.shard_id.to_owned(),
                        callable: query.callable.to_owned(),
                        ordinal: row.0,
                        fact,
                        anonymous_callable: None,
                    });
                }
            }
        }

        if result.gap.is_none() && cancellation.is_cancelled() {
            result.gap = Some(CatalogCallableValuesQueryGap::Cancelled);
        }
        if result.gap.is_none() {
            let remaining = limits.max_records.saturating_sub(result.examined_records);
            let coverage_limit = callable_values_sql_limit(remaining.saturating_add(1));
            let mut statement = connection
                .prepare(CALLABLE_VALUES_COVERAGE_SQL)
                .map_err(|error| CatalogError::sqlite("prepare callable coverage query", error))?;
            let rows = statement
                .query_map(
                    params![
                        query.manifest_digest,
                        query.shard_id,
                        callable_values_family_name(family),
                        query.callable,
                        coverage_limit,
                    ],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                        ))
                    },
                )
                .map_err(|error| CatalogError::sqlite("query callable coverage rows", error))?;
            for row in rows {
                if cancellation.is_cancelled() {
                    result.gap = Some(CatalogCallableValuesQueryGap::Cancelled);
                    break;
                }
                let row =
                    row.map_err(|error| CatalogError::sqlite("read callable coverage row", error))?;
                result.examined_records += 1;
                if result.examined_records > limits.max_records {
                    result.gap = Some(CatalogCallableValuesQueryGap::RecordBudgetExhausted {
                        max_records: limits.max_records,
                    });
                    break;
                }
                let coverage = CallableValuesCoverage {
                    family: parse_callable_values_family(&row.1)?,
                    callable: query.callable.to_owned(),
                    status: parse_coverage_status(&row.2)?,
                    limitations: decode_json_column(&row.3, "callable coverage limitations")?,
                    provenance: decode_json_column(&row.4, "callable coverage provenance")?,
                };
                result.coverage_claims.push(CatalogCallableValueCoverage {
                    manifest_digest: query.manifest_digest.to_owned(),
                    shard_id: query.shard_id.to_owned(),
                    callable: query.callable.to_owned(),
                    ordinal: row.0,
                    coverage,
                });
            }
        }
        if result.gap.is_none() && cancellation.is_cancelled() {
            result.gap = Some(CatalogCallableValuesQueryGap::Cancelled);
        }
        Ok(result)
    }
    fn query_callable_values_on_connection(
        connection: &Connection,
        query: &CatalogCallableValuesQuery<'_>,
        limits: CatalogCallableValuesQueryLimits,
        cancellation: &CancellationToken,
    ) -> Result<CatalogCallableValuesQueryResult, CatalogError> {
        let mut result = CatalogCallableValuesQueryResult {
            facts: Vec::new(),
            coverage_claims: Vec::new(),
            executable_coverage: CsmiCoverageStatus::Unknown,
            examined_records: 0,
            gap: None,
        };
        if cancellation.is_cancelled() {
            result.gap = Some(CatalogCallableValuesQueryGap::Cancelled);
            return Ok(result);
        }
        if limits.max_records == 0 {
            result.gap =
                Some(CatalogCallableValuesQueryGap::RecordBudgetExhausted { max_records: 0 });
            return Ok(result);
        }

        let limit = callable_values_sql_limit(limits.max_records.saturating_add(1));
        let family = match query.question {
            CatalogCallableValuesQuestion::ReturnedCallable { .. } => {
                CallableValuesFamily::ReturnedCallables
            }
            CatalogCallableValuesQuestion::CallbackInvocation { .. } => {
                CallableValuesFamily::CallbackInvocations
            }
        };

        match query.question {
            CatalogCallableValuesQuestion::ReturnedCallable {
                result: result_ordinal,
            } => {
                let mut statement =
                    connection
                        .prepare(CALLABLE_VALUES_RETURNED_SQL)
                        .map_err(|error| {
                            CatalogError::sqlite("prepare returned-callable query", error)
                        })?;
                let rows = statement
                    .query_map(
                        params![
                            query.manifest_digest,
                            query.shard_id,
                            query.callable,
                            result_ordinal,
                            limit,
                        ],
                        |row| {
                            Ok((
                                row.get::<_, i64>(0)?,
                                row.get::<_, i64>(1)?,
                                row.get::<_, String>(2)?,
                                row.get::<_, String>(3)?,
                            ))
                        },
                    )
                    .map_err(|error| CatalogError::sqlite("query returned-callable rows", error))?;
                for row in rows {
                    if cancellation.is_cancelled() {
                        result.gap = Some(CatalogCallableValuesQueryGap::Cancelled);
                        break;
                    }
                    let row = row.map_err(|error| {
                        CatalogError::sqlite("read returned-callable row", error)
                    })?;
                    result.examined_records += 1;
                    if result.examined_records > limits.max_records {
                        result.gap = Some(CatalogCallableValuesQueryGap::RecordBudgetExhausted {
                            max_records: limits.max_records,
                        });
                        break;
                    }
                    let payload = CsmiCallableValuesPayload::ReturnedCallable {
                        callable: query.callable.to_owned(),
                        result: u32::try_from(row.1).map_err(|error| {
                            CatalogError::Integrity(format!(
                                "stored callable result ordinal is outside u32: {error}"
                            ))
                        })?,
                        target: row.2.clone(),
                    };
                    let fact = CallableValuesFact {
                        payload,
                        provenance: decode_json_column(&row.3, "callable fact provenance")?,
                    };
                    let anonymous_callable = match load_anonymous_callable_identity(
                        connection,
                        query.manifest_digest,
                        query.shard_id,
                        &row.2,
                        limits.max_records.saturating_sub(result.examined_records),
                        cancellation,
                    )? {
                        AnonymousCallableIdentityRead::Missing => None,
                        AnonymousCallableIdentityRead::Found { identity, examined } => {
                            result.examined_records += examined;
                            Some(*identity)
                        }
                        AnonymousCallableIdentityRead::RecordBudgetExhausted { examined } => {
                            result.examined_records += examined;
                            result.gap =
                                Some(CatalogCallableValuesQueryGap::RecordBudgetExhausted {
                                    max_records: limits.max_records,
                                });
                            None
                        }
                        AnonymousCallableIdentityRead::Cancelled { examined } => {
                            result.examined_records += examined;
                            result.gap = Some(CatalogCallableValuesQueryGap::Cancelled);
                            None
                        }
                    };
                    result.facts.push(CatalogCallableValueFact {
                        manifest_digest: query.manifest_digest.to_owned(),
                        shard_id: query.shard_id.to_owned(),
                        callable: query.callable.to_owned(),
                        ordinal: row.0,
                        fact,
                        anonymous_callable,
                    });
                    if result.gap.is_some() {
                        break;
                    }
                }
            }
            CatalogCallableValuesQuestion::CallbackInvocation { callback, shape } => {
                let callback_json = json_text(callback, "callback query location")?;
                let mut statement =
                    connection
                        .prepare(CALLABLE_VALUES_CALLBACK_SQL)
                        .map_err(|error| {
                            CatalogError::sqlite("prepare callback-invocation query", error)
                        })?;
                let rows = statement
                    .query_map(
                        params![
                            query.manifest_digest,
                            query.shard_id,
                            query.callable,
                            callback_json,
                            shape.parameters,
                            shape.results,
                            limit,
                        ],
                        |row| {
                            Ok((
                                row.get::<_, i64>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, i64>(2)?,
                                row.get::<_, i64>(3)?,
                                row.get::<_, String>(4)?,
                                row.get::<_, String>(5)?,
                                row.get::<_, String>(6)?,
                                row.get::<_, String>(7)?,
                            ))
                        },
                    )
                    .map_err(|error| {
                        CatalogError::sqlite("query callback-invocation rows", error)
                    })?;
                for row in rows {
                    if cancellation.is_cancelled() {
                        result.gap = Some(CatalogCallableValuesQueryGap::Cancelled);
                        break;
                    }
                    let row = row.map_err(|error| {
                        CatalogError::sqlite("read callback-invocation row", error)
                    })?;
                    result.examined_records += 1;
                    if result.examined_records > limits.max_records {
                        result.gap = Some(CatalogCallableValuesQueryGap::RecordBudgetExhausted {
                            max_records: limits.max_records,
                        });
                        break;
                    }
                    let payload = CsmiCallableValuesPayload::CallbackInvocation {
                        callable: query.callable.to_owned(),
                        callback: decode_json_column(&row.1, "callback input location")?,
                        shape: CsmiCallableValuesShape {
                            parameters: u16::try_from(row.2).map_err(|error| {
                                CatalogError::Integrity(format!(
                                    "stored callback parameter shape is outside u16: {error}"
                                ))
                            })?,
                            results: u16::try_from(row.3).map_err(|error| {
                                CatalogError::Integrity(format!(
                                    "stored callback result shape is outside u16: {error}"
                                ))
                            })?,
                        },
                        arguments: decode_json_column(&row.4, "callback arguments")?,
                        timing: match row.5.as_str() {
                            "during-call" => CsmiCallableValuesTiming::DuringCall,
                            value => {
                                return Err(CatalogError::Integrity(format!(
                                    "unknown callable callback timing {value:?}"
                                )));
                            }
                        },
                        modality: match row.6.as_str() {
                            "may" => CsmiCallableValuesModality::May,
                            value => {
                                return Err(CatalogError::Integrity(format!(
                                    "unknown callable callback modality {value:?}"
                                )));
                            }
                        },
                    };
                    if let Err(error) = validate_callable_profile_location(&payload) {
                        result.gap =
                            Some(CatalogCallableValuesQueryGap::UnsupportedProjection(error));
                        break;
                    }
                    let fact = CallableValuesFact {
                        payload,
                        provenance: decode_json_column(&row.7, "callable fact provenance")?,
                    };
                    result.facts.push(CatalogCallableValueFact {
                        manifest_digest: query.manifest_digest.to_owned(),
                        shard_id: query.shard_id.to_owned(),
                        callable: query.callable.to_owned(),
                        ordinal: row.0,
                        fact,
                        anonymous_callable: None,
                    });
                }
            }
        }

        if result.gap.is_none() && cancellation.is_cancelled() {
            result.gap = Some(CatalogCallableValuesQueryGap::Cancelled);
        }
        if result.gap.is_none() {
            let remaining = limits.max_records.saturating_sub(result.examined_records);
            let coverage_limit = callable_values_sql_limit(remaining.saturating_add(1));
            let mut statement = connection
                .prepare(CALLABLE_VALUES_COVERAGE_SQL)
                .map_err(|error| CatalogError::sqlite("prepare callable coverage query", error))?;
            let rows = statement
                .query_map(
                    params![
                        query.manifest_digest,
                        query.shard_id,
                        callable_values_family_name(family),
                        query.callable,
                        coverage_limit,
                    ],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                        ))
                    },
                )
                .map_err(|error| CatalogError::sqlite("query callable coverage rows", error))?;
            for row in rows {
                if cancellation.is_cancelled() {
                    result.gap = Some(CatalogCallableValuesQueryGap::Cancelled);
                    break;
                }
                let row =
                    row.map_err(|error| CatalogError::sqlite("read callable coverage row", error))?;
                result.examined_records += 1;
                if result.examined_records > limits.max_records {
                    result.gap = Some(CatalogCallableValuesQueryGap::RecordBudgetExhausted {
                        max_records: limits.max_records,
                    });
                    break;
                }
                let coverage = CallableValuesCoverage {
                    family: parse_callable_values_family(&row.1)?,
                    callable: query.callable.to_owned(),
                    status: parse_coverage_status(&row.2)?,
                    limitations: decode_json_column(&row.3, "callable coverage limitations")?,
                    provenance: decode_json_column(&row.4, "callable coverage provenance")?,
                };
                result.coverage_claims.push(CatalogCallableValueCoverage {
                    manifest_digest: query.manifest_digest.to_owned(),
                    shard_id: query.shard_id.to_owned(),
                    callable: query.callable.to_owned(),
                    ordinal: row.0,
                    coverage,
                });
            }
        }
        if result.gap.is_none() && cancellation.is_cancelled() {
            result.gap = Some(CatalogCallableValuesQueryGap::Cancelled);
        }
        Ok(result)
    }

    fn callable_values_publication_present(
        connection: &Connection,
        manifest_digest: &str,
        shard_id: &str,
    ) -> Result<bool, CatalogError> {
        connection
            .query_row(
                "SELECT EXISTS(
               SELECT 1
               FROM catalog_callable_values_indexed_shards AS indexed
               JOIN catalog_packs AS pack
                 ON pack.manifest_digest = indexed.manifest_digest
               JOIN catalog_pack_shards AS shard
                 ON shard.manifest_digest = indexed.manifest_digest
                AND shard.shard_id = indexed.shard_id
               WHERE indexed.manifest_digest = ?1
                 AND indexed.shard_id = ?2
                 AND indexed.index_version = 1
                 AND pack.state = 'verified')",
                params![manifest_digest, shard_id],
                |row| row.get(0),
            )
            .map_err(|error| CatalogError::sqlite("check callable-values publication", error))
    }

    fn callable_values_index_missing_result(
        limits: CatalogCallableValuesQueryLimits,
    ) -> CatalogCallableValuesQueryResult {
        CatalogCallableValuesQueryResult {
            facts: Vec::new(),
            coverage_claims: Vec::new(),
            executable_coverage: CsmiCoverageStatus::Unknown,
            examined_records: 0,
            gap: Some(if limits.max_records == 0 {
                CatalogCallableValuesQueryGap::RecordBudgetExhausted { max_records: 0 }
            } else {
                CatalogCallableValuesQueryGap::IndexReconciliationRequired
            }),
        }
    }

    fn read_go_source_from_connection(
        connection: &Connection,
        request: &CatalogGoSourceRequest<'_>,
        limits: CatalogGoSourceReadLimits,
        cancellation: &CancellationToken,
    ) -> Result<Option<CatalogExactGoSourceSet>, CatalogError> {
        if cancellation.is_cancelled() {
            return Err(CatalogError::Cancelled);
        }
        if !is_lower_sha256(request.manifest_digest)
            || !is_lower_sha256(request.artifact_sha256)
            || request.manifest_digest.is_empty()
            || request.shard_id.is_empty()
            || request.package_import_path.is_empty()
            || !is_canonical_relative_path(request.file)
        {
            return Err(CatalogError::Integrity(
                "exact Go source request contains a non-canonical identity".to_owned(),
            ));
        }
        if limits.max_files == 0 || limits.max_source_bytes == 0 {
            return Err(CatalogError::SourceBudgetExhausted {
                max_files: limits.max_files,
                max_source_bytes: limits.max_source_bytes,
            });
        }
        let published: bool = connection
            .query_row(
                "SELECT EXISTS(
               SELECT 1
               FROM catalog_packs AS pack
               JOIN catalog_pack_shards AS shard
                 ON shard.manifest_digest = pack.manifest_digest
               WHERE pack.manifest_digest = ?1
                 AND pack.state = 'verified'
                 AND shard.shard_id = ?2)",
                params![request.manifest_digest, request.shard_id],
                |row| row.get(0),
            )
            .map_err(|error| CatalogError::sqlite("check exact Go source publication", error))?;
        if !published {
            return Ok(None);
        }
        let artifact_activated: bool = connection
            .query_row(
                "SELECT EXISTS(
               SELECT 1
               FROM catalog_selectors INDEXED BY catalog_selectors_artifact
               WHERE manifest_digest = ?1
                 AND shard_id = ?2
                 AND artifact_sha256 = ?3)",
                params![
                    request.manifest_digest,
                    request.shard_id,
                    request.artifact_sha256,
                ],
                |row| row.get(0),
            )
            .map_err(|error| CatalogError::sqlite("check exact Go source activation", error))?;
        if !artifact_activated {
            return Ok(None);
        }
        let source_set_present: bool = connection
            .query_row(
                "SELECT EXISTS(
               SELECT 1 FROM catalog_exact_go_source_sets
               WHERE manifest_digest = ?1 AND artifact_sha256 = ?2)",
                params![request.manifest_digest, request.artifact_sha256],
                |row| row.get(0),
            )
            .map_err(|error| CatalogError::sqlite("check exact Go source set", error))?;
        if !source_set_present {
            return Ok(None);
        }

        let mut file_statement = connection
            .prepare(
                "SELECT relative_path, source_text,
                    length(CAST(relative_path AS BLOB)),
                    length(CAST(source_text AS BLOB))
             FROM catalog_exact_go_source_files
                  INDEXED BY catalog_exact_go_source_files_read
             WHERE manifest_digest = ?1 AND artifact_sha256 = ?2
             ORDER BY relative_path",
            )
            .map_err(|error| CatalogError::sqlite("prepare exact Go source files", error))?;
        let mut file_rows = file_statement
            .query(params![request.manifest_digest, request.artifact_sha256])
            .map_err(|error| CatalogError::sqlite("query exact Go source files", error))?;
        let mut entries = Vec::new();
        let mut source_bytes = 0_u64;
        while let Some(row) = file_rows
            .next()
            .map_err(|error| CatalogError::sqlite("read exact Go source files", error))?
        {
            if cancellation.is_cancelled() {
                return Err(CatalogError::Cancelled);
            }
            if entries.len() >= limits.max_files {
                return Err(CatalogError::SourceBudgetExhausted {
                    max_files: limits.max_files,
                    max_source_bytes: limits.max_source_bytes,
                });
            }
            let path_bytes = row
                .get::<_, i64>(2)
                .map_err(|error| CatalogError::sqlite("read exact Go source path length", error))?;
            let source_text_bytes = row
                .get::<_, i64>(3)
                .map_err(|error| CatalogError::sqlite("read exact Go source text length", error))?;
            let path_bytes = u64::try_from(path_bytes).map_err(|error| {
                CatalogError::Integrity(format!(
                    "exact Go source path byte length is invalid: {error}"
                ))
            })?;
            let source_text_bytes = u64::try_from(source_text_bytes).map_err(|error| {
                CatalogError::Integrity(format!(
                    "exact Go source text byte length is invalid: {error}"
                ))
            })?;
            source_bytes = source_bytes
                .checked_add(path_bytes)
                .and_then(|bytes| bytes.checked_add(source_text_bytes))
                .ok_or_else(|| {
                    CatalogError::Integrity("exact Go source byte count overflowed".to_owned())
                })?;
            if source_bytes > limits.max_source_bytes {
                return Err(CatalogError::SourceBudgetExhausted {
                    max_files: limits.max_files,
                    max_source_bytes: limits.max_source_bytes,
                });
            }
            let path = row
                .get::<_, String>(0)
                .map_err(|error| CatalogError::sqlite("read exact Go source path", error))?;
            let source = row
                .get::<_, String>(1)
                .map_err(|error| CatalogError::sqlite("read exact Go source text", error))?;
            entries.push((path, source.into_bytes()));
        }
        drop(file_rows);
        drop(file_statement);

        let mut package_statement = connection
            .prepare(
                "SELECT package_ordinal, import_path, package_name,
                    length(CAST(import_path AS BLOB)),
                    length(CAST(package_name AS BLOB))
             FROM catalog_exact_go_packages INDEXED BY catalog_exact_go_packages_read
             WHERE manifest_digest = ?1 AND artifact_sha256 = ?2
             ORDER BY package_ordinal",
            )
            .map_err(|error| CatalogError::sqlite("prepare exact Go packages", error))?;
        let mut package_rows = package_statement
            .query(params![request.manifest_digest, request.artifact_sha256])
            .map_err(|error| CatalogError::sqlite("query exact Go packages", error))?;
        let mut packages: Vec<(usize, GoPinnedPackage)> = Vec::new();
        while let Some(row) = package_rows
            .next()
            .map_err(|error| CatalogError::sqlite("read exact Go packages", error))?
        {
            if cancellation.is_cancelled() {
                return Err(CatalogError::Cancelled);
            }
            if packages.len() >= limits.max_files {
                return Err(CatalogError::SourceBudgetExhausted {
                    max_files: limits.max_files,
                    max_source_bytes: limits.max_source_bytes,
                });
            }
            let import_path_bytes = row
                .get::<_, i64>(3)
                .map_err(|error| CatalogError::sqlite("read exact Go import path length", error))?;
            let package_name_bytes = row.get::<_, i64>(4).map_err(|error| {
                CatalogError::sqlite("read exact Go package name length", error)
            })?;
            let import_path_bytes = u64::try_from(import_path_bytes).map_err(|error| {
                CatalogError::Integrity(format!(
                    "exact Go import path byte length is invalid: {error}"
                ))
            })?;
            let package_name_bytes = u64::try_from(package_name_bytes).map_err(|error| {
                CatalogError::Integrity(format!(
                    "exact Go package name byte length is invalid: {error}"
                ))
            })?;
            source_bytes = source_bytes
                .checked_add(import_path_bytes)
                .and_then(|bytes| bytes.checked_add(package_name_bytes))
                .ok_or_else(|| {
                    CatalogError::Integrity("exact Go source byte count overflowed".to_owned())
                })?;
            if source_bytes > limits.max_source_bytes {
                return Err(CatalogError::SourceBudgetExhausted {
                    max_files: limits.max_files,
                    max_source_bytes: limits.max_source_bytes,
                });
            }
            let ordinal = row
                .get::<_, i64>(0)
                .map_err(|error| CatalogError::sqlite("read exact Go package ordinal", error))?;
            let import_path = row
                .get::<_, String>(1)
                .map_err(|error| CatalogError::sqlite("read exact Go import path", error))?;
            let name = row
                .get::<_, String>(2)
                .map_err(|error| CatalogError::sqlite("read exact Go package name", error))?;
            let ordinal = usize::try_from(ordinal).map_err(|error| {
                CatalogError::Integrity(format!(
                    "stored Go package ordinal is outside usize: {error}"
                ))
            })?;
            if ordinal != packages.len() {
                return Err(CatalogError::Integrity(format!(
                    "stored Go package ordinals are not contiguous at {ordinal}"
                )));
            }
            packages.push((
                ordinal,
                GoPinnedPackage {
                    import_path,
                    name,
                    files: Vec::new(),
                },
            ));
        }
        drop(package_rows);
        drop(package_statement);
        let mut file_statement = connection
            .prepare(
                "SELECT package_ordinal, file_ordinal, relative_path,
                    length(CAST(relative_path AS BLOB))
             FROM catalog_exact_go_package_files
                  INDEXED BY catalog_exact_go_package_files_ordered_read
             WHERE manifest_digest = ?1 AND artifact_sha256 = ?2
             ORDER BY package_ordinal, file_ordinal",
            )
            .map_err(|error| CatalogError::sqlite("prepare exact Go package files", error))?;
        let mut file_rows = file_statement
            .query(params![request.manifest_digest, request.artifact_sha256])
            .map_err(|error| CatalogError::sqlite("query exact Go package files", error))?;
        let mut package_index = 0_usize;
        let mut current_package_ordinal = None;
        let mut next_file_ordinal = 0_usize;
        let mut membership_rows = 0_usize;
        while let Some(row) = file_rows
            .next()
            .map_err(|error| CatalogError::sqlite("read exact Go package files", error))?
        {
            if cancellation.is_cancelled() {
                return Err(CatalogError::Cancelled);
            }
            if membership_rows >= limits.max_files {
                return Err(CatalogError::SourceBudgetExhausted {
                    max_files: limits.max_files,
                    max_source_bytes: limits.max_source_bytes,
                });
            }
            let file_bytes = row.get::<_, i64>(3).map_err(|error| {
                CatalogError::sqlite("read exact Go package file path length", error)
            })?;
            let file_bytes = u64::try_from(file_bytes).map_err(|error| {
                CatalogError::Integrity(format!(
                    "exact Go package file path byte length is invalid: {error}"
                ))
            })?;
            source_bytes = source_bytes.checked_add(file_bytes).ok_or_else(|| {
                CatalogError::Integrity("exact Go source byte count overflowed".to_owned())
            })?;
            if source_bytes > limits.max_source_bytes {
                return Err(CatalogError::SourceBudgetExhausted {
                    max_files: limits.max_files,
                    max_source_bytes: limits.max_source_bytes,
                });
            }
            let ordinal = row
                .get::<_, i64>(0)
                .map_err(|error| CatalogError::sqlite("read exact Go package ordinal", error))?;
            let file_ordinal = row
                .get::<_, i64>(1)
                .map_err(|error| CatalogError::sqlite("read exact Go file ordinal", error))?;
            let file = row
                .get::<_, String>(2)
                .map_err(|error| CatalogError::sqlite("read exact Go package file path", error))?;
            membership_rows += 1;
            let ordinal = usize::try_from(ordinal).map_err(|error| {
                CatalogError::Integrity(format!(
                    "stored Go package ordinal is outside usize: {error}"
                ))
            })?;
            while package_index < packages.len() && packages[package_index].0 < ordinal {
                package_index += 1;
            }
            let Some((package_ordinal, package)) = packages.get_mut(package_index) else {
                return Err(CatalogError::Integrity(format!(
                    "exact Go package file references missing package ordinal {ordinal}"
                )));
            };
            if *package_ordinal != ordinal {
                return Err(CatalogError::Integrity(format!(
                    "exact Go package file references missing package ordinal {ordinal}"
                )));
            }
            let file_ordinal = usize::try_from(file_ordinal).map_err(|error| {
                CatalogError::Integrity(format!("stored Go file ordinal is outside usize: {error}"))
            })?;
            if current_package_ordinal != Some(ordinal) {
                next_file_ordinal = 0;
                current_package_ordinal = Some(ordinal);
            }
            if file_ordinal != next_file_ordinal {
                return Err(CatalogError::Integrity(format!(
                    "stored Go file ordinals are not contiguous at package {ordinal}, file {file_ordinal}"
                )));
            }
            next_file_ordinal += 1;
            package.files.push(file);
        }
        drop(file_rows);
        drop(file_statement);
        let packages = packages
            .into_iter()
            .map(|(_, package)| package)
            .collect::<Vec<_>>();
        if !packages.iter().any(|package| {
            package.import_path == request.package_import_path
                && package.files.iter().any(|file| file == request.file)
        }) {
            return Ok(None);
        }
        let artifact = ExactArtifact::from_source_entries(
            PathBuf::from("<catalog exact Go source set>"),
            entries,
            limits.max_path_depth,
            &ArtifactProducerLimits {
                max_artifact_bytes: u64::MAX,
                ..ArtifactProducerLimits::default()
            },
        )
        .map_err(|diagnostic| CatalogError::Artifact(diagnostic.message))?;
        if artifact.sha256() != request.artifact_sha256 {
            return Err(CatalogError::Integrity(format!(
                "exact Go source rows hash to {}, expected {}",
                artifact.sha256(),
                request.artifact_sha256
            )));
        }
        validate_exact_go_source(&artifact, &packages)?;
        Ok(Some(CatalogExactGoSourceSet { artifact, packages }))
    }

    fn ensure_callable_values_indexed(
        &self,
        manifest_digest: &str,
        shard_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<CallableValuesIndexReadiness, CatalogError> {
        if cancellation.is_cancelled() {
            return Ok(CallableValuesIndexReadiness::Cancelled);
        }
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let indexed: bool = connection
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM catalog_callable_values_indexed_shards AS indexed
                   JOIN catalog_packs AS pack
                     ON pack.manifest_digest = indexed.manifest_digest
                   WHERE indexed.manifest_digest = ?1 AND indexed.shard_id = ?2
                     AND indexed.index_version = 1 AND pack.state = 'verified'
                 )",
                params![manifest_digest, shard_id],
                |row| row.get(0),
            )
            .map_err(|error| CatalogError::sqlite("check callable-value shard index", error))?;
        if indexed {
            return Ok(CallableValuesIndexReadiness::Ready);
        }
        if cancellation.is_cancelled() {
            return Ok(CallableValuesIndexReadiness::Cancelled);
        }
        Ok(CallableValuesIndexReadiness::Missing)
    }

    fn ensure_session_callable_values_indexed(
        &self,
        manifest_digest: &str,
        shard_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<CallableValuesIndexReadiness, CatalogError> {
        if cancellation.is_cancelled() {
            return Ok(CallableValuesIndexReadiness::Cancelled);
        }
        let session_catalog = self
            .session_callable_values
            .lock()
            .expect("session callable-values connection mutex poisoned");
        let Some(session_catalog) = session_catalog.as_ref() else {
            return Ok(CallableValuesIndexReadiness::Missing);
        };
        let indexed: bool = session_catalog
            .connection
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM catalog_callable_values_indexed_shards AS indexed
                   JOIN catalog_packs AS pack
                     ON pack.manifest_digest = indexed.manifest_digest
                   JOIN catalog_pack_shards AS shard
                     ON shard.manifest_digest = indexed.manifest_digest
                    AND shard.shard_id = indexed.shard_id
                   WHERE indexed.manifest_digest = ?1 AND indexed.shard_id = ?2
                     AND indexed.index_version = 1 AND pack.state = 'verified'
                 )",
                params![manifest_digest, shard_id],
                |row| row.get(0),
            )
            .map_err(|error| {
                CatalogError::sqlite("check session callable-value shard index", error)
            })?;
        if cancellation.is_cancelled() {
            return Ok(CallableValuesIndexReadiness::Cancelled);
        }
        Ok(if indexed {
            CallableValuesIndexReadiness::Ready
        } else {
            CallableValuesIndexReadiness::Missing
        })
    }

    pub fn accounting(&self) -> Result<CatalogAccounting, CatalogError> {
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let installed_stored_bytes = connection
            .query_row(
                "SELECT COALESCE(SUM(stored_size), 0)
                 FROM catalog_objects
                 WHERE stored_digest IN (
                   SELECT DISTINCT stored_digest FROM catalog_pack_shards
                 )",
                [],
                |row| row.get::<_, u64>(0),
            )
            .map_err(|error| CatalogError::sqlite("account installed bytes", error))?;
        let mut active_object_sizes = HashMap::new();
        let mut object_statement = connection
            .prepare(
                "SELECT DISTINCT objects.stored_digest, objects.stored_size
                 FROM catalog_objects AS objects
                 JOIN catalog_pack_shards AS shards
                   ON shards.stored_digest = objects.stored_digest
                 JOIN catalog_activations AS active
                   ON active.manifest_digest = shards.manifest_digest",
            )
            .map_err(|error| CatalogError::sqlite("prepare active byte accounting", error))?;
        let object_rows = object_statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
            })
            .map_err(|error| CatalogError::sqlite("query active byte accounting", error))?;
        for row in object_rows {
            let (digest, stored_size) =
                row.map_err(|error| CatalogError::sqlite("read active byte accounting", error))?;
            active_object_sizes.insert(digest, stored_size);
        }
        let mut active_shards = HashSet::new();
        let mut shard_statement = connection
            .prepare(
                "SELECT DISTINCT shards.manifest_digest, shards.shard_id
                 FROM catalog_pack_shards AS shards
                 JOIN catalog_activations AS active
                   ON active.manifest_digest = shards.manifest_digest",
            )
            .map_err(|error| CatalogError::sqlite("prepare active shard accounting", error))?;
        let shard_rows = shard_statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|error| CatalogError::sqlite("query active shard accounting", error))?;
        for row in shard_rows {
            active_shards.insert(
                row.map_err(|error| CatalogError::sqlite("read active shard accounting", error))?,
            );
        }
        let mut activation_statement = connection
            .prepare(
                "SELECT source_kind, source_id, COUNT(*)
                 FROM catalog_activations
                 GROUP BY source_kind, source_id
                 ORDER BY source_kind, source_id",
            )
            .map_err(|error| CatalogError::sqlite("prepare activation accounting", error))?;
        let activation_rows = activation_statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u64>(2)?,
                ))
            })
            .map_err(|error| CatalogError::sqlite("query activation accounting", error))?;
        let mut activation_counts = HashMap::new();
        for row in activation_rows {
            let (source_kind, source_id, pack_count) =
                row.map_err(|error| CatalogError::sqlite("read activation accounting", error))?;
            activation_counts.insert(
                (CatalogPackSourceKind::parse(&source_kind)?, source_id),
                pack_count,
            );
        }
        let mut session_activations = self
            .session_activations
            .lock()
            .expect("semantic-pack session activation mutex poisoned");
        session_activations.retain(|_, activation| activation.owner.upgrade().is_some());
        let mut active_session_digests = HashSet::new();
        for activation in session_activations.values() {
            for member in &activation.active_set.members {
                let source_kind = activation_catalog_kind(member.source_kind);
                *activation_counts
                    .entry((source_kind, member.source_id.clone()))
                    .or_insert(0) += 1;
                active_session_digests.insert(member.manifest_digest.clone());
            }
        }
        let session_packs = self
            .session_packs
            .lock()
            .expect("semantic-pack session mutex poisoned");
        for pack in session_packs.iter() {
            if !active_session_digests.contains(&pack.manifest.content_sha256) {
                continue;
            }
            for shard in &pack.shards {
                active_shards.insert((
                    pack.manifest.content_sha256.clone(),
                    shard.descriptor.shard_id.clone(),
                ));
                active_object_sizes
                    .entry(shard.descriptor.stored_sha256.clone())
                    .or_insert(shard.descriptor.stored_size);
            }
        }
        let active_stored_bytes =
            active_object_sizes
                .values()
                .try_fold(0_u64, |total, stored_size| {
                    total.checked_add(*stored_size).ok_or_else(|| {
                        CatalogError::Integrity("active byte accounting overflowed".to_owned())
                    })
                })?;
        let active_shard_count = u64::try_from(active_shards.len())
            .map_err(|_| CatalogError::Integrity("active shard count exceeds u64".to_owned()))?;
        let mut activations = activation_counts
            .into_iter()
            .map(
                |((source_kind, source_id), pack_count)| ActivationSourceCount {
                    source_kind,
                    source_id,
                    pack_count,
                },
            )
            .collect::<Vec<_>>();
        activations.sort_by(|left, right| {
            left.source_kind
                .precedence()
                .cmp(&right.source_kind.precedence())
                .then_with(|| left.source_id.cmp(&right.source_id))
        });
        Ok(CatalogAccounting {
            installed_stored_bytes,
            active_stored_bytes,
            object_count: count(&connection, "catalog_objects")?,
            logical_shard_count: count(&connection, "catalog_pack_shards")?,
            active_shard_count,
            source_count: count(&connection, "catalog_sources")?,
            lookup_hits: self.lookup_hits.load(Ordering::Relaxed),
            lookup_misses: self.lookup_misses.load(Ordering::Relaxed),
            quarantined_pack_count: connection
                .query_row(
                    "SELECT COUNT(*) FROM catalog_packs WHERE state = 'quarantined'",
                    [],
                    |row| row.get(0),
                )
                .map_err(|error| CatalogError::sqlite("account quarantined packs", error))?,
            activations,
        })
    }

    fn load_inner(&self, candidate: &CatalogCandidate) -> Result<LoadedCatalogShard, CatalogError> {
        match candidate.location {
            CatalogCandidateLocation::Durable if self.mode == CatalogOpenMode::ReadWrite => {
                let lease = self.lease(
                    &candidate.manifest_digest,
                    "verified-load",
                    Duration::from_secs(60),
                )?;
                let loaded = self.load_durable(candidate);
                let released = lease.release();
                match (loaded, released) {
                    (Ok(loaded), Ok(())) => Ok(loaded),
                    (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
                    (Err(error), Err(release_error)) => Err(CatalogError::Integrity(format!(
                        "{error}; failed to release load lease: {release_error}"
                    ))),
                }
            }
            CatalogCandidateLocation::Durable => self.load_durable(candidate),
            CatalogCandidateLocation::Session {
                pack_ordinal,
                shard_ordinal,
            } => self.load_session(candidate, pack_ordinal, shard_ordinal),
        }
    }

    fn load_durable(
        &self,
        candidate: &CatalogCandidate,
    ) -> Result<LoadedCatalogShard, CatalogError> {
        // The manifest comes from the memo, not from this statement: a pack
        // with 44 shards used to ship its multi-megabyte manifest bytes out of
        // SQLite once per loaded shard (#3101).
        let manifest = self.stored_manifest(&candidate.manifest_digest)?;
        self.validate_stored_python_profile_pack(&manifest)?;
        let mut connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        self.sql_statements.fetch_add(1, Ordering::Relaxed);
        let row = connection
            .query_row(
                "SELECT o.relative_path, o.stored_size
                 FROM catalog_packs AS p
                 JOIN catalog_pack_shards AS ps
                   ON ps.manifest_digest = p.manifest_digest
                 JOIN catalog_objects AS o
                   ON o.stored_digest = ps.stored_digest
                 WHERE p.state = 'verified'
                   AND p.manifest_digest = ?1
                   AND ps.shard_id = ?2
                   AND ps.stored_digest = ?3",
                params![
                    &candidate.manifest_digest,
                    &candidate.shard_id,
                    &candidate.descriptor.stored_sha256
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?)),
            )
            .optional()
            .map_err(|error| CatalogError::sqlite("load candidate location", error))?
            .ok_or(CatalogError::Unavailable)?;
        self.object_reads.fetch_add(1, Ordering::Relaxed);
        let bytes = storage::read(
            &self.root,
            &row.0,
            &candidate.descriptor.stored_sha256,
            row.1,
        )?;
        self.validated_manifest_inventory(&manifest)?;
        let limits_digest = decode_limits_digest(&self.options.decode_limits);
        self.sql_statements.fetch_add(1, Ordering::Relaxed);
        let certified: bool = connection
            .query_row(
                CERTIFIED_SHARD_SQL,
                params![
                    manifest.content_sha256,
                    candidate.shard_id,
                    SHARD_VALIDATION_VERSION,
                    limits_digest
                ],
                |row| row.get(0),
            )
            .map_err(|error| CatalogError::sqlite("lookup shard validation", error))?;
        let shard = if certified {
            super::artifact::hydrate_certified_shard(
                &manifest,
                &candidate.descriptor,
                &bytes,
                &self.options.decode_limits,
            )
            .map_err(|error| CatalogError::Artifact(error.to_string()))?
        } else {
            let shard = self.decode_stored_shard(&manifest, &candidate.descriptor, &bytes)?;
            if self.mode == CatalogOpenMode::ReadWrite {
                record_shard_validation(
                    &connection,
                    &manifest.content_sha256,
                    &candidate.shard_id,
                    &limits_digest,
                )?;
            }
            shard
        };
        if self.mode == CatalogOpenMode::ReadWrite {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|error| {
                    CatalogError::sqlite("begin callable-value load reconciliation", error)
                })?;
            let indexed: bool = transaction
                .query_row(
                    "SELECT EXISTS(
                       SELECT 1 FROM catalog_callable_values_indexed_shards
                       WHERE manifest_digest = ?1 AND shard_id = ?2 AND index_version = 1
                     )",
                    params![&candidate.manifest_digest, &candidate.shard_id],
                    |row| row.get(0),
                )
                .map_err(|error| CatalogError::sqlite("check callable-value load index", error))?;
            if !indexed {
                publish_callable_value_rows(
                    &transaction,
                    &candidate.manifest_digest,
                    &candidate.shard_id,
                    shard.callable_values.as_ref(),
                )?;
            }
            transaction.commit().map_err(|error| {
                CatalogError::sqlite("commit callable-value load reconciliation", error)
            })?;
            if !indexed {
                self.record_mutation();
            }
            connection
                .execute(
                    "UPDATE catalog_packs SET last_used_at = ?2 WHERE manifest_digest = ?1",
                    params![
                        &candidate.manifest_digest,
                        crate::cache_db::now_unix_seconds()
                    ],
                )
                .map_err(|error| CatalogError::sqlite("touch loaded pack", error))?;
        }
        Ok(LoadedCatalogShard {
            manifest,
            shard,
            source_kind: candidate.source_kind,
            source_id: candidate.source_id.clone(),
        })
    }

    fn load_session(
        &self,
        candidate: &CatalogCandidate,
        pack_ordinal: usize,
        shard_ordinal: usize,
    ) -> Result<LoadedCatalogShard, CatalogError> {
        let session_packs = self
            .session_packs
            .lock()
            .expect("semantic-pack session mutex poisoned");
        let pack = session_packs
            .get(pack_ordinal)
            .ok_or(CatalogError::Unavailable)?;
        let shard = pack
            .shards
            .get(shard_ordinal)
            .ok_or(CatalogError::Unavailable)?;
        if pack.manifest.content_sha256 != candidate.manifest_digest
            || shard.descriptor != candidate.descriptor
        {
            return Err(CatalogError::Unavailable);
        }
        let decoded = self.decode_stored_shard(&pack.manifest, &shard.descriptor, &shard.bytes)?;
        Ok(LoadedCatalogShard {
            manifest: Arc::clone(&pack.manifest),
            shard: decoded,
            source_kind: candidate.source_kind,
            source_id: candidate.source_id.clone(),
        })
    }

    pub fn garbage_collect(
        &self,
        options: &CatalogGcOptions,
    ) -> Result<CatalogGcOutcome, CatalogError> {
        self.require_writable()?;
        let now = crate::cache_db::now_unix_seconds();
        let minimum_age = i64::try_from(options.minimum_age.as_secs()).map_err(|_| {
            CatalogError::Integrity("catalog GC minimum age exceeds i64".to_owned())
        })?;
        let cutoff = now
            .checked_sub(minimum_age)
            .ok_or_else(|| CatalogError::Integrity("catalog GC cutoff underflowed".to_owned()))?;
        let max_packs = i64::try_from(options.max_packs)
            .map_err(|_| CatalogError::Integrity("catalog GC limit exceeds i64".to_owned()))?;
        let max_objects = i64::try_from(options.max_objects).map_err(|_| {
            CatalogError::Integrity("catalog GC object limit exceeds i64".to_owned())
        })?;

        let (pack_digests, object_candidates, pruned_expired_leases) = {
            let mut connection = self
                .connection
                .lock()
                .expect("semantic-pack catalog connection mutex poisoned");
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|error| CatalogError::sqlite("begin catalog GC", error))?;
            let pruned_expired_leases = transaction
                .execute("DELETE FROM catalog_leases WHERE expires_at <= ?1", [now])
                .map_err(|error| CatalogError::sqlite("prune expired pack leases", error))?;
            transaction
                .execute(
                    "DELETE FROM catalog_install_object_reservations
                     WHERE expires_at <= ?1",
                    [now],
                )
                .map_err(|error| CatalogError::sqlite("prune install reservations", error))?;
            let pack_digests = {
                let mut statement = transaction
                    .prepare(
                        "SELECT packs.manifest_digest
                         FROM catalog_packs AS packs
                         WHERE COALESCE(packs.last_used_at, packs.installed_at) <= ?1
                           AND NOT EXISTS(
                             SELECT 1 FROM catalog_sources AS sources
                             WHERE sources.manifest_digest = packs.manifest_digest
                               AND sources.source_kind <> 'generated'
                           )
                           AND NOT EXISTS(
                             SELECT 1 FROM catalog_pins AS pins
                             WHERE pins.manifest_digest = packs.manifest_digest
                           )
                           AND NOT EXISTS(
                             SELECT 1 FROM catalog_activations AS active
                             WHERE active.manifest_digest = packs.manifest_digest
                           )
                           AND NOT EXISTS(
                             SELECT 1 FROM catalog_leases AS leases
                             WHERE leases.manifest_digest = packs.manifest_digest
                               AND leases.expires_at > ?2
                           )
                         ORDER BY COALESCE(packs.last_used_at, packs.installed_at),
                                  packs.manifest_digest
                         LIMIT ?3",
                    )
                    .map_err(|error| CatalogError::sqlite("prepare unreachable packs", error))?;
                let rows = statement
                    .query_map(params![cutoff, now, max_packs], |row| {
                        row.get::<_, String>(0)
                    })
                    .map_err(|error| CatalogError::sqlite("query unreachable packs", error))?;
                let mut digests = Vec::new();
                for row in rows {
                    digests.push(
                        row.map_err(|error| CatalogError::sqlite("read unreachable pack", error))?,
                    );
                }
                digests
            };
            for digest in &pack_digests {
                transaction
                    .execute(
                        "DELETE FROM catalog_packs WHERE manifest_digest = ?1",
                        [digest],
                    )
                    .map_err(|error| CatalogError::sqlite("delete unreachable pack", error))?;
            }
            let object_candidates = {
                let mut statement = transaction
                    .prepare(
                        "SELECT objects.stored_digest, objects.relative_path, objects.stored_size
                         FROM catalog_objects AS objects
                         WHERE objects.verified_at <= ?1
                           AND NOT EXISTS(
                             SELECT 1 FROM catalog_pack_shards AS shards
                             WHERE shards.stored_digest = objects.stored_digest
                           )
                           AND NOT EXISTS(
                             SELECT 1 FROM catalog_install_object_reservations AS reservations
                             WHERE reservations.stored_digest = objects.stored_digest
                               AND reservations.expires_at > ?2
                           )
                         ORDER BY objects.verified_at, objects.stored_digest
                         LIMIT ?3",
                    )
                    .map_err(|error| CatalogError::sqlite("prepare orphan objects", error))?;
                let rows = statement
                    .query_map(params![cutoff, now, max_objects], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, u64>(2)?,
                        ))
                    })
                    .map_err(|error| CatalogError::sqlite("query orphan objects", error))?;
                let mut objects = Vec::new();
                for row in rows {
                    objects.push(
                        row.map_err(|error| CatalogError::sqlite("read orphan object", error))?,
                    );
                }
                objects
            };
            transaction
                .commit()
                .map_err(|error| CatalogError::sqlite("commit catalog GC metadata", error))?;
            (pack_digests, object_candidates, pruned_expired_leases)
        };

        let mut pruned_objects = 0;
        let mut reclaimed_bytes = 0_u64;
        for (digest, relative_path, stored_size) in object_candidates {
            let mut connection = self
                .connection
                .lock()
                .expect("semantic-pack catalog connection mutex poisoned");
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|error| CatalogError::sqlite("begin object GC recheck", error))?;
            let protected: bool = transaction
                .query_row(
                    "SELECT EXISTS(
                       SELECT 1 FROM catalog_pack_shards
                       WHERE stored_digest = ?1
                       UNION ALL
                       SELECT 1 FROM catalog_install_object_reservations
                       WHERE stored_digest = ?1 AND expires_at > ?2
                     )",
                    params![&digest, crate::cache_db::now_unix_seconds()],
                    |row| row.get(0),
                )
                .map_err(|error| CatalogError::sqlite("recheck object reachability", error))?;
            if protected {
                transaction.commit().map_err(|error| {
                    CatalogError::sqlite("finish protected object check", error)
                })?;
                continue;
            }
            let removed_file = storage::delete(&self.root, &relative_path, &digest)?;
            let deleted = transaction
                .execute(
                    "DELETE FROM catalog_objects
                     WHERE stored_digest = ?1
                       AND NOT EXISTS(
                         SELECT 1 FROM catalog_pack_shards
                         WHERE stored_digest = ?1
                       )",
                    [&digest],
                )
                .map_err(|error| CatalogError::sqlite("delete orphan object row", error))?;
            transaction
                .commit()
                .map_err(|error| CatalogError::sqlite("commit object GC", error))?;
            if deleted != 0 {
                pruned_objects += 1;
                if removed_file {
                    reclaimed_bytes =
                        reclaimed_bytes.checked_add(stored_size).ok_or_else(|| {
                            CatalogError::Integrity(
                                "catalog GC reclaimed bytes overflowed".to_owned(),
                            )
                        })?;
                }
            }
        }
        let outcome = CatalogGcOutcome {
            pruned_packs: pack_digests.len(),
            pruned_objects,
            reclaimed_bytes,
            pruned_expired_leases,
        };
        if outcome.pruned_packs != 0 {
            self.record_mutation();
        }
        Ok(outcome)
    }

    fn quarantine(
        &self,
        manifest_digest: &str,
        reason: &str,
        error: &CatalogError,
    ) -> Result<(), CatalogError> {
        let mut connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| CatalogError::sqlite("begin pack quarantine", source))?;
        transaction
            .execute(
                "UPDATE catalog_packs SET state = 'quarantined' WHERE manifest_digest = ?1",
                [manifest_digest],
            )
            .map_err(|source| CatalogError::sqlite("quarantine pack", source))?;
        transaction
            .execute(
                "DELETE FROM catalog_activations WHERE manifest_digest = ?1",
                [manifest_digest],
            )
            .map_err(|source| CatalogError::sqlite("clear quarantined activations", source))?;
        transaction
            .execute(
                "INSERT INTO catalog_quarantine(
                   manifest_digest, reason, detail, detected_at
                 ) VALUES(?1, ?2, ?3, ?4)",
                params![
                    manifest_digest,
                    reason,
                    error.to_string(),
                    crate::cache_db::now_unix_seconds()
                ],
            )
            .map_err(|source| CatalogError::sqlite("record quarantine", source))?;
        transaction
            .commit()
            .map_err(|source| CatalogError::sqlite("commit pack quarantine", source))?;
        self.record_mutation();
        Ok(())
    }

    pub(crate) fn cache_identity(&self) -> Result<SemanticPackCatalogCacheIdentity, CatalogError> {
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let sqlite_data_version = connection
            .query_row("PRAGMA data_version", [], |row| row.get(0))
            .map_err(|error| CatalogError::sqlite("read catalog data version", error))?;
        Ok(SemanticPackCatalogCacheIdentity {
            instance_identity: self.instance_identity,
            mutation_generation: self.mutation_generation.load(Ordering::Relaxed),
            sqlite_data_version,
        })
    }

    fn record_mutation(&self) {
        self.mutation_generation.fetch_add(1, Ordering::Relaxed);
    }

    fn require_writable(&self) -> Result<(), CatalogError> {
        if self.mode == CatalogOpenMode::ReadWrite {
            Ok(())
        } else {
            Err(CatalogError::ReadOnly)
        }
    }

    /// Whether this catalog handle may write catalog rows.
    ///
    /// Optional accelerator work asks first, so a read-only catalog does not
    /// report a failure for work it was never able to do.
    pub fn is_writable(&self) -> bool {
        self.mode == CatalogOpenMode::ReadWrite
    }
}

fn durable_selector_rows_on(
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

fn validate_pack(
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
        let authored =
            super::artifact::authored_pack_from_decoded_shards(&manifest, &python_shards);
        let diagnostics = super::validate::validate_csmi_profile_evidence(&authored);
        if !diagnostics.is_empty() {
            return Err(CatalogError::Integrity(format!(
                "Python compiled pack has inconsistent full-pack evidence: {diagnostics:?}"
            )));
        }
    }
    Ok(ValidatedPack { manifest, shards })
}

fn semantic_mutation_epoch(connection: &Connection) -> Result<u64, CatalogError> {
    connection
        .query_row(
            "SELECT mutation_epoch FROM catalog_semantic_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| CatalogError::sqlite("read semantic catalog mutation epoch", error))
}

fn acquisition_request_satisfied(
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
fn stored_manifest_bytes_on(
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

fn manifest_shard_rows_present(
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

fn missing_manifest_shard_ids<'a>(
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

fn validate_acquisition_receipt_request(
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

fn acquisition_source_state_digest(sources: &[AcquisitionReceiptSource]) -> String {
    let mut hasher = CanonicalHasher::new(ACQUISITION_SOURCE_STATE_DOMAIN);
    hasher.sequence("sources", sources, |hasher, source| {
        hasher.field("release_digest", source.release_digest.as_bytes());
        hasher.field("manifest_digest", source.manifest_digest.as_bytes());
        hasher.field("source_kind", source.source.kind.as_str().as_bytes());
        hasher.field("source_id", source.source.source_id.as_bytes());
    });
    lower_hex_string(&hasher.finish())
}

fn receipt_source_state_digest(
    root: &Path,
    connection: &Connection,
    limits: &DecodeLimits,
    request_digest: &str,
    release_digest: &str,
    expected_count: u64,
) -> Result<Option<String>, CatalogError> {
    let mut statement = connection
        .prepare(
            "SELECT receipt.manifest_digest, receipt.source_kind, receipt.source_id,
                    pack.state, pack.manifest_bytes
             FROM catalog_acquisition_absence_receipt_sources AS receipt
             LEFT JOIN catalog_sources AS source
               ON source.manifest_digest = receipt.manifest_digest
              AND source.source_kind = receipt.source_kind
              AND source.source_id = receipt.source_id
             LEFT JOIN catalog_packs AS pack ON pack.manifest_digest = source.manifest_digest
             WHERE receipt.request_digest = ?1 AND receipt.release_digest = ?2
             ORDER BY receipt.manifest_digest, receipt.source_kind, receipt.source_id",
        )
        .map_err(|error| CatalogError::sqlite("prepare acquisition receipt source proof", error))?;
    let rows = statement
        .query_map(params![request_digest, release_digest], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<Vec<u8>>>(4)?,
            ))
        })
        .map_err(|error| CatalogError::sqlite("query acquisition receipt source proof", error))?;
    let mut sources = Vec::new();
    for row in rows {
        let (manifest_digest, source_kind, source_id, state, manifest_bytes) =
            row.map_err(|error| {
                CatalogError::sqlite("read acquisition receipt source proof", error)
            })?;
        if state.as_deref() != Some("verified") {
            return Ok(None);
        }
        let Some(manifest_bytes) = manifest_bytes else {
            return Ok(None);
        };
        let manifest = match decode_manifest(&manifest_bytes, limits) {
            Ok(manifest) => manifest,
            Err(_) => return Ok(None),
        };
        if manifest.content_sha256 != manifest_digest
            || !manifest_shard_rows_present(root, connection, &manifest_digest, &manifest)?
        {
            return Ok(None);
        }
        sources.push(AcquisitionReceiptSource {
            release_digest: release_digest.to_owned(),
            manifest_digest,
            source: DurablePackSource {
                kind: DurablePackSourceKind::parse(&source_kind)?,
                source_id,
            },
        });
    }
    if u64::try_from(sources.len()).unwrap_or(u64::MAX) != expected_count {
        return Ok(None);
    }
    Ok(Some(acquisition_source_state_digest(&sources)))
}

fn receipt_object_is_valid(
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

fn validate_extraction_accounting(
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

fn reconcile_storage(root: &Path, connection: &mut Connection) -> Result<(), CatalogError> {
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
                params![&digest, crate::cache_db::now_unix_seconds()],
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

fn insert_manifest(
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

fn insert_source(
    transaction: &Transaction<'_>,
    manifest_digest: &str,
    source: &DurablePackSource,
    now: i64,
) -> Result<(), CatalogError> {
    transaction
        .execute(
            "INSERT OR IGNORE INTO catalog_sources(
               manifest_digest, source_kind, source_id, installed_at
             ) VALUES(?1, ?2, ?3, ?4)",
            params![
                manifest_digest,
                source.kind.as_str(),
                &source.source_id,
                now
            ],
        )
        .map_err(|error| CatalogError::sqlite("insert pack source", error))?;
    Ok(())
}

fn insert_extraction_accounting(
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

fn generated_production_digest_for_cache_version(
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

fn validate_generated_pack_identity(
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

fn validate_exact_go_source(
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

fn insert_exact_go_source_rows(
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

fn insert_generated_production(
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

fn insert_object(
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

fn insert_shard(
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

fn publish_callable_value_rows(
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

fn json_text(value: &impl Serialize, description: &str) -> Result<String, CatalogError> {
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

fn callable_values_family_name(family: CallableValuesFamily) -> &'static str {
    match family {
        CallableValuesFamily::ReturnedCallables => "returned-callables",
        CallableValuesFamily::CallbackInvocations => "callback-invocations",
    }
}

fn parse_callable_values_family(value: &str) -> Result<CallableValuesFamily, CatalogError> {
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

fn parse_coverage_status(value: &str) -> Result<CsmiCoverageStatus, CatalogError> {
    match value {
        "unknown" => Ok(CsmiCoverageStatus::Unknown),
        "partial" => Ok(CsmiCoverageStatus::Partial),
        "complete" => Ok(CsmiCoverageStatus::Complete),
        _ => Err(CatalogError::Integrity(format!(
            "unknown callable-value coverage status {value:?}"
        ))),
    }
}

fn callable_values_sql_limit(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn open_session_callable_values_catalog() -> Result<SessionCallableValuesCatalog, CatalogError> {
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
    connection
        .execute_batch(
            "PRAGMA synchronous = NORMAL;
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

fn decode_json_column<T: serde::de::DeserializeOwned>(
    value: &str,
    description: &str,
) -> Result<T, CatalogError> {
    serde_json::from_str(value)
        .map_err(|error| CatalogError::Integrity(format!("decode {description}: {error}")))
}

fn validate_callable_profile_location(
    payload: &CsmiCallableValuesPayload,
) -> Result<(), super::csmi::CsmiCallableValuesUnsupportedProjection> {
    use std::convert::Infallible;

    match payload
        .clone()
        .remap_symbols(|symbol| Ok::<_, Infallible>(symbol.to_owned()))
    {
        Ok(_) => Ok(()),
        Err(super::csmi::CsmiCallableValuesRemapError::UnsupportedProjection(error)) => Err(error),
        Err(super::csmi::CsmiCallableValuesRemapError::Symbol(never)) => match never {},
    }
}

fn load_anonymous_callable_identity(
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

fn insert_selectors(
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

fn insert_routing_keys(
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

fn manifest_compatible(
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

fn selector_matches(
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

fn query_has_exact_coordinate(query: &SemanticPackSelectorQuery) -> bool {
    [&query.package, &query.module, &query.toolchain]
        .into_iter()
        .flatten()
        .any(|coordinate| coordinate.version.is_some())
}

fn selector_binds_exact_coordinate(
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
            if !super::runtime::strict_coordinate_names_match(Some(selector), Some(query)) =>
        {
            Ok(false)
        }
        (Some(selector), Some(query)) => match (&selector.version, &query.version) {
            (None, _) => Ok(true),
            (Some(_), None) => Ok(false),
            (Some(requirement), Some(version)) => {
                super::runtime::coordinate_version_matches(requirement, version)
                    .map_err(|error| CatalogError::Integrity(error.to_string()))
            }
        },
    }
}

/// Classify one pack as a version near miss for `query`: every non-version
/// predicate accepts the query, and an exact version requirement rejects it.
/// A pack rejected for a non-version reason is not a near miss and returns
/// `None`.
fn version_near_miss(
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

fn near_miss(
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

fn count(connection: &Connection, table: &str) -> Result<u64, CatalogError> {
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

fn durable_activation_kind(
    kind: SemanticPackActivationSourceKind,
) -> Option<DurablePackSourceKind> {
    match kind {
        SemanticPackActivationSourceKind::Installed => Some(DurablePackSourceKind::Installed),
        SemanticPackActivationSourceKind::Generated => Some(DurablePackSourceKind::Generated),
        SemanticPackActivationSourceKind::PreShipped => Some(DurablePackSourceKind::PreShipped),
        SemanticPackActivationSourceKind::WorkspaceProduced => {
            Some(DurablePackSourceKind::WorkspaceProduced)
        }
        SemanticPackActivationSourceKind::Embedded
        | SemanticPackActivationSourceKind::EphemeralWorkspace => None,
    }
}

fn session_activation_kind(
    kind: SemanticPackActivationSourceKind,
) -> Option<SessionPackSourceKind> {
    match kind {
        SemanticPackActivationSourceKind::Embedded => Some(SessionPackSourceKind::Embedded),
        SemanticPackActivationSourceKind::EphemeralWorkspace => {
            Some(SessionPackSourceKind::EphemeralWorkspace)
        }
        SemanticPackActivationSourceKind::Installed
        | SemanticPackActivationSourceKind::Generated
        | SemanticPackActivationSourceKind::PreShipped
        | SemanticPackActivationSourceKind::WorkspaceProduced => None,
    }
}

pub(crate) fn parse_semantic_pack_activation_source_kind(
    value: &str,
) -> Option<SemanticPackActivationSourceKind> {
    match value {
        "installed" => Some(SemanticPackActivationSourceKind::Installed),
        "generated" => Some(SemanticPackActivationSourceKind::Generated),
        "pre_shipped" => Some(SemanticPackActivationSourceKind::PreShipped),
        "workspace_produced" => Some(SemanticPackActivationSourceKind::WorkspaceProduced),
        "embedded" => Some(SemanticPackActivationSourceKind::Embedded),
        "ephemeral_workspace" => Some(SemanticPackActivationSourceKind::EphemeralWorkspace),
        _ => None,
    }
}

pub(crate) fn activation_catalog_kind(
    kind: SemanticPackActivationSourceKind,
) -> CatalogPackSourceKind {
    match kind {
        SemanticPackActivationSourceKind::Installed => CatalogPackSourceKind::Installed,
        SemanticPackActivationSourceKind::Generated => CatalogPackSourceKind::Generated,
        SemanticPackActivationSourceKind::PreShipped => CatalogPackSourceKind::PreShipped,
        SemanticPackActivationSourceKind::WorkspaceProduced => {
            CatalogPackSourceKind::WorkspaceProduced
        }
        SemanticPackActivationSourceKind::Embedded => CatalogPackSourceKind::Embedded,
        SemanticPackActivationSourceKind::EphemeralWorkspace => {
            CatalogPackSourceKind::EphemeralWorkspace
        }
    }
}

fn lease_expiry(ttl: Duration) -> Result<i64, CatalogError> {
    if ttl.is_zero() {
        return Err(CatalogError::Integrity(
            "semantic-pack lease TTL must be positive".to_owned(),
        ));
    }
    let seconds = i64::try_from(ttl.as_secs())
        .map_err(|_| CatalogError::Integrity("semantic-pack lease TTL exceeds i64".to_owned()))?;
    let seconds = seconds
        .checked_add(i64::from(ttl.subsec_nanos() != 0))
        .ok_or_else(|| CatalogError::Integrity("semantic-pack lease TTL overflowed".to_owned()))?;
    crate::cache_db::now_unix_seconds()
        .checked_add(seconds)
        .ok_or_else(|| CatalogError::Integrity("semantic-pack lease expiry overflowed".to_owned()))
}

fn release_leases(leases: &mut Vec<CatalogLease<'_>>) -> Result<(), CatalogError> {
    let mut first_error = None;
    while let Some(lease) = leases.pop() {
        if let Err(error) = lease.release()
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn encoding_name(encoding: ArtifactEncoding) -> &'static str {
    match encoding {
        ArtifactEncoding::Raw => "raw",
        ArtifactEncoding::Deflate => "deflate",
    }
}

fn payload_kind_name(kind: PayloadKind) -> &'static str {
    match kind {
        PayloadKind::DeclarationFacts => "declaration_facts",
        PayloadKind::GeneratorRules => "generator_rules",
        PayloadKind::ProcedureSummaries => "procedure_summaries",
    }
}

#[cfg(test)]
mod python_profile_reopen_tests {
    use super::{
        CatalogCandidate, CatalogCandidateLocation, CatalogOpenMode, CatalogOptions,
        CatalogPackSourceKind, DurablePackSource, DurablePackSourceKind, SemanticPackCatalog,
        insert_manifest, insert_object, insert_shard, storage,
    };
    use crate::analyzer::semantic_model::csmi::{
        CSMI_PYTHON_PROFILE_ID, CSMI_PYTHON_PROFILE_SCHEMA, CSMI_PYTHON_PROFILE_VERSION,
        CsmiVocabularySupport, import_logical_csmi_pack,
    };
    use crate::analyzer::semantic_model::{CompilerOptions, CompressionPolicy, PayloadKind};
    use rusqlite::TransactionBehavior;

    #[test]
    fn old_verified_python_pack_revalidates_all_shards_before_first_load() {
        let source = include_bytes!("../csmi/fixtures/python-distribution-beautifulsoup4.json");
        let portable =
            crate::analyzer::semantic_model::csmi::tests::logical_pack_from_semantic(source);
        let support = CsmiVocabularySupport::support(
            CSMI_PYTHON_PROFILE_ID,
            CSMI_PYTHON_PROFILE_VERSION,
            CSMI_PYTHON_PROFILE_SCHEMA,
        );
        let imported =
            import_logical_csmi_pack(&portable, &support, &CompilerOptions::default()).unwrap();
        let mut old_pack = imported
            .compile(&CompilerOptions {
                compression: CompressionPolicy::AlwaysRaw,
                ..CompilerOptions::default()
            })
            .unwrap();
        let valid_pack = old_pack.clone();
        crate::analyzer::semantic_model::csmi::tests::rewrite_raw_declaration_shard(
            &mut old_pack,
            |types, _| {
                for fact in types {
                    if let crate::analyzer::semantic_model::Locator::Interchange {
                        profile_evidence,
                        ..
                    } = &mut fact.locator
                    {
                        *profile_evidence = None;
                    }
                }
            },
        );
        let root = tempfile::tempdir().unwrap();
        let catalog = SemanticPackCatalog::open(
            root.path(),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        catalog
            .install(
                &valid_pack,
                &DurablePackSource {
                    kind: DurablePackSourceKind::Installed,
                    source_id: "valid-python-distribution".to_owned(),
                },
            )
            .unwrap();
        assert!(
            catalog
                .install(
                    &old_pack,
                    &DurablePackSource {
                        kind: DurablePackSourceKind::Installed,
                        source_id: "rejected-by-current-admission".to_owned(),
                    },
                )
                .is_err()
        );
        // Recreate only the rows an older validator would have marked
        // verified. Every object and manifest digest is internally valid.
        let published = old_pack
            .shards
            .iter()
            .map(|shard| {
                storage::publish(root.path(), &shard.descriptor.stored_sha256, &shard.bytes)
                    .map(|(path, _)| path)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let now = crate::cache_db::now_unix_seconds();
        {
            let mut connection = catalog.connection.lock().unwrap();
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            insert_manifest(
                &transaction,
                &old_pack.manifest,
                &old_pack.manifest_bytes,
                now,
            )
            .unwrap();
            for (ordinal, (shard, path)) in old_pack.shards.iter().zip(&published).enumerate() {
                insert_object(&transaction, &shard.descriptor, path, now).unwrap();
                insert_shard(
                    &transaction,
                    &old_pack.manifest.content_sha256,
                    ordinal,
                    &shard.descriptor,
                )
                .unwrap();
            }
            transaction.commit().unwrap();
        }
        drop(catalog);
        let reopened = SemanticPackCatalog::open(
            root.path(),
            CatalogOpenMode::ReadOnly,
            CatalogOptions::default(),
        )
        .unwrap();
        let valid_descriptor = valid_pack
            .manifest
            .shards
            .iter()
            .find(|descriptor| descriptor.payload_kind == PayloadKind::ProcedureSummaries)
            .unwrap()
            .clone();
        let valid_candidate = CatalogCandidate {
            manifest_digest: valid_pack.manifest.content_sha256.clone(),
            shard_id: valid_descriptor.shard_id.clone(),
            descriptor: valid_descriptor,
            completeness: valid_pack.manifest.completeness,
            source_kind: CatalogPackSourceKind::Installed,
            source_id: "valid-python-distribution".to_owned(),
            location: CatalogCandidateLocation::Durable,
        };
        reopened.load_durable(&valid_candidate).unwrap();
        assert!(
            reopened
                .validated_python_profile_packs
                .lock()
                .unwrap()
                .contains(&valid_candidate.manifest_digest)
        );
        let descriptor = old_pack
            .manifest
            .shards
            .iter()
            .find(|descriptor| descriptor.payload_kind == PayloadKind::ProcedureSummaries)
            .unwrap()
            .clone();
        let candidate = CatalogCandidate {
            manifest_digest: old_pack.manifest.content_sha256.clone(),
            shard_id: descriptor.shard_id.clone(),
            descriptor,
            completeness: old_pack.manifest.completeness,
            source_kind: CatalogPackSourceKind::Installed,
            source_id: "old-verified-row".to_owned(),
            location: CatalogCandidateLocation::Durable,
        };
        for _ in 0..2 {
            let error = reopened.load_durable(&candidate).unwrap_err();
            assert!(format!("{error:?}").contains("python.profile_evidence_count"));
            assert!(
                !reopened
                    .validated_python_profile_packs
                    .lock()
                    .unwrap()
                    .contains(&candidate.manifest_digest)
            );
        }
    }
}

#[cfg(test)]
mod callable_value_catalog_tests {
    use super::*;
    use crate::CancellationToken;
    use crate::analyzer::go::{GoPinnedPackage, analyze_go_package_source_identities};
    use crate::analyzer::semantic_model::csmi::{
        CsmiCallableValuesArgument, CsmiCallableValuesLimitation, CsmiCallableValuesModality,
        CsmiCallableValuesPayload, CsmiCallableValuesShape, CsmiCallableValuesTiming,
        CsmiCoverageStatus, CsmiInputLocation,
    };
    use crate::analyzer::semantic_model::{
        AnonymousCallableIdentity, ArtifactProducerLimits, AuthoredSemanticModelPack,
        CallableValuesCoverage, CallableValuesFact, CallableValuesFamily, CallableValuesPayload,
        CompilerOptions, ExactArtifact, compile_pack, read_exact_source_set,
    };
    use rusqlite::TransactionBehavior;
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;

    const DECLARATIONS: &[u8] =
        include_bytes!("../../../../testdata/semantic-model-packs/declarations-v1.json");
    const CALLABLE: &str = "member.widget.create";

    fn callback_location(position: u32) -> CsmiInputLocation {
        serde_json::from_value(json!({
            "root": {"phase": "input", "role": "parameter", "position": position}
        }))
        .expect("parameter location is valid")
    }

    fn callable_pack() -> CompiledSemanticModelPack {
        let mut authored: AuthoredSemanticModelPack =
            serde_json::from_slice(DECLARATIONS).expect("declaration fixture is valid");
        authored.schema_version = 10;
        authored.compatibility.bifrost = None;
        let callback = callback_location(0);
        authored.shards[0].callable_values = Some(CallableValuesPayload {
            facts: vec![
                CallableValuesFact {
                    payload: CsmiCallableValuesPayload::ReturnedCallable {
                        callable: CALLABLE.to_owned(),
                        result: 0,
                        target: CALLABLE.to_owned(),
                    },
                    provenance: vec!["factory-return-a".to_owned()],
                },
                CallableValuesFact {
                    payload: CsmiCallableValuesPayload::ReturnedCallable {
                        callable: CALLABLE.to_owned(),
                        result: 0,
                        target: CALLABLE.to_owned(),
                    },
                    provenance: vec!["factory-return-b".to_owned()],
                },
                CallableValuesFact {
                    payload: CsmiCallableValuesPayload::CallbackInvocation {
                        callable: CALLABLE.to_owned(),
                        callback: callback.clone(),
                        shape: CsmiCallableValuesShape {
                            parameters: 1,
                            results: 1,
                        },
                        arguments: vec![CsmiCallableValuesArgument::Unknown {
                            limitation: CsmiCallableValuesLimitation {
                                kind: "unmodeled-input".to_owned(),
                                diagnostic: None,
                            },
                        }],
                        timing: CsmiCallableValuesTiming::DuringCall,
                        modality: CsmiCallableValuesModality::May,
                    },
                    provenance: vec!["callback-edge".to_owned()],
                },
            ],
            coverage: vec![
                CallableValuesCoverage {
                    family: CallableValuesFamily::ReturnedCallables,
                    callable: CALLABLE.to_owned(),
                    status: CsmiCoverageStatus::Partial,
                    limitations: Vec::new(),
                    provenance: vec!["returned-scan".to_owned()],
                },
                CallableValuesCoverage {
                    family: CallableValuesFamily::CallbackInvocations,
                    callable: CALLABLE.to_owned(),
                    status: CsmiCoverageStatus::Unknown,
                    limitations: Vec::new(),
                    provenance: vec!["callback-scan".to_owned()],
                },
            ],
            anonymous_callables: Vec::new(),
        });
        compile_pack(&authored, &CompilerOptions::default()).expect("callable pack compiles")
    }

    fn install_fixture() -> (SemanticPackCatalog, CompiledSemanticModelPack) {
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let pack = callable_pack();
        catalog
            .install(
                &pack,
                &DurablePackSource {
                    kind: DurablePackSourceKind::Installed,
                    source_id: "callable-values-fixture".to_owned(),
                },
            )
            .unwrap();
        catalog
            .install(
                &pack,
                &DurablePackSource {
                    kind: DurablePackSourceKind::Installed,
                    source_id: "callable-values-fixture-second".to_owned(),
                },
            )
            .expect("same populated publication supports multiple durable source IDs");
        (catalog, pack)
    }

    fn anonymous_source_fixture() -> (
        tempfile::TempDir,
        ExactArtifact,
        GoPinnedPackage,
        AnonymousCallableIdentity,
    ) {
        let directory = tempfile::tempdir().expect("Go source fixture directory");
        let root = directory
            .path()
            .canonicalize()
            .expect("canonical Go source root");
        fs::write(
            root.join("callbacks.go"),
            "package pkg\nfunc factory() func(int) int {\n return func(value int) int { return value }\n}\n",
        )
        .expect("write Go source fixture");
        let artifact = read_exact_source_set(
            &root,
            &[PathBuf::from("callbacks.go")],
            1,
            8,
            &ArtifactProducerLimits::default(),
        )
        .expect("exact Go source set");
        let package = GoPinnedPackage {
            import_path: "example.test/module/pkg".to_owned(),
            name: "pkg".to_owned(),
            files: vec!["callbacks.go".to_owned()],
        };
        let analysis = analyze_go_package_source_identities(&artifact, &package, 10_000, None);
        assert!(analysis.is_source_discovery_complete(), "{analysis:#?}");
        let literal = analysis
            .identities
            .iter()
            .find(|identity| {
                identity.anchor.kind
                    == crate::analyzer::go::GoSourceDeclarationKind::FunctionLiteral
            })
            .expect("anonymous callback literal is present");
        let identity = literal
            .anonymous_callable_identity("go.literal.returned-callback")
            .expect("literal signature is AST-backed");
        (directory, artifact, package, identity)
    }

    fn anonymous_callable_pack(identity: AnonymousCallableIdentity) -> CompiledSemanticModelPack {
        let mut authored: AuthoredSemanticModelPack =
            serde_json::from_slice(DECLARATIONS).expect("declaration fixture is valid");
        authored.schema_version = 10;
        authored.compatibility.bifrost = None;
        authored.language = "go".to_owned();
        authored.ecosystem = "go-module".to_owned();
        for selector in &mut authored.shards[0].activation {
            selector.artifact_sha256 = Some(identity.artifact_sha256.clone());
        }
        authored.shards[0].callable_values = Some(CallableValuesPayload {
            facts: vec![CallableValuesFact {
                payload: CsmiCallableValuesPayload::ReturnedCallable {
                    callable: CALLABLE.to_owned(),
                    result: 0,
                    target: identity.id.clone(),
                },
                provenance: vec!["exact-go-source-fixture".to_owned()],
            }],
            coverage: vec![CallableValuesCoverage {
                family: CallableValuesFamily::ReturnedCallables,
                callable: CALLABLE.to_owned(),
                status: CsmiCoverageStatus::Partial,
                limitations: Vec::new(),
                provenance: vec!["source-coverage".to_owned()],
            }],
            anonymous_callables: vec![identity],
        });
        compile_pack(&authored, &CompilerOptions::default()).expect("Go callable pack compiles")
    }

    fn query<'a>(
        pack: &'a CompiledSemanticModelPack,
        question: CatalogCallableValuesQuestion<'a>,
    ) -> CatalogCallableValuesQuery<'a> {
        CatalogCallableValuesQuery {
            manifest_digest: &pack.manifest.content_sha256,
            shard_id: &pack.manifest.shards[0].shard_id,
            callable: CALLABLE,
            question,
        }
    }

    #[test]
    fn sql_questions_preserve_alternatives_unknowns_scoped_coverage_and_exact_shape() {
        let (catalog, pack) = install_fixture();
        let cancellation = CancellationToken::new();
        let returned = catalog
            .query_callable_values(
                &query(
                    &pack,
                    CatalogCallableValuesQuestion::ReturnedCallable { result: 0 },
                ),
                CatalogCallableValuesQueryLimits { max_records: 4 },
                &cancellation,
            )
            .unwrap();
        assert_eq!(returned.facts.len(), 2, "alternatives are retained");
        assert_eq!(returned.coverage_claims.len(), 1);
        assert_eq!(returned.examined_records, 3);
        assert_eq!(returned.executable_coverage, CsmiCoverageStatus::Unknown);
        assert_eq!(
            returned.coverage_claims[0].coverage.status,
            CsmiCoverageStatus::Partial
        );

        let callback = callback_location(0);
        let callbacks = catalog
            .query_callable_values(
                &query(
                    &pack,
                    CatalogCallableValuesQuestion::CallbackInvocation {
                        callback: &callback,
                        shape: CsmiCallableValuesShape {
                            parameters: 1,
                            results: 1,
                        },
                    },
                ),
                CatalogCallableValuesQueryLimits { max_records: 2 },
                &cancellation,
            )
            .unwrap();
        assert_eq!(callbacks.facts.len(), 1);
        assert_eq!(callbacks.coverage_claims.len(), 1);
        let CsmiCallableValuesPayload::CallbackInvocation { arguments, .. } =
            &callbacks.facts[0].fact.payload
        else {
            panic!("callback question returned a non-callback fact");
        };
        assert!(matches!(
            arguments[0],
            CsmiCallableValuesArgument::Unknown { .. }
        ));
        assert_eq!(callbacks.executable_coverage, CsmiCoverageStatus::Unknown);

        let wrong_shape = catalog
            .query_callable_values(
                &query(
                    &pack,
                    CatalogCallableValuesQuestion::CallbackInvocation {
                        callback: &callback,
                        shape: CsmiCallableValuesShape {
                            parameters: 2,
                            results: 1,
                        },
                    },
                ),
                CatalogCallableValuesQueryLimits { max_records: 2 },
                &cancellation,
            )
            .unwrap();
        assert!(wrong_shape.facts.is_empty());
        assert_eq!(wrong_shape.coverage_claims.len(), 1);

        let wrong_location = callback_location(1);
        let near_miss = catalog
            .query_callable_values(
                &query(
                    &pack,
                    CatalogCallableValuesQuestion::CallbackInvocation {
                        callback: &wrong_location,
                        shape: CsmiCallableValuesShape {
                            parameters: 1,
                            results: 1,
                        },
                    },
                ),
                CatalogCallableValuesQueryLimits { max_records: 2 },
                &cancellation,
            )
            .unwrap();
        assert!(near_miss.facts.is_empty());
        assert_eq!(near_miss.coverage_claims.len(), 1);

        let bounded = catalog
            .query_callable_values(
                &query(
                    &pack,
                    CatalogCallableValuesQuestion::ReturnedCallable { result: 0 },
                ),
                CatalogCallableValuesQueryLimits { max_records: 1 },
                &cancellation,
            )
            .unwrap();
        assert_eq!(bounded.facts.len(), 1);
        assert_eq!(
            bounded.gap,
            Some(CatalogCallableValuesQueryGap::RecordBudgetExhausted { max_records: 1 })
        );

        let canceled = CancellationToken::new();
        canceled.cancel();
        let result = catalog
            .query_callable_values(
                &query(
                    &pack,
                    CatalogCallableValuesQuestion::ReturnedCallable { result: 0 },
                ),
                CatalogCallableValuesQueryLimits { max_records: 2 },
                &canceled,
            )
            .unwrap();
        assert_eq!(result.gap, Some(CatalogCallableValuesQueryGap::Cancelled));
        assert!(result.facts.is_empty());
    }

    #[test]
    fn session_sources_publish_queryable_sql_without_writing_read_only_main_catalog() {
        for (source_kind, source_id) in [
            (SessionPackSourceKind::Embedded, "embedded-session"),
            (
                SessionPackSourceKind::EphemeralWorkspace,
                "ephemeral-workspace-session",
            ),
        ] {
            let root = tempfile::tempdir().expect("session catalog root");
            drop(
                SemanticPackCatalog::open(
                    root.path(),
                    CatalogOpenMode::ReadWrite,
                    CatalogOptions::default(),
                )
                .expect("initialize main catalog"),
            );
            let catalog = SemanticPackCatalog::open(
                root.path(),
                CatalogOpenMode::ReadOnly,
                CatalogOptions::default(),
            )
            .expect("open read-only main catalog");
            let pack = callable_pack();
            catalog
                .register_session_pack(
                    &pack,
                    &SessionPackSource {
                        kind: source_kind,
                        source_id: source_id.to_owned(),
                    },
                )
                .expect("register validated session pack");
            catalog
                .register_session_pack(
                    &pack,
                    &SessionPackSource {
                        kind: source_kind,
                        source_id: format!("{source_id}-second"),
                    },
                )
                .expect("register the same populated publication under another source ID");

            assert!(
                catalog.session_packs.lock().unwrap()[0].shards[0]
                    .callable_values
                    .is_none()
            );

            let result = catalog
                .query_callable_values(
                    &query(
                        &pack,
                        CatalogCallableValuesQuestion::ReturnedCallable { result: 0 },
                    ),
                    CatalogCallableValuesQueryLimits { max_records: 4 },
                    &CancellationToken::new(),
                )
                .expect("query session SQL sidecar");
            assert_eq!(result.facts.len(), 2, "{source_kind:?}");
            assert_eq!(result.coverage_claims.len(), 1, "{source_kind:?}");
            assert_eq!(result.gap, None, "{source_kind:?}");
            assert_eq!(result.executable_coverage, CsmiCoverageStatus::Unknown);
            assert_eq!(
                catalog
                    .connection
                    .lock()
                    .unwrap()
                    .query_row("SELECT count(*) FROM catalog_packs", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .unwrap(),
                0,
                "session registration never installs into the read-only durable catalog"
            );
            let session_catalog = catalog.session_callable_values.lock().unwrap();
            assert_eq!(
                session_catalog
                    .as_ref()
                    .unwrap()
                    .connection
                    .query_row(
                        "SELECT count(*) FROM catalog_callable_values_indexed_shards
                         WHERE manifest_digest = ?1 AND shard_id = ?2",
                        params![
                            &pack.manifest.content_sha256,
                            &pack.manifest.shards[0].shard_id
                        ],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                1,
                "session SQL marker is committed with the facts"
            );
        }
    }

    #[test]
    fn legacy_missing_index_is_a_gap_until_bounded_normal_hydration_repairs_it() {
        let (catalog, pack) = install_fixture();
        let manifest = &pack.manifest.content_sha256;
        let shard = &pack.manifest.shards[0].shard_id;
        {
            let mut connection = catalog.connection.lock().unwrap();
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            transaction
                .execute(
                    "DELETE FROM catalog_anonymous_callable_identities
                     WHERE manifest_digest = ?1 AND shard_id = ?2",
                    params![manifest, shard],
                )
                .unwrap();
            transaction
                .execute(
                    "DELETE FROM catalog_callable_value_facts
                     WHERE manifest_digest = ?1 AND shard_id = ?2",
                    params![manifest, shard],
                )
                .unwrap();
            transaction
                .execute(
                    "DELETE FROM catalog_callable_value_coverage
                     WHERE manifest_digest = ?1 AND shard_id = ?2",
                    params![manifest, shard],
                )
                .unwrap();
            transaction
                .execute(
                    "DELETE FROM catalog_callable_values_indexed_shards
                     WHERE manifest_digest = ?1 AND shard_id = ?2",
                    params![manifest, shard],
                )
                .unwrap();
            transaction.commit().unwrap();
        }
        let object_reads = catalog.object_reads.load(Ordering::Relaxed);
        let no_budget = catalog
            .query_callable_values(
                &query(
                    &pack,
                    CatalogCallableValuesQuestion::ReturnedCallable { result: 0 },
                ),
                CatalogCallableValuesQueryLimits { max_records: 0 },
                &CancellationToken::new(),
            )
            .unwrap();
        assert_eq!(
            no_budget.gap,
            Some(CatalogCallableValuesQueryGap::RecordBudgetExhausted { max_records: 0 })
        );
        let no_index = catalog
            .query_callable_values(
                &query(
                    &pack,
                    CatalogCallableValuesQuestion::ReturnedCallable { result: 0 },
                ),
                CatalogCallableValuesQueryLimits { max_records: 4 },
                &CancellationToken::new(),
            )
            .unwrap();
        assert_eq!(
            no_index.gap,
            Some(CatalogCallableValuesQueryGap::IndexReconciliationRequired)
        );
        assert_eq!(catalog.object_reads.load(Ordering::Relaxed), object_reads);
        assert_eq!(
            catalog
                .connection
                .lock()
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM catalog_callable_values_indexed_shards
                     WHERE manifest_digest = ?1 AND shard_id = ?2",
                    params![manifest, shard],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0,
            "query demand does not repair by decoding an uncharged shard"
        );

        let candidate = CatalogCandidate {
            manifest_digest: manifest.clone(),
            shard_id: shard.clone(),
            descriptor: pack.manifest.shards[0].clone(),
            completeness: pack.manifest.completeness,
            source_kind: CatalogPackSourceKind::Installed,
            source_id: "callable-values-fixture".to_owned(),
            location: CatalogCandidateLocation::Durable,
        };
        catalog
            .load(&candidate)
            .expect("normal shard load succeeds");
        let repaired = catalog
            .query_callable_values(
                &query(
                    &pack,
                    CatalogCallableValuesQuestion::ReturnedCallable { result: 0 },
                ),
                CatalogCallableValuesQueryLimits { max_records: 4 },
                &CancellationToken::new(),
            )
            .unwrap();
        assert_eq!(repaired.facts.len(), 2);
        assert_eq!(repaired.coverage_claims.len(), 1);
        assert_eq!(repaired.gap, None);
    }

    #[test]
    fn anonymous_sql_rows_rebind_to_fresh_exact_go_ast_and_reject_bad_query_evidence() {
        let (_directory, artifact, package, identity) = anonymous_source_fixture();
        let pack = anonymous_callable_pack(identity.clone());
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        catalog
            .install(
                &pack,
                &DurablePackSource {
                    kind: DurablePackSourceKind::Installed,
                    source_id: "anonymous-go-fixture".to_owned(),
                },
            )
            .unwrap();
        catalog
            .install(
                &pack,
                &DurablePackSource {
                    kind: DurablePackSourceKind::Installed,
                    source_id: "anonymous-go-fixture-second".to_owned(),
                },
            )
            .expect("repeated publication replaces anonymous identities and child anchors");
        let rows = catalog
            .query_callable_values(
                &query(
                    &pack,
                    CatalogCallableValuesQuestion::ReturnedCallable { result: 0 },
                ),
                CatalogCallableValuesQueryLimits { max_records: 16 },
                &CancellationToken::new(),
            )
            .unwrap();
        assert_eq!(rows.facts.len(), 1);
        let returned = &rows.facts[0];
        assert_eq!(returned.anonymous_callable.as_ref(), Some(&identity));
        let bound = crate::analyzer::go::bind_catalog_go_anonymous_callable_target(
            returned,
            &artifact,
            &package,
            10_000,
            &CancellationToken::new(),
        )
        .expect("SQL-carried identity rebinds against the exact artifact");
        assert_eq!(bound.id(), identity.id);
        assert_eq!(SourceAnchor::from(&bound.source().anchor), identity.anchor);

        let mut missing_identity = returned.clone();
        missing_identity.anonymous_callable = None;
        assert_eq!(
            crate::analyzer::go::bind_catalog_go_anonymous_callable_target(
                &missing_identity,
                &artifact,
                &package,
                10_000,
                &CancellationToken::new(),
            ),
            Err(
                crate::analyzer::go::GoCatalogAnonymousCallableBindingError::MissingAnonymousTarget
            )
        );

        let mut wrong_target = returned.clone();
        let CsmiCallableValuesPayload::ReturnedCallable { target, .. } =
            &mut wrong_target.fact.payload
        else {
            panic!("returned-callable query produced another fact kind");
        };
        *target = "go.literal.unbound".to_owned();
        assert_eq!(
            crate::analyzer::go::bind_catalog_go_anonymous_callable_target(
                &wrong_target,
                &artifact,
                &package,
                10_000,
                &CancellationToken::new(),
            ),
            Err(crate::analyzer::go::GoCatalogAnonymousCallableBindingError::TargetMismatch)
        );

        let canceled = CancellationToken::new();
        canceled.cancel();
        assert_eq!(
            crate::analyzer::go::bind_catalog_go_anonymous_callable_target(
                returned, &artifact, &package, 10_000, &canceled,
            ),
            Err(
                crate::analyzer::go::GoCatalogAnonymousCallableBindingError::Source(
                    crate::analyzer::go::GoAnonymousCallableIdentityBindingError::Cancelled {
                        visited_nodes: 0
                    }
                )
            )
        );
    }

    #[test]
    fn runtime_source_reader_reconstructs_exact_go_source_after_catalog_drop() {
        let (_directory, artifact, package, identity) = anonymous_source_fixture();
        let pack = anonymous_callable_pack(identity);
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        catalog
            .install(
                &pack,
                &DurablePackSource {
                    kind: DurablePackSourceKind::Installed,
                    source_id: "exact-go-source-reader".to_owned(),
                },
            )
            .unwrap();
        catalog
            .register_exact_go_source(
                &pack.manifest.content_sha256,
                &artifact,
                std::slice::from_ref(&package),
            )
            .unwrap();
        let reader = catalog.runtime_source_reader();
        let request = CatalogGoSourceRequest {
            manifest_digest: &pack.manifest.content_sha256,
            shard_id: &pack.manifest.shards[0].shard_id,
            artifact_sha256: artifact.sha256(),
            package_import_path: &package.import_path,
            file: &package.files[0],
        };
        let canceled = CancellationToken::new();
        canceled.cancel();
        assert!(matches!(
            reader.read_go_source(&request, CatalogGoSourceReadLimits::default(), &canceled,),
            Err(CatalogError::Cancelled)
        ));
        let budget = reader.read_go_source(
            &request,
            CatalogGoSourceReadLimits {
                max_files: 0,
                ..CatalogGoSourceReadLimits::default()
            },
            &CancellationToken::new(),
        );
        assert!(matches!(
            budget,
            Err(CatalogError::SourceBudgetExhausted { max_files: 0, .. })
        ));
        let missing_file = reader
            .read_go_source(
                &CatalogGoSourceRequest {
                    file: "missing.go",
                    ..request
                },
                CatalogGoSourceReadLimits::default(),
                &CancellationToken::new(),
            )
            .unwrap();
        assert!(missing_file.is_none());
        let foreign_artifact = ExactArtifact::from_source_entries(
            PathBuf::from("<foreign exact Go source set>"),
            vec![("foreign.go".to_owned(), b"package foreign\n".to_vec())],
            8,
            &ArtifactProducerLimits::default(),
        )
        .unwrap();
        let foreign_package = GoPinnedPackage {
            import_path: "example.test/foreign/pkg".to_owned(),
            name: "foreign".to_owned(),
            files: vec!["foreign.go".to_owned()],
        };
        catalog
            .register_exact_go_source(
                &pack.manifest.content_sha256,
                &foreign_artifact,
                std::slice::from_ref(&foreign_package),
            )
            .unwrap();
        assert!(
            reader
                .read_go_source(
                    &CatalogGoSourceRequest {
                        artifact_sha256: foreign_artifact.sha256(),
                        package_import_path: &foreign_package.import_path,
                        file: &foreign_package.files[0],
                        ..request
                    },
                    CatalogGoSourceReadLimits::default(),
                    &CancellationToken::new(),
                )
                .unwrap()
                .is_none(),
            "a source set registered under the manifest is unreadable without shard activation"
        );
        drop(catalog);

        let selected = reader
            .read_go_source(
                &request,
                CatalogGoSourceReadLimits::default(),
                &CancellationToken::new(),
            )
            .unwrap()
            .expect("registered exact source set");
        assert_eq!(selected.artifact.sha256(), artifact.sha256());
        assert_eq!(selected.artifact.bytes(), artifact.bytes());
        assert_eq!(selected.packages, vec![package]);
        assert_eq!(
            selected.artifact.path(),
            Path::new("<catalog exact Go source set>")
        );
    }

    #[test]
    fn runtime_source_reader_bounds_stored_package_metadata_before_reconstruction() {
        for column in ["package_name", "import_path"] {
            let (_directory, artifact, package, identity) = anonymous_source_fixture();
            let pack = anonymous_callable_pack(identity);
            let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
            catalog
                .install(
                    &pack,
                    &DurablePackSource {
                        kind: DurablePackSourceKind::Installed,
                        source_id: "bounded-go-source-metadata".to_owned(),
                    },
                )
                .unwrap();
            catalog
                .register_exact_go_source(
                    &pack.manifest.content_sha256,
                    &artifact,
                    std::slice::from_ref(&package),
                )
                .unwrap();
            // A damaged catalog must be bounded before allocating or attempting
            // to validate this metadata as a package/source identity.
            catalog
                .connection
                .lock()
                .unwrap()
                .execute(
                    &format!("UPDATE catalog_exact_go_packages SET {column} = ?1"),
                    params!["x".repeat(4096)],
                )
                .unwrap();
            assert!(matches!(
                catalog.runtime_source_reader().read_go_source(
                    &CatalogGoSourceRequest {
                        manifest_digest: &pack.manifest.content_sha256,
                        shard_id: &pack.manifest.shards[0].shard_id,
                        artifact_sha256: artifact.sha256(),
                        package_import_path: &package.import_path,
                        file: &package.files[0],
                    },
                    CatalogGoSourceReadLimits {
                        max_files: 8,
                        max_source_bytes: 2048,
                        ..CatalogGoSourceReadLimits::default()
                    },
                    &CancellationToken::new(),
                ),
                Err(CatalogError::SourceBudgetExhausted {
                    max_source_bytes: 2048,
                    ..
                })
            ));
        }
    }

    #[test]
    fn session_compiled_pack_registration_publishes_exact_go_source_rows() {
        let (_directory, artifact, package, identity) = anonymous_source_fixture();
        let pack = anonymous_callable_pack(identity);
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        catalog
            .register_compiled_pack_with_exact_go_source(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::EphemeralWorkspace,
                    source_id: "exact-go-source-session".to_owned(),
                },
                &artifact,
                std::slice::from_ref(&package),
            )
            .unwrap();
        let reader = catalog.runtime_source_reader();
        let selected = reader
            .read_go_source(
                &CatalogGoSourceRequest {
                    manifest_digest: &pack.manifest.content_sha256,
                    shard_id: &pack.manifest.shards[0].shard_id,
                    artifact_sha256: artifact.sha256(),
                    package_import_path: &package.import_path,
                    file: &package.files[0],
                },
                CatalogGoSourceReadLimits::default(),
                &CancellationToken::new(),
            )
            .unwrap()
            .expect("session exact source rows");
        assert_eq!(selected.artifact.sha256(), artifact.sha256());
        assert_eq!(selected.packages, vec![package]);
    }

    #[test]
    fn populated_callable_queries_pin_their_exact_lookup_indexes_with_and_without_statistics() {
        for state in crate::cache_gc::PlannerStatisticsState::BOTH {
            let (catalog, pack) = install_fixture();
            let manifest = &pack.manifest.content_sha256;
            let shard = &pack.manifest.shards[0].shard_id;
            let callback = callback_location(0);
            let callback_json = serde_json::to_string(&callback).unwrap();
            let source_artifact = "a".repeat(64);
            {
                let mut connection = catalog.connection.lock().unwrap();
                let transaction = connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .unwrap();
                {
                    let mut insert = transaction
                        .prepare_cached(
                            "INSERT INTO catalog_callable_value_facts(
                               manifest_digest, shard_id, fact_ordinal, family,
                               callable, result_ordinal, target, provenance_json
                             ) VALUES(?1, ?2, ?3, 'returned-callables', ?4, ?5, ?6, '[]')",
                        )
                        .unwrap();
                    for ordinal in 0_i64..2_048 {
                        let callable = if ordinal % 16 == 0 {
                            CALLABLE.to_owned()
                        } else {
                            format!("member.distractor.{}", ordinal % 127)
                        };
                        insert
                            .execute(params![
                                manifest,
                                shard,
                                10_000 + ordinal,
                                callable,
                                ordinal % 4,
                                CALLABLE,
                            ])
                            .unwrap();
                    }
                }
                {
                    let mut insert = transaction
                        .prepare_cached(
                            "INSERT INTO catalog_callable_value_facts(
                               manifest_digest, shard_id, fact_ordinal, family,
                               callable, callback_location_json, callback_parameters,
                               callback_results, arguments_json, timing, modality,
                               provenance_json
                             ) VALUES(?1, ?2, ?3, 'callback-invocations', ?4, ?5,
                                      ?6, ?7, '[]', 'during-call', 'may', '[]')",
                        )
                        .unwrap();
                    for ordinal in 0_i64..2_048 {
                        let callable = if ordinal % 16 == 0 {
                            CALLABLE.to_owned()
                        } else {
                            format!("member.distractor.{}", ordinal % 127)
                        };
                        insert
                            .execute(params![
                                manifest,
                                shard,
                                20_000 + ordinal,
                                callable,
                                callback_json,
                                ordinal % 4,
                                ordinal % 3,
                            ])
                            .unwrap();
                    }
                }
                {
                    let mut insert = transaction
                        .prepare_cached(
                            "INSERT INTO catalog_callable_value_coverage(
                               manifest_digest, shard_id, coverage_ordinal, family,
                               callable, status, limitations_json, provenance_json
                             ) VALUES(?1, ?2, ?3, ?4, ?5, 'unknown', '[]', '[]')",
                        )
                        .unwrap();
                    for ordinal in 0_i64..512 {
                        let family = if ordinal % 2 == 0 {
                            "returned-callables"
                        } else {
                            "callback-invocations"
                        };
                        let callable = if ordinal % 16 == 0 {
                            CALLABLE.to_owned()
                        } else {
                            format!("member.distractor.{}", ordinal % 127)
                        };
                        insert
                            .execute(params![manifest, shard, 10_000 + ordinal, family, callable])
                            .unwrap();
                    }
                }
                for ordinal in 0_i64..256 {
                    let identity_id = format!("go.literal.plan.{ordinal}");
                    let artifact_sha256 = format!("{ordinal:064x}");
                    transaction
                        .execute(
                            "INSERT INTO catalog_anonymous_callable_identities(
                               manifest_digest, shard_id, callable_id, artifact_sha256,
                               package_import_path, anchor_file, anchor_start, anchor_end,
                               anchor_kind, signature_file, signature_start, signature_end
                             ) VALUES(?1, ?2, ?3, ?4, 'example.test/module/pkg',
                                      'callbacks.go', 10, 50, 'function-literal',
                                      'callbacks.go', 10, 20)",
                            params![manifest, shard, identity_id, artifact_sha256],
                        )
                        .unwrap();
                    transaction
                        .execute(
                            "INSERT INTO catalog_anonymous_callable_identity_anchors(
                               manifest_digest, shard_id, callable_id, chain_kind,
                               ordinal, file, byte_start, byte_end, declaration_kind
                             ) VALUES(?1, ?2, ?3, 'signature_declaration', 0,
                                      'callbacks.go', 10, 20, 'function')",
                            params![manifest, shard, identity_id],
                        )
                        .unwrap();
                    transaction
                        .execute(
                            "INSERT INTO catalog_anonymous_callable_signature_shapes(
                               manifest_digest, shard_id, callable_id, shape_kind,
                               ordinal, file, byte_start, byte_end, variadic, arity
                             ) VALUES(?1, ?2, ?3, 'parameter', 0,
                                      'callbacks.go', 11, 15, 0, 1)",
                            params![manifest, shard, identity_id],
                        )
                        .unwrap();
                }
                transaction
                    .execute(
                        "INSERT INTO catalog_exact_go_source_sets(
                           manifest_digest, artifact_sha256
                         ) VALUES(?1, ?2)",
                        params![manifest, &source_artifact],
                    )
                    .unwrap();
                transaction
                    .execute(
                        "INSERT INTO catalog_exact_go_packages(
                           manifest_digest, artifact_sha256, package_ordinal,
                           import_path, package_name
                         ) VALUES(?1, ?2, 0, 'example.test/module/pkg', 'pkg')",
                        params![manifest, &source_artifact],
                    )
                    .unwrap();
                let mut source_insert = transaction
                    .prepare_cached(
                        "INSERT INTO catalog_exact_go_source_files(
                           manifest_digest, artifact_sha256, relative_path, source_text
                         ) VALUES(?1, ?2, ?3, 'package pkg\\n')",
                    )
                    .unwrap();
                let mut membership_insert = transaction
                    .prepare_cached(
                        "INSERT INTO catalog_exact_go_package_files(
                           manifest_digest, artifact_sha256, package_ordinal,
                           file_ordinal, relative_path
                         ) VALUES(?1, ?2, 0, ?3, ?4)",
                    )
                    .unwrap();
                for ordinal in 0_i64..256 {
                    let path = format!("pkg/{ordinal:04}.go");
                    source_insert
                        .execute(params![manifest, &source_artifact, &path])
                        .unwrap();
                    membership_insert
                        .execute(params![manifest, &source_artifact, ordinal, &path])
                        .unwrap();
                }
                drop(source_insert);
                drop(membership_insert);
                transaction.commit().unwrap();
                state.install(&connection);
                if state == crate::cache_gc::PlannerStatisticsState::Representative {
                    // Catalog tables have no captured analyzer-store samples;
                    // analyze this populated catalog to exercise its own plans.
                    connection.execute_batch("ANALYZE;").unwrap();
                }

                let source_files_plan = connection
                    .prepare(
                        "EXPLAIN QUERY PLAN
                         SELECT relative_path, source_text
                         FROM catalog_exact_go_source_files
                              INDEXED BY catalog_exact_go_source_files_read
                         WHERE manifest_digest = ?1 AND artifact_sha256 = ?2
                         ORDER BY relative_path",
                    )
                    .unwrap()
                    .query_map(params![manifest, &source_artifact], |row| {
                        row.get::<_, String>(3)
                    })
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                assert!(
                    source_files_plan
                        .iter()
                        .any(|line| line.contains("catalog_exact_go_source_files_read")),
                    "{state}: {source_files_plan:?}"
                );
                assert!(
                    !source_files_plan
                        .iter()
                        .any(|line| { line.contains("SCAN ") || line.contains("AUTOMATIC") }),
                    "{state}: {source_files_plan:?}"
                );

                let source_activation_plan = connection
                    .prepare(
                        "EXPLAIN QUERY PLAN
                         SELECT EXISTS(
                           SELECT 1
                           FROM catalog_selectors INDEXED BY catalog_selectors_artifact
                           WHERE manifest_digest = ?1
                             AND shard_id = ?2
                             AND artifact_sha256 = ?3)",
                    )
                    .unwrap()
                    .query_map(params![manifest, shard, &source_artifact], |row| {
                        row.get::<_, String>(3)
                    })
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                assert!(
                    source_activation_plan
                        .iter()
                        .any(|line| {
                            line.starts_with(
                                "SEARCH catalog_selectors USING COVERING INDEX catalog_selectors_artifact ",
                            ) && line.contains(
                                "(artifact_sha256=? AND manifest_digest=? AND shard_id=?)",
                            )
                        }),
                    "{state}: {source_activation_plan:?}"
                );
                assert!(
                    !source_activation_plan.iter().any(|line| {
                        (line.contains("SCAN ") && line != "SCAN CONSTANT ROW")
                            || line.contains("AUTOMATIC")
                    }),
                    "{state}: {source_activation_plan:?}"
                );

                let package_plan = connection
                    .prepare(
                        "EXPLAIN QUERY PLAN
                         SELECT package_ordinal, import_path, package_name
                         FROM catalog_exact_go_packages
                              INDEXED BY catalog_exact_go_packages_read
                         WHERE manifest_digest = ?1 AND artifact_sha256 = ?2
                         ORDER BY package_ordinal",
                    )
                    .unwrap()
                    .query_map(params![manifest, &source_artifact], |row| {
                        row.get::<_, String>(3)
                    })
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                assert!(
                    package_plan
                        .iter()
                        .any(|line| line.contains("catalog_exact_go_packages_read")),
                    "{state}: {package_plan:?}"
                );
                assert!(
                    !package_plan
                        .iter()
                        .any(|line| { line.contains("SCAN ") || line.contains("AUTOMATIC") }),
                    "{state}: {package_plan:?}"
                );

                let package_files_plan = connection
                    .prepare(
                        "EXPLAIN QUERY PLAN
                         SELECT package_ordinal, file_ordinal, relative_path
                         FROM catalog_exact_go_package_files
                              INDEXED BY catalog_exact_go_package_files_ordered_read
                         WHERE manifest_digest = ?1 AND artifact_sha256 = ?2
                         ORDER BY package_ordinal, file_ordinal",
                    )
                    .unwrap()
                    .query_map(params![manifest, &source_artifact], |row| {
                        row.get::<_, String>(3)
                    })
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                assert!(
                    package_files_plan.iter().any(|line| {
                        line.contains("catalog_exact_go_package_files_ordered_read")
                    }),
                    "{state}: {package_files_plan:?}"
                );
                assert!(
                    !package_files_plan
                        .iter()
                        .any(|line| { line.contains("SCAN ") || line.contains("AUTOMATIC") }),
                    "{state}: {package_files_plan:?}"
                );

                let returned = connection
                    .prepare(&format!(
                        "EXPLAIN QUERY PLAN {CALLABLE_VALUES_RETURNED_SQL}"
                    ))
                    .unwrap()
                    .query_map(params![manifest, shard, CALLABLE, 0_i64, 16_i64], |row| {
                        row.get::<_, String>(3)
                    })
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                assert!(
                    returned.iter().any(|line| line.contains(
                        "SEARCH fact USING INDEX catalog_callable_value_returned_lookup"
                    )),
                    "{state}: {returned:?}"
                );
                assert!(
                    !returned
                        .iter()
                        .any(|line| { line.contains("SCAN fact") || line.contains("AUTOMATIC") }),
                    "{state}: {returned:?}"
                );

                let callbacks = connection
                    .prepare(&format!(
                        "EXPLAIN QUERY PLAN {CALLABLE_VALUES_CALLBACK_SQL}"
                    ))
                    .unwrap()
                    .query_map(
                        params![
                            manifest,
                            shard,
                            CALLABLE,
                            callback_json,
                            1_i64,
                            1_i64,
                            16_i64
                        ],
                        |row| row.get::<_, String>(3),
                    )
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                assert!(
                    callbacks.iter().any(|line| line.contains(
                        "SEARCH fact USING INDEX catalog_callable_value_callback_lookup"
                    )),
                    "{state}: {callbacks:?}"
                );
                assert!(
                    !callbacks
                        .iter()
                        .any(|line| { line.contains("SCAN fact") || line.contains("AUTOMATIC") }),
                    "{state}: {callbacks:?}"
                );

                let coverage = connection
                    .prepare(&format!(
                        "EXPLAIN QUERY PLAN {CALLABLE_VALUES_COVERAGE_SQL}"
                    ))
                    .unwrap()
                    .query_map(
                        params![manifest, shard, "returned-callables", CALLABLE, 16_i64],
                        |row| row.get::<_, String>(3),
                    )
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                assert!(
                    coverage.iter().any(|line| line.contains(
                        "SEARCH coverage USING INDEX catalog_callable_value_coverage_lookup"
                    )),
                    "{state}: {coverage:?}"
                );
                assert!(
                    !coverage.iter().any(|line| {
                        line.contains("SCAN coverage") || line.contains("AUTOMATIC")
                    }),
                    "{state}: {coverage:?}"
                );

                let anonymous_base = connection
                    .prepare(&format!(
                        "EXPLAIN QUERY PLAN {ANONYMOUS_CALLABLE_IDENTITY_SQL}"
                    ))
                    .unwrap()
                    .query_map(params![manifest, shard, "go.literal.plan.0"], |row| {
                        row.get::<_, String>(3)
                    })
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                assert!(
                    anonymous_base.iter().any(|line| line.contains(
                        "SEARCH identity USING INDEX sqlite_autoindex_catalog_anonymous_callable_identities_1"
                    )),
                    "{state}: {anonymous_base:?}"
                );
                assert!(
                    !anonymous_base.iter().any(|line| {
                        line.contains("SCAN ")
                            || line.contains("AUTOMATIC")
                            || line.contains("TEMP B-TREE")
                            || line.contains("CO-ROUTINE")
                    }),
                    "{state}: {anonymous_base:?}"
                );

                for (reader_sql, table_name) in [
                    (
                        ANONYMOUS_CALLABLE_IDENTITY_ANCHORS_SQL,
                        "catalog_anonymous_callable_identity_anchors",
                    ),
                    (
                        ANONYMOUS_CALLABLE_IDENTITY_SHAPES_SQL,
                        "catalog_anonymous_callable_signature_shapes",
                    ),
                ] {
                    let children = connection
                        .prepare(&format!("EXPLAIN QUERY PLAN {reader_sql}"))
                        .unwrap()
                        .query_map(
                            params![manifest, shard, "go.literal.plan.0", 16_i64],
                            |row| row.get::<_, String>(3),
                        )
                        .unwrap()
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap();
                    let expected_index =
                        format!("SEARCH {table_name} USING INDEX sqlite_autoindex_{table_name}_1");
                    assert!(
                        children.iter().any(|line| line.contains(&expected_index)),
                        "{state}: {children:?}"
                    );
                    assert!(
                        !children.iter().any(|line| {
                            line.contains("SCAN ")
                                || line.contains("AUTOMATIC")
                                || line.contains("TEMP B-TREE")
                                || line.contains("CO-ROUTINE")
                        }),
                        "{state}: {children:?}"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod generated_production_cache_version_tests {
    use super::{
        generated_production_digest_for_cache_version, verify_recorded_generated_production_digest,
    };
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    fn migrated_catalog_preserves_old_epochs_and_reuses_the_new_production() {
        use super::{
            CatalogCoordinate, CatalogOpenMode, CatalogOptions, GeneratedProductionKey,
            SemanticPackCatalog, SemanticPackSelectorQuery,
        };
        use crate::analyzer::semantic_model::{CompilerOptions, SourceFormat, compile_source};

        let source = serde_json::json!({
            "schema_version": 2,
            "pack_id": "fixture.generated",
            "version": "1.0.0",
            "producer": {"name": "fixture-producer", "version": "1.0.0"},
            "language": "java", "ecosystem": "jvm",
            "compatibility": {"bifrost": ">=0.8.0, <1.0.0", "toolchains": []},
            "provenance": {"source": "fixture"}, "license": "Apache-2.0",
            "completeness": "complete",
            "safety": {"generated_code_only": false, "review_required": false},
            "shards": [{
                "id": "declarations", "activation": [{"package": {"name": "fixture", "version": "=1.0.0"}}],
                "payload": {"kind": "declaration_facts", "types": [{
                    "id": "fixture.type", "name": "fixture.Type", "type_kind": "class", "visibility": "public",
                    "locator": {"kind": "artifact", "path": "fixture.jar", "symbol": "fixture/Type.class"}
                }], "members": [], "relations": []}
            }]
        });
        let old_pack = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&source).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap();
        let mut revised = source;
        revised["completeness"] = serde_json::json!("partial");
        let new_pack = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&revised).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap();
        let key =
            GeneratedProductionKey::new("a".repeat(64), "fixture-producer", "1.0.0", 2).unwrap();
        let mut old_key = key.clone();
        old_key.production_digest = generated_production_digest_for_cache_version(
            key.input_digest(),
            key.producer_name(),
            key.producer_version(),
            key.schema_version(),
            super::GENERATED_PRODUCTION_CACHE_VERSION - 1,
        );
        let root = tempfile::tempdir().unwrap();
        let catalog = SemanticPackCatalog::open(
            root.path(),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        catalog.install_generated(&old_key, &old_pack).unwrap();
        let retained_key =
            GeneratedProductionKey::new("b".repeat(64), "fixture-producer", "1.0.0", 2).unwrap();
        catalog.install_generated(&retained_key, &old_pack).unwrap();
        let source_rows = |catalog: &SemanticPackCatalog| {
            catalog
                .connection
                .lock()
                .unwrap()
                .prepare(
                    "SELECT manifest_digest, source_kind, source_id, installed_at
                     FROM catalog_sources
                     ORDER BY manifest_digest, source_kind, source_id",
                )
                .unwrap()
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        };
        let original_sources = source_rows(&catalog);
        assert_eq!(original_sources.len(), 2);
        // Recreate schema 8, with both an old and a still-current digest.
        catalog.connection.lock().unwrap().execute_batch(
            "CREATE UNIQUE INDEX catalog_generated_productions_identity ON catalog_generated_productions(input_digest, producer_name, producer_version, schema_version);
             ALTER TABLE catalog_generated_productions DROP COLUMN generated_cache_version;
             DROP VIEW catalog_verified_generated_productions;
             DROP TABLE catalog_shard_validations;
             DROP TABLE catalog_anonymous_callable_signature_shapes;
             DROP TABLE catalog_anonymous_callable_identity_anchors;
             DROP TABLE catalog_anonymous_callable_identities;
             DROP TABLE catalog_callable_value_coverage;
             DROP TABLE catalog_callable_value_facts;
             DROP TABLE catalog_callable_values_indexed_shards;
             DROP TABLE catalog_exact_go_package_files;
             DROP TABLE catalog_exact_go_packages;
             DROP TABLE catalog_exact_go_source_files;
             DROP TABLE catalog_exact_go_source_sets;
             PRAGMA user_version = 8;"
        ).unwrap();
        drop(catalog);

        let catalog = SemanticPackCatalog::open(
            root.path(),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        assert_eq!(source_rows(&catalog), original_sources);
        let query = SemanticPackSelectorQuery {
            language: "java".to_owned(),
            ecosystem: "jvm".to_owned(),
            package: Some(CatalogCoordinate {
                name: "fixture".to_owned(),
                version: Some(semver::Version::new(1, 0, 0)),
            }),
            module: None,
            toolchain: None,
            target: None,
            configuration: None,
            artifact_sha256: None,
            bifrost_version: semver::Version::new(0, 12, 0),
        };
        assert!(
            catalog
                .generated_production(&retained_key)
                .unwrap()
                .is_some()
        );
        let candidates = catalog.candidates_bounded(&query, 1).unwrap();
        assert_eq!(candidates.len(), 1, "{candidates:?}");
        assert_eq!(candidates[0].source_id(), retained_key.source_id());
        let installed = catalog
            .install_generated(&key, &new_pack)
            .expect("new epoch coexists after migration");
        assert_eq!(
            catalog.generated_production(&key).unwrap().unwrap(),
            installed.production
        );
        assert!(
            catalog.install_generated(&key, &old_pack).is_err(),
            "one exact production key cannot change its output"
        );
        let historical_manifest: String = catalog.connection.lock().unwrap().query_row(
            "SELECT manifest_digest FROM catalog_generated_productions WHERE production_digest = ?1",
            [old_key.production_digest()], |row| row.get(0),
        ).unwrap();
        assert_eq!(historical_manifest, old_pack.manifest.content_sha256);
        let sources: std::collections::BTreeSet<_> = catalog
            .candidates(&query)
            .unwrap()
            .iter()
            .map(|candidate| candidate.source_id().to_owned())
            .collect();
        assert_eq!(
            sources,
            [key.source_id(), retained_key.source_id()]
                .into_iter()
                .collect()
        );
        drop(catalog);
        let reopened = SemanticPackCatalog::open(
            root.path(),
            CatalogOpenMode::ReadOnly,
            CatalogOptions::default(),
        )
        .unwrap();
        assert_eq!(
            reopened.generated_production(&key).unwrap().unwrap(),
            installed.production
        );
    }

    #[test]
    #[hardwon("#3357: startup cache reuse rejected verified entries after an epoch change")]
    fn recorded_cache_version_verifies_identity_without_current_cache_epoch() {
        let input = "a".repeat(64);
        let recorded = generated_production_digest_for_cache_version(
            &input,
            "fixture-producer",
            "1.0.0",
            1,
            8,
        );
        assert!(
            verify_recorded_generated_production_digest(
                &recorded,
                &input,
                "fixture-producer",
                "1.0.0",
                1,
                8,
            )
            .unwrap()
        );
        assert!(
            !verify_recorded_generated_production_digest(
                &recorded,
                &input,
                "fixture-producer",
                "1.0.0",
                1,
                9,
            )
            .unwrap()
        );
    }

    use super::{CATALOG_SCHEMA_VERSION, default_semantic_pack_catalog_root_with_override};
    use std::ffi::OsString;
    use std::path::Path;

    #[test]
    #[hardwon("be576f7e556b: a generated production cache epoch change reused an old identity")]
    fn cache_version_separates_generated_production_identity() {
        let input = "a".repeat(64);
        let first = generated_production_digest_for_cache_version(
            &input,
            "fixture-producer",
            "1.0.0",
            1,
            1,
        );
        let second = generated_production_digest_for_cache_version(
            &input,
            "fixture-producer",
            "1.0.0",
            1,
            2,
        );

        assert_ne!(first, second);
    }

    #[test]
    fn explicit_cache_root_shares_generated_productions_across_workspaces() {
        let cache_root = OsString::from("shared-semantic-packs");
        let first = default_semantic_pack_catalog_root_with_override(
            Path::new("workspace-a"),
            Some(cache_root.clone()),
        );
        let second = default_semantic_pack_catalog_root_with_override(
            Path::new("workspace-b"),
            Some(cache_root),
        );

        assert_eq!(first, second);
        assert_eq!(
            first,
            Path::new("shared-semantic-packs")
                .join(format!("semantic-pack-catalog.v{CATALOG_SCHEMA_VERSION}"))
        );
    }
}

#[cfg(test)]
mod acquisition_receipt_tests {
    use brokk_bifrost_test_macros::hardwon;
    use std::fs;

    use semver::Version;
    use tempfile::TempDir;

    use super::{
        AcquisitionReceiptRequest, CatalogCoordinate, GeneratedProductionKey,
        SemanticPackSelectorQuery, lower_hex_string, receipt_object_is_valid,
    };

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
        let digest = lower_hex_string(&crate::analyzer::canonical_hash::sha256_bytes(bytes));
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

#[cfg(test)]
mod native_compatibility_catalog_tests {
    use super::{
        CatalogCoordinate, CatalogOpenMode, CatalogOptions, DurablePackSource,
        DurablePackSourceKind, SemanticPackCatalog, SemanticPackSelectorQuery,
    };
    use crate::analyzer::semantic_model::{CompilerOptions, SourceFormat, compile_source};
    use brokk_bifrost_test_macros::hardwon;
    use semver::Version;

    fn compiled_pack(
        schema_version: u32,
    ) -> crate::analyzer::semantic_model::CompiledSemanticModelPack {
        let compatibility = if schema_version
            >= crate::analyzer::semantic_model::VERSION_INDEPENDENT_COMPATIBILITY_SCHEMA_VERSION
        {
            serde_json::json!({
                "toolchains": [{"name": "jdk", "requirement": ">=21.0.0, <22.0.0"}]
            })
        } else {
            serde_json::json!({
                "bifrost": ">=0.8.0, <1.0.0",
                "toolchains": [{"name": "jdk", "requirement": ">=21.0.0, <22.0.0"}]
            })
        };
        let source = serde_json::json!({
            "schema_version": schema_version,
            "pack_id": format!("fixture.schema-{schema_version}"),
            "version": "1.0.0",
            "producer": {"name": "fixture-producer", "version": "1.0.0"},
            "language": "java",
            "ecosystem": "jvm",
            "compatibility": compatibility,
            "provenance": {"source": "catalog-compatibility-test"},
            "license": "Apache-2.0",
            "completeness": "complete",
            "safety": {"generated_code_only": false, "review_required": false},
            "shards": [{
                "id": "declarations",
                "activation": [{"package": {"name": "fixture", "version": "=1.0.0"}}],
                "payload": {"kind": "declaration_facts", "types": [{
                    "id": "fixture.type",
                    "name": "fixture.Type",
                    "type_kind": "class",
                    "visibility": "public",
                    "locator": {"kind": "artifact", "path": "fixture.jar", "symbol": "fixture/Type.class"}
                }], "members": [], "relations": []}
            }]
        });
        compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&source).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap()
    }

    fn query(engine_version: &str, toolchain_version: &str) -> SemanticPackSelectorQuery {
        SemanticPackSelectorQuery {
            language: "java".to_owned(),
            ecosystem: "jvm".to_owned(),
            package: Some(CatalogCoordinate {
                name: "fixture".to_owned(),
                version: Some(Version::parse("1.0.0").unwrap()),
            }),
            module: None,
            toolchain: Some(CatalogCoordinate {
                name: "jdk".to_owned(),
                version: Some(Version::parse(toolchain_version).unwrap()),
            }),
            target: None,
            configuration: None,
            artifact_sha256: None,
            bifrost_version: Version::parse(engine_version).unwrap(),
        }
    }

    #[test]
    #[hardwon("#3815: native pack admission incorrectly inherited the legacy engine-version gate")]
    fn schema_eight_ignores_engine_version_while_legacy_range_still_filters() {
        let root = tempfile::tempdir().unwrap();
        let root_path = std::fs::canonicalize(root.path()).unwrap();
        let catalog = SemanticPackCatalog::open(
            &root_path,
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        let legacy = compiled_pack(7);
        let native = compiled_pack(8);
        let source = |source_id: &str| DurablePackSource {
            kind: DurablePackSourceKind::Installed,
            source_id: source_id.to_owned(),
        };
        catalog.install(&legacy, &source("legacy")).unwrap();
        catalog.install(&native, &source("native")).unwrap();
        let repeated = catalog.install(&native, &source("native")).unwrap();
        assert!(
            !repeated.inserted_manifest,
            "exact verified native install is reusable"
        );

        let candidates = catalog.candidates(&query("9.0.0", "21.0.2")).unwrap();
        assert_eq!(candidates.len(), 1, "{candidates:?}");
        assert_eq!(
            candidates[0].manifest_digest(),
            native.manifest.content_sha256.as_str()
        );
        assert!(
            catalog
                .version_near_misses(&query("9.0.0", "21.0.2"))
                .unwrap()
                .is_empty()
        );

        let engine_supported = catalog.candidates(&query("0.12.0", "21.0.2")).unwrap();
        assert_eq!(engine_supported.len(), 2, "{engine_supported:?}");
        let bad_toolchain_query = query("9.0.0", "17.0.10");
        assert!(catalog.candidates(&bad_toolchain_query).unwrap().is_empty());
        let near_misses = catalog.version_near_misses(&bad_toolchain_query).unwrap();
        assert_eq!(near_misses.len(), 1, "{near_misses:?}");
        assert_eq!(
            near_misses[0].manifest_digest,
            native.manifest.content_sha256
        );
        assert_eq!(near_misses[0].coordinate, "toolchain jdk");

        let persisted_shapes: Vec<(u32, Option<String>)> = {
            let connection = catalog.connection.lock().unwrap();
            let mut statement = connection
                .prepare(
                    "SELECT schema_version, bifrost_compatibility FROM catalog_packs
                     ORDER BY schema_version",
                )
                .unwrap();
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        assert_eq!(
            persisted_shapes,
            [(7, Some(">=0.8.0, <1.0.0".to_owned())), (8, None)]
        );
        drop(catalog);

        let reopened = SemanticPackCatalog::open(
            &root_path,
            CatalogOpenMode::ReadOnly,
            CatalogOptions::default(),
        )
        .unwrap();
        let reopened_candidates = reopened.candidates(&query("9.0.0", "21.0.2")).unwrap();
        assert_eq!(reopened_candidates.len(), 1, "{reopened_candidates:?}");
        assert_eq!(
            reopened_candidates[0].manifest_digest(),
            native.manifest.content_sha256.as_str()
        );
    }
}

#[cfg(test)]
mod activation_receipt_catalog_tests {
    use super::{CatalogOptions, DurablePackSource, DurablePackSourceKind, SemanticPackCatalog};
    use crate::analyzer::semantic_model::{
        ActivationOrigin, ActivationReceipt, ActivationReceiptInvocation, CatalogCoordinate,
        CompilerOptions, SemanticModelActivationEvidence, SemanticModelActivationRequest,
        SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome, SourceFormat, compile_source,
    };
    use crate::cancellation::CancellationToken;
    use semver::Version;
    use serde_json::Value;
    use std::sync::Arc;

    fn fixture_pack(pack_id: &str, type_id: &str) -> super::CompiledSemanticModelPack {
        let source = serde_json::json!({
            "schema_version": 2,
            "pack_id": pack_id,
            "version": "1.0.0",
            "producer": {"name": "activation-receipt-catalog-test", "version": "1.0.0"},
            "language": "java",
            "ecosystem": "maven",
            "compatibility": {"bifrost": ">=0.8.0, <1.0.0"},
            "provenance": {"source": "activation-receipt-catalog-test"},
            "license": "Apache-2.0",
            "completeness": "complete",
            "safety": {"generated_code_only": false, "review_required": false},
            "shards": [{
                "id": "declarations",
                "activation": [{"package": {"name": "com.acme:widget", "version": "=1.0.0"}}],
                "payload": {"kind": "declaration_facts", "types": [{
                    "id": type_id,
                    "name": format!("com.acme.{type_id}"),
                    "type_kind": "class",
                    "visibility": "public",
                    "locator": {"kind": "artifact", "path": "widget.jar", "symbol": format!("com/acme/{type_id}.class")}
                }], "members": [], "relations": []}
            }]
        });
        compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&source).expect("fixture serializes"),
            &CompilerOptions::default(),
        )
        .unwrap_or_else(|diagnostics| panic!("catalog fixture does not compile: {diagnostics:#?}"))
    }

    fn request() -> SemanticModelActivationRequest {
        SemanticModelActivationRequest {
            bifrost_version: Version::parse("0.13.1").expect("valid Bifrost version"),
            evidence: vec![SemanticModelActivationEvidence {
                language: "java".to_owned(),
                ecosystem: "maven".to_owned(),
                package: Some(CatalogCoordinate {
                    name: "com.acme:widget".to_owned(),
                    version: Some(Version::parse("1.0.0").expect("valid package version")),
                }),
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            }],
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        }
    }

    fn new_receipt(directory: &tempfile::TempDir, name: &str) -> Arc<ActivationReceipt> {
        ActivationReceipt::create(
            directory.path().join(name),
            &ActivationReceiptInvocation {
                invocation_id: name.to_owned(),
                tool: "query_code".to_owned(),
            },
        )
        .expect("receipt creates exclusively")
    }

    fn receipt_events(receipt: &ActivationReceipt, path: &std::path::Path) -> Vec<Value> {
        receipt.finish().expect("receipt footer flushes");
        std::fs::read(path)
            .expect("receipt is readable")
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).expect("receipt line is JSON"))
            .collect()
    }

    #[test]
    fn durable_load_miss_is_recorded_incomplete_with_only_a_usable_hash() {
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let pack = fixture_pack("receipt.missing-object", "type.missing-object");
        catalog
            .install(
                &pack,
                &DurablePackSource {
                    kind: DurablePackSourceKind::Installed,
                    source_id: "test:missing-object".to_owned(),
                },
            )
            .unwrap();
        let usable_pack = fixture_pack("receipt.usable-object", "type.usable-object");
        catalog
            .install(
                &usable_pack,
                &DurablePackSource {
                    kind: DurablePackSourceKind::Installed,
                    source_id: "test:usable-object".to_owned(),
                },
            )
            .unwrap();
        let candidate = catalog
            .candidates(&super::SemanticPackSelectorQuery {
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
                bifrost_version: Version::parse("0.13.1").unwrap(),
            })
            .unwrap()
            .into_iter()
            .find(|candidate| candidate.source_id() == "test:missing-object")
            .expect("installed pack is a durable candidate");
        // Leave the verified metadata intact so discovery still returns this
        // candidate. A missing stored object is a real quarantined load miss;
        // deleting its referenced metadata would violate catalog foreign keys.
        let object_path = catalog.root.join(super::storage::relative_object_path(
            &candidate.descriptor().stored_sha256,
        ));
        std::fs::remove_file(object_path).expect("remove only the fixture's stored object");

        let temp = tempfile::tempdir().unwrap();
        let name = "missing-object.jsonl";
        let receipt = new_receipt(&temp, name);
        let request = request();
        let mut frame = receipt.begin_activation(ActivationOrigin::WorkspaceDependencyPublication);
        frame.record_request(
            &request,
            None,
            super::super::runtime::RuntimeArtifactPublication::default(),
        );
        let resolution = super::super::runtime::resolve_active_semantic_models_observed(
            &catalog,
            &request,
            &CancellationToken::default(),
            Some(&mut frame),
        );
        let super::super::runtime::SemanticModelResolutionOutcome::Incomplete { usable, report } =
            resolution
        else {
            panic!("an actual durable candidate load miss remains incomplete");
        };
        let usable = usable.map(Arc::new);
        let runtime = SemanticModelRuntimeOutcome::Incomplete { usable, report };
        frame.finish_runtime_outcome(&runtime);
        receipt.bind_snapshot(None).unwrap();
        let events = receipt_events(&receipt, &temp.path().join(name));
        let resolution = events
            .iter()
            .find(|event| event["event"] == "resolution_finish")
            .unwrap();
        assert_eq!(resolution["data"]["status"], "incomplete");
        assert!(resolution["data"]["active_model_set_hash"].is_null());
        assert!(resolution["data"]["usable_model_set_hash"].is_string());
        let runtime = events
            .iter()
            .find(|event| event["event"] == "runtime_finish")
            .unwrap();
        assert_eq!(runtime["data"]["status"], "incomplete");
        assert!(runtime["data"]["active_model_set_hash"].is_null());
        assert!(runtime["data"]["usable_model_set_hash"].is_string());
        assert_eq!(runtime["data"]["publication"], "usable_not_published");
        let load = events
            .iter()
            .find(|event| {
                event["event"] == "candidate_load"
                    && event["data"]["candidate"]["source_id"] == "test:missing-object"
            })
            .unwrap();
        assert_eq!(load["data"]["outcome"]["status"], "quarantined");
        assert!(
            load["data"]["outcome"]["reason"]
                .as_str()
                .is_some_and(|reason| !reason.is_empty())
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| {
                    event["event"] == "final_selection"
                        && event["data"]["candidate"]["source_id"] == "test:usable-object"
                })
                .count(),
            1
        );
    }
}

#[cfg(test)]
mod generated_sharing_tests {
    use super::*;

    fn generated_fixture(version: &str) -> (CompiledSemanticModelPack, GeneratedProductionKey) {
        let source = serde_json::json!({
            "schema_version": SEMANTIC_MODEL_SCHEMA_VERSION,
            "pack_id": "cache.fixture", "version": version,
            "producer": {"name": "cache-test", "version": "1.0.0"},
            "language": "java", "ecosystem": "maven",
            "compatibility": {"toolchains": []},
            "provenance": {"source": "cache-test"},
            "license": "Apache-2.0", "completeness": "complete",
            "safety": {"generated_code_only": false, "review_required": false},
            "shards": [{
                "id": "types", "activation": [{"package": {"name": "cache:fixture"}}],
                "payload": {"kind": "declaration_facts", "types": [{
                    "id": "type.example", "name": "cache.Example",
                    "type_kind": "class", "visibility": "public",
                    "locator": {"kind": "artifact", "path": "cache/Example.class", "symbol": "cache.Example"}
                }]}
            }]
        });
        let pack = super::super::compile_source(
            super::super::SourceFormat::Json,
            &serde_json::to_vec(&source).unwrap(),
            &super::super::CompilerOptions::default(),
        )
        .unwrap();
        let key = GeneratedProductionKey::new(
            pack.manifest.content_sha256.clone(),
            &pack.manifest.producer.name,
            &pack.manifest.producer.version,
            pack.manifest.schema_version,
        )
        .unwrap();
        (pack, key)
    }

    #[test]
    fn unavailable_host_preserves_local_install_identity_and_lock() {
        let root = tempfile::tempdir().unwrap();
        let unavailable = root.path().join("not-a-directory");
        std::fs::write(&unavailable, b"occupied").unwrap();
        let mut local = SemanticPackCatalog::open(
            &root.path().join("local"),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        local.shared_generated_root = Some(unavailable);
        let (pack, key) = generated_fixture("1.2.0");
        local.install_generated(&key, &pack).unwrap();
        let identity = "b".repeat(64);
        local
            .install_generated_source_identity(&identity, &key)
            .unwrap();
        assert_eq!(
            local
                .generated_production_by_source_identity(&identity, &pack.manifest.producer)
                .unwrap()
                .unwrap()
                .key,
            key
        );
        assert!(
            local
                .generated_production_lock(&key)
                .unwrap()
                .try_acquire()
                .unwrap()
        );
    }

    #[test]
    fn host_cleanup_keeps_recent_hits_and_local_copy_repairs_eviction() {
        let root = tempfile::tempdir().unwrap();
        let shared_root = root.path().join("host");
        let mut local = SemanticPackCatalog::open(
            &root.path().join("local"),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        local.shared_generated_root = Some(shared_root.clone());
        let (old, old_key) = generated_fixture("1.2.0");
        local.install_generated(&old_key, &old).unwrap();
        let shared = SemanticPackCatalog::open(
            &shared_root,
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        let age_old = || {
            shared
                .connection
                .lock()
                .unwrap()
                .execute(
                    "UPDATE catalog_packs SET last_used_at = 0 WHERE manifest_digest = ?1",
                    [&old.manifest.content_sha256],
                )
                .unwrap();
        };
        age_old();
        assert!(local.generated_production(&old_key).unwrap().is_some());
        let (new, new_key) = generated_fixture("1.3.0");
        local.install_generated(&new_key, &new).unwrap();
        assert!(shared.has_verified_generated_production(&old_key).unwrap());
        age_old();
        let (newest, newest_key) = generated_fixture("1.4.0");
        local.install_generated(&newest_key, &newest).unwrap();
        assert!(!shared.has_verified_generated_production(&old_key).unwrap());
        assert!(local.generated_production(&old_key).unwrap().is_some());
        assert!(shared.has_verified_generated_production(&old_key).unwrap());
        shared
            .connection
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM catalog_sources WHERE source_id = ?1",
                [old_key.source_id()],
            )
            .unwrap();
        assert!(!shared.has_verified_generated_production(&old_key).unwrap());
        assert!(local.generated_production(&old_key).unwrap().is_some());
        assert!(shared.has_verified_generated_production(&old_key).unwrap());
    }

    #[test]
    fn host_reuse_copies_only_exact_generated_production_and_keeps_activation_local() {
        let root = tempfile::tempdir().unwrap();
        let shared_root = root.path().join("host");
        let mut first = SemanticPackCatalog::open(
            &root.path().join("first"),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        first.shared_generated_root = Some(shared_root.clone());
        let (pack, key) = generated_fixture("1.2.0");
        first
            .install(
                &pack,
                &DurablePackSource {
                    kind: DurablePackSourceKind::WorkspaceProduced,
                    source_id: "first-only".to_owned(),
                },
            )
            .unwrap();
        first.install_generated(&key, &pack).unwrap();
        let identity = "b".repeat(64);
        first
            .install_generated_source_identity(&identity, &key)
            .unwrap();
        let first_lock = first.generated_production_lock(&key).unwrap();
        assert!(first_lock.try_acquire().unwrap());
        let mut second = SemanticPackCatalog::open(
            &root.path().join("second"),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        second.shared_generated_root = Some(shared_root);
        let second_lock = second.generated_production_lock(&key).unwrap();
        assert!(!second_lock.try_acquire().unwrap());
        drop(first_lock);
        assert!(second_lock.try_acquire().unwrap());
        drop(second_lock);
        drop(first);
        let production = second
            .generated_production_by_source_identity(&identity, &pack.manifest.producer)
            .unwrap()
            .unwrap();
        assert_eq!(production.key, key);
        assert_eq!(production.manifest_digest, pack.manifest.content_sha256);
        let connection = second.connection.lock().unwrap();
        let sources: Vec<(String, String)> = connection
            .prepare("SELECT source_kind, source_id FROM catalog_sources")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(sources, vec![("generated".to_owned(), key.source_id())]);
        drop(connection);
        let missing = GeneratedProductionKey::new(
            "c".repeat(64),
            &pack.manifest.producer.name,
            &pack.manifest.producer.version,
            pack.manifest.schema_version,
        )
        .unwrap();
        assert!(second.generated_production(&missing).unwrap().is_none());
    }

    #[test]
    fn certificate_lookup_uses_its_primary_key_with_and_without_statistics() {
        for state in crate::cache_gc::PlannerStatisticsState::BOTH {
            let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
            let (pack, key) = generated_fixture("1.2.0");
            catalog
                .install(
                    &pack,
                    &DurablePackSource {
                        kind: DurablePackSourceKind::Installed,
                        source_id: "fixture".to_owned(),
                    },
                )
                .unwrap();
            catalog.install_generated(&key, &pack).unwrap();
            let connection = catalog.connection.lock().unwrap();
            let limits = decode_limits_digest(&catalog.options.decode_limits);
            for version in (1..)
                .filter(|version| *version != SHARD_VALIDATION_VERSION)
                .take(256)
            {
                connection
                    .execute(
                        "INSERT INTO catalog_shard_validations VALUES (?1, ?2, ?3, ?4)",
                        params![
                            pack.manifest.content_sha256,
                            pack.manifest.shards[0].shard_id,
                            version,
                            limits
                        ],
                    )
                    .unwrap();
            }
            state.install(&connection);
            let publication_plan = connection
                .prepare(&format!(
                    "EXPLAIN QUERY PLAN {SHARED_PRODUCTION_PRESENT_SQL}"
                ))
                .unwrap()
                .query_map([key.production_digest()], |row| row.get::<_, String>(3))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert!(
                publication_plan
                    .iter()
                    .any(|line| line.contains("SEARCH gp")),
                "{state}: {publication_plan:?}"
            );
            assert!(
                publication_plan
                    .iter()
                    .any(|line| line.contains("SEARCH p USING")),
                "{state}: {publication_plan:?}"
            );
            assert!(
                !publication_plan.iter().any(|line| line.contains("SCAN gp")
                    || line.contains("SCAN p ")
                    || line.contains("AUTOMATIC")),
                "{state}: {publication_plan:?}"
            );
            let details = connection
                .prepare(&format!("EXPLAIN QUERY PLAN {CERTIFIED_SHARD_SQL}"))
                .unwrap()
                .query_map(
                    params![
                        pack.manifest.content_sha256,
                        pack.manifest.shards[0].shard_id,
                        SHARD_VALIDATION_VERSION,
                        limits
                    ],
                    |row| row.get::<_, String>(3),
                )
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert!(details.iter().any(|line| line.contains("SEARCH catalog_shard_validations USING PRIMARY KEY")), "{state}: {details:?}");
            assert!(
                !details
                    .iter()
                    .any(|line| line.contains("SCAN catalog_shard_validations")),
                "{state}: {details:?}"
            );
        }
    }
}
