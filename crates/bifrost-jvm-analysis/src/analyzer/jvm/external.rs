#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::analyzer::semantic::call_binding::FixedArrayInvocation;

#[cfg(any(test, feature = "test-support"))]
type JavaExternalInvocationSelection<'a> = (&'a JvmExternalCallShape, Option<FixedArrayInvocation>);

#[cfg(any(test, feature = "test-support"))]
type JavaExternalInvocationDiagnostics = (
    Result<(u32, Option<FixedArrayInvocation>), JavaExternalInvocationFailure>,
    Option<Box<ProjectedNativeModelMemberSelection>>,
);

use crate::analyzer::jvm::dependency_evidence::MavenVersion;
use crate::analyzer::jvm::equivalent_java_type_identity;
use crate::analyzer::jvm::selection_codec as codec;
use brokk_bifrost_analysis::analyzer::store::jvm_external_publication::jvm_external_provider_id;
use brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::ProjectedNativeModelMember;
use brokk_bifrost_core::analyzer::canonical_hash::{CanonicalHasher, lower_hex_string};
use brokk_bifrost_core::content_digest::{ContentDigestCache, FileIdentity};
pub(super) use brokk_bifrost_semantic::analyzer::semantic_model::dependency::JvmProbeOperation as ExternalProbeOperation;
use brokk_bifrost_semantic::analyzer::semantic_model::dependency::{
    JvmAbsentProbe, JvmDependencyGap, JvmDependencyGapCause,
};
use sha2::{Digest, Sha256};
// Only the test-support invocation diagnostics (`invocation_with_diagnostics`
// and `invocation_diagnostic_family`) name the selection type.
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::ProjectedNativeModelMemberSelection;

use crate::analyzer::jvm::restrict_visibility as restrict_semantic_visibility;

use brokk_bifrost_analysis::analyzer::dependency_support::resolve_dependency_path as resolve_path;
use brokk_bifrost_analysis::analyzer::dependency_support::{
    declare_external_discovery_reads_complete, refuse_external_discovery_reads,
    report_external_discovery_read, report_path_observation,
};
use brokk_bifrost_analysis::analyzer::semantic_model::{
    ExternalDiscoveryRead, ExternalObservation, ExternalVerifier, ListedKind, PathObservationOp,
    canonicalize_observation, list_names, list_observation, stat_observation,
};

use crate::analyzer::jvm::dependency_discovery::discover_build_tools;

use crate::analyzer::jvm::dependency_discovery::{
    DiscoveryInputs, discover_metadata, manifest_scope,
};

use crate::analyzer::jvm::java_artifact::JavaClassSurfaceOutcome;

use crate::analyzer::jvm::java_artifact::JavaJarPackProducer;

use crate::analyzer::jvm::java_artifact::ZipDirectoryStatus;

use crate::analyzer::jvm::java_artifact::class_surface;

use crate::analyzer::jvm::java_artifact::source_type_kind;

use crate::analyzer::jvm::java_artifact::zip_directory_status;

use crate::analyzer::jvm::jdk_artifact::JdkSourceArchivePackProducer;

use crate::analyzer::jvm::jdk_artifact::detect_jdk_source_archive_layout;

use crate::analyzer::jvm::jmod_artifact::JdkJmodSetPackProducer;

use crate::analyzer::jvm::kotlin_artifact::KotlinSourceJarPackProducer;

use crate::analyzer::jvm::scala_artifact::ScalaSourceJarPackProducer;

use brokk_bifrost_analysis::analyzer::semantic::{LengthDelimitedDigest, StableDigest};
use brokk_bifrost_semantic::analyzer::semantic::ids::push_optional_bytes;

pub(crate) use brokk_bifrost_analysis::analyzer::semantic_model::overlay::jvm_external::JvmExternalTypeKind;

pub(crate) use brokk_bifrost_analysis::analyzer::semantic_model::overlay::jvm_external::pack_type_kind;

pub(crate) use brokk_bifrost_analysis::analyzer::semantic_model::overlay::jvm_external::qualified_model_symbols;

use brokk_bifrost_analysis::analyzer::semantic_model::ActivationSelector;

use brokk_bifrost_semantic::analyzer::semantic_model::producer::ArtifactProducerLimits;

use brokk_bifrost_semantic::analyzer::semantic_model::producer::ArtifactProduction;

use brokk_bifrost_semantic::analyzer::semantic_model::producer::ArtifactProductionRequest;

use brokk_bifrost_analysis::analyzer::semantic_model::ArtifactSourceIdentity;

use brokk_bifrost_analysis::analyzer::semantic_model::AuthoredPayload;

use brokk_bifrost_analysis::analyzer::semantic_model::AuthoredSemanticModelPack;

use brokk_bifrost_analysis::analyzer::semantic_model::AuthoredShard;

use brokk_bifrost_analysis::analyzer::semantic_model::BoundedDependencyDiagnostics;

use brokk_bifrost_analysis::analyzer::semantic_model::CatalogCoordinate;

use brokk_bifrost_analysis::analyzer::semantic_model::Compatibility;

use brokk_bifrost_analysis::analyzer::semantic_model::Completeness;

use brokk_bifrost_analysis::analyzer::semantic_model::DependencyArtifactRole;

use brokk_bifrost_analysis::analyzer::semantic_model::DependencyDiscoveryOutcome;

use brokk_bifrost_analysis::analyzer::semantic_model::DependencyDiscoveryProfile;

use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackAdapter;

use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackDiagnostic;

use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackDiagnosticSeverity;

use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackLimits;

use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackProduction;

use brokk_bifrost_analysis::analyzer::semantic_model::DependencyProvenance;

use brokk_bifrost_analysis::analyzer::semantic_model::ExactDependencyArtifact;

use brokk_bifrost_semantic::analyzer::semantic_model::producer::ExternalArtifactKind;

use brokk_bifrost_semantic::analyzer::semantic_model::producer::ExternalArtifactPackProducer;

use brokk_bifrost_analysis::analyzer::semantic_model::{HierarchyFact, HierarchyKind};

use brokk_bifrost_analysis::analyzer::semantic_model::Locator;

use brokk_bifrost_analysis::analyzer::semantic_model::MemberFact;

use brokk_bifrost_analysis::analyzer::semantic_model::MemberKind;

use brokk_bifrost_analysis::analyzer::semantic_model::NameSelector;

use brokk_bifrost_analysis::analyzer::semantic_model::Producer;

use brokk_bifrost_semantic::analyzer::semantic_model::producer::ProducerDiagnostic;

use brokk_bifrost_semantic::analyzer::semantic_model::producer::ProducerDiagnosticSeverity;

use brokk_bifrost_analysis::analyzer::semantic_model::Provenance;

use brokk_bifrost_analysis::analyzer::semantic_model::ResolvedDependency;

use brokk_bifrost_analysis::analyzer::semantic_model::ResolvedDependencyArtifact;
use brokk_bifrost_analysis::analyzer::semantic_model::ResolvedDependencyArtifactInput;

use brokk_bifrost_analysis::analyzer::semantic_model::Safety;

use brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelActivationEvidence;

use brokk_bifrost_analysis::analyzer::semantic_model::Signature;

use brokk_bifrost_analysis::analyzer::semantic_model::SuppressedDiagnostics;

use brokk_bifrost_analysis::analyzer::semantic_model::TypeFact;

use brokk_bifrost_analysis::analyzer::semantic_model::TypeKind;

use brokk_bifrost_analysis::analyzer::semantic_model::TypeRef;

use brokk_bifrost_analysis::analyzer::semantic_model::Visibility;

use brokk_bifrost_analysis::analyzer::semantic_model::normalize_artifact_locator_paths;

use brokk_bifrost_semantic::analyzer::semantic_model::producer::read_exact_artifact_while;

use brokk_bifrost_core::analyzer::model::JVM_SEMANTIC_PACK_LANGUAGES;

use brokk_bifrost_core::analyzer::config::JvmAnalyzerConfig;

use brokk_bifrost_core::analyzer::config::JvmDependencyDiscoveryMode;

use brokk_bifrost_core::analyzer::config::JvmExternalArtifact;

use brokk_bifrost_core::analyzer::config::JvmExternalArtifactOrigin;

use brokk_bifrost_core::analyzer::config::JvmExternalDependencies;

use brokk_bifrost_core::analyzer::config::JvmMavenCoordinate;

use brokk_bifrost_core::analyzer::project::Project;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
use brokk_bifrost_core::hash::{HashMap, HashSet};
use brokk_bifrost_jvm::java::declarations::{
    class_like_body_children_rev, determine_package_name, explicit_java_source_visibility,
    is_class_like_declaration_kind, node_text, parse_tree,
};
use jclassfile::attributes::Attribute;
use jclassfile::constant_pool::ConstantPool;
use semver::Version;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{Cursor, Read};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;

fn is_public_external_type(external_type: &JvmExternalType) -> bool {
    external_type.visibility == JvmVisibility::Public
}
use tree_sitter::Parser;
use zip::ZipArchive;

use brokk_bifrost_analysis::analyzer::topology::DependencyScope;
use brokk_bifrost_core::cancellation::CancellationToken;

const MAX_ARCHIVE_ENTRIES: usize = 10_000;
pub(super) const MAX_INDEX_ARTIFACTS: usize = 128;
const MAX_SOURCE_ENTRY_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ANALYZER_SOURCE_ENTRY_BYTES: u64 = 1024 * 1024;
const MAX_CLASS_ENTRY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_ARCHIVE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_TOTAL_INDEX_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ANALYZER_SOURCE_TYPES: usize = 4_096;
const MAX_JDK_JMOD_FILES: usize = 512;
/// The most member declarations one indexed artifact may contribute to the
/// external member surface (#1900).
///
/// The type-level index bounds an artifact by bytes ([`MAX_TOTAL_ARCHIVE_BYTES`]
/// against the shared [`MAX_TOTAL_INDEX_BYTES`] remainder) and by entries
/// ([`MAX_ARCHIVE_ENTRIES`]). Members are a second dimension: one class entry
/// well inside the byte bound can declare thousands of them, so a jar of
/// generated API classes could otherwise multiply the retained index far past
/// what its bytes suggest. Charging members separately keeps the retained
/// surface bounded in the dimension that actually grows.
///
/// Reaching the bound is recorded as a production diagnostic, so the artifact
/// reports as declared-but-not-fully-indexed rather than as a complete surface
/// that happens to declare fewer members.
const MAX_ARTIFACT_MEMBERS: usize = 32_768;
/// The most owner types one member lookup may walk while following an indexed
/// owner's supertypes.
///
/// An indexed hierarchy comes from class files that were compiled separately
/// and may disagree, so a cycle is possible; the visited set already stops one,
/// and this bounds the work of a wide but acyclic hierarchy as well.
// #11912: a read-only census of 50,785 classes in JDK 25 and five large
// Kotlin/CodeQL tool archives found a maximum owner closure of 34. Keep 64
// with measured headroom, and expose reaching it as a deterministic limit.
const MAX_MEMBER_SURFACE_OWNERS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OwnerWalkCompletion {
    Complete,
    IncompleteHierarchy,
    Cycle,
    FixedLimit,
}

// #10470: the dispatch identity binds the full attributed lookup gap set.
// v4: master moved this domain to v3 (fd6c7963fd); max of both sides + 1.
// v5: #10572 hashes each artifact type's class finality, which closes dispatch.
const JVM_EXTERNAL_DISPATCH_BEHAVIOR_DOMAIN: &[u8] = b"bifrost-jvm-external-dispatch-behavior/v5";
const JVM_EXTERNAL_INDEX_MEMO_DOMAIN: &[u8] = b"bifrost-jvm-external-index-memo/v2";
const JVM_EXTERNAL_GAP_IDENTITY_DOMAIN: &[u8] = b"bifrost-jvm-external-gap-identity/v1";
/// Domain of the read-free identity of one JDK's selected JMOD set.
const JDK_JMOD_SET_SOURCE_IDENTITY_DOMAIN: &[u8] = b"bifrost-jvm.jdk-jmod-set-source-identity/v1";
const JDK_DISCOVERY_HOME_ID_DOMAIN: &[u8] = b"bifrost-jvm.jdk-discovery-home-id/v1";
/// Domains of the content digests that pin a JDK's artifacts (#9559). Each one
/// names the framing it computes, so a cached digest can never be reused under
/// another framing: the exact source-set v1 frame over the home's `jmods/*.jmod`
/// members in UTF-8 byte order of their names, and the unframed SHA-256 of the
/// `src.zip` bytes.
const JDK_JMOD_SET_DIGEST_DOMAIN: &[u8] = b"bifrost-jvm.jdk-jmod-set-digest/v1";
const JDK_SOURCE_ZIP_DIGEST_DOMAIN: &[u8] = b"bifrost-jvm.jdk-source-zip-digest/v1";

/// Whom a production diagnostic is about.
///
/// A lookup may skip a gap only when it proves that nothing the gap concerns
/// can change its answer. Today only a gap about one declared dependency
/// artifact can be proven irrelevant, and only to a lookup of a type in an
/// unshadowable JDK package (#10470). Everything the producers cannot name
/// stays `Unattributed`, which no lookup ever skips.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GapAttribution {
    /// A declared dependency whose artifact the index could not use.
    Dependency,
    /// The JDK itself: no home, an invalid JMOD set.
    Jdk,
    /// Anything else, including entry caps, unreadable entries and the entry
    /// that stands for diagnostics discovery suppressed.
    Unattributed,
}

impl GapAttribution {
    fn tag(self) -> &'static [u8] {
        match self {
            Self::Dependency => b"dependency",
            Self::Jdk => b"jdk",
            Self::Unattributed => b"unattributed",
        }
    }
}

/// One production diagnostic with the structured facts a lookup needs to
/// decide whether to record it.
///
/// The coordinate of a declared dependency travels here as a field, so no
/// reader parses it back out of the message text.
#[derive(Debug, Clone)]
pub(crate) struct IndexGap {
    diagnostic: ProducerDiagnostic,
    dependency_id: Option<String>,
}

impl std::ops::Deref for IndexGap {
    type Target = ProducerDiagnostic;

    fn deref(&self) -> &ProducerDiagnostic {
        &self.diagnostic
    }
}

impl From<ProducerDiagnostic> for IndexGap {
    fn from(diagnostic: ProducerDiagnostic) -> Self {
        Self {
            diagnostic,
            dependency_id: None,
        }
    }
}

impl IndexGap {
    fn from_discovery(diagnostic: DependencyPackDiagnostic) -> Self {
        let dependency_id = diagnostic.dependency_id.clone();
        Self {
            diagnostic: discovery_producer_diagnostic(diagnostic),
            dependency_id,
        }
    }

    pub(crate) fn dependency_id(&self) -> Option<&str> {
        self.dependency_id.as_deref()
    }

    /// Derived from the diagnostic code and its structured coordinate; the
    /// message is never read.
    pub(crate) fn attribution(&self) -> GapAttribution {
        let code = self.diagnostic.code.as_str();
        if [
            super::producer_codes::JVM_DEPENDENCY_UNRESOLVED.code,
            super::producer_codes::JVM_DEPENDENCY_UNAVAILABLE.code,
        ]
        .contains(&code)
            && self.dependency_id.is_some()
        {
            GapAttribution::Dependency
        } else if [
            super::producer_codes::JDK_HOME_UNAVAILABLE.code,
            super::producer_codes::JDK_HOME_INVALID.code,
            super::producer_codes::JDK_JMODS_INVALID.code,
        ]
        .contains(&code)
        {
            GapAttribution::Jdk
        } else {
            GapAttribution::Unattributed
        }
    }

    /// Whether a lookup records this diagnostic as a gap in its answer.
    ///
    /// These retained boundary statuses are not provider failures. In
    /// particular an unacquired JDK remains a query obligation, rather than
    /// invalidating unrelated workspace-only reads.
    ///
    /// A declaration-scoped warning names the one declaration whose facts it
    /// degraded, and the producer already folded that loss into the
    /// declaration itself: an unresolved or undecodable signature clears
    /// `callable_family_complete`, `values_complete` or `callables_complete`,
    /// which the index carries as the owner's own `shapes_incomplete`. A read
    /// that consults the declaration sees that; a read that never does must not
    /// become incomplete because of it. Recording it for every lookup made one
    /// anonymous dependency class's erased signature drop every name-selected
    /// taint endpoint in the workspace (#10388).
    pub(crate) fn is_recorded(&self) -> bool {
        let code = self.diagnostic.code.as_str();
        !(code == super::producer_codes::JDK_HOME_UNAVAILABLE.code
            || code == super::producer_codes::JAVA_SOURCE_BINARY_CONFLICT.code
            || matches!(code, "artifact.kind" | "artifact.role")
            || self.diagnostic.declaration.is_some())
    }

    fn push_identity(&self, digest: &mut LengthDelimitedDigest) {
        digest.push(self.diagnostic.code.as_bytes());
        digest.push(match self.diagnostic.severity {
            ProducerDiagnosticSeverity::Warning => b"warning",
            ProducerDiagnosticSeverity::Error => b"error",
        });
        digest.push(self.attribution().tag());
        push_optional_bytes(digest, self.dependency_id.as_deref().map(str::as_bytes));
        digest.push(&[u8::from(self.is_recorded())]);
    }
}

#[derive(Clone, Copy)]
struct LookupContext<'a> {
    file: &'a brokk_bifrost_analysis::analyzer::ProjectFile,
    span: (usize, usize),
    name: LookupName<'a>,
    tier: &'static str,
}
#[derive(Clone, Copy)]
enum LookupName<'a> {
    Text(&'a str),
    Java(&'a brokk_bifrost_jvm::java::graph_support::JavaTypeName),
}

/// The sink a Java, Kotlin or Scala lookup reports the index's gaps to.
///
/// It wraps the analyzer only to reach the current query contexts: gaps go to
/// the request that is reading, never to the warm index and never as a
/// broadcast. The index is one value shared by every request, so it keeps no
/// handle of its own.
#[derive(Clone, Copy)]
pub(crate) struct QueryGapRecorder<'a> {
    sink: GapSink<'a>,
    lookup: Option<LookupContext<'a>>,
}

#[derive(Clone, Copy)]
enum GapSink<'a> {
    Analyzer(&'a dyn brokk_bifrost_analysis::analyzer::IAnalyzer),
    /// A hand-written fake for tests that look names up without an analyzer.
    #[cfg(test)]
    Collect(&'a std::cell::RefCell<Vec<brokk_bifrost_analysis::analyzer::QueryReadIncomplete>>),
}

impl<'a> QueryGapRecorder<'a> {
    pub(crate) fn at_lookup<'b>(
        &'b self,
        file: &'b brokk_bifrost_analysis::analyzer::ProjectFile,
        span: std::ops::Range<usize>,
        name: &'b str,
        tier: &'static str,
    ) -> QueryGapRecorder<'b> {
        QueryGapRecorder {
            sink: self.sink,
            lookup: Some(LookupContext {
                file,
                span: (span.start, span.end),
                name: LookupName::Text(name),
                tier,
            }),
        }
    }

    pub(crate) fn at_type_lookup<'b>(
        &'b self,
        file: &'b brokk_bifrost_analysis::analyzer::ProjectFile,
        span: std::ops::Range<usize>,
        name: &'b brokk_bifrost_jvm::java::graph_support::JavaTypeName,
        tier: &'static str,
    ) -> QueryGapRecorder<'b> {
        QueryGapRecorder {
            sink: self.sink,
            lookup: Some(LookupContext {
                file,
                span: (span.start, span.end),
                name: LookupName::Java(name),
                tier,
            }),
        }
    }

    pub(crate) fn new(analyzer: &'a dyn brokk_bifrost_analysis::analyzer::IAnalyzer) -> Self {
        Self {
            sink: GapSink::Analyzer(analyzer),
            lookup: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn collecting(
        reasons: &'a std::cell::RefCell<Vec<brokk_bifrost_analysis::analyzer::QueryReadIncomplete>>,
    ) -> Self {
        Self {
            sink: GapSink::Collect(reasons),
            lookup: None,
        }
    }

    fn record(self, index: &JvmExternalDeclarationIndex, include: impl Fn(&IndexGap) -> bool) {
        for gap in index
            .production_diagnostics
            .iter()
            .filter(|gap| gap.is_recorded() && include(gap))
        {
            self.record_gap(gap);
        }
    }

    fn record_gap(&self, gap: &IndexGap) {
        self.record_reason(super::producer_codes::classify(gap));
    }

    fn record_reason(&self, reason: brokk_bifrost_analysis::analyzer::QueryReadIncomplete) {
        let reason = match self.lookup {
            Some(LookupContext {
                file,
                span: (start, end),
                name,
                tier,
            }) => reason.attributed(
                brokk_bifrost_analysis::analyzer::i_analyzer::QueryLookupProvenance {
                    file: file.clone(),
                    byte_span: start..end,
                    name: match name {
                        LookupName::Text(name) => name.into(),
                        LookupName::Java(name) => name.render().into_boxed_str(),
                    },
                    tier,
                },
            ),
            None => reason,
        };
        match self.sink {
            GapSink::Analyzer(analyzer) => analyzer.record_query_incomplete(reason),
            #[cfg(test)]
            GapSink::Collect(reasons) => {
                let mut reasons = reasons.borrow_mut();
                if !reasons.contains(&reason) {
                    reasons.push(reason);
                }
            }
        }
    }

    /// Every gap the index carries. Private: only the final outcome of a
    /// resolution may record unconditionally, through
    /// [`JvmExternalDeclarations::record_all_gaps`] or the enumeration read
    /// [`Self::whole_index`].
    fn all(self, index: &JvmExternalDeclarationIndex) {
        self.record(index, |_| true);
    }

    /// An enumeration over the whole built index (a receipt replay, a Scala
    /// given/implicit discovery, an import-memo fill) that no single lookup can
    /// state: it depends on every artifact the index carries.
    pub(crate) fn whole_index(self, index: &JvmExternalDeclarationIndex) {
        self.all(index);
    }

    /// Every gap not attributed to a declared dependency artifact. A hit that
    /// no dependency artifact can outrank records only these.
    fn non_dependency(self, index: &JvmExternalDeclarationIndex) {
        self.record(index, |gap| gap.attribution() != GapAttribution::Dependency);
    }

    /// Every gap attributed to a declared dependency artifact: the gapped
    /// artifacts that may precede a hit's provider.
    fn dependency(self, index: &JvmExternalDeclarationIndex) {
        self.record(index, |gap| gap.attribution() == GapAttribution::Dependency);
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct JvmExternalDeclarationIndex {
    inventory_providers: Vec<String>,
    pub(super) inventory_generation: Option<i64>,
    types_by_fqn: HashMap<String, JvmExternalType>,
    /// The member surface of every indexed owner whose own artifact entry this
    /// index read to the end, keyed by the owner's fully-qualified name
    /// (#1900).
    ///
    /// An owner with no entry here has no read member surface at all, which is
    /// not the same as an owner that declares no members: see
    /// [`JvmIndexedOwnerSurface`].
    members_by_owner: HashMap<String, JvmIndexedOwnerSurface>,
    production_diagnostics: Vec<IndexGap>,
    /// Whether Maven build files show a platform override, cannot show one,
    /// or leave the answer unknown because a relevant input may be omitted.
    /// Gradle compile options are not read.
    platform_override: super::dependency_discovery::MavenPlatformOverride,
    /// Stable, path-independent identity of the effective declaration surface
    /// this index exposes to type, member, and hierarchy resolution.
    dispatch_behavior_identity: OnceLock<StableDigest>,
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static EXTERNAL_INDEX_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
thread_local! {
    static EXTERNAL_INDEX_ARTIFACT_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn external_index_build_count_for_test() -> usize {
    EXTERNAL_INDEX_BUILDS.get()
}

/// The sample of everything the external index decodes, for the carry decision
/// (#12745): one traced discovery pass (the pass `build_for_project` runs) and,
/// for every artifact it selects, wherever it lives, the stat identity
/// (device, inode, size, mtime, ctime) of the binary and source jar. It also
/// folds in the scan outcome: every probe discovery made under a repository or
/// cache root with its found/absent/unreadable result, the diagnostics, and the
/// Maven platform override. A jar rewritten in place changes an identity; a jar
/// added under a scanned root flips a probe or resolves a coordinate. No jar is
/// read. The flag is false when an identity or a probe could not be read, or
/// discovery was cancelled or reported an incomplete reason: such a sample
/// never equals a carried one.
pub(crate) fn dependency_discovery_sample(
    analyzer: &dyn brokk_bifrost_analysis::analyzer::IAnalyzer,
    config: &JvmAnalyzerConfig,
    project: &dyn Project,
) -> (StableDigest, bool, [u8; 32]) {
    dependency_discovery_sample_with_identity(
        analyzer,
        config,
        project,
        jvm_artifact_change_identity,
        |path| artifact_content_digest(analyzer, path),
    )
}

// A build must verify its bytes independently of any digest its first sample
// admitted. This path always streams opened artifacts, including on Windows.
pub(crate) fn fresh_dependency_discovery_sample(
    analyzer: &dyn brokk_bifrost_analysis::analyzer::IAnalyzer,
    config: &JvmAnalyzerConfig,
    project: &dyn Project,
) -> (StableDigest, bool, [u8; 32]) {
    dependency_discovery_sample_with_identity(
        analyzer,
        config,
        project,
        jvm_artifact_change_identity,
        |path| {
            brokk_bifrost_analysis::analyzer::artifact_digest::rehash_file(
                analyzer
                    .snapshot_caches()
                    .map(|caches| caches.artifact_digests.as_ref()),
                path,
                hash_artifact,
            )
        },
    )
}

#[cfg(test)]
thread_local! {
    static FORCED_WEAK_ARTIFACT_IDENTITY: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

fn jvm_artifact_change_identity(
    path: &Path,
) -> std::io::Result<Option<brokk_bifrost_core::content_digest::FileIdentity>> {
    #[cfg(test)]
    if let Some(weak) = FORCED_WEAK_ARTIFACT_IDENTITY.get() {
        return if weak {
            Ok(None)
        } else {
            brokk_bifrost_core::content_digest::file_identity(path)
        };
    }
    brokk_bifrost_core::content_digest::artifact_change_identity(path)
}

// A metadata collision cannot certify separately reopened decoders. Decline
// retention even when both content samples match, while preserving this answer.
fn dependency_discovery_sample_with_identity(
    analyzer: &dyn brokk_bifrost_analysis::analyzer::IAnalyzer,
    config: &JvmAnalyzerConfig,
    project: &dyn Project,
    mut classify: impl FnMut(
        &Path,
    ) -> std::io::Result<
        Option<brokk_bifrost_core::content_digest::FileIdentity>,
    >,
    mut digest: impl FnMut(&Path) -> std::io::Result<[u8; 32]>,
) -> (StableDigest, bool, [u8; 32]) {
    let mut strong = true;
    let mut sample = dependency_discovery_sample_with(config, project, |path| {
        if classify(path)?.is_none() {
            strong = false;
            let _reason = brokk_bifrost_core::profiling::read_refusal_scope(Some(
                brokk_bifrost_core::profiling::ReadRefusal {
                    kind: "reuse_refused",
                    reason: format!("JVM artifact has no strong change-time identity: {path:?}"),
                    origin: std::panic::Location::caller(),
                },
            ));
            analyzer.refuse_read_reuse();
        }
        digest(path)
    });
    sample.1 &= strong;
    sample
}

fn dependency_discovery_sample_with(
    config: &JvmAnalyzerConfig,
    project: &dyn Project,
    mut digest_artifact: impl FnMut(&Path) -> std::io::Result<[u8; 32]>,
) -> (StableDigest, bool, [u8; 32]) {
    let mut trace = DependencyDiscoveryTrace::default();
    let inputs = manifest_scope(project, config);
    let discovery = resolve_jvm_semantic_pack_dependencies_traced(
        config,
        project,
        &inputs,
        &DependencyPackLimits::default(),
        None,
        Some(&mut trace),
    );
    // Unknown (an omitted listing could hide a manifest) is its own tag, so a
    // sample that could not see the override never equals one that could.
    let platform_override =
        if config.dependency_discovery.mode == JvmDependencyDiscoveryMode::Disabled {
            super::dependency_discovery::MavenPlatformOverride::NotVisible
        } else {
            super::dependency_discovery::maven_platform_override(&inputs)
        };
    // Unresolved coordinates are stable outcomes. Failed I/O is not an answer.
    let mut reusable = !discovery.cancelled
        && discovery.incomplete_reason.is_none()
        && !discovery.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == super::producer_codes::JVM_DEPENDENCY_UNAVAILABLE.code
        });
    let mut hash = CanonicalHasher::new(b"bifrost-jvm-external-discovery-sample:v2");
    hash.field("complete", &[u8::from(discovery.complete)]);
    let mut diagnostics: Vec<_> = discovery.diagnostics.iter().collect();
    diagnostics.sort_by_key(|diagnostic| {
        (
            &diagnostic.dependency_id,
            &diagnostic.code,
            &diagnostic.message,
            &diagnostic.location,
            match diagnostic.severity {
                DependencyPackDiagnosticSeverity::Warning => "warning",
                DependencyPackDiagnosticSeverity::Error => "error",
            },
        )
    });
    diagnostics.dedup_by(|a, b| {
        a.dependency_id == b.dependency_id
            && a.code == b.code
            && a.message == b.message
            && a.severity == b.severity
            && a.location == b.location
    });
    hash.sequence("diagnostics", &diagnostics, |hash, diagnostic| {
        codec::text(hash, "code", &diagnostic.code);
        codec::text(hash, "message", &diagnostic.message);
        codec::text(
            hash,
            "location",
            diagnostic.location.as_deref().unwrap_or(""),
        );
        codec::text(
            hash,
            "dependency",
            diagnostic.dependency_id.as_deref().unwrap_or(""),
        );
        codec::text(
            hash,
            "severity",
            match diagnostic.severity {
                DependencyPackDiagnosticSeverity::Warning => "warning",
                DependencyPackDiagnosticSeverity::Error => "error",
            },
        );
    });
    hash.field(
        "suppressed",
        &discovery.suppressed_diagnostics.total().to_le_bytes(),
    );
    let files: Vec<PathBuf> = discovery
        .dependencies
        .iter()
        .filter_map(jvm_artifact_from_dependency)
        .flat_map(|artifact| {
            std::iter::once(artifact.artifact_path).chain(artifact.source_artifact_path)
        })
        .collect();
    // Operational filesystem shape belongs only to conservative transient carry.
    let mut carry = CanonicalHasher::new(b"bifrost-jvm-artifact-stat-sample:v1");
    carry.field("platform_override", &[platform_override.tag()]);
    codec::paths(
        &mut carry,
        "repository_roots",
        &repository_roots(&config.external_dependencies),
    );
    codec::paths(
        &mut carry,
        "gradle_cache_roots",
        &gradle_cache_roots(&config.external_dependencies),
    );
    carry.sequence("probes", &trace.resolution.steps, |hash, probe| {
        reusable &= !matches!(probe.outcome, ExternalProbeOutcome::Unreadable);
        probe.hash_into(hash);
    });
    codec::sorted_paths(&mut carry, "partial_manifests", &trace.partial_manifests);
    for path in &files {
        codec::path(&mut carry, "path", path);
        match brokk_bifrost_core::content_digest::metadata_change_identity(path) {
            Ok(Some(identity)) => codec::text(&mut carry, "identity", &format!("{identity:?}")),
            Ok(None) | Err(_) => reusable = false,
        }
    }
    hash.sequence("artifacts", &files, |hash, path| {
        codec::path(hash, "path", path);
        match digest_artifact(path) {
            Ok(digest) => hash.field("sha256", &digest),
            Err(_) => reusable = false,
        }
    });
    (
        StableDigest::from_array(hash.finish()),
        reusable,
        carry.finish(),
    )
}

// Use the producer's raw-file SHA-256 framing, without retaining artifact bytes.
// Identity is only a race guard; it never enters the persisted answer.
fn artifact_content_digest(
    analyzer: &dyn brokk_bifrost_analysis::analyzer::IAnalyzer,
    path: &Path,
) -> std::io::Result<[u8; 32]> {
    brokk_bifrost_analysis::analyzer::artifact_digest::digest_file(
        analyzer
            .snapshot_caches()
            .map(|caches| caches.artifact_digests.as_ref()),
        path,
        hash_artifact,
    )
}

fn hash_artifact(file: &mut std::fs::File, size: u64) -> std::io::Result<[u8; 32]> {
    use brokk_bifrost_semantic::analyzer::semantic_model::producer::{
        finish_digest, hash_exact_file,
    };
    let mut hash = Sha256::new();
    hash_exact_file(&mut hash, size, file)?;
    Ok(finish_digest(hash))
}

/// Record that an answer reads each provider's published inventory, at the
/// digest `snapshot` shows. A rebuilt index records it while it is built; a
/// carried index records it again from the same function, so the two receipts
/// name the same inventory inputs.
fn record_provider_inventory_reads(
    analyzer: &dyn brokk_bifrost_analysis::analyzer::IAnalyzer,
    snapshot: &rusqlite::Transaction<'_>,
    providers: &[String],
) -> brokk_bifrost_analysis::analyzer::store::Result<()> {
    use brokk_bifrost_analysis::analyzer::read_ledger::{LookupKind, LookupQuestion, ReadKey};
    use brokk_bifrost_semantic::analyzer::semantic::derivation::{
        DerivationKindId, DerivationQuestion,
    };
    for provider in providers {
        analyzer.record_read(ReadKey::Lookup {
            kind: LookupKind::Derivation(DerivationKindId(
                "derivation:jvm_external_provider_inventory:v1",
            )),
            question: LookupQuestion::Derivation(DerivationQuestion {
                language: None,
                subject: None,
                rel_path: None,
                name: Some(provider.clone().into_boxed_str()),
            }),
            digest: StableDigest::from_array(
                brokk_bifrost_analysis::analyzer::store::AnalyzerStore::jvm_external_provider_inventory_digest_in_snapshot(snapshot, provider)?,
            ),
        });
    }
    Ok(())
}

#[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
pub(crate) fn get_or_build_external_declaration_index(
    analyzer: &dyn brokk_bifrost_analysis::analyzer::IAnalyzer,
    slot: &crate::analyzer::jvm::authority::JvmExternalIndexSlot,
    authority: (
        brokk_bifrost_core::analyzer::model::Language,
        brokk_bifrost_analysis::analyzer::WorkspaceFactFamily,
    ),
    config: &JvmAnalyzerConfig,
    store: &brokk_bifrost_analysis::analyzer::store::AnalyzerStore,
) -> Arc<JvmExternalDeclarationIndex> {
    match store.jvm_external_inventory_generation() {
        Ok(generation) => slot.invalidate_inventory_generation(generation),
        Err(error) => analyzer.record_query_failure(error),
    }
    let generation_project =
        brokk_bifrost_analysis::analyzer::workspace::generation_dependency_discovery_project(
            analyzer,
        );
    let project = generation_project.as_ref();
    slot.get_or_build(
        analyzer,
        authority,
        || dependency_discovery_sample(analyzer, config, project),
        || fresh_dependency_discovery_sample(analyzer, config, project),
        |carried| {
            // The carry check settles the inventory generation, so the
            // digests read here equal the ones the carried build recorded.
            if let Err(error) = store.read_conn().and_then(|conn| {
                let snapshot = conn.unchecked_transaction()?;
                record_provider_inventory_reads(analyzer, &snapshot, &carried.inventory_providers)
            }) {
                analyzer.record_query_failure(error);
            }
        },
        || {
            #[cfg(any(test, feature = "test-support"))]
            EXTERNAL_INDEX_BUILDS.set(EXTERNAL_INDEX_BUILDS.get() + 1);
            let value = JvmExternalDeclarationIndex::build_for_project_with_inventory(
                config, project, store, analyzer,
            )
            .unwrap_or_else(|error| {
                analyzer.record_query_failure(error.clone());
                eprintln!("JVM external inventory publication failed: {error}");
                JvmExternalDeclarationIndex::build_for_project(config, project)
            });
            // Stable gaps go to the lookups that read them, never to the building
            // query. An execution-dependent gap (an archive entry that could not be
            // read, an inspection that stopped) may not repeat, so the fill must
            // not be retained: recording it here makes the retained cell refuse
            // the fill, and the next request rebuilds the index (#8201).
            for gap in value
                .production_diagnostics
                .iter()
                .filter(|gap| gap.is_recorded())
            {
                let reason = super::producer_codes::classify(gap);
                if reason.is_execution_dependent() {
                    analyzer.record_query_incomplete(reason);
                }
            }
            value
        },
    )
}

pub(crate) fn java_inventory_providers(
    analyzer: &dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
    models: &brokk_bifrost_analysis::analyzer::semantic_model::ResolvedActiveSemanticModels,
) -> Vec<String> {
    // Binding publishes request-owned projections before slot validity replay.
    gate_inventory_providers(analyzer, models, Vec::new());
    let providers = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
        crate::analyzer::java::JavaAnalyzer,
    >(analyzer)
    .map(|java| {
        java.external_declaration_index()
            .inventory_providers
            .clone()
    })
    .unwrap_or_default();
    gate_inventory_providers(analyzer, models, providers)
}

pub(crate) fn kotlin_inventory_providers(
    analyzer: &dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
    models: &brokk_bifrost_analysis::analyzer::semantic_model::ResolvedActiveSemanticModels,
) -> Vec<String> {
    // Binding publishes request-owned projections before slot validity replay.
    gate_inventory_providers(analyzer, models, Vec::new());
    let providers = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
        crate::analyzer::kotlin::KotlinAnalyzer,
    >(analyzer)
    .map(|kotlin| {
        kotlin
            .external_declaration_index()
            .inventory_providers
            .clone()
    })
    .unwrap_or_default();
    gate_inventory_providers(analyzer, models, providers)
}

pub(crate) fn scala_inventory_providers(
    analyzer: &dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
    models: &brokk_bifrost_analysis::analyzer::semantic_model::ResolvedActiveSemanticModels,
) -> Vec<String> {
    // Binding publishes request-owned projections before slot validity replay.
    gate_inventory_providers(analyzer, models, Vec::new());
    let providers = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
        crate::analyzer::scala::ScalaAnalyzer,
    >(analyzer)
    .map(|scala| {
        scala
            .external_declaration_index()
            .inventory_providers
            .clone()
    })
    .unwrap_or_default();
    gate_inventory_providers(analyzer, models, providers)
}

// Certified rows are a pure function of provider_id (the publication digest
// rule). Retaining derived data is sound because every use re-gates its ids.
/// Gates against the operation's model authority, never the analyzer's own
/// snapshot: one request reads one model owner (#14384).
fn gate_inventory_providers(
    analyzer: &dyn brokk_bifrost_analysis::analyzer::IAnalyzer,
    models: &brokk_bifrost_analysis::analyzer::semantic_model::ResolvedActiveSemanticModels,
    mut providers: Vec<String>,
) -> Vec<String> {
    if let Some(open) = models.gate_inventory_providers(&mut providers) {
        // Bind failure opens this use only. Discovery data in the retained
        // index remains available to a later request with a successful bind.
        analyzer.refuse_read_reuse();
        analyzer.record_query_incomplete(if open.is_cancellation() {
            brokk_bifrost_analysis::analyzer::QueryReadIncomplete::Cancelled
        } else {
            brokk_bifrost_analysis::analyzer::QueryReadIncomplete::SemanticEvidenceUnavailable(
                format!("semantic-model lookup is open: {}", open.reason).into(),
            )
        });
    }
    providers
}

/// Whether the retained external index resolves a name from `access_package`.
pub(crate) fn jvm_external_qualified_name_exists(
    index: &JvmExternalDeclarationIndex,
    fqn: &str,
    access_package: &str,
) -> bool {
    index.resolve_qualified_name(fqn, access_package).is_some()
}

/// The member surface one indexed artifact type carries (#1900).
///
/// A surface exists only for an owner whose own archive entry passed the byte
/// budget and parsed, which is what makes the absence of a surface mean "not
/// read" rather than "declares nothing". This is the artifact half of the same
/// distinction the pack half draws between a pack that ships an empty `members`
/// array and no activated pack at all: in both halves only a positive
/// declaration is ever added, and a lookup that finds none leaves the caller's
/// status exactly where it was.
#[derive(Debug, Clone, Default)]
struct JvmIndexedOwnerSurface {
    /// One entry per written member name. Overloads are one name and not
    /// ambiguity -- `sort(List)` and `sort(List, Comparator)` are two
    /// declarations a reference spells identically -- so the first declaration
    /// read wins, which is the rule the pack half's `members_of` search already
    /// applies.
    members: HashMap<String, JvmExternalMember>,
    /// The fully-qualified supertypes the owner's own artifact entry named, so
    /// an inherited member is answered where it is declared. This is the
    /// artifact half of the pack half's `SemanticModelOverlay::owner_surface`
    /// closure.
    supertypes: Vec<String>,
    /// The owner's direct supertype edges with their type arguments: the same
    /// inventory edges the pack half walks for this class file, including the
    /// erased roots a parsed hierarchy leaves out. An edge from an unreadable
    /// signature holds only the erased name.
    hierarchy: Vec<HierarchyFact>,
    /// The ordered type parameters `hierarchy` is written against. `None` when
    /// two reads of this owner declared different lists, so no argument
    /// position can be trusted.
    type_parameters: Option<Vec<String>>,
    hierarchy_complete: bool,
}

/// What one Java artifact's declaration-fact production yielded, indexed the
/// way the archive walk consumes it (#1900).
///
/// The producer emits a flat list of member facts that point at their owner by
/// declaration id; the archive walk asks for one owner at a time, by
/// fully-qualified name, as it finishes reading that owner's entry. This does
/// the join once.
struct JavaArtifactFacts {
    types: HashMap<String, TypeFact>,
    members_by_owner: HashMap<String, Vec<MemberFact>>,
}

impl JavaArtifactFacts {
    fn new(types: HashMap<String, TypeFact>, members: Vec<MemberFact>) -> Self {
        let name_by_id = types
            .values()
            .map(|fact| (fact.id.clone(), fact.name.clone()))
            .collect::<HashMap<_, _>>();
        let mut members_by_owner: HashMap<String, Vec<MemberFact>> = HashMap::default();
        for member in members {
            // A member whose owner the production never emitted has no name to
            // hang on, so nothing can spell it.
            let Some(owner) = name_by_id.get(&member.owner) else {
                continue;
            };
            members_by_owner
                .entry(owner.clone())
                .or_default()
                .push(member);
        }
        Self {
            types,
            members_by_owner,
        }
    }

    /// The member surface for one owner whose artifact entry was just read to
    /// the end, charged against this artifact's member budget.
    ///
    /// Taking rather than borrowing keeps one owner's members from being
    /// charged twice when the same class appears under two entries.
    fn take_owner_surface(
        &mut self,
        owner_fqn: &str,
        owner_package: &str,
        budget: &mut MemberBudget,
    ) -> JvmIndexedOwnerSurface {
        // The complete inventory when the artifact has one; otherwise the
        // declared edges a source jar records, which member lookup still
        // walks while the hierarchy stays incomplete.
        let supertypes = self
            .types
            .get(owner_fqn)
            .map(|fact| match &fact.jvm_inventory {
                Some(inventory) => hierarchy_type_names(&inventory.supertypes),
                None => hierarchy_type_names(&fact.hierarchy),
            })
            .unwrap_or_default();
        let hierarchy = self
            .types
            .get(owner_fqn)
            .map(|fact| inventory_hierarchy(&fact.hierarchy, fact.jvm_inventory.as_ref()))
            .unwrap_or_default();
        let type_parameters = self
            .types
            .get(owner_fqn)
            .map(|fact| fact.type_parameters.clone());
        let hierarchy_complete = self
            .types
            .get(owner_fqn)
            .and_then(|fact| fact.jvm_inventory.as_ref())
            .is_some_and(|inventory| inventory.supertypes_complete);
        let mut members = HashMap::default();
        for fact in self.members_by_owner.remove(owner_fqn).unwrap_or_default() {
            if !budget.take() {
                break;
            }
            let is_static = fact.is_static;
            let is_constant = fact.member_kind == MemberKind::Constant;
            let shape = external_call_shape(
                fact.member_kind,
                semantic_visibility(fact.visibility),
                is_static,
                fact.signature.as_ref(),
                fact.is_abstract,
                fact.non_overridable,
            );
            let shapes_incomplete = callable_shape_is_incomplete(
                fact.member_kind,
                fact.signature.as_ref(),
                fact.callable_family_complete,
                shape.is_some(),
            );
            retain_external_member(
                &mut members,
                owner_fqn,
                owner_package,
                RetainedExternalMember {
                    name: fact.name,
                    visibility: semantic_visibility(fact.visibility),
                    returns: fact.signature.and_then(|signature| signature.returns),
                    is_static,
                    is_constant,
                    shape,
                    shapes_incomplete,
                },
            );
        }
        if budget.exhausted {
            mark_call_shapes_incomplete(&mut members);
        }
        JvmIndexedOwnerSurface {
            members,
            supertypes,
            hierarchy,
            type_parameters,
            hierarchy_complete,
        }
    }
}

/// The per-artifact member-count bound [`MAX_ARTIFACT_MEMBERS`] states,
/// carried across one artifact's whole archive walk.
///
/// Once it is spent the walk keeps indexing types and simply records no further
/// members, and `exhausted` makes the artifact report as not fully read, so a
/// member the bound dropped is unknown rather than absent.
struct MemberBudget {
    remaining: usize,
    exhausted: bool,
}

impl MemberBudget {
    fn new() -> Self {
        Self {
            remaining: MAX_ARTIFACT_MEMBERS,
            exhausted: false,
        }
    }

    fn take(&mut self) -> bool {
        match self.remaining.checked_sub(1) {
            Some(remaining) => {
                self.remaining = remaining;
                true
            }
            None => {
                self.exhausted = true;
                false
            }
        }
    }
}

/// The fully-qualified supertype names one indexed type's hierarchy facts name.
///
/// A hierarchy target the producer could not name -- an erased type variable,
/// an array -- is not a type a member surface can be read from, so it is
/// dropped rather than guessed at.
fn hierarchy_type_names(hierarchy: &[HierarchyFact]) -> Vec<String> {
    hierarchy
        .iter()
        .filter_map(hierarchy_type_name)
        .map(str::to_owned)
        .collect()
}

fn hierarchy_type_name(relation: &HierarchyFact) -> Option<&str> {
    match &relation.target {
        TypeRef::Named { name, .. } => (!name.is_empty()).then_some(name.as_str()),
        _ => None,
    }
}

/// The edges one owner keeps for type-argument projection: the inventory's
/// when the artifact has one, otherwise the declared edges a source jar
/// records. This is what the pack half reads for the same class file, so both
/// halves see one path.
fn inventory_hierarchy(
    hierarchy: &[HierarchyFact],
    inventory: Option<&brokk_bifrost_analysis::analyzer::semantic_model::JvmOwnerInventory>,
) -> Vec<HierarchyFact> {
    inventory.map_or_else(
        || hierarchy.to_vec(),
        |inventory| inventory.supertypes.clone(),
    )
}

/// What one walk over the read owner surfaces found.
struct OwnerSurfaceWalk<T> {
    /// What `select` answered, and the owners the walk crossed to the one that
    /// answered, both ends included.
    selected: Option<(T, Vec<String>)>,
    /// How far the walk can speak for the read surfaces. A supertype with no
    /// read surface does not lower it: it is listed in `unread`, and each
    /// caller decides what an unread owner means for its question.
    completion: OwnerWalkCompletion,
    /// The path to each named supertype with no read surface. Each ends at that
    /// owner, which proves nothing about what the owner itself extends.
    unread: Vec<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JvmExternalType {
    fqn: String,
    package_name: String,
    short_name: String,
    kind: JvmExternalTypeKind,
    visibility: JvmVisibility,
    /// `Some(true)` only when the producer read that this exact class admits no
    /// subclass (#10572). `Some(false)` and `None` both leave dispatch open.
    is_final: Option<bool>,
    source: JvmExternalDeclarationSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JvmVisibility {
    Public,
    Protected,
    PackagePrivate,
    Private,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JvmExternalDeclarationSource {
    SourceJar {
        artifact_path: PathBuf,
        source_path: String,
    },
    ClassFile {
        artifact_path: PathBuf,
        class_entry: String,
    },
    /// A declaration-facts record an activated semantic pack publishes
    /// (#1893). There is no artifact on disk to point at: the pack itself is
    /// the evidence, so the provenance recorded here is the pack that declared
    /// the type and the declaration identity inside it.
    SemanticPack {
        pack_id: String,
        declaration_id: String,
        /// The declaration came from a pack activated for the JDK itself, as
        /// opposed to a library pack. Only a JDK pack can speak for a `java.*`
        /// type (#10470).
        jdk: bool,
    },
}

#[derive(Debug, Clone)]
struct ResolvedJvmArtifact {
    artifact_path: PathBuf,
    source_artifact_path: Option<PathBuf>,
    coordinate: Option<JvmMavenCoordinate>,
    origin: JvmDependencyOrigin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JvmDependencyOrigin {
    ExplicitPath,
    MavenReport,
    GradleReport,
    MavenRepository,
    GradleCache,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct JvmDependencyPackAdapter;

fn replace_generic_callable_parameters(
    pack: &mut AuthoredSemanticModelPack,
    limits: &ArtifactProducerLimits,
    artifact_kind: &str,
) -> Result<(), String> {
    for shard in &mut pack.shards {
        let AuthoredPayload::DeclarationFacts { members, .. } = &mut shard.payload else {
            continue;
        };
        for member in members {
            if !matches!(
                member.member_kind,
                MemberKind::Method | MemberKind::Constructor
            ) {
                continue;
            }
            let Some(signature) = &mut member.signature else {
                continue;
            };
            let mut erased = crate::analyzer::jvm::java_artifact::erased_class_method_parameters(
                &member.locator,
                limits.max_signature_depth,
            )
            .ok_or_else(|| {
                format!(
                    "no erased {artifact_kind} signature for {}: {:?}",
                    member.id, member.locator
                )
            })?;
            if member.member_kind == MemberKind::Constructor {
                // A constructor descriptor can prepend implicit enclosing
                // instance parameters absent from its generic signature.
                // The declaration reader owns the source-visible arity.
                // Trailing captured-local parameters occur only on local
                // and anonymous classes, which are not exported API members,
                // so exported constructors have no trailing hidden parameters.
                assert!(
                    erased.len() >= signature.parameters.len(),
                    "constructor descriptor arity for {:?}",
                    member.locator
                );
                let implicit_prefix = erased.len() - signature.parameters.len();
                erased.drain(..implicit_prefix);
            }
            assert_eq!(
                signature.parameters.len(),
                erased.len(),
                "generic and erased callable arities agree for {:?}",
                member.locator
            );
            for (parameter, erased) in signature.parameters.iter_mut().zip(erased) {
                parameter.r#type = erased;
            }
        }
    }
    Ok(())
}

impl JvmDependencyPackAdapter {
    /// Produce complete declarations from one Java class JAR for offline
    /// generators. This uses the same producer and limits as dependency packs.
    pub fn read_jar_declarations(path: &Path) -> Result<ArtifactProduction, String> {
        let limits = DependencyPackLimits::default();
        let mut production = JavaJarPackProducer.produce_exact_artifact(
            &local_jvm_artifact_production_request(
                path,
                ExternalArtifactKind::JavaClassJar,
                "bifrost.external.java",
            ),
            &limits.producer,
        );
        if let Some(pack) = &mut production.pack {
            replace_generic_callable_parameters(pack, &limits.producer, "JAR")?;
        }
        Ok(production)
    }

    /// Read one JDK's exported JMOD declarations for offline pack producers.
    /// Uses the same bounded readers and diagnostics as runtime acquisition.
    pub fn read_jdk_jmod_declarations(home: &Path) -> Result<ArtifactProduction, String> {
        let mut probes = Vec::new();
        let release = read_jdk_release(home, &mut probes)?;
        if release.version.components.first() != Some(&21) {
            return Err(format!(
                "CodeQL JDK 21 expansion requires JDK 21, got {}",
                release.version.raw
            ));
        }
        let jmods = discover_jdk_jmods(home, &mut probes)?
            .ok_or_else(|| format!("no jmods in {}", home.display()))?;
        let paths = jmods
            .into_iter()
            .map(|jmod| jmod.relative_path)
            .collect::<Vec<_>>();
        let limits = DependencyPackLimits::default();
        let artifact =
            brokk_bifrost_semantic::analyzer::semantic_model::producer::read_exact_source_set_seekable_while(
                home,
                &paths,
                limits.max_source_files_per_artifact,
                limits.max_source_path_depth,
                limits.max_total_artifact_bytes,
                &limits.producer,
                || false,
            )
            .map_err(|error| format!("read JDK JMODs: {error:?}"))?;
        let dependency = resolved_jdk_dependency(release.version, None);
        let mut request = jvm_dependency_production_request(&dependency);
        request.path = home.to_owned();
        request.artifact_kind = ExternalArtifactKind::JdkJmodSet;
        let mut production = JdkJmodSetPackProducer.produce_loaded_artifact(
            &request,
            &limits.producer,
            None,
            &artifact,
        );
        if let Some(pack) = &mut production.pack {
            replace_generic_callable_parameters(pack, &limits.producer, "JMOD")?;
        }
        Ok(production)
    }

    /// Build the exact JDK dependency when no local source archive is available.
    pub fn jdk_dependency(version: JdkVersion) -> ResolvedDependency {
        resolved_jdk_dependency(version, None)
    }

    /// Build the exact JDK source dependency used by the runtime resolver.
    /// Release tooling uses this constructor so its production key includes
    /// the same evidence and provenance as a locally discovered JDK.
    pub fn jdk_source_dependency(
        version: JdkVersion,
        source_archive: PathBuf,
    ) -> ResolvedDependency {
        resolved_jdk_dependency(version, Some(source_archive))
    }
}

/// Dependency discovery for activation: the discovered JDK's artifacts are
/// pinned to content digests, because the JDK production key and the catalog
/// expectation bind them (#9559).
pub fn resolve_jvm_semantic_pack_dependencies(
    config: &JvmAnalyzerConfig,
    project: &dyn Project,
    digests: &ContentDigestCache,
    verifications: &brokk_bifrost_core::analyzer::external_selection::ToolchainVerifications,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> DependencyDiscoveryOutcome {
    let mut outcome =
        resolve_jvm_semantic_pack_dependencies_unpinned(config, project, limits, cancellation);
    if outcome.cancelled {
        return outcome;
    }
    let (selected, observation, observed_at) = match verify_jdk_record(
        config,
        project,
        digests,
        verifications,
        limits,
        cancellation,
    ) {
        Ok(verification) => (
            verification.selected,
            verification.observation,
            verification.observed_at,
        ),
        Err(()) => {
            return cancelled_discovery("JVM dependency discovery was cancelled while pinning");
        }
    };
    for dependency in &mut outcome.dependencies {
        if let Some(verified) = selected
            .dependencies
            .iter()
            .find(|verified| verified.id == dependency.id)
        {
            *dependency = verified.clone();
        }
    }
    // Every read above is keyed or has refused (the sticky refusals include
    // an OfflineBuildTools executor run). A listing that could not be
    // generated leaves the outcome incomplete, and a JDK observation that
    // changed while it was pinned cannot certify its answer.
    if outcome.incomplete_reason.is_none()
        && let Some(observation) = observation
    {
        report_external_discovery_read(ExternalDiscoveryRead::Observed {
            identity: StableDigest::from_array(
                selected.answer_digest(selected.inputs.complete, false),
            ),
            verifier: ExternalVerifier(std::sync::Arc::new(JdkObservationVerifier {
                config: config.clone(),
                project_root: project.root().to_path_buf(),
                record: VerifiedJdkRecord {
                    selected,
                    observation,
                    observed_at,
                },
            })),
        });
        declare_external_discovery_reads_complete();
    }
    outcome
}

/// Re-observes the JDK discovery as `verify_jdk_record` pinned it, with the
/// racy-identity rule of the verified record (#13537).
struct JdkObservationVerifier {
    config: JvmAnalyzerConfig,
    project_root: PathBuf,
    record: VerifiedJdkRecord,
}

impl ExternalObservation for JdkObservationVerifier {
    fn still_matches(&self) -> bool {
        self.record
            .matches(&observe_jdk(&self.config, &self.project_root))
    }
}

/// Dependency discovery for readers of the dependency list and diagnostics
/// only: the external declaration index and the dependencies question read no
/// JDK content pin (JDK artifacts never become index artifacts, and the JDK is
/// not part of the dependencies answer), so the JDK jars and JMODs are not
/// hashed.
fn resolve_jvm_semantic_pack_dependencies_unpinned(
    config: &JvmAnalyzerConfig,
    project: &dyn Project,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> DependencyDiscoveryOutcome {
    resolve_jvm_semantic_pack_dependencies_traced(
        config,
        project,
        &manifest_scope(project, config),
        limits,
        cancellation,
        None,
    )
}

fn resolve_jvm_semantic_pack_dependencies_traced(
    config: &JvmAnalyzerConfig,
    project: &dyn Project,
    inputs: &dyn DiscoveryInputs,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
    mut trace: Option<&mut DependencyDiscoveryTrace>,
) -> DependencyDiscoveryOutcome {
    let artifacts = match resolve_project_artifacts(
        config,
        project,
        inputs,
        limits,
        cancellation,
        trace.as_deref_mut(),
    ) {
        Ok(artifacts) => artifacts,
        Err(cancelled) => return cancelled,
    };
    let missing_membership = artifacts.missing_membership;
    let mut outcome = assemble_dependencies(
        artifacts.declared,
        &artifacts.declarations,
        limits,
        cancellation,
        trace,
        || discover_configured_jdk(config, project.root()),
    );
    if missing_membership {
        append_generation_listing_unavailable(&mut outcome);
    }
    outcome
}

fn append_generation_listing_unavailable(outcome: &mut DependencyDiscoveryOutcome) {
    let unavailable =
        DependencyDiscoveryOutcome::generation_listing_unavailable(&CancellationToken::new());
    outcome.complete = false;
    outcome.incomplete_reason = unavailable.incomplete_reason;
    outcome.diagnostics.extend(unavailable.diagnostics);
}

/// What project discovery resolved before any jar is classified.
struct ProjectArtifacts {
    declared: DeclaredArtifacts,
    declarations: brokk_bifrost_core::hash::HashMap<
        JvmMavenCoordinate,
        super::dependency_discovery::JvmDependencyDeclaration,
    >,
    /// The generation listing was unavailable, so the outcome is incomplete.
    missing_membership: bool,
}

/// Project discovery up to the resolved artifact files: the process
/// environment, the build files, and the Maven repository and Gradle cache
/// lookups. Nothing here reads a jar.
fn resolve_project_artifacts(
    config: &JvmAnalyzerConfig,
    project: &dyn Project,
    inputs: &dyn DiscoveryInputs,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
    mut trace: Option<&mut DependencyDiscoveryTrace>,
) -> Result<ProjectArtifacts, DependencyDiscoveryOutcome> {
    for name in [
        "JAVA_HOME",
        "HOME",
        "USERPROFILE",
        "GRADLE_USER_HOME",
        "PATH",
        "MAVEN_OPTS",
        "GRADLE_OPTS",
        "JAVA_TOOL_OPTIONS",
    ] {
        report_external_discovery_read(ExternalDiscoveryRead::Environment {
            name: name.into(),
            value: std::env::var_os(name),
            working_directory: None,
        });
    }
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return Err(cancelled_discovery(
            "JVM dependency discovery was cancelled",
        ));
    }
    let missing_membership = inputs.files().err().is_some_and(|error| {
        error.get_ref().is_some_and(|error| error.is::<brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::GenerationListingUnavailable>())
    });
    let mut dependencies = config.external_dependencies.clone();
    // What the build files *declare*, kept beside the coordinates themselves:
    // scope and declaring target are properties of the declaration, and the
    // merged coordinate list has already lost which file each came from.
    let mut declarations = brokk_bifrost_core::hash::HashMap::default();
    if config.dependency_discovery.mode != JvmDependencyDiscoveryMode::Disabled {
        let discovered = discover_metadata(inputs);
        if let Some(trace) = trace.as_deref_mut() {
            trace.partial_manifests.extend(
                discovered
                    .partial_manifests
                    .iter()
                    .map(|file| file.rel_path().to_path_buf()),
            );
        }
        declarations.clone_from(&discovered.declarations);
        discovered.merge_into(&mut dependencies);
    }
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return Err(cancelled_discovery(
            "JVM dependency discovery was cancelled",
        ));
    }
    if !missing_membership
        && config.dependency_discovery.mode == JvmDependencyDiscoveryMode::OfflineBuildTools
    {
        discover_build_tools(inputs, &config.dependency_discovery).merge_into(&mut dependencies);
    }
    let declared =
        resolve_artifacts_declared(&dependencies, project.root(), limits, cancellation, trace)?;
    Ok(ProjectArtifacts {
        declared,
        declarations,
        missing_membership,
    })
}

/// Resolve the dependencies the manifests declared in this environment. This is
/// the environment half of discovery: it reads no manifest, only the Maven
/// repository, the Gradle cache, the process environment and the JDK, so a
/// recorded coordinate set can be resolved again without the tree that declared
/// it (#11607).
fn resolve_declared_dependencies(
    config: &JvmAnalyzerConfig,
    project_root: &Path,
    dependencies: JvmExternalDependencies,
    declarations: &brokk_bifrost_core::hash::HashMap<
        JvmMavenCoordinate,
        super::dependency_discovery::JvmDependencyDeclaration,
    >,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
    mut trace: Option<&mut DependencyDiscoveryTrace>,
) -> DependencyDiscoveryOutcome {
    let declared = match resolve_artifacts_declared(
        &dependencies,
        project_root,
        limits,
        cancellation,
        trace.as_deref_mut(),
    ) {
        Ok(declared) => declared,
        Err(cancelled) => return cancelled,
    };
    assemble_dependencies(declared, declarations, limits, cancellation, trace, || {
        discover_configured_jdk(config, project_root)
    })
}

/// The artifact files declared coordinates and explicit paths resolve to, with
/// the resolution diagnostics for the coordinates that did not resolve. No jar
/// has been read yet, so this is the part of discovery a stat-keyed lookup can
/// precede.
struct DeclaredArtifacts {
    /// Resolved artifacts after the dependency limit.
    artifacts: Vec<ResolvedJvmArtifact>,
    /// Unresolved and unavailable coordinates, in coordinate order.
    diagnostics: Vec<DependencyPackDiagnostic>,
    suppressed_diagnostics: SuppressedDiagnostics,
    dependency_limit_hit: bool,
    metadata_inputs_considered: usize,
}

fn resolve_artifacts_declared(
    dependencies: &JvmExternalDependencies,
    project_root: &Path,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
    mut trace: Option<&mut DependencyDiscoveryTrace>,
) -> Result<DeclaredArtifacts, DependencyDiscoveryOutcome> {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return Err(cancelled_discovery(
            "JVM dependency discovery was cancelled",
        ));
    }
    let metadata_inputs_considered = dependencies
        .artifact_paths
        .len()
        .saturating_add(dependencies.coordinates.len());
    if let Some(trace) = trace.as_deref_mut() {
        trace
            .coordinates
            .extend(dependencies.coordinates.iter().cloned());
        for artifact in &dependencies.artifact_paths {
            trace
                .explicit_paths
                .push(resolve_path(project_root, &artifact.artifact_path));
            if let Some(source) = &artifact.source_artifact_path {
                trace
                    .explicit_paths
                    .push(resolve_path(project_root, source));
            }
        }
    }
    let (resolved, unavailable_coordinates) = resolve_configured_artifacts_traced(
        dependencies,
        project_root,
        trace.map(|trace| &mut trace.resolution),
    );
    let mut resolved_coordinates = brokk_bifrost_core::hash::HashSet::default();
    for artifact in &resolved {
        if let Some(coordinate) = &artifact.coordinate {
            resolved_coordinates.insert(coordinate.clone());
        }
    }
    let mut diagnostics = Vec::new();
    for coordinate in &dependencies.coordinates {
        if !resolved_coordinates.contains(coordinate) {
            diagnostics.push(DependencyPackDiagnostic {
                severity: DependencyPackDiagnosticSeverity::Error,
                code: if unavailable_coordinates.contains(&jvm_coordinate_id(coordinate)) {
                    super::producer_codes::JVM_DEPENDENCY_UNAVAILABLE
                } else {
                    super::producer_codes::JVM_DEPENDENCY_UNRESOLVED
                }
                .code
                .to_owned(),
                dependency_id: Some(jvm_coordinate_id(coordinate)),
                location: None,
                message: if unavailable_coordinates.contains(&jvm_coordinate_id(coordinate)) {
                    format!(
                        "local artifact acquisition failed for {}",
                        jvm_coordinate_id(coordinate)
                    )
                } else {
                    format!(
                        "exact local artifact was not found for {}",
                        jvm_coordinate_id(coordinate)
                    )
                },
            });
        }
    }
    // Dependencies dropped by the dependency limit are not diagnostics.
    let suppressed_diagnostics = SuppressedDiagnostics {
        warnings: resolved.len().saturating_sub(limits.max_dependencies),
        errors: 0,
    };
    let dependency_limit_hit = suppressed_diagnostics.total() > 0;
    let mut artifacts = resolved;
    artifacts.truncate(limits.max_dependencies);
    Ok(DeclaredArtifacts {
        artifacts,
        diagnostics,
        suppressed_diagnostics,
        dependency_limit_hit,
        metadata_inputs_considered,
    })
}

/// Classify the declared artifacts, build their dependencies, add the JDK
/// `jdk` discovers, and bound the diagnostics.
fn assemble_dependencies(
    declared: DeclaredArtifacts,
    declarations: &brokk_bifrost_core::hash::HashMap<
        JvmMavenCoordinate,
        super::dependency_discovery::JvmDependencyDeclaration,
    >,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
    mut trace: Option<&mut DependencyDiscoveryTrace>,
    jdk: impl FnOnce() -> JdkDiscovery,
) -> DependencyDiscoveryOutcome {
    let DeclaredArtifacts {
        artifacts: resolved_artifacts,
        mut diagnostics,
        mut suppressed_diagnostics,
        dependency_limit_hit,
        mut metadata_inputs_considered,
    } = declared;
    let mut resolved = Vec::with_capacity(resolved_artifacts.len());
    for artifact in resolved_artifacts {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return cancelled_discovery("JVM dependency discovery was cancelled");
        }
        let declaration = artifact
            .coordinate
            .as_ref()
            .and_then(|coordinate| declarations.get(coordinate).cloned());
        let mut dependency = resolved_semantic_pack_dependency_while(artifact, cancellation);
        // A jar resolved out of a local repository proves the artifact; only a
        // build file proves the scope, so a dependency with no declaration
        // keeps `Unknown` rather than inheriting a neighbour's scope.
        if let Some(declaration) = declaration {
            dependency.scope = declaration.scope;
            dependency.declared_by = declaration.declared_by;
        }
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return cancelled_discovery("JVM dependency discovery was cancelled");
        }
        for entry in &dependency.provenance {
            let code = match entry.key.as_str() {
                "kotlin.classification.incomplete" => {
                    super::producer_codes::KOTLIN_CLASSIFICATION_INCOMPLETE.code
                }
                "kotlin.classification.capped" => {
                    super::producer_codes::KOTLIN_CLASSIFICATION_CAPPED.code
                }
                "kotlin.classification.malformed" => {
                    super::producer_codes::KOTLIN_CLASSIFICATION_MALFORMED.code
                }
                _ => continue,
            };
            diagnostics.push(DependencyPackDiagnostic {
                severity: DependencyPackDiagnosticSeverity::Warning,
                code: code.to_owned(),
                dependency_id: Some(dependency.id.clone()),
                location: None,
                message: format!("Kotlin metadata inspection stopped: {}; the artifact requires a compatible prebuilt Kotlin pack", entry.value),
            });
        }
        resolved.push(dependency);
    }
    if let Some(trace) = trace.as_deref_mut() {
        // The dependencies question is answered before the JDK joins the
        // outcome: JDK configuration is not in its digest, and the JDK has
        // its own question.
        trace.dependencies_discovered = !dependency_limit_hit
            && !diagnostics.iter().any(|diagnostic| {
                diagnostic.severity == DependencyPackDiagnosticSeverity::Error
                    && (diagnostic.code != super::producer_codes::JVM_DEPENDENCY_UNRESOLVED.code
                        || diagnostic.dependency_id.is_none())
            });
        trace.unresolved_coordinates = diagnostics
            .iter()
            .filter(|diagnostic| {
                diagnostic.code == super::producer_codes::JVM_DEPENDENCY_UNRESOLVED.code
            })
            .filter_map(|diagnostic| diagnostic.dependency_id.clone())
            .collect();
        trace.unresolved_coordinates.sort();
        trace.unresolved_coordinates.dedup();
    }
    let dependency_diagnostic_count = diagnostics.len();
    let jdk_discovery = jdk();
    metadata_inputs_considered =
        metadata_inputs_considered.saturating_add(jdk_discovery.inputs_considered);
    resolved.extend(jdk_discovery.dependencies);
    diagnostics.extend(jdk_discovery.diagnostics);
    if dependency_limit_hit {
        diagnostics.push(DependencyPackDiagnostic {
            severity: DependencyPackDiagnosticSeverity::Error,
            code: super::producer_codes::LIMIT_DEPENDENCIES.code.to_owned(),
            dependency_id: None,
            location: None,
            message: format!(
                "JVM dependency discovery exceeded the configured limit {}",
                limits.max_dependencies
            ),
        });
    }
    if resolved.len() > limits.max_dependencies {
        suppressed_diagnostics.warnings = suppressed_diagnostics
            .warnings
            .saturating_add(resolved.len() - limits.max_dependencies);
        resolved.truncate(limits.max_dependencies);
        if !dependency_limit_hit {
            diagnostics.push(DependencyPackDiagnostic {
                severity: DependencyPackDiagnosticSeverity::Error,
                code: super::producer_codes::LIMIT_DEPENDENCIES.code.to_owned(),
                dependency_id: None,
                location: None,
                message: format!(
                    "JVM dependency discovery exceeded the configured limit {}",
                    limits.max_dependencies
                ),
            });
        }
    }
    // JVM discovery mixes warnings (incomplete Kotlin classification) with the
    // errors that decide the outcome, so bound it through the shared collector
    // instead of truncating: an error must keep a slot.
    let mut bounded = BoundedDependencyDiagnostics::new(limits);
    let mut retained_dependencies = 0;
    for (position, diagnostic) in diagnostics.into_iter().enumerate() {
        if position >= dependency_diagnostic_count
            && diagnostic.severity == DependencyPackDiagnosticSeverity::Error
            && bounded.diagnostics.len() == limits.max_diagnostics
            && bounded
                .diagnostics
                .iter()
                .rposition(|kept| kept.severity == DependencyPackDiagnosticSeverity::Warning)
                .is_some_and(|evicted| evicted < retained_dependencies)
        {
            // A JDK error can evict a dependency-origin warning from the
            // shared bound. JDK-origin suppression alone is not a dependency gap.
            if let Some(trace) = trace.as_deref_mut() {
                trace.dependencies_discovered = false;
            }
            retained_dependencies -= 1;
        }
        bounded.push(diagnostic);
        if position + 1 == dependency_diagnostic_count {
            if let Some(trace) = trace.as_deref_mut() {
                trace.dependencies_discovered &= bounded.suppressed.total() == 0;
            }
            retained_dependencies = bounded.diagnostics.len();
        }
    }
    let (diagnostics, bounded_suppressed) = bounded.finish();
    suppressed_diagnostics += bounded_suppressed;
    DependencyDiscoveryOutcome {
        incomplete_reason: None,
        profile: DependencyDiscoveryProfile {
            metadata_inputs_considered,
            dependencies_resolved: resolved.len(),
            informational_evidence: Vec::new(),
        },
        dependencies: resolved,
        complete: !diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == DependencyPackDiagnosticSeverity::Error)
            && suppressed_diagnostics.total() == 0,
        diagnostics,
        suppressed_diagnostics,
        cancelled: false,
    }
}

fn cancelled_discovery(message: &str) -> DependencyDiscoveryOutcome {
    DependencyDiscoveryOutcome::cancelled_with_message(message)
}

fn jvm_coordinate_id(coordinate: &JvmMavenCoordinate) -> String {
    format!(
        "{}:{}:{}",
        coordinate.group_id, coordinate.artifact_id, coordinate.version
    )
}

/// A bounded store-owned verification, independent of digest-cache retention.
pub(super) struct VerifiedJdkRecord {
    pub(super) selected: std::sync::Arc<SelectedJdk>,
    pub(super) observation: JdkObservation,
    pub(super) observed_at: std::time::SystemTime,
}

impl VerifiedJdkRecord {
    pub(super) fn matches(&self, current: &Option<JdkObservation>) -> bool {
        current.as_ref() == Some(&self.observation)
            && self.observation.members.iter().all(|(_, _, identity, _)| {
                !identity.racy_at(
                    self.observed_at,
                    brokk_bifrost_core::content_digest::FILE_TIMESTAMP_GRANULARITY,
                )
            })
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct JdkObservation {
    transcript: [u8; 32],
    members: Vec<(
        PathBuf,
        PathBuf,
        brokk_bifrost_core::content_digest::FileIdentity,
        u64,
    )>,
}

pub(super) fn observe_jdk(
    config: &JvmAnalyzerConfig,
    project_root: &Path,
) -> Option<JdkObservation> {
    let discovery = discover_configured_jdk(config, project_root);
    let selected = SelectedJdk {
        inputs: discovery.inputs,
        dependencies: discovery.dependencies,
    };
    let mut members = Vec::new();
    for dependency in &selected.dependencies {
        for artifact in &dependency.artifacts {
            let root = fs::canonicalize(artifact.path()).ok()?;
            let paths = match &artifact.input {
                ResolvedDependencyArtifactInput::SourceSet { relative_paths, .. } => {
                    relative_paths.clone()
                }
                ResolvedDependencyArtifactInput::File(_) => vec![PathBuf::new()],
            };
            for relative in paths {
                let path = if relative.as_os_str().is_empty() {
                    root.clone()
                } else {
                    root.join(&relative)
                };
                let identity =
                    brokk_bifrost_core::content_digest::metadata_change_identity(&path).ok()??;
                let size = fs::metadata(&path).ok()?.len();
                members.push((root.clone(), relative, identity, size));
            }
        }
    }
    Some(JdkObservation {
        transcript: selected.answer_digest(selected.inputs.complete, false),
        members,
    })
}

/// One pinned JDK selection and the metadata observation that held around the
/// pin, when it did.
pub(super) struct JdkVerification {
    pub(super) selected: std::sync::Arc<SelectedJdk>,
    /// The observation taken before and after pinning, when both agree. None
    /// means the files changed while they were pinned.
    pub(super) observation: Option<JdkObservation>,
    /// Taken before the first observation, for the racy-identity rule.
    pub(super) observed_at: std::time::SystemTime,
}

#[cfg(test)]
thread_local! {
    /// Fails the next JDK member read once, as a transient I/O error would. The
    /// error path it takes is the production one: an unreadable probe.
    pub(super) static FAIL_NEXT_JDK_PIN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn jdk_member_metadata(member: &Path) -> std::io::Result<fs::Metadata> {
    #[cfg(test)]
    if FAIL_NEXT_JDK_PIN.replace(false) {
        return Err(std::io::Error::other("injected transient read failure"));
    }
    fs::metadata(member)
}

/// Activation and refresh re-observe and re-pin through the store's shared
/// ContentDigestCache, then replace the record with a stable observation.
/// Matching non-racy metadata identities reuse a digest on every filesystem;
/// changed or racy identities stream the bytes. Observation and digest reuse share FileIdentity.
///
/// Only a complete selection is recorded. An unreadable member may be a
/// transient failure, and a recorded selection is accepted again on matching
/// metadata alone, so recording an incomplete one would keep the failure for
/// the life of the workspace. An incomplete selection is returned to the caller
/// and verified again by the next request.
pub(super) fn verify_jdk_record(
    config: &JvmAnalyzerConfig,
    project: &dyn Project,
    digests: &ContentDigestCache,
    verifications: &brokk_bifrost_core::analyzer::external_selection::ToolchainVerifications,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> Result<JdkVerification, ()> {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return Err(());
    }
    let observed_at = std::time::SystemTime::now();
    let before = observe_jdk(config, project.root());
    let mut discovery = discover_configured_jdk(config, project.root());
    if pin_jdk_discovery(&mut discovery, digests, limits, cancellation).is_break() {
        return Err(());
    }
    let selected = std::sync::Arc::new(SelectedJdk {
        inputs: discovery.inputs,
        dependencies: discovery.dependencies,
    });
    let after = observe_jdk(config, project.root());
    let observation = before.filter(|before| Some(before) == after.as_ref());
    if selected.inputs.complete
        && let Some(observation) = &observation
    {
        let key =
            brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion::for_jvm(
                config,
            )
            .remove(1)
            .digest;
        verifications.replace(
            key,
            std::sync::Arc::new(VerifiedJdkRecord {
                selected: selected.clone(),
                observation: observation.clone(),
                observed_at,
            }),
        );
    }
    Ok(JdkVerification {
        selected,
        observation,
        observed_at,
    })
}

/// The JDK question's answer: what discovery consulted and what it selected.
/// Each selected dependency keeps its version and its artifacts' content pins
/// (the framed digest of the JMOD set, the digest of `src.zip`), so two JDKs
/// at the same paths with different contents give different answers, and a
/// later transcript can be checked against a fresh discovery. An artifact
/// that could not be pinned keeps its metadata source identity instead.
#[derive(Debug)]
pub(super) struct SelectedJdk {
    pub(super) inputs: JdkInputsConsumed,
    #[allow(dead_code)] // The query-owned transcript is consumed by the later verifier.
    pub(super) dependencies: Vec<ResolvedDependency>,
}

#[derive(Debug, Default)]
struct JdkDiscovery {
    dependencies: Vec<ResolvedDependency>,
    diagnostics: Vec<DependencyPackDiagnostic>,
    inputs_considered: usize,
    inputs: JdkInputsConsumed,
}

/// JDK discovery as the configuration asks for it, reading `JAVA_HOME` and
/// `PATH` only when discovery is told to (`PATH` matters only while
/// `JAVA_HOME` is unset). The artifacts are not pinned to content
/// digests; [`pin_jdk_discovery`] does that for the paths that consume the
/// pins.
fn discover_configured_jdk(config: &JvmAnalyzerConfig, project_root: &Path) -> JdkDiscovery {
    let read_environment = config.standard_library_discovery.discover_java_home;
    discover_jdk_semantic_pack_dependencies(
        config,
        project_root,
        read_environment
            .then(|| std::env::var_os("JAVA_HOME"))
            .flatten(),
        read_environment.then(|| std::env::var_os("PATH")).flatten(),
    )
}

/// Whether a `java` candidate on `PATH` would run for this process: a
/// regular file it may execute, so a data file, or a launcher only another
/// user may run, earlier on `PATH` does not shadow the one a shell would pick.
fn is_runnable_java(path: &Path, metadata: &fs::Metadata) -> bool {
    metadata.is_file() && brokk_bifrost_core::path_utils::may_execute(path)
}

/// Why `java` on `PATH` supplied no JDK home candidate.
enum PathJavaMiss {
    /// An authoritative answer: `PATH` names no JDK. It is only the reason
    /// given when no other home supplies one.
    Rejected(String),
    /// The lookup cannot tell which `java` the process would run, so the
    /// selection may omit the JDK it names and is incomplete.
    Ambiguous(String),
}

/// The first runnable `java` (`java.exe` on Windows) in `PATH` order. Every
/// probe is recorded, so a changed `PATH` or a `java` that appears or vanishes
/// changes the recorded inputs.
///
/// A relative or empty entry names a directory relative to the process working
/// directory. That directory is not a recorded input and is not the user's
/// shell directory, so reaching such an entry before any `java` makes the
/// answer ambiguous: the lookup stops there rather than guess which `java` the
/// process would run.
fn find_java_on_path(
    path: &OsStr,
    probes: &mut Vec<ExternalPathProbe>,
) -> Result<PathBuf, PathJavaMiss> {
    if path.is_empty() {
        return Err(PathJavaMiss::Rejected("PATH is unset or empty".to_owned()));
    }
    let name = if cfg!(windows) { "java.exe" } else { "java" };
    for directory in std::env::split_paths(path) {
        if !directory.is_absolute() {
            return Err(PathJavaMiss::Ambiguous(format!(
                "PATH entry {directory:?} is relative or empty, so the `java` it selects depends on the working directory"
            )));
        }
        let candidate = directory.join(name);
        let metadata = fs::metadata(&candidate);
        record_external_probe(probes, &candidate, ExternalProbeOperation::File, &metadata);
        if metadata.is_ok_and(|metadata| is_runnable_java(&candidate, &metadata)) {
            return Ok(candidate);
        }
    }
    Err(PathJavaMiss::Rejected("no `java` found on PATH".to_owned()))
}

/// The JDK home `java` on `PATH` belongs to: its real file, with symlinks
/// followed, must sit in a `bin` directory, and the home is the directory
/// above. Returns the home candidate, or why there is none.
fn jdk_home_of_path_java(
    path: &OsStr,
    probes: &mut Vec<ExternalPathProbe>,
    found: &mut Option<PathBuf>,
) -> Result<PathBuf, PathJavaMiss> {
    let java = find_java_on_path(path, probes)?;
    *found = Some(java.clone());
    let real = fs::canonicalize(&java);
    record_external_probe(probes, &java, ExternalProbeOperation::Canonicalize, &real);
    // A failed canonicalize is recorded as a probe, which judges the inputs.
    let real = real.map_err(|error| {
        PathJavaMiss::Rejected(format!(
            "`java` on PATH ({}) could not be resolved: {error}",
            java.display()
        ))
    })?;
    let bin = real
        .parent()
        .filter(|bin| bin.file_name() == Some(OsStr::new("bin")));
    bin.and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            PathJavaMiss::Rejected(format!(
                "`java` on PATH resolves to {}, which is not in a `bin` directory of a JDK home",
                real.display()
            ))
        })
}

fn discover_jdk_semantic_pack_dependencies(
    config: &JvmAnalyzerConfig,
    project_root: &Path,
    java_home: Option<OsString>,
    path: Option<OsString>,
) -> JdkDiscovery {
    let consulted_java_home = java_home.clone();
    let mut probes = Vec::new();
    // `PATH` is read only while `JAVA_HOME` is unset. A `JAVA_HOME` that is set
    // and wrong is reported, never replaced by another JDK, and a set but
    // empty one is the long-standing opt-out from discovering a host JDK
    // (CI and the gates set it so JVM tests do not index the runner's JDK).
    let path_lookup = (config.standard_library_discovery.discover_java_home && java_home.is_none())
        .then(|| {
            let mut java_on_path = None;
            let home = jdk_home_of_path_java(
                path.as_deref().unwrap_or_default(),
                &mut probes,
                &mut java_on_path,
            );
            (path.clone(), java_on_path, home)
        });
    let mut candidates: Vec<(PathBuf, bool)> = config
        .standard_library_discovery
        .jdk_homes
        .iter()
        .map(|home| (resolve_path(project_root, home), true))
        .collect();
    candidates.extend(
        config
            .standard_library_discovery
            .source_toolchains
            .iter()
            .map(|binding| (resolve_path(project_root, binding.jdk_home()), true)),
    );
    if let Some(java_home) = java_home.filter(|value| !value.is_empty()) {
        candidates.push((resolve_path(project_root, Path::new(&java_home)), false));
    }
    // The home of `java` on `PATH` is a candidate nobody configured, so one
    // that fails validation is not an error of the user's: it is reported
    // only as the reason no JDK was found.
    let path_home = path_lookup
        .as_ref()
        .and_then(|(_, _, home)| home.as_ref().ok())
        .cloned();
    if let Some(home) = &path_home {
        candidates.push((home.clone(), false));
    }

    let discovery_requested =
        !candidates.is_empty() || config.standard_library_discovery.discover_java_home;
    let mut discovery = JdkDiscovery {
        inputs_considered: candidates.len(),
        inputs: JdkInputsConsumed {
            java_home: consulted_java_home,
            candidates: candidates.clone(),
            path: path_lookup.as_ref().and_then(|(path, _, _)| path.clone()),
            java_on_path: path_lookup.as_ref().and_then(|(_, java, _)| java.clone()),
            probes,
            complete: false,
        },
        ..JdkDiscovery::default()
    };
    let path_consulted = path_lookup.is_some();
    let mut path_rejection = None;
    match path_lookup.as_ref().map(|(_, _, home)| home) {
        Some(Err(PathJavaMiss::Rejected(reason))) => path_rejection = Some(reason.clone()),
        // Another home may still be selected, but the JDK this entry names
        // could be missing from the selection, so it is not complete.
        Some(Err(PathJavaMiss::Ambiguous(reason))) => {
            discovery.diagnostics.push(DependencyPackDiagnostic {
                severity: DependencyPackDiagnosticSeverity::Warning,
                code: super::producer_codes::JDK_HOME_INVALID.code.to_owned(),
                dependency_id: None,
                location: None,
                message: format!(
                    "`java` on PATH could not be resolved: {reason}. The JDK selection may omit the JDK it names; set JAVA_HOME to a JDK installation in the language-server process environment and restart Bifrost"
                ),
            });
        }
        Some(Ok(_)) | None => {}
    }
    let mut seen_homes = brokk_bifrost_core::hash::HashSet::default();
    let mut dependency_homes = Vec::new();
    let path_candidate_index = path_home.as_ref().map(|_| candidates.len() - 1);
    for (index, (candidate, configured)) in candidates.into_iter().enumerate() {
        let from_path = path_candidate_index == Some(index);
        let canonical = fs::canonicalize(&candidate);
        record_external_probe(
            &mut discovery.inputs.probes,
            &candidate,
            ExternalProbeOperation::Canonicalize,
            &canonical,
        );
        let home = canonical.unwrap_or(candidate);
        if !seen_homes.insert(home.clone()) {
            continue;
        }
        let release = match read_jdk_release(&home, &mut discovery.inputs.probes) {
            Ok(release) => release,
            Err(message) if from_path => {
                path_rejection = Some(format!(
                    "`java` on PATH resolves to {}, whose home {} is not a usable JDK: {message}",
                    discovery
                        .inputs
                        .java_on_path
                        .as_deref()
                        .unwrap_or(&home)
                        .display(),
                    home.display()
                ));
                continue;
            }
            Err(message) => {
                discovery.diagnostics.push(DependencyPackDiagnostic {
                    severity: if configured {
                        DependencyPackDiagnosticSeverity::Error
                    } else {
                        DependencyPackDiagnosticSeverity::Warning
                    },
                    code: super::producer_codes::JDK_HOME_INVALID.code.to_owned(),
                    dependency_id: None,
                    location: Some(home.to_string_lossy().into_owned()),
                    message,
                });
                continue;
            }
        };
        let version = release.version.clone();
        let source = [home.join("lib").join("src.zip"), home.join("src.zip")]
            .into_iter()
            .find(|path| {
                let metadata = fs::metadata(path);
                record_external_probe(
                    &mut discovery.inputs.probes,
                    path,
                    ExternalProbeOperation::File,
                    &metadata,
                );
                metadata.is_ok_and(|metadata| metadata.is_file())
            });
        let dependency = if !configured {
            match discover_jdk_jmods(&home, &mut discovery.inputs.probes) {
                Ok(Some(jmods)) => resolved_jdk_jmod_dependency(&release, home.clone(), jmods),
                Ok(None) => resolved_jdk_dependency(version.clone(), source),
                Err(message) => {
                    discovery.diagnostics.push(DependencyPackDiagnostic {
                        severity: DependencyPackDiagnosticSeverity::Warning,
                        code: super::producer_codes::JDK_JMODS_INVALID.code.to_owned(),
                        dependency_id: Some(format!("jdk:{version}")),
                        location: Some(home.to_string_lossy().into_owned()),
                        message,
                    });
                    resolved_jdk_dependency(version.clone(), source)
                }
            }
        } else if let Some(source) = source {
            let mut dependency = resolved_jdk_dependency(version.clone(), Some(source));
            match discover_jdk_jmods(&home, &mut discovery.inputs.probes) {
                Ok(Some(jmods)) => dependency
                    .artifacts
                    .push(jdk_jmod_set_artifact(&release, &home, &jmods)),
                Ok(None) => {}
                Err(message) => discovery.diagnostics.push(DependencyPackDiagnostic {
                    severity: if configured {
                        DependencyPackDiagnosticSeverity::Error
                    } else {
                        DependencyPackDiagnosticSeverity::Warning
                    },
                    code: super::producer_codes::JDK_JMODS_INVALID.code.to_owned(),
                    dependency_id: Some(format!("jdk:{version}")),
                    location: Some(home.to_string_lossy().into_owned()),
                    message,
                }),
            }
            dependency
        } else {
            match discover_jdk_jmods(&home, &mut discovery.inputs.probes) {
                Ok(Some(jmods)) => resolved_jdk_jmod_dependency(&release, home.clone(), jmods),
                Ok(None) => resolved_jdk_dependency(version.clone(), None),
                Err(message) => {
                    discovery.diagnostics.push(DependencyPackDiagnostic {
                        severity: if configured {
                            DependencyPackDiagnosticSeverity::Error
                        } else {
                            DependencyPackDiagnosticSeverity::Warning
                        },
                        code: super::producer_codes::JDK_JMODS_INVALID.code.to_owned(),
                        dependency_id: Some(format!("jdk:{version}")),
                        location: Some(home.to_string_lossy().into_owned()),
                        message,
                    });
                    resolved_jdk_dependency(version.clone(), None)
                }
            }
        };
        // Distinct homes can report the same version while carrying different
        // source or JMOD artifacts. Each artifact carries its content pin;
        // coalescing by release version here would erase one source binding.
        dependency_homes.push(home);
        discovery.dependencies.push(dependency);
    }
    let mut id_counts = HashMap::default();
    for dependency in &discovery.dependencies {
        *id_counts.entry(dependency.id.clone()).or_insert(0usize) += 1;
    }
    for (dependency, home) in discovery.dependencies.iter_mut().zip(dependency_homes) {
        if id_counts[&dependency.id] > 1 {
            // The ID correlates discovery with preparation in this run; the
            // prepared input digest, not this path-derived suffix, is the
            // artifact proof. Single-home IDs keep their existing display.
            let mut digest = LengthDelimitedDigest::new(JDK_DISCOVERY_HOME_ID_DOMAIN);
            digest.push(home.as_os_str().as_encoded_bytes());
            dependency.id = format!("{}@{}", dependency.id, digest.finish());
        }
    }
    if discovery.dependencies.is_empty() && discovery.diagnostics.is_empty() && discovery_requested
    {
        let tried_path = match (path_consulted, path_rejection) {
            (true, Some(reason)) => format!("; {reason}"),
            (true, None) => "; `java` on PATH was tried".to_owned(),
            (false, _) => String::new(),
        };
        discovery.diagnostics.push(DependencyPackDiagnostic {
            severity: DependencyPackDiagnosticSeverity::Warning,
            code: super::producer_codes::JDK_HOME_UNAVAILABLE.code.to_owned(),
            dependency_id: None,
            location: None,
            message: format!(
                "no usable JDK was discovered; JVM standard-library semantic packs are inactive. Set JAVA_HOME to a JDK installation in the language-server process environment and restart Bifrost{tried_path}"
            ),
        });
    }
    discovery.inputs.complete = jdk_inputs_complete(&discovery);
    discovery
}

/// A home, JMOD or source-archive probe that failed left an input unread,
/// whether the home was configured (an error) or came from JAVA_HOME (a
/// warning), and whether or not a diagnostic names it.
fn jdk_inputs_complete(discovery: &JdkDiscovery) -> bool {
    !discovery.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == super::producer_codes::JDK_HOME_INVALID.code
            || diagnostic.code == super::producer_codes::JDK_JMODS_INVALID.code
    }) && !discovery
        .inputs
        .probes
        .iter()
        .any(|probe| matches!(probe.outcome, ExternalProbeOutcome::Unreadable))
}

/// Pin every discovered JDK dependency to its content digests. Only activation
/// and the JDK question apply this: the production key, the catalog
/// expectation and certification bind the pins. A member that cannot be
/// hashed records an `Unreadable` probe, so the inputs are re-judged. `Break`
/// means the token was cancelled while pinning.
fn pin_jdk_discovery(
    discovery: &mut JdkDiscovery,
    digests: &ContentDigestCache,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> ControlFlow<()> {
    let mut pass_bytes = 0;
    for dependency in &mut discovery.dependencies {
        pin_jdk_artifacts(
            dependency,
            digests,
            limits,
            cancellation,
            &mut discovery.inputs.probes,
            &mut pass_bytes,
        )?;
    }
    discovery.inputs.complete = jdk_inputs_complete(discovery);
    ControlFlow::Continue(())
}

/// The member path capture frames: normalized components joined by `/`, so the
/// spelling does not depend on the platform separator.
fn framed_member_path(relative_path: &Path) -> String {
    relative_path
        .components()
        .map(|part| {
            part.as_os_str()
                .to_str()
                .expect("selected JDK member names were checked to be UTF-8")
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
thread_local! {
    /// Digests actually computed (cache misses) on this thread.
    pub(super) static JDK_DIGEST_COMPUTATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Finishes a JDK digest the cache could not serve.
fn finish_jdk_digest(hasher: Sha256) -> [u8; 32] {
    #[cfg(test)]
    JDK_DIGEST_COMPUTATIONS.set(JDK_DIGEST_COMPUTATIONS.get() + 1);
    brokk_bifrost_semantic::analyzer::semantic_model::producer::finish_digest(hasher)
}

/// Record an input selection listed moments ago and could not read. Whatever
/// the error kind, even a vanished member is an unread input, never an absent
/// candidate, so the answer is incomplete.
fn push_unreadable_probe(
    probes: &mut Vec<ExternalPathProbe>,
    path: PathBuf,
    operation: ExternalProbeOperation,
) {
    probes.push(ExternalPathProbe {
        path,
        operation,
        outcome: ExternalProbeOutcome::Unreadable,
    });
}

/// Pin each artifact of a JDK dependency to the digest capture will compute
/// (#9559), so a JMOD or `src.zip` replaced between selection and capture
/// fails as `artifact.digest_changed` instead of being parsed under a
/// selection that bound only its metadata. The digests stream the opened files
/// through the store's cache: a second selection of unchanged files reads
/// nothing when the recorded observation is outside the racy window.
///
/// A dependency is pinned all or nothing. The catalog expectation wants the
/// pinned production key only for a fully pinned dependency, and the metadata
/// source identity only for a wholly unpinned one, so a half-pinned JDK would
/// expect a production that no installed pack matches. A dependency stays
/// unpinned (uncertified, on its metadata identity) when capture would refuse
/// a pin for another reason: capture requires the pinned path to be its own
/// canonical path (a symlinked `src.zip`, as on Debian), and it refuses an
/// artifact over the producer limits, which are checked from metadata before
/// any byte is hashed. A member that cannot be read records an `Unreadable`
/// file probe for that member, which makes the answer incomplete.
fn pin_jdk_artifacts(
    dependency: &mut ResolvedDependency,
    digests: &ContentDigestCache,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
    probes: &mut Vec<ExternalPathProbe>,
    pass_bytes: &mut u64,
) -> ControlFlow<()> {
    use brokk_bifrost_semantic::analyzer::semantic_model::producer::{
        hash_exact_file, hash_source_member, source_set_hasher,
    };
    let is_cancelled = || cancellation.is_some_and(CancellationToken::is_cancelled);
    let mut total_bytes = 0u64;
    // The member sizes the limits were checked against, per JDK artifact.
    let mut listed_sizes = Vec::new();
    for artifact in &dependency.artifacts {
        let (member_paths, per_artifact_limit) = match (&artifact.input, artifact.kind) {
            (
                ResolvedDependencyArtifactInput::SourceSet {
                    root,
                    relative_paths,
                },
                ExternalArtifactKind::JdkJmodSet,
            ) => (
                relative_paths
                    .iter()
                    .map(|member| root.join(member))
                    .collect::<Vec<_>>(),
                limits.max_total_artifact_bytes,
            ),
            (ResolvedDependencyArtifactInput::File(file), ExternalArtifactKind::JdkSourceZip) => {
                (vec![file.clone()], limits.producer.max_artifact_bytes)
            }
            _ => continue,
        };
        let path = artifact.path();
        match fs::canonicalize(path) {
            Ok(canonical) if canonical == path => {}
            Ok(_) => return ControlFlow::Continue(()),
            Err(_) => {
                push_unreadable_probe(
                    probes,
                    path.to_path_buf(),
                    ExternalProbeOperation::Canonicalize,
                );
                return ControlFlow::Continue(());
            }
        }
        let mut artifact_bytes = 0u64;
        let mut sizes = Vec::with_capacity(member_paths.len());
        for member in &member_paths {
            match jdk_member_metadata(member) {
                Ok(metadata) => {
                    sizes.push(metadata.len());
                    artifact_bytes = artifact_bytes.saturating_add(metadata.len());
                }
                Err(_) => {
                    push_unreadable_probe(probes, member.clone(), ExternalProbeOperation::File);
                    return ControlFlow::Continue(());
                }
            }
        }
        listed_sizes.push(sizes);
        total_bytes = total_bytes.saturating_add(artifact_bytes);
        if artifact_bytes > per_artifact_limit || total_bytes > limits.max_total_artifact_bytes {
            return ControlFlow::Continue(());
        }
    }

    if total_bytes > limits.max_total_artifact_bytes.saturating_sub(*pass_bytes) {
        return ControlFlow::Continue(());
    }
    *pass_bytes += total_bytes;

    let mut listed_sizes = listed_sizes.into_iter();
    let mut pins = Vec::with_capacity(dependency.artifacts.len());
    for artifact in &dependency.artifacts {
        // A cache hit reads nothing, so the token is also checked here.
        if is_cancelled() {
            return ControlFlow::Break(());
        }
        let path = artifact.path().to_path_buf();
        // The members hashed before a failure, so the next one is the culprit.
        let mut visited = 0usize;
        let (digest, member_paths) = match (&artifact.input, artifact.kind) {
            (
                ResolvedDependencyArtifactInput::SourceSet {
                    root,
                    relative_paths,
                },
                ExternalArtifactKind::JdkJmodSet,
            ) => {
                let listed = listed_sizes.next().expect("one size list per JDK artifact");
                (
                    digests.digest_by_metadata(
                        JDK_JMOD_SET_DIGEST_DOMAIN,
                        root,
                        relative_paths,
                        cancellation,
                        |index, size| listed_member_size(&listed, index, size).map(|_| ()),
                        source_set_hasher,
                        |hasher, member| {
                            hash_source_member(
                                hasher,
                                &framed_member_path(member.relative_path),
                                listed_member_size(&listed, visited, member.size)?,
                                &mut CancellableRead::new(member.file, cancellation),
                            )?;
                            visited += 1;
                            Ok(())
                        },
                        finish_jdk_digest,
                    ),
                    relative_paths
                        .iter()
                        .map(|member| root.join(member))
                        .collect::<Vec<_>>(),
                )
            }
            (ResolvedDependencyArtifactInput::File(file), ExternalArtifactKind::JdkSourceZip) => {
                let listed = listed_sizes.next().expect("one size list per JDK artifact");
                (
                    digests.digest_by_metadata(
                        JDK_SOURCE_ZIP_DIGEST_DOMAIN,
                        file.parent()
                            .expect("a source archive has a parent directory"),
                        &[PathBuf::from(
                            file.file_name()
                                .expect("a source archive path names a file"),
                        )],
                        cancellation,
                        |index, size| listed_member_size(&listed, index, size).map(|_| ()),
                        |_| Sha256::new(),
                        |hasher, member| {
                            hash_exact_file(
                                hasher,
                                listed_member_size(&listed, visited, member.size)?,
                                &mut CancellableRead::new(member.file, cancellation),
                            )?;
                            visited += 1;
                            Ok(())
                        },
                        finish_jdk_digest,
                    ),
                    vec![file.clone()],
                )
            }
            _ => continue,
        };
        // A single-flight wait can finish with a cache hit without invoking
        // the cancellable reader. Check before accepting even the final pin.
        if is_cancelled() {
            return ControlFlow::Break(());
        }
        match digest {
            Ok(digest) => pins.push(lower_hex_string(&digest)),
            Err(error) => {
                let culprit = error
                    .get_ref()
                    .and_then(|source| {
                        source
                            .downcast_ref::<brokk_bifrost_core::content_digest::DigestMemberError>()
                    })
                    .map(|member| member.path.clone())
                    .unwrap_or_else(|| member_paths.get(visited).unwrap_or(&path).clone());
                push_unreadable_probe(probes, culprit, ExternalProbeOperation::File);
                return ControlFlow::Continue(());
            }
        }
    }
    let mut pins = pins.into_iter();
    for artifact in &mut dependency.artifacts {
        if matches!(
            artifact.kind,
            ExternalArtifactKind::JdkJmodSet | ExternalArtifactKind::JdkSourceZip
        ) {
            artifact.source_identity = None;
            artifact.expected_sha256 = Some(pins.next().expect("one pin per JDK artifact"));
        }
    }
    assert!(pins.next().is_none(), "one pin per JDK artifact");
    ControlFlow::Continue(())
}

/// The size the limits were checked against for the `index`th member. A member
/// opened with another size changed after that check, so it is not hashed:
/// the read stays bounded by the checked size.
fn listed_member_size(listed: &[u64], index: usize, opened: u64) -> std::io::Result<u64> {
    match listed.get(index) {
        Some(&size) if size == opened => Ok(size),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "a JDK artifact member changed size after its limits were checked",
        )),
    }
}

/// Reads through to a file, refusing each read after the token is cancelled,
/// so a cancelled pin stops between chunks instead of finishing a JMOD.
struct CancellableRead<'a, R> {
    inner: R,
    cancellation: Option<&'a CancellationToken>,
}

impl<'a, R> CancellableRead<'a, R> {
    fn new(inner: R, cancellation: Option<&'a CancellationToken>) -> Self {
        Self {
            inner,
            cancellation,
        }
    }
}

impl<R: Read> Read for CancellableRead<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self
            .cancellation
            .is_some_and(CancellationToken::is_cancelled)
        {
            return Err(std::io::Error::other("JDK pinning was cancelled"));
        }
        self.inner.read(buffer)
    }
}

/// The discovered home of one JDK dependency, derived only from the artifact
/// layout that discovery itself emitted. This identifies the configured input
/// for host-side correlation; it is never an artifact-content proof.
pub(crate) fn jdk_home_for_dependency(dependency: &ResolvedDependency) -> Option<&Path> {
    if dependency.evidence.ecosystem != "jdk" {
        return None;
    }
    let mut selected = None;
    for artifact in &dependency.artifacts {
        let home = match artifact.kind {
            ExternalArtifactKind::JdkJmodSet => artifact.path(),
            ExternalArtifactKind::JdkSourceZip => {
                let parent = artifact.path().parent()?;
                if parent.file_name().is_some_and(|name| name == "lib") {
                    parent.parent()?
                } else {
                    parent
                }
            }
            _ => return None,
        };
        match selected {
            Some(previous) if previous != home => return None,
            None => selected = Some(home),
            _ => {}
        }
    }
    selected
}

/// One selected JMOD archive with the filesystem metadata that stands in for
/// its bytes in the read-free source identity.
///
/// The discovery already inspects every candidate archive to prove it is a
/// real regular file, so the length and modification time cost no extra read.
/// `modified` is `None` when the filesystem would not report one, which is the
/// signal that this archive gets no identity at all rather than an identity
/// that spells "unknown" the same way a real timestamp would.
struct JdkJmodFile {
    relative_path: PathBuf,
    bytes: u64,
    modified: Option<SystemTime>,
}

fn discover_jdk_jmods(
    home: &Path,
    probes: &mut Vec<ExternalPathProbe>,
) -> Result<Option<Vec<JdkJmodFile>>, String> {
    let jmods = home.join("jmods");
    let metadata = fs::symlink_metadata(&jmods);
    record_external_probe(probes, &jmods, ExternalProbeOperation::List, &metadata);
    let metadata = match metadata {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("could not inspect JDK jmods directory: {error}")),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("JDK jmods path is not a real directory".to_owned());
    }
    let mut paths = Vec::new();
    let mut entries_seen = 0usize;
    let entries = fs::read_dir(&jmods)
        .map_err(|error| format!("could not read JDK jmods directory: {error}"))?;
    for entry in entries {
        entries_seen = entries_seen.saturating_add(1);
        if entries_seen > MAX_JDK_JMOD_FILES {
            return Err(format!(
                "JDK jmods directory contains more than {MAX_JDK_JMOD_FILES} bounded entries"
            ));
        }
        let entry = entry.map_err(|error| format!("could not read JDK jmod entry: {error}"))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.ends_with(".jmod") {
            continue;
        }
        let metadata = fs::symlink_metadata(&path);
        record_external_probe(probes, &path, ExternalProbeOperation::File, &metadata);
        let metadata =
            metadata.map_err(|error| format!("could not inspect JDK jmod {name}: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            continue;
        }
        paths.push(JdkJmodFile {
            relative_path: PathBuf::from("jmods").join(name),
            bytes: metadata.len(),
            modified: metadata.modified().ok(),
        });
    }
    // Capture orders the framed members by the UTF-8 bytes of their names, and
    // the pinned digest must visit them in the same order. Every name here was
    // checked to be UTF-8 above, so the encoded bytes are UTF-8 bytes.
    paths.sort_unstable_by(|left, right| {
        left.relative_path
            .as_os_str()
            .as_encoded_bytes()
            .cmp(right.relative_path.as_os_str().as_encoded_bytes())
    });
    if paths.len() > MAX_JDK_JMOD_FILES {
        return Err(format!(
            "JDK jmods directory contains more than {MAX_JDK_JMOD_FILES} bounded archives"
        ));
    }
    Ok((!paths.is_empty()).then_some(paths))
}

/// A JDK `JAVA_VERSION` exactly as the `release` file spells it. JEP 322
/// defines `feature.interim.update.patch`; fifth and later elements are free
/// for platform implementors to identify vendor-specific patch releases. The
/// raw spelling is the dependency identity; catalog toolchain comparisons use
/// only the semver view below (#2874).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JdkVersion {
    raw: String,
    components: Vec<u64>,
}

impl JdkVersion {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let mut components = Vec::new();
        for component in raw.split('.') {
            // `u64::from_str` accepts a leading `+`, and a JDK 8 spelling such
            // as `1.8.0_392` must stay rejected, so the digits are checked
            // before the conversion.
            if component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(format!("{component:?} is not a decimal component"));
            }
            components.push(u64::from_str(component).map_err(|error| {
                format!("component {component:?} does not fit in 64 bits: {error}")
            })?);
        }
        debug_assert!(
            !components.is_empty(),
            "split('.') yields at least one component, and an empty one is rejected above"
        );
        Ok(Self {
            raw: raw.to_owned(),
            components,
        })
    }

    /// The catalog's semver toolchain coordinate; vendor elements and the
    /// fourth JDK patch element are below its resolution.
    fn semver(&self) -> Version {
        let component = |index: usize| self.components.get(index).copied().unwrap_or(0);
        Version::new(component(0), component(1), component(2))
    }
}

impl std::fmt::Display for JdkVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.raw)
    }
}

/// A JDK home's `release` file: the version it declares, and the exact bytes
/// that declared it.
///
/// Those bytes are the JDK-level half of the read-free JMOD set identity
/// ([`jdk_jmod_set_source_identity`]). The discovery reads the file anyway to
/// learn the version, so identity costs no additional read.
struct JdkRelease {
    version: JdkVersion,
    bytes: Vec<u8>,
}

fn read_jdk_release(
    home: &Path,
    probes: &mut Vec<ExternalPathProbe>,
) -> Result<JdkRelease, String> {
    const MAX_RELEASE_BYTES: u64 = 64 * 1024;

    let release_path = home.join("release");
    let metadata = fs::metadata(&release_path);
    record_external_probe(
        probes,
        &release_path,
        ExternalProbeOperation::File,
        &metadata,
    );
    let metadata = metadata
        .map_err(|error| format!("JDK home does not contain a readable release file: {error}"))?;
    if !metadata.is_file() || metadata.len() > MAX_RELEASE_BYTES {
        return Err("JDK release file is not a bounded regular file".to_owned());
    }
    let mut release_bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(&release_path)
        .and_then(|file| {
            file.take(MAX_RELEASE_BYTES.saturating_add(1))
                .read_to_end(&mut release_bytes)
        })
        .map_err(|error| format!("could not read JDK release file: {error}"))?;
    if release_bytes.len() as u64 > MAX_RELEASE_BYTES {
        return Err("JDK release file grew beyond the bounded read limit".to_owned());
    }
    let release = std::str::from_utf8(&release_bytes)
        .map_err(|error| format!("JDK release file is not valid UTF-8 text: {error}"))?;
    let mut values = release.lines().filter_map(|line| {
        let (key, value) = line.split_once('=')?;
        (key == "JAVA_VERSION").then_some(value.trim().trim_matches('"'))
    });
    let raw = values
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "JDK release file does not declare JAVA_VERSION".to_owned())?;
    if values.next().is_some() {
        return Err("JDK release file declares JAVA_VERSION more than once".to_owned());
    }
    let version = JdkVersion::parse(raw).map_err(|error| {
        format!("JDK JAVA_VERSION {raw:?} is not a dotted JDK version: {error}")
    })?;
    Ok(JdkRelease {
        version,
        bytes: release_bytes,
    })
}

fn resolved_jdk_dependency(
    version: JdkVersion,
    source_archive: Option<PathBuf>,
) -> ResolvedDependency {
    ResolvedDependency {
        id: format!("jdk:{version}"),
        evidence: SemanticModelActivationEvidence {
            language: "java".to_owned(),
            ecosystem: "jdk".to_owned(),
            package: None,
            module: None,
            toolchain: Some(CatalogCoordinate {
                name: "jdk".to_owned(),
                version: Some(version.semver()),
            }),
            target: Some("jvm".to_owned()),
            configuration: None,
            production_input_digest: None,
            verified_raw_artifacts: Vec::new(),
        },
        provenance: vec![DependencyProvenance {
            key: "version".to_owned(),
            value: version.to_string(),
        }],
        artifacts: source_archive
            .map(|path| {
                let identity = jdk_source_zip_identity(&path);
                let artifact = ResolvedDependencyArtifact::file(
                    DependencyArtifactRole::Sources,
                    ExternalArtifactKind::JdkSourceZip,
                    path,
                );
                match identity {
                    Some(identity) => artifact.with_source_identity(identity),
                    None => artifact,
                }
            })
            .into_iter()
            .collect(),
        scope: DependencyScope::Unknown,
        declared_by: None,
    }
}

// Include file replacement and metadata change identity, not just length/mtime:
// an installer may preserve the archive's timestamp. A filesystem that cannot
// report a strong change identity retains the exact-read path.
fn jdk_source_zip_identity(path: &Path) -> Option<ArtifactSourceIdentity> {
    let canonical = path.canonicalize().ok()?;
    let identity = jvm_artifact_change_identity(&canonical).ok()??;
    let mut digest = LengthDelimitedDigest::new(b"bifrost.jdk-source-zip-state.v2");
    digest.push(canonical.as_os_str().as_encoded_bytes());
    digest.push(&identity.digest());
    Some(ArtifactSourceIdentity::from_digest(
        digest.finish().to_string(),
    ))
}

fn resolved_jdk_jmod_dependency(
    release: &JdkRelease,
    home: PathBuf,
    jmods: Vec<JdkJmodFile>,
) -> ResolvedDependency {
    let mut dependency = resolved_jdk_dependency(release.version.clone(), None);
    dependency.artifacts = vec![jdk_jmod_set_artifact(release, &home, &jmods)];
    dependency
}

/// The `JdkJmodSet` artifact of one JDK home, carrying the read-free identity
/// of the selected archives when the discovery could derive one.
///
/// The identity only decides whether a later process looks in the catalog
/// before reading; a JDK with no derivable identity (an archive without a
/// modification time) produces exactly the artifact it produced before.
fn jdk_jmod_set_artifact(
    release: &JdkRelease,
    home: &Path,
    jmods: &[JdkJmodFile],
) -> ResolvedDependencyArtifact {
    let artifact = ResolvedDependencyArtifact::source_set(
        DependencyArtifactRole::Binary,
        ExternalArtifactKind::JdkJmodSet,
        home.to_path_buf(),
        jmods
            .iter()
            .map(|jmod| jmod.relative_path.clone())
            .collect(),
    );
    match jdk_jmod_set_source_identity(&release.bytes, jmods) {
        Some(identity) => artifact.with_source_identity(identity),
        None => artifact,
    }
}

/// Derive the read-free identity of one JDK's selected JMOD set from the
/// `release` bytes and each archive's relative path, length, and modification
/// time.
///
/// This is the same stand-in for artifact bytes the external declaration index
/// already uses ([`push_artifact_file_evidence`]): cheap filesystem metadata
/// that changes whenever the installed JDK changes. It never decides what a
/// production contains, so a false match would only cost a lookup; the exact
/// read and its digests remain the authority for the pack's contents.
fn jdk_jmod_set_source_identity(
    release_bytes: &[u8],
    jmods: &[JdkJmodFile],
) -> Option<ArtifactSourceIdentity> {
    if jmods.is_empty() {
        return None;
    }
    let mut digest = LengthDelimitedDigest::new(JDK_JMOD_SET_SOURCE_IDENTITY_DOMAIN);
    digest.push(release_bytes);
    digest.push(&(jmods.len() as u64).to_le_bytes());
    for jmod in jmods {
        digest.push(jmod.relative_path.as_os_str().as_encoded_bytes());
        digest.push(&jmod.bytes.to_le_bytes());
        let modified = jmod.modified?.duration_since(std::time::UNIX_EPOCH).ok()?;
        digest.push(&modified.as_secs().to_le_bytes());
        digest.push(&modified.subsec_nanos().to_le_bytes());
    }
    Some(ArtifactSourceIdentity::from_digest(
        digest.finish().to_string(),
    ))
}

impl DependencyPackAdapter for JvmDependencyPackAdapter {
    fn adapter_name(&self) -> &str {
        "bifrost-jvm-dependency"
    }

    fn adapter_version(&self) -> &str {
        super::jvm_pack_producer_version()
    }

    fn production_schema_version(&self) -> u32 {
        // The key covers the newest schema in the output: distinct class
        // finality (#10572), which also admits method type-parameter bounds.
        brokk_bifrost_semantic::analyzer::semantic_model::CLASS_FINALITY_MIN_SCHEMA_VERSION
    }

    fn producer(&self) -> Producer {
        Producer {
            name: self.adapter_name().to_owned(),
            version: self.adapter_version().to_owned(),
        }
        .with_dependency_revision()
    }

    /// Only JDK artifacts carry pins, and selection computes them from the
    /// opened files through the content-digest cache ([`pin_jdk_artifacts`]).
    fn reuses_productions_by_pinned_key(&self) -> bool {
        true
    }

    fn can_produce(&self, dependency: &ResolvedDependency) -> bool {
        !matches!(dependency.evidence.language.as_str(), "scala" | "kotlin")
            || dependency.artifacts.iter().any(|artifact| {
                artifact.kind
                    == if dependency.evidence.language == "scala" {
                        ExternalArtifactKind::ScalaSourceJar
                    } else {
                        ExternalArtifactKind::KotlinSourceJar
                    }
            })
    }

    fn produce(
        &self,
        dependency: &ResolvedDependency,
        artifacts: &[ExactDependencyArtifact],
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
    ) -> DependencyPackProduction {
        let request = jvm_dependency_production_request(dependency);
        let mut diagnostics = Vec::new();
        let mut suppressed_diagnostics = SuppressedDiagnostics::default();
        let mut source_diagnostics = Vec::new();
        let mut source_suppressed = SuppressedDiagnostics::default();
        let mut source_pack = None;
        let mut binary_pack = None;
        let mut partial = false;
        let mut jdk_jmods_complete = false;
        let mut jdk_source_zip_present = false;
        for artifact in artifacts {
            let mut artifact_request = request.clone();
            artifact_request.path = artifact.path().to_owned();
            artifact_request.artifact_kind = artifact.kind();
            let production = match artifact.kind() {
                ExternalArtifactKind::ScalaSourceJar => ScalaSourceJarPackProducer
                    .produce_loaded_artifact(
                        &artifact_request,
                        limits,
                        cancellation,
                        artifact.exact(),
                    ),
                ExternalArtifactKind::KotlinSourceJar => KotlinSourceJarPackProducer
                    .produce_loaded_artifact(
                        &artifact_request,
                        limits,
                        cancellation,
                        artifact.exact(),
                    ),
                ExternalArtifactKind::JavaSourceJar | ExternalArtifactKind::JavaClassJar => {
                    JavaJarPackProducer.produce_loaded_artifact(
                        &artifact_request,
                        limits,
                        cancellation,
                        artifact.exact(),
                    )
                }
                ExternalArtifactKind::JdkSourceZip => {
                    match detect_jdk_source_archive_layout(artifact.exact()) {
                        Ok(layout) => JdkSourceArchivePackProducer::new(layout)
                            .produce_loaded_artifact(
                                &artifact_request,
                                limits,
                                cancellation,
                                artifact.exact(),
                            ),
                        Err(diagnostic) => ArtifactProduction::failed(diagnostic, limits),
                    }
                }
                ExternalArtifactKind::JdkJmodSet => JdkJmodSetPackProducer.produce_loaded_artifact(
                    &artifact_request,
                    limits,
                    cancellation,
                    artifact.exact(),
                ),
                kind => ArtifactProduction::failed(
                    ProducerDiagnostic {
                        severity: ProducerDiagnosticSeverity::Error,
                        source_entry: None,
                        code: super::producer_codes::ARTIFACT_KIND.code.to_owned(),
                        location: Some(artifact.path().to_string_lossy().into_owned()),
                        declaration: None,
                        message: format!("unsupported JVM dependency artifact kind {kind:?}"),
                    },
                    limits,
                ),
            };
            debug_assert_eq!(
                production.artifact_sha256.as_deref(),
                Some(artifact.sha256())
            );
            if matches!(artifact.kind(), ExternalArtifactKind::JdkJmodSet) {
                jdk_jmods_complete = production.completeness == Completeness::Complete
                    && production
                        .diagnostics
                        .iter()
                        .all(|diagnostic| diagnostic.severity != ProducerDiagnosticSeverity::Error)
                    && production.suppressed_diagnostics.errors == 0;
            }
            if matches!(artifact.kind(), ExternalArtifactKind::JdkSourceZip) {
                jdk_source_zip_present = true;
            }
            partial |= production.completeness != Completeness::Complete;
            if matches!(artifact.role(), DependencyArtifactRole::Sources) {
                source_diagnostics.extend(production.diagnostics);
                source_suppressed += production.suppressed_diagnostics;
            } else {
                diagnostics.extend(production.diagnostics);
                suppressed_diagnostics += production.suppressed_diagnostics;
            }
            match (artifact.role(), production.pack) {
                (DependencyArtifactRole::Sources, Some(pack)) => source_pack = Some(pack),
                (DependencyArtifactRole::Binary, Some(mut pack)) => {
                    normalize_artifact_locator_paths(
                        &mut pack,
                        &format!("sha256-{}.artifact", artifact.sha256()),
                    );
                    binary_pack = Some(pack);
                }
                (_, Some(_)) => diagnostics.push(ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    source_entry: None,
                    code: super::producer_codes::ARTIFACT_ROLE.code.to_owned(),
                    location: Some(artifact.path().to_string_lossy().into_owned()),
                    declaration: None,
                    message: "JVM dependency requires binary or sources artifact roles".to_owned(),
                }),
                (_, None) => {}
            }
        }
        let mut merge_diagnostics = Vec::new();
        let mut merge_suppressed = SuppressedDiagnostics::default();
        let pack = merge_java_dependency_packs(
            source_pack,
            binary_pack,
            &mut merge_diagnostics,
            &mut merge_suppressed,
            limits,
        );
        let mut pack = pack;
        if let Some(pack) = pack.as_mut() {
            pack.producer = self.producer();
            if jdk_jmods_complete && jdk_source_zip_present {
                // A complete JDK JMOD set enumerates the platform's declarations.
                // The optional source archive refines locators and documentation;
                // its own coverage gaps cannot weaken the binary declaration
                // surface.
                pack.completeness = Completeness::Complete;
                let auxiliary_suppressed = source_suppressed
                    .total()
                    .saturating_add(merge_suppressed.total());
                for diagnostic in source_diagnostics
                    .iter_mut()
                    .chain(merge_diagnostics.iter_mut())
                {
                    if diagnostic.severity == ProducerDiagnosticSeverity::Error {
                        diagnostic.severity = ProducerDiagnosticSeverity::Warning;
                    }
                }
                diagnostics.extend(source_diagnostics);
                diagnostics.extend(merge_diagnostics);
                if auxiliary_suppressed > 0 {
                    diagnostics.push(ProducerDiagnostic {
                        severity: ProducerDiagnosticSeverity::Warning,
                        source_entry: None,
                        code: super::producer_codes::AUXILIARY_SOURCE_DIAGNOSTICS
                            .code
                            .to_owned(),
                        location: None,
                        declaration: None,
                        message: format!(
                            "{auxiliary_suppressed} source-extraction diagnostics were suppressed; the complete binary inventory covers these declarations"
                        ),
                    });
                }
            } else {
                diagnostics.extend(source_diagnostics);
                suppressed_diagnostics += source_suppressed;
                diagnostics.extend(merge_diagnostics);
                suppressed_diagnostics += merge_suppressed;
                if partial || !diagnostics.is_empty() || suppressed_diagnostics.total() > 0 {
                    pack.completeness = Completeness::Partial;
                }
            }
        }
        DependencyPackProduction {
            pack,
            diagnostics,
            suppressed_diagnostics,
        }
    }
}

#[cfg(test)]
fn resolved_semantic_pack_dependency(artifact: ResolvedJvmArtifact) -> ResolvedDependency {
    resolved_semantic_pack_dependency_while(artifact, None)
}

fn resolved_semantic_pack_dependency_while(
    artifact: ResolvedJvmArtifact,
    cancellation: Option<&CancellationToken>,
) -> ResolvedDependency {
    let scala_library = artifact
        .coordinate
        .as_ref()
        .is_some_and(is_scala_library_coordinate);
    let source_path = if is_source_jar(&artifact.artifact_path) {
        Some(artifact.artifact_path.as_path())
    } else {
        artifact.source_artifact_path.as_deref()
    };
    let kotlin_source = source_path
        .map(|path| classify_kotlin_source(path, cancellation))
        .unwrap_or(KotlinArchiveClassification::Absent);
    let kotlin_binary = if kotlin_source == KotlinArchiveClassification::Present
        || is_source_jar(&artifact.artifact_path)
    {
        KotlinArchiveClassification::Absent
    } else {
        classify_kotlin_metadata(&artifact.artifact_path, cancellation)
    };
    let kotlin_stdlib = artifact
        .coordinate
        .as_ref()
        .is_some_and(is_kotlin_stdlib_coordinate);
    let kotlin = kotlin_source != KotlinArchiveClassification::Absent
        || kotlin_binary != KotlinArchiveClassification::Absent
        || kotlin_stdlib;
    let kotlin_classification_incomplete = !kotlin_stdlib
        && kotlin_source != KotlinArchiveClassification::Present
        && kotlin_binary != KotlinArchiveClassification::Present
        && [kotlin_source, kotlin_binary].iter().any(|value| {
            !matches!(
                value,
                KotlinArchiveClassification::Present | KotlinArchiveClassification::Absent
            )
        });
    let coordinate_id = artifact.coordinate.as_ref().map(|coordinate| {
        format!(
            "{}:{}:{}",
            coordinate.group_id, coordinate.artifact_id, coordinate.version
        )
    });
    let id = coordinate_id.unwrap_or_else(|| {
        format!(
            "explicit:{}",
            artifact
                .artifact_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
        )
    });
    let ecosystem = if scala_library || kotlin_stdlib {
        "maven"
    } else {
        match artifact.origin {
            JvmDependencyOrigin::MavenReport | JvmDependencyOrigin::MavenRepository => "maven",
            JvmDependencyOrigin::GradleReport | JvmDependencyOrigin::GradleCache => "gradle",
            JvmDependencyOrigin::ExplicitPath => "jvm",
        }
    };
    let package = artifact
        .coordinate
        .as_ref()
        .map(|coordinate| CatalogCoordinate {
            name: format!("{}:{}", coordinate.group_id, coordinate.artifact_id),
            version: maven_coordinate_version(&coordinate.version),
        });
    let mut provenance = vec![DependencyProvenance {
        key: "origin".to_owned(),
        value: jvm_dependency_origin_name(artifact.origin).to_owned(),
    }];
    if let Some(coordinate) = &artifact.coordinate {
        provenance.extend([
            DependencyProvenance {
                key: "group".to_owned(),
                value: coordinate.group_id.clone(),
            },
            DependencyProvenance {
                key: "artifact".to_owned(),
                value: coordinate.artifact_id.clone(),
            },
            DependencyProvenance {
                key: "version".to_owned(),
                value: coordinate.version.clone(),
            },
        ]);
    }
    if kotlin_classification_incomplete {
        for classification in [kotlin_source, kotlin_binary] {
            let (value, detail) = match classification {
                KotlinArchiveClassification::Incomplete => (
                    "incomplete",
                    "archive or entry read failed or inspection was cancelled".to_owned(),
                ),
                KotlinArchiveClassification::Capped(cap, limit) => {
                    ("capped", format!("{cap} = {limit}"))
                }
                KotlinArchiveClassification::Malformed => (
                    "malformed",
                    "artifact contains malformed archive or class metadata".to_owned(),
                ),
                _ => continue,
            };
            provenance.push(DependencyProvenance {
                key: format!("kotlin.classification.{value}"),
                value: detail,
            });
        }
    }
    let source_kind = if scala_library {
        ExternalArtifactKind::ScalaSourceJar
    } else if kotlin {
        ExternalArtifactKind::KotlinSourceJar
    } else {
        ExternalArtifactKind::JavaSourceJar
    };
    let artifacts = if is_source_jar(&artifact.artifact_path) {
        vec![ResolvedDependencyArtifact::file(
            DependencyArtifactRole::Sources,
            source_kind,
            artifact.artifact_path,
        )]
    } else if (scala_library || kotlin) && artifact.source_artifact_path.is_some() {
        vec![ResolvedDependencyArtifact::file(
            DependencyArtifactRole::Sources,
            source_kind,
            artifact
                .source_artifact_path
                .expect("source path was checked above"),
        )]
    } else {
        let mut artifacts = vec![ResolvedDependencyArtifact::file(
            DependencyArtifactRole::Binary,
            ExternalArtifactKind::JavaClassJar,
            artifact.artifact_path,
        )];
        if let Some(source_artifact_path) = artifact.source_artifact_path {
            artifacts.push(ResolvedDependencyArtifact::file(
                DependencyArtifactRole::Sources,
                source_kind,
                source_artifact_path,
            ));
        }
        artifacts
    };
    ResolvedDependency {
        id,
        evidence: SemanticModelActivationEvidence {
            language: if scala_library {
                "scala"
            } else if kotlin {
                "kotlin"
            } else {
                "java"
            }
            .to_owned(),
            ecosystem: ecosystem.to_owned(),
            package,
            module: (artifact.origin == JvmDependencyOrigin::ExplicitPath).then(|| {
                CatalogCoordinate {
                    name: "local-jvm-artifact".to_owned(),
                    version: None,
                }
            }),
            toolchain: (scala_library || kotlin_stdlib).then(|| CatalogCoordinate {
                name: if scala_library { "scala" } else { "kotlin" }.to_owned(),
                version: artifact
                    .coordinate
                    .as_ref()
                    .and_then(|coordinate| maven_coordinate_version(&coordinate.version)),
            }),
            target: Some("jvm".to_owned()),
            configuration: None,
            production_input_digest: None,
            verified_raw_artifacts: Vec::new(),
        },
        provenance,
        artifacts,
        scope: DependencyScope::Unknown,
        declared_by: None,
    }
}

/// The semver activation coordinate of the exact Maven version the resolver
/// selected. Maven versions are not semver (`2.6`, `32.1.2-jre`), so a strict
/// semver parse left every such row without a version and no version-ranged
/// workspace model could activate (#11371).
fn maven_coordinate_version(version: &str) -> Option<Version> {
    MavenVersion::parse(version)
        .ok()
        .and_then(|version| version.coordinate_version())
}

fn is_scala_library_coordinate(coordinate: &JvmMavenCoordinate) -> bool {
    coordinate.group_id == "org.scala-lang"
        && matches!(
            coordinate.artifact_id.as_str(),
            "scala-library" | "scala3-library_3"
        )
}

fn is_kotlin_stdlib_coordinate(coordinate: &JvmMavenCoordinate) -> bool {
    coordinate.group_id == "org.jetbrains.kotlin"
        && matches!(
            coordinate.artifact_id.as_str(),
            "kotlin-stdlib" | "kotlin-stdlib-common" | "kotlin-stdlib-jdk7" | "kotlin-stdlib-jdk8"
        )
}

fn jvm_dependency_origin_name(origin: JvmDependencyOrigin) -> &'static str {
    match origin {
        JvmDependencyOrigin::ExplicitPath => "explicit_path",
        JvmDependencyOrigin::MavenReport => "maven_report",
        JvmDependencyOrigin::GradleReport => "gradle_report",
        JvmDependencyOrigin::MavenRepository => "maven_repository",
        JvmDependencyOrigin::GradleCache => "gradle_cache",
    }
}

fn jvm_dependency_production_request(dependency: &ResolvedDependency) -> ArtifactProductionRequest {
    ArtifactProductionRequest {
        path: PathBuf::new(),
        artifact_kind: ExternalArtifactKind::JavaClassJar,
        pack_id: format!("bifrost.external.{}", dependency.evidence.language),
        pack_version: env!("CARGO_PKG_VERSION").to_owned(),
        ecosystem: dependency.evidence.ecosystem.clone(),
        compatibility: Compatibility {
            bifrost: None,
            toolchains: dependency
                .evidence
                .toolchain
                .as_ref()
                .map(
                    |coordinate| brokk_bifrost_analysis::analyzer::semantic_model::VersionConstraint {
                        name: coordinate.name.clone(),
                        requirement: coordinate
                            .version
                            .as_ref()
                            .map(|version| format!("={version}"))
                            .unwrap_or_else(|| "*".to_owned()),
                    },
                )
                .into_iter()
                .collect(),
        },
        activation: vec![
            brokk_bifrost_semantic::analyzer::semantic_model::dependency::activation_selector_for_evidence(&dependency.evidence),
        ],
        provenance: Provenance { rust_artifact_approximation: None,
            source: "exact local JVM dependency".to_owned(),
            revision: None,
        },
        license: "NOASSERTION".to_owned(),
        safety: Safety {
            generated_code_only: false,
            review_required: false,
        },
    }
}

fn merge_java_dependency_packs(
    source: Option<AuthoredSemanticModelPack>,
    binary: Option<AuthoredSemanticModelPack>,
    diagnostics: &mut Vec<ProducerDiagnostic>,
    suppressed_diagnostics: &mut SuppressedDiagnostics,
    limits: &ArtifactProducerLimits,
) -> Option<AuthoredSemanticModelPack> {
    let (mut pack, secondary) = match (source, binary) {
        (Some(source), binary) => (source, binary),
        (None, Some(binary)) => (binary, None),
        (None, None) => return None,
    };
    let Some(secondary) = secondary else {
        return Some(pack);
    };
    pack.schema_version = pack.schema_version.max(secondary.schema_version);
    let mut conflicting_finality = HashSet::default();
    let mut type_indexes = HashMap::<String, (usize, usize)>::default();
    let mut member_indexes = HashMap::<String, (usize, usize)>::default();
    let mut relation_ids = brokk_bifrost_core::hash::HashSet::<String>::default();
    let mut conflicting_scopes = brokk_bifrost_core::hash::HashSet::<String>::default();
    for (shard_index, shard) in pack.shards.iter().enumerate() {
        let AuthoredPayload::DeclarationFacts {
            types,
            members,
            relations,
            ..
        } = &shard.payload
        else {
            continue;
        };
        type_indexes.extend(
            types
                .iter()
                .enumerate()
                .map(|(fact_index, fact)| (fact.id.clone(), (shard_index, fact_index))),
        );
        member_indexes.extend(
            members
                .iter()
                .enumerate()
                .map(|(fact_index, fact)| (fact.id.clone(), (shard_index, fact_index))),
        );
        relation_ids.extend(relations.iter().map(|fact| fact.id.clone()));
    }
    for shard in secondary.shards {
        let AuthoredShard {
            id,
            activation,
            payload,
            runtime_values,
            runtime_contracts,
            collection_flows,
            deferred_yields,
            conditional_type_refinements,
            callable_values,
        } = shard;
        let (secondary_types, secondary_members, secondary_relations) = match payload {
            AuthoredPayload::DeclarationFacts {
                types,
                members,
                relations,
                ..
            } => (types, members, relations),
            payload => {
                if !pack.shards.iter().any(|shard| shard.id == id) {
                    pack.shards.push(AuthoredShard {
                        id,
                        activation,
                        payload,
                        runtime_values,
                        runtime_contracts,
                        collection_flows,
                        deferred_yields,
                        conditional_type_refinements,
                        callable_values,
                    });
                }
                continue;
            }
        };
        assert!(
            callable_values.is_none(),
            "JVM extraction cannot produce callable values"
        );
        assert!(
            runtime_contracts.is_none(),
            "JVM declaration extraction cannot produce portable runtime contracts"
        );
        let target_shard_index = pack
            .shards
            .iter()
            .position(|shard| shard.id == id)
            .unwrap_or_else(|| {
                let index = pack.shards.len();
                pack.shards.push(AuthoredShard {
                    id,
                    activation,
                    payload: AuthoredPayload::DeclarationFacts {
                        assembly_identity: None,
                        type_forwards: Vec::new(),
                        types: Vec::new(),
                        members: Vec::new(),
                        relations: Vec::new(),
                    },
                    runtime_values: None,
                    runtime_contracts: None,
                    collection_flows: None,
                    deferred_yields: None,
                    conditional_type_refinements: None,
                    callable_values: None,
                });
                index
            });
        if let Some(mut refinements) = conditional_type_refinements {
            pack.shards[target_shard_index]
                .conditional_type_refinements
                .get_or_insert_with(|| {
                    brokk_bifrost_analysis::analyzer::semantic_model::ConditionalTypeRefinementsPayload {
                        refinements: Vec::new(),
                    }
                })
                .refinements
                .append(&mut refinements.refinements);
        }
        for fact in secondary_types {
            if let Some((shard_index, fact_index)) = type_indexes.get(&fact.id).copied() {
                let AuthoredPayload::DeclarationFacts { types, .. } =
                    &mut pack.shards[shard_index].payload
                else {
                    unreachable!("Java fact indexes name declaration-fact shards")
                };
                if !equivalent_java_type_fact(&types[fact_index], &fact) {
                    push_java_merge_conflict(diagnostics, suppressed_diagnostics, limits, &fact.id);
                    conflicting_finality.insert(fact.id.clone());
                }
                // Only this already artifact-verified source/binary merge may
                // refine an unknown finality claim. Conflicting known claims
                // retain the existing diagnostic and withhold finality.
                types[fact_index].is_final = if conflicting_finality.contains(&fact.id) {
                    None
                } else {
                    types[fact_index].is_final.or(fact.is_final)
                };
                // The source declaration supplies location and documentation; the
                // binary inventory supplies reviewed scope and absence evidence.
                // An absent source inventory is not evidence of an empty scope.
                if let Some(inventory) = fact.jvm_inventory {
                    if types[fact_index]
                        .jvm_inventory
                        .as_ref()
                        .is_some_and(|source| source != &inventory)
                    {
                        push_java_merge_conflict(
                            diagnostics,
                            suppressed_diagnostics,
                            limits,
                            &fact.id,
                        );
                        conflicting_scopes.insert(fact.id.clone());
                    }
                    types[fact_index].jvm_inventory = Some(inventory);
                }
            } else {
                let AuthoredPayload::DeclarationFacts { types, .. } =
                    &mut pack.shards[target_shard_index].payload
                else {
                    unreachable!("Java merge targets a declaration-fact shard")
                };
                type_indexes.insert(fact.id.clone(), (target_shard_index, types.len()));
                types.push(fact);
            }
        }
        for mut fact in secondary_members {
            if let Some((shard_index, fact_index)) = member_indexes.get(&fact.id).copied() {
                let equivalent = {
                    let AuthoredPayload::DeclarationFacts { members, .. } =
                        &pack.shards[shard_index].payload
                    else {
                        unreachable!("Java fact indexes name declaration-fact shards")
                    };
                    equivalent_java_member_fact(&members[fact_index], &fact)
                };
                if !equivalent {
                    push_java_merge_conflict(diagnostics, suppressed_diagnostics, limits, &fact.id);
                } else {
                    let AuthoredPayload::DeclarationFacts { members, .. } =
                        &mut pack.shards[shard_index].payload
                    else {
                        unreachable!("Java fact indexes name declaration-fact shards")
                    };
                    members[fact_index].callable_family_complete |= fact.callable_family_complete;
                    // Attaching sources must not make known bounds unknown.
                    if let (Some(kept), Some(other)) =
                        (&mut members[fact_index].signature, &fact.signature)
                    {
                        if kept.bounds.is_none()
                            && kept.type_parameters == other.type_parameters
                            && other.bounds.is_some()
                        {
                            kept.bounds = other.bounds.clone();
                        } else if kept.bounds.is_some() && other.bounds.is_some() {
                            debug_assert_eq!(kept.bounds, other.bounds);
                        }
                    }
                }
            } else {
                if let Some((owner_shard, owner_index)) = type_indexes.get(&fact.owner).copied() {
                    let AuthoredPayload::DeclarationFacts { types, .. } =
                        &pack.shards[owner_shard].payload
                    else {
                        unreachable!("Java fact indexes name declaration-fact shards")
                    };
                    let owner = &types[owner_index];
                    let mut scope = owner.type_parameters.clone();
                    if let Some(inventory) = &owner.jvm_inventory {
                        scope.extend(inventory.enclosing_type_parameters.iter().cloned());
                    }
                    if let Some(signature) = &fact.signature {
                        scope.extend(signature.type_parameters.iter().cloned());
                        let covered = java_signature_scope_covered(signature, &scope);
                        if conflicting_scopes.contains(&fact.owner) || !covered {
                            push_java_merge_conflict(
                                diagnostics,
                                suppressed_diagnostics,
                                limits,
                                &fact.id,
                            );
                            fact.signature = None;
                            fact.callable_family_complete = false;
                        }
                        assert!(
                            fact.signature.is_none() || covered,
                            "binary-only Java member {} names a type parameter outside its owner scope {:?}",
                            fact.id,
                            scope
                        );
                    }
                }
                let AuthoredPayload::DeclarationFacts { members, .. } =
                    &mut pack.shards[target_shard_index].payload
                else {
                    unreachable!("Java merge targets a declaration-fact shard")
                };
                member_indexes.insert(fact.id.clone(), (target_shard_index, members.len()));
                members.push(fact);
            }
        }
        for fact in secondary_relations {
            if relation_ids.insert(fact.id.clone()) {
                let AuthoredPayload::DeclarationFacts { relations, .. } =
                    &mut pack.shards[target_shard_index].payload
                else {
                    unreachable!("Java merge targets a declaration-fact shard")
                };
                relations.push(fact);
            }
        }
    }
    // Bounds copied from binaries must use the retained owner's binder names.
    // The scope is the owner's own parameters plus, for a non-static nested
    // class, its enclosing classes' parameters, as the validator builds it.
    let owner_parameters: HashMap<_, _> = pack
        .shards
        .iter()
        .filter_map(|shard| match &shard.payload {
            AuthoredPayload::DeclarationFacts { types, .. } => Some(types),
            _ => None,
        })
        .flatten()
        .map(|owner| {
            let mut scope = owner.type_parameters.clone();
            if let Some(inventory) = &owner.jvm_inventory {
                scope.extend(inventory.enclosing_type_parameters.iter().cloned());
            }
            (owner.id.clone(), scope)
        })
        .collect();
    for shard in &mut pack.shards {
        if let AuthoredPayload::DeclarationFacts { types, members, .. } = &mut shard.payload {
            for member in members.iter_mut().chain(
                types
                    .iter_mut()
                    .filter_map(|owner| owner.jvm_inventory.as_mut())
                    .flat_map(|inventory| &mut inventory.additional_members),
            ) {
                if let Some(signature) = &mut member.signature {
                    let mut pending: Vec<_> = signature.bounds.iter().flatten().collect();
                    let mut references = Vec::new();
                    while let Some(bound) = pending.pop() {
                        references.extend([&bound.subject, &bound.bound.trait_type]);
                        references.extend(
                            bound
                                .bound
                                .associated_types
                                .iter()
                                .map(|binding| &binding.r#type),
                        );
                        pending.extend(&bound.bound.bounds);
                    }
                    let owner = owner_parameters
                        .get(&member.owner)
                        .expect("merged member has an owner");
                    if super::java_artifact::unresolved_type_variable(
                        references,
                        &[owner.as_slice(), signature.type_parameters.as_slice()],
                    )
                    .is_some()
                    {
                        signature.bounds = None;
                    }
                }
            }
        }
    }
    pack.schema_version =
        brokk_bifrost_semantic::analyzer::semantic_model::producer::required_schema_version(
            pack.schema_version,
            &pack.shards,
        );
    Some(pack)
}

fn java_signature_scope_covered(signature: &Signature, scope: &[String]) -> bool {
    let mut pending: Vec<&TypeRef> = signature
        .parameters
        .iter()
        .map(|parameter| &parameter.r#type)
        .collect();
    pending.extend(signature.returns.iter());
    while let Some(reference) = pending.pop() {
        match reference {
            TypeRef::TypeParameter { name } => {
                if !scope.contains(name) {
                    return false;
                }
            }
            TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } => {
                pending.extend(arguments)
            }
            TypeRef::Projection {
                owner,
                trait_type,
                arguments,
                ..
            } => {
                pending.push(owner);
                pending.extend(trait_type.iter().map(Box::as_ref));
                pending.extend(arguments);
            }
            TypeRef::Array { element }
            | TypeRef::ByRef { element, .. }
            | TypeRef::Pointer { element }
            | TypeRef::Slice { element }
            | TypeRef::FixedArray { element, .. }
            | TypeRef::Channel { element, .. } => pending.push(element),
            TypeRef::Map { key, value } => {
                pending.push(key);
                pending.push(value);
            }
            TypeRef::Wildcard { bound, .. } => pending.extend(bound.iter().map(Box::as_ref)),
            TypeRef::Tuple { elements } => pending.extend(elements),
            TypeRef::Function { parameters, result } => {
                pending.extend(parameters.iter().map(|parameter| &parameter.r#type));
                pending.extend(result.iter().map(Box::as_ref));
            }
            TypeRef::Unknown => {}
        }
    }
    true
}

fn equivalent_java_type_fact(left: &TypeFact, right: &TypeFact) -> bool {
    equivalent_java_type_identity(left, right)
        && !left
            .hierarchy
            .iter()
            .any(|edge| edge.target.contains_unknown())
        && !right
            .hierarchy
            .iter()
            .any(|edge| edge.target.contains_unknown())
        && left.hierarchy == right.hierarchy
        && left.aliases == right.aliases
        && left.extension_surfaces == right.extension_surfaces
}

fn equivalent_java_member_fact(left: &MemberFact, right: &MemberFact) -> bool {
    left.id == right.id
        && left.owner == right.owner
        && left.name == right.name
        && left.member_kind == right.member_kind
        && left.visibility == right.visibility
        && left.is_static == right.is_static
        && left.is_abstract == right.is_abstract
        && left.is_virtual == right.is_virtual
        && left.non_overridable == right.non_overridable
        && equivalent_java_signature(left.signature.as_ref(), right.signature.as_ref())
        && left.aliases == right.aliases
}

fn equivalent_java_signature(left: Option<&Signature>, right: Option<&Signature>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            if left.contains_unknown_types() || right.contains_unknown_types() {
                return false;
            }
            left.type_parameters.len() == right.type_parameters.len()
                && left.returns == right.returns
                && left.parameters.len() == right.parameters.len()
                && left
                    .parameters
                    .iter()
                    .zip(&right.parameters)
                    .all(|(left, right)| {
                        left.r#type == right.r#type && left.variadic == right.variadic
                    })
        }
        _ => false,
    }
}

fn push_java_merge_conflict(
    diagnostics: &mut Vec<ProducerDiagnostic>,
    suppressed_diagnostics: &mut SuppressedDiagnostics,
    limits: &ArtifactProducerLimits,
    declaration_id: &str,
) {
    if diagnostics.len() >= limits.max_diagnostics {
        suppressed_diagnostics.warnings = suppressed_diagnostics.warnings.saturating_add(1);
        return;
    }
    diagnostics.push(ProducerDiagnostic {
        severity: ProducerDiagnosticSeverity::Warning,
        source_entry: None,
        code: super::producer_codes::JAVA_SOURCE_BINARY_CONFLICT
            .code
            .to_owned(),
        location: Some(declaration_id.to_owned()),
        declaration: None,
        message: "source and binary facts disagree; deterministic source facts were kept"
            .to_owned(),
    });
}

/// Process-wide memo of built external declaration indexes, keyed by the
/// dependency-discovery evidence from [`external_index_memo_key`].
///
/// Entries are retained for the life of the process and never persisted. The
/// set of distinct dependency universes a process observes is small -- it
/// grows only when a dependency jar set actually changes -- and each retained
/// index is the bounded product of `build_from_artifacts`, so retention is the
/// same cost a long-lived server already pays through its analyzers'
/// `OnceLock` cells.
fn external_index_memo()
-> &'static Mutex<HashMap<ExternalIndexMemoKey, Arc<JvmExternalDeclarationIndex>>> {
    static MEMO: OnceLock<Mutex<HashMap<ExternalIndexMemoKey, Arc<JvmExternalDeclarationIndex>>>> =
        OnceLock::new();
    MEMO.get_or_init(|| Mutex::new(HashMap::default()))
}

/// The memo key: a digest of the artifact paths and discovery diagnostics,
/// plus the exact stat identity of every readable artifact file, in the order
/// the digest names them. The identities are compared exactly, not through a
/// hash, so two different files can never share a key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ExternalIndexMemoKey {
    evidence: StableDigest,
    identities: Vec<FileIdentity>,
}

/// Digest of everything [`JvmExternalDeclarationIndex::build_for_project`]'s
/// result is a function of, computed before any jar is classified.
///
/// That is the ordered resolved artifact files -- their paths plus the stat
/// identity (device, inode, size, mtime and ctime) that stands in for the
/// bytes behind each path -- and the resolution and JDK diagnostics the built
/// index appends verbatim. The classification diagnostics are not part of the
/// key: they are a pure function of the jar bytes the identities stand in for.
/// Coordinates, provenance, and scope are deliberately absent:
/// `build_from_artifacts` never reads them, so two discoveries that resolve
/// the same files must share one index.
///
/// `None` means no stat identity can stand in for some artifact's bytes: a
/// readable artifact is not a regular file, its mtime cannot be read, or its
/// identity is racy against the time before it was observed. The caller then
/// builds without the memo, because nothing would show that the bytes are
/// unchanged.
fn external_index_memo_key(
    declared: &DeclaredArtifacts,
    jdk: &JdkDiscovery,
    missing_membership: bool,
    platform_override: super::dependency_discovery::MavenPlatformOverride,
) -> Option<ExternalIndexMemoKey> {
    let diagnostics: Vec<IndexGap> = declared
        .diagnostics
        .iter()
        .chain(&jdk.diagnostics)
        .cloned()
        .map(IndexGap::from_discovery)
        .collect();
    // Taken before any identity is observed, never after, which would age a
    // racy identity into trust.
    let observed_at = std::time::SystemTime::now();
    let mut digest = LengthDelimitedDigest::new(JVM_EXTERNAL_INDEX_MEMO_DOMAIN);
    let mut identities = Vec::new();
    digest.push(&[platform_override.tag()]);
    // The index shape the bounded diagnostics and the dependency limit give it.
    digest.push(&[
        missing_membership as u8,
        declared.dependency_limit_hit as u8,
    ]);
    digest.push(&(declared.suppressed_diagnostics.warnings as u64).to_le_bytes());
    digest.push(&(declared.suppressed_diagnostics.errors as u64).to_le_bytes());
    digest.push(&(jdk.dependencies.len() as u64).to_le_bytes());
    digest.push(&(declared.artifacts.len() as u64).to_le_bytes());
    for artifact in &declared.artifacts {
        push_artifact_file_evidence(
            &mut digest,
            &mut identities,
            observed_at,
            &artifact.artifact_path,
        )?;
        match artifact.source_artifact_path.as_deref() {
            Some(path) => {
                push_artifact_file_evidence(&mut digest, &mut identities, observed_at, path)?
            }
            None => digest.push(b"no-sources"),
        }
    }
    digest.push(&(diagnostics.len() as u64).to_le_bytes());
    for diagnostic in &diagnostics {
        digest.push(match diagnostic.severity {
            ProducerDiagnosticSeverity::Warning => b"warning",
            ProducerDiagnosticSeverity::Error => b"error",
        });
        digest.push(diagnostic.code.as_bytes());
        push_optional_bytes(
            &mut digest,
            diagnostic.source_entry.as_deref().map(str::as_bytes),
        );
        push_optional_bytes(
            &mut digest,
            diagnostic.location.as_deref().map(str::as_bytes),
        );
        push_optional_bytes(
            &mut digest,
            diagnostic.declaration.as_deref().map(str::as_bytes),
        );
        digest.push(diagnostic.message.as_bytes());
        push_optional_bytes(&mut digest, diagnostic.dependency_id().map(str::as_bytes));
    }
    Some(ExternalIndexMemoKey {
        evidence: digest.finish(),
        identities,
    })
}

/// Push one artifact file's evidence: its path and, when the file is
/// readable, its stat identity, which stands in for its bytes. A missing or
/// unreadable file is its own evidence -- the index built from it records the
/// read failure, so it must not collide with a readable file at the same path.
/// Returns `None` when a readable file has no stat identity, or when that
/// identity is racy at `observed_at` (#13537).
fn push_artifact_file_evidence(
    digest: &mut LengthDelimitedDigest,
    identities: &mut Vec<FileIdentity>,
    observed_at: std::time::SystemTime,
    path: &Path,
) -> Option<()> {
    digest.push(path.as_os_str().as_encoded_bytes());
    let Ok(_) = fs::metadata(path) else {
        digest.push(b"unreadable");
        return Some(());
    };
    digest.push(b"identity");
    let identity = jvm_artifact_change_identity(path).ok()??;
    // Hard-won: #13107: racy artifact stat reused external_index_memo
    if identity.racy_at(
        observed_at,
        brokk_bifrost_core::content_digest::FILE_TIMESTAMP_GRANULARITY,
    ) {
        return None;
    }
    identities.push(identity);
    Some(())
}

#[allow(dead_code)] // Milestone 1 captures typed selection evidence for the later verifier.
#[derive(Debug, Clone)]
pub(super) enum ExternalSelectionFailure {
    Discovery,
    /// Dependencies the selection could not make complete. Each gap's cause
    /// says whether it is fixed for unchanged inputs.
    DependencyGaps(Vec<JvmDependencyGap>),
    /// The workspace file listing omitted these paths (workspace-relative
    /// where the listing supplies them), and each could hide a manifest
    /// ([`super::dependency_discovery::omission_could_hide_manifest`]). The
    /// reader binds through it as a gap that is never replayable.
    ListingOmitted {
        paths: Vec<PathBuf>,
    },
    /// A workspace manifest discovery could not read in full.
    PartialManifest(PathBuf),
    ArtifactRead(PathBuf),
    /// A resolution probe failed for a reason other than absence, so
    /// restoring access could change what resolution selects.
    UnreadableProbe(PathBuf),
}

#[cfg(test)]
impl ExternalSelectionFailure {
    /// The exhaustive match makes a new variant fail to compile until the
    /// replay table in `only_fixed_dependency_gaps_leave_a_selection_replayable`
    /// names it.
    pub(super) fn name(&self) -> &'static str {
        match self {
            Self::Discovery => "discovery",
            Self::DependencyGaps(_) => "dependency_gaps",
            Self::ListingOmitted { .. } => "listing_omitted",
            Self::PartialManifest(_) => "partial_manifest",
            Self::ArtifactRead(_) => "artifact_read",
            Self::UnreadableProbe(_) => "unreadable_probe",
        }
    }
}

/// Every reason a selection is not complete, in the order selection met
/// them: discovery, unresolved coordinates, partial manifests and unreadable
/// probes in input order, then artifact reads in artifact order, then the
/// artifact limit. The same inputs give the same order, so the answer digest
/// is stable.
#[derive(Debug, Default, Clone)]
pub(super) struct ExternalSelectionCompleteness {
    failures: Vec<ExternalSelectionFailure>,
}

impl ExternalSelectionCompleteness {
    pub(super) fn is_complete(&self) -> bool {
        self.failures.is_empty()
    }

    /// The gaps of a selection that is incomplete only for reasons a reader may
    /// bind through: dependency gaps, and a listing omission that could hide a
    /// manifest (carried as a gap no declared dependency owns). Any other
    /// failure, or no failure, gives `None`.
    pub(super) fn only_gaps(&self) -> Option<Vec<JvmDependencyGap>> {
        if self.failures.is_empty() {
            return None;
        }
        let mut gaps = Vec::new();
        for failure in &self.failures {
            match failure {
                ExternalSelectionFailure::DependencyGaps(items) => {
                    gaps.extend(items.iter().cloned())
                }
                ExternalSelectionFailure::ListingOmitted { paths } => {
                    gaps.push(JvmDependencyGap::listing_omitted(paths.clone()))
                }
                _ => return None,
            }
        }
        Some(gaps)
    }

    pub(super) fn record(&mut self, failure: ExternalSelectionFailure) {
        self.failures.push(failure);
    }

    #[cfg(test)]
    pub(super) fn failures(&self) -> &[ExternalSelectionFailure] {
        &self.failures
    }

    /// Whether the selection is incomplete only because a pack's fixed content
    /// is partial. PartialCoverage is deterministic for unchanged inputs, unlike
    /// a preparation failure, which may succeed on the next attempt.
    pub(super) fn only_partial_coverage(&self) -> bool {
        self.only_gaps().is_some_and(|gaps| {
            !gaps.is_empty()
                && gaps
                    .iter()
                    .all(|gap| gap.cause == JvmDependencyGapCause::PartialCoverage)
        })
    }

    /// Whether every reason for incompleteness is a gap that is fixed for
    /// unchanged inputs: a pack's partial coverage, a declared coordinate
    /// whose local artifact is absent.
    /// Such a selection is replayable. Any other failure may clear on the next
    /// attempt (an unreadable probe, a read, an omitted listing) or is not yet
    /// split by reason (#11252).
    pub(super) fn only_replayable_gaps(&self) -> bool {
        self.only_gaps().is_some_and(|gaps| {
            !gaps.is_empty()
                && gaps.iter().all(|gap| {
                    matches!(
                        gap.cause,
                        JvmDependencyGapCause::PartialCoverage
                            | JvmDependencyGapCause::Unresolved(_)
                    )
                })
        })
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(super) struct ExternalPathProbe {
    pub(super) path: PathBuf,
    pub(super) operation: ExternalProbeOperation,
    outcome: ExternalProbeOutcome,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
enum ExternalProbeOutcome {
    Found,
    Absent,
    Unreadable,
}

fn probe_operation_label(operation: ExternalProbeOperation) -> &'static str {
    match operation {
        ExternalProbeOperation::Canonicalize => "canonicalize",
        ExternalProbeOperation::List => "list",
        ExternalProbeOperation::File => "file",
    }
}

impl ExternalPathProbe {
    pub(super) fn is_absent(&self) -> bool {
        matches!(self.outcome, ExternalProbeOutcome::Absent)
    }

    fn hash_into(&self, hash: &mut CanonicalHasher) {
        let Self {
            path,
            operation,
            outcome,
        } = self;
        codec::path(hash, "path", path);
        codec::text(hash, "operation", probe_operation_label(*operation));
        codec::text(
            hash,
            "outcome",
            match outcome {
                ExternalProbeOutcome::Found => "found",
                ExternalProbeOutcome::Absent => "absent",
                ExternalProbeOutcome::Unreadable => "unreadable",
            },
        );
    }
}

fn record_external_probe(
    steps: &mut Vec<ExternalPathProbe>,
    path: &Path,
    operation: ExternalProbeOperation,
    result: &std::io::Result<impl Sized>,
) {
    let outcome = match result {
        Ok(_) => ExternalProbeOutcome::Found,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => ExternalProbeOutcome::Absent,
        Err(_) => ExternalProbeOutcome::Unreadable,
    };
    steps.push(ExternalPathProbe {
        path: path.to_path_buf(),
        operation,
        outcome,
    });
}

#[allow(dead_code)] // The query-owned transcript is consumed by the later verifier.
#[derive(Debug, Clone)]
pub(super) struct ExternalInputsConsumed {
    explicit_paths: Vec<PathBuf>,
    repository_roots: Vec<PathBuf>,
    pub(super) gradle_cache_roots: Vec<PathBuf>,
    home: Option<std::ffi::OsString>,
    userprofile: Option<std::ffi::OsString>,
    gradle_user_home: Option<std::ffi::OsString>,
    coordinates: Vec<JvmMavenCoordinate>,
    /// Workspace-relative manifests discovery could not read in full.
    partial_manifests: Vec<PathBuf>,
    pub(super) resolution_steps: Vec<ExternalPathProbe>,
    artifact_probes: Vec<PathBuf>,
}

impl ExternalInputsConsumed {
    /// Every field is destructured so a new field fails to compile until it is
    /// hashed or excluded here.
    ///
    /// Order. `explicit_paths`, the two root lists and `resolution_steps` keep
    /// their order: roots are searched first to last and the probes record that
    /// search. `artifact_probes` follows the selected dependency order, which
    /// `productions` also hashes in order. `coordinates` and
    /// `partial_manifests` are sets whose order discovery does not promise, so
    /// they are sorted by byte order.
    fn hash_into(&self, hash: &mut CanonicalHasher) {
        let Self {
            explicit_paths,
            repository_roots,
            gradle_cache_roots,
            home,
            userprofile,
            gradle_user_home,
            coordinates,
            partial_manifests,
            resolution_steps,
            artifact_probes,
        } = self;
        codec::paths(hash, "explicit_paths", explicit_paths);
        codec::paths(hash, "repository_roots", repository_roots);
        codec::paths(hash, "gradle_cache_roots", gradle_cache_roots);
        codec::optional_os(hash, "home", home);
        codec::optional_os(hash, "userprofile", userprofile);
        codec::optional_os(hash, "gradle_user_home", gradle_user_home);
        let mut sorted: Vec<&JvmMavenCoordinate> = coordinates.iter().collect();
        sorted.sort_unstable_by(|a, b| {
            (&a.group_id, &a.artifact_id, &a.version).cmp(&(
                &b.group_id,
                &b.artifact_id,
                &b.version,
            ))
        });
        hash.sequence("coordinates", &sorted, |hash, value| {
            let JvmMavenCoordinate {
                group_id,
                artifact_id,
                version,
            } = value;
            codec::text(hash, "group_id", group_id);
            codec::text(hash, "artifact_id", artifact_id);
            codec::text(hash, "version", version);
        });
        codec::sorted_paths(hash, "partial_manifests", partial_manifests);
        hash.sequence("resolution_steps", resolution_steps, |hash, value| {
            value.hash_into(hash)
        });
        codec::paths(hash, "artifact_probes", artifact_probes);
    }
}

/// What JDK discovery consulted, in order: `JAVA_HOME` when discovery reads
/// it, the candidate homes (with whether each was configured), and every
/// filesystem probe. They answer the separate JDK question, so they are not
/// part of the dependency record.
#[allow(dead_code)] // The query-owned transcript is consumed by the later verifier.
#[derive(Debug, Default)]
pub(super) struct JdkInputsConsumed {
    java_home: Option<OsString>,
    /// The process `PATH`, recorded when `JAVA_HOME` was unset and
    /// discovery looked for `java` there.
    path: Option<OsString>,
    /// The first runnable `java` found on `PATH`, before symlinks are
    /// followed. The home derived from it is in `candidates`.
    java_on_path: Option<PathBuf>,
    candidates: Vec<(PathBuf, bool)>,
    probes: Vec<ExternalPathProbe>,
    /// No home, JMOD or source-archive probe failed. False until JDK
    /// discovery finishes.
    pub(super) complete: bool,
}

impl JdkInputsConsumed {
    /// `candidates` keeps discovery's order: it is the order of the home
    /// de-duplication, so the first of two homes that canonicalize equal is
    /// the one whose dependencies the answer lists. The canonical homes
    /// themselves appear in `JdkDiscovery::dependencies` artifact paths.
    fn hash_into(&self, hash: &mut CanonicalHasher) {
        let Self {
            java_home,
            path,
            java_on_path,
            candidates,
            probes,
            complete,
        } = self;
        codec::optional_os(hash, "java_home", java_home);
        codec::optional_os(hash, "path", path);
        codec::optional_os(
            hash,
            "java_on_path",
            &java_on_path
                .as_ref()
                .map(|java| java.as_os_str().to_owned()),
        );
        hash.sequence("candidates", candidates, |hash, (path, configured)| {
            codec::path(hash, "home", path);
            codec::flag(hash, "configured", *configured);
        });
        hash.sequence("probes", probes, |hash, probe| probe.hash_into(hash));
        codec::flag(hash, "complete", *complete);
    }
}

/// What the manifests of `project` declare: the tree part of a dependency
/// selection (#11607). `None` when the declaration cannot be recorded as
/// coordinates alone: build tools run, a manifest was read only in part, or a
/// manifest names an artifact path, which resolves against the tree.
pub(crate) fn jvm_dependency_basis(
    config: &JvmAnalyzerConfig,
    project: &dyn Project,
) -> Option<brokk_bifrost_core::analyzer::external_selection::JvmDependencyBasis> {
    use brokk_bifrost_core::analyzer::external_selection::{
        JvmDependencyBasis, JvmDependencyBasisEntry,
    };
    let mode = config.dependency_discovery.mode;
    if mode == JvmDependencyDiscoveryMode::OfflineBuildTools {
        return None;
    }
    let mut dependencies = config.external_dependencies.clone();
    let mut declarations = brokk_bifrost_core::hash::HashMap::default();
    let mut platform_override = false;
    if mode != JvmDependencyDiscoveryMode::Disabled {
        let inputs = manifest_scope(project, config);
        let discovered = discover_metadata(&inputs);
        if !discovered.partial_manifests.is_empty() || !discovered.artifact_paths.is_empty() {
            return None;
        }
        declarations.clone_from(&discovered.declarations);
        discovered.merge_into(&mut dependencies);
        platform_override = match super::dependency_discovery::maven_platform_override(&inputs) {
            super::dependency_discovery::MavenPlatformOverride::Visible => true,
            super::dependency_discovery::MavenPlatformOverride::NotVisible => false,
            super::dependency_discovery::MavenPlatformOverride::Unknown => return None,
        };
    }
    let mut entries = dependencies
        .coordinates
        .iter()
        .map(|coordinate| {
            let declaration = declarations.get(coordinate);
            JvmDependencyBasisEntry {
                group_id: coordinate.group_id.clone(),
                artifact_id: coordinate.artifact_id.clone(),
                version: coordinate.version.clone(),
                scope: declaration
                    .map_or(DependencyScope::Unknown, |declaration| declaration.scope)
                    .label()
                    .to_owned(),
                declared_by: declaration.and_then(|declaration| declaration.declared_by.clone()),
            }
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        (
            &left.group_id,
            &left.artifact_id,
            &left.version,
            &left.declared_by,
        )
            .cmp(&(
                &right.group_id,
                &right.artifact_id,
                &right.version,
                &right.declared_by,
            ))
    });
    entries.dedup();
    Some(JvmDependencyBasis {
        entries,
        platform_override,
    })
}

/// The tree part of a dependency selection as the dependencies and declarations
/// that discovery would have produced from the manifests. `None` when the
/// recorded scope is unknown to this engine.
fn declared_dependencies_of_basis(
    config: &JvmAnalyzerConfig,
    basis: &brokk_bifrost_core::analyzer::external_selection::JvmDependencyBasis,
) -> Option<(
    JvmExternalDependencies,
    brokk_bifrost_core::hash::HashMap<
        JvmMavenCoordinate,
        super::dependency_discovery::JvmDependencyDeclaration,
    >,
)> {
    let mut discovered = super::dependency_discovery::DiscoveredJvmDependencies::default();
    for entry in &basis.entries {
        let coordinate = JvmMavenCoordinate::new(
            entry.group_id.clone(),
            entry.artifact_id.clone(),
            entry.version.clone(),
        );
        discovered.declarations.insert(
            coordinate.clone(),
            super::dependency_discovery::JvmDependencyDeclaration {
                scope: DependencyScope::from_label(&entry.scope)?,
                declared_by: entry.declared_by.clone(),
            },
        );
        discovered.coordinates.push(coordinate);
    }
    let declarations = discovered.declarations.clone();
    let mut dependencies = config.external_dependencies.clone();
    discovered.merge_into(&mut dependencies);
    Some((dependencies, declarations))
}

/// Every path probe that resolving the configured artifacts made, in order,
/// and which of them each coordinate's lookup made.
#[derive(Debug, Default)]
struct ResolutionTrace {
    steps: Vec<ExternalPathProbe>,
    /// The half-open range of `steps` recorded while looking for one
    /// coordinate, in coordinate order.
    coordinate_steps: Vec<(JvmMavenCoordinate, std::ops::Range<usize>)>,
}

/// The query-local sink that dependency discovery fills when its caller
/// records a selection.
#[derive(Debug, Default)]
struct DependencyDiscoveryTrace {
    coordinates: Vec<JvmMavenCoordinate>,
    partial_manifests: Vec<PathBuf>,
    explicit_paths: Vec<PathBuf>,
    resolution: ResolutionTrace,
    /// Whether dependency discovery completed without the dependency limit,
    /// an error other than an attributed unresolved coordinate, or a
    /// suppressed dependency diagnostic. False until discovery reaches that
    /// point, so a cancelled discovery leaves it incomplete.
    dependencies_discovered: bool,
    unresolved_coordinates: Vec<String>,
}

/// One selected artifact as the selection records it, after its capture has
/// been handed to the caller and dropped.
#[allow(dead_code)] // The query-owned transcript is consumed by the later verifier.
#[derive(Debug, Clone)]
struct SelectedExternalArtifactRecord {
    path: PathBuf,
    kind: ExternalArtifactKind,
    provider_id: String,
}

/// One selected artifact with its captured bytes. The selection hands each
/// capture to its caller as soon as it is read. The verified selection retains
/// only digest metadata and the production key after each capture.
pub(super) struct SelectedExternalArtifact {
    path: PathBuf,
    kind: ExternalArtifactKind,
    provider_id: String,
    exact: brokk_bifrost_semantic::analyzer::semantic_model::producer::ExactArtifact,
}

#[derive(Clone)]
struct SelectedProductionArtifact {
    role: DependencyArtifactRole,
    kind: ExternalArtifactKind,
    module: Option<String>,
    sha256: String,
}

#[derive(Clone)]
pub(super) struct ExternalInventorySelection {
    pub(super) preparation_failures: Vec<
        brokk_bifrost_semantic::analyzer::semantic_model::dependency::RecordedPreparationFailure,
    >,
    #[allow(dead_code)] // The query-owned transcript is consumed by the later verifier.
    artifacts: Vec<SelectedExternalArtifactRecord>,
    /// One slot per selected dependency, including dependencies without a
    /// producible pack. Exact captures are released after the key is minted.
    productions: Vec<(
        ResolvedDependency,
        Vec<SelectedProductionArtifact>,
        Option<brokk_bifrost_semantic::analyzer::semantic_model::catalog::GeneratedProductionKey>,
    )>,
    provider_ids: Vec<String>,
    #[allow(dead_code)] // The query-owned transcript is consumed by the later verifier.
    pub(super) inputs: ExternalInputsConsumed,
    #[allow(dead_code)] // The current index still uses its existing receipt.
    pub(super) completeness: ExternalSelectionCompleteness,
    /// Set when the activation's gaps were folded in at bind: the digest of the
    /// authority answer this selection was bound from. A later run recomputes
    /// the authority's digest, so a persisted read key names this one.
    pub(super) authority_answer_digest: Option<[u8; 32]>,
}

impl ExternalInventorySelection {
    #[cfg(test)]
    pub(super) fn empty_for_catalog_reader_test() -> Self {
        Self {
            preparation_failures: Vec::new(),
            artifacts: Vec::new(),
            productions: Vec::new(),
            provider_ids: Vec::new(),
            inputs: ExternalInputsConsumed {
                explicit_paths: Vec::new(),
                repository_roots: Vec::new(),
                gradle_cache_roots: Vec::new(),
                home: None,
                userprofile: None,
                gradle_user_home: None,
                coordinates: Vec::new(),
                partial_manifests: Vec::new(),
                resolution_steps: Vec::new(),
                artifact_probes: Vec::new(),
            },
            completeness: ExternalSelectionCompleteness::default(),
            authority_answer_digest: None,
        }
    }
    #[cfg(test)]
    pub(super) fn with_discovery_failure_for_catalog_reader_test(mut self) -> Self {
        self.completeness
            .record(ExternalSelectionFailure::Discovery);
        self
    }

    #[cfg(test)]
    pub(super) fn with_generated_key_for_catalog_reader_test(
        mut self,
        key: brokk_bifrost_semantic::analyzer::semantic_model::catalog::GeneratedProductionKey,
    ) -> Self {
        self.productions.push((
            ResolvedDependency::undeclared_scope(
                "test-provider".into(),
                brokk_bifrost_semantic::analyzer::semantic_model::runtime::SemanticModelActivationEvidence {
                    language: "java".into(), ecosystem: "maven".into(), package: None,
                    module: None, toolchain: None, target: None, configuration: None,
                    production_input_digest: None,
verified_raw_artifacts: Vec::new(),
                },
                Vec::new(), Vec::new(),
            ),
            Vec::new(), Some(key),
        ));
        self
    }
    // Failed dependencies expect no membership. Omitting the Dependency entry also
    // prevents the pinned reader from expanding it to an older installed provider.
    pub(super) fn catalog_expectations(
        &self,
    ) -> Vec<brokk_bifrost_analysis::analyzer::semantic_model::catalog::ExpectedCatalogEntry> {
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::ExpectedCatalogEntry;
        self.productions
            .iter()
            .filter(|(dependency, _, _)| {
                !self
                    .preparation_failures
                    .iter()
                    .any(|failure| failure.dependency == *dependency)
            })
            .map(|(dependency, _, key)| ExpectedCatalogEntry::Dependency {
                adapter: std::sync::Arc::new(JvmDependencyPackAdapter),
                dependency: Box::new(dependency.clone()),
                limits: DependencyPackLimits::default(),
                fallback: Box::new(match key {
                    Some(key) => ExpectedCatalogEntry::Production {
                        production_digest: key.production_digest.clone(),
                    },
                    None => ExpectedCatalogEntry::MissingProduction,
                }),
            })
            .collect()
    }

    #[allow(dead_code)] // Consumed by the request-owned catalog reader in P2.
    pub(super) fn generated_production_keys(
        &self,
    ) -> Vec<
        Option<brokk_bifrost_semantic::analyzer::semantic_model::catalog::GeneratedProductionKey>,
    > {
        self.productions
            .iter()
            .map(|(_, _, key)| key.clone())
            .collect()
    }

    /// The canonical digest of this answer, codec version in the domain. Every
    /// field of the selection is hashed or named as excluded below; the codec
    /// functions in `selection_codec` do the same for the nested types.
    pub(super) fn answer_digest(&self, complete: bool, certified: bool) -> [u8; 32] {
        self.answer_digest_in(codec::DEPENDENCIES_ANSWER_DOMAIN, complete, certified)
    }

    fn answer_digest_in(&self, domain: &[u8], complete: bool, certified: bool) -> [u8; 32] {
        let Self {
            preparation_failures,
            artifacts,
            productions,
            // The sorted, de-duplicated provider ids of `artifacts`, so a
            // function of a hashed field.
            provider_ids: _,
            inputs,
            completeness,
            // The digest of the answer before the bind folded gaps into this
            // one. It names another answer; it is not part of this one.
            authority_answer_digest: _,
        } = self;
        let mut hash = CanonicalHasher::new(domain);
        let mut failures: Vec<_> = preparation_failures.iter().collect();
        failures.sort_by(|a, b| a.dependency.id.cmp(&b.dependency.id));
        hash.sequence("preparation-failures", &failures, |hash, failure| {
            codec::resolved_dependency(hash, &failure.dependency);
            use brokk_bifrost_semantic::analyzer::semantic_model::dependency::{
                DependencyPreparationFailureCause, PreparationFailureInputs,
            };
            codec::text(
                hash,
                "cause",
                match failure.cause {
                    DependencyPreparationFailureCause::Rejected => "rejected",
                    DependencyPreparationFailureCause::PackUnavailable => "pack-unavailable",
                    DependencyPreparationFailureCause::ProducerFailed => "producer-failed",
                },
            );
            match &failure.inputs {
                PreparationFailureInputs::Bound(inputs) => {
                    codec::text(hash, "binding", "bound");
                    hash.sequence("inputs", inputs, |hash, (path, identity)| {
                        codec::path(hash, "path", path);
                        hash.field("metadata", &identity.digest());
                    });
                }
                PreparationFailureInputs::Unbound => codec::text(hash, "binding", "unbound"),
            }
        });
        codec::flag(&mut hash, "complete", complete);
        codec::flag(&mut hash, "certified", certified);
        let ExternalSelectionCompleteness { failures } = completeness;
        hash.sequence("failures", failures, |hash, failure| match failure {
            ExternalSelectionFailure::DependencyGaps(coordinates) => {
                codec::text(hash, "failure", "unresolved-coordinates");
                hash.sequence("coordinates", coordinates, |hash, coordinate| {
                    codec::text(hash, "coordinate", &coordinate.dependency_id);
                    codec::text(hash, "cause", coordinate.cause_label());
                    if let JvmDependencyGapCause::Unresolved(probes) = &coordinate.cause {
                        hash.sequence("absent_probes", probes, |hash, probe| {
                            codec::path(hash, "path", &probe.path);
                            codec::text(hash, "operation", probe_operation_label(probe.operation));
                        });
                    }
                });
            }
            ExternalSelectionFailure::ListingOmitted { paths } => {
                codec::text(hash, "failure", "listing_omitted");
                codec::sorted_paths(hash, "paths", paths);
            }
            ExternalSelectionFailure::Discovery => codec::text(hash, "failure", "discovery"),
            ExternalSelectionFailure::PartialManifest(path) => {
                codec::text(hash, "failure", "partial_manifest");
                codec::path(hash, "path", path);
            }
            ExternalSelectionFailure::ArtifactRead(path) => {
                codec::text(hash, "failure", "artifact_read");
                codec::path(hash, "path", path);
            }
            ExternalSelectionFailure::UnreadableProbe(path) => {
                codec::text(hash, "failure", "unreadable_probe");
                codec::path(hash, "path", path);
            }
        });
        inputs.hash_into(&mut hash);
        hash.sequence("artifacts", artifacts, |hash, artifact| {
            let SelectedExternalArtifactRecord {
                path,
                kind,
                provider_id,
            } = artifact;
            codec::path(hash, "path", path);
            codec::artifact_kind(hash, "kind", *kind);
            codec::text(hash, "provider_id", provider_id);
        });
        // The dependency order is part of the answer: catalog expectations and
        // generated production keys are indexed by it.
        hash.sequence(
            "productions",
            productions,
            |hash, (dependency, artifacts, key)| {
                codec::resolved_dependency(hash, dependency);
                hash.sequence("exact_artifacts", artifacts, |hash, artifact| {
                    let SelectedProductionArtifact {
                        role,
                        kind,
                        module,
                        sha256,
                    } = artifact;
                    codec::artifact_role(hash, "role", *role);
                    codec::artifact_kind(hash, "kind", *kind);
                    codec::optional_text(hash, "module", module.as_deref());
                    codec::text(hash, "sha256", sha256);
                });
                // The key folds the producer name, producer version and schema
                // version around the input digest, so hashing it all binds a
                // producer change that the dependency fields do not show.
                codec::flag(hash, "has_key", key.is_some());
                if let Some(key) = key {
                    codec::text(hash, "key_input_digest", key.input_digest());
                    codec::text(hash, "key_producer_name", key.producer_name());
                    codec::text(hash, "key_producer_version", key.producer_version());
                    hash.field("key_schema_version", &key.schema_version().to_be_bytes());
                }
            },
        );
        hash.finish()
    }
}

impl SelectedJdk {
    /// Whether every artifact of every selected JDK is pinned to the content
    /// digest selection computed. A JDK with no artifact (no `jmods` directory
    /// and no `src.zip`, each with its probe recorded) has nothing to pin: that
    /// negative answer is certified together with its probes.
    pub(super) fn every_artifact_pinned(&self) -> bool {
        self.dependencies.iter().all(|dependency| {
            dependency
                .artifacts
                .iter()
                .all(|artifact| artifact.expected_sha256.is_some())
        })
    }

    #[allow(dead_code)] // Consumed by the later pinned JVM reader routing slice.
    pub(super) fn catalog_expectations(
        &self,
    ) -> Vec<brokk_bifrost_analysis::analyzer::semantic_model::catalog::ExpectedCatalogEntry> {
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::ExpectedCatalogEntry;
        use brokk_bifrost_semantic::analyzer::semantic_model::dependency::{
            dependency_source_identity, pinned_generated_production_key,
        };

        let adapter = JvmDependencyPackAdapter;
        let producer = adapter.producer();
        let limits = DependencyPackLimits::default();
        self.dependencies
            .iter()
            .map(|dependency| {
                let fallback = (|| {
                    // A pinned dependency expects the production keyed by the
                    // digests it is pinned to, so a pack installed for other bytes
                    // never matches. One that capture cannot pin keeps the
                    // metadata identity.
                    if dependency.artifacts.is_empty()
                        || dependency
                            .artifacts
                            .iter()
                            .any(|artifact| artifact.expected_sha256.is_none())
                    {
                        return ExpectedCatalogEntry::SourceIdentity {
                            producer: producer.clone(),
                            source_identity: dependency_source_identity(
                                &adapter, dependency, &limits,
                            )
                            .map(|identity| identity.as_str().to_owned()),
                        };
                    }
                    match pinned_generated_production_key(&adapter, dependency, &limits)
                        .expect("a pinned JDK dependency has a valid production key")
                    {
                        Some(key) => ExpectedCatalogEntry::Production {
                            production_digest: key.production_digest,
                        },
                        None => ExpectedCatalogEntry::MissingProduction,
                    }
                })();
                ExpectedCatalogEntry::Dependency {
                    adapter: std::sync::Arc::new(JvmDependencyPackAdapter),
                    dependency: Box::new(dependency.clone()),
                    limits,
                    fallback: Box::new(fallback),
                }
            })
            .collect()
    }

    /// The canonical digest of the JDK answer. `certified` is bound as well
    /// (see `verify_jdk`), so a certified answer never equals an uncertified
    /// one over the same selection.
    pub(super) fn answer_digest(&self, complete: bool, certified: bool) -> [u8; 32] {
        self.answer_digest_in(codec::JDK_ANSWER_DOMAIN, complete, certified)
    }

    fn answer_digest_in(&self, domain: &[u8], complete: bool, certified: bool) -> [u8; 32] {
        let Self {
            inputs,
            dependencies,
        } = self;
        let mut hash = CanonicalHasher::new(domain);
        codec::flag(&mut hash, "complete", complete);
        codec::flag(&mut hash, "certified", certified);
        inputs.hash_into(&mut hash);
        // Discovery order is the candidate order after de-duplication.
        hash.sequence("dependencies", dependencies, codec::resolved_dependency);
        hash.finish()
    }
}

impl JvmExternalDeclarationIndex {
    #[cfg(test)]
    pub(super) fn add_discovery_gap_for_catalog_reader_test(
        &mut self,
        diagnostic: DependencyPackDiagnostic,
    ) {
        self.production_diagnostics
            .push(IndexGap::from_discovery(diagnostic));
    }

    #[cfg(test)]
    pub(crate) fn build(config: &JvmExternalDependencies, project_root: &Path) -> Self {
        let artifacts = resolve_configured_artifacts(config, project_root);
        Self::build_from_artifacts(artifacts)
    }

    /// Build the jar-backed external declaration surface the discovery
    /// evidence names, through a process-wide memo.
    ///
    /// Discovery itself runs on every call: it reads the project's build
    /// manifests, which are exactly what changes between workspaces. The
    /// expensive step -- reading and parsing every resolved dependency jar --
    /// is a pure function of the resolved artifact files and the discovery
    /// diagnostics that get appended to the result, so identical evidence
    /// (same artifact paths with the same length and mtime, same diagnostics)
    /// reuses the index already built by any analyzer in this process. A
    /// long-lived server always amortized this through each analyzer's
    /// `OnceLock`; the memo extends the same amortization to short-lived
    /// processes that rebuild workspaces over an unchanged dependency
    /// universe.
    pub(crate) fn build_for_project(
        config: &JvmAnalyzerConfig,
        project: &dyn Project,
    ) -> Arc<Self> {
        let artifacts = {
            let _timing = brokk_bifrost_core::profiling::scope("jvm_external_index.discovery");
            resolve_project_artifacts(
                config,
                project,
                &manifest_scope(project, config),
                &DependencyPackLimits::default(),
                None,
                None,
            )
        };
        let artifacts = match artifacts {
            Ok(artifacts) => artifacts,
            Err(_) => unreachable!("discovery without a cancellation token is never cancelled"),
        };
        // The Maven compiler configuration is read from the same build files
        // discovery reads. Gradle compile options are not read (#10492).
        let platform_override = if config.dependency_discovery.mode
            == JvmDependencyDiscoveryMode::Disabled
        {
            super::dependency_discovery::MavenPlatformOverride::NotVisible
        } else {
            super::dependency_discovery::maven_platform_override(&manifest_scope(project, config))
        };
        Self::build_from_declared(
            config,
            project.root(),
            artifacts.declared,
            &artifacts.declarations,
            artifacts.missing_membership,
            platform_override,
        )
    }

    /// The index the dependencies a recorded tree part declared produce in
    /// this environment, read from no manifest (#11607). `None` when the
    /// recorded scope is unknown to this engine.
    pub(crate) fn build_under_basis(
        config: &JvmAnalyzerConfig,
        project_root: &Path,
        basis: &brokk_bifrost_core::analyzer::external_selection::JvmDependencyBasis,
    ) -> Option<Arc<Self>> {
        let (dependencies, declarations) = declared_dependencies_of_basis(config, basis)?;
        let declared = match resolve_artifacts_declared(
            &dependencies,
            project_root,
            &DependencyPackLimits::default(),
            None,
            None,
        ) {
            Ok(declared) => declared,
            Err(_) => unreachable!("discovery without a cancellation token is never cancelled"),
        };
        Some(Self::build_from_declared(
            config,
            project_root,
            declared,
            &declarations,
            false,
            if basis.platform_override {
                super::dependency_discovery::MavenPlatformOverride::Visible
            } else {
                super::dependency_discovery::MavenPlatformOverride::NotVisible
            },
        ))
    }

    /// Look the index up by the resolved artifact files before any jar is
    /// classified. A hit skips classification and dependency assembly; JDK
    /// discovery still runs, because its diagnostics are part of the index
    /// and key the lookup, but it hashes nothing.
    fn build_from_declared(
        config: &JvmAnalyzerConfig,
        project_root: &Path,
        declared: DeclaredArtifacts,
        declarations: &brokk_bifrost_core::hash::HashMap<
            JvmMavenCoordinate,
            super::dependency_discovery::JvmDependencyDeclaration,
        >,
        missing_membership: bool,
        platform_override: super::dependency_discovery::MavenPlatformOverride,
    ) -> Arc<Self> {
        let jdk = discover_configured_jdk(config, project_root);
        let key = external_index_memo_key(&declared, &jdk, missing_membership, platform_override);
        let memo = external_index_memo();
        if let Some(key) = key.as_ref()
            && let Some(index) = memo.lock().expect("external index memo poisoned").get(key)
        {
            return Arc::clone(index);
        }
        let mut discovery = assemble_dependencies(
            declared,
            declarations,
            &DependencyPackLimits::default(),
            None,
            None,
            || jdk,
        );
        if missing_membership {
            append_generation_listing_unavailable(&mut discovery);
        }
        Self::build_from_discovery(discovery, platform_override, key)
    }

    fn build_from_discovery(
        discovery: DependencyDiscoveryOutcome,
        platform_override: super::dependency_discovery::MavenPlatformOverride,
        key: Option<ExternalIndexMemoKey>,
    ) -> Arc<Self> {
        let artifacts: Vec<ResolvedJvmArtifact> = discovery
            .dependencies
            .iter()
            .filter_map(jvm_artifact_from_dependency)
            .collect();
        let suppressed = discovery.suppressed_diagnostics.total();
        let mut diagnostics: Vec<IndexGap> = discovery
            .diagnostics
            .into_iter()
            .map(IndexGap::from_discovery)
            .collect();
        // Discovery bounds its diagnostic list, so with enough unresolved
        // coordinates the bound fills before a later error is seen. The count
        // survives; the entry stands for whatever it hid, and nothing can
        // attribute it, so no lookup skips it.
        if suppressed > 0 {
            diagnostics.push(
                ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    code: super::producer_codes::JVM_DISCOVERY_SUPPRESSED.code.to_owned(),
                    location: None,
                    source_entry: None,
                    declaration: None,
                    message: format!(
                        "dependency discovery suppressed {suppressed} diagnostics beyond its bound, so the index cannot say which dependencies they concern"
                    ),
                }
                .into(),
            );
        }
        let memo = external_index_memo();
        let _timing =
            brokk_bifrost_core::profiling::scope("jvm_external_index.build_from_artifacts");
        let mut index = Self::build_from_artifacts(artifacts);
        index.production_diagnostics.extend(diagnostics);
        index.platform_override = platform_override;
        let index = Arc::new(index);
        let Some(key) = key else {
            return index;
        };
        if index
            .production_diagnostics
            .iter()
            .any(|diagnostic| super::producer_codes::classify(diagnostic).is_execution_dependent())
        {
            return index;
        }
        Arc::clone(
            memo.lock()
                .expect("external index memo poisoned")
                .entry(key)
                .or_insert(index),
        )
    }

    /// Select once for inventory publication. Each artifact's bytes are
    /// captured once and handed to `visit` before the next artifact is read.
    /// Provider identity and production use the same capture. The returned
    /// selection retains ordered dependencies and exact artifacts for keys.
    pub(super) fn select_external_inventory<E>(
        config: &JvmAnalyzerConfig,
        project: &dyn Project,
        inputs: &dyn DiscoveryInputs,
        visit: impl FnMut(SelectedExternalArtifact) -> Result<(), E>,
    ) -> Result<ExternalInventorySelection, E> {
        let mut trace = DependencyDiscoveryTrace::default();
        let discovery = resolve_jvm_semantic_pack_dependencies_traced(
            config,
            project,
            inputs,
            &DependencyPackLimits::default(),
            None,
            Some(&mut trace),
        );
        Self::select_from_discovery(config, discovery, trace, visit)
    }

    /// The selection the dependencies a recorded tree part declared produce in
    /// this environment, read from no manifest (#11607).
    pub(super) fn select_under_basis<E>(
        config: &JvmAnalyzerConfig,
        project_root: &Path,
        basis: &brokk_bifrost_core::analyzer::external_selection::JvmDependencyBasis,
        visit: impl FnMut(SelectedExternalArtifact) -> Result<(), E>,
    ) -> Option<Result<ExternalInventorySelection, E>> {
        let (dependencies, declarations) = declared_dependencies_of_basis(config, basis)?;
        let mut trace = DependencyDiscoveryTrace::default();
        let discovery = resolve_declared_dependencies(
            config,
            project_root,
            dependencies,
            &declarations,
            &DependencyPackLimits::default(),
            None,
            Some(&mut trace),
        );
        Some(Self::select_from_discovery(config, discovery, trace, visit))
    }

    fn select_from_discovery<E>(
        config: &JvmAnalyzerConfig,
        discovery: DependencyDiscoveryOutcome,
        trace: DependencyDiscoveryTrace,
        mut visit: impl FnMut(SelectedExternalArtifact) -> Result<(), E>,
    ) -> Result<ExternalInventorySelection, E> {
        let DependencyDiscoveryTrace {
            coordinates,
            partial_manifests,
            explicit_paths,
            resolution:
                ResolutionTrace {
                    steps: resolution_steps,
                    coordinate_steps,
                },
            dependencies_discovered,
            unresolved_coordinates,
        } = trace;
        let mut inputs = ExternalInputsConsumed {
            explicit_paths,
            repository_roots: repository_roots(&config.external_dependencies),
            gradle_cache_roots: gradle_cache_roots(&config.external_dependencies),
            home: std::env::var_os("HOME"),
            userprofile: std::env::var_os("USERPROFILE"),
            gradle_user_home: std::env::var_os("GRADLE_USER_HOME"),
            coordinates,
            partial_manifests,
            resolution_steps,
            artifact_probes: Vec::new(),
        };
        let mut completeness = ExternalSelectionCompleteness::default();
        if !dependencies_discovered {
            completeness.record(ExternalSelectionFailure::Discovery);
        }
        if !unresolved_coordinates.is_empty() {
            // The absences each unresolved coordinate's lookup observed. Probes
            // that failed for another reason are separate unreadable-probe
            // failures below, which keep the selection from being replayed.
            let mut absent: brokk_bifrost_core::hash::HashMap<String, Vec<JvmAbsentProbe>> =
                Default::default();
            for (coordinate, steps) in &coordinate_steps {
                absent
                    .entry(jvm_coordinate_id(coordinate))
                    .or_default()
                    .extend(
                        inputs.resolution_steps[steps.clone()]
                            .iter()
                            .filter(|probe| probe.is_absent())
                            .map(|probe| JvmAbsentProbe {
                                path: probe.path.clone(),
                                operation: probe.operation,
                            }),
                    );
            }
            completeness.record(ExternalSelectionFailure::DependencyGaps(
                unresolved_coordinates
                    .into_iter()
                    .map(|id| {
                        let probes = absent.remove(&id).unwrap_or_default();
                        JvmDependencyGap::unresolved(id, probes)
                    })
                    .collect(),
            ));
        }
        for manifest in &inputs.partial_manifests {
            completeness.record(ExternalSelectionFailure::PartialManifest(manifest.clone()));
        }
        for probe in &inputs.resolution_steps {
            if matches!(probe.outcome, ExternalProbeOutcome::Unreadable) {
                completeness.record(ExternalSelectionFailure::UnreadableProbe(
                    probe.path.clone(),
                ));
            }
        }
        let limits = ArtifactProducerLimits::default();
        let pack_limits = DependencyPackLimits::default();
        let adapter = JvmDependencyPackAdapter;
        let mut artifacts = Vec::new();
        let mut productions = Vec::new();
        // Discovery already stops at `DependencyPackLimits::max_dependencies`,
        // the bound pack preparation applies, and reports itself incomplete
        // past it. A smaller bound here would leave packs that activation
        // activates outside the reader's selection, and the reader refuses
        // the whole JVM family over them (#13851).
        let selected = discovery.dependencies.iter().filter_map(|dependency| {
            jvm_artifact_from_dependency(dependency).map(|artifact| (dependency, artifact))
        });
        for (dependency, artifact) in selected {
            let mut exact_artifacts = Vec::new();
            for path in std::iter::once(artifact.artifact_path.as_path())
                .chain(artifact.source_artifact_path.as_deref())
            {
                inputs.artifact_probes.push(path.to_path_buf());
                match brokk_bifrost_semantic::analyzer::semantic_model::producer::read_exact_artifact(path, &limits) {
                    Ok(exact) => {
                        let resolved = dependency.artifacts.iter().find(|entry| entry.path() == path)
                            .expect("selected artifact must come from the resolved dependency");
                        exact_artifacts.push(ExactDependencyArtifact {
                            role: resolved.role, kind: resolved.kind,
                            module: resolved.module.clone(), artifact: exact.clone(),
                        });
                        let kind = if is_source_jar(path) { ExternalArtifactKind::JavaSourceJar } else { ExternalArtifactKind::JavaClassJar };
                        let provider_id = jvm_external_provider_id(exact.sha256());
                        artifacts.push(SelectedExternalArtifactRecord {
                            path: path.to_path_buf(),
                            kind,
                            provider_id: provider_id.clone(),
                        });
                        visit(SelectedExternalArtifact {
                            path: path.to_path_buf(),
                            kind,
                            provider_id,
                            exact,
                        })?;
                    }
                    Err(_) => {
                        completeness.record(ExternalSelectionFailure::ArtifactRead(path.to_path_buf()));
                    }
                }
            }
            exact_artifacts.sort_by_key(|exact: &ExactDependencyArtifact| {
                dependency
                    .artifacts
                    .iter()
                    .position(|resolved| resolved.path() == exact.path())
                    .expect("exact artifact must belong to the selected dependency")
            });
            let key = (adapter.can_produce(dependency)
                && exact_artifacts.len() == dependency.artifacts.len())
                .then(|| brokk_bifrost_semantic::analyzer::semantic_model::dependency::generated_production_key(
                    &adapter, dependency, &exact_artifacts, &pack_limits,
                ).ok())
                .flatten();
            let digests = exact_artifacts
                .iter()
                .map(|artifact| SelectedProductionArtifact {
                    role: artifact.role,
                    kind: artifact.kind,
                    module: artifact.module.clone(),
                    sha256: artifact.sha256().to_owned(),
                })
                .collect();
            productions.push((dependency.clone(), digests, key));
        }
        let mut provider_ids: Vec<_> = artifacts
            .iter()
            .map(|artifact| artifact.provider_id.clone())
            .collect();
        provider_ids.sort_unstable();
        provider_ids.dedup();
        Ok(ExternalInventorySelection {
            preparation_failures: Vec::new(),
            artifacts,
            productions,
            provider_ids,
            inputs,
            completeness,
            authority_answer_digest: None,
        })
    }

    /// The JDK question's selection: JDK discovery alone, which reads no
    /// workspace manifest, dependency artifact or build tool.
    #[cfg(test)]
    pub(super) fn select_jdk(
        config: &JvmAnalyzerConfig,
        project: &dyn Project,
        digests: &ContentDigestCache,
        cancellation: Option<&CancellationToken>,
    ) -> Result<SelectedJdk, ()> {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(());
        }
        let mut discovery = discover_configured_jdk(config, project.root());
        if pin_jdk_discovery(
            &mut discovery,
            digests,
            &DependencyPackLimits::default(),
            cancellation,
        )
        .is_break()
        {
            return Err(());
        }
        Ok(SelectedJdk {
            inputs: discovery.inputs,
            dependencies: discovery.dependencies,
        })
    }

    /// Direct artifact indexing publishes the same relational inventory before
    /// the name-grouped dispatch surface discards overload coordinates. Only
    /// bounded provider identities survive publication in the existing index.
    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
    pub(crate) fn build_for_project_with_inventory(
        config: &JvmAnalyzerConfig,
        project: &dyn Project,
        store: &brokk_bifrost_analysis::analyzer::store::AnalyzerStore,
        analyzer: &dyn brokk_bifrost_analysis::analyzer::IAnalyzer,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<Arc<Self>> {
        // Discovery publishes through an independent writer, so it cannot
        // share a read snapshot with its existence probes. Sample before all
        // probes and row reads: racing publication only causes another rebuild.
        let inventory_generation = store.jvm_external_inventory_generation()?;
        let mut sealed_providers = Vec::new();
        let limits = ArtifactProducerLimits::default();
        let selection = Self::select_external_inventory::<
            brokk_bifrost_analysis::analyzer::store::StoreError,
        >(
            config,
            project,
            &manifest_scope(project, config),
            |selected| {
                let path = selected.path.as_path();
                let kind = selected.kind;
                let exact = selected.exact;
                let provider = selected.provider_id;
                let exists: bool = store.read_conn()?.query_row(
                    "SELECT EXISTS(SELECT 1 FROM jvm_external_owners WHERE provider_id=?1)",
                    [&provider],
                    |row| row.get(0),
                )?;
                if !exists {
                    let request = ArtifactProductionRequest {
                        path: path.to_path_buf(),
                        artifact_kind: kind,
                        pack_id: "bifrost.external.java".to_owned(),
                        pack_version: env!("CARGO_PKG_VERSION").to_owned(),
                        ecosystem: "maven".to_owned(),
                        compatibility: Compatibility {
                            bifrost: None,
                            toolchains: Vec::new(),
                        },
                        activation: Vec::new(),
                        provenance: Provenance {
                            rust_artifact_approximation: None,
                            source: "local dependency artifact".to_owned(),
                            revision: None,
                        },
                        license: "NOASSERTION".to_owned(),
                        safety: Safety {
                            generated_code_only: false,
                            review_required: false,
                        },
                    };
                    let production = JavaJarPackProducer
                        .produce_loaded_artifact(&request, &limits, None, &exact);
                    if let Some(pack) = production.pack {
                        for shard in pack.shards {
                            if let AuthoredPayload::DeclarationFacts { types, members, .. } =
                                shard.payload
                            {
                                let outcome = store.publish_jvm_external_inventory_facts(
                                    exact.sha256().to_owned(),
                                    &types,
                                    &members,
                                    production.completeness
                                        == brokk_bifrost_analysis::analyzer::semantic_model::Completeness::Complete,
                                )?;
                                if outcome == brokk_bifrost_analysis::analyzer::store::jvm_external_inventory::JvmExternalInventoryWrite::Sealed {
                                sealed_providers.push(provider.clone());
                                break;
                            }
                            }
                        }
                    }
                }
                Ok(())
            },
        )?;
        let mut index = (*Self::build_for_project(config, project)).clone();
        // Discovery is request independent; certification happens at each use.
        index.inventory_providers = selection.provider_ids;
        index.inventory_generation = Some(inventory_generation);
        for provider in sealed_providers {
            index.production_diagnostics.push(
                ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    source_entry: None,
                    code: super::producer_codes::JVM_INVENTORY_SEALED.code.to_owned(),
                    location: None,
                    declaration: None,
                    message: format!(
                        "direct JVM inventory unavailable for sealed provider {provider}"
                    ),
                }
                .into(),
            );
        }
        // Direct publication is finished. Keep lookup receipts and the member
        // identities (including their owner uniqueness checks) in one snapshot:
        // a concurrent publication must never certify older member coordinates.
        let conn = store.read_conn()?;
        let snapshot = conn.unchecked_transaction()?;
        record_provider_inventory_reads(analyzer, &snapshot, &index.inventory_providers)?;
        let providers = serde_json::to_string(&index.inventory_providers)
            .expect("string provider identities serialize");
        let mut statement = snapshot.prepare("SELECT provider_id, owner_fqn, ordinal, member_name, is_static, json(parameters_jsonb) FROM jvm_external_owner_members member WHERE provider_id IN (SELECT value FROM json_each(?1)) AND member_kind IN ('method', 'constructor') AND (SELECT count(*) FROM jvm_external_owners owner WHERE owner.owner_fqn=member.owner_fqn AND owner.provider_id IN (SELECT value FROM json_each(?1)))=1 ORDER BY provider_id,owner_fqn,ordinal")?;
        let mut rows = statement.query([providers])?;
        while let Some(row) = rows.next()? {
            let owner: String = row.get(1)?;
            let member: String = row.get(3)?;
            let Some(family) = index
                .members_by_owner
                .get_mut(&owner)
                .and_then(|surface| surface.members.get_mut(&member))
            else {
                continue;
            };
            let parameters: Vec<brokk_bifrost_analysis::analyzer::semantic_model::Parameter> =
                serde_json::from_str(&row.get::<_, String>(5)?).map_err(|error| {
                    brokk_bifrost_analysis::analyzer::store::StoreError::new(error.to_string())
                })?;
            let is_static: bool = row.get(4)?;
            for shape in &mut family.call_shapes {
                if shape.is_static == is_static
                    && shape.parameters.len() == parameters.len()
                    && shape
                        .parameters
                        .iter()
                        .zip(&parameters)
                        .all(|(selected, formal)| *selected == formal.r#type)
                    && shape.variadic == parameters.iter().any(|formal| formal.variadic)
                {
                    let identity = brokk_bifrost_analysis::analyzer::resolution::fact_source::ExternalMemberIdentity {
                        owner: brokk_bifrost_analysis::analyzer::resolution::fact_source::ExternalOwnerIdentity {
                            provider_id: std::sync::Arc::from(row.get::<_, String>(0)?),
                            owner_fqn: std::sync::Arc::from(owner.as_str()),
                        },
                        ordinal: row.get(2)?,
                    };
                    // Conflicting provider coordinates cannot certify one
                    // selected member. The existing dispatch shape still works.
                    if shape
                        .inventory_identity
                        .as_ref()
                        .is_none_or(|old| *old == identity)
                    {
                        shape.inventory_identity = Some(identity);
                    } else {
                        shape.inventory_identity = None;
                    }
                }
            }
        }
        Ok(Arc::new(index))
    }

    fn build_from_artifacts(artifacts: Vec<ResolvedJvmArtifact>) -> Self {
        #[cfg(test)]
        EXTERNAL_INDEX_ARTIFACT_BUILDS.set(EXTERNAL_INDEX_ARTIFACT_BUILDS.get() + 1);

        let mut index = Self::default();
        let mut remaining_index_bytes = MAX_TOTAL_INDEX_BYTES;
        for artifact in artifacts.into_iter().take(MAX_INDEX_ARTIFACTS) {
            if remaining_index_bytes == 0 {
                break;
            }
            if is_source_jar(&artifact.artifact_path) {
                remaining_index_bytes = remaining_index_bytes.saturating_sub(
                    index.index_source_jar(&artifact.artifact_path, remaining_index_bytes),
                );
                continue;
            }
            if let Some(source_artifact_path) = artifact.source_artifact_path.as_deref() {
                remaining_index_bytes = remaining_index_bytes.saturating_sub(
                    index.index_source_jar(source_artifact_path, remaining_index_bytes),
                );
            }
            if remaining_index_bytes == 0 {
                break;
            }
            remaining_index_bytes = remaining_index_bytes.saturating_sub(
                index.index_class_jar(&artifact.artifact_path, remaining_index_bytes),
            );
        }
        index.apply_enclosing_visibility();
        index
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.types_by_fqn.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn production_diagnostics(&self) -> &[IndexGap] {
        &self.production_diagnostics
    }

    /// How many diagnostics the artifact producers raised while this index was
    /// built.
    ///
    /// A non-zero count means the build declared JVM artifacts that the index
    /// could not read to the end -- an archive past `MAX_ARCHIVE_ENTRIES`, a
    /// class past `MAX_CLASS_ENTRY_BYTES`, an artifact set past
    /// `MAX_INDEX_ARTIFACTS`. It is the difference between "this name is not
    /// declared anywhere" and "this name may well be declared in a dependency
    /// nothing finished indexing", which is exactly the boundary distinction a
    /// resolution trace must report. The full diagnostics stay test-only; a
    /// count is all a boundary classification needs.
    pub(crate) fn production_diagnostic_count(&self) -> usize {
        self.production_diagnostics.len()
    }

    /// Digest of the index's attributed diagnostics and the build model's platform
    /// override: everything that decides which lookups record a gap, and which.
    ///
    /// Each diagnostic contributes its code, severity, attribution, the
    /// coordinate of the declared dependency it concerns when it has one, and
    /// whether a lookup records it. The coordinate is hashed, not only the
    /// attribution: otherwise replacing one missing jar with another, with the
    /// index contents unchanged, would keep the identity, and a reused result
    /// would name the wrong jar. Artifact paths and messages are absent. The list
    /// is the one the lookups record from, so the identity and the recorded gaps
    /// cannot disagree.
    pub(crate) fn gap_identity(&self) -> StableDigest {
        let mut gaps = self.production_diagnostics.iter().collect::<Vec<_>>();
        gaps.sort_by_key(|gap| {
            (
                gap.code.as_str(),
                gap.dependency_id(),
                gap.attribution().tag(),
                matches!(gap.severity, ProducerDiagnosticSeverity::Error),
                gap.is_recorded(),
            )
        });
        let mut digest = LengthDelimitedDigest::new(JVM_EXTERNAL_GAP_IDENTITY_DOMAIN);
        digest.push(&[self.platform_override.tag()]);
        digest.push(&(gaps.len() as u64).to_le_bytes());
        for gap in gaps {
            gap.push_identity(&mut digest);
        }
        digest.finish()
    }

    /// Stable identity of every retained fact that can change external JVM
    /// dispatch behavior.
    ///
    /// Artifact paths and archive entry names are intentionally absent. Once
    /// an artifact has produced this surface, moving identical bytes does not
    /// change any resolver answer and should continue to reuse cached flow
    /// results. The attributed diagnostics enter through [`Self::gap_identity`]:
    /// two different missing sets with identical types differ, because a lookup
    /// that was complete under one must be partial under the other.
    /// Pure checksum of this immutable index, with no Project or analyzer reads.
    /// The selecting analyzer records external authority inputs even on hits.
    pub(crate) fn dispatch_behavior_identity(&self) -> StableDigest {
        *self.dispatch_behavior_identity.get_or_init(|| {
            let mut digest = LengthDelimitedDigest::new(JVM_EXTERNAL_DISPATCH_BEHAVIOR_DOMAIN);
            digest.push(self.gap_identity().as_bytes());

            let mut types = self.types_by_fqn.iter().collect::<Vec<_>>();
            types.sort_unstable_by_key(|(fqn, _)| *fqn);
            digest.push(&(types.len() as u64).to_le_bytes());
            for (lookup_fqn, external_type) in types {
                digest.push(b"type");
                digest.push(lookup_fqn.as_bytes());
                digest.push(external_type.fqn.as_bytes());
                digest.push(external_type.package_name.as_bytes());
                digest.push(external_type.short_name.as_bytes());
                digest.push(match external_type.kind {
                    JvmExternalTypeKind::Class => b"class",
                    JvmExternalTypeKind::Interface => b"interface",
                    JvmExternalTypeKind::Enum => b"enum",
                    JvmExternalTypeKind::Annotation => b"annotation",
                    JvmExternalTypeKind::Record => b"record",
                });
                digest.push(match external_type.visibility {
                    JvmVisibility::Public => b"public",
                    JvmVisibility::Protected => b"protected",
                    JvmVisibility::PackagePrivate => b"package-private",
                    JvmVisibility::Private => b"private",
                });
                // Class finality closes final-receiver dispatch (#10572); a
                // pack declaration's finality is keyed by the active model set.
                digest.push(match external_type.is_final {
                    None => b"final-unknown",
                    Some(false) => b"not-final",
                    Some(true) => b"final",
                });
            }

            let mut owners = self.members_by_owner.iter().collect::<Vec<_>>();
            owners.sort_unstable_by_key(|(owner, _)| *owner);
            digest.push(&(owners.len() as u64).to_le_bytes());
            for (owner_fqn, surface) in owners {
                digest.push(b"owner");
                digest.push(owner_fqn.as_bytes());
                digest.push(&[u8::from(surface.hierarchy_complete)]);
                digest.push(&(surface.supertypes.len() as u64).to_le_bytes());
                for supertype in &surface.supertypes {
                    digest.push(b"supertype");
                    digest.push(supertype.as_bytes());
                }
                // Java conversion reads the complete edge terms. Supertype names
                // would alias two jars that differ only in a type argument.
                digest.push(
                    &serde_json::to_vec(&surface.type_parameters)
                        .expect("type parameter names serialize"),
                );
                digest.push(
                    &serde_json::to_vec(&surface.hierarchy)
                        .expect("structured hierarchy edges serialize"),
                );

                let mut members = surface.members.iter().collect::<Vec<_>>();
                members.sort_unstable_by_key(|(name, _)| *name);
                digest.push(&(members.len() as u64).to_le_bytes());
                for (lookup_name, member) in members {
                    digest.push(b"member");
                    digest.push(lookup_name.as_bytes());
                    digest.push(member.fqn.as_bytes());
                    digest.push(member.declaring_package.as_bytes());
                    digest.push(match member.visibility {
                        JvmVisibility::Public => b"public",
                        JvmVisibility::Protected => b"protected",
                        JvmVisibility::PackagePrivate => b"package-private",
                        JvmVisibility::Private => b"private",
                    });
                    match member.declared_return_type_fqn() {
                        Some(return_type) => {
                            digest.push(b"named-return");
                            digest.push(return_type.as_bytes());
                        }
                        None => digest.push(b"no-named-return"),
                    }
                    digest.push(if member.is_static {
                        b"static"
                    } else {
                        b"instance"
                    });
                    digest.push(if member.is_constant {
                        b"constant"
                    } else {
                        b"not-constant"
                    });
                    digest.push(if member.call_shapes_incomplete {
                        b"shapes-incomplete"
                    } else {
                        b"shapes-complete"
                    });
                    digest.push(&(member.call_shapes.len() as u64).to_le_bytes());
                    for shape in &member.call_shapes {
                        digest.push(&shape.parameter_count.to_le_bytes());
                        digest.push(&[u8::from(shape.has_type_parameters)]);
                        digest.push(&[shape.visibility as u8]);
                        digest.push(&[u8::from(shape.non_overridable.is_some())]);
                        digest.push(&[u8::from(shape.is_abstract)]);
                        digest.push(if shape.is_static {
                            b"static-shape"
                        } else {
                            b"instance-shape"
                        });
                        digest.push(if shape.variadic {
                            b"variadic"
                        } else {
                            b"fixed"
                        });
                        // Argument conversion consumes the complete return term,
                        // including arrays and generic arguments. A class-name
                        // digest would alias distinct conversion behavior.
                        digest.push(
                            &serde_json::to_vec(&shape.returns)
                                .expect("structured return types serialize"),
                        );
                    }
                }
            }
            digest.finish()
        })
    }

    pub(crate) fn get(&self, fqn: &str) -> Option<&JvmExternalType> {
        self.types_by_fqn.get(fqn)
    }

    /// The member `member_name` names on the indexed owner `owner_fqn`,
    /// searched over the owner's whole read inherited surface (#1900).
    ///
    /// The walk starts at the owner and follows the supertypes its own artifact
    /// entry named, breadth first, because a JVM member is as often inherited
    /// as declared: a static factory sits on the class the reference wrote
    /// while an accessor sits on the base class it extends, and a reference
    /// spells both the same way. The declaration that answers keeps its own
    /// qualified name and its own declaring package, so the reported target
    /// names where the member is declared rather than where it was written,
    /// and package-private accessibility measures against the right package.
    ///
    /// An owner with no read surface, and a supertype whose own class file was
    /// never read, both contribute nothing rather than proving anything: this
    /// returns `None` for "not declared here" and for "never read" alike, and a
    /// caller that finds nothing keeps the status it had.
    fn member(
        &self,
        owner_fqn: &str,
        member_name: &str,
    ) -> (Option<&JvmExternalMember>, OwnerWalkCompletion) {
        let walk = self.walk_owner_surfaces(
            owner_fqn,
            |surface| surface.supertypes.iter().map(String::as_str).collect(),
            |_, surface| surface.members.get(member_name),
        );
        (walk.selected.map(|(member, _)| member), walk.completion)
    }

    /// Walk the read surfaces breadth first from `owner_fqn`, following the
    /// supertypes `parents` names, until `select` answers.
    fn walk_owner_surfaces<'a, T>(
        &'a self,
        owner_fqn: &str,
        parents: impl Fn(&'a JvmIndexedOwnerSurface) -> Vec<&'a str>,
        mut select: impl FnMut(&str, &'a JvmIndexedOwnerSurface) -> Option<T>,
    ) -> OwnerSurfaceWalk<T> {
        let mut walk = OwnerSurfaceWalk {
            selected: None,
            completion: OwnerWalkCompletion::Complete,
            unread: Vec::new(),
        };
        let mut visited = brokk_bifrost_core::hash::HashSet::default();
        let mut queue =
            std::collections::VecDeque::from([(owner_fqn.to_owned(), Vec::<String>::new())]);
        while let Some((owner, mut path)) = queue.pop_front() {
            if path.contains(&owner) {
                walk.completion = OwnerWalkCompletion::Cycle;
                continue;
            }
            if !visited.insert(owner.clone()) {
                continue;
            }
            if visited.len() > MAX_MEMBER_SURFACE_OWNERS {
                walk.completion = OwnerWalkCompletion::FixedLimit;
                return walk;
            }
            path.push(owner);
            let owner = path.last().expect("the owner was just pushed");
            let Some(surface) = self.members_by_owner.get(owner) else {
                walk.unread.push(path);
                continue;
            };
            if !surface.hierarchy_complete {
                walk.completion = OwnerWalkCompletion::IncompleteHierarchy;
            }
            if let Some(selected) = select(owner, surface) {
                walk.selected = Some((selected, path));
                return walk;
            }
            queue.extend(
                parents(surface)
                    .into_iter()
                    .map(|parent| (parent.to_owned(), path.clone())),
            );
        }
        walk
    }

    pub(crate) fn resolve_explicit_import(
        &self,
        import_path: &str,
        access_package: &str,
    ) -> Option<&JvmExternalType> {
        self.resolve_qualified_name(import_path, access_package)
    }

    pub(crate) fn resolve_wildcard_import(
        &self,
        package_name: &str,
        short_name: &str,
        access_package: &str,
    ) -> Option<&JvmExternalType> {
        self.resolve_qualified_name(&qualified_name(package_name, short_name), access_package)
    }

    pub(crate) fn resolve_same_package(
        &self,
        package_name: &str,
        short_name: &str,
    ) -> Option<&JvmExternalType> {
        self.resolve_qualified_name(&qualified_name(package_name, short_name), package_name)
    }

    pub(crate) fn resolve_qualified_name(
        &self,
        fqn: &str,
        access_package: &str,
    ) -> Option<&JvmExternalType> {
        self.get(fqn)
            .filter(|ty| ty.is_accessible_from_package(access_package))
    }

    fn insert(&mut self, external_type: JvmExternalType) {
        match self.types_by_fqn.get(&external_type.fqn) {
            Some(existing)
                if matches!(
                    existing.source,
                    JvmExternalDeclarationSource::SourceJar { .. }
                ) =>
            {
                return;
            }
            _ => {}
        }
        self.types_by_fqn
            .insert(external_type.fqn.clone(), external_type);
    }

    fn apply_enclosing_visibility(&mut self) {
        let updates: Vec<_> = self
            .types_by_fqn
            .values()
            .filter_map(|external_type| {
                let mut effective_visibility = external_type.visibility;
                for owner_fqn in enclosing_type_fqns(external_type) {
                    let Some(owner) = self.types_by_fqn.get(&owner_fqn) else {
                        continue;
                    };
                    effective_visibility =
                        restrict_visibility(effective_visibility, owner.visibility);
                }
                (effective_visibility != external_type.visibility)
                    .then(|| (external_type.fqn.clone(), effective_visibility))
            })
            .collect();

        for (fqn, visibility) in updates {
            if let Some(external_type) = self.types_by_fqn.get_mut(&fqn) {
                external_type.visibility = visibility;
            }
        }
    }

    fn index_source_jar(&mut self, artifact_path: &Path, index_byte_budget: u64) -> u64 {
        let Some(file) = open_artifact_file(artifact_path) else {
            return 0;
        };
        let Ok(mut archive) = ZipArchive::new(file) else {
            return 0;
        };
        let entry_count = archive.len().min(MAX_ARCHIVE_ENTRIES);
        let mut total_bytes = 0u64;
        let mut java_facts = None;
        let mut scala_indexed = false;
        let mut skipped_entries = 0usize;
        if archive.len() > entry_count {
            self.note_entry_cap(
                artifact_path,
                "MAX_ARCHIVE_ENTRIES",
                MAX_ARCHIVE_ENTRIES as u64,
                super::producer_codes::JVM_INDEX_CAPPED_ENTRIES,
            );
        }
        let mut member_budget = MemberBudget::new();
        for index in 0..entry_count {
            let Ok(entry) = archive.by_index(index) else {
                skipped_entries = skipped_entries.saturating_add(1);
                continue;
            };
            let name = match entry.name() {
                Ok(name) => name,
                Err(_) => {
                    skipped_entries = skipped_entries.saturating_add(1);
                    continue;
                }
            };
            let Some(language) = SourceJarLanguage::for_entry(name.as_ref()) else {
                continue;
            };
            let max_entry_bytes = language.max_entry_bytes();
            if !can_read_entry(
                entry.size(),
                max_entry_bytes,
                MAX_TOTAL_ARCHIVE_BYTES.min(index_byte_budget),
                &mut total_bytes,
            ) {
                let (name, limit, code) = if entry.size() > max_entry_bytes {
                    (
                        "max_entry_bytes",
                        max_entry_bytes,
                        super::producer_codes::JVM_INDEX_CAPPED_ENTRIES,
                    )
                } else if index_byte_budget < MAX_TOTAL_ARCHIVE_BYTES {
                    (
                        "MAX_TOTAL_INDEX_BYTES (remaining)",
                        index_byte_budget,
                        super::producer_codes::JVM_INDEX_BUDGET,
                    )
                } else {
                    (
                        "MAX_TOTAL_ARCHIVE_BYTES",
                        MAX_TOTAL_ARCHIVE_BYTES,
                        super::producer_codes::JVM_INDEX_CAPPED_ENTRIES,
                    )
                };
                self.note_entry_cap(artifact_path, name, limit, code);
                continue;
            }
            if matches!(language, SourceJarLanguage::Scala) {
                if !scala_indexed {
                    let mut facts = self
                        .produce_scala_type_facts(artifact_path)
                        .into_values()
                        .collect::<Vec<_>>();
                    facts.sort_unstable_by(|left, right| left.name.cmp(&right.name));
                    for fact in facts.into_iter().take(MAX_ANALYZER_SOURCE_TYPES) {
                        if let Some(external_type) = scala_external_type(artifact_path, fact) {
                            self.insert(external_type);
                        }
                    }
                    scala_indexed = true;
                }
                continue;
            }
            let source_path = name.into_owned();
            let mut source = String::new();
            if entry
                .take(max_entry_bytes + 1)
                .read_to_string(&mut source)
                .is_err()
            {
                skipped_entries = skipped_entries.saturating_add(1);
                continue;
            }
            if source.len() as u64 > max_entry_bytes {
                self.note_entry_cap(
                    artifact_path,
                    "max_entry_bytes",
                    max_entry_bytes,
                    super::producer_codes::JVM_INDEX_CAPPED_ENTRIES,
                );
                continue;
            }
            let external_types = language.source_types(artifact_path, &source_path, &source);
            if matches!(language, SourceJarLanguage::Java) && java_facts.is_none() {
                java_facts = Some(
                    self.produce_java_facts(artifact_path, ExternalArtifactKind::JavaSourceJar),
                );
            }
            for mut external_type in external_types {
                if let Some(facts) = java_facts.as_mut() {
                    if let Some(fact) = facts.types.get(&external_type.fqn) {
                        apply_java_type_fact(&mut external_type, fact);
                    }
                    // The entry that declares this type was read to the end, so
                    // its member surface may answer.
                    let surface = facts.take_owner_surface(
                        &external_type.fqn,
                        &external_type.package_name,
                        &mut member_budget,
                    );
                    self.attach_member_surface(&external_type.fqn, surface);
                }
                self.insert(external_type);
            }
        }
        self.note_bounded_artifact(artifact_path, skipped_entries, member_budget);
        total_bytes
    }

    fn index_class_jar(&mut self, artifact_path: &Path, index_byte_budget: u64) -> u64 {
        let Some(file) = open_artifact_file(artifact_path) else {
            return 0;
        };
        let mut enclosing_scopes = super::java_artifact::EnclosingScopeResolver::default();
        let Ok(mut archive) = ZipArchive::new(file) else {
            return 0;
        };
        let entry_count = archive.len().min(MAX_ARCHIVE_ENTRIES);
        let mut total_bytes = 0u64;
        let mut skipped_entries = 0usize;
        if archive.len() > entry_count {
            self.note_entry_cap(
                artifact_path,
                "MAX_ARCHIVE_ENTRIES",
                MAX_ARCHIVE_ENTRIES as u64,
                super::producer_codes::JVM_INDEX_CAPPED_ENTRIES,
            );
        }
        let mut member_budget = MemberBudget::new();
        let producer_limits = ArtifactProducerLimits::default();
        let mut producer_diagnostics = brokk_bifrost_semantic::analyzer::semantic_model::producer::BoundedProducerDiagnostics::new(&producer_limits);
        let mut remaining_records = producer_limits.max_records;
        let mut record_limit_hit = false;
        for index in 0..entry_count {
            let Ok(entry) = archive.by_index(index) else {
                skipped_entries = skipped_entries.saturating_add(1);
                continue;
            };
            let name = match entry.name() {
                Ok(name) => name,
                Err(_) => {
                    skipped_entries = skipped_entries.saturating_add(1);
                    continue;
                }
            };
            if !name.ends_with(".class") || name.ends_with("module-info.class") {
                continue;
            }
            if !can_read_entry(
                entry.size(),
                MAX_CLASS_ENTRY_BYTES,
                MAX_TOTAL_ARCHIVE_BYTES.min(index_byte_budget),
                &mut total_bytes,
            ) {
                let (name, limit, code) = if entry.size() > MAX_CLASS_ENTRY_BYTES {
                    (
                        "MAX_CLASS_ENTRY_BYTES",
                        MAX_CLASS_ENTRY_BYTES,
                        super::producer_codes::JVM_INDEX_CAPPED_ENTRIES,
                    )
                } else if index_byte_budget < MAX_TOTAL_ARCHIVE_BYTES {
                    (
                        "MAX_TOTAL_INDEX_BYTES (remaining)",
                        index_byte_budget,
                        super::producer_codes::JVM_INDEX_BUDGET,
                    )
                } else {
                    (
                        "MAX_TOTAL_ARCHIVE_BYTES",
                        MAX_TOTAL_ARCHIVE_BYTES,
                        super::producer_codes::JVM_INDEX_CAPPED_ENTRIES,
                    )
                };
                self.note_entry_cap(artifact_path, name, limit, code);
                continue;
            }
            let class_entry = name.into_owned();
            let mut bytes = Vec::new();
            if entry
                .take(MAX_CLASS_ENTRY_BYTES + 1)
                .read_to_end(&mut bytes)
                .is_err()
            {
                skipped_entries = skipped_entries.saturating_add(1);
                continue;
            }
            if bytes.len() as u64 > MAX_CLASS_ENTRY_BYTES {
                self.note_entry_cap(
                    artifact_path,
                    "MAX_CLASS_ENTRY_BYTES",
                    MAX_CLASS_ENTRY_BYTES,
                    super::producer_codes::JVM_INDEX_CAPPED_ENTRIES,
                );
                continue;
            }
            let surface = match class_surface(
                artifact_path.to_string_lossy().as_ref(),
                &class_entry,
                &bytes,
                &mut |outer| {
                    enclosing_scopes.parameters(
                        outer,
                        &mut archive,
                        "",
                        producer_limits.max_signature_depth,
                    )
                },
                producer_limits.max_signature_depth,
                &mut remaining_records,
                &mut record_limit_hit,
                &mut producer_diagnostics,
            ) {
                JavaClassSurfaceOutcome::Declared(surface) => surface,
                // A module descriptor and a private class were read
                // completely; the index publishes neither on purpose, and
                // neither leaves anything unread.
                JavaClassSurfaceOutcome::Excluded => continue,
                // The producer could not parse this class file, so it declares
                // no type here and, just as importantly, no member surface that
                // could later answer a member spelling negatively.
                JavaClassSurfaceOutcome::Invalid => {
                    producer_diagnostics.warning(
                        super::producer_codes::JAVA_CLASS_INVALID.code,
                        Some(class_entry.clone()),
                        "class entry did not contain supported bounded metadata",
                    );
                    // java.class.invalid already records this stable content gap.
                    continue;
                }
                // The bounded producer record limit was spent. It is reported
                // below as `limit.records`; do not misclassify an intentional
                // bound as an unread archive entry.
                JavaClassSurfaceOutcome::Skipped => continue,
            };

            let short_name = surface
                .name
                .strip_prefix(&format!("{}.", surface.package_name))
                .unwrap_or(&surface.name)
                .to_owned();
            let external_type = JvmExternalType {
                fqn: surface.name.clone(),
                package_name: surface.package_name.clone(),
                short_name,
                kind: semantic_type_kind(surface.type_kind),
                visibility: semantic_visibility(surface.visibility),
                is_final: surface.is_final,
                source: JvmExternalDeclarationSource::ClassFile {
                    artifact_path: artifact_path.to_path_buf(),
                    class_entry: class_entry.clone(),
                },
            };
            if external_type.visibility == JvmVisibility::Private {
                continue;
            }
            // This entry was read to the end and parsed, so the members the
            // same class file declares are a surface that may answer (#1900).
            let mut members = HashMap::default();
            for member in surface.members {
                // The durable inventory owns all declarations. Preserve this
                // legacy public dispatch projection before grouping overloads.
                if !matches!(
                    member.visibility,
                    Visibility::Public | Visibility::Protected
                ) {
                    continue;
                }
                if !member_budget.take() {
                    break;
                }
                let is_static = member.is_static;
                let is_constant = member.member_kind == MemberKind::Constant;
                let shape = external_call_shape(
                    member.member_kind,
                    semantic_visibility(member.visibility),
                    is_static,
                    member.signature.as_ref(),
                    member.is_abstract,
                    member.non_overridable,
                );
                let shapes_incomplete = callable_shape_is_incomplete(
                    member.member_kind,
                    member.signature.as_ref(),
                    member.callable_family_complete,
                    shape.is_some(),
                );
                retain_external_member(
                    &mut members,
                    &external_type.fqn,
                    &external_type.package_name,
                    RetainedExternalMember {
                        name: member.name,
                        visibility: semantic_visibility(member.visibility),
                        // The class file's member table is what types a chained
                        // receiver (#2454), so this path carries the declared
                        // return type exactly as `take_owner_surface` does for
                        // the pack-production path. Dropping it here made the
                        // same jar answer `response.getWriter()` on one path and
                        // not on the other, which measurably retired the whole
                        // chained-receiver census on the OWASP corpus.
                        returns: member.returns,
                        // The class file's access flags are what prove a
                        // `static final` field is a compile-time constant
                        // (#2538); dropping them here would make the same
                        // class file answer a `Cipher.ENCRYPT_MODE`-shaped
                        // read on the pack-production path and not on this
                        // one, the same asymmetry #2454's comment above
                        // describes for return types.
                        is_static,
                        is_constant,
                        shape,
                        shapes_incomplete,
                    },
                );
            }
            if member_budget.exhausted {
                mark_call_shapes_incomplete(&mut members);
            }
            self.attach_member_surface(
                &external_type.fqn,
                JvmIndexedOwnerSurface {
                    members,
                    // As above: the inventory, or a source jar's declared edges.
                    supertypes: match &surface.jvm_inventory {
                        Some(inventory) => hierarchy_type_names(&inventory.supertypes),
                        None => hierarchy_type_names(&surface.hierarchy),
                    },
                    hierarchy: inventory_hierarchy(
                        &surface.hierarchy,
                        surface.jvm_inventory.as_deref(),
                    ),
                    type_parameters: Some(surface.type_parameters),
                    hierarchy_complete: surface
                        .jvm_inventory
                        .as_ref()
                        .is_some_and(|inventory| inventory.supertypes_complete),
                },
            );
            self.insert(external_type);
        }
        enclosing_scopes.report_unread(
            &mut producer_diagnostics,
            None,
            super::producer_codes::JAVA_ARCHIVE_ENTRY_READ.code,
        );
        if record_limit_hit {
            producer_diagnostics.warning(
                super::producer_codes::LIMIT_RECORDS.code,
                None,
                format!(
                    "producer stopped after {} declaration records",
                    producer_limits.max_records
                ),
            );
        }
        let (diagnostics, _) = producer_diagnostics.finish();
        self.production_diagnostics
            .extend(diagnostics.into_iter().map(IndexGap::from));
        self.note_bounded_artifact(artifact_path, skipped_entries, member_budget);
        total_bytes
    }

    /// Record the member surface an owner's own artifact entry declared.
    ///
    /// Only ever called for an owner whose entry was read to the end, which is
    /// what gives the presence of an entry in `members_by_owner` its meaning.
    fn attach_member_surface(&mut self, owner_fqn: &str, surface: JvmIndexedOwnerSurface) {
        match self.members_by_owner.get_mut(owner_fqn) {
            // One owner can be read twice -- a binary jar beside its own
            // source jar, or two artifacts shipping the same class. Merging
            // keeps every positive declaration either read produced, which is
            // the only direction this surface ever moves.
            Some(existing) => {
                existing.hierarchy_complete &= surface.hierarchy_complete
                    && existing.supertypes.len() == surface.supertypes.len()
                    && existing
                        .supertypes
                        .iter()
                        .all(|parent| surface.supertypes.contains(parent));
                for (name, member) in surface.members {
                    existing.members.entry(name).or_insert(member);
                }
                for supertype in surface.supertypes {
                    if !existing.supertypes.contains(&supertype) {
                        existing.supertypes.push(supertype);
                    }
                }
                // Two reads that disagree on the parameters or on the edges
                // prove no argument: the edge arguments of one read were
                // written against that read's own parameters. The union below
                // still serves erased reachability.
                let same_edges = |left: &[HierarchyFact], right: &[HierarchyFact]| {
                    left.iter()
                        .all(|edge| right.iter().any(|other| other.target == edge.target))
                };
                if existing.type_parameters != surface.type_parameters
                    || !same_edges(&existing.hierarchy, &surface.hierarchy)
                    || !same_edges(&surface.hierarchy, &existing.hierarchy)
                {
                    existing.type_parameters = None;
                }
                for edge in surface.hierarchy {
                    if !existing
                        .hierarchy
                        .iter()
                        .any(|retained| retained.target == edge.target)
                    {
                        existing.hierarchy.push(edge);
                    }
                }
            }
            None => {
                self.members_by_owner.insert(owner_fqn.to_owned(), surface);
            }
        }
    }

    /// Record that one artifact was not read to the end.
    ///
    /// This is the honest-absence link for the member surface: an entry the
    /// byte budget refused, an entry that did not parse, and a member set past
    /// [`MAX_ARTIFACT_MEMBERS`] all leave declarations unread, and every JVM
    /// boundary already reads [`Self::production_diagnostic_count`] to report
    /// `external_declared_unindexed` -- "the build declared this and nothing
    /// finished reading it" -- instead of `external_unknown`. One diagnostic
    /// per artifact keeps the record bounded no matter how many entries an
    /// artifact skipped.
    fn note_entry_cap(
        &mut self,
        artifact_path: &Path,
        cap: &str,
        limit: u64,
        code: super::producer_codes::JvmProducerCode,
    ) {
        let location = artifact_path.to_string_lossy().into_owned();
        let message = format!("index read reached {cap} = {limit}; entries remain unindexed");
        if self.production_diagnostics.iter().any(|diagnostic| {
            diagnostic.code == code.code
                && diagnostic.location.as_ref() == Some(&location)
                && diagnostic.message == message
        }) {
            return;
        }
        self.production_diagnostics.push(
            ProducerDiagnostic {
                severity: ProducerDiagnosticSeverity::Warning,
                source_entry: None,
                code: code.code.to_owned(),
                location: Some(location),
                declaration: None,
                message,
            }
            .into(),
        );
    }

    fn note_bounded_artifact(
        &mut self,
        artifact_path: &Path,
        skipped_entries: usize,
        member_budget: MemberBudget,
    ) {
        if skipped_entries > 0 {
            self.production_diagnostics.push(
                ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Warning,
                    source_entry: None,
                    code: super::producer_codes::JVM_INDEX_UNREAD_ENTRIES.code.to_owned(),
                    location: Some(artifact_path.to_string_lossy().into_owned()),
                    declaration: None,
                    message: format!(
                        "archive read or malformed content prevented reading {skipped_entries} archive entries, so this artifact declares types and members the index never read"
                    ),
                }
                .into(),
            );
        }
        if member_budget.exhausted {
            self.production_diagnostics.push(
                ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Warning,
                    source_entry: None,
                    code: super::producer_codes::LIMIT_ARTIFACT_MEMBERS.code.to_owned(),
                    location: Some(artifact_path.to_string_lossy().into_owned()),
                    declaration: None,
                    message: format!(
                        "bounded index read stopped after {MAX_ARTIFACT_MEMBERS} member declarations from this artifact"
                    ),
                }
                .into(),
            );
        }
    }

    fn produce_java_facts(
        &mut self,
        artifact_path: &Path,
        artifact_kind: ExternalArtifactKind,
    ) -> JavaArtifactFacts {
        let production = JavaJarPackProducer.produce_exact_artifact(
            &local_jvm_artifact_production_request(
                artifact_path,
                artifact_kind,
                "bifrost.external.java",
            ),
            &ArtifactProducerLimits::default(),
        );
        self.production_diagnostics
            .extend(production.diagnostics.iter().cloned().map(IndexGap::from));
        let mut types = HashMap::default();
        let mut members = Vec::new();
        for shard in production.pack.into_iter().flat_map(|pack| pack.shards) {
            let AuthoredPayload::DeclarationFacts {
                types: shard_types,
                members: shard_members,
                ..
            } = shard.payload
            else {
                continue;
            };
            types.extend(
                shard_types
                    .into_iter()
                    .map(|fact| (fact.name.clone(), fact)),
            );
            members.extend(shard_members);
        }
        JavaArtifactFacts::new(types, members)
    }

    fn produce_scala_type_facts(&mut self, artifact_path: &Path) -> HashMap<String, TypeFact> {
        let production = ScalaSourceJarPackProducer.produce_exact_artifact(
            &local_jvm_artifact_production_request(
                artifact_path,
                ExternalArtifactKind::ScalaSourceJar,
                "bifrost.external.scala",
            ),
            &ArtifactProducerLimits::default(),
        );
        self.production_diagnostics
            .extend(production.diagnostics.iter().cloned().map(IndexGap::from));
        production
            .pack
            .into_iter()
            .flat_map(|pack| pack.shards)
            .flat_map(|shard| match shard.payload {
                AuthoredPayload::DeclarationFacts { types, .. } => types,
                AuthoredPayload::GeneratorRules { .. }
                | AuthoredPayload::ProcedureSummaries { .. } => Vec::new(),
            })
            .map(|fact| (fact.name.clone(), fact))
            .collect()
    }
}

/// Feeds [`JvmExternalDeclarationIndex::build_from_artifacts`]: raw
/// class-file/`-sources.jar` byte scanning (`index_class_jar`,
/// `index_source_jar`) over an ordinary Maven/Gradle dependency's resolved
/// jar(s).
///
/// A JDK dependency's own artifact is a `src.zip` or JMOD source set
/// (`ExternalArtifactKind::JdkSourceZip`/`JdkJmodSet`, built by
/// [`resolved_jdk_dependency`]
/// from `JAVA_HOME`/`jdk_homes`), and this function excludes it
/// unconditionally. This is deliberate, not an oversight, for two independent
/// reasons:
///
/// 1. Structurally, this index could not read it correctly even if let
///    through: `is_source_jar` only recognizes a `-sources.jar` filename
///    suffix (false for `src.zip`), and `index_class_jar` expects `.class`
///    entries (none exist in a source archive), so the raw-byte path silently
///    produces zero facts for it either way.
/// 2. Architecturally, a JDK source archive already has its own producer,
///    `JdkSourceArchivePackProducer` (dispatched from
///    `JvmDependencyPackAdapter::produce`, above), which turns the same
///    `src.zip` into a proper declaration-fact semantic pack. That pack
///    reaches resolution through the pack-activation pipeline
///    (`prepare_dependency_semantic_packs` / `activate_workspace_packs`, or a
///    caller's own hand-curated `SemanticModelActivationRequest`, as
///    `owasp_benchmark.rs` uses), never through this artifact index. Routing
///    the same `src.zip` through both would double-produce and diverge from
///    that pack's own completeness/gap accounting (#2401).
///
/// Confirmed twice independently: #2538's investigation found this exclusion
/// by tracing why `java.util.Locale`/
/// `javax.crypto.Cipher` never resolved through this index, and #2401's own
/// session (this repository, 2026-08-21) re-confirmed it while evaluating
/// whether to lift it. Do not lift this exclusion; if a JDK dependency ever
/// needs to resolve here too, give it a real conversion from the pack's own
/// `TypeFact`/`MemberFact` shards (`apply_java_type_fact` already exists for
/// half of that), not a change to this filter.
fn jvm_artifact_from_dependency(dependency: &ResolvedDependency) -> Option<ResolvedJvmArtifact> {
    if dependency.artifacts.iter().any(|artifact| {
        matches!(
            artifact.kind,
            ExternalArtifactKind::JdkSourceZip | ExternalArtifactKind::JdkJmodSet
        )
    }) {
        return None;
    }
    let binary = dependency
        .artifacts
        .iter()
        .find(|artifact| artifact.role == DependencyArtifactRole::Binary);
    let source = dependency
        .artifacts
        .iter()
        .find(|artifact| artifact.role == DependencyArtifactRole::Sources);
    let primary = binary.or(source)?;
    Some(ResolvedJvmArtifact {
        artifact_path: primary.path().to_owned(),
        source_artifact_path: binary.and(source).map(|source| source.path().to_owned()),
        coordinate: None,
        origin: JvmDependencyOrigin::ExplicitPath,
    })
}

fn discovery_producer_diagnostic(diagnostic: DependencyPackDiagnostic) -> ProducerDiagnostic {
    ProducerDiagnostic {
        severity: match diagnostic.severity {
            DependencyPackDiagnosticSeverity::Warning => ProducerDiagnosticSeverity::Warning,
            DependencyPackDiagnosticSeverity::Error => ProducerDiagnosticSeverity::Error,
        },
        code: diagnostic.code,
        location: diagnostic.location,
        source_entry: None,
        declaration: None,
        message: diagnostic.message,
    }
}

fn apply_java_type_fact(external_type: &mut JvmExternalType, fact: &TypeFact) {
    external_type.kind = semantic_type_kind(fact.type_kind);
    external_type.visibility = semantic_visibility(fact.visibility);
    external_type.is_final = fact.is_final;
}

fn scala_external_type(artifact_path: &Path, fact: TypeFact) -> Option<JvmExternalType> {
    let source_path = match fact.locator {
        Locator::Source { path, .. } => path,
        Locator::Artifact { .. } | Locator::Interchange { .. } => return None,
    };
    let name = fact.name;
    let (package_name, short_name) = name
        .rsplit_once('.')
        .map_or(("", name.as_str()), |(package, short)| (package, short));
    (!short_name.is_empty()).then(|| JvmExternalType {
        fqn: name.clone(),
        package_name: package_name.to_owned(),
        short_name: short_name.to_owned(),
        kind: semantic_type_kind(fact.type_kind),
        visibility: semantic_visibility(fact.visibility),
        is_final: fact.is_final,
        source: JvmExternalDeclarationSource::SourceJar {
            artifact_path: artifact_path.to_path_buf(),
            source_path,
        },
    })
}

fn semantic_type_kind(kind: TypeKind) -> JvmExternalTypeKind {
    match kind {
        TypeKind::Interface | TypeKind::Trait => JvmExternalTypeKind::Interface,
        TypeKind::Enum => JvmExternalTypeKind::Enum,
        TypeKind::Annotation => JvmExternalTypeKind::Annotation,
        TypeKind::Record => JvmExternalTypeKind::Record,
        TypeKind::Class
        | TypeKind::Delegate
        | TypeKind::Struct
        | TypeKind::Union
        | TypeKind::Module
        | TypeKind::TypeAlias => JvmExternalTypeKind::Class,
    }
}

fn semantic_visibility(visibility: Visibility) -> JvmVisibility {
    match visibility {
        Visibility::Public => JvmVisibility::Public,
        Visibility::Protected | Visibility::ProtectedInternal => JvmVisibility::Protected,
        Visibility::Package => JvmVisibility::PackagePrivate,
        Visibility::Internal => {
            unreachable!("Kotlin internal declarations are dropped before JVM publication")
        }
        Visibility::Private => JvmVisibility::Private,
    }
}

/// A JDK-pack type in an unshadowable package that a lookup reached in a scope
/// where nothing can shadow its name: through a single-type import after
/// `UnshadowedScope::check` held, or as a type a member signature of such an
/// owner names. Holding one is the proof; its field is private and only
/// [`JvmExternalDeclarations::resolve_explicit_import_in_unshadowed_scope`] and
/// [`UnshadowedJdkOwner::signature_type`] construct it.
///
/// A JDK class's members, member types and supertypes are all JDK, so a lookup
/// on it cannot be changed by a dependency jar. Dispatch families are a
/// different question (a workspace type can override through a missing jar),
/// and keep every gap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnshadowedJdkOwner {
    owner: JvmExternalType,
}

impl std::ops::Deref for UnshadowedJdkOwner {
    type Target = JvmExternalType;

    fn deref(&self) -> &JvmExternalType {
        &self.owner
    }
}

impl UnshadowedJdkOwner {
    /// The type a member signature names (a return, parameter or thrown type),
    /// resolved by canonical name inside the JDK pack, when it is a JDK-pack
    /// class in an unshadowable package.
    ///
    /// This is a witness for the class and nothing else. It is never given for
    /// a type variable or for a type argument substituted from the use site:
    /// those follow their own origin. A declared local type (`InputStream in =
    /// ...`) is a use-site name and goes through the ladder, not through here.
    pub(crate) fn signature_type(
        &self,
        declarations: &JvmExternalDeclarations<'_>,
        member: &JvmExternalMember,
        type_ref: &TypeRef,
    ) -> Option<UnshadowedJdkOwner> {
        // Only a member the JDK pack itself declares has a JDK declaration's
        // own signature; a member from any other origin names whatever it names.
        member.jdk_artifact_sha256()?;
        let TypeRef::Named { name, .. } = type_ref else {
            return None;
        };
        // Only direct declared terms carry the owner's witness. A substituted
        // type argument is not a declaration-owned signature type.
        let names_type = |term: &TypeRef| {
            let mut term = term;
            while let TypeRef::Array { element } = term {
                term = element;
            }
            matches!(term, TypeRef::Named { name: declared, .. } if declared == name)
        };
        if !member.returns.as_ref().is_some_and(names_type)
            && !member.call_shapes.iter().any(|shape| {
                shape.returns.as_ref().is_some_and(names_type)
                    || shape.parameters.iter().any(names_type)
            })
        {
            return None;
        }
        declarations
            .pack_declaration(name)
            .filter(JvmExternalType::is_unshadowable_jdk)
            .map(|owner| UnshadowedJdkOwner { owner })
    }

    /// The only way to obtain the narrowed proof state. It counts the
    /// diagnostics that are not attributed to a declared dependency artifact,
    /// because no dependency artifact can change what this owner's name means.
    pub(crate) fn retained_index_state(
        &self,
        retained: Option<&JvmExternalDeclarationIndex>,
    ) -> brokk_bifrost_jvm::proof::JvmRetainedExternalIndex {
        use brokk_bifrost_jvm::proof::JvmRetainedExternalIndex;
        match retained {
            None => JvmRetainedExternalIndex::Unbuilt,
            Some(index)
                if index
                    .production_diagnostics
                    .iter()
                    .any(|gap| gap.attribution() != GapAttribution::Dependency) =>
            {
                JvmRetainedExternalIndex::Partial
            }
            Some(_) => JvmRetainedExternalIndex::Complete,
        }
    }
}

/// The external rungs one name ladder probed and missed before its final
/// outcome. A probe records nothing by itself;
/// [`JvmExternalDeclarations::finish_ladder`] reads this at the outcome.
/// A ladder whose reads carry lookup provenance (Java's) names the phase of
/// each missed rung with [`Self::probe_at`] so the outcome can attribute its
/// gaps to the phases that missed.
#[derive(Default)]
pub(crate) struct LadderMisses {
    missed: std::cell::Cell<bool>,
    tiers: std::cell::RefCell<Vec<&'static str>>,
}

impl LadderMisses {
    /// Pass a rung's lookup through, noting a miss.
    pub(crate) fn probe<T>(&self, found: Option<T>) -> Option<T> {
        if found.is_none() {
            self.missed.set(true);
        }
        found
    }

    /// Pass a rung's lookup through, noting a miss and the rung's phase.
    pub(crate) fn probe_at<T>(&self, tier: &'static str, found: Option<T>) -> Option<T> {
        if found.is_none() {
            self.missed.set(true);
            let mut tiers = self.tiers.borrow_mut();
            if !tiers.contains(&tier) {
                tiers.push(tier);
            }
        }
        found
    }

    /// The phases [`Self::probe_at`] noted a miss in, in first-miss order.
    pub(crate) fn missed_tiers(&self) -> Vec<&'static str> {
        self.tiers.borrow().clone()
    }
}

/// What a single-type import resolves to in an unshadowed scope. Only
/// `resolve_explicit_import_in_unshadowed_scope` returns one. Its
/// `Unshadowed` arm is the witness and cannot be built by a caller; its
/// `Ordinary` arm is a plain type whose lookup recorded every gap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExplicitImportHit {
    Unshadowed(UnshadowedJdkOwner),
    Ordinary(JvmExternalType),
}

impl std::ops::Deref for ExplicitImportHit {
    type Target = JvmExternalType;

    fn deref(&self) -> &JvmExternalType {
        match self {
            Self::Unshadowed(owner) => &owner.owner,
            Self::Ordinary(external_type) => external_type,
        }
    }
}

impl From<JvmExternalType> for ExplicitImportHit {
    fn from(external_type: JvmExternalType) -> Self {
        Self::Ordinary(external_type)
    }
}

impl ExplicitImportHit {
    pub(crate) fn into_type(self) -> JvmExternalType {
        match self {
            Self::Unshadowed(owner) => owner.owner,
            Self::Ordinary(external_type) => external_type,
        }
    }

    pub(crate) fn witness(&self) -> Option<&UnshadowedJdkOwner> {
        match self {
            Self::Unshadowed(owner) => Some(owner),
            Self::Ordinary(_) => None,
        }
    }
}

/// The external declaration surface one JVM lookup reads: the artifact-derived
/// index first, then the declaration facts the activated semantic packs
/// publish (#1893).
///
/// Both halves answer the same question -- does an external declaration spell
/// this name, and may this package see it -- so they are one lookup with one
/// precedence, not two indexes with two vocabularies. The artifact half wins a
/// tie: an artifact on disk is the classpath the build actually resolved, while
/// a pack is a published claim about one.
///
/// The name may be a type's or a member's. Both halves carry member
/// declarations (#1900): the index reads them out of the member tables of the
/// class files it indexes, and a pack publishes them as declaration facts, so
/// `Collections.sort` is answered by whichever half declared the owner.
///
/// # Why the pack half is read live
///
/// [`JvmExternalDeclarationIndex`] is memoized in an analyzer `OnceLock` that
/// survives across activation transactions: a host activates, invalidates and
/// re-activates packs while one analyzer generation stays alive, and only a
/// changed build manifest drops the cell. Folding pack facts into that cell
/// would therefore answer from a pack set the host has since replaced or
/// withdrawn. This surface instead reads the published overlay on every
/// lookup, so it always reports the currently activated set and cannot go
/// stale. The read is a published `Arc` clone plus one hash lookup, which is
/// the same cost the other seven languages already pay for their overlay-backed
/// boundary evidence.
pub(crate) struct JvmExternalDeclarations<'a> {
    artifacts:
        brokk_bifrost_analysis::analyzer::common::IndexOwner<'a, JvmExternalDeclarationIndex>,
    packs: Option<
        Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
    >,
    selected_jdk_artifact_sha256: Option<Box<str>>,
    #[cfg(any(test, feature = "test-support"))]
    active_models: Option<
        Arc<
            brokk_bifrost_analysis::analyzer::semantic_model::runtime::ResolvedActiveSemanticModels,
        >,
    >,
}

/// An external surface acquired only when a lookup consumes it.
/// Shared by Java type lookup and enclosing-scope checks; source-only steps
/// must not acquire the index's workspace-wide receipt or its dependency gaps.
pub(crate) enum LazyExternal<'a> {
    Ready(&'a JvmExternalDeclarations<'a>),
    Deferred {
        cell: std::cell::OnceCell<JvmExternalDeclarations<'a>>,
        build: Box<dyn Fn() -> JvmExternalDeclarations<'a> + 'a>,
    },
}

impl<'a> LazyExternal<'a> {
    pub(crate) fn deferred(build: impl Fn() -> JvmExternalDeclarations<'a> + 'a) -> Self {
        Self::Deferred {
            cell: std::cell::OnceCell::new(),
            build: Box::new(build),
        }
    }

    pub(crate) fn get(&self) -> &JvmExternalDeclarations<'a> {
        match self {
            Self::Ready(external) => external,
            Self::Deferred { cell, build } => cell.get_or_init(build),
        }
    }
}

impl<'a> JvmExternalDeclarations<'a> {
    pub(crate) fn new(
        artifacts: impl Into<
            brokk_bifrost_analysis::analyzer::common::IndexOwner<'a, JvmExternalDeclarationIndex>,
        >,
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
    ) -> Self {
        Self {
            artifacts: artifacts.into(),
            packs,
            selected_jdk_artifact_sha256: None,
            #[cfg(any(test, feature = "test-support"))]
            active_models: None,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn with_active_models(
        mut self,
        active: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::runtime::ResolvedActiveSemanticModels>,
        >,
    ) -> Self {
        self.active_models = active;
        self
    }

    /// Scope JDK declaration facts to the exact artifact selected for this
    /// Java source file. Other dependency packs keep their ordinary lookup.
    pub(crate) fn select_jdk_artifact(mut self, digest: &str) -> Self {
        self.selected_jdk_artifact_sha256 = Some(Box::<str>::from(digest));
        self
    }

    fn admits_pack_symbol(
        &self,
        symbol: &brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbol,
    ) -> bool {
        self.selected_jdk_artifact_sha256
            .as_deref()
            .is_none_or(|expected| {
                let matched = &symbol.provenance.activation.matched_evidence;
                matched.ecosystem != "jdk" || matched.artifact_sha256.as_deref() == Some(expected)
            })
    }

    /// Return a class binding only when projection and every receiver argument
    /// are fully known. The caller must supply arguments from an exact Applied
    /// receiver shape; only then can a substituted formal be Inapplicable.
    /// Bind only exact, closed receiver arguments. A substituted formal may
    /// reject a call only after this provenance check succeeds.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn java_owner_bindings(
        &self,
        written_owner: &str,
        declaring_owner: &str,
        arguments: &[TypeRef],
    ) -> Option<std::collections::HashMap<String, TypeRef>> {
        let source = TypeRef::named(written_owner);
        let target = TypeRef::named(declaring_owner);
        match self.java_hierarchy_answer(&source, &target) {
            Ok(Some(answer)) => {
                let witness = answer.witness?;
                let positions = Self::project_java_arguments(&witness, arguments.len())?;
                let parameters = witness.type_parameters.last()?.as_ref()?;
                java_bind_projected_arguments(parameters, &positions, arguments)
            }
            // A class-file owner (#8440): the jar edges compose the positions
            // exactly as they do for a conversion, and the declaring jar
            // surface names the parameters the member's terms are written in.
            // A pack-declared target has no jar surface here, so it stays open.
            Ok(None) => {
                let parameters = self
                    .artifacts
                    .members_by_owner
                    .get(declaring_owner)?
                    .type_parameters
                    .as_deref()?;
                let positions = self
                    .project_java_artifact_arguments(
                        written_owner,
                        declaring_owner,
                        arguments.len(),
                    )
                    .ok()?;
                java_bind_projected_arguments(parameters, &positions, arguments)
            }
            Err(_) => None,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    fn java_hierarchy_answer(
        &self,
        actual: &TypeRef,
        formal: &TypeRef,
    ) -> Result<
        Option<brokk_bifrost_analysis::analyzer::semantic_model::JavaHierarchyAnswer>,
        ConversionUnknown,
    > {
        let (source, target) = (
            java_external_reference_name(actual).ok_or(ConversionUnknown::UnresolvedSourceType)?,
            java_external_reference_name(formal).ok_or(ConversionUnknown::UnresolvedTargetType)?,
        );
        let source_type = self
            .declaration(source)
            .ok_or(ConversionUnknown::UnresolvedSourceType)?;
        match &source_type.source {
            JvmExternalDeclarationSource::SemanticPack { declaration_id, .. } => {
                let overlay = self
                    .packs
                    .as_ref()
                    .ok_or(ConversionUnknown::IncompleteHierarchy)?;
                let matched = overlay.symbols_with_id(declaration_id);
                if matches!(matched.disposition, brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelOverlayDisposition::Open(_)) { return Err(ConversionUnknown::IncompleteHierarchy); }
                let source_symbol = matched
                    .records
                    .into_iter()
                    .find(|symbol| self.admits_pack_symbol(symbol))
                    .ok_or(ConversionUnknown::IncompleteHierarchy)?;
                let target_type = self
                    .pack_declaration(target)
                    .ok_or(ConversionUnknown::UnresolvedTargetType)?;
                let JvmExternalDeclarationSource::SemanticPack { declaration_id, .. } =
                    &target_type.source
                else {
                    return Err(ConversionUnknown::UnsupportedConversion);
                };
                let matched = overlay.symbols_with_id(declaration_id);
                if matches!(matched.disposition, brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelOverlayDisposition::Open(_)) { return Err(ConversionUnknown::IncompleteHierarchy); }
                let target_symbol = matched
                    .records
                    .into_iter()
                    .find(|symbol| self.admits_pack_symbol(symbol))
                    .ok_or(ConversionUnknown::IncompleteHierarchy)?;
                let answer = match &self.active_models {
                    Some(active) => overlay.java_erased_reference_widening(
                        active,
                        &source_symbol,
                        &target_symbol,
                        MAX_MEMBER_SURFACE_OWNERS,
                        None,
                    ),
                    None => overlay.java_reference_widening(
                        &source_symbol,
                        &target_symbol,
                        MAX_MEMBER_SURFACE_OWNERS,
                        None,
                    ),
                };
                Ok(Some(answer))
            }
            _ => Ok(None),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    fn java_hierarchy_incomplete_cause(
        reason: brokk_bifrost_analysis::analyzer::semantic_model::JavaHierarchyIncomplete,
    ) -> ConversionUnknown {
        use brokk_bifrost_analysis::analyzer::semantic_model::JavaHierarchyIncomplete;
        match reason {
            JavaHierarchyIncomplete::MissingHierarchy => ConversionUnknown::IncompleteHierarchy,
            JavaHierarchyIncomplete::GenericSubstitution => ConversionUnknown::GenericSubstitution,
            JavaHierarchyIncomplete::Ambiguous => ConversionUnknown::AmbiguousBinding,
            JavaHierarchyIncomplete::BudgetExhausted => ConversionUnknown::FixedLimit,
            JavaHierarchyIncomplete::Cancelled => ConversionUnknown::Cancelled,
        }
    }

    /// The positions of the actual's type arguments that a witness's last owner
    /// receives, composed along the witness's edges.
    #[cfg(any(test, feature = "test-support"))]
    fn project_java_arguments(
        witness: &brokk_bifrost_analysis::analyzer::semantic_model::JavaHierarchyWitness,
        actual_count: usize,
    ) -> Option<Vec<usize>> {
        debug_assert_eq!(witness.type_parameters.len(), witness.edges.len() + 1);
        compose_java_positions(
            actual_count,
            witness
                .edges
                .iter()
                .zip(&witness.type_parameters)
                .map(|(edge, parameters)| (parameters.as_deref(), &edge.target)),
            witness
                .type_parameters
                .last()
                .and_then(|last| last.as_deref()),
        )
    }

    /// The positions of the actual's type arguments that every route from
    /// `source` to `target` through the read jar surfaces, and then through
    /// the activated packs, gives the target.
    ///
    /// Each owner has one state, unset, `Some(positions)` or `Open`, and a
    /// worklist pushes each read owner's edges through the same hop step
    /// [`Self::project_java_arguments`] uses. Two routes that reach one owner
    /// with different positions, which separately compiled jars can produce,
    /// make it `Open`, and an `Open` owner proves nothing. States only move
    /// unset -> `Some` -> `Open`, so the worklist ends. The answer needs at
    /// least one route into the target and every route to agree.
    #[cfg(any(test, feature = "test-support"))]
    fn project_java_artifact_arguments(
        &self,
        source: &str,
        target: &str,
        actual_count: usize,
    ) -> Result<Vec<usize>, ConversionUnknown> {
        use std::collections::hash_map::Entry;
        // None is Open.
        type State = Option<Vec<usize>>;
        let owners = &self.artifacts.members_by_owner;
        let mut states = brokk_bifrost_core::hash::HashMap::<String, State>::default();
        let first = owners
            .get(source)
            .and_then(|surface| surface.type_parameters.as_deref())
            .filter(|parameters| parameters.len() == actual_count)
            .map(|_| (0..actual_count).collect());
        states.insert(source.to_owned(), first);
        let mut pending = std::collections::VecDeque::from([source.to_owned()]);
        while let Some(owner) = pending.pop_front() {
            let Some(surface) = owners.get(&owner) else {
                continue;
            };
            for edge in &surface.hierarchy {
                let Some(parent) = hierarchy_type_name(edge) else {
                    continue;
                };
                let candidate: State = states[&owner].as_deref().and_then(|positions| {
                    project_java_hop(positions, surface.type_parameters.as_deref(), &edge.target)
                });
                let changed = match states.entry(parent.to_owned()) {
                    Entry::Vacant(slot) => {
                        slot.insert(candidate);
                        true
                    }
                    // An Open owner stays Open, so nothing changes there.
                    Entry::Occupied(mut slot)
                        if slot.get().is_some() && *slot.get() != candidate =>
                    {
                        slot.insert(None);
                        true
                    }
                    Entry::Occupied(_) => false,
                };
                if states.len() > MAX_MEMBER_SURFACE_OWNERS {
                    return Err(ConversionUnknown::FixedLimit);
                }
                if changed && owners.contains_key(parent) && !pending.iter().any(|p| p == parent) {
                    pending.push_back(parent.to_owned());
                }
            }
        }
        let mut candidates: Vec<State> = Vec::new();
        for (owner, state) in &states {
            if let Some(surface) = owners.get(owner) {
                if owner == target {
                    candidates.push(state.as_ref().and_then(|positions| {
                        let parameters = surface.type_parameters.as_deref()?;
                        (parameters.len() == positions.len()).then(|| positions.clone())
                    }));
                } else if !surface.hierarchy_complete {
                    // An edge this surface did not record may reach the
                    // target with other arguments.
                    candidates.push(None);
                }
            } else if owner == "java.lang.Object" && owner != target {
                // The root declares no supertype, so it reaches nothing.
            } else if self.pack_declaration(owner).is_some()
                && self.pack_declaration(target).is_some()
            {
                // The pack supplies the parameters the target is written
                // against, whether the path ends at this owner or continues.
                match self.java_hierarchy_answer(&TypeRef::named(owner), &TypeRef::named(target)) {
                    Ok(Some(answer)) => match (answer.witness, answer.incomplete.first()) {
                        // A witness beside an unread or ambiguous branch is one
                        // route, not every route.
                        (Some(_), Some(_)) | (None, Some(_)) => candidates.push(None),
                        (Some(witness), None) => {
                            candidates.push(state.as_deref().and_then(|positions| {
                                let projected =
                                    Self::project_java_arguments(&witness, positions.len())?;
                                projected
                                    .into_iter()
                                    .map(|position| positions.get(position).copied())
                                    .collect()
                            }))
                        }
                        (None, None) => {}
                    },
                    Ok(None) | Err(_) => candidates.push(None),
                }
            } else {
                // Nothing read says where this owner leads, so a route through
                // it may reach the target with other arguments. An unread
                // target that no pack declares has no known parameters either.
                candidates.push(None);
            }
        }
        match candidates.first() {
            Some(Some(first)) if candidates.iter().all(|c| c.as_ref() == Some(first)) => {
                Ok(first.clone())
            }
            _ => Err(ConversionUnknown::GenericSubstitution),
        }
    }

    /// Whether `source`, which the jar index declares, reaches `target`.
    ///
    /// It follows the edges each read surface names. A parent no jar read ends
    /// that path: when it and the target are both pack declarations (the JDK
    /// lives in the model overlay) the activated packs continue the path, when
    /// it is the target the edge itself proves the path, and when it is
    /// `java.lang.Object` it declares no supertype to read. `Ok(false)` is a
    /// conclusive absence; anything unread that could change the answer is an
    /// error.
    #[cfg(any(test, feature = "test-support"))]
    fn java_artifact_route(&self, source: &str, target: &str) -> Result<bool, ConversionUnknown> {
        let walk = self.artifacts.walk_owner_surfaces(
            source,
            |surface| {
                surface
                    .hierarchy
                    .iter()
                    .filter_map(hierarchy_type_name)
                    .collect()
            },
            |owner, _| (owner == target).then_some(()),
        );
        if walk.selected.is_some() {
            return Ok(true);
        }
        let mut open = match walk.completion {
            OwnerWalkCompletion::Complete => None,
            OwnerWalkCompletion::FixedLimit => Some(ConversionUnknown::FixedLimit),
            OwnerWalkCompletion::IncompleteHierarchy | OwnerWalkCompletion::Cycle => {
                Some(ConversionUnknown::IncompleteHierarchy)
            }
        };
        for artifact_path in walk.unread {
            let owner = artifact_path.last().expect("an unread path ends at it");
            // The root declares no supertype, so reading it could add nothing.
            if owner == "java.lang.Object" && owner != target {
                continue;
            }
            // A parent the jars did not read may be declared by an activated
            // pack, the way the JDK is.
            if self.pack_declaration(owner).is_some() && self.pack_declaration(target).is_some() {
                match self.java_hierarchy_answer(&TypeRef::named(owner), &TypeRef::named(target)) {
                    Ok(Some(answer)) => {
                        if answer.witness.is_some() {
                            return Ok(true);
                        }
                        if let Some(reason) = answer.incomplete.first() {
                            open.get_or_insert(Self::java_hierarchy_incomplete_cause(*reason));
                        }
                    }
                    Ok(None) => {
                        open.get_or_insert(ConversionUnknown::IncompleteHierarchy);
                    }
                    Err(cause) => {
                        open.get_or_insert(cause);
                    }
                }
                continue;
            }
            // The edge itself names the target, so the erased path exists.
            if owner == target {
                return Ok(true);
            }
            open.get_or_insert(ConversionUnknown::IncompleteHierarchy);
        }
        open.map_or(Ok(false), Err)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn java_nominal_widening(
        &self,
        actual: &TypeRef,
        formal: &TypeRef,
    ) -> Result<bool, ConversionUnknown> {
        let (source, target) = (
            java_external_reference_name(actual).ok_or(ConversionUnknown::UnresolvedSourceType)?,
            java_external_reference_name(formal).ok_or(ConversionUnknown::UnresolvedTargetType)?,
        );
        let nominal = match self.java_hierarchy_answer(actual, formal)? {
            Some(answer) => {
                if answer.witness.is_some() {
                    Ok(true)
                } else if answer.incomplete.is_empty() {
                    Ok(false)
                } else {
                    Err(Self::java_hierarchy_incomplete_cause(answer.incomplete[0]))
                }
            }
            // Every reference type widens to Object, whatever a hierarchy names.
            None if target == "java.lang.Object" => Ok(true),
            None => self.java_artifact_route(source, target),
        };
        // An incompatible erased owner cannot be repaired by generic arguments.
        // A positive nominal path still needs substitution, except for a raw
        // use of the very same generic declaration (unchecked invocation
        // conversion, JLS 5.3), or a non-parameterized target.
        if nominal != Ok(true) {
            return nominal;
        }
        let arguments = |ty: &TypeRef| match ty {
            TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } => {
                !arguments.is_empty()
            }
            _ => false,
        };
        if arguments(formal) && (source != target || arguments(actual)) {
            Err(ConversionUnknown::GenericSubstitution)
        } else {
            Ok(true)
        }
    }

    /// Where the actual's type arguments land in the formal's owner, decided
    /// by the same position composition whichever half read the actual's class.
    #[cfg(any(test, feature = "test-support"))]
    fn java_different_owner_arguments(
        &self,
        actual: &TypeRef,
        formal: &TypeRef,
    ) -> Result<brokk_bifrost_jvm::java::conversion::JavaDifferentOwner, ConversionUnknown> {
        use brokk_bifrost_jvm::java::conversion::JavaDifferentOwner;
        let actual_count = || match actual {
            TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } => {
                Ok(arguments.len())
            }
            _ => Err(ConversionUnknown::GenericSubstitution),
        };
        match self.java_hierarchy_answer(actual, formal)? {
            Some(answer) => {
                if let Some(witness) = answer.witness {
                    return Self::project_java_arguments(&witness, actual_count()?)
                        .map(JavaDifferentOwner::Projected)
                        .ok_or(ConversionUnknown::GenericSubstitution);
                }
                if answer.incomplete.is_empty() {
                    Ok(JavaDifferentOwner::Incompatible)
                } else {
                    Err(Self::java_hierarchy_incomplete_cause(answer.incomplete[0]))
                }
            }
            None => {
                let (source, target) = (
                    java_external_reference_name(actual)
                        .ok_or(ConversionUnknown::UnresolvedSourceType)?,
                    java_external_reference_name(formal)
                        .ok_or(ConversionUnknown::UnresolvedTargetType)?,
                );
                if !self.java_artifact_route(source, target)? {
                    return Ok(JavaDifferentOwner::Incompatible);
                }
                self.project_java_artifact_arguments(source, target, actual_count()?)
                    .map(JavaDifferentOwner::Projected)
            }
        }
    }

    /// Whether no surface can answer anything, so a caller may skip the external
    /// tiers altogether.
    ///
    /// An empty surface is not the answer "nothing is declared": it is what a
    /// project with only missing jars and no JDK pack looks like. The caller is
    /// about to return unresolved, so the gaps are recorded here, before the
    /// early return that no lookup function would otherwise reach.
    pub(crate) fn empty_surface(&self, recorder: &QueryGapRecorder<'_>) -> bool {
        let empty = self.artifacts.is_empty() && self.packs.is_none();
        if empty {
            self.record_dependency_gaps(recorder);
        }
        empty
    }

    /// Every gap the index and the overlay carry, for an outcome that cannot
    /// be exact: a miss, an ambiguity, or a hit some interpretation that takes
    /// precedence over it could not decide.
    fn record_dependency_gaps(&self, recorder: &QueryGapRecorder<'_>) {
        recorder.all(&self.artifacts);
        self.record_overlay_gaps(recorder, None);
    }

    /// The gaps of the dependencies a hit's provider does not itself decide.
    ///
    /// A hit is exact when every alternative that takes precedence over it was
    /// decided exactly. Artifacts are consulted before packs, and no source
    /// orders two gapped dependencies against a provider, so a gapped
    /// dependency may outrank (or, between packs, make ambiguous) the hit,
    /// except in two cases: a `java.*` JDK declaration, which no jar or other
    /// dependency can supply or split unless the build overrides the platform,
    /// and the provider's own partial coverage, which cannot hide another
    /// declaration of a name it declares. Gaps no declared dependency owns
    /// are recorded for every hit.
    fn record_hit_gaps(&self, recorder: &QueryGapRecorder<'_>, provider: &JvmExternalType) {
        recorder.non_dependency(&self.artifacts);
        if provider.is_unshadowable_jdk() && !self.override_possible() {
            return;
        }
        recorder.dependency(&self.artifacts);
        let provider_pack = match &provider.source {
            JvmExternalDeclarationSource::SemanticPack { pack_id, .. } => Some(pack_id.as_str()),
            _ => None,
        };
        self.record_overlay_gaps(recorder, provider_pack);
    }

    /// The overlay's dependency gaps, except the partial coverage of
    /// `provider_pack`.
    fn record_overlay_gaps(&self, recorder: &QueryGapRecorder<'_>, provider_pack: Option<&str>) {
        let Some(overlay) = &self.packs else {
            return;
        };
        let coordinates = match overlay.jvm_dependency_gaps() {
            Ok(coordinates) => coordinates,
            Err(open) => {
                recorder.record_reason(brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay::open_read_incompleteness(open));
                return;
            }
        };
        for coordinate in coordinates {
            if provider_pack.is_some() && coordinate.partial_pack_id.as_deref() == provider_pack {
                continue;
            }
            if matches!(coordinate.cause, JvmDependencyGapCause::Unresolved(_))
                && self.artifacts.production_diagnostics.iter().any(|gap| {
                    gap.attribution() == GapAttribution::Dependency
                        && gap.dependency_id() == Some(coordinate.dependency_id.as_str())
                })
            {
                continue;
            }
            let gap = IndexGap::from_discovery(DependencyPackDiagnostic {
                severity: DependencyPackDiagnosticSeverity::Error,
                code: super::producer_codes::JVM_DEPENDENCY_UNRESOLVED
                    .code
                    .to_owned(),
                dependency_id: Some(coordinate.dependency_id.clone()),
                location: None,
                message: coordinate.message(),
            });
            recorder.record_gap(&gap);
        }
        // JvmExternalGaps remains the retained index's set. A selection with a
        // preparation failure refuses reuse. PartialCoverage gaps are a pack's
        // fixed content, so they cannot go stale: the active model set digest
        // (`ReadKey::Models`) covers each shard's completeness, and an outcome
        // that recorded one of these gaps is incomplete and recomputed.
    }

    /// Whether the surface carries no gap at all: no recorded production
    /// diagnostic and no dependency coordinate with an unresolved artifact. A
    /// lookup that finds nothing in a gap-free surface proves the name absent
    /// from every dependency, which is the fact [`Self::record_dependency_gaps`]
    /// withholds from an answer whose classpath is incomplete. Reads, and
    /// records, nothing; an open overlay read counts as a gap.
    pub(crate) fn carries_no_gaps(&self) -> bool {
        self.artifacts
            .production_diagnostics
            .iter()
            .all(|gap| !gap.is_recorded())
            && self.packs.as_ref().is_none_or(|overlay| {
                overlay
                    .jvm_dependency_gaps()
                    .is_ok_and(|coordinates| coordinates.is_empty())
            })
    }

    /// Records every gap the index carries, for an outcome that depends on the
    /// whole classpath without a lookup of its own.
    pub(crate) fn record_all_gaps(&self, recorder: &QueryGapRecorder<'_>) {
        self.record_dependency_gaps(recorder);
    }

    /// The one declaration of `fqn`, with no gap recorded. Private, so a public
    /// lookup that forgot to record cannot exist: every function below records
    /// the gaps a hit does not decide before it answers, and records nothing
    /// for a miss. A miss is a probe until the caller's final outcome, which is
    /// where the gaps are recorded ([`Self::record_all_gaps`], [`LadderGaps`],
    /// [`Self::or_record_miss`]).
    fn declaration(&self, fqn: &str) -> Option<JvmExternalType> {
        if let Some(external_type) = self.artifacts.get(fqn) {
            return Some(external_type.clone());
        }
        self.pack_declaration(fqn)
    }

    /// Whether the one admitted declaration of `fqn` is a class that no subclass
    /// can extend (#10572). Only a producer-read `Some(true)` on a non-interface
    /// declaration qualifies. A duplicate or ambiguous pack claim has no single
    /// declaration, so it is not final; sealed does not imply final.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn is_final_receiver_class(&self, fqn: &str) -> bool {
        self.declaration(fqn).is_some_and(|declaration| {
            matches!(
                declaration.kind,
                JvmExternalTypeKind::Class
                    | JvmExternalTypeKind::Record
                    | JvmExternalTypeKind::Enum
            ) && declaration.is_final == Some(true)
        })
    }

    fn accessible_declaration(&self, fqn: &str, access_package: &str) -> Option<JvmExternalType> {
        self.declaration(fqn)
            .filter(|external_type| external_type.is_accessible_from_package(access_package))
    }

    /// The declaration of `fqn`. A hit records the gaps its provider does not
    /// decide ([`Self::record_hit_gaps`]); a miss records nothing, so a caller
    /// that probes several spellings does not report a gap for each.
    pub(crate) fn get(
        &self,
        recorder: &QueryGapRecorder<'_>,
        fqn: &str,
    ) -> Option<JvmExternalType> {
        self.hit(recorder, self.declaration(fqn))
    }

    fn hit(
        &self,
        recorder: &QueryGapRecorder<'_>,
        found: Option<JvmExternalType>,
    ) -> Option<JvmExternalType> {
        if let Some(provider) = &found {
            self.record_hit_gaps(recorder, provider);
        }
        found
    }

    /// Close a name ladder (Java's tiers, Kotlin's name scope, Scala's import
    /// tiers) with its final outcome, `resolved` or not.
    ///
    /// A ladder interprets a name in a fixed order, and each external rung it
    /// probed and missed is an interpretation that takes precedence over the
    /// outcome: a gapped dependency could have satisfied that rung (a type
    /// `java` in package `app` would obscure the package `java`, JLS 6.5.2). So
    /// the final outcome is exact only when it is a hit and no earlier rung
    /// missed. No per-dependency package set exists yet (#11252), so every
    /// gapped dependency could satisfy every rung. A hit already recorded what
    /// its provider does not decide.
    pub(crate) fn finish_ladder(
        &self,
        recorder: &QueryGapRecorder<'_>,
        misses: &LadderMisses,
        resolved: bool,
    ) {
        if !resolved || misses.missed.get() {
            self.record_dependency_gaps(recorder);
        }
    }

    /// Close a lookup that is the whole outcome of its caller: a miss there is
    /// final, so a gapped dependency could have satisfied it.
    pub(crate) fn or_record_miss<T>(
        &self,
        recorder: &QueryGapRecorder<'_>,
        found: Option<T>,
    ) -> Option<T> {
        if found.is_none() {
            self.record_dependency_gaps(recorder);
        }
        found
    }

    /// Read both sources on every query, including absence, before selecting facts.
    pub(crate) fn hierarchy_supertypes(
        &self,
        recorder: &QueryGapRecorder<'_>,
        fqn: &str,
    ) -> Option<brokk_bifrost_jvm::ExternalSupertypeFacts> {
        if self.get(recorder, fqn).is_none() {
            // No declaration, so no supertype facts: a final miss.
            self.record_dependency_gaps(recorder);
            return None;
        }
        let artifact = self.artifacts.members_by_owner.get(fqn);
        if let Some(overlay) = &self.packs {
            let matched = qualified_model_symbols(overlay, fqn);
            if matches!(matched.disposition, brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelOverlayDisposition::Open(_)) { return None; }
            let declarations = matched
                .records
                .iter()
                .filter(|symbol| self.admits_pack_symbol(symbol))
                .collect::<Vec<_>>();
            if declarations.len() > 1
                || declarations
                    .iter()
                    .any(|symbol| symbol.provenance.ambiguous)
            {
                return None;
            }
        }
        let pack = self.pack_declaration(fqn);
        let pack_parents = if let Some(pack) = &pack {
            let JvmExternalDeclarationSource::SemanticPack { declaration_id, .. } = &pack.source
            else {
                unreachable!()
            };
            let overlay = self.packs.as_ref()?;
            let matched = overlay.symbols_with_id(declaration_id);
            if matches!(matched.disposition, brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelOverlayDisposition::Open(_)) { return None; }
            let symbols = matched
                .records
                .into_iter()
                .filter(|symbol| self.admits_pack_symbol(symbol))
                .collect::<Vec<_>>();
            let [symbol] = symbols.as_slice() else {
                return None;
            };
            let (edges, mut complete) = overlay.java_direct_hierarchy(symbol).ok()?;
            let mut parents = Vec::new();
            for edge in edges {
                if !matches!(
                    edge.hierarchy_kind,
                    HierarchyKind::Extends | HierarchyKind::Implements
                ) {
                    continue;
                }
                let ty = normalize_jvm_model_type_ref(Some(overlay), &edge.target);
                let TypeRef::Named { name, .. } = ty else {
                    complete = false;
                    continue;
                };
                parents.push(name);
            }
            Some(brokk_bifrost_jvm::ExternalSupertypeFacts {
                supertypes: parents,
                complete,
            })
        } else {
            None
        };
        match (artifact, pack_parents) {
            (Some(surface), pack) => {
                let mut facts = brokk_bifrost_jvm::ExternalSupertypeFacts {
                    supertypes: surface.supertypes.clone(),
                    complete: surface.hierarchy_complete,
                };
                if let Some(pack) = pack {
                    let left = facts.supertypes.iter().collect::<HashSet<_>>();
                    let right = pack.supertypes.iter().collect::<HashSet<_>>();
                    facts.complete &= pack.complete && left == right;
                    let mut seen = facts.supertypes.iter().cloned().collect::<HashSet<_>>();
                    facts.supertypes.extend(
                        pack.supertypes
                            .into_iter()
                            .filter(|parent| seen.insert(parent.clone())),
                    );
                }
                Some(facts)
            }
            (None, parents) => parents,
        }
    }

    pub(crate) fn resolve_explicit_import(
        &self,
        recorder: &QueryGapRecorder<'_>,
        import_path: &str,
        access_package: &str,
    ) -> Option<JvmExternalType> {
        self.resolve_qualified_name(recorder, import_path, access_package)
    }

    pub(crate) fn resolve_wildcard_import(
        &self,
        recorder: &QueryGapRecorder<'_>,
        package_name: &str,
        short_name: &str,
        access_package: &str,
    ) -> Option<JvmExternalType> {
        self.resolve_qualified_name(
            recorder,
            &qualified_name(package_name, short_name),
            access_package,
        )
    }

    pub(crate) fn resolve_same_package(
        &self,
        recorder: &QueryGapRecorder<'_>,
        package_name: &str,
        short_name: &str,
    ) -> Option<JvmExternalType> {
        self.resolve_qualified_name(
            recorder,
            &qualified_name(package_name, short_name),
            package_name,
        )
    }

    pub(crate) fn resolve_java_lang(
        &self,
        recorder: &QueryGapRecorder<'_>,
        short_name: &str,
    ) -> Option<JvmExternalType> {
        self.hit(
            recorder,
            self.declaration(&qualified_name("java.lang", short_name))
                .filter(is_public_external_type),
        )
    }

    pub(crate) fn resolve_qualified_name(
        &self,
        recorder: &QueryGapRecorder<'_>,
        fqn: &str,
        access_package: &str,
    ) -> Option<JvmExternalType> {
        self.hit(recorder, self.accessible_declaration(fqn, access_package))
    }

    /// A single-type import resolved where nothing in scope can shadow its name
    /// (`scope` is the proof). When the hit is a JDK-pack type in an
    /// unshadowable package, a missing dependency jar cannot change the answer,
    /// so only the gaps not attributed to a dependency artifact are recorded.
    /// Any other hit records what its provider does not decide: an
    /// artifact-origin hit could be outranked by the same name in a missing jar
    /// earlier on the classpath (and this surface consults the artifact map
    /// before the JDK pack). A miss is a bound miss, which the ladder records.
    pub(crate) fn resolve_explicit_import_in_unshadowed_scope(
        &self,
        recorder: &QueryGapRecorder<'_>,
        import_path: &str,
        access_package: &str,
        scope: crate::analyzer::java::unshadowed::UnshadowedScope,
    ) -> Option<ExplicitImportHit> {
        assert!(
            import_path == scope.simple_name()
                || import_path
                    .rsplit_once('.')
                    .is_some_and(|(_, simple)| simple == scope.simple_name()),
            "the scope was checked for {:?}, not for the import {import_path:?}",
            scope.simple_name()
        );
        match self.accessible_declaration(import_path, access_package) {
            Some(external_type) if external_type.is_unshadowable_jdk() => {
                recorder.non_dependency(&self.artifacts);
                Some(ExplicitImportHit::Unshadowed(UnshadowedJdkOwner {
                    owner: external_type,
                }))
            }
            Some(external_type) => {
                self.record_hit_gaps(recorder, &external_type);
                Some(ExplicitImportHit::Ordinary(external_type))
            }
            None => None,
        }
    }

    /// The member `member_name` names on `owner`, over the owner's whole
    /// inherited surface: the final outcome of a member resolution, so it
    /// records here, once, for Java, Kotlin and Scala alike.
    ///
    /// - A miss records every gap: a gapped dependency could have declared it.
    /// - A method hit whose path (the written owner through the declaring type)
    ///   has a partial owner records every gap: subtypes are consulted before
    ///   supertypes, and overload choice needs the whole candidate set, which a
    ///   partial owner does not prove.
    /// - A field or nested type hit records every gap when an owner strictly
    ///   before the declaring type is partial, which may declare a member that
    ///   hides it ([`PartialPath`]).
    /// - Any other hit follows the owner's own hit rule
    ///   ([`Self::record_hit_gaps`]).
    pub(crate) fn resolve_member_of_owner(
        &self,
        recorder: &QueryGapRecorder<'_>,
        owner: &JvmExternalType,
        member_name: &str,
        access_package: &str,
    ) -> Option<JvmExternalMember> {
        let (found, path) = match self.artifact_member(recorder, owner, member_name) {
            Some(member) => (Some(member), PartialPath::default()),
            None => self.pack_member(owner, member_name),
        };
        let found = found.and_then(|member| member.accessible_from_package(access_package));
        if found.is_none() || path.hides(found.as_ref()) {
            self.record_dependency_gaps(recorder);
        } else {
            self.record_hit_gaps(recorder, owner);
        }
        found
    }

    /// The member `member_name` names on an owner reached through its witness.
    /// A JDK class's members and supertypes are all JDK, so only the gaps not
    /// attributed to a dependency artifact are recorded. This answers which
    /// declaration a name denotes; the set of overriding methods a virtual call
    /// can dispatch to is another question and keeps every gap.
    pub(crate) fn resolve_member_of_unshadowed_owner(
        &self,
        recorder: &QueryGapRecorder<'_>,
        owner: &UnshadowedJdkOwner,
        member_name: &str,
        access_package: &str,
    ) -> Option<JvmExternalMember> {
        recorder.non_dependency(&self.artifacts);
        let (found, path) = self.pack_member(&owner.owner, member_name);
        let found = found.and_then(|member| member.accessible_from_package(access_package));
        // A JDK pack that is itself partial proves neither a miss, an overload
        // set, nor a field a partial subtype could hide, whatever jars the
        // build holds.
        if path.hides(found.as_ref()) {
            self.record_dependency_gaps(recorder);
        }
        found
    }

    /// The JDK-pack type a canonical fully qualified name denotes, when it is a
    /// `java.*` type no jar can touch.
    ///
    /// A canonical name is absolute: no type in scope obscures it, so there is
    /// no scope to prove. What remains is the package rule and the platform
    /// override. The artifact map would win an ordinary lookup of the same name
    /// (the reverse of Java's precedence), so a name an artifact also declares
    /// is left to the ordinary lookup, which records every gap.
    pub(crate) fn resolve_canonical_jdk_owner(&self, fqn: &str) -> Option<UnshadowedJdkOwner> {
        if self.override_possible() || self.artifacts.get(fqn).is_some() {
            return None;
        }
        self.pack_declaration(fqn)
            .filter(JvmExternalType::is_unshadowable_jdk)
            .map(|owner| UnshadowedJdkOwner { owner })
    }

    /// A model signature names an absolute declaration, never a use-site
    /// spelling. Look in artifacts before packs, as in `get`. Only a JDK-pack
    /// hit with a derived signature witness narrows its gap receipt.
    pub(crate) fn resolve_model_signature_type(
        &self,
        recorder: &QueryGapRecorder<'_>,
        name: &str,
        witness: Option<&UnshadowedJdkOwner>,
    ) -> Option<JvmExternalType> {
        let declaration = self.declaration(name);
        match &declaration {
            Some(declaration)
                if declaration.is_unshadowable_jdk()
                    && witness.is_some_and(|witness| witness.owner == *declaration) =>
            {
                recorder.non_dependency(&self.artifacts);
            }
            Some(declaration) => self.record_hit_gaps(recorder, declaration),
            // The name is absolute, so its lookup is the whole outcome: a
            // miss is final.
            None => self.record_dependency_gaps(recorder),
        }
        declaration
    }

    /// Whether a platform override is visible or possible because the project
    /// listing left a relevant input unknown. Either state refuses the reduced
    /// gap rule (see [`JvmExternalType::is_unshadowable_jdk`]).
    pub(crate) fn override_possible(&self) -> bool {
        self.artifacts.platform_override
            != super::dependency_discovery::MavenPlatformOverride::NotVisible
    }

    /// Whether the JDK pack proves that `owner_fqn` and every supertype it
    /// inherits declare no member type named `name`.
    ///
    /// The proof needs every type in the owner's surface to keep its whole
    /// member-type inventory and supertype edges. An unresolved edge or a type
    /// two packs publish refuses, which fails closed.
    ///
    /// A partial pack does not by itself refuse. The JDK pack is partial
    /// whenever any of its declarations lost a fact. When its extraction
    /// accounting names every loss as a declaration-scoped gap
    /// (`pack_names_every_loss`), a type that no gap names, and whose
    /// `Type.name` no gap names, lost nothing this proof reads (#14133; the
    /// same narrowing as #10388 and #3130). A partial pack without such
    /// accounting still refuses.
    pub(crate) fn jdk_owner_has_no_member_type(&self, owner_fqn: &str, name: &str) -> bool {
        use brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelOverlayDisposition::Open;
        use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelSurfaceGap;
        let Some(overlay) = self.packs.as_ref() else {
            return false;
        };
        let Some(owner) = self
            .pack_declaration(owner_fqn)
            .filter(JvmExternalType::is_unshadowable_jdk)
        else {
            return false;
        };
        let JvmExternalDeclarationSource::SemanticPack { declaration_id, .. } = &owner.source
        else {
            return false;
        };
        let matched = overlay.symbols_with_id(declaration_id);
        if matches!(matched.disposition, Open(_)) {
            return false;
        }
        let Some(owner_symbol) = matched
            .records
            .into_iter()
            .find(|symbol| self.admits_pack_symbol(symbol))
        else {
            return false;
        };
        let surface = overlay.owner_surface(&owner_symbol);
        if !surface.gaps.iter().all(|gap| match gap {
            SemanticModelSurfaceGap::PartialType { qualified_name } => {
                overlay.gapped(qualified_name).is_none()
                    && surface
                        .closure
                        .iter()
                        .filter(|record| &record.qualified_name == qualified_name)
                        .all(|record| overlay.pack_names_every_loss(&record.provenance.pack_digest))
            }
            SemanticModelSurfaceGap::UnresolvedEdge(_)
            | SemanticModelSurfaceGap::AmbiguousType { .. } => false,
        }) {
            return false;
        }
        surface
            .closure
            .iter()
            .filter(|declaring| self.admits_pack_symbol(declaring))
            .all(|declaring| {
                if overlay
                    .gapped_member_surface(&declaring.qualified_name, name)
                    .is_some()
                {
                    return false;
                }
                let nested = qualified_model_symbols(
                    overlay,
                    &qualified_name(&declaring.qualified_name, name),
                );
                if matches!(nested.disposition, Open(_))
                    || nested
                        .records
                        .iter()
                        .any(|symbol| pack_type_kind(symbol.kind).is_some())
                {
                    return false;
                }
                let members = overlay.members_of(&declaring.id);
                !matches!(members.disposition, Open(_))
                    && !members
                        .records
                        .iter()
                        .any(|member| member.name == name && pack_type_kind(member.kind).is_some())
            })
    }

    /// Walks `roots` and their external supertypes to find member types named
    /// `simple_name` inherited by a subtype in `subtype_package` (JLS 8.5).
    ///
    /// Returns `Err(())` when any external supertype's member-type inventory
    /// or supertype closure cannot be proven complete (missing supertype,
    /// incomplete hierarchy, missing/partial JDK pack, or closure limit).
    pub(crate) fn inherited_member_types_of_supertypes(
        &self,
        recorder: &QueryGapRecorder<'_>,
        roots: &[JvmExternalType],
        subtype_package: &str,
        simple_name: &str,
    ) -> Result<Vec<JvmExternalType>, ()> {
        if roots.is_empty() {
            return Ok(Vec::new());
        }
        const MAX_EXTERNAL_CLOSURE: usize = 256;
        let mut visited = HashSet::<(String, String, bool)>::default();
        let mut worklist = roots
            .iter()
            .cloned()
            .map(|ext| {
                let pp_intact = ext.package_name() == subtype_package;
                (ext, subtype_package.to_owned(), pp_intact)
            })
            .collect::<Vec<_>>();
        let mut found = Vec::<JvmExternalType>::new();
        while let Some((ext, inheriting_pkg, pp_intact)) = worklist.pop() {
            if !visited.insert((ext.fqn().to_owned(), inheriting_pkg.clone(), pp_intact)) {
                continue;
            }
            if visited.len() > MAX_EXTERNAL_CLOSURE {
                return Err(());
            }
            let member_fqn = format!("{}.{simple_name}", ext.fqn());
            if let Some(member) = self.declaration(&member_fqn) {
                // JLS 8.5: a member type declared in `ext` hides any member
                // type of the same name from `ext`'s supertypes, even if private.
                let inheritable = match member.visibility() {
                    JvmVisibility::Public | JvmVisibility::Protected => true,
                    JvmVisibility::PackagePrivate => {
                        pp_intact && member.package_name() == inheriting_pkg
                    }
                    JvmVisibility::Private => false,
                };
                if inheritable && !found.iter().any(|existing| existing.fqn() == member.fqn()) {
                    found.push(member);
                }
                continue;
            }
            if ext.fqn() == "java.lang.Object" && !self.override_possible() {
                continue;
            }
            if ext.is_unshadowable_jdk() && !self.override_possible() {
                if self.jdk_owner_has_no_member_type(ext.fqn(), simple_name) {
                    continue;
                }
                return Err(());
            }
            let Some(facts) = self.hierarchy_supertypes(recorder, ext.fqn()) else {
                return Err(());
            };
            if !facts.complete {
                return Err(());
            }
            for super_fqn in facts.supertypes {
                if super_fqn == "java.lang.Object" && !self.override_possible() {
                    continue;
                }
                let Some(super_ext) = self.declaration(&super_fqn) else {
                    return Err(());
                };
                let next_pp_intact = pp_intact && super_ext.package_name() == ext.package_name();
                worklist.push((super_ext, ext.package_name().to_owned(), next_pp_intact));
            }
        }
        Ok(found)
    }

    /// Direct supertype FQNs of `fqn` from external hierarchy facts.
    /// Returns `Err(())` if `fqn` is missing or its hierarchy facts are incomplete.
    pub(crate) fn direct_supertypes_of(
        &self,
        recorder: &QueryGapRecorder<'_>,
        fqn: &str,
    ) -> Result<Vec<String>, ()> {
        if fqn == "java.lang.Object" && !self.override_possible() {
            return Ok(Vec::new());
        }
        let Some(_ext) = self.declaration(fqn) else {
            return Err(());
        };
        let Some(facts) = self.hierarchy_supertypes(recorder, fqn) else {
            return Err(());
        };
        if !facts.complete {
            return Err(());
        }
        Ok(facts.supertypes)
    }

    /// The external member a written `Owner.member` spelling names (#1900).
    ///
    /// A reference-site spelling that crosses a `.` is one written name whose
    /// head is a type and whose last segment is a member: `Collections.sort`
    /// spells the `sort` member of `java.util.Collections`. The head is
    /// resolved by `resolve_owner`, which is the caller's own type ladder --
    /// Java's import tiers, Kotlin's name scope, Scala's import tiers -- so a
    /// member spelling reaches the same owner a type spelling would.
    ///
    /// Only a spelling the type ladder has already failed to answer belongs
    /// here. A nested type is spelled with the same dot, and its declaration is
    /// a type, so it is decided by the type ladder before this runs.
    ///
    /// Both halves answer here, in the same precedence the type half uses: the
    /// artifact-derived member surface first, then the activated packs'. The
    /// owner decides which half can even speak, because an owner is resolved
    /// once and carries where it came from -- an owner the jar index declared
    /// has an artifact member surface and no pack declaration id, and a
    /// pack-declared owner the reverse -- so "artifacts win ties" is settled by
    /// the owner lookup rather than by a second race here.
    ///
    /// A miss is never a proof of absence. The surface reports what it
    /// declares; a caller that finds nothing keeps the status it had, so a type
    /// whose pack declares no members, and a type whose class file the bounded
    /// index never read, both leave every member spelling exactly as unknown as
    /// it was before.
    pub(crate) fn resolve_member_spelling(
        &self,
        recorder: &QueryGapRecorder<'_>,
        spelling: &str,
        access_package: &str,
        resolve_owner: impl FnOnce(&str) -> Option<JvmExternalType>,
    ) -> Option<JvmExternalMember> {
        let (owner_spelling, member_name) = spelling.trim().rsplit_once('.')?;
        if owner_spelling.is_empty() || member_name.is_empty() {
            return None;
        }
        // An owner probe may record nothing on a miss. This member lookup is
        // a final outcome, so close that miss here just as resolve_member_of_owner
        // closes a miss after finding the owner.
        let owner = self.or_record_miss(recorder, resolve_owner(owner_spelling))?;
        self.resolve_member_of_owner(recorder, &owner, member_name, access_package)
    }

    /// The member the indexed artifacts declare on `owner` (#1900).
    ///
    /// Only an artifact-declared owner has an artifact member surface, for the
    /// same reason [`Self::pack_member`] refuses a non-pack owner: the surface
    /// is keyed by the identity the half that read it produced. An owner the
    /// jar index never read has no entry at all, which is why a miss here is
    /// silence rather than a negative answer.
    fn artifact_member(
        &self,
        recorder: &QueryGapRecorder<'_>,
        owner: &JvmExternalType,
        member_name: &str,
    ) -> Option<JvmExternalMember> {
        match owner.source {
            JvmExternalDeclarationSource::SourceJar { .. }
            | JvmExternalDeclarationSource::ClassFile { .. } => {
                let (member, completion) = self.artifacts.member(&owner.fqn, member_name);
                if completion == OwnerWalkCompletion::FixedLimit {
                    recorder.record_reason(
                        brokk_bifrost_analysis::analyzer::QueryReadIncomplete::ProofStopped {
                            reason: "fixed_limit",
                            cause: None,
                        },
                    );
                }
                member.cloned()
            }
            JvmExternalDeclarationSource::SemanticPack { .. } => None,
        }
    }

    /// The one declaration the activated packs publish for `fqn`, if exactly
    /// one does.
    ///
    /// `symbols_named` also posts every symbol under its simple name, so a bare
    /// `Collections` would otherwise match `java.util.Collections` and let any
    /// dependency type that happens to share a short name answer a JVM name.
    /// The caller has already walked its own import tiers to produce a
    /// qualified spelling, so only the qualified postings count: the declared
    /// name, and the aliases, which are qualified too. This is the same rule
    /// `JvmOverlayModel::qualified_name_disposition` applies on the
    /// proof-gated diagnostic side, so a trace, a definition and a diagnostic
    /// read one activated set the same way.
    fn pack_declaration(&self, fqn: &str) -> Option<JvmExternalType> {
        let overlay = self.packs.as_ref()?;
        let matched = qualified_model_symbols(overlay, fqn);
        if matches!(
            matched.disposition,
            brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelOverlayDisposition::Open(
                _
            )
        ) {
            return None;
        }
        let mut declarations = matched
            .records
            .into_iter()
            .filter(|symbol| self.admits_pack_symbol(symbol))
            .filter_map(|symbol| pack_external_type(&symbol));
        let declared = declarations.next()?;
        // Two activated packs claiming one qualified name is ambiguity, not a
        // declaration: the name exists but which declaration it denotes is not
        // decided, so no single external type can be reported. Reporting none
        // understates what is known and never overstates it.
        declarations.next().is_none().then_some(declared)
    }

    /// The member an activated pack publishes on `owner`, searched over the
    /// owner's whole inherited surface.
    ///
    /// The surface is the closure `SemanticModelOverlay::owner_surface` builds,
    /// because a JVM member is as often inherited as declared: `sort` sits on
    /// `java.util.Collections` while `toString` sits on `java.lang.Object`, and
    /// a reference spells both the same way. The declaration that answers keeps
    /// its own qualified name, so the reported target names where the member is
    /// declared rather than where it was written.
    ///
    /// More than one hit is the ordinary shape of an override or an overload --
    /// a class and the interface it implements both declare the method, and
    /// `sort(List)` and `sort(List, Comparator)` are two declarations of one
    /// name -- so it is not ambiguity. Only a declaration an indexed pack itself
    /// flagged ambiguous is, which is the same rule PHP's external surface
    /// applies.
    ///
    /// Staticness and arity are deliberately not filtered on. The question this
    /// surface answers is whether an external declaration spells the name, not
    /// whether the written use of it compiles: the workspace member tier does
    /// not refuse a static member written through an instance either, and a
    /// Scala `object` or Kotlin companion member is published without the
    /// static flag a Java static carries.
    ///
    /// The second answer is which owners on the lookup path come from a
    /// partial shard ([`PartialPath`]). A subtype is consulted before its
    /// supertypes, so a partial subtype may declare an overload, an override or
    /// a hiding field the lookup never saw.
    fn pack_member(
        &self,
        owner: &JvmExternalType,
        member_name: &str,
    ) -> (Option<JvmExternalMember>, PartialPath) {
        let Some(overlay) = self.packs.as_ref() else {
            return (None, PartialPath::default());
        };
        // Only a pack-declared owner has a pack member surface: an artifact
        // owner carries no declaration identity to look members up by.
        let JvmExternalDeclarationSource::SemanticPack { declaration_id, .. } = &owner.source
        else {
            return (None, PartialPath::default());
        };
        let matched = overlay.symbols_with_id(declaration_id);
        if matches!(
            matched.disposition,
            brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelOverlayDisposition::Open(
                _
            )
        ) {
            return (None, PartialPath::default());
        }
        let Some(owner_symbol) = matched
            .records
            .into_iter()
            .find(|symbol| self.admits_pack_symbol(symbol))
        else {
            return (None, PartialPath::default());
        };
        let surface = overlay.owner_surface(&owner_symbol);
        let member_surfaces = surface
            .closure
            .iter()
            .filter(|declaring| self.admits_pack_symbol(declaring))
            .map(|declaring| (declaring, overlay.members_of(&declaring.id)))
            .collect::<Vec<_>>();
        if member_surfaces.iter().any(|(_, members)| matches!(members.disposition, brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelOverlayDisposition::Open(_))) {
            return (None, PartialPath::default());
        }
        let mut path = PartialPath::default();
        let member = member_surfaces.into_iter().find_map(|(declaring, members)| {
                path.before_declaring = path.through_declaring;
                path.through_declaring |= declaring.source_completeness != Completeness::Complete;
                let matched = members.records.into_iter()
                    .filter(|symbol| {
                        symbol.name == member_name
                            && self.admits_pack_symbol(symbol)
                            && !symbol.provenance.ambiguous
                            && JVM_SEMANTIC_PACK_LANGUAGES.contains(&symbol.language.as_str())
                    })
                    .collect::<Vec<_>>();
                let member = matched.first()?.clone();
                let mut fields = matched.iter().filter(|symbol| {
                    matches!(
                        symbol.kind,
                        brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbolKind::Field
                            | brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbolKind::Constant
                    )
                });
                let field_type = match (fields.next(), fields.next()) {
                    (Some(field), None) if field.visibility == Visibility::Public => field
                        .structured_signature
                        .as_ref()
                        .and_then(|signature| signature.returns.clone()),
                    _ => None,
                };
                let mut call_shapes = Vec::new();
                let mut unshaped_model_records = Vec::new();
                let mut call_shapes_incomplete = false;
                for symbol in &matched {
                    if !brokk_bifrost_semantic::analyzer::semantic_model::overlay::symbol_kind_is_callable(symbol.kind) {
                        continue;
                    }
                    let record = ProjectedNativeModelMember::reached(
                                symbol.as_ref().clone(),
                                brokk_bifrost_analysis::analyzer::semantic_model::overlay::ModelSymbolRef {
                                    symbol_id: symbol.id.clone(),
                                    provider: brokk_bifrost_analysis::analyzer::semantic_model::overlay::ModelProvider::from(&symbol.provenance),
                                },
                                brokk_bifrost_analysis::analyzer::resolution::ExternalOwnerIdentity {
                                    provider_id: jvm_external_provider_id(&declaring.provenance.pack_digest).into(),
                                    owner_fqn: declaring.qualified_name.clone().into(),
                                },
                            );
                    let Some(signature) = symbol.structured_signature.as_ref() else {
                        unshaped_model_records.push(record);
                        call_shapes_incomplete = true;
                        continue;
                    };
                    if !symbol.callable_family_complete
                        && !(declaring.jvm_owner_family_enumerated
                            && symbol.provenance.completeness
                                == brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelCompleteness::Complete)
                    {
                        call_shapes_incomplete = true;
                    }
                    let Some(parameter_count) = u32::try_from(signature.parameters.len()).ok()
                    else {
                        unshaped_model_records.push(record);
                        call_shapes_incomplete = true;
                        continue;
                    };
                    call_shapes.push(JvmExternalCallShape {
                        visibility: semantic_visibility(symbol.visibility),
                        model_record: Some(Box::new(record)),
        inventory_identity: None,
                        non_overridable: symbol.non_overridable,
                        is_abstract: symbol.declaration_is_abstract,
                        parameter_count,
                        has_type_parameters: !signature.type_parameters.is_empty(),
                        type_parameters: signature.type_parameters.clone(),
                        parameters: signature
                            .parameters
                            .iter()
                            .map(|parameter| normalize_jvm_model_type_ref(Some(overlay), &parameter.r#type))
                            .collect(),
                        is_static: symbol.is_static,
                        variadic: signature
                            .parameters
                            .iter()
                            .any(|parameter| parameter.variadic),
                        returns: signature.returns.clone(),
                    });
                }
                Some(JvmExternalMember {
                    fqn: member.qualified_name.clone(),
                    // The package split is the one [`pack_external_type`] makes on
                    // a type's declared name, taken from the declaring type rather
                    // than from the type the reference wrote.
                    declaring_package: declaring
                        .qualified_name
                        .rsplit_once('.')
                        .map_or("", |(package, _)| package)
                        .to_owned(),
                    visibility: semantic_visibility(member.visibility),
                    returns: member
                        .structured_signature
                        .as_ref()
                        .and_then(|signature| signature.returns.clone()),
                    // Carried for parity with the artifact-derived member surface
                    // (#2538). The doc comment above already warns that a Scala
                    // `object` or Kotlin companion member is published without
                    // the static flag a Java `static` carries, so a caller that
                    // needs a *proof* of compile-time-constant-ness (not merely
                    // "declared const-shaped") must not rely on this half alone
                    // for those languages; [`JvmExternalMember::is_compile_time_constant`]
                    // requires both flags together and fails closed if either is
                    // under-reported.
                    is_static: member.is_static,
                    is_constant: member.kind
                        == brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbolKind::Constant,
                    field_type,
                    jdk_artifact_sha256: (member.provenance.activation.matched_evidence.ecosystem
                        == "jdk")
                        .then(|| {
                            member
                                .provenance
                                .activation
                                .matched_evidence
                                .artifact_sha256.clone()
                        })
                        .flatten(),
                    unshaped_model_records,
                    call_shapes,
                    call_shapes_incomplete,
                })
            });
        if member.is_none() {
            // A miss reads the whole closure, so every owner is "before" it.
            path.before_declaring = path.through_declaring;
        }
        (member, path)
    }
}

/// Which owners on a pack member lookup path come from a partial shard.
///
/// The path starts at the written owner and ends at the declaring type on a hit,
/// or at the end of the closure on a miss. A subtype is consulted before its
/// supertypes, so a partial owner may declare something the lookup never saw.
#[derive(Debug, Clone, Copy, Default)]
struct PartialPath {
    /// An owner strictly before the declaring type is partial: it may declare a
    /// field or nested type that hides the hit, or an override of it.
    before_declaring: bool,
    /// An owner up to and including the declaring type is partial: it may also
    /// declare another overload of a method hit.
    through_declaring: bool,
}

impl PartialPath {
    /// Whether the partial coverage on the path means the answer is not exact:
    /// a miss or a method (which needs the whole overload set) is hidden by any
    /// partial owner on the path, and a field or nested type only by an earlier
    /// one.
    fn hides(self, found: Option<&JvmExternalMember>) -> bool {
        match found {
            Some(member) if !member.is_callable() => self.before_declaring,
            _ => self.through_declaring,
        }
    }
}

/// One member an external declaration surface declares on an external type
/// (#1900): the `sort` of `Collections.sort`, not the `Collections`.
///
/// Both halves produce this same shape -- the jar index reads it out of a
/// class file's member table, an activated pack reads it out of a declaration
/// fact -- so one lookup answers a member spelling whichever half declared it.
///
/// A member is not a type, so it is not a [`JvmExternalType`]: nothing may
/// resolve a type name to it, and [`pack_type_kind`] rejects every member kind
/// precisely so that cannot happen. What a member shares with a type is the
/// question a boundary asks -- does an external declaration spell this name,
/// and may this package see it -- so it carries exactly what answers that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JvmExternalMember {
    fqn: String,
    /// The package of the type that *declares* the member, which is what
    /// `protected` and package-private accessibility are measured against. An
    /// inherited member is declared in its own supertype's package, not in the
    /// package of the type the reference wrote.
    declaring_package: String,
    visibility: JvmVisibility,
    /// The type the declaration writes as this member's return type, exactly as
    /// the declaring half recorded it. `None` means the declaration wrote none
    /// -- a field, a constructor, a `void` method, or a member surface whose
    /// signature the producer did not record -- which is not a claim that the
    /// member returns nothing a caller can name.
    ///
    /// Overloads share one entry per written name in the artifact half, so this
    /// is the return type of the *first* declaration read for that name. That is
    /// the same "overloads are one name, not ambiguity" rule
    /// [`JvmIndexedOwnerSurface`] already applies to the member itself.
    /// A caller that needs the return type of the overload a written call
    /// *selects*, rather than a name to continue a ladder from, asks
    /// [`JvmExternalMember::applicable_return_type`] instead (#3522).
    returns: Option<TypeRef>,
    /// Whether the declaring half marked this member `static` (#2538).
    is_static: bool,
    /// Whether the declaring half classified this member as a compile-time
    /// constant: for the JVM class-file half, exactly a field whose access
    /// flags carry both `ACC_STATIC` and `ACC_FINAL`
    /// (`MemberKind::Constant`, set by `class_field_member`); for an
    /// activated pack, `SemanticModelSymbolKind::Constant` (#2538).
    ///
    /// This is a separate signal from [`Self::is_static`] rather than the
    /// whole story on its own: a caller that needs "provably a compile-time
    /// constant" should require both, so a producer that ever set one flag
    /// without the other fails closed instead of over-claiming.
    is_constant: bool,
    /// The declared type of the one public field this name denotes, read from
    /// the field's own declaration. `returns` cannot answer this: it is the
    /// first declaration of the collapsed name, which may be a same-named
    /// method. `None` when no single public field declaration writes a type,
    /// which includes every artifact-derived field (#12136).
    field_type: Option<TypeRef>,
    /// Exact JDK declaration artifact. The Java source's selected toolchain is
    /// separate evidence and cannot turn an arbitrary library call into a JDK call.
    jdk_artifact_sha256: Option<String>,
    /// Every callable overload of this name the declaring surface recorded.
    ///
    /// The collapsed member above answers "does this name exist". These shapes
    /// answer whether one written receiver and argument count selects a single
    /// signature. Same-arity overloads stay distinct entries so a call that
    /// matches two of them is not treated as one proof. Each shape carries its
    /// own declared return type, so a selected shape can type a chained
    /// receiver without a name-only reading of some other overload (#3522).
    unshaped_model_records: Vec<ProjectedNativeModelMember>,
    call_shapes: Vec<JvmExternalCallShape>,
    /// A callable with this name was dropped, lacked a signature, or did not
    /// certify that its overload family is complete. Applicability then stays
    /// unknown instead of treating the recorded shapes as exhaustive.
    call_shapes_incomplete: bool,
}

/// One callable overload retained beside the collapsed member name.
#[derive(Debug, Clone, PartialEq, Eq)]
struct JvmExternalCallShape {
    model_record: Option<Box<ProjectedNativeModelMember>>,
    visibility: JvmVisibility,
    inventory_identity:
        Option<brokk_bifrost_analysis::analyzer::resolution::fact_source::ExternalMemberIdentity>,
    non_overridable:
        Option<brokk_bifrost_analysis::analyzer::semantic_model::NonOverridableEvidence>,
    is_abstract: bool,
    parameter_count: u32,
    parameters: Vec<TypeRef>,
    has_type_parameters: bool,
    type_parameters: Vec<String>,
    is_static: bool,
    variadic: bool,
    /// The type this overload's own declaration writes as its return type.
    ///
    /// The collapsed [`JvmExternalMember::returns`] holds the first
    /// declaration's answer for the whole name, which is enough to continue a
    /// receiver ladder from a written name but is not the *selected*
    /// overload's answer. Keeping the type beside the shape lets a caller ask
    /// for the return type of the one signature an argument count and
    /// receiver shape actually select (#3522).
    returns: Option<TypeRef>,
}

impl JvmExternalMember {
    /// Whether the name denotes a method or constructor: its overload family
    /// decides which declaration a call selects.
    fn is_callable(&self) -> bool {
        !self.call_shapes.is_empty()
            || !self.unshaped_model_records.is_empty()
            || self.call_shapes_incomplete
    }

    pub(crate) fn non_overridable_at(
        &self,
        value_receiver: bool,
        arity: usize,
    ) -> Option<brokk_bifrost_analysis::analyzer::semantic_model::NonOverridableEvidence> {
        self.applicable_shape(value_receiver, arity)
            .and_then(|shape| shape.non_overridable)
    }

    pub(crate) fn abstract_at(&self, value_receiver: bool, arity: usize) -> Option<bool> {
        self.applicable_shape(value_receiver, arity)
            .map(|shape| shape.is_abstract)
    }

    pub(crate) fn jdk_artifact_sha256(&self) -> Option<&str> {
        self.jdk_artifact_sha256.as_deref()
    }

    pub(crate) fn fqn(&self) -> &str {
        &self.fqn
    }

    /// The fully-qualified name of the class this member's declaration says it
    /// returns (#2454).
    ///
    /// This is what types a *chained* receiver: `response.getWriter()` has no
    /// written type anywhere in the reading file, but the declaration surface
    /// that declares `getWriter` also writes down that it returns
    /// `java.io.PrintWriter`.
    ///
    /// It fails closed, in the same direction as every other tier of the
    /// receiver ladder. Only a `Named` return type names a class a member
    /// lookup can continue from; a type variable, a wildcard, an array, a
    /// pointer and every other structured form name no single declaration, so
    /// they answer nothing and the call keeps the identity-free boundary it had.
    /// A primitive return spells a `Named` type no external surface declares, so
    /// it fails at the next rung rather than here.
    pub(crate) fn declared_return_type_fqn(&self) -> Option<&str> {
        named_return_type_fqn(self.returns.as_ref())
    }

    /// The declared type of the public field this member name denotes, when
    /// one field declaration writes it.
    pub(crate) fn declared_field_type(&self) -> Option<&TypeRef> {
        self.field_type.as_ref()
    }

    fn accessible_from_package(mut self, package_name: &str) -> Option<Self> {
        // Access is a property of each declaration, not the first overload in
        // a name group. It is independent of the family's enumeration claim.
        let declaring_package = &self.declaring_package;
        self.call_shapes.retain(|shape| {
            is_visible_from_package(shape.visibility, declaring_package, package_name)
        });
        if !is_visible_from_package(self.visibility, declaring_package, package_name) {
            let shape = self.call_shapes.first()?;
            self.visibility = shape.visibility;
            self.is_static = shape.is_static;
            self.returns = shape.returns.clone();
            self.is_constant = false;
        }
        Some(self)
    }

    /// Whether the declaring half marked this member `static` (#2538).
    pub(crate) fn is_static(&self) -> bool {
        self.is_static
    }

    /// Whether this member is provably a compile-time constant: `static`
    /// *and* classified `MemberKind::Constant`/`SemanticModelSymbolKind::Constant`
    /// by whichever half declared it (#2538).
    ///
    /// A field the class-file half classifies `MemberKind::Constant` is,
    /// by construction, a field whose access flags carry both `ACC_STATIC`
    /// and `ACC_FINAL` -- read straight off the real class file, not
    /// inferred -- so a caller may treat a read of such a field as carrying
    /// no attacker-influenced value flow (Java Language Specification
    /// compile-time-constant semantics for a `static final` field). Requiring
    /// both flags here, rather than trusting `is_constant` alone, means a
    /// producer that only ever set one of the two still fails closed.
    pub(crate) fn is_compile_time_constant(&self) -> bool {
        self.is_static && self.is_constant
    }

    /// The parameter count of the one non-variadic overload that accepts
    /// `arity` arguments with this receiver shape.
    ///
    /// `None` when the surface did not record a complete overload family, when
    /// a variadic overload could also accept the call, or when zero or several
    /// fixed signatures match. A name-only member is not a signature.
    pub(crate) fn applicable_parameter_count(
        &self,
        instance_receiver: bool,
        arity: usize,
    ) -> Option<u32> {
        self.applicable_shape(instance_receiver, arity)
            .map(|shape| shape.parameter_count)
    }

    /// Select one external overload from structured Java argument types.
    ///
    /// Arity alone is not Java applicability: a unique `m(String)` does not
    /// accept `m(1)`. Unknown conversions keep the external call unproved.
    #[cfg(test)]
    pub(crate) fn applicable_parameter_count_for_argument_types(
        &self,
        instance_receiver: bool,
        actuals: &[TypeRef],
        surface: Option<&JvmExternalDeclarations<'_>>,
    ) -> Option<u32> {
        self.invocation_for_argument_types_bound(instance_receiver, actuals, surface, None)
            .ok()
            .map(|(shape, _)| shape.parameter_count)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn non_overridable_for_argument_types(
        &self,
        instance_receiver: bool,
        actuals: &[TypeRef],
        surface: Option<&JvmExternalDeclarations<'_>>,
        owner_bindings: Option<&std::collections::HashMap<String, TypeRef>>,
    ) -> Option<&brokk_bifrost_analysis::analyzer::semantic_model::NonOverridableEvidence> {
        // Read the evidence of the overload the bound selection chose, not of
        // the overload the unsubstituted formals would select.
        self.invocation_for_argument_types_bound(
            instance_receiver,
            actuals,
            surface,
            owner_bindings,
        )
        .ok()?
        .0
        .non_overridable
        .as_ref()
    }

    /// Abstract status belongs to the overload selected with the same bound
    /// argument conversions as the exact call proof.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn abstract_for_argument_types(
        &self,
        instance_receiver: bool,
        actuals: &[TypeRef],
        surface: Option<&JvmExternalDeclarations<'_>>,
        owner_bindings: Option<&std::collections::HashMap<String, TypeRef>>,
    ) -> Option<bool> {
        self.invocation_for_argument_types_bound(
            instance_receiver,
            actuals,
            surface,
            owner_bindings,
        )
        .ok()
        .map(|(shape, _)| shape.is_abstract)
    }

    /// Reuse the writer's owner-member order for the overload selected by the
    /// structured argument conversion proof. This borrows the active shard;
    /// it does not materialize another payload or invent a source locator.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn direct_inventory_identity_for_argument_types(
        &self,
        instance_receiver: bool,
        actuals: &[TypeRef],
        surface: Option<&JvmExternalDeclarations<'_>>,
        owner_bindings: Option<&std::collections::HashMap<String, TypeRef>>,
    ) -> Option<brokk_bifrost_analysis::analyzer::resolution::fact_source::ExternalMemberIdentity>
    {
        self.invocation_for_argument_types_bound(
            instance_receiver,
            actuals,
            surface,
            owner_bindings,
        )
        .ok()?
        .0
        .inventory_identity
        .clone()
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn inventory_identity_for_argument_types(
        &self,
        active: &brokk_bifrost_analysis::analyzer::semantic_model::runtime::ResolvedActiveSemanticModels,
        instance_receiver: bool,
        actuals: &[TypeRef],
        surface: Option<&JvmExternalDeclarations<'_>>,
        owner_bindings: Option<&std::collections::HashMap<String, TypeRef>>,
    ) -> Option<brokk_bifrost_analysis::analyzer::resolution::fact_source::ExternalMemberIdentity>
    {
        use brokk_bifrost_analysis::analyzer::resolution::fact_source::ExternalMemberIdentity;

        use brokk_bifrost_analysis::analyzer::resolution::fact_source::ExternalOwnerIdentity;
        let (shape, _) = self
            .invocation_for_argument_types_bound(
                instance_receiver,
                actuals,
                surface,
                owner_bindings,
            )
            .ok()?;
        let (owner_fqn, member_name) = self.fqn.rsplit_once('.')?;
        let mut selected = None;
        for owner in active.types_named(owner_fqn).records {
            if !owner.shard.admits_jvm_owner_declaration(&owner.record) {
                continue;
            }
            // An open owner inventory cannot establish a selected identity.
            let members =
                brokk_bifrost_analysis::analyzer::store::active_models::owner_provider_members(
                    active, &owner,
                )
                .ok()?;
            for (ordinal, member) in members.iter().enumerate() {
                // Fields count toward the ordinal, as in the store's member
                // rows, but never match a call. A field is recorded with an
                // empty parameter list, so `HashMap.entrySet` or
                // `ArrayList.size` would otherwise tie with the zero-argument
                // method of the same name and leave no identity (#7860).
                if member.name != member_name
                    || member.is_static != shape.is_static
                    || !callable_member_kind(member.member_kind)
                {
                    continue;
                }
                let Some(signature) = &member.signature else {
                    continue;
                };
                if signature.parameters.len() != shape.parameters.len()
                    || !signature.parameters.iter().zip(&shape.parameters).all(
                        |(formal, selected)| {
                            normalize_jvm_model_type_ref(
                                surface.and_then(|surface| surface.packs.as_deref()),
                                &formal.r#type,
                            ) == *selected
                        },
                    )
                    || signature.parameters.iter().any(|formal| formal.variadic) != shape.variadic
                {
                    continue;
                }
                let identity = ExternalMemberIdentity {
                    owner: ExternalOwnerIdentity {
                        provider_id: std::sync::Arc::from(jvm_external_provider_id(
                            &owner.shard.manifest.semantic_sha256,
                        )),
                        owner_fqn: std::sync::Arc::from(owner_fqn),
                    },
                    ordinal: u32::try_from(ordinal).expect("bounded provider member ordinal"),
                };
                if selected
                    .as_ref()
                    .is_some_and(|previous| previous != &identity)
                {
                    return None;
                }
                selected = Some(identity);
            }
        }
        selected
    }

    /// Preserve the selected declaration's full return term for conversion.
    /// Arrays and generic terms must not be reduced to a displayed class name.
    pub(crate) fn applicable_return_type(
        &self,
        instance_receiver: bool,
        arity: usize,
    ) -> Option<&TypeRef> {
        self.applicable_shape(instance_receiver, arity)?
            .returns
            .as_ref()
    }

    /// The one recorded overload this written arity and receiver shape select.
    ///
    /// `None` when the surface did not record a complete overload family, when
    /// a variadic overload could also accept the call, or when zero or several
    /// fixed signatures match. A name-only member is not a signature.
    fn applicable_shape(
        &self,
        instance_receiver: bool,
        arity: usize,
    ) -> Option<&JvmExternalCallShape> {
        if self.call_shapes_incomplete {
            return None;
        }
        let arity = u32::try_from(arity).ok()?;
        let wants_static = !instance_receiver;
        let mut matched = None;
        for shape in &self.call_shapes {
            if shape.is_static != wants_static {
                continue;
            }
            if shape.variadic {
                let minimum = shape.parameter_count.saturating_sub(1);
                if arity >= minimum {
                    return None;
                }
                continue;
            }
            if shape.parameter_count != arity {
                continue;
            }
            if matched.is_some() {
                return None;
            }
            matched = Some(shape);
        }
        matched
    }

    /// A fixed nongeneric signature equal to all known static actuals is
    /// selected independently of family completeness. Receiver proof belongs
    /// to the caller, and behavior-only summaries supply no call shape.
    pub(crate) fn exact_return_type_for_argument_types(
        &self,
        instance_receiver: bool,
        actuals: &[TypeRef],
    ) -> Option<&TypeRef> {
        self.exact_shape_for_argument_types(instance_receiver, actuals)?
            .returns
            .as_ref()
    }

    fn exact_shape_for_argument_types(
        &self,
        instance_receiver: bool,
        actuals: &[TypeRef],
    ) -> Option<&JvmExternalCallShape> {
        let wants_static = !instance_receiver;
        let mut exact = self
            .call_shapes
            .iter()
            .filter(|shape| shape.is_static == wants_static && shape.java_exact_actuals(actuals));
        let selected = exact.next()?;
        // JLS 15.12.2 phase 1: no applicable overload can be strictly more
        // specific than formals equal to every actual's static type, and
        // two declarations with identical formals cannot coexist. Missing
        // family members therefore cannot change this nongeneric, fixed
        // selection. This says nothing about receiver dispatch or model
        // provenance completeness.
        exact.next().is_none().then_some(selected)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn selected_type_argument_bindings(
        &self,
        instance_receiver: bool,
        actuals: &[TypeRef],
        surface: &JvmExternalDeclarations<'_>,
        owner_bindings: &std::collections::HashMap<String, TypeRef>,
    ) -> Option<brokk_bifrost_analysis::analyzer::usages::get_definition::ExternalCallTypeBindings>
    {
        let (shape, _) = self
            .invocation_for_argument_types_bound(
                instance_receiver,
                actuals,
                Some(surface),
                Some(owner_bindings),
            )
            .ok()?;
        let mut bindings = owner_bindings.clone();
        for name in &shape.type_parameters {
            bindings.insert(name.clone(), TypeRef::TypeParameter { name: name.clone() });
        }
        let mut ordered = bindings.into_iter().collect::<Vec<_>>();
        ordered.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        Some(
            ordered
                .into_iter()
                .map(|(name, term)| (name.into_boxed_str(), term))
                .collect(),
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn invocation_with_diagnostics(
        &self,
        instance_receiver: bool,
        actuals: &[TypeRef],
        surface: Option<&JvmExternalDeclarations<'_>>,
    ) -> JavaExternalInvocationDiagnostics {
        self.invocation_with_bound_diagnostics(instance_receiver, actuals, surface, None)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn invocation_with_bound_diagnostics(
        &self,
        instance_receiver: bool,
        actuals: &[TypeRef],
        surface: Option<&JvmExternalDeclarations<'_>>,
        owner_bindings: Option<&std::collections::HashMap<String, TypeRef>>,
    ) -> JavaExternalInvocationDiagnostics {
        match self.invocation_for_argument_types_bound(
            instance_receiver,
            actuals,
            surface,
            owner_bindings,
        ) {
            Ok((shape, fixed)) => (Ok((shape.parameter_count, fixed)), None),
            Err(failure) => (
                Err(failure.cause),
                self.invocation_diagnostic_family(instance_receiver, &failure),
            ),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    fn invocation_diagnostic_family(
        &self,
        instance_receiver: bool,
        failure: &JavaExternalInvocationAssessment,
    ) -> Option<Box<ProjectedNativeModelMemberSelection>> {
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::{
            NativeInvocationContentCause, NativeInvocationOutcome, NativeInvocationShape,
        };
        let mut candidates = self
            .unshaped_model_records
            .iter()
            .filter(|record| record.declaration.is_static != instance_receiver)
            .cloned()
            .collect::<Vec<_>>();
        let mut identityless_shapes = Vec::new();
        debug_assert_eq!(self.call_shapes.len(), failure.applicability.len());
        for (shape, applicability) in self.call_shapes.iter().zip(&failure.applicability) {
            if shape.is_static == instance_receiver {
                continue;
            }
            if let Some(record) = shape.model_record.as_ref() {
                let mut record = record.as_ref().clone();
                record.rejected = *applicability == JavaExternalApplicability::Inapplicable;
                record.complete = !self.call_shapes_incomplete
                    && *applicability != JavaExternalApplicability::Unknown;
                record.selection_complete =
                    failure.cause != JavaExternalInvocationFailure::Unproven;
                candidates.push(record);
            } else {
                identityless_shapes.push(NativeInvocationShape {
                    parameter_count: shape.parameter_count as usize,
                    variadic: shape.variadic,
                });
            }
        }
        // Inventory-only calls have no model callable family to explain.
        // Keep their existing unresolved diagnostic rather than inventing one.
        (!candidates.is_empty()).then(|| {
            Box::new(ProjectedNativeModelMemberSelection {
                native_target_count: 0,
                candidates,
                identityless_shapes,
                complete: !self.call_shapes_incomplete,
                // Dynamic stops propagate out of java_native_call_argument_types
                // before this invocation is attempted. Unproven here is content,
                // including the deterministic syntax-ancestor depth cutoff.
                outcome: Some(match failure.cause {
                    JavaExternalInvocationFailure::NoApplicable => {
                        NativeInvocationOutcome::NoApplicable
                    }
                    JavaExternalInvocationFailure::Ambiguous => NativeInvocationOutcome::Ambiguous,
                    JavaExternalInvocationFailure::Unproven => NativeInvocationOutcome::Unproven(
                        NativeInvocationContentCause::OpenEvidence,
                    ),
                }),
            })
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    fn invocation_for_argument_types_bound(
        &self,
        instance_receiver: bool,
        actuals: &[TypeRef],
        surface: Option<&JvmExternalDeclarations<'_>>,
        owner_bindings: Option<&std::collections::HashMap<String, TypeRef>>,
    ) -> Result<JavaExternalInvocationSelection<'_>, JavaExternalInvocationAssessment> {
        // Formals equal to every actual's static type mention no owner type
        // variable, so receiver bindings cannot change this exact selection.
        if let Some(selected) = self.exact_shape_for_argument_types(instance_receiver, actuals) {
            return Ok((selected, None));
        }
        let wants_static = !instance_receiver;
        if self.call_shapes_incomplete {
            return Err(JavaExternalInvocationAssessment {
                cause: JavaExternalInvocationFailure::Unproven,
                applicability: vec![JavaExternalApplicability::Unknown; self.call_shapes.len()],
            });
        }
        let mut candidates = Vec::new();
        for shape in &self.call_shapes {
            if shape.is_static != wants_static {
                continue;
            }
            if shape.parameter_count as usize == actuals.len()
                || (shape.variadic
                    && actuals.len() >= shape.parameter_count.saturating_sub(1) as usize)
            {
                candidates.push(shape);
            }
        }
        let substituted = candidates
            .iter()
            .map(|shape| {
                let mut bindings = owner_bindings.cloned().unwrap_or_default();
                for name in &shape.type_parameters {
                    bindings.insert(name.clone(), TypeRef::TypeParameter { name: name.clone() });
                }
                shape
                    .parameters
                    .iter()
                    .map(|formal| {
                        formal
                            .substitute(&bindings, 64)
                            .unwrap_or_else(|| formal.clone())
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let selected = select_java_external_invocation(
            actuals,
            &candidates
                .iter()
                .zip(&substituted)
                .map(|(shape, parameters)| JavaExternalSignature {
                    parameters,
                    variadic: shape.variadic,
                    has_type_parameters: shape.has_type_parameters,
                })
                .collect::<Vec<_>>(),
            surface,
        )
        .map_err(|failure| {
            let mut applicability =
                vec![JavaExternalApplicability::Inapplicable; self.call_shapes.len()];
            for (candidate, verdict) in candidates.iter().zip(failure.applicability) {
                let ordinal = self
                    .call_shapes
                    .iter()
                    .position(|shape| std::ptr::eq(shape, *candidate))
                    .expect("candidate comes from this family");
                applicability[ordinal] = verdict;
            }
            JavaExternalInvocationAssessment {
                cause: failure.cause,
                applicability,
            }
        })?;
        Ok((
            candidates[selected.0],
            (selected.1 != JavaExternalInvocationPhase::Variable
                && candidates[selected.0].variadic)
                .then_some(FixedArrayInvocation),
        ))
    }
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum JavaExternalInvocationPhase {
    Strict,
    Loose,
    Variable,
}

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_semantic::analyzer::semantic::call_conversion::ConversionUnknown;

/// Classify semantic-model arguments for the shared position algebra.
#[cfg(any(test, feature = "test-support"))]
fn java_hop_arguments(
    parameters: Option<&[String]>,
    target: &TypeRef,
) -> Option<Vec<Option<usize>>> {
    let (TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. }) = target else {
        return None;
    };
    Some(
        arguments
            .iter()
            .map(|argument| {
                let TypeRef::TypeParameter { name } = argument else {
                    return None;
                };
                parameters?.iter().position(|parameter| parameter == name)
            })
            .collect(),
    )
}

#[cfg(any(test, feature = "test-support"))]
fn project_java_hop(
    positions: &[usize],
    parameters: Option<&[String]>,
    target: &TypeRef,
) -> Option<Vec<usize>> {
    let arguments = java_hop_arguments(parameters, target);
    brokk_bifrost_jvm::java::type_projection::project_java_hop(
        positions,
        parameters.map(<[String]>::len),
        arguments.as_deref(),
    )
}

#[cfg(any(test, feature = "test-support"))]
fn compose_java_positions<'a>(
    actual_count: usize,
    hops: impl IntoIterator<Item = (Option<&'a [String]>, &'a TypeRef)>,
    last_parameters: Option<&[String]>,
) -> Option<Vec<usize>> {
    let hops = hops
        .into_iter()
        .map(|(parameters, target)| {
            (
                parameters.map(<[String]>::len),
                java_hop_arguments(parameters, target),
            )
        })
        .collect::<Vec<_>>();
    brokk_bifrost_jvm::java::type_projection::compose_java_positions(
        actual_count,
        hops.iter().map(|(count, args)| (*count, args.as_deref())),
        last_parameters.map(<[String]>::len),
    )
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JavaExternalConversion {
    Strict,
    Loose,
    Inapplicable,
    Unknown(ConversionUnknown),
}

/// Select the unique most-specific signature under Java's fixed-arity
/// invocation phases. `None` preserves uncertainty when one of the structured
/// parameter types cannot decide applicability or specificity.
#[cfg(test)]
fn select_java_external_signature(actuals: &[TypeRef], candidates: &[&[TypeRef]]) -> Option<usize> {
    select_java_external_invocation(
        actuals,
        &candidates
            .iter()
            .map(|parameters| JavaExternalSignature {
                parameters,
                variadic: false,
                has_type_parameters: false,
            })
            .collect::<Vec<_>>(),
        None,
    )
    .ok()
    .map(|(selected, _)| selected)
}

struct JavaExternalSignature<'a> {
    parameters: &'a [TypeRef],
    variadic: bool,
    has_type_parameters: bool,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JavaExternalApplicability {
    Applicable,
    Inapplicable,
    Unknown,
}

impl JavaExternalSignature<'_> {
    #[cfg(any(test, feature = "test-support"))]
    fn applicability(
        &self,
        actuals: &[TypeRef],
        phase: JavaExternalInvocationPhase,
        surface: Option<&JvmExternalDeclarations<'_>>,
    ) -> JavaExternalApplicability {
        use crate::analyzer::jvm::external::JavaExternalApplicability::Applicable;

        use crate::analyzer::jvm::external::JavaExternalApplicability::Inapplicable;

        use crate::analyzer::jvm::external::JavaExternalApplicability::Unknown;
        let expanded = phase == JavaExternalInvocationPhase::Variable;
        let minimum = self.parameters.len().saturating_sub(1);
        if expanded {
            if !self.variadic || self.parameters.is_empty() || actuals.len() < minimum {
                return Inapplicable;
            }
        } else if self.parameters.len() != actuals.len() {
            return Inapplicable;
        }
        let tail = if expanded {
            match self.parameters.last() {
                Some(TypeRef::Array { element }) => Some(element.as_ref()),
                _ => return Unknown,
            }
        } else {
            None
        };
        let mut unknown = false;
        for (ordinal, actual) in actuals.iter().enumerate() {
            let formal = if expanded && ordinal >= minimum {
                tail.expect("expanded signature has an element type")
            } else {
                &self.parameters[ordinal]
            };
            match java_external_conversion_in(actual, formal, surface) {
                JavaExternalConversion::Strict => {}
                JavaExternalConversion::Loose if phase != JavaExternalInvocationPhase::Strict => {}
                JavaExternalConversion::Loose | JavaExternalConversion::Inapplicable => {
                    return Inapplicable;
                }
                JavaExternalConversion::Unknown(_) => unknown = true,
            }
        }
        if unknown { Unknown } else { Applicable }
    }

    fn exact_actuals(&self, actuals: &[TypeRef]) -> bool {
        !self.variadic
            && !self.has_type_parameters
            && self.parameters.len() == actuals.len()
            && self
                .parameters
                .iter()
                .zip(actuals)
                .all(|(formal, actual)| java_external_same_static_type(formal, actual))
    }
}

/// Why a complete Java invocation family did not yield one proven selection.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum JavaExternalInvocationFailure {
    NoApplicable,
    Ambiguous,
    Unproven,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug)]
struct JavaExternalInvocationAssessment {
    cause: JavaExternalInvocationFailure,
    applicability: Vec<JavaExternalApplicability>,
}

#[cfg(any(test, feature = "test-support"))]
fn select_java_external_invocation(
    actuals: &[TypeRef],
    candidates: &[JavaExternalSignature<'_>],
    surface: Option<&JvmExternalDeclarations<'_>>,
) -> Result<(usize, JavaExternalInvocationPhase), JavaExternalInvocationAssessment> {
    use crate::analyzer::jvm::external::JavaExternalInvocationPhase::Loose;

    use crate::analyzer::jvm::external::JavaExternalInvocationPhase::Strict;

    use crate::analyzer::jvm::external::JavaExternalInvocationPhase::Variable;
    for phase in [Strict, Loose, Variable] {
        let applicability = candidates
            .iter()
            .map(|candidate| candidate.applicability(actuals, phase, surface))
            .collect::<Vec<_>>();
        let failure = |cause| JavaExternalInvocationAssessment {
            cause,
            applicability: applicability.clone(),
        };
        let mut applicable = Vec::new();
        let mut uncertain = false;
        for (index, verdict) in applicability.iter().enumerate() {
            match verdict {
                JavaExternalApplicability::Applicable => applicable.push(index),
                JavaExternalApplicability::Inapplicable => {}
                JavaExternalApplicability::Unknown => uncertain = true,
            }
        }
        // Unknown applicability in an earlier phase can change whether the
        // later phase is reached; it must not be silently discarded.
        if uncertain {
            return Err(failure(JavaExternalInvocationFailure::Unproven));
        }
        if applicable.is_empty() {
            continue;
        }
        let ranking_arity = if phase == Variable {
            applicable
                .iter()
                .map(|&index| candidates[index].parameters.len())
                .max()
                .unwrap_or(0)
                .max(actuals.len())
        } else {
            actuals.len()
        };
        let expanded_formals = |index: usize| -> Option<Vec<TypeRef>> {
            let candidate = &candidates[index];
            if phase != Variable {
                return Some(candidate.parameters.to_vec());
            }
            let (last, prefix) = candidate.parameters.split_last()?;
            let TypeRef::Array { element } = last else {
                return None;
            };
            Some(
                prefix
                    .iter()
                    .cloned()
                    .chain(std::iter::repeat_n(
                        element.as_ref().clone(),
                        ranking_arity - prefix.len(),
                    ))
                    .collect(),
            )
        };
        let mut maximal = Vec::new();
        for &index in &applicable {
            let formals = expanded_formals(index)
                .ok_or_else(|| failure(JavaExternalInvocationFailure::Unproven))?;
            let mut dominated = false;
            for &other in &applicable {
                if index == other {
                    continue;
                }
                if java_external_more_specific(
                    &expanded_formals(other)
                        .ok_or_else(|| failure(JavaExternalInvocationFailure::Unproven))?,
                    &formals,
                    surface,
                )
                .ok_or_else(|| failure(JavaExternalInvocationFailure::Unproven))?
                {
                    dominated = true;
                    break;
                }
            }
            if !dominated {
                maximal.push(index);
            }
        }
        return match maximal.as_slice() {
            [selected] => Ok((*selected, phase)),
            _ => Err(failure(JavaExternalInvocationFailure::Ambiguous)),
        };
    }
    Err(JavaExternalInvocationAssessment {
        cause: JavaExternalInvocationFailure::NoApplicable,
        applicability: vec![JavaExternalApplicability::Inapplicable; candidates.len()],
    })
}

#[cfg(test)]
fn select_java_external_signature_for_types(
    actuals: &[TypeRef],
    candidates: &[Vec<TypeRef>],
) -> Option<usize> {
    let candidates = candidates.iter().map(Vec::as_slice).collect::<Vec<_>>();
    select_java_external_signature(actuals, &candidates)
}

pub(crate) fn java_external_same_static_type(left: &TypeRef, right: &TypeRef) -> bool {
    let mut pending = vec![(left, right)];
    while let Some((left, right)) = pending.pop() {
        let arguments = match (left, right) {
            (
                TypeRef::Named {
                    name: left,
                    arguments: left_args,
                    ..
                },
                TypeRef::Named {
                    name: right,
                    arguments: right_args,
                    ..
                },
            ) if !left.is_empty() && left != "void" && left == right => {
                Some((left_args, right_args))
            }
            (
                TypeRef::Declared {
                    id: left,
                    arguments: left_args,
                    ..
                },
                TypeRef::Declared {
                    id: right,
                    arguments: right_args,
                    ..
                },
            ) if !left.is_empty() && left == right => Some((left_args, right_args)),
            (TypeRef::Array { element: left }, TypeRef::Array { element: right }) => {
                pending.push((left, right));
                None
            }
            _ => return false,
        };
        if let Some((left, right)) = arguments {
            if left.len() != right.len() {
                return false;
            }
            pending.extend(left.iter().zip(right));
        }
    }
    true
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn java_known_ground_type(ty: &TypeRef) -> bool {
    java_external_open_type_cause(ty, ConversionUnknown::UnresolvedSourceType).is_none()
}

#[cfg(test)]
fn java_external_conversion(actual: &TypeRef, formal: &TypeRef) -> JavaExternalConversion {
    java_external_conversion_in(actual, formal, None)
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn java_external_conversion_in(
    actual: &TypeRef,
    formal: &TypeRef,
    surface: Option<&JvmExternalDeclarations<'_>>,
) -> JavaExternalConversion {
    struct Types<'s, 'a, 't> {
        surface: Option<&'s JvmExternalDeclarations<'a>>,
        terms: std::marker::PhantomData<&'t TypeRef>,
        cause: Option<ConversionUnknown>,
    }
    impl<'t> brokk_bifrost_jvm::java::conversion::JavaConversionTypes for Types<'_, '_, 't> {
        type Type = &'t TypeRef;
        type Error = std::convert::Infallible;
        fn ground(&self, ty: Self::Type) -> bool {
            java_known_ground_type(ty)
        }
        fn same(&self, a: Self::Type, b: Self::Type) -> bool {
            java_external_same_static_type(a, b)
        }
        fn primitive(
            &self,
            ty: Self::Type,
        ) -> Option<brokk_bifrost_jvm::java::primitives::JavaPrimitive> {
            java_external_primitive(ty)
        }
        fn element(&self, ty: Self::Type) -> Option<Self::Type> {
            match ty {
                TypeRef::Array { element } => Some(element),
                _ => None,
            }
        }
        fn name(&self, ty: Self::Type) -> Option<&str> {
            java_external_reference_name(ty)
        }
        fn named(&self, ty: Self::Type) -> bool {
            matches!(ty, TypeRef::Named { .. })
        }
        fn arguments(&self, ty: Self::Type) -> Option<Vec<Self::Type>> {
            match ty {
                TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } => {
                    Some(arguments.iter().collect())
                }
                _ => None,
            }
        }
        fn wildcard(
            &self,
            ty: Self::Type,
        ) -> Option<brokk_bifrost_jvm::java::conversion::JavaWildcard<Self::Type>> {
            use brokk_bifrost_jvm::java::conversion::JavaWildcard;
            match ty {
                TypeRef::Wildcard { variance, bound } => match (variance, bound.as_deref()) {
                    (brokk_bifrost_semantic::analyzer::semantic_model::model::WildcardVariance::Any, _) => Some(JavaWildcard::Any),
                    (brokk_bifrost_semantic::analyzer::semantic_model::model::WildcardVariance::Extends, Some(bound)) => Some(JavaWildcard::Extends(bound)),
                    (brokk_bifrost_semantic::analyzer::semantic_model::model::WildcardVariance::Super, Some(bound)) => Some(JavaWildcard::Super(bound)),
                    _ => None,
                },
                _ => None,
            }
        }
        fn nominal_widening(
            &mut self,
            a: Self::Type,
            b: Self::Type,
        ) -> Result<Option<bool>, Self::Error> {
            let answer = self
                .surface
                .map_or(Err(ConversionUnknown::IncompleteHierarchy), |surface| {
                    surface.java_nominal_widening(a, b)
                });
            match answer {
                Ok(proven) => Ok(Some(proven)),
                Err(cause) => {
                    self.cause = Some(cause);
                    Ok(None)
                }
            }
        }
        fn different_owner_arguments(
            &mut self,
            actual: Self::Type,
            formal: Self::Type,
        ) -> Result<brokk_bifrost_jvm::java::conversion::JavaDifferentOwner, Self::Error> {
            use brokk_bifrost_jvm::java::conversion::JavaDifferentOwner;
            let answer = self
                .surface
                .map_or(Err(ConversionUnknown::IncompleteHierarchy), |surface| {
                    surface.java_different_owner_arguments(actual, formal)
                });
            Ok(match answer {
                Ok(JavaDifferentOwner::Projected(positions)) => {
                    if let TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } =
                        formal
                        && positions.len() != arguments.len()
                    {
                        self.cause = Some(ConversionUnknown::GenericSubstitution);
                    }
                    JavaDifferentOwner::Projected(positions)
                }
                Ok(result) => result,
                Err(cause) => {
                    self.cause = Some(cause);
                    JavaDifferentOwner::Open
                }
            })
        }
        fn boxed_widening(
            &mut self,
            source: brokk_bifrost_jvm::java::primitives::JavaPrimitive,
            target: Self::Type,
        ) -> Result<Option<bool>, Self::Error> {
            let answer =
                self.surface
                    .map_or(Err(ConversionUnknown::IncompleteHierarchy), |surface| {
                        surface.java_nominal_widening(
                            &TypeRef::named(brokk_bifrost_jvm::java::conversion::wrapper_name(
                                source,
                            )),
                            target,
                        )
                    });
            match answer {
                Ok(proven) => Ok(Some(proven)),
                Err(cause) => {
                    self.cause = Some(cause);
                    Ok(None)
                }
            }
        }
    }
    let mut types = Types {
        surface,
        terms: std::marker::PhantomData,
        cause: None,
    };
    match brokk_bifrost_jvm::java::conversion::classify(&mut types, actual, formal) {
        Ok(brokk_bifrost_jvm::java::conversion::JavaConversion::Strict) => {
            JavaExternalConversion::Strict
        }
        Ok(brokk_bifrost_jvm::java::conversion::JavaConversion::Loose) => {
            JavaExternalConversion::Loose
        }
        Ok(brokk_bifrost_jvm::java::conversion::JavaConversion::Inapplicable) => {
            JavaExternalConversion::Inapplicable
        }
        Ok(brokk_bifrost_jvm::java::conversion::JavaConversion::Unknown) => {
            // The shared classifier retains applicability semantics. Keep the
            // structured evidence cause alongside its unknown nominal answer;
            // non-ground or unsupported type forms supply their own cause.
            JavaExternalConversion::Unknown(
                java_external_open_type_cause(actual, ConversionUnknown::UnresolvedSourceType)
                    .or_else(|| {
                        java_external_open_type_cause(
                            formal,
                            ConversionUnknown::UnresolvedTargetType,
                        )
                    })
                    .or(types.cause)
                    .unwrap_or(ConversionUnknown::UnsupportedConversion),
            )
        }
        Err(error) => match error {},
    }
}

#[cfg(any(test, feature = "test-support"))]
fn java_bind_projected_arguments(
    parameters: &[String],
    positions: &[usize],
    arguments: &[TypeRef],
) -> Option<std::collections::HashMap<String, TypeRef>> {
    if arguments.is_empty() || parameters.len() != positions.len() {
        return None;
    }
    for argument in arguments {
        let mut pending = vec![argument];
        while let Some(term) = pending.pop() {
            match term {
                // Unknown is not an exact binding: it would make every
                // selection, return and conversion substitution claim an
                // exact type that the receiver did not establish.
                TypeRef::Wildcard { .. }
                | TypeRef::TypeParameter { .. }
                | TypeRef::Projection { .. }
                | TypeRef::Unknown => return None,
                TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } => {
                    pending.extend(arguments)
                }
                TypeRef::Array { element }
                | TypeRef::ByRef { element, .. }
                | TypeRef::Pointer { element }
                | TypeRef::Slice { element }
                | TypeRef::FixedArray { element, .. }
                | TypeRef::Channel { element, .. } => pending.push(element),
                TypeRef::Map { key, value } => pending.extend([key.as_ref(), value.as_ref()]),
                TypeRef::Tuple { elements } => pending.extend(elements),
                TypeRef::Function { parameters, result } => {
                    pending.extend(parameters.iter().map(|parameter| &parameter.r#type));
                    pending.extend(result.iter().map(Box::as_ref));
                }
            }
        }
    }
    parameters
        .iter()
        .zip(positions)
        .map(|(name, index)| Some((name.clone(), arguments.get(*index)?.clone())))
        .collect()
}

#[cfg(any(test, feature = "test-support"))]
fn java_external_open_type_cause(
    ty: &TypeRef,
    unresolved: ConversionUnknown,
) -> Option<ConversionUnknown> {
    // A standalone type parameter (including an array component) has no
    // supported nominal conversion form. Inside a nominal type's arguments,
    // the missing operation is generic argument substitution instead.
    let mut pending = vec![(ty, ConversionUnknown::UnsupportedConversion)];
    while let Some((ty, open_form)) = pending.pop() {
        match ty {
            TypeRef::Named {
                name, arguments, ..
            } => {
                if name.is_empty() || name == "void" {
                    return Some(unresolved);
                }
                pending.extend(
                    arguments
                        .iter()
                        .map(|argument| (argument, ConversionUnknown::GenericSubstitution)),
                );
            }
            TypeRef::Declared { id, arguments, .. } => {
                if id.is_empty() {
                    return Some(unresolved);
                }
                pending.extend(
                    arguments
                        .iter()
                        .map(|argument| (argument, ConversionUnknown::GenericSubstitution)),
                );
            }
            TypeRef::Array { element } => pending.push((element, open_form)),
            TypeRef::Unknown => return Some(unresolved),
            TypeRef::TypeParameter { .. }
            | TypeRef::Wildcard { .. }
            | TypeRef::Projection { .. } => return Some(open_form),
            _ => return Some(ConversionUnknown::UnsupportedConversion),
        }
    }
    None
}

#[cfg(any(test, feature = "test-support"))]
fn java_external_more_specific(
    left: &[TypeRef],
    right: &[TypeRef],
    surface: Option<&JvmExternalDeclarations<'_>>,
) -> Option<bool> {
    if left.len() != right.len() {
        return None;
    }
    let mut strict = false;
    for (left, right) in left.iter().zip(right) {
        if java_external_same_static_type(left, right) {
            continue;
        }
        match java_external_conversion_in(left, right, surface) {
            JavaExternalConversion::Strict => strict = true,
            JavaExternalConversion::Loose | JavaExternalConversion::Inapplicable => {
                return Some(false);
            }
            JavaExternalConversion::Unknown(_) => return None,
        }
    }
    Some(strict)
}

#[cfg(any(test, feature = "test-support"))]
fn java_external_primitive(
    type_ref: &TypeRef,
) -> Option<brokk_bifrost_jvm::java::primitives::JavaPrimitive> {
    let TypeRef::Named {
        name, arguments, ..
    } = type_ref
    else {
        return None;
    };
    arguments
        .is_empty()
        .then(|| brokk_bifrost_jvm::java::primitives::primitive_for_name(name))
        .flatten()
}

#[cfg(any(test, feature = "test-support"))]
fn java_external_reference_name(type_ref: &TypeRef) -> Option<&str> {
    match type_ref {
        TypeRef::Named { name, .. } => Some(name),
        TypeRef::Declared { id, .. } => Some(id),
        _ => None,
    }
}

impl JvmExternalCallShape {
    fn java_exact_actuals(&self, actuals: &[TypeRef]) -> bool {
        // Type-use nullability is ignored, while declaration IDs and arguments
        // must agree; unknown and type-variable terms never establish equality.
        JavaExternalSignature {
            parameters: &self.parameters,
            variadic: self.variadic,
            has_type_parameters: self.has_type_parameters,
        }
        .exact_actuals(actuals)
    }
}

/// The class name one recorded declared return type spells, or `None` for a
/// form that names no single declaration.
///
/// Shared by the collapsed member and each retained overload so a chained
/// receiver reads the same rule from either (#2454, #3522): only a `Named`,
/// non-empty type names a class the member lookup can continue from.
fn named_return_type_fqn(returns: Option<&TypeRef>) -> Option<&str> {
    match returns? {
        TypeRef::Named { name, .. } if !name.is_empty() => Some(name),
        _ => None,
    }
}

fn callable_member_kind(kind: MemberKind) -> bool {
    matches!(kind, MemberKind::Method | MemberKind::Constructor)
}

fn external_call_shape(
    kind: MemberKind,
    visibility: JvmVisibility,
    is_static: bool,
    signature: Option<&Signature>,
    is_abstract: bool,
    non_overridable: Option<
        brokk_bifrost_analysis::analyzer::semantic_model::NonOverridableEvidence,
    >,
) -> Option<JvmExternalCallShape> {
    if !callable_member_kind(kind) {
        return None;
    }
    let signature = signature?;
    let parameter_count = u32::try_from(signature.parameters.len()).ok()?;
    Some(JvmExternalCallShape {
        visibility,
        model_record: None,
        inventory_identity: None,
        non_overridable,
        is_abstract,
        parameter_count,
        has_type_parameters: !signature.type_parameters.is_empty(),
        type_parameters: signature.type_parameters.clone(),
        parameters: signature
            .parameters
            .iter()
            .map(|parameter| parameter.r#type.clone())
            .collect(),
        is_static,
        variadic: signature
            .parameters
            .iter()
            .any(|parameter| parameter.variadic),
        returns: signature.returns.clone(),
    })
}

/// A callable whose signature or overload family is not fully known cannot
/// support an exact applicability claim. Fields are not callables, so a field
/// that shares the name does not make the method family incomplete.
fn callable_shape_is_incomplete(
    kind: MemberKind,
    signature: Option<&Signature>,
    family_complete: bool,
    shape_recorded: bool,
) -> bool {
    callable_member_kind(kind) && (signature.is_none() || !family_complete || !shape_recorded)
}

/// One overload contribution while a declaration surface is collapsed to a
/// single member name. Later contributions of the same name only add shapes.
struct RetainedExternalMember {
    name: String,
    visibility: JvmVisibility,
    returns: Option<TypeRef>,
    is_static: bool,
    is_constant: bool,
    shape: Option<JvmExternalCallShape>,
    shapes_incomplete: bool,
}

fn retain_external_member(
    members: &mut HashMap<String, JvmExternalMember>,
    owner_fqn: &str,
    owner_package: &str,
    retained: RetainedExternalMember,
) {
    match members.entry(retained.name) {
        std::collections::hash_map::Entry::Vacant(slot) => {
            let name = slot.key().clone();
            slot.insert(JvmExternalMember {
                fqn: qualified_name(owner_fqn, &name),
                declaring_package: owner_package.to_owned(),
                visibility: retained.visibility,
                returns: retained.returns,
                is_static: retained.is_static,
                is_constant: retained.is_constant,
                field_type: None,
                jdk_artifact_sha256: None,
                unshaped_model_records: Vec::new(),
                call_shapes: retained.shape.into_iter().collect(),
                call_shapes_incomplete: retained.shapes_incomplete,
            });
        }
        std::collections::hash_map::Entry::Occupied(mut slot) => {
            let existing = slot.get_mut();
            if let Some(shape) = retained.shape {
                existing.call_shapes.push(shape);
            }
            existing.call_shapes_incomplete |= retained.shapes_incomplete;
        }
    }
}

fn mark_call_shapes_incomplete(members: &mut HashMap<String, JvmExternalMember>) {
    for member in members.values_mut() {
        member.call_shapes_incomplete = true;
    }
}

/// One activated pack symbol as the JVM realm's external declaration, when the
/// symbol is a JVM type at all.
///
/// The package and short name are split out of the declared qualified name
/// exactly as the pack-fact producers in this module already do
/// ([`scala_external_type`]), because a declaration fact carries one dotted
/// name and no separate package field.
fn pack_external_type(
    symbol: &brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbol,
) -> Option<JvmExternalType> {
    if !JVM_SEMANTIC_PACK_LANGUAGES.contains(&symbol.language.as_str()) {
        return None;
    }
    let kind = pack_type_kind(symbol.kind)?;
    let (package_name, short_name) = symbol
        .qualified_name
        .rsplit_once('.')
        .map_or(("", symbol.qualified_name.as_str()), |(package, short)| {
            (package, short)
        });
    (!short_name.is_empty()).then(|| JvmExternalType {
        fqn: symbol.qualified_name.clone(),
        package_name: package_name.to_owned(),
        short_name: short_name.to_owned(),
        kind,
        visibility: semantic_visibility(symbol.visibility),
        is_final: symbol.declaration_is_final(),
        source: JvmExternalDeclarationSource::SemanticPack {
            pack_id: symbol.provenance.pack_id.clone(),
            declaration_id: symbol.id.clone(),
            jdk: symbol.provenance.activation.matched_evidence.ecosystem == "jdk",
        },
    })
}

/// A source language Bifrost can read out of a published `-sources.jar`.
///
/// All three compile to the same classpath, so one archive walk feeds one
/// index. They differ only in how much budget an entry gets and which parser
/// turns it into declarations.
#[derive(Clone, Copy)]
enum SourceJarLanguage {
    Java,
    Scala,
    Kotlin,
}

impl SourceJarLanguage {
    fn for_entry(entry_name: &str) -> Option<Self> {
        if entry_name.ends_with(".java") {
            Some(Self::Java)
        } else if entry_name.ends_with(".scala") {
            Some(Self::Scala)
        } else if entry_name.ends_with(".kt") {
            Some(Self::Kotlin)
        } else {
            // `.kts` build scripts are packaged into some source jars but
            // declare no library API, so they are deliberately skipped.
            None
        }
    }

    fn max_entry_bytes(self) -> u64 {
        match self {
            Self::Java => MAX_SOURCE_ENTRY_BYTES,
            // Scala and Kotlin entries run the language's whole declaration
            // walk rather than Java's targeted class-like scan, so they get a
            // tighter per-entry budget.
            Self::Scala | Self::Kotlin => MAX_ANALYZER_SOURCE_ENTRY_BYTES,
        }
    }

    fn source_types(
        self,
        artifact_path: &Path,
        source_path: &str,
        source: &str,
    ) -> Vec<JvmExternalType> {
        match self {
            Self::Java => source_types(artifact_path, source_path, source),
            Self::Scala => unreachable!("Scala source JARs are indexed from semantic pack facts"),
            Self::Kotlin => kotlin_source_types(artifact_path, source_path, source),
        }
    }
}

#[allow(dead_code)]
impl JvmExternalType {
    /// Whether an activated JDK pack declared this type in a `java.*` package.
    ///
    /// Only the JDK's built-in loaders define a `java.*` class
    /// (`ClassLoader.preDefineClass`), so no jar on the class path or module
    /// path can supply or split such a package, unless the build configures a
    /// platform override (see [`JvmExternalDeclarations::override_possible`]).
    /// `javax.*` and `jdk.*` are protected only when their module is resolved
    /// for the analyzed code, which the index does not model.
    pub(crate) fn is_unshadowable_jdk(&self) -> bool {
        matches!(
            self.source,
            JvmExternalDeclarationSource::SemanticPack { jdk: true, .. }
        ) && (self.package_name == "java" || self.package_name.starts_with("java."))
    }

    pub(crate) fn package_name(&self) -> &str {
        &self.package_name
    }

    pub(crate) fn short_name(&self) -> &str {
        &self.short_name
    }

    pub(crate) fn kind(&self) -> JvmExternalTypeKind {
        self.kind
    }

    pub(crate) fn visibility(&self) -> JvmVisibility {
        self.visibility
    }

    pub(crate) fn source(&self) -> &JvmExternalDeclarationSource {
        &self.source
    }

    pub(crate) fn fqn(&self) -> &str {
        &self.fqn
    }

    fn is_accessible_from_package(&self, package_name: &str) -> bool {
        is_visible_from_package(self.visibility, &self.package_name, package_name)
    }
}

/// Whether a declaration of `visibility` sitting in `declaring_package` is
/// visible to code compiled in `access_package`.
///
/// One rule for types and members, because the JVM applies one: a `protected`
/// declaration is also visible to a subtype, which this deliberately does not
/// admit, so the answer understates what is reachable and never overstates it.
fn is_visible_from_package(
    visibility: JvmVisibility,
    declaring_package: &str,
    access_package: &str,
) -> bool {
    visibility == JvmVisibility::Public
        || (matches!(
            visibility,
            JvmVisibility::Protected | JvmVisibility::PackagePrivate
        ) && declaring_package == access_package)
}

/// Whether `member` declared in an external supertype is inheritable by a
/// subtype in `subtype_package` (JLS 8.5, 6.6.1).
pub(crate) fn is_external_inheritable_by_package(
    member: &JvmExternalType,
    subtype_package: &str,
) -> bool {
    match member.visibility() {
        JvmVisibility::Public | JvmVisibility::Protected => true,
        JvmVisibility::PackagePrivate => member.package_name() == subtype_package,
        JvmVisibility::Private => false,
    }
}

fn open_artifact_file(path: &Path) -> Option<File> {
    let metadata = path.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > MAX_ARTIFACT_BYTES {
        return None;
    }
    File::open(path).ok()
}

fn can_read_entry(
    entry_size: u64,
    max_entry_bytes: u64,
    max_total_bytes: u64,
    total_bytes: &mut u64,
) -> bool {
    if entry_size > max_entry_bytes {
        return false;
    }
    let Some(next_total) = total_bytes.checked_add(entry_size) else {
        return false;
    };
    if next_total > max_total_bytes {
        return false;
    }
    *total_bytes = next_total;
    true
}

#[cfg(test)]
fn resolve_configured_artifacts(
    config: &JvmExternalDependencies,
    project_root: &Path,
) -> Vec<ResolvedJvmArtifact> {
    resolve_configured_artifacts_traced(config, project_root, None).0
}

fn resolve_configured_artifacts_traced(
    config: &JvmExternalDependencies,
    project_root: &Path,
    mut trace: Option<&mut ResolutionTrace>,
) -> (
    Vec<ResolvedJvmArtifact>,
    brokk_bifrost_core::hash::HashSet<String>,
) {
    let mut unavailable_coordinates = brokk_bifrost_core::hash::HashSet::default();
    let mut artifacts = Vec::new();
    for artifact in &config.artifact_paths {
        let resolved = resolve_explicit_artifact(artifact, project_root);
        for path in std::iter::once(resolved.artifact_path.as_path())
            .chain(resolved.source_artifact_path.as_deref())
        {
            let metadata = fs::metadata(path);
            report_path_observation(path, PathObservationOp::Stat, &stat_observation(&metadata));
            if let Some(ResolutionTrace { steps, .. }) = trace.as_deref_mut() {
                record_external_probe(steps, path, ExternalProbeOperation::File, &metadata);
            }
        }
        artifacts.push(resolved);
    }

    let repository_roots = repository_roots(config);
    let gradle_cache_roots = gradle_cache_roots(config);
    for coordinate in &config.coordinates {
        let mut coordinate_steps = Vec::new();
        let mut source_only_fallback = None;
        let mut binary_resolved = false;
        for root in &repository_roots {
            if let Some(artifact) =
                resolve_coordinate_traced(root, coordinate, Some(&mut coordinate_steps))
            {
                if is_source_jar(&artifact.artifact_path) {
                    source_only_fallback.get_or_insert(artifact);
                } else {
                    artifacts.push(artifact);
                    binary_resolved = true;
                    break;
                }
            }
        }
        if !binary_resolved {
            for root in &gradle_cache_roots {
                let gradle_artifacts =
                    resolve_gradle_coordinate_traced(root, coordinate, Some(&mut coordinate_steps));
                if !gradle_artifacts.is_empty() {
                    if gradle_artifacts
                        .iter()
                        .any(|artifact| !is_source_jar(&artifact.artifact_path))
                    {
                        binary_resolved = true;
                        artifacts.extend(gradle_artifacts);
                        break;
                    }
                    if source_only_fallback.is_none() {
                        source_only_fallback = gradle_artifacts.into_iter().next();
                    }
                }
            }
        }
        if !binary_resolved && let Some(source_only) = source_only_fallback {
            artifacts.push(source_only);
        }
        if coordinate_steps
            .iter()
            .any(|step| matches!(step.outcome, ExternalProbeOutcome::Unreadable))
        {
            unavailable_coordinates.insert(jvm_coordinate_id(coordinate));
        }
        if let Some(trace) = trace.as_deref_mut() {
            let first_step = trace.steps.len();
            trace.steps.extend(coordinate_steps);
            trace
                .coordinate_steps
                .push((coordinate.clone(), first_step..trace.steps.len()));
        }
    }

    let mut seen = brokk_bifrost_core::hash::HashSet::default();
    artifacts.retain(|artifact| {
        seen.insert((
            artifact.artifact_path.clone(),
            artifact.source_artifact_path.clone(),
        ))
    });
    (artifacts, unavailable_coordinates)
}

fn resolve_explicit_artifact(
    artifact: &JvmExternalArtifact,
    project_root: &Path,
) -> ResolvedJvmArtifact {
    ResolvedJvmArtifact {
        artifact_path: resolve_path(project_root, &artifact.artifact_path),
        source_artifact_path: artifact
            .source_artifact_path
            .as_ref()
            .map(|path| resolve_path(project_root, path)),
        coordinate: artifact.coordinate.clone(),
        origin: match artifact.origin {
            JvmExternalArtifactOrigin::Explicit => JvmDependencyOrigin::ExplicitPath,
            JvmExternalArtifactOrigin::MavenReport => JvmDependencyOrigin::MavenReport,
            JvmExternalArtifactOrigin::GradleReport => JvmDependencyOrigin::GradleReport,
        },
    }
}

fn maven_coordinate_jar_names(coordinate: &JvmMavenCoordinate) -> (String, String) {
    (
        format!("{}-{}.jar", coordinate.artifact_id, coordinate.version),
        format!(
            "{}-{}-sources.jar",
            coordinate.artifact_id, coordinate.version
        ),
    )
}

fn local_jvm_artifact_production_request(
    path: &Path,
    artifact_kind: ExternalArtifactKind,
    pack_id: &str,
) -> ArtifactProductionRequest {
    ArtifactProductionRequest {
        path: path.to_path_buf(),
        artifact_kind,
        pack_id: pack_id.to_owned(),
        pack_version: env!("CARGO_PKG_VERSION").to_owned(),
        ecosystem: "maven".to_owned(),
        compatibility: Compatibility {
            bifrost: None,
            toolchains: Vec::new(),
        },
        activation: vec![ActivationSelector {
            production_input_digest: None,
            package: None,
            module: None,
            toolchain: Some(NameSelector {
                name: "jvm".to_owned(),
                version: None,
            }),
            targets: Vec::new(),
            configurations: Vec::new(),
            artifact_sha256: None,
        }],
        provenance: Provenance {
            rust_artifact_approximation: None,
            source: "local dependency artifact".to_owned(),
            revision: None,
        },
        license: "NOASSERTION".to_owned(),
        safety: Safety {
            generated_code_only: false,
            review_required: false,
        },
    }
}

#[cfg(test)]
fn resolve_coordinate(
    repository_root: &Path,
    coordinate: &JvmMavenCoordinate,
) -> Option<ResolvedJvmArtifact> {
    resolve_coordinate_traced(repository_root, coordinate, None)
}

fn resolve_coordinate_traced(
    repository_root: &Path,
    coordinate: &JvmMavenCoordinate,
    mut trace: Option<&mut Vec<ExternalPathProbe>>,
) -> Option<ResolvedJvmArtifact> {
    if !is_safe_maven_coordinate(coordinate) {
        return None;
    }

    let canonical_root = repository_root.canonicalize();
    report_path_observation(
        repository_root,
        PathObservationOp::Canonicalize,
        &canonicalize_observation(&canonical_root),
    );
    if let Some(steps) = trace.as_deref_mut() {
        record_external_probe(
            steps,
            repository_root,
            ExternalProbeOperation::Canonicalize,
            &canonical_root,
        );
    }
    let repository_root = canonical_root.ok()?;
    let mut directory = repository_root.clone();
    for segment in coordinate.group_id.split('.') {
        directory.push(segment);
    }
    directory.push(&coordinate.artifact_id);
    directory.push(&coordinate.version);

    let (jar_name, sources_name) = maven_coordinate_jar_names(coordinate);
    let binary_candidate = directory.join(jar_name);
    let binary_result = binary_candidate.canonicalize();
    report_path_observation(
        &binary_candidate,
        PathObservationOp::Canonicalize,
        &canonicalize_observation(&binary_result),
    );
    if let Some(steps) = trace.as_deref_mut() {
        record_external_probe(
            steps,
            &binary_candidate,
            ExternalProbeOperation::Canonicalize,
            &binary_result,
        );
    }
    let binary_path = binary_result
        .ok()
        .filter(|path| path.starts_with(&repository_root))
        .filter(|path| {
            let metadata = fs::metadata(path);
            report_path_observation(path, PathObservationOp::Stat, &stat_observation(&metadata));
            if let Some(steps) = trace.as_deref_mut() {
                record_external_probe(steps, path, ExternalProbeOperation::File, &metadata);
            }
            metadata.as_ref().is_ok_and(|metadata| metadata.is_file())
        });
    let source_candidate = directory.join(sources_name);
    let source_result = source_candidate.canonicalize();
    report_path_observation(
        &source_candidate,
        PathObservationOp::Canonicalize,
        &canonicalize_observation(&source_result),
    );
    if let Some(steps) = trace.as_deref_mut() {
        record_external_probe(
            steps,
            &source_candidate,
            ExternalProbeOperation::Canonicalize,
            &source_result,
        );
    }
    let source_path = source_result
        .ok()
        .filter(|path| path.starts_with(&repository_root))
        .filter(|path| {
            let metadata = fs::metadata(path);
            report_path_observation(path, PathObservationOp::Stat, &stat_observation(&metadata));
            if let Some(steps) = trace {
                record_external_probe(steps, path, ExternalProbeOperation::File, &metadata);
            }
            metadata.as_ref().is_ok_and(|metadata| metadata.is_file())
        });
    let artifact_path = binary_path
        .clone()
        .or_else(|| source_path.as_ref().map(|_| source_candidate.clone()))?;
    let source_artifact_path = binary_path.and(source_path);
    Some(ResolvedJvmArtifact {
        artifact_path,
        source_artifact_path,
        coordinate: Some(coordinate.clone()),
        origin: JvmDependencyOrigin::MavenRepository,
    })
}

fn is_safe_maven_coordinate(coordinate: &JvmMavenCoordinate) -> bool {
    !coordinate.group_id.is_empty()
        && coordinate
            .group_id
            .split('.')
            .all(is_safe_maven_path_segment)
        && is_safe_maven_path_segment(&coordinate.artifact_id)
        && is_safe_maven_path_segment(&coordinate.version)
}

fn is_safe_maven_path_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && !segment.contains('/')
        && !segment.contains('\\')
}

fn is_source_jar(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with("-sources.jar"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KotlinArchiveClassification {
    Present,
    Absent,
    Incomplete,
    Capped(&'static str, u64),
    Malformed,
}

/// Reads one jar for classification and reports what the read observed, so
/// a carried evidence is verified against the same bytes: a `File` key (with
/// the metadata identity taken before the read, unless racy), an `AbsentFile`,
/// or an `OverBudgetFile`. Anything else cannot be reproduced and refuses.
fn classification_archive(
    path: &Path,
    cancellation: Option<&CancellationToken>,
) -> Result<ZipArchive<Cursor<Vec<u8>>>, KotlinArchiveClassification> {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        refuse_external_discovery_reads();
        return Err(KotlinArchiveClassification::Incomplete);
    }
    if !path.is_absolute() {
        // Its meaning depends on the process directory.
        refuse_external_discovery_reads();
    }
    // Taken before any identity or byte is observed.
    let observed_at = std::time::SystemTime::now();
    let size = match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => metadata.len(),
        Ok(_) => {
            refuse_external_discovery_reads();
            return Err(KotlinArchiveClassification::Incomplete);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            report_external_discovery_read(ExternalDiscoveryRead::AbsentFile {
                absolute_path: path.to_path_buf(),
            });
            return Err(KotlinArchiveClassification::Absent);
        }
        Err(_) => {
            refuse_external_discovery_reads();
            return Err(KotlinArchiveClassification::Incomplete);
        }
    };
    let identity = brokk_bifrost_core::content_digest::metadata_change_identity(path)
        .ok()
        .flatten();
    let limits = ArtifactProducerLimits {
        max_artifact_bytes: MAX_ARTIFACT_BYTES,
        ..ArtifactProducerLimits::default()
    };
    let artifact = read_exact_artifact_while(path, &limits, || {
        cancellation.is_some_and(CancellationToken::is_cancelled)
    })
    .map_err(|diagnostic| {
        if diagnostic.code == "limit.artifact_bytes" {
            report_external_discovery_read(ExternalDiscoveryRead::OverBudgetFile {
                absolute_path: path.to_path_buf(),
                size,
            });
            KotlinArchiveClassification::Capped("MAX_ARTIFACT_BYTES", MAX_ARTIFACT_BYTES)
        } else {
            refuse_external_discovery_reads();
            KotlinArchiveClassification::Incomplete
        }
    })?;
    if path.is_absolute() {
        report_external_discovery_read(ExternalDiscoveryRead::file_with_identity(
            path,
            artifact.bytes(),
            identity,
            observed_at,
        ));
    }
    match zip_directory_status(artifact.bytes()) {
        ZipDirectoryStatus::Valid => {}
        ZipDirectoryStatus::Invalid => return Err(KotlinArchiveClassification::Malformed),
        ZipDirectoryStatus::Exceeded => {
            return Err(KotlinArchiveClassification::Capped(
                "MAX_ARCHIVE_ENTRIES = 10000 or MAX_CENTRAL_DIRECTORY_BYTES",
                32 * 1024 * 1024,
            ));
        }
    }
    ZipArchive::new(Cursor::new(artifact.into_bytes()))
        .map_err(|_| KotlinArchiveClassification::Malformed)
}

fn classify_kotlin_source(
    path: &Path,
    cancellation: Option<&CancellationToken>,
) -> KotlinArchiveClassification {
    let mut archive = match classification_archive(path, cancellation) {
        Ok(archive) => archive,
        Err(classification) => return classification,
    };
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return KotlinArchiveClassification::Capped(
            "MAX_ARCHIVE_ENTRIES",
            MAX_ARCHIVE_ENTRIES as u64,
        );
    }
    for index in 0..archive.len() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return KotlinArchiveClassification::Incomplete;
        }
        let Ok(entry) = archive.by_index(index) else {
            return KotlinArchiveClassification::Incomplete;
        };
        let Ok(name) = entry.name() else {
            return KotlinArchiveClassification::Incomplete;
        };
        if name.ends_with(".kt") {
            return KotlinArchiveClassification::Present;
        }
    }
    KotlinArchiveClassification::Absent
}

fn classify_kotlin_metadata(
    path: &Path,
    cancellation: Option<&CancellationToken>,
) -> KotlinArchiveClassification {
    // Classification gates which producer reads the jar, so it must reach the
    // end of any archive that producer can read: the same entry, per-class and
    // total-byte bounds. A tighter bound here refused every pure-Java jar of
    // more than 1,024 classes as possibly Kotlin (#7473: javax:javaee-api:6.0
    // has 1,830), so its declarations were never produced.
    let mut archive = match classification_archive(path, cancellation) {
        Ok(archive) => archive,
        Err(classification) => return classification,
    };
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return KotlinArchiveClassification::Capped(
            "MAX_ARCHIVE_ENTRIES",
            MAX_ARCHIVE_ENTRIES as u64,
        );
    }
    let mut bytes_read = 0u64;
    let mut incomplete = false;
    let mut malformed = false;
    let mut capped = false;
    for index in 0..archive.len() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return KotlinArchiveClassification::Incomplete;
        }
        let Ok(mut entry) = archive.by_index(index) else {
            incomplete = true;
            continue;
        };
        let name = match entry.name() {
            Ok(name) => name,
            Err(_) => {
                incomplete = true;
                continue;
            }
        };
        if !name.ends_with(".class") || name.ends_with("module-info.class") {
            continue;
        }
        if bytes_read.saturating_add(entry.size()) > MAX_TOTAL_ARCHIVE_BYTES {
            return if incomplete {
                KotlinArchiveClassification::Incomplete
            } else {
                KotlinArchiveClassification::Capped(
                    "MAX_TOTAL_ARCHIVE_BYTES",
                    MAX_TOTAL_ARCHIVE_BYTES,
                )
            };
        }
        if entry.size() > MAX_CLASS_ENTRY_BYTES {
            capped = true;
            continue;
        }
        bytes_read = bytes_read.saturating_add(entry.size());
        let mut bytes = Vec::with_capacity(entry.size() as usize);
        if entry
            .by_ref()
            .take(MAX_CLASS_ENTRY_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .is_err()
        {
            incomplete = true;
            continue;
        }
        if bytes.len() as u64 > MAX_CLASS_ENTRY_BYTES {
            capped = true;
            continue;
        }
        let Ok(class_file) = jclassfile::class_file::parse(&bytes) else {
            malformed = true;
            continue;
        };
        if class_file.attributes().iter().any(|attribute| {
            let annotations = match attribute {
                Attribute::RuntimeVisibleAnnotations { annotations, .. }
                | Attribute::RuntimeInvisibleAnnotations { annotations } => annotations,
                _ => return false,
            };
            annotations.iter().any(|annotation| {
                matches!(
                    class_file
                        .constant_pool()
                        .get(annotation.type_index() as usize),
                    Some(ConstantPool::Utf8 { value }) if value == "Lkotlin/Metadata;"
                )
            })
        }) {
            return KotlinArchiveClassification::Present;
        }
    }
    if incomplete {
        KotlinArchiveClassification::Incomplete
    } else if capped {
        KotlinArchiveClassification::Capped("MAX_CLASS_ENTRY_BYTES", MAX_CLASS_ENTRY_BYTES)
    } else if malformed {
        KotlinArchiveClassification::Malformed
    } else {
        KotlinArchiveClassification::Absent
    }
}

fn repository_roots(config: &JvmExternalDependencies) -> Vec<PathBuf> {
    if !config.repository_roots.is_empty() {
        return config.repository_roots.clone();
    }

    home_dir()
        .map(|home| vec![home.join(".m2").join("repository")])
        .unwrap_or_default()
}

fn gradle_cache_roots(config: &JvmExternalDependencies) -> Vec<PathBuf> {
    if !config.gradle_cache_roots.is_empty() {
        return config.gradle_cache_roots.clone();
    }

    std::env::var_os("GRADLE_USER_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .map(|root| root.join("caches").join("modules-2").join("files-2.1"))
        .or_else(|| {
            home_dir().map(|home| {
                home.join(".gradle")
                    .join("caches")
                    .join("modules-2")
                    .join("files-2.1")
            })
        })
        .into_iter()
        .collect()
}

fn resolve_gradle_coordinate_traced(
    cache_root: &Path,
    coordinate: &JvmMavenCoordinate,
    mut trace: Option<&mut Vec<ExternalPathProbe>>,
) -> Vec<ResolvedJvmArtifact> {
    if !is_safe_maven_coordinate(coordinate) {
        return Vec::new();
    }
    let canonical_root = cache_root.canonicalize();
    report_path_observation(
        cache_root,
        PathObservationOp::Canonicalize,
        &canonicalize_observation(&canonical_root),
    );
    if let Some(steps) = trace.as_deref_mut() {
        record_external_probe(
            steps,
            cache_root,
            ExternalProbeOperation::Canonicalize,
            &canonical_root,
        );
    }
    let Ok(cache_root) = canonical_root else {
        return Vec::new();
    };
    let coordinate_directory = cache_root
        .join(&coordinate.group_id)
        .join(&coordinate.artifact_id)
        .join(&coordinate.version);
    let listing = list_names(&coordinate_directory);
    report_path_observation(
        &coordinate_directory,
        PathObservationOp::ListNames,
        &list_observation(&listing),
    );
    if let Some(steps) = trace.as_deref_mut() {
        record_external_probe(
            steps,
            &coordinate_directory,
            ExternalProbeOperation::List,
            &listing,
        );
    }
    let Ok(hash_directories) = listing else {
        return Vec::new();
    };

    let mut jars = Vec::new();
    for hash_directory in hash_directories {
        let hash_path = coordinate_directory.join(&hash_directory.name);
        // The listing carries the entry kind, so this probe cannot fail.
        if let Some(steps) = trace.as_deref_mut() {
            record_external_probe(
                steps,
                &hash_path,
                ExternalProbeOperation::File,
                &Ok::<(), std::io::Error>(()),
            );
        }
        if hash_directory.kind != ListedKind::Directory {
            continue;
        }
        let listing = list_names(&hash_path);
        report_path_observation(
            &hash_path,
            PathObservationOp::ListNames,
            &list_observation(&listing),
        );
        if let Some(steps) = trace.as_deref_mut() {
            record_external_probe(steps, &hash_path, ExternalProbeOperation::List, &listing);
        }
        let Ok(entries) = listing else {
            continue;
        };
        for entry in entries {
            let path = hash_path.join(&entry.name);
            if path.extension().is_none_or(|extension| extension != "jar") {
                continue;
            }
            let canonical = path.canonicalize();
            report_path_observation(
                &path,
                PathObservationOp::Canonicalize,
                &canonicalize_observation(&canonical),
            );
            if let Some(steps) = trace.as_deref_mut() {
                record_external_probe(
                    steps,
                    &path,
                    ExternalProbeOperation::Canonicalize,
                    &canonical,
                );
            }
            let Some(path) = canonical.ok().filter(|path| path.starts_with(&cache_root)) else {
                continue;
            };
            let metadata = fs::metadata(&path);
            report_path_observation(&path, PathObservationOp::Stat, &stat_observation(&metadata));
            let is_file = metadata.is_ok_and(|metadata| metadata.is_file());
            if let Some(steps) = trace.as_deref_mut() {
                steps.push(ExternalPathProbe {
                    path: path.clone(),
                    operation: ExternalProbeOperation::File,
                    outcome: if is_file {
                        ExternalProbeOutcome::Found
                    } else {
                        ExternalProbeOutcome::Absent
                    },
                });
            }
            if is_file {
                jars.push(path);
            }
        }
    }
    jars.sort();
    jars.dedup();

    let (expected_binary, expected_sources) = maven_coordinate_jar_names(coordinate);
    let sources = jars
        .iter()
        .find(|path| {
            path.file_name()
                .is_some_and(|name| name == expected_sources.as_str())
        })
        .cloned();
    let exact_binaries: Vec<_> = jars
        .iter()
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name == expected_binary.as_str())
        })
        .cloned()
        .collect();
    let binaries = exact_binaries;
    if binaries.is_empty() {
        return sources
            .into_iter()
            .map(|artifact_path| ResolvedJvmArtifact {
                artifact_path,
                source_artifact_path: None,
                coordinate: Some(coordinate.clone()),
                origin: JvmDependencyOrigin::GradleCache,
            })
            .collect();
    }
    binaries
        .into_iter()
        .map(|artifact_path| ResolvedJvmArtifact {
            artifact_path,
            source_artifact_path: sources.clone(),
            coordinate: Some(coordinate.clone()),
            origin: JvmDependencyOrigin::GradleCache,
        })
        .collect()
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
        })
}

fn source_types(artifact_path: &Path, source_path: &str, source: &str) -> Vec<JvmExternalType> {
    let Some(tree) = parse_tree(source) else {
        return Vec::new();
    };
    let root = tree.root_node();
    let package_name = determine_package_name(root, source);
    let mut result = Vec::new();
    let mut stack = Vec::new();
    for index in (0..root.named_child_count()).rev() {
        let Some(child) = root.named_child(index) else {
            continue;
        };
        if is_class_like_declaration_kind(child.kind()) {
            stack.push((
                child,
                None::<String>,
                None::<JvmVisibility>,
                JvmVisibility::PackagePrivate,
            ));
        }
    }

    while let Some((node, parent_short_name, parent_visibility, default_visibility)) = stack.pop() {
        let Some(name_node) = node.child_by_field_name("name") else {
            continue;
        };
        let simple_name = node_text(name_node, source).trim();
        if simple_name.is_empty() {
            continue;
        }

        let short_name = parent_short_name
            .as_deref()
            .map(|parent| format!("{parent}.{simple_name}"))
            .unwrap_or_else(|| simple_name.to_string());
        let declared_visibility = source_visibility(node, default_visibility);
        let visibility = parent_visibility
            .map(|parent| restrict_visibility(declared_visibility, parent))
            .unwrap_or(declared_visibility);
        if visibility != JvmVisibility::Private {
            result.push(JvmExternalType {
                fqn: qualified_name(&package_name, &short_name),
                package_name: package_name.clone(),
                short_name: short_name.clone(),
                kind: source_kind(node.kind()),
                visibility,
                is_final: None,
                source: JvmExternalDeclarationSource::SourceJar {
                    artifact_path: artifact_path.to_path_buf(),
                    source_path: source_path.to_string(),
                },
            });
        }

        let child_default_visibility = if is_interface_like_node(node.kind()) {
            JvmVisibility::Public
        } else {
            JvmVisibility::PackagePrivate
        };
        let Some(body) = node.child_by_field_name("body") else {
            continue;
        };
        for child in class_like_body_children_rev(body) {
            if is_class_like_declaration_kind(child.kind()) {
                stack.push((
                    child,
                    Some(short_name.clone()),
                    Some(visibility),
                    child_default_visibility,
                ));
            }
        }
    }

    result
}

/// Public Kotlin types declared by one `.kt` entry of a source jar.
///
/// Kotlin identities are already source-level (issue #1236): no `FooKt` file
/// facade, no `$` encoding, companions spelled by their declared name. The
/// declaration walk therefore yields exactly the names a consumer would write,
/// and no normalization step is needed the way Scala's `$`-suffixed object
/// identities require one.
///
/// A file whose tree contains a parse error is skipped entirely, matching the
/// Scala path: a source jar is untrusted input, and a partially-recovered tree
/// can name types the library does not actually export, which would make an
/// unknown name look resolvable.
fn kotlin_source_types(
    artifact_path: &Path,
    source_path: &str,
    source: &str,
) -> Vec<JvmExternalType> {
    let mut parser = Parser::new();
    parser
        .set_language(&brokk_bifrost_jvm::kotlin::language::LANGUAGE.into())
        .expect("tree-sitter Kotlin language must load");
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    if tree.root_node().has_error() {
        return Vec::new();
    }

    let synthetic_file = ProjectFile::new(std::env::temp_dir(), "external.kt");
    let parsed =
        brokk_bifrost_jvm::kotlin::declarations::parse_kotlin_file(&synthetic_file, source, &tree);
    parsed
        .declarations()
        .iter()
        .filter(|declaration| declaration.is_class() && !declaration.is_synthetic())
        .filter_map(|declaration| {
            let node = kotlin_source_declaration_node(&tree, &parsed, declaration)?;
            let visibility = kotlin_external_visibility(node, source)?;
            let kind = kotlin_external_kind(node)?;
            let short_name = declaration.short_name().to_string();
            (!short_name.is_empty()).then(|| JvmExternalType {
                fqn: declaration.fq_name(),
                package_name: declaration.package_name().to_string(),
                short_name,
                kind,
                visibility,
                is_final: None,
                source: JvmExternalDeclarationSource::SourceJar {
                    artifact_path: artifact_path.to_path_buf(),
                    source_path: source_path.to_string(),
                },
            })
        })
        // Source JARs are untrusted input. The index is deliberately
        // best-effort, so stopping at a bounded number of public Kotlin types
        // is preferable to retaining an arbitrarily large declaration set.
        .take(MAX_ANALYZER_SOURCE_TYPES)
        .collect()
}

fn kotlin_source_declaration_node<'tree>(
    tree: &'tree tree_sitter::Tree,
    parsed: &brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
    declaration: &brokk_bifrost_core::analyzer::model::CodeUnit,
) -> Option<tree_sitter::Node<'tree>> {
    let range = parsed.declaration_ranges(declaration).first()?;
    let mut node = tree
        .root_node()
        .descendant_for_byte_range(range.start_byte, range.end_byte)?;
    loop {
        if brokk_bifrost_jvm::kotlin::declarations::KOTLIN_CLASS_LIKE_KINDS.contains(&node.kind()) {
            return Some(node);
        }
        node = node.parent()?;
    }
}

/// The visibility a Kotlin declaration contributes to the shared index, or
/// `None` when it contributes nothing.
///
/// `internal` restricts a declaration to its own compilation module, so from
/// the perspective of code consuming a published artifact it is exactly as
/// invisible as `private` — neither belongs in the index at all.
fn kotlin_external_visibility(node: tree_sitter::Node<'_>, source: &str) -> Option<JvmVisibility> {
    use brokk_bifrost_jvm::kotlin::declarations::KotlinDeclaredVisibility;
    match brokk_bifrost_jvm::kotlin::declarations::kotlin_declared_visibility(node, source) {
        KotlinDeclaredVisibility::Public => Some(JvmVisibility::Public),
        // Kotlin has no package-private tier; `protected` is modelled with the
        // index's nearest same-package-only tier so a consumer in another
        // package cannot resolve it.
        KotlinDeclaredVisibility::Protected => Some(JvmVisibility::Protected),
        KotlinDeclaredVisibility::Internal | KotlinDeclaredVisibility::Private => None,
    }
}

fn kotlin_external_kind(node: tree_sitter::Node<'_>) -> Option<JvmExternalTypeKind> {
    use brokk_bifrost_jvm::kotlin::declarations::KotlinClassLikeKind;
    Some(
        match brokk_bifrost_jvm::kotlin::declarations::kotlin_class_like_kind(node)? {
            KotlinClassLikeKind::Interface => JvmExternalTypeKind::Interface,
            KotlinClassLikeKind::Enum => JvmExternalTypeKind::Enum,
            KotlinClassLikeKind::Annotation => JvmExternalTypeKind::Annotation,
            // An `object` is a class with exactly one instance; the index only
            // answers "does this type name exist", so the distinction between
            // an object and a class carries no information here.
            KotlinClassLikeKind::Class | KotlinClassLikeKind::Object => JvmExternalTypeKind::Class,
        },
    )
}

fn source_visibility(
    node: tree_sitter::Node<'_>,
    default_visibility: JvmVisibility,
) -> JvmVisibility {
    match explicit_java_source_visibility(node) {
        Some(DeclaredVisibility::Public) => JvmVisibility::Public,
        Some(DeclaredVisibility::Protected) => JvmVisibility::Protected,
        Some(DeclaredVisibility::Private) => JvmVisibility::Private,
        _ => default_visibility,
    }
}

/// One class to assemble into a test class JAR: its binary name, the binary
/// name of its superclass, and the members it declares (#1900).
///
/// Binary names use the `/` separator the class-file format itself uses, for
/// example `com/example/probe/Registry`, because that is what the bytes hold.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub struct TestClassFile<'a> {
    #[doc(hidden)]
    pub internal_name: &'a str,
    #[doc(hidden)]
    pub super_internal_name: &'a str,
    #[doc(hidden)]
    pub methods: &'a [TestClassMethod<'a>],
    /// Emit the `InnerClasses` attribute a compiler writes for a class nested
    /// inside another and declared `private`. Real JARs are full of these, and
    /// the index deliberately publishes none of them, so a fixture needs one to
    /// show that a deliberate exclusion is not a failed read.
    #[doc(hidden)]
    pub private_nested: bool,
}

/// One public method of a [`TestClassFile`]. `descriptor` is the JVM method
/// descriptor, for example `(Ljava/lang/String;)V` for a method taking one
/// `String` and returning nothing.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub struct TestClassMethod<'a> {
    #[doc(hidden)]
    pub name: &'a str,
    #[doc(hidden)]
    pub descriptor: &'a str,
    #[doc(hidden)]
    pub is_static: bool,
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn probe_registry_base_class_files() -> [TestClassFile<'static>; 2] {
    [
        TestClassFile {
            internal_name: "com/example/probe/Registry",
            super_internal_name: "com/example/probe/BaseRegistry",
            methods: &[TestClassMethod {
                name: "register",
                descriptor: "(Ljava/lang/String;)V",
                is_static: true,
            }],
            private_nested: false,
        },
        TestClassFile {
            internal_name: "com/example/probe/BaseRegistry",
            super_internal_name: "java/lang/Object",
            methods: &[TestClassMethod {
                name: "reset",
                descriptor: "()V",
                is_static: true,
            }],
            private_nested: false,
        },
    ]
}

/// The bytes of a minimal, valid `.class` file for `class`.
///
/// Bifrost's JVM tests normally compile fixtures with `javac`, and skip
/// themselves when no JDK is installed. A skipped test proves nothing, and the
/// member surface this file indexes is read out of class files, so the #1900
/// acceptance needs a class JAR that exists on every machine. Emitting the
/// bytes directly is the only way to get one without a JDK.
///
/// This writes only what the class-file format requires of a declaration: the
/// magic number, a class-file version, a constant pool holding the two class
/// names and each method's name and descriptor, the access flags, and one
/// method table entry per method with no attributes. There is no bytecode,
/// because nothing here executes; `jclassfile` parses it exactly as it parses a
/// compiled class, which is what the index reads.
#[cfg(test)]
pub(crate) fn test_class_file_bytes(class: &TestClassFile<'_>) -> Vec<u8> {
    let methods = class
        .methods
        .iter()
        .map(|method| if method.is_static { 0x0009 } else { 0x0001 })
        .collect::<Vec<_>>();
    test_class_file_bytes_with_access(
        class,
        TestClassAccess {
            class: 0x0021,
            methods: &methods,
            interfaces: &[],
        },
    )
}

/// Class-file header values for a deterministic binary fixture. These are
/// declaration data, including abstract/interface bits, rather than inferred
/// from the presence or absence of bytecode.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub struct TestClassAccess<'a> {
    pub class: u16,
    pub methods: &'a [u16],
    pub interfaces: &'a [&'a str],
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn test_class_file_bytes_with_access(
    class: &TestClassFile<'_>,
    access: TestClassAccess<'_>,
) -> Vec<u8> {
    test_class_file_bytes_with_signatures(class, access, None, &[])
}

/// What a generic declaration adds to a [`TestClassFile`]: the attributes and
/// tables javac writes for `Concrete extends ListLike<String>` and that the
/// class-file hierarchy producer reads. Signatures are JVMS 4.7.9.1 strings and
/// are written verbatim, so a fixture can also carry a malformed one.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
#[derive(Clone, Copy, Default)]
pub struct TestClassGenerics<'a> {
    #[doc(hidden)]
    pub is_interface: bool,
    /// Emit ACC_FINAL on the class (#10572).
    #[doc(hidden)]
    pub is_final: bool,
    #[doc(hidden)]
    pub interfaces: &'a [&'a str],
    #[doc(hidden)]
    pub signature: Option<&'a str>,
    /// The `Signature` attribute of each method, parallel to `methods`. Shorter
    /// than `methods` means the remaining methods have none.
    #[doc(hidden)]
    pub method_signatures: &'a [&'a str],
}

/// [`test_class_file_bytes_with_access`] with a class `Signature` attribute and
/// one per method (the first `method_signatures.len()` methods).
#[cfg(any(test, feature = "test-support"))]
fn test_class_file_bytes_with_signatures(
    class: &TestClassFile<'_>,
    access: TestClassAccess<'_>,
    signature: Option<&str>,
    method_signatures: &[&str],
) -> Vec<u8> {
    assert_eq!(class.methods.len(), access.methods.len());
    const CONSTANT_UTF8: u8 = 1;
    const CONSTANT_CLASS: u8 = 7;
    const CLASS_FILE_MAJOR_VERSION: u16 = 52; // Java 8

    let mut pool = Vec::new();
    let mut next_index = 1u16;
    // The constant pool is indexed by a `u16`, so a class declaring thousands
    // of methods only fits when repeated strings are shared. Interning is also
    // what a compiler emits, so the bytes stay ordinary.
    let mut interned: std::collections::HashMap<String, u16> = std::collections::HashMap::new();
    let mut utf8_index = |pool: &mut Vec<u8>, next_index: &mut u16, value: &str| -> u16 {
        if let Some(index) = interned.get(value) {
            return *index;
        }
        pool.push(CONSTANT_UTF8);
        pool.extend_from_slice(&(value.len() as u16).to_be_bytes());
        pool.extend_from_slice(value.as_bytes());
        let index = *next_index;
        *next_index += 1;
        interned.insert(value.to_owned(), index);
        index
    };
    let this_name_index = utf8_index(&mut pool, &mut next_index, class.internal_name);
    pool.push(CONSTANT_CLASS);
    pool.extend_from_slice(&this_name_index.to_be_bytes());
    let this_class_index = next_index;
    next_index += 1;
    let super_name_index = utf8_index(&mut pool, &mut next_index, class.super_internal_name);
    pool.push(CONSTANT_CLASS);
    pool.extend_from_slice(&super_name_index.to_be_bytes());
    // JVMS 4.1: Object alone has no superclass.
    let super_class_index = if class.internal_name == "java/lang/Object" {
        0
    } else {
        next_index
    };
    next_index += 1;
    let mut method_indexes = Vec::with_capacity(class.methods.len());
    for method in class.methods {
        let name_index = utf8_index(&mut pool, &mut next_index, method.name);
        let descriptor_index = utf8_index(&mut pool, &mut next_index, method.descriptor);
        method_indexes.push((name_index, descriptor_index));
    }
    let mut interfaces = Vec::with_capacity(access.interfaces.len());
    for name in access.interfaces {
        let name_index = utf8_index(&mut pool, &mut next_index, name);
        pool.push(CONSTANT_CLASS);
        pool.extend_from_slice(&name_index.to_be_bytes());
        interfaces.push(next_index);
        next_index += 1;
    }
    let method_signature_indexes = method_signatures
        .iter()
        .map(|signature| utf8_index(&mut pool, &mut next_index, signature))
        .collect::<Vec<_>>();
    let inner_classes_index = class
        .private_nested
        .then(|| utf8_index(&mut pool, &mut next_index, "InnerClasses"));
    let signature_name_index = (signature.is_some() || !method_signatures.is_empty())
        .then(|| utf8_index(&mut pool, &mut next_index, "Signature"));
    let class_signature_index =
        signature.map(|signature| utf8_index(&mut pool, &mut next_index, signature));

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&CLASS_FILE_MAJOR_VERSION.to_be_bytes());
    bytes.extend_from_slice(&next_index.to_be_bytes());
    bytes.extend_from_slice(&pool);
    bytes.extend_from_slice(&access.class.to_be_bytes());
    bytes.extend_from_slice(&this_class_index.to_be_bytes());
    bytes.extend_from_slice(&super_class_index.to_be_bytes());
    bytes.extend_from_slice(&(interfaces.len() as u16).to_be_bytes());
    for interface in interfaces {
        bytes.extend_from_slice(&interface.to_be_bytes());
    }
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&(class.methods.len() as u16).to_be_bytes());
    let signature_attribute = |bytes: &mut Vec<u8>, signature_index: u16| {
        let name_index = signature_name_index.expect("a signature interned its attribute name");
        bytes.extend_from_slice(&name_index.to_be_bytes());
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&signature_index.to_be_bytes());
    };
    for (ordinal, (flags, (name_index, descriptor_index))) in
        access.methods.iter().zip(method_indexes).enumerate()
    {
        bytes.extend_from_slice(&flags.to_be_bytes());
        bytes.extend_from_slice(&name_index.to_be_bytes());
        bytes.extend_from_slice(&descriptor_index.to_be_bytes());
        match method_signature_indexes.get(ordinal) {
            Some(signature_index) => {
                bytes.extend_from_slice(&1u16.to_be_bytes());
                signature_attribute(&mut bytes, *signature_index);
            }
            None => bytes.extend_from_slice(&0u16.to_be_bytes()),
        }
    }
    let attribute_count =
        u16::from(inner_classes_index.is_some()) + u16::from(class_signature_index.is_some());
    bytes.extend_from_slice(&attribute_count.to_be_bytes());
    if let Some(signature_index) = class_signature_index {
        signature_attribute(&mut bytes, signature_index);
    }
    // One `InnerClasses` entry naming this very class as a private nested
    // class: inner class, no outer, no simple name, `ACC_PRIVATE`.
    if let Some(name_index) = inner_classes_index {
        const ACC_PRIVATE_NESTED: u16 = 0x0002;

        bytes.extend_from_slice(&name_index.to_be_bytes());
        bytes.extend_from_slice(&10u32.to_be_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&this_class_index.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&ACC_PRIVATE_NESTED.to_be_bytes());
    }
    bytes
}

/// Write `classes` into a class JAR at `path`, one entry per class named after
/// its binary name, exactly as `jar cf` would lay them out.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn write_test_class_jar(path: &Path, classes: &[TestClassFile<'_>]) {
    let classes = classes
        .iter()
        .map(|class| (class, TestClassGenerics::default()))
        .collect::<Vec<_>>();
    write_test_generic_class_jar(path, &classes);
}

/// [`write_test_class_jar`] for classes that carry generic attributes.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn write_test_generic_class_jar(
    path: &Path,
    classes: &[(&TestClassFile<'_>, TestClassGenerics<'_>)],
) {
    use std::io::Write;

    let file = File::create(path).expect("create the fixture class jar");
    let mut jar = zip::ZipWriter::new(file);
    for (class, generics) in classes {
        jar.start_file(
            format!("{}.class", class.internal_name),
            brokk_bifrost_analysis::test_support::zip_helpers::deterministic_file_options(
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            ),
        )
        .expect("start a fixture class entry");
        let methods = class
            .methods
            .iter()
            .map(|method| if method.is_static { 0x0009 } else { 0x0001 })
            .collect::<Vec<_>>();
        let access = TestClassAccess {
            // ACC_PUBLIC | ACC_SUPER, or ACC_PUBLIC | ACC_INTERFACE | ACC_ABSTRACT.
            class: match (generics.is_interface, generics.is_final) {
                (true, _) => 0x0601,
                (false, false) => 0x0021,
                // ACC_PUBLIC | ACC_FINAL | ACC_SUPER.
                (false, true) => 0x0031,
            },
            methods: &methods,
            interfaces: generics.interfaces,
        };
        jar.write_all(&test_class_file_bytes_with_signatures(
            class,
            access,
            generics.signature,
            generics.method_signatures,
        ))
        .expect("write a fixture class entry");
    }
    jar.finish().expect("finish the fixture class jar");
}

fn restrict_visibility(declared: JvmVisibility, enclosing: JvmVisibility) -> JvmVisibility {
    let to_visibility = |visibility| match visibility {
        JvmVisibility::Public => Visibility::Public,
        JvmVisibility::Protected => Visibility::Protected,
        JvmVisibility::PackagePrivate => Visibility::Package,
        JvmVisibility::Private => Visibility::Private,
    };
    semantic_visibility(restrict_semantic_visibility(
        to_visibility(declared),
        to_visibility(enclosing),
    ))
}

fn is_interface_like_node(kind: &str) -> bool {
    matches!(
        kind,
        "interface_declaration" | "annotation_type_declaration"
    )
}

fn source_kind(kind: &str) -> JvmExternalTypeKind {
    source_type_kind(kind)
        .map(semantic_type_kind)
        .unwrap_or(JvmExternalTypeKind::Class)
}

fn qualified_name(package_name: &str, short_name: &str) -> String {
    brokk_bifrost_core::analyzer::common::qualify_dotted_name(package_name, short_name)
}

fn enclosing_type_fqns(external_type: &JvmExternalType) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = external_type.short_name.as_str();
    while let Some((owner, _)) = current.rsplit_once('.') {
        result.push(qualified_name(&external_type.package_name, owner));
        current = owner;
    }
    result
}

/// Model declaration IDs and source declaration IDs occupy distinct domains.
/// Canonicalize model type declarations before comparing them with scope-proven
/// nominal actuals; an unresolved or ambiguous model ID remains unknown.
pub(crate) fn normalize_jvm_model_type_ref(
    overlay: Option<
        &brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay,
    >,
    reference: &TypeRef,
) -> TypeRef {
    let mut result = reference.clone();
    let mut pending = vec![&mut result];
    while let Some(term) = pending.pop() {
        if let TypeRef::Declared {
            id,
            arguments,
            nullable,
        } = term
        {
            let selected = overlay.and_then(|overlay| {
                let matched = overlay.symbols_with_id(id);
                if matches!(matched.disposition, brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelOverlayDisposition::Open(_)) { return None; }
                let [symbol] = matched.records.as_slice() else { return None; };
                (symbol.kind.is_type_declaration() && !symbol.provenance.ambiguous)
                    .then(|| symbol.qualified_name.clone())
            });
            *term = match selected {
                Some(name) => TypeRef::Named {
                    name,
                    arguments: std::mem::take(arguments),
                    nullable: *nullable,
                },
                None => TypeRef::Unknown,
            };
        }
        match term {
            TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } => {
                pending.extend(arguments)
            }
            TypeRef::Array { element }
            | TypeRef::ByRef { element, .. }
            | TypeRef::Pointer { element }
            | TypeRef::Slice { element }
            | TypeRef::FixedArray { element, .. }
            | TypeRef::Channel { element, .. } => pending.push(element),
            TypeRef::Map { key, value } => {
                pending.push(key);
                pending.push(value);
            }
            TypeRef::Wildcard { bound, .. } => pending.extend(bound.as_deref_mut()),
            TypeRef::Tuple { elements } => pending.extend(elements),
            TypeRef::Function { parameters, result } => {
                pending.extend(parameters.iter_mut().map(|parameter| &mut parameter.r#type));
                pending.extend(result.as_deref_mut());
            }
            TypeRef::Projection { .. } | TypeRef::Unknown | TypeRef::TypeParameter { .. } => {}
        }
    }
    result
}

/// Reuse the invocation phases for both member selection and conversion rows.
/// The expanded layout names one formal term per written positional actual.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn select_java_external_model_invocation(
    actuals: &[TypeRef],
    signatures: &[brokk_bifrost_analysis::analyzer::semantic_model::Signature],
    surface: &JvmExternalDeclarations<'_>,
) -> Option<brokk_bifrost_analysis::analyzer::usages::call_conversion::ModelInvocationSelection> {
    let parameters = signatures
        .iter()
        .map(|signature| {
            signature
                .parameters
                .iter()
                .map(|parameter| {
                    normalize_jvm_model_type_ref(surface.packs.as_deref(), &parameter.r#type)
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let shapes = signatures
        .iter()
        .zip(&parameters)
        .map(|(signature, parameters)| JavaExternalSignature {
            parameters,
            has_type_parameters: !signature.type_parameters.is_empty(),
            variadic: signature
                .parameters
                .iter()
                .any(|parameter| parameter.variadic),
        })
        .collect::<Vec<_>>();
    let mut exact = shapes
        .iter()
        .enumerate()
        .filter(|(_, shape)| shape.exact_actuals(actuals));
    if let Some((selected, _)) = exact.next() {
        return exact
            .next()
            .is_none()
            .then(|| (selected, parameters[selected].clone(), None));
    }
    // Method inference is not a ground-formal conversion. Keep its candidate
    // visible rather than erasing method type parameters from applicability.
    if signatures
        .iter()
        .any(|signature| !signature.type_parameters.is_empty())
    {
        return None;
    }
    let (selected, phase) =
        select_java_external_invocation(actuals, &shapes, Some(surface)).ok()?;
    let formals = &parameters[selected];
    let layout = if phase == JavaExternalInvocationPhase::Variable {
        let (TypeRef::Array { element }, prefix) = formals.split_last()? else {
            return None;
        };
        prefix
            .iter()
            .cloned()
            .chain(std::iter::repeat_n(
                element.as_ref().clone(),
                actuals.len() - prefix.len(),
            ))
            .collect()
    } else {
        formals.clone()
    };
    Some((
        selected,
        layout,
        (phase != JavaExternalInvocationPhase::Variable && shapes[selected].variadic)
            .then_some(FixedArrayInvocation),
    ))
}

/// A budget-charged digest cache for tests that run JDK discovery with no store.
#[cfg(test)]
pub(super) fn test_digests() -> ContentDigestCache {
    ContentDigestCache::new(
        &brokk_bifrost_core::retention_budget::RetentionBudget::for_test_capacity(64 << 20),
    )
}

/// JDK discovery followed by the pinning step, as activation and the JDK
/// question run it, with no `PATH` to search.
#[cfg(test)]
fn discover_and_pin_jdk(
    config: &JvmAnalyzerConfig,
    project_root: &Path,
    java_home: Option<OsString>,
    digests: &ContentDigestCache,
) -> JdkDiscovery {
    discover_and_pin_jdk_with_path(config, project_root, java_home, None, digests)
}

/// As [`discover_and_pin_jdk`], with the `PATH` value discovery would read.
/// Tests inject it so none of them mutates the process environment.
#[cfg(test)]
fn discover_and_pin_jdk_with_path(
    config: &JvmAnalyzerConfig,
    project_root: &Path,
    java_home: Option<OsString>,
    path: Option<OsString>,
    digests: &ContentDigestCache,
) -> JdkDiscovery {
    let mut discovery =
        discover_jdk_semantic_pack_dependencies(config, project_root, java_home, path);
    assert!(pin_jdk_discovery(&mut discovery, digests, &Default::default(), None).is_continue());
    discovery
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(unix)]
    #[brokk_bifrost_test_macros::hardwon(
        "#12975: restoring a rewritten JAR mtime reused an index from before its ctime changed"
    )]
    fn strong_artifact_rewrite_with_restored_mtime_misses_process_memo() {
        use std::os::unix::fs::MetadataExt;
        let temp = tempfile::tempdir().unwrap();
        let jar = temp.path().join("dep.jar");
        let write = |name| {
            write_test_class_jar(
                &jar,
                &[TestClassFile {
                    internal_name: "example/Dep",
                    super_internal_name: "java/lang/Object",
                    methods: &[TestClassMethod {
                        name,
                        descriptor: "()V",
                        is_static: false,
                    }],
                    private_nested: false,
                }],
            )
        };
        write("first");
        // The memo trusts a stat identity only outside the racy window
        // (#13537); age the first write so the reuse assertion below tests the
        // ctime change, not the racy-stat refusal.
        age_past_racy_window();
        let metadata = fs::metadata(&jar).unwrap();
        assert_ne!(metadata.ino(), 0, "test requires a strong inode identity");
        let mut config = JvmAnalyzerConfig::default();
        config
            .external_dependencies
            .artifact_paths
            .push(JvmExternalArtifact {
                artifact_path: jar.clone(),
                ..Default::default()
            });
        let project = TestProject::new(temp.path(), Language::Java);
        let first = JvmExternalDeclarationIndex::build_for_project(&config, &project);
        let repeated = JvmExternalDeclarationIndex::build_for_project(&config, &project);
        assert!(
            Arc::ptr_eq(&first, &repeated),
            "unchanged strong artifact reuses the memo"
        );
        // Leave even a one-second ctime tick before rewriting, independently
        // of the host filesystem's timestamp precision.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        write("other");
        fs::File::options()
            .write(true)
            .open(&jar)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(metadata.modified().unwrap()))
            .unwrap();
        let changed = fs::metadata(&jar).unwrap();
        assert_eq!(changed.len(), metadata.len());
        assert_eq!(changed.modified().unwrap(), metadata.modified().unwrap());
        assert_eq!(changed.ino(), metadata.ino());
        assert_ne!(
            (changed.ctime(), changed.ctime_nsec()),
            (metadata.ctime(), metadata.ctime_nsec())
        );
        let second = JvmExternalDeclarationIndex::build_for_project(&config, &project);
        assert!(
            !Arc::ptr_eq(&first, &second),
            "ctime rewrite reused the old index"
        );
        // A second path cannot hit the first path's memo entry. Keep the
        // discovery surface identical so its diagnostics are compared too.
        let fresh_path = temp.path().join("fresh.jar");
        fs::copy(&jar, &fresh_path).unwrap();
        let mut fresh_config = config.clone();
        fresh_config.external_dependencies.artifact_paths[0].artifact_path = fresh_path;
        let fresh = JvmExternalDeclarationIndex::build_for_project(&fresh_config, &project);
        assert_ne!(
            first.dispatch_behavior_identity(),
            second.dispatch_behavior_identity()
        );
        assert_eq!(
            second.dispatch_behavior_identity(),
            fresh.dispatch_behavior_identity()
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12975: on a platform without change-time identity, the JVM index decoded bytes other than the verified ones"
    )]
    fn weak_artifact_identity_refuses_index_retention() {
        use crate::analyzer::jvm::authority::JvmExternalIndexSlot;
        use brokk_bifrost_analysis::analyzer::capture_query_reads;
        let project = crate::inline_project::InlineTestProject::with_language(Language::Java)
            .file("Caller.java", "class Caller {}")
            .build();
        let temp = tempfile::tempdir().unwrap();
        let jar = temp.path().join("dep.jar");
        write_test_class_jar(
            &jar,
            &[TestClassFile {
                internal_name: "example/Dep",
                super_internal_name: "java/lang/Object",
                methods: &[],
                private_nested: false,
            }],
        );
        let mut config = brokk_bifrost_core::analyzer::config::AnalyzerConfig::default();
        config.jvm.external_dependencies.artifact_paths.push(
            brokk_bifrost_core::analyzer::config::JvmExternalArtifact {
                artifact_path: jar.clone(),
                ..Default::default()
            },
        );
        let base = project.workspace_analyzer(config.clone());
        struct RestoreIdentity;
        impl Drop for RestoreIdentity {
            fn drop(&mut self) {
                FORCED_WEAK_ARTIFACT_IDENTITY.set(None);
            }
        }
        let _restore = RestoreIdentity;
        for weak in [true, false] {
            FORCED_WEAK_ARTIFACT_IDENTITY.set(Some(weak));
            let slot = JvmExternalIndexSlot::new(64 << 20);
            let builds = std::cell::Cell::new(0);
            let sample = || {
                dependency_discovery_sample_with_identity(
                    base.analyzer(),
                    &config.jvm,
                    base.analyzer().project(),
                    |path| {
                        if weak {
                            Ok(None)
                        } else {
                            brokk_bifrost_core::content_digest::file_identity(path)
                        }
                    },
                    |path| artifact_content_digest(base.analyzer(), path),
                )
            };
            let get = || {
                capture_query_reads(base.analyzer(), || slot.get_or_build(
                base.analyzer(),
                (Language::Java, brokk_bifrost_analysis::analyzer::WorkspaceFactFamily::JavaExternalDeclarations),
                sample, sample,
                |_| {},
                || {
                    builds.set(builds.get() + 1);
                    JvmExternalDeclarationIndex::build_for_project(&config.jvm, base.analyzer().project())
                },
            )).0
            };
            let first = get();
            assert_eq!(slot.is_built(), !weak, "weak={weak}: retention");
            let second = get();
            assert_eq!(builds.get(), if weak { 2 } else { 1 });
            assert_eq!(Arc::ptr_eq(&first, &second), !weak);
            let fresh = JvmExternalDeclarationIndex::build_for_project(
                &config.jvm,
                base.analyzer().project(),
            );
            assert!(
                first
                    .resolve_qualified_name("example.Dep", "example")
                    .is_some()
            );
            assert_eq!(
                first.dispatch_behavior_identity(),
                fresh.dispatch_behavior_identity()
            );
            assert_eq!(
                second.dispatch_behavior_identity(),
                fresh.dispatch_behavior_identity()
            );
        }
    }

    #[test]
    #[hardwon(
        "#10572: source and binary composition lost or overstated independent class finality"
    )]
    fn matching_java_source_binary_finality_refines_and_conflicts_withhold() {
        let template: AuthoredSemanticModelPack = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../bifrost-analysis/testdata/semantic-model-packs/declarations-v1.json"
        )))
        .unwrap();
        for (left, right, expected, conflict) in [
            (None, Some(true), Some(true), false),
            (None, Some(false), Some(false), false),
            (Some(true), None, Some(true), false),
            (Some(true), Some(true), Some(true), false),
            (Some(false), Some(false), Some(false), false),
            (Some(true), Some(false), None, true),
            (Some(false), Some(true), None, true),
        ] {
            let mut source = template.clone();
            let mut binary = template.clone();
            source.schema_version = 43;
            binary.schema_version = 43;
            let AuthoredPayload::DeclarationFacts { types, .. } = &mut source.shards[0].payload
            else {
                unreachable!()
            };
            types[0].is_final = left;
            let AuthoredPayload::DeclarationFacts { types, .. } = &mut binary.shards[0].payload
            else {
                unreachable!()
            };
            types[0].is_final = right;
            let mut diagnostics = Vec::new();
            let mut suppressed = SuppressedDiagnostics::default();
            let merged = merge_java_dependency_packs(
                Some(source),
                Some(binary),
                &mut diagnostics,
                &mut suppressed,
                &ArtifactProducerLimits::default(),
            )
            .unwrap();
            let AuthoredPayload::DeclarationFacts { types, .. } = &merged.shards[0].payload else {
                unreachable!()
            };
            assert_eq!(types[0].is_final, expected, "{left:?} + {right:?}");
            assert_eq!(!diagnostics.is_empty(), conflict, "{diagnostics:?}");
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11902: missing generation metadata must not discard explicit JVM artifacts"
    )]
    fn native_missing_membership_preserves_explicit_artifacts() {
        let root = tempfile::tempdir().unwrap();
        let jar = root.path().join("explicit.jar");
        write_test_class_jar(
            &jar,
            &[TestClassFile {
                internal_name: "example/Explicit",
                super_internal_name: "java/lang/Object",
                methods: &[],
                private_nested: false,
            }],
        );
        let host = brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer::Empty(
            brokk_bifrost_analysis::analyzer::workspace::EmptyAnalyzer::new(Arc::new(
                TestProject::new(root.path(), Language::Java),
            )),
        );
        let view =
            brokk_bifrost_analysis::analyzer::workspace::generation_dependency_discovery_project(
                host.analyzer(),
            );
        let mut config = JvmAnalyzerConfig::default();
        config
            .external_dependencies
            .artifact_paths
            .push(JvmExternalArtifact {
                artifact_path: jar,
                source_artifact_path: None,
                coordinate: None,
                origin: JvmExternalArtifactOrigin::Explicit,
            });
        let outcome = resolve_jvm_semantic_pack_dependencies(
            &config,
            view.as_ref(),
            &test_digests(),
            &Default::default(),
            &DependencyPackLimits::default(),
            None,
        );
        assert!(!outcome.complete);
        assert_eq!(outcome.incomplete_reason, Some(brokk_bifrost_analysis::analyzer::semantic_model::DependencyDiscoveryIncompleteReason::GenerationListingUnavailable));
        assert!(!outcome.dependencies.is_empty());
        let index = JvmExternalDeclarationIndex::build_for_project(&config, view.as_ref());
        assert!(
            index
                .resolve_explicit_import("example.Explicit", "app")
                .is_some()
        );
    }
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11902: a cold native JVM index discovered manifests outside its generation"
    )]
    fn native_discovery_keeps_generation_membership() {
        use brokk_bifrost_analysis::analyzer::IAnalyzer;
        use brokk_bifrost_core::analyzer::project::Project;
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("App.java"), "class App {} ").unwrap();
        let mut config = brokk_bifrost_core::analyzer::config::AnalyzerConfig::default();
        config.jvm.dependency_discovery.mode =
            brokk_bifrost_core::analyzer::config::JvmDependencyDiscoveryMode::Metadata;
        let project = Arc::new(TestProject::new(root.path(), Language::Java));
        let control =
            crate::analyzer::JavaAnalyzer::new_with_config(project.clone(), config.clone());
        let cold = crate::analyzer::JavaAnalyzer::new_with_config(project.clone(), config);
        let expected = control.external_declaration_index();
        std::fs::create_dir(root.path().join("nested")).unwrap();
        std::fs::write(root.path().join("nested/pom.xml"), "<project><dependencies><dependency><groupId>missing</groupId><artifactId>late</artifactId><version>1</version></dependency></dependencies></project>").unwrap();
        project.invalidate_cached_file_listing();
        let observed = cold.external_declaration_index();
        assert_eq!(expected.gap_identity(), observed.gap_identity());
        assert_eq!(
            expected.dispatch_behavior_identity(),
            observed.dispatch_behavior_identity()
        );
        let view =
            brokk_bifrost_analysis::analyzer::workspace::generation_dependency_discovery_project(
                &cold,
            );
        assert_eq!(
            view.all_files_shared().unwrap().as_ref(),
            cold.generation_membership().listing().unwrap().0.as_ref()
        );
    }
    #[test]
    fn owner_surface_fixed_limit_is_distinct_from_cycle_and_missing_hierarchy() {
        fn supertype_names(surface: &super::JvmIndexedOwnerSurface) -> Vec<&str> {
            surface.supertypes.iter().map(String::as_str).collect()
        }
        let mut index = super::JvmExternalDeclarationIndex::default();
        for owner in 0..=super::MAX_MEMBER_SURFACE_OWNERS {
            index.members_by_owner.insert(
                owner.to_string(),
                super::JvmIndexedOwnerSurface {
                    supertypes: if owner < super::MAX_MEMBER_SURFACE_OWNERS {
                        vec![(owner + 1).to_string()]
                    } else {
                        vec![]
                    },
                    hierarchy_complete: true,
                    ..Default::default()
                },
            );
        }
        for _ in 0..2 {
            let walk = index.walk_owner_surfaces("0", supertype_names, |_, _| None::<()>);
            assert!(walk.selected.is_none());
            assert_eq!(walk.completion, super::OwnerWalkCompletion::FixedLimit);
        }
        index.members_by_owner.get_mut("0").unwrap().supertypes = vec!["0".into()];
        assert_eq!(
            index
                .walk_owner_surfaces("0", supertype_names, |_, _| None::<()>)
                .completion,
            super::OwnerWalkCompletion::Cycle
        );
        // An owner nobody read is listed with its path, and it does not lower
        // the completion of the surfaces that were read.
        let walk = index.walk_owner_surfaces("missing", supertype_names, |_, _| None::<()>);
        assert_eq!(walk.completion, super::OwnerWalkCompletion::Complete);
        assert_eq!(walk.unread, vec![vec!["missing".to_owned()]]);
    }

    #[test]
    fn java_supertype_argument_projection_table() {
        use super::*;
        use brokk_bifrost_analysis::analyzer::semantic_model::JavaHierarchyWitness;
        use brokk_bifrost_semantic::analyzer::semantic_model::model::{
            HierarchyFact, HierarchyKind,
        };
        let parameter = |name: &str| TypeRef::TypeParameter { name: name.into() };
        let edge = |arguments| HierarchyFact {
            hierarchy_kind: HierarchyKind::Extends,
            target: TypeRef::Named {
                name: "Target".into(),
                arguments,
                nullable: false,
            },
            declaration_ordinal: None,
        };
        let witness = |parameters: Vec<Option<Vec<String>>>, edges: Vec<HierarchyFact>| {
            JavaHierarchyWitness {
                declarations: Vec::new(),
                type_parameters: parameters,
                edges,
            }
        };
        let names = |names: &[&str]| Some(names.iter().map(|name| (*name).into()).collect());
        let cases = [
            (
                witness(
                    vec![names(&["E"]), names(&["E"]), names(&["E"]), names(&["E"])],
                    vec![
                        edge(vec![parameter("E")]),
                        edge(vec![parameter("E")]),
                        edge(vec![parameter("E")]),
                    ],
                ),
                1,
                Some(vec![0]),
            ),
            (
                witness(
                    vec![names(&["A", "B"]), names(&["X", "Y"])],
                    vec![edge(vec![parameter("B"), parameter("A")])],
                ),
                2,
                Some(vec![1, 0]),
            ),
            // A raw edge to a parent that declares a parameter, and a parent
            // read with more parameters than the edge passes, prove nothing.
            (
                witness(vec![names(&["E"]), names(&["E"])], vec![edge(vec![])]),
                1,
                None,
            ),
            (
                witness(
                    vec![names(&["E"]), names(&["A", "B"]), names(&["T"])],
                    vec![edge(vec![parameter("E")]), edge(vec![parameter("A")])],
                ),
                1,
                None,
            ),
            (
                witness(
                    vec![names(&["E"]), names(&["E"])],
                    vec![edge(vec![TypeRef::named("String")])],
                ),
                1,
                None,
            ),
            (
                witness(
                    vec![names(&["E"]), names(&["E"])],
                    vec![edge(vec![TypeRef::Named {
                        name: "Box".into(),
                        arguments: vec![parameter("E")],
                        nullable: false,
                    }])],
                ),
                1,
                None,
            ),
            (
                witness(
                    vec![names(&["E"]), names(&["E"])],
                    vec![edge(vec![parameter("Missing")])],
                ),
                1,
                None,
            ),
            (
                witness(vec![None, names(&["E"])], vec![edge(vec![parameter("E")])]),
                1,
                None,
            ),
            (
                witness(
                    vec![names(&["E"]), names(&["E"])],
                    vec![edge(vec![parameter("E")])],
                ),
                2,
                None,
            ),
        ];
        for (witness, actual_count, expected) in cases {
            assert_eq!(
                JvmExternalDeclarations::project_java_arguments(&witness, actual_count),
                expected
            );
        }
    }
    #[test]
    fn java_receiver_binding_and_substitution_rules() {
        use super::*;
        use brokk_bifrost_analysis::analyzer::semantic_model::WildcardVariance;
        let string = TypeRef::named("java.lang.String");
        let integer = TypeRef::named("java.lang.Integer");
        let generic = TypeRef::TypeParameter {
            name: "CallerT".into(),
        };
        let wildcard = TypeRef::Wildcard {
            variance: WildcardVariance::Any,
            bound: None,
        };
        let cases = [
            (
                vec!["T".into(), "U".into()],
                vec![0, 1],
                vec![string.clone(), integer.clone()],
                true,
            ),
            (
                vec!["T".into(), "U".into()],
                vec![1, 0],
                vec![string.clone(), integer.clone()],
                true,
            ),
            (
                vec!["T".into(), "U".into()],
                vec![0],
                vec![string.clone()],
                false,
            ),
            (vec!["T".into()], vec![0], vec![wildcard], false),
            (
                vec!["T".into()],
                vec![0],
                vec![TypeRef::Array {
                    element: Box::new(generic),
                }],
                false,
            ),
        ];
        for (parameters, positions, arguments, expected) in cases {
            let bindings = java_bind_projected_arguments(&parameters, &positions, &arguments);
            assert_eq!(bindings.is_some(), expected);
            if let Some(bindings) = bindings {
                for (name, index) in parameters.iter().zip(positions) {
                    assert_eq!(
                        TypeRef::TypeParameter { name: name.clone() }.substitute(&bindings, 64),
                        Some(arguments[index].clone())
                    );
                }
            }
        }
        let mut bindings = java_bind_projected_arguments(&["T".into()], &[0], &[string]).unwrap();
        bindings.insert("T".into(), TypeRef::TypeParameter { name: "T".into() });
        assert_eq!(
            TypeRef::TypeParameter { name: "T".into() }.substitute(&bindings, 64),
            Some(TypeRef::TypeParameter { name: "T".into() })
        );
        assert_eq!(
            TypeRef::TypeParameter {
                name: "EnclosingT".into()
            }
            .substitute(&bindings, 64),
            None
        );
    }
    #[test]
    fn selected_production_keys_match_preparation_in_order_and_keep_missing_slots() {
        use super::*;
        use brokk_bifrost_analysis::analyzer::semantic_model::CatalogOptions;
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;
        use brokk_bifrost_analysis::analyzer::semantic_model::dependency::prepare_dependency_semantic_packs;
        use brokk_bifrost_core::analyzer::model::Language;
        use brokk_bifrost_core::analyzer::project::TestProject;

        let root = tempfile::tempdir().unwrap();
        let paths: Vec<_> = ["First", "Second"]
            .into_iter()
            .map(|name| {
                let path = root.path().join(format!("{name}.jar"));
                let class = test_class_file_bytes(&TestClassFile {
                    internal_name: &format!("sample/{name}"),
                    super_internal_name: "java/lang/Object",
                    methods: &[],
                    private_nested: false,
                });
                write_zip_entry(&path, &format!("sample/{name}.class"), &class);
                path
            })
            .collect();
        let project = TestProject::new(root.path(), Language::Java);
        let config = JvmAnalyzerConfig {
            without_project_build: false,
            external_dependencies: JvmExternalDependencies {
                artifact_paths: paths
                    .iter()
                    .map(|path| JvmExternalArtifact {
                        artifact_path: path.clone(),
                        ..JvmExternalArtifact::default()
                    })
                    .collect(),
                ..JvmExternalDependencies::default()
            },
            dependency_discovery:
                brokk_bifrost_core::analyzer::config::JvmDependencyDiscoveryConfig {
                    mode: JvmDependencyDiscoveryMode::Disabled,
                    ..Default::default()
                },
            standard_library_discovery:
                brokk_bifrost_core::analyzer::config::JvmStandardLibraryDiscoveryConfig {
                    discover_java_home: false,
                    ..Default::default()
                },
        };
        let selection =
            JvmExternalDeclarationIndex::select_external_inventory::<std::convert::Infallible>(
                &config,
                &project,
                &manifest_scope(&project, &Default::default()),
                |_| Ok(()),
            )
            .unwrap();
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let dependencies: Vec<_> = selection
            .productions
            .iter()
            .map(|(dependency, _, _)| dependency.clone())
            .collect();
        let prepared = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            &dependencies,
            &DependencyPackLimits::default(),
            None,
        );
        let keys = selection.generated_production_keys();
        assert_eq!(keys.len(), 2);
        assert_eq!(prepared.packs.len(), 2, "{prepared:?}");
        for key in &keys {
            let key = key.as_ref().expect("selected production key");
            // The key must cover the newest schema in the output.
            assert_eq!(
                key.schema_version(),
                brokk_bifrost_semantic::analyzer::semantic_model::CLASS_FINALITY_MIN_SCHEMA_VERSION,
            );
            assert_eq!(
                *key,
                brokk_bifrost_semantic::analyzer::semantic_model::catalog::GeneratedProductionKey::new(
                    key.input_digest(),
                    key.producer_name(),
                    key.producer_version(),
                    brokk_bifrost_semantic::analyzer::semantic_model::CLASS_FINALITY_MIN_SCHEMA_VERSION,
                )
                .unwrap()
            );
        }
        assert_eq!(
            keys,
            prepared
                .packs
                .iter()
                .map(|pack| Some(pack.production.key.clone()))
                .collect::<Vec<_>>()
        );

        assert!(
            selection
                .productions
                .iter()
                .all(|(_, _, key)| key.is_some())
        );
    }

    #[test]
    fn selection_digest_includes_probe_manifest_and_provider() {
        use super::*;
        let mut selection = ExternalInventorySelection {
            preparation_failures: Vec::new(),
            artifacts: vec![SelectedExternalArtifactRecord {
                path: PathBuf::from("lib.jar"),
                kind: ExternalArtifactKind::JavaClassJar,
                provider_id: "provider-a".to_owned(),
            }],
            provider_ids: vec!["provider-a".to_owned()],
            productions: Vec::new(),
            inputs: ExternalInputsConsumed {
                explicit_paths: Vec::new(),
                repository_roots: Vec::new(),
                gradle_cache_roots: Vec::new(),
                home: None,
                userprofile: None,
                gradle_user_home: None,
                coordinates: Vec::new(),
                partial_manifests: Vec::new(),
                resolution_steps: vec![ExternalPathProbe {
                    path: PathBuf::from("missing"),
                    operation: ExternalProbeOperation::File,
                    outcome: ExternalProbeOutcome::Absent,
                }],
                artifact_probes: Vec::new(),
            },
            completeness: ExternalSelectionCompleteness::default(),
            authority_answer_digest: None,
        };
        let baseline = selection.answer_digest(true, true);
        assert_eq!(baseline, selection.answer_digest(true, true));
        selection.inputs.resolution_steps[0].outcome = ExternalProbeOutcome::Unreadable;
        assert_ne!(baseline, selection.answer_digest(true, true));
        selection.inputs.resolution_steps[0].outcome = ExternalProbeOutcome::Absent;
        selection
            .inputs
            .partial_manifests
            .push(PathBuf::from("pom.xml"));
        assert_ne!(baseline, selection.answer_digest(true, true));
        selection.inputs.partial_manifests.clear();
        selection.artifacts[0].provider_id = "provider-b".to_owned();
        assert_ne!(baseline, selection.answer_digest(true, true));
    }

    fn codec_test_inputs() -> ExternalInputsConsumed {
        ExternalInputsConsumed {
            explicit_paths: vec![PathBuf::from("explicit")],
            repository_roots: vec![PathBuf::from("repo-a"), PathBuf::from("repo-b")],
            gradle_cache_roots: vec![PathBuf::from("gradle-a")],
            home: Some(OsString::from("/home/user")),
            userprofile: None,
            gradle_user_home: None,
            coordinates: vec![
                JvmMavenCoordinate {
                    group_id: "g".into(),
                    artifact_id: "a".into(),
                    version: "1".into(),
                },
                JvmMavenCoordinate {
                    group_id: "g".into(),
                    artifact_id: "b".into(),
                    version: "1".into(),
                },
            ],
            partial_manifests: vec![PathBuf::from("a/pom.xml"), PathBuf::from("b/pom.xml")],
            resolution_steps: vec![ExternalPathProbe {
                path: PathBuf::from("repo-a/g"),
                operation: ExternalProbeOperation::List,
                outcome: ExternalProbeOutcome::Found,
            }],
            artifact_probes: vec![PathBuf::from("x.jar"), PathBuf::from("y.jar")],
        }
    }

    fn codec_test_dependency(id: &str) -> ResolvedDependency {
        ResolvedDependency::undeclared_scope(
            id.to_owned(),
            brokk_bifrost_semantic::analyzer::semantic_model::runtime::SemanticModelActivationEvidence {
                language: "java".into(), ecosystem: "maven".into(), package: None,
                module: None, toolchain: None, target: None, configuration: None,
                production_input_digest: None,
verified_raw_artifacts: Vec::new(),
            },
            Vec::new(),
            vec![ResolvedDependencyArtifact::file(
                DependencyArtifactRole::Binary,
                ExternalArtifactKind::JavaClassJar,
                PathBuf::from(format!("{id}.jar")),
            )],
        )
    }

    fn codec_test_selection() -> ExternalInventorySelection {
        let key =
            brokk_bifrost_semantic::analyzer::semantic_model::catalog::GeneratedProductionKey::new(
                "a".repeat(64),
                "producer",
                "1",
                22,
            )
            .unwrap();
        ExternalInventorySelection {
            preparation_failures: Vec::new(),
            artifacts: vec![SelectedExternalArtifactRecord {
                path: PathBuf::from("x.jar"),
                kind: ExternalArtifactKind::JavaClassJar,
                provider_id: "p".to_owned(),
            }],
            productions: vec![
                (
                    codec_test_dependency("one"),
                    vec![SelectedProductionArtifact {
                        role: DependencyArtifactRole::Binary,
                        kind: ExternalArtifactKind::JavaClassJar,
                        module: Some("m".into()),
                        sha256: "s".repeat(64),
                    }],
                    Some(key),
                ),
                (codec_test_dependency("two"), Vec::new(), None),
            ],
            provider_ids: vec!["p".to_owned()],
            inputs: codec_test_inputs(),
            completeness: ExternalSelectionCompleteness::default(),
            authority_answer_digest: None,
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: repaired dependency must invalidate failure selection identities and reads"
    )]
    fn repaired_preparation_failure_changes_selection_and_read_key() {
        use brokk_bifrost_analysis::analyzer::read_ledger::{LookupKind, LookupQuestion, ReadKey};
        use brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest;
        use brokk_bifrost_semantic::analyzer::semantic_model::dependency::{
            DependencyDiscoveryEvidence, DependencyDiscoveryOutcome, DependencyPreparationFailure,
            DependencyPreparationFailureCause, preparation_input_bindings,
        };
        let temp = tempfile::tempdir().unwrap();
        let jar = temp.path().join("dependency.jar");
        std::fs::write(&jar, b"corrupt jar").unwrap();
        let mut dependency = codec_test_dependency("one");
        dependency.artifacts[0].input = ResolvedDependencyArtifactInput::File(jar.clone());
        let discovery = DependencyDiscoveryOutcome::complete(vec![dependency]);
        let bindings =
            preparation_input_bindings(&discovery.dependencies, &Default::default(), None);
        let evidence = DependencyDiscoveryEvidence::from_outcome(&discovery)
            .with_preparation_failures(
                &discovery.dependencies,
                &[DependencyPreparationFailure {
                    dependency_id: "one".into(),
                    cause: DependencyPreparationFailureCause::PackUnavailable,
                }],
                &bindings,
            );
        assert_eq!(evidence.preparation_failures.len(), 1);
        let mut selection = codec_test_selection();
        selection
            .completeness
            .record(ExternalSelectionFailure::DependencyGaps(vec![
                JvmDependencyGap::unresolved("one".to_owned(), Vec::new()),
            ]));
        let unresolved = selection.answer_digest(false, false);
        let providers = selection.provider_ids.clone();
        selection.preparation_failures = evidence.preparation_failures;
        let failed = selection.answer_digest(false, false);
        assert_eq!(selection.provider_ids, providers);
        assert_ne!(unresolved, failed);
        std::fs::write(&jar, b"repaired jar contents").unwrap();
        assert_ne!(
            brokk_bifrost_core::content_digest::metadata_change_identity(&jar)
                .unwrap()
                .unwrap(),
            bindings[0].as_ref().unwrap()[0].1
        );
        let unbound = DependencyDiscoveryEvidence::from_outcome(&discovery)
            .with_preparation_failures(
                &discovery.dependencies,
                &[DependencyPreparationFailure {
                    dependency_id: "one".into(),
                    cause: DependencyPreparationFailureCause::PackUnavailable,
                }],
                &bindings,
            );
        assert!(unbound.has_unbound_preparation_failures());
        let repaired_evidence = DependencyDiscoveryEvidence::from_outcome(&discovery)
            .with_preparation_failures(
                &discovery.dependencies,
                &[],
                &preparation_input_bindings(&discovery.dependencies, &Default::default(), None),
            );
        selection.preparation_failures = repaired_evidence.preparation_failures;
        let repaired = selection.answer_digest(false, false);
        assert_ne!(failed, repaired);
        let key = |digest| {
            ReadKey::Lookup {
                kind: LookupKind::ExternalSelection,
                question: LookupQuestion::ExternalSelection {
                    question_digest: [7; 32],
                },
                digest: StableDigest::from_array(digest),
            }
            .canonical_digest()
        };
        assert_ne!(key(unresolved), key(failed));
        assert_ne!(key(failed), key(repaired));
    }

    fn codec_test_jdk() -> SelectedJdk {
        SelectedJdk {
            inputs: JdkInputsConsumed {
                java_home: Some(OsString::from("/jdk")),
                path: None,
                java_on_path: None,
                candidates: vec![
                    (PathBuf::from("/jdk-a"), true),
                    (PathBuf::from("/jdk"), false),
                ],
                probes: vec![ExternalPathProbe {
                    path: PathBuf::from("/jdk-a"),
                    operation: ExternalProbeOperation::Canonicalize,
                    outcome: ExternalProbeOutcome::Found,
                }],
                complete: true,
            },
            dependencies: vec![codec_test_dependency("jdk-a"), codec_test_dependency("jdk")],
        }
    }

    #[test]
    fn answer_codec_version_complete_and_certified_change_the_digest() {
        let selection = codec_test_selection();
        let current = selection.answer_digest(true, true);
        assert_eq!(current, selection.answer_digest(true, true));
        assert_ne!(current, selection.answer_digest(false, true));
        assert_ne!(current, selection.answer_digest(true, false));
        assert_ne!(
            current,
            selection.answer_digest_in(
                b"bifrost-external-selection-answer:dependencies:v1",
                true,
                true
            )
        );
        let jdk = codec_test_jdk();
        let current = jdk.answer_digest(true, false);
        assert_ne!(current, jdk.answer_digest(false, false));
        assert_ne!(current, jdk.answer_digest(true, true));
        assert_ne!(
            current,
            jdk.answer_digest_in(b"bifrost-external-selection-answer:jdk:v1", true, false)
        );
        // The two answers never share a preimage.
        assert_ne!(
            codec_test_selection().answer_digest(true, false),
            jdk.answer_digest(true, false)
        );
    }

    #[test]
    fn every_selection_field_reaches_the_dependencies_digest() {
        type Mutation = (&'static str, fn(&mut ExternalInventorySelection));
        let mutations: &[Mutation] = &[
            ("artifacts.path", |s| {
                s.artifacts[0].path = PathBuf::from("z.jar")
            }),
            ("artifacts.kind", |s| {
                s.artifacts[0].kind = ExternalArtifactKind::JavaSourceJar
            }),
            ("artifacts.provider_id", |s| {
                s.artifacts[0].provider_id = "q".into()
            }),
            ("completeness.open", |s| {
                s.completeness.record(ExternalSelectionFailure::Discovery)
            }),
            ("completeness.unresolved", |s| {
                s.completeness
                    .record(ExternalSelectionFailure::DependencyGaps(vec![
                        JvmDependencyGap::unresolved("g:a:1".to_owned(), Vec::new()),
                    ]));
            }),
            ("completeness.unresolved.coordinate", |s| {
                s.completeness
                    .record(ExternalSelectionFailure::DependencyGaps(vec![
                        JvmDependencyGap::unresolved("g:b:1".to_owned(), Vec::new()),
                    ]));
            }),
            ("completeness.unresolved.probe", |s| {
                s.completeness
                    .record(ExternalSelectionFailure::DependencyGaps(vec![
                        JvmDependencyGap::unresolved(
                            "g:a:1".to_owned(),
                            vec![JvmAbsentProbe {
                                path: PathBuf::from("absent.jar"),
                                operation: ExternalProbeOperation::File,
                            }],
                        ),
                    ]));
            }),
            ("completeness.listing_omitted", |s| {
                s.completeness
                    .record(ExternalSelectionFailure::ListingOmitted {
                        paths: vec![PathBuf::from("linked")],
                    })
            }),
            ("completeness.listing_omitted.path", |s| {
                s.completeness
                    .record(ExternalSelectionFailure::ListingOmitted {
                        paths: vec![PathBuf::from("other")],
                    })
            }),
            ("completeness.read", |s| {
                s.completeness
                    .record(ExternalSelectionFailure::ArtifactRead(PathBuf::from(
                        "x.jar",
                    )))
            }),
            ("completeness.read.path", |s| {
                s.completeness
                    .record(ExternalSelectionFailure::ArtifactRead(PathBuf::from(
                        "y.jar",
                    )))
            }),
            ("completeness.partial", |s| {
                s.completeness
                    .record(ExternalSelectionFailure::PartialManifest(PathBuf::from(
                        "x.jar",
                    )))
            }),
            ("completeness.unreadable", |s| {
                s.completeness
                    .record(ExternalSelectionFailure::UnreadableProbe(PathBuf::from(
                        "x.jar",
                    )))
            }),
            // A later failure must not replace an earlier one, and the order
            // the selection met them is part of the answer.
            ("completeness.read_then_partial", |s| {
                s.completeness
                    .record(ExternalSelectionFailure::ArtifactRead(PathBuf::from(
                        "x.jar",
                    )));
                s.completeness
                    .record(ExternalSelectionFailure::PartialManifest(PathBuf::from(
                        "x.jar",
                    )));
            }),
            ("completeness.partial_then_read", |s| {
                s.completeness
                    .record(ExternalSelectionFailure::PartialManifest(PathBuf::from(
                        "x.jar",
                    )));
                s.completeness
                    .record(ExternalSelectionFailure::ArtifactRead(PathBuf::from(
                        "x.jar",
                    )));
            }),
            ("inputs.explicit_paths", |s| s.inputs.explicit_paths.clear()),
            ("inputs.repository_roots.order", |s| {
                s.inputs.repository_roots.reverse()
            }),
            ("inputs.gradle_cache_roots", |s| {
                s.inputs.gradle_cache_roots.clear()
            }),
            ("inputs.home", |s| s.inputs.home = None),
            ("inputs.userprofile", |s| {
                s.inputs.userprofile = Some(OsString::from("p"))
            }),
            ("inputs.gradle_user_home", |s| {
                s.inputs.gradle_user_home = Some(OsString::from("g"))
            }),
            ("inputs.coordinates", |s| {
                s.inputs.coordinates.pop();
            }),
            ("inputs.partial_manifests", |s| {
                s.inputs.partial_manifests.clear()
            }),
            ("inputs.resolution_steps.operation", |s| {
                s.inputs.resolution_steps[0].operation = ExternalProbeOperation::File
            }),
            ("inputs.resolution_steps.path", |s| {
                s.inputs.resolution_steps[0].path = PathBuf::from("elsewhere")
            }),
            ("inputs.artifact_probes.order", |s| {
                s.inputs.artifact_probes.reverse()
            }),
            ("productions.order", |s| s.productions.reverse()),
            ("productions.dependency", |s| {
                s.productions[0].0.id = "three".into()
            }),
            ("productions.artifact.role", |s| {
                s.productions[0].1[0].role = DependencyArtifactRole::Runtime
            }),
            ("productions.artifact.kind", |s| {
                s.productions[0].1[0].kind = ExternalArtifactKind::JavaSourceJar
            }),
            ("productions.artifact.module", |s| {
                s.productions[0].1[0].module = None
            }),
            ("productions.artifact.sha256", |s| {
                s.productions[0].1[0].sha256 = "t".repeat(64)
            }),
            ("productions.key", |s| s.productions[0].2 = None),
            ("productions.key.producer_version", |s| {
                s.productions[0].2 = Some(
                    brokk_bifrost_semantic::analyzer::semantic_model::catalog::GeneratedProductionKey::new(
                        "a".repeat(64), "producer", "2", 22,
                    )
                    .unwrap(),
                )
            }),
        ];
        let base = codec_test_selection().answer_digest(true, true);
        let mut seen = std::collections::HashMap::new();
        for (name, mutate) in mutations {
            let mut changed = codec_test_selection();
            mutate(&mut changed);
            let changed = changed.answer_digest(true, true);
            assert_ne!(base, changed, "{name} does not reach the digest");
            if let Some(other) = seen.insert(changed, *name) {
                panic!("{name} and {other} give the same digest");
            }
        }
    }

    /// The replay contract of an incomplete selection, by failure. Only a
    /// pack's partial coverage and an unresolved coordinate are fixed for
    /// unchanged inputs; every other failure may clear on the next attempt, or
    /// is not yet split by reason (#11252), so one of them anywhere in the
    /// selection makes it unreplayable.
    #[test]
    fn only_fixed_dependency_gaps_leave_a_selection_replayable() {
        use brokk_bifrost_semantic::analyzer::semantic_model::dependency::DependencyPreparationFailureCause as Cause;
        let gap = |cause| JvmDependencyGap {
            dependency_id: "g:a:1".to_owned(),
            cause,
            partial_pack_id: None,
        };
        let unresolved = || {
            JvmDependencyGap::unresolved(
                "g:a:1".to_owned(),
                vec![JvmAbsentProbe {
                    path: PathBuf::from("absent.jar"),
                    operation: ExternalProbeOperation::Canonicalize,
                }],
            )
        };
        let preparation = |cause| gap(JvmDependencyGapCause::PreparationFailure(cause));
        let unreadable = || ExternalSelectionFailure::UnreadableProbe(PathBuf::from("blocked"));
        type Case = (&'static str, Vec<ExternalSelectionFailure>, bool);
        let cases: Vec<Case> = vec![
            (
                "discovery",
                vec![ExternalSelectionFailure::Discovery],
                false,
            ),
            (
                "unresolved",
                vec![ExternalSelectionFailure::DependencyGaps(vec![unresolved()])],
                true,
            ),
            (
                "unresolved without probes",
                vec![ExternalSelectionFailure::DependencyGaps(vec![
                    JvmDependencyGap::unresolved("g:a:1".to_owned(), Vec::new()),
                ])],
                true,
            ),
            (
                "partial coverage",
                vec![ExternalSelectionFailure::DependencyGaps(vec![gap(
                    JvmDependencyGapCause::PartialCoverage,
                )])],
                true,
            ),
            (
                "unresolved and partial coverage",
                vec![ExternalSelectionFailure::DependencyGaps(vec![
                    unresolved(),
                    gap(JvmDependencyGapCause::PartialCoverage),
                ])],
                true,
            ),
            (
                "rejected",
                vec![ExternalSelectionFailure::DependencyGaps(vec![preparation(
                    Cause::Rejected,
                )])],
                false,
            ),
            (
                "pack unavailable",
                vec![ExternalSelectionFailure::DependencyGaps(vec![preparation(
                    Cause::PackUnavailable,
                )])],
                false,
            ),
            (
                "producer failed",
                vec![ExternalSelectionFailure::DependencyGaps(vec![preparation(
                    Cause::ProducerFailed,
                )])],
                false,
            ),
            (
                "unresolved and preparation failure",
                vec![ExternalSelectionFailure::DependencyGaps(vec![
                    unresolved(),
                    preparation(Cause::PackUnavailable),
                ])],
                false,
            ),
            (
                "partial manifest",
                vec![ExternalSelectionFailure::PartialManifest("pom.xml".into())],
                false,
            ),
            (
                "artifact read",
                vec![ExternalSelectionFailure::ArtifactRead("a.jar".into())],
                false,
            ),
            ("unreadable probe", vec![unreadable()], false),
            (
                "listing omitted",
                vec![ExternalSelectionFailure::ListingOmitted {
                    paths: vec!["linked".into()],
                }],
                false,
            ),
            (
                "unresolved then unreadable probe",
                vec![
                    ExternalSelectionFailure::DependencyGaps(vec![unresolved()]),
                    unreadable(),
                ],
                false,
            ),
            (
                "unresolved then listing omitted",
                vec![
                    ExternalSelectionFailure::DependencyGaps(vec![unresolved()]),
                    ExternalSelectionFailure::ListingOmitted {
                        paths: vec!["linked".into()],
                    },
                ],
                false,
            ),
        ];
        let mut named = std::collections::BTreeSet::new();
        for (name, failures, replayable) in cases {
            let mut completeness = ExternalSelectionCompleteness::default();
            for failure in failures {
                named.insert(failure.name());
                completeness.record(failure);
            }
            assert!(!completeness.is_complete(), "{name}");
            assert_eq!(completeness.only_replayable_gaps(), replayable, "{name}");
        }
        assert!(ExternalSelectionCompleteness::default().is_complete());
        assert!(!ExternalSelectionCompleteness::default().only_replayable_gaps());
        assert_eq!(
            named.into_iter().collect::<Vec<_>>(),
            [
                "artifact_read",
                "dependency_gaps",
                "discovery",
                "listing_omitted",
                "partial_manifest",
                "unreadable_probe",
            ],
            "every failure variant appears in the table"
        );
    }

    #[test]
    fn every_jdk_field_reaches_the_digest() {
        type Mutation = (&'static str, fn(&mut SelectedJdk));
        let mutations: &[Mutation] = &[
            ("java_home", |j| j.inputs.java_home = None),
            ("candidates.order", |j| j.inputs.candidates.reverse()),
            ("candidates.configured", |j| j.inputs.candidates[1].1 = true),
            ("candidates.path", |j| {
                j.inputs.candidates[0].0 = PathBuf::from("/other")
            }),
            ("probes.outcome", |j| {
                j.inputs.probes[0].outcome = ExternalProbeOutcome::Absent
            }),
            ("probes.operation", |j| {
                j.inputs.probes[0].operation = ExternalProbeOperation::List
            }),
            ("complete", |j| j.inputs.complete = false),
            ("dependencies.order", |j| j.dependencies.reverse()),
            ("dependencies.id", |j| j.dependencies[0].id = "other".into()),
            ("dependencies.artifact.kind", |j| {
                j.dependencies[0].artifacts[0].kind = ExternalArtifactKind::JdkJmodSet
            }),
            ("dependencies.scope", |j| {
                j.dependencies[0].scope =
                    brokk_bifrost_analysis::analyzer::topology::DependencyScope::Test
            }),
        ];
        let base = codec_test_jdk().answer_digest(true, false);
        let mut seen = std::collections::HashMap::new();
        for (name, mutate) in mutations {
            let mut changed = codec_test_jdk();
            mutate(&mut changed);
            let changed = changed.answer_digest(true, false);
            assert_ne!(base, changed, "{name} does not reach the digest");
            if let Some(other) = seen.insert(changed, *name) {
                panic!("{name} and {other} give the same digest");
            }
        }
    }

    /// Where order is not part of the answer, equal selections built in
    /// different input orders give equal digests.
    #[test]
    fn set_valued_selection_inputs_hash_independent_of_order() {
        let base = codec_test_selection().answer_digest(true, true);
        let mut reordered = codec_test_selection();
        reordered.inputs.coordinates.reverse();
        reordered.inputs.partial_manifests.reverse();
        assert_eq!(base, reordered.answer_digest(true, true));
    }

    use crate::analyzer::jvm::external::python_test_support::*;

    use crate::analyzer::jvm::external::*;
    use brokk_bifrost_analysis::analyzer::dependency_support::capture_external_discovery_reads;

    /// A Maven and a Gradle coordinate, a JDK with one JMOD, and the config
    /// that discovers them, rooted in one temporary directory.
    struct CarryFixture {
        root: tempfile::TempDir,
        config: JvmAnalyzerConfig,
    }

    impl CarryFixture {
        fn new() -> Self {
            use brokk_bifrost_core::analyzer::config::JvmStandardLibraryDiscoveryConfig;
            let root = tempfile::tempdir().unwrap();
            let home = root.path().join("jdk");
            fs::create_dir_all(home.join("jmods")).unwrap();
            fs::write(home.join("release"), "JAVA_VERSION=\"21.0.8\"\n").unwrap();
            write_zip_entries(
                &home.join("jmods/java.base.jmod"),
                &[(
                    "classes/module-info.class",
                    &crate::analyzer::jvm::jmod_artifact::test_module_info_class_bytes(
                        &["java/lang"],
                        &[],
                    ),
                )],
            );
            fs::create_dir_all(root.path().join("repo/example/lib/1")).unwrap();
            fs::create_dir_all(root.path().join("gradle/example/g/1/h1")).unwrap();
            write_zip_entry(
                &root.path().join("repo/example/lib/1/lib-1.jar"),
                "a.txt",
                b"binary",
            );
            write_zip_entry(
                &root.path().join("gradle/example/g/1/h1/g-1.jar"),
                "a.txt",
                b"binary",
            );
            let mut config = JvmAnalyzerConfig {
                standard_library_discovery: JvmStandardLibraryDiscoveryConfig {
                    jdk_homes: vec![home],
                    discover_java_home: false,
                    ..Default::default()
                },
                ..JvmAnalyzerConfig::default()
            };
            config.dependency_discovery.mode = JvmDependencyDiscoveryMode::Disabled;
            for artifact_id in ["lib", "g"] {
                config
                    .external_dependencies
                    .coordinates
                    .push(JvmMavenCoordinate::new("example", artifact_id, "1"));
            }
            config.external_dependencies.repository_roots = vec![root.path().join("repo")];
            config.external_dependencies.gradle_cache_roots = vec![root.path().join("gradle")];
            Self { root, config }
        }

        fn path(&self, relative: &str) -> PathBuf {
            self.root.path().join(relative)
        }

        fn evidence(
            &self,
        ) -> brokk_bifrost_analysis::analyzer::semantic_model::DependencyDiscoveryEvidence {
            let project = TestProject::new(self.root.path(), Language::Java);
            let (outcome, reads) = capture_external_discovery_reads(|| {
                resolve_jvm_semantic_pack_dependencies(
                    &self.config,
                    &project,
                    &test_digests(),
                    &Default::default(),
                    &DependencyPackLimits::default(),
                    None,
                )
            });
            assert!(outcome.complete, "{:#?}", outcome.diagnostics);
            brokk_bifrost_analysis::analyzer::semantic_model::DependencyDiscoveryEvidence::from_outcome(
                &outcome,
            )
            .with_external_reads(reads.keys, reads.complete)
        }
    }

    /// Whether the carried keys still describe the files on disk.
    fn carried_keys_hold(
        evidence: &brokk_bifrost_analysis::analyzer::semantic_model::DependencyDiscoveryEvidence,
    ) -> bool {
        evidence
            .carry_eligible_external_reads()
            .expect("a complete JVM discovery is carry eligible")
            .iter()
            .all(ExternalDiscoveryRead::still_matches)
    }

    #[test]
    fn jvm_discovery_keys_the_java_home_and_path_environment() {
        let fixture = CarryFixture::new();
        let evidence = fixture.evidence();
        for name in ["JAVA_HOME", "PATH"] {
            let key = evidence
                .carry_eligible_external_reads()
                .unwrap()
                .iter()
                .find(|read| {
                    matches!(read, ExternalDiscoveryRead::Environment { name: key, .. } if key.as_ref() == name)
                })
                .unwrap_or_else(|| panic!("{name} is not keyed"));
            assert!(key.still_matches());
            let ExternalDiscoveryRead::Environment {
                name,
                working_directory,
                ..
            } = key
            else {
                unreachable!()
            };
            // The process environment as recorded, but for a value no process has.
            let changed = ExternalDiscoveryRead::Environment {
                name: name.clone(),
                value: Some("/not/the/recorded/value".into()),
                working_directory: working_directory.clone(),
            };
            assert!(!changed.still_matches());
        }
    }

    #[test]
    fn jvm_discovery_reads_are_complete_and_every_observed_input_refuses_carry_when_it_changes() {
        type Mutation = fn(&CarryFixture);
        let mutations: Vec<(&str, Mutation)> = vec![
            ("an unrelated file", |fixture| {
                fs::write(fixture.path("unrelated.txt"), "x").unwrap()
            }),
            ("a Maven jar rewritten", |fixture| {
                write_zip_entry(
                    &fixture.path("repo/example/lib/1/lib-1.jar"),
                    "a.txt",
                    b"changed binary",
                )
            }),
            ("a Gradle jar rewritten", |fixture| {
                write_zip_entry(
                    &fixture.path("gradle/example/g/1/h1/g-1.jar"),
                    "a.txt",
                    b"changed binary",
                )
            }),
            ("a missing sources jar appears", |fixture| {
                write_zip_entry(
                    &fixture.path("repo/example/lib/1/lib-1-sources.jar"),
                    "a.txt",
                    b"x",
                )
            }),
            ("a Gradle hash directory appears", |fixture| {
                fs::create_dir_all(fixture.path("gradle/example/g/1/h2")).unwrap()
            }),
            ("a JMOD changes", |fixture| {
                write_zip_entries(
                    &fixture.path("jdk/jmods/java.base.jmod"),
                    &[
                        (
                            "classes/module-info.class",
                            &crate::analyzer::jvm::jmod_artifact::test_module_info_class_bytes(
                                &["java/lang"],
                                &[],
                            ),
                        ),
                        ("classes/extra.txt", b"extra"),
                    ],
                )
            }),
            ("the JDK release changes", |fixture| {
                fs::write(fixture.path("jdk/release"), "JAVA_VERSION=\"21.0.9\"\n").unwrap()
            }),
        ];
        let fixtures: Vec<_> = mutations.iter().map(|_| CarryFixture::new()).collect();
        // The JDK observation refuses an identity that could hide a rewrite in
        // its timestamp tick, so the fixtures must age past it.
        std::thread::sleep(
            brokk_bifrost_core::content_digest::FILE_TIMESTAMP_GRANULARITY
                + std::time::Duration::from_millis(500),
        );
        for ((name, mutate), fixture) in mutations.iter().zip(&fixtures) {
            let evidence = fixture.evidence();
            assert!(evidence.external_reads_complete, "{name}");
            assert!(carried_keys_hold(&evidence), "{name}: fresh keys");
            mutate(fixture);
            assert_eq!(
                carried_keys_hold(&evidence),
                *name == "an unrelated file",
                "{name}"
            );
        }
    }

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

    use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

    use crate::analyzer::JavaAnalyzer;

    use brokk_bifrost_core::analyzer::config::JvmExternalArtifact;

    use brokk_bifrost_core::analyzer::config::JvmExternalDependencies;

    use brokk_bifrost_core::analyzer::config::JvmMavenCoordinate;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::project::Project;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::analyzer::query_token::QueryScope;

    use brokk_bifrost_core::analyzer::project::TestProject;
    use std::collections::BTreeSet;
    use std::fs;

    use std::sync::Arc;
    use zip::write::SimpleFileOptions;

    use brokk_bifrost_test_macros::hardwon;

    type SourceDependencyPack = (
        ResolvedDependency,
        brokk_bifrost_semantic::analyzer::semantic_model::dependency::DependencyPackPreparationOutcome,
    );

    #[track_caller]
    fn prepare_source_dependency_pack(
        temp: &tempfile::TempDir,
        source_jar_name: &str,
        source_entry: &str,
        source: &[u8],
        artifact_jar_name: &str,
        coordinate: JvmMavenCoordinate,
    ) -> SourceDependencyPack {
        use brokk_bifrost_analysis::analyzer::semantic_model::CatalogOptions;
        use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackLimits;
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;
        use brokk_bifrost_analysis::analyzer::semantic_model::dependency::prepare_dependency_semantic_packs;

        let source_jar = temp.path().join(source_jar_name);
        write_zip_entry(&source_jar, source_entry, source);
        let dependency = resolved_semantic_pack_dependency(ResolvedJvmArtifact {
            artifact_path: temp.path().join(artifact_jar_name),
            source_artifact_path: Some(source_jar),
            coordinate: Some(coordinate),
            origin: JvmDependencyOrigin::MavenRepository,
        });
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let prepared = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            std::slice::from_ref(&dependency),
            &DependencyPackLimits::default(),
            None,
        );
        (dependency, prepared)
    }

    #[track_caller]
    fn assert_generated_source_pack(
        prepared: &brokk_bifrost_semantic::analyzer::semantic_model::dependency::DependencyPackPreparationOutcome,
        language: &str,
    ) {
        use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackPreparationStatus;

        assert!(prepared.complete, "{:#?}", prepared.diagnostics);
        assert_eq!(prepared.profile.artifacts_read, 1);
        assert_eq!(prepared.packs.len(), 1);
        assert_eq!(
            prepared.packs[0].status,
            DependencyPackPreparationStatus::Generated
        );
        assert_eq!(prepared.packs[0].evidence.language, language);
    }

    #[test]
    #[hardwon("ad9166babf21: exact external selection admitted an inaccessible private overload")]
    fn java_external_exact_selection_rejects_inaccessible_overloads() {
        use brokk_bifrost_analysis::analyzer::semantic_model::CatalogCoordinate;

        use brokk_bifrost_analysis::analyzer::semantic_model::CatalogOptions;

        use brokk_bifrost_semantic::analyzer::semantic_model::compiler::CompilerOptions;

        use brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelActivationEvidence;

        use brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelActivationRequest;

        use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay;

        use brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelResolutionOutcome;

        use brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelRuntimeLimits;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

        use brokk_bifrost_analysis::analyzer::semantic_model::SessionPackSource;

        use brokk_bifrost_analysis::analyzer::semantic_model::SessionPackSourceKind;

        use brokk_bifrost_semantic::analyzer::semantic_model::source::SourceFormat;

        use brokk_bifrost_semantic::analyzer::semantic_model::compiler::compile_source;

        use brokk_bifrost_analysis::analyzer::semantic_model::runtime::resolve_active_semantic_models;
        let method = |id: &str, visibility: &str, formal: &str| {
            serde_json::json!({
                "id": id, "owner": "type.overloads", "name": "pick", "member_kind": "method",
                "visibility": visibility, "is_static": true, "is_abstract": false, "is_virtual": false,
                "signature": {"type_parameters": [], "parameters": [{
                    "name": "value", "type": TypeRef::named(formal), "optional": false, "variadic": false
                }], "returns": TypeRef::named("void")},
                "aliases": [], "locator": {"kind": "artifact", "path": "example/Overloads.class",
                    "symbol": format!("example.Overloads.pick({formal})")}
            })
        };
        let document = serde_json::json!({
            "schema_version": 2, "pack_id": "test.jvm-private-overload", "version": "1.0.0",
            "producer": {"name": "bifrost-test", "version": "1.0.0"},
            "language": "java", "ecosystem": "jdk",
            "compatibility": {"bifrost": ">=0.8.0, <1.0.0", "toolchains": [{
                "name": "jdk", "requirement": ">=17.0.0"
            }]},
            "provenance": {"source": "test:inline", "revision": "ad9166babf21"},
            "license": "Apache-2.0", "completeness": "complete",
            "safety": {"generated_code_only": false, "review_required": false},
            "shards": [{"id": "decls", "activation": [{
                "toolchain": {"name": "jdk", "version": ">=17.0.0"},
                "targets": ["jvm"], "configurations": []
            }], "payload": {"kind": "declaration_facts", "types": [{
                "id": "type.overloads", "name": "example.Overloads", "type_kind": "class",
                "visibility": "public", "is_abstract": false, "is_sealed": false,
                "has_explicit_type_terms": false, "type_parameters": [], "type_parameter_constraints": [],
                "embedded_types": [], "hierarchy": [], "aliases": [], "extension_surfaces": [],
                "locator": {"kind": "artifact", "path": "example/Overloads.class", "symbol": "example.Overloads"}
            }], "members": [method("member.a-public", "public", "int"),
                method("member.z-private", "private", "java.lang.String")], "relations": []}}]
        });
        let pack = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&document).expect("fixture JSON"),
            &CompilerOptions::default(),
        )
        .expect("compile test-only declarations");
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
            .expect("fixture catalog");
        catalog
            .register_session_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: "test:private-overload".into(),
                },
            )
            .expect("register declarations");
        let request = SemanticModelActivationRequest {
            host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
            approximate_standard_libraries: Vec::new(),
            bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION"))
                .expect("crate version"),
            evidence: vec![SemanticModelActivationEvidence {
                language: "java".into(),
                ecosystem: "jdk".into(),
                package: None,
                module: None,
                toolchain: Some(CatalogCoordinate {
                    name: "jdk".into(),
                    version: Some(semver::Version::new(21, 0, 0)),
                }),
                target: Some("jvm".into()),
                configuration: None,
                production_input_digest: None,
                verified_raw_artifacts: Vec::new(),
            }],
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        };
        let cancellation = CancellationToken::default();
        let active = match resolve_active_semantic_models(&catalog, &request, &cancellation) {
            SemanticModelResolutionOutcome::Ready(active) => active,
            other => panic!("fixture activation must be ready: {other:#?}"),
        };
        let root = tempfile::tempdir().expect("isolated Java project");
        let analyzer = JavaAnalyzer::from_project(TestProject::new(root.path(), Language::Java));
        let active = Arc::new(active);
        let overlay = Arc::new(
            SemanticModelOverlay::build(
                &analyzer,
                &active,
                &cancellation,
                64 << 20,
                &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
            )
            .expect("fixture overlay"),
        );
        let artifacts = JvmExternalDeclarationIndex::default();
        let surface = JvmExternalDeclarations::new(&artifacts, Some(overlay));
        let gaps = std::cell::RefCell::new(Vec::new());
        let recorder = QueryGapRecorder::collecting(&gaps);
        let member = surface
            .resolve_member_spelling(&recorder, "example.Overloads.pick", "client", |name| {
                surface.get(&recorder, name)
            })
            .expect("the public overload remains visible");
        assert_eq!(
            member.applicable_parameter_count_for_argument_types(
                false,
                &[TypeRef::named("int")],
                Some(&surface)
            ),
            Some(1)
        );
        assert_eq!(
            member.applicable_parameter_count_for_argument_types(
                false,
                &[TypeRef::named("java.lang.String")],
                Some(&surface)
            ),
            None
        );
    }

    #[test]
    #[hardwon(
        "#11374: a repository holding only the sources jar was never matched because the binary probe returned first"
    )]
    fn maven_coordinate_resolves_sources_jar_without_binary() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let repo_dir = root.join("com/example/external-lib/1.2.3");
        fs::create_dir_all(&repo_dir).unwrap();
        let source_path = repo_dir.join("external-lib-1.2.3-sources.jar");
        write_zip_entry(
            &source_path,
            "com/example/probe/OnlySource.java",
            b"package com.example.probe; public class OnlySource {}",
        );
        let coordinate = JvmMavenCoordinate::new("com.example", "external-lib", "1.2.3");
        let mut probes = Vec::new();

        let resolved = resolve_coordinate_traced(&root, &coordinate, Some(&mut probes)).unwrap();

        assert_eq!(resolved.artifact_path, source_path);
        assert!(resolved.source_artifact_path.is_none());
        assert!(probes.iter().any(|probe| {
            probe.path == repo_dir.join("external-lib-1.2.3.jar")
                && probe.operation == ExternalProbeOperation::Canonicalize
                && probe.is_absent()
        }));
    }

    #[test]
    #[hardwon("#11374: a sources-only repository must not hide a binary in a later repository")]
    fn maven_coordinate_searches_later_repositories_for_binary() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let first_repo = root.join("first/com/example/external-lib/1.2.3");
        let second_repo = root.join("second/com/example/external-lib/1.2.3");
        fs::create_dir_all(&first_repo).unwrap();
        fs::create_dir_all(&second_repo).unwrap();
        write_zip_entry(
            &first_repo.join("external-lib-1.2.3-sources.jar"),
            "com/example/probe/OnlySource.java",
            b"package com.example.probe; public class OnlySource {}",
        );
        let binary_path = second_repo.join("external-lib-1.2.3.jar");
        probe_class_jar(&binary_path);
        let config = JvmExternalDependencies {
            coordinates: vec![JvmMavenCoordinate::new(
                "com.example",
                "external-lib",
                "1.2.3",
            )],
            repository_roots: vec![root.join("first"), root.join("second")],
            ..JvmExternalDependencies::default()
        };

        let resolved = resolve_configured_artifacts(&config, &root);

        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].artifact_path, binary_path);
        assert!(resolved[0].source_artifact_path.is_none());
    }

    #[test]
    #[hardwon(
        "0242909d77ed: Java census G16 (2026-10-15): variable arity discarded witnessed external overloads"
    )]
    fn java_external_varargs_selects_expanded_and_fixed_array_invocations() {
        let signature: Signature = serde_json::from_value(serde_json::json!({
            "parameters": [{"name": "values", "type": {"kind": "array", "element": TypeRef::named("java.lang.String")}, "variadic": true}]
        })).expect("variadic declaration");
        let mut member = JvmExternalMember {
            fqn: "example.Api.accept".into(),
            declaring_package: "example".into(),
            visibility: JvmVisibility::Public,
            returns: None,
            is_static: true,
            is_constant: false,
            field_type: None,
            jdk_artifact_sha256: None,
            unshaped_model_records: Vec::new(),
            call_shapes: vec![
                external_call_shape(
                    MemberKind::Method,
                    JvmVisibility::Public,
                    true,
                    Some(&signature),
                    false,
                    None,
                )
                .expect("call shape"),
            ],
            call_shapes_incomplete: false,
        };
        for actuals in [
            vec![],
            vec![
                TypeRef::named("java.lang.String"),
                TypeRef::named("java.lang.String"),
            ],
            vec![TypeRef::Array {
                element: Box::new(TypeRef::named("java.lang.String")),
            }],
        ] {
            assert_eq!(
                member.applicable_parameter_count_for_argument_types(false, &actuals, None),
                Some(1),
                "{actuals:?}"
            );
        }
        member.call_shapes_incomplete = true;
        assert_eq!(
            member.applicable_parameter_count_for_argument_types(
                false,
                &[TypeRef::named("java.lang.String")],
                None
            ),
            None
        );
        assert_eq!(
            member.call_shapes.len(),
            1,
            "incomplete discovery retains its witnessed declaration"
        );
    }

    #[test]
    #[hardwon(
        "0242909d77ed: Java census G25 (2026-10-15): reference array widening was treated as unknown"
    )]
    fn java_external_array_covariance_preserves_primitive_array_invariance() {
        let array = |name| TypeRef::Array {
            element: Box::new(TypeRef::named(name)),
        };
        let actuals = [array("java.lang.String")];
        let formals = [vec![array("java.lang.Object")]];
        assert_eq!(
            select_java_external_signature_for_types(&actuals, &formals),
            Some(0)
        );
        assert_eq!(
            java_external_conversion(&array("int"), &array("long")),
            JavaExternalConversion::Inapplicable
        );
        assert_eq!(
            java_external_conversion(&array("int"), &TypeRef::named("int")),
            JavaExternalConversion::Inapplicable
        );
    }

    #[test]
    #[hardwon(
        "0242909d77ed: Java census G15b (2026-10-15): partial families discarded exact ground overloads"
    )]
    fn partial_java_family_selects_exact_ground_formals_without_admitting_conversions() {
        let named = |name| TypeRef::named(name);
        let signatures =
            ["java.lang.String", "java.lang.Integer", "example.Base"].map(|name| Signature {
                bounds: None,
                type_parameters: Vec::new(),
                parameters: vec![
                    serde_json::from_value(serde_json::json!({
                        "name": "value", "type": named(name)
                    }))
                    .expect("test formal"),
                ],
                returns: Some(named("void")),
            });
        let member = JvmExternalMember {
            fqn: "example.Api.accept".to_owned(),
            declaring_package: "example".to_owned(),
            visibility: JvmVisibility::Public,
            returns: Some(named("void")),
            is_static: true,
            is_constant: false,
            field_type: None,
            jdk_artifact_sha256: None,
            unshaped_model_records: Vec::new(),
            call_shapes: signatures
                .iter()
                .map(|signature| {
                    external_call_shape(
                        MemberKind::Method,
                        JvmVisibility::Public,
                        true,
                        Some(signature),
                        false,
                        None,
                    )
                    .expect("test method signature")
                })
                .collect(),
            call_shapes_incomplete: true,
        };
        assert_eq!(
            member.applicable_parameter_count_for_argument_types(
                false,
                &[named("java.lang.String")],
                None
            ),
            Some(1),
            "an exact static type decides phase 1 without family closure"
        );
        for actual in [named("int"), named("example.Child"), TypeRef::Unknown] {
            assert_eq!(
                member.applicable_parameter_count_for_argument_types(
                    false,
                    std::slice::from_ref(&actual),
                    None
                ),
                None,
                "boxing, subtyping and unknown actuals stay unproved: {actual:?}"
            );
        }
        assert_eq!(
            member.non_overridable_for_argument_types(
                false,
                &[named("java.lang.String")],
                None,
                None
            ),
            None,
            "selection must not fabricate independent finality evidence"
        );
    }

    #[test]
    #[hardwon(
        "#3699: Regression ensures array shape is preserved only for one complete matching overload, not ambiguous/incomplete calls"
    )]
    fn selected_external_return_preserves_array_shape_and_overload_uncertainty() {
        let returned = TypeRef::Array {
            element: Box::new(TypeRef::Named {
                name: "java.lang.String".to_owned(),
                arguments: Vec::new(),
                nullable: false,
            }),
        };
        let mut member = JvmExternalMember {
            fqn: "example.Factory.values".to_owned(),
            declaring_package: "example".to_owned(),
            visibility: JvmVisibility::Public,
            returns: Some(returned.clone()),
            is_static: true,
            is_constant: false,
            field_type: None,
            jdk_artifact_sha256: None,
            unshaped_model_records: Vec::new(),
            call_shapes: vec![JvmExternalCallShape {
                visibility: JvmVisibility::Public,
                model_record: None,
                inventory_identity: None,
                non_overridable: None,
                is_abstract: false,
                parameter_count: 0,
                parameters: Vec::new(),
                has_type_parameters: false,
                type_parameters: Vec::new(),
                is_static: true,
                variadic: false,
                returns: Some(returned.clone()),
            }],
            call_shapes_incomplete: false,
        };
        assert_eq!(member.applicable_return_type(false, 0), Some(&returned));
        assert_eq!(
            named_return_type_fqn(member.applicable_return_type(false, 0)),
            None
        );
        assert_eq!(member.applicable_return_type(true, 0), None);
        assert_eq!(member.applicable_return_type(false, 1), None);
        member.call_shapes_incomplete = true;
        assert_eq!(member.applicable_return_type(false, 0), None);
        member.call_shapes_incomplete = false;
        member.call_shapes.push(member.call_shapes[0].clone());
        assert_eq!(member.applicable_return_type(false, 0), None);
    }

    #[test]
    #[hardwon(
        "#3693: Builds actual class jars and verifies changing an array element type changes dispatch behavior identity"
    )]
    fn external_return_array_element_changes_behavior_identity() {
        let root = tempfile::tempdir().expect("temporary class jar directory");
        let mut identities = Vec::new();
        for (name, descriptor) in [
            ("strings.jar", "()[Ljava/lang/String;"),
            ("integers.jar", "()[Ljava/lang/Integer;"),
        ] {
            let jar = root.path().join(name);
            write_test_class_jar(
                &jar,
                &[TestClassFile {
                    internal_name: "example/Factory",
                    super_internal_name: "java/lang/Object",
                    methods: &[TestClassMethod {
                        name: "values",
                        descriptor,
                        is_static: true,
                    }],
                    private_nested: false,
                }],
            );
            let index = probe_index(&jar);
            assert!(
                index.production_diagnostics().is_empty(),
                "{:?}",
                index.production_diagnostics()
            );
            identities.push(index.dispatch_behavior_identity());
        }
        assert_ne!(identities[0], identities[1]);
    }

    #[test]
    fn class_finality_changes_behavior_identity_and_the_final_receiver() {
        let root = tempfile::tempdir().expect("temporary class jar directory");
        let class = TestClassFile {
            internal_name: "example/Leaf",
            super_internal_name: "java/lang/Object",
            methods: &[TestClassMethod {
                name: "run",
                descriptor: "()V",
                is_static: false,
            }],
            private_nested: false,
        };
        let observed = [false, true].map(|is_final| {
            let jar = root.path().join(format!("final-{is_final}.jar"));
            write_test_generic_class_jar(
                &jar,
                &[(
                    &class,
                    TestClassGenerics {
                        is_final,
                        ..TestClassGenerics::default()
                    },
                )],
            );
            let index = probe_index(&jar);
            let closes =
                JvmExternalDeclarations::new(&index, None).is_final_receiver_class("example.Leaf");
            (index.dispatch_behavior_identity(), closes)
        });
        assert_ne!(observed[0].0, observed[1].0);
        assert_eq!([observed[0].1, observed[1].1], [false, true]);
    }

    fn missing_dependency_gap(coordinate: &str) -> IndexGap {
        IndexGap::from_discovery(DependencyPackDiagnostic {
            severity: DependencyPackDiagnosticSeverity::Error,
            code: super::super::producer_codes::JVM_DEPENDENCY_UNRESOLVED
                .code
                .to_owned(),
            dependency_id: Some(coordinate.to_owned()),
            location: None,
            message: "the artifact is not in any configured repository".to_owned(),
        })
    }

    /// Two indexes with the same types and different missing sets must have
    /// different dispatch identities: an ICFG-keyed product computed where a
    /// lookup was complete would otherwise be reused where that lookup must be
    /// partial, and a reused partial answer would name the wrong jar. The
    /// coordinate is part of the identity, not only the attribution.
    #[test]
    fn dispatch_identity_follows_the_missing_set_when_the_types_are_the_same() {
        let identity = |coordinates: &[&str]| {
            let mut index = JvmExternalDeclarationIndex::build_from_artifacts(Vec::new());
            index.production_diagnostics.extend(
                coordinates
                    .iter()
                    .map(|coordinate| missing_dependency_gap(coordinate)),
            );
            index.dispatch_behavior_identity()
        };
        let none = identity(&[]);
        let a = identity(&["org.example:a:1"]);
        let b = identity(&["org.example:b:1"]);
        let ab = identity(&["org.example:a:1", "org.example:b:1"]);
        let ba = identity(&["org.example:b:1", "org.example:a:1"]);
        let all = [none, a, b, ab];
        for (i, left) in all.iter().enumerate() {
            for right in &all[i + 1..] {
                assert_ne!(left, right, "{all:?}");
            }
        }
        assert_eq!(ab, ba, "the digest sorts the missing set");
    }

    #[test]
    #[hardwon(
        "#3422: Checks missing toolchain diagnostics include actionable configuration guidance"
    )]
    fn missing_jdk_discovery_explains_how_to_activate_stdlib_packs() {
        let config = JvmAnalyzerConfig::default();
        let root = tempfile::tempdir().expect("temp root");
        let discovery = discover_and_pin_jdk(&config, root.path(), None, &test_digests());

        let diagnostic = discovery
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "jdk.home.unavailable")
            .expect("missing JDK must produce actionable discovery guidance");
        assert!(diagnostic.message.contains("JAVA_HOME"));
        assert!(diagnostic.message.contains("restart Bifrost"));
    }

    // -----------------------------------------------------------------------
    // `java` on PATH (#13266). PATH is injected, never read from the process.

    /// A JDK home with `release`, `jmods` and a runnable launcher, under `root`.
    fn path_jdk_home(root: &Path, name: &str, version: &str) -> PathBuf {
        let home = root.join(name);
        fs::create_dir_all(home.join("bin")).unwrap();
        fs::create_dir_all(home.join("jmods")).unwrap();
        fs::write(
            home.join("release"),
            format!("JAVA_VERSION=\"{version}\"\n"),
        )
        .unwrap();
        fs::write(home.join("jmods/java.base.jmod"), name.as_bytes()).unwrap();
        write_runnable(&home.join("bin").join(java_launcher_name()));
        home
    }

    fn java_launcher_name() -> &'static str {
        if cfg!(windows) { "java.exe" } else { "java" }
    }

    fn write_runnable(path: &Path) {
        fs::write(path, b"launcher").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    fn path_of(directories: &[&Path]) -> Option<OsString> {
        Some(std::env::join_paths(directories).unwrap())
    }

    fn jdk_answer(discovery: JdkDiscovery) -> [u8; 32] {
        SelectedJdk {
            inputs: discovery.inputs,
            dependencies: discovery.dependencies,
        }
        .answer_digest(true, true)
    }

    #[test]
    #[hardwon("#13266: JDK discovery ignored java on PATH when JAVA_HOME was unset")]
    fn java_on_path_in_path_order_selects_its_jdk_home() {
        let root = tempfile::tempdir().unwrap();
        let first = path_jdk_home(root.path(), "jdk-first", "21.0.2");
        let second = path_jdk_home(root.path(), "jdk-second", "17.0.9");
        let empty = root.path().join("empty-bin");
        fs::create_dir_all(&empty).unwrap();
        #[cfg(unix)]
        let data_file_dir = {
            // A non-executable `java` earlier on PATH must not shadow the launcher.
            let dir = root.path().join("data-bin");
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("java"), b"not a launcher").unwrap();
            dir
        };
        #[cfg(not(unix))]
        let data_file_dir = empty.clone();

        let discovered = discover_and_pin_jdk_with_path(
            &JvmAnalyzerConfig::default(),
            root.path(),
            None,
            path_of(&[
                &empty,
                &data_file_dir,
                &first.join("bin"),
                &second.join("bin"),
            ]),
            &test_digests(),
        );

        assert!(
            discovered.diagnostics.is_empty(),
            "{:?}",
            discovered.diagnostics
        );
        assert_eq!(discovered.dependencies.len(), 1);
        assert_eq!(discovered.dependencies[0].id, "jdk:21.0.2");
        assert_eq!(discovered.dependencies[0].artifacts.len(), 1);
        assert_eq!(
            discovered.inputs.java_on_path,
            Some(first.join("bin").join(java_launcher_name()))
        );
        assert!(discovered.inputs.complete);
    }

    #[test]
    #[hardwon("#13266: a relative PATH entry was resolved against the workspace root")]
    fn relative_path_entry_before_any_java_leaves_the_jdk_selection_incomplete() {
        let root = tempfile::tempdir().unwrap();
        let home = path_jdk_home(root.path(), "jdk-absolute", "21.0.2");
        // `rel-bin` holds a launcher under the workspace root, which is where
        // the old lookup resolved it. The process would resolve it against its
        // own working directory instead, so neither is a safe answer.
        let relative = Path::new("rel-bin");
        let decoy = path_jdk_home(root.path(), "rel-jdk", "17.0.9");
        fs::rename(decoy.join("bin"), root.path().join(relative)).unwrap();
        let ambiguity = |discovery: &JdkDiscovery| {
            let diagnostic = discovery
                .diagnostics
                .iter()
                .find(|diagnostic| diagnostic.code == "jdk.home.invalid")
                .unwrap_or_else(|| panic!("{:?}", discovery.diagnostics));
            assert!(
                diagnostic
                    .message
                    .contains("\"rel-bin\" is relative or empty"),
                "{}",
                diagnostic.message
            );
            assert!(
                diagnostic.message.contains("JAVA_HOME"),
                "{}",
                diagnostic.message
            );
            assert!(!discovery.inputs.complete);
        };

        let blocked = discover_and_pin_jdk_with_path(
            &JvmAnalyzerConfig::default(),
            root.path(),
            None,
            path_of(&[relative, &home.join("bin")]),
            &test_digests(),
        );
        assert!(
            blocked.dependencies.is_empty(),
            "{:?}",
            blocked.dependencies
        );
        ambiguity(&blocked);

        // A configured home is still selected, but the JDK the relative entry
        // names could be missing beside it, so the selection is not complete.
        let mut configured = JvmAnalyzerConfig::default();
        configured.standard_library_discovery.jdk_homes = vec![home.clone()];
        let beside = discover_and_pin_jdk_with_path(
            &configured,
            root.path(),
            None,
            path_of(&[relative]),
            &test_digests(),
        );
        assert_eq!(beside.dependencies.len(), 1, "{:?}", beside.diagnostics);
        assert_eq!(beside.dependencies[0].id, "jdk:21.0.2");
        ambiguity(&beside);

        // Once an absolute entry has supplied `java`, a later relative entry
        // cannot change which launcher the process runs.
        let selected = discover_and_pin_jdk_with_path(
            &JvmAnalyzerConfig::default(),
            root.path(),
            None,
            path_of(&[&home.join("bin"), relative]),
            &test_digests(),
        );
        assert_eq!(selected.dependencies.len(), 1, "{:?}", selected.diagnostics);
        assert_eq!(selected.dependencies[0].id, "jdk:21.0.2");
        assert!(
            selected.diagnostics.is_empty(),
            "{:?}",
            selected.diagnostics
        );
        assert!(selected.inputs.complete);
    }

    #[cfg(unix)]
    #[test]
    #[hardwon("#13266: java on PATH reached through a symlink was not resolved to its JDK home")]
    fn java_on_path_resolves_a_symlink_to_the_real_jdk_home() {
        // Unix only: creating a symlink on Windows needs a privilege tests cannot assume.
        let root = tempfile::tempdir().unwrap();
        let home = path_jdk_home(root.path(), "jdk-real", "21.0.2");
        let shim = root.path().join("shim");
        fs::create_dir_all(&shim).unwrap();
        std::os::unix::fs::symlink(home.join("bin/java"), shim.join("java")).unwrap();

        let discovered = discover_and_pin_jdk_with_path(
            &JvmAnalyzerConfig::default(),
            root.path(),
            None,
            path_of(&[&shim]),
            &test_digests(),
        );

        assert!(
            discovered.diagnostics.is_empty(),
            "{:?}",
            discovered.diagnostics
        );
        assert_eq!(discovered.dependencies.len(), 1);
        assert_eq!(discovered.inputs.java_on_path, Some(shim.join("java")));
        assert_eq!(
            discovered
                .inputs
                .candidates
                .last()
                .map(|(home, _)| home.as_path()),
            Some(fs::canonicalize(&home).unwrap().as_path())
        );
    }

    #[test]
    fn java_on_path_that_is_no_jdk_stays_unavailable_without_an_invalid_home_warning() {
        let root = tempfile::tempdir().unwrap();
        // A launcher stub: the home above `bin` has no `release` file.
        let stub = root.path().join("usr");
        fs::create_dir_all(stub.join("bin")).unwrap();
        write_runnable(&stub.join("bin").join(java_launcher_name()));
        // A launcher that is not under a `bin` directory.
        let loose = root.path().join("loose");
        fs::create_dir_all(&loose).unwrap();
        write_runnable(&loose.join(java_launcher_name()));

        let stubbed = discover_and_pin_jdk_with_path(
            &JvmAnalyzerConfig::default(),
            root.path(),
            None,
            path_of(&[&stub.join("bin")]),
            &test_digests(),
        );
        let unplaced = discover_and_pin_jdk_with_path(
            &JvmAnalyzerConfig::default(),
            root.path(),
            None,
            path_of(&[&loose]),
            &test_digests(),
        );
        let missing = discover_and_pin_jdk_with_path(
            &JvmAnalyzerConfig::default(),
            root.path(),
            None,
            path_of(&[&root.path().join("nowhere")]),
            &test_digests(),
        );

        for (discovery, reason) in [
            (
                stubbed,
                "is not a usable JDK: JDK home does not contain a readable release file",
            ),
            (unplaced, "is not in a `bin` directory"),
            (missing, "no `java` found on PATH"),
        ] {
            assert!(discovery.dependencies.is_empty());
            let codes: Vec<_> = discovery
                .diagnostics
                .iter()
                .map(|d| d.code.as_str())
                .collect();
            assert_eq!(
                codes,
                ["jdk.home.unavailable"],
                "{:?}",
                discovery.diagnostics
            );
            let message = &discovery.diagnostics[0].message;
            assert!(message.contains("JAVA_HOME"), "{message}");
            assert!(message.contains(reason), "{message}");
        }
    }

    #[test]
    #[hardwon(
        "#13471: no-JDK tests found a JDK through java on PATH once PATH became the JAVA_HOME fallback"
    )]
    fn empty_java_home_keeps_no_jdk_even_with_java_on_path() {
        let root = tempfile::tempdir().unwrap();
        let on_path = path_jdk_home(root.path(), "jdk-on-path", "17.0.9");
        let path = path_of(&[&on_path.join("bin")]);
        // A set but empty JAVA_HOME is the opt-out: it never consults PATH.
        let empty = discover_and_pin_jdk_with_path(
            &JvmAnalyzerConfig::default(),
            root.path(),
            Some(OsString::new()),
            path,
            &test_digests(),
        );
        assert!(empty.dependencies.is_empty(), "{:?}", empty.dependencies);
        assert_eq!(empty.inputs.path, None, "PATH is not consulted");
        assert_eq!(empty.inputs.java_on_path, None);
        assert_eq!(empty.diagnostics.len(), 1);
        assert_eq!(empty.diagnostics[0].code, "jdk.home.unavailable");
        assert!(!empty.diagnostics[0].message.contains("on PATH"));
    }

    #[test]
    fn java_home_takes_precedence_over_path_and_never_falls_through() {
        let root = tempfile::tempdir().unwrap();
        let wanted = path_jdk_home(root.path(), "jdk-wanted", "21.0.2");
        let on_path = path_jdk_home(root.path(), "jdk-on-path", "17.0.9");
        let path = path_of(&[&on_path.join("bin")]);

        let set = discover_and_pin_jdk_with_path(
            &JvmAnalyzerConfig::default(),
            root.path(),
            Some(wanted.as_os_str().to_owned()),
            path.clone(),
            &test_digests(),
        );
        assert_eq!(set.dependencies.len(), 1);
        assert_eq!(set.dependencies[0].id, "jdk:21.0.2");
        assert_eq!(set.inputs.path, None, "PATH is not consulted");

        let wrong = discover_and_pin_jdk_with_path(
            &JvmAnalyzerConfig::default(),
            root.path(),
            Some(root.path().join("no-such-jdk").into_os_string()),
            path.clone(),
            &test_digests(),
        );
        assert!(wrong.dependencies.is_empty(), "{:?}", wrong.dependencies);
        assert_eq!(wrong.diagnostics.len(), 1);
        assert_eq!(wrong.diagnostics[0].code, "jdk.home.invalid");

        let unset = discover_and_pin_jdk_with_path(
            &JvmAnalyzerConfig::default(),
            root.path(),
            None,
            path.clone(),
            &test_digests(),
        );
        assert_eq!(unset.dependencies[0].id, "jdk:17.0.9");

        let mut disabled = JvmAnalyzerConfig::default();
        disabled.standard_library_discovery.discover_java_home = false;
        let off =
            discover_and_pin_jdk_with_path(&disabled, root.path(), None, path, &test_digests());
        assert!(off.dependencies.is_empty() && off.diagnostics.is_empty());
    }

    #[test]
    fn changed_path_or_retargeted_java_changes_the_recorded_answer() {
        let root = tempfile::tempdir().unwrap();
        let a = path_jdk_home(root.path(), "jdk-a", "21.0.2");
        let b = path_jdk_home(root.path(), "jdk-b", "21.0.2");
        let answer = |path: Option<OsString>| {
            jdk_answer(discover_and_pin_jdk_with_path(
                &JvmAnalyzerConfig::default(),
                root.path(),
                None,
                path,
                &test_digests(),
            ))
        };

        let on_a = answer(path_of(&[&a.join("bin")]));
        assert_eq!(on_a, answer(path_of(&[&a.join("bin")])));
        assert_ne!(on_a, answer(path_of(&[&b.join("bin")])));
        assert_ne!(
            on_a,
            answer(path_of(&[&root.path().join("nowhere"), &a.join("bin")]))
        );
        assert_ne!(on_a, answer(None));

        #[cfg(unix)]
        {
            // update-alternatives style retarget: the same PATH entry now
            // resolves to another home.
            let shim = root.path().join("shim");
            fs::create_dir_all(&shim).unwrap();
            let link = shim.join("java");
            std::os::unix::fs::symlink(a.join("bin/java"), &link).unwrap();
            let before = answer(path_of(&[&shim]));
            fs::remove_file(&link).unwrap();
            std::os::unix::fs::symlink(b.join("bin/java"), &link).unwrap();
            assert_ne!(before, answer(path_of(&[&shim])));
        }
    }

    // -----------------------------------------------------------------------
    // Parameterized conversions over class-file owners (#10194).
    // -----------------------------------------------------------------------

    const OBJECT_CLASS: &str = "java/lang/Object";

    /// One fixture class: binary name, superclass, interfaces, class signature.
    type GenericFixtureClass<'a> = (&'a str, &'a str, &'a [&'a str], Option<&'a str>);

    fn generic_class_jar(path: &Path, classes: &[GenericFixtureClass<'_>]) {
        let files = classes
            .iter()
            .map(|(internal_name, super_internal_name, _, _)| TestClassFile {
                internal_name,
                super_internal_name,
                methods: &[],
                private_nested: false,
            })
            .collect::<Vec<_>>();
        let entries = files
            .iter()
            .zip(classes)
            .map(|(file, (_, _, interfaces, signature))| {
                (
                    file,
                    TestClassGenerics {
                        interfaces,
                        signature: *signature,
                        ..TestClassGenerics::default()
                    },
                )
            })
            .collect::<Vec<_>>();
        write_test_generic_class_jar(path, &entries);
    }

    /// Stub JDK classes, for a jar that answers without any JDK on the machine.
    const STUB_JDK_CLASSES: &[GenericFixtureClass<'_>] = &[
        (
            "java/lang/Iterable",
            OBJECT_CLASS,
            &[],
            Some("<T:Ljava/lang/Object;>Ljava/lang/Object;"),
        ),
        ("java/lang/CharSequence", OBJECT_CLASS, &[], None),
        (
            "java/lang/String",
            OBJECT_CLASS,
            &["java/lang/CharSequence"],
            None,
        ),
        ("java/lang/Integer", OBJECT_CLASS, &[], None),
    ];

    /// The shape Guava has: every edge passes the owner's own parameters on
    /// (`Concrete<E> extends Mid<E>`, `Mid<E> extends ListLike<E>`,
    /// `ListLike<T> implements Iterable<T>`), plus one fixture for each edge
    /// that proves no argument position.
    const DEPENDENCY_CLASSES: &[GenericFixtureClass<'_>] = &[
        (
            "dep/ListLike",
            OBJECT_CLASS,
            &["java/lang/Iterable"],
            Some("<T:Ljava/lang/Object;>Ljava/lang/Object;Ljava/lang/Iterable<TT;>;"),
        ),
        (
            "dep/Mid",
            "dep/ListLike",
            &[],
            Some("<E:Ljava/lang/Object;>Ldep/ListLike<TE;>;"),
        ),
        (
            "dep/Concrete",
            "dep/Mid",
            &[],
            Some("<E:Ljava/lang/Object;>Ldep/Mid<TE;>;"),
        ),
        (
            "dep/Entry",
            OBJECT_CLASS,
            &[],
            Some("<K:Ljava/lang/Object;V:Ljava/lang/Object;>Ljava/lang/Object;"),
        ),
        (
            "dep/Swap",
            "dep/Entry",
            &[],
            Some("<A:Ljava/lang/Object;B:Ljava/lang/Object;>Ldep/Entry<TB;TA;>;"),
        ),
        // A ground edge argument: reachable, but #7643 composes only bare
        // parameters, so no position is proven.
        (
            "dep/GroundKid",
            "dep/ListLike",
            &[],
            Some("Ldep/ListLike<Ljava/lang/String;>;"),
        ),
        // A compound edge argument.
        (
            "dep/Nested",
            "dep/ListLike",
            &[],
            Some("<T:Ljava/lang/Object;>Ldep/ListLike<Ldep/ListLike<TT;>;>;"),
        ),
        ("dep/RawKid", "dep/ListLike", &[], None),
        (
            "dep/BadSignature",
            "dep/ListLike",
            &[],
            Some("this is not a class signature"),
        ),
        (
            "dep/AfterBad",
            "dep/BadSignature",
            &[],
            Some("<E:Ljava/lang/Object;>Ldep/BadSignature<TE;>;"),
        ),
        (
            "dep/Orphan",
            "dep/Missing",
            &[],
            Some("<E:Ljava/lang/Object;>Ldep/Missing<TE;>;"),
        ),
        (
            "dep/UndeclaredVariable",
            "dep/ListLike",
            &[],
            Some("Ldep/ListLike<TX;>;"),
        ),
        // A diamond whose two routes agree: both pass the parameter on.
        (
            "dep/LeftOne",
            "dep/ListLike",
            &[],
            Some("<X:Ljava/lang/Object;>Ldep/ListLike<TX;>;"),
        ),
        (
            "dep/RightOne",
            "dep/ListLike",
            &[],
            Some("<Y:Ljava/lang/Object;>Ldep/ListLike<TY;>;"),
        ),
        (
            "dep/Dia",
            OBJECT_CLASS,
            &["dep/LeftOne", "dep/RightOne"],
            Some("<E:Ljava/lang/Object;>Ljava/lang/Object;Ldep/LeftOne<TE;>;Ldep/RightOne<TE;>;"),
        ),
        // A diamond whose two routes swap the positions.
        (
            "dep/Pair",
            OBJECT_CLASS,
            &[],
            Some("<P:Ljava/lang/Object;Q:Ljava/lang/Object;>Ljava/lang/Object;"),
        ),
        (
            "dep/LeftPair",
            OBJECT_CLASS,
            &["dep/Pair"],
            Some("<X:Ljava/lang/Object;Y:Ljava/lang/Object;>Ljava/lang/Object;Ldep/Pair<TX;TY;>;"),
        ),
        (
            "dep/RightPair",
            OBJECT_CLASS,
            &["dep/Pair"],
            Some("<X:Ljava/lang/Object;Y:Ljava/lang/Object;>Ljava/lang/Object;Ldep/Pair<TX;TY;>;"),
        ),
        (
            "dep/Conflict",
            OBJECT_CLASS,
            &["dep/LeftPair", "dep/RightPair"],
            Some(
                "<A:Ljava/lang/Object;B:Ljava/lang/Object;>Ljava/lang/Object;Ldep/LeftPair<TA;TB;>;Ldep/RightPair<TB;TA;>;",
            ),
        ),
        // A found route plus a parent no jar read: that parent may lead to the
        // target with other arguments.
        (
            "dep/Split",
            "dep/ListLike",
            &["dep/Missing"],
            Some("<E:Ljava/lang/Object;>Ldep/ListLike<TE;>;Ldep/Missing<TE;>;"),
        ),
        // A hop whose parent is read with more parameters than the edge passes.
        (
            "dep/TwoParameters",
            OBJECT_CLASS,
            &["java/lang/Iterable"],
            Some(
                "<A:Ljava/lang/Object;B:Ljava/lang/Object;>Ljava/lang/Object;Ljava/lang/Iterable<TA;>;",
            ),
        ),
        (
            "dep/WrongArity",
            "dep/TwoParameters",
            &[],
            Some("<T:Ljava/lang/Object;>Ldep/TwoParameters<TT;>;"),
        ),
    ];

    fn generic_class_index(
        directory: &tempfile::TempDir,
        name: &str,
        classes: &[&[GenericFixtureClass<'_>]],
    ) -> JvmExternalDeclarationIndex {
        let jar = directory.path().join(name);
        generic_class_jar(&jar, &classes.concat());
        probe_index(&jar)
    }

    fn named(name: &str) -> TypeRef {
        TypeRef::named(name)
    }

    fn applied(name: &str, arguments: &[TypeRef]) -> TypeRef {
        TypeRef::Named {
            name: name.into(),
            arguments: arguments.to_vec(),
            nullable: false,
        }
    }

    fn wildcard(
        variance: brokk_bifrost_analysis::analyzer::semantic_model::WildcardVariance,
        bound: Option<TypeRef>,
    ) -> TypeRef {
        TypeRef::Wildcard {
            variance,
            bound: bound.map(Box::new),
        }
    }

    fn extends(bound: TypeRef) -> TypeRef {
        use brokk_bifrost_analysis::analyzer::semantic_model::WildcardVariance::Extends;
        wildcard(Extends, Some(bound))
    }

    fn superbound(bound: TypeRef) -> TypeRef {
        use brokk_bifrost_analysis::analyzer::semantic_model::WildcardVariance::Super;
        wildcard(Super, Some(bound))
    }

    fn any_argument() -> TypeRef {
        use brokk_bifrost_analysis::analyzer::semantic_model::WildcardVariance::Any;
        wildcard(Any, None)
    }

    fn iterable(argument: TypeRef) -> TypeRef {
        applied("java.lang.Iterable", &[argument])
    }

    /// The `Iterable` conversions of the bare-parameter chains, the JDK classes
    /// and the dependency classes coming from whichever half the surface reads.
    fn assert_projected_iterable_conversions(surface: &JvmExternalDeclarations<'_>) {
        use JavaExternalConversion::{Inapplicable, Strict};
        let string = || named("java.lang.String");
        let integer = || named("java.lang.Integer");
        let chars = || named("java.lang.CharSequence");
        let concrete = applied("dep.Concrete", &[string()]);
        let mid_of_integer = applied("dep.Mid", &[integer()]);
        for (actual, formal, expected) in [
            // Three hops: Concrete<E> -> Mid<E> -> ListLike<E> -> Iterable<E>.
            (&concrete, iterable(extends(chars())), Strict),
            (&concrete, iterable(string()), Strict),
            (&concrete, iterable(any_argument()), Strict),
            (&concrete, iterable(superbound(string())), Strict),
            (&concrete, iterable(integer()), Inapplicable),
            (&concrete, iterable(extends(integer())), Inapplicable),
            (&concrete, iterable(superbound(chars())), Inapplicable),
            (&concrete, named("java.lang.Iterable"), Strict),
            (&concrete, named("java.lang.Object"), Strict),
            (&mid_of_integer, iterable(integer()), Strict),
            (&mid_of_integer, iterable(extends(chars())), Inapplicable),
            // Two routes that agree on every position still project.
            (
                &applied("dep.Dia", &[string()]),
                iterable(extends(chars())),
                Strict,
            ),
            (
                &applied("dep.Dia", &[string()]),
                iterable(integer()),
                Inapplicable,
            ),
            // The positions of the supertype's arguments are composed, not
            // matched by parameter name.
            (
                &applied("dep.Swap", &[string(), integer()]),
                applied("dep.Entry", &[integer(), string()]),
                Strict,
            ),
            (
                &applied("dep.Swap", &[string(), integer()]),
                applied("dep.Entry", &[string(), integer()]),
                Inapplicable,
            ),
        ] {
            assert_eq!(
                java_external_conversion_in(actual, &formal, Some(surface)),
                expected,
                "{actual:?} -> {formal:?}"
            );
        }
    }

    #[test]
    fn class_file_owner_edges_project_type_arguments_through_every_hop() {
        let directory = tempfile::tempdir().unwrap();
        let index = generic_class_index(
            &directory,
            "generic.jar",
            &[STUB_JDK_CLASSES, DEPENDENCY_CLASSES],
        );
        let surface = JvmExternalDeclarations::new(&index, None);
        assert_projected_iterable_conversions(&surface);
    }

    #[test]
    fn class_file_edges_without_proven_arguments_only_establish_reachability() {
        use JavaExternalConversion::{Inapplicable, Strict, Unknown};
        let directory = tempfile::tempdir().unwrap();
        let index = generic_class_index(
            &directory,
            "generic.jar",
            &[STUB_JDK_CLASSES, DEPENDENCY_CLASSES],
        );
        let surface = JvmExternalDeclarations::new(&index, None);
        let string = || named("java.lang.String");
        let generic = Unknown(ConversionUnknown::GenericSubstitution);
        for (actual, formal, expected) in [
            // A ground or compound edge argument, a raw parent, an edge from a
            // malformed signature and a variable no scope declares all keep
            // the erased path and prove no argument.
            (named("dep.GroundKid"), iterable(string()), generic),
            (
                applied("dep.Nested", &[string()]),
                iterable(applied("dep.ListLike", &[string()])),
                generic,
            ),
            (named("dep.RawKid"), iterable(string()), generic),
            (named("dep.RawKid"), named("java.lang.Iterable"), Strict),
            (
                applied("dep.AfterBad", &[string()]),
                iterable(string()),
                generic,
            ),
            (
                named("dep.BadSignature"),
                named("java.lang.Iterable"),
                Strict,
            ),
            (named("dep.UndeclaredVariable"), iterable(string()), generic),
            // A bare actual may be a local whose arguments were erased in
            // transport, so it proves nothing either.
            (named("dep.Concrete"), iterable(string()), generic),
            (
                named("dep.ListLike"),
                applied("dep.ListLike", &[string()]),
                Strict,
            ),
            // Routes that disagree on the positions prove none, whichever the
            // search meets first.
            (
                applied("dep.Conflict", &[string(), named("java.lang.Integer")]),
                applied("dep.Pair", &[string(), named("java.lang.Integer")]),
                generic,
            ),
            // The erased path is proven, the arguments are not.
            (named("dep.Split"), named("java.lang.Iterable"), Strict),
            (
                applied("dep.Split", &[string()]),
                iterable(extends(named("java.lang.CharSequence"))),
                generic,
            ),
            // The edge passes one argument to a parent read with two
            // parameters, so the parent's own edge has no position to read.
            (
                applied("dep.WrongArity", &[string()]),
                iterable(string()),
                generic,
            ),
            // The actual's argument count must be the first owner's.
            (
                applied("dep.Mid", &[string(), string()]),
                iterable(string()),
                generic,
            ),
            // A missing erased path is a conclusive negative whatever the
            // arguments say.
            (named("dep.RawKid"), named("dep.Entry"), Inapplicable),
            (
                applied("dep.Concrete", &[string()]),
                applied("dep.Entry", &[string(), string()]),
                Inapplicable,
            ),
        ] {
            assert_eq!(
                java_external_conversion_in(&actual, &formal, Some(&surface)),
                expected,
                "{actual:?} -> {formal:?}"
            );
        }
    }

    #[test]
    fn an_intermediate_owner_with_an_unclosed_hierarchy_proves_no_arguments() {
        use JavaExternalConversion::{Inapplicable, Strict, Unknown};
        let directory = tempfile::tempdir().unwrap();
        let mut index = generic_class_index(
            &directory,
            "generic.jar",
            &[STUB_JDK_CLASSES, DEPENDENCY_CLASSES],
        );
        let concrete = applied("dep.Concrete", &[named("java.lang.String")]);
        let chars = iterable(extends(named("java.lang.CharSequence")));
        let integer = iterable(named("java.lang.Integer"));
        let surface = JvmExternalDeclarations::new(&index, None);
        assert_eq!(
            java_external_conversion_in(&concrete, &chars, Some(&surface)),
            Strict
        );
        assert_eq!(
            java_external_conversion_in(&concrete, &integer, Some(&surface)),
            Inapplicable
        );
        // Mid did not record every edge it has, so another edge may reach
        // Iterable with other arguments.
        index
            .members_by_owner
            .get_mut("dep.Mid")
            .expect("the jar read dep.Mid")
            .hierarchy_complete = false;
        let surface = JvmExternalDeclarations::new(&index, None);
        for formal in [&chars, &integer] {
            assert_eq!(
                java_external_conversion_in(&concrete, formal, Some(&surface)),
                Unknown(ConversionUnknown::GenericSubstitution),
                "{formal:?}"
            );
        }
        // The erased path is still proven.
        assert_eq!(
            java_external_conversion_in(
                &named("dep.Concrete"),
                &named("java.lang.Iterable"),
                Some(&surface)
            ),
            Strict
        );
    }

    #[test]
    fn an_absent_owner_stays_open_until_its_own_name_answers() {
        use JavaExternalConversion::Unknown;
        let directory = tempfile::tempdir().unwrap();
        let index = generic_class_index(
            &directory,
            "generic.jar",
            &[STUB_JDK_CLASSES, DEPENDENCY_CLASSES],
        );
        let surface = JvmExternalDeclarations::new(&index, None);
        let string = || named("java.lang.String");
        let orphan = applied("dep.Orphan", &[string()]);
        for (formal, expected) in [
            // Nothing read past dep.Missing, so Iterable is neither proved nor
            // refuted, and the unread parent is not reported as a negative.
            (
                iterable(string()),
                Unknown(ConversionUnknown::IncompleteHierarchy),
            ),
            (
                named("java.lang.Iterable"),
                Unknown(ConversionUnknown::IncompleteHierarchy),
            ),
            // The edge names the unread owner, so the path exists, but with no
            // read parameters for it the arguments are unproven.
            (
                applied("dep.Missing", &[string()]),
                Unknown(ConversionUnknown::GenericSubstitution),
            ),
        ] {
            assert_eq!(
                java_external_conversion_in(&orphan, &formal, Some(&surface)),
                expected,
                "{formal:?}"
            );
        }
    }

    #[test]
    fn two_reads_of_one_owner_that_disagree_prove_no_arguments() {
        use JavaExternalConversion::{Strict, Unknown};
        let directory = tempfile::tempdir().unwrap();
        let shared: &[GenericFixtureClass<'_>] = &[(
            "dep/Base",
            OBJECT_CLASS,
            &[],
            Some("<T:Ljava/lang/Object;>Ljava/lang/Object;"),
        )];
        // Both jars read B, C and G alike; only A's parent differs.
        let routed: &[GenericFixtureClass<'_>] = &[
            (
                "dep/G",
                OBJECT_CLASS,
                &[],
                Some("<Z:Ljava/lang/Object;>Ljava/lang/Object;"),
            ),
            (
                "dep/B",
                "dep/G",
                &[],
                Some("<X:Ljava/lang/Object;>Ldep/G<TX;>;"),
            ),
            (
                "dep/C",
                "dep/G",
                &[],
                Some("<Y:Ljava/lang/Object;>Ldep/G<TY;>;"),
            ),
        ];
        let first = directory.path().join("first.jar");
        let second = directory.path().join("second.jar");
        generic_class_jar(
            &first,
            &[
                shared,
                routed,
                &[
                    (
                        "dep/A",
                        "dep/B",
                        &[],
                        Some("<T:Ljava/lang/Object;U:Ljava/lang/Object;>Ldep/B<TT;>;"),
                    ),
                    // Two edges naming one parent are ambiguous, whatever
                    // their arguments are.
                    (
                        "dep/Twice",
                        "dep/Base",
                        &[],
                        Some("<E:Ljava/lang/Object;>Ldep/Base<TE;>;"),
                    ),
                    (
                        "dep/Shape",
                        "dep/Base",
                        &[],
                        Some("<T:Ljava/lang/Object;>Ldep/Base<TT;>;"),
                    ),
                ],
            ]
            .concat(),
        );
        generic_class_jar(
            &second,
            &[
                shared,
                routed,
                &[
                    // The same parameters as the first read, another parent.
                    (
                        "dep/A",
                        "dep/C",
                        &[],
                        Some("<T:Ljava/lang/Object;U:Ljava/lang/Object;>Ldep/C<TU;>;"),
                    ),
                    (
                        "dep/Twice",
                        "dep/Base",
                        &[],
                        Some("<E:Ljava/lang/Object;>Ldep/Base<Ldep/Base<TE;>;>;"),
                    ),
                    // Another parameter list for the same class.
                    (
                        "dep/Shape",
                        "dep/Base",
                        &[],
                        Some("<A:Ljava/lang/Object;B:Ljava/lang/Object;>Ldep/Base<TA;>;"),
                    ),
                ],
            ]
            .concat(),
        );
        let read = |artifact_path: &Path| ResolvedJvmArtifact {
            artifact_path: artifact_path.to_path_buf(),
            source_artifact_path: None,
            coordinate: None,
            origin: JvmDependencyOrigin::ExplicitPath,
        };
        let index =
            JvmExternalDeclarationIndex::build_from_artifacts(vec![read(&first), read(&second)]);
        let surface = JvmExternalDeclarations::new(&index, None);
        let string = || named("java.lang.String");
        let base = applied("dep.Base", &[string()]);
        let generic = Unknown(ConversionUnknown::GenericSubstitution);
        for (actual, expected) in [
            (applied("dep.Twice", &[string()]), generic),
            (applied("dep.Shape", &[string()]), generic),
            (named("dep.Shape"), generic),
        ] {
            assert_eq!(
                java_external_conversion_in(&actual, &base, Some(&surface)),
                expected,
                "{actual:?}"
            );
        }
        assert_eq!(
            java_external_conversion_in(&named("dep.Twice"), &named("dep.Base"), Some(&surface)),
            Strict
        );
        // Same parameters, different parents: one read passes T on and the
        // other passes U, so neither position is proven for G.
        assert_eq!(
            java_external_conversion_in(
                &applied("dep.A", &[string(), named("java.lang.Integer")]),
                &applied("dep.G", &[string()]),
                Some(&surface)
            ),
            generic
        );
        assert_eq!(
            java_external_conversion_in(&named("dep.A"), &named("dep.G"), Some(&surface)),
            Strict
        );
    }

    #[test]
    fn a_class_file_owner_widens_to_the_erased_roots_its_inventory_names() {
        use JavaExternalConversion::{Inapplicable, Strict};
        let directory = tempfile::tempdir().unwrap();
        let index = generic_class_index(
            &directory,
            "roots.jar",
            &[&[
                ("dep/Plain", OBJECT_CLASS, &[], None),
                ("dep/Point", "java/lang/Record", &[], None),
                ("dep/Marker", OBJECT_CLASS, &[], None),
            ]],
        );
        let surface = JvmExternalDeclarations::new(&index, None);
        for (actual, formal, expected) in [
            ("dep.Plain", "java.lang.Object", Strict),
            ("dep.Point", "java.lang.Record", Strict),
            ("dep.Point", "java.lang.Object", Strict),
            ("dep.Plain", "dep.Point", Inapplicable),
            ("dep.Plain", "dep.Marker", Inapplicable),
        ] {
            assert_eq!(
                java_external_conversion_in(&named(actual), &named(formal), Some(&surface)),
                expected,
                "{actual} -> {formal}"
            );
        }
    }

    /// Activate `types` as a test-only JDK declaration pack and read it through
    /// a surface whose artifact half is `artifacts`.
    fn surface_over_model_types<'a>(
        artifacts: &'a JvmExternalDeclarationIndex,
        types: Vec<serde_json::Value>,
    ) -> JvmExternalDeclarations<'a> {
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::{
            SemanticPackCatalog, SessionPackSource, SessionPackSourceKind,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay;
        use brokk_bifrost_analysis::analyzer::semantic_model::runtime::{
            SemanticModelResolutionOutcome, resolve_active_semantic_models,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            CatalogCoordinate, CatalogOptions, SemanticModelActivationEvidence,
            SemanticModelActivationRequest, SemanticModelRuntimeLimits,
        };
        use brokk_bifrost_semantic::analyzer::semantic_model::compiler::{
            CompilerOptions, compile_source,
        };
        use brokk_bifrost_semantic::analyzer::semantic_model::source::SourceFormat;

        let document = serde_json::json!({
            "schema_version": 43, "pack_id": "test.issue-10194-jdk", "version": "1.0.0",
            "producer": {"name": "bifrost-test", "version": "1.0.0"},
            "language": "java", "ecosystem": "jdk",
            "compatibility": {"toolchains": [{
                "name": "jdk", "requirement": ">=17.0.0"
            }]},
            "provenance": {"source": "test:inline", "revision": "issue-10194"},
            "license": "Apache-2.0", "completeness": "complete",
            "safety": {"generated_code_only": false, "review_required": false},
            "shards": [{"id": "decls", "activation": [{
                "toolchain": {"name": "jdk", "version": ">=17.0.0"},
                "targets": ["jvm"], "configurations": []
            }], "payload": {
                "kind": "declaration_facts", "types": types, "members": [], "relations": []
            }}]
        });
        let pack = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&document).expect("fixture JSON"),
            &CompilerOptions::default(),
        )
        .expect("compile test-only declarations");
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
            .expect("fixture catalog");
        catalog
            .register_session_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: "test:issue-10194".into(),
                },
            )
            .expect("register declarations");
        let request = SemanticModelActivationRequest {
            host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
            approximate_standard_libraries: Vec::new(),
            bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION"))
                .expect("crate version"),
            evidence: vec![SemanticModelActivationEvidence {
                language: "java".into(),
                ecosystem: "jdk".into(),
                package: None,
                module: None,
                toolchain: Some(CatalogCoordinate {
                    name: "jdk".into(),
                    version: Some(semver::Version::new(21, 0, 0)),
                }),
                target: Some("jvm".into()),
                configuration: None,
                production_input_digest: None,
                verified_raw_artifacts: Vec::new(),
            }],
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        };
        let cancellation = CancellationToken::default();
        let active = match resolve_active_semantic_models(&catalog, &request, &cancellation) {
            SemanticModelResolutionOutcome::Ready(active) => Arc::new(active),
            other => panic!("fixture activation must be ready: {other:#?}"),
        };
        let root = tempfile::tempdir().expect("isolated Java project");
        let analyzer = crate::analyzer::java::JavaAnalyzer::from_project(
            brokk_bifrost_core::analyzer::project::TestProject::new(
                root.path(),
                brokk_bifrost_core::analyzer::model::Language::Java,
            ),
        );
        let overlay = Arc::new(
            SemanticModelOverlay::build(
                &analyzer,
                &active,
                &cancellation,
                64 << 20,
                &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
            )
            .expect("fixture overlay"),
        );
        JvmExternalDeclarations::new(artifacts, Some(overlay)).with_active_models(Some(active))
    }

    /// A JDK type with the supertype inventory a real JMOD pack carries.
    fn model_type(
        name: &str,
        type_parameters: &[&str],
        supertypes: &[TypeRef],
    ) -> serde_json::Value {
        let edges = supertypes
            .iter()
            .map(|target| serde_json::json!({"hierarchy_kind": "implements", "target": target}))
            .collect::<Vec<_>>();
        serde_json::json!({
            "id": format!("type.{}", name.to_lowercase()), "name": name, "type_kind": "class",
            "visibility": "public", "is_abstract": false, "is_sealed": false,
            "jvm_inventory": {
                "callables_complete": false, "values_complete": false, "types_complete": false,
                "supertypes_complete": true, "supertypes": edges, "nested_types": [],
                "additional_members": []
            },
            "has_explicit_type_terms": true, "type_parameters": type_parameters,
            "type_parameter_constraints": [], "embedded_types": [], "hierarchy": edges,
            "aliases": [], "extension_surfaces": [],
            "locator": {"kind": "artifact", "path": format!("{name}.class"), "symbol": name}
        })
    }

    fn jdk_model_types() -> Vec<serde_json::Value> {
        let object = || named("java.lang.Object");
        let parameter = |name: &str| TypeRef::TypeParameter { name: name.into() };
        vec![
            model_type("java.lang.Object", &[], &[]),
            model_type("java.lang.CharSequence", &[], &[object()]),
            model_type(
                "java.lang.String",
                &[],
                &[object(), named("java.lang.CharSequence")],
            ),
            model_type("java.lang.Integer", &[], &[object()]),
            model_type("java.lang.Iterable", &["T"], &[object()]),
            model_type(
                "java.util.Collection",
                &["E"],
                &[object(), iterable(parameter("E"))],
            ),
            model_type(
                "java.util.ArrayList",
                &["E"],
                &[object(), applied("java.util.Collection", &[parameter("E")])],
            ),
        ]
    }

    #[test]
    fn jar_owner_edges_continue_through_the_jdk_model_overlay() {
        use JavaExternalConversion::{Inapplicable, Strict, Unknown};
        let directory = tempfile::tempdir().unwrap();
        let index = generic_class_index(
            &directory,
            "generic.jar",
            &[
                DEPENDENCY_CLASSES,
                &[(
                    "dep/ViaCollection",
                    OBJECT_CLASS,
                    &["java/util/Collection"],
                    Some("<V:Ljava/lang/Object;>Ljava/lang/Object;Ljava/util/Collection<TV;>;"),
                )],
            ],
        );
        let surface = surface_over_model_types(&index, jdk_model_types());
        assert_projected_iterable_conversions(&surface);

        // A pack answer that has a witness but also an owner with an unclosed
        // hierarchy is one route, not every route.
        let mut unclosed = jdk_model_types();
        for model in &mut unclosed {
            if model["name"] == "java.util.Collection" {
                model["jvm_inventory"]["supertypes_complete"] = false.into();
            }
        }
        let unclosed_surface = surface_over_model_types(&index, unclosed);
        assert_eq!(
            java_external_conversion_in(
                &applied("dep.ViaCollection", &[named("java.lang.String")]),
                &iterable(extends(named("java.lang.CharSequence"))),
                Some(&unclosed_surface)
            ),
            Unknown(ConversionUnknown::GenericSubstitution)
        );

        let (string, integer) = (named("java.lang.String"), named("java.lang.Integer"));
        let chars = named("java.lang.CharSequence");
        let via = applied("dep.ViaCollection", std::slice::from_ref(&string));
        let array_list = applied("java.util.ArrayList", std::slice::from_ref(&string));
        for (actual, formal, expected) in [
            // Jar edge, then a model edge that has its own type parameter.
            (&via, iterable(extends(chars.clone())), Strict),
            (&via, iterable(integer.clone()), Inapplicable),
            (&via, iterable(extends(integer.clone())), Inapplicable),
            (&via, named("java.lang.Iterable"), Strict),
            // The packs cannot exhaust a path to a type only the jar declares.
            (
                &via,
                named("dep.ListLike"),
                Unknown(ConversionUnknown::IncompleteHierarchy),
            ),
            // A pack-declared source composes the same way.
            (&array_list, iterable(extends(chars.clone())), Strict),
            (&array_list, iterable(string.clone()), Strict),
            (&array_list, iterable(integer.clone()), Inapplicable),
            // Raw use of a generic source through a parent: reachable only.
            (
                &named("java.util.ArrayList"),
                iterable(string.clone()),
                Unknown(ConversionUnknown::GenericSubstitution),
            ),
            // The same unread parent the jar-only surface reported stays open.
            (
                &applied("dep.Orphan", std::slice::from_ref(&string)),
                iterable(string.clone()),
                Unknown(ConversionUnknown::IncompleteHierarchy),
            ),
        ] {
            assert_eq!(
                java_external_conversion_in(actual, &formal, Some(&surface)),
                expected,
                "{actual:?} -> {formal:?}"
            );
        }
    }

    #[test]
    fn one_jar_answers_the_same_through_either_branch() {
        let directory = tempfile::tempdir().unwrap();
        let jar = directory.path().join("generic.jar");
        generic_class_jar(&jar, &[STUB_JDK_CLASSES, DEPENDENCY_CLASSES].concat());
        let as_class_files = probe_index(&jar);
        let class_file_surface = JvmExternalDeclarations::new(&as_class_files, None);

        // The same class files, published as pack declarations by the producer
        // dependency packs use, with no artifact index behind them.
        let production =
            JvmDependencyPackAdapter::read_jar_declarations(&jar).expect("read the fixture jar");
        let pack = production.pack.expect("the producer publishes a pack");
        let types = pack
            .shards
            .iter()
            .flat_map(|shard| match &shard.payload {
                AuthoredPayload::DeclarationFacts { types, .. } => types.as_slice(),
                _ => &[],
            })
            .map(|fact| serde_json::to_value(fact).expect("a type fact serializes"))
            // The inventory names this root, which a fixture jar cannot declare.
            .chain([model_type("java.lang.Object", &[], &[])])
            .collect::<Vec<_>>();
        let no_artifacts = JvmExternalDeclarationIndex::default();
        let pack_surface = surface_over_model_types(&no_artifacts, types);
        for surface in [&class_file_surface, &pack_surface] {
            assert_projected_iterable_conversions(surface);
        }
        let string = || named("java.lang.String");
        for (actual, formal) in [
            (named("dep.RawKid"), iterable(string())),
            (named("dep.RawKid"), named("java.lang.Iterable")),
            (named("dep.BadSignature"), iterable(string())),
            (applied("dep.AfterBad", &[string()]), iterable(string())),
            (named("dep.Mid"), iterable(string())),
            (named("dep.GroundKid"), iterable(string())),
            (
                applied("dep.Nested", &[string()]),
                iterable(applied("dep.ListLike", &[string()])),
            ),
            (applied("dep.Orphan", &[string()]), iterable(string())),
            (named("dep.Concrete"), named("dep.Entry")),
            (named("dep.ListLike"), applied("dep.ListLike", &[string()])),
        ] {
            assert_eq!(
                java_external_conversion_in(&actual, &formal, Some(&class_file_surface)),
                java_external_conversion_in(&actual, &formal, Some(&pack_surface)),
                "{actual:?} -> {formal:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // The artifact half of the JVM external member surface (#1900).
    // -----------------------------------------------------------------------

    /// A class JAR declaring `com.example.probe.Registry`, which extends
    /// `com.example.probe.BaseRegistry`. `register` is declared on the subclass
    /// and `reset` is inherited from the base, so one fixture covers both
    /// shapes a written `Owner.member` can take.
    ///
    /// The third entry is a private nested class, which every real JAR carries
    /// and this index deliberately publishes for nobody. It is here so the
    /// fixture proves a *deliberate exclusion* does not make the artifact
    /// report as not fully read.
    fn probe_class_jar(path: &Path) {
        let mut classes = probe_registry_base_class_files()
            .into_iter()
            .collect::<Vec<_>>();
        classes.push(TestClassFile {
            internal_name: "com/example/probe/Registry$Hidden",
            super_internal_name: "java/lang/Object",
            methods: &[TestClassMethod {
                name: "secret",
                descriptor: "()V",
                is_static: true,
            }],
            private_nested: true,
        });
        write_test_class_jar(path, &classes);
    }

    fn probe_index(jar: &Path) -> JvmExternalDeclarationIndex {
        JvmExternalDeclarationIndex::build_from_artifacts(vec![ResolvedJvmArtifact {
            artifact_path: jar.to_path_buf(),
            source_artifact_path: None,
            coordinate: None,
            origin: JvmDependencyOrigin::ExplicitPath,
        }])
    }

    #[test]
    #[hardwon("#9559: direct writer generation changes caused repeated retained index rebuilds")]
    fn direct_writer_extra_rebuild_is_bounded_to_one() {
        use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;
        use brokk_bifrost_analysis::analyzer::read_ledger::{ReadKey, ReadLedger};
        let root = tempfile::tempdir().unwrap();
        let jar = root.path().join("probe.jar");
        probe_class_jar(&jar);
        let store =
            brokk_bifrost_analysis::analyzer::store::AnalyzerStore::open_ephemeral().unwrap();
        let project = Arc::new(TestProject::new(root.path(), Language::Java));
        let analyzer = crate::analyzer::java::JavaAnalyzer::new(project.clone());
        let config = JvmAnalyzerConfig {
            external_dependencies: JvmExternalDependencies {
                artifact_paths: vec![JvmExternalArtifact {
                    artifact_path: jar,
                    source_artifact_path: None,
                    coordinate: None,
                    origin: JvmExternalArtifactOrigin::Explicit,
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        let slot = super::super::authority::JvmExternalIndexSlot::new(8 << 20);
        let get = || {
            get_or_build_external_declaration_index(
                &analyzer,
                &slot,
                (
                    Language::Java,
                    brokk_bifrost_analysis::analyzer::WorkspaceFactFamily::JavaExternalDeclarations,
                ),
                &config,
                &store,
            )
        };
        let before = EXTERNAL_INDEX_BUILDS.get();
        let generation = store.jvm_external_inventory_generation().unwrap();
        let ledger = Arc::new(ReadLedger::new());
        let first = {
            let _capture = AnalyzerQueryScope::with_read_ledger(&analyzer, ledger.clone());
            get()
        };
        assert!(
            !ledger
                .keys()
                .iter()
                .any(|key| matches!(key, ReadKey::Models(_)))
        );
        assert!(store.jvm_external_inventory_generation().unwrap() > generation);
        assert_eq!(EXTERNAL_INDEX_BUILDS.get(), before + 1);
        let second = get();
        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(EXTERNAL_INDEX_BUILDS.get(), before + 2);
        let third = get();
        assert!(Arc::ptr_eq(&second, &third));
        assert_eq!(EXTERNAL_INDEX_BUILDS.get(), before + 2);
        let cold = JvmExternalDeclarationIndex::build_for_project_with_inventory(
            &config,
            project.as_ref(),
            &store,
            &analyzer,
        )
        .unwrap();
        let shapes = |index: &JvmExternalDeclarationIndex| {
            index.members_by_owner["com.example.probe.Registry"].members["register"]
                .call_shapes
                .clone()
        };
        assert_eq!(shapes(&second), shapes(&cold));
        assert!(
            shapes(&second)
                .iter()
                .all(|shape| shape.inventory_identity.is_some())
        );
    }

    #[test]
    #[hardwon(
        "#9559: retained JVM external index kept stale inventory identity after bind-time publication"
    )]
    fn another_connection_publication_rebuilds_inventory_identity() {
        let root = tempfile::tempdir().unwrap();
        let jar = root.path().join("probe.jar");
        probe_class_jar(&jar);
        let store = brokk_bifrost_analysis::analyzer::store::AnalyzerStore::open_persistent(
            &root.path().join("inventory.sqlite"),
        )
        .unwrap();
        let project = Arc::new(TestProject::new(root.path(), Language::Java));
        let analyzer = crate::analyzer::java::JavaAnalyzer::new(project.clone());
        let config = JvmAnalyzerConfig {
            external_dependencies: JvmExternalDependencies {
                artifact_paths: vec![JvmExternalArtifact {
                    artifact_path: jar,
                    source_artifact_path: None,
                    coordinate: None,
                    origin: JvmExternalArtifactOrigin::Explicit,
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        let slot = super::super::authority::JvmExternalIndexSlot::new(8 << 20);
        let get = || {
            get_or_build_external_declaration_index(
                &analyzer,
                &slot,
                (
                    Language::Java,
                    brokk_bifrost_analysis::analyzer::WorkspaceFactFamily::JavaExternalDeclarations,
                ),
                &config,
                &store,
            )
        };
        JvmExternalDeclarationIndex::build_for_project_with_inventory(
            &config,
            project.as_ref(),
            &store,
            &analyzer,
        )
        .unwrap();
        let first = get();
        let retained = get();
        assert!(Arc::ptr_eq(&first, &retained));
        let before = EXTERNAL_INDEX_BUILDS.get();
        let other = rusqlite::Connection::open(root.path().join("inventory.sqlite")).unwrap();
        other.execute(
            "UPDATE jvm_external_owner_members SET ordinal=ordinal+100 WHERE member_name='register'", [],
        ).unwrap();
        let second = get();
        assert!(!Arc::ptr_eq(&retained, &second));
        assert_eq!(EXTERNAL_INDEX_BUILDS.get(), before + 1);
        let cold = JvmExternalDeclarationIndex::build_for_project_with_inventory(
            &config,
            project.as_ref(),
            &store,
            &analyzer,
        )
        .unwrap();
        let shapes = |index: &JvmExternalDeclarationIndex| {
            index.members_by_owner["com.example.probe.Registry"].members["register"]
                .call_shapes
                .clone()
        };
        assert_eq!(shapes(&second), shapes(&cold));
        assert!(
            shapes(&second)
                .iter()
                .all(|shape| shape.inventory_identity.is_some())
        );
    }

    #[test]
    #[hardwon(
        "#9559: retained JVM external index kept stale inventory identity after bind-time publication"
    )]
    #[expect(
        clippy::disallowed_methods,
        reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
    )]
    fn request_publication_rebuilds_inventory_identity() {
        let root = tempfile::tempdir().unwrap();
        let jar = root.path().join("probe.jar");
        probe_class_jar(&jar);
        let store = brokk_bifrost_analysis::analyzer::store::AnalyzerStore::open_persistent(
            &root.path().join("inventory.sqlite"),
        )
        .unwrap();
        let project = Arc::new(TestProject::new(root.path(), Language::Java));
        let analyzer = crate::analyzer::java::JavaAnalyzer::new(project.clone());
        let config = JvmAnalyzerConfig {
            external_dependencies: JvmExternalDependencies {
                artifact_paths: vec![JvmExternalArtifact {
                    artifact_path: jar,
                    source_artifact_path: None,
                    coordinate: None,
                    origin: JvmExternalArtifactOrigin::Explicit,
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        let slot = super::super::authority::JvmExternalIndexSlot::new(8 << 20);
        let get = || {
            get_or_build_external_declaration_index(
                &analyzer,
                &slot,
                (
                    Language::Java,
                    brokk_bifrost_analysis::analyzer::WorkspaceFactFamily::JavaExternalDeclarations,
                ),
                &config,
                &store,
            )
        };
        JvmExternalDeclarationIndex::build_for_project_with_inventory(
            &config,
            project.as_ref(),
            &store,
            &analyzer,
        )
        .unwrap();
        let first = get();
        let retained = get();
        assert!(Arc::ptr_eq(&first, &retained));
        let before = EXTERNAL_INDEX_BUILDS.get();
        use brokk_bifrost_analysis::analyzer::store::jvm_external_publication::{
            JvmExternalProjection, JvmExternalPublication,
        };
        let provider = retained.inventory_providers[0].clone();
        let read_rows = |sql: &str, width: usize| {
            let conn = store.read_conn().unwrap();
            conn.prepare(sql)
                .unwrap()
                .query_map([&provider], |row| {
                    (0..width)
                        .map(|i| row.get::<_, rusqlite::types::Value>(i))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        let owners = read_rows(
            "SELECT provider_id,owner_fqn,callables_complete,values_complete,types_complete,supertypes_complete,json(type_parameters_jsonb) FROM jvm_external_owners WHERE provider_id=?1",
            7,
        );
        let mut members = read_rows(
            "SELECT provider_id,owner_fqn,ordinal,member_name,member_kind,visibility,is_static,signature_present,callable_family_complete,non_overridable,json(parameters_jsonb),json(return_type_jsonb),is_abstract,json(type_parameters_jsonb) FROM jvm_external_owner_members WHERE provider_id=?1",
            14,
        );
        for row in &mut members {
            let rusqlite::types::Value::Integer(ordinal) = &mut row[2] else {
                panic!("integer ordinal")
            };
            *ordinal += 100;
        }
        // A request's publication replaces the legacy projection and seals it.
        let _request = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::with_read_ledger(
            &analyzer,
            Arc::new(brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger::new()),
        );
        assert_eq!(
            store
                .publish_jvm_external_projection(
                    || Ok(Some(JvmExternalProjection {
                        semantic_sha256: evict_uncertified_test_provider(&store, &provider),
                        provider_id: provider.clone(),
                        source_identity: "request-publication".into(),
                        owners,
                        members,
                        supertypes: Vec::new(),
                    })),
                    || false
                )
                .unwrap(),
            JvmExternalPublication::Available
        );
        let second = get();
        assert!(!Arc::ptr_eq(&retained, &second));
        assert_eq!(EXTERNAL_INDEX_BUILDS.get(), before + 1);
        let cold = JvmExternalDeclarationIndex::build_for_project_with_inventory(
            &config,
            project.as_ref(),
            &store,
            &analyzer,
        )
        .unwrap();
        let shapes = |index: &JvmExternalDeclarationIndex| {
            index.members_by_owner["com.example.probe.Registry"].members["register"]
                .call_shapes
                .clone()
        };
        assert_eq!(shapes(&second), shapes(&cold));
        assert!(
            shapes(&second)
                .iter()
                .all(|shape| shape.inventory_identity.is_some())
        );
    }

    // Model eviction before publishing a replacement, never an in-place state transition.
    fn evict_uncertified_test_provider(
        store: &brokk_bifrost_analysis::analyzer::store::AnalyzerStore,
        provider: &str,
    ) -> String {
        let provider = provider.to_owned();
        store.conn.execute(move |conn| -> brokk_bifrost_analysis::analyzer::store::Result<String> {
            let semantic_sha256 = conn.query_row("SELECT semantic_sha256 FROM jvm_external_provider_publications WHERE provider_id=?1 AND publication_state='uncertified'", [&provider], |row| row.get(0))?;
            conn.execute("DELETE FROM jvm_external_provider_publications WHERE provider_id=?1", [provider])?;
            Ok(semantic_sha256)
        }).unwrap()
    }

    #[test]
    #[hardwon(
        "#9559: retained JVM external index kept stale inventory identity after bind-time publication"
    )]
    fn persisted_provider_inventory_receipt_is_stale_after_publication() {
        use brokk_bifrost_analysis::analyzer::read_ledger::{
            LookupKind, ReadKey, ReadLedger, read_set_digest,
        };
        use brokk_bifrost_analysis::analyzer::store::jvm_external_publication::{
            JvmExternalProjection, JvmExternalPublication,
        };
        use brokk_bifrost_analysis::analyzer::store::policy_units::{
            PolicyUnitPartitionRow, PolicyUnitRow, PolicyUnitRowKey,
        };
        use brokk_bifrost_analysis::analyzer::{
            AnalyzerQueryScope, ChangedFacts, HeadInputs, LookupMemo, LookupReplayLimits,
            NoSummaryAnswers, ReadVerdict, WorkspaceAnalyzer, verify_read_set_for_artifact,
        };
        use brokk_bifrost_semantic::analyzer::semantic::invalidation::DerivedArtifactId;
        let root = tempfile::tempdir().unwrap();
        let jar = root.path().join("probe.jar");
        probe_class_jar(&jar);
        let project = Arc::new(TestProject::new(root.path(), Language::Java));
        let analyzer = crate::analyzer::java::JavaAnalyzer::new(project.clone());
        let config = JvmAnalyzerConfig {
            external_dependencies: JvmExternalDependencies {
                artifact_paths: vec![JvmExternalArtifact {
                    artifact_path: jar,
                    source_artifact_path: None,
                    coordinate: None,
                    origin: JvmExternalArtifactOrigin::Explicit,
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(project.clone(), Default::default())
                .unwrap();
        let store = workspace.store().expect("store-backed verification");
        let ledger = Arc::new(ReadLedger::new());
        let slot = super::super::authority::JvmExternalIndexSlot::new(8 << 20);
        let index = {
            let _capture = AnalyzerQueryScope::with_read_ledger(&analyzer, ledger.clone());
            get_or_build_external_declaration_index(
                &analyzer,
                &slot,
                (
                    Language::Java,
                    brokk_bifrost_analysis::analyzer::WorkspaceFactFamily::JavaExternalDeclarations,
                ),
                &config,
                store,
            )
        };
        // Persist the captured provider lookup, excluding unrelated discovery reads.
        let reads: Vec<_> = ledger
            .keys()
            .into_iter()
            .filter(|key| {
                matches!(key,
                    ReadKey::Lookup { kind: LookupKind::Derivation(kind), .. }
                        if kind.0 == "derivation:jvm_external_provider_inventory:v1"
                )
            })
            .collect();
        assert_eq!(reads.len(), 1, "real fill must record its provider receipt");
        let digest = StableDigest::sha256(b"persisted JVM provider receipt");
        let key = PolicyUnitRowKey {
            policy_semantic_hash: digest.to_string(),
            family: "match".into(),
            partition: PolicyUnitPartitionRow::Whole,
            configuration_fingerprint: digest.to_string(),
            active_model_set_hash: digest.to_string(),
            engine_epoch: digest.to_string(),
        };
        store
            .publish_policy_units(vec![PolicyUnitRow {
                seed_parse_variant: None,
                key: key.clone(),
                product_kind: "rows".into(),
                product: "{\"rows\":[]}".into(),
                read_set_digest: *read_set_digest(&reads).digest().as_bytes(),
                reads: reads.clone(),
                snapshots: vec![[1; 32]],
            }])
            .unwrap();
        let loaded = store
            .policy_units_for_keys(&[key])
            .unwrap()
            .pop()
            .unwrap()
            .unwrap();
        assert_eq!(loaded.reads, reads);
        let changed = ChangedFacts::between(&workspace, &workspace);
        let inputs = HeadInputs {
            models: digest,
            policy_semantic_hash: digest,
            policy_source: digest,
            configuration: digest,
            epoch: digest,
        };
        let verify = || {
            verify_read_set_for_artifact(
                DerivedArtifactId::semantic_artifact(digest),
                &workspace,
                &changed,
                &inputs,
                &loaded.reads,
                LookupReplayLimits::default(),
                &NoSummaryAnswers,
                &mut LookupMemo::new(),
            )
        };
        assert_eq!(verify(), ReadVerdict::Unchanged);
        assert_eq!(
            store
                .publish_jvm_external_projection(
                    || Ok(Some(JvmExternalProjection {
                        semantic_sha256: evict_uncertified_test_provider(
                            store,
                            &index.inventory_providers[0]
                        ),
                        provider_id: index.inventory_providers[0].clone(),
                        source_identity: "receipt-publication".into(),
                        owners: Vec::new(),
                        members: Vec::new(),
                        supertypes: Vec::new(),
                    })),
                    || false,
                )
                .unwrap(),
            JvmExternalPublication::Available
        );
        assert_eq!(
            verify().changed().expect("persisted receipt is stale").key,
            reads[0]
        );
    }

    #[test]
    #[hardwon(
        "#9559: retained JVM external index kept stale inventory identity after bind-time publication"
    )]
    fn provider_sealed_between_requests_rebuilds_retained_inventory() {
        let root = tempfile::tempdir().unwrap();
        let jar = root.path().join("probe.jar");
        probe_class_jar(&jar);
        let store = brokk_bifrost_analysis::analyzer::store::AnalyzerStore::open_persistent(
            &root.path().join("inventory.sqlite"),
        )
        .unwrap();
        let project = Arc::new(TestProject::new(root.path(), Language::Java));
        let analyzer = crate::analyzer::java::JavaAnalyzer::new(project.clone());
        let config = JvmAnalyzerConfig {
            external_dependencies: JvmExternalDependencies {
                artifact_paths: vec![JvmExternalArtifact {
                    artifact_path: jar,
                    source_artifact_path: None,
                    coordinate: None,
                    origin: JvmExternalArtifactOrigin::Explicit,
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        let slot = super::super::authority::JvmExternalIndexSlot::new(8 << 20);
        let get = || {
            get_or_build_external_declaration_index(
                &analyzer,
                &slot,
                (
                    Language::Java,
                    brokk_bifrost_analysis::analyzer::WorkspaceFactFamily::JavaExternalDeclarations,
                ),
                &config,
                &store,
            )
        };
        JvmExternalDeclarationIndex::build_for_project_with_inventory(
            &config,
            project.as_ref(),
            &store,
            &analyzer,
        )
        .unwrap();
        let first = get();
        let retained = get();
        assert!(Arc::ptr_eq(&first, &retained));
        let before = EXTERNAL_INDEX_BUILDS.get();
        use brokk_bifrost_analysis::analyzer::store::jvm_external_publication::{
            JvmExternalProjection, JvmExternalPublication,
        };
        let provider = retained.inventory_providers[0].clone();
        assert_eq!(
            store
                .publish_jvm_external_projection(
                    || Ok(Some(JvmExternalProjection {
                        semantic_sha256: evict_uncertified_test_provider(&store, &provider),
                        provider_id: provider,
                        source_identity: "sealed-between-requests".into(),
                        owners: Vec::new(),
                        members: Vec::new(),
                        supertypes: Vec::new(),
                    })),
                    || false,
                )
                .unwrap(),
            JvmExternalPublication::Available
        );
        let second = get();
        assert!(!Arc::ptr_eq(&retained, &second));
        assert_eq!(EXTERNAL_INDEX_BUILDS.get(), before + 1);
        // Publication bumps the generation, so this route rebuilds the cell.
        assert!(
            second.members_by_owner["com.example.probe.Registry"].members["register"]
                .call_shapes
                .iter()
                .all(|shape| shape.inventory_identity.is_none())
        );
        assert!(
            second
                .production_diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code
                    == crate::analyzer::jvm::producer_codes::JVM_INVENTORY_SEALED.code)
        );
        assert!(Arc::ptr_eq(&second, &get()));
    }

    #[test]
    #[hardwon("#9559: direct inventory writes to a sealed provider must report Open")]
    #[expect(
        clippy::disallowed_methods,
        reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
    )]
    fn sealed_direct_inventory_is_open() {
        use brokk_bifrost_analysis::analyzer::store::jvm_external_publication::{
            JvmExternalProjection, JvmExternalPublication,
        };
        let root = tempfile::tempdir().unwrap();
        let jar = root.path().join("probe.jar");
        probe_class_jar(&jar);
        let store =
            brokk_bifrost_analysis::analyzer::store::AnalyzerStore::open_ephemeral().unwrap();
        let config = JvmAnalyzerConfig {
            external_dependencies: JvmExternalDependencies {
                artifact_paths: vec![JvmExternalArtifact {
                    artifact_path: jar,
                    source_artifact_path: None,
                    coordinate: None,
                    origin: JvmExternalArtifactOrigin::Explicit,
                }],
                ..JvmExternalDependencies::default()
            },
            ..JvmAnalyzerConfig::default()
        };
        let project = TestProject::new(root.path(), Language::Java);
        JvmExternalDeclarationIndex::select_external_inventory::<std::convert::Infallible>(
            &config,
            &project,
            &manifest_scope(&project, &Default::default()),
            |selected| {
                assert_eq!(
                    store
                        .publish_jvm_external_projection(
                            || Ok(Some(JvmExternalProjection {
                                semantic_sha256: selected.exact.sha256().to_owned(),
                                provider_id: selected.provider_id,
                                source_identity: "sealed-empty".into(),
                                owners: Vec::new(),
                                members: Vec::new(),
                                supertypes: Vec::new(),
                            })),
                            || false
                        )
                        .unwrap(),
                    JvmExternalPublication::Available
                );
                Ok(())
            },
        )
        .unwrap();
        let analyzer = crate::analyzer::java::JavaAnalyzer::new(Arc::new(TestProject::new(
            root.path(),
            Language::Java,
        )));
        let index = JvmExternalDeclarationIndex::build_for_project_with_inventory(
            &config, &project, &store, &analyzer,
        )
        .expect("sealed inventory is an outcome, not a store error");
        assert_eq!(index.inventory_providers.len(), 1);
        let diagnostic = index
            .production_diagnostics
            .iter()
            .find(|diagnostic| {
                diagnostic.code == crate::analyzer::jvm::producer_codes::JVM_INVENTORY_SEALED.code
            })
            .expect("sealed provider reports incompleteness");
        assert!(matches!(
            crate::analyzer::jvm::producer_codes::classify(diagnostic),
            brokk_bifrost_analysis::analyzer::QueryReadIncomplete::ArtifactUnavailable(_)
        ));
        let count: i64 = store
            .read_conn()
            .unwrap()
            .query_row("SELECT count(*) FROM jvm_external_owners", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "sealed inventory is unchanged");
    }

    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
    )]
    fn method_bounds_states_round_trip_through_store() {
        use brokk_bifrost_semantic::analyzer::semantic_model::model::{
            GenericTraitBound, ImplementedTraitFact,
        };
        let root = tempfile::tempdir().unwrap();
        let jar = root.path().join("generic.jar");
        let class = TestClassFile {
            internal_name: "example/Generic",
            super_internal_name: OBJECT_CLASS,
            methods: &[TestClassMethod {
                name: "identity",
                descriptor: "(Ljava/lang/Object;)Ljava/lang/Object;",
                is_static: true,
            }],
            private_nested: false,
        };
        write_test_generic_class_jar(
            &jar,
            &[(
                &class,
                TestClassGenerics {
                    method_signatures: &["<T:Ljava/lang/Object;>(TT;)TT;"],
                    ..Default::default()
                },
            )],
        );
        let production = JavaJarPackProducer.produce_exact_artifact(
            &brokk_bifrost_analysis::test_support::artifact_production_request(
                jar,
                ExternalArtifactKind::JavaClassJar,
                "bifrost.test.bounds-states",
                "maven",
                "fixture:bounds-states",
                "generated test fixture",
            ),
            &ArtifactProducerLimits::default(),
        );
        let pack = production.pack.unwrap();
        let (types, members) = pack
            .shards
            .iter()
            .find_map(|shard| match &shard.payload {
                AuthoredPayload::DeclarationFacts { types, members, .. } if !members.is_empty() => {
                    Some((types, members))
                }
                _ => None,
            })
            .unwrap();
        let original = member_signature(&pack, "identity");
        let bound_type = TypeRef::named("java.lang.Number");
        let states = [
            None,
            Some(vec![]),
            Some(vec![GenericTraitBound {
                subject: TypeRef::TypeParameter { name: "T".into() },
                bound: ImplementedTraitFact {
                    rust_stability: None,
                    trait_type: bound_type.clone(),
                    is_negative: false,
                    type_parameters: vec![],
                    self_pattern: None,
                    bounds: vec![],
                    associated_types: vec![],
                },
                maybe: false,
            }]),
        ];
        for (index, bounds) in states.into_iter().enumerate() {
            let database = root.path().join(format!("states-{index}.sqlite"));
            let mut signature = original.clone();
            signature.bounds = bounds.clone();
            let wire = serde_json::to_value(&signature).unwrap();
            if index == 0 {
                assert!(wire.get("bounds").is_none());
            }
            if index == 1 {
                assert_eq!(wire["bounds"], serde_json::json!([]));
            }
            let decoded: Signature = serde_json::from_value(wire).unwrap();
            assert_eq!(decoded.bounds, bounds);
            let mut members = members.clone();
            members
                .iter_mut()
                .find(|member| member.name == "identity")
                .unwrap()
                .signature = Some(decoded);
            let store =
                brokk_bifrost_analysis::analyzer::store::AnalyzerStore::open_persistent(&database)
                    .unwrap();
            store
                .publish_jvm_external_inventory_facts("bounds-states".into(), types, &members, true)
                .unwrap();
            drop(store);
            let store =
                brokk_bifrost_analysis::analyzer::store::AnalyzerStore::open_persistent(&database)
                    .unwrap();
            let conn = store.read_conn().unwrap();
            let json: String = conn.query_row("SELECT json(type_parameters_jsonb) FROM jvm_external_owner_members WHERE member_name='identity'", [], |row| row.get(0)).unwrap();
            let expected = match index {
                0 => serde_json::json!([{"name":"T","bounds":{"state":"unknown"}}]),
                1 => serde_json::json!([{"name":"T","bounds":{"state":"known","types":[]}}]),
                _ => {
                    serde_json::json!([{"name":"T","bounds":{"state":"known","types":[bound_type]}}])
                }
            };
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&json).unwrap(),
                expected
            );
        }
        let legacy: Signature =
            serde_json::from_value(serde_json::json!({"type_parameters":["T"]})).unwrap();
        assert!(legacy.bounds.is_none());
    }

    #[test]
    #[hardwon("#12385: non-public generic methods did not raise the produced pack schema")]
    #[expect(
        clippy::disallowed_methods,
        reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
    )]
    fn jar_method_bounds_upgrade_matches_fresh_projection() {
        use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

        let root = tempfile::tempdir().unwrap();
        let jar = root.path().join("generic.jar");
        let produced_schema = || {
            let production = JavaJarPackProducer.produce_exact_artifact(
                &brokk_bifrost_analysis::test_support::artifact_production_request(
                    jar.clone(),
                    ExternalArtifactKind::JavaClassJar,
                    "bifrost.test.method-bounds",
                    "maven",
                    "fixture:method-bounds",
                    "generated test fixture",
                ),
                &ArtifactProducerLimits::default(),
            );
            let pack = production.pack.expect("class-file declaration pack");
            brokk_bifrost_semantic::analyzer::semantic_model::compiler::compile_pack(
                &pack,
                &brokk_bifrost_semantic::analyzer::semantic_model::CompilerOptions::default(),
            )
            .unwrap();
            pack.schema_version
        };
        // The only generic method is package-private and lives in the inventory.
        let hidden = TestClassFile {
            internal_name: "example/Generic",
            super_internal_name: OBJECT_CLASS,
            methods: &[TestClassMethod {
                name: "hidden",
                descriptor: "(Ljava/lang/Number;)Ljava/lang/Number;",
                is_static: true,
            }],
            private_nested: false,
        };
        let bytes = test_class_file_bytes_with_signatures(
            &hidden,
            TestClassAccess {
                class: 0x0021,
                methods: &[0x0008],
                interfaces: &[],
            },
            None,
            &["<T:Ljava/lang/Number;>(TT;)TT;"],
        );
        write_zip_entry(&jar, "example/Generic.class", &bytes);
        // Every class-file pack carries is_final (#10572), so it is schema
        // 43 whether or not it records method bounds (41).
        assert_eq!(
            produced_schema(),
            brokk_bifrost_semantic::analyzer::semantic_model::CLASS_FINALITY_MIN_SCHEMA_VERSION
        );
        write_test_class_jar(
            &jar,
            &[TestClassFile {
                internal_name: "example/Generic",
                super_internal_name: OBJECT_CLASS,
                methods: &[TestClassMethod {
                    name: "identity",
                    descriptor: "(Ljava/lang/Object;)Ljava/lang/Object;",
                    is_static: true,
                }],
                private_nested: false,
            }],
        );
        assert_eq!(
            produced_schema(),
            brokk_bifrost_semantic::analyzer::semantic_model::CLASS_FINALITY_MIN_SCHEMA_VERSION
        );
        // Test-only class file, equivalent to public static <T> T identity(T value).
        write_test_generic_class_jar(
            &jar,
            &[(
                &TestClassFile {
                    internal_name: "example/Generic",
                    super_internal_name: OBJECT_CLASS,
                    methods: &[TestClassMethod {
                        name: "identity",
                        descriptor: "(Ljava/lang/Object;)Ljava/lang/Object;",
                        is_static: true,
                    }],
                    private_nested: false,
                },
                TestClassGenerics {
                    method_signatures: &["<T:Ljava/lang/Object;>(TT;)TT;"],
                    ..Default::default()
                },
            )],
        );
        assert_eq!(
            produced_schema(),
            brokk_bifrost_semantic::analyzer::semantic_model::CLASS_FINALITY_MIN_SCHEMA_VERSION
        );
        let config = JvmAnalyzerConfig {
            external_dependencies: JvmExternalDependencies {
                artifact_paths: vec![JvmExternalArtifact {
                    artifact_path: jar,
                    source_artifact_path: None,
                    coordinate: None,
                    origin: JvmExternalArtifactOrigin::Explicit,
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        let project = Arc::new(TestProject::new(root.path(), Language::Java));
        let analyzer = crate::analyzer::java::JavaAnalyzer::new(project.clone());
        let database = root.path().join("warm.sqlite");
        let warm = AnalyzerStore::open_persistent(&database).unwrap();
        JvmExternalDeclarationIndex::build_for_project_with_inventory(
            &config,
            project.as_ref(),
            &warm,
            &analyzer,
        )
        .unwrap();
        drop(warm);
        {
            let conn = rusqlite::Connection::open(&database).unwrap();
            // Preserve M1's publication certificate while replacing only the bounds.
            // Inventory updates are sealed while the certificate exists.
            conn.execute_batch(r#"CREATE TEMP TABLE old_publication AS SELECT * FROM jvm_external_provider_publications;
                DELETE FROM jvm_external_provider_publications;
                UPDATE jvm_external_owner_members SET type_parameters_jsonb=jsonb('[{"name":"T","bounds":{"state":"unknown"}}]') WHERE member_name='identity';
                INSERT INTO jvm_external_provider_publications SELECT * FROM old_publication;
                DROP TABLE old_publication;
                "#).unwrap();
            brokk_bifrost_core::cache_db::test_apply_migration(
                &conn,
                brokk_bifrost_core::cache_db::JVM_METHOD_BOUNDS_MIGRATION_VERSION,
            );
        }
        let warm = AnalyzerStore::open_persistent(&database).unwrap();
        let cold = AnalyzerStore::open_ephemeral().unwrap();
        let bounds = |store: &AnalyzerStore| -> String {
            JvmExternalDeclarationIndex::build_for_project_with_inventory(
                &config,
                project.as_ref(),
                store,
                &analyzer,
            )
            .unwrap();
            store.read_conn().unwrap().query_row(
                "SELECT json(type_parameters_jsonb) FROM jvm_external_owner_members WHERE owner_fqn='example.Generic' AND member_name='identity'",
                [], |row| row.get(0),
            ).unwrap()
        };
        let fresh = bounds(&cold);
        assert_eq!(
            fresh,
            r#"[{"name":"T","bounds":{"state":"known","types":[]}}]"#
        );
        assert_eq!(bounds(&warm), fresh);
    }

    /// The declaration shard of a pack, as its types and members.
    fn declaration_facts(pack: &AuthoredSemanticModelPack) -> (&[TypeFact], &[MemberFact]) {
        pack.shards
            .iter()
            .find_map(|shard| match &shard.payload {
                AuthoredPayload::DeclarationFacts { types, members, .. } => {
                    Some((types.as_slice(), members.as_slice()))
                }
                _ => None,
            })
            .expect("declaration shard")
    }

    fn member_signature<'a>(
        pack: &'a AuthoredSemanticModelPack,
        name: &str,
    ) -> &'a brokk_bifrost_analysis::analyzer::semantic_model::Signature {
        declaration_facts(pack)
            .1
            .iter()
            .find(|member| member.name == name)
            .and_then(|member| member.signature.as_ref())
            .unwrap_or_else(|| panic!("a signature for {name}"))
    }

    #[test]
    fn jar_method_bound_naming_an_unrecorded_type_variable_stays_unknown() {
        let root = tempfile::tempdir().unwrap();
        let jar = root.path().join("inner.jar");
        let methods = |name| {
            [TestClassMethod {
                name,
                descriptor: "()V",
                is_static: false,
            }]
        };
        let outer = TestClassFile {
            internal_name: "example/Outer",
            super_internal_name: OBJECT_CLASS,
            methods: &[],
            private_nested: false,
        };
        let inner_methods = methods("f");
        // No `InnerClasses` entry: the inner class's enclosing scope is not recorded,
        // so the owner's type parameters do not include Outer's T.
        let inner = TestClassFile {
            internal_name: "example/Outer$Inner",
            super_internal_name: OBJECT_CLASS,
            methods: &inner_methods,
            private_nested: false,
        };
        let resolved_methods = methods("g");
        let resolved = TestClassFile {
            internal_name: "example/Generic",
            super_internal_name: OBJECT_CLASS,
            methods: &resolved_methods,
            private_nested: false,
        };
        write_test_generic_class_jar(
            &jar,
            &[
                (
                    &outer,
                    TestClassGenerics {
                        signature: Some("<T:Ljava/lang/Object;>Ljava/lang/Object;"),
                        ..Default::default()
                    },
                ),
                (
                    &inner,
                    TestClassGenerics {
                        method_signatures: &["<U:TT;>()V"],
                        ..Default::default()
                    },
                ),
                (
                    &resolved,
                    TestClassGenerics {
                        method_signatures: &["<V:Ljava/lang/Number;>()V"],
                        ..Default::default()
                    },
                ),
            ],
        );
        let production = JavaJarPackProducer.produce_exact_artifact(
            &brokk_bifrost_analysis::test_support::artifact_production_request(
                jar,
                ExternalArtifactKind::JavaClassJar,
                "bifrost.test.inner-bounds",
                "maven",
                "fixture:inner-bounds",
                "generated test fixture",
            ),
            &ArtifactProducerLimits::default(),
        );
        let pack = production.pack.expect("class-file declaration pack");
        brokk_bifrost_semantic::analyzer::semantic_model::compiler::compile_pack(
            &pack,
            &brokk_bifrost_semantic::analyzer::semantic_model::CompilerOptions::default(),
        )
        .expect("a bound on a variable outside the owner must not reject the pack");
        let unresolved = member_signature(&pack, "f");
        assert_eq!(unresolved.type_parameters, ["U"], "the signature is kept");
        assert!(unresolved.bounds.is_none(), "bounds unknown");
        let known = member_signature(&pack, "g");
        assert_eq!(known.type_parameters, ["V"]);
        assert_eq!(known.bounds.as_ref().unwrap().len(), 1);
    }

    #[test]
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only: real JDK 21")]
    #[hardwon(
        "#12385: attaching sources dropped bounds that name an enclosing class's type parameter"
    )]
    fn java_indexed_jdk_attaching_sources_preserves_enclosing_parameter_bounds() {
        use brokk_bifrost_semantic::analyzer::semantic_model::producer::read_exact_artifact;
        let temp = tempfile::tempdir().unwrap();
        let source = b"package example; public class Outer<T> { public class Inner { public <U extends T> void f() {} } }";
        let source_path = temp.path().join("Outer.java");
        std::fs::write(&source_path, source).unwrap();
        let classes = temp.path().join("classes");
        std::fs::create_dir(&classes).unwrap();
        let home = PathBuf::from(std::env::var_os("BIFROST_JDK_HOME").expect("real JDK 21"));
        let javac = home
            .join("bin")
            .join(if cfg!(windows) { "javac.exe" } else { "javac" });
        brokk_bifrost_analysis::test_support::run_command_success(
            std::process::Command::new(javac)
                .arg("-d")
                .arg(&classes)
                .arg(&source_path),
        );
        let outer = std::fs::read(classes.join("example/Outer.class")).unwrap();
        let inner = std::fs::read(classes.join("example/Outer$Inner.class")).unwrap();
        let class_jar = temp.path().join("inner.jar");
        brokk_bifrost_analysis::test_support::zip_helpers::write_zip_unwrap(
            &class_jar,
            &[
                ("example/Outer.class", outer.as_slice()),
                ("example/Outer$Inner.class", inner.as_slice()),
            ],
            SimpleFileOptions::default(),
        );
        let source_jar = temp.path().join("inner-sources.jar");
        write_zip_entry(&source_jar, "example/Outer.java", source);
        let dependency = resolved_semantic_pack_dependency(ResolvedJvmArtifact {
            artifact_path: class_jar.clone(),
            source_artifact_path: Some(source_jar.clone()),
            coordinate: Some(JvmMavenCoordinate::new("example", "inner", "1.0.0")),
            origin: JvmDependencyOrigin::ExplicitPath,
        });
        let limits = ArtifactProducerLimits::default();
        let produce = |path: &Path, kind| {
            let mut request = jvm_dependency_production_request(&dependency);
            request.path = path.to_path_buf();
            request.artifact_kind = kind;
            let artifact = read_exact_artifact(path, &limits).unwrap();
            JavaJarPackProducer
                .produce_loaded_artifact(&request, &limits, None, &artifact)
                .pack
                .unwrap()
        };
        let binary = produce(&class_jar, ExternalArtifactKind::JavaClassJar);
        let source = produce(&source_jar, ExternalArtifactKind::JavaSourceJar);
        let (types, _) = declaration_facts(&binary);
        let inner = types
            .iter()
            .find(|owner| owner.name == "example.Outer.Inner")
            .unwrap();
        assert_eq!(
            inner
                .jvm_inventory
                .as_ref()
                .unwrap()
                .enclosing_type_parameters,
            ["T"]
        );
        let bounds = member_signature(&binary, "f").bounds.clone();
        assert!(bounds.is_some());
        let merged = merge_java_dependency_packs(
            Some(source),
            Some(binary),
            &mut Vec::new(),
            &mut SuppressedDiagnostics::default(),
            &limits,
        )
        .unwrap();
        assert_eq!(member_signature(&merged, "f").bounds, bounds);
        brokk_bifrost_semantic::analyzer::semantic_model::compiler::compile_pack(
            &merged,
            &brokk_bifrost_semantic::analyzer::semantic_model::CompilerOptions::default(),
        )
        .unwrap();
    }

    #[test]
    fn attaching_sources_keeps_the_binary_method_bounds() {
        use brokk_bifrost_semantic::analyzer::semantic_model::producer::read_exact_artifact;

        let temp = tempfile::tempdir().unwrap();
        let class_jar = temp.path().join("generic.jar");
        let class = TestClassFile {
            internal_name: "example/Generic",
            super_internal_name: OBJECT_CLASS,
            methods: &[TestClassMethod {
                name: "identity",
                descriptor: "(Ljava/lang/Number;)Ljava/lang/Number;",
                is_static: true,
            }],
            private_nested: false,
        };
        // Equivalent to public static <T extends Number> T identity(T x).
        write_test_generic_class_jar(
            &class_jar,
            &[(
                &class,
                TestClassGenerics {
                    method_signatures: &["<T:Ljava/lang/Number;>(TT;)TT;"],
                    ..Default::default()
                },
            )],
        );
        let source_jar = temp.path().join("generic-sources.jar");
        write_zip_entry(
            &source_jar,
            "example/Generic.java",
            b"package example; public class Generic { public static <T extends Number> T identity(T x) { return x; } }",
        );
        let dependency = resolved_semantic_pack_dependency(ResolvedJvmArtifact {
            artifact_path: class_jar.clone(),
            source_artifact_path: Some(source_jar.clone()),
            coordinate: Some(JvmMavenCoordinate::new("example", "generic", "1.0.0")),
            origin: JvmDependencyOrigin::ExplicitPath,
        });
        let limits = ArtifactProducerLimits::default();
        let produce = |path: &Path, kind| {
            let mut request = jvm_dependency_production_request(&dependency);
            request.path = path.to_path_buf();
            request.artifact_kind = kind;
            let artifact = read_exact_artifact(path, &limits).unwrap();
            let result =
                JavaJarPackProducer.produce_loaded_artifact(&request, &limits, None, &artifact);
            result.pack.expect("Java fixture pack")
        };
        let source_pack = produce(&source_jar, ExternalArtifactKind::JavaSourceJar);
        let binary_pack = produce(&class_jar, ExternalArtifactKind::JavaClassJar);
        let binary_bounds = member_signature(&binary_pack, "identity").bounds.clone();
        assert_eq!(
            binary_bounds.as_ref().unwrap().len(),
            1,
            "the binary records its bounds"
        );
        assert!(
            member_signature(&source_pack, "identity").bounds.is_none(),
            "sources record no bounds"
        );
        let mut diagnostics = Vec::new();
        let mut suppressed = SuppressedDiagnostics::default();
        let merged = merge_java_dependency_packs(
            Some(source_pack),
            Some(binary_pack),
            &mut diagnostics,
            &mut suppressed,
            &limits,
        )
        .unwrap();
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert_eq!(member_signature(&merged, "identity").bounds, binary_bounds);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13800: a partial JDK source archive downgraded a complete JMOD inventory"
    )]
    fn complete_jdk_jmod_set_keeps_the_pack_complete_with_partial_sources() {
        use brokk_bifrost_analysis::analyzer::semantic_model::CatalogOptions;
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;
        use brokk_bifrost_analysis::analyzer::semantic_model::dependency::prepare_dependency_semantic_packs;

        let root = tempfile::tempdir().unwrap();
        let home = root.path().canonicalize().unwrap().join("jdk-21");
        write_test_jdk_jmods(&home, &[]);
        fs::create_dir_all(home.join("lib")).unwrap();
        write_zip_entries(
            &home.join("lib/src.zip"),
            &[
                (
                    "java.base/module-info.java",
                    b"module java.base { exports java.lang; }",
                ),
                (
                    "java.base/java/lang/Object.java",
                    b"package java.lang; public class Object { ??? }",
                ),
            ],
        );
        let config = test_jdk_config(&home);
        let project = TestProject::new(root.path(), Language::Java);
        let limits = DependencyPackLimits::default();
        let discovered = resolve_jvm_semantic_pack_dependencies(
            &config,
            &project,
            &test_digests(),
            &Default::default(),
            &limits,
            None,
        );
        assert!(discovered.complete, "{:#?}", discovered.diagnostics);
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let prepared = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            &discovered.dependencies,
            &limits,
            None,
        );
        assert!(prepared.complete, "{:#?}", prepared.diagnostics);
        assert_eq!(prepared.packs.len(), 1);
        assert_eq!(prepared.packs[0].completeness, Completeness::Complete);
        assert!(
            prepared
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code
                    == crate::analyzer::jvm::producer_codes::JAVA_SOURCE_PARSE.code
                    && diagnostic.severity
                        == brokk_bifrost_semantic::analyzer::semantic_model::DependencyPackDiagnosticSeverity::Warning),
            "{:#?}",
            prepared.diagnostics
        );
    }

    #[test]
    #[hardwon("#12385: binary bounds used owner binders discarded by source attachment")]
    fn attaching_sources_with_renamed_owner_parameters_keeps_bounds_unknown() {
        use brokk_bifrost_semantic::analyzer::semantic_model::producer::read_exact_artifact;

        let temp = tempfile::tempdir().unwrap();
        let class_jar = temp.path().join("generic.jar");
        let class = TestClassFile {
            internal_name: "example/Generic",
            super_internal_name: OBJECT_CLASS,
            methods: &[TestClassMethod {
                name: "identity",
                descriptor: "(Ljava/lang/Object;)Ljava/lang/Object;",
                is_static: true,
            }],
            private_nested: false,
        };
        // Equivalent to public static <T extends Number> T identity(T x).
        write_test_generic_class_jar(
            &class_jar,
            &[(
                &class,
                TestClassGenerics {
                    signature: Some("<U:Ljava/lang/Object;>Ljava/lang/Object;"),
                    method_signatures: &["<V:TU;>(TV;)TV;"],
                    ..Default::default()
                },
            )],
        );
        let source_jar = temp.path().join("generic-sources.jar");
        write_zip_entry(
            &source_jar,
            "example/Generic.java",
            b"package example; public class Generic<T> { public static <V> V identity(V x) { return x; } }",
        );
        let dependency = resolved_semantic_pack_dependency(ResolvedJvmArtifact {
            artifact_path: class_jar.clone(),
            source_artifact_path: Some(source_jar.clone()),
            coordinate: Some(JvmMavenCoordinate::new("example", "generic", "1.0.0")),
            origin: JvmDependencyOrigin::ExplicitPath,
        });
        let limits = ArtifactProducerLimits::default();
        let produce = |path: &Path, kind| {
            let mut request = jvm_dependency_production_request(&dependency);
            request.path = path.to_path_buf();
            request.artifact_kind = kind;
            let artifact = read_exact_artifact(path, &limits).unwrap();
            let result =
                JavaJarPackProducer.produce_loaded_artifact(&request, &limits, None, &artifact);
            result.pack.expect("Java fixture pack")
        };
        let source_pack = produce(&source_jar, ExternalArtifactKind::JavaSourceJar);
        let binary_pack = produce(&class_jar, ExternalArtifactKind::JavaClassJar);
        let binary_bounds = member_signature(&binary_pack, "identity").bounds.clone();
        assert_eq!(
            binary_bounds.as_ref().unwrap().len(),
            1,
            "the binary records its bounds"
        );
        assert!(
            member_signature(&source_pack, "identity").bounds.is_none(),
            "sources record no bounds"
        );
        let mut diagnostics = Vec::new();
        let mut suppressed = SuppressedDiagnostics::default();
        let merged = merge_java_dependency_packs(
            Some(source_pack),
            Some(binary_pack),
            &mut diagnostics,
            &mut suppressed,
            &limits,
        )
        .unwrap();
        assert!(member_signature(&merged, "identity").bounds.is_none());
        brokk_bifrost_semantic::analyzer::semantic_model::compiler::compile_pack(
            &merged,
            &brokk_bifrost_semantic::analyzer::semantic_model::CompilerOptions::default(),
        )
        .unwrap();
    }

    #[test]
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only: real JDK 21")]
    #[expect(
        clippy::disallowed_methods,
        reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
    )]
    fn java_indexed_jdk_generic_surfaces_project_to_store() {
        let home = PathBuf::from(std::env::var_os("BIFROST_JDK_HOME").expect("real JDK 21"));
        let production = JvmDependencyPackAdapter::read_jdk_jmod_declarations(&home).unwrap();
        let pack = production.pack.expect("JDK declaration pack");
        brokk_bifrost_semantic::analyzer::semantic_model::compiler::compile_pack(
            &pack,
            &brokk_bifrost_semantic::analyzer::semantic_model::CompilerOptions::default(),
        )
        .unwrap();
        let comparable = TypeRef::Named {
            name: "java.lang.Comparable".into(),
            nullable: false,
            arguments: vec![TypeRef::Wildcard {
                variance: brokk_bifrost_analysis::analyzer::semantic_model::WildcardVariance::Super,
                bound: Some(Box::new(TypeRef::TypeParameter { name: "T".into() })),
            }],
        };
        for (owner, name, bounds) in [
            ("java.util.Collections", "max", vec![comparable.clone()]),
            ("java.util.Collections", "sort", vec![comparable.clone()]),
            ("java.util.Collections", "singletonList", vec![]),
            ("java.util.Arrays", "asList", vec![]),
        ] {
            let signatures: Vec<_> = pack
                .shards
                .iter()
                .filter_map(|shard| match &shard.payload {
                    AuthoredPayload::DeclarationFacts { types, members, .. } => {
                        Some((types, members))
                    }
                    _ => None,
                })
                .flat_map(|(types, members)| {
                    members.iter().filter(move |member| {
                        member.name == name
                            && types
                                .iter()
                                .any(|ty| ty.id == member.owner && ty.name == owner)
                    })
                })
                .filter_map(|member| member.signature.as_ref())
                .filter(|signature| signature.parameters.len() == 1)
                .collect();
            assert!(!signatures.is_empty(), "{owner}.{name}");
            for signature in signatures {
                assert_eq!(
                    signature.bounds,
                    Some(bounds.iter().map(|trait_type| brokk_bifrost_semantic::analyzer::semantic_model::model::GenericTraitBound {
                        subject: TypeRef::TypeParameter { name: "T".into() },
                        bound: brokk_bifrost_semantic::analyzer::semantic_model::model::ImplementedTraitFact {
                            rust_stability: None,
                            trait_type: trait_type.clone(), is_negative: false, type_parameters: vec![],
                            self_pattern: None, bounds: vec![], associated_types: vec![],
                        }, maybe: false,
                    }).collect()),
                    "{owner}.{name}"
                );
            }
        }
        let store =
            brokk_bifrost_analysis::analyzer::store::AnalyzerStore::open_ephemeral().unwrap();
        for shard in pack.shards {
            if let AuthoredPayload::DeclarationFacts { types, members, .. } = shard.payload {
                store
                    .publish_jvm_external_inventory_facts(
                        "jdk-generics".into(),
                        &types,
                        &members,
                        true,
                    )
                    .unwrap();
            }
        }
        let conn = store.read_conn().unwrap();
        let member: String = conn.query_row("SELECT json(type_parameters_jsonb) FROM jvm_external_owner_members WHERE owner_fqn='java.util.Collections' AND member_name='unmodifiableList'", [], |row| row.get(0)).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&member).unwrap(),
            serde_json::json!([{"name":"T","bounds":{"state":"known","types":[]}}])
        );
        let maximum: String = conn.query_row("SELECT json(type_parameters_jsonb) FROM jvm_external_owner_members WHERE owner_fqn='java.util.Collections' AND member_name='max' AND json_array_length(parameters_jsonb)=1", [], |row| row.get(0)).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&maximum).unwrap(),
            serde_json::json!([{"name":"T","bounds":{"state":"known","types":[comparable]}}])
        );
        let owner: String = conn.query_row("SELECT json(type_parameters_jsonb) FROM jvm_external_owners WHERE owner_fqn='java.util.ArrayList'", [], |row| row.get(0)).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&owner).unwrap(),
            serde_json::json!([{"name":"E","bounds":{"state":"unknown"}}])
        );
        let arguments: String = conn.query_row("SELECT json(type_arguments_jsonb) FROM jvm_external_owner_supertypes WHERE owner_fqn='java.util.ArrayList' AND supertype_fqn='java.util.AbstractList'", [], |row| row.get(0)).unwrap();
        assert_eq!(
            serde_json::from_str::<Vec<TypeRef>>(&arguments).unwrap(),
            vec![TypeRef::TypeParameter { name: "E".into() }]
        );
        let ordinary: String = conn.query_row("SELECT json(type_parameters_jsonb) FROM jvm_external_owner_members WHERE owner_fqn='java.util.ArrayList' AND member_name='size'", [], |row| row.get(0)).unwrap();
        assert_eq!(ordinary, "[]");
    }

    #[test]
    #[hardwon(
        "#1900: A JAR member declaration must resolve where class metadata had previously discarded it"
    )]
    #[expect(
        clippy::disallowed_methods,
        reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
    )]
    fn a_class_jar_member_answers_a_written_member_spelling() {
        let root = tempfile::tempdir().unwrap();
        let jar = root.path().join("probe.jar");
        probe_class_jar(&jar);
        let store =
            brokk_bifrost_analysis::analyzer::store::AnalyzerStore::open_ephemeral().unwrap();
        let config = JvmAnalyzerConfig {
            external_dependencies: JvmExternalDependencies {
                artifact_paths: vec![JvmExternalArtifact {
                    artifact_path: jar.clone(),
                    source_artifact_path: None,
                    coordinate: None,
                    origin: JvmExternalArtifactOrigin::Explicit,
                }],
                ..JvmExternalDependencies::default()
            },
            ..JvmAnalyzerConfig::default()
        };
        let project = TestProject::new(root.path(), Language::Java);
        let analyzer = crate::analyzer::java::JavaAnalyzer::new(Arc::new(TestProject::new(
            root.path(),
            Language::Java,
        )));
        let stored = JvmExternalDeclarationIndex::build_for_project_with_inventory(
            &config, &project, &store, &analyzer,
        )
        .unwrap();
        let provider = stored
            .inventory_providers
            .first()
            .expect("indexed artifact content identity");
        let conn = store.read_conn().unwrap();
        let coverage: (bool, bool, bool, bool) = conn.query_row(
            "SELECT callables_complete,values_complete,types_complete,supertypes_complete FROM jvm_external_owners WHERE provider_id=?1 AND owner_fqn='com.example.probe.Registry'",
            [provider], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).unwrap();
        assert_eq!(coverage, (true, true, true, true));
        let gaps = std::cell::RefCell::new(Vec::new());
        let declared = JvmExternalDeclarations::new(stored.as_ref(), None)
            .resolve_member_spelling(
                &QueryGapRecorder::collecting(&gaps),
                "com.example.probe.Registry.register",
                "app",
                |owner| stored.get(owner).cloned(),
            )
            .unwrap();
        let identity = declared
            .direct_inventory_identity_for_argument_types(
                false,
                &[TypeRef::named("java.lang.String")],
                None,
                None,
            )
            .expect("direct overload has its durable member coordinate");
        assert_eq!(identity.owner.provider_id.as_ref(), provider);
        let persisted: String = conn.query_row("SELECT member_name FROM jvm_external_owner_members WHERE provider_id=?1 AND owner_fqn=?2 AND ordinal=?3", rusqlite::params![identity.owner.provider_id.as_ref(),identity.owner.owner_fqn.as_ref(),identity.ordinal], |row| row.get(0)).unwrap();
        assert_eq!(persisted, "register");
        drop(conn);
        let index = probe_index(&jar);
        let surface = JvmExternalDeclarations::new(&index, None);

        assert!(
            index.get("com.example.probe.Registry").is_some(),
            "the type half still indexes the owner"
        );
        let gaps = std::cell::RefCell::new(Vec::new());
        let recorder = QueryGapRecorder::collecting(&gaps);
        let owner = |spelling: &str| surface.resolve_qualified_name(&recorder, spelling, "app");
        let member = surface
            .resolve_member_spelling(
                &recorder,
                "com.example.probe.Registry.register",
                "app",
                owner,
            )
            .expect("the class jar declares the member");
        assert_eq!(member.fqn(), "com.example.probe.Registry.register");

        // Inherited: `reset` is declared on the base class in the same jar, and
        // a reference spells it through the subclass exactly as it spells a
        // declared member.
        let inherited = surface
            .resolve_member_spelling(&recorder, "com.example.probe.Registry.reset", "app", owner)
            .expect("the base class in the same jar declares the member");
        assert_eq!(inherited.fqn(), "com.example.probe.BaseRegistry.reset");

        // A member no class file declares is not upgraded: the owner is
        // decided, and the spelling stays exactly as unknown as before.
        assert!(
            surface
                .resolve_member_spelling(
                    &recorder,
                    "com.example.probe.Registry.absent",
                    "app",
                    owner
                )
                .is_none()
        );
        // An owner nothing indexed answers nothing at all.
        assert!(
            surface
                .resolve_member_spelling(
                    &recorder,
                    "com.example.probe.Missing.register",
                    "app",
                    owner
                )
                .is_none()
        );
        // A class the index deliberately publishes for nobody -- the private
        // nested `Registry$Hidden` -- was read completely and is not a gap.
        // Counting it as unread would make every ordinary JAR report as
        // declared-but-not-indexed, which would turn every honest miss in the
        // whole workspace into "may be there".
        assert!(
            index.get("com.example.probe.Registry.Hidden").is_none(),
            "a private nested class is not published"
        );
        assert_eq!(
            index.production_diagnostic_count(),
            0,
            "the whole fixture jar was read: {:?}",
            index.production_diagnostics()
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "e9573913cd3c: resolve_member_spelling returned early on a missing owner without closing the miss"
    )]
    fn a_class_entry_the_byte_budget_refused_declares_no_member_surface() {
        // Honest absence for the artifact half: an owner whose class entry the
        // bounded read never finished has no member surface, so its members are
        // unknown rather than absent -- and the index says so, which is what
        // makes every JVM boundary report `external_declared_unindexed` instead
        // of `external_unknown`.
        let root = tempfile::tempdir().unwrap();
        let jar = root.path().join("probe.jar");
        probe_class_jar(&jar);

        let mut index = JvmExternalDeclarationIndex::default();
        // One byte of budget refuses every entry in the archive.
        index.index_class_jar(&jar, 1);
        let surface = JvmExternalDeclarations::new(&index, None);
        assert!(
            index.get("com.example.probe.Registry").is_none(),
            "a refused entry declares no type either"
        );
        assert!(
            index
                .member("com.example.probe.Registry", "register")
                .0
                .is_none(),
            "a refused entry declares no member surface"
        );
        let gaps = std::cell::RefCell::new(Vec::new());
        let recorder = QueryGapRecorder::collecting(&gaps);
        assert!(
            surface
                .resolve_member_spelling(
                    &recorder,
                    "com.example.probe.Registry.register",
                    "app",
                    |spelling| surface.resolve_qualified_name(&recorder, spelling, "app")
                )
                .is_none()
        );
        let diagnostics = index.production_diagnostics();
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "jvm.index.runtime_budget"),
            "a refused read must be recorded, not silently look complete: {diagnostics:?}"
        );
        assert!(gaps.borrow().iter().any(|reason| {
            reason.execution_cause() == Some(brokk_bifrost_analysis::analyzer::read_ledger::DerivationExecutionCause::Budget)
                && reason.stable_replay_reason().is_none()
        }), "shared index allowance must remain operational: {:?}", gaps.borrow());
        assert!(index.production_diagnostic_count() > 0);
    }

    /// A class JAR whose first entry alone spends the whole per-artifact member
    /// budget, so `Registry`'s own members are read *after* the charge is gone.
    /// Everything stays well inside the byte and entry bounds, which is the
    /// point: members are a bound of their own.
    fn member_saturated_class_jar(path: &Path) {
        let names: Vec<String> = (0..MAX_ARTIFACT_MEMBERS)
            .map(|ordinal| format!("filler{ordinal}"))
            .collect();
        let filler_methods: Vec<TestClassMethod<'_>> = names
            .iter()
            .map(|name| TestClassMethod {
                name,
                descriptor: "()V",
                is_static: true,
            })
            .collect();
        write_test_class_jar(
            path,
            &[
                TestClassFile {
                    internal_name: "com/example/probe/Filler",
                    super_internal_name: "java/lang/Object",
                    methods: &filler_methods,
                    private_nested: false,
                },
                TestClassFile {
                    internal_name: "com/example/probe/Registry",
                    super_internal_name: "java/lang/Object",
                    methods: &[TestClassMethod {
                        name: "register",
                        descriptor: "(Ljava/lang/String;)V",
                        is_static: true,
                    }],
                    private_nested: false,
                },
            ],
        );
    }

    #[test]
    fn the_per_artifact_member_bound_drops_members_and_says_so() {
        // The second bounded dimension #1900 requires beside
        // `MAX_TOTAL_INDEX_BYTES`: one artifact well inside the byte budget can
        // declare any number of members, so members are charged per artifact.
        // What must not happen is a silent short surface -- the owner type is
        // still indexed, so a member spelling on it would otherwise look
        // decidable -- which is why exhausting the charge is recorded.
        let root = tempfile::tempdir().unwrap();
        let jar = root.path().join("probe.jar");
        member_saturated_class_jar(&jar);
        let index = probe_index(&jar);
        let surface = JvmExternalDeclarations::new(&index, None);

        assert!(
            index.get("com.example.probe.Registry").is_some(),
            "the type half still indexes the owner; only members were bounded"
        );
        let gaps = std::cell::RefCell::new(Vec::new());
        let recorder = QueryGapRecorder::collecting(&gaps);
        assert!(
            surface
                .resolve_member_spelling(
                    &recorder,
                    "com.example.probe.Registry.register",
                    "app",
                    |spelling| surface.resolve_qualified_name(&recorder, spelling, "app")
                )
                .is_none(),
            "the member fell past the per-artifact bound"
        );
        let diagnostics = index.production_diagnostics();
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "limit.artifact_members"),
            "a bounded member read must be recorded, not look complete: {diagnostics:?}"
        );
    }

    #[test]
    fn jdk_suppression_does_not_change_dependency_selection() {
        let root = tempfile::tempdir().unwrap();
        let project = TestProject::new(root.path(), Language::Java);
        let mut config = JvmAnalyzerConfig::default();
        config.standard_library_discovery.discover_java_home = false;
        let select = |config: &JvmAnalyzerConfig| {
            JvmExternalDeclarationIndex::select_external_inventory(
                config,
                &project,
                &manifest_scope(&project, &Default::default()),
                |_| Ok::<_, std::convert::Infallible>(()),
            )
            .unwrap()
        };
        let baseline = select(&config);
        config.standard_library_discovery.jdk_homes = (0..=DependencyPackLimits::default()
            .max_diagnostics)
            .map(|index| root.path().join(format!("absent-jdk-{index}")))
            .collect();
        let discovery = resolve_jvm_semantic_pack_dependencies_unpinned(
            &config,
            &project,
            &DependencyPackLimits::default(),
            None,
        );
        assert!(discovery.suppressed_diagnostics.total() > 0);
        let selection = select(&config);
        assert!(selection.completeness.is_complete());
        assert_eq!(
            baseline.answer_digest(true, false),
            selection.answer_digest(true, false)
        );
    }

    #[test]
    #[hardwon("#9559: activation must reject missing owners in a sealed provider")]
    #[expect(
        clippy::disallowed_methods,
        reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
    )]
    fn source_bound_jdk_home_discovers_and_generates_exact_source_pack() {
        use brokk_bifrost_analysis::analyzer::semantic_model::CatalogOptions;

        use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackPreparationStatus;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

        use brokk_bifrost_analysis::analyzer::semantic_model::dependency::prepare_dependency_semantic_packs;

        use brokk_bifrost_core::analyzer::config::JvmSourceToolchainBinding;

        use brokk_bifrost_core::analyzer::config::JvmStandardLibraryDiscoveryConfig;

        let root = tempfile::tempdir().unwrap();
        let relative_home = PathBuf::from("toolchains").join("jdk-21");
        let home = root.path().join(&relative_home);
        fs::create_dir_all(home.join("lib")).unwrap();
        fs::write(home.join("release"), "JAVA_VERSION=\"21.0.8\"\n").unwrap();
        let source_archive = home.join("lib").join("src.zip");
        write_zip_entries(
            &source_archive,
            &[
                (
                    "java.base/module-info.java",
                    b"module java.base { exports java.lang; }" as &[u8],
                ),
                (
                    "java.base/java/lang/Object.java",
                    b"package java.lang; public class Object { public final String echo(String value) { return value; } public final String echo(int value) { return null; } public String echo(String value, int count) { return value; } }",
                ),
            ],
        );
        let project = TestProject::new(root.path(), Language::Java);
        let config = JvmAnalyzerConfig {
            dependency_discovery:
                brokk_bifrost_core::analyzer::config::JvmDependencyDiscoveryConfig {
                    mode: JvmDependencyDiscoveryMode::Disabled,
                    ..Default::default()
                },
            standard_library_discovery: JvmStandardLibraryDiscoveryConfig {
                source_toolchains: vec![JvmSourceToolchainBinding::new(
                    PathBuf::from("src"),
                    relative_home,
                )],
                discover_java_home: false,
                ..Default::default()
            },
            ..JvmAnalyzerConfig::default()
        };
        let limits = DependencyPackLimits::default();

        let discovered = resolve_jvm_semantic_pack_dependencies(
            &config,
            &project,
            &test_digests(),
            &Default::default(),
            &limits,
            None,
        );

        assert!(discovered.complete, "{:#?}", discovered.diagnostics);
        assert_eq!(discovered.dependencies.len(), 1);
        assert_eq!(discovered.dependencies[0].id, "jdk:21.0.8");
        assert_eq!(discovered.dependencies[0].evidence.ecosystem, "jdk");
        assert_eq!(
            discovered.dependencies[0].artifacts[0].path(),
            fs::canonicalize(source_archive).unwrap()
        );

        let catalog_root = root.path().join("catalog");
        let catalog = SemanticPackCatalog::open(
            &catalog_root,
            brokk_bifrost_analysis::analyzer::semantic_model::CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        let prepared = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            &discovered.dependencies,
            &limits,
            None,
        );
        assert!(prepared.complete, "{:#?}", prepared.diagnostics);
        assert_eq!(prepared.packs.len(), 1);
        assert_eq!(
            prepared.packs[0].status,
            DependencyPackPreparationStatus::Generated
        );
        assert!(!prepared.packs[0].evidence.verified_raw_artifacts.is_empty());
        drop(catalog);
        let catalog = SemanticPackCatalog::open(
            &catalog_root,
            brokk_bifrost_analysis::analyzer::semantic_model::CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        let again = resolve_jvm_semantic_pack_dependencies(
            &config,
            &project,
            &test_digests(),
            &Default::default(),
            &limits,
            None,
        );
        let reused = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            &again.dependencies,
            &limits,
            None,
        );
        assert!(reused.complete, "{:#?}", reused.diagnostics);
        assert_eq!(reused.profile.generated_packs, 0);
        assert_eq!(reused.profile.reused_packs, 1);
        #[cfg(unix)]
        assert_eq!(reused.profile.artifacts_read, 0);
        assert_eq!(reused.packs[0].evidence, prepared.packs[0].evidence);

        let selected =
            JvmExternalDeclarationIndex::select_jdk(&config, &project, &test_digests(), None)
                .unwrap();
        let expectations = selected.catalog_expectations();
        let brokk_bifrost_analysis::analyzer::semantic_model::catalog::ExpectedCatalogEntry::Dependency { fallback, .. } = &expectations[0] else { panic!("deferred provider choice"); };
        let brokk_bifrost_analysis::analyzer::semantic_model::catalog::ExpectedCatalogEntry::Production {
            production_digest,
        } = fallback.as_ref() else {
            panic!("a pinned JDK expects the production keyed by its content digests");
        };
        assert_eq!(
            production_digest,
            prepared.packs[0].production.key.production_digest()
        );
        let reader = catalog
            .pinned_jvm_reader(
                &expectations,
                brokk_bifrost_analysis::CancellationToken::new(),
            )
            .unwrap();
        assert_eq!(reader.membership[0].ordinal, 0);
        assert_eq!(
            reader.membership[0].status,
            brokk_bifrost_analysis::analyzer::semantic_model::catalog::PinnedCatalogStatus::Present
        );
        assert_eq!(
            reader.membership[0].production_digest.as_deref(),
            Some(prepared.packs[0].production.key.production_digest())
        );
        drop(reader);

        // Cross the generated source-archive, compiler, activation, and SQLite
        // inventory boundary, including overloads and repeat publication.
        let request =
            brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelActivationRequest {
                host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
                approximate_standard_libraries: Vec::new(),
                bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
                evidence: vec![reused.packs[0].evidence.clone()],
                controls: Vec::new(),
                limits: Default::default(),
            };
        let brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelResolutionOutcome::Ready(active) =
            brokk_bifrost_analysis::analyzer::semantic_model::runtime::resolve_active_semantic_models(
                &catalog,
                &request,
                &CancellationToken::default(),
            )
        else {
            panic!("exact generated source inventory activates");
        };
        let store =
            brokk_bifrost_analysis::analyzer::store::AnalyzerStore::open_ephemeral().unwrap();
        let sealed_store =
            brokk_bifrost_analysis::analyzer::store::AnalyzerStore::open_ephemeral().unwrap();
        for shard in active.shards() {
            use brokk_bifrost_analysis::analyzer::store::jvm_external_publication::{
                JvmExternalProjection, JvmExternalPublication,
            };
            assert_eq!(
                sealed_store
                    .publish_jvm_external_projection(
                        || Ok(Some(JvmExternalProjection {
                            semantic_sha256: shard.manifest.semantic_sha256.clone(),
                            provider_id: jvm_external_provider_id(&shard.manifest.semantic_sha256),
                            source_identity: "sealed-empty".into(),
                            owners: Vec::new(),
                            members: Vec::new(),
                            supertypes: Vec::new(),
                        })),
                        || false
                    )
                    .unwrap(),
                JvmExternalPublication::Available
            );
        }
        use super::super::catalog_reader::{
            JvmCatalogReaderAccess, JvmSelectionAuthority, jvm_catalog_reader_for_request,
        };
        use brokk_bifrost_core::analyzer::outer_request::OuterRequest;
        let bound_project: Arc<dyn brokk_bifrost_core::analyzer::project::Project> =
            Arc::new(project.clone());
        let authority = JvmSelectionAuthority {
            config: config.clone(),
            project: Arc::clone(&bound_project),
            digests: test_digests(),
            verifications: Arc::new(Default::default()),
        };
        let publish = |target: &brokk_bifrost_analysis::analyzer::store::AnalyzerStore| {
            jvm_catalog_reader_for_request(
                &authority,
                &active,
                Some(&OuterRequest::new()),
                Arc::clone(&bound_project),
                &catalog.pinned_catalog_source(
                    &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                    ),
                ),
                target,
                true,
                CancellationToken::default(),
            )
            .unwrap()
        };
        assert!(matches!(
            publish(&sealed_store),
            JvmCatalogReaderAccess::CertificateConflict
        ));
        for table in [
            "jvm_external_owners",
            "jvm_external_owner_members",
            "jvm_external_owner_supertypes",
        ] {
            let count: i64 = sealed_store
                .read_conn()
                .unwrap()
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "sealed inventory remains empty: {table}");
        }
        for _ in 0..2 {
            let JvmCatalogReaderAccess::Ready(handle) = publish(&store) else {
                panic!("exact generated source inventory is certified");
            };
            for shard in active.shards() {
                assert!(
                    handle
                        .certified_providers()
                        .contains(&jvm_external_provider_id(&shard.manifest.semantic_sha256))
                );
            }
        }
        let conn = store.read_conn().unwrap();
        let complete: bool = conn
            .query_row(
                "SELECT callables_complete FROM jvm_external_owners WHERE owner_fqn='java.lang.Object'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !complete,
            "source API inventory makes no whole-namespace absence claim"
        );
        let shapes = conn
            .prepare(
                "SELECT json_array_length(parameters_jsonb), non_overridable,
                    json_extract(return_type_jsonb, '$.name')
             FROM jvm_external_owner_members WHERE member_name='echo'
             ORDER BY json_array_length(parameters_jsonb)",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            shapes,
            vec![
                (
                    1,
                    Some("java_final_method".to_owned()),
                    "java.lang.String".to_owned()
                ),
                (
                    1,
                    Some("java_final_method".to_owned()),
                    "java.lang.String".to_owned()
                ),
                (2, None, "java.lang.String".to_owned()),
            ]
        );
        let analyzer = JavaAnalyzer::from_project(project);
        let active = Arc::new(active);
        let overlay = Arc::new(
            brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay::build(
                &analyzer,
                &active,
                &CancellationToken::default(),
                128 * 1024 * 1024,
                &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
            )
            .unwrap(),
        );
        let index = JvmExternalDeclarationIndex::default();
        let declarations = JvmExternalDeclarations::new(&index, Some(overlay));
        let gaps = std::cell::RefCell::new(Vec::new());
        let recorder = QueryGapRecorder::collecting(&gaps);
        let member = declarations
            .resolve_member_spelling(&recorder, "java.lang.Object.echo", "app", |owner| {
                declarations.resolve_qualified_name(&recorder, owner, "app")
            })
            .unwrap();
        let string = TypeRef::Named {
            name: "java.lang.String".into(),
            arguments: Vec::new(),
            nullable: false,
        };
        let integer = TypeRef::Named {
            name: "int".into(),
            arguments: Vec::new(),
            nullable: false,
        };
        let string_identity = member
            .inventory_identity_for_argument_types(&active, true, &[string], None, None)
            .unwrap();
        let integer_identity = member
            .inventory_identity_for_argument_types(&active, true, &[integer], None, None)
            .unwrap();
        assert_eq!(string_identity.owner, integer_identity.owner);
        assert_ne!(
            string_identity.ordinal, integer_identity.ordinal,
            "same-arity overloads have separate inventory identities"
        );
        for (identity, parameter) in [
            (string_identity, "java.lang.String"),
            (integer_identity, "int"),
        ] {
            let stored: String = conn.query_row(
                "SELECT json_extract(parameters_jsonb,'$[0].type.name') FROM jvm_external_owner_members WHERE provider_id=?1 AND owner_fqn=?2 AND ordinal=?3",
                rusqlite::params![identity.owner.provider_id.as_ref(), identity.owner.owner_fqn.as_ref(), identity.ordinal],
                |row| row.get(0)).unwrap();
            assert_eq!(stored, parameter);
        }
    }

    #[test]
    #[cfg(any(unix, windows))]
    #[brokk_bifrost_test_macros::hardwon(
        "#14247: Windows JDK source archives had no read-free identity"
    )]
    fn source_zip_identity_detects_replacement_with_preserved_length_and_mtime() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("src.zip");
        fs::write(&path, b"first archive").unwrap();
        let before = jdk_source_zip_identity(&path).unwrap();
        let mtime = fs::metadata(&path).unwrap().modified().unwrap();
        let replacement = root.path().join("replacement.zip");
        fs::write(&replacement, b"other archive").unwrap();
        fs::File::options()
            .write(true)
            .open(&replacement)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(mtime))
            .unwrap();
        #[cfg(windows)]
        fs::remove_file(&path).unwrap();
        fs::rename(replacement, &path).unwrap();
        assert_ne!(jdk_source_zip_identity(&path).unwrap(), before);
    }

    #[test]
    fn same_version_source_bound_jdk_homes_retain_distinct_artifact_evidence() {
        use brokk_bifrost_analysis::analyzer::semantic_model::CatalogOptions;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

        use brokk_bifrost_analysis::analyzer::semantic_model::dependency::prepare_dependency_semantic_packs;

        use brokk_bifrost_core::analyzer::config::JvmSourceToolchainBinding;

        use brokk_bifrost_core::analyzer::config::JvmStandardLibraryDiscoveryConfig;

        let root = tempfile::tempdir().unwrap();
        let home_a = PathBuf::from("toolchains/jdk-a");
        let home_b = PathBuf::from("toolchains/jdk-b");
        for (home, source) in [
            (
                &home_a,
                b"package java.lang; public final class String { public String trim() { return this; } }"
                    .as_slice(),
            ),
            (
                &home_b,
                b"package java.lang; public final class String { public String strip() { return this; } }"
                    .as_slice(),
            ),
        ] {
            let absolute = root.path().join(home);
            fs::create_dir_all(absolute.join("lib")).unwrap();
            fs::write(absolute.join("release"), "JAVA_VERSION=\"21.0.8\"\n").unwrap();
            write_zip_entries(
                &absolute.join("lib/src.zip"),
                &[
                    (
                        "java.base/module-info.java",
                        b"module java.base { exports java.lang; }",
                    ),
                    ("java.base/java/lang/String.java", source),
                ],
            );
        }
        let project = TestProject::new(root.path(), Language::Java);
        let config = JvmAnalyzerConfig {
            dependency_discovery:
                brokk_bifrost_core::analyzer::config::JvmDependencyDiscoveryConfig {
                    mode: JvmDependencyDiscoveryMode::Disabled,
                    ..Default::default()
                },
            standard_library_discovery: JvmStandardLibraryDiscoveryConfig {
                source_toolchains: vec![
                    JvmSourceToolchainBinding::new(PathBuf::from("module-a"), home_a),
                    JvmSourceToolchainBinding::new(PathBuf::from("module-b"), home_b),
                    JvmSourceToolchainBinding::new(
                        PathBuf::from("module-conflict"),
                        PathBuf::from("toolchains/jdk-a"),
                    ),
                    JvmSourceToolchainBinding::new(
                        PathBuf::from("module-conflict"),
                        PathBuf::from("toolchains/jdk-b"),
                    ),
                ],
                discover_java_home: false,
                ..Default::default()
            },
            ..JvmAnalyzerConfig::default()
        };
        let limits = DependencyPackLimits::default();
        let discovered = resolve_jvm_semantic_pack_dependencies(
            &config,
            &project,
            &test_digests(),
            &Default::default(),
            &limits,
            None,
        );
        assert!(discovered.complete, "{:#?}", discovered.diagnostics);
        assert_eq!(discovered.dependencies.len(), 2);
        assert_ne!(
            discovered.dependencies[0].id, discovered.dependencies[1].id,
            "equal release versions must still correlate to separate preparations"
        );

        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let prepared = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            &discovered.dependencies,
            &limits,
            None,
        );
        assert!(prepared.complete, "{:#?}", prepared.diagnostics);
        assert_eq!(prepared.packs.len(), 2);
        for (discovered, prepared) in discovered.dependencies.iter().zip(&prepared.packs) {
            assert_eq!(discovered.id, prepared.dependency_id);
        }
        let digests = prepared
            .packs
            .iter()
            .map(|pack| pack.evidence.single_raw_sha256().unwrap())
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(
            digests.len(),
            2,
            "each selected JDK needs its own exact artifact"
        );
        let mapping = brokk_bifrost_analysis::analyzer::workspace::prepared_jdk_artifacts_for_source_bindings(
            &brokk_bifrost_core::analyzer::config::AnalyzerConfig {
                jvm: config.clone(),
                ..Default::default()
            },
            root.path(),
            &[brokk_bifrost_analysis::analyzer::workspace::DependencyPackEcosystemOutcome {
                ecosystem: brokk_bifrost_analysis::analyzer::workspace::DependencyPackEcosystem::Jvm,
                discovery: discovered,
                preparation: Some(prepared),
            }],
        )
        .expect("the JVM ecosystem was prepared");
        assert_eq!(mapping.len(), 2);
        for binding in &config.standard_library_discovery.source_toolchains {
            let evidence = mapping
                .get(binding.jdk_home())
                .expect("each configured home has exact prepared evidence");
            assert_eq!(evidence.ecosystem, "jdk");
            assert!(!evidence.verified_raw_artifacts.is_empty());
        }
        assert_ne!(
            mapping[config.standard_library_discovery.source_toolchains[0].jdk_home()]
                .verified_raw_artifacts,
            mapping[config.standard_library_discovery.source_toolchains[1].jdk_home()]
                .verified_raw_artifacts,
        );
        for (module, source) in [
            (
                "module-a",
                "class App { void run(String value) { value.trim(); value.strip(); } }",
            ),
            (
                "module-b",
                "class App { void run(String value) { value.strip(); value.trim(); } }",
            ),
            (
                "module-conflict",
                "class App { void run(String value) { value.trim(); } }",
            ),
            (
                "module-unbound",
                "class App { void run(String value) { value.trim(); } }",
            ),
        ] {
            let source_dir = root.path().join(module).join("src");
            fs::create_dir_all(&source_dir).unwrap();
            fs::write(source_dir.join("App.java"), source).unwrap();
        }
        let workspace = brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(TestProject::new(root.path(), Language::Java)),
            brokk_bifrost_core::analyzer::config::AnalyzerConfig {
                jvm: config.clone(),
                ..Default::default()
            },
        )
        .expect("two-module Java workspace builds");
        let live = CancellationToken::default();
        let activation =
            brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelActivationRequest {
                host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
                approximate_standard_libraries: Vec::new(),
                bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
                evidence: Vec::new(),
                controls: Vec::new(),
                limits: Default::default(),
            };
        let outcome = workspace.activate_dependency_packs(
            &brokk_bifrost_core::analyzer::config::AnalyzerConfig {
                jvm: config.clone(),
                ..Default::default()
            },
            &[brokk_bifrost_analysis::analyzer::workspace::DependencyPackEcosystem::Jvm],
            brokk_bifrost_analysis::analyzer::workspace::DependencyPackWorkspaceContext {
                catalog: &catalog,
                persistence: None,
                activation: &activation,
                limits,
                cancellation: &live,
            },
        );
        let brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelRuntimeOutcome::Ready {
            snapshot, ..
        } = outcome.runtime.as_ref().expect("JDK activation runs")
        else {
            panic!("both prepared JDKs must publish: {outcome:#?}");
        };
        for binding in &config.standard_library_discovery.source_toolchains {
            assert_eq!(
                snapshot.jdk_artifact_for_home(binding.jdk_home()),
                mapping.get(binding.jdk_home()),
                "publication must keep the selected home and its exact artifact together"
            );
        }
        let check = |module: &str, member: &str| {
            let file = ProjectFile::new(root.path(), format!("{module}/src/App.java"));
            let source = fs::read_to_string(file.abs_path()).unwrap();
            let start = source.find(&format!("{member}()")).unwrap();
            let scope = AnalyzerQueryScope::new(workspace.analyzer());
            let outcomes =
                brokk_bifrost_analysis::analyzer::usages::get_definition::resolve_call_target_batch_with_source(
                    workspace.analyzer(),
                    scope.token(),
                    vec![
                        brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupRequest {
                            file: file.clone(),
                            line: None,
                            column: None,
                            start_byte: Some(start),
                            end_byte: Some(start + member.len()),
                        },
                    ],
                    file.clone(),
                    Arc::<str>::from(source.as_str()),
                    None,
                );
            outcomes.into_iter().next().expect("one call request")
        };
        for (module, accepted, rejected) in
            [("module-a", "trim", "strip"), ("module-b", "strip", "trim")]
        {
            let positive = check(module, accepted);
            let proof = positive
                .exact_external_call
                .as_ref()
                .unwrap_or_else(|| panic!("{module} must bind its own JDK member: {positive:#?}"));
            let home = config
                .standard_library_discovery
                .source_toolchains
                .iter()
                .find(|binding| binding.source_root() == Path::new(module))
                .unwrap()
                .jdk_home();
            assert_eq!(
                proof.source_jdk_artifact(),
                mapping.get(home),
                "the resolver must carry this module's prepared artifact"
            );
            let near_miss = check(module, rejected);
            assert!(
                near_miss.exact_external_call.is_none(),
                "a member declared only by the other JDK must not bind here: {near_miss:#?}"
            );
        }
        for module in ["module-conflict", "module-unbound"] {
            let unresolved = check(module, "trim");
            assert!(
                unresolved.exact_external_call.is_none(),
                "{module} has no unique selected JDK artifact: {unresolved:#?}"
            );
        }
        let oracle = workspace.semantic_oracle_provider();
        for (module, selected_member) in [("module-a", "trim"), ("module-b", "strip")] {
            let file = ProjectFile::new(root.path(), format!("{module}/src/App.java"));
            let mut budget = brokk_bifrost_analysis::analyzer::semantic::SemanticBudget::default();
            let artifact = workspace
                .materialize_program_semantics(
                    &file,
                    &mut brokk_bifrost_analysis::analyzer::semantic::SemanticRequest::new(
                        &mut budget,
                        &live,
                    ),
                )
                .expect("Java semantic materialization")
                .available_value()
                .cloned()
                .expect("Java semantic artifact");
            let mut targets = Vec::new();
            for procedure in artifact.procedures() {
                for call in procedure.call_sites() {
                    let handle = artifact
                        .procedure_handle(procedure.id())
                        .and_then(|procedure| procedure.call_site_handle(call.id))
                        .expect("scoped call handle");
                    let mut budget =
                        brokk_bifrost_analysis::analyzer::semantic::SemanticBudget::default();
                    let outcome =
                        brokk_bifrost_analysis::analyzer::semantic::DispatchOracle::resolve_call(
                            &oracle,
                            &handle,
                            &mut brokk_bifrost_analysis::analyzer::semantic::SemanticRequest::new(
                                &mut budget,
                                &live,
                            ),
                        )
                        .expect("Java external dispatch");
                    let result = outcome
                        .available_value()
                        .expect("dispatch retains a result");
                    targets.extend(
                        result
                            .boundaries()
                            .iter()
                            .filter_map(|boundary| boundary.unmaterialized_external_target())
                            .filter(|target| matches!(target.member(), "trim" | "strip"))
                            .cloned(),
                    );
                }
            }
            let exact = targets
                .iter()
                .filter(|target| target.has_resolver_owned_call_shape())
                .collect::<Vec<_>>();
            assert_eq!(
                exact.len(),
                1,
                "{module} has one exact JDK call: {targets:#?}"
            );
            assert_eq!(exact[0].member(), selected_member);
            assert!(
                targets
                    .iter()
                    .filter(|target| !target.has_resolver_owned_call_shape())
                    .all(|target| target.selected_jdk_artifact().is_none()),
                "syntax-only targets cannot inherit JDK applicability"
            );
            let home = config
                .standard_library_discovery
                .source_toolchains
                .iter()
                .find(|binding| binding.source_root() == Path::new(module))
                .unwrap()
                .jdk_home();
            assert_eq!(
                exact[0].selected_jdk_artifact(),
                mapping.get(home),
                "semantic dispatch preserves the full resolver-proven JDK row"
            );
        }
    }

    #[test]
    fn jdk_home_prefers_sources_and_falls_back_to_one_exact_jmod_source_set() {
        use brokk_bifrost_core::analyzer::config::JvmStandardLibraryDiscoveryConfig;

        use brokk_bifrost_analysis::analyzer::semantic_model::CatalogOptions;

        use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackPreparationStatus;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

        use brokk_bifrost_analysis::analyzer::semantic_model::dependency::prepare_dependency_semantic_packs;

        let root = tempfile::tempdir().unwrap();
        let relative_home = PathBuf::from("toolchains").join("jdk-21");
        let home = root.path().join(&relative_home);
        fs::create_dir_all(home.join("jmods")).unwrap();
        fs::write(home.join("release"), "JAVA_VERSION=\"21.0.8\"\n").unwrap();
        let class = test_class_file_bytes(&TestClassFile {
            internal_name: "java/lang/Object",
            super_internal_name: "java/lang/Object",
            methods: &[],
            private_nested: false,
        });
        write_zip_entries(
            &home.join("jmods/java.base.jmod"),
            &[
                (
                    "classes/module-info.class",
                    &crate::analyzer::jvm::jmod_artifact::test_module_info_class_bytes(
                        &["java/lang"],
                        &[],
                    ),
                ),
                ("classes/java/lang/Object.class", &class),
            ],
        );
        let project = TestProject::new(root.path(), Language::Java);
        let config = JvmAnalyzerConfig {
            dependency_discovery:
                brokk_bifrost_core::analyzer::config::JvmDependencyDiscoveryConfig {
                    mode: JvmDependencyDiscoveryMode::Disabled,
                    ..Default::default()
                },
            standard_library_discovery: JvmStandardLibraryDiscoveryConfig {
                jdk_homes: vec![relative_home],
                discover_java_home: false,
                ..Default::default()
            },
            ..JvmAnalyzerConfig::default()
        };
        let limits = DependencyPackLimits::default();
        let discovered = resolve_jvm_semantic_pack_dependencies(
            &config,
            &project,
            &test_digests(),
            &Default::default(),
            &limits,
            None,
        );
        assert!(discovered.complete, "{:#?}", discovered.diagnostics);
        assert_eq!(discovered.dependencies.len(), 1);
        assert_eq!(discovered.dependencies[0].artifacts.len(), 1);
        assert_eq!(
            discovered.dependencies[0].artifacts[0].kind,
            ExternalArtifactKind::JdkJmodSet
        );
        assert_eq!(
            discovered.dependencies[0].artifacts[0].path(),
            fs::canonicalize(&home).unwrap()
        );

        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let prepared = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            &discovered.dependencies,
            &limits,
            None,
        );
        assert!(prepared.complete, "{:#?}", prepared.diagnostics);
        assert_eq!(prepared.packs.len(), 1);
        assert_eq!(
            prepared.packs[0].status,
            DependencyPackPreparationStatus::Generated
        );

        // Adding a source archive retains it for formal names and also retains
        // the exact JMOD set that certifies callable-family completeness.
        fs::create_dir_all(home.join("lib")).unwrap();
        write_zip_entries(
            &home.join("lib/src.zip"),
            &[
                (
                    "java.base/module-info.java",
                    b"module java.base { exports java.lang; }",
                ),
                (
                    "java.base/java/lang/Object.java",
                    b"package java.lang; public class Object {}",
                ),
            ],
        );
        let source_discovered = discover_and_pin_jdk(&config, root.path(), None, &test_digests());
        assert_eq!(source_discovered.dependencies[0].artifacts.len(), 2);
        assert_eq!(
            source_discovered.dependencies[0].artifacts[0].kind,
            ExternalArtifactKind::JdkSourceZip
        );
        assert_eq!(
            source_discovered.dependencies[0].artifacts[0].path(),
            fs::canonicalize(home.join("lib/src.zip")).unwrap()
        );
        assert_eq!(
            source_discovered.dependencies[0].artifacts[1].kind,
            ExternalArtifactKind::JdkJmodSet
        );
        assert_eq!(
            source_discovered.dependencies[0].artifacts[1].path(),
            fs::canonicalize(&home).unwrap()
        );
    }

    /// A second production over the same installed JDK must answer from the
    /// catalog instead of reading the JMOD set again (#3429).
    ///
    /// Reading every JMOD of a real JDK is the whole cost of a
    /// zero-configuration JDK pack. Selection pins the set to its framed
    /// content digest, and the pack is found under the production key those
    /// pins form, so the second preparation captures nothing. The catalog is
    /// reopened between the two preparations, so only what the first process
    /// wrote to disk can serve the second.
    #[hardwon("#3006: a jdk jmod set serves a second production without reading")]
    #[test]
    fn jdk_jmod_set_pin_serves_a_second_production_without_reading() {
        use brokk_bifrost_analysis::analyzer::semantic_model::CatalogOpenMode;

        use brokk_bifrost_analysis::analyzer::semantic_model::CatalogOptions;

        use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackPreparationStatus;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

        use brokk_bifrost_analysis::analyzer::semantic_model::dependency::prepare_dependency_semantic_packs;

        let root = tempfile::tempdir().unwrap();
        // Pinning requires the canonical path (macOS temp roots sit under a /var link).
        let home = root.path().canonicalize().unwrap().join("jdk-21");
        write_test_jdk_jmods(&home, &["java.sql.jmod"]);
        let config = test_jdk_config(&home);
        let project = TestProject::new(root.path(), Language::Java);
        let limits = DependencyPackLimits::default();
        let discovered = resolve_jvm_semantic_pack_dependencies(
            &config,
            &project,
            &test_digests(),
            &Default::default(),
            &limits,
            None,
        );
        assert!(discovered.complete, "{:#?}", discovered.diagnostics);
        assert_eq!(discovered.dependencies.len(), 1);
        assert_eq!(
            discovered.dependencies[0].artifacts[0].kind,
            ExternalArtifactKind::JdkJmodSet
        );

        let catalog_root = root.path().join("catalog");
        let catalog = SemanticPackCatalog::open(
            &catalog_root,
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        let first = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            &discovered.dependencies,
            &limits,
            None,
        );
        assert!(first.complete, "{:#?}", first.diagnostics);
        assert_eq!(first.profile.artifacts_read, 1);
        assert_eq!(first.profile.generated_packs, 1);
        assert_eq!(
            first.packs[0].status,
            DependencyPackPreparationStatus::Generated
        );
        drop(catalog);

        // A second process: the same JDK, a freshly opened catalog handle, and
        // no in-memory memory of the first production.
        let catalog = SemanticPackCatalog::open(
            &catalog_root,
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        let discovered = resolve_jvm_semantic_pack_dependencies(
            &config,
            &project,
            &test_digests(),
            &Default::default(),
            &limits,
            None,
        );
        let second = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            &discovered.dependencies,
            &limits,
            None,
        );
        assert!(second.complete, "{:#?}", second.diagnostics);
        assert_eq!(second.profile.artifacts_read, 0);
        assert_eq!(second.profile.artifact_bytes_read, 0);
        assert_eq!(second.profile.reused_packs, 1);
        assert_eq!(second.profile.generated_packs, 0);
        assert_eq!(
            second.packs[0].status,
            DependencyPackPreparationStatus::Reused
        );
        assert_eq!(first.packs[0].production, second.packs[0].production);
        assert_eq!(first.evidence, second.evidence);
        let selected =
            JvmExternalDeclarationIndex::select_jdk(&config, &project, &test_digests(), None)
                .unwrap();
        let reader = catalog
            .pinned_jvm_reader(
                &selected.catalog_expectations(),
                brokk_bifrost_analysis::CancellationToken::new(),
            )
            .unwrap();
        assert_eq!(
            reader.membership[0].status,
            brokk_bifrost_analysis::analyzer::semantic_model::catalog::PinnedCatalogStatus::Present
        );
        drop(reader);
        // A pack installed for other bytes is not matched: the expectation is
        // the production key of the digest the current files give, even when
        // the replacement has the same name and length.
        let mut other = fs::read(home.join("jmods/java.sql.jmod")).unwrap();
        other[0] ^= 0xff;
        fs::write(home.join("jmods/java.sql.jmod"), other).unwrap();
        let changed =
            JvmExternalDeclarationIndex::select_jdk(&config, &project, &test_digests(), None)
                .unwrap();
        let reader = catalog
            .pinned_jvm_reader(
                &changed.catalog_expectations(),
                brokk_bifrost_analysis::CancellationToken::new(),
            )
            .unwrap();
        assert_eq!(reader.membership.len(), 1);
        assert_eq!(reader.membership[0].ordinal, 0);
        assert_eq!(
            reader.membership[0].status,
            brokk_bifrost_analysis::analyzer::semantic_model::catalog::PinnedCatalogStatus::Missing
        );
    }

    /// A JDK whose selected JMOD set changed is a different JDK: its packs are
    /// read and produced, never served from the identity the old set was
    /// learned under (#3429).
    #[hardwon("#3006: changed jdk jmod set identity is not served from the catalog")]
    #[test]
    fn changed_jdk_jmod_set_identity_is_not_served_from_the_catalog() {
        use brokk_bifrost_analysis::analyzer::semantic_model::CatalogOpenMode;

        use brokk_bifrost_analysis::analyzer::semantic_model::CatalogOptions;

        use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackPreparationStatus;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

        use brokk_bifrost_analysis::analyzer::semantic_model::dependency::prepare_dependency_semantic_packs;

        let root = tempfile::tempdir().unwrap();
        let home = root.path().canonicalize().unwrap().join("jdk-21");
        write_test_jdk_jmods(&home, &["java.sql.jmod"]);
        let config = test_jdk_config(&home);
        let project = TestProject::new(root.path(), Language::Java);
        let limits = DependencyPackLimits::default();
        let catalog_root = root.path().join("catalog");
        let catalog = SemanticPackCatalog::open(
            &catalog_root,
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        let discovered = resolve_jvm_semantic_pack_dependencies(
            &config,
            &project,
            &test_digests(),
            &Default::default(),
            &limits,
            None,
        );
        let first = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            &discovered.dependencies,
            &limits,
            None,
        );
        assert!(first.complete, "{:#?}", first.diagnostics);
        assert_eq!(first.profile.generated_packs, 1);
        drop(catalog);

        // A module is added to the installed JDK. The listing, a length, and a
        // modification time all change, so the recorded identity no longer
        // describes this JDK.
        write_test_jdk_jmods(&home, &["java.logging.jmod", "java.sql.jmod"]);
        let catalog = SemanticPackCatalog::open(
            &catalog_root,
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        let discovered = resolve_jvm_semantic_pack_dependencies(
            &config,
            &project,
            &test_digests(),
            &Default::default(),
            &limits,
            None,
        );
        assert_eq!(discovered.dependencies.len(), 1);
        let second = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            &discovered.dependencies,
            &limits,
            None,
        );
        assert_eq!(second.profile.artifacts_read, 1);
        assert_eq!(second.profile.reused_packs, 0);
        assert_eq!(second.profile.generated_packs, 1);
        assert_eq!(
            second.packs[0].status,
            DependencyPackPreparationStatus::Generated
        );
        assert_ne!(
            first.packs[0].production.key.input_digest(),
            second.packs[0].production.key.input_digest()
        );
    }

    /// Selection and capture are two implementations of one frame: the pin
    /// selection streams from the opened files must equal the digest capture
    /// reports for the same set, and the production key built from the pins
    /// must equal the key built from the captured bytes.
    #[test]
    fn the_selection_pin_equals_the_digest_capture_computes() {
        use brokk_bifrost_semantic::analyzer::semantic_model::dependency::{
            generated_production_key, pinned_generated_production_key,
        };
        use brokk_bifrost_semantic::analyzer::semantic_model::producer::read_exact_source_set_seekable_while;

        let root = tempfile::tempdir().unwrap();
        let home = root.path().canonicalize().unwrap().join("jdk-21");
        write_test_jdk_jmods(&home, &["java.sql.jmod", "java.logging.jmod"]);
        let config = test_jdk_config(&home);
        let project = TestProject::new(root.path(), Language::Java);
        let limits = DependencyPackLimits::default();
        let discovered = resolve_jvm_semantic_pack_dependencies(
            &config,
            &project,
            &test_digests(),
            &Default::default(),
            &limits,
            None,
        );
        let dependency = &discovered.dependencies[0];
        let artifact = &dependency.artifacts[0];
        let ResolvedDependencyArtifactInput::SourceSet {
            root: set_root,
            relative_paths,
        } = &artifact.input
        else {
            panic!("a JDK without sources selects its JMOD set");
        };
        let exact = read_exact_source_set_seekable_while(
            set_root,
            relative_paths,
            512,
            limits.max_source_path_depth,
            limits.max_total_artifact_bytes,
            &limits.producer,
            || false,
        )
        .unwrap();
        assert_eq!(artifact.expected_sha256.as_deref(), Some(exact.sha256()));
        assert!(artifact.source_identity.is_none());
        let from_pins =
            pinned_generated_production_key(&JvmDependencyPackAdapter, dependency, &limits)
                .unwrap()
                .expect("a pinned JDK produces");
        let from_bytes = generated_production_key(
            &JvmDependencyPackAdapter,
            dependency,
            &[ExactDependencyArtifact {
                role: artifact.role,
                kind: artifact.kind,
                module: None,
                artifact: exact,
            }],
            &limits,
        )
        .unwrap();
        assert_eq!(from_pins.production_digest, from_bytes.production_digest);
    }

    /// A JMOD swapped for other bytes of the same length between selection and
    /// capture must not be parsed under the pin selection computed.
    #[hardwon(
        "#9559: a JMOD replaced between JDK listing and capture could be parsed under a selection that bound only its metadata"
    )]
    #[test]
    fn a_jmod_replaced_between_selection_and_capture_fails_the_pin() {
        use brokk_bifrost_analysis::analyzer::semantic_model::CatalogOpenMode;
        use brokk_bifrost_analysis::analyzer::semantic_model::CatalogOptions;
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;
        use brokk_bifrost_analysis::analyzer::semantic_model::dependency::prepare_dependency_semantic_packs;

        let root = tempfile::tempdir().unwrap();
        let home = root.path().canonicalize().unwrap().join("jdk-21");
        write_test_jdk_jmods(&home, &["java.sql.jmod"]);
        let config = test_jdk_config(&home);
        let project = TestProject::new(root.path(), Language::Java);
        let limits = DependencyPackLimits::default();
        let selected =
            JvmExternalDeclarationIndex::select_jdk(&config, &project, &test_digests(), None)
                .unwrap();
        let jmod = home.join("jmods/java.sql.jmod");
        let modified = fs::metadata(&jmod).unwrap().modified().unwrap();
        let mut replacement = fs::read(&jmod).unwrap();
        replacement[0] ^= 0xff;
        fs::write(&jmod, &replacement).unwrap();
        fs::File::options()
            .write(true)
            .open(&jmod)
            .unwrap()
            .set_modified(modified)
            .unwrap();

        let catalog = SemanticPackCatalog::open(
            &root.path().join("catalog"),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        let prepared = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            &selected.dependencies,
            &limits,
            None,
        );
        assert!(!prepared.complete);
        assert!(prepared.packs.is_empty(), "{:#?}", prepared.packs);
        assert!(
            prepared
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "artifact.digest_changed"),
            "{:#?}",
            prepared.diagnostics
        );
        // No answer certified for the old bytes describes the new ones: a
        // fresh selection pins the replacement, and its answer differs.
        let fresh =
            JvmExternalDeclarationIndex::select_jdk(&config, &project, &test_digests(), None)
                .unwrap();
        assert_ne!(
            selected.answer_digest(true, true),
            fresh.answer_digest(true, true)
        );
    }

    #[test]
    #[hardwon(
        "#13513: a same-size rewrite within one timestamp tick reused the metadata-keyed JDK digest"
    )]
    fn racy_jdk_digests_rehash_same_size_same_mtime_rewrites() {
        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let home = root_path.join("jdk-21");
        write_test_jdk_jmods(&home, &["java.sql.jmod"]);
        fs::create_dir_all(home.join("lib")).unwrap();
        let source = home.join("lib/src.zip");
        fs::write(&source, b"source archive").unwrap();
        let jmod = home.join("jmods/java.sql.jmod");
        // Future timestamps keep the observation deterministically racy even
        // if the test process is descheduled before selection.
        let modified = std::time::SystemTime::now() + std::time::Duration::from_secs(86400);
        for path in [&jmod, &source] {
            fs::File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_modified(modified)
                .unwrap();
        }
        let config = test_jdk_config(&home);
        let project = TestProject::new(&root_path, Language::Java);
        let digests = test_digests();
        let verifications =
            brokk_bifrost_core::analyzer::external_selection::ToolchainVerifications::default();
        let question =
            brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion::for_jvm(
                &config,
            )
            .remove(1);
        let select = || {
            let before = JDK_DIGEST_COMPUTATIONS.get();
            let selected = super::super::verified_selection::verify_selection_with(
                &config,
                &project,
                &digests,
                &verifications,
                &question,
                &Default::default(),
                &Default::default(),
            )
            .unwrap();
            assert!(selected.complete);
            assert_eq!(JDK_DIGEST_COMPUTATIONS.get() - before, 2);
            selected.answer_digest
        };
        let original = select();
        assert_eq!(original, select(), "even unchanged racy files must rehash");
        let mut previous = original;
        for path in [&jmod, &source] {
            let exact_modified = fs::metadata(path).unwrap().modified().unwrap();
            let mut bytes = fs::read(path).unwrap();
            bytes[0] ^= 0xff;
            fs::write(path, bytes).unwrap();
            fs::File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_modified(exact_modified)
                .unwrap();
            assert_eq!(
                fs::metadata(path).unwrap().modified().unwrap(),
                exact_modified
            );
            let changed = select();
            assert_ne!(previous, changed);
            previous = changed;
        }
        // A service has a background-refresh callback. Matching racy metadata
        // must rehash synchronously, rather than keep scheduling a refresh that
        // can only publish another racy record for these future-dated files.
        let service =
            brokk_bifrost_core::analyzer::external_selection::ToolchainVerifications::default();
        service.replace(
            question.digest,
            verifications
                .get::<VerifiedJdkRecord>(&question.digest)
                .unwrap(),
        );
        service.set_refresh_callback(std::sync::Arc::new(|| {
            panic!("matching racy JDK metadata must not schedule background refresh");
        }));
        for _ in 0..2 {
            let before = JDK_DIGEST_COMPUTATIONS.get();
            let answer = super::super::verified_selection::verify_selection_with(
                &config,
                &project,
                &digests,
                &service,
                &question,
                &Default::default(),
                &Default::default(),
            )
            .unwrap();
            assert_eq!(JDK_DIGEST_COMPUTATIONS.get() - before, 2);
            assert_eq!(answer.answer_digest, previous);
        }
    }

    /// Only the paths that consume the pins hash the JDK: activation and the
    /// JDK question. The external declaration index and the dependencies
    /// question read the dependency list and diagnostics, never a pin, so they
    /// compute no JDK digest. Each path gets a fresh cache, so a miss is
    /// certain whether or not the file system is one the cache trusts.
    #[test]
    fn only_activation_and_the_jdk_question_hash_the_jdk() {
        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let home = root_path.join("jdk-21");
        write_test_jdk_jmods(&home, &["java.sql.jmod"]);
        let config = test_jdk_config(&home);
        let project = TestProject::new(&root_path, Language::Java);
        let computed = || JDK_DIGEST_COMPUTATIONS.get();

        let before = computed();
        let index = JvmExternalDeclarationIndex::build_for_project(&config, &project);
        assert_eq!(computed() - before, 0, "the index build hashes no JDK");
        assert!(
            index.production_diagnostics.is_empty(),
            "{:?}",
            index.production_diagnostics
        );

        let before = computed();
        JvmExternalDeclarationIndex::select_external_inventory::<std::convert::Infallible>(
            &config,
            &project,
            &manifest_scope(&project, &Default::default()),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(
            computed() - before,
            0,
            "the dependencies question hashes no JDK"
        );

        let before = computed();
        let activation = resolve_jvm_semantic_pack_dependencies(
            &config,
            &project,
            &test_digests(),
            &Default::default(),
            &DependencyPackLimits::default(),
            None,
        );
        assert_eq!(computed() - before, 1, "activation pins the JMOD set");
        assert!(
            activation.dependencies[0].artifacts[0]
                .expected_sha256
                .is_some()
        );

        let before = computed();
        let jdk = JvmExternalDeclarationIndex::select_jdk(&config, &project, &test_digests(), None)
            .unwrap();
        assert_eq!(computed() - before, 1, "the JDK question pins the JMOD set");
        assert!(jdk.every_artifact_pinned());
    }

    /// A member that cannot be hashed leaves its artifact unpinned and records
    /// an unreadable probe for that member, even when it vanished (NotFound),
    /// because a selected input that was not read is not an absent one.
    #[test]
    fn an_unhashable_member_records_an_unreadable_probe_and_no_pin() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().canonicalize().unwrap();
        fs::create_dir_all(home.join("jmods")).unwrap();
        fs::write(home.join("jmods/a.jmod"), b"a").unwrap();
        let mut dependency = resolved_jdk_dependency(JdkVersion::parse("21.0.8").unwrap(), None);
        dependency.artifacts = vec![ResolvedDependencyArtifact::source_set(
            DependencyArtifactRole::Binary,
            ExternalArtifactKind::JdkJmodSet,
            home.clone(),
            vec![
                PathBuf::from("jmods/a.jmod"),
                PathBuf::from("jmods/vanished.jmod"),
            ],
        )];
        let mut probes = Vec::new();
        assert!(
            pin_jdk_artifacts(
                &mut dependency,
                &test_digests(),
                &DependencyPackLimits::default(),
                None,
                &mut probes,
                &mut 0,
            )
            .is_continue()
        );
        assert!(dependency.artifacts[0].expected_sha256.is_none());
        assert_eq!(probes.len(), 1, "{probes:?}");
        assert_eq!(probes[0].path, home.join("jmods/vanished.jmod"));
        assert!(matches!(
            probes[0].outcome,
            ExternalProbeOutcome::Unreadable
        ));
    }

    /// Capture requires a pinned path to be its own canonical path, so a
    /// symlinked source archive (Debian installs one) stays on its metadata
    /// identity, unpinned, and the JDK answer stays uncertified.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_source_archive_stays_unpinned() {
        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let home = root_path.join("jdk-21");
        fs::create_dir_all(home.join("lib")).unwrap();
        fs::write(home.join("release"), "JAVA_VERSION=\"21.0.8\"\n").unwrap();
        fs::write(root_path.join("real-src.zip"), b"archive").unwrap();
        std::os::unix::fs::symlink(root_path.join("real-src.zip"), home.join("lib/src.zip"))
            .unwrap();
        let config = test_jdk_config(&home);
        let project = TestProject::new(&root_path, Language::Java);
        let selected =
            JvmExternalDeclarationIndex::select_jdk(&config, &project, &test_digests(), None)
                .unwrap();
        assert!(selected.inputs.complete);
        let artifact = &selected.dependencies[0].artifacts[0];
        assert_eq!(artifact.kind, ExternalArtifactKind::JdkSourceZip);
        assert_eq!(artifact.path(), home.join("lib/src.zip").as_path());
        assert!(artifact.expected_sha256.is_none());
        assert!(!selected.every_artifact_pinned());
    }

    /// A JDK with JMODs and a symlinked `src.zip` (Debian) must not be half
    /// pinned: the catalog expectation wants the pinned key only for a fully
    /// pinned dependency, so pinning the JMOD set alone would expect a missing
    /// production and make the reader refuse every active shard. The whole
    /// dependency keeps its metadata identity and the answer stays uncertified.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_source_archive_leaves_the_whole_jdk_unpinned() {
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::ExpectedCatalogEntry;

        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let home = root_path.join("jdk-21");
        fs::create_dir_all(home.join("lib")).unwrap();
        fs::create_dir_all(home.join("jmods")).unwrap();
        fs::write(home.join("release"), "JAVA_VERSION=\"21.0.8\"\n").unwrap();
        fs::write(home.join("jmods/java.base.jmod"), b"jmod bytes").unwrap();
        fs::write(root_path.join("real-src.zip"), b"archive").unwrap();
        std::os::unix::fs::symlink(root_path.join("real-src.zip"), home.join("lib/src.zip"))
            .unwrap();
        let config = test_jdk_config(&home);
        let project = TestProject::new(&root_path, Language::Java);
        let selected =
            JvmExternalDeclarationIndex::select_jdk(&config, &project, &test_digests(), None)
                .unwrap();
        assert!(selected.inputs.complete);
        let artifacts = &selected.dependencies[0].artifacts;
        assert_eq!(artifacts.len(), 2, "{artifacts:?}");
        assert!(
            artifacts
                .iter()
                .all(|artifact| artifact.expected_sha256.is_none()
                    && artifact.source_identity.is_some()),
            "{artifacts:?}"
        );
        assert!(!selected.every_artifact_pinned());
        let expectations = selected.catalog_expectations();
        assert!(
            matches!(
                expectations.as_slice(),
                [ExpectedCatalogEntry::Dependency { fallback, .. }]
                    if matches!(fallback.as_ref(), ExpectedCatalogEntry::SourceIdentity { source_identity: Some(_), .. })
            ),
            "{expectations:?}"
        );
    }

    /// An artifact over a producer limit is not pinned, and nothing is hashed
    /// for it or for the other artifacts of its dependency.
    #[test]
    fn an_artifact_over_the_producer_limit_is_not_hashed() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().canonicalize().unwrap();
        fs::create_dir_all(home.join("jmods")).unwrap();
        fs::write(home.join("jmods/a.jmod"), b"a").unwrap();
        fs::write(home.join("src.zip"), b"eight by").unwrap();
        let mut dependency = resolved_jdk_dependency(JdkVersion::parse("21.0.8").unwrap(), None);
        dependency.artifacts = vec![
            ResolvedDependencyArtifact::source_set(
                DependencyArtifactRole::Binary,
                ExternalArtifactKind::JdkJmodSet,
                home.clone(),
                vec![PathBuf::from("jmods/a.jmod")],
            ),
            ResolvedDependencyArtifact::file(
                DependencyArtifactRole::Sources,
                ExternalArtifactKind::JdkSourceZip,
                home.join("src.zip"),
            ),
        ];
        let mut limits = DependencyPackLimits::default();
        limits.producer.max_artifact_bytes = 4;
        let before = JDK_DIGEST_COMPUTATIONS.get();
        let mut probes = Vec::new();
        assert!(
            pin_jdk_artifacts(
                &mut dependency,
                &test_digests(),
                &limits,
                None,
                &mut probes,
                &mut 0
            )
            .is_continue()
        );
        assert_eq!(JDK_DIGEST_COMPUTATIONS.get() - before, 0);
        assert!(probes.is_empty(), "{probes:?}");
        assert!(
            dependency
                .artifacts
                .iter()
                .all(|artifact| artifact.expected_sha256.is_none())
        );

        // Within the limits, the same dependency pins every artifact.
        assert!(
            pin_jdk_artifacts(
                &mut dependency,
                &test_digests(),
                &DependencyPackLimits::default(),
                None,
                &mut probes,
                &mut 0,
            )
            .is_continue()
        );
        assert!(
            dependency
                .artifacts
                .iter()
                .all(|artifact| artifact.expected_sha256.is_some())
        );
    }

    /// Pinning observes the discovery's cancellation: a token cancelled before
    /// pinning breaks it and sets no pin, even when the digest cache could
    /// serve every artifact without a read.
    #[test]
    fn a_cancelled_token_stops_pinning() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().canonicalize().unwrap();
        fs::create_dir_all(home.join("jmods")).unwrap();
        fs::write(home.join("jmods/a.jmod"), b"a").unwrap();
        let mut dependency = resolved_jdk_dependency(JdkVersion::parse("21.0.8").unwrap(), None);
        dependency.artifacts = vec![ResolvedDependencyArtifact::source_set(
            DependencyArtifactRole::Binary,
            ExternalArtifactKind::JdkJmodSet,
            home.clone(),
            vec![PathBuf::from("jmods/a.jmod")],
        )];
        let token = CancellationToken::new();
        token.cancel();
        let mut probes = Vec::new();
        assert!(
            pin_jdk_artifacts(
                &mut dependency,
                &test_digests(),
                &DependencyPackLimits::default(),
                Some(&token),
                &mut probes,
                &mut 0,
            )
            .is_break()
        );
        assert!(dependency.artifacts[0].expected_sha256.is_none());
        assert!(probes.is_empty(), "{probes:?}");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon("#9559: JDK pinning reset its byte budget per dependency")]
    fn jdk_pinning_budget_spans_dependencies() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().canonicalize().unwrap();
        let mut dependencies = Vec::new();
        for name in ["first.zip", "second.zip", "small.zip"] {
            fs::write(
                home.join(name),
                if name == "small.zip" {
                    &b"x"[..]
                } else {
                    &b"four"[..]
                },
            )
            .unwrap();
            let mut dependency =
                resolved_jdk_dependency(JdkVersion::parse("21.0.8").unwrap(), None);
            dependency.artifacts = vec![ResolvedDependencyArtifact::file(
                DependencyArtifactRole::Sources,
                ExternalArtifactKind::JdkSourceZip,
                home.join(name),
            )];
            dependencies.push(dependency);
        }
        let limits = DependencyPackLimits {
            max_total_artifact_bytes: 5,
            ..Default::default()
        };
        let digests = test_digests();
        let mut total = 0;
        let mut probes = Vec::new();
        for (index, dependency) in dependencies.iter_mut().enumerate() {
            let before = JDK_DIGEST_COMPUTATIONS.get();
            assert!(
                pin_jdk_artifacts(dependency, &digests, &limits, None, &mut probes, &mut total)
                    .is_continue()
            );
            assert_eq!(
                dependency.artifacts[0].expected_sha256.is_some(),
                index != 1
            );
            assert_eq!(
                JDK_DIGEST_COMPUTATIONS.get() - before,
                usize::from(index != 1)
            );
        }
        assert_eq!(total, 5);
    }

    fn test_jdk_config(home: &Path) -> JvmAnalyzerConfig {
        let mut config = brokk_bifrost_analysis::test_support::hermetic_jvm_config();
        config.jvm.standard_library_discovery.jdk_homes = vec![home.to_path_buf()];
        config.jvm
    }

    /// An installed JDK fixture with one class-bearing `java.base` module and
    /// one empty module for every name in `additional`.
    fn write_test_jdk_jmods(home: &Path, additional: &[&str]) {
        use crate::analyzer::jvm::jmod_artifact::test_module_info_class_bytes;

        fs::create_dir_all(home.join("jmods")).unwrap();
        fs::write(home.join("release"), "JAVA_VERSION=\"21.0.8\"\n").unwrap();
        let class = test_class_file_bytes(&TestClassFile {
            internal_name: "java/lang/Object",
            super_internal_name: "java/lang/Object",
            methods: &[],
            private_nested: false,
        });
        write_zip_entries(
            &home.join("jmods/java.base.jmod"),
            &[
                (
                    "classes/module-info.class",
                    &test_module_info_class_bytes(&["java/lang"], &[]),
                ),
                ("classes/java/lang/Object.class", &class),
            ],
        );
        for name in additional {
            let module = name.strip_suffix(".jmod").unwrap();
            let package = module.replace('.', "/");
            write_zip_entries(
                &home.join("jmods").join(name),
                &[(
                    "classes/module-info.class",
                    &test_module_info_class_bytes(&[package.as_str()], &[]),
                )],
            );
        }
    }

    #[test]
    fn automatic_java_home_with_only_jmods_produces_exact_binary_evidence() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("portable-jdk-home");
        fs::create_dir_all(home.join("jmods")).unwrap();
        fs::write(home.join("release"), "JAVA_VERSION=\"21.0.8\"\n").unwrap();
        fs::write(home.join("jmods/java.base.jmod"), b"exact binary input").unwrap();
        let config = JvmAnalyzerConfig::default();

        let discovered = discover_and_pin_jdk(
            &config,
            root.path(),
            Some(home.as_os_str().to_owned()),
            &test_digests(),
        );

        assert!(discovered.diagnostics.is_empty());
        assert_eq!(discovered.dependencies.len(), 1);
        assert_eq!(discovered.dependencies[0].artifacts.len(), 1);
        assert_eq!(
            discovered.dependencies[0].artifacts[0].kind,
            ExternalArtifactKind::JdkJmodSet
        );
        assert_eq!(
            discovered.dependencies[0].artifacts[0].path(),
            fs::canonicalize(&home).unwrap()
        );
        assert_eq!(
            discovered.dependencies[0]
                .evidence
                .toolchain
                .as_ref()
                .and_then(|coordinate| coordinate.version.as_ref()),
            Some(&Version::parse("21.0.8").unwrap())
        );
    }

    #[test]
    fn automatic_java_home_prefers_bounded_jmod_evidence() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("portable-jdk-home");
        fs::create_dir_all(home.join("lib")).unwrap();
        fs::create_dir_all(home.join("jmods")).unwrap();
        fs::write(home.join("release"), "JAVA_VERSION=\"21.0.8\"\n").unwrap();
        fs::write(home.join("lib/src.zip"), b"candidate source names").unwrap();
        fs::write(home.join("jmods/java.base.jmod"), b"exact binary input").unwrap();

        let discovered = discover_and_pin_jdk(
            &JvmAnalyzerConfig::default(),
            root.path(),
            Some(home.as_os_str().to_owned()),
            &test_digests(),
        );

        assert!(discovered.diagnostics.is_empty());
        assert_eq!(discovered.dependencies.len(), 1);
        assert_eq!(discovered.dependencies[0].artifacts.len(), 1);
        assert_eq!(
            discovered.dependencies[0].artifacts[0].kind,
            ExternalArtifactKind::JdkJmodSet
        );
    }

    #[test]
    #[hardwon(
        "#2874: Checks an invalid environment-selected JDK is a warning with no guessed dependency"
    )]
    fn invalid_environment_jdk_home_is_a_warning_without_guessed_version() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("not-a-jdk");

        let discovered = discover_and_pin_jdk(
            &JvmAnalyzerConfig::default(),
            root.path(),
            Some(missing.as_os_str().to_owned()),
            &test_digests(),
        );

        assert!(discovered.dependencies.is_empty());
        assert_eq!(discovered.diagnostics.len(), 1);
        assert_eq!(
            discovered.diagnostics[0].severity,
            DependencyPackDiagnosticSeverity::Warning
        );
        assert_eq!(discovered.diagnostics[0].code, "jdk.home.invalid");
    }

    /// Writes the smallest JDK home automatic discovery accepts: a `release`
    /// file that declares one `JAVA_VERSION`.
    fn write_jdk_release(root: &Path, java_version: &str) -> PathBuf {
        brokk_bifrost_analysis::test_support::write_jdk_release(&root.join("jdk"), java_version)
    }

    #[test]
    #[hardwon("#2874: Checks four-component JDK version remains exact in identity and provenance")]
    fn four_part_temurin_version_keeps_its_exact_spelling() {
        let root = tempfile::tempdir().unwrap();
        let home = write_jdk_release(root.path(), "21.0.12.1");

        let discovered = discover_and_pin_jdk(
            &JvmAnalyzerConfig::default(),
            root.path(),
            Some(home.as_os_str().to_owned()),
            &test_digests(),
        );

        assert!(
            discovered.diagnostics.is_empty(),
            "{:#?}",
            discovered.diagnostics
        );
        assert_eq!(discovered.dependencies.len(), 1);
        let dependency = &discovered.dependencies[0];
        // The fourth component names a distinct source archive, so it must
        // stay in the dependency identity and the provenance (#2874).
        assert_eq!(dependency.id, "jdk:21.0.12.1");
        assert_eq!(
            dependency
                .evidence
                .toolchain
                .as_ref()
                .and_then(|coordinate| coordinate.version.as_ref()),
            Some(&Version::parse("21.0.12").unwrap())
        );
        assert_eq!(
            dependency.provenance,
            vec![DependencyProvenance {
                key: "version".to_owned(),
                value: "21.0.12.1".to_owned(),
            }]
        );
    }

    #[test]
    #[hardwon("#13459: a JDK release file with a vendor fifth version element was rejected")]
    fn vendor_fifth_version_element_is_accepted_and_keeps_raw_identity() {
        let root = tempfile::tempdir().unwrap();
        let home = write_jdk_release(root.path(), "25.0.5.0.3");

        let discovered = discover_jdk_semantic_pack_dependencies(
            &JvmAnalyzerConfig::default(),
            root.path(),
            Some(home.as_os_str().to_owned()),
            None,
        );

        assert!(
            discovered.diagnostics.is_empty(),
            "{:#?}",
            discovered.diagnostics
        );
        assert_eq!(discovered.dependencies.len(), 1);
        let dependency = &discovered.dependencies[0];
        assert_eq!(dependency.id, "jdk:25.0.5.0.3");
        assert_eq!(
            dependency
                .evidence
                .toolchain
                .as_ref()
                .and_then(|coordinate| coordinate.version.as_ref()),
            Some(&Version::parse("25.0.5").unwrap())
        );
        assert_eq!(dependency.provenance[0].value, "25.0.5.0.3");
    }

    #[test]
    #[hardwon(
        "#2874: Checks an explicitly configured JDK home accepts a four-part release version"
    )]
    fn configured_jdk_home_accepts_a_four_part_version() {
        use brokk_bifrost_core::analyzer::config::JvmStandardLibraryDiscoveryConfig;

        let root = tempfile::tempdir().unwrap();
        let home = write_jdk_release(root.path(), "21.0.12.1");
        let config = JvmAnalyzerConfig {
            standard_library_discovery: JvmStandardLibraryDiscoveryConfig {
                jdk_homes: vec![home],
                discover_java_home: false,
                ..Default::default()
            },
            ..JvmAnalyzerConfig::default()
        };

        let discovered = discover_and_pin_jdk(&config, root.path(), None, &test_digests());

        assert!(
            discovered.diagnostics.is_empty(),
            "{:#?}",
            discovered.diagnostics
        );
        assert_eq!(discovered.dependencies.len(), 1);
        assert_eq!(discovered.dependencies[0].id, "jdk:21.0.12.1");
    }

    #[test]
    #[hardwon(
        "#2874: Checks feature-only version maps to a complete semantic-version coordinate without guessing a different feature"
    )]
    fn feature_only_jdk_version_fills_the_missing_semver_components() {
        let root = tempfile::tempdir().unwrap();
        let home = write_jdk_release(root.path(), "21");

        let discovered = discover_and_pin_jdk(
            &JvmAnalyzerConfig::default(),
            root.path(),
            Some(home.as_os_str().to_owned()),
            &test_digests(),
        );

        assert!(
            discovered.diagnostics.is_empty(),
            "{:#?}",
            discovered.diagnostics
        );
        assert_eq!(discovered.dependencies.len(), 1);
        assert_eq!(discovered.dependencies[0].id, "jdk:21");
        assert_eq!(
            discovered.dependencies[0]
                .evidence
                .toolchain
                .as_ref()
                .and_then(|coordinate| coordinate.version.as_ref()),
            Some(&Version::parse("21.0.0").unwrap())
        );
    }

    #[test]
    #[hardwon("#2874: Keeps legacy underscore version forms out of exact JDK evidence")]
    fn legacy_underscore_jdk_versions_stay_invalid() {
        for java_version in ["1.8.0_392", "21..12", "21.alpha", "18446744073709551616"] {
            let root = tempfile::tempdir().unwrap();
            let home = write_jdk_release(root.path(), java_version);

            let discovered = discover_and_pin_jdk(
                &JvmAnalyzerConfig::default(),
                root.path(),
                Some(home.as_os_str().to_owned()),
                &test_digests(),
            );

            assert!(
                discovered.dependencies.is_empty(),
                "{java_version}: {:#?}",
                discovered.dependencies
            );
            assert_eq!(discovered.diagnostics.len(), 1, "{java_version}");
            assert_eq!(
                discovered.diagnostics[0].code, "jdk.home.invalid",
                "{java_version}"
            );
        }
    }

    #[test]
    fn java_external_declaration_indexes_coordinate_and_prefers_source_jar() {
        let Some(fixture) = ExternalJarFixture::new(true) else {
            return;
        };
        let config = fixture.coordinate_config();
        let index = JvmExternalDeclarationIndex::build(&config, fixture.project_root());
        assert!(
            index.production_diagnostics().is_empty(),
            "{:?}",
            index.production_diagnostics()
        );

        let service = index.get("com.example.dep.ExternalService").unwrap();
        assert_eq!("com.example.dep", service.package_name());
        assert_eq!("ExternalService", service.short_name());
        assert_eq!(JvmExternalTypeKind::Class, service.kind());
        assert_eq!(JvmVisibility::Public, service.visibility());
        assert!(
            matches!(
                service.source(),
                JvmExternalDeclarationSource::SourceJar { source_path, .. }
                    if source_path == "com/example/dep/ExternalService.java"
            ),
            "{service:#?}"
        );

        assert!(
            index
                .get("com.example.dep.ExternalService.Nested")
                .is_some()
        );
        assert!(
            matches!(
                index
                    .get("com.example.dep.ExternalService.Nested")
                    .map(JvmExternalType::source),
                Some(JvmExternalDeclarationSource::SourceJar { .. })
            ),
            "nested source declarations should retain source-JAR provenance"
        );
        assert_eq!(
            Some(JvmVisibility::Protected),
            index
                .get("com.example.dep.ExternalService.ProtectedNested")
                .map(JvmExternalType::visibility)
        );
        assert!(
            index
                .get("com.example.dep.ExternalService.Hidden")
                .is_none(),
            "private nested classes should not be indexed as externally visible"
        );
        assert!(
            index
                .get("com.example.dep.ExternalService.Hidden.Leaks")
                .is_none(),
            "nested classes under a private parent should not be indexed as externally visible"
        );
        assert_eq!(
            Some(JvmVisibility::PackagePrivate),
            index
                .get("com.example.dep.PackageHelper")
                .map(JvmExternalType::visibility)
        );
        assert_eq!(
            Some(JvmVisibility::PackagePrivate),
            index
                .get("com.example.dep.PackageOuter.Nested")
                .map(JvmExternalType::visibility)
        );
        assert_eq!(
            Some(JvmVisibility::Public),
            index
                .get("com.example.dep.PublicApi.Callback")
                .map(JvmExternalType::visibility)
        );
        assert!(
            index
                .resolve_wildcard_import("com.example.dep", "ExternalService", "app")
                .is_some()
        );
    }

    #[test]
    #[hardwon("#4271: Annotation text containing public hid a protected source-JAR member type")]
    fn java_source_jar_visibility_ignores_annotation_values() {
        let Some(fixture) = ExternalJarFixture::new(true) else {
            return;
        };
        let index = JvmExternalDeclarationIndex::build(
            &fixture.coordinate_config(),
            fixture.project_root(),
        );
        let nested = index
            .get("com.example.dep.ExternalService.AnnotatedProtectedNested")
            .expect("annotated protected nested type is indexed");

        assert_eq!(JvmVisibility::Protected, nested.visibility());
        assert!(matches!(
            nested.source(),
            JvmExternalDeclarationSource::SourceJar { .. }
        ));
    }

    #[test]
    #[hardwon(
        "#8823: the source/binary pack merge dropped an inner class's enclosing type-parameter scope, so the JDK 21 pack was rejected"
    )]
    fn java_dependency_pack_retains_inner_constructor_scope() {
        use brokk_bifrost_semantic::analyzer::semantic_model::compiler::{
            CompilerOptions, compile_pack,
        };
        use brokk_bifrost_semantic::analyzer::semantic_model::producer::read_exact_artifact;

        // Like the other class-file fixture tests, this needs `javac` and `jar`
        // on PATH (CI installs a JDK); only their absence may skip it.
        let (javac, jar) = (PathBuf::from("javac"), PathBuf::from("jar"));
        if std::process::Command::new(&javac)
            .arg("-version")
            .output()
            .is_err()
        {
            eprintln!("skipping Java pack boundary test: javac is unavailable");
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let source = b"package fixture; public class Outer<E> { public class Mid { public class Child { public Child(Outer<E> parent, int i) {} } } public static class StaticChild { public StaticChild(Outer<?> parent) {} } }";
        let source_path = temp.path().join("Outer.java");
        fs::write(&source_path, source).unwrap();
        let classes = temp.path().join("classes");
        fs::create_dir(&classes).unwrap();
        brokk_bifrost_analysis::test_support::run_command_success(
            std::process::Command::new(&javac)
                .arg("-d")
                .arg(&classes)
                .arg(&source_path),
        );
        let source_jar = temp.path().join("fixture-sources.jar");
        write_zip_entry(&source_jar, "fixture/Outer.java", source);
        let class_jar = temp.path().join("fixture.jar");
        brokk_bifrost_analysis::test_support::run_command_success(
            std::process::Command::new(&jar)
                .current_dir(&classes)
                .arg("cf")
                .arg(&class_jar)
                .arg("."),
        );
        let dependency = resolved_semantic_pack_dependency(ResolvedJvmArtifact {
            artifact_path: class_jar.clone(),
            source_artifact_path: Some(source_jar.clone()),
            coordinate: Some(JvmMavenCoordinate::new("fixture", "inner", "1.0.0")),
            origin: JvmDependencyOrigin::ExplicitPath,
        });
        let limits = ArtifactProducerLimits::default();
        let produce = |path: &Path, kind| {
            let mut request = jvm_dependency_production_request(&dependency);
            request.path = path.to_path_buf();
            request.artifact_kind = kind;
            let artifact = read_exact_artifact(path, &limits).unwrap();
            let result =
                JavaJarPackProducer.produce_loaded_artifact(&request, &limits, None, &artifact);
            assert!(
                result
                    .diagnostics
                    .iter()
                    .all(|diagnostic| diagnostic.severity != ProducerDiagnosticSeverity::Error),
                "{:?}",
                result.diagnostics
            );
            result.pack.expect("Java fixture pack")
        };
        let source_pack = produce(&source_jar, ExternalArtifactKind::JavaSourceJar);
        let binary_pack = produce(&class_jar, ExternalArtifactKind::JavaClassJar);
        fn declarations(pack: &AuthoredSemanticModelPack) -> (&[TypeFact], &[MemberFact]) {
            pack.shards
                .iter()
                .find_map(|shard| match &shard.payload {
                    AuthoredPayload::DeclarationFacts { types, members, .. } => {
                        Some((types.as_slice(), members.as_slice()))
                    }
                    _ => None,
                })
                .expect("declaration shard")
        }
        let (binary_types, binary_members) = declarations(&binary_pack);
        let child = binary_types
            .iter()
            .find(|fact| fact.name == "fixture.Outer.Mid.Child")
            .expect("inner child");
        assert_eq!(
            child
                .jvm_inventory
                .as_ref()
                .unwrap()
                .enclosing_type_parameters,
            ["E"]
        );
        let constructor = binary_members
            .iter()
            .find(|fact| fact.owner == child.id && fact.member_kind == MemberKind::Constructor)
            .expect("binary inner constructor");
        let constructor_id = constructor.id.clone();
        assert!(
            constructor
                .signature
                .as_ref()
                .is_some_and(|signature| java_signature_scope_covered(
                    signature,
                    &["E".to_owned()]
                ))
        );

        let mut diagnostics = Vec::new();
        let mut suppressed = SuppressedDiagnostics::default();
        let merged = merge_java_dependency_packs(
            Some(source_pack.clone()),
            Some(binary_pack.clone()),
            &mut diagnostics,
            &mut suppressed,
            &limits,
        )
        .unwrap();
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        compile_pack(&merged, &CompilerOptions::default())
            .expect("merged non-static inner pack validates");
        let (merged_types, merged_members) = declarations(&merged);
        let merged_child = merged_types
            .iter()
            .find(|fact| fact.id == child.id)
            .unwrap();
        assert_eq!(
            merged_child
                .jvm_inventory
                .as_ref()
                .unwrap()
                .enclosing_type_parameters,
            ["E"]
        );
        let bound = merged_members
            .iter()
            .find(|fact| fact.id == constructor_id)
            .expect("constructor binds by binary member identity");
        assert!(
            bound.signature.is_some(),
            "the valid constructor signature survives"
        );

        // JLS 8.1.3: a static nested class has no enclosing E. Simulate a
        // malformed binary-only member and prove both validation and merge
        // refuse its generic claim.
        let mut invalid_binary = binary_pack;
        let (static_id, static_constructor_id) = {
            let (types, members) = declarations(&invalid_binary);
            let static_type = types
                .iter()
                .find(|fact| fact.name == "fixture.Outer.StaticChild")
                .unwrap();
            assert!(
                static_type
                    .jvm_inventory
                    .as_ref()
                    .unwrap()
                    .enclosing_type_parameters
                    .is_empty()
            );
            let static_constructor = members
                .iter()
                .find(|fact| {
                    fact.owner == static_type.id && fact.member_kind == MemberKind::Constructor
                })
                .unwrap();
            (static_type.id.clone(), static_constructor.id.clone())
        };
        let AuthoredPayload::DeclarationFacts { members, .. } =
            &mut invalid_binary.shards[0].payload
        else {
            unreachable!()
        };
        let bad = members
            .iter_mut()
            .find(|fact| fact.id == static_constructor_id)
            .unwrap();
        bad.id.push_str(".out-of-scope");
        bad.signature.as_mut().unwrap().parameters[0].r#type = TypeRef::TypeParameter {
            name: "E".to_owned(),
        };
        let invalid = compile_pack(&invalid_binary, &CompilerOptions::default())
            .expect_err("unmerged static signature must fail validation");
        assert!(
            invalid
                .iter()
                .any(|diagnostic| diagnostic.code == "type.unknown_parameter"),
            "{invalid:?}"
        );
        diagnostics.clear();
        let merged_static = merge_java_dependency_packs(
            Some(source_pack),
            Some(invalid_binary),
            &mut diagnostics,
            &mut suppressed,
            &limits,
        )
        .unwrap();
        assert!(
            !diagnostics.is_empty(),
            "out-of-scope signature must be reported"
        );
        let (_, members) = declarations(&merged_static);
        let erased = members
            .iter()
            .find(|fact| fact.owner == static_id && fact.id.ends_with(".out-of-scope"))
            .unwrap();
        assert!(erased.signature.is_none());
        assert!(!erased.callable_family_complete);
        compile_pack(&merged_static, &CompilerOptions::default())
            .expect("erased static signature validates");
    }

    #[test]
    fn java_dependency_pack_retains_coordinate_and_reuses_merged_artifacts() {
        use brokk_bifrost_analysis::analyzer::semantic_model::CatalogOptions;

        use brokk_bifrost_analysis::analyzer::semantic_model::DependencyArtifactRole;

        use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackLimits;

        use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackPreparationStatus;

        use brokk_bifrost_analysis::analyzer::semantic_model::ExactDependencyArtifact;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

        use brokk_bifrost_analysis::analyzer::semantic_model::dependency::prepare_dependency_semantic_packs;

        use brokk_bifrost_semantic::analyzer::semantic_model::producer::read_exact_artifact;

        let Some(fixture) = ExternalJarFixture::new(true) else {
            return;
        };
        let project = TestProject::new(fixture.project_root(), Language::Java);
        let config = JvmAnalyzerConfig {
            without_project_build: false,
            external_dependencies: fixture.coordinate_config(),
            dependency_discovery:
                brokk_bifrost_core::analyzer::config::JvmDependencyDiscoveryConfig {
                    mode: JvmDependencyDiscoveryMode::Disabled,
                    ..brokk_bifrost_core::analyzer::config::JvmDependencyDiscoveryConfig::default()
                },
            standard_library_discovery:
                brokk_bifrost_core::analyzer::config::JvmStandardLibraryDiscoveryConfig {
                    discover_java_home: false,
                    ..Default::default()
                },
        };
        let dependencies = resolve_jvm_semantic_pack_dependencies(
            &config,
            &project,
            &test_digests(),
            &Default::default(),
            &DependencyPackLimits::default(),
            None,
        );

        assert_eq!(dependencies.len(), 1);
        assert_eq!(dependencies[0].id, "com.example:external-lib:1.2.3");
        assert_eq!(
            dependencies[0]
                .evidence
                .package
                .as_ref()
                .map(|coordinate| coordinate.name.as_str()),
            Some("com.example:external-lib")
        );
        assert!(
            dependencies[0]
                .provenance
                .iter()
                .any(|entry| { entry.key == "origin" && entry.value == "maven_repository" })
        );
        assert_eq!(
            dependencies[0]
                .artifacts
                .iter()
                .map(|artifact| artifact.role)
                .collect::<Vec<_>>(),
            vec![
                DependencyArtifactRole::Binary,
                DependencyArtifactRole::Sources
            ]
        );

        let producer_limits = ArtifactProducerLimits::default();
        let exact_artifacts = [
            ExactDependencyArtifact::from_exact(
                DependencyArtifactRole::Binary,
                ExternalArtifactKind::JavaClassJar,
                None,
                read_exact_artifact(&fixture.binary_jar_path(), &producer_limits).unwrap(),
            ),
            ExactDependencyArtifact::from_exact(
                DependencyArtifactRole::Sources,
                ExternalArtifactKind::JavaSourceJar,
                None,
                read_exact_artifact(&fixture.source_jar_path(), &producer_limits).unwrap(),
            ),
        ];
        let merged = JvmDependencyPackAdapter.produce(
            &dependencies[0],
            &exact_artifacts,
            &producer_limits,
            None,
        );
        assert!(merged.diagnostics.is_empty(), "{:#?}", merged.diagnostics);
        let merged_pack = merged.pack.expect("source and binary packs merge");
        let AuthoredPayload::DeclarationFacts { types, members, .. } =
            &merged_pack.shards[0].payload
        else {
            panic!("Java dependency producer must emit declaration facts")
        };
        let owner = types
            .iter()
            .find(|fact| fact.name == "com.example.dep.ExternalService")
            .expect("merged service declaration");
        assert!(
            owner.jvm_inventory.is_some(),
            "binary scope and inventory must survive the source declaration merge"
        );
        let echo = members
            .iter()
            .find(|fact| fact.owner == owner.id && fact.name == "echo")
            .expect("merged echo declaration");
        assert_eq!(
            echo.signature
                .as_ref()
                .and_then(|signature| signature.parameters[0].name.as_deref()),
            Some("name"),
            "source formal names remain authoritative"
        );
        assert!(
            echo.callable_family_complete,
            "an equivalent exact binary table contributes scoped completeness"
        );

        let produce_java_pack = |path: &Path, kind: ExternalArtifactKind| {
            let mut request = jvm_dependency_production_request(&dependencies[0]);
            request.path = path.to_path_buf();
            request.artifact_kind = kind;
            let artifact = read_exact_artifact(path, &producer_limits).unwrap();
            JavaJarPackProducer
                .produce_loaded_artifact(&request, &producer_limits, None, &artifact)
                .pack
                .expect("standalone Java declaration pack")
        };
        let mut source_pack = produce_java_pack(
            &fixture.source_jar_path(),
            ExternalArtifactKind::JavaSourceJar,
        );
        let mut binary_pack = produce_java_pack(
            &fixture.binary_jar_path(),
            ExternalArtifactKind::JavaClassJar,
        );
        for pack in [&mut source_pack, &mut binary_pack] {
            let activation = pack.shards[0].activation.clone();
            pack.shards[0].id = "declarations.second".to_owned();
            pack.shards.insert(
                0,
                AuthoredShard {
                    id: "declarations.first".to_owned(),
                    activation,
                    payload: AuthoredPayload::DeclarationFacts {
                        assembly_identity: None,
                        type_forwards: Vec::new(),
                        types: Vec::new(),
                        members: Vec::new(),
                        relations: Vec::new(),
                    },
                    runtime_values: None,
                    runtime_contracts: None,
                    collection_flows: None,
                    deferred_yields: None,
                    conditional_type_refinements: None,
                    callable_values: None,
                },
            );
        }
        let mut multi_shard_diagnostics = Vec::new();
        let mut multi_shard_suppressed = SuppressedDiagnostics::default();
        let multi_shard = merge_java_dependency_packs(
            Some(source_pack),
            Some(binary_pack),
            &mut multi_shard_diagnostics,
            &mut multi_shard_suppressed,
            &producer_limits,
        )
        .expect("multi-shard Java packs merge");
        assert!(multi_shard_diagnostics.is_empty());
        assert_eq!(multi_shard_suppressed.total(), 0);
        let AuthoredPayload::DeclarationFacts { types, members, .. } =
            &multi_shard.shards[1].payload
        else {
            panic!("the corresponding declaration shard remains typed")
        };
        let owner = types
            .iter()
            .find(|fact| fact.name == "com.example.dep.ExternalService")
            .expect("multi-shard service declaration");
        assert!(
            members.iter().any(|fact| {
                fact.owner == owner.id && fact.name == "echo" && fact.callable_family_complete
            }),
            "binary proof must merge into the matching source shard"
        );

        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let first = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            &dependencies,
            &DependencyPackLimits::default(),
            None,
        );
        let second = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            &dependencies,
            &DependencyPackLimits::default(),
            None,
        );

        assert_eq!(first.packs.len(), 1, "{:#?}", first.diagnostics);
        assert_eq!(second.packs.len(), 1, "{:#?}", second.diagnostics);
        assert_eq!(
            first.packs[0].status,
            DependencyPackPreparationStatus::Generated
        );
        assert_eq!(
            second.packs[0].status,
            DependencyPackPreparationStatus::Reused
        );
        assert_eq!(first.packs[0].production, second.packs[0].production);
    }

    #[test]
    fn scala_library_dependency_uses_source_pack_and_exact_toolchain_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let (dependency, prepared) = prepare_source_dependency_pack(
            &temp,
            "scala-library-2.13.16-sources.jar",
            "scala/example/LibraryApi.scala",
            b"package scala.example\ntrait LibraryApi { def value: String }\n",
            "scala-library-2.13.16.jar",
            JvmMavenCoordinate::new("org.scala-lang", "scala-library", "2.13.16"),
        );

        assert_eq!(dependency.evidence.language, "scala");
        assert_eq!(
            dependency.evidence.toolchain,
            Some(CatalogCoordinate {
                name: "scala".to_owned(),
                version: Some(Version::parse("2.13.16").unwrap()),
            })
        );
        assert_eq!(dependency.artifacts.len(), 1);
        assert_eq!(
            dependency.artifacts[0].kind,
            ExternalArtifactKind::ScalaSourceJar
        );

        assert_generated_source_pack(&prepared, "scala");
    }

    #[test]
    #[hardwon(
        "#2756: A refused dependency with no compatible pack must receive specific and generic accounting diagnostics"
    )]
    fn scala_library_without_sources_waits_for_compatible_prebuilt_pack() {
        use brokk_bifrost_analysis::analyzer::semantic_model::CatalogOptions;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

        use brokk_bifrost_analysis::analyzer::semantic_model::dependency::prepare_dependency_semantic_packs;

        let dependency = resolved_semantic_pack_dependency(ResolvedJvmArtifact {
            artifact_path: PathBuf::from("scala-library-2.13.16.jar"),
            source_artifact_path: None,
            coordinate: Some(JvmMavenCoordinate::new(
                "org.scala-lang",
                "scala-library",
                "2.13.16",
            )),
            origin: JvmDependencyOrigin::GradleCache,
        });
        assert_eq!(dependency.evidence.ecosystem, "maven");
        assert!(!JvmDependencyPackAdapter.can_produce(&dependency));
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();

        let prepared = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            &[dependency],
            &DependencyPackLimits::default(),
            None,
        );

        assert!(!prepared.complete);
        assert_eq!(prepared.profile.artifacts_read, 0);
        // The dependency is unaccounted (no pack, no installed pack), so
        // preparation names both the specific reason and the generic
        // catch-all (#2756).
        assert_eq!(prepared.diagnostics.len(), 2, "{:#?}", prepared.diagnostics);
        assert!(
            prepared
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "dependency.pack_unavailable")
        );
        assert!(
            prepared
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "preparation.unaccounted-dependency")
        );
    }

    #[test]
    fn kotlin_library_dependency_uses_source_pack_and_exact_toolchain_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let (dependency, prepared) = prepare_source_dependency_pack(
            &temp,
            "kotlin-stdlib-2.2.0-sources.jar",
            "kotlin/example/LibraryApi.kt",
            b"package kotlin.example\ninterface LibraryApi {\n    fun value(): String\n}\n",
            "kotlin-stdlib-2.2.0.jar",
            JvmMavenCoordinate::new("org.jetbrains.kotlin", "kotlin-stdlib", "2.2.0"),
        );

        assert_eq!(dependency.evidence.language, "kotlin");
        assert_eq!(
            dependency.evidence.toolchain,
            Some(CatalogCoordinate {
                name: "kotlin".to_owned(),
                version: Some(Version::parse("2.2.0").unwrap()),
            })
        );
        assert_eq!(dependency.artifacts.len(), 1);
        assert_eq!(
            dependency.artifacts[0].kind,
            ExternalArtifactKind::KotlinSourceJar
        );

        assert_generated_source_pack(&prepared, "kotlin");
    }

    #[test]
    #[hardwon(
        "#2756: A refused dependency with no compatible pack must receive specific and generic accounting diagnostics"
    )]
    fn kotlin_library_without_sources_waits_for_compatible_prebuilt_pack() {
        use brokk_bifrost_analysis::analyzer::semantic_model::CatalogOptions;

        use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackLimits;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

        use brokk_bifrost_analysis::analyzer::semantic_model::dependency::prepare_dependency_semantic_packs;

        let dependency = resolved_semantic_pack_dependency(ResolvedJvmArtifact {
            artifact_path: PathBuf::from("kotlin-stdlib-2.2.0.jar"),
            source_artifact_path: None,
            coordinate: Some(JvmMavenCoordinate::new(
                "org.jetbrains.kotlin",
                "kotlin-stdlib",
                "2.2.0",
            )),
            origin: JvmDependencyOrigin::GradleCache,
        });
        assert_eq!(dependency.evidence.language, "kotlin");
        assert_eq!(dependency.evidence.ecosystem, "maven");
        assert!(!JvmDependencyPackAdapter.can_produce(&dependency));
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();

        let prepared = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            &[dependency],
            &DependencyPackLimits::default(),
            None,
        );

        assert!(!prepared.complete);
        assert_eq!(prepared.profile.artifacts_read, 0);
        // The dependency is unaccounted (no pack, no installed pack), so
        // preparation names both the specific reason and the generic
        // catch-all (#2756).
        assert_eq!(prepared.diagnostics.len(), 2, "{:#?}", prepared.diagnostics);
        assert!(
            prepared
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "dependency.pack_unavailable")
        );
        assert!(
            prepared
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "preparation.unaccounted-dependency")
        );
    }

    #[test]
    fn renamed_identical_jars_reuse_one_path_independent_manifest() {
        use brokk_bifrost_analysis::analyzer::semantic_model::CatalogOptions;

        use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackLimits;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

        use brokk_bifrost_analysis::analyzer::semantic_model::assert_path_independent_pack_reuse;

        use brokk_bifrost_analysis::analyzer::semantic_model::dependency::prepare_dependency_semantic_packs;

        let Some(fixture) = ExternalJarFixture::new(true) else {
            return;
        };
        let copies = tempfile::tempdir().unwrap();
        let first_binary = copies.path().join("first.jar");
        let second_binary = copies.path().join("renamed.jar");
        fs::copy(fixture.binary_jar_path(), &first_binary).unwrap();
        fs::copy(fixture.binary_jar_path(), &second_binary).unwrap();
        let project = TestProject::new(copies.path(), Language::Java);
        let config = |binary| JvmAnalyzerConfig {
            without_project_build: false,
            external_dependencies: JvmExternalDependencies {
                artifact_paths: vec![JvmExternalArtifact {
                    artifact_path: binary,
                    source_artifact_path: None,
                    ..JvmExternalArtifact::default()
                }],
                ..JvmExternalDependencies::default()
            },
            dependency_discovery:
                brokk_bifrost_core::analyzer::config::JvmDependencyDiscoveryConfig {
                    mode: JvmDependencyDiscoveryMode::Disabled,
                    ..Default::default()
                },
            standard_library_discovery:
                brokk_bifrost_core::analyzer::config::JvmStandardLibraryDiscoveryConfig {
                    discover_java_home: false,
                    ..Default::default()
                },
        };
        let limits = DependencyPackLimits::default();
        let first_dependencies = resolve_jvm_semantic_pack_dependencies(
            &config(first_binary),
            &project,
            &test_digests(),
            &Default::default(),
            &limits,
            None,
        );
        let second_dependencies = resolve_jvm_semantic_pack_dependencies(
            &config(second_binary),
            &project,
            &test_digests(),
            &Default::default(),
            &limits,
            None,
        );
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let first = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            &first_dependencies,
            &limits,
            None,
        );
        let second = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            &second_dependencies,
            &limits,
            None,
        );

        assert_path_independent_pack_reuse(&first, &second);
    }

    #[test]
    fn java_external_declaration_uses_classfile_when_source_jar_is_missing() {
        let Some(fixture) = ExternalJarFixture::new(false) else {
            return;
        };
        let config = fixture.coordinate_config();
        let index = JvmExternalDeclarationIndex::build(&config, fixture.project_root());

        let service = index.get("com.example.dep.ExternalService").unwrap();
        assert!(
            matches!(
                service.source(),
                JvmExternalDeclarationSource::ClassFile { class_entry, .. }
                    if class_entry == "com/example/dep/ExternalService.class"
            ),
            "{service:#?}"
        );
        assert_eq!(
            Some(JvmVisibility::Protected),
            index
                .get("com.example.dep.ExternalService.ProtectedNested")
                .map(JvmExternalType::visibility)
        );
        assert_eq!(
            Some(JvmVisibility::PackagePrivate),
            index
                .get("com.example.dep.PackageHelper")
                .map(JvmExternalType::visibility)
        );
        let package_nested = index
            .get("com.example.dep.ExternalService.PackageNested")
            .unwrap();
        assert_eq!("com.example.dep", package_nested.package_name());
        assert_eq!("ExternalService.PackageNested", package_nested.short_name());
        assert_eq!(JvmVisibility::PackagePrivate, package_nested.visibility());
        assert_eq!(
            Some(JvmVisibility::PackagePrivate),
            index
                .get("com.example.dep.PackageOuter.Nested")
                .map(JvmExternalType::visibility)
        );
        assert!(
            index
                .get("com.example.dep.ExternalService.Hidden")
                .is_none(),
            "classfile fallback should respect InnerClasses private visibility"
        );
    }

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn java_external_declaration_indexes_explicit_source_artifact_path() {
        let Some(fixture) = ExternalJarFixture::new(true) else {
            return;
        };
        let config = JvmExternalDependencies {
            artifact_paths: vec![JvmExternalArtifact {
                artifact_path: fixture.source_jar_path(),
                source_artifact_path: None,
                ..JvmExternalArtifact::default()
            }],
            ..JvmExternalDependencies::default()
        };
        let index = JvmExternalDeclarationIndex::build(&config, fixture.project_root());

        let service = index.get("com.example.dep.ExternalService").unwrap();
        assert!(
            matches!(
                service.source(),
                JvmExternalDeclarationSource::SourceJar { source_path, .. }
                    if source_path == "com/example/dep/ExternalService.java"
            ),
            "{service:#?}"
        );
    }

    #[test]
    fn jvm_external_declaration_indexes_scala_source_jar() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let source_jar = root.join("scala-library-sources.jar");
        write_zip_entry(
            &source_jar,
            "scala/example/Dependency.scala",
            b"package scala.example\nclass Dependency\ntrait Contract\nobject Defaults\nprivate class Hidden\n",
        );

        let index = JvmExternalDeclarationIndex::build(
            &JvmExternalDependencies {
                artifact_paths: vec![JvmExternalArtifact {
                    artifact_path: source_jar,
                    source_artifact_path: None,
                    ..JvmExternalArtifact::default()
                }],
                ..JvmExternalDependencies::default()
            },
            &root,
        );

        for name in [
            "scala.example.Dependency",
            "scala.example.Contract",
            "scala.example.Defaults",
        ] {
            assert!(matches!(
                index.get(name).map(JvmExternalType::source),
                Some(JvmExternalDeclarationSource::SourceJar { source_path, .. })
                    if source_path == "scala/example/Dependency.scala"
            ));
        }
        assert!(index.get("scala.example.Hidden").is_none());
    }

    #[test]
    #[hardwon(
        "de7bf58da4ba: source-jar owners lost their declared supertypes, hiding inherited members"
    )]
    fn source_jar_owner_keeps_declared_supertypes_for_member_lookup() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let source_jar = root.join("dependency-sources.jar");
        write_zip_entries(
            &source_jar,
            &[
                (
                    "com/example/dep/Base.java",
                    b"package com.example.dep; public class Base { public void run() {} }",
                ),
                (
                    "com/example/dep/Sub.java",
                    b"package com.example.dep; public class Sub extends Base {}",
                ),
            ],
        );
        let index = JvmExternalDeclarationIndex::build(
            &JvmExternalDependencies {
                artifact_paths: vec![JvmExternalArtifact {
                    artifact_path: source_jar,
                    source_artifact_path: None,
                    ..JvmExternalArtifact::default()
                }],
                ..JvmExternalDependencies::default()
            },
            &root,
        );
        assert!(matches!(
            index
                .get("com.example.dep.Sub")
                .map(JvmExternalType::source),
            Some(JvmExternalDeclarationSource::SourceJar { .. })
        ));
        // A source jar has no complete inventory, so its hierarchy stays
        // incomplete, but member lookup still follows the declared edge.
        assert!(
            index.member("com.example.dep.Sub", "run").0.is_some(),
            "{:?}",
            index
                .members_by_owner
                .get("com.example.dep.Sub")
                .map(|surface| &surface.supertypes)
        );
    }

    const KOTLIN_DEPENDENCY_SOURCE: &str = "package kotlin.example\n\
         \n\
         class Dependency {\n\
             class Nested\n\
             private class Hidden\n\
             companion object Factory\n\
         }\n\
         \n\
         interface Contract\n\
         \n\
         object Defaults\n\
         \n\
         enum class Mode { FAST, SLOW }\n\
         \n\
         annotation class Marked\n\
         \n\
         internal class ModulePrivate\n\
         \n\
         private class FilePrivate\n\
         \n\
         fun topLevelHelper(): Int = 1\n";

    fn kotlin_source_jar_index(root: &Path) -> JvmExternalDeclarationIndex {
        let source_jar = root.join("kotlin-library-sources.jar");
        write_zip_entry(
            &source_jar,
            "kotlin/example/Dependency.kt",
            KOTLIN_DEPENDENCY_SOURCE.as_bytes(),
        );
        JvmExternalDeclarationIndex::build(
            &JvmExternalDependencies {
                artifact_paths: vec![JvmExternalArtifact {
                    artifact_path: source_jar,
                    source_artifact_path: None,
                    ..JvmExternalArtifact::default()
                }],
                ..JvmExternalDependencies::default()
            },
            root,
        )
    }

    #[test]
    fn jvm_external_declaration_indexes_kotlin_source_jar() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let index = kotlin_source_jar_index(&root);

        for name in [
            "kotlin.example.Dependency",
            "kotlin.example.Dependency.Nested",
            "kotlin.example.Dependency.Factory",
            "kotlin.example.Contract",
            "kotlin.example.Defaults",
            "kotlin.example.Mode",
            "kotlin.example.Marked",
        ] {
            assert!(
                matches!(
                    index.get(name).map(JvmExternalType::source),
                    Some(JvmExternalDeclarationSource::SourceJar { source_path, .. })
                        if source_path == "kotlin/example/Dependency.kt"
                ),
                "expected {name} to be indexed from the Kotlin source jar"
            );
        }

        assert_eq!(
            Some(JvmExternalTypeKind::Interface),
            index
                .get("kotlin.example.Contract")
                .map(JvmExternalType::kind)
        );
        assert_eq!(
            Some(JvmExternalTypeKind::Enum),
            index.get("kotlin.example.Mode").map(JvmExternalType::kind)
        );
        assert_eq!(
            Some(JvmExternalTypeKind::Annotation),
            index
                .get("kotlin.example.Marked")
                .map(JvmExternalType::kind)
        );
    }

    #[test]
    fn java_external_declaration_ignores_missing_and_malformed_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let malformed = root.join("bad.jar");
        fs::write(&malformed, b"not a zip").unwrap();

        let config = JvmExternalDependencies {
            artifact_paths: vec![
                JvmExternalArtifact {
                    artifact_path: malformed,
                    source_artifact_path: None,
                    ..JvmExternalArtifact::default()
                },
                JvmExternalArtifact {
                    artifact_path: root.join("missing.jar"),
                    source_artifact_path: None,
                    ..JvmExternalArtifact::default()
                },
            ],
            ..JvmExternalDependencies::default()
        };

        let index = JvmExternalDeclarationIndex::build(&config, &root);
        assert!(index.is_empty());
    }

    #[test]
    fn java_external_declaration_rejects_unsafe_coordinates() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let unsafe_coordinates = [
            JvmMavenCoordinate::new("..", "external-lib", "1.2.3"),
            JvmMavenCoordinate::new("com.example", "../external-lib", "1.2.3"),
            JvmMavenCoordinate::new("com.example", "external-lib", "../1.2.3"),
            JvmMavenCoordinate::new("com..example", "external-lib", "1.2.3"),
        ];

        for coordinate in unsafe_coordinates {
            assert!(
                resolve_coordinate(&root, &coordinate).is_none(),
                "unsafe coordinate should not resolve: {coordinate:?}"
            );
        }
    }

    #[test]
    fn java_external_declaration_skips_oversized_source_entries() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let oversized_source_jar = root.join("oversized-sources.jar");
        write_zip_entry(
            &oversized_source_jar,
            "com/example/dep/Oversized.java",
            &vec![b' '; MAX_SOURCE_ENTRY_BYTES as usize + 1],
        );
        let config = JvmExternalDependencies {
            artifact_paths: vec![JvmExternalArtifact {
                artifact_path: oversized_source_jar,
                source_artifact_path: None,
                ..JvmExternalArtifact::default()
            }],
            ..JvmExternalDependencies::default()
        };

        let index = JvmExternalDeclarationIndex::build(&config, &root);
        assert!(index.is_empty());
    }

    #[test]
    fn java_external_declaration_skips_oversized_artifacts_before_zip_parse() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let oversized_jar = root.join("oversized.jar");
        File::create(&oversized_jar)
            .unwrap()
            .set_len(MAX_ARTIFACT_BYTES + 1)
            .unwrap();
        let config = JvmExternalDependencies {
            artifact_paths: vec![JvmExternalArtifact {
                artifact_path: oversized_jar,
                source_artifact_path: None,
                ..JvmExternalArtifact::default()
            }],
            ..JvmExternalDependencies::default()
        };

        let index = JvmExternalDeclarationIndex::build(&config, &root);
        assert!(index.is_empty());
    }

    /// Two workspaces over one unchanged dependency universe share one built
    /// index through the process-wide memo; changing a resolved artifact's
    /// bytes changes the evidence and rebuilds.
    #[test]
    fn build_for_project_memoizes_on_dependency_discovery_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let repo_dir = root.join("m2").join(GROUP_PATH);
        fs::create_dir_all(&repo_dir).unwrap();
        for workspace in ["workspace-a", "workspace-b"] {
            fs::create_dir_all(root.join(workspace)).unwrap();
        }
        probe_class_jar(&repo_dir.join(BINARY_JAR));
        age_past_racy_window();
        let config = JvmAnalyzerConfig {
            external_dependencies: JvmExternalDependencies {
                coordinates: vec![JvmMavenCoordinate::new(
                    "com.example",
                    "external-lib",
                    "1.2.3",
                )],
                repository_roots: vec![root.join("m2")],
                ..JvmExternalDependencies::default()
            },
            ..JvmAnalyzerConfig::default()
        };
        let first = JvmExternalDeclarationIndex::build_for_project(
            &config,
            &TestProject::new(root.join("workspace-a"), Language::Java),
        );
        let second = JvmExternalDeclarationIndex::build_for_project(
            &config,
            &TestProject::new(root.join("workspace-b"), Language::Java),
        );
        assert!(
            Arc::ptr_eq(&first, &second),
            "identical dependency-discovery evidence must share one built index"
        );

        write_test_class_jar(
            &repo_dir.join(BINARY_JAR),
            &[TestClassFile {
                internal_name: "com/example/probe/Replaced",
                super_internal_name: "java/lang/Object",
                methods: &[],
                private_nested: false,
            }],
        );
        let third = JvmExternalDeclarationIndex::build_for_project(
            &config,
            &TestProject::new(root.join("workspace-a"), Language::Java),
        );
        assert!(
            !Arc::ptr_eq(&first, &third),
            "a changed resolved artifact must rebuild the index"
        );
        assert!(
            third
                .resolve_qualified_name("com.example.probe.Replaced", "")
                .is_some(),
            "the rebuilt index must read the replaced artifact"
        );
    }

    #[test]
    #[hardwon(
        "#13188: a JAR replaced in place with the same size and mtime reused a stale dispatch index"
    )]
    fn in_place_jar_replacement_with_same_size_and_mtime_rebuilds_the_index() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let repo_dir = root.join("m2").join(GROUP_PATH);
        fs::create_dir_all(&repo_dir).unwrap();
        fs::create_dir_all(root.join("workspace")).unwrap();
        let jar = repo_dir.join(BINARY_JAR);
        // Stored (uncompressed) entries whose names have equal length give
        // byte-identical JAR lengths.
        let write_jar = |internal_name| {
            write_test_class_jar(
                &jar,
                &[TestClassFile {
                    internal_name,
                    super_internal_name: "java/lang/Object",
                    methods: &[],
                    private_nested: false,
                }],
            );
        };
        write_jar("com/example/probe/Before");
        let original = fs::metadata(&jar).unwrap();
        let config = JvmAnalyzerConfig {
            external_dependencies: JvmExternalDependencies {
                coordinates: vec![JvmMavenCoordinate::new(
                    "com.example",
                    "external-lib",
                    "1.2.3",
                )],
                repository_roots: vec![root.join("m2")],
                ..JvmExternalDependencies::default()
            },
            ..JvmAnalyzerConfig::default()
        };
        let project = TestProject::new(root.join("workspace"), Language::Java);
        let first = JvmExternalDeclarationIndex::build_for_project(&config, &project);
        assert!(
            first
                .resolve_qualified_name("com.example.probe.Before", "")
                .is_some()
        );

        // Linux stamps ctime from a coarse clock; wait past one tick so the
        // overwrite's ctime differs from the original write's.
        std::thread::sleep(std::time::Duration::from_millis(50));
        // File::create truncates and rewrites the same inode.
        write_jar("com/example/probe/Latter");
        File::options()
            .write(true)
            .open(&jar)
            .unwrap()
            .set_modified(original.modified().unwrap())
            .unwrap();
        let replaced = fs::metadata(&jar).unwrap();
        assert_eq!(
            replaced.len(),
            original.len(),
            "the replacement keeps the size"
        );
        assert_eq!(
            replaced.modified().unwrap(),
            original.modified().unwrap(),
            "the replacement keeps the mtime"
        );

        let second = JvmExternalDeclarationIndex::build_for_project(&config, &project);
        assert!(
            second
                .resolve_qualified_name("com.example.probe.Latter", "")
                .is_some()
                && second
                    .resolve_qualified_name("com.example.probe.Before", "")
                    .is_none(),
            "an in-place replacement with the same size and mtime must rebuild the index"
        );
    }

    /// Lets files written by the test age past the racy-identity window, so
    /// the memo may trust their stat identity (#13537).
    fn age_past_racy_window() {
        std::thread::sleep(
            brokk_bifrost_core::content_digest::FILE_TIMESTAMP_GRANULARITY
                + std::time::Duration::from_millis(500),
        );
    }

    #[test]
    #[hardwon("#13107: racy artifact stat reused external_index_memo")]
    fn an_artifact_written_inside_the_racy_window_is_never_memoized() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let repo_dir = root.join("m2").join(GROUP_PATH);
        fs::create_dir_all(&repo_dir).unwrap();
        fs::create_dir_all(root.join("workspace")).unwrap();
        let jar = repo_dir.join(BINARY_JAR);
        probe_class_jar(&jar);
        let config = JvmAnalyzerConfig {
            external_dependencies: JvmExternalDependencies {
                coordinates: vec![JvmMavenCoordinate::new(
                    "com.example",
                    "external-lib",
                    "1.2.3",
                )],
                repository_roots: vec![root.join("m2")],
                ..JvmExternalDependencies::default()
            },
            ..JvmAnalyzerConfig::default()
        };
        let project = TestProject::new(root.join("workspace"), Language::Java);
        let first = JvmExternalDeclarationIndex::build_for_project(&config, &project);
        let second = JvmExternalDeclarationIndex::build_for_project(&config, &project);
        // A slow machine can age the file past the window between the writes
        // and the builds; the memo may then rightly serve the second build.
        let still_racy = brokk_bifrost_core::content_digest::metadata_change_identity(&jar)
            .unwrap()
            .unwrap()
            .racy_at(
                std::time::SystemTime::now(),
                brokk_bifrost_core::content_digest::FILE_TIMESTAMP_GRANULARITY,
            );
        assert!(
            !still_racy || !Arc::ptr_eq(&first, &second),
            "an artifact whose stat identity may hide a same-tick rewrite must not reuse the memo"
        );
    }

    #[test]
    fn memo_key_follows_the_racy_rule_for_artifact_identities() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let jar = root.join("lib.jar");
        probe_class_jar(&jar);
        let declared = DeclaredArtifacts {
            artifacts: vec![ResolvedJvmArtifact {
                artifact_path: jar,
                source_artifact_path: None,
                coordinate: None,
                origin: JvmDependencyOrigin::ExplicitPath,
            }],
            diagnostics: Vec::new(),
            suppressed_diagnostics: SuppressedDiagnostics::default(),
            dependency_limit_hit: false,
            metadata_inputs_considered: 0,
        };
        let key = || {
            external_index_memo_key(
                &declared,
                &JdkDiscovery::default(),
                false,
                super::super::dependency_discovery::MavenPlatformOverride::NotVisible,
            )
        };
        assert!(key().is_none(), "a just-written artifact is racy");
        age_past_racy_window();
        assert!(key().is_some(), "an aged artifact is trusted");
    }

    #[test]
    #[hardwon(
        "#8486: deterministic Java source diagnostics made the external index execution-dependent, so it was never retained"
    )]
    fn malformed_java_source_diagnostic_keeps_external_index_memoized() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let repo_dir = root.join("m2").join(GROUP_PATH);
        fs::create_dir_all(&repo_dir).unwrap();
        fs::create_dir_all(root.join("workspace")).unwrap();
        probe_class_jar(&repo_dir.join(BINARY_JAR));
        write_zip_entry(
            &repo_dir.join("external-lib-1.2.3-sources.jar"),
            "com/example/probe/Bad.java",
            b"class Bad { Broken value( { }",
        );
        age_past_racy_window();
        let config = JvmAnalyzerConfig {
            external_dependencies: JvmExternalDependencies {
                coordinates: vec![JvmMavenCoordinate::new(
                    "com.example",
                    "external-lib",
                    "1.2.3",
                )],
                repository_roots: vec![root.join("m2")],
                ..JvmExternalDependencies::default()
            },
            ..JvmAnalyzerConfig::default()
        };
        let project = TestProject::new(root.join("workspace"), Language::Java);
        let first = JvmExternalDeclarationIndex::build_for_project(&config, &project);
        assert!(
            first
                .production_diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code
                    == crate::analyzer::jvm::producer_codes::JAVA_SOURCE_PARSE.code)
        );
        let second = JvmExternalDeclarationIndex::build_for_project(&config, &project);
        assert!(
            Arc::ptr_eq(&first, &second),
            "content-determined diagnostics must permit memo retention"
        );
    }

    #[test]
    #[hardwon(
        "#8951: Scala repeated-parameter-list gaps are deterministic and must not rebuild an unchanged external index"
    )]
    fn scala_repeated_parameter_list_gap_keeps_external_index_memoized() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let repo_dir = root.join("m2").join("org/scala-lang/scala-library/2.13.16");
        fs::create_dir_all(&repo_dir).unwrap();
        fs::create_dir_all(root.join("workspace")).unwrap();

        let binary_jar = repo_dir.join("scala-library-2.13.16.jar");
        let source_jar = repo_dir.join("scala-library-2.13.16-sources.jar");
        probe_class_jar(&binary_jar);

        let initial_source = r#"
package scala.example
trait RepeatedLists {
  def repeatedThenList(values: String*)(suffix: String): String = suffix
  def finalVararg(values: String*): String = ""
  def ordinary(value: String, suffix: String): String = value
}
trait Neighbor {
  def retained: String
}
"#;
        write_zip_entry(
            &source_jar,
            "scala/example/LibraryApi.scala",
            initial_source.as_bytes(),
        );

        let config = JvmAnalyzerConfig {
            without_project_build: false,
            external_dependencies: JvmExternalDependencies {
                coordinates: vec![JvmMavenCoordinate::new(
                    "org.scala-lang",
                    "scala-library",
                    "2.13.16",
                )],
                repository_roots: vec![root.join("m2")],
                ..JvmExternalDependencies::default()
            },
            dependency_discovery:
                brokk_bifrost_core::analyzer::config::JvmDependencyDiscoveryConfig {
                    mode: JvmDependencyDiscoveryMode::Disabled,
                    ..Default::default()
                },
            standard_library_discovery:
                brokk_bifrost_core::analyzer::config::JvmStandardLibraryDiscoveryConfig {
                    discover_java_home: false,
                    ..Default::default()
                },
        };
        age_past_racy_window();
        let project = TestProject::new(root.join("workspace"), Language::Scala);

        let builds_before_first = super::EXTERNAL_INDEX_ARTIFACT_BUILDS.get();
        let first = JvmExternalDeclarationIndex::build_for_project(&config, &project);
        assert_eq!(
            super::EXTERNAL_INDEX_ARTIFACT_BUILDS.get() - builds_before_first,
            1,
            "the first dependency universe must build its artifact index once"
        );
        let assert_repeated_list_gap = |index: &JvmExternalDeclarationIndex| {
            let diagnostic = index
                .production_diagnostics()
                .iter()
                .find(|diagnostic| diagnostic.code == "scala.signature.repeated_parameter_list")
                .expect("Scala producer diagnostic is retained by the external index");
            assert_eq!(
                diagnostic.declaration.as_deref(),
                Some("scala.example.RepeatedLists.repeatedThenList")
            );
            assert!(matches!(
                crate::analyzer::jvm::producer_codes::classify(diagnostic),
                brokk_bifrost_analysis::analyzer::QueryReadIncomplete::SemanticEvidenceGap(_)
            ));
        };
        assert_repeated_list_gap(&first);
        for name in ["scala.example.RepeatedLists", "scala.example.Neighbor"] {
            assert!(
                first.get(name).is_some(),
                "valid Scala type {name} remains indexed"
            );
        }

        let builds_before_second = super::EXTERNAL_INDEX_ARTIFACT_BUILDS.get();
        let second = JvmExternalDeclarationIndex::build_for_project(&config, &project);
        assert_eq!(
            super::EXTERNAL_INDEX_ARTIFACT_BUILDS.get() - builds_before_second,
            0,
            "unchanged dependency evidence must skip artifact indexing"
        );
        assert!(
            Arc::ptr_eq(&first, &second),
            "a deterministic Scala evidence gap must permit memo retention"
        );
        assert_repeated_list_gap(&second);

        let refreshed_source = r#"
package scala.example
trait RepeatedLists {
  def repeatedThenList(values: String*)(suffix: String): String = suffix
  def finalVararg(values: String*): String = ""
  def ordinary(value: String, suffix: String): String = value
}
trait Neighbor {
  def retained: String
}
trait RefreshedNeighbor {
  def newlyAvailable: String
}
"#;
        write_zip_entry(
            &source_jar,
            "scala/example/LibraryApi.scala",
            refreshed_source.as_bytes(),
        );
        let builds_before_refresh = super::EXTERNAL_INDEX_ARTIFACT_BUILDS.get();
        let refreshed = JvmExternalDeclarationIndex::build_for_project(&config, &project);
        assert_eq!(
            super::EXTERNAL_INDEX_ARTIFACT_BUILDS.get() - builds_before_refresh,
            1,
            "changed source artifact evidence must build one refreshed index"
        );
        assert!(
            !Arc::ptr_eq(&first, &refreshed),
            "changed source artifact evidence must rebuild the external index"
        );
        assert!(
            first.get("scala.example.RefreshedNeighbor").is_none(),
            "the original index must not expose a declaration added later"
        );
        assert!(
            refreshed.get("scala.example.RefreshedNeighbor").is_some(),
            "the rebuilt index must expose the changed source artifact"
        );
    }

    #[track_caller]
    fn write_zip_entry(path: &Path, entry_name: &str, bytes: &[u8]) {
        brokk_bifrost_analysis::test_support::zip_helpers::write_zip_unwrap(
            path,
            &[(entry_name, bytes)],
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
        );
    }

    fn write_zip_entries(path: &Path, entries: &[(&str, &[u8])]) {
        brokk_bifrost_analysis::test_support::zip_helpers::write_zip_unwrap(
            path,
            entries,
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
        );
    }

    #[test]
    #[ignore = "requires BIFROST_JDK_HOME pointing to a pinned JDK installation"]
    fn pinned_jdk_home_preparation_is_cached() {
        use brokk_bifrost_core::analyzer::config::JvmStandardLibraryDiscoveryConfig;

        use brokk_bifrost_analysis::analyzer::semantic_model::CatalogOptions;

        use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackPreparationStatus;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

        use brokk_bifrost_analysis::analyzer::semantic_model::dependency::prepare_dependency_semantic_packs;

        let home =
            PathBuf::from(std::env::var_os("BIFROST_JDK_HOME").expect("set BIFROST_JDK_HOME"));
        let root = tempfile::tempdir().unwrap();
        let project = TestProject::new(root.path(), Language::Java);
        let config = JvmAnalyzerConfig {
            dependency_discovery:
                brokk_bifrost_core::analyzer::config::JvmDependencyDiscoveryConfig {
                    mode: JvmDependencyDiscoveryMode::Disabled,
                    ..Default::default()
                },
            standard_library_discovery: JvmStandardLibraryDiscoveryConfig {
                jdk_homes: vec![home],
                discover_java_home: false,
                ..Default::default()
            },
            ..Default::default()
        };
        let limits = DependencyPackLimits::default();
        let discovered = resolve_jvm_semantic_pack_dependencies(
            &config,
            &project,
            &test_digests(),
            &Default::default(),
            &limits,
            None,
        );
        assert!(discovered.complete, "{discovered:#?}");
        assert_eq!(discovered.dependencies.len(), 1, "{discovered:#?}");
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let prepared = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            &discovered.dependencies,
            &limits,
            None,
        );
        // Partial declaration coverage is expected, but the artifact must
        // still install and leave exact activation evidence and a cache entry.
        assert_eq!(prepared.packs.len(), 1, "{prepared:#?}");
        assert_eq!(prepared.evidence.len(), 1, "{prepared:#?}");
        assert_eq!(
            prepared.packs[0].status,
            DependencyPackPreparationStatus::Generated
        );
        let reused = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            &discovered.dependencies,
            &limits,
            None,
        );
        assert_eq!(reused.packs.len(), 1, "{reused:#?}");
        assert_eq!(reused.profile.generated_packs, 0, "{reused:#?}");
        assert_eq!(reused.evidence, prepared.evidence);
    }

    #[test]
    fn missing_jmod_after_discovery_is_an_honest_preparation_failure() {
        use brokk_bifrost_core::analyzer::config::JvmStandardLibraryDiscoveryConfig;

        use brokk_bifrost_analysis::analyzer::semantic_model::CatalogOptions;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

        use brokk_bifrost_analysis::analyzer::semantic_model::dependency::prepare_dependency_semantic_packs;

        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("jdk");
        fs::create_dir_all(home.join("jmods")).unwrap();
        fs::write(home.join("release"), "JAVA_VERSION=\"21.0.8\"\n").unwrap();
        fs::write(home.join("jmods/java.base.jmod"), b"not a jmod").unwrap();
        let config = JvmAnalyzerConfig {
            standard_library_discovery: JvmStandardLibraryDiscoveryConfig {
                jdk_homes: vec![home.clone()],
                discover_java_home: false,
                ..Default::default()
            },
            ..JvmAnalyzerConfig::default()
        };
        let project = TestProject::new(root.path(), Language::Java);
        let limits = DependencyPackLimits::default();
        let discovered = resolve_jvm_semantic_pack_dependencies(
            &config,
            &project,
            &test_digests(),
            &Default::default(),
            &limits,
            None,
        );
        assert_eq!(discovered.dependencies.len(), 1);
        fs::remove_file(home.join("jmods/java.base.jmod")).unwrap();
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let prepared = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            &discovered.dependencies,
            &limits,
            None,
        );
        assert!(!prepared.complete);
        assert!(prepared.packs.is_empty());
        assert!(
            prepared
                .diagnostics
                .iter()
                .any(|diagnostic| { diagnostic.code == "artifact.metadata" })
        );
    }

    #[test]
    fn incomplete_kotlin_classification_never_falls_through_to_java() {
        let temp = tempfile::tempdir().unwrap();
        let source_jar = temp.path().join("unknown-sources.jar");
        File::create(&source_jar)
            .unwrap()
            .set_len(MAX_ARTIFACT_BYTES + 1)
            .unwrap();
        let invalid_jar = temp.path().join("invalid-sources.jar");
        fs::write(&invalid_jar, b"not a ZIP archive").unwrap();
        for path in [source_jar, invalid_jar] {
            let dependency = resolved_semantic_pack_dependency(ResolvedJvmArtifact {
                artifact_path: temp.path().join("unknown.jar"),
                source_artifact_path: Some(path),
                coordinate: Some(JvmMavenCoordinate::new("example", "unknown", "1.0.0")),
                origin: JvmDependencyOrigin::ExplicitPath,
            });

            assert_eq!(dependency.evidence.language, "kotlin");
            assert_eq!(
                dependency.artifacts[0].kind,
                ExternalArtifactKind::KotlinSourceJar
            );
            assert!(dependency.provenance.iter().any(|entry| {
                matches!(
                    entry.key.as_str(),
                    "kotlin.classification.capped" | "kotlin.classification.malformed"
                )
            }));
        }
    }

    #[test]
    #[hardwon("#7473: a Java jar of more than 1,024 classes was refused as possibly Kotlin")]
    fn large_java_class_jar_classifies_as_java() {
        // javax:javaee-api:6.0 has 1,830 classes and no sources jar.
        let temp = tempfile::tempdir().unwrap();
        let jar = temp.path().join("large-api-1.0.jar");
        let names = (0..1_830)
            .map(|index| format!("com/example/api/Type{index}"))
            .collect::<Vec<_>>();
        let classes = names
            .iter()
            .map(|internal_name| TestClassFile {
                internal_name,
                super_internal_name: "java/lang/Object",
                methods: &[],
                private_nested: false,
            })
            .collect::<Vec<_>>();
        write_test_class_jar(&jar, &classes);

        let dependency = resolved_semantic_pack_dependency(ResolvedJvmArtifact {
            artifact_path: jar,
            source_artifact_path: None,
            coordinate: Some(JvmMavenCoordinate::new("example", "large-api", "1.0")),
            origin: JvmDependencyOrigin::MavenRepository,
        });

        assert_eq!(dependency.evidence.language, "java", "{dependency:#?}");
        assert_eq!(
            dependency.artifacts[0].kind,
            ExternalArtifactKind::JavaClassJar,
            "{dependency:#?}"
        );
        assert!(
            !dependency
                .provenance
                .iter()
                .any(|entry| entry.key == "kotlin.classification"),
            "{dependency:#?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_coordinate_probe_preserves_provider_cause() {
        use brokk_bifrost_analysis::analyzer::read_ledger::DerivationExecutionCause;
        let root = tempfile::tempdir().unwrap();
        let repository = root.path().join("repository");
        std::os::unix::fs::symlink(&repository, &repository).unwrap();
        let project = TestProject::new(root.path(), Language::Java);
        let mut config = JvmAnalyzerConfig::default();
        config.external_dependencies.coordinates = vec![JvmMavenCoordinate {
            group_id: "org.bifrost.io.testing".into(),
            artifact_id: "unavailable".into(),
            version: "1".into(),
        }];
        config.external_dependencies.repository_roots = vec![repository];
        config.dependency_discovery.mode = JvmDependencyDiscoveryMode::Disabled;
        config.standard_library_discovery.discover_java_home = false;
        let discovery = resolve_jvm_semantic_pack_dependencies(
            &config,
            &project,
            &test_digests(),
            &Default::default(),
            &DependencyPackLimits::default(),
            None,
        );
        let diagnostic = discovery
            .diagnostics
            .into_iter()
            .find(|d| d.code == "jvm.dependency_unavailable")
            .expect("a failed acquisition is not certified absence");
        let reason =
            crate::analyzer::jvm::producer_codes::classify(&IndexGap::from_discovery(diagnostic));
        assert_eq!(
            reason.execution_cause(),
            Some(DerivationExecutionCause::Provider)
        );
        assert!(reason.stable_replay_reason().is_none());
    }

    #[test]
    fn unresolved_jvm_coordinate_is_actionable_incomplete_discovery() {
        use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackLimits;

        use brokk_bifrost_analysis::analyzer::semantic_model::dependency::prepare_discovered_dependency_semantic_packs;

        let root = tempfile::tempdir().unwrap();
        let project = TestProject::new(root.path(), Language::Java);
        let config = JvmAnalyzerConfig {
            without_project_build: false,
            external_dependencies: JvmExternalDependencies {
                coordinates: vec![JvmMavenCoordinate {
                    group_id: "com.example".to_owned(),
                    artifact_id: "missing".to_owned(),
                    version: "1.0.0".to_owned(),
                }],
                repository_roots: vec![root.path().join("repository")],
                ..JvmExternalDependencies::default()
            },
            dependency_discovery:
                brokk_bifrost_core::analyzer::config::JvmDependencyDiscoveryConfig {
                    mode: JvmDependencyDiscoveryMode::Disabled,
                    ..brokk_bifrost_core::analyzer::config::JvmDependencyDiscoveryConfig::default()
                },
            standard_library_discovery:
                brokk_bifrost_core::analyzer::config::JvmStandardLibraryDiscoveryConfig {
                    discover_java_home: false,
                    ..Default::default()
                },
        };
        let limits = DependencyPackLimits::default();
        let discovery = resolve_jvm_semantic_pack_dependencies(
            &config,
            &project,
            &test_digests(),
            &Default::default(),
            &limits,
            None,
        );

        assert!(!discovery.complete);
        assert!(discovery.dependencies.is_empty());
        assert_eq!(discovery.diagnostics[0].code, "jvm.dependency_unresolved");
        let catalog = brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog::open_ephemeral(
            Default::default(),
        )
        .unwrap();
        let prepared = prepare_discovered_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            discovery,
            &limits,
            None,
        );
        assert!(!prepared.complete);
        assert!(
            prepared
                .compose_activation_request(
                    brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelActivationRequest {
                        host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
                        approximate_standard_libraries: Vec::new(),
                        bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
                        evidence: Vec::new(),
                        controls: Vec::new(),
                        limits: Default::default(),
                    }
                )
                .is_none()
        );
    }
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn java_dependency_discovery_indexes_exact_maven_pom_coordinate() {
        let Some(fixture) = ExternalJarFixture::new(true) else {
            return;
        };
        let app = ProjectFile::new(fixture.project_root().to_path_buf(), "src/App.java");
        app.write(
            "package app; import com.example.dep.ExternalService; class App { ExternalService service; }",
        )
        .unwrap();
        ProjectFile::new(fixture.project_root().to_path_buf(), "pom.xml")
            .write(
                "<project><groupId>app</groupId><artifactId>app</artifactId><version>1</version><dependencies><dependency><groupId>com.example</groupId><artifactId>external-lib</artifactId><version>1.2.3</version></dependency></dependencies></project>",
            )
            .unwrap();
        let config = AnalyzerConfig {
            jvm: JvmAnalyzerConfig {
                external_dependencies: JvmExternalDependencies {
                    repository_roots: vec![fixture.maven_repository_root()],
                    ..JvmExternalDependencies::default()
                },
                ..JvmAnalyzerConfig::default()
            },
            ..AnalyzerConfig::default()
        };
        let analyzer = JavaAnalyzer::from_project_with_config(
            TestProject::new(fixture.project_root().to_path_buf(), Language::Java),
            config,
        );
        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        assert!(analyzer.is_known_type_name_in_file(token, None, &app, "ExternalService"));
    }

    #[test]
    fn java_dependency_discovery_indexes_only_locked_gradle_coordinate_directory() {
        let Some(fixture) = ExternalJarFixture::new(true) else {
            return;
        };
        let gradle_cache = fixture.root.join("gradle-cache");
        let locked_dir = gradle_cache.join("com.example/external-lib/1.2.3/binary-hash");
        let source_dir = gradle_cache.join("com.example/external-lib/1.2.3/source-hash");
        let unrelated_dir = gradle_cache.join("unrelated/example/9.9.9/hash");
        fs::create_dir_all(&locked_dir).unwrap();
        fs::create_dir_all(&source_dir).unwrap();
        fs::create_dir_all(&unrelated_dir).unwrap();
        fs::copy(fixture.binary_jar_path(), locked_dir.join(BINARY_JAR)).unwrap();
        fs::copy(fixture.source_jar_path(), source_dir.join(SOURCE_JAR)).unwrap();
        fs::copy(
            fixture.binary_jar_path(),
            unrelated_dir.join("example-9.9.9.jar"),
        )
        .unwrap();

        let app = ProjectFile::new(fixture.project_root().to_path_buf(), "src/App.java");
        app.write(
            "package app; import com.example.dep.ExternalService; class App { ExternalService service; }",
        )
        .unwrap();
        ProjectFile::new(fixture.project_root().to_path_buf(), "gradle.lockfile")
            .write("com.example:external-lib:1.2.3=compileClasspath\n")
            .unwrap();
        let config = AnalyzerConfig {
            jvm: JvmAnalyzerConfig {
                external_dependencies: JvmExternalDependencies {
                    repository_roots: vec![fixture.root.join("empty-maven")],
                    gradle_cache_roots: vec![gradle_cache],
                    ..JvmExternalDependencies::default()
                },
                ..JvmAnalyzerConfig::default()
            },
            ..AnalyzerConfig::default()
        };
        let analyzer = JavaAnalyzer::from_project_with_config(
            TestProject::new(fixture.project_root().to_path_buf(), Language::Java),
            config,
        );
        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        let resolution = analyzer
            .resolve_type_name_with_external(token, None, &app, "ExternalService")
            .unwrap();
        let crate::analyzer::java::imports::JavaTypeResolution::External(external) = resolution
        else {
            panic!("dependency should resolve externally");
        };
        assert!(matches!(
            external.source(),
            JvmExternalDeclarationSource::SourceJar { .. }
        ));
    }

    #[test]
    fn java_dependency_discovery_skips_classifier_only_gradle_cache_entries() {
        let Some(fixture) = ExternalJarFixture::new(false) else {
            return;
        };
        let gradle_cache = fixture.root.join("gradle-cache");
        let classifier_dir = gradle_cache.join("com.example/external-lib/1.2.3/classifier-hash");
        fs::create_dir_all(&classifier_dir).unwrap();
        fs::copy(
            fixture.binary_jar_path(),
            classifier_dir.join("external-lib-1.2.3-tests.jar"),
        )
        .unwrap();

        let config = JvmExternalDependencies {
            coordinates: vec![JvmMavenCoordinate::new(
                "com.example",
                "external-lib",
                "1.2.3",
            )],
            gradle_cache_roots: vec![gradle_cache],
            ..JvmExternalDependencies::default()
        };
        let index = JvmExternalDeclarationIndex::build(&config, fixture.project_root());
        assert!(index.is_empty());
    }
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn java_dependency_discovery_disabled_keeps_metadata_out_of_index() {
        let Some(fixture) = ExternalJarFixture::new(false) else {
            return;
        };
        let app = ProjectFile::new(fixture.project_root().to_path_buf(), "src/App.java");
        app.write(
            "package app; import com.example.dep.ExternalService; class App { ExternalService service; }",
        )
        .unwrap();
        ProjectFile::new(fixture.project_root().to_path_buf(), "pom.xml")
            .write(
                "<project><dependencies><dependency><groupId>com.example</groupId><artifactId>external-lib</artifactId><version>1.2.3</version></dependency></dependencies></project>",
            )
            .unwrap();
        let config = AnalyzerConfig {
            jvm: JvmAnalyzerConfig {
                without_project_build: false,
                external_dependencies: JvmExternalDependencies {
                    repository_roots: vec![fixture.maven_repository_root()],
                    ..JvmExternalDependencies::default()
                },
                dependency_discovery: brokk_bifrost_core::analyzer::config::JvmDependencyDiscoveryConfig {
                    mode: brokk_bifrost_core::analyzer::config::JvmDependencyDiscoveryMode::Disabled,
                    ..brokk_bifrost_core::analyzer::config::JvmDependencyDiscoveryConfig::default()
                },
                standard_library_discovery: brokk_bifrost_core::analyzer::config::JvmStandardLibraryDiscoveryConfig {
                    discover_java_home: false,
                    ..Default::default()
                },
            },
            ..AnalyzerConfig::default()
        };
        let analyzer = JavaAnalyzer::from_project_with_config(
            TestProject::new(fixture.project_root().to_path_buf(), Language::Java),
            config,
        );
        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        assert!(!analyzer.is_known_type_name_in_file(token, None, &app, "ExternalService"));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11968: a live source-only subset must refresh out-of-subset build inputs but retain the index for source edits"
    )]
    fn java_dependency_discovery_invalidates_only_for_build_inputs() {
        let Some(fixture) = ExternalJarFixture::new(false) else {
            return;
        };
        let app = ProjectFile::new(fixture.project_root().to_path_buf(), "src/App.java");
        app.write(
            "package app; import com.example.dep.ExternalService; class App { ExternalService service; }",
        )
        .unwrap();
        let pom = ProjectFile::new(fixture.project_root().to_path_buf(), "pom.xml");
        pom.write("<project><dependencies><dependency><groupId>com.example</groupId><artifactId>external-lib</artifactId></dependency></dependencies></project>")
            .unwrap();
        let config = AnalyzerConfig {
            jvm: JvmAnalyzerConfig {
                external_dependencies: JvmExternalDependencies {
                    repository_roots: vec![fixture.maven_repository_root()],
                    ..JvmExternalDependencies::default()
                },
                ..JvmAnalyzerConfig::default()
            },
            ..AnalyzerConfig::default()
        };
        let delegate = Arc::new(
            brokk_bifrost_core::analyzer::project::FilesystemProject::new(fixture.project_root())
                .unwrap(),
        );
        let subset = brokk_bifrost_core::analyzer::project::FileSetProject::new(
            fixture.project_root(),
            [app.rel_path().to_path_buf()],
        )
        .with_project_build(delegate);
        let analyzer = JavaAnalyzer::from_project_with_config(subset, config);
        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        assert!(!analyzer.is_known_type_name_in_file(token, None, &app, "ExternalService"));
        let initial_index = analyzer.external_index.clone();

        pom.write("<project><dependencies><dependency><groupId>com.example</groupId><artifactId>external-lib</artifactId><version>1.2.3</version></dependency></dependencies></project>")
            .unwrap();
        let updated = analyzer.update(&BTreeSet::from([pom.clone()]));
        assert!(updated.is_known_type_name_in_file(token, None, &app, "ExternalService"));
        assert!(!initial_index.shares_index_with(&updated.external_index));
        // The first build published the jar's inventory, which moves the store's
        // inventory generation past the one it sampled, so the next read
        // rebuilds once (#13384). Settle that before testing the carry.
        updated.external_declaration_index();

        app.write(
            "package app; import com.example.dep.ExternalService; class App { ExternalService changed; }",
        )
        .unwrap();
        let java_only = updated.update(&BTreeSet::from([app]));
        java_only.external_declaration_index();
        assert!(
            updated
                .external_index
                .shares_index_with(&java_only.external_index)
        );
        let refreshed = java_only.update_all();
        refreshed.external_declaration_index();
        assert!(
            !java_only
                .external_index
                .shares_index_with(&refreshed.external_index)
        );
    }

    #[test]
    fn jvm_external_declaration_omits_kotlin_types_a_consumer_cannot_name() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let index = kotlin_source_jar_index(&root);

        // `internal` is module-scoped and `private` is file-scoped, so neither
        // is nameable from a different artifact.
        assert!(index.get("kotlin.example.ModulePrivate").is_none());
        assert!(index.get("kotlin.example.FilePrivate").is_none());
        assert!(index.get("kotlin.example.Dependency.Hidden").is_none());

        // The index answers "does this *type* exist"; top-level callables are
        // not types, and the JVM facade Kotlin generates for them
        // (`DependencyKt`) is a compiler artifact that never appears in a
        // Kotlin identity.
        assert!(index.get("kotlin.example.topLevelHelper").is_none());
        assert!(index.get("kotlin.example.DependencyKt").is_none());
    }

    #[test]
    fn kotlin_analyzer_shares_the_jvm_dependency_realm() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let workspace_root = root.join("workspace");
        fs::create_dir_all(&workspace_root).unwrap();
        let source_jar = root.join("kotlin-library-sources.jar");
        write_zip_entry(
            &source_jar,
            "kotlin/example/Dependency.kt",
            KOTLIN_DEPENDENCY_SOURCE.as_bytes(),
        );

        ProjectFile::new(workspace_root.clone(), "src/App.kt")
            .write("package app\n\nimport kotlin.example.Dependency\n\nclass App\n")
            .unwrap();

        let config = AnalyzerConfig {
            jvm: JvmAnalyzerConfig {
                external_dependencies: JvmExternalDependencies {
                    artifact_paths: vec![JvmExternalArtifact {
                        artifact_path: source_jar,
                        source_artifact_path: None,
                        ..JvmExternalArtifact::default()
                    }],
                    ..JvmExternalDependencies::default()
                },
                ..JvmAnalyzerConfig::default()
            },
            ..AnalyzerConfig::default()
        };
        let analyzer = crate::analyzer::KotlinAnalyzer::new_with_config(
            Arc::new(TestProject::new(workspace_root, Language::Kotlin)),
            config,
        );

        let index = analyzer.external_declaration_index();
        assert!(
            index
                .resolve_explicit_import("kotlin.example.Dependency", "app")
                .is_some(),
            "the Kotlin analyzer must read the same jar-backed index Java and Scala use"
        );
        assert!(
            index
                .resolve_explicit_import("kotlin.example.ModulePrivate", "app")
                .is_none()
        );
    }

    #[test]
    fn java_external_declaration_resolver_distinguishes_source_and_external_types() {
        let Some(fixture) = ExternalJarFixture::new(true) else {
            return;
        };
        let config = AnalyzerConfig {
            jvm: brokk_bifrost_core::analyzer::config::JvmAnalyzerConfig {
                external_dependencies: fixture.coordinate_config(),
                ..brokk_bifrost_core::analyzer::config::JvmAnalyzerConfig::default()
            },
            ..AnalyzerConfig::default()
        };

        let app = ProjectFile::new(fixture.project_root().to_path_buf(), "src/App.java");
        app.write(
            "package app;\n\
             import com.example.dep.ExternalService;\n\
             import com.example.dep.ExternalHelper;\n\
             import com.example.dep.PublicApi;\n\
             import com.example.dep.*;\n\
             import com.example.other.*;\n\
             public class App { ExternalService one; ExternalService.Nested two; ExternalHelper helper; ExternalService.ProtectedNested blocked; PublicApi.Callback callback; Foo ambiguous; PackageOuter.Nested hidden; }\n",
        )
        .unwrap();
        ProjectFile::new(fixture.project_root().to_path_buf(), "src/LocalType.java")
            .write("package app; public class LocalType {}")
            .unwrap();
        let same_package_app = ProjectFile::new(
            fixture.project_root().to_path_buf(),
            "src/com/example/dep/App.java",
        );
        same_package_app
            .write("package com.example.dep; public class App { PackageHelper helper; }\n")
            .unwrap();

        let project = TestProject::new(fixture.project_root().to_path_buf(), Language::Java);
        let analyzer = JavaAnalyzer::from_project_with_config(project.clone(), config);

        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        assert!(matches!(
            analyzer.resolve_type_name_with_external(token, None, &app, "LocalType"),
            Some(crate::analyzer::java::imports::JavaTypeResolution::Source(
                _
            ))
        ));
        assert!(matches!(
            analyzer.resolve_type_name_with_external(token, None, &app, "ExternalService"),
            Some(crate::analyzer::java::imports::JavaTypeResolution::External(_))
        ));
        assert!(matches!(
            analyzer.resolve_type_name_with_external(token, None, &app, "ExternalService.Nested"),
            Some(crate::analyzer::java::imports::JavaTypeResolution::External(_))
        ));
        assert!(
            analyzer
                .resolve_type_name_with_external(
                    token,
                    None,
                    &app,
                    "ExternalService.ProtectedNested"
                )
                .is_none(),
            "protected nested dependency types should not resolve from unrelated packages"
        );
        assert!(matches!(
            analyzer.resolve_type_name_with_external(token, None, &app, "PublicApi.Callback"),
            Some(crate::analyzer::java::imports::JavaTypeResolution::External(_))
        ));
        assert!(
            analyzer
                .resolve_type_name_with_external(token, None, &app, "Foo")
                .is_none(),
            "ambiguous wildcard external types should not resolve arbitrarily"
        );
        assert!(
            analyzer
                .resolve_type_name_with_external(token, None, &app, "PackageOuter.Nested")
                .is_none(),
            "public nested types under package-private outers should not resolve from other packages"
        );
        assert!(matches!(
            analyzer.resolve_type_name_with_external(
                token,
                None,
                &same_package_app,
                "PackageHelper"
            ),
            Some(crate::analyzer::java::imports::JavaTypeResolution::External(_))
        ));
        assert!(matches!(
            analyzer.resolve_type_name_with_external(
                token,
                None,
                &same_package_app,
                "ExternalService.PackageNested"
            ),
            Some(crate::analyzer::java::imports::JavaTypeResolution::External(_))
        ));
        assert!(
            analyzer
                .resolve_type_name_in_file(token, &app, "ExternalService")
                .is_none(),
            "source-only resolution should not fabricate CodeUnits for dependency types"
        );
        assert!(
            project
                .all_files()
                .unwrap()
                .iter()
                .all(|file| !file.rel_path().to_string_lossy().contains(".jar"))
        );
    }
    /// A recorded tree part resolves again to the answer the live discovery
    /// gave, and follows the environment: a Maven repository artifact that
    /// disappears, or an explicit artifact path inside the workspace that is
    /// replaced, changes it (#11607). The gap identity folds no path, so
    /// nothing about the root the answer was first computed under enters it.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11607: a dependency selection recorded over an export could not be checked against a head that differed from its tree"
    )]
    fn a_recorded_tree_part_resolves_again_in_the_environment() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::create_dir_all(root.join("libs")).unwrap();
        fs::write(root.join("libs/a.jar"), b"not a jar").unwrap();
        fs::write(
            root.join("pom.xml"),
            r#"<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId><artifactId>app</artifactId><version>1</version>
<dependencies><dependency><groupId>com.example</groupId><artifactId>lib</artifactId><version>1.0</version><scope>test</scope></dependency></dependencies></project>"#,
        )
        .unwrap();
        let repository = root.join("repo");
        let jar = repository.join("com/example/lib/1.0/lib-1.0.jar");
        fs::create_dir_all(jar.parent().unwrap()).unwrap();
        fs::write(&jar, b"not a jar either").unwrap();
        let project = TestProject::new(&root, Language::Java);
        let config = JvmAnalyzerConfig {
            external_dependencies: JvmExternalDependencies {
                artifact_paths: vec![JvmExternalArtifact {
                    artifact_path: PathBuf::from("libs/a.jar"),
                    ..JvmExternalArtifact::default()
                }],
                repository_roots: vec![repository],
                ..JvmExternalDependencies::default()
            },
            standard_library_discovery:
                brokk_bifrost_core::analyzer::config::JvmStandardLibraryDiscoveryConfig {
                    discover_java_home: false,
                    ..Default::default()
                },
            ..JvmAnalyzerConfig::default()
        };
        let basis = jvm_dependency_basis(&config, &project).expect("a recordable tree part");
        assert_eq!(
            basis
                .entries
                .iter()
                .map(|entry| (entry.artifact_id.as_str(), entry.scope.as_str()))
                .collect::<Vec<_>>(),
            [("lib", "test")]
        );
        let live = JvmExternalDeclarationIndex::build_for_project(&config, &project).gap_identity();
        let again = || {
            JvmExternalDeclarationIndex::build_under_basis(&config, &root, &basis)
                .expect("known scope")
                .gap_identity()
        };
        assert_eq!(again(), live);
        fs::remove_file(&jar).unwrap();
        let live_without_jar =
            JvmExternalDeclarationIndex::build_for_project(&config, &project).gap_identity();
        assert_ne!(live_without_jar, live);
        assert_eq!(again(), live_without_jar);
        fs::remove_file(root.join("libs/a.jar")).unwrap();
        assert_ne!(again(), live_without_jar);
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod python_test_support;

#[cfg(test)]
mod preparation_membership_tests {
    use super::*;
    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::{
        CatalogOptions, GeneratedProductionKey, SemanticPackCatalog,
    };
    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::{
        SemanticModelActivationEvidence, SemanticModelActivationRequest,
        SemanticModelResolutionOutcome, resolve_active_semantic_models,
    };
    use brokk_bifrost_analysis::analyzer::semantic_model::{
        AuthoredSemanticModelPack, CompilerOptions, compile_pack,
    };
    use brokk_bifrost_semantic::analyzer::semantic_model::dependency::{
        DependencyPreparationFailureCause, RecordedPreparationFailure,
    };

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "cbc09cd693b2: installed partial dependency shards were excluded from pinned membership"
    )]
    fn active_shards_are_pinned_for_every_preparation_outcome() {
        #[derive(Debug, Clone, Copy)]
        enum Outcome {
            Complete,
            PartialInstalled,
            Failed(DependencyPreparationFailureCause),
            Pending,
            Cancelled,
        }
        for outcome in [
            Outcome::Complete,
            Outcome::PartialInstalled,
            Outcome::Failed(DependencyPreparationFailureCause::Rejected),
            Outcome::Failed(DependencyPreparationFailureCause::PackUnavailable),
            Outcome::Failed(DependencyPreparationFailureCause::ProducerFailed),
            Outcome::Pending,
            Outcome::Cancelled,
        ] {
            let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
            let producer = Producer {
                name: "artifact-scanner".into(),
                version: "2.0.0".into(),
            }
            .with_dependency_revision();
            let key = GeneratedProductionKey::new(
                "a".repeat(64),
                &producer.name,
                &producer.version,
                brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
            )
            .unwrap();
            let mut selection = ExternalInventorySelection::empty_for_catalog_reader_test()
                .with_generated_key_for_catalog_reader_test(key.clone());
            let installed = matches!(outcome, Outcome::Complete | Outcome::PartialInstalled);
            if installed {
                let mut authored: serde_json::Value =
                    serde_json::from_slice(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../bifrost-analysis/testdata/semantic-model-packs/declarations-v1.json"
                    )))
                    .unwrap();
                authored["schema_version"] = serde_json::json!(
                    brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION
                );
                authored["compatibility"] = serde_json::json!({});
                authored["shards"][0]["activation"] = serde_json::json!([{}]);
                authored["completeness"] =
                    serde_json::json!(if matches!(outcome, Outcome::PartialInstalled) {
                        "partial"
                    } else {
                        "complete"
                    });
                let pack = compile_pack(
                    &serde_json::from_value::<AuthoredSemanticModelPack>(authored).unwrap(),
                    &CompilerOptions::default(),
                )
                .unwrap();
                let pack = brokk_bifrost_analysis::test_support::generated_pack_fixture(
                    &pack,
                    key.input_digest(),
                    &brokk_bifrost_analysis::test_support::generated_input_slots(),
                );
                catalog
                    .install_generated(
                        &key,
                        &pack,
                        &brokk_bifrost_analysis::test_support::generated_input_slots(),
                    )
                    .unwrap();
            }
            match outcome {
                Outcome::Failed(cause) => {
                    selection
                        .preparation_failures
                        .push(RecordedPreparationFailure {
                            dependency: selection.productions[0].0.clone(),
                            cause,
                            inputs: brokk_bifrost_semantic::analyzer::semantic_model::dependency::PreparationFailureInputs::Bound(Vec::new()),
                        })
                }
                Outcome::Cancelled => selection.productions.clear(),
                _ => {}
            }
            let request = SemanticModelActivationRequest {
                host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
                bifrost_version: semver::Version::new(0, 15, 1),
                evidence: vec![SemanticModelActivationEvidence {
                    language: "java".into(),
                    ecosystem: "maven".into(),
                    package: None,
                    module: None,
                    toolchain: None,
                    target: None,
                    configuration: None,
                    production_input_digest: Some(key.input_digest().to_owned()),
                    verified_raw_artifacts:
                        brokk_bifrost_analysis::test_support::generated_input_slots(),
                }],
                approximate_standard_libraries: Vec::new(),
                controls: Vec::new(),
                limits: Default::default(),
            };
            let SemanticModelResolutionOutcome::Ready(active) =
                resolve_active_semantic_models(&catalog, &request, &CancellationToken::new())
            else {
                panic!("activation failed for {outcome:?}")
            };
            let expected = selection.catalog_expectations();
            assert_eq!(
                expected.len(),
                usize::from(installed || matches!(outcome, Outcome::Pending)),
                "{outcome:?}"
            );
            let reader = catalog
                .pinned_jvm_reader(&expected, CancellationToken::new())
                .unwrap();
            let pinned: std::collections::HashSet<_> = reader
                .membership
                .iter()
                .filter_map(|row| row.shard_key.map(|key| (row.kind.shard_database(), key)))
                .collect();
            let active: std::collections::HashSet<_> = active
                .shards
                .iter()
                .filter(|shard| {
                    brokk_bifrost_analysis::analyzer::store::active_models::shard_owner_index(
                        shard,
                        None,
                        Some(0),
                    ) == Some(0)
                })
                .filter_map(|shard| shard.row_store.map(|row| (row.database, row.shard_key)))
                .collect();
            assert_eq!(!active.is_empty(), installed, "{outcome:?}: {active:?}");
            assert!(
                active.is_subset(&pinned),
                "{outcome:?}: active={active:?}, pinned={pinned:?}"
            );
        }
    }
}
