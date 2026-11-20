//! Query-scoped external input observation. Only the two scalar answers and a
//! fixed-size carry sample survive discovery; no census is retained.
use brokk_bifrost_core::content_digest::artifact_change_identity;
use std::cell::RefCell;
use std::path::{Path, PathBuf};

use super::CSharpAnalyzerConfig;
#[cfg(test)]
use super::external::CSharpExternalDeclarationIndex;
use brokk_bifrost_analysis::analyzer::IAnalyzer;
use brokk_bifrost_analysis::analyzer::artifact_digest::{digest_bytes, digest_file, rehash_file};
use brokk_bifrost_analysis::analyzer::semantic_model::producer::read_exact_artifact_while;
use brokk_bifrost_analysis::analyzer::semantic_model::{
    ArtifactProducerLimits, DependencyDiscoveryOutcome, ExactArtifact,
};
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::project::Project;
use brokk_bifrost_semantic::analyzer::semantic::ids::StableDigest;

struct Observations {
    content: Vec<(PathBuf, [u8; 32])>,
    selected: Vec<PathBuf>,
    probes: CanonicalHasher,
    reusable: bool,
}
impl Default for Observations {
    fn default() -> Self {
        Self {
            content: Vec::new(),
            selected: Vec::new(),
            probes: CanonicalHasher::new(b"bifrost-csharp-discovery-probes"),
            reusable: true,
        }
    }
}
thread_local! {
    static OBSERVATIONS: RefCell<Option<Observations>> = const { RefCell::new(None) };
}
struct Capture(Option<Observations>);
impl Capture {
    fn new() -> Self {
        Self(OBSERVATIONS.with(|slot| slot.replace(Some(Observations::default()))))
    }
    fn finish(mut self) -> Observations {
        let result = OBSERVATIONS
            .with(|slot| slot.replace(self.0.take()))
            .expect("active capture");
        std::mem::forget(self);
        result
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        OBSERVATIONS.with(|slot| slot.replace(self.0.take()));
    }
}

pub(super) fn content(path: &Path, bytes: &[u8]) {
    OBSERVATIONS.with(|slot| {
        if let Some(observed) = slot.borrow_mut().as_mut() {
            observed
                .content
                .push((path.to_owned(), digest_bytes(bytes)));
        }
    });
}

pub(super) fn selected(path: &Path) {
    OBSERVATIONS.with(|slot| {
        if let Some(observed) = slot.borrow_mut().as_mut() {
            observed.selected.push(path.to_owned());
        }
    });
}

pub(super) fn metadata(path: &Path) -> std::io::Result<std::fs::Metadata> {
    let result = std::fs::metadata(path);
    OBSERVATIONS.with(|slot| {
        if let Some(observed) = slot.borrow_mut().as_mut() {
            observed
                .probes
                .field("metadata_path", path.as_os_str().as_encoded_bytes());
            match &result {
                Ok(metadata) => observed.probes.field(
                    "type",
                    if metadata.is_file() {
                        b"file"
                    } else if metadata.is_dir() {
                        b"directory"
                    } else {
                        b"other"
                    },
                ),
                Err(error) => {
                    observed
                        .probes
                        .field("metadata_error", format!("{:?}", error.kind()).as_bytes());
                    if error.kind() != std::io::ErrorKind::NotFound {
                        observed.reusable = false;
                    }
                }
            }
        }
    });
    result
}

pub(super) fn canonicalize(path: &Path) -> std::io::Result<PathBuf> {
    let result = path.canonicalize();
    OBSERVATIONS.with(|slot| {
        if let Some(observed) = slot.borrow_mut().as_mut() {
            observed
                .probes
                .field("path", path.as_os_str().as_encoded_bytes());
            match &result {
                Ok(path) => observed
                    .probes
                    .field("canonical", path.as_os_str().as_encoded_bytes()),
                Err(error) => {
                    observed
                        .probes
                        .field("error", format!("{:?}", error.kind()).as_bytes());
                    if error.kind() != std::io::ErrorKind::NotFound {
                        observed.reusable = false;
                    }
                }
            }
        }
    });
    if let Ok(path) = &result {
        metadata(path)?;
    }
    result
}

pub(super) struct Sample {
    pub discovery: DependencyDiscoveryOutcome,
    pub dependency: StableDigest,
    pub artifact: StableDigest,
    pub carry: [u8; 32],
    pub reusable: bool,
    pub artifacts: Vec<ArtifactInput>,
}
pub(super) struct ArtifactInput {
    pub path: PathBuf,
    pub module: Option<String>,
    pub digest: [u8; 32],
    pub exact: Option<ExactArtifact>,
}

struct ArtifactContent {
    digest: [u8; 32],
    exact: Option<ExactArtifact>,
}

impl Sample {
    pub fn same_inputs(&self, other: &Self) -> bool {
        self.reusable
            && other.reusable
            && self.dependency == other.dependency
            && self.artifact == other.artifact
            && self.carry == other.carry
    }
}

fn hash_artifact(file: &mut std::fs::File, size: u64) -> std::io::Result<[u8; 32]> {
    use brokk_bifrost_analysis::analyzer::semantic_model::producer::{
        finish_digest, hash_exact_file,
    };
    use sha2::{Digest, Sha256};
    if size > super::external::MAX_ASSEMBLY_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "assembly exceeds the byte limit",
        ));
    }
    let mut hash = Sha256::new();
    hash_exact_file(&mut hash, size, file)?;
    Ok(finish_digest(hash))
}

fn digest_with_identity(
    path: &Path,
    classify: impl FnOnce(
        &Path,
    )
        -> std::io::Result<Option<brokk_bifrost_core::content_digest::FileIdentity>>,
    supported: impl FnOnce(&Path) -> std::io::Result<[u8; 32]>,
) -> std::io::Result<ArtifactContent> {
    if classify(path)?.is_none() {
        exact_digest(path)
    } else {
        supported(path).map(|digest| ArtifactContent {
            digest,
            exact: None,
        })
    }
}

fn exact_digest(path: &Path) -> std::io::Result<ArtifactContent> {
    let limits = ArtifactProducerLimits {
        max_artifact_bytes: ArtifactProducerLimits::default()
            .max_artifact_bytes
            .min(super::external::MAX_ASSEMBLY_BYTES),
        ..ArtifactProducerLimits::default()
    };
    let artifact = read_exact_artifact_while(path, &limits, || false)
        .map_err(|diagnostic| std::io::Error::other(diagnostic.message))?;
    let digest =
        brokk_bifrost_core::analyzer::canonical_hash::parse_lower_sha256(artifact.sha256())
            .expect("exact artifact SHA-256");
    Ok(ArtifactContent {
        digest,
        exact: Some(artifact),
    })
}

pub(super) fn sample(
    analyzer: &dyn IAnalyzer,
    config: &CSharpAnalyzerConfig,
    project: &dyn Project,
) -> Sample {
    let cancellation = analyzer.active_query_cancellation();
    discover_and_sample(config, project, cancellation.as_ref(), |path| {
        // This is the same classification seam used by the file memo. An
        // unsupported identity never enters the memo or compares absent stats.
        digest_with_identity(path, artifact_change_identity, |path| {
            digest_file(
                analyzer
                    .snapshot_caches()
                    .map(|cache| cache.artifact_digests.as_ref()),
                path,
                hash_artifact,
            )
        })
    })
}

pub(super) fn fresh_sample(
    analyzer: &dyn IAnalyzer,
    config: &CSharpAnalyzerConfig,
    project: &dyn Project,
) -> Sample {
    let cancellation = analyzer.active_query_cancellation();
    discover_and_sample(config, project, cancellation.as_ref(), |path| {
        digest_with_identity(path, artifact_change_identity, |path| {
            rehash_file(
                analyzer
                    .snapshot_caches()
                    .map(|cache| cache.artifact_digests.as_ref()),
                path,
                hash_artifact,
            )
        })
    })
}

fn discover_and_sample(
    config: &CSharpAnalyzerConfig,
    project: &dyn Project,
    cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    mut digest: impl FnMut(&Path) -> std::io::Result<ArtifactContent>,
) -> Sample {
    let capture = Capture::new();
    OBSERVATIONS.with(|slot| {
        let mut slot = slot.borrow_mut();
        let observed = slot.as_mut().expect("active capture");
        for name in [
            "NUGET_PACKAGES",
            "HOME",
            "DOTNET_ROOT",
            "PATH",
            "ProgramFiles",
            "ProgramFiles(x86)",
        ] {
            observed.probes.field("environment", name.as_bytes());
            observed
                .probes
                .field("value", format!("{:?}", std::env::var_os(name)).as_bytes());
        }
    });
    // SDK selection here replays the SDK recorded by restore in assets. It
    // does not execute dotnet, inspect PATH/global.json, or enumerate installed
    // SDK versions. Canonical selected SDK/pack outcomes and the XML consumed
    // below are the selection authority; environment probes stay transient.
    let discovery = super::external::resolve_csharp_semantic_pack_dependencies(
        config,
        project,
        &brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackLimits::default(),
        cancellation,
    );
    let mut observed = capture.finish();
    let mut reusable = observed.reusable
        && discovery.complete
        && !discovery.cancelled
        && discovery.incomplete_reason.is_none();
    observed.content.sort_unstable();
    observed.content.dedup();
    // Two different reads of one input cannot certify a single outcome.
    reusable &= !observed
        .content
        .windows(2)
        .any(|pair| pair[0].0 == pair[1].0);
    observed.selected.sort_unstable();
    observed.selected.dedup();
    let mut dependency = CanonicalHasher::new(b"bifrost-csharp-discovery-content");
    dependency.sequence("files", &observed.content, |hash, (path, digest)| {
        hash.field("path", path.as_os_str().as_encoded_bytes());
        hash.field("sha256", digest);
    });
    dependency.sequence("selection", &observed.selected, |hash, path| {
        hash.field("path", path.as_os_str().as_encoded_bytes());
    });
    dependency.field("complete", &[u8::from(discovery.complete)]);
    let mut diagnostics: Vec<_> = discovery
        .diagnostics
        .iter()
        .map(|d| format!("{d:?}"))
        .collect();
    diagnostics.sort();
    diagnostics.dedup();
    dependency.sequence("diagnostics", &diagnostics, |hash, d| {
        hash.field("diagnostic", d.as_bytes())
    });
    dependency.field(
        "suppressed",
        format!("{:?}", discovery.suppressed_diagnostics).as_bytes(),
    );
    // The selected dependency metadata includes pack version, target and
    // configuration. Probe history is deliberately excluded from this answer.
    dependency.sequence("selected", &discovery.dependencies, |hash, selected| {
        hash.field("id", selected.id.as_bytes());
        hash.field("evidence", format!("{:?}", selected.evidence).as_bytes());
        hash.field(
            "provenance",
            format!("{:?}", selected.provenance).as_bytes(),
        );
    });
    let dependency = StableDigest::from_array(dependency.finish());
    let mut artifact = CanonicalHasher::new(b"bifrost-csharp-artifact-content");
    // Bind selection and content in one answer too: independently replaying
    // the two facts must not combine samples from different restore outcomes.
    artifact.field("dependency", dependency.as_bytes());
    let mut carry = observed.probes;
    carry.field("dependency", dependency.as_bytes());
    let mut artifacts = Vec::new();
    for (path, module) in super::external::discovered_artifacts(&discovery) {
        if cancellation.is_some_and(|token| token.is_cancelled()) {
            reusable = false;
            break;
        }
        match canonicalize(&path) {
            Ok(canonical) => artifact.field("path", canonical.as_os_str().as_encoded_bytes()),
            Err(_) => reusable = false,
        }
        artifact.field("module", module.as_deref().unwrap_or("").as_bytes());
        match artifact_change_identity(&path) {
            Ok(identity) => carry.field("stat", format!("{identity:?}").as_bytes()),
            Err(_) => reusable = false,
        }
        match digest(&path) {
            Ok(content) => {
                artifact.field("sha256", &content.digest);
                artifacts.push(ArtifactInput {
                    path,
                    module,
                    digest: content.digest,
                    exact: content.exact,
                });
            }
            Err(_) => reusable = false,
        }
    }
    reusable &= !cancellation.is_some_and(|token| token.is_cancelled());
    let artifact = StableDigest::from_array(artifact.finish());
    carry.field("artifact", artifact.as_bytes());
    Sample {
        discovery,
        dependency,
        artifact,
        carry: carry.finish(),
        reusable,
        artifacts,
    }
}
