//! Inert external-input questions. Milestone 2 binds answers to a request.
use std::cell::Cell;
use std::path::Path;
use std::sync::Arc;

use super::project::ProjectViewStamp;

use super::canonical_hash::CanonicalHasher;
use super::config::{JvmAnalyzerConfig, JvmDependencyDiscoveryMode};

/// Change this when the JVM selection algorithm changes. It enters both
/// question digests; see `.agents/docs/cache-identity-levers.md`.
pub const JVM_SELECTION_CODE_DOMAIN: &[u8] = b"bifrost-jvm-external-selection-code:v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalSelectionQuestionKind {
    Dependencies,
    Jdk,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalSelectionQuestion {
    pub kind: ExternalSelectionQuestionKind,
    pub digest: [u8; 32],
    /// A question can be replayed only when all its inputs can be certified.
    pub uncertified: bool,
}

/// The project view changed during capture or before an answer could be handed out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionRefused {
    Stale,
    Cancelled,
}

/// One retry allowance shared by all selection fills in an asking operation.
#[derive(Default)]
pub struct SelectionRetry(Cell<u8>);

impl SelectionRetry {
    pub fn retry(&self) -> bool {
        if self.0.get() == 0 {
            self.0.set(1);
            true
        } else {
            false
        }
    }
}

/// A request-owned answer. The payload contains the selection's typed, byte-free
/// records; the producing authority owns its interpretation. No workspace-wide
/// index is retained by this type.
pub struct VerifiedSelection {
    pub question_digest: [u8; 32],
    pub answer_digest: [u8; 32],
    pub view_stamp: Option<ProjectViewStamp>,
    pub certified: bool,
    pub complete: bool,
    pub records: Arc<dyn std::any::Any + Send + Sync>,
}

impl std::fmt::Debug for VerifiedSelection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedSelection")
            .field("question_digest", &self.question_digest)
            .field("answer_digest", &self.answer_digest)
            .field("view_stamp", &self.view_stamp)
            .field("certified", &self.certified)
            .field("complete", &self.complete)
            .finish_non_exhaustive()
    }
}

/// The request-bound answer method is added with the Milestone 2 fill.
pub trait ExternalSelectionAuthority: Send + Sync {
    fn questions(&self) -> Vec<ExternalSelectionQuestion>;

    fn answer(
        &self,
        request: &super::outer_request::OuterRequest,
        question: &ExternalSelectionQuestion,
        retry: &SelectionRetry,
        cancellation: &crate::cancellation::CancellationToken,
    ) -> Result<Arc<VerifiedSelection>, SelectionRefused>;
}

/// Collect one current question per digest across language delegates.
pub fn questions(
    authorities: &[&dyn ExternalSelectionAuthority],
) -> Vec<ExternalSelectionQuestion> {
    let mut seen = std::collections::HashSet::new();
    authorities
        .iter()
        .flat_map(|authority| authority.questions())
        .filter(|question| seen.insert(question.digest))
        .collect()
}

fn path(hash: &mut CanonicalHasher, value: &Path) {
    hash.value(value.as_os_str().as_encoded_bytes());
}
fn paths(hash: &mut CanonicalHasher, name: &str, values: &[std::path::PathBuf]) {
    hash.sequence(name, values, |hash, value| path(hash, value));
}
fn boolean(hash: &mut CanonicalHasher, value: bool) {
    hash.value(&[u8::from(value)]);
}

impl ExternalSelectionQuestion {
    pub fn for_jvm(config: &JvmAnalyzerConfig) -> Vec<Self> {
        let mut dependencies =
            CanonicalHasher::new(b"bifrost-external-selection-question:dependencies:v1");
        dependencies.value(JVM_SELECTION_CODE_DOMAIN);
        let external = &config.external_dependencies;
        dependencies.sequence(
            "artifact_paths",
            &external.artifact_paths,
            |hash, artifact| {
                path(hash, &artifact.artifact_path);
                boolean(hash, artifact.source_artifact_path.is_some());
                if let Some(source) = &artifact.source_artifact_path {
                    path(hash, source);
                }
                boolean(hash, artifact.coordinate.is_some());
                if let Some(coordinate) = &artifact.coordinate {
                    hash.value(coordinate.group_id.as_bytes());
                    hash.value(coordinate.artifact_id.as_bytes());
                    hash.value(coordinate.version.as_bytes());
                }
                hash.value(&[artifact.origin as u8]);
            },
        );
        dependencies.sequence("coordinates", &external.coordinates, |hash, coordinate| {
            hash.value(coordinate.group_id.as_bytes());
            hash.value(coordinate.artifact_id.as_bytes());
            hash.value(coordinate.version.as_bytes());
        });
        paths(
            &mut dependencies,
            "repository_roots",
            &external.repository_roots,
        );
        paths(
            &mut dependencies,
            "gradle_cache_roots",
            &external.gradle_cache_roots,
        );
        let discovery = &config.dependency_discovery;
        dependencies.value(&[discovery.mode as u8]);
        boolean(&mut dependencies, discovery.maven_executable.is_some());
        if let Some(executable) = &discovery.maven_executable {
            path(&mut dependencies, executable);
        }
        boolean(&mut dependencies, discovery.gradle_executable.is_some());
        if let Some(executable) = &discovery.gradle_executable {
            path(&mut dependencies, executable);
        }
        dependencies.value(&discovery.timeout.as_secs().to_be_bytes());
        dependencies.value(&discovery.timeout.subsec_nanos().to_be_bytes());
        // Logical defaults, not the environment values resolved by a request.
        if external.repository_roots.is_empty() {
            dependencies.value(b"HOME|USERPROFILE:.m2/repository");
        }
        if external.gradle_cache_roots.is_empty() {
            dependencies.value(b"GRADLE_USER_HOME:caches/modules-2/files-2.1|HOME|USERPROFILE:.gradle/caches/modules-2/files-2.1");
        }
        let uncertified = discovery.mode == JvmDependencyDiscoveryMode::OfflineBuildTools
            || !external.artifact_paths.is_empty()
            || external
                .repository_roots
                .iter()
                .any(|root| root.is_relative());
        let mut jdk = CanonicalHasher::new(b"bifrost-external-selection-question:jdk:v1");
        jdk.value(JVM_SELECTION_CODE_DOMAIN);
        let standard = &config.standard_library_discovery;
        paths(&mut jdk, "jdk_homes", &standard.jdk_homes);
        jdk.sequence(
            "source_toolchains",
            &standard.source_toolchains,
            |hash, binding| {
                path(hash, binding.source_root());
                path(hash, binding.jdk_home());
            },
        );
        boolean(&mut jdk, standard.discover_java_home);
        if standard.discover_java_home {
            jdk.value(b"JAVA_HOME");
        }
        vec![
            Self {
                kind: ExternalSelectionQuestionKind::Dependencies,
                digest: dependencies.finish(),
                uncertified,
            },
            Self {
                kind: ExternalSelectionQuestionKind::Jdk,
                digest: jdk.finish(),
                uncertified: false,
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::config::{JvmExternalArtifact, JvmMavenCoordinate};
    use std::path::PathBuf;

    struct Java(JvmAnalyzerConfig);
    impl ExternalSelectionAuthority for Java {
        fn answer(
            &self,
            _request: &super::super::outer_request::OuterRequest,
            _question: &ExternalSelectionQuestion,
            _retry: &SelectionRetry,
            _cancellation: &crate::cancellation::CancellationToken,
        ) -> Result<Arc<VerifiedSelection>, SelectionRefused> {
            unreachable!("question factory test has no answer")
        }
        fn questions(&self) -> Vec<ExternalSelectionQuestion> {
            ExternalSelectionQuestion::for_jvm(&self.0)
        }
    }

    #[test]
    fn equal_jvm_configs_deduplicate_and_ignore_environment() {
        let java = Java(JvmAnalyzerConfig::default());
        let kotlin = Java(java.0.clone());
        let scala = Java(java.0.clone());
        let three: [&dyn ExternalSelectionAuthority; 3] = [&java, &kotlin, &scala];
        assert_eq!(questions(&three).len(), 2);
        // The factory takes configuration only. A checkout root or environment
        // value cannot enter without becoming a named argument.
        let before = questions(&three);
        let after = ExternalSelectionQuestion::for_jvm(&JvmAnalyzerConfig::default());
        assert_eq!(before, after);
    }

    #[test]
    fn unsupported_dependency_inputs_are_uncertified() {
        let base = JvmAnalyzerConfig::default();
        let mut cases = Vec::new();
        let mut build_tool = base.clone();
        build_tool.dependency_discovery.mode = JvmDependencyDiscoveryMode::OfflineBuildTools;
        cases.push(build_tool);
        let mut explicit = base.clone();
        explicit
            .external_dependencies
            .artifact_paths
            .push(JvmExternalArtifact {
                artifact_path: PathBuf::from("/tmp/a.jar"),
                ..Default::default()
            });
        cases.push(explicit);
        let mut relative_root = base.clone();
        relative_root
            .external_dependencies
            .repository_roots
            .push(PathBuf::from("repo"));
        cases.push(relative_root);
        let mut gradle = base.clone();
        gradle
            .external_dependencies
            .gradle_cache_roots
            .push(PathBuf::from("/tmp/gradle"));
        gradle
            .external_dependencies
            .coordinates
            .push(JvmMavenCoordinate::new("g", "a", "1"));
        assert!(
            !ExternalSelectionQuestion::for_jvm(&gradle)[0].uncertified,
            "Gradle listing is an answer-time property"
        );
        for config in cases {
            assert!(
                ExternalSelectionQuestion::for_jvm(&config)[0].uncertified,
                "{config:?}"
            );
        }
    }
}
