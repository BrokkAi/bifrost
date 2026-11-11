//! Inert request-local verification of external dependency selection.
use std::sync::Arc;

use brokk_bifrost_core::analyzer::config::{JvmAnalyzerConfig, JvmDependencyDiscoveryMode};
use brokk_bifrost_core::analyzer::external_selection::{
    ExternalSelectionQuestion, ExternalSelectionQuestionKind, SelectionRefused, SelectionRetry,
    VerifiedSelection,
};
use brokk_bifrost_core::analyzer::project::Project;
use brokk_bifrost_core::content_digest::ContentDigestCache;

use super::external::{ExternalProbeOperation, JvmExternalDeclarationIndex};
use super::selected_inputs::capture;

#[allow(dead_code)] // No product caller until P2.
pub(crate) fn verify_selection(
    config: &JvmAnalyzerConfig,
    project: &dyn Project,
    digests: &ContentDigestCache,
    question: &ExternalSelectionQuestion,
    retry: &SelectionRetry,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> Result<VerifiedSelection, SelectionRefused> {
    match question.kind {
        ExternalSelectionQuestionKind::Dependencies => {
            verify_dependencies_with(config, project, question, retry, || {})
        }
        ExternalSelectionQuestionKind::Jdk => {
            verify_jdk(config, project, digests, question, retry, cancellation)
        }
    }
}

/// The JDK question reads only JDK discovery, never workspace manifests,
/// dependency artifacts or build tools, so it needs no capture. Its artifacts
/// are pinned to content digests streamed from the files (#9559), which no
/// view stamp covers, so a complete selection whose every artifact is pinned is
/// certified: bytes replaced under the same metadata change a pin. A selection
/// with no artifact (no `jmods` directory, no `src.zip`, each probe recorded)
/// is a certified negative answer; an unpinned artifact or an unreadable
/// member leaves the answer uncertified or incomplete.
fn verify_jdk(
    config: &JvmAnalyzerConfig,
    project: &dyn Project,
    digests: &ContentDigestCache,
    question: &ExternalSelectionQuestion,
    retry: &SelectionRetry,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> Result<VerifiedSelection, SelectionRefused> {
    loop {
        let stamp = project.view_stamp();
        let jdk =
            JvmExternalDeclarationIndex::select_jdk(config, project, digests, Some(cancellation))
                .map_err(|_| SelectionRefused::Cancelled)?;
        if project.view_stamp() != stamp {
            if retry.retry() {
                continue;
            }
            return Err(SelectionRefused::Stale);
        }
        let complete = jdk.inputs.complete;
        let certified = complete && stamp.is_some() && jdk.every_artifact_pinned();
        return Ok(VerifiedSelection {
            question_digest: question.digest,
            answer_digest: jdk.answer_digest(complete, certified),
            certified,
            view_stamp: stamp,
            complete,
            records: Arc::new(jdk),
        });
    }
}

fn verify_dependencies_with(
    config: &JvmAnalyzerConfig,
    project: &dyn Project,
    question: &ExternalSelectionQuestion,
    retry: &SelectionRetry,
    before_validation: impl Fn(),
) -> Result<VerifiedSelection, SelectionRefused> {
    loop {
        // Filling a cold listing advances its epoch, so the listing is filled
        // before the stamp is sampled; otherwise every cold or refreshed
        // listing would spend the retry. The capture then reads that same
        // listing unless an event invalidates it, which moves the stamp.
        let listed = project.all_files_shared();
        let stamp = project.view_stamp();
        let captured = listed.and_then(|_| capture(project));
        let (selection, valid) = match captured {
            Ok(captured) => {
                let selection = JvmExternalDeclarationIndex::select_external_inventory::<
                    std::convert::Infallible,
                >(config, project, &captured, |_| Ok(()))
                .expect("infallible artifact visitor");
                before_validation();
                let validation = captured.validate(project);
                // A file set or an absence that the authoritative walk
                // contradicts came from a cached listing that missed a file
                // change, and the retry would capture the same stale set. So
                // drop it first, as the missed event would have. That
                // advances the view stamp, and the retry refills the listing
                // and captures under the new one.
                if matches!(
                    validation,
                    Err(super::selected_inputs::CaptureDrift::FileSet(_)
                        | super::selected_inputs::CaptureDrift::Absence(_))
                ) {
                    project.invalidate_cached_file_listing();
                }
                (Some(selection), validation.is_ok())
            }
            Err(_) => (None, true),
        };
        // G1 follows validation even when validation failed.
        let after = project.view_stamp();
        if !valid || after != stamp {
            if retry.retry() {
                continue;
            }
            return Err(SelectionRefused::Stale);
        }
        let complete = selection
            .as_ref()
            .is_some_and(|selection| selection.completeness.is_complete());
        let certified = complete
            && !question.uncertified
            && config.dependency_discovery.mode != JvmDependencyDiscoveryMode::OfflineBuildTools
            && stamp.is_some()
            // Dependency resolution lists directories only in the Gradle cache,
            // and that listing makes the selection uncertified. Every listing
            // counts: the probes sit under the canonical cache root, which need
            // not share a prefix with the configured root.
            && selection.as_ref().is_some_and(|selection| {
                !selection
                    .inputs
                    .resolution_steps
                    .iter()
                    .any(|probe| matches!(probe.operation, ExternalProbeOperation::List))
            });
        return Ok(VerifiedSelection {
            question_digest: question.digest,
            answer_digest: match &selection {
                Some(selection) => selection.answer_digest(complete, certified),
                None => {
                    use crate::analyzer::jvm::selection_codec as codec;
                    use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
                    let mut hash = CanonicalHasher::new(codec::DEPENDENCIES_ANSWER_DOMAIN);
                    codec::text(&mut hash, "capture", "failed");
                    codec::flag(&mut hash, "complete", complete);
                    codec::flag(&mut hash, "certified", certified);
                    hash.finish()
                }
            },
            view_stamp: stamp,
            certified,
            complete,
            records: Arc::new(selection),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::super::external::test_digests;
    use super::*;
    use brokk_bifrost_core::analyzer::project::{FilesystemProject, WorkspaceFileListingCache};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn manifest_drift_uses_one_retry_then_returns_stale() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let manifest = root.join("pom.xml");
        std::fs::write(&manifest, "<project/>").unwrap();
        let listing = Arc::new(WorkspaceFileListingCache::new(root.clone()));
        let project = FilesystemProject::with_cached_listing(root, listing).unwrap();
        let config = JvmAnalyzerConfig::default();
        let question = ExternalSelectionQuestion::for_jvm(&config).remove(0);
        let attempts = AtomicUsize::new(0);
        let retry = SelectionRetry::default();
        let answer = verify_dependencies_with(&config, &project, &question, &retry, || {
            if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                std::fs::write(&manifest, "<project><name>changed</name></project>").unwrap();
            }
        });
        assert!(answer.is_ok());
        assert_eq!(attempts.load(Ordering::SeqCst), 2);

        let attempts = AtomicUsize::new(0);
        let retry = SelectionRetry::default();
        let answer = verify_dependencies_with(&config, &project, &question, &retry, || {
            let attempt = attempts.fetch_add(1, Ordering::SeqCst);
            std::fs::write(
                &manifest,
                format!("<project><name>{attempt}</name></project>"),
            )
            .unwrap();
        });
        assert!(matches!(answer, Err(SelectionRefused::Stale)));
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon("#9559: cancelled JDK selection was filled and memoized")]
    fn cancelled_jdk_fill_is_not_memoized() {
        use brokk_bifrost_core::analyzer::outer_request::OuterRequest;
        use brokk_bifrost_core::cancellation::CancellationToken;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let listing = Arc::new(WorkspaceFileListingCache::new(root.clone()));
        let project = FilesystemProject::with_cached_listing(root, listing).unwrap();
        let config = JvmAnalyzerConfig::default();
        let question = ExternalSelectionQuestion::for_jvm(&config)
            .into_iter()
            .find(|q| q.kind == ExternalSelectionQuestionKind::Jdk)
            .unwrap();
        let request = OuterRequest::new();
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let digests = test_digests();
        let mut fills = 0;
        for token in [&cancelled, &CancellationToken::new()] {
            let answer = request.external_selection(&project, question.digest, || {
                fills += 1;
                verify_selection(
                    &config,
                    &project,
                    &digests,
                    &question,
                    &SelectionRetry::default(),
                    token,
                )
            });
            if token.is_cancelled() {
                assert!(matches!(answer, Err(SelectionRefused::Cancelled)));
            } else {
                assert!(answer.is_ok());
            }
        }
        assert_eq!(fills, 2);
    }

    /// A cached listing that missed a new file, nested or at a conventional
    /// manifest name, is refreshed before the retry, so the one retry sees
    /// the file instead of the same stale set.
    #[test]
    fn a_stale_cached_listing_is_refreshed_before_the_retry() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("pom.xml"), "<project/>").unwrap();
        let listing = Arc::new(WorkspaceFileListingCache::new(root.clone()));
        let project = FilesystemProject::with_cached_listing(root.clone(), listing).unwrap();
        let config = JvmAnalyzerConfig::default();
        let question = ExternalSelectionQuestion::for_jvm(&config).remove(0);
        verify_selection(
            &config,
            &project,
            &test_digests(),
            &question,
            &SelectionRetry::default(),
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        )
        .unwrap();
        for created in ["module/pom.xml", "settings.gradle"] {
            let path = root.join(created);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "").unwrap();
            let answer = verify_selection(
                &config,
                &project,
                &test_digests(),
                &question,
                &SelectionRetry::default(),
                &brokk_bifrost_core::cancellation::CancellationToken::default(),
            );
            assert!(answer.is_ok(), "{created}");
        }
    }

    #[test]
    fn a_maven_selection_is_certified_and_a_gradle_cache_listing_is_not() {
        use brokk_bifrost_core::analyzer::config::JvmMavenCoordinate;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let workspace = root.join("workspace");
        let maven = root.join("maven");
        let gradle = root.join("gradle");
        std::fs::create_dir_all(&workspace).unwrap();
        let jar = maven.join("org/example/lib/1.0/lib-1.0.jar");
        std::fs::create_dir_all(jar.parent().unwrap()).unwrap();
        std::fs::write(&jar, b"maven bytes").unwrap();
        let cached = gradle.join("org.example/other/1.0/abc123/other-1.0.jar");
        std::fs::create_dir_all(cached.parent().unwrap()).unwrap();
        std::fs::write(&cached, b"gradle bytes").unwrap();
        let listing = Arc::new(WorkspaceFileListingCache::new(workspace.clone()));
        let project = FilesystemProject::with_cached_listing(workspace, listing).unwrap();
        let verify = |coordinate: JvmMavenCoordinate, gradle_root: std::path::PathBuf| {
            let mut config = JvmAnalyzerConfig::default();
            config.dependency_discovery.mode = JvmDependencyDiscoveryMode::Disabled;
            config.external_dependencies.coordinates = vec![coordinate];
            config.external_dependencies.repository_roots = vec![maven.clone()];
            config.external_dependencies.gradle_cache_roots = vec![gradle_root];
            let question = ExternalSelectionQuestion::for_jvm(&config).remove(0);
            assert_eq!(question.kind, ExternalSelectionQuestionKind::Dependencies);
            verify_selection(
                &config,
                &project,
                &test_digests(),
                &question,
                &SelectionRetry::default(),
                &brokk_bifrost_core::cancellation::CancellationToken::default(),
            )
            .unwrap()
        };

        let found = verify(
            JvmMavenCoordinate::new("org.example", "lib", "1.0"),
            gradle.clone(),
        );
        assert!(found.complete && found.certified, "{found:?}");
        let listed = verify(
            JvmMavenCoordinate::new("org.example", "other", "1.0"),
            gradle.clone(),
        );
        assert!(listed.complete && !listed.certified, "{listed:?}");
        // The listing is found under the canonical cache root even when the
        // configured root is a different spelling of it.
        #[cfg(unix)]
        {
            let alias = root.join("gradle-alias");
            std::os::unix::fs::symlink(&gradle, &alias).unwrap();
            let listed = verify(
                JvmMavenCoordinate::new("org.example", "other", "1.0"),
                alias,
            );
            assert!(listed.complete && !listed.certified, "{listed:?}");
        }
    }

    #[test]
    fn an_inventory_past_the_artifact_cap_is_incomplete() {
        use brokk_bifrost_core::analyzer::config::JvmMavenCoordinate;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let workspace = root.join("workspace");
        let maven = root.join("maven");
        std::fs::create_dir_all(&workspace).unwrap();
        let coordinates: Vec<_> = (0..=super::super::external::MAX_INDEX_ARTIFACTS)
            .map(|index| {
                let name = format!("lib{index}");
                let jar = maven.join(format!("org/example/{name}/1.0/{name}-1.0.jar"));
                std::fs::create_dir_all(jar.parent().unwrap()).unwrap();
                std::fs::write(&jar, name.as_bytes()).unwrap();
                JvmMavenCoordinate::new("org.example", &name, "1.0")
            })
            .collect();
        let listing = Arc::new(WorkspaceFileListingCache::new(workspace.clone()));
        let project = FilesystemProject::with_cached_listing(workspace, listing).unwrap();
        let mut config = JvmAnalyzerConfig::default();
        config.dependency_discovery.mode = JvmDependencyDiscoveryMode::Disabled;
        config.external_dependencies.repository_roots = vec![maven];
        config.external_dependencies.gradle_cache_roots = vec![root.join("gradle")];
        let verify = |config: &JvmAnalyzerConfig| {
            let question = ExternalSelectionQuestion::for_jvm(config).remove(0);
            verify_selection(
                config,
                &project,
                &test_digests(),
                &question,
                &SelectionRetry::default(),
                &brokk_bifrost_core::cancellation::CancellationToken::default(),
            )
            .unwrap()
        };
        config.external_dependencies.coordinates =
            coordinates[..super::super::external::MAX_INDEX_ARTIFACTS].to_vec();
        let at_cap = verify(&config);
        assert!(at_cap.complete && at_cap.certified, "{at_cap:?}");
        config.external_dependencies.coordinates = coordinates;
        let past_cap = verify(&config);
        assert!(!past_cap.complete && !past_cap.certified, "{past_cap:?}");
    }

    #[test]
    fn a_manifest_discovery_cannot_read_leaves_the_selection_uncertified() {
        let verify = |pom: &str, question: usize| {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().canonicalize().unwrap();
            std::fs::write(root.join("pom.xml"), pom).unwrap();
            let listing = Arc::new(WorkspaceFileListingCache::new(root.clone()));
            let project = FilesystemProject::with_cached_listing(root.clone(), listing).unwrap();
            let mut config = JvmAnalyzerConfig::default();
            config.external_dependencies.repository_roots = vec![root.join("repository")];
            config.external_dependencies.gradle_cache_roots = vec![root.join("gradle")];
            config.standard_library_discovery.discover_java_home = false;
            let question = ExternalSelectionQuestion::for_jvm(&config).remove(question);
            verify_selection(
                &config,
                &project,
                &test_digests(),
                &question,
                &SelectionRetry::default(),
                &brokk_bifrost_core::cancellation::CancellationToken::default(),
            )
            .unwrap()
        };
        let complete = verify("<project></project>", 0);
        assert!(complete.complete && complete.certified, "{complete:?}");
        for partial in [
            "<project><dependencies>",
            "<settings/>",
            "<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId></dependency></dependencies></project>",
        ] {
            let answer = verify(partial, 0);
            assert!(
                !answer.complete && !answer.certified,
                "{partial}: {answer:?}"
            );
            // The JDK question is answered from JDK discovery alone; with no
            // JDK configured it is a certified negative answer.
            let jdk = verify(partial, 1);
            assert!(jdk.complete && jdk.certified, "{partial}: {jdk:?}");
        }
    }

    /// The two questions answer from disjoint inputs: a JDK home that fails
    /// to read leaves the JDK answer incomplete and the dependency answer
    /// complete.
    #[test]
    fn a_failed_jdk_probe_leaves_only_the_jdk_answer_incomplete() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("pom.xml"), "<project></project>").unwrap();
        let listing = Arc::new(WorkspaceFileListingCache::new(root.clone()));
        let project = FilesystemProject::with_cached_listing(root.clone(), listing).unwrap();
        let mut config = JvmAnalyzerConfig::default();
        config.external_dependencies.repository_roots = vec![root.join("repository")];
        config.external_dependencies.gradle_cache_roots = vec![root.join("gradle")];
        config.standard_library_discovery.discover_java_home = false;
        config.standard_library_discovery.jdk_homes = vec![root.join("missing-jdk")];
        let questions = ExternalSelectionQuestion::for_jvm(&config);
        let answers: Vec<_> = questions
            .iter()
            .map(|question| {
                verify_selection(
                    &config,
                    &project,
                    &test_digests(),
                    question,
                    &SelectionRetry::default(),
                    &brokk_bifrost_core::cancellation::CancellationToken::default(),
                )
                .unwrap()
            })
            .collect();
        assert_eq!(
            questions[0].kind,
            ExternalSelectionQuestionKind::Dependencies
        );
        assert!(
            answers[0].complete && answers[0].certified,
            "{:?}",
            answers[0]
        );
        assert_eq!(questions[1].kind, ExternalSelectionQuestionKind::Jdk);
        assert!(
            !answers[1].complete && !answers[1].certified,
            "{:?}",
            answers[1]
        );
    }

    /// A probe that fails for a reason other than absence leaves the answer
    /// incomplete even when resolution goes on to find what it needs: a
    /// repository that cannot be read before the one holding the jar, or a
    /// JDK source archive that cannot be inspected beside a usable home.
    /// A path with a NUL byte fails as invalid input on every platform, and
    /// a path below a regular file fails with "not a directory" on Unix;
    /// neither needs permission changes. Windows reports the path below a
    /// regular file as not found, so there the JDK answer stays complete.
    #[test]
    fn an_unreadable_probe_leaves_the_answer_incomplete() {
        use brokk_bifrost_core::analyzer::config::JvmMavenCoordinate;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        let blocked = root.join("blocked\0repository");
        let maven = root.join("maven");
        let jar = maven.join("org/example/lib/1.0/lib-1.0.jar");
        std::fs::create_dir_all(jar.parent().unwrap()).unwrap();
        std::fs::write(&jar, b"maven bytes").unwrap();
        let listing = Arc::new(WorkspaceFileListingCache::new(workspace.clone()));
        let project = FilesystemProject::with_cached_listing(workspace, listing).unwrap();
        let verify = |repositories: Vec<std::path::PathBuf>, jdk_lib_is_file: bool| {
            let home = root.join(format!("jdk-{jdk_lib_is_file}"));
            std::fs::create_dir_all(&home).unwrap();
            std::fs::write(home.join("release"), "JAVA_VERSION=\"21.0.8\"\n").unwrap();
            if jdk_lib_is_file {
                std::fs::write(home.join("lib"), b"not a directory").unwrap();
            } else {
                std::fs::create_dir_all(home.join("lib")).unwrap();
            }
            let mut config = JvmAnalyzerConfig::default();
            config.dependency_discovery.mode = JvmDependencyDiscoveryMode::Disabled;
            config.external_dependencies.coordinates =
                vec![JvmMavenCoordinate::new("org.example", "lib", "1.0")];
            config.external_dependencies.repository_roots = repositories;
            config.external_dependencies.gradle_cache_roots = vec![root.join("gradle")];
            config.standard_library_discovery.discover_java_home = false;
            config.standard_library_discovery.jdk_homes = vec![home];
            ExternalSelectionQuestion::for_jvm(&config)
                .iter()
                .map(|question| {
                    verify_selection(
                        &config,
                        &project,
                        &test_digests(),
                        question,
                        &SelectionRetry::default(),
                        &brokk_bifrost_core::cancellation::CancellationToken::default(),
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>()
        };
        let readable = verify(vec![maven.clone()], false);
        assert!(
            readable.iter().all(|answer| answer.complete),
            "{readable:?}"
        );
        let unreadable = verify(vec![blocked, maven], true);
        let [dependencies, jdk] = &unreadable[..] else {
            panic!("one dependency and one JDK answer: {unreadable:?}");
        };
        assert!(
            !dependencies.complete && !dependencies.certified,
            "{dependencies:?}"
        );
        assert_eq!(jdk.complete, cfg!(windows), "{jdk:?}");
        assert_eq!(jdk.certified, cfg!(windows), "{jdk:?}");
    }

    /// The JDK answer records what was selected, not only which paths were
    /// probed: the same home with a different `release` gives a different
    /// answer. A home with no `jmods` directory and no source archive has
    /// nothing to pin, so its answer is a certified negative one; creating
    /// the directory later changes the answer.
    #[test]
    fn a_jdk_answer_records_the_selected_jdk() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        let home = root.join("jdk");
        std::fs::create_dir_all(home.join("lib")).unwrap();
        let listing = Arc::new(WorkspaceFileListingCache::new(workspace.clone()));
        let project = FilesystemProject::with_cached_listing(workspace, listing).unwrap();
        let mut config = JvmAnalyzerConfig::default();
        config.standard_library_discovery.discover_java_home = false;
        config.standard_library_discovery.jdk_homes = vec![home.clone()];
        let question = ExternalSelectionQuestion::for_jvm(&config).remove(1);
        let selected = |version: &str| {
            std::fs::write(
                home.join("release"),
                format!("JAVA_VERSION=\"{version}\"\n"),
            )
            .unwrap();
            let answer = verify_selection(
                &config,
                &project,
                &test_digests(),
                &question,
                &SelectionRetry::default(),
                &brokk_bifrost_core::cancellation::CancellationToken::default(),
            )
            .unwrap();
            assert!(answer.complete && answer.certified, "{answer:?}");
            let jdk = answer
                .records
                .downcast_ref::<super::super::external::SelectedJdk>()
                .expect("the JDK question answers with the selected JDK");
            (
                jdk.dependencies
                    .iter()
                    .map(|dependency| dependency.id.clone())
                    .collect::<Vec<_>>(),
                answer.answer_digest,
            )
        };
        let first = selected("21.0.8");
        assert_eq!(vec!["jdk:21.0.8".to_owned()], first.0);
        assert_eq!(first, selected("21.0.8"));
        let changed = selected("21.0.9");
        assert_eq!(vec!["jdk:21.0.9".to_owned()], changed.0);
        assert_ne!(first.1, changed.1);
        std::fs::create_dir_all(home.join("jmods")).unwrap();
        std::fs::write(home.join("jmods/java.base.jmod"), b"jmod bytes").unwrap();
        let with_jmods = selected("21.0.9");
        assert_ne!(changed.1, with_jmods.1);
    }

    /// Bytes replaced under the same metadata change the JDK answer, because
    /// the artifacts are pinned to digests streamed from the files, and the
    /// answer is certified because every artifact is pinned (#9559).
    #[test]
    fn a_pinned_jdk_answer_follows_the_bytes_and_is_certified() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        let home = root.join("jdk");
        std::fs::create_dir_all(home.join("jmods")).unwrap();
        std::fs::write(home.join("release"), "JAVA_VERSION=\"21.0.8\"\n").unwrap();
        let jmod = home.join("jmods/java.base.jmod");
        std::fs::write(&jmod, b"first bytes").unwrap();
        let listing = Arc::new(WorkspaceFileListingCache::new(workspace.clone()));
        let project = FilesystemProject::with_cached_listing(workspace, listing).unwrap();
        let mut config = JvmAnalyzerConfig::default();
        config.standard_library_discovery.discover_java_home = false;
        config.standard_library_discovery.jdk_homes = vec![home];
        let question = ExternalSelectionQuestion::for_jvm(&config).remove(1);
        let digests = test_digests();
        let select = || {
            let answer = verify_selection(
                &config,
                &project,
                &digests,
                &question,
                &SelectionRetry::default(),
                &brokk_bifrost_core::cancellation::CancellationToken::default(),
            )
            .unwrap();
            assert!(answer.complete && answer.certified, "{answer:?}");
            answer.answer_digest
        };
        let first = select();
        let modified = std::fs::metadata(&jmod).unwrap().modified().unwrap();
        std::fs::write(&jmod, b"other bytes").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&jmod)
            .unwrap()
            .set_modified(modified)
            .unwrap();
        assert_ne!(first, select());
    }

    /// A view that cannot stamp certifies nothing: both answers come back
    /// complete but uncertified, and the request map accepts them. The JDK is
    /// fully pinned here, so only the missing stamp refuses certification.
    #[test]
    fn an_unstamped_view_gives_uncertified_answers_without_panicking() {
        use brokk_bifrost_core::analyzer::outer_request::OuterRequest;
        use brokk_bifrost_core::analyzer::project::TestProject;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let home = root.join("jdk");
        std::fs::create_dir_all(home.join("jmods")).unwrap();
        std::fs::write(home.join("release"), "JAVA_VERSION=\"21.0.8\"\n").unwrap();
        std::fs::write(home.join("jmods/java.base.jmod"), b"jmod bytes").unwrap();
        let project = TestProject::new(&root, brokk_bifrost_core::analyzer::model::Language::Java);
        assert!(project.view_stamp().is_none());
        let mut config = JvmAnalyzerConfig::default();
        config.dependency_discovery.mode = JvmDependencyDiscoveryMode::Disabled;
        config.standard_library_discovery.discover_java_home = false;
        config.standard_library_discovery.jdk_homes = vec![home];
        let request = OuterRequest::new();
        let digests = test_digests();
        for question in ExternalSelectionQuestion::for_jvm(&config) {
            let answer = request
                .external_selection(&project, question.digest, || {
                    verify_selection(
                        &config,
                        &project,
                        &digests,
                        &question,
                        &SelectionRetry::default(),
                        &brokk_bifrost_core::cancellation::CancellationToken::default(),
                    )
                })
                .unwrap();
            assert!(
                answer.complete && !answer.certified && answer.view_stamp.is_none(),
                "{:?}: {answer:?}",
                question.kind
            );
        }
    }

    #[test]
    fn retry_allowance_is_shared_by_fills() {
        let retry = SelectionRetry::default();
        assert!(retry.retry());
        // A second fill receives the same operation-owned allowance.
        assert!(!retry.retry());
    }
}
