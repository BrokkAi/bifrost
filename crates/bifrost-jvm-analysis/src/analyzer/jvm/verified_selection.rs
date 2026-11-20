//! Request verification of external dependency selection.
use std::sync::Arc;

use brokk_bifrost_core::analyzer::config::{JvmAnalyzerConfig, JvmDependencyDiscoveryMode};
use brokk_bifrost_core::analyzer::external_selection::{
    ExternalSelectionQuestion, ExternalSelectionQuestionKind, SelectionRefused, SelectionRetry,
    VerifiedSelection,
};
use brokk_bifrost_core::analyzer::project::Project;
use brokk_bifrost_core::content_digest::ContentDigestCache;

use super::dependency_discovery::DiscoveryInputs;
use super::external::{
    ExternalProbeOperation, ExternalSelectionFailure, JvmExternalDeclarationIndex,
};
use super::selected_inputs::capture_listing;

#[cfg(test)]
pub(crate) fn verify_selection(
    config: &JvmAnalyzerConfig,
    project: &dyn Project,
    digests: &ContentDigestCache,
    question: &ExternalSelectionQuestion,
    retry: &SelectionRetry,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> Result<VerifiedSelection, SelectionRefused> {
    verify_selection_with(
        config,
        project,
        digests,
        &Default::default(),
        question,
        retry,
        cancellation,
    )
}

pub(crate) fn verify_selection_with(
    config: &JvmAnalyzerConfig,
    project: &dyn Project,
    digests: &ContentDigestCache,
    verifications: &brokk_bifrost_core::analyzer::external_selection::ToolchainVerifications,
    question: &ExternalSelectionQuestion,
    retry: &SelectionRetry,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> Result<VerifiedSelection, SelectionRefused> {
    match question.kind {
        ExternalSelectionQuestionKind::RustToolchain => Err(SelectionRefused::Stale),
        ExternalSelectionQuestionKind::Dependencies => {
            verify_dependencies_with_evidence(config, project, question, retry, || {})
        }
        ExternalSelectionQuestionKind::Jdk => verify_jdk(
            config,
            project,
            digests,
            verifications,
            question,
            retry,
            cancellation,
        ),
    }
}

/// Content is verified at activation, refresh or a detected change. A record
/// may skip hashing only when its identities match and were non-racy at its
/// recorded observation time. Same-tick rewrites cannot age into trust at a
/// later lookup. Missing or racy metadata requires content verification.
fn verify_jdk(
    config: &JvmAnalyzerConfig,
    project: &dyn Project,
    digests: &ContentDigestCache,
    verifications: &brokk_bifrost_core::analyzer::external_selection::ToolchainVerifications,
    question: &ExternalSelectionQuestion,
    retry: &SelectionRetry,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> Result<VerifiedSelection, SelectionRefused> {
    loop {
        let stamp = project.view_stamp();
        use super::external::{VerifiedJdkRecord, observe_jdk, verify_jdk_record};
        let observed = observe_jdk(config, project.root());
        let cached = verifications.get::<VerifiedJdkRecord>(&question.digest);
        let same_metadata = cached
            .as_ref()
            .is_some_and(|record| observed.as_ref() == Some(&record.observation));
        let matches = |record: &VerifiedJdkRecord| record.matches(&observed);
        let jdk = if let Some(record) = cached.filter(|record| matches(record)) {
            record.selected.clone()
        } else {
            // A matching racy record needs a content read on this request.
            // Background refresh would publish another racy record and keep
            // refusing answers, indefinitely for future-dated files.
            if !same_metadata && verifications.signal_stale() {
                return Err(SelectionRefused::Stale);
            }
            let _guard = verifications.lock_verification();
            let current = observe_jdk(config, project.root());
            let record = verifications.get::<VerifiedJdkRecord>(&question.digest);
            if let Some(record) = record.filter(|record| record.matches(&current)) {
                record.selected.clone()
            } else {
                let verification = verify_jdk_record(
                    config,
                    project,
                    digests,
                    verifications,
                    &Default::default(),
                    Some(cancellation),
                )
                .map_err(|_| SelectionRefused::Cancelled)?;
                // An incomplete selection is not recorded, so the pinned
                // selection itself is the answer, if the files held still.
                let after = observe_jdk(config, project.root());
                if verification
                    .observation
                    .is_none_or(|observation| after.as_ref() != Some(&observation))
                {
                    return Err(SelectionRefused::Stale);
                }
                verification.selected
            }
        };
        if project.view_stamp() != stamp {
            if retry.retry() {
                continue;
            }
            return Err(SelectionRefused::Stale);
        }
        let complete = jdk.inputs.complete;
        let verified = stamp.is_some() && jdk.every_artifact_pinned();
        let certified = complete && verified;
        return Ok(VerifiedSelection {
            question_digest: question.digest,
            answer_digest: jdk.answer_digest(complete, certified),
            verified,
            certified,
            view_stamp: stamp,
            complete,
            // An incomplete JDK names no failure that is fixed for unchanged inputs.
            only_replayable_gaps: false,
            records: jdk,
        });
    }
}

/// Whether a complete dependency selection can be certified, apart from a view
/// stamp: its question is certifiable, it ran no build tool, and it listed no
/// directory.
fn dependencies_certifiable(
    config: &JvmAnalyzerConfig,
    question: &ExternalSelectionQuestion,
    selection: Option<&super::external::ExternalInventorySelection>,
) -> bool {
    !question.uncertified
        && config.dependency_discovery.mode != JvmDependencyDiscoveryMode::OfflineBuildTools
        // Dependency resolution lists directories only in the Gradle cache, and
        // a found listing makes the selection uncertified. Absent probes are replayable:
        // the probes sit under the canonical cache root, which need not share a
        // prefix with the configured root.
        && selection.is_some_and(|selection| {
            !selection
                .inputs
                .resolution_steps
                .iter()
                .any(|probe| matches!(probe.operation, ExternalProbeOperation::List) && !probe.is_absent())
        })
}

/// The answer digest of the dependency question when its tree part is `basis`
/// and the environment is this one, or `None` unless that answer is replayable (#11607). Reads no manifest: replay resolves the recorded
/// coordinates under `project_root` and compares the digest with the recorded
/// one.
pub(crate) fn dependencies_answer_under_basis(
    config: &JvmAnalyzerConfig,
    project_root: &std::path::Path,
    question: &ExternalSelectionQuestion,
    basis: &brokk_bifrost_core::analyzer::external_selection::JvmDependencyBasis,
) -> Option<[u8; 32]> {
    let selection = JvmExternalDeclarationIndex::select_under_basis::<std::convert::Infallible>(
        config,
        project_root,
        basis,
        |_| Ok(()),
    )?
    .expect("infallible artifact visitor");
    let complete = selection.completeness.is_complete();
    let certified = complete && dependencies_certifiable(config, question, Some(&selection));
    (dependencies_certifiable(config, question, Some(&selection))
        && (complete || selection.completeness.only_replayable_gaps()))
    .then(|| selection.answer_digest(complete, certified))
}

#[cfg(test)]
fn verify_dependencies_with(
    config: &JvmAnalyzerConfig,
    project: &dyn Project,
    question: &ExternalSelectionQuestion,
    retry: &SelectionRetry,
    before_validation: impl Fn(),
) -> Result<VerifiedSelection, SelectionRefused> {
    verify_dependencies_with_evidence(config, project, question, retry, before_validation)
}

fn verify_dependencies_with_evidence(
    config: &JvmAnalyzerConfig,
    project: &dyn Project,
    question: &ExternalSelectionQuestion,
    retry: &SelectionRetry,
    before_validation: impl Fn(),
) -> Result<VerifiedSelection, SelectionRefused> {
    let inputs = super::dependency_discovery::manifest_scope(project, config);
    loop {
        // Capture the listing before sampling its owner revision. Observer
        // invalidations move that revision; authoritative scope validation
        // below also detects disk drift without an observer notification.
        let listed = inputs.files_with_omissions();
        // Only an omission that could hide a manifest makes the selection
        // incomplete; a symlink to a source file changes no dependency.
        let omitted: Vec<_> = listed
            .as_ref()
            .map(|(_, omissions)| {
                omissions
                    .iter()
                    .filter(|omission| {
                        super::dependency_discovery::omission_could_hide_manifest(omission)
                    })
                    .map(|omission| omission.path.clone())
                    .collect()
            })
            .unwrap_or_default();
        let inventory_complete = listed.is_ok() && omitted.is_empty();
        let stamp = project.view_stamp();
        let captured = listed.map(|listing| capture_listing(&inputs, listing));
        let (selection, valid) = match captured {
            Ok(captured) => {
                let mut selection = inputs
                    .capture_boundary(|| {
                        JvmExternalDeclarationIndex::select_external_inventory::<
                            std::convert::Infallible,
                        >(config, project, &captured, |_| Ok(()))
                    })
                    .expect("infallible artifact visitor");
                // A listing that omitted files may have hidden a manifest, so
                // the selection is incomplete for that named reason.
                if !inventory_complete {
                    selection
                        .completeness
                        .record(ExternalSelectionFailure::ListingOmitted { paths: omitted });
                }
                if inputs.missing_revision {
                    selection.completeness.record(ExternalSelectionFailure::DependencyGaps(vec![
                        brokk_bifrost_semantic::analyzer::semantic_model::dependency::JvmDependencyGap::missing_revision_build_authority(),
                    ]));
                }
                before_validation();
                let validation = captured.validate_scope(&inputs);
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
                    inputs.invalidate_listing();
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
        let complete = inventory_complete
            && selection
                .as_ref()
                .is_some_and(|selection| selection.completeness.is_complete());
        // `verified` is provenance: a later run can ask this authority again
        // and compare. It does not depend on `complete`; `certified` adds that.
        // Whether an incomplete selection may be reused is `replayable()`: the
        // failures that are a pack's fixed content (folded in later, at the
        // reader bind) or a declared coordinate with no local artifact are fixed
        // for unchanged inputs, while a read, a limit, an unreadable probe or an
        // omitted listing may succeed next time.
        let verified =
            stamp.is_some() && dependencies_certifiable(config, question, selection.as_ref());
        let certified = complete && verified;
        // An omitted listing is itself a failure, so it is never replayable.
        let only_replayable_gaps = selection
            .as_ref()
            .is_some_and(|selection| selection.completeness.only_replayable_gaps());
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
            verified,
            certified,
            complete,
            only_replayable_gaps,
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

    // Matching metadata identities reuse a JDK digest on every filesystem, so
    // none of these requests hashes after the first. /var/tmp additionally
    // exercises the FUSE filesystem the content-digest allowlist rejects in the
    // disposable executor.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11968: a source subset omitted its project build and could not replay dependency selections"
    )]
    fn live_subset_build_receipts_track_manifests_overlays_and_scope() {
        use super::super::catalog_reader::JvmSelectionAuthority;
        use brokk_bifrost_core::analyzer::external_selection::ExternalSelectionAuthority;
        use brokk_bifrost_core::analyzer::outer_request::OuterRequest;
        use brokk_bifrost_core::analyzer::project::{FileSetProject, OverlayProject};
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let pom = |version| {
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId><artifactId>app</artifactId><version>1</version><dependencies><dependency><groupId>com.example</groupId><artifactId>lib</artifactId><version>{version}</version></dependency></dependencies></project>"
            )
        };
        std::fs::write(root.join("pom.xml"), pom("1")).unwrap();
        std::fs::write(root.join("App.java"), "class App {}").unwrap();
        let repository = root.join("repo");
        for version in ["1", "2"] {
            let jar = repository.join(format!("com/example/lib/{version}/lib-{version}.jar"));
            std::fs::create_dir_all(jar.parent().unwrap()).unwrap();
            std::fs::write(jar, version).unwrap();
        }
        let delegate = Arc::new(FilesystemProject::new(&root).unwrap());
        let subset = Arc::new(
            FileSetProject::new(&root, [std::path::PathBuf::from("App.java")])
                .with_project_build(delegate.clone()),
        );
        let config = JvmAnalyzerConfig {
            external_dependencies: brokk_bifrost_core::analyzer::config::JvmExternalDependencies {
                repository_roots: vec![repository],
                ..Default::default()
            },
            ..Default::default()
        };
        let authority =
            |config: JvmAnalyzerConfig, project: Arc<dyn Project>| JvmSelectionAuthority {
                config,
                project,
                verifications: Arc::default(),
                digests: super::super::external::test_digests(),
            };
        let live = authority(config.clone(), subset.clone());
        let question = live.questions().remove(0);
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::new();
        let ask = |authority: &JvmSelectionAuthority, request: &OuterRequest| {
            authority
                .answer(
                    request,
                    &authority.questions().remove(0),
                    &SelectionRetry::default(),
                    &cancellation,
                )
                .unwrap()
        };
        let request = OuterRequest::new();
        let original = ask(&live, &request);
        assert!(original.complete && original.replayable(), "{original:?}");
        assert_eq!(original.view_stamp, subset.view_stamp());
        assert_eq!(
            super::super::external::jvm_dependency_basis(&config, subset.as_ref())
                .unwrap()
                .entries[0]
                .version,
            "1"
        );
        assert!(
            live.basis(&question, original.answer_digest).is_none(),
            "a live external build cannot be frozen as an export basis"
        );
        assert!(Arc::ptr_eq(&original, &ask(&live, &request)));
        // Source bytes are outside this selection's inputs. Within the same
        // outer request their edit must not cause a second selection fill.
        std::fs::write(root.join("App.java"), "class App { int changed; }").unwrap();
        assert!(Arc::ptr_eq(&original, &ask(&live, &request)));
        // Receipt replay re-asks the authority in a fresh request. The pom is
        // outside the source subset and an unsignalled edit still invalidates it.
        std::fs::write(root.join("pom.xml"), pom("2")).unwrap();
        let changed = ask(&live, &OuterRequest::new());
        assert!(changed.replayable());
        assert_ne!(original.answer_digest, changed.answer_digest);
        let replayed = ask(&live, &OuterRequest::new());
        assert_eq!(changed.answer_digest, replayed.answer_digest);
        let overlay = Arc::new(OverlayProject::new(subset.clone()));
        assert!(overlay.set(root.join("pom.xml"), pom("1")));
        let buffered = ask(&authority(config.clone(), overlay), &OuterRequest::new());
        assert_eq!(original.answer_digest, buffered.answer_digest);
        let mut opted_config = config.clone();
        opted_config.without_project_build = true;
        let opted = authority(opted_config, subset);
        assert_ne!(question.digest, opted.questions()[0].digest);
        let incomplete = ask(&opted, &request);
        assert!(
            !incomplete.complete && !incomplete.replayable(),
            "{incomplete:?}"
        );
        assert!(!Arc::ptr_eq(&original, &incomplete));
        // The opt-out's explicit membership stays fixed when the surrounding
        // workspace grows or shrinks. It remains incomplete, not stale.
        let frozen = authority(
            config.clone(),
            Arc::new(
                FileSetProject::new(&root, [std::path::PathBuf::from("App.java")])
                    .with_live_delegate(delegate.clone(), delegate.all_files_shared().unwrap()),
            ),
        );
        let unrelated = root.join("Unrelated.java");
        std::fs::write(&unrelated, "class Unrelated {}").unwrap();
        assert!(!ask(&opted, &OuterRequest::new()).replayable());
        assert!(matches!(
            frozen.answer(
                &OuterRequest::new(),
                &frozen.questions().remove(0),
                &SelectionRetry::default(),
                &cancellation
            ),
            Err(SelectionRefused::Stale)
        ));
        std::fs::remove_file(unrelated).unwrap();
        assert!(!ask(&opted, &OuterRequest::new()).replayable());
        let revision = Arc::new(
            FileSetProject::new(&root, [std::path::PathBuf::from("App.java")])
                .with_missing_revision_build_authority(),
        );
        let historical = ask(&authority(config, revision), &OuterRequest::new());
        assert!(!historical.replayable());
        let records = historical
            .records
            .downcast_ref::<Option<super::super::external::ExternalInventorySelection>>()
            .unwrap();
        assert!(records.as_ref().unwrap().completeness.only_gaps().unwrap().iter().any(|gap|
            matches!(gap.cause, brokk_bifrost_semantic::analyzer::semantic_model::dependency::JvmDependencyGapCause::MissingRevisionBuildAuthority)));
        #[cfg(unix)]
        {
            std::fs::create_dir(root.join("hidden")).unwrap();
            std::os::unix::fs::symlink(root.join("hidden"), root.join("linked-build")).unwrap();
            let omitted = ask(&live, &OuterRequest::new());
            assert!(
                !omitted.replayable(),
                "fresh omissions must not be dropped by an inventory-only check"
            );
        }
    }

    fn age_jdk_record(
        holder: &brokk_bifrost_core::analyzer::external_selection::ToolchainVerifications,
        question: &ExternalSelectionQuestion,
    ) {
        use super::super::external::VerifiedJdkRecord;
        let record = holder.get::<VerifiedJdkRecord>(&question.digest).unwrap();
        holder.replace(
            question.digest,
            Arc::new(VerifiedJdkRecord {
                selected: record.selected.clone(),
                observation: record.observation.clone(),
                observed_at: std::time::SystemTime::now() + std::time::Duration::from_secs(172800),
            }),
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12097: unchanged JDK selections rehashed on non-allowlisted filesystems"
    )]
    fn unchanged_jdk_requests_hash_nothing_and_activation_replaces_record() {
        use super::super::external::{JDK_DIGEST_COMPUTATIONS, verify_jdk_record};
        use brokk_bifrost_core::analyzer::external_selection::ToolchainVerifications;
        let locations = vec![std::env::temp_dir()];
        #[cfg(target_os = "linux")]
        let locations = {
            let mut locations = locations;
            locations.push(std::path::PathBuf::from("/var/tmp"));
            locations
        };
        for location in locations {
            let temp = tempfile::tempdir_in(location).unwrap();
            let root = temp.path().canonicalize().unwrap();
            let workspace = root.join("workspace");
            let home = root.join("jdk");
            std::fs::create_dir_all(&workspace).unwrap();
            std::fs::create_dir_all(home.join("jmods")).unwrap();
            std::fs::create_dir_all(home.join("lib")).unwrap();
            std::fs::write(home.join("release"), "JAVA_VERSION=\"21\"\n").unwrap();
            std::fs::write(home.join("jmods/java.base.jmod"), b"jmod bytes").unwrap();
            std::fs::write(home.join("lib/src.zip"), b"source bytes").unwrap();
            // Keep activation reads deterministically racy; only the explicit
            // aged verification record below is allowed to skip those reads.
            for path in [home.join("jmods/java.base.jmod"), home.join("lib/src.zip")] {
                std::fs::File::options()
                    .write(true)
                    .open(path)
                    .unwrap()
                    .set_modified(
                        std::time::SystemTime::now() + std::time::Duration::from_secs(86400),
                    )
                    .unwrap();
            }
            let listing = Arc::new(WorkspaceFileListingCache::new(workspace.clone()));
            let project = FilesystemProject::with_cached_listing(workspace, listing).unwrap();
            let mut config = JvmAnalyzerConfig::default();
            config.standard_library_discovery.discover_java_home = false;
            config.standard_library_discovery.jdk_homes = vec![home];
            let question = ExternalSelectionQuestion::for_jvm(&config).remove(1);
            let holder = ToolchainVerifications::default();
            let digests = test_digests();
            let answer = || {
                verify_selection_with(
                    &config,
                    &project,
                    &digests,
                    &holder,
                    &question,
                    &Default::default(),
                    &Default::default(),
                )
                .unwrap()
            };
            let first = answer();
            age_jdk_record(&holder, &question);
            let before = JDK_DIGEST_COMPUTATIONS.get();
            assert_eq!(first.answer_digest, answer().answer_digest);
            assert_eq!(before, JDK_DIGEST_COMPUTATIONS.get());
            // Even unchanged metadata must replace the record on activation.
            verify_jdk_record(
                &config,
                &project,
                &digests,
                &holder,
                &Default::default(),
                None,
            )
            .unwrap();
            assert_eq!(JDK_DIGEST_COMPUTATIONS.get(), before + 2);
            age_jdk_record(&holder, &question);
            let refreshed = answer();
            assert!(!Arc::ptr_eq(&first.records, &refreshed.records));
            assert_eq!(first.answer_digest, refreshed.answer_digest);
            verify_jdk_record(
                &config,
                &project,
                &digests,
                &holder,
                &Default::default(),
                None,
            )
            .unwrap();
            age_jdk_record(&holder, &question);
            let before = JDK_DIGEST_COMPUTATIONS.get();
            assert_eq!(first.answer_digest, answer().answer_digest);
            assert_eq!(before, JDK_DIGEST_COMPUTATIONS.get());
            verify_jdk_record(
                &config,
                &project,
                &digests,
                &holder,
                &Default::default(),
                None,
            )
            .unwrap();
            assert_eq!(JDK_DIGEST_COMPUTATIONS.get(), before + 2);
        }
    }

    #[test]
    fn jdk_record_reuses_selection_and_coalesces_touch_refresh() {
        use super::super::external::verify_jdk_record;
        use brokk_bifrost_core::analyzer::external_selection::ToolchainVerifications;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let workspace = root.join("workspace");
        let home = root.join("jdk");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(home.join("jmods")).unwrap();
        std::fs::write(home.join("release"), "JAVA_VERSION=\"21\"\n").unwrap();
        let jmod = home.join("jmods/java.base.jmod");
        std::fs::write(&jmod, b"jmod bytes").unwrap();
        let listing = Arc::new(WorkspaceFileListingCache::new(workspace.clone()));
        let project = FilesystemProject::with_cached_listing(workspace, listing).unwrap();
        let mut config = JvmAnalyzerConfig::default();
        config.standard_library_discovery.discover_java_home = false;
        config.standard_library_discovery.jdk_homes = vec![home];
        let question = ExternalSelectionQuestion::for_jvm(&config).remove(1);
        let holder = ToolchainVerifications::default();
        let digests = test_digests();
        let cancellation = Default::default();
        let answer = || {
            verify_selection_with(
                &config,
                &project,
                &digests,
                &holder,
                &question,
                &Default::default(),
                &cancellation,
            )
        };
        let first = answer().unwrap();
        age_jdk_record(&holder, &question);
        let second = answer().unwrap();
        assert!(Arc::ptr_eq(&first.records, &second.records));
        assert_eq!(first.answer_digest, second.answer_digest);
        let signals = Arc::new(AtomicUsize::new(0));
        let counter = signals.clone();
        holder.set_refresh_callback(Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }));
        std::fs::File::options()
            .write(true)
            .open(&jmod)
            .unwrap()
            .set_modified(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(123))
            .unwrap();
        assert!(matches!(answer(), Err(SelectionRefused::Stale)));
        assert!(matches!(answer(), Err(SelectionRefused::Stale)));
        assert_eq!(signals.load(Ordering::SeqCst), 1);
        verify_jdk_record(
            &config,
            &project,
            &digests,
            &holder,
            &Default::default(),
            None,
        )
        .unwrap();
        age_jdk_record(&holder, &question);
        let refreshed = answer().unwrap();
        assert_eq!(first.answer_digest, refreshed.answer_digest);
        assert!(!Arc::ptr_eq(&first.records, &refreshed.records));
        let fallback = ToolchainVerifications::default();
        verify_jdk_record(
            &config,
            &project,
            &digests,
            &fallback,
            &Default::default(),
            None,
        )
        .unwrap();
        std::fs::File::options()
            .write(true)
            .open(&jmod)
            .unwrap()
            .set_modified(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(456))
            .unwrap();
        assert_eq!(
            first.answer_digest,
            verify_selection_with(
                &config,
                &project,
                &digests,
                &fallback,
                &question,
                &Default::default(),
                &cancellation
            )
            .unwrap()
            .answer_digest
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: a transient JDK pin failure was recorded, so every later request reused the incomplete selection"
    )]
    fn a_transient_jdk_pin_failure_is_not_retained() {
        use super::super::external::FAIL_NEXT_JDK_PIN;
        use brokk_bifrost_core::analyzer::external_selection::ToolchainVerifications;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let workspace = root.join("workspace");
        let home = root.join("jdk");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(home.join("jmods")).unwrap();
        std::fs::write(home.join("release"), "JAVA_VERSION=\"21\"\n").unwrap();
        std::fs::write(home.join("jmods/java.base.jmod"), b"jmod bytes").unwrap();
        let listing = Arc::new(WorkspaceFileListingCache::new(workspace.clone()));
        let project = FilesystemProject::with_cached_listing(workspace, listing).unwrap();
        let mut config = JvmAnalyzerConfig::default();
        config.standard_library_discovery.discover_java_home = false;
        config.standard_library_discovery.jdk_homes = vec![home];
        let question = ExternalSelectionQuestion::for_jvm(&config).remove(1);
        let holder = ToolchainVerifications::default();
        let digests = test_digests();
        let answer = || {
            verify_selection_with(
                &config,
                &project,
                &digests,
                &holder,
                &question,
                &Default::default(),
                &Default::default(),
            )
            .unwrap()
        };
        // One member read fails once, then the file reads cleanly. The files
        // never change, so a recorded selection would keep matching.
        FAIL_NEXT_JDK_PIN.set(true);
        let transient = answer();
        assert!(!FAIL_NEXT_JDK_PIN.get(), "the injected failure was used");
        assert!(!transient.complete && !transient.certified, "{transient:?}");
        let retried = answer();
        assert!(retried.complete && retried.certified, "{retried:?}");
        assert_ne!(transient.answer_digest, retried.answer_digest);
        // A complete, non-racy observation is served without pinning.
        age_jdk_record(&holder, &question);
        let again = answer();
        assert!(Arc::ptr_eq(&retried.records, &again.records));
        assert_eq!(retried.answer_digest, again.answer_digest);
    }

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

    #[cfg(unix)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11607: under-basis replay must not certify an original selection with an omitted listing"
    )]
    fn an_omitted_original_listing_refuses_a_dependency_basis() {
        use brokk_bifrost_core::analyzer::external_selection::ExternalSelectionAuthority;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("sub")).unwrap();
        std::os::unix::fs::symlink(root.join("sub"), root.join("module")).unwrap();
        let listing = Arc::new(WorkspaceFileListingCache::new(root.clone()));
        let project =
            Arc::new(FilesystemProject::with_cached_listing(root.clone(), listing).unwrap());
        let config = JvmAnalyzerConfig::default();
        let question = ExternalSelectionQuestion::for_jvm(&config).remove(0);
        let live = verify_dependencies_with(
            &config,
            project.as_ref(),
            &question,
            &SelectionRetry::default(),
            || {},
        )
        .unwrap();
        assert!(!live.certified && !live.replayable(), "{live:?}");
        assert!(
            live.records
                .downcast_ref::<Option<super::super::external::ExternalInventorySelection>>()
                .unwrap()
                .as_ref()
                .unwrap()
                .completeness
                .failures()
                .iter()
                .any(|failure| failure.name() == "listing_omitted")
        );
        // An omitted directory also leaves platform-override visibility unknown.
        // Refuse the basis before coordinate replay can discard that evidence.
        assert!(super::super::external::jvm_dependency_basis(&config, project.as_ref()).is_none());
        let authority = super::super::catalog_reader::JvmSelectionAuthority {
            config,
            project,
            digests: test_digests(),
            verifications: Arc::new(Default::default()),
        };
        assert!(authority.basis(&question, live.answer_digest).is_none());
    }

    /// The dependency answer is reproduced from the coordinates alone, and
    /// follows the environment (#11607).
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11607: a dependency selection recorded over an export could not be checked against a head that differed from its tree"
    )]
    fn a_dependency_answer_is_reproduced_from_its_recorded_coordinates() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(
            root.join("pom.xml"),
            r#"<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId><artifactId>app</artifactId><version>1</version><dependencies><dependency><groupId>com.example</groupId><artifactId>lib</artifactId><version>1.0</version></dependency></dependencies></project>"#,
        )
        .unwrap();
        let repository = root.join("repo");
        let jar = repository.join("com/example/lib/1.0/lib-1.0.jar");
        std::fs::create_dir_all(jar.parent().unwrap()).unwrap();
        std::fs::write(&jar, b"not a jar").unwrap();
        let listing = Arc::new(WorkspaceFileListingCache::new(root.clone()));
        let project = FilesystemProject::with_cached_listing(root.clone(), listing).unwrap();
        let config = JvmAnalyzerConfig {
            external_dependencies: brokk_bifrost_core::analyzer::config::JvmExternalDependencies {
                repository_roots: vec![repository],
                ..Default::default()
            },
            ..JvmAnalyzerConfig::default()
        };
        let question = ExternalSelectionQuestion::for_jvm(&config).remove(0);
        let live = verify_dependencies_with(
            &config,
            &project,
            &question,
            &SelectionRetry::default(),
            || {},
        )
        .expect("a stable view");
        assert!(live.complete && live.certified, "{live:?}");
        let basis = super::super::external::jvm_dependency_basis(&config, &project)
            .expect("a recordable tree part");
        let under = || dependencies_answer_under_basis(&config, &root, &question, &basis);
        assert_eq!(under(), Some(live.answer_digest));
        // The artifact's bytes are the environment part.
        std::fs::write(&jar, b"other bytes").unwrap();
        assert_ne!(under(), Some(live.answer_digest));
        std::fs::remove_file(&jar).unwrap();
        assert!(under().is_some(), "an unresolved coordinate is replayable");
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
        assert!(
            found.complete && found.certified && found.replayable(),
            "{found:?}"
        );
        let listed = verify(
            JvmMavenCoordinate::new("org.example", "other", "1.0"),
            gradle.clone(),
        );
        assert!(
            listed.complete && !listed.certified && !listed.replayable(),
            "{listed:?}"
        );
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
            assert!(
                listed.complete && !listed.certified && !listed.replayable(),
                "{listed:?}"
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13851: a selection past 128 jars left packs activation activated unselected, so the reader refused every JVM lookup"
    )]
    fn an_inventory_past_128_artifacts_is_complete() {
        use brokk_bifrost_core::analyzer::config::JvmMavenCoordinate;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let workspace = root.join("workspace");
        let maven = root.join("maven");
        std::fs::create_dir_all(&workspace).unwrap();
        // BenchmarkJava resolves 132 dependency jars.
        let coordinates: Vec<_> = (0..132)
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
        config.external_dependencies.coordinates = coordinates;
        let question = ExternalSelectionQuestion::for_jvm(&config).remove(0);
        let selection = verify_selection(
            &config,
            &project,
            &test_digests(),
            &question,
            &SelectionRetry::default(),
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        )
        .unwrap();
        assert!(
            selection.complete && selection.certified && selection.replayable(),
            "{selection:?}"
        );
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
                !answer.complete && !answer.certified && !answer.replayable(),
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
            !dependencies.complete && !dependencies.certified && !dependencies.replayable(),
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

    /// One real selection per way a dependency question can end: what it
    /// proves (`certified`), whether a later run can reuse it (`replayable`),
    /// and the failures it names. An incomplete selection always names one.
    #[test]
    fn unresolved_coordinates_are_replayable_and_other_incompleteness_is_not() {
        use super::super::external::ExternalInventorySelection;
        use brokk_bifrost_core::analyzer::config::JvmMavenCoordinate;
        use brokk_bifrost_core::analyzer::project::TestProject;
        use brokk_bifrost_semantic::analyzer::semantic_model::dependency::{
            JvmDependencyGapCause, JvmProbeOperation,
        };

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let workspace = root.join("workspace");
        let maven = root.join("maven");
        let gradle = root.join("gradle");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&maven).unwrap();
        std::fs::create_dir_all(&gradle).unwrap();
        let jar = maven.join("org/example/lib/1.0/lib-1.0.jar");
        std::fs::create_dir_all(jar.parent().unwrap()).unwrap();
        std::fs::write(&jar, b"maven bytes").unwrap();
        let cached = gradle.join("org.example/cached/1.0/abc123/cached-1.0.jar");
        std::fs::create_dir_all(cached.parent().unwrap()).unwrap();
        std::fs::write(&cached, b"gradle bytes").unwrap();
        // Found, but with no jar below it: the listing was observed.
        std::fs::create_dir_all(gradle.join("org.example/hollow/1.0")).unwrap();
        let listing = Arc::new(WorkspaceFileListingCache::new(workspace.clone()));
        let project = FilesystemProject::with_cached_listing(workspace.clone(), listing).unwrap();
        let select = |project: &dyn Project,
                      names: &[&str],
                      repositories: Vec<std::path::PathBuf>,
                      uncertified: bool| {
            let mut config = JvmAnalyzerConfig::default();
            config.dependency_discovery.mode = JvmDependencyDiscoveryMode::Disabled;
            config.external_dependencies.coordinates = names
                .iter()
                .map(|name| JvmMavenCoordinate::new("org.example", *name, "1.0"))
                .collect();
            config.external_dependencies.repository_roots = repositories;
            config.external_dependencies.gradle_cache_roots = vec![gradle.clone()];
            let mut question = ExternalSelectionQuestion::for_jvm(&config).remove(0);
            question.uncertified = uncertified;
            verify_selection(
                &config,
                project,
                &test_digests(),
                &question,
                &SelectionRetry::default(),
                &brokk_bifrost_core::cancellation::CancellationToken::default(),
            )
            .unwrap()
        };
        let failures = |answer: &VerifiedSelection| -> Vec<&'static str> {
            answer
                .records
                .downcast_ref::<Option<ExternalInventorySelection>>()
                .unwrap()
                .as_ref()
                .map(|selection| {
                    selection
                        .completeness
                        .failures()
                        .iter()
                        .map(|failure| failure.name())
                        .collect()
                })
                .unwrap_or_default()
        };
        let blocked = root.join("blocked\0repository");
        // (case, answer, complete, certified, replayable, failures)
        let mut cases = vec![
            (
                "resolved",
                select(&project, &["lib"], vec![maven.clone()], false),
                true,
                true,
                true,
                vec![],
            ),
            (
                "unresolved in the Maven repository and absent from the Gradle cache",
                select(&project, &["nope"], vec![maven.clone()], false),
                false,
                false,
                true,
                vec!["dependency_gaps"],
            ),
            (
                "a resolved and an unresolved coordinate",
                select(&project, &["lib", "nope"], vec![maven.clone()], false),
                false,
                false,
                true,
                vec!["dependency_gaps"],
            ),
            (
                "resolved from a Gradle listing",
                select(&project, &["cached"], vec![maven.clone()], false),
                true,
                false,
                false,
                vec![],
            ),
            (
                "unresolved behind a Gradle listing that found a directory",
                select(&project, &["hollow"], vec![maven.clone()], false),
                false,
                false,
                false,
                vec!["dependency_gaps"],
            ),
            // An unreadable repository leaves the coordinate unavailable, not
            // certified absent (2f9505db5d): it is Provider incompleteness of
            // discovery, with no replayable Unresolved gap.
            (
                "unresolved with an unreadable repository",
                select(
                    &project,
                    &["nope"],
                    vec![blocked.clone(), maven.clone()],
                    false,
                ),
                false,
                false,
                false,
                vec!["discovery", "unreadable_probe"],
            ),
            (
                "resolved with an unreadable repository",
                select(
                    &project,
                    &["lib"],
                    vec![blocked.clone(), maven.clone()],
                    false,
                ),
                false,
                false,
                false,
                vec!["unreadable_probe"],
            ),
            (
                "unresolved under a question that cannot be certified",
                select(&project, &["nope"], vec![maven.clone()], true),
                false,
                false,
                false,
                vec!["dependency_gaps"],
            ),
        ];
        // A view that cannot stamp verifies nothing.
        let unstamped = TestProject::new(
            &workspace,
            brokk_bifrost_core::analyzer::model::Language::Java,
        );
        assert!(unstamped.view_stamp().is_none());
        cases.push((
            "unresolved in an unstamped view",
            select(&unstamped, &["nope"], vec![maven.clone()], false),
            false,
            false,
            false,
            vec!["dependency_gaps"],
        ));
        // A symbolic link to a source file hides no manifest, so the omission
        // changes nothing (#9559, 75135e29d1). A symlinked manifest, or a
        // symlinked directory, may hide one, so the selection is incomplete
        // for that named reason even when every coordinate resolves.
        #[cfg(unix)]
        {
            let linked_project = |name: &str, links: &[(&str, &str)]| {
                let linked = root.join(name);
                std::fs::create_dir_all(linked.join("sub")).unwrap();
                std::fs::write(linked.join("target.txt"), b"t").unwrap();
                for (link, target) in links {
                    std::os::unix::fs::symlink(linked.join(target), linked.join(link)).unwrap();
                }
                let listing = Arc::new(WorkspaceFileListingCache::new(linked.clone()));
                FilesystemProject::with_cached_listing(linked, listing).unwrap()
            };
            let irrelevant = linked_project("irrelevant-links", &[("link.txt", "target.txt")]);
            let manifest = linked_project("manifest-link", &[("pom.xml", "target.txt")]);
            let directory = linked_project("directory-link", &[("module", "sub")]);
            cases.push((
                "resolved with an omitted symlink to a non-manifest file",
                select(&irrelevant, &["lib"], vec![maven.clone()], false),
                true,
                true,
                true,
                vec![],
            ));
            cases.push((
                "unresolved with an omitted symlink to a non-manifest file",
                select(&irrelevant, &["nope"], vec![maven.clone()], false),
                false,
                false,
                true,
                vec!["dependency_gaps"],
            ));
            cases.push((
                "resolved with a symlinked manifest",
                select(&manifest, &["lib"], vec![maven.clone()], false),
                false,
                false,
                false,
                vec!["listing_omitted"],
            ));
            cases.push((
                "unresolved with a symlinked manifest",
                select(&manifest, &["nope"], vec![maven.clone()], false),
                false,
                false,
                false,
                vec!["dependency_gaps", "listing_omitted"],
            ));
            cases.push((
                "resolved with a symlinked directory",
                select(&directory, &["lib"], vec![maven.clone()], false),
                false,
                false,
                false,
                vec!["listing_omitted"],
            ));
        }
        for (case, answer, complete, certified, replayable, names) in &cases {
            assert_eq!(answer.complete, *complete, "{case}: {answer:?}");
            assert_eq!(answer.certified, *certified, "{case}: {answer:?}");
            assert_eq!(answer.replayable(), *replayable, "{case}: {answer:?}");
            assert_eq!(&failures(answer), names, "{case}");
            // `certified` is `complete && verified`, and only the incomplete
            // selections name failures.
            assert_eq!(
                answer.certified,
                answer.complete && answer.verified,
                "{case}"
            );
            assert_eq!(answer.complete, names.is_empty(), "{case}");
        }
        // The unresolved gap carries what selection observed: the absent
        // binary and sources artifact paths and the absent Gradle directory,
        // by operation.
        let answer = &cases[1].1;
        let selection = answer
            .records
            .downcast_ref::<Option<ExternalInventorySelection>>()
            .unwrap()
            .as_ref()
            .unwrap();
        let gaps = selection.completeness.only_gaps().unwrap();
        let [gap] = &gaps[..] else {
            panic!("one unresolved coordinate: {gaps:?}");
        };
        assert_eq!(gap.dependency_id, "org.example:nope:1.0");
        assert_eq!(gap.cause_label(), "unresolved");
        assert_eq!(
            gap.message(),
            "exact local artifact was not found for org.example:nope:1.0"
        );
        let JvmDependencyGapCause::Unresolved(probes) = &gap.cause else {
            panic!("unresolved gap: {gap:?}");
        };
        let observed: Vec<_> = probes
            .iter()
            .map(|probe| {
                (
                    probe.path.strip_prefix(&root).unwrap().to_path_buf(),
                    probe.operation,
                )
            })
            .collect();
        assert_eq!(
            observed,
            [
                (
                    std::path::PathBuf::from("maven/org/example/nope/1.0/nope-1.0.jar"),
                    JvmProbeOperation::Canonicalize
                ),
                (
                    std::path::PathBuf::from("maven/org/example/nope/1.0/nope-1.0-sources.jar"),
                    JvmProbeOperation::Canonicalize
                ),
                (
                    std::path::PathBuf::from("gradle/org.example/nope/1.0"),
                    JvmProbeOperation::List
                ),
            ]
        );
    }

    #[test]
    fn retry_allowance_is_shared_by_fills() {
        let retry = SelectionRetry::default();
        assert!(retry.retry());
        // A second fill receives the same operation-owned allowance.
        assert!(!retry.retry());
    }
}
