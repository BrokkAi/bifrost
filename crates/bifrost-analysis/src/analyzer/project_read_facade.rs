//! Legacy/custom Projects without a recorder slot enter analysis through this facade.
use super::{Language, Project, ProjectFile, ProjectSourceSnapshot};
use brokk_bifrost_core::analyzer::project::AsProject;
use brokk_bifrost_core::analyzer::project::{
    ProjectCoverage, ProjectViewStamp, SharedWorkspaceFileListing, WorkspaceOverlayContent,
};
use brokk_bifrost_core::analyzer::project_reads::{
    ProjectReadSlot, ReadCapability, listing_read, publish_file_set,
};
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(super) fn with_project_read_slot(project: Arc<dyn Project>) -> Arc<dyn Project> {
    if project.project_read_slot().is_some() {
        project
    } else {
        Arc::new(ProjectReadFacade {
            delegate: ProjectDelegate::Owned(project),
            project_reads: ProjectReadSlot::default(),
            listing: None,
        })
    }
}

/// A discovery view over an already captured membership-and-omissions record.
/// File reads still delegate to the host project and share its recorder slot.
pub(super) fn with_workspace_file_listing(
    project: &dyn Project,
    listing: SharedWorkspaceFileListing,
) -> Arc<dyn Project + '_> {
    // Share the host project's recorder slot so the dependency discovery
    // capture attributes the listing and file reads that discovery performs.
    let project_reads = project.project_read_slot().cloned().unwrap_or_default();
    Arc::new(ProjectReadFacade {
        delegate: ProjectDelegate::Borrowed(project),
        project_reads,
        listing: Some(Ok(listing)),
    })
}

/// Borrow the generation's one membership record, including an unavailable record.
pub(super) fn for_generation(analyzer: &dyn super::IAnalyzer) -> Arc<dyn Project + '_> {
    if let Ok(listing) = analyzer.generation_membership().listing() {
        return with_workspace_file_listing(analyzer.project(), listing.clone());
    }
    Arc::new(ProjectReadFacade {
        delegate: ProjectDelegate::Borrowed(analyzer.project()),
        project_reads: analyzer
            .project()
            .project_read_slot()
            .cloned()
            .unwrap_or_default(),
        listing: Some(analyzer.generation_membership().listing().cloned()),
    })
}

enum ProjectDelegate<'a> {
    Owned(Arc<dyn Project>),
    Borrowed(&'a dyn Project),
}
impl<'a> std::ops::Deref for ProjectDelegate<'a> {
    type Target = dyn Project + 'a;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Owned(project) => project.as_ref(),
            Self::Borrowed(project) => *project,
        }
    }
}

struct ProjectReadFacade<'a> {
    delegate: ProjectDelegate<'a>,
    project_reads: ProjectReadSlot,
    /// A listing the caller already owns, served instead of the delegate's.
    listing: Option<
        Result<
            SharedWorkspaceFileListing,
            super::tree_sitter_analyzer::GenerationListingUnavailable,
        >,
    >,
}
impl Project for ProjectReadFacade<'_> {
    fn listing_receipt_structurally_unknown(&self) -> bool {
        self.delegate.listing_receipt_structurally_unknown()
    }

    fn membership_point_observation(
        &self,
        listing: &brokk_bifrost_core::analyzer::project::SharedWorkspaceFileListing,
    ) -> Option<brokk_bifrost_core::analyzer::project::WorkspaceMembershipPointObservation> {
        self.delegate.membership_point_observation(listing)
    }

    fn listing_ignore_inputs_verified(
        &self,
        listing: &brokk_bifrost_core::analyzer::project::SharedWorkspaceFileListing,
    ) -> bool {
        self.delegate.listing_ignore_inputs_verified(listing)
    }

    fn build_authority(&self) -> brokk_bifrost_core::analyzer::project::ProjectBuildAuthority<'_> {
        self.delegate.build_authority()
    }

    fn view_stamp(&self) -> Option<ProjectViewStamp> {
        if self.listing.is_some() {
            return None;
        }
        self.delegate.view_stamp()
    }

    fn file_listing_stamp(&self) -> Option<Vec<ProjectViewStamp>> {
        // A captured pair has its own membership but no independent stable
        // view identity. The delegate's revisions cannot identify that pair.
        if self.listing.is_some() {
            return None;
        }
        self.delegate.file_listing_stamp()
    }

    fn directory_entries(&self, parent: &Path) -> std::io::Result<BTreeSet<ProjectFile>> {
        self.delegate.directory_entries(parent)
    }

    fn ignore_rules_digest(&self) -> std::io::Result<[u8; 32]> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.ignore_rules(self.as_project()));
        self.delegate.ignore_rules_digest()
    }
    fn project_read_slot(&self) -> Option<&ProjectReadSlot> {
        Some(&self.project_reads)
    }
    fn install_read_recorder(&self, capability: ReadCapability) -> bool {
        self.project_reads.install(capability);
        true
    }
    fn root(&self) -> &Path {
        self.delegate.root()
    }
    fn coverage(&self) -> ProjectCoverage {
        self.delegate.coverage()
    }
    fn workspace_root_for_file(&self, file: &ProjectFile) -> PathBuf {
        self.delegate.workspace_root_for_file(file)
    }
    fn analyzer_languages(&self) -> BTreeSet<Language> {
        self.project_reads
            .languages(self.as_project(), || self.delegate.analyzer_languages())
    }
    fn all_files(&self) -> io::Result<BTreeSet<ProjectFile>> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        match &self.listing {
            Some(Ok((files, _))) => Ok((**files).clone()),
            Some(Err(error)) => Err(io::Error::other(*error)),
            None => self.delegate.all_files(),
        }
    }
    fn all_files_shared(&self) -> io::Result<Arc<BTreeSet<ProjectFile>>> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        match &self.listing {
            Some(Ok((files, _))) => {
                publish_file_set(self, files.as_ref())?;
                Ok(Arc::clone(files))
            }
            Some(Err(error)) => Err(io::Error::other(*error)),
            None => self.delegate.all_files_shared(),
        }
    }
    fn cached_omissions_if_available(
        &self,
    ) -> io::Result<Option<Arc<Vec<brokk_bifrost_core::analyzer::project::WorkspaceFileOmission>>>>
    {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        match &self.listing {
            Some(Ok((_, omissions))) => Ok(Some(Arc::clone(omissions))),
            Some(Err(error)) => Err(io::Error::other(*error)),
            None => self.delegate.cached_omissions_if_available(),
        }
    }
    fn cached_listing_if_available(&self) -> io::Result<Option<SharedWorkspaceFileListing>> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        match &self.listing {
            Some(Ok(listing)) => Ok(Some(listing.clone())),
            Some(Err(error)) => Err(io::Error::other(*error)),
            None => self.delegate.cached_listing_if_available(),
        }
    }
    fn cached_analyzable_files_from(
        &self,
        files: &BTreeSet<ProjectFile>,
        language: Language,
    ) -> io::Result<Option<BTreeSet<ProjectFile>>> {
        let _project_read = listing_read(self);
        self.delegate.cached_analyzable_files_from(files, language)
    }
    fn all_files_with_omissions(&self) -> io::Result<SharedWorkspaceFileListing> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        match &self.listing {
            Some(Ok(listing)) => {
                publish_file_set(self, listing.0.as_ref())?;
                Ok(listing.clone())
            }
            Some(Err(error)) => Err(io::Error::other(*error)),
            None => self.delegate.all_files_with_omissions(),
        }
    }
    fn workspace_file_listing_count(&self) -> usize {
        self.delegate.workspace_file_listing_count()
    }
    fn analyzable_files(&self, language: Language) -> io::Result<BTreeSet<ProjectFile>> {
        let _read = listing_read(self);
        match &self.listing {
            Some(Ok((files, _))) => {
                publish_file_set(self, files.as_ref())?;
                self.delegate.analyzable_files_from(files, language)
            }
            Some(Err(error)) => Err(io::Error::other(*error)),
            None => self.delegate.analyzable_files(language),
        }
    }
    fn analyzable_files_from(
        &self,
        files: &BTreeSet<ProjectFile>,
        language: Language,
    ) -> io::Result<BTreeSet<ProjectFile>> {
        let _read = listing_read(self);
        self.delegate.analyzable_files_from(files, language)
    }
    fn file_by_rel_path(&self, path: &Path) -> Option<ProjectFile> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.path(self.as_project(), path));
        self.delegate.file_by_rel_path(path)
    }
    fn file_by_abs_path(&self, path: &Path) -> Option<ProjectFile> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.absolute_path(self.as_project(), path));
        self.delegate.file_by_abs_path(path)
    }
    fn file_by_abs_path_allow_missing(&self, path: &Path) -> Option<ProjectFile> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.absolute_path(self.as_project(), path));
        self.delegate.file_by_abs_path_allow_missing(path)
    }
    fn has_directory(&self, path: &Path) -> bool {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.directory(self.as_project(), path));
        self.delegate.has_directory(path)
    }
    fn persistence_root(&self) -> Option<&Path> {
        self.delegate.persistence_root()
    }
    fn is_gitignored(&self, path: &Path) -> bool {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.git_ignore(self.as_project(), path));
        self.delegate.is_gitignored(path)
    }
    fn retained_ignore_observation(
        &self,
    ) -> brokk_bifrost_core::analyzer::project::RetainedIgnoreObservation {
        self.delegate.retained_ignore_observation()
    }
    fn ignore_observation_for_files(
        &self,
        files: &BTreeSet<ProjectFile>,
    ) -> Result<
        brokk_bifrost_core::analyzer::project::IgnoreObservation,
        brokk_bifrost_core::analyzer::project::IgnoreObservationError,
    > {
        self.delegate.ignore_observation_for_files(files)
    }

    fn is_bifrostignored(
        &self,
        path: &Path,
    ) -> Result<bool, brokk_bifrost_core::analyzer::project::IgnoreObservationError> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.ignore_rules(self.as_project()));
        self.delegate.is_bifrostignored(path)
    }
    fn overlay_content(&self) -> Option<Arc<WorkspaceOverlayContent>> {
        let _read = self.project_reads.overlays(self.as_project());
        let answer = self.delegate.overlay_content();
        brokk_bifrost_core::analyzer::project_reads::publish_overlays(&answer);
        answer
    }
    fn has_overlay(&self, file: &ProjectFile) -> bool {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.overlay_membership(self.as_project(), file.rel_path()));
        let answer = self.delegate.has_overlay(file);
        brokk_bifrost_core::analyzer::project_reads::publish_overlay_membership(answer);
        answer
    }
    fn capture_source_overlays(
        &self,
    ) -> io::Result<Arc<brokk_bifrost_core::analyzer::project::PinnedSourceOverlayView>> {
        // Unobserved: the delegate's capture is the one atomic view.
        self.delegate.capture_source_overlays()
    }
    fn analysis_generation(&self) -> u64 {
        self.delegate.analysis_generation()
    }
    fn invalidate_cached_file_listing(&self) {
        self.delegate.invalidate_cached_file_listing();
    }
    fn revalidate_symlink_omissions(&self, changed: &BTreeSet<ProjectFile>) {
        self.delegate.revalidate_symlink_omissions(changed);
    }

    fn has_exact_directory_entry(&self, file: &ProjectFile) -> std::io::Result<bool> {
        self.delegate.has_exact_directory_entry(file)
    }

    fn update_cached_listing_for_resolved_path(&self, file: &ProjectFile) -> bool {
        self.delegate.update_cached_listing_for_resolved_path(file)
    }

    fn update_cached_listing_for_path(&self, path: &Path) -> bool {
        self.delegate.update_cached_listing_for_path(path)
    }
    fn update_cached_listing_for_removed_paths(&self, files: &[ProjectFile]) -> bool {
        self.delegate.update_cached_listing_for_removed_paths(files)
    }
    fn read_source(&self, file: &ProjectFile) -> io::Result<String> {
        self.project_reads.source(
            self.as_project(),
            file,
            || self.delegate.read_source(file),
            |source| {
                Some(
                    git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes())
                        .expect("hashing legacy project source"),
                )
            },
        )
    }
    fn read_source_limited(&self, file: &ProjectFile, max: usize) -> io::Result<Option<String>> {
        self.project_reads.source(
            self.as_project(),
            file,
            || self.delegate.read_source_limited(file, max),
            |source| {
                source.as_ref().map(|source| {
                    git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes())
                        .expect("hashing legacy project source")
                })
            },
        )
    }
    fn read_file_snapshot(
        &self,
        file: &ProjectFile,
    ) -> std::io::Result<brokk_bifrost_core::analyzer::project::ProjectFileSnapshot> {
        self.project_reads.source(
            self.as_project(),
            file,
            || self.delegate.read_file_snapshot(file),
            |snapshot| Some(snapshot.oid()),
        )
    }
    fn read_source_snapshot(&self, file: &ProjectFile) -> io::Result<ProjectSourceSnapshot> {
        self.project_reads.source(
            self.as_project(),
            file,
            || self.delegate.read_source_snapshot(file),
            |source| Some(source.oid()),
        )
    }
    fn read_source_snapshot_limited(
        &self,
        file: &ProjectFile,
        max: usize,
    ) -> io::Result<Option<ProjectSourceSnapshot>> {
        self.project_reads.source(
            self.as_project(),
            file,
            || self.delegate.read_source_snapshot_limited(file, max),
            |source| source.as_ref().map(ProjectSourceSnapshot::oid),
        )
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::project::{FilesystemProject, WorkspaceFileOmissionReason};

    #[test]
    #[brokk_bifrost_test_macros::hardwon("#11968: captured listings aliased their delegate stamp")]
    fn facade_listing_refuses_stamp_and_recorder_forwards() {
        let dir = tempfile::tempdir().unwrap();
        let delegate = FilesystemProject::new(dir.path()).unwrap();
        let first = with_workspace_file_listing(
            &delegate,
            (Arc::new(BTreeSet::new()), Arc::new(Vec::new())),
        );
        let second = with_workspace_file_listing(
            &delegate,
            (
                Arc::new(BTreeSet::from([ProjectFile::new(
                    delegate.root().to_path_buf(),
                    "selected.java",
                )])),
                Arc::new(Vec::new()),
            ),
        );
        assert!(first.view_stamp().is_none());
        assert!(second.view_stamp().is_none());
        assert!(first.file_listing_stamp().is_none());
        assert!(second.file_listing_stamp().is_none());
        delegate.invalidate_cached_file_listing();
        assert!(first.file_listing_stamp().is_none());
        assert!(first.view_stamp().is_none());
        let recorder = ProjectReadFacade {
            delegate: ProjectDelegate::Borrowed(&delegate),
            project_reads: ProjectReadSlot::default(),
            listing: None,
        };
        assert!(delegate.view_stamp().is_some());
        assert_eq!(recorder.view_stamp(), delegate.view_stamp());
        assert_eq!(recorder.file_listing_stamp(), delegate.file_listing_stamp());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon("#11902: C++ discovery bypassed the generation listing")]
    fn discovery_analyzable_files_respects_supplied_membership() {
        use brokk_bifrost_core::analyzer::project::FileSetProject;
        let root = tempfile::tempdir().unwrap();
        let project: Arc<dyn Project> = Arc::new(FileSetProject::new(
            root.path(),
            [PathBuf::from("selected.cpp"), PathBuf::from("later.cpp")],
        ));
        let selected = ProjectFile::new(root.path().to_path_buf(), "selected.cpp");
        let facade = with_workspace_file_listing(
            project.as_ref(),
            (
                Arc::new(BTreeSet::from([selected.clone()])),
                Arc::new(Vec::new()),
            ),
        );
        assert_eq!(
            facade.analyzable_files(Language::Cpp).unwrap(),
            BTreeSet::from([selected])
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon("#9737: the read facade discarded symlink omissions")]
    fn facade_forwards_listing_omissions() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("source.rs"), "fn source() {}\n").unwrap();
        std::os::unix::fs::symlink(root.join("source.rs"), root.join("linked.rs")).unwrap();
        let inner: Arc<dyn Project> = Arc::new(FilesystemProject::new(&root).unwrap());
        let facade = ProjectReadFacade {
            delegate: ProjectDelegate::Owned(inner),
            project_reads: ProjectReadSlot::default(),
            listing: None,
        };
        let listing = facade.all_files_with_omissions().unwrap();
        let omissions = Arc::clone(&listing.1);
        let retained = with_workspace_file_listing(&facade, listing.clone());
        std::fs::write(root.join("later.rs"), "fn later() {}\n").unwrap();
        let observed = retained.all_files_with_omissions().unwrap();
        let cached = retained.cached_listing_if_available().unwrap().unwrap();
        assert!(Arc::ptr_eq(&observed.0, &listing.0));
        assert!(Arc::ptr_eq(&observed.1, &omissions));
        assert!(Arc::ptr_eq(&cached.0, &listing.0));
        assert!(Arc::ptr_eq(&cached.1, &omissions));
        assert!(Arc::ptr_eq(
            &retained.cached_omissions_if_available().unwrap().unwrap(),
            &omissions,
        ));
        assert!(omissions.iter().any(|omission| {
            omission.path == Path::new("linked.rs")
                && omission.reason == WorkspaceFileOmissionReason::Symlink
        }));
    }
}
