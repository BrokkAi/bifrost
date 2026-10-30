//! Legacy/custom Projects without a recorder slot enter analysis through this facade.
use super::{Language, Project, ProjectFile, ProjectSourceSnapshot};
use brokk_bifrost_core::analyzer::project::AsProject;
use brokk_bifrost_core::analyzer::project::{ProjectCoverage, WorkspaceOverlayContent};
use brokk_bifrost_core::analyzer::project_reads::{ProjectReadSlot, ReadCapability, listing_read};
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(super) fn with_project_read_slot(project: Arc<dyn Project>) -> Arc<dyn Project> {
    if project.project_read_slot().is_some() {
        project
    } else {
        Arc::new(ProjectReadFacade {
            delegate: project,
            project_reads: ProjectReadSlot::default(),
        })
    }
}
struct ProjectReadFacade {
    delegate: Arc<dyn Project>,
    project_reads: ProjectReadSlot,
}
impl Project for ProjectReadFacade {
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
        self.delegate.all_files()
    }
    fn all_files_shared(&self) -> io::Result<Arc<BTreeSet<ProjectFile>>> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        self.delegate.all_files_shared()
    }
    fn workspace_file_listing_count(&self) -> usize {
        self.delegate.workspace_file_listing_count()
    }
    fn analyzable_files(&self, language: Language) -> io::Result<BTreeSet<ProjectFile>> {
        let _read = listing_read(self);
        self.delegate.analyzable_files(language)
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
    fn is_bifrostignored(&self, path: &Path) -> bool {
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
    fn analysis_generation(&self) -> u64 {
        self.delegate.analysis_generation()
    }
    fn invalidate_cached_file_listing(&self) {
        self.delegate.invalidate_cached_file_listing();
    }
    fn update_cached_listing_for_path(&self, path: &Path) -> bool {
        self.delegate.update_cached_listing_for_path(path)
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
