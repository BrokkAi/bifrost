//! Explicit native validation assembly. Store derivation stays below language
//! parsing and analyzer publication; production does not call this entry.
use super::PythonAdapter;
use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::store::Result;
use brokk_bifrost_analysis::analyzer::store::python_unit_summaries::{
    PythonEnvironmentPublication, PythonEnvironmentSnapshotInputs, PythonSummaryProfile,
    PythonSummaryReceipt,
};
use brokk_bifrost_analysis::analyzer::store_bridge::PythonEnvironmentPublicationEngineExt;
use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::LanguageAdapter;
use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::model::ProjectFile;
use brokk_bifrost_core::analyzer::project::Project;
use std::path::{Path, PathBuf};
use std::sync::Arc;
/// Owns a validation store, never a retained index of Python modules.
pub struct PythonNativeEnvironment {
    pub(crate) publication: PythonEnvironmentPublication,
    workspace_root: PathBuf,
}
impl PythonNativeEnvironment {
    pub fn open(path: &Path, workspace_root: &Path, profile: PythonSummaryProfile) -> Result<Self> {
        let parser = brokk_bifrost_analysis::analyzer::parser_language_for(Language::Python)
            .expect("Python grammar");
        let epoch = brokk_bifrost_analysis::analyzer::store_bridge::epoch::epoch_for(
            Language::Python,
            &parser,
        );
        Ok(Self {
            publication: PythonEnvironmentPublication::open(path, workspace_root, &epoch, profile)?,
            workspace_root: workspace_root.to_owned(),
        })
    }
    /// Partial corpus inventories have a distinct projection from the live root.
    pub fn open_scoped(
        path: &Path,
        workspace_root: &Path,
        profile: PythonSummaryProfile,
    ) -> Result<Self> {
        let mut environment = Self::open(path, workspace_root, profile)?;
        environment.publication.snapshot.workspace_id =
            brokk_bifrost_analysis::analyzer::store::WorkspaceId::for_session();
        Ok(environment)
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn route_probe(&self, project: &dyn Project, revision: i64) -> Result<String> {
        brokk_bifrost_analysis::native_resolution_test_support::python_native_route_probe(
            &self.publication,
            project,
            revision,
        )
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn route_probe_in_session(
        &self,
        project: &dyn Project,
        revision: i64,
        session: &brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession,
    ) -> Result<String> {
        brokk_bifrost_analysis::native_resolution_test_support::python_native_route_probe_in_session(
            &self.publication,
            project,
            revision,
            session,
        )
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn confirm_usages(
        &self,
        project: &dyn Project,
        revision: i64,
        targets: &[brokk_bifrost_core::analyzer::CodeUnit],
    ) -> Result<brokk_bifrost_analysis::analyzer::store::resolution_operation::python_reverse::PythonNativeReverseResult>{
        brokk_bifrost_analysis::native_resolution_test_support::python_native_reverse_confirmation(
            &self.publication,
            project,
            revision,
            targets,
        )
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn builtin_hierarchy_probe(&self, project: &dyn Project, revision: i64) -> Result<String> {
        brokk_bifrost_analysis::native_resolution_test_support::python_native_builtin_hierarchy_probe(
            &self.publication, project, revision,
        )
    }

    pub fn reconcile(
        &self,
        revision: i64,
        cancellation: &CancellationToken,
    ) -> Result<PythonSummaryReceipt> {
        let mut snapshot = self.publication.snapshot.clone();
        snapshot.revision = revision;
        self.publication.store.reconcile_python_environment(
            &snapshot,
            self.publication.profile.clone(),
            python_environment_root(self.workspace_root.clone()),
            cancellation,
        )
    }
    pub fn render(&self, revision: i64) -> Result<String> {
        self.publication.render(revision)
    }
    /// Publish source facts and ordinary revisioned inputs before SQL staging.
    pub fn publish_project(&self, project: Arc<dyn Project>) -> Result<i64> {
        let files = project.analyzable_files(Language::Python)?;
        self.publish_sources(project, &files)
    }
    pub fn publish_sources(
        &self,
        project: Arc<dyn Project>,
        files: &std::collections::BTreeSet<ProjectFile>,
    ) -> Result<i64> {
        assert_eq!(project.root(), self.workspace_root);
        let adapter = PythonAdapter::default()
            .for_project(project.clone())
            .expect("project adapter");
        self.publication.publish_sources(project, files, &adapter)
    }
}

impl PythonNativeEnvironment {
    /// Read retained source inputs under this selected native environment.
    pub fn render_binding_inputs(&self, revision: i64) -> Result<String> {
        self.publication.render_binding_inputs(revision)
    }
    /// Exercise source lexical selection without enabling production dispatch.
    pub fn temporal_binding_trace(
        &self,
        revision: i64,
        path: &str,
        point: usize,
        name: &str,
    ) -> Result<String> {
        self.publication
            .temporal_binding_trace(revision, path, point, name)
    }
}

/// Root hook shared by the harness and the production lifecycle caller.
/// Captures only a root path; all membership and bytes come from the snapshot.
pub fn python_environment_root(
    root: PathBuf,
) -> impl Fn(&Path, &PythonEnvironmentSnapshotInputs) -> Result<PathBuf> + Send + 'static {
    struct Inputs<'a>(&'a PythonEnvironmentSnapshotInputs);
    impl brokk_bifrost_python::declarations::PythonImportRootInputs for Inputs<'_> {
        fn contains(&self, path: &Path) -> bool {
            self.0.contains(path)
        }
        fn configuration_source(&self, path: &Path) -> Option<std::borrow::Cow<'_, str>> {
            self.0
                .configuration_source(path)
                .map(std::borrow::Cow::Borrowed)
        }
    }
    move |path, inputs| {
        Ok(
            brokk_bifrost_python::declarations::python_import_root_with_inputs(
                &root,
                path,
                &Inputs(inputs),
            ),
        )
    }
}

#[cfg(test)]
mod tests;
