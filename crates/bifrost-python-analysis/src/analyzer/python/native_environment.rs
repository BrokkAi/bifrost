//! Explicit native validation assembly. Store derivation stays below language
//! parsing and analyzer publication; production does not call this entry.
use super::PythonAdapter;
use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::store::python_unit_summaries::{
    PythonEnvironmentPublication, PythonSummaryAuthority, PythonSummaryProfile,
    PythonSummaryReceipt, portable,
};
use brokk_bifrost_analysis::analyzer::store::{Result, StoreError};
use brokk_bifrost_analysis::analyzer::store_bridge::PythonEnvironmentPublicationEngineExt;
use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::{LanguageAdapter, TreeSitterAnalyzer};
use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::model::ProjectFile;
use brokk_bifrost_core::analyzer::project::Project;
use std::path::Path;
use std::sync::Arc;
/// Owns a validation store, never a retained index of Python modules.
pub struct PythonNativeEnvironment {
    pub(crate) publication: PythonEnvironmentPublication,
}
impl PythonNativeEnvironment {
    pub fn open(path: &Path, profile: PythonSummaryProfile) -> Result<Self> {
        Ok(Self {
            publication: PythonEnvironmentPublication::open(path, profile)?,
        })
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
    pub fn nomination_receipts(
        &self,
        project: &dyn Project,
        revision: i64,
        targets: &[brokk_bifrost_core::analyzer::CodeUnit],
    ) -> Result<String> {
        brokk_bifrost_analysis::native_resolution_test_support::python_native_reverse_nomination_probe(
            &self.publication, project, revision, targets,
        )
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn builtin_hierarchy_probe(&self, project: &dyn Project, revision: i64) -> Result<String> {
        brokk_bifrost_analysis::native_resolution_test_support::python_native_builtin_hierarchy_probe(
            &self.publication, project, revision,
        )
    }

    pub fn begin(&self, revision: i64) -> Result<()> {
        self.publication.begin(revision)
    }
    pub fn reconcile(
        &self,
        revision: i64,
        cancellation: &CancellationToken,
    ) -> Result<PythonSummaryReceipt> {
        self.publication.reconcile(revision, cancellation)
    }
    pub fn render(&self, revision: i64) -> Result<String> {
        self.publication.render(revision)
    }
    /// Stage exactly one selected source; parsing and lowering artifacts die here.
    pub fn stage_source(
        &self,
        project: Arc<dyn Project>,
        file: &ProjectFile,
        source: &str,
        revision: i64,
    ) -> Result<()> {
        if matches!(
            self.publication.profile.authority,
            PythonSummaryAuthority::Workspace
        ) {
            let mut inputs = Vec::new();
            for directory in file
                .rel_path()
                .parent()
                .into_iter()
                .flat_map(Path::ancestors)
            {
                for name in ["pyproject.toml", "setup.py", "__init__.py"] {
                    let path = directory.join(name);
                    let mut digest =
                        brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(
                            b"python-root-configuration:v1",
                        );
                    if let Some(input) = project.file_by_rel_path(&path) {
                        let bytes = project.read_source(&input).map_err(|error| {
                            StoreError::new(format!(
                                "read selected root input {}: {error}",
                                path.display()
                            ))
                        })?;
                        digest.field("present", &[1]);
                        digest.field("source", bytes.as_bytes());
                    } else {
                        digest.field("present", &[0]);
                    }
                    inputs.push((portable(&path), digest.finish()));
                }
            }
            self.publication.stage_configuration(inputs)?;
        }
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(
                &brokk_bifrost_analysis::analyzer::parser_language_for(Language::Python)
                    .expect("Python grammar"),
            )
            .expect("compatible Python grammar");
        let tree = parser.parse(source, None).expect("Python parse tree");
        let mut parsed = brokk_bifrost_python::declarations::parse_python_file_with_native_facts(
            project.as_ref(),
            file,
            source,
            &tree,
        );
        parsed.add_file_scope(file, source);
        let facts = parsed.resolution_facts.clone();
        let state = Arc::new(TreeSitterAnalyzer::<PythonAdapter>::file_state_from_parsed(
            source.to_owned(),
            parsed,
            false,
            Some(Vec::new()),
            true,
        ));
        let adapter = PythonAdapter::default()
            .for_project(project.clone())
            .expect("project adapter");
        let oid = git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes())?;
        use brokk_bifrost_core::analyzer::prepared_syntax::{
            PreparedSourceOrigin, PreparedSyntaxSource, PreparedSyntaxTree,
        };
        let syntax = PreparedSyntaxTree::new(
            PreparedSyntaxSource::Indexed(state.clone()),
            tree,
            brokk_bifrost_core::text_utils::compute_line_starts(source),
            brokk_bifrost_core::analyzer::model::LanguageDialect::Standard(Language::Python),
            PreparedSourceOrigin::Overlay,
            None,
        );
        let file = file.clone();
        let roots = if matches!(
            self.publication.profile.authority,
            PythonSummaryAuthority::Workspace
        ) {
            vec![brokk_bifrost_python::declarations::python_import_root(
                project.as_ref(),
                &file,
            )]
        } else {
            self.publication.profile.roots.clone()
        };
        self.publication
            .stage_prepared_source(file, &syntax, oid, &adapter, state, revision, facts, roots)
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

#[cfg(test)]
mod tests;
