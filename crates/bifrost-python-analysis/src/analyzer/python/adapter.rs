//! The `LanguageAdapter` forwarding shell for Python.
//!
//! Every answer below comes from [`brokk_bifrost_python`] except
//! `synthesize_hydrated_units`, which mutates `FileState` -- an analysis type
//! with `pub(crate)` fields that cannot leave this crate.

use brokk_bifrost_analysis::analyzer::cognitive_complexity;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::LanguageAdapter;

use brokk_bifrost_core::analyzer::model::ProjectFile;
use brokk_bifrost_python::adapter::{
    PYTHON_COGNITIVE_CONFIG, PYTHON_FILE_EXTENSION, python_extract_call_receiver,
};
use brokk_bifrost_python::declarations::{
    module_code_unit, parse_python_file, python_module_fq, python_module_name,
};
use brokk_bifrost_python::queries::PYTHON_QUERY_DIRECTORY;
use brokk_bifrost_python::test_detection::python_tree_contains_tests;
use tree_sitter::Tree;

#[derive(Clone, Default)]
pub struct PythonAdapter {
    project: Option<std::sync::Arc<dyn brokk_bifrost_core::analyzer::project::Project>>,
}

impl std::fmt::Debug for PythonAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PythonAdapter").finish_non_exhaustive()
    }
}

impl PythonAdapter {
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn for_test_file(file: &ProjectFile) -> Self {
        Self {
            project: Some(std::sync::Arc::new(
                brokk_bifrost_core::analyzer::project::TestProject::new(
                    file.root(),
                    Language::Python,
                ),
            )),
        }
    }

    pub(crate) fn shared_project(
        &self,
    ) -> std::sync::Arc<dyn brokk_bifrost_core::analyzer::project::Project> {
        std::sync::Arc::clone(
            self.project
                .as_ref()
                .expect("Python adapter is project bound"),
        )
    }

    pub(crate) fn project(&self) -> &dyn brokk_bifrost_core::analyzer::project::Project {
        self.project
            .as_deref()
            .expect("Python adapter must be bound to its selected project")
    }
}

impl PythonAdapter {
    fn module_components_with_conn(
        &self,
        conn: &rusqlite::Connection,
        file: &ProjectFile,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<Vec<String>> {
        if let Some(name) = self.project().selected_module_name_with_conn(conn, file)? {
            return brokk_bifrost_python::declarations::python_module_components_from_name(
                file, &name,
            )
            .ok_or_else(|| {
                brokk_bifrost_analysis::analyzer::store::StoreError::corrupt(format!(
                    "published Python module {name:?} is not a suffix of its mounted path {:?}",
                    file.rel_path()
                ))
            });
        }
        // Empty package files and unpublished mounts still need the selected
        // packaging inputs. Both paths must use the caller's existing read.
        struct Inputs<'a> {
            project: &'a dyn brokk_bifrost_core::analyzer::project::Project,
            conn: &'a rusqlite::Connection,
        }
        impl brokk_bifrost_python::declarations::PythonImportRootInputs for Inputs<'_> {
            fn contains(&self, path: &std::path::Path) -> bool {
                self.project.file_by_rel_path(path).is_some()
            }
            fn configuration_source(
                &self,
                path: &std::path::Path,
            ) -> std::io::Result<Option<std::borrow::Cow<'_, str>>> {
                self.project
                    .configuration_source_with_conn(self.conn, path)
                    .map(|source| source.map(std::borrow::Cow::Owned))
            }
        }
        Ok(
            brokk_bifrost_python::declarations::python_module_components_with_inputs(
                file,
                &Inputs {
                    project: self.project(),
                    conn,
                },
            )?,
        )
    }
    fn synthesize_module(
        source: &str,
        state: &mut brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::FileState,
        module: Option<CodeUnit>,
    ) {
        let Some(module) = module else {
            return;
        };
        state.top_level_declarations.insert(0, module.clone());
        state.declarations.insert(module.clone());
        state.ranges.entry(module.clone()).or_default().push(
            brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::full_source_range(source),
        );
        let module_children: Vec<_> = state
            .top_level_declarations
            .iter()
            .filter(|unit| !unit.is_module() && !unit.is_file_scope())
            .filter(|unit| !unit.short_name().contains(['.', '$']))
            .cloned()
            .collect();
        if !module_children.is_empty() {
            state.children.insert(module, module_children);
        }
    }
}

impl LanguageAdapter for PythonAdapter {
    fn for_project(
        &self,
        project: std::sync::Arc<dyn brokk_bifrost_core::analyzer::project::Project>,
    ) -> Option<Self> {
        Some(Self {
            project: Some(project),
        })
    }

    fn supports_structural_line_data(&self) -> bool {
        true
    }

    fn is_structural_line_data(
        &self,
        node: tree_sitter::Node<'_>,
        should_stop: &mut dyn FnMut() -> bool,
    ) -> std::ops::ControlFlow<(), bool> {
        brokk_bifrost_python::adapter::is_string_line_data(node, should_stop)
    }

    /// Relative to `brokk-bifrost-python`'s crate root: the `.scm` assets moved
    /// with the language knowledge and are embedded there.
    fn query_directory(&self) -> &'static str {
        PYTHON_QUERY_DIRECTORY
    }

    fn file_extension(&self) -> &'static str {
        PYTHON_FILE_EXTENSION
    }

    fn persisted_content_qualifier_supports_substring_search(&self) -> bool {
        false
    }

    /// Every Python declaration is packaged by the module its file backs, so
    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        tree: &Tree,
        _parsed: &brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
    ) -> bool {
        python_tree_contains_tests(tree.root_node(), source)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        python_extract_call_receiver(reference)
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> brokk_bifrost_core::analyzer::parsed_file::ParsedFile {
        #[cfg(any(test, feature = "test-support"))]
        if super::trial_native_python_selected() {
            return brokk_bifrost_python::declarations::parse_python_file_with_native_facts(
                self.project(),
                file,
                source,
                tree,
            );
        }
        parse_python_file(self.project(), file, source, tree)
    }

    fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
        Some(&PYTHON_COGNITIVE_CONFIG)
    }
}

impl brokk_bifrost_analysis::analyzer::store::StoreLanguageAdapter for PythonAdapter {
    fn source_fact_storage(
        &self,
    ) -> Option<&'static brokk_bifrost_analysis::analyzer::store::source_facts::SourceFactStorage>
    {
        Some(&crate::analyzer::python::source_publication::SOURCE_STORAGE)
    }
    fn python_source_facts_version(&self) -> Option<i64> {
        Some(brokk_bifrost_core::analyzer::python_facts::PYTHON_SOURCE_FACTS_VERSION)
    }
    fn language(&self) -> Language {
        Language::Python
    }
    fn storage_content_qualifier(&self, _code_unit: &CodeUnit, _content_qualifier: &str) -> String {
        String::new()
    }
    fn storage_file_content_qualifier(&self, _package_name: &str) -> String {
        String::new()
    }
    fn hydrate_content_qualifier(
        &self,
        _content_qualifier: &str,
        file: &ProjectFile,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<String> {
        Ok(self
            .project()
            .selected_module_name(file)?
            .unwrap_or_else(|| python_module_name(self.project(), file)))
    }
    fn hydrate_content_qualifier_with_conn(
        &self,
        conn: &rusqlite::Connection,
        _content_qualifier: &str,
        file: &ProjectFile,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<String> {
        Ok(self.module_components_with_conn(conn, file)?.join("."))
    }
    fn hydrate_package_anchor(
        &self,
        anchor: brokk_bifrost_core::analyzer::model::PackageAnchor,
        qualifier: &str,
        file: &ProjectFile,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<
        Option<brokk_bifrost_core::analyzer::fq_name::FqName>,
    > {
        if anchor == (brokk_bifrost_core::analyzer::model::PackageAnchor::OwnModule { pop: 0 })
            && let Some(name) = self.project().selected_module_name(file)?
        {
            let components =
                brokk_bifrost_python::declarations::python_module_components_from_name(file, &name)
                    .ok_or_else(|| brokk_bifrost_analysis::analyzer::store::StoreError::corrupt(
                        format!("published Python module {name:?} is not a suffix of its mounted path {:?}", file.rel_path()),
                    ))?;
            return Ok(Some(
                brokk_bifrost_core::analyzer::fq_name::FqName::from_package_components(&components),
            ));
        }
        Ok(self.resolve_package_anchor(anchor, qualifier, file))
    }
    fn hydrate_package_anchor_with_conn(
        &self,
        conn: &rusqlite::Connection,
        anchor: brokk_bifrost_core::analyzer::model::PackageAnchor,
        qualifier: &str,
        file: &ProjectFile,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<
        Option<brokk_bifrost_core::analyzer::fq_name::FqName>,
    > {
        if anchor == (brokk_bifrost_core::analyzer::model::PackageAnchor::OwnModule { pop: 0 }) {
            let components = self.module_components_with_conn(conn, file)?;
            return Ok(Some(
                brokk_bifrost_core::analyzer::fq_name::FqName::from_package_components(&components),
            ));
        }
        Ok(self.resolve_package_anchor(anchor, qualifier, file))
    }
    fn default_package_anchor(&self) -> Option<brokk_bifrost_core::analyzer::model::PackageAnchor> {
        Some(brokk_bifrost_core::analyzer::model::PackageAnchor::OwnModule { pop: 0 })
    }
    fn resolve_package_anchor(
        &self,
        anchor: brokk_bifrost_core::analyzer::model::PackageAnchor,
        _content_qualifier: &str,
        file: &ProjectFile,
    ) -> Option<brokk_bifrost_core::analyzer::fq_name::FqName> {
        match anchor {
            brokk_bifrost_core::analyzer::model::PackageAnchor::OwnModule { pop: 0 } => {
                Some(python_module_fq(self.project(), file))
            }
            _ => None,
        }
    }
    fn should_persist_code_unit(&self, code_unit: &CodeUnit) -> bool {
        brokk_bifrost_analysis::analyzer::common::should_persist_code_unit(code_unit)
    }
    fn synthesize_hydrated_units(
        &self,
        file: &ProjectFile,
        source: &str,
        state: &mut brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::FileState,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<()> {
        Self::synthesize_module(
            source,
            state,
            self.hydrate_path_synthetic_module_unit(file)?,
        );
        Ok(())
    }
    fn synthesize_hydrated_units_with_conn(
        &self,
        conn: &rusqlite::Connection,
        file: &ProjectFile,
        source: &str,
        state: &mut brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::FileState,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<()> {
        let module = self.hydrate_path_synthetic_module_unit_with_conn(conn, file)?;
        Self::synthesize_module(source, state, module);
        Ok(())
    }
    fn path_synthetic_module_unit(&self, file: &ProjectFile) -> Option<CodeUnit> {
        module_code_unit(self.project(), file)
    }
    fn path_synthetic_module_from_published_name(
        &self,
        file: &ProjectFile,
        name: &str,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<Option<CodeUnit>> {
        brokk_bifrost_python::declarations::module_code_unit_from_name(file, name)
            .map(Some)
            .ok_or_else(|| {
                brokk_bifrost_analysis::analyzer::store::StoreError::corrupt(format!(
                    "published Python module {name:?} is not a suffix of its mounted path {:?}",
                    file.rel_path()
                ))
            })
    }
    fn hydrate_path_synthetic_module_unit(
        &self,
        file: &ProjectFile,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<Option<CodeUnit>> {
        match self.project().selected_module_name(file)? {
            Some(name) => self.path_synthetic_module_from_published_name(file, &name),
            None => Ok(module_code_unit(self.project(), file)),
        }
    }
    fn hydrate_path_synthetic_module_unit_with_conn(
        &self,
        conn: &rusqlite::Connection,
        file: &ProjectFile,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<Option<CodeUnit>> {
        let components = self.module_components_with_conn(conn, file)?;
        Ok(brokk_bifrost_python::declarations::module_code_unit_from_components(file, &components))
    }
    fn has_path_synthetic_module_units(&self) -> bool {
        true
    }
    fn requires_source_declaration_metadata_bridges(&self) -> bool {
        true
    }
    fn produces_canonical_source_facts(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod published_module_read_tests {
    use super::*;
    use brokk_bifrost_analysis::analyzer::store::StoreLanguageAdapter;
    use brokk_bifrost_core::analyzer::model::PackageAnchor;
    use brokk_bifrost_core::analyzer::project::{Project, TestProject};
    use std::collections::BTreeSet;
    use std::path::Path;

    struct PublishedModuleProject {
        inner: TestProject,
        name: Option<&'static str>,
        probes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Project for PublishedModuleProject {
        fn root(&self) -> &Path {
            self.inner.root()
        }
        fn analyzer_languages(&self) -> BTreeSet<Language> {
            self.inner.analyzer_languages()
        }
        fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.inner.all_files()
        }
        fn analyzable_files(&self, language: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.inner.analyzable_files(language)
        }
        fn file_by_rel_path(&self, path: &Path) -> Option<ProjectFile> {
            self.probes
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.inner.file_by_rel_path(path)
        }
        fn selected_module_name(&self, _file: &ProjectFile) -> std::io::Result<Option<String>> {
            self.name.map(|name| Some(name.to_owned())).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "selected module read denied",
                )
            })
        }
    }

    #[test]
    fn path_module_set_reconstructs_src_layout_packages_and_root_initializer() {
        use crate::analyzer::python::PythonAnalyzer;
        use brokk_bifrost_analysis::analyzer::{
            AnalyzerQueryScope, multi_analyzer::resolve_analyzer,
        };
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Python)
            .file(
                "setup.py",
                "from setuptools import setup\nsetup(packages=['pkg'], package_dir={'': 'src'})\n",
            )
            .file("src/__init__.py", "# import-root initializer\n")
            .file("src/pkg/__init__.py", "from .module import Item\n")
            .file("src/pkg/module.py", "class Item: pass\n")
            .build();
        for _ in 0..2 {
            let workspace = fixture.workspace_analyzer(Default::default());
            let python = resolve_analyzer::<PythonAnalyzer>(workspace.analyzer()).unwrap();
            let analyzer = &python.inner;
            let scope = AnalyzerQueryScope::capturing_read_incompleteness(workspace.analyzer());
            let kept = analyzer
                .path_synthetic_modules_named_for_test("module")
                .unwrap();
            assert_eq!(
                kept.iter().map(CodeUnit::fq_name).collect::<Vec<_>>(),
                ["pkg.module"]
            );
            assert_eq!(analyzer.path_synthetic_module_hydrations_for_test(), 1);
            let modules = analyzer.path_synthetic_modules_for_test().unwrap();
            let mut names = modules.iter().map(CodeUnit::fq_name).collect::<Vec<_>>();
            names.sort();
            assert_eq!(names, ["__init__", "pkg", "pkg.module", "setup"]);
            assert!(scope.store_error().is_none(), "{:?}", scope.store_error());
            assert!(scope.captured_read_incompleteness().is_empty());
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#7347: Python hydration hooks nested a read on the single connection store"
    )]
    fn python_store_hydration_reuses_single_connection() {
        use super::super::PythonAnalyzer;
        use crate::inline_project::InlineTestProject;
        use brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer;
        use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
        use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;
        use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::store_context_from_store;
        use brokk_bifrost_core::hash::HashMap;

        let source =
            "from .other import value\nclass Widget:\n    def render(self): return value\n";
        let project = InlineTestProject::with_language(Language::Python)
            .file(
                "pyproject.toml",
                "[tool.setuptools.packages.find]\nwhere = ['src']\n",
            )
            .file("src/pkg/__init__.py", "")
            .file("src/pkg/tool.py", source)
            .file("src/pkg/other.py", "value = 1\n")
            .file("src/pkg/empty/__init__.py", "")
            .file("src/__init__.py", "")
            .build();
        let context = store_context_from_store(
            project.project_dyn().as_ref(),
            AnalyzerStore::open_in_memory_single_connection().unwrap(),
            false,
        );
        let store = context.store.clone();
        let workspace = WorkspaceAnalyzer::build_with_store_context_for_test(
            project.project_dyn(),
            Default::default(),
            context,
        )
        .unwrap();
        let python = resolve_analyzer::<PythonAnalyzer>(workspace.analyzer()).unwrap();
        let adapter = python.inner.adapter();
        let file = project.file("src/pkg/tool.py");
        let oid = python.inner.resolve_live_oid_for_file(&file).unwrap();
        let generation = store.current_generation("python").unwrap();
        let entries = [(file.clone(), oid)];
        let key = brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "python");
        let keyed = [(file.clone(), key.clone())];
        let generations = HashMap::from_iter([("python".to_owned(), generation)]);
        let sources = HashMap::from_iter([(file.clone(), source.to_owned())]);
        let disk_root = tempfile::tempdir().unwrap();
        let disk_context = store_context_from_store(
            project.project_dyn().as_ref(),
            AnalyzerStore::open_persistent(&disk_root.path().join("control.db")).unwrap(),
            false,
        );
        let disk_store = disk_context.store.clone();
        assert!(!disk_store.uses_single_connection_reads());
        let disk_workspace = WorkspaceAnalyzer::build_with_store_context_for_test(
            project.project_dyn(),
            Default::default(),
            disk_context,
        )
        .unwrap();
        let disk_python = resolve_analyzer::<PythonAnalyzer>(disk_workspace.analyzer()).unwrap();
        let disk_generation = disk_store.current_generation("python").unwrap();
        let disk_imports = disk_store
            .hydrate_import_facts_by_key(
                &keyed,
                &HashMap::from_iter([("python".to_owned(), disk_generation)]),
                disk_python.inner.adapter(),
            )
            .unwrap();
        for imports in [
            store
                .hydrate_import_facts_by_key(&keyed, &generations, adapter)
                .unwrap(),
            store
                .hydrate_canonical_import_facts_by_key(&keyed, &generations, adapter)
                .unwrap(),
        ] {
            assert_eq!(
                imports[&file].package_name,
                disk_imports[&file].package_name
            );
            assert_eq!(imports[&file].package_name, "pkg.tool");
            assert_eq!(imports[&file].imports.len(), 1);
        }
        let single = store
            .hydrate_file_state_with_source(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "python"),
                generation,
                adapter,
                &file,
                source,
            )
            .unwrap()
            .unwrap();
        let bulk = store
            .hydrate_file_states(&entries, &key, adapter, &sources)
            .unwrap();
        let keyed_states = store
            .hydrate_file_states_by_key(&keyed, &generations, adapter, &sources)
            .unwrap();
        for state in [&single, &bulk[&file], &keyed_states[&file]] {
            assert_eq!(state.package_name, "pkg.tool");
            assert!(
                state
                    .declarations
                    .iter()
                    .any(|unit| unit.fq_name() == "pkg.tool.Widget.render")
            );
            assert!(
                state
                    .declarations
                    .iter()
                    .any(|unit| unit.is_module() && unit.fq_name() == "pkg.tool")
            );
        }
        // Point and set queries hydrate both content declarations and path-only
        // module units while their relational read transaction is open.
        use brokk_bifrost_analysis::analyzer::store::relational_query::RelationalStoreOutcome;
        use brokk_bifrost_core::analyzer::{
            DefinitionLanguageScope, RelationalDefinitionQuery, RelationalDefinitionRequest,
            RelationalDefinitionValue,
        };
        let targets = [
            single
                .declarations
                .iter()
                .find(|unit| unit.is_module())
                .unwrap(),
            single
                .declarations
                .iter()
                .find(|unit| unit.fq_name() == "pkg.tool.Widget.render")
                .unwrap(),
        ];
        let requests = (0..128)
            .map(|ordinal| RelationalDefinitionRequest {
                ordinal,
                language_scope: DefinitionLanguageScope::Language(Language::Python),
                name: python.inner.relational_name_for_unit(targets[ordinal % 2]),
                query: RelationalDefinitionQuery::ExactName,
            })
            .collect::<Vec<_>>();
        for requests in [&requests[..2], &requests[..]] {
            let outcome = store
                .relational_definition_values(
                    adapter,
                    project.root(),
                    &generations,
                    &["python".to_owned()],
                    python.inner.selected_workspace_snapshots().as_ref(),
                    requests,
                    &brokk_bifrost_core::CancellationToken::default(),
                    |_| {},
                )
                .unwrap();
            let RelationalStoreOutcome::Complete(values) = outcome else {
                panic!("uncancelled definition hydration must complete");
            };
            assert_eq!(values.len(), requests.len());
            for (index, value) in values.iter().enumerate() {
                let RelationalDefinitionValue::Definitions(units) = value else {
                    panic!("exact-name lookup must return definitions");
                };
                assert_eq!(units, &[targets[index % 2].clone()]);
            }
        }
        // Hydrate a mount without a published anchor after the disk config has
        // changed. The selected revision must still name it from retained src.
        project
            .file("pyproject.toml")
            .write("[tool.setuptools.packages.find]\nwhere = ['.']\n")
            .unwrap();
        let unpublished = project.file("src/pkg/unpublished.py");
        let mounted = store
            .hydrate_file_state_with_source(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "python"),
                generation,
                adapter,
                &unpublished,
                source,
            )
            .unwrap()
            .unwrap();
        assert_eq!(mounted.package_name, "pkg.unpublished");
        assert!(
            mounted
                .declarations
                .iter()
                .any(|unit| unit.fq_name() == "pkg.unpublished.Widget.render")
        );
        for (path, name) in [
            ("src/pkg/empty/__init__.py", "pkg.empty"),
            ("src/__init__.py", "__init__"),
        ] {
            let empty = project.file(path);
            let empty_oid = python.inner.resolve_live_oid_for_file(&empty).unwrap();
            let empty_state = store
                .hydrate_file_state_with_source(
                    &brokk_bifrost_core::gitblob::BlobKey::unvaried(empty_oid, "python"),
                    generation,
                    adapter,
                    &empty,
                    "",
                )
                .unwrap()
                .unwrap();
            assert_eq!(empty_state.package_name, name);
            assert!(
                empty_state
                    .declarations
                    .iter()
                    .any(|unit| unit.is_module() && unit.fq_name() == name)
            );
        }
        let summary = store
            .summary_file_projection(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "python"),
                generation,
                adapter,
                &file,
                source,
            )
            .unwrap()
            .unwrap();
        assert!(
            summary
                .declarations
                .iter()
                .any(|unit| unit.fq_name() == "pkg.tool.Widget.render")
        );
        let enclosing = store
            .enclosing_declarations_for_file(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "python"),
                generation,
                adapter,
                &file,
            )
            .unwrap()
            .unwrap();
        assert!(
            enclosing
                .iter()
                .any(|(unit, _)| unit.fq_name() == "pkg.tool.Widget.render")
        );
        assert!(
            store
                .type_aliases_for_file(
                    &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "python"),
                    generation,
                    adapter,
                    &file
                )
                .unwrap()
                .unwrap()
                .is_empty()
        );
        let units = store
            .read_source_transaction("python", generation, |conn| {
                brokk_bifrost_analysis::analyzer::store::read_source_unit_map(
                    conn,
                    &key,
                    adapter,
                    &file,
                    &|| true,
                )
            })
            .unwrap()
            .unwrap();
        assert!(
            units
                .values()
                .any(|unit| unit.fq_name() == "pkg.tool.Widget.render")
        );
    }

    #[test]
    fn published_module_hydration_reports_read_failures_and_corrupt_names() {
        let root = tempfile::tempdir().unwrap();
        let file = ProjectFile::new(root.path(), "pkg/tool.py");
        let probes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let adapter = |name| PythonAdapter {
            project: Some(std::sync::Arc::new(PublishedModuleProject {
                inner: TestProject::new(root.path(), Language::Python),
                name,
                probes: probes.clone(),
            })),
        };
        let failed = adapter(None);
        for error in [
            failed.hydrate_content_qualifier("", &file).unwrap_err(),
            failed
                .hydrate_package_anchor(PackageAnchor::OwnModule { pop: 0 }, "", &file)
                .unwrap_err(),
            failed
                .hydrate_path_synthetic_module_unit(&file)
                .unwrap_err(),
        ] {
            assert!(
                error.to_string().contains("selected module read denied"),
                "{error}"
            );
        }
        let corrupt = adapter(Some("other.tool"));
        for error in [
            corrupt
                .hydrate_package_anchor(PackageAnchor::OwnModule { pop: 0 }, "", &file)
                .unwrap_err(),
            corrupt
                .hydrate_path_synthetic_module_unit(&file)
                .unwrap_err(),
        ] {
            assert!(error.is_corrupt(), "{error:?}");
            assert!(error.to_string().contains("other.tool"), "{error}");
        }

        assert_eq!(
            probes.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "fallible store hydration must not fall back to probes"
        );
        let diagnostic = tempfile::NamedTempFile::new().unwrap();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(std::sync::Mutex::new(diagnostic.reopen().unwrap()))
            .with_ansi(false)
            .without_time()
            .with_max_level(tracing::Level::WARN)
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let valid = adapter(Some("pkg.tool"));
            assert_eq!(
                brokk_bifrost_python::imports::resolve_python_relative_module(
                    valid.project(),
                    &file,
                    ".sibling"
                ),
                Some("pkg.sibling".to_owned())
            );
            assert_eq!(
                probes.load(std::sync::atomic::Ordering::Relaxed),
                0,
                "consistent published identity must not probe"
            );
            for project in [corrupt.project(), failed.project()] {
                probes.store(0, std::sync::atomic::Ordering::Relaxed);
                assert_eq!(
                    brokk_bifrost_python::imports::resolve_python_relative_module(
                        project, &file, ".sibling"
                    ),
                    Some("pkg.sibling".to_owned())
                );
                assert!(
                    probes.load(std::sync::atomic::Ordering::Relaxed) > 0,
                    "the infallible import boundary must actually run the existing probes"
                );
            }
        });
        let diagnostic = std::fs::read_to_string(diagnostic.path()).unwrap();
        assert_eq!(diagnostic.lines().count(), 2, "{diagnostic}");
        for field in [
            "WARN",
            "file=",
            "tool.py",
            "published_name=other.tool",
            "mounted_path=",
            "selected module read denied",
        ] {
            assert!(
                diagnostic.contains(field),
                "missing {field:?}: {diagnostic}"
            );
        }
    }
}
