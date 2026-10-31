use crate::analyzer::rust::RustAnalyzer;
use brokk_bifrost_core::analyzer::capabilities::HierarchyAnswer;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::model::Language;

use crate::inline_project::InlineTestProject;
use brokk_bifrost_core::analyzer::capabilities::{
    ImportAnalysisProvider, TypeAliasProvider, TypeHierarchyProvider,
};
use brokk_bifrost_core::analyzer::model::CodeUnitType;
use brokk_bifrost_core::analyzer::project::Project;
use brokk_bifrost_core::analyzer::query_token::QueryScope;
use brokk_bifrost_core::analyzer::usages::model::{
    ExportEntry, ExportIndex, ImportBinder, ReexportStar,
};
use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex, ProjectFile, Range};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use brokk_bifrost_rust::cargo_routes::RustCargoRouteIndex;
use brokk_bifrost_rust::graph_support::{
    ReferenceContextError, ReferenceContextResult, RustCargoRouteError,
    RustDeclarationSourceProperties, RustPackageFileIndex, RustPackageFileRow, RustSource,
    forward_exported_targets_from_files, resolve_direct_import_files, resolve_module_files,
};
use brokk_bifrost_test_macros::hardwon;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

fn package_files(files: &[ProjectFile]) -> Arc<RustPackageFileIndex> {
    Arc::new(RustPackageFileIndex::from_summary_rows(
        files
            .iter()
            .map(|file| RustPackageFileRow {
                file: file.clone(),
                package_components: brokk_bifrost_rust::declarations::rust_package_name(file)
                    .split('.')
                    .map(str::to_owned)
                    .collect(),
                crate_name: String::new(),
                target_kind: String::new(),
                is_root_member: false,
            })
            .collect(),
    ))
}

#[test]
fn package_file_index_reads_live_summary_members_and_crate_roots() {
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"package-index\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file("src/lib.rs", "pub mod nested; pub mod consumer;\n")
        .file("src/nested.rs", "pub fn item() {}\n")
        .file("src/consumer.rs", "use package_index::nested;\n")
        .build();
    let workspace =
        fixture.workspace_analyzer(brokk_bifrost_core::analyzer::config::AnalyzerConfig::default());
    let analyzer =
        brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<RustAnalyzer>(
            workspace.analyzer(),
        )
        .expect("workspace contains the Rust analyzer");
    let consumer = fixture.file("src/consumer.rs");
    let nested = fixture.file("src/nested.rs");
    let scope = AnalyzerQueryScope::new(analyzer);
    let package_files = analyzer
        .package_file_index_while(scope.token(), &|| true)
        .expect("read the live Rust summary package and member rows");

    assert!(package_files.contains(&fixture.file("src/lib.rs")));
    assert!(package_files.contains(&consumer));
    assert!(package_files.contains(&nested));
    assert_eq!(
        resolve_direct_import_files(
            &package_files,
            &consumer,
            &["package_index".to_string(), "nested".to_string()],
        ),
        vec![nested],
        "the normalized crate root routes to its live member summary rows"
    );
}

struct ExportWalkSource {
    project: Arc<dyn Project>,
    analyzed_files: Vec<ProjectFile>,
    package_files: Arc<RustPackageFileIndex>,
    cargo_routes: Arc<RustCargoRouteIndex>,
    export_indices: HashMap<ProjectFile, Arc<ExportIndex>>,
    terminal_module: CodeUnit,
    module_file_resolutions: AtomicUsize,
}

impl CodeUnitIndex for ExportWalkSource {
    fn project(&self) -> &dyn Project {
        self.project.as_ref()
    }

    fn languages(&self) -> BTreeSet<Language> {
        BTreeSet::from([Language::Rust])
    }

    fn analyzed_files(&self) -> Vec<ProjectFile> {
        self.analyzed_files.clone()
    }

    fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        Box::new(std::iter::once(self.terminal_module.clone()))
    }

    fn definitions(&self, fq_name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        if self.terminal_module.fq_name() == fq_name {
            Box::new(std::iter::once(self.terminal_module.clone()))
        } else {
            Box::new(std::iter::empty())
        }
    }

    fn search_definitions(&self, _pattern: &str, _auto_quote: bool) -> BTreeSet<CodeUnit> {
        BTreeSet::new()
    }

    fn enclosing_code_unit(&self, _file: &ProjectFile, _range: &Range) -> Option<CodeUnit> {
        None
    }

    fn enclosing_code_unit_for_lines(
        &self,
        _file: &ProjectFile,
        _start_line: usize,
        _end_line: usize,
    ) -> Option<CodeUnit> {
        None
    }

    fn get_skeleton(&self, _code_unit: &CodeUnit) -> Option<String> {
        None
    }

    fn get_skeleton_header(&self, _code_unit: &CodeUnit) -> Option<String> {
        None
    }

    fn get_source(&self, _code_unit: &CodeUnit, _include_comments: bool) -> Option<String> {
        None
    }

    fn get_sources(&self, _code_unit: &CodeUnit, _include_comments: bool) -> BTreeSet<String> {
        BTreeSet::new()
    }
}

impl ImportAnalysisProvider for ExportWalkSource {
    fn imported_code_units_of(&self, _file: &ProjectFile) -> Arc<HashSet<CodeUnit>> {
        Arc::new(HashSet::default())
    }

    fn referencing_files_of(&self, _file: &ProjectFile) -> HashSet<ProjectFile> {
        HashSet::default()
    }
}

impl TypeAliasProvider for ExportWalkSource {}

impl TypeHierarchyProvider for ExportWalkSource {
    fn get_direct_ancestors(&self, _code_unit: &CodeUnit) -> HierarchyAnswer {
        HierarchyAnswer::complete(Vec::new())
    }

    fn get_direct_descendants(&self, _code_unit: &CodeUnit) -> HierarchyAnswer {
        HierarchyAnswer::complete(Vec::new())
    }
}

impl RustSource for ExportWalkSource {
    fn code_units(&self) -> &dyn CodeUnitIndex {
        self
    }

    fn structural_parent_of(&self, _code_unit: &CodeUnit) -> Option<CodeUnit> {
        None
    }

    fn declaration_candidates_by_fqn_while(
        &self,
        _fq_name: &str,
        keep_going: &dyn Fn() -> bool,
    ) -> ReferenceContextResult<Vec<CodeUnit>> {
        if keep_going() {
            Ok(Vec::new())
        } else {
            Err(ReferenceContextError::Interrupted)
        }
    }

    fn declaration_source_properties(
        &self,
        _file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Arc<RustDeclarationSourceProperties>, RustCargoRouteError> {
        if keep_going() {
            Ok(Arc::new(HashMap::default()))
        } else {
            Err(RustCargoRouteError::Cancelled)
        }
    }

    fn direct_ancestors(
        &self,
        _code_unit: &CodeUnit,
    ) -> Result<Vec<CodeUnit>, RustCargoRouteError> {
        Ok(Vec::new())
    }

    fn prepared_syntax(
        &self,
        _token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
        _file: &ProjectFile,
    ) -> Option<Arc<brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree>> {
        None
    }

    fn cargo_routes(&self) -> Result<Arc<RustCargoRouteIndex>, RustCargoRouteError> {
        Ok(Arc::clone(&self.cargo_routes))
    }

    fn cargo_routes_while(
        &self,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Arc<RustCargoRouteIndex>, RustCargoRouteError> {
        if keep_going() {
            self.cargo_routes()
        } else {
            Err(RustCargoRouteError::Cancelled)
        }
    }

    fn package_file_index_while(
        &self,
        _token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Arc<RustPackageFileIndex>, RustCargoRouteError> {
        if keep_going() {
            Ok(Arc::clone(&self.package_files))
        } else {
            Err(RustCargoRouteError::Cancelled)
        }
    }

    fn import_binder_of(&self, _file: &ProjectFile) -> ImportBinder {
        ImportBinder::empty()
    }

    fn export_index_of(&self, file: &ProjectFile) -> ReferenceContextResult<Arc<ExportIndex>> {
        Ok(self
            .export_indices
            .get(file)
            .cloned()
            .unwrap_or_else(|| Arc::new(ExportIndex::empty())))
    }

    fn export_index_of_while(
        &self,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> ReferenceContextResult<Arc<ExportIndex>> {
        if keep_going() {
            self.export_index_of(file)
        } else {
            Err(ReferenceContextError::Interrupted)
        }
    }

    fn note_module_file_resolution(&self) {
        self.module_file_resolutions.fetch_add(1, Ordering::Relaxed);
    }

    fn note_export_name_canonicalization(&self) {}
}

#[test]
#[hardwon("#4500: nested Rust module re-exports overflowed the resolver stack")]
fn module_reexport_chain_uses_an_explicit_stack() {
    const CHAIN_LENGTH: usize = 10_000;

    let fixture = InlineTestProject::with_language(Language::Rust)
        .file("fixture/src/lib.rs", "")
        .file("fixture/src/terminal.rs", "")
        .file("fixture/src/terminal/leaf.rs", "")
        .build();
    let root = fixture.file("fixture/src/lib.rs");
    let terminal = fixture.file("fixture/src/terminal.rs");
    let leaf = fixture.file("fixture/src/terminal/leaf.rs");
    let analyzed_files = vec![root.clone(), terminal.clone(), leaf.clone()];

    let mut root_exports = ExportIndex::empty();
    for index in 0..CHAIN_LENGTH {
        let (module_specifier, imported_name) = if index + 1 == CHAIN_LENGTH {
            ("crate::terminal".to_string(), "leaf".to_string())
        } else {
            (format!("crate::m{}", index + 1), format!("m{}", index + 1))
        };
        root_exports.exports_by_name.insert(
            format!("m{index}"),
            ExportEntry::ReexportedNamed {
                module_specifier,
                imported_name,
            },
        );
    }
    let mut terminal_exports = ExportIndex::empty();
    terminal_exports.exports_by_name.insert(
        "leaf".to_string(),
        ExportEntry::Local {
            local_name: "leaf".to_string(),
        },
    );
    let mut leaf_exports = ExportIndex::empty();
    for index in 1..CHAIN_LENGTH {
        leaf_exports.exports_by_name.insert(
            format!("m{index}"),
            ExportEntry::ReexportedNamed {
                module_specifier: "crate::terminal".to_string(),
                imported_name: "leaf".to_string(),
            },
        );
    }
    let mut export_indices = HashMap::default();
    export_indices.insert(root.clone(), Arc::new(root_exports));
    export_indices.insert(terminal.clone(), Arc::new(terminal_exports));
    export_indices.insert(leaf.clone(), Arc::new(leaf_exports));

    let terminal_module = CodeUnit::new(
        leaf.clone(),
        CodeUnitType::Module,
        "fixture.src.terminal",
        "leaf",
    );
    assert_eq!(terminal_module.fq_name(), "fixture.src.terminal.leaf");
    let package_files = package_files(&analyzed_files);
    let project = fixture.project_dyn();
    let source = ExportWalkSource {
        project: Arc::clone(&project),
        analyzed_files,
        package_files,
        cargo_routes: Arc::new(RustCargoRouteIndex::default()),
        export_indices,
        terminal_module,
        module_file_resolutions: AtomicUsize::default(),
    };
    let analyzer = RustAnalyzer::new(project);
    let scope = AnalyzerQueryScope::new(&analyzer);

    let files = resolve_module_files(&source, scope.token(), &root, "crate::m0")
        .expect("resolve the generated public module chain");

    assert_eq!(files, vec![leaf]);
}

#[test]
#[hardwon("#4510: an active path-to-module lookup was re-entered through a re-export cycle")]
fn rust_reexport_cycle_does_not_reenter_a_live_module_path_lookup() {
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file("fixture/src/lib.rs", "")
        .build();
    let root = fixture.file("fixture/src/lib.rs");
    let mut exports = ExportIndex::empty();
    exports.exports_by_name.insert(
        "looped".to_string(),
        ExportEntry::ReexportedNamed {
            module_specifier: "crate::looped".to_string(),
            imported_name: "looped".to_string(),
        },
    );
    let mut export_indices = HashMap::default();
    export_indices.insert(root.clone(), Arc::new(exports));
    let analyzed_files = vec![root.clone()];
    let package_files = package_files(&analyzed_files);
    let project = fixture.project_dyn();
    let source = ExportWalkSource {
        project: Arc::clone(&project),
        analyzed_files,
        package_files,
        cargo_routes: Arc::new(RustCargoRouteIndex::default()),
        export_indices,
        terminal_module: CodeUnit::new(root.clone(), CodeUnitType::Module, "fixture.src", "lib"),
        module_file_resolutions: AtomicUsize::default(),
    };
    let analyzer = RustAnalyzer::new(project);
    let scope = AnalyzerQueryScope::new(&analyzer);

    let files = resolve_module_files(&source, scope.token(), &root, "crate::looped")
        .expect("an unresolved cyclic re-export terminates");

    assert!(files.is_empty());
    assert_eq!(source.module_file_resolutions.load(Ordering::Relaxed), 1);
}

#[test]
#[hardwon("#4510: repeated aliases in a diamond re-expanded the same module-path frame")]
fn rust_diamond_reexports_reuse_repeated_alias_path_frames() {
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file("fixture/src/lib.rs", "")
        .file("fixture/src/left.rs", "")
        .file("fixture/src/right.rs", "")
        .file("fixture/src/shared.rs", "")
        .build();
    let root = fixture.file("fixture/src/lib.rs");
    let left = fixture.file("fixture/src/left.rs");
    let right = fixture.file("fixture/src/right.rs");
    let shared = fixture.file("fixture/src/shared.rs");
    let analyzed_files = vec![root.clone(), left.clone(), right.clone(), shared.clone()];

    let mut root_exports = ExportIndex::empty();
    root_exports.reexport_stars = ["crate::left", "crate::left", "crate::right"]
        .into_iter()
        .map(|module_specifier| ReexportStar {
            module_specifier: module_specifier.to_string(),
        })
        .collect();
    let mut left_exports = ExportIndex::empty();
    left_exports.reexport_stars.push(ReexportStar {
        module_specifier: "crate::shared".to_string(),
    });
    let mut right_exports = ExportIndex::empty();
    right_exports.reexport_stars.push(ReexportStar {
        module_specifier: "crate::shared".to_string(),
    });
    let mut shared_exports = ExportIndex::empty();
    shared_exports.exports_by_name.insert(
        "item".to_string(),
        ExportEntry::Local {
            local_name: "Item".to_string(),
        },
    );
    let mut export_indices = HashMap::default();
    export_indices.insert(root.clone(), Arc::new(root_exports));
    export_indices.insert(left.clone(), Arc::new(left_exports));
    export_indices.insert(right.clone(), Arc::new(right_exports));
    export_indices.insert(shared.clone(), Arc::new(shared_exports));
    let package_files = package_files(&analyzed_files);
    let project = fixture.project_dyn();
    let source = ExportWalkSource {
        project: Arc::clone(&project),
        analyzed_files,
        package_files,
        cargo_routes: Arc::new(RustCargoRouteIndex::default()),
        export_indices,
        terminal_module: CodeUnit::new(
            shared.clone(),
            CodeUnitType::Module,
            "fixture.src",
            "shared",
        ),
        module_file_resolutions: AtomicUsize::default(),
    };
    let analyzer = RustAnalyzer::new(project);
    let scope = AnalyzerQueryScope::new(&analyzer);

    let targets = forward_exported_targets_from_files(&source, scope.token(), &[root], "item")
        .expect("the re-export diamond resolves its shared target");

    assert_eq!(targets, BTreeSet::from([(shared, "Item".to_string())]));
    assert_eq!(source.module_file_resolutions.load(Ordering::Relaxed), 4);
}
