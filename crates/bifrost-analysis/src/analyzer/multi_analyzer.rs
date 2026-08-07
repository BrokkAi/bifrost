use crate::analyzer::common::language_for_file;
use crate::analyzer::jvm::realm_builder::jvm_source_realm;
use crate::analyzer::store::StoreError;
use crate::analyzer::{
    AnalyzerConfig, AnalyzerStoreContext, BuildProgress, CSharpAnalyzer, CloneSmell,
    CloneSmellWeights, CodeUnit, CommentDensityStats, CppAnalyzer, DeclarationInfo,
    DefinitionIndexHandle, ExceptionHandlingAnalysis, ExceptionSmellWeights, GoAnalyzer, IAnalyzer,
    ImportAnalysisProvider, ImportInfo, ImportReachability, JavaAnalyzer, JavascriptAnalyzer,
    KotlinAnalyzer, Language, PhpAnalyzer, Project, ProjectFile, PythonAnalyzer, Range,
    RubyAnalyzer, RustAnalyzer, ScalaAnalyzer, SearchSymbolCandidates, SearchSymbolPatternBatch,
    SemanticDiagnostic, SignatureMetadata, SummaryFileProjection, TestAssertionAnalysis,
    TestAssertionSmell, TestAssertionWeights, TestDetectionProvider, TypeAliasProvider,
    TypeHierarchyProvider, TypescriptAnalyzer,
};
use crate::hash::{HashMap, HashSet};
use crate::profiling;
use brokk_bifrost_jvm::realm::JvmSourceRealm;
use rayon::prelude::*;
use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

/// Resolve a concrete analyzer of type `T` out of a `&dyn IAnalyzer`, whether it is
/// that analyzer directly or a [`MultiAnalyzer`] holding it as a per-language delegate.
///
/// The contract: `T` must be a concrete analyzer type (`RustAnalyzer`,
/// `CppAnalyzer`, ...); `None` means the workspace holds no analyzer of that
/// type, which callers treat as "no declarations of that language exist" --
/// never as an error. This is the one supported downcast from the framework's
/// `&dyn IAnalyzer` into a language analyzer; host crates (e.g. the LSP
/// handlers) call it rather than re-deriving the delegate walk.
pub fn resolve_analyzer<T: Any>(analyzer: &dyn IAnalyzer) -> Option<&T> {
    if let Some(direct) = (analyzer as &dyn Any).downcast_ref::<T>() {
        return Some(direct);
    }
    let multi = (analyzer as &dyn Any).downcast_ref::<MultiAnalyzer>()?;
    multi
        .delegates()
        .values()
        .find_map(|delegate| (delegate.analyzer() as &dyn Any).downcast_ref::<T>())
}

#[derive(Clone)]
pub enum AnalyzerDelegate {
    Java(JavaAnalyzer),
    CSharp(CSharpAnalyzer),
    Cpp(CppAnalyzer),
    Go(GoAnalyzer),
    JavaScript(JavascriptAnalyzer),
    Php(PhpAnalyzer),
    Python(PythonAnalyzer),
    TypeScript(TypescriptAnalyzer),
    Rust(RustAnalyzer),
    Scala(ScalaAnalyzer),
    Ruby(RubyAnalyzer),
    Kotlin(KotlinAnalyzer),
}

impl AnalyzerDelegate {
    pub(crate) fn analyzer(&self) -> &dyn IAnalyzer {
        match self {
            Self::Java(analyzer) => analyzer,
            Self::CSharp(analyzer) => analyzer,
            Self::Cpp(analyzer) => analyzer,
            Self::Go(analyzer) => analyzer,
            Self::JavaScript(analyzer) => analyzer,
            Self::Php(analyzer) => analyzer,
            Self::Python(analyzer) => analyzer,
            Self::TypeScript(analyzer) => analyzer,
            Self::Rust(analyzer) => analyzer,
            Self::Scala(analyzer) => analyzer,
            Self::Ruby(analyzer) => analyzer,
            Self::Kotlin(analyzer) => analyzer,
        }
    }

    pub(crate) fn program_semantics_provider(
        &self,
    ) -> &dyn crate::analyzer::semantic::ProgramSemanticsProvider {
        match self {
            Self::Java(analyzer) => analyzer,
            Self::CSharp(analyzer) => analyzer,
            Self::Cpp(analyzer) => analyzer,
            Self::Go(analyzer) => analyzer,
            Self::JavaScript(analyzer) => analyzer,
            Self::Php(analyzer) => analyzer,
            Self::Python(analyzer) => analyzer,
            Self::TypeScript(analyzer) => analyzer,
            Self::Rust(analyzer) => analyzer,
            Self::Scala(analyzer) => analyzer,
            Self::Ruby(analyzer) => analyzer,
            Self::Kotlin(analyzer) => analyzer,
        }
    }

    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        match self {
            Self::Java(analyzer) => Self::Java(analyzer.clone_with_project(project)),
            Self::CSharp(analyzer) => Self::CSharp(analyzer.clone_with_project(project)),
            Self::Cpp(analyzer) => Self::Cpp(analyzer.clone_with_project(project)),
            Self::Go(analyzer) => Self::Go(analyzer.clone_with_project(project)),
            Self::JavaScript(analyzer) => Self::JavaScript(analyzer.clone_with_project(project)),
            Self::Php(analyzer) => Self::Php(analyzer.clone_with_project(project)),
            Self::Python(analyzer) => Self::Python(analyzer.clone_with_project(project)),
            Self::TypeScript(analyzer) => Self::TypeScript(analyzer.clone_with_project(project)),
            Self::Rust(analyzer) => Self::Rust(analyzer.clone_with_project(project)),
            Self::Scala(analyzer) => Self::Scala(analyzer.clone_with_project(project)),
            Self::Ruby(analyzer) => Self::Ruby(analyzer.clone_with_project(project)),
            Self::Kotlin(analyzer) => Self::Kotlin(analyzer.clone_with_project(project)),
        }
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        match self {
            Self::Java(analyzer) => Some(analyzer),
            Self::CSharp(analyzer) => Some(analyzer),
            Self::Cpp(analyzer) => Some(analyzer),
            Self::Go(analyzer) => Some(analyzer),
            Self::JavaScript(analyzer) => Some(analyzer),
            Self::Php(analyzer) => analyzer.import_analysis_provider(),
            Self::Python(analyzer) => Some(analyzer),
            Self::TypeScript(analyzer) => Some(analyzer),
            Self::Rust(analyzer) => Some(analyzer),
            Self::Scala(analyzer) => analyzer.import_analysis_provider(),
            Self::Ruby(analyzer) => Some(analyzer),
            Self::Kotlin(analyzer) => Some(analyzer),
        }
    }

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        match self {
            Self::Java(analyzer) => Some(analyzer),
            Self::CSharp(analyzer) => analyzer.type_hierarchy_provider(),
            Self::Cpp(analyzer) => analyzer.type_hierarchy_provider(),
            Self::Go(analyzer) => analyzer.type_hierarchy_provider(),
            Self::JavaScript(analyzer) => analyzer.type_hierarchy_provider(),
            Self::Php(analyzer) => analyzer.type_hierarchy_provider(),
            Self::Python(analyzer) => Some(analyzer),
            Self::TypeScript(analyzer) => analyzer.type_hierarchy_provider(),
            Self::Rust(analyzer) => analyzer.type_hierarchy_provider(),
            Self::Scala(analyzer) => analyzer.type_hierarchy_provider(),
            Self::Ruby(analyzer) => Some(analyzer),
            Self::Kotlin(analyzer) => analyzer.type_hierarchy_provider(),
        }
    }

    fn type_alias_provider(&self) -> Option<&dyn TypeAliasProvider> {
        match self {
            Self::Java(analyzer) => analyzer.type_alias_provider(),
            Self::CSharp(analyzer) => analyzer.type_alias_provider(),
            Self::Cpp(analyzer) => analyzer.type_alias_provider(),
            Self::Go(analyzer) => analyzer.type_alias_provider(),
            Self::JavaScript(analyzer) => analyzer.type_alias_provider(),
            Self::Php(analyzer) => analyzer.type_alias_provider(),
            Self::Python(analyzer) => analyzer.type_alias_provider(),
            Self::TypeScript(analyzer) => analyzer.type_alias_provider(),
            Self::Rust(analyzer) => analyzer.type_alias_provider(),
            Self::Scala(analyzer) => analyzer.type_alias_provider(),
            Self::Ruby(analyzer) => analyzer.type_alias_provider(),
            Self::Kotlin(analyzer) => analyzer.type_alias_provider(),
        }
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        match self {
            Self::Java(analyzer) => Some(analyzer),
            Self::CSharp(analyzer) => Some(analyzer),
            Self::Cpp(analyzer) => analyzer.test_detection_provider(),
            Self::Go(analyzer) => Some(analyzer),
            Self::JavaScript(analyzer) => Some(analyzer),
            Self::Php(analyzer) => Some(analyzer),
            Self::Python(analyzer) => Some(analyzer),
            Self::TypeScript(analyzer) => Some(analyzer),
            Self::Rust(analyzer) => Some(analyzer),
            Self::Scala(analyzer) => Some(analyzer),
            Self::Ruby(analyzer) => Some(analyzer),
            Self::Kotlin(analyzer) => Some(analyzer),
        }
    }

    pub(crate) fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        match self {
            Self::Java(analyzer) => Self::Java(analyzer.update(changed_files)),
            Self::CSharp(analyzer) => Self::CSharp(analyzer.update(changed_files)),
            Self::Cpp(analyzer) => Self::Cpp(analyzer.update(changed_files)),
            Self::Go(analyzer) => Self::Go(analyzer.update(changed_files)),
            Self::JavaScript(analyzer) => Self::JavaScript(analyzer.update(changed_files)),
            Self::Php(analyzer) => Self::Php(analyzer.update(changed_files)),
            Self::Python(analyzer) => Self::Python(analyzer.update(changed_files)),
            Self::TypeScript(analyzer) => Self::TypeScript(analyzer.update(changed_files)),
            Self::Rust(analyzer) => Self::Rust(analyzer.update(changed_files)),
            Self::Scala(analyzer) => Self::Scala(analyzer.update(changed_files)),
            Self::Ruby(analyzer) => Self::Ruby(analyzer.update(changed_files)),
            Self::Kotlin(analyzer) => Self::Kotlin(analyzer.update(changed_files)),
        }
    }

    fn should_receive_changed_file(&self, language: Language, file: &ProjectFile) -> bool {
        language_for_file(file) == language
            || self.analyzer().is_analyzed(file)
            || self.needs_config_update_for(file)
    }

    fn needs_config_update_for(&self, file: &ProjectFile) -> bool {
        match self {
            Self::Java(_) | Self::Scala(_) | Self::Kotlin(_) => {
                crate::analyzer::jvm::dependency_discovery::is_jvm_dependency_input(file)
            }
            Self::CSharp(_) => crate::analyzer::csharp::is_csharp_dependency_input(file),
            Self::JavaScript(_) | Self::TypeScript(_) => is_js_ts_config_file(file),
            _ => false,
        }
    }

    pub(crate) fn update_all(&self) -> Self {
        match self {
            Self::Java(analyzer) => Self::Java(analyzer.update_all()),
            Self::CSharp(analyzer) => Self::CSharp(analyzer.update_all()),
            Self::Cpp(analyzer) => Self::Cpp(analyzer.update_all()),
            Self::Go(analyzer) => Self::Go(analyzer.update_all()),
            Self::JavaScript(analyzer) => Self::JavaScript(analyzer.update_all()),
            Self::Php(analyzer) => Self::Php(analyzer.update_all()),
            Self::Python(analyzer) => Self::Python(analyzer.update_all()),
            Self::TypeScript(analyzer) => Self::TypeScript(analyzer.update_all()),
            Self::Rust(analyzer) => Self::Rust(analyzer.update_all()),
            Self::Scala(analyzer) => Self::Scala(analyzer.update_all()),
            Self::Ruby(analyzer) => Self::Ruby(analyzer.update_all()),
            Self::Kotlin(analyzer) => Self::Kotlin(analyzer.update_all()),
        }
    }
}

/// Construct the concrete analyzer serving `language`.
///
/// Assembly-layer code: this is the one place outside the registry allowed to name
/// concrete per-language analyzer types, because concrete storage and construction is
/// what [`AnalyzerDelegate`] is for.
pub(crate) fn build_language_delegate(
    language: Language,
    project: Arc<dyn Project>,
    config: AnalyzerConfig,
    mut store_context: AnalyzerStoreContext,
    progress: Option<BuildProgress>,
    revalidate_filesystem_paths: bool,
) -> Result<AnalyzerDelegate, StoreError> {
    let _scope = profiling::scope(format!("WorkspaceAnalyzer::build[{language:?}]"));
    store_context.live_paths = Arc::new(if revalidate_filesystem_paths {
        crate::analyzer::store::liveness::LivePathMap::default()
    } else {
        crate::analyzer::store::liveness::LivePathMap::trust_filesystem_generation()
    });
    macro_rules! build_delegate {
        ($variant:ident, $analyzer:ty) => {
            AnalyzerDelegate::$variant(<$analyzer>::new_with_config_store_context(
                project,
                config,
                store_context,
                progress,
            )?)
        };
    }
    Ok(match language {
        Language::Java => build_delegate!(Java, JavaAnalyzer),
        Language::Go => build_delegate!(Go, GoAnalyzer),
        Language::Cpp => build_delegate!(Cpp, CppAnalyzer),
        Language::JavaScript => build_delegate!(JavaScript, JavascriptAnalyzer),
        Language::TypeScript => build_delegate!(TypeScript, TypescriptAnalyzer),
        Language::Python => build_delegate!(Python, PythonAnalyzer),
        Language::Rust => build_delegate!(Rust, RustAnalyzer),
        Language::Php => build_delegate!(Php, PhpAnalyzer),
        Language::Scala => build_delegate!(Scala, ScalaAnalyzer),
        Language::CSharp => build_delegate!(CSharp, CSharpAnalyzer),
        Language::Ruby => build_delegate!(Ruby, RubyAnalyzer),
        Language::Kotlin => build_delegate!(Kotlin, KotlinAnalyzer),
        Language::None => unreachable!("Language::None is filtered before delegate build"),
    })
}

fn is_js_ts_config_file(file: &ProjectFile) -> bool {
    matches!(
        file.rel_path().file_name().and_then(|name| name.to_str()),
        Some("tsconfig.json" | "jsconfig.json")
    )
}

pub struct MultiAnalyzer {
    delegates: BTreeMap<Language, AnalyzerDelegate>,
    snapshot_caches: Arc<crate::analyzer::AnalyzerSnapshotCaches>,
    derived_layer_budget_bytes: u64,
    query_contexts: Mutex<Vec<Arc<crate::analyzer::AnalyzerQueryContext>>>,
}

impl Default for MultiAnalyzer {
    fn default() -> Self {
        Self::new(BTreeMap::new())
    }
}

impl Clone for MultiAnalyzer {
    fn clone(&self) -> Self {
        Self {
            delegates: self.delegates.clone(),
            snapshot_caches: Arc::clone(&self.snapshot_caches),
            derived_layer_budget_bytes: self.derived_layer_budget_bytes,
            query_contexts: Mutex::new(Vec::new()),
        }
    }
}

impl MultiAnalyzer {
    pub fn new(delegates: BTreeMap<Language, AnalyzerDelegate>) -> Self {
        Self::new_with_derived_layer_budget(
            delegates,
            crate::analyzer::structural::execution::derived::SnapshotDerivedLayerCache::DEFAULT_MAX_RETAINED_BYTES,
        )
    }

    pub(crate) fn new_with_derived_layer_budget(
        delegates: BTreeMap<Language, AnalyzerDelegate>,
        derived_layer_budget_bytes: u64,
    ) -> Self {
        Self {
            delegates,
            snapshot_caches: Arc::new(crate::analyzer::AnalyzerSnapshotCaches::new(
                derived_layer_budget_bytes,
            )),
            derived_layer_budget_bytes,
            query_contexts: Mutex::new(Vec::new()),
        }
    }

    pub fn with_java(java: JavaAnalyzer) -> Self {
        Self::new(BTreeMap::from([(
            Language::Java,
            AnalyzerDelegate::Java(java),
        )]))
    }

    pub fn delegates(&self) -> &BTreeMap<Language, AnalyzerDelegate> {
        &self.delegates
    }

    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        Self {
            delegates: self
                .delegates
                .iter()
                .map(|(language, delegate)| {
                    (*language, delegate.clone_with_project(Arc::clone(&project)))
                })
                .collect(),
            snapshot_caches: Arc::new(crate::analyzer::AnalyzerSnapshotCaches::new(
                self.derived_layer_budget_bytes,
            )),
            derived_layer_budget_bytes: self.derived_layer_budget_bytes,
            query_contexts: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn delegate_for_file(&self, file: &ProjectFile) -> Option<&AnalyzerDelegate> {
        self.delegates.get(&language_for_file(file))
    }

    pub(crate) fn program_semantics_provider_for_file(
        &self,
        file: &ProjectFile,
    ) -> Option<&dyn crate::analyzer::semantic::ProgramSemanticsProvider> {
        self.delegate_for_file(file)
            .map(AnalyzerDelegate::program_semantics_provider)
    }

    fn delegate_for_code_unit(&self, code_unit: &CodeUnit) -> Option<&AnalyzerDelegate> {
        self.delegate_for_file(code_unit.source())
    }

    /// The Kotlin delegate, together with a view of the whole JVM source realm,
    /// when this workspace has Kotlin alongside at least one other JVM
    /// language.
    ///
    /// A Kotlin analyzer only indexes `.kt` files, so on its own it cannot see
    /// that the interface a Kotlin class implements is declared in a Java file
    /// next door. `MultiAnalyzer` is the only place that holds every delegate,
    /// so it is where the realm view is constructed. `None` means the widening
    /// would add nothing and the delegate's own answer already stands.
    fn kotlin_realm(&self) -> Option<(&KotlinAnalyzer, JvmSourceRealm<'_>)> {
        let Some(AnalyzerDelegate::Kotlin(kotlin)) = self.delegates.get(&Language::Kotlin) else {
            return None;
        };
        let realm = jvm_source_realm(self);
        realm
            .has_peers_of(Language::Kotlin)
            .then_some((kotlin, realm))
    }
}

impl ImportAnalysisProvider for MultiAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> Arc<HashSet<CodeUnit>> {
        // A Kotlin file can import a Java or Scala declaration from the same
        // workspace, and only the multi-analyzer can see both sides.
        if language_for_file(file) == Language::Kotlin
            && let Some((kotlin, realm)) = self.kotlin_realm()
        {
            return kotlin.imported_code_units_in_realm(file, Some(&realm));
        }
        self.delegate_for_file(file)
            .and_then(AnalyzerDelegate::import_analysis_provider)
            .map(|provider| provider.imported_code_units_of(file))
            .unwrap_or_default()
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        self.delegates
            .values()
            .filter_map(AnalyzerDelegate::import_analysis_provider)
            .flat_map(|provider| provider.referencing_files_of(file))
            .collect()
    }

    fn import_info_of(&self, file: &ProjectFile) -> Vec<ImportInfo> {
        self.delegate_for_file(file)
            .and_then(AnalyzerDelegate::import_analysis_provider)
            .map(|provider| provider.import_info_of(file))
            .unwrap_or_default()
    }

    fn import_infos_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Option<HashMap<ProjectFile, Vec<ImportInfo>>> {
        if files.is_empty() {
            return None;
        }
        // Route each file to its language delegate and prefer that delegate's
        // bulk reader (one store round-trip for the whole group) over the
        // per-file `import_info_of` path the shared candidate walker would
        // otherwise take. Delegates without a bulk model fall back to per-file
        // reads within their own group so the merged map still covers every
        // file, keeping the caller's result identical to the file-at-a-time
        // path while collapsing thousands of single-row queries into one.
        let mut grouped: BTreeMap<Language, Vec<ProjectFile>> = BTreeMap::new();
        for file in files {
            grouped
                .entry(language_for_file(file))
                .or_default()
                .push(file.clone());
        }
        let mut out: HashMap<ProjectFile, Vec<ImportInfo>> = HashMap::default();
        let mut any = false;
        for (language, group) in grouped {
            let Some(provider) = self
                .delegates
                .get(&language)
                .and_then(AnalyzerDelegate::import_analysis_provider)
            else {
                continue;
            };
            any = true;
            if let Some(map) = provider.import_infos_for_files(&group) {
                out.extend(map);
            } else {
                for file in group {
                    let infos = provider.import_info_of(&file);
                    out.insert(file, infos);
                }
            }
        }
        any.then_some(out)
    }

    fn relevant_imports_for(&self, code_unit: &CodeUnit) -> HashSet<String> {
        self.delegate_for_code_unit(code_unit)
            .and_then(AnalyzerDelegate::import_analysis_provider)
            .map(|provider| provider.relevant_imports_for(code_unit))
            .unwrap_or_default()
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        self.delegate_for_file(source_file)
            .and_then(AnalyzerDelegate::import_analysis_provider)
            .map(|provider| provider.could_import_file(source_file, imports, target))
            .unwrap_or(false)
    }

    /// A file whose language has no delegate is undecided, not unreachable:
    /// `unwrap_or` must not manufacture a proof the workspace never made.
    fn import_reachability(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> ImportReachability {
        self.delegate_for_file(source_file)
            .and_then(AnalyzerDelegate::import_analysis_provider)
            .map(|provider| provider.import_reachability(source_file, imports, target))
            .unwrap_or(ImportReachability::Unknown)
    }

    /// Without this override, `MultiAnalyzer` falls back to the trait default (always `None`) instead
    /// of forwarding to the per-language delegate's implementation -- silently defeating a delegate's
    /// own `imported_code_units_from_infos` (e.g. Python's) for every workspace-level caller that goes
    /// through `MultiAnalyzer`, which is the common case for a `scan_usages` on a real checkout.
    fn imported_code_units_from_infos(
        &self,
        file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<Arc<HashSet<CodeUnit>>> {
        self.delegate_for_file(file)
            .and_then(AnalyzerDelegate::import_analysis_provider)
            .and_then(|provider| provider.imported_code_units_from_infos(file, imports))
    }

    /// Same omission as the method above, one rung further down: without this
    /// override `resolve_imported_files_from_infos` gets the trait default
    /// `None` and degrades to projecting imported *declarations* back to their
    /// files. An import whose target file declares nothing -- a Ruby
    /// `require_relative` loader, say -- then contributes no file edge at all,
    /// so transitive-importer candidate discovery never reaches the files that
    /// require it. Routing per file is the correct composition: `imports` always
    /// comes from `import_info_of`, which routes through the same
    /// `delegate_for_file`, so the two answers stay consistent.
    fn imported_files_from_infos(
        &self,
        file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<HashSet<ProjectFile>> {
        self.delegate_for_file(file)
            .and_then(AnalyzerDelegate::import_analysis_provider)
            .and_then(|provider| provider.imported_files_from_infos(file, imports))
    }
}

impl TypeHierarchyProvider for MultiAnalyzer {
    fn supports_type_hierarchy(&self, code_unit: &CodeUnit) -> bool {
        self.delegate_for_code_unit(code_unit)
            .and_then(AnalyzerDelegate::type_hierarchy_provider)
            .is_some_and(|provider| provider.supports_type_hierarchy(code_unit))
    }

    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        // A Kotlin class can extend a Java class or implement a Scala trait
        // declared in the same workspace; resolving that needs every JVM
        // delegate, which only the multi-analyzer holds.
        if language_for_file(code_unit.source()) == Language::Kotlin
            && let Some((kotlin, realm)) = self.kotlin_realm()
        {
            return kotlin.direct_ancestors_in_realm(code_unit, Some(&realm));
        }
        self.delegate_for_code_unit(code_unit)
            .and_then(AnalyzerDelegate::type_hierarchy_provider)
            .map(|provider| provider.get_direct_ancestors(code_unit))
            .unwrap_or_default()
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        let mut descendants = self
            .delegate_for_code_unit(code_unit)
            .and_then(AnalyzerDelegate::type_hierarchy_provider)
            .map(|provider| provider.get_direct_descendants(code_unit))
            .unwrap_or_default();
        // Kotlin subclasses of a Java or Scala type are invisible to that
        // language's own descendant index, which only walks its own
        // declarations. Kotlin's realm-aware index does resolve across the
        // realm, so folding it in is what makes `Api`'s Kotlin implementors
        // show up.
        //
        // The reverse direction — Java and Scala subclasses of a *Kotlin* type
        // — is still missing, and cannot be fixed here. Each language's
        // descendant index is the inverse of its own ancestor resolution, and
        // Java's and Scala's resolve a spelled supertype against their own
        // declarations only; folding their indexes in for a Kotlin unit would
        // fold in indexes that never saw the Kotlin declaration in the first
        // place. Closing it means giving those two hierarchy resolvers the
        // realm-aware existence predicate Kotlin's already has (`realm_type_exists`
        // / `realm_type_by_fqn` in `kotlin/hierarchy.rs`) — a change to those
        // analyzers, not to this dispatch. Issue #1239 made *usage* resolution
        // realm-aware in both directions; hierarchy resolution is a separate
        // seam and remains one-directional.
        if language_for_file(code_unit.source()) != Language::Kotlin
            && let Some((kotlin, realm)) = self.kotlin_realm()
        {
            descendants.extend(kotlin.direct_descendants_in_realm(code_unit, Some(&realm)));
        }
        descendants
    }
}

/// Method families across the whole workspace (#1477 M4).
///
/// The delegation mirrors `TypeHierarchyProvider`'s, and for the same reason:
/// a Kotlin class can override a Java method, so the ancestor and descendant
/// edges a family walk needs are exactly the realm-aware ones only the
/// multi-analyzer resolves. The per-language relation therefore receives
/// `self` as its hierarchy source rather than the owning delegate.
///
/// Language support is stated per member, never defaulted: a member whose
/// language has no landed family answers `unsupported`, even though this
/// composite exposes a provider for the workspace as a whole.
impl crate::analyzer::usages::MemberFamilyProvider for MultiAnalyzer {
    fn member_family_capability(
        &self,
        member: &CodeUnit,
    ) -> crate::analyzer::structural::resolution::MemberFamilyCapability {
        crate::analyzer::usages::java_member_family_capability(self, member)
    }

    fn member_family(
        &self,
        member: &CodeUnit,
        cancellation: Option<&crate::cancellation::CancellationToken>,
    ) -> crate::analyzer::usages::MemberFamilyAnswer {
        crate::analyzer::usages::java_member_family(self, self, member, cancellation)
    }
}

impl TypeAliasProvider for MultiAnalyzer {
    fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.delegate_for_code_unit(code_unit)
            .and_then(AnalyzerDelegate::type_alias_provider)
            .map(|provider| provider.is_type_alias(code_unit))
            .unwrap_or(false)
    }
}

impl TestDetectionProvider for MultiAnalyzer {}

use crate::analyzer::CodeUnitIndex;

impl CodeUnitIndex for MultiAnalyzer {
    fn enclosing_code_unit(&self, file: &ProjectFile, range: &Range) -> Option<CodeUnit> {
        self.delegate_for_file(file)
            .and_then(|delegate| delegate.analyzer().enclosing_code_unit(file, range))
    }

    fn enclosing_code_unit_for_lines(
        &self,
        file: &ProjectFile,
        start_line: usize,
        end_line: usize,
    ) -> Option<CodeUnit> {
        self.delegate_for_file(file).and_then(|delegate| {
            delegate
                .analyzer()
                .enclosing_code_unit_for_lines(file, start_line, end_line)
        })
    }

    fn top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit> {
        match self.delegate_for_file(file) {
            Some(delegate) => delegate.analyzer().top_level_declarations(file),
            None => Vec::new(),
        }
    }

    fn summary_file_projection(&self, file: &ProjectFile) -> Option<Arc<SummaryFileProjection>> {
        self.delegate_for_file(file)
            .and_then(|delegate| delegate.analyzer().summary_file_projection(file))
    }

    fn analyzed_files(&self) -> Vec<ProjectFile> {
        let mut files: Vec<_> = self
            .delegates
            .values()
            .flat_map(|delegate| delegate.analyzer().analyzed_files())
            .collect();
        files.sort();
        files.dedup();
        files
    }

    fn indexed_source(&self, file: &ProjectFile) -> Option<String> {
        self.delegate_for_file(file)
            .and_then(|delegate| delegate.analyzer().indexed_source(file))
    }

    fn location_declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        self.delegate_for_file(file)
            .map(|delegate| delegate.analyzer().location_declarations(file))
            .unwrap_or_default()
    }

    fn location_ranges(&self, code_unit: &CodeUnit) -> Vec<Range> {
        self.delegate_for_code_unit(code_unit)
            .map(|delegate| delegate.analyzer().location_ranges(code_unit))
            .unwrap_or_default()
    }

    fn indexed_source_matches(&self, file: &ProjectFile, source: &str) -> bool {
        self.delegate_for_file(file)
            .is_some_and(|delegate| delegate.analyzer().indexed_source_matches(file, source))
    }

    fn render_source_fragment(
        &self,
        code_unit: &CodeUnit,
        source: String,
        declaration_start: usize,
    ) -> String {
        match self.delegate_for_code_unit(code_unit) {
            Some(delegate) => {
                delegate
                    .analyzer()
                    .render_source_fragment(code_unit, source, declaration_start)
            }
            None => source,
        }
    }

    fn is_analyzed(&self, file: &ProjectFile) -> bool {
        self.delegates
            .values()
            .any(|delegate| delegate.analyzer().is_analyzed(file))
    }

    fn languages(&self) -> BTreeSet<Language> {
        self.delegates.keys().copied().collect()
    }

    fn project(&self) -> &dyn Project {
        self.delegates
            .values()
            .next()
            .expect("MultiAnalyzer requires at least one delegate")
            .analyzer()
            .project()
    }

    fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        Box::new(
            self.delegates
                .values()
                .flat_map(|delegate| delegate.analyzer().all_declarations()),
        )
    }

    fn all_declarations_with_primary_ranges(&self) -> Vec<(CodeUnit, Option<Range>)> {
        self.delegates
            .values()
            .flat_map(|delegate| delegate.analyzer().all_declarations_with_primary_ranges())
            .collect()
    }

    fn declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        match self.delegate_for_file(file) {
            Some(delegate) => delegate.analyzer().declarations(file),
            None => BTreeSet::new(),
        }
    }

    fn materialization_records(
        &self,
        file: &ProjectFile,
    ) -> Vec<crate::analyzer::structural::materialization::MaterializationRecord> {
        match self.delegate_for_file(file) {
            Some(delegate) => delegate.analyzer().materialization_records(file),
            None => Vec::new(),
        }
    }

    fn definitions(&self, fq_name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        let matches: Vec<_> = self
            .delegates
            .iter()
            .flat_map(|(language, delegate)| {
                let _scope =
                    crate::profiling::scope(format!("multi.definitions[{language:?}][{fq_name}]"));
                delegate.analyzer().definitions(fq_name)
            })
            .collect();
        Box::new(matches.into_iter())
    }

    fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        match self.delegate_for_code_unit(code_unit) {
            Some(delegate) => delegate.analyzer().direct_children(code_unit),
            None => Vec::new(),
        }
    }

    fn direct_children_in_file(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        match self.delegate_for_code_unit(code_unit) {
            Some(delegate) => delegate.analyzer().direct_children_in_file(code_unit),
            None => Vec::new(),
        }
    }

    fn parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.delegate_for_code_unit(code_unit)
            .and_then(|delegate| delegate.analyzer().parent_of(code_unit))
    }

    fn ranges(&self, code_unit: &CodeUnit) -> Vec<Range> {
        self.delegate_for_code_unit(code_unit)
            .map(|delegate| delegate.analyzer().ranges(code_unit))
            .unwrap_or_default()
    }

    fn ranges_with_limit(
        &self,
        code_unit: &CodeUnit,
        max_ranges: usize,
        cancellation: &crate::CancellationToken,
    ) -> (Vec<Range>, usize, bool) {
        self.delegate_for_code_unit(code_unit)
            .map(|delegate| {
                delegate
                    .analyzer()
                    .ranges_with_limit(code_unit, max_ranges, cancellation)
            })
            .unwrap_or_default()
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        self.delegate_for_code_unit(code_unit)
            .and_then(|delegate| delegate.analyzer().get_skeleton(code_unit))
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        self.delegate_for_code_unit(code_unit)
            .and_then(|delegate| delegate.analyzer().get_skeleton_header(code_unit))
    }

    fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String> {
        self.delegate_for_code_unit(code_unit)
            .and_then(|delegate| delegate.analyzer().get_source(code_unit, include_comments))
    }

    fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String> {
        self.delegate_for_code_unit(code_unit)
            .map(|delegate| delegate.analyzer().get_sources(code_unit, include_comments))
            .unwrap_or_default()
    }

    fn search_definitions(&self, pattern: &str, auto_quote: bool) -> BTreeSet<CodeUnit> {
        self.delegates
            .values()
            .collect::<Vec<_>>()
            .into_par_iter()
            .map(|delegate| delegate.analyzer().search_definitions(pattern, auto_quote))
            .reduce(BTreeSet::new, |mut acc, definitions| {
                acc.extend(definitions);
                acc
            })
    }

    fn search_definitions_with_literal(
        &self,
        pattern: &str,
        required_literal: &str,
        language: Language,
    ) -> BTreeSet<CodeUnit> {
        // The pattern is language-specific, so only that language's delegate
        // can produce matches the caller keeps; fanning out to every delegate
        // multiplied lookup cost by the language count (#1430).
        self.delegates
            .get(&language)
            .map(|delegate| {
                delegate.analyzer().search_definitions_with_literal(
                    pattern,
                    required_literal,
                    language,
                )
            })
            .unwrap_or_default()
    }

    fn lookup_candidates_by_short_name(&self, symbol: &str) -> BTreeSet<CodeUnit> {
        self.delegates
            .values()
            .collect::<Vec<_>>()
            .into_par_iter()
            .map(|delegate| delegate.analyzer().lookup_candidates_by_short_name(symbol))
            .reduce(BTreeSet::new, |mut acc, candidates| {
                acc.extend(candidates);
                acc
            })
    }

    fn lookup_candidates_by_identifier(&self, identifier: &str) -> BTreeSet<CodeUnit> {
        self.delegates
            .values()
            .collect::<Vec<_>>()
            .into_par_iter()
            .map(|delegate| {
                delegate
                    .analyzer()
                    .lookup_candidates_by_identifier(identifier)
            })
            .reduce(BTreeSet::new, |mut acc, candidates| {
                acc.extend(candidates);
                acc
            })
    }

    fn search_definitions_persisted(&self, pattern: &str) -> BTreeSet<CodeUnit> {
        // Fan out to each delegate's `search_definitions_persisted` so the
        // FTS5 path is consulted per-language. The default impl on
        // `IAnalyzer` would otherwise re-dispatch through our own
        // `search_definitions` override, which only hits in-memory state.
        self.delegates
            .values()
            .collect::<Vec<_>>()
            .into_par_iter()
            .map(|delegate| delegate.analyzer().search_definitions_persisted(pattern))
            .reduce(BTreeSet::new, |mut acc, definitions| {
                acc.extend(definitions);
                acc
            })
    }

    fn signatures(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.delegate_for_code_unit(code_unit)
            .map(|delegate| delegate.analyzer().signatures(code_unit))
            .unwrap_or_default()
    }

    fn signature_metadata(&self, code_unit: &CodeUnit) -> Vec<SignatureMetadata> {
        self.delegate_for_code_unit(code_unit)
            .map(|delegate| delegate.analyzer().signature_metadata(code_unit))
            .unwrap_or_default()
    }
}

impl IAnalyzer for MultiAnalyzer {
    #[cfg(any(test, feature = "test-support"))]
    fn test_hooks(&self) -> &dyn crate::analyzer::AnalyzerTestHooks {
        self
    }

    fn invalidate_cached_file_identities(&self) {
        self.delegates
            .values()
            .for_each(|delegate| delegate.analyzer().invalidate_cached_file_identities());
    }

    fn begin_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        let mut contexts = self
            .query_contexts
            .lock()
            .expect("multi-analyzer query context mutex poisoned");
        if !contexts.iter().any(|active| Arc::ptr_eq(active, context)) {
            contexts.push(Arc::clone(context));
        }
        drop(contexts);
        self.delegates
            .values()
            .for_each(|delegate| delegate.analyzer().begin_query(context));
    }

    fn end_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.delegates
            .values()
            .for_each(|delegate| delegate.analyzer().end_query(context));
        self.query_contexts
            .lock()
            .expect("multi-analyzer query context mutex poisoned")
            .retain(|active| !Arc::ptr_eq(active, context));
    }

    fn begin_streaming_file_read(&self, file: &ProjectFile) {
        if let Some(delegate) = self.delegate_for_file(file) {
            delegate.analyzer().begin_streaming_file_read(file);
        }
    }

    fn end_streaming_file_read(&self, file: &ProjectFile) {
        if let Some(delegate) = self.delegate_for_file(file) {
            delegate.analyzer().end_streaming_file_read(file);
        }
    }

    fn release_streaming_readers(&self) {
        self.delegates
            .values()
            .for_each(|delegate| delegate.analyzer().release_streaming_readers());
    }

    /// The first delegate's cell — the same delegate `project()` answers from,
    /// so the memoized listing describes exactly the workspace this analyzer
    /// reports. `begin_query` propagates to every delegate, so it is active
    /// whenever this analyzer's own scope is.
    fn workspace_file_index_cell(&self) -> Option<crate::analyzer::WorkspaceFileIndexCell> {
        self.delegates
            .values()
            .next()?
            .analyzer()
            .workspace_file_index_cell()
    }

    fn warm_query_indexes(&self) {
        self.delegates
            .values()
            .collect::<Vec<_>>()
            .into_par_iter()
            .for_each(|delegate| delegate.analyzer().warm_query_indexes());
    }

    fn query_indexes_warm(&self) -> bool {
        self.delegates
            .values()
            .all(|delegate| delegate.analyzer().query_indexes_warm())
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        let updated: Vec<(Language, AnalyzerDelegate, bool)> = self
            .delegates
            .iter()
            .collect::<Vec<_>>()
            .into_par_iter()
            .map(|(language, delegate)| {
                let relevant: BTreeSet<ProjectFile> = changed_files
                    .iter()
                    .filter(|file| delegate.should_receive_changed_file(*language, file))
                    .cloned()
                    .collect();
                if relevant.is_empty() {
                    (*language, delegate.clone(), false)
                } else {
                    (*language, delegate.update(&relevant), true)
                }
            })
            .collect();
        let any_delegate_changed = updated.iter().any(|(_, _, changed)| *changed);
        let delegates = updated
            .into_iter()
            .map(|(language, delegate, _)| (language, delegate))
            .collect();
        if any_delegate_changed {
            return Self::new_with_derived_layer_budget(delegates, self.derived_layer_budget_bytes);
        }
        // No delegate saw a relevant change, so every one of them was cloned
        // and kept everything it had built.  Keeping the workspace-level
        // derived-layer caches too matches that, and matches what a delegate's
        // own no-op update does.  The caches are generation-guarded, so nothing
        // stale can be served through them either way.
        Self {
            delegates,
            snapshot_caches: Arc::clone(&self.snapshot_caches),
            derived_layer_budget_bytes: self.derived_layer_budget_bytes,
            query_contexts: Mutex::new(Vec::new()),
        }
    }

    fn update_all(&self) -> Self {
        let delegates = self
            .delegates
            .iter()
            .collect::<Vec<_>>()
            .into_par_iter()
            .map(|(language, delegate)| (*language, delegate.update_all()))
            .collect();
        Self::new_with_derived_layer_budget(delegates, self.derived_layer_budget_bytes)
    }

    /// A view over the delegates' own indexes, never a merged copy.
    ///
    /// Each shard is built lazily by its delegate on first use, so the cost of
    /// a definition query is exactly the per-language index the delegate would
    /// have built anyway, and it survives every update and overlay snapshot
    /// that retains the delegate.  A delegate whose store read fails degrades
    /// to its own recorded-error fallback shard, which keeps the failure
    /// visible and confined instead of emptying the whole workspace view.
    fn global_usage_definition_index(&self) -> DefinitionIndexHandle<'_> {
        DefinitionIndexHandle::Merged(
            self.delegates
                .values()
                .flat_map(|delegate| {
                    delegate
                        .analyzer()
                        .global_usage_definition_index()
                        .into_shards()
                })
                .collect(),
        )
    }

    fn declaration_syntax_kind(&self, code_unit: &CodeUnit) -> Option<&'static str> {
        self.delegate_for_code_unit(code_unit)
            .and_then(|delegate| delegate.analyzer().declaration_syntax_kind(code_unit))
    }

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.delegate_for_file(file)
            .and_then(|delegate| delegate.analyzer().parse_errors(file))
    }

    fn semantic_diagnostics(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> crate::analyzer::SemanticDiagnosticReport {
        // JVM diagnostics must see the same
        // wider JVM source realm its import and hierarchy resolution do:
        // otherwise a type declared in a Java or Scala sibling file would be
        // misreported as unrecognized. Only `MultiAnalyzer` can construct
        // that realm view (see `kotlin_realm`), so this is the one place the
        // widening happens rather than inside `KotlinAnalyzer` itself.
        if language_for_file(file) == Language::Kotlin
            && let Some((kotlin, realm)) = self.kotlin_realm()
        {
            let diagnostics =
                crate::analyzer::kotlin::diagnostics::collect_kotlin_semantic_diagnostics(
                    kotlin,
                    file,
                    source,
                    Some(&realm),
                )
                .into_iter()
                .map(SemanticDiagnostic::from)
                .collect();
            return crate::analyzer::SemanticDiagnosticReport::from_workspace_absences(
                file,
                diagnostics,
            );
        }
        if language_for_file(file) == Language::Java && self.delegates.contains_key(&Language::Java)
        {
            return crate::analyzer::java::diagnostics::collect_java_semantic_diagnostics(
                self, file, source,
            );
        }
        // JS/TS diagnostics judge external imports against the activated npm
        // declaration surface and the retained npm discovery evidence (#1620).
        // Both hang off the analyzer that owns the workspace snapshot, which is
        // this one: a delegate passed on its own carries no snapshot caches and
        // would report every npm import as an unknown boundary.
        let language = language_for_file(file);
        if language == Language::JavaScript && self.delegates.contains_key(&Language::JavaScript) {
            return crate::analyzer::js_ts::diagnostics::collect_javascript_semantic_diagnostics(
                self, file, source,
            );
        }
        if language == Language::TypeScript && self.delegates.contains_key(&Language::TypeScript) {
            return crate::analyzer::js_ts::diagnostics::collect_typescript_semantic_diagnostics(
                self, file, source,
            );
        }
        self.delegate_for_file(file)
            .map(|delegate| delegate.analyzer().semantic_diagnostics(file, source))
            .unwrap_or_default()
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        self.delegates
            .values()
            .find_map(|delegate| delegate.analyzer().extract_call_receiver(reference))
    }

    fn import_statements(&self, file: &ProjectFile) -> Vec<String> {
        self.delegate_for_file(file)
            .map(|delegate| delegate.analyzer().import_statements(file))
            .unwrap_or_default()
    }

    fn is_access_expression(&self, file: &ProjectFile, start_byte: usize, end_byte: usize) -> bool {
        self.delegate_for_file(file)
            .map(|delegate| {
                delegate
                    .analyzer()
                    .is_access_expression(file, start_byte, end_byte)
            })
            .unwrap_or(true)
    }

    fn find_nearest_declaration(
        &self,
        file: &ProjectFile,
        start_byte: usize,
        end_byte: usize,
        ident: &str,
    ) -> Option<DeclarationInfo> {
        self.delegate_for_file(file).and_then(|delegate| {
            delegate
                .analyzer()
                .find_nearest_declaration(file, start_byte, end_byte, ident)
        })
    }

    fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)> {
        self.delegate_for_file(file)
            .map(|delegate| delegate.analyzer().compute_cognitive_complexities(file))
            .unwrap_or_default()
    }

    fn comment_density(&self, code_unit: &CodeUnit) -> Option<CommentDensityStats> {
        self.delegate_for_code_unit(code_unit)
            .and_then(|delegate| delegate.analyzer().comment_density(code_unit))
    }

    fn comment_density_by_top_level(&self, file: &ProjectFile) -> Vec<CommentDensityStats> {
        self.delegate_for_file(file)
            .map(|delegate| delegate.analyzer().comment_density_by_top_level(file))
            .unwrap_or_default()
    }

    fn find_exception_handling_smells(
        &self,
        file: &ProjectFile,
        weights: ExceptionSmellWeights,
    ) -> ExceptionHandlingAnalysis {
        let Some(delegate) = self.delegate_for_file(file) else {
            return ExceptionHandlingAnalysis::Unsupported {
                reason: format!(
                    "no analyzer delegate is available for {}",
                    file.rel_path().display()
                ),
            };
        };
        delegate
            .analyzer()
            .find_exception_handling_smells(file, weights)
    }

    fn find_test_assertion_smells(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        self.delegate_for_file(file)
            .map(|delegate| {
                delegate
                    .analyzer()
                    .find_test_assertion_smells(file, weights)
            })
            .unwrap_or_default()
    }

    fn find_test_assertion_smells_limited(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
        max_candidates: usize,
    ) -> TestAssertionAnalysis {
        self.delegate_for_file(file)
            .map(|delegate| {
                delegate.analyzer().find_test_assertion_smells_limited(
                    file,
                    weights,
                    max_candidates,
                )
            })
            .unwrap_or(TestAssertionAnalysis {
                findings: Vec::new(),
                inspected_candidates: None,
                truncated: false,
            })
    }

    fn find_structural_clone_smells(
        &self,
        file: &ProjectFile,
        weights: CloneSmellWeights,
    ) -> Vec<CloneSmell> {
        self.delegate_for_file(file)
            .map(|delegate| {
                delegate
                    .analyzer()
                    .find_structural_clone_smells(file, weights)
            })
            .unwrap_or_default()
    }

    fn find_structural_clone_smells_for_files(
        &self,
        files: &[ProjectFile],
        weights: CloneSmellWeights,
    ) -> Vec<CloneSmell> {
        let mut grouped: BTreeMap<Language, Vec<ProjectFile>> = BTreeMap::new();
        for file in files {
            grouped
                .entry(language_for_file(file))
                .or_default()
                .push(file.clone());
        }

        let mut findings = Vec::new();
        for (language, group) in grouped {
            if let Some(delegate) = self.delegates.get(&language) {
                findings.extend(
                    delegate
                        .analyzer()
                        .find_structural_clone_smells_for_files(&group, weights),
                );
            }
        }
        findings
    }

    fn search_symbol_candidates(
        &self,
        patterns: &SearchSymbolPatternBatch,
        cancellation: Option<&crate::CancellationToken>,
    ) -> SearchSymbolCandidates {
        self.delegates
            .values()
            .collect::<Vec<_>>()
            .into_par_iter()
            .map(|delegate| {
                delegate
                    .analyzer()
                    .search_symbol_candidates(patterns, cancellation)
            })
            .reduce(
                || SearchSymbolCandidates::complete(Vec::new(), 0),
                SearchSymbolCandidates::merge,
            )
    }

    fn partial_declaration_parts(&self, code_unit: &CodeUnit) -> Option<Vec<CodeUnit>> {
        self.delegate_for_code_unit(code_unit)?
            .analyzer()
            .partial_declaration_parts(code_unit)
    }

    fn abstract_member_implementations(&self, code_unit: &CodeUnit) -> Option<Vec<CodeUnit>> {
        self.delegate_for_code_unit(code_unit)?
            .analyzer()
            .abstract_member_implementations(code_unit)
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        self.delegates
            .values()
            .any(|delegate| delegate.import_analysis_provider().is_some())
            .then_some(self as &dyn ImportAnalysisProvider)
    }

    fn import_analysis_provider_for_file(
        &self,
        file: &ProjectFile,
    ) -> Option<&dyn ImportAnalysisProvider> {
        self.delegate_for_file(file)
            .and_then(AnalyzerDelegate::import_analysis_provider)
    }

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        self.delegates
            .values()
            .any(|delegate| delegate.type_hierarchy_provider().is_some())
            .then_some(self as &dyn TypeHierarchyProvider)
    }

    fn type_alias_provider(&self) -> Option<&dyn TypeAliasProvider> {
        self.delegates
            .values()
            .any(|delegate| delegate.type_alias_provider().is_some())
            .then_some(self as &dyn TypeAliasProvider)
    }

    fn member_family_provider(&self) -> Option<&dyn crate::analyzer::usages::MemberFamilyProvider> {
        self.delegates
            .values()
            .any(|delegate| delegate.analyzer().member_family_provider().is_some())
            .then_some(self as &dyn crate::analyzer::usages::MemberFamilyProvider)
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        self.delegates
            .values()
            .any(|delegate| delegate.test_detection_provider().is_some())
            .then_some(self as &dyn TestDetectionProvider)
    }

    fn structural_search_providers(
        &self,
    ) -> Vec<&dyn crate::analyzer::structural::StructuralSearchProvider> {
        self.delegates
            .values()
            .flat_map(|delegate| delegate.analyzer().structural_search_providers())
            .collect()
    }

    fn snapshot_caches(&self) -> Option<&crate::analyzer::AnalyzerSnapshotCaches> {
        Some(&self.snapshot_caches)
    }

    fn snapshot_source_generations(&self) -> Box<[u64]> {
        self.delegates
            .values()
            .map(|delegate| delegate.analyzer().project().analysis_generation())
            .collect()
    }

    fn snapshot_generations_match(&self, expected: &[u64]) -> bool {
        expected.len() == self.delegates.len()
            && expected.iter().copied().eq(self
                .delegates
                .values()
                .map(|delegate| delegate.analyzer().project().analysis_generation()))
    }

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.delegate_for_file(file)
            .map(|delegate| delegate.analyzer().contains_tests(file))
            .unwrap_or(false)
    }

    fn in_test_region(&self, code_unit: &CodeUnit) -> bool {
        self.delegate_for_file(code_unit.source())
            .is_some_and(|delegate| delegate.analyzer().in_test_region(code_unit))
    }

    fn file_is_test_only(&self, file: &ProjectFile) -> bool {
        self.delegate_for_file(file)
            .is_some_and(|delegate| delegate.analyzer().file_is_test_only(file))
    }

    fn get_test_modules(&self, files: &[ProjectFile]) -> Vec<String> {
        let mut grouped: BTreeMap<Language, Vec<ProjectFile>> = BTreeMap::new();
        for file in files {
            grouped
                .entry(language_for_file(file))
                .or_default()
                .push(file.clone());
        }

        let mut modules = Vec::new();
        for (language, group) in grouped {
            if let Some(delegate) = self.delegates.get(&language) {
                modules.extend(delegate.analyzer().get_test_modules(&group));
            } else {
                modules.extend(IAnalyzer::get_test_modules(self, &group));
            }
        }
        modules.sort();
        modules.dedup();
        modules
    }

    fn test_files_to_code_units(&self, files: &[ProjectFile]) -> BTreeSet<CodeUnit> {
        let mut grouped: BTreeMap<Language, Vec<ProjectFile>> = BTreeMap::new();
        for file in files {
            grouped
                .entry(language_for_file(file))
                .or_default()
                .push(file.clone());
        }

        let mut result = BTreeSet::new();
        for (language, group) in grouped {
            if let Some(delegate) = self.delegates.get(&language) {
                result.extend(delegate.analyzer().test_files_to_code_units(&group));
            } else {
                result.extend(IAnalyzer::test_files_to_code_units(self, &group));
            }
        }
        result
    }
}

#[cfg(any(test, feature = "test-support"))]
impl crate::analyzer::AnalyzerTestHooks for MultiAnalyzer {
    fn reset_global_usage_definition_index_build_count_for_test(&self) {
        for delegate in self.delegates.values() {
            delegate
                .analyzer()
                .test_hooks()
                .reset_global_usage_definition_index_build_count_for_test();
        }
    }

    fn global_usage_definition_index_build_count_for_test(&self) -> usize {
        self.delegates
            .values()
            .map(|delegate| {
                delegate
                    .analyzer()
                    .test_hooks()
                    .global_usage_definition_index_build_count_for_test()
            })
            .sum::<usize>()
    }

    fn reset_definition_candidates_query_count_for_test(&self) {
        for delegate in self.delegates.values() {
            delegate
                .analyzer()
                .test_hooks()
                .reset_definition_candidates_query_count_for_test();
        }
    }

    fn definition_candidates_query_count_for_test(&self) -> usize {
        self.delegates
            .values()
            .map(|delegate| {
                delegate
                    .analyzer()
                    .test_hooks()
                    .definition_candidates_query_count_for_test()
            })
            .sum()
    }

    fn reset_full_declaration_scan_count_for_test(&self) {
        for delegate in self.delegates.values() {
            delegate
                .analyzer()
                .test_hooks()
                .reset_full_declaration_scan_count_for_test();
        }
    }

    fn full_declaration_scan_count_for_test(&self) -> usize {
        self.delegates
            .values()
            .map(|delegate| {
                delegate
                    .analyzer()
                    .test_hooks()
                    .full_declaration_scan_count_for_test()
            })
            .sum()
    }

    fn reset_candidate_hydration_count_for_test(&self) {
        for delegate in self.delegates.values() {
            delegate
                .analyzer()
                .test_hooks()
                .reset_candidate_hydration_count_for_test();
        }
    }

    fn candidate_hydration_count_for_test(&self) -> usize {
        self.delegates
            .values()
            .map(|delegate| {
                delegate
                    .analyzer()
                    .test_hooks()
                    .candidate_hydration_count_for_test()
            })
            .sum()
    }

    fn full_candidate_hydration_count_for_test(&self) -> usize {
        self.delegates
            .values()
            .map(|delegate| {
                delegate
                    .analyzer()
                    .test_hooks()
                    .full_candidate_hydration_count_for_test()
            })
            .sum()
    }

    fn bulk_candidate_hydration_count_for_test(&self) -> usize {
        self.delegates
            .values()
            .map(|delegate| {
                delegate
                    .analyzer()
                    .test_hooks()
                    .bulk_candidate_hydration_count_for_test()
            })
            .sum()
    }

    fn reset_workspace_path_scan_count_for_test(&self) {
        for delegate in self.delegates.values() {
            delegate
                .analyzer()
                .test_hooks()
                .reset_workspace_path_scan_count_for_test();
        }
    }

    fn workspace_path_scan_count_for_test(&self) -> usize {
        self.delegates
            .values()
            .map(|delegate| {
                delegate
                    .analyzer()
                    .test_hooks()
                    .workspace_path_scan_count_for_test()
            })
            .sum()
    }

    fn reset_scala_project_types_build_count_for_test(&self) {
        for delegate in self.delegates.values() {
            delegate
                .analyzer()
                .test_hooks()
                .reset_scala_project_types_build_count_for_test();
        }
    }

    fn scala_project_types_build_count_for_test(&self) -> usize {
        self.delegates
            .values()
            .map(|delegate| {
                delegate
                    .analyzer()
                    .test_hooks()
                    .scala_project_types_build_count_for_test()
            })
            .sum()
    }

    fn reset_scala_query_scan_counts_for_test(&self) {
        for delegate in self.delegates.values() {
            delegate
                .analyzer()
                .test_hooks()
                .reset_scala_query_scan_counts_for_test();
        }
    }

    fn scala_query_parse_count_for_test(&self) -> usize {
        self.delegates
            .values()
            .map(|delegate| {
                delegate
                    .analyzer()
                    .test_hooks()
                    .scala_query_parse_count_for_test()
            })
            .sum()
    }

    fn scala_query_walk_count_for_test(&self) -> usize {
        self.delegates
            .values()
            .map(|delegate| {
                delegate
                    .analyzer()
                    .test_hooks()
                    .scala_query_walk_count_for_test()
            })
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::FileSetProject;

    fn project_file(rel_path: &str) -> ProjectFile {
        let root = if cfg!(windows) {
            std::path::PathBuf::from("C:\\tmp")
        } else {
            std::path::PathBuf::from("/tmp")
        };
        ProjectFile::new(root, rel_path)
    }

    #[test]
    fn js_ts_config_files_are_routed_as_delegate_relevant_changes() {
        assert!(is_js_ts_config_file(&project_file("tsconfig.json")));
        assert!(is_js_ts_config_file(&project_file(
            "packages/app/jsconfig.json"
        )));
        assert!(!is_js_ts_config_file(&project_file("package.json")));
        assert!(!is_js_ts_config_file(&project_file("src/app.ts")));
    }

    #[test]
    fn default_multi_analyzer_preserves_the_default_derived_layer_budget() {
        let analyzer = MultiAnalyzer::default();
        assert_eq!(
            analyzer.derived_layer_budget_bytes,
            crate::analyzer::structural::execution::derived::SnapshotDerivedLayerCache::DEFAULT_MAX_RETAINED_BYTES
        );
        assert_eq!(
            analyzer
                .snapshot_caches
                .derived_layers()
                .max_retained_bytes(),
            analyzer.derived_layer_budget_bytes
        );
    }

    #[test]
    fn java_build_inputs_are_routed_as_delegate_relevant_changes() {
        let temp = tempfile::tempdir().unwrap();
        let project = FileSetProject::new(
            temp.path().canonicalize().unwrap(),
            std::iter::empty::<std::path::PathBuf>(),
        );
        let delegate = AnalyzerDelegate::Java(JavaAnalyzer::from_project(project));
        assert!(delegate.needs_config_update_for(&project_file("pom.xml")));
        assert!(
            delegate
                .needs_config_update_for(&project_file("gradle/dependency-locks/runtime.lockfile"))
        );
        assert!(
            delegate.needs_config_update_for(&project_file("buildSrc/src/main/java/Plugin.java"))
        );
        assert!(!delegate.needs_config_update_for(&project_file("src/App.java")));
    }

    #[test]
    fn csharp_dependency_inputs_are_routed_as_delegate_relevant_changes() {
        let temp = tempfile::tempdir().unwrap();
        let project = FileSetProject::new(
            temp.path().canonicalize().unwrap(),
            std::iter::empty::<std::path::PathBuf>(),
        );
        let delegate = AnalyzerDelegate::CSharp(CSharpAnalyzer::from_project(project));
        assert!(delegate.needs_config_update_for(&project_file("obj/project.assets.json")));
        assert!(delegate.needs_config_update_for(&project_file("App.csproj")));
        assert!(delegate.needs_config_update_for(&project_file("bin/App.dll")));
        assert!(!delegate.needs_config_update_for(&project_file("src/App.cs")));
    }

    /// A two-language workspace on disk, as a `MultiAnalyzer` over real
    /// per-language delegates.  The merged definition view is only meaningful
    /// over delegates that actually hold declarations.
    fn two_language_analyzer() -> (tempfile::TempDir, MultiAnalyzer) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/App.java"),
            "package app;\npublic class App {}\n",
        )
        .unwrap();
        std::fs::write(root.join("src/lib.rs"), "pub struct Widget;\n").unwrap();
        std::fs::write(root.join("README.md"), "docs\n").unwrap();
        let project = FileSetProject::new(
            root,
            [
                std::path::PathBuf::from("src/App.java"),
                std::path::PathBuf::from("src/lib.rs"),
                std::path::PathBuf::from("README.md"),
            ],
        );
        let delegates = BTreeMap::from([
            (
                Language::Java,
                AnalyzerDelegate::Java(JavaAnalyzer::from_project(project.clone())),
            ),
            (
                Language::Rust,
                AnalyzerDelegate::Rust(RustAnalyzer::from_project(project)),
            ),
        ]);
        (temp, MultiAnalyzer::new(delegates))
    }

    #[test]
    fn definition_query_builds_each_delegate_index_once_and_scans_nothing() {
        let (_temp, analyzer) = two_language_analyzer();
        analyzer
            .test_hooks()
            .reset_global_usage_definition_index_build_count_for_test();
        analyzer
            .test_hooks()
            .reset_full_declaration_scan_count_for_test();

        // Two queries, so a view that rebuilt per call would show it.
        assert_eq!(
            analyzer
                .global_usage_definition_index()
                .fqn("app.App")
                .len(),
            1
        );
        assert_eq!(
            analyzer.global_usage_definition_index().fqn("Widget").len(),
            1
        );

        for (language, delegate) in analyzer.delegates() {
            assert_eq!(
                delegate
                    .analyzer()
                    .test_hooks()
                    .global_usage_definition_index_build_count_for_test(),
                1,
                "delegate {language:?} built its definition index more than once"
            );
        }
        // The merged view answers out of the delegates' own indexes; it must
        // never fall back to a full declaration scan per delegate.
        assert_eq!(
            analyzer.test_hooks().full_declaration_scan_count_for_test(),
            0
        );
    }

    #[test]
    fn update_with_only_irrelevant_files_retains_indexes_and_snapshot_caches() {
        let (_temp, analyzer) = two_language_analyzer();
        analyzer
            .test_hooks()
            .reset_global_usage_definition_index_build_count_for_test();
        analyzer
            .test_hooks()
            .reset_full_declaration_scan_count_for_test();
        assert_eq!(
            analyzer
                .global_usage_definition_index()
                .fqn("app.App")
                .len(),
            1
        );

        let readme = ProjectFile::new(analyzer.project().root().to_path_buf(), "README.md");
        let updated = analyzer.update(&BTreeSet::from([readme]));

        assert_eq!(
            updated.global_usage_definition_index().fqn("app.App").len(),
            1
        );
        for (language, delegate) in updated.delegates() {
            assert_eq!(
                delegate
                    .analyzer()
                    .test_hooks()
                    .global_usage_definition_index_build_count_for_test(),
                1,
                "delegate {language:?} rebuilt its definition index after an irrelevant change"
            );
        }
        assert_eq!(
            updated.test_hooks().full_declaration_scan_count_for_test(),
            0
        );
        assert!(
            Arc::ptr_eq(&analyzer.snapshot_caches, &updated.snapshot_caches),
            "an update touching no analyzed file must keep the workspace derived-layer caches"
        );
    }

    #[test]
    fn update_touching_an_analyzed_file_allocates_fresh_snapshot_caches() {
        let (_temp, analyzer) = two_language_analyzer();
        let source = ProjectFile::new(analyzer.project().root().to_path_buf(), "src/App.java");
        let updated = analyzer.update(&BTreeSet::from([source]));

        assert!(!Arc::ptr_eq(
            &analyzer.snapshot_caches,
            &updated.snapshot_caches
        ));
    }

    #[test]
    fn overlay_snapshot_recomputes_the_merged_view_from_retained_delegates() {
        let (_temp, analyzer) = two_language_analyzer();
        let project: Arc<dyn Project> = Arc::new(FileSetProject::new(
            analyzer.project().root().to_path_buf(),
            [std::path::PathBuf::from("src/App.java")],
        ));
        let snapshot = analyzer.clone_with_project(project);

        assert!(!Arc::ptr_eq(
            &analyzer.snapshot_caches,
            &snapshot.snapshot_caches
        ));
        assert_eq!(
            snapshot
                .global_usage_definition_index()
                .fqn("app.App")
                .len(),
            1
        );
    }
}
