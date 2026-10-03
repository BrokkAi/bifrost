//! The analyzer-owned half of Rust's graph support: retained bounded indexes
//! and the forwards `bifrost-lsp` and the SPI block reach through.
//!
//! Everything these methods call lives in [`brokk_bifrost_rust::graph_support`];
//! The analyzer type and its caches are analysis-owned, while reference
//! contexts are query-scoped views implemented in `bifrost-rust`.

use crate::analyzer::usages::{ExportIndex, ImportBinder};
use crate::analyzer::{AnalyzerQueryScope, QueryScope, QueryToken};
use crate::analyzer::{CodeUnit, CodeUnitIndex, ProjectFile};
use crate::hash::HashSet;
use brokk_bifrost_rust::graph_support::{
    ReferenceContextResult, RustCargoRouteError, RustPackageFileIndex, RustReferenceContext,
    exact_member, forward_reference_context_of, forward_reference_context_of_while,
    is_rust_trait_declaration, reference_context_of, reference_context_of_while,
    resolve_module_files, rust_trait_member_implementations, rust_usage_candidate_files,
};
use brokk_bifrost_rust::lexical_scope::insert_rust_import_binding;
use std::sync::Arc;

use super::RustAnalyzer;

impl RustAnalyzer {
    /// The cached per-file export index. Shared by handle: the index is
    /// immutable for the analyzer instance's lifetime, and callers ask for it
    /// once per export name per pending file, so deep-cloning the whole map on
    /// every cache hit was pure waste (#1230 item 5).
    pub fn export_index_of(&self, file: &ProjectFile) -> ReferenceContextResult<Arc<ExportIndex>> {
        self.export_index_of_while(file, &|| true)
    }

    pub fn export_index_of_while(
        &self,
        file: &ProjectFile,
        progress: &dyn Fn() -> bool,
    ) -> ReferenceContextResult<Arc<ExportIndex>> {
        if !progress() {
            return Err(brokk_bifrost_rust::graph_support::ReferenceContextError::Interrupted);
        }
        if let Some(cached) = self.export_indexes.get(file) {
            return Ok(cached);
        }
        let declarations = self.declarations(file);
        let _scope = AnalyzerQueryScope::new(self);
        let index = Arc::new(
            brokk_bifrost_rust::graph_support::export_index_of_declarations_while(
                self,
                file,
                &declarations,
                progress,
            )?,
        );
        self.export_indexes.insert(file.clone(), index.clone());
        Ok(index)
    }

    pub fn import_binder_of(&self, token: QueryToken<'_>, file: &ProjectFile) -> ImportBinder {
        let mut binder = ImportBinder::empty();

        for import in self.inner.import_info_of(token, file) {
            insert_rust_import_binding(&mut binder, &import);
        }

        binder
    }

    pub fn reference_context_of<'a>(
        &'a self,
        token: QueryToken<'a>,
        file: &ProjectFile,
    ) -> RustReferenceContext<'a> {
        reference_context_of(self, token, file)
    }

    pub fn reference_context_of_while<'a>(
        &'a self,
        token: QueryToken<'a>,
        file: &ProjectFile,
        keep_going: impl Fn() -> bool + 'a,
    ) -> RustReferenceContext<'a> {
        reference_context_of_while(self, token, file, keep_going)
    }

    pub fn forward_reference_context_of<'a>(
        &'a self,
        token: QueryToken<'a>,
        file: &ProjectFile,
    ) -> RustReferenceContext<'a> {
        forward_reference_context_of(self, token, file)
    }

    pub fn forward_reference_context_of_while<'a>(
        &'a self,
        token: QueryToken<'a>,
        file: &ProjectFile,
        keep_going: impl Fn() -> bool + 'a,
    ) -> RustReferenceContext<'a> {
        forward_reference_context_of_while(self, token, file, keep_going)
    }

    /// The analyzed-file listing bucketed by path-derived Rust package name,
    /// built at most once per analyzer instance. Same lifetime and invalidation
    /// as `cargo_routes` — both are pure projections of the analyzed-file set,
    /// so both are rebuilt by `update`/`update_all`/`clone_with_project` and by
    /// nothing else (#1230 item 3).
    pub fn package_file_index(&self) -> Arc<RustPackageFileIndex> {
        self.package_file_index
            .get_or_init(|| Arc::new(RustPackageFileIndex::build(self.get_analyzed_files())))
            .clone()
    }

    pub fn resolve_module_files(
        &self,
        importing_file: &ProjectFile,
        module_specifier: &str,
    ) -> ReferenceContextResult<Vec<ProjectFile>> {
        let scope = AnalyzerQueryScope::new(self);
        resolve_module_files(self, scope.token(), importing_file, module_specifier)
    }

    pub fn exact_member(
        &self,
        source_file: &ProjectFile,
        owner_name: &str,
        member_name: &str,
        instance_receiver: bool,
    ) -> Option<CodeUnit> {
        exact_member(
            self,
            source_file,
            owner_name,
            member_name,
            instance_receiver,
        )
    }

    pub fn rust_usage_candidate_files(
        &self,
        export_names: HashSet<String>,
        target: &CodeUnit,
    ) -> HashSet<ProjectFile> {
        rust_usage_candidate_files(self, export_names, target)
    }

    /// Reached from `bifrost-lsp`'s goto-type-definition handler, which holds a
    /// downcast analyzer rather than this module's source trait.
    pub fn rust_trait_member_implementations(
        &self,
        trait_member: &CodeUnit,
    ) -> Result<Option<Vec<CodeUnit>>, RustCargoRouteError> {
        let scope = AnalyzerQueryScope::new(self);
        Ok(rust_trait_member_implementations(
            self,
            scope.token(),
            trait_member,
        )?)
    }

    /// Reached from `bifrost-lsp`; see
    /// [`Self::rust_trait_member_implementations`].
    pub fn is_rust_trait_declaration(
        &self,
        code_unit: &CodeUnit,
    ) -> Result<bool, RustCargoRouteError> {
        is_rust_trait_declaration(self, code_unit)
    }
}

/// Frozen closure-enumerating reference resolver from before the per-site
/// rewrite. It is intentionally test-only: the live implementation must never
/// enumerate a namespace or glob export surface just to resolve one source
/// name, while this oracle does exactly that to pin answer equivalence.
#[cfg(test)]
mod frozen {
    use super::*;
    use crate::hash::HashMap;
    use brokk_bifrost_core::analyzer::usages::model::{ExportEntry, ImportKind};
    use brokk_bifrost_rust::declarations::rust_package_name;
    use brokk_bifrost_rust::graph_support::{
        canonical_export_fqn_from_files, resolve_module_package,
    };
    use brokk_bifrost_rust::imports::{
        resolve_rust_module_path_with_crate, rust_crate_root_package,
    };

    #[derive(Debug, Default)]
    pub(super) struct FrozenReferenceContext {
        package: String,
        crate_package: String,
        named: HashMap<String, String>,
        namespace: HashMap<String, String>,
        scoped: HashMap<String, String>,
        glob: HashMap<String, String>,
        same_file: HashMap<String, String>,
    }

    impl FrozenReferenceContext {
        pub(super) fn resolve_bare(&self, name: &str) -> Option<&str> {
            self.named
                .get(name)
                .or_else(|| self.namespace.get(name))
                .or_else(|| self.same_file.get(name))
                .or_else(|| self.glob.get(name))
                .map(String::as_str)
        }

        pub(super) fn bare_names_resolving_to(&self, target: &str) -> HashSet<String> {
            self.named
                .iter()
                .chain(self.namespace.iter())
                .chain(self.same_file.iter())
                .chain(self.glob.iter())
                .filter(|(_, fqn)| fqn.as_str() == target)
                .map(|(name, _)| name.clone())
                .collect()
        }

        pub(super) fn resolve_scoped(&self, path: &str, name: &str) -> Option<String> {
            self.resolve_scoped_owner(path)
                .map(|owner| join(&owner, name))
        }

        pub(super) fn resolve_scoped_owner(&self, path: &str) -> Option<String> {
            if let Some(canonical) = self.scoped.get(path) {
                return Some(canonical.clone());
            }
            if let Some((parent, item)) = path.rsplit_once("::")
                && let Some(owner) = self.resolve_scoped_owner(parent)
            {
                return Some(join(&owner, item));
            }
            if let Some(package) = self.namespace.get(path) {
                return Some(package.clone());
            }
            if rooted(path)
                && let Some(package) =
                    resolve_rust_module_path_with_crate(&self.package, &self.crate_package, path)
            {
                return Some(package);
            }
            self.named
                .get(path)
                .or_else(|| self.same_file.get(path))
                .or_else(|| self.glob.get(path))
                .cloned()
        }
    }

    pub(super) fn build(
        analyzer: &RustAnalyzer,
        token: QueryToken<'_>,
        file: &ProjectFile,
        forward: bool,
    ) -> FrozenReferenceContext {
        let binder = analyzer.import_binder_of(token, file);
        let same_file = analyzer
            .declarations(file)
            .into_iter()
            .map(|unit| (unit.identifier().to_string(), unit.fq_name()))
            .collect();
        let mut named = HashMap::default();
        let mut namespace = HashMap::default();
        let mut scoped = HashMap::default();
        let mut glob_candidates: HashMap<String, HashSet<String>> = HashMap::default();

        for (local, binding) in &binder.bindings {
            match binding.kind {
                ImportKind::Named => {
                    if let Some(imported) = binding.imported_name.as_deref() {
                        let files = analyzer
                            .resolve_module_files(file, &binding.module_specifier)
                            .expect("published frozen fixture routes");
                        let resolved = canonical(analyzer, token, &files, imported, forward)
                            .or_else(|| {
                                resolve_module_package(
                                    analyzer,
                                    token,
                                    file,
                                    &binding.module_specifier,
                                )
                                .expect("published frozen fixture routes")
                                .map(|package| join(&package, imported))
                            });
                        if let Some(resolved) = resolved {
                            named.insert(local.clone(), resolved);
                        }
                    }
                }
                ImportKind::Namespace => {
                    if let Some(package) =
                        resolve_module_package(analyzer, token, file, &binding.module_specifier)
                            .expect("published frozen fixture routes")
                    {
                        namespace.insert(local.clone(), package);
                    }
                    let files = analyzer
                        .resolve_module_files(file, &binding.module_specifier)
                        .expect("published frozen fixture routes");
                    for name in export_names(analyzer, &files) {
                        if let Some(fqn) = canonical(analyzer, token, &files, &name, forward) {
                            scoped.insert(format!("{local}::{name}"), fqn);
                        }
                    }
                }
                ImportKind::Glob => {
                    let files = analyzer
                        .resolve_module_files(file, &binding.module_specifier)
                        .expect("published frozen fixture routes");
                    for name in export_names(analyzer, &files) {
                        if let Some(fqn) = canonical(analyzer, token, &files, &name, forward) {
                            glob_candidates.entry(name).or_default().insert(fqn);
                        }
                    }
                }
                ImportKind::Default | ImportKind::CommonJsRequire => {}
            }
        }

        let own_files = [file.clone()];
        let own_index = analyzer
            .export_index_of(file)
            .expect("published frozen fixture exports");
        let mut own_names: HashSet<String> = own_index.exports_by_name.keys().cloned().collect();
        for star in &own_index.reexport_stars {
            let files = analyzer
                .resolve_module_files(file, &star.module_specifier)
                .expect("published frozen fixture routes");
            own_names.extend(export_names(analyzer, &files));
        }
        for name in own_names {
            if matches!(
                own_index.exports_by_name.get(&name),
                Some(ExportEntry::Local { .. })
            ) {
                continue;
            }
            if let Some(fqn) = canonical(analyzer, token, &own_files, &name, forward) {
                named.entry(name).or_insert(fqn);
            }
        }

        let glob = glob_candidates
            .into_iter()
            .filter_map(|(name, mut candidates)| {
                (candidates.len() == 1)
                    .then(|| (name, candidates.drain().next().expect("one glob candidate")))
            })
            .collect();
        FrozenReferenceContext {
            package: rust_package_name(file),
            crate_package: rust_crate_root_package(file),
            named,
            namespace,
            scoped,
            glob,
            same_file,
        }
    }

    fn canonical(
        analyzer: &RustAnalyzer,
        token: QueryToken<'_>,
        files: &[ProjectFile],
        name: &str,
        forward: bool,
    ) -> Option<String> {
        canonical_export_fqn_from_files(analyzer, token, files, name, forward, &|| true)
            .expect("uninterrupted frozen export traversal")
    }

    fn export_names(analyzer: &RustAnalyzer, files: &[ProjectFile]) -> HashSet<String> {
        let mut names = HashSet::default();
        let mut visited = HashSet::default();
        let mut pending = files.to_vec();
        while let Some(file) = pending.pop() {
            if !visited.insert(file.clone()) {
                continue;
            }
            let index = analyzer
                .export_index_of(&file)
                .expect("published frozen fixture exports");
            names.extend(index.exports_by_name.keys().cloned());
            for star in &index.reexport_stars {
                pending.extend(
                    analyzer
                        .resolve_module_files(&file, &star.module_specifier)
                        .expect("published frozen fixture routes"),
                );
            }
        }
        names
    }

    fn join(owner: &str, name: &str) -> String {
        if owner.is_empty() {
            name.to_string()
        } else {
            format!("{owner}.{name}")
        }
    }

    fn rooted(path: &str) -> bool {
        matches!(path.split("::").next(), Some("crate" | "self" | "super"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::usages::ExportEntry;
    use crate::analyzer::{IAnalyzer, Language};
    use crate::inline_project::InlineTestProject;
    use crate::test_support::AnalyzerFixture;
    use std::cell::Cell;
    use std::collections::BTreeSet;

    #[test]
    fn unavailable_or_cancelled_derivation_does_not_publish_export_or_declaration_caches() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", "pub mod part;\n")
            .file("src/part.rs", "pub struct Target;\n")
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/part.rs");
        assert!(matches!(
            analyzer.export_index_of_while(&file, &|| false),
            Err(brokk_bifrost_rust::graph_support::ReferenceContextError::Interrupted)
        ));
        assert!(analyzer.export_indexes.get(&file).is_none());

        analyzer.analyzer_store().delete_rust_facts_for_test("rust");
        {
            let scope = AnalyzerQueryScope::new(&analyzer);
            assert!(analyzer.export_index_of(&file).is_err());
            assert!(analyzer.rust_declaration_facts_of(&file).is_err());
            assert!(scope.store_error().is_some());
        }
        assert!(analyzer.export_indexes.get(&file).is_none());
        assert!(analyzer.declaration_facts.get(&file).is_none());

        analyzer.warm_usage_facts();
        assert!(
            analyzer
                .export_index_of(&file)
                .unwrap()
                .exports_by_name
                .contains_key("Target")
        );
        assert!(
            !analyzer
                .rust_declaration_facts_of(&file)
                .unwrap()
                .identities
                .is_empty()
        );
    }

    #[test]
    fn export_index_uses_all_canonical_declaration_visibility_alternatives() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", "pub mod part;\n")
            .file(
                "src/part.rs",
                r#"
#[cfg(not(feature = "public"))]
fn repeated() {}
#[cfg(feature = "public")]
pub fn repeated() {}
pub(crate) fn crate_visible() {}
pub(in crate) fn crate_restricted() {}
pub(self) fn self_only() {}
pub(super) fn parent_only() {}
fn private() {}
pub fn _hidden_by_convention() {}
pub struct Container { pub field: usize }
wrap! { pub fn generated() {} }
"#,
            )
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/part.rs");
        let properties = analyzer
            .declaration_source_properties(&file, &|| true)
            .unwrap();
        let repeated = properties
            .iter()
            .find(|(unit, _)| unit.identifier() == "repeated")
            .expect("repeated source declarations share a mounted CodeUnit")
            .1;
        assert_eq!(repeated.len(), 2);
        assert_eq!(
            repeated[0].visibility,
            brokk_bifrost_rust::imports::RustVisibility::Private
        );
        assert_eq!(
            repeated[1].visibility,
            brokk_bifrost_rust::imports::RustVisibility::Public
        );
        let index = analyzer
            .export_index_of(&file)
            .expect("canonical export visibility");
        let actual: BTreeSet<_> = index.exports_by_name.keys().map(String::as_str).collect();
        assert_eq!(
            actual,
            BTreeSet::from([
                "repeated",
                "crate_visible",
                "crate_restricted",
                "Container",
                "generated"
            ])
        );
        let scope = AnalyzerQueryScope::new(&analyzer);
        for (name, public_like, export_visible) in [
            ("repeated", true, true),
            ("generated", true, true),
            ("crate_visible", true, true),
            ("crate_restricted", true, true),
            ("self_only", true, false),
            ("parent_only", true, false),
            ("private", false, false),
        ] {
            let unit = properties
                .keys()
                .find(|unit| unit.identifier() == name)
                .unwrap();
            assert_eq!(
                brokk_bifrost_rust::graph_support::is_rust_public_like_declaration(&analyzer, unit)
                    .unwrap(),
                public_like,
                "public-like {name}"
            );
            assert_eq!(
                brokk_bifrost_rust::graph_support::is_rust_export_visible_declaration(
                    &analyzer, unit
                )
                .unwrap(),
                export_visible,
                "export-visible {name}"
            );
        }
        for name in ["repeated", "generated"] {
            let expected = properties
                .keys()
                .find(|unit| unit.identifier() == name)
                .unwrap()
                .fq_name();
            for forward in [false, true] {
                assert_eq!(
                    brokk_bifrost_rust::graph_support::canonical_export_fqn_from_files(
                        &analyzer,
                        scope.token(),
                        std::slice::from_ref(&file),
                        name,
                        forward,
                        &|| true
                    )
                    .unwrap(),
                    Some(expected.clone()),
                    "export FQN and canonical visibility must agree for {name}, forward={forward}"
                );
            }
        }
    }

    #[test]
    fn value_constructor_classification_uses_all_canonical_source_alternatives() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "src/lib.rs",
                r#"
pub struct Named { pub value: usize }
pub struct Tuple(pub usize);
pub struct Unit;
#[cfg(feature = "named")]
pub struct Alternative { pub value: usize }
#[cfg(not(feature = "named"))]
pub struct Alternative;
wrap! { pub struct Generated(pub usize); }
pub fn function() {}
"#,
            )
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let properties = analyzer
            .declaration_source_properties(&file, &|| true)
            .unwrap();
        let declarations = analyzer.declarations(&file);
        for (name, expected) in [
            ("Named", false),
            ("Tuple", true),
            ("Unit", true),
            ("Alternative", true),
            ("Generated", true),
            ("function", false),
        ] {
            let declaration = declarations
                .iter()
                .find(|declaration| declaration.identifier() == name)
                .unwrap();
            if name == "Alternative" {
                let rows = properties.get(declaration).unwrap();
                assert_eq!(rows.len(), 2);
                assert!(rows[0].value_constructor.is_none());
                assert!(rows[1].value_constructor.is_some());
            }
            assert_eq!(
                brokk_bifrost_rust::graph_support::has_rust_value_constructor(
                    &analyzer,
                    declaration
                ),
                Ok(expected),
                "{name}"
            );
        }
    }

    #[test]
    fn value_constructor_classification_requires_publication_and_recovers_after_repair() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", "pub struct Tuple(pub usize);\n")
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let declaration = analyzer
            .declarations(&file)
            .into_iter()
            .find(|declaration| declaration.identifier() == "Tuple")
            .unwrap();
        analyzer.analyzer_store().delete_rust_facts_for_test("rust");
        assert_eq!(
            brokk_bifrost_rust::graph_support::has_rust_value_constructor(&analyzer, &declaration),
            Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Unavailable)
        );
        assert_eq!(
            brokk_bifrost_rust::graph_support::is_rust_struct_declaration(&analyzer, &declaration),
            Err(RustCargoRouteError::Unavailable)
        );
        analyzer.warm_usage_facts();
        assert_eq!(
            brokk_bifrost_rust::graph_support::has_rust_value_constructor(&analyzer, &declaration),
            Ok(true)
        );
        assert_eq!(
            brokk_bifrost_rust::graph_support::is_rust_struct_declaration(&analyzer, &declaration),
            Ok(true)
        );
    }

    #[test]
    fn declaration_classifiers_keep_alternatives_and_require_source_identity() {
        use brokk_bifrost_rust::graph_support as support;
        type Classifier =
            fn(&dyn support::RustSource, &CodeUnit) -> Result<bool, RustCargoRouteError>;
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "src/lib.rs",
                r#"
#[cfg(feature = "struct")]
pub struct Alternative;
#[cfg(not(feature = "struct"))]
pub trait Alternative {}
pub enum Choice { Variant }
pub const CONSTANT: u8 = 0;
pub static STATIC: u8 = 0;
pub type Alias = u8;
pub fn function() {}
#[cfg(feature = "private")]
macro_rules! repeated_macro { () => {}; }
#[cfg(not(feature = "private"))]
#[macro_export]
macro_rules! repeated_macro { () => {}; }
wrap! { pub trait Embedded {} }
"#,
            )
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let declarations = analyzer.declarations(&file);
        let unit = |name: &str| {
            declarations
                .iter()
                .find(|unit| unit.identifier() == name)
                .unwrap()
        };
        let properties = analyzer
            .declaration_source_properties(&file, &|| true)
            .unwrap();
        assert_eq!(properties[unit("Alternative")].len(), 2);
        assert_eq!(properties[unit("repeated_macro")].len(), 2);
        let cases: &[(Classifier, &[&str])] = &[
            (support::is_rust_struct_declaration, &["Alternative"]),
            (
                support::is_rust_trait_declaration,
                &["Alternative", "Embedded"],
            ),
            (support::is_rust_enum_declaration, &["Choice"]),
            (support::is_rust_enum_variant_declaration, &["Variant"]),
            (
                support::is_rust_const_or_static_declaration,
                &["CONSTANT", "STATIC"],
            ),
            (support::is_rust_free_function_declaration, &["function"]),
            (
                support::is_rust_module_value_declaration,
                &["CONSTANT", "STATIC"],
            ),
            (support::is_rust_type_alias_declaration, &["Alias"]),
            (
                support::is_rust_macro_export_declaration,
                &["repeated_macro"],
            ),
        ];
        for &(classify, expected_names) in cases {
            for name in [
                "Alternative",
                "Embedded",
                "Choice",
                "Variant",
                "CONSTANT",
                "STATIC",
                "Alias",
                "repeated_macro",
                "function",
            ] {
                assert_eq!(
                    classify(&analyzer, unit(name)),
                    Ok(expected_names.contains(&name)),
                    "expected {expected_names:?}, candidate {name}"
                );
            }
            let missing = CodeUnit::new(
                file.clone(),
                crate::analyzer::CodeUnitType::Macro,
                "crate",
                "missing",
            );
            assert_eq!(
                classify(&analyzer, &missing),
                Err(RustCargoRouteError::Unavailable)
            );
        }
    }

    #[test]
    fn module_value_classification_keeps_kind_and_boundary_on_one_source_alternative() {
        use brokk_bifrost_core::analyzer::rust_facts::{
            RustDeclarationBoundary, RustDeclarationKind,
        };
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "src/lib.rs",
                "#[cfg(feature = \"field\")]\npub struct Holder { pub Mixed: u8 }\n#[cfg(not(feature = \"field\"))]\npub trait Holder { const Mixed: u8 = 0; }\n",
            )
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let candidate = analyzer
            .declarations(&file)
            .into_iter()
            .find(|unit| unit.identifier() == "Mixed")
            .unwrap();
        let properties = analyzer
            .declaration_source_properties(&file, &|| true)
            .unwrap();
        let alternatives = &properties[&candidate];
        assert_eq!(alternatives.len(), 2, "{alternatives:?}");
        assert!(
            alternatives
                .iter()
                .any(|property| property.kind == RustDeclarationKind::Const)
        );
        assert!(
            alternatives
                .iter()
                .any(|property| property.nearest_declaration_boundary
                    == RustDeclarationBoundary::ModuleOrFile)
        );
        assert_eq!(
            brokk_bifrost_rust::graph_support::is_rust_module_value_declaration(
                &analyzer, &candidate
            ),
            Ok(false),
            "the associated const cannot borrow the ordinary field's enclosing boundary"
        );
    }

    #[test]
    fn export_index_rejects_a_declaration_without_canonical_properties() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", "pub struct Present;\n")
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let mut declarations = analyzer.declarations(&file);
        let missing = CodeUnit::new(
            file.clone(),
            crate::analyzer::CodeUnitType::Function,
            "crate",
            "missing_source_identity",
        );
        declarations.insert(missing.clone());
        assert_eq!(
            brokk_bifrost_rust::graph_support::has_rust_value_constructor(&analyzer, &missing),
            Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Unavailable)
        );
        assert_eq!(
            brokk_bifrost_rust::graph_support::is_rust_public_like_declaration(&analyzer, &missing),
            Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Unavailable)
        );
        assert_eq!(
            brokk_bifrost_rust::graph_support::is_rust_export_visible_declaration(
                &analyzer, &missing
            ),
            Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Unavailable)
        );
        assert!(matches!(
            brokk_bifrost_rust::graph_support::export_index_of_declarations_while(
                &analyzer,
                &file,
                &declarations,
                &|| true
            ),
            Err(
                brokk_bifrost_rust::graph_support::ReferenceContextError::CargoRoutes(
                    brokk_bifrost_rust::graph_support::RustCargoRouteError::Unavailable
                )
            )
        ));
        assert!(analyzer.export_indexes.get(&file).is_none());
        assert!(
            analyzer
                .export_index_of(&file)
                .unwrap()
                .exports_by_name
                .contains_key("Present")
        );
    }

    #[test]
    fn cancelled_canonical_export_visibility_does_not_publish_partial_indexes() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "src/lib.rs",
                "pub struct First;\npub struct Second;\npub struct Third;\n",
            )
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let checks = Cell::new(0);
        assert!(matches!(
            analyzer.export_index_of_while(&file, &|| {
                checks.set(checks.get() + 1);
                checks.get() < 12
            }),
            Err(brokk_bifrost_rust::graph_support::ReferenceContextError::Interrupted)
        ));
        assert!(analyzer.export_indexes.get(&file).is_none());
        let index = analyzer
            .export_index_of(&file)
            .expect("complete retry after cancellation");
        assert_eq!(
            index
                .exports_by_name
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["First", "Second", "Third"])
        );
    }

    #[test]
    fn export_index_uses_published_root_imports_and_excludes_non_root_imports() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "src/lib.rs",
                "pub mod models;
pub use crate::models::{Thing as RenamedThing, *};
pub use crate::models::Alias;

fn local_scope() {
    pub use crate::models::LocalOnly;
    let _ = LocalOnly;
}

mod nested {
    pub use crate::models::NestedOnly;
}

pub extern crate external as external_alias;

macro_rules! passthrough { ($($item:item)*) => { $($item)* }; }
passthrough! {
    pub use crate::models::MacroOnly;
}
",
            )
            .file(
                "src/models.rs",
                "pub struct Thing;
pub struct Alias;
pub struct LocalOnly;
pub struct NestedOnly;
pub struct MacroOnly;
",
            )
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let index = analyzer
            .export_index_of(&file)
            .expect("published root export facts");

        assert_eq!(
            index.exports_by_name.get("RenamedThing"),
            Some(&ExportEntry::ReexportedNamed {
                module_specifier: "crate::models".to_string(),
                imported_name: "Thing".to_string(),
            })
        );
        assert_eq!(
            index.exports_by_name.get("Alias"),
            Some(&ExportEntry::ReexportedNamed {
                module_specifier: "crate::models".to_string(),
                imported_name: "Alias".to_string(),
            })
        );
        assert!(
            index
                .reexport_stars
                .iter()
                .any(|star| { star.module_specifier == "crate::models" })
        );

        for excluded in ["LocalOnly", "NestedOnly", "external_alias", "MacroOnly"] {
            assert!(
                !index.exports_by_name.contains_key(excluded),
                "non-root import {excluded} must not be an export"
            );
        }
    }

    #[test]
    fn missing_root_reexport_facts_are_unavailable_until_repaired() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", "pub use crate::missing::Alias;\n")
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");

        analyzer.analyzer_store().delete_rust_facts_for_test("rust");
        {
            let scope = AnalyzerQueryScope::new(&analyzer);
            assert!(matches!(
                analyzer.export_index_of(&file),
                Err(
                    brokk_bifrost_rust::graph_support::ReferenceContextError::CargoRoutes(
                        brokk_bifrost_rust::graph_support::RustCargoRouteError::Unavailable
                    )
                )
            ));
            assert!(scope.store_error().is_some());
        }
        assert!(analyzer.export_indexes.get(&file).is_none());

        analyzer.warm_usage_facts();
        let repaired = analyzer
            .export_index_of(&file)
            .expect("root reexport facts are available after repair");
        assert_eq!(
            repaired.exports_by_name.get("Alias"),
            Some(&ExportEntry::ReexportedNamed {
                module_specifier: "crate::missing".to_string(),
                imported_name: "Alias".to_string(),
            })
        );
    }

    const EQUIVALENCE_FIXTURE: &[(&str, &str)] = &[
        (
            "Cargo.toml",
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        ),
        (
            "src/lib.rs",
            "pub mod wide;\npub mod barrel;\npub mod consumer;\npub mod cyclic_a;\npub mod cyclic_b;\npub mod macros;\npub struct RootType;\n",
        ),
        (
            "src/wide.rs",
            "pub struct Widget;\npub struct Gadget;\npub fn make_widget() -> Widget { Widget }\npub const LIMIT: usize = 3;\npub enum Mode { On, Off }\nfn private_helper() {}\n",
        ),
        (
            "src/barrel.rs",
            "pub use crate::wide::Widget;\npub use crate::wide::Gadget as Renamed;\npub use crate::cyclic_a::*;\n",
        ),
        (
            "src/cyclic_a.rs",
            "pub use crate::cyclic_b::*;\npub struct AlphaItem;\n",
        ),
        (
            "src/cyclic_b.rs",
            "pub use crate::cyclic_a::*;\npub struct BetaItem;\n",
        ),
        (
            "src/macros.rs",
            "#[macro_export]\nmacro_rules! shout { () => {} }\npub fn use_macro() { crate::shout!(); }\n",
        ),
        (
            "src/consumer.rs",
            "use crate::wide;\nuse crate::barrel;\nuse crate::wide::Widget;\nuse crate::wide::Gadget as Alias;\nuse crate::barrel::Renamed;\nuse crate::barrel::*;\npub struct AlphaItem;\npub fn consume() { let _a = Widget; let _b = wide::make_widget(); let _c = Alias; let _d = Renamed; let _e = wide::LIMIT; let _h = barrel::Widget; let _i = barrel::Renamed; let _f = AlphaItem; let _g = BetaItem; }\n",
        ),
    ];

    const EQUIVALENCE_FILES: &[&str] = &[
        "src/lib.rs",
        "src/wide.rs",
        "src/barrel.rs",
        "src/cyclic_a.rs",
        "src/cyclic_b.rs",
        "src/macros.rs",
        "src/consumer.rs",
    ];
    const EQUIVALENCE_NAMES: &[&str] = &[
        "Widget",
        "Gadget",
        "Renamed",
        "Alias",
        "AlphaItem",
        "BetaItem",
        "RootType",
        "Mode",
        "LIMIT",
        "wide",
        "barrel",
        "consumer",
        "cyclic_a",
        "cyclic_b",
        "macros",
        "make_widget",
        "private_helper",
        "use_macro",
        "consume",
        "shout",
        "crate",
        "self",
        "super",
        "absent_name",
    ];
    const EQUIVALENCE_PREFIXES: &[&str] = &[
        "wide",
        "barrel",
        "cyclic_a",
        "cyclic_b",
        "macros",
        "crate",
        "crate::wide",
        "crate::barrel",
        "self",
        "super",
        "Widget",
        "Alias",
        "absent_prefix",
        "wide::Widget",
        "wide::make_widget",
        "wide::absent_name",
        "barrel::Widget",
        "barrel::Renamed",
        "barrel::AlphaItem",
        "barrel::BetaItem",
        "barrel::absent_name",
        "cyclic_a::BetaItem",
        "crate::wide::Widget",
        "self::AlphaItem",
    ];
    const EQUIVALENCE_TARGETS: &[&str] = &[
        "fixture.wide.Widget",
        "fixture.wide.Gadget",
        "fixture.wide.make_widget",
        "fixture.wide.LIMIT",
        "fixture.cyclic_a.AlphaItem",
        "fixture.cyclic_b.BetaItem",
        "fixture.consumer.AlphaItem",
        "fixture.wide",
        "fixture.barrel",
        "absent.Fqn",
    ];

    #[test]
    fn reference_resolution_matches_the_frozen_closure_algorithm() {
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, EQUIVALENCE_FIXTURE);
        let analyzer = RustAnalyzer::from_project(fixture.test_project().clone());
        let root = fixture.project_root();
        let consumer = ProjectFile::new(root.clone(), "src/consumer.rs");
        let scope = AnalyzerQueryScope::new(&analyzer);
        let anchors = analyzer.reference_context_of(scope.token(), &consumer);
        assert_eq!(
            anchors
                .resolve_scoped_owner("barrel::Widget")
                .unwrap()
                .as_deref(),
            Some("fixture.wide.Widget")
        );
        assert_eq!(
            anchors
                .resolve_scoped_owner("barrel::Renamed")
                .unwrap()
                .as_deref(),
            Some("fixture.wide.Gadget")
        );
        assert_eq!(
            anchors.resolve_bare("BetaItem").unwrap().as_deref(),
            Some("fixture.cyclic_b.BetaItem")
        );
        assert_eq!(
            anchors.resolve_bare("Alias").unwrap().as_deref(),
            Some("fixture.wide.Gadget")
        );
        assert_eq!(
            anchors.resolve_bare("AlphaItem").unwrap().as_deref(),
            Some("fixture.consumer.AlphaItem")
        );

        for relative in EQUIVALENCE_FILES {
            let file = ProjectFile::new(root.clone(), relative);
            for forward in [false, true] {
                let frozen = frozen::build(&analyzer, scope.token(), &file, forward);
                let live = if forward {
                    analyzer.forward_reference_context_of(scope.token(), &file)
                } else {
                    analyzer.reference_context_of(scope.token(), &file)
                };
                for name in EQUIVALENCE_NAMES {
                    assert_eq!(
                        live.resolve_bare(name).unwrap(),
                        frozen.resolve_bare(name).map(str::to_string),
                        "bare: file={relative} forward={forward} name={name}"
                    );
                }
                for prefix in EQUIVALENCE_PREFIXES {
                    assert_eq!(
                        live.resolve_scoped_owner(prefix).unwrap(),
                        frozen.resolve_scoped_owner(prefix),
                        "owner: file={relative} forward={forward} prefix={prefix}"
                    );
                    for name in EQUIVALENCE_NAMES {
                        assert_eq!(
                            live.resolve_scoped(prefix, name).unwrap(),
                            frozen.resolve_scoped(prefix, name),
                            "scoped: file={relative} forward={forward} prefix={prefix} name={name}"
                        );
                    }
                }
                for target in EQUIVALENCE_TARGETS {
                    let mut live_names: Vec<_> = live
                        .bare_names_resolving_to(target)
                        .unwrap()
                        .into_iter()
                        .collect();
                    let mut frozen_names: Vec<_> =
                        frozen.bare_names_resolving_to(target).into_iter().collect();
                    live_names.sort();
                    frozen_names.sort();
                    assert_eq!(
                        live_names, frozen_names,
                        "inverse: file={relative} forward={forward} target={target}"
                    );
                }
            }
        }
    }

    #[test]
    fn export_index_is_reused_while_reference_contexts_are_query_scoped() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Rust,
            &[
                ("src/lib.rs", "pub mod exports;\n"),
                (
                    "src/exports.rs",
                    "pub struct Public;\npub(crate) struct CrateVisible;\nstruct Private;\npub use std::collections::HashMap;\n",
                ),
            ],
        );
        let analyzer = RustAnalyzer::from_project(fixture.test_project().clone());
        let file = ProjectFile::new(fixture.project_root(), "src/exports.rs");

        let first = analyzer
            .export_index_of(&file)
            .expect("published fixture exports");
        let second = analyzer
            .export_index_of(&file)
            .expect("published fixture exports");

        assert!(Arc::ptr_eq(&first, &second));
        assert!(first.exports_by_name.contains_key("Public"));
        assert!(first.exports_by_name.contains_key("CrateVisible"));
        assert!(!first.exports_by_name.contains_key("Private"));
        assert!(first.exports_by_name.contains_key("HashMap"));
        let scope = AnalyzerQueryScope::new(&analyzer);
        assert_eq!(
            analyzer
                .forward_reference_context_of(scope.token(), &file)
                .resolve_bare("HashMap")
                .unwrap(),
            Some("std.collections.HashMap".to_string())
        );

        let unrelated_watcher_noise = ProjectFile::new(
            fixture.project_root(),
            format!(".bifrost/cache/{}", crate::cache_db::cache_db_file_name()),
        );
        let updated = analyzer.update(&BTreeSet::from([file.clone(), unrelated_watcher_noise]));
        let after_noop_update = updated
            .export_index_of(&file)
            .expect("published fixture exports");

        assert!(Arc::ptr_eq(&first, &after_noop_update));
        assert!(updated.export_indexes.get(&file).is_some());
    }

    #[test]
    fn issue_1228_forward_reference_query_observes_cancellation() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Rust,
            &[
                (
                    "src/lib.rs",
                    "pub mod exports;\nuse exports::{Alias, helper};\npub fn call(value: Alias) { helper(value); }\n",
                ),
                (
                    "src/exports.rs",
                    "pub struct Alias;\npub fn helper(_: Alias) {}\n",
                ),
            ],
        );
        let analyzer = RustAnalyzer::from_project(fixture.test_project().clone());
        let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
        let scope = AnalyzerQueryScope::new(&analyzer);
        let checks = Cell::new(0usize);

        let interrupted = analyzer.forward_reference_context_of_while(scope.token(), &file, || {
            let next = checks.get() + 1;
            checks.set(next);
            false
        });

        assert_eq!(
            interrupted.resolve_bare("Alias"),
            Err(brokk_bifrost_rust::graph_support::ReferenceContextError::Interrupted)
        );
        assert_eq!(checks.get(), 1);

        let complete = analyzer.forward_reference_context_of(scope.token(), &file);

        assert_eq!(
            complete.resolve_bare("Alias").unwrap(),
            Some("exports.Alias".to_string())
        );
        assert_eq!(
            complete.resolve_bare("helper").unwrap(),
            Some("exports.helper".to_string())
        );
    }

    #[test]
    fn issue_1304_inverted_reference_query_observes_cancellation() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Rust,
            &[
                (
                    "src/lib.rs",
                    "pub mod exports;\nuse exports::{Alias, helper};\npub fn call(value: Alias) { helper(value); }\n",
                ),
                (
                    "src/exports.rs",
                    "pub struct Alias;\npub fn helper(_: Alias) {}\n",
                ),
            ],
        );
        let analyzer = RustAnalyzer::from_project(fixture.test_project().clone());
        let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
        let scope = AnalyzerQueryScope::new(&analyzer);
        let checks = Cell::new(0usize);

        let interrupted = analyzer.reference_context_of_while(scope.token(), &file, || {
            let next = checks.get() + 1;
            checks.set(next);
            false
        });

        assert_eq!(
            interrupted.resolve_bare("Alias"),
            Err(brokk_bifrost_rust::graph_support::ReferenceContextError::Interrupted)
        );
        assert_eq!(checks.get(), 1);

        let complete = analyzer.reference_context_of(scope.token(), &file);

        assert_eq!(
            complete.resolve_bare("Alias").unwrap(),
            Some("exports.Alias".to_string())
        );
        assert_eq!(
            complete.resolve_bare("helper").unwrap(),
            Some("exports.helper".to_string())
        );
    }

    #[test]
    fn cargo_aware_bare_import_prefers_a_declared_local_module() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                concat!(
                    "[package]\nname = \"host\"\nversion = \"0.1.0\"\n",
                    "edition = \"2024\"\n",
                    "[dependencies]\ndep = { path = \"dep-crate\" }\n",
                ),
            )
            .file(
                "src/lib.rs",
                "pub mod dep;\nuse dep::target;\npub fn call() { target(); }\n",
            )
            .file("src/dep.rs", "pub fn target() {}\n")
            .file(
                "dep-crate/Cargo.toml",
                "[package]\nname = \"dep\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("dep-crate/src/lib.rs", "pub fn target() {}\n")
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let local_module = fixture.file("src/dep.rs");
        let scope = AnalyzerQueryScope::new(&analyzer);

        assert_eq!(
            analyzer
                .resolve_module_files(&file, "dep")
                .expect("published fixture routes"),
            vec![local_module]
        );
        assert_eq!(
            analyzer
                .forward_reference_context_of(scope.token(), &file)
                .resolve_bare("target")
                .unwrap(),
            Some("host.dep.target".to_string())
        );
    }

    #[test]
    fn module_visibility_keeps_same_named_cargo_target_parents_separate() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "a/Cargo.toml",
                "[package]\nname = \"duplicate\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("a/src/lib.rs", "pub mod outer { pub mod api {} }\n")
            .file(
                "z/Cargo.toml",
                "[package]\nname = \"duplicate\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("z/src/lib.rs", "mod outer { pub mod api {} }\n")
            .file(
                "host/Cargo.toml",
                concat!(
                    "[package]\nname = \"host\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
                    "[dependencies]\ndep = { package = \"duplicate\", path = \"../a\" }\n",
                ),
            )
            .file("host/src/lib.rs", "use dep::outer::api;\n")
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        assert_eq!(
            analyzer
                .resolve_module_files(&fixture.file("host/src/lib.rs"), "dep::outer::api")
                .unwrap(),
            vec![fixture.file("a/src/lib.rs")]
        );
    }

    #[test]
    fn cargo_aware_rust_2015_bare_import_starts_at_the_crate_root() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"legacy\"\nversion = \"0.1.0\"\nedition = \"2015\"\n",
            )
            .file("src/lib.rs", "mod root_item;\nmod consumer;\n")
            .file("src/root_item.rs", "pub fn target() {}\n")
            .file(
                "src/consumer.rs",
                "use root_item::target;\npub fn call() { target(); }\n",
            )
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/consumer.rs");
        let root_module = fixture.file("src/root_item.rs");
        let scope = AnalyzerQueryScope::new(&analyzer);

        assert_eq!(
            analyzer
                .resolve_module_files(&file, "root_item")
                .expect("published fixture routes"),
            vec![root_module]
        );
        assert_eq!(
            analyzer
                .forward_reference_context_of(scope.token(), &file)
                .resolve_bare("target")
                .unwrap(),
            Some("legacy.root_item.target".to_string())
        );
    }
}
