use crate::analyzer::common::language_for_file;
use crate::analyzer::languages::{LanguageSupport, language_support};
use crate::analyzer::{
    BoundedDefinitionLookup, CodeUnit, IAnalyzer, Language, ProjectFile, sort_units,
};
use crate::hash::{HashMap, HashSet};
use crate::path_utils::rel_path_string;
use std::borrow::Borrow;
use std::cell::{Cell, OnceCell, RefCell};

#[derive(Debug, Clone, Default)]
pub struct GlobalUsageDefinitionIndex {
    by_fqn: HashMap<String, Vec<CodeUnit>>,
    direct_children_by_fqn: HashMap<String, Vec<CodeUnit>>,
    direct_children_by_normalized_fqn: HashMap<String, Vec<CodeUnit>>,
    by_file_identifier: HashMap<(ProjectFile, String), Vec<CodeUnit>>,
    by_identifier: HashMap<String, Vec<CodeUnit>>,
    packages: HashSet<String>,
    files_by_package: HashMap<String, Vec<ProjectFile>>,
    package_languages: HashMap<String, HashSet<Language>>,
    child_packages_by_parent: HashMap<String, HashSet<String>>,
    by_normalized_fqn: HashMap<String, Vec<CodeUnit>>,
    types_by_package_simple: HashMap<(String, String), Vec<CodeUnit>>,
}

pub(crate) trait ForwardQueryProvider {
    fn forward_definition_fqn(&self, fqn: &str) -> Vec<CodeUnit>;
    fn forward_file_identifier(&self, file: &ProjectFile, identifier: &str) -> Vec<CodeUnit>;
    fn forward_direct_children(&self, owner: &CodeUnit) -> Vec<CodeUnit>;
    fn forward_package_exists(&self, package: &str) -> bool;
    fn forward_fqn_prefix_exists(&self, prefix: &str) -> bool;
}

macro_rules! impl_forward_query_provider {
    ($analyzer:ty) => {
        impl crate::analyzer::ForwardQueryProvider for $analyzer {
            fn forward_definition_fqn(&self, fqn: &str) -> Vec<crate::analyzer::CodeUnit> {
                self.inner.forward_definition_fqn(fqn)
            }

            fn forward_file_identifier(
                &self,
                file: &crate::analyzer::ProjectFile,
                identifier: &str,
            ) -> Vec<crate::analyzer::CodeUnit> {
                self.inner.forward_file_identifier(file, identifier)
            }

            fn forward_direct_children(
                &self,
                owner: &crate::analyzer::CodeUnit,
            ) -> Vec<crate::analyzer::CodeUnit> {
                self.inner.forward_direct_children(owner)
            }

            fn forward_package_exists(&self, package: &str) -> bool {
                self.inner.forward_package_exists(package)
            }

            fn forward_fqn_prefix_exists(&self, prefix: &str) -> bool {
                self.inner.forward_fqn_prefix_exists(prefix)
            }
        }
    };
}

pub(crate) use impl_forward_query_provider;

/// A forward-query view over an analyzer.  Keeping this separate from the
/// legacy index makes accidental whole-workspace fallback impossible at call
/// sites that accept only `BoundedDefinitionLookup`.
pub(crate) struct AnalyzerDefinitionLookup<'a> {
    analyzer: &'a dyn IAnalyzer,
    language: Cell<Language>,
    workspace_languages: OnceCell<Vec<Language>>,
    fqn_cache: RefCell<HashMap<(Language, String), Vec<CodeUnit>>>,
    file_identifier_cache: RefCell<HashMap<(ProjectFile, String), Vec<CodeUnit>>>,
    children_cache: RefCell<HashMap<(Language, String), Vec<CodeUnit>>>,
    package_cache: RefCell<HashMap<(Language, String), bool>>,
    prefix_cache: RefCell<HashMap<(Language, String), bool>>,
}

impl<'a> AnalyzerDefinitionLookup<'a> {
    pub(crate) fn new(analyzer: &'a dyn IAnalyzer, language: Language) -> Self {
        Self {
            analyzer,
            language: Cell::new(language),
            workspace_languages: OnceCell::new(),
            fqn_cache: RefCell::new(HashMap::default()),
            file_identifier_cache: RefCell::new(HashMap::default()),
            children_cache: RefCell::new(HashMap::default()),
            package_cache: RefCell::new(HashMap::default()),
            prefix_cache: RefCell::new(HashMap::default()),
        }
    }

    pub(crate) fn set_language(&self, language: Language) {
        self.language.set(language);
    }

    fn language_analyzer(&self, language: Language) -> Option<&dyn ForwardQueryProvider> {
        analyzer_for_language(self.analyzer, language)
    }

    /// The languages this workspace actually indexes, in a stable order.
    /// Resolved once per batch: `CodeUnitIndex::languages` rebuilds a set per call.
    fn workspace_languages(&self) -> &[Language] {
        self.workspace_languages
            .get_or_init(|| self.analyzer.languages().into_iter().collect())
    }

    fn fqn_for_language(&self, fqn: &str, language: Language) -> Vec<CodeUnit> {
        let key = (language, fqn.to_string());
        if let Some(cached) = self.fqn_cache.borrow().get(&key) {
            return cached.clone();
        }
        let matches = self
            .language_analyzer(language)
            .map(|analyzer| analyzer.forward_definition_fqn(fqn))
            .unwrap_or_default();
        self.fqn_cache.borrow_mut().insert(key, matches.clone());
        matches
    }
}

fn analyzer_for_language(
    analyzer: &dyn IAnalyzer,
    language: Language,
) -> Option<&dyn ForwardQueryProvider> {
    language_support(language).and_then(|support| support.forward_query_provider(analyzer))
}

impl BoundedDefinitionLookup for GlobalUsageDefinitionIndex {
    fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        Self::fqn(self, fqn)
    }

    fn fqn_in_language(&self, fqn: &str, language: Language) -> Vec<CodeUnit> {
        Self::fqn_in_language(self, fqn, language)
    }

    fn file_identifier(&self, file: &ProjectFile, ident: &str) -> Vec<CodeUnit> {
        Self::file_identifier(self, file, ident)
    }

    fn fqn_direct_children(&self, fqn: &str) -> Vec<CodeUnit> {
        Self::fqn_direct_children(self, fqn)
    }

    fn fqn_exists(&self, fqn: &str) -> bool {
        Self::fqn_exists(self, fqn)
    }

    fn package_exists(&self, package: &str) -> bool {
        Self::package_exists(self, package)
    }

    fn package_exists_in_language(&self, package: &str, language: Language) -> bool {
        Self::package_exists_in_language(self, package, language)
    }

    fn fqn_prefix_exists(&self, prefix: &str) -> bool {
        Self::fqn_prefix_exists(self, prefix)
    }
}

impl BoundedDefinitionLookup for AnalyzerDefinitionLookup<'_> {
    fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        self.fqn_for_language(fqn, self.language.get())
    }

    fn fqn_in_language(&self, fqn: &str, language: Language) -> Vec<CodeUnit> {
        self.fqn_for_language(fqn, language)
    }

    fn fqn_in_any_language(&self, fqn: &str) -> Vec<CodeUnit> {
        let mut units = Vec::new();
        for language in self.workspace_languages() {
            units.extend(self.fqn_for_language(fqn, *language));
        }
        sort_units(&mut units);
        units.dedup();
        units
    }

    fn package_exists_in_any_language(&self, package: &str) -> bool {
        self.workspace_languages()
            .iter()
            .any(|language| self.package_exists_in_language(package, *language))
    }

    fn file_identifier(&self, file: &ProjectFile, ident: &str) -> Vec<CodeUnit> {
        let key = (file.clone(), ident.to_string());
        if let Some(cached) = self.file_identifier_cache.borrow().get(&key) {
            return cached.clone();
        }
        let matches = self
            .language_analyzer(language_for_file(file))
            .map(|analyzer| analyzer.forward_file_identifier(file, ident))
            .unwrap_or_default();
        self.file_identifier_cache
            .borrow_mut()
            .insert(key, matches.clone());
        matches
    }

    fn fqn_direct_children(&self, fqn: &str) -> Vec<CodeUnit> {
        let language = self.language.get();
        let key = (language, fqn.to_string());
        if let Some(cached) = self.children_cache.borrow().get(&key) {
            return cached.clone();
        }
        let mut children = Vec::new();
        if let Some(analyzer) = self.language_analyzer(language) {
            for owner in self.fqn_for_language(fqn, language) {
                children.extend(analyzer.forward_direct_children(&owner));
            }
        }
        sort_units(&mut children);
        children.dedup();
        self.children_cache
            .borrow_mut()
            .insert(key, children.clone());
        children
    }

    fn fqn_exists(&self, fqn: &str) -> bool {
        !self.fqn(fqn).is_empty()
    }

    fn package_exists(&self, package: &str) -> bool {
        self.package_exists_in_language(package, self.language.get())
    }

    fn package_exists_in_language(&self, package: &str, language: Language) -> bool {
        let key = (language, package.to_string());
        if let Some(cached) = self.package_cache.borrow().get(&key) {
            return *cached;
        }
        let exists = self
            .language_analyzer(language)
            .is_some_and(|analyzer| analyzer.forward_package_exists(package));
        self.package_cache.borrow_mut().insert(key, exists);
        exists
    }

    fn fqn_prefix_exists(&self, prefix: &str) -> bool {
        let language = self.language.get();
        let key = (language, prefix.to_string());
        if let Some(cached) = self.prefix_cache.borrow().get(&key) {
            return *cached;
        }
        let exists = self
            .language_analyzer(language)
            .is_some_and(|analyzer| analyzer.forward_fqn_prefix_exists(prefix));
        self.prefix_cache.borrow_mut().insert(key, exists);
        exists
    }
}

impl GlobalUsageDefinitionIndex {
    pub(crate) fn from_declarations<I, N, S>(
        declarations: I,
        normalize: N,
        simple_type_name: S,
    ) -> Self
    where
        I: IntoIterator,
        I::Item: Borrow<CodeUnit>,
        N: Fn(&str) -> String,
        S: Fn(&CodeUnit) -> String,
    {
        let mut index = Self::default();
        for unit in declarations {
            let unit = unit.borrow();
            index.insert(unit, &normalize, &simple_type_name);
        }
        index.sort_entries();
        index
    }

    pub(crate) fn insert<N, S>(&mut self, unit: &CodeUnit, normalize: &N, simple_type_name: &S)
    where
        N: Fn(&str) -> String,
        S: Fn(&CodeUnit) -> String,
    {
        let fqn = unit.fq_name();
        let normalized_fqn = normalize(&fqn);
        let package = unit.package_name();
        let language = language_for_file(unit.source());
        self.packages.insert(package.to_string());
        self.files_by_package
            .entry(package.to_string())
            .or_default()
            .push(unit.source().clone());
        self.package_languages
            .entry(package.to_string())
            .or_default()
            .insert(language);
        if !package.is_empty() {
            let mut child = package;
            while let Some(parent) = package_parent_name(language, child) {
                self.child_packages_by_parent
                    .entry(parent.to_string())
                    .or_default()
                    .insert(child.to_string());
                self.package_languages
                    .entry(parent.to_string())
                    .or_default()
                    .insert(language);
                if parent.is_empty() {
                    break;
                }
                child = parent;
            }
        }
        self.by_normalized_fqn
            .entry(normalized_fqn.clone())
            .or_default()
            .push(unit.clone());
        if unit.is_class() {
            self.types_by_package_simple
                .entry((unit.package_name().to_string(), simple_type_name(unit)))
                .or_default()
                .push(unit.clone());
        }
        // fqname-M4: intentionally NOT `default_parent_fq_name` (a true segment
        // pop). Verified by mutation (issue #1168 batch 3): switching to the
        // segment pop regresses `usage_graph_csharp_test::
        // csharp_issue701_structured_expression_type_roots_have_inverted_graph_parity`.
        // The pop is *more* structurally correct for a `$`-nested C# type --
        // `Demo.InheritedOuter$Nested`'s immediate owner is `Demo.InheritedOuter`,
        // not `Demo` -- but this index's `direct_children_by_fqn`/
        // `direct_children_by_normalized_fqn` are relied upon elsewhere to key
        // nested types under their NAMESPACE (the naive rightmost-`.` cut,
        // which skips over a `$` boundary) for csharp's using-namespace nested-
        // type visibility resolution; switching to the immediate-owner cut is
        // a real behavior change there, not merely a representation change.
        // Revisit together with that consumer if this file is touched again.
        if let Some((parent_fqn, _)) = fqn.rsplit_once('.') {
            let parent_fqn = parent_fqn.to_string();
            self.direct_children_by_fqn
                .entry(parent_fqn.clone())
                .or_default()
                .push(unit.clone());
            self.direct_children_by_normalized_fqn
                .entry(normalize(&parent_fqn))
                .or_default()
                .push(unit.clone());
        }
        self.by_fqn.entry(fqn).or_default().push(unit.clone());
        self.by_file_identifier
            .entry((unit.source().clone(), unit.identifier().to_string()))
            .or_default()
            .push(unit.clone());
        self.by_identifier
            .entry(unit.identifier().to_string())
            .or_default()
            .push(unit.clone());
    }

    pub(crate) fn sort_entries(&mut self) {
        for units in self.by_fqn.values_mut() {
            sort_units(units);
        }
        for units in self.by_file_identifier.values_mut() {
            sort_units(units);
        }
        for units in self.by_identifier.values_mut() {
            sort_units(units);
            units.dedup();
        }
        for units in self.by_normalized_fqn.values_mut() {
            sort_units(units);
            units.dedup();
        }
        for units in self.types_by_package_simple.values_mut() {
            sort_units(units);
            units.dedup();
        }
        for units in self.direct_children_by_fqn.values_mut() {
            sort_units(units);
            units.dedup();
        }
        for units in self.direct_children_by_normalized_fqn.values_mut() {
            sort_units(units);
            units.dedup();
        }
        for files in self.files_by_package.values_mut() {
            files.sort_by_key(rel_path_string);
            files.dedup();
        }
    }

    pub(crate) fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        self.by_fqn.get(fqn).cloned().unwrap_or_default()
    }

    pub(crate) fn fqn_in_language(&self, fqn: &str, language: Language) -> Vec<CodeUnit> {
        self.by_fqn
            .get(fqn)
            .into_iter()
            .flat_map(|units| units.iter())
            .filter(|unit| language_for_file(unit.source()) == language)
            .cloned()
            .collect()
    }

    pub(crate) fn by_fqn(&self, fqn: &str) -> &[CodeUnit] {
        self.by_fqn.get(fqn).map(Vec::as_slice).unwrap_or(&[])
    }

    #[doc(hidden)]
    pub fn fqn_for_test(&self, fqn: &str) -> Vec<CodeUnit> {
        self.fqn(fqn)
    }

    pub(crate) fn fqn_direct_children(&self, fqn: &str) -> Vec<CodeUnit> {
        self.direct_children_by_fqn
            .get(fqn)
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn file_identifier(&self, file: &ProjectFile, ident: &str) -> Vec<CodeUnit> {
        self.by_file_identifier
            .get(&(file.clone(), ident.to_string()))
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn identifier(&self, ident: &str) -> &[CodeUnit] {
        self.by_identifier
            .get(ident)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    #[doc(hidden)]
    pub fn file_identifier_for_test(&self, file: &ProjectFile, ident: &str) -> Vec<CodeUnit> {
        self.file_identifier(file, ident)
    }

    pub(crate) fn fqn_exists(&self, fqn: &str) -> bool {
        self.by_fqn.contains_key(fqn)
    }

    pub(crate) fn by_normalized_fqn(&self, normalized: &str) -> &[CodeUnit] {
        self.by_normalized_fqn
            .get(normalized)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub(crate) fn types_in_package(&self, package: &str, simple: &str) -> &[CodeUnit] {
        self.types_by_package_simple
            .get(&(package.to_string(), simple.to_string()))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub(crate) fn package_types(&self) -> impl Iterator<Item = (&(String, String), &[CodeUnit])> {
        self.types_by_package_simple
            .iter()
            .map(|(key, units)| (key, units.as_slice()))
    }

    pub(crate) fn members_for_owner_name(
        &self,
        owner_fqn: &str,
        normalized_owner_fqn: &str,
        name: &str,
    ) -> Vec<&CodeUnit> {
        let exact = self
            .direct_children_by_fqn
            .get(owner_fqn)
            .into_iter()
            .flat_map(|units| units.iter())
            .filter(|unit| unit.identifier() == name)
            .collect::<Vec<_>>();
        if !exact.is_empty() {
            return exact;
        }
        self.direct_children_by_normalized_fqn
            .get(normalized_owner_fqn)
            .into_iter()
            .flat_map(|units| units.iter())
            .filter(|unit| unit.identifier() == name)
            .collect()
    }

    pub(crate) fn package_exists(&self, package: &str) -> bool {
        self.packages.contains(package)
    }

    pub(crate) fn package_exists_in_language(&self, package: &str, language: Language) -> bool {
        self.files_by_package
            .get(package)
            .is_some_and(|files| files.iter().any(|file| language_for_file(file) == language))
    }

    pub(crate) fn package_container_exists(&self, package: &str) -> bool {
        self.packages.contains(package) || self.child_packages_by_parent.contains_key(package)
    }

    pub(crate) fn package_files(&self, package: &str) -> &[ProjectFile] {
        self.files_by_package
            .get(package)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub(crate) fn package_languages(&self, package: &str) -> Vec<Language> {
        let mut languages: Vec<_> = self
            .package_languages
            .get(package)
            .into_iter()
            .flat_map(|languages| languages.iter().copied())
            .collect();
        if let Some(children) = self.child_packages_by_parent.get(package) {
            for child in children {
                languages.extend(
                    self.package_languages
                        .get(child)
                        .into_iter()
                        .flat_map(|languages| languages.iter().copied()),
                );
            }
        }
        languages.sort();
        languages.dedup();
        languages
    }

    pub(crate) fn child_packages(&self, package: &str) -> Vec<String> {
        let mut children: Vec<_> = self
            .child_packages_by_parent
            .get(package)
            .into_iter()
            .flat_map(|children| children.iter().cloned())
            .collect();
        children.sort();
        children
    }

    pub(crate) fn fqn_prefix_exists(&self, prefix: &str) -> bool {
        let prefix = format!("{prefix}.");
        self.by_fqn.keys().any(|fqn| fqn.starts_with(&prefix))
    }
}

/// A workspace's definition index, which may be spread over several
/// per-language shards.
///
/// A per-language analyzer owns exactly one [`GlobalUsageDefinitionIndex`] and
/// hands out `Single`.  A `MultiAnalyzer` hands out `Merged`, borrowing the
/// index of each of its delegates in delegate order (`BTreeMap<Language, _>`,
/// so the order is deterministic) rather than materializing a merged copy.
///
/// Shards never overlap: a `CodeUnit` carries the file it came from and one
/// file belongs to exactly one delegate, so chaining shard results needs no
/// cross-shard dedup.  Within a shard the index's own `sort_entries` ordering
/// is preserved.
///
/// Every query answers with an owned value.  A borrowing accessor
/// (`&[CodeUnit]`) cannot span shards without copying, and copying is the cost
/// this type exists to avoid.
pub enum DefinitionIndexHandle<'a> {
    Single(&'a GlobalUsageDefinitionIndex),
    Merged(Vec<&'a GlobalUsageDefinitionIndex>),
}

impl<'a> DefinitionIndexHandle<'a> {
    /// The shards, in delegate order.  Yields `&'a` borrows rather than
    /// borrows of `self` so shard-owned references can outlive the handle.
    fn shards(&self) -> impl Iterator<Item = &'a GlobalUsageDefinitionIndex> + '_ {
        match self {
            Self::Single(index) => std::slice::from_ref(index),
            Self::Merged(indexes) => indexes.as_slice(),
        }
        .iter()
        .copied()
    }

    /// The shards by value, for composing a wider handle out of narrower ones.
    pub(crate) fn into_shards(self) -> Vec<&'a GlobalUsageDefinitionIndex> {
        match self {
            Self::Single(index) => vec![index],
            Self::Merged(indexes) => indexes,
        }
    }

    pub(crate) fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        self.shards().flat_map(|shard| shard.fqn(fqn)).collect()
    }

    pub(crate) fn fqn_in_language(&self, fqn: &str, language: Language) -> Vec<CodeUnit> {
        self.shards()
            .flat_map(|shard| shard.fqn_in_language(fqn, language))
            .collect()
    }

    pub(crate) fn by_normalized_fqn(&self, normalized: &str) -> Vec<CodeUnit> {
        self.shards()
            .flat_map(|shard| shard.by_normalized_fqn(normalized).iter().cloned())
            .collect()
    }

    pub(crate) fn identifier(&self, ident: &str) -> Vec<CodeUnit> {
        self.shards()
            .flat_map(|shard| shard.identifier(ident).iter().cloned())
            .collect()
    }

    pub(crate) fn file_identifier(&self, file: &ProjectFile, ident: &str) -> Vec<CodeUnit> {
        self.shards()
            .flat_map(|shard| shard.file_identifier(file, ident))
            .collect()
    }

    pub(crate) fn fqn_direct_children(&self, fqn: &str) -> Vec<CodeUnit> {
        self.shards()
            .flat_map(|shard| shard.fqn_direct_children(fqn))
            .collect()
    }

    pub(crate) fn fqn_exists(&self, fqn: &str) -> bool {
        self.shards().any(|shard| shard.fqn_exists(fqn))
    }

    #[doc(hidden)]
    pub fn fqn_for_test(&self, fqn: &str) -> Vec<CodeUnit> {
        self.fqn(fqn)
    }

    #[doc(hidden)]
    pub fn file_identifier_for_test(&self, file: &ProjectFile, ident: &str) -> Vec<CodeUnit> {
        self.file_identifier(file, ident)
    }

    pub(crate) fn fqn_prefix_exists(&self, prefix: &str) -> bool {
        self.shards().any(|shard| shard.fqn_prefix_exists(prefix))
    }

    pub(crate) fn types_in_package(&self, package: &str, simple: &str) -> Vec<CodeUnit> {
        self.shards()
            .flat_map(|shard| shard.types_in_package(package, simple).iter().cloned())
            .collect()
    }

    pub(crate) fn package_types(
        &self,
    ) -> impl Iterator<Item = (&'a (String, String), &'a [CodeUnit])> + '_ {
        self.shards().flat_map(|shard| shard.package_types())
    }

    pub(crate) fn members_for_owner_name(
        &self,
        owner_fqn: &str,
        normalized_owner_fqn: &str,
        name: &str,
    ) -> Vec<&'a CodeUnit> {
        self.shards()
            .flat_map(|shard| shard.members_for_owner_name(owner_fqn, normalized_owner_fqn, name))
            .collect()
    }

    pub(crate) fn package_exists(&self, package: &str) -> bool {
        self.shards().any(|shard| shard.package_exists(package))
    }

    pub(crate) fn package_exists_in_language(&self, package: &str, language: Language) -> bool {
        self.shards()
            .any(|shard| shard.package_exists_in_language(package, language))
    }

    pub(crate) fn package_container_exists(&self, package: &str) -> bool {
        self.shards()
            .any(|shard| shard.package_container_exists(package))
    }

    pub(crate) fn package_files(&self, package: &str) -> Vec<ProjectFile> {
        self.shards()
            .flat_map(|shard| shard.package_files(package).iter().cloned())
            .collect()
    }

    pub(crate) fn package_languages(&self, package: &str) -> Vec<Language> {
        let mut languages: Vec<_> = self
            .shards()
            .flat_map(|shard| shard.package_languages(package))
            .collect();
        languages.sort();
        languages.dedup();
        languages
    }

    pub(crate) fn child_packages(&self, package: &str) -> Vec<String> {
        let mut children: Vec<_> = self
            .shards()
            .flat_map(|shard| shard.child_packages(package))
            .collect();
        children.sort();
        children.dedup();
        children
    }
}

impl BoundedDefinitionLookup for DefinitionIndexHandle<'_> {
    fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        Self::fqn(self, fqn)
    }

    fn fqn_in_language(&self, fqn: &str, language: Language) -> Vec<CodeUnit> {
        Self::fqn_in_language(self, fqn, language)
    }

    fn file_identifier(&self, file: &ProjectFile, ident: &str) -> Vec<CodeUnit> {
        Self::file_identifier(self, file, ident)
    }

    fn fqn_direct_children(&self, fqn: &str) -> Vec<CodeUnit> {
        Self::fqn_direct_children(self, fqn)
    }

    fn fqn_exists(&self, fqn: &str) -> bool {
        Self::fqn_exists(self, fqn)
    }

    fn package_exists(&self, package: &str) -> bool {
        Self::package_exists(self, package)
    }

    fn package_exists_in_language(&self, package: &str, language: Language) -> bool {
        Self::package_exists_in_language(self, package, language)
    }

    fn fqn_prefix_exists(&self, prefix: &str) -> bool {
        Self::fqn_prefix_exists(self, prefix)
    }
}

fn package_parent_name(language: Language, package: &str) -> Option<&str> {
    let separator = language_support(language).map_or(".", LanguageSupport::package_separator);
    package
        .rsplit_once(separator)
        .map(|(parent, _)| parent)
        .or(Some(""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::CodeUnitType;
    use crate::analyzer::fq_name::{FqName, SegmentKind, segment_interner};
    use std::path::Path;

    fn unit(root: &Path, file: &str, package: &str, name: &str) -> CodeUnit {
        CodeUnit::new(
            ProjectFile::new(root, file),
            CodeUnitType::Class,
            package.to_string(),
            name.to_string(),
        )
    }

    fn member_unit(
        root: &Path,
        file: &str,
        package: &str,
        owner: &str,
        owner_kind: SegmentKind,
        member: &str,
    ) -> CodeUnit {
        let interner = segment_interner();
        let mut fq = FqName::new();
        fq.push(interner.intern(package, SegmentKind::Package));
        fq.push(interner.intern(owner, owner_kind));
        fq.push(interner.intern(member, SegmentKind::Member));
        CodeUnit::from_fq(
            ProjectFile::new(root, file),
            CodeUnitType::Function,
            fq,
            1,
            None,
            false,
        )
    }

    #[test]
    fn package_catalog_keeps_exact_files_and_direct_children() {
        let root = std::env::temp_dir().join("bifrost-defindex-test");
        let units = vec![
            unit(
                &root,
                "internal/skills/discovery/a.go",
                "github.com/cli/cli/v2/internal/skills/discovery",
                "Foo",
            ),
            unit(
                &root,
                "internal/skills/discovery/b.go",
                "github.com/cli/cli/v2/internal/skills/discovery",
                "Bar",
            ),
            unit(
                &root,
                "internal/skills/registry/c.go",
                "github.com/cli/cli/v2/internal/skills/registry",
                "Baz",
            ),
            unit(
                &root,
                "internal/other/d.go",
                "github.com/cli/cli/v2/internal/other",
                "Qux",
            ),
        ];
        let index = GlobalUsageDefinitionIndex::from_declarations(&units, str::to_string, |unit| {
            unit.identifier().to_string()
        });

        let exact = index.package_files("github.com/cli/cli/v2/internal/skills/discovery");
        let exact_paths: Vec<_> = exact.iter().map(rel_path_string).collect();
        assert_eq!(
            exact_paths,
            vec![
                "internal/skills/discovery/a.go".to_string(),
                "internal/skills/discovery/b.go".to_string(),
            ]
        );

        assert_eq!(
            index.child_packages("github.com/cli/cli/v2/internal/skills"),
            vec![
                "github.com/cli/cli/v2/internal/skills/discovery".to_string(),
                "github.com/cli/cli/v2/internal/skills/registry".to_string(),
            ]
        );
        assert!(index.package_container_exists("github.com/cli/cli/v2/internal/skills"));
        assert!(!index.package_container_exists("does/not/exist"));
        assert_eq!(
            index.package_languages("github.com/cli/cli/v2/internal/skills"),
            vec![Language::Go]
        );
    }

    #[test]
    fn package_catalog_uses_language_specific_parent_separators() {
        let root = std::env::temp_dir().join("bifrost-defindex-package-parent-test");
        let units = vec![
            unit(&root, "src/A.java", "com.example.api", "A"),
            unit(&root, "src/B.java", "com.example.impl", "B"),
            unit(&root, "src/c.cpp", "base::android::ui", "C"),
        ];
        let index = GlobalUsageDefinitionIndex::from_declarations(&units, str::to_string, |unit| {
            unit.identifier().to_string()
        });

        assert_eq!(
            index.child_packages("com.example"),
            vec![
                "com.example.api".to_string(),
                "com.example.impl".to_string()
            ]
        );
        assert_eq!(
            index.child_packages("base::android"),
            vec!["base::android::ui".to_string()]
        );
    }

    #[test]
    fn resolves_types_by_package_and_normalized_fqn() {
        let root = std::env::temp_dir().join("bifrost-defindex-normalized-test");
        let units = vec![
            unit(&root, "src/Foo.scala", "example", "Foo"),
            unit(&root, "src/Helpers.scala", "example", "Helpers$"),
        ];
        let index = GlobalUsageDefinitionIndex::from_declarations(
            &units,
            |fqn| fqn.replace("$.", ".").trim_end_matches('$').to_string(),
            |unit| unit.identifier().trim_end_matches('$').to_string(),
        );

        assert_eq!(
            index.types_in_package("example", "Foo")[0].fq_name(),
            "example.Foo"
        );
        assert_eq!(
            index.types_in_package("example", "Helpers")[0].fq_name(),
            "example.Helpers$"
        );
        assert_eq!(
            index.by_normalized_fqn("example.Helpers")[0].fq_name(),
            "example.Helpers$"
        );
    }

    #[test]
    fn resolves_members_by_exact_owner_then_normalized_owner() {
        let root = std::env::temp_dir().join("bifrost-defindex-members-test");
        let units = vec![
            member_unit(
                &root,
                "src/Foo.scala",
                "example",
                "Foo",
                SegmentKind::Type,
                "run",
            ),
            member_unit(
                &root,
                "src/Helpers.scala",
                "example",
                "Helpers",
                SegmentKind::Companion,
                "run",
            ),
        ];
        let index = GlobalUsageDefinitionIndex::from_declarations(
            &units,
            |fqn| fqn.replace("$.", ".").trim_end_matches('$').to_string(),
            |unit| unit.identifier().trim_end_matches('$').to_string(),
        );

        let exact = index.members_for_owner_name("example.Foo", "example.Foo", "run");
        assert_eq!(exact.len(), 1);
        assert_eq!(exact[0].fq_name(), "example.Foo.run");

        let normalized = index.members_for_owner_name("example.Helpers", "example.Helpers", "run");
        assert_eq!(normalized.len(), 1);
        assert_eq!(normalized[0].fq_name(), "example.Helpers$.run");
    }

    #[test]
    fn streams_owned_declarations_into_index() {
        let root = std::env::temp_dir().join("bifrost-defindex-owned-test");
        let foo = unit(&root, "src/Foo.java", "example", "Foo");
        let bar = unit(&root, "src/Bar.java", "example", "Bar");

        let index = GlobalUsageDefinitionIndex::from_declarations(
            vec![foo.clone(), bar.clone()],
            str::to_string,
            |unit| unit.identifier().to_string(),
        );

        assert_eq!(index.fqn("example.Foo"), vec![foo]);
        assert_eq!(index.fqn("example.Bar"), vec![bar]);
    }
}
