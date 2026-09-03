use crate::analyzer::common::language_for_file;
use crate::analyzer::common::{IdentifierSeek, decorated_identifier_seeks};
use crate::analyzer::languages::{language_support, package_fq_name};
use crate::analyzer::store::StoreError;
use crate::analyzer::{
    BoundedDefinitionLookup, CodeUnit, DefinitionLanguageScope, IAnalyzer, Language, ProjectFile,
    RelationalBatchOutcome, RelationalDefinitionQuery, RelationalDefinitionRequest,
    RelationalDefinitionValue, sort_units,
};
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_core::analyzer::{
    PackageRelationKind, PackageRelationValue, RelationalName,
    fq_name::{FqName, SegmentKind, segment_interner},
    symbol_path::parse_symbol_path_fq,
};
use std::sync::{Arc, Mutex, OnceLock};

type MemberLookupKey = (Language, String, String, String);
type StructuredMemberLookupKey = (Language, FqName, String);

pub(crate) trait ForwardQueryProvider {
    fn normalize_rendered_name(&self, fqn: &str) -> String;
    /// Navigation candidates for a rendered name. Language adapters may admit
    /// source-spelling aliases beyond exact persisted identity.
    fn forward_definition_fqn(&self, fqn: &str) -> Vec<CodeUnit>;
    fn forward_file_identifier(&self, file: &ProjectFile, identifier: &str) -> Vec<CodeUnit>;
    fn forward_direct_children(&self, owner: &CodeUnit) -> Vec<CodeUnit>;
    fn forward_relational_name(&self, unit: &CodeUnit) -> RelationalName;
    fn forward_definition_candidate_short_names(&self, rendered: &str) -> Vec<String>;
    fn forward_package_exists(&self, package: &str) -> bool;
    fn forward_fqn_prefix_exists(&self, prefix: &str) -> bool;
}

macro_rules! impl_forward_query_provider {
    ($analyzer:ty) => {
        impl crate::analyzer::ForwardQueryProvider for $analyzer {
            fn normalize_rendered_name(&self, fqn: &str) -> String {
                self.inner.normalize_rendered_name(fqn)
            }

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

            fn forward_relational_name(
                &self,
                unit: &crate::analyzer::CodeUnit,
            ) -> brokk_bifrost_core::analyzer::RelationalName {
                self.inner.relational_name_for_unit(unit)
            }

            fn forward_definition_candidate_short_names(&self, rendered: &str) -> Vec<String> {
                self.inner.definition_candidate_short_names(rendered)
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

/// The memoized definition answers one request's lookups share.
///
/// A usage scan builds an [`AnalyzerDefinitionLookup`] per candidate file --
/// `with_usage_definitions` and the `could_import_file` and
/// `declarations_named` paths each construct one -- so memos owned by the
/// lookup meant every candidate repeated the same name, identifier and package
/// store batches (#2883). The analyzer hands out one of these per open request
/// scope, so every lookup built during that request answers from one set. With
/// no scope open a lookup owns its own, which is exactly the old behaviour.
///
/// Every key names the [`Language`] its answer was resolved in, and every
/// answer comes from that language's analyzer alone, so a lookup built over a
/// language analyzer and one built over the multi-analyzer that owns it can
/// share a memo. It is deliberately language-agnostic: #2783 added a Java-only
/// usage-evidence cache, and this path has to be fast for every language rather
/// than grow a second special case.
#[derive(Debug, Default)]
pub struct DefinitionLookupMemo {
    fqn_cache: Mutex<HashMap<(Language, String), Vec<CodeUnit>>>,
    normalized_fqn_cache: Mutex<HashMap<(Language, String), Vec<CodeUnit>>>,
    identifier_cache: Mutex<HashMap<(Language, String), Vec<CodeUnit>>>,
    file_identifier_cache: Mutex<HashMap<(ProjectFile, String), Vec<CodeUnit>>>,
    children_cache: Mutex<HashMap<(Language, String), Vec<CodeUnit>>>,
    members_cache: Mutex<HashMap<MemberLookupKey, Vec<CodeUnit>>>,
    structured_members_cache: Mutex<HashMap<StructuredMemberLookupKey, Vec<CodeUnit>>>,
    package_cache: Mutex<HashMap<(Language, String), bool>>,
    prefix_cache: Mutex<HashMap<(Language, String), bool>>,
}

/// A forward-query view over an analyzer.  Keeping this separate from the
/// legacy index makes accidental whole-workspace fallback impossible at call
/// sites that accept only `BoundedDefinitionLookup`.
pub struct AnalyzerDefinitionLookup<'a> {
    analyzer: &'a dyn IAnalyzer,
    language: Mutex<Language>,
    /// Resolved per lookup rather than in the shared memo: the languages a
    /// multi-analyzer reports are not the languages one of its delegates
    /// reports, and both kinds of analyzer can hand out the same memo.
    workspace_languages: OnceLock<Vec<Language>>,
    memo: Arc<DefinitionLookupMemo>,
}

impl<'a> AnalyzerDefinitionLookup<'a> {
    pub fn new(analyzer: &'a dyn IAnalyzer, language: Language) -> Self {
        Self {
            analyzer,
            language: Mutex::new(language),
            workspace_languages: OnceLock::new(),
            memo: analyzer.definition_lookup_memo().unwrap_or_default(),
        }
    }

    pub(crate) fn set_language(&self, language: Language) {
        *self
            .language
            .lock()
            .expect("definition language mutex poisoned") = language;
    }

    fn query_languages(&self) -> Vec<Language> {
        let language = *self
            .language
            .lock()
            .expect("definition language mutex poisoned");
        if language == Language::None {
            self.workspace_languages().to_vec()
        } else {
            vec![language]
        }
    }

    pub fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        <Self as BoundedDefinitionLookup>::fqn(self, fqn)
    }

    pub fn file_identifier(&self, file: &ProjectFile, identifier: &str) -> Vec<CodeUnit> {
        <Self as BoundedDefinitionLookup>::file_identifier(self, file, identifier)
    }

    fn language_analyzer(&self, language: Language) -> Option<&dyn ForwardQueryProvider> {
        analyzer_for_language(self.analyzer, language)
    }

    fn relational_name_for_unit(&self, language: Language, unit: &CodeUnit) -> RelationalName {
        self.language_analyzer(language)
            .map(|provider| provider.forward_relational_name(unit))
            .unwrap_or_else(|| RelationalName::stable(unit.fq().clone()))
    }

    fn rendered_identifier_candidates(&self, language: Language, rendered: &str) -> Vec<String> {
        let mut candidates = self
            .language_analyzer(language)
            .map(|provider| provider.forward_definition_candidate_short_names(rendered))
            .unwrap_or_default();
        if candidates.is_empty()
            && let Some(identifier) = Self::rendered_terminal(language, rendered)
        {
            candidates.push(identifier);
        }
        candidates.sort();
        candidates.dedup();
        candidates
    }

    /// The languages this workspace actually indexes, in a stable order.
    /// Resolved once per batch: `CodeUnitIndex::languages` rebuilds a set per call.
    fn workspace_languages(&self) -> &[Language] {
        self.workspace_languages
            .get_or_init(|| self.analyzer.languages().into_iter().collect())
    }

    fn query_values(
        &self,
        language: Language,
        questions: Vec<(RelationalName, RelationalDefinitionQuery)>,
    ) -> Vec<RelationalDefinitionValue> {
        if questions.is_empty() {
            return Vec::new();
        }
        let requests = questions
            .into_iter()
            .enumerate()
            .map(|(ordinal, (name, query))| RelationalDefinitionRequest {
                ordinal,
                language_scope: DefinitionLanguageScope::Language(language),
                name,
                query,
            })
            .collect::<Vec<_>>();
        match self
            .analyzer
            .relational_definition_batch_for_active_query(&requests)
        {
            RelationalBatchOutcome::Complete(mut results) => {
                results.sort_by_key(|result| result.ordinal);
                assert_eq!(results.len(), requests.len());
                results.into_iter().map(|result| result.value).collect()
            }
            RelationalBatchOutcome::Cancelled => Vec::new(),
            RelationalBatchOutcome::Failed(error) => {
                self.analyzer
                    .record_query_failure(StoreError::new(error.message()));
                Vec::new()
            }
        }
    }

    fn identifier_name(identifier: &str) -> Option<RelationalName> {
        if identifier.is_empty() {
            return None;
        }
        let mut name = FqName::new();
        name.push(segment_interner().intern(identifier, SegmentKind::Unknown));
        Some(RelationalName::stable(name))
    }

    fn rendered_name(language: Language, rendered: &str) -> Option<RelationalName> {
        let name = parse_symbol_path_fq(language, rendered, segment_interner());
        (!name.is_empty()).then(|| RelationalName::stable(name))
    }

    fn rendered_terminal(language: Language, rendered: &str) -> Option<String> {
        let name = parse_symbol_path_fq(language, rendered, segment_interner());
        name.last()
            .map(|segment| segment_interner().resolve(segment).0.to_string())
    }

    fn identifier_candidates_for_language(
        &self,
        language: Language,
        identifier: &str,
        file: Option<&ProjectFile>,
    ) -> Vec<CodeUnit> {
        self.identifier_candidates_for_spellings(language, &[identifier.to_string()], file)
    }

    /// Every declaration this language indexes under `identifier`, anywhere in
    /// the workspace, memoized per `(language, identifier)`.
    ///
    /// Both workspace-wide callers -- `identifier` and the file-set filter in
    /// `file_identifier_in_files` -- share the one cache entry, so a bare name
    /// asked about through either shape costs one store read per language.
    fn workspace_identifier_candidates(
        &self,
        language: Language,
        identifier: &str,
    ) -> Vec<CodeUnit> {
        let key = (language, identifier.to_string());
        if let Some(cached) = self
            .memo
            .identifier_cache
            .lock()
            .expect("definition identifier cache poisoned")
            .get(&key)
        {
            return cached.clone();
        }
        let mut matches = self.identifier_candidates_for_language(language, identifier, None);
        sort_units(&mut matches);
        matches.dedup();
        self.memo
            .identifier_cache
            .lock()
            .expect("definition identifier cache poisoned")
            .insert(key, matches.clone());
        matches
    }

    /// The relational questions one set of identifier spellings asks: the bare
    /// identifier plus each of the language's decorated seeks.
    fn identifier_queries(
        language: Language,
        identifiers: &[String],
        file: Option<&ProjectFile>,
    ) -> Vec<(RelationalName, RelationalDefinitionQuery)> {
        let mut queries = Vec::new();
        for identifier in identifiers {
            if let Some(name) = Self::identifier_name(identifier) {
                queries.push((
                    name,
                    RelationalDefinitionQuery::Identifier {
                        file: file.cloned(),
                    },
                ));
            }
            for seek in decorated_identifier_seeks(language, identifier) {
                match seek {
                    IdentifierSeek::Exact(spelling) => {
                        if let Some(name) = Self::identifier_name(&spelling) {
                            queries.push((
                                name,
                                RelationalDefinitionQuery::Identifier {
                                    file: file.cloned(),
                                },
                            ));
                        }
                    }
                    IdentifierSeek::Prefix(prefix) => {
                        if let Some(name) = Self::identifier_name(&prefix) {
                            queries.push((
                                name,
                                RelationalDefinitionQuery::IdentifierPrefix {
                                    file: file.cloned(),
                                },
                            ));
                        }
                    }
                }
            }
        }
        queries
    }

    /// Collapse the answers to [`Self::identifier_queries`] into the canonical
    /// candidate set: only units one of the spellings actually addresses,
    /// sorted and deduplicated.
    fn identifier_units_from_values(
        identifiers: &[String],
        values: Vec<RelationalDefinitionValue>,
    ) -> Vec<CodeUnit> {
        let mut units = values
            .into_iter()
            .flat_map(|value| match value {
                RelationalDefinitionValue::Definitions(units) => units,
                _ => panic!("an identifier query returned the wrong result shape"),
            })
            .filter(|unit| {
                identifiers.iter().any(|identifier| {
                    crate::analyzer::common::identifier_addresses_target(unit, identifier)
                })
            })
            .collect::<Vec<_>>();
        sort_units(&mut units);
        units.dedup();
        units
    }

    fn identifier_candidates_for_spellings(
        &self,
        language: Language,
        identifiers: &[String],
        file: Option<&ProjectFile>,
    ) -> Vec<CodeUnit> {
        let queries = Self::identifier_queries(language, identifiers, file);
        let values = self.query_values(language, queries);
        Self::identifier_units_from_values(identifiers, values)
    }

    fn exact_for_language(&self, rendered: &str, language: Language) -> Vec<CodeUnit> {
        let Some(name) = Self::rendered_name(language, rendered) else {
            return Vec::new();
        };
        let mut units = match self
            .query_values(language, vec![(name, RelationalDefinitionQuery::ExactName)])
            .pop()
        {
            Some(RelationalDefinitionValue::Definitions(units)) => units,
            Some(_) => panic!("an exact-name query returned the wrong result shape"),
            None => Vec::new(),
        };
        // A rendered path-derived identity may address a content-stable tail
        // that hydrates under a different live mount. Only an authoritative
        // hydrated-name match makes the exact result complete. Otherwise
        // consult the identifier view for mounted-name and source-spelling
        // compatibility (for example a C++ name rendered with both `::` and
        // `.`).
        units.retain(|unit| unit.fq_name() == rendered);
        if units.is_empty() {
            let identifiers = self.rendered_identifier_candidates(language, rendered);
            units.extend(self.identifier_candidates_for_spellings(language, &identifiers, None));
        }
        units.retain(|unit| unit.fq_name() == rendered);
        sort_units(&mut units);
        units.dedup();
        units
    }

    fn normalized_for_language(&self, normalized: &str, language: Language) -> Vec<CodeUnit> {
        let Some(name) = Self::rendered_name(language, normalized) else {
            return Vec::new();
        };
        let mut units = match self
            .query_values(
                language,
                vec![(name, RelationalDefinitionQuery::NormalizedName)],
            )
            .pop()
        {
            Some(RelationalDefinitionValue::Definitions(units)) => units,
            Some(_) => panic!("a normalized-name query returned the wrong result shape"),
            None => Vec::new(),
        };
        let identifiers = self.rendered_identifier_candidates(language, normalized);
        units.extend(self.identifier_candidates_for_spellings(language, &identifiers, None));
        let Some(provider) = self.language_analyzer(language) else {
            return Vec::new();
        };
        units.retain(|unit| provider.normalize_rendered_name(&unit.fq_name()) == normalized);
        sort_units(&mut units);
        units.dedup();
        units
    }

    fn fqn_for_language(&self, fqn: &str, language: Language) -> Vec<CodeUnit> {
        let key = (language, fqn.to_string());
        if let Some(cached) = self
            .memo
            .fqn_cache
            .lock()
            .expect("definition fqn cache poisoned")
            .get(&key)
        {
            return cached.clone();
        }
        let matches = self.exact_for_language(fqn, language);
        self.memo
            .fqn_cache
            .lock()
            .expect("definition fqn cache poisoned")
            .insert(key, matches.clone());
        matches
    }

    /// Resolve many rendered names into the shared fqn memo with two batched
    /// relational reads per language instead of one point batch per name.
    ///
    /// The rounds are the same two questions [`Self::exact_for_language`]
    /// asks per name -- an exact persisted-identity seek, then the identifier
    /// compatibility view for the names the exact round missed -- with
    /// identical per-name filtering, so a memoized answer cannot differ from
    /// what the point path would compute. A cancelled or failed batch
    /// memoizes nothing: every name stays unmemoized and the point path
    /// retries it with unchanged results.
    pub(crate) fn prefetch_fqn_in_language(&self, language: Language, fqns: &[String]) {
            let missing: Vec<String> = {
                let cache = self
                    .memo
                    .fqn_cache
                    .lock()
                    .expect("definition fqn cache poisoned");
                let mut seen = HashSet::default();
                fqns.iter()
                    .filter(|fqn| seen.insert(fqn.as_str()))
                    .filter(|fqn| !cache.contains_key(&(language, (*fqn).clone())))
                    .cloned()
                    .collect()
            };
            if missing.is_empty() {
                continue;
            }

            let mut exact_owners = Vec::new();
            let mut exact_questions = Vec::new();
            for (index, fqn) in missing.iter().enumerate() {
                if let Some(name) = Self::rendered_name(language, fqn) {
                    exact_owners.push(index);
                    exact_questions.push((name, RelationalDefinitionQuery::ExactName));
                }
            }
            // A name the language cannot even render as a path resolves to
            // nothing without a fallback, exactly as the point path answers.
            let mut parseable = vec![false; missing.len()];
            let mut units_by_name: Vec<Vec<CodeUnit>> = vec![Vec::new(); missing.len()];
            if !exact_questions.is_empty() {
                let expected = exact_questions.len();
                let values = self.query_values(language, exact_questions);
                if values.len() != expected {
                    return;
                }
                for (owner, value) in exact_owners.into_iter().zip(values) {
                    parseable[owner] = true;
                    match value {
                        RelationalDefinitionValue::Definitions(units) => {
                            units_by_name[owner] = units;
                        }
                        _ => panic!("an exact-name query returned the wrong result shape"),
                    }
                }
            }

            let mut fallback: Vec<(usize, std::ops::Range<usize>, Vec<String>)> = Vec::new();
            let mut fallback_questions = Vec::new();
            for (index, fqn) in missing.iter().enumerate() {
                units_by_name[index].retain(|unit| unit.fq_name() == *fqn);
                if !parseable[index] || !units_by_name[index].is_empty() {
                    continue;
                }
                let identifiers = self.rendered_identifier_candidates(language, fqn);
                let start = fallback_questions.len();
                fallback_questions.extend(Self::identifier_queries(language, &identifiers, None));
                fallback.push((index, start..fallback_questions.len(), identifiers));
            }
            if !fallback_questions.is_empty() {
                let expected = fallback_questions.len();
                let values = self.query_values(language, fallback_questions);
                if values.len() != expected {
                    return;
                }
                let mut values = values.into_iter().map(Some).collect::<Vec<_>>();
                for (index, range, identifiers) in fallback {
                    let name_values = values[range]
                        .iter_mut()
                        .map(|value| value.take().expect("each fallback value is consumed once"))
                        .collect::<Vec<_>>();
                    units_by_name[index] =
                        Self::identifier_units_from_values(&identifiers, name_values);
                    units_by_name[index].retain(|unit| unit.fq_name() == missing[index]);
                }
            }

            let mut cache = self
                .memo
                .fqn_cache
                .lock()
                .expect("definition fqn cache poisoned");
            for (fqn, mut units) in missing.into_iter().zip(units_by_name) {
                sort_units(&mut units);
                units.dedup();
                cache.insert((language, fqn), units);
            }
    }

    pub(crate) fn prefetch_fqns(&self, fqns: &[String]) {
        for language in self.query_languages() {
            self.prefetch_fqn_in_language(language, fqns);
        }
    }
}

fn analyzer_for_language(
    analyzer: &dyn IAnalyzer,
    language: Language,
) -> Option<&dyn ForwardQueryProvider> {
    language_support(language).and_then(|support| support.forward_query_provider(analyzer))
}

impl BoundedDefinitionLookup for AnalyzerDefinitionLookup<'_> {
    fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        let mut units = self
            .query_languages()
            .into_iter()
            .flat_map(|language| self.fqn_for_language(fqn, language))
            .collect::<Vec<_>>();
        sort_units(&mut units);
        units.dedup();
        units
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

    fn by_normalized_fqn(&self, normalized: &str) -> Vec<CodeUnit> {
        let mut units = Vec::new();
        for language in self.query_languages() {
            let key = (language, normalized.to_string());
            if let Some(cached) = self
                .memo
                .normalized_fqn_cache
                .lock()
                .expect("normalized definition cache poisoned")
                .get(&key)
            {
                units.extend(cached.clone());
                continue;
            }
            let mut matches = self.normalized_for_language(normalized, language);
            sort_units(&mut matches);
            matches.dedup();
            self.memo
                .normalized_fqn_cache
                .lock()
                .expect("normalized definition cache poisoned")
                .insert(key, matches.clone());
            units.extend(matches);
        }
        sort_units(&mut units);
        units.dedup();
        units
    }

    fn types_in_package(&self, package: &str, simple: &str) -> Vec<CodeUnit> {
        let mut units = Vec::new();
        for language in self.query_languages() {
            let values = self.query_values(
                language,
                vec![(
                    RelationalName::stable(package_fq_name(language, package)),
                    RelationalDefinitionQuery::PackageTypes {
                        simple_name: simple.to_string(),
                    },
                )],
            );
            units.extend(values.into_iter().flat_map(|value| match value {
                RelationalDefinitionValue::Definitions(units) => units,
                _ => panic!("a package-types query returned the wrong result shape"),
            }));
        }
        sort_units(&mut units);
        units.dedup();
        units
    }

    fn identifier(&self, ident: &str) -> Vec<CodeUnit> {
        let mut units = Vec::new();
        for language in self.query_languages() {
            units.extend(self.workspace_identifier_candidates(language, ident));
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
        if let Some(cached) = self
            .memo
            .file_identifier_cache
            .lock()
            .expect("file identifier cache poisoned")
            .get(&key)
        {
            return cached.clone();
        }
        let matches =
            self.identifier_candidates_for_language(language_for_file(file), ident, Some(file));
        self.memo
            .file_identifier_cache
            .lock()
            .expect("file identifier cache poisoned")
            .insert(key, matches.clone());
        matches
    }

    /// The trait default asks `file_identifier` once per file, so a caller
    /// that hands over a whole visibility closure pays one store read per
    /// visible file. Ruby's Zeitwerk closure is effectively the workspace, so
    /// one bare identifier cost tens of seconds on a large repository (#2743).
    ///
    /// The persisted identifier view answers the same question workspace-wide
    /// from the same `(lang, identifier)` index: `Identifier { file: Some(_) }`
    /// is `Identifier { file: None }` plus a `names.rel_path` equality, and
    /// the decorated seeks and the `identifier_addresses_target` filter depend
    /// only on the language and the spelling. So the union of the per-file
    /// answers is exactly the workspace answer restricted to those paths, and
    /// grouping by `language_for_file` reproduces the language scope each
    /// per-file query would have used.
    ///
    /// One file keeps the per-file path: the `rel_path`-scoped read is the
    /// cheaper one there, and it is what the JS/TS import resolver caches.
    fn file_identifier_in_files(&self, files: &[ProjectFile], ident: &str) -> Vec<CodeUnit> {
        if let [file] = files {
            return self.file_identifier(file, ident);
        }
        let wanted = files.iter().collect::<HashSet<&ProjectFile>>();
        let mut languages = files.iter().map(language_for_file).collect::<Vec<_>>();
        languages.sort();
        languages.dedup();
        let mut units = Vec::new();
        for language in languages {
            units.extend(
                self.workspace_identifier_candidates(language, ident)
                    .into_iter()
                    .filter(|unit| wanted.contains(unit.source())),
            );
        }
        sort_units(&mut units);
        units.dedup();
        units
    }

    fn fqn_direct_children(&self, fqn: &str) -> Vec<CodeUnit> {
        let mut all_children = Vec::new();
        for language in self.query_languages() {
            let key = (language, fqn.to_string());
            if let Some(cached) = self
                .memo
                .children_cache
                .lock()
                .expect("definition children cache poisoned")
                .get(&key)
            {
                all_children.extend(cached.clone());
                continue;
            }
            let mut owner_names = self
                .fqn_for_language(fqn, language)
                .into_iter()
                .map(|owner| self.relational_name_for_unit(language, &owner))
                .collect::<Vec<_>>();
            if self.package_exists_in_language(fqn, language) {
                owner_names.push(RelationalName::stable(package_fq_name(language, fqn)));
            }
            owner_names.sort_by_cached_key(|name| name.full_name().display(segment_interner()));
            owner_names.dedup();
            let mut children = self
                .query_values(
                    language,
                    owner_names
                        .into_iter()
                        .map(|owner| (owner, RelationalDefinitionQuery::StructuralChildren))
                        .collect(),
                )
                .into_iter()
                .flat_map(|value| match value {
                    RelationalDefinitionValue::Definitions(units) => units,
                    _ => panic!("a structural-children query returned the wrong result shape"),
                })
                .collect::<Vec<_>>();
            sort_units(&mut children);
            children.dedup();
            self.memo
                .children_cache
                .lock()
                .expect("definition children cache poisoned")
                .insert(key, children.clone());
            all_children.extend(children);
        }
        sort_units(&mut all_children);
        all_children.dedup();
        all_children
    }

    fn fqn_exists(&self, fqn: &str) -> bool {
        !self.fqn(fqn).is_empty()
    }

    fn members_for_owner_name(
        &self,
        owner_fqn: &str,
        normalized_owner_fqn: &str,
        name: &str,
    ) -> Vec<CodeUnit> {
        let mut all_members = Vec::new();
        for language in self.query_languages() {
            let key = (
                language,
                owner_fqn.to_string(),
                normalized_owner_fqn.to_string(),
                name.to_string(),
            );
            if let Some(cached) = self
                .memo
                .members_cache
                .lock()
                .expect("definition members cache poisoned")
                .get(&key)
            {
                all_members.extend(cached.clone());
                continue;
            }
            let mut owners = self.fqn_for_language(owner_fqn, language);
            owners.extend(self.normalized_for_language(normalized_owner_fqn, language));
            sort_units(&mut owners);
            owners.dedup();
            let mut owner_names = owners
                .into_iter()
                .map(|owner| self.relational_name_for_unit(language, &owner))
                .collect::<Vec<_>>();
            if self.package_exists_in_language(owner_fqn, language) {
                owner_names.push(RelationalName::stable(package_fq_name(language, owner_fqn)));
            }
            owner_names.sort_by_cached_key(|name| name.full_name().display(segment_interner()));
            owner_names.dedup();
            let query = RelationalDefinitionQuery::StructuralMembers {
                identifier: name.to_string(),
            };
            let mut members = self
                .query_values(
                    language,
                    owner_names
                        .into_iter()
                        .map(|owner| (owner, query.clone()))
                        .collect(),
                )
                .into_iter()
                .flat_map(|value| match value {
                    RelationalDefinitionValue::Definitions(units) => units,
                    _ => panic!("a structural-member query returned the wrong result shape"),
                })
                .collect::<Vec<_>>();
            sort_units(&mut members);
            members.dedup();
            self.memo
                .members_cache
                .lock()
                .expect("definition members cache poisoned")
                .insert(key, members.clone());
            all_members.extend(members);
        }
        sort_units(&mut all_members);
        all_members.dedup();
        all_members
    }

    fn members_for_owner(&self, owner: &CodeUnit, name: &str) -> Vec<CodeUnit> {
        let language = language_for_file(owner.source());
        let key = (language, owner.fq().clone(), name.to_string());
        if let Some(cached) = self
            .memo
            .structured_members_cache
            .lock()
            .expect("structured definition members cache poisoned")
            .get(&key)
        {
            return cached.clone();
        }
        let relational_owner = self.relational_name_for_unit(language, owner);
        let values = self.query_values(
            language,
            vec![(
                relational_owner,
                RelationalDefinitionQuery::StructuralMembers {
                    identifier: name.to_string(),
                },
            )],
        );
        let mut members = values
            .into_iter()
            .flat_map(|value| match value {
                RelationalDefinitionValue::Definitions(units) => units,
                _ => panic!("a structured-member query returned the wrong result shape"),
            })
            .collect::<Vec<_>>();
        sort_units(&mut members);
        members.dedup();
        self.memo
            .structured_members_cache
            .lock()
            .expect("structured definition members cache poisoned")
            .insert(key, members.clone());
        members
    }

    fn package_exists(&self, package: &str) -> bool {
        self.query_languages()
            .into_iter()
            .any(|language| self.package_exists_in_language(package, language))
    }

    fn package_exists_in_language(&self, package: &str, language: Language) -> bool {
        let key = (language, package.to_string());
        if let Some(cached) = self
            .memo
            .package_cache
            .lock()
            .expect("package cache poisoned")
            .get(&key)
        {
            return *cached;
        }
        let request = RelationalDefinitionRequest {
            ordinal: 0,
            language_scope: DefinitionLanguageScope::Language(language),
            name: RelationalName::stable(package_fq_name(language, package)),
            query: RelationalDefinitionQuery::PackageRelation(PackageRelationKind::Exists),
        };
        let exists = match self
            .analyzer
            .relational_definition_batch_for_active_query(&[request])
        {
            RelationalBatchOutcome::Complete(mut results) => {
                assert_eq!(results.len(), 1, "package point query returns one result");
                matches!(
                    results.remove(0).value,
                    RelationalDefinitionValue::PackageRelation(PackageRelationValue::Exists(true))
                )
            }
            RelationalBatchOutcome::Cancelled => false,
            RelationalBatchOutcome::Failed(error) => {
                self.analyzer
                    .record_query_failure(StoreError::new(error.message()));
                false
            }
        };
        self.memo
            .package_cache
            .lock()
            .expect("package cache poisoned")
            .insert(key, exists);
        exists
    }

    fn fqn_prefix_exists(&self, prefix: &str) -> bool {
        for language in self.query_languages() {
            let key = (language, prefix.to_string());
            if let Some(cached) = self
                .memo
                .prefix_cache
                .lock()
                .expect("fqn prefix cache poisoned")
                .get(&key)
            {
                if *cached {
                    return true;
                }
                continue;
            }
            let package_exists = self.package_exists_in_language(prefix, language);
            let has_descendants = if package_exists {
                false
            } else {
                let mut descendants = self.query_values(
                    language,
                    vec![(
                        RelationalName::stable(package_fq_name(language, prefix)),
                        RelationalDefinitionQuery::PackageRelation(
                            PackageRelationKind::Descendants,
                        ),
                    )],
                );
                matches!(
                    descendants.pop(),
                    Some(RelationalDefinitionValue::PackageRelation(
                        PackageRelationValue::Packages(packages)
                    )) if !packages.is_empty()
                )
            };
            let exists = package_exists
                || has_descendants
                || !self.fqn_for_language(prefix, language).is_empty();
            self.memo
                .prefix_cache
                .lock()
                .expect("fqn prefix cache poisoned")
                .insert(key, exists);
            if exists {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod definition_lookup_tests {
    use super::*;
    use crate::analyzer::{RubyAnalyzer, TestProject};
    use std::path::PathBuf;

    /// Four Ruby files declaring one bare top-level method: two inside the
    /// file set a test passes, one outside it, and one file that declares an
    /// unrelated name only.
    struct BareIdentifierProject {
        _temp: tempfile::TempDir,
        root: PathBuf,
        analyzer: RubyAnalyzer,
    }

    impl BareIdentifierProject {
        fn new() -> Self {
            let temp = tempfile::tempdir().expect("create temp dir");
            let root = temp.path().canonicalize().expect("canonicalize temp dir");
            for (rel, contents) in [
                ("lib/alpha.rb", "def shared_helper\n  1\nend\n"),
                ("lib/beta.rb", "def shared_helper\n  2\nend\n"),
                ("lib/gamma.rb", "def other_helper\n  3\nend\n"),
                ("lib/delta.rb", "def shared_helper\n  4\nend\n"),
            ] {
                ProjectFile::new(root.clone(), rel)
                    .write(contents)
                    .unwrap_or_else(|err| panic!("write {rel}: {err}"));
            }
            let analyzer =
                RubyAnalyzer::from_project(TestProject::new(root.clone(), Language::Ruby));
            Self {
                _temp: temp,
                root,
                analyzer,
            }
        }

        fn file(&self, rel: &str) -> ProjectFile {
            ProjectFile::new(self.root.clone(), rel)
        }

        fn lookup(&self) -> AnalyzerDefinitionLookup<'_> {
            AnalyzerDefinitionLookup::new(&self.analyzer, Language::None)
        }

        /// What the `BoundedDefinitionLookup::file_identifier_in_files` trait
        /// default computes: one file-scoped store read per file, published in
        /// the canonical order.
        fn per_file_union(&self, files: &[ProjectFile], ident: &str) -> Vec<CodeUnit> {
            let lookup = self.lookup();
            let mut units = files
                .iter()
                .flat_map(|file| lookup.file_identifier(file, ident))
                .collect::<Vec<_>>();
            sort_units(&mut units);
            units.dedup();
            units
        }

        fn sources(units: &[CodeUnit]) -> Vec<String> {
            units
                .iter()
                .map(|unit| crate::path_utils::rel_path_string(unit.source()))
                .collect()
        }
    }

    #[test]
    fn file_set_identifier_lookup_matches_the_per_file_union() {
        let project = BareIdentifierProject::new();
        let all_three = [
            project.file("lib/alpha.rb"),
            project.file("lib/beta.rb"),
            project.file("lib/gamma.rb"),
        ];

        let overridden = project
            .lookup()
            .file_identifier_in_files(&all_three, "shared_helper");
        assert_eq!(
            overridden,
            project.per_file_union(&all_three, "shared_helper"),
            "the workspace-wide filter must publish exactly the trait default's set and order"
        );
        assert_eq!(
            BareIdentifierProject::sources(&overridden),
            vec!["lib/alpha.rb".to_string(), "lib/beta.rb".to_string()],
            "lib/delta.rb declares the same identifier but is outside the file set"
        );

        let subset = [project.file("lib/alpha.rb"), project.file("lib/gamma.rb")];
        let overridden_subset = project
            .lookup()
            .file_identifier_in_files(&subset, "shared_helper");
        assert_eq!(
            overridden_subset,
            project.per_file_union(&subset, "shared_helper"),
            "a subset must agree with the trait default over that same subset"
        );
        assert_eq!(
            BareIdentifierProject::sources(&overridden_subset),
            vec!["lib/alpha.rb".to_string()],
            "dropping lib/beta.rb from the set must drop its declaration"
        );
    }

    /// Cost pin for #2883: every lookup built under one request scope answers
    /// from one memo, so the second lookup to ask for a name it already holds
    /// costs no store read. Candidate discovery builds one lookup per candidate
    /// file, which is why this is what the scan actually pays.
    #[test]
    fn lookups_under_one_query_scope_share_one_definition_memo() {
        let project = BareIdentifierProject::new();
        let checkouts = || {
            project
                .analyzer
                .relational_batch_reader_checkouts_for_test()
        };
        let _scope = crate::analyzer::AnalyzerQueryScope::new(&project.analyzer);

        let before = checkouts();
        let first = project.lookup().identifier("shared_helper");
        let first_cost = checkouts() - before;
        let second = project.lookup().identifier("shared_helper");
        let second_cost = checkouts() - before - first_cost;

        assert!(
            first_cost > 0,
            "the first lookup must actually ask the store"
        );
        assert_eq!(
            second_cost, 0,
            "a second lookup under the same scope must answer from the shared memo"
        );
        assert_eq!(
            first, second,
            "the shared memo must publish the answer the store read produced"
        );
    }

    /// The counterpart: with no request scope open there is no shared memo, so
    /// each lookup owns its own and pays its own store read. Ownership of the
    /// memo is what changes, not what a lookup answers.
    #[test]
    fn lookups_outside_a_query_scope_keep_their_own_definition_memo() {
        let project = BareIdentifierProject::new();
        let checkouts = || {
            project
                .analyzer
                .relational_batch_reader_checkouts_for_test()
        };

        let before = checkouts();
        let first = project.lookup().identifier("shared_helper");
        let first_cost = checkouts() - before;
        let second = project.lookup().identifier("shared_helper");
        let second_cost = checkouts() - before - first_cost;

        assert_eq!(
            (first_cost, second_cost),
            (1, 1),
            "without a scope each lookup asks the store for itself"
        );
        assert_eq!(first, second);
    }

    /// Parity and cost pin for the batched name prefetch: after
    /// `prefetch_fqns`, a point `fqn` ask costs no store read and answers
    /// exactly what the unprefetched point path computed -- including the
    /// name that resolves to nothing.
    #[test]
    fn prefetched_fqns_answer_from_the_shared_memo_without_store_reads() {
        let project = BareIdentifierProject::new();
        let names = vec!["shared_helper".to_string(), "no_such_name".to_string()];
        let unprefetched: Vec<_> = {
            let _scope = crate::analyzer::AnalyzerQueryScope::new(&project.analyzer);
            names
                .iter()
                .map(|name| project.lookup().fqn(name))
                .collect()
        };

        let _scope = crate::analyzer::AnalyzerQueryScope::new(&project.analyzer);
        let checkouts = || {
            project
                .analyzer
                .relational_batch_reader_checkouts_for_test()
        };
        project.lookup().prefetch_fqns(&names);
        let before = checkouts();
        let prefetched: Vec<_> = names
            .iter()
            .map(|name| project.lookup().fqn(name))
            .collect();
        assert_eq!(
            checkouts() - before,
            0,
            "a prefetched name must answer from the shared memo"
        );
        assert_eq!(
            prefetched, unprefetched,
            "a memoized answer must equal the point path's"
        );
    }

    /// Cost pin for #2743: what one bare identifier costs in store reads must
    /// not grow with the size of the file set.
    ///
    /// The counter is the relational batch reader checkout, one per store
    /// round trip. `EXPLAIN QUERY PLAN` is this repository's preferred pin for
    /// the shape of one query; it cannot express how many queries a caller
    /// issues, which is the whole defect here.
    #[test]
    fn file_set_identifier_lookup_cost_is_independent_of_the_file_count() {
        let project = BareIdentifierProject::new();
        let all_four = [
            project.file("lib/alpha.rb"),
            project.file("lib/beta.rb"),
            project.file("lib/gamma.rb"),
            project.file("lib/delta.rb"),
        ];

        let measure = |files: &[ProjectFile]| {
            let before = project
                .analyzer
                .relational_batch_reader_checkouts_for_test();
            project
                .lookup()
                .file_identifier_in_files(files, "shared_helper");
            project
                .analyzer
                .relational_batch_reader_checkouts_for_test()
                - before
        };

        let two_files = measure(&all_four[..2]);
        let four_files = measure(&all_four);
        assert_eq!(
            (two_files, four_files),
            (1, 1),
            "the override asks the store once for this single-language file set, whatever its size"
        );

        let before = project
            .analyzer
            .relational_batch_reader_checkouts_for_test();
        project.per_file_union(&all_four, "shared_helper");
        let trait_default = project
            .analyzer
            .relational_batch_reader_checkouts_for_test()
            - before;
        assert_eq!(
            trait_default,
            four_files * all_four.len(),
            "the trait default pays one store read per file, which is what the override removes"
        );
    }
}
