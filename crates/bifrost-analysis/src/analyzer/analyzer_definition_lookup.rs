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
use std::sync::atomic::{AtomicBool, Ordering};
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
    fn forward_definition_sources_may_exist(&self) -> bool;
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

            fn forward_definition_sources_may_exist(&self) -> bool {
                self.inner.definition_sources_may_exist()
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
    // A failed relational read must not publish compatibility empty values,
    // even when this lookup is used without an outer query scope.
    incomplete: AtomicBool,
    /// Resolved per lookup rather than in the shared memo: the languages a
    /// multi-analyzer reports are not the languages one of its delegates
    /// reports, and both kinds of analyzer can hand out the same memo.
    workspace_languages: OnceLock<Vec<Language>>,
    nonempty_workspace_languages: OnceLock<Vec<Language>>,
    memo: Arc<DefinitionLookupMemo>,
}

impl<'a> AnalyzerDefinitionLookup<'a> {
    pub fn new(analyzer: &'a dyn IAnalyzer, language: Language) -> Self {
        Self {
            analyzer,
            language: Mutex::new(language),
            incomplete: AtomicBool::new(false),
            workspace_languages: OnceLock::new(),
            nonempty_workspace_languages: OnceLock::new(),
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

    /// Configured languages that may contribute definitions, in stable order.
    /// Empty delegates cannot own a cross-language target (#1174), so skip
    /// their candidate rendering and store batches (#3140). Unknown providers
    /// remain eligible. Ledger reads retain negative questions for every
    /// language so adding its first source still invalidates the answer.
    fn workspace_languages(&self) -> &[Language] {
        let languages = self
            .workspace_languages
            .get_or_init(|| self.analyzer.languages().into_iter().collect());
        if self.analyzer.read_ledger_attached() {
            return languages;
        }
        self.nonempty_workspace_languages.get_or_init(|| {
            languages
                .iter()
                .copied()
                .filter(|language| {
                    self.language_analyzer(*language)
                        .is_none_or(|provider| provider.forward_definition_sources_may_exist())
                })
                .collect()
        })
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
        let scope = crate::analyzer::AnalyzerQueryScope::new(self.analyzer);
        let values = match self
            .analyzer
            .relational_definition_batch_for_active_query(&requests)
        {
            RelationalBatchOutcome::Complete(mut results) => {
                results.sort_by_key(|result| result.ordinal);
                assert_eq!(results.len(), requests.len());
                results.into_iter().map(|result| result.value).collect()
            }
            RelationalBatchOutcome::Cancelled => {
                self.incomplete.store(true, Ordering::Release);
                Vec::new()
            }
            RelationalBatchOutcome::Failed(error) => {
                self.incomplete.store(true, Ordering::Release);
                self.analyzer
                    .record_query_failure(StoreError::new(error.message()));
                Vec::new()
            }
        };
        if scope.read_completion().is_err() {
            self.incomplete.store(true, Ordering::Release);
        }
        values
    }

    pub(crate) fn can_publish(&self) -> bool {
        !self.incomplete.load(Ordering::Acquire)
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
        if self.can_publish() {
            self.memo
                .identifier_cache
                .lock()
                .expect("definition identifier cache poisoned")
                .insert(key, matches.clone());
        }
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
        let read = || self.fqn_for_language_unrecorded(fqn, language);
        if !self.analyzer.read_ledger_attached() {
            return read();
        }
        let (matches, reads) =
            crate::analyzer::i_analyzer::capture_nested_reads(self.analyzer, read);
        if self.can_publish() {
            self.record_resolved_name(fqn, Some(language), &matches);
        } else {
            for read in reads {
                self.analyzer.record_read(read);
            }
        }
        matches
    }

    fn record_resolved_name(&self, name: &str, language: Option<Language>, matches: &[CodeUnit]) {
        if !self.analyzer.read_ledger_attached() || !self.can_publish() {
            return;
        }
        self.analyzer
            .record_read(crate::analyzer::read_ledger::ReadKey::lookup(
                crate::analyzer::read_ledger::LookupKind::ResolvedName,
                crate::analyzer::read_ledger::LookupQuestion::Name {
                    language,
                    name: name.into(),
                },
                crate::analyzer::read_ledger::declaration_set_digest(matches),
            ));
    }

    fn fqn_for_language_unrecorded(&self, fqn: &str, language: Language) -> Vec<CodeUnit> {
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
        if self.can_publish() {
            self.memo
                .fqn_cache
                .lock()
                .expect("definition fqn cache poisoned")
                .insert(key, matches.clone());
        }
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
    pub(crate) fn prefetch_fqns(&self, fqns: &[String]) {
        for language in self.query_languages() {
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
                if self.can_publish() {
                    cache.insert((language, fqn), units);
                }
            }
        }
    }

    /// Populates the fqn cache for many names in one language with as few
    /// relational-store round trips as possible. A caller resolving many
    /// distinct names in a loop should prefetch them here first so each
    /// `fqn_for_language` / `fqn_in_language` call afterward is a cache hit
    /// instead of its own round trip.
    pub(crate) fn prefetch_fqn_in_language(&self, language: Language, fqns: &[String]) {
        let mut pending_fqns = Vec::new();
        {
            let cache = self
                .memo
                .fqn_cache
                .lock()
                .expect("definition fqn cache poisoned");
            let mut seen = crate::hash::HashSet::default();
            for fqn in fqns {
                if !cache.contains_key(&(language, fqn.clone())) && seen.insert(fqn.clone()) {
                    pending_fqns.push(fqn.clone());
                }
            }
        }
        if pending_fqns.is_empty() {
            return;
        }
        let mut queries = Vec::with_capacity(pending_fqns.len());
        let mut named_fqns = Vec::with_capacity(pending_fqns.len());
        for fqn in pending_fqns {
            let Some(name) = Self::rendered_name(language, &fqn) else {
                continue;
            };
            queries.push((name, RelationalDefinitionQuery::ExactName));
            named_fqns.push(fqn);
        }
        if queries.is_empty() {
            return;
        }
        let results = self.query_values(language, queries);
        let mut misses = Vec::new();
        for (fqn, value) in named_fqns.into_iter().zip(results) {
            let mut units = match value {
                RelationalDefinitionValue::Definitions(units) => units,
                _ => panic!("an exact-name query returned the wrong result shape"),
            };
            units.retain(|unit| unit.fq_name() == fqn);
            if units.is_empty() {
                misses.push(fqn);
            } else {
                sort_units(&mut units);
                units.dedup();
                if self.can_publish() {
                    self.memo
                        .fqn_cache
                        .lock()
                        .expect("definition fqn cache poisoned")
                        .insert((language, fqn), units);
                }
            }
        }
        if misses.is_empty() {
            return;
        }
        // Every miss above falls back to the identifier-candidate seek
        // `exact_for_language` uses one name at a time. Batch that fallback
        // across every miss too, tagging each query with which name it
        // answers, so a workspace where most names take this path still
        // resolves in one round trip instead of one per name (bifrost#15).
        let mut fallback_queries = Vec::new();
        let mut fallback_owner = Vec::new();
        let mut identifiers_by_fqn = Vec::with_capacity(misses.len());
        for fqn in &misses {
            let identifiers = self.rendered_identifier_candidates(language, fqn);
            for identifier in &identifiers {
                if let Some(name) = Self::identifier_name(identifier) {
                    fallback_queries
                        .push((name, RelationalDefinitionQuery::Identifier { file: None }));
                    fallback_owner.push(identifiers_by_fqn.len());
                }
                for seek in decorated_identifier_seeks(language, identifier) {
                    match seek {
                        IdentifierSeek::Exact(spelling) => {
                            if let Some(name) = Self::identifier_name(&spelling) {
                                fallback_queries.push((
                                    name,
                                    RelationalDefinitionQuery::Identifier { file: None },
                                ));
                                fallback_owner.push(identifiers_by_fqn.len());
                            }
                        }
                        IdentifierSeek::Prefix(prefix) => {
                            if let Some(name) = Self::identifier_name(&prefix) {
                                fallback_queries.push((
                                    name,
                                    RelationalDefinitionQuery::IdentifierPrefix { file: None },
                                ));
                                fallback_owner.push(identifiers_by_fqn.len());
                            }
                        }
                    }
                }
            }
            identifiers_by_fqn.push(identifiers);
        }
        let mut units_by_fqn: Vec<Vec<CodeUnit>> = vec![Vec::new(); misses.len()];
        if !fallback_queries.is_empty() {
            let fallback_results = self.query_values(language, fallback_queries);
            for (owner, value) in fallback_owner.into_iter().zip(fallback_results) {
                match value {
                    RelationalDefinitionValue::Definitions(units) => {
                        units_by_fqn[owner].extend(units);
                    }
                    _ => panic!("an identifier query returned the wrong result shape"),
                }
            }
        }
        for (fqn, (identifiers, mut units)) in misses
            .into_iter()
            .zip(identifiers_by_fqn.into_iter().zip(units_by_fqn))
        {
            units.retain(|unit| {
                identifiers.iter().any(|identifier| {
                    crate::analyzer::common::identifier_addresses_target(unit, identifier)
                }) && unit.fq_name() == fqn
            });
            sort_units(&mut units);
            units.dedup();
            if self.can_publish() {
                self.memo
                    .fqn_cache
                    .lock()
                    .expect("definition fqn cache poisoned")
                    .insert((language, fqn), units);
            }
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
        if self.analyzer.read_ledger_attached()
            && *self
                .language
                .lock()
                .expect("definition language mutex poisoned")
                == Language::None
        {
            self.record_resolved_name(fqn, None, &units);
        }
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
        self.record_resolved_name(fqn, None, &units);
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
            if self.can_publish() {
                self.memo
                    .normalized_fqn_cache
                    .lock()
                    .expect("normalized definition cache poisoned")
                    .insert(key, matches.clone());
            }
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
        if self.can_publish() {
            self.memo
                .file_identifier_cache
                .lock()
                .expect("file identifier cache poisoned")
                .insert(key, matches.clone());
        }
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
            if self.can_publish() {
                self.memo
                    .children_cache
                    .lock()
                    .expect("definition children cache poisoned")
                    .insert(key, children.clone());
            }
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
            if self.can_publish() {
                self.memo
                    .members_cache
                    .lock()
                    .expect("definition members cache poisoned")
                    .insert(key, members.clone());
            }
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
        if self.can_publish() {
            self.memo
                .structured_members_cache
                .lock()
                .expect("structured definition members cache poisoned")
                .insert(key, members.clone());
        }
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
        let mut values = self.query_values(
            language,
            vec![(
                RelationalName::stable(package_fq_name(language, package)),
                RelationalDefinitionQuery::PackageRelation(PackageRelationKind::Exists),
            )],
        );
        let exists = matches!(
            values.pop(),
            Some(RelationalDefinitionValue::PackageRelation(
                PackageRelationValue::Exists(true)
            ))
        );
        if self.can_publish() {
            self.memo
                .package_cache
                .lock()
                .expect("package cache poisoned")
                .insert(key, exists);
        }
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
            if self.can_publish() {
                self.memo
                    .prefix_cache
                    .lock()
                    .expect("fqn prefix cache poisoned")
                    .insert(key, exists);
            }
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

    #[test]
    fn workspace_lookup_skips_empty_delegates_and_observes_their_first_source() {
        use crate::analyzer::{AnalyzerDelegate, CppAnalyzer, MultiAnalyzer, ScalaAnalyzer};
        use std::collections::{BTreeMap, BTreeSet};

        let fixture = crate::inline_project::InlineTestProject::new()
            .file("widget.cpp", "class Widget {};\n")
            .build();
        let analyzer = MultiAnalyzer::new(BTreeMap::from([
            (
                Language::Cpp,
                AnalyzerDelegate::Cpp(CppAnalyzer::from_project(fixture.project().clone())),
            ),
            (
                Language::Scala,
                AnalyzerDelegate::Scala(ScalaAnalyzer::from_project(fixture.project().clone())),
            ),
        ]));
        let scala_batches = |analyzer: &MultiAnalyzer| {
            analyzer.delegates()[&Language::Scala]
                .analyzer()
                .test_hooks()
                .relational_definition_batch_call_count_for_test()
        };
        let before = scala_batches(&analyzer);
        {
            let lookup = AnalyzerDefinitionLookup::new(&analyzer, Language::None);
            assert_eq!(lookup.fqn("Widget").len(), 1);
            assert!(lookup.fqn("Absent").is_empty());
            assert_eq!(lookup.identifier("Widget").len(), 1);
            assert_eq!(lookup.by_normalized_fqn("Widget").len(), 1);
            assert!(!lookup.package_exists_in_any_language("absent"));
            lookup.prefetch_fqns(&["AlsoAbsent".to_string()]);
            assert!(lookup.fqn("AlsoAbsent").is_empty());
        }
        assert_eq!(
            scala_batches(&analyzer) - before,
            0,
            "empty Scala must do no relational work for C++ workspace lookups"
        );
        // Reusing a lookup under a newly attached ledger must restore negative
        // reads for empty languages, even after its pruned list was cached.
        let lookup = AnalyzerDefinitionLookup::new(&analyzer, Language::None);
        assert!(lookup.identifier("Missing").is_empty());
        {
            let ledger = Arc::new(crate::analyzer::ReadLedger::new());
            let _scope = crate::analyzer::AnalyzerQueryScope::with_read_ledger(
                &analyzer,
                Arc::clone(&ledger),
            );
            assert!(lookup.identifier("LedgerMissing").is_empty());
            assert!(scala_batches(&analyzer) > before);
            assert!(!ledger.keys().is_empty());
        }
        drop(lookup);

        // A scoped resolver must still see an exact target in another language.
        let lookup = AnalyzerDefinitionLookup::new(&analyzer, Language::Scala);
        assert_eq!(lookup.fqn_in_any_language("Widget").len(), 1);
        assert!(lookup.fqn("Widget").is_empty());
        drop(lookup);

        let file = ProjectFile::new(fixture.root().to_path_buf(), "Added.scala");
        file.write("package added\nclass Added\n").unwrap();
        let updated = analyzer.update(&BTreeSet::from([file]));
        let lookup = AnalyzerDefinitionLookup::new(&updated, Language::Cpp);
        assert_eq!(lookup.fqn_in_any_language("added.Added").len(), 1);
        assert!(lookup.package_exists_in_any_language("added"));
        assert!(lookup.fqn("added.Added").is_empty());
    }

    #[test]
    fn cancelled_relational_lookup_does_not_memoize_an_empty_answer() {
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Ruby)
            .file("widget.rb", "class Widget\nend\n")
            .build();
        let analyzer = RubyAnalyzer::from_project(fixture.project().clone());
        let lookup = AnalyzerDefinitionLookup::new(&analyzer, Language::Ruby);
        let cancellation = crate::CancellationToken::new();
        cancellation.cancel();
        {
            let _scope =
                crate::analyzer::AnalyzerQueryScope::with_cancellation(&analyzer, &cancellation);
            assert!(lookup.fqn("Widget").is_empty());
            assert!(
                lookup
                    .file_identifier(&fixture.file("widget.rb"), "Widget")
                    .is_empty()
            );
        }

        let recovered = lookup.fqn("Widget");
        assert!(
            recovered.iter().any(|unit| unit.fq_name() == "Widget"),
            "{recovered:?}"
        );
        assert_eq!(
            lookup.file_identifier(&fixture.file("widget.rb"), "Widget"),
            recovered,
            "a cancelled file-identifier read must be retried too"
        );
        assert!(lookup.memo.fqn_cache.lock().unwrap().is_empty());
    }

    #[test]
    fn failed_relational_lookup_does_not_publish_later_memo_entries() {
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Ruby)
            .file("widget.rb", "class Widget\nend\n")
            .build();
        let analyzer = RubyAnalyzer::from_project(fixture.project().clone());
        let lookup = AnalyzerDefinitionLookup::new(&analyzer, Language::Ruby);
        // The store rejects an exact-name question with no name. This takes
        // the real Failed batch path without relying on an I/O race.
        assert!(
            lookup
                .query_values(
                    Language::Ruby,
                    vec![(
                        RelationalName::stable(FqName::new()),
                        RelationalDefinitionQuery::ExactName
                    )]
                )
                .is_empty()
        );
        let recovered = lookup.fqn("Widget");
        assert!(
            recovered.iter().any(|unit| unit.fq_name() == "Widget"),
            "{recovered:?}"
        );
        assert!(
            lookup.memo.fqn_cache.lock().unwrap().is_empty(),
            "a lookup that observed a failed batch must not publish memo entries"
        );
    }

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
