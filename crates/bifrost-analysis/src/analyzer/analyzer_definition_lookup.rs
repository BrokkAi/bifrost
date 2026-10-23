use crate::analyzer::common::language_for_file;
use crate::analyzer::common::{IdentifierSeek, decorated_identifier_seeks};
use crate::analyzer::languages::{language_support_for_hook, package_fq_name};
use crate::analyzer::store::StoreError;
use crate::analyzer::{
    BoundedDefinitionLookup, CodeUnit, DefinitionLanguageScope, IAnalyzer, Language, ProjectFile,
    RelationalBatchOutcome, RelationalDefinitionFrontier, RelationalDefinitionQuery,
    RelationalDefinitionQuestion, RelationalDefinitionRequest, RelationalDefinitionValue,
    sort_units,
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

// Bounded C++ receiver resolution may ask the same indexed name from many
// call sites in one request. Keep only small, complete answers: the cache is
// request-scoped and its entry/row caps keep a repeated-name workload from
// retaining a workspace-sized result set.
const LIMITED_LOOKUP_CACHE_MAX_ENTRIES: usize = 512;
const LIMITED_LOOKUP_CACHE_MAX_ROWS: usize = 32;

#[doc(hidden)]
pub trait ForwardQueryProvider {
    fn normalize_rendered_name(&self, fqn: &str) -> String;
    /// The structured name a rendered spelling addresses, when the language's
    /// own rendering rules disagree with the shared client-path splitter.
    ///
    /// `parse_symbol_path_fq` splits a client path on `::`, `.`, `\`, `/` and
    /// `+`. A language that renders a *join* outside that set -- C++ spells a
    /// nested class `Outer$Inner`, which persists as a `Type` + `Nested` pair
    /// -- supplies the construction here so the exact-name query's
    /// owner/terminal boundary is the persisted one. `None` (the default)
    /// keeps the shared all-`Unknown` parse.
    fn forward_rendered_name(&self, _rendered: &str) -> Option<RelationalName> {
        None
    }
    /// Further persisted identities a source spelling names, beyond the one
    /// [`Self::forward_rendered_name`] builds.
    ///
    /// The exact-name route keeps a row when its rendering equals the request,
    /// which cannot hold when the source spelling and the canonical rendering
    /// use different joins: C++ source writes `Top::Only` for the nested class
    /// persisted and rendered as `Top$Only`. Each returned name is fully kinded,
    /// so the route asks the store for it with the persisted owner/terminal
    /// boundary and keeps a row whose structured identity equals it. Empty (the
    /// default) adds no question.
    fn forward_source_spelling_names(&self, _rendered: &str) -> Vec<FqName> {
        Vec::new()
    }
    /// Navigation candidates for a rendered name. Language adapters may admit
    /// source-spelling aliases beyond exact persisted identity.
    fn forward_definition_fqn(&self, fqn: &str) -> Vec<CodeUnit>;
    fn forward_relational_name(&self, unit: &CodeUnit) -> RelationalName;
    fn forward_definition_candidate_identifiers(&self, rendered: &str) -> Vec<String>;
    fn forward_definition_sources_may_exist(&self) -> bool;
    fn forward_package_exists(&self, package: &str) -> bool;
    fn forward_fqn_prefix_exists(&self, prefix: &str) -> bool;
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_forward_query_provider {
    ($analyzer:ty) => {
        impl $crate::analyzer::analyzer_definition_lookup::ForwardQueryProvider for $analyzer {
            fn normalize_rendered_name(&self, fqn: &str) -> String {
                self.inner.normalize_rendered_name(fqn)
            }

            fn forward_definition_fqn(&self, fqn: &str) -> Vec<$crate::analyzer::CodeUnit> {
                self.inner.forward_definition_fqn(fqn)
            }

            fn forward_relational_name(
                &self,
                unit: &$crate::analyzer::CodeUnit,
            ) -> brokk_bifrost_core::analyzer::RelationalName {
                self.inner.relational_name_for_unit(unit)
            }

            fn forward_definition_candidate_identifiers(&self, rendered: &str) -> Vec<String> {
                self.inner.definition_candidate_identifiers(rendered)
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

#[doc(hidden)]
pub use crate::impl_forward_query_provider;

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
    #[doc(hidden)]
    pub fqn_cache: Mutex<HashMap<(Language, String), Vec<CodeUnit>>>,
    normalized_fqn_cache: Mutex<HashMap<(Language, String), Vec<CodeUnit>>>,
    identifier_cache: Mutex<HashMap<(Language, String), Vec<CodeUnit>>>,
    limited_fqn_cache: Mutex<HashMap<(Language, bool, String), Vec<CodeUnit>>>,
    limited_identifier_cache: Mutex<HashMap<(Language, String), Vec<CodeUnit>>>,
    file_identifier_cache: Mutex<HashMap<(ProjectFile, String), Vec<CodeUnit>>>,
    children_cache: Mutex<HashMap<(Language, String), Vec<CodeUnit>>>,
    members_cache: Mutex<HashMap<MemberLookupKey, Vec<CodeUnit>>>,
    structured_members_cache: Mutex<HashMap<StructuredMemberLookupKey, Vec<CodeUnit>>>,
    package_cache: Mutex<HashMap<(Language, String), bool>>,
    prefix_cache: Mutex<HashMap<(Language, String), bool>>,
}

impl DefinitionLookupMemo {
    #[doc(hidden)]
    pub fn limited_fqn(
        &self,
        language: Language,
        normalized: bool,
        fqn: &str,
    ) -> Option<Vec<CodeUnit>> {
        self.limited_fqn_cache
            .lock()
            .expect("limited definition fqn cache poisoned")
            .get(&(language, normalized, fqn.to_owned()))
            .cloned()
    }

    #[doc(hidden)]
    pub fn remember_limited_fqn(
        &self,
        language: Language,
        normalized: bool,
        fqn: &str,
        units: Vec<CodeUnit>,
    ) {
        if units.len() > LIMITED_LOOKUP_CACHE_MAX_ROWS {
            return;
        }
        let mut cache = self
            .limited_fqn_cache
            .lock()
            .expect("limited definition fqn cache poisoned");
        let key = (language, normalized, fqn.to_owned());
        if cache.len() < LIMITED_LOOKUP_CACHE_MAX_ENTRIES || cache.contains_key(&key) {
            cache.insert(key, units);
        }
    }

    #[doc(hidden)]
    pub fn limited_identifier(
        &self,
        language: Language,
        identifier: &str,
    ) -> Option<Vec<CodeUnit>> {
        self.limited_identifier_cache
            .lock()
            .expect("limited definition identifier cache poisoned")
            .get(&(language, identifier.to_owned()))
            .cloned()
    }

    #[doc(hidden)]
    pub fn remember_limited_identifier(
        &self,
        language: Language,
        identifier: &str,
        units: Vec<CodeUnit>,
    ) {
        if units.len() > LIMITED_LOOKUP_CACHE_MAX_ROWS {
            return;
        }
        let mut cache = self
            .limited_identifier_cache
            .lock()
            .expect("limited definition identifier cache poisoned");
        let key = (language, identifier.to_owned());
        if cache.len() < LIMITED_LOOKUP_CACHE_MAX_ENTRIES || cache.contains_key(&key) {
            cache.insert(key, units);
        }
    }
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
    #[doc(hidden)]
    pub memo: Arc<DefinitionLookupMemo>,
    /// When set, every relational read is a frontier question instead of a
    /// synchronous store batch; see [`Self::on_frontier`].
    frontier: Option<Arc<dyn RelationalDefinitionFrontier>>,
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
            frontier: None,
        }
    }

    /// A lookup that reads through a replayable relational frontier instead
    /// of issuing its own store batches: the same candidate spellings and
    /// retention rules as [`Self::new`], but each question is recorded for
    /// the frontier runner's next barrier and answered on replay. This is how
    /// a per-file walk that runs inside a frontier evaluation (the Scala
    /// query walk's foreign-realm questions, #1859) gets one batched read per
    /// barrier rather than one synchronous read per candidate.
    ///
    /// An unanswered question comes back empty until the barrier runs, so
    /// nothing this lookup computes may be published: it gets a private memo
    /// and never marks itself publishable. Construct one per question rather
    /// than reusing it across replays.
    #[doc(hidden)]
    pub fn on_frontier(
        analyzer: &'a dyn IAnalyzer,
        language: Language,
        frontier: Arc<dyn RelationalDefinitionFrontier>,
    ) -> Self {
        Self {
            analyzer,
            language: Mutex::new(language),
            incomplete: AtomicBool::new(true),
            workspace_languages: OnceLock::new(),
            nonempty_workspace_languages: OnceLock::new(),
            memo: Arc::default(),
            frontier: Some(frontier),
        }
    }

    #[doc(hidden)]
    pub fn set_language(&self, language: Language) {
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

    /// The spellings the terminal-keyed `(lang, identifier)` index is seeked
    /// with for `rendered`.
    ///
    /// This is not the `(lang, short_name)` vocabulary: a row this lookup can
    /// keep must have `identifier_addresses_target` hold for one of these
    /// spellings, and that compares a declaration's *terminal* identifier, so
    /// the owner-chain aliases the symbol index needs are provably dead here
    /// (#3299). See `TreeSitterAnalyzer::definition_candidate_identifiers`.
    fn rendered_identifier_candidates(&self, language: Language, rendered: &str) -> Vec<String> {
        let mut candidates = self
            .language_analyzer(language)
            .map(|provider| provider.forward_definition_candidate_identifiers(rendered))
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

    #[doc(hidden)]
    pub fn query_values(
        &self,
        language: Language,
        questions: Vec<(RelationalName, RelationalDefinitionQuery)>,
    ) -> Vec<RelationalDefinitionValue> {
        if questions.is_empty() {
            return Vec::new();
        }
        if let Some(frontier) = &self.frontier {
            return questions
                .into_iter()
                .map(|(name, query)| {
                    frontier.ask(&RelationalDefinitionQuestion {
                        language_scope: DefinitionLanguageScope::Language(language),
                        name,
                        query,
                    })
                })
                .collect();
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

    #[doc(hidden)]
    pub fn can_publish(&self) -> bool {
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

    fn rendered_name(&self, language: Language, rendered: &str) -> Option<RelationalName> {
        if let Some(provider) = self.language_analyzer(language)
            && let Some(name) = provider.forward_rendered_name(rendered)
        {
            return Some(name);
        }
        let name = parse_symbol_path_fq(language, rendered, segment_interner());
        (!name.is_empty()).then(|| RelationalName::stable(name))
    }

    /// See [`ForwardQueryProvider::forward_source_spelling_names`].
    fn source_spelling_names(&self, language: Language, rendered: &str) -> Vec<FqName> {
        self.language_analyzer(language)
            .map(|provider| provider.forward_source_spelling_names(rendered))
            .unwrap_or_default()
    }

    /// The exact-name questions one rendered spelling asks: its rendered name,
    /// then each of its source-spelling names.
    fn exact_questions(
        name: RelationalName,
        spellings: &[FqName],
    ) -> impl Iterator<Item = (RelationalName, RelationalDefinitionQuery)> + '_ {
        std::iter::once(name)
            .chain(spellings.iter().cloned().map(RelationalName::stable))
            .map(|name| (name, RelationalDefinitionQuery::ExactName))
    }

    /// Whether `unit` answers an exact ask for `rendered`: its structured
    /// identity is one of the spelling's source-spelling names, or its
    /// rendering is the request itself.
    fn answers_exact_request(unit: &CodeUnit, rendered: &str, spellings: &[FqName]) -> bool {
        spellings.contains(unit.fq()) || unit.fq_name() == rendered
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
        let Some(name) = self.rendered_name(language, rendered) else {
            return Vec::new();
        };
        let spellings = self.source_spelling_names(language, rendered);
        let mut units = self
            .query_values(language, Self::exact_questions(name, &spellings).collect())
            .into_iter()
            .flat_map(|value| match value {
                RelationalDefinitionValue::Definitions(units) => units,
                _ => panic!("an exact-name query returned the wrong result shape"),
            })
            .collect::<Vec<_>>();
        // A rendered path-derived identity may address a content-stable tail
        // that hydrates under a different live mount. Only an authoritative
        // hydrated-name match makes the exact result complete. Otherwise
        // consult the identifier view for mounted-name and source-spelling
        // compatibility (for example a C++ name rendered with both `::` and
        // `.`). No normalized seek joins this round: this entry point promises
        // the exact rendered identity, and the encoding-agnostic question is
        // `by_normalized_fqn`, whose own seek already runs first there (#3299).
        units.retain(|unit| Self::answers_exact_request(unit, rendered, &spellings));
        if units.is_empty() {
            let identifiers = self.rendered_identifier_candidates(language, rendered);
            units.extend(self.identifier_candidates_for_spellings(language, &identifiers, None));
            units.retain(|unit| Self::answers_exact_request(unit, rendered, &spellings));
        }
        sort_units(&mut units);
        units.dedup();
        units
    }

    fn normalized_for_language(&self, normalized: &str, language: Language) -> Vec<CodeUnit> {
        let Some(name) = self.rendered_name(language, normalized) else {
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
        let Some(provider) = self.language_analyzer(language) else {
            return Vec::new();
        };
        units.retain(|unit| provider.normalize_rendered_name(&unit.fq_name()) == normalized);
        // The normalized view is the structural answer for every declaration
        // whose persisted spelling carries an encoding its source spelling does
        // not (scala's object `$`, C# generic arity, ...). The identifier view
        // is the compatibility net for the rows that view cannot reach, such as
        // an anchored row whose package the request does not carry; consulting
        // it for a name the normalized seek already answered would spend a
        // whole candidate vocabulary on a miss that is not one (#3299).
        if units.is_empty() {
            let identifiers = self.rendered_identifier_candidates(language, normalized);
            units.extend(self.identifier_candidates_for_spellings(language, &identifiers, None));
            units.retain(|unit| provider.normalize_rendered_name(&unit.fq_name()) == normalized);
        }
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

    fn memoized_units<K: Eq + std::hash::Hash>(
        &self,
        cache: &Mutex<HashMap<K, Vec<CodeUnit>>>,
        key: K,
        poison_message: &'static str,
        compute: impl FnOnce() -> Vec<CodeUnit>,
    ) -> Vec<CodeUnit> {
        if let Some(cached) = cache.lock().expect(poison_message).get(&key) {
            return cached.clone();
        }
        let units = compute();
        if self.can_publish() {
            cache
                .lock()
                .expect(poison_message)
                .insert(key, units.clone());
        }
        units
    }

    fn fqn_for_language_unrecorded(&self, fqn: &str, language: Language) -> Vec<CodeUnit> {
        let key = (language, fqn.to_string());
        self.memoized_units(
            &self.memo.fqn_cache,
            key,
            "definition fqn cache poisoned",
            || self.exact_for_language(fqn, language),
        )
    }

    fn fqn_for_languages(
        &self,
        fqn: &str,
        languages: impl IntoIterator<Item = Language>,
    ) -> Vec<CodeUnit> {
        let mut units = languages
            .into_iter()
            .flat_map(|language| self.fqn_for_language(fqn, language))
            .collect::<Vec<_>>();
        sort_units(&mut units);
        units.dedup();
        units
    }

    fn sorted_definition_units(
        values: Vec<RelationalDefinitionValue>,
        shape_error: &'static str,
    ) -> Vec<CodeUnit> {
        let mut units = values
            .into_iter()
            .flat_map(|value| match value {
                RelationalDefinitionValue::Definitions(units) => units,
                _ => panic!("{shape_error}"),
            })
            .collect::<Vec<_>>();
        sort_units(&mut units);
        units.dedup();
        units
    }

    fn structural_members(
        &self,
        language: Language,
        owners: impl IntoIterator<Item = RelationalName>,
        name: &str,
        shape_error: &'static str,
    ) -> Vec<CodeUnit> {
        let query = RelationalDefinitionQuery::StructuralMembers {
            identifier: name.to_string(),
        };
        let values = self.query_values(
            language,
            owners
                .into_iter()
                .map(|owner| (owner, query.clone()))
                .collect(),
        );
        Self::sorted_definition_units(values, shape_error)
    }

    fn package_exists_in_languages(
        &self,
        package: &str,
        languages: impl IntoIterator<Item = Language>,
    ) -> bool {
        languages
            .into_iter()
            .any(|language| self.package_exists_in_language(package, language))
    }

    /// Resolve many rendered names into the shared fqn memo with two batched
    /// relational reads per language instead of one point batch per name.
    ///
    /// The rounds are the same two questions [`Self::exact_for_language`]
    /// asks per name -- an exact persisted-identity seek for the rendered name
    /// and each of its source-spelling names, then the identifier
    /// compatibility view for the names the exact round missed -- with
    /// identical per-name filtering, so a memoized answer cannot differ from
    /// what the point path would compute. A cancelled or failed batch
    /// memoizes nothing: every name stays unmemoized and the point path
    /// retries it with unchanged results.
    #[doc(hidden)]
    pub fn prefetch_fqns(&self, fqns: &[String]) {
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
            let mut spellings_by_name = Vec::with_capacity(missing.len());
            for (index, fqn) in missing.iter().enumerate() {
                let Some(name) = self.rendered_name(language, fqn) else {
                    spellings_by_name.push(Vec::new());
                    continue;
                };
                let spellings = self.source_spelling_names(language, fqn);
                for question in Self::exact_questions(name, &spellings) {
                    exact_owners.push(index);
                    exact_questions.push(question);
                }
                spellings_by_name.push(spellings);
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
                            units_by_name[owner].extend(units);
                        }
                        _ => panic!("an exact-name query returned the wrong result shape"),
                    }
                }
            }

            let mut fallback: Vec<(usize, std::ops::Range<usize>, Vec<String>)> = Vec::new();
            let mut fallback_questions = Vec::new();
            for (index, fqn) in missing.iter().enumerate() {
                units_by_name[index].retain(|unit| {
                    Self::answers_exact_request(unit, fqn, &spellings_by_name[index])
                });
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
                    units_by_name[index].retain(|unit| {
                        Self::answers_exact_request(
                            unit,
                            &missing[index],
                            &spellings_by_name[index],
                        )
                    });
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
    #[doc(hidden)]
    pub fn prefetch_fqn_in_language(&self, language: Language, fqns: &[String]) {
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
        let mut query_owners = Vec::with_capacity(pending_fqns.len());
        let mut named_fqns = Vec::with_capacity(pending_fqns.len());
        for fqn in pending_fqns {
            let Some(name) = self.rendered_name(language, &fqn) else {
                continue;
            };
            let spellings = self.source_spelling_names(language, &fqn);
            for question in Self::exact_questions(name, &spellings) {
                queries.push(question);
                query_owners.push(named_fqns.len());
            }
            named_fqns.push((fqn, spellings));
        }
        if queries.is_empty() {
            return;
        }
        let expected = queries.len();
        let results = self.query_values(language, queries);
        if results.len() != expected {
            return;
        }
        let mut units_by_name: Vec<Vec<CodeUnit>> = vec![Vec::new(); named_fqns.len()];
        for (owner, value) in query_owners.into_iter().zip(results) {
            match value {
                RelationalDefinitionValue::Definitions(units) => {
                    units_by_name[owner].extend(units);
                }
                _ => panic!("an exact-name query returned the wrong result shape"),
            }
        }
        let mut misses = Vec::new();
        for ((fqn, spellings), mut units) in named_fqns.into_iter().zip(units_by_name) {
            units.retain(|unit| Self::answers_exact_request(unit, &fqn, &spellings));
            if units.is_empty() {
                misses.push((fqn, spellings));
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
        for (fqn, _) in &misses {
            let identifiers = self.rendered_identifier_candidates(language, fqn);
            let owner = identifiers_by_fqn.len();
            let queries = Self::identifier_queries(language, &identifiers, None);
            fallback_owner.extend(std::iter::repeat_n(owner, queries.len()));
            fallback_queries.extend(queries);
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
        for ((fqn, spellings), (identifiers, mut units)) in misses
            .into_iter()
            .zip(identifiers_by_fqn.into_iter().zip(units_by_fqn))
        {
            units.retain(|unit| {
                identifiers.iter().any(|identifier| {
                    crate::analyzer::common::identifier_addresses_target(unit, identifier)
                }) && Self::answers_exact_request(unit, &fqn, &spellings)
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

#[doc(hidden)]
pub fn package_exists_value(value: &RelationalDefinitionValue) -> bool {
    matches!(
        value,
        RelationalDefinitionValue::PackageRelation(PackageRelationValue::Exists(true))
    )
}

fn analyzer_for_language(
    analyzer: &dyn IAnalyzer,
    language: Language,
) -> Option<&dyn ForwardQueryProvider> {
    language_support_for_hook(language, "forward_query_provider")
        .and_then(|support| support.forward_query_provider(analyzer))
}

impl BoundedDefinitionLookup for AnalyzerDefinitionLookup<'_> {
    fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        let units = self.fqn_for_languages(fqn, self.query_languages());
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
        let units = self.fqn_for_languages(fqn, self.workspace_languages().iter().copied());
        self.record_resolved_name(fqn, None, &units);
        units
    }

    fn by_normalized_fqn(&self, normalized: &str) -> Vec<CodeUnit> {
        let mut units = Vec::new();
        for language in self.query_languages() {
            let key = (language, normalized.to_string());
            units.extend(self.memoized_units(
                &self.memo.normalized_fqn_cache,
                key,
                "normalized definition cache poisoned",
                || {
                    let mut matches = self.normalized_for_language(normalized, language);
                    sort_units(&mut matches);
                    matches.dedup();
                    matches
                },
            ));
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
        self.package_exists_in_languages(package, self.workspace_languages().iter().copied())
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
            let children = Self::sorted_definition_units(
                self.query_values(
                    language,
                    owner_names
                        .into_iter()
                        .map(|owner| (owner, RelationalDefinitionQuery::StructuralChildren))
                        .collect(),
                ),
                "a structural-children query returned the wrong result shape",
            );
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
            let members = self.structural_members(
                language,
                owner_names,
                name,
                "a structural-member query returned the wrong result shape",
            );
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
        let members = self.structural_members(
            language,
            std::iter::once(relational_owner),
            name,
            "a structured-member query returned the wrong result shape",
        );
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
        self.package_exists_in_languages(package, self.query_languages())
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
        let exists = values.pop().as_ref().is_some_and(package_exists_value);
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
