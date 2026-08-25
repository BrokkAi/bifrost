use crate::analyzer::common::language_for_file;
use crate::analyzer::common::{IdentifierSeek, decorated_identifier_seeks};
use crate::analyzer::languages::{language_support, package_fq_name};
use crate::analyzer::store::StoreError;
use crate::analyzer::{
    BoundedDefinitionLookup, CodeUnit, DefinitionLanguageScope, IAnalyzer, Language, ProjectFile,
    RelationalBatchOutcome, RelationalDefinitionQuery, RelationalDefinitionRequest,
    RelationalDefinitionValue, sort_units,
};
use crate::hash::HashMap;
use brokk_bifrost_core::analyzer::{
    PackageRelationKind, PackageRelationValue, RelationalName,
    fq_name::{FqName, SegmentKind, segment_interner},
    symbol_path::parse_symbol_path_fq,
};
use std::sync::{Mutex, OnceLock};

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

/// A forward-query view over an analyzer.  Keeping this separate from the
/// legacy index makes accidental whole-workspace fallback impossible at call
/// sites that accept only `BoundedDefinitionLookup`.
pub struct AnalyzerDefinitionLookup<'a> {
    analyzer: &'a dyn IAnalyzer,
    language: Mutex<Language>,
    workspace_languages: OnceLock<Vec<Language>>,
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

impl<'a> AnalyzerDefinitionLookup<'a> {
    pub fn new(analyzer: &'a dyn IAnalyzer, language: Language) -> Self {
        Self {
            analyzer,
            language: Mutex::new(language),
            workspace_languages: OnceLock::new(),
            fqn_cache: Mutex::new(HashMap::default()),
            normalized_fqn_cache: Mutex::new(HashMap::default()),
            identifier_cache: Mutex::new(HashMap::default()),
            file_identifier_cache: Mutex::new(HashMap::default()),
            children_cache: Mutex::new(HashMap::default()),
            members_cache: Mutex::new(HashMap::default()),
            structured_members_cache: Mutex::new(HashMap::default()),
            package_cache: Mutex::new(HashMap::default()),
            prefix_cache: Mutex::new(HashMap::default()),
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

    fn identifier_candidates_for_spellings(
        &self,
        language: Language,
        identifiers: &[String],
        file: Option<&ProjectFile>,
    ) -> Vec<CodeUnit> {
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
        let mut units = self
            .query_values(language, queries)
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
            .fqn_cache
            .lock()
            .expect("definition fqn cache poisoned")
            .get(&key)
        {
            return cached.clone();
        }
        let matches = self.exact_for_language(fqn, language);
        self.fqn_cache
            .lock()
            .expect("definition fqn cache poisoned")
            .insert(key, matches.clone());
        matches
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
            self.normalized_fqn_cache
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
            let key = (language, ident.to_string());
            if let Some(cached) = self
                .identifier_cache
                .lock()
                .expect("definition identifier cache poisoned")
                .get(&key)
            {
                units.extend(cached.clone());
                continue;
            }
            let mut matches = self.identifier_candidates_for_language(language, ident, None);
            sort_units(&mut matches);
            matches.dedup();
            self.identifier_cache
                .lock()
                .expect("definition identifier cache poisoned")
                .insert(key, matches.clone());
            units.extend(matches);
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
            .file_identifier_cache
            .lock()
            .expect("file identifier cache poisoned")
            .get(&key)
        {
            return cached.clone();
        }
        let matches =
            self.identifier_candidates_for_language(language_for_file(file), ident, Some(file));
        self.file_identifier_cache
            .lock()
            .expect("file identifier cache poisoned")
            .insert(key, matches.clone());
        matches
    }

    fn fqn_direct_children(&self, fqn: &str) -> Vec<CodeUnit> {
        let mut all_children = Vec::new();
        for language in self.query_languages() {
            let key = (language, fqn.to_string());
            if let Some(cached) = self
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
            self.children_cache
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
            self.members_cache
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
        self.structured_members_cache
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
        self.package_cache
            .lock()
            .expect("package cache poisoned")
            .insert(key, exists);
        exists
    }

    fn fqn_prefix_exists(&self, prefix: &str) -> bool {
        for language in self.query_languages() {
            let key = (language, prefix.to_string());
            if let Some(cached) = self
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
            self.prefix_cache
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
