use crate::analyzer::{CodeUnit, DefinitionLookupIndex, IAnalyzer, LanguageAdapter};
use crate::hash::{HashMap, HashSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CallableFacts {
    pub(crate) arity: Option<usize>,
    pub(crate) return_type_fqn: Option<String>,
    pub(crate) is_function: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CallableFactsEntry {
    pub(crate) declaration: CodeUnit,
    pub(crate) facts: CallableFacts,
}

pub(crate) trait SignatureFactsExtractor {
    fn arity_of(
        &self,
        signature: &str,
        metadata: Option<&crate::analyzer::SignatureMetadata>,
    ) -> Option<usize>;
    fn return_type_text<'a>(&self, signature: &'a str) -> Option<&'a str>;
    fn normalize_full_name(&self, fqn: &str) -> String;
    fn preferred_type_candidate<'a>(&self, candidates: &'a [CodeUnit]) -> Option<&'a CodeUnit> {
        candidates.first()
    }
}

impl<T: LanguageAdapter> SignatureFactsExtractor for T {
    fn arity_of(
        &self,
        signature: &str,
        metadata: Option<&crate::analyzer::SignatureMetadata>,
    ) -> Option<usize> {
        self.callable_arity(signature, metadata)
    }

    fn return_type_text<'a>(&self, signature: &'a str) -> Option<&'a str> {
        self.callable_return_type_text(signature)
    }

    fn normalize_full_name(&self, fqn: &str) -> String {
        LanguageAdapter::normalize_full_name(self, fqn)
    }

    fn preferred_type_candidate<'a>(&self, candidates: &'a [CodeUnit]) -> Option<&'a CodeUnit> {
        LanguageAdapter::preferred_type_candidate(self, candidates)
    }
}

#[derive(Clone, Debug, Default)]
pub struct UsageFactsIndex {
    #[allow(dead_code)]
    by_fqn: HashMap<String, Vec<CallableFactsEntry>>,
    by_declaration: HashMap<CodeUnit, CallableFacts>,
    unambiguous_return_by_fqn: HashMap<String, Option<String>>,
    #[allow(dead_code)]
    return_candidates_by_fqn: HashMap<String, Vec<String>>,
}

impl UsageFactsIndex {
    #[allow(dead_code)]
    pub(crate) fn build(
        analyzer: &dyn IAnalyzer,
        extract: &dyn SignatureFactsExtractor,
    ) -> UsageFactsIndex {
        Self::build_from_declarations(
            analyzer.definition_lookup_index(),
            analyzer.all_declarations(),
            |unit| {
                analyzer
                    .signatures(unit)
                    .first()
                    .cloned()
                    .or_else(|| unit.signature().map(str::to_string))
            },
            |unit| analyzer.signature_metadata(unit).first().cloned(),
            extract,
        )
    }

    pub(crate) fn build_from_declarations<'a>(
        definitions: &DefinitionLookupIndex,
        declarations: impl IntoIterator<Item = &'a CodeUnit>,
        signature_of: impl Fn(&CodeUnit) -> Option<String>,
        metadata_of: impl Fn(&CodeUnit) -> Option<crate::analyzer::SignatureMetadata>,
        extract: &dyn SignatureFactsExtractor,
    ) -> UsageFactsIndex {
        let mut by_fqn: HashMap<String, Vec<CallableFactsEntry>> = HashMap::default();
        let mut by_declaration = HashMap::default();
        let mut unambiguous_return_by_fqn = HashMap::default();
        let mut return_candidate_sets: HashMap<String, HashSet<String>> = HashMap::default();

        for unit in declarations {
            if !unit.is_function() && !unit.is_field() {
                continue;
            }
            let signature = signature_of(unit);
            let metadata = metadata_of(unit);
            let return_type_fqn = signature
                .as_deref()
                .and_then(|signature| extract.return_type_text(signature))
                .and_then(|return_type| {
                    return_type_fqn(return_type, unit.package_name(), definitions, extract)
                });
            let facts = CallableFacts {
                arity: signature
                    .as_deref()
                    .and_then(|signature| extract.arity_of(signature, metadata.as_ref())),
                return_type_fqn,
                is_function: unit.is_function(),
            };
            let fqn = unit.fq_name();
            if let Some(return_type_fqn) = &facts.return_type_fqn {
                insert_callable_return_type(
                    &mut unambiguous_return_by_fqn,
                    fqn.clone(),
                    return_type_fqn.clone(),
                );
                return_candidate_sets
                    .entry(fqn.clone())
                    .or_default()
                    .insert(return_type_fqn.clone());
            }
            by_declaration.insert(unit.clone(), facts.clone());
            by_fqn.entry(fqn).or_default().push(CallableFactsEntry {
                declaration: unit.clone(),
                facts,
            });
        }

        let mut return_candidates_by_fqn = HashMap::default();
        for (fqn, candidates) in return_candidate_sets {
            let mut candidates = candidates.into_iter().collect::<Vec<_>>();
            candidates.sort();
            return_candidates_by_fqn.insert(fqn, candidates);
        }

        Self {
            by_fqn,
            by_declaration,
            unambiguous_return_by_fqn,
            return_candidates_by_fqn,
        }
    }

    pub(crate) fn callable_return_type(&self, fqn: &str) -> Option<&str> {
        self.unambiguous_return_by_fqn
            .get(fqn)
            .and_then(|value| value.as_deref())
    }

    #[allow(dead_code)]
    pub(crate) fn callable_return_candidates(&self, fqn: &str) -> impl Iterator<Item = &str> {
        self.return_candidates_by_fqn
            .get(fqn)
            .into_iter()
            .flat_map(|candidates| candidates.iter().map(String::as_str))
    }

    #[allow(dead_code)]
    pub(crate) fn facts(&self, fqn: &str) -> &[CallableFactsEntry] {
        self.by_fqn.get(fqn).map(Vec::as_slice).unwrap_or(&[])
    }

    pub(crate) fn fact_for_declaration(&self, declaration: &CodeUnit) -> Option<&CallableFacts> {
        self.by_declaration.get(declaration)
    }
}

fn insert_callable_return_type(
    callable_return_types: &mut HashMap<String, Option<String>>,
    fqn: String,
    return_type_fqn: String,
) {
    match callable_return_types.get_mut(&fqn) {
        Some(existing) => {
            if existing
                .as_ref()
                .is_some_and(|value| *value != return_type_fqn)
            {
                *existing = None;
            }
        }
        None => {
            callable_return_types.insert(fqn, Some(return_type_fqn));
        }
    }
}

fn return_type_fqn(
    return_type: &str,
    package_name: &str,
    definitions: &DefinitionLookupIndex,
    extract: &dyn SignatureFactsExtractor,
) -> Option<String> {
    let base = return_type
        .split(['[', '(', '{', ' '])
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty())?;
    extract
        .preferred_type_candidate(definitions.types_in_package(package_name, base))
        .cloned()
        .or_else(|| definitions.fqn(base).into_iter().next())
        .or_else(|| {
            definitions
                .by_normalized_fqn(&extract.normalize_full_name(base))
                .first()
                .cloned()
        })
        .map(|decl| decl.fq_name())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{CodeUnitType, ProjectFile};
    use std::path::Path;

    struct TestExtractor;

    impl SignatureFactsExtractor for TestExtractor {
        fn arity_of(
            &self,
            signature: &str,
            _metadata: Option<&crate::analyzer::SignatureMetadata>,
        ) -> Option<usize> {
            signature.strip_prefix("arity:")?.parse().ok()
        }

        fn return_type_text<'a>(&self, signature: &'a str) -> Option<&'a str> {
            signature
                .split_once("->")
                .map(|(_, return_type)| return_type.trim())
        }

        fn normalize_full_name(&self, fqn: &str) -> String {
            fqn.replace("$.", ".").trim_end_matches('$').to_string()
        }
    }

    fn unit(
        root: &Path,
        kind: CodeUnitType,
        package: &str,
        name: &str,
        signature: Option<&str>,
    ) -> CodeUnit {
        CodeUnit::with_signature(
            ProjectFile::new(root, "src/Test.scala"),
            kind,
            package.to_string(),
            name.to_string(),
            signature.map(str::to_string),
            false,
        )
    }

    #[test]
    fn collapses_ambiguous_callable_return_type_but_keeps_candidates_and_entries() {
        let root = std::env::temp_dir().join("bifrost-usage-facts-test");
        let declarations = vec![
            unit(&root, CodeUnitType::Class, "example", "Service", None),
            unit(&root, CodeUnitType::Class, "example", "Other", None),
            unit(
                &root,
                CodeUnitType::Function,
                "example",
                "Factory.make",
                Some("arity:1 -> Service"),
            ),
            unit(
                &root,
                CodeUnitType::Function,
                "example",
                "Factory.make",
                Some("arity:1 -> Other"),
            ),
        ];
        let definitions = DefinitionLookupIndex::from_declarations(
            &declarations,
            |fqn| fqn.replace("$.", ".").trim_end_matches('$').to_string(),
            |unit| unit.identifier().trim_end_matches('$').to_string(),
        );
        let facts = UsageFactsIndex::build_from_declarations(
            &definitions,
            declarations.iter().filter(|unit| !unit.is_class()),
            |unit| unit.signature().map(str::to_string),
            |_| None,
            &TestExtractor,
        );

        assert_eq!(facts.callable_return_type("example.Factory.make"), None);
        let candidates = facts
            .callable_return_candidates("example.Factory.make")
            .collect::<Vec<_>>();
        assert_eq!(candidates, vec!["example.Other", "example.Service"]);
        assert_eq!(facts.facts("example.Factory.make").len(), 2);
    }
}
