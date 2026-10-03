use super::JavaAdapter;
use crate::analyzer::store::GenerationId;
use crate::analyzer::{ProjectFile, TreeSitterAnalyzer};
use crate::hash::HashMap;
use git2::Oid;
use std::sync::Arc;

impl TreeSitterAnalyzer<JavaAdapter> {
    pub(crate) fn canonical_java_source_facts(
        &self,
        file: &ProjectFile,
        cache: &moka::sync::Cache<
            (GenerationId, Oid, ProjectFile),
            Arc<brokk_bifrost_jvm::java::source_facts::JavaFileSourceFacts>,
        >,
    ) -> Option<Arc<brokk_bifrost_jvm::java::source_facts::JavaFileSourceFacts>> {
        let reader = self.canonical_source_read(file, "java")?;
        if let Some(state) = reader.retained_primary() {
            let source = state
                .source_facts
                .as_ref()
                .expect("retained canonical source facts");
            let facts = source.java.as_ref()?;
            let mut declaration_units: HashMap<_, Vec<_>> = HashMap::default();
            for (declaration, unit) in &state.source_declaration_units {
                declaration_units
                    .entry(*declaration)
                    .or_default()
                    .push(unit.clone());
            }
            return Some(Arc::new(
                brokk_bifrost_jvm::java::source_facts::JavaFileSourceFacts {
                    source: source.occurrences.clone(),
                    facts: facts.clone(),
                    declaration_units,
                },
            ));
        }
        let cache_key = reader.cache_key();
        if let Some(facts) = cache.get(&cache_key) {
            return Some(facts);
        }
        let facts = reader.read(
            "reading canonical Java declaration facts",
            |store, oid, generation, adapter| {
                store.java_source_facts(oid, generation, adapter, file, &|| true)
            },
        )??;
        let facts = Arc::new(facts);
        cache.insert(cache_key, Arc::clone(&facts));
        Some(facts)
    }
}
