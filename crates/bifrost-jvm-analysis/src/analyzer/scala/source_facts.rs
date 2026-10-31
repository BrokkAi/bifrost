use crate::analyzer::scala::ScalaAdapter;

use crate::analyzer::scala::source_storage::ScalaSourceStorage;

use brokk_bifrost_analysis::analyzer::store::GenerationId;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;

use brokk_bifrost_core::hash::HashMap;
use std::sync::Arc;

pub(crate) trait ScalaSourceFacts {
    fn canonical_scala_source_facts(
        &self,
        file: &ProjectFile,
        cache: &moka::sync::Cache<
            (
                GenerationId,
                brokk_bifrost_core::gitblob::BlobKey,
                ProjectFile,
            ),
            Arc<brokk_bifrost_jvm::scala::source_facts::ScalaFileSourceFacts>,
        >,
    ) -> Option<Arc<brokk_bifrost_jvm::scala::source_facts::ScalaFileSourceFacts>>;
}

impl ScalaSourceFacts for TreeSitterAnalyzer<ScalaAdapter> {
    fn canonical_scala_source_facts(
        &self,
        file: &ProjectFile,
        cache: &moka::sync::Cache<
            (
                GenerationId,
                brokk_bifrost_core::gitblob::BlobKey,
                ProjectFile,
            ),
            Arc<brokk_bifrost_jvm::scala::source_facts::ScalaFileSourceFacts>,
        >,
    ) -> Option<Arc<brokk_bifrost_jvm::scala::source_facts::ScalaFileSourceFacts>> {
        let reader = self.canonical_source_read(file, "scala")?;
        let (generation, oid, cache_file) = reader.cache_key();
        let cache_key = (
            generation,
            brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "scala"),
            cache_file,
        );
        reader.record_read_key();
        if let Some(facts) = cache.get(&cache_key) {
            return Some(facts);
        }
        if let Some(state) = reader.retained_primary() {
            let source = state
                .source_facts
                .as_ref()
                .expect("retained canonical source facts");
            let facts = source.scala.as_ref()?;
            let mut declaration_units: HashMap<_, Vec<_>> = HashMap::default();
            for (declaration, unit) in &state.source_declaration_units {
                declaration_units
                    .entry(*declaration)
                    .or_default()
                    .push(unit.clone());
            }
            let facts = Arc::new(
                brokk_bifrost_jvm::scala::source_facts::ScalaFileSourceFacts {
                    source: source.occurrences.clone(),
                    facts: facts.clone(),
                    declaration_units,
                },
            );
            cache.insert(cache_key, Arc::clone(&facts));
            return Some(facts);
        }
        let facts = reader.read(
            "reading canonical Scala declaration facts",
            |store, oid, generation, adapter| {
                store.scala_source_facts(oid, generation, adapter, file, &|| true)
            },
        )??;
        let facts = Arc::new(facts);
        cache.insert(cache_key, Arc::clone(&facts));
        Some(facts)
    }
}
