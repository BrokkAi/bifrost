//! Locations supplied by the eager analyzer or a build's authored anchors.

use super::*;

/// Lazy record projection needs source translation only for Source locators.
#[doc(hidden)]
pub trait SemanticModelLocations {
    fn record_location(
        &self,
        shard: &ActiveSemanticModelShard,
        locator: &Locator,
        fallback_symbol: &str,
        record_kind: &str,
        record_id: &str,
    ) -> SemanticModelLocation;
}

impl<T: IAnalyzer + ?Sized> SemanticModelLocations for T {
    fn record_location(
        &self,
        shard: &ActiveSemanticModelShard,
        locator: &Locator,
        fallback_symbol: &str,
        record_kind: &str,
        record_id: &str,
    ) -> SemanticModelLocation {
        authored_anchor(
            self,
            &shard.manifest.carried_sources,
            locator,
            fallback_symbol,
        )
        .map(SemanticModelLocation::Authored)
        .unwrap_or_else(|| model_location(shard, record_kind, record_id))
    }
}

pub struct CarriedSourceLocations;

impl SemanticModelLocations for CarriedSourceLocations {
    fn record_location(
        &self,
        shard: &ActiveSemanticModelShard,
        locator: &Locator,
        fallback_symbol: &str,
        record_kind: &str,
        record_id: &str,
    ) -> SemanticModelLocation {
        carried_source_anchor(&shard.manifest.carried_sources, locator, fallback_symbol)
            .map(SemanticModelLocation::Authored)
            .unwrap_or_else(|| model_location(shard, record_kind, record_id))
    }
}

pub use crate::analyzer::store::semantic_composition::SourceAnchors;

pub struct SourceAnchorView<'a> {
    pub activation: &'a SourceAnchors,
    pub request: Option<crate::retention_budget::BudgetedValue<SourceAnchors>>,
}

impl SourceAnchorView<'_> {
    pub fn ids_at_path(&self, path: &str) -> Vec<String> {
        let mut ids = self.activation.ids_at_path(path);
        if let Some(request) = &self.request {
            ids.extend(request.ids_at_path(path));
        }
        ids
    }
}

impl SemanticModelLocations for SourceAnchorView<'_> {
    fn record_location(
        &self,
        shard: &ActiveSemanticModelShard,
        _locator: &Locator,
        _fallback_symbol: &str,
        record_kind: &str,
        record_id: &str,
    ) -> SemanticModelLocation {
        self.activation
            .get(shard, record_kind, record_id)
            .or_else(|| {
                self.request
                    .as_ref()
                    .and_then(|request| request.get(shard, record_kind, record_id))
            })
            .cloned()
            .map(SemanticModelLocation::Authored)
            .unwrap_or_else(|| model_location(shard, record_kind, record_id))
    }
}

impl SemanticModelLocations for SourceAnchors {
    fn record_location(
        &self,
        shard: &ActiveSemanticModelShard,
        _locator: &Locator,
        _fallback_symbol: &str,
        record_kind: &str,
        record_id: &str,
    ) -> SemanticModelLocation {
        self.get(shard, record_kind, record_id)
            .cloned()
            .map(SemanticModelLocation::Authored)
            .unwrap_or_else(|| model_location(shard, record_kind, record_id))
    }
}
