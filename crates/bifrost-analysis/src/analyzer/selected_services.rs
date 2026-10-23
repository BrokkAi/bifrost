//! Engine bridge for the selected store's borrowed service capability.

use std::sync::Arc;

use super::semantic_model::runtime::ResolvedActiveSemanticModels;
use super::store::resolution_operation::{SelectedAnalyzerServices, SelectedModelAuthority};
use super::{CodeUnit, IAnalyzer, ProjectFile};

pub(crate) struct AnalyzerSelectedServices<'a>(pub(crate) &'a dyn IAnalyzer);

impl SelectedAnalyzerServices for AnalyzerSelectedServices<'_> {
    fn declarations_named(&self, file: &ProjectFile, name: &str) -> Vec<CodeUnit> {
        self.0.declarations_named(file, name)
    }

    fn external_inventory_providers(&self) -> Vec<String> {
        super::languages::selected_external_inventory_providers(self.0)
    }

    fn active_models(&self) -> Option<Arc<ResolvedActiveSemanticModels>> {
        self.0
            .active_semantic_model_snapshot()
            .map(|snapshot| Arc::clone(snapshot.active_models()))
    }

    fn model_authority(&self) -> Option<Arc<dyn SelectedModelAuthority + Send + Sync>> {
        self.0
            .semantic_model_overlay()
            .map(|overlay| overlay as Arc<dyn SelectedModelAuthority + Send + Sync>)
    }
}
