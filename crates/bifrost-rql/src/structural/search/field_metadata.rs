//! Shared source-field metadata lookup for language-owned relations.
//!
//! Declaration adapters publish field modifiers and initializer presence through
//! `SignatureMetadata`. Language relations use this small query-local projection
//! to join those rows back to the source ranges selected by their AST walks.

use crate::analyzer::{IAnalyzer, ProjectFile, Range};
use brokk_bifrost_core::analyzer::model::SignatureMetadata;

#[derive(Clone)]
pub(super) struct FieldSite {
    pub(super) range: Range,
    pub(super) metadata: SignatureMetadata,
}

pub(super) fn field_sites(analyzer: &dyn IAnalyzer, file: &ProjectFile) -> Vec<FieldSite> {
    let mut sites = Vec::new();
    for unit in analyzer.get_declarations(file) {
        if !unit.is_field() {
            continue;
        }
        let metadata = analyzer.signature_metadata(&unit);
        let Some(metadata) = metadata.into_iter().next() else {
            continue;
        };
        sites.extend(
            analyzer
                .ranges_of(&unit)
                .into_iter()
                .map(|range| FieldSite {
                    range,
                    metadata: metadata.clone(),
                }),
        );
    }
    sites
}
