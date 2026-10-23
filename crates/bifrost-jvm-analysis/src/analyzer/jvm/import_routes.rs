use std::collections::BTreeMap;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_analysis::analyzer::symbol_lookup::symbol_selector_leaf;

use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;

/// One explicit model-backed import route visible at a reference.
///
/// The route is selected from the import's own declaration position and scope.
/// It does not depend on where a native resolver starts walking the import
/// route (for example, at a positioned-import checkpoint).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExplicitImportModelRoute {
    pub(crate) target: String,
    pub(crate) owner: String,
    pub(crate) local_name: String,
}

pub(crate) fn explicit_import_model_route(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    reference: &ResolvedReferenceSite,
) -> Option<ExplicitImportModelRoute> {
    let language = brokk_bifrost_core::analyzer::common::language_for_file(file);
    if !matches!(language, Language::Java | Language::Scala) {
        return None;
    }
    let local_name = symbol_selector_leaf(language, &reference.text)?;
    let provider = analyzer.import_analysis_provider_for_file(file)?;
    let mut routes = BTreeMap::<String, String>::new();
    for import in provider.import_info_of(token, file) {
        if import.is_wildcard
            || (import.local_name() != Some(local_name.as_str())
                && import.path.as_ref().and_then(|path| path.segments.last()) != Some(&local_name))
        {
            continue;
        }
        let Some(path) = import.path else {
            continue;
        };
        if path.declaration_start_byte > reference.focus_start_byte
            || !path.lexical_scopes.iter().all(|scope| {
                scope.start_byte <= reference.focus_start_byte
                    && reference.focus_start_byte < scope.end_byte
            })
        {
            continue;
        }
        let Some((last, owner)) = path.segments.split_last() else {
            continue;
        };
        let mut segments = owner.to_vec();
        segments.push(last.clone());
        routes.insert(segments.join("."), owner.join("."));
    }
    if routes.len() != 1 {
        return None;
    }
    let (target, owner) = routes.into_iter().next().unwrap();
    Some(ExplicitImportModelRoute {
        target,
        owner,
        local_name,
    })
}
