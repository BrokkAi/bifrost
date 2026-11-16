//! Analysis readers for the same proof context used by selected operations.
//!
//! Selected operations implement this trait with their pinned, recorded rows.
//! They never reach these analysis readers as an unavailable-read fallback.

use super::{RustAnalyzer, call_conversion::RustTypeContext};
use brokk_bifrost_analysis::analyzer::i_analyzer::{AnalyzerQueryScope, QueryScope};
use brokk_bifrost_analysis::analyzer::store::language_support::{
    SelectedExternalTypeRootRead, SelectedTypeHeadSource, SelectedTypeProofRead,
};
use brokk_bifrost_analysis::analyzer::usages::get_definition::{
    DefinitionLookupRequest, DefinitionLookupStatus,
};
use brokk_bifrost_core::analyzer::model::{CodeUnit, ProjectFile};
use brokk_bifrost_rust::graph_support::RustFactSource;

impl RustTypeContext<'_, '_> {
    fn rust_analyzer(&self) -> &RustAnalyzer {
        brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer(self.analyzer)
            .expect("Rust type proofs require a Rust analyzer")
    }
}

impl SelectedTypeHeadSource for RustTypeContext<'_, '_> {
    fn nominal_head_identity(
        &self,
        head: brokk_bifrost_analysis::analyzer::store::language_support::SelectedNominalHead<'_>,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<
        brokk_bifrost_analysis::analyzer::store::language_support::SelectedTypeEvaluationRead<
            brokk_bifrost_analysis::analyzer::store::language_support::SelectedNominalHeadDeclaration,
        >,
    >{
        use brokk_bifrost_analysis::analyzer::store::language_support::{
            SelectedNominalHead, SelectedTypeEvaluationRead as Read,
            SelectedTypeEvaluationUnavailable as Stop,
        };
        let SelectedNominalHead::Reference { file, range } = head else {
            return Ok(Read::Unavailable(Stop::IdentityUnavailable));
        };
        Ok(match self.type_declaration(file, range)? {
            SelectedTypeProofRead::Available(unit) => Read::Available(brokk_bifrost_analysis::analyzer::store::language_support::SelectedNominalHeadDeclaration { identity: unit.declaration_id(), declaration: unit }),
            _ => Read::Unavailable(Stop::IdentityUnavailable),
        })
    }
    fn nominal_is_union(
        &self,
        symbol: &str,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<
        brokk_bifrost_analysis::analyzer::store::language_support::SelectedTypeEvaluationRead<bool>,
    > {
        use brokk_bifrost_analysis::analyzer::store::language_support::{
            SelectedTypeEvaluationRead as Read, SelectedTypeEvaluationUnavailable as Stop,
        };
        let Some(snapshot) = self.analyzer.active_semantic_model_snapshot() else {
            return Ok(Read::Unavailable(Stop::IdentityUnavailable));
        };
        let Some(overlay) = snapshot.semantic_model_overlay() else {
            return Ok(Read::Unavailable(Stop::IdentityUnavailable));
        };
        let Some(symbol) = overlay.symbols_with_id_in_family(symbol, "rust").unique() else {
            return Ok(Read::Unavailable(Stop::IdentityUnavailable));
        };
        Ok(Read::Available(
            symbol.kind
                == brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbolKind::Union,
        ))
    }
    fn evaluated_call_is_bit_reinterpretation(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &tree_sitter::Tree,
        site: &brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<
        brokk_bifrost_analysis::analyzer::store::language_support::SelectedTypeEvaluationRead<bool>,
    > {
        use brokk_bifrost_analysis::analyzer::store::language_support::{
            SelectedTypeEvaluationRead as Read, SelectedTypeEvaluationUnavailable as Stop,
        };
        if cancellation.is_cancelled() {
            return Ok(Read::Unavailable(Stop::Cancelled));
        }
        let unavailable = || {
            self.analyzer.record_query_incomplete(brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadIncomplete::SemanticEvidenceUnavailable(
                "Rust unsafe-operation call identity is unavailable".into(),
            ));
            Read::Unavailable(Stop::IdentityUnavailable)
        };
        let Some(factory) =
            super::native_points::RustDefinitionOperationFactory::new(self.analyzer, cancellation)
        else {
            return Ok(unavailable());
        };
        let mut operation = match factory.open(cancellation)? {
            brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
            _ if cancellation.is_cancelled() => return Ok(Read::Unavailable(Stop::Cancelled)),
            _ => return Ok(unavailable()),
        };
        let identity = super::std_types::resolve_external_call_identity(
            self.analyzer,
            file,
            source,
            tree,
            site,
            site.focus_start_byte,
            &factory,
            &mut operation,
            Some(cancellation),
        );
        if cancellation.is_cancelled() {
            return Ok(Read::Unavailable(Stop::Cancelled));
        }
        let Some(identity) = identity else {
            // A missing identity is a content gap, not an operational stop.
            return Ok(Read::Unavailable(Stop::IdentityUnavailable));
        };
        Ok(Read::Available(
            matches!(
                identity.owner_fqn(),
                "core.mem" | "std.mem" | "core.intrinsics" | "std.intrinsics"
            ) && matches!(
                identity.member(),
                "transmute" | "transmute_copy" | "transmute_unchecked"
            ),
        ))
    }
    fn glob_may_bind_name(
        &self,
        file: &ProjectFile,
        binding: &brokk_bifrost_core::analyzer::usages::model::ImportBinding,
        name: &str,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<SelectedTypeProofRead<bool>> {
        let scope = AnalyzerQueryScope::new(self.analyzer);
        Ok(
            match brokk_bifrost_rust::graph_support::reference_context_of(
                self.rust_analyzer(),
                scope.token(),
                file,
            )
            .glob_may_bind_name(binding, name)
            {
                Ok(may_bind) => SelectedTypeProofRead::Available(may_bind),
                Err(_) => SelectedTypeProofRead::Unavailable,
            },
        )
    }
    fn model_type_owner(
        &self,
        file: &ProjectFile,
        range: std::ops::Range<usize>,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<
        SelectedTypeProofRead<
            brokk_bifrost_analysis::analyzer::store::language_support::SelectedTypeOwner,
        >,
    > {
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            SemanticModelSymbolKind,
            overlay::{ModelProvider, ModelSymbolRef, RustReexportNamespace},
        };
        use brokk_bifrost_analysis::analyzer::store::language_support::SelectedTypeOwner;
        let scope = AnalyzerQueryScope::new(self.analyzer);
        let Some(parsed) = self.rust_analyzer().prepared_syntax(scope.token(), file) else {
            return Ok(SelectedTypeProofRead::Unavailable);
        };
        let Some(selected_node) = parsed
            .tree()
            .root_node()
            .named_descendant_for_byte_range(range.start, range.end)
        else {
            return Ok(SelectedTypeProofRead::Unavailable);
        };
        let node = selected_node
            .child_by_field_name("name")
            .unwrap_or(selected_node);
        let mut outcomes = brokk_bifrost_analysis::analyzer::usages::get_definition::resolve_definition_batch_with_source_tree(
            self.analyzer, vec![DefinitionLookupRequest {file:file.clone(), line:None,column:None,start_byte:Some(node.start_byte()),end_byte:Some(node.end_byte())}],
            file.clone(), std::sync::Arc::from(parsed.source()), Some(parsed.tree().clone()),
        );
        let outcome = outcomes
            .pop()
            .expect("one model type request has one outcome");
        let snapshot = self.analyzer.active_semantic_model_snapshot();
        let symbol = if outcome.status == DefinitionLookupStatus::UnresolvableImportBoundary {
            let cancellation = self
                .analyzer
                .active_query_cancellation()
                .unwrap_or_default();
            let super::call_conversion::selected_type::ExternalRoute::Selected(route) =
                super::call_conversion::selected_type::selected_external_route(
                    self.analyzer,
                    file,
                    &std::sync::Arc::from(parsed.source()),
                    selected_node,
                    &cancellation,
                )
            else {
                return Ok(SelectedTypeProofRead::Unavailable);
            };
            let overlay = snapshot
                .as_ref()
                .and_then(|s| s.semantic_model_overlay())
                .map(std::sync::Arc::as_ref);
            let Some(symbol) = super::crate_identity::RustOverlayCrates::new(overlay)
                .referenceable_symbol_in_namespace(&route, RustReexportNamespace::TypeOrModule)
            else {
                return Ok(SelectedTypeProofRead::Unavailable);
            };
            symbol
        } else {
            if outcome.status != DefinitionLookupStatus::Resolved
                || !outcome.diagnostics.is_empty()
                || !outcome.definitions.is_empty()
                || outcome.lexical_definition.is_some()
            {
                return Ok(SelectedTypeProofRead::Unavailable);
            }
            let [symbol] = outcome.modeled_definitions.as_slice() else {
                return Ok(SelectedTypeProofRead::Unavailable);
            };
            std::sync::Arc::clone(symbol)
        };
        if !matches!(
            symbol.kind,
            SemanticModelSymbolKind::Struct
                | SemanticModelSymbolKind::Enum
                | SemanticModelSymbolKind::Union
                | SemanticModelSymbolKind::TypeAlias
        ) {
            return Ok(SelectedTypeProofRead::Unavailable);
        }
        Ok(SelectedTypeProofRead::Available(SelectedTypeOwner::Model(
            ModelSymbolRef {
                symbol_id: symbol.id.clone(),
                provider: ModelProvider::from(&symbol.provenance),
            },
        )))
    }
    fn prelude_type(
        &self,
        file: &ProjectFile,
        name: &str,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<SelectedTypeProofRead<bool>> {
        let scope = AnalyzerQueryScope::new(self.analyzer);
        Ok(
            match brokk_bifrost_rust::graph_support::reference_context_of(
                self.rust_analyzer(),
                scope.token(),
                file,
            )
            .implicit_prelude_contains_type(name)
            {
                Ok(contains) => SelectedTypeProofRead::Available(contains),
                Err(_) => SelectedTypeProofRead::Unavailable,
            },
        )
    }
    fn standard_type_root(
        &self,
        file: &ProjectFile,
        name: &str,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<SelectedTypeProofRead<bool>> {
        let Ok(routes) = self.rust_analyzer().file_routes(file, None) else {
            return Ok(SelectedTypeProofRead::Unavailable);
        };
        if !routes.is_complete() {
            return Ok(SelectedTypeProofRead::Unavailable);
        }
        if routes.type_root_identity(file, name).is_some() {
            return Ok(SelectedTypeProofRead::Unavailable);
        }
        let prelude_type = match name {
            "std" => "String",
            "core" => "Option",
            _ => return Ok(SelectedTypeProofRead::Available(false)),
        };
        let scope = AnalyzerQueryScope::new(self.analyzer);
        let context = brokk_bifrost_rust::graph_support::reference_context_of(
            self.rust_analyzer(),
            scope.token(),
            file,
        );
        Ok(match context.implicit_prelude_contains_type(prelude_type) {
            Ok(contains) => SelectedTypeProofRead::Available(contains),
            Err(_) => SelectedTypeProofRead::Unavailable,
        })
    }

    fn external_type_root(
        &self,
        file: &ProjectFile,
        name: &str,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<SelectedExternalTypeRootRead> {
        Ok(match self.rust_analyzer().file_routes(file, None) {
            Ok(routes) if routes.is_complete() => {
                SelectedTypeProofRead::Available(routes.type_root_identity(file, name))
            }
            _ => SelectedTypeProofRead::Unavailable,
        })
    }

    fn type_declaration(
        &self,
        file: &ProjectFile,
        range: std::ops::Range<usize>,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<SelectedTypeProofRead<CodeUnit>> {
        let scope = AnalyzerQueryScope::new(self.analyzer);
        let Some(parsed) = self.rust_analyzer().prepared_syntax(scope.token(), file) else {
            return Ok(SelectedTypeProofRead::Unavailable);
        };
        let mut outcomes = brokk_bifrost_analysis::analyzer::usages::get_definition::resolve_definition_batch_with_source_tree(
            self.analyzer,
            vec![DefinitionLookupRequest {
                file: file.clone(),
                line: None,
                column: None,
                start_byte: Some(range.start),
                end_byte: Some(range.end),
            }],
            file.clone(),
            std::sync::Arc::from(parsed.source()),
            Some(parsed.tree().clone()),
        );
        let outcome = outcomes
            .pop()
            .expect("one declaration request has one outcome");
        if outcome.status != DefinitionLookupStatus::Resolved || !outcome.diagnostics.is_empty() {
            return Ok(SelectedTypeProofRead::Unavailable);
        }
        let mut definitions = outcome.definitions;
        definitions.sort_by_key(|unit| unit.declaration_id());
        definitions.dedup_by(|left, right| left.declaration_id() == right.declaration_id());
        Ok(match definitions.as_slice() {
            [unit] => SelectedTypeProofRead::Available(unit.clone()),
            _ => SelectedTypeProofRead::Unavailable,
        })
    }

    fn operator_candidate_files(
        &self,
        trait_name: &str,
        _cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<
        SelectedTypeProofRead<
            brokk_bifrost_analysis::analyzer::store::language_support::SelectedOperatorCandidates,
        >,
    > {
        let Some(spellings) = super::trait_applicability::workspace_trait_spellings(
            self.analyzer,
            self.rust_analyzer(),
            trait_name,
        ) else {
            return Ok(SelectedTypeProofRead::Unavailable);
        };
        let mut files = std::collections::HashSet::new();
        let live = self.rust_analyzer().live_blobs();
        for spelling in &spellings {
            if super::trait_applicability::macro_may_name_trait(self.rust_analyzer(), spelling)
                != Some(false)
            {
                return Ok(SelectedTypeProofRead::Unavailable);
            }
            let Ok(rows) = self
                .rust_analyzer()
                .rust_unresolved_trait_impl_files(spelling)
            else {
                return Ok(SelectedTypeProofRead::Unavailable);
            };
            for row in rows {
                files.extend(live.paths_for_oid(row.impl_blob));
            }
        }
        Ok(SelectedTypeProofRead::Available(
            brokk_bifrost_analysis::analyzer::store::language_support::SelectedOperatorCandidates {
                files: files.into_iter().collect(),
                spellings: spellings.into_iter().collect(),
            },
        ))
    }

    fn named_reason(
        &self,
        _: brokk_bifrost_analysis::analyzer::resolution::SemanticId,
    ) -> Option<(&'static str, std::sync::Arc<str>)> {
        None
    }
    fn cached_external_type_import_paths(
        &self,
        _: brokk_bifrost_analysis::analyzer::resolution::SemanticId,
    ) -> Vec<Vec<String>> {
        Vec::new()
    }
    fn external_type_import_path(
        &mut self,
        _: brokk_bifrost_analysis::analyzer::resolution::SemanticId,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<Option<Vec<String>>> {
        Ok(None)
    }
}
