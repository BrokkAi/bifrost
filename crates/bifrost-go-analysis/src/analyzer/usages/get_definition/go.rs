use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::QueryScope;
use brokk_bifrost_analysis::analyzer::common::language_for_file;
use brokk_bifrost_analysis::analyzer::lexical_definitions::LexicalDefinition;
use brokk_bifrost_analysis::analyzer::semantic::ResolverOwnedExternalCalleeIdentity;
use brokk_bifrost_analysis::analyzer::usages::get_definition::*;
use brokk_bifrost_analysis::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use brokk_bifrost_analysis::analyzer::usages::reference_site::ResolvedReferenceSite;
use brokk_bifrost_analysis::analyzer::workspace_authority::{CaptureScopedMemo, memo_attribution};
use brokk_bifrost_analysis::analyzer::{
    AnalyzerQueryScope, CodeUnit, DeclarationKind, IAnalyzer, ImportAnalysisProvider, ImportInfo,
    Language, ProjectFile, resolve_analyzer,
};
use brokk_bifrost_core::analyzer::definition_lookup::sort_units;
use brokk_bifrost_core::analyzer::usages::resolution_session::{
    BoundedResolution, ResolutionSession,
};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

use crate::analyzer::GoAnalyzer;
use crate::analyzer::go::type_identity_proof::go_result_type_nodes_with_scope;

use brokk_bifrost_go::references::GoSelectorDescriptor;

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use crate::analyzer::go::package_identity::GoModeledPackageCallResolution;

use crate::analyzer::go::package_identity::GoOverlayPackages;

use brokk_bifrost_analysis::analyzer::languages::package_fq_name;

use brokk_bifrost_analysis::analyzer::store::StoreError;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::go_named::GoExternalPackageProvenance;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::go_named::GoSelectedExternalImport;

use brokk_bifrost_core::analyzer::definition_lookup::DefinitionLanguageScope;

use brokk_bifrost_core::analyzer::model::DispatchExtensibility;

use brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadIncomplete;

use brokk_bifrost_core::analyzer::model::Range;

use brokk_bifrost_core::analyzer::definition_lookup::RelationalBatchOutcome;

use brokk_bifrost_core::analyzer::definition_lookup::RelationalDefinitionQuery;

use brokk_bifrost_core::analyzer::definition_lookup::RelationalDefinitionRequest;

use brokk_bifrost_core::analyzer::definition_lookup::RelationalDefinitionValue;

use brokk_bifrost_core::analyzer::model::SignatureMetadata;

use brokk_bifrost_core::analyzer::model::StructuredTypeIdentity;

use brokk_bifrost_core::analyzer::common::node_source_text_trimmed as go_node_text;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::tree_walk::{parent_if_field, root_node};
use brokk_bifrost_core::analyzer::usages::common::same_node;
use brokk_bifrost_core::analyzer::{PackageRelationKind, PackageRelationValue, RelationalName};
use brokk_bifrost_go::packages::go_internal_import_allowed;
use brokk_bifrost_go::references::go_name_shadowed_at_with_scope;
use tree_sitter::Tree;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GoWorkspacePackageStatus {
    Present,
    Absent,
    /// The exact package-membership query did not complete.
    Unknown,
}

pub(crate) trait GoDefinitionProvider {
    fn fqn(&self, fqn: &str) -> Vec<CodeUnit>;
    fn workspace_package_status(&self, import_path: &str) -> GoWorkspacePackageStatus;
    fn workspace_declaration_identities_authoritative(&self) -> bool;
    fn workspace_package_inventory_complete(&self) -> bool {
        false
    }
    fn import_infos(
        &self,
        token: QueryToken<'_>,
        go: &GoAnalyzer,
        file: &ProjectFile,
    ) -> Vec<ImportInfo> {
        ResolutionSession::query_limited_rows_with_optional_session(
            self.session(),
            |limit| go.import_info_limited(token, file, limit),
            || go.import_info_of(token, file),
        )
    }
    fn signature_metadata(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
    ) -> Vec<SignatureMetadata> {
        analyzer.signature_metadata(unit)
    }
    fn scope_step(&self) -> bool {
        true
    }
    fn session(&self) -> Option<&ResolutionSession> {
        None
    }

    fn result_shape_execution_stopped(&self) -> bool {
        self.session()
            .is_some_and(|session| !session.observe_cancellation())
    }

    fn external_import_name(&self, _import_path: &str) -> Option<String> {
        None
    }

    /// Positive declaration evidence for one package-qualified call target.
    /// `None` means the activated overlay cannot identify the selected name.
    fn external_package_call_resolution(
        &self,
        _import_path: &str,
        _member: &str,
        _parameter_count: usize,
    ) -> Option<GoModeledPackageCallResolution> {
        None
    }

    fn selected_call_result_count(
        &self,
        _token: QueryToken<'_>,
        _file: &ProjectFile,
        _source: &str,
        _callee: Node<'_>,
        _argument_count: usize,
    ) -> Option<usize> {
        None
    }

    fn external_package_member_is_published(&self, _import_path: &str, _member: &str) -> bool {
        false
    }

    /// Exact visible declaration identity for one structured package member.
    /// Go declaration packs may store package variables and constants below a
    /// synthetic module-scope owner, so this lookup must consider both exact
    /// storage names without choosing through ambiguity.
    fn external_visible_package_member(&self, _import_path: &str, _member: &str) -> Option<String> {
        None
    }
}

#[derive(Hash, PartialEq, Eq)]
struct GoNestedCallKey {
    file: ProjectFile,
    callee_start: usize,
    callee_end: usize,
    argument_count: usize,
}

pub(crate) struct AnalyzerGoDefinitionProvider<'a> {
    analyzer: &'a GoAnalyzer,
    session: Option<&'a ResolutionSession>,
    semantic_model_overlay: Option<
        std::sync::Arc<
            brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay,
        >,
    >,
    native_budget: ReceiverAnalysisBudget,
    nested_session: std::cell::RefCell<Option<ResolutionSession>>,
    nested_counts: CaptureScopedMemo<std::cell::RefCell<HashMap<GoNestedCallKey, Option<usize>>>>,
}

impl<'a> AnalyzerGoDefinitionProvider<'a> {
    pub(crate) fn new(
        analyzer: &'a GoAnalyzer,
        semantic_model_overlay: Option<
            std::sync::Arc<
                brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay,
            >,
        >,
    ) -> Self {
        Self {
            analyzer,
            session: None,
            semantic_model_overlay,
            native_budget: ReceiverAnalysisBudget::default(),
            nested_session: std::cell::RefCell::new(None),
            nested_counts: CaptureScopedMemo::default(),
        }
    }

    pub(crate) fn bounded(
        analyzer: &'a GoAnalyzer,
        session: &'a ResolutionSession,
        semantic_model_overlay: Option<
            std::sync::Arc<
                brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay,
            >,
        >,
    ) -> Self {
        Self {
            analyzer,
            session: Some(session),
            semantic_model_overlay,
            native_budget: ReceiverAnalysisBudget::default(),
            nested_session: std::cell::RefCell::new(None),
            nested_counts: CaptureScopedMemo::default(),
        }
    }
}

fn go_request_cancellation(
    support: &dyn GoDefinitionProvider,
    go: &GoAnalyzer,
) -> CancellationToken {
    support
        .session()
        .and_then(ResolutionSession::cancellation)
        .cloned()
        .or_else(|| go.active_query_cancellation())
        .unwrap_or_default()
}

impl AnalyzerGoDefinitionProvider<'_> {
    fn selected_model_result_count_from_resolution(
        &self,
        file: &ProjectFile,
        value: &crate::analyzer::go::native_points::GoNativeDefinitionResolution,
        cancellation: &CancellationToken,
        argument_count: usize,
    ) -> Option<usize> {
        use brokk_bifrost_analysis::analyzer::semantic_model::overlay::{
            ModelProvider, ModelProviderSelection, ModelSymbolRef, SemanticModelCallApplication,
            SemanticModelCallableDisposition as Disposition,
            SemanticModelCallableIncompleteReason as Incomplete, SemanticModelCallableKey,
        };
        let overlay = self.semantic_model_overlay.as_deref()?;
        let selected = if let Some(selection) = value.model_member_selection.as_deref() {
            let mut candidates = selection
                .candidates
                .iter()
                .filter(|candidate| candidate.selected && !candidate.rejected);
            let candidate = candidates.next()?;
            if candidates.next().is_some() {
                return None;
            }
            (candidate.member.clone(), candidate.declaration.clone())
        } else {
            let proof = value.exact_external_call.as_ref();
            let identity = value.external_callee_identity.as_ref()?;
            let application_kind =
                proof.map_or(value.call_application, |proof| proof.call_application());
            let has_receiver = match application_kind {
                CallApplicationKind::BoundReceiver => true,
                CallApplicationKind::PackageFunction => false,
                _ => return None,
            };
            let key = SemanticModelCallableKey::new(
                "go",
                identity.owner_fqn(),
                identity.member(),
                has_receiver,
                u32::try_from(argument_count).ok()?,
            );
            let matched =
                brokk_bifrost_analysis::analyzer::semantic_model::selected_model_callable(
                    self.analyzer,
                    overlay,
                    key,
                    proof.and_then(|proof| proof.external_member_identity()),
                    &SemanticModelCallApplication::positional(u32::try_from(argument_count).ok()?),
                )?;
            // Go has one declaration per function name; a partial pack still
            // proves the arity of its single positive record.
            if !matches!(
                matched.disposition,
                Disposition::Unique | Disposition::Incomplete(Incomplete::PartialModel)
            ) {
                return None;
            }
            let [symbol] = matched.records.as_slice() else {
                return None;
            };
            (
                ModelSymbolRef {
                    symbol_id: symbol.id.clone(),
                    provider: ModelProvider::from(&symbol.provenance),
                },
                (**symbol).clone(),
            )
        };
        let (member, declaration) = selected;
        let signature = declaration.structured_signature.as_ref()?;
        if declaration.provenance.ambiguous
            || !signature.type_parameters.is_empty()
            || signature
                .parameters
                .iter()
                .enumerate()
                .any(|(index, parameter)| {
                    parameter.optional
                        || (parameter.variadic && index + 1 != signature.parameters.len())
                })
        {
            return None;
        }
        if let Some((results, _)) =
            crate::analyzer::go::type_identity_proof::go_selected_callable_result_type_identities(
                self.analyzer,
                file,
                &member,
                cancellation,
            )
        {
            return Some(results.len());
        }
        if cancellation.is_cancelled() {
            return None;
        }
        match overlay.model_callable_results(
            &member,
            &ModelProviderSelection::new([member.provider.clone()]),
            cancellation,
        ) {
            Ok(results) => results.map(|results| results.len()),
            Err(_) => None,
        }
    }
}

impl GoDefinitionProvider for AnalyzerGoDefinitionProvider<'_> {
    fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        let units: Vec<_> = match self.session {
            Some(session) => session.query_limited_rows(|limit| {
                self.analyzer
                    .declaration_candidates_by_fqn_limited(fqn, limit, || {
                        session.observe_cancellation()
                    })
            }),
            None => self.analyzer.definitions(fqn).collect(),
        };
        brokk_bifrost_core::analyzer::definition_lookup::sort_dedup_units(units)
    }

    fn workspace_package_status(&self, import_path: &str) -> GoWorkspacePackageStatus {
        match self.session {
            Some(session) => {
                let request = RelationalDefinitionRequest {
                    ordinal: 0,
                    language_scope: DefinitionLanguageScope::Language(Language::Go),
                    name: RelationalName::stable(package_fq_name(Language::Go, import_path)),
                    query: RelationalDefinitionQuery::PackageRelation(PackageRelationKind::Exists),
                };
                let uncancelled = CancellationToken::new();
                let cancellation = session.cancellation().unwrap_or(&uncancelled);
                let Some(outcome) = session.query(|| {
                    self.analyzer
                        .relational_definition_batch(&[request], cancellation)
                }) else {
                    return GoWorkspacePackageStatus::Unknown;
                };
                match outcome {
                    RelationalBatchOutcome::Complete(mut results) => {
                        assert_eq!(results.len(), 1, "package point query returns one result");
                        match results.remove(0).value {
                            RelationalDefinitionValue::PackageRelation(
                                PackageRelationValue::Exists(true),
                            ) => GoWorkspacePackageStatus::Present,
                            RelationalDefinitionValue::PackageRelation(
                                PackageRelationValue::Exists(false),
                            ) if self.analyzer.workspace_package_inventory_complete() => {
                                GoWorkspacePackageStatus::Absent
                            }
                            RelationalDefinitionValue::PackageRelation(
                                PackageRelationValue::Exists(false),
                            ) => GoWorkspacePackageStatus::Unknown,
                            value => panic!(
                                "package point query returned incompatible result: {value:#?}"
                            ),
                        }
                    }
                    RelationalBatchOutcome::Cancelled => {
                        session.observe_cancellation();
                        GoWorkspacePackageStatus::Unknown
                    }
                    RelationalBatchOutcome::Failed(error) => {
                        self.analyzer
                            .record_query_failure(StoreError::new(error.message()));
                        GoWorkspacePackageStatus::Unknown
                    }
                }
            }
            None => {
                let index = self.analyzer.workspace_path_index();
                if index.exact_package_exists(import_path) {
                    GoWorkspacePackageStatus::Present
                } else if index.is_complete() {
                    GoWorkspacePackageStatus::Absent
                } else {
                    GoWorkspacePackageStatus::Unknown
                }
            }
        }
    }

    fn workspace_declaration_identities_authoritative(&self) -> bool {
        self.analyzer
            .workspace_declaration_identities_authoritative()
    }

    fn workspace_package_inventory_complete(&self) -> bool {
        self.analyzer.workspace_package_inventory_complete()
    }

    fn signature_metadata(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
    ) -> Vec<SignatureMetadata> {
        ResolutionSession::query_limited_rows_with_optional_session(
            self.session,
            |limit| self.analyzer.signature_metadata_limited(unit, limit),
            || analyzer.signature_metadata(unit),
        )
    }

    fn scope_step(&self) -> bool {
        brokk_bifrost_analysis::analyzer::usages::get_definition::session_scope_step(self.session())
    }

    fn session(&self) -> Option<&ResolutionSession> {
        self.session
    }

    fn result_shape_execution_stopped(&self) -> bool {
        self.session
            .is_some_and(|session| !session.observe_cancellation())
            || self
                .nested_session
                .borrow()
                .as_ref()
                .is_some_and(|session| !session.observe_cancellation())
    }

    fn external_import_name(&self, import_path: &str) -> Option<String> {
        crate::analyzer::go::package_identity::GoOverlayPackages::new(
            self.semantic_model_overlay.as_deref(),
        )
        .declared_package_name(import_path)
    }

    fn external_package_call_resolution(
        &self,
        import_path: &str,
        member: &str,
        parameter_count: usize,
    ) -> Option<GoModeledPackageCallResolution> {
        crate::analyzer::go::package_identity::GoOverlayPackages::new(
            self.semantic_model_overlay.as_deref(),
        )
        .package_call_resolution(import_path, member, parameter_count)
    }

    fn selected_call_result_count(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
        source: &str,
        callee: Node<'_>,
        argument_count: usize,
    ) -> Option<usize> {
        let cancellation = go_request_cancellation(self, self.analyzer);
        if cancellation.is_cancelled() {
            return None;
        }
        let key = GoNestedCallKey {
            file: file.clone(),
            callee_start: callee.start_byte(),
            callee_end: callee.end_byte(),
            argument_count,
        };
        if let Some(count) = self
            .nested_counts
            .read(&memo_attribution(self.analyzer), |memo| {
                memo.borrow().get(&key).copied()
            })
        {
            return count;
        }
        let outer_session = self
            .session
            .filter(|session| session.remaining_budget().is_some());
        let using_nested_session = outer_session.is_none();
        if using_nested_session && self.nested_session.borrow().is_none() {
            *self.nested_session.borrow_mut() = Some(ResolutionSession::bounded(
                self.native_budget,
                Some(&cancellation),
            ));
        }
        let local_session = self.nested_session.borrow();
        let session = outer_session.or_else(|| local_session.as_ref())?;
        if !session.observe_cancellation() {
            return None;
        }
        let focused = callee.child_by_field_name("field").unwrap_or(callee);
        let site = ResolvedReferenceSite {
            path: brokk_bifrost_core::path_utils::rel_path_string(file),
            text: go_node_text(focused, source).into(),
            range: Range {
                start_byte: focused.start_byte(),
                end_byte: focused.end_byte(),
                start_line: focused.start_position().row + 1,
                end_line: focused.end_position().row + 1,
            },
            focus_start_byte: focused.start_byte(),
            focus_end_byte: focused.end_byte(),
        };
        let prepared = self.analyzer.prepared_result_shape_syntax(token, file);
        let tree = prepared
            .as_ref()
            .filter(|prepared| prepared.source() == source)
            .map(|prepared| prepared.tree());
        let answer =
            crate::analyzer::go::native_points::resolve_go_definition_with_evidence_bounded(
                brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery {
                    analyzer: self.analyzer,
                    file,
                    source,
                    tree,
                    site: &site,
                    budget: session.remaining_budget().unwrap_or(self.native_budget),
                    cancellation: Some(&cancellation),
                },
                || {},
            );
        let charged = session.charge_work(&answer.work());
        let value = match answer {
            BoundedResolution::Complete { value, .. } => value,
            BoundedResolution::Cancelled { .. } => return None,
            BoundedResolution::Unavailable { reason, .. } => {
                self.analyzer.record_query_incomplete(
                    QueryReadIncomplete::SemanticEvidenceUnavailable(reason.into()),
                );
                return None;
            }
            BoundedResolution::Exceeded { limit, .. } => {
                session.mark_exceeded(limit);
                if using_nested_session {
                    self.analyzer.record_query_incomplete(
                        QueryReadIncomplete::SemanticEvidenceUnavailable(
                            "Go call result-shape work limit exceeded".into(),
                        ),
                    );
                }
                return None;
            }
        };
        if !charged {
            if using_nested_session {
                self.analyzer.record_query_incomplete(
                    QueryReadIncomplete::SemanticEvidenceUnavailable(
                        "Go call result-shape work limit exceeded".into(),
                    ),
                );
            }
            return None;
        }
        let result = value.selected_callable_result_count.or_else(|| {
            self.selected_model_result_count_from_resolution(
                file,
                &value,
                &cancellation,
                argument_count,
            )
        });
        if !cancellation.is_cancelled() {
            self.nested_counts
                .read(&memo_attribution(self.analyzer), |memo| {
                    memo.borrow_mut().insert(key, result);
                });
        }
        result
    }

    fn external_package_member_is_published(&self, import_path: &str, member: &str) -> bool {
        crate::analyzer::go::package_identity::GoOverlayPackages::new(
            self.semantic_model_overlay.as_deref(),
        )
        .publishes_any_member_fact(import_path, member)
    }

    fn external_visible_package_member(&self, import_path: &str, member: &str) -> Option<String> {
        crate::analyzer::go::package_identity::GoOverlayPackages::new(
            self.semantic_model_overlay.as_deref(),
        )
        .visible_member(import_path, member)
        .map(|symbol| symbol.qualified_name.clone())
    }
}

fn go_smallest_named_node_covering<'tree>(
    support: &dyn GoDefinitionProvider,
    node: Node<'tree>,
    start: usize,
    end: usize,
) -> Option<Node<'tree>> {
    brokk_bifrost_core::analyzer::usages::reference_site::smallest_named_node_covering_with_scope(
        node,
        start,
        end,
        || support.scope_step(),
    )
}

fn go_fqn_candidates(
    support: &dyn GoDefinitionProvider,
    fqns: impl IntoIterator<Item = String>,
) -> Vec<CodeUnit> {
    brokk_bifrost_core::analyzer::definition_lookup::collect_fqn_candidates(fqns, |fqn| {
        support.fqn(fqn)
    })
}

/// Memoized on exact source bytes (#2679): the package-selector chain probe
/// re-reads and re-parses the same package variable files once per
/// occurrence.
static GO_TREES: brokk_bifrost_analysis::analyzer::usages::get_definition::TreeParseMemo =
    brokk_bifrost_analysis::analyzer::usages::get_definition::TreeParseMemo::new();

#[doc(hidden)]
pub fn parse_go_tree(source: &str) -> Option<Tree> {
    GO_TREES.parse(source, brokk_bifrost_go::parse::parse_go)
}

/// A parser abort is operational; a recovered tree remains ordinary syntax.
pub(crate) fn parse_go_tree_for_proof(analyzer: &dyn IAnalyzer, source: &str) -> Option<Tree> {
    let tree = parse_go_tree(source);
    if tree.is_none() {
        analyzer.record_query_incomplete(
            brokk_bifrost_analysis::analyzer::QueryReadIncomplete::SemanticEvidenceUnavailable(
                "Go proof parser did not produce a tree".into(),
            ),
        );
    }
    tree
}

/// Recover the complete result inventory of a call through a function
/// value whose callee is a plain identifier bound to an explicit function type.
///
/// The call resolver may leave a function-valued binding without dispatch
/// arms because its value flow is local rather than declaration-target based.
/// This adapter has a positive proof only when the identifier's nearest visible
/// binding declares an anonymous `func(...)` type or names a function type
/// declaration, and the requested result is the unshadowed predeclared `error`.
/// Every other callee abstains.
pub(crate) fn go_function_value_result_type_identities(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    range: Range,
    cancellation: &CancellationToken,
) -> Option<Vec<Option<StructuredTypeIdentity>>> {
    if file.declaration_language() != Language::Go || range.start_byte >= range.end_byte {
        return None;
    }
    if !go_application_proof_step(analyzer, cancellation) {
        return None;
    }
    let source = analyzer.indexed_source(file)?;
    if source.len() > 1024 * 1024 {
        analyzer.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceUnavailable(
            "Go application type source exceeds proof bound".into(),
        ));
        return None;
    }
    let tree = parse_go_tree_for_proof(analyzer, &source)?;
    let root = tree.root_node();
    let go = resolve_analyzer::<GoAnalyzer>(analyzer)?;
    let session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), Some(cancellation));
    let support =
        AnalyzerGoDefinitionProvider::bounded(go, &session, analyzer.semantic_model_overlay());
    let mut step = || go_application_proof_step(analyzer, cancellation) && support.scope_step();
    let mut node = brokk_bifrost_core::analyzer::usages::reference_site::smallest_named_node_covering_with_scope(
        root, range.start_byte, range.end_byte, &mut step,
    )?;
    while node.kind() != "call_expression" {
        if !step() {
            return None;
        }
        node = node.parent()?;
    }
    if node.has_error()
        || node.start_byte() != range.start_byte
        || node.end_byte() != range.end_byte
    {
        return None;
    }
    let function = node.child_by_field_name("function")?;
    if function.kind() == "identifier"
        && let Some(GoLocalBinding::Type(type_node)) = go_nearest_visible_binding_with_evaluation(
            &support,
            root,
            &source,
            go_node_text(function, &source),
            function.start_byte(),
            GoLexicalEvaluation::ordinary(),
        )
    {
        let declaration = type_node.parent()?;
        let mut binding = None;
        let mut cursor = declaration.walk();
        for child in declaration.named_children(&mut cursor) {
            if !support.scope_step() {
                return None;
            }
            if child.kind() == "identifier"
                && child.end_byte() <= type_node.start_byte()
                && go_node_text(child, &source) == go_node_text(function, &source)
                && binding.replace(child).is_some()
            {
                return None;
            }
        }
        return go_declared_application_result_identities(
            analyzer,
            file,
            &source,
            root,
            type_node,
            binding?,
            cancellation,
            &support,
        );
    }
    None
}

// Both recipients resolve the written application type from their binding;
// the selected body is evidence of callable identity, not a type substitute.
#[allow(clippy::too_many_arguments)]
fn go_declared_application_result_identities(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    type_node: Node<'_>,
    binding: Node<'_>,
    cancellation: &CancellationToken,
    support: &dyn GoDefinitionProvider,
) -> Option<Vec<Option<StructuredTypeIdentity>>> {
    if !go_application_proof_step(analyzer, cancellation) || !support.scope_step() {
        return None;
    }
    if type_node.kind() == "function_type" {
        return go_application_result_identities(
            analyzer,
            file,
            cancellation,
            type_node,
            root,
            source,
            support,
        );
    }
    let selected =
        match crate::analyzer::go::type_identity_proof::go_explicit_binding_application_type(
            analyzer,
            file,
            source,
            Range {
                start_byte: binding.start_byte(),
                end_byte: binding.end_byte(),
                start_line: binding.start_position().row + 1,
                end_line: binding.end_position().row + 1,
            },
            cancellation,
        ) {
            BoundedResolution::Complete { value, .. } => value,
            BoundedResolution::Exceeded { limit, .. } => {
                analyzer.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceUnavailable(
                    format!("Go explicit binding type resolution budget exceeded: {limit:?}")
                        .into(),
                ));
                return None;
            }
            BoundedResolution::Cancelled { .. } => {
                analyzer.record_query_incomplete(QueryReadIncomplete::Cancelled);
                return None;
            }
            BoundedResolution::Unavailable { reason, .. } => {
                analyzer.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceUnavailable(
                    reason.into(),
                ));
                return None;
            }
        };
    let nominal = selected.nominal?;
    let Some(receipt) = selected.application_source else {
        analyzer.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceUnavailable(
            "Go named application type lacks a selected declaration source receipt".into(),
        ));
        return None;
    };
    let type_source = receipt.source;
    let type_tree = parse_go_tree_for_proof(analyzer, &type_source)?;
    let type_root = type_tree.root_node();
    let mut step = || go_application_proof_step(analyzer, cancellation) && support.scope_step();
    let function_type = go_named_function_type_node(type_root, receipt.declaration, &mut step)?;
    if function_type.has_error() {
        return None;
    }
    go_application_result_identities(
        analyzer,
        nominal.source(),
        cancellation,
        function_type,
        type_root,
        &type_source,
        support,
    )
}

fn go_application_proof_step(analyzer: &dyn IAnalyzer, cancellation: &CancellationToken) -> bool {
    if cancellation.is_cancelled() {
        analyzer.record_query_incomplete(QueryReadIncomplete::Cancelled);
        false
    } else {
        true
    }
}

/// Read the application type from the certified source and lexical declaration.
/// The declaration range is authoritative; this path never searches for a
/// replacement binder by spelling.
pub(crate) fn go_bound_function_value_result_type_identities(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    exact_source: &str,
    range: Range,
    binding: &LexicalDefinition,
    callable_range: Range,
    cancellation: &CancellationToken,
) -> Option<Vec<Option<StructuredTypeIdentity>>> {
    if file.declaration_language() != Language::Go
        || range.start_byte >= range.end_byte
        || binding
            .source_file
            .as_ref()
            .is_some_and(|source| source != file)
        || !go_application_proof_step(analyzer, cancellation)
    {
        return None;
    }
    let source = analyzer.indexed_source(file)?;
    if source != exact_source {
        return None;
    }
    if source.len() > 1024 * 1024 {
        analyzer.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceUnavailable(
            "Go application type source exceeds proof bound".into(),
        ));
        return None;
    }
    let tree = parse_go_tree_for_proof(analyzer, &source)?;
    let root = tree.root_node();
    let go = resolve_analyzer::<GoAnalyzer>(analyzer)?;
    let session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), Some(cancellation));
    let support =
        AnalyzerGoDefinitionProvider::bounded(go, &session, analyzer.semantic_model_overlay());
    let mut step = || go_application_proof_step(analyzer, cancellation) && support.scope_step();
    let mut call = brokk_bifrost_core::analyzer::usages::reference_site::smallest_named_node_covering_with_scope(
        root, range.start_byte, range.end_byte, &mut step,
    )?;
    while call.kind() != "call_expression" {
        if !step() {
            return None;
        }
        call = call.parent()?;
    }
    let function = call.child_by_field_name("function")?;
    if call.has_error()
        || call.start_byte() != range.start_byte
        || call.end_byte() != range.end_byte
        || function.kind() != "identifier"
        || go_node_text(function, &source) != binding.identifier
    {
        return None;
    }
    let declaration = brokk_bifrost_core::analyzer::tree_walk::node_for_exact_range_with_step(
        root,
        &binding.declaration_range,
        &mut step,
    )?;
    let binder = brokk_bifrost_core::analyzer::tree_walk::node_for_exact_range_with_step(
        declaration,
        &binding.name_range,
        &mut step,
    )?;
    if binder.kind() != "identifier"
        || go_node_text(binder, &source) != binding.identifier
        || binder.end_byte() > function.start_byte()
    {
        return None;
    }
    let initializer = brokk_bifrost_core::analyzer::tree_walk::node_for_exact_range_with_step(
        declaration,
        &callable_range,
        &mut step,
    )?;
    if initializer.kind() != "func_literal" {
        return None;
    }
    let mut owner = binder.parent()?;
    while owner.kind() != "var_spec" {
        if !step() || owner == declaration {
            return None;
        }
        owner = owner.parent()?;
    }
    if owner.start_byte() < declaration.start_byte() || owner.end_byte() > declaration.end_byte() {
        return None;
    }
    let type_node = owner.child_by_field_name("type")?;
    go_declared_application_result_identities(
        analyzer,
        file,
        &source,
        root,
        type_node,
        binder,
        cancellation,
        &support,
    )
}

fn go_application_result_identities(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    cancellation: &CancellationToken,
    function_type: Node<'_>,
    root: Node<'_>,
    source: &str,
    support: &dyn GoDefinitionProvider,
) -> Option<Vec<Option<StructuredTypeIdentity>>> {
    let mut step = || go_application_proof_step(analyzer, cancellation) && support.scope_step();
    let result_types = go_result_type_nodes_with_scope(function_type, &mut step)?;
    let mut identities = Vec::with_capacity(result_types.len());
    for result_type in result_types {
        if !go_application_proof_step(analyzer, cancellation) || !support.scope_step() {
            return None;
        }
        let identity = if go_node_text(result_type, source).trim() == "error"
            && crate::analyzer::go::type_identity_proof::go_predeclared_type_name_is_exact_bounded(
                analyzer,
                file,
                source,
                root,
                result_type,
                "error",
                || go_application_proof_step(analyzer, cancellation) && support.scope_step(),
            ) == Some(true)
        {
            brokk_bifrost_go::declarations::go_structured_type_identity_bounded(
                result_type,
                source,
                || go_application_proof_step(analyzer, cancellation) && support.scope_step(),
            )
        } else {
            None
        };
        identities.push(identity);
    }
    go_application_proof_step(analyzer, cancellation).then_some(identities)
}

fn go_named_function_type_node<'tree>(
    root: Node<'tree>,
    declaration: Range,
    scope_step: &mut dyn FnMut() -> bool,
) -> Option<Node<'tree>> {
    let mut stack = vec![root];
    let mut found = None;
    while let Some(node) = stack.pop() {
        if !scope_step() {
            return None;
        }
        if node.kind() == "type_spec"
            && node.start_byte() == declaration.start_byte
            && node.end_byte() == declaration.end_byte
        {
            let type_node = node.child_by_field_name("type")?;
            if found.replace(type_node).is_some() {
                return None;
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if !scope_step() {
                return None;
            }
            stack.push(child);
        }
    }
    found.filter(|type_node| type_node.kind() == "function_type")
}

struct GoCallEvidence {
    application: CallApplicationKind,
    dispatch_extensibility: Option<DispatchExtensibility>,
    exact_external_call: Option<ExactExternalCallProof>,
    external_callee_identity: Option<ResolverOwnedExternalCalleeIdentity>,
}

impl GoCallEvidence {
    fn record_exact_external_call(&mut self, proof: ExactExternalCallProof) {
        self.application = proof.call_application();
        self.dispatch_extensibility = proof.dispatch_extensibility();
        self.exact_external_call = Some(proof);
    }

    fn record_external_identity(&mut self, owner_fqn: &str, member: &str) {
        brokk_bifrost_analysis::analyzer::usages::get_definition::record_external_member_identity(
            &mut self.external_callee_identity,
            Language::Go,
            owner_fqn,
            member,
        );
    }
}

/// Preserve the canonical import path and member after the structured Go
/// resolver proves that a package selector crosses the workspace boundary.
///
/// The generic boundary constructor deliberately carries no reference because
/// most callers only know a source spelling. Here the import binder has already
/// mapped that spelling (including aliases) to `import_path`, and the selector
/// has identified the exact member. Keeping that evidence lets downstream
/// semantic-model lookup distinguish `os.Open` from a local value named `os`
/// without reparsing source text.
fn go_imported_member_boundary(
    site: &ResolvedReferenceSite,
    import_path: &str,
    member: &str,
    workspace_status: GoWorkspacePackageStatus,
    boundary_message: String,
    no_definition_message: impl Into<String>,
    call_evidence: &mut GoCallEvidence,
) -> DefinitionLookupOutcome {
    let mut outcome = go_workspace_package_boundary(
        import_path,
        workspace_status,
        boundary_message,
        "no_indexed_definition",
        no_definition_message,
    );
    if outcome.status == DefinitionLookupStatus::UnresolvableImportBoundary {
        call_evidence.record_external_identity(import_path, member);
        let mut reference = site.clone();
        reference.text = format!("{import_path}.{member}");
        outcome.reference = Some(reference);
    }
    outcome
}

fn go_workspace_package_boundary(
    import_path: &str,
    workspace_status: GoWorkspacePackageStatus,
    boundary_message: String,
    no_definition_kind: impl Into<String>,
    no_definition_message: impl Into<String>,
) -> DefinitionLookupOutcome {
    match workspace_status {
        GoWorkspacePackageStatus::Present => {
            no_definition(no_definition_kind, no_definition_message)
        }
        GoWorkspacePackageStatus::Absent => boundary_unchecked(
            boundary_message,
            UnindexedClaim::external_boundary(import_path, ClaimSubjectRole::Module),
        ),
        GoWorkspacePackageStatus::Unknown => go_workspace_package_status_unknown(import_path),
    }
}

fn go_workspace_package_status_unknown(import_path: &str) -> DefinitionLookupOutcome {
    no_definition(
        "go_workspace_package_status_unknown",
        format!(
            "workspace ownership of Go import path `{import_path}` is unavailable within this bounded resolution"
        ),
    )
}

pub(crate) fn go_method_is_interface_method(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    method: &CodeUnit,
) -> Option<bool> {
    if !method.is_function() || !method.owner_is_type_scope() {
        return None;
    }
    let mut has_receiver = None;
    for metadata in support.signature_metadata(analyzer, method) {
        if !support.scope_step() {
            return None;
        }
        let current = metadata.extension_receiver_type_identity().is_some();
        if has_receiver.is_some_and(|previous| previous != current) {
            return None;
        }
        has_receiver = Some(current);
    }
    has_receiver.map(|has_receiver| !has_receiver)
}

fn go_package_name(
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Option<Node<'_>>,
) -> Option<String> {
    if !support.workspace_declaration_identities_authoritative() {
        return None;
    }
    let declared = match root {
        Some(root) => {
            if !support.scope_step() {
                return None;
            }
            brokk_bifrost_go::declarations::try_determine_go_package_name(root, source, || {
                support.scope_step()
            })?
        }
        None if support.session().is_none() => parse_go_tree(source)
            .map(|tree| {
                brokk_bifrost_go::declarations::determine_go_package_name(tree.root_node(), source)
            })
            .unwrap_or_default(),
        None => return None,
    };
    Some(brokk_bifrost_go::packages::canonical_go_package_name(
        file, &declared,
    ))
}

/// The file import names whose structured namespace has exactly one distinct
/// package identity. Invalid edits can bind one local alias to multiple paths;
/// those names remain represented by `go_definition_import_namespaces` but do
/// not carry exact package authority here.
fn go_import_paths(
    support: &dyn GoDefinitionProvider,
    token: QueryToken<'_>,
    go: &crate::analyzer::GoAnalyzer,
    file: &ProjectFile,
) -> HashMap<String, String> {
    go_definition_import_namespaces(support, token, go, file)
        .0
        .into_iter()
        .filter_map(|(local, packages)| {
            let [package] = packages.as_slice() else {
                return None;
            };
            Some((local, package.clone()))
        })
        .collect()
}

pub(crate) fn go_imported_package_at_range(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    start_byte: usize,
    end_byte: usize,
) -> Option<String> {
    let go = resolve_analyzer::<GoAnalyzer>(analyzer)?;
    let tree = parse_go_tree(source)?;
    let node = tree
        .root_node()
        .named_descendant_for_byte_range(start_byte, end_byte)?;
    if !matches!(node.kind(), "identifier" | "package_identifier") {
        return None;
    }
    let mut root = node;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    let support = AnalyzerGoDefinitionProvider::new(go, analyzer.semantic_model_overlay());
    let name = go_node_text(node, source);
    if go_nearest_visible_binding(&support, root, source, name, start_byte).is_some() {
        return None;
    }
    let scope = brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(analyzer);
    go_import_paths(&support, scope.token(), go, file).remove(name)
}

pub(crate) fn go_native_external_import_binding_resolution(
    query: brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery<'_>,
    go: &GoAnalyzer,
    session: &ResolutionSession,
    selected_import: &GoSelectedExternalImport,
) -> Option<DefinitionLookupOutcome> {
    let tree = query.tree?;
    let selector =
        brokk_bifrost_go::references::go_selector_descriptor(tree.root_node(), query.site)?;
    if selector.focus_segment != 0 {
        return None;
    }
    let support =
        AnalyzerGoDefinitionProvider::bounded(go, session, query.analyzer.semantic_model_overlay());
    let scope = AnalyzerQueryScope::new(query.analyzer);
    let import_spec = go_selected_external_import_spec(
        query,
        &support,
        scope.token(),
        selected_import,
        tree.root_node(),
        selector.base,
    )?;
    let identifier = go_node_text(selector.base, query.source);
    let binder = import_spec
        .child_by_field_name("name")
        .or_else(|| import_spec.child_by_field_name("path"))?;
    let range = |node: tree_sitter::Node<'_>| Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row + 1,
        end_line: node.end_position().row + 1,
    };
    let definition = LexicalDefinition {
        source_file: None,
        identifier: identifier.to_string(),
        kind: DeclarationKind::ImportAlias,
        name_range: range(binder),
        declaration_range: range(import_spec),
    };
    let mut outcome = lexical_definition_outcome(definition);
    outcome.reference = Some(query.site.clone());
    Some(outcome)
}

pub(crate) fn go_native_import_namespace_resolution(
    query: brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery<'_>,
    go: &GoAnalyzer,
    session: &ResolutionSession,
) -> Option<DefinitionLookupOutcome> {
    let tree = query.tree?;
    let selector =
        brokk_bifrost_go::references::go_selector_descriptor(tree.root_node(), query.site)?;
    if selector.focus_segment != 0
        || !matches!(selector.base.kind(), "identifier" | "package_identifier")
    {
        return None;
    }
    let support =
        AnalyzerGoDefinitionProvider::bounded(go, session, query.analyzer.semantic_model_overlay());
    let query_scope = AnalyzerQueryScope::new(query.analyzer);
    let token = query_scope.token();
    let alias = go_node_text(selector.base, query.source);
    if go_nearest_visible_binding(
        &support,
        tree.root_node(),
        query.source,
        alias,
        query.site.focus_start_byte,
    )
    .is_some()
    {
        return None;
    }
    let package = go_import_paths(&support, token, go, query.file).remove(alias)?;
    let workspace_status = go_workspace_package_status(&support, &package);
    let mut outcome = match workspace_status {
        GoWorkspacePackageStatus::Present => no_definition(
            "workspace_package_namespace",
            format!(
                "`{alias}` names a Go package in this workspace, not a single indexed declaration"
            ),
        ),
        GoWorkspacePackageStatus::Absent => go_workspace_package_boundary(
            &package,
            workspace_status,
            format!("`{package}` is outside this partial Go workspace analysis"),
            "no_indexed_definition",
            format!("`{alias}` is not indexed in Go package `{package}`"),
        ),
        GoWorkspacePackageStatus::Unknown => go_workspace_package_status_unknown(&package),
    };
    outcome.reference = Some(query.site.clone());
    Some(outcome)
}

pub(crate) fn go_native_external_dot_import_call_resolution(
    query: brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery<'_>,
    go: &GoAnalyzer,
    session: &ResolutionSession,
) -> Option<(
    DefinitionLookupOutcome,
    Option<ExactExternalCallProof>,
    CallApplicationKind,
    Option<ResolverOwnedExternalCalleeIdentity>,
)> {
    let tree = query.tree?;
    let root = tree.root_node();
    let support =
        AnalyzerGoDefinitionProvider::bounded(go, session, query.analyzer.semantic_model_overlay());
    let callable = go_smallest_named_node_covering(
        &support,
        root,
        query.site.focus_start_byte,
        query.site.focus_end_byte,
    )?;
    if !matches!(callable.kind(), "identifier" | "package_identifier")
        || go_call_for_callable(&support, callable).is_none()
    {
        return None;
    }
    let name = go_node_text(callable, query.source);
    if go_nearest_visible_binding(
        &support,
        root,
        query.source,
        name,
        query.site.focus_start_byte,
    )
    .is_some()
    {
        return None;
    }
    // Go universe identifiers take precedence over dot-imported package
    // members. Local bindings were checked above because they can shadow the
    // universe; a published model member cannot.
    if brokk_bifrost_go::diagnostics::is_predeclared_go_name(name) {
        return None;
    }
    let query_scope = AnalyzerQueryScope::new(query.analyzer);
    let token = query_scope.token();
    let dot_imports = go_dot_import_paths(go, &support, token, query.file);
    if dot_imports.is_empty() {
        return None;
    }
    let mut external_imports = Vec::new();
    for package in &dot_imports {
        match go_workspace_package_status(&support, package) {
            GoWorkspacePackageStatus::Present => {}
            GoWorkspacePackageStatus::Absent => external_imports.push(package.as_str()),
            GoWorkspacePackageStatus::Unknown => return None,
        }
    }
    if external_imports.is_empty() {
        return None;
    }
    if dot_imports.len() != 1 {
        return Some((
            boundary_unchecked(
                format!(
                    "dot-imported `{name}` is ambiguous across external packages {external_imports:?}"
                ),
                UnindexedClaim::external_boundary_many(external_imports, ClaimSubjectRole::Module),
            ),
            None,
            CallApplicationKind::PackageFunction,
            None,
        ));
    }

    let package = &dot_imports[0];
    let importer_package = go_package_name(&support, query.file, query.source, Some(root))?;
    let package_scope_candidates = go_package_member_candidates(&support, &importer_package, name);
    let model_publishes_member = support
        .external_visible_package_member(package, name)
        .is_some();
    if !package_scope_candidates.is_empty() {
        if model_publishes_member {
            if let Some(outcome) = go_dot_import_package_scope_conflict_outcome(
                &support,
                &importer_package,
                name,
                &external_imports,
            ) {
                return Some((outcome, None, CallApplicationKind::PackageFunction, None));
            }
        } else {
            return None;
        }
    }
    let mut evidence = GoCallEvidence {
        application: CallApplicationKind::PackageFunction,
        dispatch_extensibility: None,
        exact_external_call: None,
        external_callee_identity: None,
    };
    if let Some(parameter_count) = go_identifier_modeled_call_argument_count(
        &support,
        token,
        go,
        query.file,
        query.source,
        root,
        query.site,
    ) && let Some(outcome) = go_model_package_call_outcome(
        &support,
        query.site,
        package,
        name,
        parameter_count,
        &mut evidence,
    ) {
        return Some((
            outcome,
            evidence.exact_external_call,
            evidence.application,
            evidence.external_callee_identity,
        ));
    }

    if let Some(outcome) =
        go_model_published_member_call_shape_outcome(&support, query.site, package, name)
    {
        evidence.record_external_identity(package, name);
        return Some((
            outcome,
            None,
            evidence.application,
            evidence.external_callee_identity,
        ));
    }
    let outcome = go_imported_member_boundary(
        query.site,
        package,
        name,
        GoWorkspacePackageStatus::Absent,
        format!("`{package}` is outside this partial Go workspace analysis"),
        format!("`{package}.{name}` has no activated exact Go call model"),
        &mut evidence,
    );
    Some((
        outcome,
        None,
        evidence.application,
        evidence.external_callee_identity,
    ))
}

pub(crate) fn go_definition_import_namespaces(
    support: &dyn GoDefinitionProvider,
    token: QueryToken<'_>,
    go: &GoAnalyzer,
    file: &ProjectFile,
) -> (HashMap<String, Vec<String>>, Vec<String>) {
    if support.session().is_some() {
        let mut aliases: HashMap<String, Vec<String>> = HashMap::default();
        let imports = support.import_infos(token, go, file);
        let mut dot_imports = Vec::new();
        for import in imports {
            let dot_import = import.alias.as_deref() == Some(".");
            let Some(import_path) = (if dot_import {
                go_dot_import_path(support, &import)
            } else {
                go_structured_import_path(support, &import)
            }) else {
                continue;
            };
            match import.alias.as_deref() {
                Some("_") => {}
                Some(".") => dot_imports.push(import_path),
                Some(explicit) => aliases
                    .entry(explicit.to_string())
                    .or_default()
                    .push(import_path),
                None => {
                    let local = support
                        .external_import_name(&import_path)
                        .or(import.identifier)
                        .filter(|local| !local.is_empty());
                    if let Some(local) = local {
                        aliases.entry(local).or_default().push(import_path);
                    }
                }
            }
        }
        for packages in aliases.values_mut() {
            packages.sort();
            packages.dedup();
        }
        dot_imports.sort();
        dot_imports.dedup();
        return (aliases, dot_imports);
    }

    let (mut aliases, dot_imports) = go.definition_import_namespaces(token, file);
    for import in go.import_info_of(token, file) {
        if import.alias.is_some() {
            continue;
        }
        let Some(path) = import.path.as_ref().filter(|path| {
            path.kind
                == Some(brokk_bifrost_core::analyzer::model::StructuredImportPathKind::Namespace)
                && !path.segments.is_empty()
        }) else {
            continue;
        };
        let import_path = path.render_segments("/");
        let Some(declared_name) = support
            .external_import_name(&import_path)
            .filter(|name| !name.is_empty() && !matches!(name.as_str(), "_" | "."))
        else {
            continue;
        };
        for packages in aliases.values_mut() {
            packages.retain(|package| package != &import_path);
        }
        aliases.retain(|_, packages| !packages.is_empty());
        aliases.entry(declared_name).or_default().push(import_path);
    }
    for packages in aliases.values_mut() {
        packages.sort();
        packages.dedup();
    }
    (aliases, dot_imports)
}

fn go_structured_import_path(
    support: &dyn GoDefinitionProvider,
    import: &ImportInfo,
) -> Option<String> {
    let path = import.path.as_ref()?;
    if path.kind != Some(brokk_bifrost_core::analyzer::model::StructuredImportPathKind::Namespace)
        || path.segments.is_empty()
    {
        return None;
    }
    for segment in &path.segments {
        if !support.scope_step() || segment.is_empty() {
            return None;
        }
    }
    Some(path.render_segments("/"))
}

fn go_workspace_package_status(
    support: &dyn GoDefinitionProvider,
    import_path: &str,
) -> GoWorkspacePackageStatus {
    support.workspace_package_status(import_path)
}

fn go_package_member_candidates(
    support: &dyn GoDefinitionProvider,
    package: &str,
    name: &str,
) -> Vec<CodeUnit> {
    go_fqn_candidates(
        support,
        [
            format!("{package}.{name}"),
            format!(
                "{package}.{}.{name}",
                brokk_bifrost_go::packages::GO_MODULE_SCOPE_SEGMENT
            ),
        ],
    )
}

fn go_unqualified_package_member_candidates(
    support: &dyn GoDefinitionProvider,
    token: QueryToken<'_>,
    go: &GoAnalyzer,
    file: &ProjectFile,
    package: &str,
    name: &str,
) -> Vec<CodeUnit> {
    let mut candidates = go_package_member_candidates(support, package, name);
    for import_path in go_dot_import_paths(go, support, token, file) {
        if !support.scope_step() {
            break;
        }
        candidates.extend(go_package_member_candidates(support, &import_path, name));
    }
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn go_native_external_package_member_resolution(
    query: brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery<'_>,
    go: &GoAnalyzer,
    session: &ResolutionSession,
    overlay: Option<
        Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
    >,
    selected_import: &GoSelectedExternalImport,
) -> Option<(
    DefinitionLookupOutcome,
    Option<ExactExternalCallProof>,
    CallApplicationKind,
    Option<ResolverOwnedExternalCalleeIdentity>,
)> {
    let tree = query.tree?;
    let selector =
        brokk_bifrost_go::references::go_selector_descriptor(tree.root_node(), query.site)?;
    if selector.focus_segment != 1
        || selector.members.len() != 1
        || !matches!(selector.base.kind(), "identifier" | "package_identifier")
    {
        return None;
    }
    let support = AnalyzerGoDefinitionProvider::bounded(go, session, overlay.clone());
    let scope = AnalyzerQueryScope::new(query.analyzer);
    go_selected_external_import_spec(
        query,
        &support,
        scope.token(),
        selected_import,
        tree.root_node(),
        selector.base,
    )?;
    let member = go_node_text(selector.focused_node(), query.source);
    let is_call_target = go_selector_is_call_target(&support, &selector);
    if is_call_target {
        let mut evidence = GoCallEvidence {
            application: CallApplicationKind::PackageFunction,
            dispatch_extensibility: None,
            exact_external_call: None,
            external_callee_identity: None,
        };
        let outcome = go_model_package_selector_outcome(
            &support,
            scope.token(),
            go,
            query.file,
            query.site,
            &selected_import.import_path,
            query.source,
            &selector,
            &mut evidence,
        );
        if let Some(outcome) = outcome {
            if outcome.status == DefinitionLookupStatus::UnresolvableImportBoundary {
                return Some((
                    outcome,
                    evidence.exact_external_call,
                    evidence.application,
                    evidence.external_callee_identity,
                ));
            }
            let proven_non_callable = outcome.status == DefinitionLookupStatus::NoDefinition
                && outcome.diagnostics.iter().any(|diagnostic| {
                    diagnostic.kind == GO_MODELED_PACKAGE_CALL_NOT_APPLICABLE_DIAGNOSTIC_KIND
                });
            if proven_non_callable {
                return Some((
                    outcome,
                    None,
                    evidence.application,
                    evidence.external_callee_identity,
                ));
            }
        }
        if let Some(outcome) = go_model_published_member_call_shape_outcome(
            &support,
            query.site,
            &selected_import.import_path,
            member,
        ) {
            evidence.record_external_identity(&selected_import.import_path, member);
            return Some((
                outcome,
                None,
                evidence.application,
                evidence.external_callee_identity,
            ));
        }
        // gated upstream: Go package discovery selected this source-less
        // import instance, so the package boundary is known even when its
        // semantic pack cannot prove this member's declaration or call shape.
        let outcome = go_imported_member_boundary(
            query.site,
            &selected_import.import_path,
            member,
            GoWorkspacePackageStatus::Absent,
            format!(
                "`{}` is a selected external Go package",
                selected_import.import_path
            ),
            format!(
                "`{}.{member}` has no activated exact Go call model",
                selected_import.import_path
            ),
            &mut evidence,
        );
        return Some((
            outcome,
            None,
            evidence.application,
            evidence.external_callee_identity,
        ));
    }

    let visible_member =
        support.external_visible_package_member(&selected_import.import_path, member);
    visible_member?;
    let canonical = format!("{}.{member}", selected_import.import_path);
    let mut reference = query.site.clone();
    reference.text = canonical.clone();
    let outcome = boundary_unchecked(
        format!("`{canonical}` is declared by an activated external Go model"),
        UnindexedClaim::resolved_external(canonical, ClaimSubjectRole::Member),
    );
    let mut outcome = outcome;
    outcome.reference = Some(reference);
    Some((outcome, None, CallApplicationKind::Unknown, None))
}

pub(crate) fn go_native_source_imported_member_resolution(
    query: brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery<'_>,
    go: &GoAnalyzer,
    session: &ResolutionSession,
    source_refusals: &[brokk_bifrost_analysis::analyzer::store::go_package_context::GoSourceImportRefusal],
) -> Option<(
    DefinitionLookupOutcome,
    Option<ExactExternalCallProof>,
    CallApplicationKind,
    Option<ResolverOwnedExternalCalleeIdentity>,
)> {
    let tree = query.tree?;
    let selector =
        brokk_bifrost_go::references::go_selector_descriptor(tree.root_node(), query.site)?;
    if selector.focus_segment != 1
        || selector.members.len() != 1
        || !matches!(selector.base.kind(), "identifier" | "package_identifier")
    {
        return None;
    }
    let overlay = query.analyzer.semantic_model_overlay();
    let support = AnalyzerGoDefinitionProvider::bounded(go, session, overlay.clone());
    let alias = go_node_text(selector.base, query.source);
    if go_name_shadowed_at_with_scope(
        tree.root_node(),
        query.source,
        selector.base.start_byte(),
        alias,
        || support.scope_step(),
    ) != Some(false)
    {
        return None;
    }
    let scope = AnalyzerQueryScope::new(query.analyzer);
    let import_path = go_import_paths(&support, scope.token(), go, query.file).remove(alias)?;
    if go_workspace_package_status(&support, &import_path) != GoWorkspacePackageStatus::Absent {
        return None;
    }
    if let Some(refusal) = source_refusals
        .iter()
        .find(|refusal| refusal.spelling == import_path)
    {
        use brokk_bifrost_analysis::analyzer::store::go_package_context::GoSourceImportRefusalReason;
        let message = match refusal.reason {
            GoSourceImportRefusalReason::RelativeImportInModuleMode => format!(
                "relative import `{import_path}` is forbidden by enclosing module manifest `{}`",
                refusal
                    .module_manifest
                    .as_deref()
                    .expect("module-mode refusal names its manifest")
            ),
            GoSourceImportRefusalReason::RelativeImportOutsideWorkspace => {
                format!("relative import `{import_path}` climbs above the workspace root")
            }
            GoSourceImportRefusalReason::SourcePackageDirectoryUnavailable => format!(
                "relative import `{import_path}` resolves to directory `{}` which holds no source package",
                refusal
                    .directory
                    .as_deref()
                    .expect("missing-package refusal has a directory")
            ),
            GoSourceImportRefusalReason::ConflictingSourcePackageNames => format!(
                "relative import `{import_path}` resolves to directory `{}` with conflicting declared package names {:?}",
                refusal
                    .directory
                    .as_deref()
                    .expect("conflicting-package refusal has a directory"),
                refusal.declared_names
            ),
        };
        // Gated upstream: selected publication records the exact local refusal.
        let mut outcome = boundary_unchecked_with_cause(
            String::new(),
            UnindexedClaim::external_boundary(&import_path, ClaimSubjectRole::Module),
            Some(ImportBoundaryCause { message }),
        );
        let mut reference = query.site.clone();
        reference.text = format!(
            "{import_path}.{}",
            go_node_text(selector.focused_node(), query.source)
        );
        outcome.reference = Some(reference);
        return Some((outcome, None, CallApplicationKind::Unknown, None));
    }
    if let Some(identity) =
        GoOverlayPackages::new(overlay.as_deref()).modeled_package_identity(&import_path)
    {
        let selected_import = GoSelectedExternalImport {
            source_spelling: import_path.clone(),
            import_path: import_path.clone(),
            package_name: identity.package_name,
            provenance: GoExternalPackageProvenance::SemanticModel {
                symbol_id: identity.symbol_id,
                pack_id: identity.pack_id,
                pack_digest: identity.pack_digest,
                record_id: identity.record_id,
            },
        };
        if let Some(resolution) = go_native_external_package_member_resolution(
            query,
            go,
            session,
            overlay.clone(),
            &selected_import,
        ) {
            return Some(resolution);
        }
    }
    let member = go_node_text(selector.focused_node(), query.source);
    let application = if go_selector_is_call_target(&support, &selector) {
        CallApplicationKind::PackageFunction
    } else {
        CallApplicationKind::Unknown
    };
    let mut evidence = GoCallEvidence {
        application,
        dispatch_extensibility: None,
        exact_external_call: None,
        external_callee_identity: None,
    };
    let outcome = go_imported_member_boundary(
        query.site,
        &import_path,
        member,
        GoWorkspacePackageStatus::Absent,
        format!("`{import_path}` is outside this partial Go workspace analysis"),
        format!("`{import_path}.{member}` has no activated exact Go call model"),
        &mut evidence,
    );
    Some((
        outcome,
        evidence.exact_external_call,
        evidence.application,
        evidence.external_callee_identity,
    ))
}

pub(crate) fn go_native_unmodeled_external_package_member_resolution(
    query: brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery<'_>,
    go: &GoAnalyzer,
    session: &ResolutionSession,
    overlay: Option<
        Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
    >,
    selected_imports: &[GoSelectedExternalImport],
) -> Option<(
    DefinitionLookupOutcome,
    Option<ExactExternalCallProof>,
    Option<ResolverOwnedExternalCalleeIdentity>,
)> {
    let tree = query.tree?;
    let selector =
        brokk_bifrost_go::references::go_selector_descriptor(tree.root_node(), query.site)?;
    if selector.focus_segment != 1
        || selector.members.len() != 1
        || !matches!(selector.base.kind(), "identifier" | "package_identifier")
    {
        return None;
    }
    let support = AnalyzerGoDefinitionProvider::bounded(go, session, overlay);
    let scope = AnalyzerQueryScope::new(query.analyzer);
    let identifier = go_node_text(selector.base, query.source);
    if go_name_shadowed_at_with_scope(
        tree.root_node(),
        query.source,
        selector.base.start_byte(),
        identifier,
        || support.scope_step(),
    ) != Some(false)
    {
        return None;
    }
    let import_path =
        go_import_paths(&support, scope.token(), go, query.file).remove(identifier)?;
    if selected_imports.iter().any(|selected| {
        selected.source_spelling == import_path || selected.import_path == import_path
    }) {
        return None;
    }
    if go_workspace_package_status(&support, &import_path) != GoWorkspacePackageStatus::Absent {
        return None;
    }

    let member = go_node_text(selector.focused_node(), query.source);
    let mut evidence = GoCallEvidence {
        application: CallApplicationKind::Unknown,
        dispatch_extensibility: None,
        exact_external_call: None,
        external_callee_identity: None,
    };
    let outcome = go_imported_member_boundary(
        query.site,
        &import_path,
        member,
        GoWorkspacePackageStatus::Absent,
        format!("`{import_path}` is outside this partial Go workspace analysis"),
        format!("`{import_path}.{member}` has no selected external package model"),
        &mut evidence,
    );
    Some((
        outcome,
        evidence.exact_external_call,
        evidence.external_callee_identity,
    ))
}

pub(crate) fn go_native_workspace_unqualified_call_resolution(
    query: brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery<'_>,
    session: &ResolutionSession,
) -> Option<DefinitionLookupOutcome> {
    let tree = query.tree?;
    let go = resolve_analyzer::<GoAnalyzer>(query.analyzer)?;
    let support =
        AnalyzerGoDefinitionProvider::bounded(go, session, query.analyzer.semantic_model_overlay());
    if !support.workspace_declaration_identities_authoritative()
        || !support.workspace_package_inventory_complete()
        || !go_identifier_is_call_target(&support, tree.root_node(), query.site)
        || go_nearest_visible_binding(
            &support,
            tree.root_node(),
            query.source,
            query.site.text.as_str(),
            query.site.focus_start_byte,
        )
        .is_some()
    {
        return None;
    }
    let package = go_package_name(&support, query.file, query.source, Some(tree.root_node()))?;
    let scope = AnalyzerQueryScope::new(query.analyzer);
    let dot_imports = go_dot_import_paths(go, &support, scope.token(), query.file);
    let mut dot_candidates = Vec::new();
    for import_path in &dot_imports {
        if go_workspace_package_status(&support, import_path) != GoWorkspacePackageStatus::Present {
            return None;
        }
        dot_candidates.extend(go_package_member_candidates(
            &support,
            import_path,
            &query.site.text,
        ));
    }
    dot_candidates.retain(|candidate| {
        brokk_bifrost_go::declarations::go_identifier_is_exported(candidate.identifier())
    });
    sort_units(&mut dot_candidates);
    dot_candidates.dedup();
    if !dot_candidates.is_empty() {
        let [target] = dot_candidates.as_slice() else {
            return None;
        };
        return target
            .is_function()
            .then(|| candidates_outcome(dot_candidates));
    }

    let candidates = go_package_member_candidates(&support, &package, &query.site.text);
    if !candidates.is_empty() {
        let [target] = candidates.as_slice() else {
            return None;
        };
        return target.is_function().then(|| candidates_outcome(candidates));
    }
    if brokk_bifrost_go::diagnostics::is_predeclared_go_name(&query.site.text) {
        return None;
    }
    let mut outcome = no_definition(
        GO_UNQUALIFIED_CALL_NO_TARGET_DIAGNOSTIC_KIND,
        format!(
            "`{}` has no declaration in the complete Go package or dot-import scope",
            query.site.text
        ),
    );
    outcome.reference = Some(query.site.clone());
    Some(outcome)
}
fn go_selected_external_import_spec<'tree>(
    query: brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery<'_>,
    support: &dyn GoDefinitionProvider,
    token: QueryToken<'_>,
    selected_import: &GoSelectedExternalImport,
    root: tree_sitter::Node<'tree>,
    base: tree_sitter::Node<'tree>,
) -> Option<tree_sitter::Node<'tree>> {
    if !selected_import.has_authoritative_provenance() {
        return None;
    }
    let identifier = go_node_text(base, query.source);
    if go_name_shadowed_at_with_scope(root, query.source, base.start_byte(), identifier, || {
        support.scope_step()
    }) != Some(false)
    {
        return None;
    }
    let go = resolve_analyzer::<GoAnalyzer>(query.analyzer)?;
    // Select the file-local namespace before filtering by provider. Filtering
    // first hides competing imports and lets each provider claim the alias.
    if go_import_paths(support, token, go, query.file)
        .get(identifier)
        .is_none_or(|path| path != &selected_import.source_spelling)
    {
        return None;
    }
    let imports = support.import_infos(token, go, query.file);
    let mut import_start = None;
    for import in imports {
        let import_path = go_structured_import_path(support, &import);
        if import_path.as_deref() != Some(selected_import.source_spelling.as_str()) {
            continue;
        }
        let bound_name = import
            .alias
            .as_deref()
            .unwrap_or(selected_import.package_name.as_str());
        if bound_name != identifier || matches!(bound_name, "_" | ".") {
            continue;
        }
        let declaration_start = import.path.as_ref()?.declaration_start_byte;
        if import_start.replace(declaration_start).is_some() {
            return None;
        }
    }
    let import_start = import_start?;
    let path_node =
        root.named_descendant_for_byte_range(import_start, import_start.checked_add(1)?)?;
    let mut import_spec = path_node;
    while import_spec.kind() != "import_spec" {
        let parent = import_spec.parent()?;
        import_spec = parent;
    }
    (import_spec.start_byte() == import_start).then_some(import_spec)
}

#[allow(clippy::too_many_arguments)]
fn go_model_package_selector_outcome(
    support: &dyn GoDefinitionProvider,
    token: QueryToken<'_>,
    go: &GoAnalyzer,
    file: &ProjectFile,
    site: &ResolvedReferenceSite,
    package: &str,
    source: &str,
    selector: &GoSelectorDescriptor<'_>,
    call_evidence: &mut GoCallEvidence,
) -> Option<DefinitionLookupOutcome> {
    if selector.focus_segment != 1 || selector.members.len() != 1 {
        return None;
    }
    let member = go_node_text(selector.focused_node(), source);
    let parameter_count =
        go_selector_modeled_call_argument_count(support, token, go, file, source, selector)?;
    go_model_package_call_outcome(
        support,
        site,
        package,
        member,
        parameter_count,
        call_evidence,
    )
}

fn go_model_published_member_call_shape_outcome(
    support: &dyn GoDefinitionProvider,
    site: &ResolvedReferenceSite,
    package: &str,
    member: &str,
) -> Option<DefinitionLookupOutcome> {
    support
        .external_package_member_is_published(package, member)
        .then(|| {
            let canonical_reference = format!("{package}.{member}");
            let mut outcome = no_definition(
                GO_MODELED_PACKAGE_CALL_UNPROVEN_DIAGNOSTIC_KIND,
                format!(
                    "`{canonical_reference}` is published by an activated Go model, but this call shape lacks exact applicability evidence"
                ),
            );
            let mut reference = site.clone();
            reference.text = canonical_reference;
            outcome.reference = Some(reference);
            outcome
        })
}

fn go_dot_import_package_scope_conflict_outcome(
    support: &dyn GoDefinitionProvider,
    importer_package: &str,
    member: &str,
    external_packages: &[&str],
) -> Option<DefinitionLookupOutcome> {
    if external_packages.len() != 1
        || go_package_member_candidates(support, importer_package, member).is_empty()
    {
        return None;
    }
    Some(boundary_unchecked(
        format!(
            "dot-imported `{member}` conflicts with a declaration in package `{importer_package}`"
        ),
        UnindexedClaim::external_boundary_many(
            external_packages.iter().copied(),
            ClaimSubjectRole::Module,
        ),
    ))
}

fn go_model_package_call_outcome(
    support: &dyn GoDefinitionProvider,
    site: &ResolvedReferenceSite,
    package: &str,
    member: &str,
    parameter_count: usize,
    call_evidence: &mut GoCallEvidence,
) -> Option<DefinitionLookupOutcome> {
    let resolution = support.external_package_call_resolution(package, member, parameter_count)?;
    let canonical_reference = format!("{package}.{member}");
    let mut outcome = match resolution {
        GoModeledPackageCallResolution::ExactFunction => {
            let parameter_count = u32::try_from(parameter_count).ok()?;
            call_evidence.record_exact_external_call(ExactExternalCallProof::go_package_function(
                canonical_reference.clone(),
                parameter_count,
            ));
            call_evidence.record_external_identity(package, member);
            go_external_model_member_outcome(&canonical_reference)
        }
        GoModeledPackageCallResolution::DefinitelyNotApplicable => no_definition(
            GO_MODELED_PACKAGE_CALL_NOT_APPLICABLE_DIAGNOSTIC_KIND,
            format!(
                "`{canonical_reference}` is published by an activated Go model but is not an exact package function with {parameter_count} argument{}",
                if parameter_count == 1 { "" } else { "s" }
            ),
        ),
        GoModeledPackageCallResolution::Unproven => no_definition(
            GO_MODELED_PACKAGE_CALL_UNPROVEN_DIAGNOSTIC_KIND,
            format!(
                "activated Go model records for `{canonical_reference}` do not prove one applicable package function"
            ),
        ),
    };
    let mut reference = site.clone();
    // A declaration overlay may prove a package member through an alternate
    // storage spelling such as the analyzer's synthetic module-scope owner.
    // Keep the canonical import-path/member identity supplied by the
    // structured import binder for dispatch and semantic summaries.
    reference.text = canonical_reference;
    outcome.reference = Some(reference);
    Some(outcome)
}

fn go_external_model_member_outcome(target: &str) -> DefinitionLookupOutcome {
    boundary_unchecked(
        format!("`{target}` is declared by an activated external Go model"),
        UnindexedClaim::resolved_external(target.to_string(), ClaimSubjectRole::Member),
    )
}

fn go_dot_import_paths(
    go: &crate::analyzer::GoAnalyzer,
    support: &dyn GoDefinitionProvider,
    token: QueryToken<'_>,
    file: &ProjectFile,
) -> Vec<String> {
    if support.session().is_none() {
        return go.definition_import_namespaces(token, file).1;
    }
    let imports = support.import_infos(token, go, file);
    go_dot_import_paths_from_imports(support, &imports)
}

fn go_dot_import_paths_from_imports(
    support: &dyn GoDefinitionProvider,
    imports: &[ImportInfo],
) -> Vec<String> {
    imports
        .iter()
        .filter_map(|import| go_dot_import_path(support, import))
        .collect()
}

fn go_dot_import_path(support: &dyn GoDefinitionProvider, import: &ImportInfo) -> Option<String> {
    (import.alias.as_deref() == Some("."))
        .then(|| go_structured_import_path(support, import))
        .flatten()
}

/// How a local binding names its type: an explicit `var x T` annotation, or the
/// value expression of an inferred `x := value` binding to derive it from. An
/// opaque binding still has exact lexical authority to shadow an import even
/// when this resolver has no useful type to infer for its value.
enum GoLocalBinding<'tree> {
    Type(Node<'tree>),
    Variadic,
    /// Multi-type, nil and default clauses retain the switch input's type.
    SwitchInput(Node<'tree>),
    Value,
    RangeElement,
    Opaque,
    /// A local type/type-parameter shadows the name without becoming a value.
    OpaqueType,
    /// An unsupported statement may declare either a type or a value.
    Unmodeled,
}

#[derive(Clone, Copy, Default)]
struct GoLexicalEvaluation;

impl GoLexicalEvaluation {
    fn ordinary() -> Self {
        Self
    }
    fn excludes_range_node(self, _node: Node<'_>) -> bool {
        false
    }
}

fn go_nearest_binding_in_scope_with_evaluation<'tree>(
    support: &dyn GoDefinitionProvider,
    scope: Node<'tree>,
    source: &str,
    name: &str,
    byte: usize,
    evaluation: GoLexicalEvaluation,
) -> Option<GoLocalBinding<'tree>> {
    if let Some(binding) = go_clause_binding(support, scope, source, name, byte) {
        return Some(binding);
    }
    // A function body's top-level statements share the parameter/result scope.
    // Inner blocks have no such owner and may shadow those names.
    let block = if scope.kind() == "statement_list" {
        scope.parent()
    } else {
        Some(scope)
    };
    let owner = block.and_then(|block| {
        block.parent().filter(|owner| {
            matches!(
                owner.kind(),
                "function_declaration" | "method_declaration" | "func_literal"
            ) && owner.child_by_field_name("body") == Some(block)
        })
    });
    let mut nearest = (scope.kind() == "statement_list")
        .then(|| scope.parent())
        .flatten()
        .and_then(|clause| {
            go_clause_binding(support, clause, source, name, byte)
                .map(|binding| (clause.start_byte(), binding))
        });
    if let Some(owner) = owner {
        let mut cursor = owner.walk();
        for child in owner.named_children(&mut cursor) {
            if !support.scope_step() {
                return None;
            }
            if matches!(child.kind(), "parameter_list" | "type_parameter_list")
                && let Some(binding) = go_parameter_list_binding(support, child, source, name)
            {
                nearest = Some((child.start_byte(), binding));
            }
        }

        if nearest.is_none()
            && owner.kind() == "method_declaration"
            && let Some(body) = owner.child_by_field_name("body")
            && brokk_bifrost_go::references::go_name_shadowed_at_with_scope(
                owner,
                source,
                body.start_byte(),
                name,
                || support.scope_step(),
            )?
        {
            nearest = Some((owner.start_byte(), GoLocalBinding::OpaqueType));
        }
    }
    let mut cursor = scope.walk();
    for child in scope.named_children(&mut cursor) {
        if !support.scope_step() {
            return None;
        }
        // Unlike if/switch initializers, a three-part for initializer is
        // nested in a for_clause. Inspect only that field, in the for's own
        // scope: its binding is visible in the condition, update and body,
        // but neither in its RHS nor after the enclosing statement.
        let child = if scope.kind() == "for_statement" && child.kind() == "for_clause" {
            let Some(initializer) = child.child_by_field_name("initializer") else {
                continue;
            };
            initializer
        } else {
            child
        };
        if child.end_byte() > byte {
            continue;
        }
        if evaluation.excludes_range_node(child) {
            continue;
        }
        // A label owns no lexical scope. Keep the wrapped declaration's byte
        // range and ordinary := rules, including through nested labels.
        let mut child = child;
        while child.kind() == "labeled_statement" {
            if !support.scope_step() {
                return None;
            }
            let statement = child.child_by_field_name("statement").or_else(|| {
                // tree-sitter-go 0.25 exposes the statement as an unnamed
                // child. Select it by grammar subtype, never by source text.
                let mut cursor = child.walk();
                child
                    .named_children(&mut cursor)
                    .find(|node| go_is_statement(*node))
            });
            let Some(statement) = statement else {
                return Some(GoLocalBinding::Unmodeled);
            };
            child = statement;
        }
        let binding = match child.kind() {
            "parameter_list" | "type_parameter_list" => {
                go_parameter_list_binding(support, child, source, name)
            }
            "type_declaration" if scope.kind() == "source_file" => None,
            "type_declaration" if scope.kind() != "source_file" => {
                let mut cursor = child.walk();
                child.named_children(&mut cursor).find_map(|spec| {
                    (matches!(spec.kind(), "type_spec" | "type_alias")
                        && go_declaration_has_name(support, spec, source, name))
                    .then_some(GoLocalBinding::OpaqueType)
                })
            }
            "type_spec" | "type_alias" if !go_spec_is_package_scoped(support, child)? => {
                go_declaration_has_name(support, child, source, name)
                    .then_some(GoLocalBinding::OpaqueType)
            }
            "short_var_declaration" => {
                // A multi-name := assigns a name already declared in this scope.
                // A single-name := must introduce its only name in valid Go.
                if nearest.is_some()
                    && child
                        .child_by_field_name("left")
                        .is_some_and(|left| left.named_child_count() > 1)
                {
                    None
                } else {
                    go_short_var_binding(support, child, source, name)
                }
            }
            "var_declaration" => go_var_declaration_binding(support, child, source, name),
            "var_spec" if !go_spec_is_package_scoped(support, child)? => {
                go_var_spec_binding(support, child, source, name)
            }
            "const_declaration" if scope.kind() == "source_file" => None,
            "const_declaration" if scope.kind() != "source_file" => {
                go_const_declaration_binding(support, child, source, name)
            }
            "const_spec" if !go_spec_is_package_scoped(support, child)? => {
                go_const_spec_binding(support, child, source, name)
            }
            "range_clause" => go_range_binding(support, child, source, name),
            // These statements cannot declare in this enclosing scope. The
            // compound statements' own scopes are visited separately above.
            "assignment_statement"
            | "break_statement"
            | "continue_statement"
            | "dec_statement"
            | "defer_statement"
            | "empty_statement"
            | "expression_statement"
            | "fallthrough_statement"
            | "go_statement"
            | "goto_statement"
            | "inc_statement"
            | "return_statement"
            | "send_statement"
            | "block"
            | "expression_switch_statement"
            | "for_statement"
            | "if_statement"
            | "select_statement"
            | "type_switch_statement" => None,
            // The grammar, not a guessed list of declaration-like names,
            // defines this boundary. An unmodeled statement may bind the name
            // in either namespace, so it cannot expose an outer static type.
            _ if go_is_statement(child) => Some(GoLocalBinding::Unmodeled),
            _ => None,
        };
        if let Some(binding) = binding
            && nearest
                .as_ref()
                .is_none_or(|(start, _)| child.start_byte() > *start)
        {
            nearest = Some((child.start_byte(), binding));
        }
    }
    nearest.map(|(_, binding)| binding)
}

/// The Go grammar's statement supertype includes the nested simple-statement
/// supertype. Traverse that constant-size metadata graph so a newly added
/// statement defaults to an unknown binding, rather than silently falling out.
fn go_is_statement(node: Node<'_>) -> bool {
    let language = node.language();
    let statement = language.id_for_node_kind("_statement", true);
    assert!(language.node_kind_is_supertype(statement));
    assert!(!language.subtypes_for_supertype(statement).is_empty());
    let mut pending = vec![statement];
    while let Some(supertype) = pending.pop() {
        for &subtype in language.subtypes_for_supertype(supertype) {
            if subtype == node.kind_id() {
                return true;
            }
            if language.node_kind_is_supertype(subtype) {
                pending.push(subtype);
            }
        }
    }
    false
}

/// Every recognized declaration either supplies a type or an opaque shadow.
/// Unknown declaration types must never expose a same-named outer binding.
fn go_declaration_has_name(
    support: &dyn GoDefinitionProvider,
    node: Node<'_>,
    source: &str,
    name: &str,
) -> bool {
    let mut cursor = node.walk();
    for declared in node.children_by_field_name("name", &mut cursor) {
        if !support.scope_step() {
            return false;
        }
        if go_node_text(declared, source) == name {
            return true;
        }
    }
    false
}

fn go_parameter_list_binding<'tree>(
    support: &dyn GoDefinitionProvider,
    node: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<GoLocalBinding<'tree>> {
    let mut cursor = node.walk();
    for parameter in node.named_children(&mut cursor) {
        if !support.scope_step() {
            return None;
        }
        if !go_declaration_has_name(support, parameter, source, name) {
            continue;
        }
        return Some(
            match (parameter.kind(), parameter.child_by_field_name("type")) {
                ("parameter_declaration", Some(type_node)) => GoLocalBinding::Type(type_node),
                ("variadic_parameter_declaration", Some(_)) => GoLocalBinding::Variadic,
                ("type_parameter_declaration", _) => GoLocalBinding::OpaqueType,
                _ => GoLocalBinding::Opaque,
            },
        );
    }
    None
}

/// Reuse the clause vocabulary used by native graph/reference scans. The
/// header alias is declared separately in each case's statement-list scope.
fn go_clause_binding<'tree>(
    support: &dyn GoDefinitionProvider,
    scope: Node<'tree>,
    source: &str,
    name: &str,
    byte: usize,
) -> Option<GoLocalBinding<'tree>> {
    use brokk_bifrost_go::syntax as ast;
    if !ast::is_clause(scope) {
        return None;
    }
    let body = ast::clause_statement_list(scope)?;
    if byte < body.start_byte()
        || byte >= body.end_byte()
        || !ast::clause_binding_names(scope, source)
            .iter()
            .any(|declared| declared == name)
    {
        return None;
    }
    if !support.scope_step() {
        return None;
    }
    let Some(switch) = scope
        .parent()
        .filter(|parent| parent.kind() == "type_switch_statement")
    else {
        // Select receive bindings still shadow even without a proven receive type.
        return Some(GoLocalBinding::Opaque);
    };
    let mut cursor = scope.walk();
    let mut types = scope
        .children_by_field_name("type", &mut cursor)
        .filter(|node| node.is_named());
    let first = types.next();
    let second = types.next();
    if let (Some(type_node), None) = (first, second)
        && go_node_text(type_node, source) != "nil"
    {
        return Some(GoLocalBinding::Type(type_node));
    }
    // Evaluate the operand before the case-local alias exists. In particular,
    // an operand with the alias's spelling still names the enclosing binding.
    Some(
        switch
            .child_by_field_name("value")
            .map(GoLocalBinding::SwitchInput)
            .unwrap_or(GoLocalBinding::Opaque),
    )
}

fn go_range_binding<'tree>(
    support: &dyn GoDefinitionProvider,
    node: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<GoLocalBinding<'tree>> {
    if !support.scope_step() || !brokk_bifrost_go::syntax::range_clause_is_short_declaration(node) {
        return None;
    }
    let left = node.child_by_field_name("left")?;
    let index = go_expression_list_index(support, left, source, name)?;
    Some(if index == 1 {
        GoLocalBinding::RangeElement
    } else {
        // The key/index type is not inferred here, but its declaration is exact.
        GoLocalBinding::Opaque
    })
}

/// An external method declaration selected directly at one Go call site.
pub(crate) fn modeled_method_selection_at_offset(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    offset: usize,
) -> Option<String> {
    let tree = parse_tree_for_language(file, Language::Go, source)?;
    let field = tree
        .root_node()
        .named_descendant_for_byte_range(offset, offset)?;
    let selector = field.parent()?;
    if field.start_byte() != offset
        || selector.kind() != "selector_expression"
        || selector.child_by_field_name("field") != Some(field)
        || selector.has_error()
    {
        return None;
    }
    let mut callee = selector;
    while callee
        .parent()
        .is_some_and(|parent| parent.kind() == "parenthesized_expression")
    {
        callee = callee.parent()?;
    }
    let call = callee.parent()?;
    if call.kind() != "call_expression"
        || call.child_by_field_name("function") != Some(callee)
        || call.has_error()
    {
        return None;
    }
    let scope = AnalyzerQueryScope::new(analyzer);
    let outcome = resolve_call_target_batch_with_source(
        analyzer,
        scope.token(),
        vec![DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(field.start_byte()),
            end_byte: Some(field.end_byte()),
        }],
        file.clone(),
        Arc::from(source),
        None,
    )
    .into_iter()
    .next()?;
    if outcome.truncated || outcome.structure_unavailable || outcome.unproven_link_unit {
        return None;
    }
    // Go creates this proof only after selecting one modeled method on the
    // concrete receiver. An indexed function-valued field wins member lookup
    // before that path and cannot acquire this declaration proof.
    let proof = outcome.exact_external_call?;
    (proof.call_application() == CallApplicationKind::BoundReceiver
        && proof.dispatch_extensibility() == Some(DispatchExtensibility::Closed))
    .then(|| proof.canonical_callee().to_owned())
}

/// Whether the Go allocation at `offset` binds by reference or creates an
/// inline value. A named type needs one direct, non-alias same-file shape.
pub fn allocation_binds_by_reference_at_offset(
    file: &ProjectFile,
    source: &str,
    offset: usize,
) -> Option<bool> {
    let tree = parse_tree_for_language(file, Language::Go, source)?;
    let node = tree
        .root_node()
        .named_descendant_for_byte_range(offset, offset)?;
    let allocation = go_allocation_expression_at_offset(node, offset)?;
    if allocation.has_error() || allocation.is_missing() {
        return None;
    }
    match allocation.kind() {
        "unary_expression" => allocation
            .child_by_field_name("operator")
            .filter(|operator| go_node_text(*operator, source) == "&")
            .map(|_| true),
        "call_expression" => go_allocation_call_binding_mode(allocation, source),
        "composite_literal" => {
            if go_composite_literal_is_addressed(allocation) {
                return Some(true);
            }
            let type_node = allocation.child_by_field_name("type")?;
            go_type_binding_mode(tree.root_node(), type_node, source, allocation)
        }
        _ => None,
    }
}

/// Whether the Go allocation at `offset` boxes a reference payload when it is
/// bound into an interface wrapper: a pointer object or a channel keeps the
/// caller's reference inside the wrapper, while an inline value and a slice or
/// map header copy a descriptor the wrapper carries no reference identity for.
///
/// This is the interface-wrapper rule of the channel transport
/// (`expression_supports_channel_payload_copy`), stated for an allocation so an
/// interface-typed parameter transports exactly the payload a
/// `chan interface{}` element transports. A shape this classification cannot
/// resolve stays unknown, so the wrapper stays unnamed.
pub fn allocation_boxes_reference_payload_at_offset(
    file: &ProjectFile,
    source: &str,
    offset: usize,
) -> Option<bool> {
    let tree = parse_tree_for_language(file, Language::Go, source)?;
    let node = tree
        .root_node()
        .named_descendant_for_byte_range(offset, offset)?;
    let allocation = go_allocation_expression_at_offset(node, offset)?;
    if allocation.has_error() || allocation.is_missing() {
        return None;
    }
    match allocation.kind() {
        // An address names the object the wrapper holds.
        "unary_expression" => allocation
            .child_by_field_name("operator")
            .filter(|operator| go_node_text(*operator, source) == "&")
            .map(|_| true),
        "call_expression" => go_allocation_call_boxes_reference_payload(allocation, source),
        // A composite literal is a value or a slice, map, or array descriptor.
        // Only its addressed form names an object the wrapper holds by
        // reference, which is what `go_composite_literal_is_addressed` proves.
        "composite_literal" => Some(go_composite_literal_is_addressed(allocation)),
        _ => None,
    }
}

/// The interface-wrapper classification of one Go allocation call. `new`
/// allocates the object its result points at, a channel is itself a reference,
/// and a slice or map result is a header whose backing storage the wrapper does
/// not name. A named allocation type stays unknown rather than guessed.
fn go_allocation_call_boxes_reference_payload(node: Node<'_>, source: &str) -> Option<bool> {
    let function = node.child_by_field_name("function")?;
    match go_node_text(function, source) {
        "new" => Some(true),
        "make" => {
            let arguments = node.child_by_field_name("arguments")?;
            match arguments.named_child(0)?.kind() {
                "channel_type" => Some(true),
                "slice_type" | "map_type" => Some(false),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Prove the storage mode of one exact Go callable result declaration.
///
/// The declaration range comes from the analyzer, while the result ordinal and
/// type shape come from the parsed callable AST. A nominal result is resolved
/// only when its same-file declaration has one direct, non-alias shape; imports,
/// aliases, generic result types, type parameters, and parser recovery remain
/// unknown.
pub fn result_binds_by_reference_at_ordinal(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    declaration: &CodeUnit,
    ordinal: usize,
) -> Option<bool> {
    if !declaration.is_function()
        || declaration.is_synthetic()
        || declaration.source() != file
        || language_for_file(file) != Language::Go
    {
        return None;
    }

    // One exact indexed signature is required. Its positional identity is
    // useful for rejecting generic result identities, but a Named identity
    // alone is not enough to decide storage mode; the AST resolver below must
    // prove the named declaration's underlying shape.
    let metadata = analyzer.signature_metadata(declaration);
    let [metadata] = metadata.as_slice() else {
        return None;
    };

    let tree = parse_tree_for_language(file, Language::Go, source)?;
    let root = tree.root_node();
    let callable = analyzer
        .ranges_of(declaration)
        .into_iter()
        .find_map(|range| {
            let node = root.named_descendant_for_byte_range(range.start_byte, range.end_byte)?;
            (node.start_byte() == range.start_byte
                && node.end_byte() == range.end_byte
                && matches!(node.kind(), "function_declaration" | "method_declaration")
                && !node.has_error()
                && !node.is_missing())
            .then_some(node)
        })?;

    let type_node = go_result_type_node_at_ordinal(callable, ordinal)?;
    if type_node.has_error() || type_node.is_missing() {
        return None;
    }

    // A generic identity is not a closed storage proof. Direct aggregate
    // shapes such as []T remain classifiable by their outer representation;
    // a type parameter or instantiated nominal reaches the AST path and stays
    // unknown.
    if metadata
        .result_type_identity(ordinal)
        .is_some_and(|identity| identity.generic_argument_count().is_some())
    {
        return None;
    }

    go_type_binding_mode(root, type_node, source, type_node)
}

/// Whether an exact Go callable parameter copies a pointer to its caller's
/// object. Descriptor copies use the separate backing-store binding domain;
/// this fact must not equate slice views or interface wrappers with payloads.
/// Unsupported named reference types and missing type evidence remain unknown.
pub fn parameter_binds_by_reference_at_span(
    file: &ProjectFile,
    source: &str,
    start: usize,
    end: usize,
    ordinal: usize,
) -> Option<bool> {
    go_parameter_binding_mode_at_span(file, source, start, end, ordinal)
        .map(|mode| matches!(mode, GoParameterBindingMode::Reference))
}

/// Identity of a direct pointer formal whose pointee has one ordinary,
/// package-scoped declaration in this exact source file. Named pointer types,
/// aliases, generic parameters and imported pointees have no proof here.
pub(crate) fn direct_pointer_formal_pointee_at_span(
    file: &ProjectFile,
    source: &str,
    start: usize,
    end: usize,
    ordinal: usize,
) -> Option<(usize, usize)> {
    if language_for_file(file) != Language::Go || start >= end || end > source.len() {
        return None;
    }
    let tree = parse_tree_for_language(file, Language::Go, source)?;
    let root = tree.root_node();
    if root.has_error() {
        return None;
    }
    let callable = go_callable_at_span(root, start, end)?;
    if callable.kind() != "function_declaration"
        || callable.child_by_field_name("type_parameters").is_some()
    {
        return None;
    }
    let pointer = go_parameter_type_node_at_ordinal(callable, ordinal)?;
    if pointer.kind() != "pointer_type" || pointer.has_error() {
        return None;
    }
    let pointee = pointer.named_child(0)?;
    if pointee.kind() != "type_identifier" || pointee.has_error() {
        return None;
    }
    let declaration =
        go_same_file_named_type_declaration(root, go_node_text(pointee, source), source)?;
    Some((declaration.start_byte(), declaration.end_byte()))
}

/// Exact named formal and selected import qualifier for a direct imported
/// pointer. The native reader resolves the qualifier; syntax only selects it.
pub(crate) fn direct_imported_pointer_formal_at_span(
    root: Node<'_>,
    start: usize,
    end: usize,
    ordinal: usize,
) -> Option<(Range, Range)> {
    let callable = go_callable_at_span(root, start, end)?;
    if callable.kind() != "function_declaration"
        || callable.has_error()
        || callable.child_by_field_name("type_parameters").is_some()
    {
        return None;
    }
    let (Some(binding), pointer) =
        go_parameter_binding_and_type_node_at_ordinal(callable, ordinal)?
    else {
        return None;
    };
    if pointer.kind() != "pointer_type" || pointer.has_error() {
        return None;
    }
    let pointee = pointer.named_child(0)?;
    if pointee.kind() != "qualified_type" || pointee.has_error() {
        return None;
    }
    let package = pointee.child_by_field_name("package")?;
    let _name = pointee.child_by_field_name("name")?;
    let range = |node: Node<'_>| Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row + 1,
        end_line: node.end_position().row + 1,
    };
    Some((range(binding), range(package)))
}

/// The direct result annotation's exact same-file pointee declaration.
pub(crate) fn direct_pointer_result_pointee_at_span(
    file: &ProjectFile,
    source: &str,
    start: usize,
    end: usize,
    ordinal: usize,
) -> Option<(usize, usize)> {
    if language_for_file(file) != Language::Go || start >= end || end > source.len() {
        return None;
    }
    let tree = parse_tree_for_language(file, Language::Go, source)?;
    let root = tree.root_node();
    if root.has_error() {
        return None;
    }
    let callable = go_callable_at_span(root, start, end)?;
    if !matches!(
        callable.kind(),
        "function_declaration" | "method_declaration"
    ) || callable.child_by_field_name("type_parameters").is_some()
    {
        return None;
    }
    let pointer = go_result_type_node_at_ordinal(callable, ordinal)?;
    if pointer.kind() != "pointer_type" || pointer.has_error() {
        return None;
    }
    let pointee = pointer.named_child(0)?;
    if pointee.kind() != "type_identifier" || pointee.has_error() {
        return None;
    }
    let declaration =
        go_same_file_named_type_declaration(root, go_node_text(pointee, source), source)?;
    Some((declaration.start_byte(), declaration.end_byte()))
}

pub(crate) fn direct_pointer_receiver_pointee_at_span(
    file: &ProjectFile,
    source: &str,
    start: usize,
    end: usize,
) -> Option<(usize, usize)> {
    if language_for_file(file) != Language::Go || start >= end || end > source.len() {
        return None;
    }
    let tree = parse_tree_for_language(file, Language::Go, source)?;
    let root = tree.root_node();
    if root.has_error() {
        return None;
    }
    let callable = go_callable_at_span(root, start, end)?;
    if callable.kind() != "method_declaration"
        || callable.child_by_field_name("type_parameters").is_some()
    {
        return None;
    }
    let pointer = brokk_bifrost_go::declarations::go_method_receiver_type_node(callable)?;
    if pointer.kind() != "pointer_type" || pointer.has_error() {
        return None;
    }
    let pointee = pointer.named_child(0)?;
    if pointee.kind() != "type_identifier" || pointee.has_error() {
        return None;
    }
    let declaration =
        go_same_file_named_type_declaration(root, go_node_text(pointee, source), source)?;
    Some((declaration.start_byte(), declaration.end_byte()))
}

/// Whether an exact Go callable parameter copies a descriptor that preserves
/// backing storage. Inline aggregate copies and pointers use their separate
/// identity domains; named or unavailable types remain unknown.
pub fn parameter_preserves_backing_at_span(
    file: &ProjectFile,
    source: &str,
    start: usize,
    end: usize,
    ordinal: usize,
) -> Option<bool> {
    go_parameter_binding_mode_at_span(file, source, start, end, ordinal)
        .map(|mode| matches!(mode, GoParameterBindingMode::BackingDescriptor))
}

/// Whether an exact Go callable parameter's declared type is an interface that
/// boxes one reference payload rather than copying the referenced object.
///
/// Go copies an interface argument, but the copy still holds the caller's
/// object inside the wrapper, so a compatible assertion on the formal recovers
/// that object. `Some(true)` means the declaration is available and the
/// formal's type is an interface; `Some(false)` means the declaration is
/// available and the formal is not an interface type. `None` means the type
/// shape is unavailable or ambiguous, so nothing may be transported.
pub fn parameter_boxes_reference_payload_at_span(
    file: &ProjectFile,
    source: &str,
    start: usize,
    end: usize,
    ordinal: usize,
) -> Option<bool> {
    if language_for_file(file) != Language::Go || start >= end || end > source.len() {
        return None;
    }
    let tree = parse_tree_for_language(file, Language::Go, source)?;
    let root = tree.root_node();
    if root.has_error() {
        return None;
    }
    let callable = go_callable_at_span(root, start, end)?;
    let type_node = go_parameter_type_node_at_ordinal(callable, ordinal)?;
    if type_node.is_missing() || type_node.has_error() {
        return None;
    }
    go_type_boxes_reference_payload(root, type_node, source, &mut HashSet::default())
}

/// Classify one Go type node as an interface whose wrapper boxes a reference
/// payload. A named type resolves through its one direct same-file
/// declaration, so a chain of local aliases-of-aliases still reaches its
/// underlying shape; a cycle, an alias that names another package, and any
/// unavailable declaration stay unknown.
fn go_type_boxes_reference_payload(
    root: Node<'_>,
    type_node: Node<'_>,
    source: &str,
    visited: &mut HashSet<usize>,
) -> Option<bool> {
    if !visited.insert(type_node.id()) {
        return None;
    }
    let type_node = go_unwrap_parenthesized_type(type_node)?;
    match type_node.kind() {
        // An empty interface and a method-bearing interface both box one
        // reference payload; the shape of the wrapper does not change what it
        // carries.
        "interface_type" => Some(true),
        "type_identifier" | "identifier" => {
            let name = go_node_text(type_node, source);
            if name.is_empty() {
                return None;
            }
            // `any` is the predeclared alias for the empty interface. A local
            // declaration of that name shadows it, so the name alone is no
            // longer an interface.
            if name == "any" && go_same_file_named_type_declaration(root, name, source).is_none() {
                return Some(true);
            }
            let declaration = go_same_file_named_type_declaration(root, name, source)?;
            let underlying = declaration.child_by_field_name("type")?;
            if underlying.is_missing() || underlying.has_error() {
                return None;
            }
            go_type_boxes_reference_payload(root, underlying, source, visited)
        }
        // A package-qualified or generic name needs cross-package or
        // type-argument resolution; the local AST alone cannot prove whether
        // the named type is an interface.
        "qualified_type" | "generic_type" => None,
        // Every other declaration shape names a concrete type that copies a
        // value or storage directly; none boxes a reference payload.
        _ => Some(false),
    }
}

/// Unwrap the parenthesized spellings of one type expression. Parentheses are
/// a spelling rather than a shape, so the underlying type node answers for it.
pub(crate) fn go_unwrap_parenthesized_type(mut type_node: Node<'_>) -> Option<Node<'_>> {
    while type_node.kind() == "parenthesized_type" {
        type_node = type_node.named_child(0)?;
    }
    (!type_node.is_missing()).then_some(type_node)
}

/// Find the one same-file direct type declaration that names `name`.
///
/// A second declaration, an alias, a generic declaration, and a declaration
/// that is not at package scope are all unavailable, so the caller keeps the
/// question open rather than guessing one shape.
fn go_same_file_named_type_declaration<'tree>(
    root: Node<'tree>,
    name: &str,
    source: &str,
) -> Option<Node<'tree>> {
    if name.is_empty() {
        return None;
    }
    let mut stack = vec![root];
    let mut matches = Vec::new();
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "type_spec" | "type_alias")
            && node
                .parent()
                .is_some_and(|parent| parent.kind() == "type_declaration")
            && node
                .child_by_field_name("name")
                .is_some_and(|declared| go_node_text(declared, source) == name)
        {
            matches.push(node);
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    let [declaration] = matches.as_slice() else {
        return None;
    };
    if declaration.kind() == "type_alias"
        || declaration
            .parent()
            .and_then(|parent| parent.parent())
            .is_none_or(|scope| scope.kind() != "source_file")
        || declaration.child_by_field_name("type_parameters").is_some()
        || declaration.has_error()
        || declaration.is_missing()
    {
        return None;
    }
    Some(*declaration)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GoParameterBindingMode {
    Reference,
    BackingDescriptor,
    ValueCopy,
}

fn go_parameter_binding_mode_at_span(
    file: &ProjectFile,
    source: &str,
    start: usize,
    end: usize,
    ordinal: usize,
) -> Option<GoParameterBindingMode> {
    if language_for_file(file) != Language::Go || start >= end || end > source.len() {
        return None;
    }
    let tree = parse_tree_for_language(file, Language::Go, source)?;
    let root = tree.root_node();
    if root.has_error() {
        return None;
    }
    let callable = go_callable_at_span(root, start, end)?;
    let type_node = go_parameter_type_node_at_ordinal(callable, ordinal)?;
    if type_node.is_missing() || type_node.has_error() {
        return None;
    }
    match type_node.kind() {
        "pointer_type" => Some(GoParameterBindingMode::Reference),
        "slice_type" | "map_type" | "channel_type" => {
            Some(GoParameterBindingMode::BackingDescriptor)
        }
        "struct_type"
        | "array_type"
        | "implicit_length_array_type"
        | "function_type"
        | "interface_type" => Some(GoParameterBindingMode::ValueCopy),
        // The shared named-type proof can establish an inline aggregate.
        // Its positive result also includes backing descriptors, so it is
        // insufficient to certify an ordinary pointer binding here.
        "type_identifier" | "identifier" => {
            (go_type_binding_mode(root, type_node, source, type_node) == Some(false))
                .then_some(GoParameterBindingMode::ValueCopy)
        }
        _ => None,
    }
}

/// The exact callable declaration or literal at a source span, when the span
/// bounds one whole node. Anonymous function literals are callables too, and a
/// name-based lookup cannot locate or tell them apart.
fn go_callable_at_span(root: Node<'_>, start: usize, end: usize) -> Option<Node<'_>> {
    let callable = root.named_descendant_for_byte_range(start, end)?;
    (callable.start_byte() == start
        && callable.end_byte() == end
        && matches!(
            callable.kind(),
            "function_declaration" | "method_declaration" | "func_literal"
        )
        && !callable.is_missing())
    .then_some(callable)
}

/// Whether one exact indexed Go callable parameter is proven to be a
/// reference-free primitive value. Only universe numeric and boolean types
/// are admitted; strings and all named, generic, imported, aggregate, and
/// recovery forms remain unknown.
pub fn parameter_is_reference_free_at_ordinal(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    declaration: &CodeUnit,
    ordinal: usize,
) -> Option<bool> {
    if !declaration.is_function()
        || declaration.is_synthetic()
        || declaration.source() != file
        || language_for_file(file) != Language::Go
    {
        return None;
    }

    let tree = parse_tree_for_language(file, Language::Go, source)?;
    let root = tree.root_node();
    if root.has_error() {
        return None;
    }
    let callable = analyzer
        .ranges_of(declaration)
        .into_iter()
        .find_map(|range| {
            let node = root.named_descendant_for_byte_range(range.start_byte, range.end_byte)?;
            (node.start_byte() == range.start_byte
                && node.end_byte() == range.end_byte
                && matches!(node.kind(), "function_declaration" | "method_declaration")
                && !node.has_error()
                && !node.is_missing())
            .then_some(node)
        })?;
    let type_node = go_parameter_type_node_at_ordinal(callable, ordinal)?;
    if type_node.has_error() || type_node.is_missing() {
        return None;
    }

    let name = match type_node.kind() {
        "type_identifier" | "identifier" => go_node_text(type_node, source),
        _ => return None,
    };
    if !go_reference_free_predeclared_name(name) {
        return None;
    }
    if go_enclosing_type_parameter_status(type_node, name, source) != Some(false) {
        return None;
    }

    let go = resolve_analyzer::<GoAnalyzer>(analyzer)?;
    if !go.workspace_declaration_identities_authoritative() {
        return None;
    }
    let scope = AnalyzerQueryScope::new(analyzer);
    let (imports, dot_imports) = go.definition_import_namespaces(scope.token(), file);
    if !dot_imports.is_empty() || imports.contains_key(name) {
        return None;
    }
    if go_name_shadowed_at_with_scope(root, source, type_node.start_byte(), name, || true)
        != Some(false)
    {
        return None;
    }

    let declared_package = go.package_clause_of(file)?;
    let package = go
        .workspace_path_index()
        .canonical_package_name(file, &declared_package);
    let package_name = format!("{package}.{name}");
    let module_name = format!(
        "{package}.{}.{name}",
        brokk_bifrost_go::packages::GO_MODULE_SCOPE_SEGMENT
    );
    if go.definitions(&package_name).next().is_some()
        || go.definitions(&module_name).next().is_some()
    {
        return None;
    }
    Some(true)
}

fn go_reference_free_predeclared_name(name: &str) -> bool {
    brokk_bifrost_go::declarations::is_predeclared_go_basic_type(name) && !matches!(name, "string")
}

fn go_result_type_node_at_ordinal(callable: Node<'_>, ordinal: usize) -> Option<Node<'_>> {
    let result = callable.child_by_field_name("result")?;
    if result.kind() != "parameter_list" {
        return (ordinal == 0).then_some(result);
    }

    go_parameter_list_type_node_at_ordinal(result, ordinal)
}

fn go_parameter_type_node_at_ordinal(callable: Node<'_>, ordinal: usize) -> Option<Node<'_>> {
    let parameters = callable.child_by_field_name("parameters")?;
    go_parameter_list_type_node_at_ordinal(parameters, ordinal)
}

fn go_parameter_list_type_node_at_ordinal(
    parameter_list: Node<'_>,
    ordinal: usize,
) -> Option<Node<'_>> {
    go_parameter_list_binding_and_type_node_at_ordinal(parameter_list, ordinal).map(|(_, ty)| ty)
}

fn go_parameter_binding_and_type_node_at_ordinal(
    callable: Node<'_>,
    ordinal: usize,
) -> Option<(Option<Node<'_>>, Node<'_>)> {
    go_parameter_list_binding_and_type_node_at_ordinal(
        callable.child_by_field_name("parameters")?,
        ordinal,
    )
}

fn go_parameter_list_binding_and_type_node_at_ordinal(
    parameter_list: Node<'_>,
    ordinal: usize,
) -> Option<(Option<Node<'_>>, Node<'_>)> {
    if parameter_list.kind() != "parameter_list" {
        return None;
    }
    let mut cursor = parameter_list.walk();
    let mut next_ordinal = 0usize;
    for declaration in parameter_list.named_children(&mut cursor) {
        if !matches!(
            declaration.kind(),
            "parameter_declaration" | "variadic_parameter_declaration"
        ) {
            return None;
        }
        let type_node = declaration.child_by_field_name("type")?;
        let mut names = declaration.walk();
        let width = declaration
            .children_by_field_name("name", &mut names)
            .count()
            .max(1);
        let end_ordinal = next_ordinal.checked_add(width)?;
        if ordinal < end_ordinal {
            if declaration.kind() == "variadic_parameter_declaration" {
                return None;
            }
            let mut names = declaration.walk();
            let binding = declaration
                .children_by_field_name("name", &mut names)
                .nth(ordinal - next_ordinal);
            return Some((binding, type_node));
        }
        next_ordinal = end_ordinal;
    }
    None
}

/// Find the allocation expression whose AST start is the source-mapping
/// offset. Some lowering paths retain an enclosing entry's mapping instead;
/// those stay unknown. Requiring the exact expression prevents an inner value
/// from inheriting an unrelated outer call or address-of expression.
fn go_allocation_expression_at_offset<'tree>(
    node: Node<'tree>,
    offset: usize,
) -> Option<Node<'tree>> {
    let mut cursor = Some(node);
    while let Some(current) = cursor {
        if current.start_byte() == offset
            && matches!(
                current.kind(),
                "unary_expression" | "call_expression" | "composite_literal"
            )
        {
            return Some(current);
        }
        cursor = current.parent();
    }
    None
}

fn go_composite_literal_is_addressed(node: Node<'_>) -> bool {
    let mut cursor = node.parent();
    while cursor.is_some_and(|parent| parent.kind() == "parenthesized_expression") {
        cursor = cursor.and_then(|parent| parent.parent());
    }
    cursor.is_some_and(|parent| {
        parent.kind() == "unary_expression"
            && parent
                .child_by_field_name("operator")
                .is_some_and(|operator| operator.kind() == "&")
    })
}

fn go_allocation_call_binding_mode(node: Node<'_>, source: &str) -> Option<bool> {
    let function = node.child_by_field_name("function")?;
    let name = go_node_text(function, source);
    match name {
        // `new(T)` creates a pointer to newly allocated T storage. The
        // semantic producer emits an Allocation row only for the builtin form.
        "new" => Some(true),
        // make's slice, map, and channel results are descriptors referring to
        // fresh backing storage, so copying the result preserves that storage.
        "make" => {
            let arguments = node.child_by_field_name("arguments")?;
            let type_node = arguments.named_child(0)?;
            go_type_binding_mode(root_node(type_node), type_node, source, node)
        }
        _ => None,
    }
}

fn go_type_binding_mode(
    root: Node<'_>,
    type_node: Node<'_>,
    source: &str,
    expression: Node<'_>,
) -> Option<bool> {
    if let Some(mode) = go_direct_type_binding_mode(type_node.kind()) {
        return Some(mode);
    }
    match type_node.kind() {
        "type_identifier" | "identifier" => {
            let name = go_node_text(type_node, source);
            go_named_type_binding_mode(root, name, source, expression)
        }
        // Qualified and generic names need package/type-argument resolution;
        // the local AST alone cannot prove their storage mode.
        _ => None,
    }
}

fn go_direct_type_binding_mode(kind: &str) -> Option<bool> {
    match kind {
        "struct_type" | "array_type" | "implicit_length_array_type" => Some(false),
        "slice_type" | "map_type" | "channel_type" | "pointer_type" => Some(true),
        _ => None,
    }
}

fn go_named_type_binding_mode(
    root: Node<'_>,
    name: &str,
    source: &str,
    expression: Node<'_>,
) -> Option<bool> {
    if name.is_empty() {
        return None;
    }
    match go_enclosing_type_parameter_status(expression, name, source) {
        Some(true) | None => return None,
        Some(false) => {}
    }
    let declaration = go_same_file_named_type_declaration(root, name, source)?;
    let type_node = declaration.child_by_field_name("type")?;
    if type_node.has_error() || type_node.is_missing() {
        return None;
    }
    go_direct_type_binding_mode(type_node.kind())
}

/// Return whether `name` is supplied by a generic context enclosing the
/// allocation expression. A receiver with a generic instantiation is kept
/// conservative because its receiver type parameters are structured in the
/// receiver list rather than in a method-level `type_parameters` field.
fn go_enclosing_type_parameter_status(
    expression: Node<'_>,
    name: &str,
    source: &str,
) -> Option<bool> {
    let mut cursor = expression.parent();
    while let Some(current) = cursor {
        if let Some(list) = current.child_by_field_name("type_parameters") {
            if list.has_error() || list.is_missing() {
                return None;
            }
            let mut list_cursor = list.walk();
            for declaration in list
                .named_children(&mut list_cursor)
                .filter(|child| child.kind() == "type_parameter_declaration")
            {
                if declaration.has_error() || declaration.is_missing() {
                    return None;
                }
                let mut names = declaration.walk();
                if declaration
                    .children_by_field_name("name", &mut names)
                    .any(|parameter| go_node_text(parameter, source) == name)
                {
                    return Some(true);
                }
            }
        }
        if current.kind() == "method_declaration"
            && let Some(receiver) = current.child_by_field_name("receiver")
        {
            if receiver.has_error() || receiver.is_missing() {
                return None;
            }
            let mut stack = vec![receiver];
            while let Some(node) = stack.pop() {
                if node.kind() == "generic_type" {
                    return Some(true);
                }
                let mut children = node.walk();
                stack.extend(node.named_children(&mut children));
            }
        }
        cursor = current.parent();
    }
    Some(false)
}

/// Whether the binding whose identifier starts at `offset` may be created on
/// every pass through a loop in one procedure invocation.
///
/// This deliberately admits only declaration positions that the Go grammar
/// identifies structurally. A reference with the same spelling, a malformed
/// path, and a declaration form without an exact supported name all remain
/// unresolved so callers do not infer singleton storage from missing syntax.
pub fn lexical_binding_repeats_at_offset(
    file: &ProjectFile,
    source: &str,
    offset: usize,
) -> Option<bool> {
    let tree = parse_tree_for_language(file, Language::Go, source)?;
    let identifier = tree
        .root_node()
        .named_descendant_for_byte_range(offset, offset)
        .filter(|node| {
            node.kind() == "identifier"
                && node.start_byte() == offset
                && !node.is_error()
                && !node.is_missing()
        })?;
    // `_` is an identifier-shaped grammar node, but it does not introduce
    // storage. This is an exact token check, not a source-text declaration
    // fallback.
    if go_node_text(identifier, source) == "_" {
        return None;
    }
    let declaration = go_binding_declaration_for_identifier(identifier)?;
    if declaration.kind() == "parameter_declaration" {
        // Named result variables are emitted as Local values, but their
        // storage is created on entry, including in a body containing goto.
        let parameters = declaration.parent()?;
        let callable = parameters.parent()?;
        return (matches!(
            callable.kind(),
            "function_declaration" | "method_declaration" | "func_literal"
        ) && !callable.has_error())
        .then_some(false);
    }
    go_binding_repeats_in_enclosing_scope(declaration)
}

fn go_binding_declaration_for_identifier<'tree>(identifier: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = identifier.parent();
    while let Some(node) = current {
        if node.is_error() || node.is_missing() || node.has_error() {
            return None;
        }
        let is_exact_binding = match node.kind() {
            "short_var_declaration" => node
                .child_by_field_name("left")
                .is_some_and(|left| go_lhs_contains_identifier(left, identifier)),
            "var_spec" | "parameter_declaration" => {
                let mut cursor = node.walk();
                node.children_by_field_name("name", &mut cursor)
                    .any(|name| same_node(name, identifier))
            }
            "range_clause" => {
                brokk_bifrost_go::syntax::range_clause_is_short_declaration(node)
                    && node
                        .child_by_field_name("left")
                        .is_some_and(|left| go_lhs_contains_identifier(left, identifier))
            }
            _ => false,
        };
        if is_exact_binding {
            return Some(node);
        }
        if matches!(
            node.kind(),
            "function_declaration" | "method_declaration" | "func_literal"
        ) {
            return None;
        }
        current = node.parent();
    }
    None
}

fn go_binding_repeats_in_enclosing_scope(declaration: Node<'_>) -> Option<bool> {
    let mut current = Some(declaration);
    while let Some(node) = current {
        if node.is_error() || node.is_missing() || node.has_error() {
            return None;
        }
        match node.kind() {
            "for_statement" => return Some(true),
            "function_declaration" | "method_declaration" | "func_literal" => {
                return match go_callable_contains_goto(node) {
                    Some(false) => Some(false),
                    Some(true) | None => None,
                };
            }
            _ => current = node.parent(),
        }
    }
    None
}

fn go_lhs_contains_identifier(left: Node<'_>, identifier: Node<'_>) -> bool {
    if same_node(left, identifier) {
        return true;
    }
    if left.kind() != "expression_list" {
        return false;
    }
    let mut cursor = left.walk();
    left.named_children(&mut cursor)
        .any(|child| same_node(child, identifier))
}

/// A backward `goto` can revisit a declaration even when it is outside a
/// syntactic loop. Keep that case unresolved, while excluding goto statements
/// belonging to nested callables from the enclosing callable's cardinality.
fn go_callable_contains_goto(callable: Node<'_>) -> Option<bool> {
    let mut stack = vec![callable];
    while let Some(node) = stack.pop() {
        if node.is_error() || node.is_missing() {
            return None;
        }
        if node.kind() == "goto_statement" {
            return Some(true);
        }
        if node.id() != callable.id()
            && matches!(
                node.kind(),
                "function_declaration" | "method_declaration" | "func_literal"
            )
        {
            continue;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    Some(false)
}

/// The struct field whose declaration one offset falls inside.
///
/// A producer resolves a field only where it can type the receiver, so a
/// capture inside a spawned closure falls back to an identity interned per
/// procedure while the parent uses the field's declaration. The two then
/// describe one field differently and their accesses are declared disjoint. A
/// definition lookup cannot close that from the parent's side, because at a
/// declaration there is no reference to follow.
///
/// Returns nothing unless the offset is a field name inside a struct type and
/// exactly one declared field of that struct carries the name. Merging
/// distinct fields would turn a missed race into a reported one.
pub(crate) fn field_declaration_at_offset(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    offset: usize,
) -> Option<CodeUnit> {
    let tree = parse_tree_for_language(file, Language::Go, source)?;
    let name = tree
        .root_node()
        .named_descendant_for_byte_range(offset, offset)
        .filter(|node| node.kind() == "field_identifier")?;
    let field_name = go_node_text(name, source);
    let owner_name = name
        .parent()
        .filter(|declaration| declaration.kind() == "field_declaration")?
        .parent()
        .filter(|list| list.kind() == "field_declaration_list")?
        .parent()
        .filter(|structure| structure.kind() == "struct_type")?
        .parent()
        .filter(|spec| spec.kind() == "type_spec")?
        .child_by_field_name("name")
        .map(|node| go_node_text(node, source))?;
    let declarations = analyzer.get_declarations(file);
    let mut matches = declarations.iter().filter(|unit| {
        unit.kind() == brokk_bifrost_core::analyzer::model::CodeUnitType::Field
            && unit.terminal_name() == field_name
            && unit.fq().parent().is_some_and(|owner_fq| {
                declarations
                    .iter()
                    .any(|owner| owner.fq() == &owner_fq && owner.terminal_name() == owner_name)
            })
    });
    let unit = matches.next()?.clone();
    matches.next().is_none().then_some(unit)
}

fn go_short_var_binding<'tree>(
    support: &dyn GoDefinitionProvider,
    node: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<GoLocalBinding<'tree>> {
    if !support.scope_step() {
        return None;
    }
    let left = node.child_by_field_name("left")?;
    let index = go_expression_list_index(support, left, source, name)?;
    Some(
        node.child_by_field_name("right")
            .and_then(|right| go_expression_list_binding(support, right, index))
            .unwrap_or(GoLocalBinding::Opaque),
    )
}

fn go_var_declaration_binding<'tree>(
    support: &dyn GoDefinitionProvider,
    node: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<GoLocalBinding<'tree>> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if !support.scope_step() {
            return None;
        }
        // `var x T` holds a `var_spec` directly; `var ( ... )` wraps each spec.
        let found = if child.kind() == "var_spec" {
            go_var_spec_binding(support, child, source, name)
        } else {
            let mut inner = child.walk();
            let mut found = None;
            for spec in child.named_children(&mut inner) {
                if !support.scope_step() {
                    return None;
                }
                if spec.kind() == "var_spec"
                    && let Some(binding) = go_var_spec_binding(support, spec, source, name)
                {
                    found = Some(binding);
                    break;
                }
            }
            found
        };
        if found.is_some() {
            return found;
        }
    }
    None
}

fn go_const_declaration_binding<'tree>(
    support: &dyn GoDefinitionProvider,
    node: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<GoLocalBinding<'tree>> {
    let mut containers = vec![node];
    while let Some(container) = containers.pop() {
        let mut cursor = container.walk();
        for child in container.named_children(&mut cursor) {
            if !support.scope_step() {
                return None;
            }
            match child.kind() {
                "const_spec" => {
                    if let Some(binding) = go_const_spec_binding(support, child, source, name) {
                        return Some(binding);
                    }
                }
                // Accepted by grammar variants that represent the parenthesized
                // form with a wrapper, rather than direct `const_spec` children.
                "const_spec_list" => containers.push(child),
                _ => {}
            }
        }
    }
    None
}

fn go_spec_is_package_scoped(support: &dyn GoDefinitionProvider, spec: Node<'_>) -> Option<bool> {
    let mut owner = spec.parent()?;
    loop {
        if !support.scope_step() {
            return None;
        }
        if matches!(
            owner.kind(),
            "const_declaration" | "var_declaration" | "type_declaration"
        ) {
            return owner.parent().map(|parent| parent.kind() == "source_file");
        }
        owner = owner.parent()?;
    }
}

fn go_const_spec_binding<'tree>(
    support: &dyn GoDefinitionProvider,
    spec: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<GoLocalBinding<'tree>> {
    go_named_identifier_index(support, spec, source, name).map(|_| GoLocalBinding::Opaque)
}

fn go_var_spec_binding<'tree>(
    support: &dyn GoDefinitionProvider,
    spec: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<GoLocalBinding<'tree>> {
    if !support.scope_step() {
        return None;
    }
    let index = go_named_identifier_index(support, spec, source, name)?;
    if let Some(type_node) = spec.child_by_field_name("type") {
        return Some(GoLocalBinding::Type(type_node));
    }
    Some(
        spec.child_by_field_name("value")
            .and_then(|value| go_expression_list_binding(support, value, index))
            .unwrap_or(GoLocalBinding::Opaque),
    )
}

fn go_named_identifier_index(
    support: &dyn GoDefinitionProvider,
    spec: Node<'_>,
    source: &str,
    name: &str,
) -> Option<usize> {
    let mut cursor = spec.walk();
    let mut position = 0usize;
    for child in spec.named_children(&mut cursor) {
        if !support.scope_step() {
            return None;
        }
        if child.kind() != "identifier" {
            continue;
        }
        if go_node_text(child, source).trim() == name {
            return Some(position);
        }
        position += 1;
    }
    None
}

fn go_expression_list_index(
    support: &dyn GoDefinitionProvider,
    list: Node<'_>,
    source: &str,
    name: &str,
) -> Option<usize> {
    let mut cursor = list.walk();
    for (index, child) in list.named_children(&mut cursor).enumerate() {
        if !support.scope_step() {
            return None;
        }
        if go_node_text(child, source).trim() == name {
            return Some(index);
        }
    }
    None
}

fn go_expression_list_binding<'tree>(
    support: &dyn GoDefinitionProvider,
    list: Node<'tree>,
    index: usize,
) -> Option<GoLocalBinding<'tree>> {
    if !support.scope_step() {
        return None;
    }
    if list.kind() == "expression_list" {
        let mut cursor = list.walk();
        let mut expressions = Vec::new();
        for child in list.named_children(&mut cursor) {
            if !support.scope_step() {
                return None;
            }
            expressions.push(child);
        }
        expressions.get(index).map(|_| GoLocalBinding::Value)
    } else {
        Some(GoLocalBinding::Value)
    }
}

fn go_first_named_child<'tree>(
    support: &dyn GoDefinitionProvider,
    node: Node<'tree>,
) -> Option<Node<'tree>> {
    if !support.scope_step() {
        return None;
    }
    let child = brokk_bifrost_core::analyzer::structural::adapter_helpers::first_named_child(node)?;
    support.scope_step().then_some(child)
}

fn go_last_named_child<'tree>(
    support: &dyn GoDefinitionProvider,
    node: Node<'tree>,
) -> Option<Node<'tree>> {
    if !support.scope_step() {
        return None;
    }
    let mut cursor = node.walk();
    let mut last = None;
    for child in node.named_children(&mut cursor) {
        if !support.scope_step() {
            return None;
        }
        last = Some(child);
    }
    last
}

struct GoCallArguments<'tree> {
    count: usize,
    has_spread: bool,
    possible_multi_result_call: Option<Node<'tree>>,
}

fn go_call_arguments<'tree>(
    support: &dyn GoDefinitionProvider,
    call: Node<'tree>,
) -> Option<GoCallArguments<'tree>> {
    if !support.scope_step() {
        return None;
    }
    let arguments = call.child_by_field_name("arguments")?;
    let mut count = 0usize;
    let mut has_spread = false;
    let mut sole_argument_call = None;
    let mut cursor = arguments.walk();
    for argument in arguments.named_children(&mut cursor) {
        if !support.scope_step() {
            return None;
        }
        count += 1;
        has_spread |= argument.kind() == "variadic_argument";
        let mut unwrapped = argument;
        while unwrapped.kind() == "parenthesized_expression" {
            unwrapped = go_first_named_child(support, unwrapped)?;
        }
        sole_argument_call =
            (count == 1 && unwrapped.kind() == "call_expression").then_some(unwrapped);
    }
    Some(GoCallArguments {
        count,
        has_spread,
        possible_multi_result_call: (count == 1).then_some(sole_argument_call).flatten(),
    })
}

/// Producer-proven sole-call tuples already have separate logical actual rows.
/// A remaining single written call argument needs a proven single result;
/// imported or cross-file multi-result calls keep their partition open.
pub(crate) fn go_call_argument_partition_is_complete(
    analyzer: &dyn IAnalyzer,
    shape: &brokk_bifrost_analysis::analyzer::usages::call_shape::CallShapeReport,
    cancellation: Option<&CancellationToken>,
) -> bool {
    if shape.arguments.len() != 1 {
        return true;
    }
    let session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), cancellation);
    let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
        return false;
    };
    let support =
        AnalyzerGoDefinitionProvider::bounded(go, &session, analyzer.semantic_model_overlay());
    let file = &shape.outcome.file;
    let Some(source) = analyzer.indexed_source(file) else {
        return false;
    };
    let Some(tree) = parse_tree_for_language(file, Language::Go, &source) else {
        return false;
    };
    let range = shape.outcome.range;
    let Some(call) = tree
        .root_node()
        .named_descendant_for_byte_range(range.start_byte, range.end_byte)
    else {
        return false;
    };
    if call.kind() != "call_expression" || call.has_error() {
        return false;
    }
    let scope = AnalyzerQueryScope::new(analyzer);
    let complete = go_call_arguments(&support, call).is_some_and(|arguments| {
        arguments.possible_multi_result_call.is_none_or(|inner| {
            go_call_result_count(&support, scope.token(), go, file, &source, inner) == Some(1)
        })
    });
    matches!(
        session.finish(complete),
        BoundedResolution::Complete { value: true, .. }
    )
}

pub(crate) fn go_callable_modeled_argument_count(
    support: &dyn GoDefinitionProvider,
    token: QueryToken<'_>,
    go: &GoAnalyzer,
    file: &ProjectFile,
    source: &str,
    callable: Node<'_>,
) -> Option<usize> {
    let (count, spread) =
        go_selected_receiver_argument_shape(support, token, go, file, source, callable)?;
    (!spread).then_some(count)
}

pub(crate) fn go_selected_receiver_argument_shape(
    support: &dyn GoDefinitionProvider,
    token: QueryToken<'_>,
    go: &GoAnalyzer,
    file: &ProjectFile,
    source: &str,
    callable: Node<'_>,
) -> Option<(usize, bool)> {
    let call = go_call_for_callable(support, callable)?;
    let arguments = go_call_arguments(support, call)?;
    let count = match arguments.possible_multi_result_call {
        Some(inner) if !arguments.has_spread => {
            match go_call_result_count(support, token, go, file, source, inner) {
                Some(0) => return None,
                count => count?,
            }
        }
        _ => arguments.count,
    };
    Some((count, arguments.has_spread))
}

/// Resolve dependent call result shapes with a query-local worklist. Type
/// inference requests missing sole-call dependencies instead of recursively
/// entering the result-count resolver. Every worklist iteration and structured
/// lookup consumes the caller's ResolutionSession scope-work budget; exhaustion
/// is retained by that session and reported as incomplete resolution. Unknown
/// and cyclic callees stay open. Nothing survives this query.
fn go_call_result_count<'tree>(
    support: &dyn GoDefinitionProvider,
    token: QueryToken<'_>,
    go: &GoAnalyzer,
    file: &ProjectFile,
    source: &str,
    call: Node<'tree>,
) -> Option<usize> {
    let mut root = call;
    while let Some(parent) = root.parent() {
        if !support.scope_step() {
            return None;
        }
        root = parent;
    }
    let mut counts = HashMap::default();
    let mut pending = vec![call];
    let mut active = HashSet::default();
    active.insert(call.id());
    // Also bound ordinary unbounded navigation requests. A stopped query may
    // retain no guessed result shape; its caller emits an incomplete binding.
    const MAX_RESULT_SHAPE_STEPS: usize = 4096;
    let mut steps = 0;
    while let Some(current) = pending.last().copied() {
        steps += 1;
        if steps > MAX_RESULT_SHAPE_STEPS {
            if let Some(session) = support.session() {
                session.mark_scope_incomplete();
            }
            go.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceUnavailable(
                "Go call result-shape work limit exceeded".into(),
            ));
            return None;
        }
        if !support.scope_step() {
            return None;
        }
        let dependencies = std::cell::RefCell::new(Vec::new());
        let argument_count = |function| {
            let call = go_call_for_callable(support, function)?;
            let arguments = go_call_arguments(support, call)?;
            if arguments.has_spread {
                return None;
            }
            match arguments.possible_multi_result_call {
                Some(inner) => match counts.get(&inner.id()) {
                    Some(count) => *count,
                    None => {
                        dependencies.borrow_mut().push(inner);
                        None
                    }
                }
                .filter(|count| *count != 0),
                None => Some(arguments.count),
            }
        };
        let result = go_resolved_call_result_count(
            support,
            token,
            go,
            file,
            source,
            root,
            current,
            &argument_count,
        );
        let dependencies = dependencies.into_inner();
        if dependencies.is_empty() {
            counts.insert(current.id(), result);
            active.remove(&current.id());
            pending.pop();
        } else {
            for dependency in dependencies {
                if !active.insert(dependency.id()) {
                    // A receiver initializer may refer back to its own call.
                    return go_nested_arity_miss(support, go);
                }
                pending.push(dependency);
            }
        }
    }
    let result = counts.remove(&call.id()).flatten();
    if go_request_cancellation(support, go).is_cancelled() {
        return None;
    }
    result.or_else(|| go_nested_arity_miss(support, go))
}

fn go_nested_arity_miss(support: &dyn GoDefinitionProvider, go: &GoAnalyzer) -> Option<usize> {
    // Session and cancellation stops already report through their request.
    if !support.result_shape_execution_stopped()
        && !go_request_cancellation(support, go).is_cancelled()
    {
        go.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceGap(
            "Go nested-call result arity unavailable from selected callable".into(),
        ));
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn go_resolved_call_result_count<'tree>(
    support: &dyn GoDefinitionProvider,
    token: QueryToken<'_>,
    go: &GoAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'tree>,
    call: Node<'tree>,
    argument_count: &dyn Fn(Node<'tree>) -> Option<usize>,
) -> Option<usize> {
    let function = call.child_by_field_name("function")?;
    let count = argument_count(function)?;
    let package = go_package_name(support, file, source, Some(root))?;
    let candidates = match function.kind() {
        "identifier" => {
            let name = go_node_text(function, source);
            if go_nearest_visible_binding(support, root, source, name, call.start_byte()).is_some()
            {
                return None;
            }
            go_unqualified_package_member_candidates(support, token, go, file, &package, name)
        }
        "selector_expression" => {
            let receiver = go_first_named_child(support, function)?;
            let member = go_node_text(go_last_named_child(support, function)?, source);
            if matches!(receiver.kind(), "identifier" | "package_identifier")
                && go_nearest_visible_binding(
                    support,
                    root,
                    source,
                    go_node_text(receiver, source),
                    call.start_byte(),
                )
                .is_none()
                && let Some(import_path) =
                    go_import_paths(support, token, go, file).remove(go_node_text(receiver, source))
            {
                if !go_internal_import_allowed(&package, &import_path) {
                    return None;
                }
                let candidates = go_package_member_candidates(support, &import_path, member);
                if candidates.is_empty() {
                    if go_workspace_package_status(support, &import_path)
                        != GoWorkspacePackageStatus::Absent
                    {
                        return None;
                    }
                    return support
                        .selected_call_result_count(token, file, source, function, count);
                }
                candidates
            } else {
                return support.selected_call_result_count(token, file, source, function, count);
            }
        }
        _ => return None,
    };
    let [candidate] = candidates.as_slice() else {
        return None;
    };
    // A function-valued field or variable is not a resolved callable body.
    // Its declared value type must not be mistaken for the call's result.
    if !candidate.is_function() {
        return None;
    }
    let signatures = support.signature_metadata(go, candidate);
    let [signature] = signatures.as_slice() else {
        return None;
    };
    if !support.scope_step() {
        return None;
    }
    if !go_source_callable_arity(go, support, candidate, signature)?.accepts(count) {
        return None;
    }
    Some(if signature.result_type_identities().is_empty() {
        if signature.return_type_identity().is_none() && signature.return_type_text().is_some() {
            return None;
        }
        usize::from(signature.return_type_identity().is_some())
    } else {
        signature.result_type_identities().len()
    })
}

/// Source declarations may omit callable_arity, but their exact parameter AST
/// still proves grouped, unnamed and variadic formal counts. The receiver is
/// stored in a separate field and never consumes a bound method's actual.
fn go_source_callable_arity(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    target: &CodeUnit,
    signature: &SignatureMetadata,
) -> Option<brokk_bifrost_core::analyzer::model::CallableArity> {
    use brokk_bifrost_core::analyzer::model::CallableArity;
    if let Some(arity) = signature.callable_arity() {
        return Some(arity);
    }
    let source = analyzer.indexed_source(target.source())?;
    let tree = parse_go_tree(&source)?;
    let ranges = analyzer.ranges_of(target);
    let [range] = ranges.as_slice() else {
        return None;
    };
    let callable = tree
        .root_node()
        .named_descendant_for_byte_range(range.start_byte, range.end_byte)?;
    if !matches!(
        callable.kind(),
        "function_declaration" | "method_declaration" | "method_elem" | "func_literal"
    ) || callable.has_error()
    {
        return None;
    }
    let parameters = callable.child_by_field_name("parameters")?;
    let mut total = 0;
    let mut repeated = false;
    for parameter in brokk_bifrost_go::declarations::go_parameter_syntax(parameters) {
        if !support.scope_step() || repeated {
            return None;
        }
        total += parameter.name_nodes.len().max(1);
        repeated = parameter.variadic;
    }
    Some(CallableArity::new(
        total - usize::from(repeated),
        total,
        repeated,
    ))
}

/// A resolved source name is not an applicable callee when its proven actual
/// value count misses its formals. Reuse the modeled-call rejection so every
/// consumer keeps the same explicit no-callee evidence instead of rebinding it.
pub(crate) fn go_source_call_arity_rejection(
    query: brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery<'_>,
    session: &ResolutionSession,
    targets: &[CodeUnit],
    application: CallApplicationKind,
) -> Option<DefinitionLookupOutcome> {
    let [target] = targets else {
        return None;
    };
    if !target.is_function()
        || (target.owner_is_type_scope() && application != CallApplicationKind::BoundReceiver)
    {
        return None;
    }
    let go = resolve_analyzer::<GoAnalyzer>(query.analyzer)?;
    let support =
        AnalyzerGoDefinitionProvider::bounded(go, session, query.analyzer.semantic_model_overlay());
    let tree = query.tree?;
    let scope = AnalyzerQueryScope::new(query.analyzer);
    let count = if let Some(selector) =
        brokk_bifrost_go::references::go_selector_descriptor(tree.root_node(), query.site)
    {
        go_selector_modeled_call_argument_count(
            &support,
            scope.token(),
            go,
            query.file,
            query.source,
            &selector,
        )?
    } else {
        go_identifier_modeled_call_argument_count(
            &support,
            scope.token(),
            go,
            query.file,
            query.source,
            tree.root_node(),
            query.site,
        )?
    };
    let signatures = support.signature_metadata(query.analyzer, target);
    let [signature] = signatures.as_slice() else {
        return None;
    };
    let arity = go_source_callable_arity(query.analyzer, &support, target, signature)?;
    if arity.accepts(count) {
        return None;
    }
    let mut outcome = no_definition(
        GO_MODELED_PACKAGE_CALL_NOT_APPLICABLE_DIAGNOSTIC_KIND,
        format!(
            "`{}` does not accept {count} argument values: {arity:?}",
            target.fq_name()
        ),
    );
    outcome.reference = Some(query.site.clone());
    Some(outcome)
}

fn go_call_for_callable<'tree>(
    support: &dyn GoDefinitionProvider,
    callable: Node<'tree>,
) -> Option<Node<'tree>> {
    if !support.scope_step() {
        return None;
    }
    parent_if_field(callable, "call_expression", "function")
}

fn go_selector_is_call_target(
    support: &dyn GoDefinitionProvider,
    selector: &GoSelectorDescriptor<'_>,
) -> bool {
    if selector.focus_segment == 0 || selector.focus_segment != selector.members.len() {
        return false;
    }
    let Some(callable) = selector.focused_node().parent() else {
        return false;
    };
    matches!(callable.kind(), "selector_expression" | "qualified_type")
        && go_call_for_callable(support, callable).is_some()
}

fn go_identifier_is_call_target(
    support: &dyn GoDefinitionProvider,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
) -> bool {
    go_smallest_named_node_covering(support, root, site.focus_start_byte, site.focus_end_byte)
        .filter(|callable| matches!(callable.kind(), "identifier" | "package_identifier"))
        .is_some_and(|callable| go_call_for_callable(support, callable).is_some())
}

fn go_selector_modeled_call_argument_count(
    support: &dyn GoDefinitionProvider,
    token: QueryToken<'_>,
    go: &GoAnalyzer,
    file: &ProjectFile,
    source: &str,
    selector: &GoSelectorDescriptor<'_>,
) -> Option<usize> {
    if selector.focus_segment == 0 || selector.focus_segment != selector.members.len() {
        return None;
    }
    if !support.scope_step() {
        return None;
    }
    let callable = selector.focused_node().parent()?;
    if !matches!(callable.kind(), "selector_expression" | "qualified_type") || !support.scope_step()
    {
        return None;
    }
    go_callable_modeled_argument_count(support, token, go, file, source, callable)
}

fn go_identifier_modeled_call_argument_count(
    support: &dyn GoDefinitionProvider,
    token: QueryToken<'_>,
    go: &GoAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
) -> Option<usize> {
    let callable =
        go_smallest_named_node_covering(support, root, site.focus_start_byte, site.focus_end_byte)?;
    matches!(callable.kind(), "identifier" | "package_identifier")
        .then_some(())
        .and_then(|()| {
            go_callable_modeled_argument_count(support, token, go, file, source, callable)
        })
}

fn go_nearest_visible_binding<'tree>(
    support: &dyn GoDefinitionProvider,
    root: Node<'tree>,
    source: &str,
    name: &str,
    byte: usize,
) -> Option<GoLocalBinding<'tree>> {
    go_nearest_visible_binding_with_evaluation(
        support,
        root,
        source,
        name,
        byte,
        GoLexicalEvaluation::ordinary(),
    )
}

fn go_nearest_visible_binding_with_evaluation<'tree>(
    support: &dyn GoDefinitionProvider,
    root: Node<'tree>,
    source: &str,
    name: &str,
    byte: usize,
    evaluation: GoLexicalEvaluation,
) -> Option<GoLocalBinding<'tree>> {
    let mut selected_name = name.trim();
    let mut selected_byte = byte;
    let mut scope = go_smallest_named_node_covering(support, root, byte, byte)?;
    loop {
        if !support.scope_step() {
            return None;
        }
        if let Some(binding) = go_nearest_binding_in_scope_with_evaluation(
            support,
            scope,
            source,
            selected_name,
            selected_byte,
            evaluation,
        ) {
            if let GoLocalBinding::SwitchInput(input) = binding
                && input.kind() == "identifier"
            {
                // The case alias retains the operand's declared type, not its
                // most recent assigned value. Follow the same shared binder
                // selection at the header, preserving explicit type syntax.
                // Definition locations still come from native case binders.
                selected_name = go_node_text(input, source);
                selected_byte = input.start_byte();
                scope =
                    go_smallest_named_node_covering(support, root, selected_byte, selected_byte)?;
                continue;
            }
            return Some(binding);
        }
        scope = scope.parent()?;
    }
}

pub(crate) fn go_call_reference_candidate(node: Node<'_>) -> bool {
    match node.parent() {
        Some(parent)
            if parent.kind() == "call_expression"
                && parent.child_by_field_name("function") == Some(node) =>
        {
            true
        }
        Some(parent)
            if parent.kind() == "selector_expression"
                && parent.child_by_field_name("field") == Some(node) =>
        {
            parent.parent().is_some_and(|grandparent| {
                grandparent.kind() == "call_expression"
                    && grandparent.child_by_field_name("function") == Some(parent)
            })
        }
        _ => false,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_definition_dispatch<'a>(
    analyzer: &'a dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
    _token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    _context: &mut brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionBatchContext<
        'a,
        '_,
    >,
    request: &brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupRequest,
    source: &std::sync::Arc<str>,
    tree: &Option<tree_sitter::Tree>,
    site: &brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite,
    _operation: Option<brokk_bifrost_analysis::navigation::NavigationOperation>,
    cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    go_session: Option<
        &brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession,
    >,
    mut definition_batch: Option<&mut GoDefinitionBatchOperation<'a>>,
) -> std::ops::ControlFlow<
    brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionResolution,
    brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionResolution,
> {
    let mut evidence = CallEvidence::default();
    let outcome = {
        let query = brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery {
            analyzer,
            file: &request.file,
            source,
            tree: tree.as_ref(),
            site,
            budget: if go_session.is_some() {
                ReceiverAnalysisBudget::default()
            } else {
                brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET
            },
            cancellation,
        };
        evidence.authority = DefinitionResolutionAuthority::NativeGoSelected;
        let native = definition_batch
            .as_mut()
            .and_then(|batch| batch.resolve(query))
            .unwrap_or_else(|| {
                crate::analyzer::go::native_points::resolve_go_definition_with_evidence_bounded(
                    query,
                    || {},
                )
            });
        match native {
            BoundedResolution::Complete { value, .. } => {
                evidence.source_member_evidence = value.source_member_evidence;
                evidence.native_resolution = value.native_resolution;
                evidence.model_member_selection = value.model_member_selection;
                evidence.call_application = value.call_application;
                evidence.external_callee_identity = value.external_callee_identity;
                if let Some(proof) = value.exact_external_call {
                    evidence.call_application = proof.call_application();
                    evidence.dispatch_extensibility = proof.dispatch_extensibility();
                    evidence.exact_external_call = Some(proof);
                }
                value.outcome
            }
            BoundedResolution::Exceeded { limit, .. } => exceeded_budget(
                limit,
                format!(
                    "Go definition resolution exceeded its {} budget",
                    limit.as_str()
                ),
            ),
            BoundedResolution::Cancelled { .. } => {
                cancelled("Go definition resolution was cancelled")
            }
            BoundedResolution::Unavailable { reason, .. } => {
                brokk_bifrost_analysis::analyzer::native_points::unavailable_definition(
                    site,
                    "native_input_unavailable",
                    reason.into(),
                )
            }
        }
    };
    std::ops::ControlFlow::Continue(DefinitionResolution {
        outcome,
        evidence,
        call_binding_discharge_digests: Vec::new(),
    })
}

pub(crate) struct GoDefinitionBatchOperation<'a> {
    analyzer: &'a dyn IAnalyzer,
    selected_snapshot: Option<
        Option<Arc<brokk_bifrost_analysis::analyzer::semantic_model::ActiveSemanticModelSnapshot>>,
    >,
    request: Option<Box<crate::analyzer::go::native_points::GoNativePointRequest<'a>>>,
    file: Option<ProjectFile>,
    open_reads: Option<brokk_bifrost_analysis::analyzer::usages::common::QueryMemoReads>,
    disabled: bool,
    #[cfg(test)]
    opened_operations: usize,
}

pub(crate) fn definition_batch_resolver<'a>(
    analyzer: &'a dyn IAnalyzer,
) -> Box<dyn DefinitionBatchResolver<'a> + 'a> {
    Box::new(GoDefinitionBatchOperation {
        analyzer,
        selected_snapshot: None,
        request: None,
        file: None,
        open_reads: None,
        disabled: false,
        #[cfg(test)]
        opened_operations: 0,
    })
}

impl<'a> GoDefinitionBatchOperation<'a> {
    fn resolve(
        &mut self,
        query: brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery<'_>,
    ) -> Option<BoundedResolution<crate::analyzer::go::native_points::GoNativeDefinitionResolution>>
    {
        let _model_scope = if let Some(snapshot) = &self.selected_snapshot {
            AnalyzerQueryScope::with_compatible_selected_model_snapshot(
                self.analyzer,
                snapshot.clone(),
            )
        } else {
            let scope = AnalyzerQueryScope::pin_selected_model_snapshot(self.analyzer);
            if scope.is_ok() {
                self.selected_snapshot = Some(crate::analyzer::go::selected_go_model_snapshot(
                    self.analyzer,
                ));
            }
            scope
        };
        let _model_scope = match _model_scope {
            Ok(scope) => scope,
            Err(_) => {
                return Some(
                    crate::analyzer::go::native_points::unavailable_go_definition_open(
                        query,
                        "native_model_authority_stale",
                        "Go batch request conflicts with the outer model selection".into(),
                    ),
                );
            }
        };
        if self.disabled {
            return None;
        }
        if self.file.as_ref().is_some_and(|file| file != query.file) {
            self.request = None;
            self.open_reads = None;
        }
        if self.request.is_none() {
            let go = resolve_analyzer::<GoAnalyzer>(self.analyzer)?;
            let cancellation = query.cancellation.cloned().unwrap_or_default();
            let (opened, reads) =
                brokk_bifrost_analysis::analyzer::usages::common::capture_memo_reads(
                    self.analyzer,
                    || {
                        crate::analyzer::go::native_points::GoNativePointRequest::open_for_file(
                            go,
                            query.file,
                            self.analyzer.semantic_model_overlay(),
                            &cancellation,
                        )
                    },
                );
            match opened {
                Ok(crate::analyzer::go::native_points::GoNativePointRequestOpen::Ready(
                    request,
                )) => {
                    #[cfg(test)]
                    {
                        self.opened_operations += 1;
                    }
                    self.request = Some(request);
                    self.file = Some(query.file.clone());
                    self.open_reads = Some(reads);
                }
                Ok(crate::analyzer::go::native_points::GoNativePointRequestOpen::Unavailable {
                    kind,
                    message,
                }) => {
                    self.disabled = true;
                    return Some(
                        crate::analyzer::go::native_points::unavailable_go_definition_open(
                            query, kind, message,
                        ),
                    );
                }
                Ok(crate::analyzer::go::native_points::GoNativePointRequestOpen::Cancelled) => {
                    return Some(BoundedResolution::Cancelled {
                        work: Default::default(),
                    });
                }
                Err(error) => {
                    self.disabled = true;
                    return Some(
                        crate::analyzer::go::native_points::unavailable_go_definition_open(
                            query,
                            "native_store_error",
                            error.to_string(),
                        ),
                    );
                }
            }
        } else if let Some(reads) = self.open_reads.as_ref() {
            brokk_bifrost_analysis::analyzer::usages::common::replay_memo_reads(
                reads,
                self.analyzer,
            );
        }
        let request = self.request.as_mut().expect("Go batch request opened");
        // Only completed candidate artifacts survive across sites. The owner
        // frontier charge belongs to this site's independent budget.
        request.begin_receiver_query(query.file);
        let result = request.resolve_definition_with_evidence(query);
        let release = request.reader_excludes_store_access()
            || !matches!(&result, BoundedResolution::Complete { value, .. } if !value.outcome.diagnostics.iter().any(|diagnostic| brokk_bifrost_analysis::analyzer::usages::common::is_native_operation_failure(&diagnostic.kind)));
        if release {
            self.request = None;
            self.open_reads = None;
        }
        Some(result)
    }
}

impl<'a> DefinitionBatchResolver<'a> for GoDefinitionBatchOperation<'a> {
    fn release_before_store_read(&mut self) {
        if self
            .request
            .as_ref()
            .is_some_and(|request| request.reader_excludes_store_access())
        {
            self.request = None;
            self.open_reads = None;
        }
    }

    fn precompute(
        &mut self,
        _analyzer: &dyn IAnalyzer,
        _context: &mut DefinitionBatchContext<'_, '_>,
        _requests: &[DefinitionLookupRequest],
        _cancellation: Option<&CancellationToken>,
    ) {
    }

    fn resolve_definition_dispatch(
        &mut self,
        analyzer: &'a dyn IAnalyzer,
        token: QueryToken<'_>,
        context: &mut DefinitionBatchContext<'a, '_>,
        request: &DefinitionLookupRequest,
        source: &Arc<str>,
        tree: &Option<Tree>,
        site: &ResolvedReferenceSite,
        operation: Option<brokk_bifrost_analysis::navigation::NavigationOperation>,
        cancellation: Option<&CancellationToken>,
        go_session: Option<&ResolutionSession>,
    ) -> std::ops::ControlFlow<DefinitionResolution, DefinitionResolution> {
        resolve_definition_dispatch(
            analyzer,
            token,
            context,
            request,
            source,
            tree,
            site,
            operation,
            cancellation,
            go_session,
            Some(self),
        )
    }
}

pub(crate) fn resolve_definition_call_target_batch(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    requests: Vec<DefinitionLookupRequest>,
    file: ProjectFile,
    source: Arc<str>,
    cancellation: Option<&CancellationToken>,
) -> Vec<CallTargetLookupOutcome> {
    let _model_scope = match AnalyzerQueryScope::pin_selected_model_snapshot(analyzer) {
        Ok(scope) => scope,
        Err(_) => {
            analyzer.mark_execution_dependent();
            return Vec::new();
        }
    };
    let scope = AnalyzerQueryScope::new(analyzer);
    let mut context = DefinitionBatchContext::new(analyzer, scope.token());
    context.sources.insert(file.clone(), Ok(source));
    debug_assert!(
        requests.iter().all(|request| request.file == file),
        "one call-target source batch must contain requests for that source file"
    );
    record_definition_batch_probe_reads(analyzer, &mut context, &requests);
    let mut definition_batch = definition_batch_resolver(analyzer);

    requests
        .into_iter()
        .map(|request| {
            let session =
                ResolutionSession::bounded(ReceiverAnalysisBudget::default(), cancellation);
            let resolution = resolve_one_with_evidence(
                analyzer,
                token,
                &mut context,
                request,
                None,
                cancellation,
                Some(&session),
                Some(definition_batch.as_mut()),
            );
            let (resolution, truncated) = match session.finish(()) {
                BoundedResolution::Complete { .. } => (resolution, false),
                BoundedResolution::Exceeded { limit, .. } => (
                    exceeded_budget(
                        limit,
                        format!(
                            "Go call-target resolution exceeded its {} budget",
                            limit.as_str()
                        ),
                    )
                    .into(),
                    true,
                ),
                BoundedResolution::Cancelled { .. } => (
                    cancelled("Go call-target resolution was cancelled").into(),
                    false,
                ),
                BoundedResolution::Unavailable { reason, .. } => {
                    let mut resolution = resolution;
                    resolution.outcome.status = brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus::Unavailable;
                    resolution.outcome.diagnostics.push(brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupDiagnostic {
                        claim: None,
                        kind: "native_input_unavailable".into(),
                        message: reason.into(),
                    });
                    (resolution, false)
                }
            };
            CallTargetLookupOutcome {
                truncated,
                ..CallTargetLookupOutcome::from_resolution(resolution)
            }
        })
        .collect()
}

#[cfg(test)]
mod bounded_tests {

    use crate::analyzer::usages::get_definition::go::*;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::Range;

    use brokk_bifrost_core::path_utils::rel_path_string;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#9015: a Go file batch reopened native selection and context for every call")]
    fn go_many_call_batch_profile() {
        let source = "package main\nimport \"example.com/app/helper\"\nfunc use() {\n    helper.Target()\n    helper.Target()\n    helper.Target()\n    helper.Target()\n    helper.Target()\n    helper.Target()\n    helper.Target()\n    helper.Target()\n}\n";
        let fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[
                ("go.mod", "module example.com/app\n"),
                ("helper/helper.go", "package helper\nfunc Target() {}\n"),
                ("main.go", source),
            ],
        );
        let file = ProjectFile::new(fixture.project_root(), "main.go");
        let requests: Vec<_> = source
            .match_indices("Target()")
            .map(|(start_byte, _)| DefinitionLookupRequest {
                file: file.clone(),
                line: None,
                column: None,
                start_byte: Some(start_byte),
                end_byte: Some(start_byte + "Target".len()),
            })
            .collect();
        assert_eq!(requests.len(), 8);
        let analyzer = fixture.analyzer.analyzer();
        let scope = AnalyzerQueryScope::new(analyzer);
        let outcomes = {
            let _profile =
                brokk_bifrost_core::cache_db::sql_profile::request_scope("go_many_call_batch");
            resolve_definition_call_target_batch(
                analyzer,
                scope.token(),
                requests.clone(),
                file.clone(),
                Arc::from(source),
                None,
            )
        };
        assert_eq!(outcomes.len(), 8);
        assert!(outcomes.iter().all(|result| {
            result.outcome.status == DefinitionLookupStatus::Resolved
                && result.outcome.definitions.len() == 1
        }));

        let mut batch = GoDefinitionBatchOperation {
            analyzer,
            selected_snapshot: None,
            request: None,
            file: None,
            open_reads: None,
            disabled: false,
            opened_operations: 0,
        };
        let mut batch_context = DefinitionBatchContext::new(analyzer, scope.token());
        let mut scalar_context = DefinitionBatchContext::new(analyzer, scope.token());
        batch_context
            .sources
            .insert(file.clone(), Ok(Arc::from(source)));
        scalar_context.sources.insert(file, Ok(Arc::from(source)));
        for request in requests {
            let ((batched, batched_reads), (scalar, scalar_reads)) = (
                brokk_bifrost_analysis::analyzer::capture_query_reads(analyzer, || {
                    resolve_one_with_evidence(
                        analyzer,
                        scope.token(),
                        &mut batch_context,
                        request.clone(),
                        None,
                        None,
                        None,
                        Some(&mut batch),
                    )
                }),
                brokk_bifrost_analysis::analyzer::capture_query_reads(analyzer, || {
                    resolve_one_with_evidence(
                        analyzer,
                        scope.token(),
                        &mut scalar_context,
                        request,
                        None,
                        None,
                        None,
                        None,
                    )
                }),
            );
            assert_eq!(batched.outcome.status, scalar.outcome.status);
            assert_eq!(batched.outcome.definitions, scalar.outcome.definitions);
            assert_eq!(
                format!(
                    "{:?}",
                    batched
                        .evidence
                        .native_resolution
                        .as_ref()
                        .map(|evidence| &evidence.completion)
                ),
                format!(
                    "{:?}",
                    scalar
                        .evidence
                        .native_resolution
                        .as_ref()
                        .map(|evidence| &evidence.completion)
                )
            );
            assert_eq!(
                format!("{:?}", batched.evidence.source_member_evidence),
                format!("{:?}", scalar.evidence.source_member_evidence)
            );
            assert_eq!(
                format!("{:?}", batched.evidence.model_member_selection),
                format!("{:?}", scalar.evidence.model_member_selection)
            );
            assert_eq!(
                format!("{:?}", batched.outcome.diagnostics),
                format!("{:?}", scalar.outcome.diagnostics)
            );
            assert_eq!(batched_reads.keys(), scalar_reads.keys());
            assert_eq!(
                batched_reads.unattributed_reads(),
                scalar_reads.unattributed_reads()
            );
            assert_eq!(
                batched_reads.execution_dependences(),
                scalar_reads.execution_dependences()
            );
        }
        assert_eq!(batch.opened_operations, 1);
        assert_eq!(
            batch
                .request
                .as_ref()
                .expect("retained Go operation")
                .prepared_file_contexts_for_test(),
            1
        );
    }

    fn site_for(
        file: &ProjectFile,
        source: &str,
        expression: &str,
        focus: &str,
    ) -> ResolvedReferenceSite {
        let expression_start = source.rfind(expression).expect("Go expression");
        let relative_focus = expression.find(focus).expect("Go focus");
        let start_byte = expression_start + relative_focus;
        let end_byte = start_byte + focus.len();
        let start_line = source[..start_byte]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1;
        ResolvedReferenceSite {
            path: rel_path_string(file),
            text: focus.to_string(),
            range: Range {
                start_byte,
                end_byte,
                start_line,
                end_line: start_line,
            },
            focus_start_byte: start_byte,
            focus_end_byte: end_byte,
        }
    }

    fn indexed_go_function_at_start(
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        source: &str,
        marker: &str,
    ) -> CodeUnit {
        let start = source.find(marker).expect("Go function marker");
        analyzer
            .get_declarations(file)
            .into_iter()
            .find(|unit| {
                unit.is_function()
                    && analyzer
                        .ranges_of(unit)
                        .into_iter()
                        .any(|range| range.start_byte == start)
            })
            .unwrap_or_else(|| panic!("indexed function starts at {start}: {marker}"))
    }

    fn activate_selector_navigation_overlay(fixture: &AnalyzerFixture) {
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            CatalogCoordinate, SemanticModelActivationControl, SemanticModelActivationEvidence,
            SemanticModelActivationRequest, SemanticModelControlAction, SemanticModelControlScope,
            SemanticModelPackSelector, SemanticModelRuntimeLimits,
        };

        let source = serde_json::to_vec(&serde_json::json!({
            "schema_version": 2,
            "pack_id": "fixture.go.selector-navigation",
            "version": "1.0.0",
            "producer": { "name": "go-selector-fixture", "version": "1.0.0" },
            "language": "go",
            "ecosystem": "go-module",
            "compatibility": { "bifrost": "*", "toolchains": [] },
            "provenance": { "source": "fixture" },
            "license": "NOASSERTION",
            "completeness": "complete",
            "safety": { "generated_code_only": false, "review_required": false },
            "shards": [{
                "id": "declarations.fixture.go.selector-navigation",
                "activation": [{ "module": { "name": "example.com/mod" } }],
                "payload": {
                    "kind": "declaration_facts",
                    "types": [
                        {
                            "id": "type.fixture.go.package",
                            "name": "example.com/mod",
                            "type_kind": "module",
                            "visibility": "package",
                            "aliases": ["mod"],
                            "locator": {
                                "kind": "artifact",
                                "path": "api.go",
                                "symbol": "example.com/mod"
                            }
                        },
                        {
                            "id": "type.fixture.go.module-scope",
                            "name": "example.com/mod._module_",
                            "type_kind": "module",
                            "visibility": "package",
                            "locator": {
                                "kind": "artifact",
                                "path": "api.go",
                                "symbol": "example.com/mod._module_"
                            }
                        },
                        {
                            "id": "type.fixture.go.concrete",
                            "name": "example.com/mod.Concrete",
                            "type_kind": "struct",
                            "visibility": "public",
                            "locator": {
                                "kind": "artifact",
                                "path": "api.go",
                                "symbol": "example.com/mod.Concrete"
                            }
                        },
                        {
                            "id": "type.fixture.go.hidden",
                            "name": "example.com/mod.hidden",
                            "type_kind": "struct",
                            "visibility": "private",
                            "locator": {
                                "kind": "artifact",
                                "path": "api.go",
                                "symbol": "example.com/mod.hidden"
                            }
                        }
                    ],
                    "members": [
                        {
                            "id": "member.fixture.go.concrete.read",
                            "owner": "type.fixture.go.concrete",
                            "name": "Read",
                            "member_kind": "method",
                            "visibility": "public",
                            "signature": { "parameters": [] },
                            "receiver": { "pointer": false },
                            "locator": {
                                "kind": "artifact",
                                "path": "api.go",
                                "symbol": "example.com/mod.Concrete.Read"
                            }
                        },
                        {
                            "id": "member.fixture.go.hidden.read",
                            "owner": "type.fixture.go.hidden",
                            "name": "Read",
                            "member_kind": "method",
                            "visibility": "public",
                            "signature": { "parameters": [] },
                            "receiver": { "pointer": false },
                            "locator": {
                                "kind": "artifact",
                                "path": "api.go",
                                "symbol": "example.com/mod.hidden.Read"
                            }
                        },
                        {
                            "id": "member.fixture.go.module-scope.exported-var",
                            "owner": "type.fixture.go.module-scope",
                            "name": "ExportedVar",
                            "member_kind": "field",
                            "visibility": "public",
                            "is_static": true,
                            "locator": {
                                "kind": "artifact",
                                "path": "api.go",
                                "symbol": "example.com/mod._module_.ExportedVar"
                            }
                        },
                        {
                            "id": "member.fixture.go.module-scope.exported-const",
                            "owner": "type.fixture.go.module-scope",
                            "name": "ExportedConst",
                            "member_kind": "constant",
                            "visibility": "public",
                            "is_static": true,
                            "locator": {
                                "kind": "artifact",
                                "path": "api.go",
                                "symbol": "example.com/mod._module_.ExportedConst"
                            }
                        },
                        {
                            "id": "member.fixture.go.package.ambiguous",
                            "owner": "type.fixture.go.package",
                            "name": "Ambiguous",
                            "member_kind": "constant",
                            "visibility": "public",
                            "is_static": true,
                            "locator": {
                                "kind": "artifact",
                                "path": "api.go",
                                "symbol": "example.com/mod.Ambiguous"
                            }
                        },
                        {
                            "id": "member.fixture.go.module-scope.ambiguous",
                            "owner": "type.fixture.go.module-scope",
                            "name": "Ambiguous",
                            "member_kind": "constant",
                            "visibility": "public",
                            "is_static": true,
                            "locator": {
                                "kind": "artifact",
                                "path": "api.go",
                                "symbol": "example.com/mod._module_.Ambiguous"
                            }
                        }
                    ],
                    "relations": []
                }
            }]
        }))
        .expect("serialize Go selector fixture");
        let request = SemanticModelActivationRequest {
            approximate_standard_libraries: Vec::new(),
            bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION"))
                .expect("crate version"),
            evidence: vec![SemanticModelActivationEvidence {
                language: "go".to_owned(),
                ecosystem: "go-module".to_owned(),
                package: None,
                module: Some(CatalogCoordinate {
                    name: "example.com/mod".to_owned(),
                    version: None,
                }),
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            }],
            controls: vec![SemanticModelActivationControl {
                scope: SemanticModelControlScope::Workspace,
                action: SemanticModelControlAction::Enable,
                selector: SemanticModelPackSelector {
                    pack_id: "fixture.go.selector-navigation".to_owned(),
                    version: None,
                    manifest_digest: None,
                },
            }],
            limits: SemanticModelRuntimeLimits::default(),
        };
        brokk_bifrost_analysis::analyzer::usages::test_support::activate_semantic_pack(
            fixture.analyzer.analyzer(),
            "fixture.go.selector-navigation",
            &source,
            &request,
        );
    }

    #[test]
    fn bounded_workspace_package_status_uses_exact_relational_authority() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[
                ("go.mod", "module example.com/app\n"),
                ("service/service.go", "package service\n"),
                ("vendor/example.com/dep/pkg/pkg.go", "package pkg\n"),
                (
                    "vendor/outer/vendor/nested.example/dep/pkg/pkg.go",
                    "package pkg\n",
                ),
                ("myvendor/example.com/fake/pkg/pkg.go", "package pkg\n"),
                ("mixed/a_external_test.go", "package mixed_test\n"),
                ("mixed/z_internal_test.go", "package mixed\n"),
                ("main.go", "package main\n"),
            ],
        );
        let go = resolve_analyzer::<GoAnalyzer>(fixture.analyzer.analyzer())
            .expect("fixture Go analyzer");
        assert_eq!(go.workspace_path_index_build_count_for_test(), 0);

        let expected_packages = [
            ("example.com/app/service", GoWorkspacePackageStatus::Present),
            ("example.com/dep/pkg", GoWorkspacePackageStatus::Present),
            ("example.com/dep", GoWorkspacePackageStatus::Absent),
            ("nested.example/dep/pkg", GoWorkspacePackageStatus::Present),
            ("nested.example/dep", GoWorkspacePackageStatus::Absent),
            (
                "example.com/app/myvendor/example.com/fake/pkg",
                GoWorkspacePackageStatus::Present,
            ),
            ("example.com/app/mixed", GoWorkspacePackageStatus::Present),
            (
                "example.com/app/mixed_test",
                GoWorkspacePackageStatus::Present,
            ),
            ("example.com/fake/pkg", GoWorkspacePackageStatus::Absent),
            ("os", GoWorkspacePackageStatus::Absent),
        ];
        for (import_path, expected) in expected_packages {
            let session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
            let status = AnalyzerGoDefinitionProvider::bounded(go, &session, None)
                .workspace_package_status(import_path);
            match session.finish(status) {
                BoundedResolution::Complete { value, .. } => {
                    assert_eq!(value, expected, "{import_path}")
                }
                outcome => panic!("{import_path} package query did not complete: {outcome:#?}"),
            }
            assert_eq!(
                go.workspace_path_index_build_count_for_test(),
                0,
                "a bounded package point lookup must not initialize the all-files index"
            );
        }

        let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
            Arc::new(fixture.test_project().clone()),
        ));
        let main = ProjectFile::new(fixture.project_root(), "main.go");
        assert!(overlay.set(
            main.abs_path().to_path_buf(),
            "package main\n// unsaved request snapshot\n".to_owned(),
        ));
        let request_snapshot = go
            .clone_with_project(overlay as Arc<dyn brokk_bifrost_core::analyzer::project::Project>);
        for (import_path, expected) in [
            ("example.com/app/service", GoWorkspacePackageStatus::Present),
            ("example.com/dep/pkg", GoWorkspacePackageStatus::Present),
            ("os", GoWorkspacePackageStatus::Unknown),
        ] {
            let session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
            let status = AnalyzerGoDefinitionProvider::bounded(&request_snapshot, &session, None)
                .workspace_package_status(import_path);
            match session.finish(status) {
                BoundedResolution::Complete { value, .. } => {
                    assert_eq!(value, expected, "overlaid {import_path}")
                }
                outcome => {
                    panic!("overlaid {import_path} package query did not complete: {outcome:#?}")
                }
            }
        }
        assert_eq!(
            request_snapshot.workspace_path_index_build_count_for_test(),
            0,
            "an incomplete request snapshot still uses relational point queries"
        );

        let module_overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
            Arc::new(fixture.test_project().clone()),
        ));
        let go_mod = ProjectFile::new(fixture.project_root(), "go.mod");
        assert!(module_overlay.set(
            go_mod.abs_path().to_path_buf(),
            "module example.com/unsaved\n".to_owned(),
        ));
        let module_request = go.clone_with_project(
            module_overlay as Arc<dyn brokk_bifrost_core::analyzer::project::Project>,
        );
        let session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
        let status = AnalyzerGoDefinitionProvider::bounded(&module_request, &session, None)
            .workspace_package_status("os");
        assert!(matches!(
            session.finish(status),
            BoundedResolution::Complete {
                value: GoWorkspacePackageStatus::Unknown,
                ..
            }
        ));
        assert_eq!(
            module_request.workspace_path_index_build_count_for_test(),
            0,
            "an overlaid go.mod must make misses unknown without building the path index"
        );

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let cancelled_session =
            ResolutionSession::bounded(ReceiverAnalysisBudget::default(), Some(&cancellation));
        assert_eq!(
            AnalyzerGoDefinitionProvider::bounded(go, &cancelled_session, None)
                .workspace_package_status("os"),
            GoWorkspacePackageStatus::Unknown
        );
        assert!(matches!(
            cancelled_session.finish(()),
            BoundedResolution::Cancelled { .. }
        ));
        assert_eq!(
            go.workspace_path_index_build_count_for_test(),
            0,
            "a cancelled package point lookup must not initialize the all-files index"
        );

        let unbounded = AnalyzerGoDefinitionProvider::new(go, None);
        for (import_path, expected) in expected_packages {
            assert_eq!(
                unbounded.workspace_package_status(import_path),
                expected,
                "unbounded package parity for {import_path}"
            );
        }
        assert_eq!(
            go.workspace_path_index_build_count_for_test(),
            1,
            "all unbounded exact package checks share one path index"
        );
    }

    #[test]
    fn internal_import_access_uses_the_canonical_import_path_prefix() {
        assert!(go_internal_import_allowed(
            "example.com/owner/consumer",
            "example.com/owner/internal/api"
        ));
        assert!(go_internal_import_allowed(
            "example.com/owner",
            "example.com/owner/internal/api"
        ));
        assert!(!go_internal_import_allowed(
            "example.com/other/consumer",
            "example.com/owner/internal/api"
        ));
        assert!(!go_internal_import_allowed(
            "example.com/ownerish/consumer",
            "example.com/owner/internal/api"
        ));
        assert!(!go_internal_import_allowed(
            "example.com/owner",
            "internal/api"
        ));
        assert!(!go_internal_import_allowed(
            "example.com/owner/consumer",
            "example.com/owner/internal/nested/internal/api"
        ));
        assert!(go_internal_import_allowed(
            "example.com/owner/internal/nested/consumer",
            "example.com/owner/internal/nested/internal/api"
        ));
    }

    #[hardwon(
        "5c5d4e214494: const and grouped-var bindings follow Go scope when shadowing imports"
    )]
    #[test]
    fn go_const_and_grouped_var_bindings_obey_spec_scope_for_import_shadowing() {
        for (label, source, marker, expected_shadow) in [
            (
                "const own initializer",
                "package main\n\nimport os \"example.com/external\"\n\nfunc use() {\n    const os = os.O_RDONLY\n    _ = os\n}\n",
                "os.O_RDONLY",
                false,
            ),
            (
                "const after spec",
                "package main\n\nimport os \"example.com/external\"\n\nfunc use() {\n    const os = 1\n    _ = os.Open\n}\n",
                "os.Open",
                true,
            ),
            (
                "earlier grouped const spec",
                "package main\n\nimport os \"example.com/external\"\n\nfunc use() {\n    const (\n        os = 1\n        later = os.Open\n    )\n    _ = later\n}\n",
                "os.Open",
                true,
            ),
            (
                "grouped local const after declaration",
                "package main\n\nimport os \"example.com/external\"\n\nfunc use() {\n    const (\n        os = 1\n        later = 2\n    )\n    _ = os.Open\n}\n",
                "os.Open",
                true,
            ),
            (
                "earlier grouped var spec",
                "package main\n\nimport os \"example.com/external\"\n\nfunc use() {\n    var (\n        os = 1\n        later = os.Open\n    )\n    _, _ = os, later\n}\n",
                "os.Open",
                true,
            ),
            (
                "package const beneath file import",
                "package main\n\nimport os \"example.com/external\"\n\nconst os = 1\n\nfunc use() {\n    _ = os.Open\n}\n",
                "os.Open",
                false,
            ),
            (
                "package grouped const later initializer",
                "package main\n\nimport os \"example.com/external\"\n\nconst (\n    os = 1\n    later = os.Open\n)\n",
                "os.Open",
                false,
            ),
            (
                "package grouped var later initializer",
                "package main\n\nimport os \"example.com/external\"\n\nvar (\n    os = 1\n    later = os.Open\n)\n",
                "os.Open",
                false,
            ),
        ] {
            let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", source)]);
            let go = resolve_analyzer::<GoAnalyzer>(fixture.analyzer.analyzer())
                .expect("fixture Go analyzer");
            let provider = AnalyzerGoDefinitionProvider::new(go, None);
            let tree = parse_go_tree(source).expect("Go tree");
            let byte = source.find(marker).expect("shadowing marker");
            let binding =
                go_nearest_visible_binding(&provider, tree.root_node(), source, "os", byte);
            assert_eq!(binding.is_some(), expected_shadow, "{label}");
        }
    }

    #[test]
    fn go_import_declarations_persist_structured_paths() {
        let source = r#"
package main
import (
    svc "example.com/app/service"
    . `example.com/app/model`
)
"#;
        let tree = parse_go_tree(source).expect("Go tree");
        let imports =
            brokk_bifrost_go::declarations::collect_go_import_infos(tree.root_node(), source);

        assert_eq!(imports.len(), 2);
        // A Go import path is stored one '/'-separated component per segment,
        // so consumers rejoin it with `render_segments("/")` instead of taking
        // segment zero as the whole path.
        assert_eq!(
            imports[0]
                .path
                .as_ref()
                .map(|path| path.segments.as_slice()),
            Some(
                [
                    "example.com".to_string(),
                    "app".to_string(),
                    "service".to_string()
                ]
                .as_slice()
            )
        );
        assert_eq!(
            imports[1]
                .path
                .as_ref()
                .map(|path| path.render_segments("/")),
            Some("example.com/app/model".to_string())
        );
    }

    #[hardwon(
        "5c5d4e214494: go.mod edits reproject package identity and invalidate cached resolution state"
    )]
    #[test]
    fn go_mod_update_reprojects_workspace_package_identity() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[
                ("go.mod", "module example.com/old\n"),
                ("pkg/pkg.go", "package pkg\n\nfunc Kept() {}\n"),
            ],
        );
        let go = resolve_analyzer::<GoAnalyzer>(fixture.analyzer.analyzer())
            .expect("fixture Go analyzer");
        let go_mod = ProjectFile::new(fixture.project_root(), "go.mod");
        let full_updates =
            brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::full_update_count_for_test(
                &fixture.project_root(),
            );
        go_mod.write("go 1.26\n").unwrap();
        let invalid = go.update(&std::collections::BTreeSet::from([go_mod.clone()]));
        for (import_path, expected) in [
            ("example.com/old/pkg", GoWorkspacePackageStatus::Present),
            ("example.com/new/pkg", GoWorkspacePackageStatus::Unknown),
        ] {
            let session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
            let status = AnalyzerGoDefinitionProvider::bounded(&invalid, &session, None)
                .workspace_package_status(import_path);
            assert!(matches!(
                session.finish(status),
                BoundedResolution::Complete { value, .. } if value == expected
            ));
        }
        assert_eq!(invalid.workspace_path_index_build_count_for_test(), 0);

        go_mod.write("module example.com/new\n").unwrap();
        let updated = invalid.update(&std::collections::BTreeSet::from([go_mod.clone()]));
        assert_eq!(
            brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::full_update_count_for_test(
                &fixture.project_root()
            ),
            full_updates + 2,
            "losing and then changing the module path must each rebuild"
        );

        for (import_path, expected) in [
            ("example.com/new/pkg", GoWorkspacePackageStatus::Present),
            ("example.com/old/pkg", GoWorkspacePackageStatus::Absent),
        ] {
            let session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
            let status = AnalyzerGoDefinitionProvider::bounded(&updated, &session, None)
                .workspace_package_status(import_path);
            assert!(matches!(
                session.finish(status),
                BoundedResolution::Complete { value, .. } if value == expected
            ));
        }
        assert_eq!(
            updated.workspace_path_index_build_count_for_test(),
            0,
            "module-path reprojection must retain exact relational authority"
        );

        // A require-only edit keeps the module path, so it rekeys no
        // declaration: the update stays incremental, moves the byte baseline
        // that content-keyed caches and overlay authority read, and publishes
        // what a fresh build of the edited tree publishes.
        go_mod
            .write("module example.com/new\n\nrequire example.com/dep v1.2.3\n")
            .unwrap();
        let required = updated.update(&std::collections::BTreeSet::from([go_mod]));
        assert_eq!(
            brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::full_update_count_for_test(
                &fixture.project_root()
            ),
            full_updates + 2,
            "a require-only go.mod edit must not rebuild the workspace"
        );
        assert_ne!(
            required.workspace_content_identity(),
            updated.workspace_content_identity()
        );
        let fresh_workspace = brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer::build_ephemeral_footgun(
            std::sync::Arc::new(fixture.test_project().clone()),
            brokk_bifrost_core::analyzer::config::AnalyzerConfig::default(),
        )
        .expect("fresh workspace");
        let fresh =
            resolve_analyzer::<GoAnalyzer>(fresh_workspace.analyzer()).expect("fresh Go analyzer");
        assert_eq!(
            required.workspace_content_identity(),
            fresh.workspace_content_identity()
        );
        let definition_names = |go: &GoAnalyzer| {
            go.get_definitions("example.com/new/pkg.Kept")
                .iter()
                .map(|unit| (unit.fq_name(), unit.source().clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(definition_names(&required).len(), 1);
        assert_eq!(definition_names(&required), definition_names(fresh));
        for import_path in ["example.com/new/pkg", "example.com/old/pkg"] {
            let status = |go: &GoAnalyzer| {
                let session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
                let status = AnalyzerGoDefinitionProvider::bounded(go, &session, None)
                    .workspace_package_status(import_path);
                match session.finish(status) {
                    BoundedResolution::Complete { value, .. } => value,
                    other => panic!("{import_path} must resolve completely: {other:?}"),
                }
            };
            assert_eq!(status(&required), status(fresh), "{import_path}");
        }
    }

    #[hardwon(
        "c51b249c4f34: parameter binding uses exact callable spans and preserves descriptor copies"
    )]
    #[test]
    fn go_parameter_binding_uses_exact_callable_spans_and_preserves_descriptor_copies() {
        let source = r#"package main
type Cell struct{}
type Other struct{}
func Values(first, second *Cell, value Cell, slice []int, mapping map[int]int, channel chan int, callback func(), boxed interface{}, array [1]int, unknown Missing) {}
func (Cell) Same(value *Cell) {}
func (Other) Same(value Cell) {}
func init() {
    _ = func(value *Cell) {}
    _ = func(value Cell) {}
}
"#;
        let file = ProjectFile::new(std::env::temp_dir(), "parameter-binding.go");
        let tree = parse_tree_for_language(&file, Language::Go, source).expect("Go fixture parses");
        let mut pending = vec![tree.root_node()];
        let mut callables = Vec::new();
        while let Some(node) = pending.pop() {
            if matches!(
                node.kind(),
                "function_declaration" | "method_declaration" | "func_literal"
            ) {
                callables.push(node);
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
        callables.sort_by_key(Node::start_byte);
        let expected = [
            vec![
                Some(true),
                Some(true),
                Some(false),
                Some(false),
                Some(false),
                Some(false),
                Some(false),
                Some(false),
                Some(false),
                None,
            ],
            vec![Some(true)],
            vec![Some(false)],
            vec![],
            vec![Some(true)],
            vec![Some(false)],
        ];
        let backing_expected = [
            vec![
                Some(false),
                Some(false),
                Some(false),
                Some(true),
                Some(true),
                Some(true),
                Some(false),
                Some(false),
                Some(false),
                None,
            ],
            vec![Some(false)],
            vec![Some(false)],
            vec![],
            vec![Some(false)],
            vec![Some(false)],
        ];
        assert_eq!(callables.len(), expected.len());
        assert_eq!(callables.len(), backing_expected.len());
        for ((callable, expected), backing_expected) in
            callables.into_iter().zip(expected).zip(backing_expected)
        {
            for (ordinal, (expected, backing_expected)) in expected
                .into_iter()
                .chain([None])
                .zip(backing_expected.into_iter().chain([None]))
                .enumerate()
            {
                assert_eq!(
                    parameter_binds_by_reference_at_span(
                        &file,
                        source,
                        callable.start_byte(),
                        callable.end_byte(),
                        ordinal
                    ),
                    expected,
                    "exact callable {:?}, ordinal {ordinal}",
                    callable.range()
                );
                assert_eq!(
                    parameter_preserves_backing_at_span(
                        &file,
                        source,
                        callable.start_byte(),
                        callable.end_byte(),
                        ordinal
                    ),
                    backing_expected,
                    "exact callable {:?}, backing ordinal {ordinal}",
                    callable.range()
                );
            }
            assert_eq!(
                parameter_binds_by_reference_at_span(
                    &file,
                    source,
                    callable.start_byte(),
                    callable.end_byte() - 1,
                    0
                ),
                None
            );
            assert_eq!(
                parameter_preserves_backing_at_span(
                    &file,
                    source,
                    callable.start_byte(),
                    callable.end_byte() - 1,
                    0
                ),
                None
            );
        }
        let recovery = "package main\nfunc broken(value *Cell) { @ }";
        assert_eq!(
            parameter_binds_by_reference_at_span(&file, recovery, 13, recovery.len(), 0),
            None
        );
        assert_eq!(
            parameter_preserves_backing_at_span(&file, recovery, 13, recovery.len(), 0),
            None
        );
    }

    #[hardwon(
        "18b213945166: parameter references use exact result ordinals and do not treat shadowed primitives as builtins"
    )]
    #[test]
    fn go_parameter_reference_free_uses_exact_ordinals_and_unshadowed_primitives() {
        let source = r#"package main

type Cell struct{}
type Alias = int
type Box[T any] struct{}
type Left struct{}
type Right struct{}

func Values(first, second int, flag bool, text string, pointer *Cell, slice []int, values map[int]int, channel chan int, callback func(), boxed interface{}, aggregate struct{}, array [1]int) {}
func AliasParameter(value Alias) {}
func Variadic(values ...int) {}
func Generic[T any](value T) {}
func (box Box[T]) GenericReceiver(value int) {}
func (Left) Build(value int) {}
func (Right) Build(value *Cell) {}
"#;
        let fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[("go.mod", "module example.com/app\n"), ("main.go", source)],
        );
        let analyzer = fixture.analyzer.analyzer();
        let file = ProjectFile::new(fixture.project_root(), "main.go");

        let values = indexed_go_function_at_start(analyzer, &file, source, "func Values(");
        for (ordinal, expected) in [
            (0, Some(true)), // first
            (1, Some(true)), // second, grouped with first
            (2, Some(true)), // bool
            (3, None),       // string
            (4, None),       // pointer
            (5, None),       // slice
            (6, None),       // map
            (7, None),       // channel
            (8, None),       // function
            (9, None),       // interface
            (10, None),      // struct
            (11, None),      // array
            (12, None),      // out of range
        ] {
            assert_eq!(
                parameter_is_reference_free_at_ordinal(analyzer, &file, source, &values, ordinal,),
                expected,
                "Values parameter ordinal {ordinal}",
            );
        }

        for (marker, expected, reason) in [
            ("func AliasParameter(", None, "named alias"),
            ("func Variadic(", None, "variadic parameter"),
            ("func Generic[", None, "type parameter"),
            (
                "func (box Box[T]) GenericReceiver(",
                None,
                "generic receiver",
            ),
        ] {
            let function = indexed_go_function_at_start(analyzer, &file, source, marker);
            assert_eq!(
                parameter_is_reference_free_at_ordinal(analyzer, &file, source, &function, 0),
                expected,
                "{reason}",
            );
        }

        let left = indexed_go_function_at_start(analyzer, &file, source, "func (Left) Build(");
        let right = indexed_go_function_at_start(analyzer, &file, source, "func (Right) Build(");
        assert_eq!(
            parameter_is_reference_free_at_ordinal(analyzer, &file, source, &left, 0),
            Some(true),
            "the exact Left.Build declaration has a primitive parameter",
        );
        assert_eq!(
            parameter_is_reference_free_at_ordinal(analyzer, &file, source, &right, 0),
            None,
            "the exact Right.Build declaration has a pointer parameter",
        );

        let shadowed_source = r#"package main

type Cell struct{}
type int *Cell

func Shadowed(value int) {}
"#;
        let shadowed_fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[
                ("go.mod", "module example.com/app\n"),
                ("main.go", shadowed_source),
            ],
        );
        let shadowed_analyzer = shadowed_fixture.analyzer.analyzer();
        let shadowed_file = ProjectFile::new(shadowed_fixture.project_root(), "main.go");
        let shadowed = indexed_go_function_at_start(
            shadowed_analyzer,
            &shadowed_file,
            shadowed_source,
            "func Shadowed(",
        );
        assert_eq!(
            parameter_is_reference_free_at_ordinal(
                shadowed_analyzer,
                &shadowed_file,
                shadowed_source,
                &shadowed,
                0,
            ),
            None,
            "a package declaration shadowing int must stay unknown",
        );
    }

    #[hardwon(
        "78664013705a: unsupported and recovered result types abstain without guessed receiver identity"
    )]
    #[test]
    fn go_result_binding_abstains_on_aliases_generics_type_parameters_and_recovery() {
        let source = r#"package main

type NamedSlice []byte
type Alias = []byte
type GenericBox[T any] struct{}

func AliasResult() Alias { return nil }
func NamedSliceResult() NamedSlice { return nil }
func GenericResult() GenericBox[int] { return GenericBox[int]{} }
func GenericPointer() *GenericBox[int] { return nil }
func GenericSlice() []GenericBox[int] { return nil }
func TypeParameterShadow[Shadow any]() Shadow {
    var zero Shadow
    return zero
}
func (box GenericBox[T]) GenericReceiver() NamedSlice { return nil }
func Recovery() *NamedSlice {
    @@@
    return nil
}
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", source)]);
        let analyzer = fixture.analyzer.analyzer();
        let file = ProjectFile::new(fixture.project_root(), "main.go");

        for (marker, expected, reason) in [
            ("func AliasResult()", None, "type alias"),
            ("func NamedSliceResult()", Some(true), "direct named slice"),
            ("func GenericResult()", None, "instantiated generic nominal"),
            (
                "func GenericPointer()",
                Some(true),
                "pointer outer shape remains known with a generic element",
            ),
            (
                "func GenericSlice()",
                Some(true),
                "slice outer shape remains known with a generic element",
            ),
            ("func TypeParameterShadow", None, "type parameter shadowing"),
            (
                "func (box GenericBox[T]) GenericReceiver()",
                None,
                "generic receiver",
            ),
            ("func Recovery()", None, "parser recovery"),
        ] {
            let function = indexed_go_function_at_start(analyzer, &file, source, marker);
            assert_eq!(
                result_binds_by_reference_at_ordinal(analyzer, &file, source, &function, 0),
                expected,
                "{reason}",
            );
        }
    }

    #[hardwon("78664013705a: result binding follows the selected Go return ordinal")]
    #[test]
    fn go_result_binding_modes_follow_exact_result_ordinals() {
        let source = r#"package main

type NamedStruct struct{}

func Shapes() (*NamedStruct, struct{}, [2]byte, []byte, map[string]int, chan int) {
    return nil, struct{}{}, [2]byte{}, nil, nil, nil
}
func NamedValue() NamedStruct { return NamedStruct{} }
func Scalar() int { return 0 }
func Grouped() (first, second []byte, third [2]byte, fourth, fifth struct{}) {
    return nil, nil, [2]byte{}, struct{}{}, struct{}{}
}
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", source)]);
        let analyzer = fixture.analyzer.analyzer();
        let file = ProjectFile::new(fixture.project_root(), "main.go");

        let shapes = indexed_go_function_at_start(analyzer, &file, source, "func Shapes()");
        for (ordinal, expected) in [
            (0, Some(true)),  // pointer
            (1, Some(false)), // struct
            (2, Some(false)), // array
            (3, Some(true)),  // slice
            (4, Some(true)),  // map
            (5, Some(true)),  // channel
            (6, None),        // out of range
        ] {
            assert_eq!(
                result_binds_by_reference_at_ordinal(analyzer, &file, source, &shapes, ordinal,),
                expected,
                "Shapes result ordinal {ordinal}",
            );
        }

        let named = indexed_go_function_at_start(analyzer, &file, source, "func NamedValue()");
        assert_eq!(
            result_binds_by_reference_at_ordinal(analyzer, &file, source, &named, 0),
            Some(false),
            "a direct same-file named struct is inline",
        );

        let scalar = indexed_go_function_at_start(analyzer, &file, source, "func Scalar()");
        assert_eq!(
            result_binds_by_reference_at_ordinal(analyzer, &file, source, &scalar, 0),
            None,
            "a scalar result has no proven reference or inline aggregate shape",
        );
        assert_eq!(
            result_binds_by_reference_at_ordinal(analyzer, &file, source, &scalar, 1),
            None,
            "a scalar result has no ordinal one",
        );

        let grouped = indexed_go_function_at_start(analyzer, &file, source, "func Grouped()");
        for (ordinal, expected) in [
            (0, Some(true)),  // first
            (1, Some(true)),  // second, grouped with first
            (2, Some(false)), // third
            (3, Some(false)), // fourth
            (4, Some(false)), // fifth, grouped with fourth
            (5, None),        // out of range
        ] {
            assert_eq!(
                result_binds_by_reference_at_ordinal(analyzer, &file, source, &grouped, ordinal,),
                expected,
                "Grouped result ordinal {ordinal}",
            );
        }
    }

    #[hardwon("78664013705a: same-named methods use the exact declaration identity")]
    #[test]
    fn go_result_binding_uses_exact_same_named_method_declaration() {
        let source = r#"package main

type Left struct{}
type Right struct{}

func (Left) Build() []byte { return nil }
func (Right) Build() struct{} { return struct{}{} }
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", source)]);
        let analyzer = fixture.analyzer.analyzer();
        let file = ProjectFile::new(fixture.project_root(), "main.go");
        let left = indexed_go_function_at_start(analyzer, &file, source, "func (Left) Build()");
        let right = indexed_go_function_at_start(analyzer, &file, source, "func (Right) Build()");

        assert_eq!(
            result_binds_by_reference_at_ordinal(analyzer, &file, source, &left, 0),
            Some(true),
            "the Left.Build declaration returns a slice",
        );
        assert_eq!(
            result_binds_by_reference_at_ordinal(analyzer, &file, source, &right, 0),
            Some(false),
            "the Right.Build declaration returns a struct",
        );
    }

    #[hardwon(
        "43a2c41d9d02: partial Go snapshots preserve valid declarations and keep missing packages unknown"
    )]
    #[test]
    fn partial_go_workspace_snapshot_keeps_valid_declarations_and_unknown_absence() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[
                ("go.mod", "module example.com/app\n"),
                ("valid/valid.go", "package valid\n\nfunc Kept() {}\n"),
                ("broken/broken.go", "\0not parseable source"),
            ],
        );
        let go = resolve_analyzer::<GoAnalyzer>(fixture.analyzer.analyzer())
            .expect("fixture Go analyzer");
        let valid_file = ProjectFile::new(fixture.project_root(), "valid/valid.go");
        let definitions = go.get_definitions("example.com/app/valid.Kept");
        let [definition] = definitions.as_slice() else {
            panic!(
                "the valid blob must remain published in the partial snapshot: {definitions:#?}"
            );
        };
        assert_eq!(definition.source(), &valid_file);

        for (import_path, expected) in [
            ("example.com/app/valid", GoWorkspacePackageStatus::Present),
            ("example.com/app/broken", GoWorkspacePackageStatus::Unknown),
        ] {
            let session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
            let status = AnalyzerGoDefinitionProvider::bounded(go, &session, None)
                .workspace_package_status(import_path);
            assert!(matches!(
                session.finish(status),
                BoundedResolution::Complete { value, .. } if value == expected
            ));
        }
        assert_eq!(
            go.workspace_path_index_build_count_for_test(),
            0,
            "partial package authority must remain a relational snapshot answer"
        );
    }

    #[hardwon(
        "5c5d4e214494: invalid go.mod makes package absence unknown instead of authoritative"
    )]
    #[test]
    fn workspace_package_inventory_is_incomplete_for_invalid_go_mod() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[("go.mod", "go 1.26\n"), ("pkg/pkg.go", "package pkg\n")],
        );
        let go = resolve_analyzer::<GoAnalyzer>(fixture.analyzer.analyzer())
            .expect("fixture Go analyzer");
        let session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
        let status = AnalyzerGoDefinitionProvider::bounded(go, &session, None)
            .workspace_package_status("example.com/app/pkg");
        assert!(matches!(
            session.finish(status),
            BoundedResolution::Complete {
                value: GoWorkspacePackageStatus::Unknown,
                ..
            }
        ));
        assert_eq!(go.workspace_path_index_build_count_for_test(), 0);
    }

    mod native_definition_tests {
        use super::*;
        use crate::analyzer::go::native_points::{
            resolve_go_definition_bounded, resolve_go_definition_with_evidence_bounded,
        };
        use brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery;
        fn resolve_native_definition(
            analyzer: &dyn IAnalyzer,
            file: &ProjectFile,
            source: &str,
            tree: Option<&Tree>,
            site: &ResolvedReferenceSite,
        ) -> crate::analyzer::go::native_points::GoNativeDefinitionResolution {
            let result = resolve_go_definition_with_evidence_bounded(
                BoundedReceiverQuery {
                    analyzer,
                    file,
                    source,
                    tree,
                    site,
                    budget: ReceiverAnalysisBudget::default(),
                    cancellation: None,
                },
                || {},
            );
            let BoundedResolution::Complete { value, .. } = result else {
                panic!("native definition lookup should complete: {result:#?}");
            };
            value
        }
        #[test]
        fn bounded_go_wide_deep_walk_honors_mid_walk_cancellation() {
            let statements = (0..96)
                .map(|index| format!("    value{index} := {index}\n    _ = value{index}\n"))
                .collect::<String>();
            let expression = format!("{}service{}.Run()", "(".repeat(24), ")".repeat(24));
            let source = format!(
                "package main\n\ntype Service struct{{}}\nfunc (Service) Run() {{}}\n\nfunc use(service Service) {{\n{statements}    {expression}\n}}\n"
            );
            let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", &source)]);
            let file = ProjectFile::new(fixture.project_root(), "main.go");
            let tree = parse_go_tree(&source).expect("Go tree");
            let site = site_for(&file, &source, &expression, "Run");
            let complete = resolve_go_definition_bounded(
                BoundedReceiverQuery {
                    analyzer: fixture.analyzer.analyzer(),
                    file: &file,
                    source: &source,
                    tree: Some(&tree),
                    site: &site,
                    budget: ReceiverAnalysisBudget::default(),
                    cancellation: None,
                },
                || {},
            );
            let BoundedResolution::Complete { value, .. } = complete else {
                panic!("uncancelled lookup must complete: {complete:#?}");
            };
            assert_eq!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");
            assert_eq!(value.definitions.len(), 1, "{value:#?}");

            // A poll sweep on this fixture measured 8192 checks inside resolution
            // (28 rounds, 1029 scope nodes), and completion at 131072 checks.
            // Require nonzero resolution work so this cannot become a test of
            // cancellation only during open or immediately after open.
            let cancellation = CancellationToken::cancel_after_checks_for_test(8192);
            let outcome = resolve_go_definition_bounded(
                BoundedReceiverQuery {
                    analyzer: fixture.analyzer.analyzer(),
                    file: &file,
                    source: &source,
                    tree: Some(&tree),
                    site: &site,
                    budget: ReceiverAnalysisBudget::default(),
                    cancellation: Some(&cancellation),
                },
                || {},
            );
            // Cancelled carries only work, so no partial definitions can escape.
            let BoundedResolution::Cancelled { work } = outcome else {
                panic!("mid-walk cancellation must discard definitions: {outcome:#?}");
            };
            assert!(work.resolution_rounds > 0, "{work:#?}");
            assert!(work.scope_nodes > 0, "{work:#?}");
        }

        #[test]
        #[hardwon(
            "bb38340252e1: Checks dot-import names remain external while local receiver types are inferred from both calls and annotations"
        )]
        fn bounded_go_dot_import_types_local_receivers_from_calls_and_annotations() {
            let source = r#"package main

import . "example.com/app/worker"

func use() {
    worker := NewWorker()
    worker.Record()
    _, paired := 0, NewWorker()
    paired.Record()
    var recorder Recorder = worker
    recorder.Record()
}
"#;
            let fixture = AnalyzerFixture::new_for_language(
                Language::Go,
                &[
                    ("go.mod", "module example.com/app\n"),
                    (
                        "worker/worker.go",
                        r#"package worker

type Worker struct{}
func (Worker) Record() {}

type Recorder interface {
    Record()
}

func NewWorker() Worker { return Worker{} }
"#,
                    ),
                    ("main.go", source),
                ],
            );
            let file = ProjectFile::new(fixture.project_root(), "main.go");
            let tree = parse_go_tree(source).expect("Go tree");

            for (expression, target) in [
                ("worker.Record()", "example.com/app/worker.Worker.Record"),
                ("paired.Record()", "example.com/app/worker.Worker.Record"),
                (
                    "recorder.Record()",
                    "example.com/app/worker.Recorder.Record",
                ),
            ] {
                let site = site_for(&file, source, expression, "Record");
                let outcome = resolve_go_definition_bounded(
                    BoundedReceiverQuery {
                        analyzer: fixture.analyzer.analyzer(),
                        file: &file,
                        source,
                        tree: Some(&tree),
                        site: &site,
                        budget: ReceiverAnalysisBudget::default(),
                        cancellation: None,
                    },
                    || {},
                );
                let BoundedResolution::Complete { value, .. } = outcome else {
                    panic!("{expression} should complete: {outcome:#?}");
                };
                assert_eq!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");
                assert!(
                    matches!(value.definitions.as_slice(), [definition] if definition.fq_name() == target),
                    "{expression}: {value:#?}"
                );
            }
        }

        fn activate_native_authority(fixture: &AnalyzerFixture) {
            use brokk_bifrost_analysis::analyzer::semantic_model::{
                CatalogCoordinate, SemanticModelActivationControl, SemanticModelActivationEvidence,
                SemanticModelActivationRequest, SemanticModelControlAction,
                SemanticModelControlScope, SemanticModelPackSelector, SemanticModelRuntimeLimits,
            };

            let id = |name: &str| {
                name.chars()
                    .map(|ch| {
                        if ch.is_ascii_alphanumeric() {
                            ch.to_ascii_lowercase()
                        } else {
                            '-'
                        }
                    })
                    .collect::<String>()
            };
            let locator = |name: &str| serde_json::json!({"kind":"artifact","path":"fixture.go","symbol":name});
            let mut types = Vec::new();
            let mut members = Vec::new();
            for (package, alias) in [
                ("example.com/external", "external"),
                ("example.com/custom", "custom"),
                ("old.example/app/internal/pkg", "pkg"),
                ("testing", "testing"),
                ("sync", "sync"),
            ] {
                types.push(serde_json::json!({"id":id(package), "name":package, "type_kind":"module", "visibility":"public", "aliases":[alias], "locator":locator(package)}));
            }
            for name in ["testing.T", "testing.F", "sync.RWMutex"] {
                types.push(serde_json::json!({"id":id(name), "name":name, "type_kind":"struct", "visibility":"public", "locator":locator(name)}));
            }
            for (owner, name, arity, count, method, result) in [
                ("example.com/external", "MakePair", 0, 2, false, "testing.T"),
                ("example.com/external", "Generic", 0, 1, false, "int"),
                ("example.com/custom", "MakePair", 0, 1, false, "int"),
                (
                    "old.example/app/internal/pkg",
                    "MakePair",
                    0,
                    2,
                    false,
                    "testing.T",
                ),
                (
                    "example.com/external",
                    "MakeVariadic",
                    2,
                    1,
                    false,
                    "testing.T",
                ),
                ("sync.RWMutex", "Lock", 0, 0, true, ""),
                ("sync.RWMutex", "RLock", 0, 0, true, ""),
                ("sync.RWMutex", "RUnlock", 0, 0, true, ""),
            ] {
                let symbol = format!("{owner}.{name}");
                let parameters: Vec<_> = (0..arity).map(|i| serde_json::json!({"name":format!("arg{i}"),"type":{"kind":"named","name":"int"}})).collect();
                let mut signature = serde_json::json!({"parameters":parameters});
                if name == "Generic" {
                    signature["type_parameters"] = serde_json::json!(["T"]);
                }
                if count > 0 {
                    let first = serde_json::json!({"kind":"named","name":result});
                    signature["returns"] = if count == 1 {
                        first
                    } else {
                        serde_json::json!({"kind":"tuple","elements":[first, {"kind":"named","name":if name == "MakePair" {"testing.F"} else {"error"}}]})
                    };
                }
                let mut member = serde_json::json!({"id":id(&symbol),"owner":id(owner),"name":name,"member_kind":if method {"method"} else {"function"},"visibility":"public","is_static":!method,"callable_family_complete":true,"signature":signature,"locator":locator(&symbol)});
                if method {
                    member["receiver"] = serde_json::json!({"pointer":true});
                }
                members.push(member);
            }
            let source = serde_json::to_vec(&serde_json::json!({
            "schema_version":8,"pack_id":"fixture.go.native-port","version":"1.0.0",
            "producer":{"name":"test-only-native-port","version":"1.0.0"},
            "language":"go","ecosystem":"go-module","compatibility":{"toolchains":[]},
            "provenance":{"source":"test-only translation of existing provider fakes"},"license":"NOASSERTION","completeness":"partial",
            "safety":{"generated_code_only":false,"review_required":false},
            "shards":[{"id":"fixture.native","activation":[{"configurations":["fixture.native"]}],"payload":{"kind":"declaration_facts","types":types,"members":members,"relations":[]}}]
        })).unwrap();
            let request = SemanticModelActivationRequest {
                approximate_standard_libraries: Vec::new(),
                bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION"))
                    .expect("crate version"),
                evidence: vec![SemanticModelActivationEvidence {
                    language: "go".to_owned(),
                    ecosystem: "go-module".to_owned(),
                    package: None,
                    module: Some(CatalogCoordinate {
                        name: "example.com/mod".to_owned(),
                        version: None,
                    }),
                    toolchain: None,
                    target: None,
                    configuration: Some("fixture.native".to_owned()),
                    artifact_sha256: None,
                }],
                controls: vec![SemanticModelActivationControl {
                    scope: SemanticModelControlScope::Workspace,
                    action: SemanticModelControlAction::Enable,
                    selector: SemanticModelPackSelector {
                        pack_id: "fixture.go.native-port".to_owned(),
                        version: None,
                        manifest_digest: None,
                    },
                }],
                limits: SemanticModelRuntimeLimits::default(),
            };
            brokk_bifrost_analysis::analyzer::usages::test_support::activate_semantic_pack(
                fixture.analyzer.analyzer(),
                "fixture.go.native-port",
                &source,
                &request,
            );
        }

        #[test]
        fn nested_generic_miss_records_one_gap_but_budget_miss_does_not() {
            let source = "package main\nimport external \"example.com/external\"\nfunc use() { outer(external.Generic()) }\n";
            let fixture = AnalyzerFixture::new_for_language(
                Language::Go,
                &[("go.mod", "module example.com/app\n"), ("main.go", source)],
            );
            activate_native_authority(&fixture);
            let file = ProjectFile::new(fixture.project_root(), "main.go");
            let tree = parse_go_tree(source).expect("Go tree");
            let start = source.find("external.Generic()").expect("inner call");
            let inner = tree
                .root_node()
                .named_descendant_for_byte_range(start, start + "external.Generic()".len())
                .expect("inner call node");
            assert_eq!(inner.kind(), "call_expression");
            let outer_start = source.find("outer(").expect("outer call");
            let outer = tree
                .root_node()
                .named_descendant_for_byte_range(outer_start, outer_start + "outer".len())
                .expect("outer callable");
            assert_eq!(outer.kind(), "identifier");
            let go = resolve_analyzer::<GoAnalyzer>(fixture.analyzer.analyzer())
                .expect("fixture Go analyzer");

            let provider = AnalyzerGoDefinitionProvider::new(
                go,
                fixture.analyzer.analyzer().semantic_model_overlay(),
            );
            let scope = AnalyzerQueryScope::capturing_read_incompleteness(go);
            for _ in 0..2 {
                assert_eq!(
                    go_call_result_count(&provider, scope.token(), go, &file, source, inner),
                    None,
                );
            }
            assert_eq!(
                provider
                    .nested_counts
                    .read(&memo_attribution(go), |memo| memo.borrow().len()),
                1
            );
            assert_eq!(
                go_selected_receiver_argument_shape(
                    &provider,
                    scope.token(),
                    go,
                    &file,
                    source,
                    outer,
                ),
                None,
            );
            assert_eq!(
                scope.captured_read_incompleteness(),
                vec![QueryReadIncomplete::SemanticEvidenceGap(
                    "Go nested-call result arity unavailable from selected callable".into(),
                )]
            );
            assert_eq!(
                scope.read_completion(),
                Err(QueryReadIncomplete::SemanticEvidenceGap(
                    "Go nested-call result arity unavailable from selected callable".into(),
                ))
            );

            let budget = ReceiverAnalysisBudget {
                max_scope_nodes: 16,
                ..ReceiverAnalysisBudget::default()
            };
            let session = ResolutionSession::bounded(budget, None);
            let provider = AnalyzerGoDefinitionProvider::bounded(
                go,
                &session,
                fixture.analyzer.analyzer().semantic_model_overlay(),
            );
            let scope = AnalyzerQueryScope::capturing_read_incompleteness(go);
            assert_eq!(
                go_call_result_count(&provider, scope.token(), go, &file, source, inner),
                None,
            );
            assert!(matches!(
                session.finish(()),
                BoundedResolution::Exceeded { .. }
            ));
            assert!(
                provider
                    .nested_counts
                    .read(&memo_attribution(go), |memo| memo.borrow().is_empty())
            );
            assert!(scope.captured_read_incompleteness().is_empty());
            assert!(scope.read_completion().is_ok());

            let mut provider = AnalyzerGoDefinitionProvider::new(
                go,
                fixture.analyzer.analyzer().semantic_model_overlay(),
            );
            provider.native_budget = ReceiverAnalysisBudget {
                max_scope_nodes: 0,
                ..ReceiverAnalysisBudget::default()
            };
            let scope = AnalyzerQueryScope::capturing_read_incompleteness(go);
            assert_eq!(
                go_call_result_count(&provider, scope.token(), go, &file, source, inner),
                None,
            );
            let reason = QueryReadIncomplete::SemanticEvidenceUnavailable(
                "Go call result-shape work limit exceeded".into(),
            );
            assert_eq!(scope.captured_read_incompleteness(), vec![reason.clone()]);
            assert_eq!(
                go_call_result_count(&provider, scope.token(), go, &file, source, inner),
                None,
            );
            assert_eq!(scope.captured_read_incompleteness(), vec![reason]);
            assert!(
                provider
                    .nested_counts
                    .read(&memo_attribution(go), |memo| memo.borrow().is_empty())
            );
        }
        fn resolve_native_receiver(
            fixture: &AnalyzerFixture,
            file: &ProjectFile,
            source: &str,
            tree: &Tree,
            site: &ResolvedReferenceSite,
        ) -> crate::analyzer::go::native_points::GoNativeDefinitionResolution {
            let analyzer = fixture.analyzer.analyzer();
            resolve_native_definition(analyzer, file, source, Some(tree), site)
        }
        fn assert_exact_import_namespace_authority(
            fixture: &AnalyzerFixture,
            provider: &dyn GoDefinitionProvider,
            file: &ProjectFile,
            source: &str,
            tree: &Tree,
        ) {
            let go = resolve_analyzer::<GoAnalyzer>(fixture.analyzer.analyzer())
                .expect("fixture Go analyzer");
            let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
            let token = scope.token();
            let (aliases, _) = go_definition_import_namespaces(provider, token, go, file);
            assert_eq!(
                aliases.get("duplicate"),
                Some(&vec![
                    "example.com/custom".to_owned(),
                    "example.com/external".to_owned(),
                ]),
                "the import namespace must retain every distinct path"
            );
            assert!(
                !go_import_paths(provider, token, go, file).contains_key("duplicate"),
                "an ambiguous local import name must not select an arbitrary path"
            );

            let resolve = |expression: &str, focus: &str| {
                let site = site_for(file, source, expression, focus);
                resolve_native_definition(
                    fixture.analyzer.analyzer(),
                    file,
                    source,
                    Some(tree),
                    &site,
                )
            };

            let positive = resolve("external.MakeVariadic(external.MakePair())", "MakeVariadic");
            let positive_proof = positive.exact_external_call.as_ref().unwrap_or_else(|| {
                panic!(
                    "unique tuple import should bind exactly: {:#?}",
                    positive.outcome
                )
            });
            assert_eq!(
                positive_proof.canonical_callee(),
                "example.com/external.MakeVariadic"
            );
            assert_eq!(positive_proof.parameter_count(), 2);

            for (expression, focus) in [
                ("duplicate.MakePair()", "MakePair"),
                (
                    "external.MakeVariadic(duplicate.MakePair())",
                    "MakeVariadic",
                ),
            ] {
                let resolution = resolve(expression, focus);
                assert!(
                    resolution.exact_external_call.is_none(),
                    "an ambiguous import must not prove a callee or tuple arity: {expression}: {:#?}",
                    resolution.outcome
                );
            }
        }

        #[test]
        #[hardwon(
            "cd472d9c1eff: Ensures an unresolved final selector does not fall back to the resolved receiver field as the answer"
        )]
        fn unresolved_terminal_selector_does_not_return_its_receiver_field() {
            let source = "package repro\n\nimport \"sync\"\n\ntype anonymizer struct { lock sync.Mutex }\nfunc (a *anonymizer) SaveMapping() { a.lock.Lock() }\n";
            let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", source)]);
            let file = ProjectFile::new(fixture.project_root(), "main.go");
            let tree = parse_go_tree(source).expect("Go tree");
            let site = site_for(&file, source, "a.lock.Lock()", "Lock");

            let outcome = resolve_go_definition_bounded(
                BoundedReceiverQuery {
                    analyzer: fixture.analyzer.analyzer(),
                    file: &file,
                    source,
                    tree: Some(&tree),
                    site: &site,
                    budget: ReceiverAnalysisBudget::default(),
                    cancellation: None,
                },
                || {},
            );
            let BoundedResolution::Complete { value, .. } = outcome else {
                panic!("Go selector lookup should complete: {outcome:#?}");
            };
            // No active pack supplies `sync.Mutex`, so its member stays open
            // (#10106) instead of proving absence. Either way the receiver
            // field must not stand in for the unresolved selector.
            assert_eq!(
                DefinitionLookupStatus::Incomplete,
                value.status,
                "{value:#?}"
            );
            assert!(
                value
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.kind == "go-external-member-unprovided"),
                "{value:#?}"
            );
            assert!(value.definitions.is_empty(), "{value:#?}");
        }

        #[hardwon("5c5d4e214494: changed go.mod cannot reuse stale internal-package authorization")]
        #[test]
        fn changed_go_mod_cannot_authorize_stale_internal_model_call() {
            let source = "package main\n\nimport pkg \"old.example/app/internal/pkg\"\n\nfunc use() { pkg.MakePair() }\n";
            let fixture = AnalyzerFixture::new_for_language(
                Language::Go,
                &[("go.mod", "module old.example/app\n"), ("main.go", source)],
            );
            activate_native_authority(&fixture);
            let file = ProjectFile::new(fixture.project_root(), "main.go");
            let tree = parse_go_tree(source).expect("Go tree");
            let site = site_for(&file, source, "pkg.MakePair()", "MakePair");

            let disk_resolution = resolve_native_definition(
                fixture.analyzer.analyzer(),
                &file,
                source,
                Some(&tree),
                &site,
            );
            assert_eq!(
                disk_resolution
                    .exact_external_call
                    .as_ref()
                    .map(ExactExternalCallProof::canonical_callee),
                Some("old.example/app/internal/pkg.MakePair"),
                "the disk module identity permits its own internal modeled package"
            );

            let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
                Arc::new(fixture.test_project().clone()),
            ));
            let go_mod = ProjectFile::new(fixture.project_root(), "go.mod");
            assert!(overlay.set(
                go_mod.abs_path().to_path_buf(),
                "module new.example/app\n".to_owned(),
            ));
            let request = fixture.analyzer.clone_with_project(
                overlay as Arc<dyn brokk_bifrost_core::analyzer::project::Project>,
            );
            let request_go =
                resolve_analyzer::<GoAnalyzer>(request.analyzer()).expect("overlay Go analyzer");
            assert!(!request_go.workspace_declaration_identities_authoritative());
            let request_resolution =
                resolve_native_definition(request.analyzer(), &file, source, Some(&tree), &site);
            assert!(
                request_resolution.exact_external_call.is_none(),
                "the disk importer identity must not authorize an internal model in the overlaid module namespace: {:#?}",
                request_resolution.outcome
            );
        }

        #[hardwon(
            "5c5d4e214494: duplicate import aliases cannot authorize an arbitrary callee or result arity"
        )]
        #[test]
        fn duplicate_import_alias_never_proves_a_callee_or_tuple_arity() {
            let source = r#"package main

import (
    external "example.com/external"
    duplicate "example.com/external"
    duplicate "example.com/custom"
)

const external = 1

func use() {
    external.MakeVariadic(external.MakePair())
    external.MakeVariadic(duplicate.MakePair())
    duplicate.MakePair()
}
"#;
            let fixture = AnalyzerFixture::new_for_language(
                Language::Go,
                &[("go.mod", "module example.com/app\n"), ("main.go", source)],
            );
            activate_native_authority(&fixture);
            let file = ProjectFile::new(fixture.project_root(), "main.go");
            let tree = parse_go_tree(source).expect("Go tree");
            let go = resolve_analyzer::<GoAnalyzer>(fixture.analyzer.analyzer())
                .expect("fixture Go analyzer");

            let unbounded = AnalyzerGoDefinitionProvider::new(go, None);
            assert_exact_import_namespace_authority(&fixture, &unbounded, &file, source, &tree);

            let session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
            let bounded = AnalyzerGoDefinitionProvider::bounded(go, &session, None);
            assert_exact_import_namespace_authority(&fixture, &bounded, &file, source, &tree);
            assert!(matches!(
                session.finish(()),
                BoundedResolution::Complete { .. }
            ));
        }

        #[hardwon(
            "43a2c41d9d02: exact overlay identity canonicalizes supported Go selectors without inventing source definitions"
        )]
        #[test]
        fn exact_go_overlay_canonicalizes_only_the_published_non_call_selector_chain() {
            let source = r#"package main

import api "example.com/mod"

var (
    _ = api.Concrete.Read
    _ = api.hidden.Read
    _ = api.Lookalike.Read
)
"#;
            let fixture = AnalyzerFixture::new_for_language(
                Language::Go,
                &[("go.mod", "module example.com/app\n"), ("main.go", source)],
            );
            activate_selector_navigation_overlay(&fixture);
            let file = ProjectFile::new(fixture.project_root(), "main.go");
            let tree = parse_go_tree(source).expect("Go tree");

            let resolve = |expression: &str| {
                let site = site_for(&file, source, expression, "Read");
                resolve_native_definition(
                    fixture.analyzer.analyzer(),
                    &file,
                    source,
                    Some(&tree),
                    &site,
                )
                .outcome
            };

            let published = resolve("api.Concrete.Read");
            assert_eq!(
                published.status,
                DefinitionLookupStatus::NoDefinition,
                "navigation carries the overlay identity without inventing a source definition: {published:#?}"
            );
            assert_eq!(
                published
                    .reference
                    .as_ref()
                    .map(|reference| reference.text.as_str()),
                Some("example.com/mod.Concrete.Read"),
                "the exact overlay declaration canonicalizes the whole selector chain: {published:#?}"
            );

            let hidden_owner = resolve("api.hidden.Read");
            assert_eq!(
                hidden_owner.status,
                DefinitionLookupStatus::UnresolvableImportBoundary,
                "a public method cannot make its unexported owner navigable: {hidden_owner:#?}"
            );

            let lookalike = resolve("api.Lookalike.Read");
            assert_eq!(
                lookalike.status,
                DefinitionLookupStatus::UnresolvableImportBoundary,
                "an unsupported same-named selector remains an external boundary: {lookalike:#?}"
            );
            assert_eq!(
                lookalike
                    .reference
                    .as_ref()
                    .map(|reference| reference.text.as_str()),
                Some("example.com/mod.Read"),
                "an unsupported same-named chain retains only the import binder's boundary identity: {lookalike:#?}"
            );
        }

        #[hardwon(
            "43a2c41d9d02: module-scope values keep canonical navigation identity and reject unsupported selectors"
        )]
        #[test]
        fn external_go_module_scope_values_keep_canonical_navigation_identity() {
            let source = r#"package main

import api "example.com/mod"

var (
    _ = api.ExportedVar
    _ = api.ExportedConst
    _ = api.Ambiguous
)
"#;
            let fixture = AnalyzerFixture::new_for_language(
                Language::Go,
                &[("go.mod", "module example.com/app\n"), ("main.go", source)],
            );
            activate_selector_navigation_overlay(&fixture);
            let file = ProjectFile::new(fixture.project_root(), "main.go");
            let tree = parse_go_tree(source).expect("Go tree");
            let resolve = |member: &str| {
                let expression = format!("api.{member}");
                let site = site_for(&file, source, &expression, member);
                resolve_native_definition(
                    fixture.analyzer.analyzer(),
                    &file,
                    source,
                    Some(&tree),
                    &site,
                )
                .outcome
            };

            for member in ["ExportedVar", "ExportedConst"] {
                let outcome = resolve(member);
                let expected = format!("example.com/mod.{member}");
                assert_eq!(
                    outcome.status,
                    DefinitionLookupStatus::UnresolvableImportBoundary,
                    "the modeled package value is navigable without inventing a source definition: {outcome:#?}"
                );
                assert_eq!(
                    outcome
                        .reference
                        .as_ref()
                        .map(|reference| reference.text.as_str()),
                    Some(expected.as_str()),
                    "the synthetic module-scope storage owner must not leak into reference identity: {outcome:#?}"
                );
            }

            let ambiguous = resolve("Ambiguous");
            assert_eq!(
                ambiguous.status,
                DefinitionLookupStatus::UnresolvableImportBoundary,
                "distinct declarations under both accepted storage names remain ambiguous: {ambiguous:#?}"
            );
            assert_eq!(
                ambiguous
                    .reference
                    .as_ref()
                    .map(|reference| reference.text.as_str()),
                Some("example.com/mod.Ambiguous"),
                "the import binder still carries the canonical unresolved boundary identity: {ambiguous:#?}"
            );
        }

        #[hardwon(
            "5c5d4e214494: a changed go.mod overlay invalidates stale workspace package declarations"
        )]
        #[test]
        fn go_mod_overlay_suppresses_stale_workspace_declarations() {
            let source = "package main\n\nimport pkg \"old.example/app/pkg\"\n\nfunc use() string { return pkg.Run(\"value\") }\n";
            let fixture = AnalyzerFixture::new_for_language(
                Language::Go,
                &[
                    ("go.mod", "module old.example/app\n"),
                    (
                        "pkg/pkg.go",
                        "package pkg\n\nfunc Run(value string) string { return value }\n",
                    ),
                    ("main.go", source),
                ],
            );
            let go = resolve_analyzer::<GoAnalyzer>(fixture.analyzer.analyzer())
                .expect("fixture Go analyzer");
            let base = AnalyzerGoDefinitionProvider::new(go, None);
            assert_eq!(
                base.workspace_package_status("old.example/app/pkg"),
                GoWorkspacePackageStatus::Present
            );
            assert_eq!(go.workspace_path_index_build_count_for_test(), 1);
            let old_definition = base
                .fqn("old.example/app/pkg.Run")
                .into_iter()
                .next()
                .expect("disk module declaration");
            assert!(
                go.get_source(&old_definition, false)
                    .is_some_and(|body| body.contains("func Run(value string) string"))
            );

            let main = ProjectFile::new(fixture.project_root(), "main.go");
            let tree = parse_go_tree(source).expect("Go tree");
            let site = site_for(&main, source, "pkg.Run(\"value\")", "Run");
            let BoundedResolution::Complete { value, .. } = resolve_go_definition_bounded(
                BoundedReceiverQuery {
                    analyzer: go,
                    file: &main,
                    source,
                    tree: Some(&tree),
                    site: &site,
                    budget: ReceiverAnalysisBudget::default(),
                    cancellation: None,
                },
                || {},
            ) else {
                panic!("disk module call must resolve within the default budget");
            };
            assert_eq!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");

            let semantic_cancellation = CancellationToken::default();
            let mut materialization_budget =
                brokk_bifrost_analysis::analyzer::semantic::SemanticBudget::default();
            let base_artifact = fixture
                .analyzer
                .materialize_program_semantics(
                    &main,
                    &mut brokk_bifrost_analysis::analyzer::semantic::SemanticRequest::new(
                        &mut materialization_budget,
                        &semantic_cancellation,
                    ),
                )
                .expect("disk caller semantic materialization")
                .available_value()
                .cloned()
                .expect("disk caller semantic artifact");
            let first_call =
                |artifact: &Arc<brokk_bifrost_analysis::analyzer::semantic::SemanticArtifact>| {
                    artifact
                        .procedures()
                        .iter()
                        .find_map(|procedure| {
                            let call = procedure.call_sites().first()?;
                            artifact
                                .procedure_handle(procedure.id())?
                                .call_site_handle(call.id)
                        })
                        .expect("caller has one package call")
                };
            let base_call = first_call(&base_artifact);
            let mut dispatch_budget =
                brokk_bifrost_analysis::analyzer::semantic::SemanticBudget::default();
            let base_dispatch =
                brokk_bifrost_analysis::analyzer::semantic::DispatchOracle::resolve_call(
                    &fixture.analyzer.semantic_oracle_provider(),
                    &base_call,
                    &mut brokk_bifrost_analysis::analyzer::semantic::SemanticRequest::new(
                        &mut dispatch_budget,
                        &semantic_cancellation,
                    ),
                )
                .expect("disk workspace dispatch");
            let base_result = base_dispatch
                .available_value()
                .expect("disk dispatch retains its workspace target");
            let old_candidate = base_result
                .candidates()
                .iter()
                .find(|candidate| {
                    candidate.target().semantics().locator().path().as_str() == "pkg/pkg.go"
                })
                .expect("disk dispatch materializes the old-module body");
            assert!(
                old_candidate
                    .target()
                    .semantics()
                    .points()
                    .iter()
                    .flat_map(|point| point.events.iter())
                    .any(|event| matches!(
                    &event.effect,
                    brokk_bifrost_analysis::analyzer::semantic::SemanticEffect::ProcedureReturn {
                        value: Some(_)
                    }
                )),
                "the baseline target carries an observable return effect"
            );

            let source_overlay =
                Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
                    Arc::new(fixture.test_project().clone()),
                ));
            assert!(source_overlay.set(main.abs_path().to_path_buf(), source.to_owned()));
            let source_request = go.clone_with_project(
                source_overlay as Arc<dyn brokk_bifrost_core::analyzer::project::Project>,
            );
            assert!(
                source_request
                    .get_definitions("old.example/app/pkg.Run")
                    .iter()
                    .any(|definition| definition == &old_definition),
                "a source-only overlay keeps the disk package namespace authoritative"
            );
            let BoundedResolution::Complete { value, .. } = resolve_go_definition_bounded(
                BoundedReceiverQuery {
                    analyzer: &source_request,
                    file: &main,
                    source,
                    tree: Some(&tree),
                    site: &site,
                    budget: ReceiverAnalysisBudget::default(),
                    cancellation: None,
                },
                || {},
            ) else {
                panic!("source-only overlay call must resolve within the default budget");
            };
            assert_eq!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");

            let unchanged_module_overlay =
                Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
                    Arc::new(fixture.test_project().clone()),
                ));
            let go_mod = ProjectFile::new(fixture.project_root(), "go.mod");
            assert!(unchanged_module_overlay.set(
                go_mod.abs_path().to_path_buf(),
                "module old.example/app\n".to_owned(),
            ));
            let unchanged_module_request = go.clone_with_project(
                unchanged_module_overlay as Arc<dyn brokk_bifrost_core::analyzer::project::Project>,
            );
            assert!(
                unchanged_module_request
                    .get_definitions("old.example/app/pkg.Run")
                    .iter()
                    .any(|definition| definition == &old_definition),
                "a byte-identical package-identity overlay retains declaration authority"
            );
            let unchanged_session =
                ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
            let unchanged_status = AnalyzerGoDefinitionProvider::bounded(
                &unchanged_module_request,
                &unchanged_session,
                None,
            )
            .workspace_package_status("missing.example/pkg");
            assert!(matches!(
                unchanged_session.finish(unchanged_status),
                BoundedResolution::Complete {
                    value: GoWorkspacePackageStatus::Absent,
                    ..
                }
            ));

            let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
                Arc::new(fixture.test_project().clone()),
            ));
            assert!(overlay.set(
                go_mod.abs_path().to_path_buf(),
                "module new.example/app\n".to_owned(),
            ));
            let workspace_request =
                fixture
                    .analyzer
                    .clone_with_project(Arc::clone(&overlay)
                        as Arc<dyn brokk_bifrost_core::analyzer::project::Project>);
            let request = go.clone_with_project(
                Arc::clone(&overlay) as Arc<dyn brokk_bifrost_core::analyzer::project::Project>
            );
            assert_eq!(request.workspace_path_index_build_count_for_test(), 0);

            let request_definitions = AnalyzerGoDefinitionProvider::new(&request, None);
            assert_eq!(
                request_definitions.workspace_package_status("new.example/app/pkg"),
                GoWorkspacePackageStatus::Present
            );
            assert_eq!(
                request_definitions.workspace_package_status("old.example/app/pkg"),
                GoWorkspacePackageStatus::Absent
            );
            assert_eq!(request.workspace_path_index_build_count_for_test(), 1);
            assert!(
                request
                    .get_definitions("old.example/app/pkg.Run")
                    .is_empty(),
                "the overlaid module must not expose a body under the disk identity"
            );
            assert!(
                request
                    .get_definitions("new.example/app/pkg.Run")
                    .is_empty(),
                "the request must not guess a rekeyed declaration identity"
            );
            assert!(
                request.get_all_declarations().is_empty(),
                "no declaration enumeration may bypass the snapshot authority boundary"
            );
            assert_eq!(
                request.get_source(&old_definition, false),
                None,
                "a CodeUnit retained from the disk snapshot must not rehydrate its old body"
            );

            let BoundedResolution::Complete { value, .. } = resolve_go_definition_bounded(
                BoundedReceiverQuery {
                    analyzer: &request,
                    file: &main,
                    source,
                    tree: Some(&tree),
                    site: &site,
                    budget: ReceiverAnalysisBudget::default(),
                    cancellation: None,
                },
                || {},
            ) else {
                panic!("overlaid go.mod lookup must fail closed within the default budget");
            };
            assert_ne!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");
            assert!(value.definitions.is_empty(), "{value:#?}");

            let mut request_materialization_budget =
                brokk_bifrost_analysis::analyzer::semantic::SemanticBudget::default();
            let request_artifact = workspace_request
                .materialize_program_semantics(
                    &main,
                    &mut brokk_bifrost_analysis::analyzer::semantic::SemanticRequest::new(
                        &mut request_materialization_budget,
                        &semantic_cancellation,
                    ),
                )
                .expect("request caller semantic materialization")
                .available_value()
                .cloned()
                .expect("request caller semantic artifact");
            let request_call = first_call(&request_artifact);
            let mut request_dispatch_budget =
                brokk_bifrost_analysis::analyzer::semantic::SemanticBudget::default();
            let request_dispatch =
                brokk_bifrost_analysis::analyzer::semantic::DispatchOracle::resolve_call(
                    &workspace_request.semantic_oracle_provider(),
                    &request_call,
                    &mut brokk_bifrost_analysis::analyzer::semantic::SemanticRequest::new(
                        &mut request_dispatch_budget,
                        &semantic_cancellation,
                    ),
                )
                .expect("request workspace dispatch");
            let request_result = request_dispatch
                .available_value()
                .expect("failed-closed dispatch retains its explicit boundary");
            assert!(
                request_result.candidates().is_empty(),
                "the changed go.mod must not reuse the old workspace body or its effects: {request_dispatch:#?}"
            );
        }

        #[hardwon(
            "ea2822a0199a: Go interface-key map ranges preserve pointer and value element types"
        )]
        #[test]
        fn interface_key_map_ranges_preserve_pointer_and_value_elements() {
            let source = r#"package main

import "sync"

type item struct {
    sync.RWMutex
}

type valueItem struct{}

func (valueItem) Run() {}

type table struct {
    items map[interface{} /* an empty interface key */]*item
}

type valueTable struct {
    items map[interface{}]valueItem
}

type other struct{}

type otherTable struct {
    items map[interface{}]*other
}

type unknownTable struct {
    items map[interface{}]*Missing
}

func run(t *table) {
    items := t.items
    for _, entry := range items {
        entry.RLock()
        entry.RUnlock()
    }
}

func runValue(t *valueTable) {
    items := t.items
    for _, entry := range items {
        entry.Run()
    }
}

func runOther(t *otherTable) {
    items := t.items
    for _, otherEntry := range items {
        otherEntry.RLock()
    }
}

func runUnknown(t *unknownTable) {
    items := t.items
    for _, unknownEntry := range items {
        unknownEntry.RLock()
    }
}
"#;
            let fixture = AnalyzerFixture::new_for_language(
                Language::Go,
                &[("go.mod", "module example.com/app\n"), ("main.go", source)],
            );
            activate_native_authority(&fixture);
            let file = ProjectFile::new(fixture.project_root(), "main.go");
            let tree = parse_go_tree(source).expect("Go tree");

            for (expression, member) in [("entry.RLock()", "RLock"), ("entry.RUnlock()", "RUnlock")]
            {
                let expected_target = format!("sync.RWMutex.{member}");
                let site = site_for(&file, source, expression, member);
                let resolution = resolve_native_receiver(&fixture, &file, source, &tree, &site);
                assert_eq!(
                    resolution.outcome.status,
                    DefinitionLookupStatus::UnresolvableImportBoundary,
                    "{expression}: {:#?}",
                    resolution.outcome
                );
                assert_eq!(
                    resolution
                        .outcome
                        .reference
                        .as_ref()
                        .map(|reference| reference.text.as_str()),
                    Some(expected_target.as_str()),
                    "{expression}: {:#?}",
                    resolution.outcome
                );
                let proof = resolution.exact_external_call.as_ref().unwrap_or_else(|| {
                    panic!(
                        "{expression} must retain one exact promoted target: {:#?}",
                        resolution.outcome
                    )
                });
                assert_eq!(proof.canonical_callee(), expected_target.as_str());
            }

            let value_site = site_for(&file, source, "entry.Run()", "Run");
            let value_resolution =
                resolve_native_receiver(&fixture, &file, source, &tree, &value_site);
            assert_eq!(
                value_resolution.outcome.status,
                DefinitionLookupStatus::Resolved,
                "value element range must retain its declared element type: {:#?}",
                value_resolution.outcome
            );
            assert!(
                value_resolution
                    .outcome
                    .definitions
                    .iter()
                    .any(|definition| { definition.fq_name() == "example.com/app.valueItem.Run" }),
                "value element range target: {:#?}",
                value_resolution.outcome
            );

            let other_site = site_for(&file, source, "otherEntry.RLock()", "RLock");
            let other_resolution =
                resolve_native_receiver(&fixture, &file, source, &tree, &other_site);
            assert_ne!(
                other_resolution.outcome.status,
                DefinitionLookupStatus::UnresolvableImportBoundary,
                "a different map element type must not inherit item's promoted method: {:#?}",
                other_resolution.outcome
            );
            assert!(
                other_resolution
                    .outcome
                    .reference
                    .as_ref()
                    .is_none_or(|reference| reference.text != "sync.RWMutex.RLock"),
                "different element target: {:#?}",
                other_resolution.outcome
            );

            let unknown_site = site_for(&file, source, "unknownEntry.RLock()", "RLock");
            let unknown_resolution =
                resolve_native_receiver(&fixture, &file, source, &tree, &unknown_site);
            assert_ne!(
                unknown_resolution.outcome.status,
                DefinitionLookupStatus::UnresolvableImportBoundary,
                "an undeclared map element type must stay unknown: {:#?}",
                unknown_resolution.outcome
            );
            assert!(
                unknown_resolution
                    .outcome
                    .reference
                    .as_ref()
                    .is_none_or(|reference| reference.text != "sync.RWMutex.RLock"),
                "unknown element target: {:#?}",
                unknown_resolution.outcome
            );
        }

        #[hardwon(
            "db3b2335e6d7: promoted external receiver resolution retains one exact method proof"
        )]
        #[test]
        fn structured_local_embedding_resolves_one_promoted_external_receiver_method() {
            let source = r#"package main

import "sync"

type CacheTable struct {
    sync.RWMutex
}

func use(table *CacheTable) {
    table.Lock()
}
"#;
            let fixture = AnalyzerFixture::new_for_language(
                Language::Go,
                &[("go.mod", "module example.com/app\n"), ("main.go", source)],
            );
            activate_native_authority(&fixture);
            let file = ProjectFile::new(fixture.project_root(), "main.go");
            let tree = parse_go_tree(source).expect("Go tree");
            let site = site_for(&file, source, "table.Lock()", "Lock");

            let resolution = resolve_native_receiver(&fixture, &file, source, &tree, &site);

            assert_eq!(
                resolution.outcome.status,
                DefinitionLookupStatus::UnresolvableImportBoundary,
                "{:#?}",
                resolution.outcome
            );
            assert_eq!(
                resolution
                    .outcome
                    .reference
                    .as_ref()
                    .map(|reference| reference.text.as_str()),
                Some("sync.RWMutex.Lock"),
                "{:#?}",
                resolution.outcome
            );
            let proof = resolution.exact_external_call.as_ref().unwrap_or_else(|| {
                panic!(
                    "the promoted receiver target must retain one exact proof: {:#?}",
                    resolution.outcome
                )
            });
            assert_eq!(proof.canonical_callee(), "sync.RWMutex.Lock");
            assert_eq!(proof.call_application(), CallApplicationKind::BoundReceiver);
            assert_eq!(proof.parameter_count(), 0);
        }

        #[test]
        fn bounded_go_deep_receiver_wrappers_use_an_explicit_work_stack() {
            let expression = format!("{}service{}.Run()", "(".repeat(512), ")".repeat(512));
            let source = format!(
                "package main\n\ntype Service struct{{}}\nfunc (Service) Run() {{}}\nfunc use(service Service) {{\n    {expression}\n}}\n"
            );
            let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", &source)]);
            let file = ProjectFile::new(fixture.project_root(), "main.go");
            let tree = parse_go_tree(&source).expect("Go tree");
            let site = site_for(&file, &source, &expression, "Run");
            let outcome = resolve_go_definition_bounded(
                BoundedReceiverQuery {
                    analyzer: fixture.analyzer.analyzer(),
                    file: &file,
                    source: &source,
                    tree: Some(&tree),
                    site: &site,
                    budget: ReceiverAnalysisBudget {
                        context_depth: 8,
                        max_targets: 16,
                        max_summary_expansions: 4_096,
                        max_scope_nodes: 100_000,
                        max_hierarchy_order_work: 100_000,
                        max_resolution_rounds: ReceiverAnalysisBudget::default()
                            .max_resolution_rounds,
                        max_hierarchy_order_steps: ReceiverAnalysisBudget::default()
                            .max_hierarchy_order_steps,
                    },
                    cancellation: None,
                },
                || {},
            );

            let BoundedResolution::Complete { value, .. } = outcome else {
                panic!("deep Go receiver lookup should complete: {outcome:#?}");
            };
            assert_eq!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");
            assert!(
                value
                    .definitions
                    .iter()
                    .any(|definition| definition.fq_name() == "main.Service.Run"),
                "{value:#?}"
            );
        }
    }
}
