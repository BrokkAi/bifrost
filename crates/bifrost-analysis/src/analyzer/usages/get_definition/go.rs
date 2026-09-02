use super::*;
use crate::analyzer::CodeUnitIndex;
use crate::analyzer::go::package_identity::{GoModeledNominalType, GoModeledPackageCallResolution};
use crate::analyzer::languages::package_fq_name;
use crate::analyzer::store::StoreError;
use crate::analyzer::{
    DefinitionLanguageScope, DispatchExtensibility, RelationalBatchOutcome,
    RelationalDefinitionQuery, RelationalDefinitionRequest, RelationalDefinitionValue,
    SignatureMetadata, StructuredTypeIdentity, go_internal_import_allowed,
};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::{
    PackageRelationKind, PackageRelationValue, RelationalName, model::StructuredTypeNodeView,
};
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
    fn members_for_owner_name(&self, owner_fqn: &str, name: &str) -> Vec<CodeUnit> {
        self.fqn(&format!("{owner_fqn}.{name}"))
    }
    fn import_infos(
        &self,
        token: QueryToken<'_>,
        go: &GoAnalyzer,
        file: &ProjectFile,
    ) -> Vec<ImportInfo> {
        go.import_info_of(token, file)
    }
    fn signature_metadata(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
    ) -> Vec<SignatureMetadata> {
        analyzer.signature_metadata(unit)
    }
    fn raw_supertypes(&self, go: &GoAnalyzer, unit: &CodeUnit) -> Vec<String> {
        go.raw_supertypes(unit)
    }
    fn scope_step(&self) -> bool {
        true
    }
    fn summary_step(&self) -> bool {
        true
    }
    fn session(&self) -> Option<&ResolutionSession> {
        None
    }
    fn retain_ambiguous_candidate_evidence(&self) -> bool {
        false
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

    fn external_package_call_result_count(
        &self,
        _import_path: &str,
        _member: &str,
        _parameter_count: usize,
    ) -> Option<usize> {
        None
    }

    fn external_package_member_is_published(&self, _import_path: &str, _member: &str) -> bool {
        false
    }

    /// Exact visible declaration identity for navigation through one
    /// structured external package selector. This carries no callable proof;
    /// call modeling must continue through the signature-aware methods above.
    fn external_visible_symbol(&self, _qualified_name: &str) -> Option<String> {
        None
    }

    /// Exact visible declaration identity for one structured package member.
    /// Go declaration packs may store package variables and constants below a
    /// synthetic module-scope owner, so this lookup must consider both exact
    /// storage names without choosing through ambiguity.
    fn external_visible_package_member(&self, _import_path: &str, _member: &str) -> Option<String> {
        None
    }

    /// The canonical modeled member selected by one structured concrete
    /// receiver. Providers without an activated declaration overlay abstain.
    fn external_concrete_receiver_member(
        &self,
        _owner_fqn: &str,
        _member: &str,
        _pointer_receivers: bool,
        _parameter_count: usize,
    ) -> Option<String> {
        None
    }

    /// One exact nominal result from one exact external declaration-fact
    /// callable. Providers without an activated declaration overlay abstain.
    fn external_callable_result_nominal_type(
        &self,
        _owner_fqn: &str,
        _member: &str,
        _has_receiver: bool,
        _parameter_count: usize,
        _result_ordinal: usize,
    ) -> Option<GoModeledNominalType> {
        None
    }

    fn fqn_exists(&self, fqn: &str) -> bool {
        !self.fqn(fqn).is_empty()
    }
}

pub(crate) struct AnalyzerGoDefinitionProvider<'a> {
    analyzer: &'a GoAnalyzer,
    session: Option<&'a ResolutionSession>,
    semantic_model_overlay:
        Option<std::sync::Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
}

impl<'a> AnalyzerGoDefinitionProvider<'a> {
    pub(crate) fn new(
        analyzer: &'a GoAnalyzer,
        semantic_model_overlay: Option<
            std::sync::Arc<crate::analyzer::semantic_model::SemanticModelOverlay>,
        >,
    ) -> Self {
        Self {
            analyzer,
            session: None,
            semantic_model_overlay,
        }
    }

    pub(crate) fn bounded(
        analyzer: &'a GoAnalyzer,
        session: &'a ResolutionSession,
        semantic_model_overlay: Option<
            std::sync::Arc<crate::analyzer::semantic_model::SemanticModelOverlay>,
        >,
    ) -> Self {
        Self {
            analyzer,
            session: Some(session),
            semantic_model_overlay,
        }
    }
}

impl GoDefinitionProvider for AnalyzerGoDefinitionProvider<'_> {
    fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        let mut units: Vec<_> = match self.session {
            Some(session) => session.query_limited_rows(|limit| {
                self.analyzer
                    .declaration_candidates_by_fqn_limited(fqn, limit, || {
                        session.observe_cancellation()
                    })
            }),
            None => self.analyzer.definitions(fqn).collect(),
        };
        sort_units(&mut units);
        units.dedup();
        units
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

    fn members_for_owner_name(&self, owner_fqn: &str, name: &str) -> Vec<CodeUnit> {
        let mut units = match self.session {
            Some(session) => session.query_limited_rows(|limit| {
                self.analyzer
                    .member_candidates_for_owner_limited(owner_fqn, name, limit, || {
                        session.observe_cancellation()
                    })
            }),
            None => self.fqn(&format!("{owner_fqn}.{name}")),
        };
        sort_units(&mut units);
        units.dedup();
        units
    }

    fn import_infos(
        &self,
        token: QueryToken<'_>,
        go: &GoAnalyzer,
        file: &ProjectFile,
    ) -> Vec<ImportInfo> {
        match self.session {
            Some(session) => {
                session.query_limited_rows(|limit| go.import_info_limited(token, file, limit))
            }
            None => go.import_info_of(token, file),
        }
    }

    fn signature_metadata(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
    ) -> Vec<SignatureMetadata> {
        match self.session {
            Some(session) => session
                .query_limited_rows(|limit| self.analyzer.signature_metadata_limited(unit, limit)),
            None => analyzer.signature_metadata(unit),
        }
    }

    fn raw_supertypes(&self, go: &GoAnalyzer, unit: &CodeUnit) -> Vec<String> {
        match self.session {
            Some(session) => {
                session.query_limited_rows(|limit| go.raw_supertypes_limited(unit, limit))
            }
            None => go.raw_supertypes(unit),
        }
    }

    fn scope_step(&self) -> bool {
        self.session.is_none_or(ResolutionSession::scope_step)
    }

    fn summary_step(&self) -> bool {
        self.session.is_none_or(ResolutionSession::summary_step)
    }

    fn session(&self) -> Option<&ResolutionSession> {
        self.session
    }

    fn retain_ambiguous_candidate_evidence(&self) -> bool {
        self.session.is_some()
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

    fn external_package_call_result_count(
        &self,
        import_path: &str,
        member: &str,
        parameter_count: usize,
    ) -> Option<usize> {
        crate::analyzer::go::package_identity::GoOverlayPackages::new(
            self.semantic_model_overlay.as_deref(),
        )
        .package_call_result_count(import_path, member, parameter_count)
    }

    fn external_package_member_is_published(&self, import_path: &str, member: &str) -> bool {
        crate::analyzer::go::package_identity::GoOverlayPackages::new(
            self.semantic_model_overlay.as_deref(),
        )
        .publishes_any_member_fact(import_path, member)
    }

    fn external_visible_symbol(&self, qualified_name: &str) -> Option<String> {
        crate::analyzer::go::package_identity::GoOverlayPackages::new(
            self.semantic_model_overlay.as_deref(),
        )
        .visible_symbol(qualified_name)
        .filter(|symbol| symbol.qualified_name == qualified_name)
        .map(|symbol| symbol.qualified_name.clone())
    }

    fn external_visible_package_member(&self, import_path: &str, member: &str) -> Option<String> {
        crate::analyzer::go::package_identity::GoOverlayPackages::new(
            self.semantic_model_overlay.as_deref(),
        )
        .visible_member(import_path, member)
        .map(|symbol| symbol.qualified_name.clone())
    }

    fn external_concrete_receiver_member(
        &self,
        owner_fqn: &str,
        member: &str,
        pointer_receivers: bool,
        parameter_count: usize,
    ) -> Option<String> {
        crate::analyzer::go::package_identity::GoOverlayPackages::new(
            self.semantic_model_overlay.as_deref(),
        )
        .concrete_receiver_method(owner_fqn, member, pointer_receivers, parameter_count)
        .map(|method| method.qualified_name.clone())
    }

    fn external_callable_result_nominal_type(
        &self,
        owner_fqn: &str,
        member: &str,
        has_receiver: bool,
        parameter_count: usize,
        result_ordinal: usize,
    ) -> Option<GoModeledNominalType> {
        crate::analyzer::go::package_identity::GoOverlayPackages::new(
            self.semantic_model_overlay.as_deref(),
        )
        .callable_result_nominal_type(
            owner_fqn,
            member,
            has_receiver,
            parameter_count,
            result_ordinal,
        )
    }
}

fn go_smallest_named_node_covering<'tree>(
    support: &dyn GoDefinitionProvider,
    mut node: Node<'tree>,
    start: usize,
    end: usize,
) -> Option<Node<'tree>> {
    if !support.scope_step() || node.end_byte() < end || node.start_byte() > start {
        return None;
    }
    loop {
        let mut cursor = node.walk();
        let mut containing_child = None;
        for child in node.named_children(&mut cursor) {
            if !support.scope_step() {
                return None;
            }
            if child.start_byte() <= start && child.end_byte() >= end {
                containing_child = Some(child);
                break;
            }
        }
        match containing_child {
            Some(child) => node = child,
            None => return Some(node),
        }
    }
}

fn go_fqn_candidates(
    support: &dyn GoDefinitionProvider,
    fqns: impl IntoIterator<Item = String>,
) -> Vec<CodeUnit> {
    let mut candidates = Vec::new();
    for fqn in fqns {
        candidates.extend(support.fqn(&fqn));
    }
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

/// Memoized on exact source bytes (#2679): the package-selector chain probe
/// re-reads and re-parses the same package variable files once per
/// occurrence.
static GO_TREES: super::TreeParseMemo = super::TreeParseMemo::new();

pub(crate) fn parse_go_tree(source: &str) -> Option<Tree> {
    GO_TREES.parse(source, |source| {
        let mut parser = Parser::new();
        parser.set_language(&tree_sitter_go::LANGUAGE.into()).ok()?;
        parser.parse(source, None)
    })
}

pub(crate) fn resolve_go_bounded(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<DefinitionLookupOutcome> {
    let session = ResolutionSession::bounded(budget, cancellation);
    let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
        return session.finish(no_definition(
            "go_analyzer_unavailable",
            "Go analyzer is unavailable",
        ));
    };
    let definitions =
        AnalyzerGoDefinitionProvider::bounded(go, &session, analyzer.semantic_model_overlay());
    let selector = tree.and_then(|tree| {
        go_selector_descriptor_with_scope(tree.root_node(), site, || definitions.scope_step())
    });
    let outcome = resolve_go(
        analyzer,
        &definitions,
        file,
        source,
        tree,
        site,
        selector.as_ref(),
        None,
    );
    session.finish(outcome.outcome)
}

pub(super) struct GoDefinitionResolution {
    pub(super) outcome: DefinitionLookupOutcome,
    pub(super) call_application: CallApplicationKind,
    pub(super) dispatch_extensibility: Option<DispatchExtensibility>,
    pub(super) exact_external_call: Option<ExactExternalCallProof>,
}

struct GoCallEvidence {
    application: CallApplicationKind,
    dispatch_extensibility: Option<DispatchExtensibility>,
    exact_external_call: Option<ExactExternalCallProof>,
}

impl GoCallEvidence {
    fn record_exact_external_call(&mut self, proof: ExactExternalCallProof) {
        self.application = proof.call_application();
        self.dispatch_extensibility = proof.dispatch_extensibility();
        self.exact_external_call = Some(proof);
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn resolve_go(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    selector: Option<&GoSelectorDescriptor<'_>>,
    resolution: Option<GoReferenceResolution>,
) -> GoDefinitionResolution {
    let application = match (resolution.as_ref(), selector) {
        (Some(resolution), selector)
            if !resolution.resolved_import_packages.is_empty()
                && selector.is_none_or(|selector| selector.focus_segment == 1) =>
        {
            CallApplicationKind::PackageFunction
        }
        (Some(resolution), Some(selector)) if resolution.shadowed && selector.focus_segment > 0 => {
            CallApplicationKind::ReceiverBindingUnknown
        }
        (Some(resolution), Some(selector))
            if !resolution.resolved_import_packages.is_empty() && selector.focus_segment > 1 =>
        {
            CallApplicationKind::ReceiverBindingUnknown
        }
        (_, Some(selector)) if selector.base_identifier(source).is_none() => {
            CallApplicationKind::ReceiverBindingUnknown
        }
        _ => CallApplicationKind::Unknown,
    };
    let mut call_evidence = GoCallEvidence {
        application,
        dispatch_extensibility: None,
        exact_external_call: None,
    };
    let outcome = resolve_go_outcome(
        analyzer,
        support,
        file,
        source,
        tree,
        site,
        selector,
        resolution,
        &mut call_evidence,
    );
    GoDefinitionResolution {
        outcome,
        call_application: call_evidence.application,
        dispatch_extensibility: call_evidence.dispatch_extensibility,
        exact_external_call: call_evidence.exact_external_call,
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_go_outcome(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    selector: Option<&GoSelectorDescriptor<'_>>,
    resolution: Option<GoReferenceResolution>,
    call_evidence: &mut GoCallEvidence,
) -> DefinitionLookupOutcome {
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
        return no_definition("go_analyzer_unavailable", "Go analyzer is unavailable");
    };
    let reference = selector
        .map(GoSelectorDescriptor::focused_node)
        .map(|node| go_node_text(node, source))
        .unwrap_or(site.text.as_str());
    let importer_package =
        go_package_name(support, file, source, tree.map(Tree::root_node)).unwrap_or_default();
    if let Some(outcome) = tree.and_then(|tree| {
        go_keyed_composite_label_outcome(
            analyzer,
            token,
            support,
            file,
            source,
            tree.root_node(),
            site,
        )
    }) {
        return outcome;
    }
    if let Some(selector) = selector
        && selector.focus_segment > 0
        && selector.base_identifier(source).is_none()
    {
        return tree
            .and_then(|tree| {
                resolve_go_local_selector_chain(
                    analyzer,
                    token,
                    support,
                    file,
                    source,
                    tree.root_node(),
                    site,
                    selector,
                    call_evidence,
                )
            })
            .unwrap_or_else(|| {
                no_definition(
                    "no_indexed_definition",
                    format!("`{reference}` did not resolve to an indexed Go definition"),
                )
            });
    }
    if let Some(resolution) = resolution {
        let candidates = go_fqn_candidates(support, resolution.fqn_candidates);
        if !candidates.is_empty()
            && (resolution.resolved_import_packages.is_empty()
                || (selector.is_some() && resolution.resolved_import_packages.len() == 1))
        {
            return candidates_outcome(candidates);
        }
        if resolution.shadowed {
            if let Some(outcome) = tree.and_then(|tree| {
                selector.and_then(|selector| {
                    resolve_go_local_selector_chain(
                        analyzer,
                        token,
                        support,
                        file,
                        source,
                        tree.root_node(),
                        site,
                        selector,
                        call_evidence,
                    )
                })
            }) {
                return outcome;
            }
            return no_definition(
                LOCAL_VARIABLE_REFERENCE_DIAGNOSTIC_KIND,
                format!("`{reference}` is shadowed by a local Go binding"),
            );
        }
        if selector.is_none() && brokk_bifrost_go::diagnostics::is_predeclared_go_name(reference) {
            call_evidence.application = CallApplicationKind::Unknown;
            return no_definition(
                PREDECLARED_SYMBOL_REFERENCE_DIAGNOSTIC_KIND,
                format!("`{reference}` is a predeclared Go symbol"),
            );
        }
        if let [package] = resolution.resolved_import_packages.as_slice()
            && let Some(selector) = selector
        {
            if selector.focus_segment == 0 {
                // The focus is the package qualifier itself (`fs` in
                // `fs.Debugf`). A package names a namespace, not a single
                // declaration, so there is nothing to navigate to — but when the
                // package is indexed in this workspace the honest answer is
                // "workspace package namespace", never a boundary claim whose
                // tail implies it may be outside the workspace (issue #1089 go
                // cousin: rclone `fs.Debugf`).
                return go_workspace_package_boundary(
                    package,
                    go_workspace_package_status(support, package),
                    format!(
                        "`{reference}` is a Go import namespace rather than an indexed declaration"
                    ),
                    "workspace_package_namespace",
                    format!(
                        "`{reference}` names a Go package in this workspace, not a single indexed declaration"
                    ),
                );
            }
            if let Some(outcome) = go_package_selector_chain_outcome(
                analyzer, token, support, go, package, source, selector,
            ) {
                return outcome;
            }
            let workspace_status = go_workspace_package_status(support, package);
            if workspace_status == GoWorkspacePackageStatus::Absent
                && go_internal_import_allowed(&importer_package, package)
                && let Some(outcome) = go_model_package_selector_outcome(
                    support,
                    token,
                    go,
                    file,
                    site,
                    package,
                    source,
                    selector,
                    call_evidence,
                )
            {
                return outcome;
            }
            if workspace_status == GoWorkspacePackageStatus::Absent
                && go_internal_import_allowed(&importer_package, package)
                && let Some(outcome) = go_model_package_selector_shape_outcome(
                    support, site, package, source, selector,
                )
            {
                return outcome;
            }
            if workspace_status == GoWorkspacePackageStatus::Absent
                && go_internal_import_allowed(&importer_package, package)
                && let Some(outcome) = go_model_package_selector_navigation_outcome(
                    support, site, package, source, selector,
                )
            {
                return outcome;
            }
            return go_imported_member_boundary(
                site,
                package,
                reference,
                workspace_status,
                format!("`{package}` is outside this partial Go workspace analysis"),
                "no_indexed_definition",
                format!("`{reference}` is not indexed in Go package `{package}`"),
            );
        }
        if selector.is_some() && !resolution.resolved_import_packages.is_empty() {
            return boundary_unchecked(format!(
                "Go import qualifier is ambiguous across packages {:?}",
                resolution.resolved_import_packages
            ));
        }
        let mut dot_candidates = Vec::new();
        for package in &resolution.resolved_import_packages {
            if !support.scope_step() {
                break;
            }
            dot_candidates.extend(go_package_member_candidates(support, package, reference));
        }
        sort_units(&mut dot_candidates);
        dot_candidates.dedup();
        let package_statuses = resolution
            .resolved_import_packages
            .iter()
            .map(|package| {
                (
                    package.as_str(),
                    go_workspace_package_status(support, package),
                )
            })
            .collect::<Vec<_>>();
        if let Some((package, _)) = package_statuses
            .iter()
            .find(|(_, status)| *status == GoWorkspacePackageStatus::Unknown)
        {
            return go_workspace_package_status_unknown(package);
        }
        let external_packages = package_statuses
            .iter()
            .filter_map(|(package, status)| {
                (*status == GoWorkspacePackageStatus::Absent).then_some(*package)
            })
            .collect::<Vec<_>>();
        if !dot_candidates.is_empty() {
            if external_packages.is_empty() {
                // Dot-imported names are declared in the file block and
                // therefore shadow same-named declarations in package scope.
                return candidates_outcome(dot_candidates);
            }
            // An indexed dot-imported declaration plus an external package
            // whose same-name surface is unavailable cannot be reduced to one
            // target. In particular, a positive external model would make the
            // source declaration itself ambiguous rather than authorizing the
            // indexed candidate alone.
            return boundary_unchecked(format!(
                "dot-imported `{reference}` is ambiguous between indexed candidates and external packages {external_packages:?}"
            ));
        }
        if let [package] = external_packages.as_slice() {
            if go_internal_import_allowed(&importer_package, package)
                && let Some(parameter_count) = tree.and_then(|tree| {
                    go_identifier_modeled_call_argument_count(
                        support,
                        token,
                        go,
                        file,
                        source,
                        tree.root_node(),
                        site,
                    )
                })
                && let Some(outcome) = go_model_package_call_outcome(
                    support,
                    site,
                    package,
                    reference,
                    parameter_count,
                    call_evidence,
                )
            {
                return outcome;
            }
            if tree
                .is_some_and(|tree| go_identifier_is_call_target(support, tree.root_node(), site))
                && let Some(outcome) =
                    go_model_published_member_call_shape_outcome(support, site, package, reference)
            {
                return outcome;
            }
            return go_imported_member_boundary(
                site,
                package,
                reference,
                GoWorkspacePackageStatus::Absent,
                format!("`{package}` is outside this partial Go workspace analysis"),
                "no_indexed_definition",
                format!("`{reference}` is not indexed in dot-imported Go package `{package}`"),
            );
        }
        if !external_packages.is_empty() {
            // gated upstream: every retained import failed the workspace-path
            // predicate above. More than one dot import is structurally
            // ambiguous, so no canonical external member identity can be
            // carried.
            return boundary_unchecked(format!(
                "dot-imported packages {external_packages:?} are outside this partial Go workspace analysis"
            ));
        }
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
    }

    if let Some(selector) = selector
        && selector.focus_segment > 0
        && let Some(qualifier) = selector.base_identifier(source)
    {
        let name = go_node_text(selector.focused_node(), source);
        let imports = go_import_paths(support, token, go, file);
        if let Some(import_path) = imports.get(qualifier) {
            if let Some(outcome) = go_package_selector_chain_outcome(
                analyzer,
                token,
                support,
                go,
                import_path,
                source,
                selector,
            ) {
                return outcome;
            }
            let workspace_status = go_workspace_package_status(support, import_path);
            if workspace_status == GoWorkspacePackageStatus::Absent
                && go_internal_import_allowed(&importer_package, import_path)
                && let Some(outcome) = go_model_package_selector_outcome(
                    support,
                    token,
                    go,
                    file,
                    site,
                    import_path,
                    source,
                    selector,
                    call_evidence,
                )
            {
                return outcome;
            }
            if workspace_status == GoWorkspacePackageStatus::Absent
                && go_internal_import_allowed(&importer_package, import_path)
                && let Some(outcome) = go_model_package_selector_shape_outcome(
                    support,
                    site,
                    import_path,
                    source,
                    selector,
                )
            {
                return outcome;
            }
            if workspace_status == GoWorkspacePackageStatus::Absent
                && go_internal_import_allowed(&importer_package, import_path)
                && let Some(outcome) = go_model_package_selector_navigation_outcome(
                    support,
                    site,
                    import_path,
                    source,
                    selector,
                )
            {
                return outcome;
            }
            return go_imported_member_boundary(
                site,
                import_path,
                name,
                workspace_status,
                format!("`{import_path}` is outside this partial Go workspace analysis"),
                "no_indexed_definition",
                format!("`{name}` is not indexed in Go package `{import_path}`"),
            );
        }
        if let Some(outcome) = tree.and_then(|tree| {
            resolve_go_local_selector_chain(
                analyzer,
                token,
                support,
                file,
                source,
                tree.root_node(),
                site,
                selector,
                call_evidence,
            )
        }) {
            return outcome;
        }
        let candidates = if selector.focus_segment == 1 {
            go_fqn_candidates(support, [format!("{importer_package}.{qualifier}.{name}")])
        } else {
            Vec::new()
        };
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
        return no_definition(
            "no_indexed_definition",
            format!("`{reference}` did not resolve to an indexed Go definition"),
        );
    }

    let candidates = go_package_member_candidates(support, &importer_package, reference);
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    let dot_imports = go_dot_import_paths(go, support, token, file);
    let mut dot_candidates = Vec::new();
    for import_path in &dot_imports {
        if !support.scope_step() {
            break;
        }
        dot_candidates.extend(go_package_member_candidates(
            support,
            import_path,
            reference,
        ));
    }
    sort_units(&mut dot_candidates);
    dot_candidates.dedup();
    if !dot_candidates.is_empty() {
        return candidates_outcome(dot_candidates);
    }
    let dot_import_statuses = dot_imports
        .iter()
        .map(|import_path| {
            (
                import_path.as_str(),
                go_workspace_package_status(support, import_path),
            )
        })
        .collect::<Vec<_>>();
    if let Some((import_path, _)) = dot_import_statuses
        .iter()
        .find(|(_, status)| *status == GoWorkspacePackageStatus::Unknown)
    {
        return go_workspace_package_status_unknown(import_path);
    }
    let external_dot_imports = dot_import_statuses
        .iter()
        .filter_map(|(import_path, status)| {
            (*status == GoWorkspacePackageStatus::Absent).then_some(*import_path)
        })
        .collect::<Vec<_>>();
    if let [import_path] = external_dot_imports.as_slice() {
        if go_internal_import_allowed(&importer_package, import_path)
            && let Some(parameter_count) = tree.and_then(|tree| {
                go_identifier_modeled_call_argument_count(
                    support,
                    token,
                    go,
                    file,
                    source,
                    tree.root_node(),
                    site,
                )
            })
            && let Some(outcome) = go_model_package_call_outcome(
                support,
                site,
                import_path,
                reference,
                parameter_count,
                call_evidence,
            )
        {
            return outcome;
        }
        if tree.is_some_and(|tree| go_identifier_is_call_target(support, tree.root_node(), site))
            && let Some(outcome) =
                go_model_published_member_call_shape_outcome(support, site, import_path, reference)
        {
            return outcome;
        }
        return go_imported_member_boundary(
            site,
            import_path,
            reference,
            GoWorkspacePackageStatus::Absent,
            format!("`{import_path}` is outside this partial Go workspace analysis"),
            "no_indexed_definition",
            format!("`{reference}` is not indexed in dot-imported Go package `{import_path}`"),
        );
    }
    if !external_dot_imports.is_empty() {
        // gated upstream: every retained dot import failed the workspace-path
        // predicate above. More than one package remains structurally
        // ambiguous, so no canonical external member identity can be carried.
        return boundary_unchecked(format!(
            "dot-imported packages {external_dot_imports:?} are outside this partial Go workspace analysis"
        ));
    }
    if brokk_bifrost_go::diagnostics::is_predeclared_go_name(reference) {
        return no_definition(
            PREDECLARED_SYMBOL_REFERENCE_DIAGNOSTIC_KIND,
            format!("`{reference}` is a predeclared Go symbol"),
        );
    }
    no_definition(
        "no_indexed_definition",
        format!("`{reference}` did not resolve to an indexed Go definition"),
    )
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
    no_definition_kind: impl Into<String>,
    no_definition_message: impl Into<String>,
) -> DefinitionLookupOutcome {
    let mut outcome = go_workspace_package_boundary(
        import_path,
        workspace_status,
        boundary_message,
        no_definition_kind,
        no_definition_message,
    );
    if outcome.status == DefinitionLookupStatus::UnresolvableImportBoundary {
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
        GoWorkspacePackageStatus::Absent => boundary_unchecked(boundary_message),
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

/// Resolve a keyed struct-composite label from the literal's structured owner.
///
/// The same `keyed_element` node represents struct labels, map keys, and
/// array/slice indexes in Go. A direct map/array/slice key remains an ordinary
/// expression; only a named literal owner, or a named element/value reached
/// through an elided literal boundary, owns a struct-field label.
fn go_keyed_composite_label_outcome(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
) -> Option<DefinitionLookupOutcome> {
    let selected =
        go_smallest_named_node_covering(support, root, site.focus_start_byte, site.focus_end_byte)?;
    let keyed = go_keyed_element_containing_key(support, selected)?;
    let key = keyed.child_by_field_name("key")?;
    let label_node = go_simple_composite_key_identifier(support, key, selected)?;

    if brokk_bifrost_go::graph::ast::composite_literal_owner_type_for_key(label_node)
        .is_some_and(|owner| matches!(owner.kind(), "map_type" | "array_type" | "slice_type"))
    {
        return None;
    }

    let direct_literal = keyed
        .parent()
        .filter(|parent| parent.kind() == "literal_value")?;
    if direct_literal
        .parent()
        .filter(|parent| parent.kind() == "composite_literal")
        .and_then(|literal| literal.child_by_field_name("type"))
        .is_some_and(|owner| matches!(owner.kind(), "map_type" | "array_type" | "slice_type"))
    {
        return None;
    }

    let label = go_node_text(label_node, source);
    let Some(owner_fqn) =
        go_composite_label_owner_fqn(analyzer, token, support, file, source, keyed)
    else {
        return Some(no_definition(
            GO_LITERAL_OWNER_UNRESOLVED_DIAGNOSTIC_KIND,
            format!(
                "could not resolve the exact Go composite-literal owner for field label `{label}`"
            ),
        ));
    };
    let candidates =
        go_composite_literal_field_candidates(analyzer, token, support, &owner_fqn, label);
    if candidates.is_empty() {
        return Some(no_definition(
            "no_indexed_definition",
            format!("`{label}` is not a direct field of Go literal owner `{owner_fqn}`"),
        ));
    }
    Some(candidates_outcome(candidates))
}

fn go_composite_literal_field_candidates(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn GoDefinitionProvider,
    owner_fqn: &str,
    label: &str,
) -> Vec<CodeUnit> {
    let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
        return Vec::new();
    };
    let mut owner_fqn = owner_fqn.to_string();
    let mut visited = HashSet::default();
    while visited.insert(owner_fqn.clone()) {
        let mut fields: Vec<_> = support
            .members_for_owner_name(&owner_fqn, label)
            .into_iter()
            .filter(CodeUnit::is_field)
            .collect();
        sort_units(&mut fields);
        fields.dedup();
        if !fields.is_empty() {
            return fields;
        }

        let mut underlying = Vec::new();
        for unit in support
            .fqn(&owner_fqn)
            .into_iter()
            .filter(CodeUnit::is_class)
        {
            if !support.scope_step() {
                return Vec::new();
            }
            for metadata in support.signature_metadata(analyzer, &unit) {
                if !support.scope_step() {
                    return Vec::new();
                }
                let Some(identity) = metadata.into_underlying_type_identity() else {
                    continue;
                };
                if let Some(fqn) = go_resolve_structured_type_fqn(
                    support,
                    token,
                    go,
                    unit.source(),
                    unit.package_name(),
                    &identity,
                ) {
                    underlying.push(fqn);
                }
            }
        }
        underlying.sort();
        underlying.dedup();
        let [next] = underlying.as_slice() else {
            return Vec::new();
        };
        owner_fqn.clone_from(next);
    }
    Vec::new()
}

enum GoCompositeOwnerStep {
    ContainerElementOrValue,
    MapKey,
    KeyedValue(Option<String>),
}

enum GoCompositeOwnerRef<'tree> {
    Syntax(Node<'tree>),
    IndexedType {
        file: ProjectFile,
        package: String,
        identity: StructuredTypeIdentity,
    },
}

fn go_composite_key_identifier_name(
    support: &dyn GoDefinitionProvider,
    key: Node<'_>,
    source: &str,
) -> Option<String> {
    if !support.scope_step() {
        return None;
    }
    if matches!(key.kind(), "identifier" | "field_identifier") {
        return Some(go_node_text(key, source).to_string());
    }
    if key.kind() != "literal_element" {
        return None;
    }
    let mut cursor = key.walk();
    let mut children = key.named_children(&mut cursor);
    let child = children.next()?;
    if !support.scope_step() || children.next().is_some() {
        return None;
    }
    matches!(child.kind(), "identifier" | "field_identifier")
        .then(|| go_node_text(child, source).to_string())
}

fn go_keyed_element_containing_key<'tree>(
    support: &dyn GoDefinitionProvider,
    mut node: Node<'tree>,
) -> Option<Node<'tree>> {
    let selected_start = node.start_byte();
    let selected_end = node.end_byte();
    loop {
        if !support.scope_step() {
            return None;
        }
        if node.kind() == "keyed_element" {
            let key = node.child_by_field_name("key")?;
            return (key.start_byte() <= selected_start && selected_end <= key.end_byte())
                .then_some(node);
        }
        node = node.parent()?;
    }
}

fn go_simple_composite_key_identifier<'tree>(
    support: &dyn GoDefinitionProvider,
    key: Node<'tree>,
    selected: Node<'tree>,
) -> Option<Node<'tree>> {
    if !support.scope_step() {
        return None;
    }
    let identifier = if matches!(key.kind(), "identifier" | "field_identifier") {
        key
    } else if key.kind() == "literal_element" {
        let mut cursor = key.walk();
        let mut children = key.named_children(&mut cursor);
        let child = children.next()?;
        if !support.scope_step() {
            return None;
        }
        if let Some(_extra) = children.next() {
            let _ = support.scope_step();
            return None;
        }
        if !matches!(child.kind(), "identifier" | "field_identifier") {
            return None;
        }
        child
    } else {
        return None;
    };
    (identifier.start_byte() <= selected.start_byte()
        && selected.end_byte() <= identifier.end_byte())
    .then_some(identifier)
}

fn go_composite_label_owner_fqn(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    keyed: Node<'_>,
) -> Option<String> {
    if !support.scope_step() {
        return None;
    }
    let mut literal = keyed
        .parent()
        .filter(|parent| parent.kind() == "literal_value")?;
    let mut steps = Vec::new();
    let owner = loop {
        if !support.scope_step() {
            return None;
        }
        let parent = literal.parent()?;
        if !support.scope_step() {
            return None;
        }
        match parent.kind() {
            "composite_literal" => {
                break GoCompositeOwnerRef::Syntax(parent.child_by_field_name("type")?);
            }
            "keyed_element" => {
                let value = parent.child_by_field_name("value")?;
                let step = if value.id() == literal.id() {
                    GoCompositeOwnerStep::KeyedValue(go_composite_key_identifier_name(
                        support,
                        parent.child_by_field_name("key")?,
                        source,
                    ))
                } else if parent
                    .child_by_field_name("key")
                    .is_some_and(|key| key.id() == literal.id())
                {
                    GoCompositeOwnerStep::MapKey
                } else {
                    return None;
                };
                steps.push(step);
                literal = parent
                    .parent()
                    .filter(|ancestor| ancestor.kind() == "literal_value")?;
            }
            "literal_value" => {
                steps.push(GoCompositeOwnerStep::ContainerElementOrValue);
                literal = parent;
            }
            "literal_element" => {
                let container = parent.parent()?;
                if !support.scope_step() {
                    return None;
                }
                literal = match container.kind() {
                    "keyed_element" => {
                        let value = container.child_by_field_name("value")?;
                        let step = if value.id() == parent.id() {
                            GoCompositeOwnerStep::KeyedValue(go_composite_key_identifier_name(
                                support,
                                container.child_by_field_name("key")?,
                                source,
                            ))
                        } else if container
                            .child_by_field_name("key")
                            .is_some_and(|key| key.id() == parent.id())
                        {
                            GoCompositeOwnerStep::MapKey
                        } else {
                            return None;
                        };
                        steps.push(step);
                        container
                            .parent()
                            .filter(|ancestor| ancestor.kind() == "literal_value")?
                    }
                    "literal_value" => {
                        steps.push(GoCompositeOwnerStep::ContainerElementOrValue);
                        container
                    }
                    _ => return None,
                };
            }
            _ => return None,
        }
    };

    let mut owner = owner;
    for step in steps.into_iter().rev() {
        if !support.scope_step() {
            return None;
        }
        owner = match step {
            GoCompositeOwnerStep::ContainerElementOrValue => {
                go_composite_owner_container_step(analyzer, token, support, file, source, owner)?
            }
            GoCompositeOwnerStep::MapKey => {
                go_composite_owner_map_key_step(analyzer, token, support, file, source, owner)?
            }
            GoCompositeOwnerStep::KeyedValue(field) => go_composite_owner_keyed_value_step(
                analyzer,
                token,
                support,
                file,
                source,
                owner,
                field.as_deref(),
            )?,
        };
    }

    match owner {
        GoCompositeOwnerRef::Syntax(owner_type) => {
            if matches!(owner_type.kind(), "map_type" | "array_type" | "slice_type") {
                return None;
            }
            go_resolve_type_fqn(analyzer, token, support, file, source, owner_type)
        }
        GoCompositeOwnerRef::IndexedType {
            file,
            package,
            identity,
        } => go_resolve_structured_type_fqn(
            support,
            token,
            resolve_analyzer::<GoAnalyzer>(analyzer)?,
            &file,
            &package,
            &identity,
        ),
    }
}

fn go_composite_owner_map_key_step<'tree>(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    owner: GoCompositeOwnerRef<'tree>,
) -> Option<GoCompositeOwnerRef<'tree>> {
    match owner {
        GoCompositeOwnerRef::Syntax(owner_type) => {
            if let Some(key) = go_composite_map_key_type(support, owner_type) {
                return Some(GoCompositeOwnerRef::Syntax(key));
            }
            go_named_underlying_composite_owner(analyzer, token, support, file, source, owner_type)?
                .and_then_map_key(support)
        }
        GoCompositeOwnerRef::IndexedType {
            file,
            package,
            identity,
        } => identity
            .into_map_key_with(|| support.scope_step())
            .map(|identity| GoCompositeOwnerRef::IndexedType {
                file,
                package,
                identity,
            }),
    }
}

fn go_composite_owner_container_step<'tree>(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    owner: GoCompositeOwnerRef<'tree>,
) -> Option<GoCompositeOwnerRef<'tree>> {
    match owner {
        GoCompositeOwnerRef::Syntax(owner_type) => {
            if let Some(element) = go_composite_container_element_or_value_type(support, owner_type)
            {
                return Some(GoCompositeOwnerRef::Syntax(element));
            }
            go_named_underlying_composite_owner(analyzer, token, support, file, source, owner_type)?
                .and_then_container_element(support)
        }
        GoCompositeOwnerRef::IndexedType {
            file,
            package,
            identity,
        } => identity
            .into_container_element_with(|| support.scope_step())
            .map(|identity| GoCompositeOwnerRef::IndexedType {
                file,
                package,
                identity,
            }),
    }
}

impl<'tree> GoCompositeOwnerRef<'tree> {
    fn and_then_container_element(self, support: &dyn GoDefinitionProvider) -> Option<Self> {
        match self {
            Self::IndexedType {
                file,
                package,
                identity,
            } => identity
                .into_container_element_with(|| support.scope_step())
                .map(|identity| Self::IndexedType {
                    file,
                    package,
                    identity,
                }),
            Self::Syntax(_) => None,
        }
    }

    fn and_then_map_key(self, support: &dyn GoDefinitionProvider) -> Option<Self> {
        match self {
            Self::IndexedType {
                file,
                package,
                identity,
            } => identity
                .into_map_key_with(|| support.scope_step())
                .map(|identity| Self::IndexedType {
                    file,
                    package,
                    identity,
                }),
            Self::Syntax(_) => None,
        }
    }
}

fn go_named_underlying_composite_owner<'tree>(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    owner_type: Node<'tree>,
) -> Option<GoCompositeOwnerRef<'tree>> {
    let owner_fqn = go_resolve_type_fqn(analyzer, token, support, file, source, owner_type)?;
    let mut candidates = Vec::new();
    for unit in support
        .fqn(&owner_fqn)
        .into_iter()
        .filter(CodeUnit::is_class)
    {
        if !support.scope_step() {
            return None;
        }
        for metadata in support.signature_metadata(analyzer, &unit) {
            if !support.scope_step() {
                return None;
            }
            let Some(identity) = metadata.into_underlying_type_identity() else {
                continue;
            };
            candidates.push((
                unit.source().clone(),
                unit.package_name().to_string(),
                identity,
            ));
        }
    }
    let (file, package, identity) = (candidates.len() == 1)
        .then(|| candidates.pop())
        .flatten()?;
    Some(GoCompositeOwnerRef::IndexedType {
        file,
        package,
        identity,
    })
}

fn go_composite_owner_keyed_value_step<'tree>(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    owner: GoCompositeOwnerRef<'tree>,
    field: Option<&str>,
) -> Option<GoCompositeOwnerRef<'tree>> {
    let owner = match owner {
        GoCompositeOwnerRef::Syntax(owner_type) => {
            if matches!(owner_type.kind(), "map_type" | "array_type" | "slice_type") {
                return Some(GoCompositeOwnerRef::Syntax(
                    go_composite_container_element_or_value_type(support, owner_type)?,
                ));
            }
            if let Some(owner) = go_named_underlying_composite_owner(
                analyzer, token, support, file, source, owner_type,
            ) {
                owner
            } else {
                let identity = crate::analyzer::go::go_structured_type_identity_bounded(
                    owner_type,
                    source,
                    || support.scope_step(),
                )?;
                GoCompositeOwnerRef::IndexedType {
                    file: file.clone(),
                    package: go_package_name(
                        support,
                        file,
                        source,
                        Some(go_syntax_root(support, owner_type)?),
                    )?,
                    identity,
                }
            }
        }
        GoCompositeOwnerRef::IndexedType {
            file,
            package,
            identity,
        } => GoCompositeOwnerRef::IndexedType {
            file,
            package,
            identity,
        },
    };

    let owner_fqn = match &owner {
        GoCompositeOwnerRef::Syntax(_) => return None,
        GoCompositeOwnerRef::IndexedType {
            file,
            package,
            identity,
        } => go_resolve_structured_type_fqn(
            support,
            token,
            resolve_analyzer::<GoAnalyzer>(analyzer)?,
            file,
            package,
            identity,
        ),
    };

    if let Some(field) = field
        && let Some((field_unit, identity)) = owner_fqn.as_deref().and_then(|owner_fqn| {
            go_indexed_field_type_identity(analyzer, token, support, owner_fqn, field)
        })
    {
        return Some(GoCompositeOwnerRef::IndexedType {
            file: field_unit.source().clone(),
            package: field_unit.package_name().to_string(),
            identity,
        });
    }

    match owner {
        GoCompositeOwnerRef::IndexedType {
            file,
            package,
            identity,
        } => identity
            .into_container_element_with(|| support.scope_step())
            .map(|identity| GoCompositeOwnerRef::IndexedType {
                file,
                package,
                identity,
            }),
        GoCompositeOwnerRef::Syntax(_) => None,
    }
}

fn go_composite_container_element_or_value_type<'tree>(
    support: &dyn GoDefinitionProvider,
    mut node: Node<'tree>,
) -> Option<Node<'tree>> {
    loop {
        if !support.scope_step() {
            return None;
        }
        match node.kind() {
            "array_type" => return node.child_by_field_name("element"),
            "slice_type" => return node.named_child(0),
            "map_type" => return node.child_by_field_name("value"),
            "pointer_type" | "parenthesized_type" => node = node.named_child(0)?,
            _ => return None,
        }
    }
}

fn go_composite_map_key_type<'tree>(
    support: &dyn GoDefinitionProvider,
    mut node: Node<'tree>,
) -> Option<Node<'tree>> {
    loop {
        if !support.scope_step() {
            return None;
        }
        match node.kind() {
            "map_type" => return node.child_by_field_name("key"),
            "pointer_type" | "parenthesized_type" => node = node.named_child(0)?,
            _ => return None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GoTypeLookupResolutionKind {
    Expression,
    InterfaceMethodOwner,
}

#[derive(Debug, Clone)]
pub(crate) struct GoTypeLookupResolution {
    pub(crate) fqn: String,
    pub(crate) kind: GoTypeLookupResolutionKind,
    pub(crate) member_name: Option<String>,
}

pub(crate) fn go_type_lookup_resolution(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
) -> Option<GoTypeLookupResolution> {
    let node =
        go_smallest_named_node_covering(support, root, site.focus_start_byte, site.focus_end_byte)?;
    if let Some((fqn, member_name)) =
        go_interface_method_owner_type_fqn(support, file, source, root, node)
    {
        return Some(GoTypeLookupResolution {
            fqn,
            kind: GoTypeLookupResolutionKind::InterfaceMethodOwner,
            member_name: Some(member_name),
        });
    }

    let expression = go_type_lookup_expression(support, node)?;
    let fqn = go_expression_type_fqn(
        analyzer,
        token,
        support,
        file,
        source,
        root,
        expression,
        site.range.start_byte,
        0,
    )?;
    Some(GoTypeLookupResolution {
        fqn,
        kind: GoTypeLookupResolutionKind::Expression,
        member_name: None,
    })
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
        Some(root) => go_declared_package_name(support, root, source)?,
        None if support.session().is_none() => parse_go_tree(source)
            .map(|tree| crate::analyzer::go::determine_go_package_name(tree.root_node(), source))
            .unwrap_or_default(),
        None => return None,
    };
    Some(crate::analyzer::go::packages::canonical_go_package_name(
        file, &declared,
    ))
}

fn go_declared_package_name(
    support: &dyn GoDefinitionProvider,
    root: Node<'_>,
    source: &str,
) -> Option<String> {
    if !support.scope_step() {
        return None;
    }
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if !support.scope_step() {
            return None;
        }
        if child.kind() != "package_clause" {
            continue;
        }
        let mut package_cursor = child.walk();
        for package_child in child.named_children(&mut package_cursor) {
            if !support.scope_step() {
                return None;
            }
            if matches!(package_child.kind(), "package_identifier" | "identifier") {
                return Some(go_node_text(package_child, source).to_string());
            }
        }
    }
    Some(String::new())
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

pub(super) fn go_definition_import_namespaces(
    support: &dyn GoDefinitionProvider,
    token: QueryToken<'_>,
    go: &GoAnalyzer,
    file: &ProjectFile,
) -> (HashMap<String, Vec<String>>, Vec<String>) {
    if support.session().is_some() {
        let mut aliases: HashMap<String, Vec<String>> = HashMap::default();
        let mut dot_imports = Vec::new();
        for import in support.import_infos(token, go, file) {
            let Some(import_path) = go_structured_import_path(support, &import) else {
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
            path.kind == Some(crate::analyzer::StructuredImportPathKind::Namespace)
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
    if path.kind != Some(crate::analyzer::StructuredImportPathKind::Namespace)
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
    let mut candidates = support.fqn(&format!("{package}.{name}"));
    candidates.extend(support.fqn(&format!(
        "{package}.{}.{name}",
        crate::analyzer::GO_MODULE_SCOPE_SEGMENT
    )));
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
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

fn go_package_selector_chain_outcome(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn GoDefinitionProvider,
    go: &GoAnalyzer,
    package: &str,
    source: &str,
    selector: &GoSelectorDescriptor<'_>,
) -> Option<DefinitionLookupOutcome> {
    let first_member = selector.member_name(source, 0)?;
    let mut candidates = go_package_member_candidates(support, package, first_member);
    if selector.focus_segment == 1 {
        return (!candidates.is_empty()).then(|| candidates_outcome(candidates));
    }
    if candidates.len() != 1 || !support.scope_step() {
        return None;
    }

    let package_variable = candidates.pop()?;
    let variable_file = package_variable.source().clone();
    let variable_source = variable_file.read_to_string().ok()?;
    let variable_tree = parse_go_tree(&variable_source)?;
    let variable_root = variable_tree.root_node();
    let binding = go_package_variable_binding(
        support,
        variable_root,
        &variable_source,
        package_variable.identifier(),
    )?;
    let binding_node = match &binding {
        GoLocalBinding::Type(node) | GoLocalBinding::RangeElement(node) => *node,
        GoLocalBinding::Value { expression, .. } => *expression,
        GoLocalBinding::Opaque => return None,
    };
    let owner = match binding {
        GoLocalBinding::Type(type_node) => go_inferred_type_from_node(
            support,
            type_node,
            &variable_file,
            &variable_source,
            package,
        ),
        GoLocalBinding::Value {
            expression,
            result_ordinal,
        } => go_expression_inferred_type(
            analyzer,
            token,
            support,
            &variable_file,
            &variable_source,
            variable_root,
            expression,
            expression.start_byte(),
            result_ordinal,
        ),
        GoLocalBinding::RangeElement(_) => None,
        GoLocalBinding::Opaque => None,
    };
    let Some(mut owner) = owner else {
        return go_external_import_in_expression(
            support,
            token,
            go,
            &variable_file,
            &variable_source,
            binding_node,
        )
        .map(|import_path| {
            boundary_unchecked(format!(
                "`{import_path}` is outside this partial Go workspace analysis"
            ))
        });
    };
    let Some(mut owner_fqn) = go_resolve_inferred_type_fqn(support, token, go, &owner) else {
        return go_external_import_in_expression(
            support,
            token,
            go,
            &variable_file,
            &variable_source,
            binding_node,
        )
        .map(|import_path| {
            boundary_unchecked(format!(
                "`{import_path}` is outside this partial Go workspace analysis"
            ))
        });
    };

    for member_node in selector.members.iter().take(selector.focus_segment).skip(1) {
        if !support.scope_step() {
            return None;
        }
        let member = go_node_text(*member_node, source);
        let lookup = go_indexed_field_lookup_with_method_set(
            analyzer,
            token,
            support,
            &owner_fqn,
            member,
            Some(&owner),
        );
        match lookup {
            GoDefinitionMemberLookup::Unique(candidate) => {
                if *member_node == selector.focused_node() {
                    return Some(candidates_outcome(vec![candidate]));
                }
                owner = go_field_inferred_type_for_receiver(
                    analyzer, token, support, &owner, &owner_fqn, member,
                )?;
                owner_fqn = go_resolve_inferred_type_fqn(support, token, go, &owner)?;
            }
            GoDefinitionMemberLookup::Ambiguous(candidates) => {
                return Some(go_ambiguous_selector_outcome(support, member, candidates));
            }
            GoDefinitionMemberLookup::Missing => {
                return Some(no_definition(
                    "no_indexed_definition",
                    format!("`{member}` is not indexed for Go type `{owner_fqn}`"),
                ));
            }
        }
    }
    None
}

fn go_package_variable_binding<'tree>(
    support: &dyn GoDefinitionProvider,
    root: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<GoLocalBinding<'tree>> {
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if !support.scope_step() {
            return None;
        }
        if child.kind() == "var_declaration"
            && let Some(binding) = go_var_declaration_binding(support, child, source, name)
        {
            return Some(binding);
        }
    }
    None
}

fn go_external_import_in_expression(
    support: &dyn GoDefinitionProvider,
    token: QueryToken<'_>,
    go: &GoAnalyzer,
    file: &ProjectFile,
    source: &str,
    expression: Node<'_>,
) -> Option<String> {
    let imports = go_import_paths(support, token, go, file);
    let mut stack = vec![expression];
    while let Some(node) = stack.pop() {
        if !support.scope_step() {
            return None;
        }
        if matches!(node.kind(), "identifier" | "package_identifier")
            && let Some(import_path) = imports.get(go_node_text(node, source))
            && go_workspace_package_status(support, import_path) == GoWorkspacePackageStatus::Absent
        {
            return Some(import_path.clone());
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    None
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

fn go_model_package_selector_shape_outcome(
    support: &dyn GoDefinitionProvider,
    site: &ResolvedReferenceSite,
    package: &str,
    source: &str,
    selector: &GoSelectorDescriptor<'_>,
) -> Option<DefinitionLookupOutcome> {
    if selector.focus_segment != 1 || !go_selector_is_call_target(support, selector) {
        return None;
    }
    go_model_published_member_call_shape_outcome(
        support,
        site,
        package,
        go_node_text(selector.focused_node(), source),
    )
}

fn go_model_package_selector_navigation_outcome(
    support: &dyn GoDefinitionProvider,
    site: &ResolvedReferenceSite,
    package: &str,
    source: &str,
    selector: &GoSelectorDescriptor<'_>,
) -> Option<DefinitionLookupOutcome> {
    if selector.focus_segment == 0 || go_selector_is_call_target(support, selector) {
        return None;
    }
    let mut members = selector.members.iter().take(selector.focus_segment);
    let first_member = go_node_text(*members.next()?, source);
    let mut target = support.external_visible_package_member(package, first_member)?;
    let mut canonical_reference = format!("{package}.{first_member}");
    for member in members {
        let member = go_node_text(*member, source);
        target.push('.');
        target.push_str(member);
        target = support.external_visible_symbol(&target)?;
        canonical_reference.push('.');
        canonical_reference.push_str(member);
    }
    let mut reference = site.clone();
    // The overlay storage owner is an implementation detail. Keep the exact
    // import-path spelling supplied by the structured import binder.
    reference.text = canonical_reference;
    Some(DefinitionLookupOutcome {
        status: DefinitionLookupStatus::NoDefinition,
        reference: Some(reference),
        definitions: Vec::new(),
        lexical_definition: None,
        diagnostics: Vec::new(),
    })
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
            boundary_unchecked(format!(
                "`{canonical_reference}` is declared by an activated external Go model"
            ))
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

fn go_model_concrete_receiver_outcome(
    support: &dyn GoDefinitionProvider,
    site: &ResolvedReferenceSite,
    owner_fqn: &str,
    member: &str,
    pointer_receivers: bool,
    parameter_count: usize,
    call_evidence: &mut GoCallEvidence,
) -> Option<DefinitionLookupOutcome> {
    let target = support.external_concrete_receiver_member(
        owner_fqn,
        member,
        pointer_receivers,
        parameter_count,
    )?;
    let parameter_count = u32::try_from(parameter_count).ok()?;
    call_evidence.record_exact_external_call(ExactExternalCallProof::go_concrete_receiver(
        target.clone(),
        parameter_count,
    ));
    // gated upstream: structured workspace type resolution failed before the
    // import-binder identity was offered to the reviewed declaration overlay.
    let mut outcome = boundary_unchecked(format!(
        "`{target}` is declared by an activated external Go model"
    ));
    let mut reference = site.clone();
    reference.text = target;
    outcome.reference = Some(reference);
    Some(outcome)
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
    support
        .import_infos(token, go, file)
        .into_iter()
        .filter_map(|import| {
            (import.alias.as_deref() == Some("."))
                .then(|| go_structured_import_path(support, &import))
                .flatten()
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn resolve_go_local_selector_chain(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
    selector: &GoSelectorDescriptor<'_>,
    call_evidence: &mut GoCallEvidence,
) -> Option<DefinitionLookupOutcome> {
    if selector.focus_segment == 0 {
        return None;
    }

    // Type the chain's structured base node directly. This supports both plain
    // identifiers and expression receivers such as `T{}` or `f()` without
    // reconstructing selector syntax from expanded source text.
    let go = resolve_analyzer::<GoAnalyzer>(analyzer)?;
    let mut owner_inferred = go_expression_inferred_type(
        analyzer,
        token,
        support,
        file,
        source,
        root,
        selector.base,
        site.focus_start_byte,
        0,
    );
    if owner_inferred.is_some() {
        call_evidence.application = CallApplicationKind::BoundReceiver;
    }
    let mut external_concrete_receiver_candidate = false;
    let mut owner_fqn = match owner_inferred.as_ref() {
        Some(owner) => {
            if let Some(modeled) = owner.modeled_nominal() {
                external_concrete_receiver_candidate = true;
                modeled.qualified_name.clone()
            } else {
                match go_resolve_inferred_type_fqn(support, token, go, owner) {
                    Some(owner_fqn) => owner_fqn,
                    None => {
                        let identity = owner.indexed_identity()?;
                        let owner_fqn = go_imported_nominal_receiver_candidate_fqn(
                            support,
                            token,
                            go,
                            &owner.file,
                            identity,
                        )?;
                        external_concrete_receiver_candidate = true;
                        owner_fqn
                    }
                }
            }
        }
        None => selector.base_identifier(source).and_then(|base| {
            go_binding_type_fqn(
                analyzer,
                token,
                support,
                file,
                source,
                root,
                base,
                site.focus_start_byte,
            )
        })?,
    };
    call_evidence.application = CallApplicationKind::BoundReceiver;
    // Both inference routes above start from an expression or a value binding.
    // A Go type name does not enter either route, so `T.M` method expressions
    // remain unknown and keep receiver-contract arity conservative.
    for (index, member) in selector
        .members
        .iter()
        .take(selector.focus_segment)
        .enumerate()
    {
        if !support.scope_step() {
            return None;
        }
        let member = go_node_text(*member, source);
        let lookup = match owner_inferred.as_ref() {
            Some(owner) => go_indexed_field_lookup_with_method_set(
                analyzer,
                token,
                support,
                &owner_fqn,
                member,
                Some(owner),
            ),
            None => go_indexed_field_lookup(analyzer, token, support, &owner_fqn, member),
        };
        if let GoDefinitionMemberLookup::Ambiguous(candidates) = &lookup {
            return Some(go_ambiguous_selector_outcome(
                support,
                member,
                candidates.clone(),
            ));
        }
        if index + 1 == selector.focus_segment {
            return match lookup {
                GoDefinitionMemberLookup::Unique(candidate) => {
                    Some(candidates_outcome(vec![candidate]))
                }
                GoDefinitionMemberLookup::Ambiguous(_) => unreachable!("handled above"),
                GoDefinitionMemberLookup::Missing => {
                    if external_concrete_receiver_candidate
                        && let Some(owner) = owner_inferred.as_ref()
                        && let Some(parameter_count) = go_selector_modeled_call_argument_count(
                            support, token, go, file, source, selector,
                        )
                        && let Some(outcome) = go_model_concrete_receiver_outcome(
                            support,
                            site,
                            &owner_fqn,
                            member,
                            owner.admits_pointer_receivers(),
                            parameter_count,
                            call_evidence,
                        )
                    {
                        return Some(outcome);
                    }
                    Some(no_definition(
                        "no_indexed_definition",
                        format!("`{member}` did not resolve to an indexed Go definition"),
                    ))
                }
            };
        }
        if external_concrete_receiver_candidate {
            // The reviewed external slice proves only a direct method on the
            // concrete receiver. It carries no field/result surface for a
            // longer selector chain.
            return None;
        }
        if let Some(owner) = owner_inferred.take() {
            let next_owner = go_field_inferred_type_for_receiver(
                analyzer, token, support, &owner, &owner_fqn, member,
            )?;
            let next_owner_fqn = go_resolve_inferred_type_fqn(support, token, go, &next_owner)?;
            owner_fqn = next_owner_fqn;
            owner_inferred = Some(next_owner);
        } else {
            let next_owner =
                go_indexed_field_type_fqn(analyzer, token, support, &owner_fqn, member)?;
            owner_fqn = next_owner;
        }
    }
    None
}

fn go_ambiguous_selector_outcome(
    support: &dyn GoDefinitionProvider,
    member: &str,
    candidates: Vec<CodeUnit>,
) -> DefinitionLookupOutcome {
    let message = format!(
        "`{member}` resolves to multiple Go embedded members at the nearest promotion depth"
    );
    if !support.retain_ambiguous_candidate_evidence() {
        // no candidates: this provider deliberately withholds candidate
        // evidence, and the ICFG contract reads the ambiguous status as a
        // `DispatchUnresolved` boundary.
        return ambiguous_without_candidates(message);
    }
    ambiguous_candidates_outcome(candidates, message)
}

#[allow(clippy::too_many_arguments)]
fn go_binding_type_fqn(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    byte: usize,
) -> Option<String> {
    go_receiver_binding_type_fqn(analyzer, token, support, file, source, root, name, byte).or_else(
        || go_local_binding_type_fqn(analyzer, token, support, file, source, root, name, byte),
    )
}

#[allow(clippy::too_many_arguments)]
fn go_receiver_binding_type_fqn(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    byte: usize,
) -> Option<String> {
    let type_node = go_receiver_binding_type_node(support, root, source, name, byte)?;
    go_resolve_type_fqn(analyzer, token, support, file, source, type_node)
}

fn go_receiver_binding_type_node<'tree>(
    support: &dyn GoDefinitionProvider,
    root: Node<'tree>,
    source: &str,
    name: &str,
    byte: usize,
) -> Option<Node<'tree>> {
    let mut current = go_smallest_named_node_covering(support, root, byte, byte)?;
    loop {
        if !support.scope_step() {
            return None;
        }
        if current.kind() == "method_declaration"
            && let Some(receiver) = current.child_by_field_name("receiver")
            && let Some(type_node) = go_parameter_type_for_name(support, receiver, source, name)
        {
            return Some(type_node);
        }
        current = current.parent()?;
    }
}

/// The type a local `name` is bound to, resolved by walking the parsed AST
/// outward from `byte`. Each enclosing scope is searched for the nearest
/// preceding `:=` or `var` declaration of `name`; the innermost match wins, so
/// shadowing is respected. An `if`/`for` initializer is a named child of the
/// statement node we walk through, so those bindings are covered too.
#[allow(clippy::too_many_arguments)]
fn go_local_binding_type_fqn(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    byte: usize,
) -> Option<String> {
    let mut scope = go_smallest_named_node_covering(support, root, byte, byte)?;
    loop {
        if !support.scope_step() {
            return None;
        }
        if let Some(binding) = go_nearest_binding_in_scope(support, scope, source, name, byte) {
            return match binding {
                GoLocalBinding::Type(type_node) => {
                    go_resolve_type_fqn(analyzer, token, support, file, source, type_node)
                }
                GoLocalBinding::Value {
                    expression,
                    result_ordinal,
                } => go_value_type_fqn(
                    analyzer,
                    token,
                    support,
                    file,
                    source,
                    root,
                    expression,
                    byte,
                    result_ordinal,
                ),
                GoLocalBinding::RangeElement(range_node) => go_range_binding_type_fqn(
                    analyzer, token, support, file, source, root, range_node,
                ),
                GoLocalBinding::Opaque => None,
            };
        }
        scope = scope.parent()?;
    }
}

/// How a local binding names its type: an explicit `var x T` annotation, or the
/// value expression of an inferred `x := value` binding to derive it from. An
/// opaque binding still has exact lexical authority to shadow an import even
/// when this resolver has no useful type to infer for its value.
enum GoLocalBinding<'tree> {
    Type(Node<'tree>),
    Value {
        expression: Node<'tree>,
        result_ordinal: usize,
    },
    RangeElement(Node<'tree>),
    Opaque,
}

fn go_nearest_binding_in_scope<'tree>(
    support: &dyn GoDefinitionProvider,
    scope: Node<'tree>,
    source: &str,
    name: &str,
    byte: usize,
) -> Option<GoLocalBinding<'tree>> {
    let mut cursor = scope.walk();
    let mut nearest: Option<(usize, GoLocalBinding<'tree>)> = None;
    for child in scope.named_children(&mut cursor) {
        if !support.scope_step() {
            return None;
        }
        if child.end_byte() > byte {
            continue;
        }
        let binding = match child.kind() {
            "parameter_list" => go_parameter_list_binding(support, child, source, name),
            "short_var_declaration" => go_short_var_binding(support, child, source, name),
            "var_declaration" => go_var_declaration_binding(support, child, source, name),
            "var_spec" if !go_spec_is_package_scoped(support, child)? => {
                go_var_spec_binding(support, child, source, name)
            }
            "const_declaration" if scope.kind() != "source_file" => {
                go_const_declaration_binding(support, child, source, name)
            }
            "const_spec" if !go_spec_is_package_scoped(support, child)? => {
                go_const_spec_binding(support, child, source, name)
            }
            "range_clause" => go_range_binding(support, child, source, name),
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
        if parameter.kind() != "parameter_declaration" {
            continue;
        }
        let Some(type_node) = go_parameter_type_for_name(support, parameter, source, name) else {
            continue;
        };
        return Some(GoLocalBinding::Type(type_node));
    }
    None
}

fn go_range_binding<'tree>(
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
    (index == 1).then_some(GoLocalBinding::RangeElement(node))
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
    let right = node.child_by_field_name("right")?;
    go_expression_list_binding(support, right, index)
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
        if matches!(owner.kind(), "const_declaration" | "var_declaration") {
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
    let value_list = spec.child_by_field_name("value")?;
    go_expression_list_binding(support, value_list, index)
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
        // `a, b := f()` selects two result ordinals from one expression;
        // `a, b := f(), g()` selects result zero from each expression.
        if let [expression] = expressions.as_slice() {
            return Some(GoLocalBinding::Value {
                expression: *expression,
                result_ordinal: index,
            });
        }
        expressions
            .get(index)
            .copied()
            .map(|expression| GoLocalBinding::Value {
                expression,
                result_ordinal: 0,
            })
    } else {
        Some(GoLocalBinding::Value {
            expression: list,
            result_ordinal: index,
        })
    }
}

fn go_first_named_child<'tree>(
    support: &dyn GoDefinitionProvider,
    node: Node<'tree>,
) -> Option<Node<'tree>> {
    if !support.scope_step() {
        return None;
    }
    let mut cursor = node.walk();
    let child = node.named_children(&mut cursor).next()?;
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

fn go_callable_modeled_argument_count(
    support: &dyn GoDefinitionProvider,
    token: QueryToken<'_>,
    go: &GoAnalyzer,
    file: &ProjectFile,
    source: &str,
    callable: Node<'_>,
) -> Option<usize> {
    let call = go_call_for_callable(support, callable)?;
    let arguments = go_call_arguments(support, call)?;
    if arguments.has_spread {
        return None;
    }
    match arguments.possible_multi_result_call {
        Some(inner_call) => {
            go_exact_modeled_package_call_result_count(support, token, go, file, source, inner_call)
                .filter(|result_count| *result_count > 0)
        }
        None => Some(arguments.count),
    }
}

fn go_exact_modeled_package_call_result_count(
    support: &dyn GoDefinitionProvider,
    token: QueryToken<'_>,
    go: &GoAnalyzer,
    file: &ProjectFile,
    source: &str,
    call: Node<'_>,
) -> Option<usize> {
    if !support.scope_step() {
        return None;
    }
    let function = call.child_by_field_name("function")?;
    if function.kind() != "selector_expression" || !support.scope_step() {
        return None;
    }
    let qualifier = go_first_named_child(support, function)?;
    let member = go_last_named_child(support, function)?;
    if !matches!(qualifier.kind(), "identifier" | "package_identifier") {
        return None;
    }
    let mut root = call;
    while let Some(parent) = root.parent() {
        if !support.scope_step() {
            return None;
        }
        root = parent;
    }
    let qualifier_name = go_node_text(qualifier, source);
    if go_nearest_visible_binding(support, root, source, qualifier_name, call.start_byte())
        .is_some()
    {
        return None;
    }
    let import_path = go_import_paths(support, token, go, file).remove(qualifier_name)?;
    if go_workspace_package_status(support, &import_path) != GoWorkspacePackageStatus::Absent {
        return None;
    }
    let importer_package = go_package_name(support, file, source, Some(root))?;
    if !go_internal_import_allowed(&importer_package, &import_path) {
        return None;
    }
    let inner_arguments = go_call_arguments(support, call)?;
    if inner_arguments.has_spread || inner_arguments.possible_multi_result_call.is_some() {
        return None;
    }
    support.external_package_call_result_count(
        &import_path,
        go_node_text(member, source),
        inner_arguments.count,
    )
}

fn go_call_for_callable<'tree>(
    support: &dyn GoDefinitionProvider,
    callable: Node<'tree>,
) -> Option<Node<'tree>> {
    if !support.scope_step() {
        return None;
    }
    let call = callable.parent()?;
    (call.kind() == "call_expression"
        && call
            .child_by_field_name("function")
            .is_some_and(|function| function.id() == callable.id()))
    .then_some(call)
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

struct GoInferredType {
    identity: GoInferredTypeIdentity,
    file: ProjectFile,
    package: String,
    addressable: bool,
}

enum GoInferredTypeIdentity {
    Indexed(StructuredTypeIdentity),
    Modeled(GoModeledNominalType),
}

impl GoInferredType {
    fn indexed_identity(&self) -> Option<&StructuredTypeIdentity> {
        match &self.identity {
            GoInferredTypeIdentity::Indexed(identity) => Some(identity),
            GoInferredTypeIdentity::Modeled(_) => None,
        }
    }

    fn modeled_nominal(&self) -> Option<&GoModeledNominalType> {
        match &self.identity {
            GoInferredTypeIdentity::Indexed(_) => None,
            GoInferredTypeIdentity::Modeled(nominal) => Some(nominal),
        }
    }

    fn admits_pointer_receivers(&self) -> bool {
        self.addressable
            || match &self.identity {
                GoInferredTypeIdentity::Indexed(identity) => identity.is_pointer(),
                GoInferredTypeIdentity::Modeled(nominal) => nominal.pointer,
            }
    }
}

enum GoTypeInferenceFrame<'tree> {
    Expression {
        node: Node<'tree>,
        reference_byte: usize,
        result_ordinal: usize,
    },
    Field(String),
    Method {
        name: String,
        parameter_count: usize,
        result_ordinal: usize,
    },
    Element,
    MakeAddressable,
    AddressOf,
    Dereference,
    MakeNonAddressable,
}

#[allow(clippy::too_many_arguments)]
fn go_expression_inferred_type(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    byte: usize,
    result_ordinal: usize,
) -> Option<GoInferredType> {
    let go = resolve_analyzer::<GoAnalyzer>(analyzer)?;
    let package = go_package_name(support, file, source, Some(root))?;
    let mut frames = vec![GoTypeInferenceFrame::Expression {
        node: expression,
        reference_byte: byte,
        result_ordinal,
    }];
    let mut values = Vec::new();
    let mut active_expressions = HashSet::default();

    while let Some(frame) = frames.pop() {
        if !support.scope_step() {
            return None;
        }
        match frame {
            GoTypeInferenceFrame::Expression {
                node,
                reference_byte,
                result_ordinal,
            } => {
                if !active_expressions.insert((node.id(), reference_byte, result_ordinal)) {
                    return None;
                }
                if result_ordinal != 0
                    && !matches!(node.kind(), "call_expression" | "parenthesized_expression")
                {
                    return None;
                }
                match node.kind() {
                    "identifier" => {
                        let name = go_node_text(node, source);
                        if let Some(type_node) = go_receiver_binding_type_node(
                            support,
                            root,
                            source,
                            name,
                            reference_byte,
                        ) {
                            let mut inferred = go_inferred_type_from_node(
                                support, type_node, file, source, &package,
                            )?;
                            inferred.addressable = true;
                            values.push(inferred);
                            continue;
                        }
                        let binding = go_nearest_visible_binding(
                            support,
                            root,
                            source,
                            name,
                            reference_byte,
                        )?;
                        match binding {
                            GoLocalBinding::Type(type_node) => {
                                let mut inferred = go_inferred_type_from_node(
                                    support, type_node, file, source, &package,
                                )?;
                                inferred.addressable = true;
                                values.push(inferred);
                            }
                            GoLocalBinding::Value {
                                expression,
                                result_ordinal,
                            } => {
                                frames.push(GoTypeInferenceFrame::MakeAddressable);
                                frames.push(GoTypeInferenceFrame::Expression {
                                    node: expression,
                                    reference_byte: expression.start_byte(),
                                    result_ordinal,
                                });
                            }
                            GoLocalBinding::RangeElement(range_node) => {
                                let iterable = range_node
                                    .child_by_field_name("right")
                                    .or_else(|| go_last_named_child(support, range_node))?;
                                frames.push(GoTypeInferenceFrame::MakeAddressable);
                                frames.push(GoTypeInferenceFrame::Element);
                                frames.push(GoTypeInferenceFrame::Expression {
                                    node: iterable,
                                    reference_byte: iterable.start_byte(),
                                    result_ordinal: 0,
                                });
                            }
                            GoLocalBinding::Opaque => return None,
                        }
                    }
                    "selector_expression" => {
                        let qualifier = go_first_named_child(support, node)?;
                        let field = go_last_named_child(support, node)?;
                        frames.push(GoTypeInferenceFrame::Field(
                            go_node_text(field, source).to_string(),
                        ));
                        frames.push(GoTypeInferenceFrame::Expression {
                            node: qualifier,
                            reference_byte: reference_byte.min(node.start_byte()),
                            result_ordinal: 0,
                        });
                    }
                    "call_expression" => {
                        let function = node
                            .child_by_field_name("function")
                            .or_else(|| go_first_named_child(support, node))?;
                        match function.kind() {
                            "identifier" => {
                                let name = go_node_text(function, source);
                                if result_ordinal == 0
                                    && name == "new"
                                    && let Some(inferred) = go_builtin_new_inferred_type(
                                        support,
                                        file,
                                        source,
                                        root,
                                        node,
                                        reference_byte,
                                        &package,
                                    )
                                {
                                    values.push(inferred);
                                } else {
                                    values.push(go_callable_return_inferred_type(
                                        analyzer,
                                        support,
                                        go_unqualified_package_member_candidates(
                                            support, token, go, file, &package, name,
                                        ),
                                        result_ordinal,
                                    )?);
                                }
                            }
                            "selector_expression" => {
                                let qualifier = go_first_named_child(support, function)?;
                                let method = go_last_named_child(support, function)?;
                                let method_name = go_node_text(method, source);
                                let parameter_count = go_callable_modeled_argument_count(
                                    support, token, go, file, source, function,
                                )?;
                                let qualifier_name = go_node_text(qualifier, source);
                                let qualifier_is_unshadowed = if qualifier.kind() == "identifier" {
                                    let binding = go_nearest_visible_binding(
                                        support,
                                        root,
                                        source,
                                        qualifier_name,
                                        node.start_byte(),
                                    );
                                    if !support.scope_step() {
                                        return None;
                                    }
                                    binding.is_none()
                                } else {
                                    false
                                };
                                let imported = qualifier_is_unshadowed
                                    .then(|| {
                                        go_import_paths(support, token, go, file)
                                            .remove(qualifier_name)
                                    })
                                    .flatten()
                                    .and_then(|import_path| {
                                        let candidates = go_package_member_candidates(
                                            support,
                                            &import_path,
                                            method_name,
                                        );
                                        if candidates.is_empty() {
                                            (go_workspace_package_status(support, &import_path)
                                                == GoWorkspacePackageStatus::Absent)
                                                .then(|| {
                                                    go_modeled_callable_result_inferred_type(
                                                        support,
                                                        file,
                                                        &package,
                                                        &import_path,
                                                        method_name,
                                                        false,
                                                        parameter_count,
                                                        result_ordinal,
                                                    )
                                                })
                                                .flatten()
                                        } else {
                                            go_callable_return_inferred_type(
                                                analyzer,
                                                support,
                                                candidates,
                                                result_ordinal,
                                            )
                                        }
                                    });
                                if let Some(imported) = imported {
                                    values.push(imported);
                                } else {
                                    frames.push(GoTypeInferenceFrame::Method {
                                        name: method_name.to_string(),
                                        parameter_count,
                                        result_ordinal,
                                    });
                                    frames.push(GoTypeInferenceFrame::Expression {
                                        node: qualifier,
                                        reference_byte: reference_byte.min(node.start_byte()),
                                        result_ordinal: 0,
                                    });
                                }
                            }
                            _ => return None,
                        }
                    }
                    "composite_literal" => {
                        let type_node = node.child_by_field_name("type")?;
                        values.push(go_inferred_type_from_node(
                            support, type_node, file, source, &package,
                        )?);
                    }
                    "index_expression" => {
                        let operand = node
                            .child_by_field_name("operand")
                            .or_else(|| go_first_named_child(support, node))?;
                        frames.push(GoTypeInferenceFrame::Element);
                        frames.push(GoTypeInferenceFrame::Expression {
                            node: operand,
                            reference_byte,
                            result_ordinal: 0,
                        });
                    }
                    "parenthesized_expression" => {
                        frames.push(GoTypeInferenceFrame::Expression {
                            node: go_first_named_child(support, node)?,
                            reference_byte,
                            result_ordinal,
                        });
                    }
                    "unary_expression" => {
                        let operator = node.child_by_field_name("operator")?.kind();
                        let operand = node
                            .child_by_field_name("operand")
                            .or_else(|| go_first_named_child(support, node))?;
                        frames.push(match operator {
                            "&" => GoTypeInferenceFrame::AddressOf,
                            "*" => GoTypeInferenceFrame::Dereference,
                            _ => GoTypeInferenceFrame::MakeNonAddressable,
                        });
                        frames.push(GoTypeInferenceFrame::Expression {
                            node: operand,
                            reference_byte,
                            result_ordinal: 0,
                        });
                    }
                    _ => return None,
                }
            }
            GoTypeInferenceFrame::Field(field) => {
                let owner = values.pop()?;
                let owner_fqn = go_resolve_inferred_type_fqn(support, token, go, &owner)?;
                values.push(go_field_inferred_type_for_receiver(
                    analyzer, token, support, &owner, &owner_fqn, &field,
                )?);
            }
            GoTypeInferenceFrame::Method {
                name: method,
                parameter_count,
                result_ordinal,
            } => {
                let owner = values.pop()?;
                let owner_fqn = go_resolve_inferred_type_fqn(support, token, go, &owner)?;
                let inferred = match go_indexed_field_lookup_with_method_set(
                    analyzer,
                    token,
                    support,
                    &owner_fqn,
                    &method,
                    Some(&owner),
                ) {
                    GoDefinitionMemberLookup::Unique(candidate) => {
                        go_callable_return_inferred_type(
                            analyzer,
                            support,
                            vec![candidate],
                            result_ordinal,
                        )
                    }
                    GoDefinitionMemberLookup::Missing => {
                        let modeled = owner.modeled_nominal()?;
                        let _target = support.external_concrete_receiver_member(
                            &modeled.qualified_name,
                            &method,
                            owner.admits_pointer_receivers(),
                            parameter_count,
                        )?;
                        go_modeled_callable_result_inferred_type(
                            support,
                            &owner.file,
                            &owner.package,
                            &modeled.qualified_name,
                            &method,
                            true,
                            parameter_count,
                            result_ordinal,
                        )
                    }
                    GoDefinitionMemberLookup::Ambiguous(_) => None,
                }?;
                values.push(inferred);
            }
            GoTypeInferenceFrame::Element => {
                let mut iterable = values.pop()?;
                let identity = iterable.indexed_identity()?;
                let addressable =
                    identity.is_slice() || (identity.is_array() && iterable.addressable);
                let GoInferredTypeIdentity::Indexed(identity) = iterable.identity else {
                    unreachable!("indexed identity was checked above")
                };
                iterable.identity = GoInferredTypeIdentity::Indexed(
                    identity.into_container_element_with(|| support.scope_step())?,
                );
                iterable.addressable = addressable;
                values.push(iterable);
            }
            GoTypeInferenceFrame::MakeAddressable => {
                let mut inferred = values.pop()?;
                inferred.addressable = true;
                values.push(inferred);
            }
            GoTypeInferenceFrame::AddressOf => {
                let mut inferred = values.pop()?;
                let GoInferredTypeIdentity::Indexed(identity) = inferred.identity else {
                    return None;
                };
                inferred.identity = GoInferredTypeIdentity::Indexed(identity.wrap_pointer()?);
                inferred.addressable = false;
                values.push(inferred);
            }
            GoTypeInferenceFrame::Dereference => {
                let mut inferred = values.pop()?;
                let GoInferredTypeIdentity::Indexed(identity) = &inferred.identity else {
                    return None;
                };
                if !identity.is_pointer() {
                    return None;
                }
                // A dereferenced pointer expression is addressable. Keeping
                // the pointer wrapper is sufficient for nominal-owner and
                // method-set selection; both resolve through the same named
                // type and admit the pointer receiver's method set.
                inferred.addressable = true;
                values.push(inferred);
            }
            GoTypeInferenceFrame::MakeNonAddressable => {
                let mut inferred = values.pop()?;
                inferred.addressable = false;
                values.push(inferred);
            }
        }
    }

    (values.len() == 1).then(|| values.pop()).flatten()
}

fn go_inferred_type_from_node(
    support: &dyn GoDefinitionProvider,
    node: Node<'_>,
    file: &ProjectFile,
    source: &str,
    package: &str,
) -> Option<GoInferredType> {
    Some(GoInferredType {
        identity: GoInferredTypeIdentity::Indexed(
            crate::analyzer::go::go_structured_type_identity_bounded(node, source, || {
                support.scope_step()
            })?,
        ),
        file: file.clone(),
        package: package.to_string(),
        addressable: false,
    })
}

#[allow(clippy::too_many_arguments)]
fn go_builtin_new_inferred_type(
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    call: Node<'_>,
    reference_byte: usize,
    package: &str,
) -> Option<GoInferredType> {
    if go_nearest_visible_binding(support, root, source, "new", reference_byte).is_some()
        || !go_package_member_candidates(support, package, "new").is_empty()
    {
        return None;
    }
    if !support.scope_step() {
        return None;
    }
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let mut argument = None;
    for child in arguments.named_children(&mut cursor) {
        if !support.scope_step() || argument.replace(child).is_some() {
            return None;
        }
    }
    let type_node = argument?;
    let mut inferred = go_inferred_type_from_node(support, type_node, file, source, package)?;
    let GoInferredTypeIdentity::Indexed(identity) = inferred.identity else {
        unreachable!("syntax-derived type identity is indexed")
    };
    inferred.identity = GoInferredTypeIdentity::Indexed(identity.wrap_pointer()?);
    inferred.addressable = false;
    Some(inferred)
}

fn go_callable_return_inferred_type(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    candidates: Vec<CodeUnit>,
    result_ordinal: usize,
) -> Option<GoInferredType> {
    if result_ordinal != 0 {
        return None;
    }
    let mut inferred = Vec::new();
    for candidate in candidates {
        if !support.scope_step() {
            return None;
        }
        for metadata in support.signature_metadata(analyzer, &candidate) {
            if !support.scope_step() {
                return None;
            }
            let Some(identity) = metadata.into_return_type_identity() else {
                continue;
            };
            let candidate_type = GoInferredType {
                identity: GoInferredTypeIdentity::Indexed(identity),
                file: candidate.source().clone(),
                package: candidate.package_name().to_string(),
                addressable: false,
            };
            let mut duplicate = false;
            for existing in &inferred {
                if go_inferred_types_equal(support, existing, &candidate_type)? {
                    duplicate = true;
                    break;
                }
            }
            if !duplicate {
                inferred.push(candidate_type);
            }
        }
    }
    (inferred.len() == 1).then(|| inferred.pop()).flatten()
}

#[allow(clippy::too_many_arguments)]
fn go_modeled_callable_result_inferred_type(
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    package: &str,
    owner_fqn: &str,
    member: &str,
    has_receiver: bool,
    parameter_count: usize,
    result_ordinal: usize,
) -> Option<GoInferredType> {
    Some(GoInferredType {
        identity: GoInferredTypeIdentity::Modeled(support.external_callable_result_nominal_type(
            owner_fqn,
            member,
            has_receiver,
            parameter_count,
            result_ordinal,
        )?),
        file: file.clone(),
        package: package.to_string(),
        addressable: false,
    })
}

fn go_inferred_types_equal(
    support: &dyn GoDefinitionProvider,
    left: &GoInferredType,
    right: &GoInferredType,
) -> Option<bool> {
    match (&left.identity, &right.identity) {
        (
            GoInferredTypeIdentity::Indexed(left_identity),
            GoInferredTypeIdentity::Indexed(right_identity),
        ) => {
            if left.file != right.file || left.package != right.package {
                return Some(false);
            }
            left_identity.structurally_eq_with(right_identity, || support.scope_step())
        }
        (
            GoInferredTypeIdentity::Modeled(left_nominal),
            GoInferredTypeIdentity::Modeled(right_nominal),
        ) => Some(left_nominal == right_nominal),
        _ => Some(false),
    }
}

fn go_field_inferred_type_for_receiver(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn GoDefinitionProvider,
    owner: &GoInferredType,
    owner_fqn: &str,
    field: &str,
) -> Option<GoInferredType> {
    let candidate = go_indexed_member_candidate_for_receiver(
        analyzer, token, support, owner_fqn, field, owner,
    )?;
    let identity = go_field_unit_type_identity(analyzer, support, &candidate)?;
    Some(GoInferredType {
        identity: GoInferredTypeIdentity::Indexed(identity),
        file: candidate.source().clone(),
        package: candidate.package_name().to_string(),
        addressable: !candidate.is_function() && owner.admits_pointer_receivers(),
    })
}

fn go_resolve_inferred_type_fqn(
    support: &dyn GoDefinitionProvider,
    token: QueryToken<'_>,
    go: &GoAnalyzer,
    inferred: &GoInferredType,
) -> Option<String> {
    match &inferred.identity {
        GoInferredTypeIdentity::Indexed(identity) => go_resolve_structured_type_fqn(
            support,
            token,
            go,
            &inferred.file,
            &inferred.package,
            identity,
        ),
        GoInferredTypeIdentity::Modeled(nominal) => Some(nominal.qualified_name.clone()),
    }
}

/// The imported nominal owner a reviewed concrete-receiver fact may prove.
///
/// This is deliberately narrower than ordinary Go type resolution: only a
/// qualified named type or a pointer to one is admitted. Local aliases,
/// generic instantiations, wrappers, containers, and reconstructed source text
/// never enter this route. The import binder supplies the package identity;
/// the declaration overlay still has to prove the concrete method before a
/// boundary can carry the returned name.
fn go_imported_nominal_receiver_candidate_fqn(
    support: &dyn GoDefinitionProvider,
    token: QueryToken<'_>,
    go: &GoAnalyzer,
    file: &ProjectFile,
    identity: &StructuredTypeIdentity,
) -> Option<String> {
    let name = match identity.view(identity.root_id())? {
        StructuredTypeNodeView::Named(name) => name,
        StructuredTypeNodeView::Pointer(inner) => match identity.view(inner)? {
            StructuredTypeNodeView::Named(name) => name,
            _ => return None,
        },
        _ => return None,
    };
    let [qualifier, name] = name.path() else {
        return None;
    };
    let import_path = go_import_paths(support, token, go, file).remove(qualifier)?;
    (go_workspace_package_status(support, &import_path) == GoWorkspacePackageStatus::Absent)
        .then(|| format!("{import_path}.{name}"))
}

#[allow(clippy::too_many_arguments)]
fn go_value_type_fqn(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    value_node: Node<'_>,
    byte: usize,
    result_ordinal: usize,
) -> Option<String> {
    go_expression_type_fqn(
        analyzer,
        token,
        support,
        file,
        source,
        root,
        value_node,
        byte,
        result_ordinal,
    )
}

#[allow(clippy::too_many_arguments)]
fn go_expression_type_fqn(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    byte: usize,
    result_ordinal: usize,
) -> Option<String> {
    let go = resolve_analyzer::<GoAnalyzer>(analyzer)?;
    let inferred = go_expression_inferred_type(
        analyzer,
        token,
        support,
        file,
        source,
        root,
        expression,
        byte,
        result_ordinal,
    )?;
    go_resolve_inferred_type_fqn(support, token, go, &inferred)
}

fn go_type_lookup_expression<'tree>(
    support: &dyn GoDefinitionProvider,
    mut node: Node<'tree>,
) -> Option<Node<'tree>> {
    loop {
        if !support.scope_step() {
            return None;
        }
        let Some(parent) = node.parent() else {
            return Some(node);
        };
        let node_id = node.id();
        let parent_is_semantic_expression = match parent.kind() {
            "selector_expression" => parent
                .child_by_field_name("field")
                .or_else(|| go_last_named_child(support, parent))
                .is_some_and(|field| field.id() == node_id),
            "call_expression" => parent
                .child_by_field_name("function")
                .is_some_and(|function| function.id() == node_id),
            "composite_literal" => parent
                .child_by_field_name("type")
                .is_some_and(|type_node| type_node.id() == node_id),
            "parenthesized_expression" | "unary_expression" => true,
            _ => false,
        };
        if !parent_is_semantic_expression {
            return Some(node);
        }
        node = parent;
    }
}

fn go_interface_method_owner_type_fqn(
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    mut node: Node<'_>,
) -> Option<(String, String)> {
    let selected = node;
    loop {
        if !support.scope_step() {
            return None;
        }
        if node.kind() == "method_elem" {
            let method_name = node
                .child_by_field_name("name")
                .or_else(|| go_first_named_child(support, node))?;
            if selected.start_byte() < method_name.start_byte()
                || selected.end_byte() > method_name.end_byte()
            {
                return None;
            }
            let interface = node.parent()?;
            if !support.scope_step() || interface.kind() != "interface_type" {
                return None;
            }
            let type_spec = interface.parent()?;
            if !support.scope_step() || type_spec.kind() != "type_spec" {
                return None;
            }
            let name = type_spec.child_by_field_name("name")?;
            let owner_fqn = go_resolve_type_name_in_package(
                support,
                &go_package_name(support, file, source, Some(root))?,
                go_node_text(name, source),
            )?;
            return Some((owner_fqn, go_node_text(method_name, source).to_string()));
        }
        node = node.parent()?;
    }
}

fn go_range_binding_type_fqn(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    range_node: Node<'_>,
) -> Option<String> {
    if !support.scope_step() {
        return None;
    }
    let right = range_node
        .child_by_field_name("right")
        .or_else(|| go_last_named_child(support, range_node))?;
    // Go's range variables enter scope only after the range expression has
    // been evaluated. Resolve the iterable at its own source position so a
    // same-named range variable cannot resolve the RHS back to itself and
    // create an unbounded type-inference cycle.
    let mut iterable_type = go_expression_inferred_type(
        analyzer,
        token,
        support,
        file,
        source,
        root,
        right,
        right.start_byte(),
        0,
    )?;
    let GoInferredTypeIdentity::Indexed(identity) = iterable_type.identity else {
        return None;
    };
    iterable_type.identity = GoInferredTypeIdentity::Indexed(
        identity.into_container_element_with(|| support.scope_step())?,
    );
    go_resolve_inferred_type_fqn(
        support,
        token,
        resolve_analyzer::<GoAnalyzer>(analyzer)?,
        &iterable_type,
    )
}

fn go_nearest_visible_binding<'tree>(
    support: &dyn GoDefinitionProvider,
    root: Node<'tree>,
    source: &str,
    name: &str,
    byte: usize,
) -> Option<GoLocalBinding<'tree>> {
    let mut scope = go_smallest_named_node_covering(support, root, byte, byte)?;
    loop {
        if !support.scope_step() {
            return None;
        }
        if let Some(binding) =
            go_nearest_binding_in_scope(support, scope, source, name.trim(), byte)
        {
            return Some(binding);
        }
        scope = scope.parent()?;
    }
}

fn go_parameter_type_for_name<'tree>(
    support: &dyn GoDefinitionProvider,
    parameter_list: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<Node<'tree>> {
    if !support.scope_step() {
        return None;
    }
    if parameter_list.kind() == "parameter_declaration" {
        return go_parameter_declaration_type_for_name(support, parameter_list, source, name);
    }
    let mut cursor = parameter_list.walk();
    for parameter in parameter_list.named_children(&mut cursor) {
        if !support.scope_step() {
            return None;
        }
        if parameter.kind() != "parameter_declaration" {
            continue;
        }
        let type_node = go_parameter_declaration_type_for_name(support, parameter, source, name);
        if type_node.is_some() {
            return type_node;
        }
    }
    None
}

fn go_parameter_declaration_type_for_name<'tree>(
    support: &dyn GoDefinitionProvider,
    parameter: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<Node<'tree>> {
    let mut names = Vec::new();
    let mut type_node = None;
    let mut inner = parameter.walk();
    for child in parameter.named_children(&mut inner) {
        if !support.scope_step() {
            return None;
        }
        match child.kind() {
            "identifier" => names.push(go_node_text(child, source)),
            _ => type_node = Some(child),
        }
    }
    names.contains(&name).then_some(type_node).flatten()
}

fn go_indexed_field_type_fqn(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn GoDefinitionProvider,
    owner_fqn: &str,
    field: &str,
) -> Option<String> {
    let go = resolve_analyzer::<GoAnalyzer>(analyzer)?;
    if let Some((field_unit, identity)) =
        go_indexed_field_type_identity(analyzer, token, support, owner_fqn, field)
    {
        return go_resolve_structured_type_fqn(
            support,
            token,
            go,
            field_unit.source(),
            field_unit.package_name(),
            &identity,
        );
    }
    if support.session().is_some() {
        return None;
    }
    let (field_file, type_text) =
        go_indexed_field_type(analyzer, token, support, owner_fqn, field)?;
    go_resolve_go_field_type_fqn(analyzer, token, support, owner_fqn, &field_file, &type_text)
}

fn go_indexed_field_type_identity(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn GoDefinitionProvider,
    owner_fqn: &str,
    field: &str,
) -> Option<(CodeUnit, StructuredTypeIdentity)> {
    let GoDefinitionMemberLookup::Unique(field_unit) =
        go_indexed_field_lookup(analyzer, token, support, owner_fqn, field)
    else {
        return None;
    };
    go_field_unit_type_identity(analyzer, support, &field_unit)
        .map(|identity| (field_unit, identity))
}

fn go_indexed_field_type(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn GoDefinitionProvider,
    owner_fqn: &str,
    field: &str,
) -> Option<(ProjectFile, String)> {
    if support.session().is_some() {
        return None;
    }
    match go_indexed_field_lookup(analyzer, token, support, owner_fqn, field) {
        GoDefinitionMemberLookup::Unique(field_unit) => {
            go_field_unit_type_text(analyzer, support, &field_unit, field)
                .map(|type_text| (field_unit.source().clone(), type_text))
        }
        GoDefinitionMemberLookup::Missing | GoDefinitionMemberLookup::Ambiguous(_) => None,
    }
}

enum GoDefinitionMemberLookup {
    Missing,
    Unique(CodeUnit),
    Ambiguous(Vec<CodeUnit>),
}

fn go_indexed_field_lookup(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn GoDefinitionProvider,
    owner_fqn: &str,
    field: &str,
) -> GoDefinitionMemberLookup {
    go_indexed_field_lookup_with_method_set(analyzer, token, support, owner_fqn, field, None)
}

fn go_indexed_member_candidate_for_receiver(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn GoDefinitionProvider,
    owner_fqn: &str,
    member: &str,
    receiver: &GoInferredType,
) -> Option<CodeUnit> {
    let GoDefinitionMemberLookup::Unique(candidate) = go_indexed_field_lookup_with_method_set(
        analyzer,
        token,
        support,
        owner_fqn,
        member,
        Some(receiver),
    ) else {
        return None;
    };
    Some(candidate)
}

fn go_indexed_field_lookup_with_method_set(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn GoDefinitionProvider,
    owner_fqn: &str,
    field: &str,
    receiver: Option<&GoInferredType>,
) -> GoDefinitionMemberLookup {
    struct PromotionPath {
        owner: String,
        pointer_receivers: Option<bool>,
        parent: Option<usize>,
    }

    let root_pointer_receivers = receiver.map(GoInferredType::admits_pointer_receivers);
    let mut paths = vec![PromotionPath {
        owner: owner_fqn.to_string(),
        pointer_receivers: root_pointer_receivers,
        parent: None,
    }];
    // Built only while a trace records (#1477): it mirrors the promotion paths
    // this walk expands and the path each candidate is found on, and decides
    // nothing.
    let mut member_trace = trace::recording().then(GoPromotionTrace::default);
    if let Some(state) = member_trace.as_mut() {
        state.push_path(owner_fqn, None);
    }
    let mut frontier = vec![0];
    while !frontier.is_empty() {
        let mut candidates = Vec::new();
        for &path_index in &frontier {
            if !support.scope_step() {
                return GoDefinitionMemberLookup::Missing;
            }
            let path = &paths[path_index];
            for candidate in support.members_for_owner_name(&path.owner, field) {
                let verdict = match path.pointer_receivers {
                    Some(pointer_receivers) => {
                        go_member_in_method_set(analyzer, support, &candidate, pointer_receivers)
                    }
                    None => GoMethodSetVerdict::UNCHECKED,
                };
                if let Some(state) = member_trace.as_mut() {
                    state.record(&candidate, path_index, verdict.interface_method());
                }
                if verdict.admits() {
                    candidates.push(candidate);
                } else if let (GoMethodSetVerdict::OutsideMethodSet, Some(state)) =
                    (verdict, member_trace.as_ref())
                {
                    // The method-set filter computed this candidate and threw
                    // it away; the row states that, with the same owner and
                    // route an admitted candidate gets. An `Undecided` verdict
                    // records nothing: the filter never reached a reason.
                    state.record_rejection(analyzer, &candidate);
                }
            }
        }
        sort_units(&mut candidates);
        match candidates.len() {
            0 => {}
            1 => {
                let candidate = candidates
                    .pop()
                    .expect("single Go member candidate was checked");
                if let Some(state) = member_trace.as_ref() {
                    state.stage_selection(analyzer, std::slice::from_ref(&candidate));
                }
                return GoDefinitionMemberLookup::Unique(candidate);
            }
            _ => {
                if let Some(state) = member_trace.as_ref() {
                    state.stage_selection(analyzer, &candidates);
                }
                return GoDefinitionMemberLookup::Ambiguous(candidates);
            }
        }
        let mut next = Vec::new();
        for path_index in frontier {
            if !support.summary_step() {
                return GoDefinitionMemberLookup::Missing;
            }
            let owner = paths[path_index].owner.clone();
            let pointer_receivers = paths[path_index].pointer_receivers;
            let embedded: Vec<(String, Option<bool>)> = if let Some(pointer_receivers) =
                pointer_receivers
            {
                go_embedded_method_set_types(analyzer, token, support, &owner, pointer_receivers)
                    .into_iter()
                    .map(|(owner, pointer_receivers)| (owner, Some(pointer_receivers)))
                    .collect()
            } else {
                go_embedded_field_types(analyzer, token, support, &owner)
                    .into_iter()
                    .map(|owner| (owner, None))
                    .collect()
            };
            for (embedded_owner, embedded_pointer_receivers) in embedded {
                let mut ancestor = Some(path_index);
                let mut cycle = false;
                while let Some(ancestor_index) = ancestor {
                    if !support.scope_step() {
                        return GoDefinitionMemberLookup::Missing;
                    }
                    let ancestor_path = &paths[ancestor_index];
                    if ancestor_path.owner == embedded_owner {
                        cycle = true;
                        break;
                    }
                    ancestor = ancestor_path.parent;
                }
                if cycle {
                    continue;
                }
                let embedded_index = paths.len();
                if let Some(state) = member_trace.as_mut() {
                    state.push_path(&embedded_owner, Some(path_index));
                }
                paths.push(PromotionPath {
                    owner: embedded_owner,
                    pointer_receivers: embedded_pointer_receivers,
                    parent: Some(path_index),
                });
                next.push(embedded_index);
            }
        }
        frontier = next;
    }
    GoDefinitionMemberLookup::Missing
}

/// What the Go method-set filter decided about one candidate.
///
/// A function candidate that declares no receiver is exactly an interface
/// method element. The filter computes that to keep open dispatch visible, so
/// `interface_method` is a fact it already holds rather than a second structure
/// asked what kind of type the owner is.
#[derive(Clone, Copy)]
enum GoMethodSetVerdict {
    /// The candidate is in the receiver's method set.
    InMethodSet { interface_method: bool },
    /// The candidate declares a pointer receiver, and the receiver this lookup
    /// has is neither a pointer nor addressable, so the method is not in its
    /// method set.
    OutsideMethodSet,
    /// The filter ran out of scope budget before it could decide. The candidate
    /// is not admitted, and nothing may be claimed about why.
    Undecided,
}

impl GoMethodSetVerdict {
    /// The verdict for a lookup with no inferred receiver. The production walk
    /// applies no method-set filter there, so it admits the candidate and
    /// observes nothing about the candidate's receiver declaration.
    const UNCHECKED: Self = Self::InMethodSet {
        interface_method: false,
    };

    const fn admits(self) -> bool {
        matches!(self, Self::InMethodSet { .. })
    }

    const fn interface_method(self) -> bool {
        matches!(
            self,
            Self::InMethodSet {
                interface_method: true
            }
        )
    }
}

fn go_member_in_method_set(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    candidate: &CodeUnit,
    pointer_receivers: bool,
) -> GoMethodSetVerdict {
    if !candidate.is_function() {
        return GoMethodSetVerdict::UNCHECKED;
    }
    let mut saw_receiver = false;
    for metadata in support.signature_metadata(analyzer, candidate) {
        if !support.scope_step() {
            return GoMethodSetVerdict::Undecided;
        }
        let Some(receiver) = metadata.extension_receiver_type_identity() else {
            continue;
        };
        saw_receiver = true;
        if !receiver.is_pointer() || pointer_receivers {
            return GoMethodSetVerdict::InMethodSet {
                interface_method: false,
            };
        }
    }
    // Interface methods have no concrete receiver declaration. Their open
    // dispatch remains visible rather than being mistaken for a pointer-only
    // concrete method.
    if saw_receiver {
        GoMethodSetVerdict::OutsideMethodSet
    } else {
        GoMethodSetVerdict::InMethodSet {
            interface_method: true,
        }
    }
}

/// The member attribution the Go promotion walk records while it runs (#1477).
///
/// [`go_indexed_field_lookup_with_method_set`] is a breadth-first walk over
/// promotion paths, and every path already names the owner it searches and the
/// path whose embedded field introduced it. This mirrors those two facts in the
/// walk's own index order, plus the path each candidate was found on, so owner,
/// depth and route are read off the walk instead of being rediscovered from its
/// flattened result. It decides nothing.
///
/// Applicability stays `Unknown`: the walk selects by owner, name and method
/// set and never inspects the call shape, so claiming anything else would
/// invent a check the resolver did not perform (#1478).
#[derive(Default)]
struct GoPromotionTrace {
    /// One entry per promotion path, in the walk's index order: the owner
    /// fully-qualified name the path searches, and the path it was embedded in.
    paths: Vec<(String, Option<usize>)>,
    /// Candidate declaration -> the promotion path it was found on, and whether
    /// the method-set filter proved it declares no receiver.
    found: Vec<(CodeUnit, usize, bool)>,
}

impl GoPromotionTrace {
    fn push_path(&mut self, owner_fqn: &str, parent: Option<usize>) {
        self.paths.push((owner_fqn.to_owned(), parent));
    }

    /// First discovery wins, exactly as the breadth-first walk does: a name
    /// reached at two depths is the shallower one's.
    fn record(&mut self, candidate: &CodeUnit, path_index: usize, interface_method: bool) {
        if self.found.iter().any(|(unit, ..)| unit == candidate) {
            return;
        }
        self.found
            .push((candidate.clone(), path_index, interface_method));
    }

    /// The promotion paths from the root owner to `path_index`, root first.
    fn chain(&self, path_index: usize) -> Vec<usize> {
        let mut chain = vec![path_index];
        while let Some(parent) = self.paths[*chain.last().expect("a chain is never empty")].1 {
            chain.push(parent);
        }
        chain.reverse();
        chain
    }

    /// The declaration `owner_fqn` names, read straight from the Go store.
    ///
    /// The read deliberately bypasses [`GoDefinitionProvider`]: a provider
    /// lookup is charged against the resolution session's scope budget, so a
    /// recording run would spend budget the untraced run does not and a request
    /// near its limit could answer differently while recording. An owner name
    /// that does not name exactly one declaration leaves the candidate
    /// unattributed rather than attributed to a guess.
    fn owner_unit(analyzer: &dyn IAnalyzer, owner_fqn: &str) -> Option<CodeUnit> {
        let go = resolve_analyzer::<GoAnalyzer>(analyzer)?;
        let mut units: Vec<CodeUnit> = go.definitions(owner_fqn).collect();
        sort_units(&mut units);
        units.dedup();
        (units.len() == 1).then(|| units.pop()).flatten()
    }

    /// The attribution for `candidate`, or `None` when an owner on its route
    /// does not name exactly one declaration.
    fn enrichment(
        &self,
        analyzer: &dyn IAnalyzer,
        candidate: &CodeUnit,
    ) -> Option<trace::MemberEnrichment> {
        use crate::analyzer::structural::{HierarchyRelation, MemberDispatchTier};
        use brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict;

        let (_, path_index, interface_method) =
            self.found.iter().find(|(unit, ..)| unit == candidate)?;
        let owners = self
            .chain(*path_index)
            .into_iter()
            .map(|index| Self::owner_unit(analyzer, &self.paths[index].0))
            .collect::<Option<Vec<CodeUnit>>>()?;
        let depth = owners.len() - 1;
        // Every hop this walk takes is a Go embedded field or embedded
        // interface, which is the one relation the walk expands.
        let route = owners
            .windows(2)
            .enumerate()
            .map(|(hop, pair)| trace::HierarchyHopRecord {
                hop,
                from: pair[0].clone(),
                to: pair[1].clone(),
                relation: HierarchyRelation::Embedded,
            })
            .collect();
        let dispatch_tier = if *interface_method {
            MemberDispatchTier::TraitOrInterface
        } else if depth == 0 {
            MemberDispatchTier::InherentOrDirect
        } else {
            MemberDispatchTier::InheritedOrPromoted
        };
        Some(trace::MemberEnrichment {
            owner: owners[depth].clone(),
            hierarchy_depth: depth,
            dispatch_tier,
            applicability: ApplicabilityVerdict::Unknown,
            route,
        })
    }

    /// Stage attribution for the candidates the walk is about to return, for
    /// the outcome constructor the caller reaches next.
    fn stage_selection(&self, analyzer: &dyn IAnalyzer, winners: &[CodeUnit]) {
        use crate::analyzer::structural::PrecedenceTier;

        let by_fq_name: Vec<(String, trace::MemberEnrichment)> = winners
            .iter()
            .filter_map(|unit| {
                self.enrichment(analyzer, unit)
                    .map(|enrichment| (unit.fq_name(), enrichment))
            })
            .collect();
        let winner_tier = by_fq_name
            .iter()
            .map(|(_, enrichment)| enrichment.hierarchy_depth)
            .min()
            .map(|depth| {
                if depth == 0 {
                    PrecedenceTier::OwnMember
                } else {
                    PrecedenceTier::InheritedMember
                }
            });
        if let Some(tier) = winner_tier {
            trace::stage_tier(tier, winners.iter().map(|unit| unit.fq_name()).collect());
        }
        trace::stage_member_context(by_fq_name);
    }

    /// Record a candidate the method-set filter computed and discarded.
    ///
    /// Go's method set is a declaration space: a method declared on `*T` is not
    /// in `T`'s method set at all, which is what
    /// [`RejectionReason::WrongDeclarationSpace`] names. It is not a visibility
    /// rule and not a call-shape rule, so neither of those reasons applies.
    fn record_rejection(&self, analyzer: &dyn IAnalyzer, candidate: &CodeUnit) {
        use crate::analyzer::structural::{PrecedenceTier, RejectionReason};

        let enrichment = self.enrichment(analyzer, candidate);
        let tier = enrichment.as_ref().map(|enrichment| {
            if enrichment.hierarchy_depth == 0 {
                PrecedenceTier::OwnMember
            } else {
                PrecedenceTier::InheritedMember
            }
        });
        let mut row = trace::TraceCandidate::rejected(
            trace::TraceCandidateRef::Unit(candidate.clone()),
            tier,
            RejectionReason::WrongDeclarationSpace,
        );
        if let Some(enrichment) = enrichment {
            row = row.with_member(enrichment);
        }
        trace::record(row);
    }
}

fn go_embedded_method_set_types(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn GoDefinitionProvider,
    owner_fqn: &str,
    inherited_pointer_receivers: bool,
) -> Vec<(String, bool)> {
    let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
        return Vec::new();
    };
    let mut embedded = Vec::new();
    for owner in support.fqn(owner_fqn) {
        if !support.scope_step() {
            return Vec::new();
        }
        let mut saw_structured_identity = false;
        for metadata in support.signature_metadata(analyzer, &owner) {
            if !support.scope_step() {
                return Vec::new();
            }
            let Some(identity) = metadata.into_return_type_identity() else {
                continue;
            };
            saw_structured_identity = true;
            let pointer_receivers = inherited_pointer_receivers || identity.is_pointer();
            if let Some(fqn) = go_resolve_structured_type_fqn(
                support,
                token,
                go,
                owner.source(),
                owner.package_name(),
                &identity,
            ) {
                embedded.push((fqn, pointer_receivers));
            }
        }
        if saw_structured_identity || support.session().is_some() {
            continue;
        }
        embedded.extend(
            go_embedded_field_types(analyzer, token, support, owner_fqn)
                .into_iter()
                .map(|fqn| (fqn, inherited_pointer_receivers)),
        );
    }
    embedded.sort();
    embedded.dedup();
    embedded
}

fn go_embedded_field_types(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn GoDefinitionProvider,
    owner_fqn: &str,
) -> Vec<String> {
    let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
        return Vec::new();
    };
    let mut embedded = Vec::new();
    for owner in support.fqn(owner_fqn) {
        if !support.scope_step() {
            return Vec::new();
        }
        if support.session().is_some() {
            for metadata in support.signature_metadata(analyzer, &owner) {
                if !support.scope_step() {
                    return Vec::new();
                }
                let Some(identity) = metadata.into_return_type_identity() else {
                    continue;
                };
                if let Some(fqn) = go_resolve_structured_type_fqn(
                    support,
                    token,
                    go,
                    owner.source(),
                    owner.package_name(),
                    &identity,
                ) {
                    embedded.push(fqn);
                }
            }
            continue;
        }
        for type_text in support.raw_supertypes(go, &owner) {
            if !support.scope_step() {
                return Vec::new();
            }
            if let Some(fqn) = go_resolve_go_field_type_fqn(
                analyzer,
                token,
                support,
                owner_fqn,
                owner.source(),
                &type_text,
            ) {
                embedded.push(fqn);
            }
        }
    }
    embedded.sort();
    embedded.dedup();
    embedded
}

fn go_field_unit_type_identity(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    field_unit: &CodeUnit,
) -> Option<StructuredTypeIdentity> {
    let mut identities: Vec<StructuredTypeIdentity> = Vec::new();
    for metadata in support.signature_metadata(analyzer, field_unit) {
        let Some(identity) = metadata.into_return_type_identity() else {
            continue;
        };
        let mut duplicate = false;
        for existing in &identities {
            if existing.structurally_eq_with(&identity, || support.scope_step())? {
                duplicate = true;
                break;
            }
        }
        if !duplicate {
            identities.push(identity);
        }
    }
    (identities.len() == 1).then(|| identities.pop()).flatten()
}

fn go_field_unit_type_text(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    field_unit: &CodeUnit,
    field: &str,
) -> Option<String> {
    let mut type_texts = support
        .signature_metadata(analyzer, field_unit)
        .into_iter()
        .filter_map(|metadata| metadata.return_type_text().map(str::to_string))
        .collect::<Vec<_>>();
    type_texts.sort();
    type_texts.dedup();
    if type_texts.len() == 1 {
        return type_texts.pop();
    }
    if support.session().is_some() {
        return None;
    }
    let signature = field_unit
        .signature()
        .map(str::to_string)
        .or_else(|| analyzer.signatures(field_unit).first().cloned())?;
    let trimmed = signature.trim();
    if let Some(type_text) = trimmed
        .strip_prefix(field)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(type_text.to_string());
    }
    let simple = go_simple_type_name(trimmed)?;
    (simple == field).then(|| trimmed.to_string())
}

fn go_resolve_go_field_type_fqn(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn GoDefinitionProvider,
    owner_fqn: &str,
    field_file: &ProjectFile,
    type_text: &str,
) -> Option<String> {
    if support.session().is_some() {
        return None;
    }
    let (qualifier, name) = go_type_name_parts(type_text)?;
    if qualifier.is_some() {
        return go_resolve_qualified_type_from_file(
            analyzer, token, support, field_file, type_text,
        );
    }
    // fqname-M4: this is a plain-string owner/name split (the `FqName` "pop the
    // last segment" equivalent), but Go's package prefix is `/`-joined and can
    // itself contain literal `.` (e.g. `github.com`), which is exactly why the
    // shared M2 shrinking-scope resolver deliberately never reaches Go (see the
    // ExecPlan's M2 Surprises entry). The generic `parse_symbol_path` splitter
    // would over-split such a prefix, so it cannot replace this rightmost-`.`
    // cut. A true structured fix needs the caller to carry the already-resolved
    // owner `CodeUnit` (its `fq()`/`package_name()` directly) instead of a
    // pre-flattened `owner_fqn` string threaded through several call sites —
    // that is a signature change across `go_indexed_field_type_fqn` and
    // `go_embedded_type_fqns`, not a mechanical one-line rewrite. Revisit
    // alongside that call chain.
    let package = owner_fqn.rsplit_once('.').map(|(package, _)| package)?;
    go_resolve_type_name_in_package(support, package, name)
}

fn go_resolve_structured_type_fqn(
    support: &dyn GoDefinitionProvider,
    token: QueryToken<'_>,
    go: &GoAnalyzer,
    file: &ProjectFile,
    default_package: &str,
    identity: &StructuredTypeIdentity,
) -> Option<String> {
    let name = identity.nominal_name_with(|| support.scope_step())?;
    match name.path() {
        [name] => {
            let mut candidates = Vec::new();
            if let Some(fqn) = go_resolve_exact_type_name_in_package(support, default_package, name)
            {
                candidates.push(fqn);
            }
            for import_path in go_dot_import_paths(go, support, token, file) {
                if !support.scope_step() {
                    return None;
                }
                if let Some(fqn) =
                    go_resolve_exact_type_name_in_package(support, &import_path, name)
                {
                    candidates.push(fqn);
                }
            }
            candidates.sort();
            candidates.dedup();
            (candidates.len() == 1).then(|| candidates.pop()).flatten()
        }
        [qualifier, name] => {
            let import_path = go_import_paths(support, token, go, file).remove(qualifier)?;
            let fqn = format!("{import_path}.{name}");
            support.fqn_exists(&fqn).then_some(fqn)
        }
        _ => None,
    }
}

fn go_resolve_qualified_type_from_file(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    type_text: &str,
) -> Option<String> {
    if support.session().is_some() {
        return None;
    }
    let (Some(qualifier), name) = go_type_name_parts(type_text)? else {
        return None;
    };
    let go = resolve_analyzer::<GoAnalyzer>(analyzer)?;
    let import_path = go_import_paths(support, token, go, file).remove(qualifier)?;
    let fqn = format!("{import_path}.{name}");
    support.fqn_exists(&fqn).then_some(fqn)
}

fn go_resolve_type_fqn(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    type_node: Node<'_>,
) -> Option<String> {
    let go = resolve_analyzer::<GoAnalyzer>(analyzer)?;
    let root = go_syntax_root(support, type_node)?;
    let package = go_package_name(support, file, source, Some(root))?;
    let identity =
        crate::analyzer::go::go_structured_type_identity_bounded(type_node, source, || {
            support.scope_step()
        })?;
    go_resolve_structured_type_fqn(support, token, go, file, &package, &identity)
}

fn go_syntax_root<'tree>(
    support: &dyn GoDefinitionProvider,
    mut node: Node<'tree>,
) -> Option<Node<'tree>> {
    loop {
        if !support.scope_step() {
            return None;
        }
        let Some(parent) = node.parent() else {
            return Some(node);
        };
        node = parent;
    }
}

fn go_resolve_type_name_in_package(
    support: &dyn GoDefinitionProvider,
    package: &str,
    type_text: &str,
) -> Option<String> {
    let name = go_simple_type_name(type_text)?;
    go_resolve_exact_type_name_in_package(support, package, name)
}

fn go_resolve_exact_type_name_in_package(
    support: &dyn GoDefinitionProvider,
    package: &str,
    name: &str,
) -> Option<String> {
    if name.is_empty() {
        return None;
    }
    let fqn = format!("{package}.{name}");
    support.fqn_exists(&fqn).then_some(fqn)
}

fn go_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or_default()
        .trim()
}

#[cfg(test)]
mod bounded_tests {
    use super::*;
    use crate::analyzer::model::StructuredTypeIdentityBuilder;
    use crate::analyzer::usages::receiver_analysis::{ReceiverAnalysisWork, ReceiverBudgetLimit};
    use crate::analyzer::{Language, Range, StructuredTypeName};
    use crate::path_utils::rel_path_string;
    use crate::test_support::AnalyzerFixture;

    struct ConcreteTestingReceiverProvider<'a> {
        inner: AnalyzerGoDefinitionProvider<'a>,
    }

    struct ExactPackageCallProvider<'a> {
        inner: AnalyzerGoDefinitionProvider<'a>,
    }

    impl GoDefinitionProvider for ExactPackageCallProvider<'_> {
        fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
            self.inner.fqn(fqn)
        }

        fn workspace_package_status(&self, import_path: &str) -> GoWorkspacePackageStatus {
            self.inner.workspace_package_status(import_path)
        }

        fn workspace_declaration_identities_authoritative(&self) -> bool {
            self.inner.workspace_declaration_identities_authoritative()
        }

        fn session(&self) -> Option<&ResolutionSession> {
            self.inner.session()
        }

        fn external_package_call_resolution(
            &self,
            import_path: &str,
            member: &str,
            parameter_count: usize,
        ) -> Option<GoModeledPackageCallResolution> {
            match (import_path, member, parameter_count) {
                ("example.com/external", "MakePair", 0)
                | ("example.com/external", "MakeVariadic", 2)
                | ("example.com/custom", "MakePair", 0)
                | ("old.example/app/internal/pkg", "MakePair", 0) => {
                    Some(GoModeledPackageCallResolution::ExactFunction)
                }
                _ => None,
            }
        }

        fn external_package_call_result_count(
            &self,
            import_path: &str,
            member: &str,
            parameter_count: usize,
        ) -> Option<usize> {
            match (import_path, member, parameter_count) {
                ("example.com/external", "MakePair", 0) => Some(2),
                ("example.com/custom", "MakePair", 0) => Some(1),
                _ => None,
            }
        }
    }

    impl GoDefinitionProvider for ConcreteTestingReceiverProvider<'_> {
        fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
            self.inner.fqn(fqn)
        }

        fn workspace_package_status(&self, import_path: &str) -> GoWorkspacePackageStatus {
            self.inner.workspace_package_status(import_path)
        }

        fn workspace_declaration_identities_authoritative(&self) -> bool {
            self.inner.workspace_declaration_identities_authoritative()
        }

        fn external_concrete_receiver_member(
            &self,
            owner_fqn: &str,
            member: &str,
            pointer_receivers: bool,
            parameter_count: usize,
        ) -> Option<String> {
            match (owner_fqn, member, pointer_receivers, parameter_count) {
                ("testing.T", "Fatal", true, 1) => Some("testing.T.Fatal".to_owned()),
                ("testing.T", "Stat", true, 0) => Some("testing.T.Stat".to_owned()),
                ("testing.F", "Fatal", true, 1) => Some("testing.F.Fatal".to_owned()),
                _ => None,
            }
        }

        fn external_callable_result_nominal_type(
            &self,
            owner_fqn: &str,
            member: &str,
            has_receiver: bool,
            parameter_count: usize,
            result_ordinal: usize,
        ) -> Option<GoModeledNominalType> {
            let (qualified_name, pointer) = match (
                owner_fqn,
                member,
                has_receiver,
                parameter_count,
                result_ordinal,
            ) {
                ("example.com/external", "MakePair", false, 0, 0)
                | ("example.com/external", "MakeFirst", false, 0, 0)
                | ("example.com/external", "Open", false, 0, 0) => ("testing.T", true),
                ("example.com/external", "MakeVariadic", false, 1, 0) => ("testing.T", true),
                ("example.com/external", "MakePair", false, 0, 1)
                | ("example.com/external", "MakeSecond", false, 0, 0) => ("testing.F", true),
                ("testing.T", "Stat", true, 0, 0) => ("testing.F", false),
                // Result zero is modeled so requesting result one can prove it
                // does not silently inherit the first result's receiver.
                ("example.com/external", "MakeError", false, 0, 0) => ("testing.T", true),
                _ => return None,
            };
            Some(GoModeledNominalType {
                declaration_id: format!("type.{qualified_name}"),
                qualified_name: qualified_name.to_owned(),
                pointer,
            })
        }
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

    fn imported_type_fixture(
        import: &str,
        expression: &str,
    ) -> (
        AnalyzerFixture,
        ProjectFile,
        String,
        Tree,
        ResolvedReferenceSite,
    ) {
        let source =
            format!("package main\n\nimport {import}\n\nfunc use() {{\n    _ = {expression}\n}}\n");
        let fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[
                ("go.mod", "module example.com/app\n"),
                (
                    "service/service.go",
                    "package service\n\ntype Service struct{}\n",
                ),
                ("main.go", &source),
            ],
        );
        let file = ProjectFile::new(fixture.project_root(), "main.go");
        let tree = parse_go_tree(&source).expect("Go tree");
        let site = site_for(&file, &source, expression, "Service");
        (fixture, file, source, tree, site)
    }

    fn activate_selector_navigation_overlay(fixture: &AnalyzerFixture) {
        use crate::analyzer::semantic_model::{
            CatalogCoordinate, CatalogOptions, CompilerOptions, SemanticModelActivationControl,
            SemanticModelActivationEvidence, SemanticModelActivationRequest,
            SemanticModelControlAction, SemanticModelControlScope, SemanticModelPackSelector,
            SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome, SemanticPackCatalog,
            SessionPackSource, SessionPackSourceKind, SourceFormat, acquire_active_semantic_models,
            compile_source,
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
        let pack = compile_source(SourceFormat::Json, &source, &CompilerOptions::default())
            .unwrap_or_else(|diagnostics| {
                panic!("Go selector fixture must compile: {diagnostics:#?}")
            });
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
            .expect("ephemeral catalog");
        catalog
            .register_session_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: "fixture.go.selector-navigation".to_owned(),
                },
            )
            .expect("register Go selector fixture");
        let request = SemanticModelActivationRequest {
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
        let SemanticModelRuntimeOutcome::Ready { .. } = acquire_active_semantic_models(
            fixture.analyzer.analyzer(),
            &catalog,
            None,
            &request,
            &CancellationToken::new(),
        ) else {
            panic!("Go selector fixture must activate");
        };
    }

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
            let selector = go_selector_descriptor_with_scope(tree.root_node(), &site, || true)
                .expect("Go selector");
            let go = resolve_analyzer::<GoAnalyzer>(fixture.analyzer.analyzer())
                .expect("fixture Go analyzer");
            let provider = AnalyzerGoDefinitionProvider::new(
                go,
                fixture.analyzer.analyzer().semantic_model_overlay(),
            );
            resolve_go(
                go,
                &provider,
                &file,
                source,
                Some(&tree),
                &site,
                Some(&selector),
                None,
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
        let go = resolve_analyzer::<GoAnalyzer>(fixture.analyzer.analyzer())
            .expect("fixture Go analyzer");
        let provider = AnalyzerGoDefinitionProvider::new(
            go,
            fixture.analyzer.analyzer().semantic_model_overlay(),
        );
        let resolve = |member: &str| {
            let expression = format!("api.{member}");
            let site = site_for(&file, source, &expression, member);
            let selector = go_selector_descriptor_with_scope(tree.root_node(), &site, || true)
                .expect("Go selector");
            resolve_go(
                go,
                &provider,
                &file,
                source,
                Some(&tree),
                &site,
                Some(&selector),
                None,
            )
            .outcome
        };

        for member in ["ExportedVar", "ExportedConst"] {
            let outcome = resolve(member);
            let expected = format!("example.com/mod.{member}");
            assert_eq!(
                outcome.status,
                DefinitionLookupStatus::NoDefinition,
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

        let overlay = Arc::new(crate::analyzer::OverlayProject::new(Arc::new(
            fixture.test_project().clone(),
        )));
        let main = ProjectFile::new(fixture.project_root(), "main.go");
        assert!(overlay.set(
            main.abs_path().to_path_buf(),
            "package main\n// unsaved request snapshot\n".to_owned(),
        ));
        let request_snapshot = go.clone_with_project(overlay as Arc<dyn crate::analyzer::Project>);
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

        let module_overlay = Arc::new(crate::analyzer::OverlayProject::new(Arc::new(
            fixture.test_project().clone(),
        )));
        let go_mod = ProjectFile::new(fixture.project_root(), "go.mod");
        assert!(module_overlay.set(
            go_mod.abs_path().to_path_buf(),
            "module example.com/unsaved\n".to_owned(),
        ));
        let module_request =
            go.clone_with_project(module_overlay as Arc<dyn crate::analyzer::Project>);
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
        let BoundedResolution::Complete { value, .. } = resolve_go_bounded(
            go,
            &main,
            source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        ) else {
            panic!("disk module call must resolve within the default budget");
        };
        assert_eq!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");

        let semantic_cancellation = CancellationToken::default();
        let mut materialization_budget = crate::analyzer::semantic::SemanticBudget::default();
        let base_artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &main,
                &mut crate::analyzer::semantic::SemanticRequest::new(
                    &mut materialization_budget,
                    &semantic_cancellation,
                ),
            )
            .expect("disk caller semantic materialization")
            .available_value()
            .cloned()
            .expect("disk caller semantic artifact");
        let first_call = |artifact: &Arc<crate::analyzer::semantic::SemanticArtifact>| {
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
        let mut dispatch_budget = crate::analyzer::semantic::SemanticBudget::default();
        let base_dispatch = crate::analyzer::semantic::DispatchOracle::resolve_call(
            &fixture.analyzer.semantic_oracle_provider(),
            &base_call,
            &mut crate::analyzer::semantic::SemanticRequest::new(
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
                    crate::analyzer::semantic::SemanticEffect::ProcedureReturn { value: Some(_) }
                )),
            "the baseline target carries an observable return effect"
        );

        let source_overlay = Arc::new(crate::analyzer::OverlayProject::new(Arc::new(
            fixture.test_project().clone(),
        )));
        assert!(source_overlay.set(main.abs_path().to_path_buf(), source.to_owned()));
        let source_request =
            go.clone_with_project(source_overlay as Arc<dyn crate::analyzer::Project>);
        assert!(
            source_request
                .get_definitions("old.example/app/pkg.Run")
                .iter()
                .any(|definition| definition == &old_definition),
            "a source-only overlay keeps the disk package namespace authoritative"
        );
        let BoundedResolution::Complete { value, .. } = resolve_go_bounded(
            &source_request,
            &main,
            source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        ) else {
            panic!("source-only overlay call must resolve within the default budget");
        };
        assert_eq!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");

        let unchanged_module_overlay = Arc::new(crate::analyzer::OverlayProject::new(Arc::new(
            fixture.test_project().clone(),
        )));
        let go_mod = ProjectFile::new(fixture.project_root(), "go.mod");
        assert!(unchanged_module_overlay.set(
            go_mod.abs_path().to_path_buf(),
            "module old.example/app\n".to_owned(),
        ));
        let unchanged_module_request =
            go.clone_with_project(unchanged_module_overlay as Arc<dyn crate::analyzer::Project>);
        assert!(
            unchanged_module_request
                .get_definitions("old.example/app/pkg.Run")
                .iter()
                .any(|definition| definition == &old_definition),
            "a byte-identical package-identity overlay retains declaration authority"
        );
        let unchanged_session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
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

        let overlay = Arc::new(crate::analyzer::OverlayProject::new(Arc::new(
            fixture.test_project().clone(),
        )));
        assert!(overlay.set(
            go_mod.abs_path().to_path_buf(),
            "module new.example/app\n".to_owned(),
        ));
        let workspace_request = fixture
            .analyzer
            .clone_with_project(Arc::clone(&overlay) as Arc<dyn crate::analyzer::Project>);
        let request =
            go.clone_with_project(Arc::clone(&overlay) as Arc<dyn crate::analyzer::Project>);
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

        let BoundedResolution::Complete { value, .. } = resolve_go_bounded(
            &request,
            &main,
            source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        ) else {
            panic!("overlaid go.mod lookup must fail closed within the default budget");
        };
        assert_ne!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");
        assert!(value.definitions.is_empty(), "{value:#?}");

        let mut request_materialization_budget =
            crate::analyzer::semantic::SemanticBudget::default();
        let request_artifact = workspace_request
            .materialize_program_semantics(
                &main,
                &mut crate::analyzer::semantic::SemanticRequest::new(
                    &mut request_materialization_budget,
                    &semantic_cancellation,
                ),
            )
            .expect("request caller semantic materialization")
            .available_value()
            .cloned()
            .expect("request caller semantic artifact");
        let request_call = first_call(&request_artifact);
        let mut request_dispatch_budget = crate::analyzer::semantic::SemanticBudget::default();
        let request_dispatch = crate::analyzer::semantic::DispatchOracle::resolve_call(
            &workspace_request.semantic_oracle_provider(),
            &request_call,
            &mut crate::analyzer::semantic::SemanticRequest::new(
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

    #[test]
    fn changed_go_mod_cannot_authorize_stale_internal_model_call() {
        let source = "package main\n\nimport pkg \"old.example/app/internal/pkg\"\n\nfunc use() { pkg.MakePair() }\n";
        let fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[("go.mod", "module old.example/app\n"), ("main.go", source)],
        );
        let file = ProjectFile::new(fixture.project_root(), "main.go");
        let tree = parse_go_tree(source).expect("Go tree");
        let site = site_for(&file, source, "pkg.MakePair()", "MakePair");
        let selector = go_selector_descriptor_with_scope(tree.root_node(), &site, || true)
            .expect("Go selector");
        let go = resolve_analyzer::<GoAnalyzer>(fixture.analyzer.analyzer())
            .expect("fixture Go analyzer");

        let disk_provider = ExactPackageCallProvider {
            inner: AnalyzerGoDefinitionProvider::new(go, None),
        };
        let disk_resolution = resolve_go(
            go,
            &disk_provider,
            &file,
            source,
            Some(&tree),
            &site,
            Some(&selector),
            None,
        );
        assert_eq!(
            disk_resolution
                .exact_external_call
                .as_ref()
                .map(ExactExternalCallProof::canonical_callee),
            Some("old.example/app/internal/pkg.MakePair"),
            "the disk module identity permits its own internal modeled package"
        );

        let overlay = Arc::new(crate::analyzer::OverlayProject::new(Arc::new(
            fixture.test_project().clone(),
        )));
        let go_mod = ProjectFile::new(fixture.project_root(), "go.mod");
        assert!(overlay.set(
            go_mod.abs_path().to_path_buf(),
            "module new.example/app\n".to_owned(),
        ));
        let request = go.clone_with_project(overlay as Arc<dyn crate::analyzer::Project>);
        assert!(!request.workspace_declaration_identities_authoritative());
        let request_provider = ExactPackageCallProvider {
            inner: AnalyzerGoDefinitionProvider::new(&request, None),
        };
        let request_resolution = resolve_go(
            &request,
            &request_provider,
            &file,
            source,
            Some(&tree),
            &site,
            Some(&selector),
            None,
        );
        assert!(
            request_resolution.exact_external_call.is_none(),
            "the disk importer identity must not authorize an internal model in the overlaid module namespace: {:#?}",
            request_resolution.outcome
        );
    }

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

    #[test]
    fn go_mod_update_reprojects_workspace_package_identity() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[
                ("go.mod", "module example.com/old\n"),
                ("pkg/pkg.go", "package pkg\n"),
            ],
        );
        let go = resolve_analyzer::<GoAnalyzer>(fixture.analyzer.analyzer())
            .expect("fixture Go analyzer");
        let go_mod = ProjectFile::new(fixture.project_root(), "go.mod");
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
        let updated = invalid.update(&std::collections::BTreeSet::from([go_mod]));

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
    }

    fn resolve_with_concrete_testing_receiver(
        fixture: &AnalyzerFixture,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
        site: &ResolvedReferenceSite,
    ) -> GoDefinitionResolution {
        let analyzer = fixture.analyzer.analyzer();
        let go = resolve_analyzer::<GoAnalyzer>(analyzer).expect("Go analyzer");
        let provider = ConcreteTestingReceiverProvider {
            inner: AnalyzerGoDefinitionProvider::new(go, None),
        };
        let selector = go_selector_descriptor_with_scope(tree.root_node(), site, || true)
            .expect("Go selector");
        resolve_go(
            analyzer,
            &provider,
            file,
            source,
            Some(tree),
            site,
            Some(&selector),
            None,
        )
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
            let selector = go_selector_descriptor_with_scope(tree.root_node(), &site, || true)
                .expect("Go selector");
            resolve_go(
                fixture.analyzer.analyzer(),
                provider,
                file,
                source,
                Some(tree),
                &site,
                Some(&selector),
                None,
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
    fn structured_concrete_external_receiver_carries_only_the_reviewed_method_identity() {
        for (
            receiver,
            expression,
            focus,
            expected_status,
            expected_target,
            expected_extensibility,
        ) in [
            (
                "*testing.T",
                "t.Fatal(\"stop\")",
                "Fatal",
                DefinitionLookupStatus::UnresolvableImportBoundary,
                Some("testing.T.Fatal"),
                Some(DispatchExtensibility::Closed),
            ),
            (
                "testing.TB",
                "t.Fatal(\"stop\")",
                "Fatal",
                DefinitionLookupStatus::NoDefinition,
                None,
                None,
            ),
            (
                "*testing.T",
                "t.Stat(1)",
                "Stat",
                DefinitionLookupStatus::NoDefinition,
                None,
                None,
            ),
        ] {
            let source = format!(
                "package main\n\nimport \"testing\"\n\nfunc use(t {receiver}) {{\n    {expression}\n}}\n"
            );
            let fixture = AnalyzerFixture::new_for_language(
                Language::Go,
                &[("go.mod", "module example.com/app\n"), ("main.go", &source)],
            );
            let file = ProjectFile::new(fixture.project_root(), "main.go");
            let tree = parse_go_tree(&source).expect("Go tree");
            let site = site_for(&file, &source, expression, focus);

            let resolution =
                resolve_with_concrete_testing_receiver(&fixture, &file, &source, &tree, &site);

            assert_eq!(
                resolution.outcome.status, expected_status,
                "{:#?}",
                resolution.outcome
            );
            assert_eq!(
                resolution
                    .outcome
                    .reference
                    .as_ref()
                    .map(|reference| reference.text.as_str()),
                expected_target,
                "{:#?}",
                resolution.outcome
            );
            assert_eq!(
                resolution.call_application,
                CallApplicationKind::BoundReceiver,
                "{:#?}",
                resolution.outcome
            );
            assert_eq!(
                resolution.dispatch_extensibility, expected_extensibility,
                "{:#?}",
                resolution.outcome
            );
            match expected_target {
                Some(expected_target) => {
                    let proof = resolution.exact_external_call.as_ref().unwrap_or_else(|| {
                        panic!(
                            "exact receiver target must retain one proof: {:#?}",
                            resolution.outcome
                        )
                    });
                    assert_eq!(proof.canonical_callee(), expected_target);
                    assert_eq!(proof.call_application(), CallApplicationKind::BoundReceiver);
                    assert_eq!(proof.parameter_count(), 1);
                }
                None => assert!(
                    resolution.exact_external_call.is_none(),
                    "a rejected receiver must not retain a partial proof: {:#?}",
                    resolution.outcome
                ),
            }
        }
    }

    #[test]
    fn modeled_external_results_preserve_go_assignment_ordinals_and_call_identity() {
        let source = r#"package main

import (
    os "example.com/external"
    custom "example.com/custom"
)

type localFactory struct{}

func pair() (int, int) { return 1, 2 }

func use() {
    values := []int{1, 2}
    primary, secondary := os.MakePair()
    primary.Fatal("stop")
    secondary.Fatal("stop")

    first, second := os.MakeFirst(), os.MakeSecond()
    first.Fatal("stop")
    second.Fatal("stop")

    opened, _ := os.Open()
    nested, nestedError := opened.Stat()
    nested.Fatal("stop")
    nestedError.Fatal("stop")

    ordinary := os.MakeVariadic(1)
    ordinary.Fatal("stop")

    tuple := os.MakeVariadic(pair())
    tuple.Fatal("stop")

    parenthesizedTuple := os.MakeVariadic((pair()))
    parenthesizedTuple.Fatal("stop")

    spread := os.MakeVariadic(values...)
    spread.Fatal("stop")

    _, rejected := os.MakeError()
    rejected.Fatal("stop")

    wrongArity, _ := os.MakePair(1)
    wrongArity.Fatal("stop")

    customResult, _ := custom.MakePair()
    customResult.Fatal("stop")

    os := localFactory{}
    shadowed, _ := os.MakePair()
    shadowed.Fatal("stop")
}
"#;
        let fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[("go.mod", "module example.com/app\n"), ("main.go", source)],
        );
        let file = ProjectFile::new(fixture.project_root(), "main.go");
        let tree = parse_go_tree(source).expect("Go tree");

        for (expression, target) in [
            ("primary.Fatal(\"stop\")", "testing.T.Fatal"),
            ("secondary.Fatal(\"stop\")", "testing.F.Fatal"),
            ("first.Fatal(\"stop\")", "testing.T.Fatal"),
            ("second.Fatal(\"stop\")", "testing.F.Fatal"),
            ("nested.Fatal(\"stop\")", "testing.F.Fatal"),
            ("ordinary.Fatal(\"stop\")", "testing.T.Fatal"),
        ] {
            let site = site_for(&file, source, expression, "Fatal");
            let resolution =
                resolve_with_concrete_testing_receiver(&fixture, &file, source, &tree, &site);
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
                Some(target),
                "{expression}: {:#?}",
                resolution.outcome
            );
        }

        for expression in [
            "rejected.Fatal(\"stop\")",
            "nestedError.Fatal(\"stop\")",
            "wrongArity.Fatal(\"stop\")",
            "customResult.Fatal(\"stop\")",
            "shadowed.Fatal(\"stop\")",
            "tuple.Fatal(\"stop\")",
            "parenthesizedTuple.Fatal(\"stop\")",
            "spread.Fatal(\"stop\")",
        ] {
            let site = site_for(&file, source, expression, "Fatal");
            let resolution =
                resolve_with_concrete_testing_receiver(&fixture, &file, source, &tree, &site);
            assert_ne!(
                resolution.outcome.status,
                DefinitionLookupStatus::UnresolvableImportBoundary,
                "{expression} must not inherit result zero's modeled receiver: {:#?}",
                resolution.outcome
            );
            assert!(
                resolution
                    .outcome
                    .reference
                    .as_ref()
                    .is_none_or(|reference| {
                        !matches!(
                            reference.text.as_str(),
                            "testing.T.Fatal" | "testing.F.Fatal"
                        )
                    }),
                "{expression}: {:#?}",
                resolution.outcome
            );
        }
    }

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
        let file = ProjectFile::new(fixture.project_root(), "main.go");
        let tree = parse_go_tree(source).expect("Go tree");
        let go = resolve_analyzer::<GoAnalyzer>(fixture.analyzer.analyzer())
            .expect("fixture Go analyzer");

        let unbounded = ExactPackageCallProvider {
            inner: AnalyzerGoDefinitionProvider::new(go, None),
        };
        assert_exact_import_namespace_authority(&fixture, &unbounded, &file, source, &tree);

        let session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
        let bounded = ExactPackageCallProvider {
            inner: AnalyzerGoDefinitionProvider::bounded(go, &session, None),
        };
        assert_exact_import_namespace_authority(&fixture, &bounded, &file, source, &tree);
        assert!(matches!(
            session.finish(()),
            BoundedResolution::Complete { .. }
        ));
    }

    #[test]
    fn unresolved_terminal_selector_does_not_return_its_receiver_field() {
        let source = "package repro\n\nimport \"sync\"\n\ntype anonymizer struct { lock sync.Mutex }\nfunc (a *anonymizer) SaveMapping() { a.lock.Lock() }\n";
        let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", source)]);
        let file = ProjectFile::new(fixture.project_root(), "main.go");
        let tree = parse_go_tree(source).expect("Go tree");
        let site = site_for(&file, source, "a.lock.Lock()", "Lock");

        let outcome = resolve_go_bounded(
            fixture.analyzer.analyzer(),
            &file,
            source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        );
        let BoundedResolution::Complete { value, .. } = outcome else {
            panic!("Go selector lookup should complete: {outcome:#?}");
        };
        assert_eq!(
            DefinitionLookupStatus::NoDefinition,
            value.status,
            "{value:#?}"
        );
        assert!(value.definitions.is_empty(), "{value:#?}");
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

    #[test]
    fn bounded_go_import_alias_and_dot_import_use_structured_paths() {
        for (import, expression) in [
            ("svc \"example.com/app/service\"", "svc.Service{}"),
            (". \"example.com/app/service\"", "Service{}"),
        ] {
            let (fixture, file, source, tree, site) = imported_type_fixture(import, expression);
            let outcome = resolve_go_bounded(
                fixture.analyzer.analyzer(),
                &file,
                &source,
                Some(&tree),
                &site,
                ReceiverAnalysisBudget::default(),
                None,
            );
            let BoundedResolution::Complete { value, .. } = outcome else {
                panic!("bounded Go import lookup should complete: {outcome:#?}");
            };
            assert_eq!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");
            assert!(
                value
                    .definitions
                    .iter()
                    .any(|definition| definition.fq_name() == "example.com/app/service.Service"),
                "{value:#?}"
            );
        }
    }

    #[test]
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
            let outcome = resolve_go_bounded(
                fixture.analyzer.analyzer(),
                &file,
                source,
                Some(&tree),
                &site,
                ReceiverAnalysisBudget::default(),
                None,
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

    fn wide_deep_fixture() -> (
        AnalyzerFixture,
        ProjectFile,
        String,
        Tree,
        ResolvedReferenceSite,
    ) {
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
        (fixture, file, source, tree, site)
    }

    #[test]
    fn bounded_go_wide_deep_walk_stops_without_partial_result() {
        let (fixture, file, source, tree, site) = wide_deep_fixture();
        let outcome = resolve_go_bounded(
            fixture.analyzer.analyzer(),
            &file,
            &source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::tiny(),
            None,
        );

        assert!(matches!(
            outcome,
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                ..
            }
        ));
    }

    #[test]
    fn bounded_go_wide_deep_walk_honors_mid_walk_cancellation() {
        let (fixture, file, source, tree, site) = wide_deep_fixture();
        let cancellation = CancellationToken::cancel_after_checks_for_test(12);
        let outcome = resolve_go_bounded(
            fixture.analyzer.analyzer(),
            &file,
            &source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            Some(&cancellation),
        );

        assert!(matches!(outcome, BoundedResolution::Cancelled { .. }));
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
        let outcome = resolve_go_bounded(
            fixture.analyzer.analyzer(),
            &file,
            &source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget {
                context_depth: 8,
                max_targets: 16,
                max_summary_expansions: 4_096,
                max_scope_nodes: 100_000,
            },
            None,
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

    #[test]
    fn bounded_go_structured_type_walk_charges_each_flat_wrapper() {
        let source = "package main\n\ntype Service struct{}\n";
        let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", source)]);
        let go = resolve_analyzer::<GoAnalyzer>(fixture.analyzer.analyzer())
            .expect("fixture Go analyzer");
        let file = ProjectFile::new(fixture.project_root(), "main.go");

        let mut builder = StructuredTypeIdentityBuilder::default();
        let name = StructuredTypeName::new(vec!["Service".to_string()], Vec::new(), false).unwrap();
        let mut root = builder.named(name).unwrap();
        for _ in 0..8 {
            root = builder.pointer(root).unwrap();
        }
        let identity = builder.finish(root).unwrap();

        let complete_session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
        let complete_provider = AnalyzerGoDefinitionProvider::bounded(go, &complete_session, None);
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let token = scope.token();
        let resolved =
            go_resolve_structured_type_fqn(&complete_provider, token, go, &file, "main", &identity);
        assert!(matches!(
            complete_session.finish(resolved),
            BoundedResolution::Complete {
                value: Some(ref fqn),
                ..
            } if fqn == "main.Service"
        ));

        let tiny_session = ResolutionSession::bounded(ReceiverAnalysisBudget::tiny(), None);
        let tiny_provider = AnalyzerGoDefinitionProvider::bounded(go, &tiny_session, None);
        let unresolved =
            go_resolve_structured_type_fqn(&tiny_provider, token, go, &file, "main", &identity);
        assert!(matches!(
            tiny_session.finish(unresolved),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                work: ReceiverAnalysisWork { scope_nodes: 1, .. },
            }
        ));
    }

    #[test]
    fn bounded_go_uses_structured_return_field_and_container_shapes() {
        let source = r#"package main

import svc "example.com/app/service"

type Holder struct {
    Next *svc.Service
    Items []svc.Service
    ByName map[string]svc.Service
}

func Make() *svc.Service { return nil }
func Similar() string { return "svc.Service" }

func use(holder Holder) {
    holder.Next.Run()
    Make().Run()
    svc.Make().Run()
    holder.Items[0].Run()
    holder.ByName["chosen"].Run()
    for _, service := range holder.Items {
        service.Run()
    }
    Similar().Run()
}
"#;
        let fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[
                ("go.mod", "module example.com/app\n"),
                (
                    "service/service.go",
                    "package service\n\ntype Service struct{}\nfunc (*Service) Run() {}\nfunc Make() *Service { return nil }\n",
                ),
                ("main.go", source),
            ],
        );
        let file = ProjectFile::new(fixture.project_root(), "main.go");
        let tree = parse_go_tree(source).expect("Go tree");

        for expression in [
            "holder.Next.Run()",
            "Make().Run()",
            "svc.Make().Run()",
            "holder.Items[0].Run()",
            "service.Run()",
        ] {
            let site = site_for(&file, source, expression, "Run");
            let outcome = resolve_go_bounded(
                fixture.analyzer.analyzer(),
                &file,
                source,
                Some(&tree),
                &site,
                ReceiverAnalysisBudget::default(),
                None,
            );
            let BoundedResolution::Complete { value, .. } = outcome else {
                panic!("{expression} should complete: {outcome:#?}");
            };
            assert_eq!(
                value.status,
                DefinitionLookupStatus::Resolved,
                "{expression}: {value:#?}"
            );
            assert!(
                value.definitions.iter().any(|definition| {
                    definition.fq_name() == "example.com/app/service.Service.Run"
                }),
                "{expression}: {value:#?}"
            );
        }

        let non_addressable_map_element =
            site_for(&file, source, "holder.ByName[\"chosen\"].Run()", "Run");
        let outcome = resolve_go_bounded(
            fixture.analyzer.analyzer(),
            &file,
            source,
            Some(&tree),
            &non_addressable_map_element,
            ReceiverAnalysisBudget::default(),
            None,
        );
        assert!(
            !matches!(
                outcome,
                BoundedResolution::Complete {
                    value: DefinitionLookupOutcome {
                        status: DefinitionLookupStatus::Resolved,
                        ..
                    },
                    ..
                }
            ),
            "a map element is not addressable and must not claim a pointer-only method: {outcome:#?}"
        );

        let negative = site_for(&file, source, "Similar().Run()", "Run");
        let outcome = resolve_go_bounded(
            fixture.analyzer.analyzer(),
            &file,
            source,
            Some(&tree),
            &negative,
            ReceiverAnalysisBudget::default(),
            None,
        );
        assert!(
            !matches!(
                outcome,
                BoundedResolution::Complete {
                    value: DefinitionLookupOutcome {
                        status: DefinitionLookupStatus::Resolved,
                        ..
                    },
                    ..
                }
            ),
            "textually similar string return must not become a receiver type: {outcome:#?}"
        );
    }

    #[test]
    fn bounded_go_builtin_new_and_method_sets_respect_addressability() {
        let source = r#"package main

type Service struct{}
func (Service) ValueOnly() {}
func (*Service) PointerOnly() {}

type Embedded struct{}
func (*Embedded) Promoted() {}
type Outer struct{ Embedded }
type OuterPointer struct{ *Embedded }

func MakeValue() Service { return Service{} }
func MakePointer() *Service { return nil }
func MakeOuter() Outer { return Outer{} }
func MakeOuterPointer() OuterPointer { return OuterPointer{} }

func use() {
    var addressable Service
    addressable.PointerOnly()
    new(Service).PointerOnly()
    new(Service).ValueOnly()
    MakePointer().PointerOnly()
    MakeValue().ValueOnly()
    MakeValue().PointerOnly()

    var outer Outer
    outer.Promoted()
    MakeOuter().Promoted()
    MakeOuterPointer().Promoted()
}
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", source)]);
        let file = ProjectFile::new(fixture.project_root(), "main.go");
        let tree = parse_go_tree(source).expect("Go tree");

        for (expression, member, target) in [
            (
                "addressable.PointerOnly()",
                "PointerOnly",
                "main.Service.PointerOnly",
            ),
            (
                "new(Service).PointerOnly()",
                "PointerOnly",
                "main.Service.PointerOnly",
            ),
            (
                "new(Service).ValueOnly()",
                "ValueOnly",
                "main.Service.ValueOnly",
            ),
            (
                "MakePointer().PointerOnly()",
                "PointerOnly",
                "main.Service.PointerOnly",
            ),
            (
                "MakeValue().ValueOnly()",
                "ValueOnly",
                "main.Service.ValueOnly",
            ),
            ("outer.Promoted()", "Promoted", "main.Embedded.Promoted"),
            (
                "MakeOuterPointer().Promoted()",
                "Promoted",
                "main.Embedded.Promoted",
            ),
        ] {
            let site = site_for(&file, source, expression, member);
            let outcome = resolve_go_bounded(
                fixture.analyzer.analyzer(),
                &file,
                source,
                Some(&tree),
                &site,
                ReceiverAnalysisBudget::default(),
                None,
            );
            let BoundedResolution::Complete { value, .. } = outcome else {
                panic!("{expression} should complete: {outcome:#?}");
            };
            assert_eq!(
                value.status,
                DefinitionLookupStatus::Resolved,
                "{expression}: {value:#?}"
            );
            assert!(
                matches!(value.definitions.as_slice(), [definition] if definition.fq_name() == target),
                "{expression}: {value:#?}"
            );
        }

        for (expression, member) in [
            ("MakeValue().PointerOnly()", "PointerOnly"),
            ("MakeOuter().Promoted()", "Promoted"),
        ] {
            let site = site_for(&file, source, expression, member);
            let outcome = resolve_go_bounded(
                fixture.analyzer.analyzer(),
                &file,
                source,
                Some(&tree),
                &site,
                ReceiverAnalysisBudget::default(),
                None,
            );
            assert!(
                !matches!(
                    outcome,
                    BoundedResolution::Complete {
                        value: DefinitionLookupOutcome {
                            status: DefinitionLookupStatus::Resolved,
                            ..
                        },
                        ..
                    }
                ),
                "non-addressable value receiver must not claim a pointer-only method: {expression}: {outcome:#?}"
            );
        }
    }

    #[test]
    fn bounded_go_shadowed_new_is_not_treated_as_builtin_allocation() {
        let source = r#"package main

type Service struct{}
func (*Service) PointerOnly() {}
func new(value Service) Service { return value }

func use() {
    new(Service{}).PointerOnly()
}
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", source)]);
        let file = ProjectFile::new(fixture.project_root(), "main.go");
        let tree = parse_go_tree(source).expect("Go tree");
        let site = site_for(&file, source, "new(Service{}).PointerOnly()", "PointerOnly");
        let outcome = resolve_go_bounded(
            fixture.analyzer.analyzer(),
            &file,
            source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        );

        assert!(
            !matches!(
                outcome,
                BoundedResolution::Complete {
                    value: DefinitionLookupOutcome {
                        status: DefinitionLookupStatus::Resolved,
                        ..
                    },
                    ..
                }
            ),
            "a package binding named new must shadow the builtin: {outcome:#?}"
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
}
