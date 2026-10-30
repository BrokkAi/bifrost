//! Analyzer-owned bounded receiver queries for structural traversal.

use crate::analyzer::common::language_for_file;
use crate::analyzer::languages::{
    BoundedReceiverQuery, LanguageSupport, ReceiverFactContext, StructuralReceiverResolver,
    language_support_for_hook,
};
use crate::analyzer::semantic::{
    AbstractObjectIdentity, CandidateCoverage, OracleLimitValues, OracleLimits, SemanticBudget,
    SemanticBudgetDimension, SemanticBudgetExceeded, SemanticCapability, SemanticOutcome,
    SemanticProviderError, SemanticRequest, SemanticWork, SourcePointsToResult,
    WorkspaceSemanticOracle,
};
use crate::analyzer::semantic_model::{
    SemanticModelCallableKey, SemanticModelMemberTargetDisposition,
    SemanticModelOverlayDisposition, SemanticModelProvenance, SemanticModelSymbol,
    SemanticModelSymbolKind, TypeRef,
};
use crate::analyzer::store::LimitedQueryRows;
use crate::analyzer::structural::FileFacts;
use crate::analyzer::structural::provider::StructuralSyntaxLimitedOutcome;
use crate::analyzer::usages::get_definition::{
    BoundedResolution, DefinitionLookupOutcome, DefinitionLookupStatus,
};
use crate::analyzer::usages::get_type::{
    TypeLookupOutcome, TypeLookupStatus, semantic_model_lookup_type,
};
use crate::analyzer::usages::receiver_analysis::{
    ReceiverAnalysisBudget, ReceiverAnalysisOutcome, ReceiverAnalysisReport, ReceiverAnalysisWork,
    ReceiverBudgetLimit, ReceiverFileCtx, ReceiverFileFacts, ReceiverFileSetup,
    ReceiverIdentityProof, ReceiverValue,
};
use crate::analyzer::usages::receiver_sites::{
    ReceiverSiteIndex, ReceiverSiteIndexBuild, ReceiverSiteIndexLimit, ReceiverSiteInputMode,
    ReceiverSiteKind, ReceiverSiteSelection, ReceiverSiteSelectionLimit, build_receiver_site_index,
};
use crate::analyzer::usages::reference_site::{
    ResolvedReferenceSite, node_range, smallest_named_node_covering,
};
use crate::analyzer::usages::target_kind::TypeLookupTargetKind;
use crate::analyzer::{
    AnalyzerDefinitionLookup, CodeUnit, DispatchExtensibility, IAnalyzer, Language, ProjectFile,
    Range, WorkspaceAnalyzer,
};
use crate::cancellation::CancellationToken;
use crate::hash::HashMap;
use crate::path_utils::rel_path_string;

use brokk_bifrost_csharp::syntax::CSHARP_INDEXER_MEMBER_NAME;
use std::cell::RefCell;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use tree_sitter::{Node, Tree};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReceiverQueryOperation {
    ReceiverTargets,
    PointsTo,
    MemberTargets,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverQueryInput {
    Expression,
    ContainingSite,
}

impl ReceiverQueryOperation {
    /// The value domain the `analysis_kind` row fields publish (issue #2515).
    pub const LABELS: &'static [&'static str] =
        &["receiver_targets", "points_to", "member_targets"];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReceiverTargets => "receiver_targets",
            Self::PointsTo => "points_to",
            Self::MemberTargets => "member_targets",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReceiverQuerySite {
    pub file: ProjectFile,
    pub language: Language,
    pub range: Range,
    pub text: String,
    pub syntax_kind: String,
    pub member_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ReceiverQueryAnalysis {
    Values(ReceiverAnalysisOutcome<ReceiverValue>),
    MemberTargets(ReceiverAnalysisOutcome<ReceiverMemberTarget>),
}

/// One exact static member target together with the exact receiver owner that
/// justified it. A modeled member is retained as its active model record,
/// never converted into a synthetic workspace declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiverMemberTarget {
    Workspace {
        receiver: Option<CodeUnit>,
        member: CodeUnit,
    },
    SemanticModel {
        receiver: Box<ModeledDeclarationIdentity>,
        member: Box<ModeledDeclarationIdentity>,
        receiver_proof: ReceiverIdentityProof,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeledDeclarationIdentity {
    pub id: String,
    pub owner_id: Option<String>,
    pub name: String,
    pub qualified_name: String,
    pub language: String,
    pub kind: SemanticModelSymbolKind,
    pub provenance: SemanticModelProvenance,
}

impl From<&SemanticModelSymbol> for ModeledDeclarationIdentity {
    fn from(symbol: &SemanticModelSymbol) -> Self {
        Self {
            id: symbol.id.clone(),
            owner_id: symbol.owner_id.clone(),
            name: symbol.name.clone(),
            qualified_name: symbol.qualified_name.clone(),
            language: symbol.language.clone(),
            kind: symbol.kind,
            provenance: symbol.provenance.clone(),
        }
    }
}

impl Hash for ModeledDeclarationIdentity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.provenance.active_model_set_hash.hash(state);
    }
}

impl Hash for ReceiverMemberTarget {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            Self::Workspace { receiver, member } => {
                receiver.hash(state);
                member.hash(state);
            }
            Self::SemanticModel {
                receiver, member, ..
            } => {
                receiver.hash(state);
                member.hash(state);
            }
        }
    }
}

impl ReceiverMemberTarget {
    pub fn workspace_receiver(&self) -> Option<&CodeUnit> {
        match self {
            Self::Workspace { receiver, .. } => receiver.as_ref(),
            Self::SemanticModel { .. } => None,
        }
    }

    pub fn workspace_member(&self) -> Option<&CodeUnit> {
        match self {
            Self::Workspace { member, .. } => Some(member),
            Self::SemanticModel { .. } => None,
        }
    }

    pub fn receiver_identity_id(&self) -> Option<String> {
        match self {
            Self::Workspace { receiver, .. } => receiver
                .as_ref()
                .map(|receiver| receiver.declaration_id().to_string()),
            Self::SemanticModel { receiver, .. } => Some(receiver.id.clone()),
        }
    }

    pub fn member_identity_id(&self) -> String {
        match self {
            Self::Workspace { member, .. } => member.declaration_id().to_string(),
            Self::SemanticModel { member, .. } => member.id.clone(),
        }
    }

    pub fn member_name(&self) -> &str {
        match self {
            Self::Workspace { member, .. } => member.identifier(),
            Self::SemanticModel { member, .. } => &member.name,
        }
    }

    pub fn fq_name(&self) -> String {
        match self {
            Self::Workspace { member, .. } => member.fq_name(),
            Self::SemanticModel { member, .. } => member.qualified_name.clone(),
        }
    }

    pub fn receiver_proof(&self) -> Option<&ReceiverIdentityProof> {
        match self {
            Self::Workspace { .. } => None,
            Self::SemanticModel { receiver_proof, .. } => Some(receiver_proof),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReceiverQueryReport {
    pub operation: ReceiverQueryOperation,
    pub site: ReceiverQuerySite,
    pub analysis: ReceiverQueryAnalysis,
    pub member_range: Option<Range>,
    pub work: ReceiverAnalysisWork,
    pub candidates_truncated: bool,
    pub semantic_unsupported: Option<SemanticCapability>,
    /// Candidate-aligned semantic points-to answers for the RQL
    /// `points_to_candidate` expansion. The display-oriented receiver values
    /// can merge candidates and therefore cannot carry this identity.
    pub points_to: Option<SourcePointsToResult>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiverQueryError {
    Cancelled,
    SemanticProvider(SemanticProviderError),
}

pub struct ReceiverQueryService<'a> {
    #[doc(hidden)]
    pub analyzer: &'a dyn IAnalyzer,
    #[doc(hidden)]
    pub workspace: Option<&'a WorkspaceAnalyzer>,
    #[doc(hidden)]
    pub definitions: AnalyzerDefinitionLookup<'a>,
    prepared_files: RefCell<HashMap<ProjectFile, PreparedReceiverFile>>,
    #[doc(hidden)]
    pub prepared_java_files: RefCell<HashMap<ProjectFile, PreparedJavaReceiverFile>>,
    #[doc(hidden)]
    pub prepared_structural_files: RefCell<HashMap<ProjectFile, PreparedStructuralReceiverFile>>,
    /// Language-owned point state belongs to this service's one RQL/policy
    /// request and grows only for source files that request touches.
    receiver_request: RefCell<Option<Box<dyn crate::analyzer::languages::ReceiverRequest + 'a>>>,
    reads: RefCell<Option<super::common::QueryMemoReads>>,
}

struct PreparedReceiverFile {
    source: String,
    tree: tree_sitter::Tree,
    facts: ReceiverFileFacts,
}

#[doc(hidden)]
pub struct PreparedStructuralReceiverFile {
    facts: Arc<FileFacts>,
    sites: ReceiverSiteIndex,
    syntax: Arc<crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree>,
}

impl PreparedStructuralReceiverFile {
    #[doc(hidden)]
    pub fn matches(&self, facts: &Arc<FileFacts>) -> bool {
        Arc::ptr_eq(&self.facts, facts)
            && self.sites.source() == facts.source()
            && self.syntax.source() == facts.source()
    }
}

#[doc(hidden)]
pub struct PreparedJavaReceiverFile {
    #[doc(hidden)]
    pub source: String,
    #[doc(hidden)]
    pub tree: tree_sitter::Tree,
    #[doc(hidden)]
    pub line_starts: Vec<usize>,
}

#[doc(hidden)]
pub enum SemanticReceiverGate {
    Bypassed {
        work: ReceiverAnalysisWork,
    },
    Available {
        work: ReceiverAnalysisWork,
        points_to: SourcePointsToResult,
        evidence: SemanticReceiverEvidence,
    },
    Unavailable {
        work: ReceiverAnalysisWork,
        unsupported: Option<SemanticCapability>,
    },
    Exceeded {
        work: ReceiverAnalysisWork,
        limit: ReceiverBudgetLimit,
    },
}

impl SemanticReceiverGate {
    #[doc(hidden)]
    pub fn work(&self) -> ReceiverAnalysisWork {
        match self {
            Self::Bypassed { work }
            | Self::Available { work, .. }
            | Self::Unavailable { work, .. }
            | Self::Exceeded { work, .. } => *work,
        }
    }

    #[doc(hidden)]
    pub fn exceeded_limit(&self) -> Option<ReceiverBudgetLimit> {
        match self {
            Self::Exceeded { limit, .. } => Some(*limit),
            Self::Bypassed { .. } | Self::Available { .. } | Self::Unavailable { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum SemanticReceiverEvidence {
    ExhaustiveComplete,
    Incomplete {
        coverage: CandidateCoverage,
        unsupported: Option<SemanticCapability>,
        origin: SemanticReceiverIncompleteness,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum SemanticReceiverIncompleteness {
    /// The retained candidates are individually proven and complete, but a
    /// globally incomplete adapter capability keeps the candidate set open.
    GlobalCapabilitiesWithProvenCandidates,
    /// Query-local uncertainty, including unproven candidates and disabled or
    /// truncated call context.
    Local,
}

impl SemanticReceiverEvidence {
    fn from_outcome<T>(outcome: &SemanticOutcome<T>, coverage: CandidateCoverage) -> Self {
        if outcome.is_complete() && coverage.is_exhaustive() {
            Self::ExhaustiveComplete
        } else {
            Self::Incomplete {
                coverage,
                unsupported: match outcome {
                    SemanticOutcome::Unsupported { capability, .. } => Some(*capability),
                    _ => None,
                },
                origin: SemanticReceiverIncompleteness::Local,
            }
        }
    }

    fn from_points_to_outcome(
        outcome: &SemanticOutcome<SourcePointsToResult>,
        points_to: &SourcePointsToResult,
    ) -> Self {
        let mut evidence = Self::from_outcome(outcome, points_to.coverage());
        if matches!(
            evidence,
            Self::Incomplete {
                coverage: CandidateCoverage::Open,
                unsupported: None,
                ..
            }
        ) && points_to.globally_incomplete_with_proven_candidates()
        {
            evidence = Self::Incomplete {
                coverage: CandidateCoverage::Open,
                unsupported: None,
                origin: SemanticReceiverIncompleteness::GlobalCapabilitiesWithProvenCandidates,
            };
        }
        evidence
    }

    #[doc(hidden)]
    pub const fn supports_precise(self) -> bool {
        matches!(self, Self::ExhaustiveComplete)
    }

    const fn legacy_provider_can_close(self) -> bool {
        matches!(
            self,
            Self::Incomplete {
                origin: SemanticReceiverIncompleteness::GlobalCapabilitiesWithProvenCandidates,
                ..
            }
        )
    }

    #[doc(hidden)]
    pub const fn is_truncated(self) -> bool {
        matches!(
            self,
            Self::Incomplete {
                coverage: CandidateCoverage::Truncated,
                ..
            }
        )
    }

    #[doc(hidden)]
    pub const fn unsupported_capability(self) -> Option<SemanticCapability> {
        match self {
            Self::Incomplete { unsupported, .. } => unsupported,
            Self::ExhaustiveComplete => None,
        }
    }
}

/// One receiver-query budget shared by setup, the neutral semantic gate, and
/// the compatibility provider. Setup consumes the same scope capacity as the
/// two analysis phases even though it remains separately visible in reports.
#[derive(Debug, Clone, Copy)]
#[doc(hidden)]
pub struct ReceiverWorkLedger {
    budget: ReceiverAnalysisBudget,
    work: ReceiverAnalysisWork,
}

impl ReceiverWorkLedger {
    #[doc(hidden)]
    pub fn new(budget: ReceiverAnalysisBudget) -> Self {
        Self {
            budget,
            work: ReceiverAnalysisWork::default(),
        }
    }

    #[doc(hidden)]
    pub fn remaining_budget(&self) -> ReceiverAnalysisBudget {
        ReceiverAnalysisBudget {
            max_scope_nodes: self
                .budget
                .max_scope_nodes
                .saturating_sub(self.work.setup_nodes.saturating_add(self.work.scope_nodes)),
            max_summary_expansions: self
                .budget
                .max_summary_expansions
                .saturating_sub(self.work.summary_expansions),
            max_resolution_rounds: self
                .budget
                .max_resolution_rounds
                .saturating_sub(self.work.resolution_rounds),
            ..self.budget
        }
    }

    #[doc(hidden)]
    pub fn charge_setup(&mut self, nodes: usize) -> Result<(), ReceiverBudgetLimit> {
        let remaining = self.remaining_budget().max_scope_nodes;
        self.work.setup_nodes = self.work.setup_nodes.saturating_add(nodes.min(remaining));
        if nodes > remaining {
            Err(ReceiverBudgetLimit::ScopeNodes)
        } else {
            Ok(())
        }
    }

    fn charge_analysis(&mut self, work: ReceiverAnalysisWork) -> Result<(), ReceiverBudgetLimit> {
        debug_assert_eq!(work.setup_nodes, 0);
        let remaining = self.remaining_budget();
        let scope_exceeded = work.scope_nodes > remaining.max_scope_nodes;
        let summaries_exceeded = work.summary_expansions > remaining.max_summary_expansions;
        let rounds_exceeded = work.resolution_rounds > remaining.max_resolution_rounds;
        self.work.scope_nodes = self
            .work
            .scope_nodes
            .saturating_add(work.scope_nodes.min(remaining.max_scope_nodes));
        self.work.summary_expansions = self.work.summary_expansions.saturating_add(
            work.summary_expansions
                .min(remaining.max_summary_expansions),
        );
        self.work.resolution_rounds = self
            .work
            .resolution_rounds
            .saturating_add(work.resolution_rounds.min(remaining.max_resolution_rounds));
        if scope_exceeded {
            Err(ReceiverBudgetLimit::ScopeNodes)
        } else if summaries_exceeded {
            Err(ReceiverBudgetLimit::SummaryExpansions)
        } else if rounds_exceeded {
            Err(ReceiverBudgetLimit::ResolutionRounds)
        } else {
            Ok(())
        }
    }

    #[doc(hidden)]
    pub fn work(&self) -> ReceiverAnalysisWork {
        self.work
    }
}

fn combined_receiver_work(
    left: ReceiverAnalysisWork,
    right: ReceiverAnalysisWork,
) -> ReceiverAnalysisWork {
    left.saturating_add(right)
}

#[doc(hidden)]
pub enum CompatibilityOutcome<T> {
    Complete(T),
    Exceeded(ReceiverBudgetLimit),
}

#[doc(hidden)]
pub fn charge_bounded_resolution<T>(
    ledger: &mut ReceiverWorkLedger,
    resolution: BoundedResolution<T>,
) -> Result<CompatibilityOutcome<T>, ReceiverQueryError> {
    let aggregate_limit = ledger.charge_analysis(resolution.work()).err();
    match resolution {
        BoundedResolution::Complete { value, .. } => Ok(match aggregate_limit {
            Some(limit) => CompatibilityOutcome::Exceeded(limit),
            None => CompatibilityOutcome::Complete(value),
        }),
        BoundedResolution::Exceeded { limit, .. } => Ok(CompatibilityOutcome::Exceeded(
            aggregate_limit.unwrap_or(limit),
        )),
        BoundedResolution::Cancelled { .. } => Err(ReceiverQueryError::Cancelled),
    }
}

#[doc(hidden)]
pub fn charge_scope_step(ledger: &mut ReceiverWorkLedger) -> Result<(), ReceiverBudgetLimit> {
    ledger.charge_analysis(ReceiverAnalysisWork {
        scope_nodes: 1,
        ..ReceiverAnalysisWork::default()
    })
}

#[doc(hidden)]
pub fn charge_summary_step(ledger: &mut ReceiverWorkLedger) -> Result<(), ReceiverBudgetLimit> {
    ledger.charge_analysis(ReceiverAnalysisWork {
        summary_expansions: 1,
        ..ReceiverAnalysisWork::default()
    })
}

fn charge_limited_projection<T>(
    batch: LimitedQueryRows<T>,
    cancellation: Option<&CancellationToken>,
    ledger: &mut ReceiverWorkLedger,
) -> Result<CompatibilityOutcome<Vec<T>>, ReceiverQueryError> {
    check_cancelled(cancellation)?;
    let charged_rows = batch.inspected.max(batch.rows.len());
    for _ in 0..charged_rows {
        check_cancelled(cancellation)?;
        if let Err(limit) = charge_scope_step(ledger) {
            return Ok(CompatibilityOutcome::Exceeded(limit));
        }
    }
    if !batch.complete {
        return Ok(CompatibilityOutcome::Exceeded(
            ReceiverBudgetLimit::ScopeNodes,
        ));
    }
    Ok(CompatibilityOutcome::Complete(batch.rows))
}

impl<'a> ReceiverQueryService<'a> {
    pub fn new(analyzer: &'a dyn IAnalyzer) -> Self {
        Self::with_workspace(analyzer, None)
    }

    pub fn from_workspace(workspace: &'a WorkspaceAnalyzer) -> Self {
        Self::with_workspace(workspace.analyzer(), Some(workspace))
    }

    fn with_workspace(
        analyzer: &'a dyn IAnalyzer,
        workspace: Option<&'a WorkspaceAnalyzer>,
    ) -> Self {
        Self {
            analyzer,
            workspace,
            definitions: AnalyzerDefinitionLookup::new(analyzer, Language::None),
            prepared_files: RefCell::new(HashMap::default()),
            prepared_java_files: RefCell::new(HashMap::default()),
            prepared_structural_files: RefCell::new(HashMap::default()),
            receiver_request: RefCell::new(None),
            reads: RefCell::new(None),
        }
    }

    fn structural_type_resolution(
        &self,
        language: Language,
        resolver: &'static dyn StructuralReceiverResolver,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome> {
        if !resolver.reuses_request_scoped_native_points() {
            return resolver.resolve_type_bounded(query);
        }
        self.ensure_receiver_request(language, query.cancellation);
        {
            let mut request = self.receiver_request.borrow_mut();
            if let Some(request) = request.as_mut() {
                return request.resolve_type(query);
            }
        }
        resolver.resolve_type_bounded(query)
    }

    fn structural_definition_resolution(
        &self,
        language: Language,
        resolver: &'static dyn StructuralReceiverResolver,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<DefinitionLookupOutcome> {
        if !resolver.reuses_request_scoped_native_points() {
            return resolver.resolve_definition_bounded(query);
        }
        self.ensure_receiver_request(language, query.cancellation);
        {
            let mut request = self.receiver_request.borrow_mut();
            if let Some(request) = request.as_mut() {
                return request.resolve_definition(query);
            }
        }
        resolver.resolve_definition_bounded(query)
    }

    #[track_caller]
    fn ensure_receiver_request(
        &self,
        language: Language,
        cancellation: Option<&CancellationToken>,
    ) {
        let mut request = self.receiver_request.borrow_mut();
        if request.is_none()
            && let Some(support) = language_support_for_hook(language, "open_receiver_request")
        {
            let cancellation = cancellation.cloned().unwrap_or_default();
            *request = support.open_receiver_request(self.analyzer, &cancellation);
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn analyze_with_structural_facts(
        &self,
        operation: ReceiverQueryOperation,
        file: &ProjectFile,
        range: Range,
        input: ReceiverQueryInput,
        facts: &Arc<FileFacts>,
        budget: ReceiverAnalysisBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Result<ReceiverQueryReport, ReceiverQueryError> {
        self.analyze_with_optional_structural_facts(
            operation,
            file,
            range,
            input,
            Some(facts),
            budget,
            cancellation,
        )
    }

    pub fn analyze(
        &self,
        operation: ReceiverQueryOperation,
        file: &ProjectFile,
        range: Range,
        input: ReceiverQueryInput,
        budget: ReceiverAnalysisBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Result<ReceiverQueryReport, ReceiverQueryError> {
        self.analyze_with_optional_structural_facts(
            operation,
            file,
            range,
            input,
            None,
            budget,
            cancellation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn analyze_with_optional_structural_facts(
        &self,
        operation: ReceiverQueryOperation,
        file: &ProjectFile,
        range: Range,
        input: ReceiverQueryInput,
        structural_facts: Option<&Arc<FileFacts>>,
        budget: ReceiverAnalysisBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Result<ReceiverQueryReport, ReceiverQueryError> {
        let previous = self.reads.take();
        let (result, reads) = super::common::capture_memo_reads(self.analyzer, || {
            if let Some(previous) = previous {
                crate::analyzer::usages::common::replay_memo_reads(&previous, self.analyzer);
            }
            if crate::analyzer::read_attribution_records_reads(|| {
                self.analyzer.read_ledger_attached()
            }) {
                if let Some(blob) = self.analyzer.indexed_blob_oid(file) {
                    self.analyzer.record_read(crate::analyzer::ReadKey::file(
                        file.language(),
                        crate::path_utils::rel_path_string(file),
                        blob,
                    ));
                } else {
                    self.analyzer.record_unattributed_read();
                }
            }
            self.analyze_with_prepared_inputs(
                operation,
                file,
                range,
                input,
                structural_facts,
                budget,
                cancellation,
            )
        });
        *self.reads.borrow_mut() = Some(reads);
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn analyze_with_prepared_inputs(
        &self,
        operation: ReceiverQueryOperation,
        file: &ProjectFile,
        range: Range,
        input: ReceiverQueryInput,
        structural_facts: Option<&Arc<FileFacts>>,
        budget: ReceiverAnalysisBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Result<ReceiverQueryReport, ReceiverQueryError> {
        check_cancelled(cancellation)?;
        let language = language_for_file(file);
        if let Some(resolver) = language_support_for_hook(language, "structural_receiver")
            .and_then(LanguageSupport::structural_receiver)
        {
            return self.analyze_structural(
                operation,
                file,
                language,
                resolver,
                range,
                input,
                structural_facts,
                budget,
                cancellation,
            );
        }
        let indexed_source = self.analyzer.indexed_source(file);
        if let Some(answer) = language_support_for_hook(language, "analyze_receiver_query")
            .and_then(|support| {
                support.analyze_receiver_query(
                    self,
                    operation,
                    file,
                    range,
                    input,
                    budget,
                    cancellation,
                    indexed_source.clone(),
                )
            })
        {
            return answer;
        }
        let Some(factory) = language_support_for_hook(language, "receiver_facts")
            .and_then(LanguageSupport::receiver_facts)
        else {
            return Ok(unsupported_report(
                operation,
                file,
                language,
                range,
                "receiver_analysis_language_unsupported",
                indexed_source.as_deref(),
            ));
        };
        let Some(source) = indexed_source else {
            return Ok(unsupported_report(
                operation,
                file,
                language,
                range,
                "indexed_source_unavailable",
                None,
            ));
        };
        let mut ledger = ReceiverWorkLedger::new(budget);
        if !self.prepared_files.borrow().contains_key(file) {
            match factory.prepare_file(&ReceiverFileCtx {
                file,
                language,
                source: &source,
                max_scope_nodes: ledger.remaining_budget().max_scope_nodes,
                cancellation,
            }) {
                ReceiverFileSetup::Ready {
                    tree,
                    facts,
                    visited,
                } => {
                    ledger
                        .charge_setup(visited)
                        .expect("completed setup traversal fits its supplied receiver budget");
                    self.prepared_files.borrow_mut().insert(
                        file.clone(),
                        PreparedReceiverFile {
                            source,
                            tree,
                            facts,
                        },
                    );
                }
                ReceiverFileSetup::ParseFailed => {
                    return Ok(unsupported_report(
                        operation,
                        file,
                        language,
                        range,
                        "receiver_source_parse_failed",
                        Some(&source),
                    ));
                }
                ReceiverFileSetup::ExceededScope { visited } => {
                    let _ = ledger.charge_setup(visited);
                    return Ok(setup_budget_report(
                        operation,
                        file,
                        language,
                        range,
                        &source,
                        ledger.work(),
                    ));
                }
                ReceiverFileSetup::Cancelled => {
                    return Err(ReceiverQueryError::Cancelled);
                }
            }
        }
        let prepared_files = self.prepared_files.borrow();
        let prepared = prepared_files
            .get(file)
            .expect("receiver file was prepared above");
        let source = prepared.source.as_str();
        let tree = &prepared.tree;
        let Some(input_node) =
            smallest_named_node_covering(tree.root_node(), range.start_byte, range.end_byte)
        else {
            let mut report = unsupported_report(
                operation,
                file,
                language,
                range,
                "receiver_input_range_unavailable",
                Some(source),
            );
            report.work = ledger.work();
            return Ok(report);
        };
        // The lookup is created language-blind and re-scoped per dispatch, the same
        // way the Java receiver path re-scopes it before its own session runs.
        self.definitions.set_language(language);
        let provider = factory.make_receiver_facts(ReceiverFactContext {
            analyzer: self.analyzer,
            definitions: &self.definitions,
            language,
            file,
            source,
            root: tree.root_node(),
            facts: &prepared.facts,
        });

        let report = match operation {
            ReceiverQueryOperation::PointsTo => {
                let gate = self.semantic_receiver_gate(
                    file,
                    node_range(input_node),
                    ledger.remaining_budget(),
                    cancellation,
                )?;
                if let Some(limit) = charge_semantic_gate(&mut ledger, &gate) {
                    return Ok(budget_report(
                        operation,
                        site(
                            file,
                            language,
                            node_range(input_node),
                            source,
                            input_node.kind(),
                            None,
                        ),
                        ledger.work(),
                        limit,
                    ));
                }
                let analysis = provider.resolve_receiver(input_node, ledger.remaining_budget());
                finalize_legacy_report(
                    self.analyzer,
                    values_report(operation, file, language, input_node, source, analysis),
                    gate,
                    &mut ledger,
                )
            }
            ReceiverQueryOperation::ReceiverTargets => {
                let receiver = match input {
                    ReceiverQueryInput::Expression => input_node,
                    ReceiverQueryInput::ContainingSite => {
                        let Some(receiver) = provider
                            .member_expression_at_site(input_node)
                            .and_then(|member| member.child_by_field_name("object"))
                        else {
                            let mut report = unsupported_report(
                                operation,
                                file,
                                language,
                                range,
                                "receiver_site_without_receiver",
                                Some(source),
                            );
                            report.work = ledger.work();
                            return Ok(report);
                        };
                        receiver
                    }
                };
                let gate = self.semantic_receiver_gate(
                    file,
                    node_range(receiver),
                    ledger.remaining_budget(),
                    cancellation,
                )?;
                if let Some(limit) = charge_semantic_gate(&mut ledger, &gate) {
                    return Ok(budget_report(
                        operation,
                        site(
                            file,
                            language,
                            node_range(receiver),
                            source,
                            receiver.kind(),
                            None,
                        ),
                        ledger.work(),
                        limit,
                    ));
                }
                let analysis = provider.resolve_receiver(receiver, ledger.remaining_budget());
                let mut report =
                    values_report(operation, file, language, receiver, source, analysis);
                if !legacy_external_module_identity_is_precise(&report.analysis) {
                    let dispatch_range = receiver
                        .child_by_field_name("function")
                        .map_or_else(|| node_range(receiver), node_range);
                    let modeled_call_result = self.modeled_call_result_type(
                        file,
                        language,
                        dispatch_range,
                        &mut ledger,
                        cancellation,
                    )?;
                    let modeled_call_result = match modeled_call_result {
                        CompatibilityOutcome::Complete(outcome) => outcome,
                        CompatibilityOutcome::Exceeded(limit) => {
                            return Ok(budget_report(operation, report.site, ledger.work(), limit));
                        }
                    };
                    if let Some(type_outcome) = modeled_call_result {
                        let model_values = projected_type_definitions(&type_outcome)
                            .cloned()
                            .map(ReceiverValue::InstanceType)
                            .collect::<Vec<_>>();
                        report.analysis = ReceiverQueryAnalysis::Values(receiver_type_outcome(
                            type_outcome.status,
                            model_values,
                        ));
                        return Ok(finalize_exact_modeled_report(report, &mut ledger));
                    }
                    let reference_site =
                        structural_reference_site(file, source, node_range(receiver));
                    let resolution = language_support_for_hook(language, "bounded_type_resolution")
                        .expect("JS/TS receiver language support")
                        .bounded_type_resolution(
                            &self.definitions,
                            language,
                            BoundedReceiverQuery {
                                analyzer: self.analyzer,
                                file,
                                source,
                                tree: Some(tree),
                                site: &reference_site,
                                budget: ledger.remaining_budget(),
                                cancellation,
                            },
                        )
                        .expect("JS/TS supports bounded type resolution");
                    let type_outcome = match charge_bounded_resolution(&mut ledger, resolution)? {
                        CompatibilityOutcome::Complete(outcome) => Some(outcome),
                        CompatibilityOutcome::Exceeded(limit) => {
                            return Ok(budget_report(operation, report.site, ledger.work(), limit));
                        }
                    };
                    if let Some(type_outcome) = type_outcome {
                        let model_values = projected_type_definitions(&type_outcome)
                            .filter(|definition| definition.is_synthetic())
                            .cloned()
                            .map(ReceiverValue::InstanceType)
                            .collect::<Vec<_>>();
                        if !model_values.is_empty() {
                            report.analysis = ReceiverQueryAnalysis::Values(receiver_type_outcome(
                                type_outcome.status,
                                model_values,
                            ));
                        } else if let SemanticReceiverGate::Available {
                            points_to,
                            evidence,
                            ..
                        } = &gate
                            && let Some(workspace) = self.workspace
                        {
                            let projection = project_receiver_values(
                                workspace,
                                points_to,
                                &type_outcome,
                                &[],
                                false,
                                cancellation,
                                &mut ledger,
                            )?;
                            let projection = match projection {
                                CompatibilityOutcome::Complete(projection) => projection,
                                CompatibilityOutcome::Exceeded(limit) => {
                                    return Ok(budget_report(
                                        operation,
                                        report.site,
                                        ledger.work(),
                                        limit,
                                    ));
                                }
                            };
                            if !projection.values.is_empty() {
                                report.analysis = ReceiverQueryAnalysis::Values(
                                    receiver_type_outcome(type_outcome.status, projection.values),
                                );
                                report.candidates_truncated |= projection.truncated;
                                if (!evidence.supports_precise()
                                    || projection.truncated
                                    || projection.multiple_identities)
                                    && !is_exact_current_receiver(&report.analysis)
                                {
                                    neutral_incomplete(&mut report.analysis);
                                }
                            }
                        }
                    }
                }
                finalize_legacy_report(self.analyzer, report, gate, &mut ledger)
            }
            ReceiverQueryOperation::MemberTargets => {
                let Some(member_expression) = provider.member_expression_at_site(input_node) else {
                    let mut report = unsupported_report(
                        operation,
                        file,
                        language,
                        range,
                        "member_target_site_unsupported",
                        Some(source),
                    );
                    report.work = ledger.work();
                    return Ok(report);
                };
                let Some(property) = member_expression.child_by_field_name("property") else {
                    let mut report = unsupported_report(
                        operation,
                        file,
                        language,
                        range,
                        "member_target_site_unsupported",
                        Some(source),
                    );
                    report.work = ledger.work();
                    return Ok(report);
                };
                let Some(receiver) = member_expression.child_by_field_name("object") else {
                    let mut report = unsupported_report(
                        operation,
                        file,
                        language,
                        range,
                        "member_target_site_unsupported",
                        Some(source),
                    );
                    report.work = ledger.work();
                    return Ok(report);
                };
                let member_name = source
                    .get(property.start_byte()..property.end_byte())
                    .unwrap_or_default();
                if member_name.is_empty() {
                    let mut report = unsupported_report(
                        operation,
                        file,
                        language,
                        range,
                        "member_target_site_unsupported",
                        Some(source),
                    );
                    report.work = ledger.work();
                    return Ok(report);
                }
                let gate_site = site(
                    file,
                    language,
                    node_range(receiver),
                    source,
                    "receiver",
                    Some(member_name.to_string()),
                );
                let gate = self.semantic_receiver_gate(
                    file,
                    node_range(receiver),
                    ledger.remaining_budget(),
                    cancellation,
                )?;
                if let Some(limit) = charge_semantic_gate(&mut ledger, &gate) {
                    return Ok(budget_report(operation, gate_site, ledger.work(), limit));
                }
                let member_report = provider
                    .resolve_member_targets_at_site(
                        input_node,
                        Some(member_name),
                        input_node.start_byte(),
                        ledger.remaining_budget(),
                    )
                    .expect("validated member expression remains supported by its provider");
                let reference_site =
                    structural_reference_site(file, source, member_report.receiver_range);
                let resolution = language_support_for_hook(language, "bounded_type_resolution")
                    .expect("JS/TS receiver language support")
                    .bounded_type_resolution(
                        &self.definitions,
                        language,
                        BoundedReceiverQuery {
                            analyzer: self.analyzer,
                            file,
                            source,
                            tree: Some(tree),
                            site: &reference_site,
                            budget: ledger.remaining_budget(),
                            cancellation,
                        },
                    )
                    .expect("JS/TS supports bounded type resolution");
                let type_outcome = match charge_bounded_resolution(&mut ledger, resolution)? {
                    CompatibilityOutcome::Complete(outcome) => outcome,
                    CompatibilityOutcome::Exceeded(limit) => {
                        return Ok(budget_report(operation, gate_site, ledger.work(), limit));
                    }
                };
                let modeled_receiver_proof = legacy_exact_modeled_receiver_proof(
                    self.analyzer,
                    &type_outcome,
                    &member_report.receiver_analysis.outcome,
                    &member_report.receiver_identity,
                );
                let site = site(
                    file,
                    language,
                    member_report.receiver_range,
                    source,
                    "receiver",
                    Some(member_report.member_name.clone()),
                );
                finalize_legacy_report(
                    self.analyzer,
                    ReceiverQueryReport {
                        operation,
                        site,
                        analysis: ReceiverQueryAnalysis::MemberTargets(
                            if let Some(receiver_proof) = modeled_receiver_proof {
                                resolved_member_targets(
                                    self.analyzer,
                                    &type_outcome,
                                    &member_report.member_name,
                                    member_report.analysis.outcome,
                                    Some(receiver_proof),
                                    ledger.remaining_budget(),
                                )
                            } else if let ReceiverAnalysisOutcome::ExceededBudget { limit } =
                                member_report.receiver_identity.outcome
                            {
                                ReceiverAnalysisOutcome::ExceededBudget { limit }
                            } else {
                                legacy_member_targets(
                                    member_report.receiver_analysis.outcome,
                                    member_report.analysis.outcome,
                                    ledger.remaining_budget(),
                                )
                            },
                        ),
                        member_range: Some(member_report.member_range),
                        work: combined_receiver_work(
                            member_report.analysis.work,
                            member_report.receiver_identity.work,
                        ),
                        candidates_truncated: member_report.analysis.candidates_truncated,
                        semantic_unsupported: None,
                        points_to: None,
                    },
                    gate,
                    &mut ledger,
                )
            }
        };
        check_cancelled(cancellation)?;
        Ok(report)
    }

    #[doc(hidden)]
    pub fn semantic_receiver_gate(
        &self,
        file: &ProjectFile,
        range: Range,
        budget: ReceiverAnalysisBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Result<SemanticReceiverGate, ReceiverQueryError> {
        let Some(workspace) = self.workspace else {
            return Ok(SemanticReceiverGate::Bypassed {
                work: ReceiverAnalysisWork::default(),
            });
        };
        let cancellation = cancellation.cloned().unwrap_or_default();
        let mut semantic = match ReceiverSemanticBridge::new(budget) {
            Ok(semantic) => semantic,
            Err(limit) => {
                return Ok(SemanticReceiverGate::Exceeded {
                    work: ReceiverAnalysisWork::default(),
                    limit,
                });
            }
        };
        let outcome = semantic
            .oracle(workspace)
            .pointees_at_source(
                file,
                range,
                &mut SemanticRequest::new(&mut semantic.budget, &cancellation),
            )
            .map_err(ReceiverQueryError::SemanticProvider)?;
        let work = semantic.work();
        let unsupported = match &outcome {
            SemanticOutcome::Unsupported { capability, .. } => Some(*capability),
            _ => None,
        };
        let evidence = outcome.available_value().map(|points_to| {
            let evidence = SemanticReceiverEvidence::from_points_to_outcome(&outcome, points_to);
            if semantic.call_context_disabled
                && points_to.object_candidates().any(|candidate| {
                    matches!(
                        candidate.value().identity(),
                        AbstractObjectIdentity::CallResult(_)
                    )
                })
            {
                SemanticReceiverEvidence::Incomplete {
                    coverage: if points_to.coverage().is_truncated() {
                        CandidateCoverage::Truncated
                    } else {
                        CandidateCoverage::Open
                    },
                    unsupported,
                    origin: SemanticReceiverIncompleteness::Local,
                }
            } else {
                evidence
            }
        });
        match outcome {
            SemanticOutcome::Cancelled { .. } => Err(ReceiverQueryError::Cancelled),
            SemanticOutcome::ExceededBudget { exceeded, .. } => {
                Ok(SemanticReceiverGate::Exceeded {
                    work,
                    limit: ReceiverSemanticBridge::receiver_limit(exceeded),
                })
            }
            outcome => match outcome.available_value() {
                Some(points_to) if !points_to.is_empty() => Ok(SemanticReceiverGate::Available {
                    work,
                    points_to: points_to.clone(),
                    evidence: evidence.expect("available semantic value has evidence quality"),
                }),
                Some(_) | None => Ok(SemanticReceiverGate::Unavailable { work, unsupported }),
            },
        }
    }

    fn modeled_call_result_type(
        &self,
        file: &ProjectFile,
        language: Language,
        range: Range,
        ledger: &mut ReceiverWorkLedger,
        cancellation: Option<&CancellationToken>,
    ) -> Result<CompatibilityOutcome<Option<TypeLookupOutcome>>, ReceiverQueryError> {
        if !matches!(language, Language::JavaScript | Language::TypeScript) {
            return Ok(CompatibilityOutcome::Complete(None));
        }
        let Some(workspace) = self.workspace else {
            return Ok(CompatibilityOutcome::Complete(None));
        };
        let Some(overlay) = self.analyzer.semantic_model_overlay() else {
            return Ok(CompatibilityOutcome::Complete(None));
        };
        let cancellation = cancellation.cloned().unwrap_or_default();
        let mut semantic = match ReceiverSemanticBridge::new(ledger.remaining_budget()) {
            Ok(semantic) => semantic,
            Err(limit) => return Ok(CompatibilityOutcome::Exceeded(limit)),
        };
        let outcome = semantic
            .oracle(workspace)
            .dispatch_at_source(
                file,
                range,
                &mut SemanticRequest::new(&mut semantic.budget, &cancellation),
            )
            .map_err(ReceiverQueryError::SemanticProvider)?;
        let aggregate_limit = ledger.charge_analysis(semantic.work()).err();
        match &outcome {
            SemanticOutcome::Cancelled { .. } => return Err(ReceiverQueryError::Cancelled),
            SemanticOutcome::ExceededBudget { exceeded, .. } => {
                return Ok(CompatibilityOutcome::Exceeded(
                    aggregate_limit
                        .unwrap_or_else(|| ReceiverSemanticBridge::receiver_limit(*exceeded)),
                ));
            }
            _ => {}
        }
        if let Some(limit) = aggregate_limit {
            return Ok(CompatibilityOutcome::Exceeded(limit));
        }
        let Some(dispatches) = outcome.available_value() else {
            return Ok(CompatibilityOutcome::Complete(None));
        };
        if dispatches.coverage().is_truncated() {
            return Ok(CompatibilityOutcome::Complete(None));
        }
        if dispatches.observations().is_empty() {
            return Ok(CompatibilityOutcome::Complete(None));
        }
        let mut exact_target = None::<(String, String, bool, u32)>;
        for observation in dispatches.observations() {
            let dispatch = observation.dispatch();
            if dispatch.coverage().is_truncated() || !dispatch.candidates().is_empty() {
                return Ok(CompatibilityOutcome::Complete(None));
            }
            let mut observation_has_target = false;
            for boundary in dispatch.boundaries() {
                let Some(target) = boundary.unmaterialized_external_target() else {
                    continue;
                };
                observation_has_target = true;
                if boundary.proven_external_receiver_shape() != Some(target.has_receiver()) {
                    return Ok(CompatibilityOutcome::Complete(None));
                }
                let target = (
                    target.owner_fqn().to_owned(),
                    target.member().to_owned(),
                    target.has_receiver(),
                    target.arity(),
                );
                match &exact_target {
                    Some(expected) if expected != &target => {
                        return Ok(CompatibilityOutcome::Complete(None));
                    }
                    None => exact_target = Some(target),
                    Some(_) => {}
                }
            }
            if !observation_has_target {
                return Ok(CompatibilityOutcome::Complete(None));
            }
        }
        let Some((owner, member, has_receiver, arity)) = exact_target else {
            return Ok(CompatibilityOutcome::Complete(None));
        };
        if let Err(limit) = charge_summary_step(ledger) {
            return Ok(CompatibilityOutcome::Exceeded(limit));
        }
        let matched = overlay.callable_for_target(SemanticModelCallableKey::new(
            language.config_label(),
            &owner,
            &member,
            has_receiver,
            arity,
        ));
        let Some(callable) = matched.unique() else {
            return Ok(CompatibilityOutcome::Complete(None));
        };
        let Some(TypeRef::Declared {
            id,
            nullable: false,
            ..
        }) = callable
            .structured_signature()
            .and_then(|signature| signature.returns.as_ref())
        else {
            return Ok(CompatibilityOutcome::Complete(None));
        };
        if let Err(limit) = charge_scope_step(ledger) {
            return Ok(CompatibilityOutcome::Exceeded(limit));
        }
        let returned = overlay.symbols_with_id(id);
        if returned.disposition != SemanticModelOverlayDisposition::Unique {
            return Ok(CompatibilityOutcome::Complete(None));
        }
        let [returned] = returned.records.as_slice() else {
            return Ok(CompatibilityOutcome::Complete(None));
        };
        if returned.owner_id.is_some()
            || returned.language != language.config_label()
            || returned.provenance.ambiguous
        {
            return Ok(CompatibilityOutcome::Complete(None));
        }
        Ok(CompatibilityOutcome::Complete(Some(TypeLookupOutcome {
            status: TypeLookupStatus::Resolved,
            reference: None,
            types: vec![semantic_model_lookup_type(file, returned)],
            diagnostics: Vec::new(),
            target_kind: TypeLookupTargetKind::ValueExpression,
        })))
    }

    #[allow(clippy::too_many_arguments)]
    fn analyze_structural(
        &self,
        operation: ReceiverQueryOperation,
        file: &ProjectFile,
        language: Language,
        resolver: &'static dyn StructuralReceiverResolver,
        range: Range,
        input: ReceiverQueryInput,
        structural_facts: Option<&Arc<FileFacts>>,
        budget: ReceiverAnalysisBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Result<ReceiverQueryReport, ReceiverQueryError> {
        let Some(workspace) = self.workspace else {
            return Ok(unsupported_report(
                operation,
                file,
                language,
                range,
                "receiver_semantic_workspace_unavailable",
                None,
            ));
        };

        let mut ledger = ReceiverWorkLedger::new(budget);
        let Some(facts) = structural_facts else {
            return Ok(unsupported_report(
                operation,
                file,
                language,
                range,
                "receiver_structural_facts_unavailable",
                None,
            ));
        };
        let prepared_matches = self
            .prepared_structural_files
            .borrow()
            .get(file)
            .is_some_and(|prepared| prepared.matches(facts));
        if !prepared_matches {
            match build_receiver_site_index(
                Arc::clone(facts),
                ReceiverSiteIndexLimit {
                    max_work_items: ledger.remaining_budget().max_scope_nodes,
                },
                cancellation,
            ) {
                ReceiverSiteIndexBuild::Complete {
                    index,
                    inspected_work,
                } => {
                    ledger
                        .charge_setup(inspected_work)
                        .expect("completed site indexing fits its supplied receiver budget");
                    check_cancelled(cancellation)?;
                    let syntax_nodes = index.source().len().div_ceil(256).max(1);
                    if ledger.charge_setup(syntax_nodes).is_err() {
                        return Ok(setup_budget_report(
                            operation,
                            file,
                            language,
                            range,
                            index.source(),
                            ledger.work(),
                        ));
                    }
                    let Some(syntax) = prepared_structural_syntax_limited(
                        self.analyzer,
                        language,
                        file,
                        index.source().len(),
                        cancellation,
                    ) else {
                        let mut report = unsupported_report(
                            operation,
                            file,
                            language,
                            range,
                            "receiver_analyzer_unavailable",
                            Some(index.source()),
                        );
                        report.work = ledger.work();
                        return Ok(report);
                    };
                    let syntax = match syntax {
                        StructuralSyntaxLimitedOutcome::Available(syntax) => {
                            let syntax = syntax.into_inner();
                            if syntax.source() == index.source() {
                                syntax
                            } else {
                                let mut report = unsupported_report(
                                    operation,
                                    file,
                                    language,
                                    range,
                                    "receiver_source_snapshot_mismatch",
                                    Some(index.source()),
                                );
                                report.work = ledger.work();
                                return Ok(report);
                            }
                        }
                        StructuralSyntaxLimitedOutcome::Exceeded { .. } => {
                            let mut report = unsupported_report(
                                operation,
                                file,
                                language,
                                range,
                                "receiver_source_snapshot_mismatch",
                                Some(index.source()),
                            );
                            report.work = ledger.work();
                            return Ok(report);
                        }
                        StructuralSyntaxLimitedOutcome::Cancelled => {
                            return Err(ReceiverQueryError::Cancelled);
                        }
                        StructuralSyntaxLimitedOutcome::Unavailable => {
                            let mut report = unsupported_report(
                                operation,
                                file,
                                language,
                                range,
                                "receiver_source_parse_failed",
                                Some(index.source()),
                            );
                            report.work = ledger.work();
                            return Ok(report);
                        }
                    };
                    check_cancelled(cancellation)?;
                    self.prepared_structural_files.borrow_mut().insert(
                        file.clone(),
                        PreparedStructuralReceiverFile {
                            facts: Arc::clone(facts),
                            sites: index,
                            syntax,
                        },
                    );
                }
                ReceiverSiteIndexBuild::Exceeded { inspected_work } => {
                    let _ = ledger.charge_setup(inspected_work);
                    return Ok(setup_budget_report(
                        operation,
                        file,
                        language,
                        range,
                        facts.source(),
                        ledger.work(),
                    ));
                }
                ReceiverSiteIndexBuild::Cancelled { inspected_work } => {
                    let _ = ledger.charge_setup(inspected_work);
                    return Err(ReceiverQueryError::Cancelled);
                }
            }
        }

        let prepared_files = self.prepared_structural_files.borrow();
        let prepared = prepared_files
            .get(file)
            .expect("structural receiver sites were prepared above");
        debug_assert!(prepared.matches(facts));
        let source = prepared.sites.source();
        let selection_mode = match (operation, input) {
            (ReceiverQueryOperation::MemberTargets, ReceiverQueryInput::Expression) => {
                resolver.member_target_input_mode()
            }
            (_, ReceiverQueryInput::ContainingSite) => ReceiverSiteInputMode::ContainingSite,
            (_, ReceiverQueryInput::Expression) => ReceiverSiteInputMode::Expression,
        };
        let selected = match prepared.sites.select_bounded(
            range,
            selection_mode,
            ReceiverSiteSelectionLimit {
                max_inspected_sites: ledger.remaining_budget().max_scope_nodes,
            },
            cancellation,
        ) {
            ReceiverSiteSelection::Complete {
                site,
                inspected_sites,
            } => {
                ledger
                    .charge_setup(inspected_sites)
                    .expect("completed site selection fits its supplied receiver budget");
                site
            }
            ReceiverSiteSelection::Exceeded { inspected_sites } => {
                let _ = ledger.charge_setup(inspected_sites);
                return Ok(setup_budget_report(
                    operation,
                    file,
                    language,
                    range,
                    source,
                    ledger.work(),
                ));
            }
            ReceiverSiteSelection::Cancelled { inspected_sites } => {
                let _ = ledger.charge_setup(inspected_sites);
                return Err(ReceiverQueryError::Cancelled);
            }
        };
        let query_range = match (operation, input, selected) {
            (ReceiverQueryOperation::MemberTargets, _, Some(site))
            | (_, ReceiverQueryInput::ContainingSite, Some(site)) => site.receiver_range,
            (ReceiverQueryOperation::MemberTargets, _, None)
            | (_, ReceiverQueryInput::ContainingSite, None) => {
                let mut report = unsupported_report(
                    operation,
                    file,
                    language,
                    range,
                    "receiver_site_without_receiver",
                    Some(source),
                );
                report.work = ledger.work();
                return Ok(report);
            }
            (_, ReceiverQueryInput::Expression, _) => range,
        };
        let member_range = (operation == ReceiverQueryOperation::MemberTargets)
            .then(|| selected.and_then(|site| site.member_range))
            .flatten();
        if operation == ReceiverQueryOperation::MemberTargets && member_range.is_none() {
            let mut report = unsupported_report(
                operation,
                file,
                language,
                range,
                "member_target_site_unsupported",
                Some(source),
            );
            report.work = ledger.work();
            return Ok(report);
        }
        let syntax_kind = selected.map_or("expression", |site| match site.kind {
            ReceiverSiteKind::Call => "call",
            ReceiverSiteKind::FieldAccess => "field_access",
        });
        let member_name = member_range.and_then(|member| {
            receiver_member_name(language, prepared.syntax.tree(), source, member)
        });
        let report_site = site(
            file,
            language,
            query_range,
            source,
            syntax_kind,
            member_name,
        );

        let fallback_cancellation = CancellationToken::default();
        let cancellation = cancellation.unwrap_or(&fallback_cancellation);
        check_cancelled(Some(cancellation))?;
        if let Err(limit) = charge_scope_step(&mut ledger) {
            return Ok(budget_report(operation, report_site, ledger.work(), limit));
        }

        let reference_site = structural_reference_site(file, source, query_range);
        let resolution = self.structural_type_resolution(
            language,
            resolver,
            BoundedReceiverQuery {
                analyzer: self.analyzer,
                file,
                source,
                tree: Some(prepared.syntax.tree()),
                site: &reference_site,
                budget: ledger.remaining_budget(),
                cancellation: Some(cancellation),
            },
        );
        let type_outcome = match charge_bounded_resolution(&mut ledger, resolution)? {
            CompatibilityOutcome::Complete(outcome) => outcome,
            CompatibilityOutcome::Exceeded(limit) => {
                return Ok(budget_report(operation, report_site, ledger.work(), limit));
            }
        };
        if let Some(reason) = structural_receiver_unsupported_reason(language, &type_outcome) {
            let mut report = unknown_report(operation, report_site, ledger.work(), false);
            neutral_unsupported(&mut report.analysis, reason);
            return Ok(report);
        }
        let static_type_reference = type_outcome.target_kind == TypeLookupTargetKind::TypeReference;
        let static_type_resolved = type_outcome.status == TypeLookupStatus::Resolved;

        if operation != ReceiverQueryOperation::MemberTargets && static_type_reference {
            let projection = match project_static_receiver_values(
                &type_outcome,
                Some(cancellation),
                &mut ledger,
            )? {
                CompatibilityOutcome::Complete(projection) => projection,
                CompatibilityOutcome::Exceeded(limit) => {
                    return Ok(budget_report(operation, report_site, ledger.work(), limit));
                }
            };
            let mut analysis = ReceiverQueryAnalysis::Values(receiver_type_outcome(
                type_outcome.status,
                projection.values,
            ));
            if projection.truncated {
                neutral_incomplete(&mut analysis);
            }
            return Ok(ReceiverQueryReport {
                operation,
                site: report_site,
                analysis,
                member_range: None,
                work: ledger.work(),
                candidates_truncated: projection.truncated,
                semantic_unsupported: None,
                points_to: None,
            });
        }

        let semantic = (!static_type_reference)
            .then(|| {
                self.semantic_receiver_gate(
                    file,
                    query_range,
                    ledger.remaining_budget(),
                    Some(cancellation),
                )
            })
            .transpose()?;
        if let Some(semantic) = &semantic
            && let Some(limit) = charge_semantic_gate(&mut ledger, semantic)
        {
            return Ok(budget_report(operation, report_site, ledger.work(), limit));
        }
        let (points_to, evidence) = match semantic {
            None => (None, SemanticReceiverEvidence::ExhaustiveComplete),
            Some(SemanticReceiverGate::Available {
                points_to,
                evidence,
                ..
            }) => (Some(points_to), evidence),
            Some(SemanticReceiverGate::Bypassed { .. }) => {
                return Ok(unknown_report(operation, report_site, ledger.work(), false));
            }
            Some(SemanticReceiverGate::Unavailable { unsupported, .. }) => {
                let mut report = unknown_report(operation, report_site, ledger.work(), false);
                if let Some(capability) = unsupported {
                    neutral_unsupported(&mut report.analysis, capability.label());
                }
                return Ok(report);
            }
            Some(SemanticReceiverGate::Exceeded { .. }) => {
                unreachable!("semantic gate budget exits before compatibility analysis")
            }
        };

        if operation == ReceiverQueryOperation::MemberTargets {
            let member_range = member_range.expect("member target range was validated above");
            let reference_site = structural_reference_site(file, source, member_range);
            let resolution = self.structural_definition_resolution(
                language,
                resolver,
                BoundedReceiverQuery {
                    analyzer: self.analyzer,
                    file,
                    source,
                    tree: Some(prepared.syntax.tree()),
                    site: &reference_site,
                    budget: ledger.remaining_budget(),
                    cancellation: Some(cancellation),
                },
            );
            let outcome = match charge_bounded_resolution(&mut ledger, resolution)? {
                CompatibilityOutcome::Complete(outcome) => outcome,
                CompatibilityOutcome::Exceeded(limit) => {
                    return Ok(budget_report(operation, report_site, ledger.work(), limit));
                }
            };
            let (workspace_outcome, resolution_truncated) =
                definition_outcome(outcome, ledger.remaining_budget().max_targets);
            let receiver_proof = if static_type_reference {
                Some(ReceiverIdentityProof::ExactStaticTypeReference)
            } else if evidence.supports_precise() {
                Some(ReceiverIdentityProof::ExactValueAnalysis)
            } else {
                None
            };
            let outcome = resolved_member_targets(
                self.analyzer,
                &type_outcome,
                report_site
                    .member_name
                    .as_deref()
                    .expect("member target site has a static member name"),
                workspace_outcome,
                receiver_proof,
                ledger.remaining_budget(),
            );
            let mut analysis = ReceiverQueryAnalysis::MemberTargets(outcome);
            let statically_bound_data_member =
                structural_member_is_statically_bound_data_member(language, &analysis);
            let evidence_supports_precision = evidence.supports_precise();
            let mut dispatch_supports_precise = statically_bound_data_member;
            if !statically_bound_data_member
                && analysis_is_precise(&analysis)
                && evidence.supports_precise()
                && !resolution_truncated
                && (!static_type_reference || static_type_resolved)
            {
                dispatch_supports_precise = match structural_member_dispatch_supports_precise(
                    self.analyzer,
                    language,
                    &analysis,
                    Some(cancellation),
                    &mut ledger,
                )? {
                    CompatibilityOutcome::Complete(supports_precise) => supports_precise,
                    CompatibilityOutcome::Exceeded(limit) => {
                        return Ok(budget_report(operation, report_site, ledger.work(), limit));
                    }
                };
            }
            if !evidence_supports_precision
                || resolution_truncated
                || !dispatch_supports_precise
                || (static_type_reference && !static_type_resolved)
            {
                neutral_incomplete(&mut analysis);
            }
            return Ok(ReceiverQueryReport {
                operation,
                site: report_site,
                analysis,
                member_range: Some(member_range),
                work: ledger.work(),
                candidates_truncated: evidence.is_truncated() || resolution_truncated,
                semantic_unsupported: evidence.unsupported_capability(),
                points_to: None,
            });
        }

        let points_to = points_to
            .expect("non-static structural receiver analysis requires neutral points-to evidence");
        let query_node = match java_smallest_named_node_covering(
            prepared.syntax.tree().root_node(),
            query_range.start_byte,
            query_range.end_byte,
            Some(cancellation),
            &mut ledger,
        )? {
            CompatibilityOutcome::Complete(node) => node,
            CompatibilityOutcome::Exceeded(limit) => {
                return Ok(budget_report(operation, report_site, ledger.work(), limit));
            }
        };
        let factories = if points_to_contains_call_result(&points_to, Some(cancellation))?
            && let Some(factory_node) =
                query_node.and_then(|node| structural_factory_name_node(language, node))
        {
            let factory_site = structural_reference_site(file, source, node_range(factory_node));
            let resolution = self.structural_definition_resolution(
                language,
                resolver,
                BoundedReceiverQuery {
                    analyzer: self.analyzer,
                    file,
                    source,
                    tree: Some(prepared.syntax.tree()),
                    site: &factory_site,
                    budget: ledger.remaining_budget(),
                    cancellation: Some(cancellation),
                },
            );
            match charge_bounded_resolution(&mut ledger, resolution)? {
                CompatibilityOutcome::Complete(outcome)
                    if outcome.status == DefinitionLookupStatus::Resolved
                        && !outcome.definitions.is_empty()
                        && outcome.definitions.iter().all(|definition| {
                            if language == Language::Cpp {
                                definition.is_callable()
                            } else {
                                definition.is_function()
                            }
                        })
                        && (language == Language::Cpp || outcome.definitions.len() == 1) =>
                {
                    outcome.definitions
                }
                CompatibilityOutcome::Complete(_) => Vec::new(),
                CompatibilityOutcome::Exceeded(limit) => {
                    return Ok(budget_report(operation, report_site, ledger.work(), limit));
                }
            }
        } else {
            Vec::new()
        };
        let values = project_receiver_values(
            workspace,
            &points_to,
            &type_outcome,
            &factories,
            false,
            Some(cancellation),
            &mut ledger,
        )?;
        let projection = match values {
            CompatibilityOutcome::Complete(projection) => projection,
            CompatibilityOutcome::Exceeded(limit) => {
                return Ok(budget_report(operation, report_site, ledger.work(), limit));
            }
        };
        let mut analysis = ReceiverQueryAnalysis::Values(receiver_type_outcome(
            type_outcome.status,
            projection.values,
        ));
        if (!evidence.supports_precise() || projection.truncated || projection.multiple_identities)
            && !is_exact_current_receiver(&analysis)
        {
            neutral_incomplete(&mut analysis);
        }
        Ok(ReceiverQueryReport {
            operation,
            site: report_site,
            analysis,
            member_range: None,
            work: ledger.work(),
            candidates_truncated: evidence.is_truncated() || projection.truncated,
            semantic_unsupported: evidence.unsupported_capability(),
            points_to: if operation == ReceiverQueryOperation::PointsTo {
                Some(points_to.clone())
            } else {
                None
            },
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn prepared_file_count(&self) -> usize {
        self.prepared_files.borrow().len()
            + self.prepared_java_files.borrow().len()
            + self.prepared_structural_files.borrow().len()
    }
}

#[doc(hidden)]
pub fn charge_semantic_gate(
    ledger: &mut ReceiverWorkLedger,
    gate: &SemanticReceiverGate,
) -> Option<ReceiverBudgetLimit> {
    ledger
        .charge_analysis(gate.work())
        .err()
        .or_else(|| gate.exceeded_limit())
}

fn analysis_is_precise(analysis: &ReceiverQueryAnalysis) -> bool {
    match analysis {
        ReceiverQueryAnalysis::Values(outcome) => outcome.is_precise(),
        ReceiverQueryAnalysis::MemberTargets(outcome) => outcome.is_precise(),
    }
}

fn prepared_structural_syntax_limited(
    analyzer: &dyn IAnalyzer,
    language: Language,
    file: &ProjectFile,
    max_source_bytes: usize,
    cancellation: Option<&CancellationToken>,
) -> Option<StructuralSyntaxLimitedOutcome> {
    analyzer
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == language)
        .map(|provider| provider.structural_syntax_limited(file, max_source_bytes, cancellation))
}

fn structural_receiver_unsupported_reason(
    language: Language,
    outcome: &TypeLookupOutcome,
) -> Option<&'static str> {
    match language {
        Language::Cpp
            if outcome
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == "cpp_c_receiver_unsupported") =>
        {
            Some("cpp_c_receiver_unsupported")
        }
        Language::CSharp
            if outcome
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == "csharp_dynamic_receiver_unsupported") =>
        {
            Some("csharp_dynamic_receiver_unsupported")
        }
        _ => None,
    }
}

#[doc(hidden)]
pub fn structural_member_dispatch_supports_precise(
    analyzer: &dyn IAnalyzer,
    language: Language,
    analysis: &ReceiverQueryAnalysis,
    cancellation: Option<&CancellationToken>,
    ledger: &mut ReceiverWorkLedger,
) -> Result<CompatibilityOutcome<bool>, ReceiverQueryError> {
    let ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Precise(targets)) = analysis
    else {
        return Ok(CompatibilityOutcome::Complete(false));
    };
    let [target] = targets.as_slice() else {
        return Ok(CompatibilityOutcome::Complete(false));
    };
    if matches!(target, ReceiverMemberTarget::SemanticModel { .. }) {
        return Ok(CompatibilityOutcome::Complete(true));
    }
    let target = target
        .workspace_member()
        .expect("non-modeled member target has a workspace declaration");
    check_cancelled(cancellation)?;
    if structural_member_is_statically_bound_data_member(language, analysis) {
        return Ok(CompatibilityOutcome::Complete(true));
    }
    if let Err(limit) = charge_summary_step(ledger) {
        return Ok(CompatibilityOutcome::Exceeded(limit));
    }
    if let Err(limit) = charge_scope_step(ledger) {
        return Ok(CompatibilityOutcome::Exceeded(limit));
    }
    let provider_limit = ledger.remaining_budget().max_scope_nodes.saturating_add(1);
    let metadata = language_support_for_hook(language, "signature_metadata_limited")
        .and_then(|support| support.signature_metadata_limited(analyzer, target, provider_limit));
    let Some(metadata) = metadata else {
        return Ok(CompatibilityOutcome::Exceeded(
            ReceiverBudgetLimit::ScopeNodes,
        ));
    };
    let metadata = match charge_limited_projection(metadata, cancellation, ledger)? {
        CompatibilityOutcome::Complete(metadata) => metadata,
        CompatibilityOutcome::Exceeded(limit) => {
            return Ok(CompatibilityOutcome::Exceeded(limit));
        }
    };
    if metadata.is_empty() {
        return Ok(CompatibilityOutcome::Complete(false));
    }
    Ok(CompatibilityOutcome::Complete(metadata.iter().all(
        |metadata| metadata.dispatch_extensibility() == Some(DispatchExtensibility::Closed),
    )))
}

fn structural_member_is_statically_bound_data_member(
    language: Language,
    analysis: &ReceiverQueryAnalysis,
) -> bool {
    let ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Precise(targets)) = analysis
    else {
        return false;
    };
    matches!(
        targets.as_slice(),
        [ReceiverMemberTarget::SemanticModel { member, .. }]
            if matches!(
                member.kind,
                SemanticModelSymbolKind::Field | SemanticModelSymbolKind::Property
            )
                && !member.provenance.ambiguous
                && member.provenance.completeness
                    == crate::analyzer::semantic_model::SemanticModelCompleteness::Complete
    ) || (matches!(language, Language::Cpp | Language::Go)
        && matches!(
            targets.as_slice(),
            [ReceiverMemberTarget::Workspace { member, .. }] if member.is_field()
        ))
}

fn finalize_legacy_report(
    analyzer: &dyn IAnalyzer,
    report: ReceiverQueryReport,
    gate: SemanticReceiverGate,
    ledger: &mut ReceiverWorkLedger,
) -> ReceiverQueryReport {
    let compatibility_limit = ledger.charge_analysis(report.work).err();
    let mut report = apply_semantic_gate(analyzer, report, gate);
    if let Some(limit) = compatibility_limit {
        neutral_exceeded(&mut report.analysis, limit);
    }
    report.work = ledger.work();
    report
}

/// Finish a JS/TS call-result projection whose exact dispatch boundary and
/// declared model return already supplied the receiver proof. The neutral
/// points-to gate cannot improve that external type identity because the
/// callee body is unmaterialized, so applying it would turn the independent
/// exact proof back into the pre-#2862 unknown result.
fn finalize_exact_modeled_report(
    mut report: ReceiverQueryReport,
    ledger: &mut ReceiverWorkLedger,
) -> ReceiverQueryReport {
    if let Err(limit) = ledger.charge_analysis(report.work) {
        neutral_exceeded(&mut report.analysis, limit);
    }
    report.work = ledger.work();
    report
}

fn apply_semantic_gate(
    analyzer: &dyn IAnalyzer,
    mut report: ReceiverQueryReport,
    gate: SemanticReceiverGate,
) -> ReceiverQueryReport {
    match gate {
        SemanticReceiverGate::Bypassed { .. } => {}
        SemanticReceiverGate::Available {
            points_to,
            evidence,
            ..
        } => {
            if report.operation == ReceiverQueryOperation::PointsTo {
                report.points_to = Some(points_to.clone());
            }
            // The neutral gate can only confirm a value it materialized
            // itself. An exact modeled external identity is proven by the
            // declaration the overlay owns (for example a DOM `Element`
            // declared by an activated standard-library pack), and the
            // neutral lowerer holds no heap row for the external type, so
            // retaining only neutral-backed candidates would drop the one
            // identity the query has. This is the retention half of the same
            // exemption the downgrade below already applies.
            let exact_modeled_identity =
                legacy_external_model_identity_is_precise(analyzer, &report.analysis);
            let exact_current_receiver = is_exact_current_receiver(&report.analysis);
            let removed = !exact_modeled_identity
                && retain_neutral_backed_values(&mut report.analysis, &points_to);
            report.candidates_truncated |= removed;
            report.candidates_truncated |= evidence.is_truncated();
            report.semantic_unsupported = evidence.unsupported_capability();
            // A single proven receiver port confirms the legacy current-self
            // category even when caller enumeration remains open. This is a
            // symbolic receiver classification, not a claim about its concrete
            // allocation at every call site.
            if !evidence.supports_precise()
                && !evidence.legacy_provider_can_close()
                && !exact_modeled_identity
                && !exact_current_receiver
            {
                neutral_incomplete(&mut report.analysis);
            }
        }
        SemanticReceiverGate::Unavailable { unsupported, .. } => {
            if legacy_external_module_identity_is_precise(&report.analysis)
                || legacy_external_model_identity_is_precise(analyzer, &report.analysis)
                || legacy_external_import_ambiguity(&report.analysis)
            {
                // Static import syntax independently proves either one package
                // module object or an explicit competing/truncated boundary,
                // even when neutral value-flow has no external-value row.
                // Member/type claims still require a declaration or model.
            } else if let Some(capability) = unsupported {
                neutral_unsupported(&mut report.analysis, capability.label());
            } else {
                neutral_unknown(&mut report.analysis);
            }
        }
        SemanticReceiverGate::Exceeded { limit, .. } => {
            neutral_exceeded(&mut report.analysis, limit);
        }
    }
    report
}

#[doc(hidden)]
pub fn is_exact_current_receiver(analysis: &ReceiverQueryAnalysis) -> bool {
    matches!(
        analysis,
        ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Precise(values))
            if matches!(values.as_slice(), [ReceiverValue::CurrentReceiver(_)])
    )
}

fn legacy_external_import_ambiguity(analysis: &ReceiverQueryAnalysis) -> bool {
    matches!(
        analysis,
        ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Ambiguous(values))
            if values.is_empty()
    )
}

fn legacy_external_model_identity_is_precise(
    analyzer: &dyn IAnalyzer,
    analysis: &ReceiverQueryAnalysis,
) -> bool {
    if let ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Precise(targets)) =
        analysis
    {
        return matches!(
            targets.as_slice(),
            [ReceiverMemberTarget::SemanticModel {
                receiver, member, ..
            }]
                if !receiver.provenance.ambiguous
                    && receiver.provenance.completeness
                        == crate::analyzer::semantic_model::SemanticModelCompleteness::Complete
                    && !member.provenance.ambiguous
                    && member.provenance.completeness
                        == crate::analyzer::semantic_model::SemanticModelCompleteness::Complete
                    && matches!(
                        member.kind,
                        SemanticModelSymbolKind::Field | SemanticModelSymbolKind::Property
                    )
        );
    }
    let ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Precise(values)) = analysis else {
        return false;
    };
    let Some(overlay) = analyzer.semantic_model_overlay() else {
        return false;
    };
    !values.is_empty()
        && values.iter().all(|value| {
            let ReceiverValue::InstanceType(unit) = value else {
                return false;
            };
            if !unit.is_synthetic() {
                return false;
            }
            let fq_name = unit.fq_name();
            let matched = overlay.symbols_named(&fq_name);
            matched.disposition
                == crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
                && matched.records[0].qualified_name == fq_name
                && !matched.records[0].provenance.ambiguous
                && matched.records[0].provenance.completeness
                    == crate::analyzer::semantic_model::SemanticModelCompleteness::Complete
        })
}

fn legacy_exact_modeled_receiver_proof(
    analyzer: &dyn IAnalyzer,
    type_outcome: &TypeLookupOutcome,
    receiver_outcome: &ReceiverAnalysisOutcome<ReceiverValue>,
    receiver_identity: &ReceiverAnalysisReport<ReceiverIdentityProof>,
) -> Option<ReceiverIdentityProof> {
    if type_outcome.status != TypeLookupStatus::Resolved {
        return None;
    }
    let [ty] = type_outcome.types.as_slice() else {
        return None;
    };
    let model_id = ty.semantic_model_id.as_deref()?;
    let overlay = analyzer.semantic_model_overlay()?;
    let owners = overlay.symbols_with_id(model_id);
    let [owner] = owners.records.as_slice() else {
        return None;
    };
    if owner.provenance.ambiguous
        || owner.provenance.completeness
            != crate::analyzer::semantic_model::SemanticModelCompleteness::Complete
    {
        return None;
    }
    if receiver_identity.candidates_truncated {
        return None;
    }
    let ReceiverAnalysisOutcome::Precise(proofs) = &receiver_identity.outcome else {
        return None;
    };
    let [proof] = proofs.as_slice() else {
        return None;
    };
    match proof {
        ReceiverIdentityProof::ExactValueAnalysis
            if !matches!(
                receiver_outcome,
                ReceiverAnalysisOutcome::Precise(values)
                    if matches!(values.as_slice(), [value]
                        if value.owner().is_synthetic()
                            && value.owner().fq_name() == owner.qualified_name)
            ) =>
        {
            None
        }
        ReceiverIdentityProof::ExactValueAnalysis
        | ReceiverIdentityProof::ExactStaticTypeReference
        | ReceiverIdentityProof::ImmutableBinding { .. } => Some(proof.clone()),
    }
}

fn legacy_external_module_identity_is_precise(analysis: &ReceiverQueryAnalysis) -> bool {
    matches!(
        analysis,
        ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Precise(values))
            if !values.is_empty()
                && values.iter().all(|value| matches!(
                    value,
                    ReceiverValue::ModuleOrExportObject(unit) if unit.is_synthetic()
                ))
    )
}

fn retain_neutral_backed_values(
    analysis: &mut ReceiverQueryAnalysis,
    points_to: &SourcePointsToResult,
) -> bool {
    // An explicit competing or truncated import boundary states its claim in
    // the outcome itself and carries no candidate list, so the neutral heap has
    // nothing to back and nothing to drop. Without this guard the empty list
    // falls through to the `values.is_empty()` arm below and the proven
    // boundary is rewritten as `Unknown`. This is the available-gate half of
    // the exemption `apply_semantic_gate` already applies when the gate is
    // unavailable.
    if legacy_external_import_ambiguity(analysis) {
        return false;
    }
    let ReceiverQueryAnalysis::Values(outcome) = analysis else {
        return false;
    };
    let previous = std::mem::replace(outcome, ReceiverAnalysisOutcome::Unknown);
    let (mut values, was_precise) = match previous {
        ReceiverAnalysisOutcome::Precise(values) => (values, true),
        ReceiverAnalysisOutcome::Ambiguous(values) => (values, false),
        terminal => {
            *outcome = terminal;
            return false;
        }
    };
    let original_len = values.len();
    values.retain(|value| {
        points_to
            .object_candidates()
            .any(|candidate| neutral_object_supports_receiver(candidate.value().identity(), value))
    });
    let removed = values.len() != original_len;
    *outcome = if values.is_empty() {
        ReceiverAnalysisOutcome::Unknown
    } else if was_precise && !removed {
        ReceiverAnalysisOutcome::Precise(values)
    } else {
        ReceiverAnalysisOutcome::Ambiguous(values)
    };
    removed
}

fn neutral_object_supports_receiver(
    identity: &AbstractObjectIdentity,
    value: &ReceiverValue,
) -> bool {
    if let ReceiverValue::FactoryReturn { value, .. } = value {
        return neutral_object_supports_receiver(identity, value);
    }
    match (identity, value) {
        (
            AbstractObjectIdentity::Allocation(allocation),
            ReceiverValue::AllocationSite { file, range, .. },
        ) => {
            let Some(row) = allocation
                .procedure()
                .semantics()
                .allocation(allocation.id())
            else {
                return false;
            };
            let Some(mapping) = allocation
                .procedure()
                .semantics()
                .source_mapping(row.source)
            else {
                return false;
            };
            let span = mapping.locator.anchor().span();
            allocation.procedure().artifact().key().path().as_path() == file.rel_path()
                && span.start_byte() as usize == range.start_byte
                && span.end_byte() as usize == range.end_byte
        }
        (AbstractObjectIdentity::ProcedurePort(port), ReceiverValue::CurrentReceiver(_)) => {
            port.kind() == crate::analyzer::semantic::ProcedurePortKind::Receiver
        }
        (AbstractObjectIdentity::ProcedurePort(port), ReceiverValue::InstanceType(_)) => matches!(
            port.kind(),
            crate::analyzer::semantic::ProcedurePortKind::Parameter { .. }
        ),
        (AbstractObjectIdentity::Static(_), ReceiverValue::ClassOrStaticObject(_))
        | (AbstractObjectIdentity::ModuleObject(_), ReceiverValue::ModuleOrExportObject(_)) => true,
        // Symbolic roots deliberately carry no nominal compatibility label.
        // The structured projector decorates that same neutral root as an
        // instance, allocation, static object, or module for the stable DTO.
        (
            AbstractObjectIdentity::Value(_)
            | AbstractObjectIdentity::CallResult(_)
            | AbstractObjectIdentity::LexicalCell(_)
            | AbstractObjectIdentity::CaptureSlot(_)
            | AbstractObjectIdentity::TypeSummary(_)
            | AbstractObjectIdentity::External(_)
            | AbstractObjectIdentity::RuntimeObject(_)
            | AbstractObjectIdentity::CallSubstitution { .. },
            _,
        ) => true,
        _ => false,
    }
}

fn neutral_unknown(analysis: &mut ReceiverQueryAnalysis) {
    match analysis {
        ReceiverQueryAnalysis::Values(outcome) => replace_with_neutral_unknown(outcome),
        ReceiverQueryAnalysis::MemberTargets(outcome) => replace_with_neutral_unknown(outcome),
    }
}

#[doc(hidden)]
pub fn neutral_incomplete(analysis: &mut ReceiverQueryAnalysis) {
    match analysis {
        ReceiverQueryAnalysis::Values(outcome) => downgrade_precise(outcome),
        ReceiverQueryAnalysis::MemberTargets(outcome) => downgrade_precise(outcome),
    }
}

#[doc(hidden)]
pub fn neutral_unsupported(analysis: &mut ReceiverQueryAnalysis, reason: &'static str) {
    match analysis {
        ReceiverQueryAnalysis::Values(outcome) => {
            *outcome = ReceiverAnalysisOutcome::Unsupported { reason };
        }
        ReceiverQueryAnalysis::MemberTargets(outcome) => {
            *outcome = ReceiverAnalysisOutcome::Unsupported { reason };
        }
    }
}

#[doc(hidden)]
pub fn downgrade_precise<T>(outcome: &mut ReceiverAnalysisOutcome<T>) {
    let ReceiverAnalysisOutcome::Precise(_) = outcome else {
        return;
    };
    let previous = std::mem::replace(outcome, ReceiverAnalysisOutcome::Unknown);
    if let ReceiverAnalysisOutcome::Precise(values) = previous
        && !values.is_empty()
    {
        *outcome = ReceiverAnalysisOutcome::Ambiguous(values);
    }
}

fn replace_with_neutral_unknown<T>(outcome: &mut ReceiverAnalysisOutcome<T>) {
    if !matches!(
        outcome,
        ReceiverAnalysisOutcome::Unsupported { .. }
            | ReceiverAnalysisOutcome::ExceededBudget { .. }
    ) {
        *outcome = ReceiverAnalysisOutcome::Unknown;
    }
}

fn neutral_exceeded(analysis: &mut ReceiverQueryAnalysis, limit: ReceiverBudgetLimit) {
    match analysis {
        ReceiverQueryAnalysis::Values(outcome) => replace_with_neutral_exceeded(outcome, limit),
        ReceiverQueryAnalysis::MemberTargets(outcome) => {
            replace_with_neutral_exceeded(outcome, limit)
        }
    }
}

fn replace_with_neutral_exceeded<T>(
    outcome: &mut ReceiverAnalysisOutcome<T>,
    limit: ReceiverBudgetLimit,
) {
    if !matches!(outcome, ReceiverAnalysisOutcome::Unsupported { .. }) {
        *outcome = ReceiverAnalysisOutcome::ExceededBudget {
            limit: limit.as_str(),
        };
    }
}

#[derive(Debug)]
#[doc(hidden)]
pub struct ReceiverSemanticBridge {
    #[doc(hidden)]
    pub budget: SemanticBudget,
    oracle_limits: OracleLimits,
    call_context_disabled: bool,
}

impl ReceiverSemanticBridge {
    #[doc(hidden)]
    pub const SCOPE_DIMENSIONS: usize = 11;
    #[doc(hidden)]
    pub const SUMMARY_DIMENSIONS: usize = 3;

    #[doc(hidden)]
    pub fn new(receiver: ReceiverAnalysisBudget) -> Result<Self, ReceiverBudgetLimit> {
        if receiver.max_scope_nodes < Self::SCOPE_DIMENSIONS {
            return Err(ReceiverBudgetLimit::ScopeNodes);
        }
        if receiver.max_summary_expansions < Self::SUMMARY_DIMENSIONS {
            return Err(ReceiverBudgetLimit::SummaryExpansions);
        }

        let scope = receiver.max_scope_nodes;
        let summaries = receiver.max_summary_expansions;
        let targets = receiver.max_targets.max(1);
        // Oracle limits are positive by contract. Preserve the caller's zero
        // context request separately so any retained call-result candidate is
        // downgraded even though the representational minimum is one frame.
        let context = receiver.context_depth.max(1);
        let text = scope.saturating_mul(1_024).max(1);
        // Publishing each retained points-to candidate consumes one nested
        // entry after graph traversal succeeds. Reserve that bounded tail so
        // an otherwise complete receiver query cannot fail while serializing
        // its final candidate set.
        let publication_reserve = targets.min(scope - Self::SCOPE_DIMENSIONS);
        let [
            procedures,
            blocks,
            program_points,
            values,
            allocations,
            source_mappings,
            evidence,
            gaps,
            events,
            control_edges,
            mut nested_entries,
        ] = partition_receiver_scope_limit(scope - publication_reserve);
        nested_entries += publication_reserve;
        // Each lane gets the full bound so an internal partition cannot starve
        // one kind of summary; the shared ledger below still enforces the
        // unchanged public aggregate summary-expansion cap.
        let budget = SemanticBudget::new(SemanticWork {
            source_bytes: text,
            procedures,
            blocks,
            program_points,
            values,
            allocations,
            call_sites: summaries,
            memory_locations: summaries,
            captures: summaries,
            source_mappings,
            evidence,
            gaps,
            events,
            control_edges,
            nested_entries,
            owned_text_bytes: text,
        })
        .expect("receiver semantic budget is positive")
        .with_shared_summary_expansion_limit(summaries);

        let defaults = OracleLimits::default().values();
        let oracle_limits = OracleLimits::new(OracleLimitValues {
            dispatch_targets: targets,
            objects_per_value: targets,
            alias_breadth: targets,
            source_observations: targets,
            call_context_depth: context,
            summary_depth: summaries,
            call_binding_entries: summaries,
            ..defaults
        })
        .expect("receiver oracle limits are positive");
        Ok(Self {
            budget,
            oracle_limits,
            call_context_disabled: receiver.context_depth == 0,
        })
    }

    #[doc(hidden)]
    pub fn oracle<'workspace>(
        &self,
        workspace: &'workspace WorkspaceAnalyzer,
    ) -> WorkspaceSemanticOracle<'workspace> {
        WorkspaceSemanticOracle::with_limits(workspace, self.oracle_limits)
    }

    #[doc(hidden)]
    pub fn work(&self) -> ReceiverAnalysisWork {
        Self::receiver_work(self.budget.used())
    }

    fn receiver_work(work: SemanticWork) -> ReceiverAnalysisWork {
        ReceiverAnalysisWork {
            setup_nodes: 0,
            resolution_rounds: 0,
            summary_expansions: work
                .call_sites
                .saturating_add(work.memory_locations)
                .saturating_add(work.captures),
            scope_nodes: work
                .procedures
                .saturating_add(work.blocks)
                .saturating_add(work.program_points)
                .saturating_add(work.values)
                .saturating_add(work.allocations)
                .saturating_add(work.source_mappings)
                .saturating_add(work.evidence)
                .saturating_add(work.gaps)
                .saturating_add(work.events)
                .saturating_add(work.control_edges)
                .saturating_add(work.nested_entries),
        }
    }

    fn receiver_limit(exceeded: SemanticBudgetExceeded) -> ReceiverBudgetLimit {
        match exceeded.dimension() {
            SemanticBudgetDimension::CallSites
            | SemanticBudgetDimension::MemoryLocations
            | SemanticBudgetDimension::Captures => ReceiverBudgetLimit::SummaryExpansions,
            SemanticBudgetDimension::SourceBytes
            | SemanticBudgetDimension::Procedures
            | SemanticBudgetDimension::Blocks
            | SemanticBudgetDimension::ProgramPoints
            | SemanticBudgetDimension::Values
            | SemanticBudgetDimension::Allocations
            | SemanticBudgetDimension::SourceMappings
            | SemanticBudgetDimension::Evidence
            | SemanticBudgetDimension::Gaps
            | SemanticBudgetDimension::Events
            | SemanticBudgetDimension::ControlEdges
            | SemanticBudgetDimension::NestedEntries
            | SemanticBudgetDimension::OwnedTextBytes => ReceiverBudgetLimit::ScopeNodes,
        }
    }
}

fn partition_receiver_scope_limit(total: usize) -> [usize; 11] {
    const DIMENSIONS: usize = ReceiverSemanticBridge::SCOPE_DIMENSIONS;
    const NESTED_ENTRIES_INDEX: usize = DIMENSIONS - 1;
    debug_assert!(total >= DIMENSIONS);

    // Semantic materialization charges syntax traversal and nested collection
    // publication to `nested_entries`, while the other dimensions mostly
    // represent emitted rows. Give traversal one quarter of the aggregate
    // scope budget and distribute the rest evenly across the ten row
    // dimensions. Every dimension remains positive and the limits still sum
    // exactly to the receiver's aggregate scope cap.
    let mut limits = [1; DIMENSIONS];
    let remaining = total - DIMENSIONS;
    let nested_extra = remaining.div_ceil(4);
    let row_capacity = remaining - nested_extra;
    let row_dimensions = DIMENSIONS - 1;
    let quotient = row_capacity / row_dimensions;
    let remainder = row_capacity % row_dimensions;
    for (index, limit) in limits[..row_dimensions].iter_mut().enumerate() {
        *limit += quotient + usize::from(index < remainder);
    }
    limits[NESTED_ENTRIES_INDEX] += nested_extra;
    limits
}

#[doc(hidden)]
pub struct ReceiverValueProjection {
    #[doc(hidden)]
    pub values: Vec<ReceiverValue>,
    #[doc(hidden)]
    pub truncated: bool,
    #[doc(hidden)]
    pub multiple_identities: bool,
}

fn projected_type_definitions(type_outcome: &TypeLookupOutcome) -> impl Iterator<Item = &CodeUnit> {
    let definitions_per_type = if type_outcome.status == TypeLookupStatus::Resolved {
        1
    } else {
        usize::MAX
    };
    type_outcome
        .types
        .iter()
        .flat_map(move |ty| ty.definitions.iter().take(definitions_per_type))
}

fn project_static_receiver_values(
    type_outcome: &TypeLookupOutcome,
    cancellation: Option<&CancellationToken>,
    ledger: &mut ReceiverWorkLedger,
) -> Result<CompatibilityOutcome<ReceiverValueProjection>, ReceiverQueryError> {
    let limit = ledger.remaining_budget().max_targets;
    let projected_count = projected_type_definitions(type_outcome).count();
    let mut values = Vec::with_capacity(projected_count.min(limit));
    for definition in projected_type_definitions(type_outcome) {
        if values.len() >= limit {
            break;
        }
        check_cancelled(cancellation)?;
        if let Err(limit) = charge_scope_step(ledger) {
            return Ok(CompatibilityOutcome::Exceeded(limit));
        }
        values.push(ReceiverValue::ClassOrStaticObject(definition.clone()));
    }
    Ok(CompatibilityOutcome::Complete(ReceiverValueProjection {
        values,
        truncated: projected_count > limit,
        multiple_identities: false,
    }))
}

#[doc(hidden)]
pub fn project_receiver_values(
    workspace: &WorkspaceAnalyzer,
    points_to: &SourcePointsToResult,
    type_outcome: &crate::analyzer::usages::get_type::TypeLookupOutcome,
    factories: &[CodeUnit],
    type_reference: bool,
    cancellation: Option<&CancellationToken>,
    ledger: &mut ReceiverWorkLedger,
) -> Result<CompatibilityOutcome<ReceiverValueProjection>, ReceiverQueryError> {
    let limit = ledger.remaining_budget().max_targets;
    let mut allocations = Vec::new();
    let mut allocations_truncated = false;
    let mut current_receiver = false;
    let mut nominal_instance = false;
    let mut source_value_identity = false;
    let mut call_results = Vec::new();
    let mut identities = Vec::new();
    for candidate in points_to.object_candidates() {
        check_cancelled(cancellation)?;
        if let Err(limit) = charge_scope_step(ledger) {
            return Ok(CompatibilityOutcome::Exceeded(limit));
        }
        let identity = candidate.value().identity();
        // A field path augments the exact candidate with object-identity
        // evidence, but it does not establish a new receiver category or
        // change the classification of any existing candidate.
        if matches!(identity, AbstractObjectIdentity::FieldPath { .. }) {
            continue;
        }
        if !identities.contains(&identity) {
            identities.push(identity);
        }
        match identity {
            AbstractObjectIdentity::Allocation(allocation) => {
                if !allocations.contains(allocation) {
                    if allocations.len() >= limit {
                        allocations_truncated = true;
                        break;
                    }
                    allocations.push(allocation.clone());
                }
            }
            AbstractObjectIdentity::ProcedurePort(port)
                if port.kind() == crate::analyzer::semantic::ProcedurePortKind::Receiver =>
            {
                current_receiver = true;
            }
            AbstractObjectIdentity::CallResult(result) => {
                if !call_results.contains(result) {
                    call_results.push(result.clone());
                }
            }
            AbstractObjectIdentity::Value(_) => source_value_identity = true,
            AbstractObjectIdentity::ProcedurePort(_)
            | AbstractObjectIdentity::Static(_)
            | AbstractObjectIdentity::LexicalCell(_)
            | AbstractObjectIdentity::CaptureSlot(_)
            | AbstractObjectIdentity::TypeSummary(_)
            | AbstractObjectIdentity::ModuleObject(_)
            | AbstractObjectIdentity::External(_) => nominal_instance = true,
            AbstractObjectIdentity::CallSubstitution { .. } => nominal_instance = true,
            AbstractObjectIdentity::FieldPath { .. } | AbstractObjectIdentity::RuntimeObject(_) => {
            }
        }
    }
    let static_reference = matches!(
        type_outcome.target_kind,
        crate::analyzer::usages::target_kind::TypeLookupTargetKind::TypeReference
    ) || type_reference;
    let mut factory_ranges = Vec::new();
    if !call_results.is_empty() {
        for factory in factories {
            let ranges = match code_unit_ranges_bounded(
                workspace.analyzer(),
                factory,
                cancellation,
                ledger,
            )? {
                CompatibilityOutcome::Complete(ranges) => ranges,
                CompatibilityOutcome::Exceeded(limit) => {
                    return Ok(CompatibilityOutcome::Exceeded(limit));
                }
            };
            factory_ranges.push((factory, ranges));
        }
    }
    let mut matching_factories = Vec::new();
    let mut unmatched_call_result = factories.is_empty() && !call_results.is_empty();
    for result in &call_results {
        let mut matched = None;
        for (factory, ranges) in &factory_ranges {
            check_cancelled(cancellation)?;
            if let Err(limit) = charge_scope_step(ledger) {
                return Ok(CompatibilityOutcome::Exceeded(limit));
            }
            if call_result_matches_factory(result, factory, ranges) {
                matched = Some((*factory).clone());
                break;
            }
        }
        if let Some(factory) = matched {
            if !matching_factories.contains(&factory) {
                matching_factories.push(factory);
            }
        } else {
            unmatched_call_result = true;
        }
    }
    // A fully matched call result is the specific public identity for the
    // exact factory expression. Some lowerers also retain generic source-value
    // scaffolding at that span; publishing it as a second nominal instance
    // duplicates the same expression and falsely turns one factory result into
    // an ambiguous answer. Other symbolic roots and unmatched calls remain
    // independent candidates.
    let factory_covers_source_value =
        !matching_factories.is_empty() && !unmatched_call_result && !call_results.is_empty();
    let include_nominal_instance =
        nominal_instance || (source_value_identity && !factory_covers_source_value);
    let projection_kinds = if static_reference {
        1
    } else {
        allocations
            .len()
            .saturating_add(usize::from(current_receiver))
            .saturating_add(usize::from(
                include_nominal_instance || unmatched_call_result,
            ))
            .saturating_add(matching_factories.len())
    };
    let projected_count = projected_type_definitions(type_outcome)
        .count()
        .saturating_mul(projection_kinds);
    let mut values = Vec::new();
    for definition in projected_type_definitions(type_outcome) {
        if values.len() >= limit {
            break;
        }
        check_cancelled(cancellation)?;
        if let Err(limit) = charge_scope_step(ledger) {
            return Ok(CompatibilityOutcome::Exceeded(limit));
        }
        if static_reference {
            values.push(ReceiverValue::ClassOrStaticObject(definition.clone()));
            continue;
        }
        if current_receiver {
            values.push(ReceiverValue::CurrentReceiver(definition.clone()));
        }
        for allocation in &allocations {
            if values.len() >= limit {
                break;
            }
            check_cancelled(cancellation)?;
            if let Err(limit) = charge_scope_step(ledger) {
                return Ok(CompatibilityOutcome::Exceeded(limit));
            }
            let row = allocation
                .procedure()
                .semantics()
                .allocation(allocation.id())
                .expect("allocation handles are validated");
            let span = allocation
                .procedure()
                .semantics()
                .source_mapping(row.source)
                .expect("allocation source is validated")
                .locator
                .anchor()
                .span();
            let key = allocation.procedure().artifact().key();
            let file = ProjectFile::new(
                workspace.analyzer().project().root().to_path_buf(),
                key.path().as_path(),
            );
            values.push(ReceiverValue::AllocationSite {
                ty: definition.clone(),
                file,
                range: Range {
                    start_byte: span.start_byte() as usize,
                    end_byte: span.end_byte() as usize,
                    start_line: span.start().line() as usize,
                    end_line: span.end().line() as usize,
                },
            });
        }
        if (include_nominal_instance || unmatched_call_result) && values.len() < limit {
            let value = ReceiverValue::InstanceType(definition.clone());
            values.push(value);
        }
        for factory in &matching_factories {
            if values.len() >= limit {
                break;
            }
            values.push(ReceiverValue::FactoryReturn {
                factory: factory.clone(),
                value: Box::new(ReceiverValue::InstanceType(definition.clone())),
            });
        }
        if values.len() >= limit {
            break;
        }
    }
    values.truncate(limit);
    Ok(CompatibilityOutcome::Complete(ReceiverValueProjection {
        values,
        truncated: allocations_truncated || projected_count > limit,
        multiple_identities: identities
            .iter()
            .filter(|identity| {
                !factory_covers_source_value
                    || !matches!(identity, AbstractObjectIdentity::Value(_))
            })
            .count()
            > 1,
    }))
}

#[doc(hidden)]
pub fn points_to_contains_call_result(
    points_to: &SourcePointsToResult,
    cancellation: Option<&CancellationToken>,
) -> Result<bool, ReceiverQueryError> {
    for candidate in points_to.object_candidates() {
        check_cancelled(cancellation)?;
        if matches!(
            candidate.value().identity(),
            AbstractObjectIdentity::CallResult(_)
        ) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[doc(hidden)]
pub fn code_unit_ranges_bounded(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    cancellation: Option<&CancellationToken>,
    ledger: &mut ReceiverWorkLedger,
) -> Result<CompatibilityOutcome<Vec<Range>>, ReceiverQueryError> {
    check_cancelled(cancellation)?;
    if let Err(limit) = charge_summary_step(ledger) {
        return Ok(CompatibilityOutcome::Exceeded(limit));
    }
    let language = language_for_file(unit.source());
    if matches!(
        language,
        Language::Cpp
            | Language::CSharp
            | Language::Go
            | Language::Java
            | Language::JavaScript
            | Language::Kotlin
            | Language::Php
            | Language::Python
            | Language::Ruby
            | Language::Rust
            | Language::Scala
            | Language::TypeScript
    ) {
        if let Err(limit) = charge_scope_step(ledger) {
            return Ok(CompatibilityOutcome::Exceeded(limit));
        }
        let provider_limit = ledger.remaining_budget().max_scope_nodes.saturating_add(1);
        let ranges = language_support_for_hook(language, "declaration_ranges_limited")
            .expect("language was checked above")
            .declaration_ranges_limited(analyzer, unit, provider_limit);
        let Some(ranges) = ranges else {
            return Ok(CompatibilityOutcome::Exceeded(
                ReceiverBudgetLimit::ScopeNodes,
            ));
        };
        return charge_limited_projection(ranges, cancellation, ledger);
    }
    Ok(CompatibilityOutcome::Exceeded(
        ReceiverBudgetLimit::ScopeNodes,
    ))
}

fn call_result_matches_factory(
    result: &crate::analyzer::semantic::CallResultHandle,
    factory: &CodeUnit,
    factory_ranges: &[Range],
) -> bool {
    let callee = result.callee();
    if callee.artifact().key().path().as_path() != factory.source().rel_path() {
        return false;
    }
    let Some(declaration) = callee.semantics().locator().declaration().segments().last() else {
        return false;
    };
    if declaration.name() != Some(factory.identifier()) {
        return false;
    }
    let span = callee.semantics().locator().anchor().span();
    let start = span.start_byte() as usize;
    let end = span.end_byte() as usize;
    factory_ranges
        .iter()
        .any(|range| range.start_byte <= start && end <= range.end_byte)
}

fn structural_factory_name_node(language: Language, node: Node<'_>) -> Option<Node<'_>> {
    if let Some(name) = crate::analyzer::languages::language_knowledge(language)
        .and_then(|support| support.factory_name_node(node))
    {
        return Some(name);
    }
    match language {
        Language::Cpp => {
            if node.kind() != "call_expression" {
                return None;
            }
            let function = node.child_by_field_name("function")?;
            match function.kind() {
                "field_expression" => function.child_by_field_name("field"),
                "qualified_identifier" => function.child_by_field_name("name"),
                "identifier" => Some(function),
                _ => None,
            }
        }
        Language::CSharp => {
            if node.kind() != "invocation_expression" {
                return None;
            }
            let function = node.child_by_field_name("function")?;
            match function.kind() {
                "member_access_expression" => function.child_by_field_name("name"),
                "identifier" | "generic_name" => Some(function),
                _ => None,
            }
        }
        Language::Go => {
            if node.kind() != "call_expression" {
                return None;
            }
            let function = node.child_by_field_name("function")?;
            match function.kind() {
                "selector_expression" => function.child_by_field_name("field"),
                "identifier" => Some(function),
                _ => None,
            }
        }
        Language::Php => match node.kind() {
            "function_call_expression" => node.child_by_field_name("function"),
            "member_call_expression"
            | "nullsafe_member_call_expression"
            | "scoped_call_expression" => node.child_by_field_name("name"),
            _ => None,
        },
        Language::Python => {
            if node.kind() != "call" {
                return None;
            }
            let function = node.child_by_field_name("function")?;
            match function.kind() {
                "attribute" => function.child_by_field_name("attribute"),
                "identifier" => Some(function),
                _ => None,
            }
        }
        Language::Ruby => {
            if node.kind() != "call" {
                return None;
            }
            node.child_by_field_name("method")
        }
        Language::Rust => {
            if node.kind() != "call_expression" {
                return None;
            }
            let mut function = node.child_by_field_name("function")?;
            while function.kind() == "generic_function" {
                function = function.child_by_field_name("function")?;
            }
            match function.kind() {
                "field_expression" => function.child_by_field_name("field"),
                "scoped_identifier" | "scoped_type_identifier" => {
                    function.child_by_field_name("name")
                }
                "identifier" => Some(function),
                _ => None,
            }
        }
        Language::Scala => {
            if node.kind() != "call_expression" {
                return None;
            }
            let mut function = node.child_by_field_name("function")?;
            while function.kind() == "call_expression" {
                function = function.child_by_field_name("function")?;
            }
            if function.kind() == "generic_function" {
                function = function.child_by_field_name("function")?;
            }
            match function.kind() {
                "field_expression" => function.child_by_field_name("field"),
                "identifier" | "operator_identifier" => Some(function),
                _ => None,
            }
        }
        _ => None,
    }
}

#[doc(hidden)]
pub fn definition_outcome(
    outcome: DefinitionLookupOutcome,
    limit: usize,
) -> (ReceiverAnalysisOutcome<CodeUnit>, bool) {
    let mut definitions = Vec::new();
    for definition in outcome.definitions {
        if !definitions.contains(&definition) {
            definitions.push(definition);
        }
    }
    let truncated = definitions.len() > limit;
    definitions.truncate(limit);
    let outcome = if outcome.status == DefinitionLookupStatus::Unavailable {
        ReceiverAnalysisOutcome::Unsupported {
            reason: "canonical_facts_unavailable",
        }
    } else if definitions.is_empty() {
        ReceiverAnalysisOutcome::Unknown
    } else {
        match outcome.status {
            DefinitionLookupStatus::Resolved => ReceiverAnalysisOutcome::Precise(definitions),
            DefinitionLookupStatus::Ambiguous => ReceiverAnalysisOutcome::Ambiguous(definitions),
            DefinitionLookupStatus::UnsupportedLanguage => ReceiverAnalysisOutcome::Unsupported {
                reason: "receiver_analysis_language_unsupported",
            },
            DefinitionLookupStatus::Unavailable => ReceiverAnalysisOutcome::Unsupported {
                reason: "canonical_facts_unavailable",
            },
            DefinitionLookupStatus::NoDefinition
            | DefinitionLookupStatus::UnresolvableImportBoundary
            | DefinitionLookupStatus::Incomplete
            | DefinitionLookupStatus::Cancelled
            | DefinitionLookupStatus::ExceededBudget(_)
            | DefinitionLookupStatus::InvalidLocation
            | DefinitionLookupStatus::NotFound => ReceiverAnalysisOutcome::Unknown,
        }
    };
    (outcome, truncated)
}

fn resolved_member_targets(
    analyzer: &dyn IAnalyzer,
    type_outcome: &TypeLookupOutcome,
    member_name: &str,
    workspace_outcome: ReceiverAnalysisOutcome<CodeUnit>,
    receiver_proof: Option<ReceiverIdentityProof>,
    budget: ReceiverAnalysisBudget,
) -> ReceiverAnalysisOutcome<ReceiverMemberTarget> {
    let mut model_type_ids = type_outcome
        .types
        .iter()
        .filter_map(|ty| ty.semantic_model_id.clone())
        .collect::<Vec<_>>();
    model_type_ids.sort();
    model_type_ids.dedup();
    if !model_type_ids.is_empty() {
        let Some(receiver_proof) = receiver_proof else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        let Some(overlay) = analyzer.semantic_model_overlay() else {
            return ReceiverAnalysisOutcome::Unsupported {
                reason: "semantic_model_member_unavailable",
            };
        };
        let mut targets = Vec::new();
        let mut exact =
            type_outcome.status == TypeLookupStatus::Resolved && model_type_ids.len() == 1;
        let mut exhaustive_absence = true;
        for owner_id in model_type_ids {
            let owners = overlay.symbols_with_id(&owner_id);
            let [owner] = owners.records.as_slice() else {
                exact = false;
                exhaustive_absence = false;
                continue;
            };
            let matched = overlay.member_target_on_owner(&owner_id, member_name);
            match matched.disposition {
                SemanticModelMemberTargetDisposition::Unique => {
                    let [member] = matched.records.as_slice() else {
                        unreachable!("unique modeled member resolution has one record");
                    };
                    targets.push(ReceiverMemberTarget::SemanticModel {
                        receiver: Box::new(ModeledDeclarationIdentity::from(owner.as_ref())),
                        member: Box::new(ModeledDeclarationIdentity::from(member.as_ref())),
                        receiver_proof: receiver_proof.clone(),
                    });
                    exhaustive_absence = false;
                }
                SemanticModelMemberTargetDisposition::Absent => {}
                SemanticModelMemberTargetDisposition::Incomplete => {
                    exact = false;
                    exhaustive_absence = false;
                    for member in matched.records {
                        targets.push(ReceiverMemberTarget::SemanticModel {
                            receiver: Box::new(ModeledDeclarationIdentity::from(owner.as_ref())),
                            member: Box::new(ModeledDeclarationIdentity::from(member.as_ref())),
                            receiver_proof: receiver_proof.clone(),
                        });
                    }
                }
                SemanticModelMemberTargetDisposition::Conflict => {
                    exact = false;
                    exhaustive_absence = false;
                    for member in matched.records {
                        targets.push(ReceiverMemberTarget::SemanticModel {
                            receiver: Box::new(ModeledDeclarationIdentity::from(owner.as_ref())),
                            member: Box::new(ModeledDeclarationIdentity::from(member.as_ref())),
                            receiver_proof: receiver_proof.clone(),
                        });
                    }
                }
            }
        }
        targets.sort_by(|left, right| modeled_member_key(left).cmp(&modeled_member_key(right)));
        targets.dedup();
        if targets.is_empty() {
            return if exhaustive_absence {
                ReceiverAnalysisOutcome::Unknown
            } else {
                ReceiverAnalysisOutcome::Unsupported {
                    reason: "semantic_model_member_incomplete",
                }
            };
        }
        let mut outcome = ReceiverAnalysisOutcome::single_precise_or_ambiguous(targets, budget);
        if !exact && let ReceiverAnalysisOutcome::Precise(values) = outcome {
            outcome = ReceiverAnalysisOutcome::Ambiguous(values);
        }
        return outcome;
    }

    // One resolved `TypeLookupType` is one logical receiver identity even when
    // the language publishes several physical declarations for it (for
    // example, C# partial classes). Keep the same representative projection as
    // `receiver_targets`; pairing every physical part with the same member
    // would manufacture ambiguity from one exact type.
    let mut receivers = projected_type_definitions(type_outcome)
        .cloned()
        .collect::<Vec<_>>();
    receivers.sort();
    receivers.dedup();
    if receivers.is_empty() {
        // Definition resolution can still prove the selected member when the
        // receiver type has no projectable declaration, such as Kotlin `this`
        // inside an extension function. Preserve that exact member without
        // inventing a receiver identity; identity-sensitive projections remain
        // incomplete until the receiver itself is proven.
        return unowned_workspace_member_targets(workspace_outcome);
    }
    let source_precise = type_outcome.status == TypeLookupStatus::Resolved
        && type_outcome.types.len() == 1
        && receivers.len() == 1;
    let member_precise = workspace_outcome.is_precise();
    match workspace_outcome {
        ReceiverAnalysisOutcome::Precise(members) | ReceiverAnalysisOutcome::Ambiguous(members) => {
            let mut targets = Vec::new();
            for receiver in &receivers {
                for member in &members {
                    targets.push(ReceiverMemberTarget::Workspace {
                        receiver: Some(receiver.clone()),
                        member: member.clone(),
                    });
                }
            }
            let mut outcome = ReceiverAnalysisOutcome::single_precise_or_ambiguous(targets, budget);
            if !(source_precise && member_precise)
                && let ReceiverAnalysisOutcome::Precise(values) = outcome
            {
                outcome = ReceiverAnalysisOutcome::Ambiguous(values);
            }
            outcome
        }
        ReceiverAnalysisOutcome::Unknown => ReceiverAnalysisOutcome::Unknown,
        ReceiverAnalysisOutcome::Unsupported { reason } => {
            ReceiverAnalysisOutcome::Unsupported { reason }
        }
        ReceiverAnalysisOutcome::ExceededBudget { limit } => {
            ReceiverAnalysisOutcome::ExceededBudget { limit }
        }
    }
}

fn legacy_member_targets(
    receiver_outcome: ReceiverAnalysisOutcome<ReceiverValue>,
    member_outcome: ReceiverAnalysisOutcome<CodeUnit>,
    budget: ReceiverAnalysisBudget,
) -> ReceiverAnalysisOutcome<ReceiverMemberTarget> {
    let receiver_precise = receiver_outcome.is_precise();
    let member_precise = member_outcome.is_precise();
    let Some(receiver_values) = receiver_outcome.values() else {
        return match receiver_outcome {
            ReceiverAnalysisOutcome::Unknown => ReceiverAnalysisOutcome::Unknown,
            ReceiverAnalysisOutcome::Unsupported { reason } => {
                ReceiverAnalysisOutcome::Unsupported { reason }
            }
            ReceiverAnalysisOutcome::ExceededBudget { limit } => {
                ReceiverAnalysisOutcome::ExceededBudget { limit }
            }
            ReceiverAnalysisOutcome::Precise(_) | ReceiverAnalysisOutcome::Ambiguous(_) => {
                unreachable!("value-carrying receiver outcome was handled above")
            }
        };
    };
    let Some(members) = member_outcome.values() else {
        return match member_outcome {
            ReceiverAnalysisOutcome::Unknown => ReceiverAnalysisOutcome::Unknown,
            ReceiverAnalysisOutcome::Unsupported { reason } => {
                ReceiverAnalysisOutcome::Unsupported { reason }
            }
            ReceiverAnalysisOutcome::ExceededBudget { limit } => {
                ReceiverAnalysisOutcome::ExceededBudget { limit }
            }
            ReceiverAnalysisOutcome::Precise(_) | ReceiverAnalysisOutcome::Ambiguous(_) => {
                unreachable!("value-carrying member outcome was handled above")
            }
        };
    };
    let mut targets = Vec::new();
    for receiver in receiver_values {
        for member in members {
            targets.push(ReceiverMemberTarget::Workspace {
                receiver: Some(receiver.owner().clone()),
                member: member.clone(),
            });
        }
    }
    let mut outcome = ReceiverAnalysisOutcome::single_precise_or_ambiguous(targets, budget);
    if !(receiver_precise && member_precise)
        && let ReceiverAnalysisOutcome::Precise(values) = outcome
    {
        outcome = ReceiverAnalysisOutcome::Ambiguous(values);
    }
    outcome
}

#[doc(hidden)]
pub fn unowned_workspace_member_targets(
    outcome: ReceiverAnalysisOutcome<CodeUnit>,
) -> ReceiverAnalysisOutcome<ReceiverMemberTarget> {
    match outcome {
        ReceiverAnalysisOutcome::Precise(values) => ReceiverAnalysisOutcome::Precise(
            values
                .into_iter()
                .map(|member| ReceiverMemberTarget::Workspace {
                    receiver: None,
                    member,
                })
                .collect(),
        ),
        ReceiverAnalysisOutcome::Ambiguous(values) => ReceiverAnalysisOutcome::Ambiguous(
            values
                .into_iter()
                .map(|member| ReceiverMemberTarget::Workspace {
                    receiver: None,
                    member,
                })
                .collect(),
        ),
        ReceiverAnalysisOutcome::Unknown => ReceiverAnalysisOutcome::Unknown,
        ReceiverAnalysisOutcome::Unsupported { reason } => {
            ReceiverAnalysisOutcome::Unsupported { reason }
        }
        ReceiverAnalysisOutcome::ExceededBudget { limit } => {
            ReceiverAnalysisOutcome::ExceededBudget { limit }
        }
    }
}

fn modeled_member_key(target: &ReceiverMemberTarget) -> (&str, &str) {
    match target {
        ReceiverMemberTarget::SemanticModel {
            receiver, member, ..
        } => (&receiver.id, &member.id),
        ReceiverMemberTarget::Workspace { .. } => ("", ""),
    }
}

#[doc(hidden)]
pub fn receiver_type_outcome<T>(
    status: TypeLookupStatus,
    values: Vec<T>,
) -> ReceiverAnalysisOutcome<T>
where
    T: Eq,
{
    let mut unique = Vec::with_capacity(values.len());
    for value in values {
        if !unique.contains(&value) {
            unique.push(value);
        }
    }
    if status == TypeLookupStatus::Unavailable {
        return ReceiverAnalysisOutcome::Unsupported {
            reason: "canonical_facts_unavailable",
        };
    }
    if unique.is_empty() {
        return ReceiverAnalysisOutcome::Unknown;
    }
    match status {
        TypeLookupStatus::Resolved if unique.len() == 1 => ReceiverAnalysisOutcome::Precise(unique),
        TypeLookupStatus::Resolved | TypeLookupStatus::Ambiguous => {
            ReceiverAnalysisOutcome::Ambiguous(unique)
        }
        TypeLookupStatus::NoType
        | TypeLookupStatus::Incomplete
        | TypeLookupStatus::Cancelled
        | TypeLookupStatus::InvalidLocation
        | TypeLookupStatus::NotFound => ReceiverAnalysisOutcome::Unknown,
        TypeLookupStatus::UnsupportedLanguage => ReceiverAnalysisOutcome::Unsupported {
            reason: "receiver_analysis_language_unsupported",
        },
        TypeLookupStatus::Unavailable => ReceiverAnalysisOutcome::Unsupported {
            reason: "canonical_facts_unavailable",
        },
        // The bounded resolvers report exhaustion as `BoundedResolution::Exceeded`,
        // which the ledger handles before an outcome reaches here; the status form
        // exists for the interactive type lookup, whose outcome is the whole answer.
        TypeLookupStatus::ExceededBudget(limit) => limit.exceeded(),
    }
}

#[doc(hidden)]
pub fn budget_report(
    operation: ReceiverQueryOperation,
    site: ReceiverQuerySite,
    work: ReceiverAnalysisWork,
    limit: ReceiverBudgetLimit,
) -> ReceiverQueryReport {
    let analysis = match operation {
        ReceiverQueryOperation::MemberTargets => {
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::ExceededBudget {
                limit: limit.as_str(),
            })
        }
        ReceiverQueryOperation::ReceiverTargets | ReceiverQueryOperation::PointsTo => {
            ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::ExceededBudget {
                limit: limit.as_str(),
            })
        }
    };
    ReceiverQueryReport {
        operation,
        site,
        analysis,
        member_range: None,
        work,
        candidates_truncated: false,
        semantic_unsupported: None,
        points_to: None,
    }
}

#[doc(hidden)]
pub fn unknown_report(
    operation: ReceiverQueryOperation,
    site: ReceiverQuerySite,
    work: ReceiverAnalysisWork,
    candidates_truncated: bool,
) -> ReceiverQueryReport {
    let analysis = match operation {
        ReceiverQueryOperation::MemberTargets => {
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Unknown)
        }
        ReceiverQueryOperation::ReceiverTargets | ReceiverQueryOperation::PointsTo => {
            ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Unknown)
        }
    };
    ReceiverQueryReport {
        operation,
        site,
        analysis,
        member_range: None,
        work,
        candidates_truncated,
        semantic_unsupported: None,
        points_to: None,
    }
}

#[doc(hidden)]
pub fn java_smallest_named_node_covering<'tree>(
    node: Node<'tree>,
    start: usize,
    end: usize,
    cancellation: Option<&CancellationToken>,
    ledger: &mut ReceiverWorkLedger,
) -> Result<CompatibilityOutcome<Option<Node<'tree>>>, ReceiverQueryError> {
    let mut cancellation_error = None;
    let mut exceeded_limit = None;
    let selected = brokk_bifrost_core::analyzer::usages::reference_site::smallest_named_node_covering_with_scope(
        node,
        start,
        end,
        || {
            if let Err(error) = check_cancelled(cancellation) {
                cancellation_error = Some(error);
                return false;
            }
            match charge_scope_step(ledger) {
                Ok(()) => true,
                Err(limit) => {
                    exceeded_limit = Some(limit);
                    false
                }
            }
        },
    );
    if let Some(error) = cancellation_error {
        return Err(error);
    }
    if let Some(limit) = exceeded_limit {
        return Ok(CompatibilityOutcome::Exceeded(limit));
    }
    Ok(CompatibilityOutcome::Complete(selected))
}

fn values_report(
    operation: ReceiverQueryOperation,
    file: &ProjectFile,
    language: Language,
    node: Node<'_>,
    source: &str,
    analysis: ReceiverAnalysisReport<ReceiverValue>,
) -> ReceiverQueryReport {
    ReceiverQueryReport {
        operation,
        site: site(file, language, node_range(node), source, node.kind(), None),
        analysis: ReceiverQueryAnalysis::Values(analysis.outcome),
        member_range: None,
        work: analysis.work,
        candidates_truncated: analysis.candidates_truncated,
        semantic_unsupported: None,
        points_to: None,
    }
}

#[doc(hidden)]
pub fn unsupported_report(
    operation: ReceiverQueryOperation,
    file: &ProjectFile,
    language: Language,
    range: Range,
    reason: &'static str,
    source: Option<&str>,
) -> ReceiverQueryReport {
    let analysis = match operation {
        ReceiverQueryOperation::MemberTargets => {
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Unsupported { reason })
        }
        ReceiverQueryOperation::ReceiverTargets | ReceiverQueryOperation::PointsTo => {
            ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Unsupported { reason })
        }
    };
    ReceiverQueryReport {
        operation,
        site: ReceiverQuerySite {
            file: file.clone(),
            language,
            range,
            text: source
                .and_then(|source| source.get(range.start_byte..range.end_byte))
                .unwrap_or_default()
                .to_string(),
            syntax_kind: "unsupported".to_string(),
            member_name: None,
        },
        analysis,
        member_range: None,
        work: ReceiverAnalysisWork::default(),
        candidates_truncated: false,
        semantic_unsupported: None,
        points_to: None,
    }
}

#[doc(hidden)]
pub fn setup_budget_report(
    operation: ReceiverQueryOperation,
    file: &ProjectFile,
    language: Language,
    range: Range,
    source: &str,
    work: ReceiverAnalysisWork,
) -> ReceiverQueryReport {
    budget_report(
        operation,
        site(file, language, range, source, "setup", None),
        work,
        ReceiverBudgetLimit::ScopeNodes,
    )
}

fn structural_reference_site(
    file: &ProjectFile,
    source: &str,
    range: Range,
) -> ResolvedReferenceSite {
    crate::analyzer::usages::common::build_reference_site(
        rel_path_string(file),
        source
            .get(range.start_byte..range.end_byte)
            .unwrap_or_default()
            .to_owned(),
        range,
        range.start_byte,
        range.end_byte,
    )
}

fn receiver_member_name(
    language: Language,
    tree: &Tree,
    source: &str,
    range: Range,
) -> Option<String> {
    if language == Language::CSharp
        && let Some(node) = tree
            .root_node()
            .named_descendant_for_byte_range(range.start_byte, range.end_byte)
        && node.kind() == "element_access_expression"
        && node.start_byte() == range.start_byte
        && node.end_byte() == range.end_byte
    {
        return Some(CSHARP_INDEXER_MEMBER_NAME.to_owned());
    }
    source
        .get(range.start_byte..range.end_byte)
        .filter(|member| !member.is_empty())
        .map(str::to_owned)
}

#[doc(hidden)]
pub fn site(
    file: &ProjectFile,
    language: Language,
    range: Range,
    source: &str,
    syntax_kind: &str,
    member_name: Option<String>,
) -> ReceiverQuerySite {
    ReceiverQuerySite {
        file: file.clone(),
        language,
        range,
        text: source
            .get(range.start_byte..range.end_byte)
            .unwrap_or_default()
            .to_string(),
        syntax_kind: syntax_kind.to_string(),
        member_name,
    }
}

#[doc(hidden)]
pub fn check_cancelled(cancellation: Option<&CancellationToken>) -> Result<(), ReceiverQueryError> {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        Err(ReceiverQueryError::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support;

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod tests;
