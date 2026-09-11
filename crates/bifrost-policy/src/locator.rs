//! Loaded-policy resolution of qualified call and receiver locators.
//!
//! Qualified locators are authoring convenience only. This module resolves
//! them once, against the analyzer's existing declaration lookup and active
//! semantic-model overlay, and leaves the relational evaluator with only
//! typed identity predicates.

use brokk_bifrost_analysis::analyzer::semantic_model::{
    SemanticModelCompleteness, SemanticModelOverlayDisposition, SemanticModelProvenance,
    SemanticModelSymbol, SemanticModelSymbolKind, semantic_model_callable_family_id,
};
use brokk_bifrost_analysis::analyzer::{CodeUnit, CodeUnitType, DescendantIndexScope, IAnalyzer};
use brokk_bifrost_rql::{
    CallIdentity, CodeQuery, CodeQueryPlanSource, QueryStep, ResolvedCallIdentity,
    ResolvedCallIdentityKind, ResolvedCallProof, ResolvedCallReceiverType,
};

use super::definition::*;
use super::source::{PolicySourceDiagnostic, PolicySourceDiagnosticSeverity, PolicySourceError};

#[derive(Debug, Clone, Copy)]
enum LocatorRole {
    Callable,
    ReceiverType,
}

impl LocatorRole {
    const fn public(self) -> ResolvedPolicyLocatorRole {
        match self {
            Self::Callable => ResolvedPolicyLocatorRole::Callable,
            Self::ReceiverType => ResolvedPolicyLocatorRole::ReceiverType,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Callable => "call",
            Self::ReceiverType => "receiver type",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum LocatorFailure {
    Zero,
    Ambiguous,
    Partial,
    InactiveModel,
    Incomplete,
}

impl LocatorFailure {
    const fn code(self, role: LocatorRole) -> &'static str {
        match (role, self) {
            (LocatorRole::Callable, Self::Zero) => "qualified-call-locator-zero",
            (LocatorRole::Callable, Self::Ambiguous) => "qualified-call-locator-ambiguous",
            (LocatorRole::Callable, Self::Partial) => "qualified-call-locator-partial",
            (LocatorRole::Callable, Self::InactiveModel) => "qualified-call-locator-inactive-model",
            (LocatorRole::Callable, Self::Incomplete) => "qualified-call-locator-incomplete",
            (LocatorRole::ReceiverType, Self::Zero) => "qualified-receiver-locator-zero",
            (LocatorRole::ReceiverType, Self::Ambiguous) => "qualified-receiver-locator-ambiguous",
            (LocatorRole::ReceiverType, Self::Partial) => "qualified-receiver-locator-partial",
            (LocatorRole::ReceiverType, Self::InactiveModel) => {
                "qualified-receiver-locator-inactive-model"
            }
            (LocatorRole::ReceiverType, Self::Incomplete) => {
                "qualified-receiver-locator-incomplete"
            }
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::Zero => "did not resolve to an exact identity",
            Self::Ambiguous => "resolved to multiple exact identities",
            Self::Partial => "resolved only through partial or uncertain model evidence",
            Self::InactiveModel => "requires an inactive semantic model",
            Self::Incomplete => {
                "could not be resolved because the analyzer/model context is incomplete"
            }
        }
    }
}

enum ResolvedLocatorIdentity {
    Workspace {
        identity: String,
        root: CodeUnit,
    },
    ActiveSemanticModel {
        identity: String,
        provenance: Box<SemanticModelProvenance>,
    },
}

impl ResolvedLocatorIdentity {
    fn kind(&self) -> ResolvedPolicyLocatorKind {
        match self {
            Self::Workspace { .. } => ResolvedPolicyLocatorKind::WorkspaceDeclaration,
            Self::ActiveSemanticModel { .. } => ResolvedPolicyLocatorKind::ActiveSemanticModel,
        }
    }

    fn identity(&self) -> &str {
        match self {
            Self::Workspace { identity, .. } => identity,
            Self::ActiveSemanticModel { identity, .. } => identity,
        }
    }

    fn provenance(&self) -> Option<SemanticModelProvenance> {
        match self {
            Self::Workspace { .. } => None,
            Self::ActiveSemanticModel { provenance, .. } => Some((**provenance).clone()),
        }
    }
}

/// Resolve every qualified locator reachable from one policy definition.
pub(super) fn resolve_policy_definition_locators(
    definition: &mut PolicyDefinition,
    analyzer: Option<&dyn IAnalyzer>,
) -> Result<(), PolicySourceError> {
    match &mut definition.analysis {
        PolicyAnalysis::Match { spec } => resolve_selector_locators(&mut spec.selector, analyzer),
        PolicyAnalysis::Assertion { spec } => {
            if let Some(plan) = &mut spec.relational {
                resolve_relational_assertion_plan(plan, analyzer)
            } else {
                resolve_selector_locators(&mut spec.subject, analyzer)
            }
        }
        PolicyAnalysis::Taint { spec } | PolicyAnalysis::Flow { spec } => {
            resolve_taint_set(&mut spec.sources, analyzer)?;
            resolve_taint_set(&mut spec.sinks, analyzer)?;
            resolve_taint_set(&mut spec.sanitizers, analyzer)?;
            resolve_taint_set(&mut spec.entry_points, analyzer)?;
            resolve_taint_set(&mut spec.transforms, analyzer)?;
            resolve_taint_set(&mut spec.external_models, analyzer)?;
            resolve_taint_entries(&mut spec.store_writes, analyzer)?;
            resolve_taint_entries(&mut spec.store_reads, analyzer)
        }
        PolicyAnalysis::Typestate { spec } => {
            for subject in &mut spec.subjects.entries {
                resolve_selector_locators(&mut subject.selector, analyzer)?;
            }
            for event in &mut spec.automaton.events {
                if let TypestateEventTrigger::Calls { selector, .. } = &mut event.trigger {
                    resolve_selector_locators(selector, analyzer)?;
                }
            }
            Ok(())
        }
    }
}

fn resolve_taint_set<T>(
    set: &mut TaintEndpointSet<T>,
    analyzer: Option<&dyn IAnalyzer>,
) -> Result<(), PolicySourceError>
where
    T: TaintSelectorAccess,
{
    resolve_taint_entries(&mut set.entries, analyzer)
}

fn resolve_taint_entries<T>(
    entries: &mut [T],
    analyzer: Option<&dyn IAnalyzer>,
) -> Result<(), PolicySourceError>
where
    T: TaintSelectorAccess,
{
    for entry in entries {
        resolve_selector_locators(entry.selector_mut(), analyzer)?;
    }
    Ok(())
}

trait TaintSelectorAccess {
    fn selector(&self) -> &PolicySelector;
    fn selector_mut(&mut self) -> &mut PolicySelector;
}

impl TaintSelectorAccess for TaintSourceSpec {
    fn selector(&self) -> &PolicySelector {
        &self.selector
    }

    fn selector_mut(&mut self) -> &mut PolicySelector {
        &mut self.selector
    }
}

impl TaintSelectorAccess for TaintSinkSpec {
    fn selector(&self) -> &PolicySelector {
        &self.selector
    }

    fn selector_mut(&mut self) -> &mut PolicySelector {
        &mut self.selector
    }
}

impl TaintSelectorAccess for TaintSanitizerSpec {
    fn selector(&self) -> &PolicySelector {
        &self.selector
    }

    fn selector_mut(&mut self) -> &mut PolicySelector {
        &mut self.selector
    }
}

impl TaintSelectorAccess for TaintEntryPointSpec {
    fn selector(&self) -> &PolicySelector {
        &self.selector
    }

    fn selector_mut(&mut self) -> &mut PolicySelector {
        &mut self.selector
    }
}

impl TaintSelectorAccess for TaintTransformSpec {
    fn selector(&self) -> &PolicySelector {
        &self.selector
    }

    fn selector_mut(&mut self) -> &mut PolicySelector {
        &mut self.selector
    }
}

impl TaintSelectorAccess for TaintExternalModelSpec {
    fn selector(&self) -> &PolicySelector {
        &self.selector
    }

    fn selector_mut(&mut self) -> &mut PolicySelector {
        &mut self.selector
    }
}

impl TaintSelectorAccess for TaintStoreWriteSpec {
    fn selector(&self) -> &PolicySelector {
        &self.selector
    }

    fn selector_mut(&mut self) -> &mut PolicySelector {
        &mut self.selector
    }
}

impl TaintSelectorAccess for TaintStoreReadSpec {
    fn selector(&self) -> &PolicySelector {
        &self.selector
    }

    fn selector_mut(&mut self) -> &mut PolicySelector {
        &mut self.selector
    }
}

/// Return resolved locator metadata in the same stable traversal order used by
/// policy authoring. This metadata belongs to the loaded-policy projection;
/// the selector hash contains only the resolved stable identity.
pub(super) fn resolved_locator_metadata(
    definition: &PolicyDefinition,
) -> Vec<&ResolvedPolicyLocator> {
    let mut locators = Vec::new();
    match &definition.analysis {
        PolicyAnalysis::Match { spec } => collect_selector_locators(&spec.selector, &mut locators),
        PolicyAnalysis::Assertion { spec } => {
            if let Some(plan) = &spec.relational {
                for binding in &plan.bindings {
                    let RowBindingSource::Query(selector) = &binding.source;
                    collect_selector_locators(selector, &mut locators);
                }
            } else {
                collect_selector_locators(&spec.subject, &mut locators);
            }
        }
        PolicyAnalysis::Taint { spec } | PolicyAnalysis::Flow { spec } => {
            collect_taint_set_locators(&spec.sources, &mut locators);
            collect_taint_set_locators(&spec.sinks, &mut locators);
            collect_taint_set_locators(&spec.sanitizers, &mut locators);
            collect_taint_set_locators(&spec.entry_points, &mut locators);
            collect_taint_set_locators(&spec.transforms, &mut locators);
            collect_taint_set_locators(&spec.external_models, &mut locators);
            collect_taint_entry_locators(&spec.store_writes, &mut locators);
            collect_taint_entry_locators(&spec.store_reads, &mut locators);
        }
        PolicyAnalysis::Typestate { spec } => {
            for subject in &spec.subjects.entries {
                collect_selector_locators(&subject.selector, &mut locators);
            }
            for event in &spec.automaton.events {
                if let TypestateEventTrigger::Calls { selector, .. } = &event.trigger {
                    collect_selector_locators(selector, &mut locators);
                }
            }
        }
    }
    locators
}

fn collect_taint_set_locators<'a, T: TaintSelectorAccess>(
    set: &'a TaintEndpointSet<T>,
    locators: &mut Vec<&'a ResolvedPolicyLocator>,
) {
    collect_taint_entry_locators(&set.entries, locators);
}

fn collect_taint_entry_locators<'a, T: TaintSelectorAccess>(
    entries: &'a [T],
    locators: &mut Vec<&'a ResolvedPolicyLocator>,
) {
    for entry in entries {
        collect_selector_locators(entry.selector(), locators);
    }
}

fn collect_selector_locators<'a>(
    selector: &'a PolicySelector,
    locators: &mut Vec<&'a ResolvedPolicyLocator>,
) {
    if let PolicySelector::Inline {
        resolved_locators, ..
    } = selector
    {
        locators.extend(resolved_locators);
    }
}

fn resolve_relational_assertion_plan(
    plan: &mut RelationalAssertionPlan,
    analyzer: Option<&dyn IAnalyzer>,
) -> Result<(), PolicySourceError> {
    for binding in &mut plan.bindings {
        let RowBindingSource::Query(selector) = &mut binding.source;
        resolve_selector_locators(selector, analyzer)?;
    }
    Ok(())
}

pub(super) fn resolve_selector_locators(
    selector: &mut PolicySelector,
    analyzer: Option<&dyn IAnalyzer>,
) -> Result<(), PolicySourceError> {
    if let PolicySelector::Inline {
        query,
        resolved_locators,
        ..
    } = selector
    {
        resolve_query_locators(query, resolved_locators, analyzer)?;
    }
    Ok(())
}

pub(super) fn resolve_query_locators(
    query: &mut CodeQuery,
    resolved_locators: &mut Vec<ResolvedPolicyLocator>,
    analyzer: Option<&dyn IAnalyzer>,
) -> Result<(), PolicySourceError> {
    let mut pending = vec![&mut query.plan];
    while let Some(plan) = pending.pop() {
        if let CodeQueryPlanSource::Set { branches, .. } = &mut plan.source {
            pending.extend(branches);
        }
        for step in &mut plan.steps {
            let QueryStep::ResolvedCall(filter) = step else {
                continue;
            };
            resolve_query_identity(
                &mut filter.resolves_to,
                filter.proof,
                LocatorRole::Callable,
                ReceiverTypeConstraintKind::Exact,
                analyzer,
                resolved_locators,
            )?;
            if let Some(receiver_type) = &mut filter.receiver_type {
                match receiver_type {
                    ResolvedCallReceiverType::Exact(identity) => resolve_query_identity(
                        identity,
                        filter.proof,
                        LocatorRole::ReceiverType,
                        ReceiverTypeConstraintKind::Exact,
                        analyzer,
                        resolved_locators,
                    )?,
                    ResolvedCallReceiverType::AssignableTo {
                        root,
                        resolved_identities,
                    } => resolve_query_receiver_family(
                        root,
                        resolved_identities,
                        analyzer,
                        resolved_locators,
                    )?,
                }
            }
        }
    }
    Ok(())
}

fn resolve_query_identity(
    locator: &mut CallIdentity,
    proof: ResolvedCallProof,
    role: LocatorRole,
    constraint: ReceiverTypeConstraintKind,
    analyzer: Option<&dyn IAnalyzer>,
    resolved_locators: &mut Vec<ResolvedPolicyLocator>,
) -> Result<(), PolicySourceError> {
    let CallIdentity::Qualified {
        value,
        source_range,
        resolved,
    } = locator
    else {
        return Ok(());
    };
    if resolved.is_some() {
        return Ok(());
    }
    let policy_locator = PolicyLocator {
        value: value.clone(),
        range: source_range.clone().unwrap_or(0..0),
    };
    let identity = resolve_qualified_locator(analyzer, &policy_locator, role)?;
    if matches!(role, LocatorRole::Callable)
        && matches!(proof, ResolvedCallProof::Declared)
        && matches!(identity, ResolvedLocatorIdentity::Workspace { .. })
    {
        return Err(source_error(
            "invalid-call-proof-for-source-locator",
            policy_locator.range,
            "resolved-call :proof declared requires an active semantic-model callable, not a workspace declaration",
        ));
    }
    let kind = match identity.kind() {
        ResolvedPolicyLocatorKind::WorkspaceDeclaration => {
            ResolvedCallIdentityKind::WorkspaceDeclaration
        }
        ResolvedPolicyLocatorKind::ActiveSemanticModel => {
            ResolvedCallIdentityKind::ActiveSemanticModel
        }
    };
    *resolved = Some(ResolvedCallIdentity {
        kind,
        identity: identity.identity().to_owned(),
    });
    resolved_locators.push(ResolvedPolicyLocator {
        role: role.public(),
        kind: identity.kind(),
        identity: identity.identity().to_owned(),
        constraint,
        provenance: identity.provenance(),
    });
    Ok(())
}

fn resolve_query_receiver_family(
    root: &mut CallIdentity,
    resolved_identities: &mut Vec<String>,
    analyzer: Option<&dyn IAnalyzer>,
    resolved_locators: &mut Vec<ResolvedPolicyLocator>,
) -> Result<(), PolicySourceError> {
    if matches!(
        root,
        CallIdentity::Qualified {
            resolved: Some(_),
            ..
        }
    ) {
        return Ok(());
    }
    let policy_locator = match root {
        CallIdentity::Stable(value) => PolicyLocator {
            value: value.clone(),
            range: 0..0,
        },
        CallIdentity::Qualified {
            value,
            source_range,
            ..
        } => PolicyLocator {
            value: value.clone(),
            range: source_range.clone().unwrap_or(0..0),
        },
    };
    let identity = resolve_qualified_locator(analyzer, &policy_locator, LocatorRole::ReceiverType)?;
    *resolved_identities = materialize_receiver_family(analyzer, &identity, &policy_locator)?;
    if let CallIdentity::Qualified { resolved, .. } = root {
        let kind = match identity.kind() {
            ResolvedPolicyLocatorKind::WorkspaceDeclaration => {
                ResolvedCallIdentityKind::WorkspaceDeclaration
            }
            ResolvedPolicyLocatorKind::ActiveSemanticModel => {
                ResolvedCallIdentityKind::ActiveSemanticModel
            }
        };
        *resolved = Some(ResolvedCallIdentity {
            kind,
            identity: identity.identity().to_owned(),
        });
    }
    resolved_locators.push(ResolvedPolicyLocator {
        role: ResolvedPolicyLocatorRole::ReceiverType,
        kind: identity.kind(),
        identity: identity.identity().to_owned(),
        constraint: ReceiverTypeConstraintKind::AssignableTo,
        provenance: identity.provenance(),
    });
    Ok(())
}

fn materialize_receiver_family(
    analyzer: Option<&dyn IAnalyzer>,
    identity: &ResolvedLocatorIdentity,
    locator: &PolicyLocator,
) -> Result<Vec<String>, PolicySourceError> {
    let ResolvedLocatorIdentity::Workspace {
        identity: root_id,
        root,
    } = identity
    else {
        return Err(locator_error(
            locator,
            LocatorRole::ReceiverType,
            LocatorFailure::Incomplete,
            "active semantic-model and external types do not yet expose a complete workspace-implementor hierarchy (#2580)",
        ));
    };

    let Some(analyzer) = analyzer else {
        return Err(locator_error(
            locator,
            LocatorRole::ReceiverType,
            LocatorFailure::Incomplete,
            "no analyzer snapshot was supplied to the loaded-policy boundary",
        ));
    };
    let Some(provider) = analyzer.type_hierarchy_provider() else {
        return Err(locator_error(
            locator,
            LocatorRole::ReceiverType,
            LocatorFailure::Incomplete,
            "the selected analyzer does not provide a typed hierarchy",
        ));
    };
    if !provider.supports_type_hierarchy(root) {
        return Err(locator_error(
            locator,
            LocatorRole::ReceiverType,
            LocatorFailure::Incomplete,
            format!("root `{root_id}` is not a supported type hierarchy declaration"),
        ));
    }

    let cancellation = analyzer.active_query_cancellation().unwrap_or_default();
    let scope = DescendantIndexScope::whole_workspace(&cancellation);
    let descendants = provider
        .get_descendants_within(root, &scope)
        .ok_or_else(|| {
            locator_error(
                locator,
                LocatorRole::ReceiverType,
                LocatorFailure::Incomplete,
                "the complete descendant hierarchy build was cancelled",
            )
        })?;
    let mut identities = Vec::with_capacity(descendants.len() + 1);
    identities.push(root_id.clone());
    identities.extend(
        descendants
            .iter()
            .map(|unit| unit.declaration_id().to_string()),
    );
    identities.sort();
    identities.dedup();
    Ok(identities)
}

fn resolve_qualified_locator(
    analyzer: Option<&dyn IAnalyzer>,
    locator: &PolicyLocator,
    role: LocatorRole,
) -> Result<ResolvedLocatorIdentity, PolicySourceError> {
    let Some(analyzer) = analyzer else {
        return Err(locator_error(
            locator,
            role,
            LocatorFailure::Incomplete,
            "no analyzer snapshot was supplied to the loaded-policy boundary",
        ));
    };

    let source_matches = analyzer
        .get_definitions(&locator.value)
        .into_iter()
        .filter(|unit| match role {
            LocatorRole::Callable => unit.kind() == CodeUnitType::Function,
            LocatorRole::ReceiverType => unit.kind() == CodeUnitType::Class,
        })
        .collect::<Vec<_>>();
    let source_identities = source_matches
        .iter()
        .map(|unit| unit.declaration_id().to_string())
        .collect::<Vec<_>>();
    let mut source_identities = source_identities;
    source_identities.sort();
    source_identities.dedup();

    let overlay = analyzer.semantic_model_overlay();
    let model_records = overlay.as_ref().map(|overlay| {
        let matched = overlay.symbols_named(&locator.value);
        let mut records = matched
            .records
            .into_iter()
            .filter(|symbol| model_symbol_matches_role(symbol, role))
            .collect::<Vec<_>>();
        records.sort_by(|left, right| left.id.cmp(&right.id));
        (matched.disposition, records)
    });

    if source_identities.len() > 1 {
        return Err(locator_error(
            locator,
            role,
            LocatorFailure::Ambiguous,
            format!("workspace declaration identities: {source_identities:?}"),
        ));
    }

    if let Some((disposition, records)) = model_records {
        if matches!(role, LocatorRole::Callable)
            && records.len() > 1
            && source_identities.is_empty()
            && let Some(identity) = semantic_model_callable_family_id(&records)
        {
            let mut provenance = records[0].provenance.clone();
            provenance.record_id = identity.clone();
            return Ok(ResolvedLocatorIdentity::ActiveSemanticModel {
                identity,
                provenance: Box::new(provenance),
            });
        }
        if records.iter().any(|record| record.provenance.ambiguous)
            || (disposition == SemanticModelOverlayDisposition::Conflict && records.len() > 1)
        {
            let identities = records
                .iter()
                .map(|record| record.id.as_str())
                .collect::<Vec<_>>();
            return Err(locator_error(
                locator,
                role,
                LocatorFailure::Ambiguous,
                format!("active semantic-model identities: {identities:?}"),
            ));
        }
        if records.len() > 1 {
            let identities = records
                .iter()
                .map(|record| record.id.as_str())
                .collect::<Vec<_>>();
            return Err(locator_error(
                locator,
                role,
                LocatorFailure::Ambiguous,
                format!("active semantic-model identities: {identities:?}"),
            ));
        }
        if let Some(record) = records.first() {
            if !source_identities.is_empty() {
                return Err(locator_error(
                    locator,
                    role,
                    LocatorFailure::Ambiguous,
                    format!(
                        "workspace identity `{}` and active semantic-model identity `{}`",
                        source_identities[0], record.id
                    ),
                ));
            }
            if matches!(role, LocatorRole::Callable) {
                let Some(identity) = overlay
                    .as_ref()
                    .and_then(|overlay| overlay.callable_family_id_for_symbol(record))
                else {
                    return Err(locator_error(
                        locator,
                        role,
                        LocatorFailure::Partial,
                        format!(
                            "active semantic-model callable family containing `{}`",
                            record.id
                        ),
                    ));
                };
                let mut provenance = record.provenance.clone();
                provenance.record_id = identity.clone();
                return Ok(ResolvedLocatorIdentity::ActiveSemanticModel {
                    identity,
                    provenance: Box::new(provenance),
                });
            }
            if record.provenance.completeness != SemanticModelCompleteness::Complete {
                return Err(locator_error(
                    locator,
                    role,
                    LocatorFailure::Partial,
                    format!("active semantic-model identity: {}", record.id),
                ));
            }
            return Ok(ResolvedLocatorIdentity::ActiveSemanticModel {
                identity: record.id.clone(),
                provenance: Box::new(record.provenance.clone()),
            });
        }
    } else if source_identities.is_empty() {
        let failure = if analyzer.active_semantic_models().is_some() {
            LocatorFailure::Incomplete
        } else {
            LocatorFailure::InactiveModel
        };
        return Err(locator_error(
            locator,
            role,
            failure,
            "no active semantic-model declaration surface was available",
        ));
    }

    if let Some(identity) = source_identities.first() {
        let root = source_matches
            .into_iter()
            .find(|unit| unit.declaration_id().as_str() == identity.as_str())
            .unwrap_or_else(|| panic!("workspace identity `{identity}` lost its root declaration"));
        return Ok(ResolvedLocatorIdentity::Workspace {
            identity: identity.clone(),
            root,
        });
    }

    Err(locator_error(
        locator,
        role,
        LocatorFailure::Zero,
        format!("qualified locator `{}`", locator.value),
    ))
}

fn model_symbol_matches_role(symbol: &SemanticModelSymbol, role: LocatorRole) -> bool {
    match role {
        LocatorRole::Callable => matches!(
            symbol.kind,
            SemanticModelSymbolKind::Constructor
                | SemanticModelSymbolKind::Method
                | SemanticModelSymbolKind::Function
        ),
        LocatorRole::ReceiverType => matches!(
            symbol.kind,
            SemanticModelSymbolKind::Class
                | SemanticModelSymbolKind::Annotation
                | SemanticModelSymbolKind::Delegate
                | SemanticModelSymbolKind::Interface
                | SemanticModelSymbolKind::Trait
                | SemanticModelSymbolKind::Struct
                | SemanticModelSymbolKind::Union
                | SemanticModelSymbolKind::Enum
                | SemanticModelSymbolKind::Record
                | SemanticModelSymbolKind::Module
                | SemanticModelSymbolKind::TypeAlias
        ),
    }
}

fn locator_error(
    locator: &PolicyLocator,
    role: LocatorRole,
    failure: LocatorFailure,
    detail: impl Into<String>,
) -> PolicySourceError {
    source_error(
        failure.code(role),
        locator.range.clone(),
        format!(
            "qualified {} locator `{}` {} ({})",
            role.label(),
            locator.value,
            failure.description(),
            detail.into()
        ),
    )
}

fn source_error(
    code: &'static str,
    range: std::ops::Range<usize>,
    message: impl Into<String>,
) -> PolicySourceError {
    PolicySourceError {
        diagnostic: PolicySourceDiagnostic {
            code,
            severity: PolicySourceDiagnosticSeverity::Error,
            message: message.into(),
            range,
            fix: None,
            related: Vec::new(),
        },
    }
}
