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
use brokk_bifrost_analysis::analyzer::{CodeUnitType, IAnalyzer};

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
    Workspace(String),
    ActiveSemanticModel {
        identity: String,
        provenance: Box<SemanticModelProvenance>,
    },
}

impl ResolvedLocatorIdentity {
    fn kind(&self) -> ResolvedPolicyLocatorKind {
        match self {
            Self::Workspace(_) => ResolvedPolicyLocatorKind::WorkspaceDeclaration,
            Self::ActiveSemanticModel { .. } => ResolvedPolicyLocatorKind::ActiveSemanticModel,
        }
    }

    fn identity(&self) -> &str {
        match self {
            Self::Workspace(identity) => identity,
            Self::ActiveSemanticModel { identity, .. } => identity,
        }
    }

    fn provenance(&self) -> Option<SemanticModelProvenance> {
        match self {
            Self::Workspace(_) => None,
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
            resolve_selector_locators(&mut spec.subject, analyzer)?;
            if let Some(plan) = &mut spec.relational {
                resolve_relational_assertion_plan(plan, analyzer)?;
            }
            Ok(())
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
/// policy authoring. This metadata belongs to the loaded-policy projection,
/// not to the relational selector hash: the latter must remain identical to a
/// handwritten identity-filter plan.
pub(super) fn resolved_locator_metadata(
    definition: &PolicyDefinition,
) -> Vec<&ResolvedPolicyLocator> {
    let mut locators = Vec::new();
    match &definition.analysis {
        PolicyAnalysis::Match { spec } => collect_selector_locators(&spec.selector, &mut locators),
        PolicyAnalysis::Assertion { spec } => {
            collect_selector_locators(&spec.subject, &mut locators);
            if let Some(plan) = &spec.relational {
                for binding in &plan.bindings {
                    if let RowBindingSource::Query(selector) = &binding.source {
                        collect_selector_locators(selector, &mut locators);
                    }
                }
                collect_row_derivation_locators(&plan.derivations, &mut locators);
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
    let PolicySelector::Rows { plan } = selector else {
        return;
    };
    for binding in &plan.bindings {
        if let RowBindingSource::Query(selector) = &binding.source {
            collect_selector_locators(selector, locators);
        }
    }
    collect_row_derivation_locators(&plan.derivations, locators);
}

fn collect_row_derivation_locators<'a>(
    derivations: &'a [RowDerivation],
    locators: &mut Vec<&'a ResolvedPolicyLocator>,
) {
    for derivation in derivations {
        if let RowDerivation::Filter(filter) = derivation {
            locators.extend(&filter.resolved_locators);
        }
    }
}

fn resolve_relational_assertion_plan(
    plan: &mut RelationalAssertionPlan,
    analyzer: Option<&dyn IAnalyzer>,
) -> Result<(), PolicySourceError> {
    for binding in &mut plan.bindings {
        if let RowBindingSource::Query(selector) = &mut binding.source {
            resolve_selector_locators(selector, analyzer)?;
        }
    }
    resolve_row_derivations(&mut plan.derivations, analyzer)
}

pub(super) fn resolve_selector_locators(
    selector: &mut PolicySelector,
    analyzer: Option<&dyn IAnalyzer>,
) -> Result<(), PolicySourceError> {
    let PolicySelector::Rows { plan } = selector else {
        return Ok(());
    };
    for binding in &mut plan.bindings {
        if let RowBindingSource::Query(selector) = &mut binding.source {
            resolve_selector_locators(selector, analyzer)?;
        }
    }
    resolve_row_derivations(&mut plan.derivations, analyzer)
}

fn resolve_row_derivations(
    derivations: &mut [RowDerivation],
    analyzer: Option<&dyn IAnalyzer>,
) -> Result<(), PolicySourceError> {
    for derivation in derivations {
        if let RowDerivation::Filter(filter) = derivation {
            resolve_row_filter(filter, analyzer)?;
        }
    }
    Ok(())
}

fn resolve_row_filter(
    filter: &mut RowFilter,
    analyzer: Option<&dyn IAnalyzer>,
) -> Result<(), PolicySourceError> {
    let Some(locator) = filter.call_locator.take() else {
        return Ok(());
    };
    let mut resolved = Vec::with_capacity(2);
    if let Some(target) = locator.target {
        let identity = resolve_qualified_locator(analyzer, &target, LocatorRole::Callable)?;
        if matches!(filter.evidence, Some(RowFilterEvidence::DeclaredCall))
            && matches!(identity, ResolvedLocatorIdentity::Workspace(_))
        {
            return Err(source_error(
                "invalid-call-proof-for-source-locator",
                target.range,
                "call :proof declared requires an active semantic-model callable, not a workspace declaration",
            ));
        }
        let target_field = match &identity {
            ResolvedLocatorIdentity::Workspace(_) => "target_id",
            ResolvedLocatorIdentity::ActiveSemanticModel { .. } => "model_callable_id",
        };
        replace_locator_predicate(
            filter,
            &target.value,
            "model_callable_id",
            target_field,
            identity.identity(),
        );
        resolved.push(ResolvedPolicyLocator {
            role: LocatorRole::Callable.public(),
            kind: identity.kind(),
            identity: identity.identity().to_owned(),
            provenance: identity.provenance(),
        });
    }
    if let Some(receiver_type) = locator.receiver_type {
        let identity =
            resolve_qualified_locator(analyzer, &receiver_type, LocatorRole::ReceiverType)?;
        replace_locator_predicate(
            filter,
            &receiver_type.value,
            "receiver_type_id",
            "receiver_type_id",
            identity.identity(),
        );
        resolved.push(ResolvedPolicyLocator {
            role: LocatorRole::ReceiverType.public(),
            kind: identity.kind(),
            identity: identity.identity().to_owned(),
            provenance: identity.provenance(),
        });
    }
    filter.resolved_locators.extend(resolved);
    Ok(())
}

fn replace_locator_predicate(
    filter: &mut RowFilter,
    authored_value: &str,
    authored_field: &str,
    field: &str,
    resolved_identity: &str,
) {
    let predicate = filter
        .predicates
        .iter_mut()
        .find(|predicate| {
            predicate.op == RowPredicateOp::Eq
                && predicate.field.field == authored_field
                && matches!(
                    &predicate.operand,
                    RowPredicateOperand::Literal(RowLiteral::String(value))
                        if value == authored_value
                )
        })
        .unwrap_or_else(|| {
            panic!(
                "qualified locator `{authored_value}` lost its decoder predicate before loaded-policy resolution"
            )
        });
    predicate.field.field = field.to_owned();
    predicate.operand =
        RowPredicateOperand::Literal(RowLiteral::String(resolved_identity.to_owned()));
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

    let source_identities = analyzer
        .get_definitions(&locator.value)
        .into_iter()
        .filter(|unit| match role {
            LocatorRole::Callable => unit.kind() == CodeUnitType::Function,
            LocatorRole::ReceiverType => unit.kind() == CodeUnitType::Class,
        })
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
        return Ok(ResolvedLocatorIdentity::Workspace(identity.clone()));
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
