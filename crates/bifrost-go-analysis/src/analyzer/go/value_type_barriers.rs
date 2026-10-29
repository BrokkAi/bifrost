//! Request-local Go carrier proofs from the selected native type frontier.

use std::cell::RefCell;
use std::sync::Arc;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;
use brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery;
use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
use brokk_bifrost_analysis::analyzer::semantic::{
    BarrierObservation, ObservedValueType, SemanticProviderError, SemanticRequest, SemanticWork,
    SourceMappingKind, ValueHandle, ValueTypeBarrierContext, ValueTypeBarrierDecision,
    ValueTypeBarrierReason, ValueTypePredicate, prepare_value_type_barrier_source,
    value_type_barrier_source_matches,
};
use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupStatus;
use brokk_bifrost_core::analyzer::model::{ProjectFile, Range};
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;
use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;
use brokk_bifrost_core::hash::{HashMap, HashSet};

use super::GoAnalyzer;
use super::native_points::{GoNativePointRequest, GoNativePointRequestOpen};
use super::type_identity_proof::{CarrierType, ObservedCarrierType, go_selected_carrier_type};
use ValueTypeBarrierDecision::{ProvenNonMatch, Undecided};
use ValueTypeBarrierReason::{
    BudgetExceeded, Cancelled, IncompleteType, UnavailableObservation, UnknownType,
};

struct DeclaredCarrierSyntax {
    file: ProjectFile,
    start: usize,
    end: usize,
    kind: &'static str,
    defined: bool,
}

struct GoBarrierContext<'a> {
    analyzer: &'a dyn IAnalyzer,
    go: &'a GoAnalyzer,
    native: RefCell<Option<Box<GoNativePointRequest<'a>>>>,
    decisions: RefCell<HashMap<(ValueHandle, ValueTypePredicate), ValueTypeBarrierDecision>>,
    syntax: RefCell<HashMap<ProjectFile, Arc<PreparedSyntaxTree>>>,
    native_refusals: RefCell<HashSet<(ValueHandle, ValueTypePredicate)>>,
    observed: RefCell<HashMap<ValueHandle, ObservedValueType>>,
}

pub(crate) fn open(analyzer: &dyn IAnalyzer) -> Box<dyn ValueTypeBarrierContext + '_> {
    Box::new(GoBarrierContext {
        analyzer,
        go: resolve_analyzer::<GoAnalyzer>(analyzer).expect("Go support belongs to a Go analyzer"),
        native: RefCell::new(None),
        decisions: RefCell::new(HashMap::default()),
        syntax: RefCell::new(HashMap::default()),
        native_refusals: RefCell::new(HashSet::default()),
        observed: RefCell::new(HashMap::default()),
    })
}

impl ValueTypeBarrierContext for GoBarrierContext<'_> {
    fn observed_type(
        &self,
        observation: &BarrierObservation,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ObservedValueType, SemanticProviderError> {
        if request.cancellation.is_cancelled() {
            return Ok(ObservedValueType::Undecided(Cancelled));
        }
        let value = observation
            .point()
            .procedure()
            .value_handle(observation.value())
            .expect("validated observation");
        if let Some(answer) = self.observed.borrow().get(&value) {
            return Ok(answer.clone());
        }
        let semantics = observation.point().procedure().semantics();
        let mapping = semantics
            .source_mapping(
                semantics
                    .value(observation.value())
                    .expect("validated value")
                    .source,
            )
            .expect("validated mapping");
        if mapping.kind != SourceMappingKind::Exact {
            return Ok(ObservedValueType::Undecided(UnavailableObservation));
        }
        let mut file = ProjectFile::new(
            self.go.inner.project().root(),
            mapping.locator.path().as_path(),
        );
        if observation.point().procedure().artifact().key().mount()
            != brokk_bifrost_analysis::analyzer::semantic::WorkspaceMountId::from_root(file.root())
        {
            return Ok(ObservedValueType::Undecided(UnavailableObservation));
        }
        let span = mapping.locator.anchor().span();
        let mut start = span.start_byte() as usize;
        let mut end = span.end_byte() as usize;
        let mut syntax = self.syntax.borrow_mut();
        let mut seen = HashSet::default();
        let answer = loop {
            if request.cancellation.is_cancelled() {
                break ObservedValueType::Undecided(Cancelled);
            }
            if !request.charge_execution_traversal(1) {
                break ObservedValueType::Undecided(BudgetExceeded);
            }
            let prepared = match prepare_value_type_barrier_source(
                &self.go.inner,
                &mut syntax,
                &file,
                request,
            ) {
                Ok(prepared) => prepared,
                Err(reason) => break ObservedValueType::Undecided(reason),
            };
            if seen.is_empty() && !value_type_barrier_source_matches(observation, &prepared) {
                break ObservedValueType::Undecided(UnavailableObservation);
            }
            if seen.is_empty() {
                let Some(reference) = observed_call_binding_reference(observation, &prepared)
                else {
                    break ObservedValueType::Undecided(UnavailableObservation);
                };
                start = reference.start_byte();
                end = reference.end_byte();
            }
            let mut native_reason = None;
            let native = self
                .resolve_native(&file, &prepared, start, end, request, |answer| {
                    let observed = super::type_identity_proof::go_observed_value_type(answer);
                    if let ObservedCarrierType::Type(ObservedValueType::Undecided(reason)) =
                        &observed
                    {
                        native_reason = Some(*reason);
                    }
                    observed
                })?
                .unwrap_or_else(|reason| {
                    ObservedCarrierType::Type(ObservedValueType::Undecided(
                        if reason == IncompleteType {
                            native_reason.unwrap_or(reason)
                        } else {
                            reason
                        },
                    ))
                });
            match native {
                ObservedCarrierType::Type(ty) => break ty,
                ObservedCarrierType::Named(unit) => {
                    if !seen.insert(unit.clone()) {
                        break ObservedValueType::Undecided(IncompleteType);
                    }
                    let declaration =
                        match self.declared_carrier_syntax(&unit, &mut syntax, request) {
                            Ok(declaration) => declaration,
                            Err(reason) => break ObservedValueType::Undecided(reason),
                        };
                    if !declaration.defined {
                        // A selected alias resolves its target through the same native operation.
                        file = declaration.file;
                        start = declaration.start;
                        end = declaration.end;
                        continue;
                    }
                    use brokk_bifrost_analysis::analyzer::semantic::ValueShape;
                    let shape = match declaration.kind {
                        "pointer_type" => Some(ValueShape::Pointer),
                        "array_type" | "implicit_length_array_type" => Some(ValueShape::Array),
                        "slice_type" => Some(ValueShape::Slice),
                        "map_type" => Some(ValueShape::Map),
                        "channel_type" => Some(ValueShape::Channel),
                        "function_type" => Some(ValueShape::Function),
                        "interface_type" => Some(ValueShape::Interface),
                        _ => None,
                    };
                    break shape.map(ObservedValueType::NonNamed).unwrap_or_else(|| {
                        ObservedValueType::Named {
                            canonical: unit.fq_name().to_string(),
                        }
                    });
                }
            }
        };
        self.observed.borrow_mut().insert(value, answer.clone());
        Ok(answer)
    }

    fn classify(
        &self,
        observation: &BarrierObservation,
        predicate: ValueTypePredicate,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ValueTypeBarrierDecision, SemanticProviderError> {
        if request.cancellation.is_cancelled() {
            return Ok(Undecided(Cancelled));
        }
        let value = observation
            .point()
            .procedure()
            .value_handle(observation.value())
            .expect("validated observation");
        let key = (value, predicate);
        if let Some(decision) = self.decisions.borrow().get(&key) {
            return Ok(*decision);
        }
        // The native receiver budget is fixed for this request. Never retry a
        // refused proof just because another observation warmed native caches.
        if self.native_refusals.borrow().contains(&key) {
            return Ok(Undecided(BudgetExceeded));
        }
        let decision = self.classify_observation(observation, predicate, request)?;
        if !matches!(decision, Undecided(BudgetExceeded | Cancelled)) {
            self.decisions.borrow_mut().insert(key, decision);
        }
        Ok(decision)
    }
}

/// Native point queries consume references, whereas an IR binding keeps its
/// declaration locator. Match the observed operand by its frozen call value ID.
fn observed_call_binding_reference<'tree>(
    observation: &BarrierObservation,
    prepared: &'tree PreparedSyntaxTree,
) -> Option<tree_sitter::Node<'tree>> {
    use brokk_bifrost_core::analyzer::tree_walk::single_named_child_matching;
    let operand = brokk_bifrost_analysis::analyzer::semantic::frozen_call_operand_node(
        observation,
        prepared,
        "call_expression",
        |node| {
            node.child_by_field_name("function")?
                .child_by_field_name("operand")
        },
    )?;
    let mut reference = operand;
    while reference.kind() == "parenthesized_expression" {
        reference = single_named_child_matching(reference, |node| node.kind() != "comment")?;
    }
    // A converted/computed value is not its binding's declared type. Only
    // direct binding reads can establish the carrier type through this seam.
    (reference.kind() == "identifier").then_some(reference)
}

impl GoBarrierContext<'_> {
    /// Inspect the declaration selected by native evidence, retaining its source revision.
    fn declared_carrier_syntax(
        &self,
        unit: &brokk_bifrost_core::analyzer::model::CodeUnit,
        syntax: &mut HashMap<ProjectFile, Arc<PreparedSyntaxTree>>,
        request: &mut SemanticRequest<'_>,
    ) -> Result<DeclaredCarrierSyntax, ValueTypeBarrierReason> {
        let prepared =
            prepare_value_type_barrier_source(&self.go.inner, syntax, unit.source(), request)?;
        if !self
            .go
            .inner
            .source_matches_selected_native_content(unit.source(), prepared.source())
        {
            return Err(UnavailableObservation);
        }
        let ranges = self.analyzer.ranges_of(unit);
        let [range] = ranges.as_slice() else {
            return Err(IncompleteType);
        };
        let Some(mut declaration) = prepared
            .tree()
            .root_node()
            .named_descendant_for_byte_range(range.start_byte, range.end_byte)
        else {
            return Err(IncompleteType);
        };
        if declaration.kind() == "type_declaration" {
            let mut cursor = declaration.walk();
            let mut specs = declaration
                .named_children(&mut cursor)
                .filter(|node| matches!(node.kind(), "type_spec" | "type_alias"));
            let Some(spec) = specs.next() else {
                return Err(IncompleteType);
            };
            if specs.next().is_some() {
                return Err(IncompleteType);
            }
            declaration = spec;
        }
        while !matches!(declaration.kind(), "type_spec" | "type_alias") {
            if !request.charge_execution_traversal(1) {
                return Err(BudgetExceeded);
            }
            if request.cancellation.is_cancelled() {
                return Err(Cancelled);
            }
            // A type parameter's constraint cannot establish an exact carrier type.
            if matches!(
                declaration.kind(),
                "type_parameter_declaration" | "type_parameter_list"
            ) {
                return Err(UnknownType);
            }
            let Some(parent) = declaration.parent() else {
                return Err(IncompleteType);
            };
            declaration = parent;
        }
        let Some(underlying) = declaration.child_by_field_name("type") else {
            return Err(IncompleteType);
        };
        Ok(DeclaredCarrierSyntax {
            file: unit.source().clone(),
            start: underlying.start_byte(),
            end: underlying.end_byte(),
            kind: underlying.kind(),
            defined: declaration.kind() == "type_spec",
        })
    }

    fn resolve_native<T>(
        &self,
        file: &ProjectFile,
        prepared: &PreparedSyntaxTree,
        start: usize,
        end: usize,
        request: &mut SemanticRequest<'_>,
        mut inspect: impl FnMut(&brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedNativeReferenceTypes) -> T,
    ) -> Result<Result<T, ValueTypeBarrierReason>, SemanticProviderError> {
        let Some(node) = prepared
            .tree()
            .root_node()
            .named_descendant_for_byte_range(start, end)
        else {
            return Ok(Err(UnavailableObservation));
        };
        if node.start_byte() != start || node.end_byte() != end || node.has_error() {
            return Ok(Err(UnavailableObservation));
        }
        let go = self.go;
        let mut selected_request = self.native.borrow_mut();
        if selected_request.is_none() {
            *selected_request = match GoNativePointRequest::open_for_file(
                go,
                file,
                self.analyzer.semantic_model_overlay(),
                request.cancellation,
            )
            .map_err(|error| SemanticProviderError::source_access(error.to_string()))?
            {
                GoNativePointRequestOpen::Ready(operation) => Some(operation),
                GoNativePointRequestOpen::Cancelled => return Ok(Err(Cancelled)),
                GoNativePointRequestOpen::Unavailable { .. } => {
                    return Ok(Err(IncompleteType));
                }
            };
        }
        let site = ResolvedReferenceSite {
            path: brokk_bifrost_core::path_utils::rel_path_string(file),
            text: prepared.source()[start..end].to_owned(),
            range: Range {
                start_byte: start,
                end_byte: end,
                start_line: node.start_position().row,
                end_line: node.end_position().row,
            },
            focus_start_byte: start,
            focus_end_byte: end,
        };
        let mut selected = None;
        let result = selected_request
            .as_mut()
            .expect("opened native operation")
            .resolve_type_with_evidence(
                BoundedReceiverQuery {
                    analyzer: self.analyzer,
                    file,
                    source: prepared.source(),
                    tree: Some(prepared.tree()),
                    site: &site,
                    budget: ReceiverAnalysisBudget::default(),
                    cancellation: Some(request.cancellation),
                },
                |answer| selected = Some(inspect(answer)),
            );
        let work = match &result {
            BoundedResolution::Cancelled { work }
            | BoundedResolution::Exceeded { work, .. }
            | BoundedResolution::Complete { work, .. } => work,
        };
        request.budget.charge_work(SemanticWork {
            events: work.scope_nodes,
            ..Default::default()
        });
        if !request.charge_execution_traversal(work.scope_nodes) {
            return Ok(Err(BudgetExceeded));
        }
        match result {
            BoundedResolution::Cancelled { .. } => return Ok(Err(Cancelled)),
            BoundedResolution::Exceeded { .. } => {
                return Ok(Err(BudgetExceeded));
            }
            BoundedResolution::Complete { value, .. } => {
                // NoType is expected when following a selected declaration's type syntax.
                if !matches!(
                    value.status,
                    TypeLookupStatus::Resolved | TypeLookupStatus::NoType
                ) {
                    return Ok(Err(IncompleteType));
                }
            }
        }
        Ok(selected.ok_or(UnknownType))
    }

    fn classify_observation(
        &self,
        observation: &BarrierObservation,
        predicate: ValueTypePredicate,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ValueTypeBarrierDecision, SemanticProviderError> {
        let go = self.go;
        let semantics = observation.point().procedure().semantics();
        let value = semantics
            .value(observation.value())
            .expect("validated observation value");
        let mapping = semantics
            .source_mapping(value.source)
            .expect("validated source mapping");
        if mapping.kind != SourceMappingKind::Exact {
            return Ok(Undecided(UnavailableObservation));
        }
        let mut file =
            ProjectFile::new(go.inner.project().root(), mapping.locator.path().as_path());
        if observation.point().procedure().artifact().key().mount()
            != brokk_bifrost_analysis::analyzer::semantic::WorkspaceMountId::from_root(file.root())
        {
            return Ok(Undecided(UnavailableObservation));
        }
        let span = mapping.locator.anchor().span();
        let mut start = span.start_byte() as usize;
        let mut end = span.end_byte() as usize;
        let mut syntax = self.syntax.borrow_mut();
        let mut seen = Vec::new();
        loop {
            if request.cancellation.is_cancelled() {
                return Ok(Undecided(Cancelled));
            }
            if !request.charge_execution_traversal(1) {
                return Ok(Undecided(BudgetExceeded));
            }
            request.budget.charge_work(SemanticWork {
                events: 1,
                ..Default::default()
            });
            let prepared =
                match prepare_value_type_barrier_source(&go.inner, &mut syntax, &file, request) {
                    Ok(prepared) => prepared,
                    Err(reason) => return Ok(Undecided(reason)),
                };
            if seen.is_empty() && !value_type_barrier_source_matches(observation, &prepared) {
                return Ok(Undecided(UnavailableObservation));
            }
            let Some(node) = prepared
                .tree()
                .root_node()
                .named_descendant_for_byte_range(start, end)
            else {
                return Ok(Undecided(UnavailableObservation));
            };
            if node.start_byte() != start || node.end_byte() != end || node.has_error() {
                return Ok(Undecided(UnavailableObservation));
            }
            let carrier =
                match self.resolve_native(&file, &prepared, start, end, request, |answer| {
                    go_selected_carrier_type(answer, predicate)
                })? {
                    Ok(carrier) => carrier,
                    Err(reason) => {
                        if reason == BudgetExceeded {
                            let value = observation
                                .point()
                                .procedure()
                                .value_handle(observation.value())
                                .expect("validated observation");
                            self.native_refusals.borrow_mut().insert((value, predicate));
                        }
                        return Ok(Undecided(reason));
                    }
                };
            match carrier {
                CarrierType::Decision(decision) => return Ok(decision),
                CarrierType::Named(unit) => {
                    if seen.contains(&unit) {
                        return Ok(Undecided(IncompleteType));
                    }
                    seen.push(unit.clone());
                    let declaration =
                        match self.declared_carrier_syntax(&unit, &mut syntax, request) {
                            Ok(declaration) => declaration,
                            Err(reason) => return Ok(Undecided(reason)),
                        };
                    match declaration.kind {
                        "interface_type" => return Ok(Undecided(UnknownType)),
                        "type_identifier" | "qualified_type" => {}
                        _ => return Ok(ProvenNonMatch),
                    }
                    if declaration.defined && predicate == ValueTypePredicate::IntrinsicBool {
                        return Ok(ProvenNonMatch);
                    }
                    file = declaration.file;
                    start = declaration.start;
                    end = declaration.end;
                }
            }
        }
    }
}
