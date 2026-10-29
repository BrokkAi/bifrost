//! Request-local proofs from selected Rust type identities and enum syntax.

use std::cell::RefCell;
use std::sync::Arc;

use crate::analyzer::rust::RustAnalyzer;

use crate::analyzer::rust::native_points::RustDefinitionOperationFactory;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_analysis::analyzer::resolution::batch::ResolutionBatchMetrics;

use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionTypeRef;

use crate::analyzer::semantic::{
    BarrierObservation, SemanticProviderError, SemanticRequest, SemanticWork, SourceMappingKind,
    ValueHandle, ValueTypeBarrierContext, ValueTypeBarrierDecision, ValueTypeBarrierReason,
    ValueTypePredicate, prepare_value_type_barrier_source, value_type_barrier_source_matches,
};
use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedSemanticLocator;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionContextMetrics;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionLocated;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedRustCallerReferenceOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedRustReferenceAnswer;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedRustSourceDefinition;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedRustTypeProjection;

use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_core::analyzer::resolution_facts::IntrinsicTypeKind;
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_rust::selected_context::RustSelectedActivation;

use ValueTypeBarrierDecision::{ProvenMatch, ProvenNonMatch, Undecided};
use ValueTypeBarrierReason::{
    AmbiguousType, BudgetExceeded, Cancelled, IncompleteEnumSurface, IncompleteType,
    UnavailableObservation, UnknownType,
};

struct RustBarrierContext<'a> {
    rust: &'a RustAnalyzer,
    state: RefCell<RustBarrierState<'a>>,
}

struct RustBarrierState<'a> {
    operation: Option<Box<SelectedResolutionOperation<'a, 'a>>>,
    unavailable: ValueTypeBarrierReason,
    values: HashMap<(ValueHandle, ValueTypePredicate), ValueTypeBarrierDecision>,
    // Native refusals use every receiver limit. Semantic refusals additionally
    // retain the remaining resident row/byte limits that caused them.
    budget_failures: HashSet<(ValueHandle, ValueTypePredicate, ReceiverAnalysisBudget)>,
    semantic_failures: HashSet<(ValueHandle, ValueTypePredicate, SemanticWork)>,
    distinct_values: HashSet<ValueHandle>,
    budget_hits: usize,
    budget_refusals: usize,
    types: HashMap<(ResolutionTypeRef, ValueTypePredicate), ValueTypeBarrierDecision>,
    syntax: HashMap<ProjectFile, Arc<PreparedSyntaxTree>>,
    observation_hits: usize,
    observation_misses: usize,
    native_type_lookups: usize,
    budget_short_circuits: usize,
}

pub(crate) fn open<'a>(
    analyzer: &'a dyn IAnalyzer,
    cancellation: &CancellationToken,
) -> Result<Box<dyn ValueTypeBarrierContext + 'a>, SemanticProviderError> {
    let rust = resolve_analyzer::<RustAnalyzer>(analyzer)
        .expect("Rust support belongs to a Rust analyzer");
    let mut unavailable = if cancellation.is_cancelled() {
        Cancelled
    } else {
        IncompleteType
    };
    let operation = match RustDefinitionOperationFactory::new(analyzer, cancellation) {
        Some(factory) => match factory
            .open(cancellation)
            .map_err(|error| SemanticProviderError::source_access(error.to_string()))?
        {
            SelectedResolutionOperationOpenOutcome::Ready(operation) => Some(operation),
            SelectedResolutionOperationOpenOutcome::Cancelled => {
                unavailable = Cancelled;
                None
            }
            SelectedResolutionOperationOpenOutcome::Unavailable(_)
            | SelectedResolutionOperationOpenOutcome::Stale(_) => None,
        },
        None => None,
    };
    Ok(Box::new(RustBarrierContext {
        rust,
        state: RefCell::new(RustBarrierState {
            operation,
            unavailable,
            values: HashMap::default(),
            budget_failures: HashSet::default(),
            semantic_failures: HashSet::default(),
            distinct_values: HashSet::default(),
            budget_hits: 0,
            budget_refusals: 0,
            types: HashMap::default(),
            syntax: HashMap::default(),
            observation_hits: 0,
            observation_misses: 0,
            native_type_lookups: 0,
            budget_short_circuits: 0,
        }),
    }))
}

impl ValueTypeBarrierContext for RustBarrierContext<'_> {
    fn classify(
        &self,
        observation: &BarrierObservation,
        predicate: ValueTypePredicate,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ValueTypeBarrierDecision, SemanticProviderError> {
        if request.cancellation.is_cancelled() {
            return Ok(Undecided(Cancelled));
        }
        let mut state = self.state.borrow_mut();
        let value = observation
            .point()
            .procedure()
            .value_handle(observation.value())
            .expect("observation value was validated at construction");
        state.distinct_values.insert(value.clone());
        let key = (value, predicate);
        if let Some(&decision) = state.values.get(&key) {
            // Native lookup reads this value's immutable source mapping, not
            // the point or phase at which propagation observes it. The handle
            // includes materialization identity; another procedure body cannot
            // reuse this proof merely because its dense ValueId is equal.
            // The proof was validated before entering this request's memo.
            state.observation_hits += 1;
            return Ok(decision);
        }
        let semantic_key = (key.0.clone(), predicate, request.budget.remaining());
        if state.semantic_failures.contains(&semantic_key)
            || state.budget_failures.contains(&(
                key.0.clone(),
                predicate,
                ReceiverAnalysisBudget::default(),
            ))
        {
            // One bounded attempt per value/predicate/full budget in this query.
            // Later native cache warming deliberately does not retry that budget.
            state.observation_hits += 1;
            state.budget_hits += 1;
            return Ok(Undecided(BudgetExceeded));
        }
        state.observation_misses += 1;
        let decision = self.classify_observation(&mut state, observation, predicate, request)?;
        let decision = if let Some(operation) = state.operation.as_mut() {
            match operation
                .finish_native(
                    decision,
                    &ResolutionCompletion::Complete,
                    request.cancellation,
                )
                .map_err(|error| SemanticProviderError::source_access(error.to_string()))?
            {
                SelectedResolutionOperationOutcome::Native(decision) => decision,
                SelectedResolutionOperationOutcome::Cancelled(_) => Undecided(Cancelled),
                SelectedResolutionOperationOutcome::Stale(_)
                | SelectedResolutionOperationOutcome::Unavailable(_) => Undecided(IncompleteType),
            }
        } else {
            decision
        };
        if decision == Undecided(BudgetExceeded) {
            state.semantic_failures.insert(semantic_key);
        } else if decision != Undecided(Cancelled) {
            state.values.insert(key, decision);
        }
        Ok(decision)
    }
}

impl Drop for RustBarrierContext<'_> {
    fn drop(&mut self) {
        let state = self.state.get_mut();
        brokk_bifrost_core::profiling::note_with(|| {
            format!(
                "taint.barriers.rust.counts operation_opens={} observation_hits={} observation_misses={} value_predicate_keys={} type_predicate_keys={} native_type_lookups={} budget_short_circuits={} distinct_value_keys={} budget_refusals={} budget_memo_hits={} native_failure_keys={} prepared_files={}",
                usize::from(state.operation.is_some()),
                state.observation_hits,
                state.observation_misses,
                state.values.len(),
                state.types.len(),
                state.native_type_lookups,
                state.budget_short_circuits,
                state.distinct_values.len(),
                state.budget_refusals,
                state.budget_hits,
                state.budget_failures.len(),
                state.syntax.len(),
            )
        });
    }
}

impl RustBarrierContext<'_> {
    fn classify_observation(
        &self,
        state: &mut RustBarrierState<'_>,
        observation: &BarrierObservation,
        predicate: ValueTypePredicate,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ValueTypeBarrierDecision, SemanticProviderError> {
        let procedure = observation.point().procedure();
        let semantics = procedure.semantics();
        let value = semantics
            .value(observation.value())
            .expect("observation value was validated at construction");
        let mapping = semantics
            .source_mapping(value.source)
            .expect("validated semantic value has a source mapping");
        if mapping.kind != SourceMappingKind::Exact {
            return Ok(Undecided(UnavailableObservation));
        }
        let Some(operation) = state.operation.as_mut() else {
            return Ok(Undecided(state.unavailable));
        };
        let file = ProjectFile::new(
            self.rust.inner.project().root(),
            mapping.locator.path().as_path(),
        );
        if procedure.artifact().key().mount()
            != crate::analyzer::semantic::WorkspaceMountId::from_root(file.root())
        {
            return Ok(Undecided(UnavailableObservation));
        }
        let prepared = match prepare_value_type_barrier_source(
            &self.rust.inner,
            &mut state.syntax,
            &file,
            request,
        ) {
            Ok(prepared) => prepared,
            Err(reason) => return Ok(Undecided(reason)),
        };
        let revision_matches = value_type_barrier_source_matches(observation, &prepared);
        if !revision_matches
            || !self
                .rust
                .inner
                .source_matches_selected_native_content(&file, prepared.source())
        {
            return Ok(Undecided(UnavailableObservation));
        }
        let span = mapping.locator.anchor().span();
        let Some(expression) = prepared
            .tree()
            .root_node()
            .named_descendant_for_byte_range(span.start_byte() as usize, span.end_byte() as usize)
        else {
            return Ok(Undecided(UnavailableObservation));
        };
        if expression.start_byte() != span.start_byte() as usize
            || expression.end_byte() != span.end_byte() as usize
            || expression.has_error()
            || expression.is_missing()
        {
            return Ok(Undecided(UnavailableObservation));
        }
        let condition = brokk_bifrost_rust::lexical_scope::rust_effective_cfg_condition(
            expression,
            prepared.source(),
        );
        if condition != brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition::Always {
            match operation
                .rust_cfg_activation_for_caller_under_site_cfg(
                    file.rel_path(),
                    &condition,
                    request.cancellation,
                )
                .map_err(|error| SemanticProviderError::source_access(error.to_string()))?
            {
                Some((RustSelectedActivation::Active, false)) => {}
                None => return Ok(Undecided(Cancelled)),
                _ => return Ok(Undecided(IncompleteType)),
            }
        }
        let Some(name) = brokk_bifrost_rust::structural::expression_name_node(expression) else {
            return Ok(Undecided(UnknownType));
        };
        let locator = SelectedSemanticLocator::for_reference_range(
            "rust",
            mapping.locator.path().as_str(),
            name.start_byte(),
            name.end_byte(),
        );
        let mut metrics = ResolutionBatchMetrics::default();
        let budget = ReceiverAnalysisBudget::default();
        let failure_key = (
            procedure
                .value_handle(observation.value())
                .expect("an observation value is live"),
            predicate,
            budget,
        );
        if state.budget_failures.contains(&failure_key) {
            state.budget_hits += 1;
            return Ok(Undecided(BudgetExceeded));
        }
        state.native_type_lookups += 1;
        let answer = operation
            .resolve_rust_type_for_caller_bounded(
                file.rel_path(),
                &locator,
                budget,
                request.cancellation,
                &mut SelectedResolutionContextMetrics,
                &mut metrics,
            )
            .map_err(|error| SemanticProviderError::source_access(error.to_string()))?;
        let (decision, work) = match answer {
            BoundedResolution::Cancelled { work } => (Undecided(Cancelled), work),
            BoundedResolution::Exceeded { work, .. } => {
                state.budget_refusals += 1;
                state.budget_failures.insert(failure_key);
                (Undecided(BudgetExceeded), work)
            }
            BoundedResolution::Complete { value, work } => (
                match value {
                    SelectedRustCallerReferenceOutcome::Operation(
                        SelectedResolutionOperationOutcome::Native(
                            SelectedResolutionLocated::Found(answers),
                        ),
                    ) => self.classify_answers(
                        operation,
                        &mut state.types,
                        &mut state.syntax,
                        &answers,
                        predicate,
                        request,
                    )?,
                    SelectedRustCallerReferenceOutcome::Operation(
                        SelectedResolutionOperationOutcome::Native(
                            SelectedResolutionLocated::Missing,
                        ),
                    ) => Undecided(UnknownType),
                    SelectedRustCallerReferenceOutcome::Operation(
                        SelectedResolutionOperationOutcome::Cancelled(_),
                    ) => Undecided(Cancelled),
                    _ => Undecided(IncompleteType),
                },
                work,
            ),
        };
        request.budget.charge_work(SemanticWork {
            events: work.scope_nodes,
            ..Default::default()
        });
        if !request.charge_execution_traversal(work.scope_nodes) {
            return Ok(Undecided(BudgetExceeded));
        }
        Ok(decision)
    }

    fn classify_answers(
        &self,
        operation: &mut SelectedResolutionOperation<'_, '_>,
        types: &mut HashMap<(ResolutionTypeRef, ValueTypePredicate), ValueTypeBarrierDecision>,
        syntax: &mut HashMap<ProjectFile, Arc<PreparedSyntaxTree>>,
        answers: &[SelectedRustReferenceAnswer<SelectedRustTypeProjection>],
        predicate: ValueTypePredicate,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ValueTypeBarrierDecision, SemanticProviderError> {
        let mut selection =
            brokk_bifrost_analysis::analyzer::native_points::BarrierValueTypeSelection::default();
        let mut selected = None;
        for answer in answers {
            if answer.resolution.binding().targets().len() > 1 {
                return Ok(Undecided(AmbiguousType));
            }
            if !answer.macro_expansion_gaps.is_empty() || !answer.generated_surface_gaps.is_empty()
            {
                return Ok(Undecided(IncompleteEnumSurface));
            }
            let ty = match selection.observe(&answer.resolution, None) {
                Ok(Some(ty)) => ty,
                Ok(None) => continue,
                Err(reason) => return Ok(Undecided(reason)),
            };
            if selected.is_none() {
                selected = Some((ty, &answer.projection));
            }
        }
        if let Err(reason) = selection.finish() {
            return Ok(Undecided(reason));
        }
        let Some((ty, projection)) = selected else {
            return Ok(Undecided(UnknownType));
        };
        if ty.indirection() != 0 {
            return Ok(ProvenNonMatch);
        }
        if let Some(decision) = types.get(&(ty, predicate)) {
            return Ok(*decision);
        }
        let decision = if let Some(intrinsic) = projection
            .intrinsic_types
            .iter()
            .find(|descriptor| descriptor.identity() == ty.identity())
        {
            if intrinsic.kind() == IntrinsicTypeKind::Primitive
                && match predicate {
                    ValueTypePredicate::IntrinsicBool => intrinsic.spelling() == "bool",
                    ValueTypePredicate::IntrinsicNumeric => matches!(
                        intrinsic.spelling(),
                        "i8" | "i16"
                            | "i32"
                            | "i64"
                            | "i128"
                            | "isize"
                            | "u8"
                            | "u16"
                            | "u32"
                            | "u64"
                            | "u128"
                            | "usize"
                            | "f16"
                            | "f32"
                            | "f64"
                            | "f128"
                    ),
                    ValueTypePredicate::FieldlessEnum => false,
                }
            {
                ProvenMatch
            } else {
                ProvenNonMatch
            }
        } else if let Some((_, definition)) = projection
            .nominal_types
            .iter()
            .find(|(identity, _)| *identity == ty.identity())
        {
            match definition {
                SelectedRustSourceDefinition::Unit(unit) => {
                    let prepared = match prepare_value_type_barrier_source(
                        &self.rust.inner,
                        syntax,
                        unit.source(),
                        request,
                    ) {
                        Ok(prepared) => prepared,
                        Err(reason) => return Ok(Undecided(reason)),
                    };
                    if !self
                        .rust
                        .inner
                        .source_matches_selected_native_content(unit.source(), prepared.source())
                    {
                        return Ok(Undecided(IncompleteType));
                    }
                    let ranges = self.rust.ranges_limited(unit, 2);
                    let [range] = ranges.rows.as_slice() else {
                        return Ok(Undecided(IncompleteEnumSurface));
                    };
                    if !ranges.complete {
                        return Ok(Undecided(IncompleteEnumSurface));
                    }
                    let Some(mut node) = prepared
                        .tree()
                        .root_node()
                        .named_descendant_for_byte_range(range.start_byte, range.end_byte)
                    else {
                        return Ok(Undecided(IncompleteEnumSurface));
                    };
                    while !matches!(
                        node.kind(),
                        "enum_item" | "struct_item" | "union_item" | "trait_item" | "type_item"
                    ) {
                        let Some(parent) = node.parent() else {
                            return Ok(Undecided(IncompleteEnumSurface));
                        };
                        node = parent;
                    }
                    if node.kind() == "type_item" {
                        return Ok(Undecided(IncompleteType));
                    }
                    if !enum_attributes_are_source_preserving(node, prepared.source()) {
                        return Ok(Undecided(IncompleteEnumSurface));
                    }
                    if node.kind() != "enum_item" || predicate != ValueTypePredicate::FieldlessEnum
                    {
                        ProvenNonMatch
                    } else {
                        enum_surface(operation, unit.source(), node, prepared.source(), request)?
                    }
                }
                // Primitive identity is proved by the intrinsic descriptor above.
                // A universe entry without that descriptor supplies no source
                // declaration from which to prove either predicate.
                SelectedRustSourceDefinition::UniverseEntry => Undecided(IncompleteType),
                SelectedRustSourceDefinition::Lexical(_)
                | SelectedRustSourceDefinition::WithoutUnit { .. } => {
                    Undecided(IncompleteEnumSurface)
                }
            }
        } else {
            Undecided(IncompleteType)
        };
        if !matches!(decision, Undecided(BudgetExceeded | Cancelled)) {
            types.insert((ty, predicate), decision);
        }
        Ok(decision)
    }
}

fn enum_surface(
    operation: &SelectedResolutionOperation<'_, '_>,
    file: &ProjectFile,
    node: tree_sitter::Node<'_>,
    source: &str,
    request: &mut SemanticRequest<'_>,
) -> Result<ValueTypeBarrierDecision, SemanticProviderError> {
    if node.has_error() || node.is_missing() || !enum_attributes_are_source_preserving(node, source)
    {
        return Ok(Undecided(IncompleteEnumSurface));
    }
    let Some(body) = node.child_by_field_name("body") else {
        return Ok(Undecided(IncompleteEnumSurface));
    };
    let mut cursor = body.walk();
    for child in body.named_children(&mut cursor) {
        if request.cancellation.is_cancelled() {
            return Ok(Undecided(Cancelled));
        }
        request.budget.charge_work(SemanticWork {
            events: 1,
            ..Default::default()
        });
        if !request.charge_execution_traversal(1) {
            return Ok(Undecided(BudgetExceeded));
        }
        if !enum_attributes_are_source_preserving(child, source) {
            return Ok(Undecided(IncompleteEnumSurface));
        }
        match child.kind() {
            "line_comment" | "block_comment" | "attribute_item" => continue,
            "enum_variant" => {}
            _ => return Ok(Undecided(IncompleteEnumSurface)),
        }
        let condition =
            brokk_bifrost_rust::lexical_scope::rust_effective_cfg_condition(child, source);
        if condition != brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition::Always {
            match operation
                .rust_cfg_activation_for_caller_under_site_cfg(
                    file.rel_path(),
                    &condition,
                    request.cancellation,
                )
                .map_err(|error| SemanticProviderError::source_access(error.to_string()))?
            {
                Some((RustSelectedActivation::Active, false)) => {}
                None => return Ok(Undecided(Cancelled)),
                _ => return Ok(Undecided(IncompleteEnumSurface)),
            }
        }
        if child.child_by_field_name("name").is_none() {
            return Ok(Undecided(IncompleteEnumSurface));
        }
        if let Some(fields) = child.child_by_field_name("body") {
            if !matches!(
                fields.kind(),
                "ordered_field_declaration_list" | "field_declaration_list"
            ) {
                return Ok(Undecided(IncompleteEnumSurface));
            }
            let mut fields_cursor = fields.walk();
            for field in fields.named_children(&mut fields_cursor) {
                if !matches!(
                    field.kind(),
                    "line_comment" | "block_comment" | "attribute_item"
                ) {
                    return Ok(ProvenNonMatch);
                }
            }
        }
    }
    Ok(ProvenMatch)
}

// Attribute macros can replace the item. Built-in attributes and derive do
// not replace the enum's variant inventory. Unknown attributes stay undecided.
fn enum_attributes_are_source_preserving(node: tree_sitter::Node<'_>, source: &str) -> bool {
    brokk_bifrost_rust::syntax::outer_attributes(node).all(|item| {
        let Some(path) = item
            .named_child(0)
            .and_then(|attribute| attribute.named_child(0))
        else {
            return false;
        };
        matches!(
            path.utf8_text(source.as_bytes()),
            Ok("cfg"
                | "derive"
                | "repr"
                | "doc"
                | "allow"
                | "warn"
                | "deny"
                | "forbid"
                | "deprecated"
                | "must_use"
                | "non_exhaustive")
        )
    })
}

#[cfg(test)]
mod tests {

    use crate::analyzer::rust::value_type_barriers::*;

    use crate::analyzer::semantic::SemanticBudget;
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_core::analyzer::model::Language;

    #[test]
    fn value_type_barrier_rust_grammar_and_native_identity_boundary() {
        let source = r#"
type AliasBool = bool;
struct Bool;
struct String;
enum State { Ready = 1, Done = 2 }
enum EmptyBodies { Tuple(), Record {} }
enum Payload { Unit, Data(u8) }
mod shadow {
    struct bool;
    fn run(shadowed: bool) { super::observe(shadowed); }
}
mod left { pub struct Ambiguous; }
mod right { pub struct Ambiguous; }
use left::*;
use right::*;
fn observe<T>(_: T) {}
fn run(flag: bool, alias: AliasBool, lookalike: Bool, state: State,
       empty: EmptyBodies, payload: Payload, string: String, ambiguous: Ambiguous,
       reference: &bool, container: Option<bool>) {
    observe(flag); observe(alias); observe(lookalike); observe(state);
    observe(empty); observe(payload); observe(string); observe(ambiguous);
    observe(reference); observe(container);
}
"#;
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"barrier-boundary\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source)
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let cancellation = CancellationToken::default();
        let factory = RustDefinitionOperationFactory::new(&rust, &cancellation).unwrap();
        let SelectedResolutionOperationOpenOutcome::Ready(mut operation) =
            factory.open(&cancellation).unwrap()
        else {
            panic!("native operation must be admitted");
        };
        let context = RustBarrierContext {
            rust: &rust,
            state: RefCell::new(RustBarrierState {
                operation: None,
                unavailable: IncompleteType,
                values: HashMap::default(),
                budget_failures: HashSet::default(),
                semantic_failures: HashSet::default(),
                distinct_values: HashSet::default(),
                budget_hits: 0,
                budget_refusals: 0,
                types: HashMap::default(),
                syntax: HashMap::default(),
                observation_hits: 0,
                observation_misses: 0,
                native_type_lookups: 0,
                budget_short_circuits: 0,
            }),
        };
        let mut budget = SemanticBudget::default();
        let mut request = SemanticRequest::new(&mut budget, &cancellation);
        let mut types = HashMap::default();
        let mut syntax = HashMap::default();
        let mut failures = Vec::new();
        for (name, predicate, expected) in [
            (
                "shadowed",
                ValueTypePredicate::IntrinsicBool,
                ProvenNonMatch,
            ),
            ("flag", ValueTypePredicate::IntrinsicBool, ProvenMatch),
            ("alias", ValueTypePredicate::IntrinsicBool, ProvenMatch),
            (
                "lookalike",
                ValueTypePredicate::IntrinsicBool,
                ProvenNonMatch,
            ),
            ("state", ValueTypePredicate::FieldlessEnum, ProvenMatch),
            ("empty", ValueTypePredicate::FieldlessEnum, ProvenMatch),
            ("payload", ValueTypePredicate::FieldlessEnum, ProvenNonMatch),
            ("string", ValueTypePredicate::FieldlessEnum, ProvenNonMatch),
            (
                "ambiguous",
                ValueTypePredicate::IntrinsicBool,
                Undecided(AmbiguousType),
            ),
            (
                "reference",
                ValueTypePredicate::IntrinsicBool,
                ProvenNonMatch,
            ),
            (
                "container",
                ValueTypePredicate::IntrinsicBool,
                ProvenNonMatch,
            ),
        ] {
            let start = source.rfind(&format!("observe({name})")).unwrap() + "observe(".len();
            let locator = SelectedSemanticLocator::for_reference_range(
                "rust",
                "src/lib.rs",
                start,
                start + name.len(),
            );
            let answer = operation
                .resolve_rust_type_for_caller_bounded(
                    std::path::Path::new("src/lib.rs"),
                    &locator,
                    Default::default(),
                    &cancellation,
                    &mut SelectedResolutionContextMetrics,
                    &mut ResolutionBatchMetrics::default(),
                )
                .unwrap();
            let BoundedResolution::Complete {
                value:
                    SelectedRustCallerReferenceOutcome::Operation(
                        SelectedResolutionOperationOutcome::Native(
                            SelectedResolutionLocated::Found(answers),
                        ),
                    ),
                ..
            } = answer
            else {
                panic!("{name}: native type answer unavailable");
            };
            let decision = context
                .classify_answers(
                    &mut operation,
                    &mut types,
                    &mut syntax,
                    &answers,
                    predicate,
                    &mut request,
                )
                .unwrap();
            if decision != expected {
                failures.push((name, decision, expected));
            }
        }
        // The grammar does not promise that a macro token tree is the complete
        // variant inventory, even when a macro could expand to unit variants.
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let generated = "enum Generated { variants!() }";
        let tree = parser.parse(generated, None).unwrap();
        let node = tree.root_node().named_child(0).unwrap();
        assert_eq!(
            enum_surface(
                &operation,
                &fixture.file("src/lib.rs"),
                node,
                generated,
                &mut request
            )
            .unwrap(),
            Undecided(IncompleteEnumSurface)
        );
        assert!(
            failures.is_empty(),
            "native identity decisions: {failures:?}"
        );
    }
}
