//! Per-procedure normal-return profiles projected from lowered semantic IR.
//!
//! Python keeps its syntax-aware profile (implicit `None`, tuple arities,
//! generator status) in `python_rule_facts`. Every other lowered language
//! shares the IR-only profile here: it reads each reachable
//! `ProcedureReturn` event, follows the returned value one value-flow step to
//! its producer, and reports whether every normal return yields the same
//! compile-time constant. A return whose value is not a structured constant
//! leaves the profile `unknown` and typed incomplete.

use super::python_rule_facts::{PythonRuleFactValue, make_row};
use super::*;
use crate::analyzer::semantic::{
    ProgramPointId, SemanticEffect, SemanticGapImpact, SemanticGapKind, SemanticValueKind,
    ValueFlowKind, ValueId,
};

const RETURN_VALUE_NOT_CONSTANT: &str = "return_value_not_constant";
const VALUELESS_RETURN_MIXED: &str = "valueless_return_mixed_with_value";
const EXIT_WITHOUT_RETURN: &str = "normal_exit_without_return_event";
const ASYNC_OR_GENERATOR: &str = "async_or_generator_procedure";

/// Reachability over the procedure's own control edges from its entry.
/// It over-approximates executable points: a branch that a constant guard
/// excludes stays reachable.
pub(super) fn reachable_points(procedure: &SemanticProcedureValue) -> Vec<bool> {
    let semantics = procedure.handle.semantics();
    let mut reachable = vec![false; semantics.points().len()];
    let mut stack = vec![semantics.entry_point()];
    while let Some(point) = stack.pop() {
        let index = point.index();
        if std::mem::replace(&mut reachable[index], true) {
            continue;
        }
        stack.extend(
            semantics
                .successor_edges(point)
                .map(|(_, edge)| edge.target_point),
        );
    }
    reachable
}

pub(super) fn procedure_return_profile_expansions(
    analyzer: &dyn IAnalyzer,
    traversal: &mut EnvironmentTraversalCache,
    procedure: &SemanticProcedureValue,
) -> Vec<PipelineExpansion> {
    let language = procedure.handle.artifact().key().language().language();
    if language == Language::Python {
        return super::python_rule_facts::procedure_return_profile_expansions(
            analyzer, traversal, procedure,
        );
    }
    vec![pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(
        lowered_return_profile(procedure, language),
    )))]
}

/// A structured compile-time constant a normal return can yield. Integers
/// normalize so an unsigned and a non-negative signed payload compare equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReturnConstant {
    Boolean(bool),
    Null,
    Unsigned(u128),
    Negative(i128),
    Float(u64),
}

impl ReturnConstant {
    fn of(kind: &SemanticValueKind) -> Option<Self> {
        Some(match kind {
            SemanticValueKind::Boolean(value) => Self::Boolean(*value),
            SemanticValueKind::Null => Self::Null,
            SemanticValueKind::UnsignedInteger(value) => Self::Unsigned(*value),
            SemanticValueKind::SignedInteger(value) => match u128::try_from(*value) {
                Ok(value) => Self::Unsigned(value),
                Err(_) => Self::Negative(*value),
            },
            SemanticValueKind::FloatingPoint { bits } => Self::Float(*bits),
            _ => return None,
        })
    }

    fn render(self) -> String {
        match self {
            Self::Boolean(value) => value.to_string(),
            Self::Null => "null".to_string(),
            Self::Unsigned(value) => value.to_string(),
            Self::Negative(value) => value.to_string(),
            Self::Float(bits) => format!("{:?}", f64::from_bits(bits)),
        }
    }
}

enum ReturnedValue {
    Constant(ReturnConstant),
    Opaque,
}

/// The constant a returned value carries: the value itself when the
/// producer published it as a constant, otherwise the constant reached by
/// walking value-preserving definitions back through the return point. A
/// return lowers its operand, any by-value carry and the return value at one
/// point, so the walk never needs another point.
fn returned_value(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    events: &[crate::analyzer::semantic::SemanticEvent],
    mut value: ValueId,
) -> ReturnedValue {
    for _ in 0..=events.len() {
        if let Some(constant) = semantics
            .value(value)
            .and_then(|value| ReturnConstant::of(&value.kind))
        {
            return ReturnedValue::Constant(constant);
        }
        let mut source = None;
        for event in events {
            let defined = match event.effect {
                SemanticEffect::ValueFlow {
                    kind,
                    source,
                    target,
                } if target == value => preserves_value(kind).then_some(source),
                SemanticEffect::Assignment {
                    target,
                    value: source,
                } if target == value => Some(source),
                _ => continue,
            };
            match (defined, source) {
                (None, _) => return ReturnedValue::Opaque,
                (Some(defined), Some(previous)) if defined != previous => {
                    return ReturnedValue::Opaque;
                }
                (Some(defined), _) => source = Some(defined),
            }
        }
        let Some(source) = source else {
            return ReturnedValue::Opaque;
        };
        value = source;
    }
    ReturnedValue::Opaque
}

fn preserves_value(kind: ValueFlowKind) -> bool {
    match kind {
        ValueFlowKind::Local | ValueFlowKind::Return => true,
        ValueFlowKind::Transfer(transfer) => transfer.preserves_member_contents(),
        _ => false,
    }
}

fn lowered_return_profile(
    procedure: &SemanticProcedureValue,
    language: Language,
) -> PythonRuleFactValue {
    let public = procedure.public();
    let span = procedure.byte_span();
    let semantics = procedure.handle.semantics();
    let properties = semantics.properties();
    let reachable = reachable_points(procedure);

    let mut incompleteness = Incompleteness::Content;
    let mut reason = None;
    if properties.is_async || properties.is_generator {
        reason = Some(ASYNC_OR_GENERATOR.to_string());
    }
    for gap in semantics.gaps() {
        if reachable[gap.point.index()] && gap.impacts.contains(SemanticGapImpact::ReturnTransfer) {
            incompleteness = incompleteness.combine(match gap.kind {
                SemanticGapKind::ExceededBudget => {
                    Incompleteness::Operational(DerivationExecutionCause::Budget)
                }
                SemanticGapKind::Ambiguous
                | SemanticGapKind::Unknown
                | SemanticGapKind::Unsupported
                | SemanticGapKind::Unproven => Incompleteness::Content,
            });
            reason.get_or_insert_with(|| gap.detail.to_string());
        }
    }

    let has_effect = |point: ProgramPointId, effect: fn(&SemanticEffect) -> bool| {
        semantics.points()[point.index()]
            .events
            .iter()
            .any(|event| effect(&event.effect))
    };
    let is_return =
        |effect: &SemanticEffect| matches!(effect, SemanticEffect::ProcedureReturn { .. });
    let mut normal_returns = 0;
    let mut valueless = 0;
    let mut opaque = 0;
    // Reachable edges into the normal exit from a point that publishes no
    // return event: a body that falls off its end, or a return routed
    // through cleanup code. Neither names the value it leaves with.
    let mut silent_exits = 0;
    let mut constants = Vec::new();
    for point in semantics.points() {
        if !reachable[point.id.index()] {
            continue;
        }
        if has_effect(point.id, |effect| {
            matches!(effect, SemanticEffect::NormalExit)
        }) {
            silent_exits += semantics
                .predecessor_edges(point.id)
                .filter(|(_, edge)| {
                    reachable[edge.source_point.index()]
                        && !has_effect(edge.source_point, is_return)
                })
                .count();
        }
        for event in &point.events {
            let SemanticEffect::ProcedureReturn { value } = event.effect else {
                continue;
            };
            normal_returns += 1;
            match value.map(|value| returned_value(semantics, &point.events, value)) {
                None => valueless += 1,
                Some(ReturnedValue::Opaque) => opaque += 1,
                Some(ReturnedValue::Constant(constant)) => {
                    if !constants.contains(&constant) {
                        constants.push(constant);
                    }
                }
            }
        }
    }

    let values = normal_returns - valueless;
    let (contract, outcome, proof, constant) = if opaque > 0 {
        reason.get_or_insert_with(|| RETURN_VALUE_NOT_CONSTANT.to_string());
        ("unknown", "open", "none", None)
    } else if valueless > 0 && values > 0 {
        reason.get_or_insert_with(|| VALUELESS_RETURN_MIXED.to_string());
        ("unknown", "open", "none", None)
    } else if silent_exits > 0 && values > 0 {
        reason.get_or_insert_with(|| EXIT_WITHOUT_RETURN.to_string());
        ("unknown", "open", "none", None)
    } else if normal_returns == 0 && silent_exits == 0 {
        ("no_normal_return", "uniform_returns", "proven", None)
    } else if values == 0 {
        ("no_value", "uniform_returns", "proven", None)
    } else if let [constant] = constants.as_slice() {
        (
            "same_constant",
            "uniform_returns",
            "proven",
            Some(constant.render()),
        )
    } else {
        // Control reachability over-approximates execution, so distinct
        // constants on reachable returns do not prove that two of them run.
        ("varying", "mixed_returns", "best_effort", None)
    };
    let complete = reason.is_none();
    let mut value = make_row(
        incompleteness,
        "procedure_return_profile",
        procedure.file(),
        span,
        public.range,
        Some(public.id),
        if complete { outcome } else { "open" },
        if complete { proof } else { "none" },
        complete,
        reason,
    );
    value.row.language = language.config_label();
    value.row.normal_returns = Some(normal_returns);
    value.row.is_async = Some(properties.is_async);
    value.row.is_generator = Some(properties.is_generator);
    value.row.return_contract = Some(if complete { contract } else { "unknown" });
    value.row.return_constant = constant.filter(|_| complete);
    value
}
