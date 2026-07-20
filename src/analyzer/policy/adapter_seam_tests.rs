//! Compile-time coverage for implementing analysis adapters from a sibling
//! policy module, where evaluator and projection private fields are invisible.

use super::budget::PolicyBudget;
use super::evaluator::{
    DefaultPolicyEvaluator, PolicyEvaluationContext, TaintPolicyEvaluator, TypestatePolicyEvaluator,
};
use super::finding::{PolicyRunCompletion, PolicyWorkReport};
use super::future_evidence::{TypestateBindingPlanHash, TypestateProtocolHash};
use super::projection::{
    TaintProjectionAuthority, TaintProjectionPayload, TypestateCompilationHashes,
    TypestateProjectionAuthority, TypestateProjectionPayload, sealed,
};
use super::resolved::{LoadedPolicy, ResolvedTaintPolicySpec, ResolvedTypestatePolicySpec};

struct SiblingTaintAdapter;

impl sealed::TaintAdapter for SiblingTaintAdapter {}

impl TaintPolicyEvaluator for SiblingTaintAdapter {
    fn evaluate_taint(
        &self,
        _authority: &TaintProjectionAuthority,
        _policy: &LoadedPolicy,
        _spec: &ResolvedTaintPolicySpec,
        _context: &PolicyEvaluationContext<'_>,
        _budget: &PolicyBudget,
    ) -> TaintProjectionPayload {
        TaintProjectionPayload {
            projections: Vec::new(),
            completion: PolicyRunCompletion::Complete,
            diagnostics: Vec::new(),
            diagnostics_truncated: false,
            work: PolicyWorkReport::default(),
        }
    }
}

struct SiblingTypestateAdapter;

impl sealed::TypestateAdapter for SiblingTypestateAdapter {}

impl TypestatePolicyEvaluator for SiblingTypestateAdapter {
    fn compilation_hashes(
        &self,
        _policy: &LoadedPolicy,
        _spec: &ResolvedTypestatePolicySpec,
        _context: &PolicyEvaluationContext<'_>,
        _budget: &PolicyBudget,
    ) -> Option<TypestateCompilationHashes> {
        Some(TypestateCompilationHashes::new(
            TypestateProtocolHash::from_canonical_bytes(b"sibling protocol"),
            TypestateBindingPlanHash::from_canonical_bytes(b"sibling bindings"),
        ))
    }

    fn evaluate_typestate(
        &self,
        _authority: &TypestateProjectionAuthority,
        _policy: &LoadedPolicy,
        _spec: &ResolvedTypestatePolicySpec,
        _context: &PolicyEvaluationContext<'_>,
        _budget: &PolicyBudget,
    ) -> TypestateProjectionPayload {
        TypestateProjectionPayload {
            projections: Vec::new(),
            completion: PolicyRunCompletion::Complete,
            diagnostics: Vec::new(),
            diagnostics_truncated: false,
            work: PolicyWorkReport::default(),
        }
    }
}

#[test]
fn sibling_module_can_install_both_production_adapters() {
    let taint = SiblingTaintAdapter;
    let typestate = SiblingTypestateAdapter;
    let _evaluator = DefaultPolicyEvaluator::new()
        .with_taint(&taint)
        .with_typestate(&typestate);
}
