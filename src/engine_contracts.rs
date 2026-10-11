use crate::extension::CapabilitySupport;

/// A bounded uncertainty that a supported operation may report for one run.
/// Capability advertisement is independent of which of these outcomes a
/// particular workspace, model, limit, or cancellation produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineContractUncertainty {
    Unsupported,
    Incomplete,
    Cancelled,
    BudgetExhausted,
}

/// An engine-owned, reviewed API contract. This is source metadata used to
/// derive the portable capability names; it is not pack metadata and is not
/// serialized into the pack-consumer profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineContract {
    pub id: &'static str,
    pub api: &'static str,
    pub operation: &'static str,
    pub support: CapabilitySupport,
    pub languages: &'static [&'static str],
    pub bounds: &'static [&'static str],
    pub model_preconditions: &'static [&'static str],
    pub workspace_preconditions: &'static [&'static str],
    pub per_run_uncertainty: &'static [EngineContractUncertainty],
}

const ALL_PER_RUN_UNCERTAINTY: &[EngineContractUncertainty] = &[
    EngineContractUncertainty::Unsupported,
    EngineContractUncertainty::Incomplete,
    EngineContractUncertainty::Cancelled,
    EngineContractUncertainty::BudgetExhausted,
];

const STRUCTURAL_LANGUAGES: &[&str] = &["typescript"];
const CFG_EXIT_LANGUAGES: &[&str] = &["rust"];
const CALL_BINDING_LANGUAGES: &[&str] = &["javascript", "python", "typescript"];
const EXACT_TARGET_LANGUAGES: &[&str] = &["python"];
const FLOW_LANGUAGES: &[&str] = &["java", "typescript"];
const TAINT_LANGUAGES: &[&str] = &["java"];

const STRUCTURAL_BOUNDS: &[&str] = &["source-backed structural match", "routed language analyzer"];
const CFG_EXIT_BOUNDS: &[&str] = &["source-backed procedure root", "cfg-exits evaluator"];
const CALL_BINDING_BOUNDS: &[&str] = &["resolver-proven call shape", "formal-binding projection"];
const EXACT_TARGET_BOUNDS: &[&str] = &["call-shape input", "structured resolver target proof"];
const FLOW_BOUNDS: &[&str] = &[
    "registered value-flow plan",
    "matching procedure root and workspace generation",
];
const TAINT_BOUNDS: &[&str] = &[
    "registered production taint result",
    "matching plan, root, and workspace generation",
];

const NO_MODEL_PRECONDITIONS: &[&str] = &[];
const STRUCTURAL_WORKSPACE_PRECONDITIONS: &[&str] = &["routed TypeScript analyzer"];
const CFG_EXIT_WORKSPACE_PRECONDITIONS: &[&str] = &["WorkspaceAnalyzer-backed query"];
const CALL_BINDING_MODEL_PRECONDITIONS: &[&str] =
    &["resolver-proven formal or dispatch facts where source syntax is insufficient"];
const CALL_BINDING_WORKSPACE_PRECONDITIONS: &[&str] =
    &["WorkspaceAnalyzer-backed call-shape query"];
const EXACT_TARGET_MODEL_PRECONDITIONS: &[&str] =
    &["resolver-proven target or matching complete external model"];
const EXACT_TARGET_WORKSPACE_PRECONDITIONS: &[&str] =
    &["WorkspaceAnalyzer-backed call-shape query"];
const FLOW_MODEL_PRECONDITIONS: &[&str] = &["caller-owned ValueFlowPlanRegistration"];
const FLOW_WORKSPACE_PRECONDITIONS: &[&str] = &[
    "matching workspace generation",
    "procedure root covered by the plan",
];
const TAINT_MODEL_PRECONDITIONS: &[&str] =
    &["caller-owned TaintResultRegistration", "plan/report match"];
const TAINT_WORKSPACE_PRECONDITIONS: &[&str] =
    &["matching workspace generation", "registered result roots"];

/// The engine-owned set of contracts that may be advertised to an independent
/// host. Entries require a public typed surface and production evaluator
/// evidence; they are never inferred from a selected pack, manifest, or enum
/// membership alone.
pub const REVIEWED_ENGINE_CONTRACTS: &[EngineContract] = &[
    EngineContract {
        id: "structural-match",
        api: "ExtensionWorkspace::structural_query",
        operation: "structural.query",
        support: CapabilitySupport::Complete,
        languages: STRUCTURAL_LANGUAGES,
        bounds: STRUCTURAL_BOUNDS,
        model_preconditions: NO_MODEL_PRECONDITIONS,
        workspace_preconditions: STRUCTURAL_WORKSPACE_PRECONDITIONS,
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
    EngineContract {
        id: "normal-and-exceptional-exit",
        api: "CodeIntelligenceRuntime::execute_query",
        operation: "cfg_exits",
        support: CapabilitySupport::Partial,
        languages: CFG_EXIT_LANGUAGES,
        bounds: CFG_EXIT_BOUNDS,
        model_preconditions: NO_MODEL_PRECONDITIONS,
        workspace_preconditions: CFG_EXIT_WORKSPACE_PRECONDITIONS,
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
    EngineContract {
        id: "actual-to-formal-binding",
        api: "CodeIntelligenceRuntime::execute_query",
        operation: "call_bindings",
        support: CapabilitySupport::Partial,
        languages: CALL_BINDING_LANGUAGES,
        bounds: CALL_BINDING_BOUNDS,
        model_preconditions: CALL_BINDING_MODEL_PRECONDITIONS,
        workspace_preconditions: CALL_BINDING_WORKSPACE_PRECONDITIONS,
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
    EngineContract {
        id: "exact-call-target",
        api: "CodeIntelligenceRuntime::execute_query",
        operation: "exact_external_callee",
        support: CapabilitySupport::Partial,
        languages: EXACT_TARGET_LANGUAGES,
        bounds: EXACT_TARGET_BOUNDS,
        model_preconditions: EXACT_TARGET_MODEL_PRECONDITIONS,
        workspace_preconditions: EXACT_TARGET_WORKSPACE_PRECONDITIONS,
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
    EngineContract {
        id: "flow",
        api: "CodeIntelligenceRuntime::execute_query_with_analysis_registrations",
        operation: "value_flow",
        support: CapabilitySupport::Partial,
        languages: FLOW_LANGUAGES,
        bounds: FLOW_BOUNDS,
        model_preconditions: FLOW_MODEL_PRECONDITIONS,
        workspace_preconditions: FLOW_WORKSPACE_PRECONDITIONS,
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
    EngineContract {
        id: "taint",
        api: "CodeIntelligenceRuntime::execute_query_with_all_analysis_registrations",
        operation: "taint",
        support: CapabilitySupport::Partial,
        languages: TAINT_LANGUAGES,
        bounds: TAINT_BOUNDS,
        model_preconditions: TAINT_MODEL_PRECONDITIONS,
        workspace_preconditions: TAINT_WORKSPACE_PRECONDITIONS,
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
];

/// Capability names for the profile. `Partial` is served by the extension
/// contract and therefore negotiates like `Complete`; only `Unsupported` is
/// excluded. Per-run completion remains in each operation's typed result.
pub fn advertised_capability_ids() -> impl Iterator<Item = &'static str> {
    REVIEWED_ENGINE_CONTRACTS
        .iter()
        .filter(|contract| contract.support.is_served())
        .map(|contract| contract.id)
}
