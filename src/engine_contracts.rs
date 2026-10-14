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
    pub operations: &'static [&'static str],
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
const NORMALIZED_CALL_LANGUAGES: &[&str] = &["javascript", "python", "typescript"];
const MEMBER_RESOLUTION_LANGUAGES: &[&str] = &["typescript"];
const EXACT_TARGET_LANGUAGES: &[&str] = &["python"];
const EFFECT_LANGUAGES: &[&str] = &["java"];
const FLOW_LANGUAGES: &[&str] = &["java", "typescript"];
const TAINT_LANGUAGES: &[&str] = &["java"];
const TYPESTATE_LANGUAGES: &[&str] = &["java", "typescript"];
const SWITCH_COVERAGE_LANGUAGES: &[&str] = &["java"];
const CONFIGURATION_LANGUAGES: &[&str] = &[];
const JAVA_RELATION_LANGUAGES: &[&str] = &["java"];

const STRUCTURAL_BOUNDS: &[&str] = &["source-backed structural match", "routed language analyzer"];
const CFG_EXIT_BOUNDS: &[&str] = &["source-backed procedure root", "cfg-exits evaluator"];
const CALL_BINDING_BOUNDS: &[&str] = &["resolver-proven call shape", "formal-binding projection"];
const NORMALIZED_CALL_BOUNDS: &[&str] = &[
    "source-backed call-shape row",
    "call-argument-group and call-argument projections",
    "does not establish callee, formal, target, or propagation identity",
];
const MEMBER_RESOLUTION_BOUNDS: &[&str] = &[
    "source-backed TypeScript member occurrence",
    "workspace declaration targets",
    "resolver-proven receiver owner and member declaration",
    "member_selection and member_family candidates are separate relations",
    "open or unknown receiver coverage remains typed uncertainty",
];
const EXACT_TARGET_BOUNDS: &[&str] = &["call-shape input", "structured resolver target proof"];
const FLOW_BOUNDS: &[&str] = &[
    "registered value-flow plan",
    "matching procedure root and workspace generation",
];
const TAINT_BOUNDS: &[&str] = &[
    "registered production taint result",
    "matching plan, root, and workspace generation",
];
const TYPESTATE_BOUNDS: &[&str] = &[
    "registered typestate plan and production evaluator",
    "exact procedure root",
    "typed finding and witness projection",
];
const SWITCH_COVERAGE_BOUNDS: &[&str] = &[
    "source-backed switch coverage row",
    "explicit default is exhaustive; open selector domains may be unknown",
    "does not establish workspace-wide switch coverage",
];
const CONFIGURATION_BOUNDS: &[&str] = &[
    "workspace configuration documents",
    "JSON, XML, TOML, YAML, and Properties facts",
    "no programming-language axis",
    "incomplete ingestion is not a clean empty result",
];

const ASSIGNMENT_RELATION_BOUNDS: &[&str] = &[
    "source-backed Java ordinary local assignment",
    "self-assignment and failed-swap relation selections",
    "resolver-proven storage binding and same-evaluation flow facts",
    "conversion-unproved failed swaps retain unknown proof and open coverage",
    "other assignment relation kinds and storage forms are not qualified",
];
const BRANCH_RELATION_BOUNDS: &[&str] = &[
    "source-backed Java if statement",
    "identical-bodies relation selection",
    "structured lexical binding and statement identity",
    "deferred executable bodies retain an open verdict and incomplete diagnostics",
    "other branch relation kinds are not qualified",
];
const STATEMENT_REACHABILITY_BOUNDS: &[&str] = &[
    "source-backed Java ordinary expression statements",
    "reachable body and unreachable suffix after return",
    "incomplete control evidence retains open rows and incomplete diagnostics",
    "other statement forms and languages are outside the reviewed scope",
];
const LOOP_RELATION_BOUNDS: &[&str] = &[
    "source-backed Java ordinary while loop",
    "reachable body exit and explicit continue repetition evidence",
    "unproved control or arithmetic evidence retains open rows and incomplete diagnostics",
    "other loop forms and languages are outside the reviewed scope",
];
const JAVA_RELATION_WORKSPACE_PRECONDITIONS: &[&str] = &[
    "WorkspaceAnalyzer-backed Java query",
    "validated prepared syntax and exact enclosing procedure",
    "requested lexical binding and semantic fact providers",
    "provider coverage gaps remain typed open or incomplete results",
];

const PYTHON_FACT_LANGUAGES: &[&str] = &["python"];
const JAVADOC_BOUNDS: &[&str] = &[
    "source-backed ordinary Java public method declarations and parsed Javadoc",
    "undocumented-function language-rule selection with a documented near miss",
    "other Javadoc rule kinds are outside the reviewed facade scope",
];
const PYTHON_CALL_RELATION_BOUNDS: &[&str] = &[
    "source-backed local Python class and explicit super expression",
    "complete super-owner mismatch and matching-owner near miss facts",
    "incomplete hierarchy retains an open lifecycle fact",
];
const PYTHON_CFG_BOUNDS: &[&str] = &[
    "source-backed Python procedure return profiles and tuple-return groups",
    "mixed and uniform return shapes remain distinct",
    "special-method raise facts retain unexpected and allowed exception outcomes",
    "other Python control-flow relations are outside the reviewed facade scope",
];
const PYTHON_IMPORT_SITE_BOUNDS: &[&str] = &[
    "source-backed Python import syntax and local workspace module targets",
    "resolved targets retain their exact workspace-relative paths",
    "missing targets retain incomplete no_workspace_target facts",
    "external import execution and dynamic exports are not established",
];
const PYTHON_IMPORT_CYCLE_BOUNDS: &[&str] = &[
    "source-backed local Python module cycles and import-time readiness",
    "qualified reads and from-imports retain issue and no-issue outcomes",
    "source declaration order distinguishes the reviewed safe near miss",
    "dynamic imports and unresolved module evidence remain uncertainty",
];
const PYTHON_SYNTAX_DIAGNOSTIC_BOUNDS: &[&str] = &[
    "source-backed parser-recovery syntax_error facts and spans",
    "complete error enumeration does not close other semantic selections",
    "valid source is a complete empty near miss for syntax_error selection",
];
const JAVADOC_WORKSPACE_PRECONDITIONS: &[&str] = &[
    "WorkspaceAnalyzer-backed Java query",
    "Java parser, indexed source declaration ranges, and signature visibility metadata",
    "member-family provider for ordinary public non-generated non-accessor non-overriding callables",
    "attached Javadoc must parse completely before documented or undocumented classification",
];
const PYTHON_CALL_RELATION_WORKSPACE_PRECONDITIONS: &[&str] = &[
    "WorkspaceAnalyzer-backed Python query",
    "requested Python declaration with source-backed class and hierarchy declarations",
    "receiver, occurrence, lexical-environment, and semantic-dispatch providers",
    "unknown, recovered and ambiguous input retains typed uncertainty",
];
const PYTHON_CFG_WORKSPACE_PRECONDITIONS: &[&str] = &[
    "WorkspaceAnalyzer-backed Python query",
    "requested procedure or structural raise match with semantic CFG, source mapping, parser, and hierarchy facts",
    "return-flow, recovered, and ambiguous input retains typed uncertainty",
];
const PYTHON_IMPORT_SITE_WORKSPACE_PRECONDITIONS: &[&str] = &[
    "WorkspaceAnalyzer-backed Python query",
    "Python structural parser and import-analysis provider",
    "local target and export evidence is bounded; unavailable, ambiguous, external, and dynamic evidence remains typed open",
];
const PYTHON_IMPORT_CYCLE_WORKSPACE_PRECONDITIONS: &[&str] = &[
    "WorkspaceAnalyzer-backed Python query",
    "Python import-analysis provider and source-backed import facts",
    "snapshot-consistent persisted reverse import graph and workspace content identity",
    "unresolved, ambiguous, dynamic, path-derived package, unavailable graph, and budget evidence remains typed uncertainty",
];
const PYTHON_SYNTAX_DIAGNOSTIC_WORKSPACE_PRECONDITIONS: &[&str] = &[
    "WorkspaceAnalyzer-backed Python structural query",
    "Python structural facts with parser-recovery spans",
    "recovered syntax may hide other selected structural nodes; semantic queries over recovered source remain typed incomplete",
];

const CALLABLE_SIGNATURE_LANGUAGES: &[&str] = &["cpp"];
const CALLABLE_SIGNATURE_BOUNDS: &[&str] = &[
    "source-backed ordinary written C++ function definitions",
    "fixed and variadic declaration signature rows with exact coverage",
    "canonical declaration and source-site identity remain joined",
    "fixed arity and trailing repetition are separate fields",
    "does not establish call-site applicability, target identity, or argument binding",
];
const CALLABLE_SIGNATURE_WORKSPACE_PRECONDITIONS: &[&str] = &[
    "WorkspaceAnalyzer-backed C++ query",
    "indexed source declaration and persisted callable signature entries",
    "unrecorded or recovered signatures remain typed uncertainty",
];

const BINDING_RESOLUTION_LANGUAGES: &[&str] = &["python"];
const BINDING_RESOLUTION_BOUNDS: &[&str] = &[
    "source-backed ordinary local Python function bindings and references",
    "binding_of joins canonical binding and binder AST identities to the reference AST",
    "same-name declarations retain distinct lexical scope identities",
    "row-capped results remain truncated and typed incomplete",
    "does not establish import, dynamic namespace, class lookup, or builtin resolution",
    "structural policy findings do not imply a canonical binding join",
];
const BINDING_RESOLUTION_WORKSPACE_PRECONDITIONS: &[&str] = &[
    "WorkspaceAnalyzer-backed Python query",
    "indexed classified binder/reference AST tokens and lexical environment provider",
    "activation intervals and declaring scope ancestry for the selected references",
];

const NO_MODEL_PRECONDITIONS: &[&str] = &[];
const STRUCTURAL_WORKSPACE_PRECONDITIONS: &[&str] = &["routed TypeScript analyzer"];
const CFG_EXIT_WORKSPACE_PRECONDITIONS: &[&str] = &["WorkspaceAnalyzer-backed query"];
const NORMALIZED_CALL_WORKSPACE_PRECONDITIONS: &[&str] =
    &["WorkspaceAnalyzer-backed call-shape query"];
const MEMBER_RESOLUTION_WORKSPACE_PRECONDITIONS: &[&str] = &[
    "WorkspaceAnalyzer-backed TypeScript query",
    "indexed declarations and receiver facts for the source member site",
];
const CALL_BINDING_MODEL_PRECONDITIONS: &[&str] =
    &["resolver-proven formal or dispatch facts where source syntax is insufficient"];
const CALL_BINDING_WORKSPACE_PRECONDITIONS: &[&str] =
    &["WorkspaceAnalyzer-backed call-shape query"];
const EXACT_TARGET_MODEL_PRECONDITIONS: &[&str] =
    &["resolver-proven target or matching complete external model"];
const EXACT_TARGET_WORKSPACE_PRECONDITIONS: &[&str] =
    &["WorkspaceAnalyzer-backed call-shape query"];
const DECLARED_EFFECT_BOUNDS: &[&str] = &[
    "source-backed call query",
    "semantic-model-declared effect projection",
    "provenance and exhaustive-effect-coverage remain result dimensions",
];
const PROCEDURE_EFFECT_BOUNDS: &[&str] = &[
    "source-backed procedure query",
    "transitive reachable call graph within the matching workspace generation",
    "provenance and exhaustive-effect-coverage remain result dimensions",
];
const EFFECT_MODEL_PRECONDITIONS: &[&str] = &["active compatible SemanticModelSnapshot"];
const EFFECT_WORKSPACE_PRECONDITIONS: &[&str] = &[
    "source-backed workspace",
    "source-backed query",
    "matching workspace generation",
];
const FLOW_MODEL_PRECONDITIONS: &[&str] = &["caller-owned ValueFlowPlanRegistration"];
const FLOW_WORKSPACE_PRECONDITIONS: &[&str] = &[
    "matching workspace generation",
    "procedure root covered by the plan",
];
const TAINT_MODEL_PRECONDITIONS: &[&str] =
    &["caller-owned TaintResultRegistration", "plan/report match"];
const TAINT_WORKSPACE_PRECONDITIONS: &[&str] =
    &["matching workspace generation", "registered result roots"];
const TYPESTATE_MODEL_PRECONDITIONS: &[&str] = &[
    "caller-owned ProtocolRegistrationSet",
    "registered protocol and bindings for the exact procedure root",
];
const TYPESTATE_WORKSPACE_PRECONDITIONS: &[&str] = &[
    "matching workspace generation",
    "WorkspaceAnalyzer-backed exact procedure root",
];
const SWITCH_COVERAGE_WORKSPACE_PRECONDITIONS: &[&str] = &[
    "WorkspaceAnalyzer-backed query",
    "complete SemanticCapability::SwitchFacts provider",
];
const CONFIGURATION_WORKSPACE_PRECONDITIONS: &[&str] = &[
    "WorkspaceAnalyzer-backed configuration ingestion",
    "supported configuration path classification",
];

/// The engine-owned set of contracts that may be advertised to an independent
/// host. Entries require a public typed surface and production evaluator
/// evidence; they are never inferred from a selected pack, manifest, or enum
/// membership alone.
pub const REVIEWED_ENGINE_CONTRACTS: &[EngineContract] = &[
    EngineContract {
        id: "structural-match",
        api: "ExtensionWorkspace::structural_query",
        operations: &["structural.query"],
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
        operations: &["cfg_exits"],
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
        operations: &["call_bindings"],
        support: CapabilitySupport::Partial,
        languages: CALL_BINDING_LANGUAGES,
        bounds: CALL_BINDING_BOUNDS,
        model_preconditions: CALL_BINDING_MODEL_PRECONDITIONS,
        workspace_preconditions: CALL_BINDING_WORKSPACE_PRECONDITIONS,
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
    EngineContract {
        id: "normalized-call",
        api: "CodeIntelligenceRuntime::execute_query",
        operations: &["call_shape"],
        support: CapabilitySupport::Partial,
        languages: NORMALIZED_CALL_LANGUAGES,
        bounds: NORMALIZED_CALL_BOUNDS,
        model_preconditions: NO_MODEL_PRECONDITIONS,
        workspace_preconditions: NORMALIZED_CALL_WORKSPACE_PRECONDITIONS,
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
    EngineContract {
        id: "member-resolution",
        api: "CodeIntelligenceRuntime::execute_query",
        operations: &["member_targets"],
        support: CapabilitySupport::Partial,
        languages: MEMBER_RESOLUTION_LANGUAGES,
        bounds: MEMBER_RESOLUTION_BOUNDS,
        model_preconditions: NO_MODEL_PRECONDITIONS,
        workspace_preconditions: MEMBER_RESOLUTION_WORKSPACE_PRECONDITIONS,
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
    EngineContract {
        id: "exact-call-target",
        api: "CodeIntelligenceRuntime::execute_query",
        operations: &["exact_external_callee"],
        support: CapabilitySupport::Partial,
        languages: EXACT_TARGET_LANGUAGES,
        bounds: EXACT_TARGET_BOUNDS,
        model_preconditions: EXACT_TARGET_MODEL_PRECONDITIONS,
        workspace_preconditions: EXACT_TARGET_WORKSPACE_PRECONDITIONS,
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
    EngineContract {
        id: "semantic-model-declared-effects",
        api: "CodeIntelligenceRuntime::execute_query",
        operations: &["call_effects"],
        support: CapabilitySupport::Partial,
        languages: EFFECT_LANGUAGES,
        bounds: DECLARED_EFFECT_BOUNDS,
        model_preconditions: EFFECT_MODEL_PRECONDITIONS,
        workspace_preconditions: EFFECT_WORKSPACE_PRECONDITIONS,
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
    EngineContract {
        id: "transitive-procedure-effects",
        api: "CodeIntelligenceRuntime::execute_query",
        operations: &["procedure_effects"],
        support: CapabilitySupport::Partial,
        languages: EFFECT_LANGUAGES,
        bounds: PROCEDURE_EFFECT_BOUNDS,
        model_preconditions: EFFECT_MODEL_PRECONDITIONS,
        workspace_preconditions: EFFECT_WORKSPACE_PRECONDITIONS,
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
    EngineContract {
        id: "flow",
        api: "CodeIntelligenceRuntime::execute_query_with_analysis_registrations",
        operations: &["value_flow"],
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
        operations: &["taint"],
        support: CapabilitySupport::Partial,
        languages: TAINT_LANGUAGES,
        bounds: TAINT_BOUNDS,
        model_preconditions: TAINT_MODEL_PRECONDITIONS,
        workspace_preconditions: TAINT_WORKSPACE_PRECONDITIONS,
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
    EngineContract {
        id: "typestate",
        api: "CodeIntelligenceRuntime::execute_query_with_registrations",
        operations: &["typestate"],
        support: CapabilitySupport::Partial,
        languages: TYPESTATE_LANGUAGES,
        bounds: TYPESTATE_BOUNDS,
        model_preconditions: TYPESTATE_MODEL_PRECONDITIONS,
        workspace_preconditions: TYPESTATE_WORKSPACE_PRECONDITIONS,
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
    EngineContract {
        id: "switch-coverage",
        api: "CodeIntelligenceRuntime::execute_query",
        operations: &["switch_coverage"],
        support: CapabilitySupport::Partial,
        languages: SWITCH_COVERAGE_LANGUAGES,
        bounds: SWITCH_COVERAGE_BOUNDS,
        model_preconditions: NO_MODEL_PRECONDITIONS,
        workspace_preconditions: SWITCH_COVERAGE_WORKSPACE_PRECONDITIONS,
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
    EngineContract {
        id: "configuration-facts",
        api: "CodeIntelligenceRuntime::execute_query",
        operations: &["configuration_facts"],
        support: CapabilitySupport::Partial,
        languages: CONFIGURATION_LANGUAGES,
        bounds: CONFIGURATION_BOUNDS,
        model_preconditions: NO_MODEL_PRECONDITIONS,
        workspace_preconditions: CONFIGURATION_WORKSPACE_PRECONDITIONS,
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
    EngineContract {
        id: "assignment-relations",
        api: "CodeIntelligenceRuntime::execute_query",
        operations: &["assignment_relations"],
        support: CapabilitySupport::Partial,
        languages: JAVA_RELATION_LANGUAGES,
        bounds: ASSIGNMENT_RELATION_BOUNDS,
        model_preconditions: NO_MODEL_PRECONDITIONS,
        workspace_preconditions: JAVA_RELATION_WORKSPACE_PRECONDITIONS,
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
    EngineContract {
        id: "branch-relations",
        api: "CodeIntelligenceRuntime::execute_query",
        operations: &["branch_relations"],
        support: CapabilitySupport::Partial,
        languages: JAVA_RELATION_LANGUAGES,
        bounds: BRANCH_RELATION_BOUNDS,
        model_preconditions: NO_MODEL_PRECONDITIONS,
        workspace_preconditions: JAVA_RELATION_WORKSPACE_PRECONDITIONS,
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
    EngineContract {
        id: "statement-reachability",
        api: "CodeIntelligenceRuntime::execute_query",
        operations: &["statement_reachability"],
        support: CapabilitySupport::Partial,
        languages: JAVA_RELATION_LANGUAGES,
        bounds: STATEMENT_REACHABILITY_BOUNDS,
        model_preconditions: NO_MODEL_PRECONDITIONS,
        workspace_preconditions: JAVA_RELATION_WORKSPACE_PRECONDITIONS,
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
    EngineContract {
        id: "loop-relations",
        api: "CodeIntelligenceRuntime::execute_query",
        operations: &["loop_relations"],
        support: CapabilitySupport::Partial,
        languages: JAVA_RELATION_LANGUAGES,
        bounds: LOOP_RELATION_BOUNDS,
        model_preconditions: NO_MODEL_PRECONDITIONS,
        workspace_preconditions: JAVA_RELATION_WORKSPACE_PRECONDITIONS,
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
    EngineContract {
        id: "javadoc-facts",
        api: "CodeIntelligenceRuntime::execute_query",
        operations: &["language_rule"],
        support: CapabilitySupport::Partial,
        languages: JAVA_RELATION_LANGUAGES,
        bounds: JAVADOC_BOUNDS,
        model_preconditions: NO_MODEL_PRECONDITIONS,
        workspace_preconditions: JAVADOC_WORKSPACE_PRECONDITIONS,
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
    EngineContract {
        id: "python-call-relations",
        api: "CodeIntelligenceRuntime::execute_query",
        operations: &["python_call_relations"],
        support: CapabilitySupport::Partial,
        languages: PYTHON_FACT_LANGUAGES,
        bounds: PYTHON_CALL_RELATION_BOUNDS,
        model_preconditions: NO_MODEL_PRECONDITIONS,
        workspace_preconditions: PYTHON_CALL_RELATION_WORKSPACE_PRECONDITIONS,
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
    EngineContract {
        id: "python-cfg",
        api: "CodeIntelligenceRuntime::execute_query",
        operations: &[
            "procedure_return_profile",
            "tuple_return_groups",
            "python_special_method_raise",
        ],
        support: CapabilitySupport::Partial,
        languages: PYTHON_FACT_LANGUAGES,
        bounds: PYTHON_CFG_BOUNDS,
        model_preconditions: NO_MODEL_PRECONDITIONS,
        workspace_preconditions: PYTHON_CFG_WORKSPACE_PRECONDITIONS,
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
    EngineContract {
        id: "python-import-site",
        api: "CodeIntelligenceRuntime::execute_query",
        operations: &["python_import_site"],
        support: CapabilitySupport::Partial,
        languages: PYTHON_FACT_LANGUAGES,
        bounds: PYTHON_IMPORT_SITE_BOUNDS,
        model_preconditions: NO_MODEL_PRECONDITIONS,
        workspace_preconditions: PYTHON_IMPORT_SITE_WORKSPACE_PRECONDITIONS,
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
    EngineContract {
        id: "python-import-cycles",
        api: "CodeIntelligenceRuntime::execute_query",
        operations: &["python_unsafe_cyclic_import"],
        support: CapabilitySupport::Partial,
        languages: PYTHON_FACT_LANGUAGES,
        bounds: PYTHON_IMPORT_CYCLE_BOUNDS,
        model_preconditions: NO_MODEL_PRECONDITIONS,
        workspace_preconditions: PYTHON_IMPORT_CYCLE_WORKSPACE_PRECONDITIONS,
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
    EngineContract {
        id: "callable-signature",
        api: "CodeIntelligenceRuntime::execute_query",
        operations: &["callable_signature"],
        support: CapabilitySupport::Partial,
        languages: CALLABLE_SIGNATURE_LANGUAGES,
        bounds: CALLABLE_SIGNATURE_BOUNDS,
        model_preconditions: NO_MODEL_PRECONDITIONS,
        workspace_preconditions: CALLABLE_SIGNATURE_WORKSPACE_PRECONDITIONS,
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
    EngineContract {
        id: "binding-resolution",
        api: "CodeIntelligenceRuntime::execute_query",
        operations: &["binding_of"],
        support: CapabilitySupport::Partial,
        languages: BINDING_RESOLUTION_LANGUAGES,
        bounds: BINDING_RESOLUTION_BOUNDS,
        model_preconditions: NO_MODEL_PRECONDITIONS,
        workspace_preconditions: BINDING_RESOLUTION_WORKSPACE_PRECONDITIONS,
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
    EngineContract {
        id: "python-syntax-diagnostics",
        api: "CodeIntelligenceRuntime::execute_query",
        operations: &["syntax_error"],
        support: CapabilitySupport::Partial,
        languages: PYTHON_FACT_LANGUAGES,
        bounds: PYTHON_SYNTAX_DIAGNOSTIC_BOUNDS,
        model_preconditions: NO_MODEL_PRECONDITIONS,
        workspace_preconditions: PYTHON_SYNTAX_DIAGNOSTIC_WORKSPACE_PRECONDITIONS,
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
    EngineContract {
        id: "reviewed-python-builtin-result-obligation",
        api: "CodeIntelligenceRuntime::execute_query",
        operations: &["call_shape", "call_result_obligations"],
        support: CapabilitySupport::Partial,
        languages: PYTHON_FACT_LANGUAGES,
        bounds: &[
            "reviewed builtin str strip, lower, upper and two-argument replace results",
            "source-proven discarded or consumed result use",
            "annotated or inferred builtin str receivers use the builtin implementation",
            "builtin methods are assumed not to be replaced",
            "subclasses, unknown receivers and conflicting dispatch remain typed open",
        ],
        model_preconditions: &[
            "active bifrost.python.str-result-use-obligations with matching cpython evidence",
            "unique complete reviewed summary with matching obligation and override coverage",
            "pure transformations require unchanged ordinary heap",
        ],
        workspace_preconditions: &[
            "WorkspaceAnalyzer-backed Python call-shape query and exact source AST site",
            "selected semantic-model snapshot and source-declared runtime compatibility",
            "a runtime declaration does not establish an installed interpreter identity",
        ],
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
    EngineContract {
        id: "reviewed-python-result-obligation",
        api: "CodeIntelligenceRuntime::execute_query",
        operations: &["call_shape", "call_result_obligations"],
        support: CapabilitySupport::Partial,
        languages: PYTHON_FACT_LANGUAGES,
        bounds: &[
            "reviewed subprocess.call and os.system fallible-status results",
            "resolver-proven standard-library function identity and result-use site",
            "consumed results remain distinct from discarded results",
            "dynamic lookup, unresolved calls and conflicting dispatch remain typed open",
        ],
        model_preconditions: &[
            "active bifrost.python.status-result-use-obligations with matching cpython evidence",
            "unique complete reviewed summary with exact result ordinal and failure predicate",
        ],
        workspace_preconditions: &[
            "WorkspaceAnalyzer-backed Python call-shape query and exact source AST site",
            "selected semantic-model snapshot and source-declared runtime compatibility",
            "a runtime declaration does not establish an installed interpreter identity",
        ],
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
    EngineContract {
        id: "reviewed-ruby-core-result-obligation",
        api: "CodeIntelligenceRuntime::execute_query",
        operations: &["call_shape", "call_result_obligations"],
        support: CapabilitySupport::Partial,
        languages: &["ruby"],
        bounds: &[
            "reviewed String strip, lstrip, rstrip, downcase and upcase results",
            "reviewed two-argument String sub and gsub results",
            "reviewed Kernel.system fallible-status results with the exact false predicate",
            "source-proven discarded or consumed result use",
            "resolver output must prove one exact builtin String owner and receiver",
            "builtin methods are assumed not to be replaced",
            "subclasses, unresolved ancestors and unknown receivers remain typed open",
        ],
        model_preconditions: &[
            "active bifrost.ruby.core-result-use-obligations in the selected model snapshot",
            "unique complete reviewed summary with matching owner, member and obligation",
            "pure transformations require unchanged ordinary heap and override coverage",
            "the selected model has no runtime-version selector",
        ],
        workspace_preconditions: &[
            "WorkspaceAnalyzer-backed Ruby call-shape query and exact source AST site",
        ],
        per_run_uncertainty: ALL_PER_RUN_UNCERTAINTY,
    },
];

const fn uncertainty_label(uncertainty: EngineContractUncertainty) -> &'static str {
    match uncertainty {
        EngineContractUncertainty::Unsupported => "unsupported",
        EngineContractUncertainty::Incomplete => "incomplete",
        EngineContractUncertainty::Cancelled => "cancelled",
        EngineContractUncertainty::BudgetExhausted => "budget_exhausted",
    }
}

/// Serialize the reviewed engine contract catalog without changing the
/// pack-consumer profile or advertising any additional capability.
pub fn engine_contract_catalog() -> serde_json::Value {
    let contracts = REVIEWED_ENGINE_CONTRACTS
        .iter()
        .map(|contract| {
            let per_run_uncertainty = contract
                .per_run_uncertainty
                .iter()
                .map(|uncertainty| uncertainty_label(*uncertainty))
                .collect::<Vec<_>>();
            serde_json::json!({
                "id": contract.id,
                "api": contract.api,
                "operations": contract.operations,
                "support": contract.support,
                "availability": contract.support.is_served(),
                "languages": contract.languages,
                "bounds": contract.bounds,
                "model_preconditions": contract.model_preconditions,
                "workspace_preconditions": contract.workspace_preconditions,
                "per_run_uncertainty": per_run_uncertainty,
            })
        })
        .collect::<Vec<_>>();

    serde_json::json!({
        "format": "bifrost_engine_contracts/v1",
        "catalog_schema_version": 1,
        "engine_version": crate::BIFROST_VERSION,
        "build_identity": crate::BIFROST_BUILD_IDENTITY,
        "contracts": contracts,
    })
}

/// Capability names for the profile. `Partial` is served by the extension
/// contract and therefore negotiates like `Complete`; only `Unsupported` is
/// excluded. Per-run completion remains in each operation's typed result.
pub fn advertised_capability_ids() -> impl Iterator<Item = &'static str> {
    REVIEWED_ENGINE_CONTRACTS
        .iter()
        .filter(|contract| contract.support.is_served())
        .map(|contract| contract.id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_contract_catalog_serializes_source_metadata_and_uncertainty() {
        let catalog = engine_contract_catalog();
        assert_eq!(catalog["format"], "bifrost_engine_contracts/v1");
        assert_eq!(catalog["catalog_schema_version"], 1);
        assert_eq!(catalog["engine_version"], crate::BIFROST_VERSION);
        assert_eq!(catalog["build_identity"], crate::BIFROST_BUILD_IDENTITY);

        let rows = catalog["contracts"]
            .as_array()
            .expect("catalog contracts are an array");
        assert_eq!(rows.len(), REVIEWED_ENGINE_CONTRACTS.len());

        let source = REVIEWED_ENGINE_CONTRACTS
            .iter()
            .find(|contract| contract.id == "taint")
            .expect("the reviewed taint contract is present");
        let row = rows
            .iter()
            .find(|row| row["id"] == source.id)
            .expect("the source taint contract is serialized");

        assert_eq!(row["api"], source.api);
        assert_eq!(row["operations"], serde_json::json!(source.operations));
        assert_eq!(row["support"], "partial");
        assert_eq!(row["availability"], source.support.is_served());
        assert_eq!(row["languages"], serde_json::json!(source.languages));
        assert_eq!(row["bounds"], serde_json::json!(source.bounds));
        assert_eq!(
            row["model_preconditions"],
            serde_json::json!(source.model_preconditions)
        );
        assert_eq!(
            row["workspace_preconditions"],
            serde_json::json!(source.workspace_preconditions)
        );

        let uncertainty = row["per_run_uncertainty"]
            .as_array()
            .expect("per-run uncertainty is an array");
        assert_eq!(uncertainty.len(), source.per_run_uncertainty.len());
        for (serialized, source_uncertainty) in uncertainty.iter().zip(source.per_run_uncertainty) {
            assert_eq!(serialized, uncertainty_label(*source_uncertainty));
        }
        assert!(uncertainty.iter().any(|value| value == "incomplete"));
        assert!(uncertainty.iter().any(|value| value == "cancelled"));
        assert!(row.get("baseline").is_none());
        assert!(row.get("proof_status").is_none());
    }

    #[test]
    fn engine_contract_catalog_keeps_partial_support_available() {
        let catalog = engine_contract_catalog();
        let row = catalog["contracts"]
            .as_array()
            .expect("catalog contracts are an array")
            .iter()
            .find(|row| row["support"] == "partial")
            .expect("the catalog contains a partial reviewed contract");
        assert_eq!(row["availability"], true);
    }
}
