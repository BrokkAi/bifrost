//! JavaScript, JSX, TypeScript, and TSX lowering into the shared executable-semantics IR.

use tree_sitter::Node;

use crate::analyzer::lexical_definitions::formal_parameter_slots;
use crate::analyzer::semantic::cfg::{
    CleanupRegionId, CompletionKind, CompletionRequest, CompletionRoute, DriveError,
    ProcedureCfgBuilder, ScopeBinding, ScopeFrameId,
};
use crate::analyzer::semantic::service::{ProgramSemanticsLowerer, SemanticAdapterIdentity};
use crate::analyzer::semantic::*;
use crate::analyzer::tree_sitter_analyzer::{
    PreparedSyntaxTree, WalkControl, try_walk_named_tree_preorder,
};
use crate::analyzer::{Language, ProjectFile, Range};
use crate::hash::{HashMap, HashSet};

const JAVASCRIPT_ADAPTER_VERSION: &[u8] = b"javascript-value-semantics-v6";
const TYPESCRIPT_ADAPTER_VERSION: &[u8] = b"typescript-value-semantics-v7";

#[derive(Debug, Clone, Copy)]
enum JsTsSemanticFlavor {
    JavaScript,
    TypeScript,
}

impl JsTsSemanticFlavor {
    const fn language(self) -> Language {
        match self {
            Self::JavaScript => Language::JavaScript,
            Self::TypeScript => Language::TypeScript,
        }
    }

    const fn adapter_name(self) -> &'static str {
        match self {
            Self::JavaScript => "javascript",
            Self::TypeScript => "typescript",
        }
    }

    const fn adapter_version(self) -> &'static [u8] {
        match self {
            Self::JavaScript => JAVASCRIPT_ADAPTER_VERSION,
            Self::TypeScript => TYPESCRIPT_ADAPTER_VERSION,
        }
    }

    const fn configuration(self) -> &'static [u8] {
        match self {
            Self::JavaScript => b"javascript-intrafile-execution-defaults-v1",
            Self::TypeScript => b"typescript-intrafile-execution-defaults-v1",
        }
    }
}

pub(crate) struct JsTsSemanticLowerer {
    flavor: JsTsSemanticFlavor,
}

impl JsTsSemanticLowerer {
    pub(crate) const fn javascript() -> Self {
        Self {
            flavor: JsTsSemanticFlavor::JavaScript,
        }
    }

    pub(crate) const fn typescript() -> Self {
        Self {
            flavor: JsTsSemanticFlavor::TypeScript,
        }
    }
}

impl ProgramSemanticsLowerer for JsTsSemanticLowerer {
    fn identity(&self) -> SemanticAdapterIdentity {
        SemanticAdapterIdentity {
            adapter: AdapterSemanticsVersion::hash_bytes(
                self.flavor.adapter_name(),
                self.flavor.adapter_version(),
            )
            .expect("adapter name is non-empty"),
            configuration: ConfigurationFingerprint::hash_bytes(self.flavor.configuration()),
            dependencies: DependencyFingerprint::hash_bytes(b"no-intrafile-dependencies"),
        }
    }

    fn capabilities(&self) -> SemanticCapabilities {
        js_ts_capabilities()
    }

    fn lower(
        &self,
        file: &ProjectFile,
        prepared: &PreparedSyntaxTree,
        budget: &SemanticBudget,
        cancellation: &CancellationToken,
    ) -> Result<SemanticOutcome<Vec<ProcedureSemanticsParts>>, SemanticProviderError> {
        if prepared.dialect().language() != self.flavor.language() {
            return Err(SemanticProviderError::invalid_identity(format!(
                "{} semantic lowerer received {} syntax",
                self.flavor.adapter_name(),
                prepared.dialect()
            )));
        }
        let mut specs = match enumerate_procedures(file, prepared, budget, cancellation)? {
            ProcedureEnumeration::Complete(specs) => specs,
            ProcedureEnumeration::ExceededBudget { exceeded, work } => {
                return Ok(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work,
                });
            }
            ProcedureEnumeration::Cancelled => {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: SemanticWork::default(),
                });
            }
        };
        if relay_receiver_capture_demand(&mut specs, cancellation).is_err() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        for index in 0..specs.len() {
            if cancellation.is_cancelled() {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: SemanticWork::default(),
                });
            }
            let parent = specs[index]
                .lexical_parent
                .and_then(|parent| specs.get(parent.index()));
            let can_capture_receiver = parent.is_some_and(|parent| {
                parent.captures_receiver
                    || (!parent.properties.is_static
                        && matches!(
                            parent.kind,
                            ProcedureKind::Method
                                | ProcedureKind::Constructor
                                | ProcedureKind::Function
                        ))
            });
            specs[index].captures_receiver &= can_capture_receiver;
        }
        if cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        let procedure_targets = specs
            .iter()
            .map(|spec| {
                (
                    spec.callable.id(),
                    NestedProcedureTarget {
                        id: spec.id,
                        receiver_capture_destination: spec
                            .captures_receiver
                            .then_some(RECEIVER_CAPTURE_DESTINATION),
                    },
                )
            })
            .collect::<HashMap<_, _>>();
        let mut bound_capture_targets = HashSet::default();
        lower_procedure_batch(
            &specs,
            SemanticWork::default(),
            budget,
            cancellation,
            |spec, staged_budget, cancellation| {
                let capture_binding_expected = bound_capture_targets.contains(&spec.id);
                let lowered = lower_procedure(
                    prepared,
                    spec,
                    &procedure_targets,
                    capture_binding_expected,
                    staged_budget,
                    cancellation,
                )?;
                bound_capture_targets
                    .extend(lowered.0.captures.iter().map(|capture| capture.target));
                Ok(lowered)
            },
        )
    }
}

fn js_ts_capabilities() -> SemanticCapabilities {
    let mut builder = SemanticCapabilities::builder();
    for capability in [
        SemanticCapability::Procedures,
        SemanticCapability::EntryBoundary,
        SemanticCapability::NormalExitBoundary,
        SemanticCapability::ExceptionalExitBoundary,
        SemanticCapability::BasicBlocks,
        SemanticCapability::ProgramPoints,
        SemanticCapability::ReturnFlow,
        SemanticCapability::NormalCallContinuation,
        SemanticCapability::ExceptionalCallContinuation,
    ] {
        builder = builder.complete(capability);
    }
    for capability in [
        SemanticCapability::ExceptionalControlFlow,
        SemanticCapability::CleanupControlFlow,
        SemanticCapability::Calls,
        SemanticCapability::DynamicDispatch,
        SemanticCapability::CallableReferences,
        SemanticCapability::Values,
        SemanticCapability::Assignments,
        SemanticCapability::Allocations,
        SemanticCapability::FieldMemory,
        SemanticCapability::IndexMemory,
        SemanticCapability::LocalFlow,
        SemanticCapability::ParameterFlow,
        SemanticCapability::ReceiverFlow,
        SemanticCapability::Captures,
        SemanticCapability::NormalControlFlow,
        SemanticCapability::GeneratorSuspension,
        SemanticCapability::NonLocalControl,
        SemanticCapability::ResourceManagement,
        SemanticCapability::AsyncSuspendResume,
        SemanticCapability::DeferredExecution,
    ] {
        builder = builder.partial(capability);
    }
    builder.build()
}

mod control;
mod inventory;
mod syntax;
#[cfg(test)]
mod tests;
mod values;

use control::lower_procedure;
use inventory::{NestedProcedureTarget, ProcedureEnumeration, ProcedureSpec, enumerate_procedures};

type TsLoweringError = ProcedureLoweringError;

#[derive(Debug, Clone, Copy)]
struct EdgeTarget {
    point: ProgramPointId,
    kind: ControlEdgeKind,
}

impl EdgeTarget {
    const fn normal(point: ProgramPointId) -> Self {
        Self {
            point,
            kind: ControlEdgeKind::Normal,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Work<'tree> {
    Statement {
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
    },
    LabeledStatement {
        node: Node<'tree>,
        label: &'tree str,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
    },
    Expression {
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
    },
    ChainedExpression {
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        skip: EdgeTarget,
    },
    Condition {
        node: Node<'tree>,
        entry: ProgramPointId,
        when_true: EdgeTarget,
        when_false: EdgeTarget,
        scope: ScopeFrameId,
    },
}

#[derive(Debug, Clone, Copy)]
struct CleanupRegion<'tree> {
    id: CleanupRegionId,
    body: Node<'tree>,
    outer_scope: ScopeFrameId,
}

struct LoweringContext<'tree, 'targets> {
    prepared: &'tree PreparedSyntaxTree,
    session: ProcedureLoweringSession<'targets>,
    expression_values: HashMap<usize, ValueId>,
    parameters: HashMap<Box<str>, ValueId>,
    locals: HashMap<Box<str>, Vec<LocalBinding>>,
    receiver: Option<ValueId>,
    captured_receiver: Option<ValueId>,
    procedure_targets: &'targets HashMap<usize, NestedProcedureTarget>,
    abruptness: HashMap<usize, bool>,
    cleanups: Vec<CleanupRegion<'tree>>,
}

struct LocalBinding {
    scope_start: usize,
    scope_end: usize,
    value: ValueId,
}
