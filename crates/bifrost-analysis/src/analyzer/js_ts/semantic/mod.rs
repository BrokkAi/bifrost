//! JavaScript, JSX, TypeScript, and TSX lowering into the shared executable-semantics IR.

use tree_sitter::Node;

use crate::analyzer::lexical_definitions::formal_parameter_slots;
use crate::analyzer::semantic::cfg::{
    CleanupRegionId, CompletionKind, CompletionRequest, CompletionRoute, ProcedureCfgBuilder,
    ScopeBinding, ScopeFrameId,
};
use crate::analyzer::semantic::service::{ProgramSemanticsLowerer, SemanticAdapterIdentity};
use crate::analyzer::semantic::*;
use crate::analyzer::tree_sitter_analyzer::{
    PreparedSyntaxTree, WalkControl, try_walk_named_tree_preorder,
};
use crate::analyzer::{Language, ProjectFile, Range};
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_js_ts::syntax::{
    JsTsImportBinder, JsTsLexicalBindingIndex, compute_import_binder,
};

const JAVASCRIPT_ADAPTER_VERSION: &[u8] = b"javascript-value-semantics-v13";
const TYPESCRIPT_ADAPTER_VERSION: &[u8] = b"typescript-value-semantics-v14";

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
        let (mut specs, initial_work, inventory_work) =
            match enumerate_procedures(file, prepared, budget, cancellation)? {
                ProcedureEnumeration::Complete {
                    value,
                    initial_work,
                    inventory_work,
                } => (value, initial_work, inventory_work),
                ProcedureEnumeration::ExceededBudget { exceeded, work } => {
                    return Ok(SemanticOutcome::ExceededBudget {
                        partial: None,
                        exceeded,
                        work,
                    });
                }
                ProcedureEnumeration::Cancelled { work } => {
                    return Ok(SemanticOutcome::Cancelled {
                        partial: None,
                        work,
                    });
                }
            };
        if relay_receiver_capture_demand(&mut specs, cancellation).is_err() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: inventory_work,
            });
        }
        for index in 0..specs.len() {
            if cancellation.is_cancelled() {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: inventory_work,
                });
            }
            let parent = specs[index]
                .lexical_parent
                .and_then(|parent| specs.get(parent.index()));
            let can_capture_receiver = parent.is_some_and(|parent| {
                parent.captures_receiver || procedure_owns_receiver(parent.kind, parent.properties)
            });
            specs[index].captures_receiver &= can_capture_receiver;
        }
        // A surviving capture ultimately reads the receiver of the nearest
        // non-lambda ancestor, so that owner must publish its receiver formal
        // even when its own body never reads `this` directly.
        for index in 0..specs.len() {
            if !specs[index].captures_receiver {
                continue;
            }
            let Some(parent) = specs[index].lexical_parent else {
                continue;
            };
            let parent = parent.index();
            if specs[parent].kind != ProcedureKind::Lambda
                && procedure_owns_receiver(specs[parent].kind, specs[parent].properties)
            {
                specs[parent].owns_receiver = true;
            }
        }
        if cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: inventory_work,
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
        let imports = compute_import_binder(prepared.source(), prepared.tree());
        let lexical_bindings =
            JsTsLexicalBindingIndex::build(prepared.tree().root_node(), prepared.source());
        let mut bound_capture_targets = HashSet::default();
        lower_procedure_batch(
            &specs,
            initial_work,
            budget,
            cancellation,
            |spec, staged_budget, cancellation| {
                let capture_binding_expected = bound_capture_targets.contains(&spec.id);
                let lowered = lower_procedure(
                    prepared,
                    spec,
                    &procedure_targets,
                    &imports,
                    &lexical_bindings,
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

const fn procedure_owns_receiver(kind: ProcedureKind, properties: ProcedureProperties) -> bool {
    matches!(kind, ProcedureKind::Initializer)
        || (!properties.is_static
            && matches!(
                kind,
                ProcedureKind::Method | ProcedureKind::Constructor | ProcedureKind::Function
            ))
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
    // Explicitly unsupported: this adapter normalizes no branch conditions, so
    // an empty `guard_facts` table means "this language publishes no guard
    // facts" rather than "this procedure has no decision" (#2443).
    builder = builder.unsupported(SemanticCapability::GuardFacts);
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

type EdgeTarget = ControlTarget;

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

impl<'tree> Work<'tree> {
    const fn condition(
        node: Node<'tree>,
        entry: ProgramPointId,
        when_true: EdgeTarget,
        when_false: EdgeTarget,
        scope: ScopeFrameId,
    ) -> Self {
        Self::Condition {
            node,
            entry,
            when_true,
            when_false,
            scope,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct CleanupRegion<'tree> {
    id: CleanupRegionId,
    body: Node<'tree>,
    outer_scope: ScopeFrameId,
}

struct LoweringContext<'tree, 'targets> {
    prepared: &'tree PreparedSyntaxTree,
    imports: &'targets JsTsImportBinder,
    lexical_bindings: &'targets JsTsLexicalBindingIndex,
    session: ProcedureLoweringSession<'targets>,
    expression_values: HashMap<usize, ValueId>,
    constant_index_values: HashMap<u64, ValueId>,
    parameters: HashMap<Box<str>, ValueId>,
    locals: HashMap<Box<str>, Vec<LocalBinding>>,
    receiver: Option<ValueId>,
    captured_receiver: Option<ValueId>,
    procedure_targets: &'targets HashMap<usize, NestedProcedureTarget>,
    abruptness: HashMap<usize, bool>,
    cleanups: Vec<CleanupRegion<'tree>>,
    catch_binders: HashMap<ProgramPointId, ValueId>,
    catch_binder_scopes: HashMap<ValueId, (usize, usize)>,
    plain_object_locals: HashMap<ValueId, PlainObjectLocal>,
    plain_object_fields: HashMap<ValueId, HashMap<Box<str>, SemanticLocator>>,
    array_locals: HashMap<ValueId, ArrayLocal>,
}

struct LocalBinding {
    scope_start: usize,
    scope_end: usize,
    value: ValueId,
}

/// A local whose value is a proven allocation for the binding's whole extent:
/// the initializer is a supported literal or built-in allocation, and every
/// use of the name in the procedure is a non-`__proto__` member-access base
/// outside call-callee position, a whole-value call argument, or another
/// recognized structured use, so no alias, capture, rebind, or prototype
/// mutation exists that could install an accessor or a proxy behind a
/// property access this local's `escapes_after` bound admits.
#[derive(Clone, Copy)]
struct PlainObjectLocal {
    /// The local value assigned by the proven allocation declaration. Aliases
    /// retain this root so their field locators remain identical.
    root: ValueId,
    /// Node id of the declaration statement's parent. A property access is
    /// established only when this node is among its ancestors, so control
    /// cannot reach the access without first executing the declarator.
    declaration_parent: usize,
    /// End byte of the declarator; accesses before it may observe the
    /// binding uninitialized.
    available_after: usize,
    /// Start byte of the first whole-value consumption of this allocation
    /// root, when the procedure has one. A callee that receives the object can
    /// install an accessor or a proxy on it, so only an access that ends
    /// before this byte is still proven.
    escapes_after: Option<usize>,
}

/// A local binding whose value is a non-escaping array literal allocation.
/// The allocation root is shared by direct declaration aliases, so indexed
/// accesses through those aliases retain one identity only while the root is
/// proven not to be rebound, captured, or used through another operation.
struct ArrayLocal {
    declaration_parent: usize,
    available_after: usize,
    /// Start byte of the first whole-value consumption of this allocation
    /// root. See [`PlainObjectLocal::escapes_after`].
    escapes_after: Option<usize>,
}
