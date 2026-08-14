//! Kotlin lowering into the language-neutral executable-semantics IR
//! (issue #1241).
//!
//! This module interprets tree-sitter nodes directly. Graph construction,
//! abrupt-completion routing, cleanup specialization, and physical adjacency
//! storage remain owned by the shared semantic substrate.
//!
//! Kotlin's grammar is expression-oriented and field-poor, so the shapes this
//! module depends on are read positionally through [`syntax`], which reuses the
//! shared Kotlin readers in [`brokk_bifrost_jvm::kotlin::syntax`] rather than
//! re-deriving them.
//!
//! Deliberate, documented omissions at this boundary:
//!
//! * `suspend` is lowered as an ordinary immediate call. The
//!   continuation-passing rewrite a `suspend` body receives is
//!   compiler-generated, so every `suspend` callable carries a
//!   procedure-scoped `AsyncSuspendResume` gap instead of claiming Rust's
//!   deferred-invocation semantics.
//! * Infix, operator-convention, and indexing calls (`a to b`, `a + b`,
//!   `a[i]`) are evaluated as opaque operations with a point-scoped `Calls`
//!   gap. Publishing them as call sites would create permanently unresolvable
//!   rows, because exact call dispatch only recognizes `call_expression` and
//!   `constructor_invocation`.
//! * Primary-constructor parameter default expressions
//!   (`class C(val x: Int = compute())`) are lowered as `Initializer`
//!   procedures over the default expression itself, so the calls inside one are
//!   ordinary call sites. *When* a default runs — it executes only at a
//!   construction that omits the argument, interleaved with property
//!   initializers and `init` blocks — stays a procedure-scoped gap, because the
//!   schedule is a property of each construction site rather than of the
//!   declaration.
//! * A Kotlin script's free top-level statements are not lowered. Declared
//!   callables inside a `.kts` file — including `val x = …` initializers —
//!   enumerate exactly as they do in a `.kt` file; only the implicit script
//!   body is absent, because it has no declaration of its own.

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
use crate::analyzer::{KotlinAnalyzer, Language, ProjectFile, Range};
use crate::hash::{HashMap, HashSet};

/// Bumped for #1242: keyword/spread argument domains, and primary-constructor
/// parameter defaults as their own initializer procedures, both change the
/// artifact a file lowers to.
const ADAPTER_VERSION: &[u8] = b"kotlin-value-semantics-v2";

impl_program_semantics_provider!(KotlinAnalyzer, KotlinSemanticLowerer);

struct KotlinSemanticLowerer;

impl ProgramSemanticsLowerer for KotlinSemanticLowerer {
    fn identity(&self) -> SemanticAdapterIdentity {
        SemanticAdapterIdentity {
            adapter: AdapterSemanticsVersion::hash_bytes("kotlin", ADAPTER_VERSION)
                .expect("adapter name is non-empty"),
            configuration: ConfigurationFingerprint::hash_bytes(
                b"kotlin-intrafile-execution-defaults-v1",
            ),
            dependencies: DependencyFingerprint::hash_bytes(b"no-intrafile-dependencies"),
        }
    }

    fn capabilities(&self) -> SemanticCapabilities {
        kotlin_capabilities()
    }

    fn lower(
        &self,
        file: &ProjectFile,
        prepared: &PreparedSyntaxTree,
        budget: &SemanticBudget,
        cancellation: &CancellationToken,
    ) -> Result<SemanticOutcome<Vec<ProcedureSemanticsParts>>, SemanticProviderError> {
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
            let can_capture_receiver = specs[index]
                .lexical_parent
                .and_then(|parent| specs.get(parent.index()))
                .is_some_and(|parent| {
                    parent.captures_receiver
                        || (!parent.properties.is_static
                            && matches!(
                                parent.kind,
                                ProcedureKind::Method
                                    | ProcedureKind::Constructor
                                    | ProcedureKind::Initializer
                                    | ProcedureKind::Accessor
                            ))
                });
            specs[index].captures_receiver &= can_capture_receiver;
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

        let Ok(constructible_types) = collect_constructible_types(prepared, cancellation) else {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: inventory_work,
            });
        };

        lower_procedure_batch(
            &specs,
            initial_work,
            budget,
            cancellation,
            |spec, staged_budget, cancellation| {
                lower_procedure(
                    prepared,
                    spec,
                    &procedure_targets,
                    &constructible_types,
                    staged_budget,
                    cancellation,
                )
            },
        )
    }
}

fn kotlin_capabilities() -> SemanticCapabilities {
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
        SemanticCapability::NormalControlFlow,
        SemanticCapability::ExceptionalControlFlow,
        SemanticCapability::CleanupControlFlow,
        SemanticCapability::Assignments,
        SemanticCapability::Values,
        SemanticCapability::Allocations,
        SemanticCapability::LocalFlow,
        SemanticCapability::ParameterFlow,
        SemanticCapability::ReceiverFlow,
        SemanticCapability::FieldMemory,
        // Kotlin's top-level and `object` properties are static, but which of
        // the two a `receiver.name` selection reads is exactly the identity the
        // property-memory gap defers, so static access is partial rather than
        // absent.
        SemanticCapability::StaticMemory,
        SemanticCapability::IndexMemory,
        SemanticCapability::Calls,
        SemanticCapability::DynamicDispatch,
        SemanticCapability::Captures,
        SemanticCapability::CallableReferences,
        SemanticCapability::DeferredExecution,
        SemanticCapability::NonLocalControl,
    ] {
        builder = builder.partial(capability);
    }
    // Explicitly unsupported, each for a source-level reason:
    //
    // * `AsyncSuspendResume` — `suspend` is a modifier, not a suspension
    //   operator. Every suspension point is compiler-generated, so each
    //   `suspend` callable carries a procedure-scoped gap and no adapter-side
    //   suspend/resume pair is invented.
    // * `GeneratorSuspension` — `sequence { yield(…) }` is library code, not
    //   syntax; `yield` is an ordinary call inside a lambda.
    // * `ConcurrentSpawn` — `launch`/`async` are library calls flowing through
    //   `Calls` and `DeferredExecution`, matching Java's treatment of executors.
    // * `ResourceManagement` — Kotlin has no resource syntax at all. `use { … }`
    //   is an ordinary stdlib higher-order call, already represented as a call
    //   site plus a lambda procedure, so claiming partial resource management
    //   would describe a construct the language does not have.
    for capability in [
        SemanticCapability::AsyncSuspendResume,
        SemanticCapability::GeneratorSuspension,
        SemanticCapability::ConcurrentSpawn,
        SemanticCapability::ResourceManagement,
    ] {
        builder = builder.unsupported(capability);
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
use inventory::{
    NestedProcedureTarget, ProcedureBody, ProcedureEnumeration, ProcedureSpec,
    collect_constructible_types, enumerate_procedures,
};

type KotlinLoweringError = ProcedureLoweringError;

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
    session: ProcedureLoweringSession<'targets>,
    expression_values: HashMap<usize, ValueId>,
    parameters: HashMap<Box<str>, ValueId>,
    locals: HashMap<Box<str>, Vec<LocalBinding>>,
    /// Nested callables a bare name in this body can denote: a local `fun`, or
    /// a lambda bound to a local `val`. These are the only Kotlin callees whose
    /// target is provable without whole-program dispatch.
    local_callables: HashMap<Box<str>, NestedProcedureTarget>,
    /// Classes this file declares, so a bare `Box(input)` call can be published
    /// as the allocation it provably is.
    constructible_types: &'targets HashSet<Box<str>>,
    receiver: Option<ValueId>,
    captured_receiver: Option<ValueId>,
    /// The label a `return@label` may name to leave *this* procedure, set for a
    /// lambda that is a labelled or trailing argument.
    boundary_label: Option<&'tree str>,
    /// Whether this procedure is a lambda, whose bare `return` is a non-local
    /// return through an inline caller rather than a return from the lambda.
    is_lambda: bool,
    procedure_targets: &'targets HashMap<usize, NestedProcedureTarget>,
    cleanups: Vec<CleanupRegion<'tree>>,
}

struct LocalBinding {
    declaration_start: usize,
    visible_from: usize,
    scope_start: usize,
    scope_end: usize,
    value: ValueId,
}
