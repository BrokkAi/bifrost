//! JavaScript, JSX, TypeScript, and TSX lowering into the shared executable-semantics IR.

use tree_sitter::Node;

use crate::analyzer::lexical_definitions::formal_parameter_slots_for_owner_with_nodes;
use crate::analyzer::semantic::cfg::{
    CleanupRegionId, CompletionKind, CompletionRequest, CompletionRoute, ProcedureCfgBuilder,
    ScopeBinding, ScopeFrameId,
};
use crate::analyzer::semantic::service::{ProgramSemanticsLowerer, SemanticAdapterIdentity};
use crate::analyzer::semantic::*;
use crate::analyzer::structural::extract::{
    LimitedFileFacts, extract_file_facts_from_tree_limited,
};
use crate::analyzer::structural::facts::STRUCTURAL_FACTS_VERSION;
use crate::analyzer::tree_sitter_analyzer::{
    PreparedSyntaxTree, WalkControl, try_walk_named_tree_preorder,
};
use crate::analyzer::{Language, ProjectFile, Range, parser_language_for_dialect};
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_js_ts::structural::TYPESCRIPT_STRUCTURAL_SPEC;
use brokk_bifrost_js_ts::syntax::{
    JsTsImportBinder, JsTsLexicalBindingIndex, compute_import_binder, is_declaration_identifier,
};
use brokk_bifrost_js_ts::ts_owners::ts_unwrap_expression;

const JAVASCRIPT_ADAPTER_VERSION: &[u8] = b"javascript-value-semantics-v15";
const TYPESCRIPT_ADAPTER_VERSION: &[u8] = b"typescript-value-semantics-v18";

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

/// Exact joins from a prepared syntax tree to the normalized structural facts
/// extracted from that same tree. The map is built once per prepared source,
/// then each parameter mapping performs only a tree-node-id lookup.
#[derive(Debug)]
struct StructuralNodeIndex {
    content: ContentIdentity,
    node_ids: HashMap<usize, u32>,
}

enum StructuralNodeIndexOutcome {
    Complete {
        index: StructuralNodeIndex,
        work_items: usize,
    },
    Exceeded {
        minimum_work_items: usize,
    },
    Cancelled,
}

impl StructuralNodeIndex {
    fn for_typescript(
        prepared: &PreparedSyntaxTree,
        max_work_items: usize,
        cancellation: &CancellationToken,
    ) -> Result<StructuralNodeIndexOutcome, SemanticProviderError> {
        let grammar = parser_language_for_dialect(prepared.dialect()).ok_or_else(|| {
            SemanticProviderError::internal(
                "TypeScript semantic lowering has no structural parser language",
            )
        })?;
        let extracted = extract_file_facts_from_tree_limited(
            &TYPESCRIPT_STRUCTURAL_SPEC,
            &grammar,
            prepared.tree(),
            prepared.source(),
            max_work_items,
            Some(cancellation),
        );
        let (facts, node_ids) = match extracted {
            LimitedFileFacts::CompleteWithNodeIndex { facts, node_ids } => (facts, node_ids),
            LimitedFileFacts::Exceeded { minimum_fact_nodes } => {
                return Ok(StructuralNodeIndexOutcome::Exceeded {
                    minimum_work_items: minimum_fact_nodes,
                });
            }
            LimitedFileFacts::Cancelled => return Ok(StructuralNodeIndexOutcome::Cancelled),
            LimitedFileFacts::Unavailable => {
                return Err(SemanticProviderError::internal(
                    "TypeScript structural identity extraction is unavailable",
                ));
            }
            LimitedFileFacts::Complete(_) => {
                return Err(SemanticProviderError::internal(
                    "prepared-tree structural extraction omitted its node index",
                ));
            }
        };
        let work_items = facts.work_item_count();
        let content = facts.source_identity();
        assert_eq!(
            content,
            ContentIdentity::hash_bytes(prepared.source().as_bytes()),
            "structural facts must be extracted from the semantic artifact source"
        );
        Ok(StructuralNodeIndexOutcome::Complete {
            index: Self { content, node_ids },
            work_items,
        })
    }

    fn identity(&self, node: Node<'_>) -> Option<StructuralNodeIdentity> {
        self.node_ids
            .get(&node.id())
            .copied()
            .map(|node_id| StructuralNodeIdentity::new(self.content, node_id))
    }
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
        let dependencies = match self.flavor {
            JsTsSemanticFlavor::JavaScript => {
                DependencyFingerprint::hash_bytes(b"no-intrafile-dependencies")
            }
            JsTsSemanticFlavor::TypeScript => {
                let mut digest = LengthDelimitedDigest::new(
                    b"bifrost.typescript-semantic.structural-facts-dependency.v1",
                );
                digest.push(&STRUCTURAL_FACTS_VERSION.to_le_bytes());
                DependencyFingerprint::from_digest(digest.finish())
            }
        };
        SemanticAdapterIdentity {
            adapter: AdapterSemanticsVersion::hash_bytes(
                self.flavor.adapter_name(),
                self.flavor.adapter_version(),
            )
            .expect("adapter name is non-empty"),
            configuration: ConfigurationFingerprint::hash_bytes(self.flavor.configuration()),
            dependencies,
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
        let (procedure_inventory, mut initial_work, mut inventory_work) =
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
        let JsTsProcedureInventory {
            mut specs,
            lexical_bindings,
            callable_bindings,
        } = procedure_inventory;
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
                        direct_invocation_supported: !spec.properties.is_async
                            && !spec.properties.is_generator
                            && spec.omitted_captures.is_empty(),
                        receiver_capture_destination: spec
                            .captures_receiver
                            .then_some(RECEIVER_CAPTURE_DESTINATION),
                        captures: spec
                            .captures
                            .iter()
                            .map(|capture| capture.binding)
                            .collect(),
                    },
                )
            })
            .collect::<HashMap<_, _>>();
        let imports = compute_import_binder(prepared.source(), prepared.tree());
        let structural_node_index = if matches!(self.flavor, JsTsSemanticFlavor::TypeScript) {
            let max_work_items = budget
                .limits()
                .nested_entries
                .saturating_sub(inventory_work.nested_entries);
            match StructuralNodeIndex::for_typescript(prepared, max_work_items, cancellation)? {
                StructuralNodeIndexOutcome::Complete { index, work_items } => {
                    let work = SemanticWork {
                        nested_entries: work_items,
                        ..SemanticWork::default()
                    };
                    initial_work = sum_lowering_work(initial_work, work);
                    inventory_work = sum_lowering_work(inventory_work, work);
                    Some(index)
                }
                StructuralNodeIndexOutcome::Exceeded { minimum_work_items } => {
                    let work = sum_lowering_work(
                        inventory_work,
                        SemanticWork {
                            nested_entries: minimum_work_items,
                            ..SemanticWork::default()
                        },
                    );
                    let exceeded = budget
                        .check(work)
                        .expect_err("structural minimum exceeds its remaining semantic budget");
                    return Ok(SemanticOutcome::ExceededBudget {
                        partial: None,
                        exceeded,
                        work,
                    });
                }
                StructuralNodeIndexOutcome::Cancelled => {
                    return Ok(SemanticOutcome::Cancelled {
                        partial: None,
                        work: inventory_work,
                    });
                }
            }
        } else {
            None
        };
        if cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: inventory_work,
            });
        }
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
                    &callable_bindings,
                    &imports,
                    &lexical_bindings,
                    structural_node_index.as_ref(),
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
use inventory::{
    JsTsProcedureInventory, LexicalCallableTarget, NestedProcedureTarget, ProcedureEnumeration,
    ProcedureSpec, enumerate_procedures,
};

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

type ElementFieldLocators = HashMap<Box<str>, SemanticLocator>;
type ArrayElementFields = HashMap<u64, ElementFieldLocators>;

struct LoweringContext<'tree, 'targets> {
    prepared: &'tree PreparedSyntaxTree,
    imports: &'targets JsTsImportBinder,
    lexical_bindings: &'targets JsTsLexicalBindingIndex,
    structural_node_index: Option<&'targets StructuralNodeIndex>,
    session: ProcedureLoweringSession<'targets>,
    expression_values: HashMap<usize, ValueId>,
    constant_index_values: HashMap<u64, ValueId>,
    parameters: HashMap<Box<str>, ValueId>,
    locals: HashMap<Box<str>, Vec<LocalBinding>>,
    receiver: Option<ValueId>,
    captured_receiver: Option<ValueId>,
    captured_bindings: HashMap<Range, ValueId>,
    procedure_targets: &'targets HashMap<usize, NestedProcedureTarget>,
    callable_bindings: &'targets HashMap<Range, LexicalCallableTarget>,
    abruptness: HashMap<usize, bool>,
    cleanups: Vec<CleanupRegion<'tree>>,
    catch_binders: HashMap<ProgramPointId, ValueId>,
    catch_binder_scopes: HashMap<ValueId, (usize, usize)>,
    plain_object_locals: HashMap<ValueId, PlainObjectLocal>,
    plain_object_fields: HashMap<ValueId, HashMap<Box<str>, SemanticLocator>>,
    array_locals: HashMap<ValueId, ArrayLocal>,
    /// Stable field locators for each element of a proven, non-escaping array
    /// literal. The outer key is the allocation root so declaration aliases
    /// retain the same element identity.
    array_element_fields: HashMap<ValueId, ArrayElementFields>,
}

struct LocalBinding {
    binding: Range,
    scope_start: usize,
    scope_end: usize,
    value: ValueId,
}

fn lexical_capture_destination(
    captures_receiver: bool,
    capture_index: usize,
) -> Result<MemoryLocationId, TsLoweringError> {
    let index = capture_index
        .checked_add(usize::from(captures_receiver))
        .ok_or_else(|| TsLoweringError::Invalid("too many JS/TS captures".into()))?;
    let index = u32::try_from(index)
        .map_err(|_| TsLoweringError::Invalid("too many JS/TS captures".into()))?;
    Ok(MemoryLocationId::new(index))
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
    /// The allocation root shared by direct declaration aliases.
    root: ValueId,
    declaration_parent: usize,
    available_after: usize,
    /// Start byte of the first whole-value consumption of this allocation
    /// root. See [`PlainObjectLocal::escapes_after`].
    escapes_after: Option<usize>,
}
